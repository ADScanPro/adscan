"""CLI helpers for BloodHound-related commands.

This module handles ACE enumeration and other BloodHound operations.
"""

from __future__ import annotations

from typing import Any, Protocol
import os
import sys
import re
import shlex
from datetime import datetime, timezone

from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.box import ROUNDED

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_list,
    print_info_verbose,
    print_instruction,
    print_operation_header,
    print_table,
    print_success,
    print_success_verbose,
    print_warning,
    telemetry,
)
from adscan_internal.bloodhound_ce_compose import BLOODHOUND_CE_DEFAULT_WEB_PORT
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.rich_output import mark_passthrough, mark_sensitive, print_panel
from adscan_internal.workspaces import domain_subpath


_BLOODHOUND_COLLECTOR_TIMEOUT_SECONDS = 1200
# Compute-time path cap for `attack_paths` UX.
# Set to `None` (default) for unlimited path computation, or to a positive int.
ATTACK_PATHS_COMPUTE_DEFAULT_MAX: int | None = None


def _get_attack_paths_step_sample_limit() -> int:
    """Return maximum number of attack-step samples to print per discovery step."""
    raw = os.getenv("ADSCAN_ATTACK_PATHS_STEP_SAMPLE_LIMIT", "20")
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = 20
    return max(0, min(limit, 200))


def _get_attack_paths_step_show_samples() -> bool:
    """Return whether to show sampled steps (capped) to the user."""
    raw = os.getenv("ADSCAN_ATTACK_PATHS_STEP_SHOW_SAMPLES", "1").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _resolve_attack_paths_compute_cap(max_display: int) -> int | None:
    """Return compute-time cap for attack-path enumeration.

    Default behavior is controlled by `ATTACK_PATHS_COMPUTE_DEFAULT_MAX`.
    `None` means unlimited (legacy behavior).

    Env overrides:
        ADSCAN_ATTACK_PATHS_COMPUTE_MAX:
            - positive int => hard cap
            - 0 / negative => unlimited
    """
    hard_cap_raw = os.getenv("ADSCAN_ATTACK_PATHS_COMPUTE_MAX", "").strip()
    if hard_cap_raw:
        try:
            hard_cap = int(hard_cap_raw)
            if hard_cap <= 0:
                return None
            return hard_cap
        except ValueError:
            pass

    _ = max_display
    if ATTACK_PATHS_COMPUTE_DEFAULT_MAX is None:
        return None
    return max(1, int(ATTACK_PATHS_COMPUTE_DEFAULT_MAX))


def _summarize_high_value_session_paths(
    paths: list[dict[str, Any]],
) -> tuple[dict[str, set[str]], int]:
    """Return host->users session map and valid edge count for HasSession paths."""
    host_to_users: dict[str, set[str]] = {}
    valid_edges = 0

    for entry in paths:
        if not isinstance(entry, dict):
            continue
        nodes = entry.get("nodes")
        rels = entry.get("rels")
        if (
            not isinstance(nodes, list)
            or len(nodes) < 2
            or not isinstance(rels, list)
            or not rels
            or str(rels[0] or "").strip().lower() != "hassession"
        ):
            continue

        host_node = nodes[0] if isinstance(nodes[0], dict) else None
        user_node = nodes[1] if isinstance(nodes[1], dict) else None
        if not isinstance(host_node, dict) or not isinstance(user_node, dict):
            continue

        host_name = str(
            host_node.get("label")
            or host_node.get("name")
            or (
                host_node.get("properties", {}).get("name")
                if isinstance(host_node.get("properties"), dict)
                else ""
            )
            or ""
        ).strip()
        user_name = str(
            user_node.get("label")
            or user_node.get("name")
            or (
                user_node.get("properties", {}).get("name")
                if isinstance(user_node.get("properties"), dict)
                else ""
            )
            or ""
        ).strip()
        if not host_name or not user_name:
            continue

        valid_edges += 1
        host_to_users.setdefault(host_name, set()).add(user_name)

    return host_to_users, valid_edges


def _print_high_value_session_summary(
    *,
    domain: str,
    paths: list[dict[str, Any]],
    max_hosts: int = 20,
    max_users_per_host: int = 4,
) -> None:
    """Render a focused UX summary for high-value session relationships."""
    host_to_users, valid_edges = _summarize_high_value_session_paths(paths)
    if not host_to_users or valid_edges <= 0:
        return

    marked_domain = mark_sensitive(domain, "domain")
    total_hosts = len(host_to_users)
    total_users = len({user for users in host_to_users.values() for user in users})

    print_panel(
        "\n".join(
            [
                f"Domain: {marked_domain}",
                "Detected active sessions from Tier Zero / high-value users.",
                f"Relationships discovered: {valid_edges}",
                f"Affected hosts: {total_hosts}",
                f"Unique high-value users in sessions: {total_users}",
            ]
        ),
        title="Tier-Zero Session Exposure",
        border_style="yellow",
    )

    table = Table(
        title=f"High-Value Sessions by Host (showing up to {max_hosts})",
        show_header=True,
        header_style="bold yellow",
        box=ROUNDED,
    )
    table.add_column("Host", style="cyan", overflow="fold")
    table.add_column("Tier0 Users", justify="right", style="yellow")
    table.add_column("Users", style="white", overflow="fold")

    ordered = sorted(
        host_to_users.items(),
        key=lambda item: (-len(item[1]), item[0].lower()),
    )
    for host, users in ordered[:max_hosts]:
        user_list = sorted(users, key=str.lower)
        shown = user_list[:max_users_per_host]
        users_text = ", ".join(mark_sensitive(u, "user") for u in shown)
        extra = len(user_list) - len(shown)
        if extra > 0:
            users_text = f"{users_text} (+{extra} more)"
        table.add_row(
            mark_sensitive(host, "hostname"),
            str(len(user_list)),
            users_text,
        )

    print_table(table)
    if total_hosts > max_hosts:
        print_info(
            f"Showing first {max_hosts} hosts only (total hosts with Tier0 sessions: {total_hosts})."
        )


def _print_collector_long_running_notice(tool_name: str, domain: str) -> None:
    """Show a UX notice that collection can take a long time on large domains."""
    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        "\n".join(
            [
                f"Collector: {tool_name}",
                f"Domain: {marked_domain}",
                "This collection can take 10–20 minutes on large domains.",
                "Please be patient while the collector runs.",
            ]
        ),
        title="Collection in progress",
        border_style="cyan",
    )


def _resolve_collector_credentials_for_license(
    shell: BloodHoundShell,
    *,
    target_domain: str,
    auth_domain: str,
    username: str,
    password: str,
    explicit_override: bool,
) -> tuple[str, str, str] | None:
    """Resolve collector credentials for current build policy.

    Current public flow allows collector execution with the selected credentials.
    """
    _ = shell
    _ = target_domain
    _ = explicit_override
    return username, password, auth_domain


class BloodHoundShell(Protocol):
    """Protocol for shell methods needed by BloodHound CLI helpers."""

    def ensure_neo4j_running(self) -> bool: ...

    def _get_bloodhound_service(self) -> object: ...

    def _filter_aces_by_adcs_requirement(
        self, aces: list[dict]
    ) -> tuple[list[dict], list[dict]]: ...

    def _extract_acl_header(self, output: str) -> str | None: ...

    def _format_acl_block(self, ace_block: dict) -> str: ...

    @property
    def domains_data(self) -> dict: ...

    @property
    def console(self) -> Any: ...

    def _get_workspace_cwd(self) -> str: ...

    def _ensure_kerberos_environment_for_command(
        self,
        target_domain: str,
        auth_domain: str,
        username: str,
        command: str,
    ) -> bool: ...

    def _questionary_select(
        self, title: str, options: list[str], default_idx: int = 0
    ) -> int | None: ...

    def dns_find_dcs(self, target_domain: str) -> None: ...

    def execute_bloodhound_collector(
        self,
        command: str,
        domain: str,
        *,
        bh_dir: str | None = None,
        sync_domain: str | None = None,
        fallback_username: str | None = None,
        fallback_password: str | None = None,
        fallback_auth_domain: str | None = None,
        dc_fqdn: str | None = None,
        dns_ip: str | None = None,
        allow_password_fallback: bool = False,
    ) -> None: ...

    @property
    def domains(self) -> list[str]: ...

    @property
    def domains_dir(self) -> str: ...

    @property
    def domain(self) -> str | None: ...

    def run_command(
        self, command: str, timeout: int | None = None, cwd: str | None = None
    ) -> Any: ...

    def _get_bloodhound_cli_path(self) -> str | None: ...

    def _write_user_list_file(
        self, domain: str, filename: str, users: list[str]
    ) -> str: ...

    def _write_domain_list_file(
        self, domain: str, filename: str, values: list[str]
    ) -> str: ...

    def check_high_value(
        self, domain: str, username: str, *, logging: bool = True
    ) -> bool: ...

    def _postprocess_user_list_file(self, domain: str, filename: str) -> None: ...

    def _process_bloodhound_computers_list(
        self, domain: str, comp_file: str, computers: list[str]
    ) -> None: ...

    def _display_items(self, items: list[str], label: str) -> None: ...

    def update_report_field(self, domain: str, key: str, value: Any) -> None: ...

    def is_computer_dc(self, domain: str, target_host: str) -> bool: ...

    @property
    def auto(self) -> bool: ...

    @property
    def type(self) -> str: ...

    @property
    def license_mode(self) -> str: ...

    def do_check_dns(self, domain: str) -> bool: ...

    def do_update_resolv_conf(self, resolv_conf_line: str) -> None: ...

    def convert_hostnames_to_ips_and_scan(
        self, domain: str, computers_file: str, nmap_dir: str
    ) -> None: ...

    def enable_user(
        self, domain: str, username: str, password: str, target_username: str
    ) -> bool: ...

    def exploit_force_change_password(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: str,
        target_domain: str,
        *,
        prompt_for_user_privs_after: bool = True,
    ) -> bool: ...

    def exploit_generic_all_user(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: str,
        target_domain: str,
        *,
        prompt_for_password_fallback: bool = True,
        prompt_for_user_privs_after: bool = True,
        prompt_for_method_choice: bool = True,
    ) -> bool: ...

    def exploit_write_spn(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: str,
        target_domain: str,
    ) -> bool: ...

    def exploit_generic_all_ou(
        self,
        domain: str,
        username: str,
        password: str,
        target_ou: str,
        target_domain: str,
        *,
        followup_after: bool = True,
    ) -> bool: ...

    def exploit_add_member(
        self,
        domain: str,
        username: str,
        password: str,
        target_group: str,
        new_member: str,
        target_domain: str,
        *,
        enumerate_aces_after: bool = True,
    ) -> bool: ...

    def exploit_gmsa_account(
        self,
        domain: str,
        username: str,
        password: str,
        target_account: str,
        target_domain: str,
        *,
        prompt_for_user_privs_after: bool = True,
    ) -> bool: ...

    def exploit_laps_password(
        self,
        domain: str,
        username: str,
        password: str,
        target_computer: str,
        target_domain: str,
        *,
        prompt_for_user_privs_after: bool = True,
    ) -> bool: ...

    def exploit_write_dacl(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: str,
        target_domain: str,
        target_type: str,
        *,
        followup_after: bool = True,
    ) -> bool: ...

    def exploit_write_owner(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: str,
        target_domain: str,
        target_type: str,
        *,
        followup_after: bool = True,
    ) -> bool: ...

    def dcsync(self, domain: str, username: str, password: str) -> None: ...


def resolve_bloodhound_zip_paths(shell: BloodHoundShell, domain: str) -> list[str]:
    """Resolve existing BloodHound ZIP artifacts for a domain."""
    workspace_cwd = shell._get_workspace_cwd()
    from adscan_internal.workspaces import DEFAULT_DOMAIN_LAYOUT

    bh_dir = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        DEFAULT_DOMAIN_LAYOUT.bloodhound,
    )

    zip_paths: list[str] = []
    domain_state = shell.domains_data.get(domain, {}) if shell.domains_data else {}
    expected_paths = domain_state.get("bh_zip_paths", [])
    if isinstance(expected_paths, list) and expected_paths:
        zip_paths = [
            path
            for path in expected_paths
            if isinstance(path, str) and os.path.exists(path)
        ]
        if len(zip_paths) != len(expected_paths):
            missing_paths = [path for path in expected_paths if path not in zip_paths]
            marked_expected = ", ".join(
                mark_sensitive(path, "path")
                for path in expected_paths
                if isinstance(path, str)
            )
            marked_missing = ", ".join(
                mark_sensitive(path, "path")
                for path in missing_paths
                if isinstance(path, str)
            )
            print_warning(
                "Expected BloodHound ZIPs were not all found on disk. "
                f"Expected: {marked_expected}"
            )
            print_warning(f"Missing ZIPs: {marked_missing}")
        return zip_paths

    if os.path.isdir(bh_dir):
        for file_name in os.listdir(bh_dir):
            if file_name.endswith(".zip"):
                zip_paths.append(os.path.join(bh_dir, file_name))
    zip_paths.sort(key=lambda path: os.path.getmtime(path), reverse=True)
    return zip_paths


def upload_bloodhound_ce_zip_files(
    shell: BloodHoundShell,
    domain: str,
    *,
    wait_for_manual_on_failure: bool,
    zip_paths: list[str] | None = None,
) -> bool:
    """Upload BloodHound ZIP artifacts to CE and optionally wait for manual fallback."""
    if zip_paths is None:
        zip_paths = resolve_bloodhound_zip_paths(shell, domain)
    else:
        zip_paths = [
            path for path in zip_paths if isinstance(path, str) and os.path.exists(path)
        ]

    if not zip_paths:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"BloodHound ZIP file(s) not found for {marked_domain}. Automatic CE upload cannot continue."
        )
        if wait_for_manual_on_failure:
            raw_login_url = (
                f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}/ui/login"
            )
            login_url = mark_passthrough(raw_login_url)
            print_instruction(
                "Please manually upload the ZIP file(s) to BloodHound CE UI at: "
                f"{login_url}"
            )
            Prompt.ask(
                "Press Enter once you have completed the import to continue with the enumeration...",
                default="",
            )
        return False

    print_info("Uploading ZIP files to BloodHound CE automatically")
    overall_success = True

    uploads: list[tuple[str, str, int | None]] = []
    for zip_file_path in zip_paths:
        zip_name = os.path.basename(zip_file_path)
        collector_label = "Unknown collector"
        if "rusthound-ce" in zip_name:
            collector_label = "rusthound-ce"
        elif "bloodhound-ce-python" in zip_name:
            collector_label = "bloodhound-ce-python"

        marked_zip_path = mark_sensitive(zip_file_path, "path")
        print_info_verbose(
            f"Submitting BloodHound ZIP upload job ({collector_label}): {marked_zip_path}"
        )
        try:
            job_id = shell._get_bloodhound_service().start_upload_job(zip_file_path)
            uploads.append((zip_file_path, collector_label, job_id))
            if job_id is None:
                overall_success = False
                print_warning(
                    f"Failed to start upload job for ZIP ({collector_label})."
                )
            else:
                print_info_verbose(
                    f"Upload job created for ({collector_label}): job_id={job_id}"
                )
        except Exception as exc:
            telemetry.capture_exception(exc)
            overall_success = False
            uploads.append((zip_file_path, collector_label, None))
            print_warning(
                "Automatic upload to BloodHound CE failed. Please upload the ZIP file manually."
            )
            print_exception(show_locals=False, exception=exc)

    for zip_file_path, collector_label, job_id in uploads:
        if job_id is None:
            continue
        marked_zip_path = mark_sensitive(zip_file_path, "path")
        print_info_verbose(
            f"Waiting for ingestion of ZIP ({collector_label}): {marked_zip_path} (job_id={job_id})"
        )
        try:
            success = shell._get_bloodhound_service().wait_for_upload_job(
                int(job_id),
                poll_interval=5,
                timeout=1800,
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_warning(
                "Automatic upload to BloodHound CE failed. Please upload the ZIP file manually."
            )
            print_exception(show_locals=False, exception=exc)
            success = False

        if success:
            print_success(
                f"ZIP file ({collector_label}) uploaded to BloodHound CE successfully!"
            )
        else:
            overall_success = False
            print_warning(
                "ZIP file upload did not complete successfully. Check BloodHound CE UI and upload manually if needed."
            )

    if not overall_success and wait_for_manual_on_failure:
        raw_login_url = f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}/ui/login"
        login_url = mark_passthrough(raw_login_url)
        print_instruction(
            "Please manually upload any missing ZIP files to BloodHound CE UI at: "
            f"{login_url}"
        )
        Prompt.ask(
            "Press Enter once you have completed the import to continue with the enumeration...",
            default="",
        )

    return overall_success


def run_bloodhound_collector(
    shell: BloodHoundShell,
    target_domain: str,
    *,
    auth_username: str | None = None,
    auth_password: str | None = None,
    auth_domain: str | None = None,
) -> list[str]:
    """Run BloodHound collection for the given domain and store results under its BH directory.

    Args:
        shell: Shell implementation used for command execution and state access.
        target_domain: Domain to collect data for.
        auth_username: Optional credential username override.
        auth_password: Optional credential password/hash override.
        auth_domain: Optional credential domain override.
    """
    from adscan_internal.bloodhound_legacy import get_bloodhound_mode

    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return []

    # Resolve BloodHound workspace directory under the current workspace.
    workspace_cwd = shell._get_workspace_cwd()
    bh_dir = domain_subpath(workspace_cwd, shell.domains_dir, target_domain, "BH")
    os.makedirs(bh_dir, exist_ok=True)

    resolved_auth_domain = (auth_domain or target_domain).strip().lower()
    if auth_username and auth_password:
        username = str(auth_username).strip()
        password = str(auth_password)
        if not resolved_auth_domain:
            resolved_auth_domain = target_domain
        marked_username = mark_sensitive(username, "user")
        marked_domain = mark_sensitive(resolved_auth_domain, "domain")
        print_info_verbose(
            "Using explicit BloodHound collector credential override: "
            f"{marked_username}@{marked_domain}"
        )
    else:
        # Support multi-domain collection:
        # - Prefer credentials for the target domain if present
        # - Otherwise fall back to the current workspace domain credentials (shell.domain),
        #   e.g., in trusted multi-domain lab environments.
        resolved_auth_domain = target_domain
        if (
            target_domain not in shell.domains_data
            or not shell.domains_data[target_domain].get("username")
            or not shell.domains_data[target_domain].get("password")
        ):
            resolved_auth_domain = shell.domain

        if resolved_auth_domain not in shell.domains_data:
            marked_target_domain = mark_sensitive(target_domain, "domain")
            marked_auth_domain = mark_sensitive(resolved_auth_domain, "domain")
            print_error(
                f"No credentials found for {marked_target_domain} and no fallback credentials available for {marked_auth_domain}."
            )
            return []

        if not shell.domains_data[resolved_auth_domain].get(
            "username"
        ) or not shell.domains_data[resolved_auth_domain].get("password"):
            marked_target_domain = mark_sensitive(target_domain, "domain")
            marked_auth_domain = mark_sensitive(resolved_auth_domain, "domain")
            print_error(
                f"No usable credentials available to run BloodHound collection for {marked_target_domain} "
                f"(missing username/password in {marked_auth_domain})."
            )
            return []

        username = shell.domains_data[resolved_auth_domain]["username"]
        password = shell.domains_data[resolved_auth_domain]["password"]

    resolved_credential = _resolve_collector_credentials_for_license(
        shell,
        target_domain=target_domain,
        auth_domain=resolved_auth_domain,
        username=username,
        password=password,
        explicit_override=bool(auth_username and auth_password),
    )
    if not resolved_credential:
        return []
    username, password, resolved_auth_domain = resolved_credential

    is_hash = len(password) == 32 and all(
        c in "0123456789abcdef" for c in password.lower()
    )

    pdc_hostname = shell.domains_data.get(target_domain, {}).get("pdc_hostname")
    pdc_ip = shell.domains_data.get(target_domain, {}).get("pdc")
    if not pdc_hostname or not pdc_ip:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_warning(
            f"Missing PDC details for {marked_target_domain}. Attempting DC discovery..."
        )
        try:
            shell.dns_find_dcs(target_domain)
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
        pdc_hostname = shell.domains_data.get(target_domain, {}).get("pdc_hostname")
        pdc_ip = shell.domains_data.get(target_domain, {}).get("pdc")

    if not pdc_hostname or not pdc_ip:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(f"Unable to determine PDC hostname/IP for {marked_target_domain}.")
        return []

    dc_fqdn = f"{pdc_hostname}.{target_domain}"

    dns_ip = str(pdc_ip)

    def _format_upn(user_value: str, domain_value: str) -> str:
        if "@" in user_value:
            return user_value
        if "\\" in user_value:
            user_value = user_value.split("\\", 1)[1]
        return f"{user_value}@{domain_value}"

    upn = _format_upn(username, resolved_auth_domain)

    # Choose BloodHound collector based on installed mode
    display_command = ""

    # Ensure Kerberos environment is ready before attempting Kerberos authentication
    kerberos_env_ready = shell._ensure_kerberos_environment_for_command(
        target_domain, resolved_auth_domain, username, "rusthound-ce -k"
    )

    if kerberos_env_ready:
        marked_username = mark_sensitive(username, "user")
        marked_domain_1 = mark_sensitive(resolved_auth_domain, "domain")
        print_info_verbose(
            f"Using Kerberos authentication for {marked_username}@{marked_domain_1}"
        )
        command = (
            "rusthound-ce "
            f"-d {shlex.quote(target_domain)} -k -c All "
            f"-f {shlex.quote(dc_fqdn)} -n {shlex.quote(dns_ip)} --zip --ldaps"
        )
        marked_target_domain = mark_sensitive(target_domain, "domain")
        marked_pdc_host = mark_sensitive(pdc_hostname, "hostname")
        marked_pdc_ip = mark_sensitive(dns_ip, "ip")
        display_command = (
            "rusthound-ce -d "
            f"{marked_target_domain} -k -c All -f "
            f"{marked_pdc_host}.{marked_target_domain} "
            f"-n {marked_pdc_ip} --zip --ldaps"
        )
    else:
        marked_domain_1 = mark_sensitive(resolved_auth_domain, "domain")
        marked_username = mark_sensitive(username, "user")
        print_warning(
            f"No Kerberos ticket found for {marked_username}@{marked_domain_1}, using password authentication."
        )
        if is_hash:
            print_warning(
                "Only an NTLM hash is available for this credential; rusthound-ce password fallback requires a cleartext password."
            )
            return []
        command = (
            "rusthound-ce "
            f"-d {shlex.quote(target_domain)} "
            f"-u {shlex.quote(upn)} -p {shlex.quote(password)} "
            f"-f {shlex.quote(dc_fqdn)} -n {shlex.quote(dns_ip)} "
            "-c All --zip --ldaps"
        )
        marked_target_domain = mark_sensitive(target_domain, "domain")
        marked_upn = mark_sensitive(upn, "user")
        marked_dc_fqdn = mark_sensitive(dc_fqdn, "hostname")
        marked_dns_ip = mark_sensitive(dns_ip, "ip")
        marked_password = mark_sensitive(shlex.quote(password), "password")
        display_command = (
            f"rusthound-ce -d {marked_target_domain} -u {marked_upn} -p {marked_password} "
            f"-f {marked_dc_fqdn} -n {marked_dns_ip} -c All --zip --ldaps"
        )

    bh_mode = get_bloodhound_mode()
    auth_type = "Kerberos" if bh_mode == "ce" and kerberos_env_ready else "Password"

    print_operation_header(
        "BloodHound Collection",
        details={
            "Domain": target_domain,
            "Authentication": auth_type,
            "Collection Type": "All",
            "Output": f"domains/{target_domain}/BH/",
        },
        icon="🩸",
    )

    print_info_debug(f"Command: {display_command or command}")
    _print_collector_long_running_notice("rusthound-ce", target_domain)

    # When using Kerberos, clock skew must be corrected against the KDC/PDC of the
    # realm that issues the tickets (auth_domain), not necessarily the target domain.
    # This is critical for multi-domain / cross-realm collection.
    sync_domain = resolved_auth_domain if kerberos_env_ready else None
    zip_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    generated_zip_paths: list[str] = []

    rusthound_zip = f"{target_domain}_rusthound-ce_{zip_timestamp}.zip"
    generated_zip_paths.append(os.path.join(bh_dir, rusthound_zip))
    shell.execute_bloodhound_collector(
        command,
        target_domain,
        bh_dir=bh_dir,
        sync_domain=sync_domain,
        fallback_username=username,
        fallback_password=password if not is_hash else None,
        fallback_auth_domain=resolved_auth_domain,
        dc_fqdn=dc_fqdn,
        dns_ip=dns_ip,
        allow_password_fallback=bool(kerberos_env_ready),
        zip_filename=rusthound_zip,
    )

    if not shell.bloodhound_ce_py_path:
        print_info_verbose(
            "bloodhound-ce-python not found; skipping secondary collector."
        )
        shell.domains_data.setdefault(target_domain, {})["bh_zip_paths"] = (
            generated_zip_paths
        )
        return generated_zip_paths

    # Run BloodHound CE Python collector after rusthound-ce.
    ce_py_command = ""
    ce_py_display_command = ""

    kerberos_env_ready_py = shell._ensure_kerberos_environment_for_command(
        target_domain, resolved_auth_domain, username, "bloodhound-ce-python -k"
    )

    if kerberos_env_ready_py:
        marked_username = mark_sensitive(username, "user")
        marked_domain_1 = mark_sensitive(resolved_auth_domain, "domain")
        print_info_verbose(
            f"Using Kerberos authentication for {marked_username}@{marked_domain_1}"
        )
        marked_upn = mark_sensitive(upn, "user")
        ce_py_command = (
            f"{shlex.quote(shell.bloodhound_ce_py_path)} "
            f"-d {shlex.quote(target_domain)} -u {shlex.quote(upn)} -k -no-pass -c All "
            f"-dc {shlex.quote(dc_fqdn)} -ns {shlex.quote(dns_ip)} "
            "--zip --use-ldaps"
        )
        marked_target_domain = mark_sensitive(target_domain, "domain")
        marked_dc_fqdn = mark_sensitive(dc_fqdn, "hostname")
        marked_dns_ip = mark_sensitive(dns_ip, "ip")
        ce_py_display_command = (
            f"{shell.bloodhound_ce_py_path} -d {marked_target_domain} -u {marked_upn} -k -no-pass -c All "
            f"-dc {marked_dc_fqdn} -ns {marked_dns_ip} --zip --use-ldaps"
        )
    else:
        marked_domain_1 = mark_sensitive(resolved_auth_domain, "domain")
        marked_username = mark_sensitive(username, "user")
        print_warning(
            f"No Kerberos ticket found for {marked_username}@{marked_domain_1}, using password authentication."
        )
        if is_hash:
            print_warning(
                "Only an NTLM hash is available for this credential; bloodhound-ce-python requires a cleartext password for password auth."
            )
            shell.domains_data.setdefault(target_domain, {})["bh_zip_paths"] = (
                generated_zip_paths
            )
            return generated_zip_paths
        ce_py_command = (
            f"{shlex.quote(shell.bloodhound_ce_py_path)} "
            f"-d {shlex.quote(target_domain)} "
            f"-u {shlex.quote(upn)} -p {shlex.quote(password)} "
            f"-c All -dc {shlex.quote(dc_fqdn)} -ns {shlex.quote(dns_ip)} "
            "--zip --use-ldaps"
        )
        marked_target_domain = mark_sensitive(target_domain, "domain")
        marked_upn = mark_sensitive(upn, "user")
        marked_dc_fqdn = mark_sensitive(dc_fqdn, "hostname")
        marked_dns_ip = mark_sensitive(dns_ip, "ip")
        marked_password = mark_sensitive(shlex.quote(password), "password")
        ce_py_display_command = (
            f"{shell.bloodhound_ce_py_path} -d {marked_target_domain} -u {marked_upn} -p {marked_password} "
            f"-c All -dc {marked_dc_fqdn} -ns {marked_dns_ip} --zip --use-ldaps"
        )

    print_operation_header(
        "BloodHound Collection",
        details={
            "Domain": target_domain,
            "Authentication": "Kerberos" if kerberos_env_ready_py else "Password",
            "Collector": "bloodhound-ce-python",
            "Collection Type": "All",
            "Output": f"domains/{target_domain}/BH/",
        },
        icon="🩸",
    )

    print_info_debug(f"Command: {ce_py_display_command or ce_py_command}")
    _print_collector_long_running_notice("bloodhound-ce-python", target_domain)

    fallback_password_command = None
    fallback_password_display = None
    if kerberos_env_ready_py and not is_hash:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        marked_upn = mark_sensitive(upn, "user")
        marked_dc_fqdn = mark_sensitive(dc_fqdn, "hostname")
        marked_dns_ip = mark_sensitive(dns_ip, "ip")
        fallback_password_command = (
            f"{shlex.quote(shell.bloodhound_ce_py_path)} "
            f"-d {shlex.quote(target_domain)} "
            f"-u {shlex.quote(upn)} -p {shlex.quote(password)} "
            f"-c All -dc {shlex.quote(dc_fqdn)} -ns {shlex.quote(dns_ip)} "
            "--zip --use-ldaps"
        )
        fallback_password_display = (
            f"{shell.bloodhound_ce_py_path} -d {marked_target_domain} -u {marked_upn} -p [REDACTED] "
            f"-c All -dc {marked_dc_fqdn} -ns {marked_dns_ip} --zip --use-ldaps"
        )

    sync_domain = resolved_auth_domain if kerberos_env_ready_py else None
    ce_py_zip = f"{target_domain}_bloodhound-ce-python_{zip_timestamp}.zip"
    generated_zip_paths.append(os.path.join(bh_dir, ce_py_zip))
    shell.execute_bloodhound_collector(
        ce_py_command,
        target_domain,
        tool_name="bloodhound-ce-python",
        ldaps_flag="--use-ldaps",
        bh_dir=bh_dir,
        sync_domain=sync_domain,
        fallback_username=username,
        fallback_password=password if not is_hash else None,
        fallback_auth_domain=resolved_auth_domain,
        dc_fqdn=dc_fqdn,
        dns_ip=dns_ip,
        allow_password_fallback=bool(kerberos_env_ready_py),
        zip_filename=ce_py_zip,
        password_fallback_command=fallback_password_command,
        password_fallback_display=fallback_password_display,
    )

    shell.domains_data.setdefault(target_domain, {})["bh_zip_paths"] = (
        generated_zip_paths
    )
    return generated_zip_paths


def _load_certipy_adcs_discovery(
    shell: BloodHoundShell,
    *,
    target_domain: str,
    graph: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load Certipy JSON (if present) and return ADCS paths + template metadata."""
    paths: list[dict[str, Any]] = []
    templates: dict[str, Any] = {}
    try:
        from adscan_internal.core import LicenseMode
        from adscan_internal.services import CredentialStoreService
        from adscan_internal.services.attack_graph_service import (
            get_certipy_adcs_paths,
            get_certipy_template_metadata,
        )
        from adscan_internal.services.exploitation import ExploitationService

        creds = CredentialStoreService.resolve_auth_credentials(
            shell.domains_data,
            target_domain=target_domain,
            primary_domain=getattr(shell, "domain", None),
        )
        if not creds:
            print_info_debug(
                "[adcs] No credentials available for certipy discovery; skipping."
            )
            return paths, templates
        username, password, auth_domain = creds
        auth = shell.build_auth_certipy(auth_domain, username, password)
        domain_data = shell.domains_data.get(target_domain, {})
        pdc_ip = domain_data.get("pdc")
        pdc_hostname = domain_data.get("pdc_hostname")
        if not pdc_ip or not pdc_hostname:
            print_info_debug(
                "[adcs] Missing PDC details for certipy discovery; skipping."
            )
            return paths, templates

        raw_license = getattr(shell, "license_mode", LicenseMode.PRO)
        if isinstance(raw_license, LicenseMode):
            license_mode = raw_license
        else:
            raw_value = str(raw_license).strip().lower()
            license_mode = LicenseMode.LITE if raw_value == "lite" else LicenseMode.PRO
        exploit_service = ExploitationService(
            event_bus=getattr(shell, "event_bus", None),
            license_mode=license_mode,
        )
        workspace_cwd = (
            shell._get_workspace_cwd()
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", os.getcwd())
        )
        adcs_dir = domain_subpath(
            workspace_cwd, shell.domains_dir, target_domain, "adcs"
        )
        os.makedirs(adcs_dir, exist_ok=True)
        output_prefix = os.path.join(adcs_dir, "certipy_find")
        print_info_debug("[adcs] Running certipy discovery (phase 2).")
        exploit_service.adcs.enum_privileges(
            certipy_path=shell.certipy_path,
            pdc_ip=pdc_ip,
            target_host=f"{pdc_hostname}.{target_domain}",
            auth_string=auth,
            output_prefix=output_prefix,
            run_command=shell.run_command,
            vulnerable_only=False,
            use_cached_json=True,
        )

        paths = get_certipy_adcs_paths(shell, target_domain, graph=graph)
        templates = get_certipy_template_metadata(shell, target_domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[adcs] Certipy cache load failed: {exc}")
    return paths, templates


def _get_adcs_escalation_paths_for_domain(
    shell: BloodHoundShell,
    *,
    service: object,
    target_domain: str,
    graph: dict[str, Any] | None = None,
    max_results: int = 1000,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Return ADCS escalation paths split by source (BloodHound vs Certipy)."""
    bh_paths: list[dict[str, Any]] = []
    try:
        bh_paths = (
            service.get_low_priv_adcs_paths(  # type: ignore[attr-defined]
                target_domain, max_results=max_results
            )
            or []
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        bh_paths = []

    certipy_paths, certipy_templates = _load_certipy_adcs_discovery(
        shell, target_domain=target_domain, graph=graph
    )
    return bh_paths, certipy_paths, certipy_templates


def run_enumerate_user_aces(shell: BloodHoundShell, args: str) -> None:
    """Parse arguments and initiate user ACE enumeration.

    Mirrors the legacy ``do_enumerate_user_aces`` entrypoint but keeps argument
    parsing and CLI usage/help text outside of `adscan.py`.
    """
    parts = args.split()
    if len(parts) != 3:
        shell.console.print("Usage: enumerate_user_aces <domain> <user> <password>")  # type: ignore[attr-defined]
        return
    domain, username, password = parts
    shell.ask_for_enumerate_user_aces(domain, username, password)  # type: ignore[attr-defined]


def run_bloodhound_attack_paths(
    shell: BloodHoundShell,
    target_domain: str,
    *,
    max_depth: int = 4,
) -> None:
    """Enumerate theoretical attack steps from low-priv users.

    Today, this phase focuses on ACL/ACE-style effective relationships derived
    from group membership + rights edges in BloodHound CE. The resulting graph
    is then used to compute maximal attack paths for CLI display.
    """
    from adscan_internal.bloodhound_legacy import (
        _check_bloodhound_ce_running,
        _start_bloodhound_ce,
        get_bloodhound_mode,
    )
    from adscan_internal.services.attack_graph_service import (
        add_bloodhound_path_edges,
        compute_maximal_attack_paths,
        get_owned_domain_usernames,
        load_attack_graph,
        path_to_display_record,
        save_attack_graph,
    )
    from adscan_internal.rich_output import (
        print_step_status,
        print_attack_path_detail,
        print_attack_paths_summary,
    )
    from adscan_internal.cli.attack_path_execution import (
        offer_attack_paths_for_execution,
    )

    if target_domain not in shell.domains:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_domain}' is not configured. Please add or select a valid domain."
        )
        return

    bh_mode = get_bloodhound_mode()
    if bh_mode == "ce":
        if not _check_bloodhound_ce_running():
            print_info("BloodHound CE is not running, starting containers...")
            if not _start_bloodhound_ce():
                print_error("Failed to start BloodHound CE. Cannot enumerate paths.")
                return
        print_info_verbose("BloodHound CE is ready for path enumeration")
    else:
        if not shell.ensure_neo4j_running():
            print_error("Neo4j is not running. Cannot enumerate paths.")
            return

    marked_domain = mark_sensitive(target_domain, "domain")
    print_operation_header(
        "Attack Paths Discovery",
        details={
            "Domain": target_domain,
            "Depth": str(max_depth),
            "Limit": "1000",
            "Mode": bh_mode,
        },
        icon="🧭",
    )
    print_info(f"Discovering attack paths for {marked_domain}")

    service = shell._get_bloodhound_service()

    adcs_bh_paths: list[dict[str, Any]] | None = None
    adcs_certipy_paths: list[dict[str, Any]] | None = None
    adcs_certipy_templates: dict[str, Any] | None = None

    def _get_adcs_certipy_paths() -> list[dict[str, Any]]:
        nonlocal adcs_bh_paths, adcs_certipy_paths, adcs_certipy_templates
        if adcs_bh_paths is None or adcs_certipy_paths is None:
            (
                adcs_bh_paths,
                adcs_certipy_paths,
                adcs_certipy_templates,
            ) = _get_adcs_escalation_paths_for_domain(
                shell,
                service=service,
                target_domain=target_domain,
                graph=graph,
            )
        return list(adcs_certipy_paths or [])

    def _get_adcs_bloodhound_paths() -> list[dict[str, Any]]:
        nonlocal adcs_bh_paths, adcs_certipy_paths, adcs_certipy_templates
        if adcs_bh_paths is None or adcs_certipy_paths is None:
            (
                adcs_bh_paths,
                adcs_certipy_paths,
                adcs_certipy_templates,
            ) = _get_adcs_escalation_paths_for_domain(
                shell,
                service=service,
                target_domain=target_domain,
                graph=graph,
            )
        return list(adcs_bh_paths or [])

    steps: list[tuple[str, str, callable]] = [
        (
            "ADCS Escalation (Certipy)",
            "get_certipy_adcs_paths",
            _get_adcs_certipy_paths,
        ),
        (
            "ADCS Escalation (BloodHound)",
            "get_low_priv_adcs_paths",
            _get_adcs_bloodhound_paths,
        ),
        (
            "Roastable Users",
            "get_roastable_user_edges",
            lambda: _get_roastable_user_edges(service, target_domain, max_results=1000),
        ),
        (
            "ACL/ACE Relationships",
            "get_low_priv_acl_paths",
            lambda: service.get_low_priv_acl_paths(target_domain, max_results=1000),
        ),  # type: ignore[attr-defined]
        (
            "Access & Sessions",
            "get_low_priv_access_paths",
            lambda: service.get_low_priv_access_paths(target_domain, max_results=1000),
        ),  # type: ignore[attr-defined]
        (
            "High-Value User Sessions",
            "get_high_value_session_paths",
            lambda: service.get_high_value_session_paths(
                target_domain, max_results=1000
            ),
        ),  # type: ignore[attr-defined]
        (
            "Delegations",
            "get_low_priv_delegation_paths",
            lambda: service.get_low_priv_delegation_paths(
                target_domain, max_results=1000
            ),
        ),  # type: ignore[attr-defined]
    ]
    total_steps = len(steps) + 2
    step_offset = 0

    unique_paths = 0
    graph = load_attack_graph(shell, target_domain)
    sample_limit = _get_attack_paths_step_sample_limit()
    show_samples = _get_attack_paths_step_show_samples()

    # ADCS discovery happens in Phase 1 (Domain Analysis).

    def _get_roastable_user_edges(
        svc: object, domain: str, *, max_results: int
    ) -> list[dict[str, Any]]:
        """Return entry-vector edges for roastable accounts.

        Produces 1-hop edges from a shared entry node ("Domain Users") to each
        roastable user. When possible, the entry node is resolved from
        BloodHound (RID 513) to avoid language-dependent naming.

        These are stored as `entry_vector` edges so that later cracking can
        update their status/notes without altering BloodHound CE provenance.
        """
        entry_node: dict[str, Any] = {
            "name": "Domain Users",
            "kind": ["Group"],
            "properties": {"name": "Domain Users"},
        }
        try:
            if hasattr(svc, "get_domain_users_group"):
                node_props = svc.get_domain_users_group(domain)  # type: ignore[attr-defined]
                if isinstance(node_props, dict) and (
                    node_props.get("name") or node_props.get("objectid")
                ):
                    entry_node = {
                        "name": str(node_props.get("name") or "Domain Users"),
                        "kind": ["Group"],
                        "objectId": node_props.get("objectid")
                        or node_props.get("objectId"),
                        "properties": node_props,
                    }
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

        edges: list[dict[str, Any]] = []
        try:
            if hasattr(svc, "get_roastable_asreproast_users"):
                asrep_users = svc.get_roastable_asreproast_users(  # type: ignore[attr-defined]
                    domain,
                    max_results=max_results,
                )
                for user_node in asrep_users or []:
                    if isinstance(user_node, dict):
                        edges.append(
                            {
                                "nodes": [entry_node, user_node],
                                "rels": ["ASREPRoasting"],
                            }
                        )
            if hasattr(svc, "get_roastable_kerberoast_users"):
                kerb_users = svc.get_roastable_kerberoast_users(  # type: ignore[attr-defined]
                    domain,
                    max_results=max_results,
                )
                for user_node in kerb_users or []:
                    if isinstance(user_node, dict):
                        edges.append(
                            {
                                "nodes": [entry_node, user_node],
                                "rels": ["Kerberoasting"],
                            }
                        )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return []

        # Deduplicate by canonical node id + relation.
        deduped: dict[tuple[str, str], dict[str, Any]] = {}
        for item in edges:
            nodes = item.get("nodes")
            rels = item.get("rels")
            if (
                not isinstance(nodes, list)
                or len(nodes) != 2
                or not isinstance(rels, list)
                or len(rels) != 1
            ):
                continue
            relation = str(rels[0])
            user_node = nodes[1] if isinstance(nodes[1], dict) else None
            if not isinstance(user_node, dict):
                continue
            user_name = _node_name(user_node)
            if not user_name:
                continue
            deduped[(user_name.lower(), relation)] = item
        return list(deduped.values())

    def _node_name(node: object) -> str:
        if isinstance(node, dict):
            props = (
                node.get("properties")
                if isinstance(node.get("properties"), dict)
                else {}
            )
            name = (
                props.get("samaccountname")
                or props.get("name")
                or node.get("samaccountname")
                or node.get("name")
                or node.get("label")
                or node.get("objectId")
                or ""
            )
        else:
            name = str(node or "")
        name = str(name)
        if "@" in name:
            name = name.split("@")[0]
        return name

    def _is_user_node(node: object) -> bool:
        if not isinstance(node, dict):
            return False
        kinds = node.get("kind") or node.get("labels") or []
        if isinstance(kinds, str):
            kinds = [kinds]
        if any(str(kind).lower() == "user" for kind in kinds):
            return True
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        node_label = (node.get("label") or props.get("label") or "").lower()
        return node_label == "user"

    def _relation_name(rel: object) -> str:
        if isinstance(rel, dict):
            return str(
                rel.get("type")
                or rel.get("label")
                or rel.get("kind")
                or rel.get("name")
                or ""
            )
        return str(rel)

    def _canonical_group_label(name: str) -> str:
        raw = str(name or "").strip()
        if not raw:
            return ""
        if "@" in raw:
            left, _, right = raw.partition("@")
            if left and right:
                return f"{left.strip().upper()}@{right.strip().upper()}"
        return f"{raw.upper()}@{target_domain.upper()}"

    def _canonical_user_label(name: str) -> str:
        raw = str(name or "").strip()
        if not raw:
            return ""
        if "@" in raw:
            left, _, right = raw.partition("@")
            if left and right:
                return f"{left.strip().upper()}@{right.strip().upper()}"
        return f"{raw.upper()}@{target_domain.upper()}"

    def _persist_membership_snapshot() -> tuple[int, int, int]:
        """Persist direct user/group and group/parent memberships to JSON."""
        client = getattr(service, "client", None)
        execute_query = getattr(client, "execute_query", None)
        if not callable(execute_query):
            print_info_debug(
                "[bloodhound] Membership snapshot skipped: CE client unavailable."
            )
            return 0, 0, 0

        user_query = f"""
        MATCH p=(u:User)-[:MemberOf]->(g:Group)
        WHERE toLower(coalesce(u.name, "")) ENDS WITH toLower('@{target_domain}')
        RETURN p
        """
        computer_query = f"""
        MATCH p=(c:Computer)-[:MemberOf]->(g:Group)
        WHERE toLower(coalesce(c.domain, "")) = toLower('{target_domain}')
        RETURN p
        """
        group_query = f"""
        MATCH p=(g:Group)-[:MemberOf]->(pg:Group)
        WHERE toLower(coalesce(g.name, "")) ENDS WITH toLower('@{target_domain}')
        RETURN p
        """

        from datetime import datetime, timezone
        from adscan_internal.services.attack_graph_service import (
            add_bloodhound_path_edges,
        )

        membership_graph: dict[str, object] = {
            "domain": target_domain,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "schema_version": "membership-1.0",
            "nodes": {},
            "edges": [],
            "version": 2,
        }

        def _append_graph_data(graph_data: dict[str, object], *, label: str) -> int:
            if not isinstance(graph_data, dict):
                return 0
            nodes_map = graph_data.get("nodes", {})
            edges = graph_data.get("edges", [])
            if not isinstance(nodes_map, dict) or not isinstance(edges, list):
                return 0
            print_info_debug(
                f"[bloodhound] Membership snapshot {label} nodes={len(nodes_map)} edges={len(edges)}"
            )
            if nodes_map:
                sample_key = next(iter(nodes_map.keys()))
                print_info_debug(
                    f"[bloodhound] Membership snapshot {label} node key type: {type(sample_key)}"
                )
            if nodes_map:
                sample_node = next(iter(nodes_map.values()))
                print_info_debug(
                    f"[bloodhound] Membership snapshot {label} node sample keys: "
                    f"{list(sample_node.keys()) if isinstance(sample_node, dict) else type(sample_node)}"
                )
            if edges:
                print_info_debug(
                    f"[bloodhound] Membership snapshot {label} edge sample: {edges[0]}"
                )

            def _lookup_node(key: object) -> dict | None:
                if key in nodes_map:
                    node = nodes_map.get(key)
                    return node if isinstance(node, dict) else None
                str_key = str(key)
                node = nodes_map.get(str_key)
                return node if isinstance(node, dict) else None

            added = 0
            skipped_missing_nodes = 0
            missing_examples: list[dict[str, object]] = []
            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                relation = edge.get("label") or edge.get("kind") or ""
                if str(relation) != "MemberOf":
                    continue
                source = edge.get("source")
                target = edge.get("target")
                if not source or not target:
                    continue
                src_node = _lookup_node(source)
                dst_node = _lookup_node(target)
                if not isinstance(src_node, dict) or not isinstance(dst_node, dict):
                    skipped_missing_nodes += 1
                    if len(missing_examples) < 3:
                        missing_examples.append(
                            {
                                "source": source,
                                "target": target,
                                "source_type": type(source).__name__,
                                "target_type": type(target).__name__,
                                "label": relation,
                            }
                        )
                    continue
                add_bloodhound_path_edges(
                    membership_graph,
                    nodes=[src_node, dst_node],
                    relations=["MemberOf"],
                    status="discovered",
                    edge_type="membership_snapshot",
                    log_creation=False,
                )
                added += 1
            if skipped_missing_nodes:
                print_info_debug(
                    f"[bloodhound] Membership snapshot {label} skipped {skipped_missing_nodes} "
                    "edges due to missing nodes."
                )
                if missing_examples:
                    print_info_debug(
                        f"[bloodhound] Membership snapshot {label} missing node examples: "
                        f"{missing_examples}"
                    )
            return added

        user_edges = 0
        computer_edges = 0
        group_edges = 0
        try:
            user_graph = client.execute_query_with_relationships(user_query)
            user_edges = _append_graph_data(user_graph, label="user")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

        try:
            computer_graph = client.execute_query_with_relationships(computer_query)
            computer_edges = _append_graph_data(computer_graph, label="computer")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

        try:
            group_graph = client.execute_query_with_relationships(group_query)
            group_edges = _append_graph_data(group_graph, label="group")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

        memberships = membership_graph

        from adscan_internal.workspaces import domain_subpath, write_json_file

        workspace_cwd = (
            shell._get_workspace_cwd()
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", os.getcwd())
        )
        output_path = domain_subpath(
            workspace_cwd, shell.domains_dir, target_domain, "memberships.json"
        )
        write_json_file(output_path, memberships)
        return user_edges, group_edges, computer_edges

    for idx, (title, method_name, runner) in enumerate(steps, start=1):
        step_number = idx + step_offset
        print_step_status(
            title, status="running", step_number=step_number, total_steps=total_steps
        )
        raw_paths = None
        try:
            raw_paths = runner()
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_step_status(
                title, status="failed", step_number=step_number, total_steps=total_steps
            )
            last_error = None
            try:
                last_error = service.get_last_query_error()  # type: ignore[attr-defined]
            except Exception:
                last_error = None
            if last_error:
                print_info_debug(f"[bloodhound] last query error: {last_error}")
            print_warning(f"{method_name} returned no results.")
            continue

        certipy_templates: dict[str, Any] = {}
        if method_name in {"get_low_priv_adcs_paths", "get_certipy_adcs_paths"}:
            if isinstance(adcs_certipy_templates, dict):
                certipy_templates = adcs_certipy_templates
            else:
                try:
                    from adscan_internal.services.attack_graph_service import (
                        get_certipy_template_metadata,
                    )

                    certipy_templates = get_certipy_template_metadata(
                        shell, target_domain
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    certipy_templates = {}

        print_info_debug(
            f"[bloodhound] {method_name} rows: {len(raw_paths) if raw_paths else 0}"
        )
        if not raw_paths:
            print_step_status(
                title,
                status="completed",
                step_number=step_number,
                total_steps=total_steps,
            )
            print_info(f"{title}: 0 results; 0 attack steps recorded.")
            continue

        warned_relation_mismatches: set[str] = set()
        recorded_steps = 0
        sampled_steps: list[str] = []
        sampled_seen: set[str] = set()

        def _node_display_label(node: object) -> str:
            if not isinstance(node, dict):
                return str(node or "").strip()
            props = (
                node.get("properties")
                if isinstance(node.get("properties"), dict)
                else {}
            )
            name = (
                props.get("name")
                or props.get("samaccountname")
                or props.get("samAccountName")
                or node.get("name")
                or node.get("samaccountname")
                or node.get("samAccountName")
                or node.get("label")
                or node.get("objectId")
                or ""
            )
            return str(name or "").strip()

        for entry in raw_paths:
            nodes = entry.get("nodes") or []
            rels = entry.get("rels") or []
            if not nodes or not rels or len(nodes) < 2:
                continue

            relation_names = [_relation_name(rel) for rel in rels]
            notes_by_relation_index: dict[int, dict[str, Any]] = {}
            for rel_idx, rel in enumerate(relation_names):
                if not isinstance(rel, str):
                    continue
                rel_upper = rel.upper()
                if not rel_upper.startswith("ADCSESC"):
                    continue
                esc_tag = rel_upper.replace("ADCS", "")
                templates: list[dict[str, Any]] = []
                for tpl_name, meta in certipy_templates.items():
                    if not isinstance(meta, dict):
                        continue
                    vuln_list = meta.get("vulnerabilities") or []
                    if esc_tag in vuln_list:
                        templates.append(
                            {
                                "name": tpl_name,
                                "min_key_length": meta.get("min_key_length"),
                            }
                        )
                if templates:
                    template_labels = []
                    for tpl in templates:
                        name = tpl.get("name")
                        min_key = tpl.get("min_key_length")
                        if name and min_key:
                            template_labels.append(f"{name}(min_key={min_key})")
                        elif name:
                            template_labels.append(str(name))
                    summary_items = template_labels[:3]
                    remaining = len(template_labels) - len(summary_items)
                    if remaining > 0:
                        summary_items.append(f"+{remaining} more")
                    notes_by_relation_index[rel_idx] = {
                        "source": "certipy_json",
                        "templates": templates,
                        "templates_summary": ", ".join(summary_items),
                    }
                elif certipy_templates and rel_upper not in warned_relation_mismatches:
                    marked_domain = mark_sensitive(target_domain, "domain")
                    print_info_debug(
                        f"[bloodhound] no certipy templates matched {rel_upper} "
                        f"for {marked_domain}; JSON may be stale or scoped differently."
                    )
                    warned_relation_mismatches.add(rel_upper)
            added_edges = add_bloodhound_path_edges(
                graph,
                nodes=[node for node in nodes if isinstance(node, dict)],
                relations=relation_names,
                status="discovered",
                edge_type="entry_vector"
                if str(method_name) == "get_roastable_user_edges"
                else "bloodhound_ce",
                notes_by_relation_index=notes_by_relation_index or None,
                log_creation=False,
            )
            recorded_steps += int(added_edges or 0)
            if added_edges:
                unique_paths += 1

            if show_samples and sample_limit > 0 and len(sampled_steps) < sample_limit:
                for rel_idx, rel in enumerate(relation_names):
                    if rel_idx + 1 >= len(nodes):
                        break
                    left = _node_display_label(nodes[rel_idx])
                    right = _node_display_label(nodes[rel_idx + 1])
                    if not left or not right or not rel:
                        continue
                    step_str = f"{mark_sensitive(left, 'user')} -> {str(rel)} -> {mark_sensitive(right, 'user')}"
                    if step_str in sampled_seen:
                        continue
                    sampled_seen.add(step_str)
                    sampled_steps.append(step_str)
                    if len(sampled_steps) >= sample_limit:
                        break

        print_step_status(
            title, status="completed", step_number=step_number, total_steps=total_steps
        )
        print_info(
            f"{title}: results={len(raw_paths)}; attack steps recorded={recorded_steps}."
        )
        if method_name == "get_high_value_session_paths":
            _print_high_value_session_summary(
                domain=target_domain,
                paths=[entry for entry in raw_paths if isinstance(entry, dict)],
            )
        if show_samples and sampled_steps:
            title_text = f"{title} - discovered steps"
            if sample_limit > 0 and len(sampled_steps) >= sample_limit:
                title_text = f"{title} - discovered steps (showing {len(sampled_steps)}/{recorded_steps})"
            print_info_list(sampled_steps, title=title_text, icon="→")

    membership_step = total_steps - 1
    print_step_status(
        "Membership Snapshot",
        status="running",
        step_number=membership_step,
        total_steps=total_steps,
    )
    try:
        user_count, group_count, computer_count = _persist_membership_snapshot()
        print_step_status(
            "Membership Snapshot",
            status="completed",
            step_number=membership_step,
            total_steps=total_steps,
            details=f"users={user_count}, computers={computer_count}, groups={group_count}",
        )
        print_info(
            "Membership Snapshot: "
            f"membership steps recorded={user_count + group_count + computer_count} "
            f"(users={user_count}, computers={computer_count}, groups={group_count})."
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc, show_locals=False)
        print_step_status(
            "Membership Snapshot",
            status="failed",
            step_number=membership_step,
            total_steps=total_steps,
            details="membership export failed",
        )

    print_step_status(
        "Entry Node Reconciliation",
        status="running",
        step_number=total_steps,
        total_steps=total_steps,
    )
    try:
        from adscan_internal.services.attack_graph_service import (
            reconcile_entry_nodes,
        )

        reconciled = reconcile_entry_nodes(shell, target_domain, graph)
        if reconciled:
            save_attack_graph(shell, target_domain, graph)
        print_step_status(
            "Entry Node Reconciliation",
            status="completed",
            step_number=total_steps,
            total_steps=total_steps,
            details=f"reconciled={reconciled}",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc, show_locals=False)
        print_step_status(
            "Entry Node Reconciliation",
            status="failed",
            step_number=total_steps,
            total_steps=total_steps,
            details="reconciliation failed",
        )

    if unique_paths == 0:
        last_error = None
        try:
            last_error = service.get_last_query_error()  # type: ignore[attr-defined]
        except Exception:
            last_error = None
        if last_error:
            print_info_debug(f"[bloodhound] last query error: {last_error}")
        print_warning("No attack steps recorded from BloodHound.")
        return

    save_attack_graph(shell, target_domain, graph)

    # Persist recursive MemberOf edges so external consumers (e.g. web UI) can
    # compute paths identically without runtime LDAP/BH group expansion.
    try:
        from adscan_internal.services.attack_graph_service import (
            ATTACK_GRAPH_PERSIST_MEMBERSHIPS,
            persist_memberof_chain_edges,
        )
        from adscan_internal.workspaces import domain_subpath

        if ATTACK_GRAPH_PERSIST_MEMBERSHIPS:
            workspace_cwd = (
                shell._get_workspace_cwd()
                if hasattr(shell, "_get_workspace_cwd")
                else getattr(shell, "current_workspace_dir", os.getcwd())
            )
            memberships_path = domain_subpath(
                workspace_cwd, shell.domains_dir, target_domain, "memberships.json"
            )
            if os.path.exists(memberships_path):
                print_info_verbose(
                    f"[attack_graph] memberships.json already exists for {marked_domain}; "
                    "skipping persisted MemberOf edges."
                )
                skip_persist_memberships = True
            else:
                skip_persist_memberships = False
        else:
            skip_persist_memberships = True

        if ATTACK_GRAPH_PERSIST_MEMBERSHIPS and not skip_persist_memberships:
            edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
            candidate_node_ids: set[str] = set()
            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                for key in ("from", "to"):
                    nid = str(edge.get(key) or "")
                    if nid:
                        candidate_node_ids.add(nid)
            injected = persist_memberof_chain_edges(
                shell,
                target_domain,
                graph,
                principal_node_ids=candidate_node_ids,
                skip_tier0_principals=True,
            )
            if injected:
                marked_domain = mark_sensitive(target_domain, "domain")
                print_info_verbose(
                    f"[attack_graph] Persisted {injected} MemberOf edges for {marked_domain}."
                )
                save_attack_graph(shell, target_domain, graph)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(f"[attack_graph] Failed to persist MemberOf edges: {exc}")

    # Next step: look for high-value attack paths from owned users and optionally execute one.
    # When a domain is already marked as compromised ("pwned"), this prompt is redundant and noisy.
    if shell.domains_data.get(target_domain, {}).get("auth") == "pwned":
        marked_domain = mark_sensitive(target_domain, "domain")
        print_info_debug(
            f"[attack_paths] skipping owned-user path prompt for {marked_domain}: domain is pwned"
        )
        return
    owned_users = get_owned_domain_usernames(shell, target_domain)
    if owned_users:
        try:
            from adscan_internal.services.attack_graph_service import (
                _node_is_tier0,
                get_node_by_label,
            )

            filtered: list[str] = []
            for username in owned_users:
                label = f"{username}@{target_domain}"
                node = get_node_by_label(shell, target_domain, label=label)
                if node is None:
                    node = get_node_by_label(shell, target_domain, label=username)
                if node is not None and _node_is_tier0(node):
                    continue
                filtered.append(username)
            owned_users = filtered
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
    if owned_users:
        try:
            from adscan_internal.cli.owned_privileged_escalation import (
                offer_owned_privileged_escalation,
            )

            offer_owned_privileged_escalation(shell, target_domain)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[owned-priv] privileged membership pre-check failed: {exc}"
            )

        if shell.domains_data.get(target_domain, {}).get("auth") == "pwned":
            marked_domain = mark_sensitive(target_domain, "domain")
            print_info_debug(
                f"[attack_paths] skipping owned-user path prompt for {marked_domain}: domain is pwned"
            )
            return

        marked_domain = mark_sensitive(target_domain, "domain")
        print_info(
            "Searching for attack paths from owned users in "
            f"{marked_domain} (users: {len(owned_users)})"
        )
        offer_attack_paths_for_execution(
            shell,
            target_domain,
            start="owned",
            max_depth=max(10, max_depth),
            max_display=20,
            include_all=False,
        )
    else:
        # Fallback: show up to 10 maximal paths for transparency when no owned users exist yet.
        computed = compute_maximal_attack_paths(graph, max_depth=max(max_depth, 10))
        display_paths = [path_to_display_record(graph, path) for path in computed]
        display_paths = sorted(
            display_paths,
            key=lambda item: (
                int(item.get("length", 0))
                if str(item.get("length", "")).isdigit()
                else 0,
                str(item.get("source", "")).lower(),
                str(item.get("target", "")).lower(),
            ),
        )
        if display_paths:
            print_attack_paths_summary(
                target_domain,
                display_paths,
                max_display=20,
            )
            is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
            if (
                sys.stdin.isatty()
                and not is_ci
                and Confirm.ask("Show details for one of the paths?", default=False)
            ):
                max_index = min(20, len(display_paths))
                selection = Prompt.ask(
                    f"Select path index (1-{max_index})",
                    default="1",
                )
                try:
                    idx = int(selection)
                except ValueError:
                    idx = 1
                idx = max(1, min(max_index, idx))
                print_attack_path_detail(
                    target_domain, display_paths[idx - 1], index=idx
                )

    # Track TTFAP (Time To First Attack Path) for case study metrics
    # Use scan_start_time (not session_start_time) for accurate timing
    # Use time.monotonic() because system clock may be manipulated for Kerberos
    try:
        if unique_paths > 0:
            # Track attack paths count
            if hasattr(shell, "_session_attack_paths_count"):
                shell._session_attack_paths_count += unique_paths

            # Track TTFAP if this is the first attack path found in the session
            if (
                hasattr(shell, "_session_first_attack_path_time")
                and shell._session_first_attack_path_time is None
                and hasattr(shell, "scan_start_time")
                and shell.scan_start_time is not None
            ):
                import time as time_module

                shell._session_first_attack_path_time = time_module.monotonic()
                ttfap_seconds = max(
                    0.0, shell._session_first_attack_path_time - shell.scan_start_time
                )
                properties = {
                    "ttfap_seconds": round(ttfap_seconds, 2),
                    "ttfap_minutes": round(ttfap_seconds / 60.0, 2),
                    "paths_count": unique_paths,
                    "scan_mode": getattr(shell, "scan_mode", None),
                }
                properties.update(
                    build_lab_event_fields(shell=shell, include_slug=True)
                )
                telemetry.capture("metric_ttfap", properties)
    except Exception as exc:  # pragma: no cover - best effort
        telemetry.capture_exception(exc)

    print_success(f"Attack paths recorded: {unique_paths} (domain {marked_domain})")


def run_show_attack_paths(
    shell: BloodHoundShell,
    target_domain: str,
    *,
    start_user: str | None = None,
    index: int | None = None,
    max_display: int = 10,
    max_depth: int = 10,
    include_all: bool = False,
    include_impact: bool = False,
    allow_execution: bool = True,
    max_path_steps: int | None = None,
) -> None:
    """Show attack paths and optionally a detailed path."""
    from adscan_internal.services.attack_graph_service import (
        compute_display_paths_for_domain,
        compute_display_paths_for_owned_users,
        compute_display_paths_for_user,
        get_attack_paths_cache_stats,
        get_owned_domain_usernames,
    )
    from adscan_internal.services.membership_snapshot import (
        get_membership_snapshot_cache_stats,
    )
    from adscan_internal.services.cache_metrics import diff_stats
    from adscan_internal.rich_output import (
        print_attack_path_detail,
        print_attack_paths_summary,
    )
    from adscan_internal.cli.attack_path_execution import execute_selected_attack_path

    def _maybe_offer_execution(summary: dict[str, Any]) -> bool:
        if not allow_execution or not sys.stdin.isatty():
            return False
        if not Confirm.ask("Execute this attack path now?", default=True):
            return False
        execute_selected_attack_path(shell, target_domain, summary=summary)
        return True

    def _interactive_detail_loop(path_refs: list[dict[str, Any]]) -> None:
        """Interactive selection loop for showing per-path details."""
        is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))

        def _path_label(path: dict[str, object], idx: int) -> str:
            nodes = path.get("nodes") if isinstance(path.get("nodes"), list) else []
            source = str(path.get("source") or "")
            target = str(path.get("target") or "")
            if nodes and isinstance(nodes, list):
                source = source or str(nodes[0])
                target = target or str(nodes[-1])
            if not source or not target:
                title = str(path.get("title") or "")
                if "->" in title:
                    parts = [part.strip() for part in title.split("->")]
                    if len(parts) >= 2:
                        source = source or parts[0]
                        target = target or parts[-1]
            marked_source = (
                mark_sensitive(source, "hostname")
                if "." in source or source.endswith("$")
                else mark_sensitive(source, "user")
            )
            marked_target = (
                mark_sensitive(target, "hostname")
                if "." in target or target.endswith("$")
                else mark_sensitive(target, "user")
            )
            status = str(path.get("status") or "theoretical")
            return f"{idx}. {marked_source} -> {marked_target} [{status}]"

        while True:
            options = [
                _path_label(path, i + 1)
                for i, path in enumerate(path_refs[:max_display])
            ]
            options.append("Exit")

            selected_idx = None
            if is_ci or not sys.stdin.isatty():
                selected_idx = 0
            elif hasattr(shell, "_questionary_select"):
                selected_idx = shell._questionary_select(
                    "Select an attack path to view details:", options, default_idx=0
                )
            else:
                selection = Prompt.ask(
                    "Select an attack path index (or 0 to exit)",
                    default="1",
                )
                try:
                    selection_idx = int(selection)
                except ValueError:
                    selection_idx = 1
                if selection_idx <= 0:
                    selected_idx = len(options) - 1
                else:
                    selected_idx = min(selection_idx - 1, len(options) - 1)

            if selected_idx is None or selected_idx >= len(options) - 1:
                return

            selected = path_refs[selected_idx]
            print_attack_path_detail(target_domain, selected, index=selected_idx + 1)
            if _maybe_offer_execution(selected):
                # Refresh summaries after execution to reflect updated statuses.
                path_refs[:] = _compute_paths()
                if not path_refs:
                    return
                print_attack_paths_summary(
                    target_domain,
                    path_refs,
                    max_display=max_display,
                    max_path_steps=max_path_steps,
                )

    if target_domain not in shell.domains:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_domain}' is not configured. Please add or select a valid domain."
        )
        return

    cache_before = get_attack_paths_cache_stats(domain=target_domain)
    membership_cache_before = get_membership_snapshot_cache_stats()

    target_mode = "impact" if include_impact else "tier0"
    start_user_norm = (start_user or "").strip().lower()
    max_paths_compute = _resolve_attack_paths_compute_cap(max_display)

    status_order = {
        "theoretical": 0,
        "unavailable": 1,
        "unsupported": 2,
        "blocked": 3,
        "attempted": 4,
        "exploited": 5,
    }

    def _sort_paths(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            paths,
            key=lambda item: (
                status_order.get(str(item.get("status") or "").strip().lower(), 3),
                int(item.get("length", 0))
                if str(item.get("length", "")).isdigit()
                else 0,
                str(item.get("source", "")).lower(),
                str(item.get("target", "")).lower(),
            ),
        )

    def _compute_paths() -> list[dict[str, Any]]:
        if start_user_norm == "owned":
            owned_users = get_owned_domain_usernames(shell, target_domain)
            if not owned_users:
                marked_domain = mark_sensitive(target_domain, "domain")
                print_warning(
                    f"No owned domain users found for {marked_domain} (no stored domain credentials)."
                )
                return []
            owned_paths = compute_display_paths_for_owned_users(
                shell,
                target_domain,
                max_depth=max_depth,
                max_paths=max_paths_compute,
                require_high_value_target=not include_all,
                target_mode=target_mode,
            )
            if not owned_paths:
                marked_domain = mark_sensitive(target_domain, "domain")
                print_warning(
                    "No attack paths found for owned users in "
                    f"{marked_domain} (users: {len(owned_users)}). "
                    "Try `attack_paths <domain> owned --impact` for high-impact targets, "
                    "or `--all` to include all targets."
                )
                return []
            return _sort_paths(owned_paths)
        if start_user:
            user_paths = compute_display_paths_for_user(
                shell,
                target_domain,
                username=start_user,
                max_depth=max_depth,
                max_paths=max_paths_compute,
                require_high_value_target=not include_all,
                target_mode=target_mode,
            )
            return _sort_paths(user_paths)
        domain_paths = compute_display_paths_for_domain(
            shell,
            target_domain,
            max_depth=max_depth,
            max_paths=max_paths_compute,
            require_high_value_target=not include_all,
            target_mode=target_mode,
        )
        return _sort_paths(domain_paths)

    path_refs = _compute_paths()
    cache_after = get_attack_paths_cache_stats(domain=target_domain)
    membership_cache_after = get_membership_snapshot_cache_stats()

    cache_delta = diff_stats(
        before=cache_before,
        after=cache_after,
        keys=("hits", "misses", "stores", "skips", "evictions", "invalidations"),
    )
    snapshot_delta = diff_stats(
        before=membership_cache_before,
        after=membership_cache_after,
        keys=("hits", "misses", "reloads", "loaded"),
    )

    print_info_debug(
        "[attack_paths] cache summary: "
        f"domain={mark_sensitive(target_domain, 'domain')} "
        f"paths_hits={cache_delta['hits']} paths_misses={cache_delta['misses']} "
        f"paths_stores={cache_delta['stores']} paths_skips={cache_delta['skips']} "
        f"paths_evictions={cache_delta['evictions']} paths_invalidations={cache_delta['invalidations']} "
        f"membership_hits={snapshot_delta['hits']} membership_misses={snapshot_delta['misses']} "
        f"membership_reloads={snapshot_delta['reloads']} membership_loaded={snapshot_delta['loaded']}"
    )

    if not path_refs:
        print_warning("No attack paths recorded for this domain.")
        return
    print_attack_paths_summary(
        target_domain,
        path_refs,
        max_display=max_display,
        max_path_steps=max_path_steps,
    )

    if index is None:
        _interactive_detail_loop(path_refs)
        return

    if index < 1 or index > len(path_refs):
        print_warning("Invalid path index.")
        return

    selected = path_refs[index - 1]
    print_attack_path_detail(target_domain, selected, index=index)
    _maybe_offer_execution(selected)


def run_show_attack_steps(
    shell: BloodHoundShell,
    target_domain: str,
    *,
    start_user: str | None = None,
    max_display: int = 10,
    relation_filter: str | None = None,
) -> None:
    """Show raw attack-graph steps (edges) for a domain (optionally for one user)."""
    from adscan_internal.rich_output import (
        print_attack_steps_summary,
        print_error,
        print_warning,
    )
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.attack_graph_service import (
        compute_display_steps_for_domain,
    )

    if target_domain not in shell.domains:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_domain}' is not configured. Please add or select a valid domain."
        )
        return

    steps = compute_display_steps_for_domain(shell, target_domain, username=start_user)
    if relation_filter:
        wanted = {
            part.strip().lower()
            for part in str(relation_filter).split(",")
            if part.strip()
        }
        steps = [
            step
            for step in steps
            if str(step.get("action") or "").strip().lower() in wanted
        ]
    if not steps:
        if start_user:
            print_warning(
                f"No attack steps recorded for user {mark_sensitive(start_user, 'user')}."
            )
        else:
            print_warning("No attack steps recorded for this domain.")
        return

    print_attack_steps_summary(
        target_domain,
        steps,
        max_display=max_display,
        start_user=start_user,
    )


def enumerate_user_aces(
    shell: BloodHoundShell,
    domain: str,
    username: str,
    password: str,
    group: str | None = None,
    cross_domain: bool | None = None,
) -> None:
    """Enumerate critical ACEs via BloodHound CE and offer exploitation.

    This function was extracted from the legacy ``enumerate_user_aces`` method
    in `adscan.py` to separate CLI orchestration from the shell class.
    """
    from adscan_internal.bloodhound_legacy import (
        _check_bloodhound_ce_running,
        _start_bloodhound_ce,
        get_bloodhound_mode,
    )

    try:
        # Check BloodHound mode and ensure appropriate service is running
        bh_mode = get_bloodhound_mode()

        if bh_mode == "ce":
            # For BloodHound CE, ensure containers are running
            if not _check_bloodhound_ce_running():
                print_info("BloodHound CE is not running, starting containers...")
                if not _start_bloodhound_ce():
                    print_error("Failed to start BloodHound CE. Cannot enumerate ACEs.")
                    return
            print_info_verbose("BloodHound CE is ready for ACE enumeration")
        else:
            # For legacy mode, ensure Neo4j is running
            if not shell.ensure_neo4j_running():
                print_error("Neo4j is not running. Cannot enumerate ACEs.")
                return

        pwned_domains: list[str] = []
        if cross_domain:
            pwned_domains = [
                dom
                for dom, data in shell.domains_data.items()
                if data.get("auth", "").lower() == "pwned"
            ]

        used_high_value_filter = False
        output = ""

        if group:
            marked_group = mark_sensitive(group, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_info(
                f"Enumerating ACEs for group {marked_group} on high-value targets"
            )
            used_high_value_filter = True
            raw_aces = shell._get_bloodhound_service().get_critical_aces(  # type: ignore[attr-defined]
                source_domain=domain,
                high_value=True,
                username=group,
                target_domain="all",
                relation="all",
            )
        elif cross_domain:
            marked_domain = mark_sensitive(domain, "domain")
            print_info(f"Enumerating ACEs for domain {marked_domain} on other domains")
            raw_aces = shell._get_bloodhound_service().get_critical_aces(  # type: ignore[attr-defined]
                source_domain=domain,
                high_value=False,
                username="all",
                target_domain="all",
                relation="all",
            )
            if pwned_domains:
                blocked = {d.lower() for d in pwned_domains}
                raw_aces = [
                    a
                    for a in raw_aces
                    if str(a.get("targetDomain") or "").lower() not in blocked
                ]
        else:
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_info(
                f"Enumerating ACEs for user {marked_username} on high-value targets"
            )
            used_high_value_filter = True
            raw_aces = shell._get_bloodhound_service().get_critical_aces(  # type: ignore[attr-defined]
                source_domain=domain,
                high_value=True,
                username=username,
                target_domain="all",
                relation="all",
            )

        aces = []
        for ace in raw_aces or []:
            source_domain_value = str(ace.get("sourceDomain") or domain)
            target_domain_value = str(ace.get("targetDomain") or domain)
            if source_domain_value.lower() == "n/a":
                source_domain_value = domain
            if target_domain_value.lower() == "n/a":
                target_domain_value = domain

            aces.append(
                {
                    "origen": ace.get("source", ""),
                    "tipoorigen": ace.get("sourceType", "Unknown"),
                    "dominio_origen": source_domain_value,
                    "destino": ace.get("target", ""),
                    "tipodestino": ace.get("targetType", "Unknown"),
                    "dominio_destino": target_domain_value,
                    "acl": ace.get("relation", ""),
                    "target_enabled": bool(ace.get("targetEnabled", True)),
                }
            )

        # If no high-value ACEs were found and high-value filter was used, retry without it
        if not aces and not cross_domain and used_high_value_filter:
            print_error("No high-value ACEs found, retrying without --high-value...")
            used_high_value_filter = False
            if group:
                marked_group = mark_sensitive(group, "user")
                print_info(f"Enumerating ACEs for group {marked_group}")
            elif not cross_domain:
                marked_username = mark_sensitive(username, "user")
                print_info(f"Enumerating ACEs for user {marked_username}")
            raw_aces = shell._get_bloodhound_service().get_critical_aces(  # type: ignore[attr-defined]
                source_domain=domain,
                high_value=False,
                username=(group or username or "all"),
                target_domain="all",
                relation="all",
            )
            aces = []
            for ace in raw_aces or []:
                source_domain_value = str(ace.get("sourceDomain") or domain)
                target_domain_value = str(ace.get("targetDomain") or domain)
                if source_domain_value.lower() == "n/a":
                    source_domain_value = domain
                if target_domain_value.lower() == "n/a":
                    target_domain_value = domain
                aces.append(
                    {
                        "origen": ace.get("source", ""),
                        "tipoorigen": ace.get("sourceType", "Unknown"),
                        "dominio_origen": source_domain_value,
                        "destino": ace.get("target", ""),
                        "tipodestino": ace.get("targetType", "Unknown"),
                        "dominio_destino": target_domain_value,
                        "acl": ace.get("relation", ""),
                        "target_enabled": bool(ace.get("targetEnabled", True)),
                    }
                )

        if aces:
            aces_to_process = []
            retried_without_high_value = False

            while True:
                filtered_aces, skipped_aces = shell._filter_aces_by_adcs_requirement(
                    aces
                )

                if filtered_aces:
                    header_section = shell._extract_acl_header(output)
                    if header_section:
                        shell.console.print(header_section)  # type: ignore[attr-defined]
                    for ace_block in filtered_aces:
                        shell.console.print(shell._format_acl_block(ace_block))  # type: ignore[attr-defined]
                    aces_to_process = filtered_aces
                    break

                if (
                    not cross_domain
                    and used_high_value_filter
                    and not retried_without_high_value
                ):
                    if not aces:
                        print_error(
                            "No high-value ACEs found, retrying without --high-value..."
                        )
                    else:
                        print_info(
                            "No actionable high-value ACEs found, retrying without --high-value..."
                        )
                    retried_without_high_value = True
                    used_high_value_filter = False

                    raw_aces = shell._get_bloodhound_service().get_critical_aces(  # type: ignore[attr-defined]
                        source_domain=domain,
                        high_value=False,
                        username=(group or username or "all"),
                        target_domain="all",
                        relation="all",
                    )
                    aces = []
                    for ace in raw_aces or []:
                        source_domain_value = str(ace.get("sourceDomain") or domain)
                        target_domain_value = str(ace.get("targetDomain") or domain)
                        if source_domain_value.lower() == "n/a":
                            source_domain_value = domain
                        if target_domain_value.lower() == "n/a":
                            target_domain_value = domain

                        aces.append(
                            {
                                "origen": ace.get("source", ""),
                                "tipoorigen": ace.get("sourceType", "Unknown"),
                                "dominio_origen": source_domain_value,
                                "destino": ace.get("target", ""),
                                "tipodestino": ace.get("targetType", "Unknown"),
                                "dominio_destino": target_domain_value,
                                "acl": ace.get("relation", ""),
                                "target_enabled": bool(ace.get("targetEnabled", True)),
                            }
                        )
                    continue

                if skipped_aces:
                    print_info(
                        "No actionable ACEs after filtering ADCS-dependent entries."
                    )
                else:
                    print_error("No ACEs found for this user")
                return

            # Process ACEs and offer exploitation options
            if aces_to_process:
                _process_aces_for_exploitation(
                    shell,
                    aces_to_process,
                    domain,
                    username,
                    password,
                    cross_domain=cross_domain,
                )
        else:
            print_warning("No critical ACEs found for enumeration.")

    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            f"ACE enumeration failure details: type={type(exc).__name__} message={exc}"
        )
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Error enumerating ACEs for domain {marked_domain}.")
        print_exception(show_locals=False, exception=exc)


def _process_aces_for_exploitation(
    shell: BloodHoundShell,
    aces_to_process: list[dict],
    domain: str,
    username: str,
    password: str,
    *,
    cross_domain: bool | None = None,
) -> None:
    """Process ACEs and offer exploitation options (legacy parity)."""
    exchange_ace = None
    for ace in aces_to_process:
        if (
            "genericall" in ace.get("acl", "").lower()
            and ace.get("destino", "").lower() == "exchange windows permissions"
        ):
            exchange_ace = ace
            print_warning(
                "There is an ACE with GenericAll on 'Exchange Windows Permissions'"
            )
            break

    for ace in aces_to_process:
        try:
            acl = ace.get("acl", "").lower()
            target_username = ace.get("destino", "")
            target_domain = ace.get("dominio_destino", "")
            display_name = mark_sensitive(target_username, "user")

            if cross_domain:
                username = ace.get("origen", username)
                password = shell.domains_data[domain]["credentials"][username]

            if "forcechangepassword" in acl:
                respuesta = Confirm.ask(
                    "Do you want to exploit the ForceChangePassword privilege on "
                    f"{display_name}?",
                    default=True,
                )
                if respuesta:
                    shell.exploit_force_change_password(
                        domain,
                        username,
                        password,
                        target_username,
                        target_domain,
                    )

            if "writespn" in acl:
                target_type = ace.get("tipodestino", "").lower()
                if target_type not in {"user", "computer"}:
                    print_warning(
                        f"WriteSPN exploitation is only supported for user/computer targets (got {target_type})."
                    )
                else:
                    respuesta = Confirm.ask(
                        "Do you want to exploit WriteSPN (Targeted Kerberoast) on "
                        f"{display_name}?",
                        default=True,
                    )
                    if respuesta:
                        shell.exploit_write_spn(
                            domain,
                            username,
                            password,
                            target_username,
                            target_domain,
                        )

            if "genericall" in acl or "genericwrite" in acl:
                if exchange_ace is not None and ace != exchange_ace:
                    continue

                target_type = ace.get("tipodestino", "").lower()
                if target_type in ("user", "computer"):
                    if not ace.get("target_enabled", True):
                        print_warning(f"Target user {display_name} is disabled.")
                        enable_respuesta = Confirm.ask(
                            "Do you want to try to enable the account first?",
                            default=True,
                        )
                        if enable_respuesta:
                            if not shell.enable_user(
                                domain, username, password, target_username
                            ):
                                print_error(
                                    f"Could not enable {display_name}. Skipping exploitation."
                                )
                                continue
                        else:
                            print_info(
                                f"Skipping exploitation for disabled user {display_name}."
                            )
                            continue

                    respuesta = Confirm.ask(
                        "Do you want to exploit the GenericAll/GenericWrite "
                        f"privilege on {display_name}?",
                        default=True,
                    )
                    if respuesta:
                        shell.exploit_generic_all_user(
                            domain,
                            username,
                            password,
                            target_username,
                            target_domain,
                        )
                elif target_type == "ou":
                    respuesta = Confirm.ask(
                        "Do you want to exploit the GenericAll/GenericWrite "
                        f"privilege on {display_name}?",
                        default=True,
                    )
                    if respuesta:
                        shell.exploit_generic_all_ou(
                            domain,
                            username,
                            password,
                            target_username,
                            target_domain,
                        )
                elif target_type == "group":
                    respuesta = Confirm.ask(
                        "Do you want to exploit the GenericAll/GenericWrite "
                        f"privilege on {display_name}?",
                        default=True,
                    )
                    if respuesta:
                        marked_username = mark_sensitive(username, "user")
                        changed_username = Prompt.ask(
                            "Enter the user you want to add: ",
                            default=marked_username,
                        )
                        shell.exploit_add_member(
                            domain,
                            username,
                            password,
                            target_username,
                            changed_username,
                            target_domain,
                        )

            if "addself" in acl:
                respuesta = Confirm.ask(
                    f"Do you want to exploit the AddSelf privilege on {display_name}?",
                    default=True,
                )
                if respuesta:
                    shell.exploit_add_member(
                        domain,
                        username,
                        password,
                        target_username,
                        username,
                        target_domain,
                    )

            if "addmember" in acl:
                respuesta = Confirm.ask(
                    f"Do you want to exploit the AddMember privilege on {display_name}?",
                    default=True,
                )
                if respuesta:
                    marked_username = mark_sensitive(username, "user")
                    changed_username = Prompt.ask(
                        "Enter the user you want to add: ",
                        default=marked_username,
                    )
                    shell.exploit_add_member(
                        domain,
                        username,
                        password,
                        target_username,
                        changed_username,
                        target_domain,
                    )

            if "readgmsapassword" in acl:
                respuesta = Confirm.ask(
                    "Do you want to exploit the ReadGMSAPassword privilege on "
                    f"{display_name}?",
                    default=True,
                )
                if respuesta:
                    shell.exploit_gmsa_account(
                        domain, username, password, target_username, target_domain
                    )

            if "readlapspassword" in acl:
                respuesta = Confirm.ask(
                    "Do you want to exploit the ReadLAPSPassword privilege on "
                    f"{display_name}?",
                    default=True,
                )
                if respuesta:
                    target_computer = f"{target_username.rstrip('$')}.{target_domain}"
                    shell.exploit_laps_password(
                        domain, username, password, target_computer, target_domain
                    )

            if "writedacl" in acl:
                target_type = ace.get("tipodestino", "").lower()
                if target_type in ("user", "group", "domain"):
                    marked_destino = mark_sensitive(
                        target_username, "domain" if target_type == "domain" else "user"
                    )
                    respuesta = Confirm.ask(
                        "Do you want to exploit the WriteDacl privilege on "
                        f"{marked_destino}?",
                        default=True,
                    )
                    if respuesta:
                        writedacl_ok = bool(
                            shell.exploit_write_dacl(
                                domain,
                                username,
                                password,
                                target_username,
                                target_domain,
                                target_type,
                            )
                        )
                        if writedacl_ok and target_type == "domain":
                            shell.ask_for_dcsync(domain, username, password)
                        elif writedacl_ok and target_type == "user":
                            shell.exploit_generic_all_user(
                                domain,
                                username,
                                password,
                                target_username,
                                target_domain,
                                prompt_for_user_privs_after=True,
                            )
                        elif writedacl_ok and target_type == "group":
                            marked_username = mark_sensitive(username, "user")
                            changed_username = Prompt.ask(
                                "Enter the user you want to add: ",
                                default=marked_username,
                            )
                            shell.exploit_add_member(
                                domain,
                                username,
                                password,
                                target_username,
                                changed_username,
                                target_domain,
                            )

            if "writeowner" in acl:
                target_type = ace.get("tipodestino", "").lower()
                if target_type in ("group", "user"):
                    respuesta = Confirm.ask(
                        "Do you want to exploit the WriteOwner privilege on "
                        f"{display_name}?",
                        default=True,
                    )
                    if respuesta:
                        writeowner_ok = bool(
                            shell.exploit_write_owner(
                                domain,
                                username,
                                password,
                                target_username,
                                target_domain,
                                target_type,
                            )
                        )
                        if writeowner_ok:
                            marked_destino = mark_sensitive(target_username, "user")
                            writedacl_respuesta = Confirm.ask(
                                "WriteOwner applied successfully. Do you want to "
                                f"try WriteDacl on {marked_destino} now?",
                                default=True,
                            )
                            if writedacl_respuesta:
                                shell.exploit_write_dacl(
                                    domain,
                                    username,
                                    password,
                                    target_username,
                                    target_domain,
                                    target_type,
                                )

            if "dcsync" in acl:
                marked_destino = mark_sensitive(target_username, "domain")
                respuesta = Confirm.ask(
                    "Do you want to exploit the DCSync privilege on domain "
                    f"{marked_destino}?",
                    default=True,
                )
                if respuesta:
                    shell.dcsync(domain, username, password)

        except Exception as exc:
            telemetry.capture_exception(exc)
            continue


def parse_bloodhound_acls(output: str) -> list[dict]:
    """Parse the output of bloodhound-cli acl and return a list of ACEs.

    This function was extracted from the legacy ``parse_bloodhound_acls`` method
    in `adscan.py` to separate BloodHound parsing logic from the shell class.

    Args:
        output: The raw output string from bloodhound-cli acl command

    Returns:
        List of ACE dictionaries with keys: origen, tipoorigen, dominio_origen,
        destino, tipodestino, dominio_destino, acl, target_enabled
    """
    aces = []
    current_ace = {}

    # Split the output into lines
    lines = output.strip().split("\n")

    for line in lines:
        line = line.strip()

        # Skip empty lines and headers
        if not line or line.startswith("ACEs for user:") or line.startswith("==="):
            continue

        # If we find a separator line, save the current ACE and start a new one
        if line.startswith("---"):
            if current_ace:
                # Default target_enabled to True if not found
                if "target_enabled" not in current_ace:
                    current_ace["target_enabled"] = True

                # Check that we have all the required fields before adding
                required_fields = [
                    "origen",
                    "tipoorigen",
                    "dominio_origen",
                    "destino",
                    "tipodestino",
                    "dominio_destino",
                    "acl",
                ]
                if all(field in current_ace for field in required_fields):
                    aces.append(current_ace)
            current_ace = {}
            continue

        # Process data line
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            # Map the keys
            key_mapping = {
                "source": "origen",
                "source type": "tipoorigen",
                "source domain": "dominio_origen",
                "target": "destino",
                "target type": "tipodestino",
                "target domain": "dominio_destino",
                "relation": "acl",
            }

            if key in key_mapping:
                current_ace[key_mapping[key]] = value
            elif key == "target enabled":  # Handle the new key
                # The value will be 'False' when the target is disabled.
                current_ace["target_enabled"] = value.lower() == "true"

    # Add the last ACE if it exists and the file doesn't end with a separator
    if current_ace:
        if "target_enabled" not in current_ace:
            current_ace["target_enabled"] = True
        required_fields = [
            "origen",
            "tipoorigen",
            "dominio_origen",
            "destino",
            "tipodestino",
            "dominio_destino",
            "acl",
        ]
        if all(field in current_ace for field in required_fields):
            aces.append(current_ace)

    return aces


# ============================================================================
# User Enumeration Functions
# ============================================================================


def run_bloodhound_users(shell: BloodHoundShell, target_domain: str) -> None:
    """Create BloodHound user lists for the specified domain.

    Three lists are created: all users, admin users, and privileged users.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate users for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    run_bloodhound_all_users(shell, target_domain)
    run_bloodhound_admin_users(shell, target_domain)
    run_bloodhound_privileged_users(shell, target_domain)


def run_bloodhound_all_users(shell: BloodHoundShell, target_domain: str) -> None:
    """Create a BloodHound user list for the specified domain and save it to a file.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate users for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    try:
        users = shell._get_bloodhound_service().get_users(domain=target_domain)
        shell._write_user_list_file(target_domain, "enabled_users.txt", users)
        shell._postprocess_user_list_file(target_domain, "enabled_users.txt")
        return
    except Exception as e:
        telemetry.capture_exception(e)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"BloodHound user query failed for {marked_target_domain}. Ensure data is ingested in BloodHound CE."
        )
        print_exception(show_locals=False, exception=e)
        return


def run_bloodhound_admin_users(shell: BloodHoundShell, target_domain: str) -> None:
    """Create a BloodHound admin user list for the specified domain and save it to a file.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate admin users for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    try:
        users = shell._get_bloodhound_service().get_users(
            domain=target_domain, filter_type="high_value"
        )
        shell._write_user_list_file(target_domain, "admins.txt", users)
        shell._postprocess_user_list_file(target_domain, "admins.txt")
        return
    except Exception as e:
        telemetry.capture_exception(e)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"BloodHound high-value user query failed for {marked_target_domain}. Ensure data is ingested in BloodHound CE."
        )
        print_exception(show_locals=False, exception=e)
        return


def run_bloodhound_privileged_users(shell: BloodHoundShell, target_domain: str) -> None:
    """Create a BloodHound privileged user list for the specified domain and save it to a file.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate privileged users for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    try:
        users = shell._get_bloodhound_service().get_users(
            domain=target_domain, filter_type="admin"
        )
        shell._write_user_list_file(target_domain, "privileged.txt", users)
        shell._postprocess_user_list_file(target_domain, "privileged.txt")
        return
    except Exception as e:
        telemetry.capture_exception(e)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"BloodHound admincount user query failed for {marked_target_domain}. Ensure data is ingested in BloodHound CE."
        )
        print_exception(show_locals=False, exception=e)
        return


def ask_for_bloodhound_users(shell: BloodHoundShell, target_domain: str) -> None:
    """Ask user if they want to enumerate BloodHound users for the domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate users for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    if shell.auto:
        run_bloodhound_users(shell, target_domain)
    else:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        if Confirm.ask(
            f"Do you want to enumerate BloodHound users for the domain {marked_target_domain}?",
            default=True,
        ):
            run_bloodhound_users(shell, target_domain)


# ============================================================================
# Password Policy Functions
# ============================================================================


def run_bloodhound_pwdneverexpires(shell: BloodHoundShell, domain: str) -> None:
    """Create a list of users with password never expires in the specified domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        domain: Domain name to query
    """
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Searching for users with password never expiring on domain {marked_domain}"
    )
    try:
        users = shell._get_bloodhound_service().get_users(
            domain=domain, filter_type="pwd_never_expires"
        )
        shell._write_user_list_file(domain, "pwdneverexpires.txt", users)
        execute_bloodhound_passnotreq(
            shell, None, domain, "pwdneverexpires.txt", users=users
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to query BloodHound for password-never-expires users.")
        print_exception(show_locals=False, exception=exc)


def run_bloodhound_passnotreq(shell: BloodHoundShell, domain: str) -> None:
    """Create a list of users with password not required in the specified domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        domain: Domain name to query
    """
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Searching for users with password not required on domain {marked_domain}"
    )
    try:
        users = shell._get_bloodhound_service().get_users(
            domain=domain, filter_type="pwd_not_required"
        )
        shell._write_user_list_file(domain, "passnotreq.txt", users)
        execute_bloodhound_passnotreq(
            shell, None, domain, "passnotreq.txt", users=users
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to query BloodHound for password-not-required users.")
        print_exception(show_locals=False, exception=exc)


def execute_bloodhound_passnotreq(
    shell: BloodHoundShell,
    command: str | None,
    domain: str,
    file: str,
    users: list[str] | None = None,
) -> None:
    """Execute the BloodHound command to find users with specific password policies.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        command: Command string (legacy, not used when users is provided)
        domain: Domain name
        file: Output filename
        users: List of users (if None, will read from file)
    """
    try:
        if users is None:
            print_info_verbose(f"Executing BloodHound command for {file}: {command}")
            completed_process = shell.run_command(command, timeout=300)
            errors = completed_process.stderr
            if completed_process.returncode != 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Error creating the user list via BloodHound for domain {marked_domain}:"
                )
                if errors:
                    print_error(errors.strip())
                return

            workspace_cwd = shell._get_workspace_cwd()
            users_file = domain_subpath(workspace_cwd, shell.domains_dir, domain, file)
            try:
                with open(users_file, "r", encoding="utf-8") as f:
                    users = [line.strip() for line in f if line.strip()]
            except Exception as e:
                telemetry.capture_exception(e)
                print_error("Error reading the users file.")
                print_exception(show_locals=False, exception=e)
                return

        # Define the key to update based on the file
        if file == "passnotreq.txt":
            key = "password_not_req"
            title = "Users with Password Not Required"
        elif file == "pwdneverexpires.txt":
            key = "password_never_expires"
            title = "Users with Password Never Expires"
        else:
            key = file
            title = "Users"

        value = users if users else None
        shell.update_report_field(domain, key, value)
        shell._display_items(users or [], title)
    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Error creating the user list via BloodHound for domain {marked_domain}: {str(e)}"
        )
        print_exception(show_locals=False, exception=e)


# ============================================================================
# DC Access Functions
# ============================================================================


def run_bloodhound_dc_access(shell: BloodHoundShell, domain: str) -> None:
    """Check non-admin users access privileges on DCs on domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        domain: Domain name to query
    """
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Checking non admin users access privs on DCs on domain {marked_domain}"
    )
    try:
        paths = shell._get_bloodhound_service().get_users_with_dc_access(domain)
        execute_bloodhound_dc_access(shell, None, domain, paths=paths)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to query BloodHound for DC access paths.")
        print_exception(show_locals=False, exception=exc)


def execute_bloodhound_dc_access(
    shell: BloodHoundShell,
    command: str | None,
    domain: str,
    paths: list[dict] | None = None,
) -> None:
    """Execute the BloodHound command and process the output for DC access.

    For each target (destino) and each relation (acl):
    - If more than 10 accounts possess the relation, print the count.
    - Otherwise, print the account names.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        command: Command string (legacy, not used when paths is provided)
        domain: Domain name
        paths: List of access path dictionaries (if None, will execute command)
    """
    try:
        if paths is None:
            print_info_verbose(f"Executing BloodHound DC access check: {command}")
            completed_process = shell.run_command(command, timeout=300)
            stdout = completed_process.stdout
            stderr = completed_process.stderr

            if completed_process.returncode != 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Error executing BloodHound DC access command for domain {marked_domain} (Return Code: {completed_process.returncode}):"
                )
                if stderr:
                    print_error(f"Stderr: {stderr.strip()}")
                elif stdout:
                    print_error(f"Stdout: {stdout.strip()}")
                return

            if stderr:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"Warnings/errors from BloodHound DC access command for domain {marked_domain}: {stderr.strip()}"
                )

            paths = []
            if stdout:
                paths = parse_bloodhound_acls(stdout)
            else:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"No stdout received from BloodHound DC access check for domain {marked_domain}."
                )

        aces = []
        for entry in paths or []:
            if "acl" in entry and "destino" in entry:
                aces.append(entry)
                continue
            # BloodHoundService returns dicts like: {source, target, path}
            src = entry.get("source") or ""
            tgt = entry.get("target") or ""
            relation = entry.get("relation") or ""
            path_text = entry.get("path") or ""
            if not relation and path_text:
                match = re.search(r"\\(([^)]+)\\)\\s*$", path_text)
                if match:
                    relation = match.group(1)

            if src and tgt:
                aces.append(
                    {
                        "origen": src,
                        "tipoorigen": "User",
                        "dominio_origen": domain,
                        "destino": tgt,
                        "tipodestino": "Computer",
                        "dominio_destino": domain,
                        "acl": relation or "Unknown",
                        "target_enabled": True,
                    }
                )

        # Group the ACEs by target (destino) and relation (acl)
        groups = {}
        for ace in aces:
            target = ace.get("destino")
            relation = ace.get("acl")
            account = ace.get("origen")
            if target and relation and account:
                key = (target, relation)
                groups.setdefault(key, []).append(account)

        # Display the results:
        # If there are more than 10 accounts, display the count.
        # Otherwise, list the account names.
        for (target, relation), accounts in groups.items():
            if len(accounts) > 10:
                print_warning(
                    f"Target: {target}, Relation: {relation} -> Accounts count: {len(accounts)}"
                )
            else:
                accounts_list = ", ".join(accounts)
                print_warning(
                    f"Target: {target}, Relation: {relation} -> Accounts: {accounts_list}"
                )

    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Exception during execution of bloodhound command for domain {marked_domain}: {str(e)}"
        )


# ============================================================================
# KRBTGT Functions
# ============================================================================


def run_bloodhound_krbtgt(shell: BloodHoundShell, domain: str) -> None:
    """Check the last password change of the 'krbtgt' user in the given domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        domain: Domain name to check
    """
    marked_domain = mark_sensitive(domain, "domain")
    bh_cli = shell._get_bloodhound_cli_path()
    if not bh_cli:
        return
    command = f"{bh_cli} user --password-last-change -d {marked_domain} -u krbtgt"
    print_info(f"Checking kbrtgt's last password change on domain {marked_domain}")
    execute_bloodhound_krbtgt(shell, command, domain)


def execute_bloodhound_krbtgt(
    shell: BloodHoundShell, command: str, domain: str
) -> None:
    """Execute the bloodhound-cli command, parse the output, extract the last password change date.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        command: Command to execute
        domain: Domain name
    """
    try:
        # Execute the command and capture its output without freezing the interactive shell
        completed_process = shell.run_command(command, timeout=60)
        output = completed_process.stdout
    except Exception as e:
        telemetry.capture_exception(e)
        # If the command execution fails, log error and exit the function
        print_error(f"Error executing bloodhound-cli command: {e}")
        return

    # Check that the expected string is present in the command output
    if "User: krbtgt | Password Last Change:" in output:
        # Use regex to extract the date string after the indicator text
        match = re.search(r"User: krbtgt \| Password Last Change:\s*(.*)", output)
        if match:
            date_str = match.group(1).strip()
            # Remove the "UTC" suffix if it exists for proper parsing
            date_str = date_str.replace("UTC", "").strip()
            try:
                # Parse the date. The expected format is "Friday, 2011-03-18 09:15:38"
                last_change = datetime.strptime(date_str, "%A, %Y-%m-%d %H:%M:%S")
                # Make the parsed datetime timezone-aware by assigning UTC
                last_change = last_change.replace(tzinfo=timezone.utc)
                # Get the current time in UTC as a timezone-aware datetime.
                # This intentionally uses wall-clock time because we care
                # about calendar age, not monotonic duration.
                now = datetime.now(timezone.utc)
                diff = now - last_change
                # Determine if the difference is one year (365 days) or more
                flag = diff.days >= 365
                shell.update_report_field(domain, "krbtgt_pass", flag)
                marked_domain = mark_sensitive(domain, "domain")
                print_success(
                    f"krbtgt password was changed last time in {date_str} in domain {marked_domain}"
                )
            except ValueError as e:
                telemetry.capture_exception(e)
                # If parsing the date fails, log an error message
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Unable to parse the date for krbtgt in domain {marked_domain}"
                )
    else:
        # If the expected string is missing in the output, log an error message
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Unable to find the expected string for krbtgt in domain {marked_domain}"
        )


# ============================================================================
# Computer Enumeration Functions
# ============================================================================


def ask_for_bloodhound_computers(shell: BloodHoundShell, target_domain: str) -> None:
    """Ask user if they want to enumerate BloodHound computers for the domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computers for
    """
    if shell.auto:
        run_bloodhound_computers(shell, target_domain)
    else:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        answer = Confirm.ask(
            f"Do you want to enumerate BloodHound computers for the domain {marked_target_domain}?"
        )
        if answer:
            run_bloodhound_computers(shell, target_domain)


def run_bloodhound_computers(shell: BloodHoundShell, target_domain: str) -> None:
    """Create computer lists for the specified domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computers for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    run_bloodhound_computers_all(shell, target_domain)
    if shell.type == "ctf":
        return
    if shell.auto:
        run_bloodhound_computers_with_laps(shell, target_domain)
        run_bloodhound_computers_without_laps(shell, target_domain)
    else:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        if Confirm.ask(
            f"Do you want to enumerate computers with/without LAPS for the domain {marked_target_domain}?"
        ):
            run_bloodhound_computers_with_laps(shell, target_domain)
            run_bloodhound_computers_without_laps(shell, target_domain)
        marked_target_domain = mark_sensitive(target_domain, "domain")


def run_bloodhound_computers_all(shell: BloodHoundShell, target_domain: str) -> None:
    """Create a list of enabled computers for the specified domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computers for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    try:
        computers = shell._get_bloodhound_service().get_computers(domain=target_domain)
        shell._process_bloodhound_computers_list(
            target_domain, "enabled_computers.txt", computers
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Error enumerating computers via BloodHound for domain {marked_target_domain}."
        )
        print_exception(show_locals=False, exception=exc)


def run_bloodhound_computers_with_laps(
    shell: BloodHoundShell, target_domain: str
) -> None:
    """Create a list of enabled computers with LAPS for the specified domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computers for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    marked_target_domain = mark_sensitive(target_domain, "domain")
    print_info(
        f"Searching for enabled computers with LAPS on domain {marked_target_domain}"
    )
    try:
        computers = shell._get_bloodhound_service().get_computers(
            domain=target_domain, laps_filter=True
        )
        execute_bloodhound_laps(
            shell,
            None,
            target_domain,
            "enabled_computers_with_laps.txt",
            computers=computers,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error enumerating LAPS-enabled computers via BloodHound.")
        print_exception(show_locals=False, exception=exc)


def run_bloodhound_computers_without_laps(
    shell: BloodHoundShell, target_domain: str
) -> None:
    """Create a list of enabled computers without LAPS for the specified domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computers for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    marked_target_domain = mark_sensitive(target_domain, "domain")
    print_info(
        f"Searching for enabled computers without LAPS on domain {marked_target_domain}"
    )
    try:
        computers = shell._get_bloodhound_service().get_computers(
            domain=target_domain, laps_filter=False
        )
        execute_bloodhound_laps(
            shell,
            None,
            target_domain,
            "enabled_computers_without_laps.txt",
            computers=computers,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error enumerating non-LAPS computers via BloodHound.")
        print_exception(show_locals=False, exception=exc)


def execute_bloodhound_laps(
    shell: BloodHoundShell,
    command: str | None,
    domain: str,
    comp_file: str,
    computers: list[str] | None = None,
) -> None:
    """Execute the BloodHound LAPS computer enumeration command and process the output.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        command: Command string (legacy, not used when computers is provided)
        domain: Domain name
        comp_file: Output filename
        computers: List of computers (if None, will execute command)
    """
    try:
        if computers is None:
            print_info_verbose("Executing BloodHound LAPS computer enumeration")
            completed_process = shell.run_command(command, timeout=300)
            errors = completed_process.stderr
            if completed_process.returncode != 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Error enumerating computers in domain with/without LAPS {marked_domain}."
                )
                if errors:
                    print_error(errors)
                return
        else:
            errors = ""

        if computers is not None:
            shell._write_domain_list_file(domain, comp_file, computers)

        marked_domain = mark_sensitive(domain, "domain")
        print_success_verbose(
            f"LAPS computer list ({comp_file}) successfully generated for domain {marked_domain}."
        )
        # Path to the computers file within the domain directory
        workspace_cwd = shell._get_workspace_cwd()
        computers_file = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, comp_file
        )
        try:
            # Read the computers file (ignoring empty lines)
            with open(computers_file, "r", encoding="utf-8") as file:
                computers = [line.strip() for line in file if line.strip()]
            count = len(computers)

            # Classify computers into DCs and non-DCs
            dc_list = []
            non_dc_list = []
            for computer in computers:
                if shell.is_computer_dc(domain, computer):
                    dc_list.append(computer)
                else:
                    non_dc_list.append(computer)
            count_dc = len(dc_list)
            count_non_dc = len(non_dc_list)

            def _write_host_list(path: str, hosts: list[str]) -> None:
                with open(path, "w", encoding="utf-8") as file_handle:
                    for host in hosts:
                        file_handle.write(host + "\n")

            def _render_laps_inventory_panel(
                *,
                laps_state_label: str,
                border_style: str,
                dc_file: str | None,
                non_dc_file: str | None,
            ) -> None:
                marked_domain_local = mark_sensitive(domain, "domain")
                marked_main_file = mark_sensitive(
                    os.path.join(shell.domains_dir, domain, comp_file), "path"
                )
                marked_dc_file = mark_sensitive(dc_file, "path") if dc_file else "N/A"
                marked_non_dc_file = (
                    mark_sensitive(non_dc_file, "path") if non_dc_file else "N/A"
                )
                dc_ratio = (count_dc / count * 100.0) if count > 0 else 0.0
                non_dc_ratio = (count_non_dc / count * 100.0) if count > 0 else 0.0
                print_panel(
                    "\n".join(
                        [
                            f"Domain: {marked_domain_local}",
                            f"LAPS state: {laps_state_label}",
                            f"Total enabled computers: {count}",
                            f"Domain Controllers: {count_dc} ({dc_ratio:.1f}%)",
                            f"Non-DC computers: {count_non_dc} ({non_dc_ratio:.1f}%)",
                            "",
                            "Artifacts",
                            f"- Full inventory: {marked_main_file}",
                            f"- DC subset: {marked_dc_file}",
                            f"- Non-DC subset: {marked_non_dc_file}",
                        ]
                    ),
                    title="LAPS Inventory Summary",
                    border_style=border_style,
                    fit=True,
                )

                dc_preview = [mark_sensitive(host, "hostname") for host in dc_list[:5]]
                non_dc_preview = [
                    mark_sensitive(host, "hostname") for host in non_dc_list[:5]
                ]
                if dc_preview:
                    print_info_list(
                        dc_preview,
                        title=f"DC sample ({len(dc_list)} total)",
                        icon="🖥️",
                    )
                if non_dc_preview:
                    print_info_list(
                        non_dc_preview,
                        title=f"Non-DC sample ({len(non_dc_list)} total)",
                        icon="💻",
                    )

            # Depending on the file (with or without LAPS), print and generate the corresponding files
            if comp_file == "enabled_computers_with_laps.txt":
                marked_domain = mark_sensitive(domain, "domain")
                print_success(
                    f"LAPS-enabled inventory generated for domain {marked_domain} ({count} hosts)."
                )
                dc_file = None
                non_dc_file = None
                if dc_list:
                    dc_file = os.path.join(
                        shell.domains_dir,
                        domain,
                        "enabled_computers_with_laps_dcs.txt",
                    )
                    _write_host_list(dc_file, dc_list)
                if non_dc_list:
                    non_dc_file = os.path.join(
                        shell.domains_dir,
                        domain,
                        "enabled_computers_with_laps_non_dcs.txt",
                    )
                    _write_host_list(non_dc_file, non_dc_list)
                _render_laps_inventory_panel(
                    laps_state_label="Enabled",
                    border_style="green",
                    dc_file=dc_file,
                    non_dc_file=non_dc_file,
                )

            elif comp_file == "enabled_computers_without_laps.txt":
                marked_domain = mark_sensitive(domain, "domain")
                print_success(
                    f"LAPS-missing inventory generated for domain {marked_domain} ({count} hosts)."
                )
                dc_file = None
                non_dc_file = None
                if dc_list:
                    dc_file = os.path.join(
                        shell.domains_dir,
                        domain,
                        "enabled_computers_without_laps_dcs.txt",
                    )
                    _write_host_list(dc_file, dc_list)
                if non_dc_list:
                    non_dc_file = os.path.join(
                        shell.domains_dir,
                        domain,
                        "enabled_computers_without_laps_non_dcs.txt",
                    )
                    _write_host_list(non_dc_file, non_dc_list)
                _render_laps_inventory_panel(
                    laps_state_label="Not enabled",
                    border_style="yellow",
                    dc_file=dc_file,
                    non_dc_file=non_dc_file,
                )

                value = {
                    "all_computers": computers if computers else None,
                    "dcs": dc_list if dc_list else None,
                    "non_dcs": non_dc_list if non_dc_list else None,
                }

                shell.update_report_field(domain, "laps", value)

        except Exception as e:
            telemetry.capture_exception(e)
            print_error("Error reading the computers file.")
            print_exception(show_locals=False, exception=e)

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing bloodhound_query.")
        print_exception(show_locals=False, exception=e)


# ============================================================================
# Session Enumeration Functions
# ============================================================================


def run_bloodhound_sessions(shell: BloodHoundShell, target_domain: str) -> None:
    """Create a list of computers with Domain Admin sessions for the specified domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computer sessions for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    marked_target_domain = mark_sensitive(target_domain, "domain")
    print_info_verbose(
        f"Searching for Domain Admin sessions on non DC computers on domain {marked_target_domain}"
    )
    try:
        sessions = shell._get_bloodhound_service().get_sessions(
            domain=target_domain, domain_admin_only=True
        )
        execute_bh_sessions(
            shell,
            None,
            target_domain,
            "computers_da_sessions.txt",
            sessions=sessions,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error querying BloodHound for sessions.")
        print_exception(show_locals=False, exception=exc)


def execute_bh_sessions(
    shell: BloodHoundShell,
    command: str | None,
    domain: str,
    comp_file: str,
    sessions: list[dict] | None = None,
) -> None:
    """Execute the BloodHound session enumeration command and process the output.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        command: Command string (legacy, not used when sessions is provided)
        domain: Domain name
        comp_file: Output filename
        sessions: List of session dictionaries (if None, will execute command)
    """
    try:
        if sessions is None:
            print_info("Searching for Domain Admin sessions on non DC computers")
            completed_process = shell.run_command(command, timeout=300)
            errors = completed_process.stderr
            if completed_process.returncode != 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Error enumerating computers with DA sessions in domain {marked_domain}."
                )
                if errors:
                    print_error(errors)
                return
            sessions = []

        da_computers = []
        for entry in sessions or []:
            computer = str(entry.get("computer") or "").strip()
            if computer:
                da_computers.append(computer)

        da_computers = list(dict.fromkeys([c.lower() for c in da_computers]))

        if not da_computers:
            shell._write_domain_list_file(domain, comp_file, ["No sessions found."])
            shell.update_report_field(domain, "da_sessions", None)
            return

        shell._write_domain_list_file(domain, comp_file, da_computers)
        shell.update_report_field(domain, "da_sessions", da_computers)
        shell._display_items(da_computers, "Computers with Domain Admin sessions")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing BloodHound sessions query.")
        print_exception(show_locals=False, exception=e)


# ============================================================================
# Collector Functions
# ============================================================================


def ask_for_bloodhound(
    shell: BloodHoundShell, target_domain: str, callback: Any | None = None
) -> None:
    """Ask user if they want to run BloodHound collector for the domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to collect data for
        callback: Optional callback function to execute after collection
    """
    run_bloodhound_collector(shell, target_domain)

    # Always call the callback if it exists, regardless of whether BloodHound ran or not
    if callback:
        callback()
