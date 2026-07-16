"""Nmap scanning and host/IP conversion utilities.

This module centralizes all functionality related to:
- Hostname to IP address conversion
- IP address to hostname conversion
- Nmap port scanning by domain/services
- Post-processing of nmap scan results
- Host file management (saving hosts to service directories)
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import csv
import ipaddress
import time
from datetime import datetime, timezone
from typing import Literal, Protocol
import json

from rich.prompt import Confirm
from rich.table import Table
import rich.box

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_operation_header,
    print_panel,
    print_success,
    print_success_verbose,
    print_warning,
    telemetry,
)
from adscan_internal.cli.ci_events import emit_event, emit_operation_progress
from adscan_internal.cli.target_scope_warning import confirm_large_target_scope
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.workspaces import domain_subpath
from adscan_internal.services.reachability.massdns_report import (
    _flatten_massdns_unique_ips,
    _load_massdns_resolution_report,
    _write_massdns_resolution_report,
)
from adscan_core.interaction import is_non_interactive
from adscan_core.tui.patience_notice import (
    PatienceNoticeConfig,
    maybe_show_patience_notice,
)
from adscan_core.tui.progress_dashboard import (
    ProgressDashboard,
    ProgressDashboardConfig,
)
from adscan_core.tui.stream_runner import (
    SpawnFailed,
    StreamedProcessResult,
    stream_command_lines,
)

NMAP_IMPORTANT_PORTS_SCAN_TIMEOUT_SECONDS = 7200
NMAP_DC_DISCOVERY_LARGE_RANGE_THRESHOLD = 4096
_MASSDNS_FULL_DETAIL_LIMIT = 25
_MASSDNS_PREVIEW_LIMIT = 10
_REACHABILITY_PREVIEW_LIMIT = 10
MassdnsReportFilter = Literal["resolved", "unresolved"]
MassdnsReportSort = Literal["hostname", "ip-count", "status"]
_SMALL_IMPORTANT_PORT_SCAN_IP_THRESHOLD = 10
_MEDIUM_IMPORTANT_PORT_SCAN_IP_THRESHOLD = 100


class NmapShell(Protocol):
    """Protocol for shell methods needed by nmap functions."""

    current_workspace_dir: str | None
    domains_dir: str
    smb_dir: str
    winrm_dir: str
    rdp_dir: str
    mssql_dir: str
    ftp_dir: str
    ssh_dir: str
    dns_dir: str
    http_dir: str
    https_dir: str
    ldap_dir: str
    vnc_dir: str
    kerberos_dir: str
    dns: str
    console: any

    def run_command(self, command: str, timeout: int | None = None) -> any: ...
    def spawn_command(self, command, **kwargs) -> any: ...
    def consolidate_service_ips(self, service: str) -> None: ...
    def consolidate_domain_computers(self, args: str) -> None: ...
    def ask_for_unauth_scan(self, domain: str) -> None: ...
    def ask_for_smb_scan(self, domain: str) -> None: ...
    def _get_dns_discovery_service(self) -> object: ...
    def _get_lab_slug(self) -> str | None: ...


def _confirm_skip_important_port_scan(
    *,
    domain: str,
    ip_count: int,
    important_ports_csv: str,
) -> bool:
    """Return whether the operator wants to skip service discovery anyway."""
    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        "\n".join(
            [
                "Skipping the important port scan will materially reduce ADscan's targeting precision.",
                f"Domain: {marked_domain}",
                f"Resolved IPs queued: {ip_count}",
                f"Important TCP ports skipped: {important_ports_csv}",
                "",
                "What ADscan loses if you skip this step:",
                "- service-specific host lists such as smb/ips.txt, winrm/ips.txt, rdp/ips.txt, and mssql/ips.txt",
                "- current-vantage reachability evidence for those hosts",
                "- cleaner post-auth targeting with less noise on broad host lists",
                "- earlier visibility into segmentation and likely pivot requirements",
                "",
                "Later workflows will fall back to broader target sets such as reachable hosts or the full enabled computer list.",
                "That usually means more noise, less confidence in host reachability, and weaker service-driven follow-up decisions.",
            ]
        ),
        title="Skip Important Port Scan?",
        border_style="yellow",
        expand=False,
    )
    return bool(
        Confirm.ask(
            f"Skip service discovery anyway for domain {marked_domain}? [not recommended]",
            default=False,
        )
    )


def _confirm_large_dc_discovery_scan(
    shell: NmapShell,
    *,
    hosts: str,
    timeout_seconds: int,
) -> bool:
    """Warn users about very large CIDR ranges before DC discovery scan."""
    return confirm_large_target_scope(
        shell,
        targets=[hosts],
        threshold=NMAP_DC_DISCOVERY_LARGE_RANGE_THRESHOLD,
        title="[bold yellow]⚠️  DC Discovery Scope Warning[/bold yellow]",
        context_label=f"DC discovery scan (timeout safeguard: {timeout_seconds} seconds)",
        recommendation_lines=[
            "Recommendation: narrow the range to likely DC subnets first.",
            "This reduces scan time and network noise significantly.",
        ],
        confirm_prompt="Continue DC discovery scan on this large range?",
        default_confirm=False,
        non_interactive_message=(
            "Non-interactive mode detected. Continuing with timeout safeguard enabled."
        ),
    )


def discover_dc_candidates_with_nmap(
    shell: NmapShell,
    *,
    hosts: str,
    ports: list[int] | None = None,
    output_path: str | None = None,
    timeout_seconds: int = 600,
) -> list[str]:
    """Discover likely DC candidates by scanning AD core ports with Nmap.

    Args:
        shell: Active shell instance with run_command.
        hosts: Target range or hosts string for nmap.
        ports: TCP ports to scan (defaults to 88, 389, 53).
        output_path: Optional path to write the gnmap output.
        timeout_seconds: Timeout for the nmap command.

    Returns:
        List of IPs that have at least one of the target ports open.
    """
    return sorted(
        discover_dc_candidates_with_nmap_details(
            shell,
            hosts=hosts,
            ports=ports,
            output_path=output_path,
            timeout_seconds=timeout_seconds,
        ).keys()
    )


def discover_dc_candidates_with_nmap_details(
    shell: NmapShell,
    *,
    hosts: str,
    ports: list[int] | None = None,
    output_path: str | None = None,
    timeout_seconds: int = 600,
) -> dict[str, set[int]]:
    """Discover likely DC candidates and retain their open-port hints.

    Returns a dictionary keyed by candidate IP with the set of open AD-related
    ports discovered during the lightweight Nmap pass. This lets later domain
    inference skip probes we already know cannot work (for example SMB/445 when
    445 was closed but LDAP/389 was open).
    """
    try:
        setattr(shell, "_last_dc_discovery_cancelled_by_user", False)
        if not _confirm_large_dc_discovery_scan(
            shell,
            hosts=hosts,
            timeout_seconds=timeout_seconds,
        ):
            setattr(shell, "_last_dc_discovery_cancelled_by_user", True)
            print_warning("DC discovery scan cancelled by user.")
            return {}

        target_ports = ports or [88, 389, 53]
        port_list = ",".join(str(p) for p in target_ports)
        marked_hosts = mark_sensitive(hosts, "host")
        marked_ports = mark_sensitive(port_list, "text")

        if not output_path:
            workspace_dir = shell.current_workspace_dir or os.getcwd()
            output_path = os.path.join(workspace_dir, "dc_candidates.gnmap")

        print_info(
            "Running a lightweight DC candidate scan (Kerberos/LDAP/DNS) "
            f"on {marked_hosts}..."
        )
        print_info_verbose(f"Scanning TCP ports {marked_ports} to identify likely DCs.")

        scan_cmd = (
            f"nmap --open -n -Pn -sS -p{port_list} "
            f"-oG {shlex.quote(output_path)} {shlex.quote(hosts)}"
        )
        print_info_debug(f"[nmap][dc-discovery] {scan_cmd}")
        result = shell.run_command(scan_cmd, timeout=timeout_seconds)
        if result is None:
            print_error("Nmap DC candidate scan did not return a result.")
            return {}

        output_text = (result.stdout or "") + "\n" + (result.stderr or "")
        if _nmap_output_indicates_missing_privileges(output_text):
            sudo_scan_cmd = (
                f"sudo -n nmap --open -n -Pn -sS -p{port_list} "
                f"-oG {shlex.quote(output_path)} {shlex.quote(hosts)}"
            )
            print_warning(
                "Nmap needs elevated privileges for SYN scan; retrying via sudo."
            )
            print_info_debug(f"[nmap][dc-discovery] {sudo_scan_cmd}")
            result = shell.run_command(sudo_scan_cmd, timeout=timeout_seconds)
            if result is None:
                print_error("Nmap DC candidate scan did not return a result.")
                return {}

            output_text = (result.stdout or "") + "\n" + (result.stderr or "")
            if _nmap_output_indicates_missing_privileges(output_text):
                print_warning(
                    "sudo -n failed or is not permitted; falling back to TCP connect scan."
                )
                scan_cmd = (
                    f"nmap --open -n -Pn -sT -p{port_list} "
                    f"-oG {shlex.quote(output_path)} {shlex.quote(hosts)}"
                )
                print_warning(
                    "Nmap still lacks privileges; retrying in TCP connect mode."
                )
                print_info_debug(f"[nmap][dc-discovery] {scan_cmd}")
                result = shell.run_command(scan_cmd, timeout=timeout_seconds)
                if result is None:
                    print_error("Nmap DC candidate scan did not return a result.")
                    return {}

        gnmap_text = _read_text_file_best_effort(output_path)
        open_ports_by_host = _parse_gnmap_open_ports(gnmap_text)
        candidates = sorted(open_ports_by_host.keys())

        print_success(
            f"Discovered {len(candidates)} DC candidate host(s) "
            f"with ports {marked_ports} open."
        )
        return open_ports_by_host
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Failed to run DC candidate discovery with Nmap.")
        print_exception(show_locals=False, exception=exc)
        return {}


def probe_host_reachability_with_nmap(
    shell: NmapShell,
    *,
    host: str,
    ports: list[int] | None = None,
    timeout_seconds: int = 20,
    report_label: str = "trusted_dc",
) -> dict[str, object]:
    """Probe one host with Nmap and classify current-vantage reachability.

    This is a lightweight reusable pre-check intended for targeted validation
    of one already-known host, such as a trusted domain controller discovered
    during trust enumeration.
    """
    target_host = str(host or "").strip()
    target_ports = ports or [88, 389, 53]
    ports_csv = ",".join(str(port) for port in target_ports)

    if not target_host:
        return {
            "host": "",
            "reachable": False,
            "open_ports": [],
            "status": "invalid_target",
            "method": "nmap_single_host_probe",
        }

    output_path = None
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if workspace_dir:
        safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", target_host)
        output_dir = os.path.join(workspace_dir, "trusted_dc_prechecks")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{report_label}_{safe_host}.gnmap")

    if output_path:
        scan_cmd = (
            f"nmap --open -n -Pn -sS -PS{ports_csv} -PA{ports_csv} -p{ports_csv} "
            f"-oG {shlex.quote(output_path)} {shlex.quote(target_host)}"
        )
    else:
        scan_cmd = (
            f"nmap --open -n -Pn -sS -PS{ports_csv} -PA{ports_csv} -p{ports_csv} "
            f"{shlex.quote(target_host)}"
        )

    print_info_debug(f"[nmap][single-host-probe] {scan_cmd}")
    completed = _run_nmap_command_with_optional_sudo_retry(
        shell,
        command=scan_cmd,
        domain=target_host,
        timeout_seconds=timeout_seconds,
    )
    if completed is None:
        return {
            "host": target_host,
            "reachable": False,
            "open_ports": [],
            "status": "probe_failed",
            "method": "nmap_single_host_probe",
            "timeout_seconds": timeout_seconds,
            "ports_scanned": target_ports,
        }

    gnmap_text = (
        _read_text_file_best_effort(output_path)
        if output_path
        else ((completed.stdout or "") + "\n" + (completed.stderr or ""))
    )
    up_hosts = _parse_gnmap_up_hosts(gnmap_text)
    open_ports_by_host = _parse_gnmap_open_ports(gnmap_text)

    host_open_ports = sorted(open_ports_by_host.get(target_host, set()))
    if not host_open_ports:
        for candidate, candidate_ports in open_ports_by_host.items():
            if str(candidate).strip() == target_host:
                host_open_ports = sorted(candidate_ports)
                break

    reachable = target_host in up_hosts or bool(host_open_ports)
    status = "reachable" if reachable else "no_response_from_current_vantage"
    return {
        "host": target_host,
        "reachable": reachable,
        "open_ports": host_open_ports,
        "status": status,
        "method": "nmap_single_host_probe",
        "timeout_seconds": timeout_seconds,
        "ports_scanned": target_ports,
        "report_file": output_path,
    }


def _read_text_file_best_effort(path: str) -> str:
    """Read text file with best-effort error handling.

    Args:
        path: Path to the text file to read.

    Returns:
        File contents as string, or empty string on error.
    """
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
    except Exception:
        return ""
    return ""


def _run_nmap_port_scan_with_timeout_recovery(
    shell: NmapShell,
    *,
    command: str,
    domain: str,
    timeout_seconds: int,
) -> any:
    """Run Nmap port scan and offer timeout recovery UX when applicable.

    If the command fails specifically due to subprocess timeout, the user can
    choose to retry the same scan without timeout limits.
    """
    result = shell.run_command(command, timeout=timeout_seconds)
    if result is not None:
        return result

    last_error = getattr(shell, "_last_run_command_error", None)
    timed_out = (
        isinstance(last_error, tuple)
        and len(last_error) >= 1
        and str(last_error[0]).strip().lower() == "timeout"
    )
    if not timed_out:
        return None

    marked_domain = mark_sensitive(domain, "domain")
    print_warning(
        f"Nmap port scan for domain {marked_domain} timed out after {timeout_seconds} seconds."
    )
    print_info("This is common on very large domains or slow VPN links.")

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive_check
    if _is_non_interactive_check(shell):
        print_warning("Non-interactive mode detected; skipping retry without timeout.")
        return None

    retry_without_timeout = Confirm.ask(
        "Do you want to retry the same Nmap scan without timeout?",
        default=False,
    )
    if not retry_without_timeout:
        return None

    print_info(
        f"Retrying Nmap port scan for domain {marked_domain} without timeout. "
        "This may take a long time."
    )
    return shell.run_command(command, timeout=None)


def parse_massdns_a_records(output: str) -> list[str]:
    """Parse massdns stdout and return IPv4 addresses from A records.

    Args:
        output: Raw massdns stdout string (simple output format).

    Returns:
        List of IPv4 addresses in the order found.
    """
    if not output:
        return []
    return re.findall(r"\bA\s+(\d{1,3}(?:\.\d{1,3}){3})", output)


def parse_massdns_ndjson_a_records(path: str) -> list[str]:
    """Parse massdns ndjson output file and return IPv4 addresses from A records."""
    if not path or not os.path.exists(path):
        return []
    ips: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                data = record.get("data")
                if not isinstance(data, dict):
                    continue
                answers = data.get("answers")
                if not isinstance(answers, list):
                    continue
                for item in answers:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("type") or "").upper() != "A":
                        continue
                    ip_value = str(item.get("data") or "").strip()
                    if ip_value and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip_value):
                        ips.append(ip_value)
    except OSError:
        return []
    return ips


def parse_massdns_ndjson_a_record_map(path: str) -> dict[str, list[str]]:
    """Parse massdns ndjson output file and return hostname -> IPv4 addresses."""
    if not path or not os.path.exists(path):
        return {}

    records: dict[str, list[str]] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                hostname = str(record.get("name") or "").strip().rstrip(".")
                data = record.get("data")
                if not isinstance(data, dict):
                    continue
                answers = data.get("answers")
                if not isinstance(answers, list):
                    continue

                collected_ips: list[str] = []
                for item in answers:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("type") or "").upper() != "A":
                        continue
                    ip_value = str(item.get("data") or "").strip()
                    if ip_value and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip_value):
                        collected_ips.append(ip_value)
                    if not hostname:
                        hostname = str(item.get("name") or "").strip().rstrip(".")

                if not hostname or not collected_ips:
                    continue

                existing = records.setdefault(hostname, [])
                for ip_value in collected_ips:
                    if ip_value not in existing:
                        existing.append(ip_value)
    except OSError:
        return {}
    return records


def _apply_persisted_pdc_ip_fallback(
    *,
    shell: NmapShell,
    domain: str,
    hostnames: list[str],
    host_to_ips: dict[str, list[str]],
) -> tuple[dict[str, list[str]], bool, str | None]:
    """Inject a persisted PDC IP when MassDNS resolves nothing.

    This protects later workflows that depend on ``enabled_computers_ips.txt`` from
    collapsing to an empty target list when hostname resolution is unavailable.
    """
    domain_data = (
        shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
    )
    pdc_ip = str(domain_data.get("pdc") or "").strip()
    if not pdc_ip:
        return host_to_ips, False, None
    validation_mode = str(domain_data.get("dns_validation_mode", "")).strip().lower()
    fallback_reason = (
        "best_effort_pdc" if validation_mode == "best_effort" else "persisted_pdc"
    )

    updated = {
        str(k).strip().rstrip(".").lower(): list(v) for k, v in host_to_ips.items()
    }
    pdc_hostname = (
        str(domain_data.get("pdc_hostname") or "").strip().rstrip(".").lower()
    )
    candidate_hosts = []
    if pdc_hostname:
        candidate_hosts.append(pdc_hostname)
        candidate_hosts.append(
            f"{pdc_hostname}.{str(domain or '').strip().rstrip('.').lower()}"
        )

    injected = False
    for candidate in candidate_hosts:
        if candidate in updated or candidate in {
            str(host or "").strip().rstrip(".").lower() for host in hostnames
        }:
            updated[candidate] = [pdc_ip]
            injected = True
            break

    if not injected:
        synthetic_key = (
            f"{pdc_hostname}.{str(domain or '').strip().rstrip('.').lower()}"
            if pdc_hostname
            else str(domain or "").strip().rstrip(".").lower()
        )
        if synthetic_key:
            updated[synthetic_key] = [pdc_ip]
            injected = True

    return updated, injected, fallback_reason


def _filter_massdns_resolution_payload(
    payload: dict[str, object],
    *,
    only: MassdnsReportFilter | None = None,
) -> dict[str, object]:
    """Return a filtered copy of a massdns report payload."""
    if only not in {"resolved", "unresolved", None}:
        return payload

    resolved_entries = (
        payload.get("resolved", []) if isinstance(payload.get("resolved"), list) else []
    )
    unresolved_entries = (
        payload.get("unresolved", [])
        if isinstance(payload.get("unresolved"), list)
        else []
    )
    context = (
        payload.get("context", {}) if isinstance(payload.get("context"), dict) else {}
    )

    filtered_resolved = resolved_entries if only in {None, "resolved"} else []
    filtered_unresolved = unresolved_entries if only in {None, "unresolved"} else []
    unique_ips: set[str] = set()
    multi_ip_hostnames: list[str] = []
    for entry in filtered_resolved:
        if not isinstance(entry, dict):
            continue
        ips = entry.get("ips", [])
        ip_values = (
            [str(ip).strip() for ip in ips if str(ip).strip()]
            if isinstance(ips, list)
            else []
        )
        unique_ips.update(ip_values)
        if len(ip_values) > 1:
            multi_ip_hostnames.append(str(entry.get("hostname") or ""))

    filtered_payload: dict[str, object] = {
        "summary": {
            "total_hostnames": len(filtered_resolved) + len(filtered_unresolved),
            "resolved_hostnames": len(filtered_resolved),
            "unresolved_hostnames": len(filtered_unresolved),
            "unique_ip_count": len(unique_ips),
            "multi_ip_hostnames": multi_ip_hostnames,
        },
        "resolved": filtered_resolved,
        "unresolved": filtered_unresolved,
    }
    if context:
        filtered_payload["context"] = context
    return filtered_payload


def _sort_massdns_resolution_payload(
    payload: dict[str, object],
    *,
    sort_by: MassdnsReportSort | None = None,
) -> dict[str, object]:
    """Return a sorted copy of a massdns report payload."""
    if sort_by not in {"hostname", "ip-count", "status", None}:
        return payload

    sorted_payload = dict(payload)
    resolved_entries = (
        list(payload.get("resolved", []))
        if isinstance(payload.get("resolved"), list)
        else []
    )
    unresolved_entries = (
        list(payload.get("unresolved", []))
        if isinstance(payload.get("unresolved"), list)
        else []
    )

    def _hostname_key(value: object) -> str:
        if isinstance(value, dict):
            return str(value.get("hostname") or "").strip().lower()
        return str(value or "").strip().lower()

    if sort_by == "hostname":
        resolved_entries.sort(key=_hostname_key)
        unresolved_entries.sort(key=_hostname_key)
    elif sort_by == "ip-count":
        resolved_entries.sort(
            key=lambda entry: (
                -len(entry.get("ips", []))
                if isinstance(entry, dict) and isinstance(entry.get("ips"), list)
                else 0,
                _hostname_key(entry),
            )
        )
        unresolved_entries.sort(key=_hostname_key)
    elif sort_by == "status":
        resolved_entries.sort(key=_hostname_key)
        unresolved_entries.sort(key=_hostname_key)

    sorted_payload["resolved"] = resolved_entries
    sorted_payload["unresolved"] = unresolved_entries
    return sorted_payload


def _write_massdns_resolution_csv(
    payload: dict[str, object],
    *,
    csv_path: str,
    only: MassdnsReportFilter | None = None,
    sort_by: MassdnsReportSort | None = None,
) -> bool:
    """Export a massdns resolution report to a flat CSV representation."""
    try:
        filtered_payload = _sort_massdns_resolution_payload(
            _filter_massdns_resolution_payload(payload, only=only),
            sort_by=sort_by,
        )
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        resolved_entries = (
            filtered_payload.get("resolved", [])
            if isinstance(filtered_payload.get("resolved"), list)
            else []
        )
        unresolved_entries = (
            filtered_payload.get("unresolved", [])
            if isinstance(filtered_payload.get("unresolved"), list)
            else []
        )
        context = (
            filtered_payload.get("context", {})
            if isinstance(filtered_payload.get("context"), dict)
            else {}
        )
        domain = str(context.get("domain") or "").strip()

        with open(csv_path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "domain",
                    "hostname",
                    "status",
                    "ip_addresses",
                    "ip_count",
                ],
            )
            writer.writeheader()
            for entry in resolved_entries:
                if not isinstance(entry, dict):
                    continue
                hostname = str(entry.get("hostname") or "").strip()
                ips = (
                    [str(ip).strip() for ip in entry.get("ips", []) if str(ip).strip()]
                    if isinstance(entry.get("ips"), list)
                    else []
                )
                writer.writerow(
                    {
                        "domain": domain,
                        "hostname": hostname,
                        "status": "resolved",
                        "ip_addresses": ",".join(ips),
                        "ip_count": len(ips),
                    }
                )
            for hostname in unresolved_entries:
                writer.writerow(
                    {
                        "domain": domain,
                        "hostname": str(hostname).strip(),
                        "status": "unresolved",
                        "ip_addresses": "",
                        "ip_count": 0,
                    }
                )
    except OSError:
        return False
    return True


def _show_massdns_resolution_summary(
    shell: NmapShell,
    *,
    hostnames: list[str],
    host_to_ips: dict[str, list[str]],
    ip_file: str,
    report_file: str | None = None,
) -> None:
    """Render a compact but useful massdns resolution summary."""
    normalized_map = {
        str(hostname or "").strip().rstrip(".").lower(): list(ips)
        for hostname, ips in host_to_ips.items()
        if str(hostname or "").strip()
    }
    ordered_resolved: list[tuple[str, list[str]]] = []
    unresolved: list[str] = []
    multi_ip_hosts = 0

    for original_host in hostnames:
        key = str(original_host or "").strip().rstrip(".").lower()
        ips = list(normalized_map.get(key, []))
        if ips:
            ordered_resolved.append((original_host, ips))
            if len(ips) > 1:
                multi_ip_hosts += 1
        else:
            unresolved.append(original_host)

    resolved_count = len(ordered_resolved)
    total_hosts = len(hostnames)
    unique_ip_count = len(
        _flatten_massdns_unique_ips(
            [hostname for hostname, _ips in ordered_resolved],
            {hostname: ips for hostname, ips in ordered_resolved},
        )
    )
    print_info(
        f"Resolved {resolved_count}/{total_hosts} host(s) into {unique_ip_count} unique IP(s). "
        f"Saved to {mark_sensitive(ip_file, 'path')}."
    )
    if report_file:
        print_info(
            "Detailed hostname-to-IP mapping saved to "
            f"{mark_sensitive(report_file, 'path')}."
        )

    if not getattr(shell, "console", None):
        return

    show_all = total_hosts <= _MASSDNS_FULL_DETAIL_LIMIT
    resolved_preview = (
        ordered_resolved if show_all else ordered_resolved[:_MASSDNS_PREVIEW_LIMIT]
    )
    unresolved_preview = unresolved if show_all else unresolved[:_MASSDNS_PREVIEW_LIMIT]

    if resolved_preview:
        resolved_table = Table(
            title=(
                "Resolved Hostnames"
                if show_all
                else f"Resolved Hostnames (showing first {_MASSDNS_PREVIEW_LIMIT})"
            ),
            show_header=True,
            header_style="bold cyan",
            box=rich.box.ROUNDED,
        )
        resolved_table.add_column("Hostname", style="bold")
        resolved_table.add_column("IP Address(es)")
        for hostname, ips in resolved_preview:
            resolved_table.add_row(
                mark_sensitive(hostname, "hostname"),
                ", ".join(mark_sensitive(ip, "ip") for ip in ips),
            )
        shell.console.print(resolved_table)

    if unresolved_preview:
        unresolved_table = Table(
            title=(
                "Unresolved Hostnames"
                if show_all
                else f"Unresolved Hostnames (showing first {_MASSDNS_PREVIEW_LIMIT})"
            ),
            show_header=True,
            header_style="bold yellow",
            box=rich.box.ROUNDED,
        )
        unresolved_table.add_column("Hostname", style="yellow")
        for hostname in unresolved_preview:
            unresolved_table.add_row(mark_sensitive(hostname, "hostname"))
        shell.console.print(unresolved_table)

    if not show_all:
        remaining_resolved = max(0, resolved_count - len(resolved_preview))
        remaining_unresolved = max(0, len(unresolved) - len(unresolved_preview))
        extra_bits: list[str] = []
        if remaining_resolved:
            extra_bits.append(f"{remaining_resolved} more resolved")
        if remaining_unresolved:
            extra_bits.append(f"{remaining_unresolved} more unresolved")
        if extra_bits:
            print_info(
                "MassDNS detail view truncated to keep the UX readable: "
                + ", ".join(extra_bits)
                + "."
            )

    if multi_ip_hosts:
        print_info_debug(
            f"[massdns] {multi_ip_hosts} hostname(s) resolved to multiple IPv4 addresses."
        )


def run_massdns_report(
    shell: NmapShell,
    *,
    domain: str,
    resolved_limit: int = 20,
    unresolved_limit: int = 20,
    csv_output_path: str | None = None,
    only: MassdnsReportFilter | None = None,
    sort_by: MassdnsReportSort | None = None,
) -> None:
    """Render a saved massdns hostname resolution report from the workspace."""
    report_path = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "massdns_resolution_report.json",
    )
    reachability_report_path = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "network_reachability_report.json",
    )
    payload = _load_massdns_resolution_report(report_path)
    reachability_payload = _load_network_reachability_report(reachability_report_path)
    if not payload:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"No massdns resolution report found for domain {marked_domain}.")
        return
    filtered_payload = _sort_massdns_resolution_payload(
        _filter_massdns_resolution_payload(payload, only=only),
        sort_by=sort_by,
    )
    if csv_output_path is not None:
        effective_csv_path = (
            csv_output_path
            if str(csv_output_path).strip()
            else os.path.join(
                shell.current_workspace_dir or "",
                shell.domains_dir,
                domain,
                "massdns_resolution_report.csv",
            )
        )
        if _write_massdns_resolution_csv(
            payload,
            csv_path=effective_csv_path,
            only=only,
            sort_by=sort_by,
        ):
            print_success(
                f"MassDNS CSV report exported to {mark_sensitive(effective_csv_path, 'path')}."
            )
        else:
            print_error(
                f"Failed to export MassDNS CSV report to {mark_sensitive(effective_csv_path, 'path')}."
            )

    summary = (
        filtered_payload.get("summary", {})
        if isinstance(filtered_payload.get("summary"), dict)
        else {}
    )
    context = (
        filtered_payload.get("context", {})
        if isinstance(filtered_payload.get("context"), dict)
        else {}
    )
    resolved_entries = (
        filtered_payload.get("resolved", [])
        if isinstance(filtered_payload.get("resolved"), list)
        else []
    )
    unresolved_entries = (
        filtered_payload.get("unresolved", [])
        if isinstance(filtered_payload.get("unresolved"), list)
        else []
    )

    total_hostnames = int(
        summary.get("total_hostnames")
        or len(resolved_entries) + len(unresolved_entries)
    )
    resolved_count = int(summary.get("resolved_hostnames") or len(resolved_entries))
    unresolved_count = int(
        summary.get("unresolved_hostnames") or len(unresolved_entries)
    )
    unique_ip_count = int(summary.get("unique_ip_count") or 0)
    multi_ip_hostnames = summary.get("multi_ip_hostnames", [])
    multi_ip_count = (
        len(multi_ip_hostnames) if isinstance(multi_ip_hostnames, list) else 0
    )

    print_operation_header(
        "MassDNS Resolution Report",
        details={
            "Domain": domain,
            "View": only or "all",
            "Sort": sort_by or "default",
            "Total Hostnames": str(total_hostnames),
            "Resolved": str(resolved_count),
            "Unresolved": str(unresolved_count),
            "Unique IPs": str(unique_ip_count),
        },
        icon="🧭",
    )

    context_lines: list[str] = []
    input_file = str(context.get("input_file") or "").strip()
    resolved_ip_file = str(context.get("resolved_ip_file") or "").strip()
    raw_output_file = str(context.get("raw_massdns_output_file") or "").strip()
    resolver_sources = context.get("resolver_sources", [])
    if input_file:
        context_lines.append(f"Input file: {mark_sensitive(input_file, 'path')}")
    if resolved_ip_file:
        context_lines.append(
            f"Resolved IP file: {mark_sensitive(resolved_ip_file, 'path')}"
        )
    if raw_output_file:
        context_lines.append(
            f"Raw massdns output: {mark_sensitive(raw_output_file, 'path')}"
        )
    if isinstance(resolver_sources, list) and resolver_sources:
        preview = resolver_sources[:5]
        resolver_text = ", ".join(mark_sensitive(str(item), "ip") for item in preview)
        if len(resolver_sources) > 5:
            resolver_text += f", +{len(resolver_sources) - 5} more"
        context_lines.append(f"Resolvers: {resolver_text}")
    if context_lines:
        print_info("Report context:")
        for line in context_lines:
            print_info(line)

    resolved_table = Table(
        title=(
            "Resolved Hostnames"
            if resolved_count <= resolved_limit
            else f"Resolved Hostnames (showing first {resolved_limit})"
        ),
        show_header=True,
        header_style="bold cyan",
        box=rich.box.ROUNDED,
    )
    resolved_table.add_column("Hostname", style="bold")
    resolved_table.add_column("IP Address(es)")

    for entry in resolved_entries[: max(1, int(resolved_limit))]:
        if not isinstance(entry, dict):
            continue
        hostname = str(entry.get("hostname") or "").strip()
        ips = entry.get("ips", [])
        if not hostname:
            continue
        ip_values = (
            [str(ip).strip() for ip in ips if str(ip).strip()]
            if isinstance(ips, list)
            else []
        )
        resolved_table.add_row(
            mark_sensitive(hostname, "hostname"),
            ", ".join(mark_sensitive(ip, "ip") for ip in ip_values) or "-",
        )

    unresolved_table = Table(
        title=(
            "Unresolved Hostnames"
            if unresolved_count <= unresolved_limit
            else f"Unresolved Hostnames (showing first {unresolved_limit})"
        ),
        show_header=True,
        header_style="bold yellow",
        box=rich.box.ROUNDED,
    )
    unresolved_table.add_column("Hostname", style="yellow")

    for hostname in unresolved_entries[: max(1, int(unresolved_limit))]:
        unresolved_table.add_row(mark_sensitive(str(hostname), "hostname"))

    if resolved_entries:
        shell.console.print(resolved_table)
    if unresolved_entries:
        shell.console.print(unresolved_table)

    if resolved_count > resolved_limit:
        print_info(
            f"Resolved view truncated: {resolved_count - resolved_limit} more hostname(s) are present in the JSON report."
        )
    if unresolved_count > unresolved_limit:
        print_info(
            f"Unresolved view truncated: {unresolved_count - unresolved_limit} more hostname(s) are present in the JSON report."
        )
    if multi_ip_count:
        print_info(f"{multi_ip_count} hostname(s) resolved to multiple IPv4 addresses.")
    if reachability_payload:
        _show_network_reachability_summary(
            shell,
            payload=reachability_payload,
            report_file=reachability_report_path,
        )
    print_info(f"JSON report path: {mark_sensitive(report_path, 'path')}.")


def _nmap_output_indicates_missing_privileges(output: str) -> bool:
    """Check if nmap output indicates missing root privileges.

    Args:
        output: Nmap command output to check.

    Returns:
        True if output indicates missing privileges, False otherwise.
    """
    lowered = (output or "").lower()
    markers = (
        "requires root privileges",
        "requested a scan type which requires root privileges",
        "you requested a scan type which requires root privileges",
        "failed to open device",
        "couldn't open a raw socket",
        "could not open a raw socket",
        "operation not permitted",
        "permission denied",
        "not permitted",
    )
    return any(marker in lowered for marker in markers)


def _run_nmap_command_with_optional_sudo_retry(
    shell: NmapShell,
    *,
    command: str,
    domain: str,
    timeout_seconds: int,
    _is_full_adscan_container_runtime: callable | None = None,
    _sudo_validate: callable | None = None,
    retry_notice: str | None = None,
    retry_debug_context: str = "scan",
) -> any:
    """Run an Nmap command and retry with sudo when a SYN scan lacks privileges.

    Args:
        shell: Active shell instance with command execution support.
        command: Full Nmap command to execute.
        domain: Domain used for timeout recovery helpers.
        timeout_seconds: Maximum execution time for the command.
        _is_full_adscan_container_runtime: Optional container runtime detector.
        _sudo_validate: Optional sudo validation callback.
        retry_notice: Optional user-facing warning before retrying with sudo.
        retry_debug_context: Short label used in debug logs.

    Returns:
        The final command result, or None if execution failed unexpectedly.
    """
    result = _run_nmap_port_scan_with_timeout_recovery(
        shell,
        command=command,
        domain=domain,
        timeout_seconds=timeout_seconds,
    )
    if result is None or result.returncode == 0:
        return result

    combined_output = (result.stdout or "") + "\n" + (result.stderr or "")
    needs_privileges = _nmap_output_indicates_missing_privileges(combined_output)
    can_escalate = os.geteuid() != 0 and shutil.which("sudo") is not None
    if not needs_privileges or not can_escalate:
        return result

    if retry_notice:
        print_warning(retry_notice)

    if _is_full_adscan_container_runtime and _is_full_adscan_container_runtime():
        print_info_debug(
            f"Nmap {retry_debug_context} requires privileges in container runtime; retrying via sudo -n."
        )
        privileged_command = f"sudo -n {command}"
    else:
        print_info_debug(
            f"Nmap {retry_debug_context} requires privileges; retrying via sudo."
        )
        if _sudo_validate and not _sudo_validate():
            return result
        privileged_command = f"sudo {command}"

    return _run_nmap_port_scan_with_timeout_recovery(
        shell,
        command=privileged_command,
        domain=domain,
        timeout_seconds=timeout_seconds,
    )


# Single source of truth for parsing Nmap's live stdout (-vvv emits one
# "Discovered open port <port>/tcp on <ip>" line per open port; --stats-every
# plus -vvv emit periodic "... Timing: About <pct>% done; ETC: <hh:mm> (<rem>
# remaining)" lines). Used by both the streaming important-port monitor and the
# monitor_nmap_domain loop so the regex lives in one place.
_NMAP_DISCOVERED_PORT_RE = re.compile(
    r"Discovered open port (?P<port>\d+)/tcp on (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
_NMAP_TIMING_PERCENT_RE = re.compile(r"About\s+([\d.]+)%\s+done")
_NMAP_TIMING_REMAINING_RE = re.compile(
    r"\((?:(\d+):)?(\d{1,2}):(\d{2})\s+remaining\)"
)


def _parse_nmap_discovered_port(line: str) -> tuple[str, int] | None:
    """Parse a single Nmap ``-vvv`` stdout line for a discovered open TCP port.

    Args:
        line: One decoded line of Nmap stdout.

    Returns:
        ``(host_ip, port)`` when the line reports a discovered open TCP port,
        otherwise ``None``.
    """
    match = _NMAP_DISCOVERED_PORT_RE.search(line or "")
    if not match:
        return None
    try:
        return match.group("ip"), int(match.group("port"))
    except (ValueError, IndexError):
        return None


def _parse_nmap_timing_progress(line: str) -> tuple[float | None, float | None]:
    """Parse Nmap timing/stats output for completion percent and remaining time.

    Nmap with ``-vvv --stats-every`` periodically prints lines such as::

        SYN Stealth Scan Timing: About 45.23% done; ETC: 14:32 (0:00:15 remaining)

    Args:
        line: One decoded line of Nmap stdout.

    Returns:
        ``(percent, eta_seconds)`` where each element is ``None`` when that
        signal is absent from the line.
    """
    text = line or ""
    percent: float | None = None
    eta_seconds: float | None = None
    pct_match = _NMAP_TIMING_PERCENT_RE.search(text)
    if pct_match:
        try:
            percent = float(pct_match.group(1))
        except ValueError:
            percent = None
    rem_match = _NMAP_TIMING_REMAINING_RE.search(text)
    if rem_match:
        try:
            hours = int(rem_match.group(1) or 0)
            minutes = int(rem_match.group(2))
            seconds = int(rem_match.group(3))
            eta_seconds = float(hours * 3600 + minutes * 60 + seconds)
        except ValueError:
            eta_seconds = None
    return percent, eta_seconds


# Terse service annotations for the live "top open ports" ranking. Keyed by the
# same ``<port>/tcp`` string the breakdown records, so a ranked entry reads
# ``445/tcp SMB 42``. Only the well-known AD ports the scan targets are named;
# unlisted ports render the bare ``<port>/tcp <count>`` with no annotation.
_IMPORTANT_PORT_SERVICE_LABELS: dict[str, str] = {
    "21/tcp": "FTP",
    "22/tcp": "SSH",
    "53/tcp": "DNS",
    "80/tcp": "HTTP",
    "88/tcp": "Kerberos",
    "389/tcp": "LDAP",
    "443/tcp": "HTTPS",
    "445/tcp": "SMB",
    "1433/tcp": "MSSQL",
    "3389/tcp": "RDP",
    "5900/tcp": "VNC",
    "5985/tcp": "WinRM",
}


def _build_important_port_scan_dashboard() -> ProgressDashboard:
    """Indeterminate important-port-scan dashboard (Nmap stdout is opaque).

    Scope is indeterminate (the resolved-IP count is not the host-with-open-
    ports count), so ``total`` stays ``None``. But Nmap's own ``-vvv
    --stats-every`` output IS parseable: the streaming runner feeds discovered
    hosts into the "found N" counter AND Nmap's reported percent / ETA into
    :meth:`ProgressDashboard.set_reported_progress`, so the panel shows honest
    forward motion during the scan instead of sitting at "found 0".
    """
    return ProgressDashboard(
        ProgressDashboardConfig(
            title="Important Port Scan",
            total=None,  # indeterminate scope; live percent driven by Nmap stats
            unit="hosts",
            last_item_type="ip",
            # A single Nmap subprocess has no per-host success/error/in-flight to
            # track, so the counter row would render a meaningless "✓ hosts 0"
            # next to the live "N found" count. Suppress it for this scan.
            show_counters=False,
            # Live "top open ports" leaderboard: ranked by the count of DISTINCT
            # hosts on which each port was discovered open, descending, bounded
            # to the busiest K of the 12 scanned ports so the panel line count
            # stays stable. The operator watches the service landscape form.
            breakdown_max=8,
            breakdown_label="top open ports",
            breakdown_annotations=_IMPORTANT_PORT_SERVICE_LABELS,
        )
    )


# Streaming primitives live in the shared, dependency-light core module so
# nmap.py and the kerbrute live flows (services/enumeration/kerberos.py,
# spraying.py) drive their dashboards through ONE budget-enforcing,
# timeout-signalling stdout streamer rather than each shipping a copy.
_StreamingScanResult = StreamedProcessResult
_StreamingSpawnFailed = SpawnFailed


def _stream_nmap_scan_into_dashboard(
    shell: NmapShell,
    *,
    command: str,
    timeout_seconds: int | None,
    dashboard: "ProgressDashboard",
    domain: str = "",
    total_hosts: int | None = None,
    emit_terminal_done: bool = True,
) -> _StreamingScanResult | None:
    """Spawn an Nmap scan and drive the dashboard from its live stdout.

    Reads stdout line-by-line via the shared :func:`stream_command_lines`
    streamer (which spawns through ``shell.spawn_command`` -- preserving the
    PyInstaller clean-env handling -- enforces its own wall-clock budget, and
    drains the remaining output). The per-line callback feeds discovered
    open-port hosts into the dashboard's "found N" counter and Nmap's own
    ``Timing: About X% done`` / remaining-time into its reported-progress
    surface.

    Args:
        shell: Active shell exposing ``spawn_command``.
        command: Full Nmap command string (already shell-quoted).
        timeout_seconds: Wall-clock budget, or ``None`` for no limit.
        dashboard: Live dashboard to drive.
        domain: Domain surfaced as the operation event's ``detail``.
        total_hosts: Number of hosts queued for the scan (the IP-file line
            count). When known, the structured ``port_scan`` operation event is
            DETERMINATE — ``total=total_hosts`` with a monotonic
            ``current=<hosts scanned>`` derived from Nmap's own reported
            progress — so the platform renders an honest "X of Y hosts" bar
            instead of an indeterminate strip. When ``None``, the event stays
            indeterminate (monotonic ``current``, no ``total``).
        emit_terminal_done: When ``True`` (default), the single terminal
            ``done=True`` tick (``current=total``, ``percent=100``) is emitted
            after the scan loop ends. The orchestrator sets this ``False`` for a
            FIRST attempt that may still be retried under sudo — a failed
            privilege-denied attempt must NOT latch the web widget as complete.
            The retried (final) attempt then owns the single terminal tick. See
            :func:`_run_important_port_scan_with_dashboard`.

    Returns:
        A :class:`_StreamingScanResult` on completion, or ``None`` if the
        process could not be spawned (caller falls back to the buffered path).
    """
    # Clear any stale timeout marker so the recovery prompt only fires for a
    # timeout produced by THIS run, never a leftover from an earlier command.
    setattr(shell, "_last_run_command_error", None)

    hosts_with_open_ports: set[str] = set()
    # Live current-operation telemetry — mirror the dashboard's forward motion
    # into the structured event stream so the platform shows "Port scan: X of Y
    # hosts" live, not just at completion. Throttled to ~1.5s so a 12-port scan
    # of 1-2k hosts never floods the event channel (no-saturation directive).
    #
    # DETERMINATE when ``total_hosts`` is known: ``current`` is the count of
    # hosts SCANNED so far, derived from Nmap's own reported "About X% done"
    # against the queued host total, and kept MONOTONIC so the platform's bar
    # only ever advances. We MUST NOT emit ``done=True`` (nor ``percent=100``)
    # on any of these mid-scan ticks — a premature done event makes the web
    # treat the operation as finished and hide every later tick. The single
    # terminal ``done=True`` is emitted once after the scan loop ends (below).
    _op_state: dict[str, float | None] = {
        "last_emit": 0.0,
        "last_percent": None,
        "last_current": 0.0,
    }

    def _scanned_hosts_from_percent() -> int | None:
        """Monotonic hosts-scanned count from Nmap's reported percent.

        Returns ``None`` when no total is known (indeterminate operation) so the
        caller falls back to a bare monotonic ``current``.
        """
        if not total_hosts or total_hosts <= 0:
            return None
        pct = _op_state["last_percent"]
        derived = 0.0 if pct is None else (float(pct) / 100.0) * float(total_hosts)
        # Clamp BELOW the total mid-scan: the terminal done tick owns "Y of Y".
        derived = max(0.0, min(derived, float(total_hosts - 1)))
        # Never regress (Nmap's per-target % can wobble); the bar only advances.
        if derived < float(_op_state["last_current"] or 0.0):
            derived = float(_op_state["last_current"] or 0.0)
        _op_state["last_current"] = derived
        return int(derived)

    def _maybe_emit_port_scan_progress(percent: float | None) -> None:
        now = time.time()
        if percent is not None:
            _op_state["last_percent"] = percent
        last_emit = _op_state["last_emit"] or 0.0
        if now - last_emit < 1.5:
            return
        _op_state["last_emit"] = now
        try:
            # Reuse the dashboard's OWN rate / ETA / elapsed (same numbers the
            # CLI rich.live panel renders) so the platform's live strip matches
            # the terminal. Nmap is an opaque subprocess: its ETA is the tool's
            # reported ``ETC`` (exposed via the dashboard's eta_seconds in
            # indeterminate mode); rate is the host-discovery rate.
            rate = dashboard.rate
            scanned = _scanned_hosts_from_percent()
            emit_operation_progress(
                operation="port_scan",
                label="Port scan",
                phase="domain_analysis",
                phase_label="Domain Intelligence",
                # Determinate "X of Y hosts" when total is known; otherwise a
                # bare monotonic count of hosts with open ports found so far.
                current=scanned if scanned is not None else (len(hosts_with_open_ports) or None),
                total=total_hosts if (total_hosts and total_hosts > 0) else None,
                percent=_op_state["last_percent"],
                rate=rate if rate > 0 else None,
                eta_seconds=dashboard.eta_seconds,
                elapsed_seconds=dashboard.elapsed,
                detail=domain or None,
                # NEVER done here — only the terminal tick after the loop is done.
            )
        except Exception:  # noqa: BLE001 -- telemetry must not abort scan
            pass

    def _on_line(line: str) -> None:
        parsed = _parse_nmap_discovered_port(line)
        if parsed is not None:
            host_ip, port = parsed
            # Feed the live "top open ports" ranking on EVERY discovery (the
            # dashboard de-duplicates distinct hosts per port internally via a
            # set, so re-seen (host, port) pairs never double-count).
            try:
                dashboard.record_breakdown(f"{port}/tcp", member=host_ip)
            except Exception:  # noqa: BLE001 -- render must not abort scan
                pass
            if host_ip not in hosts_with_open_ports:
                hosts_with_open_ports.add(host_ip)
                try:
                    # last_item_type is fixed in the dashboard config ("ip");
                    # feed the raw IP -- masking happens at render time.
                    dashboard.update(done=len(hosts_with_open_ports), last=host_ip)
                except Exception:  # noqa: BLE001 -- render must not abort scan
                    pass
                _maybe_emit_port_scan_progress(None)

        percent, eta_seconds = _parse_nmap_timing_progress(line)
        if percent is not None or eta_seconds is not None:
            try:
                dashboard.set_reported_progress(
                    percent=percent, eta_seconds=eta_seconds
                )
            except Exception:  # noqa: BLE001 -- render must not abort scan
                pass
            _maybe_emit_port_scan_progress(percent)

    def _on_timeout() -> None:
        # Mirror run_command's timeout signalling so the recovery prompt fires.
        setattr(shell, "_last_run_command_error", ("timeout", command))

    result = stream_command_lines(
        shell.spawn_command,
        command=command,
        timeout_seconds=timeout_seconds,
        on_line=_on_line,
        on_timeout=_on_timeout,
    )

    # The scan loop has ended — emit one TERMINAL done tick so the platform's
    # live "Port scan" strip clears immediately instead of freezing on its last
    # progress event (the operation finishes inside ``domain_analysis`` while
    # that phase keeps running its later sub-steps, so a phase-supersede clear
    # alone would never fire). Best-effort: telemetry must never abort the scan.
    #
    # SUPPRESSED on a to-be-retried first attempt (``emit_terminal_done=False``).
    # A privilege-denied first attempt that is about to re-spawn under sudo must
    # NOT emit ``done=True`` (it would arrive at elapsed ~0 with
    # ``current=total``/``percent=100`` and the web widget would latch the whole
    # operation complete, then ignore the real sudo-retry progress). The retried
    # FINAL attempt owns the single terminal tick instead.
    if not emit_terminal_done:
        return result
    _emit_port_scan_terminal_done(
        dashboard,
        total_hosts=total_hosts,
        domain=domain,
        hosts_found=len(hosts_with_open_ports),
    )
    return result


def _emit_port_scan_terminal_done(
    dashboard: "ProgressDashboard",
    *,
    total_hosts: int | None,
    domain: str,
    hosts_found: int,
) -> None:
    """Emit the single TERMINAL ``done=True`` tick for the port-scan operation.

    This is the ONLY ``done=True`` event for the whole ``port_scan`` operation
    and MUST be emitted exactly once, after the FINAL attempt completes — never
    on a privilege-denied first attempt that is about to be retried under sudo
    (that premature terminal tick latches the web widget complete and hides the
    real sudo-retry progress). Best-effort: telemetry must never abort the scan.

    Args:
        dashboard: The live dashboard the scan drove (for ``rate``/``elapsed``).
        total_hosts: Queued host total, or ``None`` for an indeterminate bar.
        domain: Surfaced as the event's ``detail``.
        hosts_found: Count of hosts found with open ports (the indeterminate
            ``current`` when no total is known).
    """
    try:
        rate = dashboard.rate
        emit_operation_progress(
            operation="port_scan",
            label="Port scan",
            phase="domain_analysis",
            phase_label="Domain Intelligence",
            # Terminal tick: all queued hosts have been scanned. "Y of Y" when
            # the total is known; otherwise the count of hosts found with open
            # ports. This is the ONLY ``done=True`` for the operation.
            current=total_hosts if (total_hosts and total_hosts > 0) else (hosts_found or None),
            total=total_hosts if (total_hosts and total_hosts > 0) else None,
            percent=100,
            rate=rate if rate > 0 else None,
            elapsed_seconds=dashboard.elapsed,
            detail=domain or None,
            done=True,
        )
    except Exception:  # noqa: BLE001 -- telemetry must not abort scan
        pass


def _run_important_port_scan_with_dashboard(
    shell: NmapShell,
    *,
    command: str,
    domain: str,
    timeout_seconds: int,
    run_scan_fallback: "callable",
    total_hosts: int | None = None,
    _is_full_adscan_container_runtime: "callable | None" = None,
    _sudo_validate: "callable | None" = None,
) -> any:
    """Run the important-port Nmap scan LIVE under a streaming dashboard.

    Streams the scan via ``shell.spawn_command`` and parses its stdout in real
    time so the dashboard's host counter and percent advance DURING the scan
    (not just at completion). All the robustness of the buffered path is
    preserved:

    * **Sudo retry** -- a privilege-denied first attempt re-spawns under sudo.
    * **Timeout recovery** -- the streaming loop enforces its own wall-clock
      budget (``Popen.readline`` has none); on overrun it offers the same
      "retry without timeout" prompt, gated by ``is_non_interactive``.
    * **Clean env** -- inherited from ``spawn_command``.
    * **Non-TTY / CI** -- handled by ``LiveSession`` itself.

    FAIL-SAFE: if the dashboard cannot be built or the process cannot be
    spawned, it falls back to ``run_scan_fallback`` (the buffered path) so the
    scan always completes and the result handling is never skipped.

    Args:
        shell: Active shell exposing ``spawn_command`` + ``run_command``.
        command: Full Nmap command string.
        domain: Domain for timeout-recovery messaging.
        timeout_seconds: Wall-clock budget for the streaming scan.
        run_scan_fallback: Zero-arg buffered-path callable used when streaming
            cannot be set up.
        total_hosts: Number of hosts queued for the scan (forwarded to the
            streamer so the structured ``port_scan`` operation event is a
            determinate "X of Y hosts" bar).
        _is_full_adscan_container_runtime: Optional container runtime detector
            (forwarded to the sudo-retry logic).
        _sudo_validate: Optional sudo validation callback.

    Returns:
        A :class:`_StreamingScanResult` (CompletedProcess-shaped) or whatever
        the fallback returns; ``None`` on unrecoverable failure.
    """
    try:
        dashboard = _build_important_port_scan_dashboard()
    except Exception:  # noqa: BLE001 -- dashboard build must never block the scan
        return run_scan_fallback()

    def _stream_once(
        cmd: str,
        budget: int | None,
        dash: "ProgressDashboard",
        *,
        emit_terminal_done: bool,
    ) -> _StreamingScanResult | None:
        return _stream_nmap_scan_into_dashboard(
            shell,
            command=cmd,
            timeout_seconds=budget,
            dashboard=dash,
            domain=domain,
            total_hosts=total_hosts,
            emit_terminal_done=emit_terminal_done,
        )

    def _emit_terminal_done(dash: "ProgressDashboard") -> None:
        _emit_port_scan_terminal_done(
            dash,
            total_hosts=total_hosts,
            domain=domain,
            hosts_found=getattr(dash, "_done", 0) or 0,
        )

    def _maybe_sudo_retry(
        result: _StreamingScanResult, budget: int | None, dash: "ProgressDashboard"
    ) -> _StreamingScanResult:
        """Re-spawn under sudo when the attempt was privilege-denied.

        Owns the SINGLE terminal ``done=True`` for the operation. The first
        attempt streamed with ``emit_terminal_done=False`` (it might be retried),
        so this function emits the terminal tick exactly once for the FINAL
        result: the sudo-retry attempt carries it (``emit_terminal_done=True``)
        when a retry happens, otherwise this function emits it directly for the
        first (final) attempt. A privilege-denied attempt that re-spawns under
        sudo therefore never latches the web widget complete at elapsed ~0.
        """
        if result.returncode == 0:
            _emit_terminal_done(dash)
            return result
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        needs_priv = _nmap_output_indicates_missing_privileges(combined)
        can_escalate = os.geteuid() != 0 and shutil.which("sudo") is not None
        if not needs_priv or not can_escalate:
            # No retry will happen: the first attempt was final — emit its tick.
            _emit_terminal_done(dash)
            return result
        if _is_full_adscan_container_runtime and _is_full_adscan_container_runtime():
            print_info_debug(
                "Nmap important port scan requires privileges in container "
                "runtime; retrying via sudo -n."
            )
            retry = _stream_once(f"sudo -n {command}", budget, dash, emit_terminal_done=True)
            if retry is not None:
                return retry
            # Sudo re-spawn could not start — the first attempt is the result we
            # return, so it owns the terminal tick (suppressed on its own run).
            _emit_terminal_done(dash)
            return result
        if _sudo_validate is None or _sudo_validate():
            print_info_debug(
                "Nmap important port scan requires privileges; retrying via sudo."
            )
            retry = _stream_once(f"sudo {command}", budget, dash, emit_terminal_done=True)
            if retry is not None:
                return retry
            _emit_terminal_done(dash)
            return result
        # Sudo validation declined — no retry; the first attempt is final.
        _emit_terminal_done(dash)
        return result

    def _streamed_out() -> bool:
        last_error = getattr(shell, "_last_run_command_error", None)
        return (
            isinstance(last_error, tuple)
            and len(last_error) >= 1
            and str(last_error[0]).strip().lower() == "timeout"
        )

    try:
        with dashboard.live_session():
            # First attempt suppresses the terminal done — it may be retried
            # under sudo. `_maybe_sudo_retry` owns the single terminal tick.
            result = _stream_once(command, timeout_seconds, dashboard, emit_terminal_done=False)
            if result is None:
                # spawn failed -- leave the live session, fall back below.
                raise _StreamingSpawnFailed()
            result = _maybe_sudo_retry(result, timeout_seconds, dashboard)
    except _StreamingSpawnFailed:
        # Could not spawn -- buffered fallback (no live session was entered).
        return run_scan_fallback()
    except Exception:  # noqa: BLE001 -- LiveSession / setup failure
        return run_scan_fallback()

    # Timeout recovery is handled OUTSIDE the alt-screen Live (a confirm prompt
    # inside an alt-screen buffer would be invisible). The streaming loop marks
    # `_last_run_command_error = ("timeout", ...)` on wall-clock overrun.
    if result.returncode != 0 and _streamed_out():
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Nmap port scan for domain {marked_domain} timed out after "
            f"{timeout_seconds} seconds."
        )
        print_info("This is common on very large domains or slow VPN links.")
        if is_non_interactive(shell):
            print_warning("Non-interactive mode detected; skipping retry without timeout.")
            return result
        retry_without_timeout = Confirm.ask(
            "Do you want to retry the same Nmap scan without timeout?",
            default=False,
        )
        if not retry_without_timeout:
            return result
        print_info(
            f"Retrying Nmap port scan for domain {marked_domain} without timeout. "
            "This may take a long time."
        )
        try:
            retry_dashboard = _build_important_port_scan_dashboard()
        except Exception:  # noqa: BLE001
            return run_scan_fallback()
        try:
            with retry_dashboard.live_session():
                retry_result = _stream_once(command, None, retry_dashboard, emit_terminal_done=False)
                if retry_result is None:
                    raise _StreamingSpawnFailed()
                retry_result = _maybe_sudo_retry(retry_result, None, retry_dashboard)
            return retry_result
        except _StreamingSpawnFailed:
            return run_scan_fallback()
        except Exception:  # noqa: BLE001
            return run_scan_fallback()

    return result


def _parse_gnmap_open_ports(text: str) -> dict[str, set[int]]:
    """Parse `nmap -oG` output and return open TCP ports per host.

    Args:
        text: Grepable nmap output text.

    Returns:
        Dictionary mapping host IPs to sets of open TCP port numbers.
    """
    results: dict[str, set[int]] = {}
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("Host:"):
            continue
        # Example: Host: 10.10.10.1 ()  Ports: 445/open/tcp//microsoft-ds///, ...
        try:
            host_part, rest_part = line.split("\t", 1)
            host_ip = host_part.split()[1]
        except Exception:
            continue
        if "Ports:" not in rest_part:
            continue
        ports_blob = rest_part.split("Ports:", 1)[1]
        ports: set[int] = set()
        for entry in ports_blob.split(","):
            entry = entry.strip()
            if not entry:
                continue
            fields = entry.split("/")
            if len(fields) < 3:
                continue
            port_str, state, proto = fields[0], fields[1], fields[2]
            if proto != "tcp" or state != "open":
                continue
            try:
                ports.add(int(port_str))
            except ValueError:
                continue
        if ports:
            results[host_ip] = ports
    return results


def _parse_gnmap_up_hosts(text: str) -> set[str]:
    """Parse `nmap -oG` output and return hosts marked as up."""
    results: set[str] = set()
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("Host:"):
            continue
        if "Status: Up" not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        candidate = str(parts[1]).strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        results.add(candidate)
    return results


def _prefix_hint_from_ipv4(ip_value: str) -> str | None:
    """Return a coarse `/24` prefix hint for an IPv4 address."""
    try:
        parsed = ipaddress.ip_address(str(ip_value).strip())
    except ValueError:
        return None
    if parsed.version != 4:
        return None
    network = ipaddress.ip_network(f"{parsed}/24", strict=False)
    return str(network)


def _build_ip_to_hostnames_map(
    hostnames: list[str],
    host_to_ips: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Return a stable IP -> hostnames mapping from massdns results."""
    normalized_host_to_ips = {
        str(hostname or "").strip().rstrip(".").lower(): list(ips)
        for hostname, ips in host_to_ips.items()
        if str(hostname or "").strip()
    }
    ip_to_hostnames: dict[str, list[str]] = {}
    for hostname in hostnames:
        key = str(hostname or "").strip().rstrip(".").lower()
        if not key:
            continue
        for ip_value in normalized_host_to_ips.get(key, []):
            if not ip_value:
                continue
            existing = ip_to_hostnames.setdefault(ip_value, [])
            if hostname not in existing:
                existing.append(hostname)
    return ip_to_hostnames


def _write_ip_list_file(path: str, ips: list[str]) -> bool:
    """Persist one IP per line."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            for ip_value in ips:
                handle.write(f"{ip_value}\n")
    except OSError:
        return False
    return True


def _remove_file_if_exists(path: str) -> None:
    """Remove a file if it exists, ignoring missing-file and OS errors."""
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        return


def _build_network_reachability_report(
    hostnames: list[str],
    host_to_ips: dict[str, list[str]],
    *,
    discovery_up_ips: set[str],
    ports_scanned: list[int],
    open_ports_by_host: dict[str, set[int]] | None = None,
    port_scan_performed: bool = False,
    domain: str | None = None,
    resolved_ip_file: str | None = None,
    reachable_ip_file: str | None = None,
    no_response_ip_file: str | None = None,
    discovery_output_file: str | None = None,
    port_scan_output_file: str | None = None,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Build a structured current-vantage reachability report for resolved hosts."""
    normalized_host_to_ips = {
        str(hostname or "").strip().rstrip(".").lower(): list(ips)
        for hostname, ips in host_to_ips.items()
        if str(hostname or "").strip()
    }
    ordered_unique_ips = _flatten_massdns_unique_ips(hostnames, normalized_host_to_ips)
    ip_to_hostnames = _build_ip_to_hostnames_map(hostnames, normalized_host_to_ips)
    open_ports_map = open_ports_by_host or {}

    prefix_stats: dict[str, dict[str, int]] = {}
    for ip_value in ordered_unique_ips:
        prefix_hint = _prefix_hint_from_ipv4(ip_value)
        if not prefix_hint:
            continue
        stats = prefix_stats.setdefault(
            prefix_hint, {"responsive": 0, "no_response": 0}
        )
        if ip_value in discovery_up_ips:
            stats["responsive"] += 1
        else:
            stats["no_response"] += 1

    ip_entries: list[dict[str, object]] = []
    host_entries: list[dict[str, object]] = []
    possible_segment_clusters: list[dict[str, object]] = []
    responsive_ips = set(discovery_up_ips)
    likely_down_count = 0
    no_response_count = 0
    discovery_only_count = 0
    responded_no_ports_count = 0
    open_service_count = 0
    mixed_reachability_hostnames: list[str] = []

    for prefix_hint, stats in sorted(prefix_stats.items()):
        if stats["no_response"] >= 2 and stats["responsive"] == 0:
            cluster_hosts = sorted(
                {
                    hostname
                    for ip_value in ordered_unique_ips
                    if _prefix_hint_from_ipv4(ip_value) == prefix_hint
                    for hostname in ip_to_hostnames.get(ip_value, [])
                },
                key=str.lower,
            )
            possible_segment_clusters.append(
                {
                    "prefix_hint": prefix_hint,
                    "responsive_ips": stats["responsive"],
                    "no_response_ips": stats["no_response"],
                    "hostnames_preview": cluster_hosts[:5],
                    "reason": (
                        "All observed IPs in this /24 prefix produced no TCP discovery response "
                        "from the current vantage. Pivoting or alternate routing may be required."
                    ),
                }
            )

    for ip_value in ordered_unique_ips:
        prefix_hint = _prefix_hint_from_ipv4(ip_value)
        same_prefix_stats = prefix_stats.get(
            prefix_hint or "", {"responsive": 0, "no_response": 0}
        )
        open_ports = sorted(open_ports_map.get(ip_value, set()))
        if port_scan_performed:
            if open_ports:
                status = "open_service_observed"
                classification = "reachable_with_important_services"
                open_service_count += 1
            elif ip_value in responsive_ips:
                status = "host_responded_no_important_ports_open"
                classification = "reachable_no_important_services"
                responded_no_ports_count += 1
            else:
                status = "no_response_from_current_vantage"
                if same_prefix_stats.get("responsive", 0) > 0:
                    classification = "likely_down_or_offline"
                    likely_down_count += 1
                else:
                    classification = "possible_segment_or_filtered"
                no_response_count += 1
        else:
            if ip_value in responsive_ips:
                status = "responded_to_discovery"
                classification = "reachable_discovery_only"
                discovery_only_count += 1
            else:
                status = "no_response_from_current_vantage"
                if same_prefix_stats.get("responsive", 0) > 0:
                    classification = "likely_down_or_offline"
                    likely_down_count += 1
                else:
                    classification = "possible_segment_or_filtered"
                no_response_count += 1

        ip_entries.append(
            {
                "ip": ip_value,
                "status": status,
                "classification": classification,
                "open_ports": open_ports,
                "hostname_candidates": ip_to_hostnames.get(ip_value, []),
                "prefix_hint": prefix_hint,
            }
        )

    for hostname in hostnames:
        key = str(hostname or "").strip().rstrip(".").lower()
        ips = []
        statuses: set[str] = set()
        for ip_value in normalized_host_to_ips.get(key, []):
            ip_entry = next(
                (entry for entry in ip_entries if entry.get("ip") == ip_value), None
            )
            if not isinstance(ip_entry, dict):
                continue
            statuses.add(str(ip_entry.get("status") or "").strip())
            ips.append(
                {
                    "ip": ip_value,
                    "status": ip_entry.get("status"),
                    "classification": ip_entry.get("classification"),
                    "open_ports": ip_entry.get("open_ports", []),
                    "prefix_hint": ip_entry.get("prefix_hint"),
                }
            )
        if len(statuses) > 1:
            mixed_reachability_hostnames.append(hostname)
        host_entries.append({"hostname": hostname, "ips": ips})

    summary: dict[str, object] = {
        "total_ips": len(ordered_unique_ips),
        "responsive_ips": len(responsive_ips),
        "no_response_ips": no_response_count,
        "likely_down_or_offline_ips": likely_down_count,
        "mixed_reachability_hostnames": len(mixed_reachability_hostnames),
        "possible_segment_clusters": len(possible_segment_clusters),
        "important_port_scan_performed": port_scan_performed,
    }
    if port_scan_performed:
        summary["open_service_ips"] = open_service_count
        summary["responded_no_important_ports_ips"] = responded_no_ports_count
    else:
        summary["discovery_only_reachable_ips"] = discovery_only_count

    context: dict[str, object] = {
        "ports_scanned": ports_scanned,
    }
    if domain:
        context["domain"] = domain
    if resolved_ip_file:
        context["resolved_ip_file"] = resolved_ip_file
    if reachable_ip_file:
        context["reachable_ip_file"] = reachable_ip_file
    if no_response_ip_file:
        context["no_response_ip_file"] = no_response_ip_file
    if discovery_output_file:
        context["discovery_output_file"] = discovery_output_file
    if port_scan_output_file:
        context["important_port_scan_output_file"] = port_scan_output_file

    payload = {
        "summary": summary,
        "context": context,
        "hosts": host_entries,
        "ips": ip_entries,
        "possible_segment_clusters": possible_segment_clusters,
        "mixed_reachability_hostnames": sorted(
            mixed_reachability_hostnames, key=str.lower
        ),
    }
    if generated_at:
        payload["generated_at"] = generated_at
    return payload


def _write_network_reachability_report(
    report_path: str, payload: dict[str, object]
) -> bool:
    """Persist the structured reachability report to disk."""
    try:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=False)
            handle.write("\n")
    except OSError:
        return False
    return True


def _load_network_reachability_report(report_path: str) -> dict[str, object] | None:
    """Load a structured reachability report from disk."""
    if not report_path or not os.path.exists(report_path):
        return None
    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _show_network_reachability_summary(
    shell: NmapShell,
    *,
    payload: dict[str, object],
    report_file: str | None = None,
) -> None:
    """Render a concise current-vantage reachability summary."""
    summary = (
        payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    )
    ip_entries = payload.get("ips", []) if isinstance(payload.get("ips"), list) else []
    possible_segment_clusters = (
        payload.get("possible_segment_clusters", [])
        if isinstance(payload.get("possible_segment_clusters"), list)
        else []
    )
    mixed_reachability_hostnames = (
        payload.get("mixed_reachability_hostnames", [])
        if isinstance(payload.get("mixed_reachability_hostnames"), list)
        else []
    )
    port_scan_performed = bool(summary.get("important_port_scan_performed"))
    total_ips = int(summary.get("total_ips") or len(ip_entries))
    responsive_ips = int(summary.get("responsive_ips") or 0)
    no_response_ips = int(summary.get("no_response_ips") or 0)

    if port_scan_performed:
        open_service_ips = int(summary.get("open_service_ips") or 0)
        responded_no_ports = int(summary.get("responded_no_important_ports_ips") or 0)
        print_info(
            "Current-vantage network reachability: "
            f"{open_service_ips}/{total_ips} IP(s) exposed important services, "
            f"{responded_no_ports} responded without those services, "
            f"and {no_response_ips} produced no response."
        )
    else:
        print_info(
            "Current-vantage TCP discovery: "
            f"{responsive_ips}/{total_ips} IP(s) responded and {no_response_ips} produced no response."
        )

    try:
        emit_event(
            "coverage",
            phase="domain_analysis",
            phase_label="Domain Analysis",
            category="network_coverage",
            domain=str(payload.get("domain") or ""),
            metric_type="network_reachability",
            total_ips=total_ips,
            reachable_ips=responsive_ips,
            unreachable_ips=no_response_ips,
            open_service_ips=int(summary.get("open_service_ips") or 0),
            important_port_scan_performed=port_scan_performed,
            possible_segments=len(possible_segment_clusters),
            message=(
                f"Network reachability updated: {responsive_ips}/{total_ips} resolved IPs responded"
                + (
                    f", {int(summary.get('open_service_ips') or 0)} exposed important services."
                    if port_scan_performed
                    else "."
                )
            ),
        )
    except Exception as exc:  # pragma: no cover
        telemetry.capture_exception(exc)

    likely_down_entries = [
        entry
        for entry in ip_entries
        if isinstance(entry, dict)
        and str(entry.get("classification") or "").strip() == "likely_down_or_offline"
    ]
    if likely_down_entries:
        print_info(
            f"{len(likely_down_entries)} IP(s) share a /24 prefix with responsive peers and may simply be offline/down."
        )
    if possible_segment_clusters:
        print_warning(
            f"Detected {len(possible_segment_clusters)} possible no-response network cluster(s). Pivoting may be required."
        )
    if report_file:
        print_info(
            "Detailed network reachability report saved to "
            f"{mark_sensitive(report_file, 'path')}."
        )

    if not getattr(shell, "console", None):
        return

    no_response_preview = [
        entry
        for entry in ip_entries
        if isinstance(entry, dict)
        and str(entry.get("status") or "").strip() == "no_response_from_current_vantage"
    ][:_REACHABILITY_PREVIEW_LIMIT]
    if no_response_preview:
        table = Table(
            title=(
                "No-Response IPs"
                if len(no_response_preview) < _REACHABILITY_PREVIEW_LIMIT
                else f"No-Response IPs (showing first {_REACHABILITY_PREVIEW_LIMIT})"
            ),
            show_header=True,
            header_style="bold yellow",
            box=rich.box.ROUNDED,
        )
        table.add_column("IP", style="yellow")
        table.add_column("Classification")
        table.add_column("Prefix Hint")
        table.add_column("Hostname(s)")
        for entry in no_response_preview:
            table.add_row(
                mark_sensitive(str(entry.get("ip") or ""), "ip"),
                str(entry.get("classification") or "-"),
                str(entry.get("prefix_hint") or "-"),
                ", ".join(
                    mark_sensitive(str(hostname), "hostname")
                    for hostname in entry.get("hostname_candidates", [])[:2]
                )
                if isinstance(entry.get("hostname_candidates"), list)
                else "-",
            )
        shell.console.print(table)

    if possible_segment_clusters:
        cluster_table = Table(
            title="Possible Segment Clusters",
            show_header=True,
            header_style="bold magenta",
            box=rich.box.ROUNDED,
        )
        cluster_table.add_column("Prefix Hint", style="magenta")
        cluster_table.add_column("No Response", justify="right")
        cluster_table.add_column("Preview Hostnames")
        for cluster in possible_segment_clusters[:_REACHABILITY_PREVIEW_LIMIT]:
            if not isinstance(cluster, dict):
                continue
            host_preview = cluster.get("hostnames_preview", [])
            cluster_table.add_row(
                str(cluster.get("prefix_hint") or "-"),
                str(cluster.get("no_response_ips") or "-"),
                ", ".join(
                    mark_sensitive(str(hostname), "hostname")
                    for hostname in host_preview
                )
                if isinstance(host_preview, list)
                else "-",
            )
        shell.console.print(cluster_table)

    if mixed_reachability_hostnames:
        mixed_preview = mixed_reachability_hostnames[:_REACHABILITY_PREVIEW_LIMIT]
        print_info(
            "Mixed reachability hostnames: "
            + ", ".join(
                mark_sensitive(str(hostname), "hostname") for hostname in mixed_preview
            )
            + (
                f", +{len(mixed_reachability_hostnames) - len(mixed_preview)} more"
                if len(mixed_reachability_hostnames) > len(mixed_preview)
                else ""
            )
        )


def save_domain_host_to_file(
    shell: NmapShell, host: str, service_dir: str, domain: str
) -> None:
    """Save the host's IP to the corresponding domain file, avoiding duplicates.

    Args:
        shell: The active shell instance with workspace and domain data.
        host: Host IP address to save.
        service_dir: Service directory name (e.g., "smb", "rdp").
        domain: Domain name.
    """
    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    domain_service_dir = domain_subpath(
        workspace_cwd, shell.domains_dir, domain, service_dir
    )

    if not os.path.exists(domain_service_dir):
        os.makedirs(domain_service_dir)

    host_file = os.path.join(domain_service_dir, "ips.txt")

    # Set to store existing hosts
    existing_hosts = set()

    # If the file exists, read the existing hosts
    if os.path.exists(host_file):
        with open(host_file, "r", encoding="utf-8") as f:
            existing_hosts = set(line.strip() for line in f.readlines())

    # If the host is not in the file, add it
    if host not in existing_hosts:
        with open(host_file, "a", encoding="utf-8") as f:
            f.write(f"{host}\n")


def save_host_to_file(shell: NmapShell, host: str, service_dir: str) -> None:
    """Save the host IP to the corresponding file for the service, avoiding duplicates.

    Args:
        shell: The active shell instance with workspace data.
        host: Host IP address to save.
        service_dir: Service directory path.
    """
    if not os.path.exists(service_dir):
        os.makedirs(service_dir)

    host_file = os.path.join(service_dir, "ips.txt")

    # Set to store existing hosts
    existing_hosts = set()

    # If the file exists, read the existing hosts
    if os.path.exists(host_file):
        with open(host_file, "r", encoding="utf-8") as f:
            existing_hosts = set(line.strip() for line in f.readlines())

    # If the host is not in the file, add it
    if host not in existing_hosts:
        with open(host_file, "a", encoding="utf-8") as f:
            f.write(f"{host}\n")


# Service name -> (shell service-dir attribute, tcp port). SSOT for the per-service
# {service}/ips.txt write surface AND the active-host cap intersection, so the cap
# and the writer can never drift on which port maps to which service directory.
_SERVICE_DIR_PORTS: tuple[tuple[str, str, int], ...] = (
    ("smb", "smb_dir", 445),
    ("winrm", "winrm_dir", 5985),
    ("rdp", "rdp_dir", 3389),
    ("mssql", "mssql_dir", 1433),
    ("ftp", "ftp_dir", 21),
    ("ssh", "ssh_dir", 22),
    ("dns", "dns_dir", 53),
    ("http", "http_dir", 80),
    ("https", "https_dir", 443),
    ("ldap", "ldap_dir", 389),
    ("vnc", "vnc_dir", 5900),
    ("kerberos", "kerberos_dir", 88),
)


def _resolve_active_host_cap(shell: "NmapShell") -> int:
    """Resolve the active-host cap from the scan config (mirror of
    ``intelligence._resolve_host_cap``).

    Reads ``shell.scan_config.host_cap`` (the SSOT set by ``adscan ci`` / the web
    scan-config form). Absent/malformed → ``0`` (unlimited), so a plain interactive
    run keeps every reachable host in every service list (legacy behavior).
    """
    try:
        cap = int(getattr(getattr(shell, "scan_config", None), "host_cap", 0) or 0)
        return cap if cap > 0 else 0
    except Exception:  # noqa: BLE001 — a bad config must never break the scan
        return 0


def _load_domain_computer_props(shell: "NmapShell", domain: str) -> list[dict]:
    """Load the Phase-2 attack-graph Computer property dicts for ``domain``.

    Best-effort: returns ``[]`` when the graph is absent/unreadable (the cap then
    falls back to an IP-only representative-first order — Tier 0 hosts still surface
    via the unknown-IP tie-break, never raises). Used only to feed the active-host
    cap's tier ordering; never gates whether the scan ran.
    """
    try:
        from adscan_internal.services.attack_graph_service import load_attack_graph
        from adscan_internal.services.graph_queries.inventories import (
            get_enabled_computers,
        )

        graph = load_attack_graph(shell, domain)
        if not isinstance(graph, dict):
            return []
        return list(get_enabled_computers(graph, domain))
    except Exception as exc:  # noqa: BLE001 — graph load must never abort the scan
        telemetry.capture_exception(exc)
        return []


def _write_capped_service_ips(
    shell: "NmapShell",
    domain: str,
    open_ports_by_host: dict[str, set[int]],
) -> None:
    """Write each domain ``{service}/ips.txt`` bounded to the capped active host set.

    When ``host_cap`` is positive, the reachable active host set (hosts exposing any
    targeted AD service port) is capped representative-first (Tier 0 / DCs / ADCS
    first) into a SINGLE union; every ``{service}/ips.txt`` is then that union ∩ the
    hosts with that service's port open — so the TOTAL active footprint (and every
    downstream SMB/WinRM/MSSQL privilege sweep) is bounded to ``host_cap`` hosts, not
    ``host_cap`` per service. ``host_cap=0`` is a no-op: every reachable service host
    is written (legacy behavior).

    Args:
        shell: The active shell (service-dir attributes + scan config + graph load).
        domain: Domain whose per-domain service files are being written.
        open_ports_by_host: ``{ip: {open tcp ports}}`` from the just-finished scan.
    """
    from adscan_internal.services.collector.active_host_cap import (
        select_capped_active_hosts,
    )

    service_ports = {name: port for name, _attr, port in _SERVICE_DIR_PORTS}
    # The active universe is exactly the hosts that would land in SOME
    # {service}/ips.txt under the legacy writer: every host with at least one
    # targeted service port open. A host with an open port IS reachable for that
    # service (the open-ports map is the port scan's reachability signal), so this
    # set equals the legacy write universe — making host_cap=0 a byte-for-byte
    # no-op.
    targeted_ports = set(service_ports.values())
    active_universe = [
        ip for ip, ports in open_ports_by_host.items() if ports & targeted_ports
    ]

    host_cap = _resolve_active_host_cap(shell)
    computers_props = _load_domain_computer_props(shell, domain) if host_cap > 0 else []

    capped = select_capped_active_hosts(
        reachable_ips=active_universe,
        open_ports_by_host=open_ports_by_host,
        service_ports=service_ports,
        computers_props=computers_props,
        host_cap=host_cap,
    )

    for service, attr, _port in _SERVICE_DIR_PORTS:
        for host_ip in capped.service_ips.get(service, []):
            save_domain_host_to_file(shell, host_ip, getattr(shell, attr), domain)


def _normalize_massdns_hostname(hostname: object) -> str:
    """Normalize a hostname for massdns map lookups (strip, drop trailing dot, lowercase)."""
    return str(hostname or "").strip().rstrip(".").lower()


def _load_persisted_massdns_host_to_ips(report_path: str) -> dict[str, list[str]] | None:
    """Load a persisted massdns report and return a normalized hostname -> IPs map.

    Returns ``None`` when the report is absent or unreadable, signalling the caller
    to fall back to a full massdns resolution (no regression for standalone use).

    Args:
        report_path: Path to the persisted ``massdns_resolution_report.json``.

    Returns:
        A mapping of normalized hostname to its list of resolved IPs, or ``None``.
    """
    payload = _load_massdns_resolution_report(report_path)
    if not isinstance(payload, dict):
        return None
    resolved = payload.get("resolved")
    if not isinstance(resolved, list):
        return None
    host_to_ips: dict[str, list[str]] = {}
    for entry in resolved:
        if not isinstance(entry, dict):
            continue
        normalized = _normalize_massdns_hostname(entry.get("hostname"))
        if not normalized:
            continue
        ips = entry.get("ips")
        if not isinstance(ips, list):
            continue
        host_to_ips[normalized] = [str(ip) for ip in ips if str(ip).strip()]
    return host_to_ips


def _resolve_normalized_host_to_ips(
    *,
    shell: "NmapShell",
    domain: str,
    cleaned_hosts: list[str],
    report_path: str,
    massdns_bin: str,
    resolvers_file: str,
    hosts_file: str,
    massdns_output: str,
) -> tuple[dict[str, list[str]], bool]:
    """Resolve hostnames to IPs, consuming the persisted massdns report when present.

    Delta top-up: Phase 2 (the collector DNS resolver) persists a superset
    ``massdns_resolution_report.json`` into the same domain dir. When that report
    is present, this consumes it and only runs massdns for the hostnames it does
    not already cover. When it is absent or unreadable (Phase 2 never ran, or this
    is a standalone ``nmap``/CLI invocation), it falls back to a full massdns
    resolution so standalone use is never regressed.

    Args:
        shell: The active shell instance (used for ``run_command``).
        domain: Domain name (for user-facing messages).
        cleaned_hosts: The hostnames Phase 3 needs resolved.
        report_path: Path to the persisted ``massdns_resolution_report.json``.
        massdns_bin: Path to the massdns binary.
        resolvers_file: Path to the massdns resolvers file.
        hosts_file: Path to the massdns hosts input file (rewritten for the delta).
        massdns_output: Path to the massdns NDJSON output file.

    Returns:
        A tuple of ``(normalized_host_to_ips, ok)``. ``ok`` is ``False`` only when
        a required massdns run failed (the caller should return early).
    """

    def _run_massdns(host_list_file: str) -> dict[str, list[str]] | None:
        marked_domain = mark_sensitive(domain, "domain")
        massdns_command = (
            f"{shlex.quote(massdns_bin)} -r {shlex.quote(resolvers_file)} "
            f"-t A -o J -w {shlex.quote(massdns_output)} {shlex.quote(host_list_file)}"
        )
        completed = shell.run_command(massdns_command, timeout=300)
        if completed is None:
            print_error(
                f"Failed to resolve hostnames to IPs for domain {marked_domain} "
                "(massdns timeout or execution error)."
            )
            return None
        return parse_massdns_ndjson_a_record_map(massdns_output)

    report_host_to_ips = _load_persisted_massdns_host_to_ips(report_path)
    marked_domain = mark_sensitive(domain, "domain")

    if report_host_to_ips is None:
        # Report absent / unreadable -> full resolution (no regression for standalone use).
        host_to_ips = _run_massdns(hosts_file)
        if host_to_ips is None:
            return {}, False
        normalized_host_to_ips = {
            _normalize_massdns_hostname(hostname): list(ips)
            for hostname, ips in host_to_ips.items()
            if _normalize_massdns_hostname(hostname)
        }
        return normalized_host_to_ips, True

    normalized_host_to_ips = {
        normalized: list(ips) for normalized, ips in report_host_to_ips.items()
    }
    delta_hosts = [
        host
        for host in cleaned_hosts
        if _normalize_massdns_hostname(host) not in report_host_to_ips
    ]
    if not delta_hosts:
        print_info_verbose(
            f"Reusing persisted DNS resolution for {marked_domain}; "
            "all required hostnames are already resolved (skipping massdns)."
        )
        return normalized_host_to_ips, True

    print_info_verbose(
        f"Reusing persisted DNS resolution for {marked_domain}; "
        f"resolving {len(delta_hosts)} new hostname(s) not yet in the report."
    )
    with open(hosts_file, "w", encoding="utf-8") as f:
        for host in delta_hosts:
            f.write(f"{host}\n")
    delta_host_to_ips = _run_massdns(hosts_file)
    if delta_host_to_ips is None:
        return {}, False
    for hostname, ips in delta_host_to_ips.items():
        normalized = _normalize_massdns_hostname(hostname)
        if normalized:
            normalized_host_to_ips[normalized] = list(ips)
    return normalized_host_to_ips, True


def convert_hostnames_to_ips_and_scan(
    shell: NmapShell,
    domain: str,
    computers_file: str,
    nmap_dir: str,
    *,
    _is_full_adscan_container_runtime: callable | None = None,
    _sudo_validate: callable | None = None,
    verbose_mode: bool = False,
    render: bool = True,
    auto: bool = False,
) -> None:
    """Convert hostnames to IP addresses using massdns, write enabled_computers_ips.txt,
    and then execute the port scan.

    Args:
        shell: The active shell instance with workspace and domain data.
        domain: Domain name.
        computers_file: Path to file containing hostnames.
        nmap_dir: Directory for nmap scan output.
        _is_full_adscan_container_runtime: Function to check if running in container.
        _sudo_validate: Function to validate sudo access.
        verbose_mode: Whether verbose mode is enabled.
        render: When True (default), render the reachability/unreachable-subnet
            summary UI after the scan. When False, the scan still produces every
            artifact (``{service}/ips.txt``, ``network_reachability_report.json``,
            reachable/no-response IP files) but suppresses the UI — used by the
            Phase-2 (Domain Collection) producer so the rich summary renders once
            in Phase 3 from the persisted report (scan/produce in P2, present in P3).
        auto: When True, run the important-port scan automatically without the
            "Recommended/Optional/High-Noise Important Port Scan" confirmation
            prompt (and without the skip-confirmation follow-up) — used by the
            automatic Phase-2 (Domain Collection) producer so collection is not
            blocked on operator input. Non-interactive runs already auto-resolve
            the prompt; ``auto`` additionally suppresses it for interactive runs.
    """
    ip_file = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "enabled_computers_ips.txt",
    )
    resolution_report_file = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "massdns_resolution_report.json",
    )
    reachable_ip_file = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "enabled_computers_reachable_ips.txt",
    )
    no_response_ip_file = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "enabled_computers_no_response_ips.txt",
    )
    reachability_report_file = os.path.join(
        shell.current_workspace_dir or "",
        shell.domains_dir,
        domain,
        "network_reachability_report.json",
    )
    try:
        hostnames = _read_text_file_best_effort(str(computers_file)).splitlines()
        cleaned_hosts = [h.strip() for h in hostnames if h.strip()]
        marked_computers_file = mark_sensitive(str(computers_file), "path")
        print_info_debug(
            f"Loaded {len(cleaned_hosts)} hostnames from {marked_computers_file}."
        )

        domain_data = (
            shell.domains_data.get(domain, {}) if hasattr(shell, "domains_data") else {}
        )
        resolvers: list[str] = []
        for key in ("dns", "pdc"):
            value = str(domain_data.get(key) or "").strip()
            if value:
                resolvers.append(value)
        for dc in domain_data.get("dcs", []) if isinstance(domain_data, dict) else []:
            dc_value = str(dc or "").strip()
            if dc_value:
                resolvers.append(dc_value)
        resolvers = list(dict.fromkeys(resolvers))
        if not resolvers:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"No DNS resolvers available for {marked_domain}; cannot resolve computers."
            )
            return

        resolvers_file = os.path.join(
            shell.current_workspace_dir or "",
            shell.domains_dir,
            domain,
            "massdns_resolvers.txt",
        )
        hosts_file = os.path.join(
            shell.current_workspace_dir or "",
            shell.domains_dir,
            domain,
            "massdns_hosts.txt",
        )
        with open(resolvers_file, "w", encoding="utf-8") as f:
            for resolver in resolvers:
                f.write(f"{resolver}\n")
        with open(hosts_file, "w", encoding="utf-8") as f:
            for host in cleaned_hosts:
                f.write(f"{host}\n")

        marked_resolvers = mark_sensitive(resolvers_file, "path")
        print_info_debug(
            f"Using massdns resolvers file {marked_resolvers} with {len(resolvers)} resolver(s)."
        )
        if len(resolvers) < 5:
            marked_resolvers_list = [
                mark_sensitive(resolver, "ip") for resolver in resolvers
            ]
            print_info_debug(
                f"massdns resolvers list: {', '.join(marked_resolvers_list)}"
            )
        massdns_bin = shutil.which("massdns")
        if not massdns_bin:
            adscan_home = os.getenv("ADSCAN_HOME") or ""
            candidates = [
                os.path.join(adscan_home, "bin", "massdns"),
                os.path.join(adscan_home, "tools", "massdns", "bin", "massdns"),
            ]
            for candidate in candidates:
                if candidate and os.path.exists(candidate):
                    massdns_bin = candidate
                    break
        if not massdns_bin:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"massdns is not available; cannot resolve computers for {marked_domain}."
            )
            return

        massdns_output = os.path.join(
            shell.current_workspace_dir or "",
            shell.domains_dir,
            domain,
            "massdns_output.jsonl",
        )

        normalized_host_to_ips, resolution_ok = _resolve_normalized_host_to_ips(
            shell=shell,
            domain=domain,
            cleaned_hosts=cleaned_hosts,
            report_path=resolution_report_file,
            massdns_bin=massdns_bin,
            resolvers_file=resolvers_file,
            hosts_file=hosts_file,
            massdns_output=massdns_output,
        )
        if not resolution_ok:
            return
        hostname_ip_map = {
            hostname: normalized_host_to_ips.get(
                str(hostname or "").strip().rstrip(".").lower(),
                [],
            )
            for hostname in cleaned_hosts
        }
        unique_ips = _flatten_massdns_unique_ips(cleaned_hosts, hostname_ip_map)
        resolved_count = sum(
            1 for hostname in cleaned_hosts if hostname_ip_map.get(hostname)
        )
        fallback_used = False
        fallback_reason = None
        if not unique_ips:
            (
                normalized_host_to_ips,
                fallback_used,
                fallback_reason,
            ) = _apply_persisted_pdc_ip_fallback(
                shell=shell,
                domain=domain,
                hostnames=cleaned_hosts,
                host_to_ips=normalized_host_to_ips,
            )
            if fallback_used:
                hostname_ip_map = {
                    hostname: normalized_host_to_ips.get(
                        str(hostname or "").strip().rstrip(".").lower(),
                        [],
                    )
                    for hostname in cleaned_hosts
                }
                unique_ips = _flatten_massdns_unique_ips(cleaned_hosts, hostname_ip_map)
                resolved_count = sum(
                    1 for hostname in cleaned_hosts if hostname_ip_map.get(hostname)
                )
                if not unique_ips:
                    fallback_pdc_ip = str(
                        (
                            shell.domains_data.get(domain, {})
                            if hasattr(shell, "domains_data")
                            else {}
                        ).get("pdc")
                        or ""
                    ).strip()
                    if fallback_pdc_ip:
                        unique_ips = [fallback_pdc_ip]
                fallback_message = (
                    "MassDNS resolved no hostnames. Using the persisted PDC IP "
                    "as a fallback target."
                )
                if fallback_reason == "best_effort_pdc":
                    fallback_message = (
                        "MassDNS resolved no hostnames via SRV-backed DNS. "
                        "Using the persisted PDC IP as a best-effort fallback target."
                    )
                print_warning(fallback_message)
                print_info_debug(
                    f"[massdns] PDC fallback injected for "
                    f"{mark_sensitive(domain, 'domain')}: "
                    f"reason={fallback_reason or 'persisted_pdc'} "
                    f"ip={mark_sensitive(unique_ips[0], 'ip')}"
                )
        total_hosts = len(cleaned_hosts)
        print_success_verbose(
            f"{len(unique_ips)} IPs discovered from hostnames in {marked_computers_file}."
        )
        report_written = _write_massdns_resolution_report(
            resolution_report_file,
            hostnames=cleaned_hosts,
            host_to_ips=hostname_ip_map,
            domain=domain,
            input_file=str(computers_file),
            resolvers=resolvers,
            ip_file=ip_file,
            raw_output_file=massdns_output,
        )
        _show_massdns_resolution_summary(
            shell,
            hostnames=cleaned_hosts,
            host_to_ips=normalized_host_to_ips,
            ip_file=ip_file,
            report_file=resolution_report_file if report_written else None,
        )
        if (
            total_hosts == 0
            or len(unique_ips) == 0
            or resolved_count / max(total_hosts, 1) < 0.1
        ):
            marked_domain = mark_sensitive(domain, "domain")
            panel_lines = [
                "Very few hosts resolved to IP addresses.",
                f"Domain: {marked_domain}",
                f"Resolved hostnames: {resolved_count}/{total_hosts}",
                f"Unique IPs: {len(unique_ips)}",
                "",
                "Check DNS resolvers, connectivity, or host list quality.",
            ]
            print_panel(
                "\n".join(panel_lines),
                title="DNS Resolution Warning",
                border_style="yellow",
                expand=False,
            )
        print_info_debug(
            f"Resolved {resolved_count} hostname(s) into {len(unique_ips)} IP(s) out of {total_hosts} host(s)."
        )
        # Write the unique IP addresses to enabled_computers_ips.txt
        with open(ip_file, "w", encoding="utf-8") as f:
            for ip in unique_ips:
                f.write(f"{ip}\n")
        shell.consolidate_domain_computers("")
        important_ports = [21, 22, 53, 80, 88, 389, 443, 445, 1433, 3389, 5900, 5985]
        important_ports_csv = ",".join(str(port) for port in important_ports)
        ip_count = len(unique_ips)
        marked_domain = mark_sensitive(domain, "domain")
        workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
        is_ctf_workspace = workspace_type == "ctf"
        is_small_scope = ip_count <= _SMALL_IMPORTANT_PORT_SCAN_IP_THRESHOLD
        is_medium_scope = (
            _SMALL_IMPORTANT_PORT_SCAN_IP_THRESHOLD
            < ip_count
            <= _MEDIUM_IMPORTANT_PORT_SCAN_IP_THRESHOLD
        )
        auto_run_small_scope = is_ctf_workspace and is_small_scope
        if auto_run_small_scope:
            decision_lines = [
                "Auto-running the important port scan because this is a small CTF scope.",
                f"Domain: {marked_domain}",
                f"Resolved IPs queued: {ip_count}",
                f"Important TCP ports: {important_ports_csv}",
                "",
                "Why this is automatic here:",
                "- the scope is small",
                "- service visibility is high-value immediately",
                "- segmentation hints are useful early in CTF workflows",
                "",
                "This still generates active network traffic, but the tradeoff is acceptable in CTF mode at this size.",
            ]
            panel_title = "Automatic Important Port Scan"
            prompt_text = ""
            prompt_default = True
        elif is_small_scope:
            decision_lines = [
                "This Nmap scan is recommended for small scopes.",
                f"Domain: {marked_domain}",
                f"Resolved IPs queued: {ip_count}",
                f"Important TCP ports: {important_ports_csv}",
                "",
                "Why run it now:",
                "- quickly confirms which hosts expose important AD services",
                "- shows which resolved IPs do not answer from the current vantage",
                "- helps determine whether pivoting may be needed later",
                "",
                "This is still active network traffic, but the scope is small enough that the value is usually worth it.",
            ]
            panel_title = "Recommended Important Port Scan"
            prompt_text = f"Run the recommended important-port Nmap scan for domain {marked_domain}?"
            prompt_default = True
        elif is_medium_scope:
            decision_lines = [
                "This Nmap scan is useful for validating service exposure and spotting possible segmentation in medium-sized scopes.",
                f"Domain: {marked_domain}",
                f"Resolved IPs queued: {ip_count}",
                f"Important TCP ports: {important_ports_csv}",
                "",
                "Why you may still want it:",
                "- identifies which hosts expose important AD services now",
                "- highlights which resolved IPs do not answer from the current vantage",
                "- can reveal likely pivoting needs before you get shell access",
                "",
                "Tradeoff: this is active network traffic and the noise level is noticeable at this scale.",
            ]
            panel_title = "Optional Important Port Scan"
            prompt_text = (
                f"Run the optional important-port Nmap scan for domain {marked_domain}? "
                "[recommended to confirm reachable hosts and AD service exposure]"
            )
            prompt_default = True
        else:
            decision_lines = [
                "This Nmap scan is the source of truth for current-vantage service exposure and possible segmentation in large domains.",
                f"Domain: {marked_domain}",
                f"Resolved IPs queued: {ip_count}",
                f"Important TCP ports: {important_ports_csv}",
                "",
                "What this gives you:",
                "- which hosts expose important AD services right now",
                "- which hosts respond but do not expose those services",
                "- which resolved IPs produce no response and may require pivoting",
                "",
                "Tradeoff: this is high-noise active network traffic at this scale. Use it only when you want explicit service visibility and segmentation evidence.",
            ]
            panel_title = "High-Noise Important Port Scan"
            prompt_text = (
                f"Run the important-port Nmap scan for domain {marked_domain}? "
                "[recommended when you want current-vantage reachability and service evidence]"
            )
            prompt_default = True
        print_panel(
            "\n".join(decision_lines),
            title=panel_title,
            border_style="yellow",
            expand=False,
        )
        should_run_port_scan = True
        # ``auto`` (Phase-2 automatic producer) runs the scan unconditionally with
        # no operator prompt; ``auto_run_small_scope`` (small CTF scope) is the
        # pre-existing automatic path. Both bypass the confirmation flow.
        if not auto and not auto_run_small_scope:
            should_run_port_scan = bool(
                Confirm.ask(
                    prompt_text,
                    default=prompt_default,
                )
            )
            if not should_run_port_scan:
                should_run_port_scan = not _confirm_skip_important_port_scan(
                    domain=domain,
                    ip_count=ip_count,
                    important_ports_csv=important_ports_csv,
                )
        if should_run_port_scan:
            # Now execute the port scan on the IP file sequentially
            scan_output_path = os.path.join(nmap_dir, "imp_ports_scan")
            try:
                # Pre-create the output file so if we need to run Nmap with sudo,
                # it won't leave root-owned artifacts inside user workspaces.
                os.makedirs(os.path.dirname(scan_output_path), exist_ok=True)
                with open(scan_output_path, "a", encoding="utf-8"):
                    pass
            except Exception:
                # Best-effort; nmap will still run and we can parse stdout as fallback.
                pass

            port_scan_command = (
                f"nmap -sS -PS{important_ports_csv} "
                f"-PA{important_ports_csv} "
                f"-p{important_ports_csv} "
                f"-n -vvv --stats-every 2s -iL {shlex.quote(str(ip_file))} "
                f"-oN {shlex.quote(str(scan_output_path))} "
                f"-oG {shlex.quote(str(scan_output_path))}.gnmap"
            )
            marked_domain = mark_sensitive(domain, "domain")
            print_info(
                f"Executing combined reachability and important-port scan in domain {marked_domain}..."
            )
            print_info_debug(f"Port scan command: {port_scan_command}")

            # Upfront patience notice -- threshold-gated on the IP count queued
            # for the scan. Silent for small scopes; a single line under
            # non-interactive runs. Never blocks the scan.
            try:
                maybe_show_patience_notice(
                    PatienceNoticeConfig(
                        operation="Important port scan",
                        unit="hosts",
                        threshold=100,
                        env_var="ADSCAN_PATIENCE_THRESHOLD_IMPORTANT_PORT_SCAN",
                    ),
                    count=ip_count,
                    non_interactive=is_non_interactive(shell),
                )
            except Exception:  # noqa: BLE001 -- notice must never abort the scan
                pass

            # Streaming live dashboard. Nmap is launched non-blocking via
            # spawn_command and its -vvv --stats-every stdout is parsed in real
            # time, so the host counter + percent advance DURING the scan. The
            # streaming runner owns its own wall-clock timeout (Popen.readline
            # has none), sudo-retry, and the timeout-recovery prompt; LiveSession
            # handles the non-TTY/CI fallback. FAIL-SAFE: if streaming can't be
            # set up it falls back to the buffered path (run_scan_fallback), and
            # the authoritative post-scan .gnmap parse below is unchanged.
            def _run_port_scan_buffered() -> any:
                return _run_nmap_command_with_optional_sudo_retry(
                    shell,
                    command=port_scan_command,
                    domain=domain,
                    timeout_seconds=NMAP_IMPORTANT_PORTS_SCAN_TIMEOUT_SECONDS,
                    _is_full_adscan_container_runtime=_is_full_adscan_container_runtime,
                    _sudo_validate=_sudo_validate,
                    retry_debug_context="combined reachability/port scan",
                )

            completed_scan_process = _run_important_port_scan_with_dashboard(
                shell,
                command=port_scan_command,
                domain=domain,
                timeout_seconds=NMAP_IMPORTANT_PORTS_SCAN_TIMEOUT_SECONDS,
                run_scan_fallback=_run_port_scan_buffered,
                # Drive the platform's "X of Y hosts" port-scan bar off the
                # queued IP count (enabled_computers_ips.txt line count).
                total_hosts=ip_count,
                _is_full_adscan_container_runtime=_is_full_adscan_container_runtime,
                _sudo_validate=_sudo_validate,
            )

            if completed_scan_process is None:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Failed to run Nmap port scan for domain {marked_domain} (timeout or execution error)."
                )
                return

            if completed_scan_process.returncode == 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_info_verbose(f"Nmap scan stdout for domain {marked_domain}:")
                gnmap_path = f"{scan_output_path}.gnmap"
                gnmap_text = _read_text_file_best_effort(gnmap_path)
                normal_text = _read_text_file_best_effort(scan_output_path)
                discovery_up_ips = _parse_gnmap_up_hosts(gnmap_text)
                reachable_ips = [ip for ip in unique_ips if ip in discovery_up_ips]
                no_response_ips = [
                    ip for ip in unique_ips if ip not in discovery_up_ips
                ]
                _write_ip_list_file(reachable_ip_file, reachable_ips)
                _write_ip_list_file(no_response_ip_file, no_response_ips)

                open_ports_by_host = _parse_gnmap_open_ports(gnmap_text)
                if not open_ports_by_host:
                    print_info_debug(
                        f"[DEBUG] Nmap completed with rc=0 but no open ports parsed from gnmap (len={len(gnmap_text)})."
                    )
                    if verbose_mode and normal_text:
                        for line in normal_text.splitlines():
                            shell.console.print(line)

                # Per-service {service}/ips.txt, bounded by the active-host cap.
                # The port scan above already ran on ALL hosts (cheap, complete
                # reachability inventory); this caps the REACHABLE active set to the
                # top host_cap hosts representative-first (Tier 0 first) as a single
                # union, then writes each service list as union ∩ service-open. With
                # host_cap=0 it is a no-op (every reachable service host written).
                _write_capped_service_ips(shell, domain, open_ports_by_host)

                discovered_hosts = len(open_ports_by_host)
                discovered_ports = sum(len(p) for p in open_ports_by_host.values())
                print_success(
                    f"Important port scan for the domain completed (hosts_with_open_ports={discovered_hosts}, open_tcp_ports={discovered_ports})."
                )
                generated_at = (
                    datetime.now(timezone.utc).replace(microsecond=0).isoformat()
                )
                reachability_payload = _build_network_reachability_report(
                    cleaned_hosts,
                    {
                        hostname: normalized_host_to_ips.get(
                            str(hostname or "").strip().rstrip(".").lower(),
                            [],
                        )
                        for hostname in cleaned_hosts
                    },
                    discovery_up_ips=discovery_up_ips,
                    ports_scanned=important_ports,
                    open_ports_by_host=open_ports_by_host,
                    port_scan_performed=True,
                    domain=domain,
                    resolved_ip_file=ip_file,
                    reachable_ip_file=reachable_ip_file,
                    no_response_ip_file=no_response_ip_file,
                    discovery_output_file=gnmap_path,
                    port_scan_output_file=gnmap_path,
                    generated_at=generated_at,
                )
                wrote_report = _write_network_reachability_report(
                    reachability_report_file,
                    reachability_payload,
                )
                # Produce always; render only when not deferred to Phase 3.
                if render:
                    _show_network_reachability_summary(
                        shell,
                        payload=reachability_payload,
                        report_file=(
                            reachability_report_file if wrote_report else None
                        ),
                    )
                services = [
                    "smb",
                    "rdp",
                    "mssql",
                    "winrm",
                    "ftp",
                    "ssh",
                    "dns",
                    "http",
                    "https",
                    "ldap",
                    "vnc",
                    "kerberos",
                ]
                for service in services:
                    shell.consolidate_service_ips(service)
            else:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(f"Nmap port scan for domain {marked_domain} failed.")
                if completed_scan_process.stderr:
                    print_error(f"Error details: {completed_scan_process.stderr}")
        else:
            _remove_file_if_exists(reachable_ip_file)
            _remove_file_if_exists(no_response_ip_file)
            _remove_file_if_exists(reachability_report_file)
            _remove_file_if_exists(os.path.join(nmap_dir, "imp_ports_scan"))
            _remove_file_if_exists(os.path.join(nmap_dir, "imp_ports_scan.gnmap"))
            _remove_file_if_exists(os.path.join(nmap_dir, "imp_ports_discovery.gnmap"))
            print_info(
                "Skipping Nmap by user choice. Reachability, service exposure, and segmentation inference were not computed."
            )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error during hostname to IP conversion and port scan.")
        print_exception(show_locals=False, exception=e)


def monitor_nmap_domain(shell: NmapShell, proc: any, domain: str) -> None:
    """Monitor nmap process output for domain-specific port scanning.

    This function processes nmap output in real-time, detecting open ports
    and saving hosts to appropriate service directories.

    Args:
        shell: The active shell instance with workspace and domain data.
        proc: Nmap subprocess object with stdout.
        domain: Domain name being scanned.
    """
    # Single source of truth: shared discovered-port regex.
    ip_regex = _NMAP_DISCOVERED_PORT_RE
    process_completed = False

    while True:
        line = proc.stdout.readline()
        if not line and proc.poll() is not None:
            if not process_completed:
                print_success("Important port scan for the domain completed.")
                services = ["smb", "rdp", "mssql", "winrm"]
                for service in services:
                    shell.consolidate_service_ips(service)
                process_completed = True
                break

        match = ip_regex.search(line.decode("utf-8"))
        if match:
            host_ip = match.group("ip")

            # Port 445/tcp - SMB
            if b"445/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.smb_dir, domain)

            # Port 5985/tcp - WinRM
            elif b"5985/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.winrm_dir, domain)

            # Port 3389/tcp - RDP
            elif b"3389/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.rdp_dir, domain)

            # Port 88/tcp - Kerberos
            elif b"88/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.kerberos_dir, domain)

            # Port 389/tcp - LDAP
            elif b"389/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.ldap_dir, domain)

            # Port 53/tcp - DNS
            elif b"53/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.dns_dir, domain)
                shell.dns = host_ip

            # Port 1433/tcp - MSSQL
            elif b"1433/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.mssql_dir, domain)

            # Port 22/tcp - SSH
            elif b"22/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.ssh_dir, domain)

            # Port 21/tcp - FTP
            elif b"21/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.ftp_dir, domain)

            # Port 5900/tcp - VNC
            elif b"5900/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.vnc_dir, domain)

            # Port 80/tcp - HTTP
            elif b"80/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.http_dir, domain)

            # Port 443/tcp - HTTPS
            elif b"443/tcp" in line:
                save_domain_host_to_file(shell, host_ip, shell.https_dir, domain)
