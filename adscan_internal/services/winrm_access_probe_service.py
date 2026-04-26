"""Concurrent WinRM service-access probing with PSRP and Kerberos support."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
from typing import Any, Iterable

from adscan_internal import print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.current_vantage_reachability_service import (
    load_current_vantage_reachability_report,
)
from adscan_internal.services.service_access_results import (
    ServiceAccessCategory,
    ServiceAccessFinding,
)
from adscan_internal.services.winrm_psrp_service import WinRMPSRPError, WinRMPSRPService


WINRM_ACCESS_PROBE_BACKEND = "winrm-psrp"
DEFAULT_WINRM_PROBE_WORKERS = 32
WINRM_PROBE_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "[pscustomobject]@{ComputerName=$env:COMPUTERNAME; UserName=[Environment]::UserName} "
    "| ConvertTo-Json -Compress"
)


@dataclass(frozen=True, slots=True)
class WinRMProbeTarget:
    """Resolved target for one WinRM access probe."""

    host: str
    kerberos_spn_host: str | None = None


def _normalize_target(value: object) -> str:
    """Return a stable target token suitable for matching persisted inventory."""
    return str(value or "").strip().rstrip(".")


def _is_ip_address(value: str) -> bool:
    """Return whether a target string is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _fqdn_or_domain_host(hostname: str, domain: str) -> str:
    """Return a Kerberos-friendly hostname candidate."""
    cleaned = _normalize_target(hostname).lower()
    if not cleaned:
        return ""
    domain_clean = _normalize_target(domain).lower()
    if "." in cleaned or not domain_clean:
        return cleaned
    return f"{cleaned}.{domain_clean}"


def _load_targets(targets: Iterable[str] | str) -> list[str]:
    """Load targets from an iterable or a file path."""
    if isinstance(targets, str):
        candidate = Path(targets)
        if candidate.is_file():
            return [
                line.strip()
                for line in candidate.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
                if line.strip()
            ]
        return [targets] if targets.strip() else []
    return [str(target).strip() for target in targets if str(target or "").strip()]


def _build_ip_hostname_map(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> dict[str, str]:
    """Build an IP to preferred FQDN map from current-vantage inventory."""
    payload, _report_path = load_current_vantage_reachability_report(
        workspace_dir,
        domains_dir,
        domain,
    )
    if not isinstance(payload, dict):
        return {}

    mapping: dict[str, str] = {}
    ip_entries = payload.get("ips")
    if isinstance(ip_entries, list):
        for entry in ip_entries:
            if not isinstance(entry, dict):
                continue
            ip_value = _normalize_target(entry.get("ip"))
            if not ip_value:
                continue
            candidates = entry.get("hostname_candidates", [])
            if not isinstance(candidates, list):
                continue
            for candidate in candidates:
                fqdn = _fqdn_or_domain_host(str(candidate), domain)
                if fqdn:
                    mapping[ip_value.lower()] = fqdn
                    break

    host_entries = payload.get("hosts")
    if isinstance(host_entries, list):
        for entry in host_entries:
            if not isinstance(entry, dict):
                continue
            hostname = _fqdn_or_domain_host(str(entry.get("hostname") or ""), domain)
            if not hostname:
                continue
            for ip_entry in entry.get("ips", []):
                if not isinstance(ip_entry, dict):
                    continue
                ip_value = _normalize_target(ip_entry.get("ip"))
                if ip_value and ip_value.lower() not in mapping:
                    mapping[ip_value.lower()] = hostname
    return mapping


def resolve_winrm_probe_targets(
    *,
    targets: Iterable[str] | str,
    domain: str,
    workspace_dir: str,
    domains_dir: str,
    domain_data: dict[str, Any] | None = None,
) -> list[WinRMProbeTarget]:
    """Resolve raw WinRM targets into transport hosts plus Kerberos SPN hosts."""
    raw_targets = list(dict.fromkeys(_load_targets(targets)))
    ip_hostname_map = _build_ip_hostname_map(
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=domain,
    )
    resolved: list[WinRMProbeTarget] = []
    pdc_ip = _normalize_target((domain_data or {}).get("pdc"))
    pdc_hostname = _fqdn_or_domain_host(
        str((domain_data or {}).get("pdc_hostname") or ""), domain
    )

    for raw_target in raw_targets:
        target = _normalize_target(raw_target)
        if not target:
            continue
        spn_host: str | None = None
        if _is_ip_address(target):
            spn_host = ip_hostname_map.get(target.lower())
            if (
                not spn_host
                and pdc_ip
                and target.lower() == pdc_ip.lower()
                and pdc_hostname
            ):
                spn_host = pdc_hostname
        else:
            spn_host = _fqdn_or_domain_host(target, domain)
        resolved.append(WinRMProbeTarget(host=target, kerberos_spn_host=spn_host))
    return resolved


def _classify_probe_exception(exc: BaseException) -> tuple[ServiceAccessCategory, str]:
    """Normalize PSRP exceptions into service-access categories."""
    message = str(exc or "").strip()
    lowered = message.lower()
    if any(
        marker in lowered
        for marker in (
            "access is denied",
            "unauthorized",
            "forbidden",
            "credentials were rejected",
            "logon failure",
            "invalid credentials",
        )
    ):
        return "denied", message or "authentication_denied"
    if any(
        marker in lowered
        for marker in (
            "connection refused",
            "timed out",
            "timeout",
            "name or service not known",
            "no route to host",
            "could not resolve",
            "failed to establish",
        )
    ):
        return "transport", message or "transport_error"
    return "ambiguous", message or exc.__class__.__name__


def _probe_one_target(
    *,
    target: WinRMProbeTarget,
    domain: str,
    username: str,
    password: str,
    auth_mode: str,
) -> ServiceAccessFinding:
    """Probe one target and return one normalized service-access finding."""
    try:
        service = WinRMPSRPService(
            domain=domain,
            host=target.host,
            username=username,
            password=password,
            auth_mode=auth_mode,
            kerberos_spn_host=target.kerberos_spn_host,
        )
        result = service.execute_powershell(
            WINRM_PROBE_SCRIPT,
            operation_name="winrm_access_probe",
        )
        if not result.had_errors:
            return ServiceAccessFinding(
                service="winrm",
                host=target.host,
                username=username,
                category="confirmed",
                reason="psrp_session_established",
                status=(result.stdout or "PSRP session established").strip()[:500],
                backend=WINRM_ACCESS_PROBE_BACKEND,
            )
        return ServiceAccessFinding(
            service="winrm",
            host=target.host,
            username=username,
            category="ambiguous",
            reason="psrp_had_errors",
            status=(result.stderr or result.stdout or "PSRP returned errors").strip()[
                :500
            ],
            backend=WINRM_ACCESS_PROBE_BACKEND,
        )
    except WinRMPSRPError as exc:
        category, reason = _classify_probe_exception(exc)
    except Exception as exc:  # noqa: BLE001
        category, reason = _classify_probe_exception(exc)
    return ServiceAccessFinding(
        service="winrm",
        host=target.host,
        username=username,
        category=category,
        reason=reason[:500],
        status=reason[:500],
        backend=WINRM_ACCESS_PROBE_BACKEND,
    )


def run_winrm_access_probe_sweep(
    *,
    domain: str,
    username: str,
    password: str,
    targets: Iterable[str] | str,
    workspace_dir: str,
    domains_dir: str,
    domain_data: dict[str, Any] | None = None,
    auth_mode: str = "kerberos",
    max_workers: int | None = None,
) -> list[ServiceAccessFinding]:
    """Probe WinRM access concurrently using the reusable PSRP backend."""
    probe_targets = resolve_winrm_probe_targets(
        targets=targets,
        domain=domain,
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain_data=domain_data,
    )
    if not probe_targets:
        return []

    worker_count = max(
        1, min(max_workers or DEFAULT_WINRM_PROBE_WORKERS, len(probe_targets))
    )
    print_info_debug(
        "[winrm_probe] starting PSRP access sweep: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"user={mark_sensitive(username, 'user')} "
        f"targets={len(probe_targets)} workers={worker_count} "
        f"auth={mark_sensitive(auth_mode, 'detail')}"
    )

    findings: list[ServiceAccessFinding] = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(
                _probe_one_target,
                target=target,
                domain=domain,
                username=username,
                password=password,
                auth_mode=auth_mode,
            ): target
            for target in probe_targets
        }
        for future in as_completed(future_map):
            findings.append(future.result())

    order = {target.host.lower(): index for index, target in enumerate(probe_targets)}
    findings.sort(key=lambda finding: order.get(finding.host.lower(), len(order)))
    confirmed = sum(1 for finding in findings if finding.category == "confirmed")
    print_info_debug(
        "[winrm_probe] completed PSRP access sweep: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"user={mark_sensitive(username, 'user')} "
        f"targets={len(findings)} confirmed={confirmed}"
    )
    return findings


def get_winrm_probe_worker_count() -> int:
    """Return operator-configurable WinRM probe concurrency."""
    raw_value = os.getenv("ADSCAN_WINRM_PROBE_WORKERS", "").strip()
    if not raw_value:
        return DEFAULT_WINRM_PROBE_WORKERS
    try:
        return max(1, min(int(raw_value), 128))
    except ValueError:
        return DEFAULT_WINRM_PROBE_WORKERS
