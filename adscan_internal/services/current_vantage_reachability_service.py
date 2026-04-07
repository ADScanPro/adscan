"""Resolve current-vantage target reachability from the persisted network report."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable

from adscan_internal.workspaces import domain_subpath


def _normalize_target_token(value: object) -> str:
    """Return a normalized target token for IP/hostname/FQDN matching."""
    return str(value or "").strip().rstrip(".").lower()


@dataclass(frozen=True)
class CurrentVantageTargetAssessment:
    """Current-vantage reachability assessment for one operator-supplied target."""

    requested_target: str
    matched: bool
    reachable: bool
    matched_ips: tuple[str, ...]
    matched_hostnames: tuple[str, ...]
    open_ports: tuple[int, ...]
    classification: str | None = None
    status: str | None = None

    def has_any_required_port(self, ports: Iterable[int]) -> bool:
        """Return whether any of the requested ports is open for this target."""
        requested = {int(port) for port in ports}
        return bool(requested.intersection(self.open_ports))


@dataclass(frozen=True)
class CurrentVantageResolution:
    """Grouped result for multiple targets against one current-vantage report."""

    report_available: bool
    report_path: str | None
    vantage_mode: str | None
    assessments: tuple[CurrentVantageTargetAssessment, ...]

    @property
    def reachable_targets(self) -> tuple[CurrentVantageTargetAssessment, ...]:
        """Return assessments that are matched and currently reachable."""
        return tuple(item for item in self.assessments if item.matched and item.reachable)

    @property
    def unreachable_targets(self) -> tuple[CurrentVantageTargetAssessment, ...]:
        """Return assessments that are matched but not currently reachable."""
        return tuple(item for item in self.assessments if item.matched and not item.reachable)

    @property
    def unmatched_targets(self) -> tuple[CurrentVantageTargetAssessment, ...]:
        """Return assessments that could not be resolved in the report."""
        return tuple(item for item in self.assessments if not item.matched)


def _build_hostname_to_ips_map(payload: dict[str, Any]) -> dict[str, set[str]]:
    """Build a hostname/FQDN -> IP set map from one reachability payload."""
    mapping: dict[str, set[str]] = {}

    hosts = payload.get("hosts")
    if isinstance(hosts, list):
        for entry in hosts:
            if not isinstance(entry, dict):
                continue
            hostname = _normalize_target_token(entry.get("hostname"))
            if not hostname:
                continue
            for ip_entry in entry.get("ips", []):
                if not isinstance(ip_entry, dict):
                    continue
                ip_value = _normalize_target_token(ip_entry.get("ip"))
                if ip_value:
                    mapping.setdefault(hostname, set()).add(ip_value)
                    short_name = _normalize_target_token(hostname.split(".", 1)[0])
                    if short_name:
                        mapping.setdefault(short_name, set()).add(ip_value)

    ips = payload.get("ips")
    if isinstance(ips, list):
        for entry in ips:
            if not isinstance(entry, dict):
                continue
            ip_value = _normalize_target_token(entry.get("ip"))
            if not ip_value:
                continue
            for hostname in entry.get("hostname_candidates", []):
                hostname_norm = _normalize_target_token(hostname)
                if not hostname_norm:
                    continue
                mapping.setdefault(hostname_norm, set()).add(ip_value)
                short_name = _normalize_target_token(hostname_norm.split(".", 1)[0])
                if short_name:
                    mapping.setdefault(short_name, set()).add(ip_value)
    return mapping


def _build_ip_entry_map(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build an IP -> entry map from one reachability payload."""
    ip_entries = payload.get("ips")
    if not isinstance(ip_entries, list):
        return {}
    mapping: dict[str, dict[str, Any]] = {}
    for entry in ip_entries:
        if not isinstance(entry, dict):
            continue
        ip_value = _normalize_target_token(entry.get("ip"))
        if ip_value and ip_value not in mapping:
            mapping[ip_value] = entry
    return mapping


def load_current_vantage_reachability_report(
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> tuple[dict[str, Any] | None, str]:
    """Load the persisted current-vantage reachability report for one domain."""
    report_path = domain_subpath(
        workspace_dir,
        domains_dir,
        domain,
        "network_reachability_report.json",
    )
    try:
        payload = json.loads(Path(report_path).read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return None, report_path
    return payload if isinstance(payload, dict) else None, report_path


def resolve_targets_from_current_vantage_report(
    payload: dict[str, Any] | None,
    *,
    targets: Iterable[str],
    required_ports: Iterable[int] = (),
    report_path: str | None = None,
) -> CurrentVantageResolution:
    """Resolve target reachability against the persisted current-vantage report."""
    target_list = [str(target or "").strip() for target in targets if str(target or "").strip()]
    if not isinstance(payload, dict):
        return CurrentVantageResolution(
            report_available=False,
            report_path=report_path,
            vantage_mode=None,
            assessments=tuple(
                CurrentVantageTargetAssessment(
                    requested_target=target,
                    matched=False,
                    reachable=False,
                    matched_ips=(),
                    matched_hostnames=(),
                    open_ports=(),
                )
                for target in target_list
            ),
        )

    ip_map = _build_ip_entry_map(payload)
    hostname_map = _build_hostname_to_ips_map(payload)
    required_port_set = {int(port) for port in required_ports}
    vantage = payload.get("vantage") if isinstance(payload.get("vantage"), dict) else {}
    vantage_mode = str(vantage.get("mode") or "").strip() or None

    assessments: list[CurrentVantageTargetAssessment] = []
    for target in target_list:
        target_norm = _normalize_target_token(target)
        matched_ips: set[str] = set()
        if target_norm in ip_map:
            matched_ips.add(target_norm)
        matched_ips.update(hostname_map.get(target_norm, set()))
        if "." in target_norm:
            short_name = _normalize_target_token(target_norm.split(".", 1)[0])
            matched_ips.update(hostname_map.get(short_name, set()))

        if not matched_ips:
            assessments.append(
                CurrentVantageTargetAssessment(
                    requested_target=target,
                    matched=False,
                    reachable=False,
                    matched_ips=(),
                    matched_hostnames=(),
                    open_ports=(),
                )
            )
            continue

        reachable = False
        aggregated_ports: set[int] = set()
        matched_hostnames: set[str] = set()
        status: str | None = None
        classification: str | None = None
        for ip_value in sorted(matched_ips):
            entry = ip_map.get(ip_value) or {}
            for hostname in entry.get("hostname_candidates", []):
                hostname_norm = _normalize_target_token(hostname)
                if hostname_norm:
                    matched_hostnames.add(hostname_norm)
            open_ports = {
                int(port)
                for port in entry.get("open_ports", [])
                if str(port).isdigit()
            }
            aggregated_ports.update(open_ports)
            entry_reachable = str(entry.get("status") or "").strip() != "no_response_from_current_vantage"
            if required_port_set:
                entry_reachable = entry_reachable and bool(required_port_set.intersection(open_ports))
            if entry_reachable:
                reachable = True
                status = str(entry.get("status") or "").strip() or status
                classification = str(entry.get("classification") or "").strip() or classification

        if status is None or classification is None:
            first_entry = ip_map.get(sorted(matched_ips)[0], {})
            status = str(first_entry.get("status") or "").strip() or None
            classification = str(first_entry.get("classification") or "").strip() or None

        assessments.append(
            CurrentVantageTargetAssessment(
                requested_target=target,
                matched=True,
                reachable=reachable,
                matched_ips=tuple(sorted(matched_ips)),
                matched_hostnames=tuple(sorted(matched_hostnames)),
                open_ports=tuple(sorted(aggregated_ports)),
                classification=classification,
                status=status,
            )
        )

    return CurrentVantageResolution(
        report_available=True,
        report_path=report_path,
        vantage_mode=vantage_mode,
        assessments=tuple(assessments),
    )


def resolve_targets_from_current_vantage(
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    *,
    targets: Iterable[str],
    required_ports: Iterable[int] = (),
) -> CurrentVantageResolution:
    """Resolve target reachability from the persisted current-vantage report."""
    payload, report_path = load_current_vantage_reachability_report(
        workspace_dir,
        domains_dir,
        domain,
    )
    return resolve_targets_from_current_vantage_report(
        payload,
        targets=targets,
        required_ports=required_ports,
        report_path=report_path,
    )
