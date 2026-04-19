"""Helpers for rendering CVE takeover attack-path context without changing graph semantics."""

from __future__ import annotations

from typing import Any, Mapping


_CVE_TAKEOVER_RELATIONS = {"nopac", "zerologon"}


def is_cve_takeover_relation(relation: object) -> bool:
    """Return ``True`` when the relation is a CVE-driven domain takeover path."""
    return str(relation or "").strip().lower() in _CVE_TAKEOVER_RELATIONS


def extract_cve_affected_hosts(details: Mapping[str, Any] | None) -> list[str]:
    """Extract distinct vulnerable host labels from takeover edge notes."""
    if not isinstance(details, Mapping):
        return []

    preferred_hosts: list[str] = []
    fallback_hosts: list[str] = []

    def _append(candidate: object) -> None:
        if isinstance(candidate, str):
            value = candidate.strip()
            if value:
                preferred_hosts.append(value)

    raw_labels = details.get("vulnerable_dc_labels")
    if isinstance(raw_labels, list):
        for entry in raw_labels:
            _append(entry)

    raw_affected_hosts = details.get("affected_hosts")
    if isinstance(raw_affected_hosts, list):
        for entry in raw_affected_hosts:
            if isinstance(entry, Mapping):
                _append(entry.get("label") or entry.get("hostname") or entry.get("fqdn"))
                ip_value = entry.get("ip")
                if isinstance(ip_value, str) and ip_value.strip():
                    fallback_hosts.append(ip_value.strip())
            else:
                _append(entry)

    if preferred_hosts:
        return sorted({host for host in preferred_hosts if host}, key=str.lower)

    raw_ips = details.get("vulnerable_dcs")
    if isinstance(raw_ips, list):
        for entry in raw_ips:
            if isinstance(entry, str) and entry.strip():
                fallback_hosts.append(entry.strip())

    return sorted({host for host in fallback_hosts if host}, key=str.lower)


def format_cve_affected_hosts_summary(
    details: Mapping[str, Any] | None,
    *,
    max_items: int = 3,
) -> str:
    """Build a compact vulnerable-host summary for CVE takeover notes."""
    hosts = extract_cve_affected_hosts(details)
    if not hosts:
        return ""

    visible_hosts = hosts[: max_items if max_items > 0 else len(hosts)]
    remaining = len(hosts) - len(visible_hosts)
    if remaining > 0:
        visible_hosts.append(f"+{remaining} more")
    return ", ".join(visible_hosts)


def resolve_cve_display_target(
    relation: object,
    details: Mapping[str, Any] | None,
    *,
    fallback_target: str = "",
) -> str:
    """Return the UX display target for a CVE takeover edge."""
    fallback = str(fallback_target or "").strip()
    if not is_cve_takeover_relation(relation):
        return fallback

    hosts = extract_cve_affected_hosts(details)
    if not hosts:
        return fallback
    if len(hosts) == 1:
        return hosts[0]

    summary = format_cve_affected_hosts_summary(details)
    return f"Vulnerable DCs: {summary}" if summary else f"{len(hosts)} vulnerable DCs"
