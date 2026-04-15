"""Persist workspace-scoped inter-domain reachability in a pivot-aware schema."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import json
from typing import Any


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_connectivity_vantage(shell: Any, *, source_domain: str) -> dict[str, str]:
    """Return the logical vantage metadata for one connectivity observation."""
    domain_state = getattr(shell, "domains_data", {}).get(source_domain, {})
    network_vantage = (
        domain_state.get("network_vantage", {})
        if isinstance(domain_state, dict)
        else {}
    )
    mode = str(network_vantage.get("mode") or "").strip().lower() or "direct"
    if mode == "pivot_assisted":
        pivot_method = str(network_vantage.get("refresh_source") or "").strip() or str(
            network_vantage.get("pivot_method") or ""
        ).strip()
        pivot_host = str(network_vantage.get("pivot_host") or "").strip()
        pivot_tool = str(network_vantage.get("pivot_tool") or "").strip()
        vantage_id = (
            f"pivot_assisted:{pivot_method or pivot_tool or 'pivot'}:{pivot_host or 'unknown'}"
        )
        return {
            "id": vantage_id,
            "mode": "pivot_assisted",
            "pivot_host": pivot_host,
            "refresh_source": pivot_method,
            "pivot_tool": pivot_tool,
            "source_service": str(network_vantage.get("source_service") or "").strip(),
        }

    return {
        "id": "direct:local",
        "mode": "direct",
    }


def normalize_domain_connectivity_entry(entry: Any) -> dict[str, Any]:
    """Normalize one persisted connectivity record to the current schema."""
    if not isinstance(entry, dict):
        return {"schema_version": 1, "vantages": {}, "summary": {}}
    if isinstance(entry.get("vantages"), dict):
        entry.setdefault("schema_version", 1)
        entry.setdefault("summary", {})
        return entry
    legacy_summary = dict(entry)
    return {
        "schema_version": 1,
        "vantages": {},
        "summary": legacy_summary,
    }


def merge_domain_connectivity(
    shell: Any,
    *,
    source_domain: str,
    connectivity_updates: dict[str, dict[str, Any]],
) -> None:
    """Persist trusted-domain connectivity observations at workspace scope."""
    if not hasattr(shell, "domain_connectivity") or not isinstance(
        shell.domain_connectivity, dict
    ):
        shell.domain_connectivity = {}

    vantage = build_connectivity_vantage(shell, source_domain=source_domain)
    checked_at = utc_now_iso()
    for trusted_domain, connectivity in connectivity_updates.items():
        normalized = normalize_domain_connectivity_entry(
            shell.domain_connectivity.get(trusted_domain)
        )
        observation = dict(connectivity)
        observation["checked_at"] = checked_at
        observation["vantage"] = dict(vantage)
        normalized["vantages"][vantage["id"]] = observation
        normalized["summary"] = observation
        shell.domain_connectivity[trusted_domain] = normalized

        domain_state = getattr(shell, "domains_data", {}).setdefault(trusted_domain, {})
        if isinstance(domain_state, dict):
            domain_state["connectivity"] = normalized


def _reachable_from_report_status(status: str) -> bool:
    """Return whether one current-vantage report status means reachable."""
    return status in {
        "open_service_observed",
        "host_responded_no_important_ports_open",
        "responded_to_discovery",
        "reachable",
    }


def _load_domain_reachability_report(shell: Any, *, source_domain: str) -> dict[str, Any] | None:
    """Load the persisted current-vantage reachability report for one domain."""
    report_path = os.path.join(
        str(getattr(shell, "current_workspace_dir", "") or "").strip(),
        str(getattr(shell, "domains_dir", "domains") or "domains"),
        source_domain,
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


def reconcile_domain_connectivity_from_current_vantage_report(
    shell: Any,
    *,
    source_domain: str,
    payload: dict[str, Any] | None = None,
) -> list[str]:
    """Update trusted-domain connectivity using one domain's current-vantage report."""
    if not isinstance(getattr(shell, "domain_connectivity", None), dict):
        return []

    report_payload = payload or _load_domain_reachability_report(
        shell, source_domain=source_domain
    )
    if not isinstance(report_payload, dict):
        return []

    ip_entries = report_payload.get("ips", [])
    if not isinstance(ip_entries, list):
        return []
    entries_by_ip: dict[str, dict[str, Any]] = {}
    for entry in ip_entries:
        if not isinstance(entry, dict):
            continue
        ip_value = str(entry.get("ip") or "").strip()
        if ip_value:
            entries_by_ip[ip_value] = entry

    updates: dict[str, dict[str, Any]] = {}
    newly_reachable_domains: list[str] = []
    for trusted_domain, raw_entry in shell.domain_connectivity.items():
        normalized = normalize_domain_connectivity_entry(raw_entry)
        summary = normalized.get("summary", {})
        if not isinstance(summary, dict):
            continue
        if str(summary.get("source_domain") or "").strip().lower() != source_domain.lower():
            continue
        pdc_ip = str(summary.get("pdc_ip") or "").strip()
        if not pdc_ip:
            continue
        report_entry = entries_by_ip.get(pdc_ip)
        if not isinstance(report_entry, dict):
            continue
        status = str(report_entry.get("status") or "").strip()
        was_reachable = bool(summary.get("reachable"))
        is_reachable = _reachable_from_report_status(status)
        if is_reachable and not was_reachable:
            newly_reachable_domains.append(trusted_domain)
        updates[trusted_domain] = {
            "domain": trusted_domain,
            "source_domain": source_domain,
            "pdc_ip": pdc_ip,
            "reachable": is_reachable,
            "status": status or "unknown",
            "classification": str(report_entry.get("classification") or "").strip(),
            "open_ports": list(report_entry.get("open_ports") or []),
            "method": "current_vantage_report",
        }

    if not updates:
        return []
    merge_domain_connectivity(
        shell,
        source_domain=source_domain,
        connectivity_updates=updates,
    )
    return newly_reachable_domains


__all__ = [
    "build_connectivity_vantage",
    "merge_domain_connectivity",
    "normalize_domain_connectivity_entry",
    "reconcile_domain_connectivity_from_current_vantage_report",
    "utc_now_iso",
]
