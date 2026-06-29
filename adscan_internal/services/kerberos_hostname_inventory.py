"""Workspace-backed hostname hints for Kerberos SPN targeting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from adscan_internal.workspaces import domain_subpath


HostnameInventory = Mapping[str, Iterable[str] | str]


def _normalize_ip(value: object) -> str:
    return str(value or "").strip()


def _normalize_hostname(value: object) -> str:
    return str(value or "").strip().rstrip(".")


def _add_inventory_candidate(
    inventory: dict[str, list[str]],
    *,
    ip: object,
    hostname: object,
) -> None:
    ip_value = _normalize_ip(ip)
    host_value = _normalize_hostname(hostname)
    if not ip_value or not host_value:
        return
    candidates = inventory.setdefault(ip_value, [])
    if host_value.lower() not in {candidate.lower() for candidate in candidates}:
        candidates.append(host_value)


def _load_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_massdns_inventory(path: Path) -> dict[str, list[str]]:
    payload = _load_json(path)
    inventory: dict[str, list[str]] = {}
    resolved = payload.get("resolved", [])
    if not isinstance(resolved, list):
        return inventory
    for entry in resolved:
        if not isinstance(entry, dict):
            continue
        hostname = entry.get("hostname")
        ips = entry.get("ips", [])
        if not isinstance(ips, list):
            continue
        for ip in ips:
            _add_inventory_candidate(inventory, ip=ip, hostname=hostname)
    return inventory


def _load_reachability_inventory(path: Path) -> dict[str, list[str]]:
    payload = _load_json(path)
    inventory: dict[str, list[str]] = {}
    ips = payload.get("ips", [])
    if isinstance(ips, list):
        for entry in ips:
            if not isinstance(entry, dict):
                continue
            ip_value = entry.get("ip")
            candidates = entry.get("hostname_candidates", [])
            if not isinstance(candidates, list):
                continue
            for hostname in candidates:
                _add_inventory_candidate(inventory, ip=ip_value, hostname=hostname)
    hosts = payload.get("hosts", [])
    if isinstance(hosts, list):
        for host_entry in hosts:
            if not isinstance(host_entry, dict):
                continue
            hostname = host_entry.get("hostname")
            ip_entries = host_entry.get("ips", [])
            if not isinstance(ip_entries, list):
                continue
            for ip_entry in ip_entries:
                if isinstance(ip_entry, dict):
                    _add_inventory_candidate(
                        inventory,
                        ip=ip_entry.get("ip"),
                        hostname=hostname,
                    )
    return inventory


def load_workspace_ip_hostname_inventory(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> dict[str, list[str]]:
    """Load persisted IP → hostname candidates for one domain workspace."""
    reports = [
        (
            Path(
                domain_subpath(
                    workspace_dir,
                    domains_dir,
                    domain,
                    "massdns_resolution_report.json",
                )
            ),
            _load_massdns_inventory,
        ),
        (
            Path(
                domain_subpath(
                    workspace_dir,
                    domains_dir,
                    domain,
                    "network_reachability_report.json",
                )
            ),
            _load_reachability_inventory,
        ),
    ]
    inventory: dict[str, list[str]] = {}
    for path, loader in reports:
        loaded = loader(path)
        for ip, hostnames in loaded.items():
            for hostname in hostnames:
                _add_inventory_candidate(inventory, ip=ip, hostname=hostname)

    # Liveness ranking: when an IP has MULTIPLE FQDN candidates (stale DNS / IP
    # reuse — e.g. a decommissioned CZN007 A-record sharing the IP with the live
    # CZN012, both enabled computers, no reverse PTR), order the most-recently-
    # authenticated computer FIRST so choose_hostname_for_kerberos_spn picks the
    # host that is ACTUALLY at this IP now. Without this the first candidate
    # (often the stale one) yields a TGS the live host can't decrypt
    # → KRB_ERR_GENERIC. lastLogonTimestamp is the reliable liveness signal
    # (Cyberzaintza 2026-06-17). Best-effort: no computer data → original order.
    liveness = _load_computer_liveness(workspace_dir, domains_dir, domain)
    if liveness:
        for hostnames in inventory.values():
            if len(hostnames) > 1:
                hostnames.sort(key=lambda h: liveness.get(h.lower(), -1), reverse=True)
    return inventory


def load_workspace_hostname_ip_inventory(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> dict[str, str]:
    """Load persisted hostname → IP mapping for one domain workspace (reverse).

    Inverts :func:`load_workspace_ip_hostname_inventory` (IP → hostname
    candidates) into a hostname → IP lookup, so a host→address resolver can
    answer "what IP does this name live at?" from the same massdns +
    reachability data that already powers the IP → SPN-hostname path.

    The map is alias-aware: every FQDN candidate is also indexed under its
    short label (the part before the first dot). When a short label maps to
    more than one IP (different hosts sharing a short name across subdomains)
    the FIRST-seen IP wins for the short key, while every FQDN key stays
    exact — callers that have the FQDN get the precise address, callers with
    only the short name get a best-effort one. Keys are lowercased and
    trailing-dot stripped.

    Returns an empty mapping when no inventory is available (best-effort).
    """
    ip_to_hosts = load_workspace_ip_hostname_inventory(
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=domain,
    )
    hostname_to_ip: dict[str, str] = {}
    for ip_value, hostnames in ip_to_hosts.items():
        ip_clean = _normalize_ip(ip_value)
        if not ip_clean:
            continue
        for hostname in hostnames:
            host_clean = _normalize_hostname(hostname).lower()
            if not host_clean:
                continue
            # Exact FQDN / full-name key always reflects the first IP it was
            # seen at (massdns is ordered live-first by the liveness ranking).
            hostname_to_ip.setdefault(host_clean, ip_clean)
            short = host_clean.split(".", 1)[0]
            if short and short != host_clean:
                hostname_to_ip.setdefault(short, ip_clean)
    return hostname_to_ip


def register_spn_candidate_resolver_for_shell(shell: Any) -> None:
    """Arm the stale-DNS SPN self-heal for this session (dependency-inversion).

    Injects a shell-aware closure into ``_kerberos_spn_candidates`` so the SMB
    transport can resolve an IP → ranked live-first FQDN candidates (from the
    workspace inventory) WITHOUT importing the workspace/shell. The transport
    consults it to retry a Kerberos AP/KDC failure caused by a stale-DNS
    wrong-host SPN with the live candidate, before NTLM fallback. Call once per
    session at shell setup; idempotent (re-registration replaces the closure).
    """
    from adscan_internal.services._kerberos_spn_candidates import (
        register_spn_candidate_resolver,
    )

    def _candidates(ip: str, domain: str) -> list[str]:
        try:
            workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
            domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains")
            if not workspace_dir or not domain:
                return []
            inventory = load_workspace_ip_hostname_inventory(
                workspace_dir=workspace_dir, domains_dir=domains_dir, domain=domain
            )
            return list(inventory.get(ip, []) or [])
        except Exception:  # noqa: BLE001 — best-effort, never break auth
            return []

    register_spn_candidate_resolver(_candidates)


def _load_computer_liveness(
    workspace_dir: str, domains_dir: str, domain: str
) -> dict[str, int]:
    """Map computer dNSHostName (lowercased) → lastLogonTimestamp (FILETIME int).

    Read from the persisted computer inventory to rank SPN candidates by which
    machine is actually live at an IP. Higher FILETIME = more recently
    authenticated = the live host. Best-effort: missing file / attribute → {}.
    """
    path = Path(
        domain_subpath(workspace_dir, domains_dir, domain, "inventory", "computers.json")
    )
    payload = _load_json(path)
    records = payload.get("records") if isinstance(payload, dict) else None
    liveness: dict[str, int] = {}
    if not isinstance(records, list):
        return liveness
    for record in records:
        if not isinstance(record, dict):
            continue
        props = record.get("properties")
        props = props if isinstance(props, dict) else {}
        dns = _normalize_hostname(props.get("dnshostname")).lower()
        if not dns:
            continue
        try:
            last_logon = int(props.get("lastlogon") or 0)
        except (TypeError, ValueError):
            last_logon = 0
        if last_logon > 0:
            liveness[dns] = max(liveness.get(dns, 0), last_logon)
    return liveness


def choose_hostname_for_kerberos_spn(
    *,
    ip: str,
    domain: str | None,
    inventory: HostnameInventory | None,
) -> str | None:
    """Choose the best hostname candidate for one IP-backed Kerberos SPN."""
    if not inventory:
        return None
    candidates_raw = inventory.get(str(ip or "").strip())
    if isinstance(candidates_raw, str):
        candidates = [candidates_raw]
    elif isinstance(candidates_raw, Iterable):
        candidates = [str(candidate or "") for candidate in candidates_raw]
    else:
        candidates = []
    candidates = [_normalize_hostname(candidate) for candidate in candidates]
    candidates = [candidate for candidate in candidates if candidate]
    if not candidates:
        return None
    domain_clean = str(domain or "").strip().rstrip(".").lower()
    if domain_clean:
        for candidate in candidates:
            if candidate.lower().endswith(f".{domain_clean}"):
                return candidate
        for candidate in candidates:
            if "." not in candidate:
                return f"{candidate}.{domain_clean}"
    for candidate in candidates:
        if "." in candidate:
            return candidate
    return candidates[0] if candidates else None


__all__ = [
    "HostnameInventory",
    "choose_hostname_for_kerberos_spn",
    "load_workspace_ip_hostname_inventory",
    "load_workspace_hostname_ip_inventory",
]
