"""Post-reachability active-host cap for the port-scan / privilege-sweep surface.

This is the Phase-3 peer of the Phase-2 collector cap (``host_collector._apply_host_cap``).
Both bound the ACTIVE scanning footprint to ``host_cap`` representative-first hosts
(Tier 0 / DCs / ADCS first) so a large estate (~2k hosts) stays time-bounded during
a PoV; because both sites use the SAME reachable + tier-first criteria, they converge
on the same highest-value hosts.

The split of responsibility:

- The **port/reachability scan is CHEAP and runs on ALL hosts** (a TCP connect to
  445/5985/1433); it must produce a complete reachability + open-port inventory for
  the report. We deliberately do NOT cap the scan input — capping before reachability
  would waste cap slots on dead hosts.
- AFTER reachability is known, this module caps the **reachable** set to the top
  ``host_cap`` hosts (representative-first) as a SINGLE UNION active set, then derives
  each ``{service}/ips.txt`` as ``(capped active set) ∩ (hosts with that service's
  port open)``. So the TOTAL active footprint is ``host_cap`` hosts — NOT
  ``host_cap`` per service. Every downstream per-service privilege sweep (SMB / WinRM
  / MSSQL) then operates within the same ≤``host_cap`` hosts.

The LDAP directory graph is NEVER capped here — only the active (authenticating /
port-touching) surface is bounded.

Tier data comes from the attack graph built in Phase 2 (before the Phase-3 port
scan), consumed here as the persisted graph-JSON Computer property dicts — so this
never re-runs the Privilege-Tier classifier; it reads the signals already on each
node. The ordering mirrors :func:`host_collector.order_hosts_representative_first`
(DC primaryGroupID / Tier 0 / high-value first, then member servers, then most-recent
``lastLogonTimestamp``, then name) so the two cap sites stay consistent.

Everything here is PURE: no network, no I/O, no DC bytes. Unit-testable as L1 logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from adscan_core.rich_output import print_warning

# Domain Controllers (516) + Read-only DCs (521) are the identity control plane —
# the highest-signal hosts. Mirrors host_collector._DC_PRIMARY_GROUP_RIDS and
# well_known_sids; kept local so this pure module has no collector import cycle.
_DC_PRIMARY_GROUP_RIDS = frozenset({516, 521})


def _computer_props_ip(props: dict[str, Any]) -> str:
    """Return the connect IP for a graph-JSON Computer property dict (``""`` if none)."""
    return str(props.get("ip_address") or "").strip()


def _computer_props_primary_group_id(props: dict[str, Any]) -> int | None:
    """Integer primaryGroupID from a graph-JSON Computer property dict (mirror of
    :func:`well_known_sids._node_primary_group_id` for dicts)."""
    for key in ("primarygroupid", "primaryGroupID", "primary_group_id"):
        value = props.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _computer_props_is_tier0(props: dict[str, Any]) -> bool:
    """True when the graph-JSON Computer props carry a Tier 0 / high-value marker.

    Reads the same signals the graph tier classifier uses (``isTierZero`` /
    ``highvalue`` / ``admin_tier_0`` system tag) without importing the classifier —
    this module stays pure and import-cheap.
    """
    if props.get("isTierZero") or props.get("highvalue"):
        return True
    tags = props.get("system_tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return any(str(tag).strip().lower() == "admin_tier_0" for tag in tags)


def _computer_props_is_server(props: dict[str, Any]) -> bool:
    """True when the Computer's ``operatingSystem`` marks it a member server."""
    os_str = str(props.get("os") or props.get("operatingsystem") or "").casefold()
    return "server" in os_str


def _computer_props_last_logon(props: dict[str, Any]) -> int:
    """Most-recent ``lastLogonTimestamp`` as an int (0 when absent/unparseable)."""
    for key in ("lastlogon", "lastlogontimestamp"):
        value = props.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def _computer_props_name(props: dict[str, Any]) -> str:
    """Stable display/tie-break key for a Computer props dict."""
    return str(
        props.get("name")
        or props.get("dnshostname")
        or props.get("samaccountname")
        or ""
    )


def _computer_tier_rank(props: dict[str, Any]) -> int:
    """Representative-first tier rank for a graph-JSON Computer props dict.

    HIGHER == ordered earlier. Mirrors the band ordering of
    :func:`host_collector._host_tier_rank_fallback`: DC (3) → Tier 0 / high-value
    (2) → member server (1) → workstation (0). Uses only signals on the persisted
    node, so it never re-runs the closure-based classifier.
    """
    if _computer_props_primary_group_id(props) in _DC_PRIMARY_GROUP_RIDS:
        return 3
    if _computer_props_is_tier0(props):
        return 2
    if _computer_props_is_server(props):
        return 1
    return 0


def build_ip_rank_map(computers_props: list[dict[str, Any]]) -> dict[str, tuple[int, int, int, str]]:
    """Map each Computer's connect IP to its representative-first sort key.

    The sort key mirrors :func:`host_collector.order_hosts_representative_first`
    (negated tier rank, negated server flag, negated last-logon, name ascending) so
    a plain ascending sort on the key orders highest-value first. When two Computer
    nodes share an IP, the higher-ranked one wins (so a shared-IP DC is never
    out-ranked by a workstation alias).

    Args:
        computers_props: Graph-JSON Computer property dicts (from
            ``get_enabled_computers``).

    Returns:
        ``{ip: (-tier, -server, -lastlogon, name)}`` for every Computer that has an IP.
    """
    rank_by_ip: dict[str, tuple[int, int, int, str]] = {}
    for props in computers_props:
        ip = _computer_props_ip(props)
        if not ip:
            continue
        key = (
            -_computer_tier_rank(props),
            -(1 if _computer_props_is_server(props) else 0),
            -_computer_props_last_logon(props),
            _computer_props_name(props),
        )
        existing = rank_by_ip.get(ip)
        if existing is None or key < existing:
            rank_by_ip[ip] = key
    return rank_by_ip


def order_active_ips_representative_first(
    reachable_ips: list[str],
    rank_by_ip: dict[str, tuple[int, int, int, str]],
) -> list[str]:
    """Order the reachable IP set representative-first using a graph IP-rank map.

    Reachable IPs the graph does not know (no matching Computer node — e.g. a host
    reachable on a service port whose Computer object carried no ``ip_address``) sort
    AFTER every ranked IP, deterministically by IP string, so they are still kept but
    never displace a known high-value host inside the cap. Deduplicates while
    preserving the representative-first order.

    Args:
        reachable_ips: The reachable IPs (the active universe) to order.
        rank_by_ip: IP → sort key from :func:`build_ip_rank_map`.

    Returns:
        A new, deduplicated list ordered representative-first.
    """
    # Unknown IPs get a sentinel rank that sorts strictly after any ranked IP
    # (tier band -1 < every real -tier which is in [-3, 0]). The trailing IP string
    # keeps the order total and stable.
    seen: set[str] = set()
    deduped: list[str] = []
    for ip in reachable_ips:
        clean = str(ip or "").strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        deduped.append(clean)

    def _key(ip: str) -> tuple[int, int, int, str, str]:
        ranked = rank_by_ip.get(ip)
        if ranked is None:
            return (1, 0, 0, "", ip)  # group 1 = unknown, sorts after group 0 = ranked
        return (0, ranked[0], ranked[1], ranked[2], ip + "\x00" + ranked[3])

    return sorted(deduped, key=_key)


@dataclass
class CappedActiveHosts:
    """Result of capping the reachable active-host set to ``host_cap``.

    Attributes:
        active_ips: The capped, representative-first active IP set (the union the
            per-service lists and privilege sweeps are bounded to).
        service_ips: ``{service: [ips]}`` — each list is ``active_ips`` ∩ the hosts
            with that service's port open, preserving the representative-first order.
        reachable_total: Count of reachable hosts BEFORE the cap.
        skipped_capped: Reachable hosts dropped by the cap (``0`` when it did not bite).
        capped: True when the cap actually truncated the reachable set.
    """

    active_ips: list[str]
    service_ips: dict[str, list[str]] = field(default_factory=dict)
    reachable_total: int = 0
    skipped_capped: int = 0
    capped: bool = False


def select_capped_active_hosts(
    *,
    reachable_ips: list[str],
    open_ports_by_host: dict[str, set[int]],
    service_ports: dict[str, int],
    computers_props: list[dict[str, Any]],
    host_cap: int,
) -> CappedActiveHosts:
    """Cap the reachable set and derive each service list as ``capped ∩ service-open``.

    The SSOT for the Phase-3 active-host cap. PURE — no I/O, no network. The caller
    runs the (cheap, complete) port scan first, then passes the reachable set + the
    open-ports map + the Phase-2 graph Computer props; this returns the bounded union
    and the per-service intersections.

    Args:
        reachable_ips: All reachable IPs (the active universe — already complete from
            the port scan). NOT pre-capped.
        open_ports_by_host: ``{ip: {open tcp ports}}`` from the port scan.
        service_ports: ``{service_name: tcp_port}`` (e.g. ``{"smb": 445, "winrm": 5985}``).
        computers_props: Graph-JSON Computer property dicts (Phase-2 tier signals).
        host_cap: Max hosts in the active union. ``0`` (or negative) = unlimited — a
            no-op that keeps EVERY reachable host in every service list (legacy behavior).

    Returns:
        A :class:`CappedActiveHosts`. When ``host_cap`` is ``0``/unlimited or the
        reachable set already fits, ``capped`` is False and ``active_ips`` is the full
        representative-first reachable set.
    """
    rank_by_ip = build_ip_rank_map(computers_props)
    ordered = order_active_ips_representative_first(reachable_ips, rank_by_ip)
    reachable_total = len(ordered)

    cap = int(host_cap or 0)
    if cap > 0 and reachable_total > cap:
        active_ips = ordered[:cap]
        skipped_capped = reachable_total - cap
        capped = True
        print_warning(
            f"Active host set capped to {cap} of {reachable_total} reachable hosts "
            "(representative-first: Tier 0 first); per-service target lists and "
            f"privilege sweeps bounded to this set. {skipped_capped} hosts skipped "
            "to bound scan time. Set host_cap=0 for a full active sweep."
        )
    else:
        active_ips = ordered
        skipped_capped = 0
        capped = False

    active_set = set(active_ips)
    service_ips: dict[str, list[str]] = {}
    for service, port in service_ports.items():
        # Preserve the representative-first order: walk active_ips, keep the ones
        # whose port is open. Intersection is exactly capped ∩ service-open.
        service_ips[service] = [
            ip
            for ip in active_ips
            if ip in active_set and port in (open_ports_by_host.get(ip) or set())
        ]

    return CappedActiveHosts(
        active_ips=active_ips,
        service_ips=service_ips,
        reachable_total=reachable_total,
        skipped_capped=skipped_capped,
        capped=capped,
    )
