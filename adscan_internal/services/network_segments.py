"""Which local interface has an Active Directory segment behind it.

The supported model for a segmented client network is ONE appliance with one NIC
per segment (or one NIC plus routes and firewall rules). The client chooses the
reach by cabling. So ADscan must be able to answer, for every local interface:

* **Does an AD segment sit behind it?** An interface "has an AD segment" when at
  least one IN-SCOPE AD asset (a recorded domain controller, or an enabled
  computer the collection resolved to an IP) is reached through it: the kernel's
  own route toward that asset leaves with a source address that lives on this
  interface. The route table already folds in connected subnets, static routes
  and metrics, so this is the routing decision the scan's own traffic takes, not
  a subnet comparison. It is deliberately NOT derived from "can this interface
  receive a callback": a management NIC can receive one and still have no AD
  asset behind it, and a bridge can route to a container that is no AD asset.
* **Can a target call back to it?** The kernel-first verdict from
  :mod:`adscan_internal.services.listener_ip` (a container bridge, a veth end or
  loopback cannot; a real NIC, a VLAN, a bond and a tunnel can).
* **Which of its addresses to announce?** An interface can carry several IPv4
  addresses (management plus segment, or secondaries), so taking the first one is
  a guess. The announced address is the one the kernel itself uses as the source
  toward the most AD assets routed through that interface, and the reason is
  recorded.

Two consumers today: broadcast poisoning, which binds one interface per job and
needs the list of interfaces worth poisoning (:func:`poisoning_interfaces`), and
the per-scan record of which interfaces carried AD traffic or listeners and which
had no AD asset behind them (:func:`write_network_interface_usage`), so a NIC
that was configured and never used is declared instead of silently ignored.

**Where the facts are persisted: the ``host_reach_coverage`` block, not here.**
The client-facing record of "where the scan ran from" is the shared
``adscan_core.reporting.host_reach_coverage`` block, stamped per domain by
``services/host_reach_coverage_stamp.py``. Its ``vantage`` comes from
:func:`coverage_vantage` (the segment interfaces, one row each) and its
``idle_interfaces`` from :func:`idle_interfaces`, so there is one persisted
statement of NIC use, not two. The in-memory record below
(:data:`USAGE_ATTR` on the shell, ``network_interface_usage``) only drives the
operator lines at scan end and is not written to disk. Shape (``schema`` 1)::

    {"schema": 1, "updated_at": "<iso8601>", "asset_count": <int>,
     "unattributed_asset_count": <int>,
     "interfaces": {"<name>": {"kind": "<InterfaceKind>",
                               "addresses": ["<ipv4>", ...],
                               "can_receive_callback": <bool>,
                               "routed_asset_count": <int>,
                               "advertise_ip": "<ipv4>" | null,
                               "roles": ["poisoning" | "capture_callback", ...],
                               "status": "used" | "no_ad_asset"
                                         | "not_callback_capable"}}}

Bounded computation, declared: at most :data:`MAX_ASSETS_MAPPED` assets are
routed (one connected UDP socket each, no packet sent); a larger estate records
how many were left out in ``assets_not_mapped`` rather than reading as complete.

Cross-platform: interfaces and addresses come from the PAL
(``adscan_core.pal.net``), the route from a connected UDP socket, both stdlib on
Windows. IPv4 only, like the rest of the callback ladder (see BACKLOG).
"""

from __future__ import annotations

import ipaddress
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from adscan_core.pal import net as pal_net
from adscan_core.pal.net import InterfaceKind

#: Shell attribute (and ``variables.json`` key) holding the per-scan record.
USAGE_ATTR = "network_interface_usage"

#: Shell attribute holding the roles recorded before the record is (re)written.
_ROLES_ATTR = "_network_interface_roles"
#: Shell attribute holding callback addresses whose interface is resolved late.
_CALLBACK_ADDRESSES_ATTR = "_network_callback_addresses"

ROLE_POISONING = "poisoning"
ROLE_CAPTURE_CALLBACK = "capture_callback"

STATUS_USED = "used"
STATUS_NO_AD_ASSET = "no_ad_asset"
STATUS_NOT_CALLBACK_CAPABLE = "not_callback_capable"

#: Upper bound on assets routed per mapping. A route lookup costs microseconds,
#: so this only bites on very large estates, and the overflow is recorded.
MAX_ASSETS_MAPPED = 4096

_ENABLED_COMPUTER_IP_FILES = ("enabled_computers_ips.txt",)

RouteLookup = Callable[[str], "str | None"]
KindLookup = Callable[[str], InterfaceKind]


@dataclass(frozen=True, slots=True)
class InterfaceSegment:
    """What one local interface reaches and whether a target can call it back."""

    interface: str
    kind: InterfaceKind
    addresses: tuple[str, ...]
    can_receive_callback: bool
    routed_asset_count: int
    advertise_ip: str | None
    advertise_reason: str

    @property
    def has_ad_segment(self) -> bool:
        """True when at least one in-scope AD asset is routed through it."""
        return self.routed_asset_count > 0


def _ipv4(value: object) -> str | None:
    text = str(value or "").strip()
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return None
    if parsed.version != 4 or parsed.is_unspecified:
        return None
    return str(parsed)


def _local_interfaces() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name in pal_net.interface_names():
        try:
            out[str(name)] = list(pal_net.interface_ipv4_addresses_for(str(name)) or [])
        except Exception:  # noqa: BLE001 - one unreadable NIC must not hide the rest
            out[str(name)] = []
    return out


def collect_in_scope_asset_ips(shell: Any, *, domain: str | None = None) -> list[str]:
    """Return the IPv4 addresses of the in-scope AD assets the workspace knows.

    Recorded domain controllers of every domain in ``domains_data`` (or of
    ``domain`` only) through the ``resolve_dc_ip`` ladder plus the ``dcs`` list,
    and the enabled computers the collection resolved to an IP. Hostnames are
    skipped: an unresolved name says nothing about the route. Order-preserving,
    de-duplicated. Never raises.
    """
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

    seen: dict[str, None] = {}

    def _add(value: object) -> None:
        ip = _ipv4(value)
        if ip:
            seen.setdefault(ip, None)

    domains_data = getattr(shell, "domains_data", None) or {}
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    domains_dir = str(getattr(shell, "domains_dir", "") or "domains")
    wanted = str(domain or "").strip().lower()
    for name, data in list(domains_data.items()):
        if not isinstance(data, dict):
            continue
        if wanted and str(name).strip().lower() != wanted:
            continue
        try:
            _add(resolve_dc_ip(data))
        except Exception:  # noqa: BLE001 - a malformed domain record is skipped
            pass
        for dc in data.get("dcs") or []:
            _add(dc)
        if not workspace_dir:
            continue
        for filename in _ENABLED_COMPUTER_IP_FILES:
            path = os.path.join(workspace_dir, domains_dir, str(name), filename)
            try:
                with open(path, encoding="utf-8") as handle:
                    for line in handle:
                        _add(line)
            except OSError:
                continue
    return list(seen)


def map_interface_segments(
    shell: Any,
    *,
    asset_ips: Iterable[str] | None = None,
    interfaces: Mapping[str, list[str]] | None = None,
    kind_lookup: KindLookup | None = None,
    route_lookup: RouteLookup | None = None,
) -> tuple[InterfaceSegment, ...]:
    """Map every local interface to the in-scope AD assets routed through it.

    Args:
        shell: Active shell (source of the in-scope assets when ``asset_ips`` is
            not given). ``None`` is tolerated.
        asset_ips: Explicit asset IPs to route (defaults to
            :func:`collect_in_scope_asset_ips`).
        interfaces: ``name -> [ipv4, ...]`` (defaults to the PAL walk).
        kind_lookup: ``name -> InterfaceKind`` (defaults to the kernel-first
            ``listener_ip.resolve_interface_kind``).
        route_lookup: ``target -> source ip`` (defaults to
            ``listener_ip.kernel_source_ip_toward``). A failure is inconclusive
            for that asset, never a verdict.

    Returns:
        One :class:`InterfaceSegment` per interface, in enumeration order.
        Never raises.
    """
    from adscan_internal.services.listener_ip import (  # noqa: PLC0415
        kernel_source_ip_toward,
        kind_can_receive_callback,
        resolve_interface_kind,
    )

    iface_map = dict(interfaces) if interfaces is not None else _local_interfaces()
    kinds = kind_lookup or resolve_interface_kind
    route = route_lookup or kernel_source_ip_toward
    assets = list(asset_ips) if asset_ips is not None else collect_in_scope_asset_ips(shell)

    owner_of: dict[str, str] = {}
    for name, addresses in iface_map.items():
        for address in addresses or []:
            ip = _ipv4(address)
            if ip:
                owner_of.setdefault(ip, name)

    sources: dict[str, Counter[str]] = {name: Counter() for name in iface_map}
    for asset in assets[:MAX_ASSETS_MAPPED]:
        try:
            source = _ipv4(route(asset))
        except Exception:  # noqa: BLE001 - inconclusive for this asset
            source = None
        owner = owner_of.get(source or "")
        if owner is not None:
            sources[owner][source] += 1  # type: ignore[index]

    segments: list[InterfaceSegment] = []
    for name, addresses in iface_map.items():
        try:
            kind = kinds(name)
        except Exception:  # noqa: BLE001 - the OS declined to type it
            kind = InterfaceKind.UNKNOWN
        ipv4s = tuple(ip for ip in (_ipv4(a) for a in addresses or []) if ip)
        counter = sources.get(name) or Counter()
        routed = sum(counter.values())
        advertise_ip: str | None = None
        reason = "no in-scope AD asset is routed through this interface"
        if routed:
            # most_common is stable for ties (insertion order), so the first
            # address the routes used wins a tie deterministically.
            advertise_ip, used_by = counter.most_common(1)[0]
            reason = (
                f"kernel source address toward {used_by} of the {routed} AD "
                f"asset(s) routed through {name}"
            )
        segments.append(
            InterfaceSegment(
                interface=name,
                kind=kind,
                addresses=ipv4s,
                can_receive_callback=kind_can_receive_callback(kind),
                routed_asset_count=routed,
                advertise_ip=advertise_ip,
                advertise_reason=reason,
            )
        )
    return tuple(segments)


def coverage_vantage(
    shell: Any,
    *,
    domain: str | None = None,
    segments: Iterable[InterfaceSegment] | None = None,
) -> dict[str, Any]:
    """Where the scan reached ``domain`` from, for a coverage block's ``vantage``.

    The callback-capable interfaces the domain's in-scope assets are actually
    routed through, with the address the kernel uses on each, so a multi-NIC
    appliance reads "eth1, eth2" and never the first interface the host lists
    (a container bridge on a developer machine). ``interface`` / ``address`` are
    comma-joined for a one-line label; ``interfaces`` carries the per-NIC facts.
    Empty strings when no segment is known yet, so the caller can fall back.
    Never raises.
    """
    try:
        if segments is None:
            segments = map_interface_segments(
                shell, asset_ips=collect_in_scope_asset_ips(shell, domain=domain)
            )
        used = [s for s in segments if s.can_receive_callback and s.has_ad_segment]
    except Exception:  # noqa: BLE001 - the vantage is a declaration aid, never a blocker
        used = []
    return {
        "interface": ", ".join(s.interface for s in used),
        "address": ", ".join(s.advertise_ip or "" for s in used if s.advertise_ip),
        "interfaces": [
            {
                "name": s.interface,
                "address": s.advertise_ip or "",
                "routed_asset_count": s.routed_asset_count,
            }
            for s in used
        ],
    }


def idle_interfaces(
    shell: Any, *, segments: Iterable[InterfaceSegment] | None = None
) -> list[dict[str, str]]:
    """Callback-capable interfaces no in-scope AD asset is routed through.

    A configured adapter on a segment where no scanned asset lives: never chosen,
    so it must be declared. ``{name, address}`` rows (addresses comma-joined),
    for the coverage block's ``idle_interfaces``. Bridges, veth ends and loopback
    are plumbing, not configured segments, and are left out. Never raises.
    """
    try:
        if segments is None:
            segments = map_interface_segments(shell)
        return [
            {"name": s.interface, "address": ", ".join(s.addresses)}
            for s in segments
            if s.can_receive_callback and not s.has_ad_segment
        ]
    except Exception:  # noqa: BLE001 - a declaration aid, never a blocker
        return []


def poisoning_interfaces(segments: Iterable[InterfaceSegment]) -> tuple[InterfaceSegment, ...]:
    """Interfaces worth one poisoning job each: callback-capable AND an AD segment."""
    return tuple(s for s in segments if s.can_receive_callback and s.has_ad_segment)


def _roles(shell: Any) -> dict[str, list[str]]:
    roles = getattr(shell, _ROLES_ATTR, None)
    if not isinstance(roles, dict):
        roles = {}
        try:
            setattr(shell, _ROLES_ATTR, roles)
        except Exception:  # noqa: BLE001 - a frozen shell records nothing
            return {}
    return roles


def record_interface_role(shell: Any, interface: str, role: str) -> None:
    """Record that ``interface`` carried a listener of ``role`` this scan."""
    name = str(interface or "").strip()
    if not name:
        return
    roles = _roles(shell)
    bucket = roles.setdefault(name, [])
    if role not in bucket:
        bucket.append(role)


def record_callback_address(
    shell: Any, address: str, *, interfaces: Mapping[str, list[str]] | None = None
) -> None:
    """Record that a target was told to call back to ``address``.

    The interface that owns the address gets the ``capture_callback`` role. An
    address on no local interface (a declared NAT or pivot address) is kept and
    attributed nowhere, which is the truth. Never raises.
    """
    ip = _ipv4(address)
    if not ip:
        return
    try:
        iface_map = dict(interfaces) if interfaces is not None else _local_interfaces()
    except Exception:  # noqa: BLE001
        iface_map = {}
    for name, addresses in iface_map.items():
        if ip in {_ipv4(a) for a in addresses or []}:
            record_interface_role(shell, name, ROLE_CAPTURE_CALLBACK)
            return
    pending = getattr(shell, _CALLBACK_ADDRESSES_ATTR, None)
    if not isinstance(pending, list):
        pending = []
        try:
            setattr(shell, _CALLBACK_ADDRESSES_ATTR, pending)
        except Exception:  # noqa: BLE001
            return
    if ip not in pending:
        pending.append(ip)


def _status(segment: InterfaceSegment) -> str:
    if not segment.can_receive_callback:
        return STATUS_NOT_CALLBACK_CAPABLE
    if segment.has_ad_segment:
        return STATUS_USED
    return STATUS_NO_AD_ASSET


def write_network_interface_usage(
    shell: Any,
    segments: Iterable[InterfaceSegment] | None = None,
    *,
    asset_count: int | None = None,
) -> dict[str, Any]:
    """Write (and return) the per-scan interface usage record on the shell.

    ``segments`` defaults to a fresh :func:`map_interface_segments`. The record
    is persisted with the workspace by ``save_workspace_data`` (see
    ``workspaces/state.py``). Never raises.
    """
    if segments is None:
        assets = collect_in_scope_asset_ips(shell)
        segments = map_interface_segments(shell, asset_ips=assets)
        asset_count = len(assets) if asset_count is None else asset_count
    segment_list = list(segments)
    roles = _roles(shell)
    routed_total = sum(s.routed_asset_count for s in segment_list)
    interfaces: dict[str, Any] = {}
    for segment in segment_list:
        interfaces[segment.interface] = {
            "kind": str(segment.kind),
            "addresses": list(segment.addresses),
            "can_receive_callback": segment.can_receive_callback,
            "routed_asset_count": segment.routed_asset_count,
            "advertise_ip": segment.advertise_ip,
            "advertise_reason": segment.advertise_reason,
            "roles": list(roles.get(segment.interface, [])),
            "status": _status(segment),
        }
    record: dict[str, Any] = {
        "schema": 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "interfaces": interfaces,
        "unattributed_callback_addresses": list(
            getattr(shell, _CALLBACK_ADDRESSES_ATTR, None) or []
        ),
    }
    if asset_count is not None:
        record["asset_count"] = int(asset_count)
        record["unattributed_asset_count"] = max(0, min(asset_count, MAX_ASSETS_MAPPED) - routed_total)
        record["assets_not_mapped"] = max(0, asset_count - MAX_ASSETS_MAPPED)
    try:
        setattr(shell, USAGE_ATTR, record)
    except Exception:  # noqa: BLE001 - the record is still returned
        pass
    return record


def unused_interface_lines(record: Mapping[str, Any] | None) -> list[str]:
    """Operator-facing lines naming each callback-capable NIC no AD asset uses.

    Interfaces a target cannot call back to (bridges, loopback, veth ends) are
    plumbing, not configured client segments, so they are not listed.
    """
    from adscan_internal.rich_output import mark_sensitive  # noqa: PLC0415

    lines: list[str] = []
    for name, entry in ((record or {}).get("interfaces") or {}).items():
        if not isinstance(entry, dict) or entry.get("status") != STATUS_NO_AD_ASSET:
            continue
        addresses = (
            ", ".join(str(mark_sensitive(a, "ip")) for a in entry.get("addresses") or [])
            or "no IPv4"
        )
        lines.append(
            f"{name} ({addresses}): no in-scope AD asset is routed through it, so "
            "nothing on that segment was assessed from this interface."
        )
    return lines


def unpoisoned_segment_lines(record: Mapping[str, Any] | None) -> list[str]:
    """Lines naming AD segments poisoning did not cover, when it ran elsewhere."""
    entries = ((record or {}).get("interfaces") or {}).items()
    poisoned = [n for n, e in entries if ROLE_POISONING in (e or {}).get("roles", [])]
    if not poisoned:
        return []
    lines: list[str] = []
    for name, entry in entries:
        if not isinstance(entry, dict) or entry.get("status") != STATUS_USED:
            continue
        if ROLE_POISONING in (entry.get("roles") or []):
            continue
        lines.append(
            f"{name}: {entry.get('routed_asset_count', 0)} AD asset(s) are routed "
            "through it, but broadcast poisoning did not run on it."
        )
    return lines


__all__ = [
    "InterfaceSegment",
    "MAX_ASSETS_MAPPED",
    "ROLE_CAPTURE_CALLBACK",
    "ROLE_POISONING",
    "STATUS_NOT_CALLBACK_CAPABLE",
    "STATUS_NO_AD_ASSET",
    "STATUS_USED",
    "USAGE_ATTR",
    "collect_in_scope_asset_ips",
    "coverage_vantage",
    "idle_interfaces",
    "map_interface_segments",
    "poisoning_interfaces",
    "record_callback_address",
    "record_interface_role",
    "unpoisoned_segment_lines",
    "unused_interface_lines",
    "write_network_interface_usage",
]
