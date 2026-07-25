"""Per-target egress + inbound-callback IP resolution (pivot-aware).

Single source of truth for "which local interface / source IP reaches THIS
target, and what IP should a victim on that target's segment connect BACK to".

Two distinct classes of technique need different answers (see the design spec
``docs/superpowers/specs/2026-07-24-pivot-aware-egress-and-callback-ip-resolution.md``):

* **Outbound-initiated** (host discovery, LDAP/SMB/Kerberos enum, kerberoast,
  DCSync, relay-as-client, coercion where WE dial the DC): the kernel route +
  the TUN handle deliver the packets; our source IP is irrelevant to
  correctness. These only need the interface picker to ACCEPT the vantage
  interface.
* **Inbound-callback** (write-share NTLMv2 bait, relay server, coercion-to-us,
  PrintNightmare DLL UNC, LLMNR/NBT-NS/mDNS poisoning): we embed/advertise an
  IP the victim must connect back to; correctness depends on that IP being
  reachable from the victim's segment. A single global ``shell.myip`` is wrong
  on a multi-NIC appliance and impossible through a Ligolo TUN.

:func:`resolve_egress_for_target` answers the inbound-callback question for one
target IP by consulting the kernel routing table (``ip route get`` via
:func:`assess_route_to_target`) — on a multi-NIC host the routing table already
knows which NIC (and which ``src``) reaches each segment. When the route goes
out a Ligolo TUN, it resolves the callback candidate from the pivot tunnel
record instead and flags the ``pivot`` vantage so callers can gate/annotate
honestly (an inbound callback through an L3 tunnel needs a target-segment
redirector; broadcast poisoning cannot cross an L3 tunnel at all).
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any, Literal

from adscan_internal import print_info_debug, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.network_preflight_service import assess_route_to_target
from adscan_internal.services.pivot_runtime_state_service import is_ligolo_interface
from adscan_core.rich_output import print_exception

#: The three vantages a target can be reached from.
#: * ``direct`` — a real local NIC with a kernel-chosen source IP reaches the
#:   target; ``callback_ip`` is that source IP and the local listener CAN bind it.
#: * ``pivot`` — the route goes out a Ligolo TUN; ``callback_ip`` (when set) is a
#:   target-segment redirector candidate the LOCAL listener CANNOT bind — an
#:   inbound callback needs a target-segment redirector (agent listener).
#: * ``unknown`` — routing could not be determined (route tool absent /
#:   unsupported platform / no ``src`` on a real NIC); callers fall back to the
#:   global ``shell.myip`` and this verdict is NOT memoized.
EgressVantageKind = Literal["direct", "pivot", "unknown"]

_EGRESS_CACHE_ATTR = "_egress_vantage_cache"


@dataclass(frozen=True, slots=True)
class EgressVantage:
    """Resolved egress + inbound-callback vantage for one target IP.

    Attributes:
        interface: Kernel-chosen egress interface toward the target (``None``
            when routing could not be determined).
        source_ip: Kernel-chosen source IP toward the target for a real NIC
            (``None`` for a TUN, which has no normal source IP).
        vantage: One of :data:`EgressVantageKind`.
        callback_ip: The IP a victim on the target's segment should connect back
            to. For ``direct`` this is ``source_ip`` (bindable locally). For
            ``pivot`` this is a target-segment redirector candidate (NOT locally
            bindable; requires an agent listener). ``None`` when no usable
            callback IP could be resolved.
        notes: Human-readable annotation explaining a ``pivot`` / ``unknown``
            verdict (``None`` for a clean ``direct`` resolution).
    """

    interface: str | None
    source_ip: str | None
    vantage: EgressVantageKind
    callback_ip: str | None
    notes: str | None = None

    @property
    def is_direct(self) -> bool:
        """Return whether the target is reached directly (locally bindable callback)."""

        return self.vantage == "direct" and bool(self.callback_ip)


def _segment_key(target_ip: str) -> str:
    """Return a coarse segment key for memoization (the /24, else the raw IP)."""

    try:
        addr = ipaddress.ip_address(str(target_ip).strip())
    except ValueError:
        return str(target_ip).strip()
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{addr}/24", strict=False))
    return str(ipaddress.ip_network(f"{addr}/64", strict=False))


def _ip_in_route(target_ip: str, route: str) -> bool:
    """Return whether ``target_ip`` falls within a route prefix hint / bare IP."""

    prefix = str(route or "").strip()
    if not prefix:
        return False
    try:
        addr = ipaddress.ip_address(str(target_ip).strip())
    except ValueError:
        return False
    try:
        if "/" in prefix:
            return addr in ipaddress.ip_network(prefix, strict=False)
        return addr == ipaddress.ip_address(prefix)
    except ValueError:
        return False


def _strip_port(value: str) -> str:
    """Return an address with any trailing ``:port`` stripped (best-effort)."""

    text = str(value or "").strip()
    if not text:
        return ""
    # IPv6 with brackets: [::1]:445 → ::1
    if text.startswith("["):
        return text[1 : text.find("]")] if "]" in text else text
    # IPv4 host:port (a lone ':' and no other colon → not IPv6)
    if text.count(":") == 1:
        return text.split(":", 1)[0]
    return text


def _resolve_pivot_callback_ip(shell: Any, target_ip: str) -> tuple[str | None, str]:
    """Resolve a target-segment redirector candidate for a pivoted target.

    Reads the Ligolo tunnel records and returns the pivot-host IP of the tunnel
    whose routes / confirmed targets cover ``target_ip``. This is the intended
    callback host for an L3 unicast callback; whether a redirector actually
    listens there is the reverse-channel primitive's concern (deferred item c).
    """

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if not workspace_dir:
        return None, "no workspace context to resolve the pivot tunnel"
    try:
        from adscan_internal.services.ligolo_service import (  # noqa: PLC0415
            LigoloProxyService,
        )

        domain = str(getattr(shell, "domain", "") or "").strip() or None
        service = LigoloProxyService(workspace_dir=workspace_dir, current_domain=domain)
        records = service.list_tunnel_records()
    except Exception as exc:  # noqa: BLE001 — best-effort annotation, never raises
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None, "could not read the Ligolo tunnel state"

    for record in records:
        if not isinstance(record, dict):
            continue
        routes = [str(r) for r in (record.get("routes") or [])]
        confirmed = [str(t) for t in (record.get("confirmed_targets") or [])]
        covers = any(_ip_in_route(target_ip, r) for r in routes) or any(
            _ip_in_route(target_ip, t) for t in confirmed
        )
        if not covers:
            continue
        candidate = str(record.get("pivot_host") or "").strip()
        if not candidate:
            agent = record.get("agent")
            if isinstance(agent, dict):
                candidate = _strip_port(str(agent.get("remote_addr") or ""))
        if candidate:
            return candidate, (
                "inbound callback via the Ligolo pivot requires a target-segment "
                "redirector (agent listener); broadcast poisoning is unavailable "
                "over an L3 tunnel"
            )
    return None, (
        "no Ligolo tunnel covers this target; inbound callback via the pivot is "
        "not available"
    )


def resolve_egress_for_target(shell: Any, target_ip: str) -> EgressVantage:
    """Resolve the egress + inbound-callback vantage for one target IP.

    The result is memoized per target segment on the shell so a sweep across a
    /24 pays the ``ip route get`` cost once. An ``unknown`` verdict (routing
    undeterminable) is deliberately NOT cached — the next caller re-probes.

    Args:
        shell: Active session shell (provides ``run_command``, workspace, myip).
        target_ip: The target host IP the callback must reach back from.

    Returns:
        An :class:`EgressVantage`. Never raises — routing failures degrade to an
        ``unknown`` vantage so callers fall back to the global ``shell.myip``.
    """

    key = _segment_key(target_ip)
    cache = getattr(shell, _EGRESS_CACHE_ATTR, None)
    if not isinstance(cache, dict):
        cache = {}
        try:
            setattr(shell, _EGRESS_CACHE_ATTR, cache)
        except Exception:  # noqa: BLE001 — a read-only shell just skips memoization
            cache = {}
    cached = cache.get(key)
    if isinstance(cached, EgressVantage):
        return cached

    try:
        route = assess_route_to_target(shell, target_ip=str(target_ip).strip())
    except Exception as exc:  # noqa: BLE001 — routing is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return EgressVantage(
            interface=None,
            source_ip=None,
            vantage="unknown",
            callback_ip=None,
            notes="route assessment failed",
        )

    route_interface = route.route_interface
    source_ip = route.source_ip

    if route_interface and is_ligolo_interface(route_interface):
        callback_ip, notes = _resolve_pivot_callback_ip(shell, target_ip)
        result = EgressVantage(
            interface=route_interface,
            source_ip=source_ip,
            vantage="pivot",
            callback_ip=callback_ip,
            notes=notes,
        )
        cache[key] = result
        print_info_debug(
            "egress-resolver: pivot vantage for "
            f"{mark_sensitive(str(target_ip), 'ip')} via iface "
            f"{mark_sensitive(str(route_interface), 'hostname')} "
            f"callback={mark_sensitive(str(callback_ip or 'none'), 'ip')}"
        )
        return result

    if route_interface and source_ip:
        result = EgressVantage(
            interface=route_interface,
            source_ip=source_ip,
            vantage="direct",
            callback_ip=source_ip,
            notes=None,
        )
        cache[key] = result
        print_info_debug(
            "egress-resolver: direct vantage for "
            f"{mark_sensitive(str(target_ip), 'ip')} via iface "
            f"{mark_sensitive(str(route_interface), 'hostname')} "
            f"src={mark_sensitive(str(source_ip), 'ip')}"
        )
        return result

    # Routing undeterminable (route tool absent / unsupported platform / a real
    # NIC with no src): do NOT cache — the next caller re-probes. Callers fall
    # back to the global shell.myip.
    return EgressVantage(
        interface=route_interface,
        source_ip=source_ip,
        vantage="unknown",
        callback_ip=source_ip,
        notes=route.reason,
    )


def resolve_callback_ip_for_target(
    shell: Any, target_ip: str, *, default: str | None = None
) -> str | None:
    """Convenience: resolve the inbound-callback IP for a target, with a fallback.

    Returns the resolved ``callback_ip`` when the vantage yields one; otherwise
    ``default`` (typically the global ``shell.myip``). This is the thin helper
    inbound-callback call sites use when they only need the IP, not the full
    vantage record.
    """

    vantage = resolve_egress_for_target(shell, target_ip)
    if vantage.callback_ip:
        return vantage.callback_ip
    return default


__all__ = [
    "EgressVantage",
    "EgressVantageKind",
    "resolve_callback_ip_for_target",
    "resolve_egress_for_target",
]
