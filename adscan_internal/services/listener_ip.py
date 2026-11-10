"""Which IP do we advertise to a target that must connect BACK to us.

Coercion (ESC8, NTLM capture, RBCD relay, cross-forest delegation) is the one
path where the TARGET initiates the connection, so the address we advertise has
to be reachable from the target's segment. The listener always binds
``0.0.0.0``; this module only decides what to *advertise*, and it decides it
**per target**.

Two real situations drove the design:

* A segmented client, one VLAN per asset. The DC and the ADCS CA sit on
  different VLANs of a multi-interface appliance. A single global address is
  right for one asset and wrong for the next, the coerced authentication never
  arrives and the report under-reports the client's exposure.
* An operator tunnelling in from a VPS. The address the DC must reach belongs to
  a pivot and is on NO local interface, so no inference can ever find it.

Both come from one conflation: ``shell.myip`` held an *inferred* value (the first
address of the interface the operator picked at startup) in the slot of an
*override*. Choosing an interface and declaring "the target must call me back at
this address" are different statements, so ``myip`` now carries a provenance
(:data:`MYIP_SOURCE_DECLARED` / :data:`MYIP_SOURCE_INTERFACE`).

The ladder, in order (see :func:`resolve_listener_ip`):

1. an explicit per-target override (a CLI flag such as ``--listener-ip``);
2. an operator-DECLARED ``myip`` (``set myip <ip>``): declared beats inference,
   because the only reason to type it is that inference cannot see the answer;
3. pivot-aware EGRESS resolution for that target
   (:func:`adscan_internal.services.egress_resolver.resolve_egress_for_target`):
   it knows about Ligolo tunnels, where a plain route lookup only sees the
   tunnel's own address, so it is strictly more specific than the route;
4. the per-target KERNEL ROUTE lookup (connected UDP socket, ``getsockname``).
   The route table already accounts for subnet, static routes and metrics, so
   no subnet matching is done by hand;
5. an interface-derived ``myip`` (the startup guess), kept as a compatibility
   fallback;
6. honest failure, naming what was needed.

Two different facts live around this ladder and only one is persisted. "Which
source IP reaches X" is a free, always-current kernel lookup and is never
cached. "Did a callback from X actually ARRIVE at the address we advertised" costs
a real coercion and cannot be derived from the route table (asymmetric routing,
NAT, a firewall that permits outbound and blocks inbound 445), so an observed
arrival is recorded per WORKSPACE, keyed by the advertised IP
(:func:`record_callback_success`). It is evidence only: it never changes which
address the ladder picks, it decides what we tell the operator after a coercion
produced no authentication (:func:`report_callback_outcome`). Only successes are
recorded: a failure is weak evidence (the technique, the patch level, a timeout
or an endpoint control explain it equally well) and must never poison an address.

Single source of truth: do not hand-roll a ``socket.connect`` + ``getsockname``
copy at a call site. Cross-platform: a connected UDP socket plus ``getsockname``
is stdlib and behaves the same on Windows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import asyncio
import ipaddress
import socket
import threading
from typing import Any, Callable, Literal

from adscan_core.pal import net as pal_net
from adscan_core.pal.net import InterfaceKind
from adscan_core.callback_interfaces import (  # noqa: F401 - re-exported SSOT
    _KERNEL_BLIND_VIRTUAL_NAME_PREFIXES,
    _NON_CALLBACK_INTERFACE_KINDS,
    _VIRTUAL_INTERFACE_NAME_PREFIXES,
    _VIRTUAL_INTERFACE_NAMES,
    describe_interface_kind,
    interface_can_receive_callback,
    interface_name_is_virtual,
    kind_can_receive_callback,
    resolve_interface_kind,
)

#: ``shell.myip_source`` values. ``None`` (legacy workspaces) is treated as
#: interface-derived: an old stored value is a guess, never a declaration.
MYIP_SOURCE_DECLARED = "declared"
MYIP_SOURCE_INTERFACE = "interface"

ListenerIpSourceKind = Literal[
    "override", "declared", "egress", "route", "interface", "local_interface", "none"
]

#: Workspace-level attribute holding observed callback arrivals, persisted in the
#: workspace-root ``variables.json`` next to ``myip``. A callback path is a
#: property of the NETWORK between us and the target, not of a directory, so it
#: does not live under ``domains_data[domain]``.
CALLBACK_HISTORY_ATTR = "listener_callback_history"

#: Workspace-free, in-memory queue of "no callback arrived" guidance waiting for a
#: safe point to be shown. The coroutines that run a coercion only ENQUEUE
#: (:func:`report_callback_outcome`); the foreground drains it with
#: :func:`present_pending_callback_advice` once the event loop is gone. A worker
#: never prints a prompt: that is the rule the background-job subsystem enforces.
_PENDING_ADVICE_ATTR = "_pending_callback_advice"
_PENDING_ADVICE_LOCK = threading.Lock()

#: Any UDP port works: ``connect`` on a datagram socket only resolves the route.
_ROUTE_PROBE_PORT = 9

#: The interface-kind policy (name tables, kernel demotions, callback verdict)
#: lives in :mod:`adscan_core.callback_interfaces` so the web backend shares it.

#: Rank per kind for the last-resort rung; lower sorts first.
#:
#: PHYSICAL, STACKED, TUNNEL and UNKNOWN deliberately SHARE rank 0. Ranking a
#: real NIC above a tunnel would be wrong in the one case that matters most: on
#: an HTB or GOAD engagement over VPN, ``tun0`` is the only interface that
#: reaches the target and the LAN NIC is useless. The earlier rungs (the pivot
#: resolver and the kernel route toward the target) already choose correctly when
#: a routable target exists, so this rung's only job is to keep an address that
#: reaches NOTHING from winning. UNKNOWN shares rank 0 for the same reason it is
#: not a verdict: an interface the OS does not type must not be demoted.
_INTERFACE_KIND_RANK: dict[InterfaceKind, int] = {
    InterfaceKind.PHYSICAL: 0,
    InterfaceKind.STACKED: 0,
    InterfaceKind.TUNNEL: 0,
    InterfaceKind.UNKNOWN: 0,
    InterfaceKind.BRIDGE: 1,
    InterfaceKind.VIRTUAL_OTHER: 1,
    InterfaceKind.LOOPBACK: 2,
}

#: The Docker default-bridge address pool (``docker0`` is ``172.17.0.1``, further
#: compose bridges climb ``172.18``-``172.31``). Used ONLY as a conservative,
#: secondary RANKING nudge in the last-resort rung when the interface NAME did
#: not already classify an address as virtual — never a reject, and deliberately
#: NOT the whole RFC1918 ``172.16.0.0/12`` (real client LANs live there, so a
#: private range alone is never disqualifying).
_DOCKER_DEFAULT_BRIDGE_POOL = ipaddress.ip_network("172.17.0.0/16")

RouteLookup = Callable[[str], "str | None"]
LocalIpLookup = Callable[[], "str | None"]
EgressLookup = Callable[[Any, str], "str | None"]


@dataclass(frozen=True, slots=True)
class ListenerIpSelection:
    """Outcome of choosing the listener IP to advertise to one target.

    Attributes:
        ip: The address to advertise, or ``None`` when nothing usable exists.
        source: Which rung of the ladder produced ``ip`` (``"none"`` on failure).
        target: The host that must connect back (the per-asset key).
        reason: Human-readable explanation of the decision, for debug output.
        candidates: Every rung that yielded a value, in ladder order, as
            ``(source, ip)`` pairs, so a decision is explainable afterwards.
        notes: Rungs that were skipped or rejected and why.
        previously_succeeded: Whether a callback has already ARRIVED at ``ip``
            in this workspace. Evidence only: it never influences which rung
            wins, so the chosen address is identical with or without it.
    """

    ip: str | None
    source: ListenerIpSourceKind
    target: str
    reason: str
    candidates: tuple[tuple[str, str], ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)
    previously_succeeded: bool = False

    @property
    def resolved(self) -> bool:
        """Return whether an address was chosen."""

        return bool(self.ip)

    @property
    def bind_ip(self) -> str | None:
        """Return the local address a listener should BIND to, or ``None``.

        Advertising and binding are different questions. Only the ``route`` and
        ``interface`` rungs are read from a local NIC, so only those are known to
        be bindable and bind exactly the advertised address. An ``override`` or a
        ``declared`` address is whatever the operator said (a tunnel or jump-host
        address on no local interface), and ``egress`` may be a pivot redirector;
        binding either fails, so those bind every interface (``0.0.0.0``), the
        same behaviour the relay listeners already use. A caller holding a pivot
        plan passes the plan's own bind address instead of this value.
        """

        if not self.ip:
            return None
        if self.source in ("route", "interface", "local_interface"):
            return self.ip
        return "::" if ":" in self.ip else "0.0.0.0"  # noqa: S104

    def failure_message(self, *, override_hint: str = "", subject: str = "") -> str:
        """Return an operator-facing message for an unresolved selection.

        Args:
            override_hint: Optional extra hint naming the call site's own flag
                (for example ``"--listener-ip"``).
            subject: Optional phrase replacing the default "the target <host>"
                for callers with no single target (for example
                ``"whoever opens the bait file"``).
        """

        hint = f" or pass {override_hint}" if override_hint else ""
        who = subject or f"the target {self.target or 'host'}"
        return (
            f"Could not determine which local IP {who} "
            "should connect back to: no route lookup result and no configured "
            f"callback address. Declare it with 'set listener-ip <ip>'{hint}."
        )


def _valid_ip(value: object) -> str | None:
    """Return ``value`` as a normalized IP literal, or ``None`` when invalid."""

    text = str(value or "").strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def is_valid_ip_literal(value: object) -> bool:
    """Return whether ``value`` is a syntactically valid IPv4/IPv6 literal."""

    return _valid_ip(value) is not None


def kernel_source_ip_toward(target_ip: str, port: int = _ROUTE_PROBE_PORT) -> str | None:
    """Return the source IP the kernel would use to reach ``target_ip``.

    A connected UDP socket sends no packet: ``connect`` only resolves the route
    and binds the local address, so ``getsockname`` is the routing decision.
    Returns ``None`` on any failure (no route, not an IP literal, no network).
    """

    target = _valid_ip(target_ip)
    if target is None:
        return None
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((target, port))
            return str(sock.getsockname()[0])
    except OSError:
        return None




def _address_is_container_bridge(ip: object) -> bool:
    """Return whether ``ip`` sits in the Docker default-bridge pool.

    Conservative, secondary signal only (see :data:`_DOCKER_DEFAULT_BRIDGE_POOL`).
    A private range on its own is never disqualifying.

    Now REDUNDANT on Linux, where :func:`resolve_interface_kind` demotes a
    container interface from the kernel regardless of its name or address, and
    kept because it is the only defence left on the path where the kernel is
    silent: Windows, and a container whose ``/sys`` is masked. A real client LAN
    inside ``172.17.0.0/16`` therefore loses nothing it would not already lose,
    because this is a tiebreaker and never a reject.
    """

    value = _valid_ip(ip)
    if value is None or ":" in value:
        return False
    try:
        return ipaddress.ip_address(value) in _DOCKER_DEFAULT_BRIDGE_POOL
    except ValueError:
        return False


def _callback_interface_rank(interface_name: object, ip: object) -> tuple[int, int]:
    """Rank one ``(interface, ip)`` pair as a candidate callback address.

    Lower sorts first. The primary key is the interface KIND
    (:func:`resolve_interface_kind`, kernel-first), which puts a bridge, a veth
    end and loopback behind every real NIC, VLAN, bond and tunnel. The secondary
    key is the Docker-pool address nudge, which now only ever decides anything on
    the path where the kernel is silent.

    Both are RANKING only — nothing is ever rejected here, so the last-resort
    rung still returns an address whenever one exists, and a pure-container host
    whose only address is ``172.17.0.x`` still gets that address.
    """

    kind = resolve_interface_kind(interface_name)
    return (
        _INTERFACE_KIND_RANK.get(kind, _INTERFACE_KIND_RANK[InterfaceKind.UNKNOWN]),
        1 if _address_is_container_bridge(ip) else 0,
    )


def _enumerate_local_interface_ips(shell: Any = None) -> list[tuple[str, str]]:
    """Return ``(interface_name, ipv4)`` pairs for every local interface.

    Reuses the shell's own ``PentestShell._collect_interface_ips`` (an
    ``ip -> interface`` map) when available, else the same PAL walk, so there is
    one notion of "the local addresses" and it behaves the same on Windows. The
    interface NAME is carried through (the shell helper already has it) so the
    caller can rank container/bridge NICs behind real ones.
    """

    if callable(getattr(shell, "_collect_interface_ips", None)):
        ip_to_iface = shell._collect_interface_ips()  # noqa: SLF001
        return [(str(iface), str(ip)) for ip, iface in ip_to_iface.items()]
    return [
        (str(iface), str(ip))
        for iface in pal_net.interface_names()
        for ip in (pal_net.interface_ipv4_addresses_for(str(iface)) or [])
    ]


def first_local_ipv4(shell: Any = None) -> str | None:
    """Return the best non-loopback IPv4 on a local interface, or ``None``.

    The last-resort rung of the ladder. The interface the operator used to be
    forced to pick at startup only ever yielded ``ips[0]`` of a local NIC; the
    machine still has those addresses without the question, so a session that
    chose no interface and has no routable target (a hostname-only host) can still
    advertise a real local address.

    "Best" is the regression fix: the old rung sorted the addresses as TEXT, and
    ``"172.17.0.1" < "192.168.180.5"`` lexicographically, so it actively PREFERRED
    the Docker bridge gateway over a real LAN address. Candidates are now ranked
    by :func:`_callback_interface_rank`, whose primary key is the kernel's own
    verdict on each interface (a bridge, a veth end or loopback behind every real
    NIC, VLAN, bond and tunnel), with enumeration order as the stable tiebreaker.
    It never rejects a candidate, so an address the old rung returned is still
    returned when it is the only one.

    Testing note: the machine running a test has real NICs, so a test asserting
    that nothing resolves must disable this rung, either by passing
    ``local_ip_lookup=lambda: None`` to :func:`resolve_listener_ip` or by
    monkeypatching ``listener_ip.first_local_ipv4`` to return ``None`` (what the
    listener test fixtures do).
    """

    try:
        candidates: list[tuple[str, str]] = []
        for iface, raw in _enumerate_local_interface_ips(shell):
            ip = _valid_ip(raw)
            if not ip:
                continue
            parsed = ipaddress.ip_address(ip)
            if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified:
                continue
            candidates.append((iface, ip))
        candidates.sort(key=lambda pair: _callback_interface_rank(pair[0], pair[1]))
        if candidates:
            return candidates[0][1]
    except Exception:  # noqa: BLE001 - inconclusive: the ladder fails honestly
        return None
    return None


def _egress_callback_ip(shell: Any, target_ip: str) -> str | None:
    """Return the pivot-aware callback IP for ``target_ip``, best-effort.

    Lazy import: the egress resolver pulls in the route and pivot services, and
    this module must stay importable from anywhere. Any failure is inconclusive
    and returns ``None`` so the ladder falls through.
    """

    try:
        from adscan_internal.services.egress_resolver import (  # noqa: PLC0415
            resolve_egress_for_target,
        )

        vantage = resolve_egress_for_target(shell, target_ip)
        return vantage.callback_ip or None
    except Exception:  # noqa: BLE001 - best-effort, never fatal
        return None


def myip_is_declared(shell: Any) -> bool:
    """Return whether the operator explicitly declared ``myip`` (not inferred)."""

    if shell is None:
        return False
    return bool(
        getattr(shell, "myip_source", None) == MYIP_SOURCE_DECLARED
        and _valid_ip(getattr(shell, "myip", None))
    )


def declare_myip(shell: Any, ip: str) -> None:
    """Record ``ip`` as an operator declaration (``set myip <ip>``)."""

    shell.myip = ip
    shell.myip_source = MYIP_SOURCE_DECLARED


def record_interface_myip(
    shell: Any, ip: str, *, replace_declared: bool = False
) -> bool:
    """Record an interface-derived (inferred) ``myip``.

    An inference must never silently undo an operator declaration, so by default
    this refuses to overwrite a declared value. Pass ``replace_declared=True``
    only for an explicit operator action (choosing an interface).

    Returns:
        ``True`` when ``shell.myip`` was updated.
    """

    if not replace_declared and myip_is_declared(shell):
        return False
    shell.myip = ip
    shell.myip_source = MYIP_SOURCE_INTERFACE
    return True


def resolve_listener_ip(
    shell: Any,
    *,
    target: str,
    override: str | None = None,
    route_lookup: RouteLookup | None = None,
    egress_lookup: EgressLookup | None = None,
    local_ip_lookup: LocalIpLookup | None = None,
) -> ListenerIpSelection:
    """Choose the IP to advertise to ``target`` so it can connect back to us.

    Args:
        shell: Active shell (source of ``myip`` and ``myip_source``). ``None`` is
            tolerated: only the override and the route lookup are then used.
        target: The host that will initiate the connection (the coerced host,
            not the relay destination). Pass the asset being coerced so the
            answer is per-asset.
        override: An explicit per-call address (a CLI flag). Wins over all.
        route_lookup: Injectable ``target -> source IP`` lookup; defaults to
            :func:`kernel_source_ip_toward`. A failure is inconclusive, never a
            verdict, and degrades to the next rung.
        egress_lookup: Injectable ``(shell, target) -> callback IP`` pivot-aware
            lookup; defaults to the egress resolver. Same degrade rule.
        local_ip_lookup: Injectable ``() -> IP`` for the last-resort rung; defaults
            to :func:`first_local_ipv4`.

    Returns:
        A :class:`ListenerIpSelection`. Never raises.
    """

    target_text = str(target or "").strip()
    candidates: list[tuple[str, str]] = []
    notes: list[str] = []

    override_ip = _valid_ip(override)
    if str(override or "").strip() and override_ip is None:
        notes.append("override ignored: not a valid IP address")
    if override_ip:
        candidates.append(("override", override_ip))

    myip = _valid_ip(getattr(shell, "myip", None)) if shell is not None else None
    declared = myip if myip and myip_is_declared(shell) else None
    if declared:
        candidates.append(("declared", declared))

    route_ip: str | None = None
    egress_ip: str | None = None
    target_ip = _valid_ip(target_text)
    if target_ip is None:
        notes.append("egress and route lookup skipped: target is not an IP address")
    else:
        if shell is not None:
            try:
                egress_ip = _valid_ip((egress_lookup or _egress_callback_ip)(shell, target_ip))
            except Exception as exc:  # noqa: BLE001 - inconclusive, degrade
                notes.append(f"egress lookup failed: {type(exc).__name__}")
            if egress_ip and ipaddress.ip_address(egress_ip).is_unspecified:
                notes.append("egress result rejected: not a callable address")
                egress_ip = None
            if egress_ip:
                candidates.append(("egress", egress_ip))
        lookup = route_lookup or kernel_source_ip_toward
        try:
            raw = lookup(target_ip)
        except Exception as exc:  # noqa: BLE001 - inconclusive, degrade
            raw = None
            notes.append(f"route lookup failed: {type(exc).__name__}")
        route_ip = _valid_ip(raw)
        if route_ip:
            parsed = ipaddress.ip_address(route_ip)
            target_loopback = ipaddress.ip_address(target_ip).is_loopback
            if parsed.is_unspecified or (parsed.is_loopback and not target_loopback):
                notes.append("route lookup result rejected: not a callable address")
                route_ip = None
        if route_ip:
            candidates.append(("route", route_ip))
        elif raw is None:
            notes.append("route lookup returned no address")

    interface_ip = myip if myip and not declared else None
    if interface_ip:
        candidates.append(("interface", interface_ip))

    if not candidates:
        try:
            local_ip = _valid_ip((local_ip_lookup or (lambda: first_local_ipv4(shell)))())
        except Exception:  # noqa: BLE001 - inconclusive, fail honestly below
            local_ip = None
        if local_ip:
            candidates.append(("local_interface", local_ip))
        else:
            notes.append("no non-loopback local IPv4 found")

    if not candidates:
        return ListenerIpSelection(
            ip=None,
            source="none",
            target=target_text,
            reason="no override, declared myip, egress or route result, interface myip or local IPv4",
            candidates=(),
            notes=tuple(notes),
        )

    source, ip = candidates[0]
    previously_succeeded = callback_previously_succeeded(shell, ip)
    reasons: dict[str, str] = {
        "override": "explicit per-call override",
        "declared": "operator-declared myip (declared beats inference)",
        "egress": "pivot-aware egress resolution for the target",
        "route": "kernel route lookup toward the target",
        "interface": "interface-derived myip (startup guess, compatibility fallback)",
        "local_interface": "first non-loopback local IPv4 (last resort, nothing more specific was available)",
    }
    return ListenerIpSelection(
        ip=ip,
        source=source,  # type: ignore[arg-type]
        target=target_text,
        reason=reasons[source]
        + (
            "; a callback has already arrived at this address in this workspace"
            if previously_succeeded
            else ""
        ),
        candidates=tuple(candidates),
        notes=tuple(notes),
        previously_succeeded=previously_succeeded,
    )


def _callback_history(shell: Any, *, create: bool = False) -> dict[str, Any]:
    """Return the workspace callback history dict (``{}`` when absent)."""

    history = getattr(shell, CALLBACK_HISTORY_ATTR, None) if shell is not None else None
    if isinstance(history, dict):
        return history
    if create and shell is not None:
        history = {}
        try:
            setattr(shell, CALLBACK_HISTORY_ATTR, history)
        except Exception:  # noqa: BLE001 - a shell that refuses the attribute
            return {}
        return history
    return {}


def callback_previously_succeeded(shell: Any, ip: object) -> bool:
    """Return whether a callback has been observed arriving at ``ip``."""

    key = _valid_ip(ip)
    return bool(key and key in _callback_history(shell))


def record_callback_success(shell: Any, *, advertised_ip: object, target: str = "") -> bool:
    """Record that a coerced callback ARRIVED at ``advertised_ip``.

    Call this only when an authentication was actually observed at the address
    that was advertised. A failure is never recorded: it is weak evidence (the
    technique, patch level, a timeout or an endpoint control explain it equally
    well) and recording it would let one bad coercion poison an address for every
    other host. This mirrors ``select_reachable_dc_ip`` (a timeout is inconclusive,
    never a verdict) and the posture rule "cache observations, never absences".

    The record is keyed by the advertised source IP, not by the target or its
    subnet: ADscan does not reliably know the remote prefix and inbound firewall
    policy is per host, so a success is never generalised to other hosts. Whether
    a new target is covered is answered by the route lookup, which says whether it
    egresses the same local address.

    Returns:
        ``True`` when a success was recorded.
    """

    key = _valid_ip(advertised_ip)
    if key is None or shell is None:
        return False
    if ipaddress.ip_address(key).is_unspecified:
        return False
    history = _callback_history(shell, create=True)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    entry = history.get(key)
    if not isinstance(entry, dict):
        entry = {"first_seen": now, "count": 0}
    entry["count"] = int(entry.get("count") or 0) + 1
    entry["last_seen"] = now
    entry["last_target"] = str(target or "")
    history[key] = entry
    _persist_workspace(shell)
    return True


def _persist_workspace(shell: Any) -> None:
    """Best-effort workspace save so a recorded arrival survives a reload."""

    if not (
        getattr(shell, "current_workspace", None)
        and getattr(shell, "current_workspace_dir", None)
    ):
        return
    save = getattr(shell, "save_workspace_data", None)
    if not callable(save):
        return
    try:
        save()
    except Exception:  # noqa: BLE001 - recording must never break a run
        return


def _running_loop_in_this_thread() -> bool:
    """Return whether an asyncio event loop is running in the calling thread."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def advise_on_missing_callback(
    shell: Any, *, advertised_ip: object, target: str, allow_prompt: bool = True
) -> None:
    """Tell the operator what a coercion with no callback most likely means.

    This RENDERS (and may prompt), so it belongs on the foreground thread, after
    the coercion's event loop has finished. Coroutines must not call it: they
    queue the need through :func:`report_callback_outcome` and the foreground
    shows it with :func:`present_pending_callback_advice`. As a structural
    backstop it never prompts while an event loop is running in this thread, since
    a prompt there would hold that loop (its listeners, its timeouts) for as long
    as the operator takes to answer; it prints the guidance only. ``allow_prompt``
    is the deliberate form of the same choice: the REPL backstop drain passes
    ``False`` so late guidance is printed, never asked about.

    Never prompts in a non-interactive run (``adscan ci`` prints the guidance
    only, which is the honest data gap, not a hang).

    * No recorded arrival at the advertised address: it is the prime suspect;
      interactive sessions are offered a different address to declare.
    * A recorded arrival: the address has demonstrably worked, so it is not
      blamed.
    """

    ip = _valid_ip(advertised_ip)
    if ip is None:
        return
    from adscan_internal.interaction import is_non_interactive  # noqa: PLC0415
    from adscan_internal.rich_output import (  # noqa: PLC0415
        mark_sensitive,
        print_info,
        print_success,
        print_warning,
        prompt_ask,
    )

    marked_ip = mark_sensitive(ip, "ip")
    marked_target = mark_sensitive(str(target or "the target"), "hostname")
    if callback_previously_succeeded(shell, ip):
        print_info(
            f"No authentication arrived from {marked_target}, but {marked_ip} has "
            "already received a callback on this route, so the address is unlikely "
            "to be the cause. Look at the technique, the target's patch level, a "
            "timeout or an endpoint control instead."
        )
        return
    print_warning(
        f"No authentication arrived from {marked_target}. The address advertised to "
        f"it, {marked_ip}, has never received a callback in this workspace, so it is "
        "the prime suspect: the target may not be able to reach it (asymmetric "
        "routing, NAT, a tunnel, or inbound 445 blocked). If it should call back at a "
        "different address, declare it with 'set listener-ip <ip>'."
    )
    if not allow_prompt or is_non_interactive(shell) or _running_loop_in_this_thread():
        return
    answer = prompt_ask(
        "Callback address to declare now (leave empty to keep the current one)",
        default="",
        shell=shell,
    )
    candidate = str(answer or "").strip()
    if not candidate:
        return
    if not is_valid_ip_literal(candidate):
        print_warning(
            f"Not a valid IP address: {mark_sensitive(candidate, 'ip')}. "
            "Declare one later with 'set listener-ip <ip>'."
        )
        return
    declare_myip(shell, candidate)
    print_success(
        f"Callback address declared: {mark_sensitive(candidate, 'ip')}. "
        "Run the technique again to use it."
    )


def queue_callback_advice(shell: Any, *, advertised_ip: object, target: str) -> bool:
    """Queue "no callback arrived" guidance for the foreground; never renders.

    Safe to call from a coroutine or a worker thread: it only appends to an
    in-memory list. Duplicates (same address and target) collapse.

    Returns:
        ``True`` when the guidance was queued.
    """

    ip = _valid_ip(advertised_ip)
    if ip is None or shell is None:
        return False
    entry = (ip, str(target or ""))
    with _PENDING_ADVICE_LOCK:
        pending = getattr(shell, _PENDING_ADVICE_ATTR, None)
        if not isinstance(pending, list):
            pending = []
            try:
                setattr(shell, _PENDING_ADVICE_ATTR, pending)
            except Exception:  # noqa: BLE001 - a shell that refuses the attribute
                return False
        if entry not in pending:
            pending.append(entry)
    return True


def present_pending_callback_advice(shell: Any, *, allow_prompt: bool = True) -> int:
    """Show every queued "no callback arrived" guidance; call from the foreground.

    The safe point is wherever the synchronous caller that drove the coercion's
    event loop (``run_async_sync`` / ``asyncio.run``) regains control: the loop
    has finished, its listeners are closed and its timeouts no longer matter, so
    an operator-paced prompt costs nothing. Best-effort and idempotent: the queue
    is emptied first, so a second call shows nothing, which is also why a REPL
    backstop drain after a consumer's own drain cannot print anything twice.

    Args:
        shell: Active shell; ``None`` is a no-op.
        allow_prompt: ``False`` prints the guidance without ever asking. The
            consumer seams ask (they just ran the coercion); the pre-prompt REPL
            backstop does not, because guidance reaching it means the consumer
            did not drain and the question is no longer attached to any action.

    Returns:
        The number of guidance items presented.
    """

    if shell is None:
        return 0
    with _PENDING_ADVICE_LOCK:
        pending = getattr(shell, _PENDING_ADVICE_ATTR, None)
        if not isinstance(pending, list) or not pending:
            return 0
        items = list(pending)
        pending.clear()
    shown = 0
    for ip, target in items:
        try:
            advise_on_missing_callback(
                shell, advertised_ip=ip, target=target, allow_prompt=allow_prompt
            )
            shown += 1
        except Exception as exc:  # noqa: BLE001 - guidance must never fail a run
            from adscan_internal.rich_output import print_info_debug  # noqa: PLC0415

            print_info_debug(f"callback guidance not shown: {type(exc).__name__}")
    return shown


def report_callback_outcome(
    shell: Any,
    *,
    advertised_ip: object,
    target: str,
    arrived: bool,
    listener_error: str | None = None,
) -> None:
    """Single seam for both coercion families: record an arrival or queue advice.

    Safe to call from inside a coroutine: it records (no prompt) or QUEUES the
    guidance for :func:`present_pending_callback_advice`; it never prints a prompt
    itself.

    Args:
        shell: Active shell; ``None`` is tolerated and makes this a no-op.
        advertised_ip: The address the target was told to connect back to.
        target: The host that was coerced (informational).
        arrived: Whether an authentication actually reached the listener.
        listener_error: Set when the listener could not bind. That is our own
            failure, not evidence about the address, so no advice is given.
    """

    if shell is None:
        return
    if arrived:
        record_callback_success(shell, advertised_ip=advertised_ip, target=target)
        return
    if listener_error:
        return
    queue_callback_advice(shell, advertised_ip=advertised_ip, target=target)


def resolve_untargeted_listener_ip(shell: Any) -> ListenerIpSelection:
    """Choose the IP to advertise when no single host will connect back.

    Used by the write-share NTLM bait: the authentication arrives when some
    unknown future user on an unknown host opens the file, so there is no
    target to route toward, and inventing one (the share host) would be a
    guess. The ladder therefore runs WITHOUT a routable target: an operator
    ``set myip <ip>`` declaration is honoured, then the interface-derived
    ``myip``, then an honest failure.

    The egress and route rungs are deliberately skipped, not merely unreachable:
    these paths bind the advertised address locally (the capture listener takes
    it as its bind host), and a pivot-egress candidate is a redirector address
    the local listener cannot bind.
    """

    return resolve_listener_ip(shell, target="")


def myip_toolbar_label(shell: Any) -> str:
    """Return the short status-bar text for ``shell.myip``.

    The callback address is chosen per asset, so the bar must not read as "what
    every target will call back to". A declared address is labelled as the
    operator's declaration; an interface-derived one is only the local address.
    The text contains no markup characters (it is placed inside prompt_toolkit
    HTML).
    """

    ip = str(getattr(shell, "myip", "") or "").strip()
    if not ip:
        return ""
    if myip_is_declared(shell):
        return f"Callback (declared): {ip}"
    return f"Local IP: {ip}"


_WILDCARD_BIND_HOSTS =frozenset({"", "0.0.0.0", "::", "[::]", "*"})


def resolve_payload_lhost(
    shell: Any,
    *,
    bind_host: str | None,
    target: str,
) -> ListenerIpSelection:
    """Choose the LHOST to embed in a payload or agent deployed to ``target``.

    A reverse-shell listener binds an address (often ``0.0.0.0``) and the
    payload must carry an address the deployed host can actually dial back, which
    is the same bind-versus-advertise question as coercion. When the listener is
    bound to one concrete address the caller already holds a real address and it
    is used as-is; only a wildcard bind leaves something to resolve, and that goes
    through the per-target ladder (declared ``myip``, pivot egress, the route
    toward ``target``, the interface-derived ``myip``).

    Args:
        shell: Shell carrying ``myip`` / ``myip_source``.
        bind_host: The address the listener is bound to, or ``None``.
        target: The host the payload runs on (IP preferred; a hostname skips the
            route rungs). Pass ``""`` when no single host is known.
    """

    bound = str(bind_host or "").strip()
    if bound not in _WILDCARD_BIND_HOSTS:
        return resolve_listener_ip(shell, target=target, override=bound)
    return resolve_listener_ip(shell, target=target)


__all__ = [
    "CALLBACK_HISTORY_ATTR",
    "MYIP_SOURCE_DECLARED",
    "MYIP_SOURCE_INTERFACE",
    "EgressLookup",
    "ListenerIpSelection",
    "first_local_ipv4",
    "advise_on_missing_callback",
    "callback_previously_succeeded",
    "declare_myip",
    "describe_interface_kind",
    "interface_can_receive_callback",
    "kind_can_receive_callback",
    "interface_name_is_virtual",
    "is_valid_ip_literal",
    "kernel_source_ip_toward",
    "myip_is_declared",
    "myip_toolbar_label",
    "present_pending_callback_advice",
    "queue_callback_advice",
    "record_callback_success",
    "record_interface_myip",
    "report_callback_outcome",
    "resolve_interface_kind",
    "resolve_listener_ip",
    "resolve_payload_lhost",
    "resolve_untargeted_listener_ip",
]
