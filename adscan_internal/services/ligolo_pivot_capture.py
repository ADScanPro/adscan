"""Pivot-aware inbound-callback capture through a Ligolo agent listener.

This is item (c) of the pivot-aware egress design
(``docs/superpowers/specs/2026-07-24-pivot-aware-egress-and-callback-ip-resolution.md``).

Item (b) (``egress_resolver.py``) already reports ``vantage="pivot"`` with a
redirector-host candidate when the kernel route to a target goes out a Ligolo
TUN. But a redirector candidate is not a reachable callback on its own: an
INBOUND NTLM callback (write-share bait, relay, coercion-to-us) needs a listener
that a victim on the target's segment can actually connect to, tunneled back to
our machine. Ligolo-ng provides exactly that primitive — an agent-side listener
(``POST /api/v1/listeners``) — which the integration previously did not expose.

This module is the decision + arm + teardown SSOT for turning a pivot vantage
into a working capture path, with **honest-skip as the default failure mode**:

* ``plan_pivot_capture`` inspects the live tunnels/agents and decides whether a
  capture through the pivot is viable, WITHOUT any side effect. Its dominant
  answer is a clean skip with a precise reason — the tool never claims a capture
  it cannot deliver.
* ``arm_planned_capture`` creates the agent listener for a *viable* plan and
  returns its numeric id (for teardown), or ``None`` on any failure.
* ``teardown_planned_capture`` removes the agent listener best-effort.

**445 contention is first-class.** The listener a victim connects to must bind
:445 on the redirector host, but every Windows host already serves SMB on :445 —
so a :445 redirector only works on a host that does NOT serve SMB there. The
planner probes the redirector's :445 through the tunnel and skips any host that
already serves it, naming the alt-port WebDAV/HTTP avenue as the manual next step
(that avenue needs an HTTP capture listener ADscan does not yet wire, so claiming
it would be dishonest).

**No lab, honest telemetry.** There is no GOAD double-segment pivot lab, so this
ships best-effort and is validated from real-world telemetry when a pentester
actually pivots. Every decision point logs a bracket-free, ``mark_sensitive``-d
diagnostic so a session recording shows exactly what the primitive decided.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from typing import Any

from adscan_internal import print_info_debug, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.egress_resolver import resolve_egress_for_target
from adscan_core.rich_output import print_exception

#: Default port the redirector listener binds on the agent (SMB / NTLM callback).
DEFAULT_REDIRECT_PORT = 445
#: The proxy-local address the agent listener relays inbound connections to. The
#: write-share capture broker binds ``0.0.0.0``, so loopback always reaches it.
LOCAL_REDIRECT_HOST = "127.0.0.1"
#: The bind IP the local capture broker uses for a pivot capture: all interfaces,
#: so the tunneled/loopback redirect is accepted regardless of arrival interface.
PIVOT_BROKER_BIND_IP = "0.0.0.0"
_PROBE_TIMEOUT_SECONDS = 3.0
_LOG = "ligolo-pivot-capture"


@dataclass(frozen=True, slots=True)
class PivotCapturePlan:
    """Decision for capturing an inbound callback to one target through a pivot.

    Attributes:
        applicable: Whether the target is reached through a Ligolo pivot at all.
            ``False`` means the caller should use its normal (direct) callback IP.
        viable: Whether a capture-through-pivot can actually be armed. When
            ``True`` the ``agent_id`` / ``listener_addr`` / ``redirect_addr`` /
            ``callback_ip`` / ``bind_ip`` fields are populated.
        skip_reason: Machine-readable reason when ``applicable`` but not
            ``viable`` (``no_workspace`` / ``ligolo_api_unavailable`` /
            ``no_pivot_route`` / ``redirector_serves_smb`` / ``pivot_error``).
        notes: Operator-facing explanation of the verdict.
        agent_id: Ligolo agent that hosts the redirector (viable plans only).
        redirector_host: The agent-segment host a victim connects back to; this
            is the ``callback_ip`` advertised in the bait UNC.
        callback_ip: Alias of ``redirector_host`` for callback call sites.
        listener_addr: ``host:port`` the agent binds in the target segment.
        redirect_addr: ``host:port`` local to the proxy the relay forwards to.
        bind_ip: The IP the LOCAL capture broker should bind for this capture.
        listener_port: The redirect port (default :445).
        bait_scheme: Transport of the advertised bait (``smb`` for viable plans).
    """

    applicable: bool
    viable: bool
    skip_reason: str | None = None
    notes: str = ""
    agent_id: int | None = None
    redirector_host: str | None = None
    callback_ip: str | None = None
    listener_addr: str | None = None
    redirect_addr: str | None = None
    bind_ip: str | None = None
    listener_port: int = DEFAULT_REDIRECT_PORT
    bait_scheme: str = "smb"


def _debug(message: str) -> None:
    """Emit one bracket-free pivot-capture diagnostic (recording-visible)."""

    print_info_debug(f"{_LOG}: {message}")


def _ligolo_service(shell: Any) -> Any | None:
    """Build a workspace-scoped Ligolo service, or ``None`` when unavailable."""

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if not workspace_dir:
        return None
    try:
        from adscan_internal.services.ligolo_service import (  # noqa: PLC0415
            LigoloProxyService,
        )

        domain = str(getattr(shell, "domain", "") or "").strip() or None
        return LigoloProxyService(workspace_dir=workspace_dir, current_domain=domain)
    except Exception as exc:  # noqa: BLE001 — best-effort; never raise into the caller
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _ip_in_route(target_ip: str, route: str) -> bool:
    """Return whether ``target_ip`` falls within a route prefix / bare IP hint."""

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


def _same_host(left: str, right: str) -> bool:
    """Best-effort equality for two host identifiers (IP or hostname)."""

    a = str(left or "").strip().casefold()
    b = str(right or "").strip().casefold()
    return bool(a) and a == b


def _tunnel_covers_target(record: dict[str, Any], target_ip: str) -> bool:
    """Return whether one tunnel record's routes/confirmed-targets cover a target."""

    routes = [str(r) for r in (record.get("routes") or [])]
    confirmed = [str(t) for t in (record.get("confirmed_targets") or [])]
    return any(_ip_in_route(target_ip, r) for r in routes) or any(
        _ip_in_route(target_ip, t) for t in confirmed
    )


def _redirector_host_for_record(record: dict[str, Any]) -> str:
    """Resolve the agent-segment host a victim connects back to for one tunnel."""

    host = str(record.get("pivot_host") or "").strip()
    if host:
        return host
    agent = record.get("agent")
    if isinstance(agent, dict):
        remote = str(agent.get("remote_addr") or "").strip()
        # Strip a trailing :port (IPv4 host:port; leave bare IPs / IPv6 as-is).
        if remote.count(":") == 1:
            return remote.split(":", 1)[0]
        return remote
    return ""


def _live_agent_ids(service: Any) -> set[int]:
    """Return the set of currently-connected Ligolo agent ids (best-effort)."""

    try:
        return {int(a.get("id")) for a in service.list_agents() if a.get("id") is not None}
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return set()


def _tcp_port_open(host: str, port: int, *, timeout: float = _PROBE_TIMEOUT_SECONDS) -> bool:
    """Return whether ``host:port`` accepts a TCP connection (routes via the kernel).

    The Ligolo TUN route is already in the kernel table, so a plain connect to a
    routed target-segment IP traverses the tunnel. A timeout / refusal means the
    port is not being served (the redirector CAN bind it); a successful connect
    means the host already serves that port (445 contention).
    """

    endpoint = str(host or "").strip()
    if not endpoint:
        return False
    try:
        with socket.create_connection((endpoint, int(port)), timeout=timeout):
            return True
    except OSError:
        return False
    except Exception as exc:  # noqa: BLE001 — a probe failure is treated as "closed"
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def plan_pivot_capture(
    shell: Any,
    target_ip: str,
    *,
    redirect_port: int = DEFAULT_REDIRECT_PORT,
) -> PivotCapturePlan:
    """Decide whether an inbound callback to ``target_ip`` can be captured via a pivot.

    Pure decision — no listener is created here. Honest-skip is the default: the
    function returns a non-viable plan (with a precise ``skip_reason`` / ``notes``)
    whenever a capture cannot be delivered, and NEVER raises.

    Args:
        shell: Active session shell (workspace, domain, egress cache).
        target_ip: The host the callback must reach back from.
        redirect_port: Port the redirector listener binds on the agent (:445).

    Returns:
        A :class:`PivotCapturePlan`. ``applicable=False`` when the target is not
        reached through a pivot (caller uses its direct callback IP).
    """

    try:
        vantage = resolve_egress_for_target(shell, target_ip)
    except Exception as exc:  # noqa: BLE001 — routing is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return PivotCapturePlan(
            applicable=False, viable=False, notes="egress resolution failed"
        )

    if vantage.vantage != "pivot":
        return PivotCapturePlan(
            applicable=False,
            viable=False,
            notes=f"target reached via {vantage.vantage} vantage, not a pivot",
        )

    marked_target = mark_sensitive(str(target_ip), "ip")
    service = _ligolo_service(shell)
    if service is None:
        _debug(f"no workspace/ligolo context to plan a pivot capture for {marked_target}")
        return PivotCapturePlan(
            applicable=True,
            viable=False,
            skip_reason="no_workspace",
            notes="no Ligolo workspace context to resolve a pivot redirector",
        )

    try:
        records = service.list_tunnel_records()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        _debug(f"ligolo tunnel state unavailable while planning capture for {marked_target}")
        return PivotCapturePlan(
            applicable=True,
            viable=False,
            skip_reason="ligolo_api_unavailable",
            notes="could not read the Ligolo tunnel state",
        )

    live_agent_ids = _live_agent_ids(service)

    # Collect candidate redirectors: a LIVE agent whose tunnel covers the target,
    # whose redirector host is known and is not the victim itself.
    candidates: list[tuple[int, str]] = []
    for record in records:
        if not isinstance(record, dict) or not _tunnel_covers_target(record, target_ip):
            continue
        agent = record.get("agent")
        if not isinstance(agent, dict):
            continue
        try:
            agent_id = int(agent.get("id"))
        except (TypeError, ValueError):
            continue
        if live_agent_ids and agent_id not in live_agent_ids:
            _debug(f"skipping agent {agent_id}: tunnel present but agent is not live")
            continue
        redirector_host = _redirector_host_for_record(record)
        if not redirector_host:
            _debug(f"skipping agent {agent_id}: no resolvable redirector host")
            continue
        if _same_host(redirector_host, target_ip):
            _debug(
                f"skipping agent {agent_id}: redirector host equals the victim "
                f"{marked_target} (cannot host a redirector on the target)"
            )
            continue
        if (agent_id, redirector_host) not in candidates:
            candidates.append((agent_id, redirector_host))

    if not candidates:
        _debug(f"no live pivot tunnel covers {marked_target}; capture via the pivot unavailable")
        return PivotCapturePlan(
            applicable=True,
            viable=False,
            skip_reason="no_pivot_route",
            notes="no live Ligolo tunnel covers this target segment",
        )

    # 445 contention: a redirector can only bind :redirect_port on a host that
    # does NOT already serve it. Probe each candidate through the tunnel.
    for agent_id, redirector_host in candidates:
        marked_host = mark_sensitive(str(redirector_host), "ip")
        if _tcp_port_open(redirector_host, redirect_port):
            _debug(
                f"redirector agent {agent_id} host {marked_host} already serves "
                f":{redirect_port} (SMB) — cannot host a :{redirect_port} redirector there"
            )
            continue
        listener_addr = f"0.0.0.0:{int(redirect_port)}"
        redirect_addr = f"{LOCAL_REDIRECT_HOST}:{int(redirect_port)}"
        _debug(
            f"viable pivot capture: agent {agent_id} host {marked_host} "
            f"listener {listener_addr} -> {redirect_addr}; advertise callback {marked_host}"
        )
        return PivotCapturePlan(
            applicable=True,
            viable=True,
            notes=(
                "capture-through-pivot: the Ligolo agent hosts a redirector on the "
                "target segment; the bait advertises the agent-segment host and the "
                "connection is relayed back to the local capture listener"
            ),
            agent_id=agent_id,
            redirector_host=redirector_host,
            callback_ip=redirector_host,
            listener_addr=listener_addr,
            redirect_addr=redirect_addr,
            bind_ip=PIVOT_BROKER_BIND_IP,
            listener_port=int(redirect_port),
            bait_scheme="smb",
        )

    _debug(
        f"every in-segment redirector for {marked_target} already serves "
        f":{redirect_port}; capture via a :{redirect_port} redirector is not possible"
    )
    return PivotCapturePlan(
        applicable=True,
        viable=False,
        skip_reason="redirector_serves_smb",
        notes=(
            f"every reachable in-segment redirector host already serves SMB on "
            f":{redirect_port}. Capturing through the pivot needs an alt-port "
            "WebDAV/HTTP icon bait (not yet automated) or a non-SMB redirector host "
            "in the target segment"
        ),
    )


def arm_planned_capture(shell: Any, plan: PivotCapturePlan) -> int | None:
    """Create the agent listener for a viable plan; return its id, or ``None``.

    Uses a before/after listener snapshot to resolve the new listener's numeric
    id (the create call only acknowledges, it does not return the id). Never
    raises — any failure logs + returns ``None`` so the caller honest-skips.
    """

    if not plan.viable or plan.agent_id is None or not plan.listener_addr or not plan.redirect_addr:
        return None
    service = _ligolo_service(shell)
    if service is None:
        _debug("cannot arm pivot capture: no Ligolo service context")
        return None
    try:
        before = {
            int(entry.get("listener_id"))
            for entry in service.list_agent_listeners()
            if int(entry.get("agent_id", -1)) == int(plan.agent_id)
        }
        service.add_agent_listener(
            agent_id=int(plan.agent_id),
            listener_addr=plan.listener_addr,
            redirect_addr=plan.redirect_addr,
        )
        after = [
            entry
            for entry in service.list_agent_listeners()
            if int(entry.get("agent_id", -1)) == int(plan.agent_id)
        ]
    except Exception as exc:  # noqa: BLE001 — arming failure must honest-skip, never crash
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        _debug(f"failed to arm pivot agent listener on agent {plan.agent_id}: {exc}")
        return None

    new_ids = [int(entry.get("listener_id")) for entry in after if int(entry.get("listener_id")) not in before]
    if not new_ids:
        _debug(
            f"pivot agent listener on agent {plan.agent_id} was requested but did not "
            "appear in the listener set (relay may have failed to bind on the agent)"
        )
        return None
    listener_id = new_ids[0]
    _debug(f"pivot agent listener armed: agent {plan.agent_id} listener {listener_id}")
    return listener_id


def teardown_planned_capture(shell: Any, plan: PivotCapturePlan, listener_id: int | None) -> None:
    """Remove a previously-armed agent listener. Best-effort; never raises."""

    if listener_id is None or plan.agent_id is None:
        return
    service = _ligolo_service(shell)
    if service is None:
        return
    try:
        service.delete_agent_listener(agent_id=int(plan.agent_id), listener_id=int(listener_id))
        _debug(f"pivot agent listener torn down: agent {plan.agent_id} listener {listener_id}")
    except Exception as exc:  # noqa: BLE001 — teardown is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        _debug(f"failed to tear down pivot agent listener {listener_id} on agent {plan.agent_id}: {exc}")


__all__ = [
    "DEFAULT_REDIRECT_PORT",
    "LOCAL_REDIRECT_HOST",
    "PIVOT_BROKER_BIND_IP",
    "PivotCapturePlan",
    "arm_planned_capture",
    "plan_pivot_capture",
    "teardown_planned_capture",
]
