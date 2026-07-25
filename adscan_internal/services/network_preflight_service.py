"""Network preflight primitives shared by start and DNS flows.

This module is the **sync entry point** for route + TCP reachability checks.
The TCP probe semantics are owned by ``network_probe_service`` (async); this
module is a thin sync facade plus the route-assessment helpers that depend on
the host's ``run_command`` shell.

Single source of truth for TCP probing: ``network_probe_service.tcp_probe``.
Use it directly from async code; use this module from sync CLI flows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
import ipaddress
import platform
import re
import shlex

from adscan_internal import telemetry
from adscan_internal.services.async_bridge import run_async_sync
from adscan_internal.services.network_probe_service import (
    tcp_probe,
    tcp_probe_batch,
)
from adscan_core.rich_output import print_exception


# Canonical TCP port set for judging whether a target IP is a reachable DC.
#
# A hardened corporate DC routinely firewalls plain LDAP (389) and DNS-over-TCP
# (53) while still exposing Kerberos (88) and LDAPS (636) — those two are exactly
# what a fully scannable DC keeps open when the softer ports are blocked. Probing
# only 53/389/445 structurally false-negatives such a DC and aborts a scan the DC
# would accept. The reachability verdict is ANY-port-open (a DC exposing only
# 88+636 is fully scannable), so widening the set never causes a false abort — it
# only recovers DCs the narrower set missed. Both the `start` preflight and the
# `doctor` connectivity check consume this constant so they never drift apart.
DC_REACHABILITY_TCP_PORTS: tuple[int, ...] = (53, 88, 389, 445, 636)

# Probe budget for the DC-reachability check. Tied to the auth path's connect
# budget (~5s) rather than a fast-LAN default: over a VPN a single TCP handshake
# is ~0.6-0.9s at 300ms RTT, and a 2s budget false-negatived a port (445) that
# the posture probe reached comfortably at ~5s. See the ADscan AD-constraints
# checklist § 7bis (VPN latency) — never tune this to a same-subnet lab.
DC_REACHABILITY_TIMEOUT_SECONDS: float = 5.0


class NetworkPreflightHost(Protocol):
    """Protocol for host objects that can execute shell commands."""

    def run_command(self, command: str, **kwargs: Any):  # noqa: ANN401
        """Execute a command and return a CompletedProcess-like object."""


@dataclass(frozen=True)
class RouteAssessment:
    """Result of evaluating route presence for one target IP."""

    ok: bool
    reason: str
    route_interface: str | None = None
    source_ip: str | None = None
    raw_line: str | None = None


@dataclass(frozen=True)
class TargetReachabilityAssessment:
    """Result of evaluating route + TCP port reachability for one target IP.

    ``closed_ports`` and ``filtered_ports`` are kept distinct on purpose:
    a TCP RST (``closed``) is a definitive "nothing is listening here"
    answer, while a timeout/ICMP-unreachable (``filtered``) is inconclusive
    ("my probe budget expired"). Consumers that must not infer a negative
    verdict from a transient timeout (observe-vs-infer doctrine) rely on
    this distinction. ``closed_ports`` therefore contains ONLY explicitly
    refused ports; filtered/timeout ports live in ``filtered_ports``.
    """

    target_ip: str
    route: RouteAssessment
    open_ports: tuple[int, ...]
    closed_ports: tuple[int, ...]
    filtered_ports: tuple[int, ...] = ()

    def is_port_open(self, port: int) -> bool:
        """Return whether a specific TCP port is reachable."""
        return port in self.open_ports

    def is_port_filtered(self, port: int) -> bool:
        """Return whether a port was inconclusive (timeout/filtered, not RST)."""
        return port in self.filtered_ports


def get_interface_ipv4_addresses(interface: str) -> list[str]:
    """Return IPv4 addresses configured on an interface."""
    if not interface:
        return []
    try:
        import netifaces

        addresses = netifaces.ifaddresses(interface)
        inet_addresses = addresses.get(netifaces.AF_INET) or []
        values: list[str] = []
        for entry in inet_addresses:
            candidate = str(entry.get("addr", "")).strip()
            if not candidate:
                continue
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            values.append(candidate)
        return values
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []


# Substrings that mean "the route tool itself could not run" (binary absent),
# as opposed to "the tool ran and reported no route". A missing command must
# NEVER be mapped to ``no_route`` — a false negative dead-ends an operator whose
# connection is actually fine. Consumers treat the ``route_command_failed`` /
# ``unsupported_platform`` states as non-blocking and fall through to the
# authoritative TCP-port probe instead.
_ROUTE_TOOL_MISSING_MARKERS: tuple[str, ...] = (
    "not found",
    "no such file",
    "command not found",
    "permission denied",
)


def assess_route_to_target(
    host: NetworkPreflightHost,
    *,
    target_ip: str,
    expected_interface: str | None = None,
) -> RouteAssessment:
    """Assess whether the host has a usable route to a target IP.

    The route probe is platform-specific: Linux uses ``ip route get`` (iproute2),
    macOS/BSD uses ``route -n get`` — ``ip`` does not exist on Darwin, so running
    it there always fails and would be misread as ``no_route``. On any other
    platform (or when the route tool is genuinely absent) this returns a distinct
    non-blocking state (``unsupported_platform`` / ``route_command_failed``,
    ``ok=True``) rather than asserting ``no_route``: a false "no route from local
    interfaces" verdict is worse than "could not verify routing here", and the
    downstream TCP-port reachability probe is the authoritative signal anyway.
    """
    system = platform.system()
    if system == "Darwin":
        return _assess_route_to_target_bsd(
            host, target_ip=target_ip, expected_interface=expected_interface
        )
    if system == "Linux":
        return _assess_route_to_target_linux(
            host, target_ip=target_ip, expected_interface=expected_interface
        )
    # Unknown platform (e.g. Windows host_process mode): we have no vetted route
    # command. Do not assert no_route — return the non-blocking "could not verify"
    # state so consumers rely on the TCP probe.
    return RouteAssessment(ok=True, reason="unsupported_platform")


def _assess_route_to_target_linux(
    host: NetworkPreflightHost,
    *,
    target_ip: str,
    expected_interface: str | None = None,
) -> RouteAssessment:
    """Assess route presence on Linux via ``ip -4 route get``."""
    route_cmd = f"ip -4 route get {shlex.quote(target_ip)}"
    result = host.run_command(route_cmd, timeout=20, ignore_errors=True)
    if result is None:
        return RouteAssessment(ok=True, reason="route_command_failed")

    output = "\n".join(
        line
        for line in ((result.stdout or "") + "\n" + (result.stderr or "")).splitlines()
        if line.strip()
    )
    first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    lowered = first_line.lower()
    combined_lowered = output.lower()
    # iproute2 absent (should not happen on Linux, but be robust): treat as
    # unverifiable, never as no_route.
    if result.returncode != 0 and any(
        marker in combined_lowered for marker in _ROUTE_TOOL_MISSING_MARKERS
    ):
        return RouteAssessment(ok=True, reason="route_command_failed", raw_line=first_line or None)
    if (
        result.returncode != 0
        or "unreachable" in lowered
        or "prohibit" in lowered
        or "blackhole" in lowered
    ):
        return RouteAssessment(
            ok=False,
            reason="no_route",
            raw_line=first_line or None,
        )

    route_interface = None
    source_ip = None
    dev_match = re.search(r"\bdev\s+(\S+)", first_line)
    if dev_match:
        route_interface = dev_match.group(1)
    src_match = re.search(r"\bsrc\s+(\S+)", first_line)
    if src_match:
        source_ip = src_match.group(1)

    return _finalize_route_assessment(
        route_interface=route_interface,
        source_ip=source_ip,
        expected_interface=expected_interface,
        raw_line=first_line or None,
    )


def _assess_route_to_target_bsd(
    host: NetworkPreflightHost,
    *,
    target_ip: str,
    expected_interface: str | None = None,
) -> RouteAssessment:
    """Assess route presence on macOS/BSD via ``route -n get``.

    BSD ``route`` has no ``src`` field, so the source IP is recovered from the
    resolved interface via ``netifaces`` (the same source used by
    ``get_interface_ipv4_addresses``).
    """
    route_cmd = f"route -n get {shlex.quote(target_ip)}"
    result = host.run_command(route_cmd, timeout=20, ignore_errors=True)
    if result is None:
        return RouteAssessment(ok=True, reason="route_command_failed")

    combined = (result.stdout or "") + "\n" + (result.stderr or "")
    combined_lowered = combined.lower()
    first_line = next((line.strip() for line in combined.splitlines() if line.strip()), "")
    # ``route`` binary genuinely unavailable → cannot verify, do not assert no_route.
    if any(marker in combined_lowered for marker in _ROUTE_TOOL_MISSING_MARKERS):
        return RouteAssessment(ok=True, reason="route_command_failed", raw_line=first_line or None)
    # The command ran and reported the destination is unroutable.
    if result.returncode != 0 or "not in table" in combined_lowered:
        return RouteAssessment(ok=False, reason="no_route", raw_line=first_line or None)

    route_interface = None
    iface_match = re.search(r"^\s*interface:\s*(\S+)", combined, re.MULTILINE)
    if iface_match:
        route_interface = iface_match.group(1)

    source_ip = None
    if route_interface:
        addresses = get_interface_ipv4_addresses(route_interface)
        if addresses:
            source_ip = addresses[0]

    return _finalize_route_assessment(
        route_interface=route_interface,
        source_ip=source_ip,
        expected_interface=expected_interface,
        raw_line=first_line or None,
    )


def _finalize_route_assessment(
    *,
    route_interface: str | None,
    source_ip: str | None,
    expected_interface: str | None,
    raw_line: str | None,
) -> RouteAssessment:
    """Build the final ``ok`` RouteAssessment, flagging an interface mismatch."""
    if expected_interface and route_interface and route_interface != expected_interface:
        return RouteAssessment(
            ok=True,
            reason="route_interface_mismatch",
            route_interface=route_interface,
            source_ip=source_ip,
            raw_line=raw_line,
        )
    return RouteAssessment(
        ok=True,
        reason="route_ok",
        route_interface=route_interface,
        source_ip=source_ip,
        raw_line=raw_line,
    )


def is_tcp_port_open(host: str, port: int, *, timeout_seconds: float = 2.0) -> bool:
    """Return True when a TCP port is reachable.

    Sync wrapper over the canonical async ``tcp_probe``. From async code, call
    ``tcp_probe`` directly to avoid the thread-pool detour built into
    ``run_async_sync``.
    """
    result = run_async_sync(tcp_probe(host, port, timeout=timeout_seconds))
    return result.status == "open"


def assess_target_reachability(
    host: NetworkPreflightHost,
    *,
    target_ip: str,
    expected_interface: str | None = None,
    tcp_ports: tuple[int, ...] = (53,),
    timeout_seconds: float = 2.0,
) -> TargetReachabilityAssessment:
    """Assess route and TCP port reachability for a target IP.

    Port probes run concurrently — checking N ports costs ~one timeout window,
    not N. Probing 53/389/445 on a slow target now completes in ~timeout
    seconds instead of ~3*timeout.
    """
    route = assess_route_to_target(
        host, target_ip=target_ip, expected_interface=expected_interface
    )
    if not tcp_ports:
        return TargetReachabilityAssessment(
            target_ip=target_ip,
            route=route,
            open_ports=(),
            closed_ports=(),
            filtered_ports=(),
        )
    batch = run_async_sync(
        tcp_probe_batch(target_ip, list(tcp_ports), timeout=timeout_seconds)
    )
    open_ports = tuple(sorted(p for p, r in batch.items() if r.status == "open"))
    closed_ports = tuple(sorted(p for p, r in batch.items() if r.status == "closed"))
    filtered_ports = tuple(
        sorted(p for p, r in batch.items() if r.status not in ("open", "closed"))
    )
    return TargetReachabilityAssessment(
        target_ip=target_ip,
        route=route,
        open_ports=open_ports,
        closed_ports=closed_ports,
        filtered_ports=filtered_ports,
    )
