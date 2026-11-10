"""Lightweight async TCP connectivity probe for pre-flight attack step validation.

Distinguishes three network states before committing to a full auth attempt:

  open     — TCP handshake completed: host up, port listening, service reachable.
  closed   — TCP RST received: host up, port explicitly refused (service down/disabled).
  filtered — Timeout or ICMP unreachable: host offline, firewall dropping, or no route.

Intentionally has zero dependency on the skelsec native stack — this is a raw
asyncio probe, not an AD protocol. asysocks is correct for protocol traffic that
needs to traverse proxies; a 3-second TCP check before auth does not.

Never raises. All exceptions are mapped to a ProbeStatus.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from dataclasses import dataclass, replace
from typing import Literal

from adscan_core.scan_pacing import active_pacing, component_pacing
from adscan_core.scan_pacing.pacing_consumers import consumer as _pacing_consumer
from adscan_core.scan_pacing.pacing_runtime import Outcome, RateLimiter, active_runtime


ProbeStatus = Literal["open", "closed", "filtered"]

# Per-service canonical port list (primary first).
SERVICE_PROBE_PORTS: dict[str, list[int]] = {
    "smb":   [445],
    "rdp":   [3389],
    "winrm": [5985, 5986],
    "mssql": [1433],
    "dcom":  [135],
    "ldap":  [389],
    "ldaps": [636],
    "kerberos": [88],
    "dns":   [53],
}

# BloodHound action → service key (for the blocked-gate advisory).
ACTION_TO_SERVICE: dict[str, str] = {
    "adminto":    "smb",
    "sqlaccess":  "mssql",
    "sqladmin":   "mssql",
    "canrdp":     "rdp",
    "canpsremote": "winrm",
    "executedcom": "dcom",
}


@dataclass(frozen=True)
class TCPProbeResult:
    host: str
    port: int
    status: ProbeStatus
    elapsed_ms: float


def _is_ip_literal(value: str) -> bool:
    """Return whether ``value`` is already an IP address (no DNS needed)."""
    try:
        ipaddress.ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


async def _resolve_candidate_ips(host: str, port: int) -> list[str]:
    """Return the unique IPs ``host`` resolves to, in resolution order.

    An IP literal resolves to itself. A hostname is expanded via
    ``getaddrinfo`` so a multi-homed name (several A/AAAA records) yields ALL
    of its addresses — the caller can then give each candidate its own connect
    budget. Returns ``[]`` when resolution fails, so the caller falls back to a
    direct connect on the original host string (unchanged legacy path).
    """
    if _is_ip_literal(host):
        return [host]
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception:  # noqa: BLE001 — resolution failure → let direct connect handle it
        return []
    seen: list[str] = []
    for info in infos:
        sockaddr = info[4] if len(info) > 4 else None
        candidate = str(sockaddr[0]) if sockaddr else ""
        if candidate and candidate not in seen:
            seen.append(candidate)
    return seen


async def _connect_probe(target: str, port: int, timeout: float) -> tuple[ProbeStatus, float]:
    """Single TCP connect attempt against ONE address. Never raises."""
    t0 = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout,
        )
        elapsed = (time.monotonic() - t0) * 1000
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return "open", elapsed
    except ConnectionRefusedError:
        return "closed", (time.monotonic() - t0) * 1000
    except (asyncio.TimeoutError, OSError, Exception):  # noqa: BLE001
        return "filtered", (time.monotonic() - t0) * 1000


def _select_reachable_probe(
    results: list[tuple[ProbeStatus, float]],
) -> tuple[ProbeStatus, float]:
    """Pick the reachable-candidate verdict from per-address probe results.

    Preference ``open`` > ``closed`` > ``filtered``: an ``open`` or ``closed``
    verdict came from an address that actually answered (SYN-ACK or RST), i.e.
    a reachable NIC — so it must outrank a ``filtered`` timeout from an
    unreachable secondary interface. Ties within a class take the fastest.
    """
    for wanted in ("open", "closed"):
        matching = [r for r in results if r[0] == wanted]
        if matching:
            return min(matching, key=lambda r: r[1])
    return results[0]


async def tcp_probe(
    host: str,
    port: int,
    *,
    timeout: float = 3.0,
) -> TCPProbeResult:
    """Probe a single TCP port. Never raises.

    Multi-homed hosts (a name resolving to several IPs where only one is
    reachable from the current vantage) are handled correctly: each resolved
    address gets its OWN ``timeout`` budget and they are probed concurrently,
    so an unreachable secondary interface (e.g. an internal-only NIC advertised
    in DNS alongside a routable address) can never starve a reachable candidate
    within one shared budget. The verdict is the reachable candidate's (open >
    closed > filtered). A single-address host or IP literal keeps the original
    direct-connect behavior.
    """
    candidates = await _resolve_candidate_ips(host, port)
    if len(candidates) > 1:
        results = await asyncio.gather(
            *(_connect_probe(ip, port, timeout) for ip in candidates)
        )
        status, elapsed = _select_reachable_probe(list(results))
        return TCPProbeResult(host=host, port=port, status=status, elapsed_ms=elapsed)
    target = candidates[0] if candidates else host
    status, elapsed = await _connect_probe(target, port, timeout)
    return TCPProbeResult(host=host, port=port, status=status, elapsed_ms=elapsed)


async def tcp_probe_multi(
    host: str,
    ports: list[int],
    *,
    timeout: float = 3.0,
) -> TCPProbeResult:
    """Probe multiple ports — returns first open result, otherwise the last result.

    Sequential: short-circuits as soon as one port is open. Use this when probing
    fallback ports of the same service (e.g. WinRM 5985 → 5986).
    """
    result = TCPProbeResult(host=host, port=ports[0] if ports else 0, status="filtered", elapsed_ms=0)
    for port in ports:
        result = await tcp_probe(host, port, timeout=timeout)
        if result.status == "open":
            return result
    return result


async def tcp_probe_batch(
    host: str,
    ports: list[int],
    *,
    timeout: float = 3.0,
) -> dict[int, TCPProbeResult]:
    """Probe many ports concurrently against ONE host. Returns one result per port.

    Use this when probing distinct services in parallel (e.g. checking 53/389/445
    on a DC at once instead of three sequential 2s waits).
    """
    if not ports:
        return {}
    results = await asyncio.gather(
        *(tcp_probe(host, port, timeout=timeout) for port in ports)
    )
    return {r.port: r for r in results}


async def tcp_probe_hosts(
    hosts: list[str],
    port: int,
    *,
    timeout: float | None = None,
    max_concurrency: int | None = None,
) -> dict[str, TCPProbeResult]:
    """Probe ONE port across MANY hosts with bounded concurrency.

    The bounded semaphore is mandatory at scale: 1000 simultaneous open sockets
    would exhaust file-descriptor limits (default 1024) and saturate kernel TCP
    buffers. ``max_concurrency=50`` is ~2× the auth concurrency of 20 because
    the per-socket cost is ~50× lower (no NTLM/Kerberos handshake, no protocol
    negotiation), so the optimal probe parallelism is higher.

    Returns a mapping ``host -> TCPProbeResult`` preserving order via dict
    insertion semantics (Python 3.7+).

    ``timeout`` / ``max_concurrency`` default to the scan pacing
    (``probe.tcp_probe_hosts``: 3.0 s and 50 at the default level). Each probe
    takes a token of the scan-wide request rate and feeds the strain safeguard
    (an answer, open or refused, is healthy; a timeout is not).
    """
    if not hosts:
        return {}
    pacing = component_pacing(active_pacing(), "probe.tcp_probe_hosts")
    probe_timeout = pacing["timeout_s"] if timeout is None else timeout
    runtime = active_runtime()
    sem = runtime.semaphore(
        pacing["max_concurrency"] if max_concurrency is None else max_concurrency
    )

    async def _bounded(h: str) -> TCPProbeResult:
        async with sem:
            await runtime.before_op(h)
            result = await tcp_probe(h, port, timeout=probe_timeout)
        runtime.record(
            h,
            Outcome.TIMEOUT if result.status == "filtered" else Outcome.OK,
            result.elapsed_ms / 1000.0 if result.status == "open" else None,
        )
        return result

    results = await asyncio.gather(*(_bounded(h) for h in hosts))
    return {r.host: r for r in results}


def action_to_service_ports(action: str) -> list[int]:
    """Map a BloodHound action name to its probe ports. Returns [] if unknown."""
    service = ACTION_TO_SERVICE.get(action.lower().strip())
    if not service:
        return []
    return SERVICE_PROBE_PORTS.get(service, [])


# --- In-process TCP connect-scan (Windows nmap fallback) --------------------
#
# On Windows nmap is not bundled AND a SYN scan (``-sS``) needs Npcap + admin,
# which a hardened install-nothing host cannot provide. This connect scan is the
# Windows-only replacement — an unprivileged asyncio TCP fan-out that returns
# EXACTLY the shape ``_parse_gnmap_open_ports`` returns. Linux keeps nmap ``-sS``
# unchanged (raw-SYN is faster at 5k-host scale). Mirrors the massdns->dnspython
# and hashcat->John Windows-only fallbacks already in the codebase.

# A single Windows connect scan must never expand an unbounded CIDR into millions
# of targets; cap the host set so a fat expression degrades gracefully.
_CONNECT_SCAN_HOST_CAP = 4096

# Windows connect-scan pacing — SAFE BY DEFAULT, not fastest.
#
# This scan is the Windows-only replacement for nmap -sS (see the block above).
# Reliability is proven — at concurrency >=100 it finds every open port with 0
# missed (validated on the GOAD /24 against ground truth). What matters for the
# DEFAULT is SAFETY: ADscan runs against real enterprise networks that carry
# EDR/IPS/IDS and middleboxes, and a flat fan-out of thousands of simultaneous
# SYNs is exactly what an IPS flags as a scan and what can exhaust a small
# device's connection table ("tumbar equipos/red"). So the default is calibrated
# to nmap's own industry-tuned "polite enough for production" posture (-T3), NOT
# to a wall-clock optimum. An operator who OWNS the network and wants speed opts
# in via the env overrides below; the safe default is never the aggressive one.
#
# The earlier 2000-concurrency "measured optimum" was a SPEED number and is
# rejected as a default for the reason above (it remains reachable via the env
# override for owned networks).
#
# The values live in the scan-pacing SSOT (consumer ``portscan.windows_connect``);
# these names are the default-level values, kept for the call sites and tests
# that import them.
_WINDOWS_CONNECT = _pacing_consumer("portscan.windows_connect")
_CONNECT_SCAN_SAFE_CONCURRENCY = _WINDOWS_CONNECT.param("concurrency").default  # 64, ~nmap -T3
_CONNECT_SCAN_SAFE_PER_HOST = _WINDOWS_CONNECT.param("per_host").default  # 8 per host
_CONNECT_SCAN_CONCURRENCY_FLOOR = _WINDOWS_CONNECT.param("backoff_floor").default  # 8
# Adaptive backoff: if the rolling share of connect attempts that TIME OUT
# (status "filtered" — the signal a host/middlebox is dropping under load, not a
# clean RST) crosses this fraction over a measurement window, halve the effective
# global concurrency. Eases off instead of plowing ahead when the network chokes.
_CONNECT_SCAN_BACKOFF_TIMEOUT_RATE = _WINDOWS_CONNECT.param("backoff_timeout_rate").default
_CONNECT_SCAN_BACKOFF_WINDOW = _WINDOWS_CONNECT.param("backoff_window").default  # attempts per window

# Back-compat public constants (the Windows call sites import these). The
# concurrency now resolves to the SAFE default, overridable by env.
CONNECT_SCAN_WINDOWS_TIMEOUT = _WINDOWS_CONNECT.param("timeout_s").default


def resolve_windows_scan_concurrency() -> int:
    """Global in-flight cap for the Windows connect scan, from the scan pacing."""
    return int(component_pacing(active_pacing(), "portscan.windows_connect")["concurrency"])


def resolve_windows_scan_per_host() -> int:
    """Per-host in-flight cap for the Windows connect scan, from the scan pacing."""
    return int(component_pacing(active_pacing(), "portscan.windows_connect")["per_host"])


# Back-compat alias: the value the Windows call sites pass as ``concurrency=``.
# Resolved at import; env override is read once at process start (a scan is one
# process, so re-reading per call would only matter to tests, which set it before
# import or call resolve_* directly).
CONNECT_SCAN_WINDOWS_CONCURRENCY = resolve_windows_scan_concurrency()


def expand_host_expression(expression: str, *, max_hosts: int = _CONNECT_SCAN_HOST_CAP) -> list[str]:
    """Expand an nmap-style host expression into individual connect targets.

    Handles the forms the three nmap call sites actually pass: a single IP, a
    single hostname, a whitespace/comma-separated list, and a CIDR (whose usable
    hosts are enumerated, capped at ``max_hosts``). Unknown forms (e.g. an nmap
    dash-range) fall through as an opaque token so the caller can still probe it
    verbatim. Order is preserved and duplicates are dropped.
    """
    ordered: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        token = str(value or "").strip()
        if token and token not in seen:
            seen.add(token)
            ordered.append(token)

    for raw in re.split(r"[\s,]+", str(expression or "").strip()):
        token = raw.strip()
        if not token:
            continue
        if "/" in token:
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                _add(token)
                continue
            hosts_iter = network.hosts() if network.num_addresses > 2 else iter(network)
            for host in hosts_iter:
                if len(ordered) >= max_hosts:
                    return ordered
                _add(str(host))
            continue
        _add(token)
        if len(ordered) >= max_hosts:
            return ordered[:max_hosts]
    return ordered


@dataclass(frozen=True)
class ScanPacing:
    """Pacing/safety policy for an async TCP connect scan — reusable everywhere.

    A single knob-set so any call site (the Windows port scan today, a future
    service-reachability sweep, a targeted re-probe of a few ports) uses ONE
    scanner with its own safety envelope, instead of hand-rolling a semaphore.

    Attributes:
        concurrency: global in-flight connect cap. Lower = safer/quieter.
        per_host: max simultaneous connects to a SINGLE host — stops a scan from
            fanning out every port of one box at once (host-stress / IPS trigger).
            ``0`` disables the per-host cap.
        timeout: per-connect timeout in seconds (also the "filtered" threshold).
        adaptive_backoff: when True, halve the effective global concurrency (down
            to ``floor``) if the rolling connect-timeout rate crosses
            ``backoff_timeout_rate`` over a ``backoff_window`` of attempts — the
            network is choking, so ease off instead of plowing ahead.
        floor: adaptive backoff never drops effective concurrency below this.
        backoff_timeout_rate: timeout fraction over a window that triggers a halving.
        backoff_window: number of attempts per backoff evaluation window.

    ``ScanPacing.safe()`` is the production-polite default (calibrated to nmap's
    -T3 posture); the ``fast`` pacing level is the opt-in owned-network profile.
    """

    concurrency: int = _CONNECT_SCAN_SAFE_CONCURRENCY
    per_host: int = _CONNECT_SCAN_SAFE_PER_HOST
    timeout: float = CONNECT_SCAN_WINDOWS_TIMEOUT
    adaptive_backoff: bool = True
    floor: int = _CONNECT_SCAN_CONCURRENCY_FLOOR
    backoff_timeout_rate: float = _CONNECT_SCAN_BACKOFF_TIMEOUT_RATE
    backoff_window: int = _CONNECT_SCAN_BACKOFF_WINDOW

    @classmethod
    def safe(cls) -> ScanPacing:
        """The scan pacing's connect-scan policy (production-polite at the default level)."""
        pacing = component_pacing(active_pacing(), "portscan.windows_connect")
        concurrency = max(1, int(pacing["concurrency"]))
        return cls(
            concurrency=concurrency,
            per_host=int(pacing["per_host"]),
            timeout=float(pacing["timeout_s"]),
            floor=min(int(pacing["backoff_floor"]), concurrency),
            backoff_timeout_rate=float(pacing["backoff_timeout_rate"]),
            backoff_window=int(pacing["backoff_window"]),
        )

    @classmethod
    def aggressive(cls, concurrency: int) -> ScanPacing:
        """Programmatic owned-network profile: no per-host cap, no backoff.

        No product path uses it: an operator who wants speed picks the ``fast``
        scan-pacing level, which keeps a per-host cap and the backoff. The
        caller states the concurrency explicitly.
        """
        return cls(
            concurrency=max(1, concurrency),
            per_host=0,
            adaptive_backoff=False,
        )


class _AdaptiveGate:
    """Concurrency gate that can tighten under a rising connect-timeout rate.

    Wraps a global semaphore plus optional per-host semaphores. When adaptive
    backoff is on, it tracks the timeout ("filtered") rate over a rolling window
    and, on a spike, permanently retires permits (halving toward the floor) by
    holding them — so genuinely-choking networks get a lighter touch without ever
    stalling the scan. Best-effort: never raises into the scan.
    """

    def __init__(self, pacing: ScanPacing) -> None:
        self._pacing = pacing
        self._global = asyncio.Semaphore(max(1, pacing.concurrency))
        self._effective = max(1, pacing.concurrency)
        self._retired = 0  # permits held back by backoff
        self._per_host: dict[str, asyncio.Semaphore] = {}
        self._window_attempts = 0
        self._window_timeouts = 0
        self._lock = asyncio.Lock()

    def _host_sem(self, host: str) -> asyncio.Semaphore | None:
        if self._pacing.per_host <= 0:
            return None
        sem = self._per_host.get(host)
        if sem is None:
            sem = asyncio.Semaphore(self._pacing.per_host)
            self._per_host[host] = sem
        return sem

    async def record(self, status: ProbeStatus) -> None:
        """Feed one probe outcome; may retire permits when the network chokes."""
        if not self._pacing.adaptive_backoff:
            return
        async with self._lock:
            self._window_attempts += 1
            if status == "filtered":
                self._window_timeouts += 1
            if self._window_attempts < self._pacing.backoff_window:
                return
            rate = self._window_timeouts / max(1, self._window_attempts)
            self._window_attempts = 0
            self._window_timeouts = 0
            if rate < self._pacing.backoff_timeout_rate:
                return
            target = max(self._pacing.floor, self._effective // 2)
            to_retire = self._effective - target
            for _ in range(to_retire):
                # Acquire-and-hold: shrink the live permit pool without deadlock.
                try:
                    await asyncio.wait_for(self._global.acquire(), timeout=0.001)
                    self._retired += 1
                except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                    break
            self._effective = self._pacing.concurrency - self._retired


async def connect_scan_open_ports(
    hosts: list[str],
    ports: list[int],
    *,
    timeout: float | None = None,
    concurrency: int | None = None,
    pacing: ScanPacing | None = None,
) -> dict[str, set[int]]:
    """Async TCP connect-scan over ``hosts`` x ``ports``. Never raises.

    Returns ``{host: {open_port, ...}}`` for hosts with at least one open port —
    the same shape (and ``--open`` semantics) as ``_parse_gnmap_open_ports``, so
    a caller can substitute this for the nmap+gnmap path with no downstream
    change.

    Pacing/safety is governed by a :class:`ScanPacing` policy (default
    :meth:`ScanPacing.safe`): a global in-flight cap, a per-host cap, and optional
    adaptive backoff. ``timeout``/``concurrency`` are kept as back-compat scalar
    overrides — when given they layer onto the resolved pacing — so existing call
    sites keep working. On total failure returns ``{}``.
    """
    if not hosts or not ports:
        return {}

    resolved = pacing or ScanPacing.safe()
    if concurrency is not None:
        resolved = replace(resolved, concurrency=max(1, concurrency))
    if timeout is not None:
        resolved = replace(resolved, timeout=timeout)

    results: dict[str, set[int]] = {}
    nmap_pacing = component_pacing(active_pacing(), "portscan.nmap")
    # Same port-scan knobs the Linux nmap path gets (--max-rate / --scan-delay);
    # both are unset at the default level, so the probe loop is unchanged there.
    packet_rate = RateLimiter(nmap_pacing["max_rate_pps"])
    scan_delay_s = float(nmap_pacing["scan_delay_ms"] or 0) / 1000.0
    host_next_at: dict[str, float] = {}

    async def _pace(host: str) -> None:
        await packet_rate.acquire()
        if scan_delay_s:
            now = time.monotonic()
            start = max(now, host_next_at.get(host, now))
            host_next_at[host] = start + scan_delay_s
            if start > now:
                await asyncio.sleep(start - now)

    try:
        gate = _AdaptiveGate(resolved)

        async def _probe(host: str, port: int) -> None:
            host_sem = gate._host_sem(host)
            async with gate._global:
                if host_sem is not None:
                    async with host_sem:
                        await _pace(host)
                        status, _elapsed = await _connect_probe(
                            host, port, resolved.timeout
                        )
                else:
                    await _pace(host)
                    status, _elapsed = await _connect_probe(
                        host, port, resolved.timeout
                    )
            if status == "open":
                results.setdefault(host, set()).add(port)
            await gate.record(status)

        await asyncio.gather(
            *(_probe(host, port) for host in hosts for port in ports)
        )
    except Exception:  # noqa: BLE001 — a connect scan must never break the flow
        return {host: ports_set for host, ports_set in results.items() if ports_set}
    return {host: ports_set for host, ports_set in results.items() if ports_set}


def connect_scan_open_ports_sync(
    hosts: list[str],
    ports: list[int],
    *,
    timeout: float | None = None,
    concurrency: int | None = None,
    pacing: ScanPacing | None = None,
) -> dict[str, set[int]]:
    """Synchronous wrapper around :func:`connect_scan_open_ports`."""
    from adscan_internal.services.async_bridge import run_async_sync

    try:
        return run_async_sync(
            connect_scan_open_ports(
                hosts,
                ports,
                timeout=timeout,
                concurrency=concurrency,
                pacing=pacing,
            )
        )
    except Exception:  # noqa: BLE001 — never raise into the sync caller
        return {}
