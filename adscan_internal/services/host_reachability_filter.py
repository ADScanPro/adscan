"""Centralized pre-flight reachability filter for bulk-host operations.

Used by every CLI flow that runs an expensive auth/protocol operation across
many hosts (bulk SAM/LSA/LSASS dumps, local-admin reuse check, RDP login
sweep, WinRM access probe). Filters offline / port-closed hosts BEFORE the
caller spends auth budget on them.

Why a dedicated module instead of inlining ``tcp_probe_hosts`` at each caller:

  - **Single source of truth** for the reachable/offline classification and
    its premium UX summary line — every caller renders the same vocabulary.
  - **Testable in isolation** — the auth primitives stay clean; reachability
    logic does not bleed into ``check_smb_privilege_batch``, ``scan_rdp_hosts``
    or ``run_winrm_access_probe_sweep``.
  - **Centralized tuning** — concurrency/timeout defaults live in one place;
    raising them for corporate-scale engagements is a one-line change.

Architecture: this is the L2 layer in the three-layer pre-flight design.

  L1 — network_probe_service.tcp_probe_hosts (TCP primitive, bounded)
  L2 — host_reachability_filter (this module: split + UX)
  L3 — each CLI flow (orchestrates L2 then runs the auth-heavy operation)
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console

from adscan_internal import get_console
from adscan_internal.services.network_probe_service import (
    SERVICE_PROBE_PORTS,
    TCPProbeResult,
    tcp_probe_hosts,
)


# Visual tokens — match the existing tactical aesthetic used by dumps.py.
_ICE   = "#79C0FF"
_MUTED = "#8B949E"
_ACID  = "#7EE787"
_LAVA  = "#FF7B72"


@dataclass(frozen=True)
class ReachabilityFilterResult:
    """Outcome of filtering a host list by single-port TCP reachability."""

    port: int
    reachable: tuple[str, ...]
    offline: tuple[str, ...]
    elapsed_ms: float
    raw_results: dict[str, TCPProbeResult]

    @property
    def total(self) -> int:
        return len(self.reachable) + len(self.offline)

    @property
    def reachable_pct(self) -> float:
        if self.total == 0:
            return 0.0
        return 100.0 * len(self.reachable) / self.total


async def filter_reachable_hosts(
    hosts: list[str],
    port: int,
    *,
    timeout: float | None = None,
    max_concurrency: int | None = None,
) -> ReachabilityFilterResult:
    """Split ``hosts`` into reachable vs offline for ``port`` via TCP probe.

    ``timeout`` / ``max_concurrency`` default to the scan pacing
    (``probe.tcp_probe_hosts``: 3.0 s and 50 at the default level).

    Both ``closed`` (TCP RST) and ``filtered`` (timeout) collapse into
    ``offline`` here — for the auth-heavy callers the distinction does not
    change behavior (neither will accept SMB/RDP/WinRM auth). Callers that
    need the finer-grained classification can inspect ``raw_results``.
    """
    import time

    t0 = time.monotonic()
    probe_map = await tcp_probe_hosts(
        hosts, port, timeout=timeout, max_concurrency=max_concurrency
    )
    elapsed_ms = (time.monotonic() - t0) * 1000

    reachable: list[str] = []
    offline: list[str] = []
    for h in hosts:
        result = probe_map.get(h)
        if result is not None and result.status == "open":
            reachable.append(h)
        else:
            offline.append(h)

    return ReachabilityFilterResult(
        port=port,
        reachable=tuple(reachable),
        offline=tuple(offline),
        elapsed_ms=elapsed_ms,
        raw_results=probe_map,
    )


async def filter_reachable_hosts_for_service(
    hosts: list[str],
    service: str,
    *,
    timeout: float | None = None,
    max_concurrency: int | None = None,
) -> ReachabilityFilterResult:
    """Service-aware variant — uses the canonical port from SERVICE_PROBE_PORTS.

    Multi-port services (e.g. winrm 5985/5986) probe the primary port only;
    fallback ports are the auth layer's responsibility.
    """
    ports = SERVICE_PROBE_PORTS.get(service.lower(), [])
    if not ports:
        raise ValueError(f"Unknown service for reachability filter: {service!r}")
    return await filter_reachable_hosts(
        hosts, ports[0], timeout=timeout, max_concurrency=max_concurrency
    )


def print_reachability_summary(
    result: ReachabilityFilterResult,
    *,
    service_label: str | None = None,
    console: Console | None = None,
) -> None:
    """Render the standard one-line reachability summary in tactical style.

    Only prints when at least one host was offline — staying silent when all
    hosts are reachable keeps clean runs uncluttered.
    """
    if not result.offline:
        return

    target_console = console or get_console()
    svc = f"  [{_MUTED}]({service_label})[/{_MUTED}]" if service_label else ""
    target_console.print(
        f"  [{_MUTED}]◈  Reachability sweep:"
        f"  [bold {_ICE}]{len(result.reachable)}[/bold {_ICE}] reachable"
        f"  ·  [bold]{len(result.offline)}[/bold] offline (skipped)"
        f"  ·  [{_MUTED}]port {result.port}/tcp · {result.elapsed_ms:.0f}ms[/{_MUTED}]{svc}[/{_MUTED}]"
    )


def render_no_reachable_panel(
    result: ReachabilityFilterResult,
    *,
    operation_label: str,
    console: Console | None = None,
) -> None:
    """Render a clean Rich panel when 0 hosts are reachable."""
    from rich.panel import Panel

    target_console = console or get_console()
    target_console.print(
        Panel(
            f"[{_MUTED}]  All {result.total} target hosts are offline or filtering "
            f"port {result.port}/tcp.\n  {operation_label} cannot proceed.[/{_MUTED}]",
            title=f"[{_MUTED}]{operation_label} — No Reachable Targets[/{_MUTED}]",
            border_style=_MUTED,
            padding=(0, 1),
        )
    )


def filter_reachable_hosts_sync(
    hosts: list[str],
    port: int,
    *,
    timeout: float | None = None,
    max_concurrency: int | None = None,
) -> ReachabilityFilterResult:
    """Sync wrapper for callers that are not in an async context.

    Use the async ``filter_reachable_hosts`` from inside ``async def`` code;
    this wrapper exists for sync CLI handlers (e.g. ``cli/privileges.py``
    invoking the WinRM sweep through ``run_async_sync``).
    """
    from adscan_internal.services.async_bridge import run_async_sync

    return run_async_sync(
        filter_reachable_hosts(
            hosts, port, timeout=timeout, max_concurrency=max_concurrency
        )
    )


__all__ = (
    "ReachabilityFilterResult",
    "filter_reachable_hosts",
    "filter_reachable_hosts_for_service",
    "filter_reachable_hosts_sync",
    "print_reachability_summary",
    "render_no_reachable_panel",
)
