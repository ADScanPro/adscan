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
    PROBE_EXCLUDED,
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
    #: Hosts the engagement scope kept from being probed. Nothing was sent to
    #: them, so they are neither reachable nor offline: a caller reports them
    #: as outside the scope, never as down, not checked or access denied.
    excluded: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return len(self.reachable) + len(self.offline)

    @property
    def reachable_pct(self) -> float:
        if self.total == 0:
            return 0.0
        return 100.0 * len(self.reachable) / self.total


def scope_excluded_hosts(result: object) -> list[str]:
    """The hosts of a reachability result that the engagement scope kept out.

    What a sweep records as outside the scope after its liveness gate. Reads
    the result defensively (a result with no such field excluded nobody), so a
    caller can record them without knowing how the result was built.
    """
    return [str(host) for host in (getattr(result, "excluded", None) or ())]


async def filter_reachable_hosts(
    hosts: list[str],
    port: int,
    *,
    timeout: float | None = None,
    max_concurrency: int | None = None,
    scope_surface: str = "reachability_probe",
) -> ReachabilityFilterResult:
    """Split ``hosts`` into reachable vs offline for ``port`` via TCP probe.

    ``timeout`` / ``max_concurrency`` default to the scan pacing
    (``probe.tcp_probe_hosts``: 3.0 s and 50 at the default level).

    Engagement scope: the probe fan-out asks about each host right before its
    probe (``tcp_probe_hosts``). A host the scope keeps out is in ``excluded``,
    apart from ``offline``, and is recorded under ``scope_surface`` (the
    surface of the sweep this gate belongs to).

    Both ``closed`` (TCP RST) and ``filtered`` (timeout) collapse into
    ``offline`` here — for the auth-heavy callers the distinction does not
    change behavior (neither will accept SMB/RDP/WinRM auth). Callers that
    need the finer-grained classification can inspect ``raw_results``.
    """
    import time

    t0 = time.monotonic()
    probe_map = await tcp_probe_hosts(
        hosts, port, timeout=timeout, max_concurrency=max_concurrency, scope_surface=scope_surface
    )
    elapsed_ms = (time.monotonic() - t0) * 1000

    reachable: list[str] = []
    offline: list[str] = []
    excluded: list[str] = []
    for h in hosts:
        result = probe_map.get(h)
        if result is not None and result.status == "open":
            reachable.append(h)
        elif result is not None and result.status == PROBE_EXCLUDED:
            excluded.append(h)
        else:
            offline.append(h)

    return ReachabilityFilterResult(
        port=port,
        reachable=tuple(reachable),
        offline=tuple(offline),
        elapsed_ms=elapsed_ms,
        raw_results=probe_map,
        excluded=tuple(excluded),
    )


async def filter_reachable_hosts_for_service(
    hosts: list[str],
    service: str,
    *,
    timeout: float | None = None,
    max_concurrency: int | None = None,
    scope_surface: str = "reachability_probe",
) -> ReachabilityFilterResult:
    """Service-aware variant — uses the canonical port from SERVICE_PROBE_PORTS.

    Multi-port services (e.g. winrm 5985/5986) probe the primary port only;
    fallback ports are the auth layer's responsibility.
    """
    ports = SERVICE_PROBE_PORTS.get(service.lower(), [])
    if not ports:
        raise ValueError(f"Unknown service for reachability filter: {service!r}")
    return await filter_reachable_hosts(
        hosts, ports[0], timeout=timeout, max_concurrency=max_concurrency, scope_surface=scope_surface
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
    if not result.offline and not result.excluded:
        return

    target_console = console or get_console()
    svc = f"  [{_MUTED}]({service_label})[/{_MUTED}]" if service_label else ""
    outside = (
        f"  ·  [bold]{len(result.excluded)}[/bold] outside the engagement scope (not contacted)"
        if result.excluded
        else ""
    )
    target_console.print(
        f"  [{_MUTED}]◈  Reachability sweep:"
        f"  [bold {_ICE}]{len(result.reachable)}[/bold {_ICE}] reachable"
        f"  ·  [bold]{len(result.offline)}[/bold] offline (skipped){outside}"
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
    if result.excluded and not result.total:
        body = (
            f"  All {len(result.excluded)} target hosts are outside the engagement scope "
            "and were not contacted."
        )
    else:
        body = f"  All {result.total} target hosts are offline or filtering port {result.port}/tcp."
        if result.excluded:
            body += (
                f"\n  {len(result.excluded)} more are outside the engagement scope and were not contacted."
            )
    target_console.print(
        Panel(
            f"[{_MUTED}]{body}\n  {operation_label} cannot proceed.[/{_MUTED}]",
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
    scope_surface: str = "reachability_probe",
) -> ReachabilityFilterResult:
    """Sync wrapper for callers that are not in an async context.

    Use the async ``filter_reachable_hosts`` from inside ``async def`` code;
    this wrapper exists for sync CLI handlers (e.g. ``cli/privileges.py``
    invoking the WinRM sweep through ``run_async_sync``).
    """
    from adscan_internal.services.async_bridge import run_async_sync

    return run_async_sync(
        filter_reachable_hosts(
            hosts, port, timeout=timeout, max_concurrency=max_concurrency, scope_surface=scope_surface
        )
    )


__all__ = (
    "ReachabilityFilterResult",
    "filter_reachable_hosts",
    "scope_excluded_hosts",
    "filter_reachable_hosts_for_service",
    "filter_reachable_hosts_sync",
    "print_reachability_summary",
    "render_no_reachable_panel",
)
