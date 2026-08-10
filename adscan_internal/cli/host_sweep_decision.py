"""Post-stop decision prompt for the operator early-stop of the SMB host sweep.

When the operator presses ``Ctrl+C`` during the per-host SMB enrichment sweep,
the panic-proof handler in
:mod:`adscan_internal.services.cooperative_cancellation` requests a cooperative
stop and returns; it NEVER exits ADscan. Exiting, continuing, or stopping is an
EXPLICIT choice the operator makes here, at the call site, AFTER the sweep has
returned and its ``LiveSession`` alt-screen has popped, so rendering a normal
interactive prompt is safe.

Why a prompt and not a keystroke. Field forensics showed operators MASH
``Ctrl+C`` in a panic (one real session logged nine "Shutdown already in
progress" lines). A design that maps any keystroke to "exit" fails a panicking
human: they do not count, they mash. So this prompt ABSORBS the mashing —
``Ctrl+C`` inside it is a no-op that just redraws the prompt (the centralized
``questionary_select_index`` helper returns ``None`` on ``KeyboardInterrupt``,
and the loop here re-renders rather than falling through to any destructive
default). The ONLY way to exit is to deliberately choose "Exit ADscan".

Non-interactive (``adscan ci``). No prompt is ever shown — the platform stops
the sweep via the cross-process sentinel and honours the configured host cap.
The stop-and-continue proceeds with the partial data, never blocking.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core.output import questionary_select_index
from adscan_core.rich_output import mark_sensitive, print_info_debug, print_panel
from adscan_internal.interaction import is_non_interactive
from adscan_internal.services.collector.scale_gate import (
    estimate_sweep_seconds,
)
from adscan_core.tui.progress_dashboard import format_eta

# The three explicit outcomes of the decision prompt. ``exit`` is the ONLY path
# that ends the run, and it is only ever reached by a deliberate menu choice.
DECISION_CONTINUE = "continue"
DECISION_STOP = "stop"
DECISION_EXIT = "exit"


@dataclass(frozen=True)
class HostSweepStopCoverage:
    """The X-of-Y host coverage at the moment of an operator early-stop.

    Built from the collector's ``timing.host_coverage`` block (see
    :mod:`adscan_internal.services.collector.orchestrator`). ``swept`` is how
    many hosts were enriched before the stop, ``total`` the reachable set,
    ``remaining`` the balance still to enrich.
    """

    swept: int
    total: int
    remaining: int

    @property
    def percent(self) -> int:
        """Whole-percent of the reachable set enriched so far (0 when unknown)."""
        if self.total <= 0:
            return 0
        return max(0, min(100, round(self.swept * 100 / self.total)))


def coverage_from_timing(host_coverage: Any) -> HostSweepStopCoverage | None:
    """Extract the stop coverage from a ``timing.host_coverage`` dict.

    Returns ``None`` when the block is absent or does not describe an operator
    early-stop (a full sweep, a proactive scale-gate cap/skip, or a config cap
    is not an early-stop and gets no decision prompt).
    """
    if not isinstance(host_coverage, dict):
        return None
    if host_coverage.get("reason") != "early_stop":
        return None
    try:
        total = int(host_coverage.get("hosts_total", 0) or 0)
        swept = int(host_coverage.get("hosts_swept", 0) or 0)
        remaining = int(
            host_coverage.get("hosts_remaining", max(0, total - swept)) or 0
        )
    except (TypeError, ValueError):
        return None
    return HostSweepStopCoverage(swept=swept, total=total, remaining=remaining)


def _render_decision_panel(domain: str, coverage: HostSweepStopCoverage) -> None:
    """Show the premium decision panel with the real numbers and a rough ETA."""
    eta = format_eta(estimate_sweep_seconds(coverage.remaining))
    body = (
        f"Host enrichment stopped at {coverage.swept} of {coverage.total} reachable "
        f"hosts ({coverage.percent}%). The identity graph (users, groups, computers, "
        f"ACLs, ADCS, trusts) is already complete, so attack paths can be computed now.\n\n"
        f"{coverage.remaining} hosts are not yet enriched (logged-on sessions, local "
        f"administrators, shares). Finishing them would take about {eta} (rough estimate)."
    )
    print_panel(
        body,
        title=f"Host enrichment stopped — {mark_sensitive(domain, 'domain')}",
        border_style="yellow",
    )


def resolve_host_sweep_stop_decision(
    *,
    shell: Any,
    domain: str,
    coverage: HostSweepStopCoverage,
) -> str:
    """Ask the operator how to proceed after an early-stopped host sweep.

    Renders the decision panel and a three-choice prompt, and returns one of
    :data:`DECISION_CONTINUE` / :data:`DECISION_STOP` / :data:`DECISION_EXIT`.

    Panic-absorbing: ``Ctrl+C`` inside the prompt is a no-op — the centralized
    helper returns ``None`` on ``KeyboardInterrupt`` and this loop re-renders
    the prompt rather than exiting or picking a destructive default. Exiting is
    ONLY reached by deliberately choosing "Exit ADscan".

    Non-interactive (``adscan ci``): never prompts, never blocks — returns
    :data:`DECISION_STOP` so the scan continues with the partial data.
    """
    if is_non_interactive(shell):
        print_info_debug(
            "[host-sweep] non-interactive stop; continuing the scan with the "
            f"{coverage.swept} hosts collected so far."
        )
        return DECISION_STOP

    _render_decision_panel(domain, coverage)

    options = [
        f"Stop here and continue the scan with the {coverage.swept} hosts collected (recommended)",
        f"Continue enriching the remaining {coverage.remaining} hosts",
        "Exit ADscan",
    ]
    # Map each option index to its verdict. The recommended stop is the default
    # (index 0), so a non-interactive resolution never exits.
    verdicts = [DECISION_STOP, DECISION_CONTINUE, DECISION_EXIT]

    while True:
        idx = questionary_select_index(
            title="Host enrichment stopped. How do you want to continue?",
            options=options,
            default_idx=0,
            shell=shell,
        )
        if idx is None:
            # Ctrl+C / cancel inside the prompt is the panic case: re-render and
            # keep waiting for a deliberate choice. It must NEVER fall through to
            # exit or to a default that ends the run.
            print_info_debug(
                "[host-sweep] decision prompt interrupted; re-rendering "
                "(Ctrl+C here does not exit — choose an option)."
            )
            continue
        return verdicts[idx]


__all__ = [
    "DECISION_CONTINUE",
    "DECISION_STOP",
    "DECISION_EXIT",
    "HostSweepStopCoverage",
    "coverage_from_timing",
    "resolve_host_sweep_stop_decision",
]
