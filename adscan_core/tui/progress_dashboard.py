"""Reusable live progress dashboard for long-running ADscan operations.

Single source of truth for the "this operation is alive" UX. Wraps
:class:`adscan_core.tui.LiveSession` with the mandatory premium pattern
(``alt_screen=True`` + a ``summary`` callback) and owns the vocabulary every
long op shares: an ``X / N`` progress bar, throughput (items/s), ETA, the
secondary success/error/in-flight counter row, and a single "last item" line
whose value ALWAYS goes through :func:`mark_sensitive` (the dashboard is
mirrored to the telemetry console via ``_TeeConsole`` — an unmasked host here
would be an exfiltration leak, see CLAUDE.md § Sensitive-Data and the design
spec § 6).

Two modes:

* **Determinate** (``total`` is an int): full ``X / N`` bar + rate + ETA.
* **Indeterminate** (``total is None``): spinner + elapsed + "found N so far".
  Used by opaque subprocess ops (manspider, nmap) and subprocess ops whose
  stdout is not reliably parseable (kerbrute userenum).

Optionally, a dashboard can render a **bounded "recent found" section** below
the counter row: a fixed-height rolling list of the most-recent high-value
hits (valid usernames from a kerbrute userenum, valid ``user:password`` logins
from a spray). The list is backed by a :class:`collections.deque` with a
``maxlen`` cap, so it NEVER grows past ``recent_max`` rows no matter how many
hits are discovered — keeping the renderable's line count stable from frame 1
(CLAUDE.md § Rich Live UX, the stable-line-count rule: unbounded growth leaks
ghost frames into scrollback). The header reports the TRUE total found and the
window size, e.g. ``✓ found 1000 (showing last 10)``. The cap is DISPLAY-ONLY;
the full set of hits is still written to the caller's authoritative store
(the ``-o`` file / credential store). Each recent value is masked at RENDER
time via :func:`mark_sensitive` exactly like the "last item" line.

A dashboard can ALSO render a bounded **"breakdown ranking"** section: as
(key, member) pairs stream in (e.g. ``(port, host)`` from an Nmap scan), the
dashboard aggregates the count of DISTINCT members per key and renders the TOP
``breakdown_max`` keys by that count, descending — a live "top open ports"
leaderboard (``445/tcp 42 · 389/tcp 41 · 3389/tcp 18``). DISTINCT members are
tracked with a ``set`` per key so a re-seen ``(host, port)`` never double-counts.
The ``breakdown_max`` cap bounds the rendered row count regardless of how many
distinct keys appear, so the renderable's line count stays stable from frame 1
(the same stable-line-count guarantee the recent-found section relies on).

The module is dependency-light: it imports only ``adscan_core`` primitives so
it stays importable from launcher, services and CLI alike. Do NOT import
``adscan_internal`` here.
"""

from __future__ import annotations

import itertools
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Iterator, Optional, Set

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from adscan_core.sensitive import mark_sensitive
from adscan_core.theme import (
    ADSCAN_PRIMARY,
    ADSCAN_PRIMARY_BRIGHT,
    COLOR_AMBER,
    COLOR_MUTED,
    COLOR_SAGE,
)
from adscan_core.tui.live_session import LiveSession, LiveSessionConfig

__all__ = [
    "ProgressDashboard",
    "ProgressDashboardConfig",
    "ProgressEstimator",
    "format_eta",
]

# Braille spinner frames — the modern default per tui-design § 5.
_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def format_eta(seconds: Optional[float]) -> str:
    """Format a seconds count as a compact ``Xh Ym`` / ``Xm Ys`` / ``Xs`` string.

    Args:
        seconds: Remaining seconds, or ``None`` when unknown.

    Returns:
        ``"--"`` when ``seconds`` is ``None``; otherwise a human-readable
        duration capped at two units.
    """
    if seconds is None:
        return "--"
    secs = int(round(seconds))
    if secs <= 0:
        return "0s"
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    hours = secs // 3600
    minutes = (secs % 3600) // 60
    return f"{hours}h {minutes}m"


class ProgressEstimator:
    """Throughput / ETA estimator shared by the CLI dashboard and the web events.

    The CLI ``ProgressDashboard`` computes ``rate`` (items/sec), ``eta_seconds``
    and ``elapsed`` from a construction timestamp and a cumulative ``done`` count.
    The web "current operation" strip wants the SAME three numbers on the
    ``operation_progress`` event so the platform matches the CLI rich.live view.

    Rather than fork a second estimator, this is the small computation lifted out
    of the dashboard. Call sites that already drive a :class:`ProgressDashboard`
    read its ``rate`` / ``eta_seconds`` / ``elapsed`` properties directly. Call
    sites that only have a cumulative ``(current, total)`` stream over wall-clock
    (the share collector, the share-enumeration host loop) keep one of these and
    call :meth:`observe` per tick. Both produce identical numbers because they
    share these exact formulas.

    ``elapsed`` is wall-clock since construction. ``rate`` is ``done / elapsed``
    (0.0 before any time has elapsed or any item is done). ``eta_seconds`` is
    ``remaining / rate`` and is ``None`` when the total is unknown or no
    forward motion exists yet — the estimator NEVER fabricates an ETA for an
    indeterminate run.
    """

    def __init__(self, *, _clock: Callable[[], float] = time.monotonic) -> None:
        """Initialise the estimator.

        Args:
            _clock: Injected monotonic clock (tests pass a deterministic one).
        """
        self._clock = _clock
        self._start = _clock()
        self._current = 0
        self._total: Optional[int] = None
        self._elapsed = 0.0

    def observe(self, current: int, total: Optional[int] = None) -> None:
        """Record the latest cumulative count (and optional total) and snapshot time.

        Args:
            current: Cumulative items completed so far (NOT a delta).
            total: Known total, or ``None`` for an indeterminate run.
        """
        self._current = max(0, int(current))
        if total is not None:
            self._total = max(0, int(total))
        self._elapsed = max(0.0, self._clock() - self._start)

    @property
    def elapsed_seconds(self) -> float:
        """Wall-clock seconds since construction (snapshot at the last observe)."""
        return self._elapsed

    @property
    def rate(self) -> float:
        """Throughput in items/second (0.0 before any progress)."""
        if self._elapsed <= 0 or self._current <= 0:
            return 0.0
        return self._current / self._elapsed

    @property
    def eta_seconds(self) -> Optional[float]:
        """Estimated seconds remaining, or ``None`` when indeterminate.

        Returns ``None`` when the total is unknown / non-positive or no forward
        rate exists yet — an indeterminate run must not show a fabricated ETA.
        """
        total = self._total
        if total is None or total <= 0:
            return None
        rate = self.rate
        if rate <= 0:
            return None
        remaining = max(0, total - self._current)
        return remaining / rate


@dataclass(frozen=True)
class ProgressDashboardConfig:
    """Static configuration for a :class:`ProgressDashboard`.

    Attributes:
        title: Operation name shown in the panel title (English only).
        total: Total item count for determinate mode, or ``None`` for the
            indeterminate spinner mode.
        unit: Plural noun for the items ("hosts", "users", "shares").
        last_item_type: ``mark_sensitive`` data_type for the "last item"
            value ("hostname", "ip", "user"). When ``None`` the last-item
            line is suppressed.
        show_counters: Render the success/error/in-flight counter row.
        refresh_per_second: Forwarded to :class:`LiveSessionConfig`.
        recent_max: Maximum number of "recent found" rows to render. ``0``
            (the default) suppresses the section entirely, so every existing
            caller is unchanged. When > 0, the section renders a bounded,
            fixed-height rolling window of the most-recent hits recorded via
            :meth:`ProgressDashboard.record_recent`. The window is backed by a
            ``deque(maxlen=recent_max)``, so it NEVER exceeds ``recent_max``
            rows regardless of how many hits are found (the stable-line-count
            guarantee — see the module docstring).
        recent_item_type: ``mark_sensitive`` data_type for the recent-hit
            values ("user", "hostname", ...). Required when ``recent_max > 0``;
            the values are masked at render exactly like ``last_item_type``.
        recent_label: Plural noun for the recent-hit header ("found"). The
            header renders as ``✓ {recent_label} {Z} (showing last {K})`` where
            ``Z`` is the TRUE total recorded and ``K`` is the window size.
        breakdown_max: Maximum number of ranked keys to render in the
            "breakdown ranking" section. ``0`` (the default) suppresses the
            section entirely, so every existing caller renders byte-identically.
            When > 0, the section ranks keys recorded via
            :meth:`ProgressDashboard.record_breakdown` by their DISTINCT-member
            count (descending; ties broken by key for a stable order) and draws
            at most ``breakdown_max`` of them. The cap bounds the rendered line
            count no matter how many distinct keys appear (stable-line-count).
        breakdown_label: Header text for the breakdown section
            ("top open ports"). Non-sensitive, rendered verbatim.
        breakdown_unit: Optional suffix appended after each count in the ranked
            line (e.g. "hosts"). When empty (the default) only the bare count
            is shown to keep the line terse (``445/tcp 42 · 389/tcp 41``).
        breakdown_annotations: Optional ``key -> short label`` map used to
            annotate well-known keys with a terse service name in the ranked
            line (e.g. ``{"445/tcp": "SMB", "389/tcp": "LDAP"}``). Non-sensitive,
            rendered verbatim; keys with no entry render without an annotation.
    """

    title: str
    total: Optional[int]
    unit: str = "items"
    last_item_type: Optional[str] = None
    show_counters: bool = True
    refresh_per_second: int = 8
    recent_max: int = 0
    recent_item_type: Optional[str] = None
    recent_label: str = "found"
    breakdown_max: int = 0
    breakdown_label: str = "breakdown"
    breakdown_unit: str = ""
    breakdown_annotations: Optional[Dict[str, str]] = None


class ProgressDashboard:
    """Live progress surface driven by :meth:`update`.

    Construct one, drive it inside :meth:`live_session` (sync) or
    :meth:`async_live_session` (async), calling :meth:`update` per completed
    item. The dashboard computes rate + ETA internally; the caller only
    supplies cumulative counts.
    """

    def __init__(
        self,
        config: ProgressDashboardConfig,
        *,
        _clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialise the dashboard.

        Args:
            config: Static :class:`ProgressDashboardConfig`.
            _clock: Injected monotonic clock (tests pass a deterministic one).
        """
        self._config = config
        self._clock = _clock
        self._start = _clock()
        self._elapsed_snapshot = 0.0
        self._done = 0
        self._success = 0
        self._error = 0
        self._in_flight = 0
        self._last: Optional[str] = None
        self._last_detail: Optional[str] = None
        # Bounded "recent found" window. The deque maxlen guarantees the
        # rendered list never exceeds ``recent_max`` rows even after thousands
        # of hits (CLAUDE.md stable-line-count rule). ``_recent_total`` tracks
        # the TRUE count of recorded hits for the header (the window is a
        # DISPLAY cap, not a capture cap). Values are stored RAW and masked at
        # render — never pre-masked, never logged (TeeConsole invariant).
        _recent_cap = max(0, int(config.recent_max or 0))
        self._recent: Deque[tuple[str, Optional[str]]] = deque(maxlen=_recent_cap or 1)
        self._recent_total = 0
        # Breakdown ranking: DISTINCT members per key. ``set`` membership makes
        # re-seen (key, member) pairs idempotent so a port re-discovered on a
        # host it was already counted on never inflates the count. The render
        # picks the TOP ``breakdown_max`` keys by len(set); the dict can grow to
        # the (small, bounded) number of distinct keys, but the RENDERED rows
        # are capped at ``breakdown_max`` — the stable-line-count guarantee.
        self._breakdown: Dict[str, Set[str]] = {}
        # Externally reported progress for opaque subprocess ops whose own
        # output carries a percent / ETA (e.g. Nmap ``--stats-every`` plus the
        # ``Timing: About X% done; ETC: ...`` lines). Optional; when set in
        # indeterminate mode the spinner line is augmented with the real
        # percent + remaining time so the operator sees true forward motion
        # instead of a bare "found N" counter.
        self._reported_percent: Optional[float] = None
        self._reported_eta_seconds: Optional[float] = None
        self._spinner: Iterator[str] = itertools.cycle(_SPINNER_FRAMES)
        self._spinner_frame = next(self._spinner)
        self._session: Optional[LiveSession] = None
        # Optional one-line "tightest budget" safety footer (re-evaluated per
        # frame by the caller, e.g. the spray coverage orchestrator showing the
        # account closest to lockout). None -> the footer line is not rendered.
        self._budget_line: Optional[str] = None

    # ------------------------------------------------------------------
    # Derived metrics
    # ------------------------------------------------------------------

    @property
    def elapsed(self) -> float:
        """Seconds since construction (snapshot taken at the last update)."""
        return self._elapsed_snapshot

    @property
    def rate(self) -> float:
        """Throughput in items/second (0.0 before any time has elapsed)."""
        elapsed = self.elapsed
        if elapsed <= 0 or self._done <= 0:
            return 0.0
        return self._done / elapsed

    @property
    def eta_seconds(self) -> Optional[float]:
        """Estimated seconds remaining, or ``None`` in indeterminate mode.

        In indeterminate mode (no ``total``) this returns the tool's own
        externally reported remaining time when one has been fed via
        :meth:`set_reported_progress` (e.g. Nmap's ``ETC``), so a subprocess op
        that reports its own ETA still exposes one to callers (the web event).
        """
        total = self._config.total
        if total is None or total <= 0:
            return self._reported_eta_seconds
        rate = self.rate
        if rate <= 0:
            return None
        remaining = max(0, total - self._done)
        return remaining / rate

    # ------------------------------------------------------------------
    # Drive API
    # ------------------------------------------------------------------

    def update(
        self,
        *,
        done: Optional[int] = None,
        success: Optional[int] = None,
        error: Optional[int] = None,
        in_flight: Optional[int] = None,
        last: Optional[str] = None,
        last_detail: Optional[str] = None,
    ) -> None:
        """Update cumulative counts and push a new frame to Live.

        All count args are CUMULATIVE (totals so far), not deltas. Omitted
        args leave the prior value unchanged. ``last`` is the raw item value
        (host/ip/user) — it is masked at RENDER time, never stored masked.

        Args:
            done: Items completed so far.
            success: Items that succeeded so far.
            error: Items that errored so far.
            in_flight: Items currently being processed.
            last: Raw value for the "last item" line (masked at render).
            last_detail: Optional pre-formatted detail string for the line
                (e.g. "shares 3 · sessions 7"); rendered after the value.
        """
        if done is not None:
            self._done = done
        if success is not None:
            self._success = success
        if error is not None:
            self._error = error
        if in_flight is not None:
            self._in_flight = in_flight
        if last is not None:
            self._last = last
            self._last_detail = last_detail
        self._elapsed_snapshot = max(0.0, self._clock() - self._start)
        self._spinner_frame = next(self._spinner)
        if self._session is not None:
            self._session.update(self.render())

    def record_recent(
        self,
        value: str,
        *,
        detail: Optional[str] = None,
        push_frame: bool = False,
    ) -> None:
        """Record one high-value hit in the bounded "recent found" window.

        Appends ``value`` to a fixed-capacity rolling window (``deque`` with
        ``maxlen = recent_max``) so the rendered list is ALWAYS ≤ ``recent_max``
        rows, even after thousands of hits — the stable-line-count guarantee
        the LiveSession alt-screen relies on (CLAUDE.md § Rich Live UX). The
        TRUE total count is tracked separately for the header, so the operator
        sees ``✓ found 1000 (showing last 10)`` while the panel only ever draws
        10 rows.

        This is DISPLAY-ONLY. The caller remains responsible for persisting the
        full set of hits to its authoritative store (the kerbrute ``-o`` file /
        the credential store); recording a hit here never drops a credential.

        The value is stored RAW and masked at render via :func:`mark_sensitive`
        — never pre-masked, never logged (CLAUDE.md TeeConsole invariant). A
        no-op when ``recent_max == 0`` (the section is disabled), so it is safe
        to call unconditionally.

        Args:
            value: Raw hit value (username, ...) masked at render.
            detail: Optional dim annotation rendered after the value (e.g. a
                constant sprayed-password note). Not masked — pass only
                non-sensitive context.
            push_frame: When True (and a Live session is active), immediately
                push a frame so the new hit appears without waiting for the
                next :meth:`update`. High-value hits (a valid login) set this.
        """
        if self._config.recent_max <= 0:
            return
        self._recent_total += 1
        self._recent.append((value, detail))
        if push_frame and self._session is not None:
            self._elapsed_snapshot = max(0.0, self._clock() - self._start)
            self._session.update(self.render())

    @property
    def recent_total(self) -> int:
        """TRUE count of hits recorded via :meth:`record_recent` (not capped)."""
        return self._recent_total

    def record_breakdown(
        self,
        key: str,
        *,
        member: str,
        push_frame: bool = False,
    ) -> None:
        """Record one ``(key, member)`` pair into the breakdown ranking.

        Aggregates DISTINCT members per ``key`` (e.g. distinct hosts per open
        port). Membership is set-based, so recording the same ``(key, member)``
        twice counts ONCE — a port re-discovered on a host already counted does
        not inflate the rank. The rendered section shows the TOP
        ``breakdown_max`` keys by distinct-member count (descending), so the row
        count is bounded no matter how many distinct keys are seen
        (stable-line-count rule, CLAUDE.md § Rich Live UX).

        Members are aggregation keys only — they are counted, never rendered, so
        they are NOT masked here (only the bare count per key reaches the panel).
        A no-op when ``breakdown_max == 0`` (the section is disabled), so it is
        safe to call unconditionally.

        Args:
            key: The ranking bucket (e.g. ``"445/tcp"``). Rendered verbatim;
                pass non-sensitive values only.
            member: The distinct entity to count under ``key`` (e.g. a host IP).
                Counted, never rendered.
            push_frame: When True (and a Live session is active), immediately
                push a frame so the updated ranking appears without waiting for
                the next :meth:`update`.
        """
        if self._config.breakdown_max <= 0:
            return
        bucket = self._breakdown.get(key)
        if bucket is None:
            bucket = set()
            self._breakdown[key] = bucket
        bucket.add(member)
        if push_frame and self._session is not None:
            self._elapsed_snapshot = max(0.0, self._clock() - self._start)
            self._session.update(self.render())

    def set_reported_progress(
        self,
        *,
        percent: Optional[float] = None,
        eta_seconds: Optional[float] = None,
    ) -> None:
        """Record externally-reported progress and push a frame.

        For opaque subprocess operations (Nmap, masscan) whose own output
        carries a true completion percent and/or remaining time, the caller
        feeds it here. In indeterminate mode (``total is None``) the spinner
        line is augmented with this real percent + ETA, turning an opaque
        "found N" counter into honest forward motion. Backward-compatible:
        callers that never invoke this keep the original spinner behaviour.

        Args:
            percent: Completion percent in ``[0, 100]`` reported by the tool,
                or ``None`` to leave the prior value unchanged.
            eta_seconds: Remaining seconds reported by the tool, or ``None``
                to leave the prior value unchanged.
        """
        if percent is not None:
            try:
                self._reported_percent = max(0.0, min(100.0, float(percent)))
            except (TypeError, ValueError):
                pass
        if eta_seconds is not None:
            try:
                self._reported_eta_seconds = max(0.0, float(eta_seconds))
            except (TypeError, ValueError):
                pass
        self._elapsed_snapshot = max(0.0, self._clock() - self._start)
        self._spinner_frame = next(self._spinner)
        if self._session is not None:
            self._session.update(self.render())

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def set_budget_line(self, text: Optional[str]) -> None:
        """Set (or clear with ``None``) the tightest-budget safety footer line.

        Caller-driven, re-evaluated per frame from the live ``badPwdCount`` — the
        "are we safe right now" signal for the spray coverage view. Rendered as a
        dim footer row; never stored masked (TeeConsole invariant — caller masks).
        """
        self._budget_line = text or None

    def render(self) -> RenderableType:
        """Build the current dashboard renderable (Panel)."""
        rows: list[RenderableType] = []
        detail_line = self._render_detail_line()
        if detail_line is not None:
            rows.append(detail_line)
        rows.append(self._render_progress_line())
        if self._config.show_counters:
            rows.append(self._render_counter_row())
        last_line = self._render_last_line()
        if last_line is not None:
            rows.append(last_line)
        recent_section = self._render_recent_section()
        if recent_section is not None:
            rows.append(recent_section)
        breakdown_section = self._render_breakdown_section()
        if breakdown_section is not None:
            rows.append(breakdown_section)
        if self._budget_line:
            rows.append(Text(self._budget_line, style=COLOR_MUTED))
        title = Text(self._config.title, style=f"bold {ADSCAN_PRIMARY_BRIGHT}")
        return Panel(
            Group(*rows),
            title=title,
            title_align="left",
            border_style=ADSCAN_PRIMARY,
            padding=(0, 1),
        )

    def _render_detail_line(self) -> Optional[RenderableType]:
        """Determinate-mode subtitle: the scope of the run (total + unit)."""
        total = self._config.total
        if total is None or total <= 0:
            return None
        return Text(f"{total} reachable {self._config.unit}", style=COLOR_MUTED)

    def _render_progress_line(self) -> RenderableType:
        total = self._config.total
        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right")
        if total is not None and total > 0:
            bar = ProgressBar(
                total=total,
                completed=min(self._done, total),
                width=28,
                complete_style=ADSCAN_PRIMARY_BRIGHT,
                finished_style=COLOR_SAGE,
                style=COLOR_MUTED,
            )
            count = Text(f"  {self._done} / {total} {self._config.unit}",
                         style=ADSCAN_PRIMARY)
            left = Table.grid(padding=(0, 0))
            left.add_row(bar, count)
            right = Text(
                f"rate {self.rate:.0f}/s · ETA {format_eta(self.eta_seconds)}",
                style=COLOR_MUTED,
            )
            grid.add_row(left, right)
        elif self._reported_percent is not None:
            # Indeterminate scope, but the tool reports its own percent/ETA
            # (e.g. Nmap --stats-every). Render an honest percent bar driven
            # by the tool's number instead of a bare spinner — the operator
            # sees true forward motion. ETA prefers the tool's remaining time.
            pct = self._reported_percent
            bar = ProgressBar(
                total=100.0,
                completed=min(pct, 100.0),
                width=28,
                complete_style=ADSCAN_PRIMARY_BRIGHT,
                finished_style=COLOR_SAGE,
                style=COLOR_MUTED,
            )
            # The percent is the tool's OWN scan-completion (e.g. Nmap --stats-every),
            # NOT found/total — so label it "scanned" and keep the discovery count
            # ("N found") visually distinct; they are different axes.
            count = Text(
                f"  {pct:.0f}% scanned  ·  {self._done} {self._config.unit} found",
                style=ADSCAN_PRIMARY,
            )
            left = Table.grid(padding=(0, 0))
            left.add_row(bar, count)
            eta = (
                self._reported_eta_seconds
                if self._reported_eta_seconds is not None
                else None
            )
            right = Text(
                f"elapsed {format_eta(self.elapsed)} · ETA {format_eta(eta)}",
                style=COLOR_MUTED,
            )
            grid.add_row(left, right)
        else:
            # Indeterminate: spinner + elapsed + "found N".
            left = Text(
                f"{self._spinner_frame} working… "
                f"found {self._done} {self._config.unit}",
                style=ADSCAN_PRIMARY,
            )
            right = Text(f"elapsed {format_eta(self.elapsed)}", style=COLOR_MUTED)
            grid.add_row(left, right)
        return grid

    def _render_counter_row(self) -> RenderableType:
        row = Table.grid(padding=(0, 2))
        row.add_row(
            Text(f"✓ {self._config.unit} {self._success}", style=COLOR_SAGE),
            Text(f"⚠ errors {self._error}", style=COLOR_AMBER),
            Text(f"⏳ in-flight {self._in_flight}", style=COLOR_MUTED),
        )
        return row

    def _render_last_line(self) -> Optional[RenderableType]:
        if self._config.last_item_type is None or self._last is None:
            return None
        masked = mark_sensitive(self._last, self._config.last_item_type)
        text = Text("last: ", style=COLOR_MUTED)
        text.append(masked, style=ADSCAN_PRIMARY)
        if self._last_detail:
            text.append("  ·  ", style=COLOR_MUTED)
            text.append(self._last_detail, style=COLOR_MUTED)
        return text

    def _render_recent_section(self) -> Optional[RenderableType]:
        """Render the bounded "recent found" window (≤ ``recent_max`` rows).

        Returns ``None`` when the section is disabled (``recent_max == 0``) or
        nothing has been recorded yet, so the panel shape is unchanged for
        callers that don't use it. When active, the header reports the TRUE
        total recorded and the window size (``✓ found Z (showing last K)``) and
        the body draws at most ``recent_max`` rows — newest LAST so the eye
        tracks the latest hit at the bottom. Each value is masked at render via
        :func:`mark_sensitive` (TeeConsole exfiltration invariant).
        """
        cap = self._config.recent_max
        if cap <= 0 or self._recent_total <= 0:
            return None
        item_type = self._config.recent_item_type or "user"
        header = Text()
        header.append("✓ ", style=COLOR_SAGE)
        header.append(
            f"{self._config.recent_label} {self._recent_total}", style=COLOR_SAGE
        )
        if self._recent_total > cap:
            header.append(f"  (showing last {cap})", style=COLOR_MUTED)
        body = Table.grid(padding=(0, 1))
        body.add_column()
        # ``deque`` already holds at most ``maxlen`` (== cap) entries; iterate
        # in insertion order so the newest hit renders at the bottom.
        for value, detail in self._recent:
            masked = mark_sensitive(value, item_type)
            line = Text("  • ", style=COLOR_MUTED)
            line.append(masked, style=ADSCAN_PRIMARY)
            if detail:
                line.append("  ", style=COLOR_MUTED)
                line.append(detail, style=COLOR_MUTED)
            body.add_row(line)
        return Group(header, body)

    def _render_breakdown_section(self) -> Optional[RenderableType]:
        """Render the bounded "breakdown ranking" line (≤ ``breakdown_max`` keys).

        Returns ``None`` when the section is disabled (``breakdown_max == 0``) or
        nothing has been recorded, so the panel shape is unchanged for callers
        that don't use it. When active, keys are ranked by their DISTINCT-member
        count (descending; ties broken by key ascending for a deterministic
        order) and AT MOST ``breakdown_max`` are drawn as a single compact line
        — ``445/tcp 42 · 389/tcp 41 · 3389/tcp 18`` — so the rendered line count
        is bounded regardless of how many distinct keys exist (stable-line-count
        rule). Keys and counts are non-sensitive aggregates; nothing is masked.
        """
        cap = self._config.breakdown_max
        if cap <= 0 or not self._breakdown:
            return None
        # Sort by distinct-member count desc, then key asc for a stable order,
        # and keep only the top ``cap`` keys — the render never grows past cap.
        ranked = sorted(
            self._breakdown.items(),
            key=lambda kv: (-len(kv[1]), kv[0]),
        )[:cap]
        annotations = self._config.breakdown_annotations or {}
        unit_suffix = f" {self._config.breakdown_unit}" if self._config.breakdown_unit else ""
        header = Text()
        header.append("▸ ", style=ADSCAN_PRIMARY_BRIGHT)
        header.append(self._config.breakdown_label, style=ADSCAN_PRIMARY_BRIGHT)
        if len(self._breakdown) > cap:
            header.append(f"  (top {cap})", style=COLOR_MUTED)
        line = Text()
        for idx, (key, members) in enumerate(ranked):
            if idx:
                line.append("  ·  ", style=COLOR_MUTED)
            line.append(key, style=ADSCAN_PRIMARY)
            label = annotations.get(key)
            if label:
                line.append(f" {label}", style=COLOR_MUTED)
            line.append(f" {len(members)}{unit_suffix}", style=COLOR_SAGE)
        return Group(header, line)

    # ------------------------------------------------------------------
    # LiveSession lifecycle
    # ------------------------------------------------------------------

    def _live_config(self) -> LiveSessionConfig:
        return LiveSessionConfig(
            refresh_per_second=self._config.refresh_per_second,
            alt_screen=True,
        )

    def _summary(self, console) -> None:
        """Re-print the final dashboard to scrollback after the alt-screen pops."""
        try:
            console.print(self.render())
        except Exception:  # noqa: BLE001 — summary must never break the flow
            pass

    @contextmanager
    def live_session(self) -> Iterator["ProgressDashboard"]:
        """Sync context manager: enters a LiveSession bound to this dashboard."""
        session = LiveSession(
            self.render(), config=self._live_config(), summary=self._summary
        )
        self._session = session
        with session:
            try:
                yield self
            finally:
                self._session = None

    def async_live_session(self) -> "_AsyncDashboardSession":
        """Async context manager equivalent of :meth:`live_session`."""
        return _AsyncDashboardSession(self)


class _AsyncDashboardSession:
    """Async-context wrapper binding a :class:`LiveSession` to a dashboard."""

    def __init__(self, dashboard: ProgressDashboard) -> None:
        self._dashboard = dashboard
        self._session: Optional[LiveSession] = None

    async def __aenter__(self) -> ProgressDashboard:
        self._session = LiveSession(
            self._dashboard.render(),
            config=self._dashboard._live_config(),
            summary=self._dashboard._summary,
        )
        self._dashboard._session = self._session
        await self._session.__aenter__()
        return self._dashboard

    async def __aexit__(self, exc_type, exc, tb) -> bool | None:
        self._dashboard._session = None
        if self._session is not None:
            await self._session.__aexit__(exc_type, exc, tb)
        return None
