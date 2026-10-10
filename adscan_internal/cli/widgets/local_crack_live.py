"""Waiting surface for the BLOCKING local password-recovery attack.

The local NT attack runs in the scan flow (see
:mod:`adscan_internal.services.cracking.local_nt_crack`), so the operator is
genuinely waiting on it. This panel is what they watch: which tier is running,
how far through it is, how long it has left, and how much of the lane's time
budget is spent. Every figure is real. The progress and the remaining time come
from the cracker's own status stream, and the elapsed-versus-budget line is
measured here, so nothing on screen is a guess dressed as a measurement.

Two deliberate properties:

* **It renders itself; nothing pushes frames at it.** The panel is a live Rich
  renderable reading a lock-guarded snapshot, so the cracker's status callback,
  which fires on whichever thread is draining its output, only ever writes state.
  Nothing cross-thread touches the Live region.
* **It is a no-op where there is nothing to watch.** Off a TTY, or under
  ``ADSCAN_NO_LIVE``, the panel is skipped and each tier announces itself as one
  plain line instead, which is what a captured ``adscan ci`` log can carry.
* **It steps out of the way to be spoken to.** When the attack has something to
  ask the operator (a stage whose live estimate will not fit the remaining time
  budget), :meth:`LocalCrackProgress.pause` pops the panel so the question is
  asked in the operator's normal scrollback, under the panel's last frame, and
  :meth:`LocalCrackProgress.resume` brings it back for the answer.

Display vocabulary, which the tests assert: ``·`` is the separator throughout and
there are no em dashes; the glyph is never the only signal (every state carries
literal text beside it); the panel is a fixed four lines from the first frame, so
its shape cannot grow mid-render.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Optional

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from adscan_core.rich_output import print_info
from adscan_core.theme import COLOR_MUTED, COLOR_STEEL
from adscan_core.tui import LiveSession, LiveSessionConfig

#: Panel title. Named for what the client cares about, not for the tool.
_TITLE = "Local password recovery"

#: The one separator used throughout, so the panel reads as one voice.
_SEP = " · "


def _human_seconds(seconds: float) -> str:
    """Render an elapsed/budget duration as ``45s`` / ``3m`` / ``1h 10m``."""
    total = max(0, int(seconds))
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s" if secs else f"{minutes}m"
    hours, mins = divmod(minutes, 60)
    return f"{hours}h {mins:02d}m" if mins else f"{hours}h"


@dataclass
class _State:
    """What the panel knows, guarded by :attr:`LocalCrackProgress._lock`."""

    tier_name: str = ""
    tier_allotted: Optional[int] = None
    tier_started: Optional[float] = None
    progress_pct: Optional[float] = None
    eta_seconds: Optional[int] = None
    tiers_run: int = 0
    finished: bool = False


class LocalCrackProgress:
    """Live progress for one blocking local-recovery run.

    The two callbacks are the whole public surface, and both are shaped to be
    handed straight to
    :func:`~adscan_internal.services.cracking.engine_selection.run_effort_ladder`:
    :meth:`on_tier_start` as its ``on_tier_start`` and :meth:`on_status` as its
    ``status_sink``. Neither raises: a waiting surface must never be able to break
    the attack it is describing.
    """

    def __init__(
        self, *, hash_count: int, effort: str, budget_seconds: float
    ) -> None:
        self._hash_count = max(0, int(hash_count))
        self._effort = str(effort or "").strip().lower()
        self._budget = max(0.0, float(budget_seconds or 0.0))
        self._started = time.monotonic()
        self._lock = threading.Lock()
        self._state = _State()
        self._spinner = Spinner("dots", style=COLOR_STEEL)
        self._session: LiveSession | None = None
        self._live = sys.stdout.isatty() and os.environ.get("ADSCAN_NO_LIVE") != "1"

    # ---- the ladder's two callbacks ---------------------------------------

    def on_tier_start(self, tier: Any, allotted: Optional[int]) -> None:
        """Record the tier about to run, and how long it may spend."""
        try:
            name = str(getattr(tier, "name", "") or "")
            base = os.path.basename(str(getattr(tier, "base_path", "") or ""))
            rule = os.path.basename(str(getattr(tier, "rule_path", "") or ""))
            label = base or name
            if rule:
                label = f"{label} + {os.path.splitext(rule)[0] or rule}"
            with self._lock:
                self._state.tier_name = label
                self._state.tier_allotted = allotted
                self._state.tier_started = time.monotonic()
                self._state.progress_pct = None
                self._state.eta_seconds = None
                self._state.tiers_run += 1
            self._announce(label)
        except Exception:  # noqa: BLE001 — never break the crack over its own panel
            pass

    def on_status(self, status: dict) -> None:
        """Absorb one live progress tick from the cracker."""
        try:
            if not isinstance(status, dict):
                return
            pct = status.get("progress_pct")
            eta = status.get("eta_seconds")
            with self._lock:
                if isinstance(pct, (int, float)):
                    self._state.progress_pct = float(pct)
                if isinstance(eta, (int, float)):
                    self._state.eta_seconds = int(eta)
        except Exception:  # noqa: BLE001
            pass

    # ---- lifecycle ---------------------------------------------------------

    def __enter__(self) -> "LocalCrackProgress":
        if self._live:
            self._open_session()
        return self

    def __exit__(self, *args: Any) -> None:
        with self._lock:
            self._state.finished = True
        self._close_session(*args)

    def pause(self) -> None:
        """Tear the live region down so the caller can talk to the operator.

        The panel lives in the terminal's alternate screen, so a question asked
        while it is up either renders inside a buffer about to be discarded or
        fights the live region for the same lines. Pausing closes the session,
        which pops the alt-screen and leaves the panel's last frame in normal
        scrollback: the operator reads the state they are deciding about, and the
        question is asked underneath it.

        Idempotent and best-effort, like everything else here: a surface must
        never be the reason an attack or a prompt fails.
        """
        self._close_session(None, None, None)

    def resume(self) -> None:
        """Re-open the live region after a question has been answered."""
        if not self._live or self._session is not None:
            return
        try:
            self._open_session()
        except Exception:  # noqa: BLE001 — carry on without the panel
            self._session = None

    def _open_session(self) -> None:
        self._session = LiveSession(
            self,
            config=LiveSessionConfig(refresh_per_second=8, alt_screen=True),
            summary=self._print_final_panel,
        )
        self._session.__enter__()

    def _close_session(self, *args: Any) -> None:
        if self._session is None:
            return
        session, self._session = self._session, None
        try:
            session.__exit__(*args)
        except Exception:  # noqa: BLE001 — a teardown never breaks the attack
            pass

    def _print_final_panel(self, console: Any) -> None:
        """Re-print the final panel to scrollback once the alt-screen pops."""
        try:
            console.print(self._render())
        except Exception:  # noqa: BLE001
            pass

    def _announce(self, label: str) -> None:
        """Off-TTY fallback: one plain line per tier, no panel, no frames.

        A captured log cannot render a Live region, and a per-tick line would
        flood it, so the boundary between tiers is the right granularity: it is
        the only place the plan actually changes.

        Keyed on whether this run has a panel AT ALL, not on whether one happens
        to be open: a run that paused the panel to ask the operator something
        still has one, and printing the plain line there would duplicate what the
        panel is about to show again.
        """
        if self._live or not label:
            return
        print_info(
            f"Recovering passwords locally: {label}{_SEP}"
            f"{self._effort or 'default'} effort"
        )

    # ---- rendering ---------------------------------------------------------

    def __rich__(self) -> RenderableType:
        """Rich pulls this on every refresh, so the panel updates itself."""
        return self._render()

    def _render(self) -> RenderableType:
        with self._lock:
            state = _State(**vars(self._state))
        elapsed = time.monotonic() - self._started

        headline = Text(state.tier_name or "preparing", style="bold")
        detail = _progress_text(state)
        if detail:
            headline.append(_SEP, style=COLOR_MUTED)
            headline.append_text(detail)

        line_tier: RenderableType
        if state.finished:
            line_tier = Text.assemble(
                ("finished", "green"), (_SEP, COLOR_MUTED), (state.tier_name or "", "")
            )
        else:
            row = Table.grid(padding=(0, 1))
            row.add_column(no_wrap=True)
            row.add_column(ratio=1)
            row.add_row(self._spinner, headline)
            line_tier = row

        hashes = (
            f"{self._hash_count:,} recovered NT hash"
            + ("es" if self._hash_count != 1 else "")
        )
        line_scope = Text.assemble(
            (hashes, ""),
            (_SEP, COLOR_MUTED),
            (f"{self._effort or 'default'} effort", ""),
        )
        budget = (
            f"{_human_seconds(elapsed)} elapsed of a "
            f"{_human_seconds(self._budget)} budget"
            if self._budget > 0
            else f"{_human_seconds(elapsed)} elapsed"
        )
        line_budget = Text(budget, style=COLOR_MUTED)
        line_note = Text(
            "Entirely local and offline: nothing is sent to the target network.",
            style=COLOR_MUTED,
        )
        return Panel(
            Group(line_tier, line_scope, line_budget, line_note),
            title=_TITLE,
            title_align="left",
            border_style=COLOR_STEEL,
            padding=(0, 1),
        )


def _progress_text(state: _State) -> Optional[Text]:
    """The progress / remaining-time clause, or ``None`` when nothing is known.

    Prefers the cracker's OWN reported figures. Falls back to elapsed against the
    tier's allotted time, which is a real measurement of the budget rather than a
    claim about the keyspace, and is labelled as such so the two are never
    confused.
    """
    from adscan_internal.services.background_jobs.cracking_job import (  # noqa: PLC0415
        format_eta_seconds,
        format_progress_pct,
    )

    parts: list[str] = []
    pct = format_progress_pct(state.progress_pct)
    if pct:
        parts.append(pct)
    eta = format_eta_seconds(state.eta_seconds)
    if eta:
        parts.append(eta)
    if parts:
        return Text(_SEP.join(parts), style=COLOR_STEEL)
    if state.tier_allotted and state.tier_started is not None:
        spent = max(0.0, time.monotonic() - state.tier_started)
        left = max(0, int(state.tier_allotted - spent))
        return Text(f"up to {_human_seconds(left)} left in this tier", style=COLOR_MUTED)
    return None


@contextmanager
def local_crack_progress(
    *, hash_count: int, effort: str, budget_seconds: float
) -> Iterator[LocalCrackProgress]:
    """Open the waiting surface for one blocking local-recovery run.

    Yields the :class:`LocalCrackProgress` whose two callbacks the ladder walker
    takes. Safe in every environment: the Live panel is used on a TTY, and
    skipped for the plain per-tier lines everywhere else.
    """
    progress = LocalCrackProgress(
        hash_count=hash_count, effort=effort, budget_seconds=budget_seconds
    )
    with progress:
        yield progress


__all__ = ["LocalCrackProgress", "local_crack_progress"]
