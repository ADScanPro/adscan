"""Fail-open live-progress helpers for the share credential-hunt phase.

Thin lifecycle wrappers over :class:`adscan_core.tui.ProgressDashboard` used by
the SMB Share Exposure (share credential-hunt) sub-steps to show a live
``X / N`` progress bar + ETA (share fetch, per-file analysis) or an honest
indeterminate spinner (the opaque CredSweeper secret scan). The phase can run
long in many-shares environments; without these, the operator sees no aggregate
progress.

Every helper is **DISPLAY-ONLY** and **fail-open**: a dashboard build or
``LiveSession`` setup failure degrades to a plain run so the phase always
completes and every finding is still persisted exactly as before. Timing is
monotonic (owned by the dashboard). Non-interactive / CI runs inherit the
inline fallback from ``LiveSession`` (no alt-screen) — nothing here gates on
``isatty``.

The module imports only ``adscan_core`` primitives + stdlib; it never imports
the native AD stack, so it is cheap to import from CLI and services alike.
"""

from __future__ import annotations

import os
import threading
from contextlib import ExitStack, contextmanager
from typing import Iterator, Optional

from adscan_core.tui.progress_dashboard import (
    ProgressDashboard,
    ProgressDashboardConfig,
)

__all__ = [
    "count_files_under",
    "indeterminate_scan_spinner",
    "live_progress",
]


def count_files_under(root_path: str) -> int:
    """Count regular files under ``root_path`` (0 on any walk error).

    Used to size a determinate progress bar or to label an opaque scan
    (``Scanning N files…``). Best-effort — never raises.
    """
    total = 0
    try:
        for _current_root, _dirs, files in os.walk(root_path):
            total += len(files)
    except OSError:
        return 0
    return total


@contextmanager
def live_progress(
    config: ProgressDashboardConfig,
) -> Iterator[Optional[ProgressDashboard]]:
    """Yield a LIVE :class:`ProgressDashboard`, or ``None`` if it can't run.

    Builds the dashboard and enters its ``live_session``. On ANY dashboard
    build or ``LiveSession`` setup failure the caller still receives ``None``
    and the ``with`` body runs plainly — so the loop it drives always completes
    and persists its findings (fail-open). Body exceptions are never masked:
    only the live surface is best-effort. The caller ticks via
    ``dashboard.update(...)`` guarded by ``if dashboard is not None``.

    Args:
        config: The dashboard configuration (title/total/unit/...).

    Yields:
        The active dashboard, or ``None`` when no live surface could start.
    """
    try:
        dashboard: Optional[ProgressDashboard] = ProgressDashboard(config)
    except Exception:  # noqa: BLE001 -- a display build must never block the phase
        dashboard = None
    if dashboard is None:
        yield None
        return

    stack = ExitStack()
    active: Optional[ProgressDashboard] = None
    try:
        stack.enter_context(dashboard.live_session())
        active = dashboard
    except Exception:  # noqa: BLE001 -- live setup failure degrades to a plain run
        active = None
    try:
        yield active
    finally:
        try:
            stack.close()
        except Exception:  # noqa: BLE001 -- teardown is best-effort
            pass


@contextmanager
def indeterminate_scan_spinner(
    title: str,
    *,
    label: str,
    refresh_per_second: int = 8,
) -> Iterator[None]:
    """Show an honest indeterminate spinner around ONE opaque blocking scan.

    For a single opaque call (e.g. CredSweeper's ``analyzer.run(...)``) there is
    no per-file signal to tick, so this renders a spinner + a fixed ``label``
    (``Scanning N files for secrets…``) + a live ``elapsed`` clock — and NO
    fabricated per-file ETA. A daemon ticker advances the spinner/elapsed while
    the caller's blocking work runs on the main thread; it is the only writer to
    the dashboard during that window. Fail-open + display-only.

    Args:
        title: Panel title (English only), e.g. "SMB Share Exposure · Secret Scan".
        label: The indeterminate line phrase, e.g. "Scanning 143 files for secrets…".
        refresh_per_second: Live refresh cadence forwarded to the dashboard.

    Yields:
        ``None`` — run the opaque blocking call inside the ``with`` body.
    """
    config = ProgressDashboardConfig(
        title=title,
        total=None,
        show_counters=False,
        indeterminate_label=label,
        refresh_per_second=refresh_per_second,
    )
    with live_progress(config) as dashboard:
        if dashboard is None:
            yield
            return
        stop = threading.Event()

        def _tick() -> None:
            # Advance the spinner frame + elapsed clock until the scan returns.
            # 0.4s is well under the 5-frame/sec the eye reads as "alive".
            while not stop.wait(0.4):
                try:
                    dashboard.update()
                except Exception:  # noqa: BLE001 -- render must not break the scan
                    break

        ticker = threading.Thread(
            target=_tick, name="loot-scan-spinner", daemon=True
        )
        ticker.start()
        try:
            yield
        finally:
            stop.set()
            ticker.join(timeout=1.0)
