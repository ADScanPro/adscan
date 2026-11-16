"""Live progress for the domain-collection stages that have no per-item tick.

The SMB host sweep has its own determinate dashboard. The stages around it did
not show anything: the directory read (objects, ACLs, memberships and the AD CS
probes, which run inside it) and the save of the collected graph. On a large
directory either can run for many minutes, and an operator looking at a silent
terminal after the last line the AD CS probes printed reads a hang. A partner
did exactly that on a 59,000-object directory.

:func:`collection_stage_progress` shows the shared indeterminate dashboard (the
same one the share credential hunt uses for its opaque scan): a spinner, the
stage, a live elapsed clock and the Ctrl+C hint for what the operator menu
offers at this point. It never fabricates an ETA, and it opens no scan-control
step: a stage that cannot stop half-way must not offer "stop this step". The
menu offers what the scan can honour (skip the rest of the phase, stop the
scan), and those are honoured at the next boundary, after the stage keeps what
it read.

Display-only and fail-open: a dashboard or ``LiveSession`` failure runs the
stage plainly. Without a shell (lab scripts, unit tests driving the orchestrator
directly) it shows nothing, so those callers stay byte-identical.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from adscan_core.theme import COLOR_MUTED
from adscan_core.tui.progress_dashboard import ProgressDashboardConfig

#: Panel title of every collection-stage dashboard.
STAGE_TITLE = "Domain collection"

#: Stage lines (non-sensitive, English, shown verbatim).
STAGE_DIRECTORY_READ = (
    "Reading the directory: objects, ACLs, group memberships and certificate services"
)
STAGE_GRAPH_SAVE = "Saving the collected graph"

#: Seconds between two spinner / elapsed refreshes.
_TICK_SECONDS = 0.4


def _options_footer() -> Optional[Any]:
    """The Ctrl+C hint for the current position, or ``None`` outside a scan."""
    try:
        from rich.text import Text  # noqa: PLC0415

        from adscan_core.scan_control.interrupts import (  # noqa: PLC0415
            options_hint_text,
        )

        text = options_hint_text()
    except Exception:  # noqa: BLE001 - a hint must never break a frame
        return None
    return Text(text, style=COLOR_MUTED) if text else None


@contextmanager
def collection_stage_progress(shell: Any, *, label: str) -> Iterator[None]:
    """Show a live spinner, elapsed clock and Ctrl+C hint around one stage.

    Args:
        shell: The scan shell. ``None`` shows nothing (pure-service callers).
        label: The stage line (non-sensitive), e.g. :data:`STAGE_GRAPH_SAVE`.

    Yields:
        ``None``; run the stage inside the ``with`` body.
    """
    if shell is None:
        yield
        return
    from adscan_internal.services.loot_progress import live_progress  # noqa: PLC0415

    config = ProgressDashboardConfig(
        title=STAGE_TITLE,
        total=None,
        show_counters=False,
        indeterminate_label=label,
    )
    with live_progress(config) as dashboard:
        if dashboard is None:
            yield
            return
        try:
            dashboard.set_footer_provider(_options_footer)
        except Exception:  # noqa: BLE001 - the footer is optional
            pass
        stop = threading.Event()

        def _tick() -> None:
            while not stop.wait(_TICK_SECONDS):
                try:
                    dashboard.update()
                except Exception:  # noqa: BLE001 - a frame must not break the stage
                    break

        ticker = threading.Thread(
            target=_tick, name="collection-stage-progress", daemon=True
        )
        ticker.start()
        try:
            yield
        finally:
            stop.set()
            ticker.join(timeout=1.0)


__all__ = [
    "STAGE_DIRECTORY_READ",
    "STAGE_GRAPH_SAVE",
    "STAGE_TITLE",
    "collection_stage_progress",
]
