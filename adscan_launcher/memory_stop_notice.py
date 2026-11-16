"""Tell the operator, on the host terminal, that ADscan stopped a run for memory.

The last-resort memory sentinel runs inside the container with the other threads
frozen, so it cannot be trusted to print: it writes ``memory_stop.marker.json`` in
the workspace and exits with the incomplete-run status (3). Interactive output
(a live panel) is usually on screen at that moment, so the pane looks like a crash.

The launcher owns the container's lifetime and sees its exit code. After the
container is gone it calls :func:`report_memory_stop_if_any`, which finds the marker
the run left and renders one panel. Everything here is best-effort: a missing,
stale or malformed marker changes nothing (no message, no exception), and the exit
code is never altered.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from adscan_core.memory_guard import (
    MEMORY_STOP_MARKER_SCHEMA,
    MemoryCeilingReached,
    read_memory_stop_marker,
)
from adscan_core.reporting.memory_stop_record import MEMORY_STOP_MARKER_FILENAME
from adscan_core.reporting.resource_coverage import stage_label

#: The incomplete-run exit code the sentinel uses; the only one this module reacts to.
MEMORY_STOP_EXIT_CODE = 3

#: Clock slack between the host and the container when matching a marker to a run.
_START_SLACK_SECONDS = 5


def _mb(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return f"{value / (1024 * 1024):,.0f} MB"


def find_memory_stop_marker(
    workspaces_dir: str | os.PathLike[str], *, since_epoch: float
) -> tuple[Path, dict[str, Any]] | None:
    """The newest memory-stop marker written at or after ``since_epoch``, or ``None``.

    Searches every workspace directory, hidden ``.run_*`` execution workspaces
    included, because an interactive ``start`` chooses its workspace inside the
    container and the launcher does not know it. Never raises.
    """
    best: tuple[float, Path, dict[str, Any]] | None = None
    try:
        candidates = list(Path(workspaces_dir).glob(f"*/{MEMORY_STOP_MARKER_FILENAME}"))
    except OSError:
        return None
    for path in candidates:
        try:
            marker = read_memory_stop_marker(path)
            if not marker or marker.get("schema") != MEMORY_STOP_MARKER_SCHEMA:
                continue
            if marker.get("stopped_for") != "memory":
                continue
            raw = marker.get("epoch")
            epoch = float(raw) if isinstance(raw, (int, float)) else path.stat().st_mtime
            if epoch < since_epoch - _START_SLACK_SECONDS:
                continue
            if best is None or epoch > best[0]:
                best = (epoch, path, marker)
        except (OSError, ValueError, TypeError):
            continue
    return (best[1], best[2]) if best else None


def build_memory_stop_message(marker: dict[str, Any], *, location: str) -> str:
    """The operator wording, built only from what the marker carries."""
    stage = str(marker.get("stage") or "").strip().lower()
    where = ""
    if stage and stage != "unknown":
        where = f" during {stage_label(stage).lower()}"
    measured = _mb(marker.get("measured_bytes")) or _mb(marker.get("rss_bytes"))
    ceiling = _mb(marker.get("ceiling_bytes"))
    free = _mb(marker.get("free_bytes"))
    if marker.get("reason") == "free_memory" and free:
        cause = f"The machine had only {free} of memory left free{where}, so ADscan stopped the run"
    elif measured and ceiling:
        cause = (
            f"Memory reached about {measured} of the {ceiling} ADscan can use{where}, "
            "so ADscan stopped the run"
        )
    else:
        cause = f"ADscan ran out of memory headroom{where}, so it stopped the run"
    lines = [
        f"{cause} before the system would kill it and recorded where it stopped.",
        "What it had not reached was not evaluated, so this run is incomplete (exit code 3).",
        f"Stop record: {location}",
        MemoryCeilingReached.REMEDY,
    ]
    return "\n".join(lines)


def report_memory_stop_if_any(
    exit_code: int,
    *,
    workspaces_dir: str | os.PathLike[str],
    since_epoch: float,
) -> bool:
    """Render the memory-stop panel when ``exit_code`` is 3 and a fresh marker exists.

    Returns True when a panel was printed. Never raises and never changes the code.
    """
    if int(exit_code) != MEMORY_STOP_EXIT_CODE:
        return False
    try:
        found = find_memory_stop_marker(workspaces_dir, since_epoch=since_epoch)
        if found is None:
            return False
        path, marker = found
        try:
            location = str(path.parent.relative_to(Path(workspaces_dir).parent))
        except ValueError:
            location = str(path.parent)
        from adscan_core.rich_output import print_panel  # noqa: PLC0415

        print_panel(
            build_memory_stop_message(marker, location=location),
            title="ADscan Stopped For Memory",
            border_style="yellow",
        )
        return True
    except Exception:  # noqa: BLE001 - a notice must never break the launcher's exit path
        return False
