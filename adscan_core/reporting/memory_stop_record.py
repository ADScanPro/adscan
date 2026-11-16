"""The stop record the last-resort memory sentinel leaves in a workspace.

When the process reaches the sentinel's hard line (``adscan_core.memory_guard``,
95% of the ceiling) it has a few seconds and almost no memory to say where it
stopped before it exits with the incomplete-run status. Rewriting the large
workspace documents then (``technical_report.json``, ``variables.json``) would
allocate exactly what is not there. So the sentinel writes ONE small file,
``memory_stop.json``, in the workspace: which stage stopped, for which domains,
the ``resource_coverage`` block in the client wording, and the scan phase the
stop leaves incomplete.

The record is folded into the workspace's documents by the next reader:

* the engine, when it loads the workspace (``memory_sentinel_wiring``), marks
  the phase incomplete and records the block, then removes the file;
* the web ingestion folds the block into each domain entry of the technical
  report it reads (:func:`fold_memory_stop_into_report`), so the platform shows
  the stop even before the engine runs again.

Pure logic plus one small atomic write. No engine import: the web backend uses it.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from adscan_core.reporting.resource_coverage import (
    RESOURCE_COVERAGE_KEY,
    merge_stage_coverage,
)

#: The record's filename, in the (execution) workspace directory.
MEMORY_STOP_FILENAME = "memory_stop.json"

#: The sentinel's marker, in the same directory: one JSON line it writes FIRST,
#: without any lock, before the record (``adscan_core.memory_guard``). A marker
#: without a record means "stopped for memory, record not written".
MEMORY_STOP_MARKER_FILENAME = "memory_stop.marker.json"

#: Phase a stage's stop leaves incomplete (the same map the engine applies).
STAGE_PHASES: dict[str, str] = {
    "collection": "domain_collection",
    "graph_build": "domain_collection",
    "graph_export": "domain_collection",
    "attack_paths": "attack_paths_discovery",
}

#: Format of the record (internal; not an integrator-facing output).
MEMORY_STOP_SCHEMA = 1


def write_memory_stop_record(
    workspace_dir: str | os.PathLike[str],
    *,
    domains: Iterable[str],
    stage: str,
    coverage: Mapping[str, Any],
    phase_id: str = "",
    reason: str = "memory",
) -> Path | None:
    """Write the stop record atomically. Returns its path, or ``None`` on failure.

    Small by construction (a few hundred bytes): it is written when the process
    has almost no memory left. Never raises.
    """
    try:
        directory = Path(workspace_dir)
        if not directory.is_dir():
            return None
        record = {
            "schema": MEMORY_STOP_SCHEMA,
            "at": datetime.now(timezone.utc).isoformat(),
            "domains": sorted({str(d).strip() for d in domains if str(d or "").strip()}),
            "stage": str(stage or ""),
            "reason": str(reason or "memory"),
            "phase_id": str(phase_id or ""),
            RESOURCE_COVERAGE_KEY: dict(coverage),
        }
        fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".memory_stop-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle)
                handle.flush()
                os.fsync(handle.fileno())
            target = directory / MEMORY_STOP_FILENAME
            os.replace(tmp, target)
            return target
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:  # noqa: BLE001 - the sentinel's write is best-effort
        return None


def read_memory_stop_record(workspace_dir: str | os.PathLike[str]) -> dict[str, Any] | None:
    """The workspace's pending stop, or ``None``. Never raises.

    The full record when the sentinel wrote one; otherwise, when only its marker
    is there (the run stopped for memory and the record was not written), a
    record derived from the marker: its stage (possibly ``unknown``), progress
    unknown, no domains named (a reader applies it to every domain of the run).
    """
    path = Path(workspace_dir) / MEMORY_STOP_FILENAME
    try:
        with path.open("r", encoding="utf-8") as handle:
            record = json.load(handle)
    except (OSError, ValueError):
        record = None
    if isinstance(record, dict) and isinstance(record.get(RESOURCE_COVERAGE_KEY), dict):
        return record
    return record_from_marker(workspace_dir)


def record_from_marker(workspace_dir: str | os.PathLike[str]) -> dict[str, Any] | None:
    """A stop record derived from the sentinel's marker alone, or ``None``."""
    try:
        from adscan_core.memory_guard import read_memory_stop_marker  # noqa: PLC0415
    except ImportError:
        return None
    marker = read_memory_stop_marker(Path(workspace_dir) / MEMORY_STOP_MARKER_FILENAME)
    if not marker:
        return None
    from adscan_core.reporting.resource_coverage import build_resource_coverage  # noqa: PLC0415

    stage = str(marker.get("stage") or "unknown").strip().lower() or "unknown"
    return {
        "schema": MEMORY_STOP_SCHEMA,
        "at": marker.get("utc"),
        "domains": [],
        "stage": stage,
        "reason": "memory",
        "phase_id": STAGE_PHASES.get(stage, ""),
        "record_written": False,
        RESOURCE_COVERAGE_KEY: build_resource_coverage(
            stage=stage, unit="items", examined=None, reason="memory"
        ),
    }


def fold_memory_stop_into_report(
    report: Mapping[str, Any] | None, record: Mapping[str, Any] | None
) -> Mapping[str, Any] | None:
    """Return ``report`` with the record's block folded into each named domain.

    A new mapping; ``report`` is not mutated. Domains the report does not hold
    get an entry carrying only the block, so the stop is never dropped.
    """
    if not isinstance(record, Mapping):
        return report
    block = record.get(RESOURCE_COVERAGE_KEY)
    domains = [str(d) for d in record.get("domains") or () if str(d or "").strip()]
    folded = dict(report or {})
    entries = dict(folded.get("domains") or {}) if isinstance(folded.get("domains"), Mapping) else {}
    if not domains:
        # A record derived from the marker names no domain: the stop covers
        # every domain of the run.
        domains = [str(name) for name in entries]
    if not isinstance(block, Mapping) or not domains:
        return report
    for domain in domains:
        entry = dict(entries.get(domain) or {}) if isinstance(entries.get(domain), Mapping) else {}
        entry[RESOURCE_COVERAGE_KEY] = merge_stage_coverage(entry.get(RESOURCE_COVERAGE_KEY), block)
        entries[domain] = entry
    folded["domains"] = entries
    return folded


def remove_memory_stop_record(workspace_dir: str | os.PathLike[str]) -> None:
    """Remove the record and the sentinel's marker once folded. Never raises."""
    try:
        (Path(workspace_dir) / MEMORY_STOP_FILENAME).unlink()
    except OSError:
        pass
    try:
        from adscan_core.memory_guard import remove_memory_stop_marker  # noqa: PLC0415

        remove_memory_stop_marker(Path(workspace_dir) / MEMORY_STOP_MARKER_FILENAME)
    except ImportError:
        pass


def marker_path_for(workspace_dir: str | os.PathLike[str]) -> str:
    """Where the sentinel writes its marker for this workspace."""
    return str(Path(workspace_dir) / MEMORY_STOP_MARKER_FILENAME)


__all__ = (
    "MEMORY_STOP_FILENAME",
    "MEMORY_STOP_MARKER_FILENAME",
    "STAGE_PHASES",
    "marker_path_for",
    "record_from_marker",
    "fold_memory_stop_into_report",
    "read_memory_stop_record",
    "remove_memory_stop_record",
    "write_memory_stop_record",
)
