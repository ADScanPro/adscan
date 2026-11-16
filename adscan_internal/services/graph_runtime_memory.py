"""The graph runtime's two memory boundaries: building and exporting a domain's graph.

``graph_runtime`` builds a domain's graph from its store (``_ensure_live``) and
streams it to ``attack_graph.json`` (``_export``). Both are memory-heavy stages
of the pipeline, so both run under :func:`adscan_core.memory_guard.memory_bounded`
(spec ``2026-11-12-inventory-first-graph-persistence.md`` section 15.7). This
module holds the two boundaries so ``graph_runtime`` only calls them:

* :func:`build_bounded`: the build (stage ``graph_build``). The build itself
  watches memory per stored relationship (``graph_build.memory_guard``); when it
  crosses the line nothing is built, the store is untouched, and here the stop
  is recorded (the collection phase incomplete, so ``adscan ci`` exits 3, and the
  ``resource_coverage`` block) and the file on disk is marked as NOT the export
  of this run, so no reader takes the previous graph for the current one.
* :func:`export_bounded`: the export (stage ``graph_export``), which includes
  finishing the live graph and writing the sidecars. A stop there is recorded
  the same way and leaves the previous file in place, marked not current.

A graph cannot be built in part and shown as complete, so neither stage has a
streamed mode: each stops and declares.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from adscan_core import telemetry
from adscan_core.memory_guard import OUTCOME_STOPPED, memory_bounded
from adscan_core.reporting.resource_coverage import (
    STAGE_GRAPH_BUILD,
    STAGE_GRAPH_EXPORT,
)
from adscan_core.rich_output import print_exception
from adscan_internal.services.graph_build.memory_guard import GRAPH_BUILD_UNIT

# Package D4 owns the ``export_state`` root key of ``attack_graph.json``; this is
# its entry point (a no-op on a frozen workspace).
from adscan_internal.services.graph_build.export import (
    mark_export_incomplete as _mark_export_incomplete,
)

#: What the export stage counts, for the coverage statement.
GRAPH_EXPORT_UNIT = "graph files"

#: Operator sentence for the phase record of a stopped build.
_BUILD_DETAIL = "The attack graph could not be built within the available memory."
#: Operator sentence for the phase record of a stopped export.
_EXPORT_DETAIL = "The attack graph could not be exported within the available memory."


def _export_state_block(block: dict[str, Any]) -> dict[str, Any]:
    """D4's flat ``{"stage", "reason"}`` from a ``resource_coverage`` block."""
    stages = block.get("stages") if isinstance(block, dict) else None
    entry = stages[0] if isinstance(stages, list) and stages and isinstance(stages[0], dict) else {}
    return {
        "stage": str(entry.get("stage") or block.get("stage") or "").strip(),
        "reason": str(entry.get("reason") or block.get("reason") or "").strip(),
    }


def mark_file_not_current(path: str, block: dict[str, Any], *, store: Any = None) -> bool:
    """Mark ``path`` as not the export of this run (D4's ``export_state``).

    ``block`` is the stage's ``resource_coverage`` block; D4 receives the flat
    ``stage`` and ``reason`` of its stop and the domain's ``store`` (whose
    export record it resets, so the next export rewrites the file). Returns
    whether the file was handled. Never raises.
    """
    try:
        _mark_export_incomplete(path, _export_state_block(block), store=store)
        return True
    except Exception as exc:  # noqa: BLE001 - marking never breaks the stop
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def _stop_recorder(
    shell: Any,
    domain: str,
    path: str,
    *,
    detail: str,
    store: Any = None,
    mark: bool = True,
    stamp_run: bool = False,
) -> Callable[[dict[str, Any]], None]:
    from adscan_internal.services.collector.collection_integrity import (  # noqa: PLC0415
        COLLECTION_PHASE_ID,
    )
    from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
        stage_stop_recorder,
    )

    record = stage_stop_recorder(
        shell, domain, phase_id=COLLECTION_PHASE_ID, detail=detail
    )

    def _record(block: dict[str, Any]) -> None:
        if stamp_run:
            # The run that stopped, so the SAME run does not climb to the
            # ceiling again when a later reader reopens the store.
            from adscan_core.reporting.resource_coverage import (  # noqa: PLC0415
                stamp_stop_run,
            )
            from adscan_internal.services.graph_availability import (  # noqa: PLC0415
                current_run_token,
            )

            block = stamp_stop_run(block, current_run_token(shell))
        record(block)
        if mark:
            mark_file_not_current(path, block, store=store)

    return _record


def _clear(shell: Any, domain: str, stage: str) -> None:
    from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
        clear_stage_coverage,
    )

    clear_stage_coverage(shell, domain, stage)


def _read_graph_file(path: str, loader: Callable[[str], Any] | None) -> Any:
    from adscan_core.graph_compact import load_graph_file  # noqa: PLC0415
    from adscan_internal.workspaces import read_json_file  # noqa: PLC0415

    try:
        return (loader or load_graph_file)(path)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # A corrupt file goes through the reader that keeps a backup of it.
        return read_json_file(path)


def load_graph_file_bounded(
    shell: Any, domain: str, path: str, *, loader: Callable[[str], Any] | None = None
) -> tuple[bool, Any]:
    """Read ``attack_graph.json`` under the ``graph_build`` boundary.

    Returns ``(True, data)``, or ``(False, None)`` when the read was refused
    because it would not fit (a 14.0.x file is loaded whole): the stop is
    recorded like a stopped build. The file is left as it is.
    """
    with memory_bounded(
        STAGE_GRAPH_BUILD,
        unit=GRAPH_BUILD_UNIT,
        record=_stop_recorder(shell, domain, path, detail=_BUILD_DETAIL, mark=False),
    ) as stage:
        data = _read_graph_file(path, loader)
    if stage.outcome == OUTCOME_STOPPED:
        return False, None
    # A read that fitted this time clears an earlier refused read: the graph is
    # available again. Not when the file says it is not the current export (a
    # stopped build left it): then the earlier stop is still what it rests on.
    from adscan_core.reporting.resource_coverage import (  # noqa: PLC0415
        graph_unavailable_stage,
    )

    if isinstance(data, dict) and not graph_unavailable_stage(graph=data):
        _clear(shell, domain, STAGE_GRAPH_BUILD)
    return True, data


def build_bounded(
    shell: Any, domain: str, path: str, build: Callable[[], Any], *, store: Any = None
) -> Any | None:
    """Run ``build`` (one graph build) under the ``graph_build`` boundary.

    Returns what ``build`` returned, or ``None`` when the build stopped at the
    memory ceiling (already recorded and declared).
    """
    with memory_bounded(
        STAGE_GRAPH_BUILD,
        unit=GRAPH_BUILD_UNIT,
        record=_stop_recorder(
            shell, domain, path, detail=_BUILD_DETAIL, store=store, stamp_run=True
        ),
    ) as stage:
        built = build()
    if stage.outcome == OUTCOME_STOPPED:
        return None
    _clear(shell, domain, STAGE_GRAPH_BUILD)
    return built


def export_bounded(
    shell: Any, domain: str, path: str, export: Callable[[], bool], *, store: Any = None
) -> bool:
    """Run ``export`` (finish and stream one graph) under the ``graph_export`` boundary.

    Returns whether a file was written; ``False`` when the export stopped at the
    memory ceiling (recorded, and the previous file marked not current).
    """
    with memory_bounded(
        STAGE_GRAPH_EXPORT,
        unit=GRAPH_EXPORT_UNIT,
        total=1,
        # Stamped with the run like the build's stop, so the rest of the run
        # reads it (``graph_availability.collection_memory_stop_this_run``). An
        # export is still retried in the run: only the build is not.
        record=_stop_recorder(
            shell, domain, path, detail=_EXPORT_DETAIL, store=store, stamp_run=True
        ),
    ) as stage:
        written = export()
    if stage.outcome == OUTCOME_STOPPED:
        return False
    if written:
        _clear(shell, domain, STAGE_GRAPH_EXPORT)
    return bool(written)


__all__ = (
    "GRAPH_EXPORT_UNIT",
    "build_bounded",
    "export_bounded",
    "mark_file_not_current",
)
