"""Record a pipeline stage that stopped at its memory ceiling: the one writer.

Every stage that runs under :func:`adscan_core.memory_guard.memory_bounded`
(collection, graph build, graph export, attack-path discovery, report rendering)
hands the boundary a ``record`` callback. This module builds that callback, so
a stop is recorded the same way whatever stage it hit:

* the phase the stage belongs to is marked incomplete through the single writer
  (``scan_progress.mark_phase_incomplete``, reason ``memory:<stage>``), so the
  end-of-scan verdict, ``adscan ci``'s exit status 3 and ``coverage.json`` all
  read the same record;
* the client-safe ``resource_coverage`` block is folded into the domain's
  ``domains_data`` entry (the session's view) and into
  ``technical_report.json`` (the persisted record the PDF, the LITE report and
  the web platform render, :func:`adscan_core.reporting.technical_report.record_resource_coverage`).

The terminal line naming the real cause is the boundary's job
(``MemoryCeilingReached.cause`` and ``.remedy``); nothing here prints to the
client or names the cause in client text.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from adscan_core import telemetry
from adscan_core.reporting.resource_coverage import (
    REASON_MEMORY,
    RESOURCE_COVERAGE_KEY,
    merge_stage_coverage,
    replace_stage_coverage,
)
from adscan_core.rich_output import print_exception


def _stage_of(block: Any) -> str:
    stages = block.get("stages") if isinstance(block, dict) else None
    if isinstance(stages, list) and stages and isinstance(stages[0], dict):
        return str(stages[0].get("stage") or "").strip().lower()
    return ""


def record_stage_coverage(
    shell: Any,
    domain: str,
    block: dict[str, Any],
    *,
    replace_stage: str | None = None,
) -> None:
    """Fold ``block`` into the domain's session record and its technical report.

    ``replace_stage`` sets or clears that one stage's entry instead of merging
    (see :func:`adscan_core.reporting.resource_coverage.replace_stage_coverage`).
    Never raises.
    """
    try:
        domains_data = getattr(shell, "domains_data", None)
        if isinstance(domains_data, dict) and domain:
            entry = domains_data.setdefault(domain, {})
            if isinstance(entry, dict):
                current = entry.get(RESOURCE_COVERAGE_KEY)
                merged = (
                    replace_stage_coverage(current, replace_stage, block)
                    if replace_stage
                    else merge_stage_coverage(current, block)
                )
                if merged.get("stages"):
                    entry[RESOURCE_COVERAGE_KEY] = merged
                else:
                    entry.pop(RESOURCE_COVERAGE_KEY, None)
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            record_resource_coverage,
        )

        record_resource_coverage(
            shell, domain, coverage=block, replace_stage=replace_stage
        )
    except Exception as exc:  # noqa: BLE001 - recording a stop must never raise
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


#: The scan phase a stopped stage leaves incomplete. The report and the
#: platform's own stages leave the assessment itself whole (a render can be
#: redone from the workspace), so they map to no phase.
_STAGE_PHASES: dict[str, str] = {
    "collection": "domain_collection",
    "graph_build": "domain_collection",
    "graph_export": "domain_collection",
    "attack_paths": "attack_paths_discovery",
}


def resource_coverage_gap_phases(shell: Any, domain: str) -> tuple[str, ...]:
    """The phases ``domain``'s recorded stops leave incomplete.

    Reads the session's record and the workspace's technical report (where a
    stop recorded under another session object lands). Never raises.
    """
    blocks: list[Any] = []
    try:
        domains_data = getattr(shell, "domains_data", None)
        entry = domains_data.get(domain) if isinstance(domains_data, dict) else None
        if isinstance(entry, dict):
            blocks.append(entry.get(RESOURCE_COVERAGE_KEY))
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            read_resource_coverage,
        )

        blocks.append(read_resource_coverage(shell, domain))
    except Exception:  # noqa: BLE001 - a coverage read never raises
        pass
    phases: list[str] = []
    for block in blocks:
        stages = block.get("stages") if isinstance(block, dict) else None
        for item in stages or ():
            if not isinstance(item, dict):
                continue
            phase = _STAGE_PHASES.get(str(item.get("stage") or "").strip().lower())
            if phase and phase not in phases:
                phases.append(phase)
    return tuple(phases)


def _names_stage(block: Any, key: str) -> bool:
    stages = block.get("stages") if isinstance(block, dict) else None
    return isinstance(stages, list) and any(
        isinstance(item, dict) and str(item.get("stage") or "").lower() == key
        for item in stages
    )


def clear_stage_coverage(shell: Any, domain: str, stage: str) -> None:
    """Forget an earlier stop of ``stage`` for ``domain``: it is being run again.

    A stage that completes in a later attempt (a re-run on a larger machine)
    must not keep declaring the earlier stop. Cheap when there is nothing to
    clear: only the session's record is read. Never raises.
    """
    try:
        key = str(stage or "").strip().lower()
        # The phase mark the stop left (``memory:<stage>``) goes with it, or a
        # stage that now completed would still fail the run (exit 3). Only this
        # stage's reason: another cause on the same phase still stands.
        phase = _STAGE_PHASES.get(key)
        if phase:
            from adscan_internal.services import scan_progress  # noqa: PLC0415

            scan_progress.drop_phase_incomplete_reason(
                shell, domain, phase, f"{REASON_MEMORY}:{key}"
            )
        domains_data = getattr(shell, "domains_data", None)
        entry = domains_data.get(domain) if isinstance(domains_data, dict) else None
        held = entry.get(RESOURCE_COVERAGE_KEY) if isinstance(entry, dict) else None
        if not _names_stage(held, key):
            # A stop an earlier process recorded may live only in the
            # workspace's technical report (the memoised read costs nothing
            # when the file has not changed).
            from adscan_internal.services.graph_availability import (  # noqa: PLC0415
                persisted_resource_coverage,
            )

            if not _names_stage(persisted_resource_coverage(shell, domain), key):
                return
        record_stage_coverage(
            shell, domain, {"complete": True, "stages": []}, replace_stage=key
        )
    except Exception as exc:  # noqa: BLE001 - clearing a stop must never raise
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def stage_stop_recorder(
    shell: Any,
    domain: str,
    *,
    phase_id: str,
    detail: str,
) -> Callable[[dict[str, Any]], None]:
    """The ``record`` callback for a stage of ``domain`` stopped at the ceiling.

    Args:
        shell: The session (``domains_data`` and the workspace's technical report).
        domain: The domain the stage ran for.
        phase_id: The scan phase the stop leaves incomplete
            (``domain_collection``, ``attack_paths_discovery``).
        detail: One operator-facing sentence saying what did not finish.
    """

    def _record(block: dict[str, Any]) -> None:
        stage = _stage_of(block) or "stage"
        try:
            from adscan_internal.services import scan_progress  # noqa: PLC0415

            scan_progress.mark_phase_incomplete(
                shell,
                domain,
                phase_id,
                reasons=(f"{REASON_MEMORY}:{stage}",),
                detail=detail,
            )
        except Exception as exc:  # noqa: BLE001 - recording a stop must never raise
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        record_stage_coverage(shell, domain, block)

    return _record


def collection_stop_recorder(
    shell: Any,
    domain: str,
    *,
    detail: str = "Domain collection stopped within the available memory.",
) -> Callable[[dict[str, Any]], None] | None:
    """The ``record`` callback of a COLLECTION stage of ``domain`` stopped at the ceiling.

    The directory read, the host sweep and the findings derivation at persist
    all record through this one callback: the collection phase is marked
    incomplete and the block is stamped with the run that stopped, so the rest
    of THIS run reads the stop
    (``graph_availability.collection_memory_stop_this_run``) and does not walk
    the collection result again, while a later run is not affected. ``None``
    without a session (lab scripts): the boundary still stops and declares.
    """
    if shell is None:
        return None
    from adscan_internal.services.collector.collection_integrity import (  # noqa: PLC0415
        COLLECTION_PHASE_ID,
    )
    from adscan_internal.services.graph_availability import stamp_this_run  # noqa: PLC0415

    record = stage_stop_recorder(shell, domain, phase_id=COLLECTION_PHASE_ID, detail=detail)

    def _record(block: dict[str, Any]) -> None:
        record(stamp_this_run(shell, block))

    return _record


__all__ = (
    "clear_stage_coverage",
    "collection_stop_recorder",
    "record_stage_coverage",
    "resource_coverage_gap_phases",
    "stage_stop_recorder",
)
