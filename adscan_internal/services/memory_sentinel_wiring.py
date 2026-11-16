"""The engine's side of the last-resort memory sentinel.

The sentinel itself lives in ``adscan_core.memory_guard`` (``start_memory_sentinel``):
a daemon thread that, at 95% of the memory ceiling, runs two registered callbacks
under a time budget and exits with the incomplete-run status. ``adscan_core``
never imports the engine, so the engine supplies the callbacks, and only the
engine's entry points start it (``adscan.py``: ``start``, ``ci``, ``execute``,
``recheck``). Never the web backend, never at import: an exit there would take
the web server down.

* :func:`record_stop`: the stop record, written as ONE small file
  (``adscan_core.reporting.memory_stop_record``): the stage, the domains, the
  ``resource_coverage`` block and the phase the stop leaves incomplete. The large
  workspace documents are not rewritten while memory is exhausted; the next
  reader folds the record in (:func:`apply_pending_memory_stop` at workspace
  load, the web ingestion when it reads the technical report).
* :func:`mark_exports_incomplete`: every open store's ``attack_graph.json`` is
  marked as not this run's export (``graph_build.export.mark_export_incomplete``),
  so no reader takes the previous graph for the current one.
"""

from __future__ import annotations

from typing import Any

from adscan_core import telemetry
from adscan_core.ci_exit_codes import CI_EXIT_ASSESSMENT_INCOMPLETE
from adscan_core.reporting.memory_stop_record import (
    STAGE_PHASES,
    marker_path_for,
    read_memory_stop_record,
    remove_memory_stop_record,
    write_memory_stop_record,
)
from adscan_core.rich_output import print_exception, print_info_debug

#: The engine entry points that start the sentinel.
SENTINEL_COMMANDS: frozenset[str] = frozenset({"start", "ci", "execute", "recheck"})

#: Phase a stage's stop leaves incomplete.
_STAGE_PHASES = STAGE_PHASES


def _sessions() -> list[Any]:
    """The sessions of this process: those holding a graph store, and the shell."""
    sessions: list[Any] = []
    try:
        from adscan_internal.services import graph_runtime  # noqa: PLC0415

        sessions.extend(graph_runtime.live_sessions())
    except Exception:  # noqa: BLE001
        pass
    try:
        from adscan_internal.services import dc_time  # noqa: PLC0415

        shell = getattr(dc_time, "_ACTIVE_CLOCK_SHELL", None)
        if shell is not None and shell not in sessions:
            sessions.append(shell)
    except Exception:  # noqa: BLE001
        pass
    return sessions


def _active_domains(shell: Any) -> list[str]:
    """Domains whose scan is running in this session, else the session's domain."""
    domains_data = getattr(shell, "domains_data", None)
    running: list[str] = []
    if isinstance(domains_data, dict):
        for name, entry in list(domains_data.items()):
            progress = entry.get("scan_progress") if isinstance(entry, dict) else None
            if isinstance(progress, dict) and progress.get("status") == "running":
                running.append(str(name))
    if running:
        return running
    current = str(getattr(shell, "domain", "") or "").strip()
    if current:
        return [current]
    return [str(name) for name in domains_data] if isinstance(domains_data, dict) else []


def record_stop(stop: Any) -> None:
    """Sentinel callback: write the stop record of every session's workspace."""
    stage = str(getattr(stop, "stage", "") or "")
    coverage = getattr(stop, "coverage", None) or {}
    for shell in _sessions():
        workspace = getattr(shell, "current_workspace_dir", None)
        if not workspace:
            continue
        write_memory_stop_record(
            workspace,
            domains=_active_domains(shell),
            stage=stage,
            coverage=coverage,
            phase_id=_STAGE_PHASES.get(stage, ""),
        )


def mark_exports_incomplete(stop: Any) -> None:
    """Sentinel callback: mark every open store's export as not this run's."""
    from adscan_internal.services import graph_runtime  # noqa: PLC0415

    block = {"stage": str(getattr(stop, "stage", "") or ""), "reason": "memory"}
    seen: set[int] = set()  # an entry shared by several sessions is marked once
    for shell in _sessions():
        graph_runtime.mark_open_exports_incomplete(shell, block, seen=seen)


def point_sentinel_marker_at(workspace_dir: str | None) -> None:
    """Point the running sentinel's marker at ``workspace_dir`` (``None`` clears).

    Called at every workspace activation (``workspaces.session.activate_workspace``
    and the workspace loader), which covers the platform's execution workspace
    ``.run_*`` (the shell's workspace during a platform scan). A no-op when this
    process runs no sentinel. Never raises.
    """
    try:
        from adscan_core.memory_guard import (  # noqa: PLC0415
            memory_sentinel,
            set_sentinel_marker_path,
        )

        if memory_sentinel() is None:
            return
        set_sentinel_marker_path(marker_path_for(workspace_dir) if workspace_dir else None)
    except Exception:  # noqa: BLE001 - the marker is a last resort
        return


def start_engine_memory_sentinel(command: str, workspace_dir: str | None = None) -> Any:
    """Start the sentinel for an engine entry point (``SENTINEL_COMMANDS``).

    Returns the sentinel, or ``None`` for another command or when the primitive
    is unavailable. Never raises: a run without the sentinel is still guarded
    stage by stage.
    """
    if command not in SENTINEL_COMMANDS:
        return None
    try:
        from adscan_core.memory_guard import start_memory_sentinel  # noqa: PLC0415
    except ImportError:
        print_info_debug("memory sentinel unavailable in this build")
        return None
    try:
        sentinel = start_memory_sentinel(
            CI_EXIT_ASSESSMENT_INCOMPLETE,
            record_stop=record_stop,
            mark_export_incomplete=mark_exports_incomplete,
            marker_path=marker_path_for(workspace_dir) if workspace_dir else None,
        )
        # Below the supported floor the sentinel can lose the race against a
        # fast-growing stage: say so once, at the start of the run.
        from adscan_core.memory_guard import warn_if_below_supported_floor  # noqa: PLC0415

        warn_if_below_supported_floor()
        return sentinel
    except Exception as exc:  # noqa: BLE001 - the sentinel is a last resort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def apply_pending_memory_stop(shell: Any, workspace_dir: str | None = None) -> bool:
    """Fold a stop the sentinel left into the workspace, then remove it.

    The full record when it was written; otherwise the sentinel's marker alone
    ("stopped for memory, record not written"), declared with its stage and
    progress unknown for every domain the run was assessing. For each domain:
    the phase is marked incomplete (the stage's phase, else the run-level
    ``run_stopped`` mark: a stop with no phase never names one it did not occur in) and the ``resource_coverage`` block recorded.
    Then the record and the marker are removed. Returns whether a stop was
    applied. Never raises.
    """
    directory = workspace_dir or getattr(shell, "current_workspace_dir", None)
    if not directory:
        return False
    record = read_memory_stop_record(directory)
    if record is None:
        return False
    try:
        from adscan_internal.services import scan_progress  # noqa: PLC0415
        from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
            record_stage_coverage,
        )

        from adscan_internal.services import graph_runtime  # noqa: PLC0415

        stage = str(record.get("stage") or "")
        domains = list(record.get("domains") or ()) or _active_domains(shell)
        for domain in domains:
            # The sentinel's own mark runs under a three-second budget and
            # stream-copies the whole file, so on a large export it usually ran
            # out and left the previous graph unmarked (and maybe a partial
            # temporary copy). Here there is no time pressure: mark it now.
            graph_runtime.mark_domain_export_not_current(
                shell,
                directory,
                str(domain),
                {"stage": stage or "unknown", "reason": "memory"},
            )
            # The coverage block first: it creates ``technical_report.json``, which
            # the phase mark then mirrors its verdict into.
            record_stage_coverage(shell, domain, record["resource_coverage"])
            phase = str(record.get("phase_id") or "") or _STAGE_PHASES.get(stage, "")
            if phase:
                scan_progress.mark_phase_incomplete(
                    shell,
                    domain,
                    phase,
                    reasons=(f"memory:{stage or 'unknown'}",),
                    detail="The run stopped at the memory ceiling and recorded where it stopped.",
                )
            else:
                # No phase to attribute the stop to (a stop in work no scan phase
                # owns, or a marker-only record): never name one it did not
                # occur in. The run-level mark keeps the exit status and the
                # incomplete-phase lists honest.
                scan_progress.mark_phase_incomplete(
                    shell,
                    domain,
                    scan_progress.UNATTRIBUTED_STOP_PHASE_ID,
                    reasons=(f"memory:{stage or 'unknown'}",),
                    detail="The run stopped before it finished and where it stopped was not recorded.",
                )
        remove_memory_stop_record(directory)
        return True
    except Exception as exc:  # noqa: BLE001 - folding never breaks a workspace load
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


__all__ = (
    "SENTINEL_COMMANDS",
    "apply_pending_memory_stop",
    "point_sentinel_marker_at",
    "mark_exports_incomplete",
    "record_stop",
    "start_engine_memory_sentinel",
)
