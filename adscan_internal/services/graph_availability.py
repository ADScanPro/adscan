"""Is this domain's graph available? The engine's side of the one predicate.

A build stopped at the memory ceiling hands every reader an EMPTY graph for the
rest of the session (``graph_runtime._stopped_graph``), and a directory read
stopped at the ceiling leaves the store with an earlier inventory or none. A
reader that computes over either (attack-path discovery, the KPIs, the exposure
score, the choke points, the remediation ranking, the reports) states "0 routes"
or a clean score next to a sentence saying the build stopped: a stop read as a
complete result, the exact falsehood the Exposure-Validation doctrine forbids.

So every such reader asks :func:`domain_graph_unavailable_stage` first and, when
it answers a stage, declares its own result NOT EVALUATED (naming that stage)
instead of computing, and writes no cache. The decision itself is the shared,
dependency-light :func:`adscan_core.reporting.resource_coverage.graph_unavailable_stage`
(the web backend calls it on the same persisted block); this module only gathers
its inputs from an engine session:

* the graph the reader holds, when it has one (the flag the stopped graph
  carries, or a file marked not current);
* this process's graph runtime (:func:`graph_runtime.graph_build_stopped`), so a
  stop is seen before anything was written to disk;
* the session's ``domains_data`` record and the workspace's
  ``technical_report.json`` (a stop recorded under another session object, such
  as the report's own shell, lands only there). The persisted read is memoised
  on the file's size and modification time, so asking costs nothing per call.

Nothing here is bound to an event loop; the memo is guarded by a
``threading.Lock``.
"""

from __future__ import annotations

import os
import threading
import uuid
from typing import Any

from adscan_core import telemetry
from adscan_core.reporting.resource_coverage import (
    RESOURCE_COVERAGE_KEY,
    STAGE_COLLECTION,
    STAGE_GRAPH_BUILD,
    STAGE_GRAPH_EXPORT,
    graph_unavailable_stage,
    stopped_in_run,
)
from adscan_core.rich_output import mark_sensitive, print_exception, print_info_debug

#: ``(report path, mtime_ns, size)`` -> ``{domain: resource_coverage block}``.
_PERSISTED_MEMO: dict[tuple[str, int, int], dict[str, Any]] = {}
_PERSISTED_MEMO_LOCK = threading.Lock()
#: Report files whose blocks are memoised at once (one per workspace in use).
_PERSISTED_MEMO_MAX = 8


def _persisted_blocks(shell: Any) -> dict[str, Any]:
    """``{domain: resource_coverage}`` from the workspace's technical report."""
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            _get_technical_report_path,
            _load_technical_report,
        )

        path = _get_technical_report_path(shell)
        stat = os.stat(path)
    except (OSError, TypeError, ValueError):
        return {}
    key = (str(path), int(stat.st_mtime_ns), int(stat.st_size))
    with _PERSISTED_MEMO_LOCK:
        held = _PERSISTED_MEMO.get(key)
    if held is not None:
        return held
    blocks: dict[str, Any] = {}
    try:
        report = _load_technical_report(shell)
        domains = report.get("domains") if isinstance(report, dict) else None
        if isinstance(domains, dict):
            for name, entry in domains.items():
                block = entry.get(RESOURCE_COVERAGE_KEY) if isinstance(entry, dict) else None
                if isinstance(block, dict):
                    blocks[str(name)] = block
    except Exception as exc:  # noqa: BLE001 - an unreadable report adds no stop
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}
    with _PERSISTED_MEMO_LOCK:
        _PERSISTED_MEMO[key] = blocks
        while len(_PERSISTED_MEMO) > _PERSISTED_MEMO_MAX:
            _PERSISTED_MEMO.pop(next(iter(_PERSISTED_MEMO)))
    return blocks


def persisted_resource_coverage(shell: Any, domain: str) -> Any:
    """``domain``'s ``resource_coverage`` block as the workspace's technical
    report holds it (memoised on the file's size and modification time)."""
    return _persisted_blocks(shell).get(str(domain or "").strip())


def _session_block(shell: Any, domain: str) -> Any:
    domains_data = getattr(shell, "domains_data", None)
    entry = domains_data.get(domain) if isinstance(domains_data, dict) else None
    return entry.get(RESOURCE_COVERAGE_KEY) if isinstance(entry, dict) else None


def domain_graph_unavailable_stage(shell: Any, domain: str, *, graph: Any = None) -> str:
    """The upstream stage that left ``domain`` without a graph, or ``""``.

    Args:
        shell: The session (any object ``technical_report`` and
            ``graph_runtime`` accept: a ``PentestShell``, a report shell, a
            ``SimpleNamespace`` carrying ``current_workspace_dir``).
        domain: The domain asked about.
        graph: The graph the reader already holds, when it has one.

    Returns:
        ``graph_build`` or ``collection`` when the graph is not available, else
        ``""``. Never raises: an unreadable input answers "available", because
        every input here is a record of a stop, and none recorded means none
        happened.
    """
    domain = str(domain or "").strip()
    if not domain:
        return ""
    try:
        stage = graph_unavailable_stage(graph=graph)
        if stage:
            return stage
        from adscan_internal.services import graph_runtime  # noqa: PLC0415

        if graph_runtime.graph_build_stopped(shell, domain):
            return STAGE_GRAPH_BUILD
        stage = graph_unavailable_stage(_session_block(shell, domain))
        if stage:
            return stage
        return graph_unavailable_stage(_persisted_blocks(shell).get(domain))
    except Exception as exc:  # noqa: BLE001 - the question never breaks a reader
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ""


#: The run identity of an invocation that records no engagement run (an
#: unrecorded REPL session, a bench, a test): one per process, which is that
#: invocation's run.
_PROCESS_RUN_TOKEN = f"process:{uuid.uuid4().hex}"


def current_run_token(shell: Any) -> str:
    """The identity of the run ``shell`` writes for.

    The recorded engagement run when one is active for the shell or its
    workspace (``coverage_recorder.active_run_id``, the id stamped on the run's
    artifacts), else this process's own token. A later run, in this process or
    another, has a different identity. Never raises.
    """
    try:
        from adscan_internal.services.engagement.coverage_recorder import (  # noqa: PLC0415
            active_run_id,
        )

        run = str(active_run_id(shell) or "").strip()
    except Exception as exc:  # noqa: BLE001 - no recorder: the process is the run
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        run = ""
    return run or _PROCESS_RUN_TOKEN


def graph_build_stopped_this_run(shell: Any, domain: str) -> bool:
    """Whether a build of ``domain``'s graph already stopped at the memory
    ceiling in THIS run (:func:`current_run_token`), as recorded in the
    session's or the workspace's ``resource_coverage``.

    The same run must not climb to the ceiling a second time when a later
    reader reopens the store (the report after the export closed the session's
    store); a later run builds normally and clears the stop. Never raises.
    """
    domain = str(domain or "").strip()
    if not domain:
        return False
    run = current_run_token(shell)
    try:
        return stopped_in_run(_session_block(shell, domain), STAGE_GRAPH_BUILD, run) or (
            stopped_in_run(_persisted_blocks(shell).get(domain), STAGE_GRAPH_BUILD, run)
        )
    except Exception as exc:  # noqa: BLE001 - the question never breaks a reader
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


#: The stages whose memory stop is about the in-memory collection result and the
#: graph built from it: after one of them stopped in a run, nothing later in the
#: same run walks that result again in full.
COLLECTION_MEMORY_STAGES: tuple[str, ...] = (
    STAGE_COLLECTION,
    STAGE_GRAPH_BUILD,
    STAGE_GRAPH_EXPORT,
)


def collection_memory_stop_this_run(shell: Any, domain: str) -> str:
    """The collection or graph stage of ``domain`` that stopped at the memory
    ceiling in THIS run (:func:`current_run_token`), or ``""``.

    A stop is a state the rest of the run reads, not a message: once the
    directory read, the host sweep, the findings derivation, the graph build or
    its export stopped, the data that stage was protecting is still in memory
    (the collection result) and memory is at the line. A later step of the same
    run that would walk that whole result again (the end-of-domain persist's
    findings derivation) reads this first and does not climb back to the
    ceiling. Stops are matched on the run identity stamped when they were
    recorded, so a stop left by an earlier run never suppresses work in this
    one. Never raises.
    """
    domain = str(domain or "").strip()
    if not domain or shell is None:
        return ""
    try:
        from adscan_internal.services import graph_runtime  # noqa: PLC0415

        if graph_runtime.graph_build_stopped(shell, domain):
            return STAGE_GRAPH_BUILD
        run = current_run_token(shell)
        blocks = (_session_block(shell, domain), _persisted_blocks(shell).get(domain))
        for stage in COLLECTION_MEMORY_STAGES:
            if any(stopped_in_run(block, stage, run) for block in blocks):
                return stage
        return ""
    except Exception as exc:  # noqa: BLE001 - the question never breaks a caller
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ""


def stamp_this_run(shell: Any, block: Any) -> Any:
    """``block`` with every stage entry naming the run ``shell`` writes for.

    The ``record`` side of :func:`collection_memory_stop_this_run`: a stop
    recorded without its run identity cannot be told apart from an earlier
    run's. Returns ``block`` unchanged when it cannot be stamped.
    """
    from adscan_core.reporting.resource_coverage import stamp_stop_run  # noqa: PLC0415

    return stamp_stop_run(block, current_run_token(shell))


def declare_attack_paths_not_evaluated(
    shell: Any, domain: str, upstream: str, *, scope: str | None = "domain"
) -> None:
    """Record that attack-path discovery did not run for ``domain``.

    Through the ONE writer of the per-domain ``attack_path_coverage`` block
    (``attack_graph_service._record_attack_path_coverage_for_compute``), so the
    scope rules hold (a non-canonical query never relabels the domain listing)
    and the block is mirrored into ``resource_coverage`` with the phase marked
    incomplete: a later complete computation clears both. Best-effort.
    """
    try:
        from adscan_core.reporting.attack_path_coverage import (  # noqa: PLC0415
            AttackPathCoverage,
        )
        from adscan_internal.services import attack_graph_service  # noqa: PLC0415

        print_info_debug(
            "[attack_paths] not evaluated: the graph of "
            f"{mark_sensitive(domain, 'domain')} is not available (upstream={upstream})"
        )
        attack_graph_service._record_attack_path_coverage_for_compute(  # noqa: SLF001
            shell,
            domain,
            AttackPathCoverage.not_evaluated(upstream),
            scope=scope,
        )
    except Exception as exc:  # noqa: BLE001 - a declaration never breaks a reader
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def clear_route_derived_figures(shell: Any, domain: str) -> list[str]:
    """Remove ``domain``'s route-derived report blocks (score, KPIs, choke points).

    An earlier run's figures describe a graph this run did not have; a figure
    computed over the empty graph would read as a clean domain. Neither may
    stand, so the blocks go and the not-evaluated declaration stands alone.
    Best-effort: returns the keys removed.
    """
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            clear_route_derived_blocks,
        )

        return clear_route_derived_blocks(shell, domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []


__all__ = (
    "COLLECTION_MEMORY_STAGES",
    "clear_route_derived_figures",
    "collection_memory_stop_this_run",
    "current_run_token",
    "graph_build_stopped_this_run",
    "declare_attack_paths_not_evaluated",
    "domain_graph_unavailable_stage",
    "stamp_this_run",
)
