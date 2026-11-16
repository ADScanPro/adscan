"""Host-granular Domain-Collection progress (SSOT for the crash-resume record).

Domain Collection (the per-host SMB enrichment sweep) is the longest scan phase
and the single most likely Ctrl+C / crash point. Since the inventory-first
graph store, every swept host is committed to the domain's store as its own
unit the moment it is merged (``collector.store_writer.HostUnitCommitter``):
the unit carries the host's facts AND its done-mark in one transaction, so the
resume skip-set is the store's committed hosts (:func:`resumed_done_ids`) and
nothing has to be ordered by hand.

This module keeps the sweep's RECORD in ``domains_data`` (status, totals), which
the start-of-run resume notice and the platform's resume state read::

    domains_data[<domain>]["collection_progress"] = {
        "status": "running" | "complete",     # running left behind == interrupted
        "hosts_total": 1847,                   # dispatch set size at sweep start
        "hosts_done_count": 312,               # hosts committed (a count, never the list)
        "host_cap": 0,                         # cap in force (0 = full)
        "scan_type": "audit",                  # engagement type at launch
        "updated_at": "2026-07-13T14:05:00Z",  # ISO-8601 UTC
    }

A 14.0.x record carried the done SET as ``hosts_done`` (a list of SIDs); it is
dropped on the next sweep start and never read: those hosts' edges live in the
14.0.x graph file, not in the store, so they are swept again.

Hard invariant (enforced by tests): **no ``_`` prefix.**
``collect_workspace_variables_from_shell`` drops every ``domains_data`` key
starting with ``_`` before writing ``variables.json``, and the record must
survive a crash, so its key is bare.

All helpers are fail-open: a malformed record, a shell without ``domains_data``
or an unreadable store degrades to "not started" (a fresh full sweep), never an
exception that breaks the scan. The store is reached lazily through
``graph_runtime``; nothing else of the engine is imported.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Iterable

# Persisted key under ``domains_data[domain]`` — deliberately NOT ``_``-prefixed
# so the state serializer keeps it (see module docstring).
COLLECTION_PROGRESS_KEY = "collection_progress"

# Status values. ``running`` left behind on next load == an interrupted sweep
# (the clean end always overwrites it with ``complete``).
STATUS_RUNNING = "running"
STATUS_COMPLETE = "complete"

# Operator escape hatch: force a fresh full sweep, ignoring (and discarding) the
# resume cursor of a prior interrupted run. This is the explicit opt-out named in
# the start-of-run resume notice — a re-scan is a deliberate choice, never a
# prompt. Honoured at the single seam where the skip-set is derived
# (:func:`resumed_done_ids`), so every consumer inherits it.
COLLECTOR_FRESH_ENV = "ADSCAN_COLLECTOR_FRESH"


def collector_fresh_requested() -> bool:
    """Return True when the operator asked for a fresh full sweep (no resume).

    Reads :data:`COLLECTOR_FRESH_ENV` with the collector's usual truthy idiom
    (``1``/``true``/``yes``/``on``). Fail-open: an unreadable environment reads
    as "not requested" (the default resume behaviour).
    """
    try:
        return os.getenv(COLLECTOR_FRESH_ENV, "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
    except Exception:  # noqa: BLE001 — env read must never break the scan
        return False


def _now_iso() -> str:
    """Return the current time as an ISO-8601 UTC string (same source as scan_progress)."""
    return datetime.now(timezone.utc).isoformat()


def _domain_data(shell: Any, domain: str) -> dict[str, Any] | None:
    """Return the mutable ``domains_data[domain]`` dict, creating it if needed.

    Returns ``None`` only when the shell has no usable ``domains_data`` mapping,
    in which case the caller no-ops (fail-open).
    """
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    entry = domains_data.get(domain)
    if not isinstance(entry, dict):
        entry = {}
        domains_data[domain] = entry
    return entry


def read_collection_progress(shell: Any, domain: str) -> dict[str, Any]:
    """Return the persisted ``collection_progress`` record, or ``{}`` when absent."""
    try:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return {}
        entry = domains_data.get(domain)
        if not isinstance(entry, dict):
            return {}
        record = entry.get(COLLECTION_PROGRESS_KEY)
        return dict(record) if isinstance(record, dict) else {}
    except Exception:  # noqa: BLE001 — a read must never break the scan
        return {}


def is_incomplete(shell: Any, domain: str) -> bool:
    """Return True when a persisted sweep is resumable (status still ``running``).

    A ``running`` record on load means the previous run died before writing
    ``complete`` — an interrupted collection the operator can resume.
    """
    return read_collection_progress(shell, domain).get("status") == STATUS_RUNNING


def mark_collection_running(
    shell: Any,
    domain: str,
    *,
    scan_type: str | None = None,
    hosts_total: int = 0,
    host_cap: int = 0,
) -> None:
    """Mark the collection sweep as running; initialize the record on first entry.

    Idempotent: re-entering an interrupted sweep refreshes ``hosts_total`` /
    ``host_cap`` / ``scan_type`` for the current run (the host cursor itself is
    the graph store's, untouched here). Persists immediately so the resumable ``running`` marker is
    durable the moment the sweep starts, independent of the 5 s auto-save.
    """
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(COLLECTION_PROGRESS_KEY)
    if not isinstance(record, dict):
        record = {}
    record["status"] = STATUS_RUNNING
    # The done SET lives in the graph store (``resumed_done_ids``); a list left
    # by a 14.0.x run would only mislead a reader.
    record.pop("hosts_done", None)
    record["hosts_total"] = int(hosts_total or 0)
    record["host_cap"] = int(host_cap or 0)
    if scan_type is not None:
        record["scan_type"] = scan_type
    record["updated_at"] = _now_iso()
    entry[COLLECTION_PROGRESS_KEY] = record
    _debug(
        f"mark_collection_running domain={domain} hosts_total={record['hosts_total']} "
        f"host_cap={record['host_cap']} -> persisting"
    )
    _best_effort_save(shell)


def checkpoint_collection_progress(shell: Any, domain: str) -> None:
    """Flush the ``collection_progress`` record to disk now.

    No-op when no record exists. Never raises.
    """
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(COLLECTION_PROGRESS_KEY)
    if not isinstance(record, dict):
        return
    record["updated_at"] = _now_iso()
    entry[COLLECTION_PROGRESS_KEY] = record
    _debug(
        f"checkpoint_collection_progress domain={domain} "
        f"done_count={record.get('hosts_done_count', 0)} -> flushing"
    )
    _best_effort_save(shell)


def mark_collection_complete(shell: Any, domain: str) -> None:
    """Mark the sweep cleanly finished so the reload resume offer stops.

    Only flips ``status`` to ``complete``. The resume skip-set follows the
    store's own stage state (a sweep whose stages ended ``complete`` is never
    resumed), so the next collection is a full sweep.
    """
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(COLLECTION_PROGRESS_KEY)
    if not isinstance(record, dict):
        record = {}
    record["status"] = STATUS_COMPLETE
    record["updated_at"] = _now_iso()
    entry[COLLECTION_PROGRESS_KEY] = record
    _best_effort_save(shell)


def reset_collection_progress(shell: Any, domain: str) -> None:
    """Remove the record so a deliberate re-run (fresh scan) re-collects every host."""
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    entry.pop(COLLECTION_PROGRESS_KEY, None)


#: Store stages whose committed units are a swept host's done-mark (the
#: ``graph_store.records`` names, spelled here so this module stays
#: dependency-light).
_HOST_SWEEP_STAGES: tuple[str, ...] = ("smb_hosts",)


def resumed_done_ids(
    shell: Any, domain: str, *, stages: Iterable[str] | None = None
) -> frozenset[str]:
    """Return the upper-cased host ids to skip on resume, or an empty set.

    The done-set is the domain's graph store: a host is done when its unit of
    EVERY sweep stage in ``stages`` (default: the SAMR stage, ``smb_hosts``)
    committed, which is the same transaction as its facts, so a done host is
    never ahead of its sessions, local groups or shares. Nothing is read from
    ``variables.json``: a 14.0.x workspace whose interrupted sweep kept its
    done-set there is swept again in full, because the hosts it lists have
    their edges in the 14.0.x graph file, not in the store.

    Only a sweep that did not finish yields skip entries: when every stage of
    ``stages`` last ended ``complete``, the set is empty and the next sweep
    re-collects every host (each host's unit is replaced as it is collected).

    Honours the :data:`COLLECTOR_FRESH_ENV` escape hatch: an empty set, and the
    resumable record is discarded (the orchestrator also begins the sweep's
    stages ``fresh``, which drops their units).
    """
    if collector_fresh_requested():
        reset_collection_progress(shell, domain)
        return frozenset()
    wanted = tuple(stages) if stages is not None else _HOST_SWEEP_STAGES
    if not wanted:
        return frozenset()
    try:
        from adscan_internal.services.graph_runtime import graph_store_for  # noqa: PLC0415

        store = graph_store_for(shell, domain, create=False)
        if store is None:
            return frozenset()
        runs = {run.stage: run for run in store.stage_runs()}
        if all(getattr(runs.get(stage), "status", "") == "complete" for stage in wanted):
            return frozenset()
        if not all(stage in runs for stage in wanted):
            return frozenset()
        done: frozenset[str] | None = None
        for stage in wanted:
            units = frozenset(str(unit).upper() for unit in store.done_units(stage))
            done = units if done is None else done & units
        return done or frozenset()
    except Exception as exc:  # noqa: BLE001 — a read must never break the scan
        _debug(f"resumed_done_ids: store unreadable ({type(exc).__name__}); full sweep")
        return frozenset()


def record_hosts_done_count(shell: Any, domain: str, count: int) -> None:
    """Record how many hosts the sweep has committed (a count, never the list).

    The ``collection_progress`` record keeps the sweep's status and totals for
    the resume notice and the platform's resume state; the done SET lives in
    the graph store. Not persisted here (the caller's next save carries it).
    """
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(COLLECTION_PROGRESS_KEY)
    if not isinstance(record, dict):
        return
    record["hosts_done_count"] = int(count or 0)
    record.pop("hosts_done", None)
    record["updated_at"] = _now_iso()
    entry[COLLECTION_PROGRESS_KEY] = record


def resume_notice_counts(shell: Any, domain: str) -> tuple[int, int, int] | None:
    """Return ``(already_done, total, remaining)`` for a resumable sweep, else None.

    The START-of-run mirror of the END-of-run host-enrichment coverage: it reports
    how many hosts a prior interrupted session already enriched (``already_done``),
    the full swept set that run recorded (``total``), and what is left to sweep now
    (``remaining``). Returns ``None`` when there is nothing to resume — a fresh or
    finished workspace, or a run for which the operator requested a fresh full
    sweep — so the caller emits no notice and a fresh workspace is byte-for-byte
    unchanged.

    ``total`` is read from the interrupted run's recorded ``hosts_total`` (the full
    post-cap dispatch set, stable across the run and its resume). An older record
    with a missing/too-small total falls back to the done-count so the counts are
    always internally consistent (``remaining`` never goes negative).
    """
    done_ids = resumed_done_ids(shell, domain)
    already_done = len(done_ids)
    if already_done <= 0:
        return None
    record = read_collection_progress(shell, domain)
    try:
        total = int(record.get("hosts_total") or 0)
    except (TypeError, ValueError):
        total = 0
    total = max(total, already_done)
    remaining = max(0, total - already_done)
    return already_done, total, remaining


def remaining_host_ids(
    shell: Any, domain: str, dispatch_ids: Iterable[str]
) -> list[str]:
    """Return the dispatch ids NOT yet collected (dispatch minus done, upper-compare).

    Set math over the resumed done-set; preserves the input order. A done host is
    never re-added — the done-set is a strict skip filter, so a ``host_cap``
    mismatch between the interrupted run and the resume can never drop a done host
    (it only ever removes ids from the remaining set).
    """
    done = resumed_done_ids(shell, domain)
    return [d for d in dispatch_ids if str(d).upper() not in done]


def _debug(msg: str) -> None:
    """Greppable, --debug-only checkpoint trace (best-effort; never raises)."""
    try:
        from adscan_core.rich_output import print_info_debug

        print_info_debug(f"collection-progress: {msg}")
    except Exception:  # noqa: BLE001 — logging must never break the scan
        pass


def _best_effort_save(shell: Any) -> None:
    """Persist the workspace now (belt-and-suspenders over the 5 s auto-save).

    A done-set flush written just before a crash would otherwise be lost within
    the auto-save window, re-collecting the hosts on resume. Never raises.
    """
    save = getattr(shell, "workspace_save", None)
    if not callable(save):
        _debug("_best_effort_save SKIPPED — shell has no callable workspace_save")
        return
    try:
        save()
        _debug("_best_effort_save OK — workspace_save() ran")
    except Exception as exc:  # noqa: BLE001 — a save failure must never break the scan
        _debug(f"_best_effort_save FAILED — {type(exc).__name__}: {exc}")
