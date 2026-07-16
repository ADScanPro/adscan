"""Centralized host-granular Domain-Collection checkpoint (SSOT for crash-resume).

Domain Collection (the per-host SMB enrichment sweep) is the longest scan phase
and therefore the single most likely Ctrl+C / crash point. Unlike the enumeration
phases — which the per-phase :mod:`adscan_internal.services.scan_progress`
checkpoint already covers — collection runs OUTSIDE ``run_enumeration`` and
persists its graph only ONCE at the end, so an interruption mid-sweep loses every
host enriched so far and re-runs the whole sweep on reload.

This module is the durable HOST cursor for that sweep. It records which host
object_ids were enriched so a reload can skip them and continue with the
remaining hosts, merging into the partial graph. It is modeled 1:1 on
``scan_progress`` — same status vocabulary, same list-not-set rule, same
fail-open reads, same ``_best_effort_save`` — but keyed at HOST granularity
(a set of done host ids) rather than PHASE granularity (a list of phase ids).
The two never overlap: ``collection_progress`` is only ever ``running`` before
the first enumeration phase starts, at which point the phase-level checkpoint
takes over.

The record::

    domains_data[<domain>]["collection_progress"] = {
        "status": "running" | "complete",     # running left behind == interrupted
        "hosts_total": 1847,                   # dispatch set size at sweep start
        "hosts_done": ["S-1-5-21-…-1104", …],  # OBJECT_IDs enriched (a JSON LIST)
        "host_cap": 0,                         # cap in force (0 = full)
        "scan_type": "audit",                  # engagement type at launch
        "updated_at": "2026-07-13T14:05:00Z",  # ISO-8601 UTC
    }

The host key is the graph node's ``object_id`` (the SID): it is the stable,
alias-independent node key ``CollectionResult.add_node`` writes against
(``self.nodes[object_id.upper()]``) and survives IP/DNS churn between runs — do
NOT key by IP or hostname (both drift).

Hard invariants (both enforced by tests):

* **No ``_`` prefix.** ``collect_workspace_variables_from_shell`` drops every
  ``domains_data`` key starting with ``_`` before writing ``variables.json``
  (runtime-only convention). ``collection_progress`` must survive a crash, so its
  key is bare.
* **``hosts_done`` is a JSON list, never a ``set``.** A ``set`` in
  ``domains_data`` breaks ``save_workspace_data`` (JSON serialization).

The module is dependency-light — it never imports the engine, the collector, or
the native stack — so it is safe for any consumer. All helpers are fail-open: a
malformed record or a shell without ``domains_data`` degrades to "not started"
(a fresh full sweep), never an exception that breaks the scan.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

# Persisted key under ``domains_data[domain]`` — deliberately NOT ``_``-prefixed
# so the state serializer keeps it (see module docstring).
COLLECTION_PROGRESS_KEY = "collection_progress"

# Status values. ``running`` left behind on next load == an interrupted sweep
# (the clean end always overwrites it with ``complete``).
STATUS_RUNNING = "running"
STATUS_COMPLETE = "complete"


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

    Idempotent and resume-safe: a pre-existing ``hosts_done`` list is PRESERVED
    (never wiped), so re-entering an interrupted sweep keeps the host cursor
    intact while ``hosts_total`` / ``host_cap`` / ``scan_type`` are refreshed for
    the current run. Persists immediately so the resumable ``running`` marker is
    durable the moment the sweep starts, independent of the 5 s auto-save.
    """
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(COLLECTION_PROGRESS_KEY)
    if not isinstance(record, dict):
        record = {}
    record["status"] = STATUS_RUNNING
    if not isinstance(record.get("hosts_done"), list):
        record["hosts_done"] = []
    record["hosts_total"] = int(hosts_total or 0)
    record["host_cap"] = int(host_cap or 0)
    if scan_type is not None:
        record["scan_type"] = scan_type
    record["updated_at"] = _now_iso()
    entry[COLLECTION_PROGRESS_KEY] = record
    _debug(
        f"mark_collection_running domain={domain} hosts_total={record['hosts_total']} "
        f"host_cap={record['host_cap']} done={len(record['hosts_done'])} -> persisting"
    )
    _best_effort_save(shell)


def mark_host_done(shell: Any, domain: str, object_id: str) -> None:
    """Record ``object_id`` as an enriched host (idempotent; cadence-buffered save).

    Appends the host's graph ``object_id`` (upper-cased for alias-independent
    comparison) to the in-memory ``hosts_done`` list. Deliberately does NOT
    persist per host — at 1-2k hosts a per-host ``workspace_save`` would be pure
    write amplification. The flush is buffered and performed on a cadence by
    :func:`checkpoint_collection_progress` (AFTER the partial graph is persisted,
    so a done-id never reaches disk ahead of the host's edges). Fail-open.
    """
    if not object_id:
        return
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(COLLECTION_PROGRESS_KEY)
    if not isinstance(record, dict):
        # A host-done without a prior mark_collection_running still records
        # progress rather than dropping it.
        record = {"status": STATUS_RUNNING, "hosts_done": []}
    done = record.get("hosts_done")
    if not isinstance(done, list):
        done = []
    oid = str(object_id).upper()
    if oid not in done:  # idempotent
        done.append(oid)
    record["hosts_done"] = done
    record["updated_at"] = _now_iso()
    entry[COLLECTION_PROGRESS_KEY] = record


def checkpoint_collection_progress(shell: Any, domain: str) -> None:
    """Flush the buffered ``collection_progress`` record to disk (the cadence flush).

    Call ONLY after the partial graph has been persisted — the ordering is
    load-bearing: a ``hosts_done`` id must never reach disk ahead of the host's
    edges, or a resume would skip a host whose enrichment was never persisted and
    silently drop it. No-op when no record exists. Never raises.
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
        f"done={len(record.get('hosts_done') or [])} -> flushing"
    )
    _best_effort_save(shell)


def mark_collection_complete(shell: Any, domain: str) -> None:
    """Mark the sweep cleanly finished so the reload resume offer stops.

    Retains ``hosts_done`` (history), only flips ``status`` to ``complete``. Once
    complete the record is never resumed (``resumed_done_ids`` returns empty for a
    non-``running`` record), so the next collection is a fresh full sweep.
    """
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(COLLECTION_PROGRESS_KEY)
    if not isinstance(record, dict):
        record = {"hosts_done": []}
    record["status"] = STATUS_COMPLETE
    if not isinstance(record.get("hosts_done"), list):
        record["hosts_done"] = []
    record["updated_at"] = _now_iso()
    entry[COLLECTION_PROGRESS_KEY] = record
    _best_effort_save(shell)


def reset_collection_progress(shell: Any, domain: str) -> None:
    """Remove the record so a deliberate re-run (fresh scan) re-collects every host."""
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    entry.pop(COLLECTION_PROGRESS_KEY, None)


def resumed_done_ids(shell: Any, domain: str) -> frozenset[str]:
    """Return the upper-cased done-set to skip on resume, or an empty set.

    Only a ``running`` (interrupted) record yields skip entries — an absent or
    ``complete`` record returns an empty set, so a fresh / finished scan sweeps
    every host. The set is the O(1) skip filter the fan-out applies over its
    dispatch list.
    """
    record = read_collection_progress(shell, domain)
    if record.get("status") != STATUS_RUNNING:
        return frozenset()
    done = record.get("hosts_done")
    if not isinstance(done, list):
        return frozenset()
    return frozenset(str(x).upper() for x in done)


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
