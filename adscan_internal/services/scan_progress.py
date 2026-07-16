"""Centralized per-phase scan-progress checkpoint (SSOT for crash-resume).

``run_enumeration`` runs the scan phases sequentially. Before this module the
only durable completion marker was ``phase1_complete`` — every downstream phase
re-ran from the top on a re-launch, so an interruption during (say) Password
Spraying re-ran the whole exploitation group. This module adds one persisted
record under ``domains_data[domain]["scan_progress"]`` that both the CLI resume
front door and the engine read, so a re-launched scan resumes from the first
phase it did NOT finish.

The record::

    domains_data[<domain>]["scan_progress"] = {
        "status": "running" | "complete",
        "last_phase_reached": "<phase_id>",       # phase in progress when entered
        "phases_complete": ["<phase_id>", ...],   # completed phase ids (a LIST)
        "scan_type": "audit",                     # engagement type at launch
        "updated_at": "2026-07-12T14:05:00Z",     # ISO-8601 UTC
    }

Hard invariants (both enforced by tests):

* **No ``_`` prefix.** ``collect_workspace_variables_from_shell`` drops every
  ``domains_data`` key starting with ``_`` before writing ``variables.json``
  (runtime-only convention). ``scan_progress`` must survive a crash, so its key
  is bare.
* **``phases_complete`` is a JSON list, never a ``set``.** A ``set`` in
  ``domains_data`` breaks ``save_workspace_data`` (JSON serialization).

The module is dependency-light — it never imports the engine or native stack —
so it is safe for any consumer. All helpers are fail-open: a malformed record or
a shell without ``domains_data`` degrades to "not started" (every phase runs),
never an exception that breaks the scan.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Persisted key under ``domains_data[domain]`` — deliberately NOT ``_``-prefixed
# so the state serializer keeps it (see module docstring).
SCAN_PROGRESS_KEY = "scan_progress"

# Status values. ``running`` left behind on next load == an interrupted scan
# (the clean end always overwrites it with ``complete``). ``incomplete`` is the
# derived label a consumer assigns to a persisted ``running`` record.
STATUS_RUNNING = "running"
STATUS_COMPLETE = "complete"

# The ordered phase ids ``run_enumeration`` checkpoints, in execution order.
# This is the resume vocabulary — the preflight/collection phases (DNS, topology,
# collector) are NOT checkpointed here, so a resume never re-enters at one of
# them. ``unauthenticated_attack_surface`` and ``audit_extras`` are audit-only;
# ``resume_phase_id`` filters by the scan type's applicable phase set.
RUN_ENUMERATION_PHASE_IDS: tuple[str, ...] = (
    "domain_analysis",
    "attack_paths_discovery",
    "quick_credential_wins",
    "password_spraying",
    "share_credential_hunt",
    "unauthenticated_attack_surface",
    "audit_extras",
)


def should_manage_progress(
    *,
    stop_after_phase: int | None,
    start_from_phase: int | None,
) -> bool:
    """Return whether ``run_enumeration`` should manage the crash-resume checkpoint.

    EVERY ``run_enumeration`` invocation is part of a genuine scan progression, so
    the checkpoint is managed in all of them — the full single-domain run
    (``stop_after_phase=None, start_from_phase=None``), the multi-domain **Phase-1
    chunk** (``stop_after_phase=1``), and the trust-pivot **phases-3+ chunk**
    (``start_from_phase=3``). The existing ``phase_already_complete`` /
    ``mark_phase_complete`` / ``mark_scan_running`` logic composes across those
    chunks: a phase completed in one chunk is skipped when a later chunk re-enters
    it, ``start_from_phase`` still skips its pre-window phases via the engine's own
    gate, and ``mark_scan_complete`` fires only at the natural end of
    ``run_enumeration`` (a ``stop_after_phase`` chunk returns early, before it) —
    so the Phase-1 chunk never marks the whole scan complete.

    This is a **single source of truth** for the gate decision so a future
    invocation shape that must NOT be checkpointed changes this function (and its
    test) in one place, rather than an inline boolean scattered in the 30k-line
    engine. Before the multi-domain fix the gate was
    ``start_from_phase is None and stop_after_phase is None``, which left the
    Phase-1 and phases-3+ chunks — i.e. every real (trusted) environment — with no
    checkpoint at all.

    Args:
        stop_after_phase: The phase index the invocation stops after, or ``None``.
        start_from_phase: The phase index the invocation resumes from, or ``None``.

    Returns:
        ``True`` — always manage the checkpoint for a ``run_enumeration`` call.
    """
    # The parameters are accepted (not ignored) so the SSOT signature documents
    # exactly which invocation shapes were considered and stays the single edit
    # point if a shape ever needs to opt out.
    del stop_after_phase, start_from_phase
    return True


def _now_iso() -> str:
    """Return the current time as an ISO-8601 UTC string."""
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


def read_scan_progress(shell: Any, domain: str) -> dict[str, Any]:
    """Return the persisted ``scan_progress`` record, or ``{}`` when absent."""
    try:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return {}
        entry = domains_data.get(domain)
        if not isinstance(entry, dict):
            return {}
        record = entry.get(SCAN_PROGRESS_KEY)
        return dict(record) if isinstance(record, dict) else {}
    except Exception:  # noqa: BLE001 — a read must never break the scan
        return {}


def is_incomplete(shell: Any, domain: str) -> bool:
    """Return True when a persisted scan is resumable (status still ``running``).

    A ``running`` record on load means the previous run died before writing
    ``complete`` — an interrupted scan the operator can resume.
    """
    return read_scan_progress(shell, domain).get("status") == STATUS_RUNNING


def mark_scan_running(
    shell: Any,
    domain: str,
    scan_type: str | None = None,
    *,
    phase_id: str | None = None,
) -> None:
    """Mark the scan as running; initialize the record on first entry.

    Idempotent and resume-safe: a pre-existing ``phases_complete`` list is
    PRESERVED (never wiped), so re-entering an interrupted scan keeps the
    checkpoint intact. ``phase_id`` (when given) updates ``last_phase_reached``
    so the record tracks the phase currently being entered — this is how the
    front door renders "continue from <phase>".
    """
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(SCAN_PROGRESS_KEY)
    if not isinstance(record, dict):
        record = {}
    record["status"] = STATUS_RUNNING
    if not isinstance(record.get("phases_complete"), list):
        record["phases_complete"] = []
    if scan_type is not None:
        record["scan_type"] = scan_type
    if phase_id is not None:
        record["last_phase_reached"] = phase_id
    record["updated_at"] = _now_iso()
    entry[SCAN_PROGRESS_KEY] = record
    _debug(
        f"mark_scan_running domain={domain} phase={phase_id} status=running "
        f"phases_complete={record.get('phases_complete')} -> persisting"
    )
    # Persist immediately on phase ENTRY. Without this, a scan interrupted
    # DURING a phase before it completes (e.g. Ctrl+C mid Domain Intelligence,
    # the first phase) leaves the "running" checkpoint only in memory — no
    # ``mark_phase_complete`` has run yet, so the record reaches disk only if the
    # 5s auto-save happens to fire and persist it first. That timing gap dropped
    # the checkpoint entirely (observed: interrupted first-phase scan → no
    # resumable record). Saving here makes the resumable state durable the moment
    # a phase starts, independent of the auto-save.
    _best_effort_save(shell)


def mark_phase_complete(shell: Any, domain: str, phase_id: str) -> None:
    """Append ``phase_id`` to the completed set (dedup) after the phase ran.

    Call ONLY after a phase's steps returned without an early-exit — a half-run
    phase must never be marked complete (the whole reliability point). Persists
    best-effort so the marker survives a crash inside the 5 s auto-save window.
    """
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(SCAN_PROGRESS_KEY)
    if not isinstance(record, dict):
        # A completion without a prior ``mark_scan_running`` still records
        # progress rather than dropping it.
        record = {"status": STATUS_RUNNING, "phases_complete": []}
    completed = record.get("phases_complete")
    if not isinstance(completed, list):
        completed = []
    if phase_id not in completed:
        completed.append(phase_id)
    record["phases_complete"] = completed
    record["updated_at"] = _now_iso()
    entry[SCAN_PROGRESS_KEY] = record
    _best_effort_save(shell)


def phase_already_complete(shell: Any, domain: str, phase_id: str) -> bool:
    """Return True when ``phase_id`` was completed by a prior (or the current) run.

    The single gate ``run_enumeration`` consults to SKIP a phase on resume —
    especially Password Spraying, whose blind re-run risks account lockout.
    """
    completed = read_scan_progress(shell, domain).get("phases_complete")
    return isinstance(completed, list) and phase_id in completed


def mark_scan_complete(shell: Any, domain: str) -> None:
    """Mark the scan cleanly finished so the resume offer stops.

    Retains ``phases_complete`` (history), only flips ``status`` to ``complete``.
    """
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(SCAN_PROGRESS_KEY)
    if not isinstance(record, dict):
        record = {"phases_complete": []}
    record["status"] = STATUS_COMPLETE
    if not isinstance(record.get("phases_complete"), list):
        record["phases_complete"] = []
    record["updated_at"] = _now_iso()
    entry[SCAN_PROGRESS_KEY] = record
    _best_effort_save(shell)


def reset_scan_progress(shell: Any, domain: str) -> None:
    """Remove the record so a deliberate re-run (Refresh/Replay) runs every phase."""
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    entry.pop(SCAN_PROGRESS_KEY, None)


def resume_phase_id(shell: Any, domain: str, scan_type: str) -> str | None:
    """Return the phase a resume should re-enter at — HOLE-TOLERANT.

    Resume from the FURTHEST-reached incomplete phase: the first applicable phase
    whose order index is **beyond** the highest completed phase's index. A
    first-incomplete-in-order scan would mis-report a mid-list HOLE (a phase that
    was computed but never checkpointed) as the resume point — the exact
    resume-hole bug the trust/cross-domain pivot produced by announcing
    ``attack_paths_discovery`` without ever marking it complete. Anchoring on the
    max completed index makes the checkpoint robust to a hole from ANY
    orchestration quirk, present or future: a hole below the reached frontier is
    treated as already-passed, not as the resume target.

    Returns ``None`` when there is no record or nothing remains beyond the frontier.
    """
    record = read_scan_progress(shell, domain)
    completed = record.get("phases_complete")
    if not isinstance(completed, list):
        return None
    completed_set = set(completed)
    # Restrict to the phases applicable to this scan type (audit adds the
    # unauth-surface / CVE phases; other types stop earlier).
    try:
        from adscan_internal.services.scan_phases import phases_for_scan_type

        applicable = {phase.phase_id for phase in phases_for_scan_type(scan_type)}
    except Exception:  # noqa: BLE001 — degrade to the full checkpoint set
        applicable = set(RUN_ENUMERATION_PHASE_IDS)

    # The frontier: the highest order index among completed phases (restricted to
    # the known checkpoint vocabulary). ``-1`` when nothing completed yet, so the
    # resume starts at the first applicable phase.
    phase_index = {phase_id: idx for idx, phase_id in enumerate(RUN_ENUMERATION_PHASE_IDS)}
    highest_completed = -1
    for phase_id in completed_set:
        idx = phase_index.get(phase_id)
        if idx is not None and idx > highest_completed:
            highest_completed = idx

    # First applicable phase BEYOND the frontier that is not already complete.
    # A phase at-or-before the frontier that is incomplete is a HOLE — skip it.
    for phase_id in RUN_ENUMERATION_PHASE_IDS:
        if applicable and phase_id not in applicable:
            continue
        if phase_index[phase_id] <= highest_completed:
            continue
        if phase_id not in completed_set:
            return phase_id
    return None


def _debug(msg: str) -> None:
    """Greppable, --debug-only checkpoint trace (best-effort; never raises)."""
    try:
        from adscan_core.rich_output import print_info_debug

        print_info_debug(f"scan-progress: {msg}")
    except Exception:  # noqa: BLE001 — logging must never break the scan
        pass


def _best_effort_save(shell: Any) -> None:
    """Persist the workspace now (belt-and-suspenders over the 5 s auto-save).

    A phase marker written just before a crash would otherwise be lost within
    the auto-save window, re-running the phase on resume. Never raises.
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
