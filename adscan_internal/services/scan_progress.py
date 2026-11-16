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
from enum import Enum
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


class StepOutcome(str, Enum):
    """Why a scan step's runner is telling the pipeline to continue or stop.

    ``run_enumeration``'s step runner used to answer this with a bare ``bool``
    that meant two OPPOSITE things at once — "stop, the objective is met" and
    "stop, we are done here" — so every call site could only do a bare ``return``
    and the checkpoint was left at ``status="running"`` forever. A CTF scan that
    reached full domain compromise was then indistinguishable, on the next
    workspace load, from a scan that died half-way: the resume front door offered
    to continue a scan that had already WON.

    The three outcomes are exhaustive and each carries its checkpoint obligation:

    * :attr:`CONTINUE` — the step ran (successfully or not); keep going. A step
      that FAILED is still ``CONTINUE``: the failure is logged and the pipeline
      moves on, exactly as before.
    * :attr:`STOP_OBJECTIVE_MET` — the engagement's own success criterion is
      satisfied (CTF: the domain is owned), so the remaining offensive phases are
      deliberately skipped. The scan is COMPLETE by its own definition and the
      checkpoint must be finalized — leaving it ``running`` is what produced the
      "a scan that wins is recorded as interrupted, forever" bug.
    * :attr:`STOP_INCOMPLETE` — the pipeline stopped without meeting the
      objective (an abort, a chunk boundary, an unrecoverable precondition). The
      checkpoint stays ``running`` so the scan remains resumable.

    ``bool(outcome)`` answers "should the pipeline stop?", so a foreign caller
    that still writes ``if run_step(...):`` keeps behaving correctly. In-repo
    call sites use the explicit :attr:`should_stop` / :attr:`finalizes_scan`
    properties — the whole point of this type is that "stop" and "why" are no
    longer the same bit.
    """

    CONTINUE = "continue"
    STOP_OBJECTIVE_MET = "stop_objective_met"
    STOP_INCOMPLETE = "stop_incomplete"

    @property
    def should_stop(self) -> bool:
        """Return True when the surrounding pipeline must stop here."""
        return self is not StepOutcome.CONTINUE

    @property
    def finalizes_scan(self) -> bool:
        """Return True when this stop means the scan is COMPLETE, not interrupted."""
        return self is StepOutcome.STOP_OBJECTIVE_MET

    def __bool__(self) -> bool:
        """Truthiness is "should the pipeline stop?" (compatibility guard)."""
        return self.should_stop


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


#: Record key: the digest of the asset scope the scan last ran under (``""``:
#: none). A record written before the asset scope existed has no key, which
#: reads the same as "no scope", and that is what it ran under.
ASSET_SCOPE_DIGEST_KEY = "asset_scope_digest"
#: Never equal to a stored digest: the session's scope record cannot be read.
_ASSET_SCOPE_UNREADABLE = "unreadable"


def current_asset_scope_digest(shell: Any) -> str:
    """Digest of the asset scope this session runs under (``""`` when it has none).

    The digest covers the allow and deny lists and the domain-controller rule,
    so two runs with equal digests assess exactly the same set. A record that
    cannot be read, or an answer that cannot be had, never equals a stored
    digest: a resume is then refused rather than assumed.
    """
    try:
        from adscan_internal.services.engagement_scope import asset_scope  # noqa: PLC0415

        scope = asset_scope(shell)
        if scope is None:
            return ""
        if getattr(scope, "unreadable", False):
            return _ASSET_SCOPE_UNREADABLE
        return str(scope.digest() or _ASSET_SCOPE_UNREADABLE)
    except Exception:  # noqa: BLE001 - an unknown scope is never "the same scope"
        return _ASSET_SCOPE_UNREADABLE


#: Incomplete-mark reason: the engagement scope was widened after this work
#: finished, and the scan was continued without running it again. A declared
#: gap, never a "run me again": see :func:`declare_asset_scope_widened`.
REASON_ASSET_SCOPE_WIDENED = "asset_scope_widened"
#: The collection's own integrity phase (``collector.collection_integrity``).
_COLLECTION_PHASE_ID = "domain_collection"


def _mark_reopens_phase(mark: Any) -> bool:
    """Whether an incomplete mark means "a re-run can still finish this phase".

    Every mark does, except one whose only reason is a widened engagement
    scope: the operator continued the scan knowing its finished phases would
    not run again, so the mark declares the gap and never reopens the phase (a
    blind re-run of a finished phase, password spraying above all, is what the
    resume gate exists to prevent).
    """
    if not isinstance(mark, dict):
        return True
    reasons = [str(r).split(":", 1)[0].strip().lower() for r in mark.get("reasons") or ()]
    reasons = [r for r in reasons if r]
    return not reasons or any(r != REASON_ASSET_SCOPE_WIDENED for r in reasons)


def declare_asset_scope_widened(shell: Any, domain: str, *, finished_phases: bool = True) -> None:
    """A scan is continued under a wider scope: mark what will not run again.

    The collection always (a resume and a replay both work over the collected
    data), and each finished phase when ``finished_phases``. Each keeps the
    reasons another stage already recorded on it.
    """
    detail = (
        "the engagement scope was widened after this work finished, so what the "
        "scope added was not assessed by it; start a fresh scan to assess it"
    )
    record = read_scan_progress(shell, domain)
    completed = record.get("phases_complete")
    targets = [_COLLECTION_PHASE_ID]
    if finished_phases and isinstance(completed, list):
        targets += [p for p in RUN_ENUMERATION_PHASE_IDS if p in completed]
    for phase_id in targets:
        existing = incomplete_phases(shell, domain).get(phase_id) or {}
        reasons = [
            str(r)
            for r in existing.get("reasons") or ()
            if str(r).split(":", 1)[0].strip().lower() != REASON_ASSET_SCOPE_WIDENED
        ]
        prior = str(existing.get("detail") or "").strip()
        mark_phase_incomplete(
            shell,
            domain,
            phase_id,
            reasons=(*reasons, REASON_ASSET_SCOPE_WIDENED),
            detail=f"{prior}; {detail}" if prior and detail not in prior else (prior or detail),
        )


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
    scope_digest = current_asset_scope_digest(shell)
    record[ASSET_SCOPE_DIGEST_KEY] = scope_digest
    if scope_digest != _ASSET_SCOPE_UNREADABLE:
        # The lists behind the digest, kept beside the domain's data so a later
        # resume can say whether the scope was narrowed or widened since.
        from adscan_internal.services.scan_scope_lineage import (  # noqa: PLC0415
            remember_scan_asset_scope,
        )

        remember_scan_asset_scope(shell, domain, scope_digest)
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


def _notify_coverage(shell: Any, domain: str, phase_id: str) -> None:
    recorder = getattr(shell, "_coverage_recorder", None)
    if recorder is None:
        return
    try:
        recorder.note_phase_completed(domain, phase_id)
    except Exception:  # noqa: BLE001 - coverage must never break the checkpoint
        pass


def mark_phase_complete(shell: Any, domain: str, phase_id: str) -> None:
    """Append ``phase_id`` to the completed set (dedup) after the phase ran.

    Call ONLY after a phase's steps returned without an early-exit — a half-run
    phase must never be marked complete (the whole reliability point). Persists
    best-effort so the marker survives a crash inside the 5 s auto-save window.

    Also tells the run's coverage recorder, when one is active, that the phase
    completed IN THIS RUN: the checkpoint alone cannot say that, since it
    carries phases completed by earlier runs too. Duck-typed (no import), so
    this module stays dependency-light.
    """
    _notify_coverage(shell, domain, phase_id)
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
    _engagement_scope_checkpoint(shell)


def _engagement_scope_checkpoint(shell: Any) -> None:
    """A phase boundary of the engagement scope (``scope_checkpoint``).

    Every scan flow passes here (``start``, ``ci``, the web worker's ``ci``):
    the scope's pending entries and evidence windows are refreshed, a scope
    recorded elsewhere is adopted, and what the session counted is written.
    One attribute read when no asset scope is recorded. Best-effort: the
    checkpoint of the scan never fails because of it, and a failure is never
    silent (telemetry, and the traceback in the debug log).
    """
    try:
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            asset_scope_recorded,
            scope_checkpoint,
        )

        if asset_scope_recorded(shell):
            scope_checkpoint(shell)
    except Exception as exc:  # noqa: BLE001 - never break the scan's own checkpoint
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def phase_already_complete(shell: Any, domain: str, phase_id: str) -> bool:
    """Return True when ``phase_id`` was completed by a prior (or the current) run.

    The single gate ``run_enumeration`` consults to SKIP a phase on resume —
    especially Password Spraying, whose blind re-run risks account lockout.

    A phase that reached its completion marker but was flagged incomplete (a
    bounded attack-path discovery stopped at the memory ceiling, recorded by
    :func:`mark_phase_incomplete`) is NOT complete for resume purposes: a reopen
    with more memory must recompute it. A sampled-by-design result carries NO
    incomplete mark (only a resource stop does), so it stays complete and is
    skipped — the distinction the coverage block already draws.
    """
    record = read_scan_progress(shell, domain)
    completed = record.get("phases_complete")
    if not (isinstance(completed, list) and phase_id in completed):
        return False
    incomplete = record.get(PHASES_INCOMPLETE_KEY)
    if (
        isinstance(incomplete, dict)
        and phase_id in incomplete
        and _mark_reopens_phase(incomplete[phase_id])
    ):
        return False
    return True


#: Integrity id of a run-level stop that names no scan phase (see
#: :data:`ASSESSMENT_INTEGRITY_PHASE_IDS`).
UNATTRIBUTED_STOP_PHASE_ID = "run_stopped"

#: The phases an authenticated assessment of a domain cannot do without. Until
#: both completed, the run has not looked at the domain's identities, ACLs and
#: routes, so it can state the findings it has but not that the domain held.
CORE_ASSESSMENT_PHASE_IDS: tuple[str, ...] = (
    "domain_analysis",
    "attack_paths_discovery",
)


def missing_core_assessment_phases(shell: Any, domain: str) -> tuple[str, ...]:
    """Return the core phases ``domain`` never completed, in pipeline order.

    The evidence is the persisted checkpoint, so a resumed scan whose earlier run
    completed a phase is not reported as missing it. ``domain_analysis`` also
    accepts the legacy ``phase1_complete`` flag, which ``run_enumeration`` writes
    with the same guard (the collection outputs landed).

    An empty tuple means the core assessment ran. Fail-open the other way would
    be wrong here: an unreadable record reports every core phase as missing,
    because this answer gates a "the domain held" verdict and only evidence may
    support it.

    Args:
        shell: The session shell (reads ``domains_data``).
        domain: The domain whose assessment is being judged.

    Returns:
        The ids from :data:`CORE_ASSESSMENT_PHASE_IDS` with no completion record.
    """
    completed = read_scan_progress(shell, domain).get("phases_complete")
    done = set(completed) if isinstance(completed, list) else set()
    try:
        entry = (getattr(shell, "domains_data", None) or {}).get(domain)
        if isinstance(entry, dict) and entry.get("phase1_complete") is True:
            done.add("domain_analysis")
    except Exception:  # noqa: BLE001 - a read must never break the scan
        pass
    return tuple(phase for phase in CORE_ASSESSMENT_PHASE_IDS if phase not in done)


#: Phases whose RUN can be cut short while still "completing": the collector
#: keeps going past a stage it could not read, so a phase that finished is not
#: proof it read everything. A phase listed here and marked incomplete
#: (:func:`mark_phase_incomplete`) counts as not completed for the verdict, in
#: pipeline order.
ASSESSMENT_INTEGRITY_PHASE_IDS: tuple[str, ...] = (
    "domain_collection",
    # The SQL Server authorization read (``collector.collection_integrity``). Its
    # own mark, so it never clears, nor is cleared by, the directory read's.
    "domain_collection.mssql",
    *CORE_ASSESSMENT_PHASE_IDS,
    # A stop that carried no phase (the memory sentinel stopped the run in work
    # that belongs to no scan phase, for example a share review started from
    # the prompt). Not a chapter-strip phase: it states the run stopped without
    # naming a phase the stop did not occur in, and it keeps ``adscan ci`` at
    # exit 3 like any other incomplete mark.
    UNATTRIBUTED_STOP_PHASE_ID,
)
#: Titles of the integrity ids that are not chapter-strip phases.
_INTEGRITY_SUBPHASE_TITLES: dict[str, str] = {
    "domain_collection.mssql": "SQL Server Collection",
    UNATTRIBUTED_STOP_PHASE_ID: "Assessment run",
}

#: Key, inside the ``scan_progress`` record, of the phases that ran but did not
#: finish their work: ``{phase_id: {"reasons": [...], "detail": "..."}}``.
PHASES_INCOMPLETE_KEY = "phases_incomplete"


def _notify_coverage_incomplete(
    shell: Any, domain: str, phase_id: str, reasons: tuple[str, ...]
) -> None:
    recorder = getattr(shell, "_coverage_recorder", None)
    if recorder is None:
        return
    try:
        if reasons:
            recorder.note_phase_incomplete(domain, phase_id, reasons)
        else:
            recorder.clear_phase_incomplete(domain, phase_id)
    except Exception:  # noqa: BLE001 - coverage must never break the checkpoint
        pass


def mark_phase_incomplete(
    shell: Any,
    domain: str,
    phase_id: str,
    *,
    reasons: tuple[str, ...] | list[str],
    detail: str = "",
) -> None:
    """Record that ``phase_id`` ran for ``domain`` but could not finish its work.

    The single writer of the "ran but incomplete" verdict (a collection that lost
    its domain controller mid-read is the case it exists for). It is read by
    :func:`authenticated_assessment_gap`, so the end-of-scan panel, ``adscan
    ci``'s exit status and the run's ``coverage.json`` all say the same thing.

    Args:
        shell: The session shell (writes ``domains_data``).
        domain: The domain the phase ran for.
        phase_id: The phase that did not finish.
        reasons: Machine tokens (``reason:stage``) for ``coverage.json``.
        detail: One operator-facing sentence saying what did not finish.
    """
    tokens = tuple(str(r) for r in reasons if str(r or "").strip()) or ("incomplete",)
    _notify_coverage_incomplete(shell, domain, phase_id, tokens)
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(SCAN_PROGRESS_KEY)
    if not isinstance(record, dict):
        record = {"status": STATUS_RUNNING, "phases_complete": []}
    incomplete = record.get(PHASES_INCOMPLETE_KEY)
    if not isinstance(incomplete, dict):
        incomplete = {}
    incomplete[str(phase_id)] = {"reasons": list(tokens), "detail": str(detail or "")}
    record[PHASES_INCOMPLETE_KEY] = incomplete
    record["updated_at"] = _now_iso()
    entry[SCAN_PROGRESS_KEY] = record
    _best_effort_save(shell)
    sync_assessment_integrity_to_report(shell, domain)


def clear_phase_incomplete(shell: Any, domain: str, phase_id: str) -> None:
    """Forget an earlier incomplete mark: ``phase_id`` is being run again."""
    _notify_coverage_incomplete(shell, domain, phase_id, ())
    entry = _domain_data(shell, domain)
    if entry is None:
        return
    record = entry.get(SCAN_PROGRESS_KEY)
    if not isinstance(record, dict):
        return
    incomplete = record.get(PHASES_INCOMPLETE_KEY)
    if isinstance(incomplete, dict) and phase_id in incomplete:
        incomplete.pop(phase_id, None)
        record["updated_at"] = _now_iso()
        _best_effort_save(shell)
        sync_assessment_integrity_to_report(shell, domain)


def drop_phase_incomplete_reason(
    shell: Any, domain: str, phase_id: str, reason: str
) -> bool:
    """Remove ONE reason from ``phase_id``'s incomplete mark; clear it when none remain.

    For a stage that now completed (a graph build that fitted after an earlier
    one stopped at the memory ceiling): its own reason no longer describes the
    phase, while a reason another stage left (a lost domain controller, another
    stage's memory stop) still does. Returns whether the mark changed.
    """
    entry = _domain_data(shell, domain)
    record = entry.get(SCAN_PROGRESS_KEY) if isinstance(entry, dict) else None
    incomplete = record.get(PHASES_INCOMPLETE_KEY) if isinstance(record, dict) else None
    mark = incomplete.get(phase_id) if isinstance(incomplete, dict) else None
    if not isinstance(mark, dict):
        return False
    reasons = [str(r) for r in mark.get("reasons") or ()]
    if reason not in reasons:
        return False
    remaining = [r for r in reasons if r != reason]
    if not remaining:
        clear_phase_incomplete(shell, domain, phase_id)
        return True
    mark["reasons"] = remaining
    _notify_coverage_incomplete(shell, domain, phase_id, tuple(remaining))
    record["updated_at"] = _now_iso()
    _best_effort_save(shell)
    sync_assessment_integrity_to_report(shell, domain)
    return True


def sync_assessment_integrity_to_report(shell: Any, domain: str, *, create: bool = False) -> None:
    """Mirror ``domain``'s incomplete phases into ``technical_report.json``.

    The report is the artifact a deliverable is rendered from later and the one
    the web ingests, so it must carry the same completeness verdict the console,
    the exit status and ``coverage.json`` read (``record_assessment_integrity``).
    Called on every change of the record; ``create`` writes the report even when
    no producer has created it yet (the end of an ``adscan ci`` run). Never raises.
    """
    if not domain:
        return
    try:
        from adscan_core.reporting import technical_report as tr  # noqa: PLC0415

        if not create and not tr._get_technical_report_path(shell).exists():
            return
        marks = incomplete_phases(shell, domain)
        ids = tuple(marks)
        rows = [
            {
                "phase_id": phase_id,
                "title": title,
                "reasons": [str(r) for r in (marks[phase_id].get("reasons") or ())],
                "detail": str(marks[phase_id].get("detail") or ""),
            }
            for phase_id, title in zip(ids, phase_titles(ids))
        ]
        tr.record_assessment_integrity(shell, domain, incomplete_phases=rows)
    except Exception as exc:  # noqa: BLE001 - the report mirror never breaks a scan
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def incomplete_phases(shell: Any, domain: str) -> dict[str, dict[str, Any]]:
    """Return ``{phase_id: {"reasons": [...], "detail": str}}`` for ``domain``."""
    incomplete = read_scan_progress(shell, domain).get(PHASES_INCOMPLETE_KEY)
    if not isinstance(incomplete, dict):
        return {}
    return {
        str(phase): dict(value) if isinstance(value, dict) else {"reasons": [], "detail": ""}
        for phase, value in incomplete.items()
    }


def _incomplete_excluding_asset_scope(shell: Any, domain: str) -> set[str]:
    """Incomplete phases, dropping those whose only gaps are asset exclusions.

    An unfinished-work reason that names an object the client excluded from the
    engagement scope is a gap the client asked for, not a scan that stopped
    early. A phase whose reasons are ALL asset-scope reasons is complete over its
    in-scope set and does not count as lacking. SSOT for the reason tokens:
    :data:`adscan_core.reporting.engagement_scope.ASSET_SCOPE_GAP_REASONS`.

    The exception is a scope record that cannot be used: nobody asked for that
    gap. Its reason token is not an asset-scope gap reason, and while the
    session's record is unusable no phase is dropped at all, so the phases it
    kept from running read as incomplete.
    """
    from adscan_core.reporting.engagement_scope import ASSET_SCOPE_GAP_REASONS

    marks = incomplete_phases(shell, domain)
    if marks and _scope_record_unusable(shell):
        return set(marks)
    lacking: set[str] = set()
    for phase_id, mark in marks.items():
        reasons = [str(r).split(":", 1)[0].strip().lower() for r in (mark or {}).get("reasons") or ()]
        reasons = [r for r in reasons if r]
        if reasons and all(r in ASSET_SCOPE_GAP_REASONS for r in reasons):
            continue
        lacking.add(phase_id)
    return lacking


def _scope_record_unusable(shell: Any) -> bool:
    """Whether the session's engagement-scope record cannot be used (fail closed)."""
    try:
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            asset_scope_unreadable,
        )

        return bool(asset_scope_unreadable(shell))
    except Exception:  # noqa: BLE001 - an unreadable answer never hides a gap
        return True


def resumable_recomputable_phases(shell: Any, domain: str) -> tuple[str, ...]:
    """Return the resume phases that ran but were flagged incomplete.

    A resume phase lands here when it carries an incomplete mark
    (:func:`mark_phase_incomplete`). Two origins, both meaning "a re-run can
    still finish this":

    * a bounded attack-path discovery stopped at the memory ceiling (the phase
      is ALSO in ``phases_complete`` — the seam marked it complete because the
      compute returned a partial result);
    * a phase the operator cut short from the Ctrl+C menu (``skip_step`` /
      ``skip_phase``) — the phase is NOT in ``phases_complete`` because
      ``_mark_done`` skips a stopped phase, but the scan continued and later
      phases completed, so the cut phase sits BELOW the completed frontier.

    Either way it is a deliberate "re-run me", NOT a checkpoint hole to skip. The
    distinguisher is the incomplete MARK: a true checkpoint hole (a phase
    announced but never checkpointed, with no incomplete mark) is left to the
    frontier logic, which correctly treats it as already-passed.

    In pipeline order. Empty for a clean scan, and for a sampled-by-design result
    (which records no incomplete mark).
    """
    record = read_scan_progress(shell, domain)
    incomplete = record.get(PHASES_INCOMPLETE_KEY)
    # A mark that only declares a widened scope is a gap, not a "re-run me".
    incomplete_set = (
        {phase for phase, mark in incomplete.items() if _mark_reopens_phase(mark)}
        if isinstance(incomplete, dict)
        else set()
    )
    return tuple(p for p in RUN_ENUMERATION_PHASE_IDS if p in incomplete_set)


def has_recomputable_phase_gap(shell: Any, domain: str) -> bool:
    """Return True when a resume phase ran but a re-run can still finish it.

    The second resume trigger beyond ``is_incomplete``: a scan whose status flag
    is ``complete`` but which left a phase incomplete — a bounded attack-path
    discovery, or a phase the operator cut short from the Ctrl+C menu — still has
    work a reopen can do. Used by the resume offer so the workspace surfaces the
    re-run even though the scan "finished".
    """
    return bool(resumable_recomputable_phases(shell, domain))


def authenticated_assessment_gap(
    shell: Any, domain: str, *, verb: str | None = None
) -> tuple[str, ...]:
    """Return the phase ids an authenticated assessment of ``domain`` lacks.

    A phase is lacking when it never completed (a core phase with no completion
    record) or when it ran but could not finish its work
    (:func:`mark_phase_incomplete`: a collection that lost its domain controller
    mid-read). Empty when the run was not an authenticated assessment (an
    unauthenticated scan never collects, and makes no "held" claim about the
    directory) or when nothing is lacking. Used by the recap and by ``adscan
    ci``'s exit status, so the panel and the exit code cannot disagree.

    Args:
        shell: The active pentest shell.
        domain: The domain the outcome is about.
        verb: The completed scan verb, when the caller knows it.

    Returns:
        Phase ids from :data:`ASSESSMENT_INTEGRITY_PHASE_IDS`, in pipeline order.
    """
    authenticated = verb == "start_auth" or getattr(shell, "scan_mode", None) == "auth"
    if not authenticated or not domain:
        return ()
    missing = missing_core_assessment_phases(shell, domain)
    if missing:
        # A phase the scan policy or config switched off is a declared scope
        # choice (stated by the policy-skip recap), not a scan that stopped early.
        try:
            from adscan_internal.services.scan_phases import phases_enabled_for_run

            missing = tuple(phases_enabled_for_run(shell, missing))
        except Exception:  # noqa: BLE001 - without the gate, judge every core phase
            pass
    # A phase marked incomplete RAN (it is never a scope choice), so no gate.
    # Exception: a phase whose ONLY unfinished work is an asset the client
    # excluded from the engagement scope is complete over its in-scope set. The
    # client asked for the exclusion, so it never reads as an incomplete
    # assessment (``ci`` exit 3), the same way a policy-disabled phase does not.
    incomplete = _incomplete_excluding_asset_scope(shell, domain)
    lacking = set(missing) | incomplete
    # A stage stopped at the memory ceiling and recorded in the workspace's
    # technical report: the record also covers a stop that happened under
    # another session object (the report render rebuilds the graph under its
    # own throwaway shell), so the run never reads complete over it.
    try:
        from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
            resource_coverage_gap_phases,
        )

        lacking |= set(resource_coverage_gap_phases(shell, domain))
    except Exception:  # noqa: BLE001 - the record is a second source, never a blocker
        pass
    integrity = tuple(p for p in ASSESSMENT_INTEGRITY_PHASE_IDS if p in lacking)
    # A phase whose domain controller stopped answering (``target_loss``) counts
    # wherever it sits in the pipeline: its checks were never evaluated, so the
    # run is not a complete assessment of the domain even when collection and
    # discovery finished before the controller went away.
    return integrity + target_loss_phases(shell, domain, exclude=integrity)


def target_loss_phases(
    shell: Any, domain: str, *, exclude: tuple[str, ...] = ()
) -> tuple[str, ...]:
    """Phases of ``domain`` marked incomplete because the domain controller stopped answering.

    In pipeline order (:data:`RUN_ENUMERATION_PHASE_IDS` first, then any other
    phase id in sorted order). See :mod:`adscan_internal.services.target_loss`.
    """
    from adscan_internal.services.target_loss import mark_has_target_loss  # noqa: PLC0415

    marked = {
        phase
        for phase, mark in incomplete_phases(shell, domain).items()
        if phase not in exclude and mark_has_target_loss(mark)
    }
    ordered = [p for p in RUN_ENUMERATION_PHASE_IDS if p in marked]
    ordered += sorted(marked - set(ordered))
    return tuple(ordered)


def phase_titles(phase_ids: tuple[str, ...]) -> tuple[str, ...]:
    """Return the chapter-strip titles of ``phase_ids`` (readable id fallback)."""
    try:
        from adscan_internal.services.scan_phases import get_phase
    except Exception:  # noqa: BLE001 - a title lookup must never break a verdict
        get_phase = None  # type: ignore[assignment]
    titles: list[str] = []
    for phase_id in phase_ids:
        phase = get_phase(phase_id) if get_phase is not None else None
        title = str(getattr(phase, "title", "") or "").strip() or _INTEGRITY_SUBPHASE_TITLES.get(
            str(phase_id), ""
        )
        titles.append(title or str(phase_id).replace("_", " ").capitalize())
    return tuple(titles)


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

    # A phase that ran to its completion marker but was flagged incomplete (a
    # bounded attack-path discovery stopped at the memory ceiling) is a
    # deliberate "re-run me", NOT a checkpoint hole: resume at the EARLIEST such
    # phase so a reopen with more memory recomputes it, even when later phases
    # completed on the bounded result and the frontier below would skip it.
    for phase_id in resumable_recomputable_phases(shell, domain):
        if applicable and phase_id not in applicable:
            continue
        return phase_id

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
