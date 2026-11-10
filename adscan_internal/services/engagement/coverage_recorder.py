"""Record, per run, which checks ran and on which scope (``coverage.json``).

The reconciliation rule (``adscan_core.engagement.reconcile``) closes an absent
item only when the check that observes it ran. This module is the engine-side
source of that evidence.

Evidence is what THIS run did, observed at the seams that already decide it:

* phase completion: ``scan_progress.mark_phase_complete`` (the single writer of
  the resume checkpoint) tells the active recorder, so only a phase completed in
  this process counts. A phase carried over in the checkpoint from an earlier
  run, or reused from cached results, is not a run (:func:`note_phase_not_run`).
  Both are COUNTED rather than collected, because the pipeline re-enters a
  domain once per pivot and the cached-results branch then reuses what an
  earlier pass of the SAME run produced: that is still this run's observation
  (see :meth:`CoverageRecorder.phases_completed`);
* step outcome: ``run_enumeration``'s step runner reports a step that raised
  (:func:`note_step_failed`), which makes its phase's checks FAILED even though
  the pipeline moved on;
* collection: the collector reports that it ran and persisted a domain
  (:func:`note_collection_ran`) and which hosts its sweep fully examined
  (:func:`note_collection_hosts`);
* persisted observations that already carry their own certainty: the posture
  record (a category is observed only when the DC gave a definitive answer) and
  the certificate-services detection (conclusive or not);
* the scan config: disabled phases and sub-steps, and the CVE target scope.

Still phase-level (documented, not inferred away): a step that swallows its own
failure and returns normally (a share hunt that hit its time budget, an
enumeration that logged and continued) reads as having run. Those need a seam
of their own; until then their checks are as trustworthy as their phase.

Explicit :meth:`CoverageRecorder.record` calls always win over derivation, so a
stage can only ever make the record more conservative.
"""

from __future__ import annotations

from adscan_core.scan_policy import settings as policy_settings

import time
from contextlib import contextmanager
from typing import Any, Iterable, Iterator, Mapping, Optional

from adscan_core.engagement import ALL_DOMAINS
from adscan_core.engagement.coverage_io import (
    run_coverage_to_document,
    write_json_atomic,
)
from adscan_core.engagement.model import (
    RUN_COMPLETE,
    RUN_INTERRUPTED,
    RUN_PARTIAL,
    CheckStatus,
    RunCoverage,
    Vantage,
)
from adscan_core.engagement.observations import (
    OBSERVATIONS_FILENAME,
    CheckObservation,
    ObservationRecord,
    Outcome,
    coverage_from_observations,
    merge_observations,
    observation_record_to_document,
)
from adscan_core.engagement.specs import (
    C_ADCS,
    C_AUDIT_HOSTS,
    C_COLLECTION,
    C_COLLECTION_HOSTS,
    C_COLLECTION_MSSQL,
    C_CRACKING,
    C_PATHS,
    C_PRIV_EXERCISE,
    CHECK_TO_PHASE,
    POSTURE_PREFIX,
)

#: A check whose own phase leaves no checkpoint is trusted once the phase that
#: consumes its output completed (the collector runs before domain analysis).
_COMPLETION_PHASE: Mapping[str, str] = {
    C_COLLECTION: "domain_analysis",
    C_COLLECTION_HOSTS: "domain_analysis",
    C_ADCS: "domain_analysis",
    C_COLLECTION_MSSQL: "domain_analysis",
}
#: Checks that also need the collector to have run in THIS run.
_NEEDS_COLLECTION = frozenset({C_COLLECTION, C_COLLECTION_HOSTS, C_ADCS, C_COLLECTION_MSSQL})

REASON_DISABLED = "disabled_by_config"
REASON_NOT_COMPLETED = "not_completed"
REASON_NOT_COLLECTED = "collection_not_run"
REASON_SUBPHASE_DISABLED = "subphase_disabled"
REASON_UNREADABLE = "coverage_unreadable"
REASON_STEP_FAILED = "step_failed"
REASON_CVE_SCOPE_DCS = "cve_scope_domain_controllers"
REASON_POSTURE_UNOBSERVED = "posture_unobserved"
REASON_ADCS_INCONCLUSIVE = "adcs_inconclusive"
REASON_MSSQL_UNRECORDED = "mssql_examined_set_unrecorded"
REASON_HOSTS_UNEXAMINED = "hosts_not_examined"
#: The phase ran but could not finish its work (``scan_progress.mark_phase_incomplete``).
REASON_PHASE_INCOMPLETE = "phase_incomplete"


def _dom(domain: str) -> str:
    return str(domain or "").strip().lower()


def _domain_key(domain_id: str) -> str:
    if not domain_id or domain_id == ALL_DOMAINS:
        return ALL_DOMAINS
    return str(domain_id).strip().lower()


#: How an explicit coverage status is stored as an observation (lossless for
#: what reconciliation reads: the coverage view maps it straight back).
_STATUS_TO_OBSERVATION: Mapping[CheckStatus, tuple[Outcome, bool]] = {
    CheckStatus.RAN: (Outcome.OBSERVED, True),
    CheckStatus.PARTIAL: (Outcome.OBSERVED, False),
    CheckStatus.SKIPPED: (Outcome.NOT_ASSESSED, False),
    CheckStatus.NOT_APPLICABLE: (Outcome.NOT_ASSESSED, False),
    CheckStatus.FAILED: (Outcome.FAILED, False),
}


class CoverageRecorder:
    """Holds the run's ONE observation record; coverage is a view of it.

    Two writers feed it: :meth:`record` (an explicit or phase-derived coverage
    status, which REPLACES whatever the record held for that check) and
    :meth:`observe` (a detector family reporting what it did and found, which
    MERGES with earlier observations of the same check in this run).
    """

    def __init__(self) -> None:
        self._run_id = ""
        self._vantage = Vantage.UNAUTH
        self._observations: dict[tuple[str, str], CheckObservation] = {}
        self._run_status = RUN_INTERRUPTED
        self._started_monotonic = time.monotonic()
        self._reset_notes()

    def _reset_notes(self) -> None:
        self._completed: dict[str, dict[str, int]] = {}
        self._not_run: dict[str, dict[str, str]] = {}
        self._reused: dict[str, dict[str, int]] = {}
        self._failed_steps: dict[str, dict[str, list[str]]] = {}
        self._collected: set[str] = set()
        self._examined_hosts: dict[str, set[str]] = {}
        self._incomplete: dict[str, dict[str, tuple[str, ...]]] = {}

    @property
    def run_id(self) -> str:
        """Id of the run in progress (stamped on the artifacts it writes)."""
        return self._run_id

    def begin_run(self, run_id: str, vantage: Vantage) -> None:
        """Start a run. Until :meth:`finish`, the run reads as ``interrupted``."""
        self._run_id = run_id
        self._vantage = vantage
        self._observations = {}
        self._run_status = RUN_INTERRUPTED
        self._started_monotonic = time.monotonic()
        self._reset_notes()

    # -- run-local notes, fed by the engine seams ---------------------------
    def note_phase_completed(self, domain: str, phase_id: str) -> None:
        """A phase was marked done in THIS run for ``domain``.

        Counted, not collected into a set: the pipeline re-enters a domain once
        per pivot, so the same phase is marked done several times in one run and
        only SOME of those markings are a genuine pass (see
        :meth:`phases_completed`).
        """
        marks = self._completed.setdefault(_dom(domain), {})
        key = str(phase_id)
        marks[key] = marks.get(key, 0) + 1

    def note_phase_not_run(self, domain: str, phase_id: str, reason: str) -> None:
        """A phase is marked done without having run now (cache reuse etc.)."""
        key = str(phase_id)
        self._not_run.setdefault(_dom(domain), {})[key] = reason
        reused = self._reused.setdefault(_dom(domain), {})
        reused[key] = reused.get(key, 0) + 1

    def note_step_failed(self, domain: str, phase_id: str, step: str) -> None:
        """A step of ``phase_id`` raised; the pipeline continued past it."""
        steps = self._failed_steps.setdefault(_dom(domain), {}).setdefault(str(phase_id), [])
        if step not in steps:
            steps.append(str(step))

    def note_phase_incomplete(
        self, domain: str, phase_id: str, reasons: Iterable[str]
    ) -> None:
        """``phase_id`` ran in this run but could not finish its work.

        Fed by ``scan_progress.mark_phase_incomplete`` (the single writer of
        that verdict). Its checks read PARTIAL, the run cannot read
        ``complete`` and ``coverage.json`` names the phase.
        """
        tokens = tuple(str(r) for r in reasons if str(r or "").strip())
        self._incomplete.setdefault(_dom(domain), {})[str(phase_id)] = tokens or (
            "incomplete",
        )

    def clear_phase_incomplete(self, domain: str, phase_id: str) -> None:
        """``phase_id`` is being run again: forget the earlier incomplete mark."""
        marks = self._incomplete.get(_dom(domain))
        if marks:
            marks.pop(str(phase_id), None)

    def incomplete_reasons(self, domain: str, phase_id: str) -> tuple[str, ...]:
        """Why ``phase_id`` did not finish for ``domain`` (empty when it did)."""
        return tuple(self._incomplete.get(_dom(domain), {}).get(str(phase_id), ()))

    def incomplete_phases(self) -> list[dict[str, Any]]:
        """Every phase that ran but did not finish, for ``coverage.json``."""
        return [
            {"domain_id": domain, "phase_id": phase, "reasons": list(reasons)}
            for domain, marks in sorted(self._incomplete.items())
            for phase, reasons in sorted(marks.items())
        ]

    def note_collection_ran(self, domain: str) -> None:
        """The collector ran and persisted ``domain`` in this run."""
        self._collected.add(_dom(domain))

    def note_collection_hosts(self, domain: str, host_ids: Iterable[str]) -> None:
        """Hosts the sweep fully examined (every stage, no error) this run."""
        ids = {str(h).strip().upper() for h in host_ids if str(h or "").strip()}
        self._examined_hosts.setdefault(_dom(domain), set()).update(ids)

    def phases_completed(self, domain: str) -> frozenset[str]:
        """Phases this run genuinely ran at least once for ``domain``.

        Every marking of a phase as done is counted, and so is every reuse note,
        because the cached-results branch does BOTH (it notes the reuse and then
        marks the phase done so the resume gate stays consistent). A phase is a
        genuine pass when it was marked done more often than it was reused:

        * marked once, reused once -> cache from an EARLIER run, nothing was
          re-observed, so the checks stay SKIPPED with the reuse reason;
        * marked twice, reused once -> this run walked the phase itself and a
          later pivot re-entered it and reused THIS RUN's own output. The data is
          from this run, so the checks RAN.

        Subtracting the reuse note as a set made the second case read as the
        first, so a re-scan of an existing workspace could never close anything:
        the pivot's reuse note erased the pass the same run had just made.
        """
        key = _dom(domain)
        reused = self._reused.get(key, {})
        return frozenset(
            phase
            for phase, marks in self._completed.get(key, {}).items()
            if marks > reused.get(phase, 0)
        )

    def not_run_reason(self, domain: str, phase_id: str) -> str:
        """Why a phase marked done did not run now ('' when it did or was never marked)."""
        return self._not_run.get(_dom(domain), {}).get(phase_id, "")

    def failed_steps(self, domain: str, phase_id: str) -> tuple[str, ...]:
        """Steps of ``phase_id`` that raised in this run."""
        return tuple(self._failed_steps.get(_dom(domain), {}).get(phase_id, ()))

    def collected(self, domain: str) -> bool:
        """Whether the collector ran for ``domain`` in this run."""
        return _dom(domain) in self._collected

    def examined_hosts(self, domain: str) -> Optional[frozenset[str]]:
        """Host object ids the sweep fully examined, ``None`` when unrecorded."""
        hosts = self._examined_hosts.get(_dom(domain))
        return frozenset(hosts) if hosts is not None else None

    def noted_domains(self) -> set[str]:
        """Every domain any seam reported on in this run."""
        return (
            set(self._completed)
            | set(self._not_run)
            | set(self._failed_steps)
            | set(self._collected)
            | set(self._examined_hosts)
            | {d for d, marks in self._incomplete.items() if marks}
        )

    def record(
        self,
        check_id: str,
        status: CheckStatus,
        *,
        domain_id: str = ALL_DOMAINS,
        scope_kind: str = "domain",
        examined: Optional[int] = None,
        total: Optional[int] = None,
        examined_ids: Optional[Iterable[str]] = None,
        reason: str = "",
        source: str = "explicit",
    ) -> None:
        """Record what a check did. An explicit record overrides derivation."""
        domain = _domain_key(domain_id)
        outcome, complete = _STATUS_TO_OBSERVATION[status]
        self._observations[(check_id, domain)] = CheckObservation(
            check_id=check_id,
            domain_id=domain,
            outcome=outcome,
            scope_kind=scope_kind,
            complete=complete,
            examined=examined,
            total=total,
            examined_ids=frozenset(examined_ids) if examined_ids is not None else None,
            reason=reason,
            source=source,
        )

    def observe(
        self,
        check_id: str,
        outcome: Outcome,
        *,
        domain_id: str,
        scope_kind: str = "domain",
        complete: bool = True,
        examined: Optional[int] = None,
        total: Optional[int] = None,
        examined_ids: Optional[Iterable[str]] = None,
        vantage: Optional[Vantage] = None,
        reason: str = "",
        positive_key: str = "",
        instances: Iterable[Mapping[str, Any]] = (),
        replace: bool = False,
    ) -> CheckObservation:
        """Record what a detector family did and found; merges within the run.

        ``replace`` drops the run's earlier record of ``(check_id, domain_id)``
        instead of merging into it. It is for a caller that re-derives the WHOLE
        observation from every per-host verdict of the run (the patch-level
        re-run, which re-grades hosts the first pass left not assessed); a merge
        would count those hosts twice and keep the first pass's incompleteness.
        """
        domain = _domain_key(domain_id)
        observation = CheckObservation(
            check_id=check_id,
            domain_id=domain,
            outcome=outcome,
            scope_kind=scope_kind,
            complete=complete,
            examined=examined,
            total=total,
            examined_ids=frozenset(examined_ids) if examined_ids is not None else None,
            vantage=vantage,
            reason=reason,
            positive_key=positive_key,
            instances=tuple(dict(i) for i in instances),
            source="detector",
        )
        key = (check_id, domain)
        existing = None if replace else self._observations.get(key)
        if existing is not None:
            observation = merge_observations(existing, observation)
        self._observations[key] = observation
        return observation

    def has(self, check_id: str, domain_id: str) -> bool:
        """Return whether a record exists for ``(check_id, domain_id)``."""
        return (check_id, _domain_key(domain_id)) in self._observations

    @contextmanager
    def check(
        self, check_id: str, *, domain_id: str = ALL_DOMAINS, scope_kind: str = "domain"
    ) -> Iterator[None]:
        """Mark the check ``RAN`` on a clean exit, ``FAILED`` on an exception."""
        try:
            yield
        except BaseException:
            self.record(
                check_id, CheckStatus.FAILED, domain_id=domain_id, scope_kind=scope_kind
            )
            raise
        self.record(check_id, CheckStatus.RAN, domain_id=domain_id, scope_kind=scope_kind)

    def derived_run_status(self, *, success: bool) -> str:
        """Return ``complete`` for a successful run that completed any phase.

        Completion is judged per domain, not for the run as a whole: a domain the
        run mapped but never scanned (a trusted domain that was not collected, an
        unreachable partner) simply has no check that ran, so nothing of it can
        close. Requiring every domain to have finished made one such domain turn
        the whole run partial, which closed nothing anywhere.
        """
        if not success:
            return RUN_PARTIAL
        # A phase that ran but could not finish (``note_phase_incomplete``) is
        # judged per domain too: its checks read PARTIAL, so nothing of that
        # domain closes. For the TARGET domain the caller already passes
        # ``success=False`` (``adscan ci``'s assessment gap reads the same
        # record), which is what makes the run partial.
        if any(self.phases_completed(d) for d in self._completed):
            return RUN_COMPLETE
        return RUN_PARTIAL

    def finish(self, run_status: str) -> RunCoverage:
        """Close the run with ``run_status`` and return its coverage.

        Every scan phase runs in the authenticated pipeline, so a run that
        started without credentials but completed a phase (credentials were
        found and the authenticated scan ran) observed with an authenticated
        vantage.
        """
        self._run_status = run_status
        if any(self.phases_completed(d) for d in self._completed):
            self._vantage = max(self._vantage, Vantage.AUTH)
        return self.snapshot()

    def observation_record(self) -> ObservationRecord:
        """Return the run's observation record as currently recorded."""
        return ObservationRecord(
            run_id=self._run_id,
            run_status=self._run_status,
            vantage=self._vantage,
            observations=dict(self._observations),
        )

    def snapshot(self) -> RunCoverage:
        """Return the coverage as currently recorded (a view of the record)."""
        return coverage_from_observations(self.observation_record())

    def _elapsed(self) -> dict[str, Any]:
        return {"elapsed_seconds": round(time.monotonic() - self._started_monotonic, 1)}

    def write(self, path: str) -> None:
        """Atomically write ``coverage.json``; unfinished runs read ``interrupted``.

        ``incomplete_phases`` names every phase that ran but did not finish
        (empty list when none), so a reader never has to infer it from the
        per-check reasons.
        """
        extra = {**self._elapsed(), "incomplete_phases": self.incomplete_phases()}
        doc = run_coverage_to_document(self.snapshot(), run_id=self._run_id, extra=extra)
        write_json_atomic(path, doc)

    def write_observations(self, path: str) -> None:
        """Atomically write ``observations.json`` (the record coverage is derived from)."""
        doc = observation_record_to_document(self.observation_record(), extra=self._elapsed())
        write_json_atomic(path, doc)


def record_from_scan_state(
    recorder: CoverageRecorder,
    domains_data: Mapping[str, Any],
    *,
    disabled_phases: Iterable[str],
    disabled_steps: Mapping[str, Iterable[str]],
    cve_all_hosts: bool = True,
) -> None:
    """Derive one record per ``(check, domain)`` from what this run did.

    Every known check id gets a record for every domain the workspace knows or
    a seam reported, so a check the run never completed is explicitly
    ``SKIPPED`` rather than silently absent.

    Args:
        recorder: The run's recorder, carrying the run-local seam notes.
        domains_data: The workspace domains (posture and ADCS detection are read
            from it).
        disabled_phases: Phases the scan config disabled.
        disabled_steps: Sub-steps disabled per phase.
        cve_all_hosts: Whether CVE verification scanned every host or only the
            domain controllers.
    """
    disabled = set(disabled_phases)
    steps = {k: tuple(v) for k, v in disabled_steps.items()}
    domains = {_dom(d): (d, e) for d, e in domains_data.items()}
    for noted in recorder.noted_domains():
        domains.setdefault(noted, (noted, {}))
    for key, (_name, entry) in sorted(domains.items()):
        data = entry if isinstance(entry, Mapping) else {}
        completed = recorder.phases_completed(key)
        for check_id, phase_id in CHECK_TO_PHASE.items():
            if recorder.has(check_id, key):
                continue  # an explicit record is never overridden
            status, reason = _phase_status(
                recorder, key, check_id, phase_id, completed, disabled, steps
            )
            extra: dict[str, Any] = {}
            if status is CheckStatus.RAN:
                status, reason, extra = _refine(
                    recorder, key, check_id, data, cve_all_hosts=cve_all_hosts
                )
            recorder.record(check_id, status, domain_id=key, reason=reason, source="phase", **extra)


def _phase_status(
    recorder: CoverageRecorder,
    domain: str,
    check_id: str,
    phase_id: str,
    completed: frozenset[str],
    disabled: set[str],
    steps: Mapping[str, tuple[str, ...]],
) -> tuple[CheckStatus, str]:
    """Status of a check from its phase alone (before per-check refinement)."""
    if phase_id in disabled:
        return CheckStatus.SKIPPED, REASON_DISABLED
    done_marker = _COMPLETION_PHASE.get(check_id, phase_id)
    if done_marker not in completed:
        reason = recorder.not_run_reason(domain, done_marker) or REASON_NOT_COMPLETED
        return CheckStatus.SKIPPED, reason
    if check_id in _NEEDS_COLLECTION and not recorder.collected(domain):
        return CheckStatus.SKIPPED, REASON_NOT_COLLECTED
    incomplete = recorder.incomplete_reasons(domain, phase_id)
    if incomplete:
        return CheckStatus.PARTIAL, f"{REASON_PHASE_INCOMPLETE}:{','.join(incomplete)}"
    failed = recorder.failed_steps(domain, phase_id) + (
        recorder.failed_steps(domain, done_marker) if done_marker != phase_id else ()
    )
    if failed:
        return CheckStatus.FAILED, f"{REASON_STEP_FAILED}:{','.join(sorted(set(failed)))}"
    skipped_steps = steps.get(phase_id, ())
    if skipped_steps:
        return (
            CheckStatus.PARTIAL,
            f"{REASON_SUBPHASE_DISABLED}:{','.join(sorted(skipped_steps))}",
        )
    return CheckStatus.RAN, ""


def _refine(
    recorder: CoverageRecorder,
    domain: str,
    check_id: str,
    data: Mapping[str, Any],
    *,
    cve_all_hosts: bool,
) -> tuple[CheckStatus, str, dict[str, Any]]:
    """Narrow a phase-level RAN with what the check itself observed."""
    if check_id == C_AUDIT_HOSTS and not cve_all_hosts:
        return CheckStatus.PARTIAL, REASON_CVE_SCOPE_DCS, {"scope_kind": "host"}
    if check_id.startswith(POSTURE_PREFIX):
        category = check_id[len(POSTURE_PREFIX):]
        if _posture_observed(data, domain, category):
            return CheckStatus.RAN, "", {}
        return CheckStatus.SKIPPED, REASON_POSTURE_UNOBSERVED, {}
    if check_id == C_ADCS:
        if isinstance(data.get("adcs_detected"), bool):
            return CheckStatus.RAN, "", {}
        return CheckStatus.SKIPPED, REASON_ADCS_INCONCLUSIVE, {}
    if check_id == C_COLLECTION_MSSQL:
        # A SQL Server read that never happened (lost connection, unrecovered
        # clock skew) has its own incomplete mark (``collection_integrity``).
        cut_off = recorder.incomplete_reasons(domain, C_COLLECTION_MSSQL)
        if cut_off:
            return (
                CheckStatus.PARTIAL,
                f"{REASON_PHASE_INCOMPLETE}:{','.join(cut_off)}",
                {"scope_kind": "host"},
            )
        return CheckStatus.PARTIAL, REASON_MSSQL_UNRECORDED, {"scope_kind": "host"}
    if check_id == C_COLLECTION_HOSTS:
        return _host_sweep_status(recorder, domain, data)
    return CheckStatus.RAN, "", {}


def _host_sweep_status(
    recorder: CoverageRecorder, domain: str, data: Mapping[str, Any]
) -> tuple[CheckStatus, str, dict[str, Any]]:
    """RAN only when every candidate host was examined; else PARTIAL with the set.

    The examined set lets reconciliation close host items on the hosts the sweep
    did examine, which it could not do when the record carried only counts (on a
    real estate some computer accounts are always stale, so the sweep is always
    partial by count).
    """
    examined = recorder.examined_hosts(domain)
    if examined is None:
        return CheckStatus.RAN, "", {}
    hosts = data.get("host_collection")
    hosts = hosts if isinstance(hosts, Mapping) else {}
    candidates = _int(hosts.get("candidates"))
    reachable = _int(hosts.get("reachable"))
    complete = (
        candidates is not None
        and reachable is not None
        and (_int(hosts.get("unreachable")) or 0) == 0
        and (_int(hosts.get("budget_timeouts")) or 0) == 0
        and len(examined) >= max(candidates, reachable)
    )
    if complete:
        return CheckStatus.RAN, "", {}
    return (
        CheckStatus.PARTIAL,
        REASON_HOSTS_UNEXAMINED,
        {
            "scope_kind": "host",
            "examined": len(examined),
            "total": candidates,
            "examined_ids": examined,
        },
    )


def _posture_observed(data: Mapping[str, Any], domain: str, category: str) -> bool:
    """Whether the DC gave a definitive, current answer for a posture category.

    The bar is ``ConstraintState.is_observed``, the same one the positive-evidence
    channel (``positive_control_evidence``) greens a control on: one notion of
    "observed", whichever surface asks.
    """
    try:
        from adscan_internal.services.domain_posture import (
            ConstraintCategory,
            get_posture,
        )

        constraint = get_posture({domain: data}, domain=domain).get(
            ConstraintCategory(category)
        )
    except Exception:  # noqa: BLE001 - an unreadable posture is "not observed"
        return False
    return constraint.is_observed


def _int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def record_from_coverage_blocks(
    recorder: CoverageRecorder,
    domains_data: Mapping[str, Any],
    technical_report: Optional[Mapping[str, Any]],
) -> None:
    """Turn every bounded / sampled / aborted collection signal into a PARTIAL check.

    The sources are the coverage blocks the engine already persists, never new
    counters:

    * ``attack_path_coverage`` (bounded or sampled discovery) -> ``attack_paths_discovery``;
    * ``host_enrichment_coverage`` / ``collection_coverage`` (host sweep capped,
      skipped or stopped early), ``host_reach_coverage`` (enabled computers the
      assessment could not reach over the network), ``domains_data[d]["share_collection"]`` (share
      enumeration aborted on hosts) and ``domains_data[d]["host_collection"]``
      (hosts unreachable on the 445 gate, per-host budget timeouts)
      -> ``domain_collection.hosts``;
    * ``cracking_coverage`` -> ``credential_cracking``;
    * ``vantage_coverage`` (proven but unexercised privileges) -> ``privilege_exercise``.

    Only the host sweep and attack-path coverage carry COUNTS (recorded as
    ``examined``/``total``). The host sweep's PARTIAL also carries the set of
    hosts it fully examined when the collector reported one this run
    (:func:`note_collection_hosts`), so items on those hosts can still close;
    every other PARTIAL here has no examined set and closes nothing for its
    check, which is the conservative reading.

    ``technical_report`` is ``None`` when the report could not be read; the two
    checks that depend on its blocks then go PARTIAL (``coverage_unreadable``)
    rather than being assumed complete.
    """
    report_domains: Mapping[str, Any] = {}
    if isinstance(technical_report, Mapping):
        raw = technical_report.get("domains")
        if isinstance(raw, Mapping):
            report_domains = {str(k).lower(): v for k, v in raw.items()}

    for domain, entry in domains_data.items():
        key = str(domain).lower()
        data = entry if isinstance(entry, Mapping) else {}
        if technical_report is None:
            recorder.record(C_PATHS, CheckStatus.PARTIAL, domain_id=key, reason=REASON_UNREADABLE)
            recorder.record(
                C_COLLECTION_HOSTS,
                CheckStatus.PARTIAL,
                domain_id=key,
                scope_kind="host",
                examined_ids=recorder.examined_hosts(key),
                reason=REASON_UNREADABLE,
            )
            continue
        block = report_domains.get(key)
        block = block if isinstance(block, Mapping) else {}

        paths = block.get("attack_path_coverage")
        if isinstance(paths, Mapping) and paths.get("complete") is False:
            recorder.record(
                C_PATHS,
                CheckStatus.PARTIAL,
                domain_id=key,
                scope_kind="route",
                examined=_int(paths.get("examined_routes")),
                reason=f"attack_path_{paths.get('mode') or 'bounded'}",
            )

        reasons: list[str] = []
        examined: Optional[int] = None
        total: Optional[int] = None
        enrich = block.get("host_enrichment_coverage")
        legacy = block.get("collection_coverage")
        for source, label in ((enrich, "host_enrichment"), (legacy, "collection")):
            if not isinstance(source, Mapping):
                continue
            bounded = source.get("complete") is False or source.get("early_stopped") is True
            if bounded:
                reasons.append(f"{label}_{source.get('reason') or 'bounded'}")
                examined = _int(source.get("hosts_swept"))
                total = _int(source.get("hosts_total"))
        # Enabled computers the assessment could not reach over the network
        # (unanswered, unresolvable or never measured): their host-level items
        # were not re-evaluated, so nothing on them may close as remediated.
        reach = block.get("host_reach_coverage")
        if isinstance(reach, Mapping) and reach.get("complete") is False:
            reasons.append("network_unreached")
        # Servers the pacing safeguard paused because they stopped responding:
        # their remaining checks did not run, so nothing on them may close.
        pacing = block.get("scan_pacing")
        strain = pacing.get("strain") if isinstance(pacing, Mapping) else None
        if isinstance(strain, Mapping) and strain.get("paused_hosts"):
            reasons.append("paused_by_strain_safeguard")
        shares = data.get("share_collection")
        if isinstance(shares, Mapping) and shares.get("aborted_hosts"):
            reasons.append("share_aborted")
        hosts = data.get("host_collection")
        if isinstance(hosts, Mapping):
            if (_int(hosts.get("unreachable")) or 0) > 0:
                reasons.append("unreachable_hosts")
            if (_int(hosts.get("budget_timeouts")) or 0) > 0:
                reasons.append("host_budget_timeout")
        examined_ids = recorder.examined_hosts(key)
        if reasons:
            recorder.record(
                C_COLLECTION_HOSTS,
                CheckStatus.PARTIAL,
                domain_id=key,
                scope_kind="host",
                examined=len(examined_ids) if examined_ids is not None else examined,
                total=total,
                examined_ids=examined_ids,
                reason=",".join(sorted(set(reasons))),
            )

        cracking = block.get("cracking_coverage")
        if isinstance(cracking, Mapping) and cracking.get("complete") is False:
            recorder.record(
                C_CRACKING, CheckStatus.PARTIAL, domain_id=key, reason="cracking_incomplete"
            )
        vantage = block.get("vantage_coverage")
        if isinstance(vantage, Mapping) and vantage.get("complete") is False:
            recorder.record(
                C_PRIV_EXERCISE,
                CheckStatus.PARTIAL,
                domain_id=key,
                reason="privilege_unexercised",
            )


def _read_technical_report(shell: Any) -> Optional[Mapping[str, Any]]:
    """Return the parsed ``technical_report.json`` or ``None`` when unreadable."""
    import json
    import os

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    if not workspace_dir:
        return None
    path = os.path.join(workspace_dir, "technical_report.json")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, Mapping) else None


# ---------------------------------------------------------------------------
# Run-level wiring (``adscan ci``): best-effort, never allowed to break a scan.
# ---------------------------------------------------------------------------

COVERAGE_FILENAME = "coverage.json"


def _coverage_path(shell: Any) -> str:
    import os

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    return os.path.join(workspace_dir, COVERAGE_FILENAME) if workspace_dir else ""


def _observations_path(shell: Any) -> str:
    import os

    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    return os.path.join(workspace_dir, OBSERVATIONS_FILENAME) if workspace_dir else ""


#: Workspace directory -> the recorder of the run THIS PROCESS executes there.
#: A detector reached through a stub shell built over the workspace (the
#: render-time enrichment passes) still records into the run's record, the
#: same way artifact writers resolve the run id (``coverage_io``).
_ACTIVE_RECORDERS: dict[str, CoverageRecorder] = {}


def _workspace_key(shell: Any) -> str:
    import os

    text = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    return os.path.abspath(text) if text else ""


def _active_recorder(shell: Any) -> Optional[CoverageRecorder]:
    recorder = getattr(shell, "_coverage_recorder", None)
    if isinstance(recorder, CoverageRecorder):
        return recorder
    key = _workspace_key(shell)
    return _ACTIVE_RECORDERS.get(key) if key else None


def _write_files(shell: Any, recorder: CoverageRecorder) -> None:
    coverage_path = _coverage_path(shell)
    if coverage_path:
        recorder.write(coverage_path)
    observations_path = _observations_path(shell)
    if observations_path:
        recorder.write_observations(observations_path)


def start_run_coverage(shell: Any, *, authenticated: bool) -> Optional[CoverageRecorder]:
    """Create the run's recorder and persist the ``interrupted`` default at once.

    Writing the file immediately means a run that crashes, is killed or is
    promoted by a ``finally`` path leaves a ``coverage.json`` that closes nothing,
    rather than no file (which the reader also treats as closing nothing, but
    would let a stale file from a PREVIOUS run in the same workspace speak for
    this one).
    """
    try:
        from adscan_core.engagement.coverage_io import register_active_run
        from adscan_core.engagement.run_identity import current_run_id

        recorder = CoverageRecorder()
        # The run's id is process-wide (an orchestrator's ADSCAN_RUN_ID, or one
        # minted once), so coverage, the event stream header and the run
        # summary all name the same run.
        recorder.begin_run(
            current_run_id(), Vantage.AUTH if authenticated else Vantage.UNAUTH
        )
        shell._coverage_recorder = recorder
        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
        # Declare the run for the WHOLE process, so the artifact writers that
        # build a stub shell over the workspace directory (the render-time
        # report enrichment passes) stamp it too. Stamping off the writer's
        # object alone let the report's LAST write drop the id, which left the
        # run's coverage unable to judge the report and closed nothing.
        register_active_run(workspace_dir, recorder.run_id)
        key = _workspace_key(shell)
        if key:
            _ACTIVE_RECORDERS[key] = recorder
        _install_control_evidence_observer()
        _write_files(shell, recorder)
        return recorder
    except Exception as exc:  # noqa: BLE001 - coverage must never break the scan
        _report_failure(exc)
        return None


def finalize_run_coverage(shell: Any, *, success: bool) -> None:
    """Derive per-domain coverage from the scan checkpoint and write the final file."""
    recorder = getattr(shell, "_coverage_recorder", None)
    if recorder is None:
        return
    try:
        domains_data = getattr(shell, "domains_data", None) or {}
        config = getattr(shell, "scan_config", None)
        phases = getattr(config, "phases", None)
        # Bounded / aborted collection first: explicit records win over derivation.
        record_from_coverage_blocks(
            recorder, domains_data, _read_technical_report(shell)
        )
        record_from_scan_state(
            recorder,
            domains_data,
            disabled_phases=tuple(getattr(phases, "disabled", ()) or ()),
            disabled_steps=dict(getattr(phases, "steps", {}) or {}),
            cve_all_hosts=_cve_scans_every_host(shell),
        )
        status = recorder.derived_run_status(success=success)
        recorder.finish(status)
        withdraw_contradicted_positives(shell, recorder)
        _write_files(shell, recorder)
    except Exception as exc:  # noqa: BLE001 - the file stays at its safe default
        _report_failure(exc)


def _cve_scans_every_host(shell: Any) -> bool:
    """Mirror ``ask_for_enum_cve``: is the every-host CVE pass part of this run?"""
    scope = "default"
    try:
        config = getattr(shell, "scan_config", None)
        raw = getattr(getattr(config, "audit_extras", None), "target_scope", None)
        scope = str(raw) if raw else "default"
    except Exception:  # noqa: BLE001 - unreadable config reads as the default
        scope = "default"
    if scope == "all_hosts":
        return True
    if scope == "default":
        return policy_settings.runs_full_assessment(shell)
    return False


def active_run_id(shell: Any) -> str:
    """Return the id of the run writing through ``shell`` ('' outside one).

    Artifact writers stamp it (``coverage_io.stamp_artifact_run_id``) so the
    run's ``coverage.json`` can later be matched to the files it describes.

    Falls back to the run this PROCESS registered for the shell's workspace, so
    a writer handed a stub shell built over a workspace directory (the
    render-time enrichment passes) still binds the artifact to the run that
    produced it. A later process has nothing registered, so its rewrite clears
    the id exactly as before.
    """
    from adscan_core.engagement.coverage_io import active_run_id_for_workspace

    recorder = getattr(shell, "_coverage_recorder", None)
    run_id = str(getattr(recorder, "run_id", "") or "") if recorder is not None else ""
    return run_id or active_run_id_for_workspace(
        getattr(shell, "current_workspace_dir", "")
    )


def _note(shell: Any, method: str, *args: Any) -> None:
    """Forward a seam note to the active recorder. Never raises."""
    recorder = getattr(shell, "_coverage_recorder", None)
    if recorder is None:
        return
    try:
        getattr(recorder, method)(*args)
    except Exception as exc:  # noqa: BLE001 - coverage must never break the scan
        _report_failure(exc)


def note_phase_completed(shell: Any, domain: str, phase_id: str) -> None:
    """Seam: a phase finished in this run (called by ``mark_phase_complete``)."""
    _note(shell, "note_phase_completed", domain, phase_id)


def note_phase_not_run(shell: Any, domain: str, phase_id: str, reason: str) -> None:
    """Seam: a phase is being marked done without running (cached / not computed)."""
    _note(shell, "note_phase_not_run", domain, phase_id, reason)


def note_step_failed(shell: Any, domain: str, phase_id: str, step: str) -> None:
    """Seam: a pipeline step raised and the phase continued without it."""
    _note(shell, "note_step_failed", domain, phase_id, step)


def note_collection_ran(shell: Any, domain: str) -> None:
    """Seam: the collector ran and persisted ``domain`` in this run."""
    _note(shell, "note_collection_ran", domain)


def note_collection_hosts(shell: Any, domain: str, host_ids: Iterable[str]) -> None:
    """Seam: hosts the collector's sweep fully examined in this run."""
    _note(shell, "note_collection_hosts", domain, list(host_ids))


def note_observation(
    shell: Any,
    check_id: str,
    outcome: Outcome,
    *,
    domain: str,
    persist: bool = False,
    **fields: Any,
) -> None:
    """Seam: a detector family reports what it did and found. Never raises.

    Called by the code that performed the check, at the moment it ran. Without
    an active run (an interactive session, a LITE report render) it does
    nothing: the record belongs to a recorded run.

    Args:
        shell: The scan shell, or any object exposing the workspace directory.
        check_id: The detector family (``adscan_core.engagement.detectors``).
        outcome: What the check concluded.
        domain: The domain observed.
        persist: Write ``observations.json`` now, for observations a later step
            of the same run reads back (raw per-object instances).
        **fields: :meth:`CoverageRecorder.observe` keyword arguments.
    """
    recorder = _active_recorder(shell)
    if recorder is None or not str(domain or "").strip():
        return
    try:
        recorder.observe(check_id, outcome, domain_id=domain, **fields)
        if persist:
            path = _observations_path(shell) or _registered_observations_path(recorder)
            if path:
                recorder.write_observations(path)
    except Exception as exc:  # noqa: BLE001 - coverage must never break the scan
        _report_failure(exc)


def flush_observations(shell: Any) -> None:
    """Seam: write ``observations.json`` now, for a later step of the run to read.

    Raw per-object observations (the AD CS rows) are read back by execution
    steps of the same run, before the run finalises. Never raises.
    """
    recorder = _active_recorder(shell)
    if recorder is None:
        return
    try:
        path = _observations_path(shell) or _registered_observations_path(recorder)
        if path:
            recorder.write_observations(path)
    except Exception as exc:  # noqa: BLE001 - coverage must never break the scan
        _report_failure(exc)


def _registered_observations_path(recorder: CoverageRecorder) -> str:
    import os

    for workspace, active in _ACTIVE_RECORDERS.items():
        if active is recorder:
            return os.path.join(workspace, OBSERVATIONS_FILENAME)
    return ""


def _install_control_evidence_observer() -> None:
    """Route every control-evidence write through the observation record."""
    from adscan_core.reporting.technical_report import (  # noqa: PLC0415
        register_control_evidence_observer,
    )

    register_control_evidence_observer(_control_evidence_observer)


#: Control-evidence status of a catalog finding whose check ran and found nothing.
_VERIFIED_CLEAR = "verified_clear"
_WITHDRAWN_STATUS = "not_assessed"
_withdrawing = False


def _control_evidence_observer(
    shell: Any, domain: str, key: str, status: str, details: Mapping[str, Any]
) -> None:
    """Observer installed on ``record_control_evidence`` for the run."""
    if _withdrawing:
        return  # our own withdrawal write is not a new observation
    if str(status or "").lower() == _VERIFIED_CLEAR:
        from adscan_core.engagement.detectors import detector_for  # noqa: PLC0415

        detector = detector_for("finding", key)
        if detector is not None:
            note_observation(shell, detector.check_id, Outcome.CLEAR, domain=domain)
        return
    observe_positive(shell, domain, key=key, status=status, details=details)


def withdraw_contradicted_positives(shell: Any, recorder: CoverageRecorder) -> list[str]:
    """Withdraw a recorded positive its own detector's observation does not support.

    A positive is green only when the family observed the whole scope clear.
    When the same run's record says otherwise (the family also reported a
    finding, or could not assess part of its scope), the scorecard entry is set
    back to ``not_assessed`` with the reason, so the compliance view and the
    observation record agree on what is green. Best-effort.

    Returns:
        The withdrawn ``(domain:key)`` labels, for diagnostics.
    """
    global _withdrawing  # noqa: PLW0603
    from adscan_core.engagement.observations import positive_observations  # noqa: PLC0415

    record = recorder.observation_record()
    supported = {(o.domain_id, o.positive_key) for o in positive_observations(record)}
    contradicted = [
        obs
        for obs in record.observations.values()
        if obs.positive_key
        and obs.source == "detector"
        and (obs.domain_id, obs.positive_key) not in supported
        and obs.outcome is not Outcome.NOT_ASSESSED
    ]
    if not contradicted:
        return []
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            _load_technical_report,
            record_control_evidence,
        )

        report = _load_technical_report(shell)
        domains = report.get("domains") if isinstance(report, Mapping) else None
        withdrawn: list[str] = []
        _withdrawing = True
        for obs in contradicted:
            entry = _control_evidence_entry(domains, obs.domain_id, obs.positive_key)
            if entry is None or entry[1].get("status") != "observed":
                continue
            reason = (
                "observation_found_weakness"
                if obs.outcome is Outcome.FINDING
                else "observation_incomplete"
            )
            record_control_evidence(
                shell,
                entry[0],
                key=obs.positive_key,
                status=_WITHDRAWN_STATUS,
                details={"withdrawn_reason": reason, "observation_reason": obs.reason},
            )
            withdrawn.append(f"{obs.domain_id}:{obs.positive_key}")
        return withdrawn
    except Exception as exc:  # noqa: BLE001 - never break the run's finalisation
        _report_failure(exc)
        return []
    finally:
        _withdrawing = False


def _control_evidence_entry(
    domains: Any, domain_id: str, key: str
) -> Optional[tuple[str, Mapping[str, Any]]]:
    if not isinstance(domains, Mapping):
        return None
    for name, block in domains.items():
        if str(name).strip().lower() != domain_id or not isinstance(block, Mapping):
            continue
        for item in block.get("control_evidence") or ():
            if isinstance(item, Mapping) and item.get("key") == key:
                return str(name), item
    return None


def observe_positive(
    shell: Any,
    domain: str,
    *,
    key: str,
    status: str = "observed",
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    """Seam: a compliance positive is being recorded; record its observation first.

    Every positive control the engine records flows through here (the single
    recorder seam of ``positive_control_evidence``), so the positive is the
    detector family's clear observation, not a second answer to "was this
    checked". ``status="observed"`` is a clear, complete reading; anything else
    is the family reporting it could not assess (grey, never green).
    """
    from adscan_core.engagement.detectors import detector_for_positive_key  # noqa: PLC0415

    detector = detector_for_positive_key(key)
    if detector is None:
        return
    data = details if isinstance(details, Mapping) else {}
    examined = data.get("examined")
    examined = examined if isinstance(examined, int) and not isinstance(examined, bool) else None
    if str(status or "").lower() == "observed":
        note_observation(
            shell,
            detector.check_id,
            Outcome.CLEAR,
            domain=domain,
            examined=examined,
            positive_key=key,
        )
    else:
        note_observation(
            shell,
            detector.check_id,
            Outcome.NOT_ASSESSED,
            domain=domain,
            complete=False,
            reason=str(data.get("reason") or status or "not_assessed"),
            positive_key=key,
        )


def _report_failure(exc: BaseException) -> None:
    from adscan_core import telemetry
    from adscan_core.rich_output import print_exception, print_warning

    telemetry.capture_exception(exc)
    print_exception(exception=exc)
    print_warning("Run coverage could not be recorded; findings will not be auto-closed.")
