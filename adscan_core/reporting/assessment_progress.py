"""Assessment-to-assessment delta and period aggregation (single source of truth).

Every surface that tells a client how their exposure moved between assessments
reads this module: the assessment summary sent when a scan is ingested, the
periodic executive digest, the immediate regression alert, and the executive
progress report (PDF). They cannot disagree on what was new, what was closed or
what was not re-checked, because none of them derives it.

Pure by contract: stdlib plus sibling ``adscan_core`` modules, no ORM, no web
framework, no clock. A thin adapter turns persisted rows into the value types
below (``app/services/assessment_progress_source.py`` in the web backend) and
passes them in.

The rules every consumer inherits:

* **Not re-checked is never closed.** An item is closed only when its lifecycle
  recorded a closure. A route the latest run could not re-check keeps its status
  (the coverage-aware reconcile in ``adscan_core.engagement.reconcile``), so it
  lands in ``not_reevaluated``, never in ``closed_verified``.
* **Verified means an assessment observed it.** A closure counts as verified
  only when the closing transition came from an assessment. Accepting a risk or
  dismissing a finding is the client's decision and is reported apart.
* **A regression compares like for like.** It is a route executed end to end
  that the previous assessment did not map at all (or had closed and verified),
  a route the previous assessment tried without getting through that now
  succeeds, or a domain newly compromised through one of those. A route the
  previous assessment only mapped and this one executed is "newly validated",
  not a regression: the domain did not change, the evidence did. A route only
  mapped, or one whose entry step alone is proven, never alerts (Exposure
  Validation).
* **No figure without an assessment.** A period with no assessment carries the
  age of the last verification and nothing else, so an older scan's numbers can
  never read as the period's state.

Ordering. History rows are stamped by ingestion, which runs before the scan row
is marked complete and on a host whose wall clock ADscan may step to the domain
controller's. So an event written by an assessment is placed AT that assessment
(by its scan id), not by its own timestamp. Only events with no assessment (a
person's decision) are placed by their clock.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Mapping, Optional, Sequence

from adscan_core.reporting.execution_status import (
    DOMAIN_COMPROMISED_STATE,
    WEB_PROVEN_PATH_STATUSES,
)

__all__ = [
    "Assessment",
    "AssessmentDelta",
    "BUCKET_LABELS",
    "CADENCES",
    "ComplianceReading",
    "DEFAULT_CADENCE",
    "EVIDENCE_LABELS",
    "ExposureReading",
    "FAILED_ATTEMPT_STATUSES",
    "HeadlineFigures",
    "KindActivity",
    "MAPPED_EVIDENCE_LABEL",
    "ItemBuckets",
    "ItemRef",
    "PeriodActivity",
    "PeriodSummary",
    "Regressions",
    "StartHereAction",
    "StatusEvent",
    "TrackedItem",
    "TrendPoint",
    "compute_assessment_delta",
    "evidence_label",
    "previous_period_window",
    "summarize_period",
]

# ── Vocabulary ──────────────────────────────────────────────────────────────

#: Lifecycle statuses meaning "the route still exists". ACCEPTED is a client
#: decision to live with the route; the route is still there, so it stays present
#: (dropping it would report an accepted risk as resolved). Same set as the web
#: scan diff (``scan_diff_service._PATH_PRESENT_LIKE``).
ROUTE_PRESENT_STATUSES = frozenset({"active", "reopened", "accepted"})

#: Lifecycle statuses meaning "the finding is open". ACCEPTED and FALSE_POSITIVE
#: are client decisions and take the finding off the open set, reported apart.
FINDING_PRESENT_STATUSES = frozenset({"open", "reopened"})

#: The closing status an assessment writes when it proved the item absent.
REMEDIATED_STATUS = "remediated"

#: Execution tokens meaning the route was walked end to end (the shared SSOT).
VALIDATED_EXECUTION_STATUSES = frozenset(WEB_PROVEN_PATH_STATUSES) | {
    DOMAIN_COMPROMISED_STATE
}

NOT_REEVALUATED_STATE = "not_reevaluated"

#: Digest cadences. ``off`` sends nothing.
CADENCES = ("weekly", "monthly", "quarterly", "off")
DEFAULT_CADENCE = "monthly"

#: Execution tokens meaning the previous assessment TRIED the route and it did
#: not get through: it did not complete, or the configuration closed it. A
#: route in one of these states that now succeeds is a like-for-like change in
#: the domain, so it is a regression. A safety abstention (``blocked``) is
#: ADscan's own restraint and a route only mapped (``theoretical``) was never
#: tried: neither is a comparison, so their success now is "newly validated".
FAILED_ATTEMPT_STATUSES = frozenset({"attempted", "closed_by_configuration"})

#: Client-facing bucket names, one wording for every surface (email, Slack,
#: the platform and the progress PDF).
BUCKET_LABELS: Mapping[str, str] = {
    "new": "New",
    "still_open": "Still open",
    "closed_verified": "Closed and verified",
    "closed_by_decision": "Accepted or dismissed by your team",
    "not_reevaluated": "Not re-checked in this assessment",
}

#: What the evidence for one route is, keyed by the stored web execution token
#: (``adscan_core.reporting.execution_status``). Lower case: it is shown in
#: parentheses after the route. Anything not listed was mapped, not executed.
EVIDENCE_LABELS: Mapping[str, str] = {
    "domain_compromised": "executed end to end",
    "success": "executed end to end",
    "partial": "entry step proven",
    "blocked": "not executed for safety",
    "attempted": "attempted, not completed",
    "closed_by_configuration": "closed by configuration",
}
MAPPED_EVIDENCE_LABEL = "mapped, not executed"


def evidence_label(execution_status: Optional[str]) -> str:
    """Return the client wording of a route's evidence (never stronger than proven)."""
    return EVIDENCE_LABELS.get(str(execution_status or "").strip().lower(), MAPPED_EVIDENCE_LABEL)


# ── Value types (what the adapter hands in) ─────────────────────────────────


@dataclass(frozen=True)
class HeadlineFigures:
    """Headline figures one assessment stamped, read from its own snapshot.

    ``None`` means the assessment did not stamp the figure. A consumer says
    "Not recorded", never ``0``.
    """

    routes_to_full_compromise: Optional[int] = None
    routes_executed_end_to_end: Optional[int] = None
    tier0_foothold_routes: Optional[int] = None
    ordinary_accounts_with_path: Optional[int] = None
    ordinary_accounts_total: Optional[int] = None

    def get(self, name: str) -> Optional[int]:
        """Return a figure by name (``None`` when unknown or unstamped)."""
        return getattr(self, name, None)


@dataclass(frozen=True)
class StartHereAction:
    """The first row of the "Start here" ranking the assessment stamped."""

    label: str
    line: str = ""
    proven: bool = False


@dataclass(frozen=True)
class ExposureReading:
    """The AD Exposure Score one assessment stamped (``summary.exposure``).

    Percentages of the maximum exposure score, higher is worse. ``None`` means
    the assessment did not stamp the figure.
    """

    overall_pct: Optional[float] = None
    proven_pct: Optional[float] = None


@dataclass(frozen=True)
class ComplianceReading:
    """One framework's stamped coverage at one assessment.

    Only frameworks the engagement selected are stamped, so a reading exists
    only for those. ``score`` is the conformant share of ASSESSED controls; a
    framework with no assessed control has no score (see :attr:`display_score`).
    """

    key: str
    label: str
    score: Optional[int] = None
    conformant: int = 0
    assessed: int = 0
    non_conformant: int = 0
    partially_conformant: int = 0

    @property
    def display_score(self) -> Optional[int]:
        """The score, or ``None`` when no control was assessed (never ``0``)."""
        if self.assessed <= 0 or self.score is None:
            return None
        return int(self.score)


@dataclass(frozen=True)
class Assessment:
    """One completed, ingested assessment of a workspace.

    ``start_here`` is the first "Start here" row; ``start_here_actions`` the
    leading rows in their stamped order (the first equals ``start_here``).
    """

    scan_id: str
    completed_at: datetime
    figures: Optional[HeadlineFigures] = None
    start_here: Optional[StartHereAction] = None
    exposure: Optional[ExposureReading] = None
    compliance: tuple[ComplianceReading, ...] = ()
    start_here_actions: tuple[StartHereAction, ...] = ()


@dataclass(frozen=True)
class StatusEvent:
    """One recorded transition (lifecycle or execution status).

    ``scan_id`` is set when an assessment wrote the event; ``by_assessment`` is
    False when a person did (accepting a risk, dismissing a finding).
    """

    status: str
    at: datetime
    scan_id: Optional[str] = None
    by_assessment: bool = True


@dataclass(frozen=True)
class TrackedItem:
    """A route or finding with its recorded history.

    Attributes:
        kind: ``"route"`` or ``"finding"``.
        reaches_tier0: For a route, whether its compromise class reaches a
            Tier 0 asset (decided by the caller from the shared tier predicate).
        reaches_full_compromise: For a route, whether it ends in full domain
            compromise.
        evaluation_state / last_reevaluated_scan_id: The row's coverage-aware
            reconcile stamp. It describes the LATEST ingested assessment only.
        current_execution_status: Fallback for rows written before execution
            history existed.
    """

    item_id: str
    kind: str
    domain: str
    title: str
    status_events: tuple[StatusEvent, ...] = ()
    execution_events: tuple[StatusEvent, ...] = ()
    first_seen: Optional[datetime] = None
    evaluation_state: Optional[str] = None
    last_reevaluated_scan_id: Optional[str] = None
    current_execution_status: Optional[str] = None
    reaches_tier0: bool = False
    reaches_full_compromise: bool = False
    severity: Optional[str] = None


# ── Result types ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ItemRef:
    """One item as it stood at the later assessment of a comparison."""

    item_id: str
    kind: str
    domain: str
    title: str
    execution_status: Optional[str] = None
    validated: bool = False
    severity: Optional[str] = None


@dataclass(frozen=True)
class ItemBuckets:
    """Where each item landed between two assessments."""

    new: tuple[ItemRef, ...] = ()
    still_open: tuple[ItemRef, ...] = ()
    closed_verified: tuple[ItemRef, ...] = ()
    closed_by_decision: tuple[ItemRef, ...] = ()
    not_reevaluated: tuple[ItemRef, ...] = ()

    @property
    def open_count(self) -> int:
        """Items open at the later assessment (new, still open, not re-checked)."""
        return len(self.new) + len(self.still_open) + len(self.not_reevaluated)


@dataclass(frozen=True)
class Regressions:
    """Alert-worthy changes, compared like for like with the previous assessment.

    * ``new_validated_routes``: executed end to end now and ABSENT from the
      previous assessment's mapping (never seen, or closed and verified then).
    * ``newly_succeeding_routes``: present before, where the previous
      assessment tried it and it did not get through
      (:data:`FAILED_ATTEMPT_STATUSES`), and it succeeds now.
    * ``domains_newly_compromised``: a domain with no full-compromise route
      executed before, compromised now through one of the two kinds above.

    A route the previous assessment only mapped and this one executed is not a
    regression; it is reported as newly validated.
    """

    new_validated_routes: tuple[ItemRef, ...] = ()
    domains_newly_compromised: tuple[str, ...] = ()
    newly_succeeding_routes: tuple[ItemRef, ...] = ()

    @property
    def any(self) -> bool:
        """True when at least one regression happened."""
        return bool(
            self.new_validated_routes
            or self.newly_succeeding_routes
            or self.domains_newly_compromised
        )


@dataclass(frozen=True)
class AssessmentDelta:
    """What changed from ``previous`` to ``current``.

    ``previous`` is ``None`` for the first assessment of a workspace: a baseline,
    with every open item in ``new`` and no regression (there is nothing to
    regress from).
    """

    previous: Optional[Assessment]
    current: Assessment
    routes: ItemBuckets
    findings: ItemBuckets
    newly_validated: tuple[ItemRef, ...]
    regressions: Regressions

    @property
    def is_baseline(self) -> bool:
        """True when there is no earlier assessment to compare against."""
        return self.previous is None

    def figure_change(self, name: str) -> tuple[Optional[int], Optional[int]]:
        """Return ``(previous, current)`` for a headline figure."""
        prev = (
            self.previous.figures.get(name)
            if self.previous is not None and self.previous.figures is not None
            else None
        )
        cur = self.current.figures.get(name) if self.current.figures is not None else None
        return prev, cur


@dataclass(frozen=True)
class TrendPoint:
    """One assessment on a trend line, with what that assessment stamped."""

    scan_id: str
    completed_at: datetime
    figures: Optional[HeadlineFigures]
    exposure: Optional[ExposureReading] = None
    compliance: tuple[ComplianceReading, ...] = ()


@dataclass(frozen=True)
class KindActivity:
    """What happened to one kind of item (Tier 0 routes, or findings) in a period.

    Unlike :attr:`PeriodSummary.overall`, which compares only the state at the
    start with the state at the end, this counts the assessments inside the
    period one by one, so an item found and fixed within the same period is
    both found and closed.

    * ``found``: first seen (or reopened) by an assessment inside the period.
    * ``closed_verified``: closed by an assessment that observed the closure,
      and still closed at the end of the period. A closure reopened later in
      the period is not counted.
    * ``closed_by_decision``: accepted or dismissed by the client's team, and
      still so at the end.
    * ``not_reevaluated``: open at the end, not re-checked by the last
      assessment. Never closed.
    * ``open_at_end``: open at the end (new, still open or not re-checked).
    * ``remediation_days``: per verified closure, the days from the item being
      opened to the assessment that observed it closed.
    """

    found: tuple[ItemRef, ...] = ()
    closed_verified: tuple[ItemRef, ...] = ()
    closed_by_decision: tuple[ItemRef, ...] = ()
    not_reevaluated: tuple[ItemRef, ...] = ()
    open_at_end: int = 0
    remediation_days: tuple[float, ...] = ()

    @property
    def mean_days_to_remediate(self) -> Optional[float]:
        """Mean of :attr:`remediation_days`, ``None`` without a verified closure."""
        if not self.remediation_days:
            return None
        return sum(self.remediation_days) / len(self.remediation_days)


@dataclass(frozen=True)
class PeriodActivity:
    """Activity inside a period: Tier 0 routes and findings."""

    routes: KindActivity = field(default_factory=KindActivity)
    findings: KindActivity = field(default_factory=KindActivity)


@dataclass(frozen=True)
class PeriodSummary:
    """State across a ``[window_start, window_end)`` period.

    ``overall`` compares the state at the period start (``baseline``, the last
    assessment before the window) with the state at its end (``end``, the last
    assessment inside it). ``regressions`` collects every regression seen at ANY
    step inside the period, so one that was later closed is still reported.
    """

    window_start: datetime
    window_end: datetime
    assessments_in_period: tuple[Assessment, ...]
    baseline: Optional[Assessment]
    end: Optional[Assessment]
    overall: Optional[AssessmentDelta]
    steps: tuple[AssessmentDelta, ...]
    regressions: Regressions
    trend: tuple[TrendPoint, ...]
    last_verified_at: Optional[datetime]
    days_since_last_verification: Optional[int]
    next_scheduled_at: Optional[datetime] = None
    baseline_in_period: bool = False
    activity: PeriodActivity = field(default_factory=PeriodActivity)

    @property
    def has_assessment(self) -> bool:
        """True when at least one assessment completed inside the window."""
        return bool(self.assessments_in_period)


# ── Internals ───────────────────────────────────────────────────────────────


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _token(value: Optional[str]) -> str:
    return str(value or "").strip().lower()


@dataclass(frozen=True)
class _Timeline:
    """Maps an assessment's scan id to its place in time."""

    at_by_scan: Mapping[str, datetime] = field(default_factory=dict)

    def effective_at(self, event: StatusEvent) -> datetime:
        if event.scan_id and event.scan_id in self.at_by_scan:
            return self.at_by_scan[event.scan_id]
        return _utc(event.at)

    def latest_at_or_before(
        self, events: Iterable[StatusEvent], boundary: datetime
    ) -> Optional[StatusEvent]:
        chosen: Optional[StatusEvent] = None
        chosen_key: Optional[tuple[datetime, datetime]] = None
        for event in events:
            eff = self.effective_at(event)
            if eff > boundary:
                continue
            key = (eff, _utc(event.at))
            if chosen_key is None or key >= chosen_key:
                chosen, chosen_key = event, key
        return chosen

    def latest_in(
        self, events: Iterable[StatusEvent], after: Optional[datetime], until: datetime
    ) -> Optional[StatusEvent]:
        chosen: Optional[StatusEvent] = None
        chosen_key: Optional[tuple[datetime, datetime]] = None
        for event in events:
            eff = self.effective_at(event)
            if eff > until or (after is not None and eff <= after):
                continue
            key = (eff, _utc(event.at))
            if chosen_key is None or key >= chosen_key:
                chosen, chosen_key = event, key
        return chosen


def _present_statuses(item: TrackedItem) -> frozenset[str]:
    return ROUTE_PRESENT_STATUSES if item.kind == "route" else FINDING_PRESENT_STATUSES


def _present_at(item: TrackedItem, boundary: datetime, timeline: _Timeline) -> bool:
    event = timeline.latest_at_or_before(item.status_events, boundary)
    if event is not None:
        return _token(event.status) in _present_statuses(item)
    # A row written before its first history entry existed: present from the
    # moment it was first seen.
    return item.first_seen is not None and _utc(item.first_seen) <= boundary


def _execution_at(
    item: TrackedItem, boundary: datetime, timeline: _Timeline
) -> Optional[str]:
    if not item.execution_events:
        return _token(item.current_execution_status) or None
    event = timeline.latest_at_or_before(item.execution_events, boundary)
    return _token(event.status) if event is not None else None


def _ref(item: TrackedItem, execution_status: Optional[str]) -> ItemRef:
    return ItemRef(
        item_id=item.item_id,
        kind=item.kind,
        domain=item.domain,
        title=item.title,
        execution_status=execution_status,
        validated=_token(execution_status) in VALIDATED_EXECUTION_STATUSES,
        severity=item.severity,
    )


def _not_rechecked(
    item: TrackedItem, current: Assessment, latest_scan_id: Optional[str]
) -> bool:
    """Whether ``current`` did not re-check an item present before and after.

    The row's reconcile stamp describes the LATEST ingested assessment only, so
    it is trusted for that one. For an older assessment the answer is unknown,
    and unknown is reported as still open: never as closed, never as a
    not-re-checked claim the data cannot support.
    """
    if item.last_reevaluated_scan_id and item.last_reevaluated_scan_id == current.scan_id:
        return False
    if latest_scan_id is None or current.scan_id != latest_scan_id:
        return False
    return _token(item.evaluation_state) == NOT_REEVALUATED_STATE


def _sort_refs(refs: list[ItemRef]) -> tuple[ItemRef, ...]:
    return tuple(
        sorted(refs, key=lambda r: (not r.validated, r.domain.lower(), r.title.lower()))
    )


def _timeline_for(assessments: Sequence[Assessment]) -> _Timeline:
    return _Timeline({a.scan_id: _utc(a.completed_at) for a in assessments})


def _opened_at(
    item: TrackedItem, closed_at: datetime, timeline: _Timeline
) -> Optional[datetime]:
    """When the open stretch that ``closed_at`` ended began.

    Walks the item's status events in their assessment order: the stretch starts
    at the first present event after the last absence, and ends at the closure.
    Falls back to ``first_seen`` for a row whose history predates the events.
    """
    present = _present_statuses(item)
    open_since: Optional[datetime] = None
    ordered = sorted(
        item.status_events, key=lambda e: (timeline.effective_at(e), _utc(e.at))
    )
    for event in ordered:
        eff = timeline.effective_at(event)
        if eff >= closed_at:
            break
        if _token(event.status) in present:
            if open_since is None:
                open_since = eff
        else:
            open_since = None
    if open_since is None and item.first_seen is not None:
        first = _utc(item.first_seen)
        open_since = first if first <= closed_at else None
    return open_since


def _kind_activity(
    kind: str,
    steps: Sequence[AssessmentDelta],
    overall: AssessmentDelta,
    items_by_id: Mapping[str, TrackedItem],
    timeline: _Timeline,
) -> KindActivity:
    """Count one kind's activity across the period's assessments, in order."""

    def _buckets(delta: AssessmentDelta) -> ItemBuckets:
        return delta.routes if kind == "route" else delta.findings

    end = _buckets(overall)
    open_ids = {r.item_id for r in (*end.new, *end.still_open, *end.not_reevaluated)}
    found: dict[str, ItemRef] = {}
    closed: dict[str, tuple[ItemRef, datetime]] = {}
    decided: dict[str, ItemRef] = {}
    for step in steps:
        buckets = _buckets(step)
        for ref in buckets.new:
            found.setdefault(ref.item_id, ref)
        step_at = _utc(step.current.completed_at)
        for ref in buckets.closed_verified:
            closed[ref.item_id] = (ref, step_at)
            decided.pop(ref.item_id, None)
        for ref in buckets.closed_by_decision:
            decided[ref.item_id] = ref
            closed.pop(ref.item_id, None)
    closed = {k: v for k, v in closed.items() if k not in open_ids}
    decided = {k: v for k, v in decided.items() if k not in open_ids}

    days: list[float] = []
    for item_id, (_ref, closed_at) in sorted(closed.items()):
        item = items_by_id.get(item_id)
        if item is None:
            continue
        opened = _opened_at(item, closed_at, timeline)
        if opened is not None:
            days.append(max(0.0, (closed_at - opened).total_seconds() / 86400.0))

    return KindActivity(
        found=_sort_refs(list(found.values())),
        closed_verified=_sort_refs([ref for ref, _at in closed.values()]),
        closed_by_decision=_sort_refs(list(decided.values())),
        not_reevaluated=end.not_reevaluated,
        open_at_end=end.open_count,
        remediation_days=tuple(days),
    )


# ── Public API ──────────────────────────────────────────────────────────────


def compute_assessment_delta(
    previous: Optional[Assessment],
    current: Assessment,
    items: Iterable[TrackedItem],
    *,
    latest_scan_id: Optional[str] = None,
    assessments: Optional[Sequence[Assessment]] = None,
) -> AssessmentDelta:
    """Compare two assessments of one workspace.

    Args:
        previous: The earlier assessment, or ``None`` for a baseline.
        current: The later assessment.
        items: Every route and finding of the workspace with its history.
        latest_scan_id: The workspace's latest ingested assessment, the one the
            rows' reconcile stamp describes.
        assessments: Every known assessment, so events written by one are placed
            at it. Defaults to ``previous`` and ``current``.

    Returns:
        The :class:`AssessmentDelta`. Routes are Tier 0 routes only; findings
        are every finding.
    """
    known = list(assessments or [])
    for a in (previous, current):
        if a is not None and a.scan_id not in {k.scan_id for k in known}:
            known.append(a)
    timeline = _timeline_for(known)
    cur_at = _utc(current.completed_at)
    prev_at = _utc(previous.completed_at) if previous is not None else None

    buckets: dict[str, dict[str, list[ItemRef]]] = {
        kind: {name: [] for name in BUCKET_LABELS} for kind in ("route", "finding")
    }
    newly_validated: list[ItemRef] = []
    new_validated_routes: list[ItemRef] = []
    newly_succeeding_routes: list[ItemRef] = []
    #: Domains with a full-compromise route that regressed (new, or tried and
    #: failed before), and domains already compromised at the previous one.
    compromised_by_regression: set[str] = set()
    compromised_before: set[str] = set()

    for item in items:
        if item.kind == "route" and not item.reaches_tier0:
            continue
        if item.kind not in buckets:
            continue
        present_now = _present_at(item, cur_at, timeline)
        present_before = (
            _present_at(item, prev_at, timeline) if prev_at is not None else False
        )
        exec_now = _execution_at(item, cur_at, timeline)
        exec_before = (
            _execution_at(item, prev_at, timeline) if prev_at is not None else None
        )
        ref = _ref(item, exec_now)
        target = buckets[item.kind]
        is_route = item.kind == "route"
        validated_before = _token(exec_before) in VALIDATED_EXECUTION_STATUSES

        # Like for like: a route is a regression only when the previous
        # assessment had no such route, or tried it and did not get through.
        regressed = False
        if is_route and ref.validated and previous is not None and present_now:
            if not present_before:
                new_validated_routes.append(ref)
                regressed = True
            elif _token(exec_before) in FAILED_ATTEMPT_STATUSES:
                newly_succeeding_routes.append(ref)
                regressed = True

        if is_route and item.reaches_full_compromise:
            if regressed:
                compromised_by_regression.add(item.domain)
            if present_before and validated_before:
                compromised_before.add(item.domain)

        if present_now and not present_before:
            target["new"].append(ref)
        elif present_now and present_before:
            if _not_rechecked(item, current, latest_scan_id):
                target["not_reevaluated"].append(ref)
            else:
                target["still_open"].append(ref)
            if is_route and ref.validated and not validated_before and not regressed:
                newly_validated.append(ref)
        elif present_before and not present_now:
            closing = timeline.latest_in(item.status_events, prev_at, cur_at)
            verified = (
                closing is not None
                and _token(closing.status) == REMEDIATED_STATUS
                and closing.by_assessment
                and closing.scan_id is not None
            )
            target["closed_verified" if verified else "closed_by_decision"].append(ref)

    def _buckets(kind: str) -> ItemBuckets:
        return ItemBuckets(**{name: _sort_refs(refs) for name, refs in buckets[kind].items()})

    newly_compromised = tuple(
        sorted(compromised_by_regression - compromised_before, key=str.lower)
    )
    return AssessmentDelta(
        previous=previous,
        current=current,
        routes=_buckets("route"),
        findings=_buckets("finding"),
        newly_validated=_sort_refs(newly_validated),
        regressions=Regressions(
            new_validated_routes=_sort_refs(new_validated_routes),
            domains_newly_compromised=newly_compromised,
            newly_succeeding_routes=_sort_refs(newly_succeeding_routes),
        ),
    )


def summarize_period(
    window_start: datetime,
    window_end: datetime,
    assessments: Sequence[Assessment],
    items: Sequence[TrackedItem],
    *,
    latest_scan_id: Optional[str] = None,
    next_scheduled_at: Optional[datetime] = None,
    as_of: Optional[datetime] = None,
) -> PeriodSummary:
    """Aggregate a workspace's progress over ``[window_start, window_end)``.

    Works for any window: a digest period, a board quarter, "since onboarding".

    Args:
        window_start: Inclusive start.
        window_end: Exclusive end.
        assessments: Every completed, ingested assessment of the workspace (any
            order; those outside the window give the start state and the age of
            the last verification).
        items: Every route and finding with its history.
        latest_scan_id: See :func:`compute_assessment_delta`.
        next_scheduled_at: The next scheduled assessment, if any.
        as_of: Reference instant for the verification age (default the end of
            the window).
    """
    start = _utc(window_start)
    end = _utc(window_end)
    ordered = sorted(assessments, key=lambda a: _utc(a.completed_at))
    in_period = tuple(a for a in ordered if start <= _utc(a.completed_at) < end)
    before = [a for a in ordered if _utc(a.completed_at) < start]
    baseline = before[-1] if before else None
    verified_by_end = [a for a in ordered if _utc(a.completed_at) < end]
    last_verified_at = (
        _utc(verified_by_end[-1].completed_at) if verified_by_end else None
    )
    reference = _utc(as_of) if as_of is not None else end
    days_since = (
        max(0, (reference - last_verified_at).days) if last_verified_at is not None else None
    )

    if not in_period:
        return PeriodSummary(
            window_start=start,
            window_end=end,
            assessments_in_period=(),
            baseline=baseline,
            end=None,
            overall=None,
            steps=(),
            regressions=Regressions(),
            trend=(),
            last_verified_at=last_verified_at,
            days_since_last_verification=days_since,
            next_scheduled_at=next_scheduled_at,
        )

    final = in_period[-1]
    baseline_in_period = baseline is None and len(in_period) >= 2
    start_state = in_period[0] if baseline_in_period else baseline
    overall = compute_assessment_delta(
        start_state, final, items, latest_scan_id=latest_scan_id, assessments=ordered
    )
    steps: list[AssessmentDelta] = []
    previous = baseline
    for assessment in in_period:
        steps.append(
            compute_assessment_delta(
                previous,
                assessment,
                items,
                latest_scan_id=latest_scan_id,
                assessments=ordered,
            )
        )
        previous = assessment

    seen_routes: dict[str, ItemRef] = {}
    seen_succeeding: dict[str, ItemRef] = {}
    seen_domains: list[str] = []
    for step in steps:
        for ref in step.regressions.new_validated_routes:
            seen_routes.setdefault(ref.item_id, ref)
        for ref in step.regressions.newly_succeeding_routes:
            seen_succeeding.setdefault(ref.item_id, ref)
        for domain in step.regressions.domains_newly_compromised:
            if domain not in seen_domains:
                seen_domains.append(domain)

    trend_source = ([baseline] if baseline is not None else []) + list(in_period)
    # ``baseline`` here is still the pre-window assessment: the trend starts there.
    timeline = _timeline_for(ordered)
    items_by_id = {item.item_id: item for item in items}
    activity = PeriodActivity(
        routes=_kind_activity("route", steps, overall, items_by_id, timeline),
        findings=_kind_activity("finding", steps, overall, items_by_id, timeline),
    )
    return PeriodSummary(
        window_start=start,
        window_end=end,
        assessments_in_period=in_period,
        baseline=start_state,
        end=final,
        overall=overall,
        steps=tuple(steps),
        regressions=Regressions(
            new_validated_routes=_sort_refs(list(seen_routes.values())),
            domains_newly_compromised=tuple(seen_domains),
            newly_succeeding_routes=_sort_refs(list(seen_succeeding.values())),
        ),
        trend=tuple(
            TrendPoint(
                a.scan_id,
                _utc(a.completed_at),
                a.figures,
                exposure=a.exposure,
                compliance=a.compliance,
            )
            for a in trend_source
        ),
        last_verified_at=last_verified_at,
        days_since_last_verification=days_since,
        next_scheduled_at=next_scheduled_at,
        baseline_in_period=baseline_in_period,
        activity=activity,
    )


def previous_period_window(cadence: str, now: datetime) -> tuple[datetime, datetime]:
    """Return the last COMPLETED ``[start, end)`` period for a digest cadence.

    Weekly periods run Monday 00:00 to Monday 00:00 UTC; monthly and quarterly
    periods follow the calendar.

    Raises:
        ValueError: for ``off`` or an unknown cadence.
    """
    now = _utc(now)
    token = _token(cadence)
    if token == "weekly":
        this_monday = (now - timedelta(days=now.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        return this_monday - timedelta(days=7), this_monday
    if token == "monthly":
        end = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start = _add_months(end, -1)
        return start, end
    if token == "quarterly":
        quarter_first_month = 3 * ((now.month - 1) // 3) + 1
        end = now.replace(
            month=quarter_first_month, day=1, hour=0, minute=0, second=0, microsecond=0
        )
        return _add_months(end, -3), end
    raise ValueError(f"No period for cadence {cadence!r}")


def _add_months(value: datetime, months: int) -> datetime:
    index = value.year * 12 + (value.month - 1) + months
    year, month = divmod(index, 12)
    day = min(value.day, calendar.monthrange(year, month + 1)[1])
    return value.replace(year=year, month=month + 1, day=day)
