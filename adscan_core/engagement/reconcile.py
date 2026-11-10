"""The coverage-aware reconciliation rule (single source of truth).

Pure: no I/O, no clock, no imports beyond the stdlib and sibling modules, so the
CLI ledger and the web ingestion call the same function and cannot disagree.

Rule (spec section 5.2). An item *present* in the run is simply observed. An
item *absent* from the run is only fixed when every check that observes it ran
on the item's scope, from a vantage at least as strong as the one that last
observed it, in a run that completed. Anything else is ``NOT_REEVALUATED``:
unknown never closes anything.
"""

from __future__ import annotations

from typing import Callable, Optional, Sequence

from adscan_core.engagement import ALL_DOMAINS
from adscan_core.engagement.model import (
    ACTIVE_STATUSES,
    RUN_COMPLETE,
    RUN_UNKNOWN,
    STATUS_REMEDIATED,
    TERMINAL_STATUSES,
    CheckCoverage,
    CheckStatus,
    ItemResult,
    Observed,
    PriorItem,
    RunCoverage,
    Transition,
)
from adscan_core.engagement.specs import ObservationSpec, spec_for

SpecLookup = Callable[[str, str], Optional[ObservationSpec]]

# Stable reason codes (also persisted and rendered by consumers).
REASON_RUN_INCOMPLETE = "run_incomplete"
#: No usable coverage record for this run (absent, unreadable, or not written by
#: the run that wrote the artifacts being reconciled).
REASON_COVERAGE_UNKNOWN = "coverage_unknown"
#: The artifact that would show the item as present could not be read, so its
#: absence from this run means nothing.
REASON_ARTIFACT_UNREADABLE = "artifact_unreadable"
REASON_NO_SPEC = "no_spec"
REASON_NEVER_AUTO = "never_auto"
REASON_CHECK_SKIPPED = "check_skipped"
REASON_CHECK_PARTIAL = "check_partial"
REASON_CHECK_FAILED = "check_failed"
REASON_SCOPE_MISMATCH = "scope_mismatch"
REASON_VANTAGE = "vantage"


def _coverage_for(
    coverage: RunCoverage, check_id: str, domain_id: str
) -> tuple[Optional[CheckCoverage], bool]:
    """Return the check's coverage for a domain and whether other domains have it."""
    exact = coverage.checks.get((check_id, domain_id))
    if exact is not None:
        return exact, False
    wildcard = coverage.checks.get((check_id, ALL_DOMAINS))
    if wildcard is not None:
        return wildcard, False
    elsewhere = any(cid == check_id for cid, _ in coverage.checks)
    return None, elsewhere


def _check_failure(
    item: PriorItem, spec: ObservationSpec, coverage: RunCoverage
) -> Optional[str]:
    """Return the first reason the item's absence cannot be trusted, else None."""
    needed = max(spec.requires_vantage, item.last_vantage)
    if coverage.vantage < needed:
        return REASON_VANTAGE
    for check_id in spec.observed_by:
        check, elsewhere = _coverage_for(coverage, check_id, item.domain_id)
        if check is None:
            return REASON_SCOPE_MISMATCH if elsewhere else REASON_CHECK_SKIPPED
        if check.status is CheckStatus.RAN:
            continue
        if check.status is CheckStatus.PARTIAL:
            covered = (
                spec.scope in {"object", "host"}
                and item.object_id is not None
                and check.examined_ids is not None
                and item.object_id in check.examined_ids
            )
            if covered:
                continue
            return REASON_CHECK_PARTIAL
        if check.status is CheckStatus.FAILED:
            return REASON_CHECK_FAILED
        return REASON_CHECK_SKIPPED
    return None


def _absent(
    item: PriorItem,
    coverage: RunCoverage,
    spec_lookup: SpecLookup,
) -> ItemResult:
    if coverage.run_status == RUN_UNKNOWN:
        return ItemResult(item.item_id, Transition.NOT_REEVALUATED, REASON_COVERAGE_UNKNOWN)
    if coverage.run_status != RUN_COMPLETE:
        return ItemResult(item.item_id, Transition.NOT_REEVALUATED, REASON_RUN_INCOMPLETE)
    spec = spec_lookup(item.kind, item.key)
    if spec is None:
        return ItemResult(item.item_id, Transition.NOT_REEVALUATED, REASON_NO_SPEC)
    if spec.reeval == "never_auto":
        return ItemResult(item.item_id, Transition.NOT_REEVALUATED, REASON_NEVER_AUTO)
    if not spec.observed_by:
        return ItemResult(item.item_id, Transition.NOT_REEVALUATED, REASON_NO_SPEC)
    failure = _check_failure(item, spec, coverage)
    if failure is not None:
        return ItemResult(item.item_id, Transition.NOT_REEVALUATED, failure)
    return ItemResult(item.item_id, Transition.REMEDIATED)


def reconcile(
    prior: Sequence[PriorItem],
    observed: Sequence[Observed],
    coverage: RunCoverage,
    *,
    spec_lookup: SpecLookup = spec_for,
    terminal_ids: frozenset[str] = frozenset(),
    absence_reason: Optional[str] = None,
) -> list[ItemResult]:
    """Decide the lifecycle transition of every item for one run.

    Args:
        prior: Items as known before this run.
        observed: Items this run observed to be present.
        coverage: What the run's checks did and from which vantage.
        spec_lookup: ``(kind, key) -> ObservationSpec | None``; injectable for tests.
        terminal_ids: Item ids carrying a client disposition (accepted / false
            positive): never changed automatically, in either direction.
        absence_reason: Set when this run's absence cannot be interpreted at all
            (the artifact listing what is present was unreadable): every absent
            active item is then ``NOT_REEVALUATED`` with this reason, whatever
            the coverage says.

    Returns:
        One :class:`ItemResult` per item that needs a decision, ordered by
        ``item_id``. An absent item that was already remediated yields no result
        (nothing to decide). Deterministic: input order does not matter.
    """
    prior_by_id = {p.item_id: p for p in prior}
    seen_ids = {o.item_id for o in observed}
    results: dict[str, ItemResult] = {}

    for obs in observed:
        before = prior_by_id.get(obs.item_id)
        if before is None:
            results[obs.item_id] = ItemResult(obs.item_id, Transition.NEW)
        elif obs.item_id in terminal_ids or before.status in TERMINAL_STATUSES:
            results[obs.item_id] = ItemResult(obs.item_id, Transition.TERMINAL_UNCHANGED)
        elif before.status == STATUS_REMEDIATED:
            results[obs.item_id] = ItemResult(obs.item_id, Transition.REOPENED)
        else:
            results[obs.item_id] = ItemResult(obs.item_id, Transition.STILL_PRESENT)

    for item in prior:
        if item.item_id in seen_ids:
            continue
        if item.item_id in terminal_ids or item.status in TERMINAL_STATUSES:
            results[item.item_id] = ItemResult(item.item_id, Transition.TERMINAL_UNCHANGED)
        elif item.status in ACTIVE_STATUSES:
            if absence_reason:
                results[item.item_id] = ItemResult(
                    item.item_id, Transition.NOT_REEVALUATED, absence_reason
                )
            else:
                results[item.item_id] = _absent(item, coverage, spec_lookup)
        # Already remediated and still absent: nothing to decide.

    return [results[k] for k in sorted(results)]


REASON_STEP_UNVERIFIED = "step_unverified"
REASON_NO_STEP_EVIDENCE = "no_step_evidence"


def reconcile_path(
    path_id: str,
    prior_status: Optional[str],
    *,
    present: bool,
    step_transitions: Sequence[Transition],
) -> Optional[ItemResult]:
    """Decide the lifecycle transition of a derived attack path.

    Paths are not a lifecycle unit of their own (spec 5.3): they are derived from
    steps. A path that is absent from the run is REMEDIATED only when at least one
    of its steps was itself REMEDIATED under coverage. A path that vanished
    because a step could not be re-checked (or whose steps cannot be tied to any
    recorded step) stays active and is reported as not re-evaluated.

    Args:
        path_id: Stable path identity.
        prior_status: Status before this run (``None`` when never seen).
        present: Whether the recomputed path set contains the path.
        step_transitions: This run's transitions of the path's steps.

    Returns:
        The decision, or ``None`` when there is nothing to decide (already
        remediated and still absent).
    """
    if present:
        if prior_status is None:
            return ItemResult(path_id, Transition.NEW)
        if prior_status in TERMINAL_STATUSES:
            return ItemResult(path_id, Transition.TERMINAL_UNCHANGED)
        if prior_status == STATUS_REMEDIATED:
            return ItemResult(path_id, Transition.REOPENED)
        return ItemResult(path_id, Transition.STILL_PRESENT)
    if prior_status in TERMINAL_STATUSES:
        return ItemResult(path_id, Transition.TERMINAL_UNCHANGED)
    if prior_status not in ACTIVE_STATUSES:
        return None
    if not step_transitions:
        return ItemResult(path_id, Transition.NOT_REEVALUATED, REASON_NO_STEP_EVIDENCE)
    if Transition.REMEDIATED in step_transitions:
        return ItemResult(path_id, Transition.REMEDIATED)
    return ItemResult(path_id, Transition.NOT_REEVALUATED, REASON_STEP_UNVERIFIED)
