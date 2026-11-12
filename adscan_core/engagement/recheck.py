"""Re-verification (``recheck``): targets, depths, plan and decisions.

One run kind, one RunPlan, one selector grammar (spec section 10). This module is
the pure half: it validates what to re-verify and how hard to look, builds the
``adscan.run_plan/1`` document, and turns what the engine read or executed into
the same inputs the shared :func:`adscan_core.engagement.reconcile.reconcile`
consumes, so a recheck and a scan cannot follow different lifecycle rules.

Decisions this module encodes:

* **Only targeted items are decided.** The prior state handed to ``reconcile``
  is the target set, never the whole ledger, so re-checking one step leaves
  every other item exactly as it was.
* **A recheck closes an item only through the read of its own detector**
  (``detectors.py``), never through a scan phase it did not run. The spec lookup
  is derived per item: the detector's check id at the item's base scope and
  vantage. An item whose detector has no read-only check in this release has no
  spec, so it can never close; it is reported "not re-checked" with the reason
  the recheck declares for that detector (``TargetItem.not_recheckable_reason``).
* **Presence propagates, absence does not.** A step found present proves the
  finding it backs (the catalog ``vuln_key`` join) is present too; a step found
  closed says nothing about the finding's other affected objects, so the finding
  stays open or unverified.
* **A finding is one ledger row per domain.** An object-narrowed read is
  ``partial``: it can confirm presence but cannot close the domain-level row.
* **A walk decides presence, never closure.** A completed step is re-executed and
  present; a step after the break is ``not_walked``. A stopped step closes only
  when its own observe read confirms the condition is gone
  (``precondition_removed``).

Stdlib only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping, Optional, Sequence

from adscan_core.engagement.model import (
    ACTIVE_STATUSES,
    RUN_COMPLETE,
    CheckCoverage,
    CheckStatus,
    ItemResult,
    Observed,
    PriorItem,
    RunCoverage,
    Transition,
    Vantage,
)
from adscan_core.engagement.reconcile import reconcile
from adscan_core.engagement.specs import ObservationSpec, edge_spec_lookup, spec_for

RUN_PLAN_SCHEMA = "adscan.run_plan/1"
RESULT_SCHEMA = "adscan.recheck_result/1"
KIND_RECHECK = "recheck"

LEVEL_ALL = "all"
LEVEL_FINDING = "finding"
LEVEL_STEP = "step"
LEVEL_PATH = "path"
LEVELS = (LEVEL_ALL, LEVEL_FINDING, LEVEL_STEP, LEVEL_PATH)

DEPTH_OBSERVE = "observe"
DEPTH_EXERCISE = "exercise"
DEPTH_WALK = "walk"
DEPTHS = (DEPTH_OBSERVE, DEPTH_EXERCISE, DEPTH_WALK)

#: Depths each target level supports in this release (the schema mirrors it).
DEPTHS_BY_LEVEL: Mapping[str, tuple[str, ...]] = {
    LEVEL_ALL: (DEPTH_OBSERVE,),
    LEVEL_FINDING: (DEPTH_OBSERVE,),
    LEVEL_STEP: (DEPTH_OBSERVE, DEPTH_EXERCISE),
    LEVEL_PATH: (DEPTH_OBSERVE, DEPTH_WALK),
}

#: ``--filter`` keys and the values each accepts (``None`` = free token).
FILTER_STATUSES = ("open", "remediated", "not_reevaluated", "all")
FILTER_KEYS: Mapping[str, Optional[tuple[str, ...]]] = {
    "domain": None,
    "status": FILTER_STATUSES,
}

# Verdict codes (what the operator and the result document are told).
VERDICT_RE_OBSERVED = "re_observed"
VERDICT_CLOSED_OBSERVED = "closed_observed"
VERDICT_RE_EXECUTED = "re_executed"
VERDICT_STOPPED = "stopped"
VERDICT_NOT_RECHECKED = "not_rechecked"

#: Client-facing phrase per verdict (spec section 10.5 vocabulary).
VERDICT_LABELS: Mapping[str, str] = {
    VERDICT_RE_OBSERVED: "condition re-observed",
    VERDICT_CLOSED_OBSERVED: "condition closed (observed)",
    VERDICT_RE_EXECUTED: "re-executed and validated",
    VERDICT_STOPPED: "stopped",
    VERDICT_NOT_RECHECKED: "not re-checked",
}

# Not-re-checked and stop reasons (persisted as the item's evaluation reason).
REASON_NO_READ_ONLY_CHECK = "no_read_only_check"
REASON_NOT_READ = "not_read"
REASON_READ_FAILED = "read_failed"
REASON_PARTIAL_READ = "object_read_only"
REASON_VANTAGE = "weaker_vantage"
REASON_NOT_WALKED = "not_walked"
REASON_PRECONDITION_REMOVED = "precondition_removed"

#: Operator copy per reason.
REASON_LABELS: Mapping[str, str] = {
    REASON_NO_READ_ONLY_CHECK: "no read-only check",
    REASON_NOT_READ: "its check did not run",
    REASON_READ_FAILED: "the read failed",
    REASON_PARTIAL_READ: "only some affected objects were read",
    REASON_VANTAGE: "this credential sees less than the one that found it",
    REASON_NOT_WALKED: "not walked: the route stopped earlier",
    REASON_PRECONDITION_REMOVED: "precondition removed",
    "credential_invalid": "credential no longer valid",
    "credential_removed": (
        "the credential this step starts from was removed from the workspace after "
        "the earlier assessment, and this run did not recover it again"
    ),
    "not_run": "not run in this walk",
    "unknown": "reason not established",
    "not_walkable": "not walkable",
}

# Walk step outcomes (spec section 10.4).
WALK_COMPLETED = "completed"
WALK_STOPPED = "stopped"
WALK_NOT_WALKED = "not_walked"

_HEX_ID = re.compile(r"^[0-9a-f]{8,64}$")
#: The ``P-XXXXXXXX`` label the legacy Word report printed for a path. Accepted
#: by ``--path`` for compatibility and resolved to the path id (the route
#: fingerprint), which is what the run plan and the result document record.
_LEGACY_PATH_LABEL = re.compile(r"^p-[0-9a-f]{8}$")
#: A full ledger item id (``identity.step_id`` and friends: a 64-hex digest).
_STEP_ITEM_ID = re.compile(r"^[0-9a-f]{64}$")
_FINDING_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_OBJECT_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$")
_DOMAIN_TOKEN = re.compile(r"^[a-z0-9_][a-z0-9_.-]{0,252}$")


def is_legacy_path_label(token: str) -> bool:
    """Whether ``token`` is a legacy ``P-XXXXXXXX`` path label (case-insensitive)."""
    return bool(_LEGACY_PATH_LABEL.match(str(token or "").strip().lower()))


class RecheckError(ValueError):
    """An invalid recheck request; the message is operator copy."""


@dataclass(frozen=True)
class RecheckTarget:
    """What to re-verify (spec section 10.1)."""

    level: str
    finding: str = ""
    objects: tuple[str, ...] = ()
    step: str = ""
    path: str = ""
    filters: tuple[tuple[str, str], ...] = ()

    def filter_value(self, key: str) -> str:
        return dict(self.filters).get(key, "")


def validate_target(target: RecheckTarget, depth: str) -> None:
    """Reject an incoherent target / depth combination with operator copy."""
    if target.level not in LEVELS:
        raise RecheckError(f"Unknown recheck level {target.level!r}.")
    if depth not in DEPTHS:
        raise RecheckError(f"Unknown depth {depth!r}; use observe, exercise or walk.")
    if depth not in DEPTHS_BY_LEVEL[target.level]:
        allowed = ", ".join(DEPTHS_BY_LEVEL[target.level])
        what = {LEVEL_ALL: "--all", LEVEL_FINDING: "a finding", LEVEL_STEP: "a step",
                LEVEL_PATH: "a path"}[target.level]
        raise RecheckError(f"Depth '{depth}' is not available for {what}; use {allowed}.")
    if target.level == LEVEL_FINDING:
        token = target.finding.strip().lower()
        if not (_FINDING_TOKEN.match(token) or _HEX_ID.match(token)):
            raise RecheckError("--finding needs a finding key (for example kerberoast) or a finding id.")
    if target.level == LEVEL_STEP and not _HEX_ID.match(target.step.strip().lower()):
        raise RecheckError("--step needs a step id (at least 8 hex characters).")
    if target.level == LEVEL_PATH and not (
        _HEX_ID.match(target.path.strip().lower()) or is_legacy_path_label(target.path)
    ):
        raise RecheckError(
            "--path needs a path id: the id the report prints next to each path "
            "(at least 8 hex characters), or a P-XXXXXXXX label from an older report."
        )
    if target.objects and target.level != LEVEL_FINDING:
        raise RecheckError("--object narrows a finding; use it with --finding.")
    for value in target.objects:
        if not _OBJECT_TOKEN.match(value):
            raise RecheckError(f"--object {value!r} is not an object id (a SID, wk:<SID> or guid:<GUID>).")
    for key, value in target.filters:
        allowed = FILTER_KEYS.get(key, ())
        if key not in FILTER_KEYS or (allowed is not None and value not in allowed):
            raise RecheckError(f"Invalid filter {key}={value}.")


def parse_filter(expr: str) -> tuple[tuple[str, str], ...]:
    """Parse ``key=value[,key=value]`` (keys ``domain``, ``status``)."""
    out: dict[str, str] = {}
    for part in (expr or "").split(","):
        part = part.strip()
        if not part:
            continue
        key, sep, value = part.partition("=")
        key, value = key.strip().lower(), value.strip().rstrip(".").lower()
        if not sep or not value:
            raise RecheckError(f"Filter '{part}' must read key=value.")
        if key not in FILTER_KEYS:
            keys = ", ".join(FILTER_KEYS)
            raise RecheckError(f"Unknown filter key '{key}'; use {keys}.")
        allowed = FILTER_KEYS[key]
        if allowed is not None and value not in allowed:
            raise RecheckError(f"Filter {key} accepts {', '.join(allowed)}.")
        if key == "domain" and not _DOMAIN_TOKEN.match(value):
            raise RecheckError(f"Filter domain '{value}' is not a domain name.")
        out[key] = value
    return tuple(sorted(out.items()))


def plan_document(
    target: RecheckTarget, depth: str, *, workspace: str, run_id: str = ""
) -> dict[str, object]:
    """The ``adscan.run_plan/1`` document of one recheck (validated by the schema)."""
    body: dict[str, object] = {"level": target.level}
    if target.level == LEVEL_FINDING:
        body["finding"] = target.finding.strip().lower()
        if target.objects:
            body["objects"] = list(target.objects)
    elif target.level == LEVEL_STEP:
        body["step"] = target.step.strip().lower()
    elif target.level == LEVEL_PATH:
        body["path"] = target.path.strip().lower()
    if target.filters and target.level in {LEVEL_ALL, LEVEL_FINDING}:
        body["filter"] = dict(target.filters)
    doc: dict[str, object] = {
        "schema": RUN_PLAN_SCHEMA,
        "kind": KIND_RECHECK,
        "workspace": {"name": workspace},
        "recheck": {"target": body, "depth": depth},
    }
    if run_id:
        doc["run_id"] = run_id
    return doc


# ---------------------------------------------------------------------------
# Decisions.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetItem:
    """One ledger item selected for re-verification.

    Attributes:
        status: Ledger status (``""`` for a finding key the ledger never held).
        check_id: The detector check whose read observes it; ``None`` when the
            detector has no read-only check in this release.
        finding_keys: For a step, the finding keys it backs (``vuln_key``).
        not_recheckable_reason: The declared reason this item cannot be
            re-checked read-only (its detector has no observer, or its
            observer never decides this key), as operator copy; ``""`` when
            nothing is declared.
    """

    item_id: str
    kind: str
    key: str
    domain_id: str
    object_id: Optional[str]
    label: str
    status: str
    last_vantage: Vantage
    check_id: Optional[str]
    finding_keys: tuple[str, ...] = ()
    disposition: str = ""
    not_recheckable_reason: str = ""


@dataclass(frozen=True)
class ReadOutcome:
    """What one read-only check returned for one domain.

    ``examined_ids`` is ``None`` for a domain-wide read, else the objects read.
    ``present`` maps a finding key or a step relation (lowercase) to the object
    ids where the condition holds (a domain-scoped finding uses its domain id),
    or to the ledger item ids of the steps still present when several steps
    share one object.
    """

    check_id: str
    domain_id: str
    status: CheckStatus
    examined_ids: Optional[frozenset[str]]
    present: Mapping[str, frozenset[str]] = field(default_factory=dict)
    reason: str = ""


@dataclass(frozen=True)
class WalkStep:
    """The outcome of one step in a walk or an exercise (spec section 10.4)."""

    item_id: str
    outcome: str
    reason: str = ""


def _sentence_tail(sentence: str) -> str:
    """``sentence`` continued after a colon: its first letter lowered, unless an acronym."""
    if len(sentence) > 1 and (sentence[1].islower() or sentence[1] == " "):
        return sentence[0].lower() + sentence[1:]
    return sentence


@dataclass(frozen=True)
class Verdict:
    """What the operator is told about one item.

    ``reason`` is the stable code; ``detail`` is the declared reason the item
    cannot be re-checked read-only, set only when that is why it was not
    (the read ran, or there is no read), and preferred over the code's generic
    label in :attr:`text`.
    """

    code: str
    reason: str = ""
    detail: str = ""

    @property
    def text(self) -> str:
        label = VERDICT_LABELS.get(self.code, self.code)
        if self.detail:
            return f"{label}: {_sentence_tail(self.detail)}"
        if not self.reason:
            return label
        return f"{label}: {REASON_LABELS.get(self.reason, self.reason.replace('_', ' '))}"


@dataclass(frozen=True)
class RecheckDecisions:
    """Everything one recheck run decided."""

    observed: list[Observed]
    coverage: RunCoverage
    results: list[ItemResult]
    verdicts: dict[str, Verdict]


def _base_spec(item: TargetItem) -> Optional[ObservationSpec]:
    if item.kind == "finding":
        return spec_for("finding", item.key)
    return edge_spec_lookup(item.kind, item.key)


def _is_present(item: TargetItem, outcome: Optional[ReadOutcome]) -> bool:
    if outcome is None or outcome.status not in {CheckStatus.RAN, CheckStatus.PARTIAL}:
        return False
    keys = (item.key.lower(), *item.finding_keys) if item.kind != "finding" else (item.key,)
    for key in keys:
        holders = outcome.present.get(key) or frozenset()
        # An observer that can tell steps sharing one object apart (several
        # principals holding a right over the same target) names the step
        # itself by its item id.
        if item.item_id in holders:
            return True
        if item.object_id is None:
            # A step relation can share its spelling with a finding key
            # (``DCSync`` / ``dcsync``): a present step's item id is never
            # evidence that the domain-scoped finding is present.
            if any(not _STEP_ITEM_ID.match(str(h)) for h in holders):
                return True
        elif item.object_id in holders:
            return True
    return False


def _finding_keys_of(check_id: Optional[str]) -> frozenset[str]:
    """The finding keys the detector family ``check_id`` observes."""
    if not check_id:
        return frozenset()
    from adscan_core.engagement.detectors import DETECTORS  # noqa: PLC0415

    for detector in DETECTORS:
        if detector.check_id == check_id:
            return frozenset(detector.finding_keys)
    return frozenset()


def _reason_for(result: ItemResult, outcome: Optional[ReadOutcome]) -> str:
    if result.reason in {"no_spec", "never_auto"}:
        return REASON_NO_READ_ONLY_CHECK
    if result.reason == "check_failed":
        return f"{REASON_READ_FAILED}:{outcome.reason}" if outcome and outcome.reason else REASON_READ_FAILED
    if result.reason == "check_partial":
        return REASON_PARTIAL_READ
    if result.reason == "vantage":
        return REASON_VANTAGE
    if outcome is not None and outcome.status is CheckStatus.SKIPPED and outcome.reason:
        return f"{REASON_NOT_READ}:{outcome.reason}"
    return REASON_NOT_READ


def _declared_detail(item: TargetItem, outcome: Optional[ReadOutcome]) -> str:
    """The item's declared reason, when the read ran and still did not decide it.

    A read that failed, was skipped or never ran keeps its own, run-specific
    reason: the declared one would hide what went wrong in this run.
    """
    if not item.not_recheckable_reason or outcome is None:
        return ""
    if outcome.status not in {CheckStatus.RAN, CheckStatus.PARTIAL}:
        return ""
    return item.not_recheckable_reason


def build_recheck_decisions(
    targets: Sequence[TargetItem],
    outcomes: Sequence[ReadOutcome],
    *,
    vantage: Vantage,
    walk: Sequence[WalkStep] = (),
    run_id: str = "",
) -> RecheckDecisions:
    """Turn reads and walk outcomes into ``reconcile`` decisions for the targets.

    Args:
        targets: The items selected for re-verification (the only items decided).
        outcomes: One :class:`ReadOutcome` per (detector check, domain) read.
        vantage: The vantage of the credential the reads used.
        walk: Per-step outcomes of a walk or an exercise.
        run_id: The recheck run id (stamped on the coverage).

    Returns:
        The observed items, the run coverage, ``reconcile``'s decisions (with a
        recheck-specific reason on every ``NOT_REEVALUATED``) and a verdict per
        target.
    """
    by_check = {(o.check_id, o.domain_id): o for o in outcomes}
    walked = {w.item_id: w for w in walk}
    checks = {
        (o.check_id, o.domain_id): CheckCoverage(
            check_id=o.check_id,
            status=o.status,
            domain_id=o.domain_id,
            scope_kind="domain" if o.examined_ids is None else "object",
            examined=None if o.examined_ids is None else len(o.examined_ids),
            examined_ids=o.examined_ids,
            reason=o.reason,
        )
        for o in outcomes
    }
    coverage = RunCoverage(run_status=RUN_COMPLETE, vantage=vantage, checks=checks, run_id=run_id)

    def outcome_of(item: TargetItem) -> Optional[ReadOutcome]:
        return by_check.get((item.check_id, item.domain_id)) if item.check_id else None

    present_ids: set[str] = set()
    present_findings: set[tuple[str, str]] = set()
    for item in targets:
        step = walked.get(item.item_id)
        executed = step is not None and step.outcome == WALK_COMPLETED
        if executed or _is_present(item, outcome_of(item)):
            present_ids.add(item.item_id)
            for key in item.finding_keys:
                # A read that observes the finding itself already decided it
                # through the scan's finding gate (a domain controller's
                # inherent DCSync is a step, never a finding): a step it reads
                # present does not override that. An executed step does.
                if executed or key not in _finding_keys_of(item.check_id):
                    present_findings.add((key, item.domain_id))
    for item in targets:
        if item.kind == "finding" and (item.key, item.domain_id) in present_findings:
            present_ids.add(item.item_id)

    observed = [
        Observed(i.item_id, i.kind, i.key, i.domain_id, i.object_id)
        for i in targets
        if i.item_id in present_ids
    ]
    prior = [
        PriorItem(i.item_id, i.kind, i.key, i.domain_id, i.object_id, i.disposition or i.status, i.last_vantage)
        for i in targets
        if i.status
    ]
    specs: dict[tuple[str, str], Optional[ObservationSpec]] = {}
    for item in targets:
        base = _base_spec(item)
        if item.check_id is None or base is None or base.reeval == "never_auto":
            specs[(item.kind, item.key)] = None
        else:
            specs[(item.kind, item.key)] = ObservationSpec(
                (item.check_id,), base.scope, base.requires_vantage
            )

    raw = reconcile(
        prior,
        observed,
        coverage,
        spec_lookup=lambda kind, key: specs.get((kind, key)),
        terminal_ids=frozenset(i.item_id for i in targets if i.disposition),
    )

    targets_by_id = {i.item_id: i for i in targets}
    results: list[ItemResult] = []
    verdicts: dict[str, Verdict] = {}
    for result in raw:
        item = targets_by_id[result.item_id]
        step = walked.get(item.item_id)
        outcome = outcome_of(item)
        verdict: Verdict
        if step is not None and step.outcome == WALK_COMPLETED:
            verdict = Verdict(VERDICT_RE_EXECUTED)
        elif result.transition is Transition.REMEDIATED:
            verdict = (
                Verdict(VERDICT_STOPPED, REASON_PRECONDITION_REMOVED)
                if step is not None
                else Verdict(VERDICT_CLOSED_OBSERVED)
            )
        elif item.item_id in present_ids:
            verdict = Verdict(VERDICT_RE_OBSERVED)
        elif step is not None and step.outcome == WALK_STOPPED:
            verdict = Verdict(VERDICT_STOPPED, step.reason or "unknown")
        elif step is not None and step.outcome == WALK_NOT_WALKED:
            verdict = Verdict(VERDICT_NOT_RECHECKED, step.reason or REASON_NOT_WALKED)
        elif item.check_id is None:
            verdict = Verdict(VERDICT_NOT_RECHECKED, REASON_NO_READ_ONLY_CHECK, item.not_recheckable_reason)
        else:
            verdict = Verdict(
                VERDICT_NOT_RECHECKED, _reason_for(result, outcome), _declared_detail(item, outcome)
            )
        verdicts[item.item_id] = verdict
        if result.transition is Transition.NOT_REEVALUATED:
            if verdict.reason == REASON_NO_READ_ONLY_CHECK:
                # Nothing was attempted on this item: the ledger keeps the
                # state its last evaluating run gave it (``--all`` must not
                # flag every such item as "not re-checked").
                continue
            reason = verdict.reason or REASON_NOT_READ
            if verdict.code == VERDICT_STOPPED:
                reason = f"stopped_{reason}"
            result = ItemResult(result.item_id, result.transition, reason)
        results.append(result)
    # Items with nothing to decide (already remediated, or a finding key the
    # ledger never held) still get a verdict: what the read says now.
    for item in targets:
        if item.item_id in verdicts:
            continue
        outcome = outcome_of(item)
        covered = outcome is not None and (
            outcome.status is CheckStatus.RAN
            or (
                outcome.status is CheckStatus.PARTIAL
                and item.object_id is not None
                and item.object_id in (outcome.examined_ids or frozenset())
            )
        )
        if item.check_id is None:
            verdicts[item.item_id] = Verdict(
                VERDICT_NOT_RECHECKED, REASON_NO_READ_ONLY_CHECK, item.not_recheckable_reason
            )
        elif covered:
            verdicts[item.item_id] = Verdict(VERDICT_CLOSED_OBSERVED)
        else:
            verdicts[item.item_id] = Verdict(
                VERDICT_NOT_RECHECKED, REASON_NOT_READ, _declared_detail(item, outcome)
            )
    return RecheckDecisions(observed=observed, coverage=coverage, results=results, verdicts=verdicts)


def is_open(status: str, disposition: str = "") -> bool:
    """Whether a ledger item counts as open for ``--all`` / ``status=open``."""
    return not disposition and status in ACTIVE_STATUSES


__all__ = (
    "DEPTHS",
    "DEPTHS_BY_LEVEL",
    "DEPTH_EXERCISE",
    "DEPTH_OBSERVE",
    "DEPTH_WALK",
    "FILTER_KEYS",
    "KIND_RECHECK",
    "LEVELS",
    "LEVEL_ALL",
    "LEVEL_FINDING",
    "LEVEL_PATH",
    "LEVEL_STEP",
    "REASON_LABELS",
    "REASON_NO_READ_ONLY_CHECK",
    "RESULT_SCHEMA",
    "ReadOutcome",
    "RecheckDecisions",
    "RecheckError",
    "RecheckTarget",
    "TargetItem",
    "VERDICT_CLOSED_OBSERVED",
    "VERDICT_LABELS",
    "VERDICT_NOT_RECHECKED",
    "VERDICT_RE_EXECUTED",
    "VERDICT_RE_OBSERVED",
    "VERDICT_STOPPED",
    "Verdict",
    "WALK_COMPLETED",
    "WALK_NOT_WALKED",
    "WALK_STOPPED",
    "WalkStep",
    "build_recheck_decisions",
    "is_legacy_path_label",
    "is_open",
    "parse_filter",
    "plan_document",
    "validate_target",
)
