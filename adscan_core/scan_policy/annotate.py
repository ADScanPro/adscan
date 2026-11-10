"""Mark attack-path steps a scan policy kept from running (display metadata only).

It also labels a step the engine did not run because it was not needed (its
result was already held, ``attack_path_execution_events.NOT_NEEDED_REASONS``):
that step carries its own chip and is never counted as a policy exclusion.

A route whose step the scan policy excluded is still real exposure: the path
exists, ADscan mapped it, and the client's authorization kept ADscan from
proving it. So the route keeps its own status (``theoretical``, ``partial``),
and each excluded step carries a note that says why it was not executed. It is
never rendered as clean, and never as ``blocked`` (that word belongs to the
safety policy and the target-viability checks).

:func:`annotate_policy_exclusions` is the ONE place that decision is made, for
the PDF report (``report_attack_paths.compute_report_attack_paths``), the LITE
report (which reads the same canonical listing) and the web CTEM
(``attack_paths_service``). It changes display metadata only: never the path
set, never a status, never the ordering (CLAUDE.md attack-path SSOT rule).

Two sources, in order:

1. The engine's own refusal note. When the executor refused an excluded step it
   wrote ``not_executed_reason = "excluded_by_scan_policy"`` (and the check id)
   onto the attack-graph edge, and edge notes travel into ``step["details"]``.
2. The persisted coverage block's ``excluded_relations``. A route the executor
   never reached (it was only listed) carries no engine note, but its step is
   just as excluded.

Only a step that did NOT run is marked. A step proven or attempted in an earlier
scan did run, so a policy that excludes it today does not make it "not
executed"; a stale engine note on such a step is removed so no surface prints
it.

Stdlib only, dependency-light: the web backend imports this module directly.

Design: docs/superpowers/specs/2026-11-04-scan-policy-checks-by-family-design.md § 8.3.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from adscan_core.reporting.attack_path_execution_events import NOT_NEEDED_REASONS
from adscan_core.reporting.engagement_scope import (
    DEPENDS_ON_OUTSIDE_SCOPE_STEP_LABEL,
    NOT_EXECUTED_DEPENDS_ON_OUTSIDE_SCOPE,
    NOT_EXECUTED_OUTSIDE_SCOPE,
    NOTE_SCOPE_DOMAIN_KEY,
    OUTSIDE_SCOPE_REASONS,
    OUTSIDE_SCOPE_STEP_LABEL,
    continuation_sentence,
    crossing_sentence,
    split_route_at_scope,
    step_target_domain,
)
from adscan_core.scan_policy.execution import (
    MAP_ONLY_STEP_LABEL,
    REASON_AWAITING_APPROVAL,
    REASON_OPERATOR_DECLINED,
    awaiting_approval_label,
    dependent_step_label,
    operator_declined_label,
)

#: Step-note keys the engine writes at the operator decision seam
#: (``operator_decisions``): who declined, when, and how long a relayed
#: decision waited before it timed out.
NOTE_DECLINED_BY_KEY = "declined_by"
NOTE_DECLINED_AT_KEY = "declined_at"
NOTE_AWAITING_TIMEOUT_KEY = "awaiting_timeout_seconds"
#: Step-note key the engine writes with the decision: ``True`` on a later step
#: of the route the decision stopped (it was never put to the operator itself),
#: ``False`` on the step the operator was asked about. A note without it (a
#: workspace written before it existed) is read from the route: a step whose
#: route already carries the same decision on an earlier step is a dependent.
NOTE_DECISION_DEPENDENT_KEY = "operator_decision_dependent"
#: ``meta`` key listing a route's steps left unexecuted by an operator decision
#: (declined, or awaiting an answer that never came). Read by the verdict.
META_OPERATOR_DECISION_KEY = "operator_decision_steps"
_OPERATOR_DECISION_REASONS = frozenset({REASON_OPERATOR_DECLINED, REASON_AWAITING_APPROVAL})
#: Every reason the ENGINE notes on the step itself when it keeps it from
#: running: the two operator decisions and the engagement scope (the fourth
#: not-executed reason, ``adscan_core.reporting.engagement_scope``). Each keeps
#: its own label; none is a policy exclusion.
_STEP_NOTED_REASONS = _OPERATOR_DECISION_REASONS | OUTSIDE_SCOPE_REASONS
#: Graph glue that never runs (membership expansion): it never says a route
#: stopped before the scope boundary.
_STRUCTURAL_RELATIONS = frozenset({"memberof", "contains", "trustedby"})

#: Value of ``details.not_executed_reason`` for a policy exclusion. The engine
#: writes the same value (``scan_policy_enforcement.NOT_EXECUTED_REASON``); a
#: unit test locks the two together.
NOT_EXECUTED_REASON = "excluded_by_scan_policy"
NOTE_REASON_KEY = "not_executed_reason"
NOTE_CHECK_KEY = "scan_policy_check_id"
#: Client-facing label every surface prints beside an excluded step.
NOTE_LABEL_KEY = "not_executed_label"
NOT_EXECUTED_BY_POLICY_LABEL = "Not executed: your scan policy excludes it."


def held_back_write_label(excluded_check_title: str) -> str:
    """Label of a directory write held back because a LATER step is excluded.

    The write itself is allowed, but the route cannot reach its end under the
    policy, so making the change would alter the client's directory without
    proving anything. Every surface prints this sentence on that step.
    """
    title = str(excluded_check_title or "").strip() or "a later step"
    return (
        f"Not executed, {title} later in this route is excluded by the scan "
        "policy, so this change would lead nowhere"
    )

#: ``meta`` key carrying the sentence of a route's out-of-scope continuation
#: ("From here, <domain> is reachable. It was not tested because it is outside
#: the engagement scope."). The same sentence is appended to the route note
#: (:data:`META_UNLOCK_LINE_KEY`) every surface already prints beside a route.
META_SCOPE_CONTINUATION_KEY = "engagement_scope_continuation"
#: ``meta`` key listing the out-of-scope domains a route passes through. Read by
#: the verdict (``compromise_verdict.outside_scope_domains_of``) to name them.
META_SCOPE_OUT_DOMAINS_KEY = "engagement_scope_out_domains"
#: ``meta`` keys stamped on a route that carries at least one excluded step.
META_EXCLUDED_STEPS_KEY = "policy_excluded_steps"
META_NOT_EXECUTED_KEY = "scan_policy_not_executed"
#: The sentence every surface prints beside such a route: which checks, once
#: enabled, would let the route be proven (:func:`policy_unlock_line`).
META_UNLOCK_LINE_KEY = "scan_policy_unlock_line"
#: ``meta.execution_support_status`` the engine's readiness overlay writes on a
#: path whose first pending step is excluded.
EXECUTION_SUPPORT_EXCLUDED = NOT_EXECUTED_REASON

#: Step statuses that mean the step did not run. Anything else (``success``,
#: ``attempted``, ``blocked``, ``closed_by_configuration``, ``structural``,
#: ``unsupported`` ...) is left alone: it either ran, or another doctrine owns
#: its label.
#: ``discovered`` is what the canonical listing carries for a mapped, never-run
#: step (measured on a real GOAD workspace), so it must be in this set.
_NOT_RUN_STATUSES = frozenset(
    {"", "discovered", "theoretical", "pending", "unknown", "not_executed"}
)

_PUNCT = re.compile(r"[^a-z0-9]")


def _norm(relation: Any) -> str:
    return str(relation or "").strip().lower()


def _compact(relation: Any) -> str:
    return _PUNCT.sub("", _norm(relation))


def excluded_relation_index(
    excluded_relations: Iterable[str] | Mapping[str, str] | None,
) -> dict[str, str]:
    """``{normalized relation: check_id}`` for both spellings of each relation.

    Accepts a plain list (check id unknown, stored as ``""``) or a mapping of
    relation to check id, which is the shape the coverage block persists.
    """
    return {key: value[0] for key, value in _relation_index(excluded_relations).items()}


def _relation_index(
    excluded_relations: Iterable[str] | Mapping[str, Any] | None,
) -> dict[str, tuple[str, str]]:
    """``{normalized relation: (check_id, label)}``; a value may be a check id
    string or a ``{"check_id", "label"}`` mapping (:func:`excluded_relations_from_block`)."""
    index: dict[str, tuple[str, str]] = {}
    if not excluded_relations:
        return index
    items: Iterable[tuple[Any, Any]]
    if isinstance(excluded_relations, Mapping):
        items = excluded_relations.items()
    else:
        items = ((rel, "") for rel in excluded_relations)
    for relation, value in items:
        if isinstance(value, Mapping):
            check_id = str(value.get("check_id") or "")
            label = str(value.get("label") or "")
        else:
            check_id, label = str(value or ""), ""
        for key in (_norm(relation), _compact(relation)):
            if key:
                index.setdefault(key, (check_id, label))
    return index


def excluded_relations_from_block(block: Any) -> dict[str, dict[str, str]]:
    """``{relation: {"check_id", "label"}}`` from a persisted coverage block.

    The label is the block's per-relation wording (a map-only run says the step
    was left to an operator); empty means the default policy-exclusion label.
    Every surface (the engine disclosure, the report seam, the web CTEM) reads
    the block through this, so they print the same words.
    """
    if not isinstance(block, Mapping):
        return {}
    labels = block.get("excluded_relation_labels")
    # The block lists a per-relation label only for a step a map-only run left
    # to an operator (``coverage.build_scan_policy_coverage``). The wording is
    # resolved NOW, from the current SSOT, rather than replayed from the file:
    # a workspace written before the wording changed would otherwise keep its
    # old label, and every comparison against ``MAP_ONLY_STEP_LABEL`` (the
    # unlock line among them) would stop recognising it.
    labels = (
        {rel: MAP_ONLY_STEP_LABEL for rel, text in labels.items() if str(text or "").strip()}
        if isinstance(labels, Mapping)
        else {}
    )
    mapping = block.get("excluded_relation_checks")
    out: dict[str, dict[str, str]] = {}
    if isinstance(mapping, Mapping) and mapping:
        for relation, check_id in mapping.items():
            out[str(relation)] = {
                "check_id": str(check_id or ""),
                "label": str(labels.get(relation) or ""),
            }
        return out
    relations = block.get("excluded_relations")
    if isinstance(relations, list):
        for relation in relations:
            if str(relation or "").strip():
                out[str(relation)] = {"check_id": "", "label": str(labels.get(relation) or "")}
    return out


def _step_relation(step: Mapping[str, Any]) -> str:
    return str(step.get("action") or step.get("relation") or "")


def _step_status(step: Mapping[str, Any]) -> str:
    return _norm(step.get("status"))


def status_is_not_run(status: Any) -> bool:
    """True for a step status that means the step did not run.

    The executor settles a step the policy kept from running (reached through
    another relation's branch) back to such a status, so this function and
    :func:`annotate_policy_exclusions` agree by construction.
    """
    return _norm(status) in _NOT_RUN_STATUSES


def is_policy_exclusion_note(notes: Any) -> bool:
    """True when step / edge notes carry the scan-policy "not executed" reason."""
    return isinstance(notes, Mapping) and notes.get(NOTE_REASON_KEY) == NOT_EXECUTED_REASON


def _label_not_needed_step(step: dict[str, Any], details: dict[str, Any]) -> bool:
    """Label a step the engine did not run because its result was already held.

    Not a policy exclusion and never counted as one: the chip names the reason
    (``NOT_NEEDED_REASONS``), the step keeps its status. A stale note on a step
    that ran since is removed. Returns True when the step carried such a note.
    """
    reason = str(details.get(NOTE_REASON_KEY) or "").strip().lower()
    entry = NOT_NEEDED_REASONS.get(reason)
    if entry is None:
        return False
    if _step_status(step) not in _NOT_RUN_STATUSES:
        details.pop(NOTE_REASON_KEY, None)
        details.pop(NOTE_LABEL_KEY, None)
        return True
    details[NOTE_LABEL_KEY] = str(entry.get("label") or "")
    step["details"] = details
    return True


_OPERATOR_NOTE_KEYS: tuple[str, ...] = (
    NOTE_REASON_KEY,
    NOTE_LABEL_KEY,
    NOTE_DECLINED_BY_KEY,
    NOTE_DECLINED_AT_KEY,
    NOTE_AWAITING_TIMEOUT_KEY,
    NOTE_DECISION_DEPENDENT_KEY,
)


def _decision_identity(details: Mapping[str, Any]) -> tuple[str, str, str]:
    """What makes two operator-decision notes the SAME decision."""
    return (
        str(details.get(NOTE_REASON_KEY) or "").strip().lower(),
        str(details.get(NOTE_DECLINED_AT_KEY) or ""),
        str(details.get(NOTE_AWAITING_TIMEOUT_KEY) or ""),
    )


def _is_dependent_decision_note(
    details: Mapping[str, Any], gate: tuple[str, str, str] | None
) -> bool:
    """True when an operator-decision note marks a step that waited on another.

    The engine writes :data:`NOTE_DECISION_DEPENDENT_KEY`. A note without it is
    read from the route: it is a dependent when an earlier step of THIS route
    carries the same decision.
    """
    marker = details.get(NOTE_DECISION_DEPENDENT_KEY)
    if isinstance(marker, bool):
        return marker
    return gate is not None and _decision_identity(details) == gate


def _label_operator_decision(
    step: dict[str, Any],
    details: dict[str, Any],
    gate: tuple[str, str, str] | None = None,
) -> str:
    """Label a step the engine noted as not run; return its reason.

    Reason 3 (``operator_declined``) names who declined and when; reason 2
    (``operator_required``, written when a relayed decision got no answer) names
    the wait; reason 4 (``outside_engagement_scope``) says the step leaves the
    engagement scope. A later step of a route an operator decision stopped reads
    "depends on a step awaiting approval" (or declined): it was never put to the
    operator itself. ``gate`` is the decision an earlier step of this route
    carries. A step that ran since loses the note. ``""`` when the step carries
    none of them.
    """
    reason = str(details.get(NOTE_REASON_KEY) or "").strip().lower()
    if reason not in _STEP_NOTED_REASONS:
        return ""
    if _step_status(step) not in _NOT_RUN_STATUSES:
        for key in (*_OPERATOR_NOTE_KEYS, NOTE_SCOPE_DOMAIN_KEY):
            details.pop(key, None)
        return ""
    if reason in _OPERATOR_DECISION_REASONS and _is_dependent_decision_note(details, gate):
        details[NOTE_LABEL_KEY] = dependent_step_label(gate[0] if gate else reason)
        details[NOTE_DECISION_DEPENDENT_KEY] = True
        if gate:
            details[NOTE_REASON_KEY] = gate[0]
        step["details"] = details
        return details[NOTE_REASON_KEY]
    if reason == NOT_EXECUTED_OUTSIDE_SCOPE:
        label = OUTSIDE_SCOPE_STEP_LABEL
    elif reason == NOT_EXECUTED_DEPENDS_ON_OUTSIDE_SCOPE:
        label = DEPENDS_ON_OUTSIDE_SCOPE_STEP_LABEL
    elif reason == REASON_OPERATOR_DECLINED:
        label = operator_declined_label(
            str(details.get(NOTE_DECLINED_BY_KEY) or ""),
            str(details.get(NOTE_DECLINED_AT_KEY) or ""),
        )
    else:
        try:
            timeout = int(details.get(NOTE_AWAITING_TIMEOUT_KEY) or 0)
        except (TypeError, ValueError):
            timeout = 0
        label = awaiting_approval_label(timeout or None)
    details[NOTE_LABEL_KEY] = label
    step["details"] = details
    return reason


def _mark_scope_continuation(steps: list[Any]) -> str:
    """Label the steps past a route's engagement-scope boundary; return its note.

    Reads the shared route split (``engagement_scope.split_route_at_scope``),
    the same one the path status is derived from. Every not-run step after the
    boundary gets the fourth reason: "outside the engagement scope" when its
    target is in an out-of-scope domain, "depends on a step outside the
    engagement scope" when the step itself is back inside the scope. Display
    metadata only. Returns the route note ("From here, <domain> is reachable..."
    for a route that ends outside the scope, the crossing sentence for one that
    comes back), or ``""`` when the route never crosses the boundary.
    """
    split = split_route_at_scope(steps)
    if not split.crossed:
        return ""
    for index, step in enumerate(steps):
        if index <= int(split.boundary or 0) or not isinstance(step, dict):
            continue
        if _step_relation(step) in _STRUCTURAL_RELATIONS:
            continue
        if not status_is_not_run(step.get("status")):
            continue
        details = step.get("details")
        if not isinstance(details, dict):
            details = {}
        reason = str(details.get(NOTE_REASON_KEY) or "").strip().lower()
        if reason in OUTSIDE_SCOPE_REASONS:
            continue
        domain = step_target_domain(step)
        if domain and domain in split.out_domains:
            details[NOTE_REASON_KEY] = NOT_EXECUTED_OUTSIDE_SCOPE
            details[NOTE_SCOPE_DOMAIN_KEY] = domain
        else:
            details[NOTE_REASON_KEY] = NOT_EXECUTED_DEPENDS_ON_OUTSIDE_SCOPE
        step["details"] = details
    if split.prefix_only:
        return continuation_sentence(split.out_domains[0] if split.out_domains else "")
    return crossing_sentence(split.out_domains)


def policy_unlock_line(check_titles: Iterable[str]) -> str:
    """"Enabling <checks> in the scan policy would let ADscan prove this route."

    The one sentence the PDF report, the LITE report and the web CTEM print
    beside a route the policy kept from being walked end to end. Empty when no
    title is given. A white-label deliverable substitutes the product name at
    its own render boundary.
    """
    names: list[str] = []
    for title in check_titles or ():
        text = str(title or "").strip()
        if text and text not in names:
            names.append(text)
    if not names:
        return ""
    joined = names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"
    return f"Enabling {joined} in the scan policy would let ADscan prove this route."


def _check_titles(entries: Iterable[Mapping[str, Any]]) -> list[str]:
    """Client titles of the excluded steps' checks (the relation when unknown)."""
    try:
        from adscan_core.scan_policy.registry import load_registry  # noqa: PLC0415

        registry = load_registry()
    except Exception:  # noqa: BLE001 - fall back to the relation names
        registry = None
    titles: list[str] = []
    for entry in entries or ():
        check_id = str(entry.get("check_id") or "")
        check = registry.get(check_id) if registry is not None and check_id else None
        titles.append(str(getattr(check, "title", "") or entry.get("relation") or ""))
    return titles


def _strip_note(details: dict[str, Any]) -> None:
    if details.get(NOTE_REASON_KEY) == NOT_EXECUTED_REASON:
        details.pop(NOTE_REASON_KEY, None)
        details.pop(NOTE_CHECK_KEY, None)
        details.pop(NOTE_LABEL_KEY, None)


def annotate_policy_exclusions(
    records: Iterable[Any],
    excluded_relations: Iterable[str] | Mapping[str, Any] | None = None,
) -> int:
    """Stamp the scan-policy note on every excluded, not-run step. In place.

    Args:
        records: Display records (attack-path summaries with ``steps``).
        excluded_relations: Relations the policy excluded, as a list or a
            ``{relation: check_id}`` mapping (the coverage block's
            ``excluded_relation_checks``).

    Returns:
        How many records carry at least one excluded step. Never raises on a
        malformed record; it is skipped.
    """
    index = _relation_index(excluded_relations)
    annotated = 0
    for record in records or ():
        if not isinstance(record, dict):
            continue
        steps = record.get("steps")
        if not isinstance(steps, list):
            continue
        excluded_steps: list[dict[str, Any]] = []
        #: Excluded steps a policy change would unlock. A map-only stop (the
        #: policy left the step to an operator and none was present) is not one:
        #: enabling the check changes nothing there.
        unlockable: list[dict[str, Any]] = []
        decided: list[dict[str, Any]] = []
        continuation = _mark_scope_continuation(steps)
        #: The operator decision that stopped this route, from its first step
        #: that carries one (the step the operator was asked about).
        gate: tuple[str, str, str] | None = None
        gate_reason = ""
        for position, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            raw_details = step.get("details")
            # Copy before writing: an edge note is shared by every route that
            # crosses the edge, and what it means here depends on THIS route.
            details = dict(raw_details) if isinstance(raw_details, dict) else {}
            if isinstance(raw_details, dict):
                step["details"] = details
            if _label_not_needed_step(step, details):
                continue
            relation = _step_relation(step)
            hit = index.get(_norm(relation)) if index else None
            if hit is None and index:
                hit = index.get(_compact(relation))
            noted = str(details.get(NOTE_REASON_KEY) or "").strip().lower()
            if (
                noted in _OPERATOR_DECISION_REASONS
                and status_is_not_run(step.get("status"))
                and details.get(NOTE_DECISION_DEPENDENT_KEY) is True
                and (gate is None or hit is not None)
            ):
                # A dependent note written on an edge this route shares with
                # another route: nothing on THIS route was put to the operator
                # (or the step is one the policy excludes anyway), so the note
                # is not this route's reason.
                for key in _OPERATOR_NOTE_KEYS:
                    details.pop(key, None)
                noted = ""
            elif (
                gate_reason
                and not noted
                and hit is None
                and status_is_not_run(step.get("status"))
                and relation.strip().lower() not in _STRUCTURAL_RELATIONS
            ):
                # A later step of a route the decision stopped, reached through
                # an edge the engine never noted (shared with an unasked route).
                details[NOTE_REASON_KEY] = gate_reason
                details[NOTE_DECISION_DEPENDENT_KEY] = True
            decision = _label_operator_decision(step, details, gate)
            if decision:
                if decision in _OPERATOR_DECISION_REASONS and gate is None:
                    gate = _decision_identity(details)
                    gate_reason = gate[0]
                decided.append(
                    {
                        "step": int(step.get("step") or position),
                        "relation": relation,
                        "reason": decision,
                        **(
                            {"dependent": True}
                            if details.get(NOTE_DECISION_DEPENDENT_KEY) is True
                            else {}
                        ),
                    }
                )
                continue
            engine_noted = details.get(NOTE_REASON_KEY) == NOT_EXECUTED_REASON
            check_id = hit[0] if hit is not None else None
            label = (hit[1] if hit is not None else "") or NOT_EXECUTED_BY_POLICY_LABEL
            if _step_status(step) not in _NOT_RUN_STATUSES:
                # The step ran (or another doctrine owns its label): never
                # call it "not executed", and drop a stale engine note.
                if engine_noted:
                    _strip_note(details)
                continue
            if not engine_noted and check_id is None:
                continue
            resolved_check = str(details.get(NOTE_CHECK_KEY) or check_id or "")
            details[NOTE_REASON_KEY] = NOT_EXECUTED_REASON
            if resolved_check:
                details[NOTE_CHECK_KEY] = resolved_check
            details[NOTE_LABEL_KEY] = (
                label if hit is not None else details.get(NOTE_LABEL_KEY) or label
            )
            step["details"] = details
            entry = {
                "step": int(step.get("step") or position),
                "relation": relation,
                "check_id": resolved_check,
            }
            excluded_steps.append(entry)
            if details.get(NOTE_LABEL_KEY) != MAP_ONLY_STEP_LABEL:
                unlockable.append(entry)
        meta = record.get("meta")
        if decided:
            if not isinstance(meta, dict):
                meta = {}
                record["meta"] = meta
            meta[META_OPERATOR_DECISION_KEY] = decided
        elif isinstance(meta, dict):
            meta.pop(META_OPERATOR_DECISION_KEY, None)
        if excluded_steps:
            if not isinstance(meta, dict):
                meta = {}
                record["meta"] = meta
            meta[META_EXCLUDED_STEPS_KEY] = excluded_steps
            meta[META_NOT_EXECUTED_KEY] = True
            unlock = policy_unlock_line(_check_titles(unlockable))
            if unlock:
                meta[META_UNLOCK_LINE_KEY] = unlock
            else:
                meta.pop(META_UNLOCK_LINE_KEY, None)
            annotated += 1
        elif isinstance(meta, dict):
            meta.pop(META_EXCLUDED_STEPS_KEY, None)
            meta.pop(META_NOT_EXECUTED_KEY, None)
            meta.pop(META_UNLOCK_LINE_KEY, None)
        # The out-of-scope continuation: shown beside the route as what lies past
        # the boundary, never as a reason the route itself did not run.
        if continuation:
            if not isinstance(meta, dict):
                meta = {}
                record["meta"] = meta
            meta[META_SCOPE_CONTINUATION_KEY] = continuation
            meta[META_SCOPE_OUT_DOMAINS_KEY] = list(split_route_at_scope(steps).out_domains)
            existing = str(meta.get(META_UNLOCK_LINE_KEY) or "").strip()
            if continuation not in existing:
                meta[META_UNLOCK_LINE_KEY] = " ".join(
                    part for part in (existing, continuation) if part
                )
        elif isinstance(meta, dict):
            meta.pop(META_SCOPE_CONTINUATION_KEY, None)
            meta.pop(META_SCOPE_OUT_DOMAINS_KEY, None)
    return annotated


def record_has_policy_exclusion(record: Any) -> bool:
    """True when a display record carries an excluded, not-run step."""
    if not isinstance(record, Mapping):
        return False
    meta = record.get("meta")
    if not isinstance(meta, Mapping):
        return False
    if meta.get(META_NOT_EXECUTED_KEY):
        return True
    return str(meta.get("execution_support_status") or "") == EXECUTION_SUPPORT_EXCLUDED


def route_not_executed_cause(record: Any) -> str:
    """Why an annotated route stopped short, from the first step that stopped it.

    Returns ``outside_engagement_scope`` (reason 4), ``operator_declined``
    (reason 3), ``operator_required`` (reason 2, which is also how a map-only run
    labels an enabled step), ``excluded_by_scan_policy`` (reason 1), or ``""``
    when no step carries any of them. Reads display metadata only, after :func:`annotate_policy_exclusions`.
    """
    if not isinstance(record, Mapping):
        return ""
    steps = record.get("steps")
    if not isinstance(steps, list):
        return ""
    unnoted_not_run = False
    for step in steps:
        if not isinstance(step, Mapping):
            continue
        details = step.get("details")
        if not status_is_not_run(step.get("status")):
            continue
        structural = _step_relation(step) in _STRUCTURAL_RELATIONS
        if not isinstance(details, Mapping):
            unnoted_not_run = unnoted_not_run or not structural
            continue
        reason = str(details.get(NOTE_REASON_KEY) or "").strip().lower()
        if reason in OUTSIDE_SCOPE_REASONS:
            # The scope stopped the route only when everything before the
            # boundary ran; an earlier step that simply did not run in this
            # assessment is the honest cause.
            return "" if unnoted_not_run else NOT_EXECUTED_OUTSIDE_SCOPE
        if reason in _OPERATOR_DECISION_REASONS and details.get(NOTE_DECISION_DEPENDENT_KEY) is True:
            # A step that waited on another route's decision: never this
            # route's first cause (its own gate, when it has one, came earlier).
            if not structural:
                unnoted_not_run = True
            continue
        if reason in _STEP_NOTED_REASONS:
            return reason
        if not reason and not structural:
            unnoted_not_run = True
        if reason == NOT_EXECUTED_REASON:
            if details.get(NOTE_LABEL_KEY) == MAP_ONLY_STEP_LABEL:
                return REASON_AWAITING_APPROVAL
            return NOT_EXECUTED_REASON
    return ""


def route_awaiting_wait_seconds(record: Any) -> int:
    """How long the approval request that stopped this route waited (seconds).

    Read from the first not-run step carrying the "awaiting approval" note that
    was itself put to the operator (not a step that waited on it). 0 when the
    route did not stop on an unanswered request, or nobody was there to ask.
    """
    if not isinstance(record, Mapping) or route_not_executed_cause(record) != REASON_AWAITING_APPROVAL:
        return 0
    steps = record.get("steps")
    if not isinstance(steps, list):
        return 0
    for step in steps:
        if not isinstance(step, Mapping) or not status_is_not_run(step.get("status")):
            continue
        details = step.get("details")
        if not isinstance(details, Mapping):
            continue
        if str(details.get(NOTE_REASON_KEY) or "").strip().lower() != REASON_AWAITING_APPROVAL:
            continue
        if details.get(NOTE_DECISION_DEPENDENT_KEY) is True:
            continue
        try:
            return max(0, int(details.get(NOTE_AWAITING_TIMEOUT_KEY) or 0))
        except (TypeError, ValueError):
            return 0
    return 0


def count_routes_not_executed(records: Iterable[Any]) -> int:
    """How many routes the scan policy kept from being walked end to end."""
    return sum(1 for record in records or () if record_has_policy_exclusion(record))


__all__ = (
    "META_SCOPE_CONTINUATION_KEY",
    "META_SCOPE_OUT_DOMAINS_KEY",
    "EXECUTION_SUPPORT_EXCLUDED",
    "META_EXCLUDED_STEPS_KEY",
    "META_NOT_EXECUTED_KEY",
    "META_OPERATOR_DECISION_KEY",
    "META_UNLOCK_LINE_KEY",
    "NOTE_AWAITING_TIMEOUT_KEY",
    "NOTE_CHECK_KEY",
    "NOTE_DECLINED_AT_KEY",
    "NOTE_DECLINED_BY_KEY",
    "NOTE_DECISION_DEPENDENT_KEY",
    "NOTE_LABEL_KEY",
    "NOTE_REASON_KEY",
    "route_awaiting_wait_seconds",
    "route_not_executed_cause",
    "NOT_EXECUTED_BY_POLICY_LABEL",
    "NOT_EXECUTED_REASON",
    "annotate_policy_exclusions",
    "count_routes_not_executed",
    "excluded_relation_index",
    "excluded_relations_from_block",
    "held_back_write_label",
    "is_policy_exclusion_note",
    "policy_unlock_line",
    "record_has_policy_exclusion",
    "status_is_not_run",
)
