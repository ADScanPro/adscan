"""Attack step execution support registry.

This module centralizes the "what can ADscan execute" mapping so that:
- new steps can be classified at creation time (supported vs unsupported vs policy-blocked)
- workspace loads can refresh existing graphs when ADscan is upgraded

Important:
- `unsupported` means ADscan has no implementation for the relation (tool limitation).
- `unavailable` is runtime-only and depends on credentials/metadata, so it is not part
  of this registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from adscan_internal.services.attack_step_catalog import (
    get_attack_step_entry,
    get_relation_notes_by_support_kind,
)


@dataclass(frozen=True, slots=True)
class RelationSupport:
    kind: str
    reason: str
    compromise_semantics: str = "other"
    compromise_effort: str = "other"


CONTEXT_ONLY_RELATIONS: dict[str, str] = get_relation_notes_by_support_kind("context")
POLICY_BLOCKED_RELATIONS: dict[str, str] = get_relation_notes_by_support_kind(
    "policy_blocked"
)
SUPPORTED_RELATION_NOTES: dict[str, str] = get_relation_notes_by_support_kind(
    "supported"
)

PATH_COMPROMISE_LABELS: dict[str, str] = {
    "direct_target_compromise": "Direct Compromise",
    "access_capability_only": "Privileged Access",
    "context_only": "Contextual",
    "other": "Other",
}
COMPROMISE_SEMANTICS_PRIORITY: dict[str, int] = {
    "direct_target_compromise": 0,
    "access_capability_only": 1,
    "other": 2,
    "context_only": 3,
}
COMPROMISE_EFFORT_LABELS: dict[str, str] = {
    "none": "None",
    "immediate": "Immediate",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "other": "Other",
}
COMPROMISE_EFFORT_PRIORITY: dict[str, int] = {
    "none": 0,
    "immediate": 0,
    "low": 1,
    "medium": 3,
    "high": 6,
    "other": 4,
}


def _norm(relation: str) -> str:
    return (relation or "").strip().lower()


def classify_relation_support(relation: str) -> RelationSupport:
    """Classify a relation by execution support.

    Returns:
        RelationSupport(kind=...) where kind is one of:
        - context
        - policy_blocked
        - supported
        - unsupported
    """
    key = _norm(relation)
    if not key:
        return RelationSupport(kind="unsupported", reason="Missing relation")
    entry = get_attack_step_entry(key)
    if entry:
        return RelationSupport(
            kind=entry.support_kind,
            reason=entry.support_reason,
            compromise_semantics=entry.compromise_semantics,
            compromise_effort=entry.compromise_effort,
        )
    return RelationSupport(
        kind="unsupported",
        reason="Not implemented yet in ADscan",
        compromise_semantics="other",
        compromise_effort="other",
    )


def classify_path_compromise_semantics(relations: Iterable[str]) -> str:
    """Return the terminal non-context compromise semantics for a path."""
    ordered = [str(relation or "").strip() for relation in relations]
    for relation in reversed(ordered):
        support = classify_relation_support(relation)
        if support.kind == "context":
            continue
        return support.compromise_semantics or "other"
    return "context_only"


def describe_path_compromise_semantics(relations: Iterable[str]) -> str:
    """Return a human-readable label for the path compromise semantics."""
    semantics = classify_path_compromise_semantics(relations)
    return PATH_COMPROMISE_LABELS.get(semantics, "Other")


def classify_path_compromise_effort(relations: Iterable[str]) -> str:
    """Return the terminal non-context compromise effort for a path."""
    ordered = [str(relation or "").strip() for relation in relations]
    for relation in reversed(ordered):
        support = classify_relation_support(relation)
        if support.kind == "context":
            continue
        return support.compromise_effort or "other"
    return "none"


def describe_path_compromise_effort(relations: Iterable[str]) -> str:
    """Return a human-readable label for the path compromise effort."""
    effort = classify_path_compromise_effort(relations)
    return COMPROMISE_EFFORT_LABELS.get(effort, "Other")


def build_path_priority_key(
    record: dict[str, object],
) -> tuple[int, int, int, int, int, str, str]:
    """Return a semantics-aware sort key for attack-path display ordering.

    Ordering after status is driven primarily by aggregate compromise effort, so
    multi-step low-effort paths beat shorter but materially harder paths such as
    single-step Kerberoasting. Terminal compromise semantics are then used as a
    secondary tie-breaker, followed by executable length and stable labels.
    """
    status_order = {
        "theoretical": 0,
        "unavailable": 1,
        "unsupported": 2,
        "blocked": 3,
        "attempted": 4,
        "exploited": 5,
    }
    relations_raw = record.get("relations")
    relations = (
        [str(relation or "").strip() for relation in relations_raw]
        if isinstance(relations_raw, list)
        else []
    )
    actionable_support = [
        classify_relation_support(relation)
        for relation in relations
        if str(relation or "").strip()
    ]
    actionable_support = [
        support for support in actionable_support if support.kind != "context"
    ]
    aggregate_effort_score = sum(
        COMPROMISE_EFFORT_PRIORITY.get(support.compromise_effort, 4)
        for support in actionable_support
    )
    terminal_semantics = classify_path_compromise_semantics(relations)
    terminal_effort = classify_path_compromise_effort(relations)
    executable_length = (
        int(record.get("length", 0))
        if str(record.get("length", "")).isdigit()
        else len(actionable_support)
    )
    return (
        status_order.get(str(record.get("status") or "").strip().lower(), 3),
        aggregate_effort_score,
        COMPROMISE_SEMANTICS_PRIORITY.get(terminal_semantics, 2),
        COMPROMISE_EFFORT_PRIORITY.get(terminal_effort, 4),
        executable_length,
        str(record.get("source", "")).lower(),
        str(record.get("target", "")).lower(),
    )
