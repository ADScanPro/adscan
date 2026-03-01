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

from adscan_internal.services.attack_step_catalog import (
    get_attack_step_entry,
    get_relation_notes_by_support_kind,
)


@dataclass(frozen=True, slots=True)
class RelationSupport:
    kind: str
    reason: str


CONTEXT_ONLY_RELATIONS: dict[str, str] = get_relation_notes_by_support_kind("context")
POLICY_BLOCKED_RELATIONS: dict[str, str] = get_relation_notes_by_support_kind(
    "policy_blocked"
)
SUPPORTED_RELATION_NOTES: dict[str, str] = get_relation_notes_by_support_kind(
    "supported"
)


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
        return RelationSupport(kind=entry.support_kind, reason=entry.support_reason)
    return RelationSupport(kind="unsupported", reason="Not implemented yet in ADscan")
