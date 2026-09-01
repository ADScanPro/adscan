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
from functools import lru_cache
from typing import Iterable

from adscan_internal.services.attack_step_catalog import (
    get_attack_step_catalog,
    get_attack_step_entry,
    get_relation_notes_by_support_kind,
    normalize_execution_relation,
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
TARGET_OUTCOME_LABELS: dict[str, str] = {
    "direct_compromise": "Direct Domain Control",
    "tier0_foothold": "Tier 0 Foothold (post-ex pending)",
    "followup_terminal": "Domain Compromise Enabler",
    "graph_extension": "High-Impact Privilege",
    "future_followup": "Future Follow-up",
    "dependency_only": "Dependency",
    "pivot": "Pivot Opportunity",
}
TARGET_OUTCOME_SECTION_ORDER: tuple[str, ...] = (
    "direct_compromise",
    "tier0_foothold",
    "followup_terminal",
    "graph_extension",
    "pivot",
)
TARGET_OUTCOME_SECTION_STYLES: dict[str, tuple[str, str, str]] = {
    "direct_compromise": ("Direct Domain Control", "🔥", "error"),
    "tier0_foothold": ("Tier 0 Footholds", "🔓", "warning"),
    "followup_terminal": ("Domain Compromise Enablers", "🎯", "warning"),
    "graph_extension": ("High-Impact Privileges", "⚠", "info"),
    "pivot": ("Pivot Opportunities", "➜", "info"),
}

# Display tiers — the operator-facing 3-level grouping the CLI table sections
# render. Distinct on purpose from the 5-value ``outcome_class`` above, which is
# kept verbatim because the PDF report, executive PDF, premium report.html and
# cached records all consume those strings. This collapses the five outcome
# classes into the three triage tiers a pentester actually reasons about, and
# fixes the crossed-label confusion where the canonical ``COMPROMISE_ENABLER``
# class surfaced under a section labelled "High-Impact Privileges" while the
# section labelled "Domain Compromise Enablers" was fed by ``PRIVILEGED_ESCALATOR``.
DISPLAY_TIER_DOMAIN_COMPROMISE = "domain_compromised"
# Tier-0 Foothold — an access edge (CanRDP/CanPSRemote/SQLAdmin/AdminTo) that
# lands on a Tier-0 asset. Per the nomenclature standard (rule 2) this is NOT a
# domain compromise: the operator still has to execute post-ex on the box to
# promote it. It is its own triage tier so the renderer never appends the
# "⇒ Domain Compromised" closure marker for these paths (that marker is gated on
# DISPLAY_TIER_DOMAIN_COMPROMISE), while still ranking the path above generic
# enablers because reaching a Tier-0 box is high severity.
DISPLAY_TIER_TIER0_FOOTHOLD = "tier0_foothold"
DISPLAY_TIER_COMPROMISE_ENABLER = "compromise_enabler"
DISPLAY_TIER_LATERAL_PIVOT = "lateral_pivot"

_OUTCOME_CLASS_TO_DISPLAY_TIER: dict[str, str] = {
    "direct_compromise": DISPLAY_TIER_DOMAIN_COMPROMISE,
    "tier0_foothold": DISPLAY_TIER_TIER0_FOOTHOLD,
    "followup_terminal": DISPLAY_TIER_COMPROMISE_ENABLER,
    "graph_extension": DISPLAY_TIER_COMPROMISE_ENABLER,
    "future_followup": DISPLAY_TIER_LATERAL_PIVOT,
    "dependency_only": DISPLAY_TIER_LATERAL_PIVOT,
    "pivot": DISPLAY_TIER_LATERAL_PIVOT,
}

DISPLAY_TIER_ORDER: tuple[str, ...] = (
    DISPLAY_TIER_DOMAIN_COMPROMISE,
    DISPLAY_TIER_TIER0_FOOTHOLD,
    DISPLAY_TIER_COMPROMISE_ENABLER,
    DISPLAY_TIER_LATERAL_PIVOT,
)

# (label, icon, style_key) — style_key indexes BRAND_COLORS at the call site.
DISPLAY_TIER_STYLES: dict[str, tuple[str, str, str]] = {
    DISPLAY_TIER_DOMAIN_COMPROMISE: ("Domain Compromised", "🔥", "error"),
    DISPLAY_TIER_TIER0_FOOTHOLD: ("Tier 0 Footholds (post-ex pending)", "🔓", "warning"),
    DISPLAY_TIER_COMPROMISE_ENABLER: ("Compromise Enablers", "🎯", "warning"),
    DISPLAY_TIER_LATERAL_PIVOT: ("Lateral & Pivot", "➜", "info"),
}
CANONICAL_SEARCH_MODE_LABELS: dict[str, str] = {
    "pivot": "Pivot Search",
    "low_priv": "Low-Priv Search",
    "direct_compromise": "Direct Domain Control",
    "followup_terminal": "Domain Compromise Enablers",
}
SEARCH_MODE_ALIASES: dict[str, str] = {
    "pivot search": "pivot",
    "pivot opportunity": "pivot",
    "pivot opportunities": "pivot",
    "low-priv search": "low_priv",
    "low priv search": "low_priv",
    "tier-0 search": "direct_compromise",
    "tier0 search": "direct_compromise",
    "direct domain control": "direct_compromise",
    "high-value search": "followup_terminal",
    "high value search": "followup_terminal",
    "domain compromise enabler": "followup_terminal",
    "domain compromise enablers": "followup_terminal",
}


# Reasons this module authors itself, for relations the catalog does not cover.
# Engineering register, exactly like the catalog's ``support_reason`` values.
_MISSING_RELATION_REASON = "Missing relation"
_NOT_IMPLEMENTED_REASON = "Not implemented yet in ADscan"
_LOCAL_SUPPORT_REASONS: tuple[str, ...] = (
    _MISSING_RELATION_REASON,
    _NOT_IMPLEMENTED_REASON,
)


def _norm(relation: str) -> str:
    return (relation or "").strip().lower()


@lru_cache(maxsize=1)
def internal_support_reasons() -> frozenset[str]:
    """Return every internal ``support_reason`` string, casefolded.

    ``support_reason`` explains to an ENGINEER why ADscan does or does not
    automate a relation ("Not implemented yet in ADscan", "High-risk /
    potentially disruptive (disabled by design)"). It is diagnostic text and
    must never reach a client deliverable — a paying client reading "Not
    implemented yet in ADscan" in their report gets a capability-gap confession
    instead of a finding.

    The set is derived from the catalog plus this module's own fallbacks, so a
    newly authored reason is covered without anyone remembering to register it.
    Consumed by ``destructive_action_policy.is_internal_engineering_reason``,
    which every client-facing renderer screens its reason strings through.
    """
    reasons = {
        str(entry.support_reason or "").strip().casefold()
        for entry in get_attack_step_catalog()
    }
    reasons.update(reason.casefold() for reason in _LOCAL_SUPPORT_REASONS)
    reasons.discard("")
    return frozenset(reasons)


@lru_cache(maxsize=None)
def classify_relation_support(relation: str) -> RelationSupport:
    """Classify a relation by execution support.

    Pure function of a single hashable ``str`` returning an immutable
    (``frozen=True, slots=True``) ``RelationSupport``: it reads only the
    module-level catalog (built at import, never mutated), so the result depends
    solely on ``relation`` and is safe to memoize across domains. The distinct
    relation set is small and bounded, so an unbounded cache is memory-safe.

    Returns:
        RelationSupport(kind=...) where kind is one of:
        - context
        - policy_blocked
        - supported
        - unsupported
    """
    key = normalize_execution_relation(relation)
    if not key:
        return RelationSupport(kind="unsupported", reason=_MISSING_RELATION_REASON)
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
        reason=_NOT_IMPLEMENTED_REASON,
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
) -> tuple[int, int, int, int, int, int, int, int, int, int, str, str]:
    """Return a semantics-aware sort key for attack-path display ordering.

    Ordering is deterministic and target-aware:
    BloodHound criticality decides the main UX bucket (Tier-0, High-Value,
    Pivot), while ADscan terminality decides whether a target is a direct
    compromise, a follow-up terminal, or a graph-extension waypoint.
    """
    priority_class_order = {
        "tierzero": 0,
        "highvalue": 1,
        "pivot": 2,
    }
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
    target_priority_class = str(
        record.get("target_priority_class")
        or ("tierzero" if record.get("is_tier_zero") else "highvalue" if record.get("target_is_high_value") else "pivot")
    ).strip().lower()
    terminal_class_order = {
        "direct_compromise": 0,
        "tier0_foothold": 1,
        "followup_terminal": 2,
        "graph_extension": 3,
        "pivot": 4,
    }
    target_followup_status = str(
        record.get("target_followup_status") or ""
    ).strip().lower()
    if not target_followup_status:
        target_followup_status = {
            "direct_compromise": "actionable",
            "tier0_foothold": "theoretical",
            "followup_terminal": "theoretical",
            "graph_extension": "theoretical",
            "future_followup": "unsupported",
            "dependency_only": "unavailable",
        }.get(str(record.get("target_terminal_class") or "pivot").strip().lower(), "unavailable")
    target_followup_status_order = {
        "actionable": 0,
        "theoretical": 1,
        "unsupported": 2,
        "unavailable": 3,
    }
    target_terminal_class = str(
        record.get("target_terminal_class") or "pivot"
    ).strip().lower()
    try:
        target_priority_rank = int(record.get("target_priority_rank", 100))
    except (TypeError, ValueError):
        target_priority_rank = 100
    # Target reachability deboost — when the annotation phase has determined
    # that the path's terminal host is not reachable from the current vantage,
    # demote the path within its (priority_class, terminal_class, followup,
    # priority_rank) bucket so reachable paths surface first.  ``meta`` is
    # populated by ``_annotate_execution_readiness``; absent it (pre-annotation
    # ordering), every path scores 0 and the ranking is unchanged.
    meta = record.get("meta") if isinstance(record.get("meta"), dict) else {}
    viability_status = str(
        (meta or {}).get("execution_target_viability_status") or ""
    ).strip().lower()
    _UNREACHABLE_VIABILITY_STATES = {
        "resolved_but_unreachable",
        "enabled_but_unresolved",
        "not_in_enabled_inventory",
    }
    target_viability_rank = 1 if viability_status in _UNREACHABLE_VIABILITY_STATES else 0
    return (
        priority_class_order.get(target_priority_class, 2),
        terminal_class_order.get(target_terminal_class, 3),
        # Domain-object-first within the (priority_class, terminal_class) bucket:
        # a path landing on the Domain node itself precedes one landing on a
        # direct-compromise principal (DA/DCs). Stamped by the annotation phase.
        0 if record.get("target_is_domain_object") else 1,
        target_followup_status_order.get(target_followup_status, 3),
        target_priority_rank,
        target_viability_rank,
        status_order.get(str(record.get("status") or "").strip().lower(), 3),
        aggregate_effort_score,
        COMPROMISE_SEMANTICS_PRIORITY.get(terminal_semantics, 2),
        COMPROMISE_EFFORT_PRIORITY.get(terminal_effort, 4),
        executable_length,
        str(record.get("source", "")).lower(),
        str(record.get("target", "")).lower(),
    )


def get_path_target_outcome_class(record: dict[str, object]) -> str:
    """Return the normalized ADscan outcome class for one path.

    Phase 3 — when the materializer has stamped a canonical
    ``outcome_class`` on the record (via the path-based classifier in
    :mod:`adscan_internal.services.compromise_class`), that value is
    authoritative. The legacy heuristics below remain only for
    backward compatibility with cached records produced before Phase 3.
    """
    explicit = str(record.get("outcome_class") or "").strip().lower()
    if explicit in {
        "direct_compromise",
        "tier0_foothold",
        "followup_terminal",
        "graph_extension",
        "future_followup",
        "dependency_only",
        "pivot",
    }:
        return explicit
    terminal_class = str(record.get("target_terminal_class") or "").strip().lower()
    if terminal_class in {
        "direct_compromise",
        "tier0_foothold",
        "followup_terminal",
        "graph_extension",
        "future_followup",
        "dependency_only",
    }:
        return terminal_class
    priority_class = str(record.get("target_priority_class") or "").strip().lower()
    if priority_class == "tierzero" or bool(record.get("is_tier_zero")):
        return "direct_compromise"
    if priority_class == "highvalue" or bool(record.get("target_is_high_value")):
        return "followup_terminal"
    return "pivot"


def describe_path_target_outcome(record: dict[str, object]) -> str:
    """Return a customer-facing label for one path outcome class."""
    return TARGET_OUTCOME_LABELS.get(
        get_path_target_outcome_class(record),
        "Pivot Opportunity",
    )


def get_path_display_tier(record: dict[str, object]) -> str:
    """Return the 3-level operator display tier for one path.

    Collapses the 5-value :func:`get_path_target_outcome_class` into the three
    triage tiers the CLI table sections render (Domain Compromised / Compromise
    Enablers / Lateral & Pivot). See :data:`DISPLAY_TIER_ORDER`.
    """
    return _OUTCOME_CLASS_TO_DISPLAY_TIER.get(
        get_path_target_outcome_class(record),
        DISPLAY_TIER_LATERAL_PIVOT,
    )


def normalize_search_mode_label(label: str | None) -> str:
    """Return the canonical backend search-mode key for one visible label."""
    normalized = str(label or "").strip().lower()
    return SEARCH_MODE_ALIASES.get(normalized, normalized)


def describe_search_mode_label(mode: str | None) -> str:
    """Return the preferred visible label for one canonical search mode."""
    normalized = normalize_search_mode_label(mode)
    return CANONICAL_SEARCH_MODE_LABELS.get(normalized, str(mode or "").strip())


def build_path_execution_priority_key(
    record: dict[str, object],
) -> tuple[int, int, int, int, int, int, int, int, int, int, str, str]:
    """Return the canonical execution-priority key for one path."""
    return build_path_priority_key(record)


def build_path_remediation_priority_key(
    record: dict[str, object],
) -> tuple[int, int, int, int, int, int, int, int, int, int, str, str]:
    """Return a remediation-oriented priority key for one path.

    Remediation favors blast-radius/choke-point value while still preserving
    target criticality, terminal semantics, and execution state.
    """
    base = build_path_priority_key(record)
    blast_radius = 0
    choke_points = record.get("steps")
    if isinstance(choke_points, list):
        for step in choke_points:
            if not isinstance(step, dict):
                continue
            details = step.get("details")
            if not isinstance(details, dict) or not bool(details.get("is_choke_point")):
                continue
            candidate = details.get("blast_radius")
            if isinstance(candidate, int) and candidate > blast_radius:
                blast_radius = candidate
    # The viability_rank field is at base[4]; every later index shifted +1.
    return (
        base[0],
        base[1],
        -blast_radius,
        base[2],
        base[3],
        base[4],   # target_viability_rank
        base[5],   # status_order (was base[4])
        base[6],   # agg_effort_score (was base[5])
        base[7],   # terminal_semantics (was base[6])
        base[8],   # terminal_effort (was base[7])
        base[10],  # source (was base[9])
        base[11],  # target (was base[10])
    )
