"""Central choke-point classification for ADscan attack steps.

This module is the shared source of truth for privilege-transition choke points.
It can be used both by:

- structural snapshot builders (Phase 1 / identity exposure)
- runtime attack-step persistence (`upsert_edge`)
"""

from __future__ import annotations

from typing import Any

from adscan_internal.services.control_semantics import (
    classify_group_control_semantics,
    is_material_control_transition,
)


def control_rank(value: str) -> int:
    """Return a stable ordinal rank for one ADscan control level."""
    normalized = str(value or "").strip().lower()
    if normalized == "direct_domain_control":
        return 3
    if normalized == "domain_control_enabler":
        return 2
    if normalized == "high_impact_privilege":
        return 1
    return 0


def classify_control_transition(
    *,
    source_label: str,
    source_kind: str,
    source_control_level: str,
    target_label: str,
    target_kind: str,
    target_control_level: str,
    transition_type: str,
    blast_radius: int = 1,
    affected_user_count: int | None = None,
    reason: str | None = None,
    source_semantics: dict[str, Any] | None = None,
    target_semantics: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return one normalized choke-point record when control rises."""
    source_semantics = source_semantics or {"control_level": source_control_level}
    target_semantics = target_semantics or {"control_level": target_control_level}
    if not is_material_control_transition(source_semantics, target_semantics):
        return None
    if control_rank(target_control_level) <= control_rank(source_control_level):
        return None

    directness = (
        "direct"
        if target_control_level == "direct_domain_control"
        else "indirect"
        if target_control_level == "domain_control_enabler"
        else "contextual"
    )
    severity = (
        "critical"
        if directness == "direct" and blast_radius >= 5
        else "high"
        if directness in {"direct", "indirect"} and blast_radius >= 2
        else "medium"
    )
    return {
        "is_choke_point": True,
        "choke_point_type": transition_type,
        "choke_point_directness": directness,
        "from_control_level": source_control_level,
        "to_control_level": target_control_level,
        "blast_radius": max(1, int(blast_radius or 1)),
        "affected_principal_count": int(
            affected_user_count if affected_user_count is not None else blast_radius or 1
        ),
        "choke_point_reason": reason
        or f"{source_label} transitions to {target_label} via {transition_type}",
        "source_kind": source_kind,
        "target_kind": target_kind,
        "source_label": source_label,
        "target_label": target_label,
        "severity": severity,
        "title": f"{source_label} -> {target_label}",
    }


def _extract_sid_from_node(node: dict[str, Any]) -> str:
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    for candidate in (
        node.get("objectId"),
        node.get("objectid"),
        props.get("objectId"),
        props.get("objectid"),
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def _node_kind(node: dict[str, Any]) -> str:
    kind = node.get("kind") or node.get("labels") or node.get("type")
    if isinstance(kind, list) and kind:
        return str(kind[0])
    return str(kind or "")


def infer_node_control_level(node: dict[str, Any]) -> str:
    """Infer ADscan control level for one graph node."""
    kind = _node_kind(node).strip().lower()
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if kind == "group":
        meta = classify_group_control_semantics(
            sid=_extract_sid_from_node(node),
            name=str(node.get("label") or props.get("name") or ""),
        )
        return str(meta.get("control_level") or "standard")

    is_tier0 = bool(node.get("isTierZero") or props.get("isTierZero"))
    tags = node.get("system_tags") or props.get("system_tags") or []
    if isinstance(tags, str):
        tags = [tags]
    if any(str(tag).strip().lower() == "admin_tier_0" for tag in tags):
        is_tier0 = True
    is_high_value = bool(node.get("highvalue") or props.get("highvalue"))

    if kind in {"computer", "domain"} and (is_tier0 or is_high_value):
        return "direct_domain_control"
    if kind == "user":
        if is_tier0:
            return "direct_domain_control"
        if is_high_value:
            return "high_impact_privilege"
        return "standard"
    if is_tier0:
        return "direct_domain_control"
    if is_high_value:
        return "high_impact_privilege"
    return "standard"


def classify_attack_graph_edge_choke_point(
    graph: dict[str, Any],
    *,
    from_id: str,
    relation: str,
    to_id: str,
    notes: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Classify one persisted attack-graph edge as a choke point when applicable."""
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return None
    from_node = nodes_map.get(from_id)
    to_node = nodes_map.get(to_id)
    if not isinstance(from_node, dict) or not isinstance(to_node, dict):
        return None

    relation_key = str(relation or "").strip().lower()
    source_label = str(from_node.get("label") or from_id)
    target_label = str(to_node.get("label") or to_id)
    source_kind = _node_kind(from_node).strip().lower() or "unknown"
    target_kind = _node_kind(to_node).strip().lower() or "unknown"
    source_control_level = infer_node_control_level(from_node)
    target_control_level = infer_node_control_level(to_node)
    source_semantics = (
        classify_group_control_semantics(
            sid=_extract_sid_from_node(from_node),
            name=str(from_node.get("label") or ""),
        )
        if source_kind == "group"
        else {"control_level": source_control_level}
    )
    target_semantics = (
        classify_group_control_semantics(
            sid=_extract_sid_from_node(to_node),
            name=str(to_node.get("label") or ""),
        )
        if target_kind == "group"
        else {"control_level": target_control_level}
    )
    if not is_material_control_transition(source_semantics, target_semantics):
        return None
    blast_radius = 1
    affected_count = 1
    if isinstance(notes, dict):
        try:
            blast_radius = max(
                int(notes.get("blast_radius") or 1),
                int(notes.get("affected_user_count") or 1),
                int(notes.get("affected_principal_count") or 1),
            )
        except (TypeError, ValueError):
            blast_radius = 1
        affected_count = blast_radius

    transition_type = {
        "memberof": "membership_assignment",
        "adminto": "execution_access",
        "genericall": "object_control",
        "genericwrite": "object_control",
        "writedacl": "object_control",
        "writeowner": "object_control",
        "addmember": "group_membership_control",
        "forcechangepassword": "credential_control",
    }.get(relation_key, "attack_step_transition")

    reason = (
        f"{source_label} gains a control transition to {target_label} via {relation_key}"
    )
    return classify_control_transition(
        source_label=source_label.split("@", 1)[0],
        source_kind=source_kind,
        source_control_level=source_control_level,
        target_label=target_label.split("@", 1)[0],
        target_kind=target_kind,
        target_control_level=target_control_level,
        transition_type=transition_type,
        blast_radius=blast_radius,
        affected_user_count=affected_count,
        reason=reason,
    )
