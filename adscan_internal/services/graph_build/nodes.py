"""Graph nodes from collected objects: payloads, privileged-membership annotations, tier stamp.

The rules that turn collected directory objects into attack-graph node payloads.
Moved here from ``collector/persistence.py`` (bodies unchanged) so the graph
build and the 14.0.x persist share ONE implementation. Design:
``docs/superpowers/specs/2026-11-12-inventory-first-graph-persistence.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core.memory_guard import check_enclosing_stage
from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.models import CollectionResult
from adscan_internal.services.privileged_group_classifier import (
    classify_privileged_membership,
    resolve_privileged_followup_decision,
)

#: Objects classified between two questions to the enclosing stage's memory
#: guard (the derivation at persist, or the graph build). The question itself is
#: rate limited; this only spares a context lookup per object.
_MEMORY_CHECK_EVERY = 1024


@dataclass(frozen=True)
class UpsertedNodes:
    """The collected objects of one result, written into a graph.

    Attributes:
        payloads: The classified node payloads, in collection order.
        payload_by_sid: Payload by upper-cased object SID.
        sid_to_graph_id: Upper-cased object SID -> graph node id. Computed AFTER
            the upsert, because ``upsert_nodes`` normalizes a principal's name
            and the node id can depend on it.
    """

    payloads: list[dict[str, Any]]
    payload_by_sid: dict[str, dict[str, Any]]
    sid_to_graph_id: dict[str, str]


def upsert_result_nodes(graph: dict[str, Any], result: CollectionResult) -> UpsertedNodes:
    """Write ``result``'s classified nodes into ``graph`` and index their graph ids.

    ONE implementation for the 14.0.x persist and the graph build.
    """
    node_payloads = _build_classified_node_payloads(result)
    attack_graph_service.upsert_nodes(graph, node_payloads)
    sid_to_graph_id: dict[str, str] = {}
    payload_by_sid = {
        str(payload.get("objectId") or "").upper(): payload
        for payload in node_payloads
        if str(payload.get("objectId") or "").strip()
    }
    for sid in result.nodes:
        payload = payload_by_sid.get(sid.upper())
        if not payload:
            payload = result.nodes[sid].to_graph_payload()
        sid_to_graph_id[sid.upper()] = attack_graph_service._node_id(payload)  # noqa: SLF001
    return UpsertedNodes(
        payloads=node_payloads,
        payload_by_sid=payload_by_sid,
        sid_to_graph_id=sid_to_graph_id,
    )


def _build_classified_node_payloads(result: CollectionResult) -> list[dict[str, Any]]:
    """Return graph node payloads with effective privileged-membership annotations."""
    payloads: dict[str, dict[str, Any]] = {}
    for index, (sid, node) in enumerate(result.nodes.items()):
        if index % _MEMORY_CHECK_EVERY == 0:
            check_enclosing_stage()
        payloads[sid.upper()] = node.to_graph_payload()
    inherited = _resolve_inherited_privileged_memberships(result)

    for sid, record in inherited.items():
        payload = payloads.get(sid)
        if not payload:
            continue
        props = payload.setdefault("properties", {})
        if not isinstance(props, dict):
            props = {}
            payload["properties"] = props

        memberships = tuple(
            str(item) for item in record.get("memberships", ()) if str(item).strip()
        )
        terminal_class = str(record.get("terminal_class") or "direct_compromise")
        matched_keys = tuple(
            str(item) for item in record.get("matched_keys", ()) if str(item).strip()
        )

        payload["isTierZero"] = True
        payload["highvalue"] = True
        payload["system_tags"] = _merge_system_tags(
            payload.get("system_tags"), "admin_tier_0"
        )
        payload["tier0_inherited"] = True
        payload["tier0_memberships"] = list(memberships)
        payload["target_terminal_class"] = terminal_class

        props["isTierZero"] = True
        props["highvalue"] = True
        props["system_tags"] = _merge_system_tags(
            props.get("system_tags"), "admin_tier_0"
        )
        props["tier0_inherited"] = True
        props["tier0_memberships"] = list(memberships)
        props["tier0_membership_keys"] = list(matched_keys)
        props["target_terminal_class"] = terminal_class

    _stamp_privilege_tier_on_payloads(result, payloads)
    return list(payloads.values())


def _stamp_privilege_tier_on_payloads(
    result: CollectionResult, payloads: dict[str, dict[str, Any]]
) -> None:
    """Stamp ``properties["privilege_tier"]`` on every graph node payload (Phase 1c).

    Additive: writes the enriched tier-SSOT :class:`PrivilegeTier` value onto each
    node so downstream consumers can key on ONE per-node tier. No reader consumes
    it yet (the reader switch is Phase 2), so this cannot move any attack path.

    GAP-B (the load-bearing correctness point): User/Computer nodes are stamped
    with the MEMBERSHIP-AWARE tier from :func:`_classify_principals_by_membership`
    (the same SSOT that stamps ``computers.json``/``users.json``), NEVER the bare
    node-resolver — a member of Domain Admins grades ``tier0_direct`` via its
    transitive group closure, which a per-node identity read would miss and grade
    ``tier2``. Group / Domain / ADCS nodes carry their tier on their own identity,
    so they resolve through :func:`privilege_tier_for_node` (which grades a DA
    group ``tier0_direct``, DNSAdmins ``tier0_escalation_capable``, and a CA /
    certificate template ``tier0_escalation_capable`` by kind).
    """
    from adscan_internal.services.collector.inventory_persistence import (  # noqa: PLC0415
        _classify_principals_by_membership,
    )
    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        PrivilegeTier,
        privilege_tier_for_node,
    )

    # Membership-aware tiers for User/Computer (tier0/tier1 only; tier2 omitted to
    # keep the inventory compact). Anything absent defaults to tier2 below. The
    # third map records HOW a computer's tier was inferred (axis-1 confidence).
    _, member_tier_by_id, member_tier_basis_by_id = (
        _classify_principals_by_membership(_membership_tier_view(result))
    )

    for sid, payload in payloads.items():
        kind = str(payload.get("kind") or "").strip().lower()
        props = payload.setdefault("properties", {})
        if not isinstance(props, dict):
            props = {}
            payload["properties"] = props
        if kind in ("user", "computer"):
            tier_value = member_tier_by_id.get(sid, PrivilegeTier.TIER2.value)
        else:
            # Group / Domain / ADCS — tier is a property of the node's own
            # identity, resolved through the enriched tier SSOT.
            tier_value = privilege_tier_for_node(payload).value
        props["privilege_tier"] = tier_value
        # Computers carry the tier-basis (heuristic Tier 1 vs deterministic
        # Tier 0) so the report can declare how each server tier was inferred.
        basis_value = member_tier_basis_by_id.get(sid)
        if basis_value:
            props["privilege_tier_basis"] = basis_value


def _membership_tier_relations() -> frozenset[str]:
    """The relations ``_classify_principals_by_membership`` reads.

    Group membership, the admin grants that floor a principal's tier (the
    ``relation_is_admin_grant`` SSOT over the control-strength table), broad
    RDP reach and delegation. Every other relationship is skipped by that
    function, so handing it only these gives the same answer.
    """
    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        relation_is_admin_grant,
    )
    from adscan_internal.services.edge_kind import (  # noqa: PLC0415
        _CONTROL_STRENGTH_BY_RELATION,
    )

    admin_grants = {r for r in _CONTROL_STRENGTH_BY_RELATION if relation_is_admin_grant(r)}
    return frozenset({"MemberOf", "CanRDP", "AllowedToDelegate", *admin_grants})


def _membership_tier_view(result: CollectionResult) -> CollectionResult:
    """``result`` with its relationships narrowed to :func:`_membership_tier_relations`.

    A shallow copy (the node and finding containers are shared, unchanged);
    from a build the relationships stay a store view, re-iterable.
    """
    from dataclasses import replace  # noqa: PLC0415

    from adscan_internal.services.graph_build.edge_view import edges_of  # noqa: PLC0415

    return replace(result, edges=edges_of(result.edges, _membership_tier_relations()))


def _merge_system_tags(existing: object, *tags: str) -> str:
    """Return a stable comma-separated system_tags string."""
    values: list[str] = []
    if isinstance(existing, str):
        values.extend(part.strip() for part in existing.replace(" ", ",").split(","))
    elif isinstance(existing, list):
        values.extend(str(part).strip() for part in existing)
    values.extend(tag.strip() for tag in tags)
    deduped = sorted({value for value in values if value})
    return ",".join(deduped)


def _resolve_inherited_privileged_memberships(
    result: CollectionResult,
) -> dict[str, dict[str, Any]]:
    """Classify User/Computer nodes by recursive membership in privileged groups."""
    from adscan_internal.services.graph_build.edge_view import edges_of  # noqa: PLC0415

    group_parents: dict[str, set[str]] = {}
    principal_groups: dict[str, set[str]] = {}
    for edge in edges_of(result.edges, ("MemberOf",)):
        if edge.relation != "MemberOf":
            continue
        source_sid = edge.source_object_id.upper()
        target_sid = edge.target_object_id.upper()
        source_node = result.nodes.get(source_sid)
        target_node = result.nodes.get(target_sid)
        if not source_node or not target_node or target_node.kind != "Group":
            continue
        if source_node.kind == "Group":
            group_parents.setdefault(source_sid, set()).add(target_sid)
        elif source_node.kind in {"User", "Computer"}:
            principal_groups.setdefault(source_sid, set()).add(target_sid)

    def _expand_groups(group_sids: set[str]) -> set[str]:
        expanded: set[str] = set()
        pending = list(group_sids)
        while pending:
            group_sid = pending.pop()
            if group_sid in expanded:
                continue
            expanded.add(group_sid)
            pending.extend(sorted(group_parents.get(group_sid, set()) - expanded))
        return expanded

    inherited: dict[str, dict[str, Any]] = {}
    for index, (principal_sid, direct_group_sids) in enumerate(principal_groups.items()):
        if index % _MEMORY_CHECK_EVERY == 0:
            check_enclosing_stage()
        principal_node = result.nodes.get(principal_sid)
        if not principal_node or principal_node.kind not in {"User", "Computer"}:
            continue
        group_sids = _expand_groups(direct_group_sids)
        group_nodes = [
            result.nodes[group_sid]
            for group_sid in sorted(group_sids)
            if group_sid in result.nodes
        ]
        membership = classify_privileged_membership(
            group_sids=[node.object_id for node in group_nodes],
            group_names=[node.name for node in group_nodes],
            group_distinguished_names=[node.distinguished_name for node in group_nodes],
        )
        decision = resolve_privileged_followup_decision(membership)
        if not decision.matched_keys:
            continue
        terminal_class = _terminal_class_from_privileged_decision(decision)
        inherited[principal_sid] = {
            "memberships": tuple(node.name for node in group_nodes),
            "matched_keys": decision.matched_keys,
            "terminal_class": terminal_class,
        }
    return inherited


def _terminal_class_from_privileged_decision(decision: object) -> str:
    """Map a privileged follow-up decision to attack-graph terminal semantics."""
    direct_keys = set(getattr(decision, "direct_action_keys", ()) or ())
    enrichment_keys = set(getattr(decision, "enrichment_keys", ()) or ())
    future_keys = set(getattr(decision, "future_followup_keys", ()) or ())
    dependency_keys = set(getattr(decision, "dependency_only_keys", ()) or ())
    actionable_keys = set(getattr(decision, "actionable_keys", ()) or ())

    if direct_keys:
        return "direct_compromise"
    if {"backup_operators", "dns_admins"} & actionable_keys:
        return "followup_terminal"
    if enrichment_keys:
        return "graph_extension"
    if future_keys:
        return "future_followup"
    if dependency_keys:
        return "dependency_only"
    return "direct_compromise"
