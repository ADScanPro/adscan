"""Prune rules: the raw facts that never become path steps, and the edges a
derivation makes redundant.

Moved from ``collector/persistence.py`` (bodies unchanged). The base-edge skip
predicate (:func:`_should_skip_attack_graph_edge`) is applied by the build to
every collected relationship, and
:func:`_drop_redundant_direct_compromise_to_domain_edges` is the derivation pass
that collapses direct-compromise edges to the domain. The build is a full
rebuild from the store, so there is no earlier graph to clean: the 14.0.x
``_prune_existing_*`` passes, which removed stale edges from a graph loaded off
disk before a merge, left with the persist that loaded it.
"""

from __future__ import annotations

from typing import Any

from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.models import CollectionResult, CollectorEdge
from adscan_internal.services.graph_build.passes.adcs import _ESC_DERIVED_RELATIONS
from adscan_internal.services.privileged_group_classifier import sid_rid


_ADCS_OBJECT_KINDS: frozenset[str] = frozenset(
    {
        "CertTemplate",
        "EnterpriseCA",
        "RootCA",
        "AIACA",
        "NTAuthStore",
    }
)


_ADCS_RAW_ACL_RELATIONS: frozenset[str] = frozenset(
    {
        "AllExtendedRights",
        "AutoEnroll",
        "Enroll",
        "GenericAll",
        "GenericWrite",
        "WriteDACL",
        "WriteOwner",
    }
)


_CONTAINER_SCOPE_RELATIONS: frozenset[str] = frozenset(
    {
        "ReadLAPSPassword",
        "SyncLAPSPassword",
    }
)


_CONTAINER_SCOPE_KINDS: frozenset[str] = frozenset({"OU", "Container"})


# Replication-rights extended rights that are evidence-only when targeting the
# Domain object. ``_persist_dcsync_steps`` derives a single canonical
# ``DCSync`` edge from the (GetChanges + GetChangesAll) pair (or from
# ``AllExtendedRights``); persisting the raw component edges as separate
# attack-path steps just produces 3 visually-identical paths through the same
# principal (e.g. Administrators -GetChanges-> Domain, -GetChangesAll-> Domain,
# -GetChangesInFilteredSet-> Domain). One DCSync edge is the kill chain; the
# raws are noise.
_REPLICATION_RIGHT_RELATIONS: frozenset[str] = frozenset(
    {
        "GetChanges",
        "GetChangesAll",
        "GetChangesInFilteredSet",
    }
)


# Key Admins (RID 526) and Enterprise Key Admins (RID 527) are only exploitable
# via shadow credentials + PKINIT, which requires an EnterpriseCA. ACL edges
# targeting these groups are noise when no ADCS is present.
_KEY_ADMINS_RIDS: frozenset[int] = frozenset({526, 527})


def _should_skip_attack_graph_edge(
    edge: CollectorEdge,
    result: CollectionResult,
    *,
    has_enterprise_ca: bool = True,
    container_scope_pairs: frozenset[tuple[str, str]] | None = None,
) -> bool:
    """Return True for raw ACL facts that should not become path steps.

    ADCS detectors consume ACL facts on templates and CAs to emit interpreted
    ``ADCSESC*`` attack steps. Persisting the raw ACL edge as a separate attack
    path transition adds noisy duplicate paths such as ``AllExtendedRights ->
    ESC1`` or non-exploitable standalone paths such as ``Enroll -> ESC1``
    without improving operator actionability.

    The interpreted ``ADCSESC*`` edges that target a CertTemplate or
    EnterpriseCA are also skipped here. ``_persist_esc_compromise_steps``
    re-emits them with the impersonated principal (Domain Admins, Domain
    Controllers, or the ESC13 issuance-policy group) as the target so attack
    paths terminate at the actual compromise instead of at the abuse-vector
    configuration. ESC13 raw edges only get skipped when their linked group is
    resolved — otherwise the raw template-targeted edge is preserved so the
    misconfiguration remains visible.

    ``container_scope_pairs`` is :func:`container_scope_concrete_pairs` of
    ``result``, computed once by a caller that checks many edges (one filtered
    scan for the whole loop). Omitted, it is computed for this call.
    """
    if edge.relation in _ESC_DERIVED_RELATIONS:
        return True
    if edge.relation == "ADCSESC13":
        linked_dn = str((edge.notes or {}).get("linked_group_dn") or "").strip()
        if linked_dn:
            return True
    # Replication-rights to Domain are subsumed by the derived ``DCSync`` edge.
    # Without the full pair the raw edge isn't actionable on its own; with the
    # pair the DCSync edge is the canonical kill-chain step. Either way the
    # raw component edges are noise as path steps.
    if edge.relation in _REPLICATION_RIGHT_RELATIONS:
        target = result.nodes.get(edge.target_object_id.upper())
        if target is not None and str(target.kind) == "Domain":
            return True
    # ACL edges targeting Key Admins (RID 526) / Enterprise Key Admins (RID 527)
    # are only exploitable via shadow credentials + PKINIT, which requires an
    # EnterpriseCA. Without ADCS the groups are not abusable — skip all ACL
    # relations regardless of which specific right is granted.
    if (
        not has_enterprise_ca
        and str(edge.method or "").strip().lower() == "acl"
        and sid_rid(edge.target_object_id) in _KEY_ADMINS_RIDS
    ):
        return True
    if edge.relation not in _ADCS_RAW_ACL_RELATIONS:
        return _is_redundant_container_scope_edge(
            edge, result, container_scope_pairs=container_scope_pairs
        )
    if str(edge.method or "").strip().lower() != "acl":
        return False
    target = result.nodes.get(edge.target_object_id.upper())
    if target is None:
        return False
    return str(target.kind) in _ADCS_OBJECT_KINDS


def container_scope_concrete_pairs(result: CollectionResult) -> frozenset[tuple[str, str]]:
    """``(source SID upper, relation)`` of every container-scope secret read with a concrete target.

    One filtered scan of the relationships (only the container-scope
    relations), so the skip rule answers in O(1) per edge instead of walking
    every relationship per candidate. A target that is not a collected object
    is not concrete, as in the per-candidate rule this replaces.
    """
    from adscan_internal.services.graph_build.edge_view import edges_of  # noqa: PLC0415

    pairs: set[tuple[str, str]] = set()
    for candidate in edges_of(result.edges, _CONTAINER_SCOPE_RELATIONS):
        if candidate.relation not in _CONTAINER_SCOPE_RELATIONS:
            continue
        candidate_target = result.nodes.get(candidate.target_object_id.upper())
        if candidate_target and str(candidate_target.kind) not in _CONTAINER_SCOPE_KINDS:
            pairs.add((candidate.source_object_id.upper(), candidate.relation))
    return frozenset(pairs)


def _is_redundant_container_scope_edge(
    edge: CollectorEdge,
    result: CollectionResult,
    *,
    container_scope_pairs: frozenset[tuple[str, str]] | None = None,
) -> bool:
    """Return True when a container-scope secret read has concrete targets.

    The same principal holds the same right over a concrete object (not a
    container), so the container-level edge adds nothing. The edge itself never
    counts: its target is a container, which is never concrete.
    """
    if edge.relation not in _CONTAINER_SCOPE_RELATIONS:
        return False
    target = result.nodes.get(edge.target_object_id.upper())
    if target is None or str(target.kind) not in _CONTAINER_SCOPE_KINDS:
        return False
    if container_scope_pairs is None:
        container_scope_pairs = container_scope_concrete_pairs(result)
    return (edge.source_object_id.upper(), edge.relation) in container_scope_pairs


# Priority hierarchy for ``direct_compromise → Domain`` edges: smaller rank
# wins. Anything not in the table is treated as "no opinion" — neither
# considered a candidate for the best edge, nor dropped as redundant.
_DOMAIN_COMPROMISE_RELATION_PRIORITY: dict[str, int] = {
    "DCSync": 0,
    "AllExtendedRights": 1,
    "GenericAll": 2,
    "WriteDACL": 3,
    "WriteOwner": 4,
    "GenericWrite": 5,
}


def _drop_redundant_direct_compromise_to_domain_edges(
    graph: dict[str, Any],
) -> int:
    """Collapse direct-compromise → Domain edges to the highest-impact relation.

    For each ``direct_compromise`` source S that has any edge to the Domain
    object, compute the highest-priority relation reachable from S to Domain
    by traversing nested ``MemberOf`` edges through other direct-compromise
    groups. S's own edges to Domain are then trimmed: anything below the
    transitively-reachable best relation is dropped.

    Concrete Active.htb example:

    * ``Domain Admins -GenericWrite-> active.htb``
    * ``Enterprise Admins -GenericAll-> active.htb``
    * ``BUILTIN Administrators -DCSync-> active.htb``
    * ``Domain Admins -MemberOf-> BUILTIN Administrators``
    * ``Enterprise Admins -MemberOf-> BUILTIN Administrators``

    DA can reach DCSync transitively via Administrators, so DA's direct
    ``GenericWrite-> Domain`` edge is redundant noise — drop it. Same for
    EA's ``GenericAll`` edge. The kill chain becomes a single canonical
    path: ``Admin → MemberOf → DA → MemberOf → Administrators → DCSync →
    Domain``. If DA were NOT a member of Administrators (custom env), the
    direct ``GenericWrite`` would survive as the best DA can reach.

    Stepping-stone sources (graph_extension groups like Account Operators,
    EWP, Exchange Trusted Subsystem) are not touched — their lower-impact
    edges to Domain are the legitimate kill chain when no DCSync is
    reachable, and silencing them would break Forest-style multi-hop paths.

    Returns the number of edges removed.
    """
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, dict) or not isinstance(edges, list):
        return 0

    domain_ids = {
        nid
        for nid, node in nodes.items()
        if isinstance(node, dict) and str(node.get("kind") or "") == "Domain"
    }
    if not domain_ids:
        return 0

    # Map: group_id → set of direct parent group_ids (only Group → Group MemberOf).
    from collections import defaultdict

    group_parents: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "") != "MemberOf":
            continue
        src = str(edge.get("from") or "")
        dst = str(edge.get("to") or "")
        if not src or not dst:
            continue
        src_node = nodes.get(src)
        dst_node = nodes.get(dst)
        if not isinstance(src_node, dict) or not isinstance(dst_node, dict):
            continue
        if (
            str(src_node.get("kind") or "") == "Group"
            and str(dst_node.get("kind") or "") == "Group"
        ):
            group_parents[src].add(dst)

    def _ancestors(group_id: str) -> set[str]:
        seen: set[str] = set()
        stack = [group_id]
        while stack:
            current = stack.pop()
            for parent in group_parents.get(current, ()):
                if parent not in seen:
                    seen.add(parent)
                    stack.append(parent)
        return seen

    def _is_direct_compromise(node_id: str) -> bool:
        node = nodes.get(node_id)
        if not isinstance(node, dict):
            return False
        # Reuse the canonical classifier from attack_graph_service to stay in
        # sync with the rest of the path/filter pipeline.
        return attack_graph_service._node_is_direct_compromise_source(node)  # noqa: SLF001

    # Index direct edges to Domain per source: src_id → relation → list[edge].
    edges_to_domain: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("to") or "") not in domain_ids:
            continue
        src = str(edge.get("from") or "")
        rel = str(edge.get("relation") or "")
        if not src or not rel:
            continue
        edges_to_domain[src][rel].append(edge)

    def _best(rels: set[str]) -> str | None:
        candidates = [r for r in rels if r in _DOMAIN_COMPROMISE_RELATION_PRIORITY]
        if not candidates:
            return None
        return min(candidates, key=lambda r: _DOMAIN_COMPROMISE_RELATION_PRIORITY[r])

    edges_to_drop: list[dict[str, Any]] = []
    for src_id, rel_to_edges in list(edges_to_domain.items()):
        if not _is_direct_compromise(src_id):
            # Stepping stones (graph_extension etc.) keep all their edges.
            continue

        direct_rels = set(rel_to_edges.keys())
        transitive_rels: set[str] = set()
        for ancestor in _ancestors(src_id):
            if not _is_direct_compromise(ancestor):
                continue
            transitive_rels.update(edges_to_domain.get(ancestor, {}).keys())

        best = _best(direct_rels | transitive_rels)
        if best is None:
            continue

        for rel, edge_list in rel_to_edges.items():
            if rel not in _DOMAIN_COMPROMISE_RELATION_PRIORITY:
                continue
            if rel == best:
                continue
            edges_to_drop.extend(edge_list)

    if not edges_to_drop:
        return 0

    drop_ids = {id(e) for e in edges_to_drop}
    new_edges = [e for e in edges if id(e) not in drop_ids]
    removed = len(edges) - len(new_edges)
    graph["edges"] = new_edges
    return removed
