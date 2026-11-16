"""Base edges: collected relationships become graph edges.

ONE implementation for the 14.0.x persist and the graph build:
:func:`emit_base_edges` applies the skip rules (raw facts that are never path
steps), resolves both endpoints (a foreign target through the cross-domain
registry, as a light endpoint node keyed by the foreign graph id) and upserts
the edge through ``attack_graph_service.upsert_edge``, the edge-writing SSOT.
``_ensure_foreign_endpoint_node`` moved here from ``collector/persistence.py``
(body unchanged).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    ForeignNodeRef,
)
from adscan_internal.services.graph_build.edge_view import (
    InventorySpan,
    iter_stamped_edges,
)
from adscan_internal.services.graph_build.passes.adcs import _result_has_enterprise_ca
from adscan_internal.services.graph_build.passes.prunes import (
    _should_skip_attack_graph_edge,
    container_scope_concrete_pairs,
)

#: ``BaseEdgeOutcome.dropped`` keys: why a collected relationship produced no edge.
DROPPED_BY_SKIP_RULE = "skip_rule"
DROPPED_UNRESOLVED_SOURCE = "unresolved_source"
DROPPED_UNRESOLVED_TARGET = "unresolved_target"
DROPPED_REFUSED = "refused"
#: The source is a domain-takeover principal (``upsert_edge``'s Tier-0-source
#: refusal), rejected before the upsert. Counted apart from ``refused`` so the
#: dominant reason on a dense directory is named.
DROPPED_TIER0_SOURCE = "tier0_source"
#: Not a drop: the relationship was folded onto an edge with the same identity
#: (one session seen from two client addresses, one grant read twice). Counted
#: so a per-relation reconciliation of facts against edges has no unexplained
#: remainder.
MERGED_DUPLICATE = "merged_duplicate"

#: Separator of the per-relation keys (``"refused:AdminTo"``) that
#: :meth:`BaseEdgeOutcome.drop` writes beside each reason's total.
RELATION_KEY_SEPARATOR = ":"

#: Private key a base edge carries between :func:`emit_base_edges` and
#: :func:`apply_store_stamps`: ``(first_seen, last_seen)`` merged over the store
#: facts that map to it. The derivation passes that run in between upsert onto
#: base edges and refresh the clock fields, so the store's dates are applied
#: only once they are done. Never present in a finished graph.
STORE_STAMP_KEY = "_store_stamp"


@dataclass
class BaseEdgeOutcome:
    """What :func:`emit_base_edges` did."""

    persisted: int = 0
    dropped: dict[str, int] = field(default_factory=dict)
    #: Earliest and latest commit over every stored fact (a build from the
    #: store); empty for the 14.0.x persist, whose input carries no dates.
    span: InventorySpan = field(default_factory=InventorySpan)
    #: One shared ``(first, last)`` tuple per distinct pair. A store has a
    #: handful of commit dates, so every edge points at one of a few tuples
    #: instead of carrying its own copy of two date strings.
    stamp_pool: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)

    def drop(self, reason: str, relation: str = "") -> None:
        """Count one relationship that produced no new edge, by reason.

        With ``relation`` the count is also kept per relation under
        ``"<reason>:<relation>"``, so a reconciliation of one relation's facts
        against its edges (the host-sweep gate) can explain every difference.
        """
        self.dropped[reason] = self.dropped.get(reason, 0) + 1
        if relation:
            key = f"{reason}{RELATION_KEY_SEPARATOR}{relation}"
            self.dropped[key] = self.dropped.get(key, 0) + 1


def base_edge_endpoints(
    graph: dict[str, Any],
    edge: CollectorEdge,
    *,
    sid_to_graph_id: Mapping[str, str],
    foreign_sid_to_label: Mapping[str, ForeignNodeRef],
) -> tuple[str, str, bool] | None:
    """``(from_id, to_id, cross_domain)`` of one collected relationship, or ``None``.

    A source must be a collected object of this domain. A target that is not
    resolves through the cross-domain registry to the foreign node's graph id
    (creating its light endpoint node in ``graph``); unresolvable is ``None``.
    """
    from_id = sid_to_graph_id.get(edge.source_object_id.upper())
    if not from_id:
        return None
    to_id = sid_to_graph_id.get(edge.target_object_id.upper())
    if to_id:
        return from_id, to_id, False
    foreign = _ensure_foreign_endpoint_node(
        graph,
        edge.target_object_id,
        foreign_sid_to_label,  # type: ignore[arg-type]
    )
    if not foreign:
        return None
    return from_id, foreign, True


def base_edge_notes(edge: CollectorEdge, *, cross_domain: bool) -> dict[str, Any]:
    """The notes a collected relationship's edge is written with."""
    notes: dict[str, Any] = {"collector_method": edge.method, **edge.notes}
    if cross_domain:
        notes["cross_domain"] = True
    return notes


def emit_base_edges(
    graph: dict[str, Any],
    *,
    result: CollectionResult,
    sid_to_graph_id: Mapping[str, str],
    foreign_sid_to_label: Mapping[str, ForeignNodeRef] | None = None,
    edge_index: "attack_graph_service.EdgeUpsertIndex | None" = None,
) -> BaseEdgeOutcome:
    """Write every collected relationship of ``result`` that is a path step into ``graph``.

    From a build, ``result.edges`` is an ``EdgeView``: the loop is ONE stream of
    the store, which also stamps each edge with the dates of the facts that map
    to it (applied later by :func:`apply_store_stamps`) and accumulates the
    inventory span (``BaseEdgeOutcome.span``). The container-scope skip rule
    reads one precomputed set (one filtered scan), never a scan per edge.
    """
    # ``is None``, never ``or``: a lazily-resolving registry is empty until asked.
    if foreign_sid_to_label is None:
        foreign_sid_to_label = {}
    if edge_index is None:
        edge_index = attack_graph_service.EdgeUpsertIndex()
    has_enterprise_ca = _result_has_enterprise_ca(result)
    container_scope_pairs = container_scope_concrete_pairs(result)
    outcome = BaseEdgeOutcome()
    # Source graph id -> its direct-compromise verdict. Nodes are not changed
    # while base edges are emitted, so one verdict per source holds for the
    # whole loop (the verdict classifies the node's group memberships; computed
    # per edge it was the largest cost of this pass on a dense directory).
    direct_source_memo: dict[str, bool] = {}
    edges = graph.setdefault("edges", [])
    for stamped in iter_stamped_edges(result.edges, outcome.span):
        edge = stamped.edge
        relation = str(edge.relation or "")
        if _should_skip_attack_graph_edge(
            edge,
            result,
            has_enterprise_ca=has_enterprise_ca,
            container_scope_pairs=container_scope_pairs,
        ):
            outcome.drop(DROPPED_BY_SKIP_RULE, relation)
            continue
        if not sid_to_graph_id.get(edge.source_object_id.upper()):
            outcome.drop(DROPPED_UNRESOLVED_SOURCE, relation)
            continue
        endpoints = base_edge_endpoints(
            graph,
            edge,
            sid_to_graph_id=sid_to_graph_id,
            foreign_sid_to_label=foreign_sid_to_label,
        )
        if endpoints is None:
            outcome.drop(DROPPED_UNRESOLVED_TARGET, relation)  # out of scope, no foreign ref
            continue
        from_id, to_id, cross_domain = endpoints
        relation_norm = attack_graph_service._normalize_relation(edge.relation)  # noqa: SLF001
        if relation_norm and _is_tier0_source_edge(
            graph, from_id, to_id, relation_norm, direct_source_memo
        ):
            attack_graph_service._record_tier0_source_attack_edge_skip(  # noqa: SLF001
                graph, relation=relation_norm
            )
            outcome.drop(DROPPED_TIER0_SOURCE, relation)
            continue
        edges = graph.get("edges") if isinstance(graph.get("edges"), list) else edges
        before = len(edges)
        persisted = attack_graph_service.upsert_edge(
            graph,
            index=edge_index,
            from_id=from_id,
            to_id=to_id,
            relation=edge.relation,
            edge_type=f"native_{edge.source}",
            status="discovered",
            notes=base_edge_notes(edge, cross_domain=cross_domain),
            log_creation=False,
            tier0_source_checked=bool(relation_norm),
        )
        if persisted:
            outcome.persisted += 1
            if len(graph.get("edges") or ()) == before:
                outcome.drop(MERGED_DUPLICATE, relation)
            if stamped.last_seen is not None:
                _merge_store_stamp(
                    persisted, stamped.first_seen or "", stamped.last_seen, outcome.stamp_pool
                )
        else:
            outcome.drop(DROPPED_REFUSED, relation)
    return outcome


def _is_tier0_source_edge(
    graph: dict[str, Any],
    from_id: str,
    to_id: str,
    relation_norm: str,
    memo: dict[str, bool],
) -> bool:
    """``upsert_edge``'s Tier-0-source refusal, with the source verdict memoised."""
    return attack_graph_service._edge_has_tier0_source(  # noqa: SLF001
        graph, from_id=from_id, relation=relation_norm, to_id=to_id, source_verdicts=memo
    )


def _merge_store_stamp(
    edge: dict[str, Any],
    first: str,
    last: str,
    pool: dict[tuple[str, str], tuple[str, str]],
) -> None:
    """Earliest non-empty first date and latest last date over the facts of one edge."""
    previous = edge.get(STORE_STAMP_KEY)
    if previous is not None:
        firsts = [stamp for stamp in (previous[0], first) if stamp]
        first = min(firsts) if firsts else ""
        last = max(previous[1], last)
    pair = (first, last)
    edge[STORE_STAMP_KEY] = pool.setdefault(pair, pair)


def apply_store_stamps(graph: dict[str, Any], span: tuple[str, str]) -> None:
    """Give every edge its store dates, after the derivation passes.

    A base edge takes the dates :func:`emit_base_edges` merged from its facts;
    any other edge (derived) the inventory ``span``. ``discovered_at`` is the
    first date. The private carrier key is removed.
    """
    for edge in graph.get("edges") or ():
        if not isinstance(edge, dict):
            continue
        first, last = edge.pop(STORE_STAMP_KEY, None) or span
        edge["first_seen"] = first
        edge["last_seen"] = last
        edge["discovered_at"] = first


def _ensure_foreign_endpoint_node(
    graph: dict[str, Any],
    target_sid: str,
    foreign_sid_to_label: dict[str, ForeignNodeRef],
) -> str | None:
    """Resolve a foreign target SID to a graph id, creating a light endpoint node.

    When an edge's target SID belongs to another collected domain, the current
    graph has no node for it, so the edge would be dropped. If the cross-domain
    registry knows the SID, we create (idempotently) a light node in THIS graph
    keyed by the foreign node's canonical graph id — the SAME id the foreign
    domain's own graph uses — so the query-time merge collapses the two onto one
    node and the DFS crosses the domain boundary.

    Args:
        graph: The origin domain's attack graph being persisted.
        target_sid: The edge's (foreign) target object SID.
        foreign_sid_to_label: SID -> :class:`ForeignNodeRef` registry.

    Returns:
        The foreign node's graph id, or ``None`` when the SID is genuinely
        unresolvable (out of scope, no registry entry) — the edge stays dropped.
    """
    ref = foreign_sid_to_label.get(str(target_sid or "").upper())
    if ref is None or not ref.node_id:
        return None
    nodes = graph.setdefault("nodes", {})
    if not isinstance(nodes, dict):
        nodes = {}
        graph["nodes"] = nodes
    if ref.node_id not in nodes:
        # Light placeholder — the real foreign node (same graph id) overwrites it
        # when the graphs merge. ``cross_domain_endpoint`` marks it as a stand-in.
        nodes[ref.node_id] = {
            "kind": ref.kind,
            "label": ref.label,
            "name": ref.label,
            "objectId": str(target_sid or "").upper(),
            "highvalue": ref.is_tier0,
            "isTierZero": ref.is_tier0,
            "properties": {
                "name": ref.label,
                "objectid": str(target_sid or "").upper(),
                "cross_domain_endpoint": True,
            },
        }
    return ref.node_id
