"""Cross-domain trust escalation edges: ``CrossOrgTgtDelegation`` and ``RaiseChild``.

In 14.0.x the collector re-persisted every domain once all were collected
(``orchestrator._persist_cross_domain_edges`` →
``attack_graph_service.persist_cross_domain_trust_edges``) so these edges, then
minted only in memory at load time, reached the file and their execution status
survived a reload. With the build they are derived like every other edge, from
the recorded trusts (``context.domains_data``) and the partner domains' own
stores (``context.sibling_stores``), whatever order the domains were collected
in, and in every build.

Same rules as 14.0.x, through the same single implementations
(``attack_graph_core.couple_cross_org_tgt_delegation_edges`` and
``couple_raise_child_edges``). A coupling needs BOTH Domain nodes; a partner
Domain whose node lives in another domain's graph is added as the same light
cross-domain Domain payload the 14.0.x re-persist added (one per collected
partner domain, keyed by its own graph id, so the query-time merge collapses
it onto the real node).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from adscan_core.graph_store import GraphStore

#: Relations this pass writes.
TRUST_RELATIONS = ("CrossOrgTgtDelegation", "RaiseChild")


def partner_domain_nodes(sibling_stores: Mapping[str, GraphStore]) -> dict[str, dict[str, Any]]:
    """Graph id -> light Domain payload for every partner domain's Domain object."""
    from adscan_internal.services.graph_build.inputs import foreign_ref_from_record  # noqa: PLC0415

    out: dict[str, dict[str, Any]] = {}
    for name in sorted(sibling_stores):
        for record in sibling_stores[name].iter_objects(kinds=("Domain",)):
            ref = foreign_ref_from_record(record)
            sid = str(record.object_id or "").upper()
            if not ref.node_id or ref.node_id in out:
                continue
            out[ref.node_id] = {
                "kind": "Domain",
                "label": ref.label,
                "name": ref.label,
                "objectId": sid,
                "highvalue": True,
                "isTierZero": True,
                "properties": {
                    "name": ref.label,
                    "objectid": sid,
                    "cross_domain_endpoint": True,
                },
            }
    return out


def derive_trust_edges(
    graph: dict[str, Any],
    *,
    domains_data: Mapping[str, Any],
    sibling_stores: Mapping[str, GraphStore],
) -> int:
    """Couple the trust escalation edges into ``graph``. Returns how many edges it added."""
    from adscan_internal.services import attack_graph_core  # noqa: PLC0415

    if not sibling_stores:
        return 0
    nodes = graph.setdefault("nodes", {})
    for node_id, payload in partner_domain_nodes(sibling_stores).items():
        if node_id not in nodes:
            nodes[node_id] = payload
    before = len(graph.get("edges") or ())
    attack_graph_core.couple_cross_org_tgt_delegation_edges(graph, domains_data)
    attack_graph_core.couple_raise_child_edges(graph, domains_data)
    return max(0, len(graph.get("edges") or ()) - before)


__all__ = ("TRUST_RELATIONS", "derive_trust_edges", "partner_domain_nodes")
