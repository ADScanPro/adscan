"""Pre-DFS explosion predictor: count control mega-hubs in one edge pass.

The forward DFS explodes (2M-state cap, ~20s + ~10GB RSS) on an INTERIOR MESH of
several mega-hubs — nodes with thousands of same-relation control edges. This
predicts that shape cheaply, BEFORE the DFS runs, so hub-heavy graphs route to the
fallback engine without paying the abort cost. Measured: Potech = 18 mega-hubs;
the most extreme completing graph = 1. Threshold >=2. max_out_degree / edge:node
ratio alone are NOT safe (a single big fan-out completes) — the mesh signature is
the COUNT of mega-hubs, which is what this measures.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind


def _control_fanout_by_source_relation(
    graph: dict[str, Any],
) -> dict[tuple[str, str], int]:
    """Return the per-``(source_id, relation)`` control-edge count in ONE pass.

    This is the single definition of "control fan-out": for every CONTROL edge in
    the graph, tally how many same-relation control edges leave each source node.
    Both :func:`count_control_mega_hubs` (the routing decision) and
    :func:`top_control_hubs` (the human-facing breakdown) consume this map, so the
    two read the SAME numbers by construction — there is one edge walk and one
    definition, never two that can drift.

    Args:
        graph: The attack graph dict (``edges`` a list of ``{from, to, relation}``).

    Returns:
        A mapping ``(source_id, relation_lower) -> control_edge_count``. Relations
        are lower-cased so the same relation under different casing folds together.
    """
    per_source_rel: dict[tuple[str, str], int] = defaultdict(int)
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        rel = str(edge.get("relation") or "").strip()
        if not rel:
            continue
        if classify_edge_kind(rel) is not EdgeKind.CONTROL:
            continue
        src = str(edge.get("from") or "").strip()
        if not src:
            continue
        per_source_rel[(src, rel.lower())] += 1
    return per_source_rel


def count_control_mega_hubs(graph: dict[str, Any], *, min_out_degree: int = 500) -> int:
    """Return the number of nodes with > min_out_degree same-relation CONTROL edges."""
    per_source_rel = _control_fanout_by_source_relation(graph)
    hubs: set[str] = {
        src for (src, _rel), n in per_source_rel.items() if n > min_out_degree
    }
    return len(hubs)


def _node_label_map(graph: dict[str, Any]) -> dict[str, str]:
    """Map node id -> a human-friendly label for the top-hub breakdown.

    Nodes may be persisted as a dict keyed by id (the live ``attack_graph.json``
    shape) or as a plain list of node dicts (the shape the tests use). A node's
    label is ``label`` -> ``name`` -> its id, mirroring the resolution the attack
    step/path renderers already use. A node with no resolvable id is skipped.

    Args:
        graph: The attack graph dict.

    Returns:
        A mapping from node id to its display label.
    """
    labels: dict[str, str] = {}
    raw = graph.get("nodes")
    if isinstance(raw, dict):
        items: Any = raw.items()
    elif isinstance(raw, list):
        items = ((None, node) for node in raw)
    else:
        return labels
    for key, node in items:
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id") or key or "").strip()
        if not node_id:
            continue
        labels[node_id] = str(
            node.get("label") or node.get("name") or node_id
        ).strip() or node_id
    return labels


def top_control_hubs(
    graph: dict[str, Any], *, top_n: int = 5, min_out_degree: int = 1
) -> list[tuple[str, str, int]]:
    """Return the top-N ``(source_label, relation, edge_count)`` control fan-outs.

    Highest count first. Shares the single per-``(src, rel)`` control-edge pass
    with :func:`count_control_mega_hubs` (via
    :func:`_control_fanout_by_source_relation`) so the routing decision and the
    human breakdown read the SAME numbers by construction.

    Args:
        graph: The attack graph dict.
        top_n: How many hubs to return (highest fan-out first).
        min_out_degree: Only include a ``(source, relation)`` whose control-edge
            count strictly exceeds this floor. Defaults to 1 (any real fan-out).

    Returns:
        A list of ``(source_label, relation, edge_count)`` tuples, longest
        fan-out first, capped at ``top_n``. The relation is returned lower-cased
        (as counted). Ties break on the source label then the relation for a
        stable ordering.
    """
    per_source_rel = _control_fanout_by_source_relation(graph)
    labels = _node_label_map(graph)
    ranked = sorted(
        (
            (labels.get(src, src), rel, count)
            for (src, rel), count in per_source_rel.items()
            if count > min_out_degree
        ),
        key=lambda row: (-row[2], row[0], row[1]),
    )
    return ranked[: max(0, top_n)]


def predicts_explosion(
    graph: dict[str, Any], *, hub_threshold: int = 2, min_out_degree: int = 500
) -> bool:
    """Return True when the graph has >= hub_threshold control mega-hubs (mesh signature)."""
    return (
        count_control_mega_hubs(graph, min_out_degree=min_out_degree) >= hub_threshold
    )
