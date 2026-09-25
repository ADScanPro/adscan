"""Pre-DFS explosion predictor: count control mega-hubs in one edge pass.

The forward DFS explodes (2M-state cap, ~20s + ~10GB RSS) on an INTERIOR MESH of
several mega-hubs — nodes with thousands of same-relation control edges. This
predicts that shape cheaply, BEFORE the DFS runs, so hub-heavy graphs route to the
fallback engine without paying the abort cost. Measured: Contoso = 18 mega-hubs;
the most extreme completing graph = 1. Threshold >=2. max_out_degree / edge:node
ratio alone are NOT safe (a single big fan-out completes) — the mesh signature is
the COUNT of mega-hubs, which is what this measures.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from adscan_internal.services.compromise_class import node_is_tier0_by_stamped_label
from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind

# Edge kinds a forward walk may traverse to decide whether an owned/start
# principal can ARRIVE at a control mega-hub: membership stitches a principal
# into the groups that own the hub, control/escalation edges carry it across
# object-control and privileged-group escalations. Auth (session) and trust
# edges are intentionally excluded — reaching a hub means acquiring the rights
# that let the DFS fan out through it, which is exactly this set.
_REACHABILITY_EDGE_KINDS: frozenset[EdgeKind] = frozenset(
    {EdgeKind.CONTROL, EdgeKind.MEMBERSHIP, EdgeKind.ESCALATION}
)


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


def _control_mega_hub_ids(graph: dict[str, Any], *, min_out_degree: int = 500) -> set[str]:
    """Return the set of node ids that are control mega-hubs.

    A control mega-hub is a source node with more than ``min_out_degree``
    same-relation CONTROL edges. This is the SINGLE definition of the mega-hub
    criterion — both :func:`count_control_mega_hubs` (the raw count) and
    :func:`predicts_explosion_reachable` (the reachability-filtered count) consume
    it, so the two can never drift on what counts as a hub.

    Args:
        graph: The attack graph dict.
        min_out_degree: The strict fan-out floor a ``(source, relation)`` must
            exceed to make its source a mega-hub.

    Returns:
        The set of mega-hub source-node ids.
    """
    per_source_rel = _control_fanout_by_source_relation(graph)
    return {src for (src, _rel), n in per_source_rel.items() if n > min_out_degree}


def count_control_mega_hubs(graph: dict[str, Any], *, min_out_degree: int = 500) -> int:
    """Return the number of nodes with > min_out_degree same-relation CONTROL edges."""
    return len(_control_mega_hub_ids(graph, min_out_degree=min_out_degree))


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


def _node_by_id_map(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map node id -> its node dict, tolerating both persisted node shapes.

    Nodes may be a dict keyed by id (the live ``attack_graph.json`` shape) or a
    plain list of node dicts (the shape the tests use). Mirrors the shape handling
    of :func:`_node_label_map`. Used to resolve a mega-hub id back to its node so a
    caller can read its STAMPED ``privilege_tier`` (Tier-0 frontier detection).

    Args:
        graph: The attack graph dict.

    Returns:
        A mapping from node id to the node dict.
    """
    by_id: dict[str, dict[str, Any]] = {}
    raw = graph.get("nodes")
    if isinstance(raw, dict):
        items: Any = raw.items()
    elif isinstance(raw, list):
        items = ((None, node) for node in raw)
    else:
        return by_id
    for key, node in items:
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id") or key or "").strip()
        if not node_id:
            continue
        by_id[node_id] = node
    return by_id


def _non_tier0_frontier_hub_ids(
    graph: dict[str, Any], hub_ids: set[str]
) -> set[str]:
    """Filter ``hub_ids`` to those that are NOT Tier-0 frontier stops.

    The DFS is two-phase with a Tier-0 frontier stop: Phase 1 (Tier-2 -> Tier-0,
    all-paths, combinatorial) frontier-STOPS at the first Tier-0 node, so a Tier-0
    control mega-hub is a TERMINAL, not a traversed node — paths END there, they do
    NOT multiply through it, so it cannot cause the combinatorial explosion. Only a
    NON-Tier-0 control mega-hub (traversed mid-path on a Tier-2 -> Tier-0 route) is a
    real explosion source. A hub whose stamped ``privilege_tier`` places it in Tier 0
    (via :func:`node_is_tier0_by_stamped_label`) is therefore excluded from the
    routing count.

    Args:
        graph: The attack graph dict.
        hub_ids: The mega-hub source-node ids to filter.

    Returns:
        The subset of ``hub_ids`` whose node is NOT a Tier-0 frontier stop (a node
        with no resolvable stamp is conservatively kept — it is not proven Tier-0).
    """
    if not hub_ids:
        return set()
    by_id = _node_by_id_map(graph)
    return {
        hub for hub in hub_ids if not node_is_tier0_by_stamped_label(by_id.get(hub))
    }


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


def _reachable_node_ids(
    graph: dict[str, Any], start_node_ids: set[str]
) -> set[str]:
    """Return every node id reachable from ``start_node_ids`` in ONE forward walk.

    Traverses only edges whose :class:`EdgeKind` is in
    :data:`_REACHABILITY_EDGE_KINDS` (control / membership / escalation) — the
    edges that let an owned principal actually ACQUIRE the rights to arrive at a
    control mega-hub. The start nodes are themselves reachable (a hub that IS an
    owned principal counts). Cheap: one adjacency build over the already-loaded
    edge list plus a BFS.

    Args:
        graph: The attack graph dict.
        start_node_ids: The owned / start principal node ids to walk from.

    Returns:
        The set of reachable node ids (including the start set).
    """
    if not start_node_ids:
        return set()

    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if classify_edge_kind(edge.get("relation")) not in _REACHABILITY_EDGE_KINDS:
            continue
        src = str(edge.get("from") or "").strip()
        dst = str(edge.get("to") or "").strip()
        if not src or not dst:
            continue
        adjacency[src].append(dst)

    reachable: set[str] = set(start_node_ids)
    queue: deque[str] = deque(start_node_ids)
    while queue:
        current = queue.popleft()
        for neighbour in adjacency.get(current, ()):
            if neighbour not in reachable:
                reachable.add(neighbour)
                queue.append(neighbour)
    return reachable


def predicts_explosion_reachable(
    graph: dict[str, Any],
    *,
    start_node_ids: set[str] | None = None,
    hub_threshold: int = 2,
    min_out_degree: int = 500,
) -> bool:
    """Return True when >= ``hub_threshold`` control mega-hubs are REACHABLE.

    The reachability-aware refinement of :func:`predicts_explosion`. It counts a
    control mega-hub (same criterion as :func:`count_control_mega_hubs`) ONLY when
    both of the following hold:

    * the hub is NOT a Tier-0 frontier stop — the DFS is two-phase and
      frontier-STOPS at the first Tier-0 node, so a Tier-0 control mega-hub is a
      TERMINAL that paths end at, never a node paths multiply THROUGH; it cannot
      drive the combinatorial explosion (see :func:`_non_tier0_frontier_hub_ids`).
      Only a NON-Tier-0 hub, traversed mid-path on a Tier-2 -> Tier-0 route, is a
      real explosion source; and
    * an owned / start principal in ``start_node_ids`` can actually reach that hub
      via a forward walk over control / membership / escalation edges.

    Together these remove the raw structural predictor's false positives on
    mega-hubs no Tier-2 -> Tier-0 route multiplies through: a hub no path traverses
    (an Account-Operators group with zero members) OR a hub that is a Tier-0
    frontier stop (a frontier-stopped Exchange / Domain-Admins mesh). Routing such
    a domain to the bounded fallback engine loses coverage the full DFS would have
    completed.

    Args:
        graph: The attack graph dict.
        start_node_ids: The owned / start principal node ids. When ``None`` the
            caller has no start context, so this falls back to the raw structural
            :func:`count_control_mega_hubs` count — byte-identical to callers that
            never supplied a start set. An explicit EMPTY set means "no owned
            principals": nothing is reachable, so the predicate never fires.
        hub_threshold: How many reachable, non-Tier-0 mega-hubs trigger the
            prediction.
        min_out_degree: The strict same-relation control fan-out floor for a hub.

    Returns:
        True when the count of mega-hubs that are BOTH reachable AND not Tier-0
        frontier stops is at least ``hub_threshold`` (or, when
        ``start_node_ids is None``, the raw mega-hub count is).
    """
    hub_ids = _control_mega_hub_ids(graph, min_out_degree=min_out_degree)
    if not hub_ids:
        return False
    if start_node_ids is None:
        return len(hub_ids) >= hub_threshold
    # A Tier-0 mega-hub is a Phase-1 frontier STOP (a terminal), not a traversed
    # node — paths end there, they do not multiply through it — so exclude it from
    # the routing count. Only a NON-Tier-0 hub is a real explosion source.
    explosion_hub_ids = _non_tier0_frontier_hub_ids(graph, hub_ids)
    if not explosion_hub_ids:
        return False
    reachable = _reachable_node_ids(graph, start_node_ids)
    reachable_hub_count = sum(1 for hub in explosion_hub_ids if hub in reachable)
    return reachable_hub_count >= hub_threshold
