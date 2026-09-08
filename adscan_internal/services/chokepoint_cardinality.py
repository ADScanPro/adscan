"""Choke-point cardinality over the reachable set (set algebra, no enumeration).

When a dense directory graph is routed to the bounded fallback engine, the route
sample is capped, so the client needs a prioritization signal that does NOT
depend on enumerating every route: "which single edge, if removed, severs the
most source -> value-terminal reach?". This is the BloodHound-Enterprise
choke-point idea expressed as *set cardinality over reachability*, which is cheap
because it is set algebra and never touches path enumeration.

This module produces the cardinality DATA only. It performs no scoring, no
ranking, and no rendering (those belong to a later render task, E3). It also
provides a best-effort persistence helper that stamps a compact summary into the
technical report the same way the exposure KPIs are stamped, so a future render
can read it.

Design notes:
    * Works on the PERSISTED graph (``attack_graph.json``), not the DFS-visible
      frontier. It deliberately does NOT reuse
      :func:`attack_graph_core._build_reverse_reachable_node_ids`, which needs
      local-reuse / frontier arguments this module does not have. Instead it
      builds a self-contained forward/reverse adjacency and runs plain BFS.
    * ``Reach^-1(S)`` = every node that can reach some terminal in ``S`` by
      following edges forward toward ``S`` (equivalently, reachable backward from
      ``S`` over the reversed adjacency).
    * Two choke views, both exact set-cardinality (no path enumeration):
        - EDGE choke (:func:`compute_chokepoint_cardinality`): for each edge, how
          many *sources* (leaf originators — reachable nodes with no inbound reach
          edge) have EVERY path to ``S`` traversing it, so cutting that one edge
          severs all of them.
        - NODE choke (:func:`compute_node_chokepoint_cardinality`): for each node,
          how many *source principals* (enabled User/Computer/Group nodes that
          reach ``S``) lose all reach when that node is removed, via a dominator
          tree.
    * On a dense directory graph the EDGE list is usually empty — path redundancy
      means no single edge is a bottleneck — while the NODE choke carries the
      large cardinalities (a mega-hub group / well-known SID). Reporting both lets
      the render (E3) prioritise the strongest choke of either kind. The edge view
      is the exact one the H3 brief's bridge test pins; the node view is the one
      that lights up at Potech scale.

Complexity:
    The computation is driven per SOURCE, which is what keeps it cheap on a
    directory graph: the number of leaf originators is tiny (single/low digits
    even at Potech scale, where ~34k nodes / ~276k edges yield only ~11 sources
    and a ~4.8k-node terminal-reachable set). For each source we forward-flood
    the reachable subgraph once (``O(E_r)`` over the ``E_r`` reachable edges) to
    learn the small set of edges it can reach, then test each such edge's
    criticality with a scoped forward BFS that skips it (a terminal is
    unreachable afterwards iff the edge was on ALL of that source's paths to
    ``S``). This is ``O(sources * reachable_edges * E_r)`` worst case but in
    practice low-seconds at Potech, versus ~100s for the naive "remove each of
    ~50k whole-graph candidate edges and re-flood" approach. It is exact:
    validated against the brute-force reflood oracle over thousands of random
    cyclic graphs.
"""

from __future__ import annotations

from typing import Any

# Node kinds that can plausibly originate an attack (an enabled principal).
_PRINCIPAL_KINDS: frozenset[str] = frozenset({"User", "Computer", "Group"})


def _iter_nodes(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Normalize ``graph["nodes"]`` into an ``id -> node`` mapping.

    Nodes may be persisted either as a dict keyed by node id (the live
    ``attack_graph.json`` shape) or as a plain list of node dicts (the shape the
    brief's tests use). Both normalize to the same mapping.

    Args:
        graph: The attack graph dict.

    Returns:
        A mapping from node id to the node dict. Nodes without a resolvable id
        are dropped.
    """
    raw = graph.get("nodes")
    result: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        for key, node in raw.items():
            if not isinstance(node, dict):
                continue
            node_id = str(node.get("id") or key or "").strip()
            if node_id:
                result[node_id] = node
    elif isinstance(raw, list):
        for node in raw:
            if not isinstance(node, dict):
                continue
            node_id = str(node.get("id") or "").strip()
            if node_id:
                result[node_id] = node
    return result


def _build_reverse_adjacency(
    graph: dict[str, Any],
) -> dict[str, set[str]]:
    """Build the reverse adjacency ``to -> {from, ...}`` from the graph edges.

    Each edge dict carries ``from``/``to`` (and a ``relation`` used only for the
    stable edge key). A reverse edge ``to -> from`` is what a reverse BFS from a
    terminal follows to discover every node that can reach that terminal.

    Args:
        graph: The attack graph dict.

    Returns:
        A mapping from a node id to the set of node ids that have an edge INTO
        it.
    """
    reverse: dict[str, set[str]] = {}
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return reverse
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if not from_id or not to_id:
            continue
        reverse.setdefault(to_id, set()).add(from_id)
    return reverse


def _reverse_reach(
    reverse: dict[str, set[str]],
    seeds: set[str],
    *,
    excluded_edge: tuple[str, str] | None = None,
) -> set[str]:
    """Return every node that can reach ``seeds`` over the reverse adjacency.

    A plain BFS backward from every seed. When ``excluded_edge`` is supplied the
    corresponding reverse hop ``v -> u`` (i.e. the forward edge ``u -> v``) is
    skipped, which yields ``Reach^-1(S)`` with that single edge removed without
    mutating the adjacency.

    Args:
        reverse: The reverse adjacency ``to -> {from, ...}``.
        seeds: The value-terminal node ids to flood back from.
        excluded_edge: An optional ``(u, v)`` forward edge to treat as removed.

    Returns:
        The set of node ids that can reach some seed (the seeds are included).
    """
    reachable: set[str] = set(seeds)
    pending = list(seeds)
    while pending:
        current = pending.pop()
        for predecessor in reverse.get(current, ()):
            if excluded_edge is not None and (predecessor, current) == excluded_edge:
                continue
            if predecessor in reachable:
                continue
            reachable.add(predecessor)
            pending.append(predecessor)
    return reachable


def _node_is_disabled(node: dict[str, Any]) -> bool:
    """Return ``True`` only when the node is EXPLICITLY marked disabled.

    The persisted graph records the ``enabled`` flag under ``properties`` (the
    top-level ``enabled`` is usually ``None``). Only an explicit ``False`` (at
    either location) counts as disabled; a missing flag is treated as enabled so
    the predicate stays permissive, which is what the brief asks for.

    Args:
        node: The node dict.

    Returns:
        ``True`` if the node is explicitly disabled, else ``False``.
    """
    if node.get("enabled") is False:
        return True
    props = node.get("properties")
    if isinstance(props, dict) and props.get("enabled") is False:
        return True
    return False


def _node_is_enabled_principal(node: dict[str, Any]) -> bool:
    """Return ``True`` if the node is a plausible, non-disabled attack source.

    An enabled principal is a node whose ``kind`` is a user / computer / group
    principal and that is not explicitly disabled. The predicate is deliberately
    permissive: the brief's ``exposure_source_count`` test only needs ``>= 1``,
    and over-counting a container as a principal is harmless here because the
    reverse-reachable set already bounds the count to nodes that actually reach a
    value terminal.

    Args:
        node: The node dict.

    Returns:
        ``True`` for an enabled principal node.
    """
    kind = str(node.get("kind") or "").strip()
    if kind not in _PRINCIPAL_KINDS:
        return False
    return not _node_is_disabled(node)


def exposure_source_count(graph: dict[str, Any], *, value_terminals: set[str]) -> int:
    """Count enabled principals that can reach the value-terminal set.

    This is ``|Reach^-1(S) intersect enabled-principals|`` — the complete-exposure
    anchor: how many principals in the directory have SOME route to the crown
    jewels, independent of how many individual routes exist. It is the number the
    bounded engine can report honestly even when the route sample is capped,
    because it is a set cardinality, not a path count.

    The value-terminal set itself is excluded from the source count (a crown
    jewel is not one of its own attackers).

    Args:
        graph: The attack graph dict (``nodes`` dict-or-list, ``edges`` list).
        value_terminals: The value-terminal (crown-jewel) node ids.

    Returns:
        The number of enabled principal nodes that can reach ``value_terminals``.
    """
    terminals = {str(t) for t in value_terminals if str(t)}
    if not terminals:
        return 0
    nodes = _iter_nodes(graph)
    reverse = _build_reverse_adjacency(graph)
    reachable = _reverse_reach(reverse, terminals)
    count = 0
    for node_id in reachable:
        if node_id in terminals:
            continue
        node = nodes.get(node_id)
        if isinstance(node, dict) and _node_is_enabled_principal(node):
            count += 1
    return count


def edge_key(from_id: str, relation: str, to_id: str) -> str:
    """Build the stable string key for an edge.

    Args:
        from_id: The edge source node id.
        relation: The edge relation label.
        to_id: The edge target node id.

    Returns:
        A ``"{from}|{relation}|{to}"`` key.
    """
    return f"{from_id}|{relation}|{to_id}"


def _build_forward_adjacency(graph: dict[str, Any]) -> dict[str, set[str]]:
    """Build the forward adjacency ``from -> {to, ...}`` from the graph edges.

    Args:
        graph: The attack graph dict.

    Returns:
        A mapping from a node id to the set of node ids it has an edge INTO.
    """
    forward: dict[str, set[str]] = {}
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return forward
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if not from_id or not to_id:
            continue
        forward.setdefault(from_id, set()).add(to_id)
    return forward


def _source_still_reaches_terminals(
    source: str,
    forward: dict[str, set[str]],
    reach: set[str],
    terminals: set[str],
    *,
    excluded_edge: tuple[str, str] | None,
) -> bool:
    """Return ``True`` if ``source`` still reaches any terminal with ``e`` cut.

    A forward BFS from ``source`` restricted to the reachable subgraph
    (``reach``), skipping the single ``excluded_edge`` if given. Restricting the
    walk to ``reach`` keeps each BFS cheap because it never wanders into nodes
    that cannot lead to a terminal anyway.

    Args:
        source: The source node id to flood forward from.
        forward: The forward adjacency ``from -> {to, ...}``.
        reach: The set of nodes that can reach the terminal set.
        terminals: The value-terminal node ids.
        excluded_edge: An optional ``(u, v)`` edge to treat as removed.

    Returns:
        ``True`` if a terminal is still reachable from ``source``.
    """
    if source in terminals:
        return True
    seen: set[str] = {source}
    pending = [source]
    while pending:
        current = pending.pop()
        for nxt in forward.get(current, ()):
            if excluded_edge is not None and (current, nxt) == excluded_edge:
                continue
            if nxt not in reach or nxt in seen:
                continue
            if nxt in terminals:
                return True
            seen.add(nxt)
            pending.append(nxt)
    return False


def compute_chokepoint_cardinality(
    graph: dict[str, Any], *, value_terminals: set[str]
) -> dict[str, int]:
    """Return per-edge choke-point cardinality via per-source set algebra.

    The cardinality of edge ``e = (u, v)`` (oriented toward the value-terminal set
    ``S``) is the number of *sources* — leaf originators, i.e. reachable nodes
    with no inbound reach edge — whose EVERY path to ``S`` traverses ``e``, so
    cutting that single edge severs all of them. This is the set reading of
    ``|Reach^-1(S)| - |Reach^-1(S) with e removed|`` restricted to source nodes.

    It is computed source-by-source, which is what makes it cheap on a directory
    graph: the number of leaf originators is tiny (single/low digits even at
    Potech scale ~34k nodes / ~276k edges, where there are ~11 sources), while
    the terminal-reachable set is only a few thousand nodes. For each source we
    forward-flood the reachable subgraph once to learn the small set of edges it
    can reach, then test each such edge's criticality with a scoped forward BFS
    that skips it — a terminal is unreachable afterwards iff the edge was on ALL
    of that source's paths to ``S``. Each critical edge accrues +1 per source it
    severs. This is exact (validated against the brute-force reflood oracle over
    thousands of random cyclic graphs) and avoids the ``O(all_candidate_edges *
    E)`` cost of the naive whole-graph reflood, which was ~100s at Potech.

    Counting SOURCES (not every reachable node) is what the bridge test expects:
    three low-priv sources funnelling through one bridge edge returns a
    cardinality of 3 — the intermediary bridge node is a relay, not a fourth
    source of itself.

    Args:
        graph: The attack graph dict (``nodes`` dict-or-list, ``edges`` list).
        value_terminals: The value-terminal (crown-jewel) node ids.

    Returns:
        A mapping from a stable edge key (``"{from}|{relation}|{to}"``) to its
        choke-point cardinality (>= 1). Non-choke edges are omitted. Returns an
        empty dict when there are no terminals, edges, or sources.
    """
    terminals = {str(t) for t in value_terminals if str(t)}
    edges = graph.get("edges")
    if not terminals or not isinstance(edges, list):
        return {}

    reverse = _build_reverse_adjacency(graph)
    reach = _reverse_reach(reverse, terminals)

    # Sources = leaf originators: reachable nodes with no inbound reach edge.
    sources = {
        node_id
        for node_id in reach
        if node_id not in terminals and not (reverse.get(node_id, set()) & reach)
    }
    if not sources:
        return {}

    forward = _build_forward_adjacency(graph)

    # Relation lookup so the omitted-cardinality edges never cost a graph scan.
    relation_by_pair: dict[tuple[str, str], str] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if not from_id or not to_id:
            continue
        # Keep the first-seen relation for a parallel-edge pair (stable key).
        relation_by_pair.setdefault(
            (from_id, to_id), str(edge.get("relation") or "").strip()
        )

    result: dict[str, int] = {}
    for source in sources:
        # The edges this source could ever traverse toward S: its forward-reach
        # within the terminal-reachable subgraph. Only these can be critical.
        forward_reach: set[str] = {source}
        pending = [source]
        while pending:
            current = pending.pop()
            for nxt in forward.get(current, ()):
                if nxt in reach and nxt not in forward_reach:
                    forward_reach.add(nxt)
                    pending.append(nxt)

        for u in forward_reach:
            for v in forward.get(u, ()):
                if v not in reach:
                    continue
                if _source_still_reaches_terminals(
                    source, forward, reach, terminals, excluded_edge=(u, v)
                ):
                    continue
                relation = relation_by_pair.get((u, v), "")
                key = edge_key(u, relation, v)
                result[key] = result.get(key, 0) + 1
    return result


_DOM_ROOT = "__chokepoint_dom_root__"


def _compute_immediate_dominators(
    succ: dict[str, set[str]],
    pred: dict[str, set[str]],
    root: str,
) -> dict[str, str]:
    """Compute the immediate-dominator map of a flowgraph rooted at ``root``.

    Iterative Cooper-Harvey-Kennedy ("A Simple, Fast Dominance Algorithm"). The
    graph is oriented in flow direction (``succ`` = flow-forward adjacency,
    ``pred`` its transpose). Every node must be reachable from ``root`` — the
    caller guarantees this by joining a virtual root to every terminal and
    building ``succ``/``pred`` over the reachable subgraph only.

    Args:
        succ: Flow-forward adjacency ``node -> {successor, ...}``.
        pred: Flow-backward adjacency ``node -> {predecessor, ...}`` (transpose).
        root: The single entry node all others are reachable from.

    Returns:
        ``idom`` mapping ``node -> immediate dominator``. ``root`` is omitted.
    """
    order: list[str] = []
    visited: set[str] = {root}
    stack: list[tuple[str, bool]] = [(root, False)]
    while stack:
        node, processed = stack.pop()
        if processed:
            order.append(node)
            continue
        stack.append((node, True))
        for nxt in succ.get(node, ()):
            if nxt not in visited:
                visited.add(nxt)
                stack.append((nxt, False))
    order.reverse()  # reverse postorder
    rpo_index = {node: i for i, node in enumerate(order)}

    idom: dict[str, str] = {root: root}

    def _intersect(a: str, b: str) -> str:
        while a != b:
            while rpo_index[a] > rpo_index[b]:
                a = idom[a]
            while rpo_index[b] > rpo_index[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for node in order:
            if node == root:
                continue
            new_idom: str | None = None
            for p in pred.get(node, ()):
                if p not in rpo_index or p not in idom:
                    continue
                new_idom = p if new_idom is None else _intersect(p, new_idom)
            if new_idom is not None and idom.get(node) != new_idom:
                idom[node] = new_idom
                changed = True

    idom.pop(root, None)
    return idom


def compute_node_chokepoint_cardinality(
    graph: dict[str, Any], *, value_terminals: set[str]
) -> dict[str, int]:
    """Return per-NODE choke-point cardinality via a dominator tree (set algebra).

    The cardinality of a node ``n`` is the number of *source principals* — enabled
    User / Computer / Group nodes that can reach the value-terminal set ``S`` —
    that lose ALL reach to ``S`` when ``n`` is removed, i.e. every one of their
    paths to ``S`` passes through ``n``. On a dense directory graph the strongest
    choke is almost always a NODE (a mega-hub group like Account Operators / a
    well-known SID) rather than a single edge, because path redundancy means no
    single edge is a bottleneck while a hub still is — which is why this
    node-level signal, not :func:`compute_chokepoint_cardinality`, carries the
    large cardinalities at scale.

    Computed WITHOUT re-flooding per node: one dominator tree over the reachable
    subgraph (rooted at a virtual root joined to every terminal). A node ``d``
    *dominates* node ``m`` when every path from ``m`` to ``S`` passes through
    ``d``; the number of source principals in ``n``'s dominator subtree is exactly
    how many are severed by removing ``n``. Near-linear in practice. Exact:
    validated against the brute-force node-removal oracle over thousands of random
    cyclic graphs.

    Args:
        graph: The attack graph dict (``nodes`` dict-or-list, ``edges`` list).
        value_terminals: The value-terminal (crown-jewel) node ids.

    Returns:
        A mapping from a node id to its choke-point cardinality (>= 1). Nodes that
        sever no source are omitted. Returns an empty dict when there are no
        terminals, edges, or source principals.
    """
    terminals = {str(t) for t in value_terminals if str(t)}
    edges = graph.get("edges")
    if not terminals or not isinstance(edges, list):
        return {}

    nodes = _iter_nodes(graph)
    reverse = _build_reverse_adjacency(graph)
    reach = _reverse_reach(reverse, terminals)

    sources = {
        node_id
        for node_id in reach
        if node_id not in terminals
        and isinstance(nodes.get(node_id), dict)
        and _node_is_enabled_principal(nodes[node_id])
    }
    if not sources:
        return {}

    # Dominator flow graph rooted at S: flow runs FROM the virtual root (joined
    # to every terminal) BACKWARD along the graph edges toward the sources, so a
    # node's dominator subtree is exactly the set of nodes whose every path to S
    # passes through it. ``succ`` is the reverse adjacency, ``pred`` its transpose.
    succ: dict[str, set[str]] = {_DOM_ROOT: set(terminals)}
    pred: dict[str, set[str]] = {}
    for terminal in terminals:
        pred.setdefault(terminal, set()).add(_DOM_ROOT)
    for to_id, froms in reverse.items():
        if to_id not in reach:
            continue
        for from_id in froms:
            if from_id not in reach:
                continue
            succ.setdefault(to_id, set()).add(from_id)
            pred.setdefault(from_id, set()).add(to_id)

    idom = _compute_immediate_dominators(succ, pred, _DOM_ROOT)

    # For each source, every strict dominator on its idom chain (excluding the
    # source itself and the terminals) severs it when removed.
    result: dict[str, int] = {}
    for source in sources:
        node = source
        seen: set[str] = set()
        while node in idom and node not in seen:
            seen.add(node)
            node = idom[node]
            if node in reach and node not in terminals:
                result[node] = result.get(node, 0) + 1
    return {node_id: count for node_id, count in result.items() if count > 0}


def build_chokepoint_summary(
    graph: dict[str, Any],
    *,
    value_terminals: set[str],
    top_k: int = 20,
) -> dict[str, Any]:
    """Build the compact, JSON-safe choke-point summary for persistence.

    Runs the edge choke, the node choke and the exposure-source anchor, returning
    the top-``K`` of each. The shape is deliberately small (only the top entries,
    not the full per-edge / per-node maps) so it is cheap to stamp into the report
    and read back for a later render (E3).

    On a dense directory graph the edge list is usually empty (path redundancy
    means no single edge is a bottleneck) while the node list carries the large
    cardinalities (a mega-hub group / well-known SID). Both are reported so E3 can
    prioritise the strongest choke of either kind.

    Args:
        graph: The attack graph dict.
        value_terminals: The value-terminal node ids.
        top_k: How many top choke points of each kind to keep.

    Returns:
        A JSON-safe dict with ``schema_version``, ``exposure_source_count``,
        ``value_terminal_count``, ``edge_candidate_count``, ``node_candidate_count``,
        a ``top_chokepoints`` list of ``{"edge_key", "cardinality"}`` entries and a
        ``top_node_chokepoints`` list of ``{"node_id", "cardinality"}`` entries,
        each in descending order.
    """
    terminals = {str(t) for t in value_terminals if str(t)}
    keep = max(0, int(top_k))

    edge_cardinality = compute_chokepoint_cardinality(graph, value_terminals=terminals)
    edge_ranked = sorted(edge_cardinality.items(), key=lambda kv: (-kv[1], kv[0]))
    top_edges = [
        {"edge_key": key, "cardinality": int(count)}
        for key, count in edge_ranked[:keep]
    ]

    node_cardinality = compute_node_chokepoint_cardinality(
        graph, value_terminals=terminals
    )
    node_ranked = sorted(node_cardinality.items(), key=lambda kv: (-kv[1], kv[0]))
    top_nodes = [
        {"node_id": node_id, "cardinality": int(count)}
        for node_id, count in node_ranked[:keep]
    ]

    return {
        "schema_version": 1,
        "exposure_source_count": exposure_source_count(
            graph, value_terminals=terminals
        ),
        "value_terminal_count": len(terminals),
        "edge_candidate_count": len(edge_cardinality),
        "node_candidate_count": len(node_cardinality),
        "top_chokepoints": top_edges,
        "top_node_chokepoints": top_nodes,
    }


def derive_chokepoint_kpi(summary: dict[str, Any] | None) -> dict[str, Any] | None:
    """Derive the three-line choke-point KPI headline card from a persisted block.

    This is the CISO-first summary the report leads with: a tiny fix against a
    large, measured blast radius. It is derived ENTIRELY from the
    already-persisted ``chokepoint_cardinality`` block (the same source the
    "Start here" section renders from), so it never re-loads or recomputes over
    the graph, and the wording comes from the copy SSOT
    (:func:`adscan_core.reporting.chokepoint_copy.chokepoint_kpi_lines`) — never
    hand-authored here.

    The blast-radius / percentage semantics:

    * ``routes_severed`` = the TOP single choke's OWN cardinality
      (``ranked_chokepoints[0]["cardinality"]``), because the copy says "fixing 1
      object" — it is that one object's blast radius, never the aggregate of the
      shown rows.
    * ``validated_exposure_pct`` = ``round(100 * routes_severed /
      exposure_source_count)`` when ``exposure_source_count > 0``, else ``None``.
      The DENOMINATOR is ``exposure_source_count`` — the count of principals that
      hold a validated path to a value (Tier 0) target, i.e. *validated reach*.
      It is NOT the total domain user/account population; using that would inflate
      the share and mislabel it. This is the "% of validated exposure" the copy
      SSOT renders, and it appears ONLY in the ``context`` line.
    * ``bounded`` (from the persisted block) drives the "among the routes we
      evaluated" caveat, handled inside ``chokepoint_kpi_lines``.

    Args:
        summary: The persisted ``domain_data["chokepoint_cardinality"]`` dict
            (must carry ``ranked_chokepoints``), or ``None``.

    Returns:
        A JSON-safe dict ``{big, ratio, context, top_object_count,
        routes_severed, validated_exposure_pct}``, or ``None`` when the block is
        absent or carries no ranked rows (older scans render unchanged).
    """
    if not isinstance(summary, dict):
        return None
    ranked = summary.get("ranked_chokepoints")
    if not isinstance(ranked, list) or not ranked:
        return None
    top = ranked[0]
    if not isinstance(top, dict):
        return None

    # The "fixing 1 object" number is the top choke's OWN blast radius, never the
    # aggregate of the rows.
    routes_severed = int(top.get("cardinality") or 0)
    # The KPI card headlines the SINGLE top choke — the copy's ``big`` is
    # "…cut by fixing 1 object" and ``routes_severed`` is that one object's own
    # blast radius, so ``top_object_count`` is 1 to keep the "N objects → M
    # routes" ratio internally consistent (pairing >1 objects with the top-1
    # object's route count would misread). The full ranked list is the detail the
    # "Start here" section renders below the card.
    top_object_count = 1

    # Denominator = validated reach (principals with a proven path to a value
    # target), NEVER the total domain population.
    exposure_source_count = int(summary.get("exposure_source_count") or 0)
    if exposure_source_count > 0:
        # Clamp to [0, 100]: routes_severed (a choke's cardinality) and
        # exposure_source_count (source principals with validated reach) are
        # different counts whose co-domain is not guaranteed, so a persisted block
        # could yield >100. A "112% of validated exposure removed" headline is
        # client-visible nonsense in the paid deliverable; the clamp can never turn
        # a valid percentage wrong, it only bounds an out-of-range one.
        validated_exposure_pct: int | None = min(
            100, max(0, round(100 * routes_severed / exposure_source_count))
        )
    else:
        validated_exposure_pct = None

    bounded = bool(summary.get("bounded"))

    from adscan_core.reporting.chokepoint_copy import (  # noqa: PLC0415
        chokepoint_kpi_lines,
    )

    lines = chokepoint_kpi_lines(
        top_object_count=top_object_count,
        routes_severed=routes_severed,
        validated_exposure_pct=validated_exposure_pct,
        bounded=bounded,
    )

    return {
        "big": lines["big"],
        "ratio": lines["ratio"],
        "context": lines["context"],
        "top_object_count": int(top_object_count),
        "routes_severed": int(routes_severed),
        "validated_exposure_pct": validated_exposure_pct,
    }


def record_chokepoint_cardinality(
    shell: Any,
    domain: str,
    *,
    summary: dict[str, Any],
) -> None:
    """Best-effort persist the choke-point summary into the technical report.

    Mirrors the exposure-KPI stamper
    (:func:`adscan_core.reporting.technical_report.record_exposure_kpis`): stamps
    the value onto ``domains[<domain>]["chokepoint_cardinality"]`` so the JSON
    export carries it and a future render (task E3) reads it instead of
    recomputing. Best-effort: ignores a missing/invalid payload and never raises
    into the caller.

    Live-flow wiring (calling this from the scan pipeline once discovery routes a
    dense graph to the bounded engine) is deferred to the E3 render task; this
    function is the stamp seam it will call.

    Args:
        shell: The report shell carrying the technical-report path.
        domain: The domain the summary belongs to.
        summary: The output of :func:`build_chokepoint_summary`.
    """
    if not domain or not isinstance(summary, dict) or "top_chokepoints" not in summary:
        return
    try:
        from adscan_core.reporting.technical_report import (
            _ensure_technical_domain,
            _load_technical_report,
            _save_technical_report,
        )

        report = _load_technical_report(shell)
        domain_entry = _ensure_technical_domain(report, domain)
        domain_entry["chokepoint_cardinality"] = summary
        _save_technical_report(shell, report)
    except Exception:  # noqa: BLE001 - persistence is best-effort, never fatal
        return


def resolve_choke_bounded(
    domain_data: dict[str, Any], *, engine_marker_bounded: bool
) -> bool:
    """Decide whether the choke summary should carry the bounded caveat.

    Reads the SAME "was this run capped" truth the report and web already render,
    so the choke caveat and the coverage declaration can never disagree. This is
    the tier-shared, LITE-safe SSOT both the PRO report seam and the LITE report
    flow call — it depends only on ``adscan_core`` (no ``adscan_internal.pro``).
    Resolution order (first available wins), best-effort:

    1. The persisted ``attack_path_coverage`` block (H4) on ``domain_data``: a
       ``sampled`` OR ``bounded`` coverage mode means the route sample was capped,
       which is precisely when the client needs "the highest-impact choke point
       among the routes we evaluated". Read through the public
       :func:`attack_path_coverage_view`, which normalizes older blocks too.
    2. Else the engine marker observed on the scan shell (``_attack_path_engine_used
       == "fallback"``), passed in by the caller.
    3. Else ``False``.

    Args:
        domain_data: The in-memory report entry (may carry ``attack_path_coverage``).
        engine_marker_bounded: The shell-marker fallback the caller resolved.

    Returns:
        ``True`` when the run was capped/sampled, else the marker fallback / ``False``.
    """
    try:
        coverage = domain_data.get("attack_path_coverage")
        if coverage is not None:
            from adscan_core.reporting.attack_path_memory_gate import (  # noqa: PLC0415
                COVERAGE_MODE_BOUNDED,
                COVERAGE_MODE_SAMPLED,
                attack_path_coverage_view,
            )

            mode = attack_path_coverage_view(coverage).get("mode")
            return mode in (COVERAGE_MODE_SAMPLED, COVERAGE_MODE_BOUNDED)
    except Exception:  # noqa: BLE001 - coverage read is best-effort
        pass
    return bool(engine_marker_bounded)


def _node_cardinality_map_from_summary(summary: dict[str, Any]) -> dict[str, int]:
    """Build the node total-cut map used only for the structural-choke badge.

    Keys the persisted cardinality by BOTH node id (from ``top_node_chokepoints``)
    AND node label (from the enriched ``ranked_chokepoints``), so a priority row
    whose ``top_choke_point`` is a label OR an id resolves either way. This mirrors
    the PDF's ``_node_cardinality`` construction exactly, so the badge decision the
    web reads matches the deliverable. Only positive cardinalities are kept.
    """
    card_map: dict[str, int] = {}
    for _n in summary.get("top_node_chokepoints") or []:
        if not isinstance(_n, dict):
            continue
        _nid = str(_n.get("node_id") or "").strip()
        try:
            _card = int(_n.get("cardinality") or 0)
        except (TypeError, ValueError):
            _card = 0
        if _nid and _card > 0:
            card_map[_nid] = max(card_map.get(_nid, 0), _card)
    for _r in summary.get("ranked_chokepoints") or []:
        if not isinstance(_r, dict):
            continue
        try:
            _card = int(_r.get("cardinality") or 0)
        except (TypeError, ValueError):
            _card = 0
        if _card <= 0:
            continue
        for _idk in ("node_id", "node_label"):
            _idv = str(_r.get(_idk) or "").strip()
            if _idv:
                card_map[_idv] = max(card_map.get(_idv, 0), _card)
    return card_map


def _build_remediation_start_here_for_domain(
    *,
    domain: str,
    domain_data: dict[str, Any],
    summary: dict[str, Any],
    bounded: bool,
) -> dict[str, Any] | None:
    """Build the persisted "Start here" remediation LEAD for one domain.

    Reuses the ONE tier-shared model-builder
    (:func:`adscan_internal.services.remediation_start_here.build_remediation_start_here`)
    fed the SAME impact-score ranking the PRO PDF renders
    (:func:`~adscan_internal.services.remediation_start_here.compute_remediation_priorities`),
    so the persisted block the web reads carries the exact ranking, counts and
    copy the deliverable shows. Executed / mapped counts are scoped to this
    domain's paths (executed = the proven bucket ``_PROVEN_STATUSES``; mapped =
    all statuses), so the "validated / executed" wording is literally true.

    Returns the JSON/Jinja-safe render model, or ``None`` when the domain has no
    attack paths or no technique carries client exposure.
    """
    from adscan_internal.services.path_state import _PROVEN_STATUSES  # noqa: PLC0415
    from adscan_internal.services.remediation_start_here import (  # noqa: PLC0415
        build_remediation_start_here,
        compute_remediation_priorities,
    )

    raw_paths = domain_data.get("attack_paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        return None

    total_mapped_paths = 0
    total_executed_paths = 0
    for _p in raw_paths:
        if not isinstance(_p, dict):
            continue
        total_mapped_paths += 1
        if str(_p.get("status") or "").strip().lower() in _PROVEN_STATUSES:
            total_executed_paths += 1

    if total_mapped_paths == 0:
        return None

    priorities = compute_remediation_priorities(
        [{"name": domain, "attack_paths": raw_paths}],
        total_mapped_paths,
    )
    if not priorities:
        return None

    node_cardinality = _node_cardinality_map_from_summary(summary)

    return build_remediation_start_here(
        priorities,
        total_executed_paths=total_executed_paths,
        total_mapped_paths=total_mapped_paths,
        node_cardinality=node_cardinality,
        bounded=bounded,
    )


def stamp_chokepoint_cardinality_for_domain(
    *,
    shell: Any,
    domain: str,
    norm_graph: dict[str, Any],
    value_terminals: set[str],
    bounded: bool,
    domain_data: dict[str, Any],
) -> None:
    """Build + rank + persist the choke-point cardinality summary for one domain.

    This is the ONE tier-shared, LITE-safe stamp seam. Both the PRO report service
    (``ensure_report_attack_paths``) and the LITE report flow
    (``generate_lite_report_artifacts``) call it, so the choke-point block is
    computed identically in both tiers and no renderer has to re-load the (large)
    attack graph. It depends only on modules under ``services``/``adscan_core`` —
    never ``adscan_internal.pro`` — so it is reachable from the stripped LITE build.

    The choke-point summary answers "which single object, if removed, severs the
    most source -> value-terminal reach?" as set cardinality over the reachable
    set (no path enumeration). It is scoped to the REAL reachable value-terminal
    set (``value_terminals``), never an inferred one, so the ranking reflects the
    crown jewels this scope can actually reach.

    The ``bounded`` caveat is passed in already resolved (via
    :func:`resolve_choke_bounded`) so it reflects the same capped-run truth the
    report/web render — the choke caveat can never disagree with the coverage
    declaration.

    Best-effort by design: a choke-summary failure must NEVER break report
    generation or the KPI record, so the whole body is guarded and the summary is
    simply absent on failure. Persists to
    ``domains[<domain>]["chokepoint_cardinality"]`` (both the in-memory
    ``domain_data`` and the technical-report file) exactly the way the exposure
    KPIs are recorded.

    Idempotency: if ``domain_data`` already carries a valid, already-ranked
    ``chokepoint_cardinality`` block (e.g. a PRO run stamped it and the LITE flow
    reads the same ``technical_report.json``), the block is left untouched — the
    graph is not re-loaded and nothing is recomputed/overwritten.

    Args:
        shell: A shell namespace carrying ``current_workspace_dir`` (the same
            shape ``record_exposure_kpis`` is called with).
        domain: The domain the summary belongs to.
        norm_graph: The normalized attack graph (``{"nodes": [...], "edges": [...]}``).
        value_terminals: The reachable value-terminal node ids.
        bounded: The already-resolved capped-run caveat (see
            :func:`resolve_choke_bounded`).
        domain_data: The in-memory report entry to stamp the summary onto.
    """
    # Idempotency guard: a valid, already-ranked block means a prior seam (PRO or
    # an earlier LITE pass) already stamped it. Do not recompute/overwrite.
    existing = domain_data.get("chokepoint_cardinality")
    if (
        isinstance(existing, dict)
        and existing.get("schema_version")
        and isinstance(existing.get("ranked_chokepoints"), list)
    ):
        return

    try:
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415
    except Exception:  # noqa: BLE001 - never let an import break the report
        telemetry = None  # type: ignore[assignment]
        print_exception = None  # type: ignore[assignment]

    try:
        summary = build_chokepoint_summary(
            norm_graph,
            value_terminals=value_terminals,
            top_k=20,
        )
        summary["bounded"] = bool(bounded)
        # Rank + severity-enrich HERE, at the one seam that HAS the graph, so
        # every downstream render (PRO PDF, LITE, web) inherits the two-axis
        # order (severity leads cardinality) with real labels, WITHOUT re-loading
        # the ~194MB graph in each renderer. The persisted rows are kept JSON-safe:
        # the severity SSOT returns a ``Severity`` enum, coerced to its string
        # value; the shared ``ranked_edges`` back-reference each row carries is
        # dropped (identical on every row, not needed by the render). Best-effort —
        # a ranking failure must never break the summary.
        try:
            from adscan_internal.services.chokepoint_scoring import (  # noqa: PLC0415
                rank_chokepoints,
            )

            _choke_nodes = (
                norm_graph.get("nodes") if isinstance(norm_graph, dict) else None
            )
            _nodes_map: dict[str, Any] = {}
            if isinstance(_choke_nodes, dict):
                for _nid, _node in _choke_nodes.items():
                    if isinstance(_node, dict):
                        _nodes_map[str(_node.get("id") or _nid)] = _node
            elif isinstance(_choke_nodes, list):
                for _node in _choke_nodes:
                    if isinstance(_node, dict) and _node.get("id"):
                        _nodes_map[str(_node["id"])] = _node

            _ranked = rank_chokepoints(summary, nodes_map=_nodes_map, graph=norm_graph)
            summary["ranked_chokepoints"] = [
                {
                    "node_id": str(_r.get("node_id") or ""),
                    "node_label": str(_r.get("node_label") or _r.get("node_id") or ""),
                    "cardinality": int(_r.get("cardinality") or 0),
                    # Severity is a ``str, Enum`` — store its plain string value.
                    "severity": str(getattr(_r.get("severity"), "value", "") or ""),
                    "severity_rank": int(_r.get("severity_rank") or 0),
                    "protected_terminal_label": str(
                        _r.get("protected_terminal_label") or ""
                    ),
                }
                for _r in _ranked
            ]
        except Exception as _rank_exc:  # noqa: BLE001 - ranking is best-effort
            if print_exception is not None:
                print_exception(exception=_rank_exc)

        # Derive + persist the KPI headline card HERE, at the stamp seam, so every
        # downstream render (PRO PDF, LITE, web T6) reads the SAME card without
        # recomputing. It is derived from the ranked rows + exposure_source_count
        # already on the summary; JSON-safe; best-effort (a failure just omits the
        # card, older scans render unchanged).
        try:
            _kpi = derive_chokepoint_kpi(summary)
            if _kpi is not None:
                summary["chokepoint_kpi"] = _kpi
        except Exception as _kpi_exc:  # noqa: BLE001 - card is best-effort
            if print_exception is not None:
                print_exception(exception=_kpi_exc)

        # Derive + persist the "Start here" remediation LEAD (E4) HERE, at the one
        # seam that already has the domain's attack paths + the choke cardinality,
        # so every downstream render reads the SAME lead without recomputing. This
        # calls the ONE tier-shared model-builder the PRO PDF and LITE report use
        # (``services.remediation_start_here``): the validated-paths-broken ranking
        # (executed-over-theoretical), the executed/mapped count framing, the
        # structural-choke badge, and the KPI card. The paid web CTEM inherits it
        # verbatim (T6). JSON-safe; best-effort (a failure just omits the lead,
        # older scans render unchanged).
        try:
            _start_here = _build_remediation_start_here_for_domain(
                domain=domain,
                domain_data=domain_data,
                summary=summary,
                bounded=bool(bounded),
            )
            if _start_here is not None:
                summary["remediation_start_here"] = _start_here
        except Exception as _sh_exc:  # noqa: BLE001 - lead is best-effort
            if print_exception is not None:
                print_exception(exception=_sh_exc)

        domain_data["chokepoint_cardinality"] = summary
        record_chokepoint_cardinality(shell, domain, summary=summary)
    except Exception as exc:  # noqa: BLE001
        if telemetry is not None:
            telemetry.capture_exception(exc)
        if print_exception is not None:
            print_exception(exception=exc)
