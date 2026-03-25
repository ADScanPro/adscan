"""Attack graph DFS engine backed by rustworkx (Rust-native graph library).

This module is a drop-in replacement for the hot DFS paths in
``attack_graph_core``.  It is designed to be swapped in transparently at the
module level during dev-mode benchmarking — the existing Python engine remains
completely untouched.

Key optimisations vs the Python DFS engine:

1. **Pre-materialised virtual edges** — LocalAdminPassReuse virtual edges are
   expanded once at graph-build time instead of O(C×M²) per DFS visit.
2. **Rust-backed adjacency** — ``rw_graph.out_edges(idx)`` delegates to a Rust
   hashmap, lower constant than Python ``dict.get()`` at scale.

Requires: ``rustworkx>=0.15``  (pip-installable, PyInstaller-compatible).
Falls back gracefully when not installed: ``is_available()`` returns False.
"""

from __future__ import annotations

from typing import Any

from adscan_internal.services.attack_graph_core import (  # noqa: PLC2701
    AttackPath,
    AttackPathStep,
    _build_local_reuse_virtual_state,
    _build_local_reuse_useful_node_ids,
    _is_same_local_reuse_cluster_chain,
    _LOCAL_REUSE_RELATION_KEY,
    _node_is_enabled_user,
    _node_is_effectively_high_value,
    _node_is_tier0,
    _node_is_impact_high_value,
)

try:
    import rustworkx as _rw_lib  # type: ignore[import]

    _RUSTWORKX_AVAILABLE = True
except ImportError:
    _rw_lib = None  # type: ignore[assignment]
    _RUSTWORKX_AVAILABLE = False


def is_available() -> bool:
    """Return True when rustworkx is installed and importable."""
    return _RUSTWORKX_AVAILABLE


def _build_rustworkx_graph(
    nodes_map: dict[str, Any],
    edges: list[dict[str, Any]],
    local_reuse_by_node: dict[str, list[dict[str, Any]]],
    local_reuse_existing_pairs: set[tuple[str, str]],
    local_reuse_useful_nodes: set[str],
) -> tuple[Any, dict[str, int], dict[int, str]]:
    """Build a rustworkx.PyDiGraph from graph data.

    Virtual LocalAdminPassReuse edges (star topology) are pre-materialised as
    real edges in the graph so the DFS loop never needs to expand them on-the-fly.
    Real LocalAdminPassReuse edges pointing to non-useful nodes are dropped here
    instead of per-visit.

    Returns:
        (rw_graph, node_id_to_idx, idx_to_node_id)
    """
    rw_graph = _rw_lib.PyDiGraph()

    node_id_to_idx: dict[str, int] = {}
    idx_to_node_id: dict[int, str] = {}

    for node_id in nodes_map:
        idx = rw_graph.add_node(node_id)
        node_id_to_idx[node_id] = idx
        idx_to_node_id[idx] = node_id

    # Real edges — filter useless LocalAdminPassReuse at build time.
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = str(edge.get("from") or "")
        to_id = str(edge.get("to") or "")
        if not from_id or not to_id:
            continue
        if from_id not in node_id_to_idx or to_id not in node_id_to_idx:
            continue
        relation_key = str(edge.get("relation") or "").strip().lower()
        if relation_key == _LOCAL_REUSE_RELATION_KEY and to_id not in local_reuse_useful_nodes:
            continue
        rw_graph.add_edge(node_id_to_idx[from_id], node_id_to_idx[to_id], edge)

    # Pre-materialise virtual LocalAdminPassReuse edges (star topology clusters).
    for node_id, clusters in local_reuse_by_node.items():
        if node_id not in node_id_to_idx:
            continue
        from_idx = node_id_to_idx[node_id]
        for cluster in clusters:
            cluster_id = str(cluster.get("cluster_id") or "")
            emitted: set[tuple[str, str]] = set()
            for dst_id in cluster.get("node_ids") or []:
                dst = str(dst_id).strip()
                if not dst or dst == node_id:
                    continue
                if dst not in local_reuse_useful_nodes or dst not in node_id_to_idx:
                    continue
                pair = (node_id, dst)
                if pair in local_reuse_existing_pairs or pair in emitted:
                    continue
                emitted.add(pair)
                rw_graph.add_edge(
                    from_idx,
                    node_id_to_idx[dst],
                    {
                        "from": node_id,
                        "to": dst,
                        "relation": "LocalAdminPassReuse",
                        "status": "discovered",
                        "notes": {
                            "source": "local_reuse_virtual_expansion",
                            "virtual_expansion": True,
                            "reuse_cluster_id": cluster_id,
                            "local_admin_username": cluster.get("local_admin_username"),
                        },
                    },
                )

    return rw_graph, node_id_to_idx, idx_to_node_id


def compute_maximal_attack_paths_rustworkx(
    graph: dict[str, Any],
    *,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    terminal_mode: str = "tier0",
    start_node_ids: set[str] | None = None,
) -> list[AttackPath]:
    """Compute maximal attack paths for a full-domain graph using rustworkx adjacency.

    Drop-in replacement for ``attack_graph_core.compute_maximal_attack_paths``.
    Falls back to the Python implementation when rustworkx is not available.
    """
    if not _RUSTWORKX_AVAILABLE or max_depth <= 0:
        from adscan_internal.services.attack_graph_core import compute_maximal_attack_paths

        return compute_maximal_attack_paths(
            graph,
            max_depth=max_depth,
            max_paths=max_paths,
            target=target,
            terminal_mode=terminal_mode,
            start_node_ids=start_node_ids,
        )

    max_paths_cap = (
        None
        if max_paths is None
        else max(1, int(max_paths))
        if int(max_paths) > 0
        else None
    )

    nodes_map = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return []

    local_reuse_by_node, local_reuse_existing_pairs = _build_local_reuse_virtual_state(
        nodes_map, edges
    )
    local_reuse_useful_nodes = _build_local_reuse_useful_node_ids(nodes_map, edges)
    rw_graph, node_id_to_idx, idx_to_node_id = _build_rustworkx_graph(
        nodes_map,
        edges,
        local_reuse_by_node,
        local_reuse_existing_pairs,
        local_reuse_useful_nodes,
    )

    # Domain scope should start from every low-priv principal with outgoing
    # attack steps, not only from root nodes with zero incoming degree.
    outgoing: dict[str, int] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = str(edge.get("from") or "")
        to_id = str(edge.get("to") or "")
        rel = str(edge.get("relation") or "")
        if not from_id or not to_id or not rel:
            continue
        outgoing[from_id] = outgoing.get(from_id, 0) + 1
        outgoing.setdefault(to_id, outgoing.get(to_id, 0))

    allowed_start_ids: set[str] = (
        {str(node_id) for node_id in start_node_ids if str(node_id).strip()}
        if start_node_ids
        else set()
    )
    sources: list[str] = []
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        if allowed_start_ids and node_id not in allowed_start_ids:
            continue
        if outgoing.get(node_id, 0) <= 0:
            continue
        if not _node_is_enabled_user(node):
            continue
        if _node_is_effectively_high_value(node):
            continue
        sources.append(node_id)

    mode = (terminal_mode or "tier0").strip().lower()
    if mode not in {"tier0", "impact"}:
        mode = "tier0"

    def is_terminal(node_id: str) -> bool:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            return False
        return (
            _node_is_impact_high_value(node) if mode == "impact" else _node_is_tier0(node)
        )

    paths: list[AttackPath] = []
    seen_signatures: set[tuple[tuple[str, str, str], ...]] = set()

    def emit(acc_steps: list[AttackPathStep]) -> None:
        if not acc_steps:
            return
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        if (target == "highvalue" and not is_terminal(acc_steps[-1].to_id)) or (
            target == "lowpriv" and is_terminal(acc_steps[-1].to_id)
        ):
            return
        signature = tuple((s.from_id, s.relation, s.to_id) for s in acc_steps)
        if signature in seen_signatures:
            return
        seen_signatures.add(signature)
        paths.append(
            AttackPath(
                steps=list(acc_steps),
                source_id=acc_steps[0].from_id,
                target_id=acc_steps[-1].to_id,
            )
        )

    def dfs(
        current: str,
        current_idx: int,
        visited: set[str],
        acc_steps: list[AttackPathStep],
    ) -> None:
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        depth = len(acc_steps)
        if depth >= max_depth or (depth > 0 and is_terminal(current)):
            emit(acc_steps)
            return

        out_edges = rw_graph.out_edges(current_idx)  # Rust-backed adjacency lookup
        if not out_edges:
            emit(acc_steps)
            return

        extended = False
        for _, tgt_idx, edge_data in out_edges:
            if not isinstance(edge_data, dict):
                continue
            last_step = acc_steps[-1] if acc_steps else None
            if _is_same_local_reuse_cluster_chain(last_step, edge_data):
                continue
            to_id = idx_to_node_id.get(tgt_idx)
            if not to_id or to_id in visited:
                continue
            step = AttackPathStep(
                from_id=current,
                relation=str(edge_data.get("relation") or ""),
                to_id=to_id,
                status=str(edge_data.get("status") or "discovered"),
                notes=(
                    edge_data.get("notes")
                    if isinstance(edge_data.get("notes"), dict)
                    else {}
                ),
            )
            visited.add(to_id)
            acc_steps.append(step)
            dfs(to_id, tgt_idx, visited, acc_steps)
            acc_steps.pop()
            visited.remove(to_id)
            extended = True

        if not extended:
            emit(acc_steps)

    for source_id in sources:
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            break
        source_idx = node_id_to_idx.get(source_id)
        if source_idx is None:
            continue
        dfs(source_id, source_idx, {source_id}, [])

    return paths


def compute_maximal_attack_paths_from_start_rustworkx(
    graph: dict[str, Any],
    *,
    start_node_id: str,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    terminal_mode: str = "tier0",
) -> list[AttackPath]:
    """Compute maximal paths from a specific start node using rustworkx adjacency.

    Drop-in replacement for ``attack_graph_core.compute_maximal_attack_paths_from_start``.
    Falls back to the Python implementation when rustworkx is not available.
    """
    if not _RUSTWORKX_AVAILABLE or max_depth <= 0 or not start_node_id:
        from adscan_internal.services.attack_graph_core import (
            compute_maximal_attack_paths_from_start,
        )

        return compute_maximal_attack_paths_from_start(
            graph,
            start_node_id=start_node_id,
            max_depth=max_depth,
            max_paths=max_paths,
            target=target,
            terminal_mode=terminal_mode,
        )

    max_paths_cap = (
        None
        if max_paths is None
        else max(1, int(max_paths))
        if int(max_paths) > 0
        else None
    )

    nodes_map = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return []

    local_reuse_by_node, local_reuse_existing_pairs = _build_local_reuse_virtual_state(
        nodes_map, edges
    )
    local_reuse_useful_nodes = _build_local_reuse_useful_node_ids(nodes_map, edges)
    rw_graph, node_id_to_idx, idx_to_node_id = _build_rustworkx_graph(
        nodes_map,
        edges,
        local_reuse_by_node,
        local_reuse_existing_pairs,
        local_reuse_useful_nodes,
    )

    mode = (terminal_mode or "tier0").strip().lower()
    if mode not in {"tier0", "impact"}:
        mode = "tier0"

    def is_terminal(node_id: str) -> bool:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            return False
        return (
            _node_is_impact_high_value(node) if mode == "impact" else _node_is_tier0(node)
        )

    paths: list[AttackPath] = []
    seen_signatures: set[tuple[tuple[str, str, str], ...]] = set()

    def emit(acc_steps: list[AttackPathStep]) -> None:
        if not acc_steps:
            return
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        if (target == "highvalue" and not is_terminal(acc_steps[-1].to_id)) or (
            target == "lowpriv" and is_terminal(acc_steps[-1].to_id)
        ):
            return
        signature = tuple((s.from_id, s.relation, s.to_id) for s in acc_steps)
        if signature in seen_signatures:
            return
        seen_signatures.add(signature)
        paths.append(
            AttackPath(
                steps=list(acc_steps),
                source_id=acc_steps[0].from_id,
                target_id=acc_steps[-1].to_id,
            )
        )

    def dfs(
        current: str,
        current_idx: int,
        visited: set[str],
        acc_steps: list[AttackPathStep],
    ) -> None:
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        depth = len(acc_steps)
        if depth >= max_depth or (depth > 0 and is_terminal(current)):
            emit(acc_steps)
            return

        out_edges = rw_graph.out_edges(current_idx)
        if not out_edges:
            emit(acc_steps)
            return

        extended = False
        for _, tgt_idx, edge_data in out_edges:
            if not isinstance(edge_data, dict):
                continue
            last_step = acc_steps[-1] if acc_steps else None
            if _is_same_local_reuse_cluster_chain(last_step, edge_data):
                continue
            to_id = idx_to_node_id.get(tgt_idx)
            if not to_id or to_id in visited:
                continue
            step = AttackPathStep(
                from_id=current,
                relation=str(edge_data.get("relation") or ""),
                to_id=to_id,
                status=str(edge_data.get("status") or "discovered"),
                notes=(
                    edge_data.get("notes")
                    if isinstance(edge_data.get("notes"), dict)
                    else {}
                ),
            )
            visited.add(to_id)
            acc_steps.append(step)
            dfs(to_id, tgt_idx, visited, acc_steps)
            acc_steps.pop()
            visited.remove(to_id)
            extended = True

        if not extended:
            emit(acc_steps)

    start_idx = node_id_to_idx.get(start_node_id)
    if start_idx is None:
        return []
    dfs(start_node_id, start_idx, {start_node_id}, [])
    return paths
