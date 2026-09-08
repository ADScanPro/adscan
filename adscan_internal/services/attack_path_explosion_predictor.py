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


def count_control_mega_hubs(graph: dict[str, Any], *, min_out_degree: int = 500) -> int:
    """Return the number of nodes with > min_out_degree same-relation CONTROL edges."""
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
    hubs: set[str] = {
        src for (src, _rel), n in per_source_rel.items() if n > min_out_degree
    }
    return len(hubs)


def predicts_explosion(
    graph: dict[str, Any], *, hub_threshold: int = 2, min_out_degree: int = 500
) -> bool:
    """Return True when the graph has >= hub_threshold control mega-hubs (mesh signature)."""
    return (
        count_control_mega_hubs(graph, min_out_degree=min_out_degree) >= hub_threshold
    )
