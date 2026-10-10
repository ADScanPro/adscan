"""Reachable compromise-terminal set primitive (Stage 1 reachability layer).

This module answers a k-independent EXPOSURE question over a materialized
attack graph: given a start-node scope, which distinct *value-classified
compromise terminals* are forward-reachable? It is reachability, not path
enumeration, so the figure it produces does not depend on the DFS
materialization budget (``max_paths`` / ``max_depth``).

Reachability is monotone over the real edge set, so a plain forward flood over
``from`` → ``to`` adjacency is sufficient and correct — the virtual local-reuse
edges the DFS adds only compress already-reachable pairs, they never make an
unreachable terminal reachable.

Value classification delegates entirely to the compromise-class SSOT
(:mod:`adscan_internal.services.compromise_class`); the only new logic here is
the flood and a thin dispatch onto those classifiers.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from adscan_internal.services.attack_graph_core import (
    _build_high_value_terminal_candidate_ids,
    is_traversable_attack_edge,
)
from adscan_internal.services.compromise_class import (
    is_direct_domain_breaker_target,
    is_privileged_escalator_target,
)


@dataclass(frozen=True)
class ReachableTerminal:
    """A single value-classified compromise terminal reachable from a scope.

    Attributes:
        node_id: The graph node id of the terminal.
        label: The node's display label (identifier, often ``NAME@DOMAIN``).
        value_class: One of ``"domain_object"``, ``"tier0_direct"``,
            ``"tier0_enabler"`` or ``"non_tier0"``.
    """

    node_id: str
    label: str
    value_class: str


def _node_is_domain_object(node: Mapping[str, Any]) -> bool:
    """Return whether *node* is the domain object itself (kind == domain)."""
    return str(node.get("kind") or "").strip().lower() == "domain"


def _is_enabler_label_aware(node: Mapping[str, Any]) -> bool:
    """Return whether *node* is a Tier-0 escalation group, label-aware.

    The public :func:`is_privileged_escalator_target` matches by the bare group
    NAME only (the ``{"name": "DnsAdmins"}`` stub shape). Real graph nodes carry
    a LABEL like ``DNSADMINS@ESSOS.LOCAL``, so a direct call misses them. This
    tries the public wrapper first, then retries against a normalized stub built
    by splitting the node's ``label``/``name`` on ``@`` and lowercasing — reusing
    the same group set without duplicating it.
    """
    if is_privileged_escalator_target(node):
        return True
    raw = node.get("label") or node.get("name") or ""
    bare = str(raw).split("@", 1)[0].strip().lower()
    if not bare:
        return False
    return is_privileged_escalator_target({"name": bare})


def _classify_value(node: Mapping[str, Any]) -> str:
    """Return the ``value_class`` of *node* per the fixed decision order.

    Order: domain kind → ``"domain_object"``; else direct breaker →
    ``"tier0_direct"``; else escalation group (label-aware) →
    ``"tier0_enabler"``; else ``"non_tier0"``.
    """
    if _node_is_domain_object(node):
        return "domain_object"
    if is_direct_domain_breaker_target(node):
        return "tier0_direct"
    if _is_enabler_label_aware(node):
        return "tier0_enabler"
    return "non_tier0"


def _forward_reachable(
    nodes_map: dict[str, Any], edges: list[dict[str, Any]], start_node_ids: set[str]
) -> set[str]:
    """Breadth-first forward flood from *start_node_ids* over ``from`` → ``to``.

    Start ids not present in *nodes_map* are ignored. Returns the set of reached
    node ids (including the valid start ids themselves).

    The adjacency is built over ONLY traversable compromise edges — the SAME gate
    the DFS uses (:func:`attack_graph_core.is_traversable_attack_edge`). Without
    it the flood would cross share-access edges (e.g.
    ``Everyone --FullControlShare--> DC$``), which are exposure findings, not
    host-compromise transitions, and would falsely report full-domain reach for
    every standard user.
    """
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if not is_traversable_attack_edge(edge, nodes_map):
            continue
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if not from_id or not to_id:
            continue
        adjacency.setdefault(from_id, []).append(to_id)

    reached: set[str] = set()
    queue: deque[str] = deque(
        node_id for node_id in start_node_ids if node_id in nodes_map
    )
    reached.update(queue)
    while queue:
        current = queue.popleft()
        for neighbor in adjacency.get(current, ()):
            if neighbor in reached:
                continue
            reached.add(neighbor)
            queue.append(neighbor)
    return reached


def compute_reachable_terminals(
    graph: dict[str, Any], *, start_node_ids: set[str], target: str = "all"
) -> list[ReachableTerminal]:
    """Return the distinct value-classified compromise terminals reachable.

    Performs a forward flood from *start_node_ids* over the real edge adjacency
    (``from`` → ``to``), then keeps only reached nodes that are value-classified
    compromise terminals, deduplicated by ``node_id``.

    Args:
        graph: The materialized attack graph, ``{"nodes": [...], "edges": [...]}``.
            Nodes carry ``"id"``, ``"kind"``, ``"label"``; edges carry ``"from"``,
            ``"to"``, ``"relation"``.
        start_node_ids: The scope to seed the flood. Ids not present in the graph
            are ignored.
        target: When ``"all"`` (default), a reached node is a terminal if its
            ``value_class != "non_tier0"`` OR it is in the high-value candidate
            set (so promotable Tier-2 stepping-stones still count). When any
            other value, terminals are restricted to the high-value candidate set
            (``mode="object"``).

    Returns:
        A list of :class:`ReachableTerminal`, one per distinct terminal node.
    """
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    nodes_map: dict[str, Any] = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id") or "").strip()
        if node_id:
            nodes_map[node_id] = node

    reached = _forward_reachable(nodes_map, edges, start_node_ids)

    candidate_ids = _build_high_value_terminal_candidate_ids(
        nodes_map, edges, mode="object"
    )

    # `reached` is a set of distinct node ids, so no id repeats here — no extra
    # dedup guard is needed to keep the terminals list unique by node_id.
    terminals: list[ReachableTerminal] = []
    for node_id in reached:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            continue
        value_class = _classify_value(node)
        if target == "all":
            is_terminal = value_class != "non_tier0" or node_id in candidate_ids
        else:
            is_terminal = node_id in candidate_ids
        if not is_terminal:
            continue
        terminals.append(
            ReachableTerminal(
                node_id=node_id,
                label=str(node.get("label") or node.get("name") or node_id),
                value_class=value_class,
            )
        )
    return terminals


def reachability_summary_for_workspace(
    workspace_dir: str,
    domain: str,
    *,
    graph: dict[str, Any] | None = None,
) -> dict[str, int] | None:
    """Return the reachable-terminal summary for one domain in a workspace.

    The SSOT for "which distinct compromise terminals can the domain's enabled
    low-priv users reach", resolved directly from the workspace graph. It is the
    ONE place that (a) loads the base attack graph, (b) resolves the enabled
    low-priv start scope, (c) normalizes the runtime node shape (the runtime
    graph stores nodes as a DICT ``id -> node``; :func:`compute_reachable_terminals`
    iterates ``nodes`` as a LIST, so a dict passed unnormalized computes 0), and
    (d) floods + summarizes. Both the report's ``exposure_kpis`` stamping seam
    (``exposure_score_service``) and the telemetry counts fallback
    (``attack_path_counts.client_path_totals``) call this, so the ``reachable_*``
    EXPOSURE numbers are computed identically whether or not a report has been
    generated yet.

    Args:
        workspace_dir: The scan workspace root (execution ``.run_*`` dir for a
            live scan). Used to build the shell namespace the graph/start-id
            resolvers read from.
        domain: The domain to summarize.
        graph: An already-loaded base attack graph to reuse (avoids a second
            reload when the caller has one). When ``None`` the graph is loaded
            here.

    Returns:
        The per-class reachable-terminal summary (see
        :func:`summarize_reachable_terminals`), or ``None`` on any failure /
        missing graph. Best-effort: never raises.
    """
    workspace_dir = str(workspace_dir or "").strip()
    domain_name = str(domain or "").strip()
    if not workspace_dir or not domain_name:
        return None
    try:
        from types import SimpleNamespace  # noqa: PLC0415

        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            _resolve_domain_enabled_low_priv_user_start_ids,
            load_attack_graph,
        )

        shell_ns = SimpleNamespace(
            current_workspace_dir=workspace_dir, domains_dir="domains"
        )
        base_graph = graph if isinstance(graph, dict) else load_attack_graph(
            shell_ns, domain_name
        )
        if not isinstance(base_graph, dict) or not base_graph:
            return None
        start_ids = _resolve_domain_enabled_low_priv_user_start_ids(
            shell_ns, domain_name, base_graph
        )
        # The runtime graph stores nodes as a DICT (id -> node);
        # compute_reachable_terminals iterates graph["nodes"] as a LIST, so
        # normalize before passing (else it computes 0).
        raw_nodes = base_graph.get("nodes")
        norm_graph = {
            "nodes": (
                list(raw_nodes.values())
                if isinstance(raw_nodes, dict)
                else (raw_nodes or [])
            ),
            "edges": base_graph.get("edges") or [],
        }
        terminals = compute_reachable_terminals(
            norm_graph, start_node_ids=start_ids, target="all"
        )
        return summarize_reachable_terminals(terminals)
    except Exception:  # noqa: BLE001 - best-effort analytics/telemetry helper
        return None


def summarize_reachable_terminals(
    terminals: Sequence[ReachableTerminal],
) -> dict[str, int]:
    """Return per-class counts and the derived compromise aggregates.

    Args:
        terminals: The terminals from :func:`compute_reachable_terminals`.

    Returns:
        A dict with per-class counts under ``"domain_object"``,
        ``"tier0_direct"``, ``"tier0_enabler"``, ``"non_tier0"``, plus
        ``"full_domain_compromise"`` (= ``domain_object + tier0_direct``) and
        ``"tier0_reachable"`` (= ``domain_object + tier0_direct + tier0_enabler``).
    """
    counts = {
        "domain_object": 0,
        "tier0_direct": 0,
        "tier0_enabler": 0,
        "non_tier0": 0,
    }
    for terminal in terminals:
        if terminal.value_class in counts:
            counts[terminal.value_class] += 1
    counts["full_domain_compromise"] = counts["domain_object"] + counts["tier0_direct"]
    counts["tier0_reachable"] = (
        counts["domain_object"] + counts["tier0_direct"] + counts["tier0_enabler"]
    )
    return counts
