"""Choke-point scoring — rank H3 cardinality entries for client presentation.

H3 (:mod:`chokepoint_cardinality`) answers a pure set-algebra question: for each
node/edge, how many *source* principals lose ALL reach to the value-terminal set
if that choke is removed. That is the blast-radius magnitude, but it says nothing
about WHAT the choke protects. A choke that severs 2,000 low-value sources from a
member server is a smaller finding than one that severs 200 sources from a domain
controller — the second guards the domain control plane.

This module adds the ranking layer. It is a **two-axis** ordering, in the exact
shape of the fan-out rollup precedent
(:func:`attack_fanout_rollup.rollup_fanout`'s
``sort(key=lambda s: (severity_rank(s.severity), -s.count))``):

1. **PRIMARY — the severity of the value-terminal the choke protects.** Resolved
   through the severity SSOT (:func:`severity.compute_edge_severity`), so a choke
   guarding a DC outranks one guarding a member server regardless of how many
   sources each severs.
2. **SECONDARY — the cardinality.** Within one severity band, the choke that
   severs more sources ranks first.

It is a pure function — no I/O, no graph mutation, no DC. The severity grading
reuses the single source of truth; no parallel formula is introduced. The
``EdgeSeverityInput`` for the edge INTO a protected terminal is built exactly the
way the engine builds it in
:func:`attack_fanout_rollup.fanout_input_from_edge` /
:func:`attack_fanout_rollup._severity_for_input`: source/target compromise class
coerced from the node (falling back to the path classifier when unstamped), the
edge kind and control strength from :mod:`edge_kind`, and the graded target tier
from :mod:`compromise_class`.
"""

from __future__ import annotations

from typing import Any, Mapping

from adscan_internal.services.compromise_class import (
    CompromiseClass,
    derive_compromise_class_from_path,
    privilege_tier_for_node,
)
from adscan_internal.services.edge_kind import (
    classify_edge_kind,
    edge_control_strength,
)
from adscan_internal.services.severity import (
    EdgeSeverityInput,
    Severity,
    compute_edge_severity,
    severity_rank,
)

# Maximum forward-BFS frontier expanded per choke node when resolving which
# value-terminals it protects. A directory graph's terminal-reachable subgraph is
# small (a few thousand nodes even at ~34k-node scale); this cap is a defensive
# ceiling so a pathological graph can never turn scoring into an unbounded walk.
_FORWARD_BFS_NODE_CAP: int = 50_000


def _coerce_compromise_class(value: Any) -> CompromiseClass | None:
    """Return a :class:`CompromiseClass` for a raw string / enum, else ``None``.

    Mirrors :func:`attack_fanout_rollup._coerce_compromise_class` so a node's
    stamped ``compromise_class`` grades identically across the two surfaces.

    Args:
        value: A raw stamped value — an enum, its ``.value`` string, or junk.

    Returns:
        The matching :class:`CompromiseClass`, or ``None`` when unset/unknown.
    """
    if isinstance(value, CompromiseClass):
        return value
    token = str(value or "").strip().lower()
    if not token:
        return None
    for member in CompromiseClass:
        if member.value == token:
            return member
    return None


def _node_is_tier0_asset(node: Mapping[str, Any] | None) -> bool:
    """Return True when a node carries a Tier 0 asset flag (best-effort).

    Mirrors :func:`attack_fanout_rollup._node_is_tier0_asset`.

    Args:
        node: A BloodHound/ADscan-shaped node dict, or ``None``.

    Returns:
        True when ``isTierZero`` / ``highvalue`` (snake or camel, top-level or
        under ``properties``) is set.
    """
    if not isinstance(node, Mapping):
        return False
    props = node.get("properties")
    props = props if isinstance(props, Mapping) else {}
    for source in (node, props):
        for key in ("isTierZero", "istierzero", "highvalue", "highValue"):
            if bool(source.get(key)):
                return True
    return False


def _is_builtin_local_group(node: Mapping[str, Any]) -> bool:
    """Return True when a node is a BUILTIN local group (not a domain principal.

    A BUILTIN local group (Administrators, Users, Guests, Power Users, ...) has
    the well-known SID prefix ``S-1-5-32-`` or lives under the directory's
    ``CN=Builtin`` container. Its ``sAMAccountName`` is frequently a common
    English word, so rendering it bare (the graph-wide ``NAME@DOMAIN`` label
    convention) is ambiguous against a same-named domain object.

    Args:
        node: A node dict (already confirmed to be a Mapping).

    Returns:
        True when the node is a BUILTIN local group.
    """
    props = node.get("properties")
    props = props if isinstance(props, Mapping) else {}
    sid = str(
        node.get("objectId") or node.get("objectid") or props.get("objectid") or ""
    ).upper()
    if sid.startswith("S-1-5-32-"):
        return True
    dn = str(props.get("distinguishedname") or "")
    return ",CN=BUILTIN," in dn.upper()


def _node_label(node: Mapping[str, Any] | None, fallback: str) -> str:
    """Return a node's display label, falling back to name then id.

    A BUILTIN local group (SID prefix ``S-1-5-32-`` or ``CN=Builtin`` in its
    DN) is qualified as ``BUILTIN\\<samaccountname>`` instead of the bare
    graph-wide ``NAME@DOMAIN`` label — that convention is correct for domain
    accounts but ambiguous for a BUILTIN group whose name is a common English
    word (``Users``, ``Administrators``, ``Guests``, ``Power Users``), which a
    reader cannot distinguish from ``Domain Users`` or a container.

    Args:
        node: A node dict, or ``None``.
        fallback: The value to return when no label/name is present (the id).

    Returns:
        The best available display label.
    """
    if not isinstance(node, Mapping):
        return fallback
    if _is_builtin_local_group(node):
        props = node.get("properties")
        props = props if isinstance(props, Mapping) else {}
        sam = str(props.get("samaccountname") or "").strip()
        if sam:
            return f"BUILTIN\\{sam}"
        bare = str(node.get("label") or node.get("name") or fallback)
        name_part = bare.split("@", 1)[0]
        return f"BUILTIN\\{name_part.title()}"
    return str(node.get("label") or node.get("name") or fallback)


def _resolve_target_compromise_class(
    to_node: Mapping[str, Any] | None,
    relation: str,
) -> CompromiseClass | None:
    """Resolve the target's compromise class for severity grading.

    Prefers a stamped ``compromise_class`` on the node (the engine's convention);
    when absent, derives it from the SSOT path classifier over the single edge
    INTO the target — a choke's protected edge IS a one-edge path, so its reach
    class is the same question :func:`derive_compromise_class_from_path` answers.
    This keeps unstamped nodes (fresh graphs, tests) grading correctly instead of
    collapsing to the weakest class.

    Args:
        to_node: The terminal node dict, or ``None``.
        relation: The raw relation of the edge into the terminal.

    Returns:
        The terminal's :class:`CompromiseClass`, or ``None`` when indeterminate.
    """
    stamped = _coerce_compromise_class(
        (to_node or {}).get("compromise_class")
        if isinstance(to_node, Mapping)
        else None
    )
    if stamped is not None:
        return stamped
    derived = derive_compromise_class_from_path([{"relation": relation}], to_node)
    return derived if derived is not CompromiseClass.NONE else None


def _severity_for_edge_into(
    from_node: Mapping[str, Any] | None,
    to_node: Mapping[str, Any] | None,
    relation: str,
) -> Severity:
    """Compute the severity of one edge via the severity SSOT.

    Builds the :class:`EdgeSeverityInput` the same way the engine does at
    :func:`attack_fanout_rollup.fanout_input_from_edge` /
    :func:`attack_fanout_rollup._severity_for_input`:

    * ``source_compromise_class`` / ``target_compromise_class`` — coerced from
      each node's stamped class (target falls back to the path classifier).
    * ``edge_kind`` — :func:`edge_kind.classify_edge_kind` of the relation.
    * ``target_privilege_tier`` — :func:`compromise_class.privilege_tier_for_node`
      of the terminal, with the degraded ``isTierZero``/``highvalue`` fallback.
    * ``edge_control_strength`` — :func:`edge_kind.edge_control_strength`.
    * ``target_is_tier0_asset`` — derived from the graded tier.
    * ``target_is_domain`` — the ``kind == "Domain"`` terminal signal.

    Args:
        from_node: The choke/source node dict, or ``None``.
        to_node: The terminal node dict, or ``None``.
        relation: The raw relation label of the edge into the terminal.

    Returns:
        The canonical :class:`Severity` of the edge.
    """
    target_tier = privilege_tier_for_node(
        to_node if isinstance(to_node, Mapping) else None,
        is_tier0_asset=_node_is_tier0_asset(to_node),
    )
    target_is_domain = (
        str((to_node or {}).get("kind") or "").strip().lower() == "domain"
        if isinstance(to_node, Mapping)
        else False
    )
    return compute_edge_severity(
        EdgeSeverityInput(
            source_compromise_class=_coerce_compromise_class(
                (from_node or {}).get("compromise_class")
                if isinstance(from_node, Mapping)
                else None
            ),
            target_compromise_class=_resolve_target_compromise_class(to_node, relation),
            edge_kind=classify_edge_kind(relation),
            target_privilege_tier=target_tier,
            edge_control_strength=edge_control_strength(relation),
            target_is_tier0_asset=target_tier.is_tier0,
            target_is_domain=target_is_domain,
        )
    )


def _build_inbound_index(
    graph: Mapping[str, Any],
) -> dict[str, list[tuple[str, str]]]:
    """Build a ``to_id -> [(from_id, relation), ...]`` inbound-edge index.

    Args:
        graph: The attack graph dict (``edges`` is a list of ``{from, to,
            relation}`` dicts).

    Returns:
        A mapping from a node id to the list of edges landing on it.
    """
    inbound: dict[str, list[tuple[str, str]]] = {}
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return inbound
    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        from_id = str(edge.get("from") or edge.get("source") or "").strip()
        to_id = str(edge.get("to") or edge.get("target") or "").strip()
        if not from_id or not to_id:
            continue
        relation = str(edge.get("relation") or edge.get("kind_label") or "")
        inbound.setdefault(to_id, []).append((from_id, relation))
    return inbound


def _build_forward_adjacency(
    graph: Mapping[str, Any],
) -> dict[str, list[tuple[str, str]]]:
    """Build a ``from_id -> [(to_id, relation), ...]`` forward-edge index.

    Args:
        graph: The attack graph dict.

    Returns:
        A mapping from a node id to the edges departing it.
    """
    forward: dict[str, list[tuple[str, str]]] = {}
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return forward
    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        from_id = str(edge.get("from") or edge.get("source") or "").strip()
        to_id = str(edge.get("to") or edge.get("target") or "").strip()
        if not from_id or not to_id:
            continue
        relation = str(edge.get("relation") or edge.get("kind_label") or "")
        forward.setdefault(from_id, []).append((to_id, relation))
    return forward


def _best_protected_terminal(
    choke_id: str,
    *,
    nodes_map: Mapping[str, Any],
    forward: Mapping[str, list[tuple[str, str]]],
) -> tuple[Severity, int, str, str] | None:
    """Find the highest-severity value-terminal a choke protects.

    Forward-BFS from the choke node over the graph edges; for EVERY node the
    choke can reach, grade the severity of the edge that lands on it and keep the
    most severe. The most-severe reachable target IS the value-terminal the choke
    protects — this needs no separately supplied terminal set: a choke that only
    reaches a member server protects that server; one that reaches a DC protects
    the DC. The choke's OWN inbound edge is not the finding — the outbound reach
    to the protected asset is.

    Args:
        choke_id: The choke node id.
        nodes_map: node-id → node-dict map.
        forward: Forward adjacency ``from_id -> [(to_id, relation), ...]``.

    Returns:
        A ``(severity, severity_rank, terminal_id, relation)`` tuple for the
        best-protected terminal, or ``None`` when the choke reaches nothing.
    """
    best: tuple[Severity, int, str, str] | None = None
    best_rank: int | None = None
    seen: set[str] = {choke_id}
    pending: list[str] = [choke_id]
    from_node = nodes_map.get(choke_id)
    expanded = 0
    while pending and expanded < _FORWARD_BFS_NODE_CAP:
        current = pending.pop()
        current_node = nodes_map.get(current)
        for to_id, relation in forward.get(current, ()):
            edge_source = current_node if current != choke_id else from_node
            to_node = nodes_map.get(to_id)
            sev = _severity_for_edge_into(edge_source, to_node, relation)
            rank = severity_rank(sev)
            if best_rank is None or rank < best_rank:
                best_rank = rank
                best = (sev, rank, to_id, relation)
            if to_id not in seen:
                seen.add(to_id)
                pending.append(to_id)
                expanded += 1
    return best


def _enrich_node_choke(
    entry: Mapping[str, Any],
    *,
    nodes_map: Mapping[str, Any],
    forward: Mapping[str, list[tuple[str, str]]],
) -> dict[str, Any]:
    """Enrich one H3 node-choke entry with its protected-terminal severity.

    Args:
        entry: An H3 ``{node_id, cardinality}`` dict.
        nodes_map: node-id → node-dict map.
        forward: Forward adjacency for terminal resolution.

    Returns:
        The enriched dict — ``node_id``, ``node_label``, ``cardinality``,
        ``severity``, ``severity_rank``, ``protected_terminal_label``.
    """
    node_id = str(entry.get("node_id") or "")
    cardinality = int(entry.get("cardinality") or 0)
    node = nodes_map.get(node_id)
    best = _best_protected_terminal(node_id, nodes_map=nodes_map, forward=forward)
    if best is None:
        # A choke that reaches no forward target has no protected terminal — grade
        # it at the floor (INFO) so it sorts last but is never dropped.
        severity = Severity.INFO
        terminal_label = ""
    else:
        severity, _rank, terminal_id, _relation = best
        terminal_label = _node_label(nodes_map.get(terminal_id), terminal_id)
    return {
        "node_id": node_id,
        "node_label": _node_label(node, node_id),
        "cardinality": cardinality,
        "severity": severity,
        "severity_rank": severity_rank(severity),
        "protected_terminal_label": terminal_label,
    }


def _enrich_edge_choke(
    entry: Mapping[str, Any],
    *,
    nodes_map: Mapping[str, Any],
) -> dict[str, Any]:
    """Enrich one H3 edge-choke entry with its own edge severity.

    The edge key is ``"{from}|{relation}|{to}"`` (see
    :func:`chokepoint_cardinality.edge_key`); the protected terminal is the edge's
    own ``to`` node, and the severity is graded on that single edge.

    Args:
        entry: An H3 ``{edge_key, cardinality}`` dict.
        nodes_map: node-id → node-dict map.

    Returns:
        The enriched dict — ``edge_key``, ``from_id``, ``to_id``, ``relation``,
        ``cardinality``, ``severity``, ``severity_rank``,
        ``protected_terminal_label``.
    """
    edge_key = str(entry.get("edge_key") or "")
    cardinality = int(entry.get("cardinality") or 0)
    # The relation may itself contain "|" is not expected — split into exactly 3.
    parts = edge_key.split("|", 2)
    from_id = parts[0] if len(parts) > 0 else ""
    relation = parts[1] if len(parts) > 1 else ""
    to_id = parts[2] if len(parts) > 2 else ""
    severity = _severity_for_edge_into(
        nodes_map.get(from_id), nodes_map.get(to_id), relation
    )
    return {
        "edge_key": edge_key,
        "from_id": from_id,
        "to_id": to_id,
        "relation": relation,
        "cardinality": cardinality,
        "severity": severity,
        "severity_rank": severity_rank(severity),
        "protected_terminal_label": _node_label(nodes_map.get(to_id), to_id),
    }


def rank_chokepoints(
    summary: dict[str, Any],
    *,
    nodes_map: dict[str, Any],
    graph: dict[str, Any],
) -> list[dict[str, Any]]:
    """Rank H3 choke points for client presentation, severity then cardinality.

    Enriches each node choke from ``summary["top_node_chokepoints"]`` with the
    severity of the value-terminal it protects (resolved by forward reach through
    the graph and graded via the severity SSOT), then sorts by
    ``(severity_rank(severity), -cardinality)`` — most severe first, ties broken
    by the largest blast radius. This is the exact ordering shape of the fan-out
    rollup precedent, so a choke guarding a domain controller outranks a larger
    one guarding a member server.

    The edge chokes (``summary["top_chokepoints"]``) are enriched the same way
    and attached to every primary entry as a shared ``ranked_edges`` reference —
    the node chokes are the primary return list; the edges reinforce.

    This is a pure function: no I/O, no graph mutation, no DC access. The severity
    grading reuses :func:`severity.compute_edge_severity` — no parallel formula.

    Args:
        summary: The H3 summary dict from
            :func:`chokepoint_cardinality.build_chokepoint_summary`
            (``top_node_chokepoints``, ``top_chokepoints``, …).
        nodes_map: node-id → node-dict map. Node ids must match the graph edges'
            ``from``/``to`` ids and the summary's ``node_id`` values.
        graph: The attack graph dict (``nodes``, ``edges``) — used to resolve the
            forward reach from each choke to its protected terminal.

    Returns:
        The node choke points, most-critical first, each enriched with
        ``node_id``, ``node_label``, ``cardinality``, ``severity`` (a
        :class:`Severity`), ``severity_rank`` (int), ``protected_terminal_label``,
        and the shared ``ranked_edges`` secondary list.
    """
    forward = _build_forward_adjacency(graph)

    raw_nodes = summary.get("top_node_chokepoints")
    node_entries = raw_nodes if isinstance(raw_nodes, list) else []
    ranked_nodes = [
        _enrich_node_choke(entry, nodes_map=nodes_map, forward=forward)
        for entry in node_entries
        if isinstance(entry, Mapping)
    ]
    ranked_nodes.sort(key=lambda r: (r["severity_rank"], -r["cardinality"]))

    raw_edges = summary.get("top_chokepoints")
    edge_entries = raw_edges if isinstance(raw_edges, list) else []
    ranked_edges = [
        _enrich_edge_choke(entry, nodes_map=nodes_map)
        for entry in edge_entries
        if isinstance(entry, Mapping)
    ]
    ranked_edges.sort(key=lambda r: (r["severity_rank"], -r["cardinality"]))

    # Attach the edge reinforcement as a shared secondary list on each primary
    # entry, so a consumer holding only the node list can still reach it.
    for node in ranked_nodes:
        node["ranked_edges"] = ranked_edges

    return ranked_nodes
