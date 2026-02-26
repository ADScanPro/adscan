"""Attack graph core utilities (pure functions).

This module contains the core logic for computing attack paths from an
`attack_graph.json` structure. It is intentionally written without any
dependency on the interactive CLI "shell" object, so it can be reused by both
the CLI and the web backend.

Notes:
    - The core functions operate on the in-memory attack graph dict structure
      (schema_version 1.1). Callers are responsible for loading/saving files.
    - Callers may optionally "enrich" the graph (e.g., inject runtime MemberOf
      edges) before calling these functions. The core treats the graph as the
      source of truth and performs no network calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adscan_internal.workspaces import read_json_file


@dataclass(frozen=True)
class AttackPathStep:
    from_id: str
    relation: str
    to_id: str
    status: str
    notes: dict[str, Any]


@dataclass(frozen=True)
class AttackPath:
    steps: list[AttackPathStep]
    source_id: str
    target_id: str

    @property
    def length(self) -> int:
        return len(self.steps)


def load_attack_graph(path: Path) -> dict[str, Any] | None:
    """Load an attack graph from an `attack_graph.json` file path.

    Args:
        path: Path to `attack_graph.json`.

    Returns:
        The parsed graph dict when readable/valid, otherwise None.
    """
    try:
        if not path.exists():
            return None
    except OSError:
        return None

    data = read_json_file(str(path))
    if not isinstance(data, dict):
        return None
    nodes_map = data.get("nodes")
    edges = data.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return None
    return data


def get_owned_node_ids(
    variables: dict[str, Any],
    graph: dict[str, Any],
    *,
    domain: str,
) -> list[str]:
    """Resolve "owned" usernames from variables.json into attack-graph node ids.

    The core algorithm only understands node ids. The web backend typically
    reads owned credentials from variables.json and then needs to map them into
    the graph nodes.

    Args:
        variables: Parsed `variables.json`.
        graph: Parsed attack graph.
        domain: Domain key (e.g. "htb.local").

    Returns:
        A list of node ids that exist in the graph and represent owned users.
    """
    domains_data = (
        variables.get("domains_data") if isinstance(variables, dict) else None
    )
    domain_data = (
        domains_data.get(domain)
        if isinstance(domains_data, dict) and isinstance(domain, str)
        else None
    )
    if not isinstance(domain_data, dict):
        return []

    credentials = domain_data.get("credentials")
    owned_usernames: set[str] = set()
    if isinstance(credentials, dict):
        owned_usernames.update(
            str(u).strip() for u in credentials.keys() if str(u).strip()
        )

    if not owned_usernames:
        return []

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return []

    domain_upper = str(domain).strip().upper()
    resolved: list[str] = []
    for username in sorted(owned_usernames):
        canonical_label = f"{username.upper()}@{domain_upper}"
        node_id = _find_user_node_id(
            nodes_map, username=username, canonical_label=canonical_label
        )
        if node_id:
            resolved.append(node_id)
    return resolved


def compute_display_paths_for_domain_unfiltered(
    graph: dict[str, Any],
    *,
    max_depth: int,
    require_high_value_target: bool = True,
    target_mode: str = "tier0",
) -> list[dict[str, Any]]:
    """Compute maximal attack paths for a domain (graph-only, unfiltered).

    This is the graph-only equivalent of the CLI `attack_paths <domain>` logic.
    Callers can optionally post-process with `filter_contained_paths_for_domain_listing`.
    """
    mode = (target_mode or "tier0").strip().lower()
    if mode not in {"tier0", "impact"}:
        mode = "tier0"

    computed = compute_maximal_attack_paths(
        graph,
        max_depth=max_depth,
        # Always compute all paths and apply filtering/promotion after.
        require_high_value_target=False,
        terminal_mode=mode,
    )

    results: list[dict[str, Any]] = []
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()

    for path in computed:
        candidate = path
        if require_high_value_target:
            target_is_hv = _path_target_is_high_value(graph, path.target_id, mode=mode)
            if not target_is_hv:
                promoted = _try_promote_target_via_membership_edges(
                    graph, path, required_rank=1 if mode == "impact" else 3, mode=mode
                )
                if promoted:
                    candidate = promoted
                    target_is_hv = True
            if not target_is_hv:
                continue

        record = path_to_display_record(graph, candidate)
        nodes = record.get("nodes")
        rels = record.get("relations")
        if not isinstance(nodes, list) or not isinstance(rels, list):
            continue
        key = (tuple(str(n) for n in nodes), tuple(str(r) for r in rels))
        if key in seen:
            continue
        seen.add(key)
        results.append(record)

    return results


def filter_contained_paths_for_domain_listing(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Remove paths that are fully contained within another longer path."""
    if len(records) <= 1:
        return records, 0

    normalized: list[tuple[tuple[str, ...], tuple[str, ...], dict[str, Any]]] = []
    for record in records:
        nodes = record.get("nodes")
        rels = record.get("relations")
        if not isinstance(nodes, list) or not isinstance(rels, list):
            continue
        nodes_t = tuple(str(n) for n in nodes)
        rels_t = tuple(str(r) for r in rels)
        normalized.append((nodes_t, rels_t, record))

    normalized.sort(key=lambda item: len(item[1]), reverse=True)

    covered: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    kept: list[dict[str, Any]] = []
    removed = 0

    for nodes_t, rels_t, record in normalized:
        sig = (nodes_t, rels_t)
        if sig in covered:
            removed += 1
            continue
        kept.append(record)

        rel_len = len(rels_t)
        if rel_len <= 0:
            continue
        for start in range(0, rel_len):
            for end in range(start + 1, rel_len + 1):
                if end - start >= rel_len:
                    continue
                sub_nodes = nodes_t[start : end + 1]
                sub_rels = rels_t[start:end]
                covered.add((sub_nodes, sub_rels))

    return kept, removed


def compute_display_paths_for_start_node(
    graph: dict[str, Any],
    *,
    start_node_id: str,
    max_depth: int,
    require_high_value_target: bool = True,
    target_mode: str = "tier0",
) -> list[dict[str, Any]]:
    """Compute maximal attack paths starting from a specific node id."""
    mode = (target_mode or "tier0").strip().lower()
    if mode not in {"tier0", "impact"}:
        mode = "tier0"

    computed = compute_maximal_attack_paths_from_start(
        graph,
        start_node_id=start_node_id,
        max_depth=max_depth,
        require_high_value_target=False,
        terminal_mode=mode,
    )

    results: list[dict[str, Any]] = []
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()

    for path in computed:
        candidate = path
        if require_high_value_target:
            target_is_hv = _path_target_is_high_value(graph, path.target_id, mode=mode)
            if not target_is_hv:
                promoted = _try_promote_target_via_membership_edges(
                    graph, path, required_rank=1 if mode == "impact" else 3, mode=mode
                )
                if promoted:
                    candidate = promoted
                    target_is_hv = True
            if not target_is_hv:
                continue

        record = path_to_display_record(graph, candidate)
        nodes = record.get("nodes")
        rels = record.get("relations")
        if not isinstance(nodes, list) or not isinstance(rels, list):
            continue
        key = (tuple(str(n) for n in nodes), tuple(str(r) for r in rels))
        if key in seen:
            continue
        seen.add(key)
        results.append(record)

    return results


def compute_maximal_attack_paths(
    graph: dict[str, Any],
    *,
    max_depth: int,
    require_high_value_target: bool = True,
    terminal_mode: str = "tier0",
) -> list[AttackPath]:
    """Compute maximal paths up to depth for a full-domain graph."""
    if max_depth <= 0:
        return []

    nodes_map = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return []

    adjacency: dict[str, list[dict[str, Any]]] = {}
    incoming: dict[str, int] = {}
    outgoing: dict[str, int] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = str(edge.get("from") or "")
        to_id = str(edge.get("to") or "")
        rel = str(edge.get("relation") or "")
        if not from_id or not to_id or not rel:
            continue
        adjacency.setdefault(from_id, []).append(edge)
        outgoing[from_id] = outgoing.get(from_id, 0) + 1
        # MemberOf edges (persisted or runtime) should not change which nodes
        # are considered "sources" in domain-wide path listing.
        if rel != "MemberOf":
            incoming[to_id] = incoming.get(to_id, 0) + 1
        incoming.setdefault(from_id, incoming.get(from_id, 0))
        outgoing.setdefault(to_id, outgoing.get(to_id, 0))

    mode = (terminal_mode or "tier0").strip().lower()
    if mode not in {"tier0", "impact"}:
        mode = "tier0"

    def is_terminal(node_id: str) -> bool:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            return False
        if mode == "impact":
            return _node_is_impact_high_value(node)
        return _node_is_tier0(node)

    sources = [node_id for node_id in nodes_map.keys() if incoming.get(node_id, 0) == 0]

    paths: list[AttackPath] = []
    seen_signatures: set[tuple[tuple[str, str, str], ...]] = set()

    def emit(acc_steps: list[AttackPathStep]) -> None:
        if not acc_steps:
            return
        if require_high_value_target and not is_terminal(acc_steps[-1].to_id):
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

    def dfs(current: str, visited: set[str], acc_steps: list[AttackPathStep]) -> None:
        depth = len(acc_steps)
        if depth >= max_depth or (depth > 0 and is_terminal(current)):
            emit(acc_steps)
            return

        next_edges = adjacency.get(current) or []
        if not next_edges:
            emit(acc_steps)
            return

        extended = False
        for edge in next_edges:
            to_id = str(edge.get("to") or "")
            if not to_id or to_id in visited:
                continue
            step = AttackPathStep(
                from_id=current,
                relation=str(edge.get("relation") or ""),
                to_id=to_id,
                status=str(edge.get("status") or "discovered"),
                notes=edge.get("notes") if isinstance(edge.get("notes"), dict) else {},
            )
            visited.add(to_id)
            acc_steps.append(step)
            dfs(to_id, visited, acc_steps)
            acc_steps.pop()
            visited.remove(to_id)
            extended = True

        if not extended:
            emit(acc_steps)

    for source in sources:
        dfs(source, visited={source}, acc_steps=[])

    return paths


def compute_maximal_attack_paths_from_start(
    graph: dict[str, Any],
    *,
    start_node_id: str,
    max_depth: int,
    require_high_value_target: bool = True,
    terminal_mode: str = "tier0",
) -> list[AttackPath]:
    """Compute maximal paths starting from a specific node."""
    if max_depth <= 0 or not start_node_id:
        return []

    nodes_map = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return []

    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = str(edge.get("from") or "")
        to_id = str(edge.get("to") or "")
        rel = str(edge.get("relation") or "")
        if not from_id or not to_id or not rel:
            continue
        adjacency.setdefault(from_id, []).append(edge)

    mode = (terminal_mode or "tier0").strip().lower()
    if mode not in {"tier0", "impact"}:
        mode = "tier0"

    def is_terminal(node_id: str) -> bool:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            return False
        if mode == "impact":
            return _node_is_impact_high_value(node)
        return _node_is_tier0(node)

    paths: list[AttackPath] = []
    seen_signatures: set[tuple[tuple[str, str, str], ...]] = set()

    def emit(acc_steps: list[AttackPathStep]) -> None:
        if not acc_steps:
            return
        if require_high_value_target and not is_terminal(acc_steps[-1].to_id):
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

    def dfs(current: str, visited: set[str], acc_steps: list[AttackPathStep]) -> None:
        depth = len(acc_steps)
        if depth >= max_depth or (depth > 0 and is_terminal(current)):
            emit(acc_steps)
            return

        next_edges = adjacency.get(current) or []
        if not next_edges:
            emit(acc_steps)
            return

        extended = False
        for edge in next_edges:
            to_id = str(edge.get("to") or "")
            if not to_id or to_id in visited:
                continue
            step = AttackPathStep(
                from_id=current,
                relation=str(edge.get("relation") or ""),
                to_id=to_id,
                status=str(edge.get("status") or "discovered"),
                notes=edge.get("notes") if isinstance(edge.get("notes"), dict) else {},
            )
            visited.add(to_id)
            acc_steps.append(step)
            dfs(to_id, visited, acc_steps)
            acc_steps.pop()
            visited.remove(to_id)
            extended = True

        if not extended:
            emit(acc_steps)

    dfs(start_node_id, visited={start_node_id}, acc_steps=[])
    return paths


def path_to_display_record(graph: dict[str, Any], path: AttackPath) -> dict[str, Any]:
    """Convert an AttackPath to the CLI/UI-friendly dict shape."""
    from adscan_internal.services.attack_step_support_registry import (
        classify_relation_support,
    )

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    context_relations = {"memberof"}

    def label(node_id: str) -> str:
        node = nodes_map.get(node_id)
        if isinstance(node, dict):
            return str(node.get("label") or node_id)
        return node_id

    nodes = [label(path.source_id)]
    relations: list[str] = []
    for step in path.steps:
        relations.append(step.relation)
        nodes.append(label(step.to_id))

    derived_status = "theoretical"
    executable_steps = [
        s
        for s in path.steps
        if isinstance(getattr(s, "relation", None), str)
        and str(s.relation).strip().lower() not in context_relations
    ]
    statuses = [
        s.status.lower()
        for s in executable_steps
        if isinstance(s.status, str) and s.status
    ]
    if statuses and all(s == "success" for s in statuses):
        derived_status = "exploited"
    elif any(s in {"attempted", "failed", "error"} for s in statuses):
        derived_status = "attempted"
    elif any(s == "unavailable" for s in statuses):
        derived_status = "unavailable"
    elif any(s == "blocked" for s in statuses) or any(
        classify_relation_support(str(s.relation or "").strip().lower()).kind
        == "policy_blocked"
        for s in executable_steps
    ):
        derived_status = "blocked"
    elif any(s == "unsupported" for s in statuses):
        derived_status = "unsupported"

    steps_for_ui: list[dict[str, Any]] = []
    for idx, step in enumerate(path.steps, start=1):
        steps_for_ui.append(
            {
                "step": idx,
                "action": step.relation,
                "status": step.status,
                "details": {
                    "from": label(step.from_id),
                    "to": label(step.to_id),
                    **(step.notes or {}),
                },
            }
        )

    return {
        "nodes": nodes,
        "relations": relations,
        "length": sum(
            1
            for rel in relations
            if str(rel or "").strip().lower() not in context_relations
        ),
        "source": nodes[0] if nodes else "",
        "target": nodes[-1] if nodes else "",
        "status": derived_status,
        "steps": steps_for_ui,
    }


def _find_user_node_id(
    nodes_map: dict[str, Any],
    *,
    username: str,
    canonical_label: str,
) -> str | None:
    username_clean = str(username or "").strip().lower()
    if not username_clean:
        return None
    canonical_label_clean = str(canonical_label or "").strip().lower()
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        if str(node.get("kind") or "") != "User":
            continue
        if str(node.get("label") or "").strip().lower() == canonical_label_clean:
            return str(node_id)
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        sam = str(props.get("samaccountname") or "").strip().lower()
        if sam and sam == username_clean:
            return str(node_id)
    return None


def _path_target_is_high_value(
    graph: dict[str, Any], target_id: str, *, mode: str
) -> bool:
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    node = nodes_map.get(str(target_id or "")) if isinstance(nodes_map, dict) else None
    if not isinstance(node, dict):
        return False
    if mode == "impact":
        return _node_is_impact_high_value(node)
    return _node_is_tier0(node)


def _node_is_tier0(node: dict[str, Any]) -> bool:
    if bool(node.get("isTierZero")):
        return True
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if bool(props.get("isTierZero")):
        return True
    tags = node.get("system_tags") or props.get("system_tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return any(str(tag).lower() == "admin_tier_0" for tag in tags)


def _node_is_privileged_group(node: dict[str, Any]) -> bool:
    if str(node.get("kind") or "") != "Group":
        return False
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    candidates = [
        props.get("objectid"),
        props.get("objectId"),
        node.get("objectid"),
        node.get("objectId"),
    ]
    sid: str | None = None
    for value in candidates:
        if isinstance(value, str) and value.strip():
            sid = value.strip()
            break
    if not sid:
        return False
    sid_upper = sid.strip().upper()
    sid_idx = sid_upper.find("S-1-")
    if sid_idx != -1:
        sid_upper = sid_upper[sid_idx:]
    try:
        rid = int(sid_upper.rsplit("-", 1)[-1])
    except Exception:
        rid = None

    builtin_privileged_rids = {544, 548, 549, 550, 551}
    if rid in builtin_privileged_rids and sid_upper.startswith("S-1-5-32-"):
        return True

    domain_privileged_rids = {512, 518, 519}
    if rid in domain_privileged_rids:
        return True

    if rid == 1101:
        return True

    return False


def _node_is_effectively_high_value(node: dict[str, Any]) -> bool:
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if _node_is_tier0(node):
        return True
    if bool(node.get("highvalue")) or bool(props.get("highvalue")):
        return True
    return _node_is_privileged_group(node)


def _node_is_impact_high_value(node: dict[str, Any]) -> bool:
    return _node_is_effectively_high_value(node)


def _node_high_value_rank(node: dict[str, Any]) -> int:
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if bool(node.get("isTierZero")) or bool(props.get("isTierZero")):
        return 3
    tags = node.get("system_tags") or props.get("system_tags") or []
    if isinstance(tags, str):
        tags = [tags]
    if any(str(tag).lower() == "admin_tier_0" for tag in tags):
        return 3
    if bool(node.get("highvalue")) or bool(props.get("highvalue")):
        return 2
    if _node_is_privileged_group(node):
        return 1
    return 0


def _try_promote_target_via_membership_edges(
    graph: dict[str, Any],
    path: AttackPath,
    *,
    required_rank: int,
    mode: str,
) -> AttackPath | None:
    """Promote a non-high-value User/Computer target via MemberOf edges in the graph."""
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return None

    target_id = str(path.target_id or "")
    target_node = nodes_map.get(target_id)
    if not isinstance(target_node, dict):
        return None
    if str(target_node.get("kind") or "") not in {"User", "Computer"}:
        return None

    best_rank = 0
    best_group_id: str | None = None
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("from") or "") != target_id:
            continue
        if str(edge.get("relation") or "").strip().lower() != "memberof":
            continue
        to_id = str(edge.get("to") or "")
        if not to_id:
            continue
        group_node = nodes_map.get(to_id)
        if not isinstance(group_node, dict):
            continue
        if str(group_node.get("kind") or "") != "Group":
            continue
        rank = _node_high_value_rank(group_node)
        if rank < required_rank:
            continue
        if rank > best_rank:
            best_rank = rank
            best_group_id = to_id
            if best_rank >= 3:
                break

    if not best_group_id:
        return None

    extended_steps = list(path.steps)
    extended_steps.append(
        AttackPathStep(
            from_id=target_id,
            relation="MemberOf",
            to_id=best_group_id,
            status="discovered",
            notes={
                "edge": "runtime",
                "context": "high_value_via_group"
                if mode == "impact"
                else "tier0_via_group",
            },
        )
    )
    return AttackPath(
        steps=extended_steps,
        source_id=path.source_id,
        target_id=best_group_id,
    )
