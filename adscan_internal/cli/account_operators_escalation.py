"""Account Operators escalation helper.

This helper is invoked when we detect a compromised user is effectively high
value because it belongs to the built-in Account Operators group.

Goal:
    Use BloodHound CE to find a short ACL/ACE-driven path from
    ``ACCOUNT OPERATORS@<DOMAIN>`` to a Tier-0 target. If found, persist the
    relationships into `attack_graph.json` so the normal attack-path UX can
    present and execute the chain.
"""

from __future__ import annotations

from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_info_debug,
    print_warning,
)
from adscan_internal.services.attack_graph_service import (
    add_bloodhound_path_edges,
    load_attack_graph,
    save_attack_graph,
)


def _account_operators_canonical(domain: str) -> str:
    return f"ACCOUNT OPERATORS@{(domain or '').strip().upper()}"


def _build_account_operators_shortest_paths_query(domain: str) -> str:
    group_name = _account_operators_canonical(domain)
    # Use a single-line query because BloodHound CE's cypher endpoint is strict
    # about whitespace normalization.
    return (
        "MATCH p=shortestPath((s:Group)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|"
        "AddMember|ForceChangePassword|DCSync*1..10]->(t)) "
        f"WHERE toLower(coalesce(s.name,'')) = toLower('{group_name}') "
        "AND s<>t "
        f"AND COALESCE(t.system_tags, '') CONTAINS 'admin_tier_0' "
        "RETURN p "
        "LIMIT 20"
    )


def _node_props(node_data: dict[str, Any]) -> dict[str, Any]:
    props = node_data.get("properties")
    return props if isinstance(props, dict) else {}


def _node_kind(node_data: dict[str, Any]) -> str:
    kind = node_data.get("kind")
    if isinstance(kind, str) and kind:
        return kind
    return "Unknown"


def _node_name_for_attack_graph(node_data: dict[str, Any]) -> str:
    props = _node_props(node_data)
    return str(props.get("name") or node_data.get("label") or "")


def _node_object_id(node_data: dict[str, Any]) -> str | None:
    props = _node_props(node_data)
    value = props.get("objectid") or props.get("objectId")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _node_is_tier0(node_data: dict[str, Any]) -> bool:
    props = _node_props(node_data)
    tags = props.get("system_tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return any(str(tag).lower() == "admin_tier_0" for tag in tags)


def _extract_candidate_paths(
    graph_data: dict[str, Any],
    *,
    domain: str,
    max_depth: int = 10,
) -> list[tuple[list[dict[str, Any]], list[str]]]:
    """Extract simple paths (nodes+relations) from a CE graph response."""
    nodes_map = graph_data.get("nodes")
    edges = graph_data.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return []

    canonical_start = _account_operators_canonical(domain)
    start_node_id: str | None = None
    for node_id, node_data in nodes_map.items():
        if not isinstance(node_data, dict):
            continue
        props = _node_props(node_data)
        name = str(props.get("name") or "")
        if name and name.strip().lower() == canonical_start.lower():
            start_node_id = str(node_id)
            break

    if not start_node_id:
        return []

    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        src = str(edge.get("source") or "")
        if not src:
            continue
        adjacency.setdefault(src, []).append(edge)

    results: list[tuple[list[str], list[str]]] = []

    def dfs(current: str, visited: set[str], path_nodes: list[str], rels: list[str]) -> None:
        if len(rels) >= max_depth:
            return
        current_node = nodes_map.get(current)
        if isinstance(current_node, dict) and _node_is_tier0(current_node) and rels:
            results.append((list(path_nodes), list(rels)))
            return

        for edge in adjacency.get(current, []):
            dst = str(edge.get("target") or "")
            if not dst or dst in visited:
                continue
            label = str(edge.get("label") or "").strip()
            if not label:
                continue
            visited.add(dst)
            path_nodes.append(dst)
            rels.append(label)
            dfs(dst, visited, path_nodes, rels)
            rels.pop()
            path_nodes.pop()
            visited.remove(dst)

    dfs(start_node_id, visited={start_node_id}, path_nodes=[start_node_id], rels=[])
    if not results:
        return []

    def to_attack_graph_node(node_id: str) -> dict[str, Any] | None:
        node_data = nodes_map.get(node_id)
        if not isinstance(node_data, dict):
            return None
        props = _node_props(node_data)
        name = _node_name_for_attack_graph(node_data)
        if not name:
            return None
        out: dict[str, Any] = {"name": name, "kind": [_node_kind(node_data)], "properties": props}
        object_id = _node_object_id(node_data)
        if object_id:
            out["objectId"] = object_id
        return out

    candidates: list[tuple[list[dict[str, Any]], list[str]]] = []
    for node_ids, rels in results:
        nodes: list[dict[str, Any]] = []
        for node_id in node_ids:
            converted = to_attack_graph_node(node_id)
            if not converted:
                nodes = []
                break
            nodes.append(converted)
        if not nodes:
            continue
        if len(nodes) != len(rels) + 1:
            continue
        candidates.append((nodes, rels))

    return candidates


def _path_requires_adcs(nodes: list[dict[str, Any]], domain: str) -> bool:
    if not nodes:
        return False
    last = str(nodes[-1].get("name") or "").strip().lower()
    domain_upper = (domain or "").strip().upper()
    key_admins = f"KEY ADMINS@{domain_upper}".lower()
    ent_key_admins = f"ENTERPRISE KEY ADMINS@{domain_upper}".lower()
    return last in {key_admins, ent_key_admins}


def _select_best_path(
    shell: Any,
    domain: str,
    candidates: list[tuple[list[dict[str, Any]], list[str]]],
) -> tuple[list[dict[str, Any]], list[str]] | None:
    """Pick the best candidate path, filtering ADCS-dependent ones when needed."""
    if not candidates:
        return None

    has_adcs: bool | None = None

    filtered: list[tuple[list[dict[str, Any]], list[str]]] = []
    for nodes, rels in candidates:
        if _path_requires_adcs(nodes, domain):
            if has_adcs is None:
                has_adcs = bool(
                    getattr(shell, "_detect_adcs", lambda *_a, **_k: False)(
                        domain, silent=True, emit_telemetry=False
                    )
                )
            if not has_adcs:
                continue
        filtered.append((nodes, rels))

    if not filtered:
        return None

    # Prefer shortest; stable tie-breaker by target name.
    filtered.sort(key=lambda item: (len(item[1]), str(item[0][-1].get("name") or "").lower()))
    return filtered[0]


def offer_account_operators_escalation(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> bool:
    """Offer an Account Operators → Tier-0 escalation chain.

    Returns:
        True if we persisted at least one path edge, otherwise False.
    """
    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")

    print_warning(
        f"User {marked_user} is in Account Operators for {marked_domain}. This can often lead to domain compromise."
    )

    try:
        service = shell._get_bloodhound_service()
    except Exception as exc:  # pragma: no cover
        telemetry.capture_exception(exc)
        print_info_debug(f"[acct-ops] BloodHound service unavailable: {exc}")
        return False

    query = _build_account_operators_shortest_paths_query(domain)
    print_info_debug(
        f"[acct-ops] shortest-path query: {mark_sensitive(query, 'command')}"
    )

    graph_data: dict[str, Any] = {}
    try:
        client = getattr(service, "client", None)
        runner = getattr(client, "execute_query_with_relationships", None)
        if callable(runner):
            graph_data = runner(query)
    except Exception as exc:  # pragma: no cover
        telemetry.capture_exception(exc)
        print_info_debug(f"[acct-ops] query failed: {exc}")
        return False

    candidates = _extract_candidate_paths(graph_data, domain=domain, max_depth=10)
    # Filter out ADCS-dependent paths when no ADCS is present.
    has_adcs: bool | None = None
    filtered: list[tuple[list[dict[str, Any]], list[str]]] = []
    for nodes, rels in candidates:
        if _path_requires_adcs(nodes, domain):
            if has_adcs is None:
                has_adcs = bool(
                    getattr(shell, "_detect_adcs", lambda *_a, **_k: False)(
                        domain, silent=True, emit_telemetry=False
                    )
                )
            if not has_adcs:
                continue
        filtered.append((nodes, rels))

    if not filtered:
        print_info(
            f"No suitable escalation path found from Account Operators in {marked_domain}."
        )
        return False

    graph = load_attack_graph(shell, domain)

    # Persist all candidate paths and build the same UX as `attack_paths`:
    # user -> MemberOf -> Account Operators -> ...
    summaries: list[dict[str, Any]] = []
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    total_edges_added = 0
    account_ops_label = _account_operators_canonical(domain)

    # Best-effort: resolve canonical BloodHound user node for stable ids/labels.
    user_node = None
    try:
        resolver = getattr(service, "get_user_node_by_samaccountname", None)
        if callable(resolver):
            user_node = resolver(domain, username)
    except Exception as exc:  # pragma: no cover
        telemetry.capture_exception(exc)
        user_node = None

    user_label = username
    if isinstance(user_node, dict):
        node_name = str(user_node.get("name") or "").strip()
        node_domain = str(user_node.get("domain") or domain).strip().upper()
        node_sam = str(user_node.get("samaccountname") or "").strip()
        if node_name and "@" in node_name:
            user_label = node_name
        elif node_sam and node_domain:
            user_label = f"{node_sam.upper()}@{node_domain}"
        else:
            user_label = str(username)

    for nodes, rels in filtered:
        key = (tuple(str(n.get("name") or "") for n in nodes), tuple(rels))
        if key in seen:
            continue
        seen.add(key)

        total_edges_added += add_bloodhound_path_edges(
            graph,
            nodes=nodes,
            relations=rels,
            status="discovered",
            edge_type="bloodhound_ce",
            shell=shell,
        )

        # Ensure the user + account operators nodes exist for display resolution.
        if isinstance(user_node, dict):
            from adscan_internal.services.attack_graph_service import upsert_nodes

            # Wrap raw BloodHound properties into our node shape to avoid
            # persisting Users as kind=Unknown (which would use SID-based IDs).
            user_record = {"name": user_label, "kind": ["User"], "properties": user_node}
            upsert_nodes(graph, [user_record])

        # Account Operators node must exist from the candidate path; if not, add a minimal one.
        if nodes and str(nodes[0].get("name") or "").strip():
            account_ops_label = str(nodes[0].get("name") or account_ops_label)

        # Build an in-memory path (with MemberOf prefix) and reuse the detail UX.
        node_labels = [user_label, account_ops_label] + [
            str(n.get("name") or "") for n in nodes[1:]
        ]
        relations = ["MemberOf"] + list(rels)

        steps: list[dict[str, Any]] = []
        for idx, rel in enumerate(relations, start=1):
            from_label = node_labels[idx - 1]
            to_label = node_labels[idx]
            steps.append(
                {
                    "step": idx,
                    "action": rel,
                    "status": "discovered",
                    "details": {"from": from_label, "to": to_label},
                }
            )

        length = sum(1 for rel in relations if str(rel).strip().lower() != "memberof")
        summaries.append(
            {
                "nodes": node_labels,
                "relations": relations,
                "length": length,
                "source": node_labels[0],
                "target": node_labels[-1],
                "status": "theoretical",
                "steps": steps,
            }
        )

    if total_edges_added:
        save_attack_graph(shell, domain, graph)
        print_info("Recorded Account Operators escalation paths into the attack graph.")

    if not summaries:
        return False

    from adscan_internal.cli.attack_path_execution import (
        offer_attack_paths_for_execution_summaries,
    )

    offer_attack_paths_for_execution_summaries(
        shell,
        domain,
        summaries=summaries,
        max_display=min(10, len(summaries)),
        context_username=username,
        context_password=password,
    )
    return True
