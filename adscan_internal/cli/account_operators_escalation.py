"""High-value group -> terminal target enrichment helpers."""

from __future__ import annotations

import os
from typing import Any

from adscan_internal import telemetry
from adscan_internal import print_info_list
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_info_debug,
    print_warning,
)
from adscan_internal.services.adcs_target_filter import (
    domain_has_adcs_for_attack_steps,
    path_contains_adcs_dependent_node,
)
from adscan_internal.services.attack_graph_core import (
    _node_is_terminal_target as _attack_graph_node_is_terminal_target,
)
from adscan_internal.services.attack_graph_service import (
    add_bloodhound_path_edges,
    load_attack_graph,
    save_attack_graph,
)


HIGH_VALUE_GROUP_ENRICHMENT_MAX_DEPTH = 4
HIGH_VALUE_GROUP_ENRICHMENT_MAX_RESULTS = 100


def _account_operators_canonical(domain: str) -> str:
    return f"ACCOUNT OPERATORS@{(domain or '').strip().upper()}"


def _exchange_windows_permissions_canonical(domain: str) -> str:
    return f"EXCHANGE WINDOWS PERMISSIONS@{(domain or '').strip().upper()}"


def _exchange_trusted_subsystem_canonical(domain: str) -> str:
    return f"EXCHANGE TRUSTED SUBSYSTEM@{(domain or '').strip().upper()}"


def _get_attack_step_sample_limit() -> int:
    """Return maximum number of enrichment step samples to print."""
    raw = os.getenv("ADSCAN_ATTACK_PATHS_STEP_SAMPLE_LIMIT", "20")
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = 20
    return max(0, min(limit, 200))


def _should_show_attack_step_samples() -> bool:
    """Return whether enrichment step samples should be shown."""
    raw = os.getenv("ADSCAN_ATTACK_PATHS_STEP_SHOW_SAMPLES", "1").strip().lower()
    return raw in {"1", "true", "yes", "on"}


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


def _ce_node_is_terminal_target(node_data: dict[str, Any]) -> bool:
    """Return True when a CE response node should terminate enrichment DFS.

    The enrichment flow must mirror the central attack-graph terminality rules:
    graph-extension groups such as Exchange Windows Permissions are not terminal,
    even when BloodHound marks them as Tier Zero.
    """
    props = _node_props(node_data)
    adapted_node = {
        "kind": _node_kind(node_data),
        "properties": props,
        "highvalue": props.get("highvalue"),
        "isTierZero": props.get("isTierZero"),
        "system_tags": props.get("system_tags"),
        "label": node_data.get("label"),
    }
    return _attack_graph_node_is_terminal_target(adapted_node)


def _extract_candidate_paths(
    graph_data: dict[str, Any],
    *,
    domain: str,
    source_group_label: str,
    max_depth: int = 10,
) -> list[tuple[list[dict[str, Any]], list[str]]]:
    """Extract simple paths (nodes+relations) from a CE graph response."""
    nodes_map = graph_data.get("nodes")
    edges = graph_data.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return []

    canonical_start = str(source_group_label or "").strip() or _account_operators_canonical(domain)
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
        if (
            isinstance(current_node, dict)
            and _ce_node_is_terminal_target(current_node)
            and rels
        ):
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


def _candidate_path_requires_adcs(nodes: list[dict[str, Any]], domain: str) -> bool:
    """Return True when any meaningful node in the path requires ADCS."""
    return path_contains_adcs_dependent_node(nodes, domain, skip_first=True)


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
        if _candidate_path_requires_adcs(nodes, domain):
            if has_adcs is None:
                has_adcs = domain_has_adcs_for_attack_steps(shell, domain)
            if not has_adcs:
                continue
        filtered.append((nodes, rels))

    if not filtered:
        return None

    # Prefer shortest; stable tie-breaker by target name.
    filtered.sort(key=lambda item: (len(item[1]), str(item[0][-1].get("name") or "").lower()))
    return filtered[0]


def _offer_group_tier_zero_enrichment(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    source_group_label: str,
    display_name: str,
    ce_method_name: str,
) -> bool:
    """Enrich the graph with group-derived paths into terminal targets."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")

    print_warning(
        f"User {marked_user} is in {display_name} for {marked_domain}. This can often lead to domain compromise."
    )

    try:
        service = shell._get_bloodhound_service()
    except Exception as exc:  # pragma: no cover
        telemetry.capture_exception(exc)
        print_info_debug(f"[acct-ops] BloodHound service unavailable: {exc}")
        return False

    graph_data: dict[str, Any] = {}
    try:
        client = getattr(service, "client", None)
        runner = getattr(client, ce_method_name, None)
        if callable(runner):
            graph_data = runner(
                domain,
                max_depth=HIGH_VALUE_GROUP_ENRICHMENT_MAX_DEPTH,
                max_results=HIGH_VALUE_GROUP_ENRICHMENT_MAX_RESULTS,
            )
    except Exception as exc:  # pragma: no cover
        telemetry.capture_exception(exc)
        print_info_debug(f"[acct-ops] query failed: {exc}")
        return False

    candidates = _extract_candidate_paths(
        graph_data,
        domain=domain,
        source_group_label=source_group_label,
        max_depth=HIGH_VALUE_GROUP_ENRICHMENT_MAX_DEPTH,
    )
    # Filter out ADCS-dependent paths when no ADCS is present.
    has_adcs: bool | None = None
    filtered: list[tuple[list[dict[str, Any]], list[str]]] = []
    for nodes, rels in candidates:
        if _candidate_path_requires_adcs(nodes, domain):
            if has_adcs is None:
                has_adcs = domain_has_adcs_for_attack_steps(shell, domain)
            if not has_adcs:
                continue
        filtered.append((nodes, rels))

    if not filtered:
        print_info(
            f"No suitable escalation path found from {display_name} in {marked_domain}."
        )
        return False

    graph = load_attack_graph(shell, domain)

    # Persist all candidate paths so the central attack-path UX can recalculate
    # and present the enriched graph in one place.
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    total_edges_added = 0
    added_targets: set[str] = set()
    sampled_steps: list[str] = []
    sampled_seen: set[str] = set()
    sample_limit = _get_attack_step_sample_limit()
    show_samples = _should_show_attack_step_samples()
    source_group_canonical = source_group_label

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
            source_group_canonical = str(nodes[0].get("name") or source_group_canonical)

        target_label = str(nodes[-1].get("name") or "").strip()
        if target_label:
            added_targets.add(target_label)

        if show_samples and sample_limit > 0:
            node_labels = [user_label, source_group_canonical] + [
                str(n.get("name") or "") for n in nodes[1:]
            ]
            relations = ["MemberOf"] + list(rels)
            step_str = f"{mark_sensitive(node_labels[0], 'node')}"
            for idx, rel in enumerate(relations):
                step_str += f" -> {str(rel)} -> {mark_sensitive(node_labels[idx + 1], 'node')}"
            if step_str not in sampled_seen and len(sampled_steps) < sample_limit:
                sampled_seen.add(step_str)
                sampled_steps.append(step_str)

    if total_edges_added:
        save_attack_graph(shell, domain, graph)
        print_info(
            f"{display_name} enrichment: results={len(filtered)}; attack steps recorded={total_edges_added}."
        )
        sample_targets = sorted(added_targets)[:5]
        if sample_targets:
            sample_text = ", ".join(mark_sensitive(target, "group") for target in sample_targets)
            remaining = max(0, len(added_targets) - len(sample_targets))
            suffix = f" (+{remaining} more)" if remaining else ""
            print_info(
                f"Recorded {total_edges_added} {display_name}-derived attack step(s) into the attack graph. "
                f"New targets include: {sample_text}{suffix}."
            )
        else:
            print_info(
                f"Recorded {total_edges_added} {display_name}-derived attack step(s) into the attack graph."
            )
        if show_samples and sampled_steps:
            title = f"{display_name} enrichment - discovered steps"
            if sample_limit > 0 and len(sampled_steps) >= sample_limit:
                title = (
                    f"{display_name} enrichment - discovered steps "
                    f"(showing {len(sampled_steps)}/{total_edges_added})"
                )
            print_info_list(sampled_steps, title=title, icon="→")

    return bool(total_edges_added)


def offer_account_operators_escalation(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> bool:
    """Enrich the graph with Account Operators -> terminal attack steps."""
    return _offer_group_tier_zero_enrichment(
        shell,
        domain=domain,
        username=username,
        password=password,
        source_group_label=_account_operators_canonical(domain),
        display_name="Account Operators",
        ce_method_name="get_account_operators_paths_to_tier_zero_graph",
    )


def offer_exchange_windows_permissions_escalation(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> bool:
    """Enrich the graph with Exchange Windows Permissions -> terminal attack steps."""
    return _offer_group_tier_zero_enrichment(
        shell,
        domain=domain,
        username=username,
        password=password,
        source_group_label=_exchange_windows_permissions_canonical(domain),
        display_name="Exchange Windows Permissions",
        ce_method_name="get_exchange_windows_permissions_paths_to_tier_zero_graph",
    )


def offer_exchange_trusted_subsystem_escalation(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> bool:
    """Enrich the graph with Exchange Trusted Subsystem -> terminal attack steps."""
    return _offer_group_tier_zero_enrichment(
        shell,
        domain=domain,
        username=username,
        password=password,
        source_group_label=_exchange_trusted_subsystem_canonical(domain),
        display_name="Exchange Trusted Subsystem",
        ce_method_name="get_exchange_trusted_subsystem_paths_to_tier_zero_graph",
    )
