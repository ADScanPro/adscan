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
from collections.abc import Callable
from typing import Any

from adscan_internal.services.attack_step_support_registry import (
    CONTEXT_ONLY_RELATIONS,
)
from adscan_internal.workspaces import read_json_file

_LOCAL_REUSE_RELATION_KEY = "localadminpassreuse"


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


def display_record_signature(record: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return a case-insensitive deduplication signature for one display record.

    Attack-path records can occasionally differ only by label casing when
    multiple data sources persist semantically identical nodes (for example a
    BloodHound-backed `ESSOS.LOCAL` domain node and a synthetic `essos.local`
    node). The UI should treat those paths as the same path.

    Args:
        record: Display record produced by ``path_to_display_record``.

    Returns:
        Tuple ``(nodes, relations)`` normalized for case-insensitive matching.
    """
    nodes = tuple(str(node or "").strip().lower() for node in (record.get("nodes") or []))
    relations = tuple(
        str(relation or "").strip().lower() for relation in (record.get("relations") or [])
    )
    return nodes, relations


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
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "tier0",
    start_node_ids: set[str] | None = None,
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
        max_paths=max_paths,
        # Always compute all paths and apply filtering/promotion after.
        target="all",
        terminal_mode=mode,
        start_node_ids=start_node_ids,
    )

    results: list[dict[str, Any]] = []
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()

    for path in computed:
        candidate = path
        if target == "highvalue":
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
        elif target == "lowpriv":
            if _path_target_is_high_value(graph, path.target_id, mode=mode):
                continue

        record = path_to_display_record(graph, candidate)
        record["target_is_high_value"] = _path_target_is_high_value(
            graph, candidate.target_id, mode=mode
        )
        nodes = record.get("nodes")
        rels = record.get("relations")
        if not isinstance(nodes, list) or not isinstance(rels, list):
            continue
        key = display_record_signature(record)
        if key in seen:
            continue
        seen.add(key)
        results.append(record)

    return results


def filter_contained_paths_for_domain_listing(
    records: list[dict[str, Any]],
    *,
    keep_shortest: bool = False,
    is_hv_terminal: Callable[[dict[str, Any]], bool] | None = None,
    preserve_prefix_paths: bool = False,
) -> tuple[list[dict[str, Any]], int]:
    """Remove paths that are fully contained within another path.

    Args:
        records: Display path records to filter.
        keep_shortest: When False (default / domain scope), keep the longest
            path and remove shorter ones that are strict contiguous sub-paths of
            it — giving the most holistic attack chain view.  When True
            (owned / principals multi-user scope), keep the shortest path and
            remove longer paths that contain it — giving the most direct route
            to exploitation from already-compromised principals.
        is_hv_terminal: Optional callable returning True when a record's
            terminal node is high-value / tier-0.  Only used with
            ``keep_shortest=True``.  When provided the sort key becomes
            ``(not is_hv_terminal(rec), length)`` so that HV-terminal paths are
            processed before non-HV paths of the same or greater length.  This
            prevents a shorter non-HV path from shadowing a longer HV path:
            e.g.  ``A→B`` (non-HV) would otherwise mark ``A→B→C→HV`` as a
            super-path and drop it.
        preserve_prefix_paths: When True (non-domain scopes), a longer path is
            only considered redundant if the matching sub-sequence ends at the
            **same terminal node** as the longer path.  This prevents dropping
            ``A→B`` just because ``A→B→C`` exists — B and C are different
            exploitable targets.  When False (domain scope), all sub-sequences
            are marked as covered/shadowed regardless of their terminal, giving
            the most compact holistic view.
    """
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

    if not keep_shortest:
        # Domain mode: process longest-first; mark strict sub-paths as covered.
        #
        # preserve_prefix_paths=True  (non-domain callers): only sub-sequences
        #   ending at the same terminal as the kept path are shadowed.  These are
        #   exactly the strict suffixes of the kept path — O(L) per path.
        #
        # preserve_prefix_paths=False (domain scope): all strict contiguous
        #   sub-sequences are shadowed — O(L²) per path but unavoidable for the
        #   holistic domain view.
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
            if preserve_prefix_paths:
                # O(L): only strict suffixes share the same terminal by definition.
                # s=0 would be the full path itself — start from 1.
                for s in range(1, rel_len):
                    covered.add((nodes_t[s:], rels_t[s:]))
            else:
                # O(L²): mark every strict contiguous sub-sequence as covered.
                for start in range(0, rel_len):
                    for end in range(start + 1, rel_len + 1):
                        if end - start >= rel_len:
                            continue
                        covered.add((nodes_t[start : end + 1], rels_t[start:end]))
        return kept, removed
    else:
        # Owned/principals multi-user mode: keep the most direct path within
        # each contained group.  Sort key:
        #   (not is_hv, length)
        # HV-terminal paths get priority (False < True), then shorter within
        # the same HV category.  This ensures:
        #   • A shorter HV path beats a longer HV path              → keep shorter HV
        #   • A longer HV path beats a shorter non-HV path          → keep HV even if longer
        #   • Neither is HV → keep shorter                          → most direct route
        #
        # preserve_prefix_paths=True  (production path): a candidate is a
        #   super-path only when the shadowing sub-sequence ends at the same
        #   terminal.  These are the strict suffixes of the candidate — O(L).
        #
        # preserve_prefix_paths=False: any sub-sequence match suffices — O(L²).
        if is_hv_terminal is not None:
            normalized.sort(key=lambda item: (not is_hv_terminal(item[2]), len(item[1])))
        else:
            normalized.sort(key=lambda item: len(item[1]))
        kept_sigs: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
        # Store tuples so Pass 2 can access node/rel sequences without re-parsing.
        kept_entries: list[tuple[tuple[str, ...], tuple[str, ...], dict[str, Any]]] = []
        removed_multi = 0
        for nodes_t, rels_t, record in normalized:
            rel_len = len(rels_t)
            is_super_path = False
            if preserve_prefix_paths:
                # O(L): check only strict suffixes of the candidate — these end at
                # the same terminal by construction, so no per-iteration node check.
                # s=0 would be the full path (not a strict sub-path) — start from 1.
                for s in range(1, rel_len):
                    if (nodes_t[s:], rels_t[s:]) in kept_sigs:
                        is_super_path = True
                        break
            else:
                # O(L²): check all strict sub-sequences regardless of terminal.
                for start in range(0, rel_len):
                    for end in range(start + 1, rel_len + 1):
                        if end - start >= rel_len:
                            continue
                        if (nodes_t[start : end + 1], rels_t[start:end]) in kept_sigs:
                            is_super_path = True
                            break
                    if is_super_path:
                        break
            if is_super_path:
                removed_multi += 1
            else:
                kept_entries.append((nodes_t, rels_t, record))
                kept_sigs.add((nodes_t, rels_t))

        # Pass 2 — Case 1: remove strict prefixes (same source, different target).
        # Builds a set of every prefix sub-sequence (starting at index 0) that exists
        # inside a longer kept path.  A shorter path whose full signature appears in
        # this set is a strict prefix of some longer path and adds no information —
        # the intermediate node is already visible in the longer chain.
        #
        # HV-terminal paths are never dropped, even if they happen to be a prefix of
        # a longer non-HV path (e.g. "A→HV" survives when "A→HV→X" also exists).
        covered_prefixes: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
        for nodes_t, rels_t, _rec in kept_entries:
            for end in range(1, len(rels_t)):   # strict prefix: end < full length
                covered_prefixes.add((nodes_t[: end + 1], rels_t[:end]))

        pass2_kept: list[dict[str, Any]] = []
        pass2_removed = 0
        for nodes_t, rels_t, record in kept_entries:
            rec_is_hv = is_hv_terminal(record) if is_hv_terminal is not None else False
            if (nodes_t, rels_t) in covered_prefixes and not rec_is_hv:
                pass2_removed += 1
            else:
                pass2_kept.append(record)

        return pass2_kept, removed_multi + pass2_removed


def compute_display_paths_for_start_node(
    graph: dict[str, Any],
    *,
    start_node_id: str,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
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
        max_paths=max_paths,
        target="all",
        terminal_mode=mode,
    )

    results: list[dict[str, Any]] = []
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()

    for path in computed:
        candidate = path
        if target == "highvalue":
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
        elif target == "lowpriv":
            if _path_target_is_high_value(graph, path.target_id, mode=mode):
                continue

        record = path_to_display_record(graph, candidate)
        record["target_is_high_value"] = _path_target_is_high_value(
            graph, candidate.target_id, mode=mode
        )
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


def _build_local_reuse_virtual_state(
    nodes_map: dict[str, Any],
    edges: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], set[tuple[str, str]]]:
    """Build virtual-expansion state for compressed LocalAdminPassReuse groups.

    When LocalAdminPassReuse is persisted in compressed topology (star), this
    helper reconstructs group membership metadata so traversal can expand
    missing host-to-host relations virtually (without materializing N^2 edges).
    """
    existing_pairs: set[tuple[str, str]] = set()
    clusters: dict[tuple[str, str], dict[str, Any]] = {}

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation_key = str(edge.get("relation") or "").strip().lower()
        if relation_key != _LOCAL_REUSE_RELATION_KEY:
            continue

        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if from_id and to_id:
            existing_pairs.add((from_id, to_id))

        notes = edge.get("notes")
        if not isinstance(notes, dict):
            continue
        topology = str(notes.get("topology") or "").strip().lower()
        if topology != "star":
            # Mesh already has all relations materialized.
            continue

        local_user = str(notes.get("local_admin_username") or "").strip().lower()
        cluster_id = str(notes.get("reuse_cluster_id") or "").strip()
        if not cluster_id:
            # Backward-compatible fallback for legacy edges without cluster id.
            cluster_id = f"legacy:{local_user or 'unknown'}"

        cluster_key = (cluster_id, local_user)
        if cluster_key not in clusters:
            clusters[cluster_key] = {
                "cluster_id": cluster_id,
                "local_admin_username": notes.get("local_admin_username"),
                "node_ids": set(),
            }
        cluster = clusters[cluster_key]
        node_ids_set = cluster.get("node_ids")
        if isinstance(node_ids_set, set):
            if from_id in nodes_map:
                node_ids_set.add(from_id)
            if to_id in nodes_map:
                node_ids_set.add(to_id)
            raw_node_ids = notes.get("confirmed_node_ids")
            if isinstance(raw_node_ids, list):
                node_ids_set.update(
                    {
                        str(node_id).strip()
                        for node_id in raw_node_ids
                        if isinstance(node_id, str)
                        and str(node_id).strip()
                        and str(node_id).strip() in nodes_map
                    }
                )

    by_node: dict[str, list[dict[str, Any]]] = {}
    for cluster in clusters.values():
        node_ids_set = cluster.get("node_ids")
        if not isinstance(node_ids_set, set):
            continue
        node_ids = tuple(sorted({str(node_id) for node_id in node_ids_set}, key=str.lower))
        if len(node_ids) < 2:
            continue
        cluster["node_ids"] = node_ids
        for node_id in node_ids:
            by_node.setdefault(node_id, []).append(cluster)

    return by_node, existing_pairs


def _build_local_reuse_useful_node_ids(
    nodes_map: dict[str, Any],
    edges: list[dict[str, Any]],
) -> set[str]:
    """Return nodes worth targeting via LocalAdminPassReuse hops.

    We keep local-reuse transitions only when the destination node can produce
    non-context progress (e.g. AdminTo/HasSession/ExecuteDCOM) or is already a
    high-value node.
    """
    useful: set[str] = set()
    context_relations = {
        str(rel).strip().lower() for rel in CONTEXT_ONLY_RELATIONS.keys()
    }

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation_key = str(edge.get("relation") or "").strip().lower()
        if (
            not relation_key
            or relation_key == _LOCAL_REUSE_RELATION_KEY
            or relation_key in context_relations
        ):
            continue
        from_id = str(edge.get("from") or "").strip()
        if from_id:
            useful.add(from_id)

    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        if _node_is_effectively_high_value(node):
            useful.add(str(node_id))

    return useful


def _iter_outgoing_edges_with_virtual_local_reuse(
    current: str,
    *,
    adjacency: dict[str, list[dict[str, Any]]],
    acc_steps: list[AttackPathStep],
    local_reuse_by_node: dict[str, list[dict[str, Any]]],
    local_reuse_existing_pairs: set[tuple[str, str]],
    local_reuse_useful_nodes: set[str],
) -> list[dict[str, Any]]:
    """Return real + virtual outgoing edges for traversal.

    Virtual edges are only emitted for compressed (`topology=star`) local reuse
    clusters, and only for missing direct pairs not already materialized.
    """
    next_edges: list[dict[str, Any]] = []
    for edge in list(adjacency.get(current) or []):
        if not isinstance(edge, dict):
            continue
        relation_key = str(edge.get("relation") or "").strip().lower()
        if relation_key == _LOCAL_REUSE_RELATION_KEY:
            dst = str(edge.get("to") or "").strip()
            if not dst or dst not in local_reuse_useful_nodes:
                continue
        next_edges.append(edge)
    clusters = local_reuse_by_node.get(current) or []
    if not clusters:
        return next_edges

    last_step = acc_steps[-1] if acc_steps else None
    last_relation = (
        str(last_step.relation or "").strip().lower() if last_step else ""
    )
    last_cluster_id = (
        str((last_step.notes or {}).get("reuse_cluster_id") or "").strip()
        if last_step
        else ""
    )

    emitted_virtual_pairs: set[tuple[str, str]] = set()
    for cluster in clusters:
        cluster_id = str(cluster.get("cluster_id") or "").strip()
        # Avoid chaining the same local-reuse cluster repeatedly, which only
        # adds redundant permutations and increases path-search pressure.
        if (
            last_relation == _LOCAL_REUSE_RELATION_KEY
            and cluster_id
            and cluster_id == last_cluster_id
        ):
            continue
        for dst_id in cluster.get("node_ids") or []:
            dst = str(dst_id).strip()
            if not dst or dst == current:
                continue
            if dst not in local_reuse_useful_nodes:
                continue
            pair = (current, dst)
            if pair in local_reuse_existing_pairs or pair in emitted_virtual_pairs:
                continue
            emitted_virtual_pairs.add(pair)
            next_edges.append(
                {
                    "from": current,
                    "to": dst,
                    "relation": "LocalAdminPassReuse",
                    "status": "discovered",
                    "notes": {
                        "source": "local_reuse_virtual_expansion",
                        "virtual_expansion": True,
                        "reuse_cluster_id": cluster_id,
                        "local_admin_username": cluster.get(
                            "local_admin_username"
                        ),
                    },
                }
            )
    return next_edges


def _is_same_local_reuse_cluster_chain(
    previous_step: AttackPathStep | None,
    next_edge: dict[str, Any],
) -> bool:
    """Return True when two consecutive LocalAdminPassReuse hops use same cluster."""
    if previous_step is None:
        return False
    prev_relation = str(previous_step.relation or "").strip().lower()
    if prev_relation != _LOCAL_REUSE_RELATION_KEY:
        return False
    next_relation = str(next_edge.get("relation") or "").strip().lower()
    if next_relation != _LOCAL_REUSE_RELATION_KEY:
        return False
    prev_notes = previous_step.notes if isinstance(previous_step.notes, dict) else {}
    next_notes = next_edge.get("notes")
    next_notes = next_notes if isinstance(next_notes, dict) else {}
    prev_cluster = str(prev_notes.get("reuse_cluster_id") or "").strip()
    next_cluster = str(next_notes.get("reuse_cluster_id") or "").strip()
    if not prev_cluster or not next_cluster:
        return False
    return prev_cluster == next_cluster


def compute_maximal_attack_paths(
    graph: dict[str, Any],
    *,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    terminal_mode: str = "tier0",
    start_node_ids: set[str] | None = None,
) -> list[AttackPath]:
    """Compute maximal paths up to depth for a full-domain graph."""
    if max_depth <= 0:
        return []
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
    local_reuse_by_node, local_reuse_existing_pairs = (
        _build_local_reuse_virtual_state(nodes_map, edges)
    )
    local_reuse_useful_nodes = _build_local_reuse_useful_node_ids(nodes_map, edges)

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

    paths: list[AttackPath] = []
    seen_signatures: set[tuple[tuple[str, str, str], ...]] = set()

    def emit(acc_steps: list[AttackPathStep]) -> None:
        if not acc_steps:
            return
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        if (target == "highvalue" and not is_terminal(acc_steps[-1].to_id)) or (target == "lowpriv" and is_terminal(acc_steps[-1].to_id)):
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
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        depth = len(acc_steps)
        if depth >= max_depth or (depth > 0 and is_terminal(current)):
            emit(acc_steps)
            return

        next_edges = _iter_outgoing_edges_with_virtual_local_reuse(
            current,
            adjacency=adjacency,
            acc_steps=acc_steps,
            local_reuse_by_node=local_reuse_by_node,
            local_reuse_existing_pairs=local_reuse_existing_pairs,
            local_reuse_useful_nodes=local_reuse_useful_nodes,
        )
        if not next_edges:
            emit(acc_steps)
            return

        extended = False
        for edge in next_edges:
            last_step = acc_steps[-1] if acc_steps else None
            if _is_same_local_reuse_cluster_chain(last_step, edge):
                continue
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
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            break
        dfs(source, visited={source}, acc_steps=[])

    return paths


def compute_maximal_attack_paths_from_start(
    graph: dict[str, Any],
    *,
    start_node_id: str,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    terminal_mode: str = "tier0",
) -> list[AttackPath]:
    """Compute maximal paths starting from a specific node."""
    if max_depth <= 0 or not start_node_id:
        return []
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
    local_reuse_by_node, local_reuse_existing_pairs = (
        _build_local_reuse_virtual_state(nodes_map, edges)
    )
    local_reuse_useful_nodes = _build_local_reuse_useful_node_ids(nodes_map, edges)

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
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        if (target == "highvalue" and not is_terminal(acc_steps[-1].to_id)) or (target == "lowpriv" and is_terminal(acc_steps[-1].to_id)):
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
        if max_paths_cap is not None and len(paths) >= max_paths_cap:
            return
        depth = len(acc_steps)
        if depth >= max_depth or (depth > 0 and is_terminal(current)):
            emit(acc_steps)
            return

        next_edges = _iter_outgoing_edges_with_virtual_local_reuse(
            current,
            adjacency=adjacency,
            acc_steps=acc_steps,
            local_reuse_by_node=local_reuse_by_node,
            local_reuse_existing_pairs=local_reuse_existing_pairs,
            local_reuse_useful_nodes=local_reuse_useful_nodes,
        )
        if not next_edges:
            emit(acc_steps)
            return

        extended = False
        for edge in next_edges:
            last_step = acc_steps[-1] if acc_steps else None
            if _is_same_local_reuse_cluster_chain(last_step, edge):
                continue
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


def collect_source_step_signatures_on_high_value_paths(
    graph: dict[str, Any],
    *,
    start_node_id: str,
    max_depth: int,
    target_mode: str = "tier0",
) -> set[tuple[str, str, str]]:
    """Return source-edge signatures that participate in HV/tier-zero paths.

    This helper is intentionally lower-level than the CLI display pipeline. It
    reuses the core DFS and high-value promotion semantics, but skips all
    display-only minimization, deduplication, and UX shaping.

    Args:
        graph: In-memory attack graph.
        start_node_id: Source node id to expand from.
        max_depth: Maximum path depth.
        target_mode: ``"tier0"`` or ``"impact"``. ``"tier0"`` is the default
            so intermediate high-value pivots do not stop expansion early.

    Returns:
        Set of ``(from_id, relation, to_id)`` signatures for steps that start
        at ``start_node_id`` and are part of at least one path that reaches a
        high-value / tier-zero target under the same promotion semantics used by
        display-path generation.
    """
    mode = (target_mode or "tier0").strip().lower()
    if mode not in {"tier0", "impact"}:
        mode = "tier0"

    required_rank = 1 if mode == "impact" else 3
    results: set[tuple[str, str, str]] = set()

    for path in compute_maximal_attack_paths_from_start(
        graph,
        start_node_id=start_node_id,
        max_depth=max_depth,
        max_paths=None,
        target="all",
        terminal_mode=mode,
    ):
        candidate = path
        if not _path_target_is_high_value(graph, path.target_id, mode=mode):
            promoted = _try_promote_target_via_membership_edges(
                graph,
                path,
                required_rank=required_rank,
                mode=mode,
            )
            if not promoted:
                continue
            candidate = promoted

        for step in candidate.steps:
            if step.from_id != start_node_id:
                continue
            results.add((step.from_id, step.relation, step.to_id))

    return results


def path_to_display_record(graph: dict[str, Any], path: AttackPath) -> dict[str, Any]:
    """Convert an AttackPath to the CLI/UI-friendly dict shape."""
    from adscan_internal.services.attack_step_support_registry import (
        classify_relation_support,
    )

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    context_relations = {
        str(rel).strip().lower() for rel in CONTEXT_ONLY_RELATIONS.keys()
    }

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


def _node_is_enabled_user(node: dict[str, Any]) -> bool:
    """Return True when the node represents an enabled user principal."""
    if str(node.get("kind") or "") != "User":
        return False
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    enabled = props.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    enabled = node.get("enabled")
    return enabled is True


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
