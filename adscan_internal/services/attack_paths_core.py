"""Attack path computation core (pure functions).

This module centralizes attack-path display logic so both CLI and web can
produce identical results using the same inputs (attack_graph + memberships).
It performs no I/O and does not depend on shell context.
"""

from __future__ import annotations

import os
import re
from typing import Any, Callable, Iterable

from adscan_internal.services import attack_graph_core


_EMPTY_GROUP_WHITELIST = {
    item.strip().upper()
    for item in os.getenv(
        "ADSCAN_ATTACK_PATH_EMPTY_GROUP_WHITELIST", "S-1-5-7,S-1-5-32-546,S-1-5-32-514"
    ).split(",")
    if item.strip()
}

_SID_PATTERN = re.compile(r"(S-1-\d+(?:-\d+)+)", re.IGNORECASE)


def _extract_sid(value: str) -> str | None:
    if not value:
        return None
    match = _SID_PATTERN.search(value)
    if not match:
        return None
    return match.group(1).upper()


def _empty_group_whitelist(domain: str) -> set[str]:
    normalized: set[str] = set()
    domain_value = str(domain or "").strip()
    for item in _EMPTY_GROUP_WHITELIST:
        if not item:
            continue
        expanded = item
        if "{domain}" in expanded.lower():
            expanded = expanded.replace("{domain}", domain_value).replace(
                "{DOMAIN}", domain_value
            )
        expanded = expanded.strip()
        normalized.add(expanded.upper())
        if not _extract_sid(expanded):
            normalized.add(_canonical_membership_label(domain, expanded))
    return normalized


def _is_empty_group_whitelisted(
    domain: str, source_label: str, source_sid: str | None
) -> bool:
    if not source_label and not source_sid:
        return False
    whitelist = _empty_group_whitelist(domain)
    normalized_raw = str(source_label or "").strip().upper()
    canonical = _canonical_membership_label(domain, source_label)
    if source_sid:
        normalized_sid = _extract_sid(source_sid)
        if normalized_sid and normalized_sid in whitelist:
            return True
    return normalized_raw in whitelist or canonical in whitelist


def prepare_membership_snapshot(
    data: dict[str, Any] | None, domain: str
) -> dict[str, Any] | None:
    """Normalize memberships.json into a consistent snapshot structure."""
    if not isinstance(data, dict):
        return None

    if isinstance(data.get("user_to_groups"), dict) or isinstance(
        data.get("group_to_parents"), dict
    ):
        normalized = dict(data)
        normalized.setdefault("tier0_users", [])
        return normalized

    nodes_map = data.get("nodes")
    edges = data.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return None

    user_to_groups: dict[str, set[str]] = {}
    computer_to_groups: dict[str, set[str]] = {}
    group_to_parents: dict[str, set[str]] = {}
    label_to_sid: dict[str, str] = {}
    sid_to_label: dict[str, str] = {}
    domain_sid: str | None = None
    preferred_domain_sid: str | None = None
    first_domain_sid: str | None = None
    tier0_users: set[str] = set()

    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        label = _canonical_membership_label(domain, _canonical_node_label(node))
        if not label:
            continue
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        object_id = str(
            node.get("objectId") or props.get("objectid") or props.get("objectId") or ""
        ).strip()
        sid = _extract_sid(object_id)
        if sid:
            label_to_sid[label] = sid
            sid_to_label.setdefault(sid, label)
            if sid.startswith("S-1-5-21-"):
                parts = sid.split("-")
                if len(parts) >= 5:
                    candidate_sid = "-".join(parts[:-1])
                    if not first_domain_sid:
                        first_domain_sid = candidate_sid
                    if not preferred_domain_sid:
                        label_domain = str(domain or "").strip().upper()
                        label_match = label.endswith(f"@{label_domain}")
                        rid = parts[-1]
                        preferred_rids = {
                            "512",
                            "513",
                            "514",
                            "515",
                            "516",
                            "517",
                            "518",
                            "519",
                            "520",
                        }
                        if label_match and rid in preferred_rids:
                            preferred_domain_sid = candidate_sid
        if _node_kind(node) == "User" and _node_is_high_value(node):
            tier0_users.add(label)

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = edge.get("relation") or edge.get("label") or edge.get("kind") or ""
        if str(relation) != "MemberOf":
            continue
        from_id = edge.get("from") or edge.get("source")
        to_id = edge.get("to") or edge.get("target")
        if not from_id or not to_id:
            continue
        from_node = nodes_map.get(str(from_id))
        to_node = nodes_map.get(str(to_id))
        if not isinstance(from_node, dict) or not isinstance(to_node, dict):
            continue
        if _node_kind(to_node) != "Group":
            continue

        from_label = _canonical_membership_label(
            domain, _canonical_node_label(from_node)
        )
        to_label = _canonical_membership_label(domain, _canonical_node_label(to_node))
        if not from_label or not to_label:
            continue

        from_kind = _node_kind(from_node)
        if from_kind == "User":
            user_to_groups.setdefault(from_label, set()).add(to_label)
        elif from_kind == "Computer":
            computer_to_groups.setdefault(from_label, set()).add(to_label)
        elif from_kind == "Group":
            group_to_parents.setdefault(from_label, set()).add(to_label)

    domain_sid = preferred_domain_sid or first_domain_sid
    return {
        "user_to_groups": {
            user: sorted(groups, key=str.lower)
            for user, groups in sorted(user_to_groups.items())
        },
        "computer_to_groups": {
            computer: sorted(groups, key=str.lower)
            for computer, groups in sorted(computer_to_groups.items())
        },
        "group_to_parents": {
            group: sorted(parents, key=str.lower)
            for group, parents in sorted(group_to_parents.items())
        },
        "tier0_users": sorted(tier0_users, key=str.lower),
        "label_to_sid": label_to_sid,
        "sid_to_label": sid_to_label,
        "domain_sid": domain_sid,
    }


def _canonical_membership_label(domain: str, value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "@" in raw:
        left, _, right = raw.partition("@")
        if left and right:
            return f"{left.strip().upper()}@{right.strip().upper()}"
    return f"{raw.upper()}@{str(domain or '').strip().upper()}"


def _membership_label_to_name(label: str) -> str:
    raw = str(label or "").strip()
    if "@" in raw:
        return raw.split("@", 1)[0].strip()
    return raw


def _normalize_account(value: str) -> str:
    name = (value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def _canonical_node_label(node: dict[str, Any]) -> str:
    label = node.get("label") or node.get("name")
    if isinstance(label, str) and label.strip():
        return label.strip()
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    name = props.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return str(label or "").strip()


def _node_kind(node: dict[str, Any]) -> str:
    kind = node.get("kind") or node.get("labels") or node.get("type")
    if isinstance(kind, list) and kind:
        preferred = {
            "User",
            "Computer",
            "Group",
            "Domain",
            "GPO",
            "OU",
            "Container",
            "CertTemplate",
            "EnterpriseCA",
            "AIACA",
            "RootCA",
            "NTAuthStore",
        }
        for entry in kind:
            if str(entry) in preferred:
                return str(entry)
        return str(kind[0])
    if isinstance(kind, str) and kind:
        return kind
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    fallback = props.get("type") or props.get("objecttype")
    if isinstance(fallback, str) and fallback:
        return fallback
    return "Unknown"


def _node_is_high_value(node: dict[str, Any]) -> bool:
    if bool(node.get("isTierZero")):
        return True
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if bool(props.get("isTierZero")):
        return True
    tags = node.get("system_tags") or props.get("system_tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return any(str(tag).lower() == "admin_tier_0" for tag in tags)


def _graph_has_persisted_memberships(graph: dict[str, Any]) -> bool:
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return False
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "") != "MemberOf":
            continue
        edge_type = str(edge.get("edge_type") or edge.get("type") or "")
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        source = str(notes.get("source") or "")
        if edge_type == "membership" or source == "derived_membership":
            return True
    return False


def _find_node_id_by_label(graph: dict[str, Any], label: str) -> str | None:
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return None
    normalized = _normalize_account(label)

    def _quality_score(node: dict[str, Any]) -> int:
        score = 0
        kind = _node_kind(node)
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )

        if kind != "Unknown":
            score += 50
        else:
            score -= 50

        if kind in {"User", "Computer"}:
            if str(props.get("samaccountname") or "").strip():
                score += 30
            if str(props.get("domain") or "").strip():
                score += 10
        if kind == "Group":
            if str(node.get("objectId") or props.get("objectid") or "").strip():
                score += 20

        if props:
            score += 10
        if str(node.get("objectId") or "").strip():
            score += 5
        return score

    matches: list[tuple[int, str]] = []
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        node_label = str(node.get("label") or "")
        if _normalize_account(node_label) != normalized:
            continue
        matches.append((_quality_score(node), str(node_id)))

    if not matches:
        return None

    matches.sort(key=lambda x: (-x[0], x[1]))
    return matches[0][1]


def _ensure_group_node_id(graph: dict[str, Any], *, domain: str, label: str) -> str:
    nodes_map = graph.get("nodes")
    if not isinstance(nodes_map, dict):
        return ""
    canonical = _canonical_membership_label(domain, label)
    existing = _find_node_id_by_label(graph, canonical)
    if existing:
        return existing
    node_id = f"name:{canonical}"
    nodes_map[node_id] = {
        "id": node_id,
        "label": canonical,
        "kind": "Group",
        "properties": {"name": canonical, "domain": str(domain or "").strip().upper()},
    }
    return node_id


def _expand_group_ancestors(
    domain: str,
    group_label: str,
    group_to_parents: dict[str, Any],
    cache: dict[str, set[str]],
) -> set[str]:
    if group_label in cache:
        return cache[group_label]
    parents = group_to_parents.get(group_label, []) if group_to_parents else []
    results: set[str] = set()
    if isinstance(parents, list):
        for parent in parents:
            parent_label = _canonical_membership_label(domain, parent)
            if not parent_label:
                continue
            results.add(parent_label)
            results.update(
                _expand_group_ancestors(domain, parent_label, group_to_parents, cache)
            )
    cache[group_label] = results
    return results


def build_group_membership_index(
    snapshot: dict[str, Any] | None,
    domain: str,
    *,
    principal_labels: Iterable[str] | None = None,
    sample_limit: int = 3,
) -> tuple[dict[str, int], dict[str, list[str]]]:
    if not snapshot:
        return {}, {}

    user_to_groups = snapshot.get("user_to_groups")
    computer_to_groups = snapshot.get("computer_to_groups")
    group_to_parents = snapshot.get("group_to_parents")
    if not isinstance(user_to_groups, dict) and not isinstance(
        computer_to_groups, dict
    ):
        return {}, {}

    principals: list[str] = []
    if principal_labels is None:
        if isinstance(user_to_groups, dict):
            principals.extend(user_to_groups.keys())
        if isinstance(computer_to_groups, dict):
            principals.extend(computer_to_groups.keys())
    else:
        for principal in principal_labels:
            canonical = _canonical_membership_label(domain, principal)
            if canonical:
                principals.append(canonical)

    counts: dict[str, int] = {}
    samples: dict[str, list[str]] = {}
    ancestor_cache: dict[str, set[str]] = {}
    parents_map = group_to_parents if isinstance(group_to_parents, dict) else {}

    for principal in principals:
        direct_groups: list[str] = []
        if isinstance(user_to_groups, dict):
            direct_groups = user_to_groups.get(principal, []) or []
        if not direct_groups and isinstance(computer_to_groups, dict):
            direct_groups = computer_to_groups.get(principal, []) or []

        if not isinstance(direct_groups, list):
            continue

        for group in direct_groups:
            group_label = _canonical_membership_label(domain, group)
            if not group_label:
                continue
            groups_to_count = {group_label}
            groups_to_count.update(
                _expand_group_ancestors(
                    domain, group_label, parents_map, ancestor_cache
                )
            )
            for counted_group in groups_to_count:
                counts[counted_group] = counts.get(counted_group, 0) + 1
                if sample_limit <= 0:
                    continue
                sample = samples.setdefault(counted_group, [])
                if principal not in sample and len(sample) < sample_limit:
                    sample.append(principal)

    return counts, samples


def build_group_member_index(
    snapshot: dict[str, Any] | None,
    domain: str,
    *,
    exclude_tier0: bool = False,
) -> tuple[dict[str, set[str]], bool]:
    if not snapshot:
        return {}, False

    user_to_groups = snapshot.get("user_to_groups")
    group_to_parents = snapshot.get("group_to_parents")
    if not isinstance(user_to_groups, dict):
        return {}, False

    has_users = bool(user_to_groups)
    group_members: dict[str, set[str]] = {}
    ancestor_cache: dict[str, set[str]] = {}
    parents_map = group_to_parents if isinstance(group_to_parents, dict) else {}

    tier0_users: set[str] = set()
    if exclude_tier0:
        tier0_from_snapshot = snapshot.get("tier0_users")
        if isinstance(tier0_from_snapshot, list):
            tier0_users.update(
                _canonical_membership_label(domain, user)
                for user in tier0_from_snapshot
                if str(user or "").strip()
            )

    for user_label, direct_groups in user_to_groups.items():
        if not isinstance(direct_groups, list):
            continue
        canonical_user = _canonical_membership_label(domain, user_label)
        if not canonical_user:
            continue
        if exclude_tier0 and canonical_user in tier0_users:
            continue

        for group in direct_groups:
            group_label = _canonical_membership_label(domain, group)
            if not group_label:
                continue
            groups_to_add = {group_label}
            groups_to_add.update(
                _expand_group_ancestors(
                    domain, group_label, parents_map, ancestor_cache
                )
            )
            for ancestor in groups_to_add:
                group_members.setdefault(ancestor, set()).add(canonical_user)

    return group_members, has_users


def _strip_leading_relations(
    record: dict[str, Any],
    *,
    relations_to_strip: set[str],
) -> tuple[dict[str, Any], int]:
    nodes = record.get("nodes")
    rels = record.get("relations")
    steps = record.get("steps")
    if (
        not isinstance(nodes, list)
        or not isinstance(rels, list)
        or not isinstance(steps, list)
    ):
        return record, 0

    strip_count = 0
    for rel in rels:
        if str(rel) in relations_to_strip:
            strip_count += 1
            continue
        break

    if strip_count <= 0:
        return record, 0

    new_nodes = [str(n) for n in nodes[strip_count:]]
    new_rels = [str(r) for r in rels[strip_count:]]
    kept_steps = [step for step in steps[strip_count:] if isinstance(step, dict)]
    for idx, step in enumerate(kept_steps, start=1):
        step["step"] = idx

    new_record: dict[str, Any] = dict(record)
    new_record["nodes"] = new_nodes
    new_record["relations"] = new_rels
    new_record["length"] = sum(
        1 for rel in new_rels if str(rel or "").strip().lower() != "memberof"
    )
    new_record["source"] = new_nodes[0] if new_nodes else ""
    new_record["target"] = new_nodes[-1] if new_nodes else ""
    new_record["steps"] = kept_steps
    new_record["status"] = _derive_display_status_from_steps(kept_steps)
    return new_record, strip_count


def _derive_display_status_from_steps(steps: list[dict[str, Any]]) -> str:
    statuses: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        if action == "memberof":
            continue
        value = step.get("status")
        if isinstance(value, str) and value:
            statuses.append(value.strip().lower())

    if statuses and all(status == "success" for status in statuses):
        return "exploited"
    if any(status in {"attempted", "failed", "error"} for status in statuses):
        return "attempted"
    if any(status == "unavailable" for status in statuses):
        return "unavailable"
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if any(status == "unsupported" for status in statuses):
        return "unsupported"
    # Use support registry (not a hardcoded list) for policy-blocked relations.
    from adscan_internal.services.attack_step_support_registry import (
        classify_relation_support,
    )

    if any(
        classify_relation_support(str(step.get("action") or "").strip().lower()).kind
        == "policy_blocked"
        for step in steps
        if isinstance(step, dict)
        and str(step.get("action") or "").strip().lower() != "memberof"
    ):
        return "blocked"
    return "theoretical"


def _strip_leading_steps(
    record: dict[str, Any],
    *,
    count: int,
) -> dict[str, Any] | None:
    nodes = record.get("nodes")
    rels = record.get("relations")
    steps = record.get("steps")
    if (
        not isinstance(nodes, list)
        or not isinstance(rels, list)
        or not isinstance(steps, list)
    ):
        return None
    if count <= 0 or count > len(rels):
        return None

    new_nodes = [str(n) for n in nodes[count:]]
    new_rels = [str(r) for r in rels[count:]]
    kept_steps = [step for step in steps[count:] if isinstance(step, dict)]
    for idx, step in enumerate(kept_steps, start=1):
        step["step"] = idx

    new_record: dict[str, Any] = dict(record)
    new_record["nodes"] = new_nodes
    new_record["relations"] = new_rels
    new_record["length"] = sum(
        1 for rel in new_rels if str(rel or "").strip().lower() != "memberof"
    )
    new_record["source"] = new_nodes[0] if new_nodes else ""
    new_record["target"] = new_nodes[-1] if new_nodes else ""
    new_record["steps"] = kept_steps
    new_record["status"] = _derive_display_status_from_steps(kept_steps)
    if not new_rels or len(new_nodes) < 2:
        return None
    return new_record


def collapse_memberof_prefixes(
    records: list[dict[str, Any]],
    domain: str,
    snapshot: dict[str, Any] | None,
    *,
    principal_labels: Iterable[str] | None = None,
    sample_limit: int = 3,
) -> list[dict[str, Any]]:
    if not records:
        return []

    counts, samples = build_group_membership_index(
        snapshot, domain, principal_labels=principal_labels, sample_limit=sample_limit
    )
    grouped: dict[tuple[tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}

    for record in records:
        nodes = record.get("nodes")
        rels = record.get("relations")
        if not isinstance(nodes, list) or not isinstance(rels, list):
            continue
        collapsed_record = record
        if rels and str(rels[0]) == "MemberOf" and len(nodes) > 1 and counts:
            group_label = _canonical_membership_label(domain, str(nodes[1]))
            member_count = counts.get(group_label, 0)
            if member_count > 1:
                collapsed_record, _ = _strip_leading_relations(
                    record, relations_to_strip={"MemberOf"}
                )
                sample_users = samples.get(group_label, [])
                if sample_users:
                    collapsed_record = dict(collapsed_record)
                    collapsed_record["applies_to_users"] = sample_users

        collapsed_nodes = collapsed_record.get("nodes")
        collapsed_rels = collapsed_record.get("relations")
        if not isinstance(collapsed_nodes, list) or not isinstance(
            collapsed_rels, list
        ):
            continue
        key = (
            tuple(str(n) for n in collapsed_nodes),
            tuple(str(r) for r in collapsed_rels),
        )
        existing = grouped.get(key)
        if existing and isinstance(existing, dict):
            applies = existing.get("applies_to_users")
            incoming = collapsed_record.get("applies_to_users")
            if isinstance(applies, list) and isinstance(incoming, list):
                merged = list(dict.fromkeys(applies + incoming))
                existing["applies_to_users"] = merged[:sample_limit]
            elif isinstance(incoming, list):
                existing["applies_to_users"] = incoming[:sample_limit]
            continue
        grouped[key] = collapsed_record

    return list(grouped.values())


def apply_affected_user_metadata(
    records: list[dict[str, Any]],
    *,
    graph: dict[str, Any],
    domain: str,
    snapshot: dict[str, Any] | None,
    filter_empty: bool = True,
) -> list[dict[str, Any]]:
    if not records:
        return []

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    label_kind_map: dict[str, str] = {}
    label_sid_map: dict[str, str] = {}
    if isinstance(nodes_map, dict):
        for node in nodes_map.values():
            if not isinstance(node, dict):
                continue
            label = str(node.get("label") or "")
            if not label:
                continue
            canonical_label = _canonical_membership_label(domain, label)
            label_kind_map[canonical_label] = _node_kind(node)
            props = (
                node.get("properties")
                if isinstance(node.get("properties"), dict)
                else {}
            )
            object_id = str(node.get("objectId") or props.get("objectid") or "")
            sid = _extract_sid(object_id)
            if sid:
                label_sid_map[canonical_label] = sid

    group_members, has_users = build_group_member_index(
        snapshot, domain, exclude_tier0=True
    )
    if not has_users:
        return records

    annotated: list[dict[str, Any]] = []
    for record in records:
        current = record
        while True:
            nodes = current.get("nodes")
            if not isinstance(nodes, list) or not nodes:
                annotated.append(current)
                break
            rels = current.get("relations")
            if not isinstance(rels, list):
                annotated.append(current)
                break
            source_label = str(nodes[0] or "").strip()
            canonical_source = _canonical_membership_label(domain, source_label)
            kind = label_kind_map.get(canonical_source, "")

            affected_users: list[str] = []
            affected_count = 0
            if kind == "Group":
                members = sorted(
                    group_members.get(canonical_source, set()), key=str.lower
                )
                affected_users = members
                affected_count = len(members)
            elif source_label:
                affected_users = [source_label]
                affected_count = 1

            if filter_empty and kind == "Group" and affected_count == 0:
                source_sid = label_sid_map.get(canonical_source)
                if not _is_empty_group_whitelisted(domain, source_label, source_sid):
                    stripped = _strip_leading_steps(current, count=1)
                    if stripped is None:
                        break
                    current = stripped
                    continue

            if (
                rels
                and str(rels[0] or "").strip().lower() == "memberof"
                and len(nodes) > 1
            ):
                group_label = _canonical_membership_label(domain, str(nodes[1]))
                member_count = len(group_members.get(group_label, set()))
                if member_count > 1:
                    stripped_record, stripped_count = _strip_leading_relations(
                        current, relations_to_strip={"MemberOf"}
                    )
                    if stripped_count > 0:
                        current = stripped_record
                        continue

            if "meta" in current and not isinstance(current.get("meta"), dict):
                current = dict(current)
                current["meta"] = {}
            elif "meta" not in current:
                current = dict(current)
                current["meta"] = {}
            meta = current["meta"]
            if isinstance(meta, dict):
                meta.setdefault("affected_users", affected_users)
                meta.setdefault("affected_user_count", affected_count)
            annotated.append(current)
            break

    return annotated


def dedupe_exact_display_paths(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if len(records) <= 1:
        return records

    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    deduped: list[dict[str, Any]] = []
    for record in records:
        nodes = record.get("nodes")
        rels = record.get("relations")
        if not isinstance(nodes, list) or not isinstance(rels, list):
            continue
        key = (tuple(str(n) for n in nodes), tuple(str(r) for r in rels))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)

    return deduped


def minimize_display_paths(
    records: list[dict[str, Any]],
    *,
    domain: str,
    snapshot: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Minimize confusing/redundant prefixes in display records.

    This is intentionally a *display-layer* transformation: it does not change
    the underlying graph or which maximal paths exist. It only rewrites how a
    path is shown to the user.

    Current minimizations:
    1) Redundant `MemberOf` pivots:
       If a path contains `... -> X -> MemberOf -> G -> ...` but some prior
       principal already belonged to `G`, the `X -> MemberOf -> G` portion is
       redundant and we strip the prefix so the path starts at `G`.
    2) Repeated nodes (by label):
       If the same node label appears multiple times in a record, we strip the
       prefix up to the *last* occurrence to avoid "loop-like" rendering.
    """
    if not records:
        return records

    def _recompute_status(record: dict[str, Any]) -> dict[str, Any]:
        steps = record.get("steps")
        if isinstance(steps, list):
            record = dict(record)
            record["status"] = _derive_display_status_from_steps(steps)
        return record

    if not snapshot:
        # Still allow label-based minimization (2) when no snapshot is available.
        return [
            _recompute_status(_minimize_display_record_by_repeated_labels(record))
            for record in records
        ]

    user_to_groups = (
        snapshot.get("user_to_groups") if isinstance(snapshot, dict) else {}
    )
    computer_to_groups = (
        snapshot.get("computer_to_groups") if isinstance(snapshot, dict) else {}
    )
    group_to_parents = (
        snapshot.get("group_to_parents") if isinstance(snapshot, dict) else {}
    )

    principal_groups_cache: dict[str, set[str]] = {}
    ancestor_cache: dict[str, set[str]] = {}

    def principal_group_closure(principal_label: str) -> set[str]:
        canonical_principal = _canonical_membership_label(domain, principal_label)
        cached = principal_groups_cache.get(canonical_principal)
        if cached is not None:
            return cached

        direct: list[str] = []
        if isinstance(user_to_groups, dict) and canonical_principal in user_to_groups:
            direct = user_to_groups.get(canonical_principal, []) or []
        elif (
            isinstance(computer_to_groups, dict)
            and canonical_principal in computer_to_groups
        ):
            direct = computer_to_groups.get(canonical_principal, []) or []

        groups: set[str] = set()
        if isinstance(direct, list):
            for group in direct:
                group_label = _canonical_membership_label(domain, str(group))
                if not group_label:
                    continue
                groups.add(group_label)
                parents = _expand_group_ancestors(
                    domain, group_label, group_to_parents, ancestor_cache
                )
                groups.update(parents)

        principal_groups_cache[canonical_principal] = groups
        return groups

    minimized: list[dict[str, Any]] = []
    for record in records:
        updated = _minimize_display_record_by_redundant_memberof(
            record,
            domain=domain,
            principal_group_closure=principal_group_closure,
            user_to_groups=user_to_groups,
            computer_to_groups=computer_to_groups,
        )
        updated = _minimize_display_record_by_repeated_labels(updated)
        minimized.append(_recompute_status(updated))
    return minimized


def _strip_display_record_prefix(
    record: dict[str, Any],
    *,
    start_node_index: int,
    reason: str,
) -> dict[str, Any]:
    """Return a copy of `record` starting from `nodes[start_node_index]`."""
    nodes = record.get("nodes")
    rels = record.get("relations")
    if not isinstance(nodes, list) or not isinstance(rels, list):
        return record

    if start_node_index <= 0:
        return record
    if start_node_index >= len(nodes) - 1:
        # Would remove all executable steps; keep original.
        return record
    if start_node_index > len(rels):
        return record

    new_record: dict[str, Any] = dict(record)
    new_nodes = list(nodes[start_node_index:])
    new_rels = list(rels[start_node_index:])
    new_record["nodes"] = new_nodes
    new_record["relations"] = new_rels

    if isinstance(new_record.get("source"), str):
        new_record["source"] = str(new_nodes[0])
    if isinstance(new_record.get("target"), str):
        new_record["target"] = str(new_nodes[-1])

    # Align `steps` with relations.
    steps = record.get("steps")
    if isinstance(steps, list):
        trimmed_steps = [s for s in steps[start_node_index:] if isinstance(s, dict)]
        for idx, step in enumerate(trimmed_steps, start=1):
            step["step"] = idx
        new_record["steps"] = trimmed_steps

    # Recompute display length to match what is shown.
    new_record["length"] = sum(
        1 for rel in new_rels if str(rel or "").strip().lower() != "memberof"
    )
    new_record["status"] = _derive_display_status_from_steps(
        new_record.get("steps", [])
    )

    meta = new_record.get("meta")
    if meta is None:
        meta = {}
        new_record["meta"] = meta
    if isinstance(meta, dict):
        meta.setdefault("full_length", record.get("length"))
        meta["minimized"] = True
        meta["minimized_reason"] = reason
        meta["minimized_start_label"] = str(new_nodes[0])
    return new_record


def _minimize_display_record_by_redundant_memberof(
    record: dict[str, Any],
    *,
    domain: str,
    principal_group_closure: Callable[[str], set[str]],
    user_to_groups: object,
    computer_to_groups: object,
) -> dict[str, Any]:
    nodes = record.get("nodes")
    rels = record.get("relations")
    if not isinstance(nodes, list) or not isinstance(rels, list) or not nodes:
        return record

    # Track groups that are already satisfied by earlier principals.
    satisfied_groups: set[str] = set()
    seen_principals: set[str] = set()
    redundant_memberof_indices: list[int] = []

    for rel_idx, rel in enumerate(rels):
        if rel_idx >= len(nodes):
            break
        current = str(nodes[rel_idx] or "").strip()
        if current:
            canonical = _canonical_membership_label(domain, current)
            # Only treat labels that exist in membership maps as principals.
            is_principal = False
            if isinstance(user_to_groups, dict) and canonical in user_to_groups:
                is_principal = True
            if (
                not is_principal
                and isinstance(computer_to_groups, dict)
                and canonical in computer_to_groups
            ):
                is_principal = True
            if is_principal and canonical not in seen_principals:
                seen_principals.add(canonical)
                satisfied_groups.update(principal_group_closure(current))

        if str(rel or "").strip().lower() != "memberof":
            continue
        if rel_idx + 1 >= len(nodes):
            continue
        group_label = _canonical_membership_label(domain, str(nodes[rel_idx + 1]))
        if group_label and group_label in satisfied_groups:
            redundant_memberof_indices.append(rel_idx)

    if not redundant_memberof_indices:
        return record

    # Strip to the last redundant MemberOf pivot (closest to the terminal action).
    last_idx = redundant_memberof_indices[-1]
    return _strip_display_record_prefix(
        record,
        start_node_index=last_idx + 1,
        reason="redundant_memberof",
    )


def _minimize_display_record_by_repeated_labels(
    record: dict[str, Any],
) -> dict[str, Any]:
    nodes = record.get("nodes")
    rels = record.get("relations")
    if not isinstance(nodes, list) or not isinstance(rels, list) or len(nodes) <= 1:
        return record

    last_seen: dict[str, int] = {}
    for idx, node in enumerate(nodes):
        label = str(node or "").strip().lower()
        if not label:
            continue
        last_seen[label] = idx

    # Find the latest index that repeats some earlier label.
    start_idx = 0
    for idx, node in enumerate(nodes):
        label = str(node or "").strip().lower()
        if not label:
            continue
        last_idx = last_seen.get(label, idx)
        if last_idx > idx:
            start_idx = max(start_idx, last_idx)

    if start_idx <= 0:
        return record
    return _strip_display_record_prefix(
        record,
        start_node_index=start_idx,
        reason="repeated_node_label",
    )


def filter_shortest_paths_for_principals(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if len(records) <= 1:
        return records

    best_by_key: dict[tuple[str, str, str], tuple[int, int]] = {}
    for idx, record in enumerate(records):
        nodes = record.get("nodes")
        rels = record.get("relations")
        if not isinstance(nodes, list) or not isinstance(rels, list) or not nodes:
            continue
        terminal_rel = ""
        terminal_idx = None
        for rel_idx in range(len(rels) - 1, -1, -1):
            if str(rels[rel_idx] or "").strip().lower() == "memberof":
                continue
            terminal_rel = str(rels[rel_idx])
            terminal_idx = rel_idx
            break
        if terminal_idx is None:
            continue
        if terminal_idx + 1 >= len(nodes):
            continue
        terminal_from = str(nodes[terminal_idx]).lower()
        terminal_to = str(nodes[terminal_idx + 1]).lower()
        length = record.get("length")
        if not isinstance(length, int):
            length = sum(
                1 for rel in rels if str(rel or "").strip().lower() != "memberof"
            )
        key = (terminal_from, terminal_rel, terminal_to)
        existing = best_by_key.get(key)
        if existing is None or length < existing[0]:
            best_by_key[key] = (length, idx)

    if not best_by_key:
        return records

    keep_indices = {idx for _, idx in best_by_key.values()}
    return [record for idx, record in enumerate(records) if idx in keep_indices]


def _inject_memberof_edges_from_snapshot(
    runtime_graph: dict[str, Any],
    domain: str,
    snapshot: dict[str, Any] | None,
    *,
    principal_node_ids: set[str],
    recursive: bool,
) -> int:
    if not snapshot:
        return 0

    nodes_map = runtime_graph.get("nodes")
    edges = runtime_graph.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return 0

    existing: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "") != "MemberOf":
            continue
        existing.add((str(edge.get("from") or ""), str(edge.get("to") or "")))

    user_to_groups = (
        snapshot.get("user_to_groups") if isinstance(snapshot, dict) else {}
    )
    computer_to_groups = (
        snapshot.get("computer_to_groups") if isinstance(snapshot, dict) else {}
    )
    group_to_parents = (
        snapshot.get("group_to_parents") if isinstance(snapshot, dict) else {}
    )
    ancestor_cache: dict[str, set[str]] = {}

    injected = 0
    for node_id in principal_node_ids:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            continue
        kind = _node_kind(node)
        if kind not in {"User", "Computer"}:
            continue
        label = _canonical_membership_label(domain, _canonical_node_label(node))
        if not label:
            continue

        direct_groups: list[str] = []
        if kind == "User" and isinstance(user_to_groups, dict):
            direct_groups = user_to_groups.get(label, []) or []
        elif kind == "Computer" and isinstance(computer_to_groups, dict):
            direct_groups = computer_to_groups.get(label, []) or []
        if not isinstance(direct_groups, list):
            continue

        group_labels: set[str] = set()
        for group in direct_groups:
            group_label = _canonical_membership_label(domain, group)
            if not group_label:
                continue
            group_labels.add(group_label)
            if recursive:
                parents = _expand_group_ancestors(
                    domain, group_label, group_to_parents, ancestor_cache
                )
                group_labels.update(parents)

        for group_label in group_labels:
            gid = _ensure_group_node_id(runtime_graph, domain=domain, label=group_label)
            if not gid:
                continue
            key = (node_id, gid)
            if key in existing:
                continue
            edges.append(
                {
                    "from": node_id,
                    "to": gid,
                    "relation": "MemberOf",
                    "edge_type": "runtime",
                    "status": "discovered",
                    "notes": {"edge": "runtime"},
                }
            )
            existing.add(key)
            injected += 1

    return injected


def compute_display_paths_for_domain(
    graph: dict[str, Any],
    *,
    domain: str,
    snapshot: dict[str, Any] | None,
    max_depth: int,
    require_high_value_target: bool = True,
    target_mode: str = "tier0",
    expand_terminal_memberships: bool = True,
) -> list[dict[str, Any]]:
    runtime_graph: dict[str, Any] = dict(graph)
    runtime_graph["nodes"] = dict(
        graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    )
    runtime_graph["edges"] = list(
        graph.get("edges") if isinstance(graph.get("edges"), list) else []
    )

    if (
        expand_terminal_memberships
        and snapshot
        and not _graph_has_persisted_memberships(runtime_graph)
    ):
        candidate_to_ids: set[str] = set()
        for edge in runtime_graph["edges"]:
            if not isinstance(edge, dict):
                continue
            if (
                str(edge.get("relation") or "") == "MemberOf"
                and str(edge.get("edge_type") or "") == "runtime"
            ):
                continue
            to_id = str(edge.get("to") or "")
            if to_id:
                candidate_to_ids.add(to_id)
        _inject_memberof_edges_from_snapshot(
            runtime_graph,
            domain,
            snapshot,
            principal_node_ids=candidate_to_ids,
            recursive=True,
        )

    mode = (target_mode or "tier0").strip().lower()
    if mode not in {"tier0", "impact"}:
        mode = "tier0"
    unfiltered = attack_graph_core.compute_display_paths_for_domain_unfiltered(
        runtime_graph,
        max_depth=max_depth,
        require_high_value_target=require_high_value_target,
        target_mode=mode,
    )
    collapsed = collapse_memberof_prefixes(
        unfiltered,
        domain,
        snapshot,
        principal_labels=None,
        sample_limit=0,
    )
    minimized = minimize_display_paths(collapsed, domain=domain, snapshot=snapshot)
    annotated = apply_affected_user_metadata(
        minimized,
        graph=runtime_graph,
        domain=domain,
        snapshot=snapshot,
        filter_empty=True,
    )
    deduped = dedupe_exact_display_paths(annotated)
    filtered, _ = attack_graph_core.filter_contained_paths_for_domain_listing(deduped)
    return filtered


def compute_display_paths_for_start_node(
    graph: dict[str, Any],
    *,
    domain: str,
    snapshot: dict[str, Any] | None,
    start_node_id: str,
    max_depth: int,
    require_high_value_target: bool = True,
    target_mode: str = "tier0",
    expand_start_memberships: bool = True,
    expand_terminal_memberships: bool = True,
    filter_shortest_paths: bool = True,
) -> list[dict[str, Any]]:
    runtime_graph: dict[str, Any] = dict(graph)
    runtime_graph["nodes"] = dict(
        graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    )
    runtime_graph["edges"] = list(
        graph.get("edges") if isinstance(graph.get("edges"), list) else []
    )

    has_persisted = _graph_has_persisted_memberships(runtime_graph)

    if expand_start_memberships and snapshot:
        if has_persisted:
            edges = runtime_graph["edges"]
            assert isinstance(edges, list)
            start_has_memberof = any(
                isinstance(edge, dict)
                and str(edge.get("from") or "") == start_node_id
                and str(edge.get("relation") or "") == "MemberOf"
                and (
                    str(edge.get("edge_type") or edge.get("type") or "") == "membership"
                    or (
                        isinstance(edge.get("notes"), dict)
                        and str(edge["notes"].get("source") or "")
                        == "derived_membership"
                    )
                )
                for edge in edges
            )
            if not start_has_memberof:
                _inject_memberof_edges_from_snapshot(
                    runtime_graph,
                    domain,
                    snapshot,
                    principal_node_ids={start_node_id},
                    recursive=False,
                )
        else:
            _inject_memberof_edges_from_snapshot(
                runtime_graph,
                domain,
                snapshot,
                principal_node_ids={start_node_id},
                recursive=True,
            )

    if expand_terminal_memberships and snapshot and not has_persisted:
        candidate_to_ids: set[str] = set()
        for edge in runtime_graph["edges"]:
            if not isinstance(edge, dict):
                continue
            if (
                str(edge.get("relation") or "") == "MemberOf"
                and str(edge.get("edge_type") or "") == "runtime"
            ):
                continue
            to_id = str(edge.get("to") or "")
            if to_id:
                candidate_to_ids.add(to_id)
        _inject_memberof_edges_from_snapshot(
            runtime_graph,
            domain,
            snapshot,
            principal_node_ids=candidate_to_ids,
            recursive=True,
        )

    mode = (target_mode or "tier0").strip().lower()
    if mode not in {"tier0", "impact"}:
        mode = "tier0"
    records = attack_graph_core.compute_display_paths_for_start_node(
        runtime_graph,
        start_node_id=start_node_id,
        max_depth=max_depth,
        require_high_value_target=require_high_value_target,
        target_mode=mode,
    )
    records = minimize_display_paths(records, domain=domain, snapshot=snapshot)
    annotated = apply_affected_user_metadata(
        records,
        graph=runtime_graph,
        domain=domain,
        snapshot=snapshot,
        filter_empty=True,
    )
    if filter_shortest_paths:
        return filter_shortest_paths_for_principals(annotated)
    return annotated


def compute_display_paths_for_user(
    graph: dict[str, Any],
    *,
    domain: str,
    snapshot: dict[str, Any] | None,
    username: str,
    max_depth: int,
    require_high_value_target: bool = True,
    target_mode: str = "tier0",
    filter_shortest_paths: bool = True,
) -> list[dict[str, Any]]:
    start_node_id = _find_node_id_by_label(graph, username)
    if not start_node_id:
        return []
    return compute_display_paths_for_start_node(
        graph,
        domain=domain,
        snapshot=snapshot,
        start_node_id=start_node_id,
        max_depth=max_depth,
        require_high_value_target=require_high_value_target,
        target_mode=target_mode,
        filter_shortest_paths=filter_shortest_paths,
    )


def compute_display_paths_for_principals(
    graph: dict[str, Any],
    *,
    domain: str,
    snapshot: dict[str, Any] | None,
    principals: list[str],
    max_depth: int,
    require_high_value_target: bool = True,
    membership_sample_max: int = 3,
    target_mode: str = "tier0",
    filter_shortest_paths: bool = True,
) -> list[dict[str, Any]]:
    normalized_principals = [str(p or "").strip().lower() for p in principals]
    normalized_principals = [p for p in normalized_principals if p]
    if not normalized_principals:
        return []

    all_records: list[dict[str, Any]] = []
    for username in normalized_principals:
        records = compute_display_paths_for_user(
            graph,
            domain=domain,
            snapshot=snapshot,
            username=username,
            max_depth=max_depth,
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
            filter_shortest_paths=filter_shortest_paths,
        )
        all_records.extend(records)

    collapsed_records = collapse_memberof_prefixes(
        all_records,
        domain,
        snapshot,
        principal_labels=normalized_principals,
        sample_limit=membership_sample_max,
    )
    minimized = minimize_display_paths(
        collapsed_records, domain=domain, snapshot=snapshot
    )
    annotated = apply_affected_user_metadata(
        minimized,
        graph=graph,
        domain=domain,
        snapshot=snapshot,
        filter_empty=True,
    )
    if filter_shortest_paths:
        return filter_shortest_paths_for_principals(annotated)
    return annotated
