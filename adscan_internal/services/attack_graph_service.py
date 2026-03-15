from __future__ import annotations

import copy
import hashlib
import logging
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, cast

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_exception,
)
from adscan_internal.workspaces import domain_subpath, read_json_file, write_json_file
from adscan_internal.workspaces.computers import load_enabled_computer_samaccounts

from adscan_internal.services import attack_paths_core
from adscan_internal.services.attack_step_support_registry import (
    CONTEXT_ONLY_RELATIONS,
    classify_relation_support,
)
from adscan_internal.services.attack_step_catalog import (
    get_exploitation_relation_vuln_keys,
)
from adscan_internal.services.membership_snapshot import (
    load_membership_snapshot as _load_membership_snapshot_impl,
    membership_snapshot_path as _membership_snapshot_path,
    snapshot_has_sid_metadata as _snapshot_has_sid_metadata,
)
from adscan_internal.services.cache_metrics import (
    copy_stats,
    increment_scoped_stats,
    reset_stats,
)


ATTACK_GRAPH_SCHEMA_VERSION = "1.1"
_ATTACK_GRAPH_MAINTENANCE_VERSION = 1
_CONTEXT_RELATIONS_LOWER = {
    str(relation).strip().lower() for relation in CONTEXT_ONLY_RELATIONS.keys()
}

# Edge classification for CTEM correlation (centralized in attack_step_catalog).
EXPLOITATION_EDGE_VULN_KEYS: dict[str, str] = get_exploitation_relation_vuln_keys()
logger = logging.getLogger(__name__)

# Attack-path UX may need different trade-offs than privilege verification flows.
# We keep it configurable so operators can prefer speed (BloodHound-first) or
# accuracy (LDAP-first) while exploring paths.
#
# Valid values: "bloodhound", "ldap"
ATTACK_PATH_GROUP_MEMBERSHIP_PRIMARY = (
    os.getenv("ADSCAN_ATTACK_PATH_GROUP_MEMBERSHIP_PRIMARY", "bloodhound")
    .strip()
    .lower()
)

ATTACK_PATH_GROUP_MEMBERSHIP_ALLOW_FALLBACK = os.getenv(
    "ADSCAN_ATTACK_PATH_GROUP_MEMBERSHIP_ALLOW_FALLBACK", "0"
).strip().lower() in {"1", "true", "yes", "on"}

ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS = os.getenv(
    "ADSCAN_ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS", "1"
).strip().lower() in {"1", "true", "yes", "on"}

_CERTIPY_TEMPLATE_CACHE: dict[str, dict[str, Any]] = {}
_REPORT_SYNC_FN: Callable[[object, str, dict[str, Any]], None] | None | bool = None


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    """Read an integer env var with fallback and floor."""
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float = 0.0,
    maximum: float = 1.0,
) -> float:
    """Read a float env var with fallback and clamped bounds."""
    raw = os.getenv(name, str(default)).strip()
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


_ATTACK_PATHS_CACHE_ENABLED = os.getenv(
    "ADSCAN_ATTACK_PATHS_CACHE_ENABLED", "1"
).strip().lower() in {"1", "true", "yes", "on"}
_ATTACK_PATHS_CACHE_MAX_ENTRIES = _env_int("ADSCAN_ATTACK_PATHS_CACHE_MAX_ENTRIES", 64)
_ATTACK_PATHS_CACHE_MAX_RECORDS = _env_int(
    "ADSCAN_ATTACK_PATHS_CACHE_MAX_RECORDS", 2000
)
_ATTACK_PATH_ENABLE_SYNTHETIC_PRINCIPAL_BATCH = os.getenv(
    "ADSCAN_ATTACK_PATH_ENABLE_SYNTHETIC_PRINCIPAL_BATCH", "0"
).strip().lower() in {"1", "true", "yes", "on"}
_ATTACK_PATH_PRINCIPAL_BH_RESOLVE_MAX = _env_int(
    "ADSCAN_ATTACK_PATH_PRINCIPAL_BH_RESOLVE_MAX",
    64,
)
_ATTACK_PATH_PRINCIPAL_SYNTHETIC_MIN_SNAPSHOT_COVERAGE = _env_float(
    "ADSCAN_ATTACK_PATH_PRINCIPAL_SYNTHETIC_MIN_SNAPSHOT_COVERAGE",
    0.85,
)
_ATTACK_PATHS_COMPUTE_CACHE: "OrderedDict[tuple[Any, ...], list[dict[str, Any]]]" = (
    OrderedDict()
)
_ATTACK_PATHS_CACHE_STATS: dict[str, int] = {
    "hits": 0,
    "misses": 0,
    "stores": 0,
    "skips": 0,
    "evictions": 0,
    "invalidations": 0,
}
_ATTACK_PATHS_CACHE_DOMAIN_STATS: dict[str, dict[str, int]] = {}


def _cache_stats_inc(domain: str, key: str, by: int = 1) -> None:
    """Increment global + per-domain attack-path cache counters."""
    domain_key = str(domain or "").strip().lower()
    increment_scoped_stats(
        global_stats=_ATTACK_PATHS_CACHE_STATS,
        scoped_stats=_ATTACK_PATHS_CACHE_DOMAIN_STATS,
        scope_key=domain_key,
        key=key,
        by=by,
    )


def _get_attack_graph_maintenance_state(graph: dict[str, Any]) -> dict[str, Any]:
    """Return mutable maintenance-state metadata for an attack graph."""
    state = graph.get("maintenance")
    if not isinstance(state, dict):
        state = {}
        graph["maintenance"] = state
    return state


def _maintenance_key(version: int) -> str:
    """Return the maintenance marker key for the current code version."""
    return f"v{version}"


def _load_enabled_users(shell: object, domain: str) -> set[str] | None:
    """Load enabled users list for a domain if available."""
    try:
        workspace_cwd = (
            shell._get_workspace_cwd()  # type: ignore[attr-defined]
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", os.getcwd())
        )
        domains_dir = getattr(shell, "domains_dir", "domains")
        enabled_path = domain_subpath(
            workspace_cwd, domains_dir, domain, "enabled_users.txt"
        )
        if not os.path.exists(enabled_path):
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                f"[membership] enabled users file missing for {marked_domain}: {enabled_path}"
            )
            return None
        with open(enabled_path, encoding="utf-8") as handle:
            users = {
                str(line).strip().lower()
                for line in handle
                if isinstance(line, str) and str(line).strip()
            }
        if users:
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                f"[membership] enabled users loaded for {marked_domain}: "
                f"count={len(users)} path={enabled_path}"
            )
            return users
        return None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[membership] enabled users load failed for {marked_domain}: {exc}"
        )
        return None


def _load_domain_users(shell: object, domain: str) -> list[str] | None:
    """Load the persisted domain user list for a workspace domain."""
    try:
        workspace_cwd = (
            shell._get_workspace_cwd()  # type: ignore[attr-defined]
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", os.getcwd())
        )
        domains_dir = getattr(shell, "domains_dir", "domains")
        users_path = domain_subpath(workspace_cwd, domains_dir, domain, "users.txt")
        if not os.path.exists(users_path):
            return None
        with open(users_path, encoding="utf-8") as handle:
            users = [
                str(line).strip()
                for line in handle
                if isinstance(line, str) and str(line).strip()
            ]
        return users or None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[membership] users list load failed for {marked_domain}: {exc}"
        )
        return None


def get_enabled_users_for_domain(
    shell: object,
    domain: str,
) -> set[str] | None:
    """Return enabled users for a domain using file-first + snapshot fallback."""
    enabled_users = _load_enabled_users(shell, domain)
    if enabled_users:
        return enabled_users

    snapshot = _load_membership_snapshot(shell, domain)
    if not isinstance(snapshot, dict):
        return None
    enabled_map = snapshot.get("user_enabled")
    if not isinstance(enabled_map, dict):
        return None

    users = {
        str(username).strip().lower()
        for username, is_enabled in enabled_map.items()
        if str(username).strip() and bool(is_enabled)
    }
    if users:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[membership] enabled users loaded from snapshot for {marked_domain}: count={len(users)}"
        )
        return users
    return None


def get_enabled_computers_for_domain(
    shell: object,
    domain: str,
) -> set[str] | None:
    """Return enabled computer sAMAccountNames for a domain using workspace data."""
    try:
        workspace_cwd = (
            shell._get_workspace_cwd()  # type: ignore[attr-defined]
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", os.getcwd())
        )
        domains_dir = getattr(shell, "domains_dir", "domains")
        computers = load_enabled_computer_samaccounts(
            workspace_cwd, domains_dir, domain
        )
    except OSError:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[membership] enabled computers file missing/unreadable for {marked_domain}"
        )
        return None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[membership] enabled computers load failed for {marked_domain}: {exc}"
        )
        return None

    enabled_computers = {
        str(computer).strip().lower()
        for computer in computers
        if isinstance(computer, str) and str(computer).strip()
    }
    if enabled_computers:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[membership] enabled computers loaded for {marked_domain}: count={len(enabled_computers)}"
        )
        return enabled_computers
    return None


def infer_directory_object_enabled_state(
    shell: object,
    *,
    domain: str,
    principal_name: str,
    principal_kind: str,
    node: dict[str, Any] | None = None,
) -> tuple[bool | None, str]:
    """Infer whether a user or computer object is enabled.

    The resolution order is:
    1. BloodHound node ``properties.enabled`` when present.
    2. Workspace enabled-user/enabled-computer inventories.

    Args:
        shell: Active CLI shell/runtime object.
        domain: Domain owning the target object.
        principal_name: Target sAMAccountName or label.
        principal_kind: BloodHound object kind (User/Computer/...).
        node: Optional BloodHound node to inspect directly.

    Returns:
        Tuple ``(enabled_state, source)`` where ``enabled_state`` may be
        ``None`` when no reliable data is available.
    """
    domain = str(domain or "").strip().lower()
    props = node.get("properties") if isinstance(node, dict) else {}
    if isinstance(props, dict):
        direct_enabled = props.get("enabled")
        if isinstance(direct_enabled, bool):
            return direct_enabled, "node_properties.enabled"

        samaccountname = props.get("samaccountname")
        if isinstance(samaccountname, str) and samaccountname.strip():
            principal_name = samaccountname

    normalized_name = _normalize_account(str(principal_name or ""))
    if not normalized_name:
        return None, "unknown"

    kind = str(principal_kind or "").strip().lower()
    if kind == "user":
        enabled_principals = get_enabled_users_for_domain(shell, domain)
        source = "enabled_users"
    elif kind == "computer":
        enabled_principals = get_enabled_computers_for_domain(shell, domain)
        source = "enabled_computers"
    else:
        return None, "unknown"

    if not enabled_principals:
        return None, f"{source}_unavailable"
    return normalized_name in enabled_principals, source


def _enrich_node_enabled_metadata(
    shell: object | None,
    graph: dict[str, Any],
    node: dict[str, Any],
) -> dict[str, Any]:
    """Best-effort enrich BloodHound node metadata with persisted enabled state."""
    if shell is None or not isinstance(node, dict):
        return node

    kind = _node_kind(node)
    if kind not in {"User", "Computer"}:
        return node

    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if isinstance(props.get("enabled"), bool):
        return node

    domain = str(
        props.get("domain") or node.get("domain") or graph.get("domain") or ""
    ).strip()
    if not domain:
        return node

    principal_name = str(
        props.get("samaccountname")
        or props.get("name")
        or node.get("samaccountname")
        or node.get("name")
        or node.get("label")
        or ""
    ).strip()
    if not principal_name:
        return node

    enabled, source = infer_directory_object_enabled_state(
        shell,
        domain=domain,
        principal_name=principal_name,
        principal_kind=kind,
        node=node,
    )
    if not isinstance(enabled, bool):
        return node

    updated = dict(node)
    updated_props = dict(props)
    updated_props["enabled"] = enabled
    updated_props.setdefault("enabled_source", source)
    updated["properties"] = updated_props
    return updated


def filter_enabled_domain_users(
    shell: object,
    domain: str,
    usernames: Iterable[str],
) -> tuple[list[str], bool]:
    """Filter usernames using enabled-user data when available.

    Returns:
        Tuple ``(filtered_users, enabled_data_used)``.
    """
    normalized: list[str] = []
    seen: set[str] = set()
    for username in usernames:
        value = str(username or "").strip()
        if not value:
            continue
        key = _normalize_account(value)
        if not key or key in seen:
            continue
        seen.add(key)
        normalized.append(value)
    if not normalized:
        return [], False

    enabled_users = get_enabled_users_for_domain(shell, domain)
    if not enabled_users:
        return normalized, False

    filtered = [
        username
        for username in normalized
        if _normalize_account(username) in enabled_users
    ]
    return filtered, True


def resolve_group_members_by_rid(
    shell: object,
    domain: str,
    rid: int,
    *,
    enabled_only: bool = True,
) -> list[str] | None:
    """Resolve group members by RID using snapshot, BH, then fallback to caller."""
    marked_domain = mark_sensitive(domain, "domain")
    enabled_users = _load_enabled_users(shell, domain) if enabled_only else None
    if enabled_only and enabled_users is None:
        print_info_debug(
            f"[membership] enabled users list missing for {marked_domain}; "
            "falling back to snapshot/BloodHound enabled flags."
        )

    snapshot_members = get_users_in_group_rid_from_snapshot(shell, domain, rid)
    if snapshot_members is not None:
        members = snapshot_members
        if enabled_users is not None:
            members = [user for user in members if user in enabled_users]
        elif enabled_only:
            snapshot = _load_membership_snapshot(shell, domain)
            enabled_map = (
                snapshot.get("user_enabled") if isinstance(snapshot, dict) else None
            )
            if isinstance(enabled_map, dict):
                members = [user for user in members if enabled_map.get(user, True)]
                print_info_debug(
                    f"[membership] applied snapshot enabled filter for {marked_domain}: "
                    f"remaining={len(members)}"
                )
        print_info_debug(
            f"[membership] RID {rid} resolved from memberships.json for {marked_domain}: "
            f"{len(members)} member(s)."
        )
        return sorted(set(members), key=str.lower)

    print_info_debug(
        f"[membership] memberships.json unavailable for {marked_domain}; "
        "trying BloodHound."
    )

    service = getattr(shell, "_get_bloodhound_service", None)
    if service:
        try:
            bh_service = service()
            client = getattr(bh_service, "client", None)
            if client and hasattr(client, "execute_query"):
                query = f"""
                MATCH (g:Group)
                WHERE toLower(coalesce(g.domain, "")) = toLower("{domain}")
                  AND (
                    coalesce(g.objectid, g.objectId, "") = coalesce(g.domainsid, g.domainSid, "") + "-{rid}"
                  )
                WITH g
                MATCH (m:User)-[:MemberOf*1..]->(g)
                RETURN DISTINCT m
                """
                print_info_debug(
                    f"[membership] BloodHound RID {rid} query for {marked_domain}: {query.strip()}"
                )
                rows = client.execute_query(query)
                members: list[str] = []
                if isinstance(rows, list):
                    print_info_debug(
                        f"[membership] BloodHound RID {rid} raw rows for {marked_domain}: "
                        f"{len(rows)}"
                    )
                    if rows:
                        print_info_debug(
                            f"[membership] BloodHound RID {rid} sample row for {marked_domain}: {rows[0]}"
                        )
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        node = row.get("m")
                        if not isinstance(node, dict):
                            continue
                        props = node.get("properties")
                        if not isinstance(props, dict):
                            props = {}
                        enabled = node.get("enabled")
                        if enabled_only and enabled_users is None:
                            if enabled is False or props.get("enabled") is False:
                                continue
                        name = (
                            props.get("samaccountname")
                            or props.get("samAccountName")
                            or node.get("samaccountname")
                            or node.get("samAccountName")
                            or props.get("name")
                            or node.get("name")
                        )
                        if isinstance(name, str) and name.strip():
                            members.append(name.strip().lower())
                if enabled_users is not None:
                    members = [user for user in members if user in enabled_users]
                elif enabled_only:
                    print_info_debug(
                        f"[membership] BloodHound enabled filter used for {marked_domain}: "
                        f"remaining={len(members)}"
                    )
                print_info_debug(
                    f"[membership] RID {rid} resolved from BloodHound for {marked_domain}: "
                    f"{len(members)} member(s)."
                )
                return sorted(set(members), key=str.lower)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[membership] BloodHound RID {rid} query failed for {marked_domain}: {exc}"
            )

    print_info_debug(
        f"[membership] BloodHound unavailable for RID {rid} in {marked_domain}."
    )
    return None


ATTACK_GRAPH_PERSIST_MEMBERSHIPS = os.getenv(
    "ADSCAN_ATTACK_GRAPH_PERSIST_MEMBERSHIPS", "1"
).strip().lower() in {"1", "true", "yes", "on"}

_DOMAIN_SID_VALIDATION_CACHE: set[str] = set()


def _resolve_local_reuse_topology(total_hosts: int) -> str:
    """Return edge-topology mode for LocalAdminPassReuse materialization.

    Modes:
        - star: compressed bidirectional star (2 * (N-1) edges) [default]
        - mesh: full directed graph (N * (N-1) edges), debug/compat mode only
        - auto: legacy threshold behavior (mesh up to ADSCAN_LOCAL_REUSE_MESH_MAX_HOSTS)
    """
    mode = os.getenv("ADSCAN_LOCAL_REUSE_EDGE_TOPOLOGY", "star").strip().lower()
    if mode in {"mesh", "full", "clique"}:
        return "mesh"
    if mode == "star":
        return "star"
    if mode != "auto":
        return "star"

    threshold_raw = os.getenv("ADSCAN_LOCAL_REUSE_MESH_MAX_HOSTS", "8").strip()
    try:
        threshold = max(2, int(threshold_raw))
    except ValueError:
        threshold = 8
    return "mesh" if max(0, int(total_hosts)) <= threshold else "star"


def _augment_snapshot_with_attack_graph(
    shell: object, domain: str, snapshot: dict[str, Any]
) -> dict[str, Any]:
    try:
        graph_path = _graph_path(shell, domain)
        if not os.path.exists(graph_path):
            return snapshot
        graph = read_json_file(graph_path)
    except Exception:
        return snapshot
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return snapshot
    label_to_sid: dict[str, str] = dict(snapshot.get("label_to_sid") or {})
    sid_to_label: dict[str, str] = dict(snapshot.get("sid_to_label") or {})
    domain_sid = snapshot.get("domain_sid")

    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        label = attack_paths_core._canonical_membership_label(  # noqa: SLF001
            domain,
            attack_paths_core._canonical_node_label(node),  # noqa: SLF001
        )
        if not label:
            continue
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        object_id = str(
            node.get("objectId") or props.get("objectid") or props.get("objectId") or ""
        ).strip()
        sid = attack_paths_core._extract_sid(object_id)  # noqa: SLF001
        if not sid:
            continue
        label_to_sid[label] = sid
        sid_to_label.setdefault(sid, label)
        if not domain_sid and sid.startswith("S-1-5-21-"):
            parts = sid.split("-")
            if len(parts) >= 5:
                domain_sid = "-".join(parts[:-1])

    snapshot["label_to_sid"] = label_to_sid
    snapshot["sid_to_label"] = sid_to_label
    if domain_sid:
        snapshot["domain_sid"] = domain_sid
    return snapshot


def _load_membership_snapshot(shell: object, domain: str) -> dict[str, Any] | None:
    """Load memberships.json with caching and augmentation."""
    return _load_membership_snapshot_impl(  # type: ignore[misc]
        shell,
        domain,
        augment_fn=lambda snap: _augment_snapshot_with_attack_graph(
            shell, domain, snap
        ),
    )


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


def _snapshot_get_direct_groups(
    shell: object, domain: str, principal: str
) -> list[str] | None:
    snapshot = _load_membership_snapshot(shell, domain)
    if not snapshot:
        return None
    canonical = _canonical_membership_label(domain, principal)
    user_groups = snapshot.get("user_to_groups")
    computer_groups = snapshot.get("computer_to_groups")
    groups: set[str] = set()
    if isinstance(user_groups, dict):
        groups.update(user_groups.get(canonical, []) or [])
    if isinstance(computer_groups, dict):
        groups.update(computer_groups.get(canonical, []) or [])
    if not groups:
        marked_principal = mark_sensitive(principal, "user")
        marked_domain = mark_sensitive(domain, "domain")
        user_count = len(user_groups) if isinstance(user_groups, dict) else 0
        computer_count = (
            len(computer_groups) if isinstance(computer_groups, dict) else 0
        )
        in_users = isinstance(user_groups, dict) and canonical in user_groups
        in_computers = (
            isinstance(computer_groups, dict) and canonical in computer_groups
        )
        print_info_debug(
            f"[membership] no groups for {marked_principal}@{marked_domain}: "
            f"canonical={canonical} user_keys={user_count} computer_keys={computer_count} "
            f"in_users={in_users} in_computers={in_computers}"
        )
    return [_membership_label_to_name(group) for group in sorted(groups, key=str.lower)]


def _snapshot_get_recursive_groups(
    shell: object, domain: str, principal: str
) -> list[str] | None:
    snapshot = _load_membership_snapshot(shell, domain)
    if not snapshot:
        return None
    direct = _snapshot_get_direct_groups(shell, domain, principal)
    if direct is None:
        return None
    group_to_parents = snapshot.get("group_to_parents")
    if not isinstance(group_to_parents, dict):
        return direct

    seen: set[str] = set()
    queue: list[str] = [_canonical_membership_label(domain, group) for group in direct]
    results: set[str] = set(direct)

    while queue:
        group_label = queue.pop(0)
        if group_label in seen:
            continue
        seen.add(group_label)
        parents = group_to_parents.get(group_label, []) if group_to_parents else []
        if not parents:
            continue
        for parent in parents:
            parent_name = _membership_label_to_name(parent)
            if parent_name:
                results.add(parent_name)
            parent_label = _canonical_membership_label(domain, parent)
            if parent_label not in seen:
                queue.append(parent_label)

    return sorted(results, key=str.lower)


def _snapshot_get_recursive_group_labels(
    shell: object, domain: str, principal: str
) -> set[str] | None:
    snapshot = _load_membership_snapshot(shell, domain)
    if not snapshot:
        return None
    direct = _snapshot_get_direct_groups(shell, domain, principal)
    if direct is None:
        return None
    group_to_parents = snapshot.get("group_to_parents")
    if not isinstance(group_to_parents, dict):
        return {_canonical_membership_label(domain, group) for group in direct if group}

    seen: set[str] = set()
    queue: list[str] = [
        _canonical_membership_label(domain, group) for group in direct if group
    ]
    results: set[str] = set(queue)

    while queue:
        group_label = queue.pop(0)
        if group_label in seen:
            continue
        seen.add(group_label)
        parents = group_to_parents.get(group_label, []) if group_to_parents else []
        if not parents:
            continue
        for parent in parents:
            parent_label = _canonical_membership_label(domain, parent)
            if not parent_label:
                continue
            if parent_label not in results:
                results.add(parent_label)
            if parent_label not in seen:
                queue.append(parent_label)

    return results


def _snapshot_get_recursive_group_sids(
    shell: object, domain: str, groups: list[str]
) -> list[str]:
    snapshot = _load_membership_snapshot(shell, domain)
    if not snapshot:
        return []
    label_to_sid = snapshot.get("label_to_sid")
    if not isinstance(label_to_sid, dict):
        return []
    group_sids: list[str] = []
    for group in groups:
        label = _canonical_membership_label(domain, group)
        sid = label_to_sid.get(label)
        if isinstance(sid, str) and sid.strip():
            group_sids.append(sid.strip())
    return sorted(set(group_sids), key=str.upper)


def resolve_principal_groups(
    shell: object,
    domain: str,
    principal: str,
    *,
    include_sids: bool = True,
) -> dict[str, Any]:
    """Resolve recursive group memberships for a principal with fallbacks.

    Resolution order:
        1) memberships.json snapshot
        2) BloodHound
        3) LDAP

    Returns:
        Dict containing:
            groups: list[str]
            group_sids: list[str]
            source: str
    """
    sam_clean = (principal or "").strip()
    domain_clean = (domain or "").strip()
    if not sam_clean or not domain_clean:
        return {"groups": [], "group_sids": [], "source": "none"}

    marked_domain = mark_sensitive(domain_clean, "domain")
    marked_principal = mark_sensitive(sam_clean, "user")
    snapshot_groups = _snapshot_get_recursive_groups(shell, domain_clean, sam_clean)
    if snapshot_groups is not None:
        group_sids = (
            _snapshot_get_recursive_group_sids(shell, domain_clean, snapshot_groups)
            if include_sids
            else []
        )
        print_info_debug(
            "[membership] principal groups resolved from memberships.json for "
            f"{marked_principal}@{marked_domain}: groups={len(snapshot_groups)} "
            f"sids={len(group_sids)}"
        )
        return {
            "groups": sorted(set(snapshot_groups), key=str.lower),
            "group_sids": group_sids,
            "source": "memberships",
        }

    print_info_debug(
        f"[membership] memberships.json unavailable for {marked_principal}@{marked_domain}; "
        "trying BloodHound."
    )

    # BloodHound fallback
    try:
        if hasattr(shell, "_get_bloodhound_service"):
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
            getter = getattr(service, "get_user_groups", None)
            if callable(getter):
                groups = getter(domain_clean, sam_clean, True)
                if isinstance(groups, list):
                    resolved = [
                        _extract_group_name_from_bh(str(group))
                        for group in groups
                        if str(group).strip()
                    ]
                    group_sids: list[str] = []
                    if include_sids:
                        resolver = getattr(
                            service, "get_group_node_by_samaccountname", None
                        )
                        if callable(resolver):
                            for group in resolved:
                                node = resolver(domain_clean, group)
                                if isinstance(node, dict):
                                    sid = (
                                        node.get("objectid")
                                        or node.get("objectId")
                                        or (node.get("properties") or {}).get(
                                            "objectid"
                                        )
                                        or (node.get("properties") or {}).get(
                                            "objectId"
                                        )
                                    )
                                    if isinstance(sid, str) and sid.strip():
                                        group_sids.append(sid.strip())
                    print_info_debug(
                        "[membership] principal groups resolved from BloodHound for "
                        f"{marked_principal}@{marked_domain}: groups={len(resolved)} "
                        f"sids={len(group_sids)}"
                    )
                    return {
                        "groups": sorted(set(resolved), key=str.lower),
                        "group_sids": sorted(set(group_sids), key=str.upper),
                        "source": "bloodhound",
                    }
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    print_info_debug(
        f"[membership] BloodHound unavailable for {marked_principal}@{marked_domain}; "
        "trying LDAP."
    )

    # LDAP fallback
    try:
        from adscan_internal.cli.ldap import (
            get_recursive_principal_group_sids_in_chain,
            get_recursive_principal_groups_in_chain,
        )

        group_sids = get_recursive_principal_group_sids_in_chain(
            shell, domain=domain_clean, target_samaccountname=sam_clean
        )
        group_names = get_recursive_principal_groups_in_chain(
            shell, domain=domain_clean, target_samaccountname=sam_clean
        )
        print_info_debug(
            "[membership] principal groups resolved from LDAP for "
            f"{marked_principal}@{marked_domain}: groups="
            f"{len(group_names) if isinstance(group_names, list) else 0} "
            f"sids={len(group_sids) if isinstance(group_sids, list) else 0}"
        )
        return {
            "groups": sorted(set(group_names), key=str.lower)
            if isinstance(group_names, list)
            else [],
            "group_sids": sorted(set(group_sids), key=str.upper)
            if isinstance(group_sids, list)
            else [],
            "source": "ldap",
        }
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    return {"groups": [], "group_sids": [], "source": "none"}


def _normalize_machine_account(value: str) -> str:
    from adscan_internal.principal_utils import normalize_machine_account

    return normalize_machine_account(value)


def _derive_domain_sid(snapshot: dict[str, Any]) -> str | None:
    domain_sid = snapshot.get("domain_sid")
    if isinstance(domain_sid, str) and domain_sid:
        return domain_sid
    label_to_sid = snapshot.get("label_to_sid")
    if not isinstance(label_to_sid, dict):
        return None
    for sid in label_to_sid.values():
        if not isinstance(sid, str):
            continue
        if sid.startswith("S-1-5-21-"):
            parts = sid.split("-")
            if len(parts) >= 5:
                return "-".join(parts[:-1])
    return None


def _load_domain_sid_from_domains_data(shell: object, domain: str) -> str | None:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_entry = domains_data.get(domain)
    if not isinstance(domain_entry, dict):
        return None
    domain_sid = domain_entry.get("domain_sid")
    if isinstance(domain_sid, str) and domain_sid:
        return domain_sid
    return None


def _persist_domain_sid(shell: object, domain: str, domain_sid: str) -> None:
    if not isinstance(domain_sid, str) or not domain_sid:
        return
    if not hasattr(shell, "domains_data") or not isinstance(shell.domains_data, dict):
        return
    domain_entry = shell.domains_data.get(domain)
    if not isinstance(domain_entry, dict):
        return
    if domain_entry.get("domain_sid") == domain_sid:
        return
    domain_entry["domain_sid"] = domain_sid
    shell.domains_data[domain] = domain_entry
    marked_domain = mark_sensitive(domain, "domain")
    marked_sid = mark_sensitive(domain_sid, "user")
    print_info_debug(
        f"[membership] persisted domain SID for {marked_domain}: {marked_sid}"
    )
    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(show_locals=False, exception=exc)


def _should_validate_domain_sid(
    *,
    domain_key: str,
    snapshot: dict[str, Any],
    domain_sid: str | None,
    persisted_sid: str | None,
) -> bool:
    if domain_key in _DOMAIN_SID_VALIDATION_CACHE:
        return False
    if not domain_sid:
        return True
    if not _snapshot_has_sid_metadata(snapshot):
        return True
    if persisted_sid and persisted_sid != domain_sid:
        return True
    return False


def _lookup_domain_sid_via_ldap(shell: object, domain: str) -> str | None:
    try:
        from adscan_internal.integrations.netexec.parsers import (
            parse_netexec_ldap_query_attribute_values,
        )
    except Exception:
        return None

    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_entry = domains_data.get(domain)
    if not isinstance(domain_entry, dict):
        return None
    netexec_path = getattr(shell, "netexec_path", None)
    if not netexec_path:
        return None

    auth_username = domain_entry.get("username")
    auth_password = domain_entry.get("password")
    pdc = domain_entry.get("pdc")
    if not auth_username or not auth_password or not pdc:
        return None

    kerberos = bool(domain_entry.get("kerberos_tickets"))
    auth_str = shell.build_auth_nxc(  # type: ignore[attr-defined]
        str(auth_username),
        str(auth_password),
        str(domain),
        kerberos=kerberos,
    )
    marked_user = mark_sensitive(str(auth_username), "user")
    marked_pass = mark_sensitive(str(auth_password), "password")
    marked_domain = mark_sensitive(str(domain), "domain")
    marked_pdc = mark_sensitive(
        str(pdc),
        "ip" if str(pdc).replace(".", "").isdigit() else "hostname",
    )
    auth_str = auth_str.replace(str(auth_username), str(marked_user)).replace(
        str(auth_password), str(marked_pass)
    )
    auth_str = auth_str.replace(str(domain), str(marked_domain))

    query = f"(&(objectClass=domain)(name={domain}))"
    command = f'{netexec_path} ldap {marked_pdc} {auth_str} --query "{query}" objectSid'
    print_info_debug(f"[membership] domain SID LDAP command: {command}")
    runner = getattr(shell, "_run_netexec", None)
    if callable(runner):
        result = runner(command, domain=domain)  # type: ignore[misc]
    else:
        result = shell.run_command(command)  # type: ignore[attr-defined]
    if not result or result.returncode != 0:
        return None
    sids = parse_netexec_ldap_query_attribute_values(result.stdout or "", "objectSid")
    sids = [sid.strip() for sid in sids if str(sid).strip()]
    if not sids:
        return None
    return sids[0]


def _lookup_user_sid_via_ldap(shell: object, domain: str, username: str) -> str | None:
    try:
        from adscan_internal.integrations.netexec.parsers import (
            parse_netexec_ldap_query_attribute_values,
        )
    except Exception:
        return None
    domain_entry = getattr(shell, "domains_data", {}).get(domain, {})
    netexec_path = getattr(shell, "netexec_path", None)
    if not netexec_path:
        return None

    auth_username = domain_entry.get("username")
    auth_password = domain_entry.get("password")
    pdc = domain_entry.get("pdc")
    if not auth_username or not auth_password or not pdc:
        return None

    kerberos = bool(domain_entry.get("kerberos_tickets"))
    auth_str = shell.build_auth_nxc(  # type: ignore[attr-defined]
        str(auth_username),
        str(auth_password),
        str(domain),
        kerberos=kerberos,
    )
    marked_user = mark_sensitive(str(auth_username), "user")
    marked_pass = mark_sensitive(str(auth_password), "password")
    marked_domain = mark_sensitive(str(domain), "domain")
    marked_pdc = mark_sensitive(
        str(pdc),
        "ip" if str(pdc).replace(".", "").isdigit() else "hostname",
    )
    auth_str = auth_str.replace(str(auth_username), str(marked_user)).replace(
        str(auth_password), str(marked_pass)
    )
    auth_str = auth_str.replace(str(domain), str(marked_domain))

    query = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))"
    command = f'{netexec_path} ldap {marked_pdc} {auth_str} --query "{query}" objectSid'
    print_info_debug(f"[membership] user SID LDAP command: {command}")
    runner = getattr(shell, "_run_netexec", None)
    if callable(runner):
        result = runner(command, domain=domain)  # type: ignore[misc]
    else:
        result = shell.run_command(command)  # type: ignore[attr-defined]
    if not result or result.returncode != 0:
        return None
    sids = parse_netexec_ldap_query_attribute_values(result.stdout or "", "objectSid")
    sids = [sid.strip() for sid in sids if str(sid).strip()]
    if not sids:
        return None
    return sids[0]


def resolve_user_sid(shell: object, domain: str, username: str) -> str | None:
    """Resolve a user's objectSid via snapshot, BloodHound, then LDAP."""
    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")
    snapshot = _load_membership_snapshot(shell, domain)
    if snapshot:
        label_to_sid = snapshot.get("label_to_sid")
        if isinstance(label_to_sid, dict):
            label = _canonical_membership_label(domain, username)
            sid = label_to_sid.get(label)
            if isinstance(sid, str) and sid.strip():
                print_info_debug(
                    f"[membership] user SID resolved from memberships.json for "
                    f"{marked_user}@{marked_domain}: {mark_sensitive(sid, 'user')}"
                )
                return sid.strip()

    try:
        service = getattr(shell, "_get_bloodhound_service", None)
        if service:
            bh_service = service()
            resolver = getattr(bh_service, "get_user_node_by_samaccountname", None)
            if callable(resolver):
                node = resolver(domain, username)
                if isinstance(node, dict):
                    sid = (
                        node.get("objectid")
                        or node.get("objectId")
                        or (node.get("properties") or {}).get("objectid")
                        or (node.get("properties") or {}).get("objectId")
                    )
                    if isinstance(sid, str) and sid.strip():
                        print_info_debug(
                            f"[membership] user SID resolved from BloodHound for "
                            f"{marked_user}@{marked_domain}: {mark_sensitive(sid, 'user')}"
                        )
                        return sid.strip()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    sid = _lookup_user_sid_via_ldap(shell, domain, username)
    if sid:
        print_info_debug(
            f"[membership] user SID resolved via LDAP for "
            f"{marked_user}@{marked_domain}: {mark_sensitive(sid, 'user')}"
        )
        return sid

    print_info_debug(
        f"[membership] user SID unresolved for {marked_user}@{marked_domain}."
    )
    return None


def _resolve_domain_sid(
    shell: object, domain: str, snapshot: dict[str, Any]
) -> str | None:
    marked_domain = mark_sensitive(domain, "domain")
    domain_sid = _derive_domain_sid(snapshot)
    persisted_sid = _load_domain_sid_from_domains_data(shell, domain)
    domain_key = str(domain or "").strip().lower()
    if domain_sid:
        if _should_validate_domain_sid(
            domain_key=domain_key,
            snapshot=snapshot,
            domain_sid=domain_sid,
            persisted_sid=persisted_sid,
        ):
            ldap_sid = _lookup_domain_sid_via_ldap(shell, domain)
            _DOMAIN_SID_VALIDATION_CACHE.add(domain_key)
            if ldap_sid and ldap_sid != domain_sid:
                print_info_debug(
                    f"[membership] domain SID mismatch for {marked_domain}: "
                    f"snapshot={mark_sensitive(domain_sid, 'user')} "
                    f"ldap={mark_sensitive(ldap_sid, 'user')}"
                )
                domain_sid = ldap_sid
                snapshot["domain_sid"] = domain_sid
                _persist_domain_sid(shell, domain, domain_sid)
        print_info_debug(
            f"[membership] domain SID resolved from memberships.json for {marked_domain}: "
            f"{mark_sensitive(domain_sid, 'user')}"
        )
        return domain_sid

    domain_sid = persisted_sid
    if domain_sid:
        print_info_debug(
            f"[membership] domain SID loaded from domains_data for {marked_domain}: "
            f"{mark_sensitive(domain_sid, 'user')}"
        )
        snapshot["domain_sid"] = domain_sid
        return domain_sid

    domain_sid = _derive_domain_sid(
        _augment_snapshot_with_attack_graph(shell, domain, snapshot)
    )
    if domain_sid:
        print_info_debug(
            f"[membership] domain SID derived from BloodHound for {marked_domain}: "
            f"{mark_sensitive(domain_sid, 'user')}"
        )
        snapshot["domain_sid"] = domain_sid
        _persist_domain_sid(shell, domain, domain_sid)
        return domain_sid

    domain_sid = _lookup_domain_sid_via_ldap(shell, domain)
    if domain_sid:
        print_info_debug(
            f"[membership] domain SID resolved via LDAP for {marked_domain}: "
            f"{mark_sensitive(domain_sid, 'user')}"
        )
        snapshot["domain_sid"] = domain_sid
        _persist_domain_sid(shell, domain, domain_sid)
        return domain_sid

    try:
        label_to_sid = snapshot.get("label_to_sid")
        label_count = len(label_to_sid) if isinstance(label_to_sid, dict) else 0
        print_info_debug(
            f"[membership] domain SID unresolved for {marked_domain}; "
            f"label_to_sid_count={label_count} persisted_sid={'set' if persisted_sid else 'unset'}"
        )
    except Exception:
        pass
    print_info_debug(
        f"[membership] domain SID unresolved for {marked_domain}; "
        "RID-based membership lookups may be incomplete."
    )
    return None


def _resolve_group_label_for_sid(
    snapshot: dict[str, Any],
    domain: str,
    target_sid: str,
) -> str | None:
    if not target_sid:
        return None
    target_sid = str(target_sid).upper()
    sid_to_label = snapshot.get("sid_to_label")
    if isinstance(sid_to_label, dict):
        label = sid_to_label.get(target_sid)
        if isinstance(label, str) and label:
            return _canonical_membership_label(domain, label)
    label_to_sid = snapshot.get("label_to_sid")
    if isinstance(label_to_sid, dict):
        for label, sid in label_to_sid.items():
            if isinstance(sid, str) and sid.upper() == target_sid:
                return _canonical_membership_label(domain, label)
    return None


def is_principal_member_of_rid_from_snapshot(
    shell: object,
    domain: str,
    principal: str,
    rid: int,
) -> bool | None:
    """Check recursive group membership by RID using memberships.json.

    Returns:
        True/False when memberships.json is available, or None when the snapshot
        is missing/unavailable or lacks SID metadata.
    """
    marked_domain = mark_sensitive(domain, "domain")
    snapshot = _load_membership_snapshot(shell, domain)
    if not snapshot:
        print_info_debug(
            f"[membership] snapshot unavailable for {marked_domain}; "
            "cannot resolve principal membership by RID."
        )
        return None
    label_to_sid = snapshot.get("label_to_sid")
    if not isinstance(label_to_sid, dict) or not label_to_sid:
        print_info_debug(
            f"[membership] snapshot missing SID metadata for {marked_domain}; "
            "cannot resolve principal membership by RID."
        )
        return None
    domain_sid = _resolve_domain_sid(shell, domain, snapshot)
    if not domain_sid:
        print_info_debug(
            f"[membership] domain SID unresolved for {marked_domain}; "
            "cannot resolve principal membership by RID."
        )
        return None
    target_sid = f"{domain_sid}-{rid}"
    print_info_debug(
        f"[membership] principal RID lookup for {marked_domain}: target_sid={mark_sensitive(target_sid, 'user')}"
    )
    groups = _snapshot_get_recursive_groups(shell, domain, principal)
    if groups is None:
        return None
    for group in groups:
        label = _canonical_membership_label(domain, group)
        sid = label_to_sid.get(label)
        if isinstance(sid, str) and sid.upper() == target_sid.upper():
            return True
    return False


def get_users_in_group_rid_from_snapshot(
    shell: object,
    domain: str,
    rid: int,
) -> list[str] | None:
    """Return usernames that belong to a group by RID using memberships.json."""
    snapshot = _load_membership_snapshot(shell, domain)
    if not snapshot:
        return None
    domain_sid = _resolve_domain_sid(shell, domain, snapshot)
    if not domain_sid:
        return None
    target_sid = f"{domain_sid}-{rid}"
    marked_domain = mark_sensitive(domain, "domain")
    print_info_debug(
        f"[membership] group RID lookup for {marked_domain}: "
        f"rid={rid} target_sid={mark_sensitive(target_sid, 'user')}"
    )
    group_label = _resolve_group_label_for_sid(snapshot, domain, target_sid)
    if not group_label:
        return []
    user_groups = snapshot.get("user_to_groups")
    if not isinstance(user_groups, dict):
        return []
    members: list[str] = []
    for user_label in user_groups:
        if not isinstance(user_label, str) or not user_label:
            continue
        recursive_labels = _snapshot_get_recursive_group_labels(
            shell, domain, user_label
        )
        if not recursive_labels:
            continue
        if group_label in recursive_labels:
            members.append(_membership_label_to_name(user_label).lower())
    return sorted(set(members), key=str.lower)


def resolve_group_name_by_rid(
    shell: object,
    domain: str,
    rid: int,
) -> str | None:
    """Resolve a domain group name by RID using snapshot first, then BloodHound.

    Args:
        shell: Shell-like object with workspace and optional BloodHound access.
        domain: Target AD domain.
        rid: Relative identifier of the target group.

    Returns:
        Group name (without ``@DOMAIN`` suffix) when resolvable, otherwise ``None``.
    """
    marked_domain = mark_sensitive(domain, "domain")
    snapshot = _load_membership_snapshot(shell, domain)
    if snapshot:
        domain_sid = _resolve_domain_sid(shell, domain, snapshot)
        if domain_sid:
            target_sid = f"{domain_sid}-{rid}"
            group_label = _resolve_group_label_for_sid(snapshot, domain, target_sid)
            if group_label:
                group_name = _membership_label_to_name(group_label).strip()
                if group_name:
                    print_info_debug(
                        f"[membership] RID {rid} group resolved from snapshot for "
                        f"{marked_domain}: {mark_sensitive(group_name, 'group')}"
                    )
                    return group_name

    service = getattr(shell, "_get_bloodhound_service", None)
    if service:
        try:
            bh_service = service()
            client = getattr(bh_service, "client", None)
            if client and hasattr(client, "execute_query"):
                escaped_domain = (
                    str(domain or "").replace("\\", "\\\\").replace('"', '\\"')
                )
                query = f"""
                MATCH (g:Group)
                WHERE toLower(coalesce(g.domain, "")) = toLower("{escaped_domain}")
                  AND (
                    coalesce(g.objectid, g.objectId, "") =
                    coalesce(g.domainsid, g.domainSid, "") + "-{rid}"
                  )
                RETURN g
                LIMIT 1
                """
                rows = client.execute_query(query)
                if isinstance(rows, list) and rows:
                    row = rows[0]
                    if isinstance(row, dict):
                        node = row.get("g")
                        if isinstance(node, dict):
                            props = (
                                node.get("properties")
                                if isinstance(node.get("properties"), dict)
                                else {}
                            )
                            raw_name = (
                                props.get("samaccountname")
                                or props.get("samAccountName")
                                or node.get("samaccountname")
                                or node.get("samAccountName")
                                or props.get("name")
                                or node.get("name")
                            )
                            if isinstance(raw_name, str) and raw_name.strip():
                                group_name = raw_name.strip()
                                if "@" in group_name:
                                    group_name = group_name.split("@", 1)[0].strip()
                                if group_name:
                                    print_info_debug(
                                        f"[membership] RID {rid} group resolved from BloodHound for "
                                        f"{marked_domain}: {mark_sensitive(group_name, 'group')}"
                                    )
                                    return group_name
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[membership] BloodHound group RID {rid} lookup failed for {marked_domain}: {exc}"
            )

    print_info_debug(f"[membership] RID {rid} group unresolved for {marked_domain}.")
    return None


def resolve_group_user_members(
    shell: object,
    domain: str,
    group_name: str,
    *,
    enabled_only: bool = True,
    max_results: int = 500,
) -> list[str] | None:
    """Resolve recursive user members of a group by name.

    Resolution order:
        1) memberships.json snapshot
        2) BloodHound recursive membership query

    Args:
        shell: Shell-like object with workspace and optional BloodHound access.
        domain: Target AD domain.
        group_name: Group samAccountName/label (with or without ``@DOMAIN``).
        enabled_only: When True, keep enabled users only.
        max_results: Hard cap to avoid huge result sets.

    Returns:
        Sorted usernames (lowercase), ``[]`` when resolvable but no members, or
        ``None`` when no resolver backend is available.
    """
    marked_domain = mark_sensitive(domain, "domain")
    canonical_group = _canonical_membership_label(domain, group_name)
    if not canonical_group:
        return []

    enabled_users = _load_enabled_users(shell, domain) if enabled_only else None
    if enabled_only and enabled_users is None:
        print_info_debug(
            f"[membership] enabled users list missing for {marked_domain}; "
            "falling back to snapshot/BloodHound enabled flags."
        )

    snapshot = _load_membership_snapshot(shell, domain)
    if isinstance(snapshot, dict):
        group_members, has_users = attack_paths_core.build_group_member_index(
            snapshot,
            domain,
            exclude_tier0=False,
        )
        if has_users:
            members_labels = group_members.get(canonical_group, set()) or set()
            members = [
                _membership_label_to_name(label).strip().lower()
                for label in members_labels
                if isinstance(label, str) and _membership_label_to_name(label).strip()
            ]
            if enabled_users is not None:
                members = [user for user in members if user in enabled_users]
            elif enabled_only:
                enabled_map = snapshot.get("user_enabled")
                if isinstance(enabled_map, dict):
                    members = [user for user in members if enabled_map.get(user, True)]
            unique_members = sorted(set(members), key=str.lower)[:max_results]
            marked_group = mark_sensitive(
                _membership_label_to_name(canonical_group), "group"
            )
            print_info_debug(
                f"[membership] group members resolved from memberships.json for "
                f"{marked_group}@{marked_domain}: {len(unique_members)} member(s)."
            )
            return unique_members

    service = getattr(shell, "_get_bloodhound_service", None)
    if service:
        try:
            bh_service = service()
            client = getattr(bh_service, "client", None)
            if client and hasattr(client, "execute_query"):
                group_base = _membership_label_to_name(canonical_group)
                group_with_domain = canonical_group
                escaped_domain = (
                    str(domain or "").replace("\\", "\\\\").replace('"', '\\"')
                )
                escaped_group = (
                    str(group_base).replace("\\", "\\\\").replace('"', '\\"')
                )
                escaped_group_with_domain = (
                    str(group_with_domain).replace("\\", "\\\\").replace('"', '\\"')
                )
                query = f"""
                MATCH (g:Group)
                WHERE toLower(coalesce(g.domain, "")) = toLower("{escaped_domain}")
                  AND (
                    toLower(coalesce(g.samaccountname, g.samAccountName, "")) = toLower("{escaped_group}")
                    OR toLower(coalesce(g.name, "")) = toLower("{escaped_group_with_domain}")
                  )
                WITH g
                MATCH (m:User)-[:MemberOf*1..]->(g)
                RETURN DISTINCT m
                """
                rows = client.execute_query(query)
                members: list[str] = []
                if isinstance(rows, list):
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        node = row.get("m")
                        if not isinstance(node, dict):
                            continue
                        props = (
                            node.get("properties")
                            if isinstance(node.get("properties"), dict)
                            else {}
                        )
                        enabled = node.get("enabled")
                        if enabled_only and enabled_users is None:
                            if enabled is False or props.get("enabled") is False:
                                continue
                        name = (
                            props.get("samaccountname")
                            or props.get("samAccountName")
                            or node.get("samaccountname")
                            or node.get("samAccountName")
                            or props.get("name")
                            or node.get("name")
                        )
                        if isinstance(name, str) and name.strip():
                            members.append(name.strip().lower())
                if enabled_users is not None:
                    members = [user for user in members if user in enabled_users]
                unique_members = sorted(set(members), key=str.lower)[:max_results]
                marked_group = mark_sensitive(group_base, "group")
                print_info_debug(
                    f"[membership] group members resolved from BloodHound for "
                    f"{marked_group}@{marked_domain}: {len(unique_members)} member(s)."
                )
                return unique_members
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            marked_group = mark_sensitive(
                _membership_label_to_name(canonical_group), "group"
            )
            print_info_debug(
                f"[membership] BloodHound group member lookup failed for "
                f"{marked_group}@{marked_domain}: {exc}"
            )

    print_info_debug(
        f"[membership] group member resolvers unavailable for {marked_domain}: "
        f"group={mark_sensitive(_membership_label_to_name(canonical_group), 'group')}"
    )
    return None


def get_recursive_principal_groups_from_snapshot(
    shell: object, domain: str, principal: str
) -> list[str] | None:
    """Return recursive group memberships for a principal using memberships.json.

    Args:
        shell: Shell instance (for workspace + domains dir resolution).
        domain: Target domain.
        principal: Principal label (samAccountName or label).

    Returns:
        List of group names when memberships.json is available, or None when the
        snapshot is missing/unavailable.
    """
    return _snapshot_get_recursive_groups(shell, domain, principal)


def _snapshot_get_direct_group_parents(
    shell: object, domain: str, group_label: str
) -> list[str] | None:
    snapshot = _load_membership_snapshot(shell, domain)
    if not snapshot:
        return None
    group_to_parents = snapshot.get("group_to_parents")
    if not isinstance(group_to_parents, dict):
        return []
    canonical = _canonical_membership_label(domain, group_label)
    parents = group_to_parents.get(canonical, []) or []
    return [_membership_label_to_name(parent) for parent in parents]


def _expand_group_ancestors(
    domain: str,
    group_label: str,
    group_to_parents: dict[str, Any],
    cache: dict[str, set[str]],
) -> set[str]:
    """Return recursive ancestor groups for a canonical group label."""
    if group_label in cache:
        return cache[group_label]

    def _parent_labels(label: str) -> list[str]:
        parents = group_to_parents.get(label, []) if group_to_parents else []
        if not isinstance(parents, list):
            return []
        labels: list[str] = []
        for parent in parents:
            normalized = _canonical_membership_label(domain, parent)
            if normalized:
                labels.append(normalized)
        return labels

    stack: list[tuple[str, bool]] = [(group_label, False)]
    resolving: set[str] = set()

    while stack:
        current, expanded = stack.pop()
        if current in cache:
            continue

        if expanded:
            results: set[str] = set()
            for parent_label in _parent_labels(current):
                if parent_label == current:
                    continue
                results.add(parent_label)
                parent_cached = cache.get(parent_label)
                if parent_cached:
                    results.update(parent_cached)
            results.discard(current)
            cache[current] = results
            resolving.discard(current)
            continue

        if current in resolving:
            continue
        resolving.add(current)
        stack.append((current, True))

        for parent_label in _parent_labels(current):
            if (
                parent_label in cache
                or parent_label in resolving
                or parent_label == current
            ):
                continue
            stack.append((parent_label, False))

    return cache.get(group_label, set())


def _log_attack_path_compute_timing(
    *,
    domain: str,
    scope: str,
    elapsed_seconds: float,
    path_count: int,
    max_depth: int,
    require_high_value_target: bool,
    target_mode: str,
) -> None:
    """Emit centralized timing metrics for attack-path computations."""
    marked_domain = mark_sensitive(domain, "domain")
    print_info_verbose(
        f"[attack_paths] compute scope={scope} domain={marked_domain} "
        f"paths={path_count} max_depth={max_depth} "
        f"high_value_only={require_high_value_target!r} target_mode={target_mode} "
        f"elapsed={elapsed_seconds:.2f}s"
    )
    if elapsed_seconds >= 30.0:
        print_info(
            f"Attack-path computation ({scope}) for {marked_domain} "
            f"took {elapsed_seconds:.1f}s ({path_count} paths)."
        )


def _file_mtime_token(path: str) -> float | None:
    """Return file mtime token for cache invalidation."""
    try:
        if not path or not os.path.exists(path):
            return None
        return os.path.getmtime(path)
    except OSError:
        return None


def _attack_paths_cache_base_key(
    shell: object,
    domain: str,
    *,
    scope: str,
    params: tuple[Any, ...],
) -> tuple[Any, ...]:
    """Build cache key bound to graph/snapshot mtimes plus query params."""
    graph_path = _graph_path(shell, domain)
    snapshot_path = _membership_snapshot_path(shell, domain)
    return (
        str(domain or "").strip().lower(),
        str(scope or "").strip().lower(),
        _file_mtime_token(graph_path),
        _file_mtime_token(snapshot_path),
        params,
    )


def _attack_paths_cache_get(
    key: tuple[Any, ...], *, domain: str, scope: str
) -> list[dict[str, Any]] | None:
    """Return cached attack-path records when available."""
    if not _ATTACK_PATHS_CACHE_ENABLED:
        return None
    cached = _ATTACK_PATHS_COMPUTE_CACHE.get(key)
    if cached is None:
        _cache_stats_inc(domain, "misses")
        return None
    _cache_stats_inc(domain, "hits")
    # LRU touch.
    _ATTACK_PATHS_COMPUTE_CACHE.move_to_end(key)
    print_info_debug(
        f"[attack_paths] cache hit: domain={mark_sensitive(domain, 'domain')} "
        f"scope={scope} records={len(cached)}"
    )
    return copy.deepcopy(cached)


def _attack_paths_cache_put(
    key: tuple[Any, ...],
    records: list[dict[str, Any]],
    *,
    domain: str,
    scope: str,
) -> None:
    """Store attack-path records in bounded LRU cache."""
    if not _ATTACK_PATHS_CACHE_ENABLED:
        return
    if len(records) > _ATTACK_PATHS_CACHE_MAX_RECORDS:
        _cache_stats_inc(domain, "skips")
        print_info_debug(
            f"[attack_paths] cache skip: domain={mark_sensitive(domain, 'domain')} "
            f"scope={scope} records={len(records)} reason=too_many"
        )
        return
    _ATTACK_PATHS_COMPUTE_CACHE[key] = copy.deepcopy(records)
    _cache_stats_inc(domain, "stores")
    _ATTACK_PATHS_COMPUTE_CACHE.move_to_end(key)
    evicted = 0
    while len(_ATTACK_PATHS_COMPUTE_CACHE) > _ATTACK_PATHS_CACHE_MAX_ENTRIES:
        _ATTACK_PATHS_COMPUTE_CACHE.popitem(last=False)
        evicted += 1
    if evicted:
        _cache_stats_inc(domain, "evictions", by=evicted)
    print_info_debug(
        f"[attack_paths] cache store: domain={mark_sensitive(domain, 'domain')} "
        f"scope={scope} records={len(records)} entries={len(_ATTACK_PATHS_COMPUTE_CACHE)}"
    )


def _invalidate_attack_paths_cache(domain: str, *, reason: str) -> None:
    """Invalidate in-memory attack-path cache entries for a domain."""
    if not _ATTACK_PATHS_CACHE_ENABLED:
        return
    domain_key = str(domain or "").strip().lower()
    removed = 0
    keys = list(_ATTACK_PATHS_COMPUTE_CACHE.keys())
    for key in keys:
        if not isinstance(key, tuple) or not key:
            continue
        if str(key[0] or "").strip().lower() != domain_key:
            continue
        _ATTACK_PATHS_COMPUTE_CACHE.pop(key, None)
        removed += 1
    if removed:
        _cache_stats_inc(domain, "invalidations", by=1)
        print_info_debug(
            f"[attack_paths] cache invalidated: domain={mark_sensitive(domain, 'domain')} "
            f"entries={removed} reason={reason}"
        )


def get_attack_paths_cache_stats(
    *,
    domain: str | None = None,
    reset: bool = False,
) -> dict[str, int]:
    """Return attack-path cache counters (global or per-domain).

    Args:
        domain: Optional domain filter.
        reset: When True, reset returned counters to zero after reading.
    """
    if domain:
        domain_key = str(domain or "").strip().lower()
        stats = copy_stats(_ATTACK_PATHS_CACHE_DOMAIN_STATS.get(domain_key, {}))
        if reset:
            _ATTACK_PATHS_CACHE_DOMAIN_STATS[domain_key] = {}
        return stats

    stats = copy_stats(_ATTACK_PATHS_CACHE_STATS)
    if reset:
        reset_stats(_ATTACK_PATHS_CACHE_STATS)
        _ATTACK_PATHS_CACHE_DOMAIN_STATS.clear()
    return stats


__all__ = [
    "get_attack_path_summaries",
    "get_owned_domain_usernames_for_attack_paths",
    "get_recursive_principal_groups_from_snapshot",
    "is_principal_member_of_rid_from_snapshot",
    "get_users_in_group_rid_from_snapshot",
    "resolve_group_name_by_rid",
    "resolve_group_user_members",
    "resolve_group_members_by_rid",
    "resolve_principal_groups",
    "resolve_user_sid",
    "_normalize_machine_account",
]


def _build_group_membership_index(
    shell: object,
    domain: str,
    *,
    principal_labels: Iterable[str] | None = None,
    sample_limit: int = 3,
) -> tuple[dict[str, int], dict[str, list[str]]]:
    """Build group membership counts (recursive) for principals in scope."""
    snapshot = _load_membership_snapshot(shell, domain)
    return attack_paths_core.build_group_membership_index(
        snapshot, domain, principal_labels=principal_labels, sample_limit=sample_limit
    )


def _build_group_member_index(
    shell: object,
    domain: str,
    *,
    exclude_tier0: bool = False,
) -> tuple[dict[str, set[str]], bool]:
    """Build group -> members index (recursive) for users in scope."""
    snapshot = _load_membership_snapshot(shell, domain)
    return attack_paths_core.build_group_member_index(
        snapshot, domain, exclude_tier0=exclude_tier0
    )


def _collapse_memberof_prefixes(
    shell: object,
    domain: str,
    records: list[dict[str, Any]],
    *,
    principal_labels: Iterable[str] | None = None,
    sample_limit: int = 3,
) -> list[dict[str, Any]]:
    """Collapse leading MemberOf edges when a group has multiple principals."""
    snapshot = _load_membership_snapshot(shell, domain)
    return attack_paths_core.collapse_memberof_prefixes(
        records,
        domain,
        snapshot,
        principal_labels=principal_labels,
        sample_limit=sample_limit,
    )


def _apply_affected_user_metadata(
    shell: object,
    domain: str,
    records: list[dict[str, Any]],
    *,
    filter_empty: bool = True,
) -> list[dict[str, Any]]:
    """Annotate paths with affected-user metadata plus shell-aware fallbacks."""
    if not records:
        return []

    snapshot = _load_membership_snapshot(shell, domain)
    base_graph = load_attack_graph(shell, domain)
    annotated = attack_paths_core.apply_affected_user_metadata(
        records,
        graph=base_graph,
        domain=domain,
        snapshot=snapshot,
        filter_empty=filter_empty,
    )
    if not annotated:
        return []

    nodes_map = (
        base_graph.get("nodes") if isinstance(base_graph.get("nodes"), dict) else {}
    )
    label_kind_map: dict[str, str] = {}
    if isinstance(nodes_map, dict):
        for node in nodes_map.values():
            if not isinstance(node, dict):
                continue
            canonical = _canonical_membership_label(
                domain, _canonical_node_label(node)
            )
            if canonical:
                label_kind_map[canonical] = _node_kind(node)

    group_members, has_users = attack_paths_core.build_group_member_index(
        snapshot, domain, exclude_tier0=True
    )
    broad_group_names = {
        "DOMAIN USERS",
        "AUTHENTICATED USERS",
        "EVERYONE",
        "USERS",
    }

    fallback_domain_users_source = ""
    enabled_users = get_enabled_users_for_domain(shell, domain)
    if enabled_users:
        fallback_domain_users = sorted(enabled_users)
        fallback_domain_users_source = "enabled_users"
    else:
        loaded_domain_users = _load_domain_users(shell, domain)
        if loaded_domain_users:
            fallback_domain_users = loaded_domain_users
            fallback_domain_users_source = "users"
        else:
            snapshot_domain_users = sorted(
                {
                    _membership_label_to_name(label)
                    for label in (
                        snapshot.get("user_to_groups", {}).keys()
                        if isinstance(snapshot, dict)
                        and isinstance(snapshot.get("user_to_groups"), dict)
                        else []
                    )
                    if isinstance(label, str) and str(label).strip()
                },
                key=str.lower,
            )
            fallback_domain_users = snapshot_domain_users or None
            if snapshot_domain_users:
                fallback_domain_users_source = "snapshot"

    enriched: list[dict[str, Any]] = []
    for record in annotated:
        current = dict(record)
        meta = current.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            current["meta"] = meta

        nodes = current.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            enriched.append(current)
            continue
        source_label = str(nodes[0] or "").strip()
        execution_scope = _derive_execution_scope_metadata(current, source_label)
        if execution_scope:
            meta.update(execution_scope)
        scope_label = _canonical_membership_label(domain, source_label)
        if not scope_label:
            enriched.append(current)
            continue

        scope_name = _membership_label_to_name(scope_label).upper()
        source_name = scope_name

        should_override = (
            not isinstance(meta.get("affected_user_count"), int)
            or int(meta.get("affected_user_count", 0)) <= 0
        )
        if not should_override:
            enriched.append(current)
            continue

        affected_users: list[str] = []
        affected_count = 0
        affected_source = ""
        kind = label_kind_map.get(scope_label, "")
        if kind == "Group":
            resolved_members = resolve_group_user_members(
                shell,
                domain,
                scope_label,
                enabled_only=True,
                max_results=100_000,
            )
            if resolved_members is not None:
                affected_users = list(resolved_members)
                affected_count = len(affected_users)
                affected_source = "group_resolver"
            elif scope_name in broad_group_names and fallback_domain_users:
                affected_users = list(fallback_domain_users)
                affected_count = len(affected_users)
                affected_source = fallback_domain_users_source
            elif has_users:
                affected_users = sorted(group_members.get(scope_label, set()), key=str.lower)
                affected_count = len(affected_users)
                if affected_count > 0:
                    affected_source = "snapshot_group_members"
        elif scope_label:
            affected_users = [_membership_label_to_name(scope_label)]
            affected_count = 1
            affected_source = "principal"

        if affected_count > 0:
            meta["affected_user_count"] = affected_count
            meta["affected_users"] = affected_users
            if affected_source:
                meta["affected_users_source"] = affected_source
            if affected_source == "group_resolver":
                print_info_debug(
                    "[attack_paths] affected users resolved through centralized group membership resolver: "
                    f"domain={mark_sensitive(domain, 'domain')} "
                    f"source={source_name or 'N/A'} "
                    f"scope={scope_name} "
                    f"count={affected_count}"
                )
            elif scope_name in broad_group_names and fallback_domain_users_source:
                print_info_debug(
                    "[attack_paths] affected users derived from broad group scope: "
                    f"domain={mark_sensitive(domain, 'domain')} "
                    f"source={source_name or 'N/A'} "
                    f"scope={scope_name} "
                    f"count={affected_count} "
                    f"fallback={fallback_domain_users_source}"
                )

        enriched.append(current)

    return enriched


def _derive_execution_scope_metadata(
    record: dict[str, Any],
    source_label: str,
) -> dict[str, str]:
    """Return execution-scope metadata for synthetic entry principals."""
    normalized_source = _membership_label_to_name(source_label).strip().upper()
    if not normalized_source:
        return {}

    relations = record.get("relations")
    first_relation = str(relations[0] or "").strip() if isinstance(relations, list) and relations else ""
    relation_key = _normalize_relation_key(first_relation)

    if normalized_source == "ANONYMOUS LOGON":
        execution_scope = "Any unauthenticated internal client"
        if relation_key == "ldapanonymousbind":
            execution_scope = "Any unauthenticated internal client with LDAP access"
        elif relation_key == "nullsession":
            execution_scope = "Any unauthenticated SMB client"
        return {
            "execution_scope": execution_scope,
            "execution_scope_source": "anonymous_logon",
        }

    if normalized_source in {"NULL SESSION", "NULLSESSION"}:
        return {
            "execution_scope": "Any unauthenticated SMB client",
            "execution_scope_source": "null_session",
        }

    if normalized_source in {"GUEST SESSION", "GUEST"}:
        return {
            "execution_scope": "Any guest-authenticated client",
            "execution_scope_source": "guest_session",
        }

    return {}


def _filter_shortest_paths_for_principals(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep only the shortest path per (terminal from, relation, terminal to)."""
    return attack_paths_core.filter_shortest_paths_for_principals(records)


def _graph_has_persisted_memberships(graph: dict[str, Any]) -> bool:
    """Return True when the graph already contains persisted membership edges.

    We use this to decide whether runtime recursive membership injection is
    necessary for attack-path stitching.
    """
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


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_relation(value: str) -> str:
    return (value or "").strip()


def _normalize_relation_key(value: str) -> str:
    """Normalize relation names for classification (case-insensitive, punctuation-free)."""
    return re.sub(r"[^a-z0-9]+", "", (value or "").strip().lower())


def _classify_edge_relation(relation: str) -> tuple[str, str | None]:
    """Return (category, vuln_key) for a relation."""
    relation_key = _normalize_relation_key(relation)
    vuln_key = EXPLOITATION_EDGE_VULN_KEYS.get(relation_key)
    if vuln_key:
        return "exploitation", vuln_key
    return "relationship", None


def _load_latest_certipy_json(domain_dir: str) -> str | None:
    """Return path to latest Certipy JSON output under the domain adcs directory."""
    if not domain_dir:
        return None
    adcs_dir = os.path.join(domain_dir, "adcs")
    if not os.path.isdir(adcs_dir):
        return None
    # Prefer the stable Phase-1 inventory file when present. Other Certipy runs
    # (e.g. per-user `-vulnerable` checks) may produce additional JSON files in
    # the same directory and should not override the canonical template inventory.
    preferred = os.path.join(adcs_dir, "certipy_find_Certipy.json")
    if os.path.exists(preferred):
        return preferred
    candidates: list[tuple[float, str]] = []
    for name in os.listdir(adcs_dir):
        if not name.endswith("_Certipy.json"):
            continue
        path = os.path.join(adcs_dir, name)
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        candidates.append((mtime, path))
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def _extract_certipy_principals(entry: dict[str, Any]) -> list[str]:
    """Extract enrollee principals from a Certipy template entry."""
    for key in (
        "[+] User Enrollable Principals",
        "[+] Enrollable Principals",
        "User Enrollable Principals",
        "Enrollable Principals",
    ):
        value = entry.get(key)
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
        if isinstance(value, dict):
            return [str(item) for item in value.keys() if str(item).strip()]
    return []


def _normalize_certipy_principal(*, domain: str, principal: str) -> tuple[str, str]:
    """Normalize certipy principal strings into (domain, group_name)."""
    raw = str(principal or "").strip()
    if not raw:
        return domain, ""
    if "\\" in raw:
        left, _, right = raw.partition("\\")
        return (left.strip() or domain), right.strip()
    if "@" in raw:
        left, _, right = raw.partition("@")
        return (right.strip() or domain), left.strip()
    return domain, raw


def _should_skip_certipy_object_control_principal(name: str) -> bool:
    """Return True when a Certipy object-control principal should be ignored for path sources."""
    lower = str(name or "").strip().lower()
    if not lower:
        return True
    # Ignore built-in service principals that should never be treated as an operator path source.
    if lower in {"local system", "nt authority\\system", "system"}:
        return True
    return False


def _extract_certipy_object_control_principals(entry: dict[str, Any]) -> set[str]:
    """Extract object-control principals from a Certipy template entry."""
    permissions = entry.get("Permissions")
    if not isinstance(permissions, dict):
        return set()
    object_control = permissions.get("Object Control Permissions")
    if not isinstance(object_control, dict):
        return set()
    principals: set[str] = set()
    for key in (
        "Full Control Principals",
        "Write Owner Principals",
        "Write Dacl Principals",
    ):
        values = object_control.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value.strip():
                principals.add(value.strip())
    return principals


def get_certipy_adcs_paths(
    shell: object,
    domain: str,
    *,
    graph: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build ADCS escalation edges based on Certipy JSON output.

    Notes:
        Certipy's `[!] Vulnerabilities` section is *principal-aware* when
        generated via `certipy find` and can reflect only the user that ran the
        command. Phase 2 path discovery needs a domain-wide view (e.g. when
        BloodHound shows `ADCSESC4` for a different low-priv user than the
        credential we used to run Certipy). For ESC4 specifically, we can infer
        candidates from the template's object-control ACL lists (WriteDACL /
        WriteOwner / FullControl) emitted in the JSON.
    """
    domain_key = str(domain or "").strip()
    if not domain_key:
        return []
    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    domain_dir = domain_data.get("dir") if isinstance(domain_data, dict) else None
    if not isinstance(domain_dir, str) or not domain_dir:
        return []
    json_path = _load_latest_certipy_json(domain_dir)
    if not json_path:
        return []
    try:
        data = read_json_file(json_path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return []
    templates = data.get("Certificate Templates")
    if not isinstance(templates, dict):
        return []

    domain_node = {
        "name": domain_key,
        "kind": ["Domain"],
        "properties": {"name": domain_key, "domain": domain_key},
        "isTierZero": True,
    }

    loaded_graph = graph
    if loaded_graph is None:
        try:
            loaded_graph = load_attack_graph(shell, domain_key)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            loaded_graph = None

    def _canonical_principal_label(*, principal_domain: str, name: str) -> str:
        name_clean = str(name or "").strip()
        domain_clean = str(principal_domain or "").strip()
        if not name_clean or not domain_clean:
            return name_clean or ""
        if "@" in name_clean:
            left, _, right = name_clean.partition("@")
            if left and right:
                return f"{left.strip().upper()}@{right.strip().upper()}"
        return f"{name_clean.strip().upper()}@{domain_clean.strip().upper()}"

    def _infer_principal_kind(name: str) -> str:
        raw = str(name or "").strip()
        if raw.endswith("$"):
            return "Computer"
        if " " in raw:
            return "Group"
        return "User"

    def _principal_is_tier0(label: str) -> bool:
        if not loaded_graph:
            return False
        try:
            node_id = _find_node_id_by_label(loaded_graph, label)
            if not node_id:
                return False
            nodes_map = (
                loaded_graph.get("nodes")
                if isinstance(loaded_graph.get("nodes"), dict)
                else {}
            )
            node = nodes_map.get(node_id) if isinstance(nodes_map, dict) else None
            if not isinstance(node, dict):
                return False
            return _node_is_tier0(node)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return False

    edges: list[dict[str, Any]] = []
    for entry in templates.values():
        if not isinstance(entry, dict):
            continue
        vulnerabilities = entry.get("[!] Vulnerabilities") or {}
        if isinstance(vulnerabilities, dict) and vulnerabilities:
            principals = _extract_certipy_principals(entry)
            if principals:
                for vuln in vulnerabilities.keys():
                    relation = f"ADCS{str(vuln).strip().upper()}"
                    for principal in principals:
                        principal_domain, group_name = _normalize_certipy_principal(
                            domain=domain_key, principal=principal
                        )
                        if not group_name:
                            continue
                        group_label = _canonical_group_label(
                            domain=principal_domain, group_name=group_name
                        )
                        if not group_label:
                            continue
                        group_node = {
                            "name": group_label,
                            "kind": ["Group"],
                            "properties": {
                                "name": group_label,
                                "domain": str(principal_domain or domain_key)
                                .strip()
                                .upper(),
                            },
                        }
                        edges.append(
                            {
                                "nodes": [group_node, domain_node],
                                "rels": [relation],
                            }
                        )

        # ESC4 (template object control) can apply to principals other than the
        # user that executed certipy. Infer it from template ACL lists.
        try:
            enabled = entry.get("Enabled")
            cas = entry.get("Certificate Authorities")
            if enabled is False:
                continue
            if isinstance(cas, list) and not cas:
                continue
            object_control_principals = _extract_certipy_object_control_principals(
                entry
            )
            if not object_control_principals:
                continue
            for principal in sorted(object_control_principals, key=str.lower):
                principal_domain, principal_name = _normalize_certipy_principal(
                    domain=domain_key, principal=principal
                )
                if _should_skip_certipy_object_control_principal(principal_name):
                    continue
                principal_label = _canonical_principal_label(
                    principal_domain=principal_domain, name=principal_name
                )
                if not principal_label:
                    continue
                if _principal_is_tier0(principal_label):
                    continue
                kind = _infer_principal_kind(principal_name)
                principal_node = {
                    "name": principal_label,
                    "kind": [kind],
                    "properties": {
                        "name": principal_label,
                        "domain": str(principal_domain or domain_key).strip().upper(),
                        "samaccountname": principal_name,
                    },
                }
                edges.append(
                    {
                        "nodes": [principal_node, domain_node],
                        "rels": ["ADCSESC4"],
                    }
                )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
    print_info_debug(
        f"[attack_graph] certipy-derived ADCS paths for {mark_sensitive(domain_key, 'domain')}: "
        f"count={len(edges)}"
    )
    return edges


def resolve_certipy_esc4_templates_for_principal(
    shell: object,
    *,
    domain: str,
    principal_samaccountname: str,
    json_path: str | None = None,
    groups: list[str] | None = None,
) -> list[str]:
    """Resolve ESC4 candidate templates for a principal from Certipy JSON.

    Certipy's `[!] Vulnerabilities` is principal-aware. For ESC4 we can infer
    candidates for a given user by checking whether the user (or any of their
    groups) appears in the template's Object Control permission lists.

    Args:
        shell: Shell providing workspace/domain context.
        domain: Target domain.
        principal_samaccountname: Principal `samaccountname` (e.g. `khal.drogo`).
        json_path: Optional explicit Certipy JSON path (defaults to latest in domain dir).
        groups: Optional recursive group names for the principal (names only, no DOMAIN\\ prefix).

    Returns:
        Sorted list of template names that appear ESC4-abusable for the principal.
    """
    domain_key = str(domain or "").strip()
    sam_clean = str(principal_samaccountname or "").strip()
    if not domain_key or not sam_clean:
        return []

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    domain_dir = domain_data.get("dir") if isinstance(domain_data, dict) else None
    if not isinstance(domain_dir, str) or not domain_dir:
        return []

    effective_json_path = json_path or _load_latest_certipy_json(domain_dir)
    if not effective_json_path:
        return []

    try:
        data = read_json_file(effective_json_path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return []

    templates = data.get("Certificate Templates")
    if not isinstance(templates, dict):
        return []

    effective_groups = groups
    if effective_groups is None:
        try:
            effective_groups = _attack_path_get_recursive_groups(
                shell,
                domain=domain_key,
                samaccountname=sam_clean,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            effective_groups = []

    sam_lower = sam_clean.lower()
    groups_lower = {
        str(g).strip().lower() for g in (effective_groups or []) if str(g).strip()
    }

    matches: set[str] = set()
    for entry in templates.values():
        if not isinstance(entry, dict):
            continue
        enabled = entry.get("Enabled")
        cas = entry.get("Certificate Authorities")
        if enabled is False:
            continue
        if isinstance(cas, list) and not cas:
            continue
        template_name = str(entry.get("Template Name") or "").strip()
        if not template_name:
            continue

        principals = _extract_certipy_object_control_principals(entry)
        if not principals:
            continue
        for raw in principals:
            principal_domain, principal_name = _normalize_certipy_principal(
                domain=domain_key, principal=raw
            )
            _ = principal_domain
            if _should_skip_certipy_object_control_principal(principal_name):
                continue
            name_lower = str(principal_name or "").strip().lower()
            if not name_lower:
                continue
            if name_lower == sam_lower or name_lower in groups_lower:
                matches.add(template_name)
                break

    return sorted(matches, key=str.lower)


def get_certipy_template_metadata(shell: object, domain: str) -> dict[str, Any]:
    """Load Certipy JSON and return template metadata keyed by template name."""
    domain_key = str(domain or "").strip().lower()
    if not domain_key:
        return {}
    if domain_key in _CERTIPY_TEMPLATE_CACHE:
        return _CERTIPY_TEMPLATE_CACHE[domain_key]

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    domain_dir = domain_data.get("dir") if isinstance(domain_data, dict) else None
    if not isinstance(domain_dir, str) or not domain_dir:
        return {}
    json_path = _load_latest_certipy_json(domain_dir)
    if not json_path:
        return {}

    try:
        data = read_json_file(json_path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return {}

    templates = data.get("Certificate Templates")
    if not isinstance(templates, dict):
        return {}

    metadata: dict[str, Any] = {}
    for entry in templates.values():
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("Template Name") or "").strip()
        if not name:
            continue
        vulnerabilities = entry.get("[!] Vulnerabilities") or {}
        vuln_list = []
        if isinstance(vulnerabilities, dict):
            vuln_list = list(vulnerabilities.keys())
        min_key = entry.get("Minimum RSA Key Length")
        try:
            min_key_int = int(min_key) if min_key is not None else None
        except Exception:  # noqa: BLE001
            min_key_int = None
        metadata[name] = {
            "min_key_length": min_key_int,
            "vulnerabilities": vuln_list,
        }

    _CERTIPY_TEMPLATE_CACHE[domain_key] = metadata
    print_info_debug(
        f"[attack_graph] Loaded certipy template metadata for {mark_sensitive(domain, 'domain')}: "
        f"templates={len(metadata)}"
    )
    return metadata


def _canonical_account_identifier(value: str) -> str:
    """Normalize an AD principal identifier to a stable, domain-local form.

    Examples:
        - NORTH\\jon.snow -> jon.snow
        - JON.SNOW@NORTH.SEVENKINGDOMS.LOCAL -> jon.snow
        - WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL -> winterfell.north.sevenkingdoms.local
    """
    name = (value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def _canonical_node_label(node: dict[str, Any]) -> str:
    """Pick a stable display label for a node.

    For Users/Computers we prefer BloodHound's canonical `NAME@DOMAIN` when
    available. This avoids ambiguous cross-domain displays and prevents
    accidental duplication in attack paths (e.g. `svc-alfresco` vs
    `SVC-ALFRESCO@HTB.LOCAL`).

    For other objects, we fall back to `name` or existing labels.
    """
    kind = _node_kind(node)
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}

    def _pick(*values: object) -> str | None:
        for value in values:
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    if kind in {"User", "Computer"}:
        canonical = _pick(props.get("name"), node.get("name"))
        if canonical and "@" in canonical:
            return canonical

        sam = _pick(props.get("samaccountname"), node.get("samaccountname"))
        domain = _pick(props.get("domain"), node.get("domain"))
        if sam and domain:
            return f"{sam.upper()}@{domain.upper()}"
        if sam:
            return sam

    # Prefer canonical "name" for groups/GPOs/etc, then existing label.
    return (
        _pick(props.get("name"), node.get("name"), node.get("label"))
        or _pick(node.get("objectId"), node.get("objectid"))
        or "N/A"
    )


def _canonical_node_id_value(node: dict[str, Any]) -> str:
    """Compute the canonical *name* portion for our `name:<value>` node IDs.

    We intentionally avoid using objectId for Users/Computers because other
    parts of the tool (e.g. roasting discovery) may not have SIDs available.
    The canonical name is domain-local because graphs are persisted per domain.
    """
    kind = _node_kind(node)
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}

    def _pick(*values: object) -> str | None:
        for value in values:
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    # Users/Computers: prefer samAccountName, fall back to `name`/`label`.
    if kind in {"User", "Computer"}:
        raw = _pick(
            props.get("samaccountname"),
            node.get("samaccountname"),
            props.get("name"),
            node.get("name"),
            node.get("label"),
        )
        if raw:
            return _canonical_account_identifier(raw)

    # Other objects: use objectId when present (stable + unique), otherwise name/label.
    object_id = _pick(node.get("objectId"), node.get("objectid"), props.get("objectid"))
    if object_id:
        return object_id

    raw = _pick(props.get("name"), node.get("name"), node.get("label"))
    if raw:
        return _canonical_account_identifier(raw)

    return _canonical_account_identifier(_canonical_node_label(node))


def _node_display_name(node: dict[str, Any]) -> str:
    return _canonical_node_label(node)


def _node_id(node: dict[str, Any]) -> str:
    return f"name:{_canonical_node_id_value(node)}"


def _node_kind(node: dict[str, Any]) -> str:
    kind = node.get("kind") or node.get("labels") or node.get("type")
    if isinstance(kind, list) and kind:
        # BloodHound can return multiple labels where the "real" type is not
        # the first element (e.g., ["Base", "User"]). Prefer known primary types.
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


def _node_is_tier0(node: dict[str, Any]) -> bool:
    """Return True when node represents a Tier-0 (domain-compromise) target.

    We treat Tier-0 as:
      - explicit `isTierZero` markers (node or properties)
      - `admin_tier_0` system tag (node or properties)

    Notes:
        We intentionally exclude BloodHound's `highvalue` flag here because
        it can represent "high impact" targets that do not necessarily imply
        domain compromise (e.g. some built-in operator groups).
    """
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
    """Return True when node looks like a known privileged AD group.

    BloodHound does not always tag built-in groups as high-value. We treat a
    small set of well-known privileged groups as "effectively high value" so
    high-value filtering behaves as operators expect.

    Implementation detail:
        We intentionally avoid matching on group names because they can be
        localized. Instead, we match on well-known SIDs/RIDs when present.
    """
    if _node_kind(node) != "Group":
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
    # BloodHound CE sometimes prefixes the SID with the domain string, e.g.:
    #   HTB.LOCAL-S-1-5-32-548
    # Normalise it so we can reliably reason about SIDs/RIDs.
    sid_idx = sid_upper.find("S-1-")
    if sid_idx != -1:
        sid_upper = sid_upper[sid_idx:]

    rid: int | None = None
    try:
        rid = int(sid_upper.rsplit("-", 1)[-1])
    except Exception:
        rid = None

    # Built-in local groups (BUILTIN domain) have well-known RIDs.
    # These are language-agnostic and stable.
    builtin_privileged_rids = {544, 548, 549, 550, 551}
    if rid in builtin_privileged_rids and sid_upper.startswith("S-1-5-32-"):
        return True

    # Domain-specific privileged groups have stable RIDs appended to the domain SID.
    # Examples:
    # - Domain Admins:     ...-512
    # - Schema Admins:     ...-518
    # - Enterprise Admins: ...-519
    domain_privileged_rids = {512, 518, 519}
    if rid in domain_privileged_rids:
        return True

    # Best-effort: DnsAdmins is commonly created with RID 1101 when DNS is installed.
    # This is not as universally stable as built-in groups, but is still useful for
    # "effective high value" filtering in most environments.
    if rid == 1101:
        return True

    return False


def _node_is_effectively_high_value(node: dict[str, Any]) -> bool:
    # "Effective high value" is an "impact" concept: include BloodHound's
    # broader `highvalue` marker plus our SID/RID privileged-group heuristics.
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if _node_is_tier0(node):
        return True
    if bool(node.get("highvalue")) or bool(props.get("highvalue")):
        return True
    return _node_is_privileged_group(node)


def _node_is_impact_high_value(node: dict[str, Any]) -> bool:
    """Return True for "high impact" (not necessarily domain-compromise) nodes."""
    return _node_is_effectively_high_value(node)


def _extract_group_name_from_bh(value: str) -> str:
    """Normalize BloodHound group strings like 'GROUP@DOMAIN' to 'GROUP'."""
    raw = (value or "").strip()
    if "@" in raw:
        raw = raw.split("@", 1)[0]
    return raw.strip()


def _attack_path_get_recursive_groups(
    shell: object,
    *,
    domain: str,
    samaccountname: str,
    force_source: str | None = None,
) -> list[str]:
    """Resolve recursive group memberships for attack-path computations.

    This helper is intentionally *only* used by attack-path computation code so
    we can tune speed/accuracy trade-offs independently from other flows (e.g.
    privileged verification).

    Args:
        shell: Shell providing LDAP/BloodHound integrations.
        domain: Target domain.
        samaccountname: Principal sAMAccountName (user or computer).
        require_additional_on_miss: When True and the primary method returns a
            non-empty list, we still try the secondary method if no downstream
            match is found (caller-controlled). This avoids missing high-value
            promotions when BloodHound data is stale.

    Returns:
        Deduplicated list of group identifiers (group names; may contain spaces).
    """
    sam_clean = (samaccountname or "").strip()
    domain_clean = (domain or "").strip()
    if not sam_clean or not domain_clean:
        return []

    snapshot_groups = _snapshot_get_recursive_groups(shell, domain_clean, sam_clean)
    snapshot_empty = snapshot_groups is not None and not snapshot_groups
    if snapshot_groups:
        return snapshot_groups

    primary = (force_source or ATTACK_PATH_GROUP_MEMBERSHIP_PRIMARY).strip().lower()
    if primary not in {"ldap", "bloodhound"}:
        primary = "bloodhound"

    def _from_bloodhound() -> list[str]:
        try:
            if not hasattr(shell, "_get_bloodhound_service"):
                return []
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
            getter = getattr(service, "get_user_groups", None)
            if not callable(getter):
                return []
            groups = getter(domain_clean, sam_clean, True)
            if not isinstance(groups, list):
                return []
            return [
                _extract_group_name_from_bh(str(group))
                for group in groups
                if str(group).strip()
            ]
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return []

    def _from_ldap() -> list[str]:
        try:
            from adscan_internal.cli.ldap import get_recursive_principal_groups_in_chain

            groups = get_recursive_principal_groups_in_chain(
                shell, domain=domain_clean, target_samaccountname=sam_clean
            )
            return list(groups) if isinstance(groups, list) else []
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return []

    primary_fn = _from_bloodhound if primary == "bloodhound" else _from_ldap
    secondary_fn = _from_ldap if primary == "bloodhound" else _from_bloodhound

    if snapshot_empty:
        try:
            marked_domain = mark_sensitive(domain_clean, "domain")
            marked_sam = mark_sensitive(sam_clean, "user")
            print_info_debug(
                f"[attack_paths] Snapshot groups empty for {marked_sam}@{marked_domain}; "
                f"trying {primary} lookup."
            )
        except Exception:
            pass

    groups = primary_fn()
    if groups:
        return sorted(set(groups))

    if force_source or not ATTACK_PATH_GROUP_MEMBERSHIP_ALLOW_FALLBACK:
        # Caller requested a specific source, or fallback is disabled for attack paths.
        return []

    try:
        marked_domain = mark_sensitive(domain_clean, "domain")
        marked_sam = mark_sensitive(sam_clean, "user")
        print_info_debug(
            f"[attack_paths] Group lookup via {primary} returned no results for "
            f"{marked_sam}@{marked_domain}; trying secondary source."
        )
    except Exception:
        pass

    groups = secondary_fn()
    return sorted(set(groups))


def _attack_path_get_recursive_groups_for_group(
    shell: object,
    *,
    domain: str,
    group_name: str,
    force_source: str | None = None,
) -> list[str]:
    """Resolve recursive parent groups for a Group (Group -> MemberOf* -> Group).

    Note: LDAP in-chain for groups would require resolving the group's DN and
    then querying groups where `member:...:=<GROUP_DN>`. For now, this helper
    uses BloodHound when available because it is fast and consistent for attack
    path UX stitching.
    """
    group_clean = (group_name or "").strip()
    domain_clean = (domain or "").strip()
    if not group_clean or not domain_clean:
        return []

    snapshot_parents = _snapshot_get_direct_group_parents(
        shell, domain_clean, group_clean
    )
    if snapshot_parents is not None:
        return snapshot_parents

    primary = (force_source or ATTACK_PATH_GROUP_MEMBERSHIP_PRIMARY).strip().lower()
    if primary not in {"ldap", "bloodhound"}:
        primary = "bloodhound"

    if primary != "bloodhound":
        # Best-effort: we currently don't implement LDAP group->group recursion here.
        if force_source:
            return []
        primary = "bloodhound"

    try:
        if not hasattr(shell, "_get_bloodhound_service"):
            return []
        service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
        client = getattr(service, "client", None)
        execute_query = getattr(client, "execute_query", None)
        if not callable(execute_query):
            return []

        if "@" in group_clean:
            canonical = group_clean
        else:
            canonical = f"{group_clean}@{domain_clean}"
        sanitized = canonical.replace("'", "\\'")
        query = f"""
        MATCH (g:Group)
        WHERE toLower(coalesce(g.name, "")) = toLower('{sanitized}')
        MATCH (g)-[:MemberOf*1..]->(p:Group)
        RETURN DISTINCT p
        ORDER BY toLower(p.name)
        """
        rows = execute_query(query)
        if not isinstance(rows, list) or not rows:
            return []

        groups: list[str] = []
        for props in rows:
            if not isinstance(props, dict):
                continue
            name = str(props.get("name") or "").strip()
            if name:
                groups.append(name)
        return sorted(set(groups), key=str.lower)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return []


def _principal_samaccountname_for_group_lookup(node: dict[str, Any]) -> str:
    """Best-effort principal identifier for group membership resolution.

    For Users/Computers we prefer `properties.samaccountname` when present,
    otherwise we fall back to the node label and normalize it.
    """
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    candidate = (
        str(props.get("samaccountname") or "").strip()
        or str(node.get("label") or "").strip()
    )
    if not candidate:
        return ""
    # Keep trailing '$' for computer accounts if present.
    if "@" in candidate:
        candidate = candidate.split("@", 1)[0]
    if "\\" in candidate:
        candidate = candidate.split("\\", 1)[1]
    return candidate.strip()


def _principal_label_for_group_lookup(node: dict[str, Any]) -> str:
    label = str(node.get("label") or "").strip()
    return label


def _canonical_group_label(*, domain: str, group_name: str) -> str:
    """Return a canonical `GROUP@DOMAIN` label for a group name/label."""
    group_clean = str(group_name or "").strip()
    domain_clean = str(domain or "").strip()
    if not group_clean or not domain_clean:
        return group_clean or ""
    if "@" in group_clean:
        left, _, right = group_clean.partition("@")
        if left and right:
            return f"{left.strip().upper()}@{right.strip().upper()}"
    return f"{group_clean.strip().upper()}@{domain_clean.strip().upper()}"


def _ensure_group_node_for_domain(
    graph: dict[str, Any], *, domain: str, group_name: str
) -> str | None:
    """Ensure a group node exists, using a canonical GROUP@DOMAIN label."""
    label = _canonical_group_label(domain=domain, group_name=group_name)
    if not label:
        return None
    node_record = {
        "name": label,
        "kind": ["Group"],
        "properties": {"name": label, "domain": str(domain or "").strip().upper()},
    }
    _mark_synthetic_node_record(
        node_record, domain=domain, source="fallback_group_entry"
    )
    upsert_nodes(graph, [node_record])
    return _node_id(node_record)


def _attack_path_get_direct_groups(
    shell: object,
    *,
    domain: str,
    samaccountname: str,
    force_source: str | None = None,
) -> list[str]:
    """Resolve *direct* group memberships for a principal (non-recursive).

    This is used for persisted membership chains. We avoid writing the full
    transitive closure (principal -> all ancestor groups) because it creates
    synthetic "shortcut" edges that inflate the number of displayed paths.
    """
    sam_clean = (samaccountname or "").strip()
    domain_clean = (domain or "").strip()
    if not sam_clean or not domain_clean:
        return []

    snapshot_groups = _snapshot_get_direct_groups(shell, domain_clean, sam_clean)
    snapshot_empty = snapshot_groups is not None and not snapshot_groups
    if snapshot_groups:
        return snapshot_groups

    primary = (force_source or ATTACK_PATH_GROUP_MEMBERSHIP_PRIMARY).strip().lower()
    if primary not in {"ldap", "bloodhound"}:
        primary = "bloodhound"

    def _from_bloodhound() -> list[str]:
        try:
            if not hasattr(shell, "_get_bloodhound_service"):
                return []
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
            getter = getattr(service, "get_user_groups", None)
            if callable(getter):
                groups = getter(domain_clean, sam_clean, False)
                if isinstance(groups, list) and groups:
                    return [
                        _extract_group_name_from_bh(str(group))
                        for group in groups
                        if str(group).strip()
                    ]
            return []
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return []

    def _from_ldap() -> list[str]:
        # NOTE: We intentionally do not use the "in-chain" recursive OID here.
        # If/when needed, implement a dedicated direct-membership LDAP helper.
        return []

    primary_fn = _from_bloodhound if primary == "bloodhound" else _from_ldap
    secondary_fn = _from_ldap if primary == "bloodhound" else _from_bloodhound

    if snapshot_empty:
        try:
            marked_domain = mark_sensitive(domain_clean, "domain")
            marked_sam = mark_sensitive(sam_clean, "user")
            print_info_debug(
                f"[attack_paths] Snapshot direct groups empty for {marked_sam}@{marked_domain}; "
                f"trying {primary} lookup."
            )
        except Exception:
            pass

    groups = primary_fn()
    if groups:
        return sorted(set(groups))

    if force_source or not ATTACK_PATH_GROUP_MEMBERSHIP_ALLOW_FALLBACK:
        return []
    groups = secondary_fn()
    return sorted(set(groups))


def _attack_path_get_direct_groups_for_group(
    shell: object,
    *,
    domain: str,
    group_name: str,
    force_source: str | None = None,
) -> list[str]:
    """Resolve *direct* parent groups for a Group (Group -> MemberOf -> Group)."""
    group_clean = (group_name or "").strip()
    domain_clean = (domain or "").strip()
    if not group_clean or not domain_clean:
        return []

    snapshot_parents = _snapshot_get_direct_group_parents(
        shell, domain_clean, group_clean
    )
    if snapshot_parents is not None:
        return snapshot_parents

    primary = (force_source or ATTACK_PATH_GROUP_MEMBERSHIP_PRIMARY).strip().lower()
    if primary not in {"ldap", "bloodhound"}:
        primary = "bloodhound"

    if primary != "bloodhound":
        if force_source:
            return []
        primary = "bloodhound"

    try:
        if not hasattr(shell, "_get_bloodhound_service"):
            return []
        service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
        client = getattr(service, "client", None)
        execute_query = getattr(client, "execute_query", None)
        if not callable(execute_query):
            return []

        canonical = (
            group_clean if "@" in group_clean else f"{group_clean}@{domain_clean}"
        )
        sanitized = canonical.replace("'", "\\'")
        query = f"""
        MATCH (g:Group)
        WHERE toLower(coalesce(g.name, "")) = toLower('{sanitized}')
        MATCH (g)-[:MemberOf]->(p:Group)
        RETURN DISTINCT p
        ORDER BY toLower(p.name)
        """
        rows = execute_query(query)
        if not isinstance(rows, list) or not rows:
            return []

        groups: list[str] = []
        for props in rows:
            if not isinstance(props, dict):
                continue
            name = str(props.get("name") or "").strip()
            if name:
                groups.append(name)
        return sorted(set(groups), key=str.lower)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return []


def persist_memberof_chain_edges(
    shell: object,
    domain: str,
    graph: dict[str, Any],
    *,
    principal_node_ids: set[str],
    skip_tier0_principals: bool = True,
) -> int:
    """Persist *direct* `MemberOf` edges (principal->group, group->group) into the graph.

    We persist membership as an explicit chain rather than writing the full
    transitive closure (principal -> all ancestor groups). This avoids creating
    synthetic shortcut edges that inflate the number of displayed paths.
    """
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return 0

    existing: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "") != "MemberOf":
            continue
        existing.add((str(edge.get("from") or ""), str(edge.get("to") or "")))

    created = 0

    cache_principal: dict[str, list[str]] = {}
    cache_group: dict[str, list[str]] = {}
    seen_groups: set[str] = set()
    pending_groups: list[str] = []

    for node_id in sorted(principal_node_ids):
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            continue
        kind = _node_kind(node)
        if kind not in {"User", "Computer"}:
            continue
        if skip_tier0_principals and _node_is_tier0(node):
            continue

        sam = _principal_samaccountname_for_group_lookup(node)
        if not sam:
            continue

        cache_key = f"{kind}:{sam.lower()}"
        groups = cache_principal.get(cache_key)
        if groups is None:
            groups = _attack_path_get_direct_groups(
                shell, domain=domain, samaccountname=sam
            )
            cache_principal[cache_key] = groups
        if not groups:
            continue

        for group in groups:
            gid = _ensure_group_node_for_domain(graph, domain=domain, group_name=group)
            if not gid:
                continue
            key = (node_id, gid)
            if key in existing:
                continue
            upsert_edge(
                graph,
                from_id=node_id,
                to_id=gid,
                relation="MemberOf",
                edge_type="membership",
                status="discovered",
                notes={"source": "derived_membership"},
            )
            existing.add(key)
            created += 1
            group_label = _canonical_group_label(domain=domain, group_name=group)
            if group_label and group_label not in seen_groups:
                seen_groups.add(group_label)
                pending_groups.append(group_label)

    # Now expand group nesting as a chain: Group -> MemberOf -> ParentGroup (direct only).
    # This is best-effort (BloodHound CE query when available).
    while pending_groups:
        group_label = pending_groups.pop()
        cache_key = group_label.lower()
        parents = cache_group.get(cache_key)
        if parents is None:
            parents = _attack_path_get_direct_groups_for_group(
                shell, domain=domain, group_name=group_label
            )
            cache_group[cache_key] = parents
        if not parents:
            continue
        from_id = _ensure_group_node_for_domain(
            graph, domain=domain, group_name=group_label
        )
        if not from_id:
            continue
        for parent in parents:
            to_id = _ensure_group_node_for_domain(
                graph, domain=domain, group_name=parent
            )
            if not to_id:
                continue
            key = (from_id, to_id)
            if key in existing:
                continue
            upsert_edge(
                graph,
                from_id=from_id,
                to_id=to_id,
                relation="MemberOf",
                edge_type="membership",
                status="discovered",
                notes={"source": "derived_membership"},
            )
            existing.add(key)
            created += 1
            parent_label = _canonical_group_label(domain=domain, group_name=parent)
            if parent_label and parent_label not in seen_groups:
                seen_groups.add(parent_label)
                pending_groups.append(parent_label)

    return created


def _inject_runtime_recursive_memberof_edges(
    shell: object,
    *,
    domain: str,
    runtime_graph: dict[str, Any],
    principal_node_ids: set[str],
    skip_tier0_principals: bool = True,
) -> int:
    """Inject ephemeral `MemberOf` edges for principals into `runtime_graph`.

    This is used to "stitch" graph paths that transition from a User/Computer
    into a Group-originating path without persisting memberships into the
    attack graph on disk.
    """
    nodes_map = (
        runtime_graph.get("nodes")
        if isinstance(runtime_graph.get("nodes"), dict)
        else {}
    )
    edges = (
        runtime_graph.get("edges")
        if isinstance(runtime_graph.get("edges"), list)
        else []
    )
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return 0

    existing: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "") != "MemberOf":
            continue
        existing.add((str(edge.get("from") or ""), str(edge.get("to") or "")))

    injected = 0
    cache: dict[str, list[str]] = {}

    def _ensure_group_node_id(group: str) -> str | None:
        """Ensure a group node exists in the runtime graph and return its node id.

        This is best-effort and prefers:
        1) An existing node in the attack graph matching the group label.
        2) A BloodHound-backed group node (objectid present) when available.
        3) A synthetic `GROUP@DOMAIN` node as a last resort.
        """
        group_clean = str(group or "").strip()
        if not group_clean:
            return None

        existing_id = _find_node_id_by_label(runtime_graph, group_clean)
        if existing_id:
            return existing_id

        try:
            if hasattr(shell, "_get_bloodhound_service"):
                service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
                resolver = getattr(service, "get_group_node_by_samaccountname", None)
                if callable(resolver):
                    sam = _extract_group_name_from_bh(group_clean)
                    props = resolver(domain, sam)
                    if isinstance(props, dict) and (
                        props.get("samaccountname")
                        or props.get("name")
                        or props.get("objectid")
                    ):
                        node_record = {
                            "name": str(
                                props.get("name")
                                or props.get("samaccountname")
                                or group_clean
                            ),
                            "kind": ["Group"],
                            "objectId": props.get("objectid") or props.get("objectId"),
                            "properties": props,
                        }
                        upsert_nodes(runtime_graph, [node_record])
                        return _node_id(node_record)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

        # Last resort: create a synthetic group node so at least the stitching works.
        return _ensure_group_node_for_domain(
            runtime_graph, domain=domain, group_name=group_clean
        )

    for node_id in sorted(principal_node_ids):
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            continue
        kind = _node_kind(node)
        if kind not in {"User", "Computer", "Group"}:
            continue
        if skip_tier0_principals and _node_is_tier0(node):
            continue

        cache_key = ""
        groups: list[str] | None = None
        if kind in {"User", "Computer"}:
            sam = _principal_samaccountname_for_group_lookup(node)
            if not sam:
                continue
            cache_key = f"{kind}:{sam.lower()}"
            groups = cache.get(cache_key)
            if groups is None:
                groups = _attack_path_get_recursive_groups(
                    shell, domain=domain, samaccountname=sam
                )
                cache[cache_key] = groups
        else:
            group_label = _principal_label_for_group_lookup(node)
            if not group_label:
                continue
            cache_key = f"{kind}:{group_label.lower()}"
            groups = cache.get(cache_key)
            if groups is None:
                groups = _attack_path_get_recursive_groups_for_group(
                    shell, domain=domain, group_name=group_label
                )
                cache[cache_key] = groups

        if not groups:
            continue

        for group in groups:
            gid = _ensure_group_node_id(group)
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
                    "first_seen": _utc_now_iso(),
                    "last_seen": _utc_now_iso(),
                }
            )
            existing.add(key)
            injected += 1

    return injected


def _status_rank(status: str) -> int:
    value = (status or "discovered").strip().lower()
    if value == "blocked":
        return 1
    if value == "unsupported":
        return 1
    if value == "unavailable":
        return 1
    if value in {"attempted", "failed", "error"}:
        return 2
    if value == "success":
        return 3
    return 0


def _graph_path(shell: object, domain: str) -> str:
    workspace_cwd = (
        shell._get_workspace_cwd()  # type: ignore[attr-defined]
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", os.getcwd())
    )
    domains_dir = getattr(shell, "domains_dir", "domains")
    return domain_subpath(workspace_cwd, domains_dir, domain, "attack_graph.json")


def load_attack_graph(shell: object, domain: str) -> dict[str, Any]:
    """Load or initialize the attack graph for a domain."""
    path = _graph_path(shell, domain)
    if os.path.exists(path):
        data = read_json_file(path)
        schema_version = str(data.get("schema_version") or "")
        if schema_version == ATTACK_GRAPH_SCHEMA_VERSION:
            maintenance = _get_attack_graph_maintenance_state(data)
            maintenance_target = _maintenance_key(_ATTACK_GRAPH_MAINTENANCE_VERSION)
            maintenance_version = str(maintenance.get("normalization") or "").strip()

            repaired = False
            normalized = False
            kind_normalized = False
            metadata_updated = 0
            reuse_notes_compacted = 0

            # These maintenance passes are expensive on large graphs and should
            # run only once per maintenance version.
            if maintenance_version != maintenance_target:
                # Historical graphs may contain duplicate nodes (same label, different IDs).
                # Repair them early so path computations stay consistent and self-loop
                # avoidance works as intended.
                repaired = _repair_duplicate_nodes_by_label(data)
                normalized = _normalize_user_computer_labels(data)
                snapshot = _load_membership_snapshot(shell, domain)
                kind_normalized = _normalize_principal_kinds_from_snapshot(
                    data, snapshot
                )
                metadata_updated = _refresh_attack_graph_edge_metadata(data)
                reuse_notes_compacted = _compact_local_reuse_edge_notes(data)
                maintenance["normalization"] = maintenance_target

            if (
                maintenance_version != maintenance_target
                or repaired
                or normalized
                or kind_normalized
                or metadata_updated
                or reuse_notes_compacted
            ):
                try:
                    marked_domain = mark_sensitive(domain, "domain")
                    parts: list[str] = []
                    if maintenance_version != maintenance_target:
                        parts.append("applied graph maintenance")
                    if repaired:
                        parts.append("repaired duplicate nodes")
                    if normalized:
                        parts.append("normalized principal labels")
                    if kind_normalized:
                        parts.append("normalized principal kinds")
                    if metadata_updated:
                        parts.append("classified edge metadata")
                    if reuse_notes_compacted:
                        parts.append("compacted local reuse notes")
                    action = ", ".join(parts) if parts else "updated"
                    print_info_debug(
                        f"[attack_graph] {action} in {marked_domain} attack graph."
                    )
                except Exception:
                    pass
                save_attack_graph(shell, domain, data)
            return data
        if schema_version in {"1.0"}:
            migrated = _migrate_attack_graph(data)
            if migrated:
                _repair_duplicate_nodes_by_label(migrated)
                _normalize_user_computer_labels(migrated)
                snapshot = _load_membership_snapshot(shell, domain)
                _normalize_principal_kinds_from_snapshot(migrated, snapshot)
                _refresh_attack_graph_edge_metadata(migrated)
                _compact_local_reuse_edge_notes(migrated)
                maintenance = _get_attack_graph_maintenance_state(migrated)
                maintenance["normalization"] = _maintenance_key(
                    _ATTACK_GRAPH_MAINTENANCE_VERSION
                )
                save_attack_graph(shell, domain, migrated)
                return migrated
    return {
        "schema_version": ATTACK_GRAPH_SCHEMA_VERSION,
        "domain": domain,
        "generated_at": _utc_now_iso(),
        "maintenance": {
            "normalization": _maintenance_key(_ATTACK_GRAPH_MAINTENANCE_VERSION),
        },
        "nodes": {},
        "edges": [],
    }


def _migrate_attack_graph(graph: dict[str, Any]) -> dict[str, Any] | None:
    """Migrate older attack graph schema versions to the current version."""
    nodes_map = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return None

    id_map: dict[str, str] = {}
    new_nodes: dict[str, Any] = {}

    for old_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        # Ensure the record contains expected keys for our canonicalisers.
        node_record: dict[str, Any] = dict(node)
        node_record.setdefault(
            "label", node.get("label") or node.get("name") or str(old_id)
        )
        node_record.setdefault(
            "kind", node.get("kind") or node.get("type") or "Unknown"
        )
        node_record.setdefault(
            "properties",
            node.get("properties") if isinstance(node.get("properties"), dict) else {},
        )

        new_id = _node_id(node_record)
        id_map[str(old_id)] = new_id

        existing = new_nodes.get(new_id)
        merged = existing if isinstance(existing, dict) else {}
        merged.update(node_record)
        merged["id"] = new_id
        merged["label"] = _canonical_node_label(node_record)
        merged["kind"] = _node_kind(node_record)
        merged["is_high_value"] = bool(
            merged.get("is_high_value")
        ) or _node_is_effectively_high_value(node_record)

        new_nodes[new_id] = merged

    new_edges: list[dict[str, Any]] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_old = str(edge.get("from") or "")
        to_old = str(edge.get("to") or "")
        relation = str(edge.get("relation") or "")
        if not from_old or not to_old or not relation:
            continue
        from_new = id_map.get(from_old, from_old)
        to_new = id_map.get(to_old, to_old)
        edge_type = str(edge.get("edge_type") or "runtime")
        status = str(edge.get("status") or "discovered")
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}

        migrated_entry = upsert_edge(
            {"nodes": new_nodes, "edges": new_edges},
            from_id=from_new,
            to_id=to_new,
            relation=relation,
            edge_type=edge_type,
            status=status,
            notes=notes,
        )
        if migrated_entry:
            # Preserve timestamps when present
            for key in ("first_seen", "last_seen"):
                if key in edge and key not in migrated_entry:
                    migrated_entry[key] = edge[key]

    migrated: dict[str, Any] = {
        "schema_version": ATTACK_GRAPH_SCHEMA_VERSION,
        "domain": graph.get("domain") or "",
        "generated_at": _utc_now_iso(),
        "nodes": new_nodes,
        "edges": new_edges,
    }
    return migrated


def _refresh_attack_graph_edge_metadata(graph: dict[str, Any]) -> int:
    """Ensure category/vuln_key metadata is present for every edge."""
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return 0
    changed = 0
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or "").strip()
        if not relation:
            continue
        category, vuln_key = _classify_edge_relation(relation)
        if "discovered_at" not in edge:
            first_seen = edge.get("first_seen")
            edge["discovered_at"] = first_seen or _utc_now_iso()
            changed += 1
        if edge.get("category") != category or edge.get("vuln_key") != vuln_key:
            edge["category"] = category
            edge["vuln_key"] = vuln_key
            changed += 1
    return changed


def _compact_local_reuse_edge_notes(graph: dict[str, Any]) -> int:
    """Drop bulky duplicated LocalAdminPassReuse note payloads.

    Legacy runs may store full host/node arrays in every edge note. This
    dramatically increases attack_graph.json size in large environments.
    """
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return 0
    changed = 0
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "").strip().lower() != "localadminpassreuse":
            continue
        notes = edge.get("notes")
        if not isinstance(notes, dict):
            continue
        removed = False
        for key in ("confirmed_hosts", "confirmed_node_ids"):
            if key in notes:
                notes.pop(key, None)
                removed = True
        if removed:
            edge["notes"] = notes
            changed += 1
    return changed


def save_attack_graph(shell: object, domain: str, graph: dict[str, Any]) -> None:
    """Persist the attack graph to disk with stable formatting."""
    graph["schema_version"] = ATTACK_GRAPH_SCHEMA_VERSION
    graph["domain"] = domain
    graph["generated_at"] = _utc_now_iso()
    path = _graph_path(shell, domain)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    edges = graph.get("edges")
    if isinstance(edges, list):
        graph["edges"] = sorted(
            edges,
            key=lambda e: (
                str(e.get("from", "")),
                str(e.get("relation", "")),
                str(e.get("to", "")),
            )
            if isinstance(e, dict)
            else ("", "", ""),
        )

    write_json_file(path, graph)
    _invalidate_attack_paths_cache(domain, reason="graph_saved")
    try:
        domains_data = getattr(shell, "domains_data", None)
        if isinstance(domains_data, dict):
            domains_data.setdefault(domain, {})["attack_graph_file"] = path
    except Exception:
        pass
    _sync_attack_graph_findings_best_effort(shell, domain, graph)


def _sync_attack_graph_findings_best_effort(
    shell: object, domain: str, graph: dict[str, Any]
) -> None:
    """Sync findings when report service is available.

    Lite/private runtime images may omit report_service. Cache that availability
    so we avoid repeated import failures on every graph save.
    """
    global _REPORT_SYNC_FN  # noqa: PLW0603

    if _REPORT_SYNC_FN is False:
        return

    if _REPORT_SYNC_FN is None:
        try:
            from adscan_internal.services.report_service import (
                sync_attack_graph_findings,
            )

            _REPORT_SYNC_FN = sync_attack_graph_findings
        except Exception as exc:  # pragma: no cover - best effort
            _REPORT_SYNC_FN = False
            print_info_debug(
                "[attack_graph] Technical findings sync unavailable "
                f"(report_service missing): {type(exc).__name__}: {exc}"
            )
            return

    try:
        assert callable(_REPORT_SYNC_FN)
        _REPORT_SYNC_FN(shell, domain, graph)
    except Exception as exc:  # pragma: no cover - best effort
        print_info_debug(
            f"[attack_graph] Failed to sync technical findings: {type(exc).__name__}: {exc}"
        )


def refresh_attack_graph_execution_support(
    shell: object, domain: str
) -> dict[str, int]:
    """Refresh execution support classification for edges in an existing graph.

    This is used when loading a workspace to keep older `attack_graph.json` files
    aligned with the current ADscan version's supported/policy-blocked relations.

    Returns:
        Counts of changes performed.
    """
    graph = load_attack_graph(shell, domain)
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    if not edges:
        return {"changed": 0}

    changed = 0
    to_blocked = 0
    to_unsupported = 0
    to_discovered = 0
    metadata_updated = 0
    version = getattr(telemetry, "VERSION", "unknown")

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or "").strip()
        if not relation:
            continue
        category, vuln_key = _classify_edge_relation(relation)
        if "discovered_at" not in edge:
            first_seen = edge.get("first_seen")
            edge["discovered_at"] = first_seen or _utc_now_iso()
            changed += 1
            metadata_updated += 1
        if edge.get("category") != category or edge.get("vuln_key") != vuln_key:
            edge["category"] = category
            edge["vuln_key"] = vuln_key
            changed += 1
            metadata_updated += 1
        current_status = str(edge.get("status") or "discovered").strip().lower()
        if current_status in {"success", "attempted", "failed", "error", "unavailable"}:
            continue

        support = classify_relation_support(relation)
        desired_status = "discovered"
        desired_notes: dict[str, Any] = {
            "exec_support": support.kind,
            "exec_support_version": version,
        }
        if support.kind == "policy_blocked":
            desired_status = "blocked"
            desired_notes.update(
                {
                    "blocked_kind": "dangerous",
                    "reason": support.reason,
                    "exec_support": "policy_blocked",
                }
            )
        elif support.kind == "unsupported":
            desired_status = "unsupported"
            desired_notes.update(
                {
                    "blocked_kind": "unsupported",
                    "reason": support.reason,
                    "exec_support": "unsupported",
                }
            )

        if desired_status != current_status:
            edge["status"] = desired_status
            changed += 1
            if desired_status == "blocked":
                to_blocked += 1
            elif desired_status == "unsupported":
                to_unsupported += 1
            elif desired_status == "discovered":
                to_discovered += 1

        existing_notes = edge.get("notes")
        if not isinstance(existing_notes, dict):
            existing_notes = {}
        existing_notes.update(desired_notes)
        edge["notes"] = existing_notes

    if changed:
        save_attack_graph(shell, domain, graph)
    return {
        "changed": changed,
        "to_blocked": to_blocked,
        "to_unsupported": to_unsupported,
        "to_discovered": to_discovered,
        "metadata_updated": metadata_updated,
    }


def upsert_nodes(
    graph: dict[str, Any], nodes: Iterable[dict[str, Any]]
) -> dict[str, str]:
    """Upsert nodes and return a mapping of their computed ids."""
    node_map: dict[str, Any] = graph.setdefault("nodes", {})
    if not isinstance(node_map, dict):
        node_map = {}
        graph["nodes"] = node_map

    computed: dict[str, str] = {}
    graph_domain = str(graph.get("domain") or "").strip()
    domain_upper = graph_domain.upper() if graph_domain else ""
    for node in nodes:
        if not isinstance(node, dict):
            continue
        # Centralize principal normalization: when operating inside a domain-scoped
        # graph, ensure User/Computer nodes always carry `domain` and canonical
        # `NAME@DOMAIN` so the UI stays consistent and cross-module node creation
        # does not drift.
        kind = _node_kind(node)
        nid = _node_id(node)
        computed[_node_display_name(node)] = nid
        existing = node_map.get(nid)
        merged = existing if isinstance(existing, dict) else {}
        node_properties = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        if kind in {"User", "Computer"} and domain_upper:
            sam = str(
                node_properties.get("samaccountname")
                or node.get("samaccountname")
                or ""
            ).strip()
            if sam:
                node_properties.setdefault("domain", domain_upper)
                # Normalize name to NAME@DOMAIN for display.
                props_name = str(node_properties.get("name") or "").strip()
                if not props_name or "@" not in props_name:
                    node_properties["name"] = f"{sam.upper()}@{domain_upper}"
                # Keep top-level name aligned when present.
                node_name = str(node.get("name") or "").strip()
                if node_name and "@" not in node_name:
                    node["name"] = str(node_properties.get("name") or node_name)
        system_tags = (
            node.get("system_tags") or node_properties.get("system_tags") or []
        )
        if isinstance(system_tags, str):
            system_tags = [system_tags]
        merged.update(
            {
                "id": nid,
                "label": _node_display_name(node),
                "kind": _node_kind(node),
                "objectId": node.get("objectId") or node.get("objectid"),
                # Persist common BloodHound metadata at the top-level so
                # attack-path filtering and tests can rely on it without
                # requiring a full `properties` payload.
                "isTierZero": bool(
                    node.get("isTierZero") or node_properties.get("isTierZero")
                ),
                "highvalue": bool(
                    node.get("highvalue") or node_properties.get("highvalue")
                ),
                "system_tags": list(system_tags)
                if isinstance(system_tags, list)
                else [],
                "is_high_value": _node_is_effectively_high_value(node),
                "properties": node_properties,
            }
        )
        # If we merged with an existing node, the best label/kind can depend on
        # the combined properties (e.g. one insert had `samaccountname`, another
        # had canonical `name@domain`). Recompute from merged state.
        merged["kind"] = _node_kind(merged)
        merged["label"] = _canonical_node_label(merged)
        node_map[nid] = merged

    return computed


def upsert_edge(
    graph: dict[str, Any],
    *,
    from_id: str,
    to_id: str,
    relation: str,
    edge_type: str,
    status: str = "discovered",
    notes: dict[str, Any] | None = None,
    log_creation: bool = True,
) -> dict[str, Any]:
    """Upsert an edge by (from, relation, to)."""
    relation_norm = _normalize_relation(relation)
    if not from_id or not to_id or not relation_norm:
        return {}

    # Classify execution support for this relation (version-sensitive).
    edge_category, edge_vuln_key = _classify_edge_relation(relation_norm)
    support = classify_relation_support(relation_norm)
    desired_status = (status or "discovered").strip().lower()
    desired_notes: dict[str, Any] = {}
    # Avoid filesystem I/O during graph creation/migration: telemetry.VERSION is in-memory.
    version = getattr(telemetry, "VERSION", "unknown")
    if desired_status in {"", "discovered"}:
        if support.kind == "policy_blocked":
            desired_status = "blocked"
            desired_notes = {
                "blocked_kind": "dangerous",
                "reason": support.reason,
                "exec_support": "policy_blocked",
                "exec_support_version": version,
            }
        elif support.kind == "unsupported":
            desired_status = "unsupported"
            desired_notes = {
                "blocked_kind": "unsupported",
                "reason": support.reason,
                "exec_support": "unsupported",
                "exec_support_version": version,
            }
        else:
            desired_notes = {
                "exec_support": support.kind,
                "exec_support_version": version,
            }

    edges: list[dict[str, Any]] = graph.setdefault("edges", [])
    if not isinstance(edges, list):
        edges = []
        graph["edges"] = edges

    now = _utc_now_iso()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if (
            edge.get("from") == from_id
            and edge.get("to") == to_id
            and str(edge.get("relation") or "") == relation_norm
        ):
            edge["last_seen"] = now
            edge.setdefault("discovered_at", edge.get("first_seen") or now)
            edge["category"] = edge_category
            edge["vuln_key"] = edge_vuln_key
            current = str(edge.get("status") or "discovered")
            if _status_rank(desired_status) > _status_rank(current):
                edge["status"] = desired_status
            edge.setdefault("edge_type", edge_type)
            merged_notes: dict[str, Any] = {}
            if notes:
                existing_notes = edge.get("notes")
                if not isinstance(existing_notes, dict):
                    existing_notes = {}
                merged_notes.update(existing_notes)
                merged_notes.update(notes)
            if desired_notes:
                existing_notes = edge.get("notes")
                if not isinstance(existing_notes, dict):
                    existing_notes = {}
                merged_notes.update(existing_notes)
                merged_notes.update(desired_notes)
            if merged_notes:
                edge["notes"] = merged_notes
            return edge

    edge_id_input = f"{from_id}|{relation_norm}|{to_id}|{edge_type}"
    edge_id = hashlib.md5(edge_id_input.encode("utf-8")).hexdigest()
    entry: dict[str, Any] = {
        "id": edge_id,
        "from": from_id,
        "to": to_id,
        "relation": relation_norm,
        "edge_type": edge_type,
        "category": edge_category,
        "vuln_key": edge_vuln_key,
        "status": desired_status,
        "notes": {**(notes or {}), **desired_notes},
        "discovered_at": now,
        "first_seen": now,
        "last_seen": now,
    }
    edges.append(entry)
    if log_creation:
        try:

            def _sanitize_value_for_log(value: Any) -> Any:
                """Return a display-safe value for attack-step debug logs."""
                if value is None or isinstance(value, (bool, int, float)):
                    return value
                if isinstance(value, str):
                    return mark_sensitive(value, "user")
                if isinstance(value, list):
                    return [_sanitize_value_for_log(item) for item in value]
                if isinstance(value, dict):
                    return {
                        str(key): _sanitize_value_for_log(val)
                        for key, val in value.items()
                    }
                return mark_sensitive(str(value), "user")

            nodes_map = graph.get("nodes")
            from_label = from_id
            to_label = to_id
            if isinstance(nodes_map, dict):
                from_node = nodes_map.get(from_id)
                to_node = nodes_map.get(to_id)
                if isinstance(from_node, dict):
                    from_label = str(
                        from_node.get("label")
                        or from_node.get("name")
                        or from_node.get("id")
                        or from_id
                    )
                if isinstance(to_node, dict):
                    to_label = str(
                        to_node.get("label")
                        or to_node.get("name")
                        or to_node.get("id")
                        or to_id
                    )
            marked_from = mark_sensitive(from_label, "user")
            marked_to = mark_sensitive(to_label, "user")
            print_info_debug(
                f"[attack_step] recorded: {marked_from} -> {relation_norm} -> {marked_to}"
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
    return entry


def add_bloodhound_path_edges(
    graph: dict[str, Any],
    *,
    nodes: list[dict[str, Any]],
    relations: list[str],
    status: str = "discovered",
    edge_type: str = "bloodhound_ce",
    notes_by_relation_index: dict[int, dict[str, Any]] | None = None,
    log_creation: bool = True,
    shell: object | None = None,
) -> int:
    """Add edges for a BloodHound-derived path (nodes + relations).

    Args:
        graph: Domain attack graph dict.
        nodes: Ordered node dicts.
        relations: Ordered relationship names connecting consecutive nodes.
        status: Initial edge status.
        edge_type: Edge category stored in the graph (defaults to `bloodhound_ce`).
            This is used for both provenance and UI rendering (e.g. `entry_vector`).
    """
    if not nodes or not relations:
        return 0
    enriched_nodes = [
        _enrich_node_enabled_metadata(shell, graph, node) for node in nodes
    ]
    upsert_nodes(graph, enriched_nodes)

    created = 0
    for idx, rel in enumerate(relations):
        if idx + 1 >= len(enriched_nodes):
            break
        from_id = _node_id(enriched_nodes[idx])
        to_id = _node_id(enriched_nodes[idx + 1])
        edge = upsert_edge(
            graph,
            from_id=from_id,
            to_id=to_id,
            relation=rel,
            edge_type=edge_type,
            status=status,
            notes=notes_by_relation_index.get(idx) if notes_by_relation_index else None,
            log_creation=log_creation,
        )
        if edge:
            created += 1
    return created


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


@dataclass(frozen=True)
class CredentialSourceStep:
    """Describe how a domain credential was obtained (provenance).

    This is used by credential verification flows to record a corresponding
    edge in `attack_graph.json` when a credential is confirmed as valid.
    """

    relation: str
    edge_type: str
    entry_label: str = "Domain Users"
    notes: dict[str, Any] = field(default_factory=dict)
    record_on_failure: bool = False


def record_credential_source_steps(
    shell: object,
    domain: str,
    *,
    username: str,
    steps: list[CredentialSourceStep],
    status: str,
) -> bool:
    """Record provenance edges for a verified credential.

    Args:
        shell: Shell instance providing workspace path context.
        domain: Domain name for the per-domain attack graph.
        username: Target username (credential owner).
        steps: Provenance descriptors to materialize as edges.
        status: Edge status to apply (e.g., success, attempted).

    Returns:
        True if at least one edge was recorded, False otherwise.
    """
    if not steps:
        return False

    graph = load_attack_graph(shell, domain)
    user_id = ensure_user_node_for_domain(shell, domain, graph, username=username)

    recorded = False
    for step in steps:
        if not isinstance(step, CredentialSourceStep):
            continue
        entry_label = str(step.entry_label or "").strip()
        notes = step.notes if isinstance(step.notes, dict) else {}
        entry_kind = str(notes.get("entry_kind") or "").strip().lower()

        use_computer_entry = False
        if entry_kind == "computer":
            use_computer_entry = True
        elif entry_label:
            from adscan_internal.principal_utils import is_machine_account

            label_for_check = entry_label.split("@", 1)[0].strip()
            use_computer_entry = is_machine_account(label_for_check)

        if use_computer_entry:
            entry_id = ensure_computer_node_for_domain(
                shell, domain, graph, principal=entry_label
            )
        else:
            entry_id = ensure_entry_node_for_domain(
                shell, domain, graph, label=entry_label
            )
        edge = upsert_edge(
            graph,
            from_id=entry_id,
            to_id=user_id,
            relation=step.relation,
            edge_type=step.edge_type,
            status=status,
            notes=step.notes,
        )
        recorded = recorded or bool(edge)

    if recorded:
        save_attack_graph(shell, domain, graph)
    return recorded


def compute_maximal_attack_paths(
    graph: dict[str, Any],
    *,
    max_depth: int,
    require_high_value_target: bool = True,
    terminal_mode: str = "tier0",
) -> list[AttackPath]:
    """Compute maximal paths up to depth.

    By default we only return paths whose terminal node is marked high value.
    High-value detection relies on node metadata persisted in `attack_graph.json`
    (Tier Zero, highvalue, admin_tier_0 tag).

    Important:
        This is a core graph primitive. Do not use it directly for user-facing
        CLI/web attack-path summaries. UX callers must go through
        `get_attack_path_summaries()` so shell-aware post-processing is applied
        consistently (Affected counts, zero-length filtering, cache/logging, and
        future UX enrichments).
    """
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
        # Runtime MemberOf edges are contextual and should not change which nodes
        # are considered "sources" in domain-wide path listing.
        edge_type = str(edge.get("edge_type") or "")
        if not (rel == "MemberOf" and edge_type == "runtime"):
            incoming[to_id] = incoming.get(to_id, 0) + 1
        incoming.setdefault(from_id, incoming.get(from_id, 0))
        outgoing.setdefault(to_id, outgoing.get(to_id, 0))

    def is_terminal(node_id: str) -> bool:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            return False
        mode = (terminal_mode or "tier0").strip().lower()
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

    def dfs(
        current: str,
        visited: set[str],
        acc_steps: list[AttackPathStep],
    ) -> None:
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

        if not extended and acc_steps:
            emit(acc_steps)

    for source in sources:
        dfs(source, visited={source}, acc_steps=[])

    return paths


def _normalize_account(value: str) -> str:
    name = (value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def paths_involving_user(
    graph: dict[str, Any],
    *,
    username: str,
    max_depth: int,
) -> list[dict[str, Any]]:
    """Return UI-ready maximal attack paths that involve a given user.

    The returned list contains dicts in the same shape used by the CLI tables,
    with an additional `role` field: source/target/intermediate.
    """
    normalized = _normalize_account(username)
    if not normalized:
        return []

    computed = compute_maximal_attack_paths(graph, max_depth=max_depth)
    results: list[dict[str, Any]] = []
    for path in computed:
        record = path_to_display_record(graph, path)
        nodes = record.get("nodes") if isinstance(record.get("nodes"), list) else []
        role: str | None = None
        if nodes:
            if _normalize_account(str(nodes[0])) == normalized:
                role = "source"
            elif _normalize_account(str(nodes[-1])) == normalized:
                role = "target"
            else:
                for node in nodes[1:-1]:
                    if _normalize_account(str(node)) == normalized:
                        role = "intermediate"
                        break
        if role:
            record["role"] = role
            results.append(record)
    return results


def compute_display_steps_for_domain(
    shell: object,
    domain: str,
    *,
    username: str | None = None,
) -> list[dict[str, Any]]:
    """Return UI-ready step dicts for all edges in the domain graph.

    This is primarily a diagnostic / transparency helper for the CLI. The
    returned items follow the same shape used by `print_attack_path_detail`:

    - step: 1-based index
    - action: relation name
    - status: edge status
    - details: contains from/to labels and a condensed notes string (when any)
    """
    graph = load_attack_graph(shell, domain)
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return []

    from_id: str | None = None
    if username:
        from_id = _find_node_id_by_label(graph, username)
        if not from_id:
            return []

    def label(node_id: str) -> str:
        node = nodes_map.get(node_id)
        if isinstance(node, dict):
            return str(node.get("label") or node_id)
        return node_id

    def summarize_notes(edge: dict[str, Any]) -> str:
        notes = edge.get("notes")
        if not isinstance(notes, dict) or not notes:
            return ""

        edge_type = str(edge.get("edge_type") or "")
        if edge_type == "entry_vector":
            attempts = notes.get("attempts")
            if isinstance(attempts, list) and attempts:
                last = attempts[-1] if isinstance(attempts[-1], dict) else {}
                wordlist = last.get("wordlist")
                status = last.get("status")
                parts: list[str] = []
                if isinstance(status, str) and status:
                    parts.append(f"last={status}")
                if isinstance(wordlist, str) and wordlist:
                    parts.append(f"wordlist={wordlist}")
                if len(attempts) > 1:
                    parts.append(f"attempts={len(attempts)}")
                return " ".join(parts)
            return ""

        # Generic notes: keep only primitive key/value pairs for compact display.
        parts: list[str] = []
        for key, value in notes.items():
            if value is None:
                continue
            if isinstance(value, (str, int, float, bool)) and str(value).strip():
                parts.append(f"{key}={value}")
        return " ".join(parts[:4])

    display: list[dict[str, Any]] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if from_id and str(edge.get("from") or "") != from_id:
            continue

        from_node_id = str(edge.get("from") or "")
        to_node_id = str(edge.get("to") or "")
        relation = str(edge.get("relation") or "")
        if not from_node_id or not to_node_id or not relation:
            continue

        notes_summary = summarize_notes(edge)
        details: dict[str, Any] = {
            "from": label(from_node_id),
            "to": label(to_node_id),
        }
        edge_type = str(edge.get("edge_type") or "")
        if edge_type:
            details["edge_type"] = edge_type
        if notes_summary:
            details["notes"] = notes_summary

        display.append(
            {
                "step": len(display) + 1,
                "action": relation,
                "status": str(edge.get("status") or "discovered"),
                "details": details,
            }
        )

    return display


def update_edge_status_by_labels(
    shell: object,
    domain: str,
    *,
    from_label: str,
    relation: str,
    to_label: str,
    status: str,
    notes: dict[str, Any] | None = None,
) -> bool:
    """Update an edge status by matching node labels (best-effort).

    This is used by interactive CLI flows where we only have display labels.
    Note: Attack path metrics are computed from the persisted graph at scan completion
    using compute_attack_path_metrics() rather than tracked at runtime.
    """
    graph = load_attack_graph(shell, domain)
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return False

    from_norm = _normalize_account(from_label)
    to_norm = _normalize_account(to_label)
    if not from_norm or not to_norm:
        return False

    def match(label: str, node_id: str) -> bool:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            return False
        node_label = str(node.get("label") or "")
        return _normalize_account(node_label) == _normalize_account(label)

    from_id = next((nid for nid in nodes_map.keys() if match(from_label, nid)), "")
    to_id = next((nid for nid in nodes_map.keys() if match(to_label, nid)), "")
    if not from_id or not to_id:
        return False

    upsert_edge(
        graph,
        from_id=from_id,
        to_id=to_id,
        relation=relation,
        edge_type="runtime",
        status=status,
        notes=notes,
    )
    save_attack_graph(shell, domain, graph)
    return True


def get_node_by_label(
    shell: object, domain: str, *, label: str
) -> dict[str, Any] | None:
    """Return a persisted attack-graph node by display label.

    This is a convenience helper for runtime executors (attack path execution,
    privilege confirmation, etc.) that only have the UI label available.

    Args:
        shell: Shell instance used to load the attack graph.
        domain: Domain for which the graph is loaded.
        label: UI label of the node (e.g. ``WINTERFELL$``).

    Returns:
        Node dict when found, otherwise None.
    """
    label_clean = str(label or "").strip()
    if not label_clean:
        return None
    graph = load_attack_graph(shell, domain)
    node_id = _find_node_id_by_label(graph, label_clean)
    if not node_id:
        return None
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    node = nodes_map.get(node_id) if isinstance(nodes_map, dict) else None
    return node if isinstance(node, dict) else None


def path_to_display_record(graph: dict[str, Any], path: AttackPath) -> dict[str, Any]:
    """Convert an AttackPath to the low-level display-record shape.

    Important:
        This helper intentionally performs only graph-local shaping. It does not
        apply shell-aware UX enrichment such as affected-user fallbacks. Use
        `get_attack_path_summaries()` for any user-facing CLI/web flow.
    """
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    context_relations = _CONTEXT_RELATIONS_LOWER

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
        step_status = step.status
        relation_key = str(step.relation or "").strip().lower()
        steps_for_ui.append(
            {
                "step": idx,
                "action": step.relation,
                "status": step_status,
                "details": {
                    "from": label(step.from_id),
                    "to": label(step.to_id),
                    **(step.notes or {}),
                    **(
                        {
                            "blocked_kind": "dangerous",
                            "reason": "High-risk / potentially disruptive (disabled by design)",
                        }
                        if classify_relation_support(relation_key).kind
                        == "policy_blocked"
                        and str(step_status or "").strip().lower() == "blocked"
                        else {}
                    ),
                },
            }
        )

    return {
        "nodes": nodes,
        "relations": relations,
        # Some relations are context-only (e.g. runtime `MemberOf` expansion) and should
        # not affect the perceived "effort" or exploitation status of a path.
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


def ensure_entry_node(graph: dict[str, Any], *, label: str) -> str:
    """Ensure the shared entry node exists (e.g. 'Domain Users')."""
    node = {
        "name": label,
        "kind": ["Group"],
        "properties": {"name": label},
    }
    upsert_nodes(graph, [node])
    return _node_id(node)


def _mark_synthetic_node_record(
    node_record: dict[str, Any],
    *,
    domain: str,
    source: str,
) -> dict[str, Any]:
    """Attach synthetic metadata to a node record (in-place)."""
    props = node_record.get("properties")
    if not isinstance(props, dict):
        props = {}
        node_record["properties"] = props
    props.setdefault("synthetic", True)
    props.setdefault("synthetic_source", source)
    props.setdefault("synthetic_domain", str(domain or "").strip().upper())
    return node_record


def ensure_entry_node_for_domain(
    shell: object,
    domain: str,
    graph: dict[str, Any],
    *,
    label: str,
) -> str:
    """Ensure an entry node exists, preferring BloodHound-backed nodes when possible.

    For some entry vectors (e.g. "Domain Users") we prefer persisting the real
    BloodHound node (RID 513) to avoid language-dependent naming. When the
    BloodHound service is unavailable or the lookup fails, we fall back to a
    synthetic node label.
    """
    label_clean = (label or "").strip()
    label_lower = label_clean.lower()
    if label_lower == "domain users":
        try:
            if hasattr(shell, "_get_bloodhound_service"):
                service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
                if service and hasattr(service, "get_domain_users_group"):
                    node_props = service.get_domain_users_group(domain)  # type: ignore[attr-defined]
                    if isinstance(node_props, dict) and (
                        node_props.get("name") or node_props.get("objectid")
                    ):
                        # Normalize into our node record shape.
                        node_record = {
                            "name": str(node_props.get("name") or label_clean),
                            "kind": ["Group"],
                            "objectId": node_props.get("objectid")
                            or node_props.get("objectId"),
                            "properties": node_props,
                        }
                        upsert_nodes(graph, [node_record])
                        marked_domain = mark_sensitive(domain, "domain")
                        marked_label = mark_sensitive(
                            str(node_record.get("name") or ""), "user"
                        )
                        marked_object_id = mark_sensitive(
                            str(node_record.get("objectId") or ""), "user"
                        )
                        print_info_debug(
                            f"[domain_users] resolved from BloodHound for {marked_domain}: "
                            f"label={marked_label} objectid={marked_object_id}"
                        )
                        return _node_id(node_record)
                    marked_domain = mark_sensitive(domain, "domain")
                    print_info_debug(
                        f"[domain_users] BloodHound returned no RID 513 group for {marked_domain}; "
                        "falling back to synthetic"
                    )
                else:
                    marked_domain = mark_sensitive(domain, "domain")
                    print_info_debug(
                        f"[domain_users] BloodHound service missing resolver for {marked_domain}; "
                        "falling back to synthetic"
                    )
            else:
                marked_domain = mark_sensitive(domain, "domain")
                print_info_debug(
                    f"[domain_users] shell has no BloodHound service accessor for {marked_domain}; "
                    "falling back to synthetic"
                )
        except Exception as exc:  # noqa: BLE001
            # Best-effort; fall back to synthetic node.
            telemetry.capture_exception(exc)
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                f"[domain_users] resolver failed for {marked_domain}; falling back to synthetic: {exc}"
            )
            logger.exception(
                "Failed to resolve Domain Users group from BloodHound; falling back to synthetic",
                extra={"domain": domain},
            )

    special_entry = _resolve_special_principal_entry(shell, domain, graph, label_clean)
    if special_entry:
        return special_entry

    if label_lower == "domain users":
        scoped_label = attack_paths_core._canonical_membership_label(  # noqa: SLF001
            domain, label_clean
        )
        node_record = {
            "name": scoped_label,
            "kind": ["Group"],
            "properties": {
                "name": scoped_label,
                "domain": str(domain or "").strip().upper(),
            },
        }
        _mark_synthetic_node_record(
            node_record, domain=domain, source="fallback_domain_users"
        )
        upsert_nodes(graph, [node_record])
        return _node_id(node_record)

    return ensure_entry_node(graph, label=label_clean)


def resolve_entry_label_for_auth(auth_username: str | None) -> str:
    """Resolve the entry label based on authentication context.

    Returns a stable label for non-authenticated sessions, otherwise the
    provided username (lowercased at call sites when needed).
    """
    if not auth_username:
        return "Domain Users"
    normalized = str(auth_username).strip()
    if not normalized:
        return "Domain Users"
    lowered = normalized.lower()
    if lowered in {"null", "anonymous"}:
        return "ANONYMOUS LOGON"
    if lowered == "guest":
        return "GUESTS"
    return normalized


def _resolve_special_principal_entry(
    shell: object,
    domain: str,
    graph: dict[str, Any],
    label: str,
) -> str | None:
    """Resolve well-known non-auth principals (anonymous/guest) via BH SIDs."""
    label_lower = str(label or "").strip().lower()
    sid_suffix_map = {
        "anonymous logon": "S-1-5-7",
        "guests": "S-1-5-32-546",
    }
    sid_suffix = sid_suffix_map.get(label_lower)
    if not sid_suffix:
        return None
    try:
        if hasattr(shell, "_get_bloodhound_service"):
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
            if service and hasattr(service, "client"):
                domain_clean = str(domain or "").strip()
                query = f"""
                MATCH (g:Group)
                WHERE toLower(coalesce(g.objectid, g.objectId, "")) ENDS WITH toLower("{sid_suffix}")
                  AND (
                    toLower(coalesce(g.domain, "")) = toLower("{domain_clean}")
                    OR toLower(coalesce(g.name, "")) ENDS WITH toLower("@{domain_clean}")
                  )
                RETURN g
                LIMIT 1
                """
                rows = service.client.execute_query(query)
                marked_domain = mark_sensitive(domain, "domain")
                print_info_debug(
                    f"[{label_lower}] lookup completed for {marked_domain}: "
                    f"rows={len(rows) if isinstance(rows, list) else 'N/A'}"
                )
                if isinstance(rows, list) and rows:
                    node = rows[0]
                    if isinstance(node, dict):
                        name = str(node.get("name") or label)
                        object_id = str(
                            node.get("objectid") or node.get("objectId") or ""
                        )
                        node_record = {
                            "name": name,
                            "kind": ["Group"],
                            "objectId": object_id or None,
                            "properties": node,
                        }
                        upsert_nodes(graph, [node_record])
                        print_info_debug(
                            f"[{label_lower}] node found for {marked_domain}: "
                            f"name={mark_sensitive(name, 'user')}, "
                            f"objectid={mark_sensitive(object_id, 'user')}"
                        )
                        return _node_id(node_record)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(f"[{label_lower}] lookup failed for {marked_domain}: {exc}")

    # BloodHound is missing or returned nothing: fall back to a synthetic node
    # scoped to the current domain so attack-path logic still works.
    scoped_label = attack_paths_core._canonical_membership_label(  # noqa: SLF001
        domain, label
    )
    object_id = f"{str(domain or '').strip().upper()}-{sid_suffix}"
    node_record = {
        "name": scoped_label,
        "kind": ["Group"],
        "objectId": object_id,
        "properties": {
            "name": scoped_label,
            "objectid": object_id,
            "domain": str(domain or "").strip().upper(),
        },
    }
    _mark_synthetic_node_record(
        node_record, domain=domain, source="fallback_special_principal"
    )
    upsert_nodes(graph, [node_record])
    return _node_id(node_record)


def ensure_domain_node_for_domain(
    shell: object,
    domain: str,
    graph: dict[str, Any],
) -> str:
    """Ensure a domain node exists, preferring BloodHound-backed nodes when possible.

    We use a dedicated Domain node so takeover steps can end at a canonical
    destination (the domain object) rather than an arbitrary Tier0 host.
    """
    domain_clean = (domain or "").strip()
    if not domain_clean:
        # Fall back to a stable placeholder.
        return ensure_entry_node(graph, label="Domain")

    try:
        if hasattr(shell, "_get_bloodhound_service"):
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
            if service and hasattr(service, "get_domain_node"):
                node_props = service.get_domain_node(domain_clean)  # type: ignore[attr-defined]
                if isinstance(node_props, dict) and (
                    node_props.get("name") or node_props.get("objectid")
                ):
                    # Mark as high value to ensure default path filtering includes it.
                    node_record = {
                        "name": str(node_props.get("name") or domain_clean),
                        "kind": ["Domain"],
                        "objectId": node_props.get("objectid")
                        or node_props.get("objectId"),
                        "properties": node_props,
                        "isTierZero": True,
                    }
                    upsert_nodes(graph, [node_record])
                    marked_domain = mark_sensitive(domain_clean, "domain")
                    marked_label = mark_sensitive(
                        str(node_record.get("name") or ""), "domain"
                    )
                    print_info_debug(
                        f"[domain_node] resolved from BloodHound for {marked_domain}: label={marked_label}"
                    )
                    return _node_id(node_record)
            marked_domain = mark_sensitive(domain_clean, "domain")
            print_info_debug(
                f"[domain_node] BloodHound service missing resolver for {marked_domain}; "
                "falling back to synthetic"
            )
        else:
            marked_domain = mark_sensitive(domain_clean, "domain")
            print_info_debug(
                f"[domain_node] shell has no BloodHound service accessor for {marked_domain}; "
                "falling back to synthetic"
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain_clean, "domain")
        print_info_debug(
            f"[domain_node] resolver failed for {marked_domain}; falling back to synthetic: {exc}"
        )
        logger.exception(
            "Failed to resolve domain node from BloodHound; falling back to synthetic",
            extra={"domain": domain_clean},
        )

    # Fallback: create a synthetic Domain node (still marked high value).
    node_record = {
        "name": domain_clean,
        "kind": ["Domain"],
        "properties": {"name": domain_clean, "domain": domain_clean},
        "isTierZero": True,
    }
    _mark_synthetic_node_record(
        node_record, domain=domain_clean, source="fallback_domain_node"
    )
    upsert_nodes(graph, [node_record])
    return _node_id(node_record)


def resolve_netexec_target_for_node_label(
    shell: object,
    domain: str,
    *,
    node_label: str,
) -> str | None:
    """Resolve an attack-graph node label into a NetExec target string.

    BloodHound computer nodes are often referenced by ``samAccountName`` (e.g.
    ``CASTELBLACK$``) in attack path relationships, but NetExec expects a host
    target such as an IP, hostname, or FQDN. Our attack graph stores the
    BloodHound node properties, so we can usually resolve a usable target via:

    - ``properties.name`` (BloodHound's canonical "name", usually FQDN)
    - fallback to ``properties.samaccountname`` without the trailing ``$`` and
      appending the current domain (best-effort).

    Args:
        shell: Shell instance used to load the attack graph.
        domain: Domain for which the graph is loaded.
        node_label: Label of the node to resolve (e.g. ``WINTERFELL$``).

    Returns:
        NetExec-compatible target string, or None if it can't be resolved.
    """
    label_clean = str(node_label or "").strip()
    if not label_clean:
        return None
    domain_clean = str(domain or "").strip().lower()

    graph = load_attack_graph(shell, domain)
    node_id = _find_node_id_by_label(graph, label_clean)
    if not node_id:
        return _normalize_netexec_target_candidate(
            label_clean, fallback_domain=domain_clean
        )

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    node = nodes_map.get(node_id) if isinstance(nodes_map, dict) else None
    if not isinstance(node, dict):
        return _normalize_netexec_target_candidate(
            label_clean, fallback_domain=domain_clean
        )

    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    for property_key in (
        "dNSHostName",
        "dnshostname",
        "dnsHostName",
        "hostname",
        "name",
        "samaccountname",
    ):
        value = props.get(property_key)
        if not isinstance(value, str):
            continue
        resolved = _normalize_netexec_target_candidate(
            value, fallback_domain=domain_clean
        )
        if resolved:
            return resolved

    for node_key in ("label", "name", "samaccountname"):
        value = node.get(node_key)
        if not isinstance(value, str):
            continue
        resolved = _normalize_netexec_target_candidate(
            value, fallback_domain=domain_clean
        )
        if resolved:
            return resolved

    host = _normalize_netexec_target_candidate(
        str(node.get("label") or label_clean).strip(),
        fallback_domain=domain_clean,
    )
    if not host:
        return None
    marked_node = mark_sensitive(label_clean, "hostname")
    marked_host = mark_sensitive(host, "hostname")
    print_info_verbose(
        f"Resolved target for {marked_node} using fallback (samAccountName -> FQDN): {marked_host}"
    )
    return host


def _normalize_netexec_target_candidate(
    candidate: str,
    *,
    fallback_domain: str,
) -> str | None:
    """Normalize node labels/properties into NetExec host targets.

    Handles common BloodHound representations such as:
    - ``CASTELBLACK$@NORTH.SEVENKINGDOMS.LOCAL``
    - ``NORTH\\CASTELBLACK$``
    - ``CASTELBLACK$``
    """
    raw = str(candidate or "").strip().strip(".")
    if not raw:
        return None

    if "\\" in raw:
        raw = raw.split("\\", 1)[1]

    lower = raw.lower()
    if "@" in lower:
        left, right = lower.split("@", 1)
        left = left.strip().rstrip("$")
        right = right.strip().strip(".")
        if left and right:
            return f"{left}.{right}"

    lower = lower.rstrip("$")
    if not lower:
        return None

    # Keep IPv4 targets as-is.
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", lower):
        return lower

    if "." in lower:
        return lower

    if fallback_domain:
        return f"{lower}.{fallback_domain}"
    return lower


def _resolve_netexec_target_fqdn(
    shell: object,
    *,
    domain: str,
    target_ip: str,
    target_hostname: str | None = None,
) -> str | None:
    """Resolve NetExec target IP/hostname into an FQDN suitable for BloodHound lookup."""
    domain_clean = str(domain or "").strip()
    ip_clean = str(target_ip or "").strip()
    if not domain_clean or not ip_clean:
        return None

    fqdn: str | None = None
    try:
        if hasattr(shell, "_get_dns_discovery_service"):
            dns_service = shell._get_dns_discovery_service()  # type: ignore[attr-defined]
            if dns_service and hasattr(dns_service, "reverse_resolve_fqdn_robust"):
                fqdn = dns_service.reverse_resolve_fqdn_robust(  # type: ignore[attr-defined]
                    ip_clean
                )
            elif dns_service and hasattr(dns_service, "reverse_resolve_fqdn"):
                fqdn = dns_service.reverse_resolve_fqdn(ip_clean)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        fqdn = None

    if not fqdn and target_hostname:
        candidate = f"{str(target_hostname).strip().rstrip('.')}.{domain_clean}".lower()
        fqdn = candidate
        marked_ip = mark_sensitive(ip_clean, "ip")
        marked_fqdn = mark_sensitive(candidate, "host")
        print_info_verbose(
            f"[netexec_edge] Using FQDN fallback from hostname for {marked_ip}: {marked_fqdn}"
        )

    if not fqdn:
        marked_ip = mark_sensitive(ip_clean, "ip")
        print_info_verbose(
            f"[netexec_edge] Could not resolve hostname for target {marked_ip}; skipping step creation."
        )
        return None

    return fqdn


def _resolve_netexec_target_computer_node(
    shell: object,
    *,
    service: object,
    domain: str,
    target_ip: str,
    target_hostname: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Resolve a NetExec target into a BloodHound computer node and canonical FQDN.

    Resolution strategy:
    1. Prefer hostname from NetExec output (`target_hostname`) as ``hostname.domain``.
    2. If no node matches that candidate, fallback to DNS reverse resolution by IP.
    """
    domain_clean = str(domain or "").strip()
    ip_clean = str(target_ip or "").strip()
    if not domain_clean or not ip_clean:
        return None, None

    candidate_fqdn: str | None = None
    if target_hostname:
        candidate_fqdn = (
            f"{str(target_hostname).strip().rstrip('.')}.{domain_clean}".lower()
        )
        node_props = service.get_computer_node_by_name(domain_clean, candidate_fqdn)  # type: ignore[attr-defined]
        if isinstance(node_props, dict):
            marked_ip = mark_sensitive(ip_clean, "ip")
            marked_fqdn = mark_sensitive(candidate_fqdn, "host")
            print_info_debug(
                f"[netexec_edge] Resolved node from hostname-first for {marked_ip}: {marked_fqdn}"
            )
            return node_props, candidate_fqdn

        marked_fqdn = mark_sensitive(candidate_fqdn, "host")
        print_info_verbose(
            f"[netexec_edge] Hostname-derived FQDN {marked_fqdn} not found in BloodHound; trying DNS reverse."
        )

    fqdn = _resolve_netexec_target_fqdn(
        shell,
        domain=domain_clean,
        target_ip=ip_clean,
        target_hostname=None,
    )
    if not fqdn:
        return None, None

    node_props = service.get_computer_node_by_name(domain_clean, fqdn)  # type: ignore[attr-defined]
    if not isinstance(node_props, dict):
        marked_fqdn = mark_sensitive(fqdn, "host")
        print_info_verbose(
            f"[netexec_edge] No BloodHound Computer node found for {marked_fqdn}; skipping step creation."
        )
        return None, None

    return node_props, fqdn


def upsert_netexec_privilege_edge(
    shell: object,
    domain: str,
    *,
    username: str,
    relation: str,
    target_ip: str,
    target_hostname: str | None = None,
) -> bool:
    """Upsert a privilege edge discovered via NetExec into the attack graph.

    This normalizes NetExec host identifiers (often IPs and NetBIOS hostnames)
    into BloodHound Computer nodes (e.g. ``CASTELBLACK$``) when possible.

    The edge is only recorded when we can resolve the IP to a hostname/FQDN and
    find the corresponding BloodHound Computer node. If resolution fails, we do
    not create an IP-based node to avoid contaminating the BloodHound-aligned
    graph.

    Args:
        shell: Shell instance used to access DNS and BloodHound services.
        domain: Target domain.
        username: Source user for the edge.
        relation: Relationship to upsert (e.g. ``AdminTo``).
        target_ip: IP address of the target host (from NetExec output).
        target_hostname: Optional hostname captured from NetExec output (often NetBIOS).

    Returns:
        True when the edge was recorded, False otherwise.
    """
    domain_clean = str(domain or "").strip()
    username_clean = str(username or "").strip()
    relation_clean = str(relation or "").strip()
    ip_clean = str(target_ip or "").strip()
    if not domain_clean or not username_clean or not relation_clean or not ip_clean:
        return False

    try:
        service = None
        if hasattr(shell, "_get_bloodhound_service"):
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
        if not service or not hasattr(service, "get_computer_node_by_name"):
            marked_domain = mark_sensitive(domain_clean, "domain")
            print_info_verbose(
                f"[netexec_edge] BloodHound service unavailable for {marked_domain}; skipping step creation."
            )
            return False

        node_props, fqdn = _resolve_netexec_target_computer_node(
            shell,
            service=service,
            domain=domain_clean,
            target_ip=ip_clean,
            target_hostname=target_hostname,
        )
        if not isinstance(node_props, dict) or not fqdn:
            return False

        graph = load_attack_graph(shell, domain_clean)

        user_record = {
            "name": username_clean,
            "kind": ["User"],
            "properties": {
                "samaccountname": username_clean,
                "name": username_clean,
                "domain": domain_clean,
            },
        }
        comp_record = {
            "name": str(node_props.get("name") or fqdn),
            "kind": ["Computer"],
            "objectId": node_props.get("objectid") or node_props.get("objectId"),
            "properties": node_props,
        }
        upsert_nodes(graph, [user_record, comp_record])

        from_id = _node_id(user_record)
        to_id = _node_id(comp_record)
        notes: dict[str, Any] = {"source": "netexec", "ip": ip_clean}
        if fqdn:
            notes["fqdn"] = fqdn
        if target_hostname:
            notes["hostname"] = str(target_hostname).strip()

        upsert_edge(
            graph,
            from_id=from_id,
            to_id=to_id,
            relation=relation_clean,
            edge_type="netexec",
            status="success",
            notes=notes,
        )
        save_attack_graph(shell, domain_clean, graph)

        marked_user = mark_sensitive(username_clean, "user")
        marked_rel = mark_sensitive(relation_clean, "service")
        host_label = str(
            node_props.get("samaccountname") or node_props.get("name") or fqdn or ""
        )
        marked_host = mark_sensitive(host_label, "hostname")
        print_info_debug(
            f"[netexec_edge] Recorded {marked_rel} step for {marked_user} -> {marked_host}"
        )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain_clean, "domain")
        print_info_verbose(
            f"[netexec_edge] Failed to record NetExec-discovered step for {marked_domain}."
        )
        return False


def upsert_local_admin_password_reuse_edges(
    shell: object,
    domain: str,
    *,
    local_admin_username: str,
    credential: str | None = None,
    targets: list[dict[str, str]],
    status: str = "discovered",
) -> int:
    """Upsert host-to-host reuse edges with topology compression for scale.

    For small host sets, ADscan keeps a full directed mesh. For larger sets it
    switches to a compressed bidirectional star topology to avoid edge
    explosion and attack-path combinatorial blow-ups.
    """
    domain_clean = str(domain or "").strip()
    user_clean = str(local_admin_username or "").strip()
    credential_clean = str(credential or "").strip()
    if not domain_clean or not user_clean or not isinstance(targets, list):
        return 0

    try:
        service = None
        if hasattr(shell, "_get_bloodhound_service"):
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
        if not service or not hasattr(service, "get_computer_node_by_name"):
            marked_domain = mark_sensitive(domain_clean, "domain")
            print_info_verbose(
                f"[local_reuse] BloodHound service unavailable for {marked_domain}; skipping attack-step creation."
            )
            return 0

        graph = load_attack_graph(shell, domain_clean)
        resolved: dict[str, dict[str, str]] = {}

        for target in targets:
            if not isinstance(target, dict):
                continue
            ip_clean = str(target.get("ip") or "").strip()
            host_hint = str(
                target.get("hostname") or target.get("target") or ""
            ).strip()
            node_props: dict[str, Any] | None = None
            fqdn: str | None = None

            if ip_clean:
                node_props, fqdn = _resolve_netexec_target_computer_node(
                    shell,
                    service=service,
                    domain=domain_clean,
                    target_ip=ip_clean,
                    target_hostname=host_hint or None,
                )

            if not node_props and host_hint:
                candidate_fqdn = (
                    host_hint.strip().rstrip(".").lower()
                    if "." in host_hint
                    else f"{host_hint.strip().rstrip('.')}.{domain_clean}".lower()
                )
                resolver = getattr(service, "get_computer_node_by_name", None)
                if callable(resolver):
                    resolved_fn = cast(Callable[[str, str], Any], resolver)
                    props = resolved_fn(  # pylint: disable=not-callable
                        domain_clean, candidate_fqdn
                    )
                    if isinstance(props, dict):
                        node_props = props
                        fqdn = candidate_fqdn

            if not isinstance(node_props, dict):
                continue

            comp_record = {
                "name": str(node_props.get("name") or fqdn or host_hint or ip_clean),
                "kind": ["Computer"],
                "objectId": node_props.get("objectid") or node_props.get("objectId"),
                "properties": node_props,
            }
            upsert_nodes(graph, [comp_record])
            node_id = _node_id(comp_record)
            if not node_id:
                continue
            resolved[node_id] = {
                "label": str(comp_record.get("name") or node_id),
                "ip": ip_clean,
                "hostname": host_hint,
            }

        if len(resolved) < 2:
            return 0

        node_ids = sorted(resolved.keys())
        total_hosts = len(node_ids)
        reuse_cluster_seed = f"{user_clean.lower()}|" + "|".join(
            sorted(node_ids, key=str.lower)
        )
        reuse_cluster_id = hashlib.md5(reuse_cluster_seed.encode("utf-8")).hexdigest()

        topology = _resolve_local_reuse_topology(total_hosts)
        anchor_id: str | None = None
        if topology == "star":
            anchor_id = min(
                node_ids,
                key=lambda node_id: (
                    str(resolved.get(node_id, {}).get("label") or "").lower(),
                    node_id,
                ),
            )

        edge_pairs: set[tuple[str, str]] = set()
        if topology == "star" and anchor_id:
            for node_id in node_ids:
                if node_id == anchor_id:
                    continue
                edge_pairs.add((anchor_id, node_id))
                edge_pairs.add((node_id, anchor_id))
        else:
            for src_id in node_ids:
                for dst_id in node_ids:
                    if src_id == dst_id:
                        continue
                    edge_pairs.add((src_id, dst_id))

        # Compact stale LocalAdminPassReuse edges for the same reuse cluster:
        # when topology choice changes (mesh -> star), prune obsolete edges.
        desired_pairs = set(edge_pairs)
        edges_list = graph.get("edges")
        if isinstance(edges_list, list):
            compacted_edges: list[dict[str, Any]] = []
            for edge in edges_list:
                if not isinstance(edge, dict):
                    compacted_edges.append(edge)
                    continue
                if (
                    str(edge.get("relation") or "").strip().lower()
                    != "localadminpassreuse"
                ):
                    compacted_edges.append(edge)
                    continue
                notes = edge.get("notes")
                if not isinstance(notes, dict):
                    compacted_edges.append(edge)
                    continue
                note_user = str(notes.get("local_admin_username") or "").strip()
                if note_user.lower() != user_clean.lower():
                    compacted_edges.append(edge)
                    continue
                note_cluster_id = str(notes.get("reuse_cluster_id") or "").strip()
                if note_cluster_id != reuse_cluster_id:
                    compacted_edges.append(edge)
                    continue
                from_key = str(edge.get("from") or "").strip()
                to_key = str(edge.get("to") or "").strip()
                if not from_key or not to_key:
                    compacted_edges.append(edge)
                    continue
                if (from_key, to_key) in desired_pairs:
                    compacted_edges.append(edge)
            graph["edges"] = compacted_edges

        # Count only newly-created edges (not updates) for UX summaries.
        existing_keys: set[tuple[str, str, str]] = set()
        for edge in graph.get("edges", []):
            if not isinstance(edge, dict):
                continue
            if str(edge.get("relation") or "").strip().lower() != "localadminpassreuse":
                continue
            from_key = str(edge.get("from") or "").strip()
            to_key = str(edge.get("to") or "").strip()
            if from_key and to_key:
                existing_keys.add((from_key, "localadminpassreuse", to_key))

        created = 0
        upserted = 0
        credential_type = (
            "hash"
            if credential_clean
            and bool(re.fullmatch(r"[0-9a-fA-F]{32}", credential_clean))
            else "password"
            if credential_clean
            else ""
        )
        for src_id, dst_id in sorted(edge_pairs):
            key = (src_id, "localadminpassreuse", dst_id)
            edge = upsert_edge(
                graph,
                from_id=src_id,
                to_id=dst_id,
                relation="LocalAdminPassReuse",
                edge_type="local_cred_reuse",
                status=status,
                notes={
                    "source": "netexec_local_cred_reuse",
                    "local_admin_username": user_clean,
                    "reuse_cluster_id": reuse_cluster_id,
                    "reuse_group_size": total_hosts,
                    "bidirectional": True,
                    "topology": topology,
                    "anchor_host": resolved.get(anchor_id, {}).get("label")
                    if anchor_id
                    else None,
                    **(
                        {"credential": credential_clean, "credential_type": credential_type}
                        if credential_clean
                        else {}
                    ),
                },
            )
            if edge:
                upserted += 1
                if key not in existing_keys:
                    created += 1

        if upserted:
            save_attack_graph(shell, domain_clean, graph)
            marked_domain = mark_sensitive(domain_clean, "domain")
            marked_user = mark_sensitive(user_clean, "user")
            print_info_debug(
                f"[local_reuse] Upserted {upserted} LocalAdminPassReuse edge(s) "
                f"(new={created}, topology={topology}, hosts={total_hosts}) "
                f"for {marked_user} in {marked_domain}."
            )
        return created
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain_clean, "domain")
        print_info_verbose(
            f"[local_reuse] Failed to persist local admin reuse edges for {marked_domain}."
        )
        return 0


def upsert_local_cred_to_domain_reuse_edges(
    shell: object,
    domain: str,
    *,
    source_hosts: list[str],
    domain_usernames: list[str],
    credential: str,
    status: str = "discovered",
) -> int:
    """Upsert compressed SAM local-credential -> domain-account reuse edges.

    The graph is materialized with one synthetic cluster node per credential
    variant fingerprint:

      Computer -> LocalCredReuseSource -> LocalCredCluster -> LocalCredToDomainReuse -> User

    This preserves path coverage while avoiding an O(N_hosts * M_users) mesh.
    """
    domain_clean = str(domain or "").strip()
    credential_clean = str(credential or "").strip()
    if (
        not domain_clean
        or not credential_clean
        or not isinstance(source_hosts, list)
        or not isinstance(domain_usernames, list)
    ):
        return 0

    normalized_hosts = sorted(
        {
            str(host).strip()
            for host in source_hosts
            if isinstance(host, str) and str(host).strip()
        },
        key=str.lower,
    )
    normalized_users = sorted(
        {
            str(user).strip()
            for user in domain_usernames
            if isinstance(user, str) and str(user).strip()
        },
        key=str.lower,
    )
    if not normalized_hosts or not normalized_users:
        return 0

    try:
        graph = load_attack_graph(shell, domain_clean)
        source_node_ids: set[str] = set()
        for host in normalized_hosts:
            node_id = ensure_computer_node_for_domain(
                shell,
                domain_clean,
                graph,
                principal=host,
            )
            if node_id:
                source_node_ids.add(node_id)
        domain_user_ids: set[str] = set()
        for username in normalized_users:
            user_id = ensure_user_node_for_domain(
                shell,
                domain_clean,
                graph,
                username=username,
            )
            if user_id:
                domain_user_ids.add(user_id)

        if not source_node_ids or not domain_user_ids:
            return 0

        credential_type = (
            "hash"
            if bool(re.fullmatch(r"[0-9a-fA-F]{32}", credential_clean))
            else "password"
        )
        cluster_fingerprint = hashlib.sha256(
            f"{credential_type}:{credential_clean}".encode("utf-8")
        ).hexdigest()[:16]
        cluster_label = f"Local Credential Reuse [{cluster_fingerprint}]"
        cluster_node = {
            "name": cluster_label,
            "kind": ["Group"],
            "properties": {
                "name": cluster_label,
                "domain": domain_clean.upper(),
                "synthetic": True,
                "synthetic_source": "sam_domain_reuse",
                "cluster_type": "local_credential_reuse",
                "credential_fingerprint": cluster_fingerprint,
                "credential_type": credential_type,
            },
        }
        upsert_nodes(graph, [cluster_node])
        cluster_node_id = _node_id(cluster_node)
        if not cluster_node_id:
            return 0

        existing_keys: set[tuple[str, str, str]] = set()
        for edge in graph.get("edges", []):
            if not isinstance(edge, dict):
                continue
            relation_key = str(edge.get("relation") or "").strip().lower()
            if relation_key not in {"localcredreusesource", "localcredtodomainreuse"}:
                continue
            from_key = str(edge.get("from") or "").strip()
            to_key = str(edge.get("to") or "").strip()
            if from_key and to_key:
                existing_keys.add((from_key, relation_key, to_key))

        created = 0
        upserted = 0
        common_notes: dict[str, Any] = {
            "source": "sam_domain_reuse_validation",
            "credential_fingerprint": cluster_fingerprint,
            "credential_type": credential_type,
            "credential": credential_clean,
            "source_hosts": len(source_node_ids),
            "domain_users": len(domain_user_ids),
        }
        for source_id in sorted(source_node_ids):
            key = (source_id, "localcredreusesource", cluster_node_id)
            edge = upsert_edge(
                graph,
                from_id=source_id,
                to_id=cluster_node_id,
                relation="LocalCredReuseSource",
                edge_type="sam_domain_reuse",
                status=status,
                notes=common_notes,
            )
            if edge:
                upserted += 1
                if key not in existing_keys:
                    created += 1

        for user_id in sorted(domain_user_ids):
            key = (cluster_node_id, "localcredtodomainreuse", user_id)
            edge = upsert_edge(
                graph,
                from_id=cluster_node_id,
                to_id=user_id,
                relation="LocalCredToDomainReuse",
                edge_type="sam_domain_reuse",
                status=status,
                notes=common_notes,
            )
            if edge:
                upserted += 1
                if key not in existing_keys:
                    created += 1

        if upserted:
            save_attack_graph(shell, domain_clean, graph)
            marked_domain = mark_sensitive(domain_clean, "domain")
            print_info_debug(
                "[sam_domain_reuse] Upserted "
                f"{upserted} edge(s) (new={created}, hosts={len(source_node_ids)}, "
                f"users={len(domain_user_ids)}) in {marked_domain}."
            )
        return created
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain_clean, "domain")
        print_info_verbose(
            f"[sam_domain_reuse] Failed to persist SAM->domain reuse edges for {marked_domain}."
        )
        return 0


def upsert_domain_password_reuse_edges(
    shell: object,
    domain: str,
    *,
    source_usernames: list[str],
    target_usernames: list[str],
    credential: str,
    status: str = "discovered",
    evidence_source: str = "unknown",
) -> int:
    """Upsert compressed domain password/hash reuse edges.

    Materialized topology:
      User -> DomainPassReuseSource -> [Domain Password Reuse Cluster]
      Cluster -> DomainPassReuse -> User

    The cluster node keeps edge count linear and avoids O(N*M) pairwise meshes.
    """
    from adscan_internal.principal_utils import is_machine_account

    domain_clean = str(domain or "").strip()
    credential_clean = str(credential or "").strip()
    if (
        not domain_clean
        or not credential_clean
        or not isinstance(source_usernames, list)
        or not isinstance(target_usernames, list)
    ):
        return 0

    normalized_sources = sorted(
        {
            str(username).strip()
            for username in source_usernames
            if isinstance(username, str)
            and str(username).strip()
            and not is_machine_account(str(username).strip())
        },
        key=lambda item: _normalize_account(item),
    )
    normalized_targets = sorted(
        {
            str(username).strip()
            for username in target_usernames
            if isinstance(username, str)
            and str(username).strip()
            and not is_machine_account(str(username).strip())
        },
        key=lambda item: _normalize_account(item),
    )
    if not normalized_sources or not normalized_targets:
        return 0

    participant_seed = {_normalize_account(user) for user in normalized_sources}
    participant_seed.update(_normalize_account(user) for user in normalized_targets)
    participant_seed.discard("")
    if len(participant_seed) < 2:
        return 0

    try:
        enabled_users = get_enabled_users_for_domain(shell, domain_clean)
        enabled_filter_applied = bool(enabled_users)
        if enabled_users:
            filtered_sources = [
                username
                for username in normalized_sources
                if _normalize_account(username) in enabled_users
            ]
            filtered_targets = [
                username
                for username in normalized_targets
                if _normalize_account(username) in enabled_users
            ]
        else:
            filtered_sources = list(normalized_sources)
            filtered_targets = list(normalized_targets)
        if not filtered_sources or not filtered_targets:
            return 0
        filtered_participants = {
            _normalize_account(user) for user in filtered_sources + filtered_targets
        }
        filtered_participants.discard("")
        if len(filtered_participants) < 2:
            return 0

        graph = load_attack_graph(shell, domain_clean)
        source_ids: set[str] = set()
        target_ids: set[str] = set()
        for username in filtered_sources:
            node_id = ensure_user_node_for_domain(
                shell,
                domain_clean,
                graph,
                username=username,
            )
            if node_id:
                source_ids.add(node_id)
        for username in filtered_targets:
            node_id = ensure_user_node_for_domain(
                shell,
                domain_clean,
                graph,
                username=username,
            )
            if node_id:
                target_ids.add(node_id)
        if not source_ids or not target_ids:
            return 0

        credential_type = (
            "hash"
            if bool(re.fullmatch(r"[0-9a-fA-F]{32}", credential_clean))
            else "password"
        )
        fingerprint = hashlib.sha256(
            f"{credential_type}:{credential_clean}".encode("utf-8")
        ).hexdigest()[:16]
        cluster_label = f"Domain Password Reuse [{fingerprint}]"
        cluster_node = {
            "name": cluster_label,
            "kind": ["Group"],
            "properties": {
                "name": cluster_label,
                "domain": domain_clean.upper(),
                "synthetic": True,
                "synthetic_source": "domain_password_reuse",
                "cluster_type": "domain_password_reuse",
                "credential_fingerprint": fingerprint,
                "credential_type": credential_type,
            },
        }
        upsert_nodes(graph, [cluster_node])
        cluster_node_id = _node_id(cluster_node)
        if not cluster_node_id:
            return 0

        existing_keys: set[tuple[str, str, str]] = set()
        for edge in graph.get("edges", []):
            if not isinstance(edge, dict):
                continue
            relation_key = str(edge.get("relation") or "").strip().lower()
            if relation_key not in {"domainpassreusesource", "domainpassreuse"}:
                continue
            from_key = str(edge.get("from") or "").strip()
            to_key = str(edge.get("to") or "").strip()
            if from_key and to_key:
                existing_keys.add((from_key, relation_key, to_key))

        common_notes: dict[str, Any] = {
            "source": "domain_password_reuse",
            "evidence_source": str(evidence_source or "unknown").strip() or "unknown",
            "credential_fingerprint": fingerprint,
            "credential_type": credential_type,
            "credential": credential_clean,
            "source_users": len(source_ids),
            "target_users": len(target_ids),
            "enabled_filter_applied": enabled_filter_applied,
        }

        created = 0
        upserted = 0
        for src_id in sorted(source_ids):
            key = (src_id, "domainpassreusesource", cluster_node_id)
            edge = upsert_edge(
                graph,
                from_id=src_id,
                to_id=cluster_node_id,
                relation="DomainPassReuseSource",
                edge_type="domain_password_reuse",
                status=status,
                notes=common_notes,
            )
            if edge:
                upserted += 1
                if key not in existing_keys:
                    created += 1

        for dst_id in sorted(target_ids):
            key = (cluster_node_id, "domainpassreuse", dst_id)
            edge = upsert_edge(
                graph,
                from_id=cluster_node_id,
                to_id=dst_id,
                relation="DomainPassReuse",
                edge_type="domain_password_reuse",
                status=status,
                notes=common_notes,
            )
            if edge:
                upserted += 1
                if key not in existing_keys:
                    created += 1

        if upserted:
            save_attack_graph(shell, domain_clean, graph)
            marked_domain = mark_sensitive(domain_clean, "domain")
            print_info_debug(
                "[domain_pass_reuse] Upserted "
                f"{upserted} edge(s) (new={created}, sources={len(source_ids)}, "
                f"targets={len(target_ids)}) in {marked_domain}."
            )
        return created
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain_clean, "domain")
        print_info_verbose(
            f"[domain_pass_reuse] Failed to persist DomainPassReuse edges for {marked_domain}."
        )
        return 0


def upsert_cve_host_edge(
    shell: object,
    domain: str,
    *,
    relation: str,
    target_ip: str,
    target_hostname: str | None = None,
    status: str = "discovered",
    notes: dict[str, Any] | None = None,
) -> bool:
    """Upsert a CVE discovery edge for a vulnerable host.

    The edge is recorded as: Domain Users -> <relation> -> Computer
    where relation is a friendly vulnerability label (e.g. PrintNightmare).
    """
    domain_clean = str(domain or "").strip()
    relation_clean = str(relation or "").strip()
    ip_clean = str(target_ip or "").strip()
    if not domain_clean or not relation_clean or not ip_clean:
        return False

    try:
        service = None
        if hasattr(shell, "_get_bloodhound_service"):
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
        if not service or not hasattr(service, "get_computer_node_by_name"):
            marked_domain = mark_sensitive(domain_clean, "domain")
            print_info_verbose(
                f"[netexec_edge] BloodHound service unavailable for {marked_domain}; skipping CVE step creation."
            )
            return False

        node_props, fqdn = _resolve_netexec_target_computer_node(
            shell,
            service=service,
            domain=domain_clean,
            target_ip=ip_clean,
            target_hostname=target_hostname,
        )
        if not isinstance(node_props, dict) or not fqdn:
            return False

        graph = load_attack_graph(shell, domain_clean)

        entry_id = ensure_entry_node_for_domain(
            shell, domain_clean, graph, label="Domain Users"
        )
        comp_record = {
            "name": str(node_props.get("name") or fqdn),
            "kind": ["Computer"],
            "objectId": node_props.get("objectid") or node_props.get("objectId"),
            "properties": node_props,
        }
        upsert_nodes(graph, [comp_record])
        to_id = _node_id(comp_record)

        edge_notes: dict[str, Any] = {"source": "netexec", "ip": ip_clean}
        if fqdn:
            edge_notes["fqdn"] = fqdn
        if target_hostname:
            edge_notes["hostname"] = str(target_hostname).strip()
        if notes:
            edge_notes.update(notes)

        upsert_edge(
            graph,
            from_id=entry_id,
            to_id=to_id,
            relation=relation_clean,
            edge_type="cve_host",
            status=status,
            notes=edge_notes,
        )
        save_attack_graph(shell, domain_clean, graph)

        marked_rel = mark_sensitive(relation_clean, "service")
        host_label = str(
            node_props.get("samaccountname") or node_props.get("name") or fqdn or ""
        )
        marked_host = mark_sensitive(host_label, "hostname")
        print_info_debug(
            f"[netexec_edge] Recorded {marked_rel} CVE step for {marked_host}"
        )
        return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain_clean, "domain")
        print_info_verbose(
            f"[netexec_edge] Failed to record CVE step for {marked_domain}."
        )
        return False


def upsert_cve_takeover_edge(
    shell: object,
    domain: str,
    *,
    cve: str,
    status: str = "discovered",
    notes: dict[str, Any] | None = None,
) -> bool:
    """Upsert a CVE takeover edge: Domain Users -> CVE -> Domain.

    Args:
        shell: Shell instance used for workspace paths and BloodHound service access.
        domain: Target domain.
        cve: "nopac" or "zerologon" (case-insensitive).
        status: Edge status (default: discovered).
        notes: Optional notes (e.g., affected DC IPs, log path).
    """
    cve_norm = (cve or "").strip().lower()
    if cve_norm not in {"nopac", "zerologon"}:
        return False

    relation = "NoPac" if cve_norm == "nopac" else "Zerologon"
    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(shell, domain, graph, label="Domain Users")
    domain_id = ensure_domain_node_for_domain(shell, domain, graph)

    upsert_edge(
        graph,
        from_id=entry_id,
        to_id=domain_id,
        relation=relation,
        edge_type="cve_takeover",
        status=status,
        notes=notes,
    )
    save_attack_graph(shell, domain, graph)
    return True


def ensure_user_node(graph: dict[str, Any], *, username: str) -> str:
    """Ensure a minimal user node exists for a username."""
    node = {
        "name": username,
        "kind": ["User"],
        "properties": {"samaccountname": username, "name": username},
    }
    upsert_nodes(graph, [node])
    return _node_id(node)


def ensure_user_node_for_domain(
    shell: object,
    domain: str,
    graph: dict[str, Any],
    *,
    username: str,
) -> str:
    """Ensure a user node exists, preferring BloodHound-backed nodes when possible.

    Args:
        shell: Shell instance used to access the BloodHound service.
        domain: Target domain for the graph.
        graph: Attack graph to update.
        username: Username to resolve (prefer samAccountName).

    Returns:
        Node id for the ensured user node.
    """
    raw_username = str(username or "").strip()
    user_clean = _normalize_account(raw_username) or raw_username
    if not user_clean:
        return ensure_user_node(graph, username=user_clean)

    try:
        if hasattr(shell, "_get_bloodhound_service"):
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
            resolver = getattr(service, "get_user_node_by_samaccountname", None)
            if callable(resolver):
                node_props = resolver(domain, user_clean)
                if isinstance(node_props, dict) and (
                    node_props.get("samaccountname") or node_props.get("name")
                ):
                    canonical_domain = domain.upper()
                    canonical_name = str(node_props.get("name") or "").strip()
                    if not canonical_name:
                        canonical_name = f"{user_clean.upper()}@{canonical_domain}"
                        node_props["name"] = canonical_name
                    if "@" not in canonical_name:
                        canonical_name = f"{canonical_name.upper()}@{canonical_domain}"
                        node_props["name"] = canonical_name

                    sam = str(node_props.get("samaccountname") or "").strip()
                    if not sam and canonical_name:
                        sam = canonical_name.split("@", 1)[0]
                        node_props["samaccountname"] = sam.lower()
                    node_props.setdefault("domain", canonical_domain)

                    node_record = {
                        "name": canonical_name,
                        "kind": ["User"],
                        "objectId": node_props.get("objectid")
                        or node_props.get("objectId"),
                        "properties": node_props,
                    }
                    upsert_nodes(graph, [node_record])
                    marked_domain = mark_sensitive(domain, "domain")
                    marked_user = mark_sensitive(
                        str(node_record.get("name") or user_clean), "user"
                    )
                    marked_object_id = mark_sensitive(
                        str(node_record.get("objectId") or ""), "user"
                    )
                    print_info_debug(
                        f"[user_node] resolved from BloodHound for {marked_domain}: "
                        f"user={marked_user} objectid={marked_object_id}"
                    )
                    return _node_id(node_record)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        marked_user = mark_sensitive(user_clean, "user")
        print_info_debug(
            f"[user_node] resolver failed for {marked_domain} user={marked_user}; falling back to synthetic: {exc}"
        )

    canonical_domain = domain.upper()
    canonical_name = f"{user_clean.upper()}@{canonical_domain}"
    node_record = {
        "name": canonical_name,
        "kind": ["User"],
        "properties": {
            "samaccountname": user_clean,
            "domain": canonical_domain,
            "name": canonical_name,
        },
    }
    _mark_synthetic_node_record(node_record, domain=domain, source="fallback_user_node")
    upsert_nodes(graph, [node_record])
    return _node_id(node_record)


def _ensure_user_node_for_domain_synthetic(
    domain: str,
    graph: dict[str, Any],
    *,
    username: str,
) -> str:
    """Ensure a synthetic domain user node without querying external resolvers."""
    raw_username = str(username or "").strip()
    user_clean = _normalize_account(raw_username) or raw_username
    if not user_clean:
        return ensure_user_node(graph, username=user_clean)
    canonical_domain = str(domain or "").strip().upper()
    canonical_name = (
        f"{user_clean.upper()}@{canonical_domain}"
        if canonical_domain
        else user_clean.upper()
    )
    node_record = {
        "name": canonical_name,
        "kind": ["User"],
        "properties": {
            "samaccountname": user_clean,
            "domain": canonical_domain,
            "name": canonical_name,
        },
    }
    _mark_synthetic_node_record(
        node_record,
        domain=str(domain or "").strip(),
        source="principal_batch_synthetic_node",
    )
    upsert_nodes(graph, [node_record])
    return _node_id(node_record)


def ensure_computer_node_for_domain(
    shell: object,
    domain: str,
    graph: dict[str, Any],
    *,
    principal: str,
) -> str:
    """Ensure a computer node exists, preferring BloodHound-backed nodes.

    Args:
        shell: Shell instance used to access the BloodHound service.
        domain: Target domain for the graph.
        graph: Attack graph to update.
        principal: Computer account identifier (samAccountName or hostname).

    Returns:
        Node id for the ensured computer node.
    """
    from adscan_internal.principal_utils import normalize_machine_account

    principal_clean = str(principal or "").strip()
    if not principal_clean:
        return ensure_user_node(graph, username=principal_clean)

    domain_clean = str(domain or "").strip()
    sam = normalize_machine_account(principal_clean)
    host_base = sam.rstrip("$")
    fqdn = (
        principal_clean.strip().rstrip(".")
        if "." in principal_clean and not principal_clean.endswith("$")
        else f"{host_base}.{domain_clean}".lower()
        if domain_clean
        else host_base.lower()
    )

    try:
        if hasattr(shell, "_get_bloodhound_service"):
            service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
            resolver = getattr(service, "get_computer_node_by_name", None)
            if callable(resolver) and fqdn:
                node_props = resolver(domain_clean, fqdn)
                if isinstance(node_props, dict) and (
                    node_props.get("samaccountname")
                    or node_props.get("name")
                    or node_props.get("objectid")
                    or node_props.get("objectId")
                ):
                    canonical_domain = domain_clean.upper()
                    canonical_name = str(node_props.get("name") or fqdn).strip()
                    if not canonical_name:
                        canonical_name = fqdn
                        node_props["name"] = canonical_name

                    sam_prop = str(node_props.get("samaccountname") or "").strip()
                    if not sam_prop and sam:
                        node_props["samaccountname"] = sam
                    node_props.setdefault("domain", canonical_domain)

                    node_record = {
                        "name": canonical_name,
                        "kind": ["Computer"],
                        "objectId": node_props.get("objectid")
                        or node_props.get("objectId"),
                        "properties": node_props,
                    }
                    upsert_nodes(graph, [node_record])
                    marked_domain = mark_sensitive(domain_clean, "domain")
                    marked_comp = mark_sensitive(
                        str(node_record.get("name") or sam), "host"
                    )
                    marked_object_id = mark_sensitive(
                        str(node_record.get("objectId") or ""), "user"
                    )
                    print_info_debug(
                        f"[computer_node] resolved from BloodHound for {marked_domain}: "
                        f"computer={marked_comp} objectid={marked_object_id}"
                    )
                    return _node_id(node_record)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain_clean, "domain")
        marked_comp = mark_sensitive(principal_clean, "host")
        print_info_debug(
            f"[computer_node] resolver failed for {marked_domain} computer={marked_comp}; "
            f"falling back to synthetic: {exc}"
        )

    canonical_domain = domain_clean.upper()
    canonical_name = fqdn or sam or principal_clean
    node_record = {
        "name": canonical_name,
        "kind": ["Computer"],
        "properties": {
            "samaccountname": sam,
            "domain": canonical_domain,
            "name": canonical_name,
        },
    }
    _mark_synthetic_node_record(
        node_record, domain=domain_clean, source="fallback_computer_node"
    )
    upsert_nodes(graph, [node_record])
    return _node_id(node_record)


def ensure_principal_node_for_domain(
    shell: object,
    domain: str,
    graph: dict[str, Any],
    *,
    principal: str,
    principal_kind: str | None = None,
) -> str:
    """Ensure a node exists for a user or computer principal.

    Args:
        shell: Shell instance used to access the BloodHound service.
        domain: Target domain for the graph.
        graph: Attack graph to update.
        principal: Principal identifier (user or computer).
        principal_kind: Optional hint ("user" or "computer").

    Returns:
        Node id for the ensured principal node.
    """
    from adscan_internal.principal_utils import is_machine_account

    kind_hint = (principal_kind or "").strip().lower()
    if kind_hint not in {"user", "computer"}:
        kind_hint = ""

    if kind_hint == "computer" or is_machine_account(principal):
        return ensure_computer_node_for_domain(
            shell, domain, graph, principal=principal
        )
    return ensure_user_node_for_domain(
        shell, domain, graph, username=str(principal or "").strip()
    )


def upsert_roast_entry_edge(
    shell: object,
    domain: str,
    *,
    roast_type: str,
    username: str,
    status: str,
    notes: dict[str, Any] | None = None,
    entry_label: str = "Domain Users",
) -> bool:
    """Upsert an entry-vector edge for roasting: Entry -> roast_type -> username."""
    roast_type_norm = (roast_type or "").strip().lower()
    if roast_type_norm not in {"kerberoast", "asreproast"}:
        return False
    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(shell, domain, graph, label=entry_label)
    user_id = ensure_user_node_for_domain(shell, domain, graph, username=username)
    relation = "Kerberoasting" if roast_type_norm == "kerberoast" else "ASREPRoasting"
    upsert_edge(
        graph,
        from_id=entry_id,
        to_id=user_id,
        relation=relation,
        edge_type="entry_vector",
        status=status,
        notes=notes,
    )
    save_attack_graph(shell, domain, graph)
    return True


def upsert_ldap_anonymous_bind_entry_edge(
    shell: object,
    domain: str,
    *,
    status: str = "success",
    entry_label: str = "ANONYMOUS LOGON",
    target_label: str = "Domain Users",
    notes: dict[str, Any] | None = None,
) -> bool:
    """Upsert an LDAP anonymous-bind entry edge: Anonymous -> LDAPAnonymousBind -> Domain Users."""
    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(shell, domain, graph, label=entry_label)
    target_id = ensure_entry_node_for_domain(shell, domain, graph, label=target_label)

    upsert_edge(
        graph,
        from_id=entry_id,
        to_id=target_id,
        relation="LDAPAnonymousBind",
        edge_type="entry_vector",
        status=status,
        notes=notes or {},
    )
    save_attack_graph(shell, domain, graph)
    return True


def upsert_password_spray_entry_edge(
    shell: object,
    domain: str,
    *,
    username: str,
    password: str,
    spray_type: str | None = None,
    status: str = "success",
    entry_label: str = "Domain Users",
) -> bool:
    """Upsert a password spraying entry-vector edge: Entry -> PasswordSpray -> username.

    This records provenance in `attack_graph.json` so attack paths can be
    constructed dynamically from compromised users.

    Args:
        shell: Shell instance used to access the BloodHound service when available.
        domain: Target domain for the graph.
        username: User compromised via spraying.
        password: Password that was accepted for the user.
        spray_type: Human-friendly spray mode label (optional).
        status: Edge status (default: success).
        entry_label: Label for the entry node (default: "Domain Users").

    Returns:
        True when the edge was recorded, False otherwise.
    """
    user_clean = str(username or "").strip()
    if not user_clean:
        return False

    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(shell, domain, graph, label=entry_label)
    spray_kind_hint = None
    if str(spray_type or "").strip().lower() == "computer pre2k":
        spray_kind_hint = "computer"
    user_id = ensure_principal_node_for_domain(
        shell,
        domain,
        graph,
        principal=user_clean,
        principal_kind=spray_kind_hint,
    )

    notes: dict[str, Any] = {
        "username": user_clean,
        "password": str(password or ""),
    }
    if spray_type:
        notes["spray_type"] = str(spray_type)

    upsert_edge(
        graph,
        from_id=entry_id,
        to_id=user_id,
        relation="PasswordSpray",
        edge_type="entry_vector",
        status=status,
        notes=notes,
    )
    save_attack_graph(shell, domain, graph)
    return True


def upsert_share_password_entry_edge(
    shell: object,
    domain: str,
    *,
    username: str,
    entry_label: str,
    status: str = "success",
    notes: dict[str, object] | None = None,
) -> bool:
    """Upsert an entry-vector edge for share-discovered password verification."""
    user_clean = str(username or "").strip()
    if not user_clean:
        return False

    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(shell, domain, graph, label=entry_label)
    user_id = ensure_user_node_for_domain(shell, domain, graph, username=user_clean)

    upsert_edge(
        graph,
        from_id=entry_id,
        to_id=user_id,
        relation="PasswordInShare",
        edge_type="share_password",
        status=status,
        notes=notes or {},
    )
    save_attack_graph(shell, domain, graph)
    return True


def update_roast_entry_edge_status(
    shell: object,
    domain: str,
    *,
    roast_type: str,
    username: str,
    status: str,
    wordlist: str | None = None,
    entry_label: str = "Domain Users",
) -> bool:
    """Update the roasting entry edge status and append wordlist attempt notes.

    This is the canonical way for cracking flows to update the graph without
    relying on any cached "attack path" structures.
    """
    roast_type_norm = (roast_type or "").strip().lower()
    if roast_type_norm not in {"kerberoast", "asreproast"}:
        return False

    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(shell, domain, graph, label=entry_label)
    user_id = ensure_user_node_for_domain(shell, domain, graph, username=username)
    relation = "Kerberoasting" if roast_type_norm == "kerberoast" else "ASREPRoasting"

    now = _utc_now_iso()
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if (
            str(edge.get("from") or "") != entry_id
            or str(edge.get("to") or "") != user_id
            or str(edge.get("relation") or "") != relation
        ):
            continue

        current = str(edge.get("status") or "discovered")
        if _status_rank(status) > _status_rank(current):
            edge["status"] = status
        edge["last_seen"] = now

        notes = edge.get("notes")
        if not isinstance(notes, dict):
            notes = {}
        attempts = notes.get("attempts")
        if not isinstance(attempts, list):
            attempts = []
        if wordlist:
            attempts.append({"wordlist": wordlist, "status": status, "at": now})
        else:
            attempts.append({"status": status, "at": now})
        notes["attempts"] = attempts
        edge["notes"] = notes
        save_attack_graph(shell, domain, graph)
        return True

    notes: dict[str, Any] = {}
    if wordlist:
        notes["attempts"] = [{"wordlist": wordlist, "status": status, "at": now}]
    else:
        notes["attempts"] = [{"status": status, "at": now}]
    upsert_edge(
        graph,
        from_id=entry_id,
        to_id=user_id,
        relation=relation,
        edge_type="entry_vector",
        status=status,
        notes=notes,
    )
    save_attack_graph(shell, domain, graph)
    return True


def has_attack_paths_for_user(shell: object, domain: str, username: str) -> bool:
    """Return True when any dynamic path can be computed for a user.

    This includes group-originating paths via runtime `MemberOf` expansion, so
    it works even when the user node is not yet present in `attack_graph.json`.
    """
    return bool(
        compute_display_paths_for_user(
            shell,
            domain,
            username=username,
            max_depth=10,
            require_high_value_target=True,
        )
    )


def _find_node_id_by_label(graph: dict[str, Any], label: str) -> str | None:
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return None
    normalized = _normalize_account(label)

    def _quality_score(node: dict[str, Any]) -> int:
        """Prefer well-formed BloodHound-backed nodes over synthetic/unknown ones."""
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

    # Deterministic: highest score, then stable ID ordering.
    matches.sort(key=lambda x: (-x[0], x[1]))
    return matches[0][1]


def _repair_duplicate_nodes_by_label(graph: dict[str, Any]) -> bool:
    """Repair graphs containing duplicate nodes that represent the same principal.

    We have seen historical graphs where the same principal label (e.g.
    `SVC-ALFRESCO@HTB.LOCAL`) is persisted under multiple node IDs, typically
    because one code path created a synthetic `User` node (ID derived from
    samAccountName) while another persisted an incomplete BloodHound node as
    `Unknown` (ID derived from objectId/SID).

    This breaks self-loop avoidance and can create confusing attack paths like:
        SVC-ALFRESCO -> Domain Users -> SVC-ALFRESCO -> ...

    Strategy:
      - Group nodes by *exact* label (case-insensitive).
      - Pick the best representative node (prefer non-Unknown, with properties).
      - Remap all edges from/to duplicates onto the representative.
      - Drop duplicate nodes and deduplicate edges by (from, relation, to).
    """
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return False

    # Build groups of node IDs sharing the same label.
    label_to_ids: dict[str, list[str]] = {}
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        label = str(node.get("label") or "").strip()
        if not label:
            continue
        label_to_ids.setdefault(label.lower(), []).append(str(node_id))

    duplicate_groups = {k: v for k, v in label_to_ids.items() if len(v) > 1}
    if not duplicate_groups:
        return False

    def _quality_score(node: dict[str, Any]) -> int:
        # Mirror the resolver preference: keep the most informative node.
        score = 0
        kind = _node_kind(node)
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        if kind != "Unknown":
            score += 50
        else:
            score -= 50
        if props:
            score += 10
        if (
            kind in {"User", "Computer"}
            and str(props.get("samaccountname") or "").strip()
        ):
            score += 30
        if (
            kind == "Group"
            and str(node.get("objectId") or props.get("objectid") or "").strip()
        ):
            score += 20
        if str(node.get("objectId") or "").strip():
            score += 5
        return score

    remap: dict[str, str] = {}
    removed: set[str] = set()

    for _, ids in duplicate_groups.items():
        scored: list[tuple[int, str]] = []
        for nid in ids:
            node = nodes_map.get(nid)
            if isinstance(node, dict):
                scored.append((_quality_score(node), nid))
        if not scored:
            continue
        scored.sort(key=lambda x: (-x[0], x[1]))
        keep_id = scored[0][1]
        for _, nid in scored[1:]:
            remap[nid] = keep_id
            removed.add(nid)

    if not remap:
        return False

    # Remap edges and dedupe.
    merged_edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = remap.get(str(edge.get("from") or ""), str(edge.get("from") or ""))
        to_id = remap.get(str(edge.get("to") or ""), str(edge.get("to") or ""))
        relation = str(edge.get("relation") or "")
        if not from_id or not to_id or not relation:
            continue
        key = (from_id, relation, to_id)
        existing = merged_edges.get(key)
        if not existing:
            new_edge = dict(edge)
            new_edge["from"] = from_id
            new_edge["to"] = to_id
            merged_edges[key] = new_edge
            continue

        # Merge status/notes/timestamps best-effort.
        existing_status = str(existing.get("status") or "discovered")
        new_status = str(edge.get("status") or "discovered")
        if _status_rank(new_status) > _status_rank(existing_status):
            existing["status"] = new_status
        existing_notes = existing.get("notes")
        if not isinstance(existing_notes, dict):
            existing_notes = {}
        edge_notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        existing_notes.update(edge_notes)
        existing["notes"] = existing_notes
        for ts_key in ("first_seen", "last_seen"):
            if ts_key in edge and ts_key not in existing:
                existing[ts_key] = edge[ts_key]

    graph["edges"] = list(merged_edges.values())

    # Drop removed nodes.
    for nid in removed:
        nodes_map.pop(nid, None)
    graph["nodes"] = nodes_map
    return True


def reconcile_entry_nodes(shell: object, domain: str, graph: dict[str, Any]) -> int:
    """Reconcile synthetic nodes with BloodHound-backed nodes when available.

    This upgrades nodes created via fallback (properties.synthetic=true) once
    BloodHound has data for the domain.
    """
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict) or not nodes_map:
        return 0

    if not hasattr(shell, "_get_bloodhound_service"):
        return 0
    service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
    if not service:
        return 0

    reconciled = 0
    for node in list(nodes_map.values()):
        if not isinstance(node, dict):
            continue
        props = node.get("properties")
        if not isinstance(props, dict) or not props.get("synthetic"):
            continue

        kind = _node_kind(node)
        label = str(node.get("label") or node.get("name") or "").strip()
        if not label:
            continue

        node_props: dict[str, Any] | None = None
        if kind == "Domain" and hasattr(service, "get_domain_node"):
            node_props = service.get_domain_node(domain)  # type: ignore[attr-defined]
        elif kind == "User" and hasattr(service, "get_user_node_by_samaccountname"):
            sam = _normalize_account(label)
            node_props = service.get_user_node_by_samaccountname(domain, sam)  # type: ignore[attr-defined]
        elif kind == "Computer" and hasattr(service, "get_computer_node_by_fqdn"):
            node_props = service.get_computer_node_by_fqdn(domain, label)  # type: ignore[attr-defined]
        elif kind == "Group" and hasattr(service, "get_group_node_by_samaccountname"):
            group_name = _extract_group_name_from_bh(label)
            node_props = service.get_group_node_by_samaccountname(domain, group_name)  # type: ignore[attr-defined]

        if not isinstance(node_props, dict) or not (
            node_props.get("name")
            or node_props.get("objectid")
            or node_props.get("objectId")
        ):
            continue

        node_record = {
            "name": str(node_props.get("name") or label),
            "kind": [kind] if kind else node.get("kind") or ["Unknown"],
            "objectId": node_props.get("objectid") or node_props.get("objectId"),
            "properties": node_props,
        }
        upsert_nodes(graph, [node_record])
        reconciled += 1

    if reconciled:
        _repair_duplicate_nodes_by_label(graph)
    return reconciled


def _normalize_user_computer_labels(graph: dict[str, Any]) -> bool:
    """Ensure User/Computer nodes have domain + NAME@DOMAIN labels when possible."""
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return False

    graph_domain = str(graph.get("domain") or "").strip()
    domain_upper = graph_domain.upper() if graph_domain else ""
    if not domain_upper:
        return False

    changed = False
    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        kind = _node_kind(node)
        if kind not in {"User", "Computer"}:
            continue
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        sam = str(props.get("samaccountname") or "").strip()
        if not sam:
            continue
        if not str(props.get("domain") or "").strip():
            props["domain"] = domain_upper
            changed = True
        else:
            # Normalize domain casing.
            dom = str(props.get("domain") or "").strip()
            if dom and dom != dom.upper():
                props["domain"] = dom.upper()
                changed = True
        canonical = (
            f"{sam.upper()}@{str(props.get('domain') or domain_upper).strip().upper()}"
        )
        current_name = str(props.get("name") or "").strip()
        if not current_name or "@" not in current_name:
            props["name"] = canonical
            changed = True
        current_label = str(node.get("label") or "").strip()
        if current_label != canonical:
            node["label"] = canonical
            changed = True
        node["properties"] = props
        # Keep kind stable (it might have drifted).
        if node.get("kind") != kind:
            node["kind"] = kind
            changed = True
    return changed


def _normalize_principal_kinds_from_snapshot(
    graph: dict[str, Any], snapshot: dict[str, Any] | None
) -> bool:
    """Align User/Computer node kinds with membership snapshot data."""
    if not snapshot or not isinstance(snapshot, dict):
        return False
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return False

    domain = str(graph.get("domain") or "").strip()
    if not domain:
        return False

    user_groups = snapshot.get("user_to_groups")
    computer_groups = snapshot.get("computer_to_groups")
    if not isinstance(user_groups, dict) and not isinstance(computer_groups, dict):
        return False

    changed = False
    user_to_computer: list[str] = []
    computer_to_user: list[str] = []
    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        kind = _node_kind(node)
        if kind not in {"User", "Computer"}:
            continue
        label = _canonical_membership_label(domain, _canonical_node_label(node))
        if not label:
            continue

        in_user = isinstance(user_groups, dict) and label in user_groups
        in_computer = isinstance(computer_groups, dict) and label in computer_groups
        if in_computer and not in_user and kind != "Computer":
            node["kind"] = ["Computer"]
            changed = True
            user_to_computer.append(label)
        elif in_user and not in_computer and kind != "User":
            node["kind"] = ["User"]
            changed = True
            computer_to_user.append(label)

    if changed:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[attack_graph] normalized principal kinds using memberships.json for {marked_domain}: "
            f"user->computer={len(user_to_computer)}, computer->user={len(computer_to_user)}"
        )
        sample = user_to_computer[:3] + computer_to_user[:3]
        if sample:
            marked_sample = ", ".join(mark_sensitive(label, "user") for label in sample)
            print_info_debug(
                f"[attack_graph] kind normalization sample ({marked_domain}): {marked_sample}"
            )
    return changed


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

    def is_terminal(node_id: str) -> bool:
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            return False
        mode = (terminal_mode or "tier0").strip().lower()
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


def _sort_display_paths(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    status_order = {
        "theoretical": 0,
        "unavailable": 1,
        "unsupported": 2,
        "blocked": 3,
        "attempted": 4,
        "exploited": 5,
    }

    return sorted(
        records,
        key=lambda item: (
            status_order.get(str(item.get("status") or "").strip().lower(), 3),
            int(item.get("length", 0)) if str(item.get("length", "")).isdigit() else 0,
            str(item.get("source", "")).lower(),
            str(item.get("target", "")).lower(),
        ),
    )


def _record_has_executable_steps(record: dict[str, Any]) -> bool:
    """Return whether a display-path record includes at least one executable step."""
    raw_length = record.get("length")
    if isinstance(raw_length, int):
        return raw_length > 0
    if isinstance(raw_length, str) and raw_length.strip().isdigit():
        return int(raw_length.strip()) > 0

    relations = record.get("relations")
    if isinstance(relations, list):
        for relation in relations:
            if str(relation or "").strip().lower() not in _CONTEXT_RELATIONS_LOWER:
                return True
        return False

    steps = record.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            relation = str(step.get("action") or step.get("relation") or "").strip()
            if relation and relation.lower() not in _CONTEXT_RELATIONS_LOWER:
                return True
        return False

    return False


def _filter_zero_length_display_paths(
    records: list[dict[str, Any]],
    *,
    domain: str,
    scope: str,
) -> list[dict[str, Any]]:
    """Drop context-only display paths that have no executable attack steps."""
    filtered = [
        record
        for record in records
        if isinstance(record, dict) and _record_has_executable_steps(record)
    ]
    removed = len(records) - len(filtered)
    if removed > 0:
        print_info_debug(
            "[attack_paths] filtered non-actionable display paths: "
            f"domain={mark_sensitive(domain, 'domain')} scope={scope} removed={removed}"
        )
    return filtered


def _node_ids_without_memberof_edges(
    graph: dict[str, Any], *, node_ids: set[str]
) -> set[str]:
    """Return node IDs that do not currently have outgoing MemberOf edges."""
    pending = {str(node_id) for node_id in node_ids if str(node_id).strip()}
    if not pending:
        return set()

    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    if not isinstance(edges, list):
        return pending

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "").strip() != "MemberOf":
            continue
        from_id = str(edge.get("from") or "").strip()
        if from_id in pending:
            pending.discard(from_id)
            if not pending:
                break
    return pending


def _stitch_principal_memberships_for_runtime_paths(
    shell: object,
    *,
    domain: str,
    runtime_graph: dict[str, Any],
    principal_node_ids: set[str],
    snapshot: dict[str, Any] | None,
    scope: str,
) -> tuple[int, int]:
    """Ensure principals have outgoing membership edges in runtime graph.

    Returns:
        Tuple ``(snapshot_injected, runtime_injected)``.
    """
    missing = _node_ids_without_memberof_edges(
        runtime_graph, node_ids=principal_node_ids
    )
    if not missing:
        return 0, 0

    snapshot_injected = 0
    if snapshot:
        snapshot_injected = attack_paths_core._inject_memberof_edges_from_snapshot(  # noqa: SLF001
            runtime_graph,
            domain,
            snapshot,
            principal_node_ids=missing,
            recursive=True,
        )
        missing = _node_ids_without_memberof_edges(runtime_graph, node_ids=missing)

    runtime_injected = 0
    if missing:
        runtime_injected = _inject_runtime_recursive_memberof_edges(
            shell,
            domain=domain,
            runtime_graph=runtime_graph,
            principal_node_ids=missing,
            skip_tier0_principals=False,
        )

    if snapshot_injected or runtime_injected:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[attack_paths] membership stitch scope={scope} domain={marked_domain} "
            f"principals={len(principal_node_ids)} snapshot_injected={snapshot_injected} "
            f"runtime_injected={runtime_injected}"
        )
    return snapshot_injected, runtime_injected


def compute_display_paths_for_user(
    shell: object,
    domain: str,
    *,
    username: str,
    max_depth: int,
    max_paths: int | None = None,
    require_high_value_target: bool = True,
    target_mode: str = "tier0",
) -> list[dict[str, Any]]:
    """Compute maximal dynamic paths from a specific user node.

    This function expands the starting point beyond the user node itself by
    optionally including recursive group memberships (when a BloodHound service
    is available at runtime).

    Implementation note:
        We expand memberships *before* computing attack paths by injecting
        ephemeral `MemberOf` edges in-memory (not persisted). This has two
        important properties:
          1) It surfaces group-originating attack paths as:
                <user> -MemberOf-> <group> -> ...
          2) It avoids confusing "self-loop" paths like:
                jon.snow -> Domain Users -> jon.snow -> ...
             because our DFS only returns simple paths (no repeated nodes).
    """
    started_at = time.monotonic()
    user_norm = str(username or "").strip().lower()
    cache_key = _attack_paths_cache_base_key(
        shell,
        domain,
        scope="user",
        params=(
            user_norm,
            int(max_depth),
            max_paths,
            bool(require_high_value_target),
            str(target_mode or "tier0").strip().lower(),
            bool(ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS),
        ),
    )
    cached = _attack_paths_cache_get(cache_key, domain=domain, scope="user")
    if cached is not None:
        cached = _filter_zero_length_display_paths(
            cached, domain=domain, scope="user"
        )
        cached = _apply_affected_user_metadata(shell, domain, cached)
        _log_attack_path_compute_timing(
            domain=domain,
            scope="user",
            elapsed_seconds=max(0.0, time.monotonic() - started_at),
            path_count=len(cached),
            max_depth=max_depth,
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
        )
        return cached

    base_graph = load_attack_graph(shell, domain)
    runtime_graph: dict[str, Any] = dict(base_graph)
    runtime_graph["nodes"] = dict(
        base_graph.get("nodes") if isinstance(base_graph.get("nodes"), dict) else {}
    )
    runtime_graph["edges"] = list(
        base_graph.get("edges") if isinstance(base_graph.get("edges"), list) else []
    )

    start_node_id = _find_node_id_by_label(runtime_graph, username)
    if not start_node_id:
        start_node_id = ensure_user_node_for_domain(
            shell, domain, runtime_graph, username=str(username or "").strip()
        )

    snapshot = _load_membership_snapshot(shell, domain)
    _stitch_principal_memberships_for_runtime_paths(
        shell,
        domain=domain,
        runtime_graph=runtime_graph,
        principal_node_ids={start_node_id} if start_node_id else set(),
        snapshot=snapshot,
        scope="user",
    )
    if (
        not snapshot
        and start_node_id
        and not _graph_has_persisted_memberships(runtime_graph)
    ):
        candidate_to_ids: set[str] = {start_node_id}
        if ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS:
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

        _inject_runtime_recursive_memberof_edges(
            shell,
            domain=domain,
            runtime_graph=runtime_graph,
            principal_node_ids=candidate_to_ids,
            skip_tier0_principals=True,
        )
    records = _sort_display_paths(
        attack_paths_core.compute_display_paths_for_start_node(
            runtime_graph,
            domain=domain,
            snapshot=snapshot,
            start_node_id=start_node_id,
            max_depth=max_depth,
            max_paths=max_paths,
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
            expand_terminal_memberships=ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS,
            filter_shortest_paths=False,
        )
    )
    records = _filter_zero_length_display_paths(records, domain=domain, scope="user")
    records = _apply_affected_user_metadata(shell, domain, records)
    _log_attack_path_compute_timing(
        domain=domain,
        scope="user",
        elapsed_seconds=max(0.0, time.monotonic() - started_at),
        path_count=len(records),
        max_depth=max_depth,
        require_high_value_target=require_high_value_target,
        target_mode=target_mode,
    )
    _attack_paths_cache_put(cache_key, records, domain=domain, scope="user")
    return records


def compute_display_paths_for_domain(
    shell: object,
    domain: str,
    *,
    max_depth: int,
    max_paths: int | None = None,
    require_high_value_target: bool = True,
    target_mode: str = "tier0",
) -> list[dict[str, Any]]:
    """Compute maximal attack paths for a domain with optional high-value promotion.

    This is the backend used by `attack_paths <domain>` when no explicit start
    user (or "owned") is provided.

    When `require_high_value_target=True`, we still compute all maximal paths,
    then *promote* paths whose terminal node is not high value but is a member
    (recursively) of an effectively high-value group. The promotion appends a
    context-only `MemberOf` step so the operator can understand why the path is
    surfaced.
    """
    started_at = time.monotonic()
    cache_key = _attack_paths_cache_base_key(
        shell,
        domain,
        scope="domain",
        params=(
            int(max_depth),
            max_paths,
            bool(require_high_value_target),
            str(target_mode or "tier0").strip().lower(),
            bool(ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS),
        ),
    )
    cached = _attack_paths_cache_get(cache_key, domain=domain, scope="domain")
    if cached is not None:
        cached = _filter_zero_length_display_paths(
            cached, domain=domain, scope="domain"
        )
        cached = _apply_affected_user_metadata(shell, domain, cached)
        _log_attack_path_compute_timing(
            domain=domain,
            scope="domain",
            elapsed_seconds=max(0.0, time.monotonic() - started_at),
            path_count=len(cached),
            max_depth=max_depth,
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
        )
        return cached

    base_graph = load_attack_graph(shell, domain)
    runtime_graph: dict[str, Any] = dict(base_graph)
    runtime_graph["nodes"] = dict(
        base_graph.get("nodes") if isinstance(base_graph.get("nodes"), dict) else {}
    )
    runtime_graph["edges"] = list(
        base_graph.get("edges") if isinstance(base_graph.get("edges"), list) else []
    )

    snapshot = _load_membership_snapshot(shell, domain)
    if (
        ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS
        and not snapshot
        and not _graph_has_persisted_memberships(runtime_graph)
    ):
        candidate_to_ids: set[str] = set()
        for edge in runtime_graph["edges"]:
            if not isinstance(edge, dict):
                continue
            to_id = str(edge.get("to") or "")
            if to_id:
                candidate_to_ids.add(to_id)
        if candidate_to_ids:
            _inject_runtime_recursive_memberof_edges(
                shell,
                domain=domain,
                runtime_graph=runtime_graph,
                principal_node_ids=candidate_to_ids,
                skip_tier0_principals=True,
            )
    records = _sort_display_paths(
        attack_paths_core.compute_display_paths_for_domain(
            runtime_graph,
            domain=domain,
            snapshot=snapshot,
            max_depth=max_depth,
            max_paths=max_paths,
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
            expand_terminal_memberships=ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS,
        )
    )
    records = _filter_zero_length_display_paths(records, domain=domain, scope="domain")
    records = _apply_affected_user_metadata(shell, domain, records)
    _log_attack_path_compute_timing(
        domain=domain,
        scope="domain",
        elapsed_seconds=max(0.0, time.monotonic() - started_at),
        path_count=len(records),
        max_depth=max_depth,
        require_high_value_target=require_high_value_target,
        target_mode=target_mode,
    )
    _attack_paths_cache_put(cache_key, records, domain=domain, scope="domain")
    return records


def _filter_contained_paths_for_domain_listing(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Remove paths that are fully contained within another longer path.

    This is used only for the domain-wide view (`attack_paths <domain>`), where
    showing both a path and its suffix/prefix variants is usually redundant.

    Notes:
        We treat containment as a *contiguous* subpath match on both nodes and
        relations. Only strictly shorter paths are removed.
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

        # Mark all contiguous subpaths as covered so we can drop them later.
        # Only mark strictly shorter subpaths.
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


def _dedupe_exact_display_paths(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove exact duplicate paths based on nodes + relations."""
    return attack_paths_core.dedupe_exact_display_paths(records)


def get_owned_domain_usernames(shell: object, domain: str) -> list[str]:
    """Return domain usernames considered "owned" (compromised) for a domain.

    "Owned" users are those with stored *domain* credentials in
    `shell.domains_data[domain]["credentials"]`. This intentionally excludes
    any local (host/service) credentials.

    Args:
        shell: Shell instance holding `domains_data`.
        domain: Domain key used in `domains_data`.

    Returns:
        Sorted list of usernames. Empty when none are stored.
    """

    def _normalize_domain_key(value: str) -> str:
        # Be robust against accidental invisible marker usage in keys.
        zero_width = {"\u200b", "\u200c", "\u200d", "\u2060", "\u200e", "\u200f"}
        cleaned = "".join(ch for ch in (value or "") if ch not in zero_width)
        return cleaned.strip().lower()

    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return []
    domain_data = domains_data.get(domain)
    if domain_data is None:
        target_norm = _normalize_domain_key(domain)
        for key, value in domains_data.items():
            if not isinstance(key, str):
                continue
            if _normalize_domain_key(key) == target_norm:
                domain_data = value
                break
    if not isinstance(domain_data, dict):
        return []
    credentials = domain_data.get("credentials")
    if not isinstance(credentials, dict):
        return []
    return sorted(
        str(username) for username in credentials.keys() if str(username).strip()
    )


def get_owned_domain_usernames_for_attack_paths(
    shell: object,
    domain: str,
) -> list[str]:
    """Return the effective owned-user set for owned attack-path UX.

    Tier-0 owned users are only filtered once the domain is already marked as
    ``pwned``. Before that point, they remain visible so attack-path discovery
    can reflect the newly achieved compromise level.
    """
    owned = get_owned_domain_usernames(shell, domain)
    if not owned:
        return []

    domains_data = getattr(shell, "domains_data", None)
    domain_data = domains_data.get(domain) if isinstance(domains_data, dict) else None
    auth_state = (
        str(domain_data.get("auth") or "").strip().lower()
        if isinstance(domain_data, dict)
        else ""
    )
    if auth_state != "pwned":
        return owned

    filtered: list[str] = []
    skipped_tier0: list[str] = []
    for username in owned:
        label = f"{username}@{domain}"
        node = get_node_by_label(shell, domain, label=label)
        if node is None:
            node = get_node_by_label(shell, domain, label=username)
        if node is not None and _node_is_tier0(node):
            skipped_tier0.append(username)
            continue
        filtered.append(username)

    if skipped_tier0:
        print_info_debug(
            "[attack_paths] owned-user candidates skipped because the domain is already pwned and they are Tier-0: "
            f"domain={mark_sensitive(domain, 'domain')} "
            f"users={', '.join(mark_sensitive(user, 'user') for user in skipped_tier0)}"
        )

    return filtered


def compute_display_paths_for_owned_users(
    shell: object,
    domain: str,
    *,
    max_depth: int,
    max_paths: int | None = None,
    require_high_value_target: bool = True,
    target_mode: str = "tier0",
) -> list[dict[str, Any]]:
    """Compute maximal dynamic paths for all owned users in a domain.

    This is a convenience helper for the CLI `attack_paths <domain> owned`.

    Args:
        shell: Shell instance holding `domains_data` and BloodHound service access.
        domain: Domain name.
        max_depth: Max depth for path search.
        require_high_value_target: When True, only include paths whose terminal node
            is high value (Tier Zero / highvalue / admin_tier_0).

    Returns:
        Deduplicated list of UI-ready path dicts (same shape as `path_to_display_record`).
    """
    owned = get_owned_domain_usernames_for_attack_paths(shell, domain)
    if not owned:
        return []
    return compute_display_paths_for_principals(
        shell,
        domain,
        principals=owned,
        max_depth=max_depth,
        max_paths=max_paths,
        require_high_value_target=require_high_value_target,
        target_mode=target_mode,
    )


def get_attack_path_summaries(
    shell: object,
    domain: str,
    *,
    scope: str = "domain",
    username: str | None = None,
    principals: list[str] | None = None,
    max_depth: int,
    max_paths: int | None = None,
    require_high_value_target: bool = True,
    target_mode: str = "tier0",
    membership_sample_max: int = 3,
) -> list[dict[str, Any]]:
    """Return user-facing attack-path summaries through the shell-aware layer.

    This is the single entry point callers should use for CLI/web summaries.
    It guarantees that all shell-aware post-processing is applied consistently:
    filtering, affected-user metadata, cache handling, and future UX-oriented
    enrichments.
    """
    scope_norm = str(scope or "domain").strip().lower()
    if scope_norm == "domain":
        return compute_display_paths_for_domain(
            shell,
            domain,
            max_depth=max_depth,
            max_paths=max_paths,
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
        )
    if scope_norm == "user":
        if not str(username or "").strip():
            return []
        return compute_display_paths_for_user(
            shell,
            domain,
            username=str(username or "").strip(),
            max_depth=max_depth,
            max_paths=max_paths,
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
        )
    if scope_norm == "owned":
        return compute_display_paths_for_owned_users(
            shell,
            domain,
            max_depth=max_depth,
            max_paths=max_paths,
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
        )
    if scope_norm == "principals":
        normalized_principals = [
            str(principal or "").strip()
            for principal in (principals or [])
            if str(principal or "").strip()
        ]
        if not normalized_principals:
            return []
        return compute_display_paths_for_principals(
            shell,
            domain,
            principals=normalized_principals,
            max_depth=max_depth,
            max_paths=max_paths,
            require_high_value_target=require_high_value_target,
            membership_sample_max=membership_sample_max,
            target_mode=target_mode,
        )
    raise ValueError(f"Unsupported attack path summary scope: {scope!r}")


def _derive_display_status_from_steps(steps: list[dict[str, Any]]) -> str:
    statuses: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        action = str(step.get("action") or "").strip().lower()
        if action in _CONTEXT_RELATIONS_LOWER:
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
    if any(
        classify_relation_support(str(step.get("action") or "").strip().lower()).kind
        == "policy_blocked"
        for step in steps
        if isinstance(step, dict)
        and str(step.get("action") or "").strip().lower()
        not in _CONTEXT_RELATIONS_LOWER
    ):
        # Policy-blocked steps should surface as blocked even before any execution attempt.
        return "blocked"
    return "theoretical"


def _strip_leading_relations(
    record: dict[str, Any],
    *,
    relations_to_strip: set[str],
) -> tuple[dict[str, Any], int]:
    """Return a copy of record with a leading relation prefix stripped.

    This is primarily used to collapse runtime `MemberOf` expansions when
    listing owned/principal paths: different users may share the same "core"
    escalation (e.g. Domain Users -> NoPac -> Domain).
    """
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
        1
        for rel in new_rels
        if str(rel or "").strip().lower() not in _CONTEXT_RELATIONS_LOWER
    )
    new_record["source"] = new_nodes[0] if new_nodes else ""
    new_record["target"] = new_nodes[-1] if new_nodes else ""
    new_record["steps"] = kept_steps
    new_record["status"] = _derive_display_status_from_steps(kept_steps)
    return new_record, strip_count


def compute_display_paths_for_principals(
    shell: object,
    domain: str,
    *,
    principals: list[str],
    max_depth: int,
    max_paths: int | None = None,
    require_high_value_target: bool = True,
    membership_sample_max: int = 3,
    target_mode: str = "tier0",
) -> list[dict[str, Any]]:
    """Compute maximal dynamic paths for a list of user principals.

    This is used to implement `attack_paths <domain> owned` without spamming one
    identical membership-originating path per owned user.
    """
    started_at = time.monotonic()
    normalized_principals = [str(p or "").strip().lower() for p in principals]
    normalized_principals = [p for p in normalized_principals if p]
    if not normalized_principals:
        _log_attack_path_compute_timing(
            domain=domain,
            scope="principals",
            elapsed_seconds=max(0.0, time.monotonic() - started_at),
            path_count=0,
            max_depth=max_depth,
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
        )
        return []

    unique_principals = sorted(set(normalized_principals))
    principals_key = tuple(unique_principals)
    cache_key = _attack_paths_cache_base_key(
        shell,
        domain,
        scope="principals",
        params=(
            principals_key,
            int(max_depth),
            max_paths,
            bool(require_high_value_target),
            int(membership_sample_max),
            str(target_mode or "tier0").strip().lower(),
        ),
    )
    cached = _attack_paths_cache_get(cache_key, domain=domain, scope="principals")
    if cached is not None:
        cached = _filter_zero_length_display_paths(
            cached, domain=domain, scope="principals"
        )
        cached = _apply_affected_user_metadata(shell, domain, cached)
        _log_attack_path_compute_timing(
            domain=domain,
            scope="principals",
            elapsed_seconds=max(0.0, time.monotonic() - started_at),
            path_count=len(cached),
            max_depth=max_depth,
            require_high_value_target=require_high_value_target,
            target_mode=target_mode,
        )
        return cached

    snapshot = _load_membership_snapshot(shell, domain)
    snapshot_user_to_groups = (
        snapshot.get("user_to_groups") if isinstance(snapshot, dict) else None
    )
    snapshot_user_keys: set[str] = set()
    if isinstance(snapshot_user_to_groups, dict):
        for principal_label in snapshot_user_to_groups.keys():
            normalized = _normalize_account(str(principal_label or ""))
            if normalized:
                snapshot_user_keys.add(normalized)

    principal_coverage_keys = [
        _normalize_account(principal) or principal for principal in unique_principals
    ]
    covered_by_snapshot = (
        sum(
            1
            for principal_key in principal_coverage_keys
            if principal_key in snapshot_user_keys
        )
        if snapshot_user_keys
        else 0
    )
    snapshot_coverage_ratio = (
        covered_by_snapshot / len(unique_principals) if unique_principals else 0.0
    )

    base_graph = load_attack_graph(shell, domain)
    runtime_graph: dict[str, Any] = dict(base_graph)
    runtime_graph["nodes"] = dict(
        base_graph.get("nodes") if isinstance(base_graph.get("nodes"), dict) else {}
    )
    runtime_graph["edges"] = list(
        base_graph.get("edges") if isinstance(base_graph.get("edges"), list) else []
    )
    # Coverage-first default: keep BloodHound resolution unless an operator
    # explicitly enables synthetic batch mode for performance experiments.
    resolve_via_bloodhound = True
    if _ATTACK_PATH_ENABLE_SYNTHETIC_PRINCIPAL_BATCH and (
        _ATTACK_PATH_PRINCIPAL_BH_RESOLVE_MAX > 0
        and len(unique_principals) > _ATTACK_PATH_PRINCIPAL_BH_RESOLVE_MAX
    ):
        if (
            snapshot_user_keys
            and snapshot_coverage_ratio
            >= _ATTACK_PATH_PRINCIPAL_SYNTHETIC_MIN_SNAPSHOT_COVERAGE
        ):
            resolve_via_bloodhound = False
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                "[attack_paths] synthetic batch mode enabled for principal resolution: "
                f"domain={marked_domain} principals={len(unique_principals)} "
                f"threshold={_ATTACK_PATH_PRINCIPAL_BH_RESOLVE_MAX} "
                f"snapshot_coverage={snapshot_coverage_ratio:.2%}"
            )
        else:
            marked_domain = mark_sensitive(domain, "domain")
            print_info_debug(
                "[attack_paths] synthetic batch mode requested but not used "
                "(coverage guard): "
                f"domain={marked_domain} principals={len(unique_principals)} "
                f"threshold={_ATTACK_PATH_PRINCIPAL_BH_RESOLVE_MAX} "
                f"snapshot_coverage={snapshot_coverage_ratio:.2%} "
                f"required={_ATTACK_PATH_PRINCIPAL_SYNTHETIC_MIN_SNAPSHOT_COVERAGE:.2%}"
            )
    elif not _ATTACK_PATH_ENABLE_SYNTHETIC_PRINCIPAL_BATCH:
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            "[attack_paths] coverage-first mode active: "
            f"domain={marked_domain} principal resolution via BloodHound"
        )
    principal_node_ids: set[str] = set()
    for username in unique_principals:
        if not _find_node_id_by_label(runtime_graph, username):
            if resolve_via_bloodhound:
                ensure_user_node_for_domain(
                    shell, domain, runtime_graph, username=str(username or "").strip()
                )
            else:
                _ensure_user_node_for_domain_synthetic(
                    domain,
                    runtime_graph,
                    username=str(username or "").strip(),
                )
        principal_id = _find_node_id_by_label(runtime_graph, username)
        if principal_id:
            principal_node_ids.add(principal_id)

    _stitch_principal_memberships_for_runtime_paths(
        shell,
        domain=domain,
        runtime_graph=runtime_graph,
        principal_node_ids=principal_node_ids,
        snapshot=snapshot,
        scope="principals",
    )
    records = _sort_display_paths(
        attack_paths_core.compute_display_paths_for_principals(
            runtime_graph,
            domain=domain,
            snapshot=snapshot,
            principals=unique_principals,
            max_depth=max_depth,
            max_paths=max_paths,
            require_high_value_target=require_high_value_target,
            membership_sample_max=membership_sample_max,
            target_mode=target_mode,
            filter_shortest_paths=False,
        )
    )
    records = _filter_zero_length_display_paths(
        records, domain=domain, scope="principals"
    )
    records = _apply_affected_user_metadata(shell, domain, records)
    _log_attack_path_compute_timing(
        domain=domain,
        scope="principals",
        elapsed_seconds=max(0.0, time.monotonic() - started_at),
        path_count=len(records),
        max_depth=max_depth,
        require_high_value_target=require_high_value_target,
        target_mode=target_mode,
    )
    _attack_paths_cache_put(cache_key, records, domain=domain, scope="principals")
    return records


def compute_attack_path_metrics(
    shell: object,
    domain: str,
    *,
    max_depth: int = 10,
) -> dict[str, Any]:
    """Compute attack path metrics for case studies.

    This function analyzes the attack graph to compute metrics about complete
    attack paths to Tier 0 targets, suitable for case study reports.

    Args:
        shell: Shell instance for loading the attack graph.
        domain: Domain to analyze.
        max_depth: Maximum path depth to consider.

    Returns:
        Dictionary with path metrics:
        - paths_to_tier0: Total complete paths found
        - paths_exploited: Paths where all steps succeeded
        - paths_partial: Paths where exploitation was attempted but incomplete
        - paths_not_attempted: Paths discovered but not executed
        - paths_by_type: Breakdown by attack type (adcs, kerberos, acl, etc.)
    """
    try:
        graph = load_attack_graph(shell, domain)
        if not graph:
            return _empty_path_metrics()

        # Compute maximal paths to Tier 0
        paths = compute_maximal_attack_paths(
            graph,
            max_depth=max_depth,
            require_high_value_target=True,
            terminal_mode="tier0",
        )

        if not paths:
            return _empty_path_metrics()

        # Analyze each path
        paths_exploited = 0
        paths_partial = 0
        paths_not_attempted = 0
        paths_by_type: dict[str, dict[str, int]] = {}

        # Context relations that don't count as executable steps
        context_relations = _CONTEXT_RELATIONS_LOWER

        for path in paths:
            # Get executable steps (exclude context relations like MemberOf)
            executable_steps = [
                s
                for s in path.steps
                if isinstance(getattr(s, "relation", None), str)
                and str(s.relation).strip().lower() not in context_relations
            ]

            if not executable_steps:
                continue

            # Determine path status
            statuses = [
                s.status.lower()
                if isinstance(s.status, str) and s.status
                else "discovered"
                for s in executable_steps
            ]

            if all(s == "success" for s in statuses):
                path_status = "exploited"
                paths_exploited += 1
            elif any(
                s in {"attempted", "failed", "error", "success"} for s in statuses
            ):
                path_status = "partial"
                paths_partial += 1
            else:
                path_status = "not_attempted"
                paths_not_attempted += 1

            # Determine path type from primary relation
            path_type = _determine_path_type(executable_steps)

            # Track by type
            if path_type not in paths_by_type:
                paths_by_type[path_type] = {
                    "found": 0,
                    "exploited": 0,
                    "partial": 0,
                    "not_attempted": 0,
                }
            paths_by_type[path_type]["found"] += 1
            paths_by_type[path_type][path_status] += 1

        return {
            "paths_to_tier0": len(paths),
            "paths_exploited": paths_exploited,
            "paths_partial": paths_partial,
            "paths_not_attempted": paths_not_attempted,
            "paths_by_type": paths_by_type,
        }
    except Exception as exc:
        telemetry.capture_exception(exc)
        return _empty_path_metrics()


def _empty_path_metrics() -> dict[str, Any]:
    """Return empty path metrics structure."""
    return {
        "paths_to_tier0": 0,
        "paths_exploited": 0,
        "paths_partial": 0,
        "paths_not_attempted": 0,
        "paths_by_type": {},
    }


def _determine_path_type(steps: list[AttackPathStep]) -> str:
    """Determine the primary type of an attack path from its steps.

    The type is determined by the most significant relation in the path:
    - ADCS relations take precedence (ESC1, ESC3, etc.)
    - Then Kerberos (kerberoasting, asreproasting)
    - Then delegation
    - Then DCSync
    - Then ACL
    - Then access
    - Otherwise "other"
    """
    relations = [
        str(s.relation).strip().lower()
        for s in steps
        if isinstance(getattr(s, "relation", None), str)
    ]

    # Check for ADCS
    adcs_relations = {
        "adcsesc1",
        "adcsesc3",
        "adcsesc4",
        "adcsesc6",
        "adcsesc8",
        "adcsesc9",
        "adcsesc10",
    }
    if any(r in adcs_relations for r in relations):
        return "adcs"

    # Check for Kerberos
    kerberos_relations = {"kerberoasting", "asreproasting"}
    if any(r in kerberos_relations for r in relations):
        return "kerberos"

    # Check for delegation
    delegation_relations = {"allowedtodelegate", "allowedtoactonbehalfofotheridentity"}
    if any(r in delegation_relations for r in relations):
        return "delegation"

    # Check for DCSync
    dcsync_relations = {"dcsync", "getchanges", "getchangesall"}
    if any(r in dcsync_relations for r in relations):
        return "dcsync"

    # Check for ACL
    acl_relations = {
        "genericall",
        "genericwrite",
        "writedacl",
        "writeowner",
        "owns",
        "forcechangepassword",
        "addmember",
        "addself",
        "writespn",
        "addkeycreatentiallink",
        "readlapspassword",
        "readgmsapassword",
    }
    if any(r in acl_relations for r in relations):
        return "acl"

    # Check for access
    access_relations = {"adminto", "canrdp", "canpsremote", "executedcom"}
    if any(r in access_relations for r in relations):
        return "access"

    return "other"
