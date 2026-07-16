"""Attack path computation core (pure functions).

This module centralizes attack-path display logic so both CLI and web can
produce identical results using the same inputs (attack_graph + memberships).
It performs no I/O and does not depend on shell context.
"""

from __future__ import annotations

import time
import os
import re
import logging
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from adscan_core.rich_output import strip_sensitive_markers
from adscan_internal.rich_output import print_info_debug
from adscan_internal.services import attack_graph_core
from adscan_internal.services.attack_step_support_registry import (
    CONTEXT_ONLY_RELATIONS,
)
from adscan_internal.services.tier_lattice import (
    TargetTier,
    classify_target_tier,
    comparability_key,
    record_domain_compromise_tier,
    stamp_records_target_tier,
    target_tier_from_record,
    tier_dominates,
)

# ---------------------------------------------------------------------------
# Parallel principals infrastructure
#
# Activated by ADSCAN_ATTACK_PATH_WORKERS (same env var as attack_graph_core):
#   0   → sequential (default, safe)
#   -1  → auto (cpu_count workers)
#   N>0 → use N worker processes (capped at cpu_count and principal count)
#
# The graph + snapshot are sent to each worker once via the pool initializer;
# only the per-task username string is pickled per dispatch.
# ---------------------------------------------------------------------------


def _read_principal_workers() -> int:
    try:
        return int(os.getenv("ADSCAN_ATTACK_PATH_WORKERS", "0").strip())
    except (TypeError, ValueError):
        return 0


_PRINCIPAL_WORKERS: int = _read_principal_workers()


def _read_phase_profiling_enabled() -> bool:
    """Return whether per-phase attack-path profiling logs are enabled."""
    return str(os.getenv("ADSCAN_ATTACK_PATH_PROFILE_PHASES", "0")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


_ATTACK_PATH_PHASE_PROFILING_ENABLED = _read_phase_profiling_enabled()


def _read_debug_sample_limit() -> int:
    """Return the max number of per-path debug lines to emit per category."""
    raw = os.getenv("ADSCAN_ATTACK_PATH_DEBUG_SAMPLE_LIMIT", "5").strip()
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 5


@dataclass
class SampledDebugLogger:
    """Emit only a sample of repetitive debug lines and summarize the rest.

    This keeps attack-path telemetry bounded while preserving representative
    examples for troubleshooting. Aggregate summary lines should still be
    logged separately by callers.
    """

    prefix: str
    summary_label: str
    enabled: bool = True
    limit: int | None = None
    _emitted: int = 0
    _suppressed: int = 0

    def __post_init__(self) -> None:
        """Resolve the effective sample limit after dataclass initialization."""
        if self.limit is None:
            self.limit = _read_debug_sample_limit()

    def log(self, message: str) -> None:
        """Emit one debug line or account for it as suppressed."""
        if not self.enabled:
            return
        if self.limit is not None and self.limit > self._emitted:
            print_info_debug(message)
            self._emitted += 1
            return
        self._suppressed += 1

    def flush(self) -> None:
        """Emit a compact suppression summary when lines were skipped."""
        if not self.enabled or self._suppressed <= 0:
            return
        total = self._emitted + self._suppressed
        print_info_debug(
            f"{self.prefix} {self.summary_label}: "
            f"{total} total ({self._emitted} shown, {self._suppressed} suppressed)"
        )


# Per-worker state for principal parallelism.
_PW_GRAPH: dict[str, Any] = {}
_PW_DOMAIN: str = ""
_PW_SNAPSHOT: dict[str, Any] | None = None
_PW_MAX_DEPTH: int = 7
_PW_MAX_PATHS: int | None = None
_PW_TARGET: str = "highvalue"
_PW_TARGET_MODE: str = "domain"
_PW_FILTER_SHORTEST: bool = True
_GROUP_MEMBERSHIP_INDEX_CACHE: dict[
    tuple[int, str, int], tuple[dict[str, int], dict[str, list[str]]]
] = {}
_GROUP_MEMBER_INDEX_CACHE: dict[
    tuple[int, str, bool, bool],
    tuple[dict[str, set[str]], dict[str, set[str]], bool],
] = {}


def _log_phase_timing(
    *,
    scope: str,
    phase: str,
    started_at: float,
    records: list[dict[str, Any]] | None = None,
) -> None:
    """Emit one debug timing line for a pipeline phase when profiling is enabled."""
    if not _ATTACK_PATH_PHASE_PROFILING_ENABLED:
        return
    suffix = ""
    if isinstance(records, list):
        suffix = f" records={len(records)}"
    print_info_debug(
        f"[attack-paths-profile] scope={scope} phase={phase} "
        f"elapsed={max(0.0, time.monotonic() - started_at):.6f}s{suffix}"
    )


def _debug_logging_enabled() -> bool:
    """Return whether attack-path debug logs are currently enabled."""
    return logging.getLogger("adscan").isEnabledFor(logging.DEBUG)


def _debug_paths_checkpoint(label: str, records: list[dict[str, Any]]) -> None:
    """Emit one compact debug line summarising a pipeline stage result.

    Shows total path count plus a sample of unique sources so the log stays
    readable even when hundreds of paths share the same starting node.
    """
    if not records:
        print_info_debug(f"[attack_paths_core] {label}: 0 paths")
        return
    sources = [str(r.get("source") or "") for r in records if r.get("source")]
    unique = sorted(set(sources))
    top = unique[:3]
    sample = ", ".join(repr(s) for s in top)
    extra = f" +{len(unique) - 3} more" if len(unique) > 3 else ""
    print_info_debug(
        f"[attack_paths_core] {label}: {len(records)} paths, "
        f"{len(unique)} unique source(s) [{sample}{extra}]"
    )


def _string_tuple(values: list[Any]) -> tuple[str, ...]:
    """Return a tuple of strings for a display-record sequence.

    Display records in this pipeline already carry strings, so converting via
    ``tuple(...)`` avoids per-element coercion overhead on very large path sets.
    """
    return tuple(values)


def _record_exact_signature(
    record: dict[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Return or build the exact path signature for one display record."""
    cached = record.get("_exact_signature")
    if (
        isinstance(cached, tuple)
        and len(cached) == 2
        and isinstance(cached[0], tuple)
        and isinstance(cached[1], tuple)
    ):
        return cached  # type: ignore[return-value]

    nodes = record.get("nodes")
    rels = record.get("relations")
    if not isinstance(nodes, list) or not isinstance(rels, list):
        return None
    signature = (_string_tuple(nodes), _string_tuple(rels))
    record["_exact_signature"] = signature
    return signature


def _principal_worker_init(
    graph: dict[str, Any],
    domain: str,
    snapshot: dict[str, Any] | None,
    max_depth: int,
    max_paths: int | None,
    target: str,
    target_mode: str,
    filter_shortest_paths: bool,
) -> None:
    """Populate per-worker globals. Called once per worker process by the pool initializer."""
    global _PW_GRAPH, _PW_DOMAIN, _PW_SNAPSHOT  # noqa: PLW0603
    global _PW_MAX_DEPTH, _PW_MAX_PATHS, _PW_TARGET, _PW_TARGET_MODE, _PW_FILTER_SHORTEST  # noqa: PLW0603
    _PW_GRAPH = graph
    _PW_DOMAIN = domain
    _PW_SNAPSHOT = snapshot
    _PW_MAX_DEPTH = max_depth
    _PW_MAX_PATHS = max_paths
    _PW_TARGET = target
    _PW_TARGET_MODE = target_mode
    _PW_FILTER_SHORTEST = filter_shortest_paths


def _compute_paths_for_principal_worker(username: str) -> list[dict[str, Any]]:
    """Compute attack paths for one principal using per-worker state.

    Module-level so it is picklable for multiprocessing dispatch.
    """
    return compute_display_paths_for_user(
        _PW_GRAPH,
        domain=_PW_DOMAIN,
        snapshot=_PW_SNAPSHOT,
        username=username,
        max_depth=_PW_MAX_DEPTH,
        max_paths=_PW_MAX_PATHS,
        target=_PW_TARGET,
        target_mode=_PW_TARGET_MODE,
        filter_shortest_paths=_PW_FILTER_SHORTEST,
    )


def _effective_principal_workers(n_principals: int) -> int:
    """Return the effective worker count for *n_principals* principals.

    Returns 0 when parallelism is disabled or the principal count is too
    small to offset the process-spawn overhead (threshold: ≥ 3 principals).
    """
    if _PRINCIPAL_WORKERS == 0 or n_principals < 3:
        return 0
    cpu = os.cpu_count() or 1
    if _PRINCIPAL_WORKERS < 0:
        return min(cpu, n_principals)
    return min(_PRINCIPAL_WORKERS, cpu, n_principals)


def _run_parallel_principals(
    principals: list[str],
    graph: dict[str, Any],
    domain: str,
    snapshot: dict[str, Any] | None,
    max_depth: int,
    max_paths: int | None,
    target: str,
    target_mode: str,
    filter_shortest_paths: bool,
    n_workers: int,
) -> list[dict[str, Any]] | None:
    """Run per-principal DFS in parallel with spawn-context workers.

    The graph and snapshot are sent to each worker once via the pool
    initializer.  Each task only carries the principal username string.

    Returns the aggregated list of raw records on success, or None on any
    error (caller should fall back to sequential).
    """
    import concurrent.futures
    import multiprocessing

    ctx = multiprocessing.get_context("spawn")
    all_records: list[dict[str, Any]] = []

    try:
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=n_workers,
            mp_context=ctx,
            initializer=_principal_worker_init,
            initargs=(
                graph,
                domain,
                snapshot,
                max_depth,
                max_paths,
                target,
                target_mode,
                filter_shortest_paths,
            ),
        ) as pool:
            futures = {
                pool.submit(_compute_paths_for_principal_worker, u): u
                for u in principals
            }
            for future in concurrent.futures.as_completed(futures):
                records = future.result()
                all_records.extend(records)
    except Exception:  # noqa: BLE001
        return None

    return all_records


_EMPTY_GROUP_WHITELIST = {
    item.strip().upper()
    for item in os.getenv(
        "ADSCAN_ATTACK_PATH_EMPTY_GROUP_WHITELIST", "S-1-5-7,S-1-5-32-546,S-1-5-32-514"
    ).split(",")
    if item.strip()
}

_SID_PATTERN = re.compile(r"(S-1-\d+(?:-\d+)+)", re.IGNORECASE)
_CONTEXT_RELATIONS_LOWER = {
    str(relation).strip().lower() for relation in CONTEXT_ONLY_RELATIONS.keys()
}


def _extract_sid(value: str) -> str | None:
    if not value:
        return None
    match = _SID_PATTERN.search(value)
    if not match:
        return None
    return match.group(1).upper()


def _domain_sid_from_sid(sid: str) -> str | None:
    """Return the AD domain SID for a domain object SID or principal SID."""
    sid = str(sid or "").strip().upper()
    if not sid.startswith("S-1-5-21-"):
        return None
    parts = sid.split("-")
    if len(parts) == 7:
        return sid
    if len(parts) > 7:
        return "-".join(parts[:-1])
    return None


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
        # When the file also has raw BH edges (membership-1.0 schema written by
        # persist_bloodhound_membership_snapshot), merge those MemberOf edges into
        # the existing dicts. This prevents runtime additions (ESC13, AddMember)
        # from shadowing real AD memberships when user_to_groups was only partially
        # populated before the BH edges were present.
        nodes_map = normalized.get("nodes")
        edges = normalized.get("edges")
        if isinstance(nodes_map, dict) and isinstance(edges, list) and edges:
            u2g: dict[str, list[str]] = normalized.get("user_to_groups") or {}
            if not isinstance(u2g, dict):
                u2g = {}
            c2g: dict[str, list[str]] = normalized.get("computer_to_groups") or {}
            if not isinstance(c2g, dict):
                c2g = {}
            g2p: dict[str, list[str]] = normalized.get("group_to_parents") or {}
            if not isinstance(g2p, dict):
                g2p = {}
            u2g_sets: dict[str, set[str]] = {
                k: set(v) for k, v in u2g.items() if isinstance(v, list)
            }
            c2g_sets: dict[str, set[str]] = {
                k: set(v) for k, v in c2g.items() if isinstance(v, list)
            }
            g2p_sets: dict[str, set[str]] = {
                k: set(v) for k, v in g2p.items() if isinstance(v, list)
            }
            changed = False
            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                relation = (
                    edge.get("relation") or edge.get("label") or edge.get("kind") or ""
                )
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
                    domain, _canonical_principal_label_for_membership(from_node)
                )
                to_label = _canonical_membership_label(
                    domain, _canonical_node_label(to_node)
                )
                if not from_label or not to_label:
                    continue
                from_kind = _node_kind(from_node)
                if from_kind == "User":
                    before = len(u2g_sets.get(from_label, set()))
                    u2g_sets.setdefault(from_label, set()).add(to_label)
                    changed = changed or len(u2g_sets[from_label]) != before
                elif from_kind == "Computer":
                    before = len(c2g_sets.get(from_label, set()))
                    c2g_sets.setdefault(from_label, set()).add(to_label)
                    changed = changed or len(c2g_sets[from_label]) != before
                elif from_kind == "Group":
                    before = len(g2p_sets.get(from_label, set()))
                    g2p_sets.setdefault(from_label, set()).add(to_label)
                    changed = changed or len(g2p_sets[from_label]) != before
            primary_changed = _merge_primary_group_memberships_from_nodes(
                domain=domain,
                nodes_map=nodes_map,
                user_to_groups=u2g_sets,
                computer_to_groups=c2g_sets,
            )
            changed = changed or primary_changed
            if changed:
                normalized["user_to_groups"] = {
                    k: sorted(v, key=str.lower) for k, v in sorted(u2g_sets.items())
                }
                normalized["computer_to_groups"] = {
                    k: sorted(v, key=str.lower) for k, v in sorted(c2g_sets.items())
                }
                normalized["group_to_parents"] = {
                    k: sorted(v, key=str.lower) for k, v in sorted(g2p_sets.items())
                }
        return normalized

    nodes_map = data.get("nodes")
    edges = data.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return None

    user_to_groups: dict[str, set[str]] = {}
    computer_to_groups: dict[str, set[str]] = {}
    group_to_parents: dict[str, set[str]] = {}
    group_labels: set[str] = set()
    label_to_sid: dict[str, str] = {}
    sid_to_label: dict[str, str] = {}
    domain_sid: str | None = None
    preferred_domain_sid: str | None = None
    first_domain_sid: str | None = None
    tier0_users: set[str] = set()

    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        label = _canonical_membership_label(
            domain, _canonical_principal_label_for_membership(node)
        )
        if not label:
            continue
        if _node_kind(node) == "Group":
            group_labels.add(label)
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
                candidate_sid = _domain_sid_from_sid(sid)
                if candidate_sid:
                    if not first_domain_sid:
                        first_domain_sid = candidate_sid
                    if not preferred_domain_sid:
                        label_domain = str(domain or "").strip().upper()
                        label_match = label.endswith(f"@{label_domain}")
                        rid = sid.split("-")[-1]
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
            domain, _canonical_principal_label_for_membership(from_node)
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

    _merge_primary_group_memberships_from_nodes(
        domain=domain,
        nodes_map=nodes_map,
        user_to_groups=user_to_groups,
        computer_to_groups=computer_to_groups,
    )

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
        "group_labels": sorted(group_labels, key=str.lower),
        "tier0_users": sorted(tier0_users, key=str.lower),
        "label_to_sid": label_to_sid,
        "sid_to_label": sid_to_label,
        "domain_sid": domain_sid,
    }


def _merge_primary_group_memberships_from_nodes(
    *,
    domain: str,
    nodes_map: dict[str, Any],
    user_to_groups: dict[str, set[str]],
    computer_to_groups: dict[str, set[str]],
) -> bool:
    """Add effective primary-group memberships omitted from LDAP ``memberOf``.

    Active Directory does not include a principal's primary group in the
    ``memberOf`` attribute. Native graph snapshots therefore need to derive that
    edge from ``primaryGroupID`` and the principal/domain SID so owned-scope
    path search can inherit rights granted to groups such as Domain Users.
    """
    sid_to_group_label = _build_group_label_by_sid(domain, nodes_map)
    changed = False
    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        kind = _node_kind(node)
        if kind not in {"User", "Computer"}:
            continue
        principal_label = _canonical_membership_label(
            domain, _canonical_principal_label_for_membership(node)
        )
        primary_group_sid = _primary_group_sid_for_node(node)
        if not principal_label or not primary_group_sid:
            continue
        group_label = sid_to_group_label.get(primary_group_sid)
        if not group_label or group_label == principal_label:
            continue
        target = user_to_groups if kind == "User" else computer_to_groups
        groups = target.setdefault(principal_label, set())
        before = len(groups)
        groups.add(group_label)
        changed = changed or len(groups) != before
    return changed


def _build_group_label_by_sid(domain: str, nodes_map: dict[str, Any]) -> dict[str, str]:
    """Return SID -> canonical group label for group nodes in a graph snapshot."""
    result: dict[str, str] = {}
    for node in nodes_map.values():
        if not isinstance(node, dict) or _node_kind(node) != "Group":
            continue
        sid = _extract_node_sid(node)
        label = _canonical_membership_label(domain, _canonical_node_label(node))
        if sid and label:
            result[sid] = label
    return result


def _primary_group_sid_for_node(node: dict[str, Any]) -> str:
    """Return the primary group SID for a user/computer node, if derivable."""
    principal_sid = _extract_node_sid(node)
    if not principal_sid or not principal_sid.startswith("S-1-5-21-"):
        return ""
    primary_group_id = _node_primary_group_id(node)
    if primary_group_id is None:
        return ""
    domain_sid, _, _rid = principal_sid.rpartition("-")
    if not domain_sid:
        return ""
    return f"{domain_sid}-{primary_group_id}"


def _node_primary_group_id(node: dict[str, Any]) -> int | None:
    """Return a normalized ``primaryGroupID`` value from node metadata."""
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    for key in ("primarygroupid", "primaryGroupID", "primary_group_id"):
        value = node.get(key)
        if value is None:
            value = props.get(key)
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _extract_node_sid(node: dict[str, Any]) -> str:
    """Extract a normalized SID from a graph node."""
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    object_id = str(
        node.get("objectId") or props.get("objectid") or props.get("objectId") or ""
    ).strip()
    return _extract_sid(object_id)


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
    name = strip_sensitive_markers(str(value or "")).strip()
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


def _canonical_principal_label_for_membership(node: dict[str, Any]) -> str:
    """Return the canonical principal label used for membership snapshot keys.

    Membership lookups (``_snapshot_get_direct_groups``) canonicalize the
    incoming principal as ``<sAMAccountName>@<DOMAIN>``.  For consistency,
    the snapshot writer must store keys in the same form.  BloodHound's
    ``label`` field equals the sAMAccountName for User nodes but the
    FQDN for Computer nodes (``RODC01.GARFIELD.HTB``), which would key
    Computer entries under a form lookups never use.

    Prefers ``properties.samaccountname`` (BloodHound CE / native collector
    populate this on User and Computer nodes), then falls back to the
    existing ``_canonical_node_label`` behaviour for non-principal node
    kinds (Group, Domain, OU, GPO, etc.) where the label IS the canonical
    identifier.
    """
    kind = _node_kind(node)
    if kind in {"User", "Computer"}:
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        for key in ("samaccountname", "sAMAccountName", "sam_account_name"):
            value = props.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return _canonical_node_label(node)


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


def _graph_has_materialized_terminal_memberships(graph: dict[str, Any]) -> bool:
    """Return True when terminal runtime memberships were already materialized."""
    return bool(graph.get("_attack_paths_terminal_memberships_materialized"))


def _find_node_id_by_label(graph: dict[str, Any], label: str) -> str | None:
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return None
    normalized = _normalize_account(label)

    def _quality_score(node: dict[str, Any]) -> int:
        """Mirror of attack_graph_service._find_node_id_by_label scoring.

        Security principals (Group/User/Computer/Domain) outrank structural
        AD objects (OU/Container/CertTemplate) so an OU named "Domain
        Controllers" never wins over the Domain Controllers security group.
        """
        score = 0
        kind = _node_kind(node)
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )

        if kind in {"Group", "User", "Computer", "Domain"}:
            score += 100  # security principals always outrank structural objects
        elif kind != "Unknown":
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


def _build_node_id_index_by_canonical_label(
    graph: dict[str, Any],
    *,
    domain: str,
) -> dict[str, str]:
    """Build one canonical label -> node_id index for exact label lookups.

    This is intentionally lighter than ``_find_node_id_by_label``: it preserves
    the first observed node id for one canonical label and is used only inside
    hot paths that repeatedly resolve or create group nodes during runtime
    membership expansion.
    """
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return {}

    result: dict[str, str] = {}
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        canonical_label = _canonical_membership_label(
            domain, _canonical_node_label(node)
        )
        if canonical_label and canonical_label not in result:
            result[canonical_label] = str(node_id)
    return result


def _ensure_group_node_id(
    graph: dict[str, Any],
    *,
    domain: str,
    label: str,
    node_id_by_label: dict[str, str] | None = None,
) -> str:
    nodes_map = graph.get("nodes")
    if not isinstance(nodes_map, dict):
        return ""
    canonical = _canonical_membership_label(domain, label)
    existing = None
    if node_id_by_label is not None:
        existing = node_id_by_label.get(canonical)
    if not existing:
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
    if node_id_by_label is not None and canonical:
        node_id_by_label[canonical] = node_id
    return node_id


def _expand_group_ancestors(
    domain: str,
    group_label: str,
    group_to_parents: dict[str, Any],
    cache: dict[str, set[str]],
) -> set[str]:
    """Expand recursive parent groups without Python recursion.

    The previous recursive implementation could hit ``RecursionError`` in very
    large/degenerate environments (deep nested groups or accidental cycles).
    This iterative DFS keeps the same cache contract while avoiding call-stack
    growth.
    """
    if group_label in cache:
        return cache[group_label]

    def _parent_labels(label: str) -> list[str]:
        parents = group_to_parents.get(label, []) if group_to_parents else []
        if not isinstance(parents, list):
            return []
        normalized: list[str] = []
        for parent in parents:
            parent_label = _canonical_membership_label(domain, parent)
            if not parent_label:
                continue
            normalized.append(parent_label)
        return normalized

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

    if principal_labels is None:
        cache_key = (id(snapshot), str(domain or "").strip().upper(), int(sample_limit))
        cached = _GROUP_MEMBERSHIP_INDEX_CACHE.get(cache_key)
        if cached is not None:
            return cached

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

    result = (counts, samples)
    if principal_labels is None:
        _GROUP_MEMBERSHIP_INDEX_CACHE[cache_key] = result
    return result


def build_group_member_index(
    snapshot: dict[str, Any] | None,
    domain: str,
    *,
    exclude_tier0: bool = False,
    include_computers: bool = True,
) -> tuple[dict[str, set[str]], dict[str, set[str]], bool]:
    """Build inverted group-membership indices from the snapshot.

    Args:
        snapshot: Prepared membership snapshot (from ``prepare_membership_snapshot``).
        domain: Canonical domain name used for label normalisation.
        exclude_tier0: When True, tier-0 users are excluded from the user index.
        include_computers: When True (default), also build a computer membership
            index from ``computer_to_groups``.  Computers are kept separate from
            users so that execution helpers (which resolve user credentials) are
            not polluted with computer accounts.

    Returns:
        ``(user_group_members, computer_group_members, has_principals)`` where:
        - ``user_group_members``     — ``{group_canonical: {user_labels}}``
        - ``computer_group_members`` — ``{group_canonical: {computer_labels}}``
        - ``has_principals``         — True when at least one user *or* computer
          was found in the snapshot (guards against completely empty snapshots).
    """
    if not snapshot:
        return {}, {}, False

    user_to_groups = snapshot.get("user_to_groups")
    computer_to_groups = snapshot.get("computer_to_groups")
    group_to_parents = snapshot.get("group_to_parents")

    has_users = isinstance(user_to_groups, dict) and bool(user_to_groups)
    has_computers = (
        include_computers
        and isinstance(computer_to_groups, dict)
        and bool(computer_to_groups)
    )

    if not has_users and not has_computers:
        return {}, {}, False

    cache_key = (
        id(snapshot),
        str(domain or "").strip().upper(),
        bool(exclude_tier0),
        bool(include_computers),
    )
    cached = _GROUP_MEMBER_INDEX_CACHE.get(cache_key)
    if cached is not None:
        return cached

    user_group_members: dict[str, set[str]] = {}
    computer_group_members: dict[str, set[str]] = {}
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

    def _add_to_index(
        index: dict[str, set[str]],
        principal_label: str,
        direct_groups: list[str],
    ) -> None:
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
                index.setdefault(ancestor, set()).add(principal_label)

    if has_users:
        for user_label, direct_groups in user_to_groups.items():  # type: ignore[union-attr]
            if not isinstance(direct_groups, list):
                continue
            canonical_user = _canonical_membership_label(domain, user_label)
            if not canonical_user:
                continue
            if exclude_tier0 and canonical_user in tier0_users:
                continue
            _add_to_index(user_group_members, canonical_user, direct_groups)

    if has_computers:
        for computer_label, direct_groups in computer_to_groups.items():  # type: ignore[union-attr]
            if not isinstance(direct_groups, list):
                continue
            canonical_computer = _canonical_membership_label(domain, computer_label)
            if not canonical_computer:
                continue
            _add_to_index(computer_group_members, canonical_computer, direct_groups)

    result = (user_group_members, computer_group_members, has_users or has_computers)
    _GROUP_MEMBER_INDEX_CACHE[cache_key] = result
    return result


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
    new_record["_exact_signature"] = (tuple(new_nodes), tuple(new_rels))
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
    # Use support registry (not a hardcoded list) for policy-blocked relations.
    from adscan_internal.services.attack_step_support_registry import (
        classify_relation_support,
    )

    non_context_actions = [
        str(step.get("action") or "").strip().lower()
        for step in steps
        if isinstance(step, dict)
        and str(step.get("action") or "").strip().lower()
        not in _CONTEXT_RELATIONS_LOWER
    ]
    if any(
        classify_relation_support(action).kind == "policy_blocked"
        for action in non_context_actions
    ):
        return "blocked"
    if any(
        # Live support classification is the single source of truth — surface an
        # ``unsupported`` relation even when the persisted step status still
        # carries the pre-flip default (see CrackNTLMv1).
        classify_relation_support(action).kind == "unsupported"
        for action in non_context_actions
    ):
        return "unsupported"
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
    new_record["_exact_signature"] = (tuple(new_nodes), tuple(new_rels))
    new_record["length"] = sum(
        1
        for rel in new_rels
        if str(rel or "").strip().lower() not in _CONTEXT_RELATIONS_LOWER
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
    group_label_cache: dict[str, str] = {}

    for record in records:
        nodes = record.get("nodes")
        rels = record.get("relations")
        if not isinstance(nodes, list) or not isinstance(rels, list):
            continue
        collapse_leading_memberof = False
        sample_users: list[str] = []
        strip_count = 0
        if rels and rels[0] == "MemberOf" and len(nodes) > 1 and counts:
            raw_group_label = str(nodes[1])
            group_label = group_label_cache.get(raw_group_label)
            if group_label is None:
                group_label = _canonical_membership_label(domain, raw_group_label)
                group_label_cache[raw_group_label] = group_label
            if counts.get(group_label, 0) > 1:
                collapse_leading_memberof = True
                for relation in rels:
                    if relation == "MemberOf":
                        strip_count += 1
                        continue
                    break
                if sample_limit > 0:
                    sample_users = samples.get(group_label, [])

        if collapse_leading_memberof:
            key = (tuple(nodes[strip_count:]), tuple(rels[strip_count:]))
            existing = grouped.get(key)
            if existing and isinstance(existing, dict):
                if sample_users:
                    applies = existing.get("applies_to_users")
                    if isinstance(applies, list):
                        merged = list(dict.fromkeys(applies + sample_users))
                        existing["applies_to_users"] = merged[:sample_limit]
                    else:
                        existing["applies_to_users"] = sample_users[:sample_limit]
                continue

            collapsed_record, _ = _strip_leading_relations(
                record, relations_to_strip={"MemberOf"}
            )
            if sample_users:
                collapsed_record = dict(collapsed_record)
                collapsed_record["applies_to_users"] = sample_users[:sample_limit]
            grouped[key] = collapsed_record
            continue

        key = _record_exact_signature(record)
        if key is None:
            continue
        if key not in grouped:
            grouped[key] = record

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

    user_group_members, computer_group_members, has_principals = (
        build_group_member_index(
            snapshot, domain, exclude_tier0=True, include_computers=True
        )
    )
    if not has_principals:
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

            # Users and computers are tracked separately:
            #   affected_users     — for execution helpers that resolve credentials
            #   affected_computers — for display only (computer accounts have no stored creds)
            affected_users: list[str] = []
            affected_computers: list[str] = []
            if kind == "Group":
                affected_users = sorted(
                    user_group_members.get(canonical_source, set()), key=str.lower
                )
                affected_computers = sorted(
                    computer_group_members.get(canonical_source, set()), key=str.lower
                )
            elif source_label:
                # Individual principal (User or Computer) — single affected entry.
                affected_users = [source_label]

            affected_user_count = len(affected_users)
            affected_computer_count = len(affected_computers)
            affected_principal_count = affected_user_count + affected_computer_count

            if filter_empty and kind == "Group" and affected_principal_count == 0:
                source_sid = label_sid_map.get(canonical_source)
                if not _is_empty_group_whitelisted(domain, source_label, source_sid):
                    stripped = _strip_leading_steps(current, count=1)
                    if stripped is None:
                        break
                    current = stripped
                    continue

            # Only aggregate User/Computer → MemberOf → Group into the group
            # source when the source itself IS a group.  For User or Computer
            # sources the MemberOf represents the attacker's own membership
            # chain (e.g. ms01$ → MemberOf → GroupA → ...) which must be
            # preserved so that the selected principal is not stripped from the
            # display.
            if (
                kind == "Group"
                and rels
                and str(rels[0] or "").strip().lower() == "memberof"
                and len(nodes) > 1
            ):
                group_label = _canonical_membership_label(domain, str(nodes[1]))
                # Check combined user + computer count for the leading-MemberOf
                # collapse heuristic: collapse only when the next group has multiple
                # principals (avoid collapsing single-member groups).
                next_user_count = len(user_group_members.get(group_label, set()))
                next_computer_count = len(
                    computer_group_members.get(group_label, set())
                )
                if next_user_count + next_computer_count > 1:
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
                meta.setdefault("affected_user_count", affected_user_count)
                if affected_computers:
                    meta.setdefault("affected_computers", affected_computers)
                    meta.setdefault("affected_computer_count", affected_computer_count)
                # Combined count used by display layer (Affected column).
                meta.setdefault("affected_principal_count", affected_principal_count)
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
        key = _record_exact_signature(record)
        if key is None:
            continue
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
    scope: str | None = None,
    principal_count: int = 1,
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
    canonical_label_cache: dict[str, str] = {}
    principal_groups_by_label_cache: dict[str, set[str]] = {}
    user_principal_labels = (
        set(user_to_groups.keys()) if isinstance(user_to_groups, dict) else set()
    )
    computer_principal_labels = (
        set(computer_to_groups.keys())
        if isinstance(computer_to_groups, dict)
        else set()
    )

    # Minimal label→node resolver for tier classification inside the redundant-
    # MemberOf minimizer. At minimization time the records are NOT yet stamped
    # with ``target_tier`` (stamp_records_target_tier runs AFTER minimization in
    # the pipeline) and we have no full node index here — but the one signal that
    # drives the strip-to-group decision is whether the terminal IS the Domain
    # object. The terminal Domain node renders with the bare domain FQDN as its
    # label, so synthesize a ``kind="Domain"`` node for that label; everything
    # else resolves to a name-only node (sufficient for relation-driven tiers).
    _domain_fqdn_lower = str(domain or "").strip().lower()

    def _label_to_node(label: str) -> dict[str, Any]:
        bare = str(label or "").strip().lower().split("@", 1)[0]
        if _domain_fqdn_lower and bare == _domain_fqdn_lower:
            return {"name": str(label), "kind": "Domain"}
        return {"name": str(label)}

    def canonical_label(value: str) -> str:
        cached = canonical_label_cache.get(value)
        if cached is not None:
            return cached
        cached = _canonical_membership_label(domain, value)
        canonical_label_cache[value] = cached
        return cached

    def principal_group_closure(principal_label: str) -> set[str]:
        canonical_principal = canonical_label(principal_label)
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

    def principal_group_closure_by_label(principal_label: str) -> set[str]:
        cached = principal_groups_by_label_cache.get(principal_label)
        if cached is not None:
            return cached
        cached = principal_group_closure(principal_label)
        principal_groups_by_label_cache[principal_label] = cached
        return cached

    def is_membership_principal(label: str) -> bool:
        canonical = canonical_label(label)
        return (
            canonical in user_principal_labels or canonical in computer_principal_labels
        )

    # When scope is not explicitly supplied (legacy callers), default to an empty
    # string so that scope-gated minimizations (leading_memberof, domain-only) are
    # NOT applied.  Callers that want domain-scope behaviour must pass scope="domain".
    scope_norm = str(scope or "").strip().lower()
    # leading_memberof collapses USER → MemberOf → GROUP prefixes:
    #   - domain: always (all low-priv users as source → group view is the signal)
    #   - owned / principals: only when multiple users are in scope — with a single
    #     owned user the starting principal IS the point of interest, same as "user"
    #   - user: never (the specific user is the point of interest)
    _apply_leading_memberof = scope_norm == "domain" or (
        scope_norm in {"owned", "principals"} and principal_count > 1
    )
    _active_rules = ["redundant_memberof", "repeated_labels"]
    if _apply_leading_memberof:
        _active_rules.append("leading_memberof")
    print_info_debug(
        f"[bh-minimize] scope={scope_norm!r} principal_count={principal_count}"
        f" → active rules: {', '.join(_active_rules)} | {len(records)} path(s)"
    )
    debug_enabled = _debug_logging_enabled()
    eliminated_debug = SampledDebugLogger(
        prefix="[bh-minimize]",
        summary_label="eliminated (redundant_memberof)",
        enabled=debug_enabled,
    )
    minimized_debug = SampledDebugLogger(
        prefix="[bh-minimize]",
        summary_label="minimized path rewrites",
        enabled=debug_enabled,
    )
    minimized: list[dict[str, Any]] = []
    for record in records:
        orig_nodes = record.get("nodes") or []
        updated = _minimize_display_record_by_redundant_memberof(
            record,
            principal_group_closure_by_label=principal_group_closure_by_label,
            is_membership_principal=is_membership_principal,
            canonical_label=canonical_label,
            label_to_node=_label_to_node,
            # Same scope rule as leading-memberof: a single queried principal IS
            # the point of interest, so its prefix must never be stripped to a
            # group. (domain / multi-principal views keep the strip-to-group.)
            preserve_source=not _apply_leading_memberof,
        )
        if updated is None:
            if debug_enabled:
                orig_path = " → ".join(str(n) for n in orig_nodes)
                eliminated_debug.log(
                    f"[bh-minimize] eliminated (redundant_memberof): {orig_path!r}"
                )
            continue
        updated = _minimize_display_record_by_repeated_labels(updated)
        if _apply_leading_memberof:
            updated = _minimize_display_record_by_leading_memberof(updated)
        final = _recompute_status(updated)
        if debug_enabled and final.get("meta", {}).get("minimized"):
            orig_path = " → ".join(str(n) for n in orig_nodes)
            new_path = " → ".join(str(n) for n in (final.get("nodes") or []))
            reason = final.get("meta", {}).get("minimized_reason", "")
            minimized_debug.log(
                f"[bh-minimize] {orig_path!r} → {new_path!r} (reason={reason})"
            )
        minimized.append(final)
    eliminated_debug.flush()
    minimized_debug.flush()
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
    new_record["_exact_signature"] = (tuple(new_nodes), tuple(new_rels))

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
        1
        for rel in new_rels
        if str(rel or "").strip().lower() not in _CONTEXT_RELATIONS_LOWER
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


# Access/session edges: the attacker gains EXECUTION on a host *as a specific
# principal*, so the accessing principal (the edge source) determines the
# privilege of that access. Re-arriving at a node via one of these from a
# DIFFERENT principal is a privilege change, not a redundant loop. Control/ACL
# edges (GenericAll, GenericWrite, …) are NOT here: re-controlling an
# already-controlled node is redundant regardless of who does it.
_ACCESS_CAPABILITY_RELATIONS: frozenset[str] = frozenset(
    {"canpsremote", "canrdp", "adminto", "sqladmin", "sqlaccess", "executedcom"}
)


def _excise_display_record_loop(
    record: dict[str, Any],
    *,
    first_index: int,
    last_index: int,
    reason: str,
) -> dict[str, Any]:
    """Excise the loop between the first and last occurrence of a repeated node.

    Keeps the ``origin → … → X`` prefix and the ``X → … → end`` suffix, dropping
    only the noisy middle ``X → … → X`` detour. Unlike
    :func:`_strip_display_record_prefix` (which re-roots at the last occurrence
    and loses the scoped origin), this preserves how the attacker reached ``X``
    from the requested principal.
    """
    nodes = record.get("nodes")
    rels = record.get("relations")
    if not isinstance(nodes, list) or not isinstance(rels, list):
        return record
    if not (0 <= first_index < last_index < len(nodes)):
        return record
    if last_index > len(rels):
        return record

    new_nodes = list(nodes[: first_index + 1]) + list(nodes[last_index + 1 :])
    new_rels = list(rels[:first_index]) + list(rels[last_index:])
    if len(new_nodes) < 2 or not new_rels:
        # Would collapse to a single node / no executable steps — keep original.
        return record

    new_record: dict[str, Any] = dict(record)
    new_record["nodes"] = new_nodes
    new_record["relations"] = new_rels
    new_record["_exact_signature"] = (tuple(new_nodes), tuple(new_rels))
    if isinstance(new_record.get("source"), str):
        new_record["source"] = str(new_nodes[0])
    if isinstance(new_record.get("target"), str):
        new_record["target"] = str(new_nodes[-1])

    steps = record.get("steps")
    if isinstance(steps, list):
        kept_steps = [
            s
            for s in (list(steps[:first_index]) + list(steps[last_index:]))
            if isinstance(s, dict)
        ]
        for idx, step in enumerate(kept_steps, start=1):
            step["step"] = idx
        new_record["steps"] = kept_steps

    new_record["length"] = sum(
        1
        for rel in new_rels
        if str(rel or "").strip().lower() not in _CONTEXT_RELATIONS_LOWER
    )
    new_record["status"] = _derive_display_status_from_steps(
        new_record.get("steps", [])
    )

    meta = new_record.get("meta")
    if not isinstance(meta, dict):
        meta = {}
        new_record["meta"] = meta
    meta.setdefault("full_length", record.get("length"))
    meta["minimized"] = True
    meta["minimized_reason"] = reason
    meta["minimized_start_label"] = str(new_nodes[0])
    return new_record


def _minimize_display_record_by_redundant_memberof(
    record: dict[str, Any],
    *,
    principal_group_closure_by_label: Callable[[str], set[str]],
    is_membership_principal: Callable[[str], bool],
    canonical_label: Callable[[str], str],
    label_to_node: Callable[[str], dict[str, Any]] | None = None,
    preserve_source: bool = False,
) -> dict[str, Any] | None:
    """Eliminate display records that contain redundant MemberOf prefix pivots.

    A ``X → MemberOf → G`` edge is considered *redundant* when G was already
    reachable through a prior principal's transitive group membership.  For
    example, in ``USER1 → GenericAll → USER2 → MemberOf → GROUP1 → DCSync``
    where USER1 is already a member of GROUP1, showing USER2's membership hop
    is redundant.  The entire record is dropped (returns ``None``) because
    truncating it to start from GROUP1 would create a duplicate of the shorter
    path that already starts at GROUP1 directly.

    Critical ordering rule: the outgoing edge is checked BEFORE adding the
    current node's groups to ``satisfied_groups``.  This prevents a principal
    from making its *own* outgoing ``MemberOf`` look redundant (which would
    incorrectly strip the selected principal from the display).

    ``preserve_source``: when True (single-principal scopes — ``user`` and a
    single ``owned``/``principals`` query), the queried source principal is the
    point of interest, so the record must NEVER be re-rooted at a group. The
    strip-to-group branch is suppressed and the record is truncated to its
    source-preserving prefix instead. Without this, the strip emits an
    orphan ``GROUP → … → Domain`` path that does not start at the queried
    principal — nonsensical for a "what can <principal> do" query (e.g. a
    ``from khal.drogo`` query returning ``ADMINISTRATORS → DCSync → Domain``).
    """
    nodes = record.get("nodes")
    rels = record.get("relations")
    if not isinstance(nodes, list) or not isinstance(rels, list) or not nodes:
        return record

    _resolve_node = label_to_node or (lambda lbl: {"name": str(lbl)})

    # Tier of the edge ARRIVING at nodes[rel_idx]. The start node has no incoming
    # edge → context floor. classify_target_tier is relation-driven for the cases
    # that matter here (DumpLSA self-cred, access lanes, EdgeKind control/cred
    # fallback); the resolver also flags the Domain terminal so a Domain arrival
    # is classified into the top "domain" lane.
    def _incoming_tier(rel_idx: int) -> TargetTier:
        if rel_idx <= 0:
            return TargetTier(lane="context", level=0)
        return classify_target_tier(
            relation=str(rels[rel_idx - 1]),
            source_node=_resolve_node(str(nodes[rel_idx - 1])),
            target_node=_resolve_node(str(nodes[rel_idx])),
            prior_path_relations=[str(r) for r in rels[: rel_idx - 1]],
        )

    satisfied_groups: set[str] = set()
    seen_principals: set[str] = set()
    redundant_memberof_indices: list[int] = []
    # Per canonical object: the tier of the incoming edge at the point its group
    # closure was first added to ``satisfied_groups``. Used by the
    # tier-monotonicity carve-out (Change A): re-arriving at the same object at a
    # strictly-higher or incomparable tier re-enables its membership hops.
    satisfied_at_tier: dict[str, TargetTier] = {}

    for rel_idx, rel in enumerate(rels):
        if rel_idx >= len(nodes):
            break
        current = str(nodes[rel_idx] or "").strip()
        canonical = canonical_label(current) if current else ""
        is_principal = bool(current) and is_membership_principal(current)

        # CHECK the outgoing edge FIRST, before adding this node's groups.
        # The check-before-add order is critical: it ensures that at rel_idx=0
        # satisfied_groups is still empty when we evaluate the start node's own
        # outgoing MemberOf, so the start node never falsely marks its own direct
        # membership hop as redundant.  All other MemberOf edges at rel_idx > 0
        # are evaluated against groups already accumulated by prior nodes.
        #
        # The redundancy check ONLY applies when the source of the MemberOf is
        # a membership principal (User/Computer). The original anti-pattern is
        # ``USER1 → GenericAll → USER2 → MemberOf → GROUP`` where USER1 is
        # already in GROUP, so showing USER2's hop adds no value. Group→Group
        # MemberOf chains (e.g. ``DA → MemberOf → Administrators``) are pure
        # nested membership topology and are load-bearing in domain-mode kill
        # chains — never flag those as redundant or the rule deletes paths
        # routed deliberately by the priority-membership-suppression filter.
        #
        # TIER-MONOTONICITY CARVE-OUT (Change A — generalizes the old self-loop
        # heuristic): re-arriving at an object whose groups were already satisfied
        # is NOT redundant when arriving at the CURRENT node represents a tier
        # INCREASE on that object since the group was satisfied. The DumpLSA
        # self-loop (session → machine-account credentials) is ONE instance:
        # the post-DumpLSA arrival carries an os/LOCAL_ADMIN self-cred tier that
        # does not dominate-and-is-not-dominated-by the pre-credential arrival, so
        # the first occurrence's group closure no longer masks the second. Any
        # higher-or-incomparable re-arrival tier on the same object qualifies (not
        # only the literal consecutive-identical-label self-loop), so kill-chains
        # like AllowedToDelegate/GenericAll → host → DumpLSA/CanPSRemote → host →
        # MemberOf → host_group → DCSync → Domain are never incorrectly truncated.
        _arrived_at_higher_tier = False
        if canonical and canonical in satisfied_at_tier:
            prior_tier = satisfied_at_tier[canonical]
            current_tier = _incoming_tier(rel_idx)
            # Higher OR incomparable (cross-lane) re-arrival → not dominated by the
            # tier at which the group was satisfied → a genuine tier increase.
            if not tier_dominates(prior_tier, current_tier):
                _arrived_at_higher_tier = True
        if (
            is_principal
            and not _arrived_at_higher_tier
            and str(rel or "").strip().lower() == "memberof"
            and rel_idx + 1 < len(nodes)
        ):
            group_label = canonical_label(str(nodes[rel_idx + 1]))
            if group_label and group_label in satisfied_groups:
                redundant_memberof_indices.append(rel_idx)

        # THEN add this principal's transitive groups so that *subsequent*
        # MemberOf edges later in the path can be checked against them.
        # The start node is included: if an intermediate principal later joins a
        # group the start node already belongs to, that hop is redundant.
        if is_principal and canonical and canonical not in seen_principals:
            seen_principals.add(canonical)
            satisfied_groups.update(principal_group_closure_by_label(current))
            satisfied_at_tier[canonical] = _incoming_tier(rel_idx)

    if not redundant_memberof_indices:
        return record

    # The path contains a redundant MemberOf tail. Instead of eliminating the
    # entire record, TRUNCATE it at the first redundant hop. This preserves
    # the non-redundant prefix — e.g. "USER1 → ForceChangePassword → USER2 →
    # MemberOf → Group[redundant]" becomes "USER1 → ForceChangePassword → USER2",
    # which is a valuable attack step that would otherwise be silently dropped.
    #
    # Original rationale for full elimination: "truncating to GROUP1 creates a
    # duplicate of the shorter path that already starts at GROUP1 directly." But
    # that argument only applies when the terminal is a GROUP continuation, not
    # when the truncation terminal is a USER being targeted by a control edge.
    # The dedup stage (step 4 of the post-processing pipeline) handles any
    # duplicates produced by truncation.
    first_redundant = redundant_memberof_indices[0]
    if first_redundant == 0:
        # Entire path starts with a redundant hop — no valuable prefix to keep.
        return None

    # DECIDE HOW TO MINIMIZE (Change B — tier-aware):
    #
    #   ... → SRC →MemberOf(redundant)→ GROUP → <tail> → <terminal>
    #          ^prefix terminal (nodes[first_redundant])     ^full terminal
    #
    # The historic behavior TRUNCATES-TO-PREFIX: keep nodes[:first_redundant+1]
    # and drop the tail. That is correct ONLY when the prefix terminal already
    # dominates whatever the tail reaches — otherwise it DROPS a strictly-higher
    # (or incomparable) terminal, the canonical case being a tail that reaches
    # ``DCSync → Domain`` (lane "domain") while the prefix terminal is a plain
    # user/object. To preserve that higher-tier terminal we instead STRIP-TO-GROUP:
    # re-root the record at the satisfied GROUP (``nodes[first_redundant + 1]``),
    # keeping ``GROUP → <tail> → <higher-tier terminal>`` and relying on the
    # downstream dedup stage to fold any duplicate group-rooted path.
    _l2n = {
        str(label): _resolve_node(str(label))
        for label in nodes
        if isinstance(label, str) or label is not None
    }
    # F5: use the 4-tier domain-compromise total order (T4 Domain object > T3
    # direct-breaker group > T2 enabler > T1 host) for the strip-to-group decision
    # so the Domain object out-tiers a direct-breaker group consistently with the
    # prefix/contained filters — the lane-based ``tier_dominates`` treated both as
    # cross-lane-incomparable and could mis-decide object-vs-group. The tail
    # out-tiers the prefix when its domain-compromise tier is strictly higher.
    prefix_subrecord = {
        "nodes": list(nodes)[: first_redundant + 1],
        "relations": list(rels)[:first_redundant],
    }
    full_dct = record_domain_compromise_tier(record, label_to_node=_l2n)
    prefix_dct = record_domain_compromise_tier(prefix_subrecord, label_to_node=_l2n)
    tail_out_tiers_prefix = full_dct > prefix_dct

    # In single-principal scopes the queried source is fixed and must be kept:
    # never re-root at a group (which would orphan the source). Truncate to the
    # source-preserving prefix instead — the higher-tier tail is reachable in the
    # holistic domain-scope view, not in a "what can <this principal> do" query.
    if tail_out_tiers_prefix and not preserve_source:
        # STRIP-TO-GROUP: re-root at the satisfied group, preserving the tail and
        # its higher-tier terminal (e.g. DCSync → Domain).
        group_index = first_redundant + 1
        if group_index >= len(nodes) - 1 or group_index > len(rels):
            # No actionable tail beyond the group — nothing to preserve.
            return None
        stripped = dict(record)
        stripped_nodes = list(nodes)[group_index:]
        stripped_rels = list(rels)[group_index:]
        if len(stripped_nodes) < 2 or not stripped_rels:
            return None
        stripped["nodes"] = stripped_nodes
        stripped["relations"] = stripped_rels
        stripped["_exact_signature"] = (
            _string_tuple([str(n) for n in stripped_nodes]),
            _string_tuple([str(r) for r in stripped_rels]),
        )
        if "length" in stripped:
            stripped["length"] = sum(
                1
                for rel in stripped_rels
                if str(rel or "").strip().lower() not in _CONTEXT_RELATIONS_LOWER
            )
        if "source" in stripped:
            stripped["source"] = str(stripped_nodes[0])
        if "target" in stripped:
            stripped["target"] = str(stripped_nodes[-1])
        orig_steps = record.get("steps")
        if isinstance(orig_steps, list) and orig_steps:
            stripped_steps = [dict(s) for s in orig_steps[group_index:] if isinstance(s, dict)]
            for i, s in enumerate(stripped_steps, start=1):
                s["step"] = i
            stripped["steps"] = stripped_steps
        else:
            stripped["steps"] = [
                {
                    "step": i + 1,
                    "action": str(stripped_rels[i]),
                    "from": str(stripped_nodes[i]),
                    "to": str(stripped_nodes[i + 1]),
                    "status": record.get("status", "theoretical"),
                }
                for i in range(len(stripped_rels))
                if i + 1 < len(stripped_nodes)
            ]
        _meta = stripped.get("meta")
        if not isinstance(_meta, dict):
            _meta = {}
            stripped["meta"] = _meta
        _meta.setdefault("full_length", record.get("length"))
        _meta["minimized"] = True
        _meta["minimized_reason"] = "strip_to_group_redundant_memberof"
        _meta["minimized_start_label"] = str(stripped_nodes[0])
        return stripped

    # ELSE: the prefix terminal dominates the tail — no higher-tier terminal at
    # risk. Keep the historic TRUNCATE-TO-PREFIX behavior: keep nodes up to the
    # principal BEFORE the redundant MemberOf, drop everything from the redundant
    # index onwards. This preserves the non-redundant prefix — e.g. "USER1 →
    # ForceChangePassword → USER2 → MemberOf → Group[redundant]" becomes "USER1 →
    # ForceChangePassword → USER2", a valuable step otherwise silently dropped.
    # The dedup stage handles any duplicates produced by truncation.
    truncated_nodes = list(nodes)[: first_redundant + 1]
    truncated_rels = list(rels)[:first_redundant]

    if not truncated_rels:
        # Nothing actionable in the truncated path.
        return None

    truncated = dict(record)
    truncated["nodes"] = truncated_nodes
    truncated["relations"] = truncated_rels
    truncated["_exact_signature"] = (
        _string_tuple([str(n) for n in truncated_nodes]),
        _string_tuple([str(r) for r in truncated_rels]),
    )
    if "length" in truncated:
        truncated["length"] = sum(
            1
            for rel in truncated_rels
            if str(rel or "").strip().lower() not in _CONTEXT_RELATIONS_LOWER
        )
    # Preserve source/target: source stays the same, target is now the node
    # just before the first redundant hop.
    if "target" in truncated and len(truncated_nodes) > 1:
        truncated["target"] = truncated_nodes[-1]
    # Slice steps to match the truncated relations so the execution router
    # has the correct step list.  If there are no original steps, build
    # minimal ones from nodes+relations so the router can proceed.
    orig_steps = record.get("steps")
    if isinstance(orig_steps, list) and orig_steps:
        truncated_steps = list(orig_steps)[:first_redundant]
        # Re-number steps sequentially after slicing.
        for i, s in enumerate(truncated_steps, start=1):
            if isinstance(s, dict):
                s = dict(s)
                s["step"] = i
                truncated_steps[i - 1] = s
        truncated["steps"] = truncated_steps
    else:
        # Build minimal step dicts from the truncated nodes/relations.
        truncated["steps"] = [
            {
                "step": i + 1,
                "action": str(truncated_rels[i]),
                "from": str(truncated_nodes[i]),
                "to": str(truncated_nodes[i + 1]),
                "status": record.get("status", "theoretical"),
            }
            for i in range(len(truncated_rels))
            if i + 1 < len(truncated_nodes)
        ]
    _meta = truncated.get("meta")
    if not isinstance(_meta, dict):
        _meta = {}
        truncated["meta"] = _meta
    _meta.setdefault("full_length", record.get("length"))
    _meta["minimized"] = True
    _meta["minimized_reason"] = "truncate_redundant_memberof"
    _meta["minimized_start_label"] = str(truncated_nodes[0])
    return truncated


def _minimize_display_record_by_repeated_labels(
    record: dict[str, Any],
) -> dict[str, Any]:
    nodes = record.get("nodes")
    rels = record.get("relations")
    if not isinstance(nodes, list) or not isinstance(rels, list) or len(nodes) <= 1:
        return record

    lowered_nodes = [str(node or "").strip().lower() for node in nodes]
    if len(lowered_nodes) == len(set(lowered_nodes)):
        return record

    # Self-loop transparency: a self-loop step (from == to — the DumpLSA /
    # DumpLSASS / DumpDPAPI in-place overlays) renders as two CONSECUTIVE
    # identical node labels (``X → DumpLSA → X``). The only way two adjacent
    # node labels are equal is a self-loop, and a self-loop is an in-place
    # context upgrade, NOT a loop back to an already-visited node. It must not
    # count as a repeat — otherwise a legitimate chain like
    #   adscan → … → ReadLAPSPassword → BRAAVOS$ → DumpLSA → BRAAVOS$ → ADCSESC7 → DA
    # is stripped to ``BRAAVOS$ → ADCSESC7 → DA`` and wrongly re-sourced at the
    # computer. Collapse consecutive-identical runs, detect genuine (non-adjacent)
    # repeats on that view, then map the strip point back to the original index.
    collapsed_to_original: list[int] = []
    for idx, label in enumerate(lowered_nodes):
        if collapsed_to_original and lowered_nodes[collapsed_to_original[-1]] == label:
            collapsed_to_original[-1] = idx  # extend the self-loop run; keep its last index
        else:
            collapsed_to_original.append(idx)
    collapsed_labels = [lowered_nodes[i] for i in collapsed_to_original]
    if len(collapsed_labels) == len(set(collapsed_labels)):
        # Every repetition was a self-loop run — no genuine loop to minimize.
        return record

    last_seen: dict[str, int] = {}
    for cpos, label in enumerate(collapsed_labels):
        if not label:
            continue
        last_seen[label] = cpos

    # Find the latest collapsed position that repeats some earlier label.
    start_cpos = 0
    for cpos, label in enumerate(collapsed_labels):
        if not label:
            continue
        last_cpos = last_seen.get(label, cpos)
        if last_cpos > cpos:
            start_cpos = max(start_cpos, last_cpos)

    if start_cpos <= 0:
        return record

    # The genuine repeat to collapse is the label at ``start_cpos``. Find its
    # first and last ORIGINAL occurrence.
    repeated_label = collapsed_labels[start_cpos]
    orig_positions = [i for i, lbl in enumerate(lowered_nodes) if lbl == repeated_label]
    first_index = orig_positions[0]
    last_index = orig_positions[-1]
    if first_index >= last_index:
        return record

    # Context-aware guard: a re-arrival at the repeated node via an ACCESS edge
    # (CanPSRemote / CanRDP / AdminTo / SQLAdmin …) from a DIFFERENT principal is
    # a privilege change (e.g. ``BRAAVOS$`` as the user vs. as a dumped admin),
    # NOT a redundant loop — keep the path whole. Control edges (GenericAll, …)
    # are always collapsible: re-controlling an already-controlled node is
    # redundant regardless of which principal does it.
    incoming_rel = (
        str(rels[last_index - 1] or "").strip().lower() if last_index >= 1 else ""
    )
    accessor_last = lowered_nodes[last_index - 1] if last_index >= 1 else ""
    accessor_first = lowered_nodes[first_index - 1] if first_index >= 1 else ""
    if (
        incoming_rel in _ACCESS_CAPABILITY_RELATIONS
        and accessor_last
        and accessor_last != accessor_first
    ):
        return record

    # Excise the middle loop, preserving the scoped origin → X prefix.
    return _excise_display_record_loop(
        record,
        first_index=first_index,
        last_index=last_index,
        reason="repeated_node_label",
    )


def _minimize_display_record_by_leading_memberof(
    record: dict[str, Any],
) -> dict[str, Any]:
    """Strip a leading ``X → MemberOf → GROUP`` prefix (domain scope only).

    When the very first relationship in a path is MemberOf, the path starts
    with a principal's own group membership pivot.  In domain-wide scope all
    members of that group share this path, so stripping the leading principal
    produces a cleaner group-level display::

        ADSCAN → MemberOf → DOMAIN USERS → ADCSESC3 → TARGET
        → DOMAIN USERS → ADCSESC3 → TARGET

    This is intentionally restricted to cases where ``rels[0] == "MemberOf"``
    so that mid-path pivots like ``ATTACKER → GenericAll → USER2 → MemberOf →
    GROUP → ATTACK`` (where GenericAll is rels[0]) are unaffected.
    """
    nodes = record.get("nodes")
    rels = record.get("relations")
    if (
        isinstance(nodes, list)
        and isinstance(rels, list)
        and rels
        and len(nodes) >= 3
        and str(rels[0] or "").strip().lower() == "memberof"
    ):
        return _strip_display_record_prefix(
            record, start_node_index=1, reason="leading_memberof"
        )
    return record


def filter_shortest_paths_for_principals(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep one representative record per terminal triple PER COMPARABLE TIER LANE.

    Tier-aware de-dup (F3). The group key is the terminal triple
    ``(terminal_from, terminal_rel, terminal_to)`` combined with the tier lane
    (``comparability_key``). Records that are tier-INCOMPARABLE for the same
    terminal triple (different lanes — e.g. os/admin vs mssql) therefore land in
    SEPARATE groups and BOTH survive. WITHIN a group (same triple + same lane) the
    tier-DOMINANT record is kept (``tier_dominates``); ties (equal tier) break by
    min ``length`` — the original tier-blind behavior. A higher-tier record always
    wins over a shorter lower-tier one in the same lane, so a stronger standing on
    a terminal is never shadowed by a shorter weaker path to it.
    """
    if len(records) <= 1:
        return records

    # Per group: (best_length, best_idx, best_tier). best_tier is the tier of the
    # currently-kept record, used to decide tier dominance against challengers.
    best_by_key: dict[tuple[str, str, str, tuple[str, ...]], tuple[int, int, TargetTier]] = {}
    for idx, record in enumerate(records):
        nodes = record.get("nodes")
        rels = record.get("relations")
        if not isinstance(nodes, list) or not isinstance(rels, list) or not nodes:
            continue
        terminal_rel = ""
        terminal_idx = None
        for rel_idx in range(len(rels) - 1, -1, -1):
            if str(rels[rel_idx] or "").strip().lower() in _CONTEXT_RELATIONS_LOWER:
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
                1
                for rel in rels
                if str(rel or "").strip().lower() not in _CONTEXT_RELATIONS_LOWER
            )
        # Precondition: stamp_records_target_tier() must have been called on this
        # list (both compute_display_paths_for_* callers do, immediately before
        # this filter). The fallback in target_tier_from_record lacks
        # label_to_node and degrades domain-node classification to name-only
        # heuristics, which could mis-key a domain terminal into the wrong lane.
        tier = target_tier_from_record(record)
        key = (terminal_from, terminal_rel, terminal_to, comparability_key(tier))
        existing = best_by_key.get(key)
        if existing is None:
            best_by_key[key] = (length, idx, tier)
            continue
        existing_length, _existing_idx, existing_tier = existing
        # Same triple + same lane → comparable. Keep the strictly tier-dominant
        # record; on equal tier fall back to the original min-length tie-break.
        challenger_dominates = tier_dominates(tier, existing_tier)
        incumbent_dominates = tier_dominates(existing_tier, tier)
        if challenger_dominates and not incumbent_dominates:
            best_by_key[key] = (length, idx, tier)
        elif incumbent_dominates and not challenger_dominates:
            continue  # incumbent strictly stronger — keep it regardless of length
        elif length < existing_length:
            # Equal tier (mutual dominance) — original behavior: shortest wins.
            best_by_key[key] = (length, idx, tier)

    if not best_by_key:
        return records

    keep_indices = {idx for _, idx, _ in best_by_key.values()}
    return [record for idx, record in enumerate(records) if idx in keep_indices]


def _inject_memberof_edges_from_snapshot(
    runtime_graph: dict[str, Any],
    domain: str,
    snapshot: dict[str, Any] | None,
    *,
    principal_node_ids: set[str],
    recursive: bool,
    node_id_by_label: dict[str, str] | None = None,
    recursive_groups_by_principal: dict[str, tuple[str, ...]] | None = None,
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
    resolved_node_id_by_label = (
        node_id_by_label
        or _build_node_id_index_by_canonical_label(
            runtime_graph,
            domain=domain,
        )
    )

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
        cached_recursive_groups = (
            recursive_groups_by_principal.get(label, ())
            if recursive and recursive_groups_by_principal
            else ()
        )
        if cached_recursive_groups:
            group_labels.update(cached_recursive_groups)
        else:
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
            gid = _ensure_group_node_id(
                runtime_graph,
                domain=domain,
                label=group_label,
                node_id_by_label=resolved_node_id_by_label,
            )
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


def _build_attack_potential_node_ids(
    graph: dict[str, Any],
    *,
    domain: str | None = None,
    snapshot: dict[str, Any] | None = None,
) -> set[str]:
    """Return the set of node_ids that have at least one non-context outgoing edge.

    Used to pre-filter principals before running the DFS: any principal whose
    node_id is NOT in this set can never produce an attack path, so the DFS
    call (and the entire post-processing pipeline) can be skipped entirely.

    When a membership snapshot is available, principals with direct snapshot
    group memberships are also considered attack-capable because the runtime
    pipeline may inject ``MemberOf`` edges for them before DFS execution.

    Cost: O(E) single pass over edges plus an optional O(V) snapshot-aware pass
    over graph nodes — computed once per principals batch.
    """
    result: set[str] = set()
    context_reverse: dict[str, set[str]] = {}
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or "").strip().lower()
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if relation in _CONTEXT_RELATIONS_LOWER:
            if from_id and to_id:
                context_reverse.setdefault(to_id, set()).add(from_id)
            continue
        if from_id:
            result.add(from_id)

    if result and context_reverse:
        stack = list(result)
        while stack:
            target_id = stack.pop()
            for source_id in context_reverse.get(target_id, ()):
                if source_id in result:
                    continue
                result.add(source_id)
                stack.append(source_id)

    if not snapshot or not domain:
        return result

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return result

    user_to_groups = snapshot.get("user_to_groups")
    computer_to_groups = snapshot.get("computer_to_groups")
    if not isinstance(user_to_groups, dict) and not isinstance(
        computer_to_groups, dict
    ):
        return result

    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        kind = _node_kind(node)
        if kind not in {"User", "Computer"}:
            continue
        canonical_label = _canonical_membership_label(
            domain,
            _canonical_node_label(node),
        )
        if not canonical_label:
            continue
        direct_groups: list[str] = []
        if kind == "User" and isinstance(user_to_groups, dict):
            direct_groups = user_to_groups.get(canonical_label, []) or []
        elif kind == "Computer" and isinstance(computer_to_groups, dict):
            direct_groups = computer_to_groups.get(canonical_label, []) or []
        if isinstance(direct_groups, list) and direct_groups:
            result.add(str(node_id))
    return result


def compute_display_paths_for_domain(
    graph: dict[str, Any],
    *,
    domain: str,
    snapshot: dict[str, Any] | None,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "object",
    expand_terminal_memberships: bool = True,
    start_node_ids: set[str] | None = None,
    materialized_artifacts: dict[str, Any] | None = None,
    keep_longest: bool = False,
) -> list[dict[str, Any]]:
    pipeline_started_at = time.monotonic()
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
        and not _graph_has_materialized_terminal_memberships(runtime_graph)
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
            node_id_by_label=(
                materialized_artifacts.get("node_id_by_label")
                if isinstance(materialized_artifacts, dict)
                else None
            ),
            recursive_groups_by_principal=(
                materialized_artifacts.get("recursive_groups_by_principal")
                if isinstance(materialized_artifacts, dict)
                else None
            ),
        )

    mode = attack_graph_core.normalize_target_mode(target_mode)
    # Layer 3: node-ids of the collapse choke points (>1-member MemberOf target
    # groups) for the choke-point-rooted DFS.  Built from the SAME counts index
    # and SAME canonical label that ``collapse_memberof_prefixes`` uses below, so
    # the DFS suppresses exactly the leading-MemberOf prefixes the collapse would
    # strip — byte-identical output, the duplicates simply never generated.
    chokepoint_group_ids: set[str] | None = None
    _chokepoint_counts, _ = build_group_membership_index(
        snapshot, domain, principal_labels=None, sample_limit=0
    )
    if _chokepoint_counts:
        chokepoint_group_ids = set()
        for nid, node in (runtime_graph.get("nodes") or {}).items():
            if not isinstance(node, dict):
                continue
            clabel = _canonical_membership_label(domain, str(node.get("label") or nid))
            if clabel and _chokepoint_counts.get(clabel, 0) > 1:
                chokepoint_group_ids.add(str(nid))
    unfiltered_started_at = time.monotonic()
    unfiltered = attack_graph_core.compute_display_paths_for_domain_unfiltered(
        runtime_graph,
        max_depth=max_depth,
        max_paths=max_paths,
        target=target,
        target_mode=mode,
        start_node_ids=start_node_ids,
        chokepoint_group_ids=chokepoint_group_ids,
    )
    _log_phase_timing(
        scope="domain",
        phase="compute_display_paths_for_domain_unfiltered",
        started_at=unfiltered_started_at,
        records=unfiltered,
    )
    collapsed_started_at = time.monotonic()
    collapsed = collapse_memberof_prefixes(
        unfiltered,
        domain,
        snapshot,
        principal_labels=None,
        sample_limit=0,
    )
    _log_phase_timing(
        scope="domain",
        phase="collapse_memberof_prefixes",
        started_at=collapsed_started_at,
        records=collapsed,
    )
    minimized_started_at = time.monotonic()
    minimized = minimize_display_paths(collapsed, domain=domain, snapshot=snapshot)
    _log_phase_timing(
        scope="domain",
        phase="minimize_display_paths",
        started_at=minimized_started_at,
        records=minimized,
    )
    annotated_started_at = time.monotonic()
    annotated = apply_affected_user_metadata(
        minimized,
        graph=runtime_graph,
        domain=domain,
        snapshot=snapshot,
        filter_empty=True,
    )
    _log_phase_timing(
        scope="domain",
        phase="apply_affected_user_metadata",
        started_at=annotated_started_at,
        records=annotated,
    )
    deduped_started_at = time.monotonic()
    deduped = dedupe_exact_display_paths(annotated)
    _log_phase_timing(
        scope="domain",
        phase="dedupe_exact_display_paths",
        started_at=deduped_started_at,
        records=deduped,
    )
    filtered_started_at = time.monotonic()
    # Domain scope returns the shortest HV-aware route to domain compromise by
    # default (most direct kill chain) via the shared single-source-of-truth helper;
    # keep_longest=True reverts to the legacy holistic longest view.
    # label_to_node keyed by label only — matches path_to_display_record's label()
    # and the principals pipeline's stamping (so tier classification is consistent).
    _l2n = {
        str(n.get("label") or nid): n
        for nid, n in (runtime_graph.get("nodes") or {}).items()
        if isinstance(n, dict)
    }
    filtered, _ = attack_graph_core.filter_domain_listing_paths(
        deduped, label_to_node=_l2n, keep_longest=keep_longest
    )
    _log_phase_timing(
        scope="domain",
        phase="filter_contained_paths_for_domain_listing",
        started_at=filtered_started_at,
        records=filtered,
    )
    _log_phase_timing(
        scope="domain",
        phase="total_pipeline",
        started_at=pipeline_started_at,
        records=filtered,
    )
    return filtered


def compute_display_paths_for_start_node(
    graph: dict[str, Any],
    *,
    domain: str,
    snapshot: dict[str, Any] | None,
    start_node_id: str,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "object",
    expand_start_memberships: bool = True,
    expand_terminal_memberships: bool = True,
    filter_shortest_paths: bool = True,
    materialized_artifacts: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    pipeline_started_at = time.monotonic()
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
                    node_id_by_label=(
                        materialized_artifacts.get("node_id_by_label")
                        if isinstance(materialized_artifacts, dict)
                        else None
                    ),
                )
        else:
            _inject_memberof_edges_from_snapshot(
                runtime_graph,
                domain,
                snapshot,
                principal_node_ids={start_node_id},
                recursive=True,
                node_id_by_label=(
                    materialized_artifacts.get("node_id_by_label")
                    if isinstance(materialized_artifacts, dict)
                    else None
                ),
                recursive_groups_by_principal=(
                    materialized_artifacts.get("recursive_groups_by_principal")
                    if isinstance(materialized_artifacts, dict)
                    else None
                ),
            )

    if (
        expand_terminal_memberships
        and snapshot
        and not has_persisted
        and not _graph_has_materialized_terminal_memberships(runtime_graph)
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
            node_id_by_label=(
                materialized_artifacts.get("node_id_by_label")
                if isinstance(materialized_artifacts, dict)
                else None
            ),
            recursive_groups_by_principal=(
                materialized_artifacts.get("recursive_groups_by_principal")
                if isinstance(materialized_artifacts, dict)
                else None
            ),
        )

    mode = attack_graph_core.normalize_target_mode(target_mode)
    raw_started_at = time.monotonic()
    records = attack_graph_core.compute_display_paths_for_start_node(
        runtime_graph,
        start_node_id=start_node_id,
        max_depth=max_depth,
        max_paths=max_paths,
        target=target,
        target_mode=mode,
    )
    _log_phase_timing(
        scope="start_node",
        phase="compute_display_paths_for_start_node",
        started_at=raw_started_at,
        records=records,
    )

    _debug_paths_checkpoint(f"raw paths start_node_id={start_node_id}", records)
    minimized_started_at = time.monotonic()
    minimized_records = minimize_display_paths(
        records, domain=domain, snapshot=snapshot
    )
    _log_phase_timing(
        scope="start_node",
        phase="minimize_display_paths",
        started_at=minimized_started_at,
        records=minimized_records,
    )
    _debug_paths_checkpoint("after minimize_display_paths", minimized_records)
    annotated_started_at = time.monotonic()
    annotated = apply_affected_user_metadata(
        minimized_records,
        graph=runtime_graph,
        domain=domain,
        snapshot=snapshot,
        filter_empty=True,
    )
    _log_phase_timing(
        scope="start_node",
        phase="apply_affected_user_metadata",
        started_at=annotated_started_at,
        records=annotated,
    )
    _debug_paths_checkpoint("after apply_affected_user_metadata", annotated)
    if filter_shortest_paths:
        # Stamp per-record tier so the shortest-path filter is tier-aware.
        # Key by label only — must match path_to_display_record's label() and _build_snapshot_label_to_node.
        _l2n = {
            str(n.get("label") or nid): n
            for nid, n in (runtime_graph.get("nodes") or {}).items()
            if isinstance(n, dict)
        }
        stamp_records_target_tier(annotated, label_to_node=_l2n)
        filtered_started_at = time.monotonic()
        filtered = filter_shortest_paths_for_principals(annotated)
        _log_phase_timing(
            scope="start_node",
            phase="filter_shortest_paths_for_principals",
            started_at=filtered_started_at,
            records=filtered,
        )
        _log_phase_timing(
            scope="start_node",
            phase="total_pipeline",
            started_at=pipeline_started_at,
            records=filtered,
        )
        _debug_paths_checkpoint("after filter_shortest_paths_for_principals", filtered)
        return filtered
    _log_phase_timing(
        scope="start_node",
        phase="total_pipeline",
        started_at=pipeline_started_at,
        records=annotated,
    )
    return annotated


def compute_display_paths_for_user(
    graph: dict[str, Any],
    *,
    domain: str,
    snapshot: dict[str, Any] | None,
    username: str,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "object",
    filter_shortest_paths: bool = True,
    materialized_artifacts: dict[str, Any] | None = None,
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
        max_paths=max_paths,
        target=target,
        target_mode=target_mode,
        filter_shortest_paths=filter_shortest_paths,
        materialized_artifacts=materialized_artifacts,
    )


def compute_display_paths_for_principals(
    graph: dict[str, Any],
    *,
    domain: str,
    snapshot: dict[str, Any] | None,
    principals: list[str],
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    membership_sample_max: int = 3,
    target_mode: str = "object",
    filter_shortest_paths: bool = True,
) -> list[dict[str, Any]]:
    pipeline_started_at = time.monotonic()
    normalized_principals = [str(p or "").strip().lower() for p in principals]
    normalized_principals = [p for p in normalized_principals if p]
    if not normalized_principals:
        return []

    # --- Pre-filter: skip principals with no attack-relevant outgoing edges --
    # Build once O(E), then filter the principal list in O(P) before any DFS.
    attack_potential_ids = _build_attack_potential_node_ids(
        graph,
        domain=domain,
        snapshot=snapshot,
    )
    principals_with_potential = []
    for username in normalized_principals:
        node_id = _find_node_id_by_label(graph, username)
        if node_id and node_id in attack_potential_ids:
            principals_with_potential.append(username)
    skipped = len(normalized_principals) - len(principals_with_potential)
    if skipped:
        print_info_debug(
            f"[principals-dfs] pre-filter: skipped {skipped}/{len(normalized_principals)} "
            f"principals with no attack-relevant outgoing edges"
        )
    if not principals_with_potential:
        return []
    normalized_principals = principals_with_potential

    # --- Parallel principals DFS ---------------------------------------------
    # When ADSCAN_ATTACK_PATH_WORKERS != 0 and there are enough principals,
    # dispatch each principal's DFS to a separate worker process.  The graph
    # and snapshot are sent via the pool initializer (once per worker).
    # max_paths budget is not enforced per-principal in parallel mode (the
    # global cap is approximate); the post-processing pipeline handles it.
    all_records: list[dict[str, Any]] = []
    n_workers = _effective_principal_workers(len(normalized_principals))
    if n_workers >= 2:
        print_info_debug(
            f"[principals-dfs] parallel: {n_workers} workers / {len(normalized_principals)} principals"
        )
        parallel_result = _run_parallel_principals(
            normalized_principals,
            graph,
            domain,
            snapshot,
            max_depth,
            max_paths,
            target,
            target_mode,
            filter_shortest_paths,
            n_workers,
        )
        if parallel_result is not None:
            all_records = parallel_result
        else:
            print_info_debug(
                "[principals-dfs] parallel failed, falling back to sequential"
            )
            n_workers = 0  # fall through to sequential

    if n_workers < 2:
        # --- Sequential DFS (default / fallback) ----------------------------
        for username in normalized_principals:
            remaining = None
            if isinstance(max_paths, int) and max_paths > 0:
                remaining = max_paths - len(all_records)
                if remaining <= 0:
                    break
            records = compute_display_paths_for_user(
                graph,
                domain=domain,
                snapshot=snapshot,
                username=username,
                max_depth=max_depth,
                max_paths=remaining,
                target=target,
                target_mode=target_mode,
                filter_shortest_paths=filter_shortest_paths,
            )
            all_records.extend(records)

    raw_started_at = pipeline_started_at
    _log_phase_timing(
        scope="principals",
        phase="compute_display_paths_for_principals_raw",
        started_at=raw_started_at,
        records=all_records,
    )
    collapsed_started_at = time.monotonic()
    collapsed_records = collapse_memberof_prefixes(
        all_records,
        domain,
        snapshot,
        principal_labels=normalized_principals,
        sample_limit=membership_sample_max,
    )
    _log_phase_timing(
        scope="principals",
        phase="collapse_memberof_prefixes",
        started_at=collapsed_started_at,
        records=collapsed_records,
    )
    minimized_started_at = time.monotonic()
    minimized = minimize_display_paths(
        collapsed_records, domain=domain, snapshot=snapshot
    )
    _log_phase_timing(
        scope="principals",
        phase="minimize_display_paths",
        started_at=minimized_started_at,
        records=minimized,
    )
    annotated_started_at = time.monotonic()
    annotated = apply_affected_user_metadata(
        minimized,
        graph=graph,
        domain=domain,
        snapshot=snapshot,
        filter_empty=True,
    )
    _log_phase_timing(
        scope="principals",
        phase="apply_affected_user_metadata",
        started_at=annotated_started_at,
        records=annotated,
    )
    if filter_shortest_paths:
        # Stamp per-record tier so the shortest-path filter is tier-aware.
        # Key by label only — must match path_to_display_record's label() and _build_snapshot_label_to_node.
        _l2n = {
            str(n.get("label") or nid): n
            for nid, n in (graph.get("nodes") or {}).items()
            if isinstance(n, dict)
        }
        stamp_records_target_tier(annotated, label_to_node=_l2n)
        filtered_started_at = time.monotonic()
        filtered = filter_shortest_paths_for_principals(annotated)
        _log_phase_timing(
            scope="principals",
            phase="filter_shortest_paths_for_principals",
            started_at=filtered_started_at,
            records=filtered,
        )
        _log_phase_timing(
            scope="principals",
            phase="total_pipeline",
            started_at=pipeline_started_at,
            records=filtered,
        )
        return filtered
    _log_phase_timing(
        scope="principals",
        phase="total_pipeline",
        started_at=pipeline_started_at,
        records=annotated,
    )
    return annotated
