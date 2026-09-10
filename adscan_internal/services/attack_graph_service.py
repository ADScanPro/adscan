from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator, Mapping, cast

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_warning,
    print_warning_debug,
    print_error,
    print_exception,
    print_attack_paths_summary_debug,
)
from adscan_core.rich_output import strip_sensitive_markers
from adscan_internal.workspaces import (
    domain_subpath,
    read_json_file,
    resolve_workspace_cwd,
    write_json_file,
)
from adscan_internal.workspaces.computers import load_enabled_computer_samaccounts

from adscan_internal.services import attack_graph_core, attack_paths_core
from adscan_internal.services import attack_path_progress
from adscan_internal.services.attack_path_explosion_predictor import predicts_explosion

# The budget-exceeded signal now lives in the pure-logic gate module so BOTH this
# service layer (which catches it) and ``attack_graph_core`` (the in-DFS bound,
# which imports from ``adscan_core`` but never from this module) raise the SAME
# class. Re-exported here under its original name so this module's existing callers
# (and any consumer catching it via this module) are unchanged.
from adscan_core.reporting.attack_path_memory_gate import (
    _AttackPathMemoryBudgetExceeded,
)
from adscan_internal.services.attack_graph_findings import sync_attack_graph_findings
from adscan_internal.services.privileged_group_classifier import (
    classify_privileged_membership,
    is_dependency_only_tier_zero_group,
    is_followup_terminal_group,
    is_future_followup_tier_zero_group,
    is_graph_extension_group,
    normalize_group_name,
    normalize_sid,
    sid_rid,
    privileged_followup_order_for_group_name,
    resolve_privileged_followup_decision,
)
from adscan_internal.services.attack_paths_materialized_cache import (
    MaterializedAttackPathArtifacts,
    MaterializedPreparedRuntimeGraph,
    build_attack_path_artifact_fingerprint,
    invalidate_attack_path_artifacts,
    load_disk_cached_attack_path_results,
    load_materialized_attack_path_artifacts,
    load_materialized_prepared_runtime_graph,
    persist_attack_path_results_to_disk,
    persist_materialized_attack_path_artifacts,
    persist_materialized_prepared_runtime_graph,
    unlink_attack_path_results_for_domain,
)
from adscan_internal.services.attack_step_support_registry import (
    CONTEXT_ONLY_RELATIONS,
    RelationSupport,
    classify_relation_support,
)
from adscan_internal.services.attack_step_catalog import (
    build_step_knowledge,
    classify_edge_relation,
    derive_step_display_status,
    get_exploitation_relation_vuln_keys,
    normalize_execution_relation,
)
from adscan_internal.services.attack_graph_node_identity import (
    describe_resolution_failure as describe_node_resolution_failure,
    resolve_node_candidates as resolve_graph_node_candidates,
)
from adscan_internal.services.path_state import (
    _PROVEN_STATUSES as _PROVEN_EDGE_STATUSES,
)
from adscan_internal.services.domain_controller_classifier import node_is_rodc_computer
from adscan_internal.services.edge_kind import classify_edge_kind
from adscan_internal.services.compromise_class import (
    PrivilegeTier,
    apply_path_based_classification,
    is_structural_hierarchy_source,
    privilege_tier_for_node,
    privilege_tier_for_principal,
)
from adscan_internal.services.tier_descent_prune import apply_tier_descent_prune
from adscan_internal.services.tier_lattice import (
    stamp_records_domain_compromise_tier,
    stamp_records_target_tier,
)
from adscan_internal.services.membership_snapshot import (
    load_membership_snapshot as _load_membership_snapshot_impl,
    membership_snapshot_path as _membership_snapshot_path,
    snapshot_has_sid_metadata as _snapshot_has_sid_metadata,
    _canonical_membership_label as _canonical_membership_label_full,
)
from adscan_internal.services.high_value import (
    classify_users_tier0_high_value,
    normalize_samaccountname,
)
from adscan_internal.services.identity_risk_service import (
    load_or_build_identity_risk_snapshot,
)
from adscan_internal.services.choke_point_classifier import (
    CHOKE_POINT_VERDICT_NOTE_KEYS,
    classify_attack_graph_edge_choke_point,
)
from adscan_internal.services.cache_metrics import (
    copy_stats,
    increment_scoped_stats,
    reset_stats,
)
from adscan_internal.services.adcs_path_display import (
    format_adcs_templates_summary,
    resolve_adcs_display_target,
)
from adscan_internal.services.adcs_target_filter import (
    is_adcs_tier_zero_group,
    domain_has_adcs_for_attack_steps,
)
from adscan_internal.services.ldap_transport_service import (
    prepare_kerberos_ldap_environment,
    resolve_ldap_target_endpoints,
)


# Schema 1.2 (Phase 2 attack-graph refactor, 2026-05-02): every edge now
# carries a top-level "kind" field set from EdgeKind. Schema 1.1 graphs
# load transparently — load_attack_graph backfills kinds in memory and
# the next save_attack_graph rewrites the JSON at 1.2.
ATTACK_GRAPH_SCHEMA_VERSION = "1.2"
_ATTACK_GRAPH_MAINTENANCE_VERSION = 2
_CONTEXT_RELATIONS_LOWER = {
    str(relation).strip().lower() for relation in CONTEXT_ONLY_RELATIONS.keys()
}
_NON_ACTIONABLE_SOURCE_FILTER_RELATIONS: frozenset[str] = frozenset(
    {
        "memberof",
        "contains",
        "gplink",
        "trustedby",
    }
)
# Relations that cross a domain/forest boundary at the EDGE level (not via a
# trust node): an MSSQL linked server lets a login on the source instance run
# T-SQL on a target instance that may live in a DIFFERENT forest. A Tier-0
# source reaching a DIFFERENT-domain target this way is a genuine cross-boundary
# compromise finding, NOT the "you already own this domain" noise that the
# Tier-0-source filter suppresses — so it is exempted when cross-domain (see
# _edge_has_tier0_source). These relations did not exist as graph edges before
# this exemption, so it changes no existing path counts.
_CROSS_FOREST_LATERAL_RELATIONS: frozenset[str] = frozenset(
    {
        "mssqllinkedserverlateral",
    }
)
_DUPLICATE_LABEL_DEBUG_SAMPLE_LIMIT = 5

# Edge classification for CTEM correlation (centralized in attack_step_catalog).
EXPLOITATION_EDGE_VULN_KEYS: dict[str, str] = get_exploitation_relation_vuln_keys()
ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS = os.getenv(
    "ADSCAN_ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS", "1"
).strip().lower() in {"1", "true", "yes", "on"}

_ATTACK_PATH_DEBUG_SUMMARY_TABLES_ENABLED = True
_EVERYONE_SID = "S-1-1-0"
_AUTHENTICATED_USERS_SID = "S-1-5-11"
_BUILTIN_USERS_SID = "S-1-5-32-545"
_DOMAIN_USERS_RID = 513


@dataclass(frozen=True, slots=True)
class AttackPathSummaryFilters:
    """Optional filters applied to computed attack-path summary records.

    These are post-compute filters over the summary/output layer, intended for
    follow-up workflows that need to reuse the standard attack-path engine but
    narrow the result set to a specific target or terminal primitive.
    """

    target_labels: tuple[str, ...] = ()
    terminal_relations: tuple[str, ...] = ()


@contextmanager
def _attack_path_debug_summary_tables(enabled: bool):
    """Temporarily control debug attack-path summary table rendering."""
    global _ATTACK_PATH_DEBUG_SUMMARY_TABLES_ENABLED  # noqa: PLW0603
    previous = _ATTACK_PATH_DEBUG_SUMMARY_TABLES_ENABLED
    _ATTACK_PATH_DEBUG_SUMMARY_TABLES_ENABLED = bool(enabled)
    try:
        yield
    finally:
        _ATTACK_PATH_DEBUG_SUMMARY_TABLES_ENABLED = previous


# When set, ``_ask_or_get_attack_path_engine`` skips the DEV engine/parallelism
# questionary pickers and returns the production default (local DFS, sequential).
# The pickers are a dev-only benchmark affordance; some callers drive attack-path
# computation from an INCIDENTAL, non-interactive seam (the background-job drain /
# idle-prompt harvest review) where firing an engine picker every render is a
# UX defect, not a meaningful choice. Scope it with ``suppress_dev_engine_picker``
# rather than threading an ``engine_override`` through every nested call site.
_SUPPRESS_DEV_ENGINE_PICKER: ContextVar[bool] = ContextVar(
    "_suppress_dev_engine_picker", default=False
)


@contextmanager
def suppress_dev_engine_picker() -> Iterator[None]:
    """Force the production attack-path engine default within this scope.

    Inside the ``with`` block, ``_ask_or_get_attack_path_engine`` returns
    ``("local", 0)`` without prompting, even in dev mode — so any attack-path
    computation triggered from an incidental non-interactive seam (e.g. the
    background-job drain rendering a harvest review, which classifies compromise
    reach via ``get_attack_path_summaries``) never fires the dev engine /
    parallelism questionary pickers. The INTENDED interactive selectors of that
    flow (credential activation) are unaffected; only the dev-benchmark engine
    picker is silenced. Re-entrant and asyncio-safe (backed by a ``ContextVar``).
    """
    token = _SUPPRESS_DEV_ENGINE_PICKER.set(True)
    try:
        yield
    finally:
        _SUPPRESS_DEV_ENGINE_PICKER.reset(token)


# Carries the engine/parallelism selection resolved BEFORE the compute enters a
# LiveSession alt-screen. When set, ``_ask_or_get_attack_path_engine`` returns
# it without prompting, so the dev pickers never fire from inside the compute
# (where the alt-screen hides the prompt and hangs the run until Ctrl-C).
_PRESELECTED_DEV_ENGINE: ContextVar[tuple[str, int] | None] = ContextVar(
    "_preselected_dev_engine", default=None
)


@contextmanager
def preselect_dev_engine_for_display(shell: object) -> Iterator[None]:
    """Resolve the dev engine/parallelism selection ONCE, before a LiveSession.

    The attack-path compute runs inside a ``LiveSession`` alt-screen. In dev
    mode the engine/parallelism questionary pickers fire from deep inside the
    compute (``_ask_or_get_attack_path_engine`` at the DFS entry) — but the
    alt-screen hides the prompt, so the compute hangs waiting for input that
    never arrives (only Ctrl-C cancels it, then it falls back to defaults). This
    resolves the selection HERE, while the terminal is still normal (prompt
    visible + answerable), stashes it in a ContextVar, and the in-compute picker
    returns the stashed value without prompting again. In production (non-dev)
    this resolves ``("local", 0)`` without prompting, so it is a no-op there.
    Re-entrant / asyncio-safe (ContextVar-backed).
    """
    engine_workers = _ask_or_get_attack_path_engine(shell)
    token = _PRESELECTED_DEV_ENGINE.set(engine_workers)
    try:
        yield
    finally:
        _PRESELECTED_DEV_ENGINE.reset(token)


def _maybe_print_attack_paths_summary_debug(
    domain: str,
    paths: list[dict[str, Any]],
    *,
    stage_label: str,
    max_display: int = 30,
) -> None:
    """Render the debug attack-path table only when this computation allows it."""
    if not _ATTACK_PATH_DEBUG_SUMMARY_TABLES_ENABLED:
        return
    print_attack_paths_summary_debug(
        domain,
        paths,
        stage_label=stage_label,
        max_display=max_display,
    )


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


# ---------------------------------------------------------------------------
# Attack path depth constants — shared by both BH CE and local DFS engines.
# These values ensure fair comparisons and prevent path explosion in wide scopes.
#
#   user / owned / principals  →  ATTACK_PATHS_MAX_DEPTH_USER   (7)
#   domain                     →  ATTACK_PATHS_MAX_DEPTH_DOMAIN  (6)
#   --all / --lowpriv target   →  additional -1 reduction (more terminal nodes)
#
# Effective depth matrix:
#   scope=user,      target=highvalue → 7
#   scope=user,      target=all       → 6
#   scope=domain,    target=highvalue → 6
#   scope=domain,    target=all       → 5
# ---------------------------------------------------------------------------
ATTACK_PATHS_MAX_DEPTH_USER: int = int(
    os.getenv("ADSCAN_ATTACK_PATHS_MAX_DEPTH_USER", "7")
)
ATTACK_PATHS_MAX_DEPTH_DOMAIN: int = int(
    os.getenv("ADSCAN_ATTACK_PATHS_MAX_DEPTH_DOMAIN", "6")
)
_ATTACK_PATHS_ALL_TARGET_DEPTH_REDUCTION: int = 1


def _effective_max_depth(requested: int, *, scope: str, target: str) -> int:
    """Compute the effective max path depth for a scope + target combination.

    Applies a scope-specific safety cap (domain < user) and an additional
    −1 reduction for non-highvalue targets (--all / --lowpriv), which produce
    many more terminal nodes and therefore much larger path sets.

    If the caller explicitly requests a depth below the cap, that is respected.
    If they request more, the cap is enforced for safety.

    Args:
        requested: Caller-supplied max_depth (from CLI --depth flag or default).
        scope: One of "user", "owned", "principals", "domain".
        target: One of "highvalue", "all", "lowpriv".

    Returns:
        Effective depth to use (always ≥ 1).
    """
    scope_cap = (
        ATTACK_PATHS_MAX_DEPTH_DOMAIN
        if str(scope or "").strip().lower() == "domain"
        else ATTACK_PATHS_MAX_DEPTH_USER
    )
    target_reduction = (
        _ATTACK_PATHS_ALL_TARGET_DEPTH_REDUCTION
        if str(target or "").strip().lower() in {"all", "lowpriv"}
        else 0
    )
    return max(1, min(requested, scope_cap - target_reduction))


_ATTACK_PATHS_CACHE_ENABLED = os.getenv(
    "ADSCAN_ATTACK_PATHS_CACHE_ENABLED", "1"
).strip().lower() in {"1", "true", "yes", "on"}
_ATTACK_PATHS_CACHE_MAX_ENTRIES = _env_int("ADSCAN_ATTACK_PATHS_CACHE_MAX_ENTRIES", 64)
# NOTE: kept defined for backward compatibility but NO LONGER used to gate the
# store. A path-COUNT cap bounds the wrong dimension: per-path RAM is not
# constant (~11KB + 20B*affected_width, a 30x span), so 2000 paths is ~20MB on a
# narrow domain but ~1GB on a wide corporate "Domain Users" domain. The store is
# now bounded by an ESTIMATED per-entry BYTE ceiling plus a "caching-is-a-win"
# gate (see ``_attack_paths_cache_put``).
_ATTACK_PATHS_CACHE_MAX_RECORDS = _env_int(
    "ADSCAN_ATTACK_PATHS_CACHE_MAX_RECORDS", 2000
)
# Per-entry byte-estimation proxy. Measured within +/-10% (over-estimates at the
# low end, which is the safe direction). Pure arithmetic on ``record["meta"]`` —
# no OS calls, so the admission decision is identical on Linux/macOS/Windows.
_CACHE_ENTRY_BASE_BYTES = _env_int("ADSCAN_ATTACK_PATHS_CACHE_ENTRY_BASE_BYTES", 11_000)
_CACHE_ENTRY_BYTES_PER_AFFECTED = _env_int(
    "ADSCAN_ATTACK_PATHS_CACHE_ENTRY_BYTES_PER_AFFECTED", 20
)
# Reject an entry whose estimated deep-copied size exceeds this ceiling (256 MB).
# Admits a 2000-path entry up to affected width ~6150 (the ordinary enterprise
# case); rejects the ~404 MB / width-10k monster that alone x64 LRU slots would
# OOM a small box.
_CACHE_ENTRY_MAX_BYTES = _env_int(
    "ADSCAN_ATTACK_PATHS_CACHE_ENTRY_MAX_BYTES", 256 * 1024 * 1024
)
# Estimated wall-clock cost of ``copy.deepcopy`` per byte (measured). Used only to
# compare against the real recompute time in the "caching-is-a-win" gate — pure
# arithmetic, no timing dependency at admission.
_CACHE_DEEPCOPY_SEC_PER_BYTE = _env_float(
    "ADSCAN_ATTACK_PATHS_CACHE_DEEPCOPY_SEC_PER_BYTE", 1.6e-8
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
_ATTACK_PATHS_MATERIALIZED_CACHE_ENABLED = os.getenv(
    "ADSCAN_ATTACK_PATHS_MATERIALIZED_CACHE_ENABLED", "1"
).strip().lower() in {"1", "true", "yes", "on"}
_ATTACK_PATHS_MATERIALIZED_CACHE: OrderedDict[
    tuple[str, str], MaterializedAttackPathArtifacts
] = OrderedDict()
_ATTACK_PATHS_PREPARED_RUNTIME_GRAPH_CACHE: OrderedDict[
    tuple[str, str], MaterializedPreparedRuntimeGraph
] = OrderedDict()
_ATTACK_PATHS_MATERIALIZED_CACHE_MAX_ENTRIES = _env_int(
    "ADSCAN_ATTACK_PATHS_MATERIALIZED_CACHE_MAX_ENTRIES",
    16,
)

# Epoch-keyed in-process memo for the fully-prepared (parsed + schema-backfilled +
# enriched) attack graph returned by ``load_attack_graph``. The per-path readiness
# / offer-evaluation pass drives ``load_attack_graph`` thousands of times per run
# (~2.7x per path on Forest, 16,922 loads) through independent read-only lookup
# helpers, each of which otherwise re-reads and re-parses the whole
# ``attack_graph.json`` from disk. The graph is READ, not mutated, during that
# pass, so serving one already-prepared object per graph epoch collapses the
# dominant cost of the eval pass (the JSON re-parse + ``_enrich_foreign_dc_nodes``)
# to a single load per epoch.
#
# NEVER-STALE contract: the key is ``attack_paths_epoch_fingerprint`` —
# ``(graph_mtime, snapshot_mtime)`` — the SAME epoch the compute cache keys on.
# Any ``save_attack_graph`` bumps the graph file mtime, so the very next load
# computes a fresh epoch and the stale entry is never matched; every mutating
# writer in this module loads-mutates-then-saves, so a mid-pass step execution
# that writes the graph is picked up on its next load. ``_invalidate_attack_paths_cache``
# also clears this memo (belt-and-suspenders). Bounded tiny (the pass works one
# domain at a time); per-process, never persisted. Returns the shared object — the
# readiness-pass callers are read-only lookups (audited: ``get_node_by_label`` /
# ``resolve_source_node_kind`` / ``_resolve_step_execution_host`` /
# ``resolve_netexec_target_for_node_label``); the only in-place mutators are the
# writer functions, which each ``save_attack_graph`` (busting the memo) after the
# mutation in the same synchronous call. Locked by
# ``tests/unit/services/test_load_attack_graph_memo.py``.
_LOAD_ATTACK_GRAPH_MEMO_ENABLED = os.getenv(
    "ADSCAN_LOAD_ATTACK_GRAPH_MEMO_ENABLED", "1"
).strip().lower() in {"1", "true", "yes", "on"}
_LOAD_ATTACK_GRAPH_MEMO_MAX_ENTRIES = 2
_LOAD_ATTACK_GRAPH_MEMO: "OrderedDict[tuple[str, tuple[Any, ...]], dict[str, Any]]" = (
    OrderedDict()
)


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
        workspace_cwd = resolve_workspace_cwd(shell)
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
        print_exception(exception=exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_info_debug(
            f"[membership] enabled users load failed for {marked_domain}: {exc}"
        )
        return None


def _load_domain_users(shell: object, domain: str) -> list[str] | None:
    """Load the persisted domain user list for a workspace domain."""
    try:
        workspace_cwd = resolve_workspace_cwd(shell)
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
        print_exception(exception=exc)
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


def get_domain_users_for_domain(
    shell: object,
    domain: str,
) -> set[str] | None:
    """Return domain users from membership data without applying enabled filtering."""
    snapshot = _load_membership_snapshot(shell, domain)
    if not isinstance(snapshot, dict):
        return None
    user_to_groups = snapshot.get("user_to_groups")
    if not isinstance(user_to_groups, dict):
        return None
    users = {
        normalized
        for label in user_to_groups.keys()
        if isinstance(label, str) and str(label).strip()
        if (normalized := normalize_samaccountname(_membership_label_to_name(label)))
    }
    return users or None


def get_enabled_computers_for_domain(
    shell: object,
    domain: str,
) -> set[str] | None:
    """Return enabled computer sAMAccountNames for a domain using workspace data."""
    try:
        workspace_cwd = resolve_workspace_cwd(shell)
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
        print_exception(exception=exc)
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

    service = getattr(shell, "_get_graph_service", None)
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
            print_exception(exception=exc)
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
            domain_sid = attack_paths_core._domain_sid_from_sid(sid)  # noqa: SLF001

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
        if hasattr(shell, "_get_graph_service"):
            service = shell._get_graph_service()  # type: ignore[attr-defined]
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
        print_exception(exception=exc)

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
        print_exception(exception=exc)

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
        domain_sid = attack_paths_core._domain_sid_from_sid(sid)  # noqa: SLF001
        if domain_sid:
            return domain_sid
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
        from adscan_internal.services.ldap_query_service import (
            query_shell_ldap_attribute_values,
        )
    except Exception:
        return None

    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_entry = domains_data.get(domain)
    if not isinstance(domain_entry, dict):
        return None
    auth_username = domain_entry.get("username")
    auth_password = domain_entry.get("password")
    pdc = domain_entry.get("pdc")
    if not auth_username or not auth_password or not pdc:
        return None

    query = f"(&(objectClass=domain)(name={domain}))"
    sids = query_shell_ldap_attribute_values(
        shell,
        domain=domain,
        ldap_filter=query,
        attribute="objectSid",
        auth_username=str(auth_username),
        auth_password=str(auth_password),
        pdc=str(pdc),
        prefer_kerberos=True,
        allow_ntlm_fallback=True,
        operation_name="domain SID lookup",
    )
    if sids is None:
        return None
    sids = [sid.strip() for sid in sids if str(sid).strip()]
    if not sids:
        return None
    return sids[0]


def _lookup_user_sid_via_ldap(shell: object, domain: str, username: str) -> str | None:
    try:
        from adscan_internal.services.ldap_query_service import (
            query_shell_ldap_attribute_values,
        )
    except Exception:
        return None
    domain_entry = getattr(shell, "domains_data", {}).get(domain, {})

    auth_username = domain_entry.get("username")
    auth_password = domain_entry.get("password")
    pdc = domain_entry.get("pdc")
    if not auth_username or not auth_password or not pdc:
        return None

    query = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))"
    sids = query_shell_ldap_attribute_values(
        shell,
        domain=domain,
        ldap_filter=query,
        attribute="objectSid",
        auth_username=str(auth_username),
        auth_password=str(auth_password),
        pdc=str(pdc),
        prefer_kerberos=True,
        allow_ntlm_fallback=True,
        operation_name="user SID lookup",
    )
    if sids is None:
        return None
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
        node = _resolve_bloodhound_principal_node(
            shell,
            domain,
            _canonical_membership_label(domain, username),
            entry_kind="user",
            graph=None,
            lookup_name=username,
        )
        sid = _extract_node_object_id(node)
        if isinstance(sid, str) and sid.strip():
            print_info_debug(
                f"[membership] user SID resolved from BloodHound for "
                f"{marked_user}@{marked_domain}: {mark_sensitive(sid, 'user')}"
            )
            return sid.strip()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

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


def _get_users_in_group_label_from_snapshot(
    shell: object,
    domain: str,
    group_label: str,
) -> list[str] | None:
    """Return usernames that recursively belong to one canonical group label."""
    snapshot = _load_membership_snapshot(shell, domain)
    if not snapshot:
        return None
    canonical_group = _canonical_membership_label(domain, group_label)
    if not canonical_group:
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
        if canonical_group in recursive_labels:
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

    service = getattr(shell, "_get_graph_service", None)
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
            print_exception(exception=exc)
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
        group_members, _computers, has_users = (
            attack_paths_core.build_group_member_index(
                snapshot,
                domain,
                exclude_tier0=False,
                include_computers=False,
            )
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

    service = getattr(shell, "_get_graph_service", None)
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
            print_exception(exception=exc)
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


def _read_memory_ceiling() -> tuple[int | None, int | None]:
    """Return ``(limit_bytes, available_bytes)`` from the memory probe, best-effort.

    Reuses :func:`adscan_core.memory_probe.read_memory_situation` — the cgroup-aware
    reader (never ``/proc/meminfo`` host RAM when a container cap exists). Returns
    ``(None, None)`` on any failure so the gate proceeds rather than aborting blind.
    """
    try:
        from adscan_core import memory_probe

        situation = memory_probe.read_memory_situation()
        return situation.limit_bytes, situation.available_bytes
    except Exception:  # noqa: BLE001 — a memory read must never break discovery.
        return None, None


def _gate_attack_path_memory_pre_dfs(nodes: int, edges: int) -> None:
    """Stage A — project the graph term only, before the DFS runs.

    The graph-resident memory is the only signal available before an hour of DFS.
    A graph large enough to cross the ceiling on its own is surfaced HERE, at phase
    entry, because the remedy (resize + re-run) is one the operator should learn
    now rather than after the DFS burns time.

    Interactive: WARN and proceed — ``raw_paths`` (often the dominant term) is not
    yet known, so a viable compute is not aborted prematurely; the operator sees
    the resize advice and can choose to stop.

    Non-interactive (``adscan ci`` / the web worker): when the GRAPH TERM ALONE
    already crosses the threshold the run is unconditionally doomed — adding the
    path term can only make it worse — and there is nobody to react, so proceeding
    would only burn the DFS and reach the same fatal allocation. In that case block
    now (raise the declared abort) so the run stops cleanly with a coverage
    declaration instead of being ``SIGKILL``ed. The abort is caught at the public
    entry point.

    Best-effort: any failure other than the declared abort leaves the compute
    unchanged.
    """
    try:
        from adscan_core.reporting import attack_path_memory_gate as gate

        limit_bytes, available_bytes = _read_memory_ceiling()
        projection = gate.evaluate_projection(
            nodes=nodes,
            edges=edges,
            raw_paths=None,
            limit_bytes=limit_bytes,
            available_bytes=available_bytes,
            stage="pre_dfs",
        )
        if not projection.exceeds:
            return
        message = gate.operator_message(projection)
    except _AttackPathMemoryBudgetExceeded:
        raise
    except Exception:  # noqa: BLE001 — the pre-DFS gate must never break discovery.
        return

    non_interactive = False
    try:
        from adscan_internal.interaction import is_non_interactive

        non_interactive = bool(is_non_interactive())
    except Exception:  # noqa: BLE001 — default to the safe interactive behaviour.
        non_interactive = False

    if non_interactive:
        # Doomed graph, unattended run — stop cleanly with a declaration rather
        # than let the DFS reach a SIGKILL. examined_routes=0: the DFS never ran.
        raise _AttackPathMemoryBudgetExceeded(message, examined_routes=0)
    print_warning(message)


def _estimate_affected_count_for_gate(
    shell: object,
    domain: str,
    *,
    scope: str = "domain",
    start_principal_count: int = 0,
) -> int:
    """Return a CONSERVATIVE upper bound on the per-path blast radius, best-effort.

    The memory gate's affected-aware path term needs ``affected_count`` — how many
    principals each surviving path stores in its ``meta.affected_users`` list — but
    that value is resolved only later, INSIDE the post-processing stage this gate
    protects (:func:`_apply_affected_user_metadata`), AFTER this seam fires. So the
    gate must estimate it, and the estimate must be conservative in the SAFE
    direction: OVER-estimate the blast radius, so the projection over-shoots and the
    gate errs toward a clean early stop, never toward letting the run reach the OOM.

    **The upper bound is SCOPE-DEPENDENT — the estimate must reflect the scope.**
    A path's ``affected_users`` list holds the START principals it advances, so its
    size can never exceed the number of principals the query STARTS from:

    - **``domain`` scope** — the query starts from every node, and broad-group
      (Domain Users) convergence genuinely makes each path's ``affected_users`` wide.
      The faithful upper bound is the domain's ENABLED-PRINCIPAL count (a large
      corporate directory has thousands, the true convergence blast radius the
      affected slope charges for). This is the calibrated behaviour (commit
      ``0a2a349ae``) and is preserved unchanged.
    - **``owned`` / ``user`` / ``principals`` scope** — the query starts from the
      owned / named / explicit principal set only, so a path can affect no more than
      that set. Using the domain-wide enabled count here OVER-projects by the ratio
      ``enabled_users / start_principals`` (measured 21–33x on Exchange-heavy
      directories, where the real per-path ``affected_users`` is ~1), which aborts a
      perfectly-sized owned run to zero routes — a silent false-negative. The
      faithful upper bound is the START-principal count.

    Returns ``0`` when no bound can be read — the projection then degrades to the
    base per-raw term, safe but no worse than the prior model.
    """
    scope_norm = str(scope or "").strip().lower()
    if scope_norm in {"owned", "user", "principals"}:
        # The blast radius is bounded by the number of START principals: a path
        # from a single owned principal advances at most that set, never the whole
        # directory. ``start_principal_count`` is the conservative upper bound for
        # these scopes; fall through to the domain-wide estimate only when it is
        # unknown (0), so a working projection never degrades to the base term
        # needlessly.
        if start_principal_count > 0:
            return start_principal_count
    try:
        enabled = get_enabled_users_for_domain(shell, domain)
        if enabled:
            return len(enabled)
        domain_users = get_domain_users_for_domain(shell, domain)
        if domain_users:
            return len(domain_users)
    except Exception:  # noqa: BLE001 — an estimate must never break discovery.
        return 0
    return 0


def _gate_attack_path_memory_post_dfs(
    *,
    shell: object,
    domain: str,
    nodes: int,
    edges: int,
    raw_paths: int,
    scope: str = "domain",
    start_principal_count: int = 0,
) -> None:
    """Stage B — project the full peak now that ``raw_paths`` is known.

    The DFS is done and its raw route count is the term that most often blows the
    budget. There is a large safety window here: the DFS finishes with RSS flat,
    then the decoration/ordering stages spike memory. So this is the moment to
    project the FULL peak and, if it crosses the threshold, ABORT before those
    stages run — saving both the wasted CPU and the fatal allocation. On a decision
    to abort this raises :class:`_AttackPathMemoryBudgetExceeded`; on any internal
    error it returns silently so the compute proceeds unchanged.

    The peak model is affected-aware (each surviving path stores its blast-radius
    list), but the true per-path blast radius is resolved only later, so this seam
    passes a CONSERVATIVE upper bound (:func:`_estimate_affected_count_for_gate`)
    that makes the projection over-shoot rather than miss. That bound is
    SCOPE-DEPENDENT: at ``owned``/``user``/``principals`` scope the blast radius is
    bounded by ``start_principal_count`` (a path from one owned principal cannot
    affect more than the start set); at ``domain`` scope it is the domain-wide
    enabled-principal count (broad-group convergence). The graph-density regime
    (keyed on ``nodes``/``edges``/``raw_paths``) is folded in by the gate itself.
    """
    try:
        from adscan_core.reporting import attack_path_memory_gate as gate

        limit_bytes, available_bytes = _read_memory_ceiling()
        affected_count = _estimate_affected_count_for_gate(
            shell,
            domain,
            scope=scope,
            start_principal_count=start_principal_count,
        )
        projection = gate.evaluate_projection(
            nodes=nodes,
            edges=edges,
            raw_paths=raw_paths,
            limit_bytes=limit_bytes,
            available_bytes=available_bytes,
            stage="post_dfs",
            affected_count=affected_count,
        )
        if not projection.exceeds:
            return
        message = gate.operator_message(projection)
    except _AttackPathMemoryBudgetExceeded:
        raise
    except Exception:  # noqa: BLE001 — a gate failure must never break discovery.
        return
    # Raise OUTSIDE the try so the abort signal is not swallowed by the broad
    # except above. The operator message reaches the terminal at the catch site.
    raise _AttackPathMemoryBudgetExceeded(message, examined_routes=raw_paths)


def _choose_attack_path_engine(graph: dict[str, Any]) -> str:
    """Return the attack-path engine to use for ``graph``: ``"dfs"`` or ``"fallback"``.

    Pure pre-DFS routing decision for the hybrid switch. Runs the cheap
    explosion predictor (one edge pass counting control mega-hubs) over a
    normalized ``{"nodes": <list>, "edges": <list>}`` view — the predictor
    expects ``nodes`` as a list, so a dict node-map is flattened to its values.
    Returns ``"fallback"`` when the graph carries the dense hub-mesh signature
    the all-simple-paths DFS explodes on, else ``"dfs"`` (the byte-identical
    default path). Never raises — an unreadable graph routes to the DFS.
    """
    try:
        nodes = graph.get("nodes") if isinstance(graph, dict) else None
        edges = graph.get("edges") if isinstance(graph, dict) else None
        normalized = {
            "nodes": list(nodes.values()) if isinstance(nodes, dict) else (nodes or []),
            "edges": edges or [],
        }
        return "fallback" if predicts_explosion(normalized) else "dfs"
    except Exception:  # noqa: BLE001 — a routing miss must never break discovery.
        return "dfs"


def _record_attack_path_engine_used(
    shell: object, *, engine: str, reason: str | None = None
) -> None:
    """Record which traversal engine produced the result (best-effort, non-JSON-safe).

    Stored on the shell as plain attributes (NOT ``domains_data`` — must never
    reach ``save_workspace_data`` as unexpected state) so downstream coverage /
    reporting can read which engine ran and why the fallback fired. Best-effort;
    never raises.
    """
    try:
        setattr(shell, "_attack_path_engine_used", str(engine))
        setattr(shell, "_attack_path_fallback_reason", reason)
    except Exception:  # noqa: BLE001 — the marker is best-effort telemetry.
        pass


def _handle_attack_path_memory_abort(
    shell: object, domain: str, exc: "_AttackPathMemoryBudgetExceeded"
) -> None:
    """Handle a memory-gate abort: operator terminal line + client coverage record.

    Two audiences, two messages (CLAUDE.md § "A bounded computation is a data
    gap"): the OPERATOR gets the real cause and remedy on the terminal (projected
    memory, the ceiling, resize-or-free); the CLIENT deliverable gets only the
    coverage boundary — how many routes were examined and that the set is not
    exhaustive — never the internal reason and never a verdict about their
    directory. Best-effort; never raises.
    """
    try:
        print_warning(exc.operator_message)
    except Exception:  # noqa: BLE001 — the operator line is best-effort.
        pass
    try:
        from adscan_core.reporting.attack_path_memory_gate import (
            build_attack_path_coverage,
        )
        from adscan_core.reporting.technical_report import (
            record_attack_path_coverage,
        )

        coverage = build_attack_path_coverage(
            bounded=True, examined_routes=exc.examined_routes
        )
        record_attack_path_coverage(shell, domain, coverage=coverage)
    except Exception as record_exc:  # noqa: BLE001
        telemetry.capture_exception(record_exc)
        print_exception(exception=record_exc)


def _resolve_exposure_source_count(shell: object, domain: str) -> int | None:
    """Return how many enabled principals can reach a high-value target, or None.

    The STABLE exposure figure the sampled-coverage declaration anchors the
    re-scan narrative on: a set cardinality (``|Reach^-1(value-terminals) ∩
    enabled-principals|``), NOT a route count — it is stable across re-scans even
    when the specific routes shown are a capped sample. Computed from the persisted
    attack graph via the choke-point SSOT (``exposure_source_count``), reusing the
    engine's own value-terminal set builder so the count matches what the fallback
    materialised evidence toward.

    Best-effort: any failure (no graph, an unreadable one) returns ``None`` and the
    declaration still stands, just without the concrete number.
    """
    try:
        graph = load_attack_graph(shell, domain)
        if not isinstance(graph, dict):
            return None
        return _resolve_exposure_source_count_for_graph(graph)
    except Exception as exc:  # noqa: BLE001 — the count is best-effort.
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _resolve_exposure_source_count_for_graph(graph: dict[str, Any]) -> int | None:
    """Return the exposure source count for an ALREADY-loaded graph, or None.

    The graph-only core of :func:`_resolve_exposure_source_count`, split out so a
    caller that already holds the loaded graph (the pre-flight builder) can reuse
    the SAME value-terminal set — domain objects plus the tier-0 / promotable
    high-value candidates — without a second ``load_attack_graph``. Best-effort:
    returns ``None`` on any failure or when no value terminal exists.
    """
    try:
        if not isinstance(graph, dict):
            return None
        nodes = graph.get("nodes")
        nodes_map = (
            nodes
            if isinstance(nodes, dict)
            else {str(n.get("id")): n for n in (nodes or []) if isinstance(n, dict)}
        )
        edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
        # The value terminals the fallback floors coverage toward: the domain
        # objects plus the tier-0 / promotable high-value candidates — the same
        # set the per-terminal engine enumerates.
        terminals: set[str] = {
            str(node_id)
            for node_id, node in nodes_map.items()
            if isinstance(node, dict) and attack_graph_core._node_is_domain(node)  # noqa: SLF001
        }
        terminals |= attack_graph_core._build_high_value_terminal_candidate_ids(  # noqa: SLF001
            nodes_map, edges, mode="tier0"
        )
        if not terminals:
            return None
        from adscan_internal.services.chokepoint_cardinality import (
            exposure_source_count,
        )

        return int(exposure_source_count(graph, value_terminals=terminals))
    except Exception as exc:  # noqa: BLE001 — the count is best-effort.
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _handle_attack_path_sampled_coverage(shell: object, domain: str) -> None:
    """Record the SAMPLED coverage declaration after a fallback-engine run.

    When the run used the bounded fallback engine (predicted explosion OR the
    post-DFS abort backstop), the deliverable must state that routes were SAMPLED
    — every reachable high-value target is represented, but the per-target route
    count is capped — and anchor the re-scan narrative on the STABLE exposure
    count (CLAUDE.md § "A bounded computation is a data gap"). Never states the
    internal reason and never a verdict about the client's directory. Best-effort;
    never raises into the caller.
    """
    try:
        from adscan_core.reporting.attack_path_memory_gate import (
            build_attack_path_coverage,
        )
        from adscan_core.reporting.technical_report import (
            record_attack_path_coverage,
        )

        coverage = build_attack_path_coverage(
            sampled=True,
            exposure_source_count=_resolve_exposure_source_count(shell, domain),
        )
        record_attack_path_coverage(shell, domain, coverage=coverage)
    except Exception as record_exc:  # noqa: BLE001
        telemetry.capture_exception(record_exc)
        print_exception(exception=record_exc)


def _emit_attack_path_discovery_started(
    shell: object,
    domain: str,
    *,
    scope: str,
    target: str,
    target_mode: str,
) -> None:
    """Emit a pre-discovery telemetry beacon BEFORE the DFS allocates memory.

    Attack-path discovery can OOM-kill on a large domain, and an OOM is a
    ``SIGKILL`` — no ``atexit``/signal handler runs, so the session's telemetry
    is lost with the process and the crash cannot be sized from field data. This
    beacon fires at the top of :func:`_compute_attack_path_summaries_inner`,
    before any of the ``compute_display_paths_for_*`` DFS entry points run, so a
    run that dies DURING discovery still leaves a record of the graph it was
    about to walk and the memory situation at that moment.

    It carries the base graph size (``nodes``/``edges`` — the predictor a future
    memory gate needs), the query slice (``scope``/``target``/``target_mode``),
    and the memory situation (cgroup limit / RSS / available, source-tagged) from
    :mod:`adscan_core.memory_probe`. The event is FLUSHED synchronously
    (:func:`telemetry.drain_telemetry_dispatch`) so it survives a ``SIGKILL`` that
    lands during the subsequent allocation — the ``atexit`` disk-persist drain
    never runs under ``SIGKILL``, so buffering it would lose it exactly as today.

    Best-effort in every part: reading the graph, the memory figures, and the
    flush are each wrapped so a beacon can never crash or slow the discovery it
    is meant to instrument.

    Args:
        shell: The active shell (for the graph load + lab-event enrichment).
        domain: The domain whose graph is about to be walked.
        scope: The attack-path scope (``domain``/``owned``/``user``/``principals``).
        target: The target selector (``highvalue``/``all``/…).
        target_mode: The target mode (``object``/``domain``/``tier0``).
    """
    try:
        from adscan_core import telemetry
        from adscan_core import memory_probe

        nodes_count = 0
        edges_count = 0
        mega_hub_count = 0
        predicts_sampled = False
        try:
            base_graph = load_attack_graph(shell, domain)
            if isinstance(base_graph, dict):
                base_nodes = base_graph.get("nodes")
                base_edges = base_graph.get("edges")
                if isinstance(base_nodes, (list, dict)):
                    nodes_count = len(base_nodes)
                if isinstance(base_edges, (list, dict)):
                    edges_count = len(base_edges)
                # The same predictor the routing decision runs, off the graph we
                # already loaded — no second load. This carries the engine
                # decision (scale + sampled-mode verdict) into the CI capture and
                # the collapsed operator line below.
                try:
                    from adscan_internal.services.attack_path_explosion_predictor import (
                        count_control_mega_hubs,
                        predicts_explosion,
                    )

                    mega_hub_count = count_control_mega_hubs(base_graph)
                    predicts_sampled = predicts_explosion(base_graph)
                except Exception:  # noqa: BLE001 — predictor read is best-effort.
                    pass
        except Exception:  # noqa: BLE001 — a beacon must never block discovery.
            pass

        # Collapsed pre-flight for the non-interactive (`adscan ci`) run: one line,
        # not the full REPL panel — the scale + the engine-routing decision. Gated
        # to non-interactive so the interactive path shows only the rich panel.
        try:
            from adscan_internal.interaction import is_non_interactive

            if is_non_interactive(shell):
                marked = mark_sensitive(domain, "domain")
                verdict = (
                    f"sampled mode ({mega_hub_count} control mega-hubs)"
                    if predicts_sampled
                    else "full discovery"
                )
                print_info(
                    f"Attack graph {marked}: {nodes_count:,} nodes, "
                    f"{edges_count:,} edges -> {verdict}."
                )
        except Exception:  # noqa: BLE001 — the one-liner is best-effort.
            pass

        properties: dict[str, Any] = {
            "domain": mark_sensitive(domain, "domain"),
            "scope": scope,
            "target": target,
            "target_mode": target_mode,
            "nodes": nodes_count,
            "edges": edges_count,
            "mega_hub_count": mega_hub_count,
            "predicts_sampled": predicts_sampled,
        }
        try:
            properties.update(memory_probe.memory_situation_fields())
        except Exception:  # noqa: BLE001 — memory read is best-effort.
            pass
        try:
            from adscan_internal.cli.common import build_lab_event_fields

            properties.update(build_lab_event_fields(shell=shell, include_slug=False))
        except Exception:  # noqa: BLE001 — lab fields are best-effort enrichment.
            pass

        telemetry.capture("attack_path_discovery_started", properties)
        # Force the beacon onto the wire NOW. capture() enqueues onto the
        # fire-and-forget dispatch daemon; a bounded drain blocks until that
        # daemon has POSTed the queued job (or the bound elapses), so the event
        # is sent before the DFS starts allocating and a SIGKILL during the walk
        # cannot lose it. The SIGKILL disk-persist drain never runs, so this
        # synchronous flush is the only thing that makes the beacon survive.
        try:
            telemetry.drain_telemetry_dispatch(total_timeout=2.5)
        except Exception:  # noqa: BLE001 — flush is best-effort.
            pass
    except Exception:  # noqa: BLE001 — the beacon must never break discovery.
        pass


def _log_attack_path_compute_timing(
    *,
    domain: str,
    scope: str,
    elapsed_seconds: float,
    path_count: int,
    max_depth: int,
    target: str,
    target_mode: str,
) -> None:
    """Emit centralized timing metrics for attack-path computations."""
    marked_domain = mark_sensitive(domain, "domain")
    print_info_verbose(
        f"[attack_paths] compute scope={scope} domain={marked_domain} "
        f"paths={path_count} max_depth={max_depth} "
        f"target={target!r} target_mode={target_mode} "
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
    """Build cache key bound to the shared graph epoch plus query params.

    The epoch tokens come from :func:`attack_paths_epoch_fingerprint` (the ONE
    SSOT) so the compute cache inherits whichever invalidation semantics that
    function is in — legacy mtime (flag off) or structural (flag on). This is why
    a status-only write no longer colds the compute cache under the structural
    epoch, while a topology change still does.
    """
    graph_epoch, snapshot_epoch = attack_paths_epoch_fingerprint(shell, domain)
    return (
        str(domain or "").strip().lower(),
        str(scope or "").strip().lower(),
        graph_epoch,
        snapshot_epoch,
        params,
    )


# Sentinel the structural hash returns when it cannot canonicalize a graph. It
# is intentionally NOT a stable value keyed on content: two malformed graphs
# must NOT collide into a warm cache hit, so it embeds a fresh token per call
# (forces a recompute rather than a blind serve).
_STRUCTURAL_HASH_ERROR_PREFIX = "structural-error:"


def _graph_structural_hash(graph: dict[str, Any]) -> str:
    """Return a stable structural fingerprint of an attack graph.

    Covers EXACTLY the fields route discovery reads to build DFS adjacency
    (cross-reference ``attack_graph_core.build_expansion_view`` /
    ``admit_frontier_edge`` / ``_is_nontraversable_attack_edge``):

    - the NODE set (id + ``kind`` — ``kind`` gates the ``WriteSPN`` → Computer
      non-traversable rule; it is a structural attribute, never a status field);
    - the EDGE set as ``(from, relation, to)`` triples, endpoint-key-agnostic
      (``from``/``source`` and ``to``/``target``, mirroring every graph consumer
      so a freshly-inserted ``source``/``target``-keyed derived edge counts).

    It deliberately IGNORES ``status`` / ``notes`` / ``knowledge`` / timestamps
    (``last_seen`` / ``generated_at`` / ``discovered_at``) — none of them change
    which routes exist, so a status-only write leaves this hash unchanged (the
    whole point: caches stay warm across the post-ex status storm).

    Deterministic across runs: node/edge tuples are sorted before hashing, so
    there is no set/dict-iteration-order dependence.

    Best-effort: on a malformed graph it returns a per-call error sentinel that
    forces a recompute (never a blind stale serve) and never raises.
    """
    try:
        node_tokens: list[str] = []
        nodes = graph.get("nodes")
        node_iter: list[Any]
        if isinstance(nodes, dict):
            node_iter = list(nodes.values())
        elif isinstance(nodes, list):
            node_iter = nodes
        else:
            node_iter = []
        for node in node_iter:
            if not isinstance(node, dict):
                continue
            node_id = str(node.get("id") or "")
            if not node_id:
                continue
            kind = str(node.get("kind") or "").strip().lower()
            node_tokens.append(f"{node_id}\x1f{kind}")

        edge_tokens: list[str] = []
        edges = graph.get("edges")
        edge_iter = edges if isinstance(edges, list) else []
        for edge in edge_iter:
            if not isinstance(edge, dict):
                continue
            from_id = str(edge.get("from") or edge.get("source") or "")
            to_id = str(edge.get("to") or edge.get("target") or "")
            relation = str(edge.get("relation") or "")
            if not from_id or not to_id or not relation:
                continue
            edge_tokens.append(f"{from_id}\x1f{relation}\x1f{to_id}")

        hasher = hashlib.blake2b(digest_size=16)
        # Length-prefix each section so a node token can never be confused with
        # an edge token (canonical, unambiguous join).
        hasher.update(f"N{len(node_tokens)}\x1e".encode("utf-8"))
        for token in sorted(node_tokens):
            hasher.update(token.encode("utf-8"))
            hasher.update(b"\x1e")
        hasher.update(f"E{len(edge_tokens)}\x1e".encode("utf-8"))
        for token in sorted(edge_tokens):
            hasher.update(token.encode("utf-8"))
            hasher.update(b"\x1e")
        return hasher.hexdigest()
    except Exception:  # noqa: BLE001 — best-effort; never raise, force recompute
        return f"{_STRUCTURAL_HASH_ERROR_PREFIX}{uuid.uuid4().hex}"


def _hash_membership_map(hasher: "hashlib._Hash", label: str, mapping: Any) -> None:
    """Fold a ``label -> [values]`` membership map into ``hasher``, order-stable."""
    if not isinstance(mapping, dict):
        return
    hasher.update(f"M{label}:{len(mapping)}\x1e".encode("utf-8"))
    for key in sorted(str(k) for k in mapping.keys()):
        values = mapping.get(key)
        if isinstance(values, (list, tuple, set)):
            joined = "\x1f".join(sorted(str(v) for v in values))
        else:
            joined = str(values)
        hasher.update(f"{key}\x1f{joined}\x1e".encode("utf-8"))


def _snapshot_structural_hash(shell: object, domain: str) -> str:
    """Return a stable structural fingerprint of the membership snapshot.

    Covers the reachability-relevant structure the group-expansion layer reads:
    the snapshot's node set + ``(from, relation, to)`` MemberOf triples (same
    shape as the attack graph, so it reuses :func:`_graph_structural_hash`) AND
    the built membership maps (``user_to_groups`` / ``computer_to_groups`` /
    ``group_to_parents``) when present — a runtime group add/remove mutates one
    of those, and it changes which routes exist, so it MUST move this hash.

    Ignores ``generated_at`` and any per-snapshot timestamp. Best-effort: returns
    a per-call error sentinel on failure (forces recompute) and never raises.
    """
    try:
        snapshot = _load_membership_snapshot(shell, domain)
        if not isinstance(snapshot, dict):
            # An absent snapshot is a STABLE structural state (no memberships),
            # distinct from a load error. Key it on a fixed token so two absent
            # loads agree (no spurious invalidation), unlike the error sentinel.
            return "structural-snapshot:absent"
        hasher = hashlib.blake2b(digest_size=16)
        # The snapshot's own node/edge graph (MemberOf topology).
        hasher.update(_graph_structural_hash(snapshot).encode("utf-8"))
        hasher.update(b"\x1e")
        _hash_membership_map(hasher, "u2g", snapshot.get("user_to_groups"))
        _hash_membership_map(hasher, "c2g", snapshot.get("computer_to_groups"))
        _hash_membership_map(hasher, "g2p", snapshot.get("group_to_parents"))
        return hasher.hexdigest()
    except Exception:  # noqa: BLE001 — best-effort; never raise, force recompute
        return f"{_STRUCTURAL_HASH_ERROR_PREFIX}{uuid.uuid4().hex}"


def _structural_epoch_enabled() -> bool:
    """Return True when the structural attack-path cache epoch is enabled.

    Read at call time (not module load) so a test / operator can toggle
    ``ADSCAN_ATTACK_PATHS_STRUCTURAL_EPOCH`` without re-importing the module.
    Currently defaults ON for LAB VALIDATION: the structural epoch changes the
    never-stale cache contract, and it is turned on in-code so a real post-ex lab
    run (GOAD/Forest) can validate it without the operator setting the env var.
    This default is PROVISIONAL — pending the lab-validation handoff (does a real
    DCSync-inserted ``derived`` edge still surface its route; does the deliverable
    match a flag-OFF run). Revert to ``"0"`` if validation is not clean; set
    ``ADSCAN_ATTACK_PATHS_STRUCTURAL_EPOCH=0`` to force the proven mtime path.
    """
    return os.getenv("ADSCAN_ATTACK_PATHS_STRUCTURAL_EPOCH", "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _mtime_epoch_fingerprint(shell: object, domain: str) -> tuple[Any, ...]:
    """Return the legacy ``(graph_mtime, snapshot_mtime)`` file-mtime epoch.

    This is the ORIGINAL invalidation epoch — cheap disk stats, changes on EVERY
    ``save_attack_graph`` (including status-only writes). It is the flag-OFF
    behaviour of :func:`attack_paths_epoch_fingerprint` AND the key
    :func:`load_attack_graph`'s own memo uses unconditionally (the load memo only
    needs to invalidate on ANY file change, and mtime does that cheaply without
    the recursion a structural key would create — the fingerprint loads the graph
    via ``load_attack_graph``).

    Returns:
        ``(graph_mtime_token, snapshot_mtime_token)`` — each a float mtime or
        ``None`` when the file is absent. Best-effort; never raises.
    """
    graph_path = _graph_path(shell, domain)
    snapshot_path = _membership_snapshot_path(shell, domain)
    return (_file_mtime_token(graph_path), _file_mtime_token(snapshot_path))


def attack_paths_epoch_fingerprint(shell: object, domain: str) -> tuple[Any, ...]:
    """Return the graph-epoch tokens the attack-path compute caches key on.

    Single source of truth for the invalidation epoch shared by the compute
    cache (:func:`_attack_paths_cache_base_key`) and the credential-harvest reach
    memo. Every consumer keys on THESE exact tokens (not a parallel epoch), so a
    change to what this returns propagates the invalidation semantics to all of
    them with no per-consumer change.

    Two modes, selected by ``ADSCAN_ATTACK_PATHS_STRUCTURAL_EPOCH``:

    - **OFF (default)** — the legacy ``(graph_mtime, snapshot_mtime)`` tuple. Every
      ``save_attack_graph`` bumps the graph mtime, so a step-state (status) write
      changes the epoch and colds the caches. Provably never-stale, but re-runs
      the compute on every post-ex status write (the recompute storm).
    - **ON (structural)** — ``(graph_structural_hash, snapshot_structural_hash)``
      computed from the already-warm loaded graph
      (:func:`_graph_structural_hash` / :func:`_snapshot_structural_hash`). A
      status/notes/timestamp-only write does NOT change the hash (caches stay warm,
      correctly); a topology change (new edge/node, runtime membership add) DOES
      (caches invalidate, correctly). This kills the recompute storm while
      remaining never-stale for the route SET. A warm serve additionally re-derives
      each record's display status from current step statuses (see
      :func:`_attack_paths_cache_get`), so a reused set is never status-stale.

    Best-effort: any structural-hash failure falls back to the mtime tuple — never
    raises, never a blind stale serve.

    Returns:
        A 2-tuple of epoch tokens (mtime floats OR structural hex hashes).
    """
    if not _structural_epoch_enabled():
        return _mtime_epoch_fingerprint(shell, domain)
    try:
        graph = load_attack_graph(shell, domain)
        graph_hash = _graph_structural_hash(graph)
        snapshot_hash = _snapshot_structural_hash(shell, domain)
        return (graph_hash, snapshot_hash)
    except Exception:  # noqa: BLE001 — never raise; fall back to the proven mtime epoch
        return _mtime_epoch_fingerprint(shell, domain)


def _build_current_edge_status_index(graph: dict[str, Any]) -> dict[tuple[str, str, str], str]:
    """Index the warm graph's CURRENT edge statuses by ``(from, relation, to)`` label.

    Endpoints are resolved node-id -> label and normalized with
    :func:`_normalize_account` so they compare against a cached step's
    ``details.from``/``details.to`` labels. Relation is lower-cased. Best-effort:
    a malformed graph yields an empty index (no re-derivation, cached serve).
    """
    index: dict[tuple[str, str, str], str] = {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []

    def _label_for(node_id: str) -> str:
        node = nodes.get(node_id) if isinstance(nodes, dict) else None
        if isinstance(node, dict):
            return str(node.get("label") or node.get("name") or node_id)
        return node_id

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = str(edge.get("from") or edge.get("source") or "")
        to_id = str(edge.get("to") or edge.get("target") or "")
        relation = str(edge.get("relation") or "").strip().lower()
        status = str(edge.get("status") or "").strip().lower()
        if not from_id or not to_id or not relation or not status:
            continue
        key = (
            _normalize_account(_label_for(from_id)),
            relation,
            _normalize_account(_label_for(to_id)),
        )
        index[key] = status
    return index


def _rederive_cached_record_statuses(
    records: list[dict[str, Any]], *, shell: object, domain: str
) -> list[dict[str, Any]]:
    """Refresh a warm-served record set's step + display statuses from the graph.

    Under the structural epoch a status-only write is a cache HIT, so the cached
    records carry the step statuses that were current WHEN they were stored — now
    stale. This re-reads the CURRENT edge status for each step from the warm graph,
    passes it through the SAME per-step display transform the record builders use
    (:func:`derive_step_display_status` — a ``context_only`` hop such as MemberOf
    becomes ``structural``; a display verdict such as ``unsupported`` is preserved),
    and re-derives each record's display ``status`` via the SSOT
    (:func:`_derive_display_status_from_steps`). Routing the raw status through the
    display transform makes the warm-served status byte-identical to what a cold
    compute would bake, so a reused route set is never status-stale (a proven step
    is never shown as ``theoretical`` and vice versa) and a structural hop is never
    mislabeled ``theoretical``.

    Mutates ``records`` in place (they are already a deepcopy from the cache) and
    returns them. Best-effort: on any failure the records pass through unchanged
    (a slightly-stale status beats a broken serve, and the mtime-epoch default is
    unaffected since it never serves a status-changed set warm).
    """
    try:
        graph = load_attack_graph(shell, domain)
        status_index = _build_current_edge_status_index(graph)
        if not status_index:
            return records
        for record in records:
            if not isinstance(record, dict):
                continue
            steps = record.get("steps")
            if not isinstance(steps, list):
                continue
            changed = False
            for step in steps:
                if not isinstance(step, dict):
                    continue
                relation = str(step.get("action") or "").strip().lower()
                details = step.get("details") if isinstance(step.get("details"), dict) else {}
                key = (
                    _normalize_account(str(details.get("from") or "")),
                    relation,
                    _normalize_account(str(details.get("to") or "")),
                )
                current = status_index.get(key)
                if current is None:
                    continue
                # Route the RAW edge status through the SAME display transform the
                # record builders use, so the warm-served status is byte-identical
                # to what a cold compute would bake (a context_only relation like
                # MemberOf -> "structural", a display verdict like "unsupported"
                # preserved). Without this the re-derive would overwrite the baked
                # display status with the raw status and mislabel a structural hop
                # as "Theoretical" in the client report.
                current_display = str(
                    derive_step_display_status(step.get("action"), current) or ""
                ).strip().lower()
                if current_display and current_display != str(step.get("status") or "").strip().lower():
                    step["status"] = current_display
                    changed = True
            if changed:
                record["status"] = _derive_display_status_from_steps(steps)
        return records
    except Exception:  # noqa: BLE001 — best-effort; a cached serve is better than a crash
        return records


def _attack_paths_cache_get(
    key: tuple[Any, ...],
    *,
    domain: str,
    scope: str,
    no_cache: bool = False,
    shell: object | None = None,
) -> list[dict[str, Any]] | None:
    """Return cached attack-path records when available.

    Under the structural epoch (``ADSCAN_ATTACK_PATHS_STRUCTURAL_EPOCH``) a
    status-only write is a HIT, so a warm serve re-derives each record's step +
    display status from the CURRENT graph via
    :func:`_rederive_cached_record_statuses` (needs ``shell``). Under the legacy
    mtime epoch a status write was a MISS anyway, so the re-derivation is skipped
    (byte-identical to before).
    """
    if no_cache or not _ATTACK_PATHS_CACHE_ENABLED:
        return None
    cached = _ATTACK_PATHS_COMPUTE_CACHE.get(key)
    if cached is None:
        # L1 MISS -> try the L2 disk sidecar (cold-start reuse). A disk hit is
        # promoted into L1 through the existing put path so the byte-budget
        # ceiling / eviction still governs the in-memory copy (a monster disk hit
        # cannot blow the memory bound). ``shell`` is required to resolve the
        # workspace dir; a shell-less call (the unit put helper) skips disk.
        disk_records = _load_attack_paths_disk_cache(
            key, domain=domain, scope=scope, shell=shell
        )
        if disk_records is None:
            _cache_stats_inc(domain, "misses")
            return None
        _cache_stats_inc(domain, "disk_hits")
        # Promote into L1 (no compute time -> win-gate skipped, byte ceiling still
        # applies). ``shell=None`` here so the promote does NOT re-write the disk
        # sidecar we just read from.
        _attack_paths_cache_put(
            key, disk_records, domain=domain, scope=scope, compute_seconds=None
        )
        cached = disk_records
    else:
        _cache_stats_inc(domain, "hits")
        # LRU touch.
        _ATTACK_PATHS_COMPUTE_CACHE.move_to_end(key)
        print_info_debug(
            f"[attack_paths] cache hit: domain={mark_sensitive(domain, 'domain')} "
            f"scope={scope} records={len(cached)}"
        )
    served = copy.deepcopy(cached)
    if shell is not None and _structural_epoch_enabled():
        served = _rederive_cached_record_statuses(served, shell=shell, domain=domain)
    return served


def _load_attack_paths_disk_cache(
    key: tuple[Any, ...],
    *,
    domain: str,
    scope: str,
    shell: object | None,
) -> list[dict[str, Any]] | None:
    """Return the disk L2 result set for a key, or None (best-effort)."""
    if shell is None:
        return None
    try:
        return load_disk_cached_attack_path_results(
            shell=shell, domain=domain, cache_key=key
        )
    except Exception:  # noqa: BLE001 — a disk error must fall back to compute, never raise
        return None


def _estimate_cache_entry_bytes(records: list[dict[str, Any]]) -> int:
    """Estimate the deep-copied RAM footprint of a cached entry.

    O(N), no recursion. Per-path RAM is a tight linear model
    ``base + per_affected * affected_width`` where the affected width is the
    blast-radius list ``apply_affected_user_metadata`` stores in ``meta``. Read
    ``meta`` defensively — a record may be missing ``meta`` or either count
    (``affected_computer_count`` is only written when there are affected
    computers), and any missing key contributes 0. Pure arithmetic, so the
    estimate is identical on Linux/macOS/Windows.
    """
    total = 0
    for record in records:
        meta = record.get("meta") if isinstance(record, dict) else None
        affected = 0
        if isinstance(meta, dict):
            for count_key in ("affected_user_count", "affected_computer_count"):
                value = meta.get(count_key, 0)
                if isinstance(value, int) and value > 0:
                    affected += value
        total += _CACHE_ENTRY_BASE_BYTES + _CACHE_ENTRY_BYTES_PER_AFFECTED * affected
    return total


def _attack_paths_cache_put(
    key: tuple[Any, ...],
    records: list[dict[str, Any]],
    *,
    domain: str,
    scope: str,
    compute_seconds: float | None = None,
    shell: object | None = None,
    no_cache: bool = False,
) -> None:
    """Store attack-path records in a bounded LRU cache (+ optional disk L2).

    The entry is bounded by an estimated per-entry BYTE ceiling and a
    "caching-is-a-win" gate, NOT by a path count (which bounds the wrong
    dimension — see ``_ATTACK_PATHS_CACHE_MAX_RECORDS``):

    1. Skip when the estimated deep-copied size exceeds ``_CACHE_ENTRY_MAX_BYTES``
       (``reason=entry_too_large``). A single wide entry can otherwise be
       hundreds of MB x up to 64 LRU slots -> OOM on a small box.
    2. Skip when caching would be a net loss — the estimated ``copy.deepcopy``
       time to serve a future hit is >= the ``compute_seconds`` it took to
       produce these records (``reason=deepcopy_exceeds_recompute``). The
       genuinely dangerous wide entries are exactly the ones this refuses, so
       refusing them costs nothing. When ``compute_seconds`` is None the caller
       did not measure the recompute time, so this gate is skipped (the byte
       ceiling still applies) — never guess a recompute time.

    Both gates are pure arithmetic on data already in ``record["meta"]`` plus the
    caller's measured elapsed time; there is no OS call, memory probe, or cgroup
    read, so admission is identical across platforms.

    When ``shell`` is provided (the real compute call sites) AND ``no_cache`` is
    False, the same admitted record set is ALSO written to the L2 disk sidecar so
    a cold-start process reuses it — governed by the SAME two gates (a monster
    entry the byte ceiling rejects, or a wide entry the win-gate rejects, is not
    worth persisting on disk either). The disk write NEVER re-triggers on the
    disk-hit promotion path (that call passes ``shell=None``), so a served disk
    hit is not re-written.
    """
    if no_cache or not _ATTACK_PATHS_CACHE_ENABLED:
        return
    estimated_entry_bytes = _estimate_cache_entry_bytes(records)
    if estimated_entry_bytes > _CACHE_ENTRY_MAX_BYTES:
        _cache_stats_inc(domain, "skips")
        print_info_debug(
            f"[attack_paths] cache skip: domain={mark_sensitive(domain, 'domain')} "
            f"scope={scope} records={len(records)} bytes={estimated_entry_bytes} "
            f"reason=entry_too_large"
        )
        return
    if compute_seconds is not None:
        estimated_deepcopy_seconds = estimated_entry_bytes * _CACHE_DEEPCOPY_SEC_PER_BYTE
        if estimated_deepcopy_seconds >= compute_seconds:
            _cache_stats_inc(domain, "skips")
            print_info_debug(
                f"[attack_paths] cache skip: domain={mark_sensitive(domain, 'domain')} "
                f"scope={scope} records={len(records)} "
                f"deepcopy={estimated_deepcopy_seconds:.3f}s recompute={compute_seconds:.3f}s "
                f"reason=deepcopy_exceeds_recompute"
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
    # L2 disk sidecar — only from real compute call sites (shell present), only
    # for an entry that passed BOTH gates above (composes with the byte-budget),
    # and never on the disk-hit promotion (shell=None) or no_cache path.
    if shell is not None:
        _store_attack_paths_disk_cache(key, records, domain=domain, scope=scope, shell=shell)


def _store_attack_paths_disk_cache(
    key: tuple[Any, ...],
    records: list[dict[str, Any]],
    *,
    domain: str,
    scope: str,
    shell: object,
) -> None:
    """Persist an admitted record set to the disk L2 (best-effort)."""
    try:
        epoch = attack_paths_epoch_fingerprint(shell, domain)
    except Exception:  # noqa: BLE001 — no epoch stamp is fine; unlink falls back to wipe-all
        epoch = None
    try:
        wrote = persist_attack_path_results_to_disk(
            shell=shell, domain=domain, cache_key=key, records=records, epoch=epoch
        )
    except Exception:  # noqa: BLE001 — a disk write error must never break the in-memory serve
        return
    if wrote:
        _cache_stats_inc(domain, "disk_stores")


def _invalidate_load_attack_graph_memo(domain: str) -> None:
    """Drop every epoch-keyed load-graph memo entry for a domain."""
    if not _LOAD_ATTACK_GRAPH_MEMO:
        return
    domain_key = str(domain or "").strip().lower()
    for key in [k for k in _LOAD_ATTACK_GRAPH_MEMO if k[0] == domain_key]:
        _LOAD_ATTACK_GRAPH_MEMO.pop(key, None)


def _invalidate_attack_paths_cache(
    domain: str, *, reason: str, shell: object | None = None
) -> None:
    """Invalidate in-memory attack-path cache entries for a domain.

    When ``shell`` is provided (the ``save_attack_graph`` seam), this ALSO
    actively unlinks the domain's L2 disk result sidecars (GUARD 1). The disk
    entry's epoch-bearing key already makes a stale file unreachable, but a graph
    change is the moment to reclaim the disk too, not leave it for the file-count
    LRU. Best-effort — never raises.

    Under the STRUCTURAL epoch (``ADSCAN_ATTACK_PATHS_STRUCTURAL_EPOCH``) the
    in-memory compute cache is NOT popped here: the compute-cache key embeds the
    structural graph hash, so a topology change already re-keys the entry to a
    natural MISS while a status-only write keeps the key for a warm HIT (served
    with a status re-derive). Popping the entry would DEFEAT that warm serve —
    the entire point of the epoch — so the epoch, not this imperative pop, is the
    sole arbiter of the compute cache. Under the legacy mtime epoch the pop stays
    (a status write was a miss there anyway; keeping it is byte-identical to the
    proven path).
    """
    # Belt-and-suspenders: drop the epoch-keyed load memo for this domain even
    # when the compute cache is disabled. The mtime epoch already ages the memo
    # out on the next load after a save, but actively clearing it here (on every
    # ``save_attack_graph``) guarantees a mutated graph is never served from the
    # memo — independent of the compute-cache toggle below.
    _invalidate_load_attack_graph_memo(domain)
    if shell is not None:
        _unlink_attack_paths_disk_cache(shell, domain, reason=reason)
    # Structural epoch: the compute-cache key IS the epoch, so a pop is redundant
    # (topology change -> re-key -> miss) AND harmful (status write -> same key ->
    # would cold the warm serve). Leave the entry; the epoch decides.
    if _structural_epoch_enabled():
        return
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


def _unlink_attack_paths_disk_cache(shell: object, domain: str, *, reason: str) -> None:
    """Actively unlink the domain's STALE L2 disk result sidecars (GUARD 1).

    Passes the CURRENT graph epoch so a sidecar written under the same epoch (a
    status-only write under the structural epoch) is KEPT for the warm serve —
    only genuinely stale files (a moved epoch, i.e. a topology change) are deleted.
    On any epoch-resolution error the epoch is None and the unlink wipes ALL files
    (the safe direction). Best-effort — never raises.
    """
    try:
        current_epoch = attack_paths_epoch_fingerprint(shell, domain)
    except Exception:  # noqa: BLE001 — unknown epoch -> wipe-all (safe)
        current_epoch = None
    try:
        removed = unlink_attack_path_results_for_domain(
            shell, domain, current_epoch=current_epoch
        )
    except Exception:  # noqa: BLE001 — disk hygiene must never break the graph write
        return
    if removed:
        _cache_stats_inc(domain, "disk_invalidations", by=1)
        print_info_debug(
            f"[attack_paths] disk result cache unlinked: domain={mark_sensitive(domain, 'domain')} "
            f"files={removed} reason={reason}"
        )


def _materialized_cache_get(
    domain: str,
    *,
    fingerprint: str,
) -> MaterializedAttackPathArtifacts | None:
    """Return a matching in-memory materialized artifact bundle."""
    if not _ATTACK_PATHS_MATERIALIZED_CACHE_ENABLED:
        return None
    key = (str(domain or "").strip().lower(), fingerprint)
    cached = _ATTACK_PATHS_MATERIALIZED_CACHE.get(key)
    if cached is None:
        return None
    _ATTACK_PATHS_MATERIALIZED_CACHE.move_to_end(key)
    return cached


def _materialized_cache_put(
    domain: str,
    artifacts: MaterializedAttackPathArtifacts,
) -> None:
    """Store a materialized artifact bundle in the bounded in-memory cache."""
    if not _ATTACK_PATHS_MATERIALIZED_CACHE_ENABLED:
        return
    key = (str(domain or "").strip().lower(), artifacts.fingerprint)
    _ATTACK_PATHS_MATERIALIZED_CACHE[key] = artifacts
    _ATTACK_PATHS_MATERIALIZED_CACHE.move_to_end(key)
    while (
        len(_ATTACK_PATHS_MATERIALIZED_CACHE)
        > _ATTACK_PATHS_MATERIALIZED_CACHE_MAX_ENTRIES
    ):
        _ATTACK_PATHS_MATERIALIZED_CACHE.popitem(last=False)


def _invalidate_materialized_attack_path_cache(domain: str) -> None:
    """Invalidate in-memory + on-disk materialized artifacts for a domain."""
    domain_key = str(domain or "").strip().lower()
    keys = list(_ATTACK_PATHS_MATERIALIZED_CACHE.keys())
    for key in keys:
        if key and str(key[0] or "").strip().lower() == domain_key:
            _ATTACK_PATHS_MATERIALIZED_CACHE.pop(key, None)
    runtime_keys = list(_ATTACK_PATHS_PREPARED_RUNTIME_GRAPH_CACHE.keys())
    for key in runtime_keys:
        if key and str(key[0] or "").strip().lower() == domain_key:
            _ATTACK_PATHS_PREPARED_RUNTIME_GRAPH_CACHE.pop(key, None)


# NOTE (2026-09-09, invalidation-SSOT unification): the imperative helper
# ``force_fresh_attack_paths_recompute`` was DELETED. Under the structural epoch
# the compute-cache key IS the epoch, so the post-execution refresh flows recompute
# via their own ``recompute_summaries`` callback and the epoch alone decides HIT
# (status-only write -> warm serve with re-derive) vs MISS (topology change -> fresh
# compute). A dedicated force-drop is redundant (topology change re-keys the entry)
# and harmful (a status write would cold the warm serve). The materialized/prepared
# caches stay a separate mtime-keyed subsystem (their fingerprint refuses a stale
# hit), so no imperative drop is needed for them either.
# See docs/superpowers/specs/2026-09-09-invalidation-ssot-unification-design.md.


def _build_recursive_membership_closure(
    domain: str,
    snapshot: dict[str, Any],
) -> dict[str, tuple[str, ...]]:
    """Build ``principal -> recursive groups`` from the membership snapshot."""
    user_to_groups = snapshot.get("user_to_groups")
    computer_to_groups = snapshot.get("computer_to_groups")
    group_to_parents = snapshot.get("group_to_parents")
    if not isinstance(user_to_groups, dict) and not isinstance(
        computer_to_groups, dict
    ):
        return {}

    recursive_groups_by_principal: dict[str, tuple[str, ...]] = {}
    ancestor_cache: dict[str, set[str]] = {}
    direct_maps = []
    if isinstance(user_to_groups, dict):
        direct_maps.append(user_to_groups)
    if isinstance(computer_to_groups, dict):
        direct_maps.append(computer_to_groups)

    for direct_map in direct_maps:
        for principal_label, direct_groups in direct_map.items():
            if not isinstance(direct_groups, list):
                continue
            principal = attack_paths_core._canonical_membership_label(  # noqa: SLF001
                domain,
                principal_label,
            )
            if not principal:
                continue
            expanded: set[str] = set()
            for group_label in direct_groups:
                canonical_group = attack_paths_core._canonical_membership_label(  # noqa: SLF001
                    domain,
                    group_label,
                )
                if not canonical_group:
                    continue
                expanded.add(canonical_group)
                expanded.update(
                    attack_paths_core._expand_group_ancestors(  # noqa: SLF001
                        domain,
                        canonical_group,
                        group_to_parents if isinstance(group_to_parents, dict) else {},
                        ancestor_cache,
                    )
                )
            if expanded:
                recursive_groups_by_principal[principal] = tuple(sorted(expanded))
    return recursive_groups_by_principal


def _build_recursive_group_ancestor_closure(
    domain: str,
    snapshot: dict[str, Any],
) -> dict[str, tuple[str, ...]]:
    """Build ``group -> recursive parent groups`` from the membership snapshot."""
    group_to_parents = snapshot.get("group_to_parents")
    if not isinstance(group_to_parents, dict):
        return {}

    ancestor_cache: dict[str, set[str]] = {}
    recursive_parents_by_group: dict[str, tuple[str, ...]] = {}
    for group_label in group_to_parents:
        canonical_group = attack_paths_core._canonical_membership_label(  # noqa: SLF001
            domain,
            group_label,
        )
        if not canonical_group:
            continue
        expanded = attack_paths_core._expand_group_ancestors(  # noqa: SLF001
            domain,
            canonical_group,
            group_to_parents,
            ancestor_cache,
        )
        if expanded:
            recursive_parents_by_group[canonical_group] = tuple(sorted(expanded))
    return recursive_parents_by_group


def _apply_recursive_target_priority_overrides(
    graph: dict[str, Any],
    snapshot: dict[str, Any] | None,
    *,
    domain: str,
) -> bool:
    """No-op compatibility shim.

    BloodHound is the source of truth for target criticality (tier-zero/high-value).
    ADscan now layers follow-up/terminal semantics on top of that instead of
    mutating criticality recursively in the local graph.
    """
    _ = graph, snapshot, domain
    return False


def _load_or_build_materialized_attack_path_artifacts(
    shell: object,
    *,
    domain: str,
    base_graph: dict[str, Any],
    snapshot: dict[str, Any] | None,
) -> MaterializedAttackPathArtifacts | None:
    """Load or build reusable derived artifacts for attack-path runtime stitching."""
    if not _ATTACK_PATHS_MATERIALIZED_CACHE_ENABLED or not snapshot:
        return None

    # A MERGED multi-domain graph must NOT read/write the per-domain disk cache:
    # that cache fingerprints on the single-domain graph FILE, so caching merged
    # content under the primary domain's key would poison the single-domain path.
    # Build the artifacts fresh, in memory, from the merged graph instead.
    if bool(base_graph.get("_merged_domains")):
        return MaterializedAttackPathArtifacts(
            fingerprint="merged",
            node_id_by_label=attack_paths_core._build_node_id_index_by_canonical_label(  # noqa: SLF001
                base_graph,
                domain=domain,
            ),
            recursive_groups_by_principal=_build_recursive_membership_closure(
                domain, snapshot
            ),
            storage_format="memory",
        )

    graph_path = _graph_path(shell, domain)
    snapshot_path = _membership_snapshot_path(shell, domain)
    fingerprint = build_attack_path_artifact_fingerprint(
        graph_path=graph_path,
        snapshot_path=snapshot_path,
        schema_version=ATTACK_GRAPH_SCHEMA_VERSION,
    )

    cached = _materialized_cache_get(domain, fingerprint=fingerprint)
    if cached is not None:
        return cached

    loaded = load_materialized_attack_path_artifacts(
        shell=shell,
        domain=domain,
        fingerprint=fingerprint,
    )
    if loaded is not None:
        _materialized_cache_put(domain, loaded)
        print_info_debug(
            f"[attack_paths] materialized artifacts cache hit: "
            f"domain={mark_sensitive(domain, 'domain')} format={loaded.storage_format}"
        )
        return loaded

    node_id_by_label = attack_paths_core._build_node_id_index_by_canonical_label(  # noqa: SLF001
        base_graph,
        domain=domain,
    )
    recursive_groups_by_principal = _build_recursive_membership_closure(
        domain, snapshot
    )
    built = MaterializedAttackPathArtifacts(
        fingerprint=fingerprint,
        node_id_by_label=node_id_by_label,
        recursive_groups_by_principal=recursive_groups_by_principal,
        storage_format="memory",
    )
    persist_materialized_attack_path_artifacts(
        shell=shell,
        domain=domain,
        artifacts=built,
    )
    persisted = load_materialized_attack_path_artifacts(
        shell=shell,
        domain=domain,
        fingerprint=fingerprint,
    )
    final = persisted or built
    _materialized_cache_put(domain, final)
    return final


def _prepared_runtime_graph_cache_get(
    domain: str,
    *,
    fingerprint: str,
) -> MaterializedPreparedRuntimeGraph | None:
    """Return a matching in-memory prepared runtime graph bundle."""
    if not _ATTACK_PATHS_MATERIALIZED_CACHE_ENABLED:
        return None
    key = (str(domain or "").strip().lower(), fingerprint)
    cached = _ATTACK_PATHS_PREPARED_RUNTIME_GRAPH_CACHE.get(key)
    if cached is None:
        return None
    _ATTACK_PATHS_PREPARED_RUNTIME_GRAPH_CACHE.move_to_end(key)
    return cached


def _prepared_runtime_graph_cache_put(
    domain: str,
    prepared_graph: MaterializedPreparedRuntimeGraph,
) -> None:
    """Store a prepared runtime graph in the bounded in-memory cache."""
    if not _ATTACK_PATHS_MATERIALIZED_CACHE_ENABLED:
        return
    key = (str(domain or "").strip().lower(), prepared_graph.fingerprint)
    _ATTACK_PATHS_PREPARED_RUNTIME_GRAPH_CACHE[key] = prepared_graph
    _ATTACK_PATHS_PREPARED_RUNTIME_GRAPH_CACHE.move_to_end(key)
    while (
        len(_ATTACK_PATHS_PREPARED_RUNTIME_GRAPH_CACHE)
        > _ATTACK_PATHS_MATERIALIZED_CACHE_MAX_ENTRIES
    ):
        _ATTACK_PATHS_PREPARED_RUNTIME_GRAPH_CACHE.popitem(last=False)


def _build_prepared_runtime_graph(
    *,
    base_graph: dict[str, Any],
    domain: str,
    snapshot: dict[str, Any] | None,
    expand_terminal_memberships: bool,
    materialized_artifacts: MaterializedAttackPathArtifacts | None,
) -> dict[str, Any]:
    """Build a reusable runtime graph with terminal memberships already expanded."""
    runtime_graph: dict[str, Any] = dict(base_graph)
    runtime_graph["nodes"] = dict(
        base_graph.get("nodes") if isinstance(base_graph.get("nodes"), dict) else {}
    )
    runtime_graph["edges"] = list(
        base_graph.get("edges") if isinstance(base_graph.get("edges"), list) else []
    )
    if (
        expand_terminal_memberships
        and snapshot
        and not attack_paths_core._graph_has_persisted_memberships(runtime_graph)  # noqa: SLF001
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
        attack_paths_core._inject_memberof_edges_from_snapshot(  # noqa: SLF001
            runtime_graph,
            domain,
            snapshot,
            principal_node_ids=candidate_to_ids,
            recursive=True,
            node_id_by_label=(
                materialized_artifacts.node_id_by_label
                if materialized_artifacts is not None
                else None
            ),
            recursive_groups_by_principal=(
                materialized_artifacts.recursive_groups_by_principal
                if materialized_artifacts is not None
                else None
            ),
        )
    runtime_graph["_attack_paths_terminal_memberships_materialized"] = True
    return runtime_graph


def _load_or_build_prepared_runtime_graph(
    shell: object,
    *,
    domain: str,
    base_graph: dict[str, Any],
    snapshot: dict[str, Any] | None,
    expand_terminal_memberships: bool,
    materialized_artifacts: MaterializedAttackPathArtifacts | None,
) -> dict[str, Any]:
    """Load or build a reusable prepared runtime graph for local DFS scopes.

    The prepared runtime graph is DISK-materialized and fingerprinted on the
    graph FILE's mtime, so the in-memory foreign-DC enrichment (which depends on
    live ``domains_data`` and never touches the file) would be bypassed by a
    stale disk/memory cache. It is therefore re-applied to whatever graph this
    returns — the graph the DFS actually consumes — on every call. Idempotent
    and a no-op when no foreign DC matches the inventory.
    """
    prepared = _load_or_build_prepared_runtime_graph_raw(
        shell,
        domain=domain,
        base_graph=base_graph,
        snapshot=snapshot,
        expand_terminal_memberships=expand_terminal_memberships,
        materialized_artifacts=materialized_artifacts,
    )
    _enrich_foreign_dc_nodes(shell, domain, prepared)
    return prepared


def _load_or_build_prepared_runtime_graph_raw(
    shell: object,
    *,
    domain: str,
    base_graph: dict[str, Any],
    snapshot: dict[str, Any] | None,
    expand_terminal_memberships: bool,
    materialized_artifacts: MaterializedAttackPathArtifacts | None,
) -> dict[str, Any]:
    """Load or build a reusable prepared runtime graph for local DFS scopes."""
    # A MERGED multi-domain graph must build fresh in-memory and NEVER touch the
    # per-domain disk cache (fingerprinted on the single-domain graph file), or it
    # would poison the single-domain prepared graph with cross-domain content.
    if not _ATTACK_PATHS_MATERIALIZED_CACHE_ENABLED or bool(
        base_graph.get("_merged_domains")
    ):
        return _build_prepared_runtime_graph(
            base_graph=base_graph,
            domain=domain,
            snapshot=snapshot,
            expand_terminal_memberships=expand_terminal_memberships,
            materialized_artifacts=materialized_artifacts,
        )

    graph_path = _graph_path(shell, domain)
    snapshot_path = _membership_snapshot_path(shell, domain)
    fingerprint = build_attack_path_artifact_fingerprint(
        graph_path=graph_path,
        snapshot_path=snapshot_path,
        schema_version=f"{ATTACK_GRAPH_SCHEMA_VERSION}:prepared:{int(expand_terminal_memberships)}",
    )

    cached = _prepared_runtime_graph_cache_get(domain, fingerprint=fingerprint)
    if cached is not None:
        return dict(cached.graph)

    loaded = load_materialized_prepared_runtime_graph(
        shell=shell,
        domain=domain,
        fingerprint=fingerprint,
    )
    if loaded is not None:
        _prepared_runtime_graph_cache_put(domain, loaded)
        print_info_debug(
            f"[attack_paths] prepared runtime graph cache hit: "
            f"domain={mark_sensitive(domain, 'domain')} format={loaded.storage_format}"
        )
        return dict(loaded.graph)

    prepared_graph = _build_prepared_runtime_graph(
        base_graph=base_graph,
        domain=domain,
        snapshot=snapshot,
        expand_terminal_memberships=expand_terminal_memberships,
        materialized_artifacts=materialized_artifacts,
    )
    built = MaterializedPreparedRuntimeGraph(
        fingerprint=fingerprint,
        graph=prepared_graph,
        storage_format="memory",
    )
    persist_materialized_prepared_runtime_graph(
        shell=shell,
        domain=domain,
        prepared_graph=built,
    )
    persisted = load_materialized_prepared_runtime_graph(
        shell=shell,
        domain=domain,
        fingerprint=fingerprint,
    )
    final = persisted or built
    _prepared_runtime_graph_cache_put(domain, final)
    return dict(final.graph)


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
    "AttackPathSummaryFilters",
    "attack_paths_epoch_fingerprint",
    "get_attack_path_summaries",
    "get_graph_service_access_pairs",
    "get_owned_attack_path_summaries_to_target",
    "get_owned_domain_usernames_for_attack_paths",
    "get_rodc_prp_control_paths",
    "get_recursive_principal_groups_from_snapshot",
    "is_principal_member_of_rid_from_snapshot",
    "get_users_in_group_rid_from_snapshot",
    "resolve_group_name_by_rid",
    "resolve_group_user_members",
    "resolve_group_members_by_rid",
    "resolve_principal_groups",
    "resolve_target_labels",
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
    include_computers: bool = True,
) -> tuple[dict[str, set[str]], dict[str, set[str]], bool]:
    """Build group -> members index (recursive) for users and optionally computers."""
    snapshot = _load_membership_snapshot(shell, domain)
    return attack_paths_core.build_group_member_index(
        snapshot,
        domain,
        exclude_tier0=exclude_tier0,
        include_computers=include_computers,
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


#: Tier-breakdown bucket keys for the affected-account blast radius. The two
#: Tier-0 sub-tiers (direct vs escalation-capable) are collapsed into a single
#: ``tier0`` bucket — the blast-radius KPI distinguishes only the three coarse
#: ESAE tiers, while directness drives ordering/severity elsewhere.
_AFFECTED_TIER_BUCKETS: tuple[str, str, str] = ("tier0", "tier1", "tier2")


def _coarse_tier_bucket(tier: PrivilegeTier) -> str:
    """Fold a fine :class:`PrivilegeTier` onto its coarse blast-radius bucket.

    The drill-down breakdown distinguishes only ``tier0`` / ``tier1`` / ``tier2``:
    both Tier-0 sub-tiers (direct, escalation-capable) collapse into ``tier0``.
    The SINGLE place the fold is defined so the per-account classification and the
    aggregate breakdown can never disagree (the per-account fine tiers always sum
    back to the coarse breakdown).
    """
    if tier in (PrivilegeTier.TIER0_DIRECT, PrivilegeTier.TIER0_ESCALATION_CAPABLE):
        return "tier0"
    if tier is PrivilegeTier.TIER1:
        return "tier1"
    return "tier2"


def _affected_users_tier_classification(
    users: Iterable[str],
    tier_resolver: Callable[[str], PrivilegeTier],
) -> tuple[dict[str, int], dict[str, str]]:
    """Classify affected accounts into a coarse breakdown AND a per-account map.

    The drill-down for "accounts that can take over the domain" surfaces a
    Tier-2 standard user with a validated path to domain compromise (the headline
    delta) against the Tier-0 members that can take over because they ALREADY are
    admins. The aggregate breakdown drives the summary counts; the per-account
    map lets the report/web badge EACH row with its own Privilege Tier.

    Both outputs come from ONE pass over ONE classification of each account, so
    the per-account fine tiers always fold back onto the coarse breakdown — they
    can never disagree.

    Args:
        users: The affected sAMAccountNames (the FULL blast radius, including
            already-Tier-0 members — they are part of who can take over).
        tier_resolver: Maps one account to its :class:`PrivilegeTier` via the
            engine SSOT (``privilege_tier_for_principal``). Injected so the pure
            classification logic is unit-testable without a shell.

    Returns:
        ``(breakdown, tier_map)`` where ``breakdown`` is
        ``{"tier0": n0, "tier1": n1, "tier2": n2}`` (the two Tier-0 sub-tiers
        folded into ``tier0``; the three buckets sum to the deduplicated account
        count) and ``tier_map`` maps each ORIGINAL (un-normalised) account string
        to its FINE :class:`PrivilegeTier` ``.value`` (``"tier0_direct"`` /
        ``"tier0_escalation_capable"`` / ``"tier1"`` / ``"tier2"``). The fine
        values preserve the directness split the coarse bucket discards, so the
        badge SSOT can render "Tier 0: Domain Control" vs "Escalation-capable".
    """
    breakdown = {bucket: 0 for bucket in _AFFECTED_TIER_BUCKETS}
    tier_map: dict[str, str] = {}
    seen: set[str] = set()
    for raw in users:
        user = str(raw or "").strip()
        if not user:
            continue
        key = user.lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            tier = tier_resolver(user)
        except Exception:  # noqa: BLE001 - a single bad lookup never breaks the report
            tier = PrivilegeTier.TIER2
        breakdown[_coarse_tier_bucket(tier)] += 1
        tier_map[user] = tier.value
    return breakdown, tier_map


def _affected_users_tier_breakdown(
    users: Iterable[str],
    tier_resolver: Callable[[str], PrivilegeTier],
) -> dict[str, int]:
    """Coarse Tier 0 / 1 / 2 breakdown of the affected accounts.

    Thin wrapper over :func:`_affected_users_tier_classification` that keeps only
    the aggregate buckets. Retained as the stable public helper for callers (and
    tests) that need the breakdown alone.
    """
    breakdown, _tier_map = _affected_users_tier_classification(users, tier_resolver)
    return breakdown


def _build_label_kind_and_sid_maps(
    domain: str,
    graph: dict[str, Any] | None,
    snapshot: dict[str, Any] | None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Index the graph (and snapshot) by canonical membership label.

    Returns ``(label -> node kind, label -> SID)``. The SID half is what lets a
    principal's Privilege Tier account for its own RID (500 Administrator, 502
    krbtgt) rather than only its group closure; the snapshot's ``label_to_sid``
    fills in any principal the graph did not carry an ``objectId`` for.
    """
    label_kind_map: dict[str, str] = {}
    label_sid_map: dict[str, str] = {}
    nodes_map = graph.get("nodes") if isinstance(graph, dict) else None
    if isinstance(nodes_map, dict):
        for node in nodes_map.values():
            if not isinstance(node, dict):
                continue
            canonical = _canonical_membership_label(domain, _canonical_node_label(node))
            if not canonical:
                continue
            label_kind_map[canonical] = _node_kind(node)
            props = (
                node.get("properties")
                if isinstance(node.get("properties"), dict)
                else {}
            )
            object_id = str(
                node.get("objectId")
                or props.get("objectid")
                or props.get("objectId")
                or ""
            ).strip()
            sid = attack_paths_core._extract_sid(object_id)  # noqa: SLF001
            if sid:
                label_sid_map[canonical] = sid
    if isinstance(snapshot, dict):
        snapshot_label_to_sid = snapshot.get("label_to_sid")
        if isinstance(snapshot_label_to_sid, dict):
            for label, sid in snapshot_label_to_sid.items():
                canonical = _canonical_membership_label(domain, str(label or ""))
                normalized_sid = normalize_sid(str(sid or ""))
                if canonical and normalized_sid:
                    label_sid_map.setdefault(canonical, normalized_sid)
    return label_kind_map, label_sid_map


def _classify_accounts_by_privilege_tier(
    shell: object,
    domain: str,
    users: Iterable[str],
    *,
    label_sid_map: Mapping[str, str],
    membership_closure: Mapping[str, tuple[str, ...]],
) -> tuple[dict[str, int], dict[str, str]]:
    """Grade a set of accounts by the Privilege Tier each one IS GRANTED.

    Returns ``(coarse {tier0,tier1,tier2} breakdown, account -> fine tier value)``.

    The one classification behind every account-tier figure ADscan reports: the
    Tier split of the accounts a path affects AND the Tier split of the account
    POPULATION the exposure KPIs measure against. They have to come from the same
    resolver, because the two are compared — an affected Tier-0 count larger than
    the population's would be arithmetic nobody could defend.

    Grading is the engine SSOT ``privilege_tier_for_principal`` over each
    account's TRANSITIVE group closure, with its own RID read from the SID, and
    the identity-risk Tier-0 flag as a floor for an account the snapshot did not
    cover.
    """
    normalized_users = sorted(
        {
            normalize_samaccountname(str(user))
            for user in users
            if normalize_samaccountname(str(user))
        },
        key=str.lower,
    )
    if not normalized_users:
        return {bucket: 0 for bucket in _AFFECTED_TIER_BUCKETS}, {}
    risk_flags = classify_users_tier0_high_value(
        shell,
        domain=domain,
        usernames=normalized_users,
    )

    def _resolver(samaccountname: str) -> PrivilegeTier:
        canonical = _canonical_membership_label(domain, samaccountname)
        groups = membership_closure.get(canonical, ()) if canonical else ()
        sid = label_sid_map.get(canonical or "", "") if canonical else ""
        tier = privilege_tier_for_principal(list(groups), sid=sid or None)
        if not tier.is_tier0:
            risk = risk_flags.get(normalize_samaccountname(str(samaccountname)))
            if bool(getattr(risk, "is_tier0", False)):
                return PrivilegeTier.TIER0_DIRECT
        return tier

    return _affected_users_tier_classification(normalized_users, _resolver)


def classify_accounts_by_privilege_tier(
    shell: object,
    domain: str,
    users: Iterable[str],
) -> tuple[dict[str, int], dict[str, str]]:
    """Public front door over :func:`_classify_accounts_by_privilege_tier`.

    Loads the attack graph and membership snapshot itself, for callers that hold
    only a shell and a domain (the account-population tier split behind the
    privilege-sprawl KPI). Callers already holding both should use the private
    form and pass their loaded copies rather than re-reading the workspace.
    """
    graph = load_attack_graph(shell, domain)
    snapshot = _load_membership_snapshot(shell, domain)
    _kinds, label_sid_map = _build_label_kind_and_sid_maps(domain, graph, snapshot)
    membership_closure = (
        _build_recursive_membership_closure(domain, snapshot)
        if isinstance(snapshot, dict)
        else {}
    )
    return _classify_accounts_by_privilege_tier(
        shell,
        domain,
        users,
        label_sid_map=label_sid_map,
        membership_closure=membership_closure,
    )


def _affected_metadata_group_key(record: dict[str, Any]) -> tuple[str, str, str]:
    """Return the key that fully captures the per-path annotation inputs.

    ``_apply_affected_user_metadata``'s per-path body is a pure function of
    exactly these three things — the source principal (``nodes[0]``), the first
    relation (which drives ``_derive_execution_scope_metadata``), and the
    incoming affected-user meta signature. Two records with the same key produce
    an identical annotation delta, so the annotation can be computed once per key
    and broadcast, byte-identically, across the whole group.
    """
    nodes = record.get("nodes")
    source_label = (
        str(nodes[0] or "").strip() if isinstance(nodes, list) and nodes else ""
    )
    relations = record.get("relations")
    first_relation = (
        str(relations[0] or "").strip()
        if isinstance(relations, list) and relations
        else ""
    )
    relation_key = _normalize_relation_key(first_relation)
    meta = record.get("meta") if isinstance(record.get("meta"), dict) else {}
    affected_users = meta.get("affected_users") or []
    users_sig = "|".join(
        sorted(
            str(user).lower()
            for user in affected_users
            if isinstance(user, str) and str(user).strip()
        )
    )
    meta_sig = (
        f"{users_sig}"
        f"#uc={meta.get('affected_user_count')!r}"
        f"#pc={meta.get('affected_principal_count')!r}"
        f"#cc={meta.get('affected_computer_count')!r}"
        f"#src={meta.get('affected_users_source')!r}"
    )
    return (source_label, relation_key, meta_sig)


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
    base_graph = _load_attack_graph_for_paths(shell, domain)
    annotated = attack_paths_core.apply_affected_user_metadata(
        records,
        graph=base_graph,
        domain=domain,
        snapshot=snapshot,
        filter_empty=filter_empty,
    )
    if not annotated:
        return []

    label_kind_map, label_sid_map = _build_label_kind_and_sid_maps(
        domain, base_graph, snapshot
    )

    group_members, _computer_group_members, has_users = (
        attack_paths_core.build_group_member_index(
            snapshot, domain, exclude_tier0=True, include_computers=False
        )
    )
    broad_group_resolution_cache: dict[str, tuple[list[str], str]] = {}
    # Cache of the per-domain Tier 0/1/2 blast-radius classification, keyed by
    # scope label, so a broad-group path shared across many records classifies
    # once. Holds BOTH the coarse breakdown and the per-account fine-tier map.
    broad_group_tier_classification_cache: dict[
        str, tuple[dict[str, int], dict[str, str]]
    ] = {}

    # Recursive (transitive) group closure for principals, so a user's own
    # Privilege Tier is derived from EVERY group it belongs to, not just the
    # direct ones — the same transitive view the collector stamps onto
    # users.json. Built once per call and reused by the tier resolver below.
    _membership_closure: dict[str, tuple[str, ...]] = (
        _build_recursive_membership_closure(domain, snapshot)
        if isinstance(snapshot, dict)
        else {}
    )

    def _tier_classification_for_affected(
        users: list[str],
    ) -> tuple[dict[str, int], dict[str, str]]:
        """Tier 0/1/2 classification for a broad-group affected-account set.

        Delegates to the shared account grader
        (:func:`_classify_accounts_by_privilege_tier`) with the graph/snapshot
        indexes this call already built, so the affected set and the account
        POPULATION behind the sprawl KPI are graded by one resolver and their
        Tier-0 counts always reconcile.
        """
        return _classify_accounts_by_privilege_tier(
            shell,
            domain,
            users,
            label_sid_map=label_sid_map,
            membership_closure=_membership_closure,
        )

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

    def _annotate_one(record: dict[str, Any]) -> dict[str, Any]:
        """Compute the enriched record for ONE path.

        This is the original per-path loop body, extracted verbatim so the
        group-by-scope broadcast below can run it on ONE representative per
        distinct scope key and reuse the result across every path that shares
        the key. The shared per-scope caches (``broad_group_resolution_cache``,
        ``broad_group_tier_classification_cache``) remain live across
        representatives, so cross-key work is still memoized once.
        """
        current = dict(record)
        meta = current.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            current["meta"] = meta

        nodes = current.get("nodes")
        if not isinstance(nodes, list) or not nodes:
            return current
        source_label = str(nodes[0] or "").strip()
        execution_scope = _derive_execution_scope_metadata(current, source_label)
        if execution_scope:
            meta.update(execution_scope)
        scope_label = _canonical_membership_label(domain, source_label)
        if not scope_label:
            return current

        scope_name = _membership_label_to_name(scope_label).upper()
        source_name = scope_name
        kind = label_kind_map.get(scope_label, "")
        broad_group_scope = _classify_broad_group_scope(
            domain,
            scope_label,
            label_sid_map=label_sid_map,
        )
        is_broad_group_scope = kind == "Group" and broad_group_scope is not None
        existing_users = [
            str(user).strip()
            for user in meta.get("affected_users", [])
            if isinstance(user, str) and str(user).strip()
        ]
        existing_users_normalized = sorted(
            {user.lower() for user in existing_users},
            key=str.lower,
        )
        existing_user_count = (
            int(meta.get("affected_user_count", 0))
            if isinstance(meta.get("affected_user_count"), int)
            else len(existing_users_normalized)
        )
        existing_computer_count = (
            int(meta.get("affected_computer_count", 0))
            if isinstance(meta.get("affected_computer_count"), int)
            else 0
        )

        should_override = (
            not isinstance(meta.get("affected_principal_count"), int)
            or int(meta.get("affected_principal_count", 0)) <= 0
        ) and (
            not isinstance(meta.get("affected_user_count"), int)
            or int(meta.get("affected_user_count", 0)) <= 0
        )
        if not should_override and not is_broad_group_scope:
            return current

        affected_users: list[str] = []
        affected_count = 0
        affected_source = ""
        if kind == "Group":
            if is_broad_group_scope and scope_label in broad_group_resolution_cache:
                affected_users, affected_source = broad_group_resolution_cache[
                    scope_label
                ]
                affected_count = len(affected_users)
            else:
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
                elif is_broad_group_scope and fallback_domain_users:
                    affected_users = list(fallback_domain_users)
                    affected_count = len(affected_users)
                    affected_source = fallback_domain_users_source
                elif has_users:
                    affected_users = sorted(
                        group_members.get(scope_label, set()), key=str.lower
                    )
                    affected_count = len(affected_users)
                    if affected_count > 0:
                        affected_source = "snapshot_group_members"
                if is_broad_group_scope:
                    # Blast-radius fix: the affected set for "accounts that can
                    # take over the domain" is the FULL broad-group population —
                    # the already-Tier-0 members can take over because they ARE
                    # admins, the lower-tier members because they reach Tier 0
                    # via the path. We DO NOT strip the Tier-0 members here (the
                    # old behaviour undercounted by exactly that delta); instead
                    # we expose a Tier 0/1/2 breakdown of the full set so the
                    # report/web can surface the delta. Stored is the full set.
                    broad_group_resolution_cache[scope_label] = (
                        list(affected_users),
                        affected_source,
                    )
        elif scope_label:
            affected_users = [_membership_label_to_name(scope_label)]
            affected_count = 1
            affected_source = "principal"

        should_apply_resolution = should_override
        resolution_reason = "fill_missing_metadata"
        if is_broad_group_scope and affected_count > 0:
            resolved_users_normalized = sorted(
                {user.lower() for user in affected_users},
                key=str.lower,
            )
            should_apply_resolution = (
                resolved_users_normalized != existing_users_normalized
                or affected_count != existing_user_count
            )
            resolution_reason = "refresh_broad_group_metadata"
            print_info_debug(
                "[attack_paths] broad-group affected user evaluation: "
                f"domain={mark_sensitive(domain, 'domain')} "
                f"source={mark_sensitive(source_name or 'N/A', 'group')} "
                f"scope={mark_sensitive(scope_name, 'group')} "
                f"classification={broad_group_scope or 'N/A'} "
                f"existing_count={existing_user_count} "
                f"resolved_count={affected_count} "
                f"existing_source={meta.get('affected_users_source') or 'N/A'} "
                f"resolved_source={affected_source or 'N/A'} "
                f"replace={should_apply_resolution}"
            )

        if affected_count > 0 and should_apply_resolution:
            affected_principal_count = affected_count + max(0, existing_computer_count)
            meta["affected_user_count"] = affected_count
            meta["affected_users"] = affected_users
            meta["affected_principal_count"] = affected_principal_count
            if affected_source:
                meta["affected_users_source"] = affected_source
            print_info_debug(
                "[attack_paths] affected users metadata updated: "
                f"domain={mark_sensitive(domain, 'domain')} "
                f"source={mark_sensitive(source_name or 'N/A', 'group')} "
                f"scope={mark_sensitive(scope_name, 'group')} "
                f"classification={broad_group_scope or 'N/A'} "
                f"reason={resolution_reason} "
                f"count={affected_count} "
                f"principal_count={affected_principal_count} "
                f"resolver={affected_source or 'N/A'}"
            )
            if affected_source == "group_resolver":
                print_info_debug(
                    "[attack_paths] affected users resolved through centralized group membership resolver: "
                    f"domain={mark_sensitive(domain, 'domain')} "
                    f"source={source_name or 'N/A'} "
                    f"scope={scope_name} "
                    f"count={affected_count}"
                )
            elif is_broad_group_scope and fallback_domain_users_source:
                print_info_debug(
                    "[attack_paths] affected users derived from broad group scope: "
                    f"domain={mark_sensitive(domain, 'domain')} "
                    f"source={source_name or 'N/A'} "
                    f"scope={scope_name} "
                    f"count={affected_count} "
                    f"fallback={fallback_domain_users_source}"
                )
        elif is_broad_group_scope:
            print_info_debug(
                "[attack_paths] broad-group affected users metadata preserved: "
                f"domain={mark_sensitive(domain, 'domain')} "
                f"source={mark_sensitive(source_name or 'N/A', 'group')} "
                f"scope={mark_sensitive(scope_name, 'group')} "
                f"classification={broad_group_scope or 'N/A'} "
                f"existing_count={existing_user_count} "
                f"resolver={affected_source or 'N/A'}"
            )

        # Explicit broad-group BOOLEAN CONTRACT (Defect A fix). The downstream
        # exposure-KPI aggregator must NOT infer "all enabled domain users" from
        # the fragile ``affected_users_source`` string allowlist (which drifted
        # out of sync with the resolver's actual source tokens). It reads THIS
        # boolean, stamped directly from the ``is_broad_group_scope`` the
        # materializer already computed. Stamped for every broad-group path —
        # independent of whether the user list itself was refreshed this pass —
        # so idempotent re-runs and the metadata-preserved branch both carry it.
        if is_broad_group_scope:
            meta["affected_users_all_enabled"] = True
            # Tier 0/1/2 classification of the FULL blast radius (the drill-down
            # the report/web consume to surface the Tier-2 -> Tier-0 delta).
            # Computed once per scope label and reused across every path sharing
            # it. Stamps BOTH the coarse breakdown (summary counts) and the
            # per-account fine-tier map (so every drill-down row can be badged by
            # its own Privilege Tier). Both come from ONE classification pass, so
            # the per-account tiers always fold back onto the breakdown.
            breakdown_users = (
                meta.get("affected_users")
                if isinstance(meta.get("affected_users"), list)
                else affected_users
            )
            if scope_label in broad_group_tier_classification_cache:
                tier_breakdown, tier_map = broad_group_tier_classification_cache[
                    scope_label
                ]
            else:
                tier_breakdown, tier_map = _tier_classification_for_affected(
                    [str(u) for u in (breakdown_users or []) if isinstance(u, str)]
                )
                broad_group_tier_classification_cache[scope_label] = (
                    tier_breakdown,
                    tier_map,
                )
            meta["affected_users_tier_breakdown"] = dict(tier_breakdown)
            meta["affected_users_tier_map"] = dict(tier_map)

        return current

    # Group-by-scope + broadcast. The per-path body above is a PURE function of
    # (source_label, first-relation key, incoming-meta signature): every field
    # it reads comes from ``record["nodes"][0]``, ``record["relations"][0]`` (via
    # ``_derive_execution_scope_metadata``) and the incoming ``meta`` fields the
    # signature captures. On a domain-wide graph, all N paths typically share ONE
    # scope with ONE identical incoming-meta signature, so the original loop
    # recomputed the identical annotation N times. Instead we compute it ONCE per
    # distinct key on a representative record and broadcast the resulting meta
    # delta to every path in the group. This drops L15k domain/all from ~27s to
    # ~10s and roughly halves peak RSS, byte-identically.
    groups: dict[tuple[str, str, str], list[int]] = {}
    key_order: list[tuple[str, str, str]] = []
    for idx, record in enumerate(annotated):
        key = _affected_metadata_group_key(record)
        bucket = groups.get(key)
        if bucket is None:
            groups[key] = bucket = []
            key_order.append(key)
        bucket.append(idx)

    enriched: list[dict[str, Any]] = [None] * len(annotated)  # type: ignore[list-item]
    for key in key_order:
        indices = groups[key]
        rep_idx = indices[0]
        rep_record = annotated[rep_idx]
        # Snapshot the representative's INCOMING meta values BEFORE annotating.
        # ``_annotate_one`` mutates ``record["meta"]`` in place (it aliases the
        # shallow-copied ``current["meta"]``), so ``rep_record["meta"]`` is the
        # SAME dict as the output — a post-hoc comparison against it would miss
        # every overwritten key. This frozen copy is what the delta is measured
        # against.
        rep_meta_in = rep_record.get("meta")
        rep_meta_before = dict(rep_meta_in) if isinstance(rep_meta_in, dict) else {}
        rep_current = _annotate_one(rep_record)
        enriched[rep_idx] = rep_current
        if len(indices) == 1:
            continue
        rep_meta_out = rep_current.get("meta")
        if not isinstance(rep_meta_out, dict):
            # Defensive: nothing to broadcast — annotate each member directly.
            for member_idx in indices[1:]:
                enriched[member_idx] = _annotate_one(annotated[member_idx])
            continue
        # The delta is exactly the keys the representative's body added or
        # modified relative to its incoming meta. The signature guarantees each
        # member's incoming meta matches the representative on those fields, so
        # applying the same delta is byte-identical to running the body per
        # member. We SHARE the large ``affected_users``/``affected_computers``
        # list references (read-only / wholesale-replaced downstream — same
        # precedent as commit 0c7038e19), and re-copy the small tier dicts so no
        # two records alias one dict.
        _MISSING = object()
        delta_keys = [
            mk
            for mk in rep_meta_out
            if rep_meta_out[mk] is not rep_meta_before.get(mk, _MISSING)
        ]
        for member_idx in indices[1:]:
            member_record = annotated[member_idx]
            member_current = dict(member_record)
            member_meta_in = member_current.get("meta")
            member_meta = (
                dict(member_meta_in) if isinstance(member_meta_in, dict) else {}
            )
            for mk in delta_keys:
                mv = rep_meta_out[mk]
                if mk in ("affected_users_tier_breakdown", "affected_users_tier_map"):
                    member_meta[mk] = dict(mv) if isinstance(mv, dict) else mv
                else:
                    member_meta[mk] = mv
            member_current["meta"] = member_meta
            enriched[member_idx] = member_current

    return [record for record in enriched if record is not None]


def _classify_broad_group_scope(
    domain: str,
    scope_label: str,
    *,
    label_sid_map: dict[str, str],
) -> str | None:
    """Return the canonical broad-group classification for a scope label."""
    canonical_scope = _canonical_membership_label(domain, scope_label)
    if not canonical_scope:
        return None

    sid = normalize_sid(label_sid_map.get(canonical_scope, ""))
    rid = sid_rid(sid or "")
    if sid == _EVERYONE_SID:
        return "EVERYONE"
    if sid == _AUTHENTICATED_USERS_SID:
        return "AUTHENTICATED_USERS"
    if sid == _BUILTIN_USERS_SID:
        return "USERS"
    if rid == _DOMAIN_USERS_RID and sid and sid.startswith("S-1-5-21-"):
        return "DOMAIN_USERS"

    scope_name = _membership_label_to_name(canonical_scope).upper()
    if scope_name == "EVERYONE":
        return "EVERYONE"
    if scope_name == "AUTHENTICATED USERS":
        return "AUTHENTICATED_USERS"
    if scope_name == "USERS":
        return "USERS"
    if scope_name == "DOMAIN USERS":
        return "DOMAIN_USERS"
    return None


def _derive_execution_scope_metadata(
    record: dict[str, Any],
    source_label: str,
) -> dict[str, str]:
    """Return execution-scope metadata for synthetic entry principals."""
    normalized_source = _membership_label_to_name(source_label).strip().upper()
    if not normalized_source:
        return {}

    relations = record.get("relations")
    first_relation = (
        str(relations[0] or "").strip()
        if isinstance(relations, list) and relations
        else ""
    )
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
    """Return (category, vuln_key) for a relation.

    Thin alias over the catalog SSOT :func:`classify_edge_relation`, kept because
    several call sites in this module already read this private name.
    """
    return classify_edge_relation(relation)


def _writable_attribute_report_path(
    domain_dir: str,
) -> str | None:
    """Return the canonical writable-attribute cache path for one domain."""
    if not domain_dir:
        return None
    acl_dir = os.path.join(domain_dir, "acl")
    if not os.path.isdir(acl_dir):
        try:
            os.makedirs(acl_dir, exist_ok=True)
        except OSError:
            return None
    return os.path.join(acl_dir, "writable_attributes_domain.json")


def _rodc_prp_report_path(
    domain_dir: str,
) -> str | None:
    """Return the canonical RODC PRP control cache path for one domain."""
    if not domain_dir:
        return None
    acl_dir = os.path.join(domain_dir, "acl")
    if not os.path.isdir(acl_dir):
        try:
            os.makedirs(acl_dir, exist_ok=True)
        except OSError:
            return None
    return os.path.join(acl_dir, "rodc_prp_writers_domain.json")


def _load_writable_attribute_report(
    domain_dir: str,
) -> dict[str, Any] | None:
    """Load cached writable-attribute findings when present."""
    report_path = _writable_attribute_report_path(domain_dir)
    if not report_path or not os.path.exists(report_path):
        return None
    try:
        report = read_json_file(report_path)
        return report if isinstance(report, dict) else None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _persist_writable_attribute_report(
    domain_dir: str,
    report: dict[str, Any],
) -> None:
    """Persist writable-attribute findings for one domain."""
    report_path = _writable_attribute_report_path(domain_dir)
    if not report_path:
        return
    try:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        write_json_file(report_path, report)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _load_rodc_prp_report(
    domain_dir: str,
) -> dict[str, Any] | None:
    """Load cached RODC PRP findings when present."""
    report_path = _rodc_prp_report_path(domain_dir)
    if not report_path or not os.path.exists(report_path):
        return None
    try:
        report = read_json_file(report_path)
        return report if isinstance(report, dict) else None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _persist_rodc_prp_report(
    domain_dir: str,
    report: dict[str, Any],
) -> None:
    """Persist RODC PRP findings for one domain."""
    report_path = _rodc_prp_report_path(domain_dir)
    if not report_path:
        return
    try:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        write_json_file(report_path, report)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _resolve_writable_attribute_report_from_graph(
    shell: object,
    domain: str,
) -> dict[str, Any]:
    """Read WriteLogonScript edges from the attack graph; no LDAP pass."""
    from datetime import datetime, timezone

    graph = load_attack_graph(shell, domain)
    nodes: dict[str, Any] = (
        graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    )
    edges: list[Any] = (
        graph.get("edges") if isinstance(graph.get("edges"), list) else []
    )
    findings: list[dict[str, Any]] = []
    for edge in edges:
        if str(edge.get("relation") or "") != "WriteLogonScript":
            continue
        from_id = edge.get("from")
        to_id = edge.get("to")
        from_node = nodes.get(from_id) if from_id else {}
        to_node = nodes.get(to_id) if to_id else {}
        from_props = (
            (from_node.get("properties") or {}) if isinstance(from_node, dict) else {}
        )
        to_props = (
            (to_node.get("properties") or {}) if isinstance(to_node, dict) else {}
        )
        findings.append(
            {
                "relation": "WriteLogonScript",
                "attribute": "scriptPath",
                "target_dn": to_props.get("distinguishedname", ""),
                "target_username": to_props.get("samaccountname", ""),
                "target_object_id": to_props.get("objectid", ""),
                "target_user_account_control": to_props.get("useraccountcontrol", 0),
                "principal_sid": from_props.get("objectid", ""),
                "ace_object_type": None,
                "applies_to_all_properties": False,
                "is_inherited": bool(edge.get("is_inherited", False)),
            }
        )
    return {
        "schema_version": "writable-attributes-domain-1.0",
        "detector": "native_graph_passthrough",
        "domain": domain,
        "attribute_guids": {},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }


def _resolve_writable_attribute_report(
    shell: object,
    domain: str,
) -> dict[str, Any] | None:
    """Load or build domain-scope writable-attribute findings for one domain."""
    from adscan_internal.services import CredentialStoreService
    from adscan_internal.services.domain_writable_attribute_detection_service import (
        DomainWritableAttributeDetectionService,
    )

    domain_key = str(domain or "").strip()
    if not domain_key:
        return None

    print_info_debug(
        "[writable-attrs] native graph mode — reading WriteLogonScript edges from attack_graph.json"
    )
    return _resolve_writable_attribute_report_from_graph(shell, domain_key)

    domain_data = getattr(shell, "domains_data", {}).get(domain_key, {})
    domain_dir = domain_data.get("dir") if isinstance(domain_data, dict) else None
    if not isinstance(domain_dir, str) or not domain_dir:
        return None

    creds = CredentialStoreService.resolve_auth_credentials(
        getattr(shell, "domains_data", {}),
        target_domain=domain_key,
        primary_domain=getattr(shell, "domain", None),
    )
    if not creds:
        print_info_debug(
            "[writable-attrs] No credentials available for writable-attribute discovery; skipping."
        )
        return None
    username, password, auth_domain = creds

    cached_report = _load_writable_attribute_report(domain_dir)
    if isinstance(cached_report, dict):
        return cached_report

    kerberos_ready = bool(
        getattr(shell, "domains_data", {}).get(domain_key, {}).get("kerberos_tickets")
    )
    if kerberos_ready:
        kerberos_ready = prepare_kerberos_ldap_environment(
            operation_name="Domain writable-attribute detection",
            target_domain=domain_key,
            workspace_dir=str(
                getattr(shell, "current_workspace_dir", "")
                or getattr(shell, "_get_workspace_cwd", lambda: "")()
                or ""
            ),
            username=str(username),
            user_domain=str(auth_domain or domain_key),
            credential=str(password),
            dc_ip=str(domain_data.get("pdc") or "")
            if isinstance(domain_data, dict)
            else None,
            domains_data=getattr(shell, "domains_data", {}),
            sync_clock=getattr(shell, "do_sync_clock_with_pdc", None),
        )
    ldap_targets = resolve_ldap_target_endpoints(
        target_domain=domain_key,
        domain_data=domain_data,
        kerberos_ready=kerberos_ready,
    )
    dc_target = ldap_targets.dc_address
    kerberos_target_hostname = ldap_targets.kerberos_target_hostname
    if not dc_target:
        print_info_debug(
            "[writable-attrs] Missing DC target for writable-attribute discovery; skipping."
        )
        return None

    print_info_debug(
        f"[writable-attrs] attempting domain-wide writable-attribute discovery for "
        f"{mark_sensitive(domain_key, 'domain')} via {mark_sensitive(str(dc_target), 'host')}"
    )
    report = (
        DomainWritableAttributeDetectionService().build_user_attribute_write_report(
            dc_address=str(dc_target),
            kerberos_target_hostname=kerberos_target_hostname,
            target_domain=domain_key,
            username=str(username),
            password=str(password),
            use_kerberos=kerberos_ready,
            use_ldaps=True,
        )
    )
    if not isinstance(report, dict):
        return None

    _persist_writable_attribute_report(domain_dir, report=report)
    return report


def _resolve_rodc_prp_report_from_graph(
    shell: object,
    domain: str,
) -> dict[str, Any]:
    """Read ManageRODCPrp edges from the attack graph; no LDAP pass."""
    from datetime import datetime, timezone

    graph = load_attack_graph(shell, domain)
    nodes: dict[str, Any] = (
        graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    )
    edges: list[Any] = (
        graph.get("edges") if isinstance(graph.get("edges"), list) else []
    )
    findings: list[dict[str, Any]] = []
    for edge in edges:
        if str(edge.get("relation") or "") != "ManageRODCPrp":
            continue
        from_id = edge.get("from")
        to_id = edge.get("to")
        from_node = nodes.get(from_id) if from_id else {}
        to_node = nodes.get(to_id) if to_id else {}
        from_props = (
            (from_node.get("properties") or {}) if isinstance(from_node, dict) else {}
        )
        to_props = (
            (to_node.get("properties") or {}) if isinstance(to_node, dict) else {}
        )
        findings.append(
            {
                "relation": "ManageRODCPrp",
                "target_dn": to_props.get("distinguishedname", ""),
                "target_machine": to_props.get("samaccountname", ""),
                "target_object_id": to_props.get("objectid", ""),
                "principal_sid": from_props.get("objectid", ""),
                "required_attributes": [
                    "msDS-RevealOnDemandGroup",
                    "msDS-NeverRevealGroup",
                ],
            }
        )
    return {
        "schema_version": "rodc-prp-writers-domain-1.0",
        "detector": "native_graph_passthrough",
        "domain": domain,
        "attribute_guids": {},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "used_ldaps": False,
    }


def _resolve_rodc_prp_report(
    shell: object,
    domain: str,
    *,
    force_refresh: bool = False,
) -> dict[str, Any] | None:
    """Load or build domain-scope delegated RODC PRP-write findings."""
    from adscan_internal.services import CredentialStoreService
    from adscan_internal.services.domain_rodc_prp_detection_service import (
        DomainRodcPrpDetectionService,
    )

    domain_key = str(domain or "").strip()
    if not domain_key:
        return None

    print_info_debug(
        "[rodc-prp] native graph mode — reading ManageRODCPrp edges from attack_graph.json"
    )
    return _resolve_rodc_prp_report_from_graph(shell, domain_key)

    domain_data = getattr(shell, "domains_data", {}).get(domain_key, {})
    domain_dir = domain_data.get("dir") if isinstance(domain_data, dict) else None
    if not isinstance(domain_dir, str) or not domain_dir:
        return None

    creds = CredentialStoreService.resolve_auth_credentials(
        getattr(shell, "domains_data", {}),
        target_domain=domain_key,
        primary_domain=getattr(shell, "domain", None),
    )
    if not creds:
        print_info_debug(
            "[rodc-prp] No credentials available for delegated RODC PRP discovery; skipping."
        )
        return None
    username, password, auth_domain = creds

    cached_report = None if force_refresh else _load_rodc_prp_report(domain_dir)
    if isinstance(cached_report, dict):
        return cached_report

    kerberos_ready = bool(
        getattr(shell, "domains_data", {}).get(domain_key, {}).get("kerberos_tickets")
    )
    if kerberos_ready:
        kerberos_ready = prepare_kerberos_ldap_environment(
            operation_name="RODC PRP detection",
            target_domain=domain_key,
            workspace_dir=str(
                getattr(shell, "current_workspace_dir", "")
                or getattr(shell, "_get_workspace_cwd", lambda: "")()
                or ""
            ),
            username=str(username),
            user_domain=str(auth_domain or domain_key),
            credential=str(password),
            dc_ip=str(domain_data.get("pdc") or "")
            if isinstance(domain_data, dict)
            else None,
            domains_data=getattr(shell, "domains_data", {}),
            sync_clock=getattr(shell, "do_sync_clock_with_pdc", None),
        )
    ldap_targets = resolve_ldap_target_endpoints(
        target_domain=domain_key,
        domain_data=domain_data,
        kerberos_ready=kerberos_ready,
    )
    dc_target = ldap_targets.dc_address
    kerberos_target_hostname = ldap_targets.kerberos_target_hostname
    if not dc_target:
        print_info_debug(
            "[rodc-prp] Missing DC target for delegated RODC PRP discovery; skipping."
        )
        return None

    print_info_debug(
        f"[rodc-prp] attempting delegated RODC PRP discovery for "
        f"{mark_sensitive(domain_key, 'domain')} via {mark_sensitive(str(dc_target), 'host')}"
    )
    password_fallback_secret = (
        "" if CredentialStoreService._looks_like_ntlm_hash(password) else str(password)
    )
    report = DomainRodcPrpDetectionService().build_rodc_prp_write_report(
        dc_address=str(dc_target),
        kerberos_target_hostname=kerberos_target_hostname,
        target_domain=domain_key,
        username=str(username),
        password=password_fallback_secret,
        use_kerberos=kerberos_ready,
        use_ldaps=True,
    )
    if not isinstance(report, dict):
        return None

    _persist_rodc_prp_report(domain_dir, report=report)
    return report


def _resolve_current_token_principal_labels(
    shell: object,
    *,
    domain: str,
    username: str,
) -> set[str]:
    """Resolve canonical labels represented by the current authenticated token."""
    domain_key = str(domain or "").strip()
    username_clean = normalize_samaccountname(username)
    if not domain_key or not username_clean:
        return set()
    labels = {
        _canonical_membership_label(domain_key, username_clean),
        _canonical_membership_label(domain_key, "Authenticated Users"),
        _canonical_membership_label(domain_key, "Everyone"),
    }
    try:
        recursive_groups = _attack_path_get_recursive_groups(
            shell,
            domain=domain_key,
            samaccountname=username_clean,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        recursive_groups = []
    for group_name in recursive_groups:
        label = _canonical_membership_label(domain_key, group_name)
        if label:
            labels.add(label)
    return {label for label in labels if label}


def get_netlogon_write_support_paths(
    shell: object,
    domain: str,
    *,
    graph: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Validate NETLOGON prerequisites for existing ``WriteLogonScript`` edges."""
    from adscan_internal.services import CredentialStoreService
    from adscan_internal.services.smb_path_access_service import SMBPathAccessService

    domain_key = str(domain or "").strip()
    if not domain_key:
        return []
    graph_data = (
        graph if isinstance(graph, dict) else load_attack_graph(shell, domain_key)
    )

    report = _resolve_writable_attribute_report(shell, domain_key)
    if not isinstance(report, dict):
        return []
    findings = report.get("findings")
    if not isinstance(findings, list) or not findings:
        return []

    creds = CredentialStoreService.resolve_auth_credentials(
        getattr(shell, "domains_data", {}),
        target_domain=domain_key,
        primary_domain=getattr(shell, "domain", None),
    )
    if not creds:
        print_info_debug(
            "[smb-path] No credentials available for NETLOGON write validation; skipping."
        )
        return []
    username, password, auth_domain = creds

    domain_data = getattr(shell, "domains_data", {}).get(domain_key, {})
    dc_fqdn = domain_data.get("pdc_hostname_fqdn") or domain_data.get("pdc_fqdn")
    if not dc_fqdn:
        pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip()
        if pdc_hostname:
            dc_fqdn = (
                pdc_hostname if "." in pdc_hostname else f"{pdc_hostname}.{domain_key}"
            )
    dc_target = str(dc_fqdn or domain_data.get("pdc") or "").strip()
    if not dc_target:
        print_info_debug(
            "[smb-path] Missing DC target for NETLOGON write validation; skipping."
        )
        return []

    kerberos_ready = bool(
        getattr(shell, "domains_data", {}).get(domain_key, {}).get("kerberos_tickets")
    )
    if kerberos_ready:
        kerberos_ready = prepare_kerberos_ldap_environment(
            operation_name="NETLOGON write validation",
            target_domain=domain_key,
            workspace_dir=str(
                getattr(shell, "current_workspace_dir", "")
                or getattr(shell, "_get_workspace_cwd", lambda: "")()
                or ""
            ),
            username=str(username),
            user_domain=str(auth_domain or domain_key),
            credential=str(password),
            dc_ip=str(domain_data.get("pdc") or "")
            if isinstance(domain_data, dict)
            else None,
            domains_data=getattr(shell, "domains_data", {}),
            sync_clock=getattr(shell, "do_sync_clock_with_pdc", None),
        )

    probe_service = SMBPathAccessService()
    staging_candidates = _build_writelogonscript_staging_candidates(domain_key)
    candidate_snapshots: list[tuple[dict[str, str], Any]] = []
    for candidate in staging_candidates:
        security_snapshot = probe_service.collect_security_snapshot(
            target_host=dc_target,
            share_name=candidate["share"],
            directory_path=candidate["path"],
            username=str(username),
            password=str(password),
            auth_domain=str(auth_domain or domain_key),
            use_kerberos=kerberos_ready,
            kdc_host=dc_target if kerberos_ready else None,
        )
        candidate_snapshots.append((candidate, security_snapshot))
        if (
            not security_snapshot.share_descriptor_readable
            or not security_snapshot.path_descriptor_readable
        ):
            print_info_debug(
                f"[smb-path] {candidate['name']} ACL snapshot incomplete for "
                f"{mark_sensitive(domain_key, 'domain')}: "
                f"share_sd={security_snapshot.share_descriptor_readable} "
                f"path_sd={security_snapshot.path_descriptor_readable} "
                f"status={security_snapshot.status_code or '-'} "
                f"error={security_snapshot.error_message or '-'}"
            )

    seen_source_labels: set[str] = set()
    seen_source_ids: set[str] = set()
    principals_evaluated = 0
    validated_edges = 0
    unavailable_edges = 0
    unknown_edges = 0
    graph_changed = False
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        principal_sid = str(finding.get("principal_sid") or "").strip()
        if not principal_sid:
            continue
        should_skip, _, principal_node = _evaluate_lowpriv_source_principal(
            shell,
            domain=domain_key,
            object_id=principal_sid,
            preferred_kind="group",
            graph=graph,
            skip_on_unresolved=True,
        )
        if should_skip or not isinstance(principal_node, dict):
            continue
        source_label = str(principal_node.get("name") or "").strip()
        if not source_label:
            continue
        if source_label.upper() in seen_source_labels:
            continue
        source_object_id = normalize_sid(
            _extract_node_object_id(principal_node) or principal_sid
        )
        if not source_object_id:
            continue
        if source_object_id in seen_source_ids:
            continue
        seen_source_ids.add(source_object_id)
        principals_evaluated += 1
        candidate_notes: list[dict[str, Any]] = []
        selected_candidate: dict[str, Any] | None = None
        all_candidates_denied = True
        for candidate, security_snapshot in candidate_snapshots:
            base_notes = {
                "name": candidate["name"],
                "host": dc_target,
                "share": candidate["share"],
                "path": candidate["path"],
                "source": "smb_acl_snapshot",
                "detector": "impacket_smb_acl",
                "validated_via_username": str(username),
                "auth_mode": security_snapshot.auth_mode,
                "share_descriptor_readable": security_snapshot.share_descriptor_readable,
                "path_descriptor_readable": security_snapshot.path_descriptor_readable,
                "share_backing_path": security_snapshot.share_backing_path,
            }
            if (
                not security_snapshot.share_descriptor_readable
                or not security_snapshot.path_descriptor_readable
            ):
                candidate_notes.append(
                    {
                        **base_notes,
                        "validation": "unknown",
                        "reason": f"{candidate['name']} share/path security descriptor could not be fully read",
                    }
                )
                all_candidates_denied = False
                continue

            acl_result = probe_service.evaluate_snapshot_write_access(
                snapshot=security_snapshot,
                principal_sid=source_object_id,
            )
            effective_can_write = bool(
                acl_result.share_allows_write and acl_result.path_allows_write
            )
            candidate_result = {
                **base_notes,
                "validation": "validated" if effective_can_write else "denied",
                "share_allows_write": acl_result.share_allows_write,
                "path_allows_write": acl_result.path_allows_write,
                "matched_share_sids": list(acl_result.matched_share_sids),
                "matched_path_sids": list(acl_result.matched_path_sids),
            }
            candidate_notes.append(candidate_result)
            if effective_can_write and selected_candidate is None:
                selected_candidate = candidate_result
            if effective_can_write:
                all_candidates_denied = False
            elif candidate_result["validation"] != "denied":
                all_candidates_denied = False

        validation_state = "unknown"
        reason = "No staging share candidate could be validated."
        top_level_notes: dict[str, Any] = {
            "source": "smb_acl_snapshot",
            "detector": "impacket_smb_acl",
            "host": dc_target,
            "validated_via_username": str(username),
            "staging_candidates": candidate_notes,
        }
        primary_candidate = selected_candidate or (
            candidate_notes[0] if candidate_notes else None
        )
        if isinstance(primary_candidate, dict):
            top_level_notes.update(
                {
                    "share": primary_candidate.get("share"),
                    "path": primary_candidate.get("path"),
                    "auth_mode": primary_candidate.get("auth_mode"),
                    "share_descriptor_readable": primary_candidate.get(
                        "share_descriptor_readable"
                    ),
                    "path_descriptor_readable": primary_candidate.get(
                        "path_descriptor_readable"
                    ),
                    "share_backing_path": primary_candidate.get("share_backing_path"),
                    "share_allows_write": primary_candidate.get("share_allows_write"),
                    "path_allows_write": primary_candidate.get("path_allows_write"),
                    "matched_share_sids": primary_candidate.get(
                        "matched_share_sids", []
                    ),
                    "matched_path_sids": primary_candidate.get("matched_path_sids", []),
                }
            )
        if selected_candidate is not None:
            validation_state = "validated"
            reason = f"{selected_candidate['name']} share and path ACLs allow write for the source principal"
            top_level_notes.update(
                {
                    "selected_staging_candidate": selected_candidate.get("name"),
                }
            )
            seen_source_labels.add(source_label.upper())
        elif all_candidates_denied and candidate_notes:
            validation_state = "denied"
            reason = "No supported staging share/path candidate provides write access for the source principal"
        else:
            validation_state = "unknown"
            reason = "Supported staging share/path candidates could not be fully validated for the source principal"

        updated = _annotate_writelogonscript_prerequisite_status(
            graph_data,
            source_object_id=source_object_id,
            validation_state=validation_state,
            notes={
                **top_level_notes,
                "reason": reason,
            },
        )
        if validation_state == "validated":
            validated_edges += updated
        elif validation_state == "denied":
            unavailable_edges += updated
        else:
            unknown_edges += updated
        graph_changed = graph_changed or bool(updated)

    print_info_debug(
        f"[attack_graph] NETLOGON prerequisite validation for {mark_sensitive(domain_key, 'domain')}: "
        f"principals_evaluated={principals_evaluated} "
        f"validated_edges={validated_edges} "
        f"unavailable_edges={unavailable_edges} "
        f"unknown_edges={unknown_edges}"
    )
    if graph_changed and graph is None:
        save_attack_graph(shell, domain_key, graph_data)
    return []


def _build_writelogonscript_staging_candidates(domain: str) -> list[dict[str, str]]:
    """Return supported SMB staging locations for logon-script abuse."""
    domain_key = str(domain or "").strip().strip("\\/")
    return [
        {"name": "NETLOGON", "share": "NETLOGON", "path": ""},
        {
            "name": "SYSVOL scripts",
            "share": "SYSVOL",
            "path": f"{domain_key}\\scripts" if domain_key else "scripts",
        },
    ]


def _annotate_writelogonscript_prerequisite_status(
    graph: dict[str, Any],
    *,
    source_object_id: str,
    validation_state: str,
    notes: dict[str, Any],
) -> int:
    """Update matching ``WriteLogonScript`` edges with NETLOGON prerequisite state."""
    source_key = normalize_sid(str(source_object_id or "").strip())
    state = str(validation_state or "").strip().lower()
    desired_status = {
        "validated": "discovered",
        "unknown": "discovered",
        "denied": "unavailable",
    }.get(state)
    if not source_key or not desired_status:
        return 0

    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    if not edges:
        return 0

    changed = 0
    now = _utc_now_iso()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "").strip().lower() != "writelogonscript":
            continue
        if normalize_sid(str(edge.get("from") or "").strip()) != source_key:
            continue

        existing_notes = edge.get("notes")
        if not isinstance(existing_notes, dict):
            existing_notes = {}
        merged_notes = dict(existing_notes)
        merged_notes.update(notes)
        merged_notes["netlogon_validation"] = state
        merged_notes["netlogon_validation_checked_at"] = now
        edge["notes"] = merged_notes

        current_status = str(edge.get("status") or "discovered").strip().lower()
        if current_status not in {"success", "attempted", "failed", "error"}:
            edge["status"] = desired_status
        edge["last_seen"] = now
        changed += 1

    return changed


def _infer_kind_from_label(label: str) -> str:
    """Infer a principal kind from a normalized BloodHound-style label."""
    label_clean = str(label or "").strip()
    if not label_clean:
        return "Unknown"
    left = label_clean.split("@", 1)[0].strip()
    if left.endswith("$"):
        return "Computer"
    if " " in left:
        return "Group"
    return "User"


def _build_synthetic_principal_node_from_sid(
    *,
    domain: str,
    sid: str,
    label: str | None,
) -> dict[str, Any]:
    """Build a synthetic principal node when BH-backed resolution is unavailable."""
    resolved_label = str(label or sid or "").strip()
    kind = _infer_kind_from_label(resolved_label)
    return {
        "name": resolved_label,
        "kind": [kind],
        "objectId": sid,
        "properties": {
            "name": resolved_label,
            "domain": str(domain or "").strip().upper(),
            "objectid": sid,
        },
    }


def _resolve_principal_label_from_sid(
    shell: object,
    *,
    domain: str,
    sid: str,
    preferred_kind: str | None = None,
) -> str | None:
    """Resolve one SID to a canonical membership label when possible."""
    sid_clean = str(sid or "").strip()
    if not sid_clean:
        return None
    snapshot = _load_membership_snapshot(shell, domain)
    if isinstance(snapshot, dict):
        label = _resolve_group_label_for_sid(snapshot, domain, sid_clean)
        if label:
            return label
    node = _resolve_bloodhound_principal_node(
        shell,
        domain,
        sid_clean,
        object_id=sid_clean,
        entry_kind=(preferred_kind or "").strip().lower() or None,
        graph=None,
        lookup_name=sid_clean,
    )
    if not isinstance(node, dict):
        return None
    node_name = str(node.get("name") or "").strip()
    if not node_name:
        return None
    return _canonical_membership_label(domain, node_name)


def _resolve_principal_node_from_sid(
    shell: object,
    *,
    domain: str,
    sid: str,
    preferred_kind: str = "group",
) -> dict[str, Any] | None:
    """Resolve one principal node from a SID using BH-backed lookup helpers."""
    domain_key = str(domain or "").strip()
    sid_clean = str(sid or "").strip().upper()
    if not domain_key or not sid_clean:
        return None

    label = _resolve_principal_label_from_sid(
        shell,
        domain=domain_key,
        sid=sid_clean,
        preferred_kind=preferred_kind,
    )
    if not label:
        return None

    principal_name = _membership_label_to_name(label)
    return _resolve_bloodhound_principal_node(
        shell,
        domain_key,
        label,
        object_id=sid_clean,
        entry_kind=preferred_kind,
        graph=None,
        lookup_name=principal_name or sid_clean,
    )


def _looks_like_sid(value: str) -> bool:
    """Return whether one string looks like a SID value."""
    candidate = str(value or "").strip().upper()
    return bool(candidate) and candidate.startswith("S-1-")


def _is_non_emittable_builtin_sid(sid: str) -> bool:
    """Return whether one SID is a builtin/system principal we never emit."""
    sid_clean = str(sid or "").strip().upper()
    if not sid_clean:
        return False
    well_known = {
        "S-1-5-18",  # LOCAL SYSTEM
        "S-1-5-19",  # LOCAL SERVICE
        "S-1-5-20",  # NETWORK SERVICE
    }
    return sid_clean in well_known


def _is_population_wide_lowpriv_trustee_sid(
    shell: object, *, domain: str, sid: str
) -> bool:
    """Return whether one trustee SID intentionally expands to the enabled low-priv population."""
    sid_clean = str(sid or "").strip().upper()
    if not sid_clean:
        return False
    if sid_clean in {"S-1-5-11", "S-1-1-0"}:
        return True
    domain_sid = _load_domain_sid_from_domains_data(shell, domain)
    if not domain_sid:
        snapshot = _load_membership_snapshot(shell, domain)
        if isinstance(snapshot, dict):
            domain_sid = _resolve_domain_sid(shell, domain, snapshot)
    return bool(domain_sid) and sid_clean == f"{domain_sid.upper()}-513"


def _evaluate_lowpriv_source_principal(
    shell: object,
    *,
    domain: str,
    object_id: str | None = None,
    label: str | None = None,
    principal_name: str | None = None,
    preferred_kind: str = "group",
    graph: dict[str, Any] | None = None,
    skip_on_unresolved: bool = True,
) -> tuple[bool, str | None, dict[str, Any] | None]:
    """Evaluate whether one source principal should be skipped for low-priv pathing."""
    object_id_clean = str(object_id or "").strip().upper()
    if object_id_clean and _is_non_emittable_builtin_sid(object_id_clean):
        return True, "builtin_or_system_principal", None

    node: dict[str, Any] | None = None
    if object_id_clean:
        node = _resolve_principal_node_from_sid(
            shell,
            domain=domain,
            sid=object_id_clean,
            preferred_kind=preferred_kind,
        )
    else:
        label_clean = str(label or "").strip()
        if label_clean:
            node = _resolve_bloodhound_principal_node(
                shell,
                domain,
                label_clean,
                object_id=object_id_clean or None,
                entry_kind=preferred_kind,
                graph=graph,
                lookup_name=principal_name or label_clean,
            )

    if not isinstance(node, dict):
        if skip_on_unresolved:
            return True, "unresolved_principal", None
        return False, None, None

    if _node_is_effectively_high_value(node):
        return True, "privileged_principal", node

    return False, None, node


def _expand_low_priv_usernames_from_trustee_sid(
    shell: object,
    *,
    domain: str,
    principal_sid: str,
    candidate_users: set[str] | None,
) -> set[str]:
    """Expand one trustee SID into candidate user sources for Phase 2."""
    domain_key = str(domain or "").strip()
    if not domain_key:
        return set()

    sid_clean = str(principal_sid or "").strip().upper()
    if not sid_clean:
        return set()

    domain_sid = _load_domain_sid_from_domains_data(shell, domain_key)
    if not domain_sid:
        snapshot = _load_membership_snapshot(shell, domain_key)
        if isinstance(snapshot, dict):
            domain_sid = _resolve_domain_sid(shell, domain_key, snapshot)

    if sid_clean in {"S-1-5-11", "S-1-1-0"}:
        return set(candidate_users or set())
    if domain_sid and sid_clean == f"{domain_sid.upper()}-513":
        return set(resolve_group_members_by_rid(shell, domain_key, 513) or [])

    label = _resolve_principal_label_from_sid(
        shell,
        domain=domain_key,
        sid=sid_clean,
        preferred_kind="group",
    )
    if not label:
        return set()

    principal_name = _membership_label_to_name(label)
    if not principal_name:
        return set()

    direct_user_sid = resolve_user_sid(shell, domain_key, principal_name)
    if direct_user_sid and direct_user_sid.upper() == sid_clean:
        normalized = normalize_samaccountname(principal_name)
        if normalized and (candidate_users is None or normalized in candidate_users):
            return {normalized}
        return set()

    snapshot = _load_membership_snapshot(shell, domain_key)
    if not isinstance(snapshot, dict):
        return set()

    candidate_usernames = (
        candidate_users or get_domain_users_for_domain(shell, domain_key) or set()
    )
    expanded: set[str] = set()
    target_group_label = _canonical_membership_label(domain_key, label)
    for username in candidate_usernames:
        recursive_labels = _snapshot_get_recursive_group_labels(
            shell, domain_key, username
        )
        if recursive_labels and target_group_label in recursive_labels:
            normalized = normalize_samaccountname(username)
            if normalized:
                expanded.add(normalized)
    return expanded


def _index_existing_user_object_control_relations(
    graph: dict[str, Any] | None,
) -> set[tuple[str, str]]:
    """Return source/target pairs already covered by GenericAll/GenericWrite.

    The writable-attribute detector can discover ``scriptPath`` writes even when
    BloodHound already produced a broader object-control edge for the same
    source-target pair. In those cases the graph should prefer the canonical
    ACL relation and suppress the narrower ``WriteLogonScript`` attack step.
    """
    if not isinstance(graph, dict):
        return set()

    indexed_pairs: set[tuple[str, str]] = set()
    raw_edges = graph.get("edges")
    if not isinstance(raw_edges, list):
        return indexed_pairs

    raw_nodes = graph.get("nodes")
    node_index: dict[str, dict[str, Any]] = {}
    if isinstance(raw_nodes, list):
        for node in raw_nodes:
            if not isinstance(node, dict):
                continue
            object_id = str(node.get("objectId") or "").strip()
            if object_id:
                node_index[object_id] = node

    for edge in raw_edges:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or "").strip().lower()
        if relation not in {"genericall", "genericwrite"}:
            continue

        source_id = str(edge.get("from") or "").strip()
        target_id = str(edge.get("to") or "").strip()
        if not source_id or not target_id:
            continue

        target_node = node_index.get(target_id)
        target_kinds = (
            target_node.get("kind") if isinstance(target_node, dict) else None
        )
        if isinstance(target_kinds, list) and target_kinds:
            if not any(str(kind).strip().lower() == "user" for kind in target_kinds):
                continue

        indexed_pairs.add((source_id.upper(), target_id.upper()))

    return indexed_pairs


def _acl_object_control_coverage_path(shell: object, domain: str) -> str:
    """Return the compact ACL object-control coverage sidecar path."""
    workspace_cwd = resolve_workspace_cwd(shell)
    domains_dir = getattr(shell, "domains_dir", "domains")
    return domain_subpath(
        workspace_cwd,
        domains_dir,
        domain,
        "BH",
        "acl_object_control_coverage.json",
    )


def _load_acl_object_control_inventory_pairs(
    shell: object,
    domain: str,
) -> set[tuple[str, str]]:
    """Return source/target pairs covered by raw GenericAll/GenericWrite ACLs."""
    path = _acl_object_control_coverage_path(shell, domain)
    if not os.path.exists(path):
        return set()

    try:
        payload = read_json_file(path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[attack_graph] failed to read ACL object-control coverage sidecar: {exc}"
        )
        return set()

    coverage = payload.get("coverage")
    if not isinstance(coverage, list):
        return set()

    def _record_identity_variants(
        record: dict[str, Any],
        *,
        prefix: str,
        default_label_field: str,
    ) -> set[str]:
        """Return comparable identity keys for one sidecar endpoint."""
        variants: set[str] = set()
        for field_name in (
            f"{prefix}_graph_id",
            f"{prefix}_id",
            f"{prefix}_object_id",
            default_label_field,
        ):
            value = str(record.get(field_name) or "").strip()
            if value:
                variants.add(value.upper())
        label_value = str(record.get(default_label_field) or "").strip()
        if label_value:
            canonical_label = _canonical_account_identifier(label_value)
            if canonical_label:
                variants.add(f"name:{canonical_label}".upper())
        return variants

    indexed_pairs: set[tuple[str, str]] = set()
    for record in coverage:
        if not isinstance(record, dict):
            continue
        relation = str(record.get("relation") or "").strip().lower()
        if relation not in {"genericall", "genericwrite"}:
            continue
        target_kind = str(record.get("target_kind") or "").strip().lower()
        if target_kind and target_kind != "user":
            continue
        source_variants = _record_identity_variants(
            record,
            prefix="source",
            default_label_field="source",
        )
        target_variants = _record_identity_variants(
            record,
            prefix="target",
            default_label_field="target",
        )
        if not source_variants or not target_variants:
            continue
        indexed_pairs.update(
            (source_variant, target_variant)
            for source_variant in source_variants
            for target_variant in target_variants
        )

    if indexed_pairs:
        print_info_debug(
            "[attack_graph] loaded ACL object-control coverage sidecar: "
            f"pairs={len(indexed_pairs)} "
            f"path={mark_sensitive(path, 'path')}"
        )
    return indexed_pairs


def get_writable_user_attribute_paths(
    shell: object,
    domain: str,
    *,
    graph: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build attack-step edges from domain-wide writable user attributes."""
    domain_key = str(domain or "").strip()
    if not domain_key:
        return []

    report = _resolve_writable_attribute_report(shell, domain_key)
    if not isinstance(report, dict):
        return []

    raw_findings = report.get("findings")
    if not isinstance(raw_findings, list):
        return []

    resolved_rows: list[dict[str, Any]] = []
    target_usernames: set[str] = set()
    discard_counters: dict[str, int] = {
        "findings_collected": len(raw_findings),
        "skipped_invalid_row": 0,
        "skipped_privileged_principal": 0,
        "skipped_builtin_or_system_principal": 0,
        "skipped_unresolved_principal": 0,
        "skipped_target_not_enabled": 0,
        "skipped_subsumed_by_acl_inventory": 0,
        "skipped_subsumed_by_graph_fallback": 0,
        "skipped_target_tier0": 0,
        "skipped_self_edge": 0,
        "edges_emitted": 0,
    }
    drop_samples: dict[str, int] = {}
    enabled_users = get_enabled_users_for_domain(shell, domain_key)
    inventory_acl_pairs = _load_acl_object_control_inventory_pairs(shell, domain_key)
    graph_fallback_acl_pairs = _index_existing_user_object_control_relations(graph)

    def _sample_drop(reason: str, message: str) -> None:
        count = drop_samples.get(reason, 0)
        if count < 3:
            print_info_debug(message)
        drop_samples[reason] = count + 1

    for finding in raw_findings:
        if not isinstance(finding, dict):
            discard_counters["skipped_invalid_row"] += 1
            continue
        relation = str(finding.get("relation") or "").strip()
        principal_sid = str(finding.get("principal_sid") or "").strip()
        target_username = str(finding.get("target_username") or "").strip()
        if not relation or not principal_sid or not target_username:
            discard_counters["skipped_invalid_row"] += 1
            continue

        should_skip, skip_reason, principal_node = _evaluate_lowpriv_source_principal(
            shell,
            domain=domain_key,
            object_id=principal_sid,
            preferred_kind="group",
            graph=graph,
            skip_on_unresolved=True,
        )
        if should_skip:
            if skip_reason == "privileged_principal":
                discard_counters["skipped_privileged_principal"] += 1
            elif skip_reason == "builtin_or_system_principal":
                discard_counters["skipped_builtin_or_system_principal"] += 1
            else:
                discard_counters["skipped_unresolved_principal"] += 1
            _sample_drop(
                skip_reason or "skipped_source",
                f"[attack_graph] writable-attrs drop: "
                f"reason={skip_reason or 'unknown'} "
                f"principal_sid={mark_sensitive(principal_sid, 'user')} "
                f"target={mark_sensitive(target_username, 'user')}",
            )
            continue

        target_norm = normalize_samaccountname(target_username)
        if not target_norm:
            discard_counters["skipped_invalid_row"] += 1
            continue
        if enabled_users is not None and target_norm not in enabled_users:
            discard_counters["skipped_target_not_enabled"] += 1
            _sample_drop(
                "target_not_enabled",
                "[attack_graph] writable-attrs drop: "
                "reason=target_not_enabled "
                f"target={mark_sensitive(target_username, 'user')}",
            )
            continue

        resolved_rows.append(
            {
                "finding": finding,
                "target_norm": target_norm,
                "source_node": principal_node,
            }
        )
        target_usernames.add(target_norm)

    if not resolved_rows:
        return []

    target_risk_flags = classify_users_tier0_high_value(
        shell,
        domain=domain_key,
        usernames=sorted(target_usernames),
    )

    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def _candidate_pair_variants(
        *,
        source_node: dict[str, Any],
        target_node: dict[str, Any],
        target_object_id: str,
    ) -> set[tuple[str, str]]:
        """Return comparable source/target identity variants for subsumption checks."""
        source_variants: set[str] = set()
        target_variants: set[str] = set()

        source_graph_id = str(_node_id(source_node) or "").strip()
        source_object_id = str(source_node.get("objectId") or "").strip()
        source_name = str(source_node.get("name") or "").strip()
        target_graph_id = str(_node_id(target_node) or "").strip()
        target_name = str(target_node.get("name") or "").strip()

        for value in (
            source_graph_id,
            source_object_id,
            source_name,
        ):
            value_clean = str(value or "").strip()
            if not value_clean:
                continue
            source_variants.add(value_clean.upper())
            canonical = _canonical_account_identifier(value_clean)
            if canonical:
                source_variants.add(f"name:{canonical}".upper())

        for value in (
            target_graph_id,
            target_object_id,
            target_name,
        ):
            value_clean = str(value or "").strip()
            if not value_clean:
                continue
            target_variants.add(value_clean.upper())
            canonical = _canonical_account_identifier(value_clean)
            if canonical:
                target_variants.add(f"name:{canonical}".upper())

        return {
            (source_variant, target_variant)
            for source_variant in source_variants
            for target_variant in target_variants
        }

    for row in resolved_rows:
        finding = row["finding"]
        relation = str(finding.get("relation") or "").strip()
        target_username = str(finding.get("target_username") or "").strip()
        target_norm = normalize_samaccountname(target_username)
        target_flags = target_risk_flags.get(target_norm)
        if target_flags and target_flags.is_tier0:
            discard_counters["skipped_target_tier0"] += 1
            continue

        target_label = f"{target_username.upper()}@{domain_key.upper()}"
        target_node: dict[str, Any] = {
            "name": target_label,
            "kind": ["User"],
            "objectId": str(finding.get("target_object_id") or "").strip() or None,
            "properties": {
                "name": target_label,
                "samaccountname": target_username,
                "domain": domain_key.upper(),
                "distinguishedname": finding.get("target_dn"),
                "highvalue": bool(target_flags.is_high_value)
                if target_flags
                else False,
                "isTierZero": bool(target_flags.is_tier0) if target_flags else False,
                "objectid": str(finding.get("target_object_id") or "").strip() or None,
            },
        }
        if target_node.get("objectId") in {"", None}:
            target_node.pop("objectId", None)
            target_node["properties"].pop("objectid", None)

        source_node = row.get("source_node")
        if not isinstance(source_node, dict):
            discard_counters["skipped_unresolved_principal"] += 1
            continue
        source_name = str(source_node.get("name") or "").strip()
        if source_name and source_name.upper() == target_label.upper():
            discard_counters["skipped_self_edge"] += 1
            continue
        source_object_id = str(source_node.get("objectId") or "").strip()
        target_object_id = str(finding.get("target_object_id") or "").strip()
        if relation.lower() == "writelogonscript":
            pair_variants = _candidate_pair_variants(
                source_node=source_node,
                target_node=target_node,
                target_object_id=target_object_id,
            )
            if pair_variants.intersection(inventory_acl_pairs):
                discard_counters["skipped_subsumed_by_acl_inventory"] += 1
                _sample_drop(
                    "subsumed_by_acl_inventory",
                    "[attack_graph] writable-attrs drop: "
                    "reason=subsumed_by_acl_inventory "
                    f"source={mark_sensitive(source_name or source_object_id, 'user')} "
                    f"target={mark_sensitive(target_label, 'user')}",
                )
                continue
            if pair_variants.intersection(graph_fallback_acl_pairs):
                discard_counters["skipped_subsumed_by_graph_fallback"] += 1
                _sample_drop(
                    "subsumed_by_graph_fallback",
                    "[attack_graph] writable-attrs drop: "
                    "reason=subsumed_by_graph_fallback "
                    f"source={mark_sensitive(source_name or source_object_id, 'user')} "
                    f"target={mark_sensitive(target_label, 'user')}",
                )
                continue

        notes = {
            "source": "ldap_attribute_acl",
            "detector": "ldap_acl",
            "attribute": str(finding.get("attribute") or "").strip() or "scriptPath",
            "target_dn": str(finding.get("target_dn") or "").strip(),
            "principal_sid": str(finding.get("principal_sid") or "").strip(),
            "applies_to_all_properties": bool(finding.get("applies_to_all_properties")),
            "is_inherited": bool(finding.get("is_inherited")),
        }
        sig = (
            source_name.upper(),
            relation.lower(),
            normalize_samaccountname(target_username),
        )
        if sig in seen:
            continue
        seen.add(sig)
        edges.append(
            {
                "nodes": [source_node, target_node],
                "rels": [relation],
                "notes_by_relation_index": {0: notes},
            }
        )
        discard_counters["edges_emitted"] += 1

    print_info_debug(
        f"[attack_graph] writable-attribute paths for {mark_sensitive(domain_key, 'domain')}: "
        f"count={len(edges)}"
    )
    print_info_debug(
        "[attack_graph] writable-attribute summary: "
        + " ".join(f"{key}={value}" for key, value in discard_counters.items())
    )
    return edges


def get_rodc_prp_control_paths(
    shell: object,
    domain: str,
    *,
    graph: dict[str, Any] | None = None,
    force_refresh: bool = False,
) -> list[dict[str, Any]]:
    """Build custom ``ManageRODCPrp`` edges from delegated RODC PRP write findings."""
    domain_key = str(domain or "").strip()
    if not domain_key:
        return []

    report = _resolve_rodc_prp_report(shell, domain_key, force_refresh=force_refresh)
    if not isinstance(report, dict):
        return []

    raw_findings = report.get("findings")
    if not isinstance(raw_findings, list):
        return []

    edges: list[dict[str, Any]] = []
    discard_counters: dict[str, int] = {
        "findings_collected": len(raw_findings),
        "skipped_invalid_row": 0,
        "skipped_privileged_principal": 0,
        "skipped_builtin_or_system_principal": 0,
        "skipped_unresolved_principal": 0,
        "skipped_self_edge": 0,
        "edges_emitted": 0,
    }
    drop_samples: dict[str, int] = {}

    def _sample_drop(reason: str, message: str) -> None:
        count = drop_samples.get(reason, 0)
        if count < 3:
            print_info_debug(message)
        drop_samples[reason] = count + 1

    for finding in raw_findings:
        if not isinstance(finding, dict):
            discard_counters["skipped_invalid_row"] += 1
            continue
        relation = str(finding.get("relation") or "").strip()
        principal_sid = str(finding.get("principal_sid") or "").strip()
        target_machine = str(finding.get("target_machine") or "").strip()
        target_object_id = str(finding.get("target_object_id") or "").strip()
        target_dn = str(finding.get("target_dn") or "").strip()
        if (
            not relation
            or not principal_sid
            or not target_machine
            or not target_object_id
        ):
            discard_counters["skipped_invalid_row"] += 1
            continue

        should_skip, skip_reason, principal_node = _evaluate_lowpriv_source_principal(
            shell,
            domain=domain_key,
            object_id=principal_sid,
            preferred_kind="group",
            graph=graph,
            skip_on_unresolved=True,
        )
        if should_skip:
            if skip_reason == "privileged_principal":
                discard_counters["skipped_privileged_principal"] += 1
            elif skip_reason == "builtin_or_system_principal":
                discard_counters["skipped_builtin_or_system_principal"] += 1
            else:
                discard_counters["skipped_unresolved_principal"] += 1
            _sample_drop(
                skip_reason or "skipped_source",
                f"[attack_graph] rodc-prp drop: "
                f"reason={skip_reason or 'unknown'} "
                f"principal_sid={mark_sensitive(principal_sid, 'user')} "
                f"target={mark_sensitive(target_machine, 'user')}",
            )
            continue

        target_machine_label = _canonical_membership_label(domain_key, target_machine)
        source_label = str(
            (principal_node or {}).get("name")
            or _resolve_principal_label_from_sid(
                shell,
                domain=domain_key,
                sid=principal_sid,
                preferred_kind="group",
            )
            or ""
        ).strip()
        if not source_label or not target_machine_label:
            discard_counters["skipped_invalid_row"] += 1
            continue
        if source_label.casefold() == target_machine_label.casefold():
            discard_counters["skipped_self_edge"] += 1
            continue

        target_node = {
            "name": target_machine_label,
            "kind": ["Computer"],
            "objectId": target_object_id,
            "properties": {
                "name": target_machine_label,
                "objectid": target_object_id,
                "distinguishedname": target_dn,
                "domain": domain_key.upper(),
                "samaccountname": target_machine,
                "msDS-isRODC": True,
            },
        }
        notes = {
            "source": "ldap_rodc_prp_acl",
            "detector": "ldap_rodc_prp_acl",
            "target_dn": target_dn,
            "required_attributes": list(finding.get("required_attributes") or []),
            "principal_sid": principal_sid,
        }
        edges.append(
            {
                "nodes": [principal_node, target_node],
                "rels": [relation],
                "notes_by_relation_index": {0: notes},
            }
        )
        discard_counters["edges_emitted"] += 1

    print_info_debug(
        f"[attack_graph] rodc-prp paths for {mark_sensitive(domain_key, 'domain')}: "
        + " ".join(f"{key}={value}" for key, value in discard_counters.items())
    )
    return edges


# ---------------------------------------------------------------------------
# Native-inventory ADCS helpers — read from collector JSON, no subprocess
# ---------------------------------------------------------------------------


def _inventory_adcs_path(domain_dir: str, filename: str) -> str:
    """Return path to a native-collector inventory file inside domain_dir."""
    return os.path.join(domain_dir, "inventory", filename)


def resolve_adcs_vulns_from_inventory(
    domain_dir: str,
    *,
    username: str,
    groups: list[str] | None = None,
) -> "list | None":
    """Return ADCSVulnerability list from native collector inventory, or None if unavailable.

    Reads ``adcs_attack_steps.json`` produced by the native ADCS collector in
    Phase 1.  Returns ``None`` (not an empty list) when the file does not exist
    so callers can distinguish "no inventory yet" from "no vulns found".

    Args:
        domain_dir: Domain workspace directory (e.g. ``/opt/adscan/workspaces/X/domains/d``).
        username: sAMAccountName of the executing principal.
        groups: Optional list of group sAMAccountNames the principal belongs to.

    Returns:
        List of ``ADCSVulnerability`` objects, or ``None`` when file is absent.
    """
    from adscan_internal.services.adcs.types import ADCSVulnerability

    steps_path = _inventory_adcs_path(domain_dir, "adcs_attack_steps.json")
    if not os.path.isfile(steps_path):
        return None

    try:
        data = read_json_file(steps_path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None

    records = data.get("records")
    if not isinstance(records, list):
        return None

    sam_lower = str(username or "").strip().lower()
    groups_lower = {str(g).strip().lower() for g in (groups or []) if str(g).strip()}
    all_identities = {sam_lower} | groups_lower

    # CA-level ESC relations (no template involved)
    _CA_ESCS = {"ADCSESC6", "ADCSESC7", "ADCSESC8", "ADCSESC11"}

    seen: set[tuple[str, str | None]] = set()
    vulns: list[ADCSVulnerability] = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        relation = str(rec.get("relation") or "").strip()
        if not relation.startswith("ADCSESC"):
            continue
        esc_num = relation.removeprefix("ADCSESC")

        source_name = str(rec.get("source_name") or "").strip().lower()
        if source_name not in all_identities:
            continue

        if relation in _CA_ESCS:
            key: tuple[str, str | None] = (esc_num, None)
            if key not in seen:
                seen.add(key)
                vulns.append(ADCSVulnerability(esc_number=esc_num, source="ca"))
        else:
            template_name = str(rec.get("target_name") or "").strip() or None
            key = (esc_num, (template_name or "").lower())
            if key not in seen:
                seen.add(key)
                vulns.append(
                    ADCSVulnerability(
                        esc_number=esc_num,
                        source="template",
                        template=template_name,
                    )
                )

    return vulns


def resolve_esc4_templates_from_inventory(
    domain_dir: str,
    *,
    username: str,
    groups: list[str] | None = None,
) -> list[str] | None:
    """Return ESC4-abusable template names from native inventory, or None if unavailable.

    Returns ``None`` when the inventory file does not exist so the caller can
    fall back to native inventory if available.
    """
    steps_path = _inventory_adcs_path(domain_dir, "adcs_attack_steps.json")
    if not os.path.isfile(steps_path):
        return None

    try:
        data = read_json_file(steps_path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None

    records = data.get("records")
    if not isinstance(records, list):
        return None

    sam_lower = str(username or "").strip().lower()
    groups_lower = {str(g).strip().lower() for g in (groups or []) if str(g).strip()}
    all_identities = {sam_lower} | groups_lower

    matches: set[str] = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        if str(rec.get("relation") or "") != "ADCSESC4":
            continue
        source_name = str(rec.get("source_name") or "").strip().lower()
        if source_name not in all_identities:
            continue
        template_name = str(rec.get("target_name") or "").strip()
        if template_name:
            matches.add(template_name)

    return sorted(matches, key=str.lower)


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

    if kind == "Domain":
        canonical = _pick(
            props.get("name"),
            node.get("name"),
            node.get("label"),
            props.get("domain"),
            node.get("domain"),
        )
        if canonical:
            return canonical.upper()

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
    return _node_is_tier0(node)


def _node_is_tier0(node: dict[str, Any]) -> bool:
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if bool(node.get("isTierZero")):
        return True
    if bool(props.get("isTierZero")):
        return True
    if node_is_rodc_computer(node):
        return True
    tags = node.get("system_tags") or props.get("system_tags") or []
    if isinstance(tags, str):
        tags = [tag.strip() for tag in re.split(r"[, ]+", tags) if tag.strip()]
    return any(str(tag).lower() == "admin_tier_0" for tag in tags)


def _node_is_domain(node: dict[str, Any]) -> bool:
    """Return True when the node represents the Active Directory Domain object.

    The Domain node is the canonical kill-chain terminal: every actionable path
    that reaches Tier-0 ultimately materialises domain compromise on this node
    (DCSync, owner of Domain object, replication rights, etc.).
    """
    return str(node.get("kind") or "").strip().lower() == "domain"


def _relation_is_actionable_for_source_filter(relation: str) -> bool:
    """Return True when a relation represents an attack step, not graph context."""
    relation_key = str(relation or "").strip().lower()
    if not relation_key:
        return False
    if relation_key in _CONTEXT_RELATIONS_LOWER:
        return False
    return relation_key not in _NON_ACTIONABLE_SOURCE_FILTER_RELATIONS


def _edge_has_tier0_source(
    graph: dict[str, Any],
    *,
    from_id: str,
    relation: str,
    to_id: str | None = None,
) -> bool:
    """Return True when an actionable edge starts from a Tier-0 principal.

    The filter narrowed to ``direct_compromise`` sources only — the canonical
    "domain-takeover sinks" (Domain Admins, Enterprise Admins, BUILTIN
    Administrators, Schema Admins, krbtgt, Domain Controllers). Once an
    attacker is at one of those, every additional outgoing edge is noise: the
    domain is already compromised, ``DA -AdminTo-> server01`` adds no chain.

    Other privileged Tier-0 groups that show up because of inheritance
    (``Account Operators``, ``Backup Operators``, ``DnsAdmins``, the Exchange
    groups, ``Key Admins``, etc.) are *stepping stones* — their outgoing
    actionable edges form real multi-hop paths to the Domain object via
    intermediate Tier-0 nodes. They must NOT be filtered.

    Two exemptions short-circuit the check before classification:

    1. Target is the Domain object — the kill-chain terminal step always
       survives so domain-mode pathfinding can complete.
    2. Source is not classified as ``direct_compromise`` — anything else
       (graph_extension / followup_terminal / future_followup) keeps its
       edges so chains can form.
    """
    relation_lc = str(relation or "").strip().lower()
    # A self-loop MSSQL SYSTEM-escalation proof step (MssqlSeImpersonateEscalation
    # / MssqlTokenTheftEscalation) recorded ON a Tier-0 DC is NOT "you already own
    # the domain" lateral noise: it is the coupled step that PROVES
    # ``NT AUTHORITY\SYSTEM`` (= the DC machine account) was reached, and it is
    # exactly what the direct-DCSync overlay (F6, attack_graph_core.
    # _build_implicit_dc_dcsync_overlay) couples onto to render the
    # domain-compromise terminal. Pruning it as a Tier-0 source edge would strip
    # the escalation step AND its DCSync follow-up, leaving the path dead at a
    # Tier-0 foothold with the KPI reading 0. Keep the self-loop proof step.
    from adscan_internal.services.post_exploitation.access_followups import (  # noqa: PLC0415
        grants_host_system_session,
    )

    if (
        from_id
        and to_id
        and str(from_id).strip() == str(to_id).strip()
        and grants_host_system_session(relation_lc)
    ):
        return False
    is_cross_forest_lateral = relation_lc in _CROSS_FOREST_LATERAL_RELATIONS
    # Cross-forest lateral relations (MssqlLinkedServerLateral) carry
    # support_kind=context so the DFS/execution loop treats them as a pass-through
    # pivot (the downstream step consumes the SQL session). That execution-level
    # classification must NOT exempt them from the Tier-0-source suppression: a
    # SAME-domain linked-server edge from a Tier-0 source is still "you already
    # own this domain" noise. Keep them in scope for this filter even though they
    # read as non-actionable for the DFS; the cross-domain carve-out below still
    # rescues the genuine cross-forest finding.
    if not is_cross_forest_lateral and not _relation_is_actionable_for_source_filter(
        relation
    ):
        return False
    nodes = graph.get("nodes")
    if not isinstance(nodes, dict):
        return False
    if to_id:
        target_node = nodes.get(str(to_id).strip())
        if isinstance(target_node, dict) and _node_is_domain(target_node):
            return False
    source_node = nodes.get(str(from_id or "").strip())
    if not isinstance(source_node, dict):
        return False
    # Cross-forest lateral exemption: an MSSQL linked-server edge FROM a Tier-0
    # source reaching a target in a DIFFERENT domain crosses the trust/forest
    # boundary — a real compromise finding, not "already own this domain" noise.
    # (DarkZero topology: SQL on the DC → linked server into a different forest.)
    if to_id and is_cross_forest_lateral:
        target_node = nodes.get(str(to_id).strip())
        if isinstance(target_node, dict):
            src_domain = _node_domain(source_node)
            tgt_domain = _node_domain(target_node)
            if src_domain and tgt_domain and src_domain != tgt_domain:
                return False
    return _node_is_direct_compromise_source(source_node)


def _node_domain(node: dict[str, Any]) -> str:
    """Normalized (upper-case) domain of a graph node.

    Reads the ``domain`` from the node's ``properties`` first, then the
    top-level field. Used to tell a cross-forest lateral (e.g. an MSSQL linked
    server into a different forest) apart from a same-domain one.
    """
    props = node.get("properties")
    raw = ""
    if isinstance(props, dict):
        raw = props.get("domain") or ""
    raw = raw or node.get("domain") or ""
    return str(raw).strip().upper()


def _node_is_direct_compromise_source(node: dict[str, Any]) -> bool:
    """True when the node is a domain-takeover sink (DA/EA/Admins/krbtgt/DC).

    Reuses the canonical ``target_terminal_class`` taxonomy so the
    classification stays in sync with path UX, choke-point analysis, and the
    rest of the priority pipeline. Falls back to a fresh computation when the
    field has not been persisted yet (graph upgrades, in-flight collection).

    Special case — Tier-0 computer accounts (Domain Controllers):
    DC$ nodes carry ``target_terminal_class="graph_extension"`` because the
    Domain Controllers *group* is a BFS stepping stone as a TARGET (you reach
    it to unlock further abuse vectors).  But as a SOURCE, controlling DC$
    machine credentials means you already own the domain (dcsync, DPAPI, etc.).
    Any Tier-0 Computer node must therefore be treated as direct_compromise for
    source-filter purposes regardless of its inherited terminal class.
    """
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}

    persisted = (
        str(
            node.get("target_terminal_class")
            or (props.get("target_terminal_class") if isinstance(props, dict) else "")
            or ""
        )
        .strip()
        .lower()
    )
    if persisted:
        return persisted == "direct_compromise"
    # Defensive fallback — recompute from the canonical helper.
    return (
        attack_graph_core._node_target_terminal_class(node)  # noqa: SLF001
        == "direct_compromise"
    )


def _prune_tier0_source_attack_edges(graph: dict[str, Any]) -> int:
    """Remove persisted attack edges that originate from Tier-0 principals."""
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return 0

    kept: list[dict[str, Any]] = []
    removed = 0
    for edge in edges:
        if not isinstance(edge, dict):
            kept.append(edge)
            continue
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        relation = str(edge.get("relation") or "").strip()
        if _edge_has_tier0_source(
            graph, from_id=from_id, relation=relation, to_id=to_id
        ):
            removed += 1
            continue
        kept.append(edge)

    if removed:
        graph["edges"] = kept
        maintenance = graph.setdefault("maintenance", {})
        if isinstance(maintenance, dict):
            maintenance["tier0_source_attack_edges_pruned"] = (
                int(maintenance.get("tier0_source_attack_edges_pruned") or 0) + removed
            )
        print_info_debug(
            f"[attack_graph] pruned {removed} attack edge(s) with Tier-0 source principal"
        )
    return removed


def _record_tier0_source_attack_edge_skip(
    graph: dict[str, Any],
    *,
    relation: str,
) -> None:
    """Accumulate Tier-0 source edge skips without logging every edge."""
    maintenance = graph.setdefault("maintenance", {})
    if not isinstance(maintenance, dict):
        graph["maintenance"] = {}
        maintenance = graph["maintenance"]

    summary = maintenance.setdefault("tier0_source_attack_edge_skips", {})
    if not isinstance(summary, dict):
        summary = {}
        maintenance["tier0_source_attack_edge_skips"] = summary

    relation_key = str(relation or "unknown").strip() or "unknown"
    by_relation = summary.setdefault("by_relation", {})
    if not isinstance(by_relation, dict):
        by_relation = {}
        summary["by_relation"] = by_relation
    by_relation[relation_key] = int(by_relation.get(relation_key) or 0) + 1
    summary["total"] = int(summary.get("total") or 0) + 1


def _flush_tier0_source_attack_edge_skip_summary(graph: dict[str, Any]) -> None:
    """Log one sampled summary for Tier-0 source edge skips."""
    maintenance = graph.get("maintenance")
    if not isinstance(maintenance, dict):
        return
    summary = maintenance.get("tier0_source_attack_edge_skips")
    if not isinstance(summary, dict):
        return
    total = int(summary.get("total") or 0)
    if total <= 0 or summary.get("logged"):
        return
    by_relation = summary.get("by_relation")
    if not isinstance(by_relation, dict):
        by_relation = {}
    top_relations = sorted(
        ((str(relation), int(count or 0)) for relation, count in by_relation.items()),
        key=lambda item: (-item[1], item[0].lower()),
    )[:8]
    relation_text = ", ".join(
        f"{relation}={count}" for relation, count in top_relations
    )
    if len(by_relation) > len(top_relations):
        relation_text += f", +{len(by_relation) - len(top_relations)} more"
    print_info_debug(
        "[attack_graph] skipped attack edges with Tier-0 source principals: "
        f"total={total}" + (f" ({relation_text})" if relation_text else "")
    )
    summary["logged"] = True


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
    # BloodHound is the source of truth for criticality.  ADscan adds
    # follow-up/terminal semantics on top, but does not mutate high-value state.
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if _node_is_tier0(node):
        return True
    return bool(node.get("highvalue")) or bool(props.get("highvalue"))


def _node_is_enabled_user(node: dict[str, Any]) -> bool:
    """Return True when the node represents an enabled user principal."""
    if _node_kind(node) != "User":
        return False
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    enabled = props.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    enabled = node.get("enabled")
    return enabled is True


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
    force_source: str | None = None,  # noqa: ARG001 — kept for signature compatibility
) -> list[str]:
    """Resolve recursive group memberships for attack-path computations.

    Snapshot-first lookup; falls back to a recursive LDAP membership query
    when the snapshot is empty.

    Args:
        shell: Shell providing LDAP integrations.
        domain: Target domain.
        samaccountname: Principal sAMAccountName (user or computer).

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

    if snapshot_empty:
        try:
            marked_domain = mark_sensitive(domain_clean, "domain")
            marked_sam = mark_sensitive(sam_clean, "user")
            print_info_debug(
                f"[attack_paths] Snapshot groups empty for {marked_sam}@{marked_domain}; "
                "trying LDAP lookup."
            )
        except Exception:
            pass

    try:
        from adscan_internal.cli.ldap import get_recursive_principal_groups_in_chain

        groups = get_recursive_principal_groups_in_chain(
            shell, domain=domain_clean, target_samaccountname=sam_clean
        )
        if not isinstance(groups, list):
            return []
        return sorted(set(groups))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []


def _attack_path_get_recursive_groups_for_group(
    shell: object,
    *,
    domain: str,
    group_name: str,
    force_source: str | None = None,  # noqa: ARG001 — kept for signature compatibility
) -> list[str]:
    """Resolve recursive parent groups for a Group (Group -> MemberOf* -> Group).

    Snapshot-first lookup. There is no native LDAP recursive group->group
    walker yet, so when the snapshot is empty we return an empty list rather
    than fabricating partial data.
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


def _resolve_attack_step_group_node(
    shell: object,
    *,
    domain: str,
    group_name: str,
    graph: dict[str, Any] | None = None,
    source: str,
) -> dict[str, Any]:
    """Resolve one group principal for attack-step creation into a canonical node.

    Prefer stable identifiers (well-known SID/RID or BloodHound-backed objectId)
    over plain labels so attack steps do not fork the same group into multiple
    node IDs.
    """
    domain_clean = str(domain or "").strip()
    domain_lookup = domain_clean.lower()
    group_clean = str(group_name or "").strip()
    canonical_label = _canonical_group_label(
        domain=domain_clean, group_name=group_clean
    )
    if not domain_lookup or not group_clean or not canonical_label:
        node_record = {
            "name": canonical_label or group_clean or "UNKNOWN",
            "kind": ["Group"],
            "properties": {
                "name": canonical_label or group_clean or "UNKNOWN",
                "domain": domain_clean.upper(),
            },
        }
        _mark_synthetic_node_record(
            node_record,
            domain=domain_clean,
            source=f"{source}_invalid_group_fallback",
        )
        return node_record

    marked_domain = mark_sensitive(domain_clean, "domain")
    marked_group = mark_sensitive(group_clean, "group")
    lowered = group_clean.casefold()
    well_known_sid = {
        "authenticated users": "S-1-5-11",
        "everyone": "S-1-1-0",
        "anonymous logon": "S-1-5-7",
        "guests": "S-1-5-32-546",
    }.get(lowered)
    domain_rid = {
        "domain admins": 512,
        "domain users": 513,
        "cert publishers": 517,
        "schema admins": 518,
        "enterprise admins": 519,
        "domain computers": 515,
    }.get(lowered)

    def _log_resolved(path: str, node: dict[str, Any]) -> None:
        object_id = _extract_node_object_id(node) or ""
        name = str(node.get("name") or canonical_label or group_clean).strip()
        print_info_debug(
            f"[attack_graph] {source} group resolved for {marked_domain}: "
            f"group={marked_group} path={path} "
            f"name={mark_sensitive(name, 'group')} "
            f"objectid={mark_sensitive(object_id, 'user')}"
        )

    def _finalize(node: dict[str, Any]) -> dict[str, Any]:
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        canonical_name = (
            str(
                node.get("name")
                or props.get("name")
                or node.get("label")
                or canonical_label
            ).strip()
            or canonical_label
        )
        object_id = (
            node.get("objectId")
            or node.get("objectid")
            or props.get("objectId")
            or props.get("objectid")
        )
        finalized = dict(node)
        finalized["name"] = canonical_name
        finalized["kind"] = ["Group"]
        if object_id:
            finalized["objectId"] = object_id
        finalized["properties"] = props or {
            "name": canonical_name,
            "domain": domain_clean.upper(),
        }
        return finalized

    if well_known_sid:
        node = _resolve_principal_node_from_sid(
            shell,
            domain=domain_lookup,
            sid=well_known_sid,
            preferred_kind="group",
        )
        if isinstance(node, dict):
            node = _finalize(node)
            _log_resolved("well_known_sid", node)
            return node
        label_from_sid = _resolve_principal_label_from_sid(
            shell,
            domain=domain_lookup,
            sid=well_known_sid,
            preferred_kind="group",
        )
        node = _build_synthetic_principal_node_from_sid(
            domain=domain_clean,
            sid=well_known_sid,
            label=label_from_sid or canonical_label,
        )
        _mark_synthetic_node_record(
            node, domain=domain_clean, source=f"{source}_well_known_sid_fallback"
        )
        node = _finalize(node)
        _log_resolved("well_known_sid_fallback", node)
        return node

    if domain_rid is not None:
        snapshot = _load_membership_snapshot(shell, domain_lookup)
        domain_sid = _load_domain_sid_from_domains_data(shell, domain_lookup)
        if not domain_sid and isinstance(snapshot, dict):
            domain_sid = _resolve_domain_sid(shell, domain_lookup, snapshot)
        if domain_sid:
            target_sid = f"{domain_sid.upper()}-{domain_rid}"
            node = _resolve_principal_node_from_sid(
                shell,
                domain=domain_lookup,
                sid=target_sid,
                preferred_kind="group",
            )
            if isinstance(node, dict):
                node = _finalize(node)
                _log_resolved(f"domain_rid:{domain_rid}", node)
                return node
            label_from_sid = _resolve_principal_label_from_sid(
                shell,
                domain=domain_lookup,
                sid=target_sid,
                preferred_kind="group",
            )
            node = _build_synthetic_principal_node_from_sid(
                domain=domain_clean,
                sid=target_sid,
                label=label_from_sid or canonical_label,
            )
            _mark_synthetic_node_record(
                node, domain=domain_clean, source=f"{source}_domain_rid_fallback"
            )
            node = _finalize(node)
            _log_resolved(f"domain_rid_fallback:{domain_rid}", node)
            return node
        print_info_debug(
            f"[attack_graph] {source} group RID unresolved for {marked_domain}: "
            f"group={marked_group} rid={domain_rid}"
        )

    node = _resolve_bloodhound_principal_node(
        shell,
        domain_lookup,
        canonical_label,
        entry_kind="group",
        graph=graph,
        lookup_name=group_clean,
    )
    if isinstance(node, dict):
        node = _finalize(node)
        _log_resolved("bloodhound_lookup", node)
        return node

    node = {
        "name": canonical_label,
        "kind": ["Group"],
        "properties": {
            "name": canonical_label,
            "domain": domain_clean.upper(),
        },
    }
    _mark_synthetic_node_record(
        node, domain=domain_clean, source=f"{source}_synthetic_group_fallback"
    )
    node = _finalize(node)
    _log_resolved("synthetic_fallback", node)
    return node


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
    force_source: str | None = None,  # noqa: ARG001 — kept for signature compatibility
) -> list[str]:
    """Resolve *direct* group memberships for a principal (non-recursive).

    Used for persisted membership chains: we avoid writing the full transitive
    closure (principal -> all ancestor groups) because it creates synthetic
    "shortcut" edges that inflate the number of displayed paths. Returns the
    snapshot result when available, else an empty list (no native LDAP
    direct-membership walker is wired up yet).
    """
    sam_clean = (samaccountname or "").strip()
    domain_clean = (domain or "").strip()
    if not sam_clean or not domain_clean:
        return []

    snapshot_groups = _snapshot_get_direct_groups(shell, domain_clean, sam_clean)
    if snapshot_groups:
        return snapshot_groups
    return []


def _attack_path_get_direct_groups_for_group(
    shell: object,
    *,
    domain: str,
    group_name: str,
    force_source: str | None = None,  # noqa: ARG001 — kept for signature compatibility
) -> list[str]:
    """Resolve *direct* parent groups for a Group (Group -> MemberOf -> Group).

    Snapshot-first lookup; returns [] when the snapshot has no entry for the
    group (no native LDAP group->group walker is wired up yet).
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
        principal_domain = _extract_domain_from_node(node, fallback_domain=domain)

        cache_key = f"{kind}:{principal_domain}:{sam.lower()}"
        groups = cache_principal.get(cache_key)
        if groups is None:
            groups = _attack_path_get_direct_groups(
                shell, domain=principal_domain, samaccountname=sam
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


def _resolve_privileged_group_followup_spec(
    node: dict[str, Any],
) -> dict[str, Any] | None:
    """Return one canonical persisted follow-up spec for a privileged group node."""
    if _node_kind(node) != "Group":
        return None

    sid_upper, rid = attack_graph_core._extract_node_sid_and_rid(node)  # noqa: SLF001
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    group_name = str(props.get("name") or node.get("label") or "").strip()
    membership = classify_privileged_membership(
        group_sids=[sid_upper] if sid_upper else [],
        group_names=[group_name] if group_name else [],
    )

    if membership.backup_operators:
        return {
            "relation": "BackupOperatorEscalation",
            "status": "theoretical",
            "reason": "Backup Operators can enable a follow-up path to domain compromise",
            "followup_kind": "direct",
        }
    if membership.dns_admins:
        return {
            "relation": "DnsAdminAbuse",
            "status": "discovered",
            "reason": "DNSAdmins abuse is modeled but blocked in production-safe execution mode",
            "followup_kind": "blocked",
        }
    if rid == 550 and isinstance(sid_upper, str) and sid_upper.startswith("S-1-5-32-"):
        return {
            "relation": "PrintOperatorAbuse",
            "status": "discovered",
            "reason": "Print Operators can unlock a domain-compromise path but ADscan does not execute it automatically yet",
            "followup_kind": "unsupported",
        }
    return None


def persist_privileged_group_followup_edges(
    shell: object,
    domain: str,
    graph: dict[str, Any],
) -> int:
    """Persist canonical privileged-group follow-up edges into the attack graph.

    These edges are ADscan-owned semantics layered on top of persisted
    ``MemberOf`` relationships so that path discovery, execution tracking and
    reporting all use the same source of truth.
    """
    domain_node_id = ensure_domain_node_for_domain(shell, domain, graph)
    if not domain_node_id:
        return 0

    snapshot = _load_membership_snapshot(shell, domain)
    candidate_node_ids: set[str] = set()
    if isinstance(snapshot, dict):
        group_labels: set[str] = set()
        snapshot_group_labels = snapshot.get("group_labels")
        if isinstance(snapshot_group_labels, list):
            for group_label in snapshot_group_labels:
                canonical_group = _canonical_membership_label(
                    domain, str(group_label or "")
                )
                if canonical_group:
                    group_labels.add(canonical_group)
        for mapping_key in ("user_to_groups", "computer_to_groups"):
            mapping = snapshot.get(mapping_key)
            if not isinstance(mapping, dict):
                continue
            for groups in mapping.values():
                if not isinstance(groups, list):
                    continue
                for group in groups:
                    group_label = _canonical_membership_label(domain, str(group or ""))
                    if group_label:
                        group_labels.add(group_label)
        group_to_parents = snapshot.get("group_to_parents")
        if isinstance(group_to_parents, dict):
            for group, parents in group_to_parents.items():
                group_label = _canonical_membership_label(domain, str(group or ""))
                if group_label:
                    group_labels.add(group_label)
                if not isinstance(parents, list):
                    continue
                for parent in parents:
                    parent_label = _canonical_membership_label(
                        domain, str(parent or "")
                    )
                    if parent_label:
                        group_labels.add(parent_label)

        label_to_sid = snapshot.get("label_to_sid")
        if isinstance(label_to_sid, dict) and group_labels:
            for label in sorted(group_labels):
                sid = label_to_sid.get(label)
                group_label = _canonical_membership_label(domain, str(label or ""))
                group_sid = str(sid or "").strip()
                if not group_label:
                    continue
                group_node: dict[str, Any] = {
                    "name": group_label,
                    "label": group_label,
                    "kind": ["Group"],
                    "objectId": group_sid or None,
                    "properties": {
                        "name": group_label,
                        "domain": str(domain or "").strip().upper(),
                        **({"objectid": group_sid} if group_sid else {}),
                    },
                }
                upsert_nodes(graph, [group_node])
                candidate_node_ids.add(_node_id(group_node))

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return 0
    if not candidate_node_ids:
        candidate_node_ids = {
            str(node_id)
            for node_id, node in nodes_map.items()
            if isinstance(node, dict) and _node_kind(node) == "Group"
        }

    created = 0
    for node_id in sorted(candidate_node_ids):
        node = nodes_map.get(node_id)
        if not isinstance(node, dict):
            continue
        followup = _resolve_privileged_group_followup_spec(node)
        if not isinstance(followup, dict):
            continue

        group_label = str(node.get("label") or node.get("name") or "").strip()
        member_users = _get_users_in_group_label_from_snapshot(
            shell, domain, group_label
        )
        affected_principal_count = (
            len(member_users) if isinstance(member_users, list) else 0
        )
        sample_users = (
            [str(user) for user in member_users[:5]]
            if isinstance(member_users, list)
            else []
        )

        before_count = len(
            graph.get("edges") if isinstance(graph.get("edges"), list) else []
        )
        upsert_edge(
            graph,
            from_id=str(node_id),
            to_id=domain_node_id,
            relation=str(followup["relation"]),
            edge_type="privileged_group_followup",
            status=str(followup.get("status") or "discovered"),
            notes={
                "source": "privileged_group_followup",
                "followup_source_group": str(node.get("label") or ""),
                "followup_kind": str(followup.get("followup_kind") or ""),
                "reason": str(followup.get("reason") or ""),
                "affected_principal_count": affected_principal_count,
                "sample_users": sample_users,
            },
        )
        after_count = len(
            graph.get("edges") if isinstance(graph.get("edges"), list) else []
        )
        if after_count > before_count:
            created += 1
    return created


def _persist_synthetic_followup_node(
    graph: dict[str, Any],
    *,
    name: str,
    kind: str,
    domain: str,
    source: str,
    properties: dict[str, Any] | None = None,
) -> str:
    """Persist one synthetic follow-up state node and return its node id."""
    node_record: dict[str, Any] = {
        "name": str(name),
        "kind": [str(kind)],
        "properties": {
            "name": str(name),
            "domain": str(domain or "").strip().upper(),
            **(properties or {}),
        },
    }
    _mark_synthetic_node_record(
        node_record,
        domain=domain,
        source=source,
    )
    upsert_nodes(graph, [node_record])
    return _node_id(node_record)


def rodc_followup_state_label(*, target_computer: str, stage: str) -> str:
    """Return the canonical synthetic node label for one RODC follow-up stage."""
    rodc_label = str(target_computer or "").strip()
    stage_key = str(stage or "").strip().lower()
    stage_titles = {
        "prepare_credential_caching": "RODC Credential Cache Ready",
        "extract_krbtgt": "RODC krbtgt Secret Ready",
        "forge_golden_ticket": "RODC Golden Ticket Ready",
    }
    title = stage_titles.get(stage_key, "RODC Follow-up State")
    return f"{title} ({rodc_label})"


def persist_rodc_followup_chain_edges(
    shell: object,
    domain: str,
    graph: dict[str, Any],
) -> int:
    """Persist the canonical multi-step RODC follow-up chain into the attack graph."""
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return 0

    domain_node_id = ensure_domain_node_for_domain(shell, domain, graph)
    if not domain_node_id:
        return 0

    created = 0
    for node_id, node in list(nodes_map.items()):
        if not isinstance(node, dict) or not node_is_rodc_computer(node):
            continue

        rodc_label = str(node.get("label") or node.get("name") or node_id).strip()
        cache_ready_label = rodc_followup_state_label(
            target_computer=rodc_label,
            stage="prepare_credential_caching",
        )
        cache_ready_id = _persist_synthetic_followup_node(
            graph,
            name=cache_ready_label,
            kind="FollowupState",
            domain=domain,
            source="rodc_followup_chain",
            properties={
                "rodc_target": rodc_label,
                "stage": "prepare_credential_caching",
            },
        )
        krbtgt_ready_label = rodc_followup_state_label(
            target_computer=rodc_label,
            stage="extract_krbtgt",
        )
        krbtgt_ready_id = _persist_synthetic_followup_node(
            graph,
            name=krbtgt_ready_label,
            kind="FollowupState",
            domain=domain,
            source="rodc_followup_chain",
            properties={
                "rodc_target": rodc_label,
                "stage": "extract_krbtgt",
            },
        )
        golden_ticket_label = rodc_followup_state_label(
            target_computer=rodc_label,
            stage="forge_golden_ticket",
        )
        golden_ticket_id = _persist_synthetic_followup_node(
            graph,
            name=golden_ticket_label,
            kind="FollowupState",
            domain=domain,
            source="rodc_followup_chain",
            properties={
                "rodc_target": rodc_label,
                "stage": "forge_golden_ticket",
            },
        )

        chain = (
            (
                str(node_id),
                cache_ready_id,
                "PrepareRodcCredentialCaching",
                "Prepare RODC credential caching via password-replication-policy changes on the RODC object",
            ),
            (
                cache_ready_id,
                krbtgt_ready_id,
                "ExtractRodcKrbtgtSecret",
                "Extract per-RODC krbtgt material from the compromised RODC",
            ),
            (
                krbtgt_ready_id,
                golden_ticket_id,
                "ForgeRodcGoldenTicket",
                "Forge a reusable RODC golden ticket from recovered per-RODC krbtgt material",
            ),
            (
                golden_ticket_id,
                domain_node_id,
                "KerberosKeyList",
                "Use the forged RODC golden ticket to retrieve Key List data from a writable domain controller",
            ),
        )

        for from_id, to_id, relation, reason in chain:
            before_count = len(
                graph.get("edges") if isinstance(graph.get("edges"), list) else []
            )
            upsert_edge(
                graph,
                from_id=from_id,
                to_id=to_id,
                relation=relation,
                edge_type="rodc_followup",
                status="theoretical",
                notes={
                    "source": "rodc_followup_chain",
                    "rodc_target": rodc_label,
                    "reason": reason,
                },
            )
            after_count = len(
                graph.get("edges") if isinstance(graph.get("edges"), list) else []
            )
            if after_count > before_count:
                created += 1
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
            node_record = _resolve_bloodhound_principal_node(
                shell,
                domain,
                group_clean,
                entry_kind="group",
                graph=None,
                lookup_name=_extract_group_name_from_bh(group_clean),
            )
            if isinstance(node_record, dict):
                upsert_nodes(runtime_graph, [node_record])
                return _node_id(node_record)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

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
            principal_domain = _extract_domain_from_node(node, fallback_domain=domain)
            cache_key = f"{kind}:{principal_domain}:{sam.lower()}"
            groups = cache.get(cache_key)
            if groups is None:
                groups = _attack_path_get_recursive_groups(
                    shell, domain=principal_domain, samaccountname=sam
                )
                cache[cache_key] = groups
        else:
            group_label = _principal_label_for_group_lookup(node)
            if not group_label:
                continue
            group_domain = _extract_domain_from_node(node, fallback_domain=domain)
            cache_key = f"{kind}:{group_domain}:{group_label.lower()}"
            groups = cache.get(cache_key)
            if groups is None:
                groups = _attack_path_get_recursive_groups_for_group(
                    shell, domain=group_domain, group_name=group_label
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
    workspace_cwd = resolve_workspace_cwd(shell)
    domains_dir = getattr(shell, "domains_dir", "domains")
    return domain_subpath(workspace_cwd, domains_dir, domain, "attack_graph.json")


def load_merged_attack_graph(shell: object, domains: list[str]) -> dict[str, Any]:
    """Load and merge attack graphs for multiple domains into one unified graph.

    Nodes are already namespaced as NAME@DOMAIN so there are no key collisions.
    The merged graph is ephemeral (not persisted) and is used only for cross-domain
    path computation.

    Args:
        shell: Shell or workspace context used to resolve graph file paths.
        domains: Ordered list of domain names whose attack graphs will be merged.

    Returns:
        Unified attack graph dict with keys ``schema_version``, ``nodes``,
        ``edges``, and ``_merged_domains``. Edges are deduplicated by the SAME
        identity ``upsert_edge`` uses — ``(from, relation, to, share_identity)`` —
        so a cross-domain edge persisted in one domain and its foreign-endpoint
        twin in another collapse to one, without flattening distinct edges that
        merely share a ``kind``.
    """
    merged: dict[str, Any] = {
        "schema_version": ATTACK_GRAPH_SCHEMA_VERSION,
        "nodes": {},
        "edges": [],
        "_merged_domains": list(domains),
    }
    seen_edge_keys: set[tuple[str, str, str, str]] = set()

    # Re-key every node to a GLOBALLY-unique id (the canonical ``NAME@DOMAIN``
    # label; see ``_merged_node_global_id``). Two resolution maps are built so
    # edges remap correctly EVEN when a cross-domain edge in domain A references a
    # foreign node by an id/SID that only exists in domain B's file:
    #   * ``local_to_global[domain]`` — that domain's own ``local_id -> global_id``.
    #   * ``sid_to_global`` — a GLOBAL ``objectId/SID -> global_id`` index, so a
    #     foreign edge that references a node by its ``name:<SID>`` local id or a
    #     bare SID resolves to the foreign node's label-based global id even though
    #     the label-based re-key made the two ids differ.
    per_domain_local_to_global: dict[str, dict[str, str]] = {}
    sid_to_global: dict[str, str] = {}
    per_domain_graphs: dict[str, dict[str, Any]] = {}

    # Pass 1 — nodes.
    for domain in domains:
        graph = load_attack_graph(shell, domain)
        per_domain_graphs[domain] = graph
        raw_nodes = graph.get("nodes")
        raw_nodes = raw_nodes if isinstance(raw_nodes, dict) else {}
        local_to_global: dict[str, str] = {}
        per_domain_local_to_global[domain] = local_to_global
        for local_id, node_data in raw_nodes.items():
            global_id = _merged_node_global_id(
                node_data, domain=domain, local_id=local_id
            )
            local_to_global[local_id] = global_id
            object_id = _merged_node_object_id(node_data)
            if object_id and object_id not in sid_to_global:
                # First (primary-domain-first) real node keyed by this SID wins the
                # global index; a per-domain BUILTIN SID (label-keyed, distinct
                # global ids) never lands here because two ADMINISTRATORS@<dom>
                # share the SID — only the first is indexed, and edges referencing
                # that SID from ANOTHER domain resolve via the local map first (see
                # the remap order below), so BUILTIN edges never cross domains.
                sid_to_global[object_id] = global_id
            # Primary domain is ordered first, so its node wins on any real
            # (same-label) collision; a stand-in endpoint is overwritten by the
            # real foreign node it merges onto.
            merged["nodes"].setdefault(global_id, node_data)
            if not isinstance(merged["nodes"].get(global_id), dict) or bool(
                (merged["nodes"][global_id].get("properties") or {}).get(
                    "cross_domain_endpoint"
                )
            ):
                # A previously-inserted stand-in must yield to a real node.
                merged["nodes"][global_id] = node_data

    # Pass 2 — edges. Remap endpoints to the global ids and deduplicate by the
    # upsert identity so we neither drop a distinct edge nor duplicate a
    # cross-domain edge and its foreign twin. A reference is resolved LOCAL-first
    # (the edge's own domain), then via the global SID index (a cross-domain
    # reference to a foreign node whose id lives only in the other domain's file).
    for domain in domains:
        graph = per_domain_graphs[domain]
        local_to_global = per_domain_local_to_global[domain]
        for edge in graph.get("edges", []):
            if not isinstance(edge, dict):
                continue
            from_local = str(edge.get("from") or edge.get("source") or "")
            to_local = str(edge.get("to") or edge.get("target") or "")
            from_global = _resolve_merged_endpoint(
                from_local, local_to_global, sid_to_global
            )
            to_global = _resolve_merged_endpoint(
                to_local, local_to_global, sid_to_global
            )
            relation = _normalize_relation(str(edge.get("relation") or ""))
            key = (
                from_global,
                relation,
                to_global,
                _edge_share_identity(relation, edge.get("notes")),
            )
            if key in seen_edge_keys:
                continue
            seen_edge_keys.add(key)
            remapped = dict(edge)
            remapped["from"] = from_global
            remapped["to"] = to_global
            merged["edges"].append(remapped)

    return merged


def _merged_node_object_id(node: dict[str, Any]) -> str:
    """Return a node's objectId/SID (top-level or under ``properties``), upper-cased."""
    object_id = str(node.get("objectId") or node.get("objectid") or "").strip()
    if not object_id:
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        object_id = str(props.get("objectid") or "").strip()
    return object_id.upper()


def _resolve_merged_endpoint(
    reference: str,
    local_to_global: dict[str, str],
    sid_to_global: dict[str, str],
) -> str:
    """Resolve an edge endpoint reference to its merged-graph global id.

    LOCAL-first (the edge's own domain map — so a per-domain BUILTIN SID edge stays
    within its domain), then the global SID index (a cross-domain edge that
    references a foreign node by its ``name:<SID>`` local id or a bare SID, when
    that node's node-entry lives only in the other domain's file), then the raw
    reference unchanged.
    """
    if reference in local_to_global:
        return local_to_global[reference]
    ref_upper = reference.upper()
    # A ``name:<SID>`` local-id reference to a foreign node → index by the SID.
    sid = ref_upper[len("NAME:") :] if ref_upper.startswith("NAME:") else ref_upper
    if sid in sid_to_global:
        return sid_to_global[sid]
    return reference


def _merged_node_global_id(node: dict[str, Any], *, domain: str, local_id: str) -> str:
    """Return a globally-unique merged-graph node id.

    Identity is the canonical ``NAME@DOMAIN`` label, NOT the bare objectId/SID.
    This is decisive for two node classes the bare-SID key got wrong:

    * **Per-domain BUILTIN groups.** ``BUILTIN\\Administrators`` is
      ``S-1-5-32-544`` in EVERY domain; keying by that shared SID FUSED
      ``ADMINISTRATORS@ESSOS`` / ``@NORTH`` / ``@SEVENKINGDOMS`` into one node and
      hung all three domains' ``DCSync`` edges off it — inventing false
      cross-domain compromise paths (a DA of forest A "DCSyncing" forest B). The
      ``@DOMAIN`` suffix in the label keeps them SEPARATE.
    * **Foreign-endpoint stand-ins.** A collector stand-in and the real
      SID-keyed node for the same account carry the SAME ``NAME@DOMAIN`` label,
      so keying by label correctly MERGES them into one.

    Genuinely-global well-known principals (``Everyone@WELLKNOWN`` = ``S-1-1-0``,
    ``Authenticated Users@WELLKNOWN`` = ``S-1-5-11``) carry a domain-agnostic
    ``@WELLKNOWN`` label that is identical across domains, so keying by label
    correctly FUSES them into one shared node.

    Resolution order:
        1. A canonical ``NAME@DOMAIN`` / ``@WELLKNOWN`` label (has ``@``) — the
           domain-qualified label distinguishes per-domain objects and unifies
           genuinely-global and real/stand-in pairs.
        2. Otherwise the globally-unique objectId/SID — used for container-class
           objects (Container/GPO/OU/Domain) whose canonical label is a bare name
           or a GUID that repeats across domains (e.g. the Default Domain Policy
           GUID); their objectId is a domain-unique GUID/domain-SID, never a
           shared well-known SID (those always carry an ``@``-qualified label and
           take slot 1), so this never re-introduces the cross-domain fusion.
        3. Otherwise a non-``@`` label, domain-namespaced so an ambiguous shared
           label cannot fuse across domains.
        4. Otherwise the domain-prefixed local id.
    """
    label = _canonical_node_label(node)
    if label and label not in {"N/A", ""} and "@" in label:
        return f"label:{label.upper()}"
    object_id = _merged_node_object_id(node)
    if object_id:
        return f"name:{object_id}"
    if label and label not in {"N/A", ""}:
        return f"{str(domain or '').strip().upper()}::label:{label.upper()}"
    return f"{str(domain or '').strip().upper()}::{local_id}"


def list_domains_with_attack_graph(shell: object) -> list[str]:
    """List every workspace domain that has a persisted ``attack_graph.json``.

    Scans ``<workspace>/<domains_dir>/*/attack_graph.json`` so path computation
    can decide whether to merge (more than one domain graph) or run single-domain.

    Returns:
        Sorted domain names (directory names) that carry an attack graph.
    """
    workspace_cwd = resolve_workspace_cwd(shell)
    if not workspace_cwd:
        return []
    domains_dir = getattr(shell, "domains_dir", "domains")
    root = os.path.join(workspace_cwd, domains_dir)
    if not os.path.isdir(root):
        return []
    found: list[str] = []
    try:
        for entry in os.listdir(root):
            graph_file = os.path.join(root, entry, "attack_graph.json")
            if os.path.isfile(graph_file):
                found.append(entry)
    except OSError:
        return []
    return sorted(found)


def _order_domains(domains: list[str], *, primary: str) -> list[str]:
    """Return ``domains`` with ``primary`` first, so the merged graph's primary
    domain wins on any node-label collision during the merge."""
    primary_norm = str(primary or "").strip().lower()
    ordered = [d for d in domains if str(d).strip().lower() == primary_norm]
    ordered += [d for d in domains if str(d).strip().lower() != primary_norm]
    return ordered


def _load_attack_graph_for_paths(shell: object, domain: str) -> dict[str, Any]:
    """Load the graph the DFS should run over for ``domain``.

    When the workspace has MORE THAN ONE domain graph, return the MERGED graph of
    all of them (primary ``domain`` first) so a persisted cross-domain edge lets
    the DFS cross the boundary — this is the single, always-on compute path (no
    caller-selected merge mode). When there is exactly one domain graph, return
    it unchanged, so single-domain runs stay byte-identical.
    """
    domains_with_graph = list_domains_with_attack_graph(shell)
    if len(domains_with_graph) > 1:
        return load_merged_attack_graph(
            shell, _order_domains(domains_with_graph, primary=domain)
        )
    return load_attack_graph(shell, domain)


def persist_cross_domain_trust_edges(
    shell: object,
    *,
    domain: str,
    domains_data: "Mapping[str, Any] | None",
    foreign_domain_nodes: "Mapping[str, dict[str, Any]] | None" = None,
) -> bool:
    """Persist CrossOrgTgtDelegation + RaiseChild trust escalation edges to disk.

    These edges were previously minted in-memory only (``virtual``) at query time,
    so a status write (``update_edge_status_by_labels``) had no persisted edge to
    land on and a reload re-derived them as ``theoretical``. This runs the same
    couplings against the ORIGIN domain's on-disk graph and saves it, so the edge
    (and its execution status) survives reloads. The query-time merge re-runs the
    couplings as a no-op once the persisted edge exists.

    A coupling needs BOTH domain nodes present. When the trust partner's Domain
    node is not in this domain's own graph, ``foreign_domain_nodes`` (partner FQDN
    upper -> a light Domain node payload, built from the cross-domain registry)
    supplies it, keyed by the partner node's graph id so it merges cleanly.

    Best-effort and idempotent. Returns True when it changed (and re-saved) the
    graph.
    """
    graph = load_attack_graph(shell, domain)
    nodes = graph.setdefault("nodes", {})
    if not isinstance(nodes, dict):
        nodes = {}
        graph["nodes"] = nodes
    if foreign_domain_nodes:
        for node_id, node_payload in foreign_domain_nodes.items():
            if node_id and node_id not in nodes and isinstance(node_payload, dict):
                nodes[node_id] = node_payload

    # NOTE: ``load_attack_graph`` already runs these couplings IN MEMORY on every
    # load (via ``_enrich_foreign_dc_nodes``), so the edge is usually present in
    # ``graph`` before we call the couplings again — their idempotent return would
    # then be False even though nothing is on DISK yet. So we do not gate the save
    # on the coupling return: we save whenever a synthesized trust edge is present
    # in the graph, materializing the previously in-memory-only edge to disk so its
    # execution status survives reloads. Idempotent — a second call re-saves the
    # same content (no duplicate, upsert identity).
    attack_graph_core.couple_cross_org_tgt_delegation_edges(graph, domains_data)
    attack_graph_core.couple_raise_child_edges(graph, domains_data)
    synthesized = [
        edge
        for edge in graph.get("edges", [])
        if isinstance(edge, dict)
        and str(edge.get("relation") or "") in {"CrossOrgTgtDelegation", "RaiseChild"}
        and str((edge.get("notes") or {}).get("synthesized_from") or "").startswith(
            ("cross_org_tgt_delegation", "within_forest_child_parent")
        )
    ]
    if not synthesized:
        return False
    save_attack_graph(shell, domain, graph)
    return True


def _enrich_foreign_dc_nodes(shell: object, domain: str, graph: dict[str, Any]) -> None:
    """Back-fill writable-DC markers on pivot-discovered DC nodes from inventory.

    Thin shell-aware wrapper over
    :func:`attack_graph_core.enrich_foreign_dc_nodes_from_inventory`: it reads the
    live ``shell.domains_data`` (which holds every trusted domain's DC inventory
    from trust enumeration) and enriches ``graph`` IN PLACE, in memory only. This
    is what lets the F6 direct-DCSync overlay couple a cross-forest compromised DC
    (e.g. ``dc02.darkzero.ext`` reached via an MSSQL linked-server pivot) to its
    own trusted domain node. Best-effort — never raises into the load path.
    """
    try:
        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict) or not domains_data:
            return
        changed = attack_graph_core.enrich_foreign_dc_nodes_from_inventory(
            graph, domains_data
        )
        if changed:
            print_info_debug(
                f"[attack_graph] back-filled foreign DC role markers in "
                f"{mark_sensitive(domain, 'domain')} attack graph (in-memory)."
            )
        # Couple the cross-forest TGT-delegation escalation AFTER DC enrichment so
        # any synthetic trusted-domain node it needs already exists. Adds a derived
        # escalation edge (compromised trusted domain -> trusting domain) only when
        # the trust actually carries CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION.
        coupled = attack_graph_core.couple_cross_org_tgt_delegation_edges(
            graph, domains_data
        )
        if coupled:
            print_info_debug(
                f"[attack_graph] coupled cross-forest TGT-delegation escalation edge "
                f"in {mark_sensitive(domain, 'domain')} attack graph (in-memory)."
            )
        # Same-forest child->parent RaiseChild escalation edge (intra-forest
        # analogue of the cross-org coupling); only when a WITHIN_FOREST trust to a
        # known parent exists and both domain nodes are present.
        coupled_rc = attack_graph_core.couple_raise_child_edges(graph, domains_data)
        if coupled_rc:
            print_info_debug(
                f"[attack_graph] coupled child->parent RaiseChild escalation edge "
                f"in {mark_sensitive(domain, 'domain')} attack graph (in-memory)."
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def load_attack_graph(shell: object, domain: str) -> dict[str, Any]:
    """Load or initialize the attack graph for a domain (epoch-memoized).

    Thin memoizing entry over :func:`_load_and_prepare_attack_graph`. During the
    per-path readiness / offer-evaluation pass this is called thousands of times
    for the same unchanged graph; the memo returns the already-parsed, already-
    enriched object for a ``(domain, epoch)`` without touching disk. The epoch is
    :func:`attack_paths_epoch_fingerprint` — ``(graph_mtime, snapshot_mtime)`` —
    so any :func:`save_attack_graph` (which bumps the graph mtime) forces the next
    load to miss the memo and re-read, making the memo provably never-stale. See
    ``_LOAD_ATTACK_GRAPH_MEMO`` for the read-only-callers audit.
    """
    if not _LOAD_ATTACK_GRAPH_MEMO_ENABLED:
        return _load_and_prepare_attack_graph(shell, domain)

    domain_key = str(domain or "").strip().lower()
    try:
        path = _graph_path(shell, domain)
        # Only memoize when the graph file EXISTS: the file-absent branch returns a
        # fresh empty dict (an ambiguous ``(None, None)`` epoch shared by every
        # not-yet-created graph), which a caller then mutates before the first save,
        # so caching it would leak that scaffold across unrelated domains/workspaces.
        if not os.path.exists(path):
            return _load_and_prepare_attack_graph(shell, domain)
        # The load memo keys on the MTIME epoch unconditionally — NOT the public
        # structural epoch. Two reasons: (1) the load memo only needs to
        # invalidate on ANY file change (a re-read of the parsed graph is cheap;
        # it is the downstream COMPUTE that is expensive and wants the structural
        # epoch), and (2) the structural epoch computes its hash BY loading the
        # graph via this very function — keying the load memo on it would recurse.
        epoch = _mtime_epoch_fingerprint(shell, domain)
    except Exception:  # noqa: BLE001 — never fail a load over the memo key
        return _load_and_prepare_attack_graph(shell, domain)

    # Key on the resolved FILE PATH (not just the domain name): the same domain
    # name legitimately maps to different files across workspaces, and the mtime
    # epoch alone cannot tell them apart.
    memo_key = (domain_key, path, epoch)
    cached = _LOAD_ATTACK_GRAPH_MEMO.get(memo_key)
    if cached is not None:
        _LOAD_ATTACK_GRAPH_MEMO.move_to_end(memo_key)
        return cached

    data = _load_and_prepare_attack_graph(shell, domain)
    _LOAD_ATTACK_GRAPH_MEMO[memo_key] = data
    _LOAD_ATTACK_GRAPH_MEMO.move_to_end(memo_key)
    while len(_LOAD_ATTACK_GRAPH_MEMO) > _LOAD_ATTACK_GRAPH_MEMO_MAX_ENTRIES:
        _LOAD_ATTACK_GRAPH_MEMO.popitem(last=False)
    return data


def _load_and_prepare_attack_graph(shell: object, domain: str) -> dict[str, Any]:
    """Load or initialize the attack graph for a domain."""
    path = _graph_path(shell, domain)
    if os.path.exists(path):
        data = read_json_file(path)
        schema_version = str(data.get("schema_version") or "")
        # Phase 2 (schema 1.2) added a top-level `kind` field to every
        # edge. Schema 1.1 graphs upgrade transparently: backfill the
        # kinds in memory; the schema_version is bumped on the next save.
        if schema_version in {ATTACK_GRAPH_SCHEMA_VERSION, "1.1"}:
            if schema_version != ATTACK_GRAPH_SCHEMA_VERSION:
                edges_list = data.get("edges")
                if isinstance(edges_list, list):
                    for _edge in edges_list:
                        if isinstance(_edge, dict) and not _edge.get("kind"):
                            _edge["kind"] = classify_edge_kind(
                                str(_edge.get("relation") or "")
                            ).value
            maintenance = _get_attack_graph_maintenance_state(data)
            maintenance_target = _maintenance_key(_ATTACK_GRAPH_MAINTENANCE_VERSION)
            maintenance_version = str(maintenance.get("normalization") or "").strip()
            snapshot = _load_membership_snapshot(shell, domain)

            repaired = False
            normalized = False
            domain_normalized = False
            kind_normalized = False
            metadata_updated = 0
            reuse_notes_compacted = 0
            target_priority_overrides_updated = False

            # These maintenance passes are expensive on large graphs and should
            # run only once per maintenance version.
            if maintenance_version != maintenance_target:
                # Historical graphs may contain duplicate nodes (same label, different IDs).
                # Repair them early so path computations stay consistent and self-loop
                # avoidance works as intended.
                repaired = _repair_duplicate_nodes_by_label(data)
                normalized = _normalize_user_computer_labels(data)
                domain_normalized = _normalize_domain_labels(data)
                kind_normalized = _normalize_principal_kinds_from_snapshot(
                    data, snapshot
                )
                metadata_updated = _refresh_attack_graph_edge_metadata(data)
                reuse_notes_compacted = _compact_local_reuse_edge_notes(data)
                maintenance["normalization"] = maintenance_target

            target_priority_overrides_updated = (
                _apply_recursive_target_priority_overrides(
                    data,
                    snapshot,
                    domain=domain,
                )
            )

            if (
                maintenance_version != maintenance_target
                or repaired
                or normalized
                or domain_normalized
                or kind_normalized
                or metadata_updated
                or reuse_notes_compacted
                or target_priority_overrides_updated
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
                    if domain_normalized:
                        parts.append("normalized domain labels")
                    if kind_normalized:
                        parts.append("normalized principal kinds")
                    if metadata_updated:
                        parts.append("classified edge metadata")
                    if reuse_notes_compacted:
                        parts.append("compacted local reuse notes")
                    if target_priority_overrides_updated:
                        parts.append("updated recursive target priority overrides")
                    action = ", ".join(parts) if parts else "updated"
                    print_info_debug(
                        f"[attack_graph] {action} in {marked_domain} attack graph."
                    )
                except Exception:
                    pass
                save_attack_graph(shell, domain, data)
            # In-memory only, applied on EVERY load AFTER the persist decision so
            # it never reaches disk: back-fill the writable-DC role marker on a
            # foreign (pivot-discovered) DC node from the trust-enum inventory in
            # domains_data, and synthesize the trusted domain's Domain node when
            # absent. This lets the F6 DCSync overlay couple a cross-forest
            # compromised DC to its own domain. Depends on live domains_data, so
            # it cannot be a version-gated maintenance pass.
            _enrich_foreign_dc_nodes(shell, domain, data)
            attack_graph_core._backfill_privilege_tier(data)
            return data
        if schema_version in {"1.0"}:
            migrated = _migrate_attack_graph(data)
            if migrated:
                _repair_duplicate_nodes_by_label(migrated)
                _normalize_user_computer_labels(migrated)
                _normalize_domain_labels(migrated)
                snapshot = _load_membership_snapshot(shell, domain)
                _normalize_principal_kinds_from_snapshot(migrated, snapshot)
                _refresh_attack_graph_edge_metadata(migrated)
                _compact_local_reuse_edge_notes(migrated)
                _apply_recursive_target_priority_overrides(
                    migrated,
                    snapshot,
                    domain=domain,
                )
                maintenance = _get_attack_graph_maintenance_state(migrated)
                maintenance["normalization"] = _maintenance_key(
                    _ATTACK_GRAPH_MAINTENANCE_VERSION
                )
                save_attack_graph(shell, domain, migrated)
                _enrich_foreign_dc_nodes(shell, domain, migrated)
                attack_graph_core._backfill_privilege_tier(migrated)
                return migrated
    return {
        "schema_version": ATTACK_GRAPH_SCHEMA_VERSION,
        "domain": domain,
        "generated_at": _utc_now_iso(),
        "maintenance": {
            "normalization": _maintenance_key(_ATTACK_GRAPH_MAINTENANCE_VERSION),
            "bh_ce_synced": True,  # New graphs sync edges in real-time; no migration needed.
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


def _policy_blocked_edge_notes(
    graph: dict[str, Any],
    *,
    relation: str,
    to_id: str,
    support: "RelationSupport",
) -> dict[str, Any]:
    """Return the notes marker for a ``policy_blocked`` graph edge.

    EVERY hard-refused safety abstention — a destructive reset
    (ForceChangePassword against a computer/machine account) OR a disruptive
    technique (Zerologon, NoPac, PrintNightmare, DNSAdmins abuse) — is routed
    through the single :func:`classify_destructive` classifier and stamped
    ``blocked_kind="dangerous_destructive"`` plus a client-safe reason, so the
    client-facing render places all of them in the "Not executed for safety"
    bucket. Only a policy_blocked step that is NOT hard-blocked (e.g. the
    opt-in-only ForceChangePassword on a user) keeps ``blocked_kind="dangerous"``.
    Only the notes are enriched — the ``blocked`` status token is unaffected.
    """
    from adscan_internal.services.destructive_action_policy import (  # noqa: PLC0415
        classify_destructive,
    )

    nodes = graph.get("nodes")
    target_node = (
        nodes.get(str(to_id or "").strip()) if isinstance(nodes, dict) else None
    )
    target_kind = (
        str(target_node.get("kind") or "").strip().lower()
        if isinstance(target_node, dict)
        else ""
    )
    verdict = classify_destructive(relation, target_kind)
    if verdict.hard_blocked:
        return {
            "blocked_kind": "dangerous_destructive",
            # Both keys carry the SAME authored, client-facing sentence — never
            # ``support.reason``, which is the catalog's engineering-register
            # note and must not reach a deliverable.
            "reason": verdict.client_safe_reason,
            "client_safe_reason": verdict.client_safe_reason,
            "exec_support": "policy_blocked",
        }
    # Opt-in-only (not hard-blocked). ``support.reason`` is the catalog's
    # engineering-register note, so the authored client-facing sentence from the
    # classifier is stamped alongside it — the deliverable renders
    # ``client_safe_reason`` and never the internal note.
    return {
        "blocked_kind": "dangerous",
        "reason": support.reason,
        "client_safe_reason": verdict.client_safe_reason,
        "exec_support": "policy_blocked",
    }


def _classify_edge_execution_support(
    graph: dict[str, Any],
    *,
    relation: str,
    to_id: str,
) -> RelationSupport:
    """Return support classification for one persisted graph edge.

    Most relations are classified purely by relation name. Some disruptive ACL
    actions need graph-aware target policy checks so that dangerous paths are
    blocked before execution.
    """
    base_support = classify_relation_support(relation)
    nodes = graph.get("nodes")
    target_node = (
        nodes.get(str(to_id or "").strip()) if isinstance(nodes, dict) else None
    )
    target_kind = (
        str(target_node.get("kind") or "").strip().lower()
        if isinstance(target_node, dict)
        else ""
    )
    if (
        normalize_execution_relation(relation) == "writeaccountrestrictions"
        and target_kind == "computer"
    ):
        return RelationSupport(
            kind="supported",
            reason="ACL/ACE abuse (WriteAccountRestrictions -> RBCD on computer)",
            compromise_semantics=base_support.compromise_semantics,
            compromise_effort=base_support.compromise_effort,
        )
    # Safety hard-block: ForceChangePassword against ANY computer/machine account
    # resets that host's password and is disruptive (not just Tier Zero DCs/RODCs).
    # Routed through the destructive-action SSOT so the graph classification, the
    # display, and the executor stay aligned.
    from adscan_internal.services.destructive_action_policy import (  # noqa: PLC0415
        classify_destructive,
    )

    if normalize_execution_relation(relation) == "forcechangepassword":
        destructive_verdict = classify_destructive(relation, target_kind)
        if destructive_verdict.hard_blocked:
            return RelationSupport(
                kind="policy_blocked",
                reason=destructive_verdict.client_safe_reason,
                compromise_semantics=base_support.compromise_semantics,
                compromise_effort=base_support.compromise_effort,
            )
    return base_support


def _desired_exec_support_state(
    graph: dict[str, Any],
    *,
    relation: str,
    to_id: str,
) -> tuple[str, dict[str, Any]]:
    """Return the ``(status, notes)`` the execution-support classifier wants.

    The one definition of "can ADscan run this relation, and if not, why" that
    the persistence seam and the version reconcile both apply, so a graph saved
    in the session that discovered an edge and the same graph reopened later
    cannot disagree about it.
    """
    support = _classify_edge_execution_support(graph, relation=relation, to_id=to_id)
    version = getattr(telemetry, "VERSION", "unknown")
    notes: dict[str, Any] = {
        "exec_support": support.kind,
        "exec_support_version": version,
    }
    if support.kind == "policy_blocked":
        notes.update(
            _policy_blocked_edge_notes(
                graph, relation=relation, to_id=to_id, support=support
            )
        )
        return "blocked", notes
    if support.kind == "unsupported":
        notes.update(
            {
                "blocked_kind": "unsupported",
                "reason": support.reason,
                "exec_support": "unsupported",
            }
        )
        return "unsupported", notes
    return "discovered", notes


#: Statuses that mean "nothing has been decided about this edge yet", so the
#: persistence seam may stamp the execution-support verdict over them.
#: ``theoretical`` is here because it is a PATH display token that raw builders
#: borrowed as an edge placeholder — the reconcile has always overwritten it, and
#: an edge left on it reads to the client as a live, runnable avenue.
#: Everything else — ``success`` / ``attempted`` / ``failed`` / ``error`` /
#: ``unavailable`` (execution outcomes), ``closed_by_configuration`` (the client's
#: own hardening) and a safety ``blocked`` — is a verdict the seam must never
#: touch.
_UNDECIDED_EDGE_STATUSES: frozenset[str] = frozenset({"", "discovered", "theoretical"})


def classify_graph_edges(graph: dict[str, Any]) -> int:
    """Give every edge the classification the canonical writer would have given it.

    Classification is a property of *persisting* the document, not of whichever
    writer happened to build the edge. :func:`upsert_edge` classifies what it
    creates, but a writer that appends a dict to ``graph["edges"]`` directly does
    not — and two of them (the CVE scanner's derived-edge inserter and the NTLMv1
    relay builder) shipped noPac, PrintNightmare and the whole NTLMv1 family with
    no ``category`` and no execution-support verdict. The finding derivation
    filters on ``category == "exploitation"``, so it never saw them at all;
    ``CrackNTLMv1`` additionally sat on its builder's ``theoretical`` placeholder,
    which reads as a live avenue when the technique has no crack backend at all.
    Running both stamps here means no writer can persist a half-classified edge.

    Two stamps, with different rules:

    * ``category`` / ``vuln_key`` — a pure function of the relation, so it is
      re-derived for EVERY edge on every save and always agrees with the catalog.
      Cheap, and it also corrects a key a since-renamed catalog entry left stale.
    * execution support — applied ONLY to an **exploitation** edge that carries no
      ``exec_support`` note yet AND whose status is still undecided
      (:data:`_UNDECIDED_EDGE_STATUSES`). Exploitation is the exact set the
      finding derivation and the exposure gate read, and restricting the stamp to
      it keeps the seam from rewriting the notes of every ``MemberOf`` /
      ``GenericAll`` edge in a large directory. It is one-shot per edge and
      normally does nothing: an edge from ``upsert_edge`` already carries the
      note, and an execution outcome or a configuration close is never overwritten.

    The stamp is deliberately NOT the version reconcile
    (:func:`refresh_attack_graph_execution_support`), which re-evaluates edges
    that ALREADY carry a verdict so an upgraded ADscan can open a technique it
    now supports. That is a version concern and stays on the reopen path; this is
    a persistence concern and only ever fills a blank.

    O(E) over a dict this same call already sorts and serializes, so it costs
    nothing measurable next to the save it is part of — unlike the load-time
    backstop, which is gated precisely because it charges a read-only path for
    the same pass.

    Args:
        graph: The attack graph about to be written.

    Returns:
        How many edges were stamped.
    """
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
        category, vuln_key = classify_edge_relation(relation)
        if edge.get("category") != category or edge.get("vuln_key") != vuln_key:
            edge["category"] = category
            edge["vuln_key"] = vuln_key
            changed += 1

        if category != "exploitation":
            continue
        notes = edge.get("notes")
        notes = notes if isinstance(notes, dict) else {}
        if notes.get("exec_support"):
            continue
        if (
            str(edge.get("status") or "").strip().lower()
            not in _UNDECIDED_EDGE_STATUSES
        ):
            continue
        desired_status, desired_notes = _desired_exec_support_state(
            graph, relation=relation, to_id=str(edge.get("to") or "")
        )
        edge["status"] = desired_status
        notes.update(desired_notes)
        edge["notes"] = notes
        changed += 1
    return changed


def _refresh_edge_verify_commands(graph: dict[str, Any]) -> int:
    """Re-render the ``knowledge`` verify commands on technique edges.

    An edge's ``knowledge`` block is baked in :func:`upsert_edge`, which runs
    during collection — before ``save_attack_graph`` stamps ``graph["dc_ip"]``
    (and, for some writers, ``graph["domain"]``) — so its ``verify_windows`` /
    ``verify_linux`` still carry the literal ``<dc_ip>`` / ``<domain>`` tokens.
    Once the writer knows the coordinates it re-renders them against each edge's
    own source/target so the web CTEM shows a copy-paste command with the real
    DC IP and domain, matching what the report re-renders at PDF-build time.

    Only technique edges (those carrying a ``knowledge`` block with a verify
    command) are touched; ``<user>`` / ``<pass>`` are never substituted. Idempotent
    and best-effort — a no-op when the graph has no coordinates or no such edges.
    """
    dc_ip = str(graph.get("dc_ip") or "").strip()
    domain = str(graph.get("domain") or "").strip()
    if not dc_ip and not domain:
        return 0
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return 0
    try:
        from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
            render_step_verify,
        )
    except Exception:  # noqa: BLE001 — never break the write over an enrichment
        return 0
    refreshed = 0
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        knowledge = edge.get("knowledge")
        if not isinstance(knowledge, dict):
            continue
        if not (knowledge.get("verify_windows") or knowledge.get("verify_linux")):
            continue
        relation = str(edge.get("relation") or "").strip()
        if not relation:
            continue
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        verify_step = {
            "relation": relation,
            "details": {
                "from": str(notes.get("source_label") or edge.get("from") or ""),
                "to": str(notes.get("target_label") or edge.get("to") or ""),
                **({"dc_ip": dc_ip} if dc_ip else {}),
                **({"domain": domain} if domain else {}),
            },
        }
        try:
            rendered = render_step_verify(verify_step)
        except Exception:  # noqa: BLE001
            continue
        changed = False
        if rendered.get("windows") and knowledge.get("verify_windows"):
            if knowledge["verify_windows"] != rendered["windows"]:
                knowledge["verify_windows"] = rendered["windows"]
                changed = True
        if rendered.get("linux") and knowledge.get("verify_linux"):
            if knowledge["verify_linux"] != rendered["linux"]:
                knowledge["verify_linux"] = rendered["linux"]
                changed = True
        if changed:
            refreshed += 1
    return refreshed


def save_attack_graph(shell: object, domain: str, graph: dict[str, Any]) -> None:
    """Persist the attack graph to disk with stable formatting.

    The ONE writer of ``domains/<domain>/attack_graph.json``. Everything a
    persisted graph must be true of lives here — edge classification, the Tier-0
    source prune, stable edge ordering, an atomic write, cache invalidation and
    the technical-findings sync — so a caller that appends edges by hand inherits
    all of it by persisting through this function instead of serializing the file
    itself. Locked by ``tests/unit/services/test_attack_graph_write_seam.py``.
    """
    graph["schema_version"] = ATTACK_GRAPH_SCHEMA_VERSION
    graph["domain"] = domain
    graph["generated_at"] = _utc_now_iso()
    # Stamp the DC/KDC IP onto the graph so downstream renderers (report,
    # attack-path snapshot, edge-knowledge bake) can substitute a real IP into
    # the independent-verification commands instead of a literal <dc_ip> token.
    # Resolved once here through the ``resolve_dc_ip`` SSOT (never a hand-rolled
    # .get("dc_ip") walk). Best-effort: absent domains_data / no resolvable DC
    # leaves the field unset and the catalog degrades to the literal token.
    try:
        from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

        domains_data = getattr(shell, "domains_data", None)
        domain_entry = (
            domains_data.get(domain) if isinstance(domains_data, dict) else None
        )
        if isinstance(domain_entry, dict):
            resolved_dc_ip = resolve_dc_ip(domain_entry)
            if resolved_dc_ip:
                graph["dc_ip"] = resolved_dc_ip
    except Exception:  # noqa: BLE001 — never break the graph write over an enrichment
        pass
    # Edges are baked during collection, BEFORE the dc_ip/domain stamps above
    # exist on the graph, so their knowledge verify blocks still carry the
    # literal <dc_ip>/<domain> tokens. Refresh them here — at the ONE writer,
    # after the coordinates are known — so the web CTEM edge panel gets the real
    # DC IP + domain in its copy-paste verify commands (parity with the report).
    _refresh_edge_verify_commands(graph)
    classify_graph_edges(graph)
    _prune_tier0_source_attack_edges(graph)
    _flush_tier0_source_attack_edge_skip_summary(graph)
    path = _graph_path(shell, domain)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    edges = graph.get("edges")
    if isinstance(edges, list):
        graph["edges"] = sorted(
            edges,
            key=lambda e: (
                (
                    str(e.get("from", "")),
                    str(e.get("relation", "")),
                    str(e.get("to", "")),
                )
                if isinstance(e, dict)
                else ("", "", "")
            ),
        )

    write_json_file(path, graph)
    _invalidate_attack_paths_cache(domain, reason="graph_saved", shell=shell)
    _invalidate_materialized_attack_path_cache(domain)
    invalidate_attack_path_artifacts(shell, domain)
    try:
        domains_data = getattr(shell, "domains_data", None)
        if isinstance(domains_data, dict):
            domains_data.setdefault(domain, {})["attack_graph_file"] = path
            # Persist a compact, ANONYMOUS AD-scale fingerprint (counts only, no
            # principal names) so session telemetry can report per-domain scale
            # (computers/users/groups + enabled) cheaply at session time without
            # re-reading the (potentially large) attack_graph.json. Read back by
            # build_session_ad_scale_metadata(). Plain JSON ints -> safe for
            # save_workspace_data. Best-effort: never break the graph save.
            stats = _compute_ad_scale_stats(graph)
            if stats:
                domains_data[domain]["collection_stats"] = stats
    except Exception:
        pass
    _sync_attack_graph_findings_best_effort(shell, domain, graph)


def _compute_ad_scale_stats(graph: dict[str, Any]) -> dict[str, int]:
    """Count attack-graph nodes by kind + enabled state for telemetry.

    ANONYMOUS by construction — returns only integer counts, never labels/SIDs.
    ``enabled`` is fail-open: a node with unknown (``None``) enabled state counts
    as enabled (mirrors ``is_collectable_computer_host``), so ``*_enabled`` is
    "total minus the explicitly-disabled".
    """
    nodes = graph.get("nodes")
    if isinstance(nodes, dict):
        node_iter = nodes.values()
    elif isinstance(nodes, list):
        node_iter = nodes
    else:
        return {}
    counts: dict[str, int] = {
        "computers": 0,
        "enabled_computers": 0,
        "users": 0,
        "enabled_users": 0,
        "groups": 0,
        "ous": 0,
        "gpos": 0,
    }
    for node in node_iter:
        if not isinstance(node, dict):
            continue
        kind = str(node.get("kind") or node.get("type") or "")
        enabled = node.get("enabled")
        if enabled is None and isinstance(node.get("properties"), dict):
            enabled = node["properties"].get("enabled")
        if kind == "Computer":
            counts["computers"] += 1
            if enabled is not False:
                counts["enabled_computers"] += 1
        elif kind == "User":
            counts["users"] += 1
            if enabled is not False:
                counts["enabled_users"] += 1
        elif kind == "Group":
            counts["groups"] += 1
        elif kind == "OU":
            counts["ous"] += 1
        elif kind == "GPO":
            counts["gpos"] += 1
    return counts


def _sync_attack_graph_findings_best_effort(
    shell: object, domain: str, graph: dict[str, Any]
) -> None:
    """Materialize this graph's exploitation edges as technical findings.

    The derivation lives in the LITE-safe
    :mod:`adscan_internal.services.attack_graph_findings`, so it ships in BOTH
    images and runs on every graph save regardless of tier. It used to be loaded
    through the optional PRO report-service seam, which meant a LITE runtime
    cached it as unavailable and recorded no graph-derived finding at all — do
    not reintroduce an optional-import gate here.

    Best-effort: a failure never breaks the graph save.
    """
    try:
        sync_attack_graph_findings(shell, domain, graph)
    except Exception as exc:  # pragma: no cover - best effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
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

    from adscan_internal.services.destructive_action_policy import (  # noqa: PLC0415
        DANGEROUS_DESTRUCTIVE_MARKER,
    )

    changed = 0
    to_blocked = 0
    to_unsupported = 0
    to_discovered = 0
    metadata_updated = 0

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
        if current_status in {
            "success",
            "attempted",
            "failed",
            "error",
            "unavailable",
            # An environment/topology closure (e.g. single-DC NTLMv1 self-relay
            # reflection). This is decided by the environment, NOT by the ADscan
            # version — the exec-support reconcile (a VERSION concern) must never
            # re-open it as an executable "discovered" step. Without this, a
            # config-closed edge on a SUPPORTED relation was silently re-stamped
            # "discovered" and offered for execution.
            "closed_by_configuration",
        }:
            continue
        # A SAFETY abstention — a destructive step hard-refused by the
        # destructive-action policy (stamped ``blocked_kind="dangerous_destructive"``)
        # — is likewise an environment/safety closure, not a version concern.
        # Re-opening it to "discovered" would offer a destructive action ADscan
        # deliberately refuses to run. Gated on the safety marker so the
        # policy_blocked reconcile below (which SETS ``blocked`` on other edges,
        # and re-derives an opt-in ``blocked_kind="dangerous"`` FCP edge) is
        # unaffected.
        if current_status == "blocked":
            existing = edge.get("notes")
            if (
                isinstance(existing, dict)
                and str(existing.get("blocked_kind") or "").strip()
                == DANGEROUS_DESTRUCTIVE_MARKER
            ):
                continue

        desired_status, desired_notes = _desired_exec_support_state(
            graph,
            relation=relation,
            to_id=str(edge.get("to") or ""),
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


def reset_attack_graph_execution_statuses(shell: object, domain: str) -> dict[str, int]:
    """Reset persisted edge execution states to their support-derived defaults.

    This helper is intended for local testing workflows where operators want to
    clear all runtime execution outcomes and return the graph to the same status
    baseline produced by a fresh enumeration.

    Returns:
        Counts describing how many edges were updated.
    """
    graph = load_attack_graph(shell, domain)
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    if not edges:
        return {"changed": 0}

    changed = 0
    to_blocked = 0
    to_unsupported = 0
    to_discovered = 0
    attempts_cleared = 0
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

        support = _classify_edge_execution_support(
            graph,
            relation=relation,
            to_id=str(edge.get("to") or ""),
        )
        desired_status = "discovered"
        desired_notes: dict[str, Any] = {
            "exec_support": support.kind,
            "exec_support_version": version,
        }
        if support.kind == "policy_blocked":
            desired_status = "blocked"
            desired_notes.update(
                _policy_blocked_edge_notes(
                    graph,
                    relation=relation,
                    to_id=str(edge.get("to") or ""),
                    support=support,
                )
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

        current_status = str(edge.get("status") or "discovered").strip().lower()
        if desired_status != current_status:
            edge["status"] = desired_status
            changed += 1
            if desired_status == "blocked":
                to_blocked += 1
            elif desired_status == "unsupported":
                to_unsupported += 1
            else:
                to_discovered += 1

        existing_notes = edge.get("notes")
        if not isinstance(existing_notes, dict):
            existing_notes = {}
        if "attempts" in existing_notes:
            existing_notes.pop("attempts", None)
            attempts_cleared += 1
            changed += 1
        existing_notes.update(desired_notes)
        edge["notes"] = existing_notes

    if changed:
        save_attack_graph(shell, domain, graph)
    return {
        "changed": changed,
        "to_blocked": to_blocked,
        "to_unsupported": to_unsupported,
        "to_discovered": to_discovered,
        "attempts_cleared": attempts_cleared,
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
        existing_best_id = _find_node_id_by_label(graph, _node_display_name(node))
        if existing_best_id and existing_best_id != nid:
            maintenance = graph.setdefault("maintenance", {})
            if isinstance(maintenance, dict):
                duplicate_summary = maintenance.setdefault(
                    "duplicate_label_upserts", {}
                )
                if not isinstance(duplicate_summary, dict):
                    duplicate_summary = {}
                    maintenance["duplicate_label_upserts"] = duplicate_summary
                duplicate_summary["total"] = (
                    int(duplicate_summary.get("total") or 0) + 1
                )
                sample_count = int(duplicate_summary.get("sampled") or 0)
                if sample_count < _DUPLICATE_LABEL_DEBUG_SAMPLE_LIMIT:
                    existing_best = node_map.get(existing_best_id)
                    existing_object_id = _extract_node_object_id(existing_best) or ""
                    new_object_id = _extract_node_object_id(node) or ""
                    print_info_debug(
                        "[attack_graph] duplicate-label node upsert detected: "
                        f"label={mark_sensitive(_node_display_name(node), 'user')} "
                        f"existing_id={mark_sensitive(existing_best_id, 'user')} "
                        f"new_id={mark_sensitive(nid, 'user')} "
                        f"existing_objectid={mark_sensitive(existing_object_id, 'user')} "
                        f"new_objectid={mark_sensitive(new_object_id, 'user')}"
                    )
                    duplicate_summary["sampled"] = sample_count + 1
        existing = node_map.get(nid)
        merged = existing if isinstance(existing, dict) else {}
        existing_properties = (
            merged.get("properties")
            if isinstance(merged.get("properties"), dict)
            else {}
        )
        incoming_properties = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        node_properties = dict(existing_properties)
        node_properties.update(incoming_properties)
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

        def _normalize_system_tags(value: object) -> list[str]:
            """Return normalized BloodHound system tags from one node field."""
            if isinstance(value, str):
                return [tag.strip() for tag in re.split(r"[, ]+", value) if tag.strip()]
            if isinstance(value, list):
                return [str(tag).strip() for tag in value if str(tag).strip()]
            return []

        system_tags = sorted(
            {
                *[
                    tag.lower()
                    for tag in _normalize_system_tags(merged.get("system_tags"))
                ],
                *[
                    tag.lower()
                    for tag in _normalize_system_tags(
                        existing_properties.get("system_tags")
                    )
                ],
                *[
                    tag.lower()
                    for tag in _normalize_system_tags(node.get("system_tags"))
                ],
                *[
                    tag.lower()
                    for tag in _normalize_system_tags(
                        node_properties.get("system_tags")
                    )
                ],
            }
        )
        is_tier_zero = bool(
            merged.get("isTierZero")
            or existing_properties.get("isTierZero")
            or node.get("isTierZero")
            or node_properties.get("isTierZero")
            or "admin_tier_0" in system_tags
        )
        is_high_value = bool(
            is_tier_zero
            or merged.get("highvalue")
            or existing_properties.get("highvalue")
            or node.get("highvalue")
            or node_properties.get("highvalue")
        )
        node_properties["isTierZero"] = is_tier_zero
        node_properties["highvalue"] = is_high_value
        if system_tags:
            node_properties["system_tags"] = ",".join(system_tags)
        tier0_inherited = bool(
            merged.get("tier0_inherited")
            or existing_properties.get("tier0_inherited")
            or node.get("tier0_inherited")
            or node_properties.get("tier0_inherited")
        )
        target_terminal_class = str(
            node_properties.get("target_terminal_class")
            or node.get("target_terminal_class")
            or merged.get("target_terminal_class")
            or ""
        ).strip()
        merged.update(
            {
                "id": nid,
                "label": _node_display_name(node),
                "kind": _node_kind(node),
                "objectId": (
                    node.get("objectId")
                    or node.get("objectid")
                    or merged.get("objectId")
                    or merged.get("objectid")
                ),
                # Persist common BloodHound metadata at the top-level so
                # attack-path filtering and tests can rely on it without
                # requiring a full `properties` payload.
                "isTierZero": is_tier_zero,
                "highvalue": is_high_value,
                "system_tags": system_tags,
                "is_high_value": is_high_value,
                "tier0_inherited": tier0_inherited,
                "target_terminal_class": target_terminal_class or None,
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


_SHARE_ACCESS_RELATION_KEYS = {"readshare", "writeshare", "fullcontrolshare"}


def _share_access_identity_from_notes(notes: dict[str, Any] | None) -> str:
    """Return the canonical share identity for SMB share-access edges."""
    if not isinstance(notes, dict):
        return ""
    share_name = str(notes.get("share_name") or notes.get("share") or "").strip()
    if not share_name:
        collector_method = str(notes.get("collector_method") or "").strip()
        if collector_method.lower().startswith("share_acl:"):
            share_name = collector_method.split(":", 1)[1].strip()
    return share_name.casefold()


def _edge_share_identity(relation: str, notes: dict[str, Any] | None) -> str:
    relation_key = str(relation or "").strip().lower()
    if relation_key not in _SHARE_ACCESS_RELATION_KEYS:
        return ""
    return _share_access_identity_from_notes(notes)


def _edge_matches_upsert_identity(
    edge: dict[str, Any],
    *,
    from_id: str,
    to_id: str,
    relation: str,
    incoming_notes: dict[str, Any] | None,
) -> bool:
    if (
        edge.get("from") != from_id
        or edge.get("to") != to_id
        or str(edge.get("relation") or "") != relation
    ):
        return False
    incoming_share = _edge_share_identity(relation, incoming_notes)
    existing_notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
    existing_share = _edge_share_identity(relation, existing_notes)
    if incoming_share or existing_share:
        return incoming_share == existing_share
    return True


# Cache of the baked technique-knowledge object, keyed by
# ``(relation, source_is_tier0_direct)``. The prose is pure (a function of the
# relation, that one flag, and the static VULN_CATALOG), so resolving it once
# per key per process avoids re-running the catalog join on every
# ``upsert_edge`` call at 1-2k-host scale.
_EDGE_KNOWLEDGE_CACHE: dict[tuple[str, bool], dict[str, Any]] = {}


def _bake_edge_technique_knowledge(
    relation_norm: str,
    *,
    source_is_tier0_direct: bool = False,
) -> dict[str, Any] | None:
    """Resolve the rich technique-knowledge object for one edge relation.

    The persisted attack-graph artifact (``attack_graph.json``) is ingested by
    the paid web, which must NOT import the PRO ``VULN_CATALOG``. So the CLI
    engine (which HAS the catalog) bakes the per-edge technique prose here and
    the web reads it straight from the ingested edge — mirroring how findings
    carry their ``knowledge`` block (commit ``fdf34348``).

    Reuses ``build_step_knowledge`` (the single source of truth for per-step
    technique prose that already feeds ``attack_paths_snapshot.json``) so the
    edge card and the path-step card read identical prose. The join is lazy +
    best-effort: an edge whose relation has no catalog entry, or a LITE/runtime
    context without the PRO catalog, yields ``None`` and no ``knowledge`` is
    stamped (the panel then falls back to its generic blurb).

    Args:
        relation_norm: The already-normalized edge relation.
        source_is_tier0_direct: True when the edge's SOURCE is already a Tier 0
            direct principal, so the catalog renders the structural-hierarchy
            line instead of removal advice (the web edge panel would otherwise
            tell a client to strip replication rights off its own domain
            controllers). Part of the cache key — at most two entries per
            relation.

    Returns:
        The technique-knowledge dict (``description``, ``impact``,
        ``remediation``, ``references``, ``mitre_technique_id/name``,
        ``vuln_key``), or ``None`` when the relation maps to no technique.
    """
    if not relation_norm:
        return None
    cache_key = (relation_norm, bool(source_is_tier0_direct))
    cached = _EDGE_KNOWLEDGE_CACHE.get(cache_key)
    if cached is not None:
        return cached or None
    try:
        knowledge = build_step_knowledge(
            {
                "relation": relation_norm,
                "details": {
                    "source_privilege_tier": (
                        PrivilegeTier.TIER0_DIRECT.value
                        if source_is_tier0_direct
                        else PrivilegeTier.TIER2.value
                    )
                },
            }
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        knowledge = None

    baked: dict[str, Any] | None = None
    # Only TECHNIQUE edges carry baked knowledge — those that resolve to a
    # ``vuln_key`` (ESC1, DCSync, Kerberoast, ...). Structural edges (MemberOf,
    # Contains, GpLink) resolve generic prose with no ``vuln_key``; they stay
    # clean so the web panel shows them as plain relations, not techniques.
    catalog_key = (
        str(knowledge.get("vuln_key") or "").strip()
        if isinstance(knowledge, dict)
        else ""
    )
    if isinstance(knowledge, dict) and knowledge and catalog_key:
        baked = knowledge
        # Enrich with the catalog's title + severity so the web edge panel can
        # render a contextual severity band without the PRO catalog. Lazy +
        # best-effort: a LITE/runtime context without the catalog keeps the
        # base prose ``build_step_knowledge`` already resolved. Only the edge
        # artifact carries these — the shared path-step knowledge shape (which
        # also feeds the report) is intentionally left unchanged.
        try:
            from adscan_internal.pro.reporting.vuln_catalog import VULN_CATALOG

            catalog_entry = VULN_CATALOG.get(catalog_key)
        except Exception:  # noqa: BLE001
            catalog_entry = None
        if isinstance(catalog_entry, dict):
            title = str(catalog_entry.get("title") or "").strip()
            severity = str(catalog_entry.get("severity") or "").strip()
            if title:
                baked["title"] = title
            if severity:
                baked["severity"] = severity
    # Cache the resolved value (even a no-technique resolution, stored as ``{}``)
    # so a relation without a technique mapping is not re-resolved on every
    # upsert at scale.
    _EDGE_KNOWLEDGE_CACHE[cache_key] = baked if isinstance(baked, dict) else {}
    return baked


def _personalize_edge_knowledge(
    relation_norm: str,
    edge_notes: dict[str, Any] | None,
    *,
    source_is_tier0_direct: bool = False,
    dc_ip: str = "",
    domain: str = "",
) -> dict[str, Any] | None:
    """Weave THIS edge's concrete assets into its baked technique knowledge.

    The base knowledge from :func:`_bake_edge_technique_knowledge` is shared
    (cached) per relation, so it carries the generic catalog prose. This builds
    a per-edge COPY whose impact/remediation name the exact assets on this edge
    (the abused certificate template, the enrolling principal), so the paid web
    edge-detail panel reads "ESC1 (DOMAIN USERS can enrol)" instead of "the
    affected template". Never mutates the cached base. Returns ``None`` when the
    relation maps to no technique (so the caller stamps nothing).

    The cached base bakes the independent-verification commands from a synthetic,
    context-free step, so its ``verify_windows``/``verify_linux`` carry the
    literal ``<dc_ip>``/``<domain>`` tokens. When the caller passes this edge's
    environment coordinates (``dc_ip`` from the graph's ``resolve_dc_ip`` stamp,
    ``domain`` from the graph), the verify block is re-rendered against a step
    carrying them plus this edge's source/target, so the web CTEM shows a
    copy-paste command with the real DC IP and domain — parity with the report,
    which re-renders the same block at PDF-build time. ``<user>``/``<pass>`` are
    NEVER substituted (the credential must never land in the CTEM). Absent
    coordinates leave the literal tokens in place.

    Mirrors the finding-side weave in
    ``report_service.sync_attack_graph_findings`` via the SAME affected-assets
    SSOT, so the edge card and the finding card name identical assets.
    """
    base = _bake_edge_technique_knowledge(
        relation_norm, source_is_tier0_direct=source_is_tier0_direct
    )
    if not isinstance(base, dict) or not base:
        return base
    if not isinstance(edge_notes, dict) or not edge_notes:
        edge_notes = {}
    # Re-render the verification commands against this edge's real coordinates so
    # the web CTEM's copy-paste verify block carries the DC IP + domain, matching
    # the report. Only when the graph supplied at least one coordinate and the
    # base actually carries a verify block. Best-effort: any failure keeps the
    # generic (literal-token) verify already on the base.
    verify_override: dict[str, str] = {}
    if (dc_ip or domain) and (base.get("verify_windows") or base.get("verify_linux")):
        try:
            from adscan_internal.services.attack_step_catalog import (  # noqa: PLC0415
                render_step_verify,
            )

            verify_step = {
                "relation": relation_norm,
                "details": {
                    "from": str(edge_notes.get("source_label") or ""),
                    "to": str(edge_notes.get("target_label") or ""),
                    **({"dc_ip": dc_ip} if dc_ip else {}),
                    **({"domain": domain} if domain else {}),
                },
            }
            rendered = render_step_verify(verify_step)
            if rendered.get("windows") and base.get("verify_windows"):
                verify_override["verify_windows"] = rendered["windows"]
            if rendered.get("linux") and base.get("verify_linux"):
                verify_override["verify_linux"] = rendered["linux"]
        except Exception as exc:  # noqa: BLE001 — edge baking must never break the graph
            telemetry.capture_exception(exc)

    def _with_verify(result: dict[str, Any] | None) -> dict[str, Any] | None:
        """Overlay the re-rendered verify commands onto a knowledge dict.

        Copies before mutating so the cached base is never touched. A no-op when
        there is no override (no coordinates, or the base had no verify block).
        """
        if not verify_override or not isinstance(result, dict):
            return result
        merged = dict(result)
        merged.update(verify_override)
        return merged

    if not edge_notes and not verify_override:
        return base
    try:
        from adscan_internal.pro.reporting.finding_specifics import (
            weave_specifics_into_knowledge,
        )
    except Exception:  # noqa: BLE001 — LITE/runtime without the PRO catalog
        return _with_verify(base)
    vuln_key = str(base.get("vuln_key") or "").strip()
    if not vuln_key:
        return _with_verify(base)
    if not edge_notes:
        # Coordinates but no per-edge assets to weave — just overlay verify.
        return _with_verify(base)
    # Synthesise the minimal ``details`` shape the specifics SSOT expects: one
    # attack-graph edge whose source/target/notes carry the concrete assets.
    synthetic_details = {
        "attack_graph_edges": [
            {
                "relation": relation_norm,
                "source": edge_notes.get("source_label") or "",
                "target": edge_notes.get("target_label") or "",
                "notes": edge_notes,
            }
        ]
    }
    try:
        return _with_verify(
            weave_specifics_into_knowledge(vuln_key, base, synthetic_details)
        )
    except Exception as exc:  # noqa: BLE001 — edge baking must never break the graph
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return _with_verify(base)


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
    """Upsert an edge.

    Most relations are keyed by ``(from, relation, to)``. SMB share-access
    relations are additionally keyed by share name because the same principal
    can legitimately have different access to multiple shares on one host.
    """
    relation_norm = _normalize_relation(relation)
    if not from_id or not to_id or not relation_norm:
        return {}
    if _edge_has_tier0_source(
        graph, from_id=from_id, relation=relation_norm, to_id=to_id
    ):
        _record_tier0_source_attack_edge_skip(graph, relation=relation_norm)
        return {}

    # Classify execution support for this relation (version-sensitive).
    edge_category, edge_vuln_key = _classify_edge_relation(relation_norm)
    support = _classify_edge_execution_support(
        graph,
        relation=relation_norm,
        to_id=to_id,
    )
    desired_status = (status or "discovered").strip().lower()
    desired_notes: dict[str, Any] = {}
    # Avoid filesystem I/O during graph creation/migration: telemetry.VERSION is in-memory.
    version = getattr(telemetry, "VERSION", "unknown")
    if desired_status in {"", "discovered"}:
        if support.kind == "policy_blocked":
            desired_status = "blocked"
            desired_notes = {
                **_policy_blocked_edge_notes(
                    graph,
                    relation=relation_norm,
                    to_id=to_id,
                    support=support,
                ),
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
    # Is this edge built-in AD hierarchy (its SOURCE is already Tier 0 direct)?
    # Resolved once and threaded into the baked technique knowledge, so the paid
    # web edge panel never advises removing a right the domain needs to run.
    _graph_nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    source_is_tier0_direct = is_structural_hierarchy_source(
        _graph_nodes.get(from_id) if isinstance(_graph_nodes, dict) else None
    )
    choke_point_notes = classify_attack_graph_edge_choke_point(
        graph,
        from_id=from_id,
        relation=relation_norm,
        to_id=to_id,
        notes=notes,
    )
    if isinstance(choke_point_notes, dict):
        desired_notes = _merge_attack_step_notes(
            existing=desired_notes,
            incoming=choke_point_notes,
        )

    edges: list[dict[str, Any]] = graph.setdefault("edges", [])
    if not isinstance(edges, list):
        edges = []
        graph["edges"] = edges

    now = _utc_now_iso()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if _edge_matches_upsert_identity(
            edge,
            from_id=from_id,
            to_id=to_id,
            relation=relation_norm,
            incoming_notes=notes,
        ):
            edge["last_seen"] = now
            edge.setdefault("discovered_at", edge.get("first_seen") or now)
            edge["category"] = edge_category
            edge["vuln_key"] = edge_vuln_key
            # Phase 2: keep canonical EdgeKind in sync with current catalog.
            edge["kind"] = classify_edge_kind(relation_norm).value
            current = str(edge.get("status") or "discovered")
            status_changed = _status_rank(desired_status) > _status_rank(current)
            if status_changed:
                edge["status"] = desired_status
            edge.setdefault("edge_type", edge_type)
            existing_notes = edge.get("notes")
            if not isinstance(existing_notes, dict):
                existing_notes = {}
            merged_notes = _merge_attack_step_notes(
                existing=existing_notes,
                incoming=notes or {},
            )
            merged_notes = _merge_attack_step_notes(
                existing=merged_notes,
                incoming=desired_notes,
            )
            # Heal a choke-point stamp the current classifier no longer agrees
            # with. Notes MERGE, so without this an edge stamped a choke point by
            # an older build keeps that stamp — and its severity — for the life
            # of the workspace, even after the classifier learned the transition
            # was built-in AD hierarchy. Same heal-on-re-sync contract the baked
            # ``knowledge`` block below follows.
            if choke_point_notes is None:
                for stale_key in CHOKE_POINT_VERDICT_NOTE_KEYS:
                    merged_notes.pop(stale_key, None)
            if merged_notes:
                edge["notes"] = merged_notes
            # Bake the technique-knowledge prose so the paid web edge panel can
            # render it without importing the PRO catalog. Personalised with THIS
            # edge's concrete assets (template name, enrolling principal) from the
            # merged notes, so the web edge-detail names the exact assets. Healed
            # on re-sync: stamp when present, drop a stale block if the relation
            # no longer maps to a technique.
            baked_knowledge = _personalize_edge_knowledge(
                relation_norm,
                merged_notes,
                source_is_tier0_direct=source_is_tier0_direct,
                dc_ip=str(graph.get("dc_ip") or "").strip(),
                domain=str(graph.get("domain") or "").strip(),
            )
            if baked_knowledge:
                edge["knowledge"] = baked_knowledge
            elif "knowledge" in edge:
                edge.pop("knowledge", None)
            return edge

    share_identity = _edge_share_identity(relation_norm, notes)
    edge_id_input = f"{from_id}|{relation_norm}|{to_id}|{edge_type}|{share_identity}"
    edge_id = hashlib.md5(edge_id_input.encode("utf-8")).hexdigest()
    entry: dict[str, Any] = {
        "id": edge_id,
        "from": from_id,
        "to": to_id,
        "relation": relation_norm,
        # Phase 2: canonical EdgeKind persisted as a top-level field. See
        # adscan_internal/services/edge_kind.py for the catalog.
        "kind": classify_edge_kind(relation_norm).value,
        "edge_type": edge_type,
        "category": edge_category,
        "vuln_key": edge_vuln_key,
        "status": desired_status,
        "notes": {**(notes or {}), **desired_notes},
        "discovered_at": now,
        "first_seen": now,
        "last_seen": now,
    }
    # Bake the rich technique-knowledge prose onto the edge so the paid web edge
    # panel renders a high-level + technical brief without importing the PRO
    # catalog. Personalised with THIS edge's concrete assets (template name,
    # enrolling principal) so the web edge-detail names the exact assets. Only
    # technique edges (those with a resolvable catalog entry) carry it;
    # structural edges (MemberOf, Contains, ...) stay clean.
    baked_knowledge = _personalize_edge_knowledge(
        relation_norm,
        entry.get("notes") if isinstance(entry.get("notes"), dict) else None,
        source_is_tier0_direct=source_is_tier0_direct,
        dc_ip=str(graph.get("dc_ip") or "").strip(),
        domain=str(graph.get("domain") or "").strip(),
    )
    if baked_knowledge:
        entry["knowledge"] = baked_knowledge
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
            print_exception(exception=exc)
    return entry


def _merge_attack_step_notes(
    *,
    existing: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    """Merge attack-step notes while preserving detector/source provenance."""
    merged: dict[str, Any] = dict(existing or {})
    if not incoming:
        return merged

    merged.update(incoming)

    for key in (
        "templates",
        "template_dns",
        "agent_templates",
        "target_templates",
        "reasons",
        "enterprisecas",
        "enterpriseca_dns",
    ):
        merged_values = _merge_note_list_values(existing.get(key), incoming.get(key))
        if merged_values:
            merged[key] = merged_values

    if "template" not in merged:
        template_values = merged.get("templates")
        if isinstance(template_values, list) and len(template_values) == 1:
            single_template = template_values[0]
            if isinstance(single_template, dict):
                template_name = str(single_template.get("name") or "").strip()
                if template_name:
                    merged["template"] = template_name
            elif str(single_template).strip():
                merged["template"] = str(single_template).strip()

    source_values = _merge_note_scalar_provenance(
        existing=existing,
        incoming=incoming,
        field="source",
        list_field="sources",
    )
    detector_values = _merge_note_scalar_provenance(
        existing=existing,
        incoming=incoming,
        field="detector",
        list_field="detectors",
    )
    if source_values:
        merged["sources"] = source_values
        merged["source"] = source_values[0]
    if detector_values:
        merged["detectors"] = detector_values
        merged["detector"] = detector_values[0]

    return merged


def _merge_note_scalar_provenance(
    *,
    existing: dict[str, Any],
    incoming: dict[str, Any],
    field: str,
    list_field: str,
) -> list[str]:
    """Merge one provenance scalar plus its plural list form into one unique list."""
    values: list[str] = []
    for candidate in (
        existing.get(field),
        incoming.get(field),
    ):
        value = str(candidate or "").strip()
        if value and value not in values:
            values.append(value)
    for collection in (existing.get(list_field), incoming.get(list_field)):
        if not isinstance(collection, list):
            continue
        for item in collection:
            value = str(item or "").strip()
            if value and value not in values:
                values.append(value)
    return values


def _merge_note_list_values(
    existing: Any,
    incoming: Any,
) -> list[Any]:
    """Merge two note list values while preserving order and complex items."""
    merged: list[Any] = []
    seen_keys: set[str] = set()
    for collection in (existing, incoming):
        if not isinstance(collection, list):
            continue
        for item in collection:
            item_key = _note_list_item_key(item)
            if item_key in seen_keys:
                continue
            seen_keys.add(item_key)
            merged.append(item)
    return merged


def _note_list_item_key(value: Any) -> str:
    """Return a stable deduplication key for one note list item."""
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, default=str)
    if isinstance(value, list):
        return json.dumps(value, default=str)
    return str(value)


def _build_opengraph_ref(
    node_id: str,
    *,
    graph: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Build an OpenGraph node match reference from an internal ``name:`` node ID.

    Uses the graph to look up the actual node properties so we can send the
    most reliable match reference to BH CE:

    1. ``match_by: "id"`` with the SID — most reliable, used when objectId is available.
    2. ``match_by: "name"`` with full ``NAME@DOMAIN`` uppercase — required by BH CE for
       name-based matching (e.g. ``"MISSANDEI@ESSOS.LOCAL"``).

    Args:
        node_id: Internal node ID, e.g. ``"name:administrator"`` or ``"name:S-1-5-21-..."``.
        graph: Optional attack graph dict; when provided, node properties are used to
            build a more precise reference.

    Returns:
        OpenGraph match dict: ``{"match_by": "id"|"name", "value": "..."}``.
    """
    value = node_id.removeprefix("name:").strip()
    if value.upper().startswith("S-1-"):
        return {"match_by": "id", "value": value.upper()}

    # Resolve via graph when available — critical for user/computer nodes whose
    # internal id is just samaccountname but BH CE needs NAME@DOMAIN or SID.
    if graph is not None:
        nodes_map = graph.get("nodes")
        if isinstance(nodes_map, dict):
            node = nodes_map.get(node_id)
            if isinstance(node, dict):
                props = (
                    node.get("properties")
                    if isinstance(node.get("properties"), dict)
                    else {}
                )
                # Prefer SID (most reliable match in BH CE)
                object_id = (
                    node.get("objectId")
                    or node.get("objectid")
                    or props.get("objectid")
                    or props.get("objectId")
                )
                if object_id and str(object_id).upper().startswith("S-1-"):
                    return {"match_by": "id", "value": str(object_id).upper()}
                # Fall back to full NAME@DOMAIN format
                full_name = node.get("name") or props.get("name")
                if full_name and "@" in str(full_name):
                    return {"match_by": "name", "value": str(full_name).upper()}

    return {"match_by": "name", "value": value.upper()}


def add_bloodhound_path_edges(
    graph: dict[str, Any],
    *,
    nodes: list[dict[str, Any]],
    relations: list[str],
    status: str = "discovered",
    edge_type: str = "graph_collection",
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
        edge_type: Edge category stored in the graph (defaults to `graph_collection`).
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
    entry_kind: str = ""
    notes: dict[str, Any] = field(default_factory=dict)
    record_on_failure: bool = False


def _is_collectable_computers_scope_node(node: dict[str, Any] | None) -> bool:
    """Return True for the synthetic host-scope node used by native collection."""
    if not isinstance(node, dict):
        return False
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    return (
        bool(props.get("synthetic"))
        and str(props.get("scope_kind") or "").strip().lower()
        == "collectable_computers"
        and str(props.get("target_selector") or "").strip().lower()
        == "all_collectable_computers"
    )


def _is_scope_expandable_computer_node(node: dict[str, Any] | None) -> bool:
    """Return True when a graph node is a real computer target for scope edges."""
    if not isinstance(node, dict) or _node_kind(node) != "Computer":
        return False
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if props.get("is_smb_host") is False or props.get("is_gmsa") is True:
        return False
    return str(props.get("account_type") or "").strip().casefold() != "gmsa"


def _expand_collectable_computers_scope_edge(
    graph: dict[str, Any],
    edge: dict[str, Any],
) -> list[dict[str, Any]]:
    """Expand a compressed group-inferred host access edge into runtime host edges."""
    relation = str(edge.get("relation") or "").strip()
    if relation not in {"CanRDP", "CanPSRemote"}:
        return [edge]
    nodes_map = graph.get("nodes")
    if not isinstance(nodes_map, dict):
        return [edge]
    target_id = str(edge.get("to") or "").strip()
    target_node = nodes_map.get(target_id)
    if not _is_collectable_computers_scope_node(target_node):
        return [edge]

    expanded: list[dict[str, Any]] = []
    original_notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
    for computer_id, computer_node in nodes_map.items():
        if not _is_scope_expandable_computer_node(computer_node):
            continue
        expanded_edge = dict(edge)
        expanded_edge["to"] = str(computer_id)
        expanded_edge["edge_type"] = str(edge.get("edge_type") or "native_ldap")
        expanded_edge["notes"] = {
            **original_notes,
            "compressed_target": target_id,
            "target_selector": "all_collectable_computers",
            "scope_expanded": True,
        }
        expanded.append(expanded_edge)
    return expanded


def _iter_runtime_graph_edges(graph: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield persisted edges, expanding compressed scope edges for path search."""
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        yield from _expand_collectable_computers_scope_edge(graph, edge)


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
        entry_kind = (
            str(step.entry_kind or notes.get("entry_kind") or "").strip().lower()
        )

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
        elif entry_kind == "user":
            entry_id = ensure_user_node_for_domain(
                shell, domain, graph, username=entry_label
            )
        elif entry_kind == "group":
            # A global well-known read-set SID (Everyone/Authenticated Users/Anonymous
            # Logon/Guests) must fuse onto the shared cross-domain name:<SID> node, even
            # when the DISPLAY label is localized and never matches the by-name map.
            # Prefer the measured source_sid; fall back to the English label.
            entry_id = _resolve_wellknown_source_entry(graph, entry_label, notes)
            if entry_id is None:
                entry_id = ensure_entry_node_for_domain(
                    shell, domain, graph, label=entry_label, entry_kind="group"
                )
        else:
            entry_id = _resolve_wellknown_source_entry(graph, entry_label, notes)
            if entry_id is None:
                entry_id = ensure_entry_node_for_domain(
                    shell, domain, graph, label=entry_label, entry_kind=entry_kind or None
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
    target: str = "highvalue",
    terminal_mode: str = "domain",
    start_node_ids: set[str] | None = None,
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
    for edge in _iter_runtime_graph_edges(graph):
        if attack_graph_core._is_nontraversable_attack_edge(edge, nodes_map):  # noqa: SLF001
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
        mode = (terminal_mode or "domain").strip().lower()
        if mode == "domain":
            return _node_is_domain(node)
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
    seen_signatures: set[tuple[tuple[str, str, str, str], ...]] = set()

    def emit(acc_steps: list[AttackPathStep]) -> None:
        if not acc_steps:
            return
        if (target == "highvalue" and not is_terminal(acc_steps[-1].to_id)) or (
            target == "lowpriv" and is_terminal(acc_steps[-1].to_id)
        ):
            return
        signature = tuple(
            attack_graph_core.attack_path_step_signature(s) for s in acc_steps
        )
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
        actionable_depth = attack_graph_core._count_actionable_edges(acc_steps)  # noqa: SLF001
        structural_depth = len(acc_steps) - actionable_depth
        if (
            actionable_depth >= max_depth
            or structural_depth >= attack_graph_core._MAX_STRUCTURAL_HOPS  # noqa: SLF001
            or (acc_steps and is_terminal(current))
        ):
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
    name = strip_sensitive_markers(str(value or "")).strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def _normalize_attack_path_filter_label(value: str) -> str:
    """Return a comparable canonical label for summary target/source matching."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    return raw.upper()


def _summary_terminal_relation(record: dict[str, Any]) -> str:
    """Return the last executable relation key for one summary record."""
    steps = record.get("steps")
    if isinstance(steps, list):
        terminal_relation = ""
        for step in steps:
            if not isinstance(step, dict):
                continue
            relation = str(step.get("action") or "").strip()
            if not relation:
                continue
            if relation.strip().lower() in _CONTEXT_RELATIONS_LOWER:
                continue
            terminal_relation = relation
        if terminal_relation:
            return str(terminal_relation or "").strip().lower()
    relations = record.get("relations")
    if isinstance(relations, list):
        for relation in reversed(relations):
            relation_clean = str(relation or "").strip()
            if not relation_clean:
                continue
            if relation_clean.lower() in _CONTEXT_RELATIONS_LOWER:
                continue
            return relation_clean.lower()
    return ""


def _apply_attack_path_summary_filters(
    records: list[dict[str, Any]],
    *,
    filters: AttackPathSummaryFilters | None,
) -> list[dict[str, Any]]:
    """Apply optional reusable filters to attack-path summary records."""
    if not filters:
        return records

    target_labels = {
        _normalize_attack_path_filter_label(label)
        for label in filters.target_labels
        if _normalize_attack_path_filter_label(label)
    }
    terminal_relations = {
        str(relation or "").strip().lower()
        for relation in filters.terminal_relations
        if str(relation or "").strip()
    }
    if not target_labels and not terminal_relations:
        return records

    filtered: list[dict[str, Any]] = []
    for record in records:
        target_label = _normalize_attack_path_filter_label(
            str(record.get("target") or "")
        )
        if not target_label:
            nodes = record.get("nodes")
            if isinstance(nodes, list) and nodes:
                target_label = _normalize_attack_path_filter_label(str(nodes[-1] or ""))
        if target_labels and target_label not in target_labels:
            continue
        terminal_relation = _summary_terminal_relation(record)
        if terminal_relations and terminal_relation not in terminal_relations:
            continue
        filtered.append(record)
    return filtered


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


def _select_edge_endpoints(
    graph: dict[str, Any],
    *,
    relation: str,
    from_candidates: list[str],
    to_candidates: list[str],
) -> tuple[str, str]:
    """Pick the endpoint pair a status update should be written onto.

    A display label is not unique in an AD graph (an AD CS deployment renders
    its EnterpriseCA, AIACA and RootCA with the same ``<CA>@<REALM>`` label),
    so identity resolution alone can hand back several candidates. The edge
    being updated is the tie-breaker: prefer the ``(from, to)`` pair that
    already carries an edge with this relation, because that is the edge the
    attack path was built from. Falls back to the best identity candidate when
    no existing edge matches (a genuinely new runtime edge).

    Returns:
        ``(from_id, to_id)``; either may be ``""`` when nothing resolved.
    """
    best_from = from_candidates[0] if from_candidates else ""
    best_to = to_candidates[0] if to_candidates else ""
    if len(from_candidates) <= 1 and len(to_candidates) <= 1:
        return best_from, best_to

    edges = graph.get("edges")
    if not isinstance(edges, list):
        return best_from, best_to

    wanted_relation = _normalize_relation_key(relation)
    from_set = set(from_candidates)
    to_set = set(to_candidates)
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if _normalize_relation_key(edge.get("relation")) != wanted_relation:
            continue
        edge_from = str(edge.get("from") or "")
        edge_to = str(edge.get("to") or "")
        if edge_from in from_set and edge_to in to_set:
            return edge_from, edge_to
    return best_from, best_to


def _resolve_edge_endpoints_in_graph(
    graph: dict[str, Any],
    *,
    from_label: str,
    relation: str,
    to_label: str,
) -> tuple[str, str]:
    """Resolve ``(from_id, to_id)`` for an edge inside ONE graph (best-effort).

    Returns ``("", "")`` when either endpoint is unresolvable in this graph.
    Endpoint resolution is alias-aware and lives in one place
    (``attack_graph_node_identity``).  Three properties matter here:

    * Security principals (Group, User, Computer, Domain) win over structural
      AD objects (OU, Container, CertTemplate, EnterpriseCA) when several nodes
      share the same normalised display label.
    * A host-shaped endpoint may be named by IP, short name, FQDN or ``HOST$``
      while the node is labelled with one of the other three.
    * A display label is NOT unique, so when an endpoint is ambiguous prefer the
      candidate pair that ALREADY carries an edge with this relation.
    """
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict) or not nodes_map:
        return "", ""
    from_candidates = resolve_graph_node_candidates(nodes_map, from_label)
    to_candidates = resolve_graph_node_candidates(nodes_map, to_label)
    from_id, to_id = _select_edge_endpoints(
        graph,
        relation=relation,
        from_candidates=from_candidates,
        to_candidates=to_candidates,
    )
    return (from_id or ""), (to_id or "")


def _write_edge_status_in_graph(
    shell: object,
    domain: str,
    graph: dict[str, Any],
    *,
    from_id: str,
    to_id: str,
    relation: str,
    status: str,
    from_label: str,
    to_label: str,
    notes: dict[str, Any] | None,
) -> None:
    """Upsert the edge status into ``graph`` and persist ``domain``'s graph."""
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
    print_info_debug(
        "[attack-graph] Edge status updated: "
        f"domain={mark_sensitive(domain, 'domain')} relation={relation} status={status} "
        f"from={mark_sensitive(from_label, 'node')} to={mark_sensitive(to_label, 'node')}"
    )


def _is_cross_domain_relation(relation: str) -> bool:
    """True when ``relation`` is a modeled cross-domain / cross-forest escalation.

    Reuses the SSOT set from ``attack_graph_core`` so a new cross-domain edge
    (RaiseChild, a future bidirectional inter-forest edge) inherits the
    owning-graph write-back routing with no per-technique change here.
    """
    return _normalize_relation_key(relation) in (
        attack_graph_core._CROSS_DOMAIN_ESCALATION_RELATIONS  # noqa: SLF001
    )


def _route_cross_domain_status_to_owning_graph(
    shell: object,
    path_domain: str,
    *,
    from_label: str,
    relation: str,
    to_label: str,
    status: str,
    notes: dict[str, Any] | None,
) -> bool:
    """Write a cross-domain edge's status into whichever domain graph OWNS it.

    A cross-domain edge (CrossOrgTgtDelegation, RaiseChild, …) spans two domains,
    so it is persisted in ONE of them (the trusting / child side), which is often
    NOT the path's own domain.  When the endpoints do not resolve in the
    path-domain graph, walk every OTHER persisted domain graph and write the
    status into the one whose graph resolves BOTH endpoints — "an edge whose
    endpoints span two domains gets its status written to whichever domain graph
    persists it".

    Returns True when it found the owning graph and wrote the status.
    """
    for other_domain in list_domains_with_attack_graph(shell):
        if str(other_domain).strip().lower() == str(path_domain).strip().lower():
            continue
        other_graph = load_attack_graph(shell, other_domain)
        from_id, to_id = _resolve_edge_endpoints_in_graph(
            other_graph, from_label=from_label, relation=relation, to_label=to_label
        )
        if not from_id or not to_id:
            continue
        _write_edge_status_in_graph(
            shell,
            other_domain,
            other_graph,
            from_id=from_id,
            to_id=to_id,
            relation=relation,
            status=status,
            from_label=from_label,
            to_label=to_label,
            notes=notes,
        )
        print_info_debug(
            "[attack-graph] Cross-domain edge status routed to owning graph: "
            f"path_domain={mark_sensitive(path_domain, 'domain')} "
            f"owning_domain={mark_sensitive(other_domain, 'domain')} "
            f"relation={relation} status={status}"
        )
        return True
    return False


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
    Note: attack-path counts are derived from the curated client path set at scan
    completion (``services.attack_path_counts``) rather than tracked at runtime.
    """
    graph = load_attack_graph(shell, domain)
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        print_info_debug(
            "[attack-graph] Edge status update skipped: "
            f"domain={mark_sensitive(domain, 'domain')} relation={relation} status={status} "
            "reason=missing_nodes_map"
        )
        return False

    from_norm = _normalize_account(from_label)
    to_norm = _normalize_account(to_label)
    if not from_norm or not to_norm:
        print_info_debug(
            "[attack-graph] Edge status update skipped: "
            f"domain={mark_sensitive(domain, 'domain')} relation={relation} status={status} "
            f"from={mark_sensitive(from_label, 'node')} to={mark_sensitive(to_label, 'node')} "
            "reason=invalid_endpoint_labels"
        )
        return False

    from_id, to_id = _resolve_edge_endpoints_in_graph(
        graph, from_label=from_label, relation=relation, to_label=to_label
    )
    if not from_id or not to_id:
        # A cross-domain edge (CrossOrgTgtDelegation, RaiseChild, future
        # bidirectional inter-forest edges) spans two domains, so it is persisted
        # in the OTHER domain's graph (the trusting / child side) — not the path's
        # own domain. When the terminal node is not in THIS graph but the relation
        # is cross-domain, route the write to the graph that actually holds the
        # edge, rather than dropping the status. Generalized via the SSOT relation
        # set — no per-technique special-casing.
        if _is_cross_domain_relation(
            relation
        ) and _route_cross_domain_status_to_owning_graph(
            shell,
            domain,
            from_label=from_label,
            relation=relation,
            to_label=to_label,
            status=status,
            notes=notes,
        ):
            return True

        # Only the sampled node LABELS are marked: the counts and the kind
        # census carry no identity and must stay readable in a recording — they
        # are what tells "no node of this kind exists" apart from "it exists
        # under another label".
        diagnosis = describe_node_resolution_failure(
            nodes_map,
            from_label=from_label,
            to_label=to_label,
            from_id=from_id,
            to_id=to_id,
            mask_label=lambda value: mark_sensitive(value, "node"),
        )
        print_info_debug(
            "attack-graph: Edge status update skipped: "
            f"domain={mark_sensitive(domain, 'domain')} relation={relation} status={status} "
            f"from={mark_sensitive(from_label, 'node')} to={mark_sensitive(to_label, 'node')} "
            f"reason=edge_nodes_not_found from_id={mark_sensitive(from_id or 'N/A', 'detail')} "
            f"to_id={mark_sensitive(to_id or 'N/A', 'detail')} "
            f"{diagnosis}"
        )
        if str(status or "").strip().lower() in _PROVEN_EDGE_STATUSES:
            # Losing a PROVEN step is the expensive failure: the compromise
            # happened but the graph — and therefore the report and the web
            # CTEM — never record it. Surface it above debug-only noise.
            print_warning_debug(
                "attack-graph: a PROVEN attack step could not be recorded: "
                f"relation={relation} status={status} "
                f"from={mark_sensitive(from_label, 'node')} to={mark_sensitive(to_label, 'node')} "
                f"{diagnosis}"
            )
        return False

    _write_edge_status_in_graph(
        shell,
        domain,
        graph,
        from_id=from_id,
        to_id=to_id,
        relation=relation,
        status=status,
        from_label=from_label,
        to_label=to_label,
        notes=notes,
    )
    return True


#: Note key recording the principal ADscan authenticated as when it performed a
#: replication. Distinguishes an edge proven by an observed execution from one
#: that merely describes who holds replication rights.
_DCSYNC_EXECUTED_AS_NOTE = "dcsync_executed_as"


def _dcsync_grant_exercised_by(
    graph: dict[str, Any],
    *,
    user: str,
) -> tuple[str, str] | None:
    """Return the ``(from_label, to_label)`` of the DCSync grant ``user`` used.

    A ``DCSync -> Domain`` edge answers one of two very different questions.
    Either ADscan authenticated as a principal covered by that grant and pulled
    the directory through it, or the directory simply grants some principal
    replication rights — canonically ``Domain Controllers``, which holds them
    because replicating is what the group is for. Only the first is evidence.

    Which grant authorised a replication is decided by the executing
    principal's Kerberos token: its own SID plus every group SID it transitively
    belongs to. An edge sourced from inside that token was exercised; anything
    else was not. Group expansion reuses the cycle-safe, depth-capped SID
    closure SSOT (:func:`build_sid_group_closure`) over the graph's own
    ``MemberOf`` edges, so the ids compare directly against an edge's ``from``.

    Only EXISTING ``DCSync -> Domain`` edges are considered, and exactly one is
    returned. Both matter: the caller feeds the labels to
    :func:`update_edge_status_by_labels`, which would otherwise CREATE an edge
    that the directory never granted; and when a token happens to cover two
    grants, one replication is evidence for one of them, so claiming both would
    reintroduce the inflation this resolution exists to remove. A grant on the
    principal's own account wins over a grant it inherits from a group, then
    node id, so the choice is stable across runs.

    Args:
        graph: The loaded attack graph.
        user: The principal ADscan authenticated as (sAMAccountName, UPN or
            ``DOMAIN\\user`` — resolved alias-aware).

    Returns:
        The endpoint labels of the exercised grant, or ``None`` when the
        principal does not resolve in this graph (a foreign principal reaching
        in over a trust) or holds no DCSync edge onto the domain.
    """
    from adscan_internal.services.collector.share_ntfs_verification import (
        build_sid_group_closure,
    )

    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    if not nodes or not edges:
        return None

    candidates = resolve_graph_node_candidates(nodes, user)
    if not candidates:
        return None
    # An AD graph legitimately renders several objects under one label (a
    # CertTemplate named after the account it was cloned for, say), and only an
    # account can carry a Kerberos token.
    seed = next(
        (
            node_id
            for node_id in candidates
            if str((nodes.get(node_id) or {}).get("kind") or "")
            in {"User", "Computer", "Group", "ManagedServiceAccount"}
        ),
        candidates[0],
    )
    seed_key = seed.upper()

    member_of = [
        (str(edge.get("from") or ""), str(edge.get("to") or ""))
        for edge in edges
        if isinstance(edge, dict)
        and _normalize_relation_key(edge.get("relation")) == "memberof"
    ]
    token_scope = {seed_key} | set(
        build_sid_group_closure(member_of).get(seed_key, frozenset())
    )

    domain_node_ids = {
        node_id
        for node_id, node in nodes.items()
        if isinstance(node, dict) and _node_is_domain(node)
    }
    if not domain_node_ids:
        return None

    matches: list[tuple[int, str, str, str]] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if _normalize_relation_key(edge.get("relation")) != "dcsync":
            continue
        to_id = str(edge.get("to") or edge.get("to_id") or "")
        if to_id not in domain_node_ids:
            continue
        from_id = str(edge.get("from") or edge.get("from_id") or "")
        if from_id.upper() not in token_scope:
            continue
        from_label = str((nodes.get(from_id) or {}).get("label") or "").strip()
        to_label = str((nodes.get(to_id) or {}).get("label") or "").strip()
        if not from_label or not to_label:
            continue
        matches.append(
            (0 if from_id.upper() == seed_key else 1, from_id, from_label, to_label)
        )

    if not matches:
        return None
    matches.sort()
    _, _, best_from_label, best_to_label = matches[0]
    if len(matches) > 1:
        print_info_debug(
            "attack-graph: the replicating principal holds several DCSync grants; "
            "one replication proves one grant, so recording only "
            f"{mark_sensitive(best_from_label, 'node')} "
            f"(candidates={len(matches)})."
        )
    return best_from_label, best_to_label


def record_executed_dcsync_edge(
    shell: object,
    domain: str,
    *,
    user: str | None = None,
) -> bool:
    """Mark the one ``DCSync -> Domain`` edge ADscan actually replicated through.

    Called when ADscan has replicated the domain's credential database from the
    Domain Controller (a full NTDS "all" walk — the authoritative
    ``dcsync_all_done`` signal). A DCSync driven by the attack-path executor
    marks its own edge like any other step; this exists for the replication that
    does NOT flow through that machinery — the post-compromise "all" dump from
    an already-Domain-Admin context. Without it that takeover leaves its
    terminal DCSync step at ``discovered`` and the client report contradicts its
    own "domain compromised" headline.

    DCSync is recorded exactly like every other attack step: one execution marks
    the one edge it executed, through the shared per-edge seam
    (:func:`update_edge_status_by_labels`, matching on
    ``(from_label, relation, to_label)``). It does NOT sweep the relation. A
    ``Domain Controllers -> DCSync -> <domain>`` edge stays as collected —
    replication rights that group holds by design, real exposure worth
    reporting, but not something ADscan demonstrated — and becomes ``success``
    only if a step is ever executed from there. Presenting it otherwise reuses
    one replication as several and attributes a step to a principal ADscan never
    authenticated as, which costs more than the missing status it was fixing:
    proof is the whole claim.

    Naming the edge is the only work this function adds over the seam. When a
    DCSync step is executing, its own context already names it. Otherwise the
    grant is resolved from the executing principal's token
    (:func:`_dcsync_grant_exercised_by`), because a standalone replication has
    no step context to name an edge with.

    Best-effort: never raises.

    Args:
        shell: The ADscan shell instance.
        domain: Domain whose directory was replicated.
        user: The principal ADscan authenticated as. Without it, and with no
            active DCSync step, nothing is recorded — a replication can only be
            evidence for the grant its executor actually held.

    Returns:
        ``True`` when an edge was recorded.
    """
    executing_user = str(user or "").strip()
    notes: dict[str, Any] = {
        # The synthetic DC-bridge models an unexecuted replication as
        # ``theoretical``; the one we just performed no longer is.
        "theoretical": False,
    }
    if executing_user:
        notes["user"] = executing_user
        notes[_DCSYNC_EXECUTED_AS_NOTE] = executing_user

    # A DCSync attack-path step names its own edge — the same context every
    # other step marks itself through, and more authoritative than any
    # after-the-fact attribution.
    try:
        from adscan_internal.services.attack_graph_runtime_service import (
            get_active_step,
            update_active_step_status,
        )

        active = get_active_step(shell)
        if (
            active is not None
            and active.domain == domain
            and _normalize_relation_key(active.relation) == "dcsync"
        ):
            return bool(
                update_active_step_status(
                    shell, domain=domain, status="success", notes=notes
                )
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    if not executing_user:
        print_info_debug(
            "attack-graph: DCSync replication recorded without an executing "
            f"principal for domain={mark_sensitive(domain, 'domain')} — no edge "
            "can be attributed, so none is marked."
        )
        return False

    try:
        graph = load_attack_graph(shell, domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
    if not isinstance(graph, dict):
        return False

    exercised = _dcsync_grant_exercised_by(graph, user=executing_user)
    if exercised is None:
        print_info_debug(
            "attack-graph: no DCSync grant in this domain's graph is covered by "
            f"the replicating principal: domain={mark_sensitive(domain, 'domain')} "
            f"user={mark_sensitive(executing_user, 'user')} — leaving every DCSync "
            "edge as collected rather than crediting a principal ADscan never "
            "authenticated as."
        )
        return False

    from_label, to_label = exercised
    return update_edge_status_by_labels(
        shell,
        domain,
        from_label=from_label,
        relation="DCSync",
        to_label=to_label,
        status="success",
        notes=notes,
    )


def get_node_by_label(
    shell: object, domain: str, *, label: str
) -> dict[str, Any] | None:
    """Return a persisted attack-graph node by display label.

    This is a convenience helper for runtime executors (attack path execution,
    privilege confirmation, etc.) that only have the UI label available.

    Args:
        shell: Shell instance used to load the attack graph.
        domain: Primary domain for which the graph is loaded. When the workspace
            holds more than one domain graph, the MERGED multi-domain graph is
            searched (primary ``domain`` first), so a node that lives in a trusted
            in-scope domain — the target/source of a cross-domain attack-path step
            — resolves here. In the single-domain case this is byte-identical to
            loading ``domain``'s own graph.
        label: UI label of the node (e.g. ``WINTERFELL$``).

    Returns:
        Node dict when found, otherwise None.
    """
    label_clean = str(label or "").strip()
    if not label_clean:
        return None
    graph = _load_attack_graph_for_paths(shell, domain)
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

    # Environment coordinates for the per-step independent-verification commands
    # (the catalog renders {dc_ip}/{domain} into the copy-paste verify block).
    # Both are graph-level facts stamped by ``save_attack_graph`` — the domain
    # name always, and the DC/KDC IP resolved once there via the ``resolve_dc_ip``
    # SSOT. Stamping them into every step's ``details`` here means both the report
    # (which re-renders verify at PDF-build time) and the attack-path snapshot
    # (which bakes the ``knowledge`` block the web CTEM consumes) inherit real
    # values for free — no seam re-resolves them. Absent (an older graph written
    # before the stamp, or a domain with no resolvable DC) → left unset, and the
    # catalog degrades to the literal ``<dc_ip>``/``<domain>`` token.
    _graph_dc_ip = str(graph.get("dc_ip") or "").strip()
    _graph_domain = str(graph.get("domain") or "").strip()

    def _stamp_env(details: dict[str, Any]) -> dict[str, Any]:
        """Attach dc_ip/domain to a step's details when the graph carries them."""
        if _graph_dc_ip:
            details.setdefault("dc_ip", _graph_dc_ip)
        if _graph_domain:
            details.setdefault("domain", _graph_domain)
        return details

    def label(node_id: str) -> str:
        node = nodes_map.get(node_id)
        if isinstance(node, dict):
            return str(node.get("label") or node_id)
        return node_id

    def _resolve_membership_followup_step(
        target_node: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        if not isinstance(target_node, dict):
            return None
        target_kind = (
            target_node.get("kind")
            or target_node.get("labels")
            or target_node.get("type")
        )
        if isinstance(target_kind, list):
            target_kind = str(target_kind[0] if target_kind else "")
        if str(target_kind or "") != "Group":
            return None
        props = (
            target_node.get("properties")
            if isinstance(target_node.get("properties"), dict)
            else {}
        )
        sid_upper, _ = attack_graph_core._extract_node_sid_and_rid(target_node)  # noqa: SLF001
        group_name = str(props.get("name") or target_node.get("label") or "").strip()
        membership = classify_privileged_membership(
            group_sids=[sid_upper],
            group_names=[group_name],
        )
        normalized_group_name = normalize_group_name(group_name)
        # Terminate the synthetic escalation follow-up at the REAL domain object
        # node (not a "Domain Control" placeholder) so the annotation phase — which
        # resolves the terminal node by label — classifies it against the domain
        # object and the canonical target_mode="object" ordering surfaces it in the
        # Domain Compromised tier.
        domain_label = attack_graph_core._resolve_membership_followup_domain_label(  # noqa: SLF001
            graph, target_node
        )
        if membership.dns_admins:
            return {
                "relation": "DnsAdminAbuse",
                "status": "blocked",
                "to": domain_label,
                "reason": "Production-impacting DNS modification is blocked by design",
            }
        if membership.backup_operators:
            return {
                "relation": "BackupOperatorEscalation",
                "status": "theoretical",
                "to": domain_label,
                "reason": "Backup Operators can enable a follow-up path to domain compromise",
            }
        if normalized_group_name == "print operators":
            return {
                "relation": "PrintOperatorAbuse",
                "status": "unsupported",
                "to": domain_label,
                "reason": "Print Operators exposure is modeled, but ADscan has no automated follow-up yet",
            }
        return None

    nodes = [label(path.source_id)]
    relations: list[str] = []
    for step in path.steps:
        relations.append(step.relation)
        nodes.append(label(step.to_id))

    # A pure coverage-declaration marker (the fallback floor's synthetic
    # ``reached_not_materialized`` record) is NOT a real attack step. Branch on it
    # FIRST so it derives the dedicated ``coverage_sample`` status and never rolls
    # into ``attempted``. Mirrors the sibling in ``attack_graph_core``.
    _is_coverage_marker = attack_graph_core.is_coverage_marker_path(path.steps)

    derived_status = "theoretical"
    executable_steps = [
        s
        for s in path.steps
        if isinstance(getattr(s, "relation", None), str)
        and str(s.relation).strip().lower() not in context_relations
    ]
    target_node = nodes_map.get(path.target_id) if isinstance(nodes_map, dict) else None
    synthetic_followup = None
    if (
        not executable_steps
        and path.steps
        and str(path.steps[-1].relation or "").strip().lower() == "memberof"
    ):
        synthetic_followup = _resolve_membership_followup_step(target_node)
        if synthetic_followup is not None:
            relations.append(str(synthetic_followup["relation"]))
            nodes.append(str(synthetic_followup["to"]))
    statuses = [
        s.status.lower()
        for s in executable_steps
        if isinstance(s.status, str) and s.status
    ]
    if synthetic_followup is not None:
        statuses.append(str(synthetic_followup.get("status") or "").strip().lower())
    if _is_coverage_marker:
        derived_status = attack_graph_core.COVERAGE_SAMPLE_STATUS
    elif statuses and all(s == "success" for s in statuses):
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
    elif any(s == "closed_by_configuration" for s in statuses):
        # A relay avenue ADscan observed to be CLOSED with certainty by the
        # environment's configuration/topology (signing/CBT/no-ADCS/MAQ/single-DC
        # reflection). A POSITIVE exposure fact — never a risk/held status.
        derived_status = "closed_by_configuration"
    elif any(s == "unsupported" for s in statuses) or any(
        # Live support classification is the single source of truth: a relation
        # whose catalog ``support_kind`` is ``unsupported`` surfaces as such even
        # when the persisted edge status still carries the pre-flip default
        # (e.g. CrackNTLMv1 flipped supported→unsupported after the graph was
        # last enumerated). Mirrors the live ``policy_blocked`` check above.
        classify_relation_support(str(s.relation or "").strip().lower()).kind
        == "unsupported"
        for s in executable_steps
    ):
        derived_status = "unsupported"

    steps_for_ui: list[dict[str, Any]] = []
    for idx, step in enumerate(path.steps, start=1):
        # A non-executed ``context_only`` hop (MemberOf, credential-reuse pivot)
        # is a structural FACT — surface it as ``structural`` at the data SSOT so
        # every consumer (snapshot/PDF/web) agrees; proven / blocked / config-close
        # statuses are preserved unchanged (see ``derive_step_display_status``).
        step_status = derive_step_display_status(step.relation, step.status)
        relation_key = str(step.relation or "").strip().lower()
        step_details = {
            "from": label(step.from_id),
            "to": label(step.to_id),
            # The SOURCE's granted Privilege Tier (axis 1), resolved HERE
            # because this is where the graph nodes are in hand — a downstream
            # renderer only ever sees labels, and a label cannot tell you that
            # MEEREEN$ is a domain controller. Consumed by
            # ``attack_step_catalog.render_step_remediation`` to suppress
            # "remove it" advice on a step out of a Tier-0-direct principal
            # (built-in AD hierarchy, not a misconfiguration). Baked as DATA at
            # this SSOT, mirroring how ``derive_step_display_status`` bakes the
            # ``structural`` status, so the PDF and the web read one verdict
            # instead of each re-deriving it.
            "source_privilege_tier": privilege_tier_for_node(
                nodes_map.get(step.from_id)
            ).value,
            **(step.notes or {}),
        }
        if relation_key.startswith("adcs") or relation_key in {
            "coerceandrelayntlmtoadcs",
        }:
            step_details.setdefault(
                "templates_summary",
                format_adcs_templates_summary(step_details),
            )
            display_to = resolve_adcs_display_target(
                step.relation,
                step_details,
                fallback_target=str(step_details.get("to") or ""),
            )
            if display_to and display_to != str(step_details.get("to") or ""):
                step_details.setdefault(
                    "impact_target", str(step_details.get("to") or "")
                )
                step_details["display_to"] = display_to
        from adscan_internal.services.destructive_action_policy import (  # noqa: PLC0415
            safety_abstention_notes,
        )

        safety_notes = safety_abstention_notes(relation_key)
        steps_for_ui.append(
            {
                "step": idx,
                "action": step.relation,
                "status": step_status,
                "details": _stamp_env(
                    {
                        **step_details,
                        # A hard-blocked safety abstention is stamped
                        # ``dangerous_destructive`` (routed via the single classifier)
                        # so it renders under "Not executed for safety"; never
                        # downgrade it to ``dangerous`` here.
                        **(
                            safety_notes
                            if safety_notes is not None
                            else (
                                {
                                    "blocked_kind": "dangerous",
                                    "reason": "High-risk / potentially disruptive (disabled by design)",
                                }
                                if classify_relation_support(relation_key).kind
                                == "policy_blocked"
                                and str(step_status or "").strip().lower() == "blocked"
                                else {}
                            )
                        ),
                    }
                ),
            }
        )
    if synthetic_followup is not None:
        from adscan_internal.services.destructive_action_policy import (  # noqa: PLC0415
            safety_abstention_notes,
        )

        synthetic_status = str(synthetic_followup.get("status") or "theoretical")
        steps_for_ui.append(
            {
                "step": len(steps_for_ui) + 1,
                "action": str(synthetic_followup["relation"]),
                "status": synthetic_status,
                "details": _stamp_env(
                    {
                        "from": label(path.target_id),
                        "to": str(synthetic_followup["to"]),
                        # Same axis-1 stamp as the real steps above, so every step a
                        # renderer receives carries the source tier.
                        "source_privilege_tier": privilege_tier_for_node(
                            nodes_map.get(path.target_id)
                        ).value,
                        "reason": str(synthetic_followup.get("reason") or ""),
                        "synthetic_followup": True,
                        "followup_source_group": label(path.target_id),
                        # A blocked synthetic follow-up (e.g. DNSAdmins abuse) is a
                        # safety abstention — stamp ``dangerous_destructive`` via the
                        # single classifier so it renders under "Not executed for
                        # safety", never a bare ``dangerous``.
                        **(
                            (
                                safety_abstention_notes(
                                    str(synthetic_followup["relation"])
                                )
                                or {
                                    "blocked_kind": "dangerous",
                                    "reason": str(
                                        synthetic_followup.get("reason") or ""
                                    ),
                                }
                            )
                            if synthetic_status.strip().lower() == "blocked"
                            else {}
                        ),
                    }
                ),
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
        # When a synthetic escalation follow-up extends the path past the group
        # to the domain object, the terminal IS that domain object — the
        # annotation phase must resolve the domain node, not the group, so the
        # path is classified/ordered as a domain-compromise terminal.
        "terminal_target_label": (
            str(synthetic_followup["to"])
            if synthetic_followup is not None
            else label(path.target_id)
        ),
        "status": derived_status,
        "steps": steps_for_ui,
    }


def ensure_entry_node(graph: dict[str, Any], *, label: str) -> str:
    """Ensure a synthetic non-principal entry node exists."""
    node = {
        "name": label,
        "kind": ["Entry"],
        "properties": {"name": label},
    }
    _mark_synthetic_node_record(node, domain="", source="fallback_entry")
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
    entry_kind: str | None = None,
) -> str:
    """Ensure an entry node exists, preferring BloodHound-backed nodes when possible.

    For some entry vectors (e.g. "Domain Users") we prefer persisting the real
    BloodHound node (RID 513) to avoid language-dependent naming. When the
    BloodHound service is unavailable or the lookup fails, we fall back to a
    synthetic node label.
    """
    label_clean = (label or "").strip()
    special_entry = _resolve_special_principal_entry(shell, domain, graph, label_clean)
    if special_entry:
        return special_entry

    resolved_principal = _resolve_bloodhound_principal_entry(
        shell,
        domain,
        graph,
        label_clean,
        entry_kind=entry_kind,
    )
    if resolved_principal:
        return resolved_principal

    if label_clean.lower() == "domain users":
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


def _resolve_bloodhound_principal_entry(
    shell: object,
    domain: str,
    graph: dict[str, Any],
    label: str,
    *,
    entry_kind: str | None = None,
) -> str | None:
    """Best-effort resolve an arbitrary entry label to a real BH-backed principal node."""
    node_record = _resolve_bloodhound_principal_node(
        shell,
        domain,
        label,
        entry_kind=entry_kind,
        graph=graph,
    )
    if not isinstance(node_record, dict):
        return None
    upsert_nodes(graph, [node_record])
    return _node_id(node_record)


def _extract_node_object_id(node: dict[str, Any] | None) -> str | None:
    """Return the objectId/objectid value from a node record or node props."""
    if not isinstance(node, dict):
        return None
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    for value in (
        node.get("objectId"),
        node.get("objectid"),
        props.get("objectId"),
        props.get("objectid"),
    ):
        cleaned = str(value or "").strip()
        if cleaned:
            return cleaned
    return None


def _resolve_bloodhound_principal_node(
    shell: object,
    domain: str,
    label: str,
    *,
    object_id: str | None = None,
    entry_kind: str | None = None,
    graph: dict[str, Any] | None = None,
    lookup_name: str | None = None,
) -> dict[str, Any] | None:
    """Best-effort resolve a principal to a BH-backed node record.

    Resolution order:
    1. Existing attack-graph node by label when ``graph`` is provided.
    2. Centralized BloodHound service lookup (objectid-first, then kind-aware).
    3. Legacy per-kind fallback when the service does not expose the unified resolver.
    """
    label_clean = str(label or "").strip()
    if not label_clean:
        return None

    if isinstance(graph, dict):
        node_id = _find_node_id_by_label(graph, label_clean)
        if node_id:
            nodes_map = (
                graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
            )
            node = nodes_map.get(node_id) if isinstance(nodes_map, dict) else None
            if isinstance(node, dict):
                return node

    if not hasattr(shell, "_get_graph_service"):
        return None

    try:
        service = shell._get_graph_service()  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    if not service:
        return None

    normalized = _normalize_account(label_clean)
    lookup_name_clean = str(lookup_name or "").strip() or label_clean
    kind_hint = str(entry_kind or "").strip().lower()

    if hasattr(service, "get_principal_node"):
        try:
            node_props = service.get_principal_node(  # type: ignore[attr-defined]
                domain,
                label_clean,
                principal_type=kind_hint or None,
                object_id=object_id,
                lookup_name=lookup_name_clean,
            )
            if isinstance(node_props, dict):
                kind_map = {"user": "User", "group": "Group", "computer": "Computer"}
                node_kind = kind_map.get(
                    kind_hint, "Group" if " " in label_clean else "User"
                )
                canonical_name = (
                    str(node_props.get("name") or label_clean).strip() or label_clean
                )
                return {
                    "name": canonical_name,
                    "kind": [node_kind],
                    "objectId": node_props.get("objectid")
                    or node_props.get("objectId")
                    or object_id
                    or None,
                    "properties": node_props,
                }
            if object_id and (
                _looks_like_sid(lookup_name_clean)
                or lookup_name_clean.upper() == str(object_id).strip().upper()
            ):
                return None
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    domain_upper = str(domain or "").strip().upper()
    candidates: list[tuple[int, dict[str, Any]]] = []

    def _append_candidate(kind: str, node_props: dict[str, Any] | None) -> None:
        if not isinstance(node_props, dict):
            return
        object_id = node_props.get("objectid") or node_props.get("objectId")
        name = str(node_props.get("name") or "").strip()
        if kind == "User":
            canonical_name = name or f"{normalized.upper()}@{domain_upper}"
            node_props.setdefault("name", canonical_name)
            node_props.setdefault("samaccountname", normalized)
        elif kind == "Computer":
            canonical_name = name or label_clean
            node_props.setdefault("name", canonical_name)
        else:
            canonical_name = name or label_clean
            node_props.setdefault("name", canonical_name)
        node_record = {
            "name": canonical_name,
            "kind": [kind],
            "objectId": object_id or None,
            "properties": node_props,
        }
        kind_priority = {"user": 0, "computer": 1, "group": 2}
        if kind_hint in kind_priority:
            score = 0 if kind.lower() == kind_hint else 10 + kind_priority[kind.lower()]
        else:
            score = kind_priority.get(kind.lower(), 20)
        if object_id:
            score -= 5
        candidates.append((score, node_record))

    if normalized and hasattr(service, "get_user_node_by_samaccountname"):
        try:
            _append_candidate(
                "User",
                service.get_user_node_by_samaccountname(  # type: ignore[attr-defined]
                    domain, normalize_samaccountname(lookup_name_clean) or normalized
                ),
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    if hasattr(service, "get_group_node_by_samaccountname"):
        try:
            _append_candidate(
                "Group",
                service.get_group_node_by_samaccountname(  # type: ignore[attr-defined]
                    domain, lookup_name_clean
                ),
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    if hasattr(service, "get_computer_node_by_name"):
        try:
            _append_candidate(
                "Computer",
                service.get_computer_node_by_name(domain, lookup_name_clean),  # type: ignore[attr-defined]
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1]


def resolve_entry_label_for_auth(auth_username: str | None, *, perspective: str | None = None) -> str:
    """Resolve the entry label for a credential-provenance step.

    Domain Users is never a fallback. The ladder: an explicit authenticated
    username wins; an unauthenticated perspective (null/anonymous/guest)
    resolves to ANONYMOUS LOGON / GUESTS; otherwise the honest authenticated
    default is Authenticated Users (S-1-5-11) — the broadest scope that needs
    only an authenticated bind (and a truer reach answer than Domain Users,
    which under-states it to a single domain's users).
    """
    persp = str(perspective or "").strip().lower()
    normalized = str(auth_username or "").strip()
    lowered = normalized.lower()
    if lowered in {"null", "anonymous"} or persp in {"null", "anonymous"}:
        return "ANONYMOUS LOGON"
    if lowered == "guest" or persp == "guest":
        return "GUESTS"
    if normalized:
        return normalized
    return "Authenticated Users"


# Genuinely-global well-known principals carry a domain-AGNOSTIC @WELLKNOWN label
# (identical across domains) and a fixed SID, so they must resolve to ONE shared,
# cross-domain-traversable node — never a per-domain synthetic fork. Authenticated
# Users (S-1-5-11) is the actor scope for any attack that needs only an
# authenticated bind (Kerberoasting, AS-REP Roasting, UserDescription), which is
# cross-forest capable. This is the SAME node the collector injects via
# well_known_sids.inject_all_well_known_sid_nodes, so keying by its fixed SID
# merges the entry-node with the injected node.
_GLOBAL_WELL_KNOWN_ENTRY_SIDS: dict[str, tuple[str, str]] = {
    "authenticated users": ("S-1-5-11", "Authenticated Users"),
    "everyone": ("S-1-1-0", "Everyone"),
    # Anonymous Logon and Guests carry globally-fixed SIDs too, so a Spanish DC's
    # "Invitados" fuses with S-1-5-32-546. Keying them here (same as Everyone /
    # Authenticated Users) merges the entry node with the collector-injected
    # S-1-5-7 / S-1-5-32-546 node instead of forking per domain by localized name.
    "anonymous logon": ("S-1-5-7", "Anonymous Logon"),
    "guests": ("S-1-5-32-546", "Guests"),
}

# Reverse index SID -> by-name key, so a credential-source step expressed by its
# measured read-capable SID (notes["source_sid"]) can fuse onto the shared node even
# when the DISPLAY label is localized and never matches the by-name map above.
_GLOBAL_WELL_KNOWN_ENTRY_BY_SID: dict[str, str] = {
    sid: label_key for label_key, (sid, _name) in _GLOBAL_WELL_KNOWN_ENTRY_SIDS.items()
}


def _resolve_global_well_known_entry(
    graph: dict[str, Any],
    label_lower: str,
) -> str | None:
    """Resolve a genuinely-global well-known principal to its shared @WELLKNOWN node.

    Returns the graph node id (``name:<SID>``) or ``None`` when the label is not a
    globally-well-known principal. The node shape mirrors
    ``well_known_sids._make_well_known_node`` so it fuses with the collector-injected
    node and stays cross-domain traversable.
    """
    entry = _GLOBAL_WELL_KNOWN_ENTRY_SIDS.get(label_lower)
    if entry is None:
        return None
    sid, display_name = entry
    # Derive the node KIND from the collector's canonical SID→kind SSOT rather than
    # hardcoding "Group": most well-known SIDs are Groups, but some (e.g. Anonymous
    # Logon S-1-5-7) are typed "User". Node-id derivation keys User/Computer nodes by
    # NAME and all other kinds by objectId, so a hardcoded "Group" forks the entry
    # node (name:S-1-5-7) away from the collector-injected User node
    # (name:anonymous logon). Using the collector SSOT's kind makes the entry node
    # BYTE-IDENTICAL to well_known_sids._make_well_known_node, so the two fuse.
    from adscan_internal.services.collector.well_known_sids import _WELL_KNOWN

    kind = _WELL_KNOWN.get(sid, (display_name, "Group"))[1]
    node_record = {
        "name": f"{display_name}@WELLKNOWN",
        "kind": [kind],
        "objectId": sid,
        "properties": {
            "name": f"{display_name}@WELLKNOWN",
            "objectid": sid,
            "domain": "WELLKNOWN",
            "well_known_sid": True,
            "display_name": display_name,
        },
    }
    upsert_nodes(graph, [node_record])
    return _node_id(node_record)


def _resolve_wellknown_source_entry(
    graph: dict[str, Any],
    entry_label: str,
    notes: dict[str, Any],
) -> str | None:
    """Resolve a credential-source entry to the fused well-known node when possible.

    A credential read-set is measured by SID, so prefer ``notes["source_sid"]`` when it
    names a global well-known principal (Everyone/Authenticated Users/Anonymous Logon/
    Guests) — this fuses onto the shared cross-domain ``name:<SID>`` node even when the
    DISPLAY label is localized and never matches the by-name map. Fall back to the
    label. Returns ``None`` for a non-well-known entry so the caller keeps today's
    per-domain ``ensure_entry_node_for_domain`` behaviour.
    """
    source_sid = str(notes.get("source_sid") or "").strip().upper()
    label_key = _GLOBAL_WELL_KNOWN_ENTRY_BY_SID.get(source_sid)
    if label_key is not None:
        resolved = _resolve_global_well_known_entry(graph, label_key)
        if resolved:
            return resolved
    return _resolve_global_well_known_entry(graph, str(entry_label or "").strip().lower())


def _resolve_special_principal_entry(
    shell: object,
    domain: str,
    graph: dict[str, Any],
    label: str,
) -> str | None:
    """Resolve well-known principals (authenticated-users/everyone/anonymous/guest)."""
    label_lower = str(label or "").strip().lower()
    global_entry = _resolve_global_well_known_entry(graph, label_lower)
    if global_entry:
        return global_entry
    # Unreachable for anonymous logon / guests: both are in
    # _GLOBAL_WELL_KNOWN_ENTRY_SIDS, so _resolve_global_well_known_entry above
    # short-circuits and returns first. Dead but harmless Neo4j (legacy BloodHound)
    # fallback kept for any future non-global well-known added to this map.
    sid_suffix_map = {
        "anonymous logon": "S-1-5-7",
        "guests": "S-1-5-32-546",
    }
    sid_suffix = sid_suffix_map.get(label_lower)
    if not sid_suffix:
        return None
    try:
        if hasattr(shell, "_get_graph_service"):
            service = shell._get_graph_service()  # type: ignore[attr-defined]
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
        print_exception(exception=exc)
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
    """Ensure a canonical Domain node exists for one domain."""
    node_record = resolve_domain_node_record_for_domain(shell, domain, graph=graph)
    upsert_nodes(graph, [node_record])
    return _node_id(node_record)


def _normalize_domain_fqdn(value: str | None) -> str:
    """Return a stable uppercase FQDN representation for one domain-like value."""
    return str(value or "").strip().rstrip(".").upper()


def _canonicalize_domain_node_record(
    node_record: dict[str, Any],
    *,
    domain: str,
) -> dict[str, Any]:
    """Return a normalized Domain node record with canonical casing."""
    canonical_domain = _normalize_domain_fqdn(domain)
    record = copy.deepcopy(node_record) if isinstance(node_record, dict) else {}
    props = (
        record.get("properties") if isinstance(record.get("properties"), dict) else {}
    )
    props = dict(props)

    label = _canonical_node_label(
        {
            **record,
            "kind": ["Domain"],
            "properties": props,
        }
    )
    canonical_label = _normalize_domain_fqdn(label or canonical_domain)

    record["name"] = canonical_label
    record["kind"] = ["Domain"]
    record["isTierZero"] = True
    record["label"] = canonical_label
    props["name"] = canonical_label
    props["domain"] = canonical_domain or canonical_label
    record["properties"] = props
    return record


def _select_existing_domain_node_record(
    graph: dict[str, Any] | None,
    *,
    domain: str,
) -> dict[str, Any] | None:
    """Return the best matching persisted Domain node for one domain, if present."""
    if not isinstance(graph, dict):
        return None
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return None

    normalized_domain = str(domain or "").strip().rstrip(".").lower()
    if not normalized_domain:
        return None

    def _matches(node: dict[str, Any]) -> bool:
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        for raw in (
            node.get("label"),
            node.get("name"),
            props.get("name"),
            props.get("domain"),
        ):
            candidate = str(raw or "").strip().rstrip(".").lower()
            if candidate == normalized_domain:
                return True
        return False

    def _score(node: dict[str, Any]) -> tuple[int, int, int]:
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        return (
            1 if str(node.get("objectId") or node.get("objectid") or "").strip() else 0,
            1 if bool(props) else 0,
            1 if bool(node.get("isTierZero") or props.get("isTierZero")) else 0,
        )

    matches: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        if _node_kind(node) != "Domain":
            continue
        if not _matches(node):
            continue
        matches.append((_score(node), node))

    if not matches:
        return None

    matches.sort(key=lambda item: item[0], reverse=True)
    return _canonicalize_domain_node_record(matches[0][1], domain=domain)


def resolve_domain_node_record_for_domain(
    shell: object,
    domain: str,
    *,
    graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve the canonical Domain node record, preferring graph/BH over synthetic.

    Resolution order:
    1. Existing persisted Domain node in the provided graph.
    2. BloodHound domain-node resolver.
    3. Synthetic fallback.
    """
    domain_clean = (domain or "").strip()
    if not domain_clean:
        return {
            "name": "DOMAIN",
            "kind": ["Domain"],
            "label": "DOMAIN",
            "properties": {"name": "DOMAIN", "domain": "DOMAIN"},
            "isTierZero": True,
        }

    existing = _select_existing_domain_node_record(graph, domain=domain_clean)
    if existing:
        return existing

    marked_domain = mark_sensitive(domain_clean, "domain")
    try:
        if hasattr(shell, "_get_graph_service"):
            service = shell._get_graph_service()  # type: ignore[attr-defined]
            if service and hasattr(service, "get_domain_node"):
                node_props = service.get_domain_node(domain_clean)  # type: ignore[attr-defined]
                if isinstance(node_props, dict) and (
                    node_props.get("name") or node_props.get("objectid")
                ):
                    node_record = _canonicalize_domain_node_record(
                        {
                            "name": str(node_props.get("name") or domain_clean),
                            "kind": ["Domain"],
                            "objectId": node_props.get("objectid")
                            or node_props.get("objectId"),
                            "properties": node_props,
                            "isTierZero": True,
                        },
                        domain=domain_clean,
                    )
                    marked_label = mark_sensitive(
                        str(node_record.get("label") or ""), "domain"
                    )
                    print_info_debug(
                        f"[domain_node] resolved from BloodHound for {marked_domain}: label={marked_label}"
                    )
                    return node_record
            print_info_debug(
                f"[domain_node] BloodHound service missing resolver for {marked_domain}; "
                "falling back to synthetic"
            )
        else:
            print_info_debug(
                f"[domain_node] shell has no BloodHound service accessor for {marked_domain}; "
                "falling back to synthetic"
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[domain_node] resolver failed for {marked_domain}; falling back to synthetic: {exc}"
        )

    node_record = _canonicalize_domain_node_record(
        {
            "name": domain_clean,
            "kind": ["Domain"],
            "properties": {"name": domain_clean, "domain": domain_clean},
            "isTierZero": True,
        },
        domain=domain_clean,
    )
    _mark_synthetic_node_record(
        node_record, domain=domain_clean, source="fallback_domain_node"
    )
    return node_record


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

    # Search the MERGED multi-domain graph when the workspace holds more than one
    # domain, so a cross-domain attack-path step's TARGET host (living in a
    # trusted in-scope domain) resolves to its real properties.name/FQDN rather
    # than the best-effort samAccountName fallback. Single-domain: byte-identical.
    graph = _load_attack_graph_for_paths(shell, domain)
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
    from adscan_internal.models.domain import qualify_host_fqdn  # noqa: PLC0415

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
        print_exception(exception=exc)
        fqdn = None

    if not fqdn and target_hostname:
        # ``target_hostname`` may arrive as a short NetBIOS name (netexec parse)
        # or as an already-qualified FQDN (native aiosmb sweep). The centralised
        # qualifier appends the domain only to a short label and self-heals an
        # accidental ``host.domain.domain`` double suffix that otherwise misses
        # the BloodHound node lookup and silently drops the AdminTo edge.
        candidate = qualify_host_fqdn(target_hostname, domain_clean)
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
    from adscan_internal.models.domain import qualify_host_fqdn  # noqa: PLC0415

    domain_clean = str(domain or "").strip()
    ip_clean = str(target_ip or "").strip()
    if not domain_clean or not ip_clean:
        return None, None

    candidate_fqdn: str | None = None
    if target_hostname:
        # Centralised FQDN qualifier: appends the domain only to a short label,
        # leaves an already-qualified FQDN as-is, and self-heals a double suffix.
        candidate_fqdn = qualify_host_fqdn(target_hostname, domain_clean)
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
    notes_extra: dict[str, Any] | None = None,
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
        notes_extra: Optional extra metadata merged into the edge ``notes`` dict
            (e.g. an impersonated principal or the technique used).

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
        if hasattr(shell, "_get_graph_service"):
            service = shell._get_graph_service()  # type: ignore[attr-defined]
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
        if isinstance(notes_extra, dict):
            notes.update(notes_extra)

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
        print_exception(exception=exc)
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
        if hasattr(shell, "_get_graph_service"):
            service = shell._get_graph_service()  # type: ignore[attr-defined]
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
                        {
                            "credential": credential_clean,
                            "credential_type": credential_type,
                        }
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
        print_exception(exception=exc)
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
        print_exception(exception=exc)
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
        print_exception(exception=exc)
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
        if hasattr(shell, "_get_graph_service"):
            service = shell._get_graph_service()  # type: ignore[attr-defined]
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
        print_exception(exception=exc)
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
    vulnerable_dc_labels: list[str] | None = None,
) -> bool:
    """Upsert CVE takeover edges: Domain Users -> CVE -> DC (one edge per vulnerable DC).

    Creates one edge per vulnerable DC computer node so the paths align with
    how BloodHound models these CVEs (Computer targets, not Domain node).
    Falls back to the domain node only when no DC labels are available.

    Args:
        shell: Shell instance used for workspace paths and BloodHound service access.
        domain: Target domain.
        cve: "nopac" or "zerologon" (case-insensitive).
        status: Edge status (default: discovered).
        notes: Optional notes (e.g., affected DC IPs, log path).
        vulnerable_dc_labels: SAM account names / hostnames of vulnerable DCs.
    """
    cve_norm = (cve or "").strip().lower()
    if cve_norm not in {"nopac", "zerologon"}:
        return False

    relation = "NoPac" if cve_norm == "nopac" else "Zerologon"
    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(shell, domain, graph, label="Domain Users")

    dc_labels = [lbl for lbl in (vulnerable_dc_labels or []) if lbl]
    if dc_labels:
        for dc_label in dc_labels:
            dc_id = ensure_computer_node_for_domain(
                shell, domain, graph, principal=dc_label
            )
            upsert_edge(
                graph,
                from_id=entry_id,
                to_id=dc_id,
                relation=relation,
                edge_type="cve_takeover",
                status=status,
                notes=notes,
            )
    else:
        # Fallback: no DC info available — edge to domain node
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
    lookup_domain = (
        _extract_domain_from_principal_label(raw_username)
        or str(domain or "").strip().lower()
    )

    try:
        if hasattr(shell, "_get_graph_service"):
            service = shell._get_graph_service()  # type: ignore[attr-defined]
            resolver = getattr(service, "get_user_node_by_samaccountname", None)
            if callable(resolver):
                node_props = resolver(lookup_domain, user_clean)
                if isinstance(node_props, dict) and (
                    node_props.get("samaccountname") or node_props.get("name")
                ):
                    canonical_domain = lookup_domain.upper()
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
                    marked_domain = mark_sensitive(lookup_domain, "domain")
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
        print_exception(exception=exc)
        marked_domain = mark_sensitive(lookup_domain, "domain")
        marked_user = mark_sensitive(user_clean, "user")
        print_info_debug(
            f"[user_node] resolver failed for {marked_domain} user={marked_user}; falling back to synthetic: {exc}"
        )

    canonical_domain = lookup_domain.upper()
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
    _mark_synthetic_node_record(
        node_record,
        domain=lookup_domain,
        source="fallback_user_node",
    )
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
        if hasattr(shell, "_get_graph_service"):
            service = shell._get_graph_service()  # type: ignore[attr-defined]
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
        print_exception(exception=exc)
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
    entry_label: str | None = None,
) -> bool:
    """Upsert an entry-vector edge for roasting: Entry -> roast_type -> username."""
    roast_type_norm = (roast_type or "").strip().lower()
    relation_map = {
        # Authenticated Users (S-1-5-11) is the collector's SSOT source for
        # authenticated-bind roasting edges; using it makes the execution recorder
        # upsert the collector edge in place instead of inserting a Domain-Users-keyed
        # duplicate.
        "kerberoast": ("Kerberoasting", "user", "Authenticated Users"),
        "asreproast": ("ASREPRoasting", "user", "Authenticated Users"),
        "timeroast": ("Timeroasting", "computer", "ANONYMOUS LOGON"),
    }
    relation_info = relation_map.get(roast_type_norm)
    if relation_info is None:
        return False
    relation, principal_kind, default_entry_label = relation_info
    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(
        shell,
        domain,
        graph,
        label=entry_label or default_entry_label,
    )
    principal_id = ensure_principal_node_for_domain(
        shell,
        domain,
        graph,
        principal=username,
        principal_kind=principal_kind,
    )
    upsert_edge(
        graph,
        from_id=entry_id,
        to_id=principal_id,
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


def upsert_poison_capture_ntlmv2_crack_edge(
    shell: object,
    domain: str,
    *,
    username: str,
    status: str = "success",
    notes: dict[str, Any] | None = None,
) -> bool:
    """Materialize a broadcast-poison → NetNTLMv2 capture → offline-crack edge.

    Records ``ANONYMOUS LOGON -> PoisonCaptureNtlmv2Crack -> <cracked user>`` as
    an entry-vector edge. The source is the unauthenticated-principal node (the
    same ``ANONYMOUS LOGON`` representation used by
    :func:`upsert_ldap_anonymous_bind_entry_edge`) so the edge is classified
    ``UNAUTHENTICATED_PRINCIPAL`` at the source and severity-capped accordingly —
    no credential is held by the attacker.

    This edge is materialized ONLY on crack SUCCESS: the capture on its own is
    the LLMNR/NBT-NS poisoning FINDING, and a NetNTLMv2 response is not usable
    until it is cracked back to the cleartext password. Once cracked, the victim
    user is an owned entry point, so the edge makes that principal a valid start
    for attack-path search (like the anonymous-bind / password-spray entry
    edges). Distinct from the NTLMv1 steps by design — those recover a machine
    NT hash (pass-the-hash capable) and keep their own relations.

    Args:
        shell: Shell instance used for workspace path context.
        domain: Domain the cracked credential belongs to.
        username: sAMAccountName of the user whose NetNTLMv2 was cracked.
        status: Edge status (default ``success`` — this edge only exists once
            the crack has proven a usable credential).
        notes: Optional edge notes (e.g. observed segment / capture metadata).

    Returns:
        True when the edge was recorded, False when the username was empty.
    """
    user_clean = str(username or "").strip()
    if not user_clean:
        return False
    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(
        shell, domain, graph, label="ANONYMOUS LOGON"
    )
    user_id = ensure_user_node_for_domain(shell, domain, graph, username=user_clean)
    upsert_edge(
        graph,
        from_id=entry_id,
        to_id=user_id,
        relation="PoisonCaptureNtlmv2Crack",
        edge_type="entry_vector",
        status=status,
        notes=notes or {},
    )
    save_attack_graph(shell, domain, graph)
    return True


def upsert_ntlmv1_crack_user_edge(
    shell: object,
    domain: str,
    *,
    username: str,
    status: str = "success",
    notes: dict[str, Any] | None = None,
) -> bool:
    """Materialize a wordlist-cracked USER NetNTLMv1 as a ``CrackNTLMv1`` edge.

    Reuses the existing ``CrackNTLMv1`` relation (the catalog entry keeps its
    static ``unsupported`` default for the coercion-relay, machine-targeted
    avenue built by ``ntlmv1_relay_graph_builder``) but records THIS specific
    instance — a captured NetNTLMv1 challenge/response for a USER account,
    recovered by an ordinary wordlist crack — as its own ``ANONYMOUS LOGON ->
    CrackNTLMv1 -> <cracked user>`` entry-vector edge with an executed
    (``success``) status. A per-edge ``success`` status renders as exploited
    regardless of the relation's global catalog classification (see
    ``attack_step_support_registry.classify_relation_support`` and the
    derived-status precedence in this module), so a user-account crack is
    never masked by the machine-account avenue's ``unsupported`` default.

    Call site: ``cli/cracking.py``'s crack-success materialization, mirroring
    :func:`upsert_poison_capture_ntlmv2_crack_edge`. Gate the CALL on
    ``attack_step_catalog.ntlmv1_crack_support_for(account_type) ==
    "supported"`` (via ``captured_credential_policy.classify_principal``) —
    a machine account must never reach this function.

    Args:
        shell: Shell instance used for workspace path context.
        domain: Domain the cracked credential belongs to.
        username: sAMAccountName of the user whose NetNTLMv1 was cracked.
        status: Edge status (default ``success``).
        notes: Optional edge notes (e.g. capture/crack metadata).

    Returns:
        True when the edge was recorded, False when the username was empty.
    """
    user_clean = str(username or "").strip()
    if not user_clean:
        return False
    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(
        shell, domain, graph, label="ANONYMOUS LOGON"
    )
    user_id = ensure_user_node_for_domain(shell, domain, graph, username=user_clean)
    upsert_edge(
        graph,
        from_id=entry_id,
        to_id=user_id,
        relation="CrackNTLMv1",
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
    spray_category: str | None = None,
    status: str = "success",
    entry_label: str = "Domain Users",
) -> bool:
    """Upsert a spraying entry-vector edge: Entry -> spray relation -> principal.

    This records provenance in `attack_graph.json` so attack paths can be
    constructed dynamically from compromised users.

    Args:
        shell: Shell instance used to access the BloodHound service when available.
        domain: Target domain for the graph.
        username: User compromised via spraying.
        password: Password that was accepted for the user.
        spray_type: Human-friendly spray mode label (optional).
        spray_category: Stable internal spray mode key (optional).
        status: Edge status (default: success).
        entry_label: Label for the entry node (default: "Domain Users").

    Returns:
        True when the edge was recorded, False otherwise.
    """
    user_clean = str(username or "").strip()
    if not user_clean:
        return False

    spray_category_clean = str(spray_category or "").strip().lower()
    spray_type_clean = str(spray_type or "").strip().lower()

    relation = "PasswordSpray"
    if spray_category_clean == "computer_pre2k" or spray_type_clean == "computer pre2k":
        relation = "ComputerPre2k"
    elif spray_category_clean in {"useraspass", "useraspass_lower", "useraspass_upper"}:
        relation = "UserAsPass"
    elif (
        spray_category_clean == "blank_password" or spray_type_clean == "blank password"
    ):
        relation = "BlankPassword"

    graph = load_attack_graph(shell, domain)
    effective_entry_label = (
        "Domain Users" if relation == "ComputerPre2k" else entry_label
    )
    entry_id = ensure_entry_node_for_domain(
        shell,
        domain,
        graph,
        label=effective_entry_label or "Domain Users",
    )
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
    if spray_category:
        notes["spray_category"] = str(spray_category)

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
    entry_label: str | None = None,
) -> bool:
    """Update the roasting entry edge status and append wordlist attempt notes.

    This is the canonical way for cracking flows to update the graph without
    relying on any cached "attack path" structures.
    """
    roast_type_norm = (roast_type or "").strip().lower()
    relation_map = {
        # Authenticated Users (S-1-5-11) is the collector's SSOT source for
        # authenticated-bind roasting edges; using it makes the execution recorder
        # upsert the collector edge in place instead of inserting a Domain-Users-keyed
        # duplicate.
        "kerberoast": ("Kerberoasting", "user", "Authenticated Users"),
        "asreproast": ("ASREPRoasting", "user", "Authenticated Users"),
        "timeroast": ("Timeroasting", "computer", "ANONYMOUS LOGON"),
    }
    relation_info = relation_map.get(roast_type_norm)
    if relation_info is None:
        return False
    relation, principal_kind, default_entry_label = relation_info

    graph = load_attack_graph(shell, domain)
    entry_id = ensure_entry_node_for_domain(
        shell,
        domain,
        graph,
        label=entry_label or default_entry_label,
    )
    principal_id = ensure_principal_node_for_domain(
        shell,
        domain,
        graph,
        principal=username,
        principal_kind=principal_kind,
    )

    now = _utc_now_iso()
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if (
            str(edge.get("from") or "") != entry_id
            or str(edge.get("to") or "") != principal_id
            or str(edge.get("relation") or "") != relation
        ):
            continue

        current = str(edge.get("status") or "discovered")
        status_changed = _status_rank(status) > _status_rank(current)
        if status_changed:
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
        to_id=principal_id,
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
            max_depth=ATTACK_PATHS_MAX_DEPTH_USER,
            target="highvalue",
        )
    )


def _find_node_id_by_label(graph: dict[str, Any], label: str) -> str | None:
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return None

    def _quality_score(node: dict[str, Any]) -> int:
        """Prefer well-formed BloodHound-backed nodes over synthetic/unknown ones.

        Security principals (Group/User/Computer/Domain) outrank structural AD
        objects (OU/Container/CertTemplate) when label collides — e.g. an OU
        named "Domain Controllers" must NOT be returned in place of the
        Domain Controllers security group, otherwise edge-status updates land
        on the wrong node and runtime success/failure transitions are lost.
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

    exact = str(label or "").strip().upper()
    if exact:
        exact_matches: list[tuple[int, str]] = []
        for node_id, node in nodes_map.items():
            if not isinstance(node, dict):
                continue
            node_label = str(node.get("label") or "").strip().upper()
            if node_label != exact:
                continue
            exact_matches.append((_quality_score(node), str(node_id)))
        if exact_matches:
            exact_matches.sort(key=lambda x: (-x[0], x[1]))
            return exact_matches[0][1]

    normalized = _normalize_account(label)

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


def _extract_domain_from_principal_label(value: str) -> str:
    """Extract the `domain.tld` suffix from `NAME@DOMAIN` labels."""
    raw = str(value or "").strip()
    if "@" not in raw:
        return ""
    return raw.rsplit("@", 1)[-1].strip().lower()


def _extract_domain_from_node(node: dict[str, Any], *, fallback_domain: str) -> str:
    """Return the effective node domain for membership lookup purposes."""
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    for candidate in (
        props.get("domain"),
        node.get("domain"),
        props.get("name"),
        node.get("label"),
        node.get("name"),
    ):
        text = str(candidate or "").strip()
        if not text:
            continue
        label_domain = _extract_domain_from_principal_label(text)
        if label_domain:
            return label_domain
        if "." in text and "@" not in text:
            return text.lower()
    return str(fallback_domain or "").strip().lower()


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

    if not hasattr(shell, "_get_graph_service"):
        return 0
    service = shell._get_graph_service()  # type: ignore[attr-defined]
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
        elif kind in {"User", "Computer", "Group"}:
            lookup_name = label
            if kind == "User":
                lookup_name = _normalize_account(label)
            elif kind == "Group":
                lookup_name = _extract_group_name_from_bh(label)
            node_record = _resolve_bloodhound_principal_node(
                shell,
                domain,
                label,
                object_id=_extract_node_object_id(node),
                entry_kind=kind.lower(),
                graph=None,
                lookup_name=lookup_name,
            )
            node_props = (
                node_record.get("properties") if isinstance(node_record, dict) else None
            )

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


def _normalize_domain_labels(graph: dict[str, Any]) -> bool:
    """Ensure Domain nodes use a canonical uppercase FQDN label."""
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict):
        return False

    graph_domain = str(graph.get("domain") or "").strip().upper()
    changed = False
    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        if _node_kind(node) != "Domain":
            continue

        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        canonical = _canonical_node_label(node)
        if not canonical and graph_domain:
            canonical = graph_domain
        if not canonical:
            continue

        if str(node.get("label") or "").strip() != canonical:
            node["label"] = canonical
            changed = True

        if str(props.get("name") or "").strip() != canonical:
            props["name"] = canonical
            changed = True

        if graph_domain and str(props.get("domain") or "").strip() != graph_domain:
            props["domain"] = graph_domain
            changed = True

        if node.get("properties") is not props:
            node["properties"] = props

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
    target: str = "highvalue",
    terminal_mode: str = "domain",
) -> list[AttackPath]:
    """Compute maximal paths starting from a specific node."""
    if max_depth <= 0 or not start_node_id:
        return []

    nodes_map = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes_map, dict) or not isinstance(edges, list):
        return []

    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in _iter_runtime_graph_edges(graph):
        if attack_graph_core._is_nontraversable_attack_edge(edge, nodes_map):  # noqa: SLF001
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
        mode = (terminal_mode or "domain").strip().lower()
        if mode == "domain":
            return _node_is_domain(node)
        if mode == "impact":
            return _node_is_impact_high_value(node)
        return _node_is_tier0(node)

    paths: list[AttackPath] = []
    seen_signatures: set[tuple[tuple[str, str, str, str], ...]] = set()

    def emit(acc_steps: list[AttackPathStep]) -> None:
        if not acc_steps:
            return
        if (target == "highvalue" and not is_terminal(acc_steps[-1].to_id)) or (
            target == "lowpriv" and is_terminal(acc_steps[-1].to_id)
        ):
            return
        signature = tuple(
            attack_graph_core.attack_path_step_signature(s) for s in acc_steps
        )
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
        actionable_depth = attack_graph_core._count_actionable_edges(acc_steps)  # noqa: SLF001
        structural_depth = len(acc_steps) - actionable_depth
        if (
            actionable_depth >= max_depth
            or structural_depth >= attack_graph_core._MAX_STRUCTURAL_HOPS  # noqa: SLF001
            or (acc_steps and is_terminal(current))
        ):
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
    from adscan_internal.services.attack_step_support_registry import (
        build_path_priority_key,
    )

    return sorted(records, key=build_path_priority_key)


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
    materialized_artifacts: MaterializedAttackPathArtifacts | None = None,
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
            node_id_by_label=(
                materialized_artifacts.node_id_by_label
                if materialized_artifacts is not None
                else None
            ),
            recursive_groups_by_principal=(
                materialized_artifacts.recursive_groups_by_principal
                if materialized_artifacts is not None
                else None
            ),
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


def _build_snapshot_label_to_node(
    snapshot: dict[str, Any] | None,
    base_graph: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Build a {label: node_dict} index for HV lookups.

    Sources (merged, base_graph wins on conflict):
      1. Membership snapshot nodes  — users and groups with HV properties.
      2. Attack graph nodes         — domain nodes and other targets that the DFS
         uses as terminals; these carry the ``highvalue``/``isTierZero``/
         ``system_tags`` properties that ``_node_is_effectively_high_value`` checks.

    The snapshot alone is insufficient because it only contains user/group
    membership data and never includes domain-level nodes (e.g. ``ESSOS.LOCAL``).
    Without the attack graph, domain terminals are always tagged as pivot.
    """
    result: dict[str, dict[str, Any]] = {}

    # Layer 1: snapshot nodes (users/groups).
    if snapshot:
        snap_nodes = snapshot.get("nodes")
        if isinstance(snap_nodes, dict):
            for node in snap_nodes.values():
                if isinstance(node, dict):
                    label = str(node.get("label") or "").strip()
                    if label:
                        result[label] = node

    # Layer 2: attack graph nodes (domains, computers, CAs, etc.) — override snapshot.
    if base_graph:
        ag_nodes = base_graph.get("nodes")
        if isinstance(ag_nodes, dict):
            for node in ag_nodes.values():
                if isinstance(node, dict):
                    label = str(node.get("label") or "").strip()
                    if label:
                        result[label] = node

    return result


def _trim_trailing_memberof_edges(
    rec: dict[str, Any],
    *,
    label_to_node: dict[str, Any],
    except_hv: bool,
) -> dict[str, Any] | None:
    """Strip trailing MemberOf-to-non-HV edges from a path record.

    Recursively removes trailing (MemberOf, Group) pairs until the last relation
    is not MemberOf, the terminal node is HV (when except_hv=True, matching BH CE
    behaviour where HV terminals are kept), or the path becomes degenerate (< 2 nodes).

    Args:
        rec: Path record dict with ``nodes`` and ``relations``/``rels`` keys.
        label_to_node: Label-to-node index built from snapshot + attack graph.
        except_hv: When True, stop trimming as soon as the terminal node is HV
            (mirrors BH CE ``target="all"`` semantics).

    Returns:
        Trimmed copy of *rec* with updated ``nodes``, ``relations``/``rels``, and
        ``target`` fields, or ``None`` if the path has fewer than 2 nodes after
        trimming (degenerate — discard).
    """
    nodes = list(rec.get("nodes") or [])
    rel_key = "relations" if "relations" in rec else "rels"
    rels = list(rec.get(rel_key) or [])

    while rels:
        last_rel = str(rels[-1]).strip().lower()
        if last_rel != "memberof":
            break
        if except_hv:
            tgt_label = str(nodes[-1]) if nodes else ""
            tgt_node = label_to_node.get(tgt_label) or {}
            if attack_graph_core._node_target_priority_class(tgt_node) != "pivot":  # noqa: SLF001
                break  # HV terminal — stop trimming, keep as-is
        # Remove the last node and last relation.
        nodes = nodes[:-1]
        rels = rels[:-1]

    if len(nodes) < 2:
        return None

    trimmed = dict(rec)
    trimmed["nodes"] = nodes
    trimmed[rel_key] = rels
    trimmed["target"] = nodes[-1]
    # ``terminal_target_label`` is stamped at path-creation time from the
    # pre-trim ``path.target_id``. When we strip trailing MemberOf hops the
    # terminal node changes, so the stamped label is now stale and points at
    # the discarded pivot group (e.g. a CrackNTLMv1 path trimmed back to the DC
    # computer object would still carry the trailing
    # ``DENIED RODC PASSWORD REPLICATION GROUP`` label). Stage-7 classification
    # resolves the target node via ``terminal_target_label`` first, so leaving
    # it stale mislabels the path (compromise_enabler instead of
    # domain_breaker). Reset it to the trimmed terminal label so the classifier
    # resolves the real terminal node.
    if "terminal_target_label" in trimmed:
        trimmed["terminal_target_label"] = nodes[-1]
    return trimmed


def _record_terminal_is_hv(
    rec: dict[str, Any],
    label_to_node: dict[str, Any],
) -> bool:
    """Return True when *rec*'s terminal node is high-value / tier-0.

    Consults the same ``_node_is_effectively_high_value`` predicate used by the
    HV-tag stage (stage 7 in the local pipeline, stage 6 in the BH pipeline) so
    that the containment filter and any UX ordering logic use identical criteria.

    Args:
        rec: Display path record with a ``target`` field.
        label_to_node: Label-to-node index (snapshot + attack graph nodes).

    Returns:
        True if the target node is effectively high-value; False otherwise or
        when the target cannot be resolved.
    """
    tgt_node = label_to_node.get(str(rec.get("target") or "")) or {}
    return (
        attack_graph_core._node_target_priority_class(tgt_node) != "pivot"  # noqa: SLF001
    )


def _record_terminal_is_terminal_target(
    rec: dict[str, Any],
    label_to_node: dict[str, Any],
) -> bool:
    """Return True when *rec*'s terminal should stop path discovery."""
    tgt_node = label_to_node.get(str(rec.get("target") or "")) or {}
    return attack_graph_core._node_is_terminal_target(tgt_node)  # noqa: SLF001


def _annotate_record_target_priority(
    record: dict[str, Any],
    *,
    target_node: dict[str, Any] | None,
    shell: object | None = None,
    domain: str | None = None,
    recursive_groups_by_principal: dict[str, tuple[str, ...]] | None = None,
    ou_contained_tierzero_groups_cache: dict[str, tuple[dict[str, Any], ...]]
    | None = None,
    adcs_available: bool | None = None,
) -> None:
    """Annotate one display record with ADscan-owned target priority fields."""
    node = target_node if isinstance(target_node, dict) else {}
    target_priority_class = attack_graph_core._node_target_priority_class(node)  # noqa: SLF001
    target_priority_rank = attack_graph_core._node_target_priority_rank(node)  # noqa: SLF001
    target_terminal_class = attack_graph_core._node_target_terminal_class(node)  # noqa: SLF001

    effective_terminal = _resolve_effective_principal_terminal_annotation(
        node,
        domain=domain,
        recursive_groups_by_principal=recursive_groups_by_principal,
    )
    if effective_terminal is not None:
        target_terminal_class, target_priority_rank = effective_terminal
    else:
        effective_terminal = _resolve_effective_ou_terminal_annotation(
            node,
            shell=shell,
            domain=domain,
            ou_contained_tierzero_groups_cache=ou_contained_tierzero_groups_cache,
            recursive_groups_by_principal=recursive_groups_by_principal,
        )
        if effective_terminal is not None:
            target_terminal_class, target_priority_rank = effective_terminal

    target_followup_status = _resolve_target_followup_status(
        node,
        target_terminal_class=target_terminal_class,
        domain=domain,
        recursive_groups_by_principal=recursive_groups_by_principal,
        shell=shell,
        ou_contained_tierzero_groups_cache=ou_contained_tierzero_groups_cache,
        adcs_available=adcs_available,
    )

    record["target_priority_class"] = target_priority_class
    record["target_priority_rank"] = target_priority_rank
    record["target_terminal_class"] = target_terminal_class
    record["target_followup_status"] = target_followup_status
    # Domain-object-first ordering within the Domain Compromised tier: a path
    # terminating at the Domain node itself (WriteDACL/GenericAll on the domain)
    # outranks one terminating at a direct-compromise principal (DA/DCs). The
    # sort key reads this flag right after terminal_class. ("Los que acaban en
    # el objeto dominio van primero SIEMPRE.")
    record["target_is_domain_object"] = (
        str(node.get("kind") or "").strip().lower() == "domain"
    )
    record["is_tier_zero"] = target_priority_class == "tierzero"
    record["target_is_high_value"] = target_priority_class in {"tierzero", "highvalue"}
    _annotate_effective_target_basis(
        record,
        node=node,
        shell=shell,
        domain=domain,
        recursive_groups_by_principal=recursive_groups_by_principal,
        ou_contained_tierzero_groups_cache=ou_contained_tierzero_groups_cache,
    )


def _resolve_effective_principal_terminal_annotation(
    node: dict[str, Any],
    *,
    domain: str | None,
    recursive_groups_by_principal: dict[str, tuple[str, ...]] | None,
) -> tuple[str, int] | None:
    """Return effective terminal semantics for a principal via recursive memberships."""
    if not isinstance(node, dict) or not recursive_groups_by_principal or not domain:
        return None

    base_terminal_class = attack_graph_core._node_target_terminal_class(node)  # noqa: SLF001
    if base_terminal_class != "direct_compromise":
        return None

    kind = attack_paths_core._node_kind(node)  # noqa: SLF001
    if kind not in {"User", "Computer"}:
        return None

    canonical_label = attack_paths_core._canonical_membership_label(  # noqa: SLF001
        domain,
        attack_paths_core._canonical_node_label(node),  # noqa: SLF001
    )
    if not canonical_label:
        return None

    recursive_groups = recursive_groups_by_principal.get(canonical_label) or ()
    if not recursive_groups:
        return None

    membership = classify_privileged_membership(group_names=recursive_groups)
    decision = resolve_privileged_followup_decision(membership)

    if any(
        (
            membership.domain_admin,
            membership.administrators,
            membership.cert_publishers,
            membership.key_admins,
            membership.enterprise_key_admins,
        )
    ):
        return None

    if membership.backup_operators:
        return ("followup_terminal", 20)
    if membership.dns_admins:
        return ("followup_terminal", 30)
    if membership.account_operators:
        return ("graph_extension", 10)
    if any(
        (
            membership.exchange_windows_permissions,
            membership.exchange_trusted_subsystem,
        )
    ):
        return ("graph_extension", 15)
    if decision.future_followup_keys:
        return ("future_followup", 31)
    if decision.dependency_only_keys:
        return ("dependency_only", 32)
    return None


def _resolve_effective_principal_membership(
    node: dict[str, Any],
    *,
    domain: str | None,
    recursive_groups_by_principal: dict[str, tuple[str, ...]] | None,
):
    """Return recursive privileged membership for a final principal target."""
    if not isinstance(node, dict) or not recursive_groups_by_principal or not domain:
        return None

    kind = attack_paths_core._node_kind(node)  # noqa: SLF001
    if kind not in {"User", "Computer"}:
        return None

    canonical_label = attack_paths_core._canonical_membership_label(  # noqa: SLF001
        domain,
        attack_paths_core._canonical_node_label(node),  # noqa: SLF001
    )
    if not canonical_label:
        return None

    recursive_groups = recursive_groups_by_principal.get(canonical_label) or ()
    if not recursive_groups:
        return None
    return classify_privileged_membership(group_names=recursive_groups)


_DIRECT_GROUP_REASON_DISPLAY_NAMES = {
    "administrators": "Administrators",
    "cert publishers": "Cert Publishers",
    "domain admins": "Domain Admins",
    "domain controllers": "Domain Controllers",
    "enterprise admins": "Enterprise Admins",
    "enterprise key admins": "Enterprise Key Admins",
    "incoming forest trust builders": "Incoming Forest Trust Builders",
    "key admins": "Key Admins",
    "read-only domain controllers": "Read-Only Domain Controllers",
    "schema admins": "Schema Admins",
}

_EFFECTIVE_GROUP_REASON_DISPLAY_NAMES = {
    "account operators": "Account Operators",
    "backup operators": "Backup Operators",
    "cert publishers": "Cert Publishers",
    "cryptographic operators": "Cryptographic Operators",
    "distributed com users": "Distributed COM Users",
    "dnsadmins": "DNSAdmins",
    "domain admins": "Domain Admins",
    "enterprise key admins": "Enterprise Key Admins",
    "exchange trusted subsystem": "Exchange Trusted Subsystem",
    "exchange windows permissions": "Exchange Windows Permissions",
    "incoming forest trust builders": "Incoming Forest Trust Builders",
    "key admins": "Key Admins",
    "performance log users": "Performance Log Users",
}

_SYNTHETIC_GROUP_REASON_SIDS = {
    "account operators": "S-1-5-32-548",
    "administrators": "S-1-5-32-544",
    "backup operators": "S-1-5-32-551",
    "cert publishers": "S-1-5-21-0-0-0-517",
    "cryptographic operators": "S-1-5-21-0-0-0-569",
    "distributed com users": "S-1-5-32-562",
    "dnsadmins": "S-1-5-21-0-0-0-1101",
    "domain admins": "S-1-5-21-0-0-0-512",
    "domain controllers": "S-1-5-21-0-0-0-516",
    "enterprise admins": "S-1-5-21-0-0-0-519",
    "enterprise key admins": "S-1-5-21-0-0-0-527",
    "exchange trusted subsystem": "S-1-5-21-0-0-0-1119",
    "exchange windows permissions": "S-1-5-21-0-0-0-1121",
    "incoming forest trust builders": "S-1-5-32-557",
    "key admins": "S-1-5-21-0-0-0-526",
    "performance log users": "S-1-5-32-559",
    "read-only domain controllers": "S-1-5-21-0-0-0-521",
    "schema admins": "S-1-5-21-0-0-0-518",
}


def _normalize_effective_target_basis_label(value: str) -> str:
    """Return a stable normalized label used to dedupe reason metadata."""
    return normalize_group_name(value)


def _display_effective_target_basis_label(value: str) -> str:
    """Return one compact human-readable label for target-basis rendering."""
    raw = str(value or "").strip()
    if not raw:
        return "Unknown"
    normalized = _normalize_effective_target_basis_label(raw)
    if normalized in _DIRECT_GROUP_REASON_DISPLAY_NAMES:
        return _DIRECT_GROUP_REASON_DISPLAY_NAMES[normalized]
    if normalized in _EFFECTIVE_GROUP_REASON_DISPLAY_NAMES:
        return _EFFECTIVE_GROUP_REASON_DISPLAY_NAMES[normalized]
    return raw


def _build_effective_target_basis_record(
    *,
    basis_kind: str,
    target_kind: str,
    target_label: str,
    terminal_class: str,
    priority_rank: int,
) -> dict[str, Any]:
    """Return one normalized effective-target-basis explanation record."""
    display_label = _display_effective_target_basis_label(target_label)
    return {
        "basis_kind": basis_kind,
        "target_kind": str(target_kind or "").strip(),
        "target_label": display_label,
        "normalized_target_label": _normalize_effective_target_basis_label(
            display_label
        ),
        "terminal_class": str(terminal_class or "pivot").strip().lower(),
        "priority_rank": int(priority_rank),
    }


def _build_effective_target_basis_record_from_node(
    node: dict[str, Any],
    *,
    basis_kind: str,
) -> dict[str, Any] | None:
    """Return explanation metadata for one node when it carries target semantics."""
    if not isinstance(node, dict):
        return None
    target_kind = attack_paths_core._node_kind(node)  # noqa: SLF001
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    target_label = str(props.get("name") or node.get("label") or "").strip()
    if not target_label:
        return None
    return _build_effective_target_basis_record(
        basis_kind=basis_kind,
        target_kind=target_kind,
        target_label=target_label,
        terminal_class=attack_graph_core._node_target_terminal_class(node),  # noqa: SLF001
        priority_rank=attack_graph_core._node_target_priority_rank(node),  # noqa: SLF001
    )


def _build_synthetic_tierzero_group_node(group_label: str) -> dict[str, Any] | None:
    """Return a synthetic Tier Zero group node for one recognized membership label."""
    raw = str(group_label or "").strip()
    if not raw:
        return None

    normalized = normalize_group_name(raw)
    is_recognized = normalized in _DIRECT_GROUP_REASON_DISPLAY_NAMES or any(
        (
            is_graph_extension_group(name=raw),
            is_followup_terminal_group(name=raw),
            is_future_followup_tier_zero_group(name=raw),
            is_dependency_only_tier_zero_group(name=raw),
            normalized in _EFFECTIVE_GROUP_REASON_DISPLAY_NAMES,
        )
    )
    if not is_recognized:
        return None

    return {
        "kind": "Group",
        "label": raw,
        "isTierZero": True,
        "properties": {
            "name": raw,
            "isTierZero": True,
            "objectid": _SYNTHETIC_GROUP_REASON_SIDS.get(normalized, ""),
        },
    }


def _dedupe_effective_target_basis_records(
    records: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return records deduped by basis kind, label, terminal class, and rank."""
    deduped: OrderedDict[tuple[str, str, str, int], dict[str, Any]] = OrderedDict()
    for record in records:
        if not isinstance(record, dict):
            continue
        basis_kind = str(record.get("basis_kind") or "").strip().lower()
        normalized_target_label = str(
            record.get("normalized_target_label")
            or _normalize_effective_target_basis_label(
                str(record.get("target_label") or "")
            )
        ).strip()
        terminal_class = str(record.get("terminal_class") or "pivot").strip().lower()
        try:
            priority_rank = int(record.get("priority_rank", 100))
        except (TypeError, ValueError):
            priority_rank = 100
        if not basis_kind or not normalized_target_label:
            continue
        key = (
            basis_kind,
            normalized_target_label,
            terminal_class,
            priority_rank,
        )
        deduped.setdefault(key, record)
    return list(deduped.values())


def _effective_target_basis_sort_key(
    record: dict[str, Any],
) -> tuple[int, int, int, str]:
    """Return one deterministic ordering key for effective target basis records."""
    terminal_class = str(record.get("terminal_class") or "pivot").strip().lower()
    try:
        priority_rank = int(record.get("priority_rank", 100))
    except (TypeError, ValueError):
        priority_rank = 100
    direct_bias = 0 if terminal_class == "direct_compromise" else 1
    label = str(record.get("target_label") or "").casefold()
    privileged_order = privileged_followup_order_for_group_name(
        str(record.get("target_label") or "")
    )
    if privileged_order is None:
        privileged_order = 999
    return (direct_bias, privileged_order, priority_rank, label)


def _select_effective_target_basis_records(
    records: Iterable[dict[str, Any]],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Return primary + extra explanation records using stable premium ordering."""
    deduped = _dedupe_effective_target_basis_records(records)
    if not deduped:
        return None, []
    ordered = sorted(deduped, key=_effective_target_basis_sort_key)
    return ordered[0], ordered[1:]


def _collect_effective_principal_basis_records(
    node: dict[str, Any],
    *,
    domain: str | None,
    recursive_groups_by_principal: dict[str, tuple[str, ...]] | None,
) -> list[dict[str, Any]]:
    """Return normalized explanation records for a principal target."""
    if not isinstance(node, dict) or not recursive_groups_by_principal or not domain:
        return []

    kind = attack_paths_core._node_kind(node)  # noqa: SLF001
    if kind not in {"User", "Computer"}:
        return []

    canonical_label = attack_paths_core._canonical_membership_label(  # noqa: SLF001
        domain,
        attack_paths_core._canonical_node_label(node),  # noqa: SLF001
    )
    if not canonical_label:
        return []

    recursive_groups = recursive_groups_by_principal.get(canonical_label) or ()
    if not recursive_groups:
        return []

    records: list[dict[str, Any]] = []
    for recursive_group in recursive_groups:
        synthetic_group = _build_synthetic_tierzero_group_node(
            str(recursive_group or "")
        )
        if synthetic_group is None:
            continue
        record = _build_effective_target_basis_record_from_node(
            synthetic_group,
            basis_kind="member_of",
        )
        if record is not None:
            records.append(record)
    return _dedupe_effective_target_basis_records(records)


def _resolve_effective_contained_object_annotation(
    node: dict[str, Any],
    *,
    domain: str | None,
    recursive_groups_by_principal: dict[str, tuple[str, ...]] | None,
) -> tuple[str, int]:
    """Return effective terminal semantics for one contained Tier Zero OU object."""
    effective_terminal = _resolve_effective_principal_terminal_annotation(
        node,
        domain=domain,
        recursive_groups_by_principal=recursive_groups_by_principal,
    )
    if effective_terminal is not None:
        return effective_terminal
    return (
        attack_graph_core._node_target_terminal_class(node),  # noqa: SLF001
        attack_graph_core._node_target_priority_rank(node),  # noqa: SLF001
    )


def _extract_node_distinguished_name(node: dict[str, Any]) -> str:
    """Return one normalized distinguished name for a graph node when present."""
    if not isinstance(node, dict):
        return ""
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    return str(
        props.get("distinguishedname")
        or props.get("distinguishedName")
        or node.get("distinguishedname")
        or node.get("distinguishedName")
        or ""
    ).strip()


def _load_ou_contained_tierzero_objects(
    shell: object,
    *,
    domain: str,
    ou_distinguished_name: str,
) -> tuple[dict[str, Any], ...]:
    """Return best-effort tier-zero objects contained inside one OU via BloodHound."""
    domain_clean = str(domain or "").strip()
    ou_dn = str(ou_distinguished_name or "").strip()
    if not domain_clean or not ou_dn or not hasattr(shell, "_get_graph_service"):
        return ()
    try:
        service = shell._get_graph_service()  # type: ignore[attr-defined]
        get_objects = getattr(service, "get_tierzero_objects_in_ou", None)
        if not callable(get_objects):
            return ()
        rows = get_objects(domain_clean, ou_dn)
        if not rows:
            return ()

        objects: list[dict[str, Any]] = []
        for row in rows:
            node_data = row
            props = (
                node_data.get("properties")
                if isinstance(node_data.get("properties"), dict)
                else {}
            )
            labels = node_data.get("kinds") or node_data.get("labels")
            node_kind = ""
            if isinstance(labels, list):
                for label in labels:
                    label_clean = str(label or "").strip()
                    if label_clean in {"Group", "User", "Computer"}:
                        node_kind = label_clean
                        break
            if not node_kind:
                node_kind = str(node_data.get("kind") or "").strip()
            name = str(
                props.get("name")
                or node_data.get("name")
                or node_data.get("label")
                or ""
            ).strip()
            objectid = str(
                props.get("objectid")
                or node_data.get("objectid")
                or props.get("objectId")
                or node_data.get("objectId")
                or node_data.get("id")
                or ""
            ).strip()
            distinguishedname = str(
                props.get("distinguishedname")
                or node_data.get("distinguishedname")
                or props.get("distinguishedName")
                or node_data.get("distinguishedName")
                or ""
            ).strip()
            if not node_kind or not any((name, objectid, distinguishedname)):
                continue
            is_tier_zero = bool(
                node_data.get("isTierZero")
                or props.get("isTierZero")
                or node_data.get("istierzero")
                or props.get("istierzero")
                or node_data.get("highvalue")
                or props.get("highvalue")
                or "admin_tier_0" in str(node_data.get("system_tags") or "")
                or "admin_tier_0" in str(props.get("system_tags") or "")
            )
            highvalue = bool(
                node_data.get("highvalue")
                or props.get("highvalue")
                or "admin_tier_0" in str(node_data.get("system_tags") or "")
                or "admin_tier_0" in str(props.get("system_tags") or "")
            )
            objects.append(
                {
                    "kind": node_kind,
                    "label": name or objectid or distinguishedname,
                    "isTierZero": is_tier_zero,
                    "highvalue": highvalue,
                    "properties": {
                        "name": name or objectid or distinguishedname,
                        "objectid": objectid,
                        "distinguishedname": distinguishedname,
                        "isTierZero": is_tier_zero,
                        "highvalue": highvalue,
                    },
                }
            )
        return tuple(objects)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ()


def _collect_effective_ou_basis_records(
    node: dict[str, Any],
    *,
    shell: object | None,
    domain: str | None,
    ou_contained_tierzero_groups_cache: dict[str, tuple[dict[str, Any], ...]] | None,
    recursive_groups_by_principal: dict[str, tuple[str, ...]] | None = None,
) -> list[dict[str, Any]]:
    """Return normalized explanation records for a Tier Zero OU target."""
    if not isinstance(node, dict) or shell is None or not domain:
        return []
    if attack_paths_core._node_kind(node) != "OU":  # noqa: SLF001
        return []

    distinguished_name = _extract_node_distinguished_name(node)
    if not distinguished_name:
        return []

    cache_key = distinguished_name.casefold()
    contained_objects = (
        ou_contained_tierzero_groups_cache.get(cache_key)
        if isinstance(ou_contained_tierzero_groups_cache, dict)
        else None
    )
    if contained_objects is None:
        contained_objects = _load_ou_contained_tierzero_objects(
            shell,
            domain=domain,
            ou_distinguished_name=distinguished_name,
        )
        if isinstance(ou_contained_tierzero_groups_cache, dict):
            ou_contained_tierzero_groups_cache[cache_key] = contained_objects

    if not contained_objects:
        return []

    records: list[dict[str, Any]] = []
    for contained_node in contained_objects:
        contained_kind = attack_paths_core._node_kind(contained_node)  # noqa: SLF001
        if contained_kind in {"User", "Computer"}:
            principal_records = _collect_effective_principal_basis_records(
                contained_node,
                domain=domain,
                recursive_groups_by_principal=recursive_groups_by_principal,
            )
            if principal_records:
                for principal_record in principal_records:
                    records.append(
                        {
                            **principal_record,
                            "basis_kind": "contains",
                        }
                    )
                continue

        contained_record = _build_effective_target_basis_record_from_node(
            contained_node,
            basis_kind="contains",
        )
        if contained_record is not None:
            records.append(contained_record)
    return _dedupe_effective_target_basis_records(records)


def _annotate_effective_target_basis(
    record: dict[str, Any],
    *,
    node: dict[str, Any],
    shell: object | None,
    domain: str | None,
    recursive_groups_by_principal: dict[str, tuple[str, ...]] | None,
    ou_contained_tierzero_groups_cache: dict[str, tuple[dict[str, Any], ...]] | None,
) -> None:
    """Annotate one attack-path record with explainable effective-target metadata."""
    basis_records: list[dict[str, Any]] = []
    kind = attack_paths_core._node_kind(node)  # noqa: SLF001
    if kind in {"User", "Computer"}:
        basis_records = _collect_effective_principal_basis_records(
            node,
            domain=domain,
            recursive_groups_by_principal=recursive_groups_by_principal,
        )
    elif kind == "OU":
        basis_records = _collect_effective_ou_basis_records(
            node,
            shell=shell,
            domain=domain,
            ou_contained_tierzero_groups_cache=ou_contained_tierzero_groups_cache,
            recursive_groups_by_principal=recursive_groups_by_principal,
        )

    primary_record, extra_records = _select_effective_target_basis_records(
        basis_records
    )
    record["effective_target_basis_kind"] = (
        str(primary_record.get("basis_kind") or "").strip().lower()
        if isinstance(primary_record, dict)
        else ""
    )
    record["effective_target_basis_primary"] = primary_record
    record["effective_target_basis_extras"] = extra_records
    record["effective_target_basis_count"] = len(basis_records)


def _resolve_effective_ou_terminal_annotation(
    node: dict[str, Any],
    *,
    shell: object | None,
    domain: str | None,
    ou_contained_tierzero_groups_cache: dict[str, tuple[dict[str, Any], ...]] | None,
    recursive_groups_by_principal: dict[str, tuple[str, ...]] | None = None,
) -> tuple[str, int] | None:
    """Return effective terminal semantics for a Tier Zero OU via contained objects."""
    if not isinstance(node, dict) or shell is None or not domain:
        return None
    base_terminal_class = attack_graph_core._node_target_terminal_class(node)  # noqa: SLF001
    if base_terminal_class != "direct_compromise":
        return None
    if attack_paths_core._node_kind(node) != "OU":  # noqa: SLF001
        return None

    distinguished_name = _extract_node_distinguished_name(node)
    if not distinguished_name:
        return None

    cache_key = distinguished_name.casefold()
    cached_groups = (
        ou_contained_tierzero_groups_cache.get(cache_key)
        if isinstance(ou_contained_tierzero_groups_cache, dict)
        else None
    )
    if cached_groups is None:
        cached_groups = _load_ou_contained_tierzero_objects(
            shell,
            domain=domain,
            ou_distinguished_name=distinguished_name,
        )
        if isinstance(ou_contained_tierzero_groups_cache, dict):
            ou_contained_tierzero_groups_cache[cache_key] = cached_groups

    if not cached_groups:
        return None

    candidates: list[tuple[str, int]] = []
    for group_node in cached_groups:
        terminal_class, rank = _resolve_effective_contained_object_annotation(
            group_node,
            domain=domain,
            recursive_groups_by_principal=recursive_groups_by_principal,
        )
        if terminal_class == "direct_compromise":
            return None
        if terminal_class in {
            "followup_terminal",
            "graph_extension",
            "future_followup",
            "dependency_only",
        }:
            candidates.append((terminal_class, rank))

    if not candidates:
        return None
    return min(candidates, key=lambda item: item[1])


def _resolve_target_followup_status(
    node: dict[str, Any],
    *,
    target_terminal_class: str,
    domain: str | None,
    recursive_groups_by_principal: dict[str, tuple[str, ...]] | None,
    shell: object | None,
    ou_contained_tierzero_groups_cache: dict[str, tuple[dict[str, Any], ...]] | None,
    adcs_available: bool | None,
) -> str:
    """Return ADscan execution readiness for one terminal target.

    This is intentionally separate from ``target_terminal_class``:
    - terminal class = what the target means in the graph
    - followup status = how actionable that target is in ADscan today
    """
    terminal = str(target_terminal_class or "pivot").strip().lower()
    if not isinstance(node, dict):
        return "unavailable"

    effective_membership = _resolve_effective_principal_membership(
        node,
        domain=domain,
        recursive_groups_by_principal=recursive_groups_by_principal,
    )

    if effective_membership is not None:
        if effective_membership.dns_admins:
            return "unsupported"
        if any(
            (
                effective_membership.account_operators,
                effective_membership.exchange_windows_permissions,
                effective_membership.exchange_trusted_subsystem,
                effective_membership.backup_operators,
            )
        ):
            return "theoretical"
        decision = resolve_privileged_followup_decision(
            effective_membership,
            adcs_available=adcs_available,
        )
        if decision.future_followup_keys:
            return "unsupported"
        if decision.dependency_only_keys:
            return "unavailable"
        if is_adcs_tier_zero_group(node) and adcs_available is False:
            return "unavailable"

    if (
        isinstance(node, dict)
        and shell is not None
        and attack_paths_core._node_kind(node) == "OU"  # noqa: SLF001
    ):
        effective_terminal = _resolve_effective_ou_terminal_annotation(
            node,
            shell=shell,
            domain=domain,
            ou_contained_tierzero_groups_cache=ou_contained_tierzero_groups_cache,
            recursive_groups_by_principal=recursive_groups_by_principal,
        )
        if effective_terminal is not None:
            effective_terminal_class, _ = effective_terminal
            if effective_terminal_class == "graph_extension":
                return "theoretical"
            if effective_terminal_class == "followup_terminal":
                distinguished_name = _extract_node_distinguished_name(node)
                cache_key = distinguished_name.casefold()
                contained_groups = (
                    ou_contained_tierzero_groups_cache.get(cache_key)
                    if isinstance(ou_contained_tierzero_groups_cache, dict)
                    else ()
                ) or ()
                for group_node in contained_groups:
                    contained_terminal_class, _ = (
                        _resolve_effective_contained_object_annotation(
                            group_node,
                            domain=domain,
                            recursive_groups_by_principal=recursive_groups_by_principal,
                        )
                    )
                    if contained_terminal_class != "followup_terminal":
                        continue
                    membership = _resolve_effective_principal_membership(
                        group_node,
                        domain=domain,
                        recursive_groups_by_principal=recursive_groups_by_principal,
                    )
                    if membership is None:
                        sid_upper, _ = attack_graph_core._extract_node_sid_and_rid(
                            group_node
                        )  # noqa: SLF001
                        props = (
                            group_node.get("properties")
                            if isinstance(group_node.get("properties"), dict)
                            else {}
                        )
                        group_name = str(
                            props.get("name") or group_node.get("label") or ""
                        )
                        membership = classify_privileged_membership(
                            group_sids=[sid_upper],
                            group_names=[group_name],
                        )
                    if membership.dns_admins:
                        return "unsupported"
                return "theoretical"
            if effective_terminal_class == "future_followup":
                return "unsupported"
            if effective_terminal_class == "dependency_only":
                return "unavailable"

    if terminal == "direct_compromise":
        if is_adcs_tier_zero_group(node) and adcs_available is False:
            return "unavailable"
        return "actionable"
    if terminal == "followup_terminal":
        sid_upper, _ = attack_graph_core._extract_node_sid_and_rid(node)  # noqa: SLF001
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        group_name = str(props.get("name") or node.get("label") or "")
        membership = classify_privileged_membership(
            group_sids=[sid_upper], group_names=[group_name]
        )
        if membership.dns_admins:
            return "unsupported"
        return "theoretical"
    if terminal == "graph_extension":
        return "theoretical"
    if terminal == "future_followup":
        return "unsupported"
    if terminal == "dependency_only":
        return "unavailable"
    return "unavailable"


def _apply_local_postprocessing_pipeline(
    records: list[dict[str, Any]],
    *,
    shell: object,
    domain: str,
    scope: str,
    target: str,
    snapshot: dict[str, Any] | None,
    principal_count: int = 1,
    owned_labels: frozenset[str] | None = None,
    allow_owned_terminal_target: bool = False,
    target_mode: str = "object",
    display_friendly: bool | None = None,
    keep_longest: bool = False,
    runtime_graph: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Apply the shared post-processing pipeline to local DFS results.


    Pipeline stages:
        1.  Debug log raw output
        2.  terminal-MemberOf filter + trim (target=all/lowpriv; mirrors BH CE Cypher filter)
        2b. owned-terminal filter — after trim (terminals may change), before minimize
        3.  ADCS-dependent terminal filter
        4.  minimize_display_paths (redundant_memberof, repeated_labels)
        5.  Safety-net dedup (exact key)
        6.  apply_affected_user_metadata
        7.  filter_contained_paths (HV-aware keep_shortest or keep_longest by scope)
        8.  target_is_high_value tagging via snapshot nodes

    Stage ordering rationale: BH CE applies the non-terminal MemberOf filter at the Cypher
    level (before any Python post-processing). In local we mirror this by running it as the
    first Python stage — before minimize — so redundant_memberof cannot strip a trailing
    MemberOf edge and hide paths that should have been filtered.
    """
    _is_multi = principal_count > 1
    _target_mode_norm = str(target_mode or "object").strip().lower()

    # ``display_friendly`` controls UX-oriented post-processing — independent
    # of the target_mode discriminator.  Two behaviours toggle on it:
    #   - ``leading_memberof``: stripping the owned-user MemberOf prefix gives
    #     a cleaner display row but loses the executing principal — fine for
    #     the user-facing attack-paths panel, harmful for programmatic
    #     follow-up checks that need to know who runs each step.
    #   - ``contained_filter`` policy: ``keep_longest`` without
    #     ``preserve_prefix_paths`` collapses sub-paths into the longest kill
    #     chain — compact for display, but drops paths to specific target
    #     nodes when a longer extension exists.
    #
    # When unset, derive a sensible default: ``"object"`` mode is for
    # programmatic object-targeted queries (preserve everything), every other
    # mode is for the display panel (apply UX optimisations).  Existing
    # callers that pass ``target_mode="domain"`` get the legacy behaviour
    # automatically; new callers can opt out explicitly.
    if display_friendly is None:
        display_friendly = _target_mode_norm != "object"

    # Build label-to-node index once — reused by stage 2 (terminal MemberOf) and stage 7 (HV tag).
    # Must include attack graph nodes (domains, computers, CAs) because the membership snapshot
    # only carries user/group data; domain terminals like ESSOS.LOCAL are only in the attack graph.
    _base_graph = _load_attack_graph_for_paths(shell, domain)
    _label_to_node = _build_snapshot_label_to_node(snapshot, base_graph=_base_graph)
    _recursive_groups_by_principal = (
        _build_recursive_membership_closure(domain, snapshot) if snapshot else None
    )

    # Surface pipeline progress (stage + counts + timing) to any registered
    # observer. No-op when none is registered — the compute is unchanged; see
    # ``attack_path_progress``. Record the raw path count and graph size before
    # any filtering so the progress panel and the ``attack_path_compute_performance``
    # telemetry event both start from the true totals.
    _base_nodes = _base_graph.get("nodes") if isinstance(_base_graph, dict) else None
    _base_edges = _base_graph.get("edges") if isinstance(_base_graph, dict) else None
    _base_nodes_count = len(_base_nodes) if isinstance(_base_nodes, (list, dict)) else 0
    _base_edges_count = len(_base_edges) if isinstance(_base_edges, (list, dict)) else 0
    attack_path_progress.notify_graph_size(_base_nodes_count, _base_edges_count)
    attack_path_progress.notify_stage("raw", len(records))

    # Stage B of the memory gate — now that the DFS is done and ``raw_paths`` is
    # known (the term that most often blows the budget), project the FULL peak and
    # ABORT before the memory-heavy decoration/ordering stages below run. The DFS
    # left RSS flat; those stages are where it spikes. Aborting here saves both the
    # remaining CPU and the fatal allocation. A declared abort propagates to
    # get_attack_path_summaries, which records the coverage declaration.
    _gate_attack_path_memory_post_dfs(
        shell=shell,
        domain=domain,
        nodes=_base_nodes_count,
        edges=_base_edges_count,
        raw_paths=len(records),
        scope=scope,
        # For owned/user/principals scope the per-path blast radius is bounded by
        # the START-principal count, NOT the domain-wide enabled count — see
        # _estimate_affected_count_for_gate. ``principal_count`` is exactly that
        # start set size here (1 for owned-single/user, N for the principals set;
        # domain scope passes the sentinel 2 and ignores this value).
        start_principal_count=principal_count,
    )

    # Log scope / rule matrix (mirrors BH CE pipeline header).
    _apply_leading = display_friendly and (
        scope == "domain" or (scope in {"owned", "principals"} and _is_multi)
    )
    _minimize_rules = "redundant_memberof + repeated_labels" + (
        " + leading_memberof" if _apply_leading else ""
    )
    if scope == "domain":
        _scope_filter = "filter_contained_paths[keep_longest]"
    elif scope in {"owned", "principals"} and _is_multi:
        _scope_filter = "filter_contained_paths[keep_shortest]"
    else:
        _scope_filter = "none (single principal)"
    print_info_debug(
        f"[local-pipeline] scope={scope!r} principal_count={principal_count} → "
        f"minimize: [{_minimize_rules}] | scope-filter: [{_scope_filter}] | "
        f"dedup: [exact key safety-net, all scopes]"
    )

    # Per-stage wall-clock so the aggregate ``post=…`` (logged by the caller) can
    # be attributed to the stage that actually spends it. Always on under
    # --debug (one monotonic() delta per stage; negligible cost). On the dense
    # Exchange-ACL graphs that explode to tens of thousands of paths, the
    # post-processing — minimize (O(L²) rewrites) and the contained /
    # prefix-dominated filters (O(L²) per path) — dominates total compute, so
    # this breakdown is what tells you which stage to optimise.
    _stage_mark = [time.monotonic()]

    def _stage_done(label: str, current_records: list[dict[str, Any]]) -> None:
        now = time.monotonic()
        print_info_debug(
            f"[local-pipeline] stage {label}: {now - _stage_mark[0]:.3f}s "
            f"(records={len(current_records)})"
        )
        _stage_mark[0] = now
        # Surface the stage boundary to the progress observer (no-op when none
        # is registered). This is the same seam the debug log uses — it does not
        # alter the records or the compute.
        attack_path_progress.notify_stage(label, len(current_records))

    scope_filtered_records: list[dict[str, Any]] = []
    scope_terminal_removed = 0
    for rec in records:
        node_labels = rec.get("nodes") if isinstance(rec.get("nodes"), list) else []
        terminal_label = str(
            rec.get("target") or (node_labels[-1] if node_labels else "") or ""
        ).strip()
        terminal_node = _label_to_node.get(terminal_label)
        if _is_collectable_computers_scope_node(terminal_node):
            scope_terminal_removed += 1
            continue
        scope_filtered_records.append(rec)
    if scope_terminal_removed:
        print_info_debug(
            f"[local-pipeline] collectable-computers scope filter: "
            f"removed {scope_terminal_removed} internal scope-terminal path(s)"
        )
    records = scope_filtered_records

    _maybe_print_attack_paths_summary_debug(
        domain, records, stage_label="1/6 · raw local-dfs"
    )
    _stage_done("input+scope-filter", records)

    # Stage 2: Non-terminal MemberOf filter — mirrors BH CE _build_non_terminal_memberof_filter.
    #   Runs BEFORE minimize so redundant_memberof cannot strip a trailing MemberOf and hide
    #   paths that should be filtered.
    #   target="highvalue": skip — terminal is already constrained to HV by DFS, filter N/A.
    #   target="all":       filter paths ending in MemberOf UNLESS terminal node is HV/tier-0.
    #   target="lowpriv":   filter all paths ending in MemberOf (no exceptions).
    # Rationale: a path ending KERBEROAST → USER → MemberOf → NIGHT WATCH adds no attack value;
    # MemberOf is a property of the compromised principal, not an actionable next step.
    if target in {"all", "lowpriv"}:
        _except_hv_terminal = target == "all"
        _terminal_mo_trimmed = 0
        _terminal_mo_discarded = 0
        _terminal_mo_kept: list[dict[str, Any]] = []
        _terminal_mo_discarded_debug = attack_paths_core.SampledDebugLogger(
            prefix="[local-pipeline]",
            summary_label="terminal-memberof discarded",
        )
        _terminal_mo_trimmed_debug = attack_paths_core.SampledDebugLogger(
            prefix="[local-pipeline]",
            summary_label="terminal-memberof trimmed",
        )
        for rec in records:
            rels = rec.get("relations") or rec.get("rels") or []
            last_rel = str(rels[-1] if rels else "").strip().lower()
            if last_rel != "memberof":
                _terminal_mo_kept.append(rec)
                continue
            # Path ends in MemberOf. If HV terminal and except_hv=True, keep as-is.
            if _except_hv_terminal:
                tgt_label = str(rec.get("target") or "")
                tgt_node = _label_to_node.get(tgt_label) or {}
                if attack_graph_core._node_is_effectively_high_value(tgt_node):  # noqa: SLF001
                    _terminal_mo_kept.append(rec)
                    continue
            # Trim trailing MemberOf→non-HV edges instead of discarding the path.
            # BH CE naturally produces paths ending at the pre-MemberOf node (e.g. a
            # Computer) because its Cypher WHERE clause filters paths whose last edge
            # is MemberOf to a non-HV group.  Local DFS generates the extended path;
            # we mirror BH CE by stripping those trailing edges.
            trimmed = _trim_trailing_memberof_edges(
                rec,
                label_to_node=_label_to_node,
                except_hv=_except_hv_terminal,
            )
            if trimmed is None:
                _terminal_mo_discarded += 1
                _terminal_mo_discarded_debug.log(
                    f"[local-pipeline]   terminal-memberof discarded (degenerate after trim): "
                    f"{' → '.join(rec.get('nodes') or [])}"
                )
            else:
                _terminal_mo_trimmed += 1
                _terminal_mo_kept.append(trimmed)
                _terminal_mo_trimmed_debug.log(
                    f"[local-pipeline]   terminal-memberof trimmed: "
                    f"{' → '.join(rec.get('nodes') or [])} "
                    f"→→ {' → '.join(trimmed.get('nodes') or [])}"
                )
        _terminal_mo_discarded_debug.flush()
        _terminal_mo_trimmed_debug.flush()
        if _terminal_mo_trimmed or _terminal_mo_discarded:
            print_info_debug(
                f"[local-pipeline] terminal-memberof [{target!r}, except_hv={_except_hv_terminal}]: "
                f"trimmed {_terminal_mo_trimmed}, discarded {_terminal_mo_discarded} "
                f"→ {len(_terminal_mo_kept)} remain"
            )
        records = _terminal_mo_kept
    _maybe_print_attack_paths_summary_debug(
        domain,
        records,
        stage_label=f"2/6 · after terminal-memberof filter [{target!r}]",
    )
    _stage_done("terminal-memberof", records)

    # Stage 2b: Owned-terminal filter.
    # Placed here — after the terminal-MemberOf trim (which can change the final
    # node of a path) but BEFORE minimize (expensive O(n²) operation).  Removing
    # useless paths early reduces the work for all subsequent stages.
    #
    # Discards paths whose terminal node is already an owned/compromised principal.
    # A path ending at an owned node has zero exploitation value — the operator
    # already controls that node.  Paths that pass *through* an owned intermediate
    # are handled by the containment filter (stage 6): the shorter path from that
    # owned node is kept and the longer super-path dropped.
    #
    # Active for any scope EXCEPT "domain" (which is meant for full-graph audit
    # views and intentionally keeps the global topology).  When the caller does
    # not provide owned_labels (e.g. domain scope) the filter is a no-op.
    if owned_labels and scope != "domain" and not allow_owned_terminal_target:
        _owned_removed = 0
        _owned_kept: list[dict[str, Any]] = []
        _owned_removed_debug = attack_paths_core.SampledDebugLogger(
            prefix="[local-pipeline]",
            summary_label="owned-terminal removed",
        )
        for rec in records:
            term = _normalize_account(str(rec.get("target") or ""))
            if term in owned_labels:
                _owned_removed += 1
                _owned_removed_debug.log(
                    f"[local-pipeline]   owned-terminal removed: "
                    f"{' → '.join(rec.get('nodes') or [])}"
                )
            else:
                _owned_kept.append(rec)
        _owned_removed_debug.flush()
        if _owned_removed:
            print_info_debug(
                f"[local-pipeline] owned-terminal filter: removed {_owned_removed} path(s) "
                f"ending at owned principal(s) → {len(_owned_kept)} remain"
            )
        records = _owned_kept

    # Stage 3: minimize_display_paths.
    n_before_min = len(records)
    records = attack_paths_core.minimize_display_paths(
        records,
        domain=domain,
        snapshot=snapshot,
        scope=scope,
        principal_count=principal_count,
    )
    n_minimized = sum(1 for r in records if r.get("meta", {}).get("minimized"))
    if n_minimized or n_before_min != len(records):
        print_info_debug(
            f"[local-pipeline] minimize: {n_before_min} → {len(records)}, "
            f"{n_minimized} record(s) modified"
        )
    _maybe_print_attack_paths_summary_debug(
        domain,
        records,
        stage_label=f"3/6 · after minimize (scope={scope}, {n_minimized} record(s) modified)",
    )
    _stage_done("minimize", records)

    # Stage 4: Safety-net dedup.
    seen: set[tuple[Any, ...]] = set()
    deduped: list[dict[str, Any]] = []
    n_dedup_removed = 0
    _dedup_removed_debug = attack_paths_core.SampledDebugLogger(
        prefix="[local-pipeline]",
        summary_label="dedup removed",
    )
    for rec in records:
        key = attack_graph_core.display_record_signature(rec)
        if key not in seen:
            seen.add(key)
            deduped.append(rec)
        else:
            n_dedup_removed += 1
            _dedup_removed_debug.log(
                f"[local-pipeline]   dedup removed: {' → '.join(rec.get('nodes') or [])}"
            )
    _dedup_removed_debug.flush()
    if n_dedup_removed:
        print_info_debug(
            f"[local-pipeline] dedup: removed {n_dedup_removed} duplicate(s) → {len(deduped)} remain"
        )
    records = deduped
    _maybe_print_attack_paths_summary_debug(
        domain,
        records,
        stage_label=f"4/6 · after dedup [{scope}] ({n_dedup_removed} removed)",
    )
    _stage_done("dedup", records)

    # Stage 5: affected-user metadata (shell-aware, no BH CE graph required).
    records = _apply_affected_user_metadata(shell, domain, records)
    _maybe_print_attack_paths_summary_debug(
        domain, records, stage_label=f"5/6 · after annotate_affected_users [{scope}]"
    )
    _stage_done("annotate-affected-users", records)

    # Stage 6: Containment filter.
    #
    # domain scope: always keep_longest (holistic view — full chain is more
    #   informative than sub-paths).
    # owned/principals multi-principal: HV-aware keep_shortest regardless of
    #   target mode.  Rationale: owned principals are already compromised; the
    # domain scope  : keep_longest — holistic view, reduce noise.
    # non-domain     : unified HV-aware keep_shortest + Pass-2 prefix removal.
    #   • Pass 1 (keep_shortest + HV priority): keep shorter path to same terminal;
    #     HV-terminal paths beat non-HV regardless of length (Case 2 + HV priority).
    #   • Pass 2: drop strict prefixes — if a shorter path is a prefix of a longer
    #     kept path (same source, different terminal) it is removed.  HV-terminal
    #     paths are never dropped even if they happen to be a prefix of a longer
    #     non-HV path (Case 1).
    #   Applies uniformly to all non-domain scopes (user, owned, principals) and
    #   all target modes (--all, --highvalue, --lowpriv).
    # In domain-mode, the maximal kill chain (terminating at the Domain object)
    # subsumes shorter prefix paths that stop at intermediate tier-0 groups
    # (e.g. ESC1→DA, Kerberoast→Admin). Use keep_longest so those prefixes are
    # collapsed. Outside domain-mode (or for legacy tier0 / impact modes) keep
    # the original keep_shortest+preserve_prefix behaviour that surfaces the
    # most direct route to each distinct HV/tier-0 target.
    # Contained-path filter strategy:
    #
    #   not display_friendly (programmatic / object-targeted)
    #     → keep_shortest + preserve_prefix_paths: most direct route from any
    #       source to the specific target object.  Super-paths that pass through
    #       an already-owned intermediate before reaching the target are dropped
    #       in favour of the shorter sub-path that starts directly from that
    #       owned intermediate.  preserve_prefix_paths ensures a shorter path
    #       ending AT the target is not removed if a longer path passes through
    #       it en route to a different node.
    #
    #   display_friendly, scope == "domain"
    #     → keep_longest: holistic kill-chain view; sub-paths are noise.
    #
    #   display_friendly, scope != "domain", tier0/impact target mode
    #     → keep_shortest HV-aware: most direct route to each distinct HV
    #       target; HV-terminal paths beat non-HV paths of equal/greater length.
    #
    #   display_friendly, scope != "domain", domain target mode
    #     → keep_longest: collapse Compromise Enabler / Foothold sub-paths
    #       into the longest Domain Breaker kill chain for compact display.
    # Stamp record["target_tier"] at the central choke-point — right before the
    # display filters consume it. _label_to_node is already built above; the
    # stamp lets the tier-aware filters keep higher-tier (Domain object) paths
    # from being trimmed against lower-tier ones.
    stamp_records_target_tier(records, label_to_node=_label_to_node)
    # Stamp the 4-tier domain-compromise rank (F5) on the SAME choke-point so the
    # prefix/contained filters can collapse redundant domain-tier subpaths (e.g. a
    # path truncated at the Domain Controllers group inside the full DCSync→Domain
    # chain) using the total order T4(object) > T3(breaker group) > T2(enabler) >
    # T1(host). _label_to_node is required here to recognize the Domain object as T4.
    stamp_records_domain_compromise_tier(records, label_to_node=_label_to_node)
    # Tier-descent noise prune (flag-gated, default OFF → byte-identical passthrough).
    # Runs right after the tier stamps (is_tier_zero / target_priority_class /
    # per-node ESAE tier are all resolvable here) and BEFORE the contained/prefix
    # filters, so those O(N^2) stages see the smaller set. Deletes only descending +
    # unprotected + non-pivot paths, with Protection A (peak-preservation) + the
    # per-source guard making it coverage-safe. On `target=highvalue` every terminal
    # is record-protected → nothing is pruned (byte-identical, the red line).
    _n_before_descent_prune = len(records)
    records = apply_tier_descent_prune(records, _label_to_node)
    if len(records) != _n_before_descent_prune:
        _maybe_print_attack_paths_summary_debug(
            domain,
            records,
            stage_label=(
                "6/6 · after tier-descent prune "
                f"({_n_before_descent_prune - len(records)} removed)"
            ),
        )
    if not display_friendly:
        result, n_contained = (
            attack_graph_core.filter_contained_paths_for_domain_listing(
                records,
                keep_shortest=True,
                preserve_prefix_paths=True,
            )
        )
        if n_contained:
            print_info_debug(
                f"[local-pipeline] contained filter [programmatic, {scope}, "
                f"keep_shortest+preserve_prefix]: removed {n_contained} "
                f"redundant super-path(s) → {len(result)} remain"
            )
        records = result
        _maybe_print_attack_paths_summary_debug(
            domain,
            records,
            stage_label=(
                f"6/6 · after contained filter [programmatic, {scope}] ({n_contained} removed)"
            ),
        )
    elif scope not in {"domain"} and _target_mode_norm in {"tier0", "impact"}:
        _is_hv = lambda rec: _record_terminal_is_hv(rec, _label_to_node)  # noqa: E731
        result, n_contained = (
            attack_graph_core.filter_contained_paths_for_domain_listing(
                records,
                keep_shortest=True,
                is_hv_terminal=_is_hv,
                preserve_prefix_paths=True,
            )
        )
        if n_contained:
            print_info_debug(
                f"[local-pipeline] contained filter [hv-aware, {scope}]: "
                f"removed {n_contained} path(s) → {len(result)} remain"
            )
        records = result
        _maybe_print_attack_paths_summary_debug(
            domain,
            records,
            stage_label=(
                f"6/6 · after contained filter [hv-aware, {scope}] ({n_contained} removed)"
            ),
        )
    elif scope not in {"domain"}:
        # display_friendly + object mode + non-domain scope: keep_longest so
        # Domain Breaker paths subsume shorter Compromise Enabler / Foothold
        # prefix paths for a compact, holistic kill-chain display.
        result, n_contained = (
            attack_graph_core.filter_contained_paths_for_domain_listing(
                records, keep_shortest=False
            )
        )
        if n_contained:
            print_info_debug(
                f"[local-pipeline] contained filter [keep_longest, {scope}, object-mode]: "
                f"removed {n_contained} prefix path(s) → {len(result)} remain"
            )
        records = result
        _maybe_print_attack_paths_summary_debug(
            domain,
            records,
            stage_label=(
                f"6/6 · after contained filter [keep_longest, domain-mode] ({n_contained} removed)"
            ),
        )
    else:
        # Domain scope (display/report). Shared single-source-of-truth helper:
        # shortest HV-aware route to domain compromise by default, legacy holistic
        # keep_longest only when the threaded keep_longest flag is set. Tiers are
        # already stamped above; the helper re-stamps idempotently so both pipelines
        # agree.
        _mode_label = "keep_longest" if keep_longest else "shortest-hv-aware"
        result, n_contained = attack_graph_core.filter_domain_listing_paths(
            records, label_to_node=_label_to_node, keep_longest=keep_longest
        )
        if n_contained:
            print_info_debug(
                f"[local-pipeline] contained filter [{_mode_label}, domain]: "
                f"removed {n_contained} path(s) → {len(result)} remain"
            )
        records = result
        _maybe_print_attack_paths_summary_debug(
            domain,
            records,
            stage_label=(
                f"6/6 · after contained filter [{_mode_label}, domain] ({n_contained} removed)"
            ),
        )
    _stage_done("contained-filter", records)

    # Stage 6c: deduplicate paths with identical attack core but different
    # trailing contextual edges (MemberOf, Contains…).  Must run BEFORE 6b so
    # the surviving core representative can be matched as a prefix of a longer
    # kill-chain by 6b.  Applied to all scopes — Stage 6 (per-scope contained
    # filter) handles most sub-path cases, but 6c/6b catch the trailing-structural
    # and class-aware patterns it misses.
    # Env-var ADSCAN_ATTACK_PATHS_DISABLE_DEDUP=1 disables Stages 6c+6b for
    # debugging — produces the raw pre-dedup baseline so you can diff against the
    # filtered result.
    _dedup_disabled = str(
        os.environ.get("ADSCAN_ATTACK_PATHS_DISABLE_DEDUP", "")
    ).strip() in {"1", "true", "yes"}
    if _dedup_disabled:
        print_info_debug(
            "[local-pipeline] dedup filters 6c+6b DISABLED via "
            "ADSCAN_ATTACK_PATHS_DISABLE_DEDUP — returning raw pre-dedup baseline"
        )
    _pre_6c = len(records)
    records, _n_ctx_dedup = (
        (records, 0)
        if _dedup_disabled
        else attack_graph_core.deduplicate_trailing_contextual_suffix_paths(records)
    )
    if _n_ctx_dedup:
        print_info_debug(
            f"[local-pipeline] trailing-contextual dedup: "
            f"removed {_n_ctx_dedup} path(s) sharing same attack core "
            f"→ {len(records)} remain (was {_pre_6c})"
        )
    _stage_done("contextual-dedup-6c", records)

    # Stage 6b: cross-target prefix-dominated-by-super-path elimination.
    # If path A is a strict contiguous prefix of path B and rank(B) >= rank(A),
    # drop A — the operator already sees A's nodes inside B.
    _pre_6b = len(records)
    records, _n_prefix_dominated = (
        (records, 0)
        if _dedup_disabled
        else attack_graph_core.filter_prefix_paths_dominated_by_super_path(records)
    )
    if _n_prefix_dominated:
        print_info_debug(
            f"[local-pipeline] prefix-dominated filter: "
            f"removed {_n_prefix_dominated} path(s) covered by higher-class super-paths "
            f"→ {len(records)} remain (was {_pre_6b})"
        )
    _stage_done("prefix-dominated-6b", records)

    # Stage 7: target-priority tagging using ADscan-owned semantics.
    _adcs_available = domain_has_adcs_for_attack_steps(shell, domain)
    _ou_contained_tierzero_groups_cache: dict[str, tuple[dict[str, Any], ...]] = {}
    _tier0_count = 0
    _hv_count = 0
    for rec in records:
        target_lookup_label = str(
            rec.get("terminal_target_label") or rec.get("target") or ""
        )
        tgt_node = _label_to_node.get(target_lookup_label) or {}
        _annotate_record_target_priority(
            rec,
            target_node=tgt_node,
            shell=shell,
            domain=domain,
            recursive_groups_by_principal=_recursive_groups_by_principal,
            ou_contained_tierzero_groups_cache=_ou_contained_tierzero_groups_cache,
            adcs_available=_adcs_available,
        )
        # Phase 3 — path-based compromise-class classifier overrides the
        # legacy target-node heuristic when they disagree (e.g. CanPSRemote
        # to a DC must be tier0_foothold, not direct_compromise).
        apply_path_based_classification(rec, tgt_node)
        if rec.get("target_priority_class") == "tierzero":
            _tier0_count += 1
        elif rec.get("target_priority_class") == "highvalue":
            _hv_count += 1
    print_info_debug(
        f"[local-pipeline] priority-tag: {_tier0_count} tierzero, {_hv_count} high-value, "
        f"{len(records) - _tier0_count - _hv_count} pivot"
    )
    print_info_debug(
        f"[local-pipeline] final: {len(records)} attack path(s) after all post-processing"
    )

    # Decorate seam — the ONE place the deferred per-step decoration is applied,
    # after every minimisation/filter/dedup stage across both the core and the
    # local-postprocessing pipeline. The DFS built LIGHT records (path_to_display_
    # record(..., decorate=False)); only these survivors pay the expensive
    # remediability + Privilege-Tier resolution. Idempotent, so it is a no-op on
    # already-decorated records (e.g. a cache-hit path). Uses the SAME graph the
    # DFS ran on (``runtime_graph``, which may carry injected group/membership
    # nodes absent from the persisted base graph) so the output is byte-identical
    # to eager decoration; falls back to the base graph only if a caller omits it.
    _decorate_graph = (
        runtime_graph
        if isinstance(runtime_graph, dict) and runtime_graph.get("nodes")
        else _base_graph
    )
    attack_graph_core.decorate_display_records(_decorate_graph, records)

    return records


def compute_display_paths_for_user(
    shell: object,
    domain: str,
    *,
    username: str,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "object",
    no_cache: bool = False,
    allow_owned_terminal_target: bool = False,
    display_friendly: bool | None = None,
    force_perterminal: bool = False,
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
    effective_depth = _effective_max_depth(max_depth, scope="user", target=target)
    print_info_debug(
        f"[local-pipeline] effective_depth={effective_depth} (requested={max_depth} scope='user' target={target!r})"
    )
    user_norm = str(username or "").strip().lower()
    cache_key = _attack_paths_cache_base_key(
        shell,
        domain,
        scope="user",
        params=(
            user_norm,
            int(effective_depth),
            max_paths,
            target,
            str(target_mode or "object").strip().lower(),
            bool(ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS),
            bool(force_perterminal),
        ),
    )
    cached = _attack_paths_cache_get(
        cache_key, domain=domain, scope="user", no_cache=no_cache, shell=shell
    )
    if cached is not None:
        cached = _filter_zero_length_display_paths(cached, domain=domain, scope="user")
        cached = _apply_affected_user_metadata(shell, domain, cached)
        _log_attack_path_compute_timing(
            domain=domain,
            scope="user",
            elapsed_seconds=max(0.0, time.monotonic() - started_at),
            path_count=len(cached),
            max_depth=effective_depth,
            target=target,
            target_mode=target_mode,
        )
        return cached

    base_graph = _load_attack_graph_for_paths(shell, domain)
    snapshot = _load_membership_snapshot(shell, domain)
    materialized_artifacts = _load_or_build_materialized_attack_path_artifacts(
        shell,
        domain=domain,
        base_graph=base_graph,
        snapshot=snapshot,
    )
    prepared_graph = _load_or_build_prepared_runtime_graph(
        shell,
        domain=domain,
        base_graph=base_graph,
        snapshot=snapshot,
        expand_terminal_memberships=ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS,
        materialized_artifacts=materialized_artifacts,
    )
    runtime_graph: dict[str, Any] = dict(prepared_graph)
    runtime_graph["nodes"] = dict(
        prepared_graph.get("nodes")
        if isinstance(prepared_graph.get("nodes"), dict)
        else {}
    )
    runtime_graph["edges"] = list(
        prepared_graph.get("edges")
        if isinstance(prepared_graph.get("edges"), list)
        else []
    )

    start_node_id = _find_node_id_by_label(runtime_graph, username)
    if not start_node_id:
        start_node_id = ensure_user_node_for_domain(
            shell, domain, runtime_graph, username=str(username or "").strip()
        )
    _stitch_principal_memberships_for_runtime_paths(
        shell,
        domain=domain,
        runtime_graph=runtime_graph,
        principal_node_ids={start_node_id} if start_node_id else set(),
        snapshot=snapshot,
        scope="user",
        materialized_artifacts=materialized_artifacts,
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
    _dfs_t0 = time.monotonic()
    records = _sort_display_paths(
        attack_paths_core.compute_display_paths_for_start_node(
            runtime_graph,
            domain=domain,
            snapshot=snapshot,
            start_node_id=start_node_id,
            max_depth=effective_depth,
            max_paths=max_paths,
            target=target,
            target_mode=target_mode,
            expand_terminal_memberships=ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS,
            filter_shortest_paths=False,
            materialized_artifacts=(
                {
                    "node_id_by_label": materialized_artifacts.node_id_by_label,
                    "recursive_groups_by_principal": materialized_artifacts.recursive_groups_by_principal,
                }
                if materialized_artifacts is not None
                else None
            ),
            force_perterminal=force_perterminal,
        )
    )
    _dfs_elapsed = time.monotonic() - _dfs_t0
    print_info_debug(
        f"[engine=local-dfs] dfs={_dfs_elapsed:.3f}s ({len(records)} raw paths, scope=user)"
    )
    records = _filter_zero_length_display_paths(records, domain=domain, scope="user")
    # Populate owned_labels so the owned-terminal filter can drop paths whose
    # final node is already a compromised principal (e.g. an attack path from
    # audit2020 → ... → SUPPORT when SUPPORT is already owned — that path has
    # zero operational value, we already control SUPPORT).
    try:
        _user_scope_owned = frozenset(
            _normalize_account(label)
            for label in get_attack_path_owned_principal_labels(shell, domain)
        )
    except Exception:  # noqa: BLE001
        _user_scope_owned = frozenset()
    records = _apply_local_postprocessing_pipeline(
        records,
        shell=shell,
        domain=domain,
        scope="user",
        target=target,
        snapshot=snapshot,
        principal_count=1,
        owned_labels=_user_scope_owned or None,
        allow_owned_terminal_target=allow_owned_terminal_target,
        target_mode=target_mode,
        display_friendly=display_friendly,
        runtime_graph=runtime_graph,
    )
    _total_elapsed = max(0.0, time.monotonic() - started_at)
    print_info_debug(
        f"[engine=local-dfs] dfs={_dfs_elapsed:.3f}s | post={max(0.0, _total_elapsed - _dfs_elapsed):.3f}s"
        f" | total={_total_elapsed:.3f}s ({len(records)} paths, scope=user)"
    )
    _log_attack_path_compute_timing(
        domain=domain,
        scope="user",
        elapsed_seconds=_total_elapsed,
        path_count=len(records),
        max_depth=effective_depth,
        target=target,
        target_mode=target_mode,
    )
    _attack_paths_cache_put(
        cache_key,
        records,
        domain=domain,
        scope="user",
        compute_seconds=_total_elapsed,
        shell=shell,
        no_cache=no_cache,
    )
    return records


def compute_display_paths_for_domain(
    shell: object,
    domain: str,
    *,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "object",
    no_cache: bool = False,
    allow_owned_terminal_target: bool = False,
    display_friendly: bool | None = None,
    keep_longest: bool = True,
    force_perterminal: bool = False,
) -> list[dict[str, Any]]:
    """Compute maximal attack paths for a domain with optional high-value promotion.

    This is the backend used by `attack_paths <domain>` when no explicit start
    user (or "owned") is provided.

    When `target="highvalue"`, we still compute all maximal paths,
    then *promote* paths whose terminal node is not high value but is a member
    (recursively) of an effectively high-value group. The promotion appends a
    context-only `MemberOf` step so the operator can understand why the path is
    surfaced.
    """
    started_at = time.monotonic()
    effective_depth = _effective_max_depth(max_depth, scope="domain", target=target)
    print_info_debug(
        f"[local-pipeline] effective_depth={effective_depth} (requested={max_depth} scope='domain' target={target!r})"
    )
    cache_key = _attack_paths_cache_base_key(
        shell,
        domain,
        scope="domain",
        params=(
            int(effective_depth),
            max_paths,
            target,
            str(target_mode or "object").strip().lower(),
            bool(ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS),
            # keep_longest changes the domain-listing output (shortest HV-aware vs
            # holistic longest), so it MUST be part of the cache key — otherwise
            # alternating modes in one process returns stale results.
            bool(keep_longest),
            # The traversal engine changes the result set (DFS all-simple-paths vs
            # the bounded per-terminal fallback), so a fallback run must never
            # serve a cached DFS result or vice versa.
            bool(force_perterminal),
        ),
    )
    cached = _attack_paths_cache_get(
        cache_key, domain=domain, scope="domain", no_cache=no_cache, shell=shell
    )
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
            max_depth=effective_depth,
            target=target,
            target_mode=target_mode,
        )
        return cached

    base_graph = _load_attack_graph_for_paths(shell, domain)
    snapshot = _load_membership_snapshot(shell, domain)
    materialized_artifacts = _load_or_build_materialized_attack_path_artifacts(
        shell,
        domain=domain,
        base_graph=base_graph,
        snapshot=snapshot,
    )
    prepared_graph = _load_or_build_prepared_runtime_graph(
        shell,
        domain=domain,
        base_graph=base_graph,
        snapshot=snapshot,
        expand_terminal_memberships=ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS,
        materialized_artifacts=materialized_artifacts,
    )
    runtime_graph: dict[str, Any] = dict(prepared_graph)
    runtime_graph["nodes"] = dict(
        prepared_graph.get("nodes")
        if isinstance(prepared_graph.get("nodes"), dict)
        else {}
    )
    runtime_graph["edges"] = list(
        prepared_graph.get("edges")
        if isinstance(prepared_graph.get("edges"), list)
        else []
    )
    start_node_ids = _resolve_domain_enabled_low_priv_user_start_ids(
        shell, domain, runtime_graph
    )
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
    try:
        _dfs_t0 = time.monotonic()
        records = _sort_display_paths(
            attack_paths_core.compute_display_paths_for_domain(
                runtime_graph,
                domain=domain,
                snapshot=snapshot,
                max_depth=effective_depth,
                max_paths=max_paths,
                target=target,
                target_mode=target_mode,
                expand_terminal_memberships=ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS,
                start_node_ids=start_node_ids,
                materialized_artifacts=(
                    {
                        "node_id_by_label": materialized_artifacts.node_id_by_label,
                        "recursive_groups_by_principal": materialized_artifacts.recursive_groups_by_principal,
                    }
                    if materialized_artifacts is not None
                    else None
                ),
                keep_longest=keep_longest,
                force_perterminal=force_perterminal,
            )
        )
        _dfs_elapsed = time.monotonic() - _dfs_t0
        print_info_debug(
            f"[engine=local-dfs] dfs={_dfs_elapsed:.3f}s ({len(records)} raw paths, scope=domain)"
        )
        records = _filter_zero_length_display_paths(
            records, domain=domain, scope="domain"
        )
        records = _apply_local_postprocessing_pipeline(
            records,
            shell=shell,
            domain=domain,
            scope="domain",
            target=target,
            snapshot=snapshot,
            principal_count=2,  # domain scope is always treated as multi-principal
            allow_owned_terminal_target=allow_owned_terminal_target,
            target_mode=target_mode,
            display_friendly=display_friendly,
            keep_longest=keep_longest,
            runtime_graph=runtime_graph,
        )
    except _AttackPathMemoryBudgetExceeded as exc:
        # The memory gate stopped discovery cleanly before it could be SIGKILLed
        # (either mid-DFS or in the O(N²) post-DFS projection). Stop the
        # coverage-bounded stop leaking out of the SERVICE layer at the SOURCE:
        # every DIRECT caller of this function (the PDF report, the snapshot
        # re-materializer) inherits the honest bounded fallback + coverage
        # declaration instead of a scary crash. When ``force_perterminal`` is
        # already set the run WAS the bounded fallback (either a direct caller asked
        # for it, or ``_recover_from_memory_abort`` re-entered here): re-raise so the
        # shared helper's nested-abort branch degrades to an empty set rather than
        # recovering a second time. Otherwise route through the ONE shared recovery,
        # whose ``recompute_bounded`` re-runs THIS function with the per-terminal
        # fallback engaged (CLAUDE.md § "A bounded computation is a data gap").
        if force_perterminal:
            raise

        def _recompute_bounded_domain() -> list[dict[str, Any]]:
            return compute_display_paths_for_domain(
                shell,
                domain,
                max_depth=max_depth,
                max_paths=max_paths,
                target=target,
                target_mode=target_mode,
                # Freshness: never serve a cached DFS result for the bounded re-run.
                no_cache=True,
                allow_owned_terminal_target=allow_owned_terminal_target,
                display_friendly=display_friendly,
                keep_longest=keep_longest,
                force_perterminal=True,
            )

        return _recover_from_memory_abort(
            shell, domain, exc, recompute_bounded=_recompute_bounded_domain
        )
    _total_elapsed = max(0.0, time.monotonic() - started_at)
    print_info_debug(
        f"[engine=local-dfs] dfs={_dfs_elapsed:.3f}s | post={max(0.0, _total_elapsed - _dfs_elapsed):.3f}s"
        f" | total={_total_elapsed:.3f}s ({len(records)} paths, scope=domain)"
    )
    _log_attack_path_compute_timing(
        domain=domain,
        scope="domain",
        elapsed_seconds=_total_elapsed,
        path_count=len(records),
        max_depth=effective_depth,
        target=target,
        target_mode=target_mode,
    )
    _attack_paths_cache_put(
        cache_key,
        records,
        domain=domain,
        scope="domain",
        compute_seconds=_total_elapsed,
        shell=shell,
        no_cache=no_cache,
    )
    return records


def _node_is_non_tier0_group(node: dict[str, Any]) -> bool:
    """Return True when node is a Group that is not already Tier-0.

    All non-Tier-0 groups are valid Phase 2 BFS sources: they may have
    ACL/AdminTo/CanRDP/CanPSRemote edges in the local graph that lead to
    domain compromise. Groups with no outbound edges terminate immediately
    in the BFS at negligible cost.
    """
    return _node_kind(node) == "Group" and not _node_is_effectively_high_value(node)


def _resolve_domain_enabled_low_priv_user_start_ids(
    shell: object,
    domain: str,
    graph: dict[str, Any],
) -> set[str]:
    """Return enabled low-priv user node ids for the requested domain."""
    nodes_map = graph.get("nodes")
    if not isinstance(nodes_map, dict):
        return set()

    enabled_users = get_enabled_users_for_domain(shell, domain)
    normalized_enabled_users = {
        _normalize_account(username)
        for username in (enabled_users or set())
        if _normalize_account(username)
    }
    normalized_domain = str(domain or "").strip().upper()
    identity_snapshot = load_or_build_identity_risk_snapshot(shell, domain)
    risk_users = (
        identity_snapshot.get("users") if isinstance(identity_snapshot, dict) else {}
    )
    if not isinstance(risk_users, dict):
        risk_users = {}

    start_node_ids: set[str] = set()
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        node = _enrich_node_enabled_metadata(shell, graph, node)
        nodes_map[str(node_id)] = node
        if not _node_is_enabled_user(node):
            continue

        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        node_domain = str(props.get("domain") or "").strip().upper()
        if not node_domain:
            label = _canonical_node_label(node)
            if "@" in label:
                node_domain = label.rsplit("@", 1)[-1].strip().upper()
        if node_domain != normalized_domain:
            continue

        normalized_username = _normalize_account(_canonical_node_label(node))
        if (
            normalized_enabled_users
            and normalized_username not in normalized_enabled_users
        ):
            continue
        risk_record = risk_users.get(normalized_username)
        if isinstance(risk_record, dict) and (
            bool(risk_record.get("has_direct_domain_control"))
            or bool(risk_record.get("is_control_exposed"))
        ):
            continue
        if risk_record is None and _node_is_effectively_high_value(node):
            continue
        start_node_ids.add(str(node_id))

    # Include all non-Tier-0 groups as additional BFS start nodes.
    # Any group with outbound ACL/AdminTo/CanRDP/CanPSRemote edges in the local
    # graph is a valid escalation source. Groups with no such edges terminate
    # immediately in the BFS at negligible cost, so no whitelist is needed.
    group_start_ids: set[str] = set()
    for node_id, node in nodes_map.items():
        if not isinstance(node, dict):
            continue
        if not _node_is_non_tier0_group(node):
            continue
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        node_domain = str(props.get("domain") or "").strip().upper()
        if not node_domain:
            label = _canonical_node_label(node)
            if "@" in label:
                node_domain = label.rsplit("@", 1)[-1].strip().upper()
        if node_domain and node_domain != normalized_domain:
            continue
        group_start_ids.add(str(node_id))

    start_node_ids |= group_start_ids

    marked_domain = mark_sensitive(domain, "domain")
    print_info_debug(
        f"[attack_paths] domain start nodes resolved for {marked_domain}: "
        f"{len(start_node_ids)} nodes "
        f"(users={len(start_node_ids) - len(group_start_ids)}, non_tier0_groups={len(group_start_ids)})"
    )
    return start_node_ids


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
    risk_flags = classify_users_tier0_high_value(shell, domain=domain, usernames=owned)
    for username in owned:
        flags = risk_flags.get(normalize_samaccountname(username))
        if bool(getattr(flags, "is_tier0", False)):
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


def _user_label_stem(value: object) -> str:
    """Return a SAM-like lowercase stem for a graph user label.

    Strips a ``DOMAIN\\`` prefix and an ``@domain`` suffix. Internal dots
    are preserved because user samaccountnames frequently contain them
    (e.g. ``l.wilson_adm`` → ``l.wilson_adm``, not ``l``).
    """

    token = str(value or "").strip()
    if "\\" in token:
        token = token.split("\\", 1)[1]
    if "@" in token:
        token = token.split("@", 1)[0]
    return token.strip().lower()


def _computer_label_stem(value: object) -> str:
    """Return a hostname-like lowercase stem for a graph computer label.

    Strips ``DOMAIN\\`` prefix, ``@domain`` suffix, the trailing ``$`` from
    a SAM, and any DNS suffix so ``DC01$@GARFIELD.HTB`` and
    ``DC01.garfield.htb`` both collapse to ``dc01``.
    """

    token = str(value or "").strip()
    if "\\" in token:
        token = token.split("\\", 1)[1]
    if "@" in token:
        token = token.split("@", 1)[0]
    token = token.strip().rstrip(".")
    if token.endswith("$"):
        token = token[:-1]
    if "." in token:
        token = token.split(".", 1)[0]
    return token.lower()


def get_graph_service_access_pairs(
    shell: object,
    domain: str,
    *,
    relation: str,
) -> frozenset[tuple[str, str]]:
    """Return ``(user_stem, computer_stem)`` pairs confirmed in the attack graph.

    Iterates the per-domain attack graph and collects every direct edge whose
    relation matches ``relation`` (e.g. ``CanPSRemote``, ``CanRDP``) and whose
    endpoints resolve to a User-kind source and a Computer-kind target. This
    is the ground truth for service-access affinity used by the pivot offer
    UX to filter owned users that actually hold the relation in the graph
    against a candidate pivot host.

    Args:
        shell: Shell instance providing workspace context.
        domain: Domain key for the per-domain attack graph.
        relation: BloodHound-style edge relation name (case-insensitive).

    Returns:
        Frozen set of ``(user_stem, computer_stem)`` tuples — user stems
        normalized via :func:`_user_label_stem` (preserves dots in SAMs)
        and computer stems via :func:`_computer_label_stem` (strips ``$``
        and DNS suffixes). Empty when the graph is missing or holds no
        matching direct edges.
    """

    relation_norm = str(relation or "").strip()
    if not relation_norm:
        return frozenset()

    try:
        graph = load_attack_graph(shell, domain)
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return frozenset()

    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    edges = graph.get("edges") if isinstance(graph, dict) else None
    if not isinstance(nodes, dict) or not isinstance(edges, list):
        return frozenset()

    relation_key = relation_norm.casefold()
    pairs: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        edge_relation = str(edge.get("relation") or "").strip().casefold()
        if edge_relation != relation_key:
            continue
        source_id = str(edge.get("from") or "").strip()
        target_id = str(edge.get("to") or "").strip()
        if not source_id or not target_id:
            continue
        source_node = nodes.get(source_id)
        target_node = nodes.get(target_id)
        if not isinstance(source_node, dict) or not isinstance(target_node, dict):
            continue
        if _node_kind(source_node) != "User":
            continue
        if _node_kind(target_node) != "Computer":
            continue
        user_stem = _user_label_stem(source_node.get("label"))
        computer_stem = _computer_label_stem(target_node.get("label"))
        if not user_stem or not computer_stem:
            continue
        pairs.add((user_stem, computer_stem))

    return frozenset(pairs)


def get_attack_path_source_domains(shell: object, domain: str) -> list[str]:
    """Return domains that may legitimately source attack-path steps for `domain`."""
    domain_clean = str(domain or "").strip().lower()
    if not domain_clean:
        return []

    allowed: set[str] = {domain_clean}
    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict):
        for candidate_domain, entry in domains_data.items():
            candidate = str(candidate_domain or "").strip().lower()
            if (
                not candidate
                or candidate == domain_clean
                or not isinstance(entry, dict)
            ):
                continue
            connectivity = entry.get("connectivity")
            summary = (
                connectivity.get("summary") if isinstance(connectivity, dict) else {}
            )
            if not isinstance(summary, dict):
                summary = {}
            if str(
                summary.get("source_domain") or ""
            ).strip().lower() == domain_clean and bool(summary.get("reachable")):
                allowed.add(candidate)

    raw_connectivity = getattr(shell, "domain_connectivity", None)
    if isinstance(raw_connectivity, dict):
        for candidate_domain, entry in raw_connectivity.items():
            candidate = str(candidate_domain or "").strip().lower()
            if (
                not candidate
                or candidate == domain_clean
                or not isinstance(entry, dict)
            ):
                continue
            summary = entry.get("summary")
            if not isinstance(summary, dict):
                continue
            if str(
                summary.get("source_domain") or ""
            ).strip().lower() == domain_clean and bool(summary.get("reachable")):
                allowed.add(candidate)

    return sorted(allowed)


def get_attack_path_owned_principal_labels(
    shell: object,
    domain: str,
    *,
    include_trusted_domains: bool = False,
) -> list[str]:
    """Return owned principals as canonical `NAME@DOMAIN` labels for pathing."""
    target_domains = (
        get_attack_path_source_domains(shell, domain)
        if include_trusted_domains
        else [str(domain or "").strip().lower()]
    )
    labels: list[str] = []
    for current_domain in target_domains:
        owned = get_owned_domain_usernames_for_attack_paths(shell, current_domain)
        if not owned:
            continue
        domain_upper = current_domain.upper()
        for username in owned:
            raw = str(username or "").strip()
            if not raw:
                continue
            if "@" in raw:
                left, _, right = raw.partition("@")
                if left and right:
                    labels.append(f"{left.strip().upper()}@{right.strip().upper()}")
                    continue
            labels.append(f"{raw.upper()}@{domain_upper}")
    return sorted(set(labels))


def compute_display_paths_for_owned_users(
    shell: object,
    domain: str,
    *,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "object",
    no_cache: bool = False,
    allow_owned_terminal_target: bool = False,
    display_friendly: bool | None = None,
    force_perterminal: bool = False,
) -> list[dict[str, Any]]:
    """Compute maximal dynamic paths for all owned users in a domain.

    This is a convenience helper for the CLI `attack_paths <domain> owned`.

    Args:
        shell: Shell instance holding `domains_data` and BloodHound service access.
        domain: Domain name.
        max_depth: Max depth for path search.
        target: When "highvalue", only include paths whose terminal node
            is high value (Tier Zero / highvalue / admin_tier_0).

    Returns:
        Deduplicated list of UI-ready path dicts (same shape as `path_to_display_record`).
    """
    owned = get_attack_path_owned_principal_labels(
        shell,
        domain,
        include_trusted_domains=True,
    )
    if not owned:
        return []
    return compute_display_paths_for_principals(
        shell,
        domain,
        principals=owned,
        max_depth=max_depth,
        max_paths=max_paths,
        target=target,
        target_mode=target_mode,
        no_cache=no_cache,
        allow_owned_terminal_target=allow_owned_terminal_target,
        display_friendly=display_friendly,
        force_perterminal=force_perterminal,
    )


def _ask_or_get_attack_path_engine(shell: object) -> tuple[str, int]:
    """Return the attack-path engine and worker override to use.

    In production (non-dev) always returns ``("local", 0)`` — local DFS is
    faster and sequential execution currently benchmarks better than the
    parallel worker mode for the workloads ADscan computes by default.
    In development mode (``ADSCAN_SESSION_ENV=dev``) shows an interactive
    questionary selector so engineers can compare the local Python DFS engine
    against the rustworkx benchmark engine, and choose Sequential vs Parallel
    execution.

    Returns:
        Tuple of (engine, dev_workers) where engine is ``"local"`` or
        ``"rustworkx"`` and dev_workers is the worker count override
        (-1 = auto, 0 = sequential, used only for this computation).
    """
    # A selection pre-resolved by ``preselect_dev_engine_for_display`` (called
    # BEFORE the LiveSession alt-screen) short-circuits the pickers so they never
    # fire from inside the compute, where the alt-screen would hide the prompt and
    # hang the run. See that context manager for the rationale.
    _preselected = _PRESELECTED_DEV_ENGINE.get()
    if _preselected is not None:
        return _preselected

    # In production (non-dev) always use local DFS in sequential mode.
    is_dev = os.getenv("ADSCAN_SESSION_ENV", "").strip().lower() == "dev"
    if not is_dev:
        return "local", 0

    # An incidental non-interactive seam (the background-job drain / idle-prompt
    # harvest review) suppresses the dev picker for its scope — return the
    # production default rather than prompting on every render.
    if _SUPPRESS_DEV_ENGINE_PICKER.get():
        return "local", 0

    if not hasattr(shell, "_questionary_select"):
        return "local", 0

    options = [
        "Local  (Python DFS)",
        "rustworkx  (Rust-backed DFS)  [dev benchmark]",
    ]

    try:
        idx = shell._questionary_select(  # type: ignore[attr-defined]
            "Select attack path engine:",
            options,
            default_idx=0,
        )
    except Exception:  # noqa: BLE001
        return "local", 0

    engine = "rustworkx" if idx == 1 else "local"

    # For local engines, ask whether to use sequential or parallel execution.
    try:
        parallelism_idx = shell._questionary_select(  # type: ignore[attr-defined]
            "Parallelism mode  [dev benchmark]:",
            [
                "Sequential  (single process)",
                "Parallel  (auto workers)",
            ],
            default_idx=0,
        )
    except Exception:  # noqa: BLE001
        return engine, 0

    dev_workers = 0 if parallelism_idx == 0 else -1
    return engine, dev_workers


def _compute_rustworkx_display_paths(
    shell: object,
    domain: str,
    *,
    scope: str,
    username: str | None = None,
    principals: list[str] | None = None,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "object",
    membership_sample_max: int = 3,
    keep_longest: bool = False,
) -> list[dict[str, Any]]:
    """Run the full local-DFS pipeline with rustworkx as the graph engine.

    Temporarily replaces ``attack_graph_core.compute_maximal_attack_paths`` and
    ``compute_maximal_attack_paths_from_start`` with their rustworkx-backed
    equivalents, then delegates to the standard scope-specific service functions
    (with ``no_cache=True`` to get fresh DFS timings).  Original functions are
    restored in a ``finally`` block.

    Dev-mode only — not called in production.
    """
    from adscan_internal.services import attack_graph_core as _ag_core
    from adscan_internal.services import attack_graph_core_rustworkx as _rw_engine

    if not _rw_engine.is_available():
        print_info_debug(
            "[engine=rustworkx] rustworkx not installed — falling back to local Python DFS"
        )
        # Fall through to local DFS by returning sentinel; caller handles this.
        return []

    _orig_domain_dfs = _ag_core.compute_maximal_attack_paths  # type: ignore[attr-defined]
    _orig_start_dfs = _ag_core.compute_maximal_attack_paths_from_start  # type: ignore[attr-defined]
    try:
        # Swap Python DFS with rustworkx variants (single-threaded CLI — safe).
        _ag_core.compute_maximal_attack_paths = (  # type: ignore[attr-defined]
            _rw_engine.compute_maximal_attack_paths_rustworkx
        )
        _ag_core.compute_maximal_attack_paths_from_start = (  # type: ignore[attr-defined]
            _rw_engine.compute_maximal_attack_paths_from_start_rustworkx
        )

        scope_norm = str(scope or "domain").strip().lower()
        _rw_t0 = time.perf_counter()

        if scope_norm == "domain":
            result = compute_display_paths_for_domain(
                shell,
                domain,
                max_depth=max_depth,
                max_paths=max_paths,
                target=target,
                target_mode=target_mode,
                no_cache=True,
                keep_longest=keep_longest,
            )
        elif scope_norm == "user":
            if not str(username or "").strip():
                return []
            result = compute_display_paths_for_user(
                shell,
                domain,
                username=str(username or "").strip(),
                max_depth=max_depth,
                max_paths=max_paths,
                target=target,
                target_mode=target_mode,
                no_cache=True,
            )
        elif scope_norm == "owned":
            result = compute_display_paths_for_owned_users(
                shell,
                domain,
                max_depth=max_depth,
                max_paths=max_paths,
                target=target,
                target_mode=target_mode,
                no_cache=True,
            )
        elif scope_norm == "principals":
            normalized = [
                str(p or "").strip() for p in (principals or []) if str(p or "").strip()
            ]
            if not normalized:
                return []
            result = compute_display_paths_for_principals(
                shell,
                domain,
                principals=normalized,
                max_depth=max_depth,
                max_paths=max_paths,
                target=target,
                target_mode=target_mode,
                membership_sample_max=membership_sample_max,
                no_cache=True,
            )
        else:
            raise ValueError(f"Unsupported scope for rustworkx engine: {scope!r}")

        print_info_debug(
            f"[engine=rustworkx] {len(result)} path(s) in {time.perf_counter() - _rw_t0:.2f}s"
        )
        return result
    finally:
        _ag_core.compute_maximal_attack_paths = _orig_domain_dfs  # type: ignore[attr-defined]
        _ag_core.compute_maximal_attack_paths_from_start = _orig_start_dfs  # type: ignore[attr-defined]


def _recover_from_memory_abort(
    shell: object,
    domain: str,
    exc: "_AttackPathMemoryBudgetExceeded",
    *,
    recompute_bounded: "Callable[[], list[dict[str, Any]]]",
) -> list[dict[str, Any]]:
    """Recover from a memory-gate abort by re-running the BOUNDED fallback (SSOT).

    The single place the coverage-bounded stop is turned into a real result. The
    memory gate stopped discovery cleanly before it could be SIGKILLed, raising
    :class:`_AttackPathMemoryBudgetExceeded`; this helper:

    1. gives the OPERATOR the real cause + remedy on the terminal and records the
       hard-abort ("bounded") client coverage declaration
       (:func:`_handle_attack_path_memory_abort`);
    2. marks the traversal engine as the bounded fallback
       (:func:`_record_attack_path_engine_used`);
    3. re-runs the computation ONCE through the caller-supplied ``recompute_bounded``
       closure, which must engage the bounded per-terminal fallback
       (``force_perterminal=True``) so the deliverable carries a real
       coverage-floored route set instead of an empty one; and
    4. overwrites the hard-abort record with the SAMPLED coverage declaration
       (:func:`_handle_attack_path_sampled_coverage`), since discovery ultimately
       DID return a floored set covering every reachable target.

    If the bounded recompute ITSELF blows the budget (should not happen — the
    fallback is bounded), the hard-abort ("bounded") record stands and an empty
    list is returned, exactly as before this recovery was centralized.

    This is the ONE implementation of the recovery, consumed by both the public
    summaries entry point (:func:`get_attack_path_summaries`) and the service-layer
    domain compute (:func:`compute_display_paths_for_domain`), so the recovery
    logic can never drift across the two seams (CLAUDE.md § "A bounded computation
    is a data gap").
    """
    _handle_attack_path_memory_abort(shell, domain, exc)
    _record_attack_path_engine_used(shell, engine="fallback", reason="dfs_aborted")
    try:
        result = recompute_bounded()
    except _AttackPathMemoryBudgetExceeded:
        # The bounded fallback itself blew the budget — the hard-abort ("bounded")
        # record stands and the result is empty, exactly as before.
        return []
    _handle_attack_path_sampled_coverage(shell, domain)
    return result


def get_attack_path_summaries(
    shell: object,
    domain: str,
    *,
    scope: str = "domain",
    username: str | None = None,
    principals: list[str] | None = None,
    max_depth: int,
    max_paths: int | None = None,
    target: str = "highvalue",
    target_mode: str = "object",
    summary_filters: AttackPathSummaryFilters | None = None,
    membership_sample_max: int = 3,
    no_cache: bool = False,
    engine_override: str | None = None,
    dev_workers_override: int | None = None,
    render_debug_tables: bool = True,
    display_friendly: bool | None = None,
    keep_longest: bool = True,
) -> list[dict[str, Any]]:
    """Return user-facing attack-path summaries through the shell-aware layer.

    This is the single entry point callers should use for CLI/web summaries.
    It guarantees that all shell-aware post-processing is applied consistently:
    filtering, affected-user metadata, cache handling, and future UX-oriented
    enrichments.

    When BloodHound CE is available, prompts the user interactively to choose
    between the BloodHound Cypher engine and the local Python DFS engine.
    The choice is cached on the shell for the duration of the session.

    ``keep_longest`` only affects the ``domain`` scope: when False (default) the
    listing returns the most direct route to domain compromise; when True it
    returns the holistic longest kill chain. It is part of the domain-scope cache
    key, so alternating modes in one process does not return stale results.
    """
    scope_norm = str(scope or "domain").strip().lower()

    # In dev mode an interactive selector lets engineers compare all three engines
    # and choose sequential vs parallel execution. Callers that need a silent
    # internal computation path can bypass prompts with explicit overrides.
    if engine_override is None:
        _engine, _dev_workers = _ask_or_get_attack_path_engine(shell)
    else:
        _engine = str(engine_override or "local").strip().lower() or "local"
        # Default to the module worker setting (env ADSCAN_ATTACK_PATH_WORKERS,
        # default 0 = SEQUENTIAL). Measured 2026-07: on real attack-path graphs
        # parallel gives no speedup (the cost is the shared-subtree re-walk /
        # per-principal downstream fan-out, not independent per-source work), it
        # was the source of an under-reporting coverage divergence vs sequential,
        # and its per-worker graph copies pressure memory on weak VMs. Sequential
        # is the correct production default; parallel stays available for
        # debugging via ADSCAN_ATTACK_PATH_WORKERS=-1, an explicit
        # dev_workers_override, or the dev interactive engine selector.
        _dev_workers = (
            int(dev_workers_override)
            if isinstance(dev_workers_override, int)
            else attack_graph_core._ATTACK_PATH_WORKERS  # noqa: SLF001
        )

    # Apply the resolved worker count for this computation, restoring the module
    # default in the finally. In production _dev_workers now equals the module
    # setting (sequential by default), so this is a no-op unless a debug override
    # (env / param / dev selector) explicitly requested parallel.
    _prev_graph_workers = attack_graph_core._ATTACK_PATH_WORKERS  # noqa: SLF001
    _prev_principal_workers = attack_paths_core._PRINCIPAL_WORKERS  # noqa: SLF001
    attack_graph_core._ATTACK_PATH_WORKERS = _dev_workers  # noqa: SLF001
    attack_paths_core._PRINCIPAL_WORKERS = _dev_workers  # noqa: SLF001

    try:
        with _attack_path_debug_summary_tables(render_debug_tables):
            result = _compute_attack_path_summaries_inner(
                shell,
                domain,
                scope_norm=scope_norm,
                engine=_engine,
                username=username,
                principals=principals,
                max_depth=max_depth,
                max_paths=max_paths,
                target=target,
                target_mode=target_mode,
                summary_filters=summary_filters,
                membership_sample_max=membership_sample_max,
                no_cache=no_cache,
                display_friendly=display_friendly,
                keep_longest=keep_longest,
            )
        # The pre-DFS predictor may have routed this run to the bounded fallback
        # engine (a very large directory). When it did, the route set is a
        # coverage-floored SAMPLE, so record the sampled-coverage declaration for
        # the deliverable + web CTEM (never rendering a sampled run as complete).
        # A full-DFS ("dfs") run records nothing new — it rendered exactly as before.
        if getattr(shell, "_attack_path_engine_used", None) == "fallback":
            _handle_attack_path_sampled_coverage(shell, domain)
        return result
    except _AttackPathMemoryBudgetExceeded as exc:
        # The memory gate stopped discovery cleanly before it could be SIGKILLed.
        # Abort backstop (hybrid switch): the DFS blew the budget even though the
        # pre-DFS predictor did not fire. Route the whole recovery through the ONE
        # shared helper (operator line + hard-abort record + engine marker + bounded
        # re-run + sampled-coverage record). The bounded recompute here re-runs the
        # FULL inner (so the summaries-layer filters/postprocessing still apply)
        # with ``force_perterminal=True`` and forces the local engine — the
        # per-terminal fallback is a local-DFS entry-point concept, so a dev
        # "rustworkx" selection would just re-run (and re-abort) the same path.
        def _recompute_bounded_summaries() -> list[dict[str, Any]]:
            with _attack_path_debug_summary_tables(render_debug_tables):
                return _compute_attack_path_summaries_inner(
                    shell,
                    domain,
                    scope_norm=scope_norm,
                    engine="local",
                    username=username,
                    principals=principals,
                    max_depth=max_depth,
                    max_paths=max_paths,
                    target=target,
                    target_mode=target_mode,
                    summary_filters=summary_filters,
                    membership_sample_max=membership_sample_max,
                    no_cache=no_cache,
                    display_friendly=display_friendly,
                    keep_longest=keep_longest,
                    force_perterminal=True,
                )

        return _recover_from_memory_abort(
            shell, domain, exc, recompute_bounded=_recompute_bounded_summaries
        )
    finally:
        attack_graph_core._ATTACK_PATH_WORKERS = _prev_graph_workers  # noqa: SLF001
        attack_paths_core._PRINCIPAL_WORKERS = _prev_principal_workers  # noqa: SLF001


def get_owned_attack_path_summaries_to_target(
    shell: object,
    domain: str,
    *,
    target_label: str,
    terminal_relations: Iterable[str] | None = None,
    max_depth: int,
    max_paths: int | None = None,
    target_mode: str = "object",
    membership_sample_max: int = 3,
    no_cache: bool = False,
    engine_override: str | None = None,
    dev_workers_override: int | None = None,
    render_debug_tables: bool = True,
) -> list[dict[str, Any]]:
    """Return owned-scope attack-path summaries narrowed to a specific target.

    This helper exists for follow-up workflows that need the standard attack-path
    computation, but only for one concrete target object and optionally only when
    the final executable step matches one of a known set of relations.

    Defaults ``target_mode="object"`` because that is the semantically correct
    mode for "all owned-principal paths terminating at one specific node":
    it preserves the owned-user source through chained MemberOf+ACL paths
    (skips ``leading_memberof``) and uses a contained-filter that retains
    shorter paths to the target object even when a longer extension exists.
    Pass ``target_mode="domain"`` only if you want the legacy "subsume into the
    longest kill chain" behaviour, which is rarely correct for object-targeted
    queries.

    Args:
        shell: Active shell/session object.
        domain: Domain whose attack graph should be queried.
        target_label: Concrete summary target label to retain.
        terminal_relations: Optional final-step relation keys to retain.
        max_depth: Max graph depth for the underlying computation.
        max_paths: Optional path cap.
        target_mode: Existing attack-path target mode.
        membership_sample_max: Existing sample setting forwarded to summaries.
        no_cache: When True, bypass cached summary results.
        engine_override: Optional internal engine override to avoid interactive
            engine selection for programmatic prerequisite checks.
        dev_workers_override: Optional worker override paired with
            ``engine_override``.
        render_debug_tables: Whether to render debug attack-path tables during
            the underlying computation.

    Returns:
        Filtered list of summary dicts matching the requested target and, when
        provided, one of the requested terminal relations.
    """
    relation_filters = tuple(
        sorted(
            {
                str(relation or "").strip().lower()
                for relation in (terminal_relations or ())
                if str(relation or "").strip()
            }
        )
    )
    return get_attack_path_summaries(
        shell,
        domain,
        scope="owned",
        max_depth=max_depth,
        max_paths=max_paths,
        target="all",
        target_mode=target_mode,
        summary_filters=AttackPathSummaryFilters(
            target_labels=(target_label,),
            terminal_relations=relation_filters,
        ),
        membership_sample_max=membership_sample_max,
        no_cache=no_cache,
        engine_override=engine_override,
        dev_workers_override=dev_workers_override,
        render_debug_tables=render_debug_tables,
    )


def _build_target_label_index(
    shell: object, domain: str
) -> dict[str, dict[str, Any]]:
    """Return the {label: node} index the target-label filter matches against.

    Same index the attack-path compute builds internally: the membership
    snapshot (users/groups) merged with the attack-graph nodes (domains,
    computers, CAs, OUs). Every label a summary record can terminate at lives
    here, so it is the canonical name-space for resolving ``--target``.
    """
    snapshot = _load_membership_snapshot(shell, domain)
    base_graph = _load_attack_graph_for_paths(shell, domain)
    return _build_snapshot_label_to_node(snapshot, base_graph=base_graph)


def _object_ids_for_label(
    label: str, label_index: dict[str, dict[str, Any]]
) -> set[str]:
    """Return the objectId(s) a canonical label maps to in the graph.

    A node's SID is carried at the top level (``objectId``) or under
    ``properties``. Empty set when the label is unknown or carries no SID.
    """
    node = label_index.get(label)
    if not isinstance(node, dict):
        return set()
    ids: set[str] = set()
    for candidate in (
        node.get("objectId"),
        (node.get("properties") or {}).get("objectId")
        if isinstance(node.get("properties"), dict)
        else None,
    ):
        text = str(candidate or "").strip()
        if text:
            ids.add(text.upper())
    return ids


def _labels_sharing_object_ids(
    object_ids: set[str], label_index: dict[str, dict[str, Any]]
) -> set[str]:
    """Return every label whose node shares one of ``object_ids``.

    This is the multi-label OR resolver: the SAME principal (e.g. a Tier-0
    group) can appear in the graph under both a SID-keyed and a name-keyed
    label, and matching only one silently drops half the paths. Collecting all
    labels that share the SID guarantees the filter ORs both.
    """
    if not object_ids:
        return set()
    matches: set[str] = set()
    for label, node in label_index.items():
        if not isinstance(node, dict):
            continue
        node_ids = _object_ids_for_label(label, label_index)
        if node_ids & object_ids:
            matches.add(label)
    return matches


def _closest_target_candidates(
    user_target: str, label_index: dict[str, dict[str, Any]], *, limit: int = 8
) -> list[str]:
    """Return the labels most similar to a failed ``--target`` for the hint.

    Substring matches first (what the operator most likely meant), then a
    difflib similarity ranking over the remaining labels. Sampled from the real
    graph, never invented (mirrors the debug skill's "don't invent labels" rule).
    """
    import difflib

    needle = str(user_target or "").strip().upper()
    all_labels = sorted(label_index.keys())
    if not needle:
        return all_labels[:limit]

    substring = [label for label in all_labels if needle in label.upper()]
    remaining = [label for label in all_labels if label not in substring]
    fuzzy = difflib.get_close_matches(needle, remaining, n=limit, cutoff=0.4)
    ordered = substring + fuzzy
    return ordered[:limit]


def resolve_target_labels(
    shell: object, domain: str, user_target: str
) -> tuple[str, ...]:
    """Resolve an operator ``--target`` string to canonical graph label(s).

    The attack-path summary filter (``AttackPathSummaryFilters.target_labels``)
    matches summary records by their canonical terminal label. The operator,
    though, types a friendly name (``Domain Admins``, a host, an OU). This is
    the single resolver both the REPL flag and any future caller share, so the
    name-space is defined in exactly one place.

    Resolution ladder (first non-empty result wins, then always widened to all
    SID-twins):

    1. **Exact label** — the operator pasted a canonical label already in the
       graph label index (``DOMAIN ADMINS@ESSOS.LOCAL``, ``DC01$@CORP.LOCAL``,
       an OU distinguished name). Return it as-is.
    2. **Canonical membership label** — normalise the friendly name with the
       membership canonicalizer (handles ``name``, ``NAME@DOMAIN`` and
       ``DOMAIN\\name`` forms) and match it against the index.
    3. **Group-membership index** — if the canonical label is not a direct
       index entry but IS a known group in the membership snapshot, take it
       (a Tier-0 group present in memberships whose graph label form differs).
    4. **Host / OU** — covered by steps 1-2 (host ``SAM$@DOMAIN`` and OU DN both
       flow through the same index), so no special-casing.

    Whatever ladder step matches, the result is widened to EVERY label in the
    index that shares the matched node's objectId (SID). That is the multi-label
    OR guarantee: a group keyed by SID under one node and by name under another
    must return BOTH labels or paths silently vanish.

    Args:
        shell: Active shell/session object.
        domain: Domain whose attack graph defines the label name-space.
        user_target: The operator-supplied target string.

    Returns:
        A tuple of canonical labels (OR-matched by the summary filter). Empty
        when nothing resolves — the caller must then fail loudly with the
        closest-candidate hints from ``_closest_target_candidates`` rather than
        silently returning no paths.
    """
    raw = str(user_target or "").strip()
    if not raw:
        return ()

    label_index = _build_target_label_index(shell, domain)
    if not label_index:
        return ()

    matched: set[str] = set()

    # 1. Exact label match (case-insensitive against the canonical UPPER index).
    upper = raw.upper()
    if upper in label_index:
        matched.add(upper)
    else:
        for label in label_index:
            if label.upper() == upper:
                matched.add(label)
                break

    # 2. Canonical membership label (handles name / NAME@DOMAIN / DOMAIN\name).
    if not matched:
        canonical = _canonical_membership_label_full(domain, raw)
        if canonical and canonical in label_index:
            matched.add(canonical)
        elif canonical:
            for label in label_index:
                if label.upper() == canonical.upper():
                    matched.add(label)
                    break

        # 3. Group-membership index fallback — a group known to the membership
        #    snapshot whose graph label form is not a direct index entry.
        if not matched and canonical:
            snapshot = _load_membership_snapshot(shell, domain)
            try:
                user_members, computer_members, _ = (
                    attack_paths_core.build_group_member_index(snapshot, domain)
                )
            except Exception:  # noqa: BLE001 — best-effort fallback tier
                user_members, computer_members = {}, {}
            group_labels = set(user_members) | set(computer_members)
            for group_label in group_labels:
                if group_label.upper() == canonical.upper():
                    matched.add(group_label)
                    break

    if not matched:
        return ()

    # Widen to every SID-twin so a group present under both a SID-keyed and a
    # name-keyed label is OR-matched (the top correctness risk).
    widened: set[str] = set(matched)
    for label in list(matched):
        widened |= _labels_sharing_object_ids(
            _object_ids_for_label(label, label_index), label_index
        )

    return tuple(sorted(widened))


def _diagnose_zero_domain_paths(
    shell: object,
    domain: str,
    *,
    scope_norm: str,
    username: str | None,
    principals: list[str] | None,
    max_depth: int,
) -> None:
    """Explain why domain-mode returned zero paths.

    Inspects the persisted graph and reports the most likely break point in the
    kill chain so the operator does not have to reverse-engineer empty output.
    """
    try:
        graph = load_attack_graph(shell, domain)
    except Exception as exc:  # noqa: BLE001
        print_warning(
            f"[attack_paths] no paths found in domain mode and graph could not be loaded: {exc}"
        )
        return

    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []

    domain_node_ids = {
        node_id
        for node_id, node in nodes.items()
        if isinstance(node, dict) and _node_is_domain(node)
    }
    tier0_node_ids = {
        node_id
        for node_id, node in nodes.items()
        if isinstance(node, dict) and _node_is_tier0(node)
    }

    dcsync_to_domain = 0
    actionable_to_domain = 0
    actionable_to_domain_relations: dict[str, int] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        to_id = str(edge.get("to") or "").strip()
        if to_id not in domain_node_ids:
            continue
        relation = str(edge.get("relation") or "").strip()
        relation_lc = relation.lower()
        if not _relation_is_actionable_for_source_filter(relation_lc):
            continue
        actionable_to_domain += 1
        actionable_to_domain_relations[relation] = (
            actionable_to_domain_relations.get(relation, 0) + 1
        )
        if relation_lc == "dcsync":
            dcsync_to_domain += 1

    maintenance = (
        graph.get("maintenance") if isinstance(graph.get("maintenance"), dict) else {}
    )
    pruned = int(maintenance.get("tier0_source_attack_edges_pruned") or 0)
    skip_summary = (
        maintenance.get("tier0_source_attack_edge_skips")
        if isinstance(maintenance.get("tier0_source_attack_edge_skips"), dict)
        else {}
    )
    skipped_total = int(skip_summary.get("total") or 0)

    marked_domain = mark_sensitive(domain, "domain")
    print_warning(f"[attack_paths] domain mode returned 0 paths for {marked_domain}")
    print_info(
        "[attack_paths] graph snapshot: "
        f"nodes={len(nodes)} edges={len(edges)} "
        f"domain_nodes={len(domain_node_ids)} tier0_nodes={len(tier0_node_ids)}"
    )
    print_info(
        "[attack_paths] kill-chain terminal edges to Domain: "
        f"actionable={actionable_to_domain} (DCSync={dcsync_to_domain})"
    )
    if actionable_to_domain_relations:
        breakdown = ", ".join(
            f"{rel}={count}"
            for rel, count in sorted(
                actionable_to_domain_relations.items(), key=lambda item: -item[1]
            )
        )
        print_info(f"[attack_paths] terminal-edge relation breakdown: {breakdown}")
    if pruned or skipped_total:
        print_warning(
            "[attack_paths] tier0-source filter activity: "
            f"persisted-edges-pruned={pruned} upsert-skips={skipped_total} "
            "(should be 0 for edges targeting the Domain object)"
        )

    if not domain_node_ids:
        print_error(
            "[attack_paths] no Domain-kind node found in graph — collector did not "
            "ingest the domain object. Re-run BloodHound/native collection."
        )
        return
    if actionable_to_domain == 0:
        print_error(
            "[attack_paths] no actionable edge terminates at the Domain node. "
            "Either no principal holds replication rights (DCSync, GenericAll on "
            "Domain) or the collector did not parse them. Inspect ACLs on the "
            "domain object and confirm GetChanges/GetChangesAll were collected."
        )
        return

    # We do reach the Domain via at least one edge — the break must be earlier.
    try:
        fallback = compute_maximal_attack_paths(
            graph,
            max_depth=max_depth,
            target="highvalue",
            terminal_mode="tier0",
        )
    except Exception as exc:  # noqa: BLE001
        print_warning(
            f"[attack_paths] tier0 fallback compute failed during diagnosis: {exc}"
        )
        return

    print_info(
        "[attack_paths] tier0-mode fallback would have produced "
        f"{len(fallback)} path(s). The break is between tier-0 and Domain — "
        "a tier-0 principal with kill-chain reach exists but is not connected "
        "to the Domain via an actionable edge."
    )

    if scope_norm == "user" and username:
        print_info(
            f"[attack_paths] scope=user username={mark_sensitive(username, 'user')}"
        )
    if scope_norm == "principals" and principals:
        sample = ", ".join(mark_sensitive(str(p or ""), "user") for p in principals[:5])
        print_info(f"[attack_paths] scope=principals sample=[{sample}]")


def _compute_attack_path_summaries_inner(
    shell: object,
    domain: str,
    *,
    scope_norm: str,
    engine: str,
    username: str | None,
    principals: list[str] | None,
    max_depth: int,
    max_paths: int | None,
    target: str,
    target_mode: str,
    summary_filters: AttackPathSummaryFilters | None,
    membership_sample_max: int,
    no_cache: bool,
    display_friendly: bool | None = None,
    keep_longest: bool = False,
    force_perterminal: bool = False,
) -> list[dict[str, Any]]:
    """Inner implementation of compute_attack_path_summaries, engine-dispatched."""
    # Pre-discovery beacon: emit the base graph size + memory situation BEFORE
    # any engine's DFS runs, so a run that OOM-kills DURING discovery (a SIGKILL,
    # which skips the atexit telemetry drain) still leaves a diagnosable record.
    # Best-effort and synchronously flushed inside the helper.
    _emit_attack_path_discovery_started(
        shell,
        domain,
        scope=scope_norm,
        target=target,
        target_mode=target_mode,
    )

    # Stage A of the memory gate — project the graph-resident term BEFORE any DFS
    # runs. This is the only memory signal available pre-DFS; when the graph alone
    # would cross the ceiling, warn (interactive) or block cleanly (non-interactive)
    # now, so the resize-and-re-run remedy surfaces before an hour of DFS. The
    # size read is best-effort; a declared abort propagates to the public entry.
    _stage_a_nodes_count = 0
    _stage_a_edges_count = 0
    _stage_a_graph: Any = None
    _stage_a_nodes: Any = None
    _stage_a_edges: Any = None
    try:
        _stage_a_graph = load_attack_graph(shell, domain)
        _stage_a_nodes = (
            _stage_a_graph.get("nodes") if isinstance(_stage_a_graph, dict) else None
        )
        _stage_a_edges = (
            _stage_a_graph.get("edges") if isinstance(_stage_a_graph, dict) else None
        )
        _stage_a_nodes_count = (
            len(_stage_a_nodes) if isinstance(_stage_a_nodes, (list, dict)) else 0
        )
        _stage_a_edges_count = (
            len(_stage_a_edges) if isinstance(_stage_a_edges, (list, dict)) else 0
        )
    except Exception:  # noqa: BLE001 — the graph-size read is best-effort.
        _stage_a_nodes_count = 0
        _stage_a_edges_count = 0

    # Pre-DFS hybrid switch: run the cheap explosion predictor over the base
    # graph BEFORE the all-simple-paths DFS runs. A dense hub-mesh graph (>= 2
    # control mega-hubs) routes to the BOUNDED per-terminal fallback engine here,
    # so it never pays the ~2M-state DFS abort cost. Completing graphs never carry
    # this signature (Potech = 18 mega-hubs; the most extreme completer = 1;
    # threshold >= 2), so the DFS path stays byte-identical — the predictor must
    # not fire on them. When the predictor fires we ALSO skip the size-linear
    # pre-gate: the fallback is bounded, so the DFS-oriented pre-gate would only
    # abort a run the fallback can complete.
    if not force_perterminal and isinstance(_stage_a_graph, dict):
        if (
            _choose_attack_path_engine(
                {
                    "nodes": (
                        list(_stage_a_nodes.values())
                        if isinstance(_stage_a_nodes, dict)
                        else (_stage_a_nodes or [])
                    ),
                    "edges": _stage_a_edges or [],
                }
            )
            == "fallback"
        ):
            force_perterminal = True
            _record_attack_path_engine_used(
                shell, engine="fallback", reason="predicted_explosion"
            )

    if not force_perterminal:
        _record_attack_path_engine_used(shell, engine="dfs", reason=None)
        # A declared abort from here propagates to get_attack_path_summaries, which
        # records the coverage declaration — do NOT wrap this in a swallowing except.
        # Skipped for the bounded fallback (the size-linear DFS pre-gate does not
        # apply to it).
        _gate_attack_path_memory_pre_dfs(_stage_a_nodes_count, _stage_a_edges_count)

    allow_owned_terminal_target = bool(
        isinstance(summary_filters, AttackPathSummaryFilters)
        and summary_filters.target_labels
    )
    if engine == "rustworkx":
        return _apply_attack_path_summary_filters(
            _compute_rustworkx_display_paths(
                shell,
                domain,
                scope=scope_norm,
                username=username,
                principals=list(principals or []),
                max_depth=max_depth,
                max_paths=max_paths,
                target=target,
                target_mode=target_mode,
                membership_sample_max=membership_sample_max,
                keep_longest=keep_longest,
            ),
            filters=summary_filters,
        )

    _local_t0 = time.perf_counter()
    local_result: list[dict[str, Any]]
    if scope_norm == "domain":
        local_result = compute_display_paths_for_domain(
            shell,
            domain,
            max_depth=max_depth,
            max_paths=max_paths,
            target=target,
            target_mode=target_mode,
            no_cache=no_cache,
            allow_owned_terminal_target=allow_owned_terminal_target,
            display_friendly=display_friendly,
            keep_longest=keep_longest,
            force_perterminal=force_perterminal,
        )
    elif scope_norm == "user":
        if not str(username or "").strip():
            return []
        local_result = compute_display_paths_for_user(
            shell,
            domain,
            username=str(username or "").strip(),
            max_depth=max_depth,
            max_paths=max_paths,
            target=target,
            target_mode=target_mode,
            no_cache=no_cache,
            allow_owned_terminal_target=allow_owned_terminal_target,
            display_friendly=display_friendly,
            force_perterminal=force_perterminal,
        )
    elif scope_norm == "owned":
        local_result = compute_display_paths_for_owned_users(
            shell,
            domain,
            max_depth=max_depth,
            max_paths=max_paths,
            target=target,
            target_mode=target_mode,
            no_cache=no_cache,
            allow_owned_terminal_target=allow_owned_terminal_target,
            display_friendly=display_friendly,
            force_perterminal=force_perterminal,
        )
    elif scope_norm == "principals":
        normalized_principals = [
            str(principal or "").strip()
            for principal in (principals or [])
            if str(principal or "").strip()
        ]
        if not normalized_principals:
            return []
        local_result = compute_display_paths_for_principals(
            shell,
            domain,
            principals=normalized_principals,
            max_depth=max_depth,
            max_paths=max_paths,
            target=target,
            membership_sample_max=membership_sample_max,
            target_mode=target_mode,
            no_cache=no_cache,
            allow_owned_terminal_target=allow_owned_terminal_target,
            display_friendly=display_friendly,
            force_perterminal=force_perterminal,
        )
    else:
        raise ValueError(f"Unsupported attack path summary scope: {scope_norm!r}")
    print_info_debug(
        f"[engine=local-dfs] {len(local_result)} path(s) in {time.perf_counter() - _local_t0:.2f}s"
    )
    if not local_result and str(target_mode or "").strip().lower() == "domain":
        _diagnose_zero_domain_paths(
            shell,
            domain,
            scope_norm=scope_norm,
            username=username,
            principals=principals,
            max_depth=max_depth,
        )
    return _apply_attack_path_summary_filters(
        local_result,
        filters=summary_filters,
    )


def _derive_display_status_from_steps(steps: list[dict[str, Any]]) -> str:
    """Derive a path's display status from its per-step statuses.

    SSOT — the logic (including the ``partial`` signal, doctrine-status
    precedence, and the support-registry fallback) is maintained ONCE in
    :func:`adscan_internal.services.attack_paths_core._derive_display_status_from_steps`.
    This module previously carried a byte-drifting duplicate; it now delegates so
    both display pipelines classify identically.
    """
    return attack_paths_core._derive_display_status_from_steps(steps)  # noqa: SLF001


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
    target: str = "highvalue",
    membership_sample_max: int = 3,
    target_mode: str = "object",
    no_cache: bool = False,
    allow_owned_terminal_target: bool = False,
    display_friendly: bool | None = None,
    force_perterminal: bool = False,
) -> list[dict[str, Any]]:
    """Compute maximal dynamic paths for a list of user principals.

    This is used to implement `attack_paths <domain> owned` without spamming one
    identical membership-originating path per owned user.
    """
    started_at = time.monotonic()
    effective_depth = _effective_max_depth(max_depth, scope="principals", target=target)
    print_info_debug(
        f"[local-pipeline] effective_depth={effective_depth} (requested={max_depth} scope='principals' target={target!r})"
    )
    normalized_principals = [str(p or "").strip().lower() for p in principals]
    normalized_principals = [p for p in normalized_principals if p]
    if not normalized_principals:
        _log_attack_path_compute_timing(
            domain=domain,
            scope="principals",
            elapsed_seconds=max(0.0, time.monotonic() - started_at),
            path_count=0,
            max_depth=effective_depth,
            target=target,
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
            int(effective_depth),
            max_paths,
            target,
            int(membership_sample_max),
            str(target_mode or "object").strip().lower(),
            bool(force_perterminal),
        ),
    )
    cached = _attack_paths_cache_get(
        cache_key, domain=domain, scope="principals", no_cache=no_cache, shell=shell
    )
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
            max_depth=effective_depth,
            target=target,
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

    base_graph = _load_attack_graph_for_paths(shell, domain)
    materialized_artifacts = _load_or_build_materialized_attack_path_artifacts(
        shell,
        domain=domain,
        base_graph=base_graph,
        snapshot=snapshot,
    )
    prepared_graph = _load_or_build_prepared_runtime_graph(
        shell,
        domain=domain,
        base_graph=base_graph,
        snapshot=snapshot,
        expand_terminal_memberships=ATTACK_PATH_EXPAND_TERMINAL_MEMBERSHIPS,
        materialized_artifacts=materialized_artifacts,
    )
    runtime_graph: dict[str, Any] = dict(prepared_graph)
    runtime_graph["nodes"] = dict(
        prepared_graph.get("nodes")
        if isinstance(prepared_graph.get("nodes"), dict)
        else {}
    )
    runtime_graph["edges"] = list(
        prepared_graph.get("edges")
        if isinstance(prepared_graph.get("edges"), list)
        else []
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
        materialized_artifacts=materialized_artifacts,
    )
    _dfs_t0 = time.monotonic()
    records = _sort_display_paths(
        attack_paths_core.compute_display_paths_for_principals(
            runtime_graph,
            domain=domain,
            snapshot=snapshot,
            principals=unique_principals,
            max_depth=effective_depth,
            max_paths=max_paths,
            target=target,
            membership_sample_max=membership_sample_max,
            target_mode=target_mode,
            filter_shortest_paths=False,
            force_perterminal=force_perterminal,
        )
    )
    _dfs_elapsed = time.monotonic() - _dfs_t0
    print_info_debug(
        f"[engine=local-dfs] dfs={_dfs_elapsed:.3f}s ({len(records)} raw paths, scope=principals)"
    )
    records = _filter_zero_length_display_paths(
        records, domain=domain, scope="principals"
    )
    records = _apply_local_postprocessing_pipeline(
        records,
        shell=shell,
        domain=domain,
        scope="principals",
        target=target,
        snapshot=snapshot,
        principal_count=len(unique_principals),
        owned_labels=frozenset(_normalize_account(p) for p in unique_principals),
        allow_owned_terminal_target=allow_owned_terminal_target,
        target_mode=target_mode,
        display_friendly=display_friendly,
        runtime_graph=runtime_graph,
    )
    _total_elapsed = max(0.0, time.monotonic() - started_at)
    print_info_debug(
        f"[engine=local-dfs] dfs={_dfs_elapsed:.3f}s | post={max(0.0, _total_elapsed - _dfs_elapsed):.3f}s"
        f" | total={_total_elapsed:.3f}s ({len(records)} paths, scope=principals)"
    )
    _log_attack_path_compute_timing(
        domain=domain,
        scope="principals",
        elapsed_seconds=_total_elapsed,
        path_count=len(records),
        max_depth=effective_depth,
        target=target,
        target_mode=target_mode,
    )
    _attack_paths_cache_put(
        cache_key,
        records,
        domain=domain,
        scope="principals",
        compute_seconds=_total_elapsed,
        shell=shell,
        no_cache=no_cache,
    )
    return records
