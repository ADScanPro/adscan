"""Membership snapshot loading and caching helpers."""

from __future__ import annotations

import os
from typing import Any, Callable

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_exception,
    print_info_debug,
)
from adscan_internal.workspaces import domain_subpath, read_json_file, write_json_file
from adscan_internal.services import attack_paths_core
from adscan_internal.services.cache_metrics import (
    copy_stats,
    increment_stats,
    reset_stats,
)

_MEMBERSHIP_SNAPSHOT_CACHE: dict[str, dict[str, Any] | None] = {}
_MEMBERSHIP_SNAPSHOT_CACHE_LOGGED: set[str] = set()
_MEMBERSHIP_SNAPSHOT_MTIME: dict[str, float | None] = {}
_MEMBERSHIP_SNAPSHOT_STATS: dict[str, int] = {
    "hits": 0,
    "misses": 0,
    "reloads": 0,
    "loaded": 0,
}


def get_membership_snapshot_cache_stats(*, reset: bool = False) -> dict[str, int]:
    """Return memberships.json cache counters."""
    stats = copy_stats(_MEMBERSHIP_SNAPSHOT_STATS)
    if reset:
        reset_stats(_MEMBERSHIP_SNAPSHOT_STATS)
    return stats


def snapshot_has_sid_metadata(snapshot: dict[str, Any] | None) -> bool:
    """Return True when snapshot has SID metadata needed for RID lookups."""
    if not isinstance(snapshot, dict):
        return False
    label_to_sid = snapshot.get("label_to_sid")
    domain_sid = snapshot.get("domain_sid")
    has_label_map = isinstance(label_to_sid, dict) and bool(label_to_sid)
    has_domain_sid = isinstance(domain_sid, str) and bool(domain_sid)
    return has_label_map or has_domain_sid


def membership_snapshot_path(shell: object, domain: str) -> str:
    """Resolve memberships.json path for a domain."""
    workspace_cwd = (
        shell._get_workspace_cwd()  # type: ignore[attr-defined]
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", os.getcwd())
    )
    domains_dir = getattr(shell, "domains_dir", "domains")
    path = domain_subpath(workspace_cwd, domains_dir, domain, "memberships.json")
    return path


def _canonical_membership_label(domain: str, value: str) -> str:
    """Return the canonical ``NAME@DOMAIN`` membership label."""
    raw = str(value or "").strip()
    domain_clean = str(domain or "").strip()
    if not raw:
        return ""
    if "\\" in raw:
        raw_domain, _, raw_name = raw.partition("\\")
        raw = raw_name or raw
        if raw_domain and "." in raw_domain:
            domain_clean = raw_domain
    if "@" in raw:
        left, _, right = raw.partition("@")
        if left and right:
            return f"{left.strip().upper()}@{right.strip().upper()}"
    if not domain_clean:
        return raw.strip().upper()
    return f"{raw.strip().upper()}@{domain_clean.upper()}"


def _invalidate_membership_snapshot_cache(domain: str) -> None:
    """Invalidate in-memory cache for one domain after a snapshot mutation."""
    domain_key = str(domain or "").strip().lower()
    if not domain_key:
        return
    _MEMBERSHIP_SNAPSHOT_CACHE.pop(domain_key, None)
    _MEMBERSHIP_SNAPSHOT_MTIME.pop(domain_key, None)
    _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED.discard(domain_key)


def add_runtime_user_group_membership(
    shell: object,
    domain: str,
    *,
    username: str,
    group_name: str,
    source: str,
    evidence: dict[str, Any] | None = None,
) -> bool:
    """Persist an effective runtime user-to-group membership in ``memberships.json``.

    This helper is intended for attack outcomes that create effective access for
    ADscan's graph engine without necessarily changing the LDAP ``memberOf``
    attribute, for example ESC13 PAC group authorization from a certificate.

    Args:
        shell: Shell object used to resolve the workspace path.
        domain: AD domain.
        username: User receiving effective membership.
        group_name: Group that should be considered effective for path search.
        source: Short source identifier for auditability.
        evidence: Optional structured evidence to persist.

    Returns:
        True when the snapshot was created or updated, otherwise False.
    """
    user_label = _canonical_membership_label(domain, username)
    group_label = _canonical_membership_label(domain, group_name)
    if not user_label or not group_label:
        return False

    path = membership_snapshot_path(shell, domain)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = read_json_file(path) if os.path.exists(path) else {}
    if not isinstance(data, dict):
        data = {}

    user_to_groups = data.setdefault("user_to_groups", {})
    if not isinstance(user_to_groups, dict):
        user_to_groups = {}
        data["user_to_groups"] = user_to_groups

    current_groups = user_to_groups.setdefault(user_label, [])
    if not isinstance(current_groups, list):
        current_groups = []
        user_to_groups[user_label] = current_groups

    changed = False
    if group_label not in current_groups:
        current_groups.append(group_label)
        current_groups.sort(key=str.lower)
        changed = True

    group_labels = data.setdefault("group_labels", [])
    if not isinstance(group_labels, list):
        group_labels = []
        data["group_labels"] = group_labels
    if group_label not in group_labels:
        group_labels.append(group_label)
        group_labels.sort(key=str.lower)
        changed = True

    data.setdefault("computer_to_groups", {})
    data.setdefault("group_to_parents", {})
    data.setdefault("label_to_sid", {})
    data.setdefault("sid_to_label", {})

    runtime_memberships = data.setdefault("runtime_memberships", [])
    if not isinstance(runtime_memberships, list):
        runtime_memberships = []
        data["runtime_memberships"] = runtime_memberships
    runtime_key = (user_label, group_label, str(source or "").strip())
    existing_runtime = {
        (
            str(item.get("user") or ""),
            str(item.get("group") or ""),
            str(item.get("source") or ""),
        )
        for item in runtime_memberships
        if isinstance(item, dict)
    }
    if runtime_key not in existing_runtime:
        runtime_memberships.append(
            {
                "user": user_label,
                "group": group_label,
                "source": str(source or "runtime").strip() or "runtime",
                "evidence": evidence or {},
            }
        )
        changed = True

    if not changed:
        return False

    write_json_file(path, data)
    _invalidate_membership_snapshot_cache(domain)
    print_info_debug(
        "[membership] runtime membership persisted: "
        f"user={mark_sensitive(user_label, 'user')} "
        f"group={mark_sensitive(group_label, 'group')} "
        f"source={mark_sensitive(str(source), 'detail')} "
        f"path={mark_sensitive(path, 'path')}"
    )
    return True


def load_membership_snapshot(
    shell: object,
    domain: str,
    *,
    augment_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Load memberships.json with caching and optional augmentation."""
    domain_key = str(domain or "").strip().lower()
    if not domain_key:
        return None
    if domain_key in _MEMBERSHIP_SNAPSHOT_CACHE:
        increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "hits")
        cached = _MEMBERSHIP_SNAPSHOT_CACHE[domain_key]
        cached_mtime = _MEMBERSHIP_SNAPSHOT_MTIME.get(domain_key)
        path = membership_snapshot_path(shell, domain)
        file_exists = os.path.exists(path)
        file_mtime = os.path.getmtime(path) if file_exists else None
        if cached is not None and not file_exists:
            print_info_debug(
                f"[membership] snapshot cache hit: domain={domain_key} value=loaded "
                f"but file missing at path={path}; invalidating cache."
            )
            _MEMBERSHIP_SNAPSHOT_CACHE.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_MTIME.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED.discard(domain_key)
            increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "reloads")
            return load_membership_snapshot(shell, domain, augment_fn=augment_fn)
        if cached is None and file_exists:
            print_info_debug(
                f"[membership] snapshot cache hit: domain={domain_key} value=none "
                f"but file now exists; invalidating cache (path={path})."
            )
            _MEMBERSHIP_SNAPSHOT_CACHE.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_MTIME.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED.discard(domain_key)
            increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "reloads")
            return load_membership_snapshot(shell, domain, augment_fn=augment_fn)
        if (
            cached is not None
            and file_mtime
            and cached_mtime
            and file_mtime != cached_mtime
        ):
            print_info_debug(
                f"[membership] snapshot cache stale for {domain_key}; file changed "
                f"(old_mtime={cached_mtime}, new_mtime={file_mtime}). Reloading."
            )
            _MEMBERSHIP_SNAPSHOT_CACHE.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_MTIME.pop(domain_key, None)
            _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED.discard(domain_key)
            increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "reloads")
            return load_membership_snapshot(shell, domain, augment_fn=augment_fn)
        if domain_key not in _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED:
            print_info_debug(
                f"[membership] snapshot cache hit: domain={domain_key} "
                f"value={'loaded' if cached else 'none'}"
            )
            _MEMBERSHIP_SNAPSHOT_CACHE_LOGGED.add(domain_key)
        if cached and not snapshot_has_sid_metadata(cached) and augment_fn:
            print_info_debug(
                f"[membership] snapshot cache missing SID metadata for {domain_key}; "
                "augmenting from attack_graph.json."
            )
            cached = augment_fn(cached)
            _MEMBERSHIP_SNAPSHOT_CACHE[domain_key] = cached
        return cached

    path = membership_snapshot_path(shell, domain)
    if not os.path.exists(path):
        increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "misses")
        print_info_debug(
            f"[membership] snapshot cache miss: domain={domain_key} "
            f"file_missing=True path={path}"
        )
        _MEMBERSHIP_SNAPSHOT_CACHE[domain_key] = None
        _MEMBERSHIP_SNAPSHOT_MTIME[domain_key] = None
        return None
    data = read_json_file(path)
    if not isinstance(data, dict):
        increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "misses")
        _MEMBERSHIP_SNAPSHOT_CACHE[domain_key] = None
        _MEMBERSHIP_SNAPSHOT_MTIME[domain_key] = None
        return None
    if not data:
        print_info_debug(
            f"[membership] snapshot JSON is empty for {domain_key}: path={path}"
        )

    snapshot = attack_paths_core.prepare_membership_snapshot(data, domain)
    if snapshot is None:
        print_info_debug(
            f"[membership] snapshot normalization failed for {domain_key}; "
            f"raw_keys={sorted(data.keys())} path={path}"
        )
    if snapshot and not snapshot_has_sid_metadata(snapshot) and augment_fn:
        print_info_debug(
            f"[membership] snapshot missing SID metadata for {domain_key}; "
            "augmenting from attack_graph.json."
        )
        snapshot = augment_fn(snapshot)
    if snapshot:
        increment_stats(_MEMBERSHIP_SNAPSHOT_STATS, "loaded")
        domain_sid = snapshot.get("domain_sid")
        generated_at = data.get("generated_at") if isinstance(data, dict) else None
        print_info_debug(
            f"[membership] snapshot loaded: domain={domain_key} path={path} "
            f"keys={sorted(snapshot.keys())} domain_sid={domain_sid or 'unset'}"
        )
        if generated_at:
            print_info_debug(
                f"[membership] snapshot generated_at for {domain_key}: {generated_at}"
            )
        if (
            isinstance(domain_sid, str)
            and domain_sid
            and hasattr(shell, "domains_data")
            and isinstance(shell.domains_data, dict)
        ):
            domain_entry = shell.domains_data.get(domain)
            if isinstance(domain_entry, dict):
                stored_sid = domain_entry.get("domain_sid")
                if stored_sid != domain_sid:
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
    _MEMBERSHIP_SNAPSHOT_CACHE[domain_key] = snapshot
    _MEMBERSHIP_SNAPSHOT_MTIME[domain_key] = os.path.getmtime(path)
    return snapshot


__all__ = [
    "add_runtime_user_group_membership",
    "get_membership_snapshot_cache_stats",
    "load_membership_snapshot",
    "membership_snapshot_path",
    "snapshot_has_sid_metadata",
]
