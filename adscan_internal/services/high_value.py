"""ADscan control-exposure helpers.

This module centralizes best-effort logic for determining whether an identity
has direct domain control or broader control exposure under ADscan semantics.

Callers sometimes have a fully-resolved attack-graph node, and sometimes only
have a user identifier (samAccountName/label). Provide both APIs:
- node-based predicates (pure, no shell access)
- shell+domain-based predicates (best-effort lookup via attack_graph.json and
  optional fallbacks).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from adscan_internal import print_info_debug, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.identity_risk_service import (
    CONTROL_EXPOSURE_IDENTITIES_FILENAME,
    get_identity_risk_record,
)


def normalize_samaccountname(value: str) -> str:
    """Normalize a principal label into a samAccountName-like value."""
    name = (value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def is_node_tier0(node: dict[str, Any]) -> bool:
    """Return True if an attack-graph node is Tier-0."""
    if not isinstance(node, dict):
        return False
    if bool(node.get("isTierZero")):
        return True
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if bool(props.get("isTierZero")):
        return True
    tags = node.get("system_tags") or props.get("system_tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return any(str(tag).strip().lower() == "admin_tier_0" for tag in tags)


def is_node_high_value(node: dict[str, Any]) -> bool:
    """Return True if an attack-graph node is high-value (impact).

    Note: this intentionally does not imply Tier-0. Tier-0 is a separate predicate.
    """
    if not isinstance(node, dict):
        return False
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    return bool(node.get("highvalue") or props.get("highvalue"))


def is_node_tier0_or_high_value(node: dict[str, Any]) -> bool:
    """Return True if a node is Tier-0 or high-value."""
    return bool(is_node_tier0(node) or is_node_high_value(node))


@dataclass(frozen=True)
class UserRiskFlags:
    """ADscan control-exposure classification flags for a user."""

    is_tier0: bool = False
    is_high_value: bool = False


def _find_user_node_in_attack_graph(
    shell: object,
    *,
    domain: str,
    samaccountname: str,
) -> dict[str, Any] | None:
    """Best-effort: locate a User node for a given samAccountName in attack_graph.json."""
    try:
        from adscan_internal.services.attack_graph_service import load_attack_graph
    except Exception:  # noqa: BLE001
        return None

    normalized_sam = normalize_samaccountname(samaccountname)
    if not normalized_sam:
        return None

    try:
        graph = load_attack_graph(shell, domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None

    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not isinstance(nodes_map, dict) or not nodes_map:
        return None

    candidate_labels = {
        normalized_sam.upper(),
        f"{normalized_sam.upper()}@{domain.strip().upper()}",
    }

    for node in nodes_map.values():
        if not isinstance(node, dict):
            continue
        if str(node.get("kind") or "") != "User":
            continue

        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )

        node_sam = props.get("samaccountname")
        if (
            isinstance(node_sam, str)
            and normalize_samaccountname(node_sam) == normalized_sam
        ):
            return node

        label = str(node.get("label") or "").strip()
        if not label:
            continue
        label_left = label.split("@", 1)[0].strip().upper()
        if label in candidate_labels or label_left in candidate_labels:
            return node

    return None


def _debug_resolve_source(
    *,
    domain: str,
    samaccountname: str,
    source: str,
    detail: str | None = None,
) -> None:
    """Central debug log helper for resolution sources."""
    try:
        marked_domain = mark_sensitive(domain, "domain")
        marked_user = mark_sensitive(samaccountname, "user")
        suffix = f" detail={detail}" if detail else ""
        print_info_debug(
            f"[high-value] resolve user node: domain={marked_domain} user={marked_user} source={source}{suffix}"
        )
    except Exception:
        pass


def _try_user_node_from_bloodhound(
    shell: Any,
    *,
    domain: str,
    samaccountname: str,
) -> dict[str, Any] | None:
    """Best-effort: resolve a user node via the BloodHound service if available."""
    normalized_sam = normalize_samaccountname(samaccountname)
    if not normalized_sam:
        return None
    try:
        service = shell._get_bloodhound_service()  # type: ignore[attr-defined]
        resolver = getattr(service, "get_user_node_by_samaccountname", None)
        if callable(resolver):
            node = resolver(domain, normalized_sam)
            if isinstance(node, dict):
                _debug_resolve_source(
                    domain=domain, samaccountname=normalized_sam, source="bloodhound_ce"
                )
                return node
            _debug_resolve_source(
                domain=domain,
                samaccountname=normalized_sam,
                source="bloodhound_ce",
                detail="resolver returned non-dict",
            )
            return None
        _debug_resolve_source(
            domain=domain,
            samaccountname=normalized_sam,
            source="bloodhound_ce",
            detail="resolver unavailable",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        _debug_resolve_source(
            domain=domain,
            samaccountname=normalized_sam,
            source="bloodhound_ce",
            detail=f"exception={type(exc).__name__}",
        )
    return None


def _load_cached_user_list_file(
    shell: Any,
    *,
    domain: str,
    filename: str,
) -> set[str] | None:
    """Load a cached user list file under the workspace domain directory.

    These files are generated during Phase 1 (BloodHound CE queries) and are
    intended as a fast offline lookup before falling back to heavier methods.

    Args:
        shell: Shell instance (expected to expose `current_workspace_dir` and `domains_dir`).
        domain: Target domain.
        filename: File to load (e.g., "admins.txt").

    Returns:
        A set of normalized samAccountName values when the file exists, otherwise None.
    """
    try:
        from adscan_internal.workspaces import domain_subpath
    except Exception:  # noqa: BLE001
        return None

    domains_dir = str(getattr(shell, "domains_dir", "domains") or "domains")
    workspace_cwd = getattr(shell, "current_workspace_dir", None) or os.getcwd()

    users_file = domain_subpath(workspace_cwd, domains_dir, domain, filename)
    if not os.path.exists(users_file):
        return None

    try:
        with open(users_file, "r", encoding="utf-8", errors="ignore") as f:
            raw_lines = [line.strip() for line in f if line.strip()]
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None

    normalized: set[str] = set()
    for line in raw_lines:
        sam = normalize_samaccountname(str(line))
        if sam:
            normalized.add(sam)
    return normalized


def _is_user_in_cached_user_list_file(
    shell: Any,
    *,
    domain: str,
    samaccountname: str,
    filename: str,
) -> bool | None:
    """Return True/False if cache file exists, otherwise None (unknown)."""
    normalized_sam = normalize_samaccountname(samaccountname)
    if not normalized_sam:
        return False

    cached = _load_cached_user_list_file(shell, domain=domain, filename=filename)
    if cached is None:
        return None
    return normalized_sam in cached


def is_user_tier0(shell: Any, *, domain: str, samaccountname: str) -> bool:
    """Return True if the user is Tier-0 (best-effort)."""
    normalized_sam = normalize_samaccountname(samaccountname)
    if not normalized_sam:
        return False

    identity_record = get_identity_risk_record(
        shell,
        domain=domain,
        samaccountname=normalized_sam,
    )
    if isinstance(identity_record, dict):
        return bool(identity_record.get("has_direct_domain_control"))

    node = _find_user_node_in_attack_graph(
        shell, domain=domain, samaccountname=normalized_sam
    )
    if node is not None:
        _debug_resolve_source(
            domain=domain, samaccountname=normalized_sam, source="attack_graph"
        )
    if node is None:
        node = _try_user_node_from_bloodhound(
            shell, domain=domain, samaccountname=normalized_sam
        )

    if node is not None:
        result = is_node_tier0(node)
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        print_info_debug(
            "[high-value] tier0 check: "
            f"user={mark_sensitive(normalized_sam, 'user')} "
            f"node_label={mark_sensitive(str(node.get('label') or 'N/A'), 'node')} "
            f"isTierZero={bool(node.get('isTierZero') or props.get('isTierZero'))!r} "
            f"result={result!r}"
        )
        return result

    # Snapshot fallback for Tier-0 privileged groups (Domain/Enterprise/Schema Admins).
    try:
        from adscan_internal.services.attack_graph_service import (
            is_principal_member_of_rid_from_snapshot,
        )

        for rid in (512, 518, 519):
            rid_result = is_principal_member_of_rid_from_snapshot(
                shell,
                domain,
                normalized_sam,
                rid,
            )
            if rid_result is True:
                _debug_resolve_source(
                    domain=domain,
                    samaccountname=normalized_sam,
                    source="membership_snapshot",
                    detail=f"rid={rid}",
                )
                return True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    _debug_resolve_source(
        domain=domain,
        samaccountname=normalized_sam,
        source="unresolved",
        detail="tier0: no node and no snapshot match",
    )
    return False


def is_user_high_value(shell: Any, *, domain: str, samaccountname: str) -> bool:
    """Return True if the user is high-value (impact), best-effort."""
    normalized_sam = normalize_samaccountname(samaccountname)
    if not normalized_sam:
        return False

    identity_record = get_identity_risk_record(
        shell,
        domain=domain,
        samaccountname=normalized_sam,
    )
    if isinstance(identity_record, dict):
        return bool(identity_record.get("is_control_exposed"))

    node = _find_user_node_in_attack_graph(
        shell, domain=domain, samaccountname=normalized_sam
    )
    if node is not None:
        _debug_resolve_source(
            domain=domain, samaccountname=normalized_sam, source="attack_graph"
        )
    if node is None:
        node = _try_user_node_from_bloodhound(
            shell, domain=domain, samaccountname=normalized_sam
        )

    if node is not None:
        result = is_node_high_value(node)
        props = (
            node.get("properties") if isinstance(node.get("properties"), dict) else {}
        )
        print_info_debug(
            "[high-value] highvalue check: "
            f"user={mark_sensitive(normalized_sam, 'user')} "
            f"node_label={mark_sensitive(str(node.get('label') or 'N/A'), 'node')} "
            f"highvalue={bool(node.get('highvalue') or props.get('highvalue'))!r} "
            f"result={result!r}"
        )
        return result

    # Snapshot fallback for "impact" groups is intentionally conservative. Keep False.
    _debug_resolve_source(
        domain=domain,
        samaccountname=normalized_sam,
        source="unresolved",
        detail="highvalue: no node",
    )
    return False


def is_user_tier0_or_high_value(
    shell: Any, *, domain: str, samaccountname: str
) -> bool:
    """Return True if the user is Tier-0 or high-value (best-effort)."""
    normalized_sam = normalize_samaccountname(samaccountname)
    if not normalized_sam:
        return False

    # Fast-path: Phase 1 writes the ADscan control-exposure union list.
    # Use it as a positive-only cache to avoid unnecessary BloodHound queries.
    cached_hit = _is_user_in_cached_user_list_file(
        shell,
        domain=domain,
        samaccountname=normalized_sam,
        filename=CONTROL_EXPOSURE_IDENTITIES_FILENAME,
    )
    if cached_hit is True:
        _debug_resolve_source(
            domain=domain,
            samaccountname=normalized_sam,
            source="user_list_files",
            detail="control_exposure_identities hit",
        )
        return True

    return bool(
        is_user_tier0(shell, domain=domain, samaccountname=normalized_sam)
        or is_user_high_value(shell, domain=domain, samaccountname=normalized_sam)
    )


def classify_users_tier0_high_value(
    shell: Any, *, domain: str, usernames: list[str]
) -> dict[str, UserRiskFlags]:
    """Classify many users as Tier-0/high-value in a single pass.

    This helper is optimized for batch flows (for example DCSync summaries),
    avoiding repeated graph loads and repetitive membership snapshot calls.

    Resolution order:
    1) Attack-graph User nodes (single graph load)
    2) Membership snapshot RID checks (512/518/519) for unresolved Tier-0 users
    3) Cached ``admins.txt`` positive matches for unresolved high-value users

    Args:
        shell: Shell-like object with workspace/BloodHound context.
        domain: Target AD domain.
        usernames: Candidate usernames/principals to classify.

    Returns:
        Mapping keyed by normalized samAccountName. Each value contains
        Tier-0/high-value flags.
    """
    normalized_user_set: set[str] = set()
    for username in usernames:
        normalized = normalize_samaccountname(str(username))
        if normalized:
            normalized_user_set.add(normalized)
    normalized_users = sorted(normalized_user_set, key=str.lower)
    if not normalized_users:
        return {}

    results: dict[str, dict[str, bool]] = {
        user: {"is_tier0": False, "is_high_value": False} for user in normalized_users
    }

    for user in normalized_users:
        identity_record = get_identity_risk_record(
            shell,
            domain=domain,
            samaccountname=user,
        )
        if not isinstance(identity_record, dict):
            continue
        results[user]["is_tier0"] = bool(
            identity_record.get("has_direct_domain_control")
        )
        results[user]["is_high_value"] = bool(identity_record.get("is_control_exposed"))

    # Pass 1: attack_graph.json (single load) for unresolved users.
    try:
        from adscan_internal.services.attack_graph_service import load_attack_graph

        graph = load_attack_graph(shell, domain)
        nodes_map = graph.get("nodes") if isinstance(graph, dict) else None
        if isinstance(nodes_map, dict):
            for node in nodes_map.values():
                if not isinstance(node, dict):
                    continue
                if str(node.get("kind") or "") != "User":
                    continue

                props = (
                    node.get("properties")
                    if isinstance(node.get("properties"), dict)
                    else {}
                )
                candidates: set[str] = set()

                node_sam = props.get("samaccountname")
                if isinstance(node_sam, str):
                    normalized = normalize_samaccountname(node_sam)
                    if normalized:
                        candidates.add(normalized)

                label = str(node.get("label") or "").strip()
                if label:
                    normalized = normalize_samaccountname(label)
                    if normalized:
                        candidates.add(normalized)

                candidates &= set(results)
                unresolved_candidates = {
                    candidate
                    for candidate in candidates
                    if not results[candidate]["is_tier0"]
                    and not results[candidate]["is_high_value"]
                }
                if not unresolved_candidates:
                    continue

                is_tier0_user = is_node_tier0(node)
                is_high_value_user = is_node_high_value(node)
                if not is_tier0_user and not is_high_value_user:
                    continue

                for candidate in unresolved_candidates:
                    if is_tier0_user:
                        results[candidate]["is_tier0"] = True
                    if is_high_value_user:
                        results[candidate]["is_high_value"] = True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    # Pass 2: memberships snapshot RID fallback for unresolved Tier-0 users.
    unresolved_tier0 = {
        user for user, flags in results.items() if not bool(flags.get("is_tier0"))
    }
    if unresolved_tier0:
        try:
            from adscan_internal.services.attack_graph_service import (
                get_users_in_group_rid_from_snapshot,
            )

            tier0_members: set[str] = set()
            for rid in (512, 518, 519):
                members = get_users_in_group_rid_from_snapshot(shell, domain, rid)
                if not members:
                    continue
                for member in members:
                    normalized = normalize_samaccountname(member)
                    if normalized:
                        tier0_members.add(normalized)

            for user in unresolved_tier0:
                if user in tier0_members:
                    results[user]["is_tier0"] = True
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

    # Pass 3: positive-only control-exposure cache fallback.
    unresolved_high_value = {
        user
        for user, flags in results.items()
        if not bool(flags.get("is_tier0")) and not bool(flags.get("is_high_value"))
    }
    if unresolved_high_value:
        cached_admins = _load_cached_user_list_file(
            shell,
            domain=domain,
            filename=CONTROL_EXPOSURE_IDENTITIES_FILENAME,
        )
        if cached_admins:
            for user in unresolved_high_value:
                if user in cached_admins:
                    results[user]["is_high_value"] = True

    tier0_count = sum(1 for flags in results.values() if flags["is_tier0"])
    high_value_only_count = sum(
        1
        for flags in results.values()
        if flags["is_high_value"] and not flags["is_tier0"]
    )
    print_info_debug(
        "[high-value] batch classify: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"users={len(results)} tier0={tier0_count} high_value_only={high_value_only_count}"
    )

    return {
        user: UserRiskFlags(
            is_tier0=bool(flags["is_tier0"]),
            is_high_value=bool(flags["is_high_value"]),
        )
        for user, flags in results.items()
    }
