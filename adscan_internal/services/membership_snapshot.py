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


def _invalidate_pac_for_membership_change(
    *,
    domain: str,
    user_label: str,
    group_label: str,
    action: str,
) -> None:
    """Notify the credential registry that a runtime group membership changed.

    AD builds the access token from the PAC inside the requesting user's TGT.
    A TGT minted before this membership change will not contain the new group
    SID, so subsequent operations using the cached ccache will be evaluated
    against an outdated token (classic ``insufficientAccessRights`` after a
    successful AddMember).  Bumping the realm-wide epoch forces every
    :class:`CredentialContext` bound to this realm to re-AS-REQ on its next
    bind.  Per-realm (rather than per-principal) invalidation is intentional:
    the principal whose PAC needs refreshing is most often **not** the user
    being added (it is the executor, who may be a transitive member of the
    target group).  Realm-wide is the conservative correct answer.
    """
    try:
        from adscan_internal.services.auth import get_credential_registry

        registry = get_credential_registry()
        registry.invalidate_domain(
            domain,
            reason=f"membership_{action}:{user_label}->{group_label}",
        )
        # Cross-domain: also bump the per-principal slot keyed by the user
        # label so a TGT whose realm differs from the membership realm (e.g.
        # user@domA added to group in domB) sees the timestamp bump too.
        registry.invalidate(
            user_label,
            domain,
            reason=f"membership_{action}_principal:{group_label}",
        )
    except Exception:  # noqa: BLE001 — never let registry failures break writes
        from adscan_internal.rich_output import print_info_debug

        print_info_debug(
            "[membership] credential registry unavailable; skipping PAC invalidation"
        )



def _normalize_runtime_membership_metadata(
    *,
    source: str,
    evidence: dict[str, Any] | None = None,
    origin_kind: str | None = None,
    origin_technique: str | None = None,
    origin_relation: str | None = None,
    cleanup_behavior: str | None = None,
    managed_by_adscan: bool = True,
) -> dict[str, Any]:
    """Return a stable provenance schema for runtime memberships."""
    evidence_dict = evidence if isinstance(evidence, dict) else {}
    source_value = str(source or "runtime").strip() or "runtime"
    normalized_origin_kind = str(
        origin_kind
        or evidence_dict.get("origin_kind")
        or ("runtime_effective" if source_value == "adcs_esc13" else "directory_write")
    ).strip()
    normalized_origin_technique = str(
        origin_technique
        or evidence_dict.get("origin_technique")
        or (
            "esc13"
            if source_value == "adcs_esc13"
            else str(evidence_dict.get("action") or "group_membership_change")
        )
    ).strip()
    normalized_origin_relation = str(
        origin_relation
        or evidence_dict.get("origin_relation")
        or ("ADCSESC13" if source_value == "adcs_esc13" else "AddMember")
    ).strip()
    normalized_cleanup_behavior = str(
        cleanup_behavior
        or evidence_dict.get("cleanup_behavior")
        or (
            "remove_runtime_only"
            if source_value == "adcs_esc13"
            else "remove_directory_and_runtime"
        )
    ).strip()
    return {
        "source": source_value,
        "managed_by_adscan": bool(managed_by_adscan),
        "origin_kind": normalized_origin_kind,
        "origin_technique": normalized_origin_technique,
        "origin_relation": normalized_origin_relation,
        "cleanup_behavior": normalized_cleanup_behavior,
        "evidence": evidence_dict,
    }


def add_runtime_user_group_membership(
    shell: object,
    domain: str,
    *,
    username: str,
    group_name: str,
    source: str,
    evidence: dict[str, Any] | None = None,
    origin_kind: str | None = None,
    origin_technique: str | None = None,
    origin_relation: str | None = None,
    cleanup_behavior: str | None = None,
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
    metadata = _normalize_runtime_membership_metadata(
        source=source,
        evidence=evidence,
        origin_kind=origin_kind,
        origin_technique=origin_technique,
        origin_relation=origin_relation,
        cleanup_behavior=cleanup_behavior,
    )
    runtime_key = (
        user_label,
        group_label,
        str(metadata.get("source") or "").strip(),
        str(metadata.get("origin_relation") or "").strip(),
    )
    existing_runtime = {
        (
            str(item.get("user") or ""),
            str(item.get("group") or ""),
            str(item.get("source") or ""),
            str(item.get("origin_relation") or ""),
        )
        for item in runtime_memberships
        if isinstance(item, dict)
    }
    if runtime_key not in existing_runtime:
        runtime_memberships.append(
            {
                "user": user_label,
                "group": group_label,
                **metadata,
            }
        )
        changed = True

    if not changed:
        return False

    write_json_file(path, data)
    _invalidate_membership_snapshot_cache(domain)
    _invalidate_pac_for_membership_change(
        domain=domain,
        user_label=user_label,
        group_label=group_label,
        action="add",
    )
    print_info_debug(
        "[membership] runtime membership persisted: "
        f"user={mark_sensitive(user_label, 'user')} "
        f"group={mark_sensitive(group_label, 'group')} "
        f"source={mark_sensitive(str(source), 'detail')} "
        f"path={mark_sensitive(path, 'path')}"
    )
    return True



def add_runtime_computer_group_membership(
    shell: object,
    domain: str,
    *,
    computer_name: str,
    group_rid: int = 515,
    group_name: str | None = None,
    source: str,
    evidence: dict[str, Any] | None = None,
    origin_kind: str | None = None,
    origin_technique: str | None = None,
    origin_relation: str | None = None,
    cleanup_behavior: str | None = None,
) -> bool:
    """Persist an effective runtime computer-to-group membership in ``memberships.json``.

    Companion to :func:`add_runtime_user_group_membership` for Computer
    principals.  Intended for ADscan-created machine accounts (e.g. RBCD
    attacker machines) that did not exist when the collector built the
    snapshot — without this injection, every subsequent attack-path render
    falls back to LDAP queries that return 0 results because computer
    primary-group memberships live in ``primaryGroupID`` (not in the
    ``member`` attribute).

    The default ``group_rid=515`` (Domain Computers) matches the SAMR
    convention for new machine accounts created via
    ``hSamrCreateUser2InDomain`` with ``USER_WORKSTATION_TRUST_ACCOUNT`` —
    Windows assigns ``primaryGroupID=515`` automatically.  When the
    snapshot already knows this group's label via ``sid_to_label`` we use
    that exact label; otherwise we fall back to the canonical synthetic
    label or the explicitly-supplied ``group_name``.

    Args:
        shell: Shell object used to resolve the workspace path.
        domain: AD domain.
        computer_name: ``sAMAccountName`` of the new machine account
            (with or without the trailing ``$`` — both are accepted).
        group_rid: Group RID to claim membership in.  Defaults to 515
            (Domain Computers).
        group_name: Optional explicit group name override.  When omitted,
            resolves from ``sid_to_label`` via ``<domain_sid>-<group_rid>``,
            falling back to ``"DOMAIN COMPUTERS"`` for RID 515.
        source: Short source identifier for auditability.
        evidence: Optional structured evidence to persist.

    Returns:
        True when the snapshot was created or updated, otherwise False.
    """
    computer_label = _canonical_membership_label(domain, computer_name)
    if not computer_label:
        return False

    path = membership_snapshot_path(shell, domain)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = read_json_file(path) if os.path.exists(path) else {}
    if not isinstance(data, dict):
        data = {}

    # Resolve the group label.  Preference order:
    # 1. Explicit ``group_name`` argument.
    # 2. ``sid_to_label`` lookup for ``<domain_sid>-<group_rid>``.
    # 3. Synthetic fallback (``DOMAIN COMPUTERS`` for RID 515).
    resolved_group_label: str = ""
    if group_name and str(group_name).strip():
        resolved_group_label = _canonical_membership_label(domain, str(group_name))
    if not resolved_group_label:
        domain_sid = str(data.get("domain_sid") or "").strip()
        if domain_sid:
            target_sid = f"{domain_sid}-{group_rid}"
            sid_to_label = data.get("sid_to_label")
            if isinstance(sid_to_label, dict):
                candidate = sid_to_label.get(target_sid)
                if isinstance(candidate, str) and candidate.strip():
                    resolved_group_label = _canonical_membership_label(
                        domain, candidate
                    )
    if not resolved_group_label:
        # Per-RID synthetic fallback — only RID 515 is well-known enough to
        # synthesize blindly.  Other RIDs require the snapshot to have a real
        # label so we don't fabricate group names that may not exist.
        if group_rid == 515:
            resolved_group_label = _canonical_membership_label(
                domain, "DOMAIN COMPUTERS"
            )
        else:
            print_info_debug(
                "[membership] runtime computer membership skipped: cannot "
                f"resolve group label for RID {group_rid} in domain "
                f"{mark_sensitive(domain, 'domain')}"
            )
            return False

    computer_to_groups = data.setdefault("computer_to_groups", {})
    if not isinstance(computer_to_groups, dict):
        computer_to_groups = {}
        data["computer_to_groups"] = computer_to_groups

    current_groups = computer_to_groups.setdefault(computer_label, [])
    if not isinstance(current_groups, list):
        current_groups = []
        computer_to_groups[computer_label] = current_groups

    changed = False
    if resolved_group_label not in current_groups:
        current_groups.append(resolved_group_label)
        current_groups.sort(key=str.lower)
        changed = True

    group_labels = data.setdefault("group_labels", [])
    if not isinstance(group_labels, list):
        group_labels = []
        data["group_labels"] = group_labels
    if resolved_group_label not in group_labels:
        group_labels.append(resolved_group_label)
        group_labels.sort(key=str.lower)
        changed = True

    data.setdefault("user_to_groups", {})
    data.setdefault("group_to_parents", {})
    data.setdefault("label_to_sid", {})
    data.setdefault("sid_to_label", {})

    runtime_memberships = data.setdefault("runtime_memberships", [])
    if not isinstance(runtime_memberships, list):
        runtime_memberships = []
        data["runtime_memberships"] = runtime_memberships
    metadata = _normalize_runtime_membership_metadata(
        source=source,
        evidence=evidence,
        origin_kind=origin_kind,
        origin_technique=origin_technique,
        origin_relation=origin_relation,
        cleanup_behavior=cleanup_behavior,
    )
    runtime_key = (
        computer_label,
        resolved_group_label,
        str(metadata.get("source") or "").strip(),
        str(metadata.get("origin_relation") or "").strip(),
    )
    existing_runtime = {
        (
            str(item.get("computer") or item.get("user") or ""),
            str(item.get("group") or ""),
            str(item.get("source") or ""),
            str(item.get("origin_relation") or ""),
        )
        for item in runtime_memberships
        if isinstance(item, dict)
    }
    if runtime_key not in existing_runtime:
        runtime_memberships.append(
            {
                "computer": computer_label,
                "group": resolved_group_label,
                **metadata,
            }
        )
        changed = True

    if not changed:
        return False

    write_json_file(path, data)
    _invalidate_membership_snapshot_cache(domain)
    print_info_debug(
        "[membership] runtime computer membership persisted: "
        f"computer={mark_sensitive(computer_label, 'user')} "
        f"group={mark_sensitive(resolved_group_label, 'group')} "
        f"source={mark_sensitive(str(source), 'detail')} "
        f"path={mark_sensitive(path, 'path')}"
    )
    return True


# ---------------------------------------------------------------------------
# Runtime AdminTo edge writer (Phase 3 of credential-metadata cleanup).
#
# When SMB Pwn3d! verifies a domain user as local admin on a host, we want
# the attack graph to reflect that effective access so the privilege-role
# picker (read side) returns the user via LOCAL_ADMIN_VERIFIED for that
# host. Domain Admins / Enterprise Admins / Built-in Administrators (and
# RID 500 / 519 principals) are explicitly skipped: they reach every
# domain-joined host implicitly via Domain Admins -> AdminTo -> All
# Computers and explicit per-host edges add graph noise without changing
# the picker outcome (those users already resolve to a higher-priority
# role via tier).
# ---------------------------------------------------------------------------


_ADMIN_RISK_REASON_SKIPS = {
    "domain_admins",
    "enterprise_admins",
    "builtin_administrators",
}
_ADMIN_RID_SKIPS = {500, 519}


def _admin_to_skip_user_via_risk(
    shell: object,
    *,
    domain: str,
    username: str,
) -> bool:
    """Return True when identity-risk reasons mark username as DA/EA/BA."""
    try:
        from adscan_internal.services.identity_risk_service import (
            get_identity_risk_record,
        )
    except Exception:  # noqa: BLE001
        return False
    try:
        record = get_identity_risk_record(
            shell, domain=domain, samaccountname=username
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return False
    if not record:
        return False
    raw_reasons = (
        record.get("reasons")
        if isinstance(record, dict)
        else getattr(record, "reasons", None)
    ) or ()
    reasons = {str(r).strip().lower() for r in raw_reasons}
    return bool(reasons & _ADMIN_RISK_REASON_SKIPS)


def _admin_to_skip_user_via_rid(
    shell: object,
    *,
    domain: str,
    username: str,
) -> bool:
    """Return True when username has RID 500 or 519 in the attack graph."""
    try:
        from adscan_internal.services.high_value import (
            _find_user_node_in_attack_graph,
        )
    except Exception:  # noqa: BLE001
        return False
    try:
        node = _find_user_node_in_attack_graph(
            shell, domain=domain, samaccountname=username
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return False
    if not isinstance(node, dict):
        return False
    sid = (
        node.get("objectId")
        or node.get("objectid")
        or node.get("id")
        or ""
    )
    if not sid:
        props = node.get("properties")
        if isinstance(props, dict):
            sid = (
                props.get("objectid")
                or props.get("objectId")
                or props.get("sid")
                or ""
            )
    sid = str(sid or "").strip()
    if not sid or "-" not in sid:
        return False
    try:
        rid = int(sid.rsplit("-", 1)[-1])
    except (TypeError, ValueError):
        return False
    return rid in _ADMIN_RID_SKIPS


def add_runtime_admin_to_edge(
    shell: object,
    domain: str,
    *,
    username: str,
    host_identifier: str,
    target_hostname: str | None = None,
    source: str = "smb_pwn3d_verified",
    evidence: dict[str, Any] | None = None,
) -> bool:
    """Persist an effective AdminTo edge from username to a host.

    Skipped silently when the user already has domain_admins /
    enterprise_admins / builtin_administrators via the
    identity-risk service or RID 500 / 519 in their SID — those users
    reach every domain-joined host implicitly via the
    Domain Admins -> AdminTo -> All Computers graph hierarchy and
    explicit edges add noise without changing picker decisions.

    Args:
        shell: Shell instance used to access the workspace, identity-risk
            store, and BloodHound graph service.
        domain: AD domain that owns username.
        username: User receiving effective AdminTo on the host.
        host_identifier: IP or FQDN of the target host. Resolved to a
            BloodHound Computer node by the underlying graph service.
        target_hostname: Optional hostname hint when host_identifier
            is an IP address (NetBIOS / FQDN).
        source: Short source identifier persisted on the edge notes
            ("smb_pwn3d_verified", "schtask_admin_validated", ...).
        evidence: Optional structured evidence (timestamp, NT_STATUS,
            share that was written, etc.) merged into the edge notes.

    Returns:
        True when the edge was upserted into the attack graph, False
        when the user was skipped (DA/EA/BA/RID 500/519), the host
        could not be resolved, or any internal error occurred. Never
        raises to the caller.
    """
    domain_clean = str(domain or "").strip()
    user_clean = str(username or "").strip()
    host_clean = str(host_identifier or "").strip()
    if not domain_clean or not user_clean or not host_clean:
        return False

    try:
        if _admin_to_skip_user_via_risk(
            shell, domain=domain_clean, username=user_clean
        ):
            print_info_debug(
                "[admin_to] skip: user is DA/EA/BA via identity-risk "
                f"user={mark_sensitive(user_clean, 'user')} "
                f"host={mark_sensitive(host_clean, 'hostname')}"
            )
            return False
        if _admin_to_skip_user_via_rid(
            shell, domain=domain_clean, username=user_clean
        ):
            print_info_debug(
                "[admin_to] skip: user RID is 500/519 "
                f"user={mark_sensitive(user_clean, 'user')} "
                f"host={mark_sensitive(host_clean, 'hostname')}"
            )
            return False
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        # Defensive: if the skip check fails, do not write the edge —
        # we cannot prove the user is non-DA, and a false-positive
        # explicit edge for a DA pollutes the graph.
        return False

    try:
        from adscan_internal.services.attack_graph_service import (
            upsert_netexec_privilege_edge,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return False

    try:
        recorded = upsert_netexec_privilege_edge(
            shell,
            domain_clean,
            username=user_clean,
            relation="AdminTo",
            target_ip=host_clean,
            target_hostname=target_hostname,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return False

    if recorded:
        evidence_marker = ""
        if isinstance(evidence, dict) and evidence:
            try:
                evidence_marker = " evidence=" + ",".join(
                    f"{k}={v}" for k, v in sorted(evidence.items())
                )
            except Exception:  # noqa: BLE001
                evidence_marker = ""
        print_info_debug(
            "[admin_to] runtime AdminTo edge persisted: "
            f"user={mark_sensitive(user_clean, 'user')} "
            f"host={mark_sensitive(host_clean, 'hostname')} "
            f"source={mark_sensitive(source, 'detail')}"
            f"{evidence_marker}"
        )
    return bool(recorded)




def remove_runtime_user_group_membership(
    shell: object,
    domain: str,
    *,
    username: str,
    group_name: str,
    source: str | None = None,
    origin_relation: str | None = None,
) -> bool:
    """Remove one runtime user-to-group membership from ``memberships.json``.

    Args:
        shell: Shell object used to resolve the workspace path.
        domain: AD domain.
        username: User losing the effective membership.
        group_name: Group that should no longer be considered effective.
        source: Optional source identifier. When set, only matching runtime
            evidence entries are removed. Group membership in ``user_to_groups``
            is removed regardless because runtime access should reflect the
            current effective state.

    Returns:
        True when the snapshot was updated, otherwise False.
    """
    user_label = _canonical_membership_label(domain, username)
    group_label = _canonical_membership_label(domain, group_name)
    if not user_label or not group_label:
        return False

    path = membership_snapshot_path(shell, domain)
    if not os.path.exists(path):
        return False
    data = read_json_file(path)
    if not isinstance(data, dict):
        return False

    changed = False

    user_to_groups = data.get("user_to_groups")
    if isinstance(user_to_groups, dict):
        current_groups = user_to_groups.get(user_label)
        if isinstance(current_groups, list) and group_label in current_groups:
            user_to_groups[user_label] = [
                item for item in current_groups if str(item) != group_label
            ]
            changed = True
            if not user_to_groups[user_label]:
                user_to_groups.pop(user_label, None)

    runtime_memberships = data.get("runtime_memberships")
    if isinstance(runtime_memberships, list):
        source_value = str(source or "").strip()
        relation_value = str(origin_relation or "").strip()
        filtered_runtime_memberships = []
        removed_runtime = False
        for item in runtime_memberships:
            if not isinstance(item, dict):
                filtered_runtime_memberships.append(item)
                continue
            item_user = str(item.get("user") or "")
            item_group = str(item.get("group") or "")
            item_source = str(item.get("source") or "").strip()
            item_relation = str(item.get("origin_relation") or "").strip()
            source_matches = not source_value or item_source == source_value
            relation_matches = not relation_value or item_relation == relation_value
            if (
                item_user == user_label
                and item_group == group_label
                and source_matches
                and relation_matches
            ):
                removed_runtime = True
                continue
            filtered_runtime_memberships.append(item)
        if removed_runtime:
            data["runtime_memberships"] = filtered_runtime_memberships
            changed = True

    if not changed:
        return False

    write_json_file(path, data)
    _invalidate_membership_snapshot_cache(domain)
    _invalidate_pac_for_membership_change(
        domain=domain,
        user_label=user_label,
        group_label=group_label,
        action="remove",
    )
    print_info_debug(
        "[membership] runtime membership removed: "
        f"user={mark_sensitive(user_label, 'user')} "
        f"group={mark_sensitive(group_label, 'group')} "
        f"source={mark_sensitive(str(source or ''), 'detail')} "
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
            f"keys={sorted(snapshot.keys())} "
            f"domain_sid={mark_sensitive(domain_sid, 'sid') if domain_sid else 'unset'}"
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
    "add_runtime_computer_group_membership",
    "add_runtime_user_group_membership",
    "get_membership_snapshot_cache_stats",
    "load_membership_snapshot",
    "membership_snapshot_path",
    "remove_runtime_user_group_membership",
    "snapshot_has_sid_metadata",
]
