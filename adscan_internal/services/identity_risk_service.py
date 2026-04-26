"""ADscan-owned identity risk classification helpers.

This module defines the product-level identity semantics used by ADscan for
user segmentation. BloodHound remains a valuable graph source, but ADscan owns
the final classification exposed to customers so environments with unusual
group nesting do not inherit misleading Tier-0 labels.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.control_semantics import (
    classify_group_control_semantics,
    classify_membership_control_semantics,
)
from adscan_internal.services.membership_snapshot import load_membership_snapshot
from adscan_internal.services.privileged_group_classifier import (
    PrivilegedGroupMembership,
    classify_privileged_membership,
    normalize_sid,
    sid_rid,
)
from adscan_internal.workspaces import domain_subpath, read_json_file, write_json_file

IDENTITY_RISK_SNAPSHOT_FILENAME = "identity_risk_snapshot.json"
CONTROL_EXPOSURE_IDENTITIES_FILENAME = "control_exposure_identities.txt"
DIRECT_DOMAIN_CONTROL_IDENTITIES_FILENAME = "direct_domain_control.txt"
DOMAIN_COMPROMISE_ENABLERS_FILENAME = "domain_compromise_enablers.txt"
HIGH_IMPACT_PRIVILEGES_FILENAME = "high_impact_privileges.txt"


@dataclass(frozen=True)
class IdentityRiskRecord:
    """One persisted ADscan-owned user risk record."""

    username: str
    control_level: str = "standard"
    has_direct_domain_control: bool = False
    is_domain_compromise_enabler: bool = False
    has_high_impact_privilege: bool = False
    is_control_exposed: bool = False
    reasons: tuple[str, ...] = ()
    group_names: tuple[str, ...] = ()
    group_sids: tuple[str, ...] = ()


def _workspace_cwd(shell: object) -> str:
    getter = getattr(shell, "_get_workspace_cwd", None)
    if callable(getter):
        try:
            return str(getter())
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
    return str(getattr(shell, "current_workspace_dir", os.getcwd()) or os.getcwd())


def _identity_risk_snapshot_path(shell: object, domain: str) -> str:
    """Return the workspace path for the persisted identity-risk snapshot."""
    return domain_subpath(
        _workspace_cwd(shell),
        str(getattr(shell, "domains_dir", "domains") or "domains"),
        domain,
        IDENTITY_RISK_SNAPSHOT_FILENAME,
    )


def _normalize_username(value: str) -> str:
    name = str(value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def _canonical_membership_label(domain: str, value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "@" in raw:
        left, _, right = raw.partition("@")
        if left and right:
            return f"{left.strip().upper()}@{right.strip().upper()}"
    return f"{raw.upper()}@{str(domain or '').strip().upper()}"


def _recursive_group_labels(
    domain: str,
    direct_groups: list[str],
    group_to_parents: dict[str, list[str]],
) -> set[str]:
    """Return direct + recursive parent groups for one principal."""
    resolved: set[str] = set()
    stack = [_canonical_membership_label(domain, group) for group in direct_groups]
    while stack:
        current = stack.pop()
        if not current or current in resolved:
            continue
        resolved.add(current)
        for parent in group_to_parents.get(current, []):
            canonical = _canonical_membership_label(domain, parent)
            if canonical and canonical not in resolved:
                stack.append(canonical)
    return resolved


def _classify_record(
    *,
    username: str,
    membership: PrivilegedGroupMembership,
    group_names: list[str],
    group_sids: list[str],
) -> IdentityRiskRecord:
    """Translate low-level group membership into ADscan product semantics."""
    normalized_group_sids = [
        sid for sid in (normalize_sid(value) for value in group_sids) if sid
    ]
    reasons: list[str] = []
    semantics = classify_membership_control_semantics(
        membership=membership,
        group_sids=normalized_group_sids,
    )

    if membership.domain_admin:
        reasons.append("domain_admins")
    if membership.enterprise_admins:
        reasons.append("enterprise_admins")
    if membership.schema_admins:
        reasons.append("schema_admins")
    if membership.administrators:
        reasons.append("builtin_administrators")
    if membership.read_only_domain_controllers:
        reasons.append("rodc")
    if membership.backup_operators:
        reasons.append("backup_operators")
    if membership.account_operators:
        reasons.append("account_operators")
    if membership.cert_publishers:
        reasons.append("cert_publishers")
    if membership.key_admins:
        reasons.append("key_admins")
    if membership.enterprise_key_admins:
        reasons.append("enterprise_key_admins")
    if membership.exchange_trusted_subsystem:
        reasons.append("exchange_trusted_subsystem")
    if membership.exchange_windows_permissions:
        reasons.append("exchange_windows_permissions")
    if membership.dns_admins:
        reasons.append("dns_admins")
    if sid_rid("S-1-5-32-549") in {sid_rid(sid) for sid in normalized_group_sids}:
        reasons.append("server_operators")
    if sid_rid("S-1-5-32-550") in {sid_rid(sid) for sid in normalized_group_sids}:
        reasons.append("print_operators")
    if membership.cryptographic_operators:
        reasons.append("cryptographic_operators")
    if membership.distributed_com_users:
        reasons.append("distributed_com_users")
    if membership.performance_log_users:
        reasons.append("performance_log_users")
    if membership.incoming_forest_trust_builders:
        reasons.append("incoming_forest_trust_builders")

    control_level = str(semantics.get("control_level") or "standard")
    has_direct_domain_control = bool(semantics.get("is_direct_control"))
    is_domain_compromise_enabler = bool(semantics.get("is_enabler"))
    has_high_impact_privilege = bool(semantics.get("is_high_impact"))
    is_control_exposed = any(
        (
            has_direct_domain_control,
            is_domain_compromise_enabler,
            has_high_impact_privilege,
        )
    )
    return IdentityRiskRecord(
        username=username,
        control_level=control_level,
        has_direct_domain_control=has_direct_domain_control,
        is_domain_compromise_enabler=is_domain_compromise_enabler,
        has_high_impact_privilege=has_high_impact_privilege,
        is_control_exposed=is_control_exposed,
        reasons=tuple(sorted(set(reasons))),
        group_names=tuple(sorted(set(group_names), key=str.lower)),
        group_sids=tuple(sorted(set(normalized_group_sids))),
    )


def classify_group_control_level(
    *,
    sid: str | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    """Return ADscan control semantics for one group-like object.

    The result intentionally separates the group's own role from the exposure of
    principals that belong to it. Callers should not equate membership with the
    group's terminal criticality.
    """
    return classify_group_control_semantics(sid=sid, name=name)


def build_identity_risk_snapshot(shell: object, domain: str) -> dict[str, Any]:
    """Build and persist the ADscan-owned identity risk snapshot for one domain."""
    snapshot = load_membership_snapshot(shell, domain)
    if not isinstance(snapshot, dict):
        return {
            "domain": domain,
            "version": 1,
            "users": {},
            "direct_domain_control_identities": [],
            "domain_compromise_enablers": [],
            "high_impact_privileges": [],
            "control_exposure_identities": [],
        }

    user_to_groups = snapshot.get("user_to_groups")
    group_to_parents = snapshot.get("group_to_parents")
    label_to_sid = snapshot.get("label_to_sid")
    if not isinstance(user_to_groups, dict) or not isinstance(group_to_parents, dict):
        return {
            "domain": domain,
            "version": 1,
            "users": {},
            "direct_domain_control_identities": [],
            "domain_compromise_enablers": [],
            "high_impact_privileges": [],
            "control_exposure_identities": [],
        }
    if not isinstance(label_to_sid, dict):
        label_to_sid = {}

    users: dict[str, dict[str, Any]] = {}
    direct_domain_control_identities: list[str] = []
    domain_compromise_enablers: list[str] = []
    high_impact_privileges: list[str] = []
    control_exposure_identities: list[str] = []

    for user_label, direct_groups in user_to_groups.items():
        username = _normalize_username(user_label)
        if not username:
            continue
        direct_groups_list = direct_groups if isinstance(direct_groups, list) else []
        recursive_labels = _recursive_group_labels(
            domain, direct_groups_list, group_to_parents
        )
        group_names = [label.split("@", 1)[0] for label in recursive_labels]
        group_sids = [
            str(label_to_sid.get(label) or "").strip()
            for label in recursive_labels
            if str(label_to_sid.get(label) or "").strip()
        ]
        membership = classify_privileged_membership(
            group_sids=group_sids,
            group_names=group_names,
        )
        record = _classify_record(
            username=username,
            membership=membership,
            group_names=group_names,
            group_sids=group_sids,
        )
        semantics = classify_membership_control_semantics(
            membership=membership,
            group_sids=group_sids,
        )
        payload = {
            "control_level": record.control_level,
            "has_direct_domain_control": record.has_direct_domain_control,
            "is_domain_compromise_enabler": record.is_domain_compromise_enabler,
            "has_high_impact_privilege": record.has_high_impact_privilege,
            "is_control_exposed": record.is_control_exposed,
            "scope": str(semantics.get("scope") or "none"),
            "equivalence_class": str(semantics.get("equivalence_class") or "standard"),
            "reasons": list(record.reasons),
            "group_names": list(record.group_names),
            "group_sids": list(record.group_sids),
        }
        users[username] = payload
        if record.has_direct_domain_control:
            direct_domain_control_identities.append(username)
        if record.is_domain_compromise_enabler:
            domain_compromise_enablers.append(username)
        if record.has_high_impact_privilege:
            high_impact_privileges.append(username)
        if record.is_control_exposed:
            control_exposure_identities.append(username)

    result = {
        "domain": domain,
        "version": 1,
        "users": users,
        "direct_domain_control_identities": sorted(
            set(direct_domain_control_identities), key=str.lower
        ),
        "domain_compromise_enablers": sorted(
            set(domain_compromise_enablers), key=str.lower
        ),
        "high_impact_privileges": sorted(set(high_impact_privileges), key=str.lower),
        "control_exposure_identities": sorted(
            set(control_exposure_identities), key=str.lower
        ),
        "generated_by": "adscan_identity_risk",
    }
    write_json_file(_identity_risk_snapshot_path(shell, domain), result)
    print_info_debug(
        "[identity-risk] snapshot built: "
        f"domain={mark_sensitive(domain, 'domain')} "
        f"users={len(users)} direct_control={len(result['direct_domain_control_identities'])} "
        f"control_exposed={len(result['control_exposure_identities'])}"
    )
    return result


def load_identity_risk_snapshot(shell: object, domain: str) -> dict[str, Any] | None:
    """Load the persisted ADscan-owned identity risk snapshot when available."""
    path = _identity_risk_snapshot_path(shell, domain)
    if not os.path.exists(path):
        return None
    data = read_json_file(path)
    return data if isinstance(data, dict) else None


def load_or_build_identity_risk_snapshot(shell: object, domain: str) -> dict[str, Any]:
    """Return the persisted identity-risk snapshot, building it when missing."""
    loaded = load_identity_risk_snapshot(shell, domain)
    if isinstance(loaded, dict):
        return loaded
    try:
        return build_identity_risk_snapshot(shell, domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return {
            "domain": domain,
            "version": 1,
            "users": {},
            "direct_domain_control_identities": [],
            "domain_compromise_enablers": [],
            "high_impact_privileges": [],
            "control_exposure_identities": [],
        }


def get_identity_risk_record(
    shell: object,
    *,
    domain: str,
    samaccountname: str,
) -> dict[str, Any] | None:
    """Return one ADscan-owned user risk record when present."""
    snapshot = load_identity_risk_snapshot(shell, domain)
    if not isinstance(snapshot, dict):
        return None
    users = snapshot.get("users")
    if not isinstance(users, dict):
        return None
    return users.get(_normalize_username(samaccountname))
