"""Central ADscan control semantics for privileged groups and principals."""

from __future__ import annotations

from typing import Any

from adscan_internal.services.privileged_group_classifier import (
    PrivilegedGroupMembership,
    classify_privileged_membership,
    normalize_sid,
    sid_rid,
)

_PRINT_OPERATORS_RID = 550
_SERVER_OPERATORS_RID = 549


def _equivalence_class_for_membership(membership: PrivilegedGroupMembership) -> str:
    if any(
        (
            membership.domain_admin,
            membership.enterprise_admins,
            membership.schema_admins,
            membership.administrators,
            membership.read_only_domain_controllers,
            membership.backup_operators,
        )
    ):
        return "critical_control"
    if any(
        (
            membership.account_operators,
            membership.cert_publishers,
            membership.key_admins,
            membership.enterprise_key_admins,
            membership.exchange_trusted_subsystem,
            membership.exchange_windows_permissions,
            membership.dns_admins,
        )
    ):
        return "control_enabler"
    if any(
        (
            membership.cryptographic_operators,
            membership.distributed_com_users,
            membership.performance_log_users,
            membership.incoming_forest_trust_builders,
        )
    ):
        return "high_impact"
    return "standard"


def classify_membership_control_semantics(
    *,
    membership: PrivilegedGroupMembership,
    group_sids: list[str],
) -> dict[str, Any]:
    """Return ADscan control semantics for one principal or group."""
    normalized_group_sids = [
        sid for sid in (normalize_sid(value) for value in group_sids) if sid
    ]
    rids = {sid_rid(sid) for sid in normalized_group_sids}

    is_direct_control = any(
        (
            membership.domain_admin,
            membership.enterprise_admins,
            membership.schema_admins,
            membership.administrators,
            membership.read_only_domain_controllers,
            membership.backup_operators,
        )
    )
    is_enabler = any(
        (
            membership.account_operators,
            membership.cert_publishers,
            membership.key_admins,
            membership.enterprise_key_admins,
            membership.exchange_trusted_subsystem,
            membership.exchange_windows_permissions,
            membership.dns_admins,
            _PRINT_OPERATORS_RID in rids,
            _SERVER_OPERATORS_RID in rids,
        )
    )
    is_high_impact = any(
        (
            membership.cryptographic_operators,
            membership.distributed_com_users,
            membership.performance_log_users,
            membership.incoming_forest_trust_builders,
        )
    )

    if is_direct_control:
        control_level = "direct_domain_control"
        terminality = "direct"
    elif is_enabler:
        control_level = "domain_control_enabler"
        terminality = "indirect"
    elif is_high_impact:
        control_level = "high_impact_privilege"
        terminality = "contextual"
    else:
        control_level = "standard"
        terminality = "none"

    scope = (
        "forest"
        if membership.enterprise_admins or membership.schema_admins
        else "domain"
        if is_direct_control or is_enabler
        else "contextual"
        if is_high_impact
        else "none"
    )
    return {
        "control_level": control_level,
        "terminality": terminality,
        "scope": scope,
        "equivalence_class": _equivalence_class_for_membership(membership),
        "is_direct_control": is_direct_control,
        "is_enabler": is_enabler,
        "is_high_impact": is_high_impact,
    }


def classify_group_control_semantics(
    *,
    sid: str | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    """Return ADscan control semantics for one group-like object."""
    group_sid = normalize_sid(sid or "")
    group_name = str(name or "").strip()
    membership = classify_privileged_membership(
        group_sids=[group_sid] if group_sid else [],
        group_names=[group_name] if group_name else [],
    )
    return classify_membership_control_semantics(
        membership=membership,
        group_sids=[group_sid] if group_sid else [],
    )


def is_material_control_transition(
    source: dict[str, Any],
    target: dict[str, Any],
) -> bool:
    """Return True when the transition changes ADscan-relevant control semantics."""
    source_level = str(source.get("control_level") or "standard")
    target_level = str(target.get("control_level") or "standard")
    if source_level == target_level and source_level in {
        "direct_domain_control",
        "domain_control_enabler",
        "high_impact_privilege",
    }:
        source_equivalence = str(source.get("equivalence_class") or "")
        target_equivalence = str(target.get("equivalence_class") or "")
        if source_equivalence and source_equivalence == target_equivalence:
            return False
    return True
