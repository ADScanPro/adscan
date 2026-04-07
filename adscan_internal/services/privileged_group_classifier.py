"""Privileged group classification helpers.

This module centralizes the logic used to determine whether a user belongs to
well-known privileged AD groups, using SIDs/RIDs rather than group names.

Rationale:
    Group names can be localized and may differ across environments. SIDs/RIDs
    are stable and language-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import zip_longest
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class PrivilegedFollowupSpec:
    """Central metadata for one privileged group family."""

    key: str
    label: str
    rank: int
    followup_mode: str
    requires_adcs: bool = False


_PRIVILEGED_FOLLOWUP_SPECS: tuple[PrivilegedFollowupSpec, ...] = (
    PrivilegedFollowupSpec("domain_admin", "Domain Admins", 400, "direct"),
    PrivilegedFollowupSpec("Administrators", "Administrators", 300, "direct"),
    PrivilegedFollowupSpec("backup_operators", "Backup Operators", 200, "direct"),
    PrivilegedFollowupSpec(
        "exchange_trusted_subsystem",
        "Exchange Trusted Subsystem",
        110,
        "enrichment",
    ),
    PrivilegedFollowupSpec(
        "exchange_windows_permissions",
        "Exchange Windows Permissions",
        110,
        "enrichment",
    ),
    PrivilegedFollowupSpec(
        "account_operators", "Account Operators", 100, "enrichment"
    ),
    PrivilegedFollowupSpec(
        "key_admins", "Key Admins", 90, "enrichment", requires_adcs=True
    ),
    PrivilegedFollowupSpec(
        "enterprise_key_admins",
        "Enterprise Key Admins",
        90,
        "enrichment",
        requires_adcs=True,
    ),
    PrivilegedFollowupSpec(
        "cert_publishers", "Cert Publishers", 90, "enrichment", requires_adcs=True
    ),
    PrivilegedFollowupSpec(
        "dns_admins", "DNSAdmins", 80, "future"
    ),
    PrivilegedFollowupSpec("cryptographic_operators", "Cryptographic Operators", 35, "none"),
    PrivilegedFollowupSpec("distributed_com_users", "Distributed COM Users", 35, "none"),
    PrivilegedFollowupSpec("performance_log_users", "Performance Log Users", 35, "none"),
    PrivilegedFollowupSpec(
        "incoming_forest_trust_builders",
        "Incoming Forest Trust Builders",
        31,
        "future",
    ),
)

_FOLLOWUP_SPEC_BY_KEY: dict[str, PrivilegedFollowupSpec] = {
    spec.key: spec for spec in _PRIVILEGED_FOLLOWUP_SPECS
}
_FOLLOWUP_SPEC_ORDER_BY_KEY: dict[str, int] = {
    spec.key: index for index, spec in enumerate(_PRIVILEGED_FOLLOWUP_SPECS)
}

_BUILTIN_ACCOUNT_OPERATORS_RID = 548
_BUILTIN_BACKUP_OPERATORS_RID = 551
_BUILTIN_INCOMING_FOREST_TRUST_BUILDERS_RID = 557
_BUILTIN_PERFORMANCE_LOG_USERS_RID = 559
_BUILTIN_DISTRIBUTED_COM_USERS_RID = 562
_CRYPTOGRAPHIC_OPERATORS_RID = 569
_CERT_PUBLISHERS_RID = 517
_KEY_ADMINS_RID = 526
_ENTERPRISE_KEY_ADMINS_RID = 527
_DNSADMINS_RID = 1101
_EXCHANGE_TRUSTED_SUBSYSTEM_RID = 1119
_EXCHANGE_WINDOWS_PERMISSIONS_RID = 1121
_EXCHANGE_SECURITY_GROUPS_OU_TOKEN = "OU=MICROSOFT EXCHANGE SECURITY GROUPS,"


def normalize_sid(value: str) -> str | None:
    """Return a normalized SID string or None when it can't be extracted.

    BloodHound CE sometimes prefixes SIDs with domain strings (e.g.:
    ``HTB.LOCAL-S-1-5-32-548``). Some tools may also embed the SID inside
    additional text. We extract the first ``S-1-`` substring and keep it.
    """
    raw = (value or "").strip()
    if not raw:
        return None

    upper = raw.upper()
    idx = upper.find("S-1-")
    if idx == -1:
        return None

    sid = upper[idx:]
    # Defensive: trim obvious trailing punctuation.
    sid = sid.strip().strip("',\"")
    if not sid.startswith("S-1-"):
        return None
    return sid


def sid_rid(value: str) -> int | None:
    """Return RID from a SID string, or None when it can't be parsed."""
    sid = normalize_sid(value)
    if not sid:
        return None
    try:
        return int(sid.rsplit("-", 1)[-1])
    except Exception:
        return None


@dataclass(frozen=True)
class PrivilegedGroupMembership:
    """Structured privileged membership flags for a principal."""

    domain_admin: bool = False
    administrators: bool = False
    backup_operators: bool = False
    cert_publishers: bool = False
    key_admins: bool = False
    enterprise_key_admins: bool = False
    cryptographic_operators: bool = False
    distributed_com_users: bool = False
    incoming_forest_trust_builders: bool = False
    performance_log_users: bool = False
    exchange_trusted_subsystem: bool = False
    exchange_windows_permissions: bool = False
    account_operators: bool = False
    dns_admins: bool = False

    def as_dict(self) -> dict[str, Any]:
        """Return a dict compatible with existing `check_privileged_groups` callers."""
        return {
            "domain_admin": bool(self.domain_admin),
            "Administrators": bool(self.administrators),
            "backup_operators": bool(self.backup_operators),
            "cert_publishers": bool(self.cert_publishers),
            "key_admins": bool(self.key_admins),
            "enterprise_key_admins": bool(self.enterprise_key_admins),
            "cryptographic_operators": bool(self.cryptographic_operators),
            "distributed_com_users": bool(self.distributed_com_users),
            "incoming_forest_trust_builders": bool(
                self.incoming_forest_trust_builders
            ),
            "performance_log_users": bool(self.performance_log_users),
            "exchange_trusted_subsystem": bool(self.exchange_trusted_subsystem),
            "exchange_windows_permissions": bool(self.exchange_windows_permissions),
            "account_operators": bool(self.account_operators),
            "dns_admins": bool(self.dns_admins),
        }


def normalize_group_name(value: str) -> str:
    """Return one normalized group name without the optional @DOMAIN suffix."""
    raw = str(value or "").strip().lower()
    if "@" in raw:
        raw = raw.rsplit("@", 1)[0].strip()
    return " ".join(raw.split())


def is_exchange_windows_permissions_group_name(value: str) -> bool:
    """Return True when the input matches the Exchange Windows Permissions group."""
    return normalize_group_name(value) == "exchange windows permissions"


def is_exchange_trusted_subsystem_group_name(value: str) -> bool:
    """Return True when the input matches the Exchange Trusted Subsystem group."""
    return normalize_group_name(value) == "exchange trusted subsystem"


def is_account_operators_group_name(value: str) -> bool:
    """Return True when the input matches the Account Operators group."""
    return normalize_group_name(value) == "account operators"


def is_cert_publishers_group_name(value: str) -> bool:
    """Return True when the input matches the Cert Publishers group."""
    return normalize_group_name(value) == "cert publishers"


def is_key_admins_group_name(value: str) -> bool:
    """Return True when the input matches the Key Admins group."""
    return normalize_group_name(value) == "key admins"


def is_enterprise_key_admins_group_name(value: str) -> bool:
    """Return True when the input matches the Enterprise Key Admins group."""
    return normalize_group_name(value) == "enterprise key admins"


def is_cryptographic_operators_group_name(value: str) -> bool:
    """Return True when the input matches the Cryptographic Operators group."""
    return normalize_group_name(value) == "cryptographic operators"


def is_distributed_com_users_group_name(value: str) -> bool:
    """Return True when the input matches the Distributed COM Users group."""
    return normalize_group_name(value) == "distributed com users"


def is_performance_log_users_group_name(value: str) -> bool:
    """Return True when the input matches the Performance Log Users group."""
    return normalize_group_name(value) == "performance log users"


def is_incoming_forest_trust_builders_group_name(value: str) -> bool:
    """Return True when the input matches the Incoming Forest Trust Builders group."""
    return normalize_group_name(value) == "incoming forest trust builders"


def normalize_distinguished_name(value: str) -> str:
    """Return one normalized distinguished name for comparison."""
    raw = str(value or "").strip().upper()
    return " ".join(raw.split())


def is_exchange_security_group_dn(value: str) -> bool:
    """Return True when the DN belongs to the Exchange security groups OU."""
    dn = normalize_distinguished_name(value)
    return _EXCHANGE_SECURITY_GROUPS_OU_TOKEN in dn


def is_exchange_windows_permissions_group(
    *,
    sid: str | None = None,
    name: str | None = None,
    distinguished_name: str | None = None,
) -> bool:
    """Return True when one group matches Exchange Windows Permissions.

    Primary signal:
    - Exchange security groups OU + domain RID 1121

    Fallback:
    - Canonical English group name, kept only for legacy/non-BH flows that do
      not provide object identifiers or distinguished names.
    """
    rid = sid_rid(sid or "")
    if rid == _EXCHANGE_WINDOWS_PERMISSIONS_RID and is_exchange_security_group_dn(
        distinguished_name or ""
    ):
        return True
    return is_exchange_windows_permissions_group_name(name or "")


def is_exchange_trusted_subsystem_group(
    *,
    sid: str | None = None,
    name: str | None = None,
    distinguished_name: str | None = None,
) -> bool:
    """Return True when one group matches Exchange Trusted Subsystem.

    Primary signal:
    - Exchange security groups OU + domain RID 1119

    Fallback:
    - Canonical English group name, kept only for legacy/non-BH flows that do
      not provide object identifiers or distinguished names.
    """
    rid = sid_rid(sid or "")
    if rid == _EXCHANGE_TRUSTED_SUBSYSTEM_RID and is_exchange_security_group_dn(
        distinguished_name or ""
    ):
        return True
    return is_exchange_trusted_subsystem_group_name(name or "")


def is_graph_extension_group(
    *,
    sid: str | None = None,
    name: str | None = None,
    distinguished_name: str | None = None,
) -> bool:
    """Return True when one privileged group should extend graph discovery.

    Graph-extension groups are operationally valuable, but ADscan should not
    stop path discovery at them because their main benefit is to unlock
    additional downstream options.
    """
    if is_exchange_windows_permissions_group(
        sid=sid,
        name=name,
        distinguished_name=distinguished_name,
    ):
        return True
    if is_exchange_trusted_subsystem_group(
        sid=sid,
        name=name,
        distinguished_name=distinguished_name,
    ):
        return True

    rid = sid_rid(sid or "")
    normalized_sid = normalize_sid(sid or "")
    return (
        rid == _BUILTIN_ACCOUNT_OPERATORS_RID
        and isinstance(normalized_sid, str)
        and normalized_sid.startswith("S-1-5-32-")
    )


def is_adcs_followup_group(*, sid: str | None = None, name: str | None = None) -> bool:
    """Return True when one group is an ADCS-dependent future follow-up target."""
    rid = sid_rid(sid or "")
    if rid in {
        _CERT_PUBLISHERS_RID,
        _KEY_ADMINS_RID,
        _ENTERPRISE_KEY_ADMINS_RID,
    }:
        return True

    group_name = name or ""
    return any(
        predicate(group_name)
        for predicate in (
            is_cert_publishers_group_name,
            is_key_admins_group_name,
            is_enterprise_key_admins_group_name,
        )
    )


def is_dependency_only_tier_zero_group(
    *, sid: str | None = None, name: str | None = None
) -> bool:
    """Return True for Tier Zero dependency groups without actionable follow-ups."""
    rid = sid_rid(sid or "")
    normalized_sid = normalize_sid(sid or "")
    if (
        rid in {
            _BUILTIN_PERFORMANCE_LOG_USERS_RID,
            _BUILTIN_DISTRIBUTED_COM_USERS_RID,
        }
        and isinstance(normalized_sid, str)
        and normalized_sid.startswith("S-1-5-32-")
    ):
        return True
    if rid == _CRYPTOGRAPHIC_OPERATORS_RID:
        return True

    group_name = name or ""
    return any(
        predicate(group_name)
        for predicate in (
            is_cryptographic_operators_group_name,
            is_distributed_com_users_group_name,
            is_performance_log_users_group_name,
        )
    )


def is_future_followup_tier_zero_group(
    *, sid: str | None = None, name: str | None = None
) -> bool:
    """Return True for Tier Zero groups reserved for future follow-up support."""
    rid = sid_rid(sid or "")
    normalized_sid = normalize_sid(sid or "")
    if (
        rid == _BUILTIN_INCOMING_FOREST_TRUST_BUILDERS_RID
        and isinstance(normalized_sid, str)
        and normalized_sid.startswith("S-1-5-32-")
    ):
        return True
    return is_incoming_forest_trust_builders_group_name(name or "")


def is_followup_terminal_group(*, sid: str | None = None, name: str | None = None) -> bool:
    """Return True when one privileged group is a terminal follow-up target."""
    if is_graph_extension_group(sid=sid, name=name):
        return False
    rid = sid_rid(sid or "")
    normalized_sid = normalize_sid(sid or "")
    if (
        rid == _BUILTIN_BACKUP_OPERATORS_RID
        and isinstance(normalized_sid, str)
        and normalized_sid.startswith("S-1-5-32-")
    ):
        return True
    return rid == _DNSADMINS_RID


@dataclass(frozen=True)
class PrivilegedFollowupDecision:
    """Centralized decision derived from privileged membership flags."""

    matched_keys: tuple[str, ...] = ()
    actionable_keys: tuple[str, ...] = ()
    direct_action_keys: tuple[str, ...] = ()
    enrichment_keys: tuple[str, ...] = ()
    future_followup_keys: tuple[str, ...] = ()
    dependency_only_keys: tuple[str, ...] = ()
    primary_key: str | None = None
    highest_rank: int = 0

    @property
    def has_actionable_membership(self) -> bool:
        """Return True when at least one privileged follow-up can run."""
        return bool(self.actionable_keys)

    @property
    def skip_attack_path_search(self) -> bool:
        """Return True when direct privileged follow-up should win over pathing."""
        return bool(self.direct_action_keys)

    @property
    def should_run_enrichment_followup(self) -> bool:
        """Return True when a non-blocking enrichment follow-up should run."""
        return bool(self.enrichment_keys)

    def is_member(self, key: str) -> bool:
        """Return True when the membership matched the given privileged key."""
        return key in self.matched_keys

    def is_actionable(self, key: str | None = None) -> bool:
        """Return True when a specific or any matched key is actionable."""
        if key is None:
            return self.has_actionable_membership
        return key in self.actionable_keys


@dataclass(frozen=True)
class PrivilegedFollowupOption:
    """One normalized privileged follow-up option ordered by central policy."""

    key: str
    label: str
    rank: int
    followup_mode: str
    actionable: bool
    requires_adcs: bool = False
    selected_by_default: bool = False


def _coerce_membership_flags(
    membership: PrivilegedGroupMembership | Mapping[str, Any],
) -> dict[str, bool]:
    """Normalize membership input into the canonical boolean flag mapping."""
    if isinstance(membership, PrivilegedGroupMembership):
        return membership.as_dict()

    return {
        "domain_admin": bool(membership.get("domain_admin")),
        "Administrators": bool(
            membership.get("Administrators") or membership.get("administrators")
        ),
        "backup_operators": bool(membership.get("backup_operators")),
        "cert_publishers": bool(membership.get("cert_publishers")),
        "key_admins": bool(membership.get("key_admins")),
        "enterprise_key_admins": bool(membership.get("enterprise_key_admins")),
        "cryptographic_operators": bool(membership.get("cryptographic_operators")),
        "distributed_com_users": bool(membership.get("distributed_com_users")),
        "incoming_forest_trust_builders": bool(
            membership.get("incoming_forest_trust_builders")
        ),
        "performance_log_users": bool(membership.get("performance_log_users")),
        "exchange_trusted_subsystem": bool(
            membership.get("exchange_trusted_subsystem")
        ),
        "exchange_windows_permissions": bool(
            membership.get("exchange_windows_permissions")
        ),
        "account_operators": bool(membership.get("account_operators")),
        "dns_admins": bool(membership.get("dns_admins")),
    }


def privileged_followup_spec_for_key(key: str) -> PrivilegedFollowupSpec | None:
    """Return the central follow-up spec for one key."""
    return _FOLLOWUP_SPEC_BY_KEY.get(str(key or "").strip())


def privileged_followup_order_for_key(key: str) -> int | None:
    """Return the central ordering index for one follow-up key."""
    return _FOLLOWUP_SPEC_ORDER_BY_KEY.get(str(key or "").strip())


def privileged_followup_order_for_group_name(name: str) -> int | None:
    """Return the central ordering index for one group display/name alias."""
    normalized = normalize_group_name(name)
    alias_to_key = {
        "domain admins": "domain_admin",
        "administrators": "Administrators",
        "backup operators": "backup_operators",
        "account operators": "account_operators",
        "cert publishers": "cert_publishers",
        "key admins": "key_admins",
        "enterprise key admins": "enterprise_key_admins",
        "exchange trusted subsystem": "exchange_trusted_subsystem",
        "exchange windows permissions": "exchange_windows_permissions",
        "dnsadmins": "dns_admins",
        "cryptographic operators": "cryptographic_operators",
        "distributed com users": "distributed_com_users",
        "performance log users": "performance_log_users",
        "incoming forest trust builders": "incoming_forest_trust_builders",
    }
    mapped_key = alias_to_key.get(normalized)
    if not mapped_key:
        return None
    return privileged_followup_order_for_key(mapped_key)


def resolve_privileged_followup_options(
    membership: PrivilegedGroupMembership | Mapping[str, Any],
    *,
    adcs_available: bool | None = None,
) -> tuple[PrivilegedFollowupOption, ...]:
    """Return privileged follow-up options ordered by the central source of truth."""
    flags = _coerce_membership_flags(membership)
    options: list[PrivilegedFollowupOption] = []
    for spec in _PRIVILEGED_FOLLOWUP_SPECS:
        if not flags.get(spec.key):
            continue
        actionable = (
            spec.followup_mode not in {"none", "future"}
            and (not spec.requires_adcs or adcs_available is not False)
        )
        options.append(
            PrivilegedFollowupOption(
                key=spec.key,
                label=spec.label,
                rank=spec.rank,
                followup_mode=spec.followup_mode,
                actionable=actionable,
                requires_adcs=spec.requires_adcs,
            )
        )
    if not options:
        return ()
    primary_actionable_key = next((option.key for option in options if option.actionable), None)
    return tuple(
        PrivilegedFollowupOption(
            key=option.key,
            label=option.label,
            rank=option.rank,
            followup_mode=option.followup_mode,
            actionable=option.actionable,
            requires_adcs=option.requires_adcs,
            selected_by_default=option.key == primary_actionable_key,
        )
        for option in options
    )


def resolve_privileged_followup_decision(
    membership: PrivilegedGroupMembership | Mapping[str, Any],
    *,
    adcs_available: bool | None = None,
) -> PrivilegedFollowupDecision:
    """Resolve a single privileged follow-up decision from membership flags."""
    options = resolve_privileged_followup_options(
        membership,
        adcs_available=adcs_available,
    )
    matched_keys = tuple(option.key for option in options)
    actionable_keys = tuple(option.key for option in options if option.actionable)
    direct_action_keys = tuple(
        option.key for option in options if option.actionable and option.followup_mode == "direct"
    )
    enrichment_keys = tuple(
        option.key for option in options if option.actionable and option.followup_mode == "enrichment"
    )
    future_followup_keys = tuple(
        option.key for option in options if option.followup_mode == "future"
    )
    dependency_only_keys = tuple(
        option.key for option in options if option.followup_mode == "none"
    )
    primary_key = actionable_keys[0] if actionable_keys else None
    highest_rank = next((option.rank for option in options if option.actionable), 0)
    return PrivilegedFollowupDecision(
        matched_keys=matched_keys,
        actionable_keys=actionable_keys,
        direct_action_keys=direct_action_keys,
        enrichment_keys=enrichment_keys,
        future_followup_keys=future_followup_keys,
        dependency_only_keys=dependency_only_keys,
        primary_key=primary_key,
        highest_rank=highest_rank,
    )


def classify_privileged_membership_from_group_sids(
    group_sids: Iterable[str],
) -> PrivilegedGroupMembership:
    """Classify privileged group membership based on group SIDs.

    Supported roles align with the current `check_privileged_groups` UX/actions:
        - Domain Admins (domain RID 512)
        - BUILTIN\\Administrators (RID 544)
        - BUILTIN\\Backup Operators (RID 551)
        - BUILTIN\\Account Operators (RID 548)
    """
    domain_admin = False
    administrators = False
    backup_operators = False
    cert_publishers = False
    key_admins = False
    enterprise_key_admins = False
    cryptographic_operators = False
    distributed_com_users = False
    incoming_forest_trust_builders = False
    performance_log_users = False
    account_operators = False
    dns_admins = False

    for raw in group_sids:
        sid = normalize_sid(str(raw))
        if not sid:
            continue

        rid = sid_rid(sid)
        if rid is None:
            continue

        # Domain-specific: Domain Admins.
        if rid == 512:
            domain_admin = True
        elif rid == _CERT_PUBLISHERS_RID:
            cert_publishers = True
        elif rid == _KEY_ADMINS_RID:
            key_admins = True
        elif rid == _ENTERPRISE_KEY_ADMINS_RID:
            enterprise_key_admins = True
        elif rid == _CRYPTOGRAPHIC_OPERATORS_RID:
            cryptographic_operators = True
        elif rid == _DNSADMINS_RID:
            dns_admins = True

        # Built-in: match by RID and BUILTIN SID prefix.
        if sid.startswith("S-1-5-32-"):
            if rid == 544:
                administrators = True
            elif rid == 551:
                backup_operators = True
            elif rid == 548:
                account_operators = True
            elif rid == _BUILTIN_INCOMING_FOREST_TRUST_BUILDERS_RID:
                incoming_forest_trust_builders = True
            elif rid == _BUILTIN_DISTRIBUTED_COM_USERS_RID:
                distributed_com_users = True
            elif rid == _BUILTIN_PERFORMANCE_LOG_USERS_RID:
                performance_log_users = True

        if (
            domain_admin
            and administrators
            and backup_operators
            and cert_publishers
            and key_admins
            and enterprise_key_admins
            and cryptographic_operators
            and distributed_com_users
            and incoming_forest_trust_builders
            and performance_log_users
            and account_operators
            and dns_admins
        ):
            break

    return PrivilegedGroupMembership(
        domain_admin=domain_admin,
        administrators=administrators,
        backup_operators=backup_operators,
        cert_publishers=cert_publishers,
        key_admins=key_admins,
        enterprise_key_admins=enterprise_key_admins,
        cryptographic_operators=cryptographic_operators,
        distributed_com_users=distributed_com_users,
        incoming_forest_trust_builders=incoming_forest_trust_builders,
        performance_log_users=performance_log_users,
        account_operators=account_operators,
        dns_admins=dns_admins,
    )


def classify_privileged_membership(
    *,
    group_sids: Iterable[str] | None = None,
    group_names: Iterable[str] | None = None,
    group_distinguished_names: Iterable[str] | None = None,
) -> PrivilegedGroupMembership:
    """Classify privileged memberships using SIDs first, then normalized group names."""
    base = classify_privileged_membership_from_group_sids(group_sids or [])
    cert_publishers = False
    key_admins = False
    enterprise_key_admins = False
    cryptographic_operators = False
    distributed_com_users = False
    incoming_forest_trust_builders = False
    performance_log_users = False
    exchange_trusted_subsystem = False
    exchange_windows_permissions = False
    account_operators = False
    dns_admins = False

    for sid, name, distinguished_name in zip_longest(
        group_sids or [],
        group_names or [],
        group_distinguished_names or [],
        fillvalue="",
    ):
        if not exchange_trusted_subsystem and is_exchange_trusted_subsystem_group(
            sid=str(sid or ""),
            name=str(name or ""),
            distinguished_name=str(distinguished_name or ""),
        ):
            exchange_trusted_subsystem = True
        if not exchange_windows_permissions and is_exchange_windows_permissions_group(
            sid=str(sid or ""),
            name=str(name or ""),
            distinguished_name=str(distinguished_name or ""),
        ):
            exchange_windows_permissions = True
        if not account_operators and (
            sid_rid(str(sid or "")) == _BUILTIN_ACCOUNT_OPERATORS_RID
            or is_account_operators_group_name(str(name or ""))
        ):
            account_operators = True
        if not cert_publishers and (
            sid_rid(str(sid or "")) == _CERT_PUBLISHERS_RID
            or is_cert_publishers_group_name(str(name or ""))
        ):
            cert_publishers = True
        if not key_admins and (
            sid_rid(str(sid or "")) == _KEY_ADMINS_RID
            or is_key_admins_group_name(str(name or ""))
        ):
            key_admins = True
        if not enterprise_key_admins and (
            sid_rid(str(sid or "")) == _ENTERPRISE_KEY_ADMINS_RID
            or is_enterprise_key_admins_group_name(str(name or ""))
        ):
            enterprise_key_admins = True
        if not cryptographic_operators and (
            sid_rid(str(sid or "")) == _CRYPTOGRAPHIC_OPERATORS_RID
            or is_cryptographic_operators_group_name(str(name or ""))
        ):
            cryptographic_operators = True
        if not distributed_com_users and (
            (
                sid_rid(str(sid or "")) == _BUILTIN_DISTRIBUTED_COM_USERS_RID
                and str(sid or "").upper().find("S-1-5-32-") != -1
            )
            or is_distributed_com_users_group_name(str(name or ""))
        ):
            distributed_com_users = True
        if not performance_log_users and (
            (
                sid_rid(str(sid or "")) == _BUILTIN_PERFORMANCE_LOG_USERS_RID
                and str(sid or "").upper().find("S-1-5-32-") != -1
            )
            or is_performance_log_users_group_name(str(name or ""))
        ):
            performance_log_users = True
        if not incoming_forest_trust_builders and (
            (
                sid_rid(str(sid or "")) == _BUILTIN_INCOMING_FOREST_TRUST_BUILDERS_RID
                and str(sid or "").upper().find("S-1-5-32-") != -1
            )
            or is_incoming_forest_trust_builders_group_name(str(name or ""))
        ):
            incoming_forest_trust_builders = True
        if not dns_admins and (
            sid_rid(str(sid or "")) == _DNSADMINS_RID
            or normalize_group_name(str(name or "")) == "dnsadmins"
        ):
            dns_admins = True

    return PrivilegedGroupMembership(
        domain_admin=base.domain_admin,
        administrators=base.administrators,
        backup_operators=base.backup_operators,
        cert_publishers=cert_publishers or base.cert_publishers,
        key_admins=key_admins or base.key_admins,
        enterprise_key_admins=enterprise_key_admins or base.enterprise_key_admins,
        cryptographic_operators=cryptographic_operators or base.cryptographic_operators,
        distributed_com_users=distributed_com_users or base.distributed_com_users,
        incoming_forest_trust_builders=(
            incoming_forest_trust_builders or base.incoming_forest_trust_builders
        ),
        performance_log_users=performance_log_users or base.performance_log_users,
        exchange_trusted_subsystem=exchange_trusted_subsystem,
        exchange_windows_permissions=exchange_windows_permissions,
        account_operators=account_operators or base.account_operators,
        dns_admins=dns_admins or base.dns_admins,
    )
