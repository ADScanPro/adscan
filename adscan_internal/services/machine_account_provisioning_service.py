"""Reusable machine-account provisioning helpers.

This module centralizes the LDAP preflight and workspace bookkeeping used by
flows that need an attacker-controlled computer account.  It intentionally does
not own the bind/transport used to create the account: authenticated LDAP,
relay-authenticated LDAP, and future transports have different security
constraints.  They can all share the same capacity checks and registry format.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from adscan_core import telemetry
from adscan_internal.principal_utils import normalize_machine_account
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)
from adscan_internal.services.machine_account_quota_state_service import (
    clear_machine_account_quota_exhausted,
    is_machine_account_quota_exhausted,
    mark_machine_account_quota_exhausted,
)


@dataclass(frozen=True, slots=True)
class MachineAccountCapacity:
    """Machine-account creation capacity for one actor."""

    domain_quota: int | None
    actor_sid: str | None
    created_count: int | None
    remaining: int | None
    can_create: bool | None
    blocked_reason: str | None = None


@dataclass(frozen=True, slots=True)
class ManagedMachineAccount:
    """Persisted machine account controlled by ADscan."""

    sam_account_name: str
    password: str
    dn: str | None = None
    sid: str | None = None
    created_by: str | None = None
    source: str = "unknown"
    created_at: str | None = None
    last_validated_at: str | None = None


def generate_machine_account_name(prefix: str = "ADSCAN") -> str:
    """Return a random AD-safe machine sAMAccountName with trailing ``$``."""
    token = secrets.token_hex(3).upper()
    return normalize_machine_account(f"{prefix}{token}")


def generate_machine_account_password(
    length: int = 18, *, policy: "Any | None" = None
) -> str:
    """Return a strong random password suitable for a computer account.

    Routed through the unified policy-driven generator
    (:func:`adscan_internal.passwords.generate_compliant_password` in machine
    mode) so machine passwords are CLI-safe and satisfy AD complexity even
    against a strict domain policy.

    Args:
        length: Length floor; the result is at least ``max(length, 18)`` chars
            when no ``policy`` is supplied.
        policy: Optional resolved
            :class:`~adscan_internal.services.domain_posture.ResultantPasswordPolicy`.
            When a caller has a live domain context it should resolve the policy
            (via :func:`adscan_internal.services.posture_probe.resolve_resultant_password_policy`)
            and pass it here so the machine password honours ``minPwdLength`` /
            complexity even against a strict policy. When ``None`` (no domain
            context), the strong safe default is used — backward-compatible with
            every existing caller.

    Returns:
        A generated machine-account password guaranteed to pass
        :func:`adscan_internal.passwords.validate_against_policy` in machine mode.
    """
    from adscan_internal.passwords import generate_compliant_password
    from adscan_internal.services.domain_posture import ResultantPasswordPolicy

    if policy is None:
        policy = ResultantPasswordPolicy(
            min_length=max(int(length or 0), 18),
            require_complexity=True,
            required_classes=3,
            source="default_assumed",
            detected_at=datetime.now(timezone.utc),
        )
    return generate_compliant_password(policy, machine=True)


def build_machine_account_attributes(
    *,
    computer_name: str,
    domain: str,
) -> dict[str, Any]:
    """Build standard LDAP attributes for a new AD computer account."""
    sam = normalize_machine_account(computer_name)
    cn = sam.rstrip("$")
    domain_name = str(domain or "").strip().lower()
    return {
        "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
        "sAMAccountName": sam,
        "userAccountControl": 4096,
        "dnsHostName": f"{cn}.{domain_name}",
        "servicePrincipalName": [
            f"HOST/{cn}.{domain_name}",
            f"HOST/{cn}",
            f"RestrictedKrbHost/{cn}",
            f"RestrictedKrbHost/{cn}.{domain_name}",
        ],
    }


def assess_machine_account_capacity(
    *,
    ldap_config: ADscanLDAPConfig,
    actor_username: str,
    shell: Any | None = None,
) -> MachineAccountCapacity:
    """Return whether one actor appears able to create another machine account.

    The domain-level ``ms-DS-MachineAccountQuota`` only stores the maximum
    number of machine accounts a non-privileged creator may own.  AD records the
    actual creator on each computer in ``mS-DS-CreatorSID``; counting those
    objects gives ADscan a useful preflight before attempting an add.
    """
    if shell is not None and is_machine_account_quota_exhausted(
        shell,
        domain=ldap_config.domain,
        username=actor_username,
    ):
        return MachineAccountCapacity(
            domain_quota=None,
            actor_sid=None,
            created_count=None,
            remaining=0,
            can_create=False,
            blocked_reason="actor previously exhausted MachineAccountQuota",
        )

    try:
        with ADscanLDAPConnection(ldap_config) as conn:
            quota = _read_domain_machine_account_quota(conn)
            if quota is None:
                return MachineAccountCapacity(
                    domain_quota=None,
                    actor_sid=None,
                    created_count=None,
                    remaining=None,
                    can_create=None,
                    blocked_reason="domain MachineAccountQuota could not be read",
                )
            if quota <= 0:
                return MachineAccountCapacity(
                    domain_quota=quota,
                    actor_sid=None,
                    created_count=None,
                    remaining=0,
                    can_create=False,
                    blocked_reason="domain MachineAccountQuota is 0",
                )

            actor_sid = _resolve_principal_sid(conn, actor_username)
            if not actor_sid:
                return MachineAccountCapacity(
                    domain_quota=quota,
                    actor_sid=None,
                    created_count=None,
                    remaining=None,
                    can_create=None,
                    blocked_reason="actor SID could not be resolved",
                )

            created_count = _count_machines_created_by_sid(conn, actor_sid)
            remaining = max(0, quota - created_count)
            return MachineAccountCapacity(
                domain_quota=quota,
                actor_sid=actor_sid,
                created_count=created_count,
                remaining=remaining,
                can_create=remaining > 0,
                blocked_reason=None
                if remaining > 0
                else "actor MachineAccountQuota exhausted",
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return MachineAccountCapacity(
            domain_quota=None,
            actor_sid=None,
            created_count=None,
            remaining=None,
            can_create=None,
            blocked_reason=str(exc) or "MachineAccountQuota preflight failed",
        )


def register_managed_machine_account(
    shell: Any,
    *,
    domain: str,
    sam_account_name: str,
    password: str,
    dn: str | None = None,
    sid: str | None = None,
    created_by: str | None = None,
    source: str = "authenticated_ldap",
) -> ManagedMachineAccount:
    """Persist one ADscan-controlled machine account in domain state."""
    account = ManagedMachineAccount(
        sam_account_name=normalize_machine_account(sam_account_name),
        password=str(password or ""),
        dn=dn,
        sid=sid,
        created_by=created_by,
        source=source,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    bucket = _managed_machine_bucket(shell, domain)
    bucket[account.sam_account_name.lower()] = {
        "sam_account_name": account.sam_account_name,
        "password": account.password,
        "dn": account.dn or "",
        "sid": account.sid or "",
        "created_by": account.created_by or "",
        "source": account.source,
        "created_at": account.created_at or "",
        "last_validated_at": account.last_validated_at or "",
    }
    return account


def list_managed_machine_accounts(
    shell: Any, *, domain: str
) -> list[ManagedMachineAccount]:
    """Return ADscan-managed machine accounts known for a domain."""
    results: list[ManagedMachineAccount] = []
    for raw in _managed_machine_bucket(shell, domain).values():
        if not isinstance(raw, dict):
            continue
        sam = str(raw.get("sam_account_name") or "").strip()
        password = str(raw.get("password") or "").strip()
        if not sam or not password:
            continue
        results.append(
            ManagedMachineAccount(
                sam_account_name=normalize_machine_account(sam),
                password=password,
                dn=str(raw.get("dn") or "").strip() or None,
                sid=str(raw.get("sid") or "").strip() or None,
                created_by=str(raw.get("created_by") or "").strip() or None,
                source=str(raw.get("source") or "").strip() or "unknown",
                created_at=str(raw.get("created_at") or "").strip() or None,
                last_validated_at=str(raw.get("last_validated_at") or "").strip()
                or None,
            )
        )
    results.sort(key=lambda item: item.sam_account_name.lower())
    return results


def record_machine_account_creation_result(
    shell: Any | None,
    *,
    domain: str,
    actor_username: str,
    success: bool,
    quota_exceeded: bool = False,
    reason: str = "",
) -> None:
    """Update persisted MAQ posture after a create attempt."""
    if shell is None or not actor_username:
        return
    if success:
        clear_machine_account_quota_exhausted(
            shell, domain=domain, username=actor_username
        )
        return
    if quota_exceeded:
        mark_machine_account_quota_exhausted(
            shell,
            domain=domain,
            username=actor_username,
            reason=reason or "MachineAccountQuota exceeded for actor.",
        )


def _read_domain_machine_account_quota(conn: ADscanLDAPConnection) -> int | None:
    """Read MAQ from the current domain naming context."""
    conn.search(
        search_base=conn.domain_dn,
        search_filter="(objectClass=domainDNS)",
        attributes=["ms-DS-MachineAccountQuota"],
        search_scope="BASE",
    )
    if not conn.entries:
        return None
    value = conn.entries[0]["ms-DS-MachineAccountQuota"].value
    return int(str(value)) if value is not None else None


def _resolve_principal_sid(conn: ADscanLDAPConnection, principal: str) -> str | None:
    """Resolve a user/computer principal to a SID string."""
    token = str(principal or "").strip()
    if not token:
        return None
    if "\\" in token:
        token = token.split("\\", 1)[1]
    if "@" in token:
        token = token.split("@", 1)[0]
    sam = token if token.endswith("$") else token.rstrip("$")
    filters = [f"(sAMAccountName={_escape_filter_value(sam)})"]
    if not sam.endswith("$"):
        filters.append(f"(userPrincipalName={_escape_filter_value(principal)})")
    conn.search(
        search_base=conn.domain_dn,
        search_filter=f"(|{''.join(filters)})" if len(filters) > 1 else filters[0],
        attributes=["objectSid"],
    )
    if not conn.entries:
        return None
    raw = conn.entries[0].entry_raw_attributes.get("objectSid") or []
    if raw and isinstance(raw[0], bytes):
        return _sid_bytes_to_str(raw[0])
    value = conn.entries[0]["objectSid"].value
    return str(value) if value else None


def _count_machines_created_by_sid(conn: ADscanLDAPConnection, actor_sid: str) -> int:
    """Count computer objects whose ``mS-DS-CreatorSID`` matches *actor_sid*."""
    sid_filter = _sid_to_ldap_filter_bytes(actor_sid)
    conn.search(
        search_base=conn.domain_dn,
        search_filter=f"(&(objectClass=computer)(mS-DS-CreatorSID={sid_filter}))",
        attributes=["sAMAccountName"],
    )
    return len(conn.entries)


def _managed_machine_bucket(shell: Any, domain: str) -> dict[str, Any]:
    """Return the mutable managed-machine registry for one domain."""
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        domains_data = {}
        if shell is not None:
            setattr(shell, "domains_data", domains_data)
    domain_bucket = domains_data.setdefault(domain, {})
    if not isinstance(domain_bucket, dict):
        domain_bucket = {}
        domains_data[domain] = domain_bucket
    registry = domain_bucket.setdefault("managed_machine_accounts", {})
    if not isinstance(registry, dict):
        registry = {}
        domain_bucket["managed_machine_accounts"] = registry
    return registry


def _escape_filter_value(value: str) -> str:
    """Escape a value for use inside an LDAP equality filter."""
    return (
        str(value)
        .replace("\\", r"\5c")
        .replace("*", r"\2a")
        .replace("(", r"\28")
        .replace(")", r"\29")
        .replace("\x00", r"\00")
    )


def _sid_bytes_to_str(raw: bytes) -> str:
    """Decode binary objectSid bytes to SID string."""
    if len(raw) < 8:
        return ""
    revision = raw[0]
    subauth_count = raw[1]
    authority = int.from_bytes(raw[2:8], byteorder="big")
    parts = [f"S-{revision}-{authority}"]
    offset = 8
    for _ in range(subauth_count):
        if offset + 4 > len(raw):
            break
        parts.append(str(int.from_bytes(raw[offset : offset + 4], byteorder="little")))
        offset += 4
    return "-".join(parts)


def _sid_to_ldap_filter_bytes(sid: str) -> str:
    """Encode SID string as escaped LDAP filter bytes."""
    parts = str(sid or "").strip().split("-")
    if len(parts) < 3 or parts[0].upper() != "S":
        return _escape_filter_value(sid)
    revision = int(parts[1])
    authority = int(parts[2])
    subauths = [int(part) for part in parts[3:]]
    raw = bytes([revision, len(subauths)]) + authority.to_bytes(6, byteorder="big")
    for subauth in subauths:
        raw += subauth.to_bytes(4, byteorder="little")
    return "".join(f"\\{byte:02x}" for byte in raw)


__all__ = [
    "MachineAccountCapacity",
    "ManagedMachineAccount",
    "assess_machine_account_capacity",
    "build_machine_account_attributes",
    "generate_machine_account_name",
    "generate_machine_account_password",
    "list_managed_machine_accounts",
    "record_machine_account_creation_result",
    "register_managed_machine_account",
]
