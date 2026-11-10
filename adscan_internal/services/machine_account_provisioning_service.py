"""Reusable machine-account provisioning helpers.

This module centralizes the LDAP preflight and workspace bookkeeping used by
flows that need an attacker-controlled computer account.  It intentionally does
not own the bind/transport used to create the account: authenticated LDAP,
relay-authenticated LDAP, and future transports have different security
constraints.  They can all share the same capacity checks and registry format.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
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
from adscan_core.rich_output import print_exception


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
    """Return a random AD-safe machine sAMAccountName with trailing ``$``.

    ``ADSCAN`` + 8 hex characters: 14 characters, inside the 15-character
    NetBIOS computer-name limit, recognisable in the client's directory as
    ADscan's, and random enough that two runs never collide.
    """
    token = secrets.token_hex(4).upper()
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
        print_exception(exception=exc)
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


#: Machine-account retention policies (decision D4). ``revert_each_run`` is the
#: default: one-off audits leave nothing behind. ``retain_one`` keeps ONE named
#: ADscan account per domain between runs, only with the client's recorded
#: consent (Enterprise onboarding), disclosed in every report and retired when
#: the policy is switched back (contract closure) or the domain quota is 0.
POLICY_REVERT_EACH_RUN = "revert_each_run"
POLICY_RETAIN_ONE = "retain_one"
MACHINE_ACCOUNT_POLICIES = (POLICY_REVERT_EACH_RUN, POLICY_RETAIN_ONE)
MACHINE_ACCOUNT_POLICY_ENV = "ADSCAN_MACHINE_ACCOUNT_POLICY"

#: Marker on a managed-registry ``source`` for the account kept under retain_one.
RETAINED_SOURCE_SUFFIX = ":retained"

#: Description written on every computer account ADscan creates, so the client's
#: administrators recognise it. Whether a quota creator may set it is a lab
#: question (Task 5.0); the write is best-effort.
MACHINE_ACCOUNT_DESCRIPTION = "Created by ADscan for exposure validation; safe to delete"


@dataclass(frozen=True, slots=True)
class MachineAccountLease:
    """A computer account the assessment controls, from the provisioning SSOT.

    Attributes:
        sam_account_name: With the trailing ``$``.
        password: Its secret (never in ``repr``).
        dn / sid: Directory identifiers when known.
        created: True when this call created it; False when it was reused.
        ledger_change_id: The environment-change record of the object.
        policy: The retention policy it was provisioned under.
    """

    sam_account_name: str
    password: str = field(repr=False, default="")
    dn: str | None = None
    sid: str | None = None
    created: bool = False
    ledger_change_id: str | None = None
    policy: str = POLICY_REVERT_EACH_RUN


def resolve_machine_account_policy(shell: Any) -> str:
    """The retention policy for this run (never raises).

    ``retain_one`` only when chosen (scan configuration
    ``durable_changes.machine_account_policy``, then
    ``ADSCAN_MACHINE_ACCOUNT_POLICY``, then the scan policy's
    ``machine_account`` setting, whose default is ``revert_each_run``) AND
    automatic reversion is on (with it off, nothing is reverted anyway).
    """
    import os  # noqa: PLC0415

    from adscan_core.scan_policy import settings as policy_settings  # noqa: PLC0415

    value = None
    try:
        section = getattr(getattr(shell, "scan_config", None), "durable_changes", None)
        value = getattr(section, "machine_account_policy", None)
    except Exception:  # noqa: BLE001
        value = None
    if value not in MACHINE_ACCOUNT_POLICIES:
        value = str(os.environ.get(MACHINE_ACCOUNT_POLICY_ENV, "") or "").strip().lower()
    if value not in MACHINE_ACCOUNT_POLICIES:
        value = policy_settings.policy_setting(shell, policy_settings.MACHINE_ACCOUNT)
    if value != POLICY_RETAIN_ONE:
        return POLICY_REVERT_EACH_RUN
    try:
        from adscan_internal.services.durable_change_policy import (  # noqa: PLC0415
            resolve_auto_revert,
        )

        if not resolve_auto_revert(shell).enabled:
            return POLICY_REVERT_EACH_RUN
    except Exception:  # noqa: BLE001
        return POLICY_REVERT_EACH_RUN
    return POLICY_RETAIN_ONE


async def provision_machine_account(
    ldap_config: ADscanLDAPConfig,
    *,
    computer_name: str | None = None,
    password: str | None = None,
) -> Any:
    """The ONE creation primitive every creator goes through.

    Creates ``ADSCAN`` + 8 hex unless a name is given (an operator's explicit
    choice), then writes :data:`MACHINE_ACCOUNT_DESCRIPTION` best-effort. Returns
    the native stack's ``AddComputerNativeResult``. A structural test forbids
    calling ``add_computer_native`` anywhere else.
    """
    from adscan_internal.services.exploitation.delegation_native import (  # noqa: PLC0415
        add_computer_native,
    )

    name = computer_name or generate_machine_account_name().rstrip("$")
    result = await add_computer_native(
        ldap_config=ldap_config, computer_name=name, password=password
    )
    if getattr(result, "success", False) and getattr(result, "dn", None):
        await _set_description_best_effort(ldap_config, str(result.dn))
    return result


async def _set_description_best_effort(ldap_config: ADscanLDAPConfig, dn: str) -> None:
    import asyncio  # noqa: PLC0415

    def _write() -> bool:
        with ADscanLDAPConnection(ldap_config) as conn:
            return bool(
                conn.modify(dn, {"description": [("replace", [MACHINE_ACCOUNT_DESCRIPTION])]})
            )

    try:
        await asyncio.to_thread(_write)
    except Exception as exc:  # noqa: BLE001 - a missing description never fails the step
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def register_provisioned_machine_account(
    shell: Any,
    *,
    domain: str,
    sam_account_name: str,
    dn: str | None,
    sid: str | None,
    executor_username: str,
    purpose: str,
    method: str,
    ledger_kind: str = "machine_account_created",
    durable: bool = True,
    extra_detail: dict[str, Any] | None = None,
    allow_retention: bool = True,
) -> str | None:
    """Record a computer account ADscan created: ONE shape for every creator.

    ``durable`` objects (an RBCD delegate a later step may reuse) are
    ``operator_confirmed`` and resolved at workspace exit; a step-scoped one
    (ESC14) is ``auto_revert``. Under ``retain_one`` a durable account is kept on
    purpose (subtype ``provisioned_reusable``) and disclosed as such. Never raises.
    """
    from adscan_internal.services.ledger_guard import ledger_or_warn  # noqa: PLC0415

    ledger = ledger_or_warn(shell)
    if ledger is None:
        return None
    from adscan_internal.services.environment_change_ledger import (  # noqa: PLC0415
        CHANGE_CLASS_AUTO_REVERT,
        CHANGE_CLASS_OPERATOR_CONFIRMED,
    )

    policy = (
        resolve_machine_account_policy(shell)
        if durable and allow_retention
        else POLICY_REVERT_EACH_RUN
    )
    sam = normalize_machine_account(sam_account_name)
    detail: dict[str, Any] = {
        "dn": dn,
        "sam": sam,
        "sid": sid,
        "purpose": purpose,
        "exec_username": executor_username,
        "executor_username": executor_username,
        "executor_auth_domain": domain,
        "provisioned_by_adscan": True,
        "retention": policy,
    }
    if policy == POLICY_RETAIN_ONE:
        detail["subtype"] = "provisioned_reusable"
    detail.update(extra_detail or {})
    if policy == POLICY_RETAIN_ONE:
        from adscan_core.reporting.cleanup_disclosures import (  # noqa: PLC0415
            RETAINED_ACCOUNT_METHOD,
        )

        # The shared disclosure copy recognises the kept account by this method.
        method = RETAINED_ACCOUNT_METHOD
    try:
        change_id = ledger.register_change(
            kind=ledger_kind,
            domain=domain,
            target=sam,
            detail=detail,
            method=method,
            change_class=CHANGE_CLASS_OPERATOR_CONFIRMED if durable else CHANGE_CLASS_AUTO_REVERT,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    if policy == POLICY_RETAIN_ONE:
        from adscan_core.reporting.cleanup_disclosures import (  # noqa: PLC0415
            retained_machine_account_remediation,
        )

        try:
            ledger.set_revert_metadata(
                change_id,
                remediation_command=retained_machine_account_remediation(
                    sam_account_name=sam
                ),
                remediation_object_dn=str(dn or ""),
            )
            from adscan_core.reporting.cleanup_disclosures import (  # noqa: PLC0415
                KEPT_REASON_RETAINED,
            )

            ledger.mark_kept(change_id, reason=KEPT_REASON_RETAINED)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    return change_id


def retained_machine_account(shell: Any, *, domain: str) -> ManagedMachineAccount | None:
    """The ONE ADscan account kept under ``retain_one`` for ``domain``, if any."""
    for account in list_managed_machine_accounts(shell, domain=domain):
        if account.source.endswith(RETAINED_SOURCE_SUFFIX):
            return account
    return None


def mark_machine_account_retained(shell: Any, *, domain: str, sam_account_name: str) -> None:
    """Flag a managed account as THE retained one (retain_one)."""
    bucket = _managed_machine_bucket(shell, domain)
    raw = bucket.get(normalize_machine_account(sam_account_name).lower())
    if isinstance(raw, dict) and not str(raw.get("source") or "").endswith(
        RETAINED_SOURCE_SUFFIX
    ):
        raw["source"] = f"{raw.get('source') or 'adscan'}{RETAINED_SOURCE_SUFFIX}"


def retire_retained_machine_account(shell: Any, *, domain: str, reason: str) -> bool:
    """Queue the retained account for deletion at the end of this run.

    Called when the domain quota is observed 0 (an account ADscan keeps must not
    hold open an avenue the client closed) or when the policy is no longer
    ``retain_one`` (contract closure). Registers it as a step-scoped change, so
    the exit cleanup and the final retry pass delete it with the best credential.
    """
    account = retained_machine_account(shell, domain=domain)
    if account is None:
        return False
    change_id = register_provisioned_machine_account(
        shell,
        domain=domain,
        sam_account_name=account.sam_account_name,
        dn=account.dn,
        sid=account.sid,
        executor_username=account.created_by or "",
        purpose="retained_account_retirement",
        method=f"Retire the retained ADscan computer account ({reason})",
        durable=True,
        extra_detail={"retirement_reason": reason},
        allow_retention=False,
    )
    raw = _managed_machine_bucket(shell, domain).get(account.sam_account_name.lower())
    if isinstance(raw, dict):
        raw["source"] = str(raw.get("source") or "").replace(RETAINED_SOURCE_SUFFIX, "")
    return change_id is not None


def _verify_retained_account(
    actor_ldap_config: ADscanLDAPConfig, account: ManagedMachineAccount
) -> bool:
    """Exists, is enabled, and its stored secret still authenticates (one bind)."""
    import dataclasses  # noqa: PLC0415

    try:
        with ADscanLDAPConnection(actor_ldap_config) as conn:
            conn.search(
                search_base=conn.domain_dn,
                search_filter=(
                    f"(sAMAccountName={_escape_filter_value(account.sam_account_name)})"
                ),
                attributes=["userAccountControl"],
            )
            if not conn.entries:
                return False
            uac = conn.entries[0]["userAccountControl"].value
            if uac is not None and int(str(uac)) & 0x2:
                return False
        machine_cfg = dataclasses.replace(
            actor_ldap_config,
            username=account.sam_account_name,
            password=account.password,
            use_kerberos=False,
            ccache_path=None,
            aes_key=None,
        )
        with ADscanLDAPConnection(machine_cfg):
            return True
    except Exception as exc:  # noqa: BLE001 - an unverifiable account is not reused
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def acquire_controlled_machine_account(
    shell: Any,
    *,
    domain: str,
    actor_ldap_config: ADscanLDAPConfig,
    actor_username: str,
    purpose: str,
    method: str,
    computer_name: str | None = None,
    password: str | None = None,
    step_scoped: bool = False,
    ledger_kind: str = "machine_account_created",
    extra_detail: dict[str, Any] | None = None,
    respect_capacity: bool = False,
) -> MachineAccountLease | None:
    """THE way an attack step gets a computer account it controls.

    Every creator goes through here (the relay delegate, the authenticated RBCD
    delegate, ESC14's enrollment account and weak-mapping victim); a structural
    test forbids calling :func:`provision_machine_account` from anywhere else.

    1. Re-read the actor's capacity this run (never cached across runs).
    2. Apply the retention rules (retire the retained account when the policy
       ended or the domain quota is 0).
    3. Under ``retain_one``, reuse the retained account if it still exists, is
       enabled and authenticates.
    4. Otherwise create ``ADSCAN`` + 8 hex through :func:`provision_machine_account`,
       record it in the ledger and the managed registry, and (``retain_one``)
       mark it as the retained account.

    Args:
        step_scoped: The caller deletes the account at the end of its step
            (ESC14) unless it is the retained one. Under ``revert_each_run`` it
            is recorded as an automatic, step-scoped change; under ``retain_one``
            it is kept and disclosed like every retained account.
        ledger_kind: The ledger change kind of a created account.
        extra_detail: Additional non-secret ledger detail.
        respect_capacity: Do not attempt a creation the capacity read already
            shows impossible (the domain quota is 0 or the actor's quota is
            used). Callers whose actor may be privileged (and so not bound by the
            quota) leave it off.

    Returns ``None`` when no account could be obtained (the reason is printed
    and a real quota exhaustion is recorded for the actor). A lease with
    ``created=False`` is the retained account, which the caller must not delete.
    """
    from adscan_core.rich_output import print_warning  # noqa: PLC0415
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415

    capacity = assess_machine_account_capacity(
        ldap_config=actor_ldap_config, actor_username=actor_username, shell=shell
    )
    _record_capacity(shell, domain=domain, actor=actor_username, capacity=capacity)
    reconcile_retained_machine_account(shell, domain=domain)
    policy = resolve_machine_account_policy(shell)
    if policy == POLICY_RETAIN_ONE:
        retained = retained_machine_account(shell, domain=domain)
        if retained is not None and _verify_retained_account(actor_ldap_config, retained):
            return MachineAccountLease(
                sam_account_name=retained.sam_account_name,
                password=retained.password,
                dn=retained.dn,
                sid=retained.sid,
                created=False,
                policy=policy,
            )
    if respect_capacity and capacity.can_create is False:
        print_warning(
            "No computer account can be created for this step: "
            f"{capacity.blocked_reason or 'MachineAccountQuota does not allow it'}."
        )
        return None
    # Its creator cannot delete a quota-created computer account; under a policy
    # that allows no manual cleanup it is created only when the client's cleanup
    # account is verified as an administrator of this domain.
    from adscan_internal.services.revert_permission import (  # noqa: PLC0415
        cleanup_write_permitted,
    )

    if not cleanup_write_permitted(
        shell, domain=domain, kinds=(ledger_kind,), surface=purpose, target=str(computer_name or "")
    ):
        return None
    result = run_async_sync(
        provision_machine_account(
            actor_ldap_config, computer_name=computer_name, password=password
        )
    )
    if not getattr(result, "success", False):
        reason = str(getattr(result, "error", "") or "")
        record_machine_account_creation_result(
            shell,
            domain=domain,
            actor_username=actor_username,
            success=False,
            quota_exceeded=bool(getattr(result, "quota_exceeded", False)),
            reason=reason,
        )
        print_warning(
            f"Computer account creation failed: {reason or 'the domain controller refused it'}."
        )
        return None
    record_machine_account_creation_result(
        shell, domain=domain, actor_username=actor_username, success=True
    )
    sam = normalize_machine_account(
        str(getattr(result, "computer_name", None) or computer_name or "")
    )
    machine_password = str(getattr(result, "password", None) or password or "")
    sid = None
    try:
        with ADscanLDAPConnection(actor_ldap_config) as conn:
            sid = _resolve_principal_sid(conn, sam)
    except Exception as exc:  # noqa: BLE001 - the caller decides whether it needs the SID
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    change_id = register_provisioned_machine_account(
        shell,
        domain=domain,
        sam_account_name=sam,
        dn=getattr(result, "dn", None),
        sid=sid,
        executor_username=actor_username,
        purpose=purpose,
        method=method,
        ledger_kind=ledger_kind,
        # A step-scoped account is an automatic revert unless it becomes THE
        # retained account (retain_one), which is kept and disclosed.
        durable=(not step_scoped) or policy == POLICY_RETAIN_ONE,
        extra_detail={
            **(extra_detail or {}),
            "method": getattr(result, "method", None),
            # For the burn forecast: the domain quota this actor creates under.
            "actor_domain_quota": capacity.domain_quota,
        },
    )
    register_managed_machine_account(
        shell,
        domain=domain,
        sam_account_name=sam,
        password=machine_password,
        dn=getattr(result, "dn", None),
        sid=sid,
        created_by=actor_username,
        source=purpose,
    )
    if policy == POLICY_RETAIN_ONE:
        mark_machine_account_retained(shell, domain=domain, sam_account_name=sam)
    return MachineAccountLease(
        sam_account_name=sam,
        password=machine_password,
        dn=getattr(result, "dn", None),
        sid=sid,
        created=True,
        ledger_change_id=change_id,
        policy=policy,
    )


def _record_capacity(
    shell: Any, *, domain: str, actor: str, capacity: MachineAccountCapacity
) -> None:
    """Persist the capacity observed THIS run (the burn forecast reads it)."""
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return
    bucket = domains_data.setdefault(domain, {})
    if not isinstance(bucket, dict):
        return
    bucket["machine_account_capacity"] = {
        "actor": actor,
        "domain_quota": capacity.domain_quota,
        "created_count": capacity.created_count,
        "remaining": capacity.remaining,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }


def reconcile_retained_machine_account(shell: Any, *, domain: str) -> str | None:
    """Apply the retention rules at the start of a run. Returns a retirement reason.

    * policy no longer ``retain_one`` (contract closure, or a one-off run): retire;
    * domain quota observed 0: retire (decision D3: the client closed the
      avenue, and ADscan's own account must not keep it open).
    """
    if retained_machine_account(shell, domain=domain) is None:
        return None
    reason = None
    if resolve_machine_account_policy(shell) != POLICY_RETAIN_ONE:
        reason = "retention no longer requested"
    elif observed_domain_machine_account_quota(shell, domain=domain) == 0:
        reason = "domain MachineAccountQuota is 0"
    if reason is None:
        return None
    retire_retained_machine_account(shell, domain=domain, reason=reason)
    return reason


_PROVISIONED_LEDGER_KINDS = frozenset({"machine_account_created", "computer_account_created"})


def adscan_provisioned_machine_accounts(shell: Any, *, domain: str) -> set[str]:
    """sAMAccountNames (lower-case, with ``$``) of computer accounts ADscan created.

    Read from the managed registry and from the environment-change ledger, so an
    account created by any path (relay, authenticated RBCD, ESC14) counts.
    """
    found: set[str] = set()
    domains_data = getattr(shell, "domains_data", None) or {}
    bucket = domains_data.get(domain) if isinstance(domains_data, dict) else None
    registry = (bucket or {}).get("managed_machine_accounts") if isinstance(bucket, dict) else None
    for sam in registry or {}:
        found.add(normalize_machine_account(str(sam)).lower())
    from adscan_internal.services.ledger_guard import ledger_or_warn  # noqa: PLC0415

    ledger = ledger_or_warn(shell, "machine account provisioning lookup")
    get_changes = getattr(ledger, "get_changes", None)
    if callable(get_changes):
        try:
            for entry in get_changes():
                if str(entry.get("kind") or "") not in _PROVISIONED_LEDGER_KINDS:
                    continue
                if str(entry.get("domain") or "").lower() != str(domain or "").lower():
                    continue
                detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
                sam = (detail or {}).get("sam") or (detail or {}).get("computer_name") or entry.get("target")
                if sam:
                    found.add(normalize_machine_account(str(sam)).lower())
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    return found


def non_adscan_controlled_computer_accounts(shell: Any, *, domain: str) -> set[str]:
    """Computer accounts the assessment controls that ADscan did NOT provision.

    These are attacker-equivalent footholds (a dumped machine secret, a
    compromised host's account). ADscan's own accounts are artifacts of the
    assessment and are excluded (decision D3).
    """
    domains_data = getattr(shell, "domains_data", None) or {}
    bucket = domains_data.get(domain) if isinstance(domains_data, dict) else None
    creds = (bucket or {}).get("credentials") if isinstance(bucket, dict) else None
    if not isinstance(creds, dict):
        return set()
    owned = {str(user).strip().lower() for user in creds if str(user).strip().endswith("$")}
    return owned - adscan_provisioned_machine_accounts(shell, domain=domain)


def observed_domain_machine_account_quota(shell: Any, *, domain: str) -> int | None:
    """The domain ms-DS-MachineAccountQuota the collector recorded, or ``None``.

    The collector reads it from the domain object on every run and persists it in
    ``inventory/domain_policy.json``; ``None`` means unread (never a verdict).
    """
    try:
        import json  # noqa: PLC0415
        import os  # noqa: PLC0415

        from adscan_internal.services.collector.inventory_persistence import (  # noqa: PLC0415
            _inventory_dir,
        )

        path = os.path.join(_inventory_dir(shell, domain), "domain_policy.json")
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        value = (payload.get("policy") or {}).get("machine_account_quota")
        return int(value) if value is not None else None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def forget_machine_account(shell: Any, *, domain: str, sam_account_name: str) -> bool:
    """Drop a DELETED machine account from every place a later step reads it.

    Without this, a deleted delegate stayed in ``credentials`` and in the
    managed registry, and the authenticated-RBCD path could pick it as
    "reusable" later in the same workspace (MAQ investigation, section 2).
    Returns True when anything was removed. Never raises.
    """
    sam = normalize_machine_account(str(sam_account_name or "")).lower()
    if not sam or shell is None:
        return False
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return False
    domain_bucket = domains_data.get(domain)
    if not isinstance(domain_bucket, dict):
        return False
    removed = False
    for key in ("credentials", "credentials_meta", "managed_machine_accounts"):
        bucket = domain_bucket.get(key)
        if not isinstance(bucket, dict):
            continue
        for stored in list(bucket):
            # Exact machine-account match only: a user account that happens to
            # share the name without the trailing ``$`` is a different principal.
            if str(stored).strip().lower() == sam:
                bucket.pop(stored, None)
                removed = True
    return removed


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
    "MACHINE_ACCOUNT_DESCRIPTION",
    "MACHINE_ACCOUNT_POLICIES",
    "MACHINE_ACCOUNT_POLICY_ENV",
    "POLICY_RETAIN_ONE",
    "POLICY_REVERT_EACH_RUN",
    "MachineAccountLease",
    "acquire_controlled_machine_account",
    "adscan_provisioned_machine_accounts",
    "forget_machine_account",
    "mark_machine_account_retained",
    "non_adscan_controlled_computer_accounts",
    "observed_domain_machine_account_quota",
    "provision_machine_account",
    "reconcile_retained_machine_account",
    "register_provisioned_machine_account",
    "resolve_machine_account_policy",
    "retained_machine_account",
    "retire_retained_machine_account",
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
