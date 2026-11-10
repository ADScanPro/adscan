"""Read-only re-observation of a detector family (recheck depth ``observe``).

One observer per detector check id (``adscan_core.engagement.detectors``). Each
reads the directory with LDAP searches only and grades what it read with the SAME
detector the scan uses, so ``observe`` and the scan cannot disagree:

* ``policy.password`` / ``policy.machine_account_quota``: one BASE read of the
  domain root, decoded by ``domain_policy_from_attrs`` and graded by
  ``analyze_weak_password_policy`` / ``analyze_machine_account_quota``;
* ``ldap.roastable_accounts``: the accounts publishing a service principal name or
  not requiring pre-authentication (domain-wide), or the named accounts by SID
  (per object), graded by ``roasting_exposure_from_attrs``.

Every other detector has no read-only check in this release; its items are
reported "not re-checked: no read-only check" and never closed.

An observer never writes. It receives an open connection and returns a
:class:`adscan_core.engagement.recheck.ReadOutcome`; a failure is an outcome with
status ``failed`` and a reason, never an exception that could close something.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from adscan_core.engagement.model import CheckStatus
from adscan_core.engagement.recheck import ReadOutcome

CHECK_PASSWORD_POLICY = "policy.password"
CHECK_MACHINE_ACCOUNT_QUOTA = "policy.machine_account_quota"
CHECK_ROASTABLE = "ldap.roastable_accounts"

#: Accounts per ``(|(objectSid=...)...)`` filter in a per-object read.
SID_BATCH = 50

_ROASTABLE_CANDIDATES = (
    "(&(objectCategory=person)(objectClass=user)"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
    "(|(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=4194304)))"
)


@dataclass
class ReadContext:
    """One domain's open, read-only directory connection.

    Attributes:
        conn: An entered ``ADscanLDAPConnection`` (``search`` + ``entries``).
        domain_id: The ledger domain id (lower-case DNS name).
        domain_dn: The domain naming context.
        cache: Reads shared by observers of the same domain in one run.
    """

    conn: Any
    domain_id: str
    domain_dn: str
    cache: dict[str, Any] = field(default_factory=dict)


Observer = Callable[[ReadContext, Optional[frozenset[str]]], ReadOutcome]


def _domain_root(ctx: ReadContext) -> Optional[dict[str, list[Any]]]:
    if "domain_root" not in ctx.cache:
        from adscan_internal.services.collector.ldap_collector import (  # noqa: PLC0415
            DOMAIN_POLICY_ATTRIBUTES,
            ldap_entry_attributes,
        )

        ctx.conn.search(
            search_base=ctx.domain_dn,
            search_filter="(objectClass=domainDNS)",
            attributes=list(DOMAIN_POLICY_ATTRIBUTES),
            search_scope="BASE",
        )
        entries = list(ctx.conn.entries)
        ctx.cache["domain_root"] = ldap_entry_attributes(entries[0]) if entries else None
    return ctx.cache["domain_root"]


def _policy_outcome(check_id: str, ctx: ReadContext, finding_key: str, grade: Callable[[Any], Any],
                    readable: Callable[[Any], bool]) -> ReadOutcome:
    from adscan_internal.services.collector.ldap_collector import (  # noqa: PLC0415
        domain_policy_from_attrs,
    )

    attrs = _domain_root(ctx)
    if attrs is None:
        return ReadOutcome(check_id, ctx.domain_id, CheckStatus.FAILED, None, {}, "domain_root_unreadable")
    policy = domain_policy_from_attrs(attrs)
    if not readable(policy):
        return ReadOutcome(check_id, ctx.domain_id, CheckStatus.FAILED, None, {}, "attribute_unreadable")
    present = {finding_key: frozenset({ctx.domain_id})} if grade(policy) is not None else {}
    return ReadOutcome(check_id, ctx.domain_id, CheckStatus.RAN, None, present)


def observe_password_policy(ctx: ReadContext, _objects: Optional[frozenset[str]]) -> ReadOutcome:
    """``weak_password_policy``: the Default Domain Password Policy, re-read."""
    from adscan_internal.services.collector.audit_analyzer import (  # noqa: PLC0415
        analyze_weak_password_policy,
    )

    return _policy_outcome(
        CHECK_PASSWORD_POLICY,
        ctx,
        "weak_password_policy",
        analyze_weak_password_policy,
        lambda p: p.min_pwd_length is not None and p.lockout_threshold is not None,
    )


def observe_machine_account_quota(ctx: ReadContext, _objects: Optional[frozenset[str]]) -> ReadOutcome:
    """``machine_account_quota_risk``: ``ms-DS-MachineAccountQuota``, re-read."""
    from adscan_internal.services.collector.audit_analyzer import (  # noqa: PLC0415
        analyze_machine_account_quota,
    )

    return _policy_outcome(
        CHECK_MACHINE_ACCOUNT_QUOTA,
        ctx,
        "machine_account_quota_risk",
        analyze_machine_account_quota,
        lambda p: p.machine_account_quota is not None,
    )


def _sid_filter(sids: list[str]) -> str:
    """``(|(objectSid=<escaped bytes>)...)``, encoded by the ACL module's SSOT."""
    from adscan_internal.services.exploitation.acl import (  # noqa: PLC0415
        _sid_to_ldap_filter_bytes,
    )

    clauses = [f"(objectSid={encoded})" for sid in sids if (encoded := _sid_to_ldap_filter_bytes(sid))]
    return "(|" + "".join(clauses) + ")" if clauses else ""


def observe_roastable_accounts(ctx: ReadContext, objects: Optional[frozenset[str]]) -> ReadOutcome:
    """``kerberoast`` / ``asreproast`` and their steps: the accounts, re-read."""
    from adscan_internal.services.collector.ldap_collector import (  # noqa: PLC0415
        ROASTING_ATTRIBUTES,
        ldap_entry_attributes,
        roasting_exposure_from_attrs,
    )

    kerberoastable: set[str] = set()
    asrep: set[str] = set()

    def grade(entries: list[Any]) -> set[str]:
        seen: set[str] = set()
        for entry in entries:
            exposure = roasting_exposure_from_attrs(ldap_entry_attributes(entry))
            sid = exposure["sid"]
            if not sid:
                continue
            seen.add(sid)
            if exposure["kerberoastable"]:
                kerberoastable.add(sid)
            if exposure["asrep_roastable"]:
                asrep.add(sid)
        return seen

    if objects is None:
        ctx.conn.search(ctx.domain_dn, _ROASTABLE_CANDIDATES, attributes=list(ROASTING_ATTRIBUTES))
        grade(list(ctx.conn.entries))
        examined: Optional[frozenset[str]] = None
        status = CheckStatus.RAN
    else:
        # Only directory SIDs can be read back; other ids stay unexamined.
        sids = sorted(o for o in objects if o.upper().startswith("S-1-5-21-"))
        for start in range(0, len(sids), SID_BATCH):
            query = _sid_filter(sids[start:start + SID_BATCH])
            if not query:
                continue
            ctx.conn.search(ctx.domain_dn, query, attributes=list(ROASTING_ATTRIBUTES))
            grade(list(ctx.conn.entries))
        # An account the directory no longer returns is examined too: it no
        # longer exists, so it cannot be roasted.
        examined = frozenset(sids)
        status = CheckStatus.PARTIAL
    present = {
        "kerberoast": frozenset(kerberoastable),
        "kerberoasting": frozenset(kerberoastable),
        "asreproast": frozenset(asrep),
        "asreproasting": frozenset(asrep),
    }
    return ReadOutcome(CHECK_ROASTABLE, ctx.domain_id, status, examined, present)


OBSERVERS: Mapping[str, Observer] = {
    CHECK_PASSWORD_POLICY: observe_password_policy,
    CHECK_MACHINE_ACCOUNT_QUOTA: observe_machine_account_quota,
    CHECK_ROASTABLE: observe_roastable_accounts,
}


def has_read_only_check(check_id: Optional[str]) -> bool:
    """Whether a detector family can be re-observed read-only in this release."""
    return bool(check_id) and check_id in OBSERVERS


def run_observer(check_id: str, ctx: ReadContext, objects: Optional[frozenset[str]]) -> ReadOutcome:
    """Run one observer; any error becomes a ``failed`` outcome (never closes)."""
    from adscan_core import telemetry  # noqa: PLC0415
    from adscan_core.rich_output import print_exception  # noqa: PLC0415

    try:
        return OBSERVERS[check_id](ctx, objects)
    except Exception as exc:  # noqa: BLE001 - a read error must never close an item
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ReadOutcome(check_id, ctx.domain_id, CheckStatus.FAILED, None, {}, "read_error")


__all__ = (
    "CHECK_MACHINE_ACCOUNT_QUOTA",
    "CHECK_PASSWORD_POLICY",
    "CHECK_ROASTABLE",
    "OBSERVERS",
    "ReadContext",
    "has_read_only_check",
    "run_observer",
)
