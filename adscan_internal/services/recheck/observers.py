"""Read-only re-observation of a detector family (recheck depth ``observe``).

One observer per detector check id (``adscan_core.engagement.detectors``). Each
reads the directory with LDAP searches only and grades what it read with the SAME
detector the scan uses, so ``observe`` and the scan cannot disagree:

* ``policy.password`` / ``policy.machine_account_quota``: one BASE read of the
  domain root, decoded by ``domain_policy_from_attrs`` and graded by
  ``analyze_weak_password_policy`` / ``analyze_machine_account_quota``;
* ``ldap.roastable_accounts``: the accounts publishing a service principal name or
  not requiring pre-authentication (domain-wide), or the named accounts by SID
  (per object), graded by ``roasting_exposure_from_attrs``;
* ``adcs.esc1`` .. ``adcs.esc15`` (template and CA configuration): the PKI
  objects, their ACLs and the CA-host values re-read with the AD CS collector's
  own reads and graded by its own detection seam (``adcs_observers``);
* ``ldap.object_acl`` / ``ldap.laps`` / ``ldap.replication_rights`` /
  ``ldap.gmsa``: the recorded targets' security descriptors re-read and graded
  by the effective-rights SSOT (``acl_observers``);
* ``posture.*`` (LDAP signing and channel binding, SMB signing, NTLM, LDAPS,
  Kerberos RC4 / AES): the scan's posture probe, forced, graded by the scan's
  own posture-to-finding rules (``posture_observers``).

Every detector is decided once: it has an observer here, or it is declared in
``not_recheckable.NOT_RECHECKABLE`` with the reason it has none (re-exported
below). Its items are reported "not re-checked" with that reason and never
closed. ``tests/unit/services/recheck/test_recheck_coverage_declared.py`` fails
on a detector in neither map, or in both.

**An observer grades with the scan's own function, never a copy.** Each one
declares the scan read and grading seam it reuses in ``SCAN_GRADERS``
(``module:attribute``); the same test checks that every entry resolves to an
object defined outside this package and that the observer's module imports it.
A new observer that needs a rule the scan keeps inline first moves that rule
into a reusable function in the scan module, then calls it from both sides.

An observer never writes. It receives an open connection and returns a
:class:`adscan_core.engagement.recheck.ReadOutcome`; a failure is an outcome with
status ``failed`` and a reason, never an exception that could close something.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from adscan_core.engagement.model import CheckStatus
from adscan_core.engagement.recheck import ReadOutcome
from adscan_internal.services.recheck.acl_observers import ACL_OBSERVERS, ACL_SCAN_GRADERS
from adscan_internal.services.recheck.adcs_observers import ADCS_OBSERVERS, ADCS_SCAN_GRADERS
from adscan_internal.services.recheck.not_recheckable import (
    NOT_RECHECKABLE,
    NOT_RECHECKABLE_KEYS,
)
from adscan_internal.services.recheck.posture_observers import (
    POSTURE_OBSERVERS,
    POSTURE_SCAN_GRADERS,
)

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
    #: The workspace shell, when the run has one. The AD CS observers need it
    #: for the scan's recorded graph, the engagement-scope host verdict and the
    #: CA-host credential; without it they decide only what LDAP can.
    shell: Any = None


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
    # AD CS template and CA configuration (ESC1-9, 11, 13, 15): see
    # ``adcs_observers`` for which families are covered and why the rest are not.
    **ADCS_OBSERVERS,
    # Directory rights: object ACEs, LAPS read, replication, gMSA retrieval.
    **ACL_OBSERVERS,
    # The domain controller's posture (LDAP signing / channel binding, SMB
    # signing, NTLM, LDAPS, Kerberos RC4 / AES), re-probed by the scan's probe.
    **POSTURE_OBSERVERS,
}


_DOMAIN_POLICY_DECODER = "adscan_internal.services.collector.ldap_collector:domain_policy_from_attrs"

#: The scan's own read and grading seam each observer reuses (``module:attribute``).
SCAN_GRADERS: Mapping[str, tuple[str, ...]] = {
    CHECK_PASSWORD_POLICY: (
        _DOMAIN_POLICY_DECODER,
        "adscan_internal.services.collector.audit_analyzer:analyze_weak_password_policy",
    ),
    CHECK_MACHINE_ACCOUNT_QUOTA: (
        _DOMAIN_POLICY_DECODER,
        "adscan_internal.services.collector.audit_analyzer:analyze_machine_account_quota",
    ),
    CHECK_ROASTABLE: ("adscan_internal.services.collector.ldap_collector:roasting_exposure_from_attrs",),
    **ADCS_SCAN_GRADERS,
    **ACL_SCAN_GRADERS,
    **POSTURE_SCAN_GRADERS,
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
    "NOT_RECHECKABLE",
    "NOT_RECHECKABLE_KEYS",
    "OBSERVERS",
    "SCAN_GRADERS",
    "ReadContext",
    "has_read_only_check",
    "run_observer",
)
