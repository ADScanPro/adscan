"""Engine side of ``reverted_when_permitted``: verify the cleanup account, gate the write.

The decision table and every client-facing sentence live in
:mod:`adscan_core.scan_policy.revert_permission`; this module gathers the inputs
from the run and applies the answer:

* :func:`revert_permission_context` tells policy resolution whether a cleanup
  account is supplied at all (``resolve_policy(revert_permission=...)``).
* :func:`refresh_policy_revert_permission` re-resolves the active policy when
  the account changes during a session (loaded for the run, set or cleared by
  the operator), so the gates follow it.
* :func:`verify_cleanup_account` establishes, READ-ONLY, whether the account is
  an administrator of a given domain, from the collected membership snapshot
  (the membership SSOT). Nothing is written to test it.
* :func:`cleanup_write_permitted` is the gate every write seam of such a change
  calls before writing (the machine-account provisioning SSOT and the NTLM relay
  entry). A policy that accepts manual cleanup passes straight through, exactly
  as before; any other one writes only after the account is verified for that
  domain, and otherwise declines, says why once, and records it for the report.

Each verdict is persisted under ``domains_data[<domain>]["revert_permission"]``
so the report, which renders in a later process, states what the run
established.
"""

from __future__ import annotations

from typing import Any, Iterable

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info, print_info_debug
from adscan_core.scan_policy.model import ENV_MANUAL_CLEANUP
from adscan_core.scan_policy.resolve import (
    RevertPermissionContext,
    re_resolve_with_revert_permission,
)
from adscan_core.scan_policy.revert_permission import (
    REASON_NO_CLEANUP_ACCOUNT,
    STATE_UNDETERMINABLE,
    RevertPermissionVerdict,
    admin_roles_from_group_sids,
    decide_revert_permission,
    verdict_line,
)
from adscan_internal.rich_output import mark_sensitive

#: ``domains_data[<domain>]`` key holding the persisted verdict.
DOMAIN_VERDICT_KEY = "revert_permission"
#: Shell attribute: verdicts established this session, keyed by domain.
_SHELL_CACHE_ATTR = "_revert_permission_verdicts"
#: Shell attribute: declined writes, for the disclosure.
_SHELL_REFUSALS_ATTR = "_revert_permission_refusals"
#: Edge note written on a step declined for want of a verified cleanup account.
NOT_EXECUTED_REASON = "revert_not_permitted"


def revert_permission_context() -> RevertPermissionContext:
    """What the run knows before it starts: is a cleanup account supplied?"""
    try:
        from adscan_internal.services.cleanup_credential_loader import (  # noqa: PLC0415
            cleanup_account_supplied,
        )

        return RevertPermissionContext(cleanup_account_supplied=cleanup_account_supplied())
    except Exception as exc:  # noqa: BLE001 - an unreadable store is "no account"
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return RevertPermissionContext(cleanup_account_supplied=False)


def refresh_policy_revert_permission(shell: Any) -> None:
    """Re-resolve the active policy against the current cleanup account. Never raises."""
    policy = getattr(shell, "scan_policy", None)
    try:
        from adscan_core.scan_policy.resolve import ResolvedScanPolicy  # noqa: PLC0415

        if not isinstance(policy, ResolvedScanPolicy):
            return
        context = revert_permission_context()
        if policy.revert_permission == context:
            return
        shell.scan_policy = re_resolve_with_revert_permission(
            policy, context, getattr(shell, "scan_policy_registry", None)
        )
        # Verdicts were established for the previous account; drop them.
        setattr(shell, _SHELL_CACHE_ATTR, {})
    except Exception as exc:  # noqa: BLE001 - the previous resolution stays in force
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _membership_inputs(shell: Any, *, domain: str, principal: str) -> tuple[bool, bool, frozenset[str]]:
    """``(membership_available, principal_found, roles)`` from the membership SSOT."""
    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
        _expand_group_ancestors,
    )
    from adscan_internal.services.membership_snapshot import (  # noqa: PLC0415
        load_membership_snapshot,
    )

    snapshot = load_membership_snapshot(shell, domain)
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("user_to_groups"), dict):
        return False, False, frozenset()
    domain_sid = str(snapshot.get("domain_sid") or "")
    label_to_sid = snapshot.get("label_to_sid") or {}
    if not domain_sid or not isinstance(label_to_sid, dict):
        return False, False, frozenset()
    label = f"{principal.strip().upper()}@{domain.strip().upper()}"
    direct = snapshot["user_to_groups"].get(label)
    if direct is None:
        return True, False, frozenset()
    group_to_parents = snapshot.get("group_to_parents") or {}
    cache: dict[str, set[str]] = {}
    groups: set[str] = set()
    for group in direct or ():
        group_label = str(group or "").strip().upper()
        if not group_label:
            continue
        groups.add(group_label)
        groups.update(_expand_group_ancestors(domain, group_label, group_to_parents, cache))
    sids = [str(label_to_sid.get(g) or "") for g in groups]
    return True, True, admin_roles_from_group_sids(sids, domain_sid=domain_sid)


def verify_cleanup_account(
    shell: Any, *, domain: str, rights: Iterable[str]
) -> RevertPermissionVerdict:
    """Whether the cleanup account holds ``rights`` in ``domain``. Read-only, cached."""
    wanted = tuple(sorted({str(r) for r in rights}))
    key = (str(domain or "").strip().lower(), wanted)
    cache = getattr(shell, _SHELL_CACHE_ATTR, None)
    if not isinstance(cache, dict):
        cache = {}
        try:
            setattr(shell, _SHELL_CACHE_ATTR, cache)
        except Exception:  # noqa: BLE001 - a read-only shell just recomputes
            pass
    if key in cache:
        return cache[key]
    principal, home = "", ""
    available, found, roles = False, False, frozenset()
    try:
        from adscan_internal.services.cleanup_credential_loader import (  # noqa: PLC0415
            cleanup_account_identity,
        )

        identity = cleanup_account_identity(domain)
        if identity is not None:
            principal, home = identity
            available, found, roles = _membership_inputs(shell, domain=domain, principal=principal)
    except Exception as exc:  # noqa: BLE001 - an unreadable input counts as not undoable
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        available, found, roles = False, False, frozenset()
    verdict = decide_revert_permission(
        domain=domain,
        rights=wanted,
        principal=principal,
        principal_domain=home,
        membership_available=available,
        principal_found=found,
        roles=roles,
    )
    cache[key] = verdict
    _persist_verdict(shell, verdict)
    print_info_debug(
        "revert-permission "
        f"domain={mark_sensitive(domain, 'domain')} state={verdict.state} "
        f"reason={verdict.reason} roles={list(verdict.roles)}"
    )
    return verdict


def _persist_verdict(shell: Any, verdict: RevertPermissionVerdict) -> None:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict) or not verdict.domain:
        return
    for key, bucket in domains_data.items():
        if isinstance(key, str) and key.strip().lower() == verdict.domain and isinstance(bucket, dict):
            bucket[DOMAIN_VERDICT_KEY] = verdict.to_dict()
            return


def persisted_verdicts(domains_data: Any) -> list[RevertPermissionVerdict]:
    """The verdicts a run recorded, in domain order (the report reads these)."""
    out: list[RevertPermissionVerdict] = []
    if not isinstance(domains_data, dict):
        return out
    for domain in sorted(k for k in domains_data if isinstance(k, str)):
        bucket = domains_data.get(domain)
        raw = bucket.get(DOMAIN_VERDICT_KEY) if isinstance(bucket, dict) else None
        if isinstance(raw, dict):
            out.append(RevertPermissionVerdict.from_mapping(raw))
    return out


def _ledger_changes(shell: Any) -> list[dict[str, Any]]:
    """The change ledger's entries for this run, or ``[]`` when it cannot be read."""
    try:
        from adscan_internal.services.ledger_guard import active_ledger  # noqa: PLC0415

        ledger = active_ledger(shell)
        changes = ledger.get_changes() if ledger is not None else []
        return [c for c in changes if isinstance(c, dict)]
    except Exception as exc:  # noqa: BLE001 - an unreadable ledger leaves the claim unmade
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []


def verdicts_for_report(shell: Any) -> list[RevertPermissionVerdict]:
    """The verdicts a report may state: in-scope domains, with what actually ran.

    Two rules, both about not claiming what did not happen:

    * A domain outside the engagement scope is never presented as assessed, so
      its verdict is dropped (the scope SSOT decides, as for every attack step).
    * Whether the steps that need the cleanup account ran there comes from the
      change ledger (a step that writes registers a change before it returns),
      never from the permission alone. A permitted account whose steps were
      never reached reads as allowed, with no change made.

    Without a readable ledger the counts stay ``None`` and the sentence claims
    nothing beyond the permission.
    """
    import dataclasses  # noqa: PLC0415

    from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
        domain_in_engagement_scope,
    )
    from adscan_internal.services.environment_change_ledger import (  # noqa: PLC0415
        STATUS_REVERTED_CONFIRMED,
    )
    from adscan_internal.services.safeguard_profile import (  # noqa: PLC0415
        CLEANUP_ACCOUNT_REVERT_RIGHTS,
    )

    verdicts = [
        v
        for v in persisted_verdicts(getattr(shell, "domains_data", None))
        if domain_in_engagement_scope(shell, v.domain)
    ]
    from adscan_internal.services.ledger_guard import active_ledger  # noqa: PLC0415

    ledger = active_ledger(shell)
    changes = _ledger_changes(shell) if ledger is not None else None
    out: list[RevertPermissionVerdict] = []
    for verdict in verdicts:
        if changes is None:
            out.append(verdict)
            continue
        mine = [
            c
            for c in changes
            if str(c.get("kind") or "") in CLEANUP_ACCOUNT_REVERT_RIGHTS
            and str(c.get("domain") or "").strip().lower() == verdict.domain
        ]
        reverted = sum(
            1 for c in mine if str(c.get("revert_status") or "") == STATUS_REVERTED_CONFIRMED
        )
        out.append(dataclasses.replace(verdict, changes_made=len(mine), changes_reverted=reverted))
    return out


def in_scope_run_domains(shell: Any, domains: Iterable[str]) -> list[str]:
    """``domains`` narrowed to those inside the engagement scope."""
    from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
        domain_in_engagement_scope,
    )

    return [d for d in domains if domain_in_engagement_scope(shell, d)]


def record_domain_verdicts(shell: Any, domains: Iterable[str]) -> None:
    """Record the cleanup-account verdict for every in-scope domain, read-only.

    The per-write gate only establishes a verdict when a gated write is reached,
    so a run that never reaches one could not state whether the account it was
    given may undo such a change. This asks the SAME question
    (:func:`verify_cleanup_account`, the same decision function) once per domain,
    for every right a cleanup account can hold, as soon as the membership snapshot
    exists. It runs only when a cleanup account is supplied, writes nothing to the
    directory, and keeps a verdict a later write already established. A verdict
    that could not be determined (no membership data yet) is retried on the next
    call and never cached, so a later gated write re-evaluates it. Never raises.
    """
    try:
        if not revert_permission_context().cleanup_account_supplied:
            return
        from adscan_internal.services.safeguard_profile import (  # noqa: PLC0415
            CLEANUP_ACCOUNT_REVERT_RIGHTS,
        )

        rights = sorted(set(CLEANUP_ACCOUNT_REVERT_RIGHTS.values()))
        existing = {v.domain: v for v in persisted_verdicts(getattr(shell, "domains_data", None))}
        for domain in domains:
            name = str(domain or "").strip().lower()
            if not name:
                continue
            prior = existing.get(name)
            if prior is not None and prior.state != STATE_UNDETERMINABLE:
                continue
            verdict = verify_cleanup_account(shell, domain=name, rights=rights)
            if verdict.state == STATE_UNDETERMINABLE:
                cache = getattr(shell, _SHELL_CACHE_ATTR, None)
                if isinstance(cache, dict):
                    cache.pop((name, tuple(rights)), None)
    except Exception as exc:  # noqa: BLE001 - a disclosure helper never breaks the run
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _policy_accepts_manual_cleanup(shell: Any) -> bool | None:
    """True / False for an active policy, ``None`` when no policy is in force."""
    from adscan_core.scan_policy import gate  # noqa: PLC0415

    policy = gate.active_policy(shell)
    if policy is None:
        return None
    permits = getattr(policy, "permits_change_class", None)
    if not callable(permits):
        return False
    return bool(permits(ENV_MANUAL_CLEANUP))


def cleanup_write_permitted(
    shell: Any,
    *,
    domain: str,
    kinds: Iterable[str],
    surface: str,
    target: str = "",
) -> bool:
    """Gate a write whose undo needs an account the assessment does not hold.

    Returns True to proceed. Without a policy, or under one that accepts manual
    cleanup, it proceeds exactly as before (the change is then disclosed for
    manual removal if no account can undo it). Otherwise it proceeds only when
    the cleanup account is verified for ``domain``. Never raises: an error
    declines, because an unresolvable revert counts as not undoable.
    """
    try:
        from adscan_internal.services.safeguard_profile import (  # noqa: PLC0415
            CLEANUP_ACCOUNT_REVERT_RIGHTS,
        )

        rights = sorted({CLEANUP_ACCOUNT_REVERT_RIGHTS[k] for k in kinds if k in CLEANUP_ACCOUNT_REVERT_RIGHTS})
        if not rights:
            return True
        accepts = _policy_accepts_manual_cleanup(shell)
        if accepts is None or accepts:
            return True
        verdict = verify_cleanup_account(shell, domain=domain, rights=rights)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        verdict = RevertPermissionVerdict(
            domain=str(domain or "").lower(), state="undeterminable", reason="error"
        )
    if verdict.permitted:
        return True
    _record_refusal(shell, verdict, surface=surface, target=target)
    return False


def _record_refusal(
    shell: Any, verdict: RevertPermissionVerdict, *, surface: str, target: str
) -> None:
    refusals = getattr(shell, _SHELL_REFUSALS_ATTR, None)
    if not isinstance(refusals, list):
        refusals = []
        try:
            setattr(shell, _SHELL_REFUSALS_ATTR, refusals)
        except Exception:  # noqa: BLE001
            pass
    first_for_domain = not any(r.get("domain") == verdict.domain for r in refusals)
    refusals.append({"domain": verdict.domain, "surface": surface, "target": target, "reason": verdict.reason})
    if first_for_domain or verdict.reason == REASON_NO_CLEANUP_ACCOUNT:
        print_info(mark_sensitive(verdict_line(verdict), "detail"))


def revert_permission_refusals(shell: Any) -> list[dict[str, Any]]:
    """Writes declined this session for want of a verified cleanup account."""
    refusals = getattr(shell, _SHELL_REFUSALS_ATTR, None)
    return list(refusals) if isinstance(refusals, list) else []


__all__ = [
    "DOMAIN_VERDICT_KEY",
    "NOT_EXECUTED_REASON",
    "cleanup_write_permitted",
    "persisted_verdicts",
    "record_domain_verdicts",
    "in_scope_run_domains",
    "refresh_policy_revert_permission",
    "revert_permission_context",
    "revert_permission_refusals",
    "verdicts_for_report",
    "verify_cleanup_account",
]
