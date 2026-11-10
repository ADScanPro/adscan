"""Deferred cleanup helpers for ACL/attribute-level environment changes.

Handles shadow credentials, DACL ACEs, owner changes, SPN injections, and
password resets registered during attack-path exploitation. Mirrors the
structure of attack_path_cleanup_service.py but operates on
shell.acl_cleanup_actions rather than scoped cleanup stacks.
"""

from __future__ import annotations

from adscan_internal.services.ledger_guard import active_ledger, ledger_or_warn

import asyncio
import time
from dataclasses import dataclass
from typing import Any

from rich.markup import escape

from adscan_internal import print_info, print_info_debug, print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_internal.services.cleanup_credential_resolver import (
    CleanupCredential,
    looks_like_access_denied,
)
from adscan_internal.services.cleanup_verification import (
    VERIFY_ACCOUNT_DISABLED,
    VERIFY_DACL_ACE,
    VERIFY_GROUP_MEMBERSHIP,
    VERIFY_KEYCREDENTIAL,
    VERIFY_OWNER,
    VERIFY_SPN,
    verify_account_disabled,
    verify_dacl_ace_removed,
    verify_group_membership_removed,
    verify_keycredential_removed,
    verify_owner_restored,
    verify_spn_removed,
)
from adscan_internal.services.environment_change_ledger import MAX_REVERT_ATTEMPTS
from adscan_internal.services.exploitation import ExploitationService
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)
from adscan_core.rich_output import print_exception

# Remediation templates are the SSOT in cleanup_taxonomy; re-exported here only
# for back-compat references.
_MANUAL_SHADOW_CREDS = _tax.MANUAL_SHADOW_CREDS
_MANUAL_DACL_ACE = _tax.MANUAL_DACL_ACE
_MANUAL_OWNER = _tax.MANUAL_OWNER
_MANUAL_SPN = _tax.MANUAL_SPN
_MANUAL_PASSWORD = _tax.MANUAL_PASSWORD
_MANUAL_GROUP_MEMBERSHIP = _tax.MANUAL_GROUP_MEMBERSHIP

_TRANSIENT_EXC = (
    TimeoutError,
    asyncio.TimeoutError,
    asyncio.CancelledError,
    ConnectionResetError,
    ConnectionError,
)
_TRANSIENT_MARKERS = (
    "timeout",
    "timed out",
    "wait_for",
    "connection reset",
    "connection refused",
    "connection aborted",
    "connectionerror",
    "connection error",
    "broken pipe",
    "temporarily unavailable",
    "cancelled",
)
_REVERT_BACKOFF_SECONDS = 1.5


def _walk_exception_chain(error: BaseException) -> list[BaseException]:
    """Return ``error`` followed by its ``__cause__``/``__context__`` chain.

    ``asyncio.timeout()``/``asyncio.wait_for()`` (Python 3.11+) re-raise a bare
    ``TimeoutError`` chained ``from`` the ``CancelledError`` that cancellation
    produced — ``error.__cause__`` is the ``CancelledError``. A top-level
    ``isinstance`` check alone still classifies this correctly (the outer
    exception IS a ``TimeoutError``), but walking the chain makes the
    classifier robust to any future wrapper that surfaces the transient cause
    one level down instead of at the top.
    """
    seen: set[int] = set()
    chain: list[BaseException] = []
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _is_transient_failure(error: BaseException | str | None) -> bool:
    """Classify a revert failure as transient (retry) vs definitive (manual).

    Two input shapes reach here: a raised ``BaseException`` (when the revert
    callable itself raises) or a plain string (the common case — every
    ``service.acl.*`` revert callable swallows its exception into a
    ``result.raw_output``/``error_message`` string rather than raising; see
    ``adscan_internal.services.exploitation.acl._format_ldap_error``). Both
    paths must classify a transient TimeoutError/ConnectionError the same way,
    so the string carries the exception's ``type(...).__name__`` even when the
    instance's own ``str()`` is empty (a bare ``TimeoutError()`` — the
    Python 3.11+ ``asyncio.timeout()`` cancellation shape).
    """
    if isinstance(error, BaseException):
        if any(isinstance(candidate, _TRANSIENT_EXC) for candidate in _walk_exception_chain(error)):
            return True
        text = " ".join(
            f"{type(candidate).__name__}: {candidate}".strip().lower()
            for candidate in _walk_exception_chain(error)
        )
    else:
        text = str(error or "").strip().lower()
    if not text:
        return False
    if looks_like_access_denied(text):
        return False
    return any(marker in text for marker in _TRANSIENT_MARKERS)


def _resolve_pdc(shell: Any, domain: str) -> str:
    """Resolve the PDC FQDN (or IP last-resort) for a domain from shell.domains_data.

    The reverts driven off this value authenticate with ``kerberos=True``, so the
    host must be a real FQDN for the service SPN (CLAUDE.md "Kerberos SPNs — always
    FQDN"). Routes through the ``resolve_dc_fqdn`` SSOT, which promotes a short
    ``pdc_hostname`` to ``<host>.<domain>`` and adds the workspace inventory
    fallback; a bare IP is kept only as the same last resort the caller had before.
    """
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return ""
    domain_data = domains_data.get(domain) or {}
    if not isinstance(domain_data, dict):
        return ""
    from adscan_internal.models.domain import (  # noqa: PLC0415
        resolve_dc_fqdn,
        resolve_dc_ip,
    )

    return str(
        resolve_dc_fqdn(domain_data, target_domain=domain)
        or resolve_dc_ip(domain_data)
        or ""
    ).strip()


def execute_acl_cleanup(shell: Any) -> None:
    """Execute all deferred ACL/attribute cleanup actions and mark results in the ledger.

    Called from do_exit() before cleanup_workspace_ligolo_artifacts().
    Safe to call when shell.acl_cleanup_actions is missing — exits immediately.
    """
    actions = _resolve_cleanup_actions(shell)
    if not actions:
        return

    ledger = ledger_or_warn(shell)

    from adscan_internal.services.durable_change_policy import (  # noqa: PLC0415
        resolve_auto_revert,
    )

    actions = _reconfirm_unconfirmed_reverts(shell, ledger, actions)
    if not actions:
        return

    auto = resolve_auto_revert(shell)
    if not auto.enabled:
        _keep_actions(ledger, actions, source=auto.source)
        return

    for action in actions:
        if not isinstance(action, dict):
            continue
        kind = str(action.get("kind") or "").strip()
        change_id = action.get("_ledger_change_id")
        target = str(action.get("target") or "").strip()
        domain = str(action.get("domain") or "").strip()
        target_domain = str(action.get("target_domain") or domain).strip() or domain
        credentials = revert_credentials_for_action(
            shell, action=action, domain=domain, target_domain=target_domain
        )

        try:
            _execute_one_action(
                shell=shell,
                ledger=ledger,
                kind=kind,
                change_id=change_id,
                target=target,
                domain=domain,
                target_domain=target_domain,
                credentials=credentials,
                action=action,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            if ledger is not None and change_id:
                try:
                    ledger.mark_manual_required(
                        change_id,
                        reason=_tax.MANUAL_REASON_REVERT_FAILED,
                        remediation_command=_manual_instructions(kind, action),
                        remediation_object_dn=_object_dn_for(action, target),
                        error=str(exc),
                    )
                except Exception:  # noqa: BLE001
                    pass


def revert_credentials_for_action(
    shell: Any,
    *,
    action: dict[str, Any],
    domain: str,
    target_domain: str,
    exclude: tuple[str, ...] = (),
) -> list[CleanupCredential]:
    """The shared revert precedence for one ACL/attribute change.

    Client cleanup account, then a verified privileged credential, then the
    account that made the change. These services speak password or NT hash
    only, so a privileged credential held only as a Kerberos key or ticket is
    skipped here (the next candidate is tried).
    """
    from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
        revert_candidates,
    )

    candidates = revert_candidates(
        shell,
        domain=target_domain or domain,
        purpose=str(action.get("kind") or ""),
        creator_username=str(
            action.get("exec_username") or action.get("executor_username") or ""
        ),
        creator_secret=str(action.get("exec_password") or ""),
        creator_domain=domain,
        exclude=exclude,
    )
    change_id = str(action.get("_ledger_change_id") or "") or None
    if change_id:
        from adscan_internal.services.ledger_guard import active_ledger  # noqa: PLC0415
        from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
            record_revert_rights,
        )

        # Before the password-or-hash filter below: a privileged account held
        # only as a Kerberos key still means the rights were available.
        record_revert_rights(active_ledger(shell), change_id, candidates)
    out: list[CleanupCredential] = []
    for candidate in candidates:
        pair = candidate.as_password_or_hash()
        if pair is None:
            continue
        out.append(
            CleanupCredential(
                username=pair[0],
                secret=pair[1],
                principal_label=candidate.role,
                domain=candidate.domain,
                role=candidate.role,
            )
        )
    return out


def retry_ledger_entry(
    shell: Any, *, ledger: Any, entry: dict[str, Any], exclude: tuple[str, ...] = ()
) -> bool:
    """Final-pass dispatcher: one more revert of a ledger entry, untried credentials only.

    Returns True when the revert was confirmed by a re-read.
    """
    record = dict(entry)
    if str(record.get("kind") or "") == _tax.KIND_GROUP_MEMBERSHIP_ADDED:
        record["kind"] = "group_membership_changed"
    action = _cleanup_action_from_ledger_entry(record)
    if not action:
        return False
    change_id = str(action.get("_ledger_change_id") or "") or None
    domain = str(action.get("domain") or "")
    target_domain = str(action.get("target_domain") or domain) or domain
    credentials = revert_credentials_for_action(
        shell, action=action, domain=domain, target_domain=target_domain, exclude=exclude
    )
    if not credentials:
        return False
    _execute_one_action(
        shell=shell,
        ledger=ledger,
        kind=str(action.get("kind") or ""),
        change_id=change_id,
        target=str(action.get("target") or ""),
        domain=domain,
        target_domain=target_domain,
        credentials=credentials,
        action=action,
    )
    get_change = getattr(ledger, "get_change", None)
    if not callable(get_change) or not change_id:
        return False
    refreshed = get_change(change_id) or {}
    return str(refreshed.get("revert_status") or "") == _tax.STATUS_REVERTED_CONFIRMED


def revert_acl_change_now(shell: Any, *, action: dict[str, Any]) -> bool:
    """Step-scoped revert of ONE ACL/attribute change, right after its step.

    The same executor the exit cleanup and the final retry pass use: the shared
    revert precedence (client cleanup account, verified privileged credential,
    the account that made the change), every attempt recorded on the ledger
    entry, and a confirming re-read before ``reverted_confirmed``. An attack
    step that needs a change only for itself (a key credential for PKINIT, for
    instance) reverts it through here instead of inline as the executing
    principal, so the report can name who undid it.

    Args:
        shell: The session shell.
        action: A cleanup action (``kind``, ``domain``, ``target_domain``,
            ``target``, ``exec_username``, optional in-memory ``exec_password``,
            the kind-specific fields, and ``_ledger_change_id``).

    Returns:
        True only when a re-read confirmed the revert.
    """
    kind = str(action.get("kind") or "").strip()
    domain = str(action.get("domain") or "").strip()
    target_domain = str(action.get("target_domain") or domain).strip() or domain
    change_id = str(action.get("_ledger_change_id") or "") or None
    ledger = ledger_or_warn(shell) if change_id else None
    try:
        credentials = revert_credentials_for_action(
            shell, action=action, domain=domain, target_domain=target_domain
        )
        return _execute_one_action(
            shell=shell,
            ledger=ledger,
            kind=kind,
            change_id=change_id,
            target=str(action.get("target") or "").strip(),
            domain=domain,
            target_domain=target_domain,
            credentials=credentials,
            action=action,
        )
    except Exception as exc:  # noqa: BLE001 - the caller discloses the change
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def confirm_reverted_by(
    shell: Any, *, action: dict[str, Any], principal: str, role: str
) -> bool:
    """Settle a change an earlier step ALREADY undid, after a confirming re-read.

    For the inline fallback of a step whose shared-precedence revert could not
    run: the undo happened as ``principal``, and this re-reads the object with
    the same verifier the executor uses. Only a confirming re-read settles the
    entry ``reverted_confirmed`` (attributed to ``principal`` / ``role``); an
    unconfirmed one leaves it pending for the exit cleanup and the final pass.
    """
    kind = str(action.get("kind") or "").strip()
    change_id = str(action.get("_ledger_change_id") or "") or None
    domain = str(action.get("domain") or "").strip()
    target_domain = str(action.get("target_domain") or domain).strip() or domain
    plan = _build_revert_plan(
        kind=kind, target=str(action.get("target") or "").strip(), action=action
    )
    if not plan or plan.get("needs_manual"):
        return False
    readers = _reread_readers(
        None,
        revert_credentials_for_action(
            shell, action=action, domain=domain, target_domain=target_domain
        ),
    )
    reread = _verify_revert(
        shell, domain=domain, target_domain=target_domain, plan=plan, readers=readers
    )
    if not reread.confirmed:
        return False
    ledger = ledger_or_warn(shell) if change_id else None
    if ledger is not None and change_id:
        _record_attempt(
            ledger,
            change_id,
            CleanupCredential(username=principal, secret="", principal_label=role, role=role),
            "reverted",
        )
        ledger.mark_reverted_confirmed(
            change_id, verification_method=str(plan.get("verification_method") or "")
        )
    return True


def _keep_actions(ledger: Any, actions: list[dict[str, Any]], *, source: str) -> None:
    """Automatic reversion is off: every change nobody tried to undo stays, kept.

    ``ledger.mark_kept`` refuses a change whose revert was already attempted
    (it keeps its own state and reason), so a step-scoped revert that ran but
    could not be confirmed is never relabelled as "left in place".
    """
    from adscan_core.reporting.cleanup_disclosures import (  # noqa: PLC0415
        KEPT_REASON_AUTO_REVERT_OFF,
    )

    kept = 0
    for action in actions:
        change_id = action.get("_ledger_change_id") if isinstance(action, dict) else None
        if ledger is None or not change_id:
            continue
        try:
            if ledger.mark_kept(str(change_id), reason=KEPT_REASON_AUTO_REVERT_OFF) is not False:
                kept += 1
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    if kept:
        print_info(
            f"Automatic reversion is off ({source.replace('_', ' ')}): {kept} directory "
            "change(s) stay in place and are listed as kept in the report, each with "
            "the command that removes it."
        )


def _reconfirm_unconfirmed_reverts(
    shell: Any, ledger: Any, actions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Re-read the changes whose revert RAN but could not be confirmed.

    Read-only, so it runs whether or not automatic reversion is on: a revert a
    step already executed is confirmed now (``confirm_reverted_by``, attributed
    to the account that performed it) or keeps its ``revert_unconfirmed`` state
    and instruction. It is never run again as a new revert (removing a value
    that is already gone fails, and would turn an executed revert into a
    "failed" one), and never relabelled as kept.

    Returns:
        The actions that still need the regular exit handling: every action
        except the unconfirmed reverts this pass looked at.
    """
    get_change = getattr(ledger, "get_change", None) if ledger is not None else None
    if not callable(get_change):
        return list(actions)
    remaining: list[dict[str, Any]] = []
    for action in actions:
        change_id = str(action.get("_ledger_change_id") or "") if isinstance(action, dict) else ""
        entry = get_change(change_id) if change_id else None
        if not isinstance(entry, dict) or not (
            str(entry.get("revert_status") or "") == _tax.STATUS_MANUAL_REQUIRED
            and str(entry.get("manual_reason") or "") == _tax.MANUAL_REASON_REVERT_UNCONFIRMED
        ):
            remaining.append(action)
            continue
        performer = next(
            (
                attempt
                for attempt in reversed(entry.get("revert_credential_attempts") or [])
                if isinstance(attempt, dict) and attempt.get("outcome") == "unconfirmed"
            ),
            {},
        )
        try:
            confirm_reverted_by(
                shell,
                action=action,
                principal=str(performer.get("principal") or action.get("exec_username") or ""),
                role=str(performer.get("role") or "creator"),
            )
        except Exception as exc:  # noqa: BLE001 - the entry keeps its state
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    return remaining


def _record_attempt(
    ledger: Any, change_id: str | None, credential: CleanupCredential, outcome: str
) -> None:
    """Record one credential attempt on the ledger entry (principal and role)."""
    if ledger is None or not change_id or not credential.role:
        return
    record = getattr(ledger, "record_revert_credential_attempt", None)
    if not callable(record):
        return
    try:
        record(change_id, principal=credential.username, role=credential.role, outcome=outcome)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _object_dn_for(action: dict[str, Any], target: str) -> str:
    """Best-known object DN the client acts on (for the manual checklist)."""
    for key in ("target_dn", "object_dn", "dn", "target_object"):
        value = str(action.get(key) or "").strip()
        if value:
            return value
    if str(action.get("kind") or "") == "group_membership_changed":
        return str(action.get("target_group") or target).strip()
    return str(target or "").strip()


def _execute_one_action(
    *,
    shell: Any,
    ledger: Any,
    kind: str,
    change_id: str | None,
    target: str,
    domain: str,
    target_domain: str,
    credentials: list[CleanupCredential],
    action: dict[str, Any],
) -> bool:
    """Revert ONE ACL/attribute change with verify-the-undo + bounded retry.

    Builds a per-kind plan (revert callable + verify callable + remediation +
    object DN) and drives it through ``mark_revert_in_progress`` → (verify)
    ``mark_reverted_confirmed`` / (transient) ``mark_revert_retry`` / (definitive
    or unverifiable) ``mark_manual_required``. A ``TimeoutError`` is never
    swallowed into a terminal state on the first hit. Escalation to a stored DA
    credential is LAZY: only after a real ACCESS_DENIED on the minimal principal.

    Returns True only when a re-read confirmed the revert.
    """
    marked_target = mark_sensitive(target, "user")
    object_dn = _object_dn_for(action, target)
    remediation = _manual_instructions(kind, action)
    if ledger is not None and change_id:
        try:
            ledger.set_revert_metadata(
                change_id,
                remediation_command=remediation,
                remediation_object_dn=object_dn,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    # A password reset is put back only when the original secret is held in
    # memory for this session (never persisted): the shared restore executor
    # sets it again and confirms it by signing in with it. Without it nothing
    # can restore the previous value, and the record says exactly that.
    if kind == "password_changed":
        original_secret = str(action.get("original_secret") or "")
        if original_secret:
            from adscan_internal.services.password_restore import (  # noqa: PLC0415
                restore_reset_password,
            )

            return restore_reset_password(
                shell,
                ledger=ledger,
                change_id=change_id,
                domain=domain,
                target_domain=target_domain,
                target_user=str(action.get("target_user") or target),
                original_secret=original_secret,
                creator_username=str(action.get("exec_username") or ""),
                creator_secret=str(action.get("exec_password") or ""),
            )
        print_warning(
            f"Password reset cannot be reverted: the previous password is not known · "
            f"{marked_target}"
        )
        if ledger is not None and change_id:
            ledger.mark_manual_required(
                change_id,
                reason=_tax.MANUAL_REASON_ORIGINAL_SECRET_UNKNOWN,
                remediation_command=remediation,
                remediation_object_dn=object_dn,
            )
        return False

    pdc_host = _resolve_pdc(shell, target_domain)
    if not pdc_host:
        print_warning(
            f"PDC not found for {target_domain} — cannot revert {kind} · {marked_target}"
        )
        if ledger is not None and change_id:
            ledger.mark_manual_required(
                change_id,
                reason=_tax.MANUAL_REASON_MISSING_METADATA,
                remediation_command=remediation,
                remediation_object_dn=object_dn,
            )
        return False

    if not credentials:
        print_warning(f"No usable rollback credential found for {kind} · {marked_target}")
        if ledger is not None and change_id:
            ledger.mark_manual_required(
                change_id,
                reason=_tax.MANUAL_REASON_MISSING_CREDENTIAL,
                remediation_command=remediation,
                remediation_object_dn=object_dn,
            )
        return False

    plan = _build_revert_plan(kind=kind, target=target, action=action)
    if plan is None:
        print_warning(f"Unknown ACL cleanup kind '{kind}' — skipping")
        return False
    if plan.get("needs_manual"):
        if ledger is not None and change_id:
            ledger.mark_manual_required(
                change_id,
                reason=_tax.MANUAL_REASON_MISSING_METADATA,
                # The record-rendered instruction (real object, owner, value)
                # wins over the plan's generic template.
                remediation_command=remediation or plan.get("remediation"),
                remediation_object_dn=object_dn,
            )
        return False

    return _drive_revert_with_verify(
        shell=shell,
        ledger=ledger,
        change_id=change_id,
        kind=kind,
        target=target,
        domain=domain,
        target_domain=target_domain,
        pdc_host=pdc_host,
        credentials=credentials,
        plan=plan,
        remediation=remediation,
        object_dn=object_dn,
    )


def _build_revert_plan(
    *, kind: str, target: str, action: dict[str, Any]
) -> dict[str, Any] | None:
    """Return a per-kind revert plan, or None for an unknown kind.

    A plan dict carries:
        revert(service, conn_args) -> result    : performs the revert call
        verify(conn) -> bool                     : post-revert re-read (fail-closed)
        verification_method: str                 : ledger verification_method tag
        success_label: str                       : info message on confirm
        needs_manual: bool / remediation: str    : when metadata is missing
    """
    if kind == "shadow_credentials_added":
        added_value = str(action.get("added_key_credential_value") or "").strip()
        if not added_value:
            return {
                "needs_manual": True,
                "remediation": _MANUAL_SHADOW_CREDS,
            }

        def _revert_shadow(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.remove_shadow_credential_value(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_user=target,
                key_credential_value=added_value, kerberos=True, timeout=300,
            )

        return {
            "revert": _revert_shadow,
            "verify": lambda conn: verify_keycredential_removed(
                conn, target=target, key_credential_value=added_value
            ),
            "verification_method": VERIFY_KEYCREDENTIAL,
            "success_label": "Shadow credential value removed",
        }

    if kind == "dacl_ace_added":
        trustee = str(action.get("trustee") or "").strip()
        rights_type = str(action.get("rights_type") or "genericAll").strip()
        trustee_sid = str(action.get("trustee_sid") or "").strip()

        def _revert_dacl(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.remove_dacl_ace(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_object=target, trustee=trustee,
                rights_type=rights_type, kerberos=True, timeout=300,
            )

        def _verify(conn: Any) -> bool:
            # Without the resolved trustee SID we cannot positively confirm the
            # ACE is gone → fail-closed (manual) rather than claim done.
            if not trustee_sid:
                return False
            return verify_dacl_ace_removed(conn, target=target, trustee_sid=trustee_sid)

        rights_label = "DCSync" if rights_type == "dcsync" else "GenericAll"
        return {
            "revert": _revert_dacl,
            "verify": _verify,
            "verification_method": VERIFY_DACL_ACE,
            "success_label": f"DACL ACE removed ({rights_label})",
        }

    if kind == "owner_changed":
        original_owner_sid = action.get("original_owner_sid")
        if not original_owner_sid:
            return {"needs_manual": True, "remediation": _MANUAL_OWNER}

        def _revert_owner(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.restore_owner(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_object=target,
                original_owner_sid=str(original_owner_sid), kerberos=True, timeout=300,
            )

        return {
            "revert": _revert_owner,
            "verify": lambda conn: verify_owner_restored(
                conn, target=target, original_owner_sid=str(original_owner_sid)
            ),
            "verification_method": VERIFY_OWNER,
            "success_label": "Object owner restored",
        }

    if kind == "spn_added":
        spn = str(action.get("spn") or "").strip()

        def _revert_spn(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.clear_service_principal_name(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_user=target, spn=spn,
                kerberos=True, timeout=300,
            )

        return {
            "revert": _revert_spn,
            "verify": lambda conn: verify_spn_removed(conn, target=target, spn=spn),
            "verification_method": VERIFY_SPN,
            "success_label": "SPN cleared",
        }

    if kind == "group_membership_changed":
        target_group = str(action.get("target_group") or target).strip()
        added_user = str(action.get("added_user") or "").strip()
        if not target_group or not added_user:
            return {"needs_manual": True}

        def _revert_group(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.remove_group_member(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_group=target_group,
                target_username=added_user, kerberos=True,
                target_domain=str(action.get("target_domain") or domain), timeout=300,
            )

        return {
            "revert": _revert_group,
            "verify": lambda conn: verify_group_membership_removed(
                conn, group=target_group, member=added_user
            ),
            "verification_method": VERIFY_GROUP_MEMBERSHIP,
            "success_label": "Group membership reverted",
        }

    if kind == _tax.KIND_ACCOUNT_ENABLED:
        # Re-disable ONLY an account the pre-write read proved was disabled. An
        # unknown prior state is never guessed: the client is told instead.
        if not action.get("revertible"):
            return {
                "needs_manual": True,
                "remediation": _tax.MANUAL_ACCOUNT_ENABLED.replace("TARGET", target),
            }

        def _revert_enable(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.disable_account(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_object=target, kerberos=True,
            )

        return {
            "revert": _revert_enable,
            "verify": lambda conn: verify_account_disabled(conn, target=target),
            "verification_method": VERIFY_ACCOUNT_DISABLED,
            "success_label": "Account disabled again",
        }

    return None


#: Outcomes of the confirming re-read (``_verify_revert``).
REREAD_CONFIRMED = "confirmed"
#: A reader bound and the re-read still shows the change (or could not prove
#: it gone): the revert did not take, fail closed.
REREAD_NOT_CONFIRMED = "not_confirmed"
#: No reader could bind: the revert ran, but nothing was read back. This is NOT
#: evidence that the change is still present.
REREAD_UNREADABLE = "unreadable"


@dataclass(frozen=True)
class RereadOutcome:
    """Result of the confirming re-read after a revert.

    Attributes:
        status: One of ``REREAD_*``.
        reader: The credential whose connection ran the re-read, if any bound.
        error: Why no reader could bind (``REREAD_UNREADABLE``), else empty.
    """

    status: str
    reader: CleanupCredential | None = None
    error: str = ""

    @property
    def confirmed(self) -> bool:
        return self.status == REREAD_CONFIRMED


def _reread_readers(
    first: CleanupCredential | None, others: list[CleanupCredential]
) -> list[CleanupCredential]:
    """The credentials a re-read may bind as, in order, each principal once.

    The credential that just performed the revert goes first: it has proved it
    can bind and holds rights on the object. The rest follow the shared revert
    precedence (``revert_credentials``), never an arbitrary stored credential.
    """
    ordered: list[CleanupCredential] = []
    seen: set[str] = set()
    for candidate in ([first] if first is not None else []) + list(others or []):
        if candidate is None or not candidate.username or not candidate.secret:
            continue
        key = candidate.username.strip().lower().split("@", 1)[0].split("\\")[-1]
        if key in seen:
            continue
        seen.add(key)
        ordered.append(candidate)
    return ordered


def _build_verification_conn(
    shell: Any,
    *,
    credential: CleanupCredential,
    domain: str,
    target_domain: str,
    pdc_host: str,
) -> tuple[ADscanLDAPConnection | None, str]:
    """Build the re-read connection that authenticates AS ``credential``.

    The ticket comes from the principal-specific SSOT ``ensure_user_ccache``,
    so the bind can never fall back to an ambient ccache or to another stored
    credential. The connection targets the same DC host the revert used.

    Returns:
        ``(connection, "")`` ready to enter, or ``(None, reason)`` when no
        ticket could be obtained for this principal.
    """
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
    from adscan_internal.services._kerberos_spn import is_ip_address  # noqa: PLC0415
    from adscan_internal.services.kerberos_ticket_service import (  # noqa: PLC0415
        ensure_user_ccache,
    )

    auth_domain = str(credential.domain or domain or target_domain).strip()
    domains_data = getattr(shell, "domains_data", {}) or {}
    auth_data = domains_data.get(auth_domain) if isinstance(domains_data, dict) else None
    auth_dc_ip = resolve_dc_ip(auth_data) if isinstance(auth_data, dict) else None
    mint_errors: list[str] = []
    ccache_path = ensure_user_ccache(
        shell,
        user=credential.username,
        domain=auth_domain,
        credential=credential.secret,
        dc_ip=auth_dc_ip or None,
        error_out=mint_errors,
    )
    if not ccache_path:
        reason = mint_errors[-1] if mint_errors else "no Kerberos ticket could be obtained"
        return None, f"ticket for the re-read could not be obtained: {reason}"

    posture_snapshot = None
    try:
        from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415

        posture_snapshot = get_posture(domains_data, domain=target_domain)
    except Exception:  # noqa: BLE001 - posture only prunes the auth plan
        posture_snapshot = None

    host = str(pdc_host or "").strip()
    config = ADscanLDAPConfig(
        domain=target_domain or domain,
        dc_ip=host,
        use_ldaps=True,
        use_kerberos=True,
        username=credential.username,
        ccache_path=ccache_path,
        kerberos_target_hostname=host if host and not is_ip_address(host) else None,
        auth_domain=auth_domain,
        posture_snapshot=posture_snapshot,
    )
    return ADscanLDAPConnection(config), ""


def _verify_revert(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    plan: dict[str, Any],
    readers: list[CleanupCredential],
    pdc_host: str = "",
) -> RereadOutcome:
    """Re-read the object after a revert, binding through the revert precedence.

    Each reader is tried in order until one BINDS; that reader's verdict is
    final (another principal would read the same object). A reader that cannot
    bind is skipped, so one dead credential never turns an executed revert into
    "still present". Fail-closed: only a bound reader whose verifier confirms
    the change is gone yields ``REREAD_CONFIRMED``.
    """
    verify_fn = plan.get("verify")
    if not callable(verify_fn):
        return RereadOutcome(REREAD_UNREADABLE, error="no re-read is defined for this change")
    host = str(pdc_host or "").strip() or _resolve_pdc(shell, target_domain)
    if not host:
        return RereadOutcome(
            REREAD_UNREADABLE, error=f"no domain controller is known for {target_domain}"
        )
    if not readers:
        return RereadOutcome(
            REREAD_UNREADABLE, error="no credential was available for the re-read"
        )

    bind_errors: list[str] = []
    for reader in readers:
        who = f"{reader.role or 'assessment'} account"
        try:
            conn, reason = _build_verification_conn(
                shell,
                credential=reader,
                domain=domain,
                target_domain=target_domain,
                pdc_host=host,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            conn, reason = None, f"{type(exc).__name__}: {exc}"
        if conn is None:
            bind_errors.append(f"{who}: {reason}")
            continue
        try:
            live = conn.__enter__()
        except Exception as exc:  # noqa: BLE001 - a failed bind is a skipped reader
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            bind_errors.append(f"{who}: {type(exc).__name__}: {exc}")
            print_info_debug(
                "acl-cleanup: re-read bind failed as "
                + escape(mark_sensitive(reader.username, "user"))
                + f" ({escape(who)}); trying the next credential"
            )
            continue
        try:
            confirmed = bool(verify_fn(live))
        except Exception as exc:  # noqa: BLE001 - verifiers are fail-closed
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            confirmed = False
        finally:
            try:
                conn.__exit__(None, None, None)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
        return RereadOutcome(
            REREAD_CONFIRMED if confirmed else REREAD_NOT_CONFIRMED, reader=reader
        )

    return RereadOutcome(
        REREAD_UNREADABLE,
        error="; ".join(bind_errors) or "no credential could open the re-read",
    )


def _drive_revert_with_verify(
    *,
    shell: Any,
    ledger: Any,
    change_id: str | None,
    kind: str,
    target: str,
    domain: str,
    target_domain: str,
    pdc_host: str,
    credentials: list[CleanupCredential],
    plan: dict[str, Any],
    remediation: str,
    object_dn: str,
) -> bool:
    """Revert precedence + bounded retry + verify-the-undo for one change.

    Each credential (client cleanup account, verified privileged, the account
    that made the change) is tried in order. A transient failure is retried on
    the same credential within the ledger's bounded budget; any definitive
    failure moves to the next credential. Only the last one's failure settles
    the entry ``manual_required``.
    """
    marked_target = mark_sensitive(target, "user")
    service = ExploitationService()
    last_error = "Automatic cleanup returned a non-success result."

    for index, active in enumerate(credentials):
        final = index == len(credentials) - 1
        auth_domain = active.domain or domain
        outcome = _try_one_credential(
            shell=shell,
            ledger=ledger,
            change_id=change_id,
            kind=kind,
            target=target,
            domain=auth_domain,
            target_domain=target_domain,
            pdc_host=pdc_host,
            credential=active,
            plan=plan,
            service=service,
            readers=_reread_readers(active, credentials),
        )
        status, error = outcome
        if status == "confirmed":
            print_info(f"{plan['success_label']} (verified) · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_reverted_confirmed(
                    change_id,
                    verification_method=str(plan.get("verification_method") or ""),
                )
            _record_attempt(ledger, change_id, active, "reverted")
            return True
        if status == "unconfirmed":
            # The directory accepted the undo, but no credential could bind to
            # read it back. Nothing shows the change is still present, so it is
            # disclosed as unconfirmed (the client checks), never as failed, and
            # the exit cleanup and final pass may still confirm it.
            _record_attempt(ledger, change_id, active, "unconfirmed")
            print_warning(
                f"Rollback ran but could not be re-read to confirm it · {marked_target}"
            )
            _manual(
                ledger, change_id, _tax.MANUAL_REASON_REVERT_UNCONFIRMED, remediation,
                object_dn, error or "The revert ran; the follow-up read could not bind.",
            )
            return False
        _record_attempt(ledger, change_id, active, "failed")
        last_error = error or last_error
        if status == "budget_exhausted":
            return False  # mark_revert_retry already routed the entry to manual
        if status == "unverified":
            # The call said ok and a reader BOUND, but its re-read did not
            # show the change gone: a stronger credential cannot change what
            # the object holds. Fail closed.
            print_warning(f"Could not verify rollback · {marked_target}")
            _manual(
                ledger, change_id, _tax.MANUAL_REASON_REVERT_FAILED, remediation,
                object_dn, last_error,
            )
            return False
        if not final:
            print_info(
                f"{plan['success_label']} failed as the {active.role or 'assessment'} "
                f"account; trying the next credential · {marked_target}"
            )
            continue

    _manual(ledger, change_id, _reason_for(last_error), remediation, object_dn, last_error)
    print_warning(f"{plan['success_label']} failed · {marked_target}")
    return False


def _try_one_credential(
    *,
    shell: Any,
    ledger: Any,
    change_id: str | None,
    kind: str,
    target: str,
    domain: str,
    target_domain: str,
    pdc_host: str,
    credential: CleanupCredential,
    plan: dict[str, Any],
    service: Any,
    readers: list[CleanupCredential] | None = None,
) -> tuple[str, str | None]:
    """One credential, bounded transient retries. Returns (status, error).

    status: ``confirmed`` | ``failed`` (definitive, try the next credential) |
    ``unverified`` (call ok, a bound re-read did not confirm it) |
    ``unconfirmed`` (call ok, no reader could bind to re-read it) |
    ``budget_exhausted``.

    ``readers`` are the credentials the confirming re-read may bind as (the
    reverting credential first, then the revert precedence); defaults to the
    reverting credential alone.
    """
    marked_target = mark_sensitive(target, "user")
    last_error: str | None = None
    for _ in range(MAX_REVERT_ATTEMPTS + 1):
        if ledger is not None and change_id:
            try:
                ledger.mark_revert_in_progress(change_id)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
        transient = False
        try:
            result = plan["revert"](
                service, pdc_host=pdc_host, domain=domain, cred=credential
            )
            success = bool(getattr(result, "success", False))
            raw = str(getattr(result, "raw_output", "") or "").strip()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            success = False
            raw = str(exc)
            # Track transience from the EXCEPTION TYPE, not the (often opaque)
            # string — a TimeoutError must never be misclassified as definitive.
            transient = _is_transient_failure(exc)
            print_info_debug(
                f"acl-cleanup: classify kind={escape(kind)} raised "
                f"exc_type={type(exc).__name__} transient={transient} "
                "exc_repr=" + escape(repr(exc))
            )
        if success:
            reread = _verify_revert(
                shell,
                domain=domain,
                target_domain=target_domain,
                plan=plan,
                readers=readers if readers is not None else _reread_readers(credential, []),
                pdc_host=pdc_host,
            )
            if reread.confirmed:
                return "confirmed", None
            if reread.status == REREAD_UNREADABLE:
                return (
                    "unconfirmed",
                    "The revert ran, but no credential could bind to re-read the object: "
                    + reread.error,
                )
            return "unverified", "The revert ran, but the re-read did not confirm the change is gone."
        last_error = raw or "Automatic cleanup returned a non-success result."
        if not transient:
            transient = _is_transient_failure(last_error)
        # The error text is uncontrolled (an OSError str() can read
        # "[Errno 104] ..."), so it is markup-escaped before interpolation.
        print_info_debug(
            "acl-cleanup: classify kind="
            + escape(kind)
            + f" transient={transient} last_error="
            + escape(repr(last_error))
        )
        if transient and ledger is not None and change_id:
            used = ledger.mark_revert_retry(change_id, error=last_error)
            if used < MAX_REVERT_ATTEMPTS:
                print_warning(
                    f"Transient cleanup failure (attempt {used}/{MAX_REVERT_ATTEMPTS}) "
                    f"· {marked_target}; retrying…"
                )
                time.sleep(_REVERT_BACKOFF_SECONDS)
                continue
            return "budget_exhausted", last_error
        return "failed", last_error
    return "failed", last_error


def _reason_for(error: str) -> str:
    """Pick the manual_reason discriminator for a definitive revert failure."""
    return (
        _tax.MANUAL_REASON_ACCESS_DENIED
        if looks_like_access_denied(error)
        else _tax.MANUAL_REASON_REVERT_FAILED
    )


def _manual(
    ledger: Any,
    change_id: str | None,
    reason: str,
    remediation: str,
    object_dn: str,
    error: str,
) -> None:
    """Mark a change manual_required (no-op when ledger/change_id absent)."""
    if ledger is None or not change_id:
        return
    ledger.mark_manual_required(
        change_id,
        reason=reason,
        remediation_command=remediation,
        remediation_object_dn=object_dn,
        error=error,
    )


def _manual_instructions(kind: str, action: dict[str, Any]) -> str:
    """The client instruction that removes one queued change.

    Delegates to the ledger-record SSOT (``cleanup_taxonomy.remediation_for_entry``)
    with the queued action projected into the record shape, so the exit cleanup,
    the final retry pass, the kept list and the report all render the same
    command for the same change.
    """
    ledger_kind = "group_membership_added" if kind == "group_membership_changed" else kind
    detail = {
        key: value
        for key, value in action.items()
        if not str(key).startswith("_")
        and key not in ("exec_password", "original_secret")
    }
    entry = {
        "kind": ledger_kind,
        "target": str(action.get("target") or ""),
        "domain": str(action.get("target_domain") or action.get("domain") or ""),
        "detail": detail,
        "remediation_object_dn": str(
            action.get("target_dn") or action.get("object_dn") or action.get("dn") or ""
        ),
    }
    return _tax.remediation_for_entry(entry)


def _resolve_cleanup_actions(shell: Any) -> list[dict[str, Any]]:
    """Return in-memory cleanup actions plus pending actions reconstructed from ledger."""
    actions: list[dict[str, Any]] = []
    raw_actions = getattr(shell, "acl_cleanup_actions", None)
    if isinstance(raw_actions, list):
        actions.extend(action for action in raw_actions if isinstance(action, dict))

    seen_ids = {
        str(action.get("_ledger_change_id") or "")
        for action in actions
        if str(action.get("_ledger_change_id") or "")
    }
    ledger = active_ledger(shell)
    get_changes = getattr(ledger, "get_changes", None)
    if not callable(get_changes):
        return actions
    try:
        changes = get_changes()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return actions
    if not isinstance(changes, list):
        return actions

    for entry in changes:
        if not isinstance(entry, dict):
            continue
        change_id = str(entry.get("change_id") or "").strip()
        if change_id and change_id in seen_ids:
            continue
        status = str(entry.get("revert_status") or "").strip().lower()
        # Re-attempt records that are still pending/in-progress, or that landed in
        # the collapsed manual_required(revert_failed) terminal (legacy "failed").
        retryable = status in {
            _tax.STATUS_PENDING,
            _tax.STATUS_REVERT_IN_PROGRESS,
            _tax.STATUS_REVERT_FAILED_RETRYING,
            _tax.STATUS_LEGACY_FAILED,
        } or (
            status == _tax.STATUS_MANUAL_REQUIRED
            and str(entry.get("manual_reason") or "") in _tax.RETRYABLE_REVERT_REASONS
        )
        if not retryable:
            continue
        action = _cleanup_action_from_ledger_entry(entry)
        if action:
            actions.append(action)
            if change_id:
                seen_ids.add(change_id)
    return actions


def _cleanup_action_from_ledger_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Build one cleanup action from persisted environment ledger metadata."""
    kind = str(entry.get("kind") or "").strip()
    if kind not in {
        "shadow_credentials_added",
        "dacl_ace_added",
        "owner_changed",
        "spn_added",
        "password_changed",
        "group_membership_changed",
        _tax.KIND_ACCOUNT_ENABLED,
    }:
        return None
    detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
    action = {
        "kind": kind,
        "domain": str(entry.get("domain") or detail.get("domain") or "").strip(),
        "target_domain": str(
            detail.get("target_domain") or entry.get("domain") or ""
        ).strip(),
        "target": str(detail.get("target_object") or entry.get("target") or "").strip(),
        "exec_username": str(
            detail.get("exec_username") or detail.get("executor_username") or ""
        ).strip(),
        "_ledger_change_id": str(entry.get("change_id") or "").strip(),
    }
    for key in (
        "trustee",
        "rights_type",
        "original_owner_sid",
        "spn",
        "target_user",
        "added_key_credential_value",
        "target_group",
        "added_user",
        "object_kind",
        "prior_uac",
        "revertible",
    ):
        if key in detail:
            action[key] = detail[key]
    if kind == "password_changed" and detail.get("target_user"):
        action["target"] = str(detail.get("target_user") or "").strip()
    return action


