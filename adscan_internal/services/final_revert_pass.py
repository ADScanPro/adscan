"""The final retry pass: one more attempt at every pending revert, at the end.

Founder decision 2026-11-05 ("Reversion de cambios en el directorio"), timing:

* a change needed only during one step is reverted right after that step (the
  step-scoped rollback, unchanged);
* a reusable object is reverted at the end of the run (the exit cleanup);
* then ONE final pass retries every revert still outstanding with the best
  credential available AT THAT MOMENT.

Why a pass at the end: the run's best credential usually arrives late. A
machine account created early by an ordinary account cannot be deleted by it;
by the end the run may hold a verified Domain Admin, or the client supplied a
cleanup account. Retrying then turns "manual_required" or "disabled, still
holding a quota slot" into a confirmed deletion without the client lifting a
finger.

Rules:
* Only entries whose revert can still succeed with a different credential are
  retried: ``manual_required`` for an access, credential or revert failure, and
  machine accounts that were only disabled. A change that is manual BY DESIGN
  (a reset password, a restored object) is never touched.
* Only credentials NOT already tried for that entry are used (the attempt log
  on the ledger), so the pass never repeats a failed logon.
* It honours the automatic-reversion switch: off means nothing is retried.
* One pass, best effort, never raises; runs before ``ledger.finalize()``.

Changes inherited from a session that ended
-------------------------------------------
A run that is killed leaves its records on disk with no exit cleanup: still
``pending`` (or mid-revert), or ``manual_required(session_died)`` when the
dying process got as far as ``finalize()``. The next run of the workspace (a
resume) loads them, and they are still ADscan's changes. The services that undo
a change during a run hold what they need in memory, so nothing in the new run
owns those records, and ``finalize()`` used to settle them as
``manual_required(session_died)`` without one attempt, although the run held
the same credentials and the same cleanup account (release gate R32: an
``xp_cmdshell`` enable was left on a SQL Server while the same run revoked the
certificates the killed run had issued, because their record happened to be
``manual_required`` already).

So this pass also takes every inherited record whose revert never settled and
sends it through the same dispatcher and the same precedence as a change of its
own. It becomes ``manual_required`` only when no dispatcher exists for its
kind, no account is available, or the attempt fails, each with its real reason.
A record this process registered is never taken that way: its own service
still owns it. ``RESUMABLE_REVERT_KINDS`` (``adscan_core``) names the kinds a
dispatcher exists for, and is what the platform reads to tell a client which
changes a resumed scan undoes.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info, print_info_debug

__all__ = [
    "run_final_revert_retry_pass",
    "RETRYABLE_MANUAL_REASONS",
    "entry_is_retryable",
    "scheduled_reverter",
    "DISPATCHED_KINDS",
    "NOT_DISPATCHED_KINDS",
]

#: ``manual_required`` reasons a different credential can overturn.
RETRYABLE_MANUAL_REASONS: frozenset[str] = frozenset(
    {
        "access_denied",
        "missing_credential",
        "revert_failed",
        "revert_unconfirmed",
        "neutralized_not_deleted",
        # No account with the rights was available earlier; the final pass may
        # hold one now (a cleanup account or a domain administrator).
        "no_privileged_credential",
        # Settled by a session that ended before it could try the revert.
        "session_died",
    }
)

_RELAY_KINDS = frozenset(
    {
        "machine_account_created",
        "computer_account_created",
        "rbcd_delegation_added",
        "keycredentiallink_added",
    }
)
_ACL_KINDS = frozenset(
    {
        "shadow_credentials_added",
        "dacl_ace_added",
        "owner_changed",
        "spn_added",
        "group_membership_changed",
        "group_membership_added",
        "account_enabled",
    }
)
_CERTIFICATE_KINDS = frozenset({"issued_certificate"})
_MSSQL_XP_CMDSHELL_KINDS = frozenset({"mssql_xp_cmdshell_enabled"})

#: Every kind this pass can undo from the ledger record alone. Equal to
#: ``adscan_core.reporting.cleanup_outcome.RESUMABLE_REVERT_KINDS`` (tested).
DISPATCHED_KINDS: frozenset[str] = (
    _RELAY_KINDS | _ACL_KINDS | _CERTIFICATE_KINDS | _MSSQL_XP_CMDSHELL_KINDS
)


#: Its own exit cleanup rebuilds an unsettled record from the ledger, so a
#: record an ended session left is retried there, not by this pass.
NOT_DISPATCHED_OWN_EXIT_CLEANUP = "own_exit_cleanup"
#: Nothing can undo this kind from the ledger record alone: its revert runs
#: only inside the session that made the change (it needs state that session
#: held in memory), or no automatic undo exists for it. A record an ended
#: session left is settled as manual, with the instruction that removes it.
NOT_DISPATCHED_NO_LEDGER_REVERTER = "no_ledger_reverter"

#: Every other change kind of the taxonomy, with why this pass does not undo it
#: from the ledger record. A kind is here or in :data:`DISPATCHED_KINDS`, never
#: in neither (tested), so a new kind cannot ship without deciding what happens
#: to a change of that kind when the session that made it ends.
NOT_DISPATCHED_KINDS: dict[str, str] = {
    "password_changed": NOT_DISPATCHED_OWN_EXIT_CLEANUP,
    "mssql_admin_account_created": NOT_DISPATCHED_OWN_EXIT_CLEANUP,
    "dns_record_added": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "user_created": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "scheduled_task_created": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "logon_script_path_modified": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "rodc_prp_modified": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "object_restored": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "ca_officer_added": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "ca_private_key_exfiltrated": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "forged_certificate": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "ca_backup_service": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "ca_backup_temp_pfx": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "file_written": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "file_uploaded": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "template_modified": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "template_mutated": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "ca_template_enabled": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "acl_modified": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "spn_relocated": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "upn_changed": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "altsecurityidentities_written": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "victim_attribute_written": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "dacl_grant_dcsync": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "gpo_ldap_attribute_modified": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "gpo_gpt_ini_modified": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "gpo_sysvol_dir_created": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "gpo_sysvol_file_created": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "mssql_postex_account": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "mssql_clr_assembly_loaded": NOT_DISPATCHED_NO_LEDGER_REVERTER,
    "mssql_clr_config_changed": NOT_DISPATCHED_NO_LEDGER_REVERTER,
}


def _inherited_unsettled(entry: dict[str, Any]) -> bool:
    from adscan_internal.services.environment_change_ledger import (  # noqa: PLC0415
        change_is_inherited_unsettled,
    )

    return change_is_inherited_unsettled(entry)


def entry_is_retryable(entry: dict[str, Any]) -> bool:
    """Whether a ledger entry is worth one more attempt with a new credential."""
    if not isinstance(entry, dict):
        return False
    kind = str(entry.get("kind") or "")
    status = str(entry.get("revert_status") or "").strip().lower()
    detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
    if kind in ("machine_account_created", "computer_account_created") and bool(
        (detail or {}).get("neutralized_only")
    ):
        return True
    has_ca_identifiers = bool((detail or {}).get("serial") and (detail or {}).get("ca_name"))
    if status != "manual_required":
        # A record an ended session left unsettled: nothing in this run owns
        # it, so this pass is its one attempt.
        if kind not in DISPATCHED_KINDS or not _inherited_unsettled(entry):
            return False
        return has_ca_identifiers if kind in _CERTIFICATE_KINDS else True
    reason = str(entry.get("manual_reason") or "")
    if kind in _CERTIFICATE_KINDS:
        # Revocation is attempted only when the CA identifiers were recorded.
        return reason in RETRYABLE_MANUAL_REASONS | {"not_attempted"} and has_ca_identifiers
    return reason in RETRYABLE_MANUAL_REASONS


def _dispatcher_for(kind: str) -> Optional[Callable[..., bool]]:
    if kind in _RELAY_KINDS:
        from adscan_internal.cli.relay_rbcd import (  # noqa: PLC0415
            revert_ledger_entry_with_cascade,
        )

        return revert_ledger_entry_with_cascade
    if kind in _ACL_KINDS:
        from adscan_internal.services.acl_change_cleanup_service import (  # noqa: PLC0415
            retry_ledger_entry,
        )

        return retry_ledger_entry
    if kind in _CERTIFICATE_KINDS:
        from adscan_internal.services.adcs.certificate_revocation import (  # noqa: PLC0415
            revoke_ledger_certificate,
        )

        return revoke_ledger_certificate
    if kind in _MSSQL_XP_CMDSHELL_KINDS:
        from adscan_internal.cli.mssql import (  # noqa: PLC0415
            revert_ledger_xp_cmdshell_entry,
        )

        return revert_ledger_xp_cmdshell_entry
    return None


def _has_untried_candidate(shell: Any, entry: dict[str, Any], tried: set[str]) -> bool:
    from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
        revert_candidates,
    )

    detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
    domain = str((detail or {}).get("target_domain") or entry.get("domain") or "")
    candidates = revert_candidates(
        shell,
        domain=domain,
        purpose=str(entry.get("kind") or ""),
        creator_username=str(
            (detail or {}).get("executor_username") or (detail or {}).get("exec_username") or ""
        ),
        exclude=tried,
    )
    return bool(candidates)


def scheduled_reverter(shell: Any, entry: dict[str, Any]) -> str:
    """Who this pass will try to undo ``entry`` as, in operator words (``""``: nobody).

    The question a change asks at the moment it is made: "will the final pass
    attempt my revert?". The answer uses the pass's own rules (the automatic
    reversion switch, :func:`entry_is_retryable`, a credential the revert
    precedence offers for this kind), so what is announced at registration and
    what the pass later does cannot disagree. Never raises.
    """
    try:
        from adscan_internal.services.durable_change_policy import (  # noqa: PLC0415
            resolve_auto_revert,
        )
        from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
            ROLE_CLEANUP,
            ROLE_CLEANUP_SAVED,
            revert_candidates,
        )

        if not resolve_auto_revert(shell).enabled or not entry_is_retryable(entry):
            return ""
        if _dispatcher_for(str(entry.get("kind") or "")) is None:
            return ""
        detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
        candidates = revert_candidates(
            shell,
            domain=str((detail or {}).get("target_domain") or entry.get("domain") or ""),
            purpose=str(entry.get("kind") or ""),
            creator_username=str(
                (detail or {}).get("executor_username") or (detail or {}).get("exec_username") or ""
            ),
        )
        if not candidates:
            return ""
        if candidates[0].role in (ROLE_CLEANUP, ROLE_CLEANUP_SAVED):
            return "the cleanup account"
        return "a privileged account verified during the run"
    except Exception as exc:  # noqa: BLE001 - an unknown answer is "not scheduled"
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ""


def run_final_revert_retry_pass(shell: Any) -> int:
    """Retry every outstanding revert once with credentials not yet tried.

    Returns the number of entries confirmed reverted by this pass. Whatever
    the pass did, a revert that was scheduled for it and did not happen is
    announced as manual when it ends.
    """
    try:
        return _run_final_revert_retry_pass(shell)
    finally:
        _settle_scheduled(shell)


def _settle_scheduled(shell: Any) -> None:
    try:
        from adscan_internal.services.ledger_guard import active_ledger  # noqa: PLC0415

        settle = getattr(active_ledger(shell), "settle_scheduled_reverts", None)
        if callable(settle):
            settle()
    except Exception as exc:  # noqa: BLE001 - never block shutdown
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _settle_inherited_without_candidate(
    shell: Any, ledger: Any, entry: dict[str, Any], tried: set[str]
) -> None:
    """Give an inherited unsettled record its real reason when no account can try.

    Without this it would reach ``finalize()`` and read "session ended before
    rollback completed", which hides what is actually missing: an account.
    """
    if not _inherited_unsettled(entry):
        return
    mark = getattr(ledger, "mark_manual_required", None)
    change_id = str(entry.get("change_id") or "")
    if not callable(mark) or not change_id:
        return
    from adscan_internal.services import cleanup_taxonomy as _tax  # noqa: PLC0415

    if tried and _has_untried_candidate(shell, entry, set()):
        reason = _tax.MANUAL_REASON_REVERT_FAILED
        error = (
            "Every account available to the assessment had already tried this revert "
            "before the earlier session ended."
        )
    else:
        reason = _tax.MANUAL_REASON_NO_PRIVILEGED_CREDENTIAL
        error = (
            "The session that made this change ended before undoing it, and this run "
            "holds no account that can."
        )
    mark(
        change_id,
        reason=reason,
        remediation_command=_tax.remediation_for_entry(entry),
        remediation_object_dn=str(entry.get("remediation_object_dn") or ""),
        error=error,
    )


def _run_final_revert_retry_pass(shell: Any) -> int:
    try:
        from adscan_internal.services.durable_change_policy import (  # noqa: PLC0415
            resolve_auto_revert,
        )
        from adscan_internal.services.ledger_guard import active_ledger  # noqa: PLC0415
        from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
            tried_principals,
        )

        if not resolve_auto_revert(shell).enabled:
            return 0
        ledger = active_ledger(shell)
        get_changes = getattr(ledger, "get_changes", None)
        if not callable(get_changes):
            return 0
        pending = [e for e in get_changes() if entry_is_retryable(e)]
    except Exception as exc:  # noqa: BLE001 - never block shutdown
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return 0
    if not pending:
        return 0

    confirmed = 0
    announced = False
    for entry in pending:
        kind = str(entry.get("kind") or "")
        dispatch = _dispatcher_for(kind)
        if dispatch is None:
            continue
        try:
            tried = tried_principals(entry)
            if not _has_untried_candidate(shell, entry, tried):
                print_info_debug(f"final-revert-pass skip kind={kind}: no untried credential")
                _settle_inherited_without_candidate(shell, ledger, entry, tried)
                continue
            if not announced:
                print_info(
                    "Final cleanup pass: retrying outstanding reverts with the best "
                    "credential available now."
                )
                announced = True
            if dispatch(shell, ledger=ledger, entry=entry, exclude=tuple(tried)):
                confirmed += 1
        except Exception as exc:  # noqa: BLE001 - one entry never blocks the rest
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    if announced:
        print_info(f"Final cleanup pass: {confirmed} change(s) reverted on retry.")
    return confirmed
