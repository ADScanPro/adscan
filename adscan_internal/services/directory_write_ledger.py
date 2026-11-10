"""Ledger recording for the directory writes made by the ACL write seams.

The write seams in ``cli/exploits.py`` (``run_exploit_write_spn``,
``run_exploit_force_change_password``, ``run_exploit_add_member``,
``run_exploit_write_dacl``, ``run_exploit_write_owner``) are reached from several
callers: the attack-path ACE step, the interactive ACL menu
(``enumerate_user_aces``), the post-step follow-ups and the GenericAll / OU
helpers. Recording used to live in ONE of those callers (the ACE step), so every
other path changed the client's directory without leaving a trace, and the ACE
step recorded what it assumed had happened (a GenericAll on a user was always
"shadow credentials", whatever the helper actually wrote).

Recording now happens at the seam, once, from what the write really did, and
every caller inherits it:

* :func:`record_directory_write` registers a revertible change in the
  environment-change ledger AND queues it on ``shell.acl_cleanup_actions``, the
  list the ACL cleanup service drains at exit (revert, then re-read to confirm).
* :func:`record_password_reset` registers a password reset and settles it
  ``manual_required`` immediately: the previous secret is gone, so there is
  nothing to revert, only a reset for the client to run.
* :func:`claim_directory_write` lets a caller with its OWN revert mechanism (the
  attack-path cleanup scope, which removes a group membership when the path
  ends) take over a seam record: it drops the queued exit action so the change
  is reverted once, and keeps the ledger record so it is reported once.

Never record a change ADscan did not make: each seam calls these only after the
directory confirmed the write, and never for a value that already existed (an
SPN the account already held, a membership already present).
"""

from __future__ import annotations

from adscan_internal.services.ledger_guard import ledger_or_warn

from typing import Any, Optional

from adscan_internal import telemetry
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_core.rich_output import print_exception

__all__ = [
    "record_directory_write",
    "record_password_reset",
    "claim_directory_write",
]


def record_directory_write(
    shell: Any,
    *,
    kind: str,
    domain: str,
    target_domain: str,
    target: str,
    exec_username: str,
    exec_password: str,
    method: str,
    detail: Optional[dict[str, Any]] = None,
    action_kind: Optional[str] = None,
) -> Optional[str]:
    """Record one revertible directory write; returns the ledger ``change_id``.

    Args:
        shell: The active shell (carries the ledger and the exit cleanup queue).
        kind: The ledger change kind (a ``cleanup_taxonomy`` kind).
        domain: The executor's domain (where its credential lives).
        target_domain: The domain of the object that was written.
        target: The written object (sAMAccountName, DN or label).
        exec_username: The principal that performed the write.
        exec_password: Its secret, kept in memory for the cleanup credential.
        method: Human-readable technique that caused the change.
        detail: Kind-specific metadata the revert plan reads (``spn``,
            ``trustee``, ``original_owner_sid``, ``target_group`` ...).
        action_kind: The exit-cleanup action kind, when it differs from the
            ledger kind (a group membership is ledger ``group_membership_added``
            and cleanup ``group_membership_changed``).

    Returns:
        The ledger change id, or ``None`` when no ledger is available. Never raises.
    """
    ledger = ledger_or_warn(shell)
    actions = getattr(shell, "acl_cleanup_actions", None)
    extra = dict(detail or {})
    change_id: Optional[str] = None
    if ledger is not None:
        try:
            ledger_detail: dict[str, Any] = {
                "target_domain": target_domain,
                "target_object": target,
                "exec_username": exec_username,
                "executor_username": exec_username,
                "executor_auth_domain": domain,
                "credential_lookup_domain": domain,
            }
            ledger_detail.update(extra)
            change_id = ledger.register_change(
                kind=kind,
                domain=domain,
                target=target,
                detail=ledger_detail,
                method=method,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    if isinstance(actions, list):
        action: dict[str, Any] = {
            "kind": action_kind or kind,
            "domain": domain,
            "target_domain": target_domain,
            "target": target,
            "exec_username": exec_username,
            "exec_password": exec_password,
            "_ledger_change_id": change_id,
        }
        action.update(extra)
        actions.append(action)
    return change_id


def record_password_reset(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    target_user: str,
    exec_username: str,
    method: str,
    remediation_command: Optional[str] = None,
    detail: Optional[dict[str, Any]] = None,
    original_secret: Optional[str] = None,
    exec_password: str = "",
    reason: Optional[str] = None,
) -> Optional[str]:
    """Record a password ADscan reset.

    Two shapes, decided by whether the previous secret is held:

    * ``original_secret`` given: the reset can be undone exactly. The record
      stays pending and an exit-cleanup action carrying the previous secret IN
      MEMORY ONLY is queued; the exit cleanup puts it back through the shared
      revert precedence and confirms it by signing in with it
      (``password_restore``). The ledger never stores the secret.
    * no previous secret: nothing can restore it, so the record is settled
      ``manual_required`` at once with ``reason`` and the reset instruction.

    Args:
        shell: The active shell.
        domain: The executor's domain.
        target_domain: The domain of the account whose password was reset.
        target_user: That account's sAMAccountName.
        exec_username: The principal that performed (or staged) the reset.
        method: Human-readable technique that caused the change.
        remediation_command: The client-facing command; defaults to the
            confirmed-reset instruction built from the record.
        detail: Extra metadata (``reason``, ``reset_observed`` ...).
        original_secret: The account's previous password or NT hash, when held.
        exec_password: The executor's secret (memory only), a revert candidate.
        reason: ``manual_reason`` when no previous secret is held; defaults to
            ``not_attempted`` (no automatic rollback is possible).

    Returns:
        The ledger change id, or ``None`` when no ledger is available. Never raises.
    """
    ledger = ledger_or_warn(shell)
    if ledger is None:
        return None
    record_detail: dict[str, Any] = {
        "target_domain": target_domain,
        "target_object": target_user,
        "target_user": target_user,
        "exec_username": exec_username,
        "executor_username": exec_username,
        "executor_auth_domain": domain,
        "credential_lookup_domain": domain,
    }
    record_detail.update(detail or {})
    if original_secret:
        record_detail["previous_secret_held"] = True
    command = (
        remediation_command
        or _tax.remediation_for_entry(
            {"kind": _tax.KIND_PASSWORD_CHANGED, "target": target_user, "detail": record_detail}
        )
    ).replace("TARGET", target_user)
    try:
        change_id = ledger.register_change(
            kind=_tax.KIND_PASSWORD_CHANGED,
            domain=domain,
            target=target_user,
            detail=record_detail,
            method=method,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    try:
        if original_secret:
            ledger.set_revert_metadata(
                change_id,
                remediation_command=command,
                remediation_object_dn=target_user,
            )
            actions = getattr(shell, "acl_cleanup_actions", None)
            if isinstance(actions, list):
                actions.append(
                    {
                        "kind": _tax.KIND_PASSWORD_CHANGED,
                        "domain": domain,
                        "target_domain": target_domain,
                        "target": target_user,
                        "target_user": target_user,
                        "exec_username": exec_username,
                        "exec_password": exec_password,
                        "original_secret": original_secret,
                        "_ledger_change_id": change_id,
                    }
                )
        else:
            ledger.mark_manual_required(
                change_id,
                reason=reason or _tax.MANUAL_REASON_NOT_ATTEMPTED,
                remediation_command=command,
                remediation_object_dn=target_user,
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return change_id


def claim_directory_write(shell: Any, change_id: Optional[str]) -> bool:
    """Hand a seam record's revert over to the caller; True when it was queued.

    Removes the exit-cleanup action carrying ``change_id`` so the change is
    reverted once (by the claiming caller), while the ledger record stays the
    single disclosure of it. Never raises.
    """
    if not change_id:
        return False
    actions = getattr(shell, "acl_cleanup_actions", None)
    if not isinstance(actions, list):
        return False
    for idx, action in enumerate(list(actions)):
        if isinstance(action, dict) and action.get("_ledger_change_id") == change_id:
            del actions[idx]
            return True
    return False
