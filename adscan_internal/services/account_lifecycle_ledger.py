"""Ledger recording for account lifecycle writes ADscan makes as step preparation.

Re-enabling a disabled account and restoring a deleted object from the AD
Recycle Bin are directory changes in their own right, even though they only
prepare the technique that follows. Each one is recorded here, at the shell
seams every caller funnels through (``PentestShell.enable_user`` /
``enable_computer`` / ``restore_deleted_object``), so the environment-change
disclosure in the report lists it and the exit cleanup can act on it:

* ``account_enabled``: reverted at exit by setting ACCOUNTDISABLE again and
  re-reading ``userAccountControl`` to confirm it (verified automatic revert).
  Recorded ONLY when ADscan actually cleared the bit; an account that was
  already enabled is not ADscan's change and is never disabled at cleanup.
* ``object_restored``: never reverted automatically. Deleting the object again
  is a decision for the client's directory owners, so the record goes straight
  to ``manual_required`` with the object DN and the native command.

Both record into the ledger AND ``shell.acl_cleanup_actions``, the queue the
ACL cleanup service drains at exit, mirroring ``directory_write_ledger.record_directory_write``.
"""

from __future__ import annotations

from adscan_internal.services.ledger_guard import ledger_or_warn

from typing import Any, Optional

from adscan_internal import telemetry
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_core.rich_output import print_exception

__all__ = [
    "KIND_ACCOUNT_ENABLED",
    "KIND_OBJECT_RESTORED",
    "record_account_enabled",
    "record_object_restored",
]

KIND_ACCOUNT_ENABLED = _tax.KIND_ACCOUNT_ENABLED
KIND_OBJECT_RESTORED = _tax.KIND_OBJECT_RESTORED

_UF_ACCOUNTDISABLE = 0x2


def _append_action(shell: Any, action: dict[str, Any]) -> None:
    actions = getattr(shell, "acl_cleanup_actions", None)
    if isinstance(actions, list):
        actions.append(action)


def record_account_enabled(
    shell: Any,
    *,
    domain: str,
    target: str,
    object_kind: str,
    change: Any,
    exec_username: str,
    exec_password: str,
) -> Optional[str]:
    """Record an account ADscan enabled; returns the ledger ``change_id``.

    Args:
        shell: The active shell (carries the ledger and the cleanup queue).
        domain: The domain the account lives in.
        target: The account's sAMAccountName.
        object_kind: ``"user"`` or ``"computer"``.
        change: The service result. An ``AccountStateChange`` carries
            ``changed`` / ``prior_uac``; a bare ``bool`` (a test double or an
            older implementation) is treated as "changed, prior state unknown",
            which records the change but never re-disables automatically.
        exec_username: The principal that performed the write.
        exec_password: Its secret, kept in-memory for the cleanup credential.

    Returns:
        The ledger change id, or ``None`` when nothing was recorded.
    """
    if not bool(change):
        return None
    changed = getattr(change, "changed", True)
    if changed is False:
        return None
    prior_uac = getattr(change, "prior_uac", None)
    # Automatic re-disable is safe only when the read before the write proved the
    # account WAS disabled. Anything else is recorded but left to the client.
    revertible = isinstance(prior_uac, int) and bool(prior_uac & _UF_ACCOUNTDISABLE)
    ledger = ledger_or_warn(shell)
    change_id: Optional[str] = None
    if ledger is not None:
        try:
            change_id = ledger.register_change(
                kind=KIND_ACCOUNT_ENABLED,
                domain=domain,
                target=target,
                detail={
                    "target_domain": domain,
                    "target_object": target,
                    "object_kind": object_kind,
                    "prior_uac": prior_uac,
                    "new_uac": getattr(change, "new_uac", None),
                    "revertible": revertible,
                    "exec_username": exec_username,
                    "executor_username": exec_username,
                    "executor_auth_domain": domain,
                    "credential_lookup_domain": domain,
                },
                method=f"Enable disabled {object_kind} account before the attack step",
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    _append_action(
        shell,
        {
            "kind": KIND_ACCOUNT_ENABLED,
            "domain": domain,
            "target_domain": domain,
            "target": target,
            "object_kind": object_kind,
            "prior_uac": prior_uac,
            "revertible": revertible,
            "exec_username": exec_username,
            "exec_password": exec_password,
            "_ledger_change_id": change_id,
        },
    )
    return change_id


def record_object_restored(
    shell: Any,
    *,
    domain: str,
    restored_dn: str,
    sam_account_name: Optional[str],
    exec_username: str,
) -> Optional[str]:
    """Record a deleted object ADscan restored; settled ``manual_required`` now.

    Args:
        shell: The active shell.
        domain: The domain the object lives in.
        restored_dn: The live DN the object was restored to.
        sam_account_name: Its sAMAccountName, when known.
        exec_username: The principal that performed the restore.

    Returns:
        The ledger change id, or ``None`` when no ledger is available.
    """
    ledger = ledger_or_warn(shell)
    if ledger is None:
        return None
    target = str(sam_account_name or restored_dn or "").strip()
    try:
        change_id = ledger.register_change(
            kind=KIND_OBJECT_RESTORED,
            domain=domain,
            target=target,
            detail={
                "target_domain": domain,
                "target_object": target,
                "restored_dn": restored_dn,
                "exec_username": exec_username,
                "executor_username": exec_username,
            },
            method="Restore deleted object from the AD Recycle Bin before the attack step",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    try:
        ledger.mark_manual_required(
            change_id,
            reason=_tax.MANUAL_REASON_NOT_ATTEMPTED,
            remediation_command=_tax.object_restored_remediation(restored_dn or target),
            remediation_object_dn=restored_dn or target,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return change_id
