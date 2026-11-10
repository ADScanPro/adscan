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
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info, print_info_debug

__all__ = ["run_final_revert_retry_pass", "RETRYABLE_MANUAL_REASONS", "entry_is_retryable"]

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
    if status != "manual_required":
        return False
    reason = str(entry.get("manual_reason") or "")
    if kind in _CERTIFICATE_KINDS:
        # Revocation is attempted only when the CA identifiers were recorded.
        return reason in RETRYABLE_MANUAL_REASONS | {"not_attempted"} and bool(
            (detail or {}).get("serial") and (detail or {}).get("ca_name")
        )
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


def run_final_revert_retry_pass(shell: Any) -> int:
    """Retry every outstanding revert once with credentials not yet tried.

    Returns the number of entries confirmed reverted by this pass.
    """
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
