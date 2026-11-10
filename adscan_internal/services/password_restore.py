"""Put back a password the assessment reset, when its previous value is held.

A ForceChangePassword step replaces an account's password. When the session
already held that account's previous secret (it was the operator-supplied scan
account, it was cracked, or its NT hash was recovered), the change can be undone
exactly, and the environment-change ledger must not report it as permanent.

The restore follows the shared revert precedence (``revert_credentials``): the
client cleanup account, then a verified privileged account, then the principal
that made the reset. Each attempt is recorded on the ledger entry. The previous
secret lives only in memory for the session; it is never written to the ledger.

How the value goes back:

* previous **cleartext** password: an administrative reset to that value through
  the same posture-aware reset primitive the step used
  (``ExploitationService.acl.force_change_password``). The account's Kerberos
  keys are derived again from the same password and salt, so the restore is
  complete (only ``pwdLastSet`` keeps the new date; it cannot be set back).
* previous **NT hash** only: SAMR ``SamrSetInformationUser`` with
  ``UserInternal1Information`` (information class 18), the only SAMR class that
  carries an OWF rather than a cleartext buffer (``samr_set_nt_hash``). Sign-in
  with the old password works again, but a hash cannot rebuild the AES keys, so
  the record stays a client action: the owner changes the password once.

Confirmation is a sign-in AS the restored account with the previous secret. A
sign-in that fails counts against that account's lockout threshold, so one
attempt is reserved from its lockout budget first (``failing_auth_budget``); with
no headroom the restore is reported as unconfirmed rather than tested blind.
"""

from __future__ import annotations

from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import (
    mark_sensitive,
    print_exception,
    print_info,
    print_info_debug,
    print_warning,
)

__all__ = [
    "VERIFY_PASSWORD_SIGNIN",
    "restore_reset_password",
]

#: Ledger ``verification_method`` of a password restore confirmed by signing in.
VERIFY_PASSWORD_SIGNIN = "password_signin_with_previous_secret"

_PURPOSE = "password_changed"


def _looks_like_nt_hash(secret: str) -> bool:
    value = str(secret or "").strip()
    if ":" in value:
        value = value.split(":")[-1]
    return len(value) == 32 and all(c in "0123456789abcdefABCDEF" for c in value)


def _domain_data(shell: Any, domain: str) -> dict[str, Any]:
    data = (getattr(shell, "domains_data", {}) or {}).get(domain)
    return data if isinstance(data, dict) else {}


def _dc_endpoints(shell: Any, domain: str) -> tuple[str, str]:
    """``(dc_ip, dc_fqdn)`` of the domain the account lives in."""
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

    data = _domain_data(shell, domain)
    dc_ip = str(resolve_dc_ip(data) or "").strip()
    fqdn = str(
        data.get("pdc_hostname_fqdn") or data.get("dc_fqdn") or data.get("pdc_fqdn") or ""
    ).strip()
    return dc_ip, fqdn


def _set_previous_secret(
    shell: Any,
    *,
    candidate: Any,
    target_domain: str,
    target_user: str,
    original_secret: str,
    dc_ip: str,
    dc_fqdn: str,
) -> tuple[bool, Optional[str]]:
    """Write the previous secret back as ``candidate``. Returns ``(accepted, error)``."""
    from adscan_internal.services.password_reset_target import (  # noqa: PLC0415
        password_reset_verdict,
    )

    # Defense in depth: the reset being undone already passed this classifier
    # at the choke point, so an account a running system depends on never gets
    # here. Every password-setting call consults it all the same.
    verdict = password_reset_verdict(shell, domain=target_domain, account=target_user)
    if verdict.hard_blocked:
        return False, f"refused for safety: {verdict.client_safe_reason}"
    if _looks_like_nt_hash(original_secret):
        from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
        from adscan_internal.services.exploitation._samr_backend import (  # noqa: PLC0415
            samr_set_nt_hash,
        )

        netbios = str(_domain_data(shell, target_domain).get("netbios") or "").strip()
        config = candidate.smb_config(
            target_ip=dc_ip, target_hostname=dc_fqdn or dc_ip, kdc_ip=dc_ip
        )
        return run_async_sync(
            samr_set_nt_hash(
                smb_config=config,
                netbios_domain=netbios,
                sam_target=target_user,
                nt_hash=original_secret,
            )
        )

    from adscan_internal.services.exploitation import ExploitationService  # noqa: PLC0415

    result = ExploitationService().acl.force_change_password(
        pdc_host=dc_fqdn or dc_ip,
        pdc_ip=dc_ip,
        domain=candidate.domain,
        username=candidate.username,
        password=candidate.secret,
        target_user=target_user,
        new_password=original_secret,
        kerberos=True,
        timeout=300,
    )
    if bool(getattr(result, "success", False)):
        return True, None
    return False, str(getattr(result, "raw_error", "") or "the directory refused the reset")


def _sign_in_with_previous_secret(
    *, target_domain: str, target_user: str, original_secret: str, dc_ip: str, dc_fqdn: str
) -> tuple[bool, Optional[str]]:
    """Authenticate AS the restored account with its previous secret."""
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        ADscanLDAPConnection,
    )
    from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
        KIND_NT_HASH,
        KIND_PASSWORD,
        RevertCandidate,
    )

    probe = RevertCandidate(
        role="target",
        username=target_user,
        domain=target_domain,
        secret=original_secret,
        kind=KIND_NT_HASH if _looks_like_nt_hash(original_secret) else KIND_PASSWORD,
    )
    try:
        with ADscanLDAPConnection(probe.ldap_config(dc_ip=dc_ip, dc_fqdn=dc_fqdn or None)):
            return True, None
    except Exception as exc:  # noqa: BLE001 - a failed sign-in is the answer
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False, f"{type(exc).__name__}: {exc}"


def _store_previous_secret(
    shell: Any, *, target_domain: str, target_user: str, original_secret: str
) -> None:
    """Make the restored secret the account's active credential again."""
    try:
        from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
            CredentialStoreService,
        )

        domains_data = getattr(shell, "domains_data", None)
        if not isinstance(domains_data, dict):
            return
        CredentialStoreService().update_domain_credential(
            domains_data=domains_data,
            domain=target_domain,
            username=target_user,
            credential=original_secret,
            is_hash=_looks_like_nt_hash(original_secret),
            origin="password_restored",
            provenance_strength="proven",
        )
        creds = (domains_data.get(target_domain) or {}).get("credentials")
        if isinstance(creds, dict):
            # The reset password no longer works: the restored one is the only
            # secret that authenticates, whatever the format ranking prefers.
            for key in list(creds):
                if str(key).strip().lower() == target_user.strip().lower():
                    creds[key] = original_secret
                    break
    except Exception as exc:  # noqa: BLE001 - the ledger outcome stands regardless
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def restore_reset_password(
    shell: Any,
    *,
    ledger: Any,
    change_id: Optional[str],
    domain: str,
    target_domain: str,
    target_user: str,
    original_secret: str,
    creator_username: str = "",
    creator_secret: str = "",
) -> bool:
    """Put back the previous password of ``target_user`` and settle its ledger entry.

    Args:
        shell: The session shell.
        ledger: The environment-change ledger (may be ``None``).
        change_id: The ``password_changed`` entry being undone.
        domain: The domain of the principal that made the reset.
        target_domain: The domain the reset account lives in.
        target_user: The reset account's sAMAccountName.
        original_secret: Its previous password or NT hash (memory only).
        creator_username / creator_secret: The principal that made the reset.

    Returns:
        True only when the previous secret was put back AND a sign-in with it
        succeeded, with the full password (not only its hash) restored.
    """
    from adscan_internal.services import cleanup_taxonomy as _tax  # noqa: PLC0415
    from adscan_internal.services.failing_auth_budget import (  # noqa: PLC0415
        resolve_failing_auth_budget,
    )
    from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
        KIND_NT_HASH,
        KIND_PASSWORD,
        record_revert_rights,
        revert_candidates,
    )

    marked_target = mark_sensitive(target_user, "user")
    from_hash = _looks_like_nt_hash(original_secret)
    record = {
        "kind": _tax.KIND_PASSWORD_CHANGED,
        "target": target_user,
        "domain": target_domain,
        "detail": {"target_user": target_user},
    }
    instruction = _tax.remediation_for_entry(record)

    def _attempt(principal: str, role: str, outcome: str) -> None:
        recorder = getattr(ledger, "record_revert_credential_attempt", None)
        if ledger is None or not change_id or not callable(recorder):
            return
        try:
            recorder(change_id, principal=principal, role=role, outcome=outcome)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)

    def _manual(reason: str, error: str, command: str = "") -> None:
        if ledger is None or not change_id:
            return
        ledger.mark_manual_required(
            change_id,
            reason=reason,
            remediation_command=command or instruction,
            remediation_object_dn=target_user,
            error=error,
        )

    dc_ip, dc_fqdn = _dc_endpoints(shell, target_domain)
    if not dc_ip:
        _manual(
            _tax.MANUAL_REASON_MISSING_METADATA,
            f"No domain controller is known for {target_domain}.",
        )
        return False

    available = revert_candidates(
        shell,
        domain=target_domain,
        purpose=_PURPOSE,
        creator_username=creator_username,
        creator_secret=creator_secret,
        creator_domain=domain,
        exclude=(target_user,),
    )
    record_revert_rights(ledger, change_id, available)
    candidates = [c for c in available if c.kind in (KIND_PASSWORD, KIND_NT_HASH)]
    if not candidates:
        _manual(
            _tax.MANUAL_REASON_MISSING_CREDENTIAL,
            "No credential able to reset the account was available.",
        )
        return False

    last_error = "The previous password could not be put back."
    for candidate in candidates:
        try:
            accepted, error = _set_previous_secret(
                shell,
                candidate=candidate,
                target_domain=target_domain,
                target_user=target_user,
                original_secret=original_secret,
                dc_ip=dc_ip,
                dc_fqdn=dc_fqdn,
            )
        except Exception as exc:  # noqa: BLE001 - try the next credential
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            accepted, error = False, f"{type(exc).__name__}: {exc}"
        if not accepted:
            _attempt(candidate.username, candidate.role, "failed")
            last_error = error or last_error
            print_info_debug(
                "[password-restore] restore refused as "
                f"{mark_sensitive(candidate.username, 'user')} ({candidate.role}); "
                "trying the next credential"
            )
            continue

        # The directory accepted the previous secret. Confirm it by signing in
        # as the account, within its lockout headroom.
        budget = resolve_failing_auth_budget(
            shell,
            domain=target_domain,
            username=target_user,
            password=None,
            dc_ip=dc_ip,
            kerberos_target_hostname=dc_fqdn or None,
            reader_username=candidate.username,
            reader_password=candidate.secret,
        )
        if not budget.try_reserve():
            _attempt(candidate.username, candidate.role, "unconfirmed")
            print_warning(
                "Previous password put back, but the confirming sign-in was skipped to "
                f"protect the account from lockout · {marked_target}"
            )
            _manual(
                _tax.MANUAL_REASON_REVERT_UNCONFIRMED,
                f"The previous password was set again; no sign-in was attempted ({budget.reason}).",
            )
            return False
        signed_in, sign_in_error = _sign_in_with_previous_secret(
            target_domain=target_domain,
            target_user=target_user,
            original_secret=original_secret,
            dc_ip=dc_ip,
            dc_fqdn=dc_fqdn,
        )
        if not signed_in:
            _attempt(candidate.username, candidate.role, "failed")
            print_warning(f"Could not confirm the restored password · {marked_target}")
            _manual(
                _tax.MANUAL_REASON_REVERT_FAILED,
                "The directory accepted the previous password, but signing in with it "
                f"failed: {sign_in_error}",
            )
            return False
        budget.refund()  # a successful sign-in does not count as a failure
        _attempt(candidate.username, candidate.role, "reverted")
        _store_previous_secret(
            shell,
            target_domain=target_domain,
            target_user=target_user,
            original_secret=original_secret,
        )
        if from_hash:
            print_info(
                "Previous password restored from its hash; the owner must change it once "
                f"· {marked_target}"
            )
            hash_record = dict(record)
            hash_record["manual_reason"] = _tax.MANUAL_REASON_PASSWORD_RESTORED_FROM_HASH
            _manual(
                _tax.MANUAL_REASON_PASSWORD_RESTORED_FROM_HASH,
                "Restored from the NT hash; the account's Kerberos AES keys are rebuilt "
                "only when its password next changes.",
                command=_tax.remediation_for_entry(hash_record),
            )
            return False
        if ledger is not None and change_id:
            ledger.mark_reverted_confirmed(change_id, verification_method=VERIFY_PASSWORD_SIGNIN)
        return True

    _manual(
        _tax.MANUAL_REASON_ACCESS_DENIED
        if "denied" in last_error.lower()
        else _tax.MANUAL_REASON_REVERT_FAILED,
        last_error,
    )
    print_warning(f"Could not put the previous password back · {marked_target}")
    return False
