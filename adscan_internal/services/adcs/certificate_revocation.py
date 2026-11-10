"""Revoke the certificates the assessment obtained, when a credential can.

Every certificate a live CA issued during the assessment is disclosed at issue
time as ``manual_required`` with the native revocation procedure
(``esc_cleanup.register_issued_certificate``). That disclosure stays the floor.
On top of it, founder decision 2026-11-05: when the run holds a credential with
certificate-manager rights on the CA (the client cleanup account, or a verified
privileged account), ADscan revokes the certificate itself through the CA
administration interface (MS-CSRA ``ICertAdminD::RevokeCertificate``, native
aiosmb DCOM, Kerberos-capable) and CONFIRMS it by re-reading the CA database
(``IsValidCertificate``).

What the report states, honestly: the CA has recorded the revocation, and
relying parties stop accepting the certificate once the CA publishes its next
certificate revocation list. A domain controller that cached the previous list
keeps accepting it until then; the client can publish immediately with
``certutil -CRL``.

The certificate's own enrollee is never tried: enrolling does not grant
certificate-manager rights.
"""

from __future__ import annotations

from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import mark_sensitive, print_exception, print_info, print_success

__all__ = [
    "VERIFY_CERTIFICATE_REVOKED",
    "revoked_certificate_note",
    "revoke_ledger_certificate",
]

#: Ledger ``verification_method`` for a revocation confirmed by re-reading the CA.
VERIFY_CERTIFICATE_REVOKED = "ca_database_reread_revoked"

#: CRL reason: key compromise (the private key was generated outside the
#: client's control, which is the accurate reason).
_REASON_KEY_COMPROMISE = 1


def revoked_certificate_note(*, ca_config: str) -> str:
    """What the client reads under a certificate ADscan revoked itself."""
    return (
        "Revoked on the certification authority during the assessment, reason key "
        "compromise. Relying parties stop accepting the certificate once the CA "
        "publishes its next certificate revocation list. To publish one now, run this "
        "command on the CA.\n"
        f'  certutil -config "{ca_config}" -CRL'
    )


def _smb_config_for(candidate: Any, *, ca_host: str, dc_ip: Optional[str], posture: Any) -> Any:
    from adscan_internal.services.adcs.ca_admin import _build_ca_smb_config  # noqa: PLC0415
    from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
        KIND_AES128,
        KIND_AES256,
        KIND_CCACHE,
        KIND_NT_HASH,
    )

    if candidate.kind in (KIND_AES128, KIND_AES256):
        return None  # the CA admin seam takes password, hash or ticket
    return _build_ca_smb_config(
        ca_host=ca_host,
        domain=candidate.domain,
        username=candidate.username,
        password=candidate.secret if candidate.kind == "password" else None,
        nt_hash=candidate.secret if candidate.kind == KIND_NT_HASH else None,
        ccache_path=candidate.secret if candidate.kind == KIND_CCACHE else None,
        dc_ip=dc_ip,
        posture_snapshot=posture,
    )


def _revoke_once(smb_config: Any, *, ca_name: str, serial: str) -> tuple[bool, str]:
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415

    async def _run() -> tuple[bool, str]:
        from adscan_internal.services.smb_transport import (  # noqa: PLC0415
            smb_machine_with_fallback,
        )

        async with smb_machine_with_fallback(smb_config) as machine:
            code, err = await machine.revoke_cert_dcom(ca_name, serial, _REASON_KEY_COMPROMISE)
            if err is not None:
                return False, str(err)
            if code:
                return False, f"CA returned {code} (revocation not confirmed by re-read)"
            return True, ""

    return run_async_sync(_run())


def revoke_ledger_certificate(
    shell: Any, *, ledger: Any, entry: dict[str, Any], exclude: tuple[str, ...] = ()
) -> bool:
    """Revoke one ledger ``issued_certificate`` with the shared revert precedence.

    Returns True when the CA database shows the certificate revoked. Any other
    outcome leaves the entry as it was: ``manual_required`` with the native
    procedure, which is exactly what the client still has to do.
    """
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415
    from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415
    from adscan_internal.services.revert_credentials import (  # noqa: PLC0415
        revert_candidates,
        run_revert_cascade,
    )

    detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
    serial = str((detail or {}).get("serial") or "").strip()
    ca_name = str((detail or {}).get("ca_name") or "").strip()
    domain = str(entry.get("domain") or "")
    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain) or {}
    ca_host = str((detail or {}).get("ca_host") or "").strip() or str(
        domain_data.get("pdc") or ""
    )
    change_id = str(entry.get("change_id") or "") or None
    if not (serial and ca_name and ca_host and change_id):
        return False
    dc_ip = resolve_dc_ip(domain_data) if domain_data else None
    try:
        posture = get_posture(getattr(shell, "domains_data", {}) or {}, domain=domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        posture = None
    candidates = revert_candidates(
        shell, domain=domain, purpose="issued_certificate", exclude=exclude
    )
    if not candidates:
        return False
    ca_config = f"{ca_host}\\{ca_name}"

    def _attempt(candidate: Any, attempt_ledger: Any, _final: bool) -> None:
        smb_config = _smb_config_for(candidate, ca_host=ca_host, dc_ip=dc_ip, posture=posture)
        if smb_config is None:
            raise RuntimeError("credential kind not usable against the CA")
        ok, error = _revoke_once(smb_config, ca_name=ca_name, serial=serial)
        if not ok:
            raise RuntimeError(error or "revocation failed")
        attempt_ledger.set_revert_metadata(
            change_id, remediation_command=revoked_certificate_note(ca_config=ca_config)
        )
        attempt_ledger.mark_reverted_confirmed(
            change_id, verification_method=VERIFY_CERTIFICATE_REVOKED
        )

    print_info(
        f"Revoking certificate serial {mark_sensitive(serial, 'text')} on "
        f"{mark_sensitive(ca_name, 'hostname')}…"
    )
    result = run_revert_cascade(
        ledger=ledger,
        change_id=change_id,
        candidates=candidates,
        attempt=_attempt,
        on_exhausted=lambda _error: None,  # stays manual with its procedure
    )
    if result.confirmed:
        print_success(
            f"Certificate serial {mark_sensitive(serial, 'text')} revoked on the CA; it "
            "stops being accepted once the CA publishes its next revocation list."
        )
    return result.confirmed
