"""Rollback context manager and ledger helpers for ESC exploitation."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any, Callable, Optional

from adscan_internal import telemetry
from adscan_internal.rich_output import print_error
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_internal.services.environment_change_ledger import (
    CHANGE_CLASS_OPERATOR_CONFIRMED,
)
from adscan_core.rich_output import print_exception


class RollbackQueue:
    """Ordered queue of rollback callables — executes in reverse (LIFO)."""

    def __init__(self) -> None:
        self._fns: list[Callable] = []

    def add(self, fn: Callable) -> None:
        self._fns.append(fn)

    async def run_all(self) -> list[str]:
        errors: list[str] = []
        for fn in reversed(self._fns):
            try:
                result = fn()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                errors.append(str(exc))
        return errors


@asynccontextmanager
async def esc_rollback_scope():
    """Async context manager: runs registered rollbacks in LIFO order on exception."""
    rb = RollbackQueue()
    try:
        yield rb
    except Exception:
        errors = await rb.run_all()
        if errors:
            print_error(f"Rollback errors: {'; '.join(errors)}")
        raise


def register_ldap_change(
    shell: Any,
    *,
    kind: str,
    domain: str,
    target: str,
    detail: dict[str, Any],
    method: str,
) -> Optional[str]:
    """Register a destructive change to the environment ledger. Returns change_id."""
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is None:
        return None
    try:
        return ledger.register_change(
            kind=kind, domain=domain, target=target, detail=detail, method=method
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def format_certificate_not_after(cert: Any) -> Optional[str]:
    """Format an X.509 certificate's expiry the way every ADCS surface shows it.

    One formatting decision for the operator panel, the ledger record and the
    client's revocation instructions, so the same certificate never shows two
    different expiry strings.

    Args:
        cert: A ``cryptography`` X.509 certificate object.

    Returns:
        ``"YYYY-MM-DD HH:MM UTC"``, or ``None`` when the value is unreadable.
    """
    try:
        return cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:  # noqa: BLE001 — presentation must never break issuance
        return None


def register_issued_certificate(
    shell: Any,
    *,
    domain: str,
    technique: str,
    principal: Optional[str] = None,
    serial: Optional[str] = None,
    request_id: Optional[int | str] = None,
    template: Optional[str] = None,
    ca_name: Optional[str] = None,
    ca_host: Optional[str] = None,
    not_after: Optional[str] = None,
    pfx_path: Optional[str] = None,
) -> Optional[str]:
    """Disclose a certificate the CA issued during the scan as a MANUAL cleanup item.

    Every certificate ADscan obtains from a live CA — through enrollment or
    through a relayed authentication — is a durable credential that outlives the
    engagement: it sits in the CA database and authenticates its subject until it
    expires or is revoked. Revoking it needs certificate-manager rights on the CA
    that ADscan does not hold, so the record is written straight to the
    ``manual_required`` terminal state (``not_attempted``) rather than left
    pending. That matters operationally: the disclosure is complete on disk the
    moment the certificate exists, so a scan killed before it can finalize still
    leaves the client a full, actionable record.

    This is the single registration point for issued certificates. Native
    enrollment converges here through ``cert_request``; the relay ESCs converge
    here through ``esc_relay``.

    Args:
        shell: The session shell carrying ``environment_change_ledger``.
        domain: Domain the certificate was issued in.
        technique: Attack technique that produced it (e.g. ``"ADCSESC8 — ADCS
            Web Enrollment relay"``), recorded as the ledger ``method``.
        principal: Account the certificate authenticates as.
        serial: Hex serial number recorded by the CA.
        request_id: Request ID assigned by the CA.
        template: Certificate template used.
        ca_name: CA common name.
        ca_host: Host running the CA.
        not_after: Expiry, formatted for a human reader.
        pfx_path: Where the assessment stored the key material.

    Returns:
        The ledger ``change_id``, or ``None`` when no ledger is available.
    """
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is None:
        return None
    subject = principal or "an unnamed principal"
    serial_display = serial or "unknown serial"
    try:
        change_id = ledger.register_change(
            kind=_tax.KIND_ISSUED_CERTIFICATE,
            domain=domain,
            target=f"Certificate for {subject} — serial {serial_display}",
            detail={
                "principal": principal,
                "serial": serial,
                "request_id": request_id,
                "template": template,
                "ca_name": ca_name,
                "ca_host": ca_host,
                "not_after": not_after,
                "pfx_path": pfx_path,
            },
            method=technique,
            change_class=CHANGE_CLASS_OPERATOR_CONFIRMED,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None

    try:
        ledger.mark_manual_required(
            change_id,
            reason=_tax.MANUAL_REASON_NOT_ATTEMPTED,
            remediation_command=_tax.issued_certificate_remediation(
                serial=serial,
                request_id=request_id,
                ca_name=ca_name,
                ca_host=ca_host,
                template=template,
                principal=principal,
                not_after=not_after,
            ),
            remediation_object_dn=_issued_certificate_object_label(
                ca_name=ca_name, ca_host=ca_host, request_id=request_id
            ),
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return change_id


def _issued_certificate_object_label(
    *,
    ca_name: Optional[str],
    ca_host: Optional[str],
    request_id: Optional[int | str],
) -> str:
    """Build the object label an administrator uses to find the CA record."""
    parts: list[str] = []
    if ca_name and ca_host:
        parts.append(f"CA {ca_name} on {ca_host}")
    elif ca_name:
        parts.append(f"CA {ca_name}")
    elif ca_host:
        parts.append(f"CA on {ca_host}")
    if request_id is not None:
        parts.append(f"Request ID {request_id}")
    return " · ".join(parts)


def register_ca_private_key_exfiltrated(
    shell: Any,
    *,
    domain: str,
    technique: str,
    ca_subject: Optional[str] = None,
    ca_name: Optional[str] = None,
    ca_host: Optional[str] = None,
    is_root_ca: bool = False,
    key_size_bits: Optional[int] = None,
    pfx_path: Optional[str] = None,
) -> Optional[str]:
    """Disclose that the CA's private key was copied off the CA host (AD CS ESC5).

    A CA signing key outside the client's control is a permanent compromise of
    the whole PKI: it forges certificates for any identity with no CA-database
    record. There is no per-object revert — only CA key rotation removes the
    exposure — so, like an issued certificate, this is written straight to the
    ``manual_required`` terminal state, complete on disk the moment the key is
    exfiltrated.

    Args:
        shell: Session shell carrying ``environment_change_ledger``.
        domain: Domain hosting the CA.
        technique: Attack technique (ledger ``method``).
        ca_subject: Subject DN of the recovered CA certificate.
        ca_name: CA common name.
        ca_host: Host the key was copied from.
        is_root_ca: Whether the CA is self-signed (a root).
        key_size_bits: RSA key size of the recovered key.
        pfx_path: Where the assessment stored the recovered key material.

    Returns:
        The ledger ``change_id``, or ``None`` when no ledger is available.
    """
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is None:
        return None
    identity = ca_subject or ca_name or (f"the CA on {ca_host}" if ca_host else "the CA")
    try:
        change_id = ledger.register_change(
            kind=_tax.KIND_CA_PRIVATE_KEY_EXFILTRATED,
            domain=domain,
            target=f"CA private key of {identity} copied off {ca_host or 'the CA host'}",
            detail={
                "ca_subject": ca_subject,
                "ca_name": ca_name,
                "ca_host": ca_host,
                "is_root_ca": is_root_ca,
                "key_size_bits": key_size_bits,
                "pfx_path": pfx_path,
            },
            method=technique,
            change_class=CHANGE_CLASS_OPERATOR_CONFIRMED,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    try:
        ledger.mark_manual_required(
            change_id,
            reason=_tax.MANUAL_REASON_NOT_ATTEMPTED,
            remediation_command=_tax.ca_private_key_remediation(
                ca_subject=ca_subject, ca_name=ca_name, ca_host=ca_host
            ),
            remediation_object_dn=identity,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return change_id


def register_forged_certificate(
    shell: Any,
    *,
    domain: str,
    technique: str,
    principal: Optional[str] = None,
    target_sid: Optional[str] = None,
    serial: Optional[str] = None,
    not_after: Optional[str] = None,
    ca_name: Optional[str] = None,
    ca_host: Optional[str] = None,
    subject: Optional[str] = None,
    pfx_path: Optional[str] = None,
) -> Optional[str]:
    """Disclose a certificate forged offline with the stolen CA key (AD CS ESC5).

    Distinct from ``register_issued_certificate``: a forged certificate carries
    NO request id, is ABSENT from the CA database, and the normal revocation
    procedure cannot reach it. Only retiring the signing CA key invalidates it,
    so the record is always ``manual_required`` and says so plainly.

    Args:
        shell: Session shell carrying ``environment_change_ledger``.
        domain: Domain the forged certificate authenticates into.
        technique: Attack technique (ledger ``method``).
        principal: Account (UPN/subject) the certificate impersonates.
        target_sid: SID embedded for strong certificate mapping.
        serial: Assessment-chosen serial number.
        not_after: Expiry, formatted for a human reader.
        ca_name: CA whose key signed the forgery.
        ca_host: Host the signing CA runs on.
        subject: Subject DN of the forged certificate.
        pfx_path: Where the assessment stored the forged key material.

    Returns:
        The ledger ``change_id``, or ``None`` when no ledger is available.
    """
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is None:
        return None
    subject_display = principal or subject or "an unnamed principal"
    serial_display = serial or "unknown serial"
    try:
        change_id = ledger.register_change(
            kind=_tax.KIND_FORGED_CERTIFICATE,
            domain=domain,
            target=f"Forged certificate for {subject_display} — serial {serial_display}",
            detail={
                "principal": principal,
                "subject": subject,
                "target_sid": target_sid,
                "serial": serial,
                "not_after": not_after,
                "ca_name": ca_name,
                "ca_host": ca_host,
                "pfx_path": pfx_path,
                "in_ca_database": False,
                "request_id": None,
            },
            method=technique,
            change_class=CHANGE_CLASS_OPERATOR_CONFIRMED,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    object_dn = (
        f"CA {ca_name} — no request id (certificate absent from the CA database)"
        if ca_name
        else "No request id (certificate absent from the CA database)"
    )
    try:
        ledger.mark_manual_required(
            change_id,
            reason=_tax.MANUAL_REASON_NOT_ATTEMPTED,
            remediation_command=_tax.forged_certificate_remediation(
                principal=principal or subject,
                serial=serial,
                not_after=not_after,
            ),
            remediation_object_dn=object_dn,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return change_id


def register_ca_backup_service(
    shell: Any,
    *,
    domain: str,
    technique: str,
    service_name: str,
    ca_host: Optional[str] = None,
) -> Optional[str]:
    """Write-ahead disclosure of the transient CA-backup service.

    Registered BEFORE the service is created, so a session killed mid-creation
    still leaves a record (``finalize()`` then force-transitions it to
    ``manual_required(session_died)`` carrying the concrete remediation stamped
    here). The record stays ``pending`` until :func:`resolve_ca_backup_service`
    marks it reverted (verified delete) or manual_required (survived).

    Returns:
        The ledger ``change_id``, or ``None`` when no ledger is available.
    """
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is None:
        return None
    try:
        change_id = ledger.register_change(
            kind=_tax.KIND_CA_BACKUP_SERVICE,
            domain=domain,
            target=f"Temporary service {service_name} on {ca_host or 'the CA host'}",
            detail={"service_name": service_name, "ca_host": ca_host},
            method=technique,
            change_class=CHANGE_CLASS_OPERATOR_CONFIRMED,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    try:
        ledger.set_revert_metadata(
            change_id,
            remediation_command=_tax.ca_backup_service_remediation(
                service_name=service_name, ca_host=ca_host
            ),
            remediation_object_dn=f"Service {service_name} on {ca_host or 'the CA host'}",
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return change_id


def register_ca_backup_temp_pfx(
    shell: Any,
    *,
    domain: str,
    technique: str,
    unc_path: str,
    ca_host: Optional[str] = None,
) -> Optional[str]:
    """Write-ahead disclosure of the temporary CA key file on the CA host.

    Same lifecycle as the transient service: the temp PFX holds the CA private
    key under a fixed, publicly-known password, so a survived file is a CA-key
    exposure. Registered before the backup runs; resolved by
    :func:`resolve_ca_backup_temp_pfx`.

    Returns:
        The ledger ``change_id``, or ``None`` when no ledger is available.
    """
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is None:
        return None
    try:
        change_id = ledger.register_change(
            kind=_tax.KIND_CA_BACKUP_TEMP_PFX,
            domain=domain,
            target=f"Temporary CA key file {unc_path}",
            detail={
                "unc_path": unc_path,
                "ca_host": ca_host,
                "known_password": True,
            },
            method=technique,
            change_class=CHANGE_CLASS_OPERATOR_CONFIRMED,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    try:
        ledger.set_revert_metadata(
            change_id,
            remediation_command=_tax.ca_backup_temp_pfx_remediation(unc_path=unc_path),
            remediation_object_dn=unc_path,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return change_id


def resolve_ca_backup_service(
    shell: Any,
    change_id: Optional[str],
    *,
    created: bool,
    verified_gone: Optional[bool],
    service_name: str,
    ca_host: Optional[str] = None,
) -> None:
    """Resolve a write-ahead CA-backup service record at cleanup.

    A service is genuinely reversible, so the record is marked reverted only on
    a VERIFIED removal (a fresh open of the service returns not-found), never on
    "we called delete and swallowed the exception".

    - ``created=False`` (the service was never created): the record describes a
      change that never happened → discarded.
    - ``verified_gone is True``: the service was removed and re-verified absent →
      reverted-confirmed.
    - ``verified_gone is False`` (it still opens): ``manual_required``
      (revert failed) with the exact object and the client's command.
    - ``verified_gone is None`` (removal could not be verified — connection
      lost): ``manual_required`` (session ended) — never assume it is gone.
    """
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is None or not change_id:
        return
    try:
        if not created:
            ledger.discard_change(change_id)
            return
        if verified_gone is True:
            ledger.mark_reverted_confirmed(
                change_id, verification_method="ca_backup_service_reopen_absent"
            )
            return
        reason = (
            _tax.MANUAL_REASON_REVERT_FAILED
            if verified_gone is False
            else _tax.MANUAL_REASON_SESSION_DIED
        )
        error = (
            "The temporary service is still present on the CA host."
            if verified_gone is False
            else "ADscan could not confirm the temporary service was removed."
        )
        ledger.mark_manual_required(
            change_id,
            reason=reason,
            remediation_command=_tax.ca_backup_service_remediation(
                service_name=service_name, ca_host=ca_host
            ),
            remediation_object_dn=f"Service {service_name} on {ca_host or 'the CA host'}",
            error=error,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def resolve_ca_backup_temp_pfx(
    shell: Any,
    change_id: Optional[str],
    *,
    observed: bool,
    gone: Optional[bool],
    unc_path: str,
) -> None:
    """Resolve a write-ahead CA-backup temp-PFX record at cleanup.

    - ``gone is True`` and the file was observed: reverted-confirmed.
    - ``gone is True`` and it was never observed: the file was never created →
      discarded.
    - ``gone is False`` (still present): ``manual_required`` (revert failed).
    - ``gone is None`` (could not verify — connection lost): ``manual_required``
      (session ended) — never assume a CA key file is gone.
    """
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is None or not change_id:
        return
    try:
        if gone is True:
            if observed:
                ledger.mark_reverted_confirmed(
                    change_id, verification_method="ca_backup_temp_pfx_absence_reread"
                )
            else:
                ledger.discard_change(change_id)
            return
        reason = (
            _tax.MANUAL_REASON_REVERT_FAILED
            if gone is False
            else _tax.MANUAL_REASON_SESSION_DIED
        )
        error = (
            "The temporary CA key file is still present on the CA host."
            if gone is False
            else "ADscan could not confirm the temporary CA key file was removed."
        )
        ledger.mark_manual_required(
            change_id,
            reason=reason,
            remediation_command=_tax.ca_backup_temp_pfx_remediation(unc_path=unc_path),
            remediation_object_dn=unc_path,
            error=error,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def mark_reverted(shell: Any, change_id: Optional[str]) -> None:
    if not change_id:
        return
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger:
        try:
            ledger.mark_reverted(change_id)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


def mark_revert_failed(
    shell: Any, change_id: Optional[str], *, error: str, instructions: str
) -> None:
    if not change_id:
        return
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger:
        try:
            ledger.mark_failed(change_id, error=error, manual_cleanup_instructions=instructions)
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
