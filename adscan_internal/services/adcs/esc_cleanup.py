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
