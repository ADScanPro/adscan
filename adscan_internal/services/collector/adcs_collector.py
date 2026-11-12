"""Native ADCS object collector.

Enumerates AD Certificate Services objects under
``CN=Public Key Services,CN=Services,{config_dn}`` and converts them into
``CollectorNode`` / ``CollectorEdge`` instances that feed the same
persistence pipeline as the main LDAP collector.

The five enumerated kinds:

- ``CertTemplate``     — pKICertificateTemplate objects.
- ``EnterpriseCA``     — pKIEnrollmentService objects.
- ``RootCA``           — certificationAuthority under CN=Certification Authorities.
- ``AIACA``            — certificationAuthority under CN=AIA.
- ``NTAuthStore``      — single CN=NTAuthCertificates object.

ACL edges are emitted by the existing :class:`ACLParser`, so ESC4 / ESC5
coverage falls out of Phase 1 automatically.

ADCS objects are not security principals and have no SID. We mint a stable
synthetic object id ``{DOMAIN_UPPER}-{GUID}`` that cannot collide with the
``S-1-*`` SID namespace.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any, NamedTuple

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_info_verbose,
    print_warning_debug,
)
from adscan_internal.services.adcs.ca_registry_checks import (
    CHECK_CERTIGHOST,
    CHECK_ESC6,
    CHECK_ESC11,
    REGISTRY_FINDING_KEYS,
    assess_registry_checks,
    observe_registry_check,
)
from adscan_internal.services.adcs.esc12_detection import (
    REASON_CA_HOST_UNKNOWN,
    REASON_EXCLUDED_BY_POLICY,
    REASON_NO_LOCAL_ADMIN,
    REASON_READ_FAILED,
)
from adscan_internal.services.adcs_ca_registry_service import (
    ADCSCARegistryProbe,
    CARegistryProbeResult,
)
from adscan_internal.services.adcs_web_enrollment_probe import (
    ADCSWebEnrollmentProbe,
    WebEnrollmentProbeResult,
    WebProbeCredential,
)
from adscan_internal.services.collector.acl_parser import ACLParser
from adscan_internal.services.collector.adcs_detectors import (
    detect_all_for_ca as _detect_adcs_ca_escalations,
    detect_all_for_template as _detect_adcs_escalations,
)
from adscan_internal.services.collector.collection_integrity import (
    note_stage_exception,
)
from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    CollectorNode,
    NodeKind,
)
from adscan_internal.services.ldap_transport_service import (
    SD_FLAGS_DACL_CONTROL,
    ADscanLDAPConnection,
)
from adscan_internal.services.smb_transport import SMBConfig
from adscan_core.rich_output import print_exception

# ---------------------------------------------------------------------------
# CA identity handling
# ---------------------------------------------------------------------------

# Win32 ACCESS_DENIED, as surfaced by the CSRA/ICertAdminD2 fault. Reading a CA
# security descriptor requires CA-admin rights, so this is the expected answer
# for any ordinary domain account — not a failure.
_CA_ACCESS_DENIED_MARKERS = ("0x80070005", "access_denied", "access denied")

# The HRESULT / NT-status codes that mean "the account lacks the CA-admin rights
# needed to read the security descriptor" — the EXPECTED low-priv audit outcome.
# ``CertAdminSecurityError`` now carries the fault code on ``error_code`` (vendor
# ``certadmin.py``), so we classify by CODE first: the inner DCE-RPC error can
# stringify EMPTY, which left the substring test blind and escalated a benign
# denial to a red operator error + a PostHog exception.
_CA_ACCESS_DENIED_CODES = (
    0x80070005,  # E_ACCESSDENIED / ERROR_ACCESS_DENIED
    0x00000005,  # ERROR_ACCESS_DENIED (bare Win32 form)
)


def _is_expected_ca_security_denial(exc: BaseException) -> bool:
    """Return whether a GetCASecurity error is the normal not-CA-admin denial.

    Classifies by the fault CODE the exception carries first (robust even when
    the underlying DCE-RPC error stringifies to an empty message), then falls
    back to a substring match on the message for any error object that exposes no
    code.
    """
    code = getattr(exc, "error_code", None)
    if isinstance(code, int) and (code & 0xFFFFFFFF) in _CA_ACCESS_DENIED_CODES:
        return True
    return any(marker in str(exc).lower() for marker in _CA_ACCESS_DENIED_MARKERS)


# A CA whose FQDN cannot be resolved from the current vantage (the DC-DNS gap on
# a member CA) surfaces as ``socket.gaierror`` (``[Errno -2] Name or service not
# known``), usually wrapped in an ``SMBConnectionError`` from the DCOM connect.
# This is a DATA GAP (the CA-security read is skipped), not a failure — mirror
# the ESC8 ``could_not_verify`` handling: never a red operator error.
_CA_HOST_UNRESOLVABLE_MARKERS = (
    "name or service not known",
    "[errno -2]",
    "temporary failure in name resolution",
    "[errno -3]",
    "nodename nor servname provided",
    "[errno -5]",
    "getaddrinfo",
)


def _is_ca_host_unresolvable(exc: BaseException) -> bool:
    """Return whether a GetCASecurity failure is an unresolvable-CA-host data gap."""
    import socket

    cause: BaseException | None = exc
    seen: set[int] = set()
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, socket.gaierror):
            return True
        cause = cause.__cause__ or cause.__context__
    lowered = str(exc).lower()
    return any(marker in lowered for marker in _CA_HOST_UNRESOLVABLE_MARKERS)


# LDAP ``noSuchObject`` (result code 32) / its Windows twin
# ``ERROR_DS_OBJ_NOT_FOUND`` (0x80072030). A PKI container search that hits this
# means the domain simply has NO Public Key Services — the EXPECTED answer for
# essos, north, and most client domains that are not the PKI forest root — not
# an error. Quieting it stops ~6 spurious red ``✗ Error: noSuchObject`` lines and
# ~6 PostHog error-tracking events per ADCS-less domain.
_ADCS_ABSENT_MARKERS = (
    "nosuchobject",
    "error_ds_obj_not_found",
    "0x80072030",
)


def _is_adcs_container_absent(exc: BaseException) -> bool:
    """Return whether an ADCS container search failed because there is no PKI.

    Prefers badldap's structured ``resultname`` (``noSuchObject``) when the
    exception carries it, and falls back to a substring match on the message so
    a wrapped / re-raised error is still recognised. Any OTHER cause (a real
    bind error, a timeout, an ``SMBConnectionError``, a permission denial) is
    NOT matched and keeps the full error-handling path.
    """
    resultname = str(getattr(exc, "resultname", "") or "").strip().lower()
    if resultname == "nosuchobject":
        return True
    lowered = str(exc).lower()
    return any(marker in lowered for marker in _ADCS_ABSENT_MARKERS)


def _register_ca_identity(ca_name: str, ca_host: str) -> None:
    """Register a CA's names with the telemetry sanitizer as soon as they resolve.

    A CA common name follows ``<ORG>-<DCHOST>-CA``, so it publishes the
    customer's organisation name and a DC hostname. It is not a computer account
    and never appears in the workspace's ``enabled_computers.txt``, so the
    hostname net had nothing to match — and the name reached the recording
    verbatim inside vendor exception text such as
    ``GetCASecurity failed for <CA>: ...``.

    Registering here scrubs every occurrence in the exported buffer, including
    ones recorded before this point and ones inside strings this module never
    formats itself.
    """
    try:
        telemetry.add_known_hostname(ca_name, ca_host)
    except Exception:  # pragma: no cover - best effort, never break collection
        pass


_UNSET: Any = object()


def _stamp_role_separation_reading(
    ca: CollectorNode,
    *,
    role_separation: Any = _UNSET,
    security_edges: list[CollectorEdge] | None = None,
) -> None:
    """Record on the CA node what was read about its role separation.

    The segregation-of-duties evidence
    (:mod:`adscan_core.reporting.ca_role_separation`) is decided from this
    record, so it stores only what the CA ANSWERED: the flag when the CA gave a
    definitive 0 or 1, and the CA Administrator / Certificate Manager trustees
    only when the security descriptor itself was read. A read that failed leaves
    its field absent, which the evidence reads as "not read", never as "off" or
    as "nobody holds the role".
    """
    from adscan_core.reporting.ca_role_separation import (  # noqa: PLC0415
        READING_ADMINS,
        READING_ATTEMPTED,
        READING_FLAG,
        READING_OFFICERS,
        READING_PROPERTY,
        READING_SECURITY_READ,
    )
    from adscan_core.scan_policy.revert_rights import (  # noqa: PLC0415
        role_separation_state,
    )

    reading = ca.properties.get(READING_PROPERTY)
    if not isinstance(reading, dict):
        reading = {}
        ca.properties[READING_PROPERTY] = reading
    reading[READING_ATTEMPTED] = True
    if role_separation is not _UNSET:
        state = role_separation_state(role_separation)
        if state is not None:
            reading[READING_FLAG] = 1 if state else 0
    if security_edges is not None:
        admins = sorted(
            {e.source_object_id for e in security_edges if e.relation == "ManageCA"}
        )
        officers = sorted(
            {
                e.source_object_id
                for e in security_edges
                if e.relation == "ManageCertificates"
            }
        )
        reading[READING_SECURITY_READ] = True
        reading[READING_ADMINS] = admins
        reading[READING_OFFICERS] = officers


# ---------------------------------------------------------------------------
# Attribute lists per kind
# ---------------------------------------------------------------------------

_COMMON_ATTRS = [
    "cn",
    "name",
    "displayName",
    "objectGUID",
    "distinguishedName",
    "objectClass",
    "nTSecurityDescriptor",
    "whenCreated",
    "whenChanged",
]

_CERT_TEMPLATE_ATTRS = _COMMON_ATTRS + [
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature",
    "msPKI-Certificate-Application-Policy",
    "msPKI-Certificate-Policy",
    "msPKI-RA-Application-Policies",
    "pKIExtendedKeyUsage",
    "pKIExpirationPeriod",
    "pKIOverlapPeriod",
    "msPKI-Template-Schema-Version",
    "msPKI-Template-Minor-Revision",
    "msPKI-Private-Key-Flag",
    "msPKI-Minimal-Key-Size",
    "msPKI-Cert-Template-OID",
    "flags",
    "revision",
]

_ENTERPRISE_CA_ATTRS = _COMMON_ATTRS + [
    "dNSHostName",
    "certificateTemplates",
    "cACertificate",
    "cACertificateDN",
    "flags",
    "msPKI-Enrollment-Servers",
]

_ROOT_CA_ATTRS = _COMMON_ATTRS + [
    "cACertificate",
    "certificateRevocationList",
    "authorityRevocationList",
]

_NTAUTH_ATTRS = _COMMON_ATTRS + ["cACertificate"]

_AIA_ATTRS = _COMMON_ATTRS + ["cACertificate"]

# msPKI-Enterprise-Oid objects under CN=OID,CN=Public Key Services,CN=Services,
# Configuration. ``msPKI-Cert-Template-OID`` is the issuance policy OID;
# ``msDS-OIDToGroupLink`` is the DN of the linked group when the policy is
# group-mapped (the ESC13 abuse precondition).
_OID_LINK_ATTRS = _COMMON_ATTRS + [
    "msPKI-Cert-Template-OID",
    "msDS-OIDToGroupLink",
    "displayName",
]

# Properties stored under ``CollectorNode.properties`` for downstream
# Phase 2 detector consumption.
_TEMPLATE_PROPERTY_KEYS = {
    "mspki-certificate-name-flag": "mspki_certificate_name_flag",
    "mspki-enrollment-flag": "mspki_enrollment_flag",
    "mspki-ra-signature": "mspki_ra_signature",
    "mspki-certificate-application-policy": "mspki_certificate_application_policy",
    "mspki-certificate-policy": "mspki_certificate_policy",
    "mspki-ra-application-policies": "mspki_ra_application_policies",
    "pkiextendedkeyusage": "pki_extended_key_usage",
    "pkiexpirationperiod": "pki_expiration_period",
    "mspki-template-schema-version": "mspki_template_schema_version",
    "mspki-template-minor-revision": "mspki_template_minor_revision",
    "mspki-private-key-flag": "mspki_private_key_flag",
    "mspki-minimal-key-size": "mspki_minimal_key_size",
    "mspki-cert-template-oid": "mspki_cert_template_oid",
    "flags": "flags",
    "revision": "revision",
}

_ENTERPRISE_CA_PROPERTY_KEYS = {
    "dnshostname": "dns_hostname",
    "certificatetemplates": "certificate_templates",
    "cacertificatedn": "ca_certificate_dn",
    "flags": "flags",
    "mspki-enrollment-servers": "mspki_enrollment_servers",
}


#: Why the registry probe was not even attempted when the collector was built
#: without a credential builder (lab scripts, metadata-only detection).
REASON_REGISTRY_PROBE_NOT_CONFIGURED = "registry_probe_not_configured"

# Type alias for dependency-injected probe credential builder. Receives the
# CA host (DNS or IP) and returns an SMBConfig already authenticated with
# the appropriate credentials, or ``None`` if no creds are available for
# that host (cross-domain CA without trust path, etc.).
SMBConfigBuilder = Callable[[str], Awaitable[SMBConfig | None]]

# Optional DC binding-state probe callback. The orchestrator owns the LDAP
# credential context and the DC list, so the cleanest decoupling is to let
# it produce the per-domain ``(cert_mapping_methods, strong_cert_binding_enforced)``
# tuple. Returns ``None`` if no DC could be probed.
DCBindingProbe = Callable[[str], Awaitable[tuple[int, bool] | None]]


# ---------------------------------------------------------------------------
# Pure helpers (re-implemented locally to avoid coupling to ldap_collector
# private helpers; same semantics).
# ---------------------------------------------------------------------------


def _collect_computer_hostnames(result: CollectionResult) -> set[str]:
    """Return every hostname a collected Computer object owns (lower-cased).

    The set carries both the full ``dNSHostName`` FQDN and its short label, plus
    each computer's ``sAMAccountName`` short name (``DC01$`` → ``dc01``), so a CA
    host can be matched against it whether the CA advertises an FQDN or a short
    name. Used to answer "does any computer own this CA host?" — the second,
    conservative condition of the orphaned-CA hygiene test.
    """
    names: set[str] = set()
    for node in result.nodes.values():
        if str(node.kind) != "Computer":
            continue
        dns_name = str(node.properties.get("dnshostname") or "").strip().lower().rstrip(".")
        if dns_name:
            names.add(dns_name)
            names.add(dns_name.split(".", 1)[0])
        sam = str(node.samaccountname or "").strip().lower().split("@", 1)[0].rstrip("$")
        if sam:
            names.add(sam)
    return names


def _ca_host_is_orphaned(
    *,
    ca_host: str,
    name_unresolvable: bool,
    computer_hostnames: "set[str] | frozenset[str]",
) -> bool:
    """Return whether an enterprise CA is ORPHANED (the observed-certain hygiene case).

    A CA is orphaned — a decommissioned CA object still registered in Active
    Directory — when BOTH conditions hold:

    * ``name_unresolvable`` — the CA host name did not resolve to any usable
      address after the full resolver ladder (the web probe's ``could_not_verify``
      / NXDOMAIN signal). A host that RESOLVES but is merely unreachable
      (timeout / firewall) is NOT unresolvable and is a DATA GAP, never orphaned.
    * no collected Computer object owns that hostname — a live CA runs on a
      domain-joined member server that has a Computer object; its absence is what
      distinguishes a decommissioned host from one that is only unreachable.

    Both are required (Exposure-Validation: cache observations, never absences).
    An IP-only CA host is never orphaned — without an FQDN there is no NXDOMAIN to
    observe. Returns ``False`` on any uncertainty, so the hygiene finding is only
    ever emitted on observed-certain decommissioning.
    """
    from adscan_internal.services._kerberos_spn import is_ip_address

    host = str(ca_host or "").strip().rstrip(".")
    if not host or is_ip_address(host):
        return False
    if not name_unresolvable:
        return False
    host_lower = host.lower()
    if host_lower in computer_hostnames:
        return False
    if host_lower.split(".", 1)[0] in computer_hostnames:
        return False
    return True


def _attrs(entry: Any) -> dict[str, list[Any]]:
    """Return a case-preserving dict of attribute name → list of values.

    Mirrors :func:`adscan_internal.services.collector.ldap_collector._attrs`
    but kept local so this module can stand alone.
    """
    raw = getattr(entry, "entry_raw_attributes", {}) or {}
    decoded = getattr(entry, "entry_attributes_as_dict", {}) or {}
    keys = set(raw) | set(decoded)
    result: dict[str, list[Any]] = {}
    binary_keys = {"objectsid", "objectguid", "ntsecuritydescriptor", "cacertificate"}
    for key in keys:
        key_text = str(key)
        if key_text.casefold() in binary_keys:
            values = raw.get(key)
        else:
            values = decoded.get(key)
        if values is None:
            values = raw.get(key, [])
        if not isinstance(values, (list, tuple, set)):
            values = [values]
        result[key_text] = [v for v in values if v is not None]
    return result


def _values(attrs: dict[str, list[Any]], name: str) -> list[Any]:
    for key, values in attrs.items():
        if key.casefold() == name.casefold():
            return [v for v in values if v is not None]
    return []


def _first(attrs: dict[str, list[Any]], name: str) -> Any:
    vals = _values(attrs, name)
    return vals[0] if vals else None


def _first_str(attrs: dict[str, list[Any]], name: str) -> str:
    val = _first(attrs, name)
    return str(val).strip() if val is not None else ""


def _str_values(attrs: dict[str, list[Any]], name: str) -> list[str]:
    return [str(v).strip() for v in _values(attrs, name) if str(v).strip()]


def _decode_guid(raw: Any) -> str:
    if isinstance(raw, bytes):
        try:
            return str(uuid.UUID(bytes_le=raw))
        except (TypeError, ValueError):
            return raw.hex()
    return str(raw).strip() if raw else ""


def _raw_bytes(entry: Any, attr: str) -> bytes | None:
    raw = getattr(entry, "entry_raw_attributes", {}) or {}
    for key, values in raw.items():
        if str(key).casefold() == attr.casefold():
            return values[0] if values else None
    return None


def _cert_thumbprints(der_values: Iterable[Any] | None) -> set[str]:
    """Return the SHA-1 thumbprint (hex, lower-case) of each DER certificate value.

    A certificate thumbprint is defined as the SHA-1 hash of the whole DER blob,
    which is exactly the value ``certutil`` displays, so it round-trips into the
    client remediation command without an X.509 parser. ``usedforsecurity=False``
    documents that this is an identity fingerprint, not a cryptographic integrity
    check. Empty / missing / non-bytes values are tolerated and skipped so a
    malformed ``cACertificate`` never breaks collection.
    """
    thumbs: set[str] = set()
    for value in der_values or ():
        if not isinstance(value, (bytes, bytearray)):
            continue
        blob = bytes(value)
        if not blob:
            continue
        thumbs.add(hashlib.sha1(blob, usedforsecurity=False).hexdigest())
    return thumbs


def _synthetic_object_id(domain: str, guid: str) -> str:
    """Stable synthetic object id for a non-SID ADCS object.

    Format: ``{DOMAIN_UPPER}-{GUID_UPPER}``. Cannot collide with the
    ``S-1-*`` SID namespace.
    """
    if not guid:
        return ""
    return f"{domain.upper()}-{guid.upper()}"


# ---------------------------------------------------------------------------
# Entry → CollectorNode (pure, unit-testable)
# ---------------------------------------------------------------------------


def _build_node_from_ldap_entry(
    entry: Any, kind: NodeKind, domain: str
) -> CollectorNode | None:
    """Pure builder: convert one parsed LDAP entry into a ``CollectorNode``.

    Returns ``None`` when the entry has no objectGUID (we cannot mint a
    stable id without it).
    """
    attrs = _attrs(entry)
    raw_guid = _first(attrs, "objectGUID")
    guid = _decode_guid(raw_guid).upper() if raw_guid else ""
    if not guid:
        return None

    object_id = _synthetic_object_id(domain, guid)
    dn = _first_str(attrs, "distinguishedName")
    cn = _first_str(attrs, "cn")
    display = _first_str(attrs, "displayName")
    name_attr = _first_str(attrs, "name")
    label = (display or name_attr or cn or guid).strip()
    name = f"{label.upper()}@{domain.upper()}"

    properties: dict[str, Any] = {
        "objectguid": guid,
        "adcs_kind": kind,
    }

    if kind == "CertTemplate":
        if cn:
            properties["cn"] = cn  # actual enrollment name (e.g. "RetroClients"), distinct from displayName
        for ldap_key, prop_key in _TEMPLATE_PROPERTY_KEYS.items():
            vals = _values(attrs, ldap_key)
            if not vals:
                continue
            if prop_key in {
                "pki_extended_key_usage",
                "mspki_certificate_application_policy",
                "mspki_certificate_policy",
                "mspki_ra_application_policies",
            }:
                properties[prop_key] = [str(v).strip() for v in vals]
            else:
                first = vals[0]
                try:
                    properties[prop_key] = int(first)
                except (TypeError, ValueError):
                    properties[prop_key] = str(first).strip()
    elif kind == "EnterpriseCA":
        for ldap_key, prop_key in _ENTERPRISE_CA_PROPERTY_KEYS.items():
            vals = _values(attrs, ldap_key)
            if not vals:
                continue
            if prop_key in {"certificate_templates", "mspki_enrollment_servers"}:
                properties[prop_key] = [str(v).strip() for v in vals]
            else:
                first = vals[0]
                try:
                    properties[prop_key] = int(first)
                except (TypeError, ValueError):
                    properties[prop_key] = str(first).strip()
        # SHA-1 thumbprints of the CA's own certificate(s), stamped so the
        # NTAuth trust-anchor correlation (orphaned CA whose cert is still in
        # CN=NTAuthCertificates) can intersect them against the NTAuth store.
        ca_thumbs = _cert_thumbprints(_values(attrs, "cACertificate"))
        if ca_thumbs:
            properties["ca_certificate_thumbprints"] = sorted(ca_thumbs)
    elif kind == "NTAuthStore":
        # The NTAuthCertificates store holds every CA certificate AD trusts for
        # client authentication (PKINIT). Stamp its thumbprint set so a
        # decommissioned CA still present here is detectable by correlation.
        ntauth_thumbs = _cert_thumbprints(_values(attrs, "cACertificate"))
        if ntauth_thumbs:
            properties["ca_certificate_thumbprints"] = sorted(ntauth_thumbs)

    return CollectorNode(
        object_id=object_id,
        kind=kind,
        name=name,
        domain=domain,
        distinguished_name=dn,
        properties=properties,
    )


# ---------------------------------------------------------------------------
# Collector class
# ---------------------------------------------------------------------------


class _OidToGroupLinks(NamedTuple):
    """Outcome of resolving issuance-policy OID → linked group DN for ESC13.

    ``resolved`` distinguishes the two ways ``links`` can be empty, which the
    ESC13 detector MUST tell apart:

    * ``resolved=True`` + empty ``links`` — the LDAP query succeeded and the
      domain simply has no ``msDS-OIDToGroupLink`` on any OID. ESC13 does not
      exist here (existence-condition absent); the detector emits nothing.
    * ``resolved=False`` — the query failed (data gap). We do not know whether
      ESC13 exists, so the detector must not emit a CRITICAL false positive.
    """

    links: dict[str, str]
    resolved: bool


class ADCSCollector:
    """Enumerate ADCS objects from the Configuration naming context."""

    def __init__(
        self,
        connection: ADscanLDAPConnection,
        domain: str,
        acl_parser: ACLParser | None = None,
        smb_config_builder: SMBConfigBuilder | None = None,
        dc_binding_probe: DCBindingProbe | None = None,
        shell: Any = None,
        directory_roles: Mapping[str, Any] | None = None,
        defer_unresolved_registry: bool = False,
    ) -> None:
        self._connection = connection
        self._domain = domain
        self._acl_parser = acl_parser or ACLParser(domain=domain, connection=connection)
        # When None all CA-host probes are skipped — detector defaults
        # preserve the no-false-positive contract.
        self._smb_config_builder = smb_config_builder
        self._dc_binding_probe = dc_binding_probe
        # The pentest shell, when available (the CLI/web scan path). Carries
        # ``domains_data`` + the workspace inventory the reachable-IP SSOT reads
        # to recover a CA host's IP when the DC's DNS cannot resolve its FQDN.
        # ``None`` (lab scripts / direct-unit-test construction) keeps CA-host
        # connections targeting the FQDN — byte-for-byte the pre-fix behaviour.
        self._shell = shell
        # Administrative roles derived from the directory membership the caller
        # already collected (``privilege_role.directory_admin_roles``). The
        # attack graph does not exist yet while the collector runs, so this is
        # the evidence that lets a scan starting as Domain Admin qualify its own
        # credential for the CA-host reads (ESC12 here; the registry probe gets
        # it through the injected ``smb_config_builder``).
        self._directory_roles = dict(directory_roles or {})
        # When True, a CA whose registry probe found no CA-host administrator
        # is NOT recorded as not assessed here: it is handed to the caller on
        # ``CollectionResult.adcs_registry_pending`` and the collection
        # orchestrator re-runs it once the persisted graph resolves roles
        # (``adcs.ca_registry_rerun``), recording the outcome exactly once.
        self._defer_unresolved_registry = bool(defer_unresolved_registry)
        # Set once a PKI-container search returns ``noSuchObject`` so the whole
        # domain reports "no ADCS" as a single quiet line, not per-container.
        self._adcs_absent = False
        # Object ids of PKI objects returned WITHOUT a security descriptor (the
        # account cannot read it). An ACL-derived ESC verdict on such an object
        # is unknown, never clear: an unread ACL must not read as "nobody can
        # enroll". The recheck observers consult it; the scan path ignores it.
        self.unread_security_descriptors: set[str] = set()

    def _note_adcs_absent(self) -> None:
        """Record that a PKI container was absent (no ADCS in this domain)."""
        self._adcs_absent = True

    @property
    def adcs_absent(self) -> bool:
        """Whether a PKI container answered ``noSuchObject`` (no AD CS here)."""
        return self._adcs_absent

    def collect(self) -> CollectionResult:
        """Run all five enumerations and return a populated ``CollectionResult``."""
        result, oid_links = self.collect_directory()
        if oid_links is None:
            return result

        self._detect_escalations(result, oid_links=oid_links)

        # One quiet line for a domain with no PKI, instead of ~6 red errors.
        if self._adcs_absent and not result.nodes:
            print_info_verbose(
                "No Active Directory Certificate Services in "
                f"{mark_sensitive(self._domain, 'domain')} — skipping ADCS checks."
            )

        print_info_debug(
            "[adcs-collector] done "
            f"domain={mark_sensitive(self._domain, 'domain')} "
            f"nodes={len(result.nodes)} edges={len(result.edges)}"
        )
        return result

    def collect_directory(self) -> tuple[CollectionResult, "_OidToGroupLinks | None"]:
        """Read the PKI objects, their ACL edges and the ESC13 OID links (LDAP only).

        The directory half of :meth:`collect`: no detection, no CA-host contact.
        ``oid_links`` is ``None`` when the connection has no configuration
        naming context (nothing was read). The recheck observers call it so a
        re-check reads the CURRENT state with exactly the scan's own reads.
        """
        result = CollectionResult(domain=self._domain)

        config_dn = self._connection.config_dn
        if not config_dn:
            print_warning_debug(
                "[adcs-collector] connection has no config_dn; skipping ADCS"
            )
            return result, None

        pks_base = f"CN=Public Key Services,CN=Services,{config_dn}"
        print_info_verbose(
            f"Collecting ADCS for {mark_sensitive(self._domain, 'domain')}..."
        )

        categories: list[tuple[str, str, str, NodeKind, list[str], str]] = [
            (
                "templates",
                f"CN=Certificate Templates,{pks_base}",
                "(objectClass=pKICertificateTemplate)",
                "CertTemplate",
                _CERT_TEMPLATE_ATTRS,
                "SUBTREE",
            ),
            (
                "enterprise_cas",
                f"CN=Enrollment Services,{pks_base}",
                "(objectClass=pKIEnrollmentService)",
                "EnterpriseCA",
                _ENTERPRISE_CA_ATTRS,
                "SUBTREE",
            ),
            (
                "root_cas",
                f"CN=Certification Authorities,{pks_base}",
                "(objectClass=certificationAuthority)",
                "RootCA",
                _ROOT_CA_ATTRS,
                "SUBTREE",
            ),
            (
                "ntauth_store",
                f"CN=NTAuthCertificates,{pks_base}",
                "(objectClass=*)",
                "NTAuthStore",
                _NTAUTH_ATTRS,
                "BASE",
            ),
            (
                "aia_cas",
                f"CN=AIA,{pks_base}",
                "(objectClass=certificationAuthority)",
                "AIACA",
                _AIA_ATTRS,
                "SUBTREE",
            ),
        ]

        for label, base, ldap_filter, kind, attrs, scope in categories:
            self._collect_category(
                result=result,
                label=label,
                search_base=base,
                ldap_filter=ldap_filter,
                kind=kind,
                attributes=attrs,
                scope=scope,
            )

        # ESC13 precondition: issuance-policy OIDs that map to a group via
        # ``msDS-OIDToGroupLink``. The map is consumed by ``detect_esc13`` to
        # enrich edge notes with the linked group DN.
        oid_links = self._collect_oid_to_group_links(pks_base, result=result)
        return result, oid_links

    def _collect_category(
        self,
        *,
        result: CollectionResult,
        label: str,
        search_base: str,
        ldap_filter: str,
        kind: NodeKind,
        attributes: list[str],
        scope: str,
    ) -> None:
        try:
            self._connection.search(
                search_base=search_base,
                search_filter=ldap_filter,
                attributes=attributes,
                search_scope=scope,
                controls=SD_FLAGS_DACL_CONTROL,
            )
            entries = list(self._connection.entries)
        except Exception as exc:
            if _is_adcs_container_absent(exc):
                # No Public Key Services container in this domain — the EXPECTED
                # answer for a domain without ADCS, NOT an error. Quiet: no red
                # error line, no PostHog event. One summary line per domain.
                self._note_adcs_absent()
                print_info_debug(
                    f"[adcs-collector] {label} container absent at {search_base} "
                    "(no ADCS in this domain)"
                )
                return
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            note_stage_exception(result, f"adcs.{label}", exc)
            print_info_debug(
                f"[adcs-collector] {label} search failed at {search_base}: {exc}"
            )
            return

        print_info_debug(f"[adcs-collector] {label} found {len(entries)} entries")

        for entry in entries:
            node = None
            try:
                node = _build_node_from_ldap_entry(entry, kind, self._domain)
                if node is None:
                    continue
                result.add_node(node)

                sd_bytes = _raw_bytes(entry, "nTSecurityDescriptor")
                if sd_bytes:
                    for edge in self._acl_parser.parse_sd(
                        sd_bytes, node.object_id, node.kind
                    ):
                        result.add_edge(edge)
                else:
                    self.unread_security_descriptors.add(node.object_id)
            except Exception as exc:
                if node is not None:
                    self.unread_security_descriptors.add(node.object_id)
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    f"[adcs-collector] {label} entry processing failed: {exc}"
                )

    # ------------------------------------------------------------------
    # Phase 2/3 escalation detection (sync entry-point with async probe phase)
    # ------------------------------------------------------------------

    def _collect_oid_to_group_links(
        self, pks_base: str, result: CollectionResult | None = None
    ) -> _OidToGroupLinks:
        """Return the issuance-policy OID → linked group DN map for ESC13.

        Queries ``msPKI-Enterprise-Oid`` objects under the OID container.
        Only OIDs with a non-empty ``msDS-OIDToGroupLink`` attribute are
        included — those are the ones that produce ESC13 abuse paths.

        The result carries ``resolved`` so the ESC13 detector can tell the
        two empty-map cases apart. A query FAILURE returns
        ``resolved=False`` (a data gap — ESC13 presence is unknown); a
        SUCCESSFUL query with no linked OIDs returns ``resolved=True`` with an
        empty map (ESC13 genuinely does not exist in this domain). Both are
        empty; only the failure is uncertain.
        """
        oid_base = f"CN=OID,{pks_base}"
        try:
            self._connection.search(
                search_base=oid_base,
                search_filter="(objectClass=msPKI-Enterprise-Oid)",
                attributes=["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"],
                search_scope="SUBTREE",
            )
            entries = list(self._connection.entries)
        except Exception as exc:
            if _is_adcs_container_absent(exc):
                # No OID container — same "no ADCS in this domain" signal.
                # ESC13 presence is genuinely resolved (absent), not a data gap.
                self._note_adcs_absent()
                print_info_debug(
                    f"[adcs-collector] OID container absent at {oid_base} "
                    "(no ADCS in this domain)"
                )
                return _OidToGroupLinks(links={}, resolved=True)
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            if result is not None:
                note_stage_exception(result, "adcs.oid_links", exc)
            print_info_debug(
                f"[adcs-collector] OID-to-group link query failed at {oid_base}: {exc}"
            )
            return _OidToGroupLinks(links={}, resolved=False)

        print_info_debug(
            f"[adcs-collector] OID-to-group query returned {len(entries)} "
            f"msPKI-Enterprise-Oid entries from {oid_base}"
        )

        mapping: dict[str, str] = {}
        for entry in entries:
            oid_value = ""
            group_dn = ""
            try:
                attrs = getattr(entry, "entry_attributes_as_dict", {}) or {}
                raw_oid = attrs.get("msPKI-Cert-Template-OID") or attrs.get(
                    "mspki-cert-template-oid"
                )
                if isinstance(raw_oid, list):
                    oid_value = str(raw_oid[0]).strip() if raw_oid else ""
                elif raw_oid is not None:
                    oid_value = str(raw_oid).strip()
                raw_group = attrs.get("msDS-OIDToGroupLink") or attrs.get(
                    "msds-oidtogrouplink"
                )
                if isinstance(raw_group, list):
                    group_dn = str(raw_group[0]).strip() if raw_group else ""
                elif raw_group is not None:
                    group_dn = str(raw_group).strip()
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                continue
            if oid_value and group_dn:
                mapping[oid_value] = group_dn
            # No per-OID debug here — when none have the link, the summary
            # line below is sufficient and avoids 10–15 identical messages.

        if mapping:
            print_info_debug(
                f"[adcs-collector] resolved {len(mapping)} OID-to-group link(s) for ESC13"
            )
        elif entries:
            _unlinked = sum(
                1 for a in entries
                if not (
                    (getattr(a, "entry_attributes_as_dict", {}) or {}).get("msDS-OIDToGroupLink")
                    or (getattr(a, "entry_attributes_as_dict", {}) or {}).get("msds-oidtogrouplink")
                )
            )
            print_info_debug(
                f"[adcs-collector] no OID-to-group links found "
                f"({_unlinked}/{len(entries)} OIDs without msDS-OIDToGroupLink) — "
                "ESC13 does not exist in this domain; no ESC13 edges will be emitted"
            )
        return _OidToGroupLinks(links=mapping, resolved=True)

    def _detect_escalations(
        self,
        result: CollectionResult,
        *,
        oid_links: _OidToGroupLinks | None = None,
    ) -> None:
        """Run ESC detectors against all collected templates and CAs.

        Probe data (registry / web / DC binding) is gathered upfront via
        a single ``asyncio.run`` boundary, then injected into the pure
        detectors. Probe failures degrade silently to defaults: with no
        probe data the detectors emit no edges, preserving the
        no-false-positive contract.
        """
        templates = [n for n in result.nodes.values() if n.kind == "CertTemplate"]
        cas = [n for n in result.nodes.values() if n.kind == "EnterpriseCA"]
        if not templates and not cas:
            return

        # Run async probe phase. Any orchestration error degrades to an
        # empty probe map; per-CA / per-domain failures already degrade
        # individually inside ``_run_probes``.
        ca_probes, domain_binding = self.read_ca_host_state(cas)

        # The detection itself is ONE shared function: the scan here and the
        # read-only recheck observers grade the same inputs the same way.
        detected = detect_collected_escalations(
            result,
            domain=self._domain,
            oid_links=oid_links,
            ca_probes=ca_probes,
            domain_binding=domain_binding,
        )
        added = 0
        for edge in detected.template_edges:
            result.add_edge(edge)
            added += 1
        pki_added = 0
        for edge in detected.pki_edges:
            result.add_edge(edge)
            pki_added += 1

        ca_added = 0
        for ca in cas:
            if ca.object_id not in detected.ca_edges:
                # Detection failed for this CA (already reported): nothing to
                # record, exactly as before the detection was factored out.
                continue
            probe = ca_probes.get(ca.object_id)
            new_edges = detected.ca_edges[ca.object_id]
            for edge in new_edges:
                result.add_edge(edge)
                ca_added += 1

            # ESC6 / ESC11 / Certighost: record what the registry probe could
            # decide for THIS CA. A check whose input was not read is NOT
            # ASSESSED with its reason, never clear by absence. A CA that only
            # lacked a CA-host administrator is deferred to the orchestrator's
            # re-run instead, which records it once (see the constructor).
            pending = self._pending_registry_probe(ca, probe)
            if pending is not None:
                result.adcs_registry_pending.append(pending)
            else:
                self._observe_registry_checks(
                    ca=ca,
                    probe=probe,
                    ca_edge_relations={e.relation for e in new_edges},
                    result=result,
                    templates=templates,
                )

            # ESC12: emitted only for a confirmed read-only check.
            esc12_result = probe.esc12 if probe is not None else None
            if esc12_result is not None and getattr(esc12_result, "confirmed", False):
                from adscan_internal.services.collector.adcs_detectors.esc12 import (
                    detect_esc12,
                )

                host_sid = self._resolve_ca_host_object_id(
                    str(ca.properties.get("dns_hostname") or "")
                )
                for edge in detect_esc12(
                    ca_node=ca, check_result=esc12_result, ca_host_object_id=host_sid
                ):
                    result.add_edge(edge)
                    ca_added += 1

        total_added = added + pki_added + ca_added
        if total_added:
            print_info_debug(
                f"[adcs-collector] phase2/3 emitted {total_added} ADCSESC* edge(s)"
            )

        # Orphaned-CA hygiene signal (Part B3). A CA whose host does not resolve
        # anywhere AND has no Computer object is a decommissioned CA object still
        # registered in AD — a HYGIENE finding, never an exploitable ESC. Emitted
        # observed-certain only (a resolvable-but-unreachable CA, or one with a
        # Computer object, stays a DATA GAP). Runs AFTER ESC detection so a stale
        # CA that also carries an LDAP-detected ESC edge renders as hygiene.
        self._stamp_orphaned_cas(result, cas, ca_probes)

        # Mark ADCS nodes that are ESC targets as high-value so the Phase 2 BFS
        # treats them as Tier-0 terminal nodes and surfaces attack paths to them.
        # CertTemplates with ADCSESC1/2/3/6/9/10/15 edges and EnterpriseCA nodes
        # with ESC7/8/11 edges are domain-compromise vectors.
        _TEMPLATE_ESC_RELATIONS = frozenset(
            {
                "ADCSESC1",
                "ADCSESC2",
                "ADCSESC3",
                "ADCSESC4",
                "ADCSESC6",
                "ADCSESC9",
                "ADCSESC10",
                "ADCSESC13",
                "ADCSESC15",
            }
        )
        _CA_ESC_RELATIONS = frozenset(
            {
                "ADCSESC5",
                "ADCSESC7",
                "ADCSESC8",
                "ADCSESC11",
                # Certighost (CVE-2026-54121) targets the EnterpriseCA node too.
                "certighost",
            }
        )

        from adscan_internal.services.adcs.esc12_detection import ESC12_RELATION

        esc_targets: set[str] = set()
        for edge in result.edges:
            if (
                edge.relation in _TEMPLATE_ESC_RELATIONS
                or edge.relation in _CA_ESC_RELATIONS
                # ESC12's raw edge always targets the EnterpriseCA node.
                or edge.relation == ESC12_RELATION
            ):
                esc_targets.add(edge.target_object_id)

        if esc_targets:
            updated: dict[str, CollectorNode] = {}
            for oid, node in result.nodes.items():
                if oid in esc_targets and not node.highvalue:
                    updated[oid] = CollectorNode(
                        object_id=node.object_id,
                        kind=node.kind,
                        name=node.name,
                        domain=node.domain,
                        samaccountname=node.samaccountname,
                        distinguished_name=node.distinguished_name,
                        enabled=node.enabled,
                        highvalue=True,
                        properties=node.properties,
                    )
            result.nodes.update(updated)
            print_info_debug(
                f"[adcs-collector] marked {len(updated)} ADCS node(s) as highvalue "
                f"(ESC targets → Tier-0 BFS terminals)"
            )

    def _stamp_orphaned_cas(
        self,
        result: CollectionResult,
        cas: list[CollectorNode],
        ca_probes: dict[str, "_CAProbeBundle"],
    ) -> None:
        """Flag decommissioned CA objects and emit their standalone hygiene finding.

        For each enterprise CA that is orphaned (host unresolvable + no Computer
        object, per :func:`_ca_host_is_orphaned`):

        * stamps ``is_orphaned_ca=True`` on the CA node so the persisted
          ``adcs_enterprise_cas.json`` record carries the signal;
        * when the orphaned CA's own certificate is STILL in
          ``CN=NTAuthCertificates`` (its thumbprints intersect the NTAuth store),
          stamps ``in_ntauth_store`` + ``ntauth_thumbprint(s)`` instead of the
          plain hygiene block — AD still trusts certificates the retired CA
          issued for authentication, which the standalone HIGH catalog finding
          ``adcs_orphaned_ca_ntauth`` reports (certificate forgery is possible if
          the retired private key is recoverable);
        * otherwise stamps the standalone hygiene ``adcs_finding_state`` block on
          the CA record, so the finding stands on its own with NO dependency on an
          ESC edge existing (an orphaned CA's web enrollment is a data gap, so it
          usually has no ESC edge at all);
        * marks ``is_orphaned_ca`` on any ADCS ESC edge that DOES target the stale
          CA, so the report/web edge views (which read the same signal) render it
          as hygiene rather than a data gap.
        """
        from adscan_core.reporting.adcs_finding_state import (
            ADCS_FINDING_STATE_KEY,
            STATE_HYGIENE,
            build_adcs_finding_state,
        )

        computer_hostnames = _collect_computer_hostnames(result)
        # The thumbprint set of CN=NTAuthCertificates — the certificates AD trusts
        # for client authentication. An orphaned CA whose own certificate is still
        # in this set is a live trust anchor for a decommissioned authority, which
        # is the HIGH certificate-forgery finding (not plain cleanup hygiene).
        ntauth_thumbprints: set[str] = set()
        for node in result.nodes.values():
            if str(node.kind) != "NTAuthStore":
                continue
            ntauth_thumbprints.update(
                str(t).lower()
                for t in (node.properties.get("ca_certificate_thumbprints") or [])
            )
        orphaned = 0
        for ca in cas:
            probe = ca_probes.get(ca.object_id)
            web = probe.web if probe is not None else None
            # ``could_not_verify`` is the "name did not resolve to any usable
            # address" signal (NXDOMAIN / no recovered IP after the full resolver
            # ladder), distinct from a resolvable-but-unreachable host — which
            # connects on its recovered IP and never sets could_not_verify.
            name_unresolvable = bool(web is not None and web.could_not_verify)
            ca_host = str(ca.properties.get("dns_hostname") or "").strip()
            if not _ca_host_is_orphaned(
                ca_host=ca_host,
                name_unresolvable=name_unresolvable,
                computer_hostnames=computer_hostnames,
            ):
                continue
            ca.properties["is_orphaned_ca"] = True
            ca_thumbprints = {
                str(t).lower()
                for t in (ca.properties.get("ca_certificate_thumbprints") or [])
            }
            in_ntauth = sorted(ca_thumbprints & ntauth_thumbprints)
            if in_ntauth:
                # Trust-anchor exposure: the retired CA's certificate is still in
                # NTAuthCertificates, so AD keeps trusting certificates it issued
                # for authentication. The standalone HIGH catalog finding
                # (adcs_orphaned_ca_ntauth) carries the client message, so the
                # plain "just clean it up" hygiene block is deliberately NOT
                # stamped here — it would contradict a HIGH finding on the same CA.
                ca.properties["in_ntauth_store"] = True
                ca.properties["ntauth_thumbprint"] = in_ntauth[0]
                ca.properties["ntauth_thumbprints"] = in_ntauth
                print_info_debug(
                    "[adcs-collector] orphaned CA "
                    f"{mark_sensitive(ca_host, 'hostname')} is STILL in "
                    "NTAuthCertificates — decommissioned-CA trust-anchor finding "
                    "(certificate forgery possible if the retired key is recoverable)"
                )
            else:
                ca.properties[ADCS_FINDING_STATE_KEY] = build_adcs_finding_state(
                    state=STATE_HYGIENE, ca_host=ca_host
                )
            for edge in result.edges:
                if (
                    edge.target_object_id == ca.object_id
                    and str(edge.relation or "").upper().startswith("ADCSESC")
                ):
                    edge.notes["is_orphaned_ca"] = True
            orphaned += 1
            print_info_debug(
                "[adcs-collector] CA "
                f"{mark_sensitive(ca_host, 'hostname')} is orphaned "
                "(host unresolvable + no computer object) — hygiene finding, "
                "not an exploitable ESC"
            )
        if orphaned:
            print_info_debug(
                f"[adcs-collector] flagged {orphaned} orphaned CA(s) as hygiene findings"
            )

    def _build_web_probe_credential(self) -> WebProbeCredential | None:
        """Derive an NTLM-usable credential for the EPA test from the connection.

        The EPA (channel-binding) differential test relays NTLM, so it needs a
        password or NT hash — a Kerberos-only / ccache credential (or an
        unauthenticated scan) cannot drive it. Returns None in that case, which
        leaves the EPA state unknown and ESC8 emission unchanged.
        """
        config = getattr(self._connection, "config", None)
        if config is None:
            return None
        username = getattr(config, "username", None)
        password = getattr(config, "password", None)
        # The Kerberos pre-mint clears config.password to force the ccache bind;
        # recover the NTLM-usable secret it preserved so the EPA test still runs
        # on a password-auth Kerberos domain (plaintext OR NT-hash-in-password
        # both drive the NTLM relay). No credential_context fallback here today.
        if not password:
            password = getattr(config, "ntlm_dcom_fallback_secret", None)
        if not username or not password:
            return None
        domain = (
            getattr(config, "auth_domain", None)
            or getattr(config, "domain", None)
            or self._domain
        )
        return WebProbeCredential(
            username=str(username),
            domain=str(domain),
            password=str(password),
        )

    def _build_ca_security_credential(
        self,
    ) -> tuple[str, str | None, str | None, str] | None:
        """Derive ``(username, password, nt_hash, domain)`` for GetCASecurity.

        Mirrors :meth:`_build_web_probe_credential` (reads the connection's
        ``config``), but also surfaces a pass-the-hash secret: an NT hash stored
        either in a dedicated ``nt_hash`` field or, for LDAP pass-the-hash, in
        the ``password`` field (detected via ``_is_nt_hash``). Returns ``None``
        on a Kerberos-only / unauthenticated scan (no password AND no NT hash),
        so the CA-security read is skipped cleanly with no error — the same
        spirit as the EPA credential returning ``None``.

        Credential-context fallback: when the caller authenticated with a
        password, the LDAP transport pre-mints a Kerberos TGT and rewrites the
        config via ``dataclasses.replace(config, ccache_path=..., password=None,
        aes_key=None)`` — so ``config.password`` / ``config.nt_hash`` are
        ``None`` on exactly the path this DCOM (NTLM/PtH-only) read needs. The
        retained ``config.credential_context`` (a ``CredentialContext``) still
        holds the original secret after the pre-mint — that is how the
        expiry-reminter re-mints. So when the config secret is empty, fall back
        to that context; without it, delegated ManageCA holders (surfaced only
        via GetCASecurity over DCOM) would be silently skipped on every
        Kerberos-capable domain. An explicit config secret still wins; the
        context is a fallback only, and a Kerberos-ccache-only / unauth
        credential with no re-mintable secret still yields ``None``.
        """
        config = getattr(self._connection, "config", None)
        if config is None:
            return None
        username = getattr(config, "username", None)

        password = getattr(config, "password", None)
        nt_hash = getattr(config, "nt_hash", None)
        secret_source = "config-secret" if (password or nt_hash) else "none"

        # The Kerberos pre-mint clears config.password/nt_hash but retains
        # config.credential_context — recover the secret from there.
        if not password and not nt_hash:
            cred_ctx = getattr(config, "credential_context", None)
            if cred_ctx is not None:
                password = getattr(cred_ctx, "password", None)
                nt_hash = getattr(cred_ctx, "nt_hash", None)
                if not username:
                    username = getattr(cred_ctx, "username", None)
                if password or nt_hash:
                    secret_source = "credential_context"

        # Third fallback: the bind-inert secret the /tmp (no-credential-context)
        # pre-mint preserved before clearing config.password/aes_key. Without it
        # a password-auth Kerberos domain with no CredentialContext yields no
        # NTLM secret and delegated ManageCA holders are silently skipped.
        if not password and not nt_hash:
            fallback_secret = getattr(config, "ntlm_dcom_fallback_secret", None)
            if fallback_secret:
                password = fallback_secret
                secret_source = "ntlm_dcom_fallback"

        print_info_debug(
            f"adcs GetCASecurity credential source={secret_source}"
        )

        if not username:
            return None

        # LDAP pass-the-hash carries the NT hash in the password field — applies
        # to a config secret AND a credential-context-sourced one.
        if password and not nt_hash:
            try:
                from adscan_internal.services.ldap_transport_service import _is_nt_hash

                if _is_nt_hash(str(password)):
                    nt_hash = str(password)
                    password = None
            except Exception:  # noqa: BLE001
                pass

        if not password and not nt_hash:
            return None

        domain = (
            getattr(config, "auth_domain", None)
            or getattr(config, "domain", None)
        )
        if not domain:
            cred_ctx = getattr(config, "credential_context", None)
            if cred_ctx is not None:
                domain = getattr(cred_ctx, "auth_domain", None)
        domain = domain or self._domain
        return (
            str(username),
            str(password) if password else None,
            str(nt_hash) if nt_hash else None,
            str(domain),
        )

    def _registry_checks_allowed(self) -> bool:
        """Whether the scan policy lets any registry-fed check run (ESC6/ESC11/Certighost)."""
        if self._shell is None:
            return True
        from adscan_core.scan_policy import gate

        allowed = {key: gate.finding_allowed(self._shell, key) for key in REGISTRY_FINDING_KEYS}
        skipped = [key for key, ok in allowed.items() if not ok]
        if skipped:
            from adscan_internal.services.scan_policy_notice import notify_policy_skip

            notify_policy_skip(
                self._shell,
                [f"finding:{key}" for key in skipped],
                subject="AD CS registry checks",
                key="adcs_registry_checks",
            )
        return any(allowed.values())

    def _pending_registry_probe(
        self, ca: CollectorNode, probe: "_CAProbeBundle | None"
    ) -> "PendingCARegistryProbe | None":
        """Return the deferral record for a CA that only lacked an administrator."""
        if not self._defer_unresolved_registry or probe is None:
            return None
        if probe.registry is not None or probe.registry_skip_reason != REASON_NO_LOCAL_ADMIN:
            return None
        return PendingCARegistryProbe(
            ca_object_id=ca.object_id,
            ca_host=str(ca.properties.get("dns_hostname") or "").strip(),
            ca_name=ca.name.split("@", 1)[0] if ca.name else "",
        )

    def _observe_registry_checks(
        self,
        *,
        ca: CollectorNode,
        probe: "_CAProbeBundle | None",
        ca_edge_relations: set[str],
        result: CollectionResult,
        templates: list[CollectorNode],
    ) -> None:
        """Record the ESC6 / ESC11 / Certighost observation of one CA."""
        observe_ca_registry_checks(
            self._shell,
            domain=self._domain,
            ca=ca,
            registry=probe.registry if probe is not None else None,
            skip_reason=(
                probe.registry_skip_reason if probe is not None else REASON_NO_LOCAL_ADMIN
            ),
            ca_edge_relations=ca_edge_relations,
            result=result,
            templates=templates,
        )

    def _resolve_ca_connect_and_spn(self, ca_host: str) -> tuple[str, str]:
        """Split a CA FQDN into ``(connect_ip, spn_fqdn)`` via the reachable-IP SSOT.

        On a hardened / container engagement the DC's DNS routinely cannot
        resolve a member CA host's FQDN (``A lookup ... resolution lifetime
        expired``), so a transport handed the raw FQDN dead-ends with an
        ``SMBConnectionError`` even though ADscan reached the DC fine on its IP
        and the workspace inventory already holds the CA host's IP. This routes
        the connect target through ``resolve_connect_and_spn`` — the reachable
        IP for the CONNECT, the FQDN kept as the Kerberos SPN (an IP handed to
        Kerberos as the SPN would fail auth; the two must stay separate).

        Best-effort by contract: with no ``shell`` (lab / direct-unit-test
        construction), an already-IP host, or any resolution failure, it returns
        ``(ca_host, ca_host)`` unchanged, so a working environment never
        regresses to a worse address.
        """
        from adscan_internal.services.adcs.ca_host_access import (
            resolve_ca_connect_and_spn,
        )

        config = getattr(self._connection, "config", None)
        dc_ip = getattr(config, "dc_ip", None) if config else None
        return resolve_ca_connect_and_spn(
            self._shell,
            domain=self._domain,
            dc_ip=str(dc_ip) if dc_ip else None,
            ca_host=ca_host,
        )

    def _ca_host_verdict(self, ca_host: str) -> Any:
        """The collection-host verdict for a CA host (``None`` when unknown).

        The ownership rule is the engagement-scope SSOT
        (``engagement_scope.collection_host_verdict``): this collector contacts
        only hosts its own domain owns, and a host of another domain is never
        contacted from here, in scope or not.
        """
        if not ca_host:
            return None
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            collection_host_verdict,
        )

        return collection_host_verdict(
            self._shell, host=ca_host, collecting_domain=self._domain
        )

    def _ca_host_not_contacted(
        self, *, ca_name: str, ca_host: str, verdict: Any, record_esc12: bool = True
    ) -> "_CAProbeBundle":
        """Record every host-level CA check as not checked, with the reason.

        ``record_esc12=False`` (the read-only recheck) keeps the ESC12
        observation out of any recorded run: a recheck writes only its own
        evidence, never the scan's observation record.
        """
        from adscan_internal.services.adcs import esc12_detection as esc12  # noqa: PLC0415
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            note_collection_host_skipped,
        )

        if self._shell is not None:
            note_collection_host_skipped(
                self._shell,
                verdict,
                what=f"Certification authority {ca_name or ca_host} host checks",
            )
        else:
            print_info_debug(
                f"[adcs-collector] CA host {mark_sensitive(ca_host, 'host')} not "
                f"contacted: {verdict.reason}"
            )
        esc12_result = esc12.not_checked(ca_name, ca_host, verdict.reason)
        if record_esc12 and self._shell is not None and ca_name:
            esc12.observe_esc12_result(
                self._shell, domain=self._domain, result=esc12_result
            )
        return _CAProbeBundle(
            registry=None,
            web=None,
            ca_security_edges=[],
            esc12=esc12_result,
            registry_skip_reason=verdict.reason,
        )

    async def _fetch_ca_security_edges(
        self, ca: CollectorNode, *, host_verdict: Any = None
    ) -> list[CollectorEdge]:
        """Read the CA's authoritative security descriptor and parse ESC7 edges.

        Uses the NATIVE async aiosmb DCOM stack (ICertAdminD2::GetCASecurity)
        driven off ``smb_machine_with_fallback`` — Kerberos-native (reuses the
        collector's pre-minted TGT ccache) and posture-aware (Kerberos-AES →
        RC4 → NTLM prioritization). Kerberos-ccache is primary; the recovered
        NTLM/PtH secret is carried only as the posture-pruned fallback leg.

        Best-effort: any failure (no usable auth, DCOM/CSRA error, parse
        failure) yields ``[]`` so ADCS collection is never aborted. Consulting
        the CA security descriptor surfaces ManageCA / ManageCertificates
        holders that were delegated after CA install and are therefore absent
        from the CA object's LDAP ``nTSecurityDescriptor``.
        """
        import rich.markup

        from adscan_internal.services._kerberos_spn import is_ip_address
        from adscan_internal.services.adcs.ca_host_access import ca_host_smb_realms
        from adscan_internal.services.collector.adcs_detectors._ca_security import (
            parse_ca_security_edges,
        )
        from adscan_internal.services.smb_transport import smb_machine_with_fallback

        ca_name = ca.name.split("@", 1)[0] if ca.name else ""

        # Kerberos DCOM binds to the CA over cifs/<host> — the SPN must be an
        # FQDN (§9bis). dns_hostname is the CA's FQDN; if it is missing or an
        # IP we do NOT synthesize one, we skip cleanly.
        ca_host = str(ca.properties.get("dns_hostname") or "").strip()
        if not ca_host or not ca_name:
            return []
        _register_ca_identity(ca_name, ca_host)
        verdict = host_verdict if host_verdict is not None else self._ca_host_verdict(ca_host)
        if verdict is not None and not verdict.allowed:
            print_info_debug(
                f"adcs GetCASecurity skipped for {mark_sensitive(ca_name, 'hostname')}: "
                f"CA host not contacted from this domain ({verdict.reason})"
            )
            return []
        # From here this domain owns the CA: whatever the reads below return,
        # the segregation-of-duties evidence knows the CA was in its remit, so
        # a CA nothing could be read from reads "not assessed", never absent.
        _stamp_role_separation_reading(ca)
        if is_ip_address(ca_host):
            print_info_debug(
                f"adcs GetCASecurity skipped for {mark_sensitive(ca_name, 'hostname')}: "
                "only an IP is available for the CA host "
                "(need an FQDN for Kerberos DCOM)"
            )
            return []

        config = getattr(self._connection, "config", None)
        ccache_path = getattr(config, "ccache_path", None) if config else None

        # Recover the NTLM/PtH secret (may be None) as the posture-pruned
        # fallback leg. Kerberos-ccache stays primary.
        credential = self._build_ca_security_credential()
        username = password = nt_hash = None
        domain: str | None = None
        if credential is not None:
            username, password, nt_hash, domain = credential
        # ccache-only scan: no NTLM secret recovered, but the ccache still
        # authenticates — resolve username/domain from the LDAP config.
        if not username and config is not None:
            username = getattr(config, "username", None)
        if not domain:
            domain = (
                (getattr(config, "auth_domain", None) if config else None)
                or (getattr(config, "domain", None) if config else None)
                or self._domain
            )

        if not username or (not ccache_path and not password and not nt_hash):
            print_info_debug(
                f"adcs GetCASecurity skipped for {mark_sensitive(ca_name, 'hostname')}: "
                "no Kerberos ccache and no NTLM/PtH secret recoverable "
                "(unauthenticated scan)"
            )
            return []

        posture_snapshot = getattr(config, "posture_snapshot", None) if config else None
        dc_ip = getattr(config, "dc_ip", None) if config else None
        # Two realms (CLAUDE.md, auth vs target domain): the credential's own
        # domain mints the TGT at ITS KDC, while the CA host belongs to the
        # domain being collected, whose DC is the referral target. Collapsing
        # both onto the credential domain asked the credential's KDC for the
        # CA host's service ticket, which hands back the cross-realm referral
        # TGT, and the CA host rejects it as STATUS_WRONG_PASSWORD.
        realms = ca_host_smb_realms(
            host_domain=self._domain,
            credential_domain=str(domain),
            auth_kdc=(getattr(config, "auth_kdc", None) if config else None) or dc_ip,
            target_kdc=dc_ip,
        )

        # Recover the CA host's reachable IP so a DC-DNS gap on the member CA's
        # FQDN does not dead-end the DCOM connect. IP for the CONNECT, FQDN kept
        # as the Kerberos SPN (``target_hostname``). Run off-loop: the resolver's
        # live NIC-probe drives its own event loop, which cannot run inside this
        # coroutine's loop. Best-effort — falls back to the FQDN unchanged.
        connect_ip, spn_fqdn = ca_host, ca_host
        if self._shell is not None:
            from adscan_internal.services.async_bridge import run_sync_off_loop

            connect_ip, spn_fqdn = run_sync_off_loop(
                self._resolve_ca_connect_and_spn, ca_host
            )

        smb_config = SMBConfig(
            target_ip=connect_ip,
            target_hostname=spn_fqdn,
            username=str(username),
            password=password,
            nt_hash=nt_hash,
            ccache_path=ccache_path,
            use_kerberos=bool(ccache_path),
            posture_snapshot=posture_snapshot,
            **realms,
        )

        source = (
            "kerberos-ccache (native aiosmb DCOM)"
            if ccache_path
            else "ntlm/pth (native aiosmb DCOM)"
        )
        print_info_debug(
            f"adcs GetCASecurity read attempted ca_host="
            f"{mark_sensitive(ca_host, 'hostname')} "
            f"connect_ip={mark_sensitive(connect_ip, 'ip')} "
            f"spn={mark_sensitive(spn_fqdn, 'hostname')} "
            f"ca_name={mark_sensitive(ca_name, 'hostname')} source={source}"
        )

        sd_bytes = None
        try:
            async with smb_machine_with_fallback(smb_config) as machine:
                # The security descriptor and the role-separation flag are read
                # on ONE CA-administration interface, one after the other, so
                # the flag costs no second sign-in. A refused descriptor read
                # (the normal answer for an account that is not a CA
                # administrator) still leaves the flag, which needs only Read.
                facts, err = await machine.get_ca_security_and_role_separation_dcom(
                    ca_name
                )
                if err is not None:
                    raise err
                _stamp_role_separation_reading(
                    ca, role_separation=facts.get("role_separation")
                )
                if facts.get("role_separation_error") is not None:
                    print_info_debug(
                        "adcs role-separation flag not read for "
                        f"{mark_sensitive(ca_name, 'hostname')}: "
                        f"{type(facts['role_separation_error']).__name__}"
                    )
                if facts.get("security_error") is not None:
                    raise facts["security_error"]
                sd_bytes = facts.get("security")
        except Exception as exc:  # noqa: BLE001
            detail = f"{type(exc).__name__}: {rich.markup.escape(str(exc))}"
            if _is_expected_ca_security_denial(exc):
                # Reading the CA security descriptor requires CA-admin rights,
                # so ACCESS_DENIED is the NORMAL outcome for the vast majority
                # of authenticated scans. Reporting the expected answer as an
                # error told the operator something had gone wrong on nearly
                # every run against a domain with ADCS, and sent an exception to
                # error tracking for a case that is not one.
                print_info_debug(
                    "adcs GetCASecurity not permitted for "
                    f"{mark_sensitive(ca_name, 'hostname')} (CA-admin rights "
                    f"required): {detail}"
                )
                return []
            if _is_ca_host_unresolvable(exc):
                # The CA host FQDN could not be resolved / reached from this
                # vantage (the DC-DNS gap on a member CA). This is a DATA GAP —
                # the CA-security read is skipped, ESC7-delegated holders are
                # UNKNOWN — not a failure. Mirror the ESC8 could_not_verify path
                # rather than a red operator error.
                print_info_debug(
                    "adcs GetCASecurity skipped for "
                    f"{mark_sensitive(ca_name, 'hostname')}: CA host could not be "
                    f"resolved or reached (data gap): {detail}"
                )
                return []
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"adcs GetCASecurity read failed for "
                f"{mark_sensitive(ca_name, 'hostname')}: {detail}"
            )
            return []

        edges = parse_ca_security_edges(sd_bytes, ca.object_id)
        if sd_bytes is not None:
            _stamp_role_separation_reading(ca, security_edges=edges)
        if sd_bytes is None:
            print_info_debug(
                f"adcs GetCASecurity read failed for "
                f"{mark_sensitive(ca_name, 'hostname')}: no security "
                "descriptor returned (DCOM read error)"
            )
        else:
            print_info_debug(
                f"adcs GetCASecurity parsed {len(edges)} ManageCA/ManageCertificates "
                f"edge(s) for {mark_sensitive(ca_name, 'hostname')}"
            )
        return edges

    async def _check_esc12(
        self, *, ca_host: str, ca_name: str, host_verdict: Any = None
    ) -> Any:
        """Run the read-only ESC12 check for one CA and record its observation.

        The credential gate is the local-admin SSOT
        (``esc12_detection.resolve_esc12_credential``), never the collection
        credential: on the first low-privilege collection the check reads
        ``not_checked``, and the privileged refresh a domain compromise triggers
        (``post_da.run_audit_post_da_graph_refresh``) re-runs this collector
        with a proven administrator. Returns ``None`` when there is no shell
        (lab scripts, direct construction): no check, no observation.
        """
        if self._shell is None:
            return None
        from adscan_core.scan_policy import gate
        from adscan_internal.services.adcs import esc12_detection as esc12
        from adscan_internal.services.async_bridge import run_sync_off_loop

        if not gate.finding_allowed(self._shell, esc12.ESC12_FINDING_KEY):
            from adscan_internal.services.scan_policy_notice import notify_policy_skip

            notify_policy_skip(
                self._shell,
                f"finding:{esc12.ESC12_FINDING_KEY}",
                subject="ESC12 check",
                key="adcs_esc12",
                target=ca_name or "",
            )
            result = esc12.not_checked(ca_name, ca_host, esc12.REASON_EXCLUDED_BY_POLICY)
        elif not ca_host or not ca_name:
            result = esc12.not_checked(ca_name, ca_host, esc12.REASON_CA_HOST_UNKNOWN)
        elif (
            verdict := host_verdict if host_verdict is not None else self._ca_host_verdict(ca_host)
        ) is not None and not verdict.allowed:
            result = esc12.not_checked(ca_name, ca_host, verdict.reason)
        else:
            connect_ip, spn_fqdn = run_sync_off_loop(
                self._resolve_ca_connect_and_spn, ca_host
            )
            config = getattr(self._connection, "config", None)
            dc_ip = getattr(config, "dc_ip", None) if config is not None else None
            credential = run_sync_off_loop(
                esc12.resolve_esc12_credential,
                self._shell,
                domain=self._domain,
                ca_host=ca_host,
                connect_ip=connect_ip,
                spn_fqdn=spn_fqdn,
                kdc_ip=str(dc_ip) if dc_ip else None,
                directory_roles=self._directory_roles,
                host_domain=self._domain,
            )
            result = await esc12.check_esc12(
                ca_name=ca_name, ca_host=ca_host, credential=credential
            )
        esc12.observe_esc12_result(self._shell, domain=self._domain, result=result)
        return result

    def _resolve_ca_host_object_id(self, ca_host: str) -> str:
        """Return the SID of the CA host's computer object, ``""`` when unknown.

        One ``dNSHostName`` lookup in the domain partition, run only for a CA
        whose ESC12 check was confirmed. Best-effort: a failure leaves the edge
        anchored on the CA node (``detect_esc12``), never dropped.
        """
        host = str(ca_host or "").strip()
        base = str(getattr(self._connection, "domain_dn", "") or "").strip()
        if not host or not base:
            return ""
        escaped = "".join(
            f"\\{ord(ch):02x}" if ch in "*()\\\x00" else ch for ch in host
        )
        try:
            self._connection.search(
                search_base=base,
                search_filter=f"(&(objectCategory=computer)(dNSHostName={escaped}))",
                attributes=["objectSid"],
                search_scope="SUBTREE",
            )
            for entry in list(self._connection.entries):
                raw = _first(_attrs(entry), "objectSid")
                if isinstance(raw, (bytes, bytearray)):
                    from winacl.dtyp.sid import SID

                    return str(SID.from_bytes(bytes(raw)))
                if raw:
                    return str(raw).strip()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
        return ""

    def read_ca_host_state(
        self, cas: list[CollectorNode], *, check_esc12: bool = True
    ) -> tuple[dict[str, "_CAProbeBundle"], tuple[int, bool] | None]:
        """Run the CA-host and DC-binding reads; never raises.

        The single sync entry to :meth:`_run_probes` (one bridge call). Any
        orchestration error degrades to an empty probe map, so a CA-host check
        whose input was not read stays undecided. ``check_esc12=False`` (the
        read-only recheck) skips the ESC12 check and its observation record.
        """
        try:
            from adscan_internal.services.async_bridge import run_async_sync

            return run_async_sync(self._run_probes(cas, check_esc12=check_esc12))
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[adcs-collector] probe phase failed: {exc}")
            return {}, None

    async def _run_probes(
        self, cas: list[CollectorNode], *, check_esc12: bool = True
    ) -> tuple[dict[str, "_CAProbeBundle"], tuple[int, bool] | None]:
        """Run all CA-host and DC binding probes concurrently."""
        registry_probe = ADCSCARegistryProbe()
        web_probe = ADCSWebEnrollmentProbe()

        # Scan credential for the active EPA (channel-binding) test on the CA's
        # HTTPS /certsrv endpoint. None on unauthenticated / Kerberos-only scans
        # -> the EPA state stays unknown and ESC8 emission is unchanged.
        web_credential = self._build_web_probe_credential()

        ca_probes: dict[str, _CAProbeBundle] = {}

        # CA host probes — registry + web in parallel per CA.
        for ca in cas:
            ca_host = str(ca.properties.get("dns_hostname") or "").strip()
            ca_name = ca.name.split("@", 1)[0] if ca.name else ""
            _register_ca_identity(ca_name, ca_host)
            registry_result: CARegistryProbeResult | None = None
            web_result: WebEnrollmentProbeResult | None = None

            # Host-level reads belong to the collection of the domain that OWNS
            # the CA host. An enterprise CA lives in the forest-wide
            # Configuration NC, so a child domain's LDAP legitimately returns a
            # CA hosted in the parent: it stays mapped from that directory data,
            # and its host (web enrollment, registry, CA security descriptor,
            # ESC12) is never contacted from here.
            host_verdict = self._ca_host_verdict(ca_host)
            if host_verdict is not None and not host_verdict.allowed:
                ca_probes[ca.object_id] = self._ca_host_not_contacted(
                    ca_name=ca_name,
                    ca_host=ca_host,
                    verdict=host_verdict,
                    record_esc12=check_esc12,
                )
                continue

            # Web probe — host-only, no credentials needed. Recover the CA
            # host's reachable IP so a DC-DNS gap on its FQDN does not read as
            # "no web enrollment" (the ESC8 false negative). Connect on the IP,
            # keep the FQDN for the TLS SNI / Host header / EPA SPN. Best-effort:
            # falls back to the FQDN when there is no shell or resolution fails.
            if ca_host:
                connect_host: str | None = None
                if self._shell is not None:
                    from adscan_internal.services.async_bridge import (
                        run_sync_off_loop,
                    )

                    _ip, _spn = run_sync_off_loop(
                        self._resolve_ca_connect_and_spn, ca_host
                    )
                    if _ip and _ip != ca_host:
                        connect_host = _ip
                try:
                    web_result = await web_probe.probe(
                        host=ca_host,
                        connect_host=connect_host,
                        credential=web_credential,
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    print_info_debug(
                        f"[adcs-collector] web probe failed for "
                        f"{mark_sensitive(ca_host, 'host')}: {exc}"
                    )

            # Registry probe (ESC6 / ESC11 / Certighost inputs) — needs a CA-host
            # administrator via the builder callback. Every way it can fail to
            # run is kept as a reason: the checks are then recorded NOT
            # ASSESSED, never cleared by absence.
            registry_skip_reason = REASON_REGISTRY_PROBE_NOT_CONFIGURED
            if not ca_host or not ca_name:
                registry_skip_reason = REASON_CA_HOST_UNKNOWN
            elif not self._registry_checks_allowed():
                registry_skip_reason = REASON_EXCLUDED_BY_POLICY
            elif self._smb_config_builder is not None:
                registry_skip_reason = REASON_NO_LOCAL_ADMIN
                try:
                    smb_config = await self._smb_config_builder(ca_host)
                    if smb_config is not None:
                        registry_result = await registry_probe.probe(
                            config=smb_config, ca_name=ca_name
                        )
                        registry_skip_reason = ""
                    else:
                        print_info_debug(
                            "[adcs-collector] no CA-host administrator credential for "
                            f"{mark_sensitive(ca_host, 'host')}; "
                            + (
                                "registry probe deferred until roles resolve"
                                if self._defer_unresolved_registry
                                else "registry checks not assessed"
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    registry_skip_reason = REASON_READ_FAILED
                    print_info_debug(
                        f"[adcs-collector] registry probe failed for "
                        f"{mark_sensitive(ca_host, 'host')}: {exc}"
                    )

            # CA security descriptor (MS-CSRA GetCASecurity) — authoritative
            # ManageCA / ManageCertificates holders, including non-default
            # (delegated) ones the CA object's LDAP nTSecurityDescriptor omits.
            # Best-effort: a failure here must never abort ADCS collection.
            ca_security_edges: list[CollectorEdge] = []
            try:
                ca_security_edges = await self._fetch_ca_security_edges(
                    ca, host_verdict=host_verdict
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    "[adcs-collector] CA security read failed for "
                    f"{mark_sensitive(ca_host, 'host')}: {exc}"
                )

            # ESC12 (YubiHSM KSP password in the CA host registry). Read-only,
            # and only with a credential PROVEN to administer the CA host; every
            # outcome is recorded in the run's observation record. Best-effort.
            esc12_result = None
            try:
                if check_esc12:
                    esc12_result = await self._check_esc12(
                        ca_host=ca_host, ca_name=ca_name, host_verdict=host_verdict
                    )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    "[adcs-collector] ESC12 check failed for "
                    f"{mark_sensitive(ca_host, 'host')}: {type(exc).__name__}"
                )

            ca_probes[ca.object_id] = _CAProbeBundle(
                registry=registry_result,
                web=web_result,
                ca_security_edges=ca_security_edges,
                esc12=esc12_result,
                registry_skip_reason=registry_skip_reason,
            )

        # DC binding probe — single per-domain call for ESC10 inputs.
        domain_binding: tuple[int, bool] | None = None
        if self._dc_binding_probe is not None:
            try:
                domain_binding = await self._dc_binding_probe(self._domain)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    "[adcs-collector] DC binding probe failed for "
                    f"{mark_sensitive(self._domain, 'domain')}: {exc}"
                )

        return ca_probes, domain_binding


class DetectedEscalations(NamedTuple):
    """The ESC edges one detection pass produced, in the order the scan adds them.

    ``ca_edges`` maps each Enterprise CA object id to its edges; a CA whose
    detection raised is ABSENT from the map (an empty list means detection ran
    and found nothing), so a caller never reads a failed CA as clear.
    """

    template_edges: list[CollectorEdge]
    pki_edges: list[CollectorEdge]
    ca_edges: dict[str, list[CollectorEdge]]

    def all_edges(self) -> list[CollectorEdge]:
        """Every detected edge, template first, then PKI objects, then CAs."""
        out = list(self.template_edges) + list(self.pki_edges)
        for edges in self.ca_edges.values():
            out.extend(edges)
        return out


def published_template_labels(cas: Iterable[CollectorNode]) -> set[str]:
    """Casefolded enrollment names (``cn``) every Enterprise CA publishes.

    The publication gate (mirrors Certipy's ``is_enabled``): a template is
    issuable only when its ``cn`` appears in some CA's ``certificateTemplates``.
    Matched on ``cn``, never ``displayName``, which may differ.
    """
    labels: set[str] = set()
    for ca in cas:
        ca_templates = ca.properties.get("certificate_templates") or []
        if not isinstance(ca_templates, (list, tuple)):
            ca_templates = [ca_templates]
        for entry in ca_templates:
            label = str(entry).strip().casefold()
            if label:
                labels.add(label)
    return labels


def template_is_published(template: CollectorNode, labels: set[str]) -> bool:
    """Whether ``template`` is published by a CA (see :func:`published_template_labels`)."""
    cn = str(template.properties.get("cn") or "").strip().casefold()
    return bool(cn) and cn in labels


def detect_collected_escalations(
    result: CollectionResult,
    *,
    domain: str,
    oid_links: "_OidToGroupLinks | None",
    ca_probes: Mapping[str, "_CAProbeBundle"],
    domain_binding: tuple[int, bool] | None,
) -> DetectedEscalations:
    """Run every ESC detector over one collection's PKI objects. No side effects.

    The single detection seam of AD CS: the scan's collector and the read-only
    recheck observers both call it, so a re-check grades the current state with
    exactly the predicates that raised the finding. Inputs are the collected
    nodes and their ACL edges (``result``), the ESC13 OID links, and the CA-host
    reads (``ca_probes``, ``domain_binding``); with a CA-host read missing the
    detectors emit nothing for the checks it feeds (no false positive). A
    detector that raises is reported and skipped, never fatal.
    """
    templates = [n for n in result.nodes.values() if n.kind == "CertTemplate"]
    cas = [n for n in result.nodes.values() if n.kind == "EnterpriseCA"]

    oid_to_group_dn = dict(oid_links.links) if oid_links is not None else {}
    oid_links_resolved = oid_links.resolved if oid_links is not None else False

    edges_by_target: dict[str, list] = {}
    for edge in result.edges:
        edges_by_target.setdefault(edge.target_object_id, []).append(edge)

    cert_mapping_methods, strong_cert_binding_enforced = (
        domain_binding if domain_binding is not None else (0, False)
    )

    published_labels = published_template_labels(cas)

    # Build a "is template published by any CA whose ESC6 probe says
    # SAN2 is enabled?" flag per template. ESC6 takes a single bool;
    # if any CA publishing the template has the flag set, surface the
    # finding. Match on ``cn`` (enrollment name), same as the publication
    # gate — the old ``template.name`` (displayName) match was a latent
    # false-negative when displayName != CN.
    template_to_san2: dict[str, bool] = {}
    for ca in cas:
        probe = ca_probes.get(ca.object_id)
        if probe is None or probe.registry is None:
            continue
        if not probe.registry.editf_attributesubjectaltname2_enabled:
            continue
        for template_id in _published_template_ids(ca, templates):
            template_to_san2[template_id] = True

    # Per-template detection.
    template_edges: list[CollectorEdge] = []
    for template in templates:
        try:
            new_edges = _detect_adcs_escalations(
                template_node=template,
                template_acl_edges=edges_by_target.get(template.object_id, []),
                domain=domain,
                ca_editf_san2_enabled=template_to_san2.get(template.object_id, False),
                cert_mapping_methods=cert_mapping_methods,
                strong_cert_binding_enforced=strong_cert_binding_enforced,
                oid_to_group_dn=oid_to_group_dn,
                oid_links_resolved=oid_links_resolved,
                published=template_is_published(template, published_labels),
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"[adcs-collector] esc detection failed for {template.object_id}: {exc}"
            )
            continue
        template_edges.extend(new_edges)

    # Per-PKI-object detection (ESC5: write on NTAuthStore / RootCA / AIACA / EnterpriseCA).
    from adscan_internal.services.collector.adcs_detectors.esc5 import (  # noqa: PLC0415
        detect_esc5,
    )

    pki_edges: list[CollectorEdge] = []
    for pki_node in result.nodes.values():
        if pki_node.kind not in {"NTAuthStore", "RootCA", "AIACA", "EnterpriseCA"}:
            continue
        try:
            new_edges = detect_esc5(
                pki_node=pki_node,
                pki_acl_edges=edges_by_target.get(pki_node.object_id, []),
                domain=domain,
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"[adcs-collector] esc5 detection failed for {pki_node.object_id}: {exc}"
            )
            continue
        pki_edges.extend(new_edges)

    # ESC8 / ESC11 anchor at the well-known Authenticated Users SID
    # (S-1-5-11) — resolved by the detectors themselves — so no domain-SID
    # derivation is needed here. That node is injected into the graph before
    # persistence, so the edge always resolves and (unlike a domain-local
    # Domain Users anchor) surfaces the cross-forest NTLM-relay surface.

    # Per-CA detection (ESC7 + probe-driven ESC8 / ESC11).
    ca_edges_by_ca: dict[str, list[CollectorEdge]] = {}
    for ca in cas:
        probe = ca_probes.get(ca.object_id)
        # Merge the LDAP-derived CA ACL edges with the ManageCA /
        # ManageCertificates edges read from the CA's own security
        # descriptor (MS-CSRA). detect_esc7 dedups by SID, so the overlap
        # with the LDAP defaults collapses; the delta is the delegated
        # (non-default) management holders LDAP alone cannot see.
        ca_acl_edges = list(edges_by_target.get(ca.object_id, []))
        if probe is not None and probe.ca_security_edges:
            ca_acl_edges = ca_acl_edges + probe.ca_security_edges
        web_enabled = (
            probe.web.web_enrollment_enabled
            if probe is not None and probe.web is not None
            else False
        )
        # ESC8 data gap (Exposure-Validation doctrine): the CA host could
        # not be resolved / reached, so ESC8 is UNKNOWN — surface it as a
        # data gap, never let a DNS failure read as "web enrollment absent".
        if probe is not None and probe.web is not None and probe.web.could_not_verify:
            print_info_debug(
                "[adcs-collector] ESC8 could not be verified for CA "
                f"{mark_sensitive(ca.name or ca.object_id, 'hostname')}: "
                "CA host name could not be resolved or reached (data gap) — "
                "web enrollment status is UNKNOWN, not disabled"
            )
        registry = probe.registry if probe is not None else None
        try:
            ca_edges_by_ca[ca.object_id] = list(
                _detect_adcs_ca_escalations(
                    ca_node=ca,
                    ca_acl_edges=ca_acl_edges,
                    domain=domain,
                    web_enrollment_enabled=web_enabled,
                    **registry_ca_detector_kwargs(registry),
                )
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"[adcs-collector] esc detection failed for CA {ca.object_id}: {exc}"
            )
    return DetectedEscalations(template_edges, pki_edges, ca_edges_by_ca)


class PendingCARegistryProbe(NamedTuple):
    """A CA whose registry probe found no CA-host administrator on the first pass."""

    ca_object_id: str
    ca_host: str
    ca_name: str


def registry_ca_detector_kwargs(
    registry: CARegistryProbeResult | None,
) -> dict[str, Any]:
    """The CA-level detector inputs the registry probe decides (ESC11, Certighost).

    Safe defaults when the probe did not run or a value was not read:
    ``enforce_encrypt_icertrequest=True`` (ESC11 needs a CONFIRMED absence of
    the enforcement bit; a failed probe on a CA that enforces encryption once
    produced a false ESC11 the relay then disproved with
    ``rpc_s_access_denied``), and the Certighost inputs unset (flag off, EditFlags
    unreadable, build/UBR unknown), so a CA with no registry data stays a data
    gap, never a false positive. One definition for the first pass and the
    orchestrator's re-run.
    """
    if registry is None:
        return {
            "enforce_encrypt_icertrequest": True,
            "certighost_chase_enabled": False,
            "certighost_edit_flags_readable": False,
            "certighost_os_build_number": None,
            "certighost_os_ubr": None,
            "certighost_os_major_version": None,
            "certighost_os_minor_version": None,
        }
    return {
        "enforce_encrypt_icertrequest": (
            registry.enforce_encrypt_icertrequest
            if registry.interface_flags_readable
            else True
        ),
        "certighost_chase_enabled": bool(registry.editf_enablechaseclientdc_enabled),
        "certighost_edit_flags_readable": bool(registry.edit_flags_readable),
        "certighost_os_build_number": registry.os_build_number,
        "certighost_os_ubr": registry.os_ubr,
        "certighost_os_major_version": registry.os_major_version,
        "certighost_os_minor_version": registry.os_minor_version,
    }


def _published_template_ids(
    ca: CollectorNode, templates: Iterable[CollectorNode]
) -> set[str]:
    """Object ids of the templates ``ca`` publishes, matched on ``cn``."""
    published = ca.properties.get("certificate_templates") or []
    if not isinstance(published, (list, tuple)):
        published = [published]
    published_norm = {str(t).strip().casefold() for t in published if t}
    return {
        t.object_id
        for t in templates
        if str(t.properties.get("cn") or "").strip().casefold() in published_norm
    }


def observe_ca_registry_checks(
    shell: Any,
    *,
    domain: str,
    ca: CollectorNode,
    registry: CARegistryProbeResult | None,
    skip_reason: str,
    ca_edge_relations: set[str],
    result: CollectionResult,
    templates: list[CollectorNode],
) -> None:
    """Record the ESC6 / ESC11 / Certighost observation of one CA. Never raises."""
    if shell is None:
        return
    _share_ca_host_patch_level(shell, domain=domain, ca=ca, registry=registry)
    assessments = assess_registry_checks(
        registry, skip_reason=skip_reason or REASON_READ_FAILED
    )
    template_ids = _published_template_ids(ca, templates)
    esc6_found = any(
        e.relation == "ADCSESC6" and e.target_object_id in template_ids
        for e in result.edges
    )
    found_by_check = {
        CHECK_ESC6: esc6_found,
        CHECK_ESC11: "ADCSESC11" in ca_edge_relations,
        CHECK_CERTIGHOST: "certighost" in ca_edge_relations,
    }
    for check_id, assessment in assessments.items():
        observe_registry_check(
            shell,
            domain=domain,
            check_id=check_id,
            assessment=assessment,
            found=found_by_check[check_id],
        )


def _share_ca_host_patch_level(
    shell: Any, *, domain: str, ca: CollectorNode, registry: CARegistryProbeResult | None
) -> None:
    """Hand the CA host's build / UBR (Certighost's read) to the patch-level cache.

    The registry probe reads them with a proven administrator of the CA host, so
    the patch-level CVE checks reuse that read instead of reading the host again.
    """
    if registry is None or registry.os_build_number is None:
        return
    from adscan_internal.services.cve_scanner.checks._os_patch_level import (  # noqa: PLC0415
        ACCESS_ADMINISTRATIVE,
    )
    from adscan_internal.services.cve_scanner.host_patch_level import (  # noqa: PLC0415
        record_host_patch_level,
    )

    props = getattr(ca, "properties", None) or {}
    record_host_patch_level(
        shell,
        domain=domain,
        hosts=(registry.target_host, props.get("dnshostname") if isinstance(props, dict) else None),
        build=registry.os_build_number,
        ubr=registry.os_ubr,
        access=ACCESS_ADMINISTRATIVE,
    )


def registry_dependent_edges(
    *,
    ca: CollectorNode,
    registry: CARegistryProbeResult | None,
    templates: list[CollectorNode],
    result: CollectionResult,
    domain: str,
) -> list[CollectorEdge]:
    """The edges a late registry read adds for one CA: ESC6, ESC11, Certighost.

    Used by the orchestrator's re-run, after the first pass emitted every other
    ADCS edge for this CA without registry data (those first-pass detectors,
    given no registry, emit none of these three, so nothing is duplicated). The
    detectors are the same ones the first pass calls; ESC6 is emitted only for
    templates this CA publishes and that carry no ESC6 edge yet (another CA
    may already have raised it).
    """
    if registry is None:
        return []
    from adscan_internal.services.collector.adcs_detectors.certighost_detector import (  # noqa: PLC0415
        detect_certighost,
    )
    from adscan_internal.services.collector.adcs_detectors.esc6 import (  # noqa: PLC0415
        detect_esc6,
    )
    from adscan_internal.services.collector.adcs_detectors.esc11 import (  # noqa: PLC0415
        detect_esc11,
    )

    kwargs = registry_ca_detector_kwargs(registry)
    edges: list[CollectorEdge] = []
    try:
        edges.extend(
            detect_esc11(
                ca_node=ca,
                domain=domain,
                enforce_encrypt_icertrequest=kwargs["enforce_encrypt_icertrequest"],
            )
        )
        edges.extend(
            detect_certighost(
                ca_node=ca,
                domain=domain,
                editf_enablechaseclientdc_enabled=kwargs["certighost_chase_enabled"],
                edit_flags_readable=kwargs["certighost_edit_flags_readable"],
                os_build_number=kwargs["certighost_os_build_number"],
                os_ubr=kwargs["certighost_os_ubr"],
                os_major_version=kwargs["certighost_os_major_version"],
                os_minor_version=kwargs["certighost_os_minor_version"],
            )
        )
        if registry.editf_attributesubjectaltname2_enabled:
            published = _published_template_ids(ca, templates)
            already = {e.target_object_id for e in result.edges if e.relation == "ADCSESC6"}
            acl_by_target: dict[str, list[CollectorEdge]] = {}
            for edge in result.edges:
                acl_by_target.setdefault(edge.target_object_id, []).append(edge)
            for template in templates:
                if template.object_id not in published or template.object_id in already:
                    continue
                edges.extend(
                    detect_esc6(
                        template_node=template,
                        template_acl_edges=acl_by_target.get(template.object_id, []),
                        domain=domain,
                        ca_editf_san2_enabled=True,
                    )
                )
    except Exception as exc:  # noqa: BLE001 - a detector failure never aborts the re-run
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return edges


# Internal probe-result aggregate. Not exported.
class _CAProbeBundle:
    __slots__ = (
        "registry",
        "web",
        "ca_security_edges",
        "esc12",
        "registry_skip_reason",
    )

    def __init__(
        self,
        *,
        registry: CARegistryProbeResult | None,
        web: WebEnrollmentProbeResult | None,
        ca_security_edges: list["CollectorEdge"] | None = None,
        esc12: Any = None,
        registry_skip_reason: str = "",
    ) -> None:
        self.registry = registry
        self.web = web
        self.ca_security_edges: list["CollectorEdge"] = ca_security_edges or []
        # ESC12 read-only check result (``Esc12CheckResult``) or ``None`` when
        # the collector has no shell to resolve a local-admin credential with.
        self.esc12 = esc12
        self.registry_skip_reason = registry_skip_reason
