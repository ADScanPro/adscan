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

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_info_verbose,
    print_warning_debug,
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


def _is_expected_ca_security_denial(exc: BaseException) -> bool:
    """Return whether a GetCASecurity error is the normal not-CA-admin denial."""
    return any(marker in str(exc).lower() for marker in _CA_ACCESS_DENIED_MARKERS)


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


class ADCSCollector:
    """Enumerate ADCS objects from the Configuration naming context."""

    def __init__(
        self,
        connection: ADscanLDAPConnection,
        domain: str,
        acl_parser: ACLParser | None = None,
        smb_config_builder: SMBConfigBuilder | None = None,
        dc_binding_probe: DCBindingProbe | None = None,
    ) -> None:
        self._connection = connection
        self._domain = domain
        self._acl_parser = acl_parser or ACLParser(domain=domain, connection=connection)
        # When None all CA-host probes are skipped — detector defaults
        # preserve the no-false-positive contract.
        self._smb_config_builder = smb_config_builder
        self._dc_binding_probe = dc_binding_probe

    def collect(self) -> CollectionResult:
        """Run all five enumerations and return a populated ``CollectionResult``."""
        result = CollectionResult(domain=self._domain)

        config_dn = self._connection.config_dn
        if not config_dn:
            print_warning_debug(
                "[adcs-collector] connection has no config_dn; skipping ADCS"
            )
            return result

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
        oid_to_group_dn = self._collect_oid_to_group_links(pks_base)

        self._detect_escalations(result, oid_to_group_dn=oid_to_group_dn)

        print_info_debug(
            "[adcs-collector] done "
            f"domain={mark_sensitive(self._domain, 'domain')} "
            f"nodes={len(result.nodes)} edges={len(result.edges)}"
        )
        return result

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
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"[adcs-collector] {label} search failed at {search_base}: {exc}"
            )
            return

        print_info_debug(f"[adcs-collector] {label} found {len(entries)} entries")

        for entry in entries:
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
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    f"[adcs-collector] {label} entry processing failed: {exc}"
                )

    # ------------------------------------------------------------------
    # Phase 2/3 escalation detection (sync entry-point with async probe phase)
    # ------------------------------------------------------------------

    def _collect_oid_to_group_links(self, pks_base: str) -> dict[str, str]:
        """Return the issuance-policy OID → linked group DN map for ESC13.

        Queries ``msPKI-Enterprise-Oid`` objects under the OID container.
        Only OIDs with a non-empty ``msDS-OIDToGroupLink`` attribute are
        included — those are the ones that produce ESC13 abuse paths.

        Failures degrade silently to an empty map: ESC13 detection still
        emits ``requires_oid_resolution`` edges, just without linked-group
        enrichment.
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
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"[adcs-collector] OID-to-group link query failed at {oid_base}: {exc}"
            )
            return {}

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
                "all ESC13 edges will use requires_oid_resolution=True"
            )
        return mapping

    def _detect_escalations(
        self,
        result: CollectionResult,
        *,
        oid_to_group_dn: dict[str, str] | None = None,
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

        edges_by_target: dict[str, list] = {}
        for edge in result.edges:
            edges_by_target.setdefault(edge.target_object_id, []).append(edge)

        # Run async probe phase. Any orchestration error degrades to an
        # empty probe map; per-CA / per-domain failures already degrade
        # individually inside ``_run_probes``.
        ca_probes: dict[str, _CAProbeBundle] = {}
        domain_binding: tuple[int, bool] | None = None
        try:
            from adscan_internal.services.async_bridge import run_async_sync

            ca_probes, domain_binding = run_async_sync(self._run_probes(cas))
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"[adcs-collector] probe phase failed: {exc}")

        cert_mapping_methods, strong_cert_binding_enforced = (
            domain_binding if domain_binding is not None else (0, False)
        )

        # Build a "is template published by any CA whose ESC6 probe says
        # SAN2 is enabled?" flag per template. ESC6 takes a single bool;
        # if any CA publishing the template has the flag set, surface the
        # finding.
        template_to_san2: dict[str, bool] = {}
        for ca in cas:
            probe = ca_probes.get(ca.object_id)
            if probe is None or probe.registry is None:
                continue
            if not probe.registry.editf_attributesubjectaltname2_enabled:
                continue
            published = ca.properties.get("certificate_templates") or []
            if not isinstance(published, (list, tuple)):
                published = [published]
            published_norm = {str(t).strip().casefold() for t in published if t}
            for template in templates:
                # Match on cn / display name / objectguid label fragment.
                cn_label = template.name.split("@", 1)[0].casefold()
                if cn_label and cn_label in published_norm:
                    template_to_san2[template.object_id] = True

        # Per-template detection.
        added = 0
        for template in templates:
            template_edges = edges_by_target.get(template.object_id, [])
            try:
                new_edges = _detect_adcs_escalations(
                    template_node=template,
                    template_acl_edges=template_edges,
                    domain=self._domain,
                    ca_editf_san2_enabled=template_to_san2.get(
                        template.object_id, False
                    ),
                    cert_mapping_methods=cert_mapping_methods,
                    strong_cert_binding_enforced=strong_cert_binding_enforced,
                    oid_to_group_dn=oid_to_group_dn or {},
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    f"[adcs-collector] esc detection failed for {template.object_id}: {exc}"
                )
                continue
            for edge in new_edges:
                result.add_edge(edge)
                added += 1

        # Per-PKI-object detection (ESC5: write on NTAuthStore / RootCA / AIACA / EnterpriseCA).
        pki_nodes = [
            n
            for n in result.nodes.values()
            if n.kind in {"NTAuthStore", "RootCA", "AIACA", "EnterpriseCA"}
        ]
        pki_added = 0
        for pki_node in pki_nodes:
            pki_edges = edges_by_target.get(pki_node.object_id, [])
            try:
                from adscan_internal.services.collector.adcs_detectors.esc5 import (
                    detect_esc5,
                )

                new_edges = detect_esc5(
                    pki_node=pki_node,
                    pki_acl_edges=pki_edges,
                    domain=self._domain,
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    f"[adcs-collector] esc5 detection failed for {pki_node.object_id}: {exc}"
                )
                continue
            for edge in new_edges:
                result.add_edge(edge)
                pki_added += 1

        # Resolve Domain Users SID — needed by ESC8 / ESC11 detectors so the
        # edges resolve to a real principal rather than a synthetic placeholder.
        # The ADCS collector creates its own result so we cannot rely on a
        # Domain node from LDAP.  Instead we extract the domain SID prefix from
        # any S-1-5-21-X-Y-Z-RID source already present in the ACL edges
        # (Domain Admins / Domain Users / Authenticated Users etc. are common
        # ACE principals on templates) and append the well-known RID 513.
        import re as _re

        domain_users_sid: str | None = None
        _domain_sid_pattern = _re.compile(r"^S-1-5-21(?:-\d+){3}")
        for edge in result.edges:
            source = str(edge.source_object_id or "").upper()
            match = _domain_sid_pattern.match(source)
            if match:
                domain_users_sid = f"{match.group(0)}-513"
                break

        # Per-CA detection (ESC7 + probe-driven ESC8 / ESC11).
        ca_added = 0
        for ca in cas:
            probe = ca_probes.get(ca.object_id)
            # Merge the LDAP-derived CA ACL edges with the ManageCA /
            # ManageCertificates edges read from the CA's own security
            # descriptor (MS-CSRA). detect_esc7 dedups by SID, so the overlap
            # with the LDAP defaults collapses; the delta is the delegated
            # (non-default) management holders LDAP alone cannot see.
            ca_edges = list(edges_by_target.get(ca.object_id, []))
            if probe is not None and probe.ca_security_edges:
                ca_edges = ca_edges + probe.ca_security_edges
            web_enabled = (
                probe.web.web_enrollment_enabled
                if probe is not None and probe.web is not None
                else False
            )
            # Safe default: when registry probe failed or was unavailable,
            # treat enforce_encrypt as True so ESC11 is NOT emitted.
            # ESC11 requires CONFIRMED absence of encryption enforcement — if
            # we couldn't probe the registry we have no evidence of the
            # vulnerability and should not generate a false positive.
            # The relay execution path confirms this: a failed probe on
            # Retro.vl caused ESC11 to be emitted, but the relay returned
            # rpc_s_access_denied, proving the CA does enforce encryption.
            enforce_encrypt = (
                probe.registry.enforce_encrypt_icertrequest
                if probe is not None and probe.registry is not None
                else True
            )
            try:
                new_edges = _detect_adcs_ca_escalations(
                    ca_node=ca,
                    ca_acl_edges=ca_edges,
                    domain=self._domain,
                    web_enrollment_enabled=web_enabled,
                    enforce_encrypt_icertrequest=enforce_encrypt,
                    domain_users_sid=domain_users_sid,
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    f"[adcs-collector] esc detection failed for CA {ca.object_id}: {exc}"
                )
                continue
            for edge in new_edges:
                result.add_edge(edge)
                ca_added += 1

        total_added = added + pki_added + ca_added
        if total_added:
            print_info_debug(
                f"[adcs-collector] phase2/3 emitted {total_added} ADCSESC* edge(s)"
            )

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
            }
        )

        esc_targets: set[str] = set()
        for edge in result.edges:
            if (
                edge.relation in _TEMPLATE_ESC_RELATIONS
                or edge.relation in _CA_ESC_RELATIONS
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

    async def _fetch_ca_security_edges(
        self, ca: CollectorNode
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
        username = password = nt_hash = domain = None
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

        smb_config = SMBConfig(
            target_ip=ca_host,
            target_hostname=ca_host,
            domain=str(domain),
            auth_domain=str(domain),
            username=str(username),
            password=password,
            nt_hash=nt_hash,
            ccache_path=ccache_path,
            kdc_ip=str(dc_ip) if dc_ip else None,
            use_kerberos=bool(ccache_path),
            posture_snapshot=posture_snapshot,
        )

        source = (
            "kerberos-ccache (native aiosmb DCOM)"
            if ccache_path
            else "ntlm/pth (native aiosmb DCOM)"
        )
        print_info_debug(
            f"adcs GetCASecurity read attempted ca_host="
            f"{mark_sensitive(ca_host, 'hostname')} "
            f"ca_name={mark_sensitive(ca_name, 'hostname')} source={source}"
        )

        sd_bytes = None
        try:
            async with smb_machine_with_fallback(smb_config) as machine:
                sd_bytes, err = await machine.get_ca_security_dcom(ca_name)
                if err is not None:
                    raise err
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
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                f"adcs GetCASecurity read failed for "
                f"{mark_sensitive(ca_name, 'hostname')}: {detail}"
            )
            return []

        edges = parse_ca_security_edges(sd_bytes, ca.object_id)
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

    async def _run_probes(
        self, cas: list[CollectorNode]
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

            # Web probe — host-only, no credentials needed.
            if ca_host:
                try:
                    web_result = await web_probe.probe(
                        host=ca_host, credential=web_credential
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    print_info_debug(
                        f"[adcs-collector] web probe failed for "
                        f"{mark_sensitive(ca_host, 'host')}: {exc}"
                    )

            # Registry probe — needs SMB creds via builder callback.
            if ca_host and ca_name and self._smb_config_builder is not None:
                try:
                    smb_config = await self._smb_config_builder(ca_host)
                    if smb_config is not None:
                        registry_result = await registry_probe.probe(
                            config=smb_config, ca_name=ca_name
                        )
                    else:
                        print_info_debug(
                            "[adcs-collector] no SMB credentials available for "
                            f"{mark_sensitive(ca_host, 'host')}; skipping registry probe"
                        )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
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
                ca_security_edges = await self._fetch_ca_security_edges(ca)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                print_info_debug(
                    "[adcs-collector] CA security read failed for "
                    f"{mark_sensitive(ca_host, 'host')}: {exc}"
                )

            ca_probes[ca.object_id] = _CAProbeBundle(
                registry=registry_result,
                web=web_result,
                ca_security_edges=ca_security_edges,
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


# Internal probe-result aggregate. Not exported.
class _CAProbeBundle:
    __slots__ = ("registry", "web", "ca_security_edges")

    def __init__(
        self,
        *,
        registry: CARegistryProbeResult | None,
        web: WebEnrollmentProbeResult | None,
        ca_security_edges: list["CollectorEdge"] | None = None,
    ) -> None:
        self.registry = registry
        self.web = web
        self.ca_security_edges: list["CollectorEdge"] = ca_security_edges or []
