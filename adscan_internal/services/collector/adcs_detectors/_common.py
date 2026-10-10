"""Shared helpers for ADCS ESC detection."""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors.constants import (
    CLIENT_AUTHENTICATION_EKUS,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode

# ACL relations emitted by ACLParser that grant enrollment-capable rights on a
# certificate template. The native ACL parser does not currently emit a
# distinct "Enroll" / "AutoEnroll" relation (those are extended rights gated by
# specific control GUIDs); any of the broad object-write relations below imply
# the principal can grant itself enrollment, which is what matters for ESC1-15
# attack-path emission.
_ENROLL_RELATIONS: frozenset[str] = frozenset(
    {
        "GenericAll",
        "GenericWrite",
        "WriteDACL",
        "WriteOwner",
        "AllExtendedRights",
        "Enroll",
        "AutoEnroll",
    }
)

# ACL relations on an EnterpriseCA object that imply CA management capability.
# Native ACLParser collapses ManageCA / ManageCertificates extended rights into
# Generic*/WriteDACL/WriteOwner/AllExtendedRights — all are equivalent or
# stronger than the documented ESC7 rights.
_CA_MANAGEMENT_RELATIONS: frozenset[str] = frozenset(
    {
        "GenericAll",
        "GenericWrite",
        "WriteDACL",
        "WriteOwner",
        "AllExtendedRights",
        "ManageCA",
        "ManageCertificates",
    }
)


def get_enroll_principal_sids(acl_edges: list[CollectorEdge]) -> list[str]:
    """Return principal SIDs that hold an enrollment-capable right on the template."""
    sids: list[str] = []
    seen: set[str] = set()
    for edge in acl_edges:
        if edge.relation in _ENROLL_RELATIONS:
            sid = edge.source_object_id
            if sid and sid not in seen:
                seen.add(sid)
                sids.append(sid)
    return sids


def ca_acl_edges_with_management(
    ca_acl_edges: list[CollectorEdge],
) -> list[CollectorEdge]:
    """Return CA ACL edges that grant CA management equivalent rights.

    Native ACLParser emits GenericAll/WriteDACL/WriteOwner — all equivalent or
    stronger than the documented ESC7 ManageCA/ManageCertificates extended
    rights, so they are treated as ESC7-eligible.
    """
    return [e for e in ca_acl_edges if e.relation in _CA_MANAGEMENT_RELATIONS]


def _get_property(template_node: CollectorNode, *names: str):
    """Return the first property value found across the supplied names.

    Accepts both the underscore form stored by ``ADCSCollector`` (e.g.
    ``mspki_certificate_name_flag``) and the LDAP attribute form (e.g.
    ``mspki-certificate-name-flag`` or ``msPKI-Certificate-Name-Flag``).
    """
    props = template_node.properties or {}
    for name in names:
        if name in props:
            return props[name]
        lower = name.lower()
        if lower in props:
            return props[lower]
        # Try common case mutations
        underscore = lower.replace("-", "_")
        if underscore in props:
            return props[underscore]
        dashed = lower.replace("_", "-")
        if dashed in props:
            return props[dashed]
    return None


def template_eku_list(template_node: CollectorNode) -> list[str]:
    """Return the EKU OIDs declared on the template (pKIExtendedKeyUsage)."""
    raw = _get_property(
        template_node,
        "pki_extended_key_usage",
        "pkiextendedkeyusage",
        "pKIExtendedKeyUsage",
    )
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw] if raw else []
    if isinstance(raw, (list, tuple)):
        return [str(item).strip() for item in raw if str(item).strip()]
    return []


def template_application_policies(template_node: CollectorNode) -> list[str]:
    """Return msPKI-Certificate-Application-Policy OIDs (used by ESC3 target)."""
    raw = _get_property(
        template_node,
        "mspki_certificate_application_policy",
        "mspki-certificate-application-policy",
        "msPKI-Certificate-Application-Policy",
    )
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw] if raw else []
    if isinstance(raw, (list, tuple)):
        return [str(item).strip() for item in raw if str(item).strip()]
    return []


def template_certificate_policies(template_node: CollectorNode) -> list[str]:
    """Return msPKI-Certificate-Policy OIDs (issuance policies, used by ESC13)."""
    raw = _get_property(
        template_node,
        "mspki_certificate_policy",
        "mspki-certificate-policy",
        "msPKI-Certificate-Policy",
    )
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw] if raw else []
    if isinstance(raw, (list, tuple)):
        return [str(item) for item in raw if str(item).strip()]
    return []


def template_int_property(template_node: CollectorNode, *names: str) -> int:
    """Return an integer property value (defaults to 0). Tries each name in order."""
    raw = _get_property(template_node, *names)
    if raw is None:
        return 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def has_client_auth_or_no_eku(ekus: list[str]) -> bool:
    """Return True when EKUs grant ClientAuth or are empty (which means any purpose)."""
    if not ekus:
        return True
    return any(eku in CLIENT_AUTHENTICATION_EKUS for eku in ekus)


def template_has_authentication_eku(template_node: CollectorNode) -> bool:
    """Return True when the template grants client authentication."""
    return has_client_auth_or_no_eku(template_eku_list(template_node))


def make_adcs_edge(
    *, principal_sid: str, template_node: CollectorNode, esc: str
) -> CollectorEdge:
    return CollectorEdge(
        source_object_id=principal_sid,
        target_object_id=template_node.object_id,
        relation=f"ADCSESC{esc}",
        source="adcs_detector",
        method="adcs",
    )


def make_certighost_edge(
    *, principal_sid: str, ca_node: CollectorNode, notes: dict
) -> CollectorEdge:
    """Build a Certighost (CVE-2026-54121) CA-bound attack-graph edge.

    Unlike :func:`make_adcs_edge`, the target is the EnterpriseCA node (there is
    no template node): Certighost is a CA-level ``EditFlags`` + patch-level
    weakness, not a template misconfiguration. The source is the enrolling
    principal (Authenticated Users) — any authenticated domain user can request
    the DC-impersonation certificate. ``notes`` carries the CVE id, the
    EditFlags chase state, the CA host build / UBR, the DC-impersonation intent
    and the read-only disclosure, so the report / web CTEM render the evidence.
    """
    return CollectorEdge(
        source_object_id=principal_sid,
        target_object_id=ca_node.object_id,
        relation="certighost",
        source="adcs_detector",
        method="adcs",
        notes=dict(notes or {}),
    )
