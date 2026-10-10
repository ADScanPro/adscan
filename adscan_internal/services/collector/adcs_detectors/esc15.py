"""ESC15 (EKUwu, CVE-2024-49019) — Schema V1 template + EnrolleeSuppliesSubject."""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._common import (
    get_enroll_principal_sids,
    make_adcs_edge,
    template_int_property,
)
from adscan_internal.services.collector.adcs_detectors.constants import (
    ENROLLEE_SUPPLIES_SUBJECT,
    PEND_ALL_REQUESTS,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc15(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
) -> list[CollectorEdge]:
    """Return ADCSESC15 edges when a Schema V1 template is exploitable.

    Conditions:
      * Template kind is CertTemplate
      * msPKI-Template-Schema-Version == 1
      * msPKI-Certificate-Name-Flag has ENROLLEE_SUPPLIES_SUBJECT bit
      * msPKI-Enrollment-Flag does NOT have PEND_ALL_REQUESTS (no manager approval)
      * msPKI-RA-Signature == 0 (no RA co-sign)
      * At least one principal holds an enrollment-capable ACL right

    The template's configured EKU is deliberately NOT a precondition. ESC15
    (EKUwu, CVE-2024-49019) abuses the fact that a schema version 1 CA honors
    application policies supplied by the requester in the CSR, overriding the
    template's own EKU. So a schema-v1 enrollee-supplies-subject template is
    vulnerable regardless of whether its configured EKU grants client auth —
    the attacker injects a client-authentication application policy at request
    time. Gating on the configured EKU would miss exactly the templates (e.g. a
    Server Authentication / WebServer template) that EKUwu targets, which is the
    same class certipy flags as ESC15.
    """
    if template_node.kind != "CertTemplate":
        return []

    schema_version = template_int_property(
        template_node, "mspki_template_schema_version", "msPKI-Template-Schema-Version"
    )
    if schema_version != 1:
        return []

    name_flag = template_int_property(
        template_node, "mspki_certificate_name_flag", "msPKI-Certificate-Name-Flag"
    )
    if not (name_flag & ENROLLEE_SUPPLIES_SUBJECT):
        return []

    enrollment_flag = template_int_property(
        template_node, "mspki_enrollment_flag", "msPKI-Enrollment-Flag"
    )
    if enrollment_flag & PEND_ALL_REQUESTS:
        return []

    ra_signature = template_int_property(
        template_node, "mspki_ra_signature", "msPKI-RA-Signature"
    )
    if ra_signature > 0:
        return []

    return [
        make_adcs_edge(principal_sid=sid, template_node=template_node, esc="15")
        for sid in get_enroll_principal_sids(template_acl_edges)
    ]
