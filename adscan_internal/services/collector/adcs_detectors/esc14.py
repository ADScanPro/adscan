"""ESC14 — weak SAN-based mapping on auth template + low-priv enroll.

This phase implements the template-side half: an auth template that requires a
SAN-based USER-impersonation subject (UPN or email), has no manager approval,
no RA signature, and exposes enrollment to a non-Tier0 principal becomes an
ESC14 source. It gates ONLY on ``SUBJECT_ALT_REQUIRE_UPN`` / ``_EMAIL``, the
subject forms that bind a certificate to a user identity — NOT on
``SUBJECT_ALT_REQUIRE_DNS`` / ``_DOMAIN_DNS`` / ``_SPN``, which bind a machine
identity and are the ordinary shape of a computer/DC auto-enrollment template.
(The earlier constant nibble-shift made the "email" bit alias DOMAIN_DNS, so
machine DNS templates matched here in every domain — see ``constants.py``.)

The decisive ESC14 existence condition — a weak explicit
``altSecurityIdentities`` mapping (or write access to one) on a reachable
target AND StrongCertificateBindingEnforcement < 2 on the DCs — is INVISIBLE to
passive LDAP, so the edge is actively confirmed during collection by
``adscan_internal.services.adcs.esc14_confirmation`` (mirrors the ESC15
confirm). A template-shape match alone is a confirmation-pending candidate, not
a flat finding.
"""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._common import (
    get_enroll_principal_sids,
    make_adcs_edge,
    template_has_authentication_eku,
    template_int_property,
)
from adscan_internal.services.collector.adcs_detectors.constants import (
    PEND_ALL_REQUESTS,
    SUBJECT_ALT_REQUIRE_EMAIL,
    SUBJECT_ALT_REQUIRE_UPN,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc14(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
) -> list[CollectorEdge]:
    if template_node.kind != "CertTemplate":
        return []
    name_flag = template_int_property(
        template_node,
        "mspki_certificate_name_flag",
        "msPKI-Certificate-Name-Flag",
    )
    if not (name_flag & (SUBJECT_ALT_REQUIRE_UPN | SUBJECT_ALT_REQUIRE_EMAIL)):
        return []
    if (
        template_int_property(
            template_node, "mspki_enrollment_flag", "msPKI-Enrollment-Flag"
        )
        & PEND_ALL_REQUESTS
    ):
        return []
    if (
        template_int_property(template_node, "mspki_ra_signature", "msPKI-RA-Signature")
        > 0
    ):
        return []
    if not template_has_authentication_eku(template_node):
        return []
    return [
        make_adcs_edge(principal_sid=sid, template_node=template_node, esc="14")
        for sid in get_enroll_principal_sids(template_acl_edges)
    ]
