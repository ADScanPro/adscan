"""ESC13 — template with issuance policy OID linked to a group + low-priv enroll.

Each issuance-policy OID is resolved against the forest-wide
``msDS-OIDToGroupLink`` map collected from ``msPKI-Enterprise-Oid`` objects.
When a template carries at least one OID linked to a group, the detector
emits an ``ADCSESC13`` edge with ``linked_group_dn`` populated so the
persistence layer can re-emit a compromise-centric edge to that group.

ESC13 is an EXISTENCE-condition weakness: without an OID carrying a populated
``msDS-OIDToGroupLink``, enrolling a certificate injects NO group SID into the
PAC, so there is no privilege to escalate — no vulnerability. The detector must
therefore NOT emit an edge when no linked OID applies to the template. Two
distinct empty-map states are handled, signalled by ``oid_links_resolved``:

* ``oid_links_resolved=True`` and no linked OID — the OID query succeeded and
  the domain has no group-linked issuance policy for this template. ESC13 does
  not exist; the detector emits nothing (reporting the absence of a vulnerability
  is noise that buries real findings).
* ``oid_links_resolved=False`` — the OID→group query FAILED (a data gap). ESC13
  presence is unknown, so the detector must not emit a CRITICAL false positive.
  It suppresses the edge and logs the data gap for a ``--debug`` operator, per
  the exposure-validation doctrine ("when in doubt, leave it out").
"""

from __future__ import annotations

from adscan_core.rich_output import print_info_debug

from adscan_internal.services.collector.adcs_detectors._common import (
    get_enroll_principal_sids,
    template_certificate_policies,
    template_has_authentication_eku,
    template_int_property,
)
from adscan_internal.services.collector.adcs_detectors.constants import (
    PEND_ALL_REQUESTS,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc13(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
    oid_to_group_dn: dict[str, str] | None = None,
    oid_links_resolved: bool = False,
) -> list[CollectorEdge]:
    if template_node.kind != "CertTemplate":
        return []
    policies = template_certificate_policies(template_node)
    if not policies:
        return []
    # ESC13 abuse works by PKINIT-authenticating with the enrolled certificate,
    # so the template must grant client authentication (or carry no EKU, which
    # means any purpose). Without a client-auth EKU the injected group SID never
    # reaches a logon, so a group-linked policy alone is a false positive.
    # Certipy applies the same guard (``client_authentication`` required).
    if not template_has_authentication_eku(template_node):
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

    oid_map = oid_to_group_dn or {}
    linked_groups: list[dict[str, str]] = []
    for policy in policies:
        group_dn = oid_map.get(str(policy).strip())
        if group_dn:
            linked_groups.append({"oid": str(policy), "group_dn": group_dn})

    # No issuance-policy OID on this template resolves to a group. ESC13 abuse
    # requires an OID with a populated ``msDS-OIDToGroupLink`` — without one,
    # enrolling grants no group SID, so there is no vulnerability to report.
    if not linked_groups:
        unresolved = [str(p) for p in policies]
        if oid_links_resolved:
            print_info_debug(
                f"[esc13-detector] template {template_node.name!r}: "
                f"issuance policy OID(s) {unresolved} carry no msDS-OIDToGroupLink "
                f"in this domain — ESC13 not applicable, emitting no edge"
            )
        else:
            print_info_debug(
                f"[esc13-detector] template {template_node.name!r}: "
                f"OID(s) {unresolved} unresolved (OID->group link query failed / "
                f"data gap) — suppressing ESC13 edge to avoid a false positive"
            )
        return []

    edges: list[CollectorEdge] = []
    for sid in get_enroll_principal_sids(template_acl_edges):
        notes: dict[str, object] = {
            "issuance_policies": list(policies),
            # First match is sufficient — one ESC13 edge per template/source.
            "linked_group_dn": linked_groups[0]["group_dn"],
            "linked_oid": linked_groups[0]["oid"],
            "linked_groups": list(linked_groups),
        }
        edges.append(
            CollectorEdge(
                source_object_id=sid,
                target_object_id=template_node.object_id,
                relation="ADCSESC13",
                source="adcs_detector",
                method="adcs",
                notes=notes,
            )
        )
    return edges
