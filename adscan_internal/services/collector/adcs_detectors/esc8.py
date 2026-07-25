"""ESC8 — CA HTTP web enrollment endpoint enabled (NTLM relay surface).

Probe-driven: needs ``web_enrollment_enabled`` from a CA HTTP probe. Without
probe data no edges are emitted.

EPA gating lives in the probe verdict, not here: when the CA offers web
enrollment ONLY over HTTPS and that endpoint enforces EPA (channel binding),
the probe resolves ``web_enrollment_enabled=False`` (the NTLM relay is
defeated), so no ESC8 edge is emitted — the hardened, recommended CA state has
no residual weakness to report. HTTP web enrollment is EPA-agnostic and keeps
``web_enrollment_enabled=True``.

The edge source is the Domain Users group SID (``{domain_sid}-513``) passed by
the collector, so the edge resolves to a real graph node and surfaces correctly
in tactical findings.  Callers must pass ``domain_users_sid`` whenever the
domain SID is known; if absent we skip emission rather than using a synthetic
placeholder that cannot be resolved by the graph display layer.
"""

from __future__ import annotations

from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc8(
    *,
    ca_node: CollectorNode,
    domain: str,
    web_enrollment_enabled: bool = False,
    domain_users_sid: str | None = None,
) -> list[CollectorEdge]:
    if not web_enrollment_enabled:
        return []
    if ca_node.kind != "EnterpriseCA":
        return []

    # Resolve source to the real Domain Users SID so the edge is navigable in
    # the attack graph and renders correctly in tactical findings.
    source_oid = domain_users_sid
    if not source_oid:
        return []

    return [
        CollectorEdge(
            source_object_id=source_oid,
            target_object_id=ca_node.object_id,
            relation="ADCSESC8",
            source="adcs_detector",
            method="adcs",
            notes={"requires": "domain_credentials_with_ntlm"},
        )
    ]
