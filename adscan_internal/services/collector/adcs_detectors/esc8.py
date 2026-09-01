"""ESC8 — CA HTTP web enrollment endpoint enabled (NTLM relay surface).

Probe-driven: needs ``web_enrollment_enabled`` from a CA HTTP probe. Without
probe data no edges are emitted.

EPA gating lives in the probe verdict, not here: when the CA offers web
enrollment ONLY over HTTPS and that endpoint enforces EPA (channel binding),
the probe resolves ``web_enrollment_enabled=False`` (the NTLM relay is
defeated), so no ESC8 edge is emitted — the hardened, recommended CA state has
no residual weakness to report. HTTP web enrollment is EPA-agnostic and keeps
``web_enrollment_enabled=True``.

The edge source is the well-known Authenticated Users SID (``S-1-5-11``): the
NTLM relay only requires the coerced/authenticating principal to hold ANY valid
domain credential, which is cross-forest capable (a trusted-forest authenticated
user is also a member of Authenticated Users of the target realm). Sourcing the
edge from the domain-local Domain Users group would silently drop that
cross-forest relay surface. The Authenticated Users node is guaranteed present
in the graph — the collector injects every well-known SID node before
persistence — so the edge always resolves and renders in tactical findings.
"""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._well_known import (
    AUTHENTICATED_USERS_SID,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc8(
    *,
    ca_node: CollectorNode,
    domain: str,
    web_enrollment_enabled: bool = False,
) -> list[CollectorEdge]:
    if not web_enrollment_enabled:
        return []
    if ca_node.kind != "EnterpriseCA":
        return []

    return [
        CollectorEdge(
            source_object_id=AUTHENTICATED_USERS_SID,
            target_object_id=ca_node.object_id,
            relation="ADCSESC8",
            source="adcs_detector",
            method="adcs",
            notes={"requires": "domain_credentials_with_ntlm"},
        )
    ]
