"""ESC11 — ICPR RPC accepts plaintext requests (NTLM relay surface).

Probe-driven: needs ``enforce_encrypt_icertrequest`` from CA registry. Without
probe data no edges are emitted.

The edge source is the well-known Authenticated Users SID (``S-1-5-11``): the
NTLM relay only requires ANY valid domain credential, which is cross-forest
capable. Sourcing the edge from the domain-local Domain Users group would
silently drop that cross-forest relay surface. The Authenticated Users node is
guaranteed present in the graph (injected before persistence), so the edge
always resolves and renders in tactical findings.
"""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors._well_known import (
    AUTHENTICATED_USERS_SID,
)
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc11(
    *,
    ca_node: CollectorNode,
    domain: str,
    enforce_encrypt_icertrequest: bool = False,
) -> list[CollectorEdge]:
    if enforce_encrypt_icertrequest:
        return []
    if ca_node.kind != "EnterpriseCA":
        return []

    return [
        CollectorEdge(
            source_object_id=AUTHENTICATED_USERS_SID,
            target_object_id=ca_node.object_id,
            relation="ADCSESC11",
            source="adcs_detector",
            method="adcs",
            notes={"requires": "domain_credentials_with_ntlm"},
        )
    ]
