"""ESC12: CA key in a YubiHSM2 with the KSP password stored in the CA host registry.

Pure detector over the read-only check in
:mod:`adscan_internal.services.adcs.esc12_detection`. It emits the raw
``ADCSESC12`` edge ONLY for a confirmed result: the source is the CA host's own
computer object (whoever administers that host can use the CA signing key), the
target is the EnterpriseCA node. Persistence re-emits it with Domain Admins as
the target (``collector/persistence.py``, ``_ESC_TO_DOMAIN_ADMINS``), so a path
reads ``<principal> -AdminTo-> <CA host> -ADCSESC12-> Domain Admins``.

``not_applicable`` and ``not_checked`` emit nothing. ESC12 is an existence
condition, so its absence is never a ``closed_by_configuration`` edge, and a CA
that could not be read is recorded as not assessed by the detection service,
never as an edge.
"""

from __future__ import annotations

from typing import Any

from adscan_internal.services.collector.models import CollectorEdge, CollectorNode


def detect_esc12(
    *,
    ca_node: CollectorNode,
    check_result: Any,
    ca_host_object_id: str | None,
) -> list[CollectorEdge]:
    """Return the raw ``ADCSESC12`` edge for a confirmed check, else ``[]``.

    Args:
        ca_node: The EnterpriseCA node the check ran against.
        check_result: An ``Esc12CheckResult`` (or ``None`` when no check ran).
        ca_host_object_id: SID of the CA host's computer object. When it could
            not be resolved the edge is anchored on the CA node itself, so the
            confirmed finding is never dropped for a lookup gap.
    """
    if ca_node.kind != "EnterpriseCA" or check_result is None:
        return []
    if not getattr(check_result, "confirmed", False):
        return []
    notes = dict(check_result.edge_notes())
    source = str(ca_host_object_id or "").strip()
    if not source:
        source = ca_node.object_id
        notes["source_anchor"] = "certificate_authority"
    else:
        notes["source_anchor"] = "ca_host_computer"
    return [
        CollectorEdge(
            source_object_id=source,
            target_object_id=ca_node.object_id,
            relation="ADCSESC12",
            source="adcs_detector",
            method="adcs",
            notes=notes,
        )
    ]


__all__ = ["detect_esc12"]
