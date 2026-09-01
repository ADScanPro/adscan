"""ADCS ESC vulnerability detection (Stage 5 Phases 2 + 3).

Pure-Python detectors that consume the cert template / CA nodes and ACL edges
collected by :class:`ADCSCollector` and emit ``ADCSESC{N}`` graph edges.
No network I/O happens here.
"""

from __future__ import annotations

from adscan_internal.services.collector.adcs_detectors.esc1 import detect_esc1
from adscan_internal.services.collector.adcs_detectors.esc2 import detect_esc2
from adscan_internal.services.collector.adcs_detectors.esc3 import (
    detect_esc3,
    detect_esc3_agent,
    detect_esc3_target,
)
from adscan_internal.services.collector.adcs_detectors.esc4 import detect_esc4
from adscan_internal.services.collector.adcs_detectors.esc5 import detect_esc5
from adscan_internal.services.collector.adcs_detectors.esc6 import detect_esc6
from adscan_internal.services.collector.adcs_detectors.esc7 import detect_esc7
from adscan_internal.services.collector.adcs_detectors.esc8 import detect_esc8
from adscan_internal.services.collector.adcs_detectors.esc9 import detect_esc9
from adscan_internal.services.collector.adcs_detectors.esc10 import detect_esc10
from adscan_internal.services.collector.adcs_detectors.esc11 import detect_esc11
from adscan_internal.services.collector.adcs_detectors.esc13 import detect_esc13
from adscan_internal.services.collector.adcs_detectors.esc14 import detect_esc14
from adscan_internal.services.collector.adcs_detectors.esc15 import detect_esc15
from adscan_internal.services.collector.models import CollectorEdge, CollectorNode
from adscan_core.rich_output import print_exception

__all__ = [
    "detect_esc1",
    "detect_esc2",
    "detect_esc3",
    "detect_esc3_agent",
    "detect_esc3_target",
    "detect_esc4",
    "detect_esc5",
    "detect_esc6",
    "detect_esc7",
    "detect_esc8",
    "detect_esc9",
    "detect_esc10",
    "detect_esc11",
    "detect_esc13",
    "detect_esc14",
    "detect_esc15",
    "detect_all",
    "detect_all_for_template",
    "detect_all_for_ca",
]


# Template-bound detector names (run once per CertTemplate). Resolved by
# attribute lookup on this module so tests can monkey-patch a single detector
# without touching the orchestrator wiring.
_TEMPLATE_DETECTOR_NAMES = (
    "detect_esc1",
    "detect_esc2",
    "detect_esc3",
    "detect_esc4",
    "detect_esc6",
    "detect_esc9",
    "detect_esc10",
    "detect_esc13",
    "detect_esc14",
    "detect_esc15",
)

# Issuance-bound detectors that require the template to be PUBLISHED on an
# Enterprise CA (its CN present in some CA's ``certificateTemplates``) to be a
# real, issuable weakness. Mirrors Certipy's single ``is_enabled`` gate wrapping
# ESC1/2/3/9/13/15 (find.py:1910). ESC6/10/14 are template-issuance conditions
# too, so an unpublished template cannot be issued through any of them either.
# An unpublished-but-vulnerable template object is NOT an executable path to
# compromise (the CA rejects the request with CERTSRV_E_UNSUPPORTED_CERT_TYPE),
# so emitting one of these edges is a false positive under the
# Exposure-Validation doctrine.
#
# ``detect_esc4`` is intentionally EXCLUDED: it is a template write-ACL
# configuration weakness (a principal can modify the template into ESC1),
# independent of whether the CA currently publishes it. Certipy likewise does
# not gate ESC4 on ``is_enabled``.
_PUBLICATION_GATED_DETECTOR_NAMES = frozenset(
    _TEMPLATE_DETECTOR_NAMES
) - {"detect_esc4"}


def _safe_run(detector, **kwargs) -> list[CollectorEdge]:
    try:
        return list(detector(**kwargs))
    except Exception as exc:  # noqa: BLE001
        from adscan_core.rich_output import print_info_debug
        from adscan_internal import telemetry

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[adcs_detector] {detector.__name__} failed: {exc}")
        return []


def detect_all_for_template(
    *,
    template_node: CollectorNode,
    template_acl_edges: list[CollectorEdge],
    domain: str,
    ca_editf_san2_enabled: bool = False,
    cert_mapping_methods: int = 0,
    strong_cert_binding_enforced: bool = False,
    oid_to_group_dn: dict[str, str] | None = None,
    oid_links_resolved: bool = False,
    published: bool = True,
) -> list[CollectorEdge]:
    """Run every template-bound ADCS detector for one CertTemplate.

    Returns the union of detector edges. A failing detector captures
    telemetry and is skipped — a single ESC analyzer crashing must never
    suppress findings from the others.

    The optional probe kwargs (``ca_editf_san2_enabled``,
    ``cert_mapping_methods``, ``strong_cert_binding_enforced``) gate the
    ESC6 and ESC10 detectors. Defaults emit no edges.

    ``oid_to_group_dn`` + ``oid_links_resolved`` gate ESC13: an edge is emitted
    only when a template issuance-policy OID resolves to a group in the map.
    ``oid_links_resolved`` distinguishes "query succeeded, no link exists"
    (ESC13 absent) from "query failed" (data gap); both suppress the edge, so a
    domain without ``msDS-OIDToGroupLink`` never yields a false ESC13 finding.

    ``published`` is the publication gate (mirrors Certipy's ``is_enabled``): a
    template is issuable only when its CN appears in some Enterprise CA's
    ``certificateTemplates`` list. When ``published`` is ``False`` the
    issuance-bound detectors (ESC1/2/3/6/9/10/13/14/15) are SKIPPED — an
    unpublished template cannot be requested from any CA, so any issuance ESC
    edge would be a false-positive executable path (the CA rejects the request
    with ``CERTSRV_E_UNSUPPORTED_CERT_TYPE``). ESC4 (template write-ACL) still
    runs unconditionally, because modifying an unpublished template's ACL and
    later publishing it is a real, publication-independent weakness. ``True``
    (default) preserves the pre-gate behaviour for all callers.
    """
    if template_node.kind != "CertTemplate":
        return []

    import sys

    module = sys.modules[__name__]
    edges: list[CollectorEdge] = []
    common = {
        "template_node": template_node,
        "template_acl_edges": template_acl_edges,
        "domain": domain,
    }
    extra_per_detector = {
        "detect_esc6": {"ca_editf_san2_enabled": ca_editf_san2_enabled},
        "detect_esc10": {
            "cert_mapping_methods": cert_mapping_methods,
            "strong_cert_binding_enforced": strong_cert_binding_enforced,
        },
        "detect_esc13": {
            "oid_to_group_dn": dict(oid_to_group_dn or {}),
            "oid_links_resolved": oid_links_resolved,
        },
    }
    for name in _TEMPLATE_DETECTOR_NAMES:
        if not published and name in _PUBLICATION_GATED_DETECTOR_NAMES:
            continue
        detector = getattr(module, name)
        kwargs = dict(common)
        kwargs.update(extra_per_detector.get(name, {}))
        edges.extend(_safe_run(detector, **kwargs))
    return edges


def detect_all_for_ca(
    *,
    ca_node: CollectorNode,
    ca_acl_edges: list[CollectorEdge],
    domain: str,
    web_enrollment_enabled: bool = False,
    enforce_encrypt_icertrequest: bool = False,
) -> list[CollectorEdge]:
    """Run every CA-bound ADCS detector for one EnterpriseCA.

    The optional probe kwargs gate the ESC8 (web enrollment) and ESC11
    (encrypted ICPR enforcement) detectors. With defaults, neither emits
    edges, preserving the no-false-positive contract when probes did not
    or could not run.
    """
    if ca_node.kind != "EnterpriseCA":
        return []

    edges: list[CollectorEdge] = []
    edges.extend(
        _safe_run(
            detect_esc7,
            ca_node=ca_node,
            ca_acl_edges=ca_acl_edges,
            domain=domain,
        )
    )
    edges.extend(
        _safe_run(
            detect_esc8,
            ca_node=ca_node,
            domain=domain,
            web_enrollment_enabled=web_enrollment_enabled,
        )
    )
    edges.extend(
        _safe_run(
            detect_esc11,
            ca_node=ca_node,
            domain=domain,
            enforce_encrypt_icertrequest=enforce_encrypt_icertrequest,
        )
    )
    return edges


# Backwards-compat alias for Phase 2 callers.
detect_all = detect_all_for_template
