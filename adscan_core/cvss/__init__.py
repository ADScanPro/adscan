"""adscan_core.cvss — Contextual CVSS 3.1 scoring engine.

Public API
----------
The module exposes everything needed to compute, display, and persist
contextual CVSS scores across the CLI report generator, web ingestion
service, and any future consumer.

Typical usage
~~~~~~~~~~~~~

CLI report generator (per-domain ``cvss_fn``)::

    from adscan_core.cvss import make_contextual_cvss_fn

    for domain, domain_data in json_data.items():
        vulns = domain_data.get("vulnerabilities", {})
        cvss_fn = make_contextual_cvss_fn(vulns)
        valid = collect_valid_vulnerabilities(vulns, is_valid_fn=…, cvss_fn=cvss_fn)

CLI report generator (multi-domain ``cvss_fn``)::

    from adscan_core.cvss import make_global_cvss_fn

    cvss_fn = make_global_cvss_fn(json_data)
    render_executive_summary(document, json_data, …, cvss_fn=cvss_fn)

Web ingestion::

    from adscan_core.cvss import compute_contextual_score, extract_context_from_details

    context = extract_context_from_details(vuln_key, raw_details)
    result = compute_contextual_score(vuln_key, context, catalog_base_score=float(base_cvss))

    finding.cvss = str(result.base_score)
    finding.cvss_contextual = str(result.effective_score)
    finding.cvss_elevation_reason = result.elevation_reason
    finding.severity = Severity(result.effective_severity)

Direct result formatting::

    from adscan_core.cvss import format_score_label, score_to_severity

    label = format_score_label(8.8)          # → "8.8 (High)"
    sev   = score_to_severity(8.8)           # → "high"
"""

from adscan_core.cvss.calculator import (
    compute_contextual_score,
    extract_context_from_details,
    make_contextual_cvss_fn,
    make_global_cvss_fn,
)
from adscan_core.cvss.contextual_rules import (
    CVSS_RULES,
    VulnCvssDefinition,
    get_vuln_cvss_definition,
)
from adscan_core.cvss.models import (
    CONDITION_DC_TARGETS,
    CONDITION_EXPLOITATION,
    CONDITION_TIER_ZERO,
    CvssContext,
    CvssElevationRule,
    CvssResult,
)
from adscan_core.cvss.severity_mapper import (
    format_score_label,
    score_to_severity,
    severity_to_min_score,
)

__all__ = [
    # Calculator
    "compute_contextual_score",
    "extract_context_from_details",
    "make_contextual_cvss_fn",
    "make_global_cvss_fn",
    # Rules
    "CVSS_RULES",
    "VulnCvssDefinition",
    "get_vuln_cvss_definition",
    # Models
    "CONDITION_DC_TARGETS",
    "CONDITION_EXPLOITATION",
    "CONDITION_TIER_ZERO",
    "CvssContext",
    "CvssElevationRule",
    "CvssResult",
    # Severity helpers
    "format_score_label",
    "score_to_severity",
    "severity_to_min_score",
]
