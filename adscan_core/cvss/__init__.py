"""ADscan severity engine.

This package exposes two distinct concepts:

- Formal CVSS Base output for comparability and standards-aligned reporting.
- ADscan contextual priority output for environment-aware prioritization.
"""

from adscan_core.cvss.calculator import (
    AdscanPriorityResult,
    BaseCvssResult,
    FindingSeverityResult,
    compute_adscan_priority_result,
    compute_base_cvss_result,
    compute_finding_severity,
    extract_context_from_details,
    make_finding_severity_fn,
    make_global_cvss_base_fn,
    make_global_finding_severity_fn,
    make_global_report_priority_fn,
    make_report_cvss_base_fn,
    make_report_priority_fn,
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
)
from adscan_core.cvss.severity_mapper import (
    format_score_label,
    score_to_severity,
    severity_to_min_score,
)

__all__ = [
    "AdscanPriorityResult",
    "BaseCvssResult",
    "FindingSeverityResult",
    "compute_adscan_priority_result",
    "compute_base_cvss_result",
    "compute_finding_severity",
    "extract_context_from_details",
    "make_finding_severity_fn",
    "make_global_cvss_base_fn",
    "make_global_finding_severity_fn",
    "make_global_report_priority_fn",
    "make_report_cvss_base_fn",
    "make_report_priority_fn",
    "CVSS_RULES",
    "VulnCvssDefinition",
    "get_vuln_cvss_definition",
    "CONDITION_DC_TARGETS",
    "CONDITION_EXPLOITATION",
    "CONDITION_TIER_ZERO",
    "CvssContext",
    "CvssElevationRule",
    "format_score_label",
    "score_to_severity",
    "severity_to_min_score",
]
