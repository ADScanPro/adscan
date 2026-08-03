"""ADscan severity engine.

This package exposes two distinct concepts:

- The formal CVSS Base score, computed from a finding's Base vector, for
  comparability and standards-aligned reporting. A finding without a vector has
  no CVSS Base and none may be presented for it.
- ADscan's own contextual priority score for environment-aware prioritization.

The client-facing names for both live in :mod:`adscan_core.cvss.labels`.
"""

from adscan_core.cvss.calculator import (
    AdscanPriorityResult,
    BaseCvssResult,
    FindingSeverityResult,
    compute_adscan_priority_result,
    compute_base_cvss_result,
    compute_finding_severity,
    extract_context_from_details,
    finding_severity_for_record,
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
from adscan_core.cvss.labels import (
    ADSCAN_PRIORITY_LABEL,
    ADSCAN_PRIORITY_SHORT_LABEL,
    CVSS_BASE_LABEL,
    PRIORITY_THRESHOLD_NOUN,
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
from adscan_core.cvss.vector_score import (
    parse_vector,
    score_from_vector,
)

__all__ = [
    "AdscanPriorityResult",
    "BaseCvssResult",
    "FindingSeverityResult",
    "compute_adscan_priority_result",
    "compute_base_cvss_result",
    "compute_finding_severity",
    "extract_context_from_details",
    "finding_severity_for_record",
    "make_finding_severity_fn",
    "make_global_cvss_base_fn",
    "make_global_finding_severity_fn",
    "make_global_report_priority_fn",
    "make_report_cvss_base_fn",
    "make_report_priority_fn",
    "CVSS_RULES",
    "VulnCvssDefinition",
    "get_vuln_cvss_definition",
    "ADSCAN_PRIORITY_LABEL",
    "ADSCAN_PRIORITY_SHORT_LABEL",
    "CVSS_BASE_LABEL",
    "PRIORITY_THRESHOLD_NOUN",
    "CONDITION_DC_TARGETS",
    "CONDITION_EXPLOITATION",
    "CONDITION_TIER_ZERO",
    "CvssContext",
    "CvssElevationRule",
    "format_score_label",
    "score_to_severity",
    "severity_to_min_score",
    "parse_vector",
    "score_from_vector",
]
