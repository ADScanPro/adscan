"""CVSS 3.1 score → severity label mapping.

Follows the official CVSS v3.1 severity ratings defined by FIRST:
https://www.first.org/cvss/v3.1/specification-document  (Section 5)

    None     0.0
    Low      0.1 – 3.9
    Medium   4.0 – 6.9
    High     7.0 – 8.9
    Critical 9.0 – 10.0
"""

from __future__ import annotations


# Ordered thresholds — first match wins (highest → lowest).
_THRESHOLDS: list[tuple[float, str]] = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]

_INFO = "info"


def score_to_severity(score: float) -> str:
    """Return the CVSS 3.1 severity label for *score*.

    Args:
        score: Numeric CVSS score in the range [0.0, 10.0].

    Returns:
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``, ``"info"``.
    """
    for threshold, label in _THRESHOLDS:
        if score >= threshold:
            return label
    return _INFO


def severity_to_min_score(severity: str) -> float:
    """Return the minimum CVSS 3.1 score for a severity label.

    Useful for ordering or validation.

    Args:
        severity: One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
            ``"info"``.

    Returns:
        Minimum score (floor of the severity band).
    """
    mapping = {
        "critical": 9.0,
        "high": 7.0,
        "medium": 4.0,
        "low": 0.1,
        "info": 0.0,
    }
    return mapping.get(severity.lower(), 0.0)


def format_score_label(score: float) -> str:
    """Return a display string like ``"8.8 (High)"`` for reports and UIs.

    Args:
        score: Numeric CVSS score.

    Returns:
        Formatted string with score and severity label.
    """
    severity = score_to_severity(score)
    return f"{score:.1f} ({severity.capitalize()})"
