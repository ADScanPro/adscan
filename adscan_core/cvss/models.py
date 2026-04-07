"""Data models for the contextual CVSS scoring engine.

Three core types:
- CvssContext   — environmental signals extracted from a finding at evaluation time.
- CvssElevationRule — a single condition → elevated-score mapping for a vulnerability type.
- CvssResult    — the fully-computed output returned to callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CvssContext:
    """Environmental signals that can elevate a vulnerability's effective CVSS score.

    Attributes:
        has_tier_zero_targets: At least one Tier-0 (DA, KRBTGT, DC, EA…) entity
            is among the affected principals or attack-path targets.
        has_dc_targets: At least one Domain Controller is among the affected hosts.
        tier_zero_count: Exact number of Tier-0 affected entities (0 if unknown).
        dc_count: Exact number of affected DCs (0 if unknown).
        total_affected: Total number of affected entities (users + hosts).
        exploitation_confirmed: The scanner obtained concrete exploitation evidence
            (e.g. cracked hash, successful relay, working PoC).
    """

    has_tier_zero_targets: bool = False
    has_dc_targets: bool = False
    tier_zero_count: int = 0
    dc_count: int = 0
    total_affected: int = 0
    exploitation_confirmed: bool = False

    @classmethod
    def empty(cls) -> "CvssContext":
        """Return a context with no elevated signals (base scoring only)."""
        return cls()

    def is_elevated(self) -> bool:
        """Return True when any signal that could trigger elevation is active."""
        return (
            self.has_tier_zero_targets
            or self.has_dc_targets
            or self.exploitation_confirmed
        )


# Recognised condition identifiers — checked in priority order.
CONDITION_TIER_ZERO = "has_tier_zero_targets"
CONDITION_DC_TARGETS = "has_dc_targets"
CONDITION_EXPLOITATION = "exploitation_confirmed"


@dataclass
class CvssElevationRule:
    """A single condition-driven score elevation for a vulnerability type.

    Attributes:
        condition: Which ``CvssContext`` flag triggers this rule.
            One of: ``has_tier_zero_targets``, ``has_dc_targets``,
            ``exploitation_confirmed``.
        elevated_score: The contextual CVSS score that replaces the base score
            when the condition is True (must be > base_score).
        reason: Human-readable explanation shown in reports and the web UI.
    """

    condition: str
    elevated_score: float
    reason: str


@dataclass
class CvssResult:
    """Fully-computed CVSS scoring result for one finding instance.

    Attributes:
        base_score: Static base score from the vulnerability catalog.
        base_severity: Severity label derived from ``base_score``.
        effective_score: Contextual score when elevation applied; else ``base_score``.
        effective_severity: Severity label derived from ``effective_score``.
        cvss_vector: CVSS 3.1 Base vector string (e.g. ``CVSS:3.1/AV:N/AC:L/…``).
            ``None`` when no vector is defined for the vulnerability type.
        is_elevated: ``True`` when effective_score > base_score.
        elevation_reason: Human-readable explanation of what caused the elevation.
            ``None`` when the score was not elevated.
        context: The ``CvssContext`` that was evaluated (may be ``None`` when the
            result was computed without environmental context).
    """

    base_score: float
    base_severity: str
    effective_score: float
    effective_severity: str
    cvss_vector: Optional[str]
    is_elevated: bool
    elevation_reason: Optional[str]
    context: Optional[CvssContext] = field(default=None, repr=False)

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dict suitable for JSON storage or API responses."""
        return {
            "base_score": self.base_score,
            "base_severity": self.base_severity,
            "effective_score": self.effective_score,
            "effective_severity": self.effective_severity,
            "cvss_vector": self.cvss_vector,
            "is_elevated": self.is_elevated,
            "elevation_reason": self.elevation_reason,
        }
