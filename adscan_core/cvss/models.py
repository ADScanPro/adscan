"""Data models for ADscan severity evaluation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CvssContext:
    """Environmental signals that can elevate ADscan contextual priority.

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
        elevated_score: The ADscan contextual priority score applied when the
            condition is True (must be > base_score).
        reason: Human-readable explanation shown in reports and the web UI.
    """

    condition: str
    elevated_score: float
    reason: str
