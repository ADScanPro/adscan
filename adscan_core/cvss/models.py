"""Data models for ADscan severity evaluation.

This module defines the canonical taxonomy ADscan uses to score Active
Directory findings. The model intentionally separates three conceptually
distinct categories — Vulnerability, Chain Prerequisite and Posture —
because conflating them inside a single CVSS-like number is the root
cause of inflated severities that erode trust with technical buyers
(SOC / red teams / blue teams).

Categories
----------
- ``VULNERABILITY``: a finding with a real, intrinsic exploit. Has a
  formal CVSS Base vector (FIRST.org-aligned). Severity is honest both
  in absolute terms and after contextual elevation. Examples: ZeroLogon,
  PrintNightmare, ADCS template misconfigurations, LAPS attribute
  readable by non-admins, Kerberoastable Tier-0 service accounts.

- ``CHAIN_PREREQUISITE``: a primitive that does not break anything by
  itself but enables exploit chains when paired with a vulnerable
  relay/target/secondary condition. Has *no* formal CVSS Base. Reaches
  Critical only when ADscan has confirmed (or strongly evidenced) the
  chain endpoint. Examples: PetitPotam / DFSCoerce / MS-EFSRPC /
  PrinterBug coercion primitives, SMBv1 protocol enabled, WebDAV
  relay surface, LDAP signing not enforced.

- ``POSTURE``: absence of a control, hygiene gap, or accumulated debt.
  Has no formal CVSS Base. Maximum elevation stays inside Medium / Low-
  High territory because the finding documents *what is missing*, not
  *what is broken*. Examples: LAPS not deployed, stale enabled accounts,
  password-never-expires accounts, KRBTGT not rotated, RC4-only
  accounts, obsolete operating systems.

The calculator applies these rules per type:

- VULNERABILITY: base score from CVSS vector is the floor. Elevation
  rules can raise it further when contextual signals (Tier-0, DC,
  exploitation/relay confirmed) apply.
- CHAIN_PREREQUISITE: base score is intentionally Medium-grade
  (typically 5.3). Elevation steps: ``+CONDITION_DC_TARGETS`` raises to
  Medium-High; ``+CONDITION_RELAY_CONFIRMED`` raises to High;
  ``+CONDITION_EXPLOITATION`` raises to Critical.
- POSTURE: base score Medium (typically 5.5). Elevation rules can lift
  to High when affecting Tier-0 / DC, but never to Critical without an
  underlying VULNERABILITY finding co-existing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FindingType(str, Enum):
    """Canonical taxonomy of ADscan findings.

    Stored as a string (StrEnum) so it serializes naturally in JSON,
    Jinja templates, REST APIs and front-end TypeScript without
    additional encoding logic.
    """

    VULNERABILITY = "vulnerability"
    CHAIN_PREREQUISITE = "chain_prerequisite"
    POSTURE = "posture"

    @property
    def display_label(self) -> str:
        """Short human-readable label for badges and report headers."""
        return {
            FindingType.VULNERABILITY: "Vulnerability",
            FindingType.CHAIN_PREREQUISITE: "Chain Prerequisite",
            FindingType.POSTURE: "Posture",
        }[self]

    @property
    def short_label(self) -> str:
        """Compact label for dense list views and badges."""
        return {
            FindingType.VULNERABILITY: "VULN",
            FindingType.CHAIN_PREREQUISITE: "CHAIN",
            FindingType.POSTURE: "POSTURE",
        }[self]


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
        exploitation_confirmed: The scanner obtained concrete end-to-end
            exploitation evidence (e.g. cracked hash, dumped secret, working
            PoC, full relay-to-impact chain). Use this for outcomes ADscan
            has *materialised*, not for opportunities it has *identified*.
        relay_confirmed: A coercion / relay primitive has been chained to a
            confirmed vulnerable relay target *in the same workspace* (e.g.
            PetitPotam coerced a DC and a relay to ADCS Web Enrollment without
            EPA was demonstrated). Distinct from full exploitation_confirmed:
            relay_confirmed says "the chain endpoint exists and is reachable",
            exploitation_confirmed says "the chain ran end-to-end".

            NO PRODUCER SETS THIS TODAY. ``extract_context_from_details`` does
            not pass it when it builds the context, so every elevation rule
            keyed on ``CONDITION_RELAY_CONFIRMED`` is unreachable and a
            coercion primitive against a DC grades on ``has_dc_targets``
            instead. That is the conservative direction, so it understates
            rather than overclaims, and the field is kept because the
            distinction it draws is the right one. What it needs is the
            cross-finding signal "a vulnerable relay target exists in this
            workspace" (an ESC8 or an unsigned-LDAP finding elsewhere in the
            same scan), which no finding's own ``details`` carries: the
            extractor sees one finding at a time. Until a producer stamps it,
            the client-facing method section does NOT publish this condition,
            because an input with no effect is the one thing in a published
            method an auditor can falsify. Reachability is locked by
            ``tests/unit/core/test_severity_methodology_annex.py``; wire the
            producer and that test tells you to publish the bullet again.
    """

    has_tier_zero_targets: bool = False
    has_dc_targets: bool = False
    tier_zero_count: int = 0
    dc_count: int = 0
    total_affected: int = 0
    exploitation_confirmed: bool = False
    relay_confirmed: bool = False

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
            or self.relay_confirmed
        )


# Recognised condition identifiers — checked in priority order.
CONDITION_TIER_ZERO = "has_tier_zero_targets"
CONDITION_DC_TARGETS = "has_dc_targets"
CONDITION_EXPLOITATION = "exploitation_confirmed"
CONDITION_RELAY_CONFIRMED = "relay_confirmed"


@dataclass
class CvssElevationRule:
    """A single condition-driven score elevation for a vulnerability type.

    Attributes:
        condition: Which ``CvssContext`` flag triggers this rule.
            One of: ``has_tier_zero_targets``, ``has_dc_targets``,
            ``exploitation_confirmed``, ``relay_confirmed``.
        elevated_score: The ADscan contextual priority score applied when the
            condition is True (must be > base_score for the rule to fire).
        reason: Human-readable explanation shown in reports and the web UI.
    """

    condition: str
    elevated_score: float
    reason: str
