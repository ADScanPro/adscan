"""Multidimensional confidence scoring for SecretIntelligenceService findings.

Replaces the binary stop-word filter with a continuous score so ALL findings are
surfaced and ranked rather than destructively suppressed. Operators see everything;
the score tells them where to focus first.

Phase A: default ScoringPolicy (AD baseline). Phase B will add a from_posture()
factory on ScoringPolicy — the slot is intentionally left empty here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from adscan_internal.services.secret_intelligence_service import FileTier

from adscan_internal.services.secret_dictionary import is_dictionary_word


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoringPolicy:
    """Inputs to :func:`score_finding`.

    Two construction paths:

    * Default (no AD context): ``ScoringPolicy()`` — Windows Server 2003
      defaults (min 7-8 chars, complexity required). Used when posture has
      not detected a real policy or the orchestrator chose not to consult it.
    * Posture-derived: ``ScoringPolicy.from_password_policy(snapshot)`` —
      built from the live AD ``minPwdLength`` and ``pwdProperties`` values.
      Recommended path for any production scan.

    The TTL/freshness of posture-derived policies is the caller's
    responsibility (see ``domain_posture._PASSWORD_POLICY_TTL``); this
    dataclass is a frozen value object and does not expire on its own.
    """

    min_length: int = 8              # AD default since Windows Server 2003
    require_complexity: bool = True  # AD default
    source: str = "default"          # "ad_default_domain_policy" when from posture

    @classmethod
    def from_password_policy(cls, snapshot: object) -> "ScoringPolicy":
        """Build a :class:`ScoringPolicy` from a ``PasswordPolicySnapshot``.

        Falls back to defaults when ``snapshot`` is ``None`` or lacks the
        required attributes. Accepts the snapshot as ``object`` to avoid a
        hard import dependency on ``domain_posture`` in this pure-logic module.

        Args:
            snapshot: A ``PasswordPolicySnapshot`` (or ``None``).

        Returns:
            A ``ScoringPolicy`` reflecting the snapshot, or the defaults.
        """
        if snapshot is None:
            return cls()
        try:
            return cls(
                min_length=int(getattr(snapshot, "min_length")),
                require_complexity=bool(getattr(snapshot, "require_complexity")),
                source=str(getattr(snapshot, "source", "ad_default_domain_policy")),
            )
        except (AttributeError, TypeError, ValueError):
            return cls()


# ---------------------------------------------------------------------------
# Breakdown
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoreBreakdown:
    """Per-dimension contributions. Their sum (clamped to [0.0, 1.0]) is the
    confidence_score. Surfaced in the CLI for operator transparency.

    Ranges:
        filename_anchor   : 0.00 – 0.30
        length_match      : 0.00 – 0.20
        complexity_match  : 0.00 – 0.20
        extraction_method : 0.00 – 0.20
        context_signal    : 0.00 – 0.10
        dictionary_penalty: -0.20 – 0.00
    """

    filename_anchor: float = 0.0
    length_match: float = 0.0
    complexity_match: float = 0.0
    extraction_method: float = 0.0
    context_signal: float = 0.0
    dictionary_penalty: float = 0.0

    @property
    def total(self) -> float:
        """Sum of all dimensions, clamped to [0.0, 1.0]."""
        raw = (
            self.filename_anchor
            + self.length_match
            + self.complexity_match
            + self.extraction_method
            + self.context_signal
            + self.dictionary_penalty
        )
        return max(0.0, min(1.0, raw))

    def compact_label(self) -> str:
        """Return a short breakdown string for CLI display.

        Example: ``F.30+L.20+C.20+E.15-D.20``
        """
        parts: list[str] = []
        if self.filename_anchor:
            parts.append(f"F.{int(self.filename_anchor * 100):02d}")
        if self.length_match:
            parts.append(f"L.{int(self.length_match * 100):02d}")
        if self.complexity_match:
            parts.append(f"C.{int(self.complexity_match * 100):02d}")
        if self.extraction_method:
            parts.append(f"E.{int(self.extraction_method * 100):02d}")
        if self.context_signal:
            parts.append(f"ctx.{int(self.context_signal * 100):02d}")
        if self.dictionary_penalty:
            parts.append(f"-D.{int(abs(self.dictionary_penalty) * 100):02d}")
        return "+".join(parts) if parts else "0"


# ---------------------------------------------------------------------------
# Complexity helper (private)
# ---------------------------------------------------------------------------

_RE_UPPER = re.compile(r"[A-Z]")
_RE_LOWER = re.compile(r"[a-z]")
_RE_DIGIT = re.compile(r"\d")
_RE_SYMBOL = re.compile(r"[^A-Za-z0-9]")


def _meets_complexity(value: str) -> bool:
    """Return True when value has upper, lower, and at least one digit or symbol."""
    return (
        bool(_RE_UPPER.search(value))
        and bool(_RE_LOWER.search(value))
        and (bool(_RE_DIGIT.search(value)) or bool(_RE_SYMBOL.search(value)))
    )


# ---------------------------------------------------------------------------
# Core scoring function
# ---------------------------------------------------------------------------


def score_finding(
    *,
    value: str,
    rule: str,
    tier: "FileTier",
    has_keyword_context: bool,
    policy: ScoringPolicy,
) -> ScoreBreakdown:
    """Pure deterministic scoring. No I/O, no side effects.

    Args:
        value: Extracted credential string.
        rule: Dotted rule identifier (e.g. ``"filename_aware/bare_string"``).
        tier: Filename-tier classification from the extractor.
        has_keyword_context: True when a narrative keyword/verb was found on a
            nearby line (multi-line context extraction sets this to True).
        policy: Scoring policy — AD password policy parameters.

    Returns:
        :class:`ScoreBreakdown` with per-dimension contributions. Call
        ``.total`` for the scalar confidence score.
    """
    from adscan_internal.services.secret_intelligence_service import FileTier as _FileTier  # noqa: PLC0415

    # --- Dimension 1: filename_anchor ---
    filename_anchor = 0.30 if tier == _FileTier.STRONG else 0.0

    # --- Dimension 2: length_match ---
    # Not negative for shorter passwords: legacy systems may predate the policy
    length_match = 0.20 if len(value) >= policy.min_length else 0.0

    # --- Dimension 3: complexity_match ---
    if not policy.require_complexity:
        # No policy requirement → free pass
        complexity_match = 0.20
    elif _meets_complexity(value):
        complexity_match = 0.20
    else:
        complexity_match = 0.0

    # --- Dimension 4: extraction_method ---
    if rule == "filename_aware/bare_string":
        extraction_method = 0.20
    elif rule.startswith("multilang/multi_line_context"):
        extraction_method = 0.15
    elif rule == "filename_aware/binary_flag":
        extraction_method = 0.0
    else:
        # Any other rule (inline narrative, future rules)
        extraction_method = 0.10

    # --- Dimension 5: context_signal ---
    context_signal = 0.10 if has_keyword_context else 0.0

    # --- Dimension 6: dictionary_penalty ---
    dictionary_penalty = -0.20 if is_dictionary_word(value) else 0.0

    return ScoreBreakdown(
        filename_anchor=filename_anchor,
        length_match=length_match,
        complexity_match=complexity_match,
        extraction_method=extraction_method,
        context_signal=context_signal,
        dictionary_penalty=dictionary_penalty,
    )


# ---------------------------------------------------------------------------
# CredSweeper custom-rule scoring
# ---------------------------------------------------------------------------

# Maps each rule name from custom_config.yaml to its extraction_method weight.
# STRONG-tier rules have a structural separator (keyword + : or =) — high anchor
# confidence, weight 0.20. MEDIUM-tier rules use a verb/adjective anchor with no
# separator — noisier context, weight 0.10. Keep this dict in sync with rule
# names in custom_config.yaml.
_CS_CUSTOM_RULE_EXTRACTION_WEIGHTS: dict[str, float] = {
    # STRONG-tier — keyword + structural separator
    "ES Contraseña Inline":               0.20,
    "CA Contrasenya Inline":              0.20,
    "DE Kennwort Inline":                 0.20,
    "FR Mot de passe Inline":             0.20,
    "PT Senha Inline":                    0.20,
    "IT Parola Chiave Inline":            0.20,
    "EUS Pasahitza Inline":               0.20,
    # MEDIUM-tier — verb/adjective anchor, no separator
    "ES/CA Password Changed Verb":        0.10,
    "ES/CA New Password Narrative":       0.10,
    "EN Password Changed Narrative":      0.10,
    "DE/FR/PT Password Changed Narrative": 0.10,
    # English baseline (structural but ML-filtered)
    "CMD Net Use":                        0.10,
    "DOC Password To":                    0.10,
    "DOC Password Inline":                0.10,
    # PowerShell key-encrypted SecureString blob — magic-anchored, near-certain
    "PS ConvertFrom-SecureString KeyEncrypted": 0.90,
}


def is_cs_custom_rule(rule_name: str) -> bool:
    """Return True when ``rule_name`` belongs to ADscan's custom_config.yaml rules."""
    return rule_name in _CS_CUSTOM_RULE_EXTRACTION_WEIGHTS


def score_cs_finding(
    *,
    value: str,
    rule_name: str,
    policy: ScoringPolicy,
) -> ScoreBreakdown:
    """Score a CredSweeper-extracted finding using the same dimensions as SI.

    CS findings differ from SI in two structural ways:

    * **No filename signal** — CredSweeper rules fire on content, not on
      filename; ``filename_anchor`` is always 0.0.
    * **Keyword always present** — a rule only fires when its keyword pattern
      matches; ``context_signal`` is always 0.10 (certain keyword context).

    All other dimensions (length, complexity, extraction_method, dictionary
    penalty) are computed identically to :func:`score_finding`.

    Args:
        value: Extracted credential string.
        rule_name: CredSweeper rule name from ``custom_config.yaml``.
        policy: AD password policy parameters.

    Returns:
        :class:`ScoreBreakdown` with per-dimension contributions.
        Call ``.total`` for the scalar confidence score.
    """
    extraction_method = _CS_CUSTOM_RULE_EXTRACTION_WEIGHTS.get(rule_name, 0.10)
    length_match = 0.20 if len(value) >= policy.min_length else 0.0

    if not policy.require_complexity:
        complexity_match = 0.20
    elif _meets_complexity(value):
        complexity_match = 0.20
    else:
        complexity_match = 0.0

    dictionary_penalty = -0.20 if is_dictionary_word(value) else 0.0

    return ScoreBreakdown(
        filename_anchor=0.0,
        length_match=length_match,
        complexity_match=complexity_match,
        extraction_method=extraction_method,
        context_signal=0.10,
        dictionary_penalty=dictionary_penalty,
    )


# ---------------------------------------------------------------------------
# Label helper
# ---------------------------------------------------------------------------


def confidence_label(score: float) -> str:
    """Map a continuous score to a human label for backward-compat with confidence: str.

    Args:
        score: Scalar confidence score in [0.0, 1.0].

    Returns:
        ``"strong"`` / ``"moderate"`` / ``"weak"``
    """
    if score >= 0.7:
        return "strong"
    if score >= 0.4:
        return "moderate"
    return "weak"


__all__ = [
    "ScoringPolicy",
    "ScoreBreakdown",
    "score_finding",
    "confidence_label",
]
