"""Save-time limit on a policy's pace: never faster than the built-in it extends.

A scan policy's pace is the default AND the ceiling of every scan run under it,
so a saved policy may never be looser than the built-in it is based on
(Production-sensitive stays at most Polite, Audit at most Normal, Lab / CTF
up to Fast). This is the ONE validator for that rule, checked on the level AND
every setting. The CLI saves policies through it
(``saved_scan_policies.save_policy``) and the web policy create and update API
calls it too; a contract test locks both.

Per-scan paces and saved pace profiles are not checked here: they are clamped
per scan by the pacing resolver (``adscan_core.scan_pacing``), which tells the
user what it lowered. Only a POLICY's own pace is refused at save, because a
policy is what a written authorization names.

Stdlib + ``adscan_core`` only: the web backend imports it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from adscan_core.scan_pacing.pacing_knobs import KNOBS_BY_KEY
from adscan_core.scan_pacing.pacing_levels import LEVEL_DESCRIPTIONS, PacingLevel
from adscan_core.scan_pacing.pacing_model import (
    PacingCeiling,
    PacingConfigError,
    parse_pacing_request,
)
from adscan_core.scan_pacing.pacing_resolver import is_not_faster_than, resolve_pacing
from adscan_core.scan_policy.policy import BASE_PACING_LEVELS, BUILTIN_LABELS


@dataclass(frozen=True)
class PaceAboveBase:
    """A policy pace that is faster than its base built-in allows.

    Attributes:
        base: The base built-in key.
        limit: The fastest level the base allows.
        requested_level: The level the policy asked for.
        level_too_fast: True when the level itself is above the limit.
        settings: Keys of the settings above the limit, in knob order.
    """

    base: str
    limit: PacingLevel
    requested_level: PacingLevel
    level_too_fast: bool
    settings: tuple[str, ...]

    @property
    def base_label(self) -> str:
        return BUILTIN_LABELS.get(self.base, self.base)

    @property
    def message(self) -> str:
        """The refusal, naming the base, its limit and every value above it."""
        parts: list[str] = []
        if self.level_too_fast:
            parts.append(f"the {LEVEL_DESCRIPTIONS[self.requested_level].label} pace")
        parts.extend(KNOBS_BY_KEY[key].label for key in self.settings if key in KNOBS_BY_KEY)
        return (
            f"This pace is faster than the {self.base_label} policy it is based on allows "
            f"(at most {LEVEL_DESCRIPTIONS[self.limit].label}): {', '.join(parts)}. "
            "Choose slower values, or base the policy on a faster built-in."
        )


def base_pace_ceiling(base: str) -> PacingCeiling | None:
    """The pace the built-in ``base`` allows, or ``None`` when that base sets none."""
    level = PacingLevel.coerce(BASE_PACING_LEVELS.get(str(base or "")))
    return PacingCeiling(level=level) if level is not None else None


def pace_above_base(base: str, pacing: Mapping[str, Any] | None) -> PaceAboveBase | None:
    """``None`` when ``pacing`` stays within what ``base`` allows, else what is too fast.

    Args:
        base: The policy's base built-in key.
        pacing: The policy's own pace block (``{level, overrides}``), or ``None``
            (the base's own pace, always within it).

    Raises:
        PacingConfigError: When the block itself is malformed.
    """
    ceiling = base_pace_ceiling(base)
    if ceiling is None or not pacing:
        return None
    candidate = parse_pacing_request(dict(pacing), source="policy")
    if is_not_faster_than(candidate, ceiling, env={}):
        return None
    resolved = resolve_pacing(candidate, ceiling=ceiling, env={})
    return PaceAboveBase(
        base=str(base),
        limit=ceiling.level,
        requested_level=candidate.level,
        level_too_fast=resolved.level_capped,
        settings=tuple(key for key, knob in resolved.knobs.items() if knob.capped),
    )


__all__ = ["PaceAboveBase", "PacingConfigError", "base_pace_ceiling", "pace_above_base"]
