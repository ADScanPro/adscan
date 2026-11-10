"""How the AD Exposure Score is PRINTED, once, for every client surface.

The engine stamps ``overall_pct`` / ``proven_pct`` with one decimal
(``exposure_score_service``: ``round(self.overall_pct, 1)``), and every surface
a client reads prints it as a whole percentage: the report's page-2 numeral
(``{{ _exp|round|int }}%``), the engine's own explanation sentence
(``f"Exposure {overall:.0f}%"``), the progress report (``round(value)``), the
web Overview hero. A surface that forwards the raw decimal instead prints a
second number for the same measurement: the Enterprise scan comparison read
"99.8%" for the scan whose Overview, report and explanation all said "100%".

The rule is the report's, because the report's derivation wins (CLAUDE.md §
adscan_web): Python ``round`` to the nearest integer, ties to even. Jinja's
``round`` filter and ``:.0f`` both resolve ties that way, so the three engine
surfaces already agree; the web mirrors this function under a parity test
(``adscan_web/frontend/lib/exposure-display.ts``, fixture
``adscan_web/frontend/__tests__/fixtures/exposure-display-cases.json``).

A DIFFERENCE between two printed scores is taken between the printed values,
never rounded from the raw difference: a reader who sees "61% to 34%" checks
"27 points", and ``round(61.4 - 33.7)`` would print 28.

Dependency-light on purpose: the web backend imports it.
"""

from __future__ import annotations

from typing import Any, Optional


def exposure_display_pct(value: Any) -> Optional[int]:
    """Return an exposure percentage as the whole number a client reads.

    Args:
        value: The engine-stamped percentage (``overall_pct`` / ``proven_pct``),
            or anything else.

    Returns:
        The value rounded to the nearest integer (ties to even) and clamped to
        0-100, or ``None`` when the input is absent or not a finite number. An
        absent score stays absent: printing it as 0% would be a fabricated
        all-clear.
    """
    if value is None or isinstance(value, bool) or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in (float("inf"), float("-inf")):
        return None
    return max(0, min(100, int(round(number))))


def exposure_display_delta(from_value: Any, to_value: Any) -> Optional[int]:
    """Points moved between two printed scores, or ``None`` if either is absent."""
    start = exposure_display_pct(from_value)
    end = exposure_display_pct(to_value)
    if start is None or end is None:
        return None
    return end - start


__all__ = ["exposure_display_delta", "exposure_display_pct"]
