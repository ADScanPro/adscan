"""Which domain the exposure hero describes when a scan covers several.

The hero of every client surface (the SAR page 2, its executive summary, the
run summary, the Enterprise Overview) names ONE domain: the most exposed. Each
surface used to pick it with its own ``max(...)``, and on a tie each fell back
to whatever order the domains happened to arrive in. With two domains both at
100%, the web hero named the one where nothing was executed ("Proven 0%")
beside a board line counting the executed route in the other, and the report
could name a different domain from the web off the same scan.

The rule, once: highest overall exposure first; on equal exposure, the domain
where more of that exposure is PROVEN. Validated exposure is the stronger
claim, and it is the one ADscan exists to make, so it is the one the hero leads
with. Any further key a caller has (blast radius, framework score) breaks the
remaining tie after these two.

Dependency-light on purpose: the web backend imports it, and so does the
report engine.
"""

from __future__ import annotations

from typing import Any, Mapping


def _pct(score: Mapping[str, Any] | None, key: str) -> float:
    if not isinstance(score, Mapping):
        return 0.0
    try:
        return float(score.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def hero_exposure_key(score: Mapping[str, Any] | None) -> tuple[float, float]:
    """Sort key for an ``exposure_score`` block: (overall %, proven %).

    Use with ``max``. A missing or malformed block sorts lowest.
    """
    return (_pct(score, "overall_pct"), _pct(score, "proven_pct"))


__all__ = ["hero_exposure_key"]
