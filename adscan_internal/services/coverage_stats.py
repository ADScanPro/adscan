"""Single source of truth for ADscan coverage headline figures.

This module computes the canonical counts that describe ADscan's coverage — the
number of Active Directory attack techniques, the number of reported finding
types, and the ADCS ESC class span — directly from the live product catalogs.
Every surface that quotes these numbers (the public README, the marketing site,
the coverage-matrix PDF, the docs) must derive them from here so they can never
drift apart.

Design notes:
- Like ``attack_step_catalog``, this module has **no top-level dependency on the
  ``pro`` package**. ``ATTACK_STEP_CATALOG`` is a shared service with no ``pro``
  imports; ``VULN_CATALOG`` lives under ``pro`` and is imported lazily inside
  :func:`build_technique_stats` so the module stays importable in contexts where
  ``pro`` is not needed.
- The exclusion rule (``context`` category entries are attack-graph plumbing, not
  customer-facing techniques) is defined ONCE here as ``STEP_CATEGORY_EXCLUDE``
  and re-used by ``scripts/export_coverage_matrix.py``.
"""

from __future__ import annotations

import re
from typing import Any

from adscan_internal.services.attack_step_catalog import ATTACK_STEP_CATALOG

# ``context`` entries are pure attack-graph pivots (membership / credential-reuse
# plumbing), not a detect/exploit technique a customer sees as coverage. This is
# the single definition of the exclusion rule; other modules import it from here.
STEP_CATEGORY_EXCLUDE = {"context"}

# ESC keys look like ``adcsesc1`` … ``adcsesc16a`` — pull the leading integer.
_ESC_KEY_PREFIX = "adcsesc"


def _adcs_esc_numbers(step_catalog: dict[str, Any]) -> list[int]:
    """Return the sorted, de-duplicated ESC class numbers present in the catalog.

    ADCS templates are catalog keys of the form ``adcsesc<N>[<variant>]``
    (e.g. ``adcsesc1``, ``adcsesc6a``). Variants collapse to their integer class.
    """
    numbers: set[int] = set()
    for key, entry in step_catalog.items():
        if getattr(entry, "category", None) in STEP_CATEGORY_EXCLUDE:
            continue
        if not key.startswith(_ESC_KEY_PREFIX):
            continue
        m = re.match(r"(\d+)", key[len(_ESC_KEY_PREFIX):])
        if m:
            numbers.add(int(m.group(1)))
    return sorted(numbers)


def _adcs_esc_span(step_catalog: dict[str, Any]) -> str:
    """Compute the ADCS ESC span string (e.g. ``ESC1–ESC17``) from the catalog.

    The span is ``ESC<min>–ESC<max>`` using an en-dash, matching the register the
    site and reports already use. Empty string when no ESC techniques exist.
    """
    numbers = _adcs_esc_numbers(step_catalog)
    if not numbers:
        return ""
    return f"ESC{numbers[0]}–ESC{numbers[-1]}"


def build_technique_stats() -> dict[str, Any]:
    """Assemble the canonical coverage figures from the live catalogs.

    Returns:
        A dict with:
          - ``technique_count``: number of attack-step techniques excluding the
            ``context`` category.
          - ``finding_count``: number of reported finding types (``VULN_CATALOG``).
          - ``by_category``: technique count per (non-excluded) category, sorted
            by category name for deterministic output.
          - ``adcs_esc_span``: ``ESC<min>–ESC<max>`` computed from the catalog.
    """
    # Lazy import: keeps the module free of a top-level ``pro`` dependency.
    from adscan_internal.pro.reporting.vuln_catalog import (  # noqa: PLC0415
        VULN_CATALOG,
    )

    by_category: dict[str, int] = {}
    supported_count = 0
    for entry in ATTACK_STEP_CATALOG.values():
        cat = getattr(entry, "category", None)
        if not cat or cat in STEP_CATEGORY_EXCLUDE:
            continue
        by_category[cat] = by_category.get(cat, 0) + 1
        # "supported" = ADscan executes the technique end to end (as opposed to
        # unsupported / policy_blocked, which are detected/mapped but not run).
        # This is the "supported AD techniques" figure the platform pages quote,
        # distinct from the total technique count.
        if getattr(entry, "support_kind", None) == "supported":
            supported_count += 1

    by_category = dict(sorted(by_category.items()))
    technique_count = sum(by_category.values())
    finding_count = len(VULN_CATALOG)
    adcs_esc_span = _adcs_esc_span(ATTACK_STEP_CATALOG)

    return {
        "technique_count": technique_count,
        "supported_technique_count": supported_count,
        "finding_count": finding_count,
        "by_category": by_category,
        "adcs_esc_span": adcs_esc_span,
    }


if __name__ == "__main__":  # pragma: no cover - manual inspection helper
    import json

    print(json.dumps(build_technique_stats(), indent=2, ensure_ascii=False))
