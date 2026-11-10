"""JSON schema of the pacing vocabulary, for every surface that renders it.

The web scan form, the REPL help and the docs render levels and knobs from this
one payload, so no surface keeps its own list. JSON-safe by construction.
"""

from __future__ import annotations

import importlib.util
from typing import Any

from adscan_core.scan_pacing.pacing_knobs import (
    COMPONENT_DEFAULT,
    COMPONENT_FAST,
    PACING_KNOBS,
    UNLIMITED,
)
from adscan_core.scan_pacing.pacing_levels import (
    DEFAULT_LEVEL,
    LEVEL_DESCRIPTIONS,
    ORDERED_LEVELS,
    PRODUCTION_SAFE_LEVEL,
)

#: Bump when the payload shape changes, so a cached web client can tell.
PACING_SCHEMA_VERSION = 1

#: The duration estimator (pacing spec § 7). Designed, not built yet: its model
#: is uncalibrated until the L3 run in § 8, and a client-facing "about N times
#: longer" must not ship on invented constants. Tracked in BACKLOG.md.
ESTIMATOR_MODULE = "adscan_core.scan_pacing.pacing_estimate"


def estimate_available() -> bool:
    """Whether this version carries the duration estimator.

    Surfaces ask before requesting an estimate, so a version without one shows
    no figure and makes no request that can only fail.
    """
    try:
        return importlib.util.find_spec(ESTIMATOR_MODULE) is not None
    except (ImportError, ValueError):
        return False


def pacing_schema() -> dict[str, Any]:
    """Return the levels and knobs as a JSON-safe mapping."""
    levels = []
    for level in ORDERED_LEVELS:
        copy = LEVEL_DESCRIPTIONS[level]
        levels.append(
            {
                "key": level.value,
                "rank": level.rank,
                "label": copy.label,
                "summary": copy.summary,
                "description": copy.description,
                "requires_confirmation": copy.requires_confirmation,
            }
        )
    knobs = []
    for knob in PACING_KNOBS:
        knobs.append(
            {
                "key": knob.key,
                "label": knob.label,
                "help": knob.help,
                "group": knob.group,
                "kind": knob.kind.value,
                "unit": knob.unit,
                "minimum": knob.minimum,
                "maximum": knob.maximum,
                "allow_unlimited": knob.allow_unlimited,
                "direction": knob.direction.value,
                "values": {level.value: knob.level_values[level] for level in ORDERED_LEVELS},
            }
        )
    return {
        "version": PACING_SCHEMA_VERSION,
        "default_level": DEFAULT_LEVEL.value,
        "production_safe_level": PRODUCTION_SAFE_LEVEL.value,
        "sentinels": {
            "component_default": COMPONENT_DEFAULT,
            "component_fast": COMPONENT_FAST,
            "unlimited": UNLIMITED,
        },
        "levels": levels,
        "knobs": knobs,
        "estimate_available": estimate_available(),
    }


__all__ = ["ESTIMATOR_MODULE", "PACING_SCHEMA_VERSION", "estimate_available", "pacing_schema"]
