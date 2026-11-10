"""Scan pacing: one SSOT for how hard ADscan works a client network.

Design: ``docs/superpowers/specs/2026-11-04-scan-pacing-ssot-design.md``.

Stdlib only and importable everywhere (host launcher, container engine, the
Windows bundle, the web backend), so every surface validates and renders pacing
through this package and none keeps its own copy of the levels or knobs.
"""

from __future__ import annotations

from adscan_core.scan_pacing.pacing_active import (
    active_pacing,
    clear_active_pacing,
    has_active_pacing,
    set_active_pacing,
)
from adscan_core.scan_pacing.pacing_consumers import (
    CONSUMERS,
    CONSUMERS_BY_ID,
    LEGACY_PACING_ENV,
    ConsumerSpec,
    ParamRole,
    ParamSpec,
)
from adscan_core.scan_pacing.pacing_knobs import (
    COMPONENT_DEFAULT,
    COMPONENT_FAST,
    KNOBS_BY_KEY,
    PACING_KNOBS,
    UNLIMITED,
    KnobDirection,
    KnobKind,
    KnobSpec,
)
from adscan_core.scan_pacing.pacing_levels import (
    DEFAULT_LEVEL,
    LEVEL_DESCRIPTIONS,
    ORDERED_LEVELS,
    PRODUCTION_SAFE_LEVEL,
    PacingLevel,
)
from adscan_core.scan_pacing.pacing_model import (
    LoweredValue,
    PaceProfileRef,
    PacingBlock,
    PacingCeiling,
    PacingConfigError,
    PacingRequest,
    PolicyRef,
    merge_requests,
    parse_pacing_block,
    parse_pacing_request,
    parse_profile_ref,
    validate_knob_value,
)
from adscan_core.scan_pacing.pacing_resolver import (
    ComponentPacing,
    KnobValue,
    ParamValue,
    ResolvedPacing,
    component_pacing,
    is_not_faster_than,
    nmap_timing_flags,
    resolve_pacing,
)
from adscan_core.scan_pacing.pacing_export import PACING_SCHEMA_VERSION, pacing_schema
from adscan_core.scan_pacing.pacing_profiles import (
    FittedPacing,
    PaceProfile,
    PaceProfileError,
    compose_pacing_request,
    fit_to_ceiling,
    lowered_sentence,
    lowered_values,
    pace_digest,
    parse_pace_profile,
)

__all__ = [
    "COMPONENT_DEFAULT",
    "COMPONENT_FAST",
    "CONSUMERS",
    "CONSUMERS_BY_ID",
    "ComponentPacing",
    "ConsumerSpec",
    "FittedPacing",
    "LoweredValue",
    "PaceProfile",
    "PaceProfileError",
    "PaceProfileRef",
    "DEFAULT_LEVEL",
    "KNOBS_BY_KEY",
    "KnobDirection",
    "KnobKind",
    "KnobSpec",
    "KnobValue",
    "LEGACY_PACING_ENV",
    "LEVEL_DESCRIPTIONS",
    "ORDERED_LEVELS",
    "PACING_KNOBS",
    "PACING_SCHEMA_VERSION",
    "PRODUCTION_SAFE_LEVEL",
    "PacingBlock",
    "PacingCeiling",
    "PacingConfigError",
    "PacingLevel",
    "PacingRequest",
    "ParamRole",
    "ParamSpec",
    "ParamValue",
    "PolicyRef",
    "ResolvedPacing",
    "UNLIMITED",
    "active_pacing",
    "clear_active_pacing",
    "component_pacing",
    "compose_pacing_request",
    "fit_to_ceiling",
    "lowered_sentence",
    "lowered_values",
    "pace_digest",
    "parse_pace_profile",
    "parse_profile_ref",
    "has_active_pacing",
    "is_not_faster_than",
    "merge_requests",
    "nmap_timing_flags",
    "pacing_schema",
    "parse_pacing_block",
    "parse_pacing_request",
    "resolve_pacing",
    "set_active_pacing",
    "validate_knob_value",
]
