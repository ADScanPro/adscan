"""Pacing data model and the one validator every surface uses.

``parse_pacing_block`` is shared by the engine's ``--scan-config`` parser, the
web backend's request schema and the scan-policy layer, so all three accept and
reject exactly the same input. The block shape::

    pacing:
      level: polite                 # fragile | polite | normal (default) | fast
      overrides:                    # any subset of the knob keys
        max_parallel_hosts: 4
        port_scan.max_rate_pps: 100     # dotted, or nested under port_scan:
        share_bandwidth_mibps: unlimited
      ceiling:                      # written by the backend from a saved policy
        level: polite
        overrides: {}
        policy: {id: "...", name: "...", revision: 3}
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Mapping

from adscan_core.scan_pacing.pacing_knobs import (
    KNOBS_BY_KEY,
    UNLIMITED,
    KnobKind,
    KnobScalar,
    KnobSpec,
)
from adscan_core.scan_pacing.pacing_levels import DEFAULT_LEVEL, ORDERED_LEVELS, PacingLevel


class PacingConfigError(ValueError):
    """Raised when a pacing block is malformed or carries an unknown or invalid value."""


#: Where a request (or one of its overrides) came from. Used for provenance only.
REQUEST_SOURCES: frozenset[str] = frozenset(
    {"default", "scan_config", "policy", "cli", "repl", "workspace", "profile"}
)

_BLOCK_KEYS = frozenset({"level", "overrides", "ceiling", "profile"})
_PROFILE_KEYS = frozenset({"id", "name", "revision", "adjusted", "lowered"})
_LOWERED_KEYS = frozenset({"key", "requested", "allowed"})
_CEILING_KEYS = frozenset({"level", "overrides", "policy"})
_POLICY_KEYS = frozenset({"id", "name", "revision"})


def _frozen(mapping: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return MappingProxyType(dict(mapping or {}))


@dataclass(frozen=True)
class PolicyRef:
    """Identity of the saved policy a ceiling came from (disclosure only, never logic)."""

    policy_id: str = ""
    name: str = ""
    revision: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the block shape."""
        out: dict[str, Any] = {}
        if self.policy_id:
            out["id"] = self.policy_id
        if self.name:
            out["name"] = self.name
        if self.revision is not None:
            out["revision"] = self.revision
        return out


@dataclass(frozen=True)
class LoweredValue:
    """One value of a saved pace profile the policy ceiling lowered.

    ``key`` is ``"level"`` for the pace level, else a knob key. ``requested`` is
    what the profile asked for and ``allowed`` what the policy permits (``None``
    when the setting falls back to the level's value).
    """

    key: str
    requested: KnobScalar | str
    allowed: KnobScalar | str | None

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the block shape."""
        return {"key": self.key, "requested": self.requested, "allowed": self.allowed}


@dataclass(frozen=True)
class PaceProfileRef:
    """Identity of the saved pace profile a request started from (disclosure only).

    ``adjusted`` is True when per-run settings changed the profile's values for
    this run; ``lowered`` lists every value the policy ceiling lowered.
    """

    profile_id: str = ""
    name: str = ""
    revision: int | None = None
    adjusted: bool = False
    lowered: tuple[LoweredValue, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the block shape (round-trips through :func:`parse_profile_ref`)."""
        out: dict[str, Any] = {"name": self.name}
        if self.profile_id:
            out["id"] = self.profile_id
        if self.revision is not None:
            out["revision"] = self.revision
        if self.adjusted:
            out["adjusted"] = True
        if self.lowered:
            out["lowered"] = [item.to_dict() for item in self.lowered]
        return out


def parse_profile_ref(raw: Any) -> PaceProfileRef | None:
    """Parse ``pacing.profile``; raises :class:`PacingConfigError` on a bad shape."""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise PacingConfigError("pacing.profile must be a mapping")
    _reject_unknown(raw, _PROFILE_KEYS, where="pacing.profile")
    name = str(raw.get("name") or "").strip()
    if not name:
        raise PacingConfigError("pacing.profile.name is required")
    revision = raw.get("revision")
    if revision is not None:
        if isinstance(revision, bool):
            raise PacingConfigError("pacing.profile.revision must be an integer")
        try:
            revision = int(revision)
        except (TypeError, ValueError) as exc:
            raise PacingConfigError("pacing.profile.revision must be an integer") from exc
    lowered: list[LoweredValue] = []
    for item in raw.get("lowered") or ():
        if not isinstance(item, Mapping):
            raise PacingConfigError("pacing.profile.lowered entries must be mappings")
        _reject_unknown(item, _LOWERED_KEYS, where="pacing.profile.lowered")
        key = str(item.get("key") or "").strip()
        if key != "level" and key not in KNOBS_BY_KEY:
            raise PacingConfigError(f"pacing.profile.lowered names an unknown setting {key!r}")
        lowered.append(LoweredValue(key, item.get("requested"), item.get("allowed")))
    return PaceProfileRef(
        profile_id=str(raw.get("id") or ""),
        name=name,
        revision=revision,
        adjusted=bool(raw.get("adjusted")),
        lowered=tuple(lowered),
    )


@dataclass(frozen=True)
class PacingRequest:
    """What someone asked for: a level plus explicit knob overrides."""

    level: PacingLevel = DEFAULT_LEVEL
    overrides: Mapping[str, KnobScalar] = field(default_factory=dict)
    level_source: str = "default"
    #: knob key -> source of that override (defaults to ``level_source``).
    override_sources: Mapping[str, str] = field(default_factory=dict)
    #: The saved pace profile this request started from, when one was chosen.
    profile: PaceProfileRef | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "overrides", _frozen(self.overrides))
        object.__setattr__(self, "override_sources", _frozen(self.override_sources))

    @property
    def is_default(self) -> bool:
        """True when this request asks for nothing beyond today's behaviour.

        A request that names a saved pace profile is never the default: the
        profile is a choice the disclosure states, even at the Normal pace.
        """
        return self.level == DEFAULT_LEVEL and not self.overrides and self.profile is None

    def source_of(self, key: str) -> str:
        """Return where the override for ``key`` came from."""
        return self.override_sources.get(key, self.level_source)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the block shape (level + flat dotted overrides)."""
        out: dict[str, Any] = {"level": self.level.value}
        if self.overrides:
            out["overrides"] = dict(self.overrides)
        if self.profile is not None:
            out["profile"] = self.profile.to_dict()
        return out


@dataclass(frozen=True)
class PacingCeiling:
    """The most aggressive pacing a saved policy allows."""

    level: PacingLevel
    overrides: Mapping[str, KnobScalar] = field(default_factory=dict)
    policy: PolicyRef | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "overrides", _frozen(self.overrides))

    def as_request(self) -> PacingRequest:
        """The ceiling expressed as a request (used to compute its per-parameter values)."""
        return PacingRequest(level=self.level, overrides=self.overrides, level_source="policy")

    def to_dict(self) -> dict[str, Any]:
        """Serialise to the block shape."""
        out: dict[str, Any] = {"level": self.level.value}
        if self.overrides:
            out["overrides"] = dict(self.overrides)
        if self.policy is not None and self.policy.to_dict():
            out["policy"] = self.policy.to_dict()
        return out


@dataclass(frozen=True)
class PacingBlock:
    """A parsed ``pacing`` block: the request and, when a policy applies, its ceiling."""

    request: PacingRequest = field(default_factory=PacingRequest)
    ceiling: PacingCeiling | None = None

    @property
    def is_default(self) -> bool:
        """True when the block changes nothing (no request beyond default, no ceiling)."""
        return self.request.is_default and self.ceiling is None

    def to_dict(self) -> dict[str, Any]:
        """Serialise back to the block shape (round-trips through ``parse_pacing_block``)."""
        out = self.request.to_dict()
        if self.ceiling is not None:
            out["ceiling"] = self.ceiling.to_dict()
        return out


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _level_from(raw: Any, *, where: str) -> PacingLevel:
    level = PacingLevel.coerce(raw)
    if level is None:
        valid = ", ".join(lv.value for lv in ORDERED_LEVELS)
        raise PacingConfigError(f"{where}: unknown pacing level {raw!r}. Valid: {valid}")
    return level


def validate_knob_value(key: str, raw: Any) -> KnobScalar:
    """Validate and normalise one knob value; raises :class:`PacingConfigError`.

    Accepts the knob's type (bools are not accepted as numbers), the string
    ``"unlimited"`` where the knob allows it, and numeric strings for numeric
    knobs (YAML and form inputs often arrive as strings).
    """
    spec: KnobSpec | None = KNOBS_BY_KEY.get(key)
    if spec is None:
        valid = ", ".join(sorted(KNOBS_BY_KEY))
        raise PacingConfigError(f"unknown pacing knob {key!r}. Valid: {valid}")
    if isinstance(raw, str) and raw.strip().lower() == UNLIMITED:
        if not spec.allow_unlimited:
            raise PacingConfigError(f"pacing knob {key!r} does not accept 'unlimited'")
        return UNLIMITED
    if spec.kind is KnobKind.BOOL:
        if isinstance(raw, bool):
            return raw
        token = str(raw).strip().lower()
        if token in {"true", "on", "yes", "1"}:
            return True
        if token in {"false", "off", "no", "0"}:
            return False
        raise PacingConfigError(f"pacing knob {key!r} expects on or off, got {raw!r}")
    if isinstance(raw, bool):
        raise PacingConfigError(f"pacing knob {key!r} expects a number, got {raw!r}")
    try:
        if spec.kind is KnobKind.INT:
            if isinstance(raw, float):
                if not raw.is_integer():
                    raise ValueError
                value: float | int = int(raw)
            else:
                value = int(str(raw).strip())
        else:
            value = float(str(raw).strip()) if not isinstance(raw, (int, float)) else float(raw)
    except (TypeError, ValueError) as exc:
        raise PacingConfigError(
            f"pacing knob {key!r} expects {spec.kind.value} ({spec.unit}), got {raw!r}"
        ) from exc
    if isinstance(value, float) and not math.isfinite(value):
        raise PacingConfigError(f"pacing knob {key!r} must be finite, got {raw!r}")
    if spec.minimum is not None and value < spec.minimum:
        raise PacingConfigError(
            f"pacing knob {key!r} must be at least {spec.minimum:g} {spec.unit}, got {value}"
        )
    if spec.maximum is not None and value > spec.maximum:
        raise PacingConfigError(
            f"pacing knob {key!r} must be at most {spec.maximum:g} {spec.unit}, got {value}"
        )
    return value


def _flatten_overrides(raw: Any, *, where: str) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise PacingConfigError(f"{where}: overrides must be a mapping")
    flat: dict[str, Any] = {}
    for key, value in raw.items():
        name = str(key).strip()
        if isinstance(value, Mapping):
            for sub_key, sub_value in value.items():
                flat[f"{name}.{str(sub_key).strip()}"] = sub_value
        else:
            flat[name] = value
    return flat


def parse_overrides(raw: Any, *, where: str = "pacing") -> dict[str, KnobScalar]:
    """Validate an overrides mapping (flat dotted keys or nested groups)."""
    return {
        key: validate_knob_value(key, value)
        for key, value in _flatten_overrides(raw, where=where).items()
    }


def _reject_unknown(mapping: Mapping[str, Any], allowed: frozenset[str], *, where: str) -> None:
    unknown = sorted(str(k) for k in mapping if str(k) not in allowed)
    if unknown:
        raise PacingConfigError(
            f"{where}: unknown key(s) {', '.join(unknown)}. Valid: {', '.join(sorted(allowed))}"
        )


def _parse_policy_ref(raw: Any) -> PolicyRef | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise PacingConfigError("pacing.ceiling.policy must be a mapping")
    _reject_unknown(raw, _POLICY_KEYS, where="pacing.ceiling.policy")
    revision = raw.get("revision")
    if revision is not None:
        if isinstance(revision, bool):
            raise PacingConfigError("pacing.ceiling.policy.revision must be an integer")
        try:
            revision = int(revision)
        except (TypeError, ValueError) as exc:
            raise PacingConfigError("pacing.ceiling.policy.revision must be an integer") from exc
    return PolicyRef(
        policy_id=str(raw.get("id") or ""),
        name=str(raw.get("name") or ""),
        revision=revision,
    )


def parse_pacing_request(raw: Any, *, source: str = "scan_config") -> PacingRequest:
    """Parse the request part of a block (``level`` + ``overrides``)."""
    if source not in REQUEST_SOURCES:
        raise PacingConfigError(f"unknown pacing request source {source!r}")
    if raw is None:
        return PacingRequest(level_source=source)
    if not isinstance(raw, Mapping):
        raise PacingConfigError("pacing must be a mapping")
    level = _level_from(raw.get("level", DEFAULT_LEVEL.value), where="pacing.level")
    return PacingRequest(
        level=level,
        overrides=parse_overrides(raw.get("overrides"), where="pacing.overrides"),
        level_source=source,
    )


def parse_pacing_block(raw: Any, *, source: str = "scan_config") -> PacingBlock:
    """Parse and validate a full ``pacing`` block; raises :class:`PacingConfigError`.

    ``None`` or an empty mapping yields the default block (today's behaviour).
    """
    if raw is None:
        return PacingBlock(request=PacingRequest(level_source="default"))
    if not isinstance(raw, Mapping):
        raise PacingConfigError("pacing must be a mapping")
    _reject_unknown(raw, _BLOCK_KEYS, where="pacing")
    request = (
        parse_pacing_request(
            {k: v for k, v in raw.items() if k in ("level", "overrides")}, source=source
        )
        if ("level" in raw or "overrides" in raw)
        else PacingRequest(level_source="default")
    )
    profile = parse_profile_ref(raw.get("profile"))
    if profile is not None:
        request = replace(request, profile=profile)
    ceiling_raw = raw.get("ceiling")
    ceiling: PacingCeiling | None = None
    if ceiling_raw is not None:
        if not isinstance(ceiling_raw, Mapping):
            raise PacingConfigError("pacing.ceiling must be a mapping")
        _reject_unknown(ceiling_raw, _CEILING_KEYS, where="pacing.ceiling")
        if "level" not in ceiling_raw:
            raise PacingConfigError("pacing.ceiling.level is required")
        ceiling = PacingCeiling(
            level=_level_from(ceiling_raw.get("level"), where="pacing.ceiling.level"),
            overrides=parse_overrides(ceiling_raw.get("overrides"), where="pacing.ceiling.overrides"),
            policy=_parse_policy_ref(ceiling_raw.get("policy")),
        )
    return PacingBlock(request=request, ceiling=ceiling)


def merge_requests(base: PacingRequest, layer: PacingRequest | None) -> PacingRequest:
    """Layer ``layer`` on top of ``base`` (resolution steps 2 then 3).

    A layer whose ``level_source`` is ``"default"`` does not change the level;
    its overrides replace the base's per knob, each keeping its own source.
    """
    if layer is None:
        return base
    profile = base.profile if layer.profile is None else layer.profile
    if (
        profile is not None
        and layer.profile is None
        and (layer.level_source != "default" or layer.overrides)
        and not profile.adjusted
    ):
        profile = replace(profile, adjusted=True)
    level = base.level
    level_source = base.level_source
    if layer.level_source != "default":
        level = layer.level
        level_source = layer.level_source
    overrides = dict(base.overrides)
    sources = {key: base.source_of(key) for key in base.overrides}
    for key, value in layer.overrides.items():
        overrides[key] = value
        sources[key] = layer.source_of(key)
    return PacingRequest(
        level=level,
        overrides=overrides,
        level_source=level_source,
        override_sources=sources,
        profile=profile,
    )


__all__ = [
    "LoweredValue",
    "PaceProfileRef",
    "PacingBlock",
    "PacingCeiling",
    "PacingConfigError",
    "PacingRequest",
    "PolicyRef",
    "REQUEST_SOURCES",
    "merge_requests",
    "parse_overrides",
    "parse_pacing_block",
    "parse_pacing_request",
    "parse_profile_ref",
    "validate_knob_value",
]
