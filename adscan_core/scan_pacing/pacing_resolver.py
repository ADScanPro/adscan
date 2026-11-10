"""The one pacing resolver.

Resolution order (spec § 4.1), applied once per scan into an immutable
:class:`ResolvedPacing`:

1. Built-in default level (``normal``).
2. The request from the scan config (web form, YAML, or a saved policy's block).
3. CLI flags / REPL settings, layered on top (callers merge with
   :func:`~adscan_core.scan_pacing.pacing_model.merge_requests` before resolving).
4. Deprecated env vars, per component parameter, with their exact legacy parse.
5. Hard ranges (enforced when the request is parsed) and invariants.
6. The policy ceiling: per parameter, the slower of the value and the ceiling's.

Step 7 (the runtime strain safeguard) can only slow below this result and lives
in the runtime, not here.

At ``normal`` with no overrides and no ceiling, every parameter equals what its
component computes today, for every value of its legacy env var. That property
is the contract the identity tests lock.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from adscan_core.scan_pacing.pacing_consumers import (
    CONSUMERS,
    CONSUMERS_BY_ID,
    ConsumerSpec,
    OverrideMode,
    ParamRole,
    ParamSpec,
)
from adscan_core.scan_pacing.pacing_knobs import (
    COMPONENT_DEFAULT,
    COMPONENT_FAST,
    KNOBS_BY_KEY,
    LDAP_PAGE_SIZE,
    MAX_IN_FLIGHT_PER_HOST,
    MAX_PARALLEL_HOSTS,
    MAX_PARALLEL_PROBES,
    MAX_REQUESTS_PER_SECOND,
    MAX_RETRIES,
    PACING_KNOBS,
    PER_HOST_DELAY_MS,
    PORT_SCAN_HOST_TIMEOUT_MINUTES,
    PORT_SCAN_MAX_HOSTGROUP,
    PORT_SCAN_MAX_RATE_PPS,
    PORT_SCAN_SCAN_DELAY_MS,
    SHARE_BANDWIDTH_MIBPS,
    STRAIN_BACKOFF,
    TIMEOUT_MULTIPLIER,
    UNLIMITED,
    KnobDirection,
    KnobScalar,
)
from adscan_core.scan_pacing.pacing_levels import PacingLevel, slower_level
from adscan_core.scan_pacing.pacing_model import PacingCeiling, PacingRequest

#: Multiplier applied to DNS in-flight below ``normal`` (a resolver is built for
#: concurrent queries, so it gets more room than a host-level probe sweep).
RESOLVER_PROBE_MULTIPLIER = 4

#: nmap timing templates a ceiling below ``fast`` removes (they raise the send rate).
_FAST_TEMPLATES = frozenset({"-T4", "-T5"})

#: ``--min-hostgroup`` the ``fast`` level adds to the nmap command.
FAST_MIN_HOSTGROUP = 64


class _Behaviour:
    FANOUT = "fanout"
    RESOLVER = "resolver"
    SCALE = "scale"
    CAP = "cap"
    FLOOR_DELAY = "floor_delay"
    REPLACE = "replace"
    HOST_TIMEOUT = "host_timeout"
    FIXED = "fixed"


#: role -> (knob key or None, behaviour)
ROLE_KNOB: dict[ParamRole, tuple[str | None, str]] = {
    ParamRole.HOST_FANOUT: (MAX_PARALLEL_HOSTS, _Behaviour.FANOUT),
    ParamRole.PROBE_FANOUT: (MAX_PARALLEL_PROBES, _Behaviour.FANOUT),
    ParamRole.PER_HOST_IN_FLIGHT: (MAX_IN_FLIGHT_PER_HOST, _Behaviour.FANOUT),
    ParamRole.RESOLVER_IN_FLIGHT: (MAX_PARALLEL_PROBES, _Behaviour.RESOLVER),
    ParamRole.TIMEOUT: (TIMEOUT_MULTIPLIER, _Behaviour.SCALE),
    ParamRole.BUDGET: (TIMEOUT_MULTIPLIER, _Behaviour.SCALE),
    ParamRole.RATE: (MAX_REQUESTS_PER_SECOND, _Behaviour.CAP),
    ParamRole.BANDWIDTH: (SHARE_BANDWIDTH_MIBPS, _Behaviour.CAP),
    ParamRole.DELAY: (PER_HOST_DELAY_MS, _Behaviour.FLOOR_DELAY),
    ParamRole.PAGE_SIZE: (LDAP_PAGE_SIZE, _Behaviour.REPLACE),
    ParamRole.RETRIES: (MAX_RETRIES, _Behaviour.REPLACE),
    ParamRole.PORT_SCAN_HOST_TIMEOUT: (PORT_SCAN_HOST_TIMEOUT_MINUTES, _Behaviour.HOST_TIMEOUT),
    ParamRole.PORT_RATE: (PORT_SCAN_MAX_RATE_PPS, _Behaviour.CAP),
    ParamRole.PORT_HOSTGROUP: (PORT_SCAN_MAX_HOSTGROUP, _Behaviour.CAP),
    ParamRole.PORT_SCAN_DELAY: (PORT_SCAN_SCAN_DELAY_MS, _Behaviour.FLOOR_DELAY),
    ParamRole.ATTEMPTS: (None, _Behaviour.FIXED),
    ParamRole.FIXED: (None, _Behaviour.FIXED),
}


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParamValue:
    """One resolved component parameter and where its value came from.

    ``source`` is one of ``default`` (today's value, untouched), ``level``,
    ``override``, ``legacy_env``, ``policy_cap``.
    """

    value: Any
    source: str
    detail: str = ""


@dataclass(frozen=True)
class ComponentPacing:
    """The resolved parameters of one component. Index it by parameter name."""

    consumer_id: str
    values: Mapping[str, ParamValue]

    def __getitem__(self, name: str) -> Any:
        return self.values[name].value

    def get(self, name: str, default: Any = None) -> Any:
        """Return the parameter's value, or ``default`` when absent."""
        entry = self.values.get(name)
        return default if entry is None else entry.value

    def provenance(self, name: str) -> ParamValue:
        """Return the full :class:`ParamValue` for a parameter."""
        return self.values[name]


@dataclass(frozen=True)
class KnobValue:
    """The effective value of one knob, for display and disclosure."""

    key: str
    value: KnobScalar
    unit: str
    source: str
    detail: str = ""
    capped: bool = False


@dataclass(frozen=True)
class ResolvedPacing:
    """Immutable result of :func:`resolve_pacing`."""

    requested_level: PacingLevel
    level: PacingLevel
    knobs: Mapping[str, KnobValue]
    components: Mapping[str, ComponentPacing]
    request: PacingRequest
    ceiling: PacingCeiling | None = None
    #: deprecated env vars that changed at least one value, in registry order
    legacy_env: tuple[str, ...] = ()
    #: deprecated env vars that were set but not applied, with the reason
    legacy_env_ignored: Mapping[str, str] = field(default_factory=dict)
    #: ``consumer_id.param`` entries the policy ceiling lowered
    capped: tuple[str, ...] = ()

    @property
    def level_capped(self) -> bool:
        """True when the ceiling lowered the requested level."""
        return self.level != self.requested_level

    @property
    def is_default(self) -> bool:
        """True when nothing was requested, no ceiling applies and no legacy env acted."""
        return (
            self.request.is_default
            and self.ceiling is None
            and not self.legacy_env
            and not self.legacy_env_ignored
        )

    def component(self, consumer_id: str) -> ComponentPacing:
        """Return one component's resolved parameters; ``KeyError`` when unknown."""
        return self.components[consumer_id]


# ---------------------------------------------------------------------------
# Arithmetic per behaviour
# ---------------------------------------------------------------------------


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _scale(default: Any, factor: float) -> Any:
    if default is None or factor == 1.0:
        return default
    if isinstance(default, int) and not isinstance(default, bool):
        return int(math.ceil(default * factor))
    return round(float(default) * factor, 6)


def _cap(default: Any, knob_value: KnobScalar) -> Any:
    if knob_value == UNLIMITED or not _is_number(knob_value):
        return default
    if default is None:
        return knob_value
    if knob_value >= default:
        return default
    if isinstance(default, int) and not isinstance(default, bool):
        return max(1, int(knob_value))
    return knob_value


def _fanout(spec: ParamSpec, knob_value: KnobScalar, *, from_override: bool) -> Any:
    default = spec.default
    if knob_value == COMPONENT_DEFAULT:
        return default
    if knob_value == COMPONENT_FAST:
        if default is None:
            return None
        ceiling = KNOBS_BY_KEY[ROLE_KNOB[spec.role][0]].fast_ceiling or default * 2
        return max(default, min(default * 2, ceiling))
    if not _is_number(knob_value):
        return default
    value = int(knob_value)
    if from_override and spec.override_mode is OverrideMode.REPLACE:
        return value
    return value if default is None else min(default, value)


def _param_value(
    spec: ParamSpec,
    knob_value: KnobScalar | None,
    *,
    from_override: bool,
) -> Any:
    _knob, behaviour = ROLE_KNOB[spec.role]
    default = spec.default
    if behaviour == _Behaviour.FIXED or knob_value is None:
        return default
    if behaviour == _Behaviour.FANOUT:
        return _fanout(spec, knob_value, from_override=from_override)
    if behaviour == _Behaviour.RESOLVER:
        if knob_value == COMPONENT_FAST and _is_number(default):
            # Fast doubles the resolver's room like every other fan-out (500 -> 1000,
            # the in-flight value normal used before WP2b).
            return int(default) * 2
        if not _is_number(knob_value):
            return default
        return min(default, int(knob_value) * RESOLVER_PROBE_MULTIPLIER)
    if behaviour == _Behaviour.SCALE:
        return _scale(default, float(knob_value))
    if behaviour == _Behaviour.CAP:
        return _cap(default, knob_value)
    if behaviour == _Behaviour.FLOOR_DELAY:
        divisor = 1.0 if spec.unit == "ms" else 1000.0
        candidate = float(knob_value) / divisor
        if default is None:
            return candidate
        if candidate <= default:
            return default
        return int(candidate) if isinstance(default, int) else candidate
    if behaviour == _Behaviour.REPLACE:
        return int(knob_value) if isinstance(default, int) else knob_value
    if behaviour == _Behaviour.HOST_TIMEOUT:
        return f"{int(knob_value)}m"
    return default  # pragma: no cover - every behaviour is handled above


#: Direction of the roles no knob moves but a level or a ceiling can still lower.
_KNOBLESS_ROLE_DIRECTION: dict[ParamRole, KnobDirection] = {
    ParamRole.ATTEMPTS: KnobDirection.HIGHER_IS_FASTER,
}


def _faster(spec: ParamSpec, value: Any, other: Any) -> bool:
    """True when ``value`` is more aggressive than ``other`` for this parameter."""
    knob_key = ROLE_KNOB[spec.role][0]
    if knob_key is None:
        direction = _KNOBLESS_ROLE_DIRECTION.get(spec.role)
        if direction is None:
            return False
    else:
        direction = KNOBS_BY_KEY[knob_key].direction
    if direction is KnobDirection.NEUTRAL:
        return False
    if direction is KnobDirection.HIGHER_IS_SLOWER:
        if value is None or other is None:
            return False
        return value < other
    # higher is faster; None means unlimited (the fastest value)
    if other is None:
        return False
    if value is None:
        return True
    return value > other


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _knob_values(request: PacingRequest, level: PacingLevel) -> dict[str, tuple[KnobScalar, bool]]:
    """knob key -> (value, from_override) for the effective level."""
    out: dict[str, tuple[KnobScalar, bool]] = {}
    for knob in PACING_KNOBS:
        if knob.key in request.overrides:
            out[knob.key] = (request.overrides[knob.key], True)
        else:
            out[knob.key] = (knob.level_values[level], False)
    return out


def _has_port_scan_override(request: PacingRequest) -> bool:
    return any(key.startswith("port_scan.") or key == MAX_RETRIES for key in request.overrides)


def _compute_components(
    request: PacingRequest,
    level: PacingLevel,
    env: Mapping[str, str],
) -> tuple[dict[str, dict[str, ParamValue]], list[str], dict[str, str]]:
    knob_values = _knob_values(request, level)
    components: dict[str, dict[str, ParamValue]] = {}
    legacy_applied: list[str] = []
    legacy_ignored: dict[str, str] = {}
    for spec in CONSUMERS:
        values: dict[str, ParamValue] = {}
        for param in spec.params:
            knob_key = ROLE_KNOB[param.role][0]
            if knob_key is None:
                value, from_override = param.default, False
                entry = ParamValue(param.default, "default")
            else:
                knob_value, from_override = knob_values[knob_key]
                if not from_override and level is PacingLevel.NORMAL:
                    # Identity by construction: normal, untouched knob -> today's value.
                    value = param.default
                    entry = ParamValue(value, "default")
                else:
                    value = _param_value(param, knob_value, from_override=from_override)
                    if value == param.default and type(value) is type(param.default):
                        entry = ParamValue(value, "default")
                    else:
                        source = "override" if from_override else "level"
                        detail = request.source_of(knob_key) if from_override else level.value
                        entry = ParamValue(value, source, detail)
            bound = param.level_values.get(level)
            if bound is not None and _faster(param, value, bound):
                # The component's own pace at this level: it only ever slows down.
                value = bound
                entry = ParamValue(bound, "level", level.value)
            if spec.consumer_id == "portscan.nmap" and param.name == "timing_template":
                entry = _nmap_template_pre_env(level)
                value = entry.value
            if param.legacy_env is not None:
                raw = env.get(param.legacy_env.name)
                parsed = param.legacy_env.rule(raw)
                if parsed is not None:
                    if (
                        spec.consumer_id == "portscan.nmap"
                        and param.name == "timing_template"
                        and (level is not PacingLevel.NORMAL or _has_port_scan_override(request))
                    ):
                        legacy_ignored[param.legacy_env.name] = (
                            "a pacing level other than normal, or a port scan setting, "
                            "replaces the timing template"
                        )
                    elif parsed != value:
                        detail = param.legacy_env.name
                        if parsed == "-T5":
                            # Invariant: never -T5. The deprecated env var is clamped.
                            parsed = "-T4"
                            detail = f"{param.legacy_env.name} (-T5 clamped to -T4)"
                        entry = ParamValue(parsed, "legacy_env", detail)
                        if param.legacy_env.name not in legacy_applied:
                            legacy_applied.append(param.legacy_env.name)
            values[param.name] = entry
        components[spec.consumer_id] = values
    return components, legacy_applied, legacy_ignored


def _nmap_template_pre_env(level: PacingLevel) -> ParamValue:
    if level is PacingLevel.FAST:
        return ParamValue("-T4", "level", level.value)
    return ParamValue(None, "default")


def _apply_ceiling(
    components: dict[str, dict[str, ParamValue]],
    ceiling: PacingCeiling,
) -> list[str]:
    ceiling_components, _applied, _ignored = _compute_components(
        ceiling.as_request(), ceiling.level, env={}
    )
    label = _ceiling_label(ceiling)
    capped: list[str] = []
    for spec in CONSUMERS:
        values = components[spec.consumer_id]
        for param in spec.params:
            current = values[param.name]
            limit = ceiling_components[spec.consumer_id][param.name].value
            if spec.consumer_id == "portscan.nmap" and param.name == "timing_template":
                if current.value in _FAST_TEMPLATES and ceiling.level is not PacingLevel.FAST:
                    values[param.name] = ParamValue(None, "policy_cap", f"{current.value} removed by {label}")
                    capped.append(f"{spec.consumer_id}.{param.name}")
                continue
            if _faster(param, current.value, limit):
                values[param.name] = ParamValue(
                    limit, "policy_cap", f"requested {current.value}, limited by {label}"
                )
                capped.append(f"{spec.consumer_id}.{param.name}")
    return capped


def _ceiling_label(ceiling: PacingCeiling) -> str:
    policy = ceiling.policy
    if policy is not None and policy.name:
        if policy.revision is not None:
            return f"policy '{policy.name}' (revision {policy.revision})"
        return f"policy '{policy.name}'"
    return "the scan policy"


def _knob_view(
    request: PacingRequest,
    level: PacingLevel,
    ceiling: PacingCeiling | None,
    capped: list[str],
) -> dict[str, KnobValue]:
    knob_values = _knob_values(request, level)
    capped_knobs: set[str] = set()
    for item in capped:
        consumer_id, param_name = item.rsplit(".", 1)
        param = CONSUMERS_BY_ID[consumer_id].param(param_name)
        knob_key = ROLE_KNOB[param.role][0]
        if knob_key is not None:
            capped_knobs.add(knob_key)
    label = _ceiling_label(ceiling) if ceiling is not None else ""
    view: dict[str, KnobValue] = {}
    for knob in PACING_KNOBS:
        value, from_override = knob_values[knob.key]
        source = "override" if from_override else "level"
        detail = request.source_of(knob.key) if from_override else level.value
        is_capped = knob.key in capped_knobs
        if knob.key == STRAIN_BACKOFF and ceiling is not None:
            ceiling_value = (
                ceiling.overrides.get(STRAIN_BACKOFF)
                if STRAIN_BACKOFF in ceiling.overrides
                else knob.level_values[ceiling.level]
            )
            if ceiling_value is True and value is False:
                value, source, is_capped = True, "policy_cap", True
        view[knob.key] = KnobValue(
            key=knob.key,
            value=value,
            unit=knob.unit,
            source=source,
            detail=f"limited by {label}" if is_capped else detail,
            capped=is_capped,
        )
    return view


def resolve_pacing(
    request: PacingRequest | None = None,
    *,
    ceiling: PacingCeiling | None = None,
    env: Mapping[str, str] | None = None,
) -> ResolvedPacing:
    """Resolve a pacing request into the immutable per-component result.

    Args:
        request: The merged request (scan config, then CLI/REPL layered on top).
            ``None`` means today's default.
        ceiling: The policy ceiling, when a saved policy applies.
        env: Environment to read the deprecated env vars from; defaults to
            ``os.environ``. Tests pass an explicit mapping.

    Returns:
        A :class:`ResolvedPacing`. Never raises for a request that passed
        :func:`~adscan_core.scan_pacing.pacing_model.parse_pacing_block`.
    """
    request = request or PacingRequest()
    environ: Mapping[str, str] = os.environ if env is None else env
    level = request.level if ceiling is None else slower_level(request.level, ceiling.level)
    components, legacy_applied, legacy_ignored = _compute_components(request, level, environ)
    capped: list[str] = _apply_ceiling(components, ceiling) if ceiling is not None else []
    knobs = _knob_view(request, level, ceiling, capped)
    frozen_components = {
        consumer_id: ComponentPacing(consumer_id, MappingProxyType(values))
        for consumer_id, values in components.items()
    }
    return ResolvedPacing(
        requested_level=request.level,
        level=level,
        knobs=MappingProxyType(knobs),
        components=MappingProxyType(frozen_components),
        request=request,
        ceiling=ceiling,
        legacy_env=tuple(legacy_applied),
        legacy_env_ignored=MappingProxyType(legacy_ignored),
        capped=tuple(capped),
    )


def component_pacing(resolved: ResolvedPacing, consumer_id: str) -> ComponentPacing:
    """Return the resolved parameters of one component (the call every consumer makes)."""
    return resolved.components[consumer_id]


def is_not_faster_than(
    request: PacingRequest,
    ceiling: PacingCeiling,
    *,
    env: Mapping[str, str] | None = None,
) -> bool:
    """True when ``request`` stays within ``ceiling`` with nothing capped.

    The web greys out choices above a policy with it, and the REPL refuses
    ``set pacing`` beyond the workspace's policy before a scan starts.
    """
    resolved = resolve_pacing(request, ceiling=ceiling, env={} if env is None else env)
    strain = resolved.knobs[STRAIN_BACKOFF]
    return not resolved.level_capped and not resolved.capped and not strain.capped


def nmap_timing_flags(resolved: ResolvedPacing) -> str:
    """Build the nmap timing flags for a resolved pacing.

    At ``normal`` with no overrides this is exactly what
    ``adscan_internal.cli.nmap._nmap_timing_flags()`` returns today for the same
    environment: ``[-T<n> ]--max-retries R --host-timeout H``. Other levels
    append rate, batch, parallelism and per-host delay limits after those flags.
    Never ``--min-rate``; never ``-Pn`` (that is decided by the call site).
    """
    nmap = resolved.components["portscan.nmap"]
    flags = f"--max-retries {nmap['max_retries']} --host-timeout {nmap['host_timeout']}"
    template = nmap["timing_template"]
    if template:
        flags = f"{template} {flags}"
    extras: list[str] = []
    rate = nmap["max_rate_pps"]
    if rate is not None:
        extras.append(f"--max-rate {int(rate)}")
    hostgroup = nmap["max_hostgroup"]
    if hostgroup is not None:
        extras.append(f"--max-hostgroup {int(hostgroup)}")
    elif resolved.level is PacingLevel.FAST:
        extras.append(f"--min-hostgroup {FAST_MIN_HOSTGROUP}")
    parallelism = nmap["max_parallelism"]
    if parallelism is not None:
        extras.append(f"--max-parallelism {int(parallelism)}")
    delay = nmap["scan_delay_ms"]
    if delay:
        extras.append(f"--scan-delay {int(delay)}ms")
    if extras:
        flags = f"{flags} {' '.join(extras)}"
    return flags


def describe_component(spec: ConsumerSpec) -> dict[str, Any]:
    """Return a JSON-safe description of one component (docs, ``show pacing``)."""
    return {
        "id": spec.consumer_id,
        "description": spec.description,
        "location": spec.location,
        "params": [
            {
                "name": p.name,
                "default": p.default,
                "unit": p.unit,
                "knob": ROLE_KNOB[p.role][0],
                "legacy_env": p.legacy_env.name if p.legacy_env else None,
                "level_values": {lvl.value: v for lvl, v in p.level_values.items()},
            }
            for p in spec.params
        ],
    }


__all__ = [
    "ComponentPacing",
    "FAST_MIN_HOSTGROUP",
    "KnobValue",
    "ParamValue",
    "RESOLVER_PROBE_MULTIPLIER",
    "ROLE_KNOB",
    "ResolvedPacing",
    "component_pacing",
    "describe_component",
    "is_not_faster_than",
    "nmap_timing_flags",
    "resolve_pacing",
]
