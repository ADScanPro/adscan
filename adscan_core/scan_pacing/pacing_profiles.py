"""Saved pace profiles: a named pace a user tunes once and reuses with any policy.

A pace profile is ``{name, description, level, overrides}``, validated by the
pacing SSOT. It holds NO scope and NO safety setting: which checks run, the
execution mode, the environment and the password-attempt margin belong to the
scan policy, and a profile that carries one of them is refused.

Three rules this module owns (design:
``docs/superpowers/specs/2026-11-06-saved-pace-profiles-design.md``):

* **Precedence** (:func:`compose_pacing_request`): explicit per-run settings,
  then the chosen profile, then the policy's own pace, then the default. A
  profile REPLACES the policy's pace as the starting point; per-run settings
  layer per setting on top of it.
* **The clamp** (:func:`fit_to_ceiling`): the policy stays authoritative. A
  profile is held to the policy ceiling knob by knob by the one resolver
  (:func:`~adscan_core.scan_pacing.pacing_resolver.resolve_pacing`); this module
  only turns the resolver's verdict into a concrete request and the list of
  values it lowered, so the user can be told which and why.
* **The fingerprint** (:func:`pace_digest`): a stable digest of the effective
  pace (level and every effective setting), the same whichever surface reached
  it.

Stdlib only: the engine, the launcher and the web backend import it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from adscan_core.scan_pacing.pacing_knobs import (
    COMPONENT_DEFAULT,
    COMPONENT_FAST,
    KNOBS_BY_KEY,
    UNLIMITED,
    KnobScalar,
)
from adscan_core.scan_pacing.pacing_levels import (
    DEFAULT_LEVEL,
    LEVEL_DESCRIPTIONS,
    ORDERED_LEVELS,
    PacingLevel,
)
from adscan_core.scan_pacing.pacing_model import (
    LoweredValue,
    PaceProfileRef,
    PacingCeiling,
    PacingConfigError,
    PacingRequest,
    merge_requests,
    parse_overrides,
)
from adscan_core.scan_pacing.pacing_resolver import (
    ResolvedPacing,
    is_not_faster_than,
    resolve_pacing,
)

#: ``format`` marker a profile document carries, so a reader knows the shape.
PROFILE_DOCUMENT_FORMAT = "adscan.pace_profile"
PROFILE_DOCUMENT_VERSION = 1

#: Same limits as a scan policy, so a name valid in the CLI is valid on the web.
PROFILE_NAME_MAX = 255
PROFILE_DESCRIPTION_MAX = 2000

_DOCUMENT_KEYS = frozenset(
    {"format", "format_version", "name", "description", "revision", "level", "overrides", "pacing"}
)
#: Keys that belong to a scan policy. Named in the refusal so the user knows where they go.
_POLICY_ONLY_KEYS = frozenset(
    {
        "checks",
        "base",
        "enabled",
        "disabled",
        "new_checks",
        "execution_mode",
        "environment",
        "password_attempts",
        "settings",
        "ceiling",
    }
)


class PaceProfileError(PacingConfigError):
    """A pace profile is malformed, or carries something that is not a pace."""


@dataclass(frozen=True)
class PaceProfile:
    """A saved pace: a level plus explicit setting overrides, under a name."""

    name: str
    level: PacingLevel = DEFAULT_LEVEL
    overrides: Mapping[str, KnobScalar] = field(default_factory=dict)
    description: str = ""
    profile_id: str = ""
    revision: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "overrides", MappingProxyType(dict(self.overrides or {})))

    def ref(self, *, adjusted: bool = False, lowered: Iterable[LoweredValue] = ()) -> PaceProfileRef:
        """The identity a run records when it starts from this profile."""
        return PaceProfileRef(
            profile_id=self.profile_id,
            name=self.name,
            revision=self.revision or None,
            adjusted=adjusted,
            lowered=tuple(lowered),
        )

    def as_request(self) -> PacingRequest:
        """The profile as a request: every value sourced ``profile``, carrying its ref."""
        return PacingRequest(
            level=self.level,
            overrides=dict(self.overrides),
            level_source="profile",
            override_sources={key: "profile" for key in self.overrides},
            profile=self.ref(),
        )

    def pacing_block(self) -> dict[str, Any]:
        """``{level, overrides}``, the shape of a policy's or a scan's pace."""
        out: dict[str, Any] = {"level": self.level.value}
        if self.overrides:
            out["overrides"] = dict(self.overrides)
        return out

    def to_document(self) -> dict[str, Any]:
        """The saved document (YAML in the CLI, the export body on the web)."""
        out: dict[str, Any] = {
            "format": PROFILE_DOCUMENT_FORMAT,
            "format_version": PROFILE_DOCUMENT_VERSION,
            "name": self.name,
        }
        if self.description:
            out["description"] = self.description
        if self.revision:
            out["revision"] = self.revision
        out.update(self.pacing_block())
        return out


def normalise_profile_name(name: Any) -> str:
    """A validated profile name: trimmed, single-spaced, non-empty, within the limit."""
    token = " ".join(str(name or "").split())
    if not token:
        raise PaceProfileError("A pace profile needs a name.")
    if len(token) > PROFILE_NAME_MAX:
        raise PaceProfileError(f"A pace profile name has at most {PROFILE_NAME_MAX} characters.")
    if not any(ch.isalnum() for ch in token):
        raise PaceProfileError(
            f"'{token}' cannot be a pace profile name: use at least one letter or digit."
        )
    return token


def parse_pace_profile(data: Any, *, default_name: str = "") -> PaceProfile:
    """Parse and validate a profile document; raises :class:`PaceProfileError`.

    Accepts the flat shape (``level`` / ``overrides`` at the top) and a nested
    ``pacing: {level, overrides}`` block (a policy's pace or a scan config's).
    Refuses any key that belongs to a scan policy.
    """
    if not isinstance(data, Mapping):
        raise PaceProfileError("A pace profile must be a mapping.")
    keys = {str(k) for k in data}
    misplaced = sorted(keys & _POLICY_ONLY_KEYS)
    if misplaced:
        raise PaceProfileError(
            "A pace profile holds only a pace (a level and its settings). "
            f"{', '.join(misplaced)} belong{'s' if len(misplaced) == 1 else ''} in a scan policy."
        )
    unknown = sorted(keys - _DOCUMENT_KEYS)
    if unknown:
        raise PaceProfileError(
            f"Unknown key(s) in the pace profile: {', '.join(unknown)}. "
            f"Valid: {', '.join(sorted(_DOCUMENT_KEYS))}."
        )
    fmt = data.get("format")
    if fmt not in (None, PROFILE_DOCUMENT_FORMAT):
        raise PaceProfileError(f"Not a pace profile document (format {fmt!r}).")
    nested = data.get("pacing")
    if nested is not None:
        if "level" in data or "overrides" in data:
            raise PaceProfileError("Give the pace once: top-level level/overrides or a pacing block.")
        if not isinstance(nested, Mapping):
            raise PaceProfileError("'pacing' must be a mapping.")
        extra = sorted(str(k) for k in nested if str(k) not in ("level", "overrides"))
        if extra:
            raise PaceProfileError(
                f"A pace profile holds only a level and its settings, not {', '.join(extra)}."
            )
        pace: Mapping[str, Any] = nested
    else:
        pace = data
    level = PacingLevel.coerce(pace.get("level", DEFAULT_LEVEL.value))
    if level is None:
        valid = ", ".join(lv.value for lv in ORDERED_LEVELS)
        raise PaceProfileError(f"Unknown pace level {pace.get('level')!r}. Valid: {valid}.")
    try:
        overrides = parse_overrides(pace.get("overrides"), where="pace profile overrides")
    except PacingConfigError as exc:
        raise PaceProfileError(str(exc)) from exc
    description = str(data.get("description") or "").strip()
    if len(description) > PROFILE_DESCRIPTION_MAX:
        raise PaceProfileError(
            f"A pace profile description has at most {PROFILE_DESCRIPTION_MAX} characters."
        )
    revision_raw = data.get("revision") or 0
    try:
        revision = int(revision_raw) if not isinstance(revision_raw, bool) else 0
    except (TypeError, ValueError) as exc:
        raise PaceProfileError("A pace profile revision must be an integer.") from exc
    return PaceProfile(
        name=normalise_profile_name(data.get("name") or default_name),
        level=level,
        overrides=overrides,
        description=description,
        revision=max(0, revision),
    )


# ---------------------------------------------------------------------------
# Precedence
# ---------------------------------------------------------------------------


def compose_pacing_request(
    *,
    policy: PacingRequest | None = None,
    profile: PaceProfile | PacingRequest | None = None,
    run: PacingRequest | None = None,
) -> PacingRequest:
    """The request a scan resolves, by precedence.

    1. ``run``: explicit per-run settings (``--pacing``, ``--pacing-set``, the
       REPL, the web form), layered per setting;
    2. ``profile``: the chosen saved profile (already fitted to the ceiling, or
       not), which REPLACES the policy's pace as the starting point;
    3. ``policy``: the policy's own pace;
    4. the default (Normal).

    The result is not yet clamped: pass it to ``resolve_pacing`` with the
    policy ceiling, which is the one clamp.
    """
    if isinstance(profile, PaceProfile):
        base = profile.as_request()
    elif isinstance(profile, PacingRequest):
        base = profile
    else:
        base = policy or PacingRequest()
    return merge_requests(base, run)


# ---------------------------------------------------------------------------
# The clamp, described
# ---------------------------------------------------------------------------


def _ceiling_knob_values(ceiling: PacingCeiling) -> Mapping[str, Any]:
    resolved = resolve_pacing(ceiling.as_request(), env={})
    return {key: knob.value for key, knob in resolved.knobs.items()}


def lowered_values(resolved: ResolvedPacing) -> tuple[LoweredValue, ...]:
    """Every value the policy ceiling lowered in ``resolved``: the level, then each setting.

    A description of what the resolver did, never a second clamp. ``allowed`` is
    the ceiling's own value for the setting.
    """
    if resolved.ceiling is None:
        return ()
    out: list[LoweredValue] = []
    if resolved.level_capped:
        out.append(
            LoweredValue("level", resolved.requested_level.value, resolved.level.value)
        )
    limits = _ceiling_knob_values(resolved.ceiling)
    for key, knob in resolved.knobs.items():
        if knob.capped:
            out.append(LoweredValue(key, knob.value, limits.get(key)))
    return tuple(out)


@dataclass(frozen=True)
class FittedPacing:
    """A request held to a ceiling, and what had to be lowered to get there."""

    request: PacingRequest
    lowered: tuple[LoweredValue, ...] = ()

    @property
    def was_lowered(self) -> bool:
        return bool(self.lowered)


def fit_to_ceiling(
    request: PacingRequest,
    ceiling: PacingCeiling | None,
) -> FittedPacing:
    """Hold ``request`` to ``ceiling`` knob by knob, as a concrete request.

    The resolver decides what is too fast (:func:`lowered_values`); this writes
    that verdict back as a request a form or a workspace can store: the level
    lowered to the ceiling's, each capped setting set to the ceiling's value
    (an override the ceiling itself sets) or dropped back to the level's
    value. The result is re-checked, and falls back to the ceiling's own
    pace if it were ever still faster. The profile reference, when present,
    records what was lowered.
    """
    if ceiling is None:
        return FittedPacing(request=request)
    resolved = resolve_pacing(request, ceiling=ceiling, env={})
    lowered = lowered_values(resolved)
    if not lowered and is_not_faster_than(request, ceiling, env={}):
        return FittedPacing(request=request)
    profile = request.profile
    if profile is not None:
        profile = replace(profile, lowered=lowered)
    limits = _ceiling_knob_values(ceiling)
    overrides = dict(request.overrides)
    sources = {key: request.source_of(key) for key in request.overrides}
    dropped: set[str] = set()

    def _candidate() -> PacingRequest:
        return PacingRequest(
            level=resolved.level,
            overrides=overrides,
            level_source=request.level_source,
            override_sources=sources,
            profile=profile,
        )

    # Up to two passes, each re-judged by the resolver. A setting the ceiling
    # itself overrides takes the ceiling's value. A setting the request
    # overrode is first dropped back to the level's value: an override REPLACES
    # a component's own tuned value while a level only ever lowers it, so
    # writing the ceiling's knob value back is not equivalent for a fan-out. A
    # value that is still too fast after that (the level's own value is above
    # the ceiling's, e.g. Normal's unlimited port-scan rate under a Fast
    # ceiling of 800 packets per second) is set to the ceiling's value.
    for _pass in range(3):
        current = resolve_pacing(_candidate(), ceiling=ceiling, env={})
        capped = [key for key, knob in current.knobs.items() if knob.capped]
        if not capped:
            break
        for key in capped:
            if key in ceiling.overrides:
                overrides[key] = ceiling.overrides[key]
                sources[key] = request.source_of(key)
            elif key in overrides and key not in dropped:
                overrides.pop(key, None)
                sources.pop(key, None)
                dropped.add(key)
            elif _usable_override(key, limits.get(key)):
                overrides[key] = limits[key]
                sources[key] = request.source_of(key)
    fitted = _candidate()
    if not is_not_faster_than(fitted, ceiling, env={}):
        # Never expected; the safe answer is the ceiling's own pace.
        fallback = ceiling.as_request()
        fitted = replace(fallback, level_source=request.level_source, profile=profile)
    return FittedPacing(request=fitted, lowered=lowered)


def _usable_override(key: str, value: Any) -> bool:
    """True when ``value`` can be written as an override of ``key`` (not a sentinel)."""
    spec = KNOBS_BY_KEY.get(key)
    if spec is None or value is None or value in (COMPONENT_DEFAULT, COMPONENT_FAST):
        return False
    return value != UNLIMITED or spec.allow_unlimited


# ---------------------------------------------------------------------------
# Wording (client-facing; passes the adscan-writing gate)
# ---------------------------------------------------------------------------


def value_display(key: str, value: Any) -> str:
    """A setting or level value in words: ``Polite``, ``8 hosts``, ``No limit``."""
    if key == "level":
        level = PacingLevel.coerce(value)
        return LEVEL_DESCRIPTIONS[level].label if level is not None else str(value)
    if value is None or value in (COMPONENT_DEFAULT, COMPONENT_FAST):
        return "the standard value"
    if value == UNLIMITED:
        return "No limit"
    if isinstance(value, bool):
        return "On" if value else "Off"
    spec = KNOBS_BY_KEY.get(key)
    unit = spec.unit if spec is not None else ""
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if unit == "x":
        return f"{value}x"
    return f"{value} {unit}".strip()


def value_label(key: str) -> str:
    """``Pace level`` or the setting's client label."""
    if key == "level":
        return "Pace level"
    spec = KNOBS_BY_KEY.get(key)
    return spec.label if spec is not None else key


def lowered_lines(lowered: Iterable[Any]) -> list[str]:
    """``Hosts in parallel from 32 hosts to 8 hosts``, one per lowered value."""
    lines: list[str] = []
    for item in lowered or ():
        if isinstance(item, Mapping):
            key, requested, allowed = item.get("key"), item.get("requested"), item.get("allowed")
        else:
            key, requested, allowed = item.key, item.requested, item.allowed
        key = str(key or "")
        if not key:
            continue
        lines.append(
            f"{value_label(key)} from {value_display(key, requested)} to {value_display(key, allowed)}"
        )
    return lines


def lowered_clause(lowered: Iterable[Any]) -> str:
    """The lowered values as one clause: ``pace level from Normal to Polite and ...``."""
    lines = lowered_lines(lowered)
    if not lines:
        return ""
    items = [line[:1].lower() + line[1:] for line in lines]
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def lowered_count_phrase(lowered: Iterable[Any]) -> str:
    """``One value of the profile was`` / ``3 values of the profile were``."""
    count = len(lowered_lines(lowered))
    return "One value of the profile was" if count == 1 else f"{count} values of the profile were"


def lowered_sentence(lowered: Iterable[Any], *, policy_name: str = "") -> str:
    """One sentence naming what the policy lowered, or ``""`` when nothing was."""
    items = list(lowered or ())
    clause = lowered_clause(items)
    if not clause:
        return ""
    who = f"The scan policy '{policy_name}'" if policy_name else "The scan policy"
    what = lowered_count_phrase(items)
    return f"{who} allows less than this profile. {what} lowered to fit it, {clause}."


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def pace_digest(level: Any, knobs: Mapping[str, Any]) -> str:
    """``sha256:<hex>`` of an effective pace: its level and every effective setting.

    Covers values only, never names: the same pace reached from the CLI or the
    web, with or without a profile, has the same fingerprint.
    """
    lvl = PacingLevel.coerce(level)
    payload = json.dumps(
        {
            "level": lvl.value if lvl is not None else str(level or ""),
            "knobs": {
                str(k): v
                for k, v in sorted((knobs or {}).items())
                if isinstance(v, (str, int, float, bool))
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def short_pace_digest(digest: str) -> str:
    """``sha256:1a2b3c4d5e6f`` from a full digest."""
    algo, _, hexpart = str(digest or "").partition(":")
    return f"{algo}:{hexpart[:12]}" if hexpart else str(digest or "")


__all__ = [
    "FittedPacing",
    "PROFILE_DESCRIPTION_MAX",
    "PROFILE_DOCUMENT_FORMAT",
    "PROFILE_DOCUMENT_VERSION",
    "PROFILE_NAME_MAX",
    "PaceProfile",
    "PaceProfileError",
    "compose_pacing_request",
    "fit_to_ceiling",
    "lowered_clause",
    "lowered_count_phrase",
    "lowered_lines",
    "lowered_sentence",
    "lowered_values",
    "normalise_profile_name",
    "pace_digest",
    "parse_pace_profile",
    "short_pace_digest",
    "value_display",
    "value_label",
]
