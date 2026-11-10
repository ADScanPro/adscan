"""The pace step shared by the policy editor and the pace-profile editor.

A scan policy carries a pace (its default and its limit); a pace profile is a
pace alone. Both are edited the same way, in the REPL and from the host: pick a
level, then optionally adjust single settings. The only differences are what
the pace is held to while it is edited, which the caller passes in:

* a policy's pace may not exceed the built-in it is based on (``ceiling`` and
  ``validate``, from :func:`adscan_core.scan_policy.pace_limits.pace_above_base`);
* a profile is saved without a limit (``ceiling=None``, no extra validation) and
  is clamped per scan.

Every prompt goes through the centralized helpers, so an unattended run keeps
the pace it started from.
"""

from __future__ import annotations

from typing import Any, Callable

from rich.markup import escape

from adscan_core.rich_output import (
    confirm_ask,
    print_error,
    prompt_ask,
    questionary_select_index,
)
from adscan_core.scan_pacing import (
    KNOBS_BY_KEY,
    LEVEL_DESCRIPTIONS,
    ORDERED_LEVELS,
    PacingCeiling,
    PacingConfigError,
    PacingLevel,
)
from adscan_core.scan_policy.policy import ScanPolicyError, parse_policy_definition


def level_options(keep_label: str) -> list[str]:
    """``Keep <current>`` followed by one line per pace level."""
    return [f"Keep {keep_label}"] + [
        f"{LEVEL_DESCRIPTIONS[level].label}: {LEVEL_DESCRIPTIONS[level].summary}"
        for level in ORDERED_LEVELS
    ]


def knob_choice_text(
    knob: Any, level: PacingLevel, overrides: dict[str, Any], ceiling: PacingCeiling | None
) -> str:
    from adscan_internal.cli.scan_pacing_cmd import format_value

    default = knob.level_values.get(level)
    text = f"level gives {format_value(knob.key, default)}" if default is not None else "level default"
    if ceiling is not None:
        limit = knob.level_values.get(ceiling.level)
        if limit is not None:
            text += f", limit {format_value(knob.key, limit)}"
    if knob.key in overrides:
        text = f"set to {format_value(knob.key, overrides[knob.key])} ({text})"
    return text


def choose_pace(
    shell: Any,
    *,
    keep: dict[str, Any] | None,
    keep_label: str,
    title: str,
    ceiling: PacingCeiling | None = None,
    validate: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any] | None:
    """The level, then optionally single settings; returns ``{level, overrides?}``.

    Args:
        shell: The REPL shell, or ``None`` on the host (prompts resolve the same).
        keep: The pace the edit starts from; unattended, it is what comes back.
        keep_label: How that pace is named in the first option.
        title: The question over the level list.
        ceiling: The limit shown beside each setting (policies only).
        validate: Called with each candidate pace block; raises ``ValueError``
            to refuse it (the previous pace is kept and the reason shown).
    """
    options = level_options(keep_label)
    idx = questionary_select_index(title=title, options=options, default_idx=0, shell=shell)
    pacing: dict[str, Any] | None = dict(keep) if keep else None
    if idx is not None and idx != 0:
        pacing = {"level": ORDERED_LEVELS[idx - 1].value}
    if not confirm_ask("Adjust individual pace settings (hosts in parallel, request rate)?", False):
        return pacing
    level = PacingLevel.coerce((pacing or {}).get("level")) or PacingLevel.NORMAL
    overrides = dict((pacing or {}).get("overrides") or {})
    knobs = list(KNOBS_BY_KEY.values())
    while True:
        labels = [
            f"{k.label} ({k.key}): {knob_choice_text(k, level, overrides, ceiling)}" for k in knobs
        ] + ["Done"]
        pick = questionary_select_index(
            title="Setting to adjust", options=labels, default_idx=len(labels) - 1, shell=shell
        )
        if pick is None or pick == len(labels) - 1:
            break
        knob = knobs[pick]
        raw = prompt_ask(
            f"{knob.label} ({knob.unit or knob.kind.value}); 'default' returns to the level's value",
            default="default", shell=shell,
        )
        trial = dict(overrides)
        if str(raw).strip().lower() in ("", "default"):
            trial.pop(knob.key, None)
        else:
            trial[knob.key] = str(raw).strip()
        candidate = {"level": level.value, **({"overrides": trial} if trial else {})}
        try:
            parsed = parse_policy_definition({"pacing": candidate}).pacing or candidate
            if validate is not None:
                validate(parsed)
        except (ScanPolicyError, PacingConfigError, ValueError) as exc:
            print_error(escape(str(exc)))
            continue
        overrides = dict(parsed.get("overrides") or {})
    return {"level": level.value, **({"overrides": overrides} if overrides else {})}


__all__ = ["choose_pace", "knob_choice_text", "level_options"]
