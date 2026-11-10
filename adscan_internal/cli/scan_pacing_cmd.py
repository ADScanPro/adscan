"""The REPL scan-pace commands: ``set pacing``, ``set pacing.<setting>`` and ``show pacing``.

Usage (REPL)::

    set pacing <fragile|polite|normal|fast>
    set pacing.<setting> <value|unlimited|default>
    show pacing

The pace is a per-workspace REQUEST persisted in ``variables.json``; it is
resolved by :func:`adscan_core.scan_pacing.resolve_pacing` against the
workspace policy's ceiling and published for the engine on every change. A
request faster than the ceiling is refused here, before any scan starts, and the
refusal names the policy (pacing spec § 6.5).
"""

from __future__ import annotations

import difflib
import shlex
from dataclasses import replace
from typing import Any

from rich.markup import escape
from rich.table import Table
from rich.text import Text

from adscan_core.rich_output import (
    BRAND_COLORS,
    confirm_ask,
    print_error,
    print_info,
    print_instruction,
    print_panel,
    print_success,
    print_table,
    print_warning,
)
from adscan_core.scan_pacing import (
    COMPONENT_DEFAULT,
    COMPONENT_FAST,
    KNOBS_BY_KEY,
    LEVEL_DESCRIPTIONS,
    ORDERED_LEVELS,
    PACING_KNOBS,
    PacingConfigError,
    PacingLevel,
    PacingRequest,
    is_not_faster_than,
    validate_knob_value,
)
from adscan_core.scan_pacing.pacing_levels import slower_level

PACING_VARIABLE = "pacing"
KNOB_PREFIX = "pacing."
#: ``set pacing.profile <name>``: apply a saved pace profile (same as ``pace use``).
PROFILE_VARIABLE = "pacing.profile"

SHOW_USAGE = "Usage: show pacing"

_REQUEST_SOURCE_LABELS = {
    "repl": "set in the shell",
    "workspace": "saved in the workspace",
    "scan_config": "scan configuration",
    "cli": "command line",
    "policy": "scan policy",
    "profile": "saved pace profile",
    "default": "default",
}


def set_variable_names() -> list[str]:
    """Every ``set`` variable this module owns (tab completion)."""
    return [
        PACING_VARIABLE,
        PROFILE_VARIABLE,
        *(f"{KNOB_PREFIX}{knob.key}" for knob in PACING_KNOBS),
    ]


def level_names() -> list[str]:
    """Level names, slowest first."""
    return [level.value for level in ORDERED_LEVELS]


def knob_value_suggestions(key: str) -> list[str]:
    """Value hints for one knob (``on/off``, ``unlimited``, ``default``)."""
    knob = KNOBS_BY_KEY[key]
    values = ["on", "off"] if knob.kind.value == "bool" else []
    if knob.allow_unlimited:
        values.append("unlimited")
    values.append("default")
    return values


def set_value_suggestions(variable: str, shell: Any = None) -> list[str]:
    """Tab-completion values for one ``set pacing*`` variable."""
    if variable == PACING_VARIABLE:
        return level_names()
    if variable == PROFILE_VARIABLE:
        from adscan_internal.services.saved_pace_profiles import list_profiles  # noqa: PLC0415

        workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "") or None
        try:
            return [p.name for p in list_profiles(workspace_dir)]
        except Exception:  # noqa: BLE001 - completion never breaks the prompt
            return []
    key = variable[len(KNOB_PREFIX):]
    return knob_value_suggestions(key) if key in KNOBS_BY_KEY else []


def is_pacing_variable(variable: str) -> bool:
    """True for ``pacing`` and ``pacing.<setting>``."""
    return variable == PACING_VARIABLE or variable.startswith(KNOB_PREFIX)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------


def format_value(key: str, value: Any) -> str:
    """Human value of a knob, with its unit."""
    from adscan_internal.services.scan_controls import format_knob_value

    knob = KNOBS_BY_KEY[key]
    if value == COMPONENT_DEFAULT:
        return "standard"
    if value == COMPONENT_FAST:
        return "2x standard"
    text = format_knob_value(value)
    # Identity checks: ``0 in (True, False)`` is True in Python.
    if value is True or value is False or value == "unlimited" or not knob.unit:
        return text
    return f"{text} {knob.unit}" if knob.unit not in ("x", "%") else f"{text}{knob.unit}"


def _source_label(resolved: Any, knob_value: Any) -> str:
    level_label = LEVEL_DESCRIPTIONS[resolved.level].label
    if knob_value.capped:
        return knob_value.detail or "limited by the scan policy"
    if knob_value.source == "override":
        return _REQUEST_SOURCE_LABELS.get(knob_value.detail, knob_value.detail or "your setting")
    if knob_value.source == "policy_cap":
        return knob_value.detail or "limited by the scan policy"
    return f"{level_label} level"


def show_pacing(shell: Any) -> None:
    """Render ``show pacing``."""
    from adscan_core.scan_pacing import active_pacing

    from adscan_internal.cli.scan_policy_cmd import pacing_label

    resolved = getattr(shell, "scan_pacing", None) or active_pacing()
    level = resolved.level
    description = LEVEL_DESCRIPTIONS[level]
    head = Text()
    head.append("Scan pace: ", style="dim")
    head.append(pacing_label(resolved), style="bold")
    head.append(f"\n{description.description}\n")
    profile = getattr(getattr(resolved, "request", None), "profile", None)
    if profile is not None:
        head.append("\nSaved pace profile: ", style="dim")
        head.append(profile.name, style="bold")
        if profile.adjusted:
            head.append(", adjusted in this shell")
        head.append("\n")
    if resolved.level_capped:
        head.append(
            f"\nYou asked for {LEVEL_DESCRIPTIONS[resolved.requested_level].label}; the scan "
            "policy does not allow a faster pace than this one.\n",
            style="yellow",
        )
    print_panel(head, title="[bold]Scan pace[/bold]", expand=False)

    table = Table(
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        box=None,
        pad_edge=False,
    )
    table.add_column("Setting", no_wrap=True)
    table.add_column("Value", no_wrap=True)
    table.add_column("Source")
    table.add_column("What it controls", style="dim")
    for knob in PACING_KNOBS:
        value = resolved.knobs[knob.key]
        changed = value.source != "level" or value.capped
        style = "yellow" if value.capped else ("bold" if changed else "")
        table.add_row(
            Text(knob.key, style=style),
            Text(format_value(knob.key, value.value), style=style),
            Text(_source_label(resolved, value)),
            Text(knob.label),
        )
    print_table(table)
    for env_var in resolved.legacy_env:
        print_warning(
            f"{env_var} is set and changes this pace. It is deprecated; use "
            "'set pacing.<setting>' instead."
        )
    for env_var, reason in dict(resolved.legacy_env_ignored).items():
        print_warning(f"{env_var} is set but not applied: {escape(str(reason))}")
    print_instruction(
        "Change it with: set pacing <" + "|".join(level_names()) + "> | "
        "set pacing.<setting> <value|unlimited|default> | pace use <profile>"
    )


# ---------------------------------------------------------------------------
# set pacing / set pacing.<setting>
# ---------------------------------------------------------------------------


def _current_request(shell: Any) -> PacingRequest:
    from adscan_internal.services.scan_controls import (
        ATTR_POLICY,
        policy_pacing_request,
        workspace_pacing_request,
    )

    return (
        workspace_pacing_request(shell)
        or policy_pacing_request(getattr(shell, ATTR_POLICY, None))
        or PacingRequest()
    )


def _refusal(candidate: PacingRequest, ceiling: Any, *, what: str) -> str:
    name = getattr(getattr(ceiling, "policy", None), "name", "") or "the scan policy"
    allowed = LEVEL_DESCRIPTIONS[ceiling.level].label
    return (
        f"{what} is faster than policy '{name}' allows (at most {allowed}). "
        "The scan pace is unchanged."
    )


def _candidate_for_knob(current: PacingRequest, key: str, raw_value: str) -> PacingRequest:
    overrides = dict(current.overrides)
    sources = {k: current.source_of(k) for k in current.overrides}
    if raw_value.strip().lower() == "default":
        overrides.pop(key, None)
        sources.pop(key, None)
    else:
        overrides[key] = validate_knob_value(key, raw_value.strip())
        sources[key] = "repl"
    return PacingRequest(
        level=current.level,
        overrides=overrides,
        level_source=current.level_source,
        override_sources=sources,
        profile=_adjusted_profile(current),
    )


def _adjusted_profile(current: PacingRequest) -> Any:
    """The current request's profile reference, marked adjusted (a setting changed)."""
    profile = current.profile
    if profile is None or profile.adjusted:
        return profile
    return replace(profile, adjusted=True)


def handle_set_pacing(shell: Any, variable: str, value: str) -> None:
    """Handle ``set pacing <level>`` and ``set pacing.<setting> <value>``."""
    from adscan_internal.services.scan_controls import (
        ATTR_PACING_REQUEST,
        publish_pacing,
        session_pacing_ceiling,
    )

    from adscan_internal.cli.scan_policy_cmd import fast_pace_notice

    raw_value = str(value or "").strip()
    if variable == PROFILE_VARIABLE:
        from adscan_internal.cli.pace_profile_cmd import use_profile  # noqa: PLC0415

        use_profile(shell, raw_value)
        return
    current = _current_request(shell)
    if variable == PACING_VARIABLE:
        level = PacingLevel.coerce(raw_value)
        if level is None:
            print_error(
                f"Unknown pace '{escape(raw_value)}'. Use one of: {', '.join(level_names())}."
            )
            return
        candidate = PacingRequest(
            level=level,
            overrides=current.overrides,
            level_source="repl",
            override_sources={k: current.source_of(k) for k in current.overrides},
            profile=_adjusted_profile(current),
        )
        what = LEVEL_DESCRIPTIONS[level].label
    else:
        key = variable[len(KNOB_PREFIX):]
        if key not in KNOBS_BY_KEY:
            close = difflib.get_close_matches(key, list(KNOBS_BY_KEY), n=3, cutoff=0.5)
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            print_error(f"Unknown pace setting '{escape(key)}'.{hint} Run 'show pacing' to list them.")
            return
        try:
            candidate = _candidate_for_knob(current, key, raw_value)
        except PacingConfigError as exc:
            print_error(escape(str(exc)))
            return
        what = f"{KNOBS_BY_KEY[key].label} {format_value(key, candidate.overrides.get(key, ''))}"

    ceiling = session_pacing_ceiling(shell)
    # A setting change is judged on its own: if the level is already above the
    # ceiling (set before the policy was), the resolver caps the level anyway,
    # and refusing an unrelated, slower setting for it would be wrong.
    checked = candidate
    if ceiling is not None and variable != PACING_VARIABLE:
        checked = replace(candidate, level=slower_level(candidate.level, ceiling.level))
    if ceiling is not None and not is_not_faster_than(checked, ceiling):
        print_error(escape(_refusal(candidate, ceiling, what=what)))
        return
    if (
        variable == PACING_VARIABLE
        and candidate.level == PacingLevel.FAST
        and current.level != PacingLevel.FAST
        and not confirm_ask(f"{fast_pace_notice()} Switch to the Fast pace?", False)
    ):
        print_info("The scan pace is unchanged.")
        return

    setattr(shell, ATTR_PACING_REQUEST, candidate)
    resolved = publish_pacing(shell, candidate, ceiling)
    _save(shell)
    if variable == PACING_VARIABLE:
        description = LEVEL_DESCRIPTIONS[resolved.level]
        print_success(f"Scan pace set to {description.label}. {description.summary}")
        if candidate.overrides:
            count = len(candidate.overrides)
            print_info(
                f"Your {count} own setting{'s' if count != 1 else ''} still "
                f"appl{'y' if count != 1 else 'ies'}. Run 'show pacing' to review."
            )
    else:
        key = variable[len(KNOB_PREFIX):]
        knob_value = resolved.knobs[key]
        print_success(
            f"{KNOBS_BY_KEY[key].label}: {format_value(key, knob_value.value)} "
            f"({_source_label(resolved, knob_value)})."
        )


def _save(shell: Any) -> None:
    saver = getattr(shell, "save_workspace_data", None)
    if callable(saver) and getattr(shell, "current_workspace_dir", None):
        saver()
    else:
        print_warning("No workspace is open: the scan pace applies to this session only.")


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


def run_show_command(shell: Any, args: str) -> None:
    """Entry point of the REPL ``show`` verb (``show pacing``)."""
    try:
        tokens = shlex.split(args or "")
    except ValueError:
        tokens = []
    if tokens == [PACING_VARIABLE]:
        show_pacing(shell)
        return
    print_error(SHOW_USAGE)


__all__ = [
    "KNOB_PREFIX",
    "PACING_VARIABLE",
    "PROFILE_VARIABLE",
    "SHOW_USAGE",
    "format_value",
    "handle_set_pacing",
    "is_pacing_variable",
    "knob_value_suggestions",
    "level_names",
    "run_show_command",
    "set_value_suggestions",
    "set_variable_names",
    "show_pacing",
]
