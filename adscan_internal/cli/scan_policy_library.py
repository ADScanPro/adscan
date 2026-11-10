"""Saved scan policies on the command line: list, show, create, edit, save,
delete, export and import.

Two surfaces share this module:

* the REPL ``policy`` verb, for the library subcommands
  (``policy list|show <name>|create|edit|save|delete|export|import``), next to
  the workspace subcommands in :mod:`adscan_internal.cli.scan_policy_cmd`;
* the container command ``adscan policy``, which the launcher forwards verbatim
  (``POLICY_PASSTHROUGH`` in :mod:`adscan_core.cli_passthrough_spec`). It runs
  every library subcommand the REPL does, plus ``use`` (which needs
  ``--workspace``: the host has no session to apply a policy to).

Both call the one set of handlers below (``run_library_action``); the host only
differs in where its workspace comes from (``--workspace``) and in the stand-in
for the shell it passes (:class:`~adscan_internal.cli.library_common.HostWorkspaceShell`).

The store, the file format and the built-ins live in
:mod:`adscan_internal.services.saved_scan_policies`; this module parses,
prompts and renders. Every prompt goes through the centralized helpers, so a
non-interactive run resolves each one to its safe default and never blocks.

What a policy does depends on the run: an interactive scan (``start``, the
REPL) only uses its exclusions and confirms each attack step with the
operator; ``adscan ci --policy`` is the one consumer that runs its enabled
attack steps unattended. :data:`INTERACTIVE_SCOPE_NOTE` states it wherever a
policy is shown.
"""

from __future__ import annotations

import argparse
import shlex
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable

from rich.markup import escape
from rich.table import Table
from rich.text import Text

from adscan_core import telemetry
from adscan_core.rich_output import (
    BRAND_COLORS,
    confirm_ask,
    print_error,
    print_exception,
    print_info,
    print_instruction,
    print_panel,
    print_success,
    print_table,
    print_warning,
    prompt_ask,
    questionary_checkbox_values,
    questionary_select_index,
)
from adscan_core.scan_pacing import (
    KNOBS_BY_KEY,
    LEVEL_DESCRIPTIONS,
    ORDERED_LEVELS,
    PacingCeiling,
    PacingConfigError,
    PacingLevel,
    PacingRequest,
)
from adscan_core.scan_policy.families import FAMILIES, FAMILIES_BY_ID
from adscan_core.scan_policy.pace_limits import base_pace_ceiling, pace_above_base
from adscan_core.scan_policy.model import (
    KIND_DETECTION,
    KIND_TECHNIQUE,
    LOCKED_ALWAYS_RUNS,
    LOCKED_NEVER_EXECUTED,
    CheckDefinition,
)
from adscan_core.scan_policy.policy import (
    BUILTIN_LABELS,
    ENVIRONMENT_LABELS,
    ENVIRONMENTS,
    NEW_CHECKS_DISABLED,
    ScanPolicyDefinition,
    ScanPolicyError,
    UNKNOWN_THRESHOLD_VALUES,
    effective_environment,
    effective_pacing,
    effective_password_attempts,
    parse_environment,
    parse_password_attempts,
    parse_policy_definition,
    password_attempts_line,
)
from adscan_core.scan_policy.new_checks import acknowledge_new_checks, new_checks_since_saved
from adscan_core.scan_policy.settings import (
    SETTING_KEYS,
    PolicySettingError,
    parse_settings,
    settings_lines,
)
from adscan_core.scan_policy.registry import CheckRegistry, load_registry
from adscan_core.scan_policy.resolve import ResolvedScanPolicy
from adscan_core.scan_policy.summary import build_policy_safety_summary
from adscan_internal.cli.library_common import (
    add_scope_argument,
    require_workspace,
    resolve_save_scope,
    resolve_workspace_dir,
    write_export_file,
)
from adscan_internal.cli.pace_prompts import choose_pace
from adscan_internal.services import saved_scan_policies as store
from adscan_internal.services.saved_scan_policies import (
    SCOPE_BUILTIN,
    SCOPE_GLOBAL,
    SCOPE_LABELS,
    SCOPE_WORKSPACE,
    SavedPolicy,
    SavedPolicyError,
)

#: Stated wherever a policy is shown in an interactive surface.
INTERACTIVE_SCOPE_NOTE = (
    "Interactive scans only use a policy's exclusions; unattended execution of attack "
    "steps is part of adscan ci (PRO). Attack steps are confirmed one by one in an "
    "interactive scan; a policy only removes them here."
)

#: Subcommands the container ``adscan policy`` accepts.
CONTAINER_ACTIONS: tuple[str, ...] = (
    "list", "show", "create", "edit", "save", "delete", "export", "import", "review-new", "use",
)
#: Library subcommands the REPL ``policy`` verb accepts (beside show/use/exclude/include/clear).
REPL_LIBRARY_ACTIONS: tuple[str, ...] = (
    "list", "show", "create", "edit", "save", "delete", "export", "import", "review-new",
)
EXPORT_FORMATS: tuple[str, ...] = ("yaml", "json")

_SCOPE_DESCRIPTIONS = {
    SCOPE_BUILTIN: "built-in, read-only",
    SCOPE_WORKSPACE: "saved in this workspace",
    SCOPE_GLOBAL: "saved for all workspaces",
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def resolve_for_display(definition: ScanPolicyDefinition) -> ResolvedScanPolicy:
    """Resolve a definition for display (unknown ids are shown, not fatal)."""
    from adscan_internal.services.scan_controls import resolve_definition

    return resolve_definition(definition, strict=False)


def counts_line(resolved: ResolvedScanPolicy) -> str:
    """``N of M attack steps, K of L vulnerability checks`` for one resolved policy."""
    summary = build_policy_safety_summary(resolved)
    return (
        f"{summary['attack_steps_enabled']} of {summary['attack_steps_total']} attack steps, "
        f"{summary['vulnerability_checks_enabled']} of {summary['vulnerability_checks_total']} "
        "vulnerability checks"
    )


def pace_label(definition: ScanPolicyDefinition) -> str:
    """The pace a policy sets, as its level label (``Normal`` when it sets none)."""
    pacing = effective_pacing(definition) or {}
    level = PacingLevel.coerce(pacing.get("level")) or PacingLevel.NORMAL
    label = LEVEL_DESCRIPTIONS[level].label
    return f"{label} (adjusted)" if pacing.get("overrides") else label


#: The short form of the scope for the list column (the long one stays in ``show``).
_LIST_SCOPE_LABELS = {SCOPE_BUILTIN: "built-in", SCOPE_WORKSPACE: "workspace", SCOPE_GLOBAL: "all workspaces"}


def scope_label(policy: SavedPolicy) -> str:
    return _SCOPE_DESCRIPTIONS.get(policy.scope, policy.scope)


def saved_where(policy: SavedPolicy) -> str:
    """``for all workspaces`` / ``in this workspace``, for a sentence."""
    return "for all workspaces" if policy.scope == SCOPE_GLOBAL else "in this workspace"


def _check_state(check: CheckDefinition, resolved: ResolvedScanPolicy) -> Text:
    if check.locked_state == LOCKED_NEVER_EXECUTED:
        return Text("Never runs", style="dim")
    if check.locked_state == LOCKED_ALWAYS_RUNS:
        return Text("Always runs")
    if check.check_id in resolved.effective_ids:
        return Text("On", style="green")
    blocker = resolved.dependency_excluded.get(check.check_id)
    if blocker:
        return Text(f"Off, needs {blocker}", style="yellow")
    return Text("Off", style="dim")


def family_table(resolved: ResolvedScanPolicy, registry: CheckRegistry | None = None) -> Table:
    """Per-family counts of techniques and detections on (the policy overview)."""
    reg = registry or load_registry()
    table = Table(show_header=True, header_style=f"bold {BRAND_COLORS['info']}", box=None, pad_edge=False)
    table.add_column("Family")
    table.add_column("Techniques", justify="right")
    table.add_column("Detections", justify="right")
    for family in FAMILIES:
        checks = reg.checks_in_family(family.family_id)
        techniques = [c for c in checks if c.kind == KIND_TECHNIQUE]
        detections = [c for c in checks if c.kind == KIND_DETECTION]
        on_t = sum(1 for c in techniques if c.check_id in resolved.effective_ids)
        on_d = sum(1 for c in detections if c.check_id in resolved.effective_ids)
        all_on = on_t == len(techniques) and on_d == len(detections)
        style = "" if all_on else ("dim" if on_t + on_d == 0 else "yellow")
        table.add_row(
            Text(family.label, style=style),
            Text(f"{on_t} of {len(techniques)}" if techniques else "-", style=style),
            Text(f"{on_d} of {len(detections)}" if detections else "-", style=style),
        )
    return table


def family_checks_table(
    resolved: ResolvedScanPolicy, family_id: str, registry: CheckRegistry | None = None
) -> Table | None:
    """The techniques of one family with the registry's safety columns.

    Columns: whether the policy runs it, the change it makes to the environment
    and how it is rolled back, the lockout line, and the events it typically
    produces. The wording is the registry's (``CheckDefinition.safety_lines``),
    never reworded here.
    """
    reg = registry or load_registry()
    family = FAMILIES_BY_ID[family_id]
    techniques = [c for c in reg.checks_in_family(family_id) if c.kind == KIND_TECHNIQUE]
    if not techniques:
        return None
    table = Table(
        title=f"{family.label}",
        title_style="bold",
        title_justify="left",
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        show_lines=True,
        expand=True,
    )
    table.add_column("Check", ratio=4, overflow="fold")
    table.add_column("In this policy", ratio=2)
    table.add_column("Environment change and rollback", ratio=5)
    table.add_column("Lockout", ratio=3)
    table.add_column("Events", ratio=4)
    for check in techniques:
        lines = check.safety_lines()
        env = Text(lines["environment_change"])
        if check.rollback_detail:
            env.append("\n" + check.rollback_detail, style="dim")
        table.add_row(
            Text(f"{check.title}\n", style="bold").append(check.check_id, style="dim"),
            _check_state(check, resolved),
            env,
            Text(lines["lockout"]),
            Text(lines["events"]),
        )
    return table


def family_detections_text(
    resolved: ResolvedScanPolicy, family_id: str, registry: CheckRegistry | None = None
) -> Text | None:
    """One block for a family's detections: they only read collected data."""
    reg = registry or load_registry()
    detections = [c for c in reg.checks_in_family(family_id) if c.kind == KIND_DETECTION]
    if not detections:
        return None
    on = [c for c in detections if c.check_id in resolved.effective_ids]
    text = Text()
    text.append(f"{FAMILIES_BY_ID[family_id].label}: ", style="bold")
    text.append(f"{len(on)} of {len(detections)} detections on. ")
    text.append(detections[0].safety_lines()["environment_change"], style="dim")
    off = [c.title for c in detections if c.check_id not in resolved.effective_ids]
    if off:
        text.append("\nOff: ", style="dim")
        text.append(", ".join(off))
    return text


def print_family_detail(resolved: ResolvedScanPolicy, family_id: str, registry: CheckRegistry | None = None) -> None:
    """A family's techniques table, then its detections line."""
    table = family_checks_table(resolved, family_id, registry)
    if table is not None:
        print_table(table)
    detections = family_detections_text(resolved, family_id, registry)
    if detections is not None:
        print_panel(detections, expand=False)


# ---------------------------------------------------------------------------
# Rendering one policy
# ---------------------------------------------------------------------------


def render_policy(
    policy: SavedPolicy, *, with_checks: bool = False, interactive_note: bool = True
) -> ResolvedScanPolicy:
    """Print a policy: identity, pace, safety statement and the family overview."""
    resolved = resolve_for_display(policy.definition)
    definition = policy.definition
    head = Text()
    head.append(policy.name, style="bold")
    head.append(f"  ({scope_label(policy)})\n", style="dim")
    if policy.description:
        head.append(f"{policy.description}\n")
    if not policy.read_only:
        head.append("Based on: ", style="dim")
        head.append(f"{BUILTIN_LABELS.get(definition.base, definition.base)}\n")
    head.append("For: ", style="dim")
    head.append(f"{environment_label(definition)}, which sets the workspace type\n")
    head.append("Password attempts: ", style="dim")
    head.append(f"{password_attempts_label(definition)}\n")
    for line in settings_lines(definition):
        label, _, value = line.partition(": ")
        head.append(f"{label}: ", style="dim")
        head.append(f"{value}\n")
    head.append("Pace: ", style="dim")
    head.append(f"{pace_label(definition)}, also the fastest a scan under it may run\n")
    for label, text in pace_detail_lines(definition):
        head.append(f"  {label}: ", style="dim")
        head.append(f"{text}\n")
    head.append("Checks: ", style="dim")
    head.append(f"{counts_line(resolved)}\n")
    notice = new_checks_since_saved(definition, resolved=resolved)
    if notice is not None and not policy.read_only:
        head.append("New checks: ", style="dim")
        head.append(f"{notice.line}\n", style="yellow")
        head.append(f"Review them with: policy review-new {shlex.quote(policy.name)}\n", style="dim")
    if definition.disabled:
        head.append("Excluded: ", style="dim")
        head.append(", ".join(definition.disabled) + "\n")
    if definition.enabled:
        head.append("Included: ", style="dim")
        head.append(", ".join(definition.enabled) + "\n")
    head.append("\n")
    _summary = build_policy_safety_summary(resolved)
    head.append(" ".join([_summary["statement"], *_summary.get("revert_permission_lines", [])]))
    if interactive_note:
        head.append("\n\n")
        head.append(INTERACTIVE_SCOPE_NOTE, style="dim")
    print_panel(head, title="[bold]Scan policy[/bold]", expand=False)
    print_table(family_table(resolved))
    for message in resolved.warnings:
        print_warning(escape(message))
    for unknown in resolved.unknown_ids:
        print_warning(
            f"'{escape(unknown)}' is not a check this version of ADscan knows; a scan "
            "refuses this policy until it is fixed."
        )
    if with_checks:
        reg = load_registry()
        for family in FAMILIES:
            print_family_detail(resolved, family.family_id, reg)
    return resolved


def browse_policy(shell: Any, policy: SavedPolicy) -> None:
    """Show a policy, then let the operator open one family at a time."""
    resolved = render_policy(policy)
    reg = load_registry()
    families = [f for f in FAMILIES if reg.checks_in_family(f.family_id)]
    options = [
        f"{f.label}: {sum(1 for c in reg.checks_in_family(f.family_id) if c.check_id in resolved.effective_ids)}"
        f" of {len(reg.checks_in_family(f.family_id))} on"
        for f in families
    ] + ["Back"]
    while True:
        idx = questionary_select_index(
            title="Open a family to see each check and its safety",
            options=options,
            default_idx=len(options) - 1,
            shell=shell,
        )
        if idx is None or idx == len(options) - 1:
            return
        print_family_detail(resolved, families[idx].family_id, reg)


# ---------------------------------------------------------------------------
# Building a definition from a selection (pure)
# ---------------------------------------------------------------------------


def _toggleable(check: CheckDefinition) -> bool:
    return check.selectable and not check.locked_state


def base_selection(base: str, registry: CheckRegistry | None = None) -> frozenset[str]:
    """The checks a base selects before dependencies, from the SSOT resolver."""
    reg = registry or load_registry()
    resolved = resolve_for_display(ScanPolicyDefinition(base=base))
    return frozenset(
        c.check_id
        for c in reg.checks
        if _toggleable(c) and c.check_id not in resolved.excluded_ids
    )


def selection_of(definition: ScanPolicyDefinition, registry: CheckRegistry | None = None) -> frozenset[str]:
    """The toggleable checks a definition selects (before dependency pruning)."""
    reg = registry or load_registry()
    resolved = resolve_for_display(definition)
    return frozenset(
        c.check_id for c in reg.checks if _toggleable(c) and c.check_id not in resolved.excluded_ids
    )


def definition_for_selection(
    source: ScanPolicyDefinition,
    wanted: Iterable[str],
    *,
    pacing: dict[str, Any] | None,
    registry: CheckRegistry | None = None,
) -> ScanPolicyDefinition:
    """The definition that selects exactly ``wanted`` over the source's base.

    Each difference from the base becomes an explicit ``enabled`` / ``disabled``
    entry; a family switched entirely the same way collapses to its
    ``family:<id>`` selector, so the saved file reads like what the operator
    chose. A new policy keeps checks added by a later release off until someone
    enables them (``new_checks: disabled``, the web's rule for a new policy), and
    keeps the source's attack-step execution mode and environment (a copy of a
    lab policy is a lab policy until someone says otherwise). Paired detections are not
    toggleable (they follow their attack step), so they never become entries.
    """
    reg = registry or load_registry()
    wanted_set = set(wanted)
    base_on = base_selection(source.base, reg)
    enabled: list[str] = []
    disabled: list[str] = []
    for family in FAMILIES:
        members = [c.check_id for c in reg.checks_in_family(family.family_id) if _toggleable(c)]
        if not members:
            continue
        turn_on = [cid for cid in members if cid in wanted_set and cid not in base_on]
        turn_off = [cid for cid in members if cid not in wanted_set and cid in base_on]
        if turn_off and len(turn_off) == len(members):
            disabled.append(f"family:{family.family_id}")
        else:
            disabled.extend(turn_off)
        if turn_on and len(turn_on) == len(members):
            enabled.append(f"family:{family.family_id}")
        else:
            enabled.extend(turn_on)
    return ScanPolicyDefinition(
        base=source.base,
        enabled=tuple(enabled),
        disabled=tuple(disabled),
        new_checks=NEW_CHECKS_DISABLED,
        pacing=pacing,
        execution_mode=source.execution_mode,
        environment=source.environment,
        password_attempts=source.password_attempts,
        settings=source.settings,
    )


def with_environment(definition: ScanPolicyDefinition, environment: str | None) -> ScanPolicyDefinition:
    """The definition written for ``environment`` (``lab`` / ``real``); unchanged when ``None``.

    Stored only when it differs from what the base implies, so a copy that keeps
    its base's environment reads exactly like the base.
    """
    if not environment:
        return definition
    try:
        token = parse_environment(environment, where="--environment")
    except ScanPolicyError as exc:
        raise SavedPolicyError(str(exc)) from exc
    base_default = effective_environment(replace(definition, environment=""))
    changed = replace(definition, environment="" if token == base_default else token)
    try:
        # A lab-only behaviour setting does not carry over to a real environment.
        parse_settings(changed.settings, environment=token, where="settings")
    except PolicySettingError as exc:
        raise SavedPolicyError(str(exc)) from exc
    try:
        # A lab-only password-attempt rule does not carry over to a real environment.
        parse_password_attempts(
            changed.password_attempts, environment=token, where="password_attempts"
        )
    except ScanPolicyError as exc:
        raise SavedPolicyError(str(exc)) from exc
    return changed


def with_password_attempts(
    definition: ScanPolicyDefinition,
    *,
    reserve_margin: int | None = None,
    unknown_threshold: str | None = None,
    ignore_threshold: bool | None = None,
) -> ScanPolicyDefinition:
    """The definition with its ``password_attempts`` keys set (unchanged when none given).

    Validated for the definition's environment by the policy SSOT, so a margin
    of 0 or ``--ignore-threshold`` is refused on a policy for a real environment.
    """
    changes: dict[str, Any] = {}
    if reserve_margin is not None:
        changes["reserve_margin"] = reserve_margin
    if unknown_threshold is not None:
        changes["unknown_threshold"] = unknown_threshold
    if ignore_threshold is not None:
        changes["ignore_threshold"] = bool(ignore_threshold)
    if not changes:
        return definition
    merged = {**dict(definition.password_attempts or {}), **changes}
    try:
        block = parse_password_attempts(
            merged, environment=effective_environment(definition), where="password_attempts"
        )
    except ScanPolicyError as exc:
        raise SavedPolicyError(str(exc)) from exc
    return replace(definition, password_attempts=block)


def with_settings(
    definition: ScanPolicyDefinition, assignments: list[str] | tuple[str, ...] | None
) -> ScanPolicyDefinition:
    """The definition with ``key=value`` behaviour settings applied (unchanged when none).

    Validated for the definition's environment by the settings SSOT, so a value
    only a lab may use is refused on a policy for a real environment.
    """
    if not assignments:
        return definition
    changes: dict[str, str] = {}
    for item in assignments:
        key, sep, value = str(item or "").partition("=")
        if not sep or not key.strip():
            raise SavedPolicyError(
                f"'--set {item}' must be KEY=VALUE. Settings: {', '.join(SETTING_KEYS)}."
            )
        changes[key.strip().lower()] = value.strip().lower()
    merged = {**dict(definition.settings or {}), **changes}
    try:
        block = parse_settings(merged, environment=effective_environment(definition), where="settings")
    except PolicySettingError as exc:
        raise SavedPolicyError(str(exc)) from exc
    return replace(definition, settings=block)


def password_attempts_label(definition: ScanPolicyDefinition) -> str:
    """The client-facing sentence for the policy's password-attempt rule."""
    return password_attempts_line(effective_password_attempts(definition))


def environment_label(definition: ScanPolicyDefinition) -> str:
    """``Lab or CTF`` / ``Real environment`` for a definition."""
    return ENVIRONMENT_LABELS[effective_environment(definition)]


def apply_selectors(
    source: ScanPolicyDefinition, *, exclude: Iterable[str] = (), include: Iterable[str] = ()
) -> ScanPolicyDefinition:
    """Add ``--exclude`` / ``--include`` selectors to a definition (validated by token)."""
    from adscan_internal.cli.scan_policy_cmd import _SelectorError, resolve_selector

    enabled = list(source.enabled)
    disabled = list(source.disabled)
    for token in exclude or ():
        try:
            selector = resolve_selector(token)
        except _SelectorError as exc:
            raise SavedPolicyError(str(exc)) from exc
        enabled = [s for s in enabled if s != selector]
        disabled = [s for s in disabled if s != selector] + [selector]
    for token in include or ():
        try:
            selector = resolve_selector(token)
        except _SelectorError as exc:
            raise SavedPolicyError(str(exc)) from exc
        disabled = [s for s in disabled if s != selector]
        enabled = [s for s in enabled if s != selector] + [selector]
    return replace(source, enabled=tuple(enabled), disabled=tuple(disabled))


def with_pace(definition: ScanPolicyDefinition, level: str | None) -> ScanPolicyDefinition:
    """The definition with its pace level set to ``level``, keeping its settings.

    Validated by the pacing SSOT and held to the base built-in's limit.
    """
    if not level:
        return definition
    current = dict(definition.pacing or {})
    candidate: dict[str, Any] = {"level": level}
    if current.get("overrides"):
        candidate["overrides"] = dict(current["overrides"])
    check_pace_within_base(definition, candidate)
    try:
        pacing = parse_policy_definition({"pacing": candidate}).pacing
    except ScanPolicyError as exc:
        raise SavedPolicyError(str(exc)) from exc
    return replace(definition, pacing=pacing)


def session_pacing_request(shell: Any) -> PacingRequest:
    """The pace the operator set in this shell (``set pacing`` / ``set pacing.<setting>``).

    Raises:
        SavedPolicyError: Outside a shell, or when no pace was set in it.
    """
    from adscan_internal.services.scan_controls import workspace_pacing_request

    request = workspace_pacing_request(shell) if shell is not None else None
    if request is None:
        raise SavedPolicyError(
            "No scan pace was set in this shell. Set one first with 'set pacing <level>' or "
            "'set pacing.<setting> <value>', then save it with --pacing-from-session."
        )
    return request


def _base_ceiling(definition: ScanPolicyDefinition) -> PacingCeiling | None:
    """The pace the policy's built-in base allows, or ``None`` when the base sets none."""
    return base_pace_ceiling(definition.base)


def check_pace_within_base(definition: ScanPolicyDefinition, pacing: dict[str, Any] | None) -> None:
    """Refuse a pace faster than the built-in the policy is based on allows.

    A thin wrapper over the one save-time validator
    (:func:`adscan_core.scan_policy.pace_limits.pace_above_base`), which the web
    policy API calls too. Nothing is lowered silently: the save fails and names
    the level and every setting above the limit.

    Raises:
        SavedPolicyError: Naming the base, its limit and the settings above it.
    """
    try:
        violation = pace_above_base(definition.base, pacing)
    except PacingConfigError as exc:
        raise SavedPolicyError(str(exc)) from exc
    if violation is not None:
        raise SavedPolicyError(violation.message + " (Start from another policy with --from.)")


def with_pace_settings(
    definition: ScanPolicyDefinition,
    assignments: list[str] | tuple[str, ...] | None = None,
    session: PacingRequest | None = None,
) -> ScanPolicyDefinition:
    """The definition with pace overrides saved into it (unchanged when none are given).

    ``assignments`` are ``KNOB=VALUE`` items parsed and validated by the same
    parser as ``adscan ci --pacing-set``. ``session`` is the pace set in the
    shell: its level (when the operator chose one) and its overrides. A later
    source wins per setting, in the order policy, session, ``--pacing-set``.

    Raises:
        SavedPolicyError: On a malformed or unknown setting, or a pace faster than
            the base policy allows.
    """
    from adscan_internal.services.scan_controls import parse_pacing_assignments

    try:
        typed = parse_pacing_assignments(assignments)
    except PacingConfigError as exc:
        raise SavedPolicyError(str(exc)) from exc
    if not typed and session is None:
        return definition
    current = dict(effective_pacing(definition) or {})
    level = current.get("level", PacingLevel.NORMAL.value)
    overrides = dict(current.get("overrides") or {})
    if session is not None:
        if session.level_source != "default":
            level = session.level.value
        overrides.update(session.overrides)
    overrides.update(typed)
    pacing: dict[str, Any] = {"level": level}
    if overrides:
        pacing["overrides"] = overrides
    check_pace_within_base(definition, pacing)
    try:
        parsed = parse_policy_definition({"pacing": pacing}).pacing
    except ScanPolicyError as exc:
        raise SavedPolicyError(str(exc)) from exc
    return replace(definition, pacing=parsed)


def pace_detail_lines(definition: ScanPolicyDefinition) -> list[tuple[str, str]]:
    """``(label, text)`` lines for ``policy show``: who set the level, then each setting."""
    from adscan_internal.cli.scan_pacing_cmd import format_value

    pacing = effective_pacing(definition) or {}
    level = PacingLevel.coerce(pacing.get("level")) or PacingLevel.NORMAL
    base_label = BUILTIN_LABELS.get(definition.base, definition.base)
    inherited = not definition.pacing or definition.identity.policy_id.startswith("builtin:")
    level_source = f"the {base_label} policy it is based on" if inherited else "this policy"
    lines = [("Pace level", f"{LEVEL_DESCRIPTIONS[level].label}, set by {level_source}")]
    for key, value in (pacing.get("overrides") or {}).items():
        knob = KNOBS_BY_KEY.get(key)
        if knob is None:
            continue
        default = knob.level_values.get(level)
        text = f"{format_value(key, value)} ({key}), set by this policy"
        if default is not None and default != value:
            text += f"; the {LEVEL_DESCRIPTIONS[level].label} level alone gives {format_value(key, default)}"
        lines.append((knob.label, text))
    return lines


# ---------------------------------------------------------------------------
# Interactive editor
# ---------------------------------------------------------------------------


def _family_option(family: Any, reg: CheckRegistry) -> str:
    checks = [c for c in reg.checks_in_family(family.family_id) if _toggleable(c)]
    techniques = sum(1 for c in checks if c.kind == KIND_TECHNIQUE)
    detections = len(checks) - techniques
    parts = []
    if techniques:
        parts.append(f"{techniques} technique{'s' if techniques != 1 else ''}")
    if detections:
        parts.append(f"{detections} detection{'s' if detections != 1 else ''}")
    return f"{family.label} ({', '.join(parts)})"


def edit_definition_interactive(shell: Any, source: SavedPolicy) -> ScanPolicyDefinition | None:
    """Toggle families and checks and set the pace, starting from ``source``.

    Returns the new definition, or ``None`` when the operator cancels. Every
    prompt resolves to the source's own state when there is no operator, so a
    non-interactive call returns the source's selection unchanged.
    """
    reg = load_registry()
    current = set(selection_of(source.definition, reg))
    families = [f for f in FAMILIES if any(_toggleable(c) for c in reg.checks_in_family(f.family_id))]
    options = [_family_option(f, reg) for f in families]
    defaults = [
        option
        for option, family in zip(options, families)
        if any(c.check_id in current for c in reg.checks_in_family(family.family_id))
    ]
    print_info(
        f"Starting from '{escape(source.name)}'. Clear a family to turn all its checks off; "
        "tick one to turn it on."
    )
    picked = questionary_checkbox_values(
        title="Families this policy runs",
        options=options,
        default_values=defaults,
        shell=shell,
    )
    if picked is None:
        return None
    picked_set = set(picked)
    for option, family in zip(options, families):
        members = [c.check_id for c in reg.checks_in_family(family.family_id) if _toggleable(c)]
        if option not in picked_set:
            current.difference_update(members)
        elif not any(cid in current for cid in members):
            current.update(members)

    if confirm_ask("Choose individual checks inside a family?", False):
        chosen = [f for f, o in zip(families, options) if o in picked_set]
        while chosen:
            labels = [f.label for f in chosen] + ["Done"]
            idx = questionary_select_index(
                title="Family to adjust", options=labels, default_idx=len(labels) - 1, shell=shell
            )
            if idx is None or idx == len(labels) - 1:
                break
            members = [c for c in reg.checks_in_family(chosen[idx].family_id) if _toggleable(c)]
            check_options = [f"{c.title} ({c.check_id})" for c in members]
            ticked = questionary_checkbox_values(
                title=f"Checks in {chosen[idx].label}",
                options=check_options,
                default_values=[o for o, c in zip(check_options, members) if c.check_id in current],
                shell=shell,
            )
            if ticked is None:
                continue
            ticked_set = set(ticked)
            for option, check in zip(check_options, members):
                if option in ticked_set:
                    current.add(check.check_id)
                else:
                    current.discard(check.check_id)

    pacing = _choose_pace(shell, source.definition)
    result = definition_for_selection(source.definition, current, pacing=pacing, registry=reg)
    print_panel(
        Text("\n".join(definition_summary_lines(result))),
        title="[bold]This policy[/bold]",
        expand=False,
    )
    return result


def _choose_pace(shell: Any, definition: ScanPolicyDefinition) -> dict[str, Any] | None:
    """The pace step of the editor: the level, then optionally single settings.

    The pace is part of the policy, so it is saved with it. Unattended, every
    prompt keeps the pace the policy starts from. A setting faster than the
    base policy's limit is refused with the reason and the previous pace kept.
    The prompts are the shared ones (:mod:`adscan_internal.cli.pace_prompts`),
    the same the pace-profile editor uses.
    """
    ceiling = _base_ceiling(definition)
    limit = (
        f" The {BUILTIN_LABELS.get(definition.base, definition.base)} policy it is based on "
        f"allows at most {LEVEL_DESCRIPTIONS[ceiling.level].label}."
        if ceiling is not None
        else ""
    )
    return choose_pace(
        shell,
        keep=effective_pacing(definition),
        keep_label=pace_label(definition),
        title="Pace (the default of a scan under this policy, and its limit)." + limit,
        ceiling=ceiling,
        validate=lambda parsed: check_pace_within_base(definition, parsed),
    )


def definition_summary_lines(definition: ScanPolicyDefinition) -> list[str]:
    """One summary of the policy the editor produced: checks, execution settings, pace."""
    resolved = resolve_for_display(definition)
    lines = [f"Checks: {counts_line(resolved)}"]
    lines.extend(settings_lines(definition))
    lines.append(f"Pace: {pace_label(definition)}")
    lines.extend(f"  {label}: {text}" for label, text in pace_detail_lines(definition)[1:])
    return lines


def save_interactive(
    shell: Any,
    definition: ScanPolicyDefinition,
    *,
    default_name: str,
    workspace_dir: str | None,
    allow_unsaved: bool,
) -> tuple[SavedPolicy | None, bool]:
    """Ask where to save a policy and under what name.

    Returns ``(saved, proceed)``: ``saved`` is ``None`` when the operator keeps
    it for this scan only (or cancels); ``proceed`` is False on a cancel.
    """
    scopes: list[str] = []
    labels: list[str] = []
    if workspace_dir:
        scopes.append(SCOPE_WORKSPACE)
        labels.append("Save it in this workspace")
    scopes.append(SCOPE_GLOBAL)
    labels.append("Save it for all workspaces")
    if allow_unsaved:
        scopes.append("")
        labels.append("Use it without adding it to the saved policies")
    idx = questionary_select_index(title="Save the policy", options=labels, default_idx=0, shell=shell)
    if idx is None:
        return None, False
    scope = scopes[idx]
    if not scope:
        return None, True
    while True:
        name = prompt_ask("Policy name", default=default_name, shell=shell).strip()
        if not name:
            return None, False
        description = prompt_ask("Description (optional)", default="", shell=shell).strip()
        existing = store.find_policy(name, workspace_dir, scope=scope)
        overwrite = False
        if existing is not None:
            overwrite = confirm_ask(
                f"A policy named '{existing.name}' is already saved {SCOPE_LABELS[scope]}. Replace it?",
                False,
            )
            if not overwrite:
                default_name = f"{name} (2)"
                continue
        try:
            saved = store.save_policy(
                name, definition, scope=scope, workspace_dir=workspace_dir,
                description=description, overwrite=overwrite,
            )
        except SavedPolicyError as exc:
            print_error(escape(str(exc)))
            if _non_interactive(shell):
                return None, False
            continue
        print_success(f"Saved '{escape(saved.name)}' {saved_where(saved)}.")
        return saved, True


def _non_interactive(shell: Any) -> bool:
    from adscan_internal.interaction import is_non_interactive

    return bool(is_non_interactive(shell))


# ---------------------------------------------------------------------------
# The library subcommands (shared by the REPL and the container command)
# ---------------------------------------------------------------------------


@dataclass
class LibraryContext:
    """Where library subcommands read and write.

    Attributes:
        workspace_dir: The workspace whose store is consulted first (or ``None``).
        default_scope: Where ``create`` / ``import`` / ``save`` write by default.
        shell: The REPL shell (``None`` in the container command).
        container: True for ``adscan policy`` (hints name the launcher commands).
        host_shell: With ``--workspace``, the stand-in for the shell on the host.
    """

    workspace_dir: str | None
    default_scope: str
    shell: Any = None
    container: bool = False
    host_shell: Any = None

    @property
    def session(self) -> Any:
        """The object that holds the workspace's current policy: the shell, or its host stand-in."""
        return self.shell if self.shell is not None else self.host_shell

    @property
    def attended(self) -> bool:
        """True when a person can answer a prompt (REPL, or a host terminal)."""
        return not _non_interactive(self.shell)

    def current_policy(self) -> Any:
        return getattr(self.session, "scan_policy", None) if self.session is not None else None

    def use_hint(self, name: str) -> str:
        quoted = shlex.quote(name)
        if self.container:
            return f"Run a scan under it with: adscan ci ... --policy {quoted}"
        return f"Apply it to this workspace with: policy use {quoted}"


def _add_library_arguments(parser: argparse.ArgumentParser, *, actions: tuple[str, ...], container: bool) -> None:
    parser.add_argument("action", choices=list(actions), help="What to do.")
    parser.add_argument("target", nargs="?", default=None, help="Policy name (or a file, for import).")
    parser.add_argument("--from", dest="source", default=None, metavar="POLICY",
                        help="Policy to start from (create). Default: the workspace's policy, else its type's built-in.")
    parser.add_argument("--exclude", action="append", default=None, metavar="CHECK",
                        help="Check id or family to switch off (create). Repeatable.")
    parser.add_argument("--include", action="append", default=None, metavar="CHECK",
                        help="Check id or family to switch on (create). Repeatable.")
    parser.add_argument("--pacing", choices=[level.value for level in ORDERED_LEVELS], default=None,
                        help="The policy's pace: its default and its limit (create).")
    parser.add_argument("--pacing-set", dest="pacing_set", action="append", default=None,
                        metavar="KNOB=VALUE",
                        help="A pace setting saved in the policy (create). Repeatable; same "
                        "settings as 'adscan ci --pacing-set', for example max_parallel_hosts=4.")
    parser.add_argument("--reserve-margin", dest="reserve_margin", type=int, default=None,
                        metavar="N",
                        help="Failed attempts kept below each account's lockout threshold "
                        "(create). Default 2; at least 1 unless the policy is for a lab.")
    parser.add_argument("--unknown-threshold", dest="unknown_threshold",
                        choices=list(UNKNOWN_THRESHOLD_VALUES), default=None,
                        help="When the lockout threshold cannot be read (create): conservative "
                        "(one attempt per account per hour) or attempt_anyway (lab only).")
    parser.add_argument("--ignore-threshold", dest="ignore_threshold", action="store_true",
                        default=None,
                        help="Spray as if no account could lock (create). Lab policies only.")
    parser.add_argument("--set", dest="settings", action="append", default=None,
                        metavar="KEY=VALUE",
                        help="A behaviour setting (create). Repeatable. Keys: "
                        + ", ".join(SETTING_KEYS) + ". 'policy show' lists each value.")
    parser.add_argument("--environment", choices=list(ENVIRONMENTS), default=None,
                        help="What the policy is for, lab or real (create). Default: the policy it "
                        "starts from. It is the workspace type: lab makes a CTF workspace.")
    parser.add_argument("--description", default=None, metavar="TEXT", help="Description (create, import).")
    parser.add_argument("--name", dest="new_name", default=None, metavar="NAME",
                        help="Save an imported policy under this name.")
    parser.add_argument("--output", "-o", default=None, metavar="FILE", help="Write the export to FILE.")
    parser.add_argument("--format", dest="fmt", choices=list(EXPORT_FORMATS), default="yaml",
                        help="Export format: yaml (default) or json (the body the web API accepts).")
    parser.add_argument("--checks", action="store_true", help="Show every check with its safety lines (show).")
    parser.add_argument("--force", action="store_true", help="Replace a saved policy of the same name.")
    parser.add_argument("--yes", action="store_true", help="Delete without asking.")
    add_scope_argument(parser)
    if container:
        parser.add_argument("--workspace", "-w", default=None, metavar="NAME",
                            help="Use this workspace's policies; create and import can save there, "
                            "and 'use' applies a policy to it.")
    else:
        parser.add_argument("--pacing-from-session", dest="pacing_from_session", action="store_true",
                            help="Save the pace set in this shell (set pacing, set pacing.<setting>) "
                            "into the policy (create).")
        parser.add_argument("--global", dest="global_scope", action="store_true",
                            help="Save to, or delete from, the policies of all workspaces.")


class _ReplParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise SavedPolicyError(message)


def repl_library_parser() -> argparse.ArgumentParser:
    parser = _ReplParser(prog="policy", add_help=False)
    _add_library_arguments(parser, actions=REPL_LIBRARY_ACTIONS, container=False)
    return parser


def add_policy_subparser(subparsers: Any) -> argparse.ArgumentParser:
    """Register the container ``adscan policy`` subparser (mirrored by POLICY_PASSTHROUGH)."""
    parser = subparsers.add_parser(
        "policy",
        help="Create and manage saved scan policies: list, show, create, edit, delete, export, import, use.",
        description=(
            "Saved scan policies: which checks ADscan may run and at what pace. "
            "Built-ins are listed first and are read-only. A policy saved in a "
            "workspace wins over a global one of the same name."
        ),
    )
    _add_library_arguments(parser, actions=CONTAINER_ACTIONS, container=True)
    return parser


def _source_policy(ctx: LibraryContext, name: str | None) -> SavedPolicy:
    if name:
        policy = store.find_policy(name, ctx.workspace_dir)
        if policy is None:
            path = Path(name).expanduser()
            if path.is_file():
                document = store.read_policy_file(path)
                return SavedPolicy(name=document.name, scope=SCOPE_GLOBAL, definition=document.definition,
                                   description=document.description)
            raise SavedPolicyError(_unknown_policy_message(name, ctx.workspace_dir))
        return policy
    current = ctx.current_policy()
    if current is not None:
        from adscan_internal.services.scan_controls import policy_display_name

        return SavedPolicy(name=policy_display_name(current.definition), scope=SCOPE_WORKSPACE,
                           definition=current.definition)
    from adscan_core.scan_policy.settings import policy_environment  # noqa: PLC0415

    environment = policy_environment(ctx.session) if ctx.session is not None else None
    builtin = store.scan_policy_model().default_for_environment(environment)
    return SavedPolicy(name=builtin.name, scope=SCOPE_BUILTIN, definition=builtin.definition,
                       description=builtin.description, key=builtin.key)


def _unknown_policy_message(name: str, workspace_dir: str | None) -> str:
    available = ", ".join(p.name for p in store.list_policies(workspace_dir))
    return f"No scan policy named '{name}'. Available: {available}."


def _cmd_list(ctx: LibraryContext) -> None:
    current = ctx.current_policy()
    current_id = current.definition.identity.policy_id if current is not None else ""
    table = Table(show_header=True, header_style=f"bold {BRAND_COLORS['info']}", box=None, pad_edge=False)
    # Fold, never truncate: at 80 columns a long policy name wraps onto a second
    # line instead of ending in an ellipsis.
    table.add_column("")
    table.add_column("Policy", overflow="fold", min_width=20)
    table.add_column("Saved", overflow="fold")
    table.add_column("Based on", overflow="fold")
    table.add_column("Pace", overflow="fold")
    table.add_column("Attack\nsteps", justify="right", overflow="fold")
    table.add_column("Vulnerability\nchecks", justify="right", overflow="fold")
    for policy in store.list_policies(ctx.workspace_dir, include_shadowed=True):
        resolved = resolve_for_display(policy.definition)
        summary = build_policy_safety_summary(resolved)
        marker = "●" if current_id and current_id in (policy.reference, f"builtin:{policy.key}") else ""
        style = "dim" if policy.shadowed else ""
        saved = _LIST_SCOPE_LABELS.get(policy.scope, policy.scope) + (
            ", hidden by the workspace policy" if policy.shadowed else ""
        )
        table.add_row(
            Text(marker, style=BRAND_COLORS["info"]),
            Text(policy.name, style=style or "bold"),
            Text(saved, style="dim"),
            # A built-in is its own base; the column is for what a saved policy starts from.
            Text("" if policy.read_only else BUILTIN_LABELS.get(policy.definition.base, policy.definition.base), style=style),
            Text(pace_label(policy.definition), style=style),
            Text(f"{summary['attack_steps_enabled']} of {summary['attack_steps_total']}", style=style),
            Text(
                f"{summary['vulnerability_checks_enabled']} of {summary['vulnerability_checks_total']}",
                style=style,
            ),
        )
    print_table(table)
    for path, reason in store.unreadable_policy_files(ctx.workspace_dir):
        print_warning(f"Skipped {escape(str(path))}: {escape(reason)}")
    if current_id:
        print_instruction("● is the policy this workspace uses.")
    elif ctx.container and not ctx.workspace_dir:
        print_instruction("Add --workspace NAME to see which one a workspace uses.")
    print_instruction(
        "Show one with: " + ("adscan policy show <name>" if ctx.container else "policy show <name>")
    )


def _cmd_show(ctx: LibraryContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPolicyError("Name the policy to show.")
    policy = store.find_policy(args.target, ctx.workspace_dir)
    if policy is None:
        raise SavedPolicyError(_unknown_policy_message(args.target, ctx.workspace_dir))
    render_policy(policy, with_checks=bool(args.checks))
    if not args.checks:
        print_instruction(
            "See each check with its safety lines: "
            + ("adscan policy show <name> --checks" if ctx.container else "policy show <name> --checks")
        )


def _save_scope(ctx: LibraryContext, args: argparse.Namespace) -> str | None:
    """Where this policy is saved: ``--scope``/``--global``, else ask or fall back.

    Returns ``None`` when the user cancels the question. The same rule the
    pace-profile library applies (:func:`library_common.resolve_save_scope`).
    """
    explicit = getattr(args, "scope", None) or (
        SCOPE_GLOBAL if getattr(args, "global_scope", False) else None
    )
    return resolve_save_scope(
        noun="policy",
        workspace_dir=ctx.workspace_dir,
        explicit=explicit,
        shell=ctx.shell,
        attended=ctx.attended,
        host=ctx.container,
        error=SavedPolicyError,
    )


def _cmd_create(ctx: LibraryContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPolicyError("Name the new policy: policy create <name> [--from <policy>].")
    source = _source_policy(ctx, args.source)
    scope = _save_scope(ctx, args)
    if scope is None:
        print_info("No policy was created.")
        return
    flags_given = bool(
        args.exclude or args.include or args.pacing or args.environment
        or args.reserve_margin is not None or args.unknown_threshold or args.ignore_threshold
        or args.settings or args.pacing_set or getattr(args, "pacing_from_session", False)
    )
    if ctx.attended and not flags_given:
        definition = edit_definition_interactive(ctx.shell, source)
        if definition is None:
            print_info("No policy was created.")
            return
        definition = with_environment(definition, _ask_environment(ctx.shell, definition))
    else:
        definition = definition_for_selection(
            source.definition, selection_of(source.definition),
            pacing=dict(source.definition.pacing) if source.definition.pacing else None,
        )
        definition = apply_selectors(definition, exclude=args.exclude or (), include=args.include or ())
        definition = with_pace(definition, args.pacing)
        session = (
            session_pacing_request(ctx.shell) if getattr(args, "pacing_from_session", False) else None
        )
        definition = with_pace_settings(definition, args.pacing_set, session)
        definition = with_environment(definition, args.environment)
        definition = with_password_attempts(
            definition,
            reserve_margin=args.reserve_margin,
            unknown_threshold=args.unknown_threshold,
            ignore_threshold=args.ignore_threshold,
        )
        definition = with_settings(definition, args.settings)
    saved = store.save_policy(
        args.target, definition, scope=scope, workspace_dir=ctx.workspace_dir,
        description=args.description or "", overwrite=bool(args.force),
    )
    resolved = resolve_for_display(saved.definition)
    print_success(
        f"Saved '{escape(saved.name)}' {saved_where(saved)}: {counts_line(resolved)}, "
        f"pace {pace_label(saved.definition)}, for a {environment_label(saved.definition).lower()}."
    )
    print_instruction(ctx.use_hint(saved.name))


def _ask_environment(shell: Any, definition: ScanPolicyDefinition) -> str:
    """Ask what the new policy is for; unattended, the policy it starts from decides."""
    current = effective_environment(definition)
    options = [f"{ENVIRONMENT_LABELS[env]}" for env in ENVIRONMENTS]
    idx = questionary_select_index(
        title="What is this policy for? It sets the workspace type (lab makes a CTF workspace).",
        options=options,
        default_idx=ENVIRONMENTS.index(current),
        shell=shell,
    )
    if idx is None:
        return current
    return ENVIRONMENTS[int(idx)]


def _cmd_edit(ctx: LibraryContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPolicyError("Name the policy to edit.")
    policy = store.find_policy(args.target, ctx.workspace_dir)
    if policy is None:
        raise SavedPolicyError(_unknown_policy_message(args.target, ctx.workspace_dir))
    if policy.read_only:
        raise SavedPolicyError(
            f"'{policy.name}' is a built-in policy and cannot be changed. Make a copy with: "
            f"policy create <name> --from {policy.key}"
        )
    flags_given = bool(args.exclude or args.include or args.pacing)
    if not flags_given and ctx.attended:
        definition = edit_definition_interactive(ctx.shell, policy)
        if definition is None:
            print_info(f"'{escape(policy.name)}' was not changed.")
            return
    else:
        definition = with_pace(
            apply_selectors(policy.definition, exclude=args.exclude or (), include=args.include or ()),
            args.pacing,
        )
    saved = store.save_policy(
        policy.name, definition, scope=policy.scope, workspace_dir=ctx.workspace_dir,
        description=args.description if args.description is not None else policy.description,
        overwrite=True,
    )
    print_success(
        f"Saved revision {saved.definition.identity.revision} of '{escape(saved.name)}' "
        f"({counts_line(resolve_for_display(saved.definition))})."
    )
    _reapply_if_current(ctx, saved)


def _reapply_if_current(ctx: LibraryContext, saved: SavedPolicy) -> None:
    current = ctx.current_policy()
    if current is None or current.definition.identity.policy_id != saved.reference:
        return
    from adscan_internal.cli.scan_policy_cmd import apply_saved_policy

    if apply_saved_policy(ctx.session, saved) is not None:
        print_info("This workspace uses it, so the new revision applies to its next scan.")


def _cmd_save(ctx: LibraryContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPolicyError("Name the policy: policy save <name>.")
    require_workspace(ctx.workspace_dir, what="Saving a workspace's policy", error=SavedPolicyError)
    current = ctx.current_policy()
    if current is None:
        raise SavedPolicyError(
            "This workspace has no scan policy to save. Set one with: "
            + ("adscan policy use <name> --workspace NAME" if ctx.container else "policy use <name>")
        )
    scope = _save_scope(ctx, args)
    if scope is None:
        print_info("The policy was not saved.")
        return
    definition = replace(current.definition, identity=replace(current.definition.identity, policy_id="", name=""))
    saved = store.save_policy(
        args.target, definition, scope=scope, workspace_dir=ctx.workspace_dir,
        description=args.description or "", overwrite=bool(args.force),
    )
    print_success(f"Saved the workspace's policy as '{escape(saved.name)}' ({scope_label(saved)}).")
    from adscan_internal.cli.scan_policy_cmd import apply_saved_policy

    apply_saved_policy(ctx.session, saved, quiet=True)


def _cmd_delete(ctx: LibraryContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPolicyError("Name the policy to delete.")
    scope = getattr(args, "scope", None) or (SCOPE_GLOBAL if getattr(args, "global_scope", False) else None)
    policy = store.find_policy(args.target, ctx.workspace_dir, scope=scope)
    if policy is None:
        raise SavedPolicyError(_unknown_policy_message(args.target, ctx.workspace_dir))
    if policy.read_only:
        raise SavedPolicyError(f"'{policy.name}' is a built-in policy and cannot be deleted.")
    if not getattr(args, "yes", False) and not confirm_ask(
        f"Delete the policy '{policy.name}' ({scope_label(policy)})?", False
    ):
        print_info("The policy was kept.")
        return
    store.delete_policy(policy.name, workspace_dir=ctx.workspace_dir, scope=policy.scope)
    print_success(f"Deleted '{escape(policy.name)}' ({saved_where(policy)}).")
    current = ctx.current_policy()
    if current is not None and current.definition.identity.policy_id == policy.reference:
        print_info(
            "This workspace keeps using the deleted policy's checks until you choose another one."
        )


def _cmd_export(ctx: LibraryContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPolicyError("Name the policy to export.")
    policy = store.find_policy(args.target, ctx.workspace_dir)
    if policy is None:
        raise SavedPolicyError(_unknown_policy_message(args.target, ctx.workspace_dir))
    text = store.export_policy_text(policy, fmt=args.fmt)
    if args.output:
        shown = write_export_file(args.output, text, error=SavedPolicyError)
        print_success(f"Exported '{escape(policy.name)}' to {escape(shown)}.")
        return
    from adscan_core.output._state import get_console

    get_console().print(Text(text.rstrip("\n")), markup=False, highlight=False, soft_wrap=True)


def _cmd_import(ctx: LibraryContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPolicyError("Name the file to import.")
    document = store.read_policy_file(args.target)
    scope = _save_scope(ctx, args)
    if scope is None:
        print_info("Nothing was imported.")
        return
    saved = store.save_policy(
        args.new_name or document.name, document.definition, scope=scope,
        workspace_dir=ctx.workspace_dir,
        description=args.description if args.description is not None else document.description,
        overwrite=bool(args.force),
    )
    print_success(
        f"Imported '{escape(saved.name)}' {saved_where(saved)}: "
        f"{counts_line(resolve_for_display(saved.definition))}, pace {pace_label(saved.definition)}."
    )
    print_instruction(ctx.use_hint(saved.name))


def new_checks_choice_defaults(notice: Any) -> list[str]:
    """The new checks a review starts with ticked: the ones running today."""
    return [_new_check_option(c) for c in notice.checks if c.on]


def _new_check_option(check: Any) -> str:
    return f"{check.title} ({check.group_label or check.group}, {check.check_id})"


def _cmd_review_new(ctx: LibraryContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPolicyError("Name the policy to review: policy review-new <name>.")
    policy = store.find_policy(args.target, ctx.workspace_dir)
    if policy is None:
        raise SavedPolicyError(_unknown_policy_message(args.target, ctx.workspace_dir))
    if policy.read_only:
        raise SavedPolicyError(
            f"'{policy.name}' is a built-in policy: it always includes the checks of this version."
        )
    notice = new_checks_since_saved(policy.definition)
    if notice is None:
        print_info(f"'{escape(policy.name)}' has no checks added since it was saved.")
        return
    print_info(escape(notice.line))
    table = Table(show_header=True, header_style=f"bold {BRAND_COLORS['info']}", box=None, pad_edge=False)
    table.add_column("Check")
    table.add_column("Group")
    table.add_column("Now")
    for check in notice.checks:
        table.add_row(
            escape(check.title), escape(check.group_label or check.group), "on" if check.on else "off"
        )
    print_table(table)
    options = [_new_check_option(c) for c in notice.checks]
    chosen = questionary_checkbox_values(
        title="Keep these checks on (the others stay off). Saving acknowledges them.",
        options=options,
        default_values=new_checks_choice_defaults(notice),
        shell=ctx.shell,
    )
    if chosen is None:
        print_info(f"'{escape(policy.name)}' was not changed.")
        return
    by_option = dict(zip(options, notice.checks))
    keep_on = [by_option[o].check_id for o in chosen if o in by_option]
    definition = acknowledge_new_checks(policy.definition, notice, keep_on)
    saved = store.save_policy(
        policy.name, definition, scope=policy.scope, workspace_dir=ctx.workspace_dir,
        description=policy.description, overwrite=True,
    )
    print_success(
        f"Saved revision {saved.definition.identity.revision} of '{escape(saved.name)}' at this "
        f"version's checks ({counts_line(resolve_for_display(saved.definition))})."
    )
    _reapply_if_current(ctx, saved)


def _cmd_use(ctx: LibraryContext, args: argparse.Namespace) -> None:
    """Make a policy the workspace's policy (host: ``adscan policy use NAME --workspace W``).

    The REPL has its own ``policy use`` (:mod:`adscan_internal.cli.scan_policy_cmd`);
    this one runs the same function on the host's stand-in shell, so the policy is
    applied and persisted exactly the same way.
    """
    if not args.target:
        raise SavedPolicyError("Name the policy to use: adscan policy use <name> --workspace NAME.")
    require_workspace(ctx.workspace_dir, what="Using a policy", error=SavedPolicyError)
    if store.find_policy(args.target, ctx.workspace_dir) is None and not Path(args.target).expanduser().is_file():
        raise SavedPolicyError(_unknown_policy_message(args.target, ctx.workspace_dir))
    from adscan_internal.cli.scan_policy_cmd import _use

    _use(ctx.session, args.target)
    print_instruction("It applies to the next scan of this workspace.")


_HANDLERS = {
    "use": _cmd_use,
    "list": lambda ctx, args: _cmd_list(ctx),
    "review-new": _cmd_review_new,
    "show": _cmd_show,
    "create": _cmd_create,
    "edit": _cmd_edit,
    "save": _cmd_save,
    "delete": _cmd_delete,
    "export": _cmd_export,
    "import": _cmd_import,
}


def run_library_action(ctx: LibraryContext, args: argparse.Namespace) -> bool:
    """Run one library subcommand; returns False (after telling the user) on an error."""
    try:
        _HANDLERS[args.action](ctx, args)
        return True
    except SavedPolicyError as exc:
        print_error(escape(str(exc)))
        return False


def run_repl_library_command(shell: Any, tokens: list[str]) -> None:
    """The REPL entry for the library subcommands."""
    try:
        args = repl_library_parser().parse_args(tokens)
    except SavedPolicyError as exc:
        print_error(escape(str(exc)))
        return
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "") or None
    ctx = LibraryContext(
        workspace_dir=workspace_dir,
        default_scope=SCOPE_WORKSPACE if workspace_dir else SCOPE_GLOBAL,
        shell=shell,
    )
    run_library_action(ctx, args)


def handle_policy_command(args: argparse.Namespace) -> int:
    """``adscan policy ...`` (container). Exit code 0 on success, 2 on a user error."""
    try:
        try:
            workspace_dir = resolve_workspace_dir(args.workspace, error=SavedPolicyError)
        except SavedPolicyError as exc:
            print_error(escape(str(exc)))
            return 2
        host_shell = None
        if workspace_dir:
            from adscan_internal.cli.library_common import HostWorkspaceShell

            host_shell = HostWorkspaceShell(workspace_dir)
        ctx = LibraryContext(
            workspace_dir=workspace_dir,
            default_scope=SCOPE_WORKSPACE if workspace_dir else SCOPE_GLOBAL,
            container=True,
            host_shell=host_shell,
        )
        return 0 if run_library_action(ctx, args) else 2
    except Exception as exc:  # noqa: BLE001 - one command, one exit code
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("The policy command failed.")
        return 1


__all__ = [
    "CONTAINER_ACTIONS",
    "EXPORT_FORMATS",
    "INTERACTIVE_SCOPE_NOTE",
    "LibraryContext",
    "REPL_LIBRARY_ACTIONS",
    "add_policy_subparser",
    "apply_selectors",
    "base_selection",
    "browse_policy",
    "definition_summary_lines",
    "counts_line",
    "definition_for_selection",
    "edit_definition_interactive",
    "family_checks_table",
    "family_table",
    "handle_policy_command",
    "pace_label",
    "render_policy",
    "run_library_action",
    "run_repl_library_command",
    "save_interactive",
    "scope_label",
    "selection_of",
    "with_pace",
    "with_pace_settings",
]
