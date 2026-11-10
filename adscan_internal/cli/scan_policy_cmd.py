"""The REPL ``policy`` command and the scan-controls summaries.

Usage (REPL)::

    policy show [<name>] [--checks]
    policy use <built-in | saved policy | file.yaml>
    policy exclude <check id | family>
    policy include <check id | family>
    policy clear [--yes]
    policy list | create | edit | save | delete | export | import | review-new ...

The library subcommands (saved policies) live in
:mod:`adscan_internal.cli.scan_policy_library`.

It reads and writes the SAME persisted workspace policy the ``checks`` section
of a scan config writes (``<workspace>/scan_policy.json``), so a policy set here
applies to the next ``start``, ``execute`` or ``adscan ci`` on this workspace,
and a policy the web sent applies here (scan-policy spec D-3, § 7.4).

All logic lives in :mod:`adscan_internal.services.scan_controls`; this module
parses, validates selectors against the registry and renders.
"""

from __future__ import annotations

import difflib
import shlex
from dataclasses import replace
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
)
from adscan_core.scan_pacing import LEVEL_DESCRIPTIONS, PacingLevel
from adscan_core.scan_policy.families import FAMILIES, FAMILIES_BY_ID, FAMILY_IDS
from adscan_core.scan_policy.model import KIND_DETECTION, KIND_TECHNIQUE, LOCKED_ALWAYS_RUNS
from adscan_core.scan_policy.policy import (
    BUILTIN_DESCRIPTIONS,
    BUILTIN_IDS,
    BUILTIN_LABELS,
    BASE_FULL_VALIDATION,
    ScanPolicyDefinition,
)
from adscan_core.scan_policy.registry import load_registry
from adscan_core.scan_policy.resolve import ResolvedScanPolicy
from adscan_core.scan_policy.summary import build_policy_safety_summary
from adscan_internal.cli.scan_policy_library import INTERACTIVE_SCOPE_NOTE

USAGE = (
    "Usage: policy show [name] | policy use <policy or file> | policy exclude <check or family> "
    "| policy include <check or family> | policy clear | policy list | policy create <name> "
    "| policy edit <name> | policy save <name> | policy delete <name> | policy export <name> "
    "| policy import <file> | policy review-new <name>"
)

_SOURCE_LABELS = {
    "scan_config": "from the scan configuration",
    "repl": "set in the shell",
    "workspace": "saved in the workspace",
    "unreadable": "the policy file cannot be read",
    "workspace_type": "chosen for the workspace type",
}


# ---------------------------------------------------------------------------
# Completion data (tab completion reads these, never a hand-written list)
# ---------------------------------------------------------------------------


def selectable_selectors() -> list[str]:
    """Every value ``policy exclude|include`` accepts: family selectors, then check ids."""
    reg = load_registry()
    families = [f"family:{family.family_id}" for family in FAMILIES]
    checks = sorted(
        check.check_id for check in reg.checks if check.selectable and not check.locked_state
    )
    return families + checks


def use_choices(workspace_dir: str | None = None) -> list[str]:
    """What ``policy use`` and ``policy show`` complete: built-in keys, then saved names."""
    from adscan_internal.services.saved_scan_policies import SCOPE_BUILTIN, list_policies

    choices = list(BUILTIN_IDS)
    try:
        for policy in list_policies(workspace_dir):
            if policy.scope != SCOPE_BUILTIN:
                choices.append(policy.name)
    except OSError:
        pass
    return list(dict.fromkeys(choices))


# ---------------------------------------------------------------------------
# Summaries (also used by the workspace loader and adscan ci)
# ---------------------------------------------------------------------------


def _counts_line(resolved: ResolvedScanPolicy) -> str:
    summary = build_policy_safety_summary(resolved)
    return (
        f"{summary['attack_steps_enabled']} of {summary['attack_steps_total']} attack steps, "
        f"{summary['vulnerability_checks_enabled']} of {summary['vulnerability_checks_total']} "
        "vulnerability checks"
    )


def pacing_label(pacing: Any) -> str:
    """``Polite`` or ``Polite (limited by policy 'X')`` for a resolved pace."""
    level = getattr(pacing, "level", PacingLevel.NORMAL)
    label = LEVEL_DESCRIPTIONS[level].label
    ceiling = getattr(pacing, "ceiling", None)
    limited = bool(getattr(pacing, "level_capped", False) or getattr(pacing, "capped", ()))
    if ceiling is not None and limited:
        name = getattr(getattr(ceiling, "policy", None), "name", "") or "the scan policy"
        return f"{label} (limited by policy '{name}')"
    return label


def announce_workspace_scan_controls(applied: Any) -> None:
    """One or two lines on workspace load; silent when nothing is set."""
    from adscan_internal.services.scan_controls import policy_display_name

    for message in getattr(applied, "warnings", ()) or ():
        print_warning(escape(message))
    policy = getattr(applied, "policy", None)
    if policy is not None:
        print_info(
            f"Scan policy '{escape(policy_display_name(policy.definition))}' applies to this "
            f"workspace ({_counts_line(policy)}). Run 'policy show' for details."
        )
    pacing = getattr(applied, "pacing", None)
    if pacing is not None and not pacing.request.is_default:
        print_info(f"Scan pace: {escape(pacing_label(pacing))}. Run 'show pacing' for details.")


def print_ci_scan_controls(applied: Any) -> None:
    """The ``adscan ci`` summary: policy, digest, pace; warnings first."""
    from adscan_internal.services.scan_controls import policy_display_name, short_digest

    for message in getattr(applied, "warnings", ()) or ():
        print_warning(escape(message))
    policy = getattr(applied, "policy", None)
    if policy is not None:
        print_info(
            f"Scan policy: {escape(policy_display_name(policy.definition))} "
            f"({_counts_line(policy)}). Digest {short_digest(policy.digest)}."
        )
    pacing = applied.pacing
    if not pacing.is_default or policy is not None:
        origin = ""
        if policy is not None and getattr(pacing.request, "level_source", "") == "policy":
            origin = f", the {policy_display_name(policy.definition)} policy's own pace"
        print_info(f"Scan pace: {escape(pacing_label(pacing) + origin)}.")
    profile = getattr(pacing.request, "profile", None)
    if profile is not None:
        print_info(
            f"Pace profile: {escape(profile.name)}"
            + (", adjusted by --pacing or --pacing-set." if profile.adjusted else ".")
        )
    if pacing.level_capped:
        print_warning(
            f"The {LEVEL_DESCRIPTIONS[pacing.requested_level].label} pace you asked for is "
            f"faster than the scan policy allows; this run uses "
            f"{LEVEL_DESCRIPTIONS[pacing.level].label}."
        )
    elif pacing.capped:
        print_warning(
            "Some pace settings you asked for are faster than the scan policy allows and "
            "were lowered to its limit. Run 'show pacing' in the shell to see them."
        )
    for env_var in pacing.legacy_env:
        print_warning(
            f"{env_var} is deprecated and still applied. Use the scan pace settings instead "
            "(--pacing-set or 'set pacing.<setting>')."
        )
    if getattr(applied, "fast_requested", False):
        print_warning(fast_pace_notice())


def fast_pace_notice() -> str:
    """The coordination notice the Fast pace always shows."""
    return (
        "Fast pace: ADscan roughly doubles the hosts it works at once and lets the port scan "
        "send up to 800 packets per second. Use it only where the network owner has agreed "
        "to a faster assessment."
    )


# ---------------------------------------------------------------------------
# policy show
# ---------------------------------------------------------------------------


def _family_table(resolved: ResolvedScanPolicy) -> Table:
    reg = load_registry()
    table = Table(
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        box=None,
        pad_edge=False,
    )
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


def _print_dependency_exclusions(resolved: ResolvedScanPolicy) -> None:
    """One line each for techniques and detections switched off by a dependency."""
    reg = load_registry()
    by_kind: dict[str, list[str]] = {KIND_TECHNIQUE: [], KIND_DETECTION: []}
    for check_id in sorted(resolved.dependency_excluded):
        check = reg.get(check_id)
        if check is not None:
            by_kind.setdefault(check.kind, []).append(check_id)
    if by_kind[KIND_TECHNIQUE]:
        count = len(by_kind[KIND_TECHNIQUE])
        print_warning(
            f"{count} technique{'s' if count != 1 else ''} will not run because a check "
            f"{'they need' if count != 1 else 'it needs'} is excluded: "
            f"{', '.join(by_kind[KIND_TECHNIQUE])}."
        )
    if by_kind[KIND_DETECTION]:
        count = len(by_kind[KIND_DETECTION])
        print_warning(
            f"{count} detection{'s are' if count != 1 else ' is'} reported as not assessed "
            f"because the check that gathers {'their' if count != 1 else 'its'} evidence is "
            f"excluded: {', '.join(by_kind[KIND_DETECTION])}."
        )


def _show(shell: Any) -> None:
    from adscan_internal.services.scan_controls import (
        ATTR_POLICY,
        ATTR_POLICY_CLEARED,
        ATTR_POLICY_SOURCE,
        policy_display_name,
        session_pacing_ceiling,
        short_digest,
    )

    resolved: ResolvedScanPolicy | None = getattr(shell, ATTR_POLICY, None)
    cleared = getattr(shell, ATTR_POLICY_CLEARED, None)
    if resolved is None:
        body = Text()
        body.append("No scan policy is set for this workspace. ", style="bold")
        body.append("Every check ADscan can run is allowed (Full validation).\n\n")
        if isinstance(cleared, dict) and cleared.get("previous"):
            previous = cleared["previous"]
            body.append(
                f"The policy '{previous.get('name', '')}' was cleared by the operator; "
                "the next report states it.\n\n",
                style="yellow",
            )
        body.append("Built-in policies:\n", style="bold")
        for base in BUILTIN_IDS:
            body.append(f"  {base}\n", style=BRAND_COLORS["info"])
            body.append(f"    {BUILTIN_DESCRIPTIONS[base]}\n", style="dim")
        print_panel(body, title="[bold]Scan policy[/bold]", expand=False)
        print_instruction("Set one with: policy use <name>. List saved ones with: policy list")
        return

    definition = resolved.definition
    summary = build_policy_safety_summary(resolved)
    head = Text()
    head.append(policy_display_name(definition), style="bold")
    source = getattr(shell, ATTR_POLICY_SOURCE, "") or "workspace"
    head.append(f"  ({_SOURCE_LABELS.get(source, source)})\n", style="dim")
    if definition.identity.name or definition.enabled or definition.disabled:
        head.append("Based on: ", style="dim")
        head.append(f"{BUILTIN_LABELS.get(definition.base, definition.base)}\n")
    head.append("Digest: ", style="dim")
    head.append(f"{short_digest(resolved.digest)}  (check registry v{resolved.registry_version})\n")
    ceiling = session_pacing_ceiling(shell)
    if ceiling is not None:
        head.append("Fastest pace allowed: ", style="dim")
        head.append(f"{LEVEL_DESCRIPTIONS[ceiling.level].label}\n")
    if definition.disabled:
        head.append("Excluded: ", style="dim")
        head.append(", ".join(definition.disabled) + "\n")
    if definition.enabled:
        head.append("Included: ", style="dim")
        head.append(", ".join(definition.enabled) + "\n")
    head.append("\n")
    head.append(" ".join([summary["statement"], *summary.get("revert_permission_lines", [])]))
    head.append("\n\n")
    head.append(INTERACTIVE_SCOPE_NOTE, style="dim")
    print_panel(head, title="[bold]Scan policy[/bold]", expand=False)
    print_table(_family_table(resolved))
    for message in resolved.warnings:
        print_warning(escape(message))
    _print_dependency_exclusions(resolved)
    print_instruction(
        "Change it with: policy exclude <check or family> | policy include <check or family> "
        "| policy use <name> | policy clear. Keep it with: policy save <name>"
    )


# ---------------------------------------------------------------------------
# Selector resolution
# ---------------------------------------------------------------------------


class _SelectorError(ValueError):
    pass


def resolve_selector(token: str) -> str:
    """Turn an operator token into a check id or a ``family:<id>`` selector.

    Accepts a full id (``step:kerberoasting``, ``family:adcs``), a bare family id
    (``adcs``) or the unique check whose name after the prefix matches
    (``kerberoasting``).

    Raises:
        _SelectorError: Unknown, ambiguous or locked.
    """
    reg = load_registry()
    value = str(token or "").strip().lower()
    if not value:
        raise _SelectorError("Name a check or a family. " + USAGE)
    if value.startswith("family:"):
        family = value.split(":", 1)[1]
        if family not in FAMILY_IDS:
            raise _SelectorError(_unknown_message(value))
        return value
    if ":" not in value and value in FAMILY_IDS:
        return f"family:{value}"
    if ":" in value:
        check = reg.get(value)
        if check is None:
            raise _SelectorError(_unknown_message(value))
    else:
        matches = [c for c in reg.checks if c.check_id.split(":", 1)[1] == value]
        if not matches:
            raise _SelectorError(_unknown_message(value))
        if len(matches) > 1:
            raise _SelectorError(
                f"'{value}' matches more than one check: "
                f"{', '.join(c.check_id for c in matches)}. Use the full id."
            )
        check = matches[0]
    if check.locked_state == LOCKED_ALWAYS_RUNS:
        raise _SelectorError(f"{check.check_id} always runs; a policy cannot change it.")
    if check.locked_state:
        raise _SelectorError(f"{check.check_id} is never executed by ADscan; a policy cannot change it.")
    if check.is_paired_detection:
        owners = ", ".join(check.owned_by)
        raise _SelectorError(
            f"{check.check_id} is reported with {owners}, which stays mapped when it is "
            "switched off; a policy cannot switch the detection off on its own."
        )
    return check.check_id


def _unknown_message(value: str) -> str:
    close = difflib.get_close_matches(value, selectable_selectors(), n=3, cutoff=0.6)
    hint = f" Did you mean: {', '.join(close)}?" if close else " Press Tab to list them."
    return f"Unknown check or family '{value}'.{hint}"


def _selector_label(selector: str) -> str:
    if selector.startswith("family:"):
        family = FAMILIES_BY_ID[selector.split(":", 1)[1]]
        return f"family '{family.label}'"
    check = load_registry().get(selector)
    return f"{check.title} ({selector})" if check is not None else selector


def _selector_checks(selector: str) -> list[Any]:
    reg = load_registry()
    if selector.startswith("family:"):
        return list(reg.checks_in_family(selector.split(":", 1)[1]))
    check = reg.get(selector)
    return [check] if check is not None else []


def _with_selector(
    definition: ScanPolicyDefinition, selector: str, *, include: bool
) -> ScanPolicyDefinition:
    enabled = [s for s in definition.enabled if s != selector]
    disabled = [s for s in definition.disabled if s != selector]
    if include:
        enabled.append(selector)
    else:
        disabled.append(selector)
    identity = definition.identity
    if identity.name and not identity.modified_for_this_scan:
        identity = replace(identity, modified_for_this_scan=True)
    return replace(definition, enabled=tuple(enabled), disabled=tuple(disabled), identity=identity)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _workspace_dir(shell: Any) -> str | None:
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "")
    if not workspace_dir:
        print_error("Open a workspace first: the scan policy is saved in the workspace.")
        return None
    return workspace_dir


def _apply(shell: Any, definition: ScanPolicyDefinition | None) -> ResolvedScanPolicy | None:
    from adscan_internal.services.scan_controls import set_policy

    workspace_dir = _workspace_dir(shell)
    if workspace_dir is None:
        return None
    resolved, pacing = set_policy(shell, definition, workspace_dir=workspace_dir)
    for message in resolved.warnings if resolved is not None else ():
        print_warning(escape(message))
    if pacing.level_capped or pacing.capped:
        print_info(f"Scan pace is now {escape(pacing_label(pacing))}.")
    return resolved


def apply_saved_policy(shell: Any, policy: Any, *, quiet: bool = False) -> ResolvedScanPolicy | None:
    """Make a built-in or saved policy the workspace's policy (interactive rule applied).

    An interactive scan only uses a policy's exclusions, so the definition goes
    through the model adapter's ``for_interactive_scan`` before it is applied.
    """
    from adscan_internal.services.saved_scan_policies import scan_policy_model
    from adscan_internal.services.scan_controls import ScanControlsError, policy_display_name

    definition = scan_policy_model().for_interactive_scan(policy.definition)
    try:
        resolved = _apply(shell, definition)
    except ScanControlsError as exc:
        print_error(escape(str(exc)))
        return None
    if resolved is not None and not quiet:
        print_success(
            f"Scan policy set to '{escape(policy_display_name(resolved.definition))}' "
            f"({_counts_line(resolved)})."
        )
        _summary = build_policy_safety_summary(resolved)
        print_info(" ".join([_summary["statement"], *_summary.get("revert_permission_lines", [])]))
    return resolved


def _use(shell: Any, target: str) -> None:
    from adscan_internal.services.saved_scan_policies import (
        SCOPE_GLOBAL,
        SavedPolicy,
        SavedPolicyError,
        find_policy,
        read_policy_file,
    )

    key = str(target or "").strip()
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "") or None
    policy = find_policy(key, workspace_dir) if key else None
    if policy is None:
        path = Path(key).expanduser()
        if not key or not path.is_file():
            print_error(
                f"Unknown policy '{escape(key)}'. Use a built-in ({', '.join(BUILTIN_IDS)}), a saved "
                "policy ('policy list'), or the path of a YAML or JSON file with a 'checks' section."
            )
            return
        try:
            document = read_policy_file(path)
        except (OSError, SavedPolicyError, ValueError) as exc:
            print_error(f"Cannot use {escape(str(path))}: {escape(str(exc))}")
            return
        policy = SavedPolicy(
            name=document.name,
            scope=SCOPE_GLOBAL,
            definition=replace(
                document.definition,
                identity=replace(document.definition.identity, name=document.name),
            ),
        )
    apply_saved_policy(shell, policy)


def _include_or_exclude(shell: Any, token: str, *, include: bool) -> None:
    from adscan_internal.services.scan_controls import ATTR_POLICY, ScanControlsError

    try:
        selector = resolve_selector(token)
    except _SelectorError as exc:
        print_error(escape(str(exc)))
        return
    current: ResolvedScanPolicy | None = getattr(shell, ATTR_POLICY, None)
    started_new = current is None
    base_definition = (
        current.definition if current is not None else ScanPolicyDefinition(base=BASE_FULL_VALIDATION)
    )
    try:
        resolved = _apply(shell, _with_selector(base_definition, selector, include=include))
    except ScanControlsError as exc:
        print_error(escape(str(exc)))
        return
    if resolved is None:
        return
    verb = "Included" if include else "Excluded"
    print_success(f"{verb} {escape(_selector_label(selector))}. Policy now allows {_counts_line(resolved)}.")
    if started_new:
        print_info("This workspace had no scan policy; it now has one based on Full validation.")
    checks = _selector_checks(selector)
    if include:
        still_off = [
            c.check_id for c in checks if c.check_id not in resolved.effective_ids and not c.locked_state
        ]
        for check_id in still_off:
            blocker = resolved.dependency_excluded.get(check_id)
            reason = f"it needs {blocker}, which is excluded" if blocker else "it is excluded by id"
            print_warning(f"{check_id} still does not run: {reason}.")
    else:
        still_on = [
            c.check_id
            for c in checks
            if c.check_id in resolved.effective_ids and c.locked_state != LOCKED_ALWAYS_RUNS
        ]
        if still_on:
            print_warning(
                "Still allowed because they are included by id: "
                f"{', '.join(still_on)}. Exclude them by id to turn them off."
            )


def _clear(shell: Any, flags: Iterable[str]) -> None:
    from adscan_internal.services.scan_controls import ATTR_POLICY, policy_display_name

    current: ResolvedScanPolicy | None = getattr(shell, ATTR_POLICY, None)
    if current is None:
        print_info("This workspace has no scan policy to clear.")
        return
    name = policy_display_name(current.definition)
    if _workspace_dir(shell) is None:
        return
    if "--yes" not in set(flags) and not confirm_ask(
        f"Remove the scan policy '{name}'? Later scans of this workspace will run every check.",
        False,
    ):
        print_info("The scan policy was kept.")
        return
    _apply(shell, None)
    print_success(f"Scan policy '{escape(name)}' removed. Every check is allowed again.")
    print_info("The next report states that the operator cleared the policy.")


def run_policy_command(shell: Any, args: str) -> None:
    """Entry point of the REPL ``policy`` verb."""
    try:
        tokens = shlex.split(args or "")
    except ValueError as exc:
        print_error(f"{escape(str(exc))}. {USAGE}")
        return
    sub = tokens[0].lower() if tokens else "show"
    rest = tokens[1:]
    try:
        from adscan_internal.cli.scan_policy_library import (
            REPL_LIBRARY_ACTIONS,
            run_repl_library_command,
        )

        if sub == "show" and not rest:
            _show(shell)
        elif sub in REPL_LIBRARY_ACTIONS:
            run_repl_library_command(shell, [sub, *rest])
        elif sub == "use" and len(rest) == 1:
            _use(shell, rest[0])
        elif sub in ("exclude", "include") and len(rest) == 1:
            _include_or_exclude(shell, rest[0], include=sub == "include")
        elif sub == "clear" and set(rest) <= {"--yes"}:
            _clear(shell, rest)
        else:
            print_error(USAGE)
    except Exception as exc:  # noqa: BLE001 - the shell loop must survive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("The policy command failed.")


__all__ = [
    "USAGE",
    "announce_workspace_scan_controls",
    "fast_pace_notice",
    "pacing_label",
    "print_ci_scan_controls",
    "resolve_selector",
    "run_policy_command",
    "selectable_selectors",
    "use_choices",
]
