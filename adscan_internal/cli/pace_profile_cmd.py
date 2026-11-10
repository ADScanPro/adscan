"""Saved pace profiles on the command line: list, show, create, edit, save, use,
delete, export and import.

Two surfaces share this module and its handlers:

* the REPL ``pace`` verb, plus ``set pacing.profile <name>``, which is ``pace use``;
* the container command ``adscan pace``, which the launcher forwards verbatim
  (``PACE_PASSTHROUGH`` in :mod:`adscan_core.cli_passthrough_spec`). It runs the
  same actions; ``use`` and ``save`` act on a workspace, so they need
  ``--workspace`` (the host has no session).

Like the policy library, ``create`` and ``edit`` walk through the level and the
single settings when a person is at the keyboard and no flags are given (the
prompts are the shared ones in :mod:`adscan_internal.cli.pace_prompts`), and a
new profile asks whether it is saved in this workspace or for all workspaces
(:func:`adscan_internal.cli.library_common.resolve_save_scope`).

``adscan ci --pace-profile NAME`` resolves a profile through
:func:`resolve_ci_profile`.

A profile is a pace only. It is saved without a limit and held to the scan
policy's ceiling knob by knob whenever a scan uses it; every lowered value is
named. The store lives in :mod:`adscan_internal.services.saved_pace_profiles`.

Design: docs/superpowers/specs/2026-11-06-saved-pace-profiles-design.md.
"""

from __future__ import annotations

import argparse
import shlex
from dataclasses import dataclass, replace
from typing import Any

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
from adscan_core.scan_pacing import (
    KNOBS_BY_KEY,
    LEVEL_DESCRIPTIONS,
    ORDERED_LEVELS,
    PacingConfigError,
    PacingLevel,
    PaceProfile,
)
from adscan_internal.cli.library_common import (
    add_scope_argument,
    is_attended,
    require_workspace,
    resolve_save_scope,
    resolve_workspace_dir,
    write_export_file,
)
from adscan_internal.cli.pace_prompts import choose_pace
from adscan_internal.cli.scan_pacing_cmd import format_value
from adscan_internal.services import saved_pace_profiles as store
from adscan_internal.services.saved_pace_profiles import (
    SCOPE_GLOBAL,
    SCOPE_LABELS,
    SCOPE_WORKSPACE,
    SavedPaceProfile,
    SavedPaceProfileError,
)

#: Every action is available in both places; ``use`` and ``save`` need a workspace.
ACTIONS: tuple[str, ...] = (
    "list", "show", "create", "edit", "save", "use", "delete", "export", "import",
)
REPL_ACTIONS: tuple[str, ...] = ACTIONS
CONTAINER_ACTIONS: tuple[str, ...] = ACTIONS

from adscan_internal.cli.shell_commands import PACE_LONG_HELP  # noqa: E402 - the one help text


class _ReplParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise SavedPaceProfileError(message)


def _add_arguments(parser: argparse.ArgumentParser, *, actions: tuple[str, ...], container: bool) -> None:
    parser.add_argument("action", choices=list(actions), help="What to do.")
    parser.add_argument("target", nargs="?", default=None, help="Profile name (or a file, for import).")
    parser.add_argument(
        "--level",
        choices=[level.value for level in ORDERED_LEVELS],
        default=None,
        help="The profile's pace level (create). Default: the --from profile's, else normal.",
    )
    parser.add_argument(
        "--set",
        dest="settings",
        action="append",
        default=None,
        metavar="KNOB=VALUE",
        help="One pace setting (create), e.g. max_parallel_hosts=4. Repeatable; the same "
        "settings as 'adscan ci --pacing-set'.",
    )
    parser.add_argument(
        "--from", dest="source", default=None, metavar="PROFILE",
        help="Profile to start from (create).",
    )
    parser.add_argument("--description", default=None, metavar="TEXT", help="Description (create, edit, save, import).")
    parser.add_argument("--name", dest="new_name", default=None, metavar="NAME",
                        help="Save an imported profile under this name.")
    parser.add_argument("--output", "-o", default=None, metavar="FILE", help="Write the export to FILE.")
    parser.add_argument("--force", action="store_true", help="Replace a saved profile of the same name.")
    parser.add_argument("--yes", action="store_true", help="Delete without asking.")
    add_scope_argument(parser)
    if container:
        parser.add_argument(
            "--workspace", "-w", default=None, metavar="NAME",
            help="Use this workspace's profiles; create and import can save there, and "
            "'use' and 'save' act on it.",
        )
    else:
        parser.add_argument(
            "--global", dest="global_scope", action="store_true",
            help="Save to, or delete from, the profiles of all workspaces.",
        )


def repl_parser() -> argparse.ArgumentParser:
    parser = _ReplParser(prog="pace", add_help=False)
    _add_arguments(parser, actions=REPL_ACTIONS, container=False)
    return parser


def add_pace_subparser(subparsers: Any) -> argparse.ArgumentParser:
    """Register the container ``adscan pace`` subparser (mirrored by PACE_PASSTHROUGH)."""
    parser = subparsers.add_parser(
        "pace",
        help="Create and manage saved pace profiles: list, show, create, edit, delete, export, import, use.",
        description=(
            "Saved pace profiles: a named scan pace reused with any scan policy. "
            "A profile saved in a workspace wins over a global one of the same name."
        ),
    )
    _add_arguments(parser, actions=CONTAINER_ACTIONS, container=True)
    return parser


@dataclass
class ProfileContext:
    """Where profile subcommands read and write."""

    workspace_dir: str | None
    default_scope: str
    shell: Any = None
    container: bool = False
    host_shell: Any = None

    @property
    def session(self) -> Any:
        """Holds the workspace's current pace: the shell, or its host stand-in."""
        return self.shell if self.shell is not None else self.host_shell

    @property
    def attended(self) -> bool:
        return is_attended(self.shell)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def profile_summary(profile: PaceProfile) -> str:
    """``Polite, 2 settings`` for a list row."""
    label = LEVEL_DESCRIPTIONS[profile.level].label
    count = len(profile.overrides)
    if not count:
        return label
    return f"{label}, {count} setting{'s' if count != 1 else ''}"


def _settings_table(profile: PaceProfile) -> Table:
    table = Table(show_header=True, header_style=f"bold {BRAND_COLORS['info']}", box=None, pad_edge=False)
    # Fold, never truncate: at 80 columns a long setting name wraps onto a second
    # line instead of ending in an ellipsis.
    table.add_column("Setting", overflow="fold")
    table.add_column("Value", overflow="fold")
    table.add_column("The level alone gives", style="dim", overflow="fold")
    for key, value in profile.overrides.items():
        knob = KNOBS_BY_KEY.get(key)
        if knob is None:
            continue
        table.add_row(
            Text(f"{knob.label} ({key})"),
            Text(format_value(key, value), style="bold"),
            Text(format_value(key, knob.level_values.get(profile.level))),
        )
    return table


def render_profile(saved: SavedPaceProfile) -> None:
    profile = saved.profile
    head = Text()
    head.append("Pace profile: ", style="dim")
    head.append(f"{profile.name}\n", style="bold")
    if profile.description:
        head.append(f"{profile.description}\n")
    head.append("Saved: ", style="dim")
    head.append(f"{SCOPE_LABELS[saved.scope]}, revision {profile.revision}\n")
    head.append("Level: ", style="dim")
    head.append(f"{LEVEL_DESCRIPTIONS[profile.level].label}. {LEVEL_DESCRIPTIONS[profile.level].summary}\n")
    head.append(
        "\nA scan under a policy that allows less runs slower: each value above the "
        "policy's limit is lowered to it and named.",
        style="dim",
    )
    print_panel(head, title="[bold]Pace profile[/bold]", expand=False)
    if profile.overrides:
        print_table(_settings_table(profile))
    else:
        print_info("Every setting takes the level's value.")


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


def _save_scope(ctx: ProfileContext, args: argparse.Namespace) -> str | None:
    """Where this profile is saved: ``--scope``/``--global``, else ask or fall back.

    Returns ``None`` when the user cancels the question. The same rule the
    policy library applies (:func:`library_common.resolve_save_scope`).
    """
    explicit = getattr(args, "scope", None) or (
        SCOPE_GLOBAL if getattr(args, "global_scope", False) else None
    )
    return resolve_save_scope(
        noun="pace profile",
        workspace_dir=ctx.workspace_dir,
        explicit=explicit,
        shell=ctx.shell,
        attended=ctx.attended,
        host=ctx.container,
        error=SavedPaceProfileError,
    )


def _cmd_list(ctx: ProfileContext, _args: argparse.Namespace) -> None:
    profiles = store.list_profiles(ctx.workspace_dir, include_shadowed=True)
    current = _current_profile_name(ctx.session)
    if not profiles:
        print_info("No pace profile is saved yet.")
    else:
        table = Table(show_header=True, header_style=f"bold {BRAND_COLORS['info']}", box=None, pad_edge=False)
        table.add_column("")
        table.add_column("Profile", overflow="fold")
        table.add_column("Saved", overflow="fold")
        table.add_column("Pace", overflow="fold")
        table.add_column("Description", style="dim", overflow="fold")
        for saved in profiles:
            style = "dim" if saved.shadowed else ""
            where = SCOPE_LABELS[saved.scope] + (
                ", hidden by the workspace profile" if saved.shadowed else ""
            )
            marker = "●" if current and current.lower() == saved.name.lower() and not saved.shadowed else ""
            table.add_row(
                Text(marker, style=BRAND_COLORS["info"]),
                Text(saved.name, style=style or "bold"),
                Text(where, style="dim"),
                Text(profile_summary(saved.profile), style=style),
                Text(saved.profile.description),
            )
        print_table(table)
        if current:
            print_instruction("● is the profile this workspace's pace started from.")
    for path, reason in store.unreadable_profile_files(ctx.workspace_dir):
        print_warning(f"Skipped {escape(str(path))}: {escape(reason)}")
    if ctx.container:
        print_instruction("Run a scan with one: adscan ci ... --pace-profile <name>")
        if not ctx.workspace_dir:
            print_instruction("Add --workspace NAME to list that workspace's profiles too.")
    else:
        print_instruction("Use one here with: pace use <name>. Save the current pace with: pace save <name>")


def _cmd_show(ctx: ProfileContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPaceProfileError("Name the profile to show: pace show <name>.")
    render_profile(store.require_profile(args.target, ctx.workspace_dir))


def _validate_pace_block(parsed: dict[str, Any]) -> None:
    """A profile has no limit at save time; the block must still be a valid pace."""
    from adscan_internal.services.scan_controls import parse_pacing_assignments  # noqa: PLC0415

    try:
        parse_pacing_assignments([f"{k}={v}" for k, v in (parsed.get("overrides") or {}).items()])
    except PacingConfigError as exc:
        raise SavedPaceProfileError(str(exc)) from exc


def _profile_from_prompts(ctx: ProfileContext, base: PaceProfile) -> PaceProfile | None:
    """Walk through the level and the single settings, starting from ``base``."""
    keep: dict[str, Any] = {"level": base.level.value}
    if base.overrides:
        keep["overrides"] = dict(base.overrides)
    pacing = choose_pace(
        ctx.shell,
        keep=keep,
        keep_label=profile_summary(base),
        title="Pace level (a scan under a policy that allows less runs slower, and the "
        "lowered values are named).",
        validate=_validate_pace_block,
    )
    if pacing is None:
        return None
    level = PacingLevel.coerce(pacing.get("level")) or base.level
    overrides = _typed_overrides(pacing.get("overrides"))
    return replace(base, level=level, overrides=overrides)


def _typed_overrides(raw: Any) -> dict[str, Any]:
    from adscan_internal.services.scan_controls import parse_pacing_assignments  # noqa: PLC0415

    try:
        return parse_pacing_assignments([f"{k}={v}" for k, v in (raw or {}).items()])
    except PacingConfigError as exc:
        raise SavedPaceProfileError(str(exc)) from exc


def _profile_from_flags(ctx: ProfileContext, args: argparse.Namespace, base: PaceProfile | None = None) -> PaceProfile:
    from adscan_internal.services.scan_controls import parse_pacing_assignments  # noqa: PLC0415

    level = PacingLevel.NORMAL
    overrides: dict[str, Any] = {}
    description = ""
    source = base
    if source is None and args.source:
        source = store.require_profile(args.source, ctx.workspace_dir).profile
    if source is not None:
        level = source.level
        overrides = dict(source.overrides)
        description = source.description
    if args.level:
        level = PacingLevel.coerce(args.level) or level
    try:
        overrides.update(parse_pacing_assignments(args.settings))
    except PacingConfigError as exc:
        raise SavedPaceProfileError(str(exc)) from exc
    return PaceProfile(
        name=base.name if base is not None else args.target,
        level=level,
        overrides=overrides,
        description=args.description if args.description is not None else description,
    )


def _flags_given(args: argparse.Namespace) -> bool:
    return bool(args.level or args.settings)


def _cmd_create(ctx: ProfileContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPaceProfileError("Name the new profile: pace create <name> --level <level>.")
    interactive = ctx.attended and not (_flags_given(args) or args.source)
    if not (_flags_given(args) or args.source or interactive):
        hint = (
            "or tune the pace with 'set pacing' and 'set pacing.<setting>' and save it with "
            "'pace save <name>'."
            if not ctx.container
            else "for example: adscan pace create 'Slow WAN site' --level polite "
            "--set max_parallel_hosts=4"
        )
        raise SavedPaceProfileError(f"Give the pace with --level and --set, {hint}")
    scope = _save_scope(ctx, args)
    if scope is None:
        print_info("No pace profile was created.")
        return
    profile = _profile_from_flags(ctx, args)
    if interactive:
        profile = _profile_from_prompts(ctx, profile)
        if profile is None:
            print_info("No pace profile was created.")
            return
    saved = store.save_profile(
        profile, scope=scope, workspace_dir=ctx.workspace_dir, overwrite=bool(args.force),
    )
    print_success(
        f"Saved the pace profile '{escape(saved.name)}' for {SCOPE_LABELS[saved.scope]}: "
        f"{profile_summary(saved.profile)}."
    )
    print_instruction(
        f"Run a scan with it: adscan ci ... --pace-profile {shlex.quote(saved.name)}"
        if ctx.container
        else f"Use it here with: pace use {shlex.quote(saved.name)}"
    )


def _cmd_edit(ctx: ProfileContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPaceProfileError("Name the profile to edit: pace edit <name>.")
    existing = store.require_profile(args.target, ctx.workspace_dir)
    interactive = ctx.attended and not (_flags_given(args) or args.description is not None)
    if not (_flags_given(args) or args.description is not None or interactive):
        raise SavedPaceProfileError(
            "Say what to change with --level, --set or --description "
            + ("(adscan pace edit NAME --level polite)." if ctx.container else "(pace edit NAME --level polite).")
        )
    profile = _profile_from_flags(ctx, args, base=existing.profile)
    if interactive:
        profile = _profile_from_prompts(ctx, profile)
        if profile is None:
            print_info(f"'{escape(existing.name)}' was not changed.")
            return
    saved = store.save_profile(
        profile, scope=existing.scope, workspace_dir=ctx.workspace_dir, overwrite=True,
    )
    print_success(
        f"Saved revision {saved.profile.revision} of the pace profile '{escape(saved.name)}' "
        f"({SCOPE_LABELS[saved.scope]}): {profile_summary(saved.profile)}."
    )
    print_info("A scan that already took the profile keeps the pace it took; the next one uses this revision.")


def _cmd_save(ctx: ProfileContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPaceProfileError("Name the profile: pace save <name>.")
    from adscan_internal.services.scan_controls import workspace_pacing_request  # noqa: PLC0415

    require_workspace(ctx.workspace_dir, what="Saving a workspace's pace", error=SavedPaceProfileError)
    session = ctx.session
    request = workspace_pacing_request(session) if session is not None else None
    if request is None:
        raise SavedPaceProfileError(
            "No scan pace was set"
            + (" in this workspace" if ctx.container else " in this shell")
            + ". Set one with "
            + ("'adscan pace use NAME --workspace NAME'" if ctx.container else "'set pacing <level>' or 'set pacing.<setting> <value>'")
            + ", then save it with 'pace save <name>'."
        )
    scope = _save_scope(ctx, args)
    if scope is None:
        print_info("The pace was not saved.")
        return
    profile = PaceProfile(
        name=args.target,
        level=request.level,
        overrides=dict(request.overrides),
        description=args.description or "",
    )
    saved = store.save_profile(
        profile, scope=scope, workspace_dir=ctx.workspace_dir, overwrite=bool(args.force)
    )
    print_success(
        f"Saved this {'workspace' if ctx.container else 'shell'}'s pace as the profile "
        f"'{escape(saved.name)}' for {SCOPE_LABELS[saved.scope]}: {profile_summary(saved.profile)}."
    )
    # The other target for the same pace: inside a scan policy, where it is
    # the policy's default and its limit (the policy library owns that path).
    print_instruction(
        "To keep it inside a scan policy instead, as that policy's pace and limit: "
        "policy create <name> --pacing-from-session"
    )


def use_profile(shell: Any, name: str) -> bool:
    """Apply a saved profile to the workspace pace (``pace use``, ``set pacing.profile``).

    ``shell`` is the REPL shell, or the host stand-in
    (:class:`~adscan_internal.cli.library_common.HostWorkspaceShell`) for
    ``adscan pace use NAME --workspace W``: the same code path either way.
    """
    from adscan_internal.services.scan_controls import (  # noqa: PLC0415
        apply_pace_profile,
        profile_lowered_message,
        session_pacing_ceiling,
    )

    from adscan_internal.cli.scan_policy_cmd import fast_pace_notice  # noqa: PLC0415

    token = str(name or "").strip()
    if not token:
        print_error("Name the pace profile: pace use <name>.")
        return False
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "") or None
    try:
        saved = store.require_profile(token, workspace_dir)
    except SavedPaceProfileError as exc:
        print_error(escape(str(exc)))
        return False
    if (
        saved.profile.level == PacingLevel.FAST
        and not confirm_ask(f"{fast_pace_notice()} Use the profile '{saved.name}'?", False)
    ):
        print_info("The scan pace is unchanged.")
        return False
    resolved, fitted = apply_pace_profile(shell, saved.profile)
    saver = getattr(shell, "save_workspace_data", None)
    if callable(saver) and getattr(shell, "current_workspace_dir", None):
        saver()
    else:
        print_warning("No workspace is open: the scan pace applies to this session only.")
    print_success(
        f"Scan pace set from the profile '{escape(saved.name)}': "
        f"{LEVEL_DESCRIPTIONS[resolved.level].label}."
    )
    message = profile_lowered_message(fitted, session_pacing_ceiling(shell))
    if message:
        print_warning(escape(message))
    print_instruction("Review every value with: show pacing")
    return True


def _cmd_use(ctx: ProfileContext, args: argparse.Namespace) -> bool:
    if not args.target:
        raise SavedPaceProfileError("Name the profile: pace use <name>.")
    if ctx.shell is None:
        require_workspace(ctx.workspace_dir, what="Using a pace profile", error=SavedPaceProfileError)
    return use_profile(ctx.session, args.target)


def _cmd_delete(ctx: ProfileContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPaceProfileError("Name the profile to delete.")
    scope = getattr(args, "scope", None) or (SCOPE_GLOBAL if getattr(args, "global_scope", False) else None)
    saved = store.find_profile(args.target, ctx.workspace_dir, scope=scope)
    if saved is None:
        raise SavedPaceProfileError(f"No pace profile named '{args.target}'.")
    if not getattr(args, "yes", False) and not confirm_ask(
        f"Delete the pace profile '{saved.name}' ({SCOPE_LABELS[saved.scope]})?", False
    ):
        print_info("The profile was kept.")
        return
    store.delete_profile(saved.name, workspace_dir=ctx.workspace_dir, scope=saved.scope)
    print_success(f"Deleted the pace profile '{escape(saved.name)}' ({SCOPE_LABELS[saved.scope]}).")
    current = _current_profile_name(ctx.session)
    if current and current.lower() == saved.name.lower():
        print_info("This workspace keeps the pace it took from the profile until you change it.")


def _cmd_export(ctx: ProfileContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPaceProfileError("Name the profile to export: pace export <name>.")
    saved = store.require_profile(args.target, ctx.workspace_dir)
    text = store.dump_profile_yaml(saved.profile)
    if args.output:
        shown = write_export_file(args.output, text, error=SavedPaceProfileError)
        print_success(f"Exported the pace profile '{escape(saved.name)}' to {escape(shown)}.")
        return
    from adscan_core.output._state import get_console  # noqa: PLC0415

    get_console().print(Text(text.rstrip("\n")), markup=False, highlight=False, soft_wrap=True)


def _cmd_import(ctx: ProfileContext, args: argparse.Namespace) -> None:
    if not args.target:
        raise SavedPaceProfileError("Name the file to import: pace import <file>.")
    document = store.read_profile_file(args.target)
    scope = _save_scope(ctx, args)
    if scope is None:
        print_info("Nothing was imported.")
        return
    profile = replace(
        document,
        name=args.new_name or document.name,
        description=args.description if args.description is not None else document.description,
    )
    saved = store.save_profile(
        profile, scope=scope, workspace_dir=ctx.workspace_dir, overwrite=bool(args.force)
    )
    print_success(
        f"Imported the pace profile '{escape(saved.name)}' for {SCOPE_LABELS[saved.scope]}: "
        f"{profile_summary(saved.profile)}."
    )


def _current_profile_name(shell: Any) -> str:
    request = getattr(shell, "scan_pacing_request", None) if shell is not None else None
    profile = getattr(request, "profile", None)
    return str(getattr(profile, "name", "") or "")


_HANDLERS = {
    "list": _cmd_list,
    "show": _cmd_show,
    "create": _cmd_create,
    "edit": _cmd_edit,
    "save": _cmd_save,
    "use": _cmd_use,
    "delete": _cmd_delete,
    "export": _cmd_export,
    "import": _cmd_import,
}


def run_action(ctx: ProfileContext, args: argparse.Namespace) -> bool:
    """Run one subcommand; returns False (after telling the user) on a user error."""
    try:
        return _HANDLERS[args.action](ctx, args) is not False
    except SavedPaceProfileError as exc:
        print_error(escape(str(exc)))
        return False


def run_repl_command(shell: Any, line: str) -> None:
    """The REPL ``pace`` verb."""
    try:
        tokens = shlex.split(line or "")
    except ValueError as exc:
        print_error(escape(str(exc)))
        return
    if not tokens:
        print_info(PACE_LONG_HELP.split("\n\n", 1)[0])
        return
    try:
        args = repl_parser().parse_args(tokens)
    except SavedPaceProfileError as exc:
        print_error(escape(str(exc)))
        return
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "") or None
    run_action(
        ProfileContext(
            workspace_dir=workspace_dir,
            default_scope=SCOPE_WORKSPACE if workspace_dir else SCOPE_GLOBAL,
            shell=shell,
        ),
        args,
    )


def handle_pace_command(args: argparse.Namespace) -> int:
    """``adscan pace ...`` (container). Exit code 0 on success, 2 on a user error."""
    try:
        try:
            workspace_dir = resolve_workspace_dir(args.workspace, error=SavedPaceProfileError)
        except SavedPaceProfileError as exc:
            print_error(escape(str(exc)))
            return 2
        host_shell = None
        if workspace_dir:
            from adscan_internal.cli.library_common import HostWorkspaceShell  # noqa: PLC0415

            host_shell = HostWorkspaceShell(workspace_dir)
        ctx = ProfileContext(
            workspace_dir=workspace_dir,
            default_scope=SCOPE_WORKSPACE if workspace_dir else SCOPE_GLOBAL,
            container=True,
            host_shell=host_shell,
        )
        return 0 if run_action(ctx, args) else 2
    except Exception as exc:  # noqa: BLE001 - one command, one exit code
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("The pace command failed.")
        return 1


def resolve_ci_profile(name: str | None, workspace_dir: str | None) -> PaceProfile | None:
    """``adscan ci --pace-profile NAME``: the profile, or ``None`` when not given.

    Raises:
        SavedPaceProfileError: An unknown name, listing the profiles that exist.
    """
    token = str(name or "").strip()
    if not token:
        return None
    return store.require_profile(token, workspace_dir).profile


__all__ = [
    "ACTIONS",
    "CONTAINER_ACTIONS",
    "PACE_LONG_HELP",
    "REPL_ACTIONS",
    "add_pace_subparser",
    "handle_pace_command",
    "profile_summary",
    "render_profile",
    "repl_parser",
    "resolve_ci_profile",
    "run_action",
    "run_repl_command",
    "use_profile",
]
