"""Workspace CLI helpers.

This module extracts the interactive workspace management logic from `adscan.py`
so the main CLI stays a thin orchestrator.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import os
from typing import Any, Protocol

from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    BRAND_COLORS,
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_instruction,
    print_panel,
    print_success,
    print_table,
    print_warning,
    prompt_ask,
)


class WorkspaceShell(Protocol):
    """Protocol for the legacy CLI shell workspace functions."""

    workspaces_dir: str
    current_workspace: str | None
    current_workspace_dir: str | None
    current_domain: str | None
    variables: dict[str, Any] | None

    def ensure_workspaces_dir(self) -> None: ...

    def _questionary_select(
        self, question: str, options: Sequence[str]
    ) -> int | None: ...

    def load_workspace_data(self, workspace_path: str) -> None: ...

    def save_workspace_data(self) -> None: ...

    def domain_save(self) -> None: ...


@dataclass(frozen=True)
class WorkspaceSelectionOption:
    """Workspace selection option for interactive prompts."""

    name: str
    is_create_new: bool = False


def _default_workspace_name(workspaces_dir: str) -> str:
    """Return a sensible, non-colliding default workspace name.

    Uses a date-stamped ``audit-YYYY-MM-DD`` base so a brand-new operator can
    press Enter at the name prompt and proceed without inventing a name. When
    that base already exists, a numeric suffix (``-2``, ``-3``, ...) is appended
    until a free name is found. This is the single source of truth for the
    pre-filled default across every workspace-name prompt.

    Args:
        workspaces_dir: Directory that holds the operator's workspaces.
    """
    from datetime import date

    try:
        from adscan_internal.workspaces import list_workspaces

        existing = set(list_workspaces(workspaces_dir))
    except Exception:  # noqa: BLE001 - a naming default must never block creation
        existing = set()

    base = f"audit-{date.today().isoformat()}"
    if base not in existing:
        return base
    suffix = 2
    while f"{base}-{suffix}" in existing:
        suffix += 1
    return f"{base}-{suffix}"


def _prompt_for_new_workspace_name(shell: WorkspaceShell) -> str:
    """Prompt for a new workspace name with an empty, editable input.

    Shows the one-time "what is a workspace" explainer for a brand-new operator
    (no workspaces yet), then renders a name prompt suggesting
    :func:`_default_workspace_name` as a hint. The operator can start typing
    their own name immediately — the suggested default is never inserted as
    pre-existing text they would have to delete first (``prefill_default=False``).
    Pressing Enter on an empty input still accepts the suggested default; a
    non-interactive run auto-resolves to it without blocking. Returns the
    stripped name, or an empty string when the operator cancels.
    """
    try:
        from adscan_internal.cli.first_run_panel import maybe_show_workspace_explainer

        maybe_show_workspace_explainer(shell.workspaces_dir)
    except Exception:  # noqa: BLE001 - orientation panel must never block creation
        pass

    default_name = _default_workspace_name(shell.workspaces_dir)
    answer = prompt_ask(
        "Enter name for a new workspace",
        default=default_name,
        shell=shell,
        prefill_default=False,
    )
    return (answer or "").strip()


def _confirm_workspace_delete(workspace_name: str) -> bool:
    """Return True only when the operator types the exact workspace name.

    Args:
        workspace_name: Workspace name that must be typed to confirm deletion.
    """
    marked_workspace_name = mark_sensitive(workspace_name, "workspace")
    print_warning(
        f"Deleting workspace '{marked_workspace_name}' will permanently remove its local data."
    )
    print_instruction("Type the exact workspace name to confirm deletion.")
    confirmation = Prompt.ask(
        Text("Workspace name: ", style="input"),
        default="",
        show_default=False,
    ).strip()
    return confirmation == workspace_name


def do_workspace(shell: WorkspaceShell, args: str) -> None:
    """Handle `workspace` subcommands.

    Args:
        shell: Legacy CLI shell instance.
        args: Raw argument string after the `workspace` command.
    """
    if not args:
        print_instruction("Usage: workspace <create|delete|purge-secrets|select|show|save|list>")
        if shell.current_workspace:
            marked_current_workspace_dir = mark_sensitive(
                shell.current_workspace_dir or "", "path"
            )
            print_success(f"Current workspace: {marked_current_workspace_dir}")
        else:
            print_warning("No workspace selected.")
        workspace_list(shell)
        return

    command, *sub_args = args.split()

    if command == "create":
        workspace_create(shell, sub_args[0] if sub_args else None)
    elif command == "delete":
        workspace_delete(shell, sub_args[0] if sub_args else "")
    elif command == "purge-secrets":
        workspace_purge_secrets(shell, sub_args)
    elif command == "select":
        workspace_select(shell)
    elif command == "show":
        workspace_show(shell)
    elif command == "save":
        workspace_save(shell)
    elif command == "list":
        workspace_list(shell)
    else:
        # Mirror the friendly, guidance-bearing hint the main REPL gives for an
        # unknown command (warning + did-you-mean + next step), rather than a
        # hard `✗` error — a mistyped subcommand is a near miss, not a failure.
        from rich.markup import escape as _rich_escape
        import difflib

        valid_commands = ["create", "delete", "purge-secrets", "select", "show", "save", "list"]
        print_warning(
            f"`workspace {_rich_escape(command)}` is not a recognized workspace command."
        )
        close = difflib.get_close_matches(command, valid_commands, n=1, cutoff=0.6)
        if close:
            print_info(
                f"Did you mean `workspace {close[0]}`? Type `workspace {close[0]}` to run it."
            )
        print_instruction(
            "Available commands: create, delete, purge-secrets, select, show, save, list. "
            "Type `help` for the full command list."
        )


def workspace_list(shell: WorkspaceShell) -> None:
    """List all available workspaces using a Rich table."""
    shell.ensure_workspaces_dir()
    try:
        from adscan_internal.workspaces import list_workspaces

        workspaces = list_workspaces(shell.workspaces_dir)
    except FileNotFoundError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"Workspaces directory not found at: {shell.workspaces_dir}")
        return
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            f"Error accessing workspaces directory {shell.workspaces_dir}: {exc}"
        )
        return

    if not workspaces:
        print_warning("No workspaces found.")
        print_instruction("Create one using: workspace create <name>")
        return

    table = Table(
        title="[bold]Available Workspaces[/bold]",
        show_header=True,
        header_style=f"bold {BRAND_COLORS['info']}",
        border_style=BRAND_COLORS["info"],
    )
    table.add_column("Name", min_width=20, overflow="fold")
    table.add_column("Status", style="yellow", width=10)
    table.add_column("Path", style="dim", overflow="fold")

    sorted_workspaces = sorted(
        workspaces, key=lambda ws: (ws != shell.current_workspace, ws)
    )
    for ws_name in sorted_workspaces:
        ws_path = os.path.join(shell.workspaces_dir, ws_name)
        marked_workspace_name = mark_sensitive(ws_name, "workspace")
        marked_workspace_path = mark_sensitive(ws_path, "path")
        status = (
            "[bold green]Active[/bold green]"
            if ws_name == shell.current_workspace
            else "Inactive"
        )
        table.add_row(marked_workspace_name, status, marked_workspace_path)

    print_table(table)


def workspace_policy_choices() -> list[Any]:
    """The policies a new workspace may start with: Lab / CTF, Audit, then saved global ones.

    The policy's environment is the workspace type (``scan_controls.workspace_type``),
    so choosing the policy is choosing whether the workspace is a lab or a real
    environment. Other built-ins remain one ``policy use`` away.
    """
    from adscan_core.scan_policy.policy import BASE_AUDIT, BASE_LAB_CTF  # noqa: PLC0415
    from adscan_internal.services import saved_scan_policies as store  # noqa: PLC0415

    choices = []
    for policy in store.list_policies(None):
        if policy.scope == store.SCOPE_BUILTIN:
            if policy.key in (BASE_LAB_CTF, BASE_AUDIT):
                choices.append(policy)
        elif policy.scope == store.SCOPE_GLOBAL:
            choices.append(policy)
    order = {BASE_LAB_CTF: 0, BASE_AUDIT: 1}
    return sorted(choices, key=lambda p: order.get(p.key, 2) if p.scope == store.SCOPE_BUILTIN else 2)


def workspace_policy_label(policy: Any) -> str:
    """``Lab / CTF``, ``Audit``, or ``<name> (saved, real environment)``."""
    from adscan_core.scan_policy.policy import (  # noqa: PLC0415
        ENVIRONMENT_LABELS,
        effective_environment,
    )
    from adscan_internal.services import saved_scan_policies as store  # noqa: PLC0415

    if policy.scope == store.SCOPE_BUILTIN:
        return policy.name
    environment = ENVIRONMENT_LABELS[effective_environment(policy.definition)].lower()
    return f"{policy.name} (saved, {environment})"


def prompt_workspace_policy(shell: Any, *, title: str = "Scan policy for this workspace?") -> Any | None:
    """Ask which policy a workspace starts with; ``None`` when cancelled.

    Unattended, the first choice (Lab / CTF) is taken, as the purpose question
    this replaces did.
    """
    choices = workspace_policy_choices()
    if not choices:
        return None
    selection = shell._questionary_select(title, [workspace_policy_label(p) for p in choices])
    if selection is None:
        return None
    return choices[int(selection)]


def install_workspace_policy(workspace_path: str, definition: Any) -> None:
    """Persist ``definition`` as the workspace's scan policy before the workspace loads."""
    from adscan_internal.services.scan_controls import (  # noqa: PLC0415
        SOURCE_WORKSPACE,
        resolve_definition,
        save_workspace_policy,
    )

    save_workspace_policy(
        workspace_path,
        resolve_definition(definition, strict=False),
        source=SOURCE_WORKSPACE,
    )


def workspace_create(shell: WorkspaceShell, workspace_name: str | None = None) -> None:
    """Create a new workspace and load it.

    Args:
        shell: Legacy CLI shell instance.
        workspace_name: Optional workspace name. When omitted, the user is prompted.
    """
    if not workspace_name:
        workspace_name = _prompt_for_new_workspace_name(shell)
        if not workspace_name:
            print_warning("Workspace creation cancelled.")
            return

    from adscan_internal.workspaces import (
        create_workspace_dir,
        resolve_workspace_paths,
        write_initial_workspace_variables,
    )

    workspace_path = resolve_workspace_paths(shell.workspaces_dir, workspace_name).root
    if os.path.exists(workspace_path):
        print_error(f"Workspace '{workspace_name}' already exists at {workspace_path}")
        return

    # One question only: the scan policy. Its environment (lab or real) is the
    # workspace type, so it decides the scan flow and the telemetry split.
    # Lab provider/name are inferred automatically at scan start from the domain.
    from adscan_core.scan_policy.policy import (  # noqa: PLC0415
        BASE_LAB_CTF,
        builtin_definition,
        workspace_type_for_definition,
    )

    chosen_policy = prompt_workspace_policy(shell)
    if chosen_policy is not None:
        policy_definition = chosen_policy.definition
    else:
        # Cancelled: Lab / CTF, as the purpose question defaulted to CTF.
        policy_definition = builtin_definition(BASE_LAB_CTF)
    workspace_type = workspace_type_for_definition(policy_definition) or "ctf"

    try:
        create_workspace_dir(shell.workspaces_dir, workspace_name)
        marked_workspace_name = mark_sensitive(workspace_name, "workspace")
        print_success(
            f"Workspace '{marked_workspace_name}' created at {workspace_path}"
        )

        write_initial_workspace_variables(
            workspace_name=workspace_name,
            workspace_path=workspace_path,
            workspace_type=workspace_type,
        )
        install_workspace_policy(workspace_path, policy_definition)
        print_info_verbose(
            f"Initialized files for workspace '{marked_workspace_name}'."
        )

        from adscan_internal.workspaces.session import (  # noqa: PLC0415
            activate_workspace as _activate_workspace,
        )

        _activate_workspace(
            shell, workspaces_dir=shell.workspaces_dir, workspace_name=workspace_name
        )
        shell.load_workspace_data(workspace_path)
        print_success(
            f"Workspace '{marked_workspace_name}' created and loaded successfully."
        )
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error(f"Failed to create workspace '{workspace_name}': {exc}")
        print_exception(show_locals=False, exception=exc)


def workspace_delete(shell: WorkspaceShell, workspace_name: str) -> None:
    """Delete an existing workspace."""
    if not workspace_name:
        print_error("Workspace name cannot be empty.")
        print_instruction("Usage: workspace delete <workspace_name>")
        return

    from adscan_internal.workspaces import delete_workspace_dir, resolve_workspace_paths

    # Before the first line this command logs: the open workspace's logs must
    # never carry the name of the one being deleted. The screen still shows it.
    from adscan_core.telemetry import forget_workspace_name  # noqa: PLC0415

    forget_workspace_name(workspace_name)
    workspace_path = resolve_workspace_paths(shell.workspaces_dir, workspace_name).root
    if not os.path.exists(workspace_path):
        print_error(f"Workspace '{workspace_name}' does not exist at {workspace_path}")
        return

    if shell.current_workspace_dir == workspace_path:
        marked_workspace_name = mark_sensitive(workspace_name, "workspace")
        print_warning(
            f"Workspace '{marked_workspace_name}' is currently active. Please select another workspace before deleting it."
        )
        return

    if not _confirm_workspace_delete(workspace_name):
        marked_workspace_name = mark_sensitive(workspace_name, "workspace")
        print_warning(f"Workspace '{marked_workspace_name}' deletion cancelled.")
        return

    try:
        delete_workspace_dir(shell.workspaces_dir, workspace_name)
        marked_workspace_name = mark_sensitive(workspace_name, "workspace")
        print_success(
            f"Workspace '{marked_workspace_name}' deleted from {workspace_path}"
        )
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error(f"Failed to delete workspace '{workspace_name}': {exc}")
        print_exception(show_locals=False, exception=exc)


PURGE_USAGE = (
    "Usage: workspace purge-secrets [workspace_name] "
    "[--keep-starting-credential] [--delete-deliverables]"
)


def _purge_confirmation_lines(deliverables: list[str], *, keep_starting: bool, delete_deliverables: bool) -> list[str]:
    """What the operator is told before confirming (removed, kept, not changed)."""
    lines = [
        "Removes every password, hash, Kerberos key, ticket and certificate this workspace "
        "recorded, from its credential store and from every file. Logs are emptied.",
        "Keeps the findings, attack paths, asset inventory and engagement history, so the "
        "next scan can still be compared with this one.",
    ]
    if keep_starting:
        lines.append("The credential the scans started from is kept. Nothing else is.")
    else:
        lines.append(
            "The credential the scans started from is removed as well. Pass "
            "--keep-starting-credential to keep it."
        )
    if deliverables and delete_deliverables:
        lines.append(f"The rendered reports in this workspace are deleted too ({len(deliverables)}).")
    elif deliverables:
        lines.append(
            f"The rendered reports in this workspace ({len(deliverables)}) stay as they are. They cannot be edited and "
            "may contain recovered secrets. Pass --delete-deliverables to delete them, or "
            "remove the copies you shared yourself."
        )
    return lines


def _clear_loaded_credential_store(shell: Any, *, keep_starting: bool) -> None:
    """Empty the credential store the session holds in memory, then save it.

    Purging the active workspace on disk alone would let the next autosave write
    the session's copy of the store back.
    """
    from adscan_core.workspace_secret_purge import clear_credential_store  # noqa: PLC0415

    view: dict[str, Any] = {
        "domains_data": getattr(shell, "domains_data", None) or {},
        "username": getattr(shell, "username", None),
        "password": getattr(shell, "password", None),
        "hash": getattr(shell, "hash", None),
    }
    clear_credential_store(view, keep_starting_credential=keep_starting)
    for key in ("password", "hash"):
        if key not in view and hasattr(shell, key):
            setattr(shell, key, None)
    shell.save_workspace_data()


def workspace_purge_secrets(shell: Any, args: Sequence[str]) -> None:
    """Remove every recovered secret from a workspace and keep its history.

    Defaults to the active workspace. The operator confirms by typing the
    workspace name, and the purge is recorded under the operator's name.
    """
    from adscan_core import workspace_secret_purge as purge  # noqa: PLC0415
    from adscan_internal.services.operator_identity import command_line_operator_name  # noqa: PLC0415
    from adscan_internal.workspaces import resolve_workspace_paths  # noqa: PLC0415

    flags = {a for a in args if a.startswith("--")}
    names = [a for a in args if not a.startswith("--")]
    unknown = flags - {"--keep-starting-credential", "--delete-deliverables"}
    if unknown or len(names) > 1:
        print_instruction(PURGE_USAGE)
        return
    keep_starting = "--keep-starting-credential" in flags
    delete_deliverables = "--delete-deliverables" in flags
    workspace_name = names[0] if names else (shell.current_workspace or "")
    if not workspace_name:
        print_error("No workspace selected.")
        print_instruction(PURGE_USAGE)
        return
    workspace_path = resolve_workspace_paths(shell.workspaces_dir, workspace_name).root
    marked = mark_sensitive(workspace_name, "workspace")
    if not os.path.isdir(workspace_path):
        print_error(f"Workspace '{marked}' does not exist.")
        return
    active = shell.current_workspace_dir == workspace_path
    if active:
        registry = getattr(shell, "_background_jobs", None)
        if registry is not None and registry.has_active_jobs():
            print_warning(
                "No secrets were removed. A background job is still running in this "
                "workspace. List it with 'jobs' and stop it with 'jobs stop <id>' first."
            )
            return

    deliverables = purge.find_rendered_deliverables(workspace_path)
    print_panel(
        "\n\n".join(
            _purge_confirmation_lines(
                deliverables, keep_starting=keep_starting, delete_deliverables=delete_deliverables
            )
        ),
        title=f"Remove recovered secrets from {marked}",
    )
    if not _confirm_typed_workspace_name(shell, workspace_name):
        print_warning("Cancelled. Nothing was removed.")
        return
    operator = command_line_operator_name(
        shell,
        prompt_text="Your name, recorded with the removal in the workspace history",
        prompt=prompt_ask,
    )
    if not operator:
        print_warning("Cancelled. A name is required to record who removed the secrets.")
        return

    options = purge.PurgeOptions(
        keep_starting_credential=keep_starting,
        delete_deliverables=delete_deliverables,
        allow_own_lock=active,
    )
    try:
        if active:
            _clear_loaded_credential_store(shell, keep_starting=keep_starting)
        result = purge.purge_workspace_secrets(
            workspace_path,
            operator=operator,
            surface=purge.SURFACE_CLI,
            options=options,
            workspaces_dir=shell.workspaces_dir,
        )
    except purge.PurgeRefused as exc:
        print_warning(f"No secrets were removed. {exc.reason.capitalize()}.")
        return
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("The secret removal stopped part way. Run it again to finish it.")
        return
    _print_purge_result(result)


def _print_purge_result(result: Any) -> None:
    """Summarise a finished purge, including what it could not remove."""
    print_success(
        f"Recovered secrets removed. Files deleted {len(result.files_deleted)}, rewritten "
        f"{len(result.files_rewritten)}, logs emptied {len(result.logs_cleared)}, credential "
        f"store entries removed {result.store_entries_removed}."
    )
    collisions = result.secrets_not_substituted.get("equals_an_identifier", 0)
    if collisions:
        print_warning(
            f"Recovered passwords equal to an account or host name, {collisions}. They stay "
            "wherever that name appears, because removing them would remove the name."
        )
    short = result.secrets_not_substituted.get("shorter_than_minimum_replaced_whole_only", 0)
    if short:
        print_warning(
            f"Recovered values shorter than six characters, {short}. They were removed "
            "where they stand alone, not inside longer text."
        )
    for item in result.remaining:
        print_warning(
            f"{mark_sensitive(item.get('path', ''), 'path')} was not changed "
            f"({str(item.get('reason', '')).replace('_', ' ')})."
        )
    kept_reports = [d for d in result.deliverables if d not in result.deliverables_deleted]
    if kept_reports:
        print_warning(
            f"Rendered reports left unchanged, {len(kept_reports)}. They may contain "
            "recovered secrets, and so may any copy already shared."
        )
    if result.deliverables_deleted:
        print_info(f"Rendered reports deleted, {len(result.deliverables_deleted)}.")
    if result.execution_workspaces_purged:
        print_info(
            f"Copies of this workspace left by earlier scans cleaned too, "
            f"{len(result.execution_workspaces_purged)}."
        )


def _confirm_typed_workspace_name(shell: Any, workspace_name: str) -> bool:
    """Return True only when the operator types the exact workspace name.

    Non-interactive runs resolve to an empty answer, so they never confirm.
    """
    print_instruction("Type the workspace name to confirm.")
    confirmation = str(prompt_ask("Workspace name", default="", shell=shell) or "").strip()
    return confirmation == workspace_name


def workspace_select(shell: WorkspaceShell) -> None:
    """Select a workspace interactively."""
    shell.ensure_workspaces_dir()
    try:
        from adscan_internal.workspaces import list_workspaces

        workspaces = list_workspaces(shell.workspaces_dir)
    except FileNotFoundError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"Workspaces directory not found: {shell.workspaces_dir}")
        return
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            f"Error accessing workspaces directory {shell.workspaces_dir}: {exc}"
        )
        return

    if not workspaces:
        print_info_debug(
            "[DEBUG] workspace_select: 'if not workspaces' condition met. About to call queued_print_warning."
        )
        print_warning("No workspaces detected.")
        new_ws_name = _prompt_for_new_workspace_name(shell)
        if new_ws_name:
            workspace_create(shell, new_ws_name)

            from adscan_internal.workspaces import (
                activate_workspace,
                resolve_workspace_paths,
            )

            if os.path.exists(
                resolve_workspace_paths(shell.workspaces_dir, new_ws_name.strip()).root
            ):
                activate_workspace(
                    shell,
                    workspaces_dir=shell.workspaces_dir,
                    workspace_name=new_ws_name.strip(),
                )
                shell.load_workspace_data(shell.current_workspace_dir or "")
                marked_workspace_name = mark_sensitive(
                    shell.current_workspace or "", "workspace"
                )
                print_success(
                    f"Workspace '{marked_workspace_name}' created and selected."
                )
        else:
            print_warning("Workspace creation cancelled.")
        return

    if shell.current_workspace:
        workspace_save(shell)

    if shell.current_domain:
        shell.domain_save()

    create_option = "[ + Create new workspace ]"
    workspace_options = workspaces + [create_option]
    selected_idx = shell._questionary_select("Select a workspace:", workspace_options)
    if selected_idx is None:
        return

    if selected_idx == len(workspaces):
        new_ws_name = _prompt_for_new_workspace_name(shell)
        if new_ws_name:
            workspace_create(shell, new_ws_name)

            from adscan_internal.workspaces import (
                activate_workspace,
                resolve_workspace_paths,
            )

            if os.path.exists(
                resolve_workspace_paths(shell.workspaces_dir, new_ws_name.strip()).root
            ):
                activate_workspace(
                    shell,
                    workspaces_dir=shell.workspaces_dir,
                    workspace_name=new_ws_name.strip(),
                )
                shell.load_workspace_data(shell.current_workspace_dir or "")
                marked_workspace_name = mark_sensitive(
                    shell.current_workspace or "", "workspace"
                )
                print_success(
                    f"Workspace '{marked_workspace_name}' created and selected."
                )
        else:
            print_warning("Workspace creation cancelled.")
        return

    if 0 <= selected_idx < len(workspaces):
        from adscan_internal.workspaces import activate_workspace

        activate_workspace(
            shell,
            workspaces_dir=shell.workspaces_dir,
            workspace_name=workspaces[selected_idx],
        )
        shell.load_workspace_data(shell.current_workspace_dir or "")
        marked_workspace_name = mark_sensitive(
            shell.current_workspace or "", "workspace"
        )
        print_success(f"Workspace '{marked_workspace_name}' selected.")


def workspace_show(shell: WorkspaceShell) -> None:
    """Display detailed information about the current workspace."""
    if not shell.current_workspace or not shell.current_workspace_dir:
        print_warning("No workspace is currently active.")
        print_instruction(
            "Use 'workspace select' to activate one, or 'workspace list' to see available ones."
        )
        return

    content = Text()
    content.append(
        Text(
            "Current Workspace Details\n",
            style=f"bold underline {BRAND_COLORS['info']}",
        )
    )
    content.append("\nName: ", style=f"bold {BRAND_COLORS['info']}")
    marked_current_workspace = mark_sensitive(shell.current_workspace, "workspace")
    content.append(f"{marked_current_workspace}\n", style="white")
    content.append("Path: ", style=f"bold {BRAND_COLORS['info']}")
    marked_current_workspace_dir = mark_sensitive(shell.current_workspace_dir, "path")
    content.append(f"{marked_current_workspace_dir}\n", style="white")

    content.append(
        "\nAssociated Data (from variables.json):\n",
        style=f"bold underline dim {BRAND_COLORS['info']}",
    )
    if shell.variables:
        display_vars = {
            "domain": shell.variables.get("domain"),
            "domains": shell.variables.get("domains"),
            "interface": shell.variables.get("interface"),
            "myip": shell.variables.get("myip"),
            "auto_mode": shell.variables.get("auto"),
        }
        for key, value in display_vars.items():
            content.append(f" {key.replace('_', ' ').capitalize()}: ")
            content.append(str(value) + "\n", style="white")
    else:
        content.append(
            "  No specific variables loaded or available for this workspace.\n",
            style="italic yellow",
        )

    try:
        ws_files = os.listdir(shell.current_workspace_dir)
        content.append(
            f"\nFiles in workspace directory ({len(ws_files)} items):\n",
            style=f"bold underline dim {BRAND_COLORS['info']}",
        )
        for f_name in ws_files[:5]:
            content.append(f" - {f_name}\n", style="dim white")
        if len(ws_files) > 5:
            content.append(
                f" ...and {len(ws_files) - 5} more.\n",
                style="dim italic white",
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        content.append(
            f"\nCould not list files in workspace: {exc}\n", style="italic red"
        )

    print_panel(
        content,
        title=f"[bold green]Workspace: {marked_current_workspace}[/bold green]",
        border_style=BRAND_COLORS["info"],
        expand=False,
    )


def workspace_save(shell: WorkspaceShell) -> None:
    """Save the variables and credentials of the current workspace."""
    if not shell.current_workspace or not shell.current_workspace_dir:
        return

    try:
        shell.save_workspace_data()
    except AttributeError as exc:
        telemetry.capture_exception(exc)
        print_error("Error saving workspace: Missing required data or method.")
        print_exception(show_locals=False, exception=exc)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_current_workspace = mark_sensitive(shell.current_workspace, "workspace")
        print_error(
            f"An unexpected error occurred while saving workspace '{marked_current_workspace}': {exc}"
        )
        print_exception(show_locals=False, exception=exc)
