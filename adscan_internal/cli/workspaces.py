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
    print_info_debug,
    print_info_verbose,
    print_instruction,
    print_panel,
    print_success,
    print_table,
    print_warning,
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


def do_workspace(shell: WorkspaceShell, args: str) -> None:
    """Handle `workspace` subcommands.

    Args:
        shell: Legacy CLI shell instance.
        args: Raw argument string after the `workspace` command.
    """
    if not args:
        print_instruction("Usage: workspace <create|delete|select|show|save|list>")
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
    elif command == "select":
        workspace_select(shell)
    elif command == "show":
        workspace_show(shell)
    elif command == "save":
        workspace_save(shell)
    elif command == "list":
        workspace_list(shell)
    else:
        print_error(f"Command '{command}' not recognized for workspace operations.")
        print_instruction(
            "Available commands: create, delete, select, show, save, list"
        )


def workspace_list(shell: WorkspaceShell) -> None:
    """List all available workspaces using a Rich table."""
    shell.ensure_workspaces_dir()
    try:
        from adscan_internal.workspaces import list_workspaces

        workspaces = list_workspaces(shell.workspaces_dir)
    except FileNotFoundError as exc:
        telemetry.capture_exception(exc)
        print_error(f"Workspaces directory not found at: {shell.workspaces_dir}")
        return
    except OSError as exc:
        telemetry.capture_exception(exc)
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


def workspace_create(shell: WorkspaceShell, workspace_name: str | None = None) -> None:
    """Create a new workspace and load it.

    Args:
        shell: Legacy CLI shell instance.
        workspace_name: Optional workspace name. When omitted, the user is prompted.
    """
    if not workspace_name:
        workspace_name = Prompt.ask(
            Text("Enter name for a new workspace: ", style="input")
        )
        if not workspace_name or not workspace_name.strip():
            print_warning("Workspace creation cancelled.")
            return
        workspace_name = workspace_name.strip()

    from adscan_internal.workspaces import (
        create_workspace_dir,
        resolve_workspace_paths,
        write_initial_workspace_variables,
    )

    workspace_path = resolve_workspace_paths(shell.workspaces_dir, workspace_name).root
    if os.path.exists(workspace_path):
        print_error(f"Workspace '{workspace_name}' already exists at {workspace_path}")
        return

    # One question only: purpose determines scan flow + telemetry split.
    # Lab provider/name are inferred automatically at scan start from the domain.
    selection = shell._questionary_select(
        "Workspace purpose?", ["CTF / Lab", "Client / Prod"]
    )
    if selection == 1:
        workspace_type = "audit"
    else:
        # Default to ctf on cancel (selection is None) or explicit CTF choice.
        workspace_type = "ctf"

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
        print_info_verbose(
            f"Initialized files for workspace '{marked_workspace_name}'."
        )

        shell.current_workspace = workspace_name
        shell.current_workspace_dir = workspace_path
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


def workspace_select(shell: WorkspaceShell) -> None:
    """Select a workspace interactively."""
    shell.ensure_workspaces_dir()
    try:
        from adscan_internal.workspaces import list_workspaces

        workspaces = list_workspaces(shell.workspaces_dir)
    except FileNotFoundError as exc:
        telemetry.capture_exception(exc)
        print_error(f"Workspaces directory not found: {shell.workspaces_dir}")
        return
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_error(
            f"Error accessing workspaces directory {shell.workspaces_dir}: {exc}"
        )
        return

    if not workspaces:
        print_info_debug(
            "[DEBUG] workspace_select: 'if not workspaces' condition met. About to call queued_print_warning."
        )
        print_warning("No workspaces detected.")
        new_ws_name = Prompt.ask(
            Text("Enter name for a new workspace: ", style="input")
        )
        if new_ws_name.strip():
            workspace_create(shell, new_ws_name.strip())

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
        new_ws_name = Prompt.ask(
            Text("Enter name for a new workspace: ", style="input")
        )
        if new_ws_name.strip():
            workspace_create(shell, new_ws_name.strip())

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
            "neo4j_host": shell.variables.get("neo4j_host"),
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
