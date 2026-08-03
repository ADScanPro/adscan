"""Workspace selection UI using curses.

This module provides the interactive curses-based selection interface for
workspaces.
"""

from __future__ import annotations

import curses
from typing import Any, Protocol

from adscan_internal.rich_output import mark_sensitive, print_success
from adscan_internal.workspaces import activate_workspace


class WorkspaceCursesShell(Protocol):
    """Protocol for shell methods needed by curses selection functions."""

    current_workspace: str | None
    current_workspace_dir: str | None
    workspaces_dir: str

    def load_workspace_data(self, workspace_path: str) -> None: ...


def select_workspace_curses(
    shell: WorkspaceCursesShell, stdscr: Any, workspaces: list[str]
) -> None:
    """Curses function to select a workspace.

    Args:
        shell: CLI shell instance that implements WorkspaceCursesShell protocol
        stdscr: Curses standard screen object
        workspaces: List of workspace names to choose from
    """
    curses.curs_set(0)  # Hide the cursor
    stdscr.clear()

    selected_index = 0
    num_workspaces = len(workspaces)

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Select a workspace using the arrow keys and Enter:\n")

        for idx, ws in enumerate(workspaces):
            if idx == selected_index:
                stdscr.addstr(idx + 1, 0, f"> {ws}", curses.A_REVERSE)
            else:
                stdscr.addstr(idx + 1, 0, f" {ws}")

        stdscr.refresh()

        key = stdscr.getch()
        if key == curses.KEY_UP:
            selected_index = (selected_index - 1) % num_workspaces
        elif key == curses.KEY_DOWN:
            selected_index = (selected_index + 1) % num_workspaces
        elif key == curses.KEY_ENTER or key in [10, 13]:
            activate_workspace(
                shell,
                workspaces_dir=shell.workspaces_dir,
                workspace_name=workspaces[selected_index],
            )
            shell.load_workspace_data(shell.current_workspace_dir or "")
            # stdscr.addstr(num_workspaces + 2, 0, f"Workspace '{shell.current_workspace}' selected.") # Curses will exit
            # stdscr.refresh()
            # stdscr.getch() # Wait for a key press before exiting curses mode
            break
    # After curses wrapper finishes, print success message using Rich
    marked_current_workspace = mark_sensitive(
        shell.current_workspace or "", "workspace"
    )
    print_success(f"Workspace '{marked_current_workspace}' selected.")


__all__ = ["select_workspace_curses", "WorkspaceCursesShell"]

