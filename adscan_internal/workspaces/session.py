from __future__ import annotations

from typing import Any

from adscan_internal.workspaces.manager import resolve_workspace_paths


def activate_workspace(shell: Any, *, workspaces_dir: str, workspace_name: str) -> str:
    """Set the active workspace fields on the shell.

    This helper only mutates in-memory state. It does not perform any I/O or
    call `load_workspace_data()` so the CLI can decide when to apply side-effects.

    Args:
        shell: CLI shell instance (adscan.PentestShell).
        workspaces_dir: Root directory containing all workspaces.
        workspace_name: Workspace folder name.

    Returns:
        Absolute workspace directory path.
    """
    paths = resolve_workspace_paths(workspaces_dir, workspace_name)
    shell.current_workspace = workspace_name
    shell.current_workspace_dir = paths.root
    return paths.root


__all__ = [
    "activate_workspace",
]
