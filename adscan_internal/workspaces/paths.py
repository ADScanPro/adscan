from __future__ import annotations

import os
from typing import Protocol


def workspace_dir(workspaces_root: str, workspace_name: str) -> str:
    """Return the absolute path to an ADscan workspace directory."""
    return os.path.join(workspaces_root, workspace_name)


def domain_dir(workspace_dir_path: str, domains_dir_name: str, domain: str) -> str:
    """Return the absolute path to a domain directory inside a workspace."""
    return os.path.join(workspace_dir_path, domains_dir_name, domain)


def workspace_variables_path(workspace_dir_path: str) -> str:
    """Return the path to the workspace-level variables.json file."""
    return os.path.join(workspace_dir_path, "variables.json")


class WorkspaceCwdShell(Protocol):
    """Protocol for shell methods needed by get_workspace_cwd."""

    current_workspace_dir: str | None


def get_workspace_cwd(shell: WorkspaceCwdShell) -> str:
    """Return the workspace directory to use for filesystem operations.

    The CLI typically ``chdir``'s into the current workspace, but some flows
    may run while the process CWD differs (e.g., during prompts or external
    tool execution). Using this helper keeps domain path resolution stable.

    Args:
        shell: CLI shell instance that implements WorkspaceCwdShell protocol

    Returns:
        The workspace directory path, or current working directory if no workspace is active
    """
    return shell.current_workspace_dir or os.getcwd()


__all__ = [
    "domain_dir",
    "get_workspace_cwd",
    "workspace_dir",
    "workspace_variables_path",
]
