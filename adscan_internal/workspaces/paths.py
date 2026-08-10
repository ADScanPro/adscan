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
    # ``current_workspace_dir`` is declared as a class attribute defaulting to
    # ``None`` on ``PentestShell``, so ``getattr(shell, ..., os.getcwd())`` at a
    # call site would never fall through — the attribute always exists. Read it
    # defensively and treat ``None``/empty/absent all as "no workspace selected".
    return getattr(shell, "current_workspace_dir", None) or os.getcwd()


def resolve_workspace_cwd(shell: object) -> str:
    """Resolve the workspace root for filesystem operations, with a CWD fallback.

    Single source of truth for the recurring idiom::

        shell._get_workspace_cwd()
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", os.getcwd())

    The bare ``getattr(..., os.getcwd())`` fallback in that idiom is a latent
    bug: because ``PentestShell.current_workspace_dir`` is a class attribute
    defaulting to ``None``, ``getattr`` returns that ``None`` instead of falling
    through to ``os.getcwd()``. The ``None`` then reaches ``os.path.join`` and
    raises ``TypeError``, which broad ``except`` blocks swallow — silently
    degrading every workspace-reading feature when no workspace is selected.

    Resolution order:
        1. ``shell._get_workspace_cwd()`` when the shell provides it (the CLI
           shell's stable resolver, which already handles the ``None`` case).
        2. Otherwise ``current_workspace_dir`` when set to a non-empty value.
        3. Otherwise ``os.getcwd()`` — correct in production, where the process
           CWD is the workspace root inside the container.

    Args:
        shell: CLI shell instance (or any object carrying the workspace state).

    Returns:
        The resolved workspace directory path.
    """
    getter = getattr(shell, "_get_workspace_cwd", None)
    if callable(getter):
        return str(getter())
    return get_workspace_cwd(shell)  # type: ignore[arg-type]


__all__ = [
    "domain_dir",
    "get_workspace_cwd",
    "resolve_workspace_cwd",
    "workspace_dir",
    "workspace_variables_path",
]
