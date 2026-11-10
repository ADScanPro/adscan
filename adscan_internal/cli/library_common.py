"""What the saved-policy library and the pace-profile library share.

``policy`` and ``pace`` are managed from two places: the REPL verbs and the host
commands ``adscan policy`` / ``adscan pace``. Both call the same handlers in
:mod:`adscan_internal.cli.scan_policy_library` and
:mod:`adscan_internal.cli.pace_profile_cmd`; the pieces below are the ones the
two libraries have in common, so neither grows its own copy:

* the "where do I save this" rule (:func:`resolve_save_scope`);
* the workspace a host command names (:func:`resolve_workspace_dir`);
* writing an export file in place (:func:`write_export_file`);
* a stand-in for the REPL shell on the host (:class:`HostWorkspaceShell`), so a
  host ``use`` applies a policy or a pace through the same functions the REPL
  does.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from rich.markup import escape

from adscan_core.interaction import is_non_interactive
from adscan_core.rich_output import print_info, questionary_select_index

SCOPE_WORKSPACE = "workspace"
SCOPE_GLOBAL = "global"
SCOPE_CHOICES: tuple[str, ...] = (SCOPE_WORKSPACE, SCOPE_GLOBAL)

SCOPE_ARGUMENT_HELP = (
    "Where to save it: 'workspace' (the one in use, or the one named with --workspace) "
    "or 'global' (all workspaces). Default: ask when a workspace is in context, "
    "otherwise global."
)


def add_scope_argument(parser: Any) -> None:
    """The ``--scope`` option both libraries accept on every saving action."""
    parser.add_argument("--scope", choices=list(SCOPE_CHOICES), default=None, help=SCOPE_ARGUMENT_HELP)


def is_attended(shell: Any = None) -> bool:
    """True when a person can answer a prompt (the REPL, or a host terminal)."""
    return not is_non_interactive(shell)


def require_workspace(workspace_dir: str | None, *, what: str, error: type[Exception]) -> str:
    """The workspace directory, or an error saying how to name one."""
    if not workspace_dir:
        raise error(
            f"{what} needs a workspace. Name one with --workspace NAME, or select one with `workspace select` in the shell."
        )
    return workspace_dir


def resolve_save_scope(
    *,
    noun: str,
    workspace_dir: str | None,
    explicit: str | None,
    shell: Any = None,
    attended: bool = False,
    host: bool = False,
    error: type[Exception] = ValueError,
) -> str | None:
    """Where a new ``noun`` (``policy`` / ``pace profile``) is saved.

    * ``explicit`` (``--scope``) wins; ``workspace`` without a workspace is an error.
    * No workspace in context: saved for all workspaces, and the user is told.
    * A workspace in context: ask when attended (default: this workspace), else
      this workspace.

    Returns ``None`` when the user cancels the prompt.
    """
    if explicit:
        if explicit == SCOPE_WORKSPACE:
            require_workspace(workspace_dir, what=f"A workspace-scoped {noun}", error=error)
        return explicit
    if not workspace_dir:
        named = "named" if host else "open"
        print_info(
            f"No workspace is {named}, so the {noun} is saved for all workspaces"
            + (" (add --workspace NAME to save it in one)." if host else ".")
        )
        return SCOPE_GLOBAL
    if not attended:
        return SCOPE_WORKSPACE
    idx = questionary_select_index(
        title=f"Where should this {noun} be saved?",
        options=["This workspace only", "All workspaces"],
        default_idx=0,
        shell=shell,
    )
    if idx is None:
        return None
    return SCOPE_WORKSPACE if int(idx) == 0 else SCOPE_GLOBAL


def resolve_workspace_dir(name: str | None, *, error: type[Exception]) -> str | None:
    """The directory of the workspace a host command names (``None`` when none is named)."""
    if not name:
        return None
    from adscan_core.paths import get_workspaces_dir

    path = get_workspaces_dir() / str(name)
    if not path.is_dir():
        raise error(f"No workspace named '{escape(str(name))}'.")
    return str(path)


def write_export_file(output: str, text: str, *, error: type[Exception]) -> str:
    """Write ``text`` to ``output`` in place; returns the name to show the user.

    In place, not via a rename: the launcher bind-mounts this one file.
    """
    path = Path(output).expanduser()
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as exc:
        raise error(f"Cannot write {path}: {exc.strerror or exc}") from exc
    from adscan_core.container_io import is_container_io_path

    return path.name if is_container_io_path(str(path)) else str(path)


class HostWorkspaceShell:
    """The slice of the REPL shell a host command needs to act on one workspace.

    ``adscan policy use`` and ``adscan pace use`` apply a policy or a pace to a
    workspace without a running shell. They do it through the same service
    functions the REPL calls (``set_policy``, ``apply_pace_profile``), which read
    and write a few attributes of the shell; this object carries exactly those,
    loaded from the workspace, and persists the pace back to its
    ``variables.json`` the way a workspace save does.
    """

    def __init__(self, workspace_dir: str) -> None:
        from adscan_internal.services.scan_controls import (
            ATTR_PACING_REQUEST,
            apply_workspace_scan_controls,
            pacing_request_from_saved,
        )

        self.current_workspace_dir = str(workspace_dir)
        self.scan_policy: Any = None
        self.scan_pacing_request: Any = None
        variables = self._read_variables()
        setattr(self, ATTR_PACING_REQUEST, pacing_request_from_saved(variables.get("pacing")))
        apply_workspace_scan_controls(self, self.current_workspace_dir)

    @property
    def _variables_path(self) -> Path:
        return Path(self.current_workspace_dir) / "variables.json"

    def _read_variables(self) -> dict[str, Any]:
        try:
            data = json.loads(self._variables_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def save_workspace_data(self) -> None:
        """Persist the pace request into the workspace's ``variables.json``."""
        from adscan_internal.services.scan_controls import pacing_request_for_save

        path = self._variables_path
        if not path.is_file():
            return
        variables = self._read_variables()
        saved = pacing_request_for_save(self)
        if saved is None:
            variables.pop("pacing", None)
        else:
            variables["pacing"] = saved
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(variables, indent=2, sort_keys=False), encoding="utf-8")
        os.replace(tmp, path)


__all__ = [
    "HostWorkspaceShell",
    "SCOPE_ARGUMENT_HELP",
    "SCOPE_CHOICES",
    "SCOPE_GLOBAL",
    "SCOPE_WORKSPACE",
    "add_scope_argument",
    "is_attended",
    "require_workspace",
    "resolve_save_scope",
    "resolve_workspace_dir",
    "write_export_file",
]
