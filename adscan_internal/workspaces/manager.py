from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from typing import Any

from adscan_core.lab_context import normalize_lab_name, normalize_lab_provider
from adscan_internal.workspaces.io import write_json_file
from adscan_internal.workspaces.paths import workspace_variables_path


@dataclass(frozen=True)
class WorkspacePaths:
    """Resolved paths for a workspace."""

    root: str
    variables_json: str


def ensure_workspaces_dir(workspaces_dir: str) -> None:
    """Ensure the workspaces directory exists."""
    os.makedirs(workspaces_dir, exist_ok=True)


def list_workspaces(workspaces_dir: str) -> list[str]:
    """List workspace names under the workspaces directory."""
    if not os.path.exists(workspaces_dir):
        return []
    return sorted(
        [
            entry
            for entry in os.listdir(workspaces_dir)
            if os.path.isdir(os.path.join(workspaces_dir, entry))
            and not entry.startswith(".")
        ]
    )


def resolve_workspace_paths(workspaces_dir: str, workspace_name: str) -> WorkspacePaths:
    """Resolve key paths for a workspace."""
    root = os.path.join(workspaces_dir, workspace_name)
    return WorkspacePaths(root=root, variables_json=workspace_variables_path(root))


def create_workspace_dir(workspaces_dir: str, workspace_name: str) -> WorkspacePaths:
    """Create a workspace directory and return its resolved paths."""
    ensure_workspaces_dir(workspaces_dir)
    paths = resolve_workspace_paths(workspaces_dir, workspace_name)
    os.makedirs(paths.root, exist_ok=False)
    return paths


def _report_execution_workspaces_in_use(kept: object) -> None:
    """Tell the operator which execution workspaces were kept, and why.

    A hidden ``.run_*`` directory a scan is still writing into is never removed
    from under the running engine. That decision has to be VISIBLE: a silent
    skip would leave the operator believing the end-of-engagement delete was
    complete when a full copy of the engagement is still on disk.
    """
    names = [str(name) for name in kept] if isinstance(kept, (list, tuple)) else []
    if not names:
        return
    from adscan_core.rich_output import print_instruction, print_warning  # noqa: PLC0415
    from adscan_core.sensitive import mark_sensitive  # noqa: PLC0415

    listed = ", ".join(mark_sensitive(name, "workspace") for name in names)
    print_warning(
        f"{len(names)} scan working director{'y' if len(names) == 1 else 'ies'} "
        f"of this workspace could not be removed because a scan still appears "
        f"to be writing into them: {listed}"
    )
    print_instruction(
        "They still hold this engagement's data. Let that scan finish, then "
        "delete the workspace again to remove them."
    )


def delete_workspace_dir(workspaces_dir: str, workspace_name: str) -> WorkspacePaths:
    """Delete a workspace and everything ADscan keeps about it elsewhere.

    The directory holds the engagement (credentials, graph, reports, logs); the
    artifacts kept outside it and keyed to it are removed too, so deleting the
    workspace leaves nothing of the client's environment behind: its lock file,
    the targeted cracking wordlists of domains no other workspace holds, its
    lines in the pre-workspace REPL history, and the hidden ``.run_*`` execution
    workspaces each of its scans wrote into (siblings of this directory, each
    holding a full copy of the engagement). See
    ``adscan_core.workspace_residue``.
    """
    from adscan_core.workspace_residue import (  # noqa: PLC0415
        purge_workspace_residue,
        workspace_domains,
    )

    # Whatever this process logs from here on (in another workspace's logs,
    # the dev trace, the outside-workspace log) names a token, never the
    # workspace that is going away.
    from adscan_core.telemetry import forget_workspace_name  # noqa: PLC0415

    forget_workspace_name(workspace_name)
    paths = resolve_workspace_paths(workspaces_dir, workspace_name)
    domains = workspace_domains(paths.root)
    shutil.rmtree(paths.root)
    purged = purge_workspace_residue(
        workspace_name,
        workspace_root=paths.root,
        domains=domains,
        workspaces_dir=workspaces_dir,
    )
    _report_execution_workspaces_in_use(purged.get("execution_workspaces_in_use"))
    return paths


def _release_workspace_logs() -> None:
    try:
        from adscan_core.logging_config import update_workspace_logging  # noqa: PLC0415

        update_workspace_logging(None)
    except Exception:  # noqa: BLE001 — best-effort; never block the delete
        pass


def trim_workspace_to_logs(workspace_dir: str) -> WorkspacePaths:
    """Remove everything from a workspace except its ``logs/`` folder.

    For a run that created its own workspace and FAILED: the logs are the only
    record of why, so they stay, inside the workspace, and nothing else does
    (credentials, hashes, graph, reports). The operator deletes the workspace
    once the logs are read, which also clears its residue elsewhere.
    """
    from adscan_core.workspace_residue import (  # noqa: PLC0415
        purge_workspace_residue,
        workspace_domains,
    )

    _release_workspace_logs()
    root = os.path.abspath(workspace_dir)
    workspaces_dir, name = os.path.dirname(root), os.path.basename(root)
    domains = workspace_domains(root)
    for entry in os.listdir(root):
        if entry == "logs":
            continue
        target = os.path.join(root, entry)
        if os.path.isdir(target) and not os.path.islink(target):
            shutil.rmtree(target)
        else:
            os.remove(target)
    purge_workspace_residue(
        name, workspace_root=root, domains=domains, workspaces_dir=workspaces_dir
    )
    return resolve_workspace_paths(workspaces_dir, name)


def delete_workspace_at(workspace_dir: str) -> WorkspacePaths:
    """Delete the workspace at ``workspace_dir`` (the end of an ephemeral run).

    For a run that created its own workspace (``ci``, ``execute``, ``doctor``):
    the log files are released first (a file with an open handle cannot be
    deleted on Windows, and every later line must stop going to it), then the
    workspace goes through :func:`delete_workspace_dir`, residue included.
    """
    _release_workspace_logs()
    root = os.path.abspath(workspace_dir)
    return delete_workspace_dir(os.path.dirname(root), os.path.basename(root))


def finish_ephemeral_workspace(workspace_dir: str, *, failed: bool) -> str:
    """End-of-run disposal of a workspace a run created for itself.

    A successful run deletes it. A failed run keeps only its ``logs/`` (see
    :func:`trim_workspace_to_logs`) so the operator can see why it failed, and
    is told where they are and how to remove them.

    Returns:
        ``"deleted"`` or ``"kept_logs"``.
    """
    if not failed:
        delete_workspace_at(workspace_dir)
        return "deleted"
    trim_workspace_to_logs(workspace_dir)
    from adscan_core.rich_output import print_instruction, print_warning  # noqa: PLC0415
    from adscan_core.sensitive import mark_sensitive  # noqa: PLC0415

    root = os.path.abspath(workspace_dir)
    name = mark_sensitive(os.path.basename(root), "workspace")
    print_warning(
        f"The run failed: workspace '{name}' was emptied except for its logs, "
        f"kept at {mark_sensitive(os.path.join(root, 'logs'), 'path')} so you can see why."
    )
    print_instruction(
        f"Delete it from the ADscan shell once you have read them: workspace delete {name}"
    )
    return "kept_logs"


def write_initial_workspace_variables(
    *,
    workspace_name: str,
    workspace_path: str,
    workspace_type: str | None,
    lab_provider: str | None = None,
    lab_name: str | None = None,
    lab_name_whitelisted: bool | None = None,
) -> dict[str, Any]:
    """Create and persist a new workspace variables.json file.

    This mirrors the historical schema in adscan.py and is safe to evolve behind
    a stable API for both CLI and future web orchestration.
    """
    variables: dict[str, Any] = {
        "hosts": None,
        "pdc": None,
        "pdc_hostname": None,
        "dcs": [],
        "interface": None,
        "username": None,
        "password": None,
        "domain": None,
        "domains": [],
        "dns": None,
        "hash": None,
        "myip": None,
        "myip_source": None,
        "base_dn": None,
        "current_workspace": workspace_name,
        "current_workspace_dir": workspace_path,
        "current_domain": None,
        "current_domain_dir": None,
        "domain_path": None,
        "auto": False,
        # Telemetry preference is left UNSET (no key) so a new workspace inherits
        # the global default live — it is not frozen to a boolean at creation,
        # which would let it shadow a later global change (opt-out or opt-in).
        "type": workspace_type,
        "lab_provider": normalize_lab_provider(lab_provider),
        "lab_name": normalize_lab_name(lab_name),
        "lab_name_whitelisted": lab_name_whitelisted,
        "lab_confirmation_state": "manual" if lab_provider or lab_name else None,
    }

    write_json_file(workspace_variables_path(workspace_path), variables)
    return variables


__all__ = [
    "WorkspacePaths",
    "create_workspace_dir",
    "delete_workspace_at",
    "finish_ephemeral_workspace",
    "trim_workspace_to_logs",
    "delete_workspace_dir",
    "ensure_workspaces_dir",
    "list_workspaces",
    "resolve_workspace_paths",
    "write_initial_workspace_variables",
]
