from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from typing import Any

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


def delete_workspace_dir(workspaces_dir: str, workspace_name: str) -> WorkspacePaths:
    """Delete a workspace directory tree and return its resolved paths."""
    paths = resolve_workspace_paths(workspaces_dir, workspace_name)
    shutil.rmtree(paths.root)
    return paths


def write_initial_workspace_variables(
    *,
    workspace_name: str,
    workspace_path: str,
    workspace_type: str,
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
        "base_dn": None,
        "current_workspace": workspace_name,
        "current_workspace_dir": workspace_path,
        "current_domain": None,
        "current_domain_dir": None,
        "domain_path": None,
        "neo4j_host": "localhost",
        "neo4j_port": 7687,
        "neo4j_db_user": "neo4j",
        "neo4j_db_password": "neo4j",
        "auto": False,
        "telemetry": True,
        "type": workspace_type,
        "lab_provider": lab_provider.lower() if lab_provider else None,
        "lab_name": lab_name.lower() if lab_name else None,
        "lab_name_whitelisted": lab_name_whitelisted,
    }

    write_json_file(workspace_variables_path(workspace_path), variables)
    return variables


__all__ = [
    "WorkspacePaths",
    "create_workspace_dir",
    "delete_workspace_dir",
    "ensure_workspaces_dir",
    "list_workspaces",
    "resolve_workspace_paths",
    "write_initial_workspace_variables",
]
