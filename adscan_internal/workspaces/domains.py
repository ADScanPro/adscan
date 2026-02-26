from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DomainPaths:
    """Resolved paths for a domain directory inside an ADscan workspace."""

    domains_root: str
    domain_dir: str


def resolve_domains_root(workspace_dir: str, domains_dir_name: str) -> str:
    """Return the absolute path to the domains root inside a workspace."""
    return os.path.join(workspace_dir, domains_dir_name)


def list_domains(workspace_dir: str, domains_dir_name: str) -> list[str]:
    """List domain directory names under `workspace/<domains_dir_name>/`."""
    domains_root = resolve_domains_root(workspace_dir, domains_dir_name)
    if not os.path.exists(domains_root):
        return []
    return sorted(
        [
            entry
            for entry in os.listdir(domains_root)
            if os.path.isdir(os.path.join(domains_root, entry))
        ]
    )


def resolve_domain_paths(
    workspace_dir: str, domains_dir_name: str, domain: str
) -> DomainPaths:
    """Resolve key domain paths for a workspace/domain."""
    domains_root = resolve_domains_root(workspace_dir, domains_dir_name)
    return DomainPaths(
        domains_root=domains_root, domain_dir=os.path.join(domains_root, domain)
    )


def activate_domain(
    shell: Any,
    *,
    workspace_dir: str,
    domains_dir_name: str,
    domain: str,
) -> str:
    """Set current_domain/current_domain_dir on the shell.

    This helper only mutates in-memory state. It does not perform any I/O.
    """
    paths = resolve_domain_paths(workspace_dir, domains_dir_name, domain)
    shell.domain_path = paths.domains_root
    shell.current_domain = domain
    shell.current_domain_dir = paths.domain_dir
    return paths.domain_dir


def create_domain_dir(workspace_dir: str, domains_dir_name: str, domain: str) -> str:
    """Create a domain directory under the workspace domains root.

    Returns:
        The created domain directory path.

    Raises:
        FileExistsError: If the domain directory already exists.
        OSError: On filesystem errors.
    """
    domains_root = resolve_domains_root(workspace_dir, domains_dir_name)
    os.makedirs(domains_root, exist_ok=True)
    domain_dir_path = os.path.join(domains_root, domain)
    os.makedirs(domain_dir_path, exist_ok=False)
    return domain_dir_path


def delete_domain_dir(workspace_dir: str, domains_dir_name: str, domain: str) -> str:
    """Delete a domain directory tree under the workspace domains root.

    Returns:
        The deleted domain directory path.
    """
    path = resolve_domain_paths(workspace_dir, domains_dir_name, domain).domain_dir
    import shutil

    shutil.rmtree(path)
    return path


__all__ = [
    "DomainPaths",
    "create_domain_dir",
    "delete_domain_dir",
    "activate_domain",
    "list_domains",
    "resolve_domain_paths",
    "resolve_domains_root",
]
