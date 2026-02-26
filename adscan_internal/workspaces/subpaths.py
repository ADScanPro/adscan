from __future__ import annotations

import os


def domain_path(
    workspace_dir: str,
    domains_dir_name: str,
    domain: str,
    *parts: str,
) -> str:
    """Return an absolute path under `workspace/<domains_dir_name>/<domain>/...`."""
    return os.path.join(workspace_dir, domains_dir_name, domain, *parts)


def domain_relpath(domains_dir_name: str, domain: str, *parts: str) -> str:
    """Return a workspace-relative path under `domains/<domain>/...`.

    This is useful for building command strings that are executed with the
    workspace as CWD.
    """
    return os.path.join(domains_dir_name, domain, *parts)


__all__ = [
    "domain_path",
    "domain_relpath",
]
