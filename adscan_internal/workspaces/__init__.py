"""ADscan workspace utilities.

This package encapsulates ADscan's own workspace system (not NetExec's state).
It focuses on predictable filesystem layout and JSON persistence so the CLI
monolith can delegate I/O logic and become more testable.
"""

from .io import read_json_file, write_json_file
from .loader import apply_loaded_workspace_variables, load_workspace_variables
from .loader import load_workspace_data as _load_workspace_data
from .manager import (
    WorkspacePaths,
    create_workspace_dir,
    delete_workspace_dir,
    ensure_workspaces_dir,
    list_workspaces,
    resolve_workspace_paths,
    write_initial_workspace_variables,
)
from .saver import save_domain_data, save_workspace_data
from .session import activate_workspace
from .domains import (
    DomainPaths,
    activate_domain,
    create_domain_dir,
    delete_domain_dir,
    list_domains,
    resolve_domain_paths,
    resolve_domains_root,
)
from .subpaths import domain_path as domain_subpath, domain_relpath
from .layout import DEFAULT_DOMAIN_LAYOUT, DomainLayout
from .ui import select_domain_curses, select_workspace_curses
from .paths import (
    domain_dir,
    get_workspace_cwd,
    workspace_dir,
    workspace_variables_path,
)
from .state import (
    apply_workspace_variables_to_shell,
    collect_domain_variables_from_shell,
    collect_workspace_variables_from_shell,
)

__all__ = [
    "apply_loaded_workspace_variables",
    "apply_workspace_variables_to_shell",
    "collect_domain_variables_from_shell",
    "collect_workspace_variables_from_shell",
    "WorkspacePaths",
    "create_workspace_dir",
    "delete_workspace_dir",
    "domain_dir",
    "ensure_workspaces_dir",
    "list_workspaces",
    "load_workspace_data",
    "load_workspace_variables",
    "read_json_file",
    "resolve_workspace_paths",
    "activate_workspace",
    "DomainPaths",
    "activate_domain",
    "create_domain_dir",
    "delete_domain_dir",
    "list_domains",
    "resolve_domain_paths",
    "resolve_domains_root",
    "domain_subpath",
    "domain_relpath",
    "DEFAULT_DOMAIN_LAYOUT",
    "DomainLayout",
    "select_domain_curses",
    "select_workspace_curses",
    "save_domain_data",
    "save_workspace_data",
    "get_workspace_cwd",
    "workspace_dir",
    "workspace_variables_path",
    "write_initial_workspace_variables",
    "write_json_file",
]

# Re-export with public name
load_workspace_data = _load_workspace_data
