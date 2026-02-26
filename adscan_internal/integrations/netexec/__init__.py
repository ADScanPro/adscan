"""NetExec integration helpers.

This package centralizes parsing and command conventions for NetExec (nxc)
so that services and CLI orchestration don't duplicate fragile stdout parsing.
"""

from .runner import NetExecContext, NetExecRunner
from .workspaces import clean_netexec_workspaces, get_nxc_workspaces_dir
from .helpers import build_auth_nxc

__all__ = [
    "NetExecContext",
    "NetExecRunner",
    "clean_netexec_workspaces",
    "get_nxc_workspaces_dir",
    "build_auth_nxc",
]
