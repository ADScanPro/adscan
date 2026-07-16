"""NetExec integration helpers.

This package centralizes parsing and command conventions for NetExec (nxc)
so that services and CLI orchestration don't duplicate fragile stdout parsing.
"""


def __getattr__(name: str):
    """Lazily expose common NetExec helpers without package import cycles."""
    if name in {"clean_netexec_workspaces", "get_nxc_workspaces_dir"}:
        from .workspaces import clean_netexec_workspaces, get_nxc_workspaces_dir

        return {
            "clean_netexec_workspaces": clean_netexec_workspaces,
            "get_nxc_workspaces_dir": get_nxc_workspaces_dir,
        }[name]
    if name == "build_auth_nxc":
        from .helpers import build_auth_nxc

        return build_auth_nxc
    raise AttributeError(name)
