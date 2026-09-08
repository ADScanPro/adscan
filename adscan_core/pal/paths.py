"""PAL semantic path helpers (OS × deployment-mode aware).

Extends the existing adscan_core.paths SSOT with the semantic locations the
runtime needs (tools, wordlists, scratch, system resolver/hosts/krb5), each
resolved per-OS. Nobody outside adscan_core.pal / adscan_core.paths /
adscan_core.path_utils should write a literal system path again.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from adscan_core.paths import (  # re-export: one import site for callers
    get_adscan_home_dir,
    get_logs_dir,
    get_workspaces_dir,
)
from adscan_core.pal.platform import is_windows

__all__ = [
    "get_adscan_home_dir",
    "get_logs_dir",
    "get_workspaces_dir",
    "tools_dir",
    "wordlists_dir",
    "tool_venvs_dir",
    "tool_binary",
    "scratch_dir",
    "system_resolv_conf",
    "system_hosts",
    "krb5_conf",
    "bin_dir",
    "static_dir",
    "runtime_venv_dir",
    "playwright_browsers_dir",
    "container_adscan_root",
    "container_workspaces_dir",
    "host_adscan_root_display",
]

# The FIXED container-side mount root. Inside the Docker runtime the host
# ``~/.adscan`` is always bind-mounted at ``/opt/adscan`` (see CLAUDE.md
# "Critical path mapping"), so this is a deployment-invariant constant, NOT the
# per-OS/per-deployment resolved home. It exists so host-side code that must
# TRANSLATE a container-emitted path back to the host (e.g. the host privileged
# helper) has one named source for the container root instead of a literal.
# The deployment-mode axis is deferred; these constants localize the two roots
# so no call-site writes them again.
_CONTAINER_ADSCAN_ROOT = "/opt/adscan"
# Canonical host-side display root. The launcher bind-mounts the container root
# to ~/.adscan on the host, so this is the equivalent path a user types on the
# host. Presentation-only; do not use it for filesystem I/O.
_HOST_ADSCAN_ROOT_DISPLAY = "~/.adscan"


def tools_dir() -> Path:
    return get_adscan_home_dir() / "tools"


def wordlists_dir() -> Path:
    return get_adscan_home_dir() / "wordlists"


def tool_venvs_dir() -> Path:
    return get_adscan_home_dir() / "tool_venvs"


def tool_binary(name: str) -> Path:
    exe = f"{name}.exe" if is_windows() else name
    return tools_dir() / exe


def scratch_dir() -> Path:
    return Path(tempfile.gettempdir())


def system_resolv_conf() -> Path | None:
    return None if is_windows() else Path("/etc/resolv.conf")


def system_hosts() -> Path:
    if is_windows():
        system_root = os.getenv("SystemRoot", r"C:\Windows")
        return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def krb5_conf() -> Path | None:
    return None if is_windows() else Path("/etc/krb5.conf")


def bin_dir() -> Path:
    """Return the ADscan bin directory (runtime-managed helper executables)."""
    return get_adscan_home_dir() / "bin"


def static_dir() -> Path:
    """Return the ADscan static-asset directory."""
    return get_adscan_home_dir() / "static"


def runtime_venv_dir() -> Path:
    """Return the ADscan runtime virtualenv directory."""
    return get_adscan_home_dir() / "venv"


def playwright_browsers_dir() -> Path:
    """Return the bundled Playwright browsers directory (ms-playwright)."""
    return get_adscan_home_dir() / "ms-playwright"


def container_adscan_root() -> str:
    """Return the fixed container-side ADscan mount root (``/opt/adscan``).

    This is the container path the host ``~/.adscan`` is always bind-mounted to;
    it is invariant across deployments and is used only for host<->container path
    translation, never as the resolved runtime home (use
    :func:`get_adscan_home_dir` for that).
    """
    return _CONTAINER_ADSCAN_ROOT


def container_workspaces_dir() -> str:
    """Return the fixed container-side workspaces root (``/opt/adscan/workspaces``)."""
    return _CONTAINER_ADSCAN_ROOT + "/workspaces"


def host_adscan_root_display() -> str:
    """Return the host-side display root (``~/.adscan``); presentation-only."""
    return _HOST_ADSCAN_ROOT_DISPLAY
