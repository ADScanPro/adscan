"""Tooling environment helpers (venv execution env and tool path resolvers).

These helpers are dependency-light and accept required paths/configurations as
parameters to avoid importing large modules or creating cycles. High-level
callers (e.g., adscan.py) provide the concrete values.
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Dict, Mapping, Optional, Callable

from adscan_internal.path_utils import get_adscan_home
from adscan_internal.docker_runtime import is_docker_env


def build_venv_exec_env(
    *,
    get_clean_env_for_compilation: Callable[[], Dict[str, str]],
    venv_path: str,
    python_executable: str,
) -> Dict[str, str]:
    """Build a clean environment for executing commands inside an isolated venv.
    
    Args:
        get_clean_env_for_compilation: Callable that returns a clean base env.
        venv_path: Path to the venv directory.
        python_executable: Path to the venv's python (used to derive bin dir).
    """
    venv_bin_path = os.path.dirname(python_executable)
    env = get_clean_env_for_compilation()
    env["PATH"] = f"{venv_bin_path}{os.pathsep}{env.get('PATH', '')}"
    env["VIRTUAL_ENV"] = venv_path
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    return env


def get_external_tool_python(
    *,
    tool_name: str,
    tool_venvs_base_dir: str,
    external_tools_config: Mapping[str, Any],
) -> Optional[str]:
    """Get the venv Python path for an external tool installed in an isolated venv."""
    if tool_name not in external_tools_config:
        return None
    tool_specific_venv_path = os.path.join(tool_venvs_base_dir, tool_name, "venv")
    tool_specific_python = os.path.join(tool_specific_venv_path, "bin", "python")
    return tool_specific_python if os.path.exists(tool_specific_python) else None


def get_external_tool_executable(
    *,
    tool_name: str,
    tools_install_dir: str,
    external_tools_config: Mapping[str, Any],
) -> Optional[str]:
    """Return the path to an external tool's executable if defined in config."""
    config = external_tools_config.get(tool_name)
    if not config:
        return None
    executable_name = config.get("name") or config.get("script_name")
    if not executable_name:
        return None
    executable_path = os.path.join(tools_install_dir, tool_name, executable_name)
    if os.path.exists(executable_path):
        return executable_path
    return None


# Tools installation directory constant
TOOLS_INSTALL_DIR = os.path.join(str(get_adscan_home()), "tools")


def _is_full_adscan_container_runtime() -> bool:
    """Return True when running inside the ADscan FULL runtime container.
    
    This is distinct from "Docker is installed on the host". In this mode, ADscan
    is already bundled with its dependencies under `/opt/adscan`, and we must
    avoid recursive Docker-mode execution (Docker-in-Docker is not supported).
    """
    if os.getenv("ADSCAN_CONTAINER_RUNTIME") == "1":
        return True
    if not is_docker_env():
        return False
    if os.getenv("ADSCAN_HOME") != "/opt/adscan":
        return False
    return (
        os.path.isdir("/opt/adscan/tool_venvs")
        and os.path.isdir("/opt/adscan/tools")
        and os.path.isdir("/opt/adscan/wordlists")
    )


def maybe_wrap_hashcat_for_container(command: str) -> str:
    """Return a hashcat command wrapped for Docker runtime compatibility.
    
    Hashcat's OpenCL backend (PoCL) can crash or fail to enumerate devices when
    executed as a non-root UID inside some container environments. In the ADscan
    FULL runtime container we prefer to run hashcat as root via sudo (NOPASSWD)
    while keeping the rest of the CLI unprivileged.
    
    Args:
        command: Command string (shell form).
    
    Returns:
        Possibly wrapped command string.
    """
    if not isinstance(command, str) or not command.strip():
        return command
    if not _is_full_adscan_container_runtime():
        return command
    # If we're already root in the container, no wrapper needed.
    if os.geteuid() == 0:
        return command
    # Only wrap hashcat invocations.
    if not command.lstrip().startswith("hashcat "):
        if command.lstrip() != "hashcat" and not command.lstrip().startswith(
            "hashcat\t"
        ):
            return command
    if not shutil.which("sudo"):
        return command
    # Avoid double-wrapping.
    if command.lstrip().startswith("sudo "):
        return command
    return f"sudo -n {command}"


# Alias for backward compatibility with adscan.py
_maybe_wrap_hashcat_for_container = maybe_wrap_hashcat_for_container

