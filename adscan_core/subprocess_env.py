"""Subprocess environment helpers shared across ADscan components.

These utilities are used to build a "clean" environment for running external
tools from:
- the host-side launcher
- the runtime CLI (including the compiled/bundled variants)

Primary motivation:
PyInstaller can inject libraries via `LD_LIBRARY_PATH` which can break system
tools (apt/dpkg, curl, gcc, etc.). The helper removes those variables while
preserving SSL-related env vars so HTTPS continues to work.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping, Sequence
from typing import Any

from adscan_core.ssl_certificates import configure_ssl_certificates


def get_clean_env_for_compilation(
    base_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a clean environment for external tools in PyInstaller builds.

    Args:
        base_env: Base environment to clean. Defaults to `os.environ`.

    Returns:
        A copy of the environment without PyInstaller interference.
    """
    env = dict(base_env or os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    configure_ssl_certificates(env)
    return env


def command_needs_clean_env(command_list: Sequence[Any]) -> bool:
    """Return True when a command should run with `clean_env` applied."""
    if not command_list:
        return True

    command0 = command_list[0]
    command = command0.lower() if isinstance(command0, str) else str(command0).lower()
    command_path = command0 if isinstance(command0, str) else str(command0)

    python_commands_not_needing_clean_env = {
        "python",
        "python3",
        "python2",
        "python3.12",
        "python3.11",
        "python3.10",
        "pip",
        "pip3",
        "pip3.12",
        "pip3.11",
        "pip3.10",
    }

    if command in python_commands_not_needing_clean_env:
        if "/" in command_path:
            system_paths = [
                "/usr/bin/",
                "/bin/",
                "/sbin/",
                "/usr/sbin/",
                "/usr/local/bin/",
            ]
            if any(command_path.startswith(path) for path in system_paths):
                return True

        if "/venv/" in command_path or "/.adscan/" in command_path:
            if len(command_list) > 1:
                tail = " ".join(str(x) for x in command_list[1:]).lower()
                if "pip" in command and "install" in tail:
                    return True
                if (
                    command in python_commands_not_needing_clean_env
                    and len(command_list) > 2
                ):
                    if (
                        command_list[1] == "-m"
                        and "pip" in str(command_list[2]).lower()
                        and "install"
                        in " ".join(str(x) for x in command_list[2:]).lower()
                    ):
                        return True
            return False
        return False

    if "/" in command_path:
        system_paths = [
            "/usr/bin/",
            "/bin/",
            "/sbin/",
            "/usr/sbin/",
            "/usr/local/bin/",
            "/opt/",
        ]
        if any(command_path.startswith(path) for path in system_paths):
            return True

    if "/venv/" in command_path or "/.adscan/" in command_path:
        if "python" in command or "pip" in command:
            if len(command_list) > 1:
                tail = " ".join(str(x) for x in command_list[1:]).lower()
                if "pip" in command and "install" in tail:
                    return True
                if (
                    command in python_commands_not_needing_clean_env
                    and len(command_list) > 2
                ):
                    if (
                        command_list[1] == "-m"
                        and "pip" in str(command_list[2]).lower()
                        and "install"
                        in " ".join(str(x) for x in command_list[2:]).lower()
                    ):
                        return True
            return False

    return True


def command_string_needs_clean_env(command_str: str) -> bool:
    """Return True if a shell command string should use `clean_env`."""
    if not command_str or not isinstance(command_str, str):
        return True

    try:
        command_list = shlex.split(command_str, posix=True)
        if not command_list:
            return True
    except ValueError:
        command_list = command_str.strip().split()
        if not command_list:
            return True

    return command_needs_clean_env(command_list)


__all__ = [
    "command_needs_clean_env",
    "command_string_needs_clean_env",
    "get_clean_env_for_compilation",
]
