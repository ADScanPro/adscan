"""Helpers for managing the binary (next‑generation) remote agent.

This module is intentionally small and focused: it provides utilities to locate
the compiled agent binary on the local filesystem. The actual deployment logic
is orchestrated from the main ADscan shell where we already have access to
WinRM/SMB helpers, logging, and telemetry.

The long‑term goal is to support a Go‑based agent for Windows targets that
speaks the same protocol as :mod:`adscan_internal.agent_protocol`. For now we
only define the lookup mechanism so that the rest of the codebase can be wired
without committing to a specific build or packaging strategy.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final, Optional

from adscan_internal.path_utils import expand_effective_user_path, get_adscan_home


AGENT_NG_ENV_VAR: Final[str] = "ADSCAN_AGENT_NG_PATH"
"""Environment variable that can override the default agent binary path.

When set, its value should point directly to the compiled agent binary for the
current platform (for example, a Windows ``.exe`` for Windows targets).
"""


def _default_agent_ng_path(target_os: str, arch: str) -> Path:
    """Return the default on‑disk location for the agent binary.

    This uses the user's ADscan home directory and a simple OS/arch layout:

    ``$HOME/.adscan/tools/agent_ng/<target_os>-<arch>/adscan_agent_ng``

    On Windows targets the expectation is that ``target_os`` is ``"windows"``
    and ``arch`` is something like ``"amd64"``.
    """
    base_dir = get_adscan_home() / "tools" / "agent_ng"
    subdir = f"{target_os.lower()}-{arch.lower()}"
    binary_name = (
        "adscan_agent_ng.exe" if target_os.lower() == "windows" else "adscan_agent_ng"
    )
    return base_dir / subdir / binary_name


def get_agent_ng_local_path(
    target_os: str = "windows", arch: str = "amd64"
) -> Optional[Path]:
    """Return the local filesystem path to the compiled agent binary.

    Lookup order:

    1. ``ADSCAN_AGENT_NG_PATH`` environment variable, if set and points to an
       existing regular file.
    2. Default path under the ADscan home directory as returned by
       :func:`_default_agent_ng_path`.

    The function only returns a path that currently exists on disk. If no valid
    candidate is found, ``None`` is returned so callers can gracefully fall
    back to non‑agent payloads.

    Args:
        target_os: Target operating system label (for example ``"windows"``).
        arch: Target architecture label (for example ``"amd64"``).

    Returns:
        ``pathlib.Path`` to the agent binary if available, otherwise ``None``.
    """
    env_path = os.getenv(AGENT_NG_ENV_VAR)
    if env_path:
        candidate = Path(expand_effective_user_path(env_path))
        if candidate.is_file():
            return candidate

    candidate = _default_agent_ng_path(target_os=target_os, arch=arch)
    if candidate.is_file():
        return candidate

    return None
