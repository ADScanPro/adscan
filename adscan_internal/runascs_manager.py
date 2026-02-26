"""Helpers for managing the RunasCs binary used to upgrade sessions.

This module mirrors :mod:`adscan_internal.agent_ng_manager` but is dedicated
to locating the compiled RunasCs executable on the operator host.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final, Optional

from adscan_internal.path_utils import expand_effective_user_path, get_adscan_home


RUNASCS_ENV_VAR: Final[str] = "ADSCAN_RUNASCS_PATH"
"""Environment variable to override the default RunasCs binary path."""


def _default_runascs_path(target_os: str, arch: str) -> Path:
    """Return the default on-disk location for the RunasCs binary."""
    base_dir = get_adscan_home() / "tools" / "runascs"
    subdir = f"{target_os.lower()}-{arch.lower()}"
    binary_name = "RunasCs.exe" if target_os.lower() == "windows" else "RunasCs"
    return base_dir / subdir / binary_name


def get_runascs_local_path(
    target_os: str = "windows", arch: str = "amd64"
) -> Optional[Path]:
    """Return the local filesystem path to the RunasCs binary, if any."""
    env_path = os.getenv(RUNASCS_ENV_VAR)
    if env_path:
        candidate = Path(expand_effective_user_path(env_path))
        if candidate.is_file():
            return candidate

    # During development we prefer the copy stored under the repository's
    # external_refs directory when available so there is no need to manually
    # copy the binary into ~/.adscan. This location will not exist in the
    # packaged PyInstaller bundle.
    try:
        repo_root = Path(__file__).resolve().parents[1]
        external_candidate = repo_root / "external_refs" / "runascs" / "RunasCs.exe"
        if external_candidate.is_file():
            return external_candidate
    except Exception:
        # Best-effort only; fall back to the standard path below.
        pass

    candidate = _default_runascs_path(target_os=target_os, arch=arch)
    if candidate.is_file():
        return candidate

    return None
