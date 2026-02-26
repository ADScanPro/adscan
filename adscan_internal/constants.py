"""Shared constants for internal tools.

This module provides a minimal subset of constants that need to be reused
outside of `adscan.py` (for example from CLI helpers) without importing
the monolithic entrypoint and creating circular imports.
"""

from __future__ import annotations

import os
from pathlib import Path


def _get_adscan_base_dir() -> str:
    """Return ADscan base directory.

    This mirrors the default behaviour from `adscan.py`:
    - Honour ADSCAN_BASE_DIR when set
    - Otherwise fall back to ~/.adscan
    """

    env_path = os.getenv("ADSCAN_BASE_DIR")
    if env_path:
        return env_path
    return str(Path.home() / ".adscan")


ADSCAN_BASE_DIR: str = _get_adscan_base_dir()

# Local tools installation directory (LSA-Reaper, PKINITtools, etc.)
TOOLS_INSTALL_DIR: str = os.path.join(ADSCAN_BASE_DIR, "tools")


