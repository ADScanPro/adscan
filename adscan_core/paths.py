"""Path helpers shared across launcher and runtime.

These helpers resolve user-owned directories under ADSCAN_HOME (sudo-safe),
matching the established project convention:
- Base: `~/.adscan` (or ADSCAN_HOME override)
- Subdirs: workspaces/, logs/, run/, state/
"""

from __future__ import annotations

import os
from pathlib import Path

from adscan_core.path_utils import (
    expand_effective_user_path,
    get_adscan_home,
    get_adscan_state_dir,
)


def get_adscan_home_dir() -> Path:
    """Return the ADscan home directory (sudo-safe)."""
    return get_adscan_home()


def get_workspaces_dir() -> Path:
    return get_adscan_home_dir() / "workspaces"


def get_logs_dir() -> Path:
    return get_adscan_home_dir() / "logs"


def get_run_dir() -> Path:
    return get_adscan_home_dir() / "run"


def get_state_dir() -> Path:
    explicit = os.getenv("ADSCAN_STATE_DIR", "").strip()
    if explicit:
        return Path(expand_effective_user_path(explicit))
    return get_adscan_state_dir()
