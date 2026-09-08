"""Path helpers for resolving user-owned ADscan locations.

These helpers are designed for cases where ADscan is executed under sudo/root
but should keep its state and configs under the invoking user's home directory
(e.g. the user running `sudo adscan ...`).
"""

from __future__ import annotations

import os
from pathlib import Path


def get_effective_user_home() -> Path:
    """Return the home directory that should own ADscan state/config.

    If running under sudo, prefer the invoking user's home so we don't write to
    ``/root`` unintentionally.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        # Imported lazily inside the function to avoid a circular import:
        # ``adscan_core.pal.paths`` imports this module, so importing the PAL at
        # module top would loop. ``pal.process`` only imports ``pal.platform``,
        # so a function-scoped import is safe (mirrors ``get_adscan_home`` below).
        from adscan_core.pal.process import lookup_user_home

        home = lookup_user_home(sudo_user)
        if home:
            return Path(home)
    return Path.home()


def expand_effective_user_path(path: str) -> str:
    """Expand ~ paths using the effective user's home directory.

    This is intentionally conservative: it only rewrites leading "~" / "~/".
    All other input is returned (after env var expansion) unchanged.
    """
    expanded = os.path.expandvars(path)
    if expanded.startswith("~/"):
        return str(get_effective_user_home() / expanded[2:])
    if expanded == "~":
        return str(get_effective_user_home())
    return expanded


def get_adscan_home() -> Path:
    """Return the base directory for ADscan runtime artifacts.

    Respects ``ADSCAN_HOME`` when provided (any OS). Without an override the
    default is OS-specific: ``%LOCALAPPDATA%\\ADscan`` on Windows,
    ``~/.adscan`` on POSIX.
    """
    override = os.getenv("ADSCAN_HOME")
    if override:
        return Path(expand_effective_user_path(override))

    from adscan_core.pal.platform import is_windows

    if is_windows():
        local_appdata = os.getenv("LOCALAPPDATA")
        base = Path(local_appdata) if local_appdata else (Path.home() / "AppData" / "Local")
        return base / "ADscan"
    return get_effective_user_home() / ".adscan"


def get_adscan_state_dir() -> Path:
    """Return the directory used for persisted ADscan state.

    This is used for small, non-sensitive state files (e.g., first-run marker,
    telemetry toggle state) that should survive container restarts.

    Respects ``ADSCAN_STATE_DIR`` when provided; otherwise defaults to
    ``<ADSCAN_HOME>/state``.
    """
    override = os.getenv("ADSCAN_STATE_DIR")
    if override:
        return Path(expand_effective_user_path(override))
    return get_adscan_home() / "state"
