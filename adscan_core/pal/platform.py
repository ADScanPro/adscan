"""OS-selector primitive for the PAL.

``current_os()`` returns ``"windows"`` or ``"posix"``. An env override
(``ADSCAN_PAL_OS``) lets a POSIX CI host exercise the Windows backend selection
deterministically; a garbage value is ignored and the real platform wins.
"""
from __future__ import annotations

import sys

PAL_OS_ENV_OVERRIDE = "ADSCAN_PAL_OS"
_VALID = ("windows", "posix")


def current_os() -> str:
    import os

    override = os.environ.get(PAL_OS_ENV_OVERRIDE, "").strip().lower()
    if override in _VALID:
        return override
    return "windows" if sys.platform.startswith("win") else "posix"


def is_windows() -> bool:
    return current_os() == "windows"


def is_posix() -> bool:
    return current_os() == "posix"
