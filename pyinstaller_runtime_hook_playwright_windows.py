"""PyInstaller runtime hook (Windows onefile): resolve the bundled Chromium.

The Windows distribution target is a PyInstaller onefile ``adscan.exe``. At
launch PyInstaller extracts the archive to a temporary ``_MEIPASS`` directory.
The Playwright-managed Chromium (staged into ``tools\\ms-playwright`` by
``scripts/build_adscan_windows.ps1``) is therefore found under ``_MEIPASS``, not
at a fixed system path.

This is the Windows counterpart to ``pyinstaller_runtime_hook_playwright.py``
(which is Linux-only and hardcodes ``/opt/adscan/ms-playwright`` +
``/usr/bin/chromium``). Keep them separate — never point the Windows build at a
POSIX path.

Phase-4 note: Chromium is not yet staged into the folder-bundle. Until the
recipe fetches it, this hook is a no-op (the managed path simply will not
exist) and PDF rendering degrades until a Chromium is present.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _meipass_root() -> Path:
    # _MEIPASS is set by the PyInstaller bootloader in a frozen build; fall back
    # to the executable's directory for a folder-bundle / dev run.
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base)
    return Path(sys.executable).resolve().parent


_root = _meipass_root()
_managed = _root / "tools" / "ms-playwright"
if _managed.exists():
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(_managed))
else:
    # Fall back to a Chromium binary staged directly under tools\.
    for _candidate in (
        _root / "tools" / "chrome-win" / "chrome.exe",
        _root / "tools" / "chromium" / "chrome.exe",
    ):
        if _candidate.exists():
            os.environ.setdefault("ADSCAN_CHROMIUM_EXECUTABLE", str(_candidate))
            break
