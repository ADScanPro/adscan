"""Compatibility shim for Rich output helpers.

Canonical implementation: `adscan_core.rich_output`.
"""

from __future__ import annotations

from adscan_core.rich_output import *  # noqa: F403
from adscan_core.rich_output import _get_console, _get_telemetry_console  # noqa: F401,E402


def __getattr__(name: str):  # pragma: no cover - runtime compatibility hook
    # `adscan.py` imports `_telemetry_console` to preserve the in-memory buffer
    # across module re-execution (PyInstaller). Keep this dynamically linked to
    # the core module state instead of binding a stale value at import time.
    if name == "_telemetry_console":
        import adscan_core.rich_output as _core  # noqa: PLC0415

        return getattr(_core, name)
    raise AttributeError(name)
