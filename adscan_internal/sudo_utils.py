"""Compatibility shim for sudo utilities.

Canonical implementation: `adscan_core.sudo_utils`.
"""

from __future__ import annotations

from adscan_core.interaction import is_non_interactive as _is_non_interactive  # noqa: F401
from adscan_core.sudo_utils import *  # noqa: F403

__all__ = [name for name in globals() if not name.startswith("__")]
