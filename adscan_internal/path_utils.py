"""Compatibility shim for path utilities.

The canonical implementation lives in `adscan_core.path_utils` so both the
launcher and runtime share a single source of truth.
"""

from __future__ import annotations

from adscan_core.path_utils import *  # noqa: F403
