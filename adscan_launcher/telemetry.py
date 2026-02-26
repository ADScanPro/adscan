"""Launcher telemetry module.

Canonical implementation lives in `adscan_core.telemetry`. The launcher imports
and uses it directly so host-side and runtime-side telemetry share a single
source of truth.
"""

from __future__ import annotations

from adscan_core.telemetry import *  # noqa: F403
