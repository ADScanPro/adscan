"""Compatibility shim for update management.

Update logic is a host/launcher responsibility and lives in `adscan_launcher`.
This module re-exports the public API for backwards compatibility with the
full in-repo CLI (`adscan.py`).
"""

from __future__ import annotations

from adscan_launcher.update_manager import (  # noqa: F401
    UpdateContext,
    get_docker_update_info,
    get_launcher_update_info,
    handle_update_command,
    offer_updates_for_command,
    run_update_command,
)

__all__ = [
    "UpdateContext",
    "get_docker_update_info",
    "get_launcher_update_info",
    "offer_updates_for_command",
    "run_update_command",
    "handle_update_command",
]
