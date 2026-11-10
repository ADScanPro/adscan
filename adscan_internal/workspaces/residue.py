"""Engine-side name of the workspace-residue purge.

The implementation moved to :mod:`adscan_core.workspace_residue` so the
Enterprise platform's worker, which cannot import the engine, runs the same
purge when a workspace is deleted from the console. This module keeps the
engine import path working; add nothing here.
"""

from __future__ import annotations

from adscan_core.workspace_residue import (
    _remove_workspace_lock,
    purge_workspace_residue,
    workspace_domains,
)

__all__ = ["_remove_workspace_lock", "purge_workspace_residue", "workspace_domains"]
