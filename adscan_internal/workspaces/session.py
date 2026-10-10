from __future__ import annotations

from typing import Any

from adscan_internal.workspaces.manager import resolve_workspace_paths


def activate_workspace(shell: Any, *, workspaces_dir: str, workspace_name: str) -> str:
    """Set the active workspace fields on the shell.

    This helper only mutates in-memory state. It does not perform any I/O or
    call `load_workspace_data()` so the CLI can decide when to apply side-effects.

    Args:
        shell: CLI shell instance (adscan.PentestShell).
        workspaces_dir: Root directory containing all workspaces.
        workspace_name: Workspace folder name.

    Returns:
        Absolute workspace directory path.
    """
    paths = resolve_workspace_paths(workspaces_dir, workspace_name)
    shell.current_workspace = workspace_name
    shell.current_workspace_dir = paths.root

    # Initialise the environment change ledger for the newly activated workspace.
    # Wrapped in a broad except so a ledger failure never blocks workspace activation.
    try:
        from adscan_internal.services.environment_change_ledger import (
            EnvironmentChangeLedger,
            register_session_ledger,
        )

        shell.environment_change_ledger = EnvironmentChangeLedger(paths.root)
        # Publish it for this workspace. A report rendered DURING the run (the
        # in-run `ci --generate-report` seam, every `deliver` helper) receives a
        # workspace path and no shell, and the ledger file may not be flushed
        # yet at that instant: without this the report states that the change
        # record could not be read while the record is live in the session.
        register_session_ledger(shell.environment_change_ledger, workspace_dir=paths.root)
    except Exception:  # noqa: BLE001 — best-effort, must not break activation
        shell.environment_change_ledger = None
        try:
            from adscan_internal.services.environment_change_ledger import (
                register_session_ledger as _unregister,
            )

            # A workspace whose ledger could not be initialized must not inherit
            # a stale registration from a previously activated workspace.
            _unregister(None, workspace_dir=paths.root)
        except Exception:  # noqa: BLE001
            pass

    shell.acl_cleanup_actions: list[dict] = []

    # Deferred MSSQL SYSTEM-escalation admin-account reverts (mirrors
    # acl_cleanup_actions). A follow-up that mints an ephemeral privileged
    # account to prove SYSTEM registers the revert HERE instead of running it
    # inline, so the account stays alive through every later scan phase that
    # may still authenticate as it (attack-path materialization, privilege
    # sweeps) — see services/mssql_system_dc_extraction.py.
    shell.mssql_cleanup_actions: list[dict] = []

    return paths.root


__all__ = [
    "activate_workspace",
]
