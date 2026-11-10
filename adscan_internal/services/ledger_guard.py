"""Fail-loud access to the environment-change ledger.

Every recorder that registers a directory write used to do
``getattr(shell, "environment_change_ledger", None)`` and return silently when
it was ``None``. That hid a real defect: an entry point that skipped
``activate_workspace`` ran live directory writes with no record, and the
report then had nothing to tell the client to clean up. This helper keeps the
best-effort contract (a missing ledger never aborts the technique) but makes
the gap visible to the operator and to telemetry.
"""

from __future__ import annotations

import sys
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_warning

_WARNED_ACTIONS: set[str] = set()


def ledger_or_warn(shell: Any, action: str | None = None) -> Any:
    """Return the shell's live environment-change ledger, warning when absent.

    Args:
        shell: The CLI shell instance.
        action: Short label of the write being recorded. Defaults to the
            calling function's name.

    Returns:
        The ledger, or ``None`` after a warning and a telemetry event. The
        warning is emitted once per action per process so a loop cannot flood
        the console; the telemetry event is sent every time.
    """
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is not None:
        return ledger
    label = action or sys._getframe(1).f_code.co_name
    try:
        telemetry.capture(
            "environment_ledger_missing",
            properties={
                "action": label,
                "session_command": getattr(shell, "session_command_type", None),
            },
        )
    except Exception:  # noqa: BLE001 - diagnostics must never break the technique
        pass
    if label not in _WARNED_ACTIONS:
        _WARNED_ACTIONS.add(label)
        try:
            print_warning(
                f"A directory change ('{label}') could not be recorded: no change ledger is "
                "active for this session. It will be missing from the cleanup list; review "
                "the target directory manually."
            )
        except Exception:  # noqa: BLE001
            pass
    return None


def active_ledger(shell: Any) -> Any:
    """Return the shell's live ledger, or ``None`` silently.

    For READ-ONLY consumers that only look for records an earlier step left
    pending (the exit cleanup resolvers, the final revert pass). They record
    nothing, so a session without a ledger (``report``, ``deliver`` and every
    other command that never writes to the directory) has nothing for them to
    find, and the "could not be recorded" warning would be false. A WRITE seam
    keeps using :func:`ledger_or_warn`.
    """
    return getattr(shell, "environment_change_ledger", None)
