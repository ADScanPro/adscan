"""Flags that were removed from ``ci`` / ``execute`` / ``doctor``, with what to do instead.

argparse alone answers a removed flag with "unrecognized arguments", which tells
a user with an old script nothing. Both the host launcher (before it starts a
container) and the engine entry point (``adscan.py``, which also runs in-process
on Windows and in the appliance dev path) check the argv against this table and
exit 2 with the replacement.

This module is the ONE place the removed spelling may appear in code; the guard
``tests/unit/cli/test_keep_workspace_flag_removed.py`` allow-lists it.
"""

from __future__ import annotations

from typing import Iterable, Optional

#: Commands whose argv is checked.
CHECKED_COMMANDS: frozenset[str] = frozenset({"ci", "execute", "doctor"})

#: Removed flag -> message shown instead of argparse's "unrecognized arguments".
REMOVED_FLAGS: dict[str, str] = {
    "--keep-workspace": (
        "--keep-workspace was removed: ci and execute keep their workspace by "
        "default. Drop the flag, or pass --ephemeral to delete the workspace a run "
        "creates."
    ),
}


def removed_flag_message(argv: Iterable[str]) -> Optional[str]:
    """The message for the first removed flag in ``argv``, or None.

    Only an argv naming one of :data:`CHECKED_COMMANDS` is checked, from that
    command on (global options before it may take values). Tokens after a bare
    ``--`` are left alone: they belong to the verb ``execute`` runs.
    """
    tokens = [str(token) for token in argv]
    start = next((i for i, t in enumerate(tokens) if t in CHECKED_COMMANDS), None)
    if start is None:
        return None
    for token in tokens[start + 1:]:
        if token == "--":
            return None
        flag = token.split("=", 1)[0]
        if flag in REMOVED_FLAGS:
            return REMOVED_FLAGS[flag]
    return None
