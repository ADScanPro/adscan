"""Keep a long-running tool alive when the operator presses Ctrl+C.

A child process started from the scan shares the terminal's foreground process
group, so the terminal delivers Ctrl+C to it too: the tool dies at the same
moment the operator menu opens, and "keep going" can no longer keep it going.
A non-interactive tool (it never reads the terminal) can run in its own session
instead. It is then stopped by the scan control plane (the step's in-loop
checkpoint stops launching new work and lets in-flight work drain), never by the
key press.

Only for tools that never read stdin: the child gets ``/dev/null`` on stdin and
no controlling terminal, so a tool that prompts would read end-of-file.
"""

from __future__ import annotations

import subprocess
from typing import Any


def terminal_isolated_subprocess_kwargs() -> dict[str, Any]:
    """``subprocess`` kwargs that detach a non-interactive tool from Ctrl+C.

    POSIX: a new session (``start_new_session``), so the terminal's SIGINT does
    not reach it. Windows: a new process group, which keeps the console's
    Ctrl+C away from it. Both through the PAL (``pal.process.new_session_kwargs``).
    """
    from adscan_core.pal.process import new_session_kwargs  # noqa: PLC0415

    kwargs: dict[str, Any] = dict(new_session_kwargs())
    kwargs["stdin"] = subprocess.DEVNULL
    return kwargs


__all__ = ["terminal_isolated_subprocess_kwargs"]
