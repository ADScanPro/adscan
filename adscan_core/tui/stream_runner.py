"""Shared primitive for streaming a subprocess's stdout into a live dashboard.

Single source of truth for the "spawn a long-running external tool, read its
stdout line-by-line as it streams, drive a live counter from what we parse, and
return a :class:`subprocess.CompletedProcess`-shaped result" pattern.

Background — why this exists
----------------------------
Several ADscan operations wrap an opaque external binary (Nmap port scan,
kerbrute userenum / passwordspray / bruteforce) under a live progress
dashboard. The naive implementation runs the tool via a *blocking* call and
ticks the counter by polling a side artefact (an ``-oG`` / ``-o`` output file).
That artefact is buffered by the tool (Go's ``bufio`` writer for kerbrute,
Nmap's periodic file flush), so the polled counter reads **0 until the process
exits** and then jumps — the operator stares at "found 0" for the whole run.

The reliable live source is the tool's **stdout**, which most CLI tools flush
per log line. Streaming stdout and parsing each line as it arrives drives the
counter in real time. This module centralises that loop so every call site
(nmap.py, services/enumeration/kerberos.py, spraying.py) shares the same
budget-enforcement, timeout-signalling and drain semantics rather than each
re-implementing a subtly different copy.

The module is dependency-light: it imports only the stdlib and takes the
``spawn`` callable as a parameter, so it stays importable from launcher,
services and CLI alike without pulling in ``adscan_internal``.
"""

from __future__ import annotations

import subprocess
import time
from typing import Callable, Optional, Protocol

__all__ = [
    "StreamedProcessResult",
    "SpawnFailed",
    "stream_command_lines",
]


class _SpawnCallable(Protocol):
    """The ``shell.spawn_command``-shaped callable this module drives.

    Only the subset of keyword arguments this module passes is declared; the
    real ``spawn_command`` accepts more. It must return a
    :class:`subprocess.Popen` (text mode) or ``None`` on spawn failure.
    """

    def __call__(
        self,
        command: str,
        *,
        shell: bool = ...,
        stdout: int = ...,
        stderr: int = ...,
        text: bool = ...,
        bufsize: int = ...,
    ) -> "subprocess.Popen[str] | None": ...


class SpawnFailed(Exception):
    """Internal sentinel: the process could not be spawned.

    Raised so a caller driving a ``LiveSession`` can distinguish a spawn
    failure (fall back to a buffered path) from a tool error (handle normally).
    """


class StreamedProcessResult:
    """A :class:`subprocess.CompletedProcess`-shaped streaming result.

    Downstream parsing reads ``returncode``, ``stdout`` and ``stderr`` from
    whatever the runner returns. Streaming yields a :class:`subprocess.Popen`,
    so its drained output is wrapped in this lightweight shape to keep every
    post-run parsing path (``-oG`` / ``-o`` file, stdout scan) unchanged.

    Attributes:
        returncode: Process exit code (negative on timeout/kill/cancel).
        stdout: Full captured standard output.
        stderr: Full captured standard error.
        timed_out: True when the wall-clock budget was exceeded.
        cancelled: True when ``should_cancel`` reported a cooperative stop
            (an operator/platform early-stop, distinct from a timeout).
    """

    __slots__ = ("returncode", "stdout", "stderr", "timed_out", "cancelled")

    def __init__(
        self,
        returncode: int,
        stdout: str,
        stderr: str,
        *,
        timed_out: bool = False,
        cancelled: bool = False,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.cancelled = cancelled


# Throttle for ``should_cancel`` polling. A cooperative-cancellation check is
# typically a file stat (cross-process sentinel poll) — cheap once, but a
# steadily-emitting tool (kerbrute at hundreds of lines/sec) would otherwise
# stat the sentinel once per line. Checking at most once per this interval
# keeps the I/O bounded regardless of line rate; being off by up to this much
# wall-clock time before actually stopping is an acceptable trade for any
# cooperative-stop consumer (the whole point is a coarse, operator-scale
# "stop soon", not a precise per-line cutoff).
_CANCEL_CHECK_INTERVAL_SECS = 0.5


def stream_command_lines(
    spawn: _SpawnCallable,
    *,
    command: str,
    timeout_seconds: Optional[int],
    on_line: Callable[[str], None],
    on_timeout: Optional[Callable[[], None]] = None,
    on_drain: Optional[Callable[[], None]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
    on_cancel: Optional[Callable[[], None]] = None,
) -> Optional[StreamedProcessResult]:
    """Spawn ``command`` and stream its stdout line-by-line through ``on_line``.

    Reads stdout via the non-blocking ``spawn`` (which preserves the
    PyInstaller clean-env handling on the real ``shell.spawn_command``),
    invoking ``on_line`` for each decoded line as it arrives. Because
    ``Popen.readline`` has no timeout, this enforces its own wall-clock budget
    and terminates the process on overrun. After the loop it drains the
    remaining output via ``communicate`` so the returned ``stdout`` is complete
    for downstream parsing.

    ``on_line`` MUST NOT raise — it is the parse-and-drive-dashboard callback
    and a render error must never abort the stream. Callers guard their own
    body; this function does not wrap it.

    Args:
        spawn: ``shell.spawn_command``-shaped callable returning a text-mode
            :class:`subprocess.Popen` or ``None`` on spawn failure.
        command: Full command string (already shell-quoted by the caller).
        timeout_seconds: Wall-clock budget in seconds, or ``None`` for no limit.
        on_line: Per-line callback receiving each decoded stdout line (the
            trailing newline already stripped). Drives the live dashboard.
        on_timeout: Optional zero-arg callback fired exactly once when the
            wall-clock budget is exceeded (e.g. to set a timeout marker on the
            shell so a recovery prompt can fire after the Live exits).
        on_drain: Optional zero-arg callback fired exactly once after the
            stdout stream closes cleanly (no timeout, no cancel), BEFORE the
            result is returned. Lets a caller push a final dashboard frame
            (e.g. snap a determinate bar to 100%) once the tool has finished
            emitting lines.
        should_cancel: Optional zero-arg predicate polled (throttled — see
            :data:`_CANCEL_CHECK_INTERVAL_SECS`) between lines. A cooperative-
            cancellation check (e.g.
            ``CooperativeCancellation.should_stop``) — when it returns
            ``True`` the process is killed exactly like a timeout, but the
            result is marked ``cancelled=True`` instead of ``timed_out=True``
            so the caller can distinguish "operator stopped this early" from
            "this tool hung" and recover the PARTIAL output the same way.
        on_cancel: Optional zero-arg callback fired exactly once when
            ``should_cancel`` triggers a stop, before the result is returned.
            Mirrors ``on_timeout`` for the cancellation case (e.g. push a
            final dashboard frame so the partial progress is visible).

    Returns:
        A :class:`StreamedProcessResult` on completion, or ``None`` if the
        process could not be spawned (the caller falls back to a buffered path).
    """
    proc = spawn(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if proc is None or proc.stdout is None:
        return None

    stdout_lines: list[str] = []
    start = time.monotonic()
    timed_out = False
    cancelled = False
    last_cancel_check = start

    try:
        for raw_line in proc.stdout:
            stdout_lines.append(raw_line)
            on_line(raw_line.rstrip("\n"))

            now = time.monotonic()
            if timeout_seconds is not None and (now - start) > timeout_seconds:
                timed_out = True
                break
            if (
                should_cancel is not None
                and (now - last_cancel_check) >= _CANCEL_CHECK_INTERVAL_SECS
            ):
                last_cancel_check = now
                if should_cancel():
                    cancelled = True
                    break
    finally:
        if timed_out or cancelled:
            try:
                proc.kill()
            except Exception:  # noqa: BLE001 -- kill is best-effort
                pass

    if not timed_out and not cancelled and on_drain is not None:
        try:
            on_drain()
        except Exception:  # noqa: BLE001 -- final-frame callback is best-effort
            pass

    try:
        remaining_out, stderr_text = proc.communicate(timeout=10)
    except Exception:  # noqa: BLE001 -- communicate may itself time out post-kill
        remaining_out, stderr_text = "", ""
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
    if remaining_out:
        stdout_lines.append(remaining_out)

    returncode = proc.returncode if proc.returncode is not None else -1
    if timed_out:
        returncode = -1
        if on_timeout is not None:
            try:
                on_timeout()
            except Exception:  # noqa: BLE001 -- marker callback is best-effort
                pass
    elif cancelled:
        returncode = -1
        if on_cancel is not None:
            try:
                on_cancel()
            except Exception:  # noqa: BLE001 -- marker callback is best-effort
                pass

    return StreamedProcessResult(
        returncode=returncode,
        stdout="".join(stdout_lines),
        stderr=stderr_text or "",
        timed_out=timed_out,
        cancelled=cancelled,
    )
