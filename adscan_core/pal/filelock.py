"""PAL advisory file locking (cross-process, OS-neutral).

An advisory lock held on an open file descriptor, used where two ADscan
PROCESSES have to serialize access to one machine-wide resource (today: the
single GPU a hashcat run owns). An in-process ``threading.Lock`` cannot see a
sibling process, and this machine routinely runs several ADscan sessions at
once.

**Why an advisory file lock and not a lockfile holding a PID.** A PID file does
not survive its holder being killed: the process dies, the file stays, and the
resource is deadlocked for every later run until somebody deletes it by hand.
That matters most for exactly the long-running holder this module exists for, a
crack that an operator may well interrupt. An advisory lock is a property of the
open file DESCRIPTION, so the kernel releases it when the holder exits for any
reason, including ``SIGKILL``. Stale-holder recovery is therefore not a code
path with a timeout to tune; it is the primitive's own behaviour.

**Per-OS implementation.** ``fcntl.flock`` on POSIX, ``msvcrt.locking`` on
Windows, both lazily imported inside their own branch so this module imports
cleanly on either platform (the PAL rule in CLAUDE.md § Cross-platform).
Windows byte-range locks are exclusive only and have no indefinite wait, so a
shared lock reports unsupported there and a blocking acquire polls. Callers must
degrade honestly rather than require the lock: see :func:`file_lock_supported`.
"""

from __future__ import annotations

import importlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Optional

from adscan_core.pal.platform import is_windows

__all__ = [
    "FileLockHandle",
    "acquire_file_lock",
    "file_lock_supported",
    "release_file_lock",
    "shared_file_lock_supported",
]

# Poll interval for a bounded blocking acquire. Neither backend offers a native
# timed wait (``flock`` blocks forever or not at all; ``msvcrt`` retries on its
# own schedule), so a deadline is honoured by retrying the non-blocking form.
_POLL_SECONDS = 0.05

# Windows locks a byte RANGE rather than the whole file, so every participant
# has to agree on the same range. One byte at offset zero is the convention.
_WINDOWS_LOCK_BYTES = 1


@dataclass
class FileLockHandle:
    """An acquired advisory lock plus the open descriptor that carries it."""

    path: Path
    fd: IO[str]
    shared: bool = False
    #: ``False`` when no OS lock backs this handle. Only produced by callers
    #: that asked to proceed unlocked; :func:`acquire_file_lock` never returns
    #: an unlocked handle.
    os_locked: bool = True


def _fcntl():
    """The POSIX ``fcntl`` module, or ``None`` where it does not exist."""
    if is_windows():
        return None
    try:
        return importlib.import_module("fcntl")
    except ImportError:
        return None


def _msvcrt():
    """The Windows ``msvcrt`` module, or ``None`` where it does not exist."""
    if not is_windows():
        return None
    try:
        return importlib.import_module("msvcrt")
    except ImportError:
        return None


def file_lock_supported() -> bool:
    """Whether this platform can take an exclusive advisory file lock.

    ``False`` means a caller must fall back to whatever in-process coordination
    it already had, never that it should refuse to run.
    """
    return _fcntl() is not None or _msvcrt() is not None


def shared_file_lock_supported() -> bool:
    """Whether this platform can take a SHARED advisory file lock.

    POSIX only. Windows byte-range locks are exclusive, so a caller using a
    shared lock as a presence flag has to degrade there.
    """
    return _fcntl() is not None


def _try_lock_once(handle: IO[str], *, shared: bool) -> Optional[bool]:
    """One non-blocking lock attempt.

    Returns ``True`` when the lock was taken, ``False`` when another holder has
    it, and ``None`` when this platform cannot lock at all.
    """
    fcntl = _fcntl()
    if fcntl is not None:
        mode = (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB
        try:
            fcntl.flock(handle.fileno(), mode)
        except (BlockingIOError, OSError):
            return False
        return True
    msvcrt = _msvcrt()
    if msvcrt is not None:
        if shared:
            # No shared mode on Windows. Reporting "unsupported" rather than
            # taking an exclusive lock keeps a presence flag from behaving as a
            # mutex and serializing readers against each other.
            return None
        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, _WINDOWS_LOCK_BYTES)
        except OSError:
            return False
        return True
    return None


def _unlock(handle: IO[str], *, shared: bool) -> None:
    """Best-effort release. Closing the descriptor releases it regardless."""
    if handle.closed:
        return
    fcntl = _fcntl()
    if fcntl is not None:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (OSError, ValueError):
            pass
        return
    msvcrt = _msvcrt()
    if msvcrt is not None and not shared:
        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, _WINDOWS_LOCK_BYTES)
        except (OSError, ValueError):
            pass


def acquire_file_lock(
    path: "str | Path",
    *,
    shared: bool = False,
    blocking: bool = False,
    timeout: Optional[float] = None,
) -> Optional[FileLockHandle]:
    """Acquire an advisory lock on ``path``, creating the file if needed.

    Args:
        path: The lock file. Its directory is created when absent.
        shared: Take a shared (reader) lock instead of an exclusive one. POSIX
            only; see :func:`shared_file_lock_supported`.
        blocking: Wait for the lock rather than returning immediately.
        timeout: Bound on the wait in seconds when ``blocking``. ``None`` waits
            indefinitely.

    Returns:
        The owning :class:`FileLockHandle`, or ``None`` when the lock was not
        taken: another holder has it, the wait timed out, or this platform
        cannot lock. "Not taken" and "no lock file could be made" are kept
        apart on purpose, because they call for opposite behaviour in the
        caller: the first means somebody owns the resource, the second means
        there is no lock to be had and the caller should carry on without one.
        So a lock file that cannot be created or opened raises ``OSError``
        rather than reporting a holder that does not exist.

    Raises:
        OSError: The lock file could not be created or opened (a read-only
            filesystem, a constrained deploy, a permissions problem).
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle = open(target, "a+", encoding="utf-8")  # noqa: SIM115

    deadline = (
        None if (not blocking or timeout is None) else time.monotonic() + float(timeout)
    )
    try:
        while True:
            outcome = _try_lock_once(handle, shared=shared)
            if outcome is None:
                handle.close()
                return None
            if outcome:
                return FileLockHandle(path=target, fd=handle, shared=shared)
            if not blocking:
                handle.close()
                return None
            if deadline is not None and time.monotonic() >= deadline:
                handle.close()
                return None
            time.sleep(_POLL_SECONDS)
    except Exception:
        try:
            handle.close()
        except OSError:
            pass
        raise


def release_file_lock(handle: Optional[FileLockHandle]) -> None:
    """Release a lock taken by :func:`acquire_file_lock`. Never raises."""
    if handle is None:
        return
    if handle.os_locked:
        _unlock(handle.fd, shared=handle.shared)
    try:
        handle.fd.close()
    except OSError:
        pass
