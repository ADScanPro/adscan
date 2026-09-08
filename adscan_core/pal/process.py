"""Process / signal / POSIX-module seam for the PAL.

A thin cross-platform layer over process signalling, session detachment, and the
POSIX-only stdlib modules (``resource``, ``pwd``) so a Windows backend can replace
the POSIX-only primitives without every caller re-implementing the OS split.

Design rules (kept deliberately narrow):

- Only stdlib is imported. ``signal``, ``subprocess`` and ``os`` exist on Windows
  and are imported at module top. ``resource`` and ``pwd`` are POSIX-only and are
  imported INSIDE the functions that need them, guarded by :func:`is_posix` — an
  unconditional ``import resource`` at module top breaks the import on Windows.
- Every function DEGRADES rather than raising for the Windows-lacking case: it
  returns ``False`` / ``None`` with the documented semantics so callers can fall
  back cleanly.

Consumes :func:`adscan_core.pal.platform.is_windows` / ``is_posix`` for the OS
split, which honours the ``ADSCAN_PAL_OS`` override so a POSIX host can exercise
the Windows selection deterministically in tests.
"""
from __future__ import annotations

import os
import signal
import subprocess

from adscan_core.pal.platform import is_posix, is_windows


def terminate_process(pid: int, *, force: bool = False) -> bool:
    """Signal a single process to terminate.

    POSIX sends ``SIGKILL`` when ``force`` is set, otherwise ``SIGTERM``. On
    Windows ``os.kill(pid, signal.SIGTERM)`` maps to ``TerminateProcess`` (there
    is no graceful/forceful distinction, so ``force`` is ignored there).

    Args:
        pid: Target process id.
        force: On POSIX, use ``SIGKILL`` instead of ``SIGTERM``.

    Returns:
        ``True`` if the signal was delivered, ``False`` if the process was already
        gone (``ProcessLookupError``) or the signal could not be sent.
    """
    try:
        if is_windows():
            # Windows maps SIGTERM to TerminateProcess; no SIGKILL concept.
            os.kill(pid, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
        return True
    except ProcessLookupError:
        return False
    except (OSError, PermissionError):
        return False


def terminate_process_group(pid: int, *, force: bool = False) -> bool:
    """Signal a whole process group to terminate.

    POSIX resolves the process group with ``os.getpgid`` and signals it with
    ``os.killpg`` (``SIGKILL`` when ``force`` is set, otherwise ``SIGTERM``).
    Windows has no POSIX process groups, so this falls back to
    :func:`terminate_process` for the single ``pid`` — the caller loses group
    semantics on Windows, which is acceptable for v1.

    Args:
        pid: A process id belonging to the target group.
        force: On POSIX, use ``SIGKILL`` instead of ``SIGTERM``.

    Returns:
        ``True`` if the signal was delivered, ``False`` if the group/process was
        already gone or the signal could not be sent.
    """
    if is_windows():
        return terminate_process(pid, force=force)
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGKILL if force else signal.SIGTERM)
        return True
    except ProcessLookupError:
        return False
    except (OSError, PermissionError):
        return False


def process_is_alive(pid: int) -> bool:
    """Report whether a process is currently alive.

    Uses the ``os.kill(pid, 0)`` liveness probe on both POSIX and Windows (Python
    emulates a signal-0 liveness check on Windows). A ``ProcessLookupError`` means
    the process is gone; a ``PermissionError`` means it exists but we may not
    signal it (still alive).

    Args:
        pid: Target process id.

    Returns:
        ``True`` if the process appears to exist, ``False`` otherwise.
    """
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def new_session_kwargs() -> dict:
    """Return the ``subprocess`` kwargs that detach a child into its own session.

    POSIX returns ``{"start_new_session": True}`` (equivalent to a ``setsid``
    ``preexec_fn`` but without the fork-safety pitfalls). Windows detaches via a
    new process group with ``CREATE_NEW_PROCESS_GROUP`` when that flag exists,
    otherwise returns an empty dict.

    Callers pass ``**new_session_kwargs()`` to ``subprocess.Popen`` instead of
    hardcoding ``preexec_fn=os.setsid`` / ``start_new_session=True``.

    Returns:
        A kwargs dict suitable for splatting into ``subprocess.Popen``.
    """
    if is_windows():
        flag = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", None)
        if flag is None:
            return {}
        return {"creationflags": flag}
    return {"start_new_session": True}


def peak_rss_bytes() -> int | None:
    """Return the peak resident set size of the current process, in bytes.

    POSIX reads ``resource.getrusage(RUSAGE_SELF).ru_maxrss`` (reported in
    kilobytes on Linux) and converts to bytes. Windows uses
    ``psutil.Process().memory_info().peak_wset`` when ``psutil`` is available,
    otherwise returns ``None``.

    This replaces the unconditional ``import resource`` in ``memory_probe.py``,
    which breaks the module import on Windows.

    Returns:
        Peak RSS in bytes, or ``None`` if it cannot be determined.
    """
    if is_posix():
        try:
            import resource  # POSIX-only; guarded import.

            return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
        except (OSError, ValueError, AttributeError):
            return None
    try:
        import psutil

        return int(psutil.Process().memory_info().peak_wset)
    except Exception:
        return None


def effective_user_is_root() -> bool:
    """Report whether the current effective user is root.

    POSIX returns ``os.geteuid() == 0``. Windows has no root concept, so this
    returns ``False`` — the privileged (sudo) paths are Linux-only and not on the
    Windows critical path, so they degrade cleanly.

    Returns:
        ``True`` only when running as effective uid 0 on POSIX.
    """
    if is_windows():
        return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def lookup_user_home(username: str) -> str | None:
    """Return a named user's home directory, or ``None`` when unavailable.

    POSIX resolves it via ``pwd.getpwnam(username).pw_dir``. Windows returns
    ``None`` (there is no ``pwd``); the caller falls back to ``Path.home()``.
    Isolates the POSIX-only ``pwd`` import.

    Args:
        username: The account name to resolve.

    Returns:
        The user's home directory path, or ``None`` if it cannot be resolved.
    """
    if is_windows():
        return None
    try:
        import pwd  # POSIX-only; guarded import.

        return pwd.getpwnam(username).pw_dir
    except (KeyError, AttributeError, OSError):
        return None


def current_user_name() -> str | None:
    """Return the current effective user's account name, or ``None``.

    POSIX resolves it via ``pwd.getpwuid(os.getuid()).pw_name`` (isolating the
    POSIX-only ``pwd`` import). Windows uses ``getpass.getuser()`` (best-effort).
    Never raises — callers use it as a ``chown`` target and fall back to
    ``$SUDO_USER`` / skip the ownership fix when it is ``None``.

    Returns:
        The account name, or ``None`` if it cannot be resolved.
    """
    if is_windows():
        try:
            import getpass

            return getpass.getuser()
        except Exception:  # pragma: no cover - best-effort on Windows
            return None
    try:
        import pwd  # POSIX-only; guarded import.

        return pwd.getpwuid(os.getuid()).pw_name
    except (KeyError, AttributeError, OSError):
        return None
