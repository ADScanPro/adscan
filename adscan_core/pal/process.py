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


def is_specific_process_id(pid: object) -> bool:
    """Return ``True`` only for a real id that names ONE specific process.

    The signalling calls give small and non-positive ids a broadcast meaning:
    ``0`` is the caller's own process group, ``-1`` is every process the user
    may signal, and group ``1`` is the same broadcast (``killpg(1, sig)`` is
    ``kill(-1, sig)``). ``1`` itself is the init process. None of them is ever a
    child this product started, so they are refused outright.

    The type check is deliberate: an object that merely converts to an integer
    (a test double whose ``pid`` attribute answers ``__index__`` with ``1``)
    would otherwise reach the system call as id ``1``. That is exactly how a
    unit test once ended a whole desktop session.
    """
    return type(pid) is int and pid > 1  # noqa: E721 -- bool and int-likes are refused on purpose


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
        gone (``ProcessLookupError``), the signal could not be sent, or ``pid``
        does not name one specific process (see :func:`is_specific_process_id`).
    """
    if not is_specific_process_id(pid):
        return False
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
        already gone, the signal could not be sent, or the target is refused.

    Refused, never signalled: a ``pid`` that does not name one specific process
    (see :func:`is_specific_process_id`), a resolved group id that is not a
    specific group (group ``1`` is a broadcast to every process of the user),
    and the caller's OWN process group (that would end the caller, its parent
    shell and its siblings). A caller that gets ``False`` falls back to
    signalling the single child it holds.
    """
    if not is_specific_process_id(pid):
        return False
    if is_windows():
        return terminate_process(pid, force=force)
    try:
        pgid = os.getpgid(pid)
        if not is_specific_process_id(pgid) or pgid == os.getpgrp():
            return False
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


def interrupt_main_thread() -> bool:
    """Deliver an interrupt to the main thread from another thread.

    POSIX sends a real ``SIGINT`` to the main thread (``pthread_kill``), so a
    blocking system call there returns ``EINTR`` and the Python SIGINT handler
    runs at once. Windows has no per-thread signals: it schedules the SIGINT
    handler with ``_thread.interrupt_main``, which runs as soon as the main
    thread executes Python code again.

    Returns:
        Whether the interrupt was delivered.
    """
    import signal  # noqa: PLC0415
    import threading  # noqa: PLC0415

    if is_posix() and hasattr(signal, "pthread_kill"):
        try:
            ident = threading.main_thread().ident
            if ident is None:
                return False
            signal.pthread_kill(ident, signal.SIGINT)
            return True
        except (OSError, ValueError):
            return False
    try:
        import _thread  # noqa: PLC0415

        _thread.interrupt_main(signal.SIGINT)
        return True
    except (RuntimeError, ValueError, TypeError):
        return False


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


def current_rss_bytes() -> int | None:
    """Return the LIVE resident set size of the current process, in bytes.

    Unlike :func:`peak_rss_bytes` (a high-water mark that never comes down), this
    is the memory the process holds right now, which is what a memory guard must
    compare against its ceiling: a stage that ran after a larger one has to see
    the memory the larger one released, or it would stop on a peak it no longer
    holds.

    Every OS reads ``psutil.Process().memory_info().rss`` (the working set on
    Windows). ``psutil`` is a core dependency; when it cannot be imported or read
    this returns ``None`` and the caller falls back to the peak.

    Returns:
        Live RSS in bytes, or ``None`` if it cannot be determined.
    """
    try:
        import psutil

        value = int(psutil.Process().memory_info().rss)
    except Exception:  # noqa: BLE001 — a memory read must never raise into the caller.
        return None
    return value if value > 0 else None


#: ``oom_score_adj`` of a process the kernel should kill first when memory runs
#: out (the maximum). Raising a process's own score needs no privilege.
PREFERRED_OOM_VICTIM_SCORE = 1000


def make_preferred_oom_victims(names: tuple[str, ...]) -> int:
    """Make this process's descendants whose name matches ``names`` the kernel's
    first choice when memory runs out. Returns how many were adjusted.

    A child that allocates a lot (the report's headless browser) can push the
    whole cgroup to the limit; the kernel then kills the process with the
    highest score, which is otherwise the engine, its parent and the larger of
    the two. With the child's score raised, the child dies instead and the
    engine sees a failed render it can declare.

    Linux writes ``/proc/<pid>/oom_score_adj``. Windows has no equivalent (its
    out-of-memory behaviour fails allocations, it does not kill by score), and
    there this is a no-op returning ``0``. Never raises.

    Args:
        names: Substrings matched against each descendant's process name and
            command line (``"chrom"``, ``"headless_shell"``).
    """
    if not is_posix() or is_windows():
        return 0
    try:
        import psutil

        children = psutil.Process().children(recursive=True)
    except Exception:  # noqa: BLE001 — a best-effort adjustment never raises
        return 0
    wanted = tuple(str(n).lower() for n in names if str(n or "").strip())
    adjusted = 0
    for child in children:
        try:
            label = " ".join([child.name(), *child.cmdline()[:1]]).lower()
        except Exception:  # noqa: BLE001 — the process may have exited
            continue
        if not any(n in label for n in wanted):
            continue
        try:
            with open(f"/proc/{child.pid}/oom_score_adj", "w", encoding="ascii") as handle:
                handle.write(str(PREFERRED_OOM_VICTIM_SCORE))
            adjusted += 1
        except OSError:
            continue
    return adjusted


def release_free_heap() -> bool:
    """Ask the C allocator to hand freed heap pages back to the OS, best-effort.

    CPython returns a freed arena to the OS, but glibc ``malloc`` keeps freed
    small-block pages in the process until something trims them, so after a
    large stage unwinds the resident set can stay near its peak. A stage that
    switches to a streamed mode after a memory stop needs that memory to show
    as released, or its own guard trips at once on memory nobody holds.

    Linux with glibc calls ``malloc_trim(0)``. Other platforms (Windows, musl,
    macOS) have no equivalent call and this is a no-op.

    The symbol is looked up on ``ctypes.CDLL(None)``, the libraries already loaded
    into this process, never through ``ctypes.util.find_library``: that spawns
    ``ldconfig`` or a compiler to search for libc, at exactly the moment memory is
    short, and can fail inside a frozen (PyInstaller) build.

    Returns:
        ``True`` when a trim ran, ``False`` otherwise. Never raises.
    """
    if not is_posix():
        return False
    try:
        import ctypes

        trim = getattr(ctypes.CDLL(None), "malloc_trim", None)
        if trim is None:
            return False
        trim.argtypes = [ctypes.c_size_t]
        trim.restype = ctypes.c_int
        trim(0)
        return True
    except Exception:  # noqa: BLE001 — best-effort; never break the caller.
        return False


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


def open_with_desktop_app(path: str) -> bool:
    """Open ``path`` with the desktop's default application, best-effort.

    Windows uses ``os.startfile`` (the shell association); POSIX spawns the
    first desktop opener on ``PATH`` (``xdg-open`` on Linux, ``open`` on
    macOS), detached from our output. The launch itself is asynchronous and
    cannot be confirmed.

    Returns:
        True when an opener was dispatched, False when none is available.
    """
    if is_windows():
        startfile = getattr(os, "startfile", None)
        if startfile is None:
            return False
        startfile(str(path))  # pylint: disable=not-callable
        return True
    import shutil  # noqa: PLC0415

    opener = shutil.which("xdg-open") or shutil.which("open")
    if not opener:
        return False
    subprocess.Popen(  # noqa: S603 - fixed opener, path passed as one argv item
        [opener, str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return True
