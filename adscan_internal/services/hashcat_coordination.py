"""SSOT for serializing concurrent hashcat process launches.

hashcat enforces a single-instance lock keyed on the binary path: a second
hashcat process aborts with ``Already an instance '<path>' running on pid N``.
Two ADscan surfaces can race for it — a REAL crack (the interactive
``cli/cracking`` path or the background ``cracking-job``) and the best-effort
measurements that plan the crack: the benchmark warm-up's ``hashcat -b`` and
the achieved-rate probe's short real attack. A real crack must NEVER fail or be
starved by a disposable measurement.

One slot serializes every hashcat launch so two can never overlap:

* A real crack acquires it BLOCKING via :func:`hashcat_slot` (``block=True``),
  so it always eventually runs and never collides.
* A measurement acquires it NON-BLOCKING via ``hashcat_slot(block=False)`` and
  SKIPS its run when the slot is held, yielding the hardware to the crack.

**The slot spans PROCESSES, not just threads.** One machine has one GPU, and
this one routinely runs several ADscan sessions at once, so an in-process mutex
is not the boundary that matters. Measured on 2026-10-09: two achieved-rate
probes of mode 5600 taken while several sessions were active disagreed by 99%
(168 against 336 MH/s), and the effort estimate for that mode landed 43% off
its real time. The same two probes on a quiet GPU agree to within 7.4%. The
probe was sound; it took a slot that was free in ITS process, measured a GPU
somebody else was using, and reported the result as measured. So the slot is
two layers: a process-wide re-entrant mutex, plus an advisory file lock under
the ADscan home that every ADscan process on the box sees (``~/.adscan`` is
bind-mounted into the container at ``/opt/adscan``, so the host launcher and the
containerized runtime share one lock file).

The consequence is the point of the design, not a side effect: a probe loses
the slot MORE often now, skips, and the effort estimate falls back to the
provisional calibration and SAYS it is provisional. Fewer measurements, none of
them taken under contention and quoted as though they were clean.

**Stale holders need no cleanup.** The file lock is advisory and lives on the
open file DESCRIPTION, so the kernel drops it when the holder exits for any
reason, ``SIGKILL`` included. A killed crack therefore frees the GPU for the
next run with nothing to reap, which a lockfile holding a PID could not do.

**Degrade, never fail.** Where no advisory lock can be taken at all (no
platform support, a read-only filesystem, a constrained deploy) the slot falls
back to the in-process mutex alone. Cracking must not become unavailable
because a lock file could not be created.

**Priority signalling (the anti-starvation half).** A plain "skip if held"
non-blocking acquire is NOT enough: ``threading.RLock`` is not fair, so a
benchmark that releases the slot between modes and immediately re-acquires
``block=False`` in a tight loop can keep WINNING the lock against a real crack
that is already blocked in ``block=True`` acquire — starving it across a whole
multi-mode ``hashcat -b`` sweep (minutes). To break that, every ``block=True``
caller (a real crack) registers its DEMAND for the slot for the entire duration
it waits for AND holds it. The benchmark checks :func:`real_crack_pending`
between modes and PAUSES its sweep the moment a real crack wants the hardware —
so the crack gets the GPU within one in-flight ``hashcat -b`` mode, not after
the full sweep. The warm-up resumes (from its persisted partial progress) on a
later scan once no real crack is pending. The real crack is always the priority;
the measurement is best-effort. Demand is published across processes too, as a
SHARED lock a real crack holds on a second file: a measurement in one session
then yields to a crack in another before launching anything. Windows byte-range
locks have no shared mode, so there demand stays in-process and a measurement
discovers the contention one step later, when the exclusive slot refuses it.

The in-process mutex is module-level and re-entrant, so nested wrapping on the
same thread never deadlocks; the file lock is taken only at the outermost
nesting level, because an advisory lock is not re-entrant across two
descriptors on the same file.
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

# Re-entrant so a single thread that nests two hashcat launches (e.g. a crack
# run followed by its ``--show`` read) never deadlocks against itself. Across
# threads it behaves as a normal mutex.
_HASHCAT_SLOT = threading.RLock()

# Nesting depth of the slot on the CURRENT thread. The cross-process file lock
# is acquired only when this goes 0 -> 1, because an advisory lock taken on a
# second descriptor of the same file conflicts with the one this thread already
# holds; the re-entrant mutex above is what makes nesting safe.
_NESTING = threading.local()

# Count of threads currently WAITING FOR or HOLDING the slot as a real crack
# (a ``block=True`` caller). Guarded by its own lightweight lock so it can be
# read (``real_crack_pending``) without touching the slot mutex itself. The
# convention is fixed (see module docstring): ``block=True`` == a real crack
# whose priority must never be starved; ``block=False`` == a best-effort
# measurement. Inferring crack-demand from ``block`` is safe in the only
# direction that matters — an unexpected ``block=True`` caller merely makes the
# best-effort measurement yield MORE, never a crack yield to the measurement.
_DEMAND_LOCK = threading.Lock()
_real_crack_demand = 0

# The cross-process demand flag, held SHARED by every waiting-or-running real
# crack in this process while ``_real_crack_demand`` is above zero.
_demand_handle = None

#: Bound on publishing the shared demand flag, which only ever contends with
#: the momentary exclusive read in ``_foreign_crack_pending``.
_DEMAND_PUBLISH_TIMEOUT = 2.0

#: File name of the exclusive slot, inside the ADscan lock directory.
_SLOT_LOCK_NAME = "hashcat-gpu.lock"
#: File name of the shared demand flag. Separate from the slot because demand
#: is published while a crack is still WAITING for the slot it cannot hold yet.
_DEMAND_LOCK_NAME = "hashcat-gpu-demand.lock"


def _lock_path(name: str) -> Optional[Path]:
    """Resolve a lock-file path under the ADscan lock directory, or ``None``.

    Routed through the paths SSOT rather than a literal, so the file lands
    under the bind-mounted ADscan home and is therefore visible to BOTH the
    host launcher and the containerized runtime. ``None`` when the location
    cannot be resolved at all, which the caller degrades on.
    """
    try:
        from adscan_core.paths import get_locks_dir  # noqa: PLC0415

        return get_locks_dir() / name
    except Exception:  # noqa: BLE001 -- an unresolvable home degrades to in-process
        return None


def _acquire_slot_file_lock(
    *, blocking: bool, timeout: Optional[float]
) -> "tuple[object | None, bool]":
    """Take the cross-process slot lock.

    Returns ``(handle, contended)``. ``handle`` is ``None`` when no lock is
    held, and ``contended`` distinguishes the two reasons for that: ``True``
    means another process holds the slot (the caller must not launch hashcat),
    ``False`` means there was no lock to take in the first place (no platform
    support, no writable lock directory) and the caller proceeds on the
    in-process mutex alone. Getting that distinction wrong in the second
    direction would make an unwritable lock file disable cracking outright,
    which is why the PAL raises on an unusable file instead of reporting a
    holder that does not exist.
    """
    from adscan_core.pal.filelock import (  # noqa: PLC0415
        acquire_file_lock,
        file_lock_supported,
    )

    if not file_lock_supported():
        return None, False
    path = _lock_path(_SLOT_LOCK_NAME)
    if path is None:
        return None, False
    try:
        handle = acquire_file_lock(path, blocking=blocking, timeout=timeout)
    except Exception:  # noqa: BLE001 -- no usable lock file; degrade in-process
        return None, False
    return (handle, False) if handle is not None else (None, True)


def _release_slot_file_lock(handle: object | None) -> None:
    if handle is None:
        return
    try:
        from adscan_core.pal.filelock import release_file_lock  # noqa: PLC0415

        release_file_lock(handle)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 -- best effort; the fd closes regardless
        pass


def _publish_demand_locked() -> None:
    """Take the shared cross-process demand flag. Caller holds ``_DEMAND_LOCK``."""
    global _demand_handle
    if _demand_handle is not None:
        return
    try:
        from adscan_core.pal.filelock import (  # noqa: PLC0415
            acquire_file_lock,
            shared_file_lock_supported,
        )

        if not shared_file_lock_supported():
            return
        path = _lock_path(_DEMAND_LOCK_NAME)
        if path is None:
            return
        # Bounded blocking rather than a bare attempt: ``_foreign_crack_pending``
        # takes this same file exclusively for an instant to read it, and a
        # crack that lost its demand flag to that instant would be invisible to
        # every other session for the whole of its run.
        _demand_handle = acquire_file_lock(
            path, shared=True, blocking=True, timeout=_DEMAND_PUBLISH_TIMEOUT
        )
    except Exception:  # noqa: BLE001 -- demand degrades to the in-process count
        _demand_handle = None


def _withdraw_demand_locked() -> None:
    """Drop the shared demand flag. Caller holds ``_DEMAND_LOCK``."""
    global _demand_handle
    handle, _demand_handle = _demand_handle, None
    _release_slot_file_lock(handle)


def _foreign_crack_pending() -> bool:
    """Whether a real crack in ANOTHER process has demand registered.

    Read by taking the demand flag EXCLUSIVELY, non-blocking: refused means
    somebody holds it shared, which is exactly the signal. ``False`` wherever
    the shared mode is unavailable (Windows) or nothing can be locked, so this
    never invents contention it cannot see.
    """
    try:
        from adscan_core.pal.filelock import (  # noqa: PLC0415
            acquire_file_lock,
            release_file_lock,
            shared_file_lock_supported,
        )

        if not shared_file_lock_supported():
            return False
        path = _lock_path(_DEMAND_LOCK_NAME)
        if path is None or not path.exists():
            return False
        handle = acquire_file_lock(path)
    except Exception:  # noqa: BLE001 -- unreadable means "no demand seen"
        return False
    if handle is None:
        return True
    release_file_lock(handle)
    return False


def shared_demand_supported() -> bool:
    """Whether real-crack demand is observable ACROSS processes on this platform.

    ``True`` where a shared advisory lock exists (POSIX). ``False`` on Windows,
    whose byte-range locks are exclusive only: demand stays in-process there and
    a measurement discovers a sibling session's crack one step later, when the
    exclusive slot refuses it. Exposed so a caller can say which of the two it
    is looking at rather than read a ``False`` as "nobody is cracking".
    """
    try:
        from adscan_core.pal.filelock import (  # noqa: PLC0415
            shared_file_lock_supported,
        )

        return shared_file_lock_supported()
    except Exception:  # noqa: BLE001 -- unresolvable means not observable
        return False


def real_crack_pending() -> bool:
    """True while any real crack is waiting for or holding the hashcat slot.

    Covers this process (a lock-guarded counter) and, where
    :func:`shared_demand_supported`, every other ADscan process on the box (the
    shared demand flag), because the GPU is one machine-wide resource. The
    best-effort benchmark warm-up polls this between modes and pauses its
    ``hashcat -b`` sweep the moment it is ``True``, so a real crack is never
    starved behind a multi-mode benchmark. The in-process half is a guarded
    counter read; the cross-process half opens and locks a small file, so this
    belongs between units of work (where its callers use it) rather than inside
    a hot loop.
    """
    with _DEMAND_LOCK:
        if _real_crack_demand > 0:
            return True
    return _foreign_crack_pending()


def _enter_nesting() -> bool:
    """Increment this thread's slot depth; True when it is the outermost entry."""
    depth = getattr(_NESTING, "depth", 0)
    _NESTING.depth = depth + 1
    return depth == 0


def _exit_nesting() -> None:
    _NESTING.depth = max(0, getattr(_NESTING, "depth", 1) - 1)


@contextmanager
def hashcat_slot(
    *, block: bool = True, timeout: Optional[float] = None
) -> Iterator[bool]:
    """Serialize a hashcat process launch against every other ADscan launch.

    Serialization spans processes as well as threads (see the module docstring),
    so a measurement in one session yields to a crack in another instead of
    measuring a GPU somebody else is using.

    Args:
        block: When ``True`` (real cracks) the caller waits for the slot and is
            guaranteed to run without colliding; it also registers slot DEMAND
            for the whole wait+hold so best-effort measurements yield to it
            (see :func:`real_crack_pending`). When ``False`` (the benchmark
            warm-up, the achieved-rate probe) the call returns immediately with
            ``False`` if the slot is held, so the caller can SKIP and yield the
            hardware to the crack that holds it.
        timeout: Optional bounded wait (seconds) when ``block`` is ``True``.
            ``None`` waits indefinitely (the crack always eventually runs).
            Ignored when ``block`` is ``False``.

    Yields:
        ``True`` when the slot was acquired (the caller may launch hashcat),
        ``False`` when it was not (a real crack holds it — do not launch).
    """
    if block:
        # Register real-crack demand for the ENTIRE wait+hold window so a
        # measurement yields even while this crack is still blocked on acquire.
        with _DEMAND_LOCK:
            global _real_crack_demand
            _real_crack_demand += 1
            if _real_crack_demand == 1:
                _publish_demand_locked()
        deadline = None if timeout is None else time.monotonic() + float(timeout)
        try:
            mutex_held = _HASHCAT_SLOT.acquire(
                blocking=True, timeout=-1 if timeout is None else timeout
            )
            outermost = False
            file_handle = None
            acquired = mutex_held
            try:
                if mutex_held:
                    outermost = _enter_nesting()
                    if outermost:
                        remaining = (
                            None
                            if deadline is None
                            else max(0.0, deadline - time.monotonic())
                        )
                        file_handle, contended = _acquire_slot_file_lock(
                            blocking=True, timeout=remaining
                        )
                        if file_handle is None and contended:
                            # Another process holds the GPU and the bounded wait
                            # expired. Report the slot as unavailable rather
                            # than launching a hashcat that would abort on its
                            # own single-instance lock.
                            acquired = False
                yield acquired
            finally:
                _release_slot_file_lock(file_handle)
                # Pairs with EVERY _enter_nesting, not only the outermost one:
                # a nested entry that incremented the depth and never gave it
                # back would leave the thread permanently "nested", and from
                # then on no entry on it would ever take the cross-process lock.
                if mutex_held:
                    _exit_nesting()
                    _HASHCAT_SLOT.release()
        finally:
            with _DEMAND_LOCK:
                _real_crack_demand -= 1
                if _real_crack_demand <= 0:
                    _real_crack_demand = 0
                    _withdraw_demand_locked()
    else:
        mutex_held = _HASHCAT_SLOT.acquire(blocking=False)
        outermost = False
        file_handle = None
        acquired = mutex_held
        try:
            if mutex_held:
                outermost = _enter_nesting()
                if outermost:
                    file_handle, contended = _acquire_slot_file_lock(
                        blocking=False, timeout=None
                    )
                    if file_handle is None and contended:
                        acquired = False
            yield acquired
        finally:
            _release_slot_file_lock(file_handle)
            if mutex_held:
                _exit_nesting()
                _HASHCAT_SLOT.release()


def unique_crack_session_name(prefix: str = "adscan") -> str:
    """Return a per-run cracking session name unique across processes and runs.

    hashcat and John both enforce a single-instance lock keyed on the session
    NAME (hashcat's default is ``hashcat``; John's is ``john``). A second run
    that reuses the default name while an instance is still alive — or a run
    whose predecessor was killed and left a stale lock/restore file behind —
    aborts with ``Already an instance '<...>' running on pid N`` and exit code
    255. Handing every ADscan crack its own session name makes that collision
    impossible: a leftover lock is keyed on the OLD name, and no two ADscan
    runs (concurrent or sequential) ever share one.

    The name combines the current PID with a short random suffix, so it is
    distinct even for two crackers launched within the same process image and
    stays valid as a filesystem session-file component on both Linux and
    Windows.

    Args:
        prefix: Leading token for the session name (defaults to ``adscan``).

    Returns:
        A session name of the form ``<prefix>-<pid>-<hex>``.
    """
    return f"{prefix}-{os.getpid()}-{secrets.token_hex(4)}"


__all__ = [
    "hashcat_slot",
    "real_crack_pending",
    "shared_demand_supported",
    "unique_crack_session_name",
]
