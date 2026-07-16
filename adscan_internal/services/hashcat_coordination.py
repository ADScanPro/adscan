"""SSOT for serializing concurrent hashcat process launches.

hashcat enforces a single-instance lock keyed on the binary path: a second
hashcat process aborts with ``Already an instance '<path>' running on pid N``.
Two ADscan surfaces can race for it — a REAL crack (the interactive
``cli/cracking`` path or the background ``cracking-job``) and the best-effort
benchmark warm-up's ``hashcat -b``. A real crack must NEVER fail or be starved
by the disposable warm-up.

One global mutex serializes every hashcat launch so two can never overlap:

* A real crack acquires it BLOCKING via :func:`hashcat_slot` (``block=True``),
  so it always eventually runs and never collides.
* The benchmark warm-up acquires it NON-BLOCKING via
  ``hashcat_slot(block=False)`` and SKIPS its run when the slot is held,
  yielding the hardware to the crack.

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
the warm-up is best-effort.

The lock is process-wide (module-level) and re-entrant, so nested wrapping on
the same thread never deadlocks.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator, Optional

# Re-entrant so a single thread that nests two hashcat launches (e.g. a crack
# run followed by its ``--show`` read) never deadlocks against itself. Across
# threads it behaves as a normal mutex.
_HASHCAT_SLOT = threading.RLock()

# Count of threads currently WAITING FOR or HOLDING the slot as a real crack
# (a ``block=True`` caller). Guarded by its own lightweight lock so it can be
# read (``real_crack_pending``) without touching the slot mutex itself. The
# convention is fixed (see module docstring): ``block=True`` == a real crack
# whose priority must never be starved; ``block=False`` == the best-effort
# benchmark. Inferring crack-demand from ``block`` is safe in the only
# direction that matters — an unexpected ``block=True`` caller merely makes the
# best-effort warm-up yield MORE, never a crack yield to the warm-up.
_DEMAND_LOCK = threading.Lock()
_real_crack_demand = 0


def real_crack_pending() -> bool:
    """True while any real crack is waiting for or holding the hashcat slot.

    The best-effort benchmark warm-up polls this between modes and pauses its
    ``hashcat -b`` sweep the moment it is ``True``, so a real crack is never
    starved behind a multi-mode benchmark. Cheap and lock-guarded — safe to call
    in a tight loop.
    """
    with _DEMAND_LOCK:
        return _real_crack_demand > 0


@contextmanager
def hashcat_slot(
    *, block: bool = True, timeout: Optional[float] = None
) -> Iterator[bool]:
    """Serialize a hashcat process launch against every other ADscan launch.

    Args:
        block: When ``True`` (real cracks) the caller waits for the slot and is
            guaranteed to run without colliding; it also registers slot DEMAND
            for the whole wait+hold so the best-effort benchmark yields to it
            (see :func:`real_crack_pending`). When ``False`` (the best-effort
            benchmark warm-up) the call returns immediately with ``False`` if
            the slot is held, so the caller can SKIP and yield the hardware to
            the crack that holds it.
        timeout: Optional bounded wait (seconds) when ``block`` is ``True``.
            ``None`` waits indefinitely (the crack always eventually runs).
            Ignored when ``block`` is ``False``.

    Yields:
        ``True`` when the slot was acquired (the caller may launch hashcat),
        ``False`` when it was not (a real crack holds it — do not launch).
    """
    if block:
        # Register real-crack demand for the ENTIRE wait+hold window so the
        # benchmark yields even while this crack is still blocked on acquire.
        with _DEMAND_LOCK:
            global _real_crack_demand
            _real_crack_demand += 1
        try:
            acquired = _HASHCAT_SLOT.acquire(
                blocking=True, timeout=-1 if timeout is None else timeout
            )
            try:
                yield acquired
            finally:
                if acquired:
                    _HASHCAT_SLOT.release()
        finally:
            with _DEMAND_LOCK:
                _real_crack_demand -= 1
    else:
        acquired = _HASHCAT_SLOT.acquire(blocking=False)
        try:
            yield acquired
        finally:
            if acquired:
                _HASHCAT_SLOT.release()


__all__ = ["hashcat_slot", "real_crack_pending"]
