"""A mutual-exclusion lock that is safe across event loops AND threads.

``asyncio.Lock`` binds to the first event loop that has to WAIT on it and raises
``RuntimeError: ... is bound to a different event loop`` for a waiter from any
other loop. ADscan is synchronous at the top and drives async service code
through ``asyncio.run`` (``run_async_sync``), so every call lives on a fresh
loop, sometimes on a worker thread. A lock that outlives one loop (module-level,
or held on the shell or a cache object) therefore must not be an asyncio
primitive.

``CrossLoopLock`` wraps a ``threading.Lock``. The acquire never blocks the event
loop: it tries without blocking and, while the lock is busy, yields with a short
``asyncio.sleep``, so the waiter can be cancelled and the loop keeps running.
It is not FIFO-fair; the callers it serves (clock sync, posture probes, per-host
caches) only need serialisation.
"""

from __future__ import annotations

import asyncio
import threading
from types import TracebackType

_POLL_SECONDS = 0.02


class CrossLoopLock:
    """Async-context-manager mutex usable from any event loop and any thread."""

    __slots__ = ("_lock",)

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def locked(self) -> bool:
        """Whether some task or thread currently holds the lock."""
        return self._lock.locked()

    async def acquire(self) -> bool:
        """Wait for the lock without blocking the calling event loop."""
        while not self._lock.acquire(blocking=False):
            await asyncio.sleep(_POLL_SECONDS)
        return True

    def release(self) -> None:
        """Release the lock (may be called from any thread)."""
        self._lock.release()

    async def __aenter__(self) -> "CrossLoopLock":
        await self.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()
