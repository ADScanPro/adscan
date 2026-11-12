"""Sync-to-async bridge for engine code: a re-export of :mod:`adscan_core.async_bridge`.

The implementation lives in ``adscan_core`` so the launcher and the shared core
can use the same single bridge. Existing callers (and the tests that patch
``adscan_internal.services.async_bridge.run_async_sync``) keep importing from
here.
"""

from __future__ import annotations

from adscan_core.async_bridge import (
    CROSS_LOOP_SIGNAL,
    is_cross_loop_error,
    report_cross_loop_error,
    run_async_sync,
    run_in_worker_thread,
    run_on_bare_loop,
    run_on_new_loop,
    run_sync_off_loop,
)

__all__ = [
    "CROSS_LOOP_SIGNAL",
    "is_cross_loop_error",
    "report_cross_loop_error",
    "run_async_sync",
    "run_in_worker_thread",
    "run_on_bare_loop",
    "run_on_new_loop",
    "run_sync_off_loop",
]
