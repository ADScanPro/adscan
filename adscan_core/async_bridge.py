"""The single bridge from synchronous ADscan code to async code.

Every place in ``adscan_internal``, ``adscan_core``, ``adscan_launcher`` and
``adscan.py`` that needs a fresh event loop opens it HERE. Calling
``asyncio.run``, ``asyncio.new_event_loop`` or ``loop.run_until_complete``
anywhere else fails ``tests/unit/core/test_single_async_bridge.py`` unless the
site is listed in its ``ALLOWED`` map with a reason (an object or thread that
owns a private loop for its whole lifetime).

Why one bridge: each call opens a NEW loop, so an asyncio primitive or an async
object (connection, client, session) built on one call and reused on a later
call fails with ``... is bound to a different event loop``. Best-effort callers
swallow that error, so the work is skipped silently. Every function here routes
the error through :func:`report_cross_loop_error` (telemetry signal
``asyncio_cross_loop_escape`` plus the debug-log traceback) and re-raises it
unchanged, so the class is visible wherever it happens. Keeping such an object
past its call is caught statically by
``tests/unit/core/test_no_cross_loop_async_object_cache.py``.

Which function to use:

* :func:`run_async_sync` - the default. Runs on a new loop; when the caller is
  already inside a running loop it runs the awaitable on a one-shot worker
  thread instead of raising.
* :func:`run_on_new_loop` - exactly ``asyncio.run`` (raises ``RuntimeError``
  when called from a running loop). For sites whose contract is to refuse a
  running loop.
* :func:`run_on_bare_loop` - ``new_event_loop`` + ``run_until_complete`` +
  ``close`` on the calling thread, WITHOUT ``asyncio.run``'s teardown
  (cancelling leftover tasks, draining the default executor). For legacy sites
  whose timing depended on that.
* :func:`run_in_worker_thread` - :func:`run_on_bare_loop` on a fresh worker
  thread, always (even with no running loop in the caller).
* :func:`run_sync_off_loop` - a SYNC callable that drives its own private loop.

This module is stdlib-only at import time so every layer can use it.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")

CROSS_LOOP_SIGNAL = "asyncio_cross_loop_escape"
_CROSS_LOOP_MARKERS = (
    "is bound to a different event loop",
    "attached to a different loop",
    "belongs to a different loop",
)


def _loop_is_running() -> bool:
    """Whether the calling thread is inside a running event loop.

    The ``RuntimeError`` from ``get_running_loop`` is consumed HERE, and the
    work runs after the ``except`` block has closed. Running it inside the
    ``except`` made every exception the awaited code raised carry ``During
    handling of the above exception ... RuntimeError: no running event loop``
    in its traceback: a false lead in every debug log.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def is_cross_loop_error(exc: BaseException | None) -> bool:
    """Whether ``exc`` (or its cause/context chain) is an asyncio cross-loop error."""
    seen = 0
    while exc is not None and seen < 4:
        if isinstance(exc, RuntimeError) and any(m in str(exc) for m in _CROSS_LOOP_MARKERS):
            return True
        exc = exc.__cause__ or exc.__context__
        seen += 1
    return False


def report_cross_loop_error(exc: BaseException, where: str) -> None:
    """Make an asyncio primitive or object that escaped its loop visible.

    Best-effort, never raises. Telemetry gets a greppable signal
    (``asyncio_cross_loop_escape``) and the traceback goes to the debug log and
    the sanitized recording.
    """
    try:
        from adscan_core import telemetry
        from adscan_core.rich_output import print_exception

        props = {"signal": CROSS_LOOP_SIGNAL, "where": where}
        telemetry.capture_exception(exc, props)  # type: ignore[arg-type]
        telemetry.capture("asyncio_cross_loop_escape", props)
        print_exception(exception=exc)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 - the detector must never mask the original error
        pass


def _report_if_cross_loop(exc: BaseException, where: str) -> None:
    if is_cross_loop_error(exc):
        report_cross_loop_error(exc, where)


def run_on_new_loop(awaitable: Awaitable[T]) -> T:
    """Exactly ``asyncio.run(awaitable)``, with the cross-loop detector.

    Raises ``RuntimeError`` when called from a running event loop, like
    ``asyncio.run``. Any exception from the awaited code is re-raised unchanged.
    """
    try:
        return asyncio.run(awaitable)  # type: ignore[arg-type]
    except Exception as exc:
        _report_if_cross_loop(exc, "run_on_new_loop")
        raise


def run_async_sync(awaitable: Awaitable[T], *, timeout: float | None = None) -> T:
    """Run an awaitable from sync code, even if the caller already owns a loop.

    Every call runs on a NEW event loop (``asyncio.run`` semantics). From inside
    a running loop the awaitable runs on a one-shot worker thread and the caller
    blocks until it finishes; ``timeout`` bounds only that wait (as
    ``Future.result(timeout)`` does, the worker thread still runs to the end).
    A cross-loop error raised by the awaited code is reported once and
    re-raised unchanged.
    """
    if not _loop_is_running():
        return run_on_new_loop(awaitable)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(run_on_new_loop, awaitable).result(timeout=timeout)


def run_on_bare_loop(awaitable: Awaitable[T], *, set_as_current: bool = False) -> T:
    """``new_event_loop`` + ``run_until_complete`` + ``close`` on this thread.

    Unlike ``asyncio.run`` it does not cancel leftover tasks, shut down async
    generators or wait for the default executor at exit; sites that were
    written against that cheaper teardown keep their timing. Raises
    ``RuntimeError`` when the calling thread already runs a loop.

    ``set_as_current`` also installs the loop as the thread's current loop for
    the duration of the call (what legacy worker-thread sites did).
    """
    loop = asyncio.new_event_loop()
    if set_as_current:
        asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(awaitable)
    except Exception as exc:
        _report_if_cross_loop(exc, "run_on_bare_loop")
        raise
    finally:
        if set_as_current:
            asyncio.set_event_loop(None)
        loop.close()


def run_in_worker_thread(awaitable: Awaitable[T]) -> T:
    """Run ``awaitable`` on a fresh loop in a fresh worker thread, always.

    For synchronous orchestrators that must never share a thread with any loop
    (the collector phases). The caller blocks until the work finishes;
    exceptions propagate unchanged.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(run_on_bare_loop, awaitable, set_as_current=True).result()


def run_sync_off_loop(fn: Callable[..., T], *args: object, **kwargs: object) -> T:
    """Run a SYNC callable that internally drives its own event loop.

    Some synchronous helpers (e.g. ``ADscanLDAPConnection``) create a private
    event loop with ``asyncio.new_event_loop()`` + ``run_until_complete()``.
    ``asyncio`` forbids driving a loop while another loop is already running in
    the same thread, so calling such helpers from inside an active event loop
    raises ``RuntimeError: Cannot run the event loop while another loop is
    running``.

    This helper offloads the *entire* synchronous callable to a single worker
    thread that has no running loop of its own. When the caller does NOT
    already own a running loop, the callable is invoked directly with no thread
    offload: behaviour is identical to calling ``fn`` itself.

    Concurrency note: ``max_workers=1`` and the blocking ``.result()`` keep the
    offload strictly sequential, one operation at a time. Process-global state
    (e.g. the gssapi/KRB5CCNAME default credential cache binding) is set inside
    the offloaded callable and must not be shared across concurrent operations.
    """
    if not _loop_is_running():
        return fn(*args, **kwargs)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: fn(*args, **kwargs)).result()


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
