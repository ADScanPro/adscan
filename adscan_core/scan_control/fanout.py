"""Stoppable fan-outs: the one way a long sweep over many hosts honours a stop.

A sweep that probes every host of a large domain (an access check, a credential
dump, a login probe) runs for minutes. Under the scan control plane the operator
can stop it and keep what it found. This module is the shared mechanics of that
stop, so every sweep behaves the same and states its coverage the same way:

* a pool of ``concurrency`` workers pulls items in order; a worker checks the
  stop before taking the next item, so items still queued leave at once and
  never touch the network;
* items already in flight get ``grace`` seconds to finish (their result is
  kept), then they are cancelled; a cancelled item is NOT checked;
* the result says, per item, whether it ran, and counts what was not checked.
  A caller must never report an item that did not run as "no access".

The async form (:func:`run_stoppable_fanout`) generalises the pattern the SMB
host collector got first (worker pool, bounded grace, cancel). The thread form
(:func:`run_stoppable_thread_fanout`) is for sweeps on a thread pool: a running
thread cannot be cancelled, so once its grace is spent it is abandoned (its
result, if it ever arrives, is ignored) and counted as not checked.

Nothing loop-bound is kept beyond one call: every asyncio object is created
inside the coroutine that uses it (CLAUDE.md "Nothing loop-bound outlives one
event loop"). Standard library only.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Generic, Iterable, Sequence, TypeVar

T = TypeVar("T")
R = TypeVar("R")

#: Seconds in-flight items get to finish after a stop, before they are cancelled.
DEFAULT_STOP_GRACE_SECONDS = 20.0
#: Seconds cancelled tasks get to unwind before the fan-out returns without them.
_CANCEL_SETTLE_SECONDS = 2.0
#: How often the stop predicate is read while workers are busy.
_STOP_POLL_SECONDS = 0.25


@dataclass
class FanOutResult(Generic[R]):
    """What a stoppable fan-out did, item by item.

    Attributes:
        results: One slot per input item, in input order; ``None`` for an item
            that did not run to completion.
        ran: Per item, whether its work completed (its result is trustworthy).
        stopped: Whether a stop ended the fan-out before every item ran.
        not_started: Items never taken from the queue because of the stop.
        cancelled_in_flight: Items that were running at the stop and did not
            finish within the grace.
        held: Per item, whether the ``before_item`` check kept it from running
            (the engagement scope, asked again right before the contact). A
            held item was never contacted: it is neither checked nor left
            unchecked by a stop.
    """

    results: list[R | None]
    ran: list[bool]
    stopped: bool = False
    not_started: int = 0
    cancelled_in_flight: int = 0
    held: list[bool] = field(default_factory=list)

    def _held(self, index: int) -> bool:
        return index < len(self.held) and self.held[index]

    @property
    def completed(self) -> int:
        """Items that ran to completion."""
        return sum(1 for flag in self.ran if flag)

    @property
    def not_checked(self) -> int:
        """Items the stop left unchecked (never started or cancelled)."""
        return len(self.ran) - self.completed - sum(1 for flag in self.held if flag)

    def completed_results(self) -> list[R]:
        """Results of the items that ran, in input order."""
        return [r for r, flag in zip(self.results, self.ran) if flag]  # type: ignore[misc]

    def not_checked_items(self, items: Sequence[T]) -> list[T]:
        """The input items a stop left unchecked, in input order (held ones excluded)."""
        return [
            item
            for index, (item, flag) in enumerate(zip(items, self.ran))
            if not flag and not self._held(index)
        ]

    def held_items(self, items: Sequence[T]) -> list[T]:
        """The input items the ``before_item`` check kept from running, in input order."""
        return [item for index, item in enumerate(items) if self._held(index)]


@dataclass
class SweepCoverage:
    """How much of a sweep ran, filled in by a stoppable sweep for its caller.

    A service that runs a stoppable fan-out takes an optional instance and fills
    it, so the caller can persist only what was checked and name what was not.

    Attributes:
        total: Items the sweep had to check.
        checked: Items checked to completion.
        not_checked: The items a stop left unchecked, in input order.
        stopped: Whether a stop ended the sweep early.
        outside_scope: The items the engagement scope kept out of the sweep.
            They never reached a worker, so they are neither checked nor
            "not checked because of a stop": a fourth outcome of its own, never
            counted in ``total`` and never recorded as a negative result.
    """

    total: int = 0
    checked: int = 0
    not_checked: list[Any] = field(default_factory=list)
    stopped: bool = False
    outside_scope: list[Any] = field(default_factory=list)

    def absorb(self, outcome: FanOutResult[Any], items: Sequence[Any]) -> None:
        """Record ``outcome`` (over ``items``) into this coverage."""
        held = outcome.held_items(items)
        self.total += len(items) - len(held)
        self.checked += outcome.completed
        self.not_checked.extend(outcome.not_checked_items(items))
        self.stopped = self.stopped or outcome.stopped
        # Kept out right before the contact: the fourth outcome, like the
        # items the scope kept out before the sweep started.
        self.note_outside_scope(held)

    def note_outside_scope(self, items: Iterable[Any]) -> None:
        """Record the items the engagement scope kept out of the sweep."""
        known = {str(item).strip().lower() for item in self.outside_scope}
        for item in items:
            key = str(item).strip().lower()
            if key and key not in known:
                known.add(key)
                self.outside_scope.append(item)


def default_should_stop() -> bool:
    """The process-wide stop check (the running step's, else a pending abort)."""
    from adscan_core.scan_control.controller import scan_control  # noqa: PLC0415

    return scan_control().should_stop()


def _admits(check: Callable[[Any], bool], item: Any) -> bool:
    """Whether ``check`` lets ``item`` run. A check that fails keeps it out."""
    try:
        return bool(check(item))
    except Exception:  # noqa: BLE001 - a gate that cannot decide does not admit
        return False


def _safe(predicate: Callable[[], bool]) -> bool:
    try:
        return bool(predicate())
    except Exception:  # noqa: BLE001 - a broken predicate never breaks a sweep
        return False


async def run_stoppable_fanout(
    items: Iterable[T],
    worker: Callable[[T], Awaitable[R]],
    *,
    concurrency: int,
    should_stop: Callable[[], bool] | None = None,
    grace: float = DEFAULT_STOP_GRACE_SECONDS,
    on_done: Callable[[int, int], None] | None = None,
    poll_interval: float = _STOP_POLL_SECONDS,
    before_item: Callable[[T], bool] | None = None,
) -> FanOutResult[R]:
    """Run ``worker`` over ``items`` with bounded concurrency, honouring a stop.

    Without a stop this behaves like a bounded ``asyncio.gather``: every item
    runs, results come back in input order, and the first exception a worker
    raises propagates (the rest are cancelled first, so nothing outlives the
    call). Once ``should_stop()`` is true, workers take no new item; items in
    flight get ``grace`` seconds, then are cancelled and counted as not checked.

    Args:
        items: The units of work (hosts, instances, accounts).
        worker: Coroutine function for one item. It keeps its own per-host
            pacing; this function only bounds and stops the fan-out.
        concurrency: Workers running at once (at least 1).
        should_stop: Stop predicate; default :func:`default_should_stop`.
        grace: Seconds in-flight items get after a stop.
        on_done: Called ``(completed, total)`` after each item completes.
        poll_interval: Seconds between two stop checks while workers are busy.
        before_item: Asked for each item right before its worker starts (in a
            thread, so it may look things up). False keeps the item from
            running: it is ``held``, never contacted and never "not checked".
            A long sweep passes the engagement scope's gate here, so a host is
            judged when it is about to be contacted, not once at the start.
    """
    item_list = list(items)
    total = len(item_list)
    results: list[R | None] = [None] * total
    ran = [False] * total
    held = [False] * total
    outcome: FanOutResult[R] = FanOutResult(results=results, ran=ran, held=held)
    if total == 0:
        return outcome
    predicate = should_stop or default_should_stop
    stop_event = asyncio.Event()
    next_index = 0
    in_flight: set[int] = set()
    errors: list[BaseException] = []
    completed = 0

    def _stop_seen() -> bool:
        if not stop_event.is_set() and _safe(predicate):
            stop_event.set()
        return stop_event.is_set()

    async def _work() -> None:
        nonlocal next_index, completed
        while True:
            if errors or _stop_seen() or next_index >= total:
                return
            index = next_index
            next_index += 1
            in_flight.add(index)
            try:
                if before_item is not None and not await asyncio.to_thread(
                    _admits, before_item, item_list[index]
                ):
                    held[index] = True
                    continue
                results[index] = await worker(item_list[index])
                ran[index] = True
                completed += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - surfaced after the drain
                errors.append(exc)
                return
            finally:
                in_flight.discard(index)
            if on_done is not None:
                try:
                    on_done(completed, total)
                except Exception:  # noqa: BLE001 - progress is decoration
                    pass

    workers = [asyncio.ensure_future(_work()) for _ in range(max(1, min(int(concurrency), total)))]
    pending: set[asyncio.Future[Any]] = set(workers)
    try:
        while pending:
            _done, pending = await asyncio.wait(pending, timeout=poll_interval)
            if errors:
                break
            if _stop_seen():
                break
        if pending and not errors:
            # A stop: in-flight items get their grace, then are cancelled.
            _done, pending = await asyncio.wait(pending, timeout=max(0.0, grace))
    finally:
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.wait(pending, timeout=_CANCEL_SETTLE_SECONDS)
    if errors:
        raise errors[0]
    if not all(flag or kept for flag, kept in zip(ran, held)):
        outcome.stopped = True
        cancelled = sum(
            1 for index in range(min(next_index, total)) if not ran[index] and not held[index]
        )
        outcome.cancelled_in_flight = cancelled
        outcome.not_started = total - min(next_index, total)
    return outcome


def run_stoppable_thread_fanout(
    items: Iterable[T],
    worker: Callable[[T], R],
    *,
    max_workers: int,
    should_stop: Callable[[], bool] | None = None,
    grace: float = DEFAULT_STOP_GRACE_SECONDS,
    on_done: Callable[[int, int], None] | None = None,
    poll_interval: float = _STOP_POLL_SECONDS,
    before_item: Callable[[T], bool] | None = None,
) -> FanOutResult[R]:
    """Thread-pool twin of :func:`run_stoppable_fanout`.

    At most ``max_workers`` items are submitted at a time, so a stop never has
    a queue of submitted work to wait for. A thread still running when its grace
    is spent is abandoned: the pool is shut down without waiting, its eventual
    result is ignored, and the item counts as not checked. The first exception
    a worker raises propagates once the running items have settled.
    ``before_item`` is asked in the worker thread, right before the item's work
    (see :func:`run_stoppable_fanout`).
    """
    item_list = list(items)
    total = len(item_list)
    results: list[R | None] = [None] * total
    ran = [False] * total
    held = [False] * total
    outcome: FanOutResult[R] = FanOutResult(results=results, ran=ran, held=held)
    if total == 0:
        return outcome
    predicate = should_stop or default_should_stop
    width = max(1, min(int(max_workers), total))

    def _run(index: int) -> R | None:
        if before_item is not None and not _admits(before_item, item_list[index]):
            held[index] = True
            return None
        return worker(item_list[index])

    executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=width, thread_name_prefix="adscan-sweep"
    )
    running: dict[concurrent.futures.Future[R], int] = {}
    next_index = 0
    completed = 0
    stop_seen = False
    first_error: BaseException | None = None
    try:
        while True:
            if not stop_seen and _safe(predicate):
                stop_seen = True
            while not stop_seen and first_error is None and next_index < total and len(running) < width:
                future = executor.submit(_run, next_index)
                running[future] = next_index
                next_index += 1
            if not running:
                break
            if stop_seen:
                break
            done, _ = concurrent.futures.wait(
                running, timeout=poll_interval, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in done:
                index = running.pop(future)
                error = future.exception()
                if error is not None:
                    first_error = first_error or error
                    continue
                if held[index]:
                    continue
                results[index] = future.result()
                ran[index] = True
                completed += 1
                if on_done is not None:
                    try:
                        on_done(completed, total)
                    except Exception:  # noqa: BLE001
                        pass
            if first_error is not None and not running:
                break
        if running:
            deadline = time.monotonic() + max(0.0, grace)
            done, _ = concurrent.futures.wait(running, timeout=max(0.0, deadline - time.monotonic()))
            for future in done:
                index = running.pop(future)
                if future.exception() is None:
                    if held[index]:
                        continue
                    results[index] = future.result()
                    ran[index] = True
                elif first_error is None and not stop_seen:
                    first_error = future.exception()
    finally:
        executor.shutdown(wait=not running, cancel_futures=True)
    if first_error is not None and not stop_seen:
        raise first_error
    if not all(flag or kept for flag, kept in zip(ran, held)):
        outcome.stopped = True
        outcome.cancelled_in_flight = sum(
            1 for index in range(min(next_index, total)) if not ran[index] and not held[index]
        )
        outcome.not_started = total - min(next_index, total)
    return outcome


__all__ = [
    "DEFAULT_STOP_GRACE_SECONDS",
    "FanOutResult",
    "SweepCoverage",
    "default_should_stop",
    "run_stoppable_fanout",
    "run_stoppable_thread_fanout",
]
