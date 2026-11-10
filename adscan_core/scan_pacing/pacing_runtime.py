"""Pacing runtime: rate limit, per-host pause, and the strain safeguard.

The resolver decides the NUMBERS once per scan; this module enforces the parts
that are about time, while the scan runs:

* :class:`RateLimiter`: a scan-wide token bucket for ``max_requests_per_second``.
* the per-host gate in :meth:`PacingRuntime.before_op`: at least
  ``per_host_delay_ms`` (plus jitter) between two operations on one host.
* the strain safeguard: per host, slow down when a server shows distress and
  pause a server that stops answering; scan-wide, shrink every
  :class:`PacedSemaphore` when many hosts strain at once, then recover
  gradually. It only ever SLOWS DOWN; nothing here can exceed the resolved
  pacing (spec § 5, decision D3: on at every level).

Two properties the consumers rely on:

* With an unlimited rate, no delay and no strain (``normal`` on a healthy
  network) every call returns without awaiting anything, so wiring a consumer
  through this module changes nothing about its scheduling.
* Never raises into a consumer. A bookkeeping failure degrades to "no pacing",
  never to a broken scan.

All durations use ``time.monotonic()`` (the host clock is stepped for PKINIT).
Events carry a wall-clock ISO timestamp only for the disclosure.
"""

from __future__ import annotations

import asyncio
import random
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from statistics import median
from typing import Any, Awaitable, Callable

from adscan_core.scan_pacing.pacing_active import active_pacing
from adscan_core.scan_pacing.pacing_knobs import (
    JITTER_PCT,
    MAX_REQUESTS_PER_SECOND,
    PER_HOST_DELAY_MS,
    STRAIN_BACKOFF,
    UNLIMITED,
)
from adscan_core.scan_pacing.pacing_resolver import ResolvedPacing

# ---------------------------------------------------------------------------
# Tunables of the safeguard (documented in spec § 5.1).
# ---------------------------------------------------------------------------

#: First samples of a host that form its latency baseline.
BASELINE_SAMPLES = 5
#: Samples needed before latency drift may count as strain.
DRIFT_MIN_SAMPLES = 8
#: Drift = EWMA above both ``DRIFT_FACTOR x baseline`` and ``baseline + DRIFT_MARGIN_S``.
DRIFT_FACTOR = 3.0
DRIFT_MARGIN_S = 0.25
EWMA_ALPHA = 0.3
#: Delay a strained host gets at minimum, and its ceiling.
STRAIN_MIN_DELAY_S = 0.25
STRAIN_MAX_DELAY_S = 10.0
#: Healthy operations after which a strained host's delay halves.
RECOVERY_HEALTHY_OPS = 10
#: Consecutive non-answers (after the host had answered) that start a cool-down.
COOLDOWN_AFTER_FAILURES = 3
COOLDOWN_S = 60.0
#: Scan-wide window and thresholds.
GLOBAL_WINDOW_S = 30.0
GLOBAL_WINDOW_OPS = 200
GLOBAL_MIN_ACTIVE_HOSTS = 4
GLOBAL_STRAINED_FRACTION = 0.25
GLOBAL_DECREASE_FACTOR = 0.5
GLOBAL_RECOVERY_STEP = 0.1
GLOBAL_MIN_FRACTION = 0.05
#: A sleep overshooting by this much means the scanner itself is lagging.
LOCAL_LAG_THRESHOLD_S = 0.25
LOCAL_LAG_MEMORY_S = 5.0
#: Bounded event log for the disclosure; counters stay exact beyond it.
MAX_EVENTS = 500


class Outcome(str, Enum):
    """What one operation against a host looked like from ADscan's side."""

    OK = "ok"
    TIMEOUT = "timeout"
    RESET = "reset"
    OVERLOADED = "overloaded"
    ERROR = "error"


_OVERLOAD_MARKERS = (
    "status_insuff_server_resources",
    "status_request_not_accepted",
    "status_too_many_sessions",
    "kdc_err_svc_unavailable",
    "server is busy",
    "resultcode=51",
    "resultcode=52",
    "busy (51)",
    "unavailable (52)",
)


def classify_exception(exc: BaseException | None) -> Outcome:
    """Map an exception from a network operation to an :class:`Outcome`.

    Only signals that say something about the TARGET count as strain: timeouts,
    resets, and explicit overload refusals. Everything else (auth errors,
    protocol errors, our own bugs) is ``ERROR`` and ignored by the safeguard.
    """
    if exc is None:
        return Outcome.OK
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return Outcome.TIMEOUT
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, ConnectionRefusedError)):
        return Outcome.RESET
    text = f"{type(exc).__name__} {exc}".lower()
    if any(marker in text for marker in _OVERLOAD_MARKERS):
        return Outcome.OVERLOADED
    if "timed out" in text or "timeout" in text:
        return Outcome.TIMEOUT
    if "connection reset" in text or "broken pipe" in text:
        return Outcome.RESET
    return Outcome.ERROR


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Scan-wide token bucket. Thread- and loop-safe; ``None`` rate is a no-op."""

    def __init__(
        self,
        rate_per_s: float | None,
        *,
        jitter_pct: float = 0.0,
        clock: Callable[[], float] = time.monotonic,
        rng: random.Random | None = None,
    ) -> None:
        self.rate_per_s = rate_per_s if rate_per_s and rate_per_s > 0 else None
        self._interval = 1.0 / self.rate_per_s if self.rate_per_s else 0.0
        self._jitter = max(0.0, min(1.0, jitter_pct / 100.0))
        self._clock = clock
        self._rng = rng or random.Random()
        self._lock = threading.Lock()
        self._next_at = 0.0

    @property
    def unlimited(self) -> bool:
        """True when this limiter never waits."""
        return self.rate_per_s is None

    def reserve(self) -> float:
        """Reserve the next slot and return how long the caller must wait (s)."""
        if self.rate_per_s is None:
            return 0.0
        with self._lock:
            now = self._clock()
            start = max(now, self._next_at)
            step = self._interval
            if self._jitter:
                step *= self._rng.uniform(1.0 - self._jitter, 1.0 + self._jitter)
            self._next_at = start + step
            return max(0.0, start - now)

    async def acquire(self) -> None:
        """Wait for a token (async). Returns without awaiting when unlimited."""
        wait = self.reserve()
        if wait > 0:
            await asyncio.sleep(wait)

    def acquire_sync(self) -> None:
        """Wait for a token (blocking thread)."""
        wait = self.reserve()
        if wait > 0:
            time.sleep(wait)


# ---------------------------------------------------------------------------
# Per-host strain state
# ---------------------------------------------------------------------------


@dataclass
class _HostState:
    samples: list[float] = field(default_factory=list)
    baseline: float | None = None
    ewma: float | None = None
    answered: bool = False
    consecutive_failures: int = 0
    healthy_streak: int = 0
    extra_delay: float = 0.0
    single_flight: bool = False
    cooldown_until: float = 0.0
    probing_after_cooldown: bool = False
    paused: bool = False
    last_op_at: float | None = None
    strained: bool = False


class PacedSemaphore:
    """An asyncio semaphore whose limit shrinks while the network is strained.

    Behaves like ``asyncio.Semaphore(limit)`` while the scan-wide strain fraction
    is 1.0. When the safeguard backs off, new acquisitions wait until fewer than
    ``effective_limit`` slots are in use; work already running is never
    interrupted. The limit never rises above ``limit``.
    """

    def __init__(self, limit: int, fraction: Callable[[], float]) -> None:
        self.limit = max(1, int(limit))
        self._fraction = fraction
        self._in_use = 0
        self._cond: asyncio.Condition | None = None

    def effective_limit(self) -> int:
        """Current limit after the scan-wide backoff (at least 1)."""
        try:
            return max(1, min(self.limit, int(self.limit * self._fraction())))
        except Exception:  # noqa: BLE001 - never break a consumer
            return self.limit

    def _condition(self) -> asyncio.Condition:
        if self._cond is None:
            self._cond = asyncio.Condition()
        return self._cond

    async def acquire(self) -> None:
        cond = self._condition()
        async with cond:
            while self._in_use >= self.effective_limit():
                await cond.wait()
            self._in_use += 1

    async def release_async(self) -> None:
        cond = self._condition()
        async with cond:
            self._in_use = max(0, self._in_use - 1)
            cond.notify(1)

    async def __aenter__(self) -> PacedSemaphore:
        await self.acquire()
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.release_async()


class PacingRuntime:
    """Runtime enforcement of one :class:`ResolvedPacing` for the whole process."""

    def __init__(
        self,
        resolved: ResolvedPacing,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        sleep_sync: Callable[[float], None] | None = None,
        rng: random.Random | None = None,
        notify: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.resolved = resolved
        knobs = resolved.knobs
        rate = knobs[MAX_REQUESTS_PER_SECOND].value
        self.base_delay_s = float(knobs[PER_HOST_DELAY_MS].value or 0) / 1000.0
        self.jitter_pct = float(knobs[JITTER_PCT].value or 0)
        self.strain_enabled = bool(knobs[STRAIN_BACKOFF].value)
        self._clock = clock
        self._sleep = sleep or asyncio.sleep
        self._sleep_sync = sleep_sync or time.sleep
        self._rng = rng or random.Random()
        self.rate = RateLimiter(
            None if rate == UNLIMITED else float(rate),
            jitter_pct=self.jitter_pct,
            clock=clock,
            rng=self._rng,
        )
        self._notify = notify
        self._lock = threading.Lock()
        self._hosts: dict[str, _HostState] = {}
        self._fraction = 1.0
        self._window_started = clock()
        self._window_ops = 0
        self._window_hosts: set[str] = set()
        self._window_strained: set[str] = set()
        self._local_lag_until = 0.0
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self._counters = {
            "hosts_slowed": 0,
            "hosts_paused": 0,
            "global_backoffs": 0,
            "global_recoveries": 0,
            "operations_skipped": 0,
        }
        self._lowest_fraction = 1.0

    # -- scan-wide ----------------------------------------------------------------

    def fraction(self) -> float:
        """Scan-wide multiplier on every paced limit (1.0 = no backoff)."""
        return self._fraction

    def semaphore(self, limit: int) -> PacedSemaphore:
        """A semaphore of ``limit`` that shrinks under scan-wide strain."""
        return PacedSemaphore(limit, self.fraction)

    def effective_limit(self, limit: int) -> int:
        """``limit`` after the scan-wide backoff, for thread-pool consumers."""
        return max(1, min(int(limit), int(int(limit) * self._fraction)))

    async def acquire(self) -> None:
        """Take one token of the scan-wide request rate (no await when unlimited)."""
        wait = self.rate.reserve()
        if wait > 0:
            await self._sleep(wait)

    def acquire_sync(self) -> None:
        """Blocking variant of :meth:`acquire`."""
        wait = self.rate.reserve()
        if wait > 0:
            self._sleep_sync(wait)

    # -- per host -----------------------------------------------------------------

    def _host(self, host: str) -> _HostState:
        key = str(host or "").strip().lower()
        state = self._hosts.get(key)
        if state is None:
            state = _HostState()
            self._hosts[key] = state
        return state

    def is_paused(self, host: str) -> bool:
        """True when the safeguard stopped working against ``host``."""
        with self._lock:
            return self._host(host).paused

    def per_host_limit(self, host: str, limit: int) -> int:
        """In-flight limit for ``host`` (1 while it is strained)."""
        with self._lock:
            return 1 if self._host(host).single_flight else max(1, int(limit))

    def _plan_wait(self, host: str) -> tuple[float, bool]:
        """Return (seconds to wait before the next op on host, allowed)."""
        now = self._clock()
        with self._lock:
            state = self._host(host)
            if state.paused:
                self._counters["operations_skipped"] += 1
                return 0.0, False
            delay = max(self.base_delay_s, state.extra_delay)
            if delay and self.jitter_pct:
                jitter = self.jitter_pct / 100.0
                delay *= self._rng.uniform(1.0 - jitter, 1.0 + jitter)
            wait = 0.0
            if delay and state.last_op_at is not None:
                wait = max(0.0, state.last_op_at + delay - now)
            if state.cooldown_until > now:
                wait = max(wait, state.cooldown_until - now)
            state.last_op_at = now + wait
            return wait, True

    def _note_overshoot(self, requested: float, actual: float) -> None:
        if actual - requested > LOCAL_LAG_THRESHOLD_S:
            with self._lock:
                self._local_lag_until = self._clock() + LOCAL_LAG_MEMORY_S

    async def before_op(self, host: str) -> bool:
        """Wait as the pacing requires before an operation on ``host``.

        Returns ``False`` when the safeguard paused the host: the caller skips
        the operation and records it as not assessed. Returns without awaiting
        anything when there is nothing to wait for.
        """
        try:
            rate_wait = self.rate.reserve()
            wait, allowed = self._plan_wait(host)
        except Exception:  # noqa: BLE001 - pacing must never break a consumer
            return True
        if not allowed:
            return False
        total = rate_wait + wait
        if total > 0:
            started = self._clock()
            await self._sleep(total)
            self._note_overshoot(total, self._clock() - started)
        return True

    def before_op_sync(self, host: str) -> bool:
        """Blocking variant of :meth:`before_op` for thread-pool consumers."""
        try:
            rate_wait = self.rate.reserve()
            wait, allowed = self._plan_wait(host)
        except Exception:  # noqa: BLE001
            return True
        if not allowed:
            return False
        total = rate_wait + wait
        if total > 0:
            started = self._clock()
            self._sleep_sync(total)
            self._note_overshoot(total, self._clock() - started)
        return True

    def record(self, host: str, outcome: Outcome, latency_s: float | None = None) -> None:
        """Feed one operation's outcome to the safeguard. Never raises."""
        if not self.strain_enabled:
            return
        try:
            self._record(host, outcome, latency_s)
        except Exception:  # noqa: BLE001
            return

    def record_exception(self, host: str, exc: BaseException | None, latency_s: float | None = None) -> None:
        """Shortcut: classify ``exc`` and record it."""
        self.record(host, classify_exception(exc), latency_s)

    # -- safeguard internals ----------------------------------------------------------

    def _record(self, host: str, outcome: Outcome, latency_s: float | None) -> None:
        events: list[tuple[str, dict[str, Any]]] = []
        now = self._clock()
        with self._lock:
            state = self._host(host)
            if state.paused:
                return
            strained = False
            if outcome is Outcome.OK:
                state.answered = True
                state.consecutive_failures = 0
                if state.probing_after_cooldown:
                    state.probing_after_cooldown = False
                    events.append(("resumed", {"host": host}))
                if latency_s is not None and latency_s >= 0:
                    strained = self._latency_drift(state, latency_s, now)
                if not strained:
                    state.healthy_streak += 1
                    if state.extra_delay and state.healthy_streak >= RECOVERY_HEALTHY_OPS:
                        state.healthy_streak = 0
                        state.extra_delay = state.extra_delay / 2
                        if state.extra_delay < max(STRAIN_MIN_DELAY_S, self.base_delay_s):
                            state.extra_delay = 0.0
                            state.single_flight = False
                            state.strained = False
                            events.append(("recovered", {"host": host}))
            elif outcome is Outcome.OVERLOADED:
                strained = True
            elif outcome in (Outcome.TIMEOUT, Outcome.RESET):
                if state.answered:
                    strained = True
                    state.consecutive_failures += 1
                    if state.probing_after_cooldown:
                        state.paused = True
                        state.probing_after_cooldown = False
                        self._counters["hosts_paused"] += 1
                        events.append(("paused", {"host": host, "reason": "stopped_responding"}))
                    elif state.consecutive_failures >= COOLDOWN_AFTER_FAILURES:
                        state.cooldown_until = now + COOLDOWN_S
                        state.probing_after_cooldown = True
                        state.consecutive_failures = 0
                        events.append(("cooldown", {"host": host, "seconds": COOLDOWN_S}))
            if strained:
                state.healthy_streak = 0
                previous = state.extra_delay
                state.extra_delay = min(
                    STRAIN_MAX_DELAY_S,
                    max(previous * 2, STRAIN_MIN_DELAY_S, self.base_delay_s),
                )
                state.single_flight = True
                if not state.strained:
                    state.strained = True
                    self._counters["hosts_slowed"] += 1
                    events.append(
                        ("slowed", {"host": host, "signal": outcome.value, "delay_s": round(state.extra_delay, 3)})
                    )
            events.extend(self._global_tick(host, strained, now))
            for kind, detail in events:
                self._events.append({"kind": kind, "at": _now_iso(), **detail})
        for kind, detail in events:
            if self._notify is not None:
                try:
                    self._notify(kind, detail)
                except Exception:  # noqa: BLE001
                    pass

    def _latency_drift(self, state: _HostState, latency_s: float, now: float) -> bool:
        state.samples.append(latency_s)
        if len(state.samples) > 64:
            del state.samples[: len(state.samples) - 64]
        if state.baseline is None:
            if len(state.samples) >= BASELINE_SAMPLES:
                state.baseline = median(state.samples[:BASELINE_SAMPLES])
                state.ewma = state.baseline
            return False
        state.ewma = latency_s if state.ewma is None else EWMA_ALPHA * latency_s + (1 - EWMA_ALPHA) * state.ewma
        if len(state.samples) < DRIFT_MIN_SAMPLES:
            return False
        if now < self._local_lag_until:
            return False  # the scanner itself is lagging; do not blame the host
        return state.ewma > DRIFT_FACTOR * state.baseline and state.ewma > state.baseline + DRIFT_MARGIN_S

    def _global_tick(self, host: str, strained: bool, now: float) -> list[tuple[str, dict[str, Any]]]:
        events: list[tuple[str, dict[str, Any]]] = []
        self._window_ops += 1
        self._window_hosts.add(host)
        if strained:
            self._window_strained.add(host)
        if self._window_ops < GLOBAL_WINDOW_OPS and now - self._window_started < GLOBAL_WINDOW_S:
            return events
        active = len(self._window_hosts)
        strained_fraction = len(self._window_strained) / active if active else 0.0
        if active >= GLOBAL_MIN_ACTIVE_HOSTS and strained_fraction > GLOBAL_STRAINED_FRACTION:
            new = max(GLOBAL_MIN_FRACTION, self._fraction * GLOBAL_DECREASE_FACTOR)
            if new < self._fraction:
                self._fraction = new
                self._lowest_fraction = min(self._lowest_fraction, new)
                self._counters["global_backoffs"] += 1
                events.append(("global_backoff", {"fraction": round(new, 3), "strained_hosts": len(self._window_strained)}))
        elif not self._window_strained and self._fraction < 1.0:
            self._fraction = min(1.0, self._fraction + GLOBAL_RECOVERY_STEP)
            self._counters["global_recoveries"] += 1
            events.append(("global_recover", {"fraction": round(self._fraction, 3)}))
        self._window_started = now
        self._window_ops = 0
        self._window_hosts = set()
        self._window_strained = set()
        return events

    # -- disclosure -----------------------------------------------------------------

    def strain_report(self) -> dict[str, Any]:
        """JSON-safe summary for the disclosure block (rendered by WP3)."""
        with self._lock:
            paused = sorted(h for h, s in self._hosts.items() if s.paused)
            slowed = sorted(h for h, s in self._hosts.items() if s.strained or s.paused)
            return {
                "enabled": self.strain_enabled,
                "acted": bool(self._counters["hosts_slowed"] or self._counters["global_backoffs"]),
                "counters": dict(self._counters),
                "lowest_fraction": round(self._lowest_fraction, 3),
                "paused_hosts": paused,
                "slowed_hosts": slowed,
                "events": list(self._events),
                "events_truncated": len(self._events) >= MAX_EVENTS,
            }


# ---------------------------------------------------------------------------
# Process-scoped runtime, bound to the active pacing.
# ---------------------------------------------------------------------------

_RUNTIME_LOCK = threading.Lock()
_RUNTIME: PacingRuntime | None = None
_NOTIFIER: Callable[[str, dict[str, Any]], None] | None = None


def set_strain_notifier(notify: Callable[[str, dict[str, Any]], None] | None) -> None:
    """Install the callback that surfaces safeguard actions to the operator.

    ``adscan_core`` does not print on its own behalf here; the engine installs a
    notifier (a ``print_*`` line, a CI event) at session start.
    """
    global _NOTIFIER, _RUNTIME  # noqa: PLW0603 - deliberate process-scoped bridge
    with _RUNTIME_LOCK:
        _NOTIFIER = notify
        if _RUNTIME is not None:
            _RUNTIME._notify = notify  # noqa: SLF001


def active_runtime() -> PacingRuntime:
    """Return the runtime for the active pacing, creating it on first use.

    A new runtime (fresh safeguard state) is created when the active pacing
    object changes, e.g. after ``set_active_pacing``.
    """
    global _RUNTIME  # noqa: PLW0603 - deliberate process-scoped bridge
    resolved = active_pacing()
    with _RUNTIME_LOCK:
        if _RUNTIME is None or _RUNTIME.resolved is not resolved:
            _RUNTIME = PacingRuntime(resolved, notify=_NOTIFIER)
        return _RUNTIME


def reset_runtime() -> None:
    """Drop the runtime (session end, tests)."""
    global _RUNTIME  # noqa: PLW0603 - deliberate process-scoped bridge
    with _RUNTIME_LOCK:
        _RUNTIME = None


__all__ = [
    "Outcome",
    "PacedSemaphore",
    "PacingRuntime",
    "RateLimiter",
    "active_runtime",
    "classify_exception",
    "reset_runtime",
    "set_strain_notifier",
]
