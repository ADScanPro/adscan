"""Foreground-state SSOT + idle-prompt wake for background-job surfacing.

Background jobs (cracking today; write-share / mitm6 next) run off the
synchronous REPL flow and NEVER print from their worker thread — they enqueue a
deferred notification onto the ``BackgroundJobRegistry`` bus, which the
foreground REPL drains and renders at a safe point. The classic safe point is
the pre-prompt poll (``check_background_tasks``), reached only BETWEEN commands.

That leaves one gap: when the operator is PARKED at the idle main prompt (no
keypress), a job that completes does not surface until the operator happens to
run some command. This module closes it — when a job enqueues a notification
while the foreground is idle at the main prompt, it wakes the blocked prompt so
the REPL drains and renders the result.

**Why a prompt-exit, not ``run_in_terminal``.** The drain body is not pure
rendering: the cracking renderer runs an interactive activation selector that,
on confirmation, calls ``add_credential`` -> authenticated enumeration ->
native trust enumeration, which drives the async stack via ``asyncio.run`` /
``run_until_complete``. ``run_in_terminal`` executes its callable INSIDE the
prompt_toolkit asyncio event loop, so the heavy action raised ``Cannot run the
event loop while another loop is running``. The invariant this module now
enforces: **the drain body ALWAYS runs on the loop-free foreground REPL thread**
— the same context the pre-prompt poll already uses. Both triggers (pre-prompt
poll AND idle-wake) converge on that one loop-free execution context, so no
background-job action of any kind can ever run under a running event loop.

The idle-wake therefore schedules :func:`Application.exit` (thread-safely, via
``loop.call_soon_threadsafe``) with :data:`BACKGROUND_DRAIN_SENTINEL` as the
result. That makes the blocked ``session.prompt`` return the sentinel; the REPL
loop recognizes it as "drain the background bus on this loop-free thread" (not a
typed command), drains + renders, then loops back to re-show the prompt.

Two responsibilities, both kept out of ``adscan.py`` so they are unit-testable
in isolation:

* :class:`ForegroundState` — the single vocabulary for "what is the foreground
  doing right now" (idle at the main prompt / running a command / driving a
  sub-prompt). The wake fires ONLY in :attr:`ForegroundState.IDLE_AT_MAIN_PROMPT`.
* :func:`schedule_idle_prompt_wake` — the thread-safe, best-effort scheduling of
  a prompt exit onto the running prompt_toolkit app's event loop. It never
  raises and never corrupts the prompt: any failure (not idle, no running app,
  a closed loop, the operator already typing, prompt_toolkit unavailable) simply
  leaves the notification queued for the next pre-prompt drain — today's
  behaviour.
"""
from __future__ import annotations

import asyncio
import enum
from typing import Callable

from adscan_core import telemetry


class ForegroundState(enum.Enum):
    """What the foreground REPL thread is doing — the wake-gate SSOT.

    A single source of truth so the idle-wake decision is not scattered across
    ad-hoc boolean flags. ``is_sub_prompt_active`` (set by the output-processor
    thread while it drives a queued Rich prompt) takes precedence and maps to
    :attr:`SUB_PROMPT_ACTIVE`; otherwise the REPL loop stamps
    :attr:`IDLE_AT_MAIN_PROMPT` right before blocking on ``session.prompt`` and
    :attr:`COMMAND_RUNNING` the moment a command begins executing.
    """

    #: Blocked on the main ``session.prompt`` with no command executing — the
    #: ONLY state in which an idle wake may fire.
    IDLE_AT_MAIN_PROMPT = "idle_at_main_prompt"
    #: A ``do_*`` command / scan is executing on the foreground thread — a wake
    #: here would collide with live output, so it is deferred to the next
    #: pre-prompt drain.
    COMMAND_RUNNING = "command_running"
    #: A background thread is driving an interactive sub-prompt — rendering over
    #: it collides, so the drain is deferred.
    SUB_PROMPT_ACTIVE = "sub_prompt_active"


#: Sentinel that :func:`schedule_idle_prompt_wake` sets as the result of the
#: idle main prompt when a background job posts a notification. ``session.prompt``
#: returns this exact object; the REPL loop tests for it by identity and treats
#: it as "a background drain was requested on this loop-free thread", NOT as a
#: typed command line. A plain sentinel object (not a string) so it can never
#: collide with anything the operator could type.
BACKGROUND_DRAIN_SENTINEL = object()


def running_event_loop_present() -> bool:
    """Return ``True`` when called with an asyncio event loop already running.

    The loop-free guard for the drain action path. The heavy background-job
    action (cracking activation -> ``add_credential`` -> authenticated
    enumeration) drives the native async stack via ``asyncio.run`` /
    ``run_until_complete``, which raises ``RuntimeError`` if a loop is already
    running. The drain must therefore only ever execute on the loop-free
    foreground REPL thread. This predicate is the belt-and-suspenders check so a
    future re-introduction of a with-loop trigger fails SAFE (defer the drain)
    instead of raising the nested-loop error to the operator.
    """
    try:
        asyncio.get_running_loop()
        return True
    except RuntimeError:
        return False


def schedule_idle_prompt_wake(*, is_idle: Callable[[], bool]) -> bool:
    """Wake the idle main prompt so the REPL drains the bus on the loop-free thread.

    Called from a BACKGROUND job thread the moment a notification is enqueued. A
    worker thread cannot touch the prompt_toolkit application directly, so this
    schedules — thread-safely (``loop.call_soon_threadsafe``) — a call to
    :meth:`Application.exit` with :data:`BACKGROUND_DRAIN_SENTINEL` as the
    result. That makes the blocked ``session.prompt`` return the sentinel, so the
    foreground REPL loop drains + renders the notification on ITS thread, which
    has no running event loop — the one context in which the heavy job action
    (activation -> authenticated enumeration -> ``asyncio.run``) is legal.

    Deliberately NOT ``run_in_terminal``: that runs its callable inside the
    prompt_toolkit event loop, which is exactly the nested-loop context the
    heavy action cannot run under.

    Hard-gated on foreground state: it fires ONLY when ``is_idle()`` reports the
    foreground is parked at the main prompt. ``is_idle`` is re-checked once more
    on the app-loop thread, closing the race where a command starts between the
    enqueue and the scheduled callback firing.

    Graceful fallback — NEVER raises, NEVER corrupts the prompt: when the
    foreground is not idle, when there is no running prompt_toolkit app (headless
    / non-prompt_toolkit input / the app is between prompts), when the loop is
    gone/closed, when the operator has already started typing a command, or when
    anything at all fails, this returns ``False`` and the notification simply
    stays queued for the next pre-prompt drain.

    Args:
        is_idle: A thread-safe predicate returning ``True`` only when the
            foreground is idle at the main prompt.

    Returns:
        ``True`` when a prompt exit was scheduled on the app loop; ``False`` when
        it fell back to the queued-for-next-drain behaviour.
    """
    try:
        if not is_idle():
            return False

        # Imported lazily so this module carries no hard prompt_toolkit dependency
        # (headless callers / tests without a running app degrade gracefully).
        from prompt_toolkit.application.current import get_app_or_none

        app = get_app_or_none()
        if app is None or not getattr(app, "is_running", False):
            return False
        loop = getattr(app, "loop", None)
        if loop is None or loop.is_closed():
            return False

        def _invoke() -> None:
            # Runs on the app-loop (main) thread. Re-check every guard: state may
            # have changed between the enqueue and this callback firing.
            try:
                if not is_idle():
                    return
                if not getattr(app, "is_running", False):
                    return
                future = getattr(app, "future", None)
                if future is None or future.done():
                    # Already exiting / result already set — a second exit would
                    # raise; leave the notification for the next drain.
                    return
                # Do not clobber in-progress typing: if the operator has started
                # entering a command, exiting would discard their buffer. Leave
                # the notification queued for the pre-prompt drain that runs the
                # instant they submit (or clear) the line.
                buff = getattr(app, "current_buffer", None)
                if buff is not None and getattr(buff, "text", ""):
                    return
                app.exit(result=BACKGROUND_DRAIN_SENTINEL)
            except Exception as exc:  # noqa: BLE001 — a wake must never crash the loop
                telemetry.capture_exception(exc)

        loop.call_soon_threadsafe(_invoke)
        return True
    except Exception as exc:  # noqa: BLE001 — fall back to the queued drain
        telemetry.capture_exception(exc)
        return False
