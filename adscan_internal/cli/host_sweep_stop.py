"""CLI Ctrl+C trigger for the operator early-stop of the SMB enrichment sweep.

Installs a ``SIGINT`` handler that is active ONLY while the per-host SMB sweep
runs. It turns the operator's ``Ctrl+C`` into a *stop-and-continue* for the
sweep (not an abort of the whole scan):

  * FIRST ``Ctrl+C`` — request a cooperative stop of the sweep. The fan-out stops
    dispatching new hosts, drains the in-flight set, and the scan continues
    (attack-path discovery, report) with the partial host data. A one-line
    confirmation is shown.
  * SECOND ``Ctrl+C`` within :data:`_DOUBLE_TAP_WINDOW_SECS` — the normal escape
    hatch: re-raise ``KeyboardInterrupt`` so the whole scan aborts.

Threading model. Python delivers signals to the MAIN thread only; the collector
runs its event loop + ``LiveSession`` in a worker thread. So the handler must NOT
render a Rich prompt or read stdin mid-flight (that would race the worker's
alt-screen and corrupt the terminal). Instead it flips the thread-safe
:class:`HostSweepCancellation` flag (a ``threading.Event``) — the worker observes
it at the next dispatch boundary and tears its own ``LiveSession`` down cleanly.
The decision shown to the operator is a deferred, non-blocking notice via the
centralized ``print_*`` sink (auto-mirrored to telemetry), so it survives the
alt-screen pop and never blocks ``adscan ci``.

Non-interactive (``adscan ci``). The handler is a NO-OP on the prompt: the
platform stops the sweep via the cross-process sentinel, never ``Ctrl+C``. Under
``is_non_interactive`` a stray ``SIGINT`` keeps the default Python behaviour
(``KeyboardInterrupt``) so an automated run is never silently turned into a
partial sweep.
"""

from __future__ import annotations

import contextlib
import signal
import time
from dataclasses import dataclass
from typing import Any

from adscan_core.interaction import is_non_interactive
from adscan_core.rich_output import print_info_debug, print_warning

from adscan_internal.services.collector.host_sweep_cancellation import (
    HostSweepCancellation,
)

# A second Ctrl+C within this window of the first escalates to a hard abort.
_DOUBLE_TAP_WINDOW_SECS = 3.0


@dataclass
class _HandlerState:
    cancellation: HostSweepCancellation
    shell: Any
    first_tap_at: float = 0.0
    previous_handler: Any = None


def _on_sigint(state: _HandlerState) -> Any:
    def _handler(signum: int, frame: Any) -> None:  # noqa: ARG001
        now = time.monotonic()
        # Double-tap within the window → hard abort (the normal escape hatch).
        if state.first_tap_at and (now - state.first_tap_at) <= _DOUBLE_TAP_WINDOW_SECS:
            raise KeyboardInterrupt
        # If the operator already stopped the sweep, a fresh Ctrl+C means abort.
        if state.cancellation.is_requested():
            raise KeyboardInterrupt
        state.first_tap_at = now
        # First tap → cooperative stop-and-continue. Flip the thread-safe flag;
        # the worker drains in-flight hosts and tears its LiveSession down. We do
        # NOT read stdin here (signal handler on the main thread, worker owns the
        # alt-screen) — the decision is shown as a non-blocking, deferred notice
        # that survives the alt-screen pop.
        state.cancellation.request_stop(source="cli")
        print_warning(
            "SMB host enrichment: stopping early and continuing the scan with the "
            "hosts collected so far (identity graph is already complete). Press "
            "Ctrl+C again to abort the whole scan."
        )

    return _handler


@contextlib.contextmanager
def cli_host_sweep_stop(
    cancellation: HostSweepCancellation,
    *,
    shell: Any = None,
) -> Any:
    """Activate the Ctrl+C stop-and-continue handler for the SMB sweep.

    Wrap the host-sweep collection call with this context manager. On a TTY it
    installs the SIGINT handler described in the module docstring and restores the
    previous handler on exit. Under ``is_non_interactive(shell)`` (``adscan ci``)
    it is a pure no-op — the platform uses the sentinel, not Ctrl+C — so an
    automated run keeps the default ``KeyboardInterrupt`` semantics.

    Best-effort: if the signal cannot be installed (e.g. called off the main
    thread), it yields without a handler rather than failing the collection.
    """
    if is_non_interactive(shell):
        # adscan ci: no Ctrl+C prompt. The sentinel-file trigger still works via
        # the same `cancellation` token; we simply do not touch SIGINT.
        yield cancellation
        return

    state = _HandlerState(cancellation=cancellation, shell=shell)
    installed = False
    try:
        # signal.signal raises ValueError off the main thread — fall back to a
        # no-op handler install in that case (the sentinel trigger still works).
        state.previous_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, _on_sigint(state))
        installed = True
    except (ValueError, OSError, RuntimeError) as exc:
        print_info_debug(
            f"[host-sweep] could not install Ctrl+C stop handler ({type(exc).__name__}); "
            "Ctrl+C keeps default behaviour, platform sentinel still active."
        )
    try:
        yield cancellation
    finally:
        if installed:
            with contextlib.suppress(ValueError, OSError, RuntimeError):
                signal.signal(signal.SIGINT, state.previous_handler)


# Re-exported so callers import the token + the activator from one place.
__all__ = ["HostSweepCancellation", "cli_host_sweep_stop"]
