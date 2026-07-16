"""CLI Ctrl+C trigger for the operator early-stop of the SMB enrichment sweep.

Installs a ``SIGINT`` handler that is active ONLY while the per-host SMB sweep
runs. It turns the operator's ``Ctrl+C`` into a *stop-and-continue* for the
sweep (not an abort of the whole scan):

  * FIRST ``Ctrl+C`` — request a cooperative stop of the sweep. The fan-out stops
    dispatching new hosts, drains the in-flight set, and the scan continues
    (attack-path discovery, report) with the partial host data. A one-line
    confirmation is shown.
  * SECOND ``Ctrl+C`` within the double-tap window — the normal escape hatch:
    re-raise ``KeyboardInterrupt`` so the whole scan aborts.

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

This was the ORIGINAL implementation of the "Ctrl+C stop-and-continue" pattern.
The double-tap state machine and signal-handler factory now live in the generic
:mod:`adscan_internal.services.cooperative_cancellation` module (reused here) —
this module keeps its own ``signal`` / ``is_non_interactive`` imports and gate
so the operator-facing contract (module docstring above) and the test surface
stay byte-identical; only the shared handler-construction logic was factored out.
"""

from __future__ import annotations

import contextlib
import signal
from typing import Any

from adscan_core.interaction import is_non_interactive
from adscan_core.rich_output import print_info_debug

from adscan_internal.services.collector.host_sweep_cancellation import (
    HostSweepCancellation,
)
from adscan_internal.services.cooperative_cancellation import (
    _CliStopHandlerState,
    _on_sigint,
)

_STOP_MESSAGE = (
    "SMB host enrichment: stopping early and continuing the scan with the "
    "hosts collected so far (identity graph is already complete). Press "
    "Ctrl+C again to abort the whole scan."
)


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

    state = _CliStopHandlerState(
        cancellation=cancellation, shell=shell, stop_message=_STOP_MESSAGE
    )
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
