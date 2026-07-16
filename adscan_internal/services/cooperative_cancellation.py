"""Generic cooperative-cancellation SSOT: stop a long loop, keep the partial
results, let the scan continue.

Several long-running operations (the per-host SMB enrichment sweep, Kerberos
username enumeration against a large wordlist, ...) can run for minutes to
hours on a large estate. The operator should be able to say "stop feeding new
work, I want to move on with the scan" WITHOUT aborting the whole run. This
module is the single, operation-agnostic implementation of that pattern:

  * ONE cancellation token (:class:`CooperativeCancellation`) with TWO
    triggers converging on a single predicate:
      (a) an IN-PROCESS flag, set by a CLI ``Ctrl+C`` handler in the same
          process (:meth:`CooperativeCancellation.request_stop`); and
      (b) a cross-process SENTINEL FILE in the scan workspace, written by the
          platform path (a Celery / web "Stop" endpoint) and polled here.
    Observing the sentinel latches the in-process flag, so the file is read
    at most once per token lifetime.

  * ONE CLI trigger (:func:`cli_cooperative_stop`) that turns the operator's
    first ``Ctrl+C`` into a *stop-and-continue* (never an abort) and a second
    ``Ctrl+C`` within a short window into the normal hard-abort escape hatch.
    A no-op under ``is_non_interactive`` — automated runs (``adscan ci``)
    never install a signal handler; the sentinel trigger still works.

The contract every consumer loop follows is the same regardless of what it is
iterating over (hosts, username candidates, ...):

  1. Check :meth:`CooperativeCancellation.should_stop` at each iteration
     boundary — BEFORE starting a new unit of work, not mid-unit.
  2. On a positive check, stop launching NEW work. Let anything already
     in-flight drain to completion (never kill in-flight work — that would
     corrupt partial state or leak a resource).
  3. Return whatever was collected so far. The caller CONTINUES the scan with
     the partial result; this is a *stop*, never an *abort*.

:class:`~adscan_internal.services.collector.host_sweep_cancellation.HostSweepCancellation`
is the original, single-purpose implementation of this pattern (the per-host
SMB sweep) and is now a thin adapter over this generic token — see that
module's docstring for the adapter contract. New consumers should use
:class:`CooperativeCancellation` directly.
"""

from __future__ import annotations

import contextlib
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from adscan_core.interaction import is_non_interactive
from adscan_core.rich_output import print_info_debug, print_warning

# A second Ctrl+C within this window of the first escalates to a hard abort.
# Shared across every operation using :func:`cli_cooperative_stop` so the
# "double-tap to abort" muscle memory is consistent product-wide.
DOUBLE_TAP_WINDOW_SECS = 3.0


def cooperative_stop_sentinel_path(
    workspace_dir: str | os.PathLike[str], operation: str
) -> str:
    """Return the absolute cross-process stop-sentinel path for ``operation``.

    SSOT for the sentinel-naming convention shared by every cooperative-stop
    consumer: ``.stop_<operation>`` inside the scan's workspace root. Both the
    writer (a platform "Stop" endpoint) and the reader (the operation's own
    poll, via :class:`CooperativeCancellation`) resolve the SAME path through
    this helper — never hand-roll the filename at either end.

    Args:
        workspace_dir: The scan's workspace root — the container-visible
            ``current_workspace_dir`` for an in-container reader, or the
            host-visible workspace root for a host-side writer; both map to
            the same bind-mounted directory.
        operation: Short, filesystem-safe name identifying the operation
            (e.g. ``"host_enrichment"``, ``"kerberos_user_enum"``).
    """
    return os.path.join(str(workspace_dir), f".stop_{operation}")


@dataclass
class CooperativeCancellation:
    """One cooperative-cancellation token shared by the CLI and platform triggers.

    Checked by a consumer's dispatch loop at the iteration boundary (BEFORE
    starting the next unit of work). When it reports requested, the loop
    stops DISPATCHING new work; anything already in-flight drains to
    completion. The token is thread-safe: the CLI ``Ctrl+C`` handler may flip
    the flag from a signal handler / a different thread than the loop itself.

    Attributes:
        operation: Short, filesystem-safe name identifying the operation this
            token guards (e.g. ``"host_enrichment"``,
            ``"kerberos_user_enum"``). Used only for the debug log line.
        sentinel_path: Absolute path of the cross-process stop sentinel to
            poll (build it with :func:`cooperative_stop_sentinel_path`), or
            ``None`` when no workspace dir is available (an in-process-only
            run still gets the CLI ``Ctrl+C`` trigger). When set and the file
            appears, the next check returns ``True`` and latches the flag.
    """

    operation: str = "operation"
    sentinel_path: str | None = None
    _flag: threading.Event = field(default_factory=threading.Event, repr=False)
    _source: str = field(default="", repr=False)

    def request_stop(self, *, source: str = "cli") -> None:
        """Latch the in-process stop flag (idempotent). Called by the CLI handler."""
        if not self._flag.is_set():
            self._source = source
            self._flag.set()

    @property
    def requested_source(self) -> str:
        """Where the stop came from ('cli' / 'platform'), '' until requested."""
        return self._source

    def is_requested(self) -> bool:
        """True when an early stop is requested by EITHER trigger (the SSOT check).

        Order: the in-process flag first (O(1), already-latched fast path), then
        the sentinel file. Observing the sentinel latches the in-process flag so
        the file is read at most once and ``requested_source`` records
        ``'platform'``. Best-effort on the file read — a stat error never aborts
        the loop.
        """
        if self._flag.is_set():
            return True
        if self.sentinel_path:
            try:
                if os.path.exists(self.sentinel_path):
                    self._source = "platform"
                    self._flag.set()
                    print_info_debug(
                        f"cooperative-cancel ({self.operation}): stop sentinel "
                        "observed; halting new work dispatch (in-flight work "
                        "will drain)"
                    )
                    return True
            except OSError:
                # Polling must never break the loop — treat an unreadable
                # sentinel as "not requested" and re-check next iteration.
                return False
        return False

    def should_stop(self) -> bool:
        """Alias for :meth:`is_requested` — the documented predicate name."""
        return self.is_requested()

    @property
    def cancelled(self) -> bool:
        """Read-only alias for :meth:`is_requested`, for call sites that prefer
        a property over a method call."""
        return self.is_requested()


@dataclass
class _CliStopHandlerState:
    cancellation: CooperativeCancellation
    shell: Any
    stop_message: str
    first_tap_at: float = 0.0
    previous_handler: Any = None


def _on_sigint(state: _CliStopHandlerState) -> Any:
    def _handler(signum: int, frame: Any) -> None:  # noqa: ARG001
        now = time.monotonic()
        # Double-tap within the window → hard abort (the normal escape hatch).
        if state.first_tap_at and (now - state.first_tap_at) <= DOUBLE_TAP_WINDOW_SECS:
            raise KeyboardInterrupt
        # If the operator already stopped the operation, a fresh Ctrl+C means abort.
        if state.cancellation.is_requested():
            raise KeyboardInterrupt
        state.first_tap_at = now
        # First tap → cooperative stop-and-continue. Flip the thread-safe flag;
        # the loop drains in-flight work and tears its LiveSession down. We do
        # NOT read stdin here (signal handler on the main thread, the loop may
        # own the alt-screen) — the decision is shown as a non-blocking,
        # deferred notice that survives the alt-screen pop.
        state.cancellation.request_stop(source="cli")
        print_warning(state.stop_message)

    return _handler


@contextlib.contextmanager
def cli_cooperative_stop(
    cancellation: CooperativeCancellation,
    *,
    shell: Any = None,
    stop_message: str,
) -> Any:
    """Activate the Ctrl+C stop-and-continue handler for one operation.

    Wrap the long-running call with this context manager. On a TTY it installs
    a ``SIGINT`` handler that turns the FIRST ``Ctrl+C`` into a cooperative
    stop (``stop_message`` is shown, ``cancellation`` is flipped, the loop
    keeps running and drains) and a SECOND ``Ctrl+C`` within
    :data:`DOUBLE_TAP_WINDOW_SECS` into the normal hard abort
    (``KeyboardInterrupt`` propagates). The previous handler is restored on
    exit.

    Under ``is_non_interactive(shell)`` (``adscan ci``) it is a pure no-op —
    the platform uses the sentinel, not Ctrl+C — so an automated run keeps the
    default ``KeyboardInterrupt`` semantics on a stray signal.

    Best-effort: if the signal cannot be installed (e.g. called off the main
    thread), it yields without a handler rather than failing the operation —
    the sentinel-file trigger still works via the same ``cancellation`` token.

    Args:
        cancellation: The token this operation's loop polls.
        shell: Optional shell instance, threaded to the non-interactive gate.
        stop_message: The line shown to the operator on the first Ctrl+C.
            Required (no generic default) so every call site's wording stays
            accurate to what it is stopping and what continues.
    """
    if is_non_interactive(shell):
        yield cancellation
        return

    state = _CliStopHandlerState(
        cancellation=cancellation, shell=shell, stop_message=stop_message
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
            f"cooperative-cancel: could not install Ctrl+C stop handler "
            f"({type(exc).__name__}); Ctrl+C keeps default behaviour, "
            "platform sentinel still active."
        )
    try:
        yield cancellation
    finally:
        if installed:
            with contextlib.suppress(ValueError, OSError, RuntimeError):
                signal.signal(signal.SIGINT, state.previous_handler)


__all__ = [
    "DOUBLE_TAP_WINDOW_SECS",
    "CooperativeCancellation",
    "cooperative_stop_sentinel_path",
    "cli_cooperative_stop",
]
