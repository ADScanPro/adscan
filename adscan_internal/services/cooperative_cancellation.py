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

  * ONE CLI trigger (:func:`cli_cooperative_stop`), now a consumer of the scan
    control plane (:mod:`adscan_core.scan_control`). It opens a LONG step for the
    operation and links the token to it: the operator's Ctrl+C opens the shared
    operator menu, and "Stop this step and keep what it found" (or a skipped
    phase, or a stopped scan) flips this token. It installs NO signal handler of
    its own: one SIGINT policy for the whole product lives in
    ``adscan_core.scan_control.interrupts``, so mashing Ctrl+C can never end the
    run (the panic-proof property the old private handler provided), and the
    same stop reaches every long step, not only the two that had a handler.

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
import threading
from dataclasses import dataclass, field
from typing import Any

from adscan_core.rich_output import print_info_debug, print_warning

# Historical constant. The cooperative-stop handler NO LONGER escalates a
# second Ctrl+C to an abort (the panic-proof rewrite: the handler never
# raises). Kept as a harmless module constant so any external reference does
# not break; it no longer gates any behaviour here.
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
    _linked: Any = field(default=None, repr=False)

    def link(self, predicate: Any, *, source: str = "operator") -> None:
        """Also stop when ``predicate()`` is true (the scan-control step's check).

        Set by :func:`cli_cooperative_stop`; ``source`` is what
        :attr:`requested_source` reports when the link fires.
        """
        self._linked = (predicate, source)

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
        linked = self._linked
        if linked is not None:
            predicate, source = linked
            try:
                fired = bool(predicate())
            except Exception:  # noqa: BLE001 - a broken link never breaks the loop
                fired = False
            if fired:
                self.request_stop(source=source)
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


#: Display names of the known operations, for the operator menu and the gap
#: statement. Unknown operations fall back to their id.
OPERATION_LABELS: dict[str, str] = {
    "kerberos_user_enum": "Kerberos user enumeration",
    "host_enrichment": "SMB host enrichment",
}


def operation_label(operation: str) -> str:
    """Display name of an operation (``"Kerberos user enumeration"``)."""
    known = OPERATION_LABELS.get(str(operation or ""))
    if known:
        return known
    text = str(operation or "operation").replace("_", " ").strip()
    return text[:1].upper() + text[1:]


@contextlib.contextmanager
def cli_cooperative_stop(
    cancellation: CooperativeCancellation,
    *,
    shell: Any = None,
    stop_message: str,
    label: str | None = None,
    unit: str = "",
    total: int | None = None,
    record_gap: bool = True,
) -> Any:
    """Run a cooperative operation as a LONG step of the scan control plane.

    Opens ``scan_control().step(<operation>, long=True)`` and links
    ``cancellation`` to it, so the shared Ctrl+C operator menu ("Stop this step
    and keep what it found"), a skipped phase, a stopped scan and the platform's
    control file all stop this operation's loop the same way. No signal handler
    is installed here: the one SIGINT policy lives in
    ``adscan_core.scan_control.interrupts``.

    The loop drains in-flight work and returns its partial result; when the
    operator chose to stop the whole scan, leaving this block raises
    ``ScanAbortRequested`` so the scan unwinds to its entry point.

    Args:
        cancellation: The token this operation's loop polls.
        shell: Kept for call-site compatibility (interactivity is the control
            plane's concern now).
        stop_message: Shown once when the operator stops this step.
        label: Display name for the menu and the gap statement (default: the
            operation's known label).
        unit: Plural noun for progress counts (``"hosts"``).
        total: Units the operation has to do, when known.
        record_gap: ``False`` when the operation declares its own coverage gap
            (the host sweep's ``host_enrichment_coverage``), so the stop is not
            stated twice.
    """
    del shell  # interactivity is decided by the control plane
    from adscan_core.scan_control import scan_control  # noqa: PLC0415

    control = scan_control()
    with control.step(
        cancellation.operation,
        label=label or operation_label(cancellation.operation),
        long=True,
        unit=unit,
        total=total,
        record_gap=record_gap,
    ) as step:
        announced: list[bool] = []

        def _linked() -> bool:
            if not step.should_stop():
                return False
            if not announced:
                announced.append(True)
                print_warning(stop_message)
            return True

        cancellation.link(_linked, source="operator")
        yield cancellation


__all__ = [
    "DOUBLE_TAP_WINDOW_SECS",
    "OPERATION_LABELS",
    "CooperativeCancellation",
    "cooperative_stop_sentinel_path",
    "cli_cooperative_stop",
    "operation_label",
]
