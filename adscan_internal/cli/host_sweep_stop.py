"""CLI trigger for the operator early-stop of the SMB host-enrichment sweep.

The per-host SMB sweep is one LONG step of the scan control plane
(:mod:`adscan_core.scan_control`). Ctrl+C opens the shared operator menu, and
"Stop this step and keep what it found" stops the sweep the same way the old
private handler did: the fan-out stops dispatching new hosts, drains the
in-flight set, and ``collect_domain_hosts`` returns the hosts enriched so far.
"Skip the rest of this phase" and "Stop the scan" reach it too, and so does the
platform's control file; the legacy ``.stop_host_enrichment`` sentinel is still
polled by the token.

No signal handler is installed here any more: the one SIGINT policy lives in
``adscan_core.scan_control.interrupts``, which is what keeps a mashed Ctrl+C
from ever ending the run (the panic-proof guarantee this module used to provide
on its own, for this sweep only).

The sweep declares its own coverage gap (``host_enrichment_coverage``, with the
hosts swept and remaining), so the step does not record a second one.

Threading model is unchanged: the collector runs its event loop and
``LiveSession`` in a worker thread. The menu pauses that Live view, holds the
console, and the worker observes the thread-safe token at the next dispatch
boundary.
"""

from __future__ import annotations

import contextlib
from typing import Any

from adscan_internal.services.collector.host_sweep_cancellation import (
    HostSweepCancellation,
)
from adscan_internal.services.cooperative_cancellation import cli_cooperative_stop

# Shown once when the operator stops the sweep from the menu.
_STOP_MESSAGE = (
    "SMB host enrichment: stopping early. Draining the hosts already in flight, "
    "then continuing the scan with the hosts collected so far."
)


@contextlib.contextmanager
def cli_host_sweep_stop(
    cancellation: HostSweepCancellation,
    *,
    shell: Any = None,
) -> Any:
    """Run the SMB host sweep as a long, operator-stoppable scan-control step."""
    with cli_cooperative_stop(
        cancellation,
        shell=shell,
        stop_message=_STOP_MESSAGE,
        label="SMB host enrichment",
        unit="hosts",
        record_gap=False,
    ) as token:
        yield token


# Re-exported so callers import the token + the activator from one place.
__all__ = ["HostSweepCancellation", "cli_host_sweep_stop"]
