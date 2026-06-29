"""Cooperative early-stop for the per-host SMB enrichment sweep.

The identity graph (LDAP collection) is complete before the per-host SMB sweep
runs; the sweep is the long, host-by-host enrichment phase. On large estates
(banks, 1-2k+ hosts) an operator may want to HALT that sweep early — when it is
taking too long — and have the scan CONTINUE cleanly with what was collected so
far (attack-path discovery, report). This is a *stop*, never an *abort*: the
in-flight hosts drain gracefully and the partial host set is kept.

This module is the SINGLE SOURCE OF TRUTH for "is an early stop requested for
this sweep". It exposes ONE predicate, :meth:`HostSweepCancellation.is_requested`,
that checks BOTH cancellation sources so the fan-out loop has a single seam:

  (a) an IN-PROCESS flag — set by the CLI ``Ctrl+C`` handler in the same
      process (``request_stop()``); and
  (b) a cross-process SENTINEL file in the scan workspace — written by the
      platform path (a Celery endpoint), polled here. The collector runs as a
      subprocess of the web worker, so a file is the simplest robust
      cross-process signal (no fragile IPC, no shared Redis client in the
      collector).

Both triggers converge on the same predicate, so the dispatch loop never forks
its stop logic. The sentinel poll is cheap and memoised: once the file is
observed the in-process flag is latched, so the file is read at most once.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field

from adscan_core.rich_output import print_info_debug

# Filename of the cross-process stop sentinel, written into the scan workspace
# root by the platform "Stop host enrichment" path. Kept dot-prefixed so it is
# never confused with a collected artifact and stays out of normal listings.
HOST_SWEEP_STOP_SENTINEL = ".stop_host_enrichment"


def host_sweep_stop_sentinel_path(workspace_dir: str | os.PathLike[str]) -> str:
    """Return the absolute sentinel path inside one scan workspace directory.

    SSOT for the sentinel location used by BOTH writer (platform/Celery) and
    reader (the collector poll). ``workspace_dir`` is the scan's workspace root
    — the container-visible ``current_workspace_dir`` for the collector, or the
    host-visible workspace root for the writer; they map to the same bind-mounted
    file.
    """
    return os.path.join(str(workspace_dir), HOST_SWEEP_STOP_SENTINEL)


@dataclass
class HostSweepCancellation:
    """One cooperative-cancellation token shared by the CLI and platform triggers.

    Checked by the host-sweep fan-out at the dispatch boundary (BEFORE acquiring
    a worker slot for the next host). When it reports requested, the loop stops
    DISPATCHING new hosts; the already in-flight hosts drain to completion. The
    token is thread-safe: the CLI ``Ctrl+C`` handler may flip the flag from a
    signal handler / a different thread than the collector's event loop.

    Attributes:
        sentinel_path: Absolute path of the cross-process stop sentinel to poll,
            or ``None`` when no workspace dir is available (CLI-only runs still
            get the in-process trigger). When set and the file appears, the next
            :meth:`is_requested` returns True and latches the flag.
    """

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
        the file is read at most once and ``requested_source`` records 'platform'.
        Best-effort on the file read — a stat error never aborts the sweep.
        """
        if self._flag.is_set():
            return True
        if self.sentinel_path:
            try:
                if os.path.exists(self.sentinel_path):
                    self._source = "platform"
                    self._flag.set()
                    print_info_debug(
                        "[host-sweep] stop sentinel observed; halting new-host "
                        "dispatch (in-flight hosts will drain)"
                    )
                    return True
            except OSError:
                # Polling must never break collection — treat an unreadable
                # sentinel as "not requested" and re-check next host.
                return False
        return False
