"""Cooperative early-stop for the per-host SMB enrichment sweep.

The identity graph (LDAP collection) is complete before the per-host SMB sweep
runs; the sweep is the long, host-by-host enrichment phase. On large estates
(banks, 1-2k+ hosts) an operator may want to HALT that sweep early — when it is
taking too long — and have the scan CONTINUE cleanly with what was collected so
far (attack-path discovery, report). This is a *stop*, never an *abort*: the
in-flight hosts drain gracefully and the partial host set is kept.

This is the ORIGINAL, single-purpose implementation of the cooperative-stop
pattern (host-sweep was the first consumer). It is now a **thin adapter** over
the generic, operation-agnostic token
:class:`~adscan_internal.services.cooperative_cancellation.CooperativeCancellation`
— :class:`HostSweepCancellation` IS one, pinned to ``operation="host_enrichment"``,
so every existing call site (``HostSweepCancellation(sentinel_path=...)``,
``.request_stop()``, ``.is_requested()``, ``.requested_source``) keeps working
byte-for-byte. New consumers (e.g. Kerberos user enumeration) should use
:class:`CooperativeCancellation` directly instead of adding another
single-purpose token — see that module's docstring for the full contract.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from adscan_internal.services.cooperative_cancellation import (
    CooperativeCancellation,
    cooperative_stop_sentinel_path,
)

# Operation key this token is pinned to — feeds both the generic sentinel
# filename convention and the debug log line in the base class.
HOST_SWEEP_OPERATION = "host_enrichment"

# Filename of the cross-process stop sentinel, written into the scan workspace
# root by the platform "Stop host enrichment" path. Kept dot-prefixed so it is
# never confused with a collected artifact and stays out of normal listings.
# Preserved as a literal constant (rather than only deriving it) so external
# readers of this module keep a stable, greppable string.
HOST_SWEEP_STOP_SENTINEL = ".stop_host_enrichment"


def host_sweep_stop_sentinel_path(workspace_dir: str | os.PathLike[str]) -> str:
    """Return the absolute sentinel path inside one scan workspace directory.

    SSOT for the sentinel location used by BOTH writer (platform/Celery) and
    reader (the collector poll). ``workspace_dir`` is the scan's workspace root
    — the container-visible ``current_workspace_dir`` for the collector, or the
    host-visible workspace root for the writer; they map to the same bind-mounted
    file. Delegates to the generic
    :func:`~adscan_internal.services.cooperative_cancellation.cooperative_stop_sentinel_path`
    so the naming convention (``.stop_<operation>``) stays in one place.
    """
    path = cooperative_stop_sentinel_path(workspace_dir, HOST_SWEEP_OPERATION)
    assert os.path.basename(path) == HOST_SWEEP_STOP_SENTINEL  # drift guard
    return path


@dataclass
class HostSweepCancellation(CooperativeCancellation):
    """Thin adapter: :class:`CooperativeCancellation` pinned to the host sweep.

    Kept as a distinct, named type (rather than callers constructing
    ``CooperativeCancellation(operation="host_enrichment")`` inline) so the
    existing import surface (``from ...host_sweep_cancellation import
    HostSweepCancellation``) and every call site across the collector,
    ``intelligence.py`` and the CLI Ctrl+C handler keep working unchanged.
    All behaviour — ``request_stop``, ``is_requested``, ``requested_source``,
    the sentinel poll — is inherited verbatim from the base class.
    """

    operation: str = HOST_SWEEP_OPERATION
