"""The graph build under the one memory doctrine (spec sections 14 and 15.7).

The build does not own a memory mechanism: it is a caller of
:mod:`adscan_core.memory_guard`, the single primitive every stage uses (one RSS
sampler, one stop fraction, the real ceiling from ``memory_probe``). This module
holds the build's three bindings to it:

* :func:`new_build_guard`: the build's :class:`~adscan_core.memory_guard.MemoryGuard`
  for stage ``graph_build``. ``build.build_graph`` ticks it once per stored
  relationship it streams (``EdgeView``'s ``on_fact``) and checks it at every
  stage boundary of the build. Crossing the line raises
  :class:`~adscan_core.memory_guard.MemoryCeilingReached` (a ``BaseException``:
  the export's ``except Exception`` cannot swallow it and write a graph).
* :data:`GRAPH_BUILD_UNIT`: what the build counts, for the coverage statement.
* :func:`record_graph_build_stop`: the ``record`` callback the stage boundary
  passes to :func:`~adscan_core.memory_guard.memory_bounded`. It marks the
  domain's collection phase incomplete through the single writer
  (``scan_progress.mark_phase_incomplete``, so ``adscan ci`` exits
  :data:`~adscan_core.ci_exit_codes.CI_EXIT_ASSESSMENT_INCOMPLETE`) and folds
  the ``resource_coverage`` block into the domain's record.

The boundary belongs to the code that exports the graph (it holds the shell)::

    with memory_bounded(STAGE_GRAPH_BUILD, unit=GRAPH_BUILD_UNIT,
                        record=record_graph_build_stop(shell, domain)) as stage:
        written = export_graph_if_due(...)      # one call: see memory_bounded
    if stage.outcome == OUTCOME_STOPPED:
        ...  # no graph was written for this domain; the store is untouched

A graph cannot be partially built and presented as complete, so there is no
streamed mode: the build stops, writes nothing, and keeps the collected data.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from adscan_core.memory_guard import MemoryGuard
from adscan_core.reporting.resource_coverage import STAGE_GRAPH_BUILD

#: Stored relationships streamed between two memory samples (the primitive's
#: rate limit applies on top). One sample reads a few small pseudo-files.
BUILD_SAMPLE_EVERY = 4096

#: Plural noun of what the build counts, for the coverage statement.
GRAPH_BUILD_UNIT = "collected relationships"


def new_build_guard() -> MemoryGuard:
    """The memory guard of one graph build."""
    return MemoryGuard(STAGE_GRAPH_BUILD, sample_every=BUILD_SAMPLE_EVERY)


def record_graph_build_stop(shell: Any, domain: str) -> Callable[[dict[str, Any]], None]:
    """The ``record`` callback for a build stopped at the memory ceiling.

    Marks the domain's collection phase incomplete (reason
    ``memory:graph_build`` in ``coverage.json``; ``adscan ci`` exits 3) and
    merges the client-safe block under ``domains_data[domain]["resource_coverage"]``
    and ``technical_report.json`` (``resource_coverage_recorder``).
    The runtime's boundary is ``graph_runtime_memory.build_bounded``.
    """

    from adscan_internal.services.collector.collection_integrity import (  # noqa: PLC0415
        COLLECTION_PHASE_ID,
    )
    from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
        stage_stop_recorder,
    )

    _record = stage_stop_recorder(
        shell,
        domain,
        phase_id=COLLECTION_PHASE_ID,
        detail="The attack graph could not be built within the available memory.",
    )
    return _record


__all__ = (
    "BUILD_SAMPLE_EVERY",
    "GRAPH_BUILD_UNIT",
    "new_build_guard",
    "record_graph_build_stop",
)
