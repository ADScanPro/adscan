"""The memory bound of attack-path post-processing (annotation, minimisation, decoration).

Attack-path discovery has two memory checks already: the projection gate before
the DFS and the in-DFS bound (:class:`~adscan_core.reporting.attack_path_memory_gate.DfsMemoryBudget`).
The stages that run AFTER the DFS on the materialised routes (the affected-user
annotation, the minimisation of redundant memberships, the display decoration)
allocate per route as well, and on a large listing they are where the peak sits.
Without a check there, a projection that undershot by a few percent is caught by
nothing but the kernel.

:class:`PostprocessMemoryBound` is that check. Each stage builds one and calls
:meth:`~PostprocessMemoryBound.tick` per route. It samples memory through the one
guard of the product (:class:`adscan_core.memory_guard.MemoryGuard`: one sampler,
one stop fraction, the real ceiling) and, when the line is crossed, raises
:class:`AttackPathPostprocessStop`, which is at once the stage's
:class:`~adscan_core.memory_guard.MemoryCeilingReached` and the compute's
``_AttackPathMemoryBudgetExceeded``. The attack-path compute that called the
stage catches it where it catches a DFS stop, discards the partial routes and
degrades to its bounded result (or declares the stop), so a stop here never
returns a partial route set as if it were complete.

Best-effort like the guard: a blind memory read never stops a stage.
"""

from __future__ import annotations

from typing import Any

from adscan_core.memory_guard import MemoryCeilingReached, MemoryGuard
from adscan_core.reporting.attack_path_memory_gate import _AttackPathMemoryBudgetExceeded
from adscan_core.reporting.resource_coverage import STAGE_ATTACK_PATHS

#: Routes processed between two memory samples. One sample reads a few small
#: pseudo-files; a route's post-processing is far heavier than that.
DEFAULT_SAMPLE_EVERY = 256


class AttackPathPostprocessStop(_AttackPathMemoryBudgetExceeded, MemoryCeilingReached):
    """The stop of an attack-path post-processing stage at the memory line.

    BOTH the stage's :class:`~adscan_core.memory_guard.MemoryCeilingReached`
    (stage ``attack_paths``, ``units_done`` = routes processed) and the
    attack-path compute's own stop,
    :class:`~adscan_core.reporting.attack_path_memory_gate._AttackPathMemoryBudgetExceeded`
    (``examined_routes``), so every seam that already recovers from a DFS stop
    (``attack_paths_core.attempt_or_stop`` and the service seams) discards the
    partial routes and degrades the same way, and a ``memory_bounded`` boundary
    around the compute (the web's live computation) declares it.

    It is an ``Exception`` through the compute's stop; nothing between the
    three stages and their seam catches broadly (locked by
    ``test_no_post_processing_stage_swallows_the_stop``).
    """

    def __init__(self, *, units_done: int, reading: Any) -> None:  # pylint: disable=super-init-not-called
        worded = MemoryCeilingReached(
            stage=STAGE_ATTACK_PATHS, units_done=units_done, reading=reading
        )
        BaseException.__init__(self, worded.operator_message)
        self.stage = STAGE_ATTACK_PATHS
        self.units_done = int(units_done)
        self.reading = reading
        self.cause = worded.cause
        self.remedy = worded.remedy
        self.operator_message = worded.operator_message
        self.examined_routes = int(units_done)


class PostprocessMemoryBound:
    """The memory check of one attack-path post-processing stage.

    Args:
        stage: Operator-facing name of the stage (``"annotating affected
            users"``), kept for diagnostics.
        sample_every: Routes between two samples.
    """

    def __init__(self, stage: str, *, sample_every: int = DEFAULT_SAMPLE_EVERY) -> None:
        self.stage = str(stage or "post-processing")
        self.routes_done = 0
        self._sample_every = max(1, int(sample_every))
        self._guard = MemoryGuard(
            STAGE_ATTACK_PATHS, sample_every=self._sample_every, min_interval_s=0.0
        )

    def tick(self) -> None:
        """Account one processed route; sample on the stride.

        Raises:
            AttackPathPostprocessStop: the line was crossed. The compute that
                called the stage discards its partial routes and degrades; a
                partial route set is never returned from here.
        """
        self.routes_done += 1
        if self.routes_done % self._sample_every:
            return
        reading = self._guard.sample()
        if reading.crossed:
            raise AttackPathPostprocessStop(units_done=self.routes_done, reading=reading)


__all__ = ("AttackPathPostprocessStop", "DEFAULT_SAMPLE_EVERY", "PostprocessMemoryBound")
