"""Attack-path traversal coverage: the value object the compute primitive returns.

The attack-path compute primitive
(:func:`adscan_internal.services.attack_paths_core.compute_display_paths_with_fallback`)
returns ``(paths, AttackPathCoverage)``. The coverage object is the in-memory
carrier of ONE fact — which traversal engine produced the routes and whether the
route set is exhaustive — and of the client-facing declaration that states the
coverage boundary when it is not.

There is no second wording here. The *declaration text* is derived from the ONE
SSOT that already words every attack-path coverage gap identically for the PDF
report and the paid web platform:
:mod:`adscan_core.reporting.attack_path_memory_gate`
(:func:`build_attack_path_coverage` + :func:`attack_path_coverage_view`, the exact
mirror of :mod:`adscan_core.reporting.cracking_coverage`). This dataclass adds the
``engine_used`` axis the persisted block does not carry, and hands
:meth:`AttackPathCoverage.to_block` back to that SSOT so a caller persists and
renders the gap through the same block a memory-gate abort already records — the
two never drift.

Three coverage shapes map onto the two engines:

* **COMPLETE** — the full DFS engine (``engine_used="dfs"``) evaluated every
  candidate route. No gap, no declaration; ``bounded`` is ``False``.
* **SAMPLED** — the bounded per-terminal fallback engine ran (proactively, because
  an explosion was predicted, or reactively, after the DFS aborted) and returned a
  coverage-floored SAMPLE: every reachable high-value target is represented, the
  routes per target are capped. ``engine_used="fallback"``, ``bounded=True``.
* **BOUNDED (hard stop)** — the fallback engine ITSELF hit the ceiling and
  discovery stopped with no route set. ``engine_used="fallback"``, ``bounded=True``,
  the result list is empty.

``bounded`` is ``True`` for BOTH fallback shapes: in either case the route set is
not the exhaustive DFS set. ``hard_stop`` distinguishes the empty hard stop (which
takes the BOUNDED wording, stating how many routes were examined) from the sampled
result (which takes the SAMPLED wording, anchored on the stable exposure count).

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from adscan_core.reporting.attack_path_memory_gate import (
    attack_path_coverage_view,
    build_attack_path_coverage,
)

#: The traversal engine that produced a result. ``dfs`` = the complete
#: all-simple-paths engine; ``fallback`` = the bounded per-terminal engine.
ENGINE_DFS = "dfs"
ENGINE_FALLBACK = "fallback"

#: Why the fallback engine ran, recorded for telemetry / the debug script.
#: ``predicted_explosion`` = the proactive reachable-explosion predicate fired and
#: the DFS was skipped; ``dfs_aborted`` = the DFS started and hit the memory bound,
#: so it was re-run bounded.
REASON_PREDICTED_EXPLOSION = "predicted_explosion"
REASON_DFS_ABORTED = "dfs_aborted"


@dataclass(frozen=True)
class AttackPathCoverage:
    """The coverage the attack-path compute primitive returns alongside its paths.

    Attributes:
        engine_used: ``"dfs"`` (complete) or ``"fallback"`` (bounded per-terminal).
        bounded: ``True`` whenever the route set is not the exhaustive DFS set —
            i.e. for every ``fallback`` result. ``False`` only for a complete DFS.
        declaration: The client-facing coverage sentence, worded by the memory-gate
            SSOT. Empty for a complete DFS (no gap to declare).
        reason: One of :data:`REASON_PREDICTED_EXPLOSION` / :data:`REASON_DFS_ABORTED`
            for a fallback result, or ``""`` for a complete DFS. Operator/telemetry
            facing, never rendered to the client.
        examined_routes: Candidate routes examined before a hard stop, when known
            — surfaced to the client as the coverage boundary in the BOUNDED wording.
        exposure_source_count: For a SAMPLED result, how many principals can reach a
            high-value target — the stable exposure figure the sampled wording
            anchors on. ``None`` still yields a valid declaration, without the number.
        hard_stop: ``True`` only when the fallback engine itself hit the ceiling and
            discovery stopped (empty result, BOUNDED wording). ``False`` for a
            sampled fallback result (SAMPLED wording).
    """

    engine_used: Literal["dfs", "fallback"] = ENGINE_DFS
    bounded: bool = False
    declaration: str = ""
    reason: str = ""
    examined_routes: int = 0
    exposure_source_count: int | None = None
    hard_stop: bool = False

    @classmethod
    def complete(cls) -> "AttackPathCoverage":
        """Return the coverage for a full DFS that evaluated every route.

        No gap and no declaration — a complete run reads exactly as it did before
        this object existed.
        """
        return cls(
            engine_used=ENGINE_DFS,
            bounded=False,
            declaration="",
            reason="",
        )

    @classmethod
    def fallback(
        cls,
        *,
        reason: str,
        examined_routes: int = 0,
        exposure_source_count: int | None = None,
        hard_stop: bool = False,
    ) -> "AttackPathCoverage":
        """Return the coverage for a bounded fallback-engine result.

        Args:
            reason: Why the fallback ran (:data:`REASON_PREDICTED_EXPLOSION` or
                :data:`REASON_DFS_ABORTED`).
            examined_routes: Routes examined before a hard stop (BOUNDED wording).
            exposure_source_count: The stable exposure count for the SAMPLED wording.
            hard_stop: ``True`` when the fallback engine itself hit the ceiling
                (empty result, BOUNDED wording); ``False`` for a sampled result.

        Returns:
            An ``AttackPathCoverage`` with ``engine_used="fallback"``,
            ``bounded=True`` and a declaration drawn from the memory-gate SSOT.
        """
        block = _coverage_block(
            hard_stop=hard_stop,
            examined_routes=examined_routes,
            exposure_source_count=exposure_source_count,
        )
        view = attack_path_coverage_view(block)
        return cls(
            engine_used=ENGINE_FALLBACK,
            bounded=True,
            declaration=str(view.get("statement") or ""),
            reason=str(reason or ""),
            examined_routes=max(0, int(examined_routes or 0)),
            exposure_source_count=exposure_source_count,
            hard_stop=bool(hard_stop),
        )

    def to_block(self) -> dict[str, Any]:
        """Return the persisted ``attack_path_coverage`` block for this coverage.

        Hands the coverage back to the memory-gate SSOT so a caller (the report
        writer, the web serializer) persists and renders it through the SAME block
        a memory-gate abort already records — one wording, one shape, no drift.
        """
        if self.engine_used == ENGINE_DFS and not self.bounded:
            return build_attack_path_coverage()
        return _coverage_block(
            hard_stop=self.hard_stop,
            examined_routes=self.examined_routes,
            exposure_source_count=self.exposure_source_count,
        )

    def coverage_view(self) -> dict[str, Any]:
        """Return the render-ready view (the shape the PDF and the web both read)."""
        return attack_path_coverage_view(self.to_block())


def _coverage_block(
    *,
    hard_stop: bool,
    examined_routes: int,
    exposure_source_count: int | None,
) -> dict[str, Any]:
    """Build the memory-gate coverage block for a fallback result.

    A hard stop (the fallback engine itself hit the ceiling) is the BOUNDED mode
    stating how many routes were examined; every other fallback result is the
    SAMPLED mode anchored on the exposure count.
    """
    if hard_stop:
        return build_attack_path_coverage(
            bounded=True, examined_routes=max(0, int(examined_routes or 0))
        )
    return build_attack_path_coverage(
        sampled=True, exposure_source_count=exposure_source_count
    )


__all__ = [
    "ENGINE_DFS",
    "ENGINE_FALLBACK",
    "REASON_PREDICTED_EXPLOSION",
    "REASON_DFS_ABORTED",
    "AttackPathCoverage",
]
