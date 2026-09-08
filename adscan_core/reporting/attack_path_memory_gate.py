"""Attack-path discovery memory gate: projection, decision, and coverage.

Attack-path discovery on a large domain can drive the process past its memory
ceiling and get it ``SIGKILL``ed — no traceback, no report, just a dead run and
an operator with no idea why. This module is the pure-logic core of a two-stage
gate that turns that OOM into a clean stop: it projects the peak resident memory
the compute will need, compares it against the *real* ceiling (the cgroup limit
inside a container, never host RAM — see :mod:`adscan_core.memory_probe`), and
decides whether to proceed, warn, or abort before the memory-heavy final stages.

The projection model was measured under ``/usr/bin/time -v`` across a curve of
real and synthetic workspaces (last re-derived 2026-08 against a high-corner
sweep validated by a real cgroup OOM kill). Peak RSS over a fixed floor is TWO
independent regimes, and the gate takes the larger:

    projected_peak = FLOOR + max(affected_aware_term, graph_density_term)

    affected_aware_term = GRAPH_BYTES_PER_ELEMENT * (nodes + edges)
                        + raw_paths * (PATH_BASE_BYTES_PER_RAWPATH
                                       + PATH_BYTES_PER_RAWPATH_AFFECTED
                                       * affected_count)

    graph_density_term  = GRAPH_BYTES_PER_ELEMENT * (nodes + edges)
                        + DENSITY_BYTES_PER_RAWPATH_BRANCH
                          * raw_paths * (edges / nodes)

**Regime 1 — the affected-aware path term.** The path term is two-dimensional:
each surviving path stores its blast-radius (``meta.affected_users``) list, so
the marginal cost per raw path grows with how many principals that path affects.
That list is a copy of REFERENCES into the shared group-member index — an
8-byte-pointer-per-element cost, not a full re-materialisation — so the true
marginal is a small pointer-sized slope, NOT the full ``raw × affected`` cartesian
residency an earlier fit assumed. Re-derived 2026-08 against the peak RSS of THREE
graphs actually run to completion with the gate disabled under a 7 GB cap
(``/proc/self/statm`` sampler, the annotate stage isolated):

    | graph    | nodes+edges | raw_paths | affected_est | real peak | slope needed |
    |----------|------------:|----------:|-------------:|----------:|-------------:|
    | AffC     |      20,772 |     8,000 |        2,001 |    667 MB |    23.8 B    |
    | AffHeavy |      33,912 |    12,000 |        3,001 |  1,599 MB |    33.5 B    |
    | L15k     |      36,112 |    15,000 |        2,501 |  1,156 MB |    18.9 B    |

The real slope needed to COVER these peaks is 19–34 B per (raw·affected); the gate
uses ``0.0625 KB = 64 B`` — roughly 2x the worst observed slope, conservative in
the safe (over-projecting) direction without the ~11x blow-up the old
``0.35 KB (358 B)`` slope caused. That old slope assumed all ~2,516 affected
principals of every one of 15,000 paths were resident at peak simultaneously
(→12.9 GB), whereas the annotate stage's real growth on L15k is only +479 MB. The
concrete customer consequence of the old coefficient: L15k domain/all projected
13,289 MB and needed a container ≥ ~15.6 GB just to NOT abort to zero paths — a
silent false negative ("no attack paths") on a directory that HAS them and fits in
1.16 GB. At 64 B the same run projects ~2.77 GB, so any container ≥ ~4 GB completes
it and returns its ~15,000 real paths.

**The affected_count is NOT known when Stage B projects** (see below), so the
gate ESTIMATES it with a conservative upper bound and over-projects rather than
under. See :func:`project_peak_bytes`.

**Regime 2 — the graph-density guard.** ``raw_paths`` is the POST-minimisation
count, but the DFS transiently holds every PRE-minimisation simple path. A small,
high-branching graph with heavy minimisation peaks far above what its reported
raw_paths predicts: the Forest anchor measured 890 MB at raw_paths=11,080,
affected=18, where the affected-aware term predicts only 191 MB — a 5x
under-prediction, because its 11,080 post-minimisation paths came from a 96,320
pre-minimisation transient. The transient scales with ``raw_paths × branching``
(branching = ``edges / nodes``, the per-node fan-out that multiplies paths), so
the density term is anchored on Forest's measured point
(``928 elements, branching 2.30, 890 MB``) and catches a Forest-shaped graph even
though its post-minimisation raw_paths looks modest. Taking the ``max`` of the two
regimes means whichever regime dominates a given graph is the one that fires.

Both terms depend on ``raw_paths``, known only AFTER the DFS. That forces two
stages:

* **Stage A** (pre-DFS): project the graph term only. It is the only signal
  available before an hour of DFS, so a graph so large it crosses the ceiling on
  its own is surfaced at phase entry, when the fix is still "resize and re-run".
* **Stage B** (post-DFS, pre-decoration): project the full peak now that
  ``raw_paths`` is known, and abort before the decoration/ordering stages spike
  memory — saving both the wasted CPU and the fatal allocation.

When the gate has to abort, the bounded result is a **data gap** in the family of
``unsupported`` (CLAUDE.md § "A bounded computation is a data gap"): the client
deliverable states the coverage boundary, never the internal reason and never a
verdict about the client's directory. The coverage block here mirrors
:mod:`adscan_core.reporting.cracking_coverage` so the PDF and the web platform
word the same gap identically.

Pure logic: no IO, no console, no network. Safe to import from ``adscan_core``,
the LITE runtime, the PRO report renderer and the web backend alike.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional

# --- The measured coefficients ------------------------------------------------
#
# Every coefficient below was pinned under ``/usr/bin/time -v`` across a workspace
# curve and re-derived 2026-08 against a high-corner sweep that isolates each term
# and was cross-checked against a real cgroup OOM kill. The floor and the graph
# term are tight (±2%); the path term is two-dimensional (a base plus an
# affected-count slope); the density term is a second, independent regime anchored
# on the Forest measurement.

#: Fixed baseline resident memory of the process before attack-path discovery
#: allocates anything — interpreter, loaded modules, the workspace already read.
#: Measured ~70 MB, tight (±2%). Final.
FLOOR_BYTES = 70 * 1024 * 1024

#: Marginal peak memory per graph element (one node OR one edge) held resident
#: during discovery. Measured ~10 KB, tight (±2%). Final.
GRAPH_BYTES_PER_ELEMENT = 10 * 1024

#: Base marginal peak memory per RAW DFS path, independent of blast radius — the
#: fixed cost of holding one path's node/edge list resident. Measured ~4 KB
#: (2026-08, the intercept of the per-raw curve at affected→0). This is the ONE
#: coefficient a future engine-aware selector will swap (rustworkx retains ~8x less
#: per path than the Python DFS), so it is kept as a single clean scalar,
#: deliberately NOT entangled with the affected-slope term above — a later
#: selector can pass an engine-specific base without re-deriving the blast-radius
#: slope. Final for the Python engine.
PATH_BASE_BYTES_PER_RAWPATH = 4 * 1024

#: Marginal peak memory per (RAW DFS path × affected principal) — the cost of each
#: surviving path storing its blast-radius ``meta.affected_users`` list, which is a
#: list of REFERENCES into the shared group-member index (an 8-byte pointer per
#: element, not a full copy). Re-derived 2026-08 against the REAL peak RSS of three
#: graphs run to completion with the gate disabled (AffC 667 MB, AffHeavy 1,599 MB,
#: L15k 1,156 MB — see the module docstring table): the true slope needed to cover
#: those peaks is 19–34 B/(raw·affected). This uses 64 B (``0.0625 KB``), ~2x the
#: worst observed slope, conservative without the ~11x over-projection the earlier
#: 358 B (``0.35 KB``) slope caused. That earlier slope assumed the FULL
#: ``raw × affected`` blast radius was resident at peak simultaneously (12.9 GB for
#: L15k), which aborted L15k domain/all to zero paths in any container under
#: ~15.6 GB — a silent false negative on a directory whose real peak is 1.16 GB.
PATH_BYTES_PER_RAWPATH_AFFECTED = int(0.0625 * 1024)

#: Second-regime density coefficient: marginal peak per (raw_path × branching),
#: where branching = ``edges / nodes``. The DFS transiently holds every
#: PRE-minimisation simple path; ``raw_paths`` is the POST-minimisation count, so
#: a small high-branching graph with heavy minimisation peaks far above what its
#: reported raw_paths predicts. Anchored on the Forest measurement (2026-08:
#: 281 nodes + 647 edges, branching 2.30, raw_paths 11,080, 96,320-path DFS
#: transient, 890 MB peak) — where the affected-aware term alone predicts only
#: 191 MB, a 5x under-prediction. ~33 KB reproduces Forest's peak and is the safe
#: (over-projecting) direction on a denser graph (e.g. CHM3 at branching 3.64
#: projects ~2.25x its measured peak — conservative, never optimistic).
DENSITY_BYTES_PER_RAWPATH_BRANCH = 33 * 1024

#: Back-compat alias: the single scalar the earlier gate exposed, now the base
#: per-raw-path term. Kept so any external reference resolves; the live model
#: uses the two-dimensional path term plus the density regime above.
PATH_BYTES_PER_RAWPATH = PATH_BASE_BYTES_PER_RAWPATH

#: Fraction of the ceiling the projected peak may reach before the gate acts.
#: The projection is a model with error bars and the SIGKILL is unrecoverable, so
#: the gate leaves headroom rather than aiming for the exact limit — crossing the
#: SIGKILL boundary is far worse than a slightly early stop.
SAFETY_FRACTION = 0.85

#: Per-domain key the coverage block is stamped under, in ``technical_report.json``
#: and in the renderer's ``report_data``. One name so the writer, the PDF and the
#: web platform cannot drift on where the record lives.
ATTACK_PATH_COVERAGE_KEY = "attack_path_coverage"

# --- In-DFS runaway bound (Option C) ------------------------------------------
#
# The two-stage gate above runs OUTSIDE the DFS — Stage A before it and Stage B
# after the raw path list exists. Neither runs INSIDE the recursion, so on a wide,
# densely-connected directory the DFS intermediate-state fan-out can exhaust memory
# MID-recursion, before ``max_paths`` (which caps COMPLETED output paths, not states
# explored) and before Stage B — and the kernel ``SIGKILL``s the process with no
# report. The in-DFS bound below closes that hole by converting the runaway into the
# SAME declared ``_AttackPathMemoryBudgetExceeded`` the outer gate raises, so the
# coverage-bounded declaration fires unchanged.
#
# Two mechanisms, both ON by default, both raising the same exception:
#
#   1. PRIMARY — RSS vs the real available ceiling. Every ``_RSS_SAMPLE_STRIDE``
#      DFS invocations (cheap: the sample is amortised ~1/4096), sample the process
#      RSS and the available memory from the SAME cgroup-aware reader the outer gate
#      uses (:func:`adscan_core.memory_probe.read_memory_situation`). When RSS
#      crosses ``_RSS_STOP_FRACTION`` of that ceiling — the point where the kernel is
#      about to kill — stop cleanly. A domain that FITS in RAM never crosses the
#      fraction, so the bound never fires and coverage is byte-identical: only the
#      pathological case that OOMs today is touched. This is the zero-coverage-loss
#      guarantee.
#
#   2. SECONDARY — an absolute DFS-state cap, a safety net for environments where
#      RSS sampling is unavailable/unreliable (no ``/proc``, no cgroup, a platform
#      whose RSS reader returns ``None``). Set high enough that no NORMAL domain
#      reaches it: a real enterprise reporter proved a ~100k-state ceiling stops the
#      runaway they hit on 24 GB, and the largest healthy real/synthetic baseline
#      (Forest ``domain/all`` ≈ 96k pre-minimisation transient states) sits just
#      under that, so the default is set with headroom above the worst healthy case
#      rather than at it. Configurable via ``ADSCAN_ATTACK_PATHS_MAX_DFS_STATES``.

#: How many ``dfs()`` invocations between RSS samples. A sample reads ``/proc`` and
#: a cgroup file; at one every few thousand recursive calls the cost is negligible
#: while still catching a runaway long before the kill boundary. A power of two so
#: the modulo is a cheap mask.
_RSS_SAMPLE_STRIDE = 4096

#: Fraction of the AVAILABLE memory ceiling the live process RSS may reach inside
#: the DFS before the bound stops it. Matches :data:`SAFETY_FRACTION` — the kill is
#: unrecoverable, so the bound leaves the same headroom the projection gate does.
_RSS_STOP_FRACTION = SAFETY_FRACTION

#: Default absolute DFS-state ceiling (the secondary net). Above the worst HEALTHY
#: baseline (Forest ``domain/all`` ≈ 96k transient states) with headroom, so a
#: normal domain never reaches it and the RSS check remains the primary bound.
#: Operators can RAISE it (or effectively disable it with a very high value) via
#: ``ADSCAN_ATTACK_PATHS_MAX_DFS_STATES``; the default protects every run.
_DEFAULT_MAX_DFS_STATES = 2_000_000

#: Env var name that overrides the absolute DFS-state ceiling. Forwarded to the
#: container by the launcher's ``ADSCAN_*`` wildcard (11.3.0), so no launcher change
#: is needed to expose it.
_MAX_DFS_STATES_ENV = "ADSCAN_ATTACK_PATHS_MAX_DFS_STATES"


def _read_max_dfs_states() -> int:
    """Return the absolute DFS-state ceiling from the env override, best-effort.

    Falls back to :data:`_DEFAULT_MAX_DFS_STATES` on an unset/invalid value. A
    non-positive override is treated as "disable the absolute net" by returning a
    very large sentinel, so the RSS check remains the only active bound (an operator
    who sets ``0`` wants no state cap, not an instant abort).
    """
    raw = os.getenv(_MAX_DFS_STATES_ENV)
    if raw is None:
        return _DEFAULT_MAX_DFS_STATES
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return _DEFAULT_MAX_DFS_STATES
    if value <= 0:
        return 1 << 62  # effectively "no absolute cap"; RSS check still guards.
    return value


class _AttackPathMemoryBudgetExceeded(Exception):
    """Signal that attack-path discovery would exceed the memory ceiling.

    Raised by BOTH the outer projection gate (pre/post-DFS in
    ``attack_graph_service``) AND the in-DFS runaway bound (:class:`DfsMemoryBudget`
    below) so a mid-recursion OOM and a pre-decoration projection abort flow through
    the SAME clean, declared stop: the whole "declare coverage bounded, state how
    many routes/states examined" path (``build_attack_path_coverage(bounded=True,
    examined_routes=...)``) fires unchanged, turning a fatal ``SIGKILL`` into a
    reviewable coverage boundary. Caught once at the public entry point
    (``get_attack_path_summaries``). Carries the count of routes/states examined so
    the coverage boundary can state how far discovery got before the bound.

    Lives in this pure-logic module (not ``attack_graph_service``) so both the
    service layer that catches it and ``attack_graph_core`` — which imports from
    ``adscan_core`` but never from ``attack_graph_service`` — raise the SAME class.
    ``attack_graph_service`` re-exports it for its existing callers.
    """

    def __init__(self, message: str, *, examined_routes: int) -> None:
        super().__init__(message)
        self.operator_message = message
        self.examined_routes = int(examined_routes)


class DfsMemoryBudget:
    """Stateful in-DFS runaway bound shared by every ``dfs()`` closure.

    ONE instance is created per compute and its :meth:`tick` is called on entry to
    every recursive ``dfs()`` invocation across all three DFS entrypoints in
    ``attack_graph_core``, so the three sites cannot drift on the bound logic.
    ``tick`` increments a state counter and, every :data:`_RSS_SAMPLE_STRIDE`
    invocations, samples live RSS vs available memory; it raises
    :class:`_AttackPathMemoryBudgetExceeded` when either the RSS fraction or the
    absolute state cap is crossed. Both checks are ON by default.

    Best-effort by construction: the RSS sample is wrapped so a sampling failure
    (no ``/proc``, no cgroup, an RSS/available read that returns ``None``) silently
    falls back to the absolute state-cap-only path — a broken memory reader must
    never break discovery, and the state cap is the safety net for exactly that
    environment.

    The message is DEFERRED to raise-time and worded for the operator; the client
    coverage declaration is built from :attr:`examined_states` by the catch site,
    so this object stays pure (no console, no report writes).
    """

    def __init__(
        self,
        *,
        rss_stop_fraction: float = _RSS_STOP_FRACTION,
        sample_stride: int = _RSS_SAMPLE_STRIDE,
        max_states: int | None = None,
    ) -> None:
        self.examined_states = 0
        self._rss_stop_fraction = float(rss_stop_fraction)
        self._sample_stride = max(1, int(sample_stride))
        self._max_states = (
            int(max_states) if max_states is not None else _read_max_dfs_states()
        )

    def tick(self) -> None:
        """Account one ``dfs()`` invocation; raise the budget exception if bound.

        Called at the top of every recursive ``dfs()``. Increments the state
        counter, checks the absolute cap unconditionally (cheap), and samples RSS
        once every ``sample_stride`` calls (the expensive read, amortised to ~zero).
        """
        self.examined_states += 1

        # Secondary net — absolute DFS-state ceiling. Cheap, checked every call.
        if self.examined_states >= self._max_states:
            raise _AttackPathMemoryBudgetExceeded(
                _dfs_bound_operator_message(
                    reason="state_cap",
                    examined_states=self.examined_states,
                    projected_bytes=None,
                    available_bytes=None,
                ),
                examined_routes=self.examined_states,
            )

        # Primary — RSS vs the real available ceiling, sampled on a stride.
        if self.examined_states % self._sample_stride != 0:
            return
        crossed, rss_bytes, available_bytes = self._rss_crossed_ceiling()
        if crossed:
            raise _AttackPathMemoryBudgetExceeded(
                _dfs_bound_operator_message(
                    reason="rss",
                    examined_states=self.examined_states,
                    projected_bytes=rss_bytes,
                    available_bytes=available_bytes,
                ),
                examined_routes=self.examined_states,
            )

    def _rss_crossed_ceiling(self) -> tuple[bool, int | None, int | None]:
        """Return ``(crossed, rss_bytes, available_bytes)``, best-effort.

        ``crossed`` is True only when BOTH live RSS and available memory are
        readable AND ``rss >= available * fraction``. Any failure (no reader, a
        ``None`` value) returns ``(False, ...)`` so the DFS proceeds under the
        absolute state cap alone — never abort on a blind read.
        """
        try:
            from adscan_core import memory_probe

            situation = memory_probe.read_memory_situation()
            rss = situation.rss_bytes
            available = situation.available_bytes
        except Exception:  # noqa: BLE001 — a memory read must never break discovery.
            return False, None, None
        if not isinstance(rss, int) or not isinstance(available, int):
            return False, None, None
        if available <= 0:
            return False, rss, available
        threshold = int(available * self._rss_stop_fraction)
        return rss >= threshold, rss, available


def _dfs_bound_operator_message(
    *,
    reason: str,
    examined_states: int,
    projected_bytes: int | None,
    available_bytes: int | None,
) -> str:
    """Compose the operator terminal line for an in-DFS runaway abort.

    Operator-facing (the real cause + remedy); the CLIENT coverage sentence is a
    separate, reason-free statement built by :func:`build_attack_path_coverage` at
    the catch site. Never names an internal module or a verdict about the directory.
    """
    if reason == "rss" and projected_bytes and available_bytes:
        rss = _mb(projected_bytes)
        avail = _mb(available_bytes)
        return (
            f"Attack-path discovery reached about {rss} of memory with only {avail} "
            "free, and was stopped before this environment would run out. Raise the "
            "available memory (or close other running workloads) and re-run to "
            "compute the full set of routes."
        )
    return (
        f"Attack-path discovery examined {examined_states:,} intermediate states and "
        "was stopped at the configured limit before it could exhaust memory. Raise "
        "the analysis host's memory (or the state limit) and re-run to compute the "
        "full set of routes."
    )


# Operator-scenario discriminator. When the projected need exceeds the TOTAL
# ceiling, freeing RAM cannot help — the ceiling is fixed and too small. When the
# total is ample but AVAILABLE is low, another workload is holding memory and
# freeing it resolves the pressure without a resize.
SCENARIO_RESIZE = "resize_required"
SCENARIO_FREE_MEMORY = "free_memory"
SCENARIO_UNKNOWN = "unknown"


@dataclass(frozen=True)
class MemoryProjection:
    """A projected peak and the decision derived from it against a ceiling.

    Attributes:
        projected_peak_bytes: The modelled peak resident memory of the compute.
        limit_bytes: The hard ceiling used for the decision (cgroup limit or the
            host total on the meminfo fallback), or ``None`` when unknown.
        available_bytes: Memory free right now before the process is killed, or
            ``None`` when unknown.
        threshold_bytes: ``ceiling * SAFETY_FRACTION`` — the line the projection
            must stay under, or ``None`` when no ceiling is known.
        exceeds: True when the projected peak crosses the threshold. Always False
            when no ceiling could be read (best-effort: never abort blind).
        scenario: One of ``SCENARIO_*`` — which operator remedy applies.
        stage: ``"pre_dfs"`` (graph term only) or ``"post_dfs"`` (full peak).
    """

    projected_peak_bytes: int
    limit_bytes: Optional[int]
    available_bytes: Optional[int]
    threshold_bytes: Optional[int]
    exceeds: bool
    scenario: str
    stage: str


def project_graph_term_bytes(nodes: int, edges: int) -> int:
    """Return the graph-resident memory term: FLOOR + per-element * (nodes+edges)."""
    elements = max(0, int(nodes)) + max(0, int(edges))
    return FLOOR_BYTES + GRAPH_BYTES_PER_ELEMENT * elements


def _affected_aware_path_term_bytes(raw_paths: int, affected_count: int) -> int:
    """Return the regime-1 path term: raw * (base + affected-slope * affected).

    ``affected_count`` is the ESTIMATED blast radius per path (see
    :func:`project_peak_bytes` — the true value is not known at the gate seam, so a
    conservative upper bound is used). Non-negative, integer-clamped.
    """
    raw = max(0, int(raw_paths))
    affected = max(0, int(affected_count))
    return raw * (
        PATH_BASE_BYTES_PER_RAWPATH + PATH_BYTES_PER_RAWPATH_AFFECTED * affected
    )


def _graph_density_path_term_bytes(nodes: int, edges: int, raw_paths: int) -> int:
    """Return the regime-2 density term: coef * raw * branching (branching=e/n).

    This bounds the DFS PRE-minimisation transient a Forest-shaped graph holds,
    which the post-minimisation ``raw_paths`` alone under-predicts. When
    ``nodes`` is zero the branching is undefined and the term is zero (the graph
    term already covers a node-less graph).
    """
    n = max(0, int(nodes))
    e = max(0, int(edges))
    raw = max(0, int(raw_paths))
    if n <= 0 or raw <= 0:
        return 0
    branching = e / n
    return int(DENSITY_BYTES_PER_RAWPATH_BRANCH * raw * branching)


def project_peak_bytes(
    nodes: int, edges: int, raw_paths: int, affected_count: int = 0
) -> int:
    """Return the full projected peak: graph term + max(regime-1, regime-2).

    Peak RSS over the floor is the larger of two independent regimes over the
    shared graph term (see the module docstring):

    * **Regime 1 — affected-aware path term.** ``raw * (base + slope * affected)``.
      Each surviving path stores its blast-radius list, so the marginal cost grows
      with ``affected_count`` (the principals a path affects).
    * **Regime 2 — graph-density term.** ``coef * raw * (edges/nodes)``. Bounds the
      DFS pre-minimisation transient that a small, high-branching graph holds, which
      the post-minimisation ``raw_paths`` under-predicts (the Forest regime).

    ``affected_count`` is CONSERVATIVE — the true per-path blast radius is resolved
    only later, inside the very post-processing stage this gate protects, so at the
    projection point it is unknown. The caller passes an upper bound (the domain's
    enabled-principal count), so the affected-aware term OVER-projects and the gate
    errs toward a clean early stop rather than toward reaching the SIGKILL. Passing
    ``0`` degrades to the base per-raw term only — safe, never optimistic beyond it.
    """
    graph_term = project_graph_term_bytes(nodes, edges)
    affected_term = _affected_aware_path_term_bytes(raw_paths, affected_count)
    density_term = _graph_density_path_term_bytes(nodes, edges, raw_paths)
    return graph_term + max(affected_term, density_term)


def _resolve_ceiling(
    limit_bytes: Optional[int], available_bytes: Optional[int]
) -> Optional[int]:
    """Pick the ceiling the projection is compared against — the REAL headroom.

    The figure that gets a process ``SIGKILL``ed is the memory FREE right now, not
    the total cap: a container capped at 8 GB but already holding 7 GB kills at the
    next 1 GB, not the next 8 GB. So compare against ``available_bytes`` (cgroup
    ``limit - current``, or host ``MemAvailable``) whenever it is known, and fall
    back to the total ``limit_bytes`` only when the free figure is unavailable.
    Returns ``None`` when neither is known, so the caller proceeds rather than
    aborting on no information. The total-vs-available distinction that decides the
    operator remedy lives in :func:`_classify_scenario`, not here.
    """
    if isinstance(available_bytes, int) and available_bytes > 0:
        return available_bytes
    if isinstance(limit_bytes, int) and limit_bytes > 0:
        return limit_bytes
    return None


def _classify_scenario(
    projected_peak_bytes: int,
    limit_bytes: Optional[int],
    available_bytes: Optional[int],
) -> str:
    """Return which operator remedy the pressure calls for.

    The discriminator is TOTAL vs AVAILABLE:

    * projected need exceeds the TOTAL ceiling → the ceiling is fixed and too
      small, freeing RAM cannot help → ``SCENARIO_RESIZE`` (raise the VM/container
      memory and re-run).
    * total is ample but AVAILABLE is low (another workload holds memory) →
      freeing it resolves the pressure, no resize → ``SCENARIO_FREE_MEMORY``.
    * neither figure is known → ``SCENARIO_UNKNOWN``.
    """
    if isinstance(limit_bytes, int) and limit_bytes > 0:
        if projected_peak_bytes > limit_bytes:
            return SCENARIO_RESIZE
        # Total is ample (projection fits under the limit) yet the threshold was
        # crossed against AVAILABLE — transient pressure from another workload.
        if isinstance(available_bytes, int) and available_bytes >= 0:
            return SCENARIO_FREE_MEMORY
        return SCENARIO_RESIZE
    # No hard limit: the only figure is host available. A projection that exceeds
    # the host's free memory is a resize story on that host.
    if isinstance(available_bytes, int) and available_bytes > 0:
        return (
            SCENARIO_RESIZE
            if projected_peak_bytes > available_bytes
            else SCENARIO_FREE_MEMORY
        )
    return SCENARIO_UNKNOWN


def evaluate_projection(
    *,
    nodes: int,
    edges: int,
    raw_paths: Optional[int],
    limit_bytes: Optional[int],
    available_bytes: Optional[int],
    stage: str,
    affected_count: int = 0,
) -> MemoryProjection:
    """Project the peak for a stage and decide whether it crosses the ceiling.

    Args:
        nodes: Graph node count.
        edges: Graph edge count.
        raw_paths: Raw DFS path count for the post-DFS stage; ``None`` for the
            pre-DFS stage (graph term only).
        limit_bytes: The container memory ceiling (cgroup limit), or ``None``.
        available_bytes: Memory free right now, or ``None``.
        stage: ``"pre_dfs"`` or ``"post_dfs"`` — recorded on the result.
        affected_count: CONSERVATIVE estimate of the per-path blast radius for the
            post-DFS stage — an upper bound (the domain's enabled-principal count),
            because the true value is not known until after this gate. Ignored on
            the pre-DFS stage. Defaults to ``0`` (base per-raw term only).

    Returns:
        A :class:`MemoryProjection`. ``exceeds`` is False whenever no ceiling
        could be resolved — the gate never aborts on missing information; the
        compute proceeds exactly as it does today.
    """
    if raw_paths is None:
        projected = project_graph_term_bytes(nodes, edges)
    else:
        projected = project_peak_bytes(nodes, edges, raw_paths, affected_count)

    ceiling = _resolve_ceiling(limit_bytes, available_bytes)
    if ceiling is None:
        return MemoryProjection(
            projected_peak_bytes=projected,
            limit_bytes=limit_bytes,
            available_bytes=available_bytes,
            threshold_bytes=None,
            exceeds=False,
            scenario=SCENARIO_UNKNOWN,
            stage=stage,
        )

    threshold = int(ceiling * SAFETY_FRACTION)
    exceeds = projected > threshold
    scenario = (
        _classify_scenario(projected, limit_bytes, available_bytes)
        if exceeds
        else SCENARIO_UNKNOWN
    )
    return MemoryProjection(
        projected_peak_bytes=projected,
        limit_bytes=limit_bytes,
        available_bytes=available_bytes,
        threshold_bytes=threshold,
        exceeds=exceeds,
        scenario=scenario,
        stage=stage,
    )


def _mb(value: Optional[int]) -> str:
    """Render a byte count as an integer-MB string for an operator line."""
    if not isinstance(value, int) or value < 0:
        return "unknown"
    return f"{value // (1024 * 1024)} MB"


def operator_message(projection: MemoryProjection) -> str:
    """Return the terminal line for the operator — the REAL cause and the remedy.

    This is developer/operator-facing (the person running the scan), so it names
    the concrete numbers and the fix. It is NOT the client-facing coverage
    statement — that is :func:`build_attack_path_coverage`'s ``statement``.
    """
    projected = _mb(projection.projected_peak_bytes)
    limit = _mb(projection.limit_bytes)
    available = _mb(projection.available_bytes)
    if projection.scenario == SCENARIO_RESIZE:
        ceiling = limit if projection.limit_bytes else available
        return (
            f"Attack-path discovery needs about {projected} of memory but this "
            f"environment is capped at {ceiling}. Raise the container or VM "
            "memory limit and re-run to compute the full set of routes."
        )
    if projection.scenario == SCENARIO_FREE_MEMORY:
        return (
            f"Attack-path discovery needs about {projected} of memory but only "
            f"{available} is free right now (of {limit}). Close other running "
            "workloads to free memory, then re-run to compute the full set of "
            "routes."
        )
    return (
        f"Attack-path discovery needs about {projected} of memory, more than this "
        "environment can provide. Raise the available memory and re-run to compute "
        "the full set of routes."
    )


# --- Client-facing coverage declaration (mirrors cracking_coverage) -----------
#
# Three coverage MODES, all rendered through the ONE ``attack_path_coverage``
# block so the PDF report and the web platform word every case identically:
#
#   * COMPLETE — the DFS engine evaluated every candidate route. No gap, no
#     declaration; the block records ``complete=True`` and renders nothing.
#   * BOUNDED — discovery hit a hard resource ceiling and STOPPED. The route set
#     is not exhaustive; a re-run on a larger host is needed to finish it.
#   * SAMPLED — a very large directory routed to the bounded fallback engine,
#     which returns a coverage-FLOORED sample: every reachable high-value target
#     is represented, but the number of routes shown per target is capped. The
#     exposure COUNT (how many principals can reach a high-value target) is the
#     stable figure to track across re-scans; the specific routes shown are a
#     sample and may change from one scan to the next.
#
# ``COMPLETE`` and ``BOUNDED`` are byte-identical to the pre-sampled block.

#: Coverage-mode tokens carried on the block, so a consumer can branch on the
#: mode without re-deriving it from the flags.
COVERAGE_MODE_COMPLETE = "complete"
COVERAGE_MODE_BOUNDED = "bounded"
COVERAGE_MODE_SAMPLED = "sampled"

_COMPLETE_STATEMENT = (
    "Attack-path discovery evaluated the full set of candidate routes."
)


def _coverage_statement(examined_routes: int) -> str:
    """Render the client-facing coverage sentence for a bounded discovery.

    States where discovery stopped and what that leaves unevaluated. It never
    gives the internal reason (a memory limit is an operator concern, and reads as
    an apology in a deliverable), never a verdict about the client's directory,
    and never lets a bounded run read as an exhaustive one.
    """
    if examined_routes > 0:
        return (
            f"Attack-path discovery stopped after examining {examined_routes:,} "
            "candidate routes; routes beyond that were not evaluated. The routes "
            "reported here are validated as usual, but the set is not exhaustive. "
            "A re-run on a larger analysis host will evaluate the remainder."
        )
    return (
        "Attack-path discovery could not evaluate the full set of candidate routes "
        "in this run, so the set reported is not exhaustive. A re-run on a larger "
        "analysis host will evaluate the remainder."
    )


def _sampled_statement(exposure_source_count: int | None) -> str:
    """Render the client-facing coverage sentence for a SAMPLED discovery.

    A very large directory returns a representative SAMPLE of routes rather than
    every route: every reachable high-value target is covered, but the number of
    routes shown per target is capped. The figure to track across re-scans is the
    exposure COUNT — how many principals can reach a high-value target — which is
    stable even though the individual routes shown are a sample and may change
    between scans. Like the bounded statement it never gives the internal reason,
    never renders a verdict about the client's directory, and never lets the
    sampled set read as an exhaustive one.
    """
    if isinstance(exposure_source_count, int) and exposure_source_count > 0:
        exposure = f"{exposure_source_count:,} principals can reach a high-value target"
        return (
            "This directory is large enough that attack-path discovery reports a "
            "representative sample of routes rather than every route. Every "
            "reachable high-value target is covered, and the exposure is measured "
            f"as a count: {exposure}. That count is the figure to track across "
            "re-scans, as it is stable even though the specific routes shown are a "
            "sample and may change from one scan to the next. The routes reported "
            "here are validated as usual."
        )
    return (
        "This directory is large enough that attack-path discovery reports a "
        "representative sample of routes rather than every route. Every reachable "
        "high-value target is covered, and the exposure is measured as a count of "
        "how many principals can reach a high-value target. That count is the "
        "figure to track across re-scans, as it is stable even though the specific "
        "routes shown are a sample and may change from one scan to the next. The "
        "routes reported here are validated as usual."
    )


def build_attack_path_coverage(
    *,
    bounded: bool = False,
    sampled: bool = False,
    examined_routes: int = 0,
    exposure_source_count: int | None = None,
) -> dict[str, Any]:
    """Build the ``attack_path_coverage`` block for one domain.

    The block carries ONE of three coverage modes (see the module comment above):
    COMPLETE (the DFS evaluated every route), BOUNDED (discovery hit a resource
    ceiling and stopped short), or SAMPLED (a very large directory returned a
    coverage-floored sample). ``bounded`` and ``sampled`` are mutually exclusive;
    ``bounded`` wins if both are passed (a hard stop is the more conservative
    claim).

    Args:
        bounded: Whether attack-path discovery had to STOP under a resource
            limit — the route set is not exhaustive and a re-run on a larger host
            is needed to finish it.
        sampled: Whether the bounded fallback engine ran and returned a
            coverage-floored SAMPLE of routes (every reachable high-value target
            represented, routes per target capped). The exposure count is the
            stable metric across re-scans.
        examined_routes: Raw candidate routes examined before a BOUNDED stop, when
            known — surfaced to the client as the coverage boundary, never the
            reason for it. Ignored for the complete and sampled modes.
        exposure_source_count: For the SAMPLED mode, how many principals can reach
            a high-value target — the stable exposure figure the statement anchors
            the re-scan narrative on. Omitted (``None``) still yields a valid
            statement, without the concrete number.

    Returns:
        The block to hand to ``record_attack_path_coverage``. Always carries
        ``statement`` so the recorder accepts it, plus ``mode``, ``complete``,
        ``sampled``, ``examined_routes`` and ``exposure_source_count``.
    """
    examined = max(0, int(examined_routes))
    source_count = (
        max(0, int(exposure_source_count))
        if isinstance(exposure_source_count, int)
        else None
    )
    if bounded:
        mode = COVERAGE_MODE_BOUNDED
        statement = _coverage_statement(examined)
    elif sampled:
        mode = COVERAGE_MODE_SAMPLED
        statement = _sampled_statement(source_count)
    else:
        mode = COVERAGE_MODE_COMPLETE
        statement = _COMPLETE_STATEMENT
    return {
        "mode": mode,
        # ``complete`` stays the historical field the view/merge key on; it is True
        # ONLY for the full-DFS mode, so a sampled run correctly reads as a gap.
        "complete": mode == COVERAGE_MODE_COMPLETE,
        "sampled": mode == COVERAGE_MODE_SAMPLED,
        "examined_routes": examined,
        "exposure_source_count": source_count,
        "statement": statement,
    }


def attack_path_coverage_view(coverage: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``attack_path_coverage`` block.

    The one shape the PDF report and the web platform both read, so a bounded run
    is worded identically wherever a client meets it.

    Returns a mapping with:
      * ``has_gap`` — whether to surface the declaration at all;
      * ``statement`` — the client-facing sentence (empty when complete);
      * ``mode`` — ``complete`` / ``bounded`` / ``sampled``, so a renderer can
        style the declaration (a sampled run is a coverage NOTE, not a failure);
      * ``sampled`` — convenience boolean for the sampled mode;
      * ``examined_routes`` — routes examined before a bounded stop;
      * ``exposure_source_count`` — for a sampled run, the stable exposure count,
        or ``None``.

    An absent or unreadable block yields ``has_gap=False`` and an empty statement:
    a scan predating this record, or a complete run, must render exactly as it did
    before rather than grow a gap notice nobody observed.
    """
    if not isinstance(coverage, Mapping):
        return {
            "has_gap": False,
            "statement": "",
            "mode": COVERAGE_MODE_COMPLETE,
            "sampled": False,
            "examined_routes": 0,
            "exposure_source_count": None,
        }
    complete = bool(coverage.get("complete", True))
    statement = str(coverage.get("statement") or "").strip()
    try:
        examined = max(0, int(coverage.get("examined_routes") or 0))
    except (TypeError, ValueError):
        examined = 0
    sampled = bool(coverage.get("sampled", False))
    # Derive the mode from the block: an older bounded block predating the mode
    # field still resolves correctly (complete=False, sampled absent → bounded).
    mode = str(coverage.get("mode") or "").strip().lower()
    if mode not in (
        COVERAGE_MODE_COMPLETE,
        COVERAGE_MODE_BOUNDED,
        COVERAGE_MODE_SAMPLED,
    ):
        if complete:
            mode = COVERAGE_MODE_COMPLETE
        elif sampled:
            mode = COVERAGE_MODE_SAMPLED
        else:
            mode = COVERAGE_MODE_BOUNDED
    raw_source_count = coverage.get("exposure_source_count")
    try:
        exposure_source_count = (
            max(0, int(raw_source_count)) if raw_source_count is not None else None
        )
    except (TypeError, ValueError):
        exposure_source_count = None
    return {
        "has_gap": bool(not complete and statement),
        "statement": statement if not complete else "",
        "mode": mode,
        "sampled": mode == COVERAGE_MODE_SAMPLED,
        "examined_routes": examined,
        "exposure_source_count": exposure_source_count,
    }


def merge_attack_path_coverage(domain_entries: Any) -> dict[str, Any]:
    """Fold every domain's recorded coverage into one report-wide view.

    A bounded OR sampled discovery in any domain means the assessment's route set
    is not exhaustive, so the union is a gap for the whole report. The statement
    returned is the one that was RECORDED (never a fresh derivation), so a later
    change to this module cannot silently rewrite a finding an already-delivered
    report made; only when several domains recorded DIFFERENT gap statements is
    one re-derived.

    When both a BOUNDED (hard stop) and a SAMPLED gap are present, the merged view
    takes the BOUNDED mode: a hard stop is the more conservative, more urgent
    claim (the route set is genuinely incomplete, versus a sampled run that still
    covers every reachable target). A report with only sampled gaps stays sampled,
    carrying the largest exposure count so the re-scan narrative anchors on the
    stable figure.

    ``domain_entries`` is any iterable of per-domain mappings (the renderer passes
    ``report_data.values()``); non-mapping entries and the reserved non-domain
    blocks that ride alongside are skipped. No recorded coverage anywhere yields
    ``has_gap=False`` — the pre-existing render, unchanged.
    """
    statements: list[str] = []
    max_examined = 0
    max_source_count = 0
    saw_bounded = False
    saw_sampled = False
    for entry in domain_entries or ():
        if not isinstance(entry, Mapping):
            continue
        block = entry.get(ATTACK_PATH_COVERAGE_KEY)
        view = attack_path_coverage_view(block)
        if not view["has_gap"]:
            continue
        if view["mode"] == COVERAGE_MODE_SAMPLED:
            saw_sampled = True
            count = view.get("exposure_source_count")
            if isinstance(count, int):
                max_source_count = max(max_source_count, count)
        else:
            saw_bounded = True
        max_examined = max(max_examined, int(view["examined_routes"]))
        if view["statement"] not in statements:
            statements.append(view["statement"])
    if not saw_bounded and not saw_sampled:
        return attack_path_coverage_view(None)
    if saw_bounded:
        merged = build_attack_path_coverage(bounded=True, examined_routes=max_examined)
    else:
        merged = build_attack_path_coverage(
            sampled=True,
            exposure_source_count=max_source_count or None,
        )
    if len(statements) == 1:
        merged["statement"] = statements[0]
    return attack_path_coverage_view(merged)


__all__ = [
    "ATTACK_PATH_COVERAGE_KEY",
    "COVERAGE_MODE_COMPLETE",
    "COVERAGE_MODE_BOUNDED",
    "COVERAGE_MODE_SAMPLED",
    "FLOOR_BYTES",
    "GRAPH_BYTES_PER_ELEMENT",
    "PATH_BASE_BYTES_PER_RAWPATH",
    "PATH_BYTES_PER_RAWPATH_AFFECTED",
    "PATH_BYTES_PER_RAWPATH",
    "DENSITY_BYTES_PER_RAWPATH_BRANCH",
    "SAFETY_FRACTION",
    "SCENARIO_FREE_MEMORY",
    "SCENARIO_RESIZE",
    "SCENARIO_UNKNOWN",
    "MemoryProjection",
    "DfsMemoryBudget",
    "_AttackPathMemoryBudgetExceeded",
    "project_graph_term_bytes",
    "project_peak_bytes",
    "evaluate_projection",
    "operator_message",
    "build_attack_path_coverage",
    "attack_path_coverage_view",
    "merge_attack_path_coverage",
]
