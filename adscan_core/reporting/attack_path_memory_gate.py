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
The measured slope is ``0.35 KB per (raw_path * affected_principal)`` — tight
(0.343–0.361 across five high-corner fixtures spanning raw 1,427→15,000 and
affected 51→3,001), predicting 5 of 6 within 2%. The old scalar
``155 KB/raw_path`` silently assumed ``affected ≈ 430``; on a corporate directory
where each path affects ~2,000 principals the true rate is ~880 KB/raw, so the
scalar gate fired ~5x too late there — it let the corporate run (the OOM the user
reported) get far closer to the kill than it should. At affected≈2,000 on a
20k-element graph, 2 GB is now crossed at ~2,600 raw_paths, not the ~13,500 the
scalar model implied.

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
#: (2026-08, the intercept of the per-raw curve at affected→0). Final.
PATH_BASE_BYTES_PER_RAWPATH = 4 * 1024

#: Marginal peak memory per (RAW DFS path × affected principal) — the cost of each
#: surviving path storing its blast-radius ``meta.affected_users`` list. Measured
#: 0.35 KB/(raw_path·affected), tight (2026-08: 0.343–0.361 across the AffA/AffB/
#: AffC/DomX-15k/L15k high-corner sweep, which fixes raw and varies affected from
#: 51 to 3,001). This slope is what the old scalar 155 KB/raw missed: it assumed a
#: fixed affected≈430, and a corporate directory affecting ~2,000 principals per
#: path costs ~880 KB/raw, so the scalar gate fired ~5x too late there.
PATH_BYTES_PER_RAWPATH_AFFECTED = int(0.35 * 1024)

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

_COMPLETE_STATEMENT = "Attack-path discovery evaluated the full set of candidate routes."


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


def build_attack_path_coverage(
    *,
    bounded: bool,
    examined_routes: int = 0,
) -> dict[str, Any]:
    """Build the ``attack_path_coverage`` block for one domain.

    Args:
        bounded: Whether attack-path discovery had to stop under a resource
            limit. ``False`` records a complete run (the statement affirms full
            coverage and ``build`` carries ``complete=True``).
        examined_routes: Raw candidate routes examined before the bound, when
            known — surfaced to the client as the coverage boundary, never the
            reason for it.

    Returns:
        The block to hand to ``record_attack_path_coverage``. Always carries
        ``statement`` so the recorder accepts it.
    """
    complete = not bounded
    return {
        "complete": complete,
        "examined_routes": max(0, int(examined_routes)),
        "statement": (
            _COMPLETE_STATEMENT
            if complete
            else _coverage_statement(max(0, int(examined_routes)))
        ),
    }


def attack_path_coverage_view(coverage: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``attack_path_coverage`` block.

    The one shape the PDF report and the web platform both read, so a bounded run
    is worded identically wherever a client meets it.

    Returns a mapping with:
      * ``has_gap`` — whether to surface the declaration at all;
      * ``statement`` — the client-facing sentence (empty when complete);
      * ``examined_routes`` — routes examined before the bound, for a machine
        consumer.

    An absent or unreadable block yields ``has_gap=False`` and an empty statement:
    a scan predating this record, or a complete run, must render exactly as it did
    before rather than grow a gap notice nobody observed.
    """
    if not isinstance(coverage, Mapping):
        return {"has_gap": False, "statement": "", "examined_routes": 0}
    complete = bool(coverage.get("complete", True))
    statement = str(coverage.get("statement") or "").strip()
    try:
        examined = max(0, int(coverage.get("examined_routes") or 0))
    except (TypeError, ValueError):
        examined = 0
    return {
        "has_gap": bool(not complete and statement),
        "statement": statement if not complete else "",
        "examined_routes": examined,
    }


def merge_attack_path_coverage(domain_entries: Any) -> dict[str, Any]:
    """Fold every domain's recorded coverage into one report-wide view.

    A bounded discovery in any domain means the assessment's route set is not
    exhaustive, so the union is a gap for the whole report. The statement returned
    is the one that was RECORDED (never a fresh derivation), so a later change to
    this module cannot silently rewrite a finding an already-delivered report made;
    only when several domains recorded DIFFERENT gap statements is one re-derived
    from the largest examined count.

    ``domain_entries`` is any iterable of per-domain mappings (the renderer passes
    ``report_data.values()``); non-mapping entries and the reserved non-domain
    blocks that ride alongside are skipped. No recorded coverage anywhere yields
    ``has_gap=False`` — the pre-existing render, unchanged.
    """
    statements: list[str] = []
    max_examined = 0
    saw_gap = False
    for entry in domain_entries or ():
        if not isinstance(entry, Mapping):
            continue
        block = entry.get(ATTACK_PATH_COVERAGE_KEY)
        view = attack_path_coverage_view(block)
        if not view["has_gap"]:
            continue
        saw_gap = True
        max_examined = max(max_examined, int(view["examined_routes"]))
        if view["statement"] not in statements:
            statements.append(view["statement"])
    if not saw_gap:
        return attack_path_coverage_view(None)
    merged = build_attack_path_coverage(bounded=True, examined_routes=max_examined)
    if len(statements) == 1:
        merged["statement"] = statements[0]
    return attack_path_coverage_view(merged)


__all__ = [
    "ATTACK_PATH_COVERAGE_KEY",
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
    "project_graph_term_bytes",
    "project_peak_bytes",
    "evaluate_projection",
    "operator_message",
    "build_attack_path_coverage",
    "attack_path_coverage_view",
    "merge_attack_path_coverage",
]
