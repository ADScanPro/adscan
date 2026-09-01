"""Single seam owning the ``attack_paths_discovery`` phase lifecycle.

The attack-path *computation engine* (``get_attack_path_summaries``) is already a
single source of truth. What used to be duplicated by hand at every orchestration
site is the phase *lifecycle contract*: announce the phase, run the compute
wrapper, and checkpoint the phase complete. Three sites drove attack-path
discovery — ``run_enumeration``'s Phase 2 (single-domain), the trust/cross-domain
pivot in ``cli/domains.py`` (merged multi-domain), and the audit post-compromise
block — and each re-implemented the contract independently. The trust pivot
implemented only the announce half (commit ``74cb0c72``) and never marked the
phase complete, leaving a permanent HOLE at ``attack_paths_discovery`` in the
crash-resume checkpoint (``resume_phase_id`` then reported that hole as the resume
point regardless of how far the scan actually reached).

This module extracts the contract into ONE function,
:func:`run_attack_paths_discovery_phase`, that owns compute + checkpoint as an
atomic unit (and optionally the announce). Both the single-domain Phase-2 seam and
the trust/cross-domain pivot route their lifecycle through it, so the checkpoint
obligation can never be forgotten again — the single-vs-multi-domain difference is
a PARAMETER (``len(domains)``), not a caller fork.

The compute is UNIFIED: one flow for one or N domains, per-domain display+execute,
and there is NO silent build-only pre-pass. A single-domain workspace runs one
``run_attack_path_discovery`` (display + execute). A multi-domain workspace runs ONE
per-domain display+execute sweep over the auto-merged graph — the earlier silent
``build_only=True`` sweep was removed as redundant. The cross-domain merge and the
RaiseChild / CrossOrg trust coupling are pure READ-TIME properties of the compute:
the merge (``_load_attack_graph_for_paths`` → ``load_merged_attack_graph``) reads
every per-domain ``attack_graph.json`` and re-applies the coupling in-memory on each
load (``_enrich_foreign_dc_nodes``), and the trust edges are already persisted during
COLLECTION (``collector/orchestrator.py`` → ``persist_cross_domain_trust_edges``).
By the time this phase runs, every selected domain's graph is on disk, so the FIRST
display compute already sees the full merged, trust-coupled graph — the build sweep
built nothing the display sweep did not, it only computed every path once and threw
it away (rendering nothing, offering no execution) before recomputing. Each domain's
owned view is computed over its full trust-union owned set (the compute *context*,
not just the owned set, governs discoverability, so restricting the owned set would
silently drop real paths), and ONE shared de-duplication ledger keyed by
``(source, target, relations, status)`` keeps each unique path in the FIRST domain
that lists it. The operator therefore sees the SAME per-domain, directly-executable
view in single- and multi-domain scans, with every unique path shown exactly once.

The multi-domain scan INTERLEAVES per domain. The trust/cross-domain pivot in
``cli/domains.py`` no longer runs ``[attack-paths for ALL domains] → [phases-3+ for
each domain]``; after collection populates every domain's graph, it runs ONE loop
``for domain in selected:`` that computes THAT domain's attack paths and then runs
THAT domain's remaining phases (quick wins, spraying, SMB, unauth, CVE …) before
moving to the next domain. So the pivot calls this seam once per domain (each with a
single-element ``domains`` list) and threads ONE shared ``seen_path_keys`` ledger
through every call, keeping the "each unique path shown once" guarantee across the
interleaved runs. A consequence the founder accepted intentionally: an earlier domain
is EXPLOITED (its phases-3+ run) before a later domain computes its attack paths, so
the later domain sees the graph/credentials already mutated by the earlier domain's
exploitation — realistic cross-domain chaining, not a regression. The merged-graph
correctness is unaffected because the merge is read-time and every domain's graph is
already on disk before the loop starts.

The separate "Cross-Domain Attack Paths" pass was REMOVED: the per-domain graph
merge is transparent (``_load_attack_graph_for_paths`` merges every per-domain
``attack_graph.json``, so each per-domain DFS already crosses trust boundaries), so
that pass was redundant AND lossy — it computed only ``reachable[0]``, a 34-110/129
coverage regression on GOAD.

The module is dependency-light: it never imports the engine or the native stack.
The compute wrapper and announce helpers are imported lazily inside the function
body so unit tests that monkeypatch them at their canonical module path keep
working.
"""

from __future__ import annotations

from typing import Any, Callable, Sequence

# The canonical phase id this seam checkpoints. Matches
# ``scan_progress.RUN_ENUMERATION_PHASE_IDS`` and ``scan_phases`` exactly.
ATTACK_PATHS_DISCOVERY_PHASE_ID = "attack_paths_discovery"

# The operator-facing step/phase label, kept identical to the string the
# single-domain Phase-2 block and the trust pivot rendered before this seam.
_ATTACK_PATHS_DISCOVERY_TITLE = "Attack Paths Discovery"


def run_attack_paths_discovery_phase(
    shell: Any,
    *,
    domains: Sequence[str],
    checkpoint_domains: Sequence[str],
    span_domain: str,
    scan_type: str | None = None,
    announce: bool = True,
    run_step: Callable[[str, Callable[[], None]], Any] | None = None,
    max_depth: int = 6,
    seen_path_keys: set[tuple[Any, ...]] | None = None,
) -> bool:
    """Run the ``attack_paths_discovery`` phase lifecycle for one or more domains.

    Owns the three-part phase contract as an atomic unit so a future call site
    inherits all three obligations by construction:

    1. **Announce** (only when ``announce`` is True): render the chapter strip and
       open a timeline span for ``attack_paths_discovery``. The single-domain
       Phase-2 caller already announces through its own ``_enter_phase`` machinery
       (which integrates with the run-level span tracker, the between-phase crack
       surfacing, and ``mark_scan_running``), so it passes ``announce=False`` to
       avoid a double announce.
    2. **Compute** via ``run_attack_path_discovery``, selecting single-domain vs
       multi-domain by ``len(domains)``:
       * ``len(domains) == 1`` — one ``run_attack_path_discovery`` (display +
         execute; no build-only pre-pass).
       * ``len(domains) > 1`` — ONE per-domain display+execute sweep over the
         auto-merged graph (no silent ``build_only=True`` pre-pass — it was
         redundant, see the module docstring). Each domain's owned view is computed
         over its full trust-union owned set (full coverage), and a shared
         de-duplication ledger keyed by ``(source, target, relations, status)``
         shows each unique path once — under the FIRST domain that lists it — so no
         duplicate rows appear across trust-connected views. The graph merge is
         transparent (see ``_load_attack_graph_for_paths``); the earlier separate
         cross-domain pass computed only ``reachable[0]`` (a 34-110/129 coverage
         regression on GOAD) and was removed.
    3. **Checkpoint**: mark ``attack_paths_discovery`` complete for every domain in
       ``checkpoint_domains`` — but ONLY on a clean, non-early-stop return. A
       CTF-pwned early stop (surfaced by ``run_step`` returning True) MUST NOT mark
       the phase complete, exactly like the inline ``_run_step`` → ``_mark_done``
       contract it replaces.

    Args:
        shell: The active ``PentestShell``.
        domains: Domains to compute paths for. One element = single-domain; more
            than one = merged multi-domain (per-domain build then cross-domain
            display).
        checkpoint_domains: Domains whose ``scan_progress`` checkpoint must record
            ``attack_paths_discovery`` complete. Pass an empty sequence to skip
            checkpointing (e.g. when the caller's checkpoint gate is off).
        span_domain: The domain used for the timeline span / chapter emission.
        scan_type: The engagement type for the chapter's visibility filter;
            defaults to ``shell.type`` when omitted.
        announce: Emit the chapter + open the timeline span here. ``False`` when
            the caller already announced the phase through its own machinery.
        run_step: Optional step-runner (the Phase-2 ``_run_step`` closure) that
            wraps the compute with the operator-facing step UX and the CTF-pwned
            early-stop check. It returns a TRUTHY value (``StepOutcome.STOP_*``)
            to signal an early stop, in which case the pipeline should stop and
            the phase is NOT marked complete. Finalizing the scan checkpoint on
            an objective-met stop is the runner's own responsibility — this seam
            only honours the stop. When omitted the compute runs directly.
        max_depth: Actionable-edge depth budget for the single-domain build.
        seen_path_keys: Optional shared de-duplication ledger keyed by
            ``(source, target, relations, status)``. The trust/cross-domain pivot
            INTERLEAVES attack-paths per domain with that domain's phases-3+, so it
            can no longer hand this seam the whole domain list in one call. Instead
            it calls the seam once per domain (each with a single-element
            ``domains``) and threads ONE ledger through every call via this
            parameter, preserving the "each unique cross-domain path shown once,
            under the first domain that lists it" guarantee across the interleaved
            runs. When ``None`` (every single-call caller — the per-domain Phase 2
            in ``run_enumeration`` and the audit block) there is no cross-call
            de-dup, which is correct because those callers cover one domain in total.

    Returns:
        ``True`` when the caller should early-stop the surrounding pipeline (only
        possible via ``run_step`` signalling a CTF-pwned compromise). ``False``
        otherwise. On ``True`` the phase is intentionally left unmarked.
    """
    from adscan_internal.services import scan_progress

    _ap_phase_cm = None
    if announce:
        try:
            from adscan_internal.services.scan_phases import emit_chapter
            from adscan_internal.services.scan_timeline import phase_span

            effective_scan_type = (
                scan_type
                if scan_type is not None
                else (getattr(shell, "type", "default") or "default")
            )
            # ``emit_chapter`` is the single transition point (chapter strip AND
            # the structured phase event); emit it exactly ONCE per phase run.
            emit_chapter(
                ATTACK_PATHS_DISCOVERY_PHASE_ID, scan_type=effective_scan_type
            )
            _ap_phase_cm = phase_span(
                shell,
                span_domain,
                phase_id=ATTACK_PATHS_DISCOVERY_PHASE_ID,
                phase_title=_ATTACK_PATHS_DISCOVERY_TITLE,
            )
            _ap_phase_cm.__enter__()
        except Exception:  # noqa: BLE001 — telemetry must never block discovery
            _ap_phase_cm = None

    def _compute() -> None:
        # Lazy import at call time so tests that monkeypatch this at
        # ``adscan_internal.cli.intelligence.*`` see the patched callable.
        from adscan_internal.cli.intelligence import run_attack_path_discovery

        if len(domains) > 1:
            # Multi-domain: ONE per-domain display+execute sweep over the SAME
            # auto-merged graph (``_load_attack_graph_for_paths`` merges every
            # per-domain ``attack_graph.json`` transparently, so each per-domain DFS
            # already crosses trust boundaries).
            #
            # There is NO separate silent ``build_only=True`` sweep anymore. It was
            # redundant: the cross-domain merge + the RaiseChild / CrossOrg trust
            # coupling are pure READ-TIME properties of the compute — the merge
            # reads each domain's on-disk ``attack_graph.json`` and re-applies the
            # coupling in-memory on every load (``_enrich_foreign_dc_nodes`` →
            # ``couple_raise_child_edges`` / ``couple_cross_org_tgt_delegation_edges``),
            # and the trust edges are already persisted during COLLECTION
            # (``collector/orchestrator.py`` → ``persist_cross_domain_trust_edges``,
            # when >1 domain is collected). By the time this phase runs, every
            # selected domain's graph is already on disk, so the FIRST display
            # compute already sees the full merged, trust-coupled graph. The old
            # build sweep just computed every path once, discarded it (rendering
            # nothing, offering no execution), then recomputed on the display pass —
            # a wasted, invisible second traversal that gated execution off.
            #
            # Each domain's owned view is computed over its full trust-union owned
            # set (so no cross-domain path is lost — the compute context matters,
            # not just the owned set), and ONE shared de-duplication ledger keeps
            # each unique path in the FIRST domain that lists it, so a cross-domain
            # path shared across trust-connected views is displayed and offered for
            # execution exactly once. Coverage is preserved; duplicate rows are not.
            #
            # ``seen_path_keys`` MAY be supplied by the caller (the trust pivot
            # threads ONE ledger across its INTERLEAVED per-domain calls — each of
            # which enters this function with a single-domain ``domains`` list — so
            # the same-once guarantee spans the whole multi-domain scan even though
            # each domain's attack-paths run is now interleaved with that domain's
            # phases-3+). When the caller passes nothing we own a fresh ledger for
            # this call's sweep.
            _ledger: set[tuple[Any, ...]] = (
                seen_path_keys if seen_path_keys is not None else set()
            )
            for one_domain in domains:
                run_attack_path_discovery(
                    shell,
                    one_domain,
                    max_depth=max_depth,
                    seen_path_keys=_ledger,
                )
        else:
            # A caller-supplied ledger (the trust pivot's interleaved per-domain
            # sweep) makes each single-domain call de-dup against the paths already
            # shown under earlier domains — the cross-scan same-once guarantee. Every
            # other single-domain caller passes ``None`` (no de-dup, legacy behaviour).
            run_attack_path_discovery(
                shell,
                domains[0],
                max_depth=max_depth,
                seen_path_keys=seen_path_keys,
            )

    try:
        if run_step is not None:
            # ``run_step`` returns a truthy outcome to signal a CTF-pwned early
            # stop; in that case the phase must NOT be marked complete (parity
            # with the inline ``if _run_step(...).should_stop: return`` before
            # ``_mark_done``).
            if run_step(_ATTACK_PATHS_DISCOVERY_TITLE, _compute):
                return True
        else:
            _compute()
    finally:
        if _ap_phase_cm is not None:
            try:
                _ap_phase_cm.__exit__(None, None, None)
            except Exception:  # noqa: BLE001 — telemetry must never block
                pass

    for checkpoint_domain in checkpoint_domains:
        scan_progress.mark_phase_complete(
            shell, checkpoint_domain, ATTACK_PATHS_DISCOVERY_PHASE_ID
        )
    return False
