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
obligation can never be forgotten again — the merged-vs-per-domain difference is a
PARAMETER (``len(domains)``), not a caller fork.

The module is dependency-light: it never imports the engine or the native stack.
The compute wrappers and announce helpers are imported lazily inside the function
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
    run_step: Callable[[str, Callable[[], None]], bool] | None = None,
    max_depth: int = 6,
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
    2. **Compute** via the existing wrappers, selecting per-domain vs merged
       multi-domain by ``len(domains)``:
       * ``len(domains) == 1`` — ``run_attack_path_discovery`` (build + display).
       * ``len(domains) > 1`` — a silent ``build_only=True`` build for every
         domain (so every ``attack_graph.json`` is populated) followed by
         ``run_cross_domain_attack_path_discovery`` to display the merged view.
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
            early-stop check. When provided and it returns True, the pipeline
            should stop and the phase is NOT marked complete. When omitted the
            compute runs directly.
        max_depth: Actionable-edge depth budget for the single-domain build.

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
        # Lazy import at call time so tests that monkeypatch these at
        # ``adscan_internal.cli.intelligence.*`` see the patched callables.
        from adscan_internal.cli.intelligence import (
            run_attack_path_discovery,
            run_cross_domain_attack_path_discovery,
        )

        if len(domains) > 1:
            # Build every per-domain graph silently first so multi-hop
            # cross-domain edges are present, then display the merged view once.
            for one_domain in domains:
                run_attack_path_discovery(shell, one_domain, build_only=True)
            run_cross_domain_attack_path_discovery(shell, list(domains))
        else:
            run_attack_path_discovery(shell, domains[0], max_depth=max_depth)

    try:
        if run_step is not None:
            # ``run_step`` returns True to signal a CTF-pwned early stop; in that
            # case the phase must NOT be marked complete (parity with the inline
            # ``if _run_step(...): return`` before ``_mark_done``).
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
