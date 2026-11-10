"""Posture-score path inputs and the report-tier split: one dependency-light SSOT.

Moved here from ``adscan_internal.services.client_exposure_figures`` and
``path_state`` (both re-export every name) so a process with no engine on its
path can compute the posture score exactly as the SAR does. The web worker is
that process: it stamps each scan's posture score at ingestion, and an engine
import there failed on every ingest ("No module named 'rich'") and stamped
nothing. Standard library only; keep it that way.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

#: A synthetic coverage-declaration record from the bounded fallback (a reachable
#: target represented without its route). It states coverage, not exposure.
COVERAGE_SAMPLE_STATUS: str = "coverage_sample"

#: A finding ADscan actively proved absent (e.g. ESC15 confirm-mode observed a
#: patched CA): a dismissed finding, not exposure.
NOT_VULNERABLE_STATUS: str = "not_vulnerable"

#: Statuses that describe NO client exposure, and therefore may never be counted
#: into a risk figure or offered to a client as something to remediate.
#:
#: * ``closed_by_configuration`` — the POSITIVE bucket. The client's own
#:   configuration already closed this avenue and ADscan observed it with
#:   certainty ("Attack Surface Reduced — Hardening Observed"). Billing them to
#:   fix hardening they already did inverts what the report is for.
#: * ``unsupported`` / ``unavailable`` — an ADscan data gap: no reachable surface
#:   to walk, so the absence of a result says nothing about the client.
#: * ``coverage_sample`` — a synthetic coverage-declaration record from the
#:   bounded fallback (a reachable target represented without its route). It
#:   states coverage, not exposure, so it is excluded exactly like a data gap.
#: * ``not_vulnerable`` — a finding ADscan actively proved absent (e.g. ESC15
#:   confirm-mode observed a patched CA). The weakness does not exist, so the
#:   path is a dismissed finding, not exposure; the positive is carried by a
#:   compliance control instead.
#:
#: This is the same set as the ``None`` entries of
#: ``exposure_score_service._PROOF_WEIGHT`` — that table builds them from here,
#: so the exposure score and every remediation ranking exclude exactly the same
#: paths and cannot drift apart. The token spelling is locked against
#: ``relay_status_constants.CONFIGURATION_CLOSE_STATUS`` by
#: ``tests/unit/services/test_remediation_status_filter.py`` (a test-only import,
#: which keeps this module the stdlib-only leaf its closure depends on).
NO_EXPOSURE_STATUSES: frozenset[str] = frozenset(
    {
        "closed_by_configuration",
        "unsupported",
        "unavailable",
        COVERAGE_SAMPLE_STATUS,
        NOT_VULNERABLE_STATUS,
    }
)


def carries_client_exposure(raw: object) -> bool:
    """Return True when a path's status describes exposure worth remediating.

    The inclusion filter every client-facing count applies before it reports a
    number as exposure: the exposure score, the remediation rankings, the
    report's Compromise Reach cards, and the page-2 executive headline. Three
    statuses answer "no", each for a reason the client would recognise:

    * ``closed_by_configuration`` — their own configuration already closed this
      avenue and ADscan observed it. It is the report's POSITIVE bucket, and
      counting it as exposure bills them for hardening they already did.
    * ``unsupported`` / ``unavailable`` — ADscan had no reachable surface to
      walk. That is a gap in our coverage, not an exposure in their directory.

    Everything else counts, including ``attempted`` and ``blocked``: ADscan
    failing to land a technique, or withholding a destructive one, says nothing
    about whether the avenue is open (CLAUDE.md § Exposure Validation).

    Declared on this stdlib-only leaf, beside the set it reads, so any consumer
    can apply the SAME filter without dragging a heavier module into its import
    closure. ``technique_priority`` re-exports it for its existing callers.

    Args:
        raw: A path's raw ``status`` token, in any casing.

    Returns:
        ``False`` only for the three statuses above. An unknown or missing token
        counts as exposure — the safe direction, since the alternative is
        dropping a real route from the client's fix list.
    """
    return str(raw or "").strip().lower() not in NO_EXPOSURE_STATUSES


#: Canonical, single-source-of-truth mapping from the engine's per-path
#: ``compromise_class`` to the three report exposure tiers (the report renderer
#: AND any exposure logic MUST import this — never re-derive the split):
#:
#: * ``domain_breaker``        → ``"T1"`` — Full domain compromise. The path
#:   reaches the DOMAIN OBJECT itself (founder decision 2026-11-05: only this
#:   class may say "domain compromise").
#: * ``tier0_control``         → ``"T1C"`` — Tier 0 control. The path ends in
#:   control of a direct Tier 0 principal or asset (Domain Admins, krbtgt, RID
#:   500, a DC) without reaching the domain object, for example a depth cap or
#:   removed replication rights. Normally empty: the engine extends these
#:   routes to the domain object. Kept out of ``T1`` so the full-domain-
#:   compromise figure never counts a route that did not reach the domain.
#: * ``tier0_foothold``        → ``"T2"`` — Tier-0 host foothold. Access to a
#:   Tier-0 HOST (e.g. CanRDP to a DC) where post-exploitation is still
#:   required; takeover is NOT yet proven.
#: * ``privileged_escalator``  → ``"T3"`` — Privilege-escalation enabler.
#:   Reaches a privileged asset (e.g. an issuance-policy group via ESC13, or a
#:   server via LSA dump) but does not constitute domain takeover on its own.
#: * ``compromise_enabler``    → ``"T4"`` — Stepping stone to Tier 0. A
#:   validated route that advances toward Tier 0 without landing on a Tier 0
#:   asset or escalation group. Tracked as its own tier so the report's
#:   Compromise Reach quartet sums to the domain's whole path total — folding
#:   it into T3 (as the report used to) undercounted the executive headline
#:   against the engine-stamped ``path_axis`` total.
#:
#: Any other / unknown class maps to ``None`` and is NOT counted in these four
#: tiers (e.g. ``unauthenticated_principal``, ``""``).
_COMPROMISE_CLASS_TO_REPORT_TIER: dict[str, str] = {
    "domain_breaker": "T1",
    "tier0_control": "T1C",
    "tier0_foothold": "T2",
    "privileged_escalator": "T3",
    "compromise_enabler": "T4",
}

#: Legacy fallback ONLY — for records that predate ``compromise_class`` stamping
#: and carry just an ``outcome_class``. Mirrors the fallback already used by
#: :func:`_is_tier0_target`. Current engine records always carry
#: ``compromise_class``, so this is never consulted for live scans; it keeps the
#: predicate correct for legacy/synthetic records (and report fixtures).
_OUTCOME_CLASS_TO_REPORT_TIER: dict[str, str] = {
    "direct_domain_control": "T1",
    "direct_compromise": "T1",
    "tier0_foothold": "T2",
    "followup_terminal": "T3",
    "high_impact_privilege": "T3",
    "domain_compromise_enabler": "T4",
}


def report_tier_for_class(compromise_class: str | None) -> str | None:
    """Map a path ``compromise_class`` to its report tier (``T1``-``T4``).

    This is the single source of truth for the report's 4-tier exposure
    breakdown (the Compromise Reach quartet). Returns ``None`` for any class
    outside the four tracked tiers (e.g. ``unauthenticated_principal``,
    ``""``), so callers can count only the four canonical tiers.

    Args:
        compromise_class: The engine's per-path ``compromise_class`` value.

    Returns:
        ``"T1"`` (full domain compromise), ``"T1C"`` (Tier 0 control),
        ``"T2"`` (Tier-0 host foothold),
        ``"T3"`` (privilege-escalation enabler), ``"T4"`` (stepping stone to
        Tier 0), or ``None`` if not tracked.
    """
    return _COMPROMISE_CLASS_TO_REPORT_TIER.get(
        (compromise_class or "").strip().lower()
    )


def report_tier_for_record(record: Mapping[str, Any]) -> str | None:
    """Resolve the report tier for a single attack-path record.

    Prefers the canonical ``compromise_class``; falls back to ``outcome_class``
    only when the class is absent (legacy/synthetic records). This is the
    record-level single source of truth used by the report renderer and
    :func:`count_report_tiers`.

    Args:
        record: An attack-path record mapping.

    Returns:
        ``"T1"`` / ``"T1C"`` / ``"T2"`` / ``"T3"`` / ``"T4"`` or ``None`` when
        untracked.
    """
    tier = report_tier_for_class(record.get("compromise_class"))
    if tier is not None:
        return tier
    return _OUTCOME_CLASS_TO_REPORT_TIER.get(
        str(record.get("outcome_class") or "").strip().lower()
    )


def derive_posture_path_inputs(
    records: Sequence[Mapping[str, Any]],
    *,
    paths_to_da: int | None = None,
) -> tuple[int, int]:
    """Return ``(paths_to_da, tier0_exposed)`` for :func:`compute_posture_score`.

    The **single source of truth** for the two path-derived posture-score inputs,
    shared by the PRO report and the LITE HTML exposure report so the SAME
    workspace always yields the SAME score on both tiers. A client who sees one
    number in the free tier and a different one after buying has a number they
    cannot trust, so this derivation must never be re-implemented per surface.

    Both inputs are class-driven via the canonical report-tier split
    (:func:`report_tier_for_record`), never via a per-record ``is_tier_zero``
    flag:

    Both counts describe OPEN exposure, so a path whose status carries none is
    skipped — the same
    :func:`~adscan_internal.services.path_state.carries_client_exposure` filter
    the exposure score applies through ``_PROOF_WEIGHT``. Without it the posture
    score and the executive headline counted avenues the client's own
    configuration had closed, plus paths ADscan never had the surface to walk,
    and reported the sum as exposure demanding immediate attention.

    * ``paths_to_da`` — the **T1** count (``domain_breaker``): paths that reach
      full domain compromise. Counted per PATH, not deduplicated by
      source/target/relations: two distinct chains to the same target are two
      distinct ways in, and the score's path penalty is meant to reflect that.
    * ``tier0_exposed`` — the count of **distinct targets** reached by **T1,
      T1C or T2** paths (the canonical :data:`_TIER0_COMPROMISE_CLASSES`: full domain
      compromise plus Tier-0 host footholds). Targets are compared
      case-insensitively so ``ESSOS.LOCAL`` and ``essos.local`` are one asset.
      **T3 (``privileged_escalator``) is deliberately EXCLUDED**: control of a
      Tier-0 escalation group (Cert Publishers, DnsAdmins, the Operators) is a
      privilege-escalation enabler, not Tier-0 asset exposure on its own, and
      counting it inflates the penalty. Including T3 was exactly the defect that
      made LITE render 0/100 where PRO rendered 2/100 on the same workspace.

    Args:
        records: Attack-path records carrying ``compromise_class`` and
            ``target`` (as produced by ``get_attack_path_summaries`` and
            persisted into ``attack_paths_snapshot.json``).
        paths_to_da: Optional pre-resolved T1 count. Callers that already
            resolved it from the engine-stamped ``exposure_kpis`` ``path_axis``
            block (the PRO report's preferred source) pass it here so this
            helper does not recount; every other caller leaves it ``None`` and
            gets the records-derived T1 count. The two agree by construction —
            the caller must pass the block's ``exposure_total``, not its raw
            ``total``, or it reintroduces the no-exposure paths this filters.

    Returns:
        A ``(paths_to_da, tier0_exposed)`` tuple of non-negative ints.
    """
    tier0_targets: set[str] = set()
    t1_count = 0
    for record in records:
        if not isinstance(record, Mapping):
            continue
        if not carries_client_exposure(record.get("status")):
            continue
        tier = report_tier_for_record(record)
        if tier == "T1":
            t1_count += 1
        if tier in {"T1", "T1C", "T2"}:
            target = str(record.get("target") or "").strip().lower()
            if target:
                tier0_targets.add(target)
    resolved_da = t1_count if paths_to_da is None else max(0, int(paths_to_da))
    return resolved_da, len(tier0_targets)
