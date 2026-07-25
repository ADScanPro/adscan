"""Client-presentation ordering for attack paths — PROVEN-first.

The compute/operator ordering (:func:`build_path_execution_priority_key`) is
tuned for the pentester driving execution: it leads with the most-actionable
next step, which places theoretical / graph-only paths ahead of an
already-proven one. That is correct at the operator console but backwards in a
CLIENT deliverable — the buyer pays for CERTAINTY, so a PROVEN compromise must
lead the client-facing attack-path list (the PDF report and the web path list),
then partially-validated, then theoretical / attempted.

This module is the single source of truth for that presentation ordering. It is
applied ONLY at the client-render boundary; every compute-order call site is
left untouched (the operator/CLI order does not change).

Order key, most-valuable first:

1. **Proof tier** — proven → partially validated → everything else. "Proven" is
   membership in the status-vocabulary SSOT
   :data:`path_state._PROVEN_STATUSES` (``success`` / ``exploited`` /
   ``domain_compromised``) — imported from the lean leaf so this ordering
   module keeps a minimal appliance-backend closure;
   ``exposure_score_service`` re-exports the same name. NEVER test
   ``status == "exploited"``: an
   end-to-end executed domain-compromise path is keyed ``domain_compromised``
   and a per-step success is keyed ``success`` — a bare-literal test silently
   drops both from the proven tier.
2. **Compromise reach** (axis 2) — ``domain_breaker`` > ``tier0_foothold`` >
   ``privileged_escalator`` > ``compromise_enabler``, reusing the canonical
   :class:`CompromiseClass` values (never a parallel taxonomy).
3. The canonical execution-priority key
   (:func:`build_path_priority_key`) as the deterministic tiebreak — it already
   encodes target criticality (Tier-0-direct / domain-object before
   escalation-capable), terminal semantics, effort, and length.
"""

from __future__ import annotations

from typing import Any

from adscan_internal.services.attack_step_support_registry import (
    build_path_priority_key,
)
from adscan_internal.services.compromise_class import CompromiseClass
from adscan_internal.services.path_state import _PROVEN_STATUSES

# Proof tiers (most-valuable first). Kept as module constants so the sort key is
# self-documenting and a future reader cannot mis-order the tiers by accident.
_PROOF_TIER_PROVEN = 0
_PROOF_TIER_PARTIAL = 1
_PROOF_TIER_UNPROVEN = 2

# Sub-order within a proof tier: by compromise reach (axis 2). Reuses the
# canonical CompromiseClass values — do NOT hand-roll a parallel taxonomy.
_COMPROMISE_REACH_RANK: dict[str, int] = {
    CompromiseClass.DOMAIN_BREAKER.value: 0,
    CompromiseClass.TIER0_FOOTHOLD.value: 1,
    CompromiseClass.PRIVILEGED_ESCALATOR.value: 2,
    CompromiseClass.COMPROMISE_ENABLER.value: 3,
    CompromiseClass.UNAUTHENTICATED_PRINCIPAL.value: 4,
    CompromiseClass.NONE.value: 5,
}
_REACH_RANK_DEFAULT = 6


def _proof_tier(record: dict[str, Any]) -> int:
    """Return the proof tier for one path record (proven=0, partial=1, else=2)."""
    status = str(record.get("status") or "").strip().lower()
    if status in _PROVEN_STATUSES:
        return _PROOF_TIER_PROVEN
    if status == "partial":
        return _PROOF_TIER_PARTIAL
    return _PROOF_TIER_UNPROVEN


def _reach_rank(record: dict[str, Any]) -> int:
    """Return the compromise-reach sub-rank for one path record."""
    return _COMPROMISE_REACH_RANK.get(
        str(record.get("compromise_class") or "").strip().lower(),
        _REACH_RANK_DEFAULT,
    )


def client_presentation_sort_key(record: dict[str, Any]) -> tuple:
    """Return the PROVEN-first client-presentation sort key for one path record.

    Args:
        record: A single attack-path summary dict (carries ``status`` and,
            for live records, an engine-stamped ``compromise_class``).

    Returns:
        A tuple ``(proof_tier, reach_rank, *execution_priority_key)`` that sorts
        proven paths first, then partially-validated, then the rest — with the
        canonical execution-priority key as the deterministic tiebreak.
    """
    return (
        _proof_tier(record),
        _reach_rank(record),
        *build_path_priority_key(record),
    )


def order_paths_for_client_presentation(
    paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return ``paths`` ordered PROVEN-first for a client deliverable.

    Pure and non-destructive (returns a new list; the input is not mutated).
    Non-dict entries (never produced by the engine, but tolerated defensively)
    are preserved and sorted to the end rather than dropped or raising.

    Args:
        paths: The client-facing attack-path records to order.

    Returns:
        A new list ordered for the PDF report / web client path list.
    """
    return sorted(
        list(paths or []),
        key=lambda p: client_presentation_sort_key(p)
        if isinstance(p, dict)
        else (_PROOF_TIER_UNPROVEN + 1, _REACH_RANK_DEFAULT + 1),
    )
