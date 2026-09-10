"""Tier-descent attack-path prune — drop redundant "descends in tier" noise.

Design: ``docs/superpowers/specs/2026-09-09-tier-descent-path-prune-design.md``.

On a hub-heavy directory the per-principal attack-path set is dominated by paths
that peak at a high tier mid-path then DESCEND to a lower-tier terminal that adds
no reach — pure ACL fan-out noise (measured: ~93-94% of the non-Tier-0 paths on
Forest / a large corporate domain). This module deletes that noise WITHOUT losing
any real path.

Coverage is the red line. The naive descent test alone was MEASURED to prune 10
genuine GOAD highvalue paths (ESSOS$-like trust/machine terminals the raw node
tier under-ranks to Tier-2 but the pipeline correctly marks ``tierzero``). So a
path is deleted only when ALL of these hold:

1. **Descends** — the terminal ESAE tier is strictly lower than the max tier over
   ALL path nodes including transited intermediates (the mid-path peak).
2. **Terminal NOT record-protected** — the record's own ``is_tier_zero`` is False
   AND ``target_priority_class`` is not in ``{tierzero, highvalue}``. NEVER decide
   terminal importance from the raw node tier — always the record fields (they are
   already stamped by ``stamp_records_target_tier``). This is what protects ESSOS$
   and the 10 GOAD paths.
3. **Terminal NOT a pivot (Protection B)** — the path contains NO ``EdgeKind.AUTH``
   edge ANYWHERE (AdminTo / CanRDP / CanPSRemote / ExecuteDCOM / SQLAdmin /
   ReadLAPSPassword / HasSession), because only an access edge unlocks a post-ex
   credential/session pivot. Check ANYWHERE, not just the last edge: the engine
   auto-appends a DERIVED post-ex step (DumpLSA) after an AUTH edge, so the last
   edge is often DERIVED.
4. **Protection A** — never delete the LAST surviving path that transits a given
   Tier-0-direct / Tier-0-escalation-capable peak node for that source (keep one
   representative per transited peak per source).
5. **Per-source guard** — only prune a source's descending paths if that source
   has ≥1 non-descending path; if ALL descend, prune NOTHING for that source.

Flag-gated ``ADSCAN_ATTACK_PATHS_TIER_DESCENT_PRUNE`` (default OFF → passthrough,
byte-identical). Best-effort: on any predicate error the record passes through
(never dropped on error).
"""

from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.services.compromise_class import (
    PrivilegeTier,
    privilege_tier_for_node,
)
from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind

__all__ = ["apply_tier_descent_prune"]

_FLAG_ENV = "ADSCAN_ATTACK_PATHS_TIER_DESCENT_PRUNE"
_PROTECTED_PRIORITY_CLASSES = frozenset({"tierzero", "highvalue"})
_TIER0_PEAK_TIERS = frozenset(
    {PrivilegeTier.TIER0_DIRECT, PrivilegeTier.TIER0_ESCALATION_CAPABLE}
)


def _flag_enabled() -> bool:
    """Return whether the prune is enabled by env flag.

    Default ON (2026-09-09): validated on Forest with real memberships — coverage
    clean (0 real paths lost, ESSOS$/trust-account misclassification handled by
    Protection C), −93% descending-noise reduction. Reversible: set
    ``ADSCAN_ATTACK_PATHS_TIER_DESCENT_PRUNE=0`` to disable. (Only exercised on
    Forest so far among fixtures with real memberships; Potech's no-op was a
    fabricated-memberships data artifact, not a prune result — a large-domain
    live/synthetic-with-real-memberships run remains a good follow-up before wide
    reliance.)
    """
    return os.getenv(_FLAG_ENV, "1").strip().lower() in {"1", "true", "yes", "on"}


def _record_nodes(record: Mapping[str, Any]) -> list[str]:
    """Return the record's node labels (``nodes`` list of label strings)."""
    nodes = record.get("nodes")
    if not isinstance(nodes, list):
        return []
    return [str(n).strip() for n in nodes if str(n).strip()]


def _record_relations(record: Mapping[str, Any]) -> list[str]:
    """Return the record's edge relations (``relations`` or legacy ``rels``)."""
    rels = record.get("relations")
    if not isinstance(rels, list):
        rels = record.get("rels")
    if not isinstance(rels, list):
        return []
    return [str(r).strip() for r in rels if str(r).strip()]


def _tier_for_label(
    label: str, label_to_node: Mapping[str, Any]
) -> PrivilegeTier:
    """Return the raw ESAE tier of a node label via ``privilege_tier_for_node``."""
    node = label_to_node.get(label)
    return privilege_tier_for_node(node if isinstance(node, Mapping) else None)


def _path_descends(
    record: Mapping[str, Any], label_to_node: Mapping[str, Any]
) -> bool:
    """Return True when the terminal tier is strictly below the mid-path peak.

    Descent = terminal ESAE tier (via ``privilege_tier_for_node``) strictly lower
    than the max ESAE tier over ALL path nodes including transited intermediates.
    """
    nodes = _record_nodes(record)
    if len(nodes) < 2:
        return False
    tiers = [_tier_for_label(n, label_to_node) for n in nodes]
    peak_rank = max(t.rank for t in tiers)
    terminal_rank = tiers[-1].rank
    return terminal_rank < peak_rank


def _is_machine_or_trust_terminal(
    label: str, label_to_node: Mapping[str, Any]
) -> bool:
    """Return True when the terminal is a machine / trust account (Protection C).

    A ``$``-suffixed sAMAccountName or a ``Computer``-kind node is a machine or
    cross-domain trust account. Control of one is never plain descending noise —
    it is a host foothold or a cross-domain pivot — so it must be protected even
    when the ``target=all`` record under-marks it as a plain ``pivot`` (the ESSOS$
    misclassification: the same terminal the highvalue pipeline marks ``tierzero``
    is stamped ``pivot`` in ``target=all`` mode). This reads the mode-independent
    NODE, not the mode-dependent record class, so a trust/machine reach is never
    dropped as noise regardless of how the current target mode ranked it.
    """
    node = label_to_node.get(label)
    if isinstance(node, Mapping) and str(node.get("kind") or "").strip().lower() == "computer":
        return True
    # ``$``-suffixed account: strip the realm qualifier (``NAME$@REALM``) first.
    local = label.split("@", 1)[0].strip()
    return local.endswith("$")


def _path_terminal_record_protected(
    record: Mapping[str, Any], label_to_node: Mapping[str, Any]
) -> bool:
    """Return True when the terminal must never be pruned (protection #2 + C).

    Protection #2 reads the RECORD's stamped fields (``is_tier_zero`` /
    ``target_priority_class``), never the raw node tier — the raw tier under-ranks
    trust/machine accounts (ESSOS$) that the highvalue pipeline marks ``tierzero``.
    Protection C additionally protects any machine / trust-account terminal
    (``$``-suffixed or ``Computer``-kind), because the ``target=all`` record can
    under-mark such a terminal as a plain ``pivot`` even though controlling it is a
    real host/cross-domain pivot — so it is never dropped as descending noise.
    """
    if bool(record.get("is_tier_zero")):
        return True
    priority = str(record.get("target_priority_class") or "").strip().lower()
    if priority in _PROTECTED_PRIORITY_CLASSES:
        return True
    nodes = _record_nodes(record)
    terminal = nodes[-1] if nodes else str(record.get("target") or "")
    return _is_machine_or_trust_terminal(terminal, label_to_node)


def _path_has_auth_edge(record: Mapping[str, Any]) -> bool:
    """Return True when ANY edge in the path is an ``EdgeKind.AUTH`` access edge.

    Protection B: check ANYWHERE, not just the last edge — the engine appends a
    DERIVED post-ex step (DumpLSA) after an AUTH edge, so the last edge is often
    DERIVED even though the pivot is real.
    """
    for relation in _record_relations(record):
        if classify_edge_kind(relation) is EdgeKind.AUTH:
            return True
    return False


def _path_transited_tier0_peaks(
    record: Mapping[str, Any], label_to_node: Mapping[str, Any]
) -> set[str]:
    """Return the labels of Tier-0 (direct or escalation-capable) nodes on the path.

    Protection A input: the set of transited Tier-0 peak nodes for which at least
    one representative path must survive per source.
    """
    peaks: set[str] = set()
    for label in _record_nodes(record):
        if _tier_for_label(label, label_to_node) in _TIER0_PEAK_TIERS:
            peaks.add(label)
    return peaks


def _is_prune_candidate(
    record: Mapping[str, Any], label_to_node: Mapping[str, Any]
) -> bool:
    """Return True when a record is a raw prune candidate (descends, unprotected, no pivot).

    Composes predicates #1–#3. Protection A (peak-preservation) and the per-source
    guard are applied by the pass, NOT here — this is the per-record admissibility.
    """
    if not _path_descends(record, label_to_node):
        return False
    if _path_terminal_record_protected(record, label_to_node):
        return False
    if _path_has_auth_edge(record):
        return False
    return True


def apply_tier_descent_prune(
    records: list[dict[str, Any]],
    label_to_node: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Delete redundant tier-descent noise from *records* (flag-gated, coverage-safe).

    Groups records by source and, within each source, deletes a descending +
    unprotected + non-pivot path UNLESS it is the last surviving carrier of a
    transited Tier-0 peak for that source (Protection A). A source with NO
    non-descending path is left untouched (the per-source guard). Flag OFF →
    returns ``records`` unchanged. Best-effort: on any error the input is returned
    unmodified (never drops a real path on a predicate failure).

    Args:
        records: The display records at the post-DFS seam (each has ``nodes``,
            ``relations`` and the stamped ``is_tier_zero`` / ``target_priority_class``).
        label_to_node: The label→node index for resolving per-node ESAE tiers.

    Returns:
        The filtered record list (order preserved), or the original list when the
        flag is off or an error occurs.
    """
    if not _flag_enabled() or not records:
        return records

    try:
        return _prune_impl(records, label_to_node)
    except Exception as exc:  # pragma: no cover - defensive best-effort
        print_exception(exception=exc)
        return records


def _prune_impl(
    records: list[dict[str, Any]],
    label_to_node: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Coverage-safe prune body (see :func:`apply_tier_descent_prune`)."""
    # Group record indices by source label (nodes[0]) — the per-source unit.
    by_source: dict[str, list[int]] = defaultdict(list)
    for idx, record in enumerate(records):
        nodes = _record_nodes(record)
        source = nodes[0] if nodes else str(record.get("source") or "")
        by_source[source].append(idx)

    drop: set[int] = set()
    for indices in by_source.values():
        # Per-source guard: only prune if the source has ≥1 NON-descending path.
        has_non_descending = any(
            not _path_descends(records[i], label_to_node) for i in indices
        )
        if not has_non_descending:
            continue

        # Protection A: seed the set of Tier-0 peaks already represented by paths
        # that will DEFINITELY survive this source (non-candidates: non-descending,
        # record-protected, or pivots). Any candidate whose transited peaks are all
        # covered is prunable; otherwise it stays as the representative and its peaks
        # become covered for the rest of the source's candidates.
        represented_peaks: set[str] = set()
        candidate_indices: list[int] = []
        for i in indices:
            if _is_prune_candidate(records[i], label_to_node):
                candidate_indices.append(i)
            else:
                represented_peaks |= _path_transited_tier0_peaks(
                    records[i], label_to_node
                )

        for i in candidate_indices:
            peaks = _path_transited_tier0_peaks(records[i], label_to_node)
            if peaks and not peaks.issubset(represented_peaks):
                # This candidate carries a peak not yet represented — keep it as the
                # representative; mark its peaks covered for later candidates.
                represented_peaks |= peaks
                continue
            drop.add(i)

    if not drop:
        return records

    kept = [record for idx, record in enumerate(records) if idx not in drop]
    print_info_debug(
        f"[local-pipeline] tier-descent prune: removed {len(drop)} "
        f"descending-noise path(s) -> {len(kept)} remain"
    )
    return kept
