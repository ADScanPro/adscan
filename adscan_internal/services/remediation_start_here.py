"""Shared, LITE-safe "Start here" remediation model — ONE implementation.

The prioritised-remediation "Start here" lead is the E4 headline: fixes ordered
by how many of the client's attack paths each one breaks, weighting executed over
theoretical and remediation effort, reframed to COUNTS (never a percentage), with
the structural-choke durability badge attached as a decoration.

This module is the single source of truth for TWO things every tier needs:

- :func:`compute_remediation_priorities` — the impact-score-ordered technique
  ranking (path coverage first, then blast radius, choke severity, remediation
  cost, exploitation evidence). It reads the shared derivation
  (:func:`adscan_internal.services.technique_priority.compute_technique_priorities`)
  and projects it into the dict shape the report template, the web schema, and the
  persisted block consume — it never re-counts paths itself.
- :func:`build_remediation_start_here` — the pure render model
  (``{headline, rows, kpi_card, ...}``) built from a pre-ranked priorities list.

Both the PRO PDF render (``html_pdf_generator``) and the tier-shared stamp seam
(``chokepoint_cardinality.stamp_chokepoint_cardinality_for_domain``) call these,
so the PDF, the LITE report and the paid web CTEM lead with the SAME ranking and
the SAME copy with no duplicated logic. The PDF's behaviour is byte-identical: it
re-exports these symbols and passes the same inputs it always did.

Dependency-light by contract: it imports only ``adscan_core.reporting.chokepoint_copy``
(the copy SSOT) and ``adscan_internal.services.technique_priority`` (the shared
derivation) — never ``adscan_internal.pro``. So it is reachable from the stripped
LITE build and the appliance backend without pulling PRO reporting code.
"""

from __future__ import annotations

from typing import Any, Mapping

from adscan_internal.services.technique_priority import (
    compute_technique_priorities,
    iter_domain_tagged_paths,
)


#: Impact-score weights — how much each factor pushes a technique up the ranking.
#: Path coverage dominates (a fix that closes many routes leads), then blast
#: radius, severity, remediation ease, and exploitation evidence.
_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_COMPLEXITY_RANK = {"low": 4, "medium": 3, "high": 2, "very_high": 1}


def _impact_score(
    paths_affected: int,
    total_paths: int,
    max_blast: int,
    severity: str,
    complexity: str,
    status_weight: int,
) -> float:
    """Composite score: prioritises path coverage, then blast radius and severity."""
    pct = (paths_affected / max(total_paths, 1)) * 100
    sev = _SEVERITY_WEIGHT.get(severity, 1)
    cplx = _COMPLEXITY_RANK.get(complexity, 2)
    return round(
        pct * 4 + min(max_blast, 50) * 1.5 + sev * 5 + cplx * 2 + status_weight * 3, 1
    )


def compute_remediation_priorities(
    domains_data: list[dict[str, Any]],
    total_paths: int,
) -> list[dict[str, Any]]:
    """Return the attack techniques ranked by remediation value.

    Each entry is one distinct technique appearing across one or more attack
    paths, with the figures the deliverable prints beside it. Ordering is this
    document's own: an impact score that weighs path coverage first, then blast
    radius, choke-point severity, remediation cost and exploitation evidence.

    Structural steps never appear — a built-in group nesting is a fact of the
    directory, not a fix anyone can apply. That exclusion belongs to the shared
    derivation, so the free report, the paid one and the web cannot disagree
    about it.

    This is the ONE implementation of the ranking. The PRO reporting engine
    re-exports it (``remediation_engine.compute_attack_path_priorities``) so the
    PDF path is byte-identical, and the tier-shared stamp seam calls it directly
    so the persisted block the web reads carries the SAME order the PDF renders.

    Args:
        domains_data: Per-domain report records, each ``{"name", "attack_paths"}``.
            A path may carry either ``steps`` or ``relations``.
        total_paths: The path total the document prints, used as the denominator
            of every percentage here so the two always agree.

    Returns:
        Dicts in the shape the report template and the web remediation schema
        consume, highest impact first, each stamped with its 1-based ``rank``.
    """
    techniques = compute_technique_priorities(
        iter_domain_tagged_paths(domains_data),
        total_paths=total_paths,
    )

    results: list[dict[str, Any]] = []
    for entry in techniques:
        if entry.paths_affected == 0:
            continue
        score = _impact_score(
            paths_affected=entry.paths_affected,
            total_paths=total_paths,
            max_blast=entry.max_blast_radius,
            severity=entry.max_choke_point_severity,
            complexity=entry.remediation_complexity,
            status_weight=entry.max_status_weight,
        )
        results.append(
            {
                "action": entry.technique,
                "action_label": entry.label,
                "paths_affected": entry.paths_affected,
                "paths_pct": entry.share_pct,
                "domains": list(entry.domains),
                # Accounts whose paths use this technique. The table used to put
                # the top choke point's blast radius under an "Affected
                # Principals" heading, which on most workspaces prints "1
                # principal" on every row while the free report says 3 for the
                # same technique — the same label, two numbers, across the tier
                # boundary a client crosses when they pay.
                "affected_principals": entry.affected_principals,
                "max_blast": entry.max_blast_radius,
                "severity": entry.max_choke_point_severity,
                # The node this technique's top choke maps to (best-effort), so the
                # report can attach the structural-choke durability badge. It never
                # affects this ranking's order.
                "top_choke_point": entry.top_choke_point_id or None,
                "exploited_paths": entry.exploited_paths,
                "complexity": entry.remediation_complexity,
                "complexity_label": entry.remediation_complexity.replace(
                    "_", " "
                ).title(),
                "can_mitigate": entry.can_fully_mitigate,
                "remediation_effort": entry.remediation_effort,
                "remediation_steps": list(entry.remediation_steps[:5]),  # top 5 steps
                "mitre_id": entry.mitre_technique_id,
                "mitre_name": entry.mitre_technique_name,
                "impact_score": score,
            }
        )

    # Proven-first ordering (the "most first" ranking the section header promises):
    # any fix that breaks an EXECUTED attack path leads the mapped-only fixes, and
    # within each group the count is monotonically descending — proven rows by
    # executed count, then mapped rows by breadth. The proven-first key is a SORT
    # prefix only; it never touches ``impact_score`` (other report figures read it).
    results.sort(
        key=lambda x: (
            0 if x["exploited_paths"] > 0 else 1,
            -x["exploited_paths"],
            -x["impact_score"],
            -x["paths_affected"],
        )
    )
    for i, item in enumerate(results, 1):
        item["rank"] = i

    return results


def _resolve_row_choke_identifier(top_choke_point: Any) -> str | None:
    """Return the node identifier a priority row's remediation maps to, or None.

    The identifier is matched against the persisted node total-cut map for the
    structural-choke badge. A priority row's ``top_choke_point`` is best-effort:
    either an explicit identifier string, or the choke record the attack-graph
    classifier stamps on a path (which carries ``source_label`` — the object a
    client would fix — and a ``node_id`` on newer graphs). Preference order:
    an explicit ``node_id`` (matches ``top_node_chokepoints``), then the
    ``source_label`` (matches the label-keyed cardinality built from the
    persisted ranked chokes).
    """
    if not top_choke_point:
        return None
    if isinstance(top_choke_point, str):
        return top_choke_point.strip() or None
    if isinstance(top_choke_point, Mapping):
        for key in ("node_id", "source_label", "title"):
            value = top_choke_point.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def build_remediation_start_here(
    priorities: list[dict[str, Any]],
    *,
    total_executed_paths: int,
    total_mapped_paths: int,
    node_cardinality: dict[str, int],
    bounded: bool,
) -> dict[str, Any] | None:
    """Build the "Start here" render model led by the paths-broken ranking.

    The prioritised-remediation section leads with the technique ranking ADscan
    already computes (:func:`compute_remediation_priorities` /
    :func:`compute_technique_priorities`): fixes ordered by how many of the
    client's attack paths each one breaks, weighting executed over theoretical
    and remediation effort. This helper does NOT reorder that ranking — it
    consumes the rows in the order given, reframes the copy to counts (the copy
    SSOT), and attaches the structural-choke badge as an independent decoration.

    The displayed COUNT is scoped to what ADscan actually EXECUTED, so the
    "validated / executed" wording is literally true (the "validated, not
    estimated" wedge E4 defends). A row is worded off its EXECUTED count
    (``exploited_paths``) against the executed-path total; a row whose technique
    appears only in THEORETICAL paths (executed count 0) is worded as "mapped"
    off its all-status count against the mapped-path total, and never claims
    execution. The ORDER stays the impact-score ranking's order regardless — the
    count register is a display choice, never a reorder.

    The node total-cut ("choke cardinality") is no longer the lead. It survives
    only as the :data:`STRUCTURAL_CHOKE_BADGE` on a row whose remediation maps to
    a true articulation point (a node whose persisted total-cut cardinality is
    positive). The badge decorates; it never sets order — a row with the highest
    ``paths_affected`` but a zero / absent choke cardinality still ranks first and
    carries no badge.

    Pure/side-effect-free; the badge decision runs through the copy SSOT's
    :func:`adscan_core.reporting.chokepoint_copy.is_structural_choke`.

    Args:
        priorities: Rows from :func:`compute_remediation_priorities`, already
            ordered by the impact score. Each row carries ``action_label``,
            ``paths_affected`` (all statuses), ``exploited_paths`` (executed end
            to end) and (best-effort) ``top_choke_point``.
        total_executed_paths: The count of attack paths ADscan executed end to
            end in scope — the denominator for an executed-framed row.
        total_mapped_paths: The total attack paths in scope (all statuses) — the
            denominator for a theoretical-only ("mapped") row.
        node_cardinality: The persisted node total-cut map (choke identifier ->
            cut cardinality) used only for the badge decision. Keyed to match the
            row's ``top_choke_point`` identifier (a node id and/or node label).
        bounded: Whether route discovery was bounded or sampled, which caveats
            the headline.

    Returns:
        A JSON/Jinja-safe render model ``{headline, total_executed_paths,
        total_mapped_paths, rows, kpi_card}`` where each row is ``{label,
        item_line, badge, badge_label, paths_affected, exploited_paths,
        executed}``; or ``None`` when there are no priorities to lead with.
    """
    from adscan_core.reporting.chokepoint_copy import (  # noqa: PLC0415
        STRUCTURAL_CHOKE_BADGE,
        is_structural_choke,
        remediation_item_line,
        remediation_kpi_lines,
        remediation_start_here_headline,
    )

    if not priorities:
        return None

    card_map = node_cardinality if isinstance(node_cardinality, dict) else {}

    rows: list[dict[str, Any]] = []
    for entry in priorities:
        if not isinstance(entry, dict):
            continue
        try:
            paths_affected = int(entry.get("paths_affected") or 0)
        except (TypeError, ValueError):
            paths_affected = 0
        try:
            exploited_paths = int(entry.get("exploited_paths") or 0)
        except (TypeError, ValueError):
            exploited_paths = 0
        # The count is scoped to what was EXECUTED so "executed" is literally
        # true. A technique that only appears in theoretical paths (executed
        # count 0) is worded as "mapped" and never claims execution.
        row_executed = exploited_paths > 0
        item_line = remediation_item_line(
            paths_broken=exploited_paths if row_executed else paths_affected,
            total_validated_paths=(
                total_executed_paths if row_executed else total_mapped_paths
            ),
            executed=row_executed,
            mapped=not row_executed,
        )
        choke_id = _resolve_row_choke_identifier(entry.get("top_choke_point"))
        badge = bool(is_structural_choke(choke_id, card_map))
        rows.append(
            {
                "label": str(entry.get("action_label") or entry.get("action") or ""),
                "item_line": item_line,
                "badge": badge,
                "badge_label": STRUCTURAL_CHOKE_BADGE if badge else "",
                "paths_affected": paths_affected,
                "exploited_paths": exploited_paths,
                "executed": row_executed,
            }
        )

    if not rows:
        return None

    # The headline claims execution only when something in scope was executed. If
    # every top fix is theoretical (no executed paths at all), it speaks of MAPPED
    # paths so the lead never overstates.
    top_executed = rows[0]["executed"]
    top_paths_broken = (
        rows[0]["exploited_paths"] if top_executed else rows[0]["paths_affected"]
    )
    top_denominator = total_executed_paths if top_executed else total_mapped_paths
    headline = remediation_start_here_headline(
        top_paths_broken=top_paths_broken,
        total_validated_paths=top_denominator,
        bounded=bounded,
        mapped=not top_executed,
    )
    # KPI headline card — derived from the SAME top fix the section leads with (the
    # #1 paths-broken row), executed-framed, so the CISO's headline card and the
    # "Start here" section can never disagree. Counts only, no percentage headline;
    # the denominator is the EXECUTED-path total for an executed top fix (the
    # "validated" wedge is then literally true) and the mapped-path total only for
    # a theoretical-only top fix, worded "mapped, not yet executed". The node
    # total-cut (E3 cardinality) is no longer the KPI headline.
    kpi_card = remediation_kpi_lines(
        top_paths_broken=top_paths_broken,
        total_validated_paths=top_denominator,
        executed=top_executed,
        mapped=not top_executed,
        bounded=bounded,
    )
    return {
        "headline": headline,
        "total_executed_paths": total_executed_paths,
        "total_mapped_paths": total_mapped_paths,
        "rows": rows,
        "kpi_card": {
            "big": kpi_card["big"],
            "ratio": kpi_card["ratio"],
            "context": kpi_card["context"],
            "top_paths_broken": int(top_paths_broken),
            "total_validated_paths": int(top_denominator),
            "executed": bool(top_executed),
        },
    }
