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
    domain_affected_user_total,
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
    tagged_paths = iter_domain_tagged_paths(domains_data)
    techniques = compute_technique_priorities(
        tagged_paths,
        total_paths=total_paths,
    )
    # The affected-USER reach denominator: the union of every path's
    # ``meta.affected_users`` across the whole domain set. Numerator and
    # denominator share the ONE source, so reach_pct is self-consistent — never
    # crossed with the tier2_exposure / affected_principal populations.
    reach_total = domain_affected_user_total(tagged_paths)

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
                # The LEAD remediation metric: distinct affected USERS exposed via
                # this technique — users with a path that traverses it (a set union
                # over the technique's paths, never summed across techniques), with
                # the domain-union denominator and a self-consistent percentage.
                # This is a surface figure (not a protection claim) the client
                # reads first (their people, in their language), above the
                # attack-path count which stays as the secondary redundancy axis.
                "reach_users": entry.reach_users,
                "reach_total": reach_total,
                "reach_pct": (
                    min(round(entry.reach_users / max(reach_total, 1) * 100, 1), 100.0)
                ),
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
    # any fix that breaks an EXECUTED attack path leads the mapped-only fixes. The
    # LEAD discriminator after the proven prefix is the number of ATTACK PATHS each
    # fix breaks (the honest sort the section title now states), because affected-
    # user reach is uniform on a bridged domain (every ordinary account funnels
    # through the same chains) and so ranks nothing there. Affected-user reach is
    # the TIE-BREAK at an equal path count, which keeps a 100%-user fix above a
    # 0%-user (computer/group-foothold) fix when they break the same number of
    # paths. The impact score is the final deterministic tie-break. The proven-
    # first key is a SORT prefix only; it never touches ``impact_score`` (other
    # report figures read it).
    results.sort(
        key=lambda x: (
            0 if x["exploited_paths"] > 0 else 1,
            -x["exploited_paths"],
            -x["paths_affected"],
            -x["reach_users"],
            -x["impact_score"],
        )
    )

    _break_ties_by_remediation_effort(results)

    for i, item in enumerate(results, 1):
        item["rank"] = i

    return results


def _break_ties_by_remediation_effort(results: list[dict[str, Any]]) -> None:
    """Re-order a self-cancelling tie run by remediation effort, cheapest first.

    A single LINEAR attack chain (every fix on it severs the exact same set of
    paths) is a genuine tie the ``impact_score`` ranking cannot break with any
    signal a client can act on: severity/blast/status are identical across the
    chain by construction, so the leading rows end up in an order that reads
    as arbitrary — and the per-row copy repeats "Eliminates N of N validated
    attack paths" on every one of them with zero differentiation.

    This scans the ALREADY-sorted list for maximal RUNS of adjacent rows that
    share the exact same ``(exploited_paths, paths_affected)`` pair — the
    literal "breaks the identical count" condition — and, ONLY within such a
    run, re-orders by ascending remediation complexity (:data:`_COMPLEXITY_RANK`,
    lowest effort first) with ``impact_score`` as the final tie-break for
    determinism. A run of length 1 (the overwhelming majority of reports,
    where different fixes break different numbers of paths) is untouched, so
    this never changes ordering outside the exact self-cancelling case.
    Mutates ``results`` in place; ``rank`` is stamped by the caller afterward.

    Each row that participates in a run of length > 1 is stamped
    ``chain_tie_size`` (the run's length) so the render model can surface the
    "these fixes are on the same chain" note (:func:`adscan_core.reporting.
    chokepoint_copy.remediation_chain_note`) without recomputing this scan.
    """
    i = 0
    n = len(results)
    while i < n:
        j = i + 1
        while j < n and (
            results[j]["exploited_paths"] == results[i]["exploited_paths"]
            and results[j]["paths_affected"] == results[i]["paths_affected"]
        ):
            j += 1
        run_length = j - i
        if run_length > 1:
            results[i:j] = sorted(
                results[i:j],
                key=lambda x: (
                    -_COMPLEXITY_RANK.get(x["complexity"], 2),
                    -x["impact_score"],
                ),
            )
            for item in results[i:j]:
                item["chain_tie_size"] = run_length
        i = j


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
        A JSON/Jinja-safe render model ``{headline, chain_note,
        total_executed_paths, total_mapped_paths, rows, kpi_card}`` where each
        row is ``{label, item_line, badge, badge_label, paths_affected,
        exploited_paths, executed, chain_tie_size, reach_*}`` PLUS the
        per-technique remediation guidance carried for the merged section
        (``mitre_id``, ``mitre_name``, ``complexity``, ``complexity_label``,
        ``remediation_effort``, ``remediation_steps``, ``can_mitigate``,
        ``paths_pct``, ``affected_principals``). ``chain_note`` is a
        client-safe sentence explaining a self-cancelling tie (see
        :func:`_break_ties_by_remediation_effort`), or ``""`` when the
        leading rows are not tied. Returns ``None`` when there are no
        priorities to lead with.
    """
    from adscan_core.reporting.chokepoint_copy import (  # noqa: PLC0415
        STRUCTURAL_CHOKE_BADGE,
        is_structural_choke,
        reach_uniform_note,
        remediation_chain_note,
        remediation_item_line,
        remediation_kpi_lines,
        remediation_start_here_headline,
    )

    if not priorities:
        return None

    card_map = node_cardinality if isinstance(node_cardinality, dict) else {}

    # Uniform-reach detection over the fixes that touch ANY ordinary user. On a
    # bridged domain every ordinary account funnels through the same chains, so
    # each such fix reaches the identical share (usually 100%). When that share is
    # a single value across two or more fixes it discriminates nothing, so the
    # per-row reach lead is dropped in favour of the attack-path count and the
    # uniform share is stated ONCE above the table. A varying reach keeps the
    # per-row reach lead. Fixes reaching 0 ordinary users (computer/group
    # footholds) are excluded from the uniformity test and always get their own
    # honest foothold wording.
    _reach_shares = {
        round(float(entry.get("reach_pct") or 0.0), 1)
        for entry in priorities
        if isinstance(entry, dict) and int(entry.get("reach_users") or 0) > 0
    }
    _reach_bearing_fixes = sum(
        1
        for entry in priorities
        if isinstance(entry, dict) and int(entry.get("reach_users") or 0) > 0
    )
    reach_is_uniform = _reach_bearing_fixes >= 2 and len(_reach_shares) == 1
    uniform_reach_pct = next(iter(_reach_shares)) if reach_is_uniform else 0.0
    # A representative reach-bearing fix supplies the ABSOLUTE affected-user
    # population for the uniform section lead (the reach is uniform, so any
    # reach-bearing fix carries the same numbers; the #1 row may be a 0-reach
    # foothold, so pick the first fix that actually reaches users).
    _uniform_reach_users = 0
    _uniform_reach_total = 0
    if reach_is_uniform:
        for entry in priorities:
            if isinstance(entry, dict) and int(entry.get("reach_users") or 0) > 0:
                _uniform_reach_users = int(entry.get("reach_users") or 0)
                _uniform_reach_total = int(entry.get("reach_total") or 0)
                break

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
        try:
            row_reach_users = int(entry.get("reach_users") or 0)
        except (TypeError, ValueError):
            row_reach_users = 0
        try:
            row_reach_total = int(entry.get("reach_total") or 0)
        except (TypeError, ValueError):
            row_reach_total = 0
        try:
            row_reach_pct = float(entry.get("reach_pct") or 0.0)
        except (TypeError, ValueError):
            row_reach_pct = 0.0
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
            # For an executed row, also state the broader mapped blast radius so
            # a high-leverage fix (few executed, many mapped) does not read as
            # narrower than a lower mapped row (MED-1).
            mapped_breadth=paths_affected if row_executed else None,
            total_mapped=total_mapped_paths if row_executed else None,
            # The affected-USER reach LEAD: when the workspace carries a user
            # population (reach_total > 0), the line leads with "N of M affected
            # users have a path through this technique (X%)" (a surface figure, not
            # a protection claim) and the path count becomes the secondary clause.
            # A workspace without the population degrades to the legacy path-count
            # lead.
            reach_users=row_reach_users,
            reach_total=row_reach_total,
            reach_pct=row_reach_pct,
            reach_is_uniform=reach_is_uniform,
        )
        choke_id = _resolve_row_choke_identifier(entry.get("top_choke_point"))
        badge = bool(is_structural_choke(choke_id, card_map))
        try:
            chain_tie_size = int(entry.get("chain_tie_size") or 0)
        except (TypeError, ValueError):
            chain_tie_size = 0
        rows.append(
            {
                "label": str(entry.get("action_label") or entry.get("action") or ""),
                "item_line": item_line,
                "badge": badge,
                "badge_label": STRUCTURAL_CHOKE_BADGE if badge else "",
                "paths_affected": paths_affected,
                "exploited_paths": exploited_paths,
                "executed": row_executed,
                "chain_tie_size": chain_tie_size,
                "reach_users": row_reach_users,
                "reach_total": row_reach_total,
                "reach_pct": row_reach_pct,
                # Per-technique remediation guidance, carried onto the row so the
                # merged remediation section (IA v2: ONE ranked list) can attach
                # the fix detail to each row instead of a second ranked table.
                # Sourced from the SAME ranking entry, so nothing is recomputed.
                "mitre_id": entry.get("mitre_id") or "",
                "mitre_name": entry.get("mitre_name") or "",
                "complexity": str(entry.get("complexity") or ""),
                "complexity_label": str(entry.get("complexity_label") or ""),
                "remediation_effort": str(entry.get("remediation_effort") or ""),
                "remediation_steps": list(entry.get("remediation_steps") or []),
                "can_mitigate": bool(entry.get("can_mitigate", True)),
                "paths_pct": entry.get("paths_pct"),
                "affected_principals": int(entry.get("affected_principals") or 0),
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
    top_reach_users = int(rows[0].get("reach_users") or 0)
    top_reach_total = int(rows[0].get("reach_total") or 0)
    top_reach_pct = float(rows[0].get("reach_pct") or 0.0)
    headline = remediation_start_here_headline(
        top_paths_broken=top_paths_broken,
        total_validated_paths=top_denominator,
        bounded=bounded,
        mapped=not top_executed,
        reach_users=top_reach_users,
        reach_total=top_reach_total,
        reach_pct=top_reach_pct,
        reach_is_uniform=reach_is_uniform,
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
        # For an executed top fix, also carry the broader all-status blast radius
        # so the headline card states BOTH breadths (executed + total), matching
        # the Start-Here row it summarises and never reading narrower than it.
        mapped_breadth=rows[0]["paths_affected"] if top_executed else None,
        total_mapped=total_mapped_paths if top_executed else None,
        # The affected-USER reach LEAD for the KPI card (falls back to the path
        # count when the workspace carries no user population, or when reach is
        # uniform — a non-discriminating 100% must not headline the card).
        reach_users=top_reach_users,
        reach_total=top_reach_total,
        reach_pct=top_reach_pct,
        reach_is_uniform=reach_is_uniform,
    )
    # A single linear attack chain leaves the leading rows tied on the exact
    # same paths-broken count — the ranking already reorders that tie by
    # remediation effort (cheapest first, see ``_break_ties_by_remediation_
    # effort``), and this note tells the client WHY, instead of letting the
    # per-row copy repeat an identical count with no explanation.
    chain_note = (
        remediation_chain_note(rows[0]["chain_tie_size"])
        if rows[0]["chain_tie_size"] > 1
        else ""
    )
    return {
        "headline": headline,
        "chain_note": chain_note,
        # When affected-user reach is uniform across the fixes, the ONE sentence a
        # renderer shows above the table instead of repeating the same percentage
        # per row (empty string otherwise). ``reach_is_uniform`` lets a renderer
        # switch the impact column header from a reach lead to a paths lead.
        "reach_is_uniform": reach_is_uniform,
        "reach_uniform_note": (
            reach_uniform_note(
                uniform_reach_pct,
                reach_users=_uniform_reach_users,
                reach_total=_uniform_reach_total,
            )
            if reach_is_uniform
            else ""
        ),
        "total_executed_paths": total_executed_paths,
        "total_mapped_paths": total_mapped_paths,
        "rows": rows,
        "kpi_card": {
            # The NAMED fix the card is about — the #1 row's technique label — so
            # the hero can say WHICH fix is the highest-confidence one, not just a
            # bare count. The order is proven-executed first, so the #1 is the
            # highest-CONFIDENCE (proven in this environment) fix, not the widest.
            "label": str(rows[0].get("label") or ""),
            "big": kpi_card["big"],
            "ratio": kpi_card["ratio"],
            "context": kpi_card["context"],
            "top_paths_broken": int(top_paths_broken),
            "total_validated_paths": int(top_denominator),
            "executed": bool(top_executed),
            "reach_users": int(top_reach_users),
            "reach_total": int(top_reach_total),
            "reach_pct": float(top_reach_pct),
        },
    }
