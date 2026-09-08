"""Client-facing copy for choke-point remediation, authored once as an SSOT.

A choke point is a directory object whose removal severs the most validated
attack routes to high-value (Tier 0) targets. The PDF report, the KPI card, and
the web platform all present the same wording by reading these functions (the web
mirrors the strings as literals under a parity test).

The framing rule is deliberate and load-bearing:

- Lead with the RATIO: a tiny fix against a large, measured blast radius, with
  proof attached. Never a percentage headline.
- A percentage may appear ONLY as a subordinate context line, and ONLY as a
  share of *validated* exposure, never of total.
- When the underlying computation was bounded or sampled, the claim is caveated
  ("the highest-impact choke point among the routes we evaluated") rather than an
  unqualified "your #1 fix".

This module is intentionally import-light (only ``__future__`` + typing). It
belongs to the shared dependency-light ``adscan_core`` layer, so it must never
import ``adscan_internal`` or any engine code.
"""

from __future__ import annotations

from typing import Mapping

#: Client-facing badge for a ranked remediation item that maps to a true
#: structural choke point (an articulation point in the attack graph with no
#: alternate route). Removing it closes routes that have no other way around, so
#: the fix holds over time. The badge DECORATES a ranked item; it never sets
#: order. Client-safe by construction: no percentage, no em-dash (a hyphen is
#: fine), human-grade English.
STRUCTURAL_CHOKE_BADGE: str = "No alternate route - durable fix"

BOUNDED_CAVEAT: str = (
    "This is the highest-impact choke point among the routes we evaluated. "
    "Route discovery was bounded, so wider coverage may surface more."
)

#: How many ranked choke rows the "Start here" section surfaces. ONE cap shared by
#: every tier — the LITE report, the PRO deliverable, and the web CTEM panel all
#: read this so a client comparing the free report and the paid surface sees the
#: same number of choke rows. The section is a prioritised head, not a second full
#: table, so the value is deliberately short.
CHOKEPOINT_MAX_ROWS: int = 10


def is_structural_choke(
    choke_point_id: str | None, node_cardinality: Mapping[str, int]
) -> bool:
    """Return whether a choke point is a true structural articulation point.

    A ranked remediation item earns the :data:`STRUCTURAL_CHOKE_BADGE` only when
    the node it maps to has a positive total-cut cardinality in the persisted
    node-choke map — i.e. it is a real articulation point whose removal severs
    routes with no alternate path. A node absent from the map, or present with a
    zero / non-positive / non-integer value, is redundant and earns no badge.

    Pure: no I/O, no imports beyond ``__future__``/``typing``.

    Args:
        choke_point_id: The node id the remediation item maps to, or ``None``.
        node_cardinality: The persisted node total-cut map (node id -> cut
            cardinality). Values are coerced to ``int`` defensively; anything
            that will not coerce counts as no badge.

    Returns:
        ``True`` iff ``choke_point_id`` is a non-empty key present in
        ``node_cardinality`` whose value coerces to an int greater than 0.
    """
    if not choke_point_id:
        return False
    if choke_point_id not in node_cardinality:
        return False
    try:
        cardinality = int(node_cardinality[choke_point_id])
    except (TypeError, ValueError):
        return False
    return cardinality > 0


def _count_noun(count: int, singular: str, plural: str) -> str:
    """Return ``"{count:,} noun"`` with singular/plural agreement.

    Keeps thousands separators. The noun is ``singular`` only when ``count`` is
    exactly 1, otherwise ``plural`` (0 and negatives read plural, per English).
    """
    return f"{count:,} {singular if count == 1 else plural}"


def chokepoint_headline(
    *, top_object_count: int, routes_severed: int, bounded: bool
) -> str:
    """Return the headline for the choke-point finding.

    Leads with the objects-to-routes ratio and states the evidence stance. Never
    contains a percentage. When ``bounded`` is set, the absolute claim is
    replaced with an "among the routes we evaluated" qualification.

    Args:
        top_object_count: How many objects the client fixes.
        routes_severed: How many validated attack routes those fixes sever.
        bounded: Whether route discovery was bounded or sampled.

    Returns:
        A single human-grade English sentence group.
    """
    # Opener reads naturally at N==1 ("Fix this object", not "Fix this 1 object").
    if top_object_count == 1:
        opener = "Fix this object"
    else:
        opener = f"Fix these {top_object_count:,} objects"

    routes_phrase = _count_noun(
        routes_severed, "validated attack route", "validated attack routes"
    )

    if bounded:
        choke_points = "choke point" if top_object_count == 1 else "choke points"
        return (
            f"{opener} and you sever {routes_phrase} to your Tier 0. These are "
            f"the highest-impact {choke_points} among the routes we evaluated, so "
            f"wider coverage may surface more."
        )

    return (
        f"{opener} and you sever {routes_phrase} to your Tier 0. Validated, not "
        f"modeled. Everything else is downstream of these."
    )


def chokepoint_kpi_lines(
    *,
    top_object_count: int,
    routes_severed: int,
    validated_exposure_pct: int | None,
    bounded: bool,
) -> dict[str, str]:
    """Return the three KPI-card lines for the choke-point finding.

    Keys:
        big: the blast-radius number, no percentage.
        ratio: the objects-to-routes ratio, no percentage.
        context: the only line where a percentage may appear, always as a share
            of *validated* exposure. Omits the percentage gracefully when
            ``validated_exposure_pct`` is ``None``.

    Args:
        top_object_count: How many objects the client fixes.
        routes_severed: How many validated attack routes those fixes sever.
        validated_exposure_pct: Share of validated exposure removed, or ``None``.
        bounded: Whether route discovery was bounded or sampled.

    Returns:
        A dict with keys ``big``, ``ratio``, ``context``.
    """
    objects_phrase = _count_noun(top_object_count, "object", "objects")
    big_routes = _count_noun(routes_severed, "attack route", "attack routes")
    ratio_routes = _count_noun(routes_severed, "route", "routes")

    big = f"{big_routes} cut by fixing 1 object"
    ratio = f"{objects_phrase} → {ratio_routes}"

    if validated_exposure_pct is None:
        context_routes = _count_noun(
            routes_severed, "validated route", "validated routes"
        )
        context = f"{context_routes} to Tier 0 removed"
    else:
        context = f"{validated_exposure_pct}% of validated exposure removed"

    if bounded:
        context = f"{context} (among the routes we evaluated)"

    return {"big": big, "ratio": ratio, "context": context}


def remediation_kpi_lines(
    *,
    top_paths_broken: int,
    total_validated_paths: int,
    executed: bool,
    mapped: bool = False,
    bounded: bool = False,
) -> dict[str, str]:
    """Return the three KPI-card lines for the top prioritised remediation.

    This is the headline card the CISO reads first, and it is derived from the
    SAME top fix the "Start here" section leads with (the #1 row of the
    paths-broken ranking), so the card and the section can never state different
    numbers. It leads with COUNTS of the client's attack paths the top fix
    eliminates — never a percentage headline — consistent with
    :func:`remediation_item_line` and :func:`remediation_start_here_headline`.

    The "validated, not estimated" stance is load-bearing: the card only uses the
    word "validated" / "executed" when the count is of paths ADscan actually ran
    end to end. When the top fix touches only THEORETICAL paths, the card is
    worded as "mapped" and never claims execution.

    Keys:
        big: the primary count line ("N of M paths"), no percentage. Bare count
            plus a short noun so it never wraps at the card's display size.
        ratio: the qualifier line — states whether the count is of VALIDATED
            (executed) or MAPPED attack paths, honest per the stance. No
            percentage.
        context: a subordinate honest execution-stance line, caveated when
            discovery was bounded. No percentage.

    Args:
        top_paths_broken: How many paths the top fix eliminates, in the register
            of ``mapped`` (the executed count by default, the mapped count when
            ``mapped`` is set).
        total_validated_paths: The denominator, in the same register — the
            executed-path total for the executed stance, the mapped-path total
            for the mapped stance.
        executed: The top fix eliminates paths ADscan executed end to end.
        mapped: The top fix only touches theoretical (mapped, not executed)
            paths; the wording avoids any execution/validation claim. Ignored
            when ``executed`` is set.
        bounded: Whether route discovery was bounded or sampled.

    Returns:
        A dict with keys ``big``, ``ratio``, ``context``. No percentage, no
        em-dash.
    """
    # ``big`` leads with the bare count and a short noun so it never wraps at the
    # card's large display size; the qualifier ("validated" / "mapped") and the
    # honest execution stance live on the shorter ``ratio`` / ``context`` lines.
    if executed:
        big_noun = "path" if top_paths_broken == 1 else "paths"
        ratio = "Top fix breaks validated attack paths ADscan executed"
        context = "Executed end to end, closed by one fix"
    elif mapped:
        big_noun = "path" if top_paths_broken == 1 else "paths"
        ratio = "Top fix breaks mapped attack paths"
        context = "Mapped, not yet executed, closed by one fix"
    else:
        big_noun = "path" if top_paths_broken == 1 else "paths"
        ratio = "Top fix breaks attack paths in scope"
        context = "Closed by one fix"

    big = f"{top_paths_broken:,} of {total_validated_paths:,} {big_noun}"

    if bounded:
        context = f"{context} (among the routes we evaluated)"

    return {"big": big, "ratio": ratio, "context": context}


def remediation_item_line(
    *,
    paths_broken: int,
    total_validated_paths: int,
    executed: bool,
    mapped: bool = False,
) -> str:
    """Return the per-item client line for a prioritised remediation.

    States how many of the client's attack paths this one fix eliminates, framed
    as COUNTS, never a percentage. A percentage here would read as a competitor's
    modeled-exposure register.

    The stance is deliberate and load-bearing (the "validated, not estimated"
    wedge): the word only claims "validated" / "executed" when the count is of
    paths ADscan actually ran. A fix that only touches THEORETICAL paths must NOT
    borrow that word — it is worded as "mapped" and its count is stated against
    the mapped total, so the client is never told a route was executed that was
    only diagrammed.

    Args:
        paths_broken: How many attack paths this fix eliminates. When
            ``executed`` is set this is the executed/validated count; when
            ``mapped`` is set it is the mapped (theoretical) count.
        total_validated_paths: The denominator, in the SAME register as
            ``paths_broken`` — the executed-path total for the executed stance,
            the mapped-path total for the mapped stance.
        executed: The fix eliminates paths ADscan executed end to end. The
            wording says so with proof attached ("validated … ADscan executed").
        mapped: The fix only touches theoretical (mapped, not executed) paths.
            The wording avoids any execution/validation claim ("mapped attack
            paths ADscan has not yet executed"). Ignored when ``executed`` is
            set; the executed stance wins.

    Returns:
        A single human-grade English sentence. No percentage, no em-dash.
    """
    if executed:
        noun = (
            "validated attack path" if paths_broken == 1 else "validated attack paths"
        )
        return (
            f"Eliminates {paths_broken:,} of {total_validated_paths:,} {noun} "
            f"ADscan executed."
        )
    if mapped:
        noun = "mapped attack path" if paths_broken == 1 else "mapped attack paths"
        return (
            f"Would eliminate {paths_broken:,} of {total_validated_paths:,} {noun} "
            f"ADscan has not yet executed."
        )
    noun = "attack path" if paths_broken == 1 else "attack paths"
    return f"Eliminates {paths_broken:,} of {total_validated_paths:,} {noun}."


def remediation_start_here_headline(
    *,
    top_paths_broken: int,
    total_validated_paths: int,
    bounded: bool,
    mapped: bool = False,
) -> str:
    """Return the "Start here" lead sentence for the remediation section.

    Leads the prioritised-remediation section by pointing the client at the
    fixes that break the most attack paths ADscan executed against their domain.
    Counts only, never a percentage, and executed-framed (never modeled). When
    the underlying route discovery was bounded or sampled, a caveat qualifies the
    claim to the routes ADscan evaluated.

    The execution claim is honest: when nothing in scope was executed end to end
    (every path is theoretical), ``mapped`` must be set so the lead says the
    fixes break the most MAPPED paths, never "executed" — the same "validated,
    not estimated" discipline as :func:`remediation_item_line`.

    Args:
        top_paths_broken: How many paths the top fixes break, in the register of
            ``mapped`` (the executed count by default, the mapped count when
            ``mapped`` is set).
        total_validated_paths: The denominator, in the same register.
        bounded: Whether route discovery was bounded or sampled.
        mapped: Nothing in scope was executed end to end, so the lead may not
            claim execution and speaks of MAPPED paths instead.

    Returns:
        A single human-grade English sentence. No percentage, no em-dash.
    """
    if mapped:
        lead = (
            "Start here: these fixes break the most attack paths we mapped "
            "against your domain"
        )
    else:
        lead = (
            "Start here: these fixes break the most attack paths we executed "
            "against your domain"
        )
    if bounded:
        return (
            f"{lead}, among the routes we evaluated "
            f"({top_paths_broken:,} of {total_validated_paths:,})."
        )
    return f"{lead} ({top_paths_broken:,} of {total_validated_paths:,})."
