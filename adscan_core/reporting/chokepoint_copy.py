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

from adscan_core.reporting.principal_display import humanize_principal_for_prose

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


#: Well-known principals a client cannot action as a structural fix. A node
#: total-cut that lands on one of these ("remove BUILTIN\\Administrators",
#: "delete Everyone") is not a remediation, so it is structural noise in a
#: client-facing choke-point section (the node total-cut is a durability signal,
#: not a lead). The SID set is primary and precise; the name set is the fallback
#: when only a display label is in hand. These SIDs are Microsoft constants and
#: never change, so a small self-contained set keeps this module engine-free.
NONACTIONABLE_WELLKNOWN_CHOKE_SIDS: frozenset[str] = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-7",  # Anonymous Logon
        "S-1-5-11",  # Authenticated Users
        "S-1-5-32-544",  # BUILTIN\Administrators
        "S-1-5-32-545",  # BUILTIN\Users
        "S-1-5-32-546",  # BUILTIN\Guests
    }
)

#: Non-actionable well-known RIDs on a domain SID (S-1-5-21-<auth>-<RID>).
_NONACTIONABLE_WELLKNOWN_RIDS: frozenset[str] = frozenset({"501", "513", "515"})

NONACTIONABLE_WELLKNOWN_CHOKE_NAMES: frozenset[str] = frozenset(
    {
        "everyone",
        "authenticated users",
        "anonymous",
        "anonymous logon",
        "guest",
        "guests",
        "users",
        "administrators",
        "builtin\\administrators",
        "builtin\\users",
        "builtin\\guests",
        "domain users",
        "domain computers",
    }
)

#: Severity label -> ordering rank (lower = more severe), so structural node
#: chokes and identity chokes order together on one scale.
CHOKE_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "info": 4,
}

_CHOKE_SEVERITY_LABELS: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational",
    "informational": "Informational",
}


def is_nonactionable_structural_choke(
    node_id: str | None, object_label: str | None
) -> bool:
    """Whether a node choke lands on a well-known principal a client cannot remove.

    Pure (``__future__``/typing only), so the PRO renderer, the LITE report and
    the web CTEM share ONE definition. Detected by well-known SID (precise: the
    named set, any ``S-1-5-32-*`` BUILTIN local group, and the non-actionable
    domain RIDs 501/513/515) and by canonical display name (fallback).
    Generalized over every well-known principal, not a per-engagement filter.
    """
    raw = str(node_id or "").strip()
    bare = raw.split("name:", 1)[-1].strip() if raw.lower().startswith("name:") else raw
    sid = bare.upper()
    if sid in NONACTIONABLE_WELLKNOWN_CHOKE_SIDS:
        return True
    if sid.startswith("S-1-5-32-"):
        return True
    if sid.startswith("S-1-5-21-"):
        rid = sid.rsplit("-", 1)[-1]
        if rid in _NONACTIONABLE_WELLKNOWN_RIDS:
            return True
    short = str(object_label or "").strip().lower().split("@", 1)[0].strip()
    return short in NONACTIONABLE_WELLKNOWN_CHOKE_NAMES


def build_identity_choke_rows(identity_choke_points: object) -> list[dict]:
    """Build actionable choke rows from a per-domain identity-choke snapshot.

    An identity choke is a membership articulation that puts many accounts one
    step from a privileged group (e.g. ``DEV SUPPORT -> BACKUP OPERATORS``) — the
    kind of choke a client can actually fix, unlike a well-known node total-cut.
    Surfaces only the MATERIAL ones (critical/high) whose source is itself
    actionable. ``accounts_affected`` is how many accounts lose the exposure once
    the membership is corrected. Pure and shared, so the deliverable and the web
    CTEM select the same chokes.
    """
    if not isinstance(identity_choke_points, list):
        return []
    rows: list[dict] = []
    for cp in identity_choke_points:
        if not isinstance(cp, dict):
            continue
        sev = str(cp.get("severity") or "").strip().lower()
        rank = CHOKE_SEVERITY_ORDER.get(sev, 9)
        if rank > 1:  # material chokes only — critical / high
            continue
        src = str(cp.get("source_label") or "").strip()
        tgt = str(cp.get("target_label") or "").strip()
        if not src or not tgt:
            continue
        if is_nonactionable_structural_choke("", src):
            continue
        # The record stores labels RAW (shouting, e.g. ``DEV SUPPORT`` /
        # ``BACKUP OPERATORS``) by design — they are join-key data at persist time.
        # Humanize ON EMIT, at this shared render SSOT, so BOTH the PDF and the web
        # CTEM (which read these same rows) name the principal exactly as the rest
        # of the report does. ``source_kind`` / ``target_kind`` are stamped by the
        # classifier; pass them so a shouting GROUP reads as words, not lower-case.
        src_display = humanize_principal_for_prose(
            label=src, kind=str(cp.get("source_kind") or "")
        )
        tgt_display = humanize_principal_for_prose(
            label=tgt, kind=str(cp.get("target_kind") or "")
        )
        affected = 0
        for key in ("affected_user_count", "blast_radius"):
            try:
                candidate = int(cp.get(key) or 0)
            except (TypeError, ValueError):
                candidate = 0
            if candidate:
                affected = candidate
                break
        rows.append(
            {
                "object": f"{src_display} → {tgt_display}",
                "protected_target": tgt_display,
                "severity": _CHOKE_SEVERITY_LABELS.get(sev, sev.title() or "High"),
                "severity_rank": rank,
                "routes_severed": affected,
                "accounts_affected": affected,
                "kind": "identity",
                "_node_id": "",
            }
        )
    return rows


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
    mapped_breadth: int | None = None,
    total_mapped: int | None = None,
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
        # State the WIDER blast radius too when the fix also breaks theoretical
        # paths beyond the executed ones — so the headline card never reads
        # narrower than the Start-Here row it summarises (the Forest
        # "1 of 1 executed / 22 of 43 total" case).
        if (
            mapped_breadth is not None
            and total_mapped is not None
            and mapped_breadth > top_paths_broken
        ):
            breadth_noun = "attack path" if mapped_breadth == 1 else "attack paths"
            context = (
                f"Executed end to end; breaks {mapped_breadth:,} of "
                f"{total_mapped:,} {breadth_noun} in total"
            )
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
    mapped_breadth: int | None = None,
    total_mapped: int | None = None,
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
        mapped_breadth: For an ``executed`` row, the fix's TOTAL blast radius
            across all statuses (the technique's all-status ``paths_affected``).
            When it exceeds ``paths_broken`` — i.e. the fix also breaks
            theoretical paths beyond the executed ones — the line appends the
            broader count so the highest-leverage fix (few executed, many
            mapped) does not read as NARROWER than a lower row worded off its
            mapped count. Ignored when ``executed`` is not set, or when it does
            not exceed ``paths_broken`` (nothing wider to state).
        total_mapped: The denominator for ``mapped_breadth`` (the all-status
            total in scope). Required alongside ``mapped_breadth``.

    Returns:
        A single human-grade English sentence. No percentage, no em-dash.
    """
    if executed:
        noun = (
            "validated attack path" if paths_broken == 1 else "validated attack paths"
        )
        line = (
            f"Eliminates {paths_broken:,} of {total_validated_paths:,} {noun} "
            f"ADscan executed."
        )
        if (
            mapped_breadth is not None
            and total_mapped is not None
            and mapped_breadth > paths_broken
        ):
            breadth_noun = "attack path" if mapped_breadth == 1 else "attack paths"
            line = (
                f"Eliminates {paths_broken:,} of {total_validated_paths:,} {noun} "
                f"ADscan executed, and {mapped_breadth:,} of {total_mapped:,} "
                f"{breadth_noun} in total."
            )
        return line
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


def remediation_chain_note(tied_count: int) -> str:
    """Return the note for a "Start here" lead ranked entirely by one chain.

    When ADscan's validated attack paths in scope form a single kill chain,
    every fix on it eliminates the SAME path count — the item line above
    would otherwise repeat "Eliminates N of N validated attack paths" on
    every one of the leading rows, which reads as either a duplicate or a
    coincidence rather than the real reason: there is only one route, and
    each of these rows is a different place to cut it.

    Args:
        tied_count: How many leading rows share the identical paths-broken
            count (always >= 2 when this note is shown).

    Returns:
        A single human-grade English sentence naming the tie and pointing the
        client at the ordering rule this module applies in that case
        (cheapest fix first). No percentage, no em-dash.
    """
    return (
        f"The top {tied_count} fixes below sit on the same attack chain, so "
        f"each one alone breaks every path it covers. They are ordered by "
        f"how much effort each takes to apply, cheapest first."
    )
