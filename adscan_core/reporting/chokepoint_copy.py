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

#: The one honesty caveat for the affected-USER reach metric, stated ONCE where the
#: reach lead / highest-leverage panel is (never per row). The reach of a technique
#: is an EXPOSURE-SURFACE figure (how many users have a path THROUGH it), not a
#: protection figure: a user's exposure runs through several techniques, so closing
#: one reduces their exposure without necessarily removing it. Client-safe: no
#: em-dash, no percentage, human-grade English.
OVERLAP_CAVEAT: str = (
    "A user's exposure can run through several techniques, so closing one "
    "reduces their exposure without necessarily removing it. Full protection "
    "needs every technique on a user's paths closed, so work the ranked list."
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


def _reach_lead_sentence(
    reach_users: int | None,
    reach_total: int | None,
    reach_pct: float | None,
    *,
    executed: bool,
) -> str | None:
    """Return the affected-USER reach lead sentence, or ``None`` when unavailable.

    The LEAD metric of the prioritised-remediation surface (founder decision,
    Value-Equation grounded): a fix is framed first by how many of the client's
    people are EXPOSED via this technique, in their language and client-verifiable,
    above the attack-path count which stays as the secondary redundancy axis.

    The verb is deliberately SURFACE, never elimination. ``reach(technique)`` is
    the count of users who have a validated path that TRAVERSES this technique, an
    EXPOSURE-SURFACE figure, NOT a protection figure: because a user's exposure
    runs through several techniques, closing this one reduces their exposure
    without necessarily removing it (see :data:`OVERLAP_CAVEAT`). So the sentence
    reads "N of M affected users have a path through this technique", never
    "removes exposure for N users" / "protects N users".

    Returns ``None`` when the workspace carries no affected-user population
    (``reach_total`` falsy / reach args absent), so the caller degrades to the
    legacy path-count lead rather than printing "0 of 0 (0%)". The percentage is
    the ONE place a percentage is allowed on this surface, because it is
    client-verifiable ("we have ~2,500 users") and it is self-consistent by
    construction (numerator and denominator share one source). ``executed``
    qualifies the path as "validated" (the technique sits on a path ADscan ran end
    to end) versus a plain "path" otherwise, keeping the validated/theoretical
    honesty. No em-dash.
    """
    if not reach_total or reach_users is None or reach_pct is None:
        return None
    users_noun = "affected user" if reach_users == 1 else "affected users"
    have = "has" if reach_users == 1 else "have"
    qualifier = "a validated path" if executed else "a path"
    return (
        f"{reach_users:,} of {reach_total:,} {users_noun} {have} {qualifier} "
        f"through this technique ({reach_pct:g}%)."
    )


def reach_uniform_note(
    reach_pct: float,
    *,
    reach_users: int | None = None,
    reach_total: int | None = None,
) -> str:
    """Return the ONE sentence shown above the table when reach is uniform.

    On a bridged domain every ordinary account funnels through the same chains, so
    the affected-user reach of the fixes that carry a user path is the identical
    percentage (usually 100%). Repeating that number on every row ranks nothing and
    reads as filler. Stated ONCE here instead, this is the SECTION LEAD that carries
    the people stakes (the buyer's dream outcome, and client-verifiable against their
    own population), so the reader never has to infer it from a row.

    When the absolute affected-user population is passed (``reach_users`` /
    ``reach_total``), the lead NAMES it ("1,141 of 1,141 affected users (100%)") so
    the people number is unmistakable, states the real ordering rule the rows then
    follow (proven execution first, then attack paths broken), and appends the ONE
    :data:`OVERLAP_CAVEAT`: in the uniform case this lead is the single place the
    affected-user reach is stated, so the reduce-not-remove honesty rides here. The
    verb is SURFACE ("sit on an attack path that runs through"), never a protection
    claim.

    Called WITHOUT the population (legacy callers), it returns the percentage-only
    sentence, scoped to "the fixes that carry an ordinary-user path": some surfaced
    fixes reach zero ordinary users (their routes originate from computer or group
    footholds) and their rows say so plainly, so a blanket "every ordinary user
    funnels through the same chains" would contradict them. Client-safe: no em-dash,
    human-grade English; the single percentage is client-verifiable (their own
    population).
    """
    if reach_total:
        # Uniform reach: every fix reaches the same population, so reach_users and
        # reach_total coincide. A caller that carries only the denominator (the LITE
        # Start Here) still gets the named people-lead; the SAR passes both.
        if reach_users is None:
            reach_users = reach_total
        users_noun = "affected user" if reach_users == 1 else "affected users"
        return (
            f"{reach_users:,} of {reach_total:,} {users_noun} ({reach_pct:g}%) sit on "
            f"an attack path that runs through the techniques below, so the people at "
            f"stake are the same for every fix here. The fixes differ in how much of "
            f"your validated attack surface each one removes, and that is the order "
            f"below. {OVERLAP_CAVEAT}"
        )
    return (
        f"Ordinary-user exposure funnels through the same chains, so the fixes "
        f"that carry an ordinary-user path all reach the same share ({reach_pct:g}%). "
        f"Fixes below are ordered by proven execution first, then by how many "
        f"attack paths each one breaks."
    )


def _foothold_reach_sentence(paths_broken: int, *, executed: bool) -> str:
    """Return the honest lead for a fix no ordinary USER account runs through.

    A fix can break real attack paths while reaching 0% of ordinary users: its
    paths originate from computer or group footholds, not user accounts. Rendering
    "0% of users" beside "eliminates N paths" reads as a bug; this states the
    honest reason instead. Client-safe: no em-dash, no percentage.
    """
    routes_noun = "attack path" if paths_broken == 1 else "attack paths"
    verb = "closes" if executed else "would close"
    return (
        f"No ordinary user account runs through this technique; the "
        f"{paths_broken:,} {routes_noun} it {verb} originate from computer or "
        f"group footholds."
    )


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
    reach_users: int | None = None,
    reach_total: int | None = None,
    reach_pct: float | None = None,
    reach_is_uniform: bool = False,
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
    # Affected-USER reach LEAD: when the workspace carries a user population, the
    # card headlines the people EXPOSED via the top fix's technique (the buyer's
    # metric, a surface figure, not a protection claim), the percentage lives on
    # ``ratio``, and the attack-path count moves to the honest execution-stance
    # ``context`` line. Falls back to the path-count card below when no user
    # population is present, OR when reach is UNIFORM — a non-discriminating 100%
    # must not headline the highest-leverage card (the founder decision), so the
    # card leads with the proven aspect + attack-path count instead.
    if (
        reach_total
        and reach_users is not None
        and reach_pct is not None
        and not reach_is_uniform
    ):
        users_noun = "user" if reach_users == 1 else "users"
        big = f"{reach_users:,} of {reach_total:,} {users_noun}"
        ratio = f"{reach_pct:g}% of affected users have a path through the top fix"
        # "Across N of M attack path(s)": the noun agrees with the denominator M
        # (total_validated_paths), not the numerator N.
        if executed:
            ctx_noun = (
                "validated attack path"
                if total_validated_paths == 1
                else "validated attack paths"
            )
            context = (
                f"Across {top_paths_broken:,} of {total_validated_paths:,} "
                f"{ctx_noun} ADscan executed"
            )
        elif mapped:
            ctx_noun = (
                "mapped attack path"
                if total_validated_paths == 1
                else "mapped attack paths"
            )
            context = (
                f"Across {top_paths_broken:,} of {total_validated_paths:,} "
                f"{ctx_noun}, not yet executed"
            )
        else:
            ctx_noun = (
                "attack path" if total_validated_paths == 1 else "attack paths"
            )
            context = (
                f"Across {top_paths_broken:,} of {total_validated_paths:,} {ctx_noun}"
            )
        if bounded:
            context = f"{context} (among the routes we evaluated)"
        return {"big": big, "ratio": ratio, "context": context}

    # ``big`` leads with the bare count and a short noun so it never wraps at the
    # card's large display size; the qualifier ("validated" / "mapped") and the
    # honest execution stance live on the shorter ``ratio`` / ``context`` lines.
    if executed:
        big_noun = "path" if total_validated_paths == 1 else "paths"
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
            breadth_noun = "attack path" if total_mapped == 1 else "attack paths"
            context = (
                f"Executed end to end; breaks {mapped_breadth:,} of "
                f"{total_mapped:,} {breadth_noun} in total"
            )
    elif mapped:
        big_noun = "path" if total_validated_paths == 1 else "paths"
        ratio = "Top fix breaks mapped attack paths"
        context = "Mapped, not yet executed, closed by one fix"
    else:
        big_noun = "path" if total_validated_paths == 1 else "paths"
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
    proven_step: bool = False,
    proven_terminal: bool = False,
    mapped_breadth: int | None = None,
    total_mapped: int | None = None,
    reach_users: int | None = None,
    reach_total: int | None = None,
    reach_pct: float | None = None,
    reach_is_uniform: bool = False,
) -> str:
    """Return the per-item client line for a prioritised remediation.

    LEADS with the affected-USER reach when the workspace carries a user
    population (``reach_total`` > 0): "N of M affected users have a path through
    this technique (X%)", the EXPOSURE-SURFACE metric the buyer reads first (not a
    protection claim), followed by the attack-path count as the SECONDARY
    redundancy clause. Falls back to the path-count lead when no user population is
    present (an older snapshot). The percentage appears ONLY in the user-reach
    lead, where it is client-verifiable and self-consistent; the path clause below
    stays count-only.

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
        proven_step: The technique's OWN step was proven (a ``success`` step on a
            partial route) even though no route through it ran end to end. Only
            meaningful with ``mapped`` set: it replaces "ADscan has not yet
            executed" (which reads as "never run") with the honest partial-proof
            stance — ADscan executed the technique, the full routes stay mapped.
            The COUNT and denominator stay in the mapped register (the routes were
            not walked end to end), so it never manufactures an "N of 0".
        proven_terminal: Only meaningful with ``proven_step`` set. The technique
            was proven as the domain-compromise TERMINAL step of one or more routes
            (its own step ran to completion, e.g. a DCSync that ends the route),
            NOT a mid-chain partial-only proof. The routes leading INTO it are
            credited to the ENTRY fix that opens them (the counting model), so this
            fix adds few incremental routes; the line then reads its proven terminal
            role as the win it is, never "mapped, not yet walked end to end", which
            would contradict a domain-compromise step ADscan actually executed.
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
        A single human-grade English line. No em-dash. A percentage appears only
        in the affected-user reach lead (when a user population is present);
        the path clause is count-only.
    """
    # Choose the LEAD clause honestly:
    #  * reach carried but this fix reaches 0 ordinary users -> the foothold lead
    #    ("no ordinary user account runs through this; the N paths originate from
    #    computer/group footholds"), never a bare "0%".
    #  * reach is UNIFORM across the top fixes -> drop the per-row reach lead
    #    entirely (it ranks nothing; the uniform note above the table states it
    #    once) and lead the row with the discriminating attack-path count.
    #  * reach VARIES -> the affected-user reach lead is the discriminator.
    if reach_total and reach_users == 0:
        lead: str | None = _foothold_reach_sentence(paths_broken, executed=executed)
    elif reach_is_uniform:
        lead = None
    else:
        lead = _reach_lead_sentence(
            reach_users, reach_total, reach_pct, executed=executed
        )
    # The noun in "N of M attack path(s)" agrees with the DENOMINATOR M (the
    # total in scope), not with N: "1 of 2 validated attack paths", not "...
    # attack path". Pluralize on total_validated_paths / total_mapped.
    if executed:
        noun = (
            "validated attack path"
            if total_validated_paths == 1
            else "validated attack paths"
        )
        line = (
            f"Eliminates {paths_broken:,} of {total_validated_paths:,} {noun} "
            f"ADscan executed."
        )
        # Show the broader "N of <total_mapped> in total" figure on EVERY executed
        # row, unless it is byte-for-byte the same claim as the validated figure
        # (same count AND same denominator) — so a proven fix always carries BOTH
        # its validated share and its all-status share, and two proven rows never
        # read with inconsistent detail (one with the "/total", one without). The
        # only suppression is a genuine duplicate: executed count == mapped breadth
        # AND executed total == mapped total.
        if (
            mapped_breadth is not None
            and total_mapped is not None
            and (mapped_breadth, total_mapped) != (paths_broken, total_validated_paths)
        ):
            breadth_noun = "attack path" if total_mapped == 1 else "attack paths"
            line = (
                f"Eliminates {paths_broken:,} of {total_validated_paths:,} {noun} "
                f"ADscan executed, and {mapped_breadth:,} of {total_mapped:,} "
                f"{breadth_noun} in total."
            )
        return f"{lead} {line}" if lead else line
    if mapped:
        noun = (
            "mapped attack path"
            if total_validated_paths == 1
            else "mapped attack paths"
        )
        if proven_step and proven_terminal:
            # The technique was proven as the domain-compromise TERMINAL step (e.g. a
            # DCSync that ends the route). The routes leading into it are credited to
            # the ENTRY fix that opens them above, so removing this technique closes
            # only the incremental routes it does not already terminate. It must read
            # its proven terminal role as the win it is, never "mapped, not yet
            # walked" (which would deny a domain-compromise step ADscan executed).
            extra_noun = "attack path" if total_validated_paths == 1 else "attack paths"
            line = (
                f"ADscan proved this technique as the step that reaches domain "
                f"compromise. The routes leading into it are credited to the fix that "
                f"opens them above, so removing it here closes a further "
                f"{paths_broken:,} of {total_validated_paths:,} {extra_noun}."
            )
        elif proven_step:
            # The technique's own step was PROVEN on a partial route, so the line
            # must never read "not yet executed" (which means "never run"): ADscan
            # DID run this technique. What stays mapped is the FULL route it sits
            # on, so the count keeps the mapped register and the wording states the
            # honest partial proof.
            line = (
                f"Would eliminate {paths_broken:,} of {total_validated_paths:,} "
                f"{noun}. ADscan executed this technique; the routes it sits on are "
                f"mapped, not yet walked end to end."
            )
        else:
            line = (
                f"Would eliminate {paths_broken:,} of {total_validated_paths:,} {noun} "
                f"ADscan has not yet executed."
            )
        return f"{lead} {line}" if lead else line
    noun = "attack path" if total_validated_paths == 1 else "attack paths"
    line = f"Eliminates {paths_broken:,} of {total_validated_paths:,} {noun}."
    return f"{lead} {line}" if lead else line


def remediation_start_here_headline(
    *,
    top_paths_broken: int,
    total_validated_paths: int,
    bounded: bool,
    mapped: bool = False,
    reach_users: int | None = None,
    reach_total: int | None = None,
    reach_pct: float | None = None,
    reach_is_uniform: bool = False,
) -> str:
    """Return the "Start here" lead sentence for the remediation section.

    LEADS with the affected-USER reach when the workspace carries a user
    population: the top fix's technique is on a path for N of M affected users
    (X%) (a surface figure, not a protection claim), and the attack-path count
    follows as the secondary axis, then the one :data:`OVERLAP_CAVEAT` sentence.
    Falls back to the path-count lead when no user population is present (an older
    snapshot).

    The execution claim is honest: when nothing in scope was executed end to end
    (every path is theoretical), ``mapped`` must be set so the lead speaks of
    MAPPED paths, never "executed" — the same "validated, not estimated"
    discipline as :func:`remediation_item_line`. When bounded, a caveat qualifies
    the claim to the routes ADscan evaluated.

    Args:
        top_paths_broken: How many paths the top fixes break, in the register of
            ``mapped`` (the executed count by default, the mapped count when
            ``mapped`` is set).
        total_validated_paths: The denominator, in the same register.
        bounded: Whether route discovery was bounded or sampled.
        mapped: Nothing in scope was executed end to end, so the lead may not
            claim execution and speaks of MAPPED paths instead.
        reach_users: Distinct affected users with a path through the top fix's
            technique.
        reach_total: The domain affected-user denominator.
        reach_pct: ``reach_users`` as a percentage of ``reach_total``.

    Returns:
        A single human-grade English sentence. No em-dash. A percentage appears
        only in the affected-user reach lead (when a user population is present).
    """
    stance = "we mapped" if mapped else "we executed"
    # When reach is UNIFORM (every top fix reaches the same share of users), the
    # per-fix reach lead ranks nothing — the uniform note above the table states
    # it once. The headline then leads with the REAL ordering rule: proven
    # execution first, then attack paths broken. Fall through to the path-count
    # lead below (skipping the reach lead) for exactly that reason.
    if reach_is_uniform:
        reach_total = None
    if reach_total and reach_users is not None and reach_pct is not None:
        users_noun = "user" if reach_users == 1 else "users"
        # SURFACE wording, never elimination: the top fix's technique sits on a
        # path for these users, it does not on its own protect them (see
        # OVERLAP_CAVEAT, appended once below). The path-count clause stays honest.
        path_phrase = "a mapped path" if mapped else "a validated path"
        lead = (
            f"Start here: your top fix's technique is on {path_phrase} for "
            f"{reach_users:,} of {reach_total:,} affected {users_noun} "
            f"({reach_pct:g}%), and these fixes break the most attack paths "
            f"{stance} against your domain "
            f"({top_paths_broken:,} of {total_validated_paths:,})"
        )
        if bounded:
            lead = f"{lead}, among the routes we evaluated"
        # The overlap caveat is stated ONCE, here at the reach lead (the SSOT),
        # never per row.
        return f"{lead}. {OVERLAP_CAVEAT}"

    lead = (
        f"Start here: these fixes break the most attack paths {stance} "
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
