"""Reach-claim wording — the SSOT both tiers share so they cannot overclaim apart.

A path counted as reaching full domain compromise is not necessarily one ADscan
WALKED end to end. The report may know only that the ROUTE exists in the graph and
that its ENTRY step is proven, with the onward chain still theoretical. Wording it
as "a validated path to full domain compromise" then overclaims proof — and worse,
the free (LITE) and paid (PRO) documents drifted apart on exactly this sentence:
the PRO executive was careful ("a mapped path ... whose entry step is proven") while
the LITE headline dropped the qualifier and read "a validated path to full domain
compromise" for the same partial-only workspace. A client who sees the honest
version free and the overclaim after paying loses trust in every other number.

Both tiers now resolve the phrase HERE, gated on one boolean — whether any route to
full domain compromise was actually walked end to end — so the two can never diverge
again. ``adscan_core`` is importable by both the LITE renderer and the PRO renderer.
"""

from __future__ import annotations

__all__ = [
    "awaiting_approval_cause",
    "FULL_COMPROMISE_MAPPED_PHRASE",
    "FULL_COMPROMISE_VALIDATED_PHRASE",
    "full_compromise_reach_phrase",
    "no_tier0_asset_reach_statement",
    "reaches_full_compromise_clause",
    "tier0_asset_reach_population_note",
    "tier0_reach_sub_phrase",
]

#: Used when at least one route to full domain compromise was WALKED end to end.
#: NOTE: this is a REACH-population phrase ("N accounts have ___"), and that
#: population is larger than the routes ADscan actually executed — so it must NOT
#: say "validated". The word "validated" is reserved for the separate execution
#: count ("M routes executed end to end"), or a reach phrase reading "N have a
#: validated path" collides with "M validated end to end" and overclaims proof on
#: the theoretical majority. The reach is worded as CONFIRMED BY CONFIGURATION
#: instead — naming what the confirmation rests on (the directory's configuration),
#: so a bare "confirmed" cannot be misread as "executed"; whether a given route was
#: executed is the stronger, separate claim.
FULL_COMPROMISE_VALIDATED_PHRASE = "a path to full domain compromise, confirmed by configuration"

#: Used when the route reaches full domain compromise but was NOT walked end to
#: end — only its entry step is proven. Never claims execution it cannot stand
#: behind, and never under-claims the proven entry either.
FULL_COMPROMISE_MAPPED_PHRASE = (
    "a mapped path to full domain compromise whose entry step is proven"
)


#: How far an unproven route was executed, and why the rest did not run. Tokens
#: are the ``compromise_verdict`` vocabulary (``REACH_*`` and the
#: ``NOT_EXECUTED_*`` reasons), repeated here as literals so this leaf keeps no
#: import. ``None`` evidence is the historical reading: entry step proven.
_EVIDENCE_ENTRY_PROVEN = "entry_proven"
_EVIDENCE_ATTEMPTED = "attempted"
_EVIDENCE_MAPPED = "mapped"
_REASON_OPERATOR = "operator_required"
_REASON_EXCLUDED = "excluded_by_scan_policy"
_REASON_DECLINED = "operator_declined"
_REASON_OUTSIDE_SCOPE = "outside_engagement_scope"


def awaiting_approval_cause(wait_seconds: int = 0) -> str:
    """Why an approval was not given, from the recorded decision.

    A relayed request that timed out recorded how long it waited (the step note
    ``awaiting_timeout_seconds``): an operator was connected and did not answer
    in time. Without a recorded wait nobody was there to ask. Minutes are
    rounded like the step label (``execution.awaiting_approval_label``), so the
    route sentence and the step it stopped at say the same thing.
    """
    try:
        seconds = int(wait_seconds or 0)
    except (TypeError, ValueError):
        seconds = 0
    if seconds > 0:
        minutes = max(1, round(seconds / 60))
        unit = "minute" if minutes == 1 else "minutes"
        return f"no answer came within {minutes} {unit}"
    return "no operator was present to decide"


def _not_executed_tail(reason: str, awaiting_wait_seconds: int = 0) -> str:
    """Why a mapped route did not run, as a trailing clause (no leading comma).

    The four reasons keep their own words (``compromise_verdict``): a step the
    policy excludes, an approval nobody gave, an operator's "no", and a step
    outside the engagement scope. The approval nobody gave names what happened
    (:func:`awaiting_approval_cause`).
    """
    if reason == _REASON_OPERATOR:
        return f"awaiting approval because {awaiting_approval_cause(awaiting_wait_seconds)}"
    if reason == _REASON_EXCLUDED:
        return "not executed because your scan policy excludes a step"
    if reason == _REASON_DECLINED:
        return "not executed because the operator chose not to run it"
    if reason == _REASON_OUTSIDE_SCOPE:
        return "not executed because a step on it is outside the engagement scope"
    return "not executed in this assessment"


def full_compromise_reach_phrase(
    end_to_end_proven: bool,
    *,
    evidence: str | None = None,
    reason: str = "",
    awaiting_wait_seconds: int = 0,
) -> str:
    """Return the noun phrase for "<principal> has ___" in a reach sentence.

    Args:
        end_to_end_proven: True when at least one route to full domain compromise
            was walked end to end (a proven full compromise).
        evidence: How far the strongest unproven route was executed
            (``entry_proven`` / ``attempted`` / ``mapped``). ``None`` keeps the
            historical entry-step reading. A route nobody executed must pass
            ``mapped``, or the phrase claims a proven entry step that never ran.
        reason: Why mapped routes did not execute (``operator_required``,
            ``excluded_by_scan_policy`` or ``""``).
    """
    if end_to_end_proven:
        return FULL_COMPROMISE_VALIDATED_PHRASE
    if evidence == _EVIDENCE_ATTEMPTED:
        return "a mapped path to full domain compromise that was attempted and did not complete"
    if evidence == _EVIDENCE_MAPPED:
        return (
            "a mapped path to full domain compromise, "
            f"{_not_executed_tail(reason, awaiting_wait_seconds)}"
        )
    return FULL_COMPROMISE_MAPPED_PHRASE


def reaches_full_compromise_clause(
    end_to_end_proven: bool,
    *,
    plural: bool,
    evidence: str | None = None,
    reason: str = "",
    entry_proven_routes: int = 0,
    mapped_routes: int = 0,
    awaiting_wait_seconds: int = 0,
) -> str:
    """Return the verb clause for "N of M attack path(s) ___".

    ``entry_proven_routes`` / ``mapped_routes`` are the per-route split the
    verdict SSOT holds (``CompromiseVerdict.entry_proven`` / ``.not_executed``).
    When routes of BOTH kinds exist, the clause counts each instead of stating
    one reading for all of them: "entry step proven" was printed for seven routes
    of which the report itself marked six as theoretical.

    Proven: "reach(es) full domain compromise". Otherwise "whose route reaches
    full domain compromise (...)", where the parenthesis states how far it was
    executed: entry step proven, attempted, or mapped with the reason it did
    not run (see :func:`full_compromise_reach_phrase`).
    """
    verb = "reach" if plural else "reaches"
    if end_to_end_proven:
        return f"{verb} full domain compromise"
    # The verb still agrees with the subject count ("route reaches" / "routes reach").
    route = "routes reach" if plural else "route reaches"
    if evidence == _EVIDENCE_ATTEMPTED:
        note = "attempted, did not complete"
    elif evidence == _EVIDENCE_ENTRY_PROVEN and entry_proven_routes > 0 and mapped_routes > 0:
        note = (
            f"{entry_proven_routes} with the entry step proven, "
            f"{mapped_routes} mapped and not executed"
        )
    elif evidence == _EVIDENCE_MAPPED:
        note = f"mapped, {_not_executed_tail(reason, awaiting_wait_seconds)}"
    else:
        note = "entry step proven, not walked end to end"
    return f"whose {route} full domain compromise ({note})"


def tier0_reach_sub_phrase(
    end_to_end_proven: bool,
    *,
    evidence: str | None = None,
    reason: str = "",
    awaiting_wait_seconds: int = 0,
) -> str:
    """Return the exposure-figure sub-line clause for the Tier-0 reach share."""
    if end_to_end_proven:
        return "have a path to Tier 0, confirmed by configuration"
    if evidence == _EVIDENCE_ATTEMPTED:
        return "have a mapped path to Tier 0 that was attempted and did not complete"
    if evidence == _EVIDENCE_MAPPED:
        return (
            "have a mapped path to Tier 0, "
            f"{_not_executed_tail(reason, awaiting_wait_seconds)}"
        )
    return "have a mapped path to Tier 0 whose entry step is proven"


def tier0_asset_reach_population_note(domain_user_count: int) -> str:
    """Return the note naming WHAT the Tier-0-asset reach figure counts.

    The report prints two account figures within a page of each other and they
    count different populations by design: this one spans every enabled domain
    account in scope, while the per-account exposure figures count only the
    ordinary accounts that hold a route. It also counts only the routes that land
    on a Tier 0 host or the domain object, so a route stopping at a Tier 0 group
    sits outside it. Read side by side with nothing joining them, a zero here
    above a "the whole population is exposed" sentence reads as the report
    contradicting itself, which costs more credibility than the finding buys.

    Both figures stay exactly as computed. This note states each one's boundary so
    a reader can hold the two at once. Layout-neutral on purpose (no "above" or
    "below"), so LITE, the PRO deliverable and the web CTEM can place it anywhere.

    Args:
        domain_user_count: The enabled domain accounts the figure spans.
    """
    return (
        f"Measured across all {domain_user_count:,} enabled domain accounts in "
        "scope, administrative accounts included. It counts only the routes that "
        "land on a Tier 0 host or the domain object itself: a route that stops at "
        "a Tier 0 group is carried under Tier 0 group takeover in the compromise "
        "reach breakdown and is outside this figure. The per-account exposure "
        "figures in this report count a smaller group, the ordinary accounts that "
        "hold at least one route."
    )


def no_tier0_asset_reach_statement() -> str:
    """Return the honest line for "no account reaches a Tier 0 asset at all".

    The reach figure can legitimately be zero while the directory still carries
    exposure, when every mapped route stops at a Tier 0 group. The sub-line that
    reads "all Tier 0 reach is foothold-only" then describes reach that does not
    exist, so this states the absence directly and points at where the exposure
    this directory does carry is reported.
    """
    return (
        "No account reaches a Tier 0 host or the domain object on any mapped "
        "route. The exposure this directory carries is reported under Tier 0 "
        "group takeover in the compromise reach breakdown."
    )
