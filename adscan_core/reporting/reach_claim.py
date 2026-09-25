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
    "FULL_COMPROMISE_MAPPED_PHRASE",
    "FULL_COMPROMISE_VALIDATED_PHRASE",
    "full_compromise_reach_phrase",
    "reaches_full_compromise_clause",
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


def full_compromise_reach_phrase(end_to_end_proven: bool) -> str:
    """Return the noun phrase for "<principal> has ___" in a reach sentence.

    Args:
        end_to_end_proven: True when at least one route to full domain compromise
            was walked end to end (a proven full compromise), False when the
            reach is mapped with only its entry step proven.
    """
    return (
        FULL_COMPROMISE_VALIDATED_PHRASE
        if end_to_end_proven
        else FULL_COMPROMISE_MAPPED_PHRASE
    )


def reaches_full_compromise_clause(end_to_end_proven: bool, *, plural: bool) -> str:
    """Return the verb clause for "N of M attack path(s) ___".

    Proven: "reach(es) full domain compromise". Mapped-only: "whose route reaches
    full domain compromise (entry step proven, not walked end to end)".
    """
    verb = "reach" if plural else "reaches"
    if end_to_end_proven:
        return f"{verb} full domain compromise"
    # Mapped-only: the verb still agrees with the subject count
    # ("route reaches" / "routes reach").
    route = "routes reach" if plural else "route reaches"
    return f"whose {route} full domain compromise (entry step proven, not walked end to end)"


def tier0_reach_sub_phrase(end_to_end_proven: bool) -> str:
    """Return the exposure-figure sub-line clause for the Tier-0 reach share."""
    if end_to_end_proven:
        return "have a path to Tier 0, confirmed by configuration"
    return "have a mapped path to Tier 0 whose entry step is proven"
