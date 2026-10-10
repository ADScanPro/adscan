"""Privilege-tier tokens and the ONE seam that words them for a client.

Axis 1 of the nomenclature standard is the tier a principal or asset IS
GRANTED, and it has exactly four values plus the honest absence of one. This
module owns the TOKENS (the machine identity a persisted record carries), their
ORDER, and the provider seam that resolves a token to its client-facing label.

WHY THE LABEL ARRIVES THROUGH A PROVIDER
----------------------------------------
``compromise_class.privilege_tier_label`` is the single owner of the wording,
and it lives in ``adscan_internal`` where the tier classifier lives. This module
is dependency-light on purpose, because the web backend and the appliance import
the reporting projections, so it cannot reach the classifier itself. The layer
that CAN installs the resolver here (``compromise_class.install_privilege_tier_label_provider``),
mirroring the ``set_finding_catalog_provider`` seam.

The default makes no claim: an unwired consumer resolves "" and renders no tier
badge rather than a wrong one. A second local copy of the label map was written
once for the endpoint-defense block and had already drifted on the day it was
written ("Tier 2" against the SSOT's "Tier 2: Standard"), which would have put
a different badge on the same tier in two documents. Do not add another.

THE FIFTH TOKEN IS NOT A TIER
-----------------------------
:data:`TIER_TOKEN_UNGRADED` is the explicit absence of a grade, for an account
or asset the assessment could not place: no graph node, or a node carrying no
stamp. It is deliberately NOT routed through the tier label owner, whose
unknown-token default is "Tier 2: Standard" — reporting an ungraded account as a
standard one is the understatement the Exposure-Validation doctrine forbids, and
is the whole reason this token exists. It words itself as "Not graded", the same
wording the endpoint-defense surfaces already use for an ungraded host.
"""

from __future__ import annotations

from typing import Any

#: The four real :class:`compromise_class.PrivilegeTier` values, as the tokens
#: a persisted record carries. Mirrors ``PrivilegeTier.value``; a test asserts
#: the two never diverge.
TIER_TOKEN_TIER0_DIRECT = "tier0_direct"
TIER_TOKEN_TIER0_ESCALATION_CAPABLE = "tier0_escalation_capable"
TIER_TOKEN_TIER1 = "tier1"
TIER_TOKEN_TIER2 = "tier2"

#: Not a tier: the declared absence of a grade. See the module docstring.
TIER_TOKEN_UNGRADED = "ungraded"

#: The client-facing wording for :data:`TIER_TOKEN_UNGRADED`.
UNGRADED_TIER_LABEL = "Not graded"

#: The containment boundary's own name, for a figure that rolls the two Tier 0
#: tokens together (a headline count, a cover stat). It is the boundary, not a
#: :class:`PrivilegeTier`, so it is not the label owner's business.
TIER0_ROLLUP_LABEL = "Tier 0"

#: Every token a tier-segmented record may carry, worst first: the segment that
#: decides the engagement leads, and the declared absence sits last because it
#: is a gap to close rather than a severity.
PRIVILEGE_TIER_TOKEN_ORDER: tuple[str, ...] = (
    TIER_TOKEN_TIER0_DIRECT,
    TIER_TOKEN_TIER0_ESCALATION_CAPABLE,
    TIER_TOKEN_TIER1,
    TIER_TOKEN_TIER2,
    TIER_TOKEN_UNGRADED,
)

#: Ordering ranks for the four real tier tokens, highest criticality first.
#: Mirrors ``compromise_class.PrivilegeTier.rank`` (which this module cannot
#: import), and a test asserts the two never diverge. Only the ORDER lives here;
#: the LABEL does not.
TIER_RANK: dict[str, int] = {
    TIER_TOKEN_TIER0_DIRECT: 0,
    TIER_TOKEN_TIER0_ESCALATION_CAPABLE: 1,
    TIER_TOKEN_TIER1: 2,
    TIER_TOKEN_TIER2: 3,
}

#: Tier 0 by the stamped label, mirroring
#: ``compromise_class.node_is_tier0_by_stamped_label``.
TIER0_TOKENS = frozenset(
    {TIER_TOKEN_TIER0_DIRECT, TIER_TOKEN_TIER0_ESCALATION_CAPABLE}
)

#: Resolves a tier token to its client-facing label. Installed by the layer that
#: can import the tier SSOT; the default makes no claim.
_TIER_LABEL_PROVIDER: Any = None


def set_privilege_tier_label_provider(provider: Any) -> None:
    """Install the resolver for a tier token's client-facing label.

    Called once by the layer that can import ``compromise_class``. Passing
    ``None`` restores the default, which returns "" for every real tier token.
    """
    global _TIER_LABEL_PROVIDER
    _TIER_LABEL_PROVIDER = provider


def normalize_privilege_tier_token(tier: Any) -> str:
    """Return a tier token in canonical form, or "" when there is none."""
    token = str(tier or "").strip().lower()
    if token in PRIVILEGE_TIER_TOKEN_ORDER:
        return token
    return ""


def privilege_tier_label_for_token(tier: Any) -> str:
    """The label for a tier token, or "" when it cannot be resolved.

    ``ungraded`` words itself (the label owner would call it Tier 2, which is
    the understatement this token exists to prevent). Empty for an absent token
    or an unwired provider: inventing a tier would assert a criticality nothing
    observed supports. Never raises, because a label is never worth failing a
    report over.
    """
    token = str(tier or "").strip().lower()
    if not token:
        return ""
    if token == TIER_TOKEN_UNGRADED:
        return UNGRADED_TIER_LABEL
    if _TIER_LABEL_PROVIDER is None:
        return ""
    try:
        return str(_TIER_LABEL_PROVIDER(token) or "")
    except Exception:  # noqa: BLE001 - a missing badge beats a failed report
        return ""


def privilege_tier_token_rank(tier: Any) -> int:
    """Sort rank for a tier token; an unknown or ungraded token sorts LAST.

    Last, never first: an ungraded account must not be ordered as though it were
    the most critical, and it must not be ordered as a standard one either, so
    it sits outside the graded ranks entirely.
    """
    return TIER_RANK.get(str(tier or "").strip().lower(), len(TIER_RANK) + 1)


def token_is_tier0(tier: Any) -> bool:
    """Whether a tier token places its subject inside the Tier 0 boundary."""
    return str(tier or "").strip().lower() in TIER0_TOKENS


def highest_privilege_tier_token(tokens: Any) -> str:
    """The most critical token among ``tokens``, or "" when there is none.

    A graded token always wins over an ungraded one, so a group holding one
    Tier-0 account and several ungraded ones reads by the Tier-0 account.
    """
    best = ""
    best_rank = len(TIER_RANK) + 2
    for raw in tokens or ():
        token = str(raw or "").strip().lower()
        if not token:
            continue
        rank = privilege_tier_token_rank(token)
        if rank < best_rank:
            best, best_rank = token, rank
    return best


__all__ = [
    "PRIVILEGE_TIER_TOKEN_ORDER",
    "TIER0_ROLLUP_LABEL",
    "TIER0_TOKENS",
    "TIER_RANK",
    "TIER_TOKEN_TIER0_DIRECT",
    "TIER_TOKEN_TIER0_ESCALATION_CAPABLE",
    "TIER_TOKEN_TIER1",
    "TIER_TOKEN_TIER2",
    "TIER_TOKEN_UNGRADED",
    "UNGRADED_TIER_LABEL",
    "highest_privilege_tier_token",
    "normalize_privilege_tier_token",
    "privilege_tier_label_for_token",
    "privilege_tier_token_rank",
    "set_privilege_tier_label_provider",
    "token_is_tier0",
]
