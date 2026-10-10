"""Client-facing wording for a privilege-tier verdict's BASIS and CONFIDENCE.

Axis 1 (the Privilege Tier a principal or asset IS GRANTED) is produced by the
tiering engine (``adscan_internal.services.compromise_class``), which stamps a
machine ``tier_basis`` on every non-trivial verdict recording WHICH signal
produced it. Tier 0 is deterministic (control-plane group membership / DC role);
Tier 1 and the Tier-2 corrections are inferred from server-role and administration
signals, because the Microsoft AD DS tier model states there is no canonical AD
attribute or group for Tier 1 ("the credential and the keyboard define the tier,
not the IP address").

This module is the single source of truth that turns the stamped machine basis
value into (1) the client-facing CONFIDENCE (``deterministic`` vs ``inferred``)
and (2) a client-safe, human-readable PHRASE explaining the verdict, so the PDF
report and the web CTEM present the SAME wording for the SAME asset. Per the
project rule, the translation happens at this authoring boundary: the web backend
reads these functions and forwards the already-translated strings, so the
frontend never re-implements the mapping.

Two hard authoring rules this file keeps:

- **No internal signal name leaks.** The machine basis values (``app_spn``,
  ``server_heuristic``, ``rds_downgrade`` …) are engine vocabulary and never reach
  a client. Every phrase below is plain English a CISO or auditor reads.
- **English only, no em-dash in client prose** (the phrases ship verbatim in the
  deliverable).

This module is intentionally import-light (only ``__future__`` + typing) and
belongs to the dependency-light ``adscan_core`` layer: it must never import
``adscan_internal`` or any engine code. It therefore keys on the stamped STRING
values; a structural test (``tests/unit/core/test_tier_basis_phrase.py``) imports
the ``TierBasis`` enum and asserts every ``.value`` is covered here, so the two
can never drift.
"""

from __future__ import annotations

from typing import NamedTuple

#: Client-facing confidence of a verdict read DIRECTLY from the directory.
CONFIDENCE_DETERMINISTIC = "deterministic"
#: Client-facing confidence of a verdict we INFERRED from role / admin signals.
CONFIDENCE_INFERRED = "inferred"

# The deterministic bases: the verdict was read from the directory (control-plane
# group membership / DC role / an observed Tier-0 control relationship), not
# inferred from a heuristic. Everything else is an inference the client can
# confirm or correct.
_DETERMINISTIC_BASES = frozenset({"tier0_group", "tier0_control"})

# Stamped machine basis value -> client-safe reason PHRASE (no "deterministic:" /
# "inferred:" prefix; that is prepended from the confidence). These keys MUST
# stay in lockstep with ``compromise_class.TierBasis`` (locked by a structural
# test). Plain English, no internal tool/signal names, no em-dash.
_BASIS_PHRASE: dict[str, str] = {
    "tier0_group": "control-plane group membership",
    "tier0_control": "holds control over a Tier 0 asset",
    "server_heuristic": "member server by operating-system role",
    "app_spn": "runs a line-of-business application server",
    "rds_downgrade": "multi-user session host where standard users log on interactively",
    "service_identity": "service identity that runs a Tier 1 application",
    "server_role_inferred": "member server by its server-role services",
}

# Fallback reason when a verdict carries no stamped basis (an older graph, or a
# deterministic Tier-0 from the DC fast-path which needs no basis). Keyed by the
# tier family so the phrase still reads correctly.
_TIER0_NO_BASIS_PHRASE = "domain controller or control-plane role"
_TIER1_NO_BASIS_PHRASE = "member server"


def _tier_is_tier0(tier: str | None) -> bool:
    """Return whether a stamped tier VALUE is a Tier-0 family value."""
    value = str(tier or "").strip().lower()
    return value in {"tier0_direct", "tier0_escalation_capable"} or value == "0"


def _tier_is_tier1(tier: str | None) -> bool:
    """Return whether a stamped tier VALUE is the Tier-1 value."""
    value = str(tier or "").strip().lower()
    return value in {"tier1", "1"}


def tier_confidence(basis: str | None, tier: str | None = None) -> str:
    """Return the client-facing confidence for a tier verdict.

    ``deterministic`` when the verdict was read from the directory: a deterministic
    basis (control-plane group membership, an observed Tier-0 control
    relationship) OR any Tier-0 family verdict (the DC fast-path stamps no basis
    but is deterministic by construction). ``inferred`` otherwise (every Tier-1 /
    Tier-2 heuristic).

    Args:
        basis: The stamped ``privilege_tier_basis`` value, or ``None``.
        tier: The stamped ``privilege_tier`` value, used to resolve the Tier-0
            fast-path (no basis) as deterministic.

    Returns:
        :data:`CONFIDENCE_DETERMINISTIC` or :data:`CONFIDENCE_INFERRED`.
    """
    key = str(basis or "").strip().lower()
    if key in _DETERMINISTIC_BASES:
        return CONFIDENCE_DETERMINISTIC
    if _tier_is_tier0(tier):
        return CONFIDENCE_DETERMINISTIC
    return CONFIDENCE_INFERRED


def tier_basis_reason(basis: str | None, tier: str | None = None) -> str | None:
    """Return the client-safe reason phrase for a tier verdict, or ``None``.

    This is the reason WITHOUT the confidence prefix (e.g. ``member server by
    operating-system role``). ``None`` when there is nothing meaningful to say
    (a plain Tier-2 with no stamped basis), so the caller renders no basis.

    Args:
        basis: The stamped ``privilege_tier_basis`` value, or ``None``.
        tier: The stamped ``privilege_tier`` value (for the no-basis fallback).

    Returns:
        The client-safe reason phrase, or ``None`` when none applies.
    """
    key = str(basis or "").strip().lower()
    phrase = _BASIS_PHRASE.get(key)
    if phrase:
        return phrase
    if key:
        # A basis value we do not recognise (a newer engine value not yet mapped):
        # stay honest and say nothing rather than leak the raw token.
        return None
    # No stamped basis: only a Tier-0 (deterministic) or Tier-1 verdict carries a
    # meaningful fallback; a plain Tier-2 shows no basis.
    if _tier_is_tier0(tier):
        return _TIER0_NO_BASIS_PHRASE
    if _tier_is_tier1(tier):
        return _TIER1_NO_BASIS_PHRASE
    return None


class TierBasisDisplay(NamedTuple):
    """The client-facing basis + confidence for one tier verdict.

    Attributes:
        confidence: ``deterministic`` or ``inferred``.
        reason: The client-safe reason phrase, or ``None`` when none applies.
        qualified: The combined phrase ready to render, e.g. ``inferred: member
            server by operating-system role`` or ``deterministic: control-plane
            group membership``. ``None`` when there is no reason to show.
    """

    confidence: str
    reason: str | None
    qualified: str | None


def describe_tier_basis(basis: str | None, tier: str | None = None) -> TierBasisDisplay:
    """Return the client-facing confidence + basis phrase for a tier verdict.

    The single call both the report and the web use. The ``qualified`` field is
    the ready-to-render string (``"<confidence>: <reason>"``); render it on demand
    (a tooltip / expandable detail) next to the tier badge so the client can see
    WHY an asset holds its tier without cluttering the default view.

    Args:
        basis: The stamped ``privilege_tier_basis`` value, or ``None``.
        tier: The stamped ``privilege_tier`` value, or ``None``.

    Returns:
        A :class:`TierBasisDisplay`.
    """
    confidence = tier_confidence(basis, tier)
    reason = tier_basis_reason(basis, tier)
    qualified = f"{confidence}: {reason}" if reason else None
    return TierBasisDisplay(confidence=confidence, reason=reason, qualified=qualified)
