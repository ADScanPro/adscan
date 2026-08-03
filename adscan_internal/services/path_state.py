"""Canonical lifecycle state for an ADscan attack path.

Declared in Phase 1 so the data model supports the lifecycle from the
start. State transitions (theoretical -> foothold_obtained -> ... ->
domain_compromised) are implemented in Phase 6 of the attack-graph
refactor — see ``adscan-obsidian/business/12_nomenclature_standard.md``
(§ Fase 1, subsection PathState).

Newly materialised paths default to :attr:`PathState.THEORETICAL`. The
runtime promotion to higher states happens only when ADscan executes a
post-exploitation technique and records the outcome (success, failure)
against the path.
"""

from __future__ import annotations

from enum import Enum

#: Statuses that count as PROVEN domain compromise — the single source of truth
#: for "is this path proven?". Strict on purpose: only a demonstrably-reached
#: Tier-0 target counts, so a failed post-ex is NOT presented as proven. The set
#: deliberately spans all three status vocabularies' proven tokens (attack STEP
#: ``success`` / attack PATH ``exploited`` / canonical ``PathState``
#: ``domain_compromised``) — NEVER test ``status == "exploited"`` against a bare
#: literal, always membership here (a proven path may be keyed
#: ``domain_compromised`` or ``success``, not ``exploited``).
#:
#: Declared on this lean, import-safe leaf (no ``adscan_internal`` imports) so
#: consumers that only need the proven-token set — e.g. the client-presentation
#: ordering ``attack_path_presentation`` imported by the web backend — get a
#: MINIMAL closure and do not drag ``exposure_score_service`` into it.
#: ``exposure_score_service`` re-exports this name for full backward compat.
_PROVEN_STATUSES: frozenset[str] = frozenset(
    {"success", "exploited", "domain_compromised"}
)

#: Statuses that describe NO client exposure, and therefore may never be counted
#: into a risk figure or offered to a client as something to remediate.
#:
#: * ``closed_by_configuration`` — the POSITIVE bucket. The client's own
#:   configuration already closed this avenue and ADscan observed it with
#:   certainty ("Attack Surface Reduced — Hardening Observed"). Billing them to
#:   fix hardening they already did inverts what the report is for.
#: * ``unsupported`` / ``unavailable`` — an ADscan data gap: no reachable surface
#:   to walk, so the absence of a result says nothing about the client.
#:
#: This is the same set as the ``None`` entries of
#: ``exposure_score_service._PROOF_WEIGHT`` — that table builds them from here,
#: so the exposure score and every remediation ranking exclude exactly the same
#: paths and cannot drift apart. The token spelling is locked against
#: ``relay_status_constants.CONFIGURATION_CLOSE_STATUS`` by
#: ``tests/unit/services/test_remediation_status_filter.py`` (a test-only import,
#: which keeps this module the stdlib-only leaf its closure depends on).
NO_EXPOSURE_STATUSES: frozenset[str] = frozenset(
    {"closed_by_configuration", "unsupported", "unavailable"}
)


def carries_client_exposure(raw: object) -> bool:
    """Return True when a path's status describes exposure worth remediating.

    The inclusion filter every client-facing count applies before it reports a
    number as exposure: the exposure score, the remediation rankings, the
    report's Compromise Reach cards, and the page-2 executive headline. Three
    statuses answer "no", each for a reason the client would recognise:

    * ``closed_by_configuration`` — their own configuration already closed this
      avenue and ADscan observed it. It is the report's POSITIVE bucket, and
      counting it as exposure bills them for hardening they already did.
    * ``unsupported`` / ``unavailable`` — ADscan had no reachable surface to
      walk. That is a gap in our coverage, not an exposure in their directory.

    Everything else counts, including ``attempted`` and ``blocked``: ADscan
    failing to land a technique, or withholding a destructive one, says nothing
    about whether the avenue is open (CLAUDE.md § Exposure Validation).

    Declared on this stdlib-only leaf, beside the set it reads, so any consumer
    can apply the SAME filter without dragging a heavier module into its import
    closure. ``technique_priority`` re-exports it for its existing callers.

    Args:
        raw: A path's raw ``status`` token, in any casing.

    Returns:
        ``False`` only for the three statuses above. An unknown or missing token
        counts as exposure — the safe direction, since the alternative is
        dropping a real route from the client's fix list.
    """
    return str(raw or "").strip().lower() not in NO_EXPOSURE_STATUSES


#: Statuses that mean "ADscan had no way to assess this avenue" — a gap in OUR
#: coverage, never a statement about the client's directory. Kept as a named set
#: so a renderer can badge them distinctly instead of folding them into
#: ``theoretical`` (which the report legend defines as "mapped from configuration
#: analysis", a claim these paths do not support).
NOT_ASSESSED_STATUSES: frozenset[str] = frozenset({"unsupported", "unavailable"})

#: Display bucket token for :data:`NOT_ASSESSED_STATUSES`. Distinct from the raw
#: engine statuses so a renderer can key its chip/CSS on one value.
NOT_ASSESSED_BUCKET: str = "not_assessed"

#: Client-facing badge text for every NON-PROVEN status, in both report tiers.
#:
#: The proven label is the caller's to choose (LITE says "Validated", the PRO
#: deliverable says "Exploited"), because the two documents address different
#: readers. Everything below the proven line is shared: those are the labels the
#: two tiers must never disagree on, and where the disagreements have actually
#: cost us — a ``partial`` chain described as configuration analysis erases the
#: segment ADscan executed, and an ``unsupported`` chain badged "Theoretical"
#: claims a route was mapped when it was not assessed at all.
_NONPROVEN_CLIENT_STATUS_LABELS: dict[str, str] = {
    "partial": "Partially Validated",
    "attempted": "Attempted",
    "failed": "Attempted",
    "error": "Attempted",
    "post_ex_failed": "Attempted",
    "unavailable": "Not Assessed",
    "unsupported": "Not Assessed",
    NOT_ASSESSED_BUCKET: "Not Assessed",
    "blocked": "Not Executed for Safety",
    "safety_blocked": "Not Executed for Safety",
    "closed_by_configuration": "Attack Surface Reduced",
    "theoretical": "Theoretical",
}


def is_not_assessed(raw: object) -> bool:
    """Return True when a status means ADscan could not assess the avenue."""
    return str(raw or "").strip().lower() in NOT_ASSESSED_STATUSES


def client_status_label(status: object, *, proven_label: str = "Validated") -> str:
    """Return the client-facing badge text for a path or step status.

    Args:
        status: A raw status token from any of the three vocabularies
            (step / path display / :class:`PathState`), in any casing.
        proven_label: What this document calls a status in
            :data:`_PROVEN_STATUSES`. LITE says ``"Validated"``; the PRO
            deliverable says ``"Exploited"``, matching its own legend.

    Returns:
        The badge text. An unknown token falls back to ``"Theoretical"``, the
        most conservative claim available.
    """
    token = str(status or "").strip().lower()
    if token in _PROVEN_STATUSES:
        return proven_label
    return _NONPROVEN_CLIENT_STATUS_LABELS.get(token, "Theoretical")


class PathState(str, Enum):
    """Canonical lifecycle state of an attack path."""

    THEORETICAL = "theoretical"
    FOOTHOLD_OBTAINED = "foothold_obtained"
    POST_EX_IN_PROGRESS = "post_ex_in_progress"
    POST_EX_FAILED = "post_ex_failed"
    DOMAIN_COMPROMISED = "domain_compromised"

    @property
    def is_proven(self) -> bool:
        """Return True when the state implies executed evidence (not just LDAP)."""
        return self in {
            PathState.FOOTHOLD_OBTAINED,
            PathState.POST_EX_IN_PROGRESS,
            PathState.POST_EX_FAILED,
            PathState.DOMAIN_COMPROMISED,
        }
