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
