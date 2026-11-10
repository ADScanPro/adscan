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

from adscan_core.reporting.execution_status import FULLY_EXECUTED_PATH_STATUSES

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
#: The set itself is declared once, in ``adscan_core.reporting.execution_status``
#: (stdlib only), so the web ingestion that stores a path's execution status reads
#: the very same tokens.
_PROVEN_STATUSES: frozenset[str] = FULLY_EXECUTED_PATH_STATUSES

#: Display-status token for a pure COVERAGE-DECLARATION record — the synthetic
#: single-step record the bounded fallback engine emits (``notes["coverage"] ==
#: "reached_not_materialized"``) to DECLARE that a reachable high-value target was
#: covered even though its individual route was not materialised in the capped
#: sample. It is NOT a real attack step: it carries no client exposure and must
#: never be counted as ``attempted`` (which would inflate the attempted totals in
#: the report / CTEM / KPIs). It rolls up into the sampled-coverage declaration
#: block, not into the per-path status buckets. See
#: :func:`adscan_internal.services.attack_paths_core.is_coverage_marker_step`.
from adscan_core.reporting.posture_inputs import (  # noqa: E402
    COVERAGE_SAMPLE_STATUS,
)

#: Display/edge-status token for a finding ADscan actively proved is NOT
#: exploitable. Emitted today only by the ESC15 (EKUwu / CVE-2024-49019)
#: non-destructive confirm-mode when the CA stripped the injected application
#: policy from the issued certificate — i.e. the CA is patched, so the ESC15
#: finding is DISMISSED. This is an OBSERVED-GOOD verdict (the probe ran and the
#: policy was proven absent from the issued cert), distinct from the
#: ``unsupported`` / ``unavailable`` data gaps (a gap in OUR coverage) and from
#: ``closed_by_configuration`` (an orthogonal avenue of a STILL-EXISTING weakness
#: closed by config). A dismissed finding is NOT client exposure, so it is a
#: member of :data:`NO_EXPOSURE_STATUSES` below. The matching GREEN compliance
#: evidence is persisted separately as a positive control
#: (``esc15_application_policy_injection_mitigated``).
from adscan_core.reporting.posture_inputs import (  # noqa: E402
    NOT_VULNERABLE_STATUS,
)

# NO_EXPOSURE_STATUSES and carries_client_exposure live in the dependency-light
# SSOT ``adscan_core.reporting.posture_inputs`` (the web worker computes the
# posture score with no engine on its path); re-exported here unchanged.
from adscan_core.reporting.posture_inputs import (  # noqa: E402,F401
    NO_EXPOSURE_STATUSES,
    carries_client_exposure,
)


#: Statuses that mean "ADscan had no way to assess this avenue" — a gap in OUR
#: coverage, never a statement about the client's directory. Kept as a named set
#: so a renderer can badge them distinctly instead of folding them into
#: ``theoretical`` (which the report legend defines as "mapped from configuration
#: analysis", a claim these paths do not support).
NOT_ASSESSED_STATUSES: frozenset[str] = frozenset({"unsupported", "unavailable"})

#: Display bucket token for :data:`NOT_ASSESSED_STATUSES`. Distinct from the raw
#: engine statuses so a renderer can key its chip/CSS on one value.
NOT_ASSESSED_BUCKET: str = "not_assessed"

#: Display bucket token for a route or step ADscan CONFIRMED and deliberately did
#: not execute, because executing it would disrupt production. Kept out of
#: ``theoretical`` for the same reason :data:`NOT_ASSESSED_BUCKET` is: the legend
#: defines Theoretical as "mapped from configuration analysis; not actively
#: exploited", which is a different and weaker claim than restraint, and a card
#: badged that way contradicted its own prose saying the route was withheld.
#: Resolution is MARKER-based, never token-based: a bare ``blocked`` with no
#: safety marker stays ``attempted``, because ADscan never attributes a
#: non-execution to a control in the client's environment. Use
#: ``destructive_action_policy.path_is_safety_abstention`` /
#: ``step_is_safety_abstention`` to decide; this is only the token to render.
SAFETY_WITHHELD_BUCKET: str = "safety_blocked"

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
    COVERAGE_SAMPLE_STATUS: "Reachable (route sampled)",
    NOT_VULNERABLE_STATUS: "Not Vulnerable",
    "theoretical": "Theoretical",
}

#: The semantic TONE of every status, shared by the LITE report (a CSS class)
#: and the web CTEM (served beside the label, mapped to a colour there). A
#: safety-withheld route is ``safety`` (a confirmed exposure ADscan chose not to
#: run), never a remediated green; ``hardening`` is the one positive tone.
_CLIENT_STATUS_TONES: dict[str, str] = {
    "partial": "partial",
    "attempted": "attempted",
    "failed": "attempted",
    "error": "attempted",
    "post_ex_failed": "attempted",
    "unavailable": "gap",
    "unsupported": "gap",
    NOT_ASSESSED_BUCKET: "gap",
    "blocked": "safety",
    "safety_blocked": "safety",
    "closed_by_configuration": "hardening",
    NOT_VULNERABLE_STATUS: "hardening",
    "theoretical": "theoretical",
}


def client_status_tone(status: object) -> str:
    """Return the semantic tone of a path or step status.

    ``proven`` for :data:`_PROVEN_STATUSES`, else the shared tone map; an
    unknown token falls back to ``theoretical``, the most conservative claim.
    """
    token = str(status or "").strip().lower()
    if token in _PROVEN_STATUSES:
        return "proven"
    return _CLIENT_STATUS_TONES.get(token, "theoretical")


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
