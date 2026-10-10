"""Which findings rest on an INFERENCE rather than an observation.

Import-safe SSOT (stdlib + typing only) so every tier reads one declaration: the
PRO report, the LITE report, the compliance annex and the paid web CTEM.

Most findings are observations. ADscan asked the directory a question and the
directory answered: this template allows requester-supplied subject names, this
account's hash replicated, this negotiate carried SMBv1. The grade can be stated
flatly because the condition was measured.

A few are not. Their condition is **indistinguishable from a benign one at
ADscan's vantage**, and the discriminator that separates the two lives with the
client, not in the directory. A directory-synchronization account replicating to
a tenant that carries none of the organization's own identity tokens is the
canonical case: the rights are real and the tenant is genuinely foreign-named,
but whether the deployment is authorized is a fact only the identity owners hold.

For those, two things change, and this module is what both read:

* the finding is graded at the level the EVIDENCE supports, with the escalation
  stated in its own prose (reported high, critical once confirmed unauthorized),
  rather than asserting the worst reading as fact;
* in the compliance annex it REQUESTS client evidence instead of asserting a
  non-conformity. Asserting a non-conformity on an inference is the same
  falsehood class as greening a control nobody tested, and it is exactly where
  an auditor pushes back.

**This is not a licence to hedge.** Per CLAUDE.md § "Grading a condition that is
indistinguishable from benign", the hedge is the LAST resort: first exhaust the
discriminators the workspace already holds (object type, privilege tier,
population scale, timestamps, correlation with a known-good source) and SEGMENT
the finding by what they separate. A key belongs here only when a discriminator
cannot settle it. Adding a key is a decision to report less certainty, so it
needs the same justification as adding a finding.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: Findings whose condition ADscan cannot distinguish from a benign one, where no
#: workspace discriminator settles it and the deciding fact is the client's.
#:
#: * ``unauthorized_external_tenant_replication`` — a replication-privileged
#:   synchronization account whose target tenant carries none of the
#:   organization's identity tokens. The tenant really is foreign-named; whether
#:   it is an authorized deployment (a parent company, an acquired entity, a
#:   trading name, a provider's own tenant) is held by the identity owners.
#: * ``shadow_credentials_present`` — accounts carrying a key credential that the
#:   directory's own enrolment population does not account for. The discriminators
#:   have ALREADY run here (see
#:   :mod:`adscan_core.reporting.shadow_credential_segmentation`: a rollout at
#:   scale is reported separately and never reaches this finding), so what is left
#:   is genuinely undecidable at this vantage: whether these specific accounts were
#:   enrolled is a fact the client's enrolment records hold.
#: * ``adcs_esc15`` — ESC15 / EKUwu (CVE-2024-49019). The passive LDAP detector
#:   sees a schema-v1 EnrolleeSuppliesSubject template but CANNOT observe the
#:   issuing CA's patch state, which is the exploitability existence condition.
#:   ADscan confirms it actively during collection
#:   (:mod:`adscan_internal.services.adcs.esc15_confirmation`): a
#:   confirmed-vulnerable instance stamps ``confirmation_resolved`` on its finding
#:   details and is graded a hard non-conformity, a hardened CA drops the finding
#:   entirely, and an instance the confirmation could not run against (no enroll
#:   rights / CA unreachable / opt-out) stays here by default — reported honestly
#:   as "critical if confirmed; CA patch state not actively verified".
#: * ``adcs_esc14`` — ESC14 (weak explicit certificate mapping). The passive LDAP
#:   detector sees the template shape but CANNOT observe the domain controllers'
#:   ``StrongCertificateBindingEnforcement`` mode, which is the exploitability
#:   existence condition (weak explicit mappings are refused at Full enforcement).
#:   ADscan confirms it actively during collection
#:   (:mod:`adscan_internal.services.adcs.esc14_confirmation`). SCBE < 2 is
#:   NECESSARY but NOT SUFFICIENT: an instance is graded a hard non-conformity
#:   (stamps ``confirmation_resolved``) ONLY when a DC accepts weak mappings AND an
#:   abusable mapping / write access is also established (a ``role=puppet`` target
#:   for variant A, or a reachable weak ``altSecurityIdentities`` mapping for
#:   variants B/C/D). Full enforcement on every DC drops the finding entirely, and
#:   an instance that is only template-shape (weak DC but no established abuse), or
#:   that the confirmation could not run against (DC unreachable / value absent /
#:   opt-out / no credential), stays here by default.
CONFIRMATION_PENDING_FINDING_KEYS: frozenset[str] = frozenset(
    {
        "unauthorized_external_tenant_replication",
        "shadow_credentials_present",
        "adcs_esc15",
        "adcs_esc14",
    }
)

#: The conformity status a control carries when its only evidence is a
#: confirmation-pending finding. Distinct from ``not_assessed``: ADscan did test
#: the control and found something, it simply cannot close the verdict without a
#: fact the client supplies. Excluded from the conformance score exactly like
#: ``not_assessed`` (never counted as a pass, never counted as a gap), but
#: labelled so the client sees an action rather than a silence.
PENDING_CLIENT_EVIDENCE_STATUS = "pending_client_evidence"


def finding_requires_client_confirmation(key: Any, details: Any = None) -> bool:
    """Return whether *key* names a finding awaiting a client-held fact.

    A finding type is confirmation-pending either because it is ALWAYS an
    inference at ADscan's vantage (the static
    :data:`CONFIRMATION_PENDING_FINDING_KEYS`) or because THIS instance carries a
    per-instance marker. The per-instance marker wins, so a finding that is
    normally an inference but was actively RESOLVED this run (``ESC15`` confirmed
    exploitable, which stamps ``confirmation_resolved``) is graded a hard
    non-conformity, and a finding not in the static set that was left pending this
    run (``confirmation_pending``) still routes to pending evidence.

    Args:
        key: Candidate finding key. Any non-string, or a key outside the
            declaration (and with no per-instance marker), is ``False``.
        details: Optional per-finding details dict. ``confirmation_resolved``
            truthy forces ``False`` (actively confirmed this run);
            ``confirmation_pending`` truthy forces ``True``.

    Returns:
        ``True`` when the finding is graded on an inference and the compliance
        annex must request evidence rather than assert a non-conformity.
    """
    if isinstance(details, Mapping):
        if _is_truthy(details.get("confirmation_resolved")):
            return False
        if _is_truthy(details.get("confirmation_pending")):
            return True
    if not isinstance(key, str):
        return False
    return key.strip() in CONFIRMATION_PENDING_FINDING_KEYS


def _is_truthy(value: Any) -> bool:
    """Return whether *value* is a truthy flag (handles ``"false"`` / ``"0"``)."""
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


__all__ = [
    "CONFIRMATION_PENDING_FINDING_KEYS",
    "PENDING_CLIENT_EVIDENCE_STATUS",
    "finding_requires_client_confirmation",
]
