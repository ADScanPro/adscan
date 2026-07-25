"""Pre-flight feasibility framework for NTLM-relay-to-LDAP attacks.

Single source of truth for deciding, BEFORE any network action, whether an
NTLM-relay-to-LDAP chain (coerce a victim's NTLM auth -> relay it to the DC's
LDAP -> write ``msDS-AllowedToActOnBehalfOfOtherIdentity`` (RBCD) or
``msDS-KeyCredentialLink`` (Shadow Credentials)) is viable against a given DC,
and WHY (or why not).

This module is a *read-only interpretation layer* over ADscan's existing
domain-posture system (:mod:`adscan_internal.services.domain_posture`). It
performs NO network I/O and NO exploitation. Every check reads the persisted
posture snapshot via :func:`get_posture` and reasons over
``ConstraintState.effective_state`` (so stale observations transparently
degrade to ``UNKNOWN`` -> the conservative baseline). It NEVER re-detects.

Design contract (spec 2026-06-01-ntlmv1-relay-ldap-feasibility-design, §§3, §5):

* The operator always gets an explicit go/no-go with the exact AD constraint
  that enables or blocks the attack -- never a silent timeout. The unit tests
  in ``tests/unit/services/relay/test_relay_feasibility.py`` ARE that "no
  silent timeout" contract.
* Each check is a small reusable callable (the :class:`RelayPrecondition`
  protocol) so individual checks (``ntlm_enabled``, ``ldap_signing``, ...) can
  be reused from other relay flows (ESC8, future targets).
* :func:`evaluate_relay_feasibility` is the aggregator: pure and deterministic
  given its inputs. It composes the verdicts into an overall
  :class:`RelayFeasibility` carrying ``viable``, the chosen relay ``target``,
  and the ordered list of :class:`FeasibilityVerdict`.

Correctness nuance baked into the composite target selector (spec §2):
drop-the-MIC (CVE-2019-1040) does NOT defeat ``LDAP_SIGNING=REQUIRED``. It only
works when LDAP signing is optional/WhenSupported. When signing is REQUIRED the
only SMB-sourced path left is relaying to LDAPS (TLS sealing sidesteps the 389
signing check) -- and that itself dies if LDAP channel binding is REQUIRED,
because an SMB source cannot supply a channel-binding token.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, Optional, Protocol, Sequence

from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    ConstraintState,
    DomainPosture,
    SignalConfidence,
    TriState,
    get_posture,
)

# --------------------------------------------------------------------------- #
# Type aliases
# --------------------------------------------------------------------------- #

VerdictStatus = Literal["ok", "blocking", "warning"]

# The exact `why` for an RBCD block caused by an exhausted machine-account quota.
# Shared SSOT so a consumer can distinguish a PARTIAL close (MAQ==0 blocks only
# minting a NEW delegate account — RBCD via an already-controlled computer account
# still works) from a CERTAIN full close. A partial close must NOT be surfaced as
# the positive ``closed_by_configuration`` status (that would over-credit a defense
# the client does not fully have). See CLAUDE.md § Status vocabularies.
MAQ_EXHAUSTED_REASON = (
    "MachineAccountQuota is 0; a new delegate machine account cannot be "
    "created for RBCD."
)

RelayTargetKind = Literal[
    "ldap_389_dropmic",
    "ldaps_636",
    "ldap_389_starttls",
    "impossible_needs_http_source",
    "unknown",
]

RelayMethod = Literal["rbcd", "shadow_creds"]


# --------------------------------------------------------------------------- #
# Value types
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FeasibilityVerdict:
    """One precondition outcome (spec §3).

    Attributes:
        check_id: Stable identifier of the check (e.g. ``"ntlm_enabled"``).
        status: ``"ok"`` (precondition met), ``"blocking"`` (attack cannot
            proceed) or ``"warning"`` (proceed with caveat).
        observed: The posture value / probe result the verdict keyed on, as a
            short human-readable string.
        why: Pentester-facing reason for the verdict.
        remediation: What to do about it (e.g. "use an HTTP coercion source"),
            or ``None`` when there is nothing to remediate.
        confidence: Confidence of the underlying observation.
    """

    check_id: str
    status: VerdictStatus
    observed: str
    why: str
    remediation: Optional[str]
    confidence: SignalConfidence


@dataclass(frozen=True)
class NtlmAuthVerdict:
    """Input describing the result of the ``check_ntlm_auth`` probe (Deliverable A).

    This module does NOT run the probe; the caller supplies its already-computed
    verdict so the feasibility framework stays free of network I/O. Either
    ``ntlmv1_observed`` (the coerced victim authenticates with NTLMv1) or
    ``dc_cve_2019_1040_vulnerable`` (the DC accepts a MIC-stripped NTLMv2 bind)
    is sufficient for drop-the-MIC to succeed.
    """

    ntlmv1_observed: Optional[bool] = None
    dc_cve_2019_1040_vulnerable: Optional[bool] = None
    detail: Optional[str] = None


@dataclass(frozen=True)
class RelayFeasibilityInputs:
    """All inputs the feasibility aggregator reasons over.

    ``domains_data`` + ``domain`` locate the persisted posture snapshot (the
    ONLY thing read from posture; never re-detected). Everything else is a
    pre-computed RESULT supplied by the caller -- the framework performs no
    network I/O.

    Attributes:
        domains_data: Workspace ``domains_data`` mapping (read-only here).
        domain: Target domain name (the DC's domain).
        dc_host: DC hostname/IP for display (masked in the panel).
        method: Which write method the operator selected; gates the
            method-specific checks. ``None`` evaluates both method gates as
            informational warnings rather than blocking.
        ntlm_auth: Result of the ``check_ntlm_auth`` probe (Deliverable A).
            ``None`` => the probe has not been run yet.
        adcs_pki_present: Whether a usable CA / NTAuth PKI is present (shadow
            creds need PKINIT). ``None`` => unknown.
        machine_account_quota: ms-DS-MachineAccountQuota for the actor, when
            known. ``None`` => unknown (treated as a warning, not blocking).
        listener_reachable_from_victim: Whether the victim has a return route
            to our relay listener. ``None`` => not yet probed (warning); the
            actual reachability probe is wired in the later offensive step.
        relayed_principal_self_write: Whether the relayed principal can write
            its own RBCD / KeyCredentialLink attribute. ``None`` => unknown
            (confirmed at execution); surfaced as a warning.
    """

    domains_data: Optional[Mapping[str, Any]]
    domain: str
    dc_host: Optional[str] = None
    method: Optional[RelayMethod] = None
    ntlm_auth: Optional[NtlmAuthVerdict] = None
    adcs_pki_present: Optional[bool] = None
    machine_account_quota: Optional[int] = None
    listener_reachable_from_victim: Optional[bool] = None
    relayed_principal_self_write: Optional[bool] = None


@dataclass(frozen=True)
class RelayFeasibility:
    """Composed overall feasibility outcome.

    Attributes:
        viable: ``True`` only when no ``blocking`` verdict was produced.
        target: The chosen relay target kind (from
            :func:`check_ldap_relay_target_viable`).
        verdicts: Ordered list of every :class:`FeasibilityVerdict` produced.
        summary: One-line operator-facing verdict (rendered as the panel's
            footer line).
    """

    viable: bool
    target: RelayTargetKind
    verdicts: Sequence[FeasibilityVerdict]
    summary: str

    @property
    def blocking_verdicts(self) -> list[FeasibilityVerdict]:
        """Subset of verdicts whose status is ``blocking``."""
        return [v for v in self.verdicts if v.status == "blocking"]

    @property
    def warning_verdicts(self) -> list[FeasibilityVerdict]:
        """Subset of verdicts whose status is ``warning``."""
        return [v for v in self.verdicts if v.status == "warning"]


class RelayPrecondition(Protocol):
    """A single reusable feasibility check.

    Each concrete check is a small callable that reads the resolved
    :class:`DomainPosture` plus the caller-supplied inputs and returns one
    :class:`FeasibilityVerdict`. Checks never perform network I/O.
    """

    def __call__(
        self, posture: DomainPosture, inputs: RelayFeasibilityInputs
    ) -> FeasibilityVerdict:  # pragma: no cover - structural
        ...


# --------------------------------------------------------------------------- #
# Small helpers (pure)
# --------------------------------------------------------------------------- #


def _observed_label(state: ConstraintState) -> str:
    """Render the observed posture state as a short label for the panel."""
    pretty = {
        TriState.UNKNOWN: "unknown",
        TriState.ENABLED: "enabled",
        TriState.DISABLED: "disabled",
        TriState.REQUIRED: "required",
    }
    label = pretty.get(state.effective_state, "unknown")
    if state.is_stale and state.state is not TriState.UNKNOWN:
        return f"{label} (stale -> unknown)"
    return label


# --------------------------------------------------------------------------- #
# Concrete blocking / informational checks
# --------------------------------------------------------------------------- #


def check_ntlm_enabled(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Blocking when NTLM is DISABLED (HIGH): nothing to relay.

    A coerced victim on an NTLM-disabled domain authenticates via Kerberos, so
    there is no NTLM authentication to relay.
    """
    state = posture.get(ConstraintCategory.NTLM_AUTHENTICATION)
    effective = state.effective_state
    if effective is TriState.DISABLED and state.confidence is SignalConfidence.HIGH:
        return FeasibilityVerdict(
            check_id="ntlm_enabled",
            status="blocking",
            observed=_observed_label(state),
            why="NTLM is disabled domain-wide; a coerced victim authenticates via "
            "Kerberos, so there is no NTLM auth to relay.",
            remediation="No relay possible against this domain; pursue a "
            "Kerberos-based escalation path instead.",
            confidence=state.confidence,
        )
    return FeasibilityVerdict(
        check_id="ntlm_enabled",
        status="ok",
        observed=_observed_label(state),
        why="NTLM authentication is not known-disabled; coerced auth can be relayed.",
        remediation=None,
        confidence=state.confidence,
    )


def check_ldap_signing(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Reads ``LDAP_SIGNING``. REQUIRED => the 389 + drop-the-MIC path is unavailable.

    Reusable, individually meaningful check. Not blocking on its own: when
    signing is REQUIRED the relay may still go to LDAPS (sealing sidesteps the
    389 signing check); that combination is resolved by the composite
    :func:`check_ldap_relay_target_viable`.
    """
    state = posture.get(ConstraintCategory.LDAP_SIGNING)
    if state.effective_state is TriState.REQUIRED:
        return FeasibilityVerdict(
            check_id="ldap_signing",
            status="warning",
            observed=_observed_label(state),
            why="LDAP signing is enforced; drop-the-MIC does not bypass it, so the "
            "389 + drop-the-MIC path is dead. A relay to LDAPS may still work.",
            remediation="Relay to LDAPS 636 instead of LDAP 389 (TLS sealing "
            "sidesteps the 389 signing check).",
            confidence=state.confidence,
        )
    return FeasibilityVerdict(
        check_id="ldap_signing",
        status="ok",
        observed=_observed_label(state),
        why="LDAP signing is not known-required; the 389 + drop-the-MIC path is open.",
        remediation=None,
        confidence=state.confidence,
    )


def check_ldap_channel_binding(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Reads ``LDAP_CHANNEL_BINDING``. REQUIRED => SMB-sourced LDAPS relay impossible.

    An SMB capture source cannot supply a channel-binding token, so when CBT is
    enforced on LDAPS the relay needs an HTTP coercion source instead.
    """
    state = posture.get(ConstraintCategory.LDAP_CHANNEL_BINDING)
    if state.effective_state is TriState.REQUIRED:
        return FeasibilityVerdict(
            check_id="ldap_channel_binding",
            status="warning",
            observed=_observed_label(state),
            why="LDAP channel binding is enforced; an SMB source cannot supply a "
            "channel-binding token, so an SMB-sourced LDAPS relay is impossible.",
            remediation="Use an HTTP coercion source (which can satisfy CBT), not SMB.",
            confidence=state.confidence,
        )
    return FeasibilityVerdict(
        check_id="ldap_channel_binding",
        status="ok",
        observed=_observed_label(state),
        why="LDAP channel binding is not known-required; an SMB-sourced LDAPS relay "
        "is not blocked by CBT.",
        remediation=None,
        confidence=state.confidence,
    )


def check_ldaps_available(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Reads ``LDAPS_AVAILABLE`` (informational/selector).

    Never blocking on its own; it feeds the composite target selector (when
    signing is REQUIRED the relay must fall back to LDAPS, which requires LDAPS
    to be reachable).
    """
    state = posture.get(ConstraintCategory.LDAPS_AVAILABLE)
    effective = state.effective_state
    if effective is TriState.DISABLED:
        return FeasibilityVerdict(
            check_id="ldaps_available",
            status="warning",
            observed=_observed_label(state),
            why="LDAPS (636) is not available; the LDAPS relay fallback (used when "
            "signing is enforced) cannot be taken.",
            remediation="If LDAP signing is also enforced, only an HTTP source over "
            "StartTLS may remain; verify StartTLS availability.",
            confidence=state.confidence,
        )
    return FeasibilityVerdict(
        check_id="ldaps_available",
        status="ok",
        observed=_observed_label(state),
        why="LDAPS availability is not known-disabled; the LDAPS relay fallback is "
        "selectable when needed.",
        remediation=None,
        confidence=state.confidence,
    )


def check_ldap_starttls_available(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Reads ``LDAP_STARTTLS_AVAILABLE`` (informational/selector)."""
    state = posture.get(ConstraintCategory.LDAP_STARTTLS_AVAILABLE)
    return FeasibilityVerdict(
        check_id="ldap_starttls_available",
        status="ok",
        observed=_observed_label(state),
        why="StartTLS on 389 is an alternate sealed channel for the relay selector.",
        remediation=None,
        confidence=state.confidence,
    )


def _select_relay_target(
    *,
    signing_required: bool,
    ldaps_disabled: bool,
    cbt_required: bool,
    starttls_available: bool,
) -> RelayTargetKind:
    """Pure target selection from the four posture facts (spec §2 matrix).

    * signing NOT required => ``ldap_389_dropmic`` (the simplest viable path).
    * signing required + CBT required => ``impossible_needs_http_source`` (an
      SMB source cannot satisfy CBT on the only sealed channel left).
    * signing required + LDAPS available + CBT not required => ``ldaps_636``.
    * signing required + LDAPS NOT available + StartTLS available + CBT not
      required => ``ldap_389_starttls``.
    * signing required + neither sealed channel reachable =>
      ``impossible_needs_http_source``.
    """
    if not signing_required:
        return "ldap_389_dropmic"
    # Signing is required: drop-the-MIC over 389 is dead; we need a sealed channel.
    if cbt_required:
        # The sealed channel is TLS-based and an SMB source cannot supply CBT.
        return "impossible_needs_http_source"
    if not ldaps_disabled:
        return "ldaps_636"
    if starttls_available:
        return "ldap_389_starttls"
    return "impossible_needs_http_source"


def check_ldap_relay_target_viable(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """COMPOSITE blocking check; also OUTPUTS the chosen relay target.

    Combines ``LDAP_SIGNING`` + ``LDAPS_AVAILABLE`` + ``LDAP_CHANNEL_BINDING``
    (+ ``LDAP_STARTTLS_AVAILABLE``) into a single go/no-go and emits the chosen
    target as part of ``observed`` (machine-readable target is recovered by the
    aggregator via :func:`relay_target_for`).

    Blocks when signing is REQUIRED AND no SMB-sourced sealed channel remains
    (no LDAPS or CBT required, and no StartTLS fallback) -- i.e. the only viable
    path is dead for an SMB source and an HTTP source is needed.
    """
    signing = posture.get(ConstraintCategory.LDAP_SIGNING)
    ldaps = posture.get(ConstraintCategory.LDAPS_AVAILABLE)
    cbt = posture.get(ConstraintCategory.LDAP_CHANNEL_BINDING)
    starttls = posture.get(ConstraintCategory.LDAP_STARTTLS_AVAILABLE)

    target = _select_relay_target(
        signing_required=signing.effective_state is TriState.REQUIRED,
        ldaps_disabled=ldaps.effective_state is TriState.DISABLED,
        cbt_required=cbt.effective_state is TriState.REQUIRED,
        starttls_available=starttls.effective_state is TriState.ENABLED,
    )

    # Confidence of the composite is the weakest input that mattered.
    confidence = _weakest_confidence(signing, ldaps, cbt, starttls)

    descriptions: dict[RelayTargetKind, str] = {
        "ldap_389_dropmic": "LDAP 389 + drop-the-MIC (signing not enforced).",
        "ldaps_636": "LDAPS 636 (signing enforced; TLS sealing sidesteps 389 "
        "signing; no CBT).",
        "ldap_389_starttls": "LDAP 389 + StartTLS (signing enforced; LDAPS "
        "unavailable; StartTLS reachable; no CBT).",
    }

    if target == "impossible_needs_http_source":
        return FeasibilityVerdict(
            check_id="ldap_relay_target_viable",
            status="blocking",
            observed=f"target={target}",
            why="LDAP signing is enforced and no SMB-sourced sealed channel remains "
            "(LDAPS unavailable or channel binding required).",
            remediation="Use an HTTP coercion source, not SMB.",
            confidence=confidence,
        )

    return FeasibilityVerdict(
        check_id="ldap_relay_target_viable",
        status="ok",
        observed=f"target={target}",
        why=f"Viable relay target selected: {descriptions[target]}",
        remediation=None,
        confidence=confidence,
    )


def relay_target_for(posture: DomainPosture) -> RelayTargetKind:
    """Return the chosen relay target for a posture (pure; reusable by selectors)."""
    signing = posture.get(ConstraintCategory.LDAP_SIGNING)
    ldaps = posture.get(ConstraintCategory.LDAPS_AVAILABLE)
    cbt = posture.get(ConstraintCategory.LDAP_CHANNEL_BINDING)
    starttls = posture.get(ConstraintCategory.LDAP_STARTTLS_AVAILABLE)
    return _select_relay_target(
        signing_required=signing.effective_state is TriState.REQUIRED,
        ldaps_disabled=ldaps.effective_state is TriState.DISABLED,
        cbt_required=cbt.effective_state is TriState.REQUIRED,
        starttls_available=starttls.effective_state is TriState.ENABLED,
    )


def check_ntlmv1_or_cve1040(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Blocking unless NTLMv1 or DC CVE-2019-1040 is confirmed.

    Consumes the ``check_ntlm_auth`` verdict supplied on the inputs (this module
    does NOT run the probe). drop-the-MIC fails against a fully-patched
    NTLMv2-with-MIC host, so at least one of the two enabling conditions must
    hold.
    """
    ntlm_auth = inputs.ntlm_auth
    if ntlm_auth is None:
        return FeasibilityVerdict(
            check_id="ntlmv1_or_cve1040",
            status="blocking",
            observed="not probed",
            why="The check_ntlm_auth pre-flight has not been run, so drop-the-MIC "
            "feasibility (NTLMv1 / CVE-2019-1040) is unknown.",
            remediation="Run 'check_ntlm_auth <ip>' against the victim/DC first.",
            confidence=SignalConfidence.LOW,
        )

    ntlmv1 = bool(ntlm_auth.ntlmv1_observed)
    cve = bool(ntlm_auth.dc_cve_2019_1040_vulnerable)
    if ntlmv1 or cve:
        enabling = []
        if ntlmv1:
            enabling.append("NTLMv1 observed")
        if cve:
            enabling.append("DC CVE-2019-1040 vulnerable")
        return FeasibilityVerdict(
            check_id="ntlmv1_or_cve1040",
            status="ok",
            observed=", ".join(enabling),
            why="drop-the-MIC can strip the MIC and relay: " + ", ".join(enabling) + ".",
            remediation=None,
            confidence=SignalConfidence.HIGH,
        )

    return FeasibilityVerdict(
        check_id="ntlmv1_or_cve1040",
        status="blocking",
        observed=ntlm_auth.detail or "NTLMv2-with-MIC, DC patched",
        why="Neither NTLMv1 nor DC CVE-2019-1040 was observed; drop-the-MIC fails "
        "against a patched NTLMv2-with-MIC host.",
        remediation="Find a victim that authenticates with NTLMv1, or an unpatched DC.",
        confidence=SignalConfidence.HIGH,
    )


def check_adcs_pki_present(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Method-specific (shadow-creds): blocking when no usable PKI is present.

    A KeyCredentialLink is only useful when there is a CA / NTAuth chain that
    lets us PKINIT with the minted key. For the RBCD method this check is not a
    blocker -- it is surfaced informationally.
    """
    is_shadow = inputs.method == "shadow_creds"
    present = inputs.adcs_pki_present
    if present is True:
        return FeasibilityVerdict(
            check_id="adcs_pki_present",
            status="ok",
            observed="CA / NTAuth present",
            why="A PKI is present; a written KeyCredentialLink can be used via PKINIT.",
            remediation=None,
            confidence=SignalConfidence.MEDIUM,
        )
    if present is False:
        return FeasibilityVerdict(
            check_id="adcs_pki_present",
            status="blocking" if is_shadow else "warning",
            observed="no CA / NTAuth",
            why="No usable PKI; a KeyCredentialLink cannot be exercised via PKINIT, "
            "so the Shadow-Credentials method is unusable.",
            remediation="Use the RBCD method instead of Shadow-Credentials.",
            confidence=SignalConfidence.MEDIUM,
        )
    return FeasibilityVerdict(
        check_id="adcs_pki_present",
        status="warning",
        observed="unknown",
        why="ADCS/PKI presence is unknown; Shadow-Credentials may not be exercisable.",
        remediation="Confirm a CA / NTAuth chain before choosing Shadow-Credentials.",
        confidence=SignalConfidence.LOW,
    )


def check_machine_account_quota(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Method-specific (RBCD-new-account): blocking when MAQ == 0.

    When ms-DS-MachineAccountQuota is 0 the operator cannot mint a fresh
    delegate machine account and must fall back to an existing controlled
    account. For the Shadow-Credentials method this is not a blocker.
    """
    is_rbcd = inputs.method == "rbcd"
    maq = inputs.machine_account_quota
    if maq is None:
        return FeasibilityVerdict(
            check_id="machine_account_quota",
            status="warning",
            observed="unknown",
            why="MachineAccountQuota is unknown; creating a new delegate account "
            "may fail.",
            remediation="Supply MAQ, or be ready to use an existing controlled account.",
            confidence=SignalConfidence.LOW,
        )
    if maq <= 0:
        return FeasibilityVerdict(
            check_id="machine_account_quota",
            status="blocking" if is_rbcd else "warning",
            observed=f"MAQ={maq}",
            why=MAQ_EXHAUSTED_REASON,
            remediation="Use an existing controlled account (SID) instead of minting one.",
            confidence=SignalConfidence.MEDIUM,
        )
    return FeasibilityVerdict(
        check_id="machine_account_quota",
        status="ok",
        observed=f"MAQ={maq}",
        why="MachineAccountQuota allows creating a new delegate machine account.",
        remediation=None,
        confidence=SignalConfidence.MEDIUM,
    )


def check_listener_reachable_from_victim(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Blocking when the victim has no return route to our relay listener.

    Consumes a reachability RESULT supplied by the caller (this module does NOT
    probe). When unknown it is a warning (the actual probe runs in the later
    offensive step); an explicit ``False`` is blocking because the coercion can
    never land.
    """
    reachable = inputs.listener_reachable_from_victim
    if reachable is True:
        return FeasibilityVerdict(
            check_id="listener_reachable_from_victim",
            status="ok",
            observed="reachable",
            why="The victim has a return route to our relay listener; coercion can land.",
            remediation=None,
            confidence=SignalConfidence.HIGH,
        )
    if reachable is False:
        return FeasibilityVerdict(
            check_id="listener_reachable_from_victim",
            status="blocking",
            observed="no return route",
            why="The victim cannot reach our listener; the coerced authentication "
            "will never arrive.",
            remediation="Place the listener on a network the victim can reach (a "
            "reverse listener through the pivot is a separate capability).",
            confidence=SignalConfidence.HIGH,
        )
    return FeasibilityVerdict(
        check_id="listener_reachable_from_victim",
        status="warning",
        observed="not probed",
        why="Listener reachability from the victim has not been confirmed.",
        remediation="Confirm the listener IP is reachable from the victim before coercing.",
        confidence=SignalConfidence.LOW,
    )


def check_smb_signing_source(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Warning: SMB signing posture of the source/relay path.

    Never blocking here -- it is a caveat the operator should weigh (a
    signing-required relay destination would refuse a relayed SMB session).
    """
    state = posture.get(ConstraintCategory.SMB_SIGNING)
    if state.effective_state is TriState.REQUIRED:
        return FeasibilityVerdict(
            check_id="smb_signing_source",
            status="warning",
            observed=_observed_label(state),
            why="SMB signing is enforced; relays whose destination is an SMB service "
            "will be refused. (Not relevant when relaying to LDAP/LDAPS.)",
            remediation="For LDAP relay this is informational; confirm the source path.",
            confidence=state.confidence,
        )
    return FeasibilityVerdict(
        check_id="smb_signing_source",
        status="ok",
        observed=_observed_label(state),
        why="SMB signing is not known-required.",
        remediation=None,
        confidence=state.confidence,
    )


def check_posture_confidence_low(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Warning: any keyed LDAP/NTLM category at LOW confidence or stale.

    Recommends a re-probe so the go/no-go is not built on weak evidence.
    """
    keyed = (
        ConstraintCategory.NTLM_AUTHENTICATION,
        ConstraintCategory.LDAP_SIGNING,
        ConstraintCategory.LDAP_CHANNEL_BINDING,
        ConstraintCategory.LDAPS_AVAILABLE,
        ConstraintCategory.LDAP_STARTTLS_AVAILABLE,
    )
    weak: list[str] = []
    for category in keyed:
        state = posture.get(category)
        if state.is_stale:
            weak.append(f"{category.value}=stale")
        elif (
            state.effective_state is not TriState.UNKNOWN
            and state.confidence is SignalConfidence.LOW
        ):
            weak.append(f"{category.value}=low")
    if weak:
        return FeasibilityVerdict(
            check_id="posture_confidence_low",
            status="warning",
            observed=", ".join(weak),
            why="Some posture observations are low-confidence or stale; the go/no-go "
            "is built on weak evidence.",
            remediation="Run 'adscan posture probe <domain>' to refresh before relaying.",
            confidence=SignalConfidence.LOW,
        )
    return FeasibilityVerdict(
        check_id="posture_confidence_low",
        status="ok",
        observed="fresh / high-confidence",
        why="Posture observations driving this decision are fresh.",
        remediation=None,
        confidence=SignalConfidence.HIGH,
    )


def check_relayed_principal_self_write(
    posture: DomainPosture, inputs: RelayFeasibilityInputs
) -> FeasibilityVerdict:
    """Warning: the relayed principal may not be able to write its own attribute.

    A coerced machine writing its own ``msDS-AllowedToActOnBehalfOf`` /
    ``msDS-KeyCredentialLink`` is not always granted; confirmed at execution.
    """
    can_write = inputs.relayed_principal_self_write
    if can_write is True:
        return FeasibilityVerdict(
            check_id="relayed_principal_self_write",
            status="ok",
            observed="self-write granted",
            why="The relayed principal can write its own delegation/key attribute.",
            remediation=None,
            confidence=SignalConfidence.MEDIUM,
        )
    if can_write is False:
        return FeasibilityVerdict(
            check_id="relayed_principal_self_write",
            status="warning",
            observed="self-write denied",
            why="The relayed principal cannot write its own attribute; the modify "
            "will fail unless another writer is used.",
            remediation="Target an object the relayed principal can write, or pick a "
            "different victim.",
            confidence=SignalConfidence.MEDIUM,
        )
    return FeasibilityVerdict(
        check_id="relayed_principal_self_write",
        status="warning",
        observed="unknown (confirmed at execution)",
        why="Whether the relayed principal can write its own attribute is confirmed "
        "only at execution.",
        remediation=None,
        confidence=SignalConfidence.LOW,
    )


# --------------------------------------------------------------------------- #
# Confidence helpers
# --------------------------------------------------------------------------- #

_CONFIDENCE_RANK = {
    SignalConfidence.LOW: 0,
    SignalConfidence.MEDIUM: 1,
    SignalConfidence.HIGH: 2,
}


def _weakest_confidence(*states: ConstraintState) -> SignalConfidence:
    """Return the weakest confidence across a set of constraint states.

    UNKNOWN constraints contribute LOW (we have no real evidence for them).
    """
    weakest = SignalConfidence.HIGH
    for state in states:
        conf = (
            SignalConfidence.LOW
            if state.effective_state is TriState.UNKNOWN
            else state.confidence
        )
        if _CONFIDENCE_RANK[conf] < _CONFIDENCE_RANK[weakest]:
            weakest = conf
    return weakest


# --------------------------------------------------------------------------- #
# Aggregator
# --------------------------------------------------------------------------- #

# The ordered set of checks the aggregator runs. Method-specific checks are
# included always; their status downgrades to a warning when the method does not
# match (so the operator still sees the fact without it being a hard blocker).
_CORE_CHECKS: tuple[RelayPrecondition, ...] = (
    check_ntlm_enabled,
    check_ntlmv1_or_cve1040,
    check_ldap_signing,
    check_ldap_channel_binding,
    check_ldaps_available,
    check_ldap_starttls_available,
    check_ldap_relay_target_viable,
    check_listener_reachable_from_victim,
)

_METHOD_CHECKS: tuple[RelayPrecondition, ...] = (
    check_adcs_pki_present,
    check_machine_account_quota,
)

_WARNING_CHECKS: tuple[RelayPrecondition, ...] = (
    check_relayed_principal_self_write,
    check_smb_signing_source,
    check_posture_confidence_low,
)


_TARGET_SUMMARY = {
    "ldap_389_dropmic": "via LDAP 389 + drop-the-MIC (signing not enforced)",
    "ldaps_636": "via LDAPS 636 (signing enforced, CBT no, LDAPS yes)",
    "ldap_389_starttls": "via LDAP 389 + StartTLS (signing enforced, LDAPS no, StartTLS yes)",
}


def evaluate_relay_feasibility(inputs: RelayFeasibilityInputs) -> RelayFeasibility:
    """Run the relevant checks and compose an overall go/no-go.

    Pure and deterministic given ``inputs``. Reads the posture snapshot once via
    :func:`get_posture` (the only thing read from posture; never re-detected)
    and runs every check over the resolved :class:`DomainPosture`.

    Args:
        inputs: Everything the framework reasons over (posture locator + the
            caller-supplied probe RESULTS).

    Returns:
        A :class:`RelayFeasibility` carrying ``viable``, the chosen relay
        ``target``, the ordered verdict list, and a one-line ``summary``.
    """
    posture = get_posture(inputs.domains_data, domain=inputs.domain)

    verdicts: list[FeasibilityVerdict] = []
    for check in (*_CORE_CHECKS, *_METHOD_CHECKS, *_WARNING_CHECKS):
        verdicts.append(check(posture, inputs))

    target = relay_target_for(posture)
    viable = not any(v.status == "blocking" for v in verdicts)

    if viable:
        target_phrase = _TARGET_SUMMARY.get(target, "via a viable relay target")
        summary = f"RELAY VIABLE -> {target_phrase}"
    else:
        # Surface the first blocking reason's remediation as the headline action.
        first_block = next((v for v in verdicts if v.status == "blocking"), None)
        if first_block is not None and first_block.remediation:
            summary = f"RELAY NOT VIABLE -> {first_block.why} {first_block.remediation}"
        elif first_block is not None:
            summary = f"RELAY NOT VIABLE -> {first_block.why}"
        else:  # pragma: no cover - defensive; viable is False only with a blocker
            summary = "RELAY NOT VIABLE"

    return RelayFeasibility(
        viable=viable,
        target=target,
        verdicts=verdicts,
        summary=summary,
    )
