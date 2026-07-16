"""Unified domain posture: single source of truth for environment constraints.

This module consolidates every observation ADscan makes about authentication
and protocol constraints discovered while talking to a target domain (NTLM
disabled, RC4 disabled, LDAP signing required, SMB signing required, LDAPS
unavailable, channel binding required, etc.) into one typed, persistent model.

Future PRs will:
- PR2-4: Have transports (kerberos/ldap/smb) emit ``PostureSignal`` instances
  instead of scattering ad-hoc detection.
- PR5: Render the "Intelligence Update" CLI panel from emitted
  ``IntelligenceFinding`` objects.
- PR6: Replace blind retry logic in ``auth_policy``/``auth_retry`` with
  posture-driven decisions read from this module.

PR1 (this module) is foundation only — it does NOT print, NOT decide, NOT
hook transports. It exposes a typed API and persists data alongside the
legacy ``auth_posture`` block in workspace ``domains_data``. The legacy API
(``auth_posture_service``) becomes a thin shim that delegates here while
preserving its public signatures byte-for-byte for existing callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Mapping, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug


# --------------------------------------------------------------------------- #
# Enums and value types
# --------------------------------------------------------------------------- #


class TriState(str, Enum):
    """Three-or-four-state knowledge of a posture constraint."""

    UNKNOWN = "unknown"
    ENABLED = "likely_enabled"
    DISABLED = "likely_disabled"
    REQUIRED = "likely_required"


class ConstraintCategory(str, Enum):
    """Canonical set of posture constraints. Add new entries here only."""

    NTLM_AUTHENTICATION = "ntlm_authentication"
    KERBEROS_RC4 = "kerberos_rc4"
    KERBEROS_AES_ONLY = "kerberos_aes_only"
    KERBEROS_ETYPE_PROBE = "kerberos_etype_probe_needed"
    LDAPS_AVAILABLE = "ldaps_available"
    LDAP_STARTTLS_AVAILABLE = "ldap_starttls_available"
    LDAP_SIGNING = "ldap_signing"
    LDAP_CHANNEL_BINDING = "ldap_channel_binding"
    SMB_SIGNING = "smb_signing"


class SignalConfidence(str, Enum):
    """How sure we are about a single observation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AdaptationOutcome(str, Enum):
    """How ADscan plans to react to a freshly-discovered constraint."""

    ADAPTED = "adapted"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


_CONFIDENCE_ORDER = {
    SignalConfidence.LOW: 0,
    SignalConfidence.MEDIUM: 1,
    SignalConfidence.HIGH: 2,
}

_MAX_EVIDENCE_PER_CONSTRAINT = 20

# Per-category freshness TTL. Reads older than this are treated as UNKNOWN by
# :attr:`ConstraintState.effective_state`. Persistence is unaffected — only the
# read-time view degrades. Values reflect how often the underlying signal can
# realistically change in a target environment: protocol-level toggles
# (NTLM/LDAP/SMB signing) are GPO-driven and may change daily, so 24h. KDC
# etype config changes far less often, so 7d.
_TTL_BY_CATEGORY: dict[ConstraintCategory, timedelta] = {
    ConstraintCategory.NTLM_AUTHENTICATION: timedelta(hours=24),
    ConstraintCategory.LDAP_SIGNING: timedelta(hours=24),
    ConstraintCategory.LDAP_CHANNEL_BINDING: timedelta(hours=24),
    ConstraintCategory.SMB_SIGNING: timedelta(hours=24),
    ConstraintCategory.LDAPS_AVAILABLE: timedelta(hours=24),
    # Same class as LDAPS_AVAILABLE: a per-service availability fact (the DC
    # may start/stop offering StartTLS on 389 when its cert is rotated), not a
    # structural crypto-migration fact — 24h, not 7d.
    ConstraintCategory.LDAP_STARTTLS_AVAILABLE: timedelta(hours=24),
    ConstraintCategory.KERBEROS_RC4: timedelta(days=7),
    ConstraintCategory.KERBEROS_AES_ONLY: timedelta(days=7),
    ConstraintCategory.KERBEROS_ETYPE_PROBE: timedelta(days=7),
}
_DEFAULT_TTL: timedelta = timedelta(hours=24)


def get_ttl(category: ConstraintCategory) -> timedelta:
    """Return the freshness TTL for a category (or ``_DEFAULT_TTL`` fallback)."""
    return _TTL_BY_CATEGORY.get(category, _DEFAULT_TTL)


@dataclass(frozen=True)
class PostureSignal:
    """One observation feeding the posture.

    Emitted by transports/integrations, not by users. The posture module
    interprets the signal and decides whether it warrants a finding.

    ``probe_schema_version`` records the version of the probe-code logic
    that generated this signal. Persisted alongside the constraint so
    future code can detect when the cached observation was produced by
    an obsolete version of the probe (see
    ``adscan_internal.services.posture_probe._PROBE_SCHEMA_VERSION``).
    Signals emitted by non-probe sources (transport reactive sinks,
    integration emits) should set this to ``None`` — the freshness
    check treats ``None`` as "version-agnostic" and trusts the cache
    until the natural TTL expires.
    """

    domain: str
    category: ConstraintCategory
    state: TriState
    confidence: SignalConfidence
    source: str
    signal_code: str
    message: str | None
    protocol: str | None
    observed_at: datetime
    probe_schema_version: Optional[int] = None


@dataclass(frozen=True)
class PostureEvidence:
    """One persisted evidence row inside a constraint history."""

    source: str
    signal_code: str
    message: str | None
    state: TriState
    confidence: SignalConfidence
    timestamp: str
    protocol: str | None


@dataclass
class ConstraintState:
    """Aggregated current state for one ``ConstraintCategory``.

    Freshness fields ``age`` and ``ttl_remaining`` are populated at read time
    by :func:`get_posture` / :func:`get_constraint`. They are NOT persisted.
    The persisted ``state`` always reflects the last observation; callers that
    make decisions should read :attr:`effective_state` instead, which collapses
    a stale observation to ``TriState.UNKNOWN`` so plan/decision code naturally
    falls back to the conservative baseline.
    """

    category: ConstraintCategory
    state: TriState = TriState.UNKNOWN
    confidence: SignalConfidence = SignalConfidence.LOW
    evidence: list[PostureEvidence] = field(default_factory=list)
    updated_at: str | None = None
    age: Optional[timedelta] = None
    ttl_remaining: Optional[timedelta] = None
    probe_schema_version: Optional[int] = None
    """Schema version of the probe-code that produced the current
    ``state`` / ``confidence``. Populated at read time by
    :func:`get_posture` from the persisted constraint record. Compared
    against the current ``_PROBE_SCHEMA_VERSION`` by callers to decide
    whether the cached observation is still trustworthy after a probe
    refactor — see :meth:`is_schema_outdated`.
    """

    def is_schema_outdated(self, current_version: int) -> bool:
        """True when this constraint was produced by an obsolete probe version.

        Compares the persisted ``probe_schema_version`` against the caller's
        current version (typically
        ``adscan_internal.services.posture_probe._PROBE_SCHEMA_VERSION``).

        Semantics:
          * ``None`` persisted version — the record predates schema-version
            tracking, OR was emitted by a non-probe source (transport
            reactive sink, integration emit). Treat as outdated when the
            caller expects probe output; the freshness guard re-probes and
            stamps a fresh version.
          * Numeric persisted version < ``current_version`` — explicit
            obsolescence after a probe-code change. Re-probe.
          * Numeric persisted version >= ``current_version`` — fresh. The
            >= covers the (unusual but harmless) case where a workspace was
            written by a newer build than the one currently reading it.

        Stale state is independent of schema obsolescence; both checks
        must pass for a probe to be skipped.
        """
        if self.probe_schema_version is None:
            return True
        return self.probe_schema_version < current_version

    @property
    def is_stale(self) -> bool:
        """True when state is non-UNKNOWN AND ttl_remaining is zero or below.

        ``UNKNOWN`` is never stale (there is nothing to expire). A constraint
        without a parseable ``updated_at`` (``ttl_remaining is None``) is also
        treated as fresh — there is no evidence it has expired.
        """
        if self.state is TriState.UNKNOWN:
            return False
        if self.ttl_remaining is None:
            return False
        return self.ttl_remaining <= timedelta(0)

    @property
    def effective_state(self) -> TriState:
        """``state`` when fresh, ``UNKNOWN`` when stale.

        Plan/decision code should read this instead of ``state`` so stale
        observations transparently degrade to the conservative baseline.
        """
        return TriState.UNKNOWN if self.is_stale else self.state


_PASSWORD_POLICY_TTL: timedelta = timedelta(seconds=60)
"""Cache TTL for :class:`PasswordPolicySnapshot`.

Intentionally short (60 s). The policy itself rarely changes mid-engagement,
but two operational concerns force a tight bound:

1. **Cosmetic scoring tolerates drift**. A stale ``min_length`` only mis-ranks
   findings, never silences them. 60 s is more than enough for ranking.
2. **Spraying does not tolerate drift**. ``lockout_threshold`` /
   ``lockout_window_minutes`` can change reactively (admin tightens GPO in
   response to suspicious activity). Cached lockout values that are stale by
   minutes can cause real account lockouts. Spray code paths must use
   ``force_fresh=True`` (see :func:`get_password_policy`) regardless of TTL.

Read the full rationale on the orchestrator integration step that introduced
the field — the snapshot covers two consumers (scoring vs spraying) with
different freshness requirements.
"""


@dataclass(frozen=True)
class PasswordPolicySnapshot:
    """Default Domain Password Policy detected via LDAP query.

    Reads the domain object's password and lockout attributes in a single
    LDAP round-trip. Two distinct consumer classes:

    * **Scoring** (cosmetic, reads ``min_length`` + ``require_complexity``):
      tolerates a stale snapshot up to :data:`_PASSWORD_POLICY_TTL`.
    * **Spraying** (operational, reads ``lockout_threshold`` +
      ``lockout_window_minutes``): MUST refuse stale snapshots. Use
      :func:`get_password_policy` with ``force_fresh=True`` before any spray
      batch — a stale lockout value can lock real customer accounts.

    Fields map directly to AD attributes on the domain object:

      - ``min_length``              ← ``minPwdLength``
      - ``require_complexity``      ← ``pwdProperties`` bit 0 (``DOMAIN_PASSWORD_COMPLEX`` = 0x01)
      - ``max_age_days``            ← ``maxPwdAge`` (FILETIME → days; informational)
      - ``lockout_threshold``       ← ``lockoutThreshold`` (0 means lockout disabled)
      - ``lockout_window_minutes``  ← ``lockoutObservationWindow`` (FILETIME → minutes)
      - ``lockout_duration_minutes``← ``lockoutDuration`` (FILETIME → minutes;
                                       0 means admin-unlock-only)
      - ``password_history_length`` ← ``pwdHistoryLength`` (None when not read)
      - ``minimum_password_age_days``← ``minPwdAge`` (FILETIME → days; None when
                                       not read)

    PSO (Password Settings Object) per-user policies are NOT in scope here —
    only the default domain policy.
    """

    min_length: int
    require_complexity: bool
    max_age_days: Optional[int]              # None means never-expires
    source: str                              # "ad_default_domain_policy" or "default_assumed"
    detected_at: datetime
    lockout_threshold: int = 0               # 0 means lockout disabled
    lockout_window_minutes: Optional[int] = None
    lockout_duration_minutes: Optional[int] = None
    password_history_length: Optional[int] = None  # None when not read; from pwdHistoryLength
    minimum_password_age_days: Optional[int] = None  # None when not read; from minPwdAge

    @property
    def lockout_enabled(self) -> bool:
        """True when the domain policy enforces a finite lockout threshold."""
        return self.lockout_threshold > 0

    def is_stale(self, *, now: Optional[datetime] = None) -> bool:
        """Return True when the snapshot is older than :data:`_PASSWORD_POLICY_TTL`.

        ``detected_at`` is expected to be timezone-aware (UTC). When it lacks a
        timezone the comparison is performed naive — that branch only happens
        for hand-built fixtures, never for probe output.
        """
        reference = now or datetime.now(timezone.utc)
        if self.detected_at.tzinfo is None and reference.tzinfo is not None:
            reference = reference.replace(tzinfo=None)
        elif self.detected_at.tzinfo is not None and reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        return (reference - self.detected_at) > _PASSWORD_POLICY_TTL


@dataclass(frozen=True)
class ResultantPasswordPolicy:
    """Resultant password policy effective for a principal (or the domain).

    Superset of :class:`PasswordPolicySnapshot`. Where ``PasswordPolicySnapshot``
    only models the Default Domain Password Policy, this type also carries the
    fields that matter when a Fine-Grained Password Policy (PSO) governs the
    target principal and the fields a password-CHANGE (vs admin reset) must
    respect (``history_length`` + ``min_pwd_age_days``).

    It is the single value type returned by
    :func:`adscan_internal.services.posture_probe.resolve_resultant_password_policy`
    and consumed by the policy-driven generator/validator in
    :mod:`adscan_internal.passwords`.

    Field provenance:

      - ``min_length``            ← ``minPwdLength`` / ``msDS-MinimumPasswordLength``
      - ``max_length``            ← AD has no maximum; ``None`` unless a quirk sets one
      - ``require_complexity``    ← ``pwdProperties`` bit 0 / ``msDS-PasswordComplexityEnabled``
      - ``required_classes``      ← AD complexity rule: 3 of {lower, upper, digit,
                                    symbol, unicode} when complexity is required
      - ``history_length``        ← ``pwdHistoryLength`` / ``msDS-PasswordHistoryLength``
      - ``min_pwd_age_days``      ← ``minPwdAge`` / ``msDS-MinimumPasswordAge``
      - ``max_pwd_age_days``      ← ``maxPwdAge`` / ``msDS-MaximumPasswordAge``
      - ``lockout_threshold``     ← ``lockoutThreshold`` / ``msDS-LockoutThreshold``
      - ``lockout_window_minutes``← ``lockoutObservationWindow`` / ``msDS-LockoutObservationWindow``
      - ``lockout_duration_minutes``← ``lockoutDuration`` / ``msDS-LockoutDuration``
      - ``source``                ← provenance of this policy (see below)
      - ``pso_dn``                ← winning PSO DN when ``source == "live_pso"``
      - ``detected_at``           ← UTC timestamp the policy was resolved

    ``source`` is one of:

      * ``"live_pso"``            — a PSO governs the target principal (live LDAP)
      * ``"live_default_domain"`` — Default Domain Policy read live via LDAP
      * ``"collector"``           — derived from a persisted collector artifact
      * ``"default_assumed"``     — no policy available; strong safe default
    """

    min_length: int
    require_complexity: bool
    required_classes: int
    source: str
    detected_at: datetime
    max_length: Optional[int] = None
    history_length: Optional[int] = None
    min_pwd_age_days: Optional[int] = None
    max_pwd_age_days: Optional[int] = None
    lockout_threshold: int = 0
    lockout_window_minutes: Optional[int] = None
    lockout_duration_minutes: Optional[int] = None
    pso_dn: Optional[str] = None

    @property
    def lockout_enabled(self) -> bool:
        """True when a finite lockout threshold is enforced."""
        return self.lockout_threshold > 0


@dataclass
class DomainPosture:
    """Aggregated posture for one domain across all categories."""

    domain: str
    constraints: dict[ConstraintCategory, ConstraintState] = field(default_factory=dict)
    updated_at: str | None = None
    password_policy: Optional[PasswordPolicySnapshot] = field(default=None)

    def get(self, category: ConstraintCategory) -> ConstraintState:
        """Return the constraint, or a fresh UNKNOWN entry if none recorded."""
        existing = self.constraints.get(category)
        if existing is not None:
            return existing
        return ConstraintState(category=category)

    def is_known(self, category: ConstraintCategory) -> bool:
        """True if the constraint has moved away from ``UNKNOWN``."""
        return self.get(category).state is not TriState.UNKNOWN


@dataclass(frozen=True)
class IntelligenceFinding:
    """First-time / upgraded discovery of a posture constraint.

    The posture module emits these but never prints them. The CLI/UI consumer
    (PR5: Intelligence Update panel) is responsible for rendering.
    """

    domain: str
    category: ConstraintCategory
    state: TriState
    evidence_signal_code: str
    evidence_message: str | None
    evidence_source: str
    suggested_outcome: AdaptationOutcome
    suggested_action: str
    persisted: bool
    detected_at: datetime


# --------------------------------------------------------------------------- #
# Locked finding copy. Single place to edit user-visible adaptation strings.
# --------------------------------------------------------------------------- #


_FINDING_CONFIG: dict[
    tuple[ConstraintCategory, TriState], tuple[AdaptationOutcome, str]
] = {
    (ConstraintCategory.NTLM_AUTHENTICATION, TriState.DISABLED): (
        AdaptationOutcome.ADAPTED,
        "Switching to Kerberos-only auth for this domain",
    ),
    (ConstraintCategory.KERBEROS_RC4, TriState.DISABLED): (
        AdaptationOutcome.ADAPTED,
        "AES-only Kerberos detected — RC4 paths skipped",
    ),
    (ConstraintCategory.LDAPS_AVAILABLE, TriState.DISABLED): (
        AdaptationOutcome.ADAPTED,
        "LDAPS unavailable — using LDAP with signing where required",
    ),
    (ConstraintCategory.LDAP_SIGNING, TriState.REQUIRED): (
        AdaptationOutcome.ADAPTED,
        "LDAP signing enforced — binds will negotiate signing",
    ),
    (ConstraintCategory.LDAP_CHANNEL_BINDING, TriState.REQUIRED): (
        AdaptationOutcome.ADAPTED,
        "LDAPS channel binding required — CBT enabled for binds",
    ),
    (ConstraintCategory.SMB_SIGNING, TriState.REQUIRED): (
        AdaptationOutcome.ADAPTED,
        "SMB signing required — relay vectors will be flagged accordingly",
    ),
}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def get_posture(
    domains_data: Mapping[str, Any] | None,
    *,
    domain: str,
    now_fn: Callable[[], datetime] | None = None,
) -> DomainPosture:
    """Read the unified posture for ``domain`` from workspace data.

    Hydrates legacy ``ntlm`` / ``kerberos.rc4_status`` blocks transparently for
    workspaces saved before the unified model existed.

    Args:
        domains_data: The workspace's ``domains_data`` mapping (may be ``None``).
        domain: Target domain name (case-insensitive lookup).

    Returns:
        A ``DomainPosture``; constraints absent from storage default to
        ``UNKNOWN`` state.
    """
    posture = DomainPosture(domain=str(domain or "").strip())
    domain_entry = _get_domain_entry(domains_data, domain)
    if not isinstance(domain_entry, Mapping):
        return posture

    auth_posture = domain_entry.get("auth_posture")
    if not isinstance(auth_posture, Mapping):
        return posture

    posture.updated_at = _coerce_str(auth_posture.get("updated_at"))

    constraints_block = auth_posture.get("constraints")
    if isinstance(constraints_block, Mapping):
        for raw_key, raw_value in constraints_block.items():
            category = _coerce_category(raw_key)
            if category is None or not isinstance(raw_value, Mapping):
                continue
            posture.constraints[category] = _deserialize_constraint(category, raw_value)

    _hydrate_from_legacy(posture, auth_posture)
    _hydrate_password_policy(posture, auth_posture)
    _annotate_freshness(posture, now_fn=now_fn)
    return posture


def get_constraint(
    domains_data: Mapping[str, Any] | None,
    *,
    domain: str,
    category: ConstraintCategory,
    now_fn: Callable[[], datetime] | None = None,
) -> ConstraintState:
    """Convenience wrapper returning a single ``ConstraintState``."""
    return get_posture(domains_data, domain=domain, now_fn=now_fn).get(category)


def update_posture(
    domains_data: dict[str, Any] | None,
    *,
    signal: PostureSignal,
) -> IntelligenceFinding | None:
    """Apply one posture signal and persist the result.

    Returns an ``IntelligenceFinding`` only on first transition from
    ``UNKNOWN`` to a known state (with confidence >= MEDIUM) or on a confidence
    upgrade from LOW to HIGH for the same state. Otherwise returns ``None``.

    Args:
        domains_data: Workspace ``domains_data`` mapping (mutated in place).
        signal: The observation to apply.

    Returns:
        An ``IntelligenceFinding`` when the change crosses a notification
        threshold, else ``None``.
    """
    if not isinstance(domains_data, dict):
        return None
    domain_key = str(signal.domain or "").strip()
    if not domain_key:
        return None

    try:
        domain_entry = domains_data.setdefault(domain_key, {})
        if not isinstance(domain_entry, dict):
            return None
        auth_posture = domain_entry.setdefault("auth_posture", {})
        if not isinstance(auth_posture, dict):
            return None
        constraints_block = auth_posture.setdefault("constraints", {})
        if not isinstance(constraints_block, dict):
            return None

        prev_raw = constraints_block.get(signal.category.value)
        prev_state = _coerce_state(
            (prev_raw or {}).get("state") if isinstance(prev_raw, dict) else None
        )
        prev_confidence = _coerce_confidence(
            (prev_raw or {}).get("confidence") if isinstance(prev_raw, dict) else None
        )
        prev_evidence: list[Any] = []
        if isinstance(prev_raw, dict):
            existing_evidence = prev_raw.get("evidence")
            if isinstance(existing_evidence, list):
                prev_evidence = list(existing_evidence)

        # Resolve the resulting (state, confidence) honoring conflict rules.
        resolved_state, resolved_confidence = _resolve_state_transition(
            prev_state=prev_state,
            prev_confidence=prev_confidence,
            new_state=signal.state,
            new_confidence=signal.confidence,
        )

        timestamp = _utc_now_iso()
        evidence_entry = {
            "source": signal.source or "unknown",
            "signal_code": signal.signal_code or "unknown",
            "message": signal.message,
            "state": signal.state.value,
            "confidence": signal.confidence.value,
            "timestamp": timestamp,
            "protocol": signal.protocol,
        }
        prev_evidence.append(evidence_entry)
        if len(prev_evidence) > _MAX_EVIDENCE_PER_CONSTRAINT:
            del prev_evidence[:-_MAX_EVIDENCE_PER_CONSTRAINT]

        # Carry the schema version forward when the incoming signal sets
        # one. Signals from non-probe sources (transport reactive sinks,
        # integration emits) pass ``None`` — in that case we PRESERVE
        # whatever version was already on the persisted record rather
        # than overwriting it with ``None``. Otherwise a single reactive
        # emit (e.g. a posture-signal raised by the LDAP transport on an
        # ``invalidCredentials`` failure mid-scan) would wipe the version
        # stamped by the most recent probe and force unnecessary
        # re-probes.
        if signal.probe_schema_version is not None:
            persisted_version: Optional[int] = signal.probe_schema_version
        else:
            persisted_version = _coerce_schema_version(
                (prev_raw or {}).get("probe_schema_version")
                if isinstance(prev_raw, dict)
                else None
            )

        constraint_record: dict[str, Any] = {
            "state": resolved_state.value,
            "confidence": resolved_confidence.value,
            "evidence": prev_evidence,
            "updated_at": timestamp,
        }
        if persisted_version is not None:
            constraint_record["probe_schema_version"] = persisted_version
        constraints_block[signal.category.value] = constraint_record
        auth_posture["updated_at"] = timestamp

        # Mirror to legacy keys for the two categories that have a legacy block.
        _mirror_to_legacy(
            auth_posture,
            category=signal.category,
            state=signal.state,
            source=signal.source,
            signal_code=signal.signal_code,
            message=signal.message,
            protocol=signal.protocol,
            timestamp=timestamp,
        )

        finding = _maybe_build_finding(
            domain=domain_key,
            category=signal.category,
            prev_state=prev_state,
            prev_confidence=prev_confidence,
            resolved_state=resolved_state,
            resolved_confidence=resolved_confidence,
            signal=signal,
        )
        if finding is not None:
            print_info_debug(
                f"[domain_posture] finding emitted: domain={domain_key} "
                f"category={signal.category.value} state={resolved_state.value}"
            )
        return finding
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        return None


def persist_password_policy(
    domains_data: dict[str, Any] | None,
    *,
    domain: str,
    snapshot: "PasswordPolicySnapshot",
) -> None:
    """Persist a :class:`PasswordPolicySnapshot` into workspace ``domains_data``.

    Stores the snapshot under ``domains_data[domain]["auth_posture"]["password_policy"]``
    so it is included in the next workspace save and can be hydrated back via
    :func:`get_posture`.

    Args:
        domains_data: The workspace's ``domains_data`` mapping (mutated in place).
        domain: Target domain name.
        snapshot: The snapshot to persist.
    """
    if not isinstance(domains_data, dict):
        return
    domain_key = str(domain or "").strip()
    if not domain_key:
        return
    try:
        domain_entry = domains_data.setdefault(domain_key, {})
        if not isinstance(domain_entry, dict):
            return
        auth_posture = domain_entry.setdefault("auth_posture", {})
        if not isinstance(auth_posture, dict):
            return
        auth_posture["password_policy"] = {
            "min_length": snapshot.min_length,
            "require_complexity": snapshot.require_complexity,
            "max_age_days": snapshot.max_age_days,
            "source": snapshot.source,
            "detected_at": snapshot.detected_at.isoformat(),
            "lockout_threshold": snapshot.lockout_threshold,
            "lockout_window_minutes": snapshot.lockout_window_minutes,
            "lockout_duration_minutes": snapshot.lockout_duration_minutes,
            "password_history_length": snapshot.password_history_length,
            "minimum_password_age_days": snapshot.minimum_password_age_days,
        }
        print_info_debug(
            f"[domain_posture] password_policy persisted: domain={domain_key} "
            f"min_length={snapshot.min_length} "
            f"require_complexity={snapshot.require_complexity} "
            f"lockout_threshold={snapshot.lockout_threshold}"
        )
    except Exception as exc:  # noqa: BLE001 - defensive
        telemetry.capture_exception(exc)


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def _hydrate_password_policy(
    posture: "DomainPosture", auth_posture: Mapping[str, Any]
) -> None:
    """Populate ``posture.password_policy`` from the stored ``auth_posture`` block.

    Called from :func:`get_posture` after the main constraints block is loaded.
    Deserializes the dict stored by :func:`persist_password_policy` back into a
    :class:`PasswordPolicySnapshot`.  Silently ignored when the block is absent
    or malformed (backward compat with workspaces saved before Phase B).
    """
    raw = auth_posture.get("password_policy")
    if not isinstance(raw, Mapping):
        return
    try:
        detected_at_raw = raw.get("detected_at")
        if detected_at_raw:
            from datetime import timezone  # noqa: PLC0415 – deferred

            detected_at = _parse_iso_utc(str(detected_at_raw))
            if detected_at is None:
                detected_at = datetime.now(timezone.utc)
        else:
            from datetime import timezone  # noqa: PLC0415 – deferred

            detected_at = datetime.now(timezone.utc)

        min_length = raw.get("min_length")
        require_complexity = raw.get("require_complexity")
        max_age_days = raw.get("max_age_days")
        source = raw.get("source") or "ad_default_domain_policy"

        if min_length is None or require_complexity is None:
            return

        lockout_threshold_raw = raw.get("lockout_threshold")
        lockout_window_raw = raw.get("lockout_window_minutes")
        lockout_duration_raw = raw.get("lockout_duration_minutes")
        history_length_raw = raw.get("password_history_length")
        min_age_raw = raw.get("minimum_password_age_days")

        posture.password_policy = PasswordPolicySnapshot(
            min_length=int(min_length),
            require_complexity=bool(require_complexity),
            max_age_days=int(max_age_days) if max_age_days is not None else None,
            source=str(source),
            detected_at=detected_at,
            lockout_threshold=int(lockout_threshold_raw) if lockout_threshold_raw is not None else 0,
            lockout_window_minutes=(
                int(lockout_window_raw) if lockout_window_raw is not None else None
            ),
            lockout_duration_minutes=(
                int(lockout_duration_raw) if lockout_duration_raw is not None else None
            ),
            password_history_length=(
                int(history_length_raw) if history_length_raw is not None else None
            ),
            minimum_password_age_days=(
                int(min_age_raw) if min_age_raw is not None else None
            ),
        )
    except Exception as exc:  # noqa: BLE001 - defensive
        telemetry.capture_exception(exc)


def _resolve_state_transition(
    *,
    prev_state: TriState,
    prev_confidence: SignalConfidence,
    new_state: TriState,
    new_confidence: SignalConfidence,
) -> tuple[TriState, SignalConfidence]:
    """Apply conflict-resolution rules described in the PR brief."""
    if prev_state is TriState.UNKNOWN:
        return new_state, new_confidence
    if new_state == prev_state:
        # Same state — keep highest confidence seen so far.
        if _CONFIDENCE_ORDER[new_confidence] > _CONFIDENCE_ORDER[prev_confidence]:
            return new_state, new_confidence
        return prev_state, prev_confidence
    # Conflict: different states.
    if _CONFIDENCE_ORDER[new_confidence] > _CONFIDENCE_ORDER[prev_confidence]:
        return new_state, new_confidence
    if _CONFIDENCE_ORDER[new_confidence] < _CONFIDENCE_ORDER[prev_confidence]:
        return prev_state, prev_confidence
    # Equal confidence: most recent wins.
    return new_state, new_confidence


def _maybe_build_finding(
    *,
    domain: str,
    category: ConstraintCategory,
    prev_state: TriState,
    prev_confidence: SignalConfidence,
    resolved_state: TriState,
    resolved_confidence: SignalConfidence,
    signal: PostureSignal,
) -> IntelligenceFinding | None:
    """Decide whether the transition warrants surfacing to the user."""
    config = _FINDING_CONFIG.get((category, resolved_state))
    if config is None:
        return None

    crossed_unknown = (
        prev_state is TriState.UNKNOWN
        and resolved_state is not TriState.UNKNOWN
        and _CONFIDENCE_ORDER[resolved_confidence]
        >= _CONFIDENCE_ORDER[SignalConfidence.MEDIUM]
    )
    confidence_upgrade = (
        prev_state == resolved_state
        and prev_confidence is SignalConfidence.LOW
        and resolved_confidence is SignalConfidence.HIGH
    )

    if not (crossed_unknown or confidence_upgrade):
        return None

    outcome, action = config
    return IntelligenceFinding(
        domain=domain,
        category=category,
        state=resolved_state,
        evidence_signal_code=signal.signal_code or "unknown",
        evidence_message=signal.message,
        evidence_source=signal.source or "unknown",
        suggested_outcome=outcome,
        suggested_action=action,
        persisted=True,
        detected_at=signal.observed_at,
    )


def _mirror_to_legacy(
    auth_posture: dict[str, Any],
    *,
    category: ConstraintCategory,
    state: TriState,
    source: str,
    signal_code: str,
    message: str | None,
    protocol: str | None,
    timestamp: str,
) -> None:
    """Mirror NTLM and RC4 categories into their pre-existing legacy blocks."""
    if category is ConstraintCategory.NTLM_AUTHENTICATION:
        if state not in (TriState.ENABLED, TriState.DISABLED):
            return
        ntlm = auth_posture.setdefault("ntlm", {})
        if not isinstance(ntlm, dict):
            return
        new_status = state.value
        protocol_key = (protocol or "").strip().lower()
        if protocol_key:
            protocols = ntlm.setdefault("protocols", {})
            if isinstance(protocols, dict):
                protocols[protocol_key] = new_status

        current_domain = str(ntlm.get("domain_status") or "unknown").strip().lower()
        if current_domain not in ("unknown", "likely_enabled", "likely_disabled"):
            current_domain = "unknown"
        if current_domain == "unknown":
            ntlm["domain_status"] = new_status
        # else: do not flip an already-decided domain status (matches legacy merge rule).
        ntlm["updated_at"] = timestamp
        evidence = ntlm.setdefault("evidence", [])
        if isinstance(evidence, list):
            evidence.append(
                {
                    "source": source or "unknown",
                    "protocol": protocol_key or None,
                    "signal": signal_code or "unknown",
                    "message": (message or None),
                    "status": new_status,
                    "timestamp": timestamp,
                }
            )
            if len(evidence) > _MAX_EVIDENCE_PER_CONSTRAINT:
                del evidence[:-_MAX_EVIDENCE_PER_CONSTRAINT]
    elif category is ConstraintCategory.KERBEROS_RC4:
        if state is not TriState.DISABLED:
            return
        kerberos = auth_posture.setdefault("kerberos", {})
        if not isinstance(kerberos, dict):
            return
        kerberos["rc4_status"] = "likely_disabled"
        kerberos["updated_at"] = timestamp
        evidence = kerberos.setdefault("evidence", [])
        if isinstance(evidence, list):
            evidence.append(
                {
                    "source": source or "unknown",
                    "signal": signal_code or "KDC_ERR_ETYPE_NOSUPP",
                    "message": (message or None),
                    "status": "likely_disabled",
                    "timestamp": timestamp,
                }
            )
            if len(evidence) > _MAX_EVIDENCE_PER_CONSTRAINT:
                del evidence[:-_MAX_EVIDENCE_PER_CONSTRAINT]


def _hydrate_from_legacy(
    posture: DomainPosture, auth_posture: Mapping[str, Any]
) -> None:
    """Populate constraints from legacy ``ntlm`` / ``kerberos`` blocks if absent."""
    ntlm = auth_posture.get("ntlm")
    if (
        isinstance(ntlm, Mapping)
        and ConstraintCategory.NTLM_AUTHENTICATION not in posture.constraints
    ):
        domain_status = str(ntlm.get("domain_status") or "unknown").strip().lower()
        state = _coerce_state(domain_status)
        if state is not TriState.UNKNOWN:
            posture.constraints[ConstraintCategory.NTLM_AUTHENTICATION] = (
                ConstraintState(
                    category=ConstraintCategory.NTLM_AUTHENTICATION,
                    state=state,
                    confidence=SignalConfidence.MEDIUM,
                    evidence=_legacy_evidence_to_typed(ntlm.get("evidence")),
                    updated_at=_coerce_str(ntlm.get("updated_at")),
                )
            )

    kerberos = auth_posture.get("kerberos")
    if (
        isinstance(kerberos, Mapping)
        and ConstraintCategory.KERBEROS_RC4 not in posture.constraints
    ):
        rc4_status = str(kerberos.get("rc4_status") or "unknown").strip().lower()
        state = _coerce_state(rc4_status)
        if state is TriState.DISABLED:
            posture.constraints[ConstraintCategory.KERBEROS_RC4] = ConstraintState(
                category=ConstraintCategory.KERBEROS_RC4,
                state=state,
                confidence=SignalConfidence.HIGH,
                evidence=_legacy_evidence_to_typed(kerberos.get("evidence")),
                updated_at=_coerce_str(kerberos.get("updated_at")),
            )


def _legacy_evidence_to_typed(raw: Any) -> list[PostureEvidence]:
    """Convert legacy evidence dicts into typed evidence entries."""
    out: list[PostureEvidence] = []
    if not isinstance(raw, list):
        return out
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        out.append(
            PostureEvidence(
                source=str(entry.get("source") or "unknown"),
                signal_code=str(
                    entry.get("signal") or entry.get("signal_code") or "unknown"
                ),
                message=_coerce_str(entry.get("message")),
                state=_coerce_state(entry.get("status") or entry.get("state")),
                confidence=_coerce_confidence(entry.get("confidence")),
                timestamp=str(entry.get("timestamp") or ""),
                protocol=_coerce_str(entry.get("protocol")),
            )
        )
    return out


def _deserialize_constraint(
    category: ConstraintCategory,
    raw: Mapping[str, Any],
) -> ConstraintState:
    """Build a typed ``ConstraintState`` from on-disk dict form."""
    evidence_list: list[PostureEvidence] = []
    raw_evidence = raw.get("evidence")
    if isinstance(raw_evidence, list):
        for entry in raw_evidence:
            if not isinstance(entry, Mapping):
                continue
            evidence_list.append(
                PostureEvidence(
                    source=str(entry.get("source") or "unknown"),
                    signal_code=str(
                        entry.get("signal_code") or entry.get("signal") or "unknown"
                    ),
                    message=_coerce_str(entry.get("message")),
                    state=_coerce_state(entry.get("state") or entry.get("status")),
                    confidence=_coerce_confidence(entry.get("confidence")),
                    timestamp=str(entry.get("timestamp") or ""),
                    protocol=_coerce_str(entry.get("protocol")),
                )
            )
    return ConstraintState(
        category=category,
        state=_coerce_state(raw.get("state")),
        confidence=_coerce_confidence(raw.get("confidence")),
        evidence=evidence_list,
        updated_at=_coerce_str(raw.get("updated_at")),
        probe_schema_version=_coerce_schema_version(raw.get("probe_schema_version")),
    )


def _coerce_schema_version(value: Any) -> Optional[int]:
    """Best-effort coercion of the persisted schema-version integer.

    Persisted constraints predating the schema-version field will have no
    ``probe_schema_version`` key — ``raw.get(...)`` returns ``None`` and
    we propagate that. A future read can then call
    ``ConstraintState.is_schema_outdated(_PROBE_SCHEMA_VERSION)`` to
    detect those legacy records and force a re-probe.
    """
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_state(value: Any) -> TriState:
    """Best-effort coercion to ``TriState``."""
    if isinstance(value, TriState):
        return value
    text = str(value or "").strip().lower()
    for member in TriState:
        if member.value == text:
            return member
    return TriState.UNKNOWN


def _coerce_confidence(value: Any) -> SignalConfidence:
    """Best-effort coercion to ``SignalConfidence`` (defaults LOW)."""
    if isinstance(value, SignalConfidence):
        return value
    text = str(value or "").strip().lower()
    for member in SignalConfidence:
        if member.value == text:
            return member
    return SignalConfidence.LOW


def _coerce_category(value: Any) -> ConstraintCategory | None:
    """Coerce a stored key to ``ConstraintCategory`` or ``None`` if unknown."""
    if isinstance(value, ConstraintCategory):
        return value
    text = str(value or "").strip().lower()
    for member in ConstraintCategory:
        if member.value == text:
            return member
    return None


def _coerce_str(value: Any) -> str | None:
    """Strip-and-coerce to non-empty string, else ``None``."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _get_domain_entry(
    domains_data: Mapping[str, Any] | None,
    domain: str | None,
) -> Mapping[str, Any] | None:
    """Resolve one domain entry from a case-insensitive ``domains_data`` map."""
    if not isinstance(domains_data, Mapping):
        return None
    domain_key = str(domain or "").strip()
    if not domain_key:
        return None
    if domain_key in domains_data:
        entry = domains_data.get(domain_key)
        return entry if isinstance(entry, Mapping) else None
    normalized = domain_key.casefold()
    for key, value in domains_data.items():
        if str(key).strip().casefold() == normalized and isinstance(value, Mapping):
            return value
    return None


def _annotate_freshness(
    posture: DomainPosture,
    *,
    now_fn: Callable[[], datetime] | None,
) -> None:
    """Populate ``age`` and ``ttl_remaining`` on every constraint at read time.

    Constraints with ``state == UNKNOWN`` or unparseable ``updated_at`` are
    left with ``age=None`` and ``ttl_remaining=None`` — there is nothing to
    expire and :attr:`ConstraintState.is_stale` will report ``False``.

    Negative ``ttl_remaining`` is clamped to zero so consumers do not see
    decreasing-into-the-past durations.
    """
    now = (now_fn or _utc_now)()
    for entry in posture.constraints.values():
        if entry.state is TriState.UNKNOWN:
            entry.age = None
            entry.ttl_remaining = None
            continue
        ts = _parse_iso_utc(entry.updated_at)
        if ts is None:
            entry.age = None
            entry.ttl_remaining = None
            continue
        age = now - ts
        if age < timedelta(0):
            age = timedelta(0)
        ttl = get_ttl(entry.category)
        remaining = ttl - age
        if remaining < timedelta(0):
            remaining = timedelta(0)
        entry.age = age
        entry.ttl_remaining = remaining


def _utc_now() -> datetime:
    """Return current UTC time. Indirection point for tests."""
    return datetime.now(timezone.utc)


def _parse_iso_utc(value: str | None) -> datetime | None:
    """Parse a stored ISO-8601 timestamp into a UTC datetime, or ``None``."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()
