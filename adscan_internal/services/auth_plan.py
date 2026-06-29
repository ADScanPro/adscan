"""Posture-driven authentication planner (PR6b + PR9).

This module is **pure logic**. Given an :class:`ADscanLDAPConfig` (credential
intent + transport preference) and an optional :class:`DomainPosture`
(persisted environment knowledge), it returns an ordered
:class:`LDAPAuthPlan` describing exactly which ``(transport, auth_scheme)``
combinations the LDAP transport should attempt.

It also provides :func:`build_kerberos_plan` (PR9), which produces a
:class:`KerberosAuthPlan` describing posture-driven etype selection and
etype-probe decisions for :mod:`kerberos_transport`.

Design contract:

- **No I/O, no logging, no rich output.** The planner only constructs typed
  data. Callers (the transports) consume the plan.
- **UNKNOWN baseline = today's behaviour.** When ``posture is None`` or the
  relevant constraints are all UNKNOWN, the plan equals the conservative
  retry chain that the legacy speculative loop produced.
- **High-confidence pruning.** When the posture has high-confidence evidence,
  impossible attempts are marked as ``skipped`` and removed from ``attempts``.

See ``docs`` in PR6b brief for the LDAP pruning matrix and PR9 brief for the
Kerberos plan rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    DomainPosture,
    SignalConfidence,
    TriState,
)
from adscan_internal.services.auth_error_classification import (
    NATIVE_KERBEROS_INFRA_ERROR_MARKERS,
)

if TYPE_CHECKING:  # pragma: no cover - import-time decoupling only
    from adscan_internal.services.ldap_transport_service import ADscanLDAPConfig
    from adscan_internal.services.kerberos_transport import KerberosConfig


# --------------------------------------------------------------------------- #
# Global auth policy
# --------------------------------------------------------------------------- #

KERBEROS_FIRST_POLICY: bool = True

KERBEROS_INFRA_ERROR_MARKERS: tuple[str, ...] = NATIVE_KERBEROS_INFRA_ERROR_MARKERS


# --------------------------------------------------------------------------- #
# Enums and value types
# --------------------------------------------------------------------------- #


class LDAPTransport(str, Enum):
    """LDAP transport flavour for one bind attempt."""

    LDAPS = "ldaps"
    LDAP = "ldap"


class LDAPAuthScheme(str, Enum):
    """Authentication scheme for one bind attempt.

    These mirror the URL ``+kerberos-*`` / ``+ntlm-*`` flavours produced by
    :func:`adscan_internal.services.ldap_transport_service._build_ldap_connection_url`.
    """

    KERBEROS_CCACHE = "kerberos_ccache"
    KERBEROS_AES = "kerberos_aes"
    KERBEROS_PASSWORD = "kerberos_password"
    KERBEROS_RC4 = "kerberos_rc4"  # NT hash via Kerberos
    PASSWORD = "password"  # raw NTLM bind with plaintext password
    NT_HASH = "nt_hash"  # raw NTLM bind with NT hash (pass-the-hash)


_KERBEROS_SCHEMES = frozenset(
    {
        LDAPAuthScheme.KERBEROS_CCACHE,
        LDAPAuthScheme.KERBEROS_AES,
        LDAPAuthScheme.KERBEROS_PASSWORD,
        LDAPAuthScheme.KERBEROS_RC4,
    }
)

_NTLM_SCHEMES = frozenset({LDAPAuthScheme.PASSWORD, LDAPAuthScheme.NT_HASH})


@dataclass(frozen=True)
class LDAPAuthAttempt:
    """A single ``(transport, auth_scheme)`` LDAP bind attempt."""

    transport: LDAPTransport
    auth_scheme: LDAPAuthScheme
    channel_binding: bool
    sign: bool
    rationale: str


@dataclass(frozen=True)
class LDAPAuthPlan:
    """Ordered plan of LDAP bind attempts plus skipped/empty bookkeeping."""

    attempts: list[LDAPAuthAttempt] = field(default_factory=list)
    skipped: list[tuple[LDAPAuthAttempt, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """True when there is no viable attempt left to try."""
        return not self.attempts

    @property
    def is_pruned(self) -> bool:
        """True when at least one attempt was skipped vs the conservative baseline."""
        return bool(self.skipped)


class NoViableLDAPAuthError(Exception):
    """Raised by callers when the posture rules out every credential we have."""


# --------------------------------------------------------------------------- #
# Planner
# --------------------------------------------------------------------------- #


def _select_primary_auth_scheme(config: "ADscanLDAPConfig") -> LDAPAuthScheme:
    """Pick the primary auth scheme from a config, mirroring URL-build priority.

    Priority order matches ``_build_ldap_connection_url`` AFTER the 2026-05
    hardening: an explicitly-passed ``config.ccache_path`` wins, but the bare
    ``$KRB5CCNAME`` fallback drops to the LAST slot — it only selects the ccache
    scheme when no aes_key / nt_hash / password was supplied. Reading
    ``$KRB5CCNAME`` ahead of explicit creds here (the old behaviour) made the
    planner pick ``KERBEROS_CCACHE`` even when the caller passed an explicit
    password/hash, mirroring the ambient-ccache principal-hijack at the URL
    builder. Final order: ccache_path > aes_key > nt_hash > password >
    $KRB5CCNAME.
    """
    import os as _os

    if config.use_kerberos:
        explicit_ccache = str(config.ccache_path or "").strip()
        if explicit_ccache:
            return LDAPAuthScheme.KERBEROS_CCACHE
        if config.aes_key:
            return LDAPAuthScheme.KERBEROS_AES
        password = str(config.password or "")
        if _looks_like_nt_hash(password):
            return LDAPAuthScheme.KERBEROS_RC4
        if password:
            return LDAPAuthScheme.KERBEROS_PASSWORD
        # No explicit credential material: only now consider the ambient
        # $KRB5CCNAME. When present, the URL builder will guard the principal
        # (see _kerberos_ccache_guard); the scheme is still ccache.
        if str(_os.environ.get("KRB5CCNAME") or "").strip():
            return LDAPAuthScheme.KERBEROS_CCACHE
        return LDAPAuthScheme.KERBEROS_PASSWORD

    password = str(config.password or "")
    if _looks_like_nt_hash(password):
        return LDAPAuthScheme.NT_HASH
    return LDAPAuthScheme.PASSWORD


def _looks_like_nt_hash(value: str) -> bool:
    """Return True if ``value`` is a 32-hex-char NT hash."""
    text = str(value or "")
    return len(text) == 32 and all(c in "0123456789abcdef" for c in text.lower())


def _build_conservative_attempts(
    config: "ADscanLDAPConfig",
) -> list[LDAPAuthAttempt]:
    """Build the UNKNOWN baseline — matches today's speculative retry chain.

    With ``use_ldaps=True``: LDAPS first, then plain LDAP fallback.
    With ``use_ldaps=False``: plain LDAP only.

    The auth scheme is the single primary scheme selected from the config —
    auth fallback (Kerberos→password) is the sync helper's territory and is
    layered separately by the caller.
    """
    primary = _select_primary_auth_scheme(config)
    rationale_baseline = "conservative baseline (posture UNKNOWN)"
    attempts: list[LDAPAuthAttempt] = []
    if config.use_ldaps:
        attempts.append(
            LDAPAuthAttempt(
                transport=LDAPTransport.LDAPS,
                auth_scheme=primary,
                channel_binding=bool(config.channel_binding),
                sign=bool(config.sign),
                rationale=rationale_baseline,
            )
        )
    attempts.append(
        LDAPAuthAttempt(
            transport=LDAPTransport.LDAP,
            auth_scheme=primary,
            channel_binding=False,  # CBT only meaningful on LDAPS
            sign=bool(config.sign),
            rationale=rationale_baseline,
        )
    )
    return attempts


def _has_high_confidence(state: TriState, confidence: SignalConfidence) -> bool:
    """Return True when a constraint has actionable high-confidence evidence."""
    return confidence is SignalConfidence.HIGH and state is not TriState.UNKNOWN


def build_ldap_auth_plan(
    *,
    config: "ADscanLDAPConfig",
    posture: DomainPosture | None,
) -> LDAPAuthPlan:
    """Produce an ordered :class:`LDAPAuthPlan` for ``config`` honoring ``posture``.

    Args:
        config: The :class:`ADscanLDAPConfig` describing the credential and
            transport intent. Mutated only via dataclass replace at call sites
            — this function returns plans, never modified configs.
        posture: Optional :class:`DomainPosture`. When ``None`` or all
            relevant constraints are UNKNOWN, returns the conservative
            baseline (today's behaviour). When high-confidence evidence is
            present, prunes impossible/wasteful attempts.

    Returns:
        An :class:`LDAPAuthPlan` whose ``attempts`` is the ordered try-list,
        ``skipped`` records dropped attempts with rationales, and ``notes``
        carries plan-level commentary.
    """
    skipped: list[tuple[LDAPAuthAttempt, str]] = []
    notes: list[str] = []

    attempts = _build_conservative_attempts(config)

    if posture is None:
        return LDAPAuthPlan(attempts=attempts, skipped=skipped, notes=notes)

    ldaps_state = posture.get(ConstraintCategory.LDAPS_AVAILABLE)
    cbt_state = posture.get(ConstraintCategory.LDAP_CHANNEL_BINDING)
    signing_state = posture.get(ConstraintCategory.LDAP_SIGNING)
    ntlm_state = posture.get(ConstraintCategory.NTLM_AUTHENTICATION)
    rc4_state = posture.get(ConstraintCategory.KERBEROS_RC4)

    # 1. LDAPS availability filter.
    if _has_high_confidence(ldaps_state.effective_state, ldaps_state.confidence):
        if ldaps_state.effective_state is TriState.DISABLED:
            ts = ldaps_state.updated_at or "n/a"
            reason = (
                f"posture: LDAPS_AVAILABLE=DISABLED ({ts}) — DC does not expose LDAPS"
            )
            kept: list[LDAPAuthAttempt] = []
            for att in attempts:
                if att.transport is LDAPTransport.LDAPS:
                    skipped.append((att, reason))
                else:
                    kept.append(att)
            attempts = kept

    # 2. Channel-binding requirement (only meaningful for remaining LDAPS).
    if (
        _has_high_confidence(cbt_state.effective_state, cbt_state.confidence)
        and cbt_state.effective_state is TriState.REQUIRED
    ):
        ts = cbt_state.updated_at or "n/a"
        cbt_reason = (
            f"posture: LDAP_CHANNEL_BINDING=REQUIRED ({ts}) — forcing CBT on LDAPS"
        )
        attempts = [
            (
                _replace_attempt(att, channel_binding=True, rationale=cbt_reason)
                if att.transport is LDAPTransport.LDAPS and not att.channel_binding
                else att
            )
            for att in attempts
        ]

    # 3. LDAP signing requirement (only for plain LDAP attempts).
    if (
        _has_high_confidence(signing_state.effective_state, signing_state.confidence)
        and signing_state.effective_state is TriState.REQUIRED
    ):
        ts = signing_state.updated_at or "n/a"
        sign_reason = (
            f"posture: LDAP_SIGNING=REQUIRED ({ts}) — forcing signing on plain LDAP"
        )
        attempts = [
            (
                _replace_attempt(att, sign=True, rationale=sign_reason)
                if att.transport is LDAPTransport.LDAP and not att.sign
                else att
            )
            for att in attempts
        ]

    # 4. NTLM availability filter.
    if (
        _has_high_confidence(ntlm_state.effective_state, ntlm_state.confidence)
        and ntlm_state.effective_state is TriState.DISABLED
    ):
        ntlm_reason = "posture: NTLM_AUTHENTICATION=DISABLED — DC rejects NTLM binds"
        kept = []
        for att in attempts:
            if att.auth_scheme in _NTLM_SCHEMES:
                skipped.append((att, ntlm_reason))
            else:
                kept.append(att)
        attempts = kept

    # 5. Kerberos RC4 filter.
    if (
        _has_high_confidence(rc4_state.effective_state, rc4_state.confidence)
        and rc4_state.effective_state is TriState.DISABLED
    ):
        rc4_reason = "posture: KERBEROS_RC4=DISABLED — KDC rejects RC4 keys"
        kept = []
        for att in attempts:
            if att.auth_scheme is LDAPAuthScheme.KERBEROS_RC4:
                skipped.append((att, rc4_reason))
            else:
                kept.append(att)
        attempts = kept

    # 6. Empty-plan note.
    if not attempts:
        notes.append(
            "All viable LDAP auth combinations were ruled out by the posture. "
            "Provide additional credentials (ccache, AES key, or AES-eligible "
            "Kerberos password)."
        )

    # 7. Sort stability: LDAPS before LDAP, Kerberos before raw NTLM within
    # each transport. Stable sort preserves insertion order otherwise.
    attempts = _stable_sort_attempts(attempts)

    return LDAPAuthPlan(attempts=attempts, skipped=skipped, notes=notes)


def _replace_attempt(
    attempt: LDAPAuthAttempt,
    *,
    channel_binding: bool | None = None,
    sign: bool | None = None,
    rationale: str | None = None,
) -> LDAPAuthAttempt:
    """Return a frozen copy of ``attempt`` with selected fields overridden."""
    return LDAPAuthAttempt(
        transport=attempt.transport,
        auth_scheme=attempt.auth_scheme,
        channel_binding=(
            attempt.channel_binding if channel_binding is None else channel_binding
        ),
        sign=attempt.sign if sign is None else sign,
        rationale=attempt.rationale if rationale is None else rationale,
    )


def _stable_sort_attempts(
    attempts: list[LDAPAuthAttempt],
) -> list[LDAPAuthAttempt]:
    """Stable sort: LDAPS before LDAP, Kerberos before raw NTLM."""

    def _key(att: LDAPAuthAttempt) -> tuple[int, int]:
        transport_rank = 0 if att.transport is LDAPTransport.LDAPS else 1
        auth_rank = 0 if att.auth_scheme in _KERBEROS_SCHEMES else 1
        return (transport_rank, auth_rank)

    return sorted(attempts, key=_key)


# --------------------------------------------------------------------------- #
# Kerberos plan (PR9)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class KerberosAttempt:
    """Posture-adjusted etype and probe settings for one Kerberos AS-REQ.

    Attributes:
        etypes: Ordered etype list to pass as ``override_etype`` to kerbad.
            An empty list means "use kerbad's default" (which includes RC4).
            ``[18, 17]`` means AES-only (AES256 then AES128).
        force_etype_probe: When True, always run
            ``_probe_and_set_etype_info2_salt`` regardless of credential type.
            Used when the posture tells us the KDC uses a non-default salt.
        skip_etype_probe: When True and the credential is a plaintext password,
            skip the ETYPE-INFO2 salt probe. The posture has confirmed that
            standard salts are in use, so the probe is unnecessary.
        rationale: Human-readable one-liner explaining why this attempt was
            built. Useful for debug logs and test assertions.
    """

    etypes: list[int]
    force_etype_probe: bool
    skip_etype_probe: bool
    rationale: str


@dataclass(frozen=True)
class KerberosAuthPlan:
    """Posture-driven Kerberos auth settings for :func:`get_tgt` / :func:`get_tgs`.

    Unlike :class:`LDAPAuthPlan`, the Kerberos plan contains a single attempt
    — there is no transport fallback at the Kerberos layer. The plan adjusts
    inputs (etype list, probe flags); viability is always left to the
    transport.

    Attributes:
        attempt: The single :class:`KerberosAttempt` to execute.
        notes: Plan-level commentary (e.g. which posture signal triggered a change).
        is_pruned: True when the posture changed anything versus the
            conservative baseline (kerbad default etypes, standard probe logic).
    """

    attempt: KerberosAttempt
    notes: list[str] = field(default_factory=list)
    is_pruned: bool = False


# Conservative baseline values — exported for test assertions.
_KERBEROS_BASELINE_ETYPES: list[int] = []
_KERBEROS_BASELINE_FORCE_PROBE: bool = False
_KERBEROS_BASELINE_SKIP_PROBE: bool = False
_KERBEROS_BASELINE_RATIONALE: str = "conservative baseline (posture UNKNOWN)"


def build_kerberos_plan(
    *,
    config: "KerberosConfig",
    posture: "DomainPosture | None",
) -> KerberosAuthPlan:
    """Build a posture-aware Kerberos attempt plan.

    When ``posture`` is ``None`` or all relevant constraints are UNKNOWN / LOW
    confidence, returns the conservative baseline (kerbad default etypes,
    standard probe logic). When HIGH-confidence posture is available, adjusts
    etypes and probe flags to skip impossible round-trips.

    Rules (applied in order; later rules can override earlier):
        1. ``KERBEROS_RC4=DISABLED`` (HIGH) or ``KERBEROS_AES_ONLY=ENABLED``
           (HIGH) → ``etypes = [18, 17]`` (AES-only). RC4 is never offered in
           the AS-REQ, preventing ``KDC_ERR_ETYPE_NOSUPP`` rejection and retry.
        2. ``KERBEROS_ETYPE_PROBE=ENABLED`` (HIGH) → ``force_etype_probe = True``.
           The KDC uses non-default salts; the probe is always needed, even for
           non-password credentials.
        3. ``KERBEROS_ETYPE_PROBE=DISABLED`` (HIGH) AND rule 2 did NOT fire →
           ``skip_etype_probe = True``. Standard salt confirmed; probe is
           unnecessary for password credentials.

    Args:
        config: The active :class:`KerberosConfig`. Only the credential fields
            are inspected to decide baseline probe behaviour; this function
            never mutates the config.
        posture: Optional :class:`DomainPosture` snapshot. When ``None``,
            the conservative baseline is returned unchanged.

    Returns:
        A frozen :class:`KerberosAuthPlan` whose ``attempt`` carries the
        etype list and probe flags to use. ``is_pruned`` is ``True`` when the
        posture changed anything vs the conservative baseline.
    """
    etypes: list[int] = list(_KERBEROS_BASELINE_ETYPES)
    force_etype_probe: bool = _KERBEROS_BASELINE_FORCE_PROBE
    skip_etype_probe: bool = _KERBEROS_BASELINE_SKIP_PROBE
    rationale: str = _KERBEROS_BASELINE_RATIONALE
    notes: list[str] = []
    pruned = False

    if posture is None:
        return KerberosAuthPlan(
            attempt=KerberosAttempt(
                etypes=etypes,
                force_etype_probe=force_etype_probe,
                skip_etype_probe=skip_etype_probe,
                rationale=rationale,
            ),
            notes=notes,
            is_pruned=False,
        )

    rc4_entry = posture.get(ConstraintCategory.KERBEROS_RC4)
    aes_only_entry = posture.get(ConstraintCategory.KERBEROS_AES_ONLY)
    probe_entry = posture.get(ConstraintCategory.KERBEROS_ETYPE_PROBE)

    # Rule 1: RC4 disabled or AES-only enforced → force AES etypes.
    rc4_disabled_high = _has_high_confidence(
        rc4_entry.effective_state, rc4_entry.confidence
    ) and (rc4_entry.effective_state is TriState.DISABLED)
    aes_only_high = _has_high_confidence(
        aes_only_entry.effective_state, aes_only_entry.confidence
    ) and (aes_only_entry.effective_state is TriState.ENABLED)

    if rc4_disabled_high or aes_only_high:
        etypes = [18, 17]
        pruned = True
        if rc4_disabled_high and aes_only_high:
            rationale = (
                "posture: KERBEROS_RC4=DISABLED + KERBEROS_AES_ONLY=ENABLED (HIGH) "
                "— AES-only etypes [18,17]"
            )
            notes.append(
                "RC4 disabled and AES-only enforced by posture — offering [AES256, AES128] only."
            )
        elif rc4_disabled_high:
            rationale = (
                "posture: KERBEROS_RC4=DISABLED (HIGH) — AES-only etypes [18,17]"
            )
            notes.append("RC4 disabled by posture — offering [AES256, AES128] only.")
        else:
            rationale = (
                "posture: KERBEROS_AES_ONLY=ENABLED (HIGH) — AES-only etypes [18,17]"
            )
            notes.append(
                "AES-only enforced by posture — offering [AES256, AES128] only."
            )

        # Decide-before-mint: AES is required (RC4 disabled / AES-only enforced)
        # but the ONLY available secret is an NT hash. AES keys cannot be derived
        # from an NT hash (string_to_key needs a plaintext password or a
        # precomputed AES key). Surfacing this here — before the mint — turns the
        # otherwise-cryptic kerbad failure ("There is no key for AES256
        # encryption" / KDC_ERR_PREAUTH_FAILED) into an actionable note.
        only_nt_hash = (
            getattr(config, "nt_hash", None)
            and not getattr(config, "password", None)
            and not getattr(config, "aes_key", None)
            and not getattr(config, "ccache_path", None)
            and not getattr(config, "ccache_bytes", None)
            and not getattr(config, "kirbi_path", None)
            and not getattr(config, "cert_pfx_path", None)
        )
        if only_nt_hash:
            notes.append(
                "AES encryption is required by this KDC (RC4 disabled), but only "
                "an NT hash is available. AES keys cannot be derived from an NT "
                "hash — a plaintext password or a precomputed AES key is required."
            )

    # Rule 2: probe known-needed → force the probe.
    probe_enabled_high = _has_high_confidence(
        probe_entry.effective_state, probe_entry.confidence
    ) and (probe_entry.effective_state is TriState.ENABLED)

    if probe_enabled_high:
        force_etype_probe = True
        skip_etype_probe = False
        pruned = True
        rationale_suffix = " + KERBEROS_ETYPE_PROBE=ENABLED (HIGH) — probe forced"
        rationale = (
            rationale + rationale_suffix
            if pruned
            else ("posture: KERBEROS_ETYPE_PROBE=ENABLED (HIGH) — probe forced")
        )
        notes.append(
            "Non-default AES salt known from posture — etype probe forced for all credentials."
        )

    # Rule 3: probe known-unneeded → skip probe (only if rule 2 did not fire).
    elif _has_high_confidence(probe_entry.effective_state, probe_entry.confidence) and (
        probe_entry.effective_state is TriState.DISABLED
    ):
        skip_etype_probe = True
        force_etype_probe = False
        pruned = True
        rationale_suffix = " + KERBEROS_ETYPE_PROBE=DISABLED (HIGH) — probe skipped"
        if rationale == _KERBEROS_BASELINE_RATIONALE:
            rationale = "posture: KERBEROS_ETYPE_PROBE=DISABLED (HIGH) — probe skipped"
        else:
            rationale = rationale + rationale_suffix
        notes.append(
            "Standard Kerberos salt confirmed by posture — etype probe skipped."
        )

    return KerberosAuthPlan(
        attempt=KerberosAttempt(
            etypes=etypes,
            force_etype_probe=force_etype_probe,
            skip_etype_probe=skip_etype_probe,
            rationale=rationale,
        ),
        notes=notes,
        is_pruned=pruned,
    )


# --------------------------------------------------------------------------- #
# SMB plan (PR10)
# --------------------------------------------------------------------------- #

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.smb_transport import SMBConfig


@dataclass(frozen=True)
class SMBAttempt:
    """Posture-adjusted parameters for a single SMB auth attempt.

    Attributes:
        use_kerberos: When True, use Kerberos auth from the first attempt.
            When False, start with NTLM (default behavior).
        signing_required: Informational flag reflecting the posture
            ``SMB_SIGNING`` constraint. aiosmb handles signing negotiation
            natively; the plan surfaces this for logging and callers that
            want to log or surface the information.
        rationale: Human-readable one-liner explaining why this attempt was
            built. Useful for debug logs and test assertions.
    """

    use_kerberos: bool
    signing_required: bool
    rationale: str


@dataclass(frozen=True)
class SMBAuthPlan:
    """Posture-driven SMB auth settings for :func:`smb_machine_with_fallback`.

    Unlike :class:`LDAPAuthPlan`, the SMB plan contains a single attempt —
    the plan adjusts whether to start with Kerberos or NTLM; the runtime
    still falls back to Kerberos on NTLM rejection when ``is_pruned`` is False.

    Attributes:
        attempt: The single :class:`SMBAttempt` to execute.
        is_pruned: True when the posture changed anything versus the
            conservative baseline (caller's ``config.use_kerberos`` value).
        notes: Plan-level commentary (e.g. which posture signal triggered a change).
    """

    attempt: SMBAttempt
    is_pruned: bool
    notes: list[str]
    ntlm_fallback_allowed: bool = False


# Conservative baseline rationale — exported for test assertions.
_SMB_BASELINE_RATIONALE: str = "conservative baseline (posture UNKNOWN)"


def build_smb_plan(
    *,
    config: "SMBConfig",
    posture: "DomainPosture | None",
) -> SMBAuthPlan:
    """Build a posture-aware SMB attempt plan.

    When ``posture`` is ``None`` or all relevant constraints are UNKNOWN / LOW
    confidence, returns the conservative baseline (``use_kerberos`` and
    ``signing_required`` taken from the caller's config). When HIGH-confidence
    posture evidence is present, upgrades to Kerberos or surfaces signing info.

    Rules (applied in order):
        1. ``NTLM_AUTHENTICATION=DISABLED`` (HIGH) → ``use_kerberos = True``.
           Avoids the doomed NTLM attempt entirely.
        2. ``NTLM_AUTHENTICATION=ENABLED`` (HIGH) → note it; caller's explicit
           Kerberos intent is preserved — no pruning.
        3. ``SMB_SIGNING=REQUIRED`` (HIGH) → ``signing_required = True``
           (informational only — aiosmb handles signing negotiation natively).

    Args:
        config: The active :class:`SMBConfig`. Only ``use_kerberos`` is
            consulted for the baseline; this function never mutates the config.
        posture: Optional :class:`DomainPosture` snapshot. When ``None``, the
            conservative baseline is returned unchanged.

    Returns:
        A frozen :class:`SMBAuthPlan` whose ``attempt`` carries the adjusted
        ``use_kerberos`` and ``signing_required`` flags. ``is_pruned`` is
        ``True`` when the posture forced a change versus the caller's config.
    """
    caller_requested_kerberos = bool(config.use_kerberos)
    # Kerberos requires a principal (username) + ticket material.  Null and
    # guest sessions have username="" — Kerberos is structurally impossible
    # regardless of infrastructure availability.  Without this guard the
    # Kerberos-first policy would upgrade the attempt to Kerberos, aiosmb
    # would crash building the auth URL with empty credentials
    # (AttributeError: 'NoneType' object has no attribute 'native'), and the
    # NTLM fallback would never fire because the crash is not SMBAuthError.
    has_principal = bool(str(getattr(config, "username", "") or "").strip())
    # Kerberos also requires actual credential material.  A fake guest/null
    # username like "ADscan" with no password/hash/ccache is not Kerberos-viable
    # — trying it would crash aiosmb when building the auth URL.
    has_credential_material = bool(
        getattr(config, "password", None)
        or getattr(config, "nt_hash", None)
        or getattr(config, "ccache_path", None)
        or getattr(config, "aes_key", None)
    )
    # Kerberos SPN must be an FQDN — never cifs/<ip>. When the SMB target
    # hostname is still an IP (no FQDN was resolvable from inventory/domains_data
    # at the config-build site), requesting Kerberos aborts on the IP-as-SPN
    # guard with a non-recoverable ValueError. Treat that as not-viable so the
    # Kerberos-first policy (Rule 0) does not upgrade a doomed attempt — NTLM is
    # used instead (still gated by the NTLM-disabled posture rule below).
    kerberos_viable = bool(
        has_principal
        and has_credential_material
        and (getattr(config, "kdc_ip", None) or getattr(config, "domain", None))
    )

    # Conservative baseline
    use_kerberos: bool = config.use_kerberos
    signing_required: bool = False
    rationale: str = _SMB_BASELINE_RATIONALE
    notes: list[str] = []
    pruned: bool = False
    ntlm_fallback_allowed: bool = False

    ntlm_entry = (
        posture.get(ConstraintCategory.NTLM_AUTHENTICATION)
        if posture is not None
        else None
    )
    signing_entry = (
        posture.get(ConstraintCategory.SMB_SIGNING) if posture is not None else None
    )
    ntlm_disabled_high = bool(
        ntlm_entry
        and _has_high_confidence(ntlm_entry.effective_state, ntlm_entry.confidence)
        and ntlm_entry.effective_state is TriState.DISABLED
    )

    # NTLM fallback on a Kerberos *infrastructure* error (KDC/SPN/AP-exchange leg)
    # is correct recovery whenever NTLM has not been ruled out by posture — a
    # Kerberos infra error is never a credential rejection, so retrying NTLM with
    # the same credential is sound. This holds regardless of whether the caller
    # explicitly requested Kerberos or the Kerberos-first policy promoted it.
    # Without this, a caller that sets ``use_kerberos=True`` (e.g. the live SMB
    # share probe, which resolves the per-host SPN itself) would hit a
    # GSSAPI-wrapped KRB-ERROR on the AP exchange — now correctly decoded by
    # badauth into a real Kerberos error-code — and surface a dead-end instead of
    # recovering over NTLM. The chokepoint still gates the actual fallback on the
    # error being a Kerberos *infra* error (not a credential rejection).
    if caller_requested_kerberos and not ntlm_disabled_high:
        ntlm_fallback_allowed = True

    # Rule 0: global Kerberos-first default when Kerberos is viable and the
    # caller did not explicitly request Kerberos. NTLM fallback is allowed only
    # for this policy-selected path, and only when posture has not ruled NTLM out.
    if (
        KERBEROS_FIRST_POLICY
        and kerberos_viable
        and not caller_requested_kerberos
        and not ntlm_disabled_high
    ):
        use_kerberos = True
        pruned = True
        ntlm_fallback_allowed = True
        rationale = "policy: Kerberos-first — starting with Kerberos auth"
        notes.append(
            "Kerberos-first policy selected SMB Kerberos; NTLM fallback allowed only on Kerberos infra errors."
        )

    # Rule 1: NTLM_AUTHENTICATION=DISABLED HIGH → force Kerberos from the start,
    # but ONLY when Kerberos is actually viable. For a credential-less session
    # (no principal/secret/ccache) Kerberos cannot be attempted; forcing it would
    # build a doomed auth URL that crashes downstream with
    # ``'NoneType' object has no attribute 'native'`` instead of cleanly skipping.
    # In that case keep the anonymous/NTLM attempt and record why.
    if ntlm_disabled_high:
        if kerberos_viable:
            if not use_kerberos:
                # We are changing the caller's default — that is a prune.
                use_kerberos = True
                pruned = True
            ntlm_fallback_allowed = False
            rationale = (
                "posture: NTLM_AUTHENTICATION=DISABLED — starting with Kerberos auth"
            )
            notes.append(
                "NTLM disabled by posture — Kerberos auth used from the first attempt."
            )
        else:
            notes.append(
                "NTLM disabled by posture but no credential material — cannot use "
                "Kerberos; anonymous/NTLM attempted."
            )

    # Rule 2: NTLM_AUTHENTICATION=ENABLED HIGH — caller's Kerberos intent is preserved.
    elif (
        ntlm_entry is not None
        and _has_high_confidence(ntlm_entry.effective_state, ntlm_entry.confidence)
        and ntlm_entry.effective_state is TriState.ENABLED
        and use_kerberos
    ):
        notes.append(
            "NTLM enabled per posture, but caller explicitly requested Kerberos — "
            "preserving caller intent."
        )

    # Rule 3: SMB_SIGNING=REQUIRED HIGH → informational signing flag.
    if (
        signing_entry is not None
        and _has_high_confidence(
            signing_entry.effective_state, signing_entry.confidence
        )
        and signing_entry.effective_state is TriState.REQUIRED
    ):
        signing_required = True
        notes.append(
            "SMB signing required per posture — aiosmb handles negotiation natively."
        )

    return SMBAuthPlan(
        attempt=SMBAttempt(
            use_kerberos=use_kerberos,
            signing_required=signing_required,
            rationale=rationale,
        ),
        is_pruned=pruned,
        notes=notes,
        ntlm_fallback_allowed=ntlm_fallback_allowed,
    )


# --------------------------------------------------------------------------- #
# WinRM plan (PR11)
# --------------------------------------------------------------------------- #


_WINRM_VALID_AUTH_MODES = frozenset({"auto", "ntlm", "kerberos", "negotiate"})
_WINRM_NTLM_LIKE_AUTH_MODES = frozenset({"auto", "ntlm", "negotiate"})
_WINRM_BASELINE_RATIONALE: str = "conservative baseline (posture UNKNOWN)"


@dataclass(frozen=True)
class WinRMAttempt:
    """Posture-adjusted parameters for a single WinRM auth attempt.

    Attributes:
        auth_mode: One of ``"kerberos" | "ntlm" | "negotiate" | "auto"``.
            The pypsrp-backed transport consumes this directly.
        rationale: Human-readable one-liner explaining why this attempt was
            built. Useful for debug logs and test assertions.
    """

    auth_mode: str
    rationale: str


@dataclass(frozen=True)
class WinRMAuthPlan:
    """Posture-driven WinRM auth-mode selection.

    Unlike SMB, WinRM has no transport fallback (it is HTTP/HTTPS PSRP), so
    the plan is a single-attempt structure rather than a list.

    Attributes:
        attempt: The single :class:`WinRMAttempt` to execute.
        is_pruned: True when the posture changed the auth_mode versus the
            caller's requested value.
        notes: Plan-level commentary (which posture signal triggered a change).
    """

    attempt: WinRMAttempt
    is_pruned: bool
    notes: list[str]
    ntlm_fallback_allowed: bool = False


def build_winrm_plan(
    *,
    requested_auth_mode: str,
    posture: "DomainPosture | None",
    kerberos_viable: bool = True,
) -> WinRMAuthPlan:
    """Build a posture-aware WinRM auth-mode plan.

    Conservative baseline: returns ``requested_auth_mode`` unchanged (or
    ``"auto"`` when the requested value is empty/unknown).

    Pruning rules (HIGH confidence only):

      - ``NTLM_AUTHENTICATION = DISABLED`` (HIGH) AND
        ``requested_auth_mode in {"auto", "ntlm", "negotiate"}`` →
        force ``"kerberos"``, ``is_pruned = True``.
      - ``NTLM_AUTHENTICATION = ENABLED`` (HIGH) AND
        ``requested_auth_mode == "auto"`` → no change.
      - ``KERBEROS_RC4 = DISABLED`` (HIGH) → no change to ``auth_mode``
        (etype selection happens in ``build_kerberos_plan``); a note is
        appended for traceability.

    Args:
        requested_auth_mode: The caller-provided WinRM auth mode. Anything
            outside ``{"auto", "ntlm", "kerberos", "negotiate"}`` is treated
            as ``"auto"``.
        posture: Optional :class:`DomainPosture` snapshot. When ``None`` or
            all relevant constraints are UNKNOWN / LOW, returns the
            conservative baseline.

    Returns:
        A frozen :class:`WinRMAuthPlan` whose ``attempt.auth_mode`` is the
        effective auth mode. ``is_pruned`` is ``True`` when the posture
        forced a change versus the caller's requested mode.
    """
    requested = str(requested_auth_mode or "").strip().lower() or "auto"
    if requested not in _WINRM_VALID_AUTH_MODES:
        requested = "auto"

    auth_mode: str = requested
    rationale: str = _WINRM_BASELINE_RATIONALE
    notes: list[str] = []
    pruned: bool = False
    ntlm_fallback_allowed: bool = False

    # Caller explicitly requested Kerberos. Posture-gate the NTLM last-resort up
    # front (mirrors ``build_smb_plan``): NTLM fallback on a residual Kerberos
    # *infrastructure* error (the GSSAPI-wrapped KRB-ERROR / AP-exchange leg) is
    # correct recovery whenever NTLM has not been ruled out by posture — a
    # Kerberos infra error is never a credential rejection, so retrying NTLM with
    # the same credential is sound. The chokepoint (winrm_psrp_service) still
    # gates the actual fallback on ``_is_kerberos_infra_error`` so it fires ONLY
    # on the residual KRB-ERROR class, never on KDC_ERR_ETYPE_NOTSUPP /
    # KRB_AP_ERR_SKEW / KRB_AP_ERR_MODIFIED (those own dedicated recovery).
    ntlm_disabled_high = False
    if posture is not None:
        _ntlm_entry = posture.get(ConstraintCategory.NTLM_AUTHENTICATION)
        ntlm_disabled_high = bool(
            _has_high_confidence(_ntlm_entry.effective_state, _ntlm_entry.confidence)
            and _ntlm_entry.effective_state is TriState.DISABLED
        )
    if requested == "kerberos" and not ntlm_disabled_high:
        ntlm_fallback_allowed = True

    if KERBEROS_FIRST_POLICY and kerberos_viable and requested == "auto":
        auth_mode = "kerberos"
        pruned = True
        ntlm_fallback_allowed = True
        rationale = "policy: Kerberos-first — starting WinRM with Kerberos"
        notes.append(
            "Kerberos-first policy selected WinRM Kerberos; NTLM fallback is a transport-level infra retry."
        )

    if posture is None:
        return WinRMAuthPlan(
            attempt=WinRMAttempt(auth_mode=auth_mode, rationale=rationale),
            is_pruned=pruned,
            notes=notes,
            ntlm_fallback_allowed=ntlm_fallback_allowed,
        )

    ntlm_entry = posture.get(ConstraintCategory.NTLM_AUTHENTICATION)
    rc4_entry = posture.get(ConstraintCategory.KERBEROS_RC4)

    # Rule 1: NTLM disabled HIGH + requested looks NTLM-capable → force Kerberos.
    if (
        _has_high_confidence(ntlm_entry.effective_state, ntlm_entry.confidence)
        and ntlm_entry.effective_state is TriState.DISABLED
        and requested in _WINRM_NTLM_LIKE_AUTH_MODES
        and kerberos_viable
    ):
        auth_mode = "kerberos"
        pruned = True
        ntlm_fallback_allowed = False
        rationale = "posture: NTLM disabled — forcing Kerberos"
        notes.append("NTLM disabled by posture — WinRM auth_mode forced to Kerberos.")

    # Rule 2: NTLM enabled HIGH + requested=auto → no change (auto is fine).
    elif (
        _has_high_confidence(ntlm_entry.effective_state, ntlm_entry.confidence)
        and ntlm_entry.effective_state is TriState.ENABLED
        and requested == "auto"
    ):
        notes.append("NTLM enabled per posture — caller's 'auto' selection preserved.")

    # Rule 3: KERBEROS_RC4 disabled HIGH — does not affect WinRM auth-mode
    # selection (etype selection happens in build_kerberos_plan), but record
    # the observation for traceability.
    if (
        _has_high_confidence(rc4_entry.effective_state, rc4_entry.confidence)
        and rc4_entry.effective_state is TriState.DISABLED
    ):
        notes.append(
            "KERBEROS_RC4 disabled per posture — etype selection handled by "
            "build_kerberos_plan; WinRM auth_mode unchanged."
        )

    return WinRMAuthPlan(
        attempt=WinRMAttempt(auth_mode=auth_mode, rationale=rationale),
        is_pruned=pruned,
        notes=notes,
        ntlm_fallback_allowed=ntlm_fallback_allowed,
    )


# --------------------------------------------------------------------------- #
# RDP plan (PR-RDP)
# --------------------------------------------------------------------------- #


_RDP_BASELINE_RATIONALE: str = "conservative baseline (posture UNKNOWN)"


@dataclass(frozen=True)
class RDPAttempt:
    """Posture-adjusted parameters for a single RDP auth attempt.

    Attributes:
        use_kerberos: When True, start RDP with CredSSP+Kerberos directly.
            When False, start with CredSSP+NTLM (current default behavior).
        rationale: Human-readable one-liner explaining why this attempt was
            built. Useful for debug logs and test assertions.
    """

    use_kerberos: bool
    rationale: str


@dataclass(frozen=True)
class RDPAuthPlan:
    """Posture-driven RDP auth selection.

    Like :class:`SMBAuthPlan`, the RDP plan contains a single attempt — RDP's
    auth choice is binary (NTLM vs Kerberos), and the runtime still applies
    the conservative NTLM-then-Kerberos fallback when ``is_pruned`` is False.

    Attributes:
        attempt: The single :class:`RDPAttempt` to execute.
        is_pruned: True when the posture changed anything versus the
            caller's ``prefer_kerberos`` value.
        notes: Plan-level commentary (which posture signal triggered a change).
    """

    attempt: RDPAttempt
    is_pruned: bool
    notes: list[str]
    ntlm_fallback_allowed: bool = False


def build_rdp_plan(
    *,
    prefer_kerberos: bool,
    posture: "DomainPosture | None",
    kerberos_viable: bool = True,
) -> RDPAuthPlan:
    """Build a posture-aware RDP auth plan.

    Conservative baseline: returns ``prefer_kerberos`` unchanged.

    Pruning rules (HIGH confidence only):

      - ``NTLM_AUTHENTICATION = DISABLED`` (HIGH) AND ``prefer_kerberos=False``
        → force ``use_kerberos = True``, ``is_pruned = True``,
        rationale ``"posture: NTLM disabled — starting RDP with Kerberos"``.
      - ``NTLM_AUTHENTICATION = ENABLED`` (HIGH) AND ``prefer_kerberos=False``
        → no change (NTLM is fine, no Kerberos overhead needed).
      - Other posture states → no change.

    Args:
        prefer_kerberos: Caller's baseline preference. Today's RDP service
            always passes ``False`` because aardwolf has no "negotiate" mode.
        posture: Optional :class:`DomainPosture` snapshot. When ``None`` or
            relevant constraints are UNKNOWN / LOW, returns the conservative
            baseline.

    Returns:
        A frozen :class:`RDPAuthPlan` whose ``attempt.use_kerberos`` is the
        effective choice. ``is_pruned`` is ``True`` when the posture forced
        a change versus ``prefer_kerberos``.
    """
    use_kerberos: bool = bool(prefer_kerberos)
    rationale: str = _RDP_BASELINE_RATIONALE
    notes: list[str] = []
    pruned: bool = False
    ntlm_fallback_allowed: bool = False

    if KERBEROS_FIRST_POLICY and kerberos_viable and not prefer_kerberos:
        use_kerberos = True
        pruned = True
        ntlm_fallback_allowed = True
        rationale = "policy: Kerberos-first — starting RDP with Kerberos"
        notes.append(
            "Kerberos-first policy selected RDP Kerberos; NTLM fallback is only for Kerberos infra errors."
        )

    if posture is None:
        return RDPAuthPlan(
            attempt=RDPAttempt(use_kerberos=use_kerberos, rationale=rationale),
            is_pruned=pruned,
            notes=notes,
            ntlm_fallback_allowed=ntlm_fallback_allowed,
        )

    ntlm_entry = posture.get(ConstraintCategory.NTLM_AUTHENTICATION)

    # Rule 1: NTLM disabled HIGH + caller wanted NTLM start → force Kerberos.
    if (
        _has_high_confidence(ntlm_entry.effective_state, ntlm_entry.confidence)
        and ntlm_entry.effective_state is TriState.DISABLED
        and not prefer_kerberos
        and kerberos_viable
    ):
        use_kerberos = True
        pruned = True
        ntlm_fallback_allowed = False
        rationale = "posture: NTLM disabled — starting RDP with Kerberos"
        notes.append(
            "NTLM disabled by posture — RDP starts with Kerberos (NTLM attempt skipped)."
        )

    # Rule 2: NTLM enabled HIGH + caller wanted NTLM → no change (note only).
    elif (
        _has_high_confidence(ntlm_entry.effective_state, ntlm_entry.confidence)
        and ntlm_entry.effective_state is TriState.ENABLED
        and not prefer_kerberos
    ):
        notes.append(
            "NTLM enabled per posture — RDP NTLM-first preserved (no Kerberos overhead)."
        )

    return RDPAuthPlan(
        attempt=RDPAttempt(use_kerberos=use_kerberos, rationale=rationale),
        is_pruned=pruned,
        notes=notes,
        ntlm_fallback_allowed=ntlm_fallback_allowed,
    )


# --------------------------------------------------------------------------- #
# MSSQL plan (PR-MSSQL)
# --------------------------------------------------------------------------- #


_MSSQL_BASELINE_RATIONALE: str = "conservative baseline (posture UNKNOWN)"


@dataclass(frozen=True)
class MSSQLAttempt:
    """Posture-adjusted parameters for one MSSQL auth attempt.

    Attributes:
        use_kerberos: When True, use Kerberos for Windows auth. When False
            (and ``use_windows_auth`` is True), use NTLM. Ignored entirely
            when ``use_windows_auth`` is False.
        use_windows_auth: When True, the credential targets Windows auth
            (domain + user + secret). When False, SQL auth is used and
            posture rules are bypassed entirely.
        rationale: Human-readable one-liner explaining why this attempt was
            built. Useful for debug logs and test assertions.
    """

    use_kerberos: bool
    use_windows_auth: bool
    rationale: str


@dataclass(frozen=True)
class MSSQLAuthPlan:
    """Posture-driven MSSQL auth selection.

    Attributes:
        attempt: The single :class:`MSSQLAttempt` to execute.
        is_pruned: True when the posture changed anything versus the
            caller's intent.
        notes: Plan-level commentary (which posture signal triggered a change).
    """

    attempt: MSSQLAttempt
    is_pruned: bool
    notes: list[str]
    ntlm_fallback_allowed: bool = False


def build_mssql_plan(
    *,
    use_windows_auth: bool,
    prefer_kerberos: bool,
    posture: "DomainPosture | None",
    kerberos_viable: bool = True,
) -> MSSQLAuthPlan:
    """Posture-driven MSSQL auth selection.

    Conservative baseline: returns the caller's intent unchanged.

    Pruning rules (HIGH confidence only):
      - ``use_windows_auth=False`` (SQL auth) → posture is irrelevant; the
        function skips all rules and returns the baseline. SQL auth bypasses
        Windows AD entirely.
      - ``NTLM_AUTHENTICATION=DISABLED HIGH`` AND ``use_windows_auth=True``
        AND ``prefer_kerberos=False`` → forces ``use_kerberos=True``,
        ``is_pruned=True``.
      - ``NTLM_AUTHENTICATION=ENABLED HIGH`` AND ``use_windows_auth=True``
        → no change (NTLM is fine).

    Args:
        use_windows_auth: True when caller is using Windows auth (domain +
            user + secret), False for SQL auth (login + password).
        prefer_kerberos: Caller's current Kerberos preference. When True,
            posture cannot reduce use_kerberos.
        posture: Optional :class:`DomainPosture` snapshot. When ``None``,
            the conservative baseline is returned unchanged.

    Returns:
        A frozen :class:`MSSQLAuthPlan`. ``is_pruned`` is ``True`` when the
        posture forced ``use_kerberos`` from False to True.
    """
    use_kerberos: bool = bool(prefer_kerberos)
    rationale: str = _MSSQL_BASELINE_RATIONALE
    notes: list[str] = []
    pruned: bool = False
    ntlm_fallback_allowed: bool = False

    # SQL auth bypasses every Windows-AD posture rule.
    if not use_windows_auth:
        return MSSQLAuthPlan(
            attempt=MSSQLAttempt(
                use_kerberos=False,
                use_windows_auth=False,
                rationale=rationale,
            ),
            is_pruned=False,
            notes=notes,
            ntlm_fallback_allowed=False,
        )

    if KERBEROS_FIRST_POLICY and kerberos_viable and not prefer_kerberos:
        use_kerberos = True
        pruned = True
        ntlm_fallback_allowed = True
        rationale = "policy: Kerberos-first — using Kerberos for MSSQL Windows auth"
        notes.append(
            "Kerberos-first policy selected MSSQL Kerberos; NTLM fallback is a transport-level infra retry."
        )

    if posture is None:
        return MSSQLAuthPlan(
            attempt=MSSQLAttempt(
                use_kerberos=use_kerberos,
                use_windows_auth=True,
                rationale=rationale,
            ),
            is_pruned=pruned,
            notes=notes,
            ntlm_fallback_allowed=ntlm_fallback_allowed,
        )

    ntlm_entry = posture.get(ConstraintCategory.NTLM_AUTHENTICATION)

    # Rule: NTLM disabled HIGH + Windows auth + caller did not already prefer
    # Kerberos → force Kerberos.
    if (
        _has_high_confidence(ntlm_entry.effective_state, ntlm_entry.confidence)
        and ntlm_entry.effective_state is TriState.DISABLED
        and not prefer_kerberos
        and kerberos_viable
    ):
        use_kerberos = True
        pruned = True
        ntlm_fallback_allowed = False
        rationale = "posture: NTLM disabled — using Kerberos for MSSQL Windows auth"
        notes.append(
            "NTLM disabled by posture — MSSQL Windows auth forced to Kerberos."
        )
    elif (
        _has_high_confidence(ntlm_entry.effective_state, ntlm_entry.confidence)
        and ntlm_entry.effective_state is TriState.ENABLED
    ):
        notes.append(
            "NTLM enabled per posture — MSSQL Windows auth selection unchanged."
        )

    return MSSQLAuthPlan(
        attempt=MSSQLAttempt(
            use_kerberos=use_kerberos,
            use_windows_auth=True,
            rationale=rationale,
        ),
        is_pruned=pruned,
        notes=notes,
        ntlm_fallback_allowed=ntlm_fallback_allowed,
    )
