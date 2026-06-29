"""Single source of truth for resolving a mass-auth sweep's credential.

Every operation that authenticates as ONE domain principal across MANY hosts —
the SMB privilege/access sweep, the WinRM and MSSQL (Windows-auth) sweeps, the
RDP login sweep, the SMB/MSSQL collectors, share enumeration — must route its
credential through :func:`resolve_sweep_credential` BEFORE it builds per-host
configs. The result is a reuse-ready, lockout-safe credential that every per-host
config shares.

The problem this fixes (validated 2026-06-16 on the Cyberzaintza audit)
====================================================================
Passing a plaintext password / NT hash straight into N per-host transport
configs makes each host mint its OWN TGT from the secret (``kerberos-password://``
→ a fresh AS-REQ per connection — see ``smb_transport._build_smb_url``). At
1-2k hosts that is:

* **Slow / noisy** — 1-2k AS-REQs hammering the single PDC instead of one.
* **A domain-lockout hazard** — the dangerous part for a customer audit. A
  wrong / rotated / must-change credential becomes N failed pre-auths =
  N ``badPwdCount`` increments = near-instant lockout of the principal across
  the domain. (Relying on the on-disk canonical ccache for reuse does NOT help
  here: if the first mint fails, hosts 2..N each retry the mint with the secret
  and amplify the lockout just the same.)

The fix
=======
Pre-mint ONE TGT for the principal up front via the existing SSOT
:func:`adscan_internal.services.kerberos_ticket_service.ensure_user_ccache`
(posture-aware: AES etype + correct salt when AES is enforced), then hand every
per-host config that single ccache. The secret touches the wire exactly once
(one AS-REQ); each host does only a cheap TGS for its service SPN. A failed
mint **aborts the sweep** (``aborted=True``) rather than falling back to
per-host password auth — fail once, never N times. This keeps the documented
Kerberos-first policy (``auth_plan.KERBEROS_FIRST_POLICY``) and works for hosts
where NTLM is disabled (they "just work" over Kerberos).

Exemptions (used as-is, never re-minted)
========================================
* **Capability-bearing / scoped artifacts** — an explicitly-supplied ccache:
  an ESC13 PAC-injected TGT, or an S4U2Proxy / RBCD / silver service ticket.
  Re-minting would destroy the synthetic SID / impersonation. This mirrors the
  carve-out in ``ensure_user_ccache`` and ``_kerberos_ccache_guard``.
* **Non-Kerberos credentials** — local-account secrets, MSSQL SQL-auth logins,
  or AES-key-only credentials have no domain TGT to pre-mint and pass through
  unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.rich_output import mark_sensitive

__all__ = [
    "SweepCredential",
    "resolve_sweep_credential",
    "SweepAuthOutcome",
    "SweepGuardDecision",
    "SweepLockoutGuard",
    "classify_sweep_auth_error",
]


@dataclass(frozen=True)
class SweepCredential:
    """A sweep credential resolved into reuse-ready, lockout-safe form.

    Exactly one of two shapes is meaningful:

    * **Pre-minted Kerberos** — ``ccache_path`` is set, the secret fields are
      cleared, ``use_kerberos`` is ``True``. Every per-host config reuses this
      one ccache.
    * **Passthrough** — a secret field is populated (non-Kerberos / AES-only /
      fallback). The caller authenticates per host as before.

    When ``aborted`` is ``True`` the caller MUST NOT start the sweep: the
    pre-mint failed and proceeding would spray the secret across hosts.
    """

    ccache_path: str | None = None
    password: str | None = None
    nt_hash: str | None = None
    aes_key: str | None = None
    use_kerberos: bool = False
    aborted: bool = False
    abort_reason: str | None = None
    notes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """``True`` when the sweep may proceed (not aborted)."""
        return not self.aborted


def _looks_like_ccache(value: str | None) -> bool:
    return bool((value or "").strip().lower().endswith(".ccache"))


def _classify_premint_failure(exc: Exception | None, note: str) -> str | None:
    """Classify a pre-mint failure into a non-credential root cause, if any.

    The pre-mint can fail for reasons that have nothing to do with the
    credential's validity — a DC that is unreachable (a stale / firewalled KDC
    IP: ``connect call failed`` to :88, no route, connection refused) or a local
    filesystem error writing the ccache (``Permission denied`` / ``[Errno 13]``).
    Blaming the credential ("verify it is valid") in those cases is misleading
    and sends the operator down the wrong path.

    Returns a short, client-safe cause string when the failure is clearly
    NON-credential (DC unreachable / local ccache write error), or ``None`` when
    the cause is unknown — in which case the caller keeps the credential-oriented
    default wording.
    """
    haystack = f"{note} {exc or ''}".lower()

    # Local ccache filesystem error — writing/opening the ccache failed on the
    # host, not an auth problem.
    if (
        "permission denied" in haystack
        or "[errno 13]" in haystack
        or "errno 13" in haystack
    ):
        return "local ccache write error (filesystem permissions on the host)"

    # DC / KDC unreachable — a stale or firewalled KDC address. The kerbad /
    # asysocks connect failure surfaces as "connect call failed" (often with the
    # ", 88" Kerberos port in the tuple), or as the generic unreachable markers.
    if (
        "connect call failed" in haystack
        or "no route" in haystack
        or "unreachable" in haystack
        or "connection refused" in haystack
        or "timed out" in haystack
        or "timeout" in haystack
    ):
        return "the Kerberos KDC (Domain Controller) was unreachable"

    return None


def resolve_sweep_credential(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    aes_key: str | None = None,
    ccache_path: str | None = None,
    auth_domain: str | None = None,
    kdc_ip: str | None = None,
    allow_password_fallback: bool = False,
) -> SweepCredential:
    """Resolve a sweep's credential to a reuse-ready, lockout-safe form.

    Pre-mints ONE TGT for ``username`` (in ``auth_domain`` or ``domain``) when a
    password / NT hash is supplied, so every per-host config can reuse the same
    ccache. See the module docstring for the rationale.

    Args:
        shell: The active ``PentestShell`` (needed by ``ensure_user_ccache`` for
            the workspace path and credential registry). Any object exposing the
            same attributes works for tests.
        domain: Target domain of the hosts being swept.
        username: sAMAccountName of the principal to authenticate as.
        password: Plaintext password (a ``.ccache`` path landing here is treated
            as an explicit ccache; an NT hash is auto-routed by the transport).
        nt_hash: NT hash for pass-the-hash (used as the TGT mint secret).
        aes_key: AES-128/256 Kerberos key. Passed through (the pre-mint path
            mints from password / NT hash).
        ccache_path: An explicitly-supplied ccache — capability-bearing (ESC13)
            or scoped (S4U/RBCD/silver). Used as-is, never re-minted.
        auth_domain: Domain the credential belongs to, when it differs from the
            target ``domain`` (cross-domain). The TGT is minted here.
        kdc_ip: KDC IP for the AS-REQ. Falls back to the domain's PDC inside
            ``ensure_user_ccache`` when omitted.
        allow_password_fallback: When ``True``, a failed pre-mint passes the
            secret through per-host instead of aborting. Reserved for paths
            where Kerberos genuinely cannot apply; NOT lockout-safe.

    Returns:
        A :class:`SweepCredential`. Check ``.ok`` / ``.aborted`` before sweeping.
    """
    masked_user = mark_sensitive(username, "user")
    notes: list[str] = []

    # 1. Explicit ccache (incl. capability-bearing ESC13 PAC-TGT and scoped
    #    S4U/RBCD/silver service tickets) → use as-is, NEVER re-mint.
    explicit_ccache = (ccache_path or "").strip()
    pw = password
    if not explicit_ccache and _looks_like_ccache(pw):
        explicit_ccache = (pw or "").strip()
        pw = None
    if explicit_ccache:
        notes.append(
            "caller-supplied ccache used as-is (capability-bearing / scoped "
            "tickets are never re-minted)"
        )
        return SweepCredential(
            ccache_path=explicit_ccache,
            use_kerberos=True,
            notes=tuple(notes),
        )

    secret = (pw or "").strip() or (nt_hash or "").strip()

    # 2. No password / NT hash to mint from → passthrough (AES-only, or no
    #    usable secret at all; the transport handles those branches).
    if not secret:
        notes.append(
            "no password / NT-hash secret to pre-mint; credential passed through"
        )
        return SweepCredential(
            password=pw,
            nt_hash=nt_hash,
            aes_key=aes_key,
            use_kerberos=bool((aes_key or "").strip()),
            notes=tuple(notes),
        )

    # 3. Domain principal with a password / NT hash → pre-mint ONE TGT.
    mint_domain = (auth_domain or domain or "").strip()
    minted: str | None = None
    mint_exc: Exception | None = None
    mint_note: str = ""
    # ``ensure_user_ccache`` swallows the underlying failure and returns ``None``
    # in the common case (it does not raise). Capture the real reason here so the
    # abort message can classify a DC-unreachable / ccache-fs failure honestly
    # instead of blaming the credential.
    mint_errors: list = []
    try:
        from adscan_internal.services.kerberos_ticket_service import (
            ensure_user_ccache,
        )

        minted = ensure_user_ccache(
            shell,
            user=username,
            domain=mint_domain,
            credential=secret,
            dc_ip=(kdc_ip or None),
            error_out=mint_errors,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort; classified below
        telemetry.capture_exception(exc)
        mint_exc = exc
        mint_note = f"pre-mint raised: {exc}"
        notes.append(mint_note)

    if not minted and mint_errors:
        # The mint returned None with a captured reason; fold it into the note
        # the classifier inspects.
        mint_note = f"{mint_note} {' '.join(str(e) for e in mint_errors)}".strip()

    if minted:
        print_info_debug(
            "[sweep_cred] pre-minted one TGT for the sweep: "
            f"user={masked_user} reused across all hosts (secret used once)"
        )
        notes.append(
            "pre-minted one TGT; per-host configs reuse this ccache (secret "
            "used once — lockout-safe)"
        )
        return SweepCredential(
            ccache_path=minted,
            use_kerberos=True,
            notes=tuple(notes),
        )

    # 4. Pre-mint failed.
    if allow_password_fallback:
        notes.append(
            "pre-mint failed; per-host secret fallback (allow_password_fallback) "
            "— NOT lockout-safe"
        )
        return SweepCredential(
            password=pw,
            nt_hash=nt_hash,
            aes_key=aes_key,
            notes=tuple(notes),
        )

    notes.append(
        "pre-mint failed; aborting sweep rather than spraying the secret across "
        "hosts (lockout-safe default)"
    )
    # The ABORT itself is always correct (never spray a secret whose mint failed),
    # but the message must state the REAL cause. A DC-unreachable (stale/firewalled
    # KDC IP) or a local ccache filesystem error is NOT a credential-validity
    # problem and is NOT a lockout risk — so don't tell the operator to "verify
    # the credential". Only fall back to that wording when the cause is unknown.
    classified_cause = _classify_premint_failure(mint_exc, mint_note)
    if classified_cause:
        abort_reason = (
            f"Kerberos TGT pre-mint failed because {classified_cause}; aborting "
            "the sweep before any host is contacted (no credential reached the "
            "wire, so this is not a lockout risk). Resolve the underlying issue "
            "and re-run — this is not a credential-validity problem."
        )
    else:
        abort_reason = (
            "Kerberos TGT pre-mint failed; aborting the sweep to avoid spraying "
            "the credential across every host (domain-lockout protection). "
            "Verify the credential is valid, or re-run with an explicit ccache."
        )
    return SweepCredential(
        aborted=True,
        abort_reason=abort_reason,
        notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# Sweep circuit-breaker — abort a mass-auth sweep when the credential is dead
# ---------------------------------------------------------------------------
#
# The pre-mint above makes the SECRET mint once. It does NOT stop a sweep from
# hammering a credential the DC keeps REJECTING: a rejected ``session_setup``
# (or a re-asserted lockout) still hits the wire per host. Observed live in a
# 117-host SMB share audit (2026-06-25): after two ``LOGON_FAILURE`` the account
# locked at host 6, and the sweep kept going — returning ``ACCOUNT_LOCKED_OUT``
# on every remaining host, re-asserting the lockout domain-wide and burning the
# rest of the engagement on a dead credential.
#
# This guard is the shared circuit-breaker. Every sweep that routes its
# credential through :func:`resolve_sweep_credential` (SMB / WinRM / MSSQL)
# should feed each host's auth result into a :class:`SweepLockoutGuard` and stop
# when it signals ABORT. The point is account protection for the CUSTOMER —
# the same domain-lockout protection the pre-mint exists for, extended to the
# rejection path the pre-mint cannot cover.

# A single LOGON_FAILURE can be one offline / mis-joined host; a credential is
# only "bad / rotated" after consecutive rejections. Conservative default.
_DEFAULT_CONSECUTIVE_FAILURE_LIMIT = 2

# NTStatus strings surface with and without the ``STATUS_`` prefix depending on
# the layer that stringifies them (aiosmb NTStatus enum vs raw wire name), so
# match both spellings. Matching is substring + case-insensitive so a wrapped
# message ("session_setup failed: NTStatus.ACCOUNT_LOCKED_OUT") still classifies.
_LOCKOUT_MARKERS = ("account_locked_out",)
_LOGON_FAILURE_MARKERS = ("logon_failure",)


class SweepAuthOutcome(str, Enum):
    """Classification of one host's authentication result during a sweep."""

    OK = "ok"
    LOCKED_OUT = "locked_out"
    LOGON_FAILURE = "logon_failure"
    OTHER = "other"
    """A non-auth failure (timeout, unreachable, access-denied to a share, …).

    Treated like a neutral event: it does NOT advance the consecutive-failure
    counter (an unreachable host is not evidence of a bad credential) and does
    NOT reset it (so a single reachable host interleaved with failures does not
    mask a dead credential). Only a clean ``OK`` resets the streak.
    """


def classify_sweep_auth_error(auth_error: str | None) -> SweepAuthOutcome:
    """Map a per-host auth-error string to a :class:`SweepAuthOutcome`.

    ``None`` / empty means the host authenticated (``OK``). A string is matched
    case-insensitively against the lockout and logon-failure markers (both the
    ``STATUS_`` and bare NTStatus spellings); anything else is ``OTHER``.
    """
    if not (auth_error or "").strip():
        return SweepAuthOutcome.OK
    lowered = auth_error.lower()
    if any(marker in lowered for marker in _LOCKOUT_MARKERS):
        return SweepAuthOutcome.LOCKED_OUT
    if any(marker in lowered for marker in _LOGON_FAILURE_MARKERS):
        return SweepAuthOutcome.LOGON_FAILURE
    return SweepAuthOutcome.OTHER


@dataclass
class SweepGuardDecision:
    """The guard's verdict after recording one host's result.

    ``should_abort`` is the actionable bit; ``reason`` is the operator-facing
    one-line explanation to surface in the abort panel.
    """

    should_abort: bool = False
    reason: str | None = None
    outcome: SweepAuthOutcome = SweepAuthOutcome.OK


@dataclass
class SweepLockoutGuard:
    """Stateful circuit-breaker that aborts a mass-auth sweep on a dead credential.

    Feed each host's authentication result via :meth:`record`. The guard signals
    ABORT on the FIRST ``ACCOUNT_LOCKED_OUT`` (the lockout is already asserted —
    every further attempt re-asserts it), or after ``consecutive_failure_limit``
    consecutive ``LOGON_FAILURE`` results (a bad / rotated credential). A clean
    success resets the consecutive-failure streak.

    The guard is protocol-agnostic: it consumes a stringified auth error, so the
    SMB, WinRM and MSSQL sweeps can all share one instance / one policy.

    Attributes:
        consecutive_failure_limit: Consecutive ``LOGON_FAILURE`` results that
            trip the breaker. Default 2 (a single failure may be one bad host).
    """

    consecutive_failure_limit: int = _DEFAULT_CONSECUTIVE_FAILURE_LIMIT
    _consecutive_failures: int = field(default=0, init=False)
    _tripped: bool = field(default=False, init=False)
    _trip_reason: str | None = field(default=None, init=False)

    @property
    def aborted(self) -> bool:
        """``True`` once the breaker has tripped (latched)."""
        return self._tripped

    @property
    def abort_reason(self) -> str | None:
        return self._trip_reason

    def record(
        self, host: str | None, auth_error: str | None
    ) -> SweepGuardDecision:
        """Record one host's auth result and return the abort decision.

        Args:
            host: The host that was attempted (for the reason string).
            auth_error: The host's auth-error string (``None`` / empty on success).

        Returns:
            A :class:`SweepGuardDecision`. Once tripped, the guard stays tripped
            (latched) and every subsequent ``record`` returns ``should_abort``.
        """
        outcome = classify_sweep_auth_error(auth_error)

        if self._tripped:
            return SweepGuardDecision(
                should_abort=True, reason=self._trip_reason, outcome=outcome
            )

        host_label = host or "?"

        if outcome is SweepAuthOutcome.LOCKED_OUT:
            self._tripped = True
            self._trip_reason = (
                f"Credential locked out at host {host_label} "
                "(ACCOUNT_LOCKED_OUT). Continuing would re-assert the lockout "
                "against every remaining host — aborting to protect the account. "
                "Reset/rotate the credential and re-run."
            )
            return SweepGuardDecision(
                should_abort=True, reason=self._trip_reason, outcome=outcome
            )

        if outcome is SweepAuthOutcome.LOGON_FAILURE:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.consecutive_failure_limit:
                self._tripped = True
                self._trip_reason = (
                    f"{self._consecutive_failures} consecutive authentication "
                    f"failures (last at host {host_label}). The credential is "
                    "likely wrong or rotated; continuing risks locking it out "
                    "domain-wide — aborting the sweep. Verify the credential and "
                    "re-run."
                )
                return SweepGuardDecision(
                    should_abort=True, reason=self._trip_reason, outcome=outcome
                )
            return SweepGuardDecision(should_abort=False, outcome=outcome)

        if outcome is SweepAuthOutcome.OK:
            # A clean authentication clears the bad-credential suspicion.
            self._consecutive_failures = 0

        # OTHER (timeout / unreachable / share-level denial) neither advances nor
        # resets the streak — it is not evidence about the credential itself.
        return SweepGuardDecision(should_abort=False, outcome=outcome)
