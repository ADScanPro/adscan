"""Proactive posture probe engine.

Runs lightweight, single-purpose probes against a Domain Controller to elicit
posture signals BEFORE the first real scan operation pays for the discovery.
Each probe targets exactly one ``ConstraintCategory``. All probes are
READ-ONLY and target only the DC the operator already pointed ADscan at —
same network scope as a regular ``start_unauth`` / ``start_auth`` phase.

Concurrency:
    - ``probe_unauth`` runs its four physical probes (U1/U4/U2/U3) FULLY
      SEQUENTIALLY — no ``asyncio.gather``. Concurrent execution caused
      event-loop starvation: the vendor TLS/NTLM path does not yield the
      loop cleanly, inflating each probe's wall-clock to seconds even though
      its real latency is ~50-150ms. See :func:`probe_unauth` docstring.
    - ``probe_auth`` Kerberos probes share the KDC connection — sequential;
      NTLM and SMB-signing probes are independent and still use
      ``asyncio.gather``.
    - ``timeout_per_probe`` is enforced per probe; one hung probe does not
      hang the others.

Idempotency:
    Re-running ``probe_unauth`` / ``probe_auth`` produces the same posture.
    Probes whose category is already known at HIGH confidence and not stale
    are skipped silently unless ``force=True``.

This module emits ``PostureSignal`` instances through the provided
``PostureSink``; it never touches the workspace directly. It does not print
to the console (only ``print_info_debug`` traces) and never wires itself into
``start.py`` — Batch 3 owns lifecycle integration.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    DomainPosture,
    IntelligenceFinding,
    PostureSignal,
    SignalConfidence,
    TriState,
)
from adscan_internal.services.posture_sink import PostureSink


# --------------------------------------------------------------------------- #
# Public types
# --------------------------------------------------------------------------- #


class ProbePhase(str, Enum):
    """Logical phase a probe runs in."""

    UNAUTH = "unauth"
    AUTH = "auth"


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of a single probe.

    Attributes:
        category: The primary ``ConstraintCategory`` this probe targets.
        state: Resolved tri-state (``UNKNOWN`` when ``succeeded=False``).
        confidence: Confidence level for the resolved state.
        signal_code: Stable machine-readable code (``"SKIPPED_ALREADY_KNOWN"``
            when ``skipped=True``, ``"PROBE_FAILED"`` when ``succeeded=False``).
        message: Human-readable description.
        duration_ms: Wall-clock time spent on the probe (0.0 when skipped).
        succeeded: ``False`` when the probe could not run to a useful answer
            (timeout, transport refused). ``state`` stays ``UNKNOWN``.
        skipped: ``True`` when no network call was made because the existing
            posture already records this category at HIGH confidence and is
            not stale.
    """

    category: ConstraintCategory
    state: TriState
    confidence: SignalConfidence
    signal_code: str
    message: str
    duration_ms: float
    succeeded: bool
    skipped: bool = False


@dataclass(frozen=True)
class ProbeCredentials:
    """Credential bundle accepted by ``probe_auth``.

    A probe that needs a specific credential type (plaintext password for
    explicit-etype AS-REQ, password-or-hash for NTLM bind, etc.) is skipped
    silently when the bundle does not provide it.
    """

    username: str
    password: Optional[str] = None
    nt_hash: Optional[str] = None
    aes_key: Optional[str] = None
    ccache_path: Optional[str] = None

    def __post_init__(self) -> None:
        # Auto-route an NT hash that landed in the password field; otherwise
        # ``can_do_explicit_etype_asreq`` would lie and the probe would build
        # an AS-REQ with a wrong AES key derived from the hash as plaintext.
        from adscan_internal.services.credential_routing import (
            promote_credential_fields,
        )

        new_pwd, new_hash, new_aes, new_cc = promote_credential_fields(
            password=self.password,
            nt_hash=self.nt_hash,
            aes_key=self.aes_key,
            ccache_path=self.ccache_path,
        )
        if new_pwd != self.password:
            object.__setattr__(self, "password", new_pwd)
        if new_hash != self.nt_hash:
            object.__setattr__(self, "nt_hash", new_hash)
        if new_aes != self.aes_key:
            object.__setattr__(self, "aes_key", new_aes)
        if new_cc != self.ccache_path:
            object.__setattr__(self, "ccache_path", new_cc)

    @property
    def can_do_explicit_etype_asreq(self) -> bool:
        """True when we can craft a controlled-etype AS-REQ (needs plaintext)."""
        return self.password is not None


# Convention:
#   on_progress(category, None)    -> probe is starting
#   on_progress(category, result)  -> probe finished (or was skipped)
ProbeProgressCallback = Callable[[ConstraintCategory, Optional[ProbeResult]], None]


# --------------------------------------------------------------------------- #
# Probe schema version — bump this when a probe's logic changes in a way that
# invalidates previously-cached results. All ``_emit`` calls stamp the current
# version into the persisted ``ConstraintState``; the freshness check treats
# a version mismatch as STALE, forcing a re-probe.
#
# Why this exists. Posture caches persist for hours-to-days (24h default, 7d
# for structural Kerberos constraints). If a probe's logic changes (new
# technique, different signal classification, fixed false-positive path)
# without bumping this version, all existing caches keep returning the OLD
# probe's verdict until their natural TTL expires — even though the new
# code would yield a different (correct) answer. Bumping the version
# transparently invalidates every cache the moment the new code runs.
#
# When to bump:
#   * Probe technique changes (e.g. bind-based U1 -> TCP+TLS U1).
#   * Classification changes (e.g. ``timeout -> DISABLED HIGH`` becomes
#     ``timeout -> UNKNOWN LOW, no emit``).
#   * New states / signal codes that change downstream interpretation.
#
# When NOT to bump:
#   * Cosmetic changes (renamed variables, comments, refactors that don't
#     change emitted state/confidence/signal_code).
#   * Bug fixes that only affect failure paths NOT writing to the sink.
#
# Version history:
#   v1 (2026-05-26): Initial. Introduced alongside the U1 TCP+TLS rewrite
#                    and the cache-only-observations policy refactor; both
#                    invalidate any pre-existing posture cache.
#   v2 (2026-05-29): Added U4 (``_probe_ldap_starttls_available``) — a new
#                    probe with new states/signal codes (LDAP_STARTTLS_*),
#                    which changes downstream interpretation (new
#                    ``LDAP_STARTTLS_AVAILABLE`` category). Bumped so any
#                    workspace written by v1 re-probes on first contact.
#   v3 (2026-05-31): U2 (LDAP signing) and U3 (channel binding) rewritten
#                    to BIND-ONLY classification. The old technique ran a
#                    post-bind rootDSE search whose ``operationsError
#                    (ERROR_NOT_AUTHENTICATED)`` on RestrictAnonymous DCs
#                    (e.g. VulnLab Breach) masked the policy answer ->
#                    ``unknown`` -> PROBE_FAILED. v3 reads the raw BIND
#                    result instead (bind success = policy NOT required;
#                    strongerAuthRequired / SEC_E_BAD_BINDINGS = REQUIRED),
#                    uses a non-degrading random bogus principal, and adds
#                    an authenticated unsigned-bind tiebreaker (A5) when
#                    real creds are available and U2 stayed UNKNOWN. The
#                    classification rules changed, so bump to re-probe.
#   v4 (2026-06-02): probe_auth restructured to AUTH-first -> barrier ->
#                    SERVICE-after, with two classification changes that
#                    invalidate v3 caches for NTLM + SMB signing:
#                    * A3 (NTLM_AUTHENTICATION): the NTLM-disabled signature
#                      set was widened beyond SEC_E_LOGON_DENIED to also map
#                      SEC_E_UNSUPPORTED_FUNCTION / 0x80090302 /
#                      STATUS_NOT_SUPPORTED / STATUS_NTLM_BLOCKED to
#                      DISABLED HIGH, with a new signal code
#                      NTLM_REFUSED_UNSUPPORTED_FUNCTION.
#                    * A4 (SMB_SIGNING): technique changed from a
#                      post-session-setup signing read to a pre-auth NEGOTIATE
#                      read; an observed NEGOTIATE that does not require signing
#                      is now a HIGH "not required" verdict
#                      (SMB_SIGNING_NEGOTIATED_NOT_REQUIRED), upgrading the old
#                      inconclusive SMB_SIGNING_NOT_NEGOTIATED UNKNOWN/LOW.
#                    Both change downstream interpretation, so bump to re-probe.
#   v5 (2026-06-02): CBT (LDAP_CHANNEL_BINDING) detection made auth-method-aware
#                    to fix a false "not enforced" on NTLM-DISABLED DCs:
#                    * U3 (NTLM-based CBT probe) now detects the NTLM-disabled
#                      SSP-collapse signature (SEC_E_UNSUPPORTED_FUNCTION /
#                      0x80090302 / STATUS_NOT_SUPPORTED / STATUS_NTLM_BLOCKED,
#                      and SEC_E_LOGON_DENIED+invalidCredentials) at BOTH bind
#                      steps and returns UNKNOWN/LOW/no-emit
#                      (NTLM_UNAVAILABLE_CANNOT_MEASURE) instead of falling
#                      through to a HIGH "not enforced" verdict it could not
#                      actually observe.
#                    * New A6 Kerberos-path CBT probe measures channel-binding
#                      enforcement over the operational Kerberos LDAPS bind
#                      (no-CBT 16-zero token via disable_self_heal=True), gated
#                      to run only when A3 found NTLM disabled. New signal codes
#                      LDAP_CBT_REJECTED_BAD_BINDINGS_KERBEROS (REQUIRED) and
#                      LDAP_CBT_NOT_ENFORCED_KERBEROS (DISABLED), authoritative
#                      over U3 when NTLM is unavailable.
#                    Classification rules changed for LDAP_CHANNEL_BINDING, so
#                    bump to re-probe stale caches.
#   v6 (2026-06-02): LDAP signing (LDAP_SIGNING) detection made auth-method-aware
#                    to fix a false "signing not required" on NTLM-DISABLED DCs
#                    (mirrors the v5 CBT fix):
#                    * U2 (NTLM bogus-cred signing probe) now detects the
#                      NTLM-disabled SSP-collapse signature
#                      (SEC_E_UNSUPPORTED_FUNCTION / 0x80090302 /
#                      STATUS_NOT_SUPPORTED / STATUS_NTLM_BLOCKED, and
#                      SEC_E_LOGON_DENIED+invalidCredentials) BEFORE
#                      classification and returns UNKNOWN/LOW/no-emit
#                      (NTLM_UNAVAILABLE_CANNOT_MEASURE) instead of mis-reading
#                      the SSP refusal as a "logon_failure -> signing not
#                      required" HIGH verdict. This stops U2 from pre-empting A5.
#                    * A5 (authenticated signing tiebreaker) is now
#                      NTLM-disabled-aware: when A3 found NTLM disabled it binds
#                      over KERBEROS (password/aes_key/ccache) on plain LDAP/389
#                      with the same unsigned (sign=False + disable_self_heal)
#                      measurement, so it can actually measure signing on a DC
#                      where the NTLM bind would collapse. Skips when only an IP
#                      is available (Kerberos needs an FQDN for the ldap/ SPN).
#                    Classification rules changed for LDAP_SIGNING, so bump to
#                    re-probe stale caches.
#   v7 (2026-06-09): Stopped INFERRING NTLM-disabled from an unauth bogus-cred
#                    bind. A bogus-credential NTLM LDAP bind on a healthy,
#                    NTLM-ENABLED DC returns SEC_E_LOGON_DENIED + invalidCredentials
#                    (the data-52e / STATUS_LOGON_FAILURE token is stripped by the
#                    vendor formatter) -- that PROVES NTLM is alive (the DC reached
#                    the credential check and rejected the fake password), it does
#                    NOT mean NTLM is disabled. Three classifiers were mis-reading
#                    that pair as "NTLM unavailable/DISABLED":
#                    * _ntlm_bind_unavailable_in_chain (U2 signing + U3 CBT): the
#                      SEC_E_LOGON_DENIED+invalidCredentials branch is REMOVED. U2
#                      now falls through to logon_failure -> LDAP_BIND_NO_SIGN_OK
#                      (signing not required); U3 falls through to its step-2 CBT
#                      verdict. Only the genuine SSP-collapse markers still defer.
#                    * A3 (_probe_ntlm_authentication): the
#                      invalidCredentials+SEC_E_LOGON_DENIED term is REMOVED from
#                      the ntlm_disabled test; that ambiguous case now stays
#                      non-DISABLED (UNKNOWN/no-emit) so auth_plan no longer prunes
#                      NTLM. NTLM-disabled determination is left ONLY to the
#                      credential-validated transport detector (Rule 3 in
#                      ldap_transport_service), which has a concurrently-valid
#                      Kerberos TGT to disambiguate.
#                    Classification rules changed for LDAP_SIGNING,
#                    LDAP_CHANNEL_BINDING and NTLM_AUTHENTICATION, so bump to
#                    re-probe stale caches (incl. any false NTLM=DISABLED HIGH).
# v8 (2026-06-10): A5 LDAP-signing probe is now KERBEROS-first (binds the
#                    mechanism a Kerberos-first engagement uses) and is the
#                    AUTHORITATIVE signing verdict — it runs even when the unauth
#                    U2 NTLM probe already resolved signing, because sign/seal
#                    enforcement is mechanism-specific on Samba/Heimdal AD
#                    (`require strong auth=yes`). Busts stale U2-NTLM
#                    LDAP_SIGNING=DISABLED HIGH verdicts that were false for the
#                    Kerberos path.
# v9 (2026-07-13): A3 NTLM_AUTHENTICATION probe reimplemented over an SMB
#                    SESSION_SETUP (bogus credential) instead of an unsigned
#                    plain-LDAP/389 NTLM bind. The LDAP bind coupled two
#                    orthogonal signals — LDAP signing (validated first) masked
#                    the NTLM SSP verdict, so on every LDAP-signing-REQUIRED
#                    domain A3 returned PROBE_FAILED and NTLM was never learned.
#                    SMB is a different protocol from LDAP signing, so the signing
#                    requirement can no longer mask the NTLM verdict. New markers
#                    (NTLM_BLOCKED_VIA_SMB / NTLM_REACHED_CRED_CHECK_VIA_SMB) and
#                    the STATUS_NTLM_BLOCKED-vs-STATUS_LOGON_FAILURE split change
#                    the technique + classification, so bump to re-probe stale A3
#                    caches (incl. any PROBE_FAILED/UNKNOWN from the old vehicle).
_PROBE_SCHEMA_VERSION: int = 9


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


def _safe_progress(
    callback: Optional[ProbeProgressCallback],
    category: ConstraintCategory,
    result: Optional[ProbeResult],
) -> None:
    """Invoke ``callback`` swallowing every exception (telemetry only).

    The probe engine must not fail because the UI layer raised.
    """
    if callback is None:
        return
    try:
        callback(category, result)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] on_progress raised: {type(exc).__name__}: {exc}"
        )


def _should_skip(
    posture: Optional[DomainPosture],
    category: ConstraintCategory,
    force: bool,
) -> tuple[bool, Optional[ProbeResult]]:
    """Return ``(skip, skipped_result)`` for the given category.

    A probe is skipped when ALL of the following hold:
      * ``force`` is False.
      * The posture records a non-UNKNOWN HIGH-confidence value.
      * The constraint is not stale (within its TTL).
      * The persisted ``probe_schema_version`` matches the current
        ``_PROBE_SCHEMA_VERSION`` — a mismatch means the cached
        observation came from a now-obsolete probe and must be
        re-validated. Legacy records (``probe_schema_version=None``)
        are also treated as obsolete, so existing workspaces
        transparently re-probe on first contact with the new code.

    Returning ``(True, skipped_result)`` short-circuits the probe and
    returns the cached state to the caller. ``(False, None)`` means
    "run the probe".
    """
    if force or posture is None:
        return False, None
    constraint = posture.get(category)
    if constraint.state == TriState.UNKNOWN:
        return False, None
    if constraint.confidence != SignalConfidence.HIGH:
        return False, None
    if constraint.is_stale:
        return False, None
    if constraint.is_schema_outdated(_PROBE_SCHEMA_VERSION):
        return False, None
    skipped = ProbeResult(
        category=category,
        state=constraint.state,
        confidence=constraint.confidence,
        signal_code="SKIPPED_ALREADY_KNOWN",
        message=f"Already known: {constraint.state.value} ({constraint.confidence.value})",
        duration_ms=0.0,
        succeeded=True,
        skipped=True,
    )
    return True, skipped


def _walk_chain(exc: BaseException) -> list[BaseException]:
    """Walk ``__cause__``/``__context__`` chain, returning every linked exception."""
    seen: set[int] = set()
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _chain_text(exc: BaseException) -> str:
    """Render the exception chain as one lowercase string for substring matches."""
    return " ".join(f"{type(c).__name__}: {c}".lower() for c in _walk_chain(exc))


def _emit(
    sink: PostureSink,
    *,
    domain: str,
    category: ConstraintCategory,
    state: TriState,
    confidence: SignalConfidence,
    signal_code: str,
    message: str,
    protocol: str,
    source: str = "posture_probe",
) -> None:
    """Best-effort emission of one ``PostureSignal`` through ``sink``.

    Stamps ``_PROBE_SCHEMA_VERSION`` on every emission so the persisted
    record carries the version of the probe-code that produced it. The
    freshness check in :func:`_should_skip` treats a version mismatch
    (or a missing version on legacy records) as STALE and forces a
    re-probe.
    """
    try:
        signal = PostureSignal(
            domain=domain,
            category=category,
            state=state,
            confidence=confidence,
            source=source,
            signal_code=signal_code,
            message=message,
            protocol=protocol,
            observed_at=datetime.now(timezone.utc),
            probe_schema_version=_PROBE_SCHEMA_VERSION,
        )
        sink(signal)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[posture_probe] sink raised: {type(exc).__name__}: {exc}")


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


# --------------------------------------------------------------------------- #
# Unauth probes
# --------------------------------------------------------------------------- #


async def _probe_ldaps_available(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe U1 — LDAPS reachability AND functionality on TCP/636.

    The question this probe answers is: **"is LDAPS actually usable
    against this DC?"**. We discriminate three failure modes the
    posture system cares about distinctly:

    * ``LDAPS_PORT_CLOSED`` — TCP/636 returns RST or is unreachable.
      The port is not listening at all.
    * ``LDAPS_TLS_BROKEN`` — TCP/636 accepts the connection but the
      TLS handshake fails (cert expired, cipher mismatch, unsupported
      TLS version, broken cert chain). Port is open but LDAPS is not
      functional. Observed in real customer environments where a DC
      had a stale self-signed cert that no client could negotiate.
    * ``LDAPS_HANDSHAKE_TIMEOUT`` — neither side completes within
      the budget. Treat as DISABLED (any subsequent LDAPS operation
      would suffer the same hang).

    Two-step in a single call. ``asyncio.open_connection(ssl=ctx)``
    does TCP + TLS handshake in one shot, and the exception type
    discriminates the layer:

    * ``ConnectionRefusedError`` / generic ``OSError`` → TCP layer.
    * ``ssl.SSLError`` → TLS layer (TCP succeeded, handshake failed).
    * ``asyncio.TimeoutError`` → either layer hung past the budget.

    We deliberately do NOT speak LDAP after the TLS handshake. The
    posture question is "can we negotiate LDAPS"; what we'd do with
    the channel is a separate concern owned by ``_probe_ldap_signing``
    and ``_probe_ldaps_channel_binding``.

    Certificate validation is intentionally disabled (``CERT_NONE``,
    ``check_hostname=False``). AD DCs frequently present self-signed
    or domain-CA-issued certificates whose hostname does not match
    the DC's IP. A strict TLS context would reject those even though
    every real LDAPS client (impacket, badldap, native Windows) also
    accepts them. The goal is to mirror what a functional LDAPS
    client would see, not to validate the PKI.

    Why a short timeout (capped at 2s of the caller's budget): TLS
    handshake to a reachable DC on a LAN completes well under 200ms.
    Anything taking longer is either congested or filtered. A short
    cap also keeps the posture cycle bounded — U1's outcome gates U3,
    so a 5s wait here delays the entire unauth wave by 5s for nothing.
    """
    import ssl as _ssl  # noqa: PLC0415 — kept local; only U1 needs it

    cat = ConstraintCategory.LDAPS_AVAILABLE
    started = _now_ms()
    handshake_timeout = min(timeout, 2.0)

    # AD DCs commonly present certs that don't match the IP/hostname
    # we connect with. Every real LDAPS client (impacket, badldap,
    # native Windows) skips strict validation here — we mirror that.
    ssl_ctx = _ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = _ssl.CERT_NONE

    print_info_debug(
        f"[posture_probe] U1 LDAPS opening TCP+TLS to {dc_ip}:636 "
        f"(timeout={handshake_timeout}s, ssl_check_hostname=False, "
        f"ssl_verify_mode=CERT_NONE)"
    )
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=dc_ip, port=636, ssl=ssl_ctx),
            timeout=handshake_timeout,
        )
        print_info_debug(
            f"[posture_probe] U1 LDAPS TCP+TLS handshake OK on {dc_ip}:636 "
            f"in {_now_ms() - started:.0f}ms"
        )
        # TCP + TLS both succeeded → LDAPS is functional.
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_TLS_OK",
            message="TCP/636 reachable and TLS handshake succeeded — LDAPS functional",
            protocol="ldaps",
        )
        return ProbeResult(
            category=cat,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_TLS_OK",
            message="TCP/636 reachable and TLS handshake succeeded — LDAPS functional",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except _ssl.SSLError as exc:
        # TCP succeeded but TLS layer failed (cert expired, cipher
        # mismatch, broken chain, ...). Port is open but LDAPS is not
        # functional — distinct from "port closed".
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U1 LDAPS ssl.SSLError on {dc_ip}:636 after "
            f"{_now_ms() - started:.0f}ms — {type(exc).__name__}: {exc} "
            f"(args={exc.args!r})"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_TLS_BROKEN",
            message=f"TCP/636 open but TLS handshake failed: {type(exc).__name__}",
            protocol="ldaps",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_TLS_BROKEN",
            message=f"TCP/636 open but TLS handshake failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        # A timeout is NOT an observation about LDAPS availability — it's
        # an observation about OUR clock. The handshake might be slow,
        # the event loop might be saturated by concurrent probes, or the
        # DC might be transiently busy. Treating timeout as DISABLED HIGH
        # was the bug that poisoned posture caches for 24h after a single
        # bad run (see CLAUDE.md § "Posture caching policy"). The correct
        # answer is UNKNOWN LOW + NO sink emit — the cache stays untouched
        # and the next operation re-probes.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U1 LDAPS asyncio.TimeoutError on {dc_ip}:636 "
            f"after {_now_ms() - started:.0f}ms (budget={handshake_timeout}s) — "
            "did NOT complete TCP+TLS handshake. Likely causes: DC TLS slow, "
            "filtered, or SNI mismatch (no server_hostname supplied). "
            "NOT persisting to posture (cache-only-observations policy)."
        )
        # NOTE: no ``_emit`` here — timeout does not persist to posture.
        # The probe failed to characterise the DC; cache stays untouched.
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAPS_HANDSHAKE_TIMEOUT",
            message=f"TCP/636 + TLS handshake hung past {handshake_timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except ConnectionRefusedError as exc:
        # Explicit TCP RST from the DC — port is closed. This IS an
        # observation; cache HIGH normally.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U1 LDAPS ConnectionRefused on {dc_ip}:636 "
            f"after {_now_ms() - started:.0f}ms — {exc}"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_PORT_CLOSED",
            message="TCP/636 returned RST — port closed",
            protocol="ldaps",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_PORT_CLOSED",
            message="TCP/636 returned RST — port closed",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except OSError as exc:
        # Generic OSError covers ``ENETUNREACH`` / ``EHOSTUNREACH`` — the
        # kernel telling us the DC is not routable. That IS an
        # observation (the network layer answered) so we cache HIGH.
        # Other rare OSErrors are also captured here — if the kernel
        # answered, the answer is authoritative for this network state.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U1 LDAPS OSError on {dc_ip}:636 "
            f"after {_now_ms() - started:.0f}ms — {type(exc).__name__}: "
            f"{exc} (errno={getattr(exc, 'errno', None)!r})"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_NETWORK_UNREACHABLE",
            message=f"TCP/636 network unreachable ({type(exc).__name__})",
            protocol="ldaps",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_NETWORK_UNREACHABLE",
            message=f"TCP/636 network unreachable ({type(exc).__name__})",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    finally:
        # Best-effort close — never let an open socket leak into the
        # event loop after the probe answers.
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as close_exc:  # noqa: BLE001
                telemetry.capture_exception(close_exc)


async def _probe_ldap_starttls_available(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe U4 — StartTLS (RFC 2830) availability on plain LDAP/389.

    The question this probe answers is: **"can a plain LDAP/389 session be
    upgraded to TLS via StartTLS against this DC?"**. StartTLS is the only
    confidentiality mechanism that protects *anonymous/SIMPLE* binds without
    an LDAPS (636) listener, so its availability is a distinct posture fact
    from ``LDAPS_AVAILABLE`` — a DC can have 636 filtered yet still present a
    usable cert on 389, or vice-versa.

    Technique (modeled on :func:`_probe_ldaps_available`): open a raw
    ``MSLDAPClientConnection`` to ``ldap://<dc_ip>`` (plain 389, anonymous,
    no bind), then call the vendor StartTLS primitive
    (``MSLDAPClientConnection.starttls()`` in
    ``vendor/badldap/badldap/connection.py``). That primitive sends the
    StartTLS extendedReq (OID ``1.3.6.1.4.1.1466.20037``) and, on a success
    result code, wraps the socket in TLS. We never bind — the posture
    question is purely "does the StartTLS handshake complete", what we would
    do with the channel is a separate concern.

    Observed-vs-inferred discrimination (CLAUDE.md § Posture caching policy):

    * ``LDAP_STARTTLS_OK`` — extendedReq accepted AND TLS handshake completed
      (``starttls()`` returned ``ok=True``). ENABLED HIGH — OBSERVED.
    * ``LDAP_STARTTLS_REFUSED`` — extendedReq returned a non-success result
      code (``unwillingToPerform`` / refused), surfaced as
      ``LDAPBindException``. DISABLED HIGH — OBSERVED (the DC told us no).
    * ``LDAP_STARTTLS_TLS_BROKEN`` — extendedReq accepted but the TLS wrap
      raised ``ssl.SSLError`` (absent/broken/expired cert). DISABLED HIGH —
      OBSERVED.
    * ``LDAP_STARTTLS_PORT_CLOSED`` — TCP/389 refused or unreachable
      (``ConnectionRefusedError`` / ``OSError``). DISABLED HIGH — OBSERVED
      (the network layer answered).
    * ``LDAP_STARTTLS_TIMEOUT`` — ``asyncio.TimeoutError`` / event-loop
      saturation / anything we cannot classify. UNKNOWN LOW, **NO ``_emit``**
      — a timeout is an observation about OUR clock, not about the DC.
      Caching it would poison the category for 24h after a single transient
      hang (the exact bug class documented in CLAUDE.md § Posture caching
      policy, Invariant 2). The cache stays clean; the next caller re-probes.

    Certificate validation is intentionally disabled — AD DCs commonly
    present self-signed / domain-CA certs whose SAN does not match the IP we
    connect with, and the vendor target's SSL context mirrors what every real
    LDAPS/StartTLS client (impacket, badldap, native Windows) accepts. The
    goal is to mirror a functional client, not to validate the PKI.
    """
    import ssl as _ssl  # noqa: PLC0415 — kept local; only U4 needs the type

    from badldap.commons.exceptions import (  # noqa: PLC0415
        LDAPBindException,
    )
    from badldap.commons.factory import (  # noqa: PLC0415
        LDAPConnectionFactory,
    )

    cat = ConstraintCategory.LDAP_STARTTLS_AVAILABLE
    started = _now_ms()
    handshake_timeout = min(timeout, 5.0)

    # Anonymous, plain LDAP/389 URL. ``MSLDAPTarget.from_url`` defaults to
    # port 389 + plain (non-TLS) transport for the bare ``ldap://`` scheme.
    url = f"ldap://{dc_ip}"

    print_info_debug(
        f"[posture_probe] U4 StartTLS opening plain LDAP/389 to {dc_ip} "
        f"(timeout={handshake_timeout}s, anonymous, no bind, "
        "ssl_verify disabled per vendor target default)"
    )

    raw_conn = None
    try:
        factory = LDAPConnectionFactory.from_url(url)
        raw_conn = factory.get_connection()
        # StartTLS (RFC 2830) does not enforce channel binding, and we never
        # bind — keep both off so the probe exercises the bare upgrade path.
        if hasattr(raw_conn, "_disable_signing"):
            raw_conn._disable_signing = True
        if hasattr(raw_conn, "_disable_channel_binding"):
            raw_conn._disable_channel_binding = True

        async def _connect_and_starttls() -> tuple[bool, Optional[BaseException]]:
            ok, err = await raw_conn.connect()
            if not ok:
                # Surface the connect failure as the StartTLS outcome — a
                # dead TCP/389 means StartTLS is unreachable. ``connect()``
                # returns ``(False, err)`` rather than raising for some
                # transport failures; re-raise so the classifier below sees
                # the same exception type a raising path would produce.
                raise err or ConnectionRefusedError(
                    f"plain LDAP/389 connect to {dc_ip} returned ok=False"
                )
            return await raw_conn.starttls()

        starttls_ok, starttls_err = await asyncio.wait_for(
            _connect_and_starttls(), timeout=handshake_timeout
        )

        if starttls_ok and starttls_err is None:
            # extendedReq accepted AND TLS handshake completed.
            print_info_debug(
                f"[posture_probe] U4 StartTLS OK on {dc_ip}:389 in "
                f"{_now_ms() - started:.0f}ms — RFC 2830 upgrade succeeded"
            )
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_OK",
                message="StartTLS extendedReq accepted and TLS handshake succeeded on LDAP/389",
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_OK",
                message="StartTLS extendedReq accepted and TLS handshake succeeded on LDAP/389",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )

        # ``starttls()`` returns ``(False, err)`` for both a refused result
        # code (``LDAPBindException``) and a TLS-layer failure (``ssl.SSLError``
        # caught inside the vendor primitive and returned as ``err``). Branch
        # on the error type to discriminate REFUSED vs TLS_BROKEN.
        if isinstance(starttls_err, _ssl.SSLError):
            telemetry.capture_exception(starttls_err)
            print_info_debug(
                f"[posture_probe] U4 StartTLS ssl.SSLError on {dc_ip}:389 after "
                f"{_now_ms() - started:.0f}ms — extendedReq accepted but TLS "
                f"handshake failed: {type(starttls_err).__name__}: {starttls_err}"
            )
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_TLS_BROKEN",
                message=(
                    "StartTLS accepted but TLS handshake failed "
                    f"({type(starttls_err).__name__}) — no usable DC cert on 389"
                ),
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_TLS_BROKEN",
                message=(
                    "StartTLS accepted but TLS handshake failed "
                    f"({type(starttls_err).__name__}) — no usable DC cert on 389"
                ),
                duration_ms=_now_ms() - started,
                succeeded=True,
            )

        if isinstance(starttls_err, LDAPBindException):
            telemetry.capture_exception(starttls_err)
            print_info_debug(
                f"[posture_probe] U4 StartTLS refused on {dc_ip}:389 after "
                f"{_now_ms() - started:.0f}ms — DC returned non-success result "
                f"code: {starttls_err}"
            )
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_REFUSED",
                message="DC refused StartTLS extendedReq (unwillingToPerform) — StartTLS not offered",
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_REFUSED",
                message="DC refused StartTLS extendedReq (unwillingToPerform) — StartTLS not offered",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )

        # ``starttls()`` returned a non-success without a recognised error
        # type. We could not characterise the DC's answer — treat as
        # inferred-by-absence: UNKNOWN/LOW, NO emit, cache stays clean.
        if starttls_err is not None:
            telemetry.capture_exception(starttls_err)
        print_info_debug(
            f"[posture_probe] U4 StartTLS unclassifiable result on {dc_ip}:389 "
            f"after {_now_ms() - started:.0f}ms — "
            f"err={type(starttls_err).__name__ if starttls_err else None}. "
            "NOT persisting to posture (cache-only-observations policy)."
        )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAP_STARTTLS_TIMEOUT",
            message="StartTLS returned an unclassifiable result — re-probe next time",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except asyncio.TimeoutError as exc:
        # A timeout is NOT an observation about StartTLS availability — it's
        # an observation about OUR clock. The event loop may be saturated by
        # concurrent probes, or the DC transiently busy. Caching DISABLED HIGH
        # here is the exact bug that poisoned ``LDAPS_AVAILABLE`` for 24h after
        # a single bad run (CLAUDE.md § Posture caching policy, Invariant 2).
        # Correct answer: UNKNOWN LOW + NO sink emit — the cache stays
        # untouched and the next operation re-probes.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U4 StartTLS asyncio.TimeoutError on {dc_ip}:389 "
            f"after {_now_ms() - started:.0f}ms (budget={handshake_timeout}s) — "
            "did NOT complete the StartTLS upgrade. NOT persisting to posture "
            "(cache-only-observations policy)."
        )
        # NOTE: no ``_emit`` here — timeout does not persist to posture.
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAP_STARTTLS_TIMEOUT",
            message=f"StartTLS upgrade hung past {handshake_timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except ConnectionRefusedError as exc:
        # Explicit TCP RST from the DC — port 389 is closed. This IS an
        # observation; cache DISABLED HIGH.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U4 StartTLS ConnectionRefused on {dc_ip}:389 "
            f"after {_now_ms() - started:.0f}ms — {exc}"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_PORT_CLOSED",
            message="TCP/389 returned RST — plain LDAP port closed, StartTLS unreachable",
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_PORT_CLOSED",
            message="TCP/389 returned RST — plain LDAP port closed, StartTLS unreachable",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except _ssl.SSLError as exc:
        # TLS layer failed during the wrap (if it escaped the vendor
        # primitive rather than being returned as ``err``). extendedReq was
        # accepted, the cert is broken/absent — OBSERVED DISABLED HIGH.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U4 StartTLS ssl.SSLError (raised) on {dc_ip}:389 "
            f"after {_now_ms() - started:.0f}ms — {type(exc).__name__}: {exc}"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_TLS_BROKEN",
            message=f"StartTLS accepted but TLS handshake failed: {type(exc).__name__}",
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_TLS_BROKEN",
            message=f"StartTLS accepted but TLS handshake failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except OSError as exc:
        # Generic OSError covers ``ENETUNREACH`` / ``EHOSTUNREACH`` — the
        # kernel telling us the DC is not routable. The network layer
        # answered, so this IS an observation; cache DISABLED HIGH.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U4 StartTLS OSError on {dc_ip}:389 after "
            f"{_now_ms() - started:.0f}ms — {type(exc).__name__}: {exc} "
            f"(errno={getattr(exc, 'errno', None)!r})"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_PORT_CLOSED",
            message=f"TCP/389 network unreachable ({type(exc).__name__}) — StartTLS unreachable",
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_PORT_CLOSED",
            message=f"TCP/389 network unreachable ({type(exc).__name__}) — StartTLS unreachable",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except Exception as exc:  # noqa: BLE001
        # Anything we cannot classify is inferred-by-absence: it tells us
        # about OUR state, not the DC's. UNKNOWN/LOW, NO emit — cache clean,
        # next caller re-probes.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U4 StartTLS unclassifiable exception on {dc_ip}:389 "
            f"after {_now_ms() - started:.0f}ms — {type(exc).__name__}: {exc}. "
            "NOT persisting to posture (cache-only-observations policy)."
        )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAP_STARTTLS_TIMEOUT",
            message=f"StartTLS probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    finally:
        # Best-effort close — never let a raw socket leak into the event loop
        # after the probe answers.
        if raw_conn is not None:
            try:
                disc = getattr(raw_conn, "disconnect", None)
                if disc is not None:
                    res = disc()
                    if asyncio.iscoroutine(res):
                        await res
            except Exception as close_exc:  # noqa: BLE001
                telemetry.capture_exception(close_exc)


# --------------------------------------------------------------------------- #
# Bogus-credential constants — BIND-ONLY transport-policy probing
#
# U2 (signing) and U3 (CBT) ask the DC which **transport policy** is in force
# by attempting an LDAP BIND with bogus credentials over an unsigned / no-CBT
# channel, and reading the **bind result code** directly. Crucially the probe
# runs in BIND-ONLY mode (``bind_only=True`` in
# ``async_connect_with_ldap_fallback``): it stops after the bind and never
# issues the post-bind rootDSE search. The bind result tells us the policy:
#
#   * Policy REQUIRED -> the bind fails on the policy check with a
#     transport-specific code (``strongerAuthRequired`` for signing;
#     ``SEC_E_BAD_BINDINGS`` for CBT). The DC short-circuits BEFORE the
#     credential check, so the bogus credential never matters.
#   * Policy NOT required -> the unsigned / no-CBT bind is ACCEPTED at the
#     bind layer. (Against AD, an NTLM SICILY LDAP bind returns bind-level
#     ``success`` even for a non-existent principal — the credential is only
#     fully evaluated when a subsequent operation needs the security context.
#     So "bind accepted" is the definitive NOT-required signal here, observed
#     empirically against VulnLab Breach where ``nxc ldap`` reports
#     ``signing:None``.)
#
# Why BIND-ONLY and not the old post-bind-search technique: the previous
# design let badldap's ``client.connect()`` run ``get_serverinfo`` (a rootDSE
# SEARCH) after the bind. On a RestrictAnonymous DC that search returns
# ``operationsError (ERROR_NOT_AUTHENTICATED)`` — a SEARCH-level error that
# has nothing to do with the bind policy — and the classifier could only
# read ``unknown`` -> ``PROBE_FAILED``. Reading the bind result directly is
# the robust fix.
#
# Why a non-degrading bogus principal (NOT an anonymous bind): an anonymous
# LDAP bind can SUCCEED even when signing is enforced for AUTHENTICATED
# principals (the "LDAP server signing requirements" GPO may apply only to
# authenticated / SASL binds). NetExec's anonymous technique only POSITIVELY
# confirms enforced (``strongerAuthRequired``) and DEFAULTS every other
# outcome to "not enforced" -> false-negative risk. We deliberately do NOT
# copy that. We force a genuine AUTHENTICATED NTLM bind by using a RANDOM,
# almost-certainly-non-existent sAMAccountName per call (so it can never
# accidentally match a real account and lock it out) with a bogus password.
# A blank ``" "`` user is avoided because some stacks degrade it toward an
# anonymous bind, which would re-introduce the false-negative.
#
# Layered design — authenticated tiebreaker (A5): when the unauth bogus-cred
# probe returns UNKNOWN (e.g. a transient failure we could not classify) AND
# valid domain credentials are available (``start_auth`` phase), an OPTIONAL
# authenticated check runs an unsigned bind with the REAL credential. A
# successful unsigned authenticated bind is the most definitive possible
# "signing NOT required" signal. The unauth bogus-cred probe stays the
# PRIMARY path (works with no creds); A5 is a tiebreaker layer, not a
# replacement. See ``_probe_ldap_signing_authenticated``.
#
# OPSEC note: each bogus bind generates a ``4625`` audit event on the DC.
# NetExec produces the same event with every ``nxc ldap`` invocation, so this
# is industry-norm noise for an authorised engagement. Operators who need a
# quieter probe can opt out via ``ADSCAN_NO_POSTURE_PROBE=1``.
# --------------------------------------------------------------------------- #
_BOGUS_CRED_PASSWORD = "Bogus!Probe#Pw0"  # noqa: S105 — intentionally rejected


def _make_bogus_probe_user() -> str:
    """Return a random, almost-certainly-non-existent sAMAccountName.

    Used by the bogus-credential transport-policy probes (U2 signing, U3 CBT)
    to force a GENUINE authenticated NTLM bind that the DC will not accept as
    anonymous. The nonce varies per call so it can never accidentally match a
    real account (and therefore never risks a lockout on a real principal).
    """
    import secrets

    return f"adscan-probe-{secrets.token_hex(4)}"

# DC response signatures. Sourced from:
#   * ``vendor/badldap/badldap/protocol/messages.py`` (LDAP result codes)
#   * ``vendor/badldap/badldap/wintypes/winerror.py`` (Windows error codes)
#
# Matched defensively against the rendered exception chain in both their
# code-name and raw-hex forms — badldap's formatter normally prints the
# code name, but a code path that bypasses it would still surface the hex.
_LDAP_SIGNING_REQUIRED_SIGS = (
    "strongerauthrequired",
    "ldap_strong_auth_required",
    "error_ds_strong_auth_required",
    "0x00002028",
    "0x2028",
    "00002028",
)
_LDAP_CBT_REQUIRED_SIGS = (
    "sec_e_bad_bindings",
    "channel bindings were incorrect",
    "channel binding",
    "0x80090346",
    "80090346",
)
# ``STATUS_LOGON_FAILURE`` (Windows error ``0xC000006D``, NTLM "data 52e"
# in LDAP error text). Surfaces from badauth's NTLM client when the DC
# rejects the bogus credential — meaning the transport policy passed and
# the DC moved on to the credential check, i.e. the policy is NOT required.
_LDAP_LOGON_FAILURE_SIGS = (
    "status_logon_failure",
    "data 52e",
    "0xc000006d",
    "c000006d",
    "logon_failure",
    "invalidcredentials",
)


def _classify_ldap_policy_response(exc: BaseException) -> str:
    """Classify a bogus-cred LDAP bind exception against the DC.

    Returns one of:
      * ``"signing_required"`` — DC rejected with ``strongerAuthRequired``
        before credential check (policy: signing REQUIRED).
      * ``"cbt_required"`` — DC rejected with ``SEC_E_BAD_BINDINGS`` before
        credential check (policy: CBT REQUIRED).
      * ``"logon_failure"`` — DC accepted the transport but rejected the
        bogus credential (policy: NOT required for this bind type).
      * ``"unknown"`` — other failure (network, TLS, clock skew, ...).
    """
    text = _chain_text(exc)
    # Order matters: signing/CBT codes are checked first because the DC
    # short-circuits on policy violations BEFORE the credential check.
    # A ``strongerAuthRequired`` or ``bad_bindings`` always precedes any
    # ``logon_failure`` text in the same exception chain.
    if any(sig in text for sig in _LDAP_CBT_REQUIRED_SIGS):
        return "cbt_required"
    if any(sig in text for sig in _LDAP_SIGNING_REQUIRED_SIGS):
        return "signing_required"
    if any(sig in text for sig in _LDAP_LOGON_FAILURE_SIGS):
        return "logon_failure"
    return "unknown"


def _ntlm_bind_unavailable_in_chain(exc: BaseException) -> bool:
    """Return whether a bogus-cred NTLM bind failed because NTLM is disabled.

    On an NTLM-DISABLED DC (``LmCompatibilityLevel`` / ``RestrictNTLM`` GPO),
    the NTLM SSP collapses BEFORE the DC ever reaches the credential check --
    so the failure tells us nothing about the LDAP transport policy (signing,
    channel binding) we were trying to measure with that bind. The signatures
    below mirror the function-local ``_NTLM_REFUSED_PLAIN_BIND_MARKERS`` set in
    :func:`_probe_ntlm_authentication` (A3).

    Critically, ``invalidcredentials`` alone is NOT enough: a healthy DC that
    merely rejected the BOGUS credential also surfaces ``invalidCredentials``
    (``STATUS_LOGON_FAILURE`` / data 52e) -- that is the GOOD path that proves
    the transport policy passed. We only treat the bind as "NTLM unavailable"
    when one of the NTLM-SSP-collapse markers is present.

    ``sec_e_logon_denied`` + ``invalidcredentials`` (with NO SSP-collapse
    marker) is DELIBERATELY NOT treated as NTLM-unavailable here. On a healthy,
    NTLM-ENABLED DC a bogus-credential bind returns exactly that pair: the DC
    reached the credential check and rejected the fake password -- which PROVES
    NTLM is alive, not disabled (the vendor formatter strips the ``data 52e`` /
    ``STATUS_LOGON_FAILURE`` token, so the only surviving signal is the
    ``invalidCredentials`` LDAP result code). Inferring NTLM-disabled from this
    unauth, bogus-cred reject is ambiguous (wrong/expired cred vs disabled) and
    used to make U2/U3 defer their real signing/CBT verdict. The ONLY reliable
    NTLM-disabled discriminator needs a concurrently-valid credential (Kerberos
    TGT), which the unauth probe path lacks; that determination is owned solely
    by the credential-validated transport detector (Rule 3 in
    ``ldap_transport_service``). So we let the bogus-cred reject fall through to
    ``_classify_ldap_policy_response`` (``invalidcredentials`` ->
    ``logon_failure``) and emit the real transport-policy verdict.

    This is the U3-context analogue of A3's classifier and is deliberately a
    distinct, local predicate (not a shared module constant): the same markers
    mean "seal could not negotiate -> cleartext downgrade" in
    ``ldap_transport_service._is_seal_negotiation_failure`` where sealing was
    requested, so they must never be unified into one classifier.
    """
    text = _chain_text(exc)
    ntlm_ssp_collapse_markers = (
        "sec_e_unsupported_function",
        "0x80090302",
        "80090302",
        "status_not_supported",
        "status_ntlm_blocked",
    )
    if any(m in text for m in ntlm_ssp_collapse_markers):
        return True
    return False


async def _probe_ldap_signing(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe U2 — LDAP signing enforcement via a BIND-ONLY bogus-cred bind.

    Opens an NTLM LDAP bind on port 389 with a random non-existent
    sAMAccountName, a bogus password, ``sign=False``, and ``bind_only=True``
    (stop after the bind; never run the post-bind rootDSE search). The DC
    validates signing policy at the BIND, so the bind result is conclusive:

      * Bind ACCEPTED (no exception) -> the DC permitted an UNSIGNED
        authenticated bind -> signing NOT required. ``DISABLED`` HIGH, emit.
        (An NTLM SICILY LDAP bind against AD returns bind-level ``success``
        even for a non-existent principal; "bind accepted" is therefore the
        definitive not-required signal. Matches ``nxc ldap signing:None``.)
      * ``strongerAuthRequired`` (LDAP result code 8 /
        ``ERROR_DS_STRONG_AUTH_REQUIRED`` = 0x00002028) -> signing REQUIRED.
        ``REQUIRED`` HIGH, emit.
      * Any other outcome (timeout, transport failure, an
        ``operationsError`` that escaped bind-only, an unclassifiable
        exception) -> ``UNKNOWN`` LOW, **no emit**. Per the cache-only-
        observations policy (CLAUDE.md Invariant 2), an inferred-by-absence
        result must never persist; the next caller re-probes.

    Why bind-only: the previous post-bind rootDSE search returned
    ``operationsError (ERROR_NOT_AUTHENTICATED)`` on RestrictAnonymous DCs
    (e.g. VulnLab Breach), masking the bind answer -> ``unknown``. Reading
    the bind result directly is the robust fix.

    Why a random non-existent principal and not an anonymous bind: an
    anonymous bind can succeed even when signing is enforced for
    authenticated principals — false-negative risk. See the
    ``_BOGUS_CRED_PASSWORD`` block comment for the full rationale, the
    NetExec anonymous-technique critique, and the layered design.

    Operational note: emits a ``4625`` audit event on the DC. See the
    bogus-credential block comment for OPSEC discussion.
    """
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
    )

    cat = ConstraintCategory.LDAP_SIGNING
    started = _now_ms()
    cfg = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=False,
        use_kerberos=False,
        username=_make_bogus_probe_user(),
        password=_BOGUS_CRED_PASSWORD,
        # Explicit OFF — the probe's purpose is to ask the DC whether it
        # enforces signing. A planner that already learned signing=REQUIRED
        # from a previous run might have flipped this on; that would mask
        # the result.
        sign=False,
        # The probe INTENTIONALLY elicits ``strongerAuthRequired``. The
        # transport's self-heal would silently retry with ``sign=True``
        # and "succeed", falsifying the answer. See ``disable_self_heal``.
        disable_self_heal=True,
    )

    print_info_debug(
        f"[posture_probe] U2 signing opening LDAP/389 bind-only bogus-cred bind to {dc_ip}:389 "
        f"(timeout={timeout}s, sign=False, bind_only=True, disable_self_heal=True)"
    )
    try:
        conn, _ = await asyncio.wait_for(
            async_connect_with_ldap_fallback(cfg, bind_only=True), timeout=timeout
        )
        # Bind ACCEPTED over an unsigned channel -> signing NOT required.
        # This is the definitive not-required signal (bind-only never ran a
        # post-bind search, so no RestrictAnonymous operationsError to mask it).
        try:
            disc = getattr(conn, "disconnect", None)
            if disc is not None:
                res = disc()
                if asyncio.iscoroutine(res):
                    await res
        except Exception as disc_exc:  # noqa: BLE001
            telemetry.capture_exception(disc_exc)
        print_info_debug(
            f"[posture_probe] U2 signing -> bind accepted (not required) on {dc_ip}:389 "
            f"in {_now_ms() - started:.0f}ms"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_BIND_NO_SIGN_OK",
            message="Unsigned LDAP bind accepted at the bind layer — signing not required",
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_BIND_NO_SIGN_OK",
            message="Unsigned LDAP bind accepted at the bind layer — signing not required",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        # elapsed-vs-budget delta is the key diagnostic: elapsed ~ budget
        # → genuine latency/slow DC; elapsed << budget → the coroutine was
        # starved (event-loop contention), which would argue for serializing
        # the bogus-cred binds rather than running them in the same wave.
        print_info_debug(
            f"[posture_probe] U2 signing timed out after {timeout}s on {dc_ip}:389 "
            f"— elapsed {_now_ms() - started:.0f}ms. "
            "NOT persisting to posture (cache-only-observations policy)."
        )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"LDAP signing probe timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        # NTLM-disabled DC: the bogus-cred NTLM bind collapses in the SSP
        # BEFORE the DC validates LDAP signing, so U2 cannot measure signing
        # enforcement this way. Observe-don't-infer: return UNKNOWN/LOW with NO
        # emit (never the false "signing not required" verdict). Critically,
        # this must be checked BEFORE _classify_ldap_policy_response, because an
        # NTLM-SSP collapse can surface ``invalidCredentials`` alongside the
        # ``sec_e_unsupported_function`` marker -- and a bare ``invalidcredentials``
        # would otherwise be (correctly, for the NTLM-available case) read as the
        # GOOD ``logon_failure`` "reached credential check -> signing not required"
        # path. ``_ntlm_bind_unavailable_in_chain`` fires ONLY on the genuine
        # SSP-collapse markers (NOT on a bare sec_e_logon_denied +
        # invalidCredentials, which on an NTLM-enabled DC merely means the DC
        # rejected the bogus password -> NTLM alive), so a genuine data 52e on an
        # NTLM-enabled DC still flows to the not-required branch below.
        # Deferring here (no HIGH verdict) is what lets the authenticated A5
        # tiebreaker actually run instead of being short-circuited by a false U2
        # resolution. The Kerberos-capable A5 probe is the authoritative
        # measurement in this case (mirrors U3 -> A6 for channel binding).
        if _ntlm_bind_unavailable_in_chain(exc):
            print_info_debug(
                "[posture_probe] U2 signing -> NTLM unavailable on "
                f"{dc_ip}:389; cannot measure LDAP signing via NTLM (deferring to "
                "the authenticated A5 tiebreaker). No verdict emitted."
            )
            return ProbeResult(
                category=cat,
                state=TriState.UNKNOWN,
                confidence=SignalConfidence.LOW,
                signal_code="NTLM_UNAVAILABLE_CANNOT_MEASURE",
                message=(
                    "NTLM bind unavailable on DC; LDAP signing not measurable via "
                    "NTLM (authenticated A5 tiebreaker is authoritative)"
                ),
                duration_ms=_now_ms() - started,
                succeeded=False,
            )
        verdict = _classify_ldap_policy_response(exc)
        print_info_debug(
            f"[posture_probe] U2 signing -> {verdict} (exception) on {dc_ip}:389 "
            f"in {_now_ms() - started:.0f}ms"
        )
        if verdict == "signing_required":
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STRONG_AUTH_REQUIRED",
                message="DC requires LDAP signing",
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STRONG_AUTH_REQUIRED",
                message="DC requires LDAP signing",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        if verdict == "logon_failure":
            # Some DCs reject the bogus credential at the bind layer with
            # ``data 52e`` instead of accepting the bind. That still proves
            # the DC PERMITTED the unsigned bind (it reached credential
            # validation) -> signing NOT required. HIGH, emit.
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_BIND_NO_SIGN_OK",
                message=(
                    "Unsigned LDAP bind reached credential validation (data 52e) — "
                    "signing not required"
                ),
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_BIND_NO_SIGN_OK",
                message=(
                    "Unsigned LDAP bind reached credential validation (data 52e) — "
                    "signing not required"
                ),
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        # Everything else (incl. an operationsError that escaped bind-only,
        # transport error, clock skew) is inferred-by-absence -> UNKNOWN LOW,
        # NO emit. The authenticated tiebreaker (A5) may resolve it later when
        # real creds are available; otherwise the next caller re-probes.
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"LDAP signing probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


def _resolve_ldap_signing_spn_host(
    dc_fqdn: Optional[str], dc_ip: Optional[str]
) -> Optional[str]:
    """Resolve an FQDN usable as the ``ldap/`` SPN host for the A5 Kerberos probe.

    A Kerberos SPN cannot target an IP (CLAUDE.md § Kerberos SPNs), so this
    returns the caller-supplied ``dc_fqdn`` when present, else ``dc_ip`` only if
    it is itself a hostname, else ``None`` (no Kerberos-capable SPN host).
    Shared by ``_probe_ldap_signing_authenticated`` (A5) and the ``probe_auth``
    gate so both agree on whether A5 can measure signing over Kerberos.
    """
    from adscan_internal.services._kerberos_spn import is_ip_address

    host = str(dc_fqdn or "").strip().rstrip(".")
    if not host:
        candidate = str(dc_ip or "").strip().rstrip(".")
        if candidate and not is_ip_address(candidate):
            host = candidate
    if not host or is_ip_address(host):
        return None
    return host


async def _probe_ldap_signing_authenticated(
    *,
    domain: str,
    dc_ip: str,
    creds: "ProbeCredentials",
    sink: PostureSink,
    timeout: float,
    posture: Optional[DomainPosture] = None,
    dc_fqdn: Optional[str] = None,
) -> ProbeResult:
    """Probe A5 — authenticated LDAP-signing tiebreaker (real credentials).

    Runs ONLY as a tiebreaker: when the unauth bogus-cred U2 probe could not
    classify signing (stayed ``UNKNOWN``) AND valid domain credentials are
    available (``start_auth`` phase). It performs an UNSIGNED, BIND-ONLY bind
    with the REAL credential on port 389:

      * Bind SUCCEEDS (unsigned authenticated bind accepted) -> the most
        definitive possible "signing NOT required" signal — resolves
        RestrictAnonymous DCs like VulnLab Breach where the unauth probe's
        downstream signals were ambiguous. ``DISABLED`` HIGH, emit.
      * ``strongerAuthRequired`` -> signing REQUIRED. ``REQUIRED`` HIGH, emit.
      * Anything else (timeout, transport failure, even an auth failure —
        which tells us nothing about the signing policy) -> stay ``UNKNOWN``
        LOW, **no emit**.

    This is a LAYER on top of the primary unauth probe, never a replacement:
    the unauth path works with no creds and stays the default. See the
    ``_BOGUS_CRED_PASSWORD`` block comment for the layered-design rationale.

    Auth-method selection — KERBEROS-first (the mechanism operations use):
      LDAP sign/seal enforcement is MECHANISM-SPECIFIC on some DCs. A Samba AD
      DC with ``ldap server require strong auth = yes`` rejects a GSS-SPNEGO
      (Kerberos) bind that negotiates no SASL security layer
      (``strongerAuthRequired — SASL:[GSS-SPNEGO]: Sign or Seal are required``)
      but lets an NTLM bind reach the credential check, because NTLMSSP
      advertises signing intrinsically. So measuring signing over NTLM yields a
      FALSE "not required" verdict for the Kerberos path (verified live against
      a Samba 4 AD DC). ADscan is Kerberos-first, so A5 measures the Kerberos
      path whenever it can:
      * When a Kerberos credential (password/aes_key/ccache) AND an FQDN for the
        ``ldap/`` SPN are available, A5 binds over KERBEROS on port 389 — this is
        the AUTHORITATIVE signing verdict for the engagement, not just the
        NTLM-disabled fallback. The LDAP-transport salt-correct-TGT pre-mint
        makes this work on non-default-salt / AES-only KDCs.
      * Otherwise (no Kerberos credential, or only an IP / no resolvable FQDN)
        A5 falls back to the NTLM/SIMPLE unsigned bind with password/NT-hash.
        An NTLM-disabled DC with only an IP cannot be measured either way (the
        Kerberos SPN needs an FQDN) -> SKIP.

    Either way the bind is UNSIGNED (``sign=False`` + ``disable_self_heal=True``).
    ``disable_self_heal=True`` is load-bearing: it makes
    ``_apply_default_seal_to_plain_ldap`` SKIP the seal-by-default upgrade for
    authenticated plain-LDAP/389, so the bind stays unsigned (the measurement)
    and the reactive self-heal does not retry with sign+seal after a
    signing-required rejection. On plain LDAP/389 the verdict is conclusive FOR
    THE BOUND MECHANISM: ``strongerAuthRequired`` -> REQUIRED; bind accepted /
    reached credential validation -> NOT_REQUIRED. Measuring over Kerberos makes
    that mechanism the engagement's actual path.
    """
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
    )

    cat = ConstraintCategory.LDAP_SIGNING
    started = _now_ms()

    # Decide whether NTLM is unusable on this DC (so the NTLM unsigned bind
    # would collapse before measuring signing). Read the in-flight overlay
    # (caller posture + A3's just-computed verdict) -- same source A6 uses.
    ntlm_state = posture.get(ConstraintCategory.NTLM_AUTHENTICATION) if posture else None
    ntlm_disabled_known = (
        ntlm_state is not None
        and ntlm_state.state == TriState.DISABLED
        and ntlm_state.confidence == SignalConfidence.HIGH
        and not ntlm_state.is_stale
    )
    has_kerberos_credential = (
        creds.password is not None
        or creds.aes_key is not None
        or creds.ccache_path is not None
    )
    # KERBEROS-first: prefer the Kerberos path whenever we have a Kerberos
    # credential AND a resolvable FQDN for the ldap/ SPN. The Kerberos GSS-SPNEGO
    # bind is the mechanism a Kerberos-first engagement uses, and its signing
    # requirement can differ from NTLM's on mechanism-specific DCs (Samba
    # `require strong auth=yes`) — so this is the authoritative measurement, not
    # only the NTLM-disabled fallback. ``_ntlm_disabled_known`` no longer gates
    # this; it only decides the SKIP reason when no FQDN is available.
    spn_host = _resolve_ldap_signing_spn_host(dc_fqdn, dc_ip)

    if has_kerberos_credential and spn_host is not None:
        cfg = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=False,
            use_kerberos=True,
            username=creds.username,
            password=creds.password,
            aes_key=creds.aes_key,
            ccache_path=creds.ccache_path,
            kerberos_target_hostname=spn_host,
            # UNSIGNED on purpose (see docstring): sign=False + disable_self_heal
            # keeps the plain-LDAP/389 Kerberos bind off the seal-by-default
            # upgrade, so an accepted bind proves signing NOT required and a
            # strongerAuthRequired proves it IS required.
            sign=False,
            disable_self_heal=True,
        )
        print_info_debug(
            f"[posture_probe] A5 signing probe (KERBEROS, authoritative) "
            f"opening LDAP/389 unsigned authenticated bind-only bind to {spn_host} "
            f"(dc_ip={dc_ip}) as {mark_sensitive(creds.username, 'user')} "
            f"(timeout={timeout}s)"
        )
    elif ntlm_disabled_known and has_kerberos_credential:
        # NTLM disabled and Kerberos is the only usable mechanism, but no FQDN
        # is available for the ldap/ SPN -> cannot measure signing either way.
        return _make_skipped(
            cat,
            reason=(
                "Skipped: NTLM disabled and only an IP is available -- the "
                "Kerberos LDAP-signing probe needs a DC FQDN for the ldap/ SPN"
            ),
        )
    else:
        # NTLM available (or no in-flight posture) -> original NTLM/SIMPLE
        # unsigned bind. ccache-only Kerberos creds are not useful here when
        # NTLM is the chosen mechanism; require a password or NT-hash.
        password = creds.password if creds.password is not None else creds.nt_hash
        if not creds.username or not password:
            return _make_skipped(
                cat,
                reason=(
                    "Skipped: authenticated signing tiebreaker requires "
                    "username + password/hash (NTLM path)"
                ),
            )
        cfg = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=False,
            use_kerberos=False,
            username=creds.username,
            password=password,
            # UNSIGNED on purpose: if the DC accepts an unsigned AUTHENTICATED
            # bind, signing is definitively not required.
            sign=False,
            disable_self_heal=True,
        )
        print_info_debug(
            f"[posture_probe] A5 signing tiebreaker opening LDAP/389 unsigned authenticated "
            f"bind-only bind to {dc_ip}:389 as {mark_sensitive(creds.username, 'user')} "
            f"(timeout={timeout}s)"
        )
    try:
        conn, _ = await asyncio.wait_for(
            async_connect_with_ldap_fallback(cfg, bind_only=True), timeout=timeout
        )
        try:
            disc = getattr(conn, "disconnect", None)
            if disc is not None:
                res = disc()
                if asyncio.iscoroutine(res):
                    await res
        except Exception as disc_exc:  # noqa: BLE001
            telemetry.capture_exception(disc_exc)
        print_info_debug(
            f"[posture_probe] A5 signing tiebreaker -> unsigned authenticated bind accepted "
            f"(not required) on {dc_ip}:389 in {_now_ms() - started:.0f}ms"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_AUTH_BIND_NO_SIGN_OK",
            message="Unsigned authenticated LDAP bind accepted — signing not required",
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_AUTH_BIND_NO_SIGN_OK",
            message="Unsigned authenticated LDAP bind accepted — signing not required",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"Authenticated signing tiebreaker timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        verdict = _classify_ldap_policy_response(exc)
        print_info_debug(
            f"[posture_probe] A5 signing tiebreaker -> {verdict} (exception) on {dc_ip}:389 "
            f"in {_now_ms() - started:.0f}ms"
        )
        if verdict == "signing_required":
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STRONG_AUTH_REQUIRED",
                message="DC requires LDAP signing (observed via authenticated bind)",
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STRONG_AUTH_REQUIRED",
                message="DC requires LDAP signing (observed via authenticated bind)",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        # An auth failure (bad creds / locked) tells us nothing about the
        # signing policy. Stay UNKNOWN, no emit.
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"Authenticated signing tiebreaker inconclusive: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )

async def _probe_ldaps_channel_binding(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    timeout: float,
    posture: Optional[DomainPosture] = None,
) -> ProbeResult:
    """Probe U3 — LDAPS channel binding requirement via BIND-ONLY bogus-cred binds.

    Two-step probe modelled on NetExec's ``check_ldaps_cbt`` (see
    ``reference/NetExec/nxc/protocols/ldap.py``), run in BIND-ONLY mode so the
    bind result is read directly (no post-bind rootDSE search that a
    RestrictAnonymous DC answers with ``operationsError`` — see the U2 probe
    and the ``_BOGUS_CRED_PASSWORD`` block comment):

      1. **No-CBT bind**. NTLM bind on LDAPS (port 636) with the CBT field
         omitted and a random bogus principal. The bind result:
           * ``SEC_E_BAD_BINDINGS`` (0x80090346) -> CBT enforced for ALL
             binds, regardless of credential validity. Emit ``REQUIRED`` HIGH
             and return.
           * Bind ACCEPTED -> the DC permitted a bind WITHOUT a CBT token.
             CBT is not enforced for absent CBT — but the policy could still
             be "When Supported" (enforce CBT only when a token IS supplied).
             Go to step 2 to disambiguate.

      2. **Wrong-CBT bind**. Same NTLM bind, but with a deliberately invalid
         CBT token populated (``null_channel_binding`` -> ``_null_channel_binding``
         in the badldap connection). Bind result:
           * ``SEC_E_BAD_BINDINGS`` -> DC validates CBT when present -> policy
             is "When Supported". Emit ``REQUIRED`` HIGH (any client that
             sends CBT must send a valid one).
           * Bind ACCEPTED -> DC ignored the wrong CBT token entirely ->
             policy is "Never". Emit ``DISABLED`` HIGH.

    Anything else at either step (timeout, transport failure, an
    unclassifiable exception) -> ``UNKNOWN`` LOW, **no emit** (cache-only-
    observations policy). Skipped when LDAPS is known unavailable — CBT lives
    only on TLS.

    Operational note: each bogus bind generates a ``4625`` audit event on the
    DC. See the bogus-credential block comment for OPSEC discussion.
    """
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
        is_ldaps_transport_failure,
    )

    cat = ConstraintCategory.LDAP_CHANNEL_BINDING
    started = _now_ms()

    # Early skip when LDAPS is known to be unavailable.
    if posture is not None:
        ldaps = posture.get(ConstraintCategory.LDAPS_AVAILABLE)
        if (
            ldaps is not None
            and ldaps.state == TriState.DISABLED
            and ldaps.confidence == SignalConfidence.HIGH
            and not ldaps.is_stale
        ):
            return _make_skipped(
                cat,
                reason=(
                    "Skipped: LDAPS not available on this DC — channel "
                    "binding cannot exist without a TLS channel"
                ),
            )

    def _make_cfg(*, null_cbt: bool) -> "ADscanLDAPConfig":
        return ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=True,
            use_kerberos=False,
            username=_make_bogus_probe_user(),
            password=_BOGUS_CRED_PASSWORD,
            # Default: no CBT in the bind. When ``null_cbt`` is True the
            # CBT field IS populated, but with garbage — used in step 2
            # to discriminate "When Supported" from "Never".
            channel_binding=False,
            null_channel_binding=null_cbt,
            disable_self_heal=True,
        )

    async def _attempt(
        cfg: "ADscanLDAPConfig", *, step: int
    ) -> tuple[Optional[Exception], bool]:
        """Run a single BIND-ONLY bind; return (exception_or_None, bind_accepted)."""
        attempt_started = _now_ms()
        print_info_debug(
            f"[posture_probe] U3 CBT opening LDAPS bind-only bogus-cred bind to {dc_ip}:636 "
            f"(timeout={timeout}s, step={step}, "
            f"null_cbt={getattr(cfg, 'null_channel_binding', False)})"
        )
        try:
            conn, _ = await asyncio.wait_for(
                async_connect_with_ldap_fallback(cfg, bind_only=True), timeout=timeout
            )
            try:
                disc = getattr(conn, "disconnect", None)
                if disc is not None:
                    res = disc()
                    if asyncio.iscoroutine(res):
                        await res
            except Exception as disc_exc:  # noqa: BLE001
                telemetry.capture_exception(disc_exc)
            return None, True
        except asyncio.TimeoutError as exc:
            # elapsed-vs-budget delta is the key diagnostic: elapsed ~ budget
            # → genuine latency/slow DC; elapsed << budget → the coroutine was
            # starved (event-loop contention with U2), which would argue for
            # serializing the two bogus-cred binds rather than running them in
            # the same wave.
            print_info_debug(
                f"[posture_probe] U3 CBT timed out after {timeout}s (step {step}) "
                f"on {dc_ip}:636 — elapsed {_now_ms() - attempt_started:.0f}ms"
            )
            return exc, False
        except Exception as exc:  # noqa: BLE001
            return exc, False

    # ---------------- Step 1 — no-CBT bind ----------------
    exc, accepted = await _attempt(_make_cfg(null_cbt=False), step=1)
    if not accepted:
        assert exc is not None
        telemetry.capture_exception(exc)
        if isinstance(exc, asyncio.TimeoutError):
            return ProbeResult(
                category=cat,
                state=TriState.UNKNOWN,
                confidence=SignalConfidence.LOW,
                signal_code="PROBE_TIMEOUT",
                message=f"CBT probe timed out after {timeout}s (step 1)",
                duration_ms=_now_ms() - started,
                succeeded=False,
            )
        if is_ldaps_transport_failure(exc):
            return ProbeResult(
                category=cat,
                state=TriState.UNKNOWN,
                confidence=SignalConfidence.LOW,
                signal_code="LDAPS_UNAVAILABLE",
                message="LDAPS unreachable; CBT requirement undetermined",
                duration_ms=_now_ms() - started,
                succeeded=False,
            )
        # NTLM-disabled DC: the bogus-cred NTLM bind collapses in the SSP
        # BEFORE the DC validates channel binding, so U3 cannot measure CBT
        # enforcement this way. Observe-don't-infer: return UNKNOWN/LOW with NO
        # emit (never the false "not enforced" verdict). The Kerberos-path CBT
        # probe in ``probe_auth`` is the authoritative measurement in this case.
        if _ntlm_bind_unavailable_in_chain(exc):
            print_info_debug(
                "[posture_probe] U3 CBT step 1 -> NTLM unavailable on "
                f"{dc_ip}:636; cannot measure CBT via NTLM (deferring to the "
                "Kerberos-path CBT probe). No verdict emitted."
            )
            return ProbeResult(
                category=cat,
                state=TriState.UNKNOWN,
                confidence=SignalConfidence.LOW,
                signal_code="NTLM_UNAVAILABLE_CANNOT_MEASURE",
                message=(
                    "NTLM bind unavailable on DC; CBT not measurable via NTLM "
                    "(Kerberos-path CBT probe is authoritative)"
                ),
                duration_ms=_now_ms() - started,
                succeeded=False,
            )
        verdict = _classify_ldap_policy_response(exc)
        print_info_debug(
            f"[posture_probe] U3 CBT step 1 -> {verdict} (exception) on {dc_ip}:636 "
            f"in {_now_ms() - started:.0f}ms"
        )
        if verdict == "cbt_required":
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_CBT_REJECTED_BAD_BINDINGS",
                message="DC rejected LDAPS bind without CBT (SEC_E_BAD_BINDINGS)",
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_CBT_REJECTED_BAD_BINDINGS",
                message="DC rejected LDAPS bind without CBT (SEC_E_BAD_BINDINGS)",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        if verdict == "logon_failure":
            # DC reached credential validation without rejecting the missing
            # CBT -> CBT not enforced for absent CBT. Fall through to step 2
            # to disambiguate "Never" vs "When Supported".
            print_info_debug(
                "[posture_probe] U3 CBT step 1 -> data 52e (no-CBT bind reached "
                "credential check); proceeding to step 2"
            )
        else:
            # Some other failure — cannot classify CBT requirement.
            return ProbeResult(
                category=cat,
                state=TriState.UNKNOWN,
                confidence=SignalConfidence.LOW,
                signal_code="PROBE_FAILED",
                message=f"CBT probe step 1 failed: {type(exc).__name__}",
                duration_ms=_now_ms() - started,
                succeeded=False,
            )
    else:
        print_info_debug(
            f"[posture_probe] U3 CBT step 1 -> no-CBT bind accepted on {dc_ip}:636 "
            f"in {_now_ms() - started:.0f}ms; proceeding to step 2"
        )

    # ---------------- Step 2 — wrong-CBT bind to disambiguate ----------------
    # Step 1 proved the DC accepted (or reached credential validation on) a
    # bind WITHOUT a CBT token. Now bind with a deliberately wrong CBT token:
    # if the DC validates CBT when present, this fails with SEC_E_BAD_BINDINGS
    # ("When Supported"); if the DC ignores CBT entirely, the bind is accepted
    # (or reaches credential validation) -> "Never".
    exc2, accepted2 = await _attempt(_make_cfg(null_cbt=True), step=2)
    if accepted2:
        # Wrong-CBT bind ACCEPTED -> DC ignored the CBT token -> "Never".
        print_info_debug(
            f"[posture_probe] U3 CBT step 2 -> wrong-CBT bind accepted on {dc_ip}:636 "
            f"in {_now_ms() - started:.0f}ms (channel binding NOT enforced)"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_NOT_ENFORCED",
            message=(
                "DC ignored both missing and wrong CBT tokens — channel binding not enforced"
            ),
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_NOT_ENFORCED",
            message=(
                "DC ignored both missing and wrong CBT tokens — channel binding not enforced"
            ),
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    assert exc2 is not None
    telemetry.capture_exception(exc2)
    # NTLM-disabled DC at step 2 as well: same observe-don't-infer rule. A
    # wrong-CBT bind that collapsed in the NTLM SSP proves nothing about CBT
    # enforcement, so never fall through to the "not enforced" verdict below.
    if _ntlm_bind_unavailable_in_chain(exc2):
        print_info_debug(
            "[posture_probe] U3 CBT step 2 -> NTLM unavailable on "
            f"{dc_ip}:636; cannot measure CBT via NTLM. No verdict emitted."
        )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="NTLM_UNAVAILABLE_CANNOT_MEASURE",
            message=(
                "NTLM bind unavailable on DC; CBT not measurable via NTLM "
                "(Kerberos-path CBT probe is authoritative)"
            ),
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    verdict2 = _classify_ldap_policy_response(exc2)
    print_info_debug(
        f"[posture_probe] U3 CBT step 2 -> {verdict2} (exception) on {dc_ip}:636 "
        f"in {_now_ms() - started:.0f}ms"
    )
    if verdict2 == "cbt_required":
        # DC validates CBT when present → "When Supported" policy. Treat
        # as REQUIRED because any client that sends CBT MUST send a valid
        # one — and any well-behaved client (badldap, impacket, native
        # Windows) sends CBT on LDAPS.
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_WHEN_SUPPORTED",
            message=(
                "DC accepts no-CBT bind but rejects wrong-CBT bind (When Supported policy)"
            ),
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_WHEN_SUPPORTED",
            message=(
                "DC accepts no-CBT bind but rejects wrong-CBT bind (When Supported policy)"
            ),
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    if verdict2 == "logon_failure":
        # Wrong-CBT bind reached credential validation -> DC ignored the CBT
        # token -> "Never".
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_NOT_ENFORCED",
            message=(
                "DC ignored both missing and wrong CBT tokens — channel binding not enforced"
            ),
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_NOT_ENFORCED",
            message=(
                "DC ignored both missing and wrong CBT tokens — channel binding not enforced"
            ),
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    return ProbeResult(
        category=cat,
        state=TriState.UNKNOWN,
        confidence=SignalConfidence.LOW,
        signal_code="PROBE_FAILED",
        message=f"CBT probe step 2 failed: {type(exc2).__name__}",
        duration_ms=_now_ms() - started,
        succeeded=False,
    )


def _ldap_posture_field_from_result(result: ProbeResult) -> Optional[tuple[str, bool]]:
    """Map an LDAP signing / channel-binding ``ProbeResult`` to a display field.

    Returns ``(label, hardened)`` when the DC gave a definitive answer, or
    ``None`` when the result is inconclusive (``succeeded is False`` or
    ``state == UNKNOWN`` — including a skipped probe). ``TriState.REQUIRED``
    is the only hardened state; any other observed state (``DISABLED`` /
    ``ENABLED``) means the policy is present but not enforced.
    """
    if not result.succeeded or result.state == TriState.UNKNOWN:
        return None
    if result.state == TriState.REQUIRED:
        return ("Required", True)
    return ("None", False)


async def probe_ldap_security_for_dc(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    timeout: float = 5.0,
) -> dict:
    """Audit one DC's LDAP signing + channel-binding posture natively.

    Reuses the single-source-of-truth detection probes
    (:func:`_probe_ldap_signing` on LDAP/389 and
    :func:`_probe_ldaps_channel_binding` on LDAPS/636) instead of parsing a
    subprocess auditor's banner text, and maps their ``ProbeResult`` outcomes
    into the per-DC ``parsed`` shape the LDAP-security audit consumes::

        {"entries": [{"signing": <str>, "signing_hardened": <bool>,
                      "channel_binding": <str>, "channel_binding_hardened": <bool>,
                      "server_name": <dc_ip>}]}

    Honest-unknown contract: if EITHER probe fails to obtain a definitive
    answer (``succeeded is False`` or ``state == UNKNOWN``), the DC could not
    be conclusively audited, so ``{"entries": []}`` is returned — the audit
    summarizer treats an empty entries list as unreachable, the correct honest
    outcome when the DC did not answer. This function adds no detection logic:
    the probes emit only OBSERVED states to ``sink`` (cache-only-observations
    policy), so the domain posture cache learns the verdict as a side effect.

    Args:
        domain: Target domain (realm) of the DC being audited.
        dc_ip: DC address or FQDN to probe (used as ``server_name`` in the
            returned entry).
        sink: Posture sink the underlying probes emit observed signals through.
        timeout: Per-probe wall-clock budget in seconds.

    Returns:
        The per-DC ``parsed`` dict described above.
    """
    signing_result = await _probe_ldap_signing(
        domain=domain, dc_ip=dc_ip, sink=sink, timeout=timeout
    )
    cbt_result = await _probe_ldaps_channel_binding(
        domain=domain, dc_ip=dc_ip, sink=sink, timeout=timeout
    )

    signing_field = _ldap_posture_field_from_result(signing_result)
    cbt_field = _ldap_posture_field_from_result(cbt_result)
    if signing_field is None or cbt_field is None:
        # At least one signal was inconclusive — do not fabricate a partial
        # verdict. An empty entries list is read as unreachable by the audit
        # summarizer, which is the honest outcome.
        return {"entries": []}

    signing_label, signing_hardened = signing_field
    channel_binding_label, channel_binding_hardened = cbt_field
    return {
        "entries": [
            {
                "signing": signing_label,
                "signing_hardened": signing_hardened,
                "channel_binding": channel_binding_label,
                "channel_binding_hardened": channel_binding_hardened,
                "server_name": dc_ip,
            }
        ]
    }


async def _probe_ldaps_channel_binding_kerberos(
    *,
    domain: str,
    dc_ip: str,
    creds: "ProbeCredentials",
    sink: PostureSink,
    timeout: float,
    dc_fqdn: Optional[str] = None,
) -> ProbeResult:
    """Probe A6 -- LDAPS channel-binding requirement via a KERBEROS bind.

    Authoritative replacement for U3 when NTLM is disabled. U3 measures CBT
    enforcement with a bogus-credential **NTLM** bind; on an NTLM-DISABLED DC
    that bind collapses in the SSP before the DC validates channel binding
    (``SEC_E_UNSUPPORTED_FUNCTION`` etc.), so U3 cannot measure and (per Part A)
    returns UNKNOWN/no-emit. This probe measures the SAME single LDAP policy
    (``LdapEnforceChannelBinding``) over the operational Kerberos auth path that
    every real ADscan LDAPS operation uses, so its verdict is authoritative.

    Methodology (validated empirically against ping.htb, 2026-06):

      * Build an LDAPS Kerberos bind config with ``channel_binding=False`` AND
        ``disable_self_heal=True``. The just-merged "default CBT-on for
        operational LDAPS binds" policy in
        ``ldap_transport_service._apply_default_cbt_to_authenticated_ldaps``
        SKIPS any config with ``disable_self_heal=True`` (or explicit
        ``channel_binding`` / ``null_channel_binding``) -- see that helper's
        discriminator:

            if (not is_ldaps
                or getattr(cfg, "disable_self_heal", False)
                or _config_requests_explicit_cbt(cfg)
                or not _plain_ldap_can_seal(cfg)):
                # left untouched

        ``disable_self_heal=True`` therefore guarantees the bind carries the
        16-zero "no bindings" GSS checksum token and is NOT silently upgraded
        to the real ``tls-server-end-point`` CBT -- which is exactly what makes
        the measurement possible. ``disable_self_heal=True`` ALSO stops the
        reactive self-heal from retrying with CBT after a ``SEC_E_BAD_BINDINGS``
        rejection, so the raw verdict bubbles up.

    Classification:
      * Bind raises ``SEC_E_BAD_BINDINGS`` -> the DC rejected a no-CBT
        Kerberos bind -> ``LDAP_CHANNEL_BINDING=REQUIRED`` HIGH (emit).
      * Bind succeeds (or reaches credential validation without a bad-bindings
        rejection) -> the DC accepted a no-CBT bind ->
        ``LDAP_CHANNEL_BINDING=NOT_REQUIRED`` (``DISABLED``) HIGH (emit).
      * Timeout / LDAPS-unreachable / unclassifiable -> ``UNKNOWN`` LOW, NO
        emit (observe-don't-infer, same policy as U3 and § 7bis of the
        AD-constraints checklist for slow links).

    The Kerberos SPN MUST be an FQDN, never an IP (CLAUDE.md § Kerberos SPNs).
    ``dc_fqdn`` is the caller-resolved FQDN (``resolve_dc_fqdn``); when absent
    we fall back to ``dc_ip`` only if it is itself a hostname. If only an IP is
    available the probe SKIPs (no FQDN -> a Kerberos bind cannot be attempted
    correctly), rather than minting a ticket against a wrong SPN.
    """
    from adscan_internal.services._kerberos_spn import is_ip_address
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
        is_ldaps_transport_failure,
    )

    cat = ConstraintCategory.LDAP_CHANNEL_BINDING
    started = _now_ms()

    # Resolve an FQDN for the Kerberos SPN. An IP cannot target a Kerberos SPN
    # correctly (CLAUDE.md § Kerberos SPNs) -- skip rather than mis-target.
    spn_host = str(dc_fqdn or "").strip().rstrip(".")
    if not spn_host:
        candidate = str(dc_ip or "").strip().rstrip(".")
        if candidate and not is_ip_address(candidate):
            spn_host = candidate
    if not spn_host or is_ip_address(spn_host):
        return _make_skipped(
            cat,
            reason=(
                "Skipped: Kerberos-path CBT probe needs a DC FQDN (only an IP "
                "is available); cannot target the ldap/ SPN"
            ),
        )

    cfg = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=True,
        username=creds.username,
        password=creds.password,
        aes_key=creds.aes_key,
        ccache_path=creds.ccache_path,
        kerberos_target_hostname=spn_host,
        # CRITICAL: channel_binding=False + disable_self_heal=True hits the
        # SKIP discriminator in _apply_default_cbt_to_authenticated_ldaps, so
        # the bind sends the 16-zero no-CBT token (the measurement) and the
        # transport does NOT auto-retry with CBT after SEC_E_BAD_BINDINGS.
        channel_binding=False,
        disable_self_heal=True,
    )
    if creds.password is None and creds.nt_hash is not None and creds.aes_key is None:
        # A plain NT hash cannot drive a Kerberos bind on its own; if that is
        # the only secret, prefer ccache/aes already set above. Nothing to do.
        pass

    print_info_debug(
        f"[posture_probe] A6 Kerberos-CBT opening LDAPS Kerberos no-CBT bind to "
        f"{spn_host} (dc_ip={dc_ip}, timeout={timeout}s)"
    )
    try:
        conn, _ = await asyncio.wait_for(
            async_connect_with_ldap_fallback(cfg, bind_only=True), timeout=timeout
        )
        try:
            disc = getattr(conn, "disconnect", None)
            if disc is not None:
                res = disc()
                if asyncio.iscoroutine(res):
                    await res
        except Exception as disc_exc:  # noqa: BLE001
            telemetry.capture_exception(disc_exc)
        # Bind accepted with NO CBT token -> CBT not enforced for absent CBT.
        print_info_debug(
            f"[posture_probe] A6 Kerberos-CBT -> no-CBT bind ACCEPTED on "
            f"{spn_host} in {_now_ms() - started:.0f}ms (channel binding NOT required)"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_NOT_ENFORCED_KERBEROS",
            message=(
                "DC accepted a Kerberos LDAPS bind without channel binding -- "
                "channel binding not enforced"
            ),
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_NOT_ENFORCED_KERBEROS",
            message=(
                "DC accepted a Kerberos LDAPS bind without channel binding -- "
                "channel binding not enforced"
            ),
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] A6 Kerberos-CBT timed out after {timeout}s on "
            f"{spn_host} -- elapsed {_now_ms() - started:.0f}ms; no verdict emitted"
        )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"Kerberos CBT probe timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        if is_ldaps_transport_failure(exc):
            return ProbeResult(
                category=cat,
                state=TriState.UNKNOWN,
                confidence=SignalConfidence.LOW,
                signal_code="LDAPS_UNAVAILABLE",
                message="LDAPS unreachable; CBT requirement undetermined",
                duration_ms=_now_ms() - started,
                succeeded=False,
            )
        verdict = _classify_ldap_policy_response(exc)
        print_info_debug(
            f"[posture_probe] A6 Kerberos-CBT -> {verdict} (exception) on "
            f"{spn_host} in {_now_ms() - started:.0f}ms"
        )
        if verdict == "cbt_required":
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_CBT_REJECTED_BAD_BINDINGS_KERBEROS",
                message=(
                    "DC rejected a Kerberos LDAPS bind without channel binding "
                    "(SEC_E_BAD_BINDINGS)"
                ),
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_CBT_REJECTED_BAD_BINDINGS_KERBEROS",
                message=(
                    "DC rejected a Kerberos LDAPS bind without channel binding "
                    "(SEC_E_BAD_BINDINGS)"
                ),
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        if verdict == "logon_failure":
            # Reached credential validation without a bad-bindings rejection ->
            # the DC accepted the no-CBT channel -> CBT not enforced.
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_CBT_NOT_ENFORCED_KERBEROS",
                message=(
                    "DC accepted a Kerberos LDAPS bind without channel binding "
                    "-- channel binding not enforced"
                ),
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_CBT_NOT_ENFORCED_KERBEROS",
                message=(
                    "DC accepted a Kerberos LDAPS bind without channel binding "
                    "-- channel binding not enforced"
                ),
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        # Anything else (clock skew, KDC error, unclassifiable) -- observe,
        # don't infer.
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"Kerberos CBT probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


# --------------------------------------------------------------------------- #
# Auth probes
# --------------------------------------------------------------------------- #


async def _probe_kerberos_rc4(
    *,
    domain: str,
    dc_ip: str,
    creds: ProbeCredentials,
    sink: PostureSink,
    posture: Optional[DomainPosture],
    force: bool,
    timeout: float,
) -> ProbeResult:
    """Probe A1 — explicit etype=23 AS-REQ; emits RC4 + AES_ONLY signals."""
    from adscan_internal.services.kerberos_transport import (
        KerberosConfig,
        KerberosEtypeError,
        get_tgt,
    )

    cat = ConstraintCategory.KERBEROS_RC4
    aes_only_cat = ConstraintCategory.KERBEROS_AES_ONLY
    started = _now_ms()
    cfg = KerberosConfig(
        domain=domain,
        kdc_ip=dc_ip,
        username=creds.username,
        password=creds.password,
        etypes=[23],
        # Probe wants the raw KDC_ERR_ETYPE_NOTSUPP to propagate so it
        # can emit ``KERBEROS_RC4=DISABLED + AES_ONLY=ENABLED``.
        # Without this flag, get_tgt's self-heal silently retries with
        # AES, the TGT succeeds, and the probe falsely concludes that
        # RC4 is supported.
        disable_self_heal=True,
    )

    def _emit_aes_only(state: TriState, signal_code: str, message: str) -> None:
        if not force and posture is not None:
            existing = posture.get(aes_only_cat)
            if (
                existing.state != TriState.UNKNOWN
                and existing.confidence == SignalConfidence.HIGH
                and not existing.is_stale
            ):
                return
        _emit(
            sink,
            domain=domain,
            category=aes_only_cat,
            state=state,
            confidence=SignalConfidence.HIGH,
            signal_code=signal_code,
            message=message,
            protocol="kerberos",
        )

    try:
        await asyncio.wait_for(get_tgt(cfg), timeout=timeout)
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="RC4_TGT_OK",
            message="KDC issued RC4 TGT",
            protocol="kerberos",
        )
        _emit_aes_only(
            TriState.DISABLED,
            "RC4_TGT_OK",
            "KDC issued RC4 TGT — AES-only is not enforced",
        )
        return ProbeResult(
            category=cat,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="RC4_TGT_OK",
            message="KDC issued RC4 TGT",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except KerberosEtypeError as exc:
        telemetry.capture_exception(exc)
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="KDC_ERR_ETYPE_NOTSUPP",
            message="KDC rejected RC4 — domain enforces AES-only Kerberos",
            protocol="kerberos",
        )
        _emit_aes_only(
            TriState.ENABLED,
            "KDC_ERR_ETYPE_NOTSUPP",
            "AES-only Kerberos enforced by KDC",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="KDC_ERR_ETYPE_NOTSUPP",
            message="KDC rejected RC4 — domain enforces AES-only Kerberos",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"Kerberos RC4 probe timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"Kerberos RC4 probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


async def _probe_kerberos_etype(
    *,
    domain: str,
    dc_ip: str,
    creds: ProbeCredentials,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe A2 — drives the existing ETYPE-INFO2 salt probe and reports outcome."""
    from adscan_internal.services.kerberos_transport import (
        KerberosConfig,
        _probe_and_set_etype_info2_salt,
    )

    cat = ConstraintCategory.KERBEROS_ETYPE_PROBE
    started = _now_ms()
    cfg = KerberosConfig(
        domain=domain,
        kdc_ip=dc_ip,
        username=creds.username,
        password=creds.password,
        disable_self_heal=True,
    )
    try:
        from kerbad.common.factory import KerberosClientFactory  # noqa: PLC0415

        # Re-use the same URL builder the transport uses.
        from adscan_internal.services.kerberos_transport import (
            _build_kerberos_url,
        )

        url = _build_kerberos_url(cfg, use_auth_kdc=True)
        cu = KerberosClientFactory.from_url(url)
        client = cu.get_client()

        nondefault = await asyncio.wait_for(
            _probe_and_set_etype_info2_salt(client, cfg), timeout=timeout
        )
        if nondefault:
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="ETYPE_INFO2_NONDEFAULT_SALT",
                message="KDC advertises non-default AES salt",
                protocol="kerberos",
            )
            return ProbeResult(
                category=cat,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="ETYPE_INFO2_NONDEFAULT_SALT",
                message="KDC advertises non-default AES salt",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="STANDARD_SALT_OK",
            message="Standard Kerberos salt",
            protocol="kerberos",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="STANDARD_SALT_OK",
            message="Standard Kerberos salt",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"Etype probe timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"Etype probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


def _classify_ntlm_session_setup_outcome(
    outcome: Any,
) -> Optional[tuple[TriState, str, str]]:
    """Map a raw SMB SESSION_SETUP outcome to an NTLM enforcement verdict.

    Returns ``(state, signal_code, message)`` for a definitive verdict, or
    ``None`` when the outcome does not reach a clean NTLM SSP decision
    (unclassifiable NTSTATUS) — the A3 probe then returns UNKNOWN/LOW and does
    NOT emit (CLAUDE.md posture policy: cache observations, never absences).

    CRITICAL BOUNDARY (design 2026-07-13 §4.1): the marker tuples below are
    function-local and MUST NOT reuse ``smb_transport._NTLM_BLOCKED_MARKERS``.
    That shared set conflates ``STATUS_LOGON_FAILURE`` with
    ``STATUS_NTLM_BLOCKED`` because for the fallback-retry path both mean "try
    Kerberos next". For THIS probe they are OPPOSITE verdicts:

      * ``LOGON_FAILURE`` — the DC reached the credential stage and rejected the
        bogus password: the NTLM SSP processed an authentication -> ENABLED.
      * ``NTLM_BLOCKED`` / ``NOT_SUPPORTED`` / ``SEC_E_UNSUPPORTED_FUNCTION`` —
        the NTLM SSP refused the session-setup outright -> DISABLED.

    Sharing the marker set would flip one verdict into its opposite.
    """
    if getattr(outcome, "session_established", False):
        return (
            TriState.ENABLED,
            "NTLM_SESSION_SETUP_OK",
            "SMB NTLM session-setup succeeded (NTLM is enabled)",
        )

    # NTLM SSP refused the SESSION_SETUP outright -> NTLM disabled by policy.
    _NTLM_DISABLED_SSP_MARKERS = (
        "ntlm_blocked",  # NTStatus.NTLM_BLOCKED (0xC0000418)
        "not_supported",  # NTStatus.NOT_SUPPORTED (0xC00000BB)
        "sec_e_unsupported_function",
        "0x80090302",
        "80090302",
        "0xc0000418",
        "c0000418",
        "0xc00000bb",
        "c00000bb",
    )
    # NTLM SSP reached the credential stage and rejected the bogus credential on
    # its merits -> NTLM enabled (the DC processed an NTLM authentication).
    _NTLM_ENABLED_CRED_CHECK_MARKERS = (
        "logon_failure",  # NTStatus.LOGON_FAILURE (0xC000006D)
        "0xc000006d",
        "c000006d",
        "wrong_password",
        "account_restriction",  # NTStatus.ACCOUNT_RESTRICTION (0xC000006E)
        "account_disabled",
        "account_locked_out",
        "password_expired",
        "password_must_change",
    )

    name = str(getattr(outcome, "ntstatus_name", "") or "").lower()
    text = str(getattr(outcome, "error_text", "") or "")
    hay = f"{name} {text}"
    # SSP-collapse (DISABLED) is checked first: it is the more specific refusal
    # and never co-occurs with a credential-check reject on the same status.
    if any(m in hay for m in _NTLM_DISABLED_SSP_MARKERS):
        return (
            TriState.DISABLED,
            "NTLM_BLOCKED_VIA_SMB",
            "DC refused the NTLM SMB session-setup (NTLM appears disabled by policy)",
        )
    if any(m in hay for m in _NTLM_ENABLED_CRED_CHECK_MARKERS):
        return (
            TriState.ENABLED,
            "NTLM_REACHED_CRED_CHECK_VIA_SMB",
            "DC processed the NTLM SMB session-setup and rejected the bogus "
            "credential (NTLM is enabled)",
        )
    return None


async def _probe_ntlm_authentication(
    *,
    domain: str,
    dc_ip: str,
    creds: ProbeCredentials,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe A3 — NTLM enforcement via an SMB SESSION_SETUP (bogus credential).

    WHY SMB, NOT LDAP (design 2026-07-13-posture-probe-dependency-order §4.1):
    NTLM-disabled and LDAP-signing-required are ORTHOGONAL GPO facts. The old A3
    measured NTLM via an unsigned plain-LDAP/389 bind — a single operation that
    exercises TWO layers in series: the LDAP signing layer (validated FIRST) and
    the NTLM SSP layer (validated SECOND). On a signing-required DC the bind is
    rejected with ``strongerAuthRequired`` at the signing layer BEFORE the NTLM
    SSP verdict is reachable, MASKING NTLM -> A3 returned PROBE_FAILED and NTLM
    was NEVER learned on ANY signing-required domain (a permanent structural
    blind spot). SMB SESSION_SETUP is a DIFFERENT protocol from LDAP signing, so
    the signing requirement can no longer mask the NTLM verdict. This mirrors the
    A4 redesign (measure SMB signing on an auth-independent NEGOTIATE): move the
    probe off the contaminated vehicle rather than special-case the classifier.

    Uses a BOGUS credential (like the U2/U3 transport-policy probes) so the probe
    is auth-independent. ``creds`` is accepted for orchestrator-signature parity
    and is intentionally NOT used for the wire authentication.

    Verdict mapping:
      * ``STATUS_NTLM_BLOCKED`` / ``STATUS_NOT_SUPPORTED`` / SSP refusal ->
        ``NTLM_AUTHENTICATION = DISABLED HIGH``, emit.
      * ``STATUS_LOGON_FAILURE`` / reached the credential check / session
        established -> ``NTLM_AUTHENTICATION = ENABLED HIGH``, emit.
      * timeout / 445 unreachable / unclassifiable -> ``UNKNOWN LOW``, NO emit
        (observe-don't-infer).
    """
    from adscan_internal.services.smb_transport import (
        SMBConfig,
        SMBConnectionError,
        smb_probe_ntlm_session_setup,
    )

    cat = ConstraintCategory.NTLM_AUTHENTICATION
    started = _now_ms()

    cfg = SMBConfig(
        target_ip=dc_ip,
        domain=domain,
        username=_make_bogus_probe_user(),
        password=_BOGUS_CRED_PASSWORD,
        use_kerberos=False,
        kdc_ip=dc_ip,
        # Probe wants the raw NTLM SSP verdict to surface, not a healed retry.
        disable_self_heal=True,
    )

    try:
        outcome = await asyncio.wait_for(
            smb_probe_ntlm_session_setup(cfg), timeout=timeout
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"NTLM SMB probe timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except SMBConnectionError as exc:
        # TCP connect / NEGOTIATE failed -> the NTLM SSP decision was never
        # reached. Observe-don't-infer: UNKNOWN/LOW, no emit.
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"NTLM SMB probe could not reach the SSP: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"NTLM SMB probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )

    verdict = _classify_ntlm_session_setup_outcome(outcome)
    if verdict is None:
        # Reached the DC but the response does not map to a clean NTLM SSP
        # decision (unclassifiable NTSTATUS). Cache nothing — the next probe
        # re-measures (CLAUDE.md: never cache an absence).
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="NTLM_INDETERMINATE",
            message=(
                "SMB session-setup did not yield a classifiable NTLM verdict "
                f"(ntstatus={getattr(outcome, 'ntstatus_name', None) or 'unknown'})"
            ),
            duration_ms=_now_ms() - started,
            succeeded=False,
        )

    state, code, message = verdict
    _emit(
        sink,
        domain=domain,
        category=cat,
        state=state,
        confidence=SignalConfidence.HIGH,
        signal_code=code,
        message=message,
        protocol="smb",
    )
    return ProbeResult(
        category=cat,
        state=state,
        confidence=SignalConfidence.HIGH,
        signal_code=code,
        message=message,
        duration_ms=_now_ms() - started,
        succeeded=True,
    )


async def _probe_smb_signing(
    *,
    domain: str,
    dc_ip: str,
    creds: ProbeCredentials,
    sink: PostureSink,
    timeout: float,
    posture: Optional[DomainPosture] = None,
) -> ProbeResult:
    """Probe A4 — SMB signing policy.

    Primary path (auth-independent): a pre-auth SMB NEGOTIATE read via
    :func:`smb_transport.smb_negotiate_signing`. The DC sends its
    ``SecurityMode`` REQUIRED flag in the NEGOTIATE response before any
    credential is presented, so this verdict does not depend on NTLM/Kerberos
    succeeding — it cannot hang on a Kerberos-only / NTLM-disabled DC (the
    failure mode of the old session-setup read, DEFECT A4).

    - NEGOTIATE set signing-required  -> ``SMB_SIGNING=REQUIRED HIGH``, emit.
    - NEGOTIATE did NOT set required   -> signing NOT required: the codebase
      represents "not required" with ``TriState.DISABLED`` (same member the
      LDAP-signing not-required path uses, see ``_probe_ldap_signing*``).
      ``DISABLED HIGH``, emit.
    - timeout / connect failure        -> ``UNKNOWN LOW``, NO emit
      (observe-don't-infer; our budget ran out, not a DC answer).

    ``posture`` is the in-flight posture overlay built by the orchestrator
    (A1/A2/A3 verdicts layered onto the persisted snapshot). It is threaded
    into the ``SMBConfig`` so the §4.2 session-setup fallback path can let
    ``build_smb_plan`` choose Kerberos when NTLM is known-disabled. The primary
    NEGOTIATE path does not authenticate, so it is unaffected by posture.
    """
    from adscan_internal.services.smb_transport import (
        SMBConfig,
        smb_negotiate_signing,
    )

    cat = ConstraintCategory.SMB_SIGNING
    started = _now_ms()

    cfg = SMBConfig(
        target_ip=dc_ip,
        domain=domain,
        username=creds.username,
        password=creds.password,
        nt_hash=creds.nt_hash,
        ccache_path=creds.ccache_path,
        kdc_ip=dc_ip,
        # Auth scheme is irrelevant for the primary NEGOTIATE read (no
        # session-setup). It only matters for the §4.2 fallback, where
        # build_smb_plan re-selects it from the in-flight posture.
        use_kerberos=False,
        posture_sink=sink,
        posture_snapshot=posture,
        # Probe wants the raw SMBSigningRequiredError to surface in the fallback
        # path rather than being silently retried with sign=True.
        disable_self_heal=True,
    )

    # ----- Primary: pre-auth NEGOTIATE read (auth-independent) -----
    try:
        neg = await asyncio.wait_for(smb_negotiate_signing(cfg), timeout=timeout)
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"SMB NEGOTIATE timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        # NEGOTIATE could not complete (connect refused, TLS/RST, or aiosmb
        # hides the standalone negotiate step in some runtime). Try the §4.2
        # posture-aware session-setup fallback before giving up.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] A4 NEGOTIATE read failed "
            f"({type(exc).__name__}); trying posture-aware session-setup fallback"
        )
        return await _probe_smb_signing_fallback(
            cfg=cfg,
            domain=domain,
            sink=sink,
            timeout=timeout,
            started=started,
            posture=posture,
        )

    # Observed NEGOTIATE response — the DC answered, so this is HIGH either way.
    if neg.signing_required:
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="SMB_SIGNING_NEGOTIATED_REQUIRED",
            message="DC NEGOTIATE response set SecurityMode signing-required",
            protocol="smb",
        )
        return ProbeResult(
            category=cat,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="SMB_SIGNING_NEGOTIATED_REQUIRED",
            message="DC NEGOTIATE response set SecurityMode signing-required",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    # NEGOTIATE observed and did NOT set signing-required -> signing NOT
    # required. ``TriState.DISABLED`` is how the codebase encodes "not required"
    # for signing constraints (mirrors the LDAP-signing not-required verdict).
    _emit(
        sink,
        domain=domain,
        category=cat,
        state=TriState.DISABLED,
        confidence=SignalConfidence.HIGH,
        signal_code="SMB_SIGNING_NEGOTIATED_NOT_REQUIRED",
        message="DC NEGOTIATE response did not set signing-required",
        protocol="smb",
    )
    return ProbeResult(
        category=cat,
        state=TriState.DISABLED,
        confidence=SignalConfidence.HIGH,
        signal_code="SMB_SIGNING_NEGOTIATED_NOT_REQUIRED",
        message="DC NEGOTIATE response did not set signing-required",
        duration_ms=_now_ms() - started,
        succeeded=True,
    )


async def _probe_smb_signing_fallback(
    *,
    cfg: "Any",
    domain: str,
    sink: PostureSink,
    timeout: float,
    started: float,
    posture: Optional[DomainPosture],
) -> ProbeResult:
    """A4 §4.2 fallback — posture-aware session-setup signing read.

    Used only when the primary pre-auth NEGOTIATE read could not complete as a
    standalone step. Auth is selected by ``build_smb_plan`` from the in-flight
    posture (NTLM-disabled -> Kerberos), NOT from credential shape — that was
    the DEFECT A4 root cause. ``disable_self_heal`` stays True so a real
    SMBSigningRequiredError surfaces as REQUIRED rather than being retried with
    sign=True.

    Timeout / connect failure -> ``UNKNOWN LOW``, NO emit (observe-don't-infer).
    """
    import dataclasses as _dc

    from adscan_internal.services.auth_plan import build_smb_plan
    from adscan_internal.services.smb_transport import smb_machine_for

    cat = ConstraintCategory.SMB_SIGNING

    plan = build_smb_plan(config=cfg, posture=posture)
    cfg_planned = _dc.replace(cfg, use_kerberos=plan.attempt.use_kerberos)

    async def _run() -> ProbeResult:
        async with smb_machine_for(cfg_planned) as _machine:
            connection = getattr(_machine, "connection", None)
            signing = False
            if connection is not None:
                try:
                    signing = bool(getattr(connection, "signing_required", False))
                except Exception as attr_exc:  # noqa: BLE001
                    telemetry.capture_exception(attr_exc)
            if signing:
                _emit(
                    sink,
                    domain=domain,
                    category=cat,
                    state=TriState.REQUIRED,
                    confidence=SignalConfidence.HIGH,
                    signal_code="SMB_SIGNING_NEGOTIATED_REQUIRED",
                    message="DC negotiated SMB signing as required (session-setup read)",
                    protocol="smb",
                )
                return ProbeResult(
                    category=cat,
                    state=TriState.REQUIRED,
                    confidence=SignalConfidence.HIGH,
                    signal_code="SMB_SIGNING_NEGOTIATED_REQUIRED",
                    message="DC negotiated SMB signing as required (session-setup read)",
                    duration_ms=_now_ms() - started,
                    succeeded=True,
                )
            # Session-setup succeeded with signing_required False -> not required.
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="SMB_SIGNING_NEGOTIATED_NOT_REQUIRED",
                message="SMB session established without required signing",
                protocol="smb",
            )
            return ProbeResult(
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="SMB_SIGNING_NEGOTIATED_NOT_REQUIRED",
                message="SMB session established without required signing",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )

    try:
        return await asyncio.wait_for(_run(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"SMB signing fallback timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        # A real SMBSigningRequiredError IS a definitive DC answer -> REQUIRED.
        from adscan_internal.services.smb_transport import SMBSigningRequiredError

        if isinstance(exc, SMBSigningRequiredError):
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="SMB_SIGNING_NEGOTIATED_REQUIRED",
                message="DC rejected unsigned SMB session — signing required",
                protocol="smb",
            )
            return ProbeResult(
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="SMB_SIGNING_NEGOTIATED_REQUIRED",
                message="DC rejected unsigned SMB session — signing required",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"SMB signing probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


# --------------------------------------------------------------------------- #
# Orchestration helpers
# --------------------------------------------------------------------------- #


async def _run_with_lifecycle(
    *,
    category: ConstraintCategory,
    runner: Callable[[], "asyncio.Future[ProbeResult] | Any"],
    on_progress: Optional[ProbeProgressCallback],
    posture: Optional[DomainPosture],
    force: bool,
) -> ProbeResult:
    """Apply skip logic, fire ``on_progress`` start/end, and run ``runner``."""
    skip, skipped_result = _should_skip(posture, category, force)
    if skip and skipped_result is not None:
        _safe_progress(on_progress, category, None)
        _safe_progress(on_progress, category, skipped_result)
        return skipped_result

    _safe_progress(on_progress, category, None)
    try:
        result = await runner()
    except Exception as exc:  # noqa: BLE001
        # Defensive net — every individual probe already wraps its failure
        # paths, but if something unexpected escapes, surface it as a failed
        # ProbeResult rather than tearing down the orchestrator.
        telemetry.capture_exception(exc)
        result = ProbeResult(
            category=category,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"Probe crashed: {type(exc).__name__}: {exc}",
            duration_ms=0.0,
            succeeded=False,
        )
    _safe_progress(on_progress, category, result)
    return result


def _make_skipped(
    category: ConstraintCategory,
    *,
    reason: str,
) -> ProbeResult:
    """Build a synthetic skipped ``ProbeResult`` for credential-gated probes."""
    return ProbeResult(
        category=category,
        state=TriState.UNKNOWN,
        confidence=SignalConfidence.LOW,
        signal_code="SKIPPED_NO_CREDENTIAL",
        message=reason,
        duration_ms=0.0,
        succeeded=True,
        skipped=True,
    )


def _layer_auth_verdicts(
    base: Optional[DomainPosture],
    domain: str,
    auth_results: list[ProbeResult],
) -> Optional[DomainPosture]:
    """Return a DomainPosture = ``base`` + every OBSERVED HIGH AUTH verdict.

    Mirrors the ``posture_for_u3`` pattern: the persisted snapshot handed to
    ``probe_auth`` is the *before-probes* state, so the SERVICE group (A4) must
    also see the AUTH group's (A1/A2/A3) just-computed verdicts WITHOUT a
    round-trip through the sink/store. This layers the finished AUTH
    ``ProbeResult``s onto ``base`` to build a fresh in-flight view.

    Only HIGH-confidence, non-UNKNOWN, succeeded, non-skipped results are
    layered — a timeout / UNKNOWN / skipped AUTH result contributes nothing
    (observe-don't-infer). When nothing qualifies, ``base`` is returned
    unchanged.

    Args:
        base: The caller's pre-probe posture snapshot (may be ``None``).
        domain: Target domain, used when ``base`` is ``None``.
        auth_results: The finished AUTH-group ``ProbeResult``s (A1..A3).

    Returns:
        A new ``DomainPosture`` overlaying the observed AUTH verdicts, or
        ``base`` when no AUTH verdict qualified.
    """
    from adscan_internal.services.domain_posture import (
        ConstraintState as _CState,
        DomainPosture as _DP,
    )

    overlay: dict[ConstraintCategory, _CState] = {}
    for r in auth_results:
        if r.skipped or not r.succeeded:
            continue
        if r.state == TriState.UNKNOWN or r.confidence != SignalConfidence.HIGH:
            continue
        overlay[r.category] = _CState(
            category=r.category,
            state=r.state,
            confidence=r.confidence,
        )
    if not overlay:
        return base
    if base is None:
        return _DP(domain=domain, constraints=dict(overlay))
    return _DP(
        domain=base.domain or domain,
        constraints={**base.constraints, **overlay},
        updated_at=base.updated_at,
        password_policy=base.password_policy,
    )


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


async def probe_unauth(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    on_progress: Optional[ProbeProgressCallback] = None,
    timeout_per_probe: float = 5.0,
    force: bool = False,
    posture: Optional[DomainPosture] = None,
) -> list[ProbeResult]:
    """Run the unauth probe set against the DC.

    Probes:
        U1 — ``LDAPS_AVAILABLE`` (anonymous LDAPS bind).
        U2 — ``LDAP_SIGNING`` (bogus-cred NTLM bind on port 389, see
             :func:`_probe_ldap_signing`).
        U3 — ``LDAP_CHANNEL_BINDING`` (bogus-cred NTLM bind on LDAPS,
             two steps to disambiguate Required / When-Supported / Never;
             see :func:`_probe_ldaps_channel_binding`).
        U4 — ``LDAP_STARTTLS_AVAILABLE`` (StartTLS upgrade on plain
             LDAP/389, see :func:`_probe_ldap_starttls_available`).

    Concurrency layout — **fully sequential**: U1 → U4 → U2 → U3. No
    ``asyncio.gather``, no overlapping background tasks. Each probe runs to
    completion before the next one starts.

    Why fully sequential and not "fast handshakes in parallel, binds
    serialized": per-step instrumentation against a real DC (2026-05-29)
    proved that the vendor TLS/NTLM operations do NOT yield the event loop
    cleanly. The low-level network primitives are fast in isolation —
    ``async_connect_with_ldap_fallback`` completes in ~122ms and
    ``conn.connect()`` in 9-52ms — yet each probe's function-level
    wall-clock was ~3.7-8.7s whenever probes ran concurrently. The gap is
    NOT in ADscan code: it is event-loop starvation during the concurrent
    wave. The vendor TLS handshake and NTLM/SPNEGO negotiation block the
    loop long enough that the "parallel" probes serialize de-facto AND
    inflate each other's wall-clock past their ``asyncio.wait_for`` budgets,
    tripping spurious ``PROBE_TIMEOUT`` / ``LDAPS_HANDSHAKE_TIMEOUT`` even
    when LDAPS/StartTLS is perfectly reachable. The decisive proof: the
    sequential post-wave reads (password policy) ran in 17-152ms — fast
    when alone. So running the probes concurrently is SLOWER (and
    timeout-prone) than running them one at a time, where each probe
    measures its true ~50-150ms of real latency.

    Ordering preserves the one data dependency: U1 (``LDAPS_AVAILABLE``)
    must complete before U3 (``LDAP_CHANNEL_BINDING``), because U3's
    self-skip consults U1's verdict via ``posture_for_u3`` (CBT lives only
    on TLS — no point binding LDAPS when U1 already proved 636 is closed).
    Sequential ordering satisfies this naturally; ``posture_for_u3`` is
    still built from U1's finished result below.

    Deferred alternative (backlog): making the vendor SSL/NTLM operations
    non-blocking — e.g. running the blocking handshake/negotiation under
    ``loop.run_in_executor`` so they genuinely yield the loop — would let
    these probes run in true parallel and reclaim the wall-clock. That is a
    vendor-layer change with wider blast radius; until then, sequential is
    both faster (no contention inflation) and timeout-safe.

    Evolution of this layout (kept for the historical record): the earliest
    "all probes parallel" design wasted ~10s on DCs without LDAPS (U3 burned
    two 5s timeouts on a question U1 had already answered). Intermediate
    designs — "U1+U2 parallel, U3 after", then "U1+U4 parallel + U2 then
    U3 sequential" — each removed one race but left another (a spurious
    ``LDAPS_HANDSHAKE_TIMEOUT`` from the U1↔bind contention, or a U2↔U3
    overlap). Full sequentialisation removes every remaining race in one
    move; the cost (one probe's latency at a time, all at their true
    ~50-150ms) is lower than the concurrent design's contention-inflated
    wall-clock.

    Why these live in UNAUTH even though they exercise an NTLM bind:
    the bogus-credential technique (see ``_BOGUS_CRED_PASSWORD`` comment
    block) does not require a real principal — it only exercises the
    DC's transport-policy validation, which runs **before** credential
    validation. So the same code path produces an authoritative answer
    in ``start_unauth`` and ``start_auth``, no second pass required.

    Args:
        domain: Target Kerberos realm / AD domain.
        dc_ip: DC IP to probe.
        sink: Posture sink that receives every emitted signal.
        on_progress: Optional callback fired twice per physical probe
            (``(cat, None)`` start, ``(cat, result)`` finish).
        timeout_per_probe: Per-probe wall-clock cap, seconds.
        force: When ``True``, run every probe even if the posture already
            records a HIGH-confidence non-stale value for its category.
        posture: Optional pre-loaded ``DomainPosture`` used for skip logic.

    Returns:
        One ``ProbeResult`` per physical probe, in the order
        ``[U1, U2, U3, U4]``.
    """

    async def _u1() -> ProbeResult:
        return await _probe_ldaps_available(
            domain=domain, dc_ip=dc_ip, sink=sink, timeout=timeout_per_probe
        )

    async def _u2() -> ProbeResult:
        return await _probe_ldap_signing(
            domain=domain, dc_ip=dc_ip, sink=sink, timeout=timeout_per_probe
        )

    async def _u4() -> ProbeResult:
        return await _probe_ldap_starttls_available(
            domain=domain, dc_ip=dc_ip, sink=sink, timeout=timeout_per_probe
        )

    # ----------------- Fully sequential: U1 -> U4 -> U2 -> U3 ----------------- #
    # NO asyncio.gather, NO overlapping background tasks. Per-step
    # instrumentation against a real DC (2026-05-29) proved that running these
    # probes concurrently causes event-loop starvation: the vendor TLS/NTLM
    # operations do not yield the loop cleanly, so the "parallel" probes
    # serialize de-facto AND inflate each other's wall-clock to ~3.7-8.7s
    # (tripping spurious PROBE_TIMEOUT / LDAPS_HANDSHAKE_TIMEOUT) even though
    # each probe's real latency is only ~50-150ms in isolation. Running them
    # one at a time lets each measure its true latency under its own
    # wait_for budget. See the docstring "Concurrency layout" section for the
    # evidence and the deferred run_in_executor alternative.

    # U1 first — its LDAPS verdict gates U3's self-skip below.
    u1 = await _run_with_lifecycle(
        category=ConstraintCategory.LDAPS_AVAILABLE,
        runner=_u1,
        on_progress=on_progress,
        posture=posture,
        force=force,
    )

    # U4 — StartTLS availability on port 389. Independent of U1's verdict.
    u4 = await _run_with_lifecycle(
        category=ConstraintCategory.LDAP_STARTTLS_AVAILABLE,
        runner=_u4,
        on_progress=on_progress,
        posture=posture,
        force=force,
    )

    # Build a posture snapshot that includes U1's verdict so U3's self-skip
    # logic short-circuits when LDAPS is unavailable. The caller's ``posture``
    # argument is the BEFORE-probes snapshot; we layer U1's finished result on
    # top of it for the purpose of U3.
    posture_for_u3 = posture
    if u1.state == TriState.DISABLED and u1.confidence == SignalConfidence.HIGH:
        from adscan_internal.services.domain_posture import (
            ConstraintState as _CState,
            DomainPosture as _DP,
        )

        ldaps_state = _CState(
            category=ConstraintCategory.LDAPS_AVAILABLE,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
        )
        if posture_for_u3 is None:
            posture_for_u3 = _DP(
                domain=domain,
                constraints={ConstraintCategory.LDAPS_AVAILABLE: ldaps_state},
            )
        else:
            posture_for_u3 = _DP(
                domain=posture_for_u3.domain or domain,
                constraints={
                    **posture_for_u3.constraints,
                    ConstraintCategory.LDAPS_AVAILABLE: ldaps_state,
                },
                updated_at=posture_for_u3.updated_at,
                password_policy=posture_for_u3.password_policy,
            )

    async def _u3() -> ProbeResult:
        return await _probe_ldaps_channel_binding(
            domain=domain,
            dc_ip=dc_ip,
            sink=sink,
            timeout=timeout_per_probe,
            posture=posture_for_u3,
        )

    # U2 — bogus-cred unsigned NTLM bind on port 389.
    u2 = await _run_with_lifecycle(
        category=ConstraintCategory.LDAP_SIGNING,
        runner=_u2,
        on_progress=on_progress,
        posture=posture,
        force=force,
    )

    # U3 — bogus-cred NTLM bind on LDAPS/636 (uses posture_for_u3 from U1).
    u3 = await _run_with_lifecycle(
        category=ConstraintCategory.LDAP_CHANNEL_BINDING,
        runner=_u3,
        on_progress=on_progress,
        posture=posture_for_u3,
        force=force,
    )

    return [u1, u2, u3, u4]


async def probe_auth(
    *,
    domain: str,
    dc_ip: str,
    creds: ProbeCredentials,
    sink: PostureSink,
    on_progress: Optional[ProbeProgressCallback] = None,
    timeout_per_probe: float = 5.0,
    force: bool = False,
    posture: Optional[DomainPosture] = None,
    dc_fqdn: Optional[str] = None,
) -> list[ProbeResult]:
    """Run the auth-mechanism probe set against the DC.

    The auth phase exists to characterise the **credential and Kerberos
    machinery**, nothing else. Properties of the DC that can be measured
    without credentials (LDAP signing requirement, LDAPS channel binding
    requirement) live in :func:`probe_unauth` so the same answer surfaces
    in ``start_unauth`` and ``start_auth``, and the AUTH phase stays
    purely about what authentication actually requires a credential.

    Probes (4 physical core + 2 conditional, 6 distinct posture signals):
        A1 — ``KERBEROS_RC4`` + ``KERBEROS_AES_ONLY`` (one explicit-etype AS-REQ).
        A2 — ``KERBEROS_ETYPE_PROBE``.
        A3 — ``NTLM_AUTHENTICATION``.
        A4 — ``SMB_SIGNING``.
        A6 — ``LDAP_CHANNEL_BINDING`` Kerberos-path probe (conditional; runs
             ONLY when A3 found NTLM disabled, the case where the unauth U3
             NTLM-based CBT probe could not measure). Authoritative.
        A5 — ``LDAP_SIGNING`` authenticated tiebreaker (conditional).

    Ordering — AUTH-first -> barrier -> SERVICE-after:

        AUTH GROUP (sequential): A1 -> A2 -> A3. Each consumes what the prior
        learned. Fully sequential for the same event-loop-starvation reason the
        unauth phase was sequentialised (vendor TLS/NTLM ops do not yield the
        loop cleanly; "parallel" probes serialize de-facto and inflate each
        other's wall-clock past their wait_for budgets).

        BARRIER: the AUTH group is fully awaited before the SERVICE group
        starts. The finished AUTH verdicts are layered onto the caller's
        posture via :func:`_layer_auth_verdicts` to build an in-flight overlay
        (only HIGH/observed/succeeded verdicts), mirroring ``posture_for_u3``.

        SERVICE GROUP: A4 (SMB signing) consumes the in-flight overlay so it
        sees A3's ``NTLM_AUTHENTICATION=DISABLED`` and A1's
        ``KERBEROS_AES_ONLY`` computed seconds earlier — its §4.2 fallback can
        then pick Kerberos on a Kerberos-only DC instead of forcing NTLM. A6
        (Kerberos-path CBT) consumes the same overlay and runs ONLY when A3
        found NTLM disabled — it is the authoritative CBT measurement in that
        case (U3's NTLM-based probe is blind on NTLM-disabled DCs). A5
        (LDAP-signing tiebreaker) runs after, unchanged.

    This replaces the old single-wave ``asyncio.gather(_kerberos_group(),
    _independent_group())`` in which A4 ran before/alongside the Kerberos and
    NTLM verdicts and could not consume them (DEFECT A4 root cause).

    Probes whose required credential type is missing are skipped silently
    (``ProbeResult.skipped=True``, no sink call).

    Args:
        domain: Target Kerberos realm / AD domain.
        dc_ip: DC IP to probe.
        creds: Credential bundle.
        sink: Posture sink that receives every emitted signal.
        on_progress: Optional callback fired twice per physical probe.
        timeout_per_probe: Per-probe wall-clock cap, seconds.
        force: When ``True``, ignore existing fresh HIGH posture and re-run.
        posture: Optional pre-loaded ``DomainPosture`` used for skip logic.

    Args (continued):
        dc_fqdn: Optional caller-resolved DC FQDN (``resolve_dc_fqdn``) for the
            A6 Kerberos-path CBT probe's ``ldap/`` SPN. When absent the probe
            falls back to ``dc_ip`` only if it is a hostname; an IP-only DC
            makes A6 skip (a Kerberos SPN cannot be an IP).

    Returns:
        ``ProbeResult`` entries in the order ``[A1, A2, A3, A4, (A6?), (A5?)]``
        — order preserved for callers/tests. A6 is appended only when it ran
        (NTLM disabled + Kerberos credential), A5 only when it ran.
    """
    has_password = creds.password is not None
    has_password_or_hash = has_password or (creds.nt_hash is not None)
    has_smb_credential = (
        has_password or (creds.nt_hash is not None) or (creds.ccache_path is not None)
    )

    # ----------------------------------------------------------------- #
    # AUTH GROUP — sequential A1 -> A2 -> A3 (each consumes what the
    # prior learned). Fully sequential per the event-loop-starvation
    # rationale documented in ``probe_unauth``.
    # ----------------------------------------------------------------- #

    # A1 — explicit-etype AS-REQ (needs plaintext password).
    if has_password:

        async def _a1() -> ProbeResult:
            return await _probe_kerberos_rc4(
                domain=domain,
                dc_ip=dc_ip,
                creds=creds,
                sink=sink,
                posture=posture,
                force=force,
                timeout=timeout_per_probe,
            )

        a1 = await _run_with_lifecycle(
            category=ConstraintCategory.KERBEROS_RC4,
            runner=_a1,
            on_progress=on_progress,
            posture=posture,
            force=force,
        )
    else:
        a1 = _make_skipped(
            ConstraintCategory.KERBEROS_RC4,
            reason="Skipped: explicit-etype AS-REQ requires plaintext password",
        )
        _safe_progress(on_progress, ConstraintCategory.KERBEROS_RC4, None)
        _safe_progress(on_progress, ConstraintCategory.KERBEROS_RC4, a1)

    # A2 — ETYPE-INFO2 probe (needs plaintext password). Sequential after A1.
    if has_password:

        async def _a2() -> ProbeResult:
            return await _probe_kerberos_etype(
                domain=domain,
                dc_ip=dc_ip,
                creds=creds,
                sink=sink,
                timeout=timeout_per_probe,
            )

        a2 = await _run_with_lifecycle(
            category=ConstraintCategory.KERBEROS_ETYPE_PROBE,
            runner=_a2,
            on_progress=on_progress,
            posture=posture,
            force=force,
        )
    else:
        a2 = _make_skipped(
            ConstraintCategory.KERBEROS_ETYPE_PROBE,
            reason="Skipped: ETYPE-INFO2 probe requires plaintext password",
        )
        _safe_progress(on_progress, ConstraintCategory.KERBEROS_ETYPE_PROBE, None)
        _safe_progress(on_progress, ConstraintCategory.KERBEROS_ETYPE_PROBE, a2)

    # A3 — plain NTLM bind via LDAP (needs password or NT hash). Sequential
    # after A2 so its verdict lands before the SERVICE group.
    if has_password_or_hash:

        async def _a3() -> ProbeResult:
            return await _probe_ntlm_authentication(
                domain=domain,
                dc_ip=dc_ip,
                creds=creds,
                sink=sink,
                timeout=timeout_per_probe,
            )

        a3 = await _run_with_lifecycle(
            category=ConstraintCategory.NTLM_AUTHENTICATION,
            runner=_a3,
            on_progress=on_progress,
            posture=posture,
            force=force,
        )
    else:
        a3 = _make_skipped(
            ConstraintCategory.NTLM_AUTHENTICATION,
            reason="Skipped: NTLM probe requires password or NT hash",
        )
        _safe_progress(on_progress, ConstraintCategory.NTLM_AUTHENTICATION, None)
        _safe_progress(on_progress, ConstraintCategory.NTLM_AUTHENTICATION, a3)

    # --------------------------- BARRIER --------------------------- #
    # The AUTH group is fully resolved above. Build the in-flight posture
    # overlay (caller's snapshot + observed HIGH AUTH verdicts) so the
    # SERVICE group sees A1/A2/A3's just-computed verdicts without a
    # round-trip through the sink/store. Mirrors ``posture_for_u3``.
    in_flight = _layer_auth_verdicts(posture, domain, [a1, a2, a3])

    # ----------------------------------------------------------------- #
    # SERVICE GROUP — A4 (SMB signing) consumes the in-flight overlay.
    # ----------------------------------------------------------------- #
    if has_smb_credential:

        async def _a4() -> ProbeResult:
            return await _probe_smb_signing(
                domain=domain,
                dc_ip=dc_ip,
                creds=creds,
                sink=sink,
                timeout=timeout_per_probe,
                posture=in_flight,
            )

        a4 = await _run_with_lifecycle(
            category=ConstraintCategory.SMB_SIGNING,
            runner=_a4,
            on_progress=on_progress,
            posture=in_flight,
            force=force,
        )
    else:
        a4 = _make_skipped(
            ConstraintCategory.SMB_SIGNING,
            reason="Skipped: SMB probe requires password, NT hash, or ccache",
        )
        _safe_progress(on_progress, ConstraintCategory.SMB_SIGNING, None)
        _safe_progress(on_progress, ConstraintCategory.SMB_SIGNING, a4)

    # A6 — Kerberos-path CBT probe (SERVICE group). Runs ONLY when NTLM is
    # known-disabled, because that is exactly the case where U3's NTLM-based
    # CBT probe could not measure channel-binding enforcement (it returned
    # UNKNOWN/no-emit per Part A). When NTLM is available, U3's verdict stands
    # and this Kerberos probe is redundant. Gating consumes the SAME in-flight
    # overlay A4 uses (caller posture + A3's just-computed
    # NTLM_AUTHENTICATION verdict), so it sees A3's DISABLED without a
    # round-trip through the sink/store.
    a6: Optional[ProbeResult] = None
    ntlm_state = in_flight.get(ConstraintCategory.NTLM_AUTHENTICATION) if in_flight else None
    ntlm_disabled_known = (
        ntlm_state is not None
        and ntlm_state.state == TriState.DISABLED
        and ntlm_state.confidence == SignalConfidence.HIGH
        and not ntlm_state.is_stale
    )
    # Has a Kerberos-usable credential? (password mints AS-REQ, aes_key or
    # ccache bind directly; a bare NT hash alone cannot drive a Kerberos bind.)
    has_kerberos_credential = (
        creds.password is not None
        or creds.aes_key is not None
        or creds.ccache_path is not None
    )
    if ntlm_disabled_known and has_kerberos_credential:
        async def _a6() -> ProbeResult:
            return await _probe_ldaps_channel_binding_kerberos(
                domain=domain,
                dc_ip=dc_ip,
                creds=creds,
                sink=sink,
                timeout=timeout_per_probe,
                dc_fqdn=dc_fqdn,
            )

        a6 = await _run_with_lifecycle(
            category=ConstraintCategory.LDAP_CHANNEL_BINDING,
            runner=_a6,
            on_progress=on_progress,
            posture=in_flight,
            # The Kerberos-path verdict is authoritative when NTLM is disabled
            # and must REPLACE U3's now-suppressed non-verdict. force=True so
            # _run_with_lifecycle does not short-circuit on a stale/UNKNOWN
            # LDAP_CHANNEL_BINDING category the unauth U3 may have written.
            force=True,
        )
    elif ntlm_disabled_known and not has_kerberos_credential:
        print_info_debug(
            "[posture_probe] A6 Kerberos-CBT skipped — NTLM disabled but no "
            "Kerberos-usable credential (password/aes_key/ccache) available"
        )

    # A5 — authenticated LDAP-signing tiebreaker. Runs ONLY when the unauth
    # U2 probe could not classify signing (UNKNOWN / absent / stale) AND a
    # usable password/hash credential is available. The unauth bogus-cred
    # probe stays the PRIMARY signing path; A5 is a layered tiebreaker that
    # resolves RestrictAnonymous DCs whose unauth signals were ambiguous.
    # An unsigned AUTHENTICATED bind that the DC accepts is the most
    # definitive "signing NOT required" signal possible. Sequential (after
    # the gather) so it can read the just-emitted U2 verdict via ``posture``.
    a5: Optional[ProbeResult] = None
    if has_password_or_hash:
        signing_state = posture.get(ConstraintCategory.LDAP_SIGNING) if posture else None
        signing_resolved = (
            signing_state is not None
            and signing_state.state != TriState.UNKNOWN
            and signing_state.confidence == SignalConfidence.HIGH
            and not signing_state.is_stale
        )
        # A5 over KERBEROS is the AUTHORITATIVE LDAP-signing measurement for a
        # Kerberos-first engagement: LDAP sign/seal enforcement is mechanism-
        # specific on some DCs (Samba `require strong auth=yes` requires it for
        # the GSS-SPNEGO bind but lets an NTLM bind reach the credential check),
        # so the unauth U2 NTLM verdict cannot speak for the Kerberos path. When
        # A5 can bind over Kerberos (Kerberos credential + resolvable ldap/ SPN
        # FQDN), run it even if U2 already resolved signing — the Kerberos-path
        # verdict is the one operations depend on, and it overrides U2's via the
        # most-recent-HIGH-wins merge. When A5 can only bind NTLM it stays a
        # tiebreaker (runs only when U2 left signing UNKNOWN), unchanged.
        has_kerberos_credential = (
            creds.password is not None
            or creds.aes_key is not None
            or creds.ccache_path is not None
        )
        a5_can_measure_kerberos = (
            has_kerberos_credential
            and _resolve_ldap_signing_spn_host(dc_fqdn, dc_ip) is not None
        )
        if force or not signing_resolved or a5_can_measure_kerberos:
            async def _a5() -> ProbeResult:
                return await _probe_ldap_signing_authenticated(
                    domain=domain,
                    dc_ip=dc_ip,
                    creds=creds,
                    sink=sink,
                    timeout=timeout_per_probe,
                    # Pass the in-flight overlay (caller posture + A3's
                    # just-computed NTLM verdict) so A5 picks Kerberos instead
                    # of the NTLM/SIMPLE bind on an NTLM-disabled DC -- the same
                    # source A6 reads. dc_fqdn supplies the ldap/ SPN for the
                    # Kerberos path (an IP-only DC makes the Kerberos branch skip).
                    posture=in_flight,
                    dc_fqdn=dc_fqdn,
                )

            a5 = await _run_with_lifecycle(
                category=ConstraintCategory.LDAP_SIGNING,
                runner=_a5,
                on_progress=on_progress,
                posture=posture,
                # A5 has its OWN freshness gate above (it only runs when U2
                # left signing UNKNOWN); pass force=True so _run_with_lifecycle
                # does not short-circuit on the LDAP_SIGNING category that the
                # unauth phase may have just written as UNKNOWN/LOW.
                force=True,
            )
        else:
            print_info_debug(
                "[posture_probe] A5 signing tiebreaker skipped — U2 already "
                "resolved LDAP signing at HIGH confidence"
            )

    results = [a1, a2, a3, a4]
    if a6 is not None:
        results.append(a6)
    if a5 is not None:
        results.append(a5)
    return results


# --------------------------------------------------------------------------- #
# Password policy probe
# --------------------------------------------------------------------------- #


def _filetime_to_days(ft: object) -> "Optional[int]":
    """Thin wrapper over the canonical AD-duration -> days converter.

    Kept as a private name for the existing call-sites in this module and the
    ``__all__`` export. The single source of truth lives in
    ``password_policy_compliance.ad_duration_to_days`` so the live policy API
    and the posture probe share one conversion.
    """
    from adscan_internal.services.password_policy_compliance import (  # noqa: PLC0415
        ad_duration_to_days,
    )

    return ad_duration_to_days(ft)


def _filetime_to_minutes(ft: object) -> "Optional[int]":
    """Thin wrapper over the canonical AD-duration -> minutes converter.

    Single source of truth: ``password_policy_compliance.ad_duration_to_minutes``.
    """
    from adscan_internal.services.password_policy_compliance import (  # noqa: PLC0415
        ad_duration_to_minutes,
    )

    return ad_duration_to_minutes(ft)


async def probe_password_policy(
    *,
    domain: str,
    dc_ip: str,
    dc_fqdn: "Optional[str]" = None,
    username: "Optional[str]" = None,
    password: "Optional[str]" = None,
    nt_hash: "Optional[str]" = None,
    ccache_path: "Optional[str]" = None,
    use_kerberos: bool = False,
    timeout: float = 10.0,
) -> "Optional[Any]":
    """Read the default domain password policy from AD via LDAP.

    Queries the domain object (naming-context root) for:
      - ``minPwdLength``  (integer)
      - ``pwdProperties`` (bitmask; bit 0 = complexity required)
      - ``maxPwdAge``     (FILETIME negative integer; 0 = never expires)

    Uses ``async_connect_with_ldap_fallback`` per CLAUDE.md: LDAPS -> LDAP
    fallback is mandatory; never use ``LDAPConnectionFactory`` directly.

    Args:
        domain: Target Kerberos realm / AD domain (e.g. ``north.sevenkingdoms.local``).
        dc_ip: DC IP for the target domain.
        username: LDAP bind username. ``None`` for anonymous bind.
        password: Plaintext password. ``None`` for anonymous / hash bind.
        nt_hash: NT hash (hex string). Used when no plaintext password is
            available and Kerberos is not requested.
        ccache_path: Explicit ccache path for Kerberos ccache bind.
        use_kerberos: When ``True``, builds a Kerberos URL; Kerberos auth is
            skipped silently when no ccache / password is available.
        timeout: Per-attempt wall-clock cap, seconds.

    Returns:
        A :class:`~adscan_internal.services.domain_posture.PasswordPolicySnapshot`
        on success, or ``None`` when the query fails or the domain object is
        absent. The caller always falls back to conservative defaults — this
        probe never aborts a scan.
    """
    from datetime import datetime, timezone

    from adscan_core import telemetry
    from adscan_core.rich_output import print_info_debug
    from adscan_internal.services.domain_posture import PasswordPolicySnapshot
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
    )

    # Kerberos LDAP binds bind the service ticket to the DC FQDN, not the IP
    # (CLAUDE.md "Kerberos SPNs — always FQDN"). Mirror the sibling signing/CBT
    # probes: thread the caller-resolved FQDN as the SPN host. Without it the
    # config falls back to the DC IP and the SPN build raises
    # KerberosSpnUnresolvedError — the exact failure that made the password
    # policy read silently degrade to the strong-safe default.
    spn_host = str(dc_fqdn or "").strip().rstrip(".")
    if use_kerberos and not spn_host:
        # Kerberos requested but no FQDN recoverable (IP-only domain_data) — a
        # Kerberos LDAP bind cannot build a valid service SPN, so skip the live
        # read cleanly (the caller falls back to the conservative default)
        # rather than raising. Cache observations, never absences.
        print_info_debug(
            "[password-policy-probe] Kerberos requested but no DC FQDN available; "
            "skipping live read (caller falls back to default)."
        )
        return None

    cfg = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=use_kerberos,
        username=username,
        password=password,
        ccache_path=ccache_path,
        kerberos_target_hostname=spn_host or None,
    )
    if password is None and nt_hash is not None and not use_kerberos:
        # Pass NT hash via the password slot (badldap auto-detects via
        # _is_nt_hash in _build_ldap_connection_url).
        cfg.password = nt_hash

    try:
        conn, _ = await asyncio.wait_for(
            async_connect_with_ldap_fallback(cfg), timeout=timeout
        )

        base_dn = cfg.domain_dn  # e.g. "DC=north,DC=sevenkingdoms,DC=local"
        results: list[dict] = []
        async for item, err in conn.pagedsearch(
            "(objectClass=domainDNS)",
            [
                "minPwdLength",
                "pwdProperties",
                "maxPwdAge",
                "minPwdAge",
                "pwdHistoryLength",
                "lockoutThreshold",
                "lockoutObservationWindow",
                "lockoutDuration",
            ],
            tree=base_dn,
            search_scope=0,  # BASE
            raw=True,
        ):
            if err is not None:
                raise err
            results.append(item)

        # Best-effort disconnect.
        try:
            disc = getattr(conn, "disconnect", None)
            if disc is not None:
                res = disc()
                if asyncio.iscoroutine(res):
                    await res
        except Exception as disc_exc:  # noqa: BLE001
            telemetry.capture_exception(disc_exc)

        if not results:
            print_info_debug(
                f"[posture] Password policy probe: no domainDNS entry returned "
                f"for base_dn={base_dn}"
            )
            return None

        attrs = results[0].get("attributes") or {}

        def _first_int(key: str, default: int) -> int:
            raw = attrs.get(key)
            if isinstance(raw, (list, tuple)):
                raw = raw[0] if raw else None
            try:
                return int(raw) if raw is not None else default
            except (ValueError, TypeError):
                return default

        min_pwd_len = _first_int("minPwdLength", 7)
        pwd_props = _first_int("pwdProperties", 0)
        require_complexity = bool(pwd_props & 0x01)  # DOMAIN_PASSWORD_COMPLEX

        raw_max_age = attrs.get("maxPwdAge")
        if isinstance(raw_max_age, (list, tuple)):
            raw_max_age = raw_max_age[0] if raw_max_age else None
        max_age_days = _filetime_to_days(raw_max_age)

        raw_min_age = attrs.get("minPwdAge")
        if isinstance(raw_min_age, (list, tuple)):
            raw_min_age = raw_min_age[0] if raw_min_age else None
        min_age_days = _filetime_to_days(raw_min_age)

        # Password history length — plain integer attribute; keep nullable so a
        # missing value is distinguishable from an explicit zero.
        raw_history = attrs.get("pwdHistoryLength")
        if isinstance(raw_history, (list, tuple)):
            raw_history = raw_history[0] if raw_history else None
        try:
            password_history_length = (
                int(raw_history) if raw_history is not None else None
            )
        except (ValueError, TypeError):
            password_history_length = None

        # Lockout attributes — same domain object, same round-trip. Critical for
        # spraying decisions (stale lockoutThreshold can lock real accounts).
        lockout_threshold = _first_int("lockoutThreshold", 0)

        raw_lockout_window = attrs.get("lockoutObservationWindow")
        if isinstance(raw_lockout_window, (list, tuple)):
            raw_lockout_window = raw_lockout_window[0] if raw_lockout_window else None
        lockout_window_minutes = _filetime_to_minutes(raw_lockout_window)

        raw_lockout_duration = attrs.get("lockoutDuration")
        if isinstance(raw_lockout_duration, (list, tuple)):
            raw_lockout_duration = raw_lockout_duration[0] if raw_lockout_duration else None
        lockout_duration_minutes = _filetime_to_minutes(raw_lockout_duration)

        snapshot = PasswordPolicySnapshot(
            min_length=min_pwd_len,
            require_complexity=require_complexity,
            max_age_days=max_age_days,
            source="ad_default_domain_policy",
            detected_at=datetime.now(timezone.utc),
            lockout_threshold=lockout_threshold,
            lockout_window_minutes=lockout_window_minutes,
            lockout_duration_minutes=lockout_duration_minutes,
            password_history_length=password_history_length,
            minimum_password_age_days=min_age_days,
        )
        print_info_debug(
            f"[posture] Password policy detected: domain={domain} "
            f"min_length={min_pwd_len} require_complexity={require_complexity} "
            f"max_age_days={max_age_days} min_age_days={min_age_days} "
            f"history_length={password_history_length} "
            f"lockout_threshold={lockout_threshold} "
            f"lockout_window_minutes={lockout_window_minutes}"
        )
        return snapshot

    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture] Password policy probe timed out after {timeout}s "
            f"for domain={domain}"
        )
        return None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture] Password policy probe failed: "
            f"{type(exc).__name__}: {exc}"
        )
        return None


# Re-exported for typing convenience at call-sites.
__all__ = [
    "ProbeCredentials",
    "ProbePhase",
    "ProbeProgressCallback",
    "ProbeResult",
    "probe_auth",
    "probe_password_policy",
    "probe_unauth",
    "get_password_policy",
    "resolve_resultant_password_policy",
    "clear_resultant_policy_cache",
    "_filetime_to_days",
    "_filetime_to_minutes",
]


async def get_password_policy(
    *,
    domain: str,
    dc_ip: str,
    dc_fqdn: "Optional[str]" = None,
    domains_data: "Optional[dict[str, Any]]" = None,
    username: "Optional[str]" = None,
    password: "Optional[str]" = None,
    nt_hash: "Optional[str]" = None,
    ccache_path: "Optional[str]" = None,
    use_kerberos: bool = False,
    timeout: float = 10.0,
    force_fresh: bool = False,
) -> "Optional[Any]":
    """Return the current :class:`PasswordPolicySnapshot` for ``domain``.

    Two modes:

    * ``force_fresh=False`` (default — used by scoring): consults the cached
      snapshot in ``domains_data`` first. When the cache is fresh (within
      :data:`domain_posture._PASSWORD_POLICY_TTL`, currently 60 s) it is
      returned without an LDAP round-trip. When stale or absent, a fresh
      probe is issued and the cache is updated.
    * ``force_fresh=True`` (REQUIRED for spraying): always issues a fresh
      LDAP query, ignoring any cached value. ``lockoutThreshold`` and
      ``lockoutObservationWindow`` can change reactively mid-engagement —
      a stale lockout value can lock real customer accounts. Spray code
      paths must use this mode before each batch.

    Args:
        domain: Target AD domain (e.g. ``ais.local``).
        dc_ip: Domain controller IP address for the LDAP connection.
        domains_data: Workspace ``domains_data`` mapping. When provided the
            cache is read and updated through it; when ``None``, behaves as
            if cache were always empty.
        username, password, nt_hash, ccache_path, use_kerberos: credentials
            forwarded to :func:`probe_password_policy`.
        timeout: LDAP probe timeout in seconds.
        force_fresh: When ``True`` bypasses the cache entirely. See above.

    Returns:
        A :class:`PasswordPolicySnapshot` or ``None`` when the probe fails.
    """
    # Deferred imports keep this module light; ``domain_posture`` carries the
    # snapshot dataclass and the persistence helpers.
    from adscan_internal.services.domain_posture import (  # noqa: PLC0415
        get_posture,
        persist_password_policy,
    )

    if not force_fresh and domains_data is not None:
        cached = getattr(
            get_posture(domains_data, domain=domain),
            "password_policy",
            None,
        )
        if cached is not None and not cached.is_stale():
            return cached

    # Resolve the DC FQDN for the Kerberos service SPN when the caller did not
    # thread one (CLAUDE.md "Kerberos SPNs — always FQDN"). Without it a
    # Kerberos LDAP bind built from the DC IP raises KerberosSpnUnresolvedError.
    if not dc_fqdn and domains_data is not None:
        from adscan_internal.models.domain import resolve_dc_fqdn  # noqa: PLC0415

        dc_fqdn = resolve_dc_fqdn(
            domains_data.get(domain) or {}, target_domain=domain
        )

    snapshot = await probe_password_policy(
        domain=domain,
        dc_ip=dc_ip,
        dc_fqdn=dc_fqdn,
        username=username,
        password=password,
        nt_hash=nt_hash,
        ccache_path=ccache_path,
        use_kerberos=use_kerberos,
        timeout=timeout,
    )
    if snapshot is not None and domains_data is not None:
        persist_password_policy(domains_data, domain=domain, snapshot=snapshot)
    return snapshot


# Touch ``IntelligenceFinding`` so static analyzers don't flag the import as
# unused — sinks may return it but the engine only forwards the call.
_ = IntelligenceFinding


# --------------------------------------------------------------------------- #
# Resultant password policy (live-first PSO-aware resolution)
# --------------------------------------------------------------------------- #

# In-session, in-memory cache for the per-user PSO leg keyed by
# ``(domain.lower(), target_user_or_None)``. PSO assignment does not change
# mid-engagement so a session-lifetime cache is safe; ``force_refresh=True``
# busts it. The domain-default leg reuses the ``domains_data``-backed cache via
# ``get_password_policy`` (see below) so this dict only memoises PSO results.
_RESULTANT_POLICY_CACHE: "dict[tuple[str, Optional[str]], Any]" = {}

# AD complexity rule: a password must contain characters from at least 3 of the
# 5 classes (lower, upper, digit, symbol, unicode) when complexity is enabled.
_AD_COMPLEXITY_REQUIRED_CLASSES = 3

# Strong safe default — aligns with the collector's weak-policy bar
# (_WEAK_PWD_POLICY_MIN_LENGTH = 14 in audit_analyzer.py).
_SAFE_DEFAULT_MIN_LENGTH = 14


def _resultant_cache_key(domain: str, target_user: "Optional[str]") -> "tuple[str, Optional[str]]":
    return (str(domain or "").lower(), str(target_user).lower() if target_user else None)


def _snapshot_to_resultant(snapshot: Any, *, source: str) -> Any:
    """Promote a ``PasswordPolicySnapshot`` to a ``ResultantPasswordPolicy``."""
    from datetime import datetime, timezone

    from adscan_internal.services.domain_posture import ResultantPasswordPolicy

    return ResultantPasswordPolicy(
        min_length=snapshot.min_length,
        require_complexity=snapshot.require_complexity,
        required_classes=(
            _AD_COMPLEXITY_REQUIRED_CLASSES if snapshot.require_complexity else 0
        ),
        source=source,
        detected_at=getattr(snapshot, "detected_at", datetime.now(timezone.utc)),
        max_pwd_age_days=getattr(snapshot, "max_age_days", None),
        lockout_threshold=getattr(snapshot, "lockout_threshold", 0),
        lockout_window_minutes=getattr(snapshot, "lockout_window_minutes", None),
        lockout_duration_minutes=getattr(snapshot, "lockout_duration_minutes", None),
    )


def _safe_default_policy() -> Any:
    """Return the strong safe default policy (source=``default_assumed``)."""
    from datetime import datetime, timezone

    from adscan_internal.services.domain_posture import ResultantPasswordPolicy

    return ResultantPasswordPolicy(
        min_length=_SAFE_DEFAULT_MIN_LENGTH,
        require_complexity=True,
        required_classes=_AD_COMPLEXITY_REQUIRED_CLASSES,
        source="default_assumed",
        detected_at=datetime.now(timezone.utc),
    )


def _coerce_bool_attr(raw: object) -> "Optional[bool]":
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    s = str(raw).strip().upper()
    if s in {"TRUE", "1"}:
        return True
    if s in {"FALSE", "0"}:
        return False
    return None


def _first_attr(attrs: dict, key: str) -> object:
    raw = attrs.get(key)
    if isinstance(raw, (list, tuple)):
        return raw[0] if raw else None
    return raw


def _values_attr(attrs: dict, key: str) -> "list[Any]":
    raw = attrs.get(key)
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return list(raw)
    return [raw]


async def _resolve_pso_policy(
    conn: Any,
    *,
    domain_dn: str,
    target_user: str,
    domain_default: Any,
    timeout: float,
) -> "Optional[Any]":
    """Resolve a PSO-derived ``ResultantPasswordPolicy`` for ``target_user``.

    Two-step, mirrors the offline ``_select_pso_for_user`` algorithm:

    1. Resolve ``sAMAccountName``/UPN -> user DN, then BASE-read
       ``msDS-ResultantPSO`` (authoritative DC-computed attribute). If present,
       BASE-read that PSO for its attributes.
    2. Fallback: SUBTREE the Password Settings Container, resolve the user's
       group DNs, and pick the covering PSO with the lowest precedence via the
       shared :func:`select_winning_pso_dn` helper.

    Returns ``None`` (caller uses the domain default) when no PSO governs the
    user or the reads fail.
    """
    from adscan_core import telemetry
    from adscan_core.rich_output import print_info_debug
    from adscan_internal.services.password_policy_compliance import (
        ad_duration_to_days,
        ad_duration_to_minutes,
        select_winning_pso_dn,
    )

    # --- Step 0: resolve the user DN + group membership in one search. ---
    user_dn = ""
    resultant_pso_dn: "Optional[str]" = None
    group_dns: list[str] = []
    user_filter = (
        f"(sAMAccountName={target_user})"
        if "@" not in target_user
        else f"(userPrincipalName={target_user})"
    )
    try:
        async for item, err in conn.pagedsearch(
            user_filter,
            ["distinguishedName", "msDS-ResultantPSO", "memberOf"],
            tree=domain_dn,
            search_scope=2,  # SUBTREE
            raw=True,
        ):
            if err is not None:
                raise err
            attrs = item.get("attributes") or {}
            dn_val = _first_attr(attrs, "distinguishedName")
            if dn_val:
                user_dn = str(dn_val)
            rp = _first_attr(attrs, "msDS-ResultantPSO")
            if rp:
                resultant_pso_dn = str(rp)
            group_dns = [str(g) for g in _values_attr(attrs, "memberOf") if g]
            break  # first match wins
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture] PSO user lookup failed for target_user: "
            f"{type(exc).__name__}: {exc}"
        )
        return None

    if not user_dn:
        print_info_debug("[posture] PSO resolution: target user not found")
        return None

    pso_attr_names = [
        "distinguishedName",
        "msDS-PasswordSettingsPrecedence",
        "msDS-MinimumPasswordLength",
        "msDS-MaximumPasswordAge",
        "msDS-MinimumPasswordAge",
        "msDS-LockoutThreshold",
        "msDS-LockoutObservationWindow",
        "msDS-LockoutDuration",
        "msDS-PasswordHistoryLength",
        "msDS-PasswordComplexityEnabled",
        "msDS-PasswordReversibleEncryptionEnabled",
        "msDS-PSOAppliesTo",
    ]

    def _build_policy(attrs: dict, pso_dn: str) -> Any:
        from datetime import datetime, timezone

        from adscan_internal.services.domain_posture import ResultantPasswordPolicy

        complexity = _coerce_bool_attr(_first_attr(attrs, "msDS-PasswordComplexityEnabled"))
        require_complexity = bool(complexity) if complexity is not None else True
        min_len_raw = _first_attr(attrs, "msDS-MinimumPasswordLength")
        try:
            min_len = int(min_len_raw) if min_len_raw is not None else domain_default.min_length
        except (ValueError, TypeError):
            min_len = domain_default.min_length
        hist_raw = _first_attr(attrs, "msDS-PasswordHistoryLength")
        try:
            history_length = int(hist_raw) if hist_raw is not None else None
        except (ValueError, TypeError):
            history_length = None
        lockout_raw = _first_attr(attrs, "msDS-LockoutThreshold")
        try:
            lockout_threshold = int(lockout_raw) if lockout_raw is not None else 0
        except (ValueError, TypeError):
            lockout_threshold = 0
        return ResultantPasswordPolicy(
            min_length=min_len,
            require_complexity=require_complexity,
            required_classes=(
                _AD_COMPLEXITY_REQUIRED_CLASSES if require_complexity else 0
            ),
            source="live_pso",
            detected_at=datetime.now(timezone.utc),
            history_length=history_length,
            min_pwd_age_days=ad_duration_to_days(_first_attr(attrs, "msDS-MinimumPasswordAge")),
            max_pwd_age_days=ad_duration_to_days(_first_attr(attrs, "msDS-MaximumPasswordAge")),
            lockout_threshold=lockout_threshold,
            lockout_window_minutes=ad_duration_to_minutes(
                _first_attr(attrs, "msDS-LockoutObservationWindow")
            ),
            lockout_duration_minutes=ad_duration_to_minutes(
                _first_attr(attrs, "msDS-LockoutDuration")
            ),
            pso_dn=pso_dn,
        )

    # --- Step 1: authoritative msDS-ResultantPSO BASE read. ---
    if resultant_pso_dn:
        try:
            async for item, err in conn.pagedsearch(
                "(objectClass=msDS-PasswordSettings)",
                pso_attr_names,
                tree=resultant_pso_dn,
                search_scope=0,  # BASE
                raw=True,
            ):
                if err is not None:
                    raise err
                attrs = item.get("attributes") or {}
                print_info_debug(
                    "[posture] PSO resolved via msDS-ResultantPSO (authoritative)"
                )
                return _build_policy(attrs, resultant_pso_dn)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[posture] msDS-ResultantPSO BASE read failed, falling back to "
                f"precedence computation: {type(exc).__name__}: {exc}"
            )

    # --- Step 2: precedence fallback over the PSO container. ---
    pso_container = f"CN=Password Settings Container,CN=System,{domain_dn}"
    candidate_psos: list[tuple[str, tuple[str, ...], "Optional[int]"]] = []
    pso_attrs_by_dn: dict[str, dict] = {}
    try:
        async for item, err in conn.pagedsearch(
            "(objectClass=msDS-PasswordSettings)",
            pso_attr_names,
            tree=pso_container,
            search_scope=2,  # SUBTREE
            raw=True,
        ):
            if err is not None:
                raise err
            attrs = item.get("attributes") or {}
            dn_val = _first_attr(attrs, "distinguishedName")
            if not dn_val:
                continue
            dn = str(dn_val)
            applies_to = tuple(str(v) for v in _values_attr(attrs, "msDS-PSOAppliesTo") if v)
            prec_raw = _first_attr(attrs, "msDS-PasswordSettingsPrecedence")
            try:
                precedence = int(prec_raw) if prec_raw is not None else None
            except (ValueError, TypeError):
                precedence = None
            candidate_psos.append((dn, applies_to, precedence))
            pso_attrs_by_dn[dn.upper()] = attrs
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture] PSO container read failed: {type(exc).__name__}: {exc}"
        )
        return None

    winning_dn = select_winning_pso_dn(
        resultant_pso_dn=resultant_pso_dn,
        user_dn=user_dn,
        principal_dns=tuple(group_dns),
        candidate_psos=candidate_psos,
    )
    if winning_dn is None:
        return None
    attrs = pso_attrs_by_dn.get(winning_dn.upper())
    if attrs is None:
        return None
    print_info_debug("[posture] PSO resolved via precedence fallback")
    return _build_policy(attrs, winning_dn)


async def resolve_resultant_password_policy(
    *,
    domain: str,
    dc_ip: str,
    target_user: "Optional[str]" = None,
    username: "Optional[str]" = None,
    password: "Optional[str]" = None,
    nt_hash: "Optional[str]" = None,
    ccache_path: "Optional[str]" = None,
    use_kerberos: bool = False,
    domains_data: "Optional[dict[str, Any]]" = None,
    force_refresh: bool = False,
    timeout: float = 10.0,
) -> Any:
    """Resolve the resultant password policy effective for a principal.

    Live-first resolution (never primarily trusts a stale collector artifact):

    1. **Live LDAP read** — domain default via :func:`probe_password_policy`
       (reused through :func:`get_password_policy`); when ``target_user`` is
       given, the per-user PSO via :func:`_resolve_pso_policy`
       (authoritative ``msDS-ResultantPSO`` BASE read, precedence fallback).
    2. **In-session cache** keyed by ``(domain, target_user_or_None)`` so a
       300-attempt spray reads the policy once. ``force_refresh=True`` busts it.
    3. **Collector / persisted** as last resort (best-effort; the JSON
       reverse-loader is deferred to a later phase — see note below).
    4. **Strong safe default** (``min_length=14``, complexity required,
       ``source="default_assumed"``) when everything else is unavailable.

    Connection handling reuses the mandatory ADscan LDAPS->LDAP fallback
    (``async_connect_with_ldap_fallback`` via ``ADscanLDAPConfig``); this
    function never imports ``LDAPConnectionFactory`` directly.

    Args:
        domain: Target Kerberos realm / AD domain.
        dc_ip: DC IP for the target domain.
        target_user: sAMAccountName or UPN to resolve a PSO for. ``None`` =
            domain default only.
        username, password, nt_hash, ccache_path, use_kerberos: bind creds.
        domains_data: Workspace mapping for the domain-default cache leg.
        force_refresh: Bypass both caches and re-read live.
        timeout: Per-LDAP-operation wall-clock cap, seconds.

    Returns:
        A :class:`~adscan_internal.services.domain_posture.ResultantPasswordPolicy`.
        Always returns a usable policy — never ``None`` (worst case the strong
        safe default).
    """
    from adscan_core import telemetry
    from adscan_core.rich_output import print_info_debug
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
    )

    cache_key = _resultant_cache_key(domain, target_user)
    if not force_refresh and cache_key in _RESULTANT_POLICY_CACHE:
        return _RESULTANT_POLICY_CACHE[cache_key]

    # --- Leg 1: live domain default (reuses the domains_data-backed cache). ---
    domain_default: "Optional[Any]" = None
    snapshot = await get_password_policy(
        domain=domain,
        dc_ip=dc_ip,
        domains_data=domains_data,
        username=username,
        password=password,
        nt_hash=nt_hash,
        ccache_path=ccache_path,
        use_kerberos=use_kerberos,
        timeout=timeout,
        force_fresh=force_refresh,
    )
    if snapshot is not None:
        domain_default = _snapshot_to_resultant(snapshot, source="live_default_domain")

    # --- Leg 1b: live PSO read when a target user is supplied. ---
    # Resolve the DC FQDN for the Kerberos service SPN (CLAUDE.md "Kerberos SPNs
    # — always FQDN"); the PSO read builds its own LDAP config, so it needs the
    # same FQDN threading Leg 1 gets via get_password_policy.
    _pso_dc_fqdn = ""
    if domains_data is not None:
        from adscan_internal.models.domain import resolve_dc_fqdn  # noqa: PLC0415

        _pso_dc_fqdn = str(
            resolve_dc_fqdn(domains_data.get(domain) or {}, target_domain=domain)
            or ""
        ).strip().rstrip(".")
    if (
        target_user
        and domain_default is not None
        and not (use_kerberos and not _pso_dc_fqdn)
    ):
        cfg = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=True,
            use_kerberos=use_kerberos,
            username=username,
            password=password,
            ccache_path=ccache_path,
            kerberos_target_hostname=_pso_dc_fqdn or None,
        )
        if password is None and nt_hash is not None and not use_kerberos:
            cfg.password = nt_hash
        try:
            conn, _used_ldaps = await asyncio.wait_for(
                async_connect_with_ldap_fallback(cfg), timeout=timeout
            )
            try:
                pso_policy = await _resolve_pso_policy(
                    conn,
                    domain_dn=cfg.domain_dn,
                    target_user=target_user,
                    domain_default=domain_default,
                    timeout=timeout,
                )
            finally:
                try:
                    disc = getattr(conn, "disconnect", None)
                    if disc is not None:
                        res = disc()
                        if asyncio.iscoroutine(res):
                            await res
                except Exception as disc_exc:  # noqa: BLE001
                    telemetry.capture_exception(disc_exc)
            if pso_policy is not None:
                _RESULTANT_POLICY_CACHE[cache_key] = pso_policy
                return pso_policy
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[posture] PSO resolution failed; using domain default: "
                f"{type(exc).__name__}: {exc}"
            )

    if domain_default is not None:
        _RESULTANT_POLICY_CACHE[cache_key] = domain_default
        return domain_default

    # --- Leg 3: collector / persisted last resort (best-effort). ---
    # NOTE: the JSON reverse-loader from the persisted ``domain_policy.json`` /
    # ``psos.json`` collector artifacts into model objects is deferred; until a
    # caller threads a parsed ``CollectionResult`` through, this leg degrades
    # straight to the strong safe default. Documented in the Phase-1 spec.

    # --- Leg 4: strong safe default. ---
    fallback = _safe_default_policy()
    _RESULTANT_POLICY_CACHE[cache_key] = fallback
    return fallback


def clear_resultant_policy_cache() -> None:
    """Clear the in-session PSO cache. Test/diagnostic helper."""
    _RESULTANT_POLICY_CACHE.clear()
