"""Async RDP login-sweep service backed by aardwolf (skelsec native stack).

Probes RDP hosts using CredSSP+NTLM (password or Pass-the-Hash).  When NTLM is
disabled on the target network and a plaintext password is available, the service
automatically retries with CredSSP+Kerberos — so the sweep works in hardened
environments where NTLM has been blocked by GPO.

Posture-aware (PR-RDP): when ``posture_snapshot`` is provided and records
``NTLM_AUTHENTICATION = DISABLED HIGH``, the planner forces Kerberos from the
first attempt — the doomed NTLM round-trip is skipped entirely. When the
snapshot is silent the conservative NTLM-then-Kerberos path runs unchanged
and its successful Kerberos retry emits ``NTLM_REJECTED_VIA_RDP_KERBEROS_FALLBACK_OK``
to feed future runs.

PtH requires Restricted Admin Mode to be enabled on the target.  There is no
Kerberos fallback for PtH because overpass-the-hash requires the Kerberos key,
not the NTLM hash — the caller must surface this as a known limitation.

Proxy support is provided transparently via asysocks.

Result semantics:
  TRUE   — CredSSP handshake succeeded; user has interactive RDP access.
  FALSE  — Connection rejected (wrong creds, RestrictedAdmin disabled, …).
  MAYBE  — NLA-permissive server (no cred challenge) — access unconfirmed.
           Treated as ambiguous by the caller.
  ERROR  — Unexpected exception during probe (aardwolf import missing, etc.).
"""

from __future__ import annotations

import asyncio
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    DomainPosture,
    PostureSignal,
    SignalConfidence,
    TriState,
)
from adscan_internal.services.posture_sink import PostureSink
from adscan_core.rich_output import print_exception

RDPLoginVerdict = Literal["TRUE", "FALSE", "MAYBE", "ERROR"]


@dataclass
class RDPLoginResult:
    host: str
    verdict: RDPLoginVerdict
    error: str | None = None

    @property
    def confirmed(self) -> bool:
        return self.verdict == "TRUE"

    @property
    def ambiguous(self) -> bool:
        return self.verdict == "MAYBE"


def _build_ntlm_url(
    domain: str, username: str, secret: str, host: str, *, is_hash: bool
) -> str:
    secret_type = "nt" if is_hash else "password"
    dom = urllib.parse.quote(domain, safe="")
    usr = urllib.parse.quote(username, safe="")
    sec = urllib.parse.quote(secret, safe="")
    h = urllib.parse.quote(host, safe="")
    return f"rdp+ntlm-{secret_type}://{dom}\\{usr}:{sec}@{h}"


def _build_kerberos_url(
    domain: str, username: str, password: str, host: str, dc_ip: str | None
) -> str:
    from adscan_internal.services._kerberos_spn import (
        normalize_kerberos_target_hostname,
    )
    from adscan_internal.services.credential_routing import (
        looks_like_ntlm_hash,
        normalize_ntlm_hash,
    )

    # Promote short hostnames to FQDN so aardwolf requests the SPN
    # ``termsrv/<host>.<realm>``. A short label yields a ticket the target
    # rejects with the same SEC_E_LOGON_DENIED pattern documented for LDAP/SMB.
    spn_host = normalize_kerberos_target_hostname(host, domain) or host
    dom = urllib.parse.quote(domain, safe="")
    usr = urllib.parse.quote(username, safe="")
    # Tolerate a NT hash supplied via the password slot. aardwolf has a
    # dedicated ``rdp+kerberos-rc4://`` scheme that consumes the NT hash as
    # the RC4-HMAC key directly, avoiding a wrong AES key derivation.
    if looks_like_ntlm_hash(password):
        scheme = "rdp+kerberos-rc4"
        secret = normalize_ntlm_hash(password)
    else:
        scheme = "rdp+kerberos-password"
        secret = password
    pw = urllib.parse.quote(secret, safe="")
    h = urllib.parse.quote(spn_host, safe="")
    url = f"{scheme}://{dom}\\{usr}:{pw}@{h}"
    if dc_ip:
        url += f"/?dc={urllib.parse.quote(dc_ip, safe='.')}"
    return url


# ---------------------------------------------------------------------------
# Posture helpers (PR-RDP)
# ---------------------------------------------------------------------------


def _walk_exception_chain(exc: BaseException) -> list[BaseException]:
    """Walk ``__cause__`` / ``__context__`` chain into a flat list."""
    seen: set[int] = set()
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _exception_chain_text(exc: BaseException) -> str:
    """Concatenate every message in the exception chain for substring matching."""
    parts: list[str] = []
    for candidate in _walk_exception_chain(exc):
        parts.append(type(candidate).__name__)
        message = str(candidate or "").strip()
        if message:
            parts.append(message)
    return " | ".join(parts)


def _emit_posture_signal(
    *,
    sink: Optional[PostureSink],
    domain: str,
    category: ConstraintCategory,
    state: TriState,
    confidence: SignalConfidence,
    signal_code: str,
    message: str,
) -> None:
    """Best-effort posture emit. Sink failures captured + swallowed."""
    if sink is None or not domain:
        return
    try:
        signal = PostureSignal(
            domain=domain,
            category=category,
            state=state,
            confidence=confidence,
            source="rdp_login",
            signal_code=signal_code,
            message=message,
            protocol="rdp",
            observed_at=datetime.now(timezone.utc),
        )
        sink(signal)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[rdp_login] posture sink failed: {exc}")


_RDP_NTLM_MARKERS = ("ntlm", "ntlmssp")
_RDP_REJECTION_MARKERS = (
    "logon_failure",
    "logon failure",
    "access_denied",
    "authentication failed",
    "credentials rejected",
)


def _is_kerberos_infra_error(exc: BaseException) -> bool:
    """Return True when a Kerberos RDP failure is infrastructure-related."""
    from adscan_internal.services.auth_error_classification import (
        is_aardwolf_kerberos_infra_error,
    )

    return is_aardwolf_kerberos_infra_error(exc)


def _emit_rdp_failure_posture(
    *,
    sink: Optional[PostureSink],
    domain: str,
    exc: BaseException,
    used_kerberos: bool,
) -> None:
    """Classify an RDP connection failure and emit any matching posture signals.

    Conservative: only emits when the failure text + auth context is
    unambiguous evidence of a domain-wide hardening control, not a
    per-credential rejection. RDP doesn't surface SEC_E_LOGON_DENIED — it
    surfaces NLA/HYBRID negotiation failures, so we require both an NTLM
    marker AND an authentication-rejection marker AND ``used_kerberos=False``
    before emitting.
    """
    if sink is None or not domain:
        return
    if used_kerberos:
        return

    chain_text = _exception_chain_text(exc).lower()
    has_ntlm = any(m in chain_text for m in _RDP_NTLM_MARKERS)
    has_rejection = any(m in chain_text for m in _RDP_REJECTION_MARKERS)
    if not (has_ntlm and has_rejection):
        return

    _emit_posture_signal(
        sink=sink,
        domain=domain,
        category=ConstraintCategory.NTLM_AUTHENTICATION,
        state=TriState.DISABLED,
        confidence=SignalConfidence.HIGH,
        signal_code="NTLM_REJECTED_VIA_RDP",
        message="DC rejected NTLM over RDP",
    )


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------


async def _attempt_connection(
    factory: object, host: str, proto: object, timeout_s: float
) -> bool:
    """Return True if the CredSSP handshake succeeds with the given protocol."""
    from aardwolf.commons.factory import RDPConnectionFactory  # noqa: F401 type hint

    ios = factory.get_settings()  # type: ignore[attr-defined]
    if proto is not None:
        ios.supported_protocols = proto
    async with asyncio.timeout(timeout_s):
        async with factory.create_connection_newtarget(host, ios) as conn:  # type: ignore[attr-defined]
            _, err = await conn.connect()
            return err is None


async def _probe_one(
    host: str,
    domain: str,
    username: str,
    secret: str,
    *,
    is_hash: bool,
    dc_ip: str | None,
    timeout_s: float,
    posture_snapshot: Optional[DomainPosture] = None,
    posture_sink: Optional[PostureSink] = None,
    domain_for_posture: Optional[str] = None,
) -> RDPLoginResult:
    """Probe a single host, with posture-aware Kerberos selection.

    When ``posture_snapshot`` carries ``NTLM_AUTHENTICATION=DISABLED HIGH`` and
    a plaintext password is available, the planner skips the NTLM attempt
    entirely and uses CredSSP+Kerberos directly. Otherwise the conservative
    NTLM-then-Kerberos retry chain runs unchanged — and its Kerberos-fallback
    success emits ``NTLM_REJECTED_VIA_RDP_KERBEROS_FALLBACK_OK`` so future runs
    can prune the wasted NTLM round-trip.
    """
    from adscan_internal.services.auth_plan import build_rdp_plan

    posture_domain = domain_for_posture or domain

    try:
        from aardwolf.commons.factory import RDPConnectionFactory
        from aardwolf.commons.iosettings import RDPIOSettings
        from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
        from aardwolf.protocol.x224.constants import SUPP_PROTOCOLS

        iosettings = RDPIOSettings()
        iosettings.channels = []
        iosettings.video_out_format = VIDEO_FORMAT.RAW
        iosettings.clipboard_use_pyperclip = False

        # ── Posture plan ──────────────────────────────────────────────────
        # aardwolf has no "negotiate" — baseline preference is NTLM-first.
        plan = build_rdp_plan(
            prefer_kerberos=False,
            posture=posture_snapshot,
            kerberos_viable=bool(dc_ip and not is_hash),
        )
        if plan.is_pruned:
            print_info_debug(f"[rdp_login] posture plan: {plan.attempt.rationale}")

        # Posture-forced Kerberos: skip NTLM entirely when we have what we need.
        if plan.attempt.use_kerberos and not is_hash and dc_ip:
            krb_url = _build_kerberos_url(domain, username, secret, host, dc_ip)
            krb_factory = RDPConnectionFactory.from_url(krb_url, iosettings)
            try:
                async with asyncio.timeout(timeout_s):
                    ok = await _attempt_connection(
                        krb_factory, host, SUPP_PROTOCOLS.HYBRID_EX, timeout_s
                    )
                    if ok:
                        return RDPLoginResult(host=host, verdict="TRUE")
            except TimeoutError:
                return RDPLoginResult(host=host, verdict="FALSE", error="timeout")
            except Exception as exc:  # noqa: BLE001
                # used_kerberos=True → not posture-relevant; log debug only.
                _emit_rdp_failure_posture(
                    sink=posture_sink,
                    domain=posture_domain,
                    exc=exc,
                    used_kerberos=True,
                )
                if plan.ntlm_fallback_allowed and _is_kerberos_infra_error(exc):
                    print_info_debug(
                        "[rdp_login] Kerberos infra error — retrying with NTLM"
                    )
                    ntlm_url = _build_ntlm_url(
                        domain, username, secret, host, is_hash=is_hash
                    )
                    ntlm_factory = RDPConnectionFactory.from_url(ntlm_url, iosettings)
                    try:
                        for nla_proto in (
                            SUPP_PROTOCOLS.HYBRID_EX,
                            SUPP_PROTOCOLS.HYBRID,
                        ):
                            async with asyncio.timeout(timeout_s):
                                ok = await _attempt_connection(
                                    ntlm_factory, host, nla_proto, timeout_s
                                )
                                if ok:
                                    return RDPLoginResult(host=host, verdict="TRUE")
                        return RDPLoginResult(host=host, verdict="FALSE")
                    except TimeoutError:
                        return RDPLoginResult(
                            host=host, verdict="FALSE", error="timeout"
                        )
                    except Exception:
                        return RDPLoginResult(host=host, verdict="FALSE")
                print_info_debug(f"[rdp_login] posture-forced Kerberos failed: {exc}")
            return RDPLoginResult(host=host, verdict="FALSE")

        # ── Conservative path (posture silent OR PtH OR no DC IP) ─────────
        ntlm_url = _build_ntlm_url(domain, username, secret, host, is_hash=is_hash)
        ntlm_factory = RDPConnectionFactory.from_url(ntlm_url, iosettings)

        # Track the most informative NTLM failure so we can emit a posture
        # signal if the subsequent Kerberos retry succeeds.
        ntlm_failure: BaseException | None = None

        # ── Pass 1: CredSSP+NTLM, NLA (HYBRID_EX then HYBRID) ─────────────
        # HYBRID_EX = Windows 8+ extended early-auth; HYBRID = Vista/7 compat.
        # Both give TRUE/FALSE from credential challenge before session opens.
        for nla_proto in (SUPP_PROTOCOLS.HYBRID_EX, SUPP_PROTOCOLS.HYBRID):
            try:
                async with asyncio.timeout(timeout_s):
                    ok = await _attempt_connection(
                        ntlm_factory, host, nla_proto, timeout_s
                    )
                    if ok:
                        return RDPLoginResult(host=host, verdict="TRUE")
                break  # server responded (rejected creds) — no need to try older NLA
            except TimeoutError:
                return RDPLoginResult(host=host, verdict="FALSE", error="timeout")
            except Exception as exc:  # noqa: BLE001
                ntlm_failure = exc
                continue  # protocol not supported, try next

        # ── Pass 2: CredSSP+Kerberos (password only, not hash) ─────────────
        # Tried when NTLM fails — covers environments where NTLM is disabled
        # by GPO.  PtH has no Kerberos equivalent without the Kerberos key.
        # Requires a KDC: without ``dc_ip`` the Kerberos credential cannot be
        # built at all, so the attempt is skipped and Pass 3 still runs.  RDP is
        # deliberately NOT wired for the sweep Kerberos pre-mint, so arriving
        # here with ``dc_ip=None`` is a normal state, not an edge case.
        if not is_hash and dc_ip:
            try:
                krb_url = _build_kerberos_url(domain, username, secret, host, dc_ip)
                krb_factory = RDPConnectionFactory.from_url(krb_url, iosettings)
                async with asyncio.timeout(timeout_s):
                    ok = await _attempt_connection(
                        krb_factory, host, SUPP_PROTOCOLS.HYBRID_EX, timeout_s
                    )
                    if ok:
                        # Kerberos succeeded after NTLM was rejected → strongest
                        # possible "NTLM disabled" signal for this domain.
                        _emit_posture_signal(
                            sink=posture_sink,
                            domain=posture_domain,
                            category=ConstraintCategory.NTLM_AUTHENTICATION,
                            state=TriState.DISABLED,
                            confidence=SignalConfidence.HIGH,
                            signal_code="NTLM_REJECTED_VIA_RDP_KERBEROS_FALLBACK_OK",
                            message=(
                                "NTLM rejected over RDP but Kerberos succeeded "
                                "— NTLM disabled by policy"
                            ),
                        )
                        return RDPLoginResult(host=host, verdict="TRUE")
            except TimeoutError:
                return RDPLoginResult(host=host, verdict="FALSE", error="timeout")
            except Exception:  # noqa: BLE001
                pass

        # NTLM failed and Kerberos either was not tried or also failed —
        # classify the NTLM failure for a defensive posture emit.
        if ntlm_failure is not None:
            _emit_rdp_failure_posture(
                sink=posture_sink,
                domain=posture_domain,
                exc=ntlm_failure,
                used_kerberos=False,
            )

        # ── Pass 3: plain (NLA-permissive server) ───────────────────────────
        try:
            async with asyncio.timeout(timeout_s):
                ok = await _attempt_connection(ntlm_factory, host, None, timeout_s)
                if ok:
                    return RDPLoginResult(host=host, verdict="MAYBE")
        except Exception:  # noqa: BLE001
            pass

        return RDPLoginResult(host=host, verdict="FALSE")

    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return RDPLoginResult(host=host, verdict="ERROR", error=str(exc))


async def scan_rdp_hosts(
    hosts: list[str],
    *,
    domain: str,
    username: str,
    secret: str,
    is_hash: bool,
    dc_ip: str | None = None,
    connect_timeout_s: float = 10.0,
    max_workers: int = 10,
    posture_snapshot: Optional[DomainPosture] = None,
    posture_sink: Optional[PostureSink] = None,
    domain_for_posture: Optional[str] = None,
) -> list[RDPLoginResult]:
    """Probe a list of hosts concurrently and return one result per host.

    Args:
        hosts: List of IP addresses or hostnames to probe.
        domain: Auth domain the credential belongs to.
        username: sAMAccountName or UPN prefix.
        secret: Plaintext password or NT hash (32-char hex).
        is_hash: True when secret is an NT hash (pass-the-hash mode).
        dc_ip: DC/KDC IP for Kerberos ticket acquisition.  Required for the
               Kerberos fallback to work in environments without AD-aware DNS.
               Safe to omit — NTLM-only probe proceeds without it.
        connect_timeout_s: Per-host handshake timeout in seconds.
        max_workers: Maximum concurrent probes.
        posture_snapshot: Optional :class:`DomainPosture` for the target
            domain. When ``NTLM_AUTHENTICATION=DISABLED HIGH`` is recorded,
            each probe skips the doomed NTLM attempt and uses Kerberos directly.
        posture_sink: Optional :data:`PostureSink` callable. When set, RDP
            failures classified as NTLM-rejected and Kerberos-fallback successes
            emit posture signals to this sink.
        domain_for_posture: Domain key under which posture signals are recorded.
            Defaults to ``domain``. Pass explicitly for cross-domain scenarios
            where the auth domain differs from the target domain.
    """
    # Transversal PROACTIVE clock sync at the RDP auth seam, ONCE before the
    # per-host fan-out (mirror of smb_transport / ldap_transport). RDP is the one
    # transport NOT covered by the sweep-premint SSOT (aardwolf is CredSSP+NTLM/PtH
    # by default), so its Kerberos fallback (rdp+kerberos-password / -rc4, used in
    # hardened NTLM-disabled envs) had no proactive clock sync of its own. When a
    # DC/KDC is in scope, converge through the guard here — TTL-memoized, so the
    # first host syncs and the rest no-op; best-effort; seeds the kerbad offset
    # host-helper-less. Keyed on the auth domain (== the Kerberos realm).
    if dc_ip and str(domain or "").strip():
        try:
            from adscan_internal.services.dc_time import (  # noqa: PLC0415
                ensure_clock_synced_for_target,
            )

            await ensure_clock_synced_for_target(str(domain), str(dc_ip))
        except Exception:  # noqa: BLE001 — never let the sync break the sweep
            pass

    sem = asyncio.Semaphore(max_workers)

    async def _guarded(host: str) -> RDPLoginResult:
        async with sem:
            return await _probe_one(
                host,
                domain,
                username,
                secret,
                is_hash=is_hash,
                dc_ip=dc_ip,
                timeout_s=connect_timeout_s,
                posture_snapshot=posture_snapshot,
                posture_sink=posture_sink,
                domain_for_posture=domain_for_posture,
            )

    return list(await asyncio.gather(*[_guarded(h) for h in hosts]))
