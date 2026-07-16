"""aiosmb transport adapter for ADscan SMB operations.

This module mirrors the ``ldap_transport_service`` pattern: it owns the
URL-string builder, connection lifecycle, and exception translation for all
aiosmb-backed SMB consumers inside ``adscan_internal``.

Only this file should import from ``aiosmb`` — all other services use the
context manager and exception classes defined here.
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import urllib.parse
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, AsyncIterator, Optional

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.domain_posture import DomainPosture

# Activate centralised Kerberos recovery (TKT_EXPIRED/NYV/TGT_REVOKED → auto
# refresh TGT & retry). See _kerberos_recovery for details.
from adscan_internal.services import _kerberos_recovery  # noqa: F401

from adscan_internal import (
    print_info_debug,
    telemetry,
)
from adscan_internal.services.async_bridge import run_async_sync
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    PostureSignal,
    SignalConfidence,
    TriState,
)
from adscan_internal.services.kerberos_tcp_target import resolve_kerberos_tcp_target
from adscan_internal.services.posture_sink import (  # noqa: F401  (re-exported)
    PostureSink,
    make_workspace_posture_sink,
)


# ---------------------------------------------------------------------------
# Domain-specific exception hierarchy
# ---------------------------------------------------------------------------


class SMBTransportError(Exception):
    """Base class for all ADscan SMB transport errors."""


class SMBAuthError(SMBTransportError):
    """Authentication failed (bad credentials, Kerberos failure, etc.)."""


class SMBAccessDeniedError(SMBTransportError):
    """Connection succeeded but the requested operation was denied."""


class SMBSigningRequiredError(SMBTransportError):
    """The server requires SMB signing and the client did not negotiate it."""


class SMBConnectionError(SMBTransportError):
    """Network-level failure: host unreachable, timeout, or TCP RST."""


# ---------------------------------------------------------------------------
# Auth-mode helpers
# ---------------------------------------------------------------------------

_NT_HASH_MARKERS = ("nt", "rc4", "nthash", "lmhash")


def _looks_like_nt_hash(value: str) -> bool:
    """Return True if the string is a 32-hex NT hash or LM:NT pair."""
    import re

    v = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}", v):
        return True
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", v))


def _is_aes_key(value: str) -> bool:
    """Return True if the string looks like an AES-128 or AES-256 key."""
    import re

    v = value.strip()
    return bool(
        re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{64}", v)
    ) and not _looks_like_nt_hash(v)


def _quote(value: str) -> str:
    """URL-encode one SMB URL component."""
    return urllib.parse.quote(str(value or ""), safe="")


# ---------------------------------------------------------------------------
# SMBConfig dataclass
# ---------------------------------------------------------------------------


@dataclass
class SMBConfig:
    """All parameters needed to open one authenticated SMB connection.

    ``auth_domain`` is the credential domain (where the user account lives).
    ``target_ip`` is the DC / host to connect to.  In cross-domain scenarios
    these two can differ — always set both explicitly.
    """

    target_ip: str
    target_hostname: str | None = None
    domain: str | None = None  # target domain (enumeration target)
    username: str | None = None
    password: str | None = None
    nt_hash: str | None = None  # plain NT or LM:NT pair
    aes_key: str | None = None  # 32-hex (AES-128) or 64-hex (AES-256)
    ccache_path: str | None = None  # path to .ccache file or KRB5CCNAME
    auth_domain: str | None = None  # credential domain (may differ from domain)
    kdc_ip: str | None = None  # KDC for auth_domain
    target_kdc_ip: str | None = None
    """KDC for the TARGET domain, used only for cross-forest Kerberos.

    When ``auth_domain`` differs from ``domain`` (e.g. essos.local credentials
    enumerating a sevenkingdoms.local host across a forest trust), the bind must
    follow a cross-realm referral: ask the AUTH KDC (``kdc_ip``) for a
    ``krbtgt/<target_realm>`` referral, then request the service ticket from the
    TARGET realm's KDC. ``target_kdc_ip`` is that target-realm KDC. When unset it
    falls back to ``target_ip`` (correct when the SMB target IS the target DC).
    Mirrors :class:`KerberosConfig.target_kdc_ip`.
    """
    port: int = 445
    timeout: int = 30
    use_kerberos: bool = False
    sign: bool = False
    encrypt: bool = False
    disable_self_heal: bool = False
    """When True, the transport will NOT retry with a healed config on
    a posture-recoverable failure (SMB signing required). See
    ``ADscanLDAPConfig.disable_self_heal`` for the full rationale —
    same contract here.
    """
    posture_sink: Optional[PostureSink] = None
    """Optional callable invoked when this transport observes a domain-wide
    SMB posture signal (NTLM rejected via SMB, SMB signing required, NTLM
    bind via SMB succeeded, etc.). Receives one :class:`PostureSignal` and
    may return an :class:`IntelligenceFinding` for the caller to surface to
    the user. When ``None`` (default), posture signals are silently dropped —
    the transport remains a pure protocol module with no workspace coupling.
    See PR2 (``KerberosConfig.posture_sink``) and PR3
    (``ADscanLDAPConfig.posture_sink``) for the matching pattern."""
    posture_snapshot: Optional["DomainPosture"] = None
    """Optional posture snapshot for the target domain. When set and
    ``NTLM_AUTHENTICATION = DISABLED HIGH`` is recorded,
    ``smb_machine_with_fallback`` skips the NTLM attempt entirely and uses
    Kerberos directly, saving one wasted RTT. When ``None``, conservative
    NTLM-first + Kerberos-retry behavior is unchanged.
    See PR10 (``build_smb_plan``) for the posture-planner contract."""
    ip_hostname_inventory: Optional[dict[str, list[str]]] = None
    """Optional persisted IP → hostname candidates from MassDNS/reachability.

    Used only for Kerberos SPN selection when ``target_ip`` is an IP and no
    explicit ``target_hostname`` is available. TCP still connects to
    ``target_ip`` via ``serverip=``.
    """

    def __post_init__(self) -> None:
        # Promote short Kerberos target hostnames to FQDN. Centralised so every
        # SMBConfig consumer is fixed at once — see services/_kerberos_spn.py.
        from adscan_internal.services._kerberos_spn import (
            normalize_kerberos_target_hostname,
        )
        from adscan_internal.services.credential_routing import (
            promote_credential_fields,
        )

        self.target_hostname = normalize_kerberos_target_hostname(
            self.target_hostname, self.domain
        )

        # Promote bare KDC addresses to FQDN — same contract as target_hostname.
        if self.kdc_ip:
            self.kdc_ip = (
                normalize_kerberos_target_hostname(self.kdc_ip, self.domain)
                or self.kdc_ip
            )
        if self.target_kdc_ip:
            self.target_kdc_ip = (
                normalize_kerberos_target_hostname(self.target_kdc_ip, self.domain)
                or self.target_kdc_ip
            )

        # Auto-route an NT hash that landed in the password field.
        self.password, self.nt_hash, self.aes_key, self.ccache_path = (
            promote_credential_fields(
                password=self.password,
                nt_hash=self.nt_hash,
                aes_key=self.aes_key,
                ccache_path=self.ccache_path,
            )
        )


# ---------------------------------------------------------------------------
# URL builder
# ---------------------------------------------------------------------------


def _build_smb_url(config: SMBConfig) -> str:
    """Build an aiosmb connection URL from an SMBConfig.

    URL scheme reference (from aiosmb/commons/connection/factory.py examples):

        smb+ntlm-password://DOMAIN\\user:password@ip
        smb+ntlm-nt://DOMAIN\\user:nthash@ip
        smb+kerberos-password://DOMAIN\\user:password@ip/?dc=kdc_ip
        smb+kerberos-rc4://DOMAIN\\user:nthash@ip/?dc=kdc_ip
        smb+kerberos-aes://DOMAIN\\user:aeskey@ip/?dc=kdc_ip
        smb+kerberos-ccache://DOMAIN\\user:ccache_path@ip/?dc=kdc_ip

    For Kerberos, the URL host is the SPN target used by aiosmb. Prefer
    ``target_hostname`` when available and pass ``serverip=target_ip`` so the
    TCP connection can still go to the resolved address. Passing an IP as the
    Kerberos URL host asks the KDC for ``cifs/<ip>``, which commonly fails with
    ``KDC_ERR_S_PRINCIPAL_UNKNOWN``.
    """
    credential_domain = str(config.auth_domain or config.domain or "").strip()
    username = str(config.username or "").strip()
    target_ip = str(config.target_ip or "").strip()
    target_hostname = str(config.target_hostname or "").strip()
    host = target_ip
    port = int(config.port or 445)

    params: list[str] = []
    if config.timeout and config.timeout != 30:
        params.append(f"timeout={int(config.timeout)}")

    if config.use_kerberos:
        from adscan_internal.services._kerberos_spn import (
            require_kerberos_target_hostname,
        )

        target = resolve_kerberos_tcp_target(
            target_host=target_ip,
            spn_host=target_hostname or None,
            resolver_ip=config.kdc_ip or None,
            domain=config.domain,
            ip_hostname_inventory=config.ip_hostname_inventory,
        )
        host = require_kerberos_target_hostname(target.spn_host, protocol="SMB")
        if target.server_ip:
            params.append(f"serverip={_quote(target.server_ip)}")

        if config.kdc_ip:
            kdc = config.kdc_ip.strip()
            # Defensive: __post_init__ should have promoted bare hostnames already.
            # If a bare label somehow slips through, log it so it is traceable.
            if kdc and "." not in kdc and not kdc.replace(":", "").replace(".", "").isdigit():
                print_info_debug(
                    f"[smb_transport] bare hostname {kdc!r} reached URL builder as kdc_ip — "
                    "expected FQDN or IP (was __post_init__ bypassed?); "
                    f"domain={config.domain!r}"
                )
        else:
            kdc = str(config.target_ip or "").strip()
            if kdc:
                print_info_debug(
                    f"[smb_transport] kdc_ip not set for Kerberos to {config.target_ip} — "
                    f"falling back to target IP as KDC ({kdc}:88); "
                    "pass kdc_ip=resolve_dc_ip(domain_data) at the call site"
                )
        if kdc:
            params.append(f"dc={_quote(kdc)}")

        # Cross-forest Kerberos: when the credential's realm (auth_domain)
        # differs from the target realm (domain), the SMB bind must follow a
        # cross-realm referral. aiosmb has no get_client_newtarget equivalent
        # (badldap, the LDAP transport, sets cross_target/cross_realm that way),
        # so without these params badauth's credential carries cross_target=None,
        # the Fresh-TGS gate's except-branch referral never fires, and the AUTH
        # KDC hands back the cross-realm REFERRAL TGT (krbtgt/TARGET@AUTH) which
        # the target SMB service rejects (KRB_ERR_GENERIC / SEC_E_LOGON_DENIED).
        #
        # ``dcc`` + ``realmc`` are the badauth URL params (UniCredential.from_url)
        # that set cred.cross_target (target-realm KDC) + cred.cross_realm
        # (target realm). The except-branch then does:
        #   get_referral_ticket(cross_realm, cross_target.ip) → get_TGS(spn)
        # exactly like the working LDAP path. ``realmc`` is the TARGET realm and
        # ``dcc`` the TARGET realm's KDC — matching what badldap's
        # get_client_newtarget(new_domain=target, ip=target_dc_ip) produces (see
        # ldap_transport_service _build_ldap_connection_url + get_client_newtarget
        # call site). ``dcc`` defaults to ``target_ip`` when ``target_kdc_ip`` is
        # unset (correct when the SMB target IS the target DC). Mirrors bloodyAD's
        # `&dcc=&realmc=`.
        auth_realm = str(config.auth_domain or "").strip()
        target_realm = str(config.domain or "").strip()
        is_cross_forest = bool(
            auth_realm and target_realm and auth_realm.casefold() != target_realm.casefold()
        )
        if is_cross_forest:
            target_kdc = str(
                config.target_kdc_ip or config.target_ip or ""
            ).strip()
            if target_kdc:
                params.append(f"dcc={_quote(target_kdc)}")
            params.append(f"realmc={_quote(target_realm)}")
            print_info_debug(
                f"[smb_transport] cross-forest Kerberos {auth_realm} -> "
                f"{target_realm}: dcc={target_kdc} realmc={target_realm} "
                "(following cross-realm referral)"
            )

        # Ccache resolution order MUST mirror the hardened LDAP builder
        # (ldap_transport_service.py:567-604): an explicitly-passed
        # ``config.ccache_path`` wins (slot 1), but the bare ``$KRB5CCNAME``
        # fallback drops to the LAST slot — it is only consulted when no
        # aes_key / nt_hash / password was supplied. The previous order OR'd
        # ``config.ccache_path`` with ``$KRB5CCNAME`` into slot 1, so a caller
        # that passed explicit creds (fresh AS-REQ as a specific user) but no
        # ccache_path silently bound as whatever TGT was sitting in the env
        # ccache from a prior operation (e.g. the DA after a DA step) — the
        # ambient-ccache principal hijack.
        explicit_ccache = str(config.ccache_path or "").strip()

        if explicit_ccache:
            # Slot 1: caller explicitly passed ccache_path. EXEMPT from the
            # principal guard — this is exactly where ESC13 capability-bearing
            # PAC-TGTs and S4U/RBCD/silver service tickets flow, and their
            # principal mismatch (impersonated/synthetic principal) is intended.
            auth_kind = "kerberos-ccache"
            secret = _quote(explicit_ccache)
        elif config.aes_key:
            auth_kind = "kerberos-aes"
            secret = _quote(config.aes_key.strip())
        elif config.nt_hash:
            # NT hash as Kerberos RC4 session key
            nt_only = (
                config.nt_hash.split(":")[-1]
                if ":" in config.nt_hash
                else config.nt_hash
            )
            auth_kind = "kerberos-rc4"
            secret = _quote(nt_only.strip())
        elif config.password:
            auth_kind = "kerberos-password"
            secret = _quote(config.password)
        else:
            # Slot 5: legacy ``$KRB5CCNAME`` fallback (no explicit creds).
            env_ccache = str(os.environ.get("KRB5CCNAME") or "").strip()
            if env_ccache:
                # Read-only principal guard: warn + record telemetry if the
                # ambient ccache authenticates as a principal other than the
                # one the caller asked for. Conservative (warn-only) for now.
                if username:
                    from adscan_internal.services._kerberos_ccache_guard import (
                        assert_ccache_principal_matches,
                    )

                    assert_ccache_principal_matches(
                        env_ccache,
                        username,
                        credential_domain,
                        source="env",
                        context="smb_transport",
                    )
                auth_kind = "kerberos-ccache"
                secret = _quote(env_ccache)
            else:
                auth_kind = "kerberos-password"
                secret = ""
    else:
        # NTLM branch
        if config.nt_hash:
            nt_only = (
                config.nt_hash.split(":")[-1]
                if ":" in config.nt_hash
                else config.nt_hash
            )
            auth_kind = "ntlm-nt"
            secret = _quote(nt_only.strip())
        elif config.password:
            auth_kind = "ntlm-password"
            secret = _quote(config.password)
        else:
            auth_kind = "ntlm-password"
            secret = ""

    user_part = (
        f"{_quote(credential_domain)}\\{_quote(username)}"
        if credential_domain
        else _quote(username)
    )
    base = f"smb+{auth_kind}://{user_part}:{secret}@{host}"
    if port != 445:
        base = f"smb+{auth_kind}://{user_part}:{secret}@{host}:{port}"

    if params:
        base = f"{base}/?{'&'.join(params)}"

    return base


# ---------------------------------------------------------------------------
# Exception translation helpers
# ---------------------------------------------------------------------------

# Strings that indicate authentication failures in aiosmb / asyauth errors.
_AUTH_MARKERS = (
    "authentication",
    "logon failure",
    "wrong password",
    "STATUS_LOGON_FAILURE",
    "STATUS_WRONG_PASSWORD",
    "STATUS_ACCOUNT_DISABLED",
    "STATUS_ACCOUNT_LOCKED_OUT",
    "STATUS_PASSWORD_EXPIRED",
    "kerberos",
    "KRB5",
    "krb_ap_err",
    "ticket",
    "pre-authentication",
    # Kerberos AP-exchange processing failures (mutual-auth leg) — must classify
    # as an AUTH error (not a connection error) so smb_machine_with_fallback
    # catches them and retries with NTLM when the plan allows. See
    # auth_error_classification.NATIVE_KERBEROS_INFRA_ERROR_MARKERS.
    "asn1_structs.ap_rep",
    "asn1_structs.ap_req",
    "krb-error error-code",
    "rejected the kerberos ap-req",
)

_ACCESS_DENIED_MARKERS = (
    "STATUS_ACCESS_DENIED",
    "access denied",
    "ACCESS_DENIED",
    "STATUS_SHARING_VIOLATION",
)

_SIGNING_MARKERS = (
    "signing required",
    "STATUS_INVALID_PARAMETER",
    "signing",
    "negotiate signing",
)

_CONNECTION_MARKERS = (
    "connection",
    "timeout",
    "refused",
    "unreachable",
    "network",
    "eof",
    "broken pipe",
    "connection reset",
)


def _translate_aiosmb_exception(exc: Exception) -> SMBTransportError:
    """Map an aiosmb / asyauth exception to an ADscan SMB domain exception."""
    msg = str(exc).lower()
    if any(m.lower() in msg for m in _AUTH_MARKERS):
        return SMBAuthError(str(exc))
    if any(m.lower() in msg for m in _ACCESS_DENIED_MARKERS):
        return SMBAccessDeniedError(str(exc))
    if any(m.lower() in msg for m in _SIGNING_MARKERS):
        return SMBSigningRequiredError(str(exc))
    if any(m.lower() in msg for m in _CONNECTION_MARKERS):
        return SMBConnectionError(str(exc))
    # Fallback: treat as connection error (callers can inspect .args[0] if needed)
    return SMBConnectionError(str(exc))


# ---------------------------------------------------------------------------
# Posture signal emission (PR4)
# ---------------------------------------------------------------------------


def _emit_posture_signal(
    config: "SMBConfig",
    *,
    category: ConstraintCategory,
    state: TriState,
    confidence: SignalConfidence,
    signal_code: str,
    message: str,
    protocol: str = "smb",
) -> None:
    """Emit an SMB posture signal to the configured sink, if any.

    Pure best-effort: any exception in the sink is captured via telemetry
    and never propagates — posture telemetry must never break an SMB bind.

    Args:
        config: The active ``SMBConfig``; the ``posture_sink`` field is
            consulted. When ``None``, this is a no-op.
        category: Which posture constraint this signal belongs to.
        state: The observed tri-state for the constraint.
        confidence: Confidence in the observation.
        signal_code: Stable machine-readable code.
        message: Human-readable description.
        protocol: Originating protocol label (default ``"smb"``).
    """
    sink = getattr(config, "posture_sink", None)
    if sink is None:
        return
    try:
        signal = PostureSignal(
            domain=str(config.domain or ""),
            category=category,
            state=state,
            confidence=confidence,
            source="smb_transport",
            signal_code=signal_code,
            message=message,
            protocol=protocol,
            observed_at=datetime.now(timezone.utc),
        )
        sink(signal)
    except Exception as sink_exc:
        telemetry.capture_exception(sink_exc)
        print_info_debug(
            f"[smb_transport] posture sink raised: "
            f"{type(sink_exc).__name__}: {sink_exc}"
        )


def _emit_smb_failure_posture(
    config: "SMBConfig",
    *,
    exc: Exception,
    used_kerberos_auth: bool,
) -> None:
    """Classify one SMB bind failure and emit any matching posture signals.

    Two independent rules:

    - If the exception classifies as :class:`SMBSigningRequiredError` we emit
      ``SMB_SIGNING REQUIRED HIGH`` regardless of auth type — signing
      enforcement is independent of NTLM.
    - If the exception classifies as :class:`SMBAuthError`, the original
      exception text matches one of :data:`_NTLM_BLOCKED_MARKERS`, and the
      attempt was NTLM (not Kerberos), we emit
      ``NTLM_AUTHENTICATION DISABLED HIGH``.

    All other failure shapes (connection/timeout, access denied, generic auth)
    are intentionally ignored — they are not domain-level hardening evidence.
    """
    translated = _translate_aiosmb_exception(exc)
    if isinstance(translated, SMBSigningRequiredError):
        _emit_posture_signal(
            config,
            category=ConstraintCategory.SMB_SIGNING,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="SMB_SIGNING_REQUIRED",
            message="DC requires SMB signing",
        )
    if isinstance(translated, SMBAuthError) and not used_kerberos_auth:
        msg_upper = str(exc).upper()
        if any(marker in msg_upper for marker in _NTLM_BLOCKED_MARKERS):
            _emit_posture_signal(
                config,
                category=ConstraintCategory.NTLM_AUTHENTICATION,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="NTLM_REJECTED_VIA_SMB",
                message=(
                    "DC rejected NTLM auth over SMB — NTLM appears disabled by policy"
                ),
            )


def _emit_smb_success_posture(
    config: "SMBConfig",
    *,
    used_kerberos_auth: bool,
    connection: Optional[Any] = None,
) -> None:
    """Emit posture signals after a successful SMB login.

    - NTLM success (no Kerberos) → ``NTLM_AUTHENTICATION ENABLED MEDIUM``.
      Kerberos success is intentionally not emitted — it is the default and
      carries no hardening signal.
    - When ``connection`` is provided and exposes ``signing_required=True``
      (the canonical attribute on aiosmb's ``SMBConnection`` — set during
      negotiate per ``vendor/aiosmb/aiosmb/connection.py``) we emit
      ``SMB_SIGNING REQUIRED HIGH``. This negotiate-time signal is stronger
      than parsing exception strings because it reflects the server's actual
      ``SecurityMode`` flags. If the attribute is absent or read raises, we
      simply skip the negotiate emit (the failure-text classifier remains as
      a fallback).
    """
    if not used_kerberos_auth:
        _emit_posture_signal(
            config,
            category=ConstraintCategory.NTLM_AUTHENTICATION,
            state=TriState.ENABLED,
            confidence=SignalConfidence.MEDIUM,
            signal_code="NTLM_BIND_OK_SMB",
            message="NTLM authentication via SMB succeeded",
        )

    if connection is None:
        return
    try:
        # Canonical name in vendored aiosmb 0.x: ``signing_required`` (set in
        # SMBConnection.__init__ and updated during negotiate). The other
        # candidates are kept for forward-compatibility with future aiosmb
        # versions; they are simply absent today.
        signing_signal = False
        for attr_name in (
            "signing_required",
            "signing_enforced",
            "is_signing_enforced",
            "signing_active",
        ):
            value = getattr(connection, attr_name, None)
            if value:
                signing_signal = True
                break
        if signing_signal:
            _emit_posture_signal(
                config,
                category=ConstraintCategory.SMB_SIGNING,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="SMB_SIGNING_NEGOTIATED_REQUIRED",
                message=("DC negotiated SMB signing as required during session setup"),
            )
    except Exception as attr_exc:
        telemetry.capture_exception(attr_exc)
        print_info_debug(
            f"[smb_transport] signing attribute read failed: "
            f"{type(attr_exc).__name__}: {attr_exc}"
        )


# ---------------------------------------------------------------------------
# Pre-auth NEGOTIATE signing read (auth-independent)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SMBSigningNegotiation:
    """Result of a pre-auth SMB NEGOTIATE round-trip.

    ``signing_required`` reflects the server's ``SecurityMode`` REQUIRED bit as
    read from the NEGOTIATE response — observed BEFORE any session-setup, so it
    is independent of whether NTLM or Kerberos would authenticate. ``dialect``
    is the selected SMB dialect (informational; may be ``None`` if aiosmb did
    not expose it).
    """

    signing_required: bool
    dialect: Optional[Any] = None


@dataclass(frozen=True)
class SMBSessionSetupOutcome:
    """Raw outcome of one NTLM SMB SESSION_SETUP attempt (posture-probe use).

    Reports what the DC did with an NTLM session-setup WITHOUT interpreting it
    into a posture verdict. The caller owns the verdict mapping — and it must,
    because an NTLM-disabled DC (``NTLM_BLOCKED``/``NOT_SUPPORTED``) and a
    bogus-credential rejection (``LOGON_FAILURE``) are OPPOSITE verdicts for the
    NTLM_AUTHENTICATION probe and must never share a classifier (see the A3
    probe in ``posture_probe``; contrast ``_NTLM_BLOCKED_MARKERS`` which
    deliberately conflates them for the fallback-retry path).

    Attributes:
        session_established: The SESSION_SETUP fully succeeded — the NTLM SSP
            reached the credential stage and the DC accepted it. With a bogus
            credential this only happens on a guest-mapped / NULL-session DC;
            either way NTLM was reachable, so it means NTLM is enabled.
        ntstatus_name: The ``NTStatus`` enum name the DC returned when the
            SESSION_SETUP failed (e.g. ``"LOGON_FAILURE"``, ``"NTLM_BLOCKED"``,
            ``"NOT_SUPPORTED"``), or ``None`` when no structured NTSTATUS was
            surfaced.
        error_text: The lowercased rendered error for substring classification
            when ``ntstatus_name`` is unavailable (empty on success).
    """

    session_established: bool
    ntstatus_name: Optional[str]
    error_text: str


async def smb_probe_ntlm_session_setup(config: SMBConfig) -> SMBSessionSetupOutcome:
    """Pre-auth NTLM SMB SESSION_SETUP that surfaces the raw NTSTATUS.

    Runs ``connect()`` -> ``negotiate()`` -> ``session_setup()`` over NTLM using
    the (typically BOGUS) credential baked into ``config``'s URL, then returns
    the raw DC response without interpreting it. This is the single source of
    truth for "what did the NTLM SSP do" as an SMB operation — a DIFFERENT
    protocol from the LDAP signing layer, so the NTLM verdict it produces cannot
    be masked by an LDAP signing-required policy (the A3 posture-probe bug this
    primitive exists to fix). Mirrors :func:`smb_negotiate_signing` in shape.

    The auth scheme in ``config`` must be NTLM (``use_kerberos=False``) — the
    whole point is to exercise the NTLM SSP. The caller is expected to wrap this
    in an ``asyncio.wait_for`` budget for a hard ceiling.

    Args:
        config: The :class:`SMBConfig` whose ``target_ip`` / ``port`` /
            ``username`` / ``password`` (or ``nt_hash``) build the NTLM URL.

    Returns:
        An :class:`SMBSessionSetupOutcome` describing the raw DC response.

    Raises:
        SMBConnectionError: TCP connect or NEGOTIATE failed — the NTLM SSP
            decision was never reached. The A3 probe treats this as UNKNOWN/LOW
            and does NOT emit a posture signal (observe-don't-infer).
    """
    try:
        from aiosmb.commons.connection.factory import SMBConnectionFactory
    except ImportError as exc:
        telemetry.capture_exception(exc)
        raise SMBConnectionError(
            f"aiosmb is not available in this runtime environment: {exc}"
        ) from exc

    url = _build_smb_url(config)
    print_info_debug(
        f"[smb-transport] NTLM SESSION_SETUP probe to "
        f"{config.target_ip}:{config.port} (bogus-cred, raw NTSTATUS)"
    )
    connection = SMBConnectionFactory.from_url(url).get_connection()

    _, err = await connection.connect()  # TCP only — no auth
    if err is not None:
        telemetry.capture_exception(err)
        raise SMBConnectionError(
            f"SMB connect to {config.target_ip} failed during NTLM probe: {err}"
        ) from err

    try:
        _, err = await connection.negotiate()
        if err is not None:
            telemetry.capture_exception(err)
            raise SMBConnectionError(
                f"SMB NEGOTIATE to {config.target_ip} failed during NTLM probe: {err}"
            ) from err

        # session_setup() catches internally and returns (ok, err); it never
        # raises. On failure ``err`` is an SMBException carrying ``.ntstatus``
        # (the DC's reply header status) — LOGON_FAILURE (bogus cred reached the
        # credential check) vs NTLM_BLOCKED / NOT_SUPPORTED (SSP refused).
        ok, err = await connection.session_setup()
        if ok and err is None:
            return SMBSessionSetupOutcome(
                session_established=True,
                ntstatus_name=None,
                error_text="",
            )
        nts = getattr(err, "ntstatus", None)
        name = getattr(nts, "name", None)
        return SMBSessionSetupOutcome(
            session_established=False,
            ntstatus_name=str(name) if name is not None else None,
            error_text=(
                f"{type(err).__name__}: {err}".lower() if err is not None else ""
            ),
        )
    finally:
        try:
            await connection.disconnect()
        except Exception as disc_exc:  # noqa: BLE001
            telemetry.capture_exception(disc_exc)


async def smb_negotiate_signing(config: SMBConfig) -> SMBSigningNegotiation:
    """Pre-auth: TCP connect + SMB NEGOTIATE only; read the server SecurityMode.

    Performs ``connect()`` -> ``negotiate()`` -> read ``signing_required`` ->
    ``disconnect()``. It NEVER calls ``session_setup()`` / ``login()``, so the
    returned signing verdict is independent of NTLM/Kerberos — it reflects the
    server's negotiated ``SecurityMode`` REQUIRED flag, which the DC sends in
    the NEGOTIATE response before any credential is presented.

    This is the single source of truth for "what SMB signing policy did the DC
    negotiate" without authenticating. The A4 posture probe uses it as its
    primary path (it cannot hang on an NTLM-disabled DC, because the NEGOTIATE
    precedes the auth that would block). Any caller that needs the negotiated
    signing policy without authenticating can reuse it.

    The auth scheme baked into the URL is never exercised (no session-setup is
    performed), so credentials are irrelevant — the function works even with no
    credential material at all.

    Args:
        config: The :class:`SMBConfig` whose ``target_ip`` / ``port`` /
            ``timeout`` are used to open the TCP connection. ``timeout`` bounds
            the connect; the caller is expected to wrap the whole call in an
            ``asyncio.wait_for`` budget for a hard ceiling.

    Returns:
        An :class:`SMBSigningNegotiation` describing the observed policy.

    Raises:
        SMBConnectionError: TCP connect failed, or NEGOTIATE returned an error.
            The caller (the posture probe) treats this as UNKNOWN/LOW and does
            NOT emit a posture signal (observe-don't-infer).
    """
    try:
        from aiosmb.commons.connection.factory import SMBConnectionFactory
    except ImportError as exc:
        telemetry.capture_exception(exc)
        raise SMBConnectionError(
            f"aiosmb is not available in this runtime environment: {exc}"
        ) from exc

    url = _build_smb_url(config)  # auth scheme is irrelevant; never exercised
    print_info_debug(
        f"[smb-transport] pre-auth NEGOTIATE to "
        f"{config.target_ip}:{config.port} (no session-setup)"
    )
    connection = SMBConnectionFactory.from_url(url).get_connection()

    _, err = await connection.connect()  # TCP only — no auth
    if err is not None:
        telemetry.capture_exception(err)
        raise SMBConnectionError(
            f"SMB connect to {config.target_ip} failed during NEGOTIATE probe: {err}"
        ) from err

    try:
        _, err = await connection.negotiate()  # sets connection.signing_required
        if err is not None:
            telemetry.capture_exception(err)
            raise SMBConnectionError(
                f"SMB NEGOTIATE to {config.target_ip} failed: {err}"
            ) from err
        return SMBSigningNegotiation(
            signing_required=bool(getattr(connection, "signing_required", False)),
            dialect=getattr(connection, "selected_dialect", None),
        )
    finally:
        try:
            await connection.disconnect()
        except Exception as disc_exc:  # noqa: BLE001
            telemetry.capture_exception(disc_exc)


# ---------------------------------------------------------------------------
# SMBMachine context manager
# ---------------------------------------------------------------------------


class _SelfHealRetrySentinel(Exception):
    """Internal-only marker used to break out of an ``async with`` block
    when the SMB login failed with a posture-recoverable error and we want
    to retry the connection with a healed config. Never propagates to
    callers — :func:`smb_machine_for` catches it and loops.
    """


def _classify_recoverable_smb_failure(
    exc: BaseException,
    *,
    cfg: "SMBConfig",
) -> Optional["SMBConfig"]:
    """Identify an SMB failure whose fix is a posture-driven config tweak.

    Mirror of ``_classify_recoverable_bind_failure`` (LDAP) and
    ``_classify_recoverable_kerberos_failure`` (Kerberos). Returns a new
    :class:`SMBConfig` to retry with, or ``None`` when the failure is
    not posture-recoverable.

    Recovery rule (single one today):

      * Translated error is :class:`SMBSigningRequiredError` AND
        ``cfg.sign`` is False → retry with ``sign=True``. The signal
        ``SMB_SIGNING REQUIRED HIGH`` is emitted by
        :func:`_emit_smb_failure_posture` separately so the planner
        learns regardless of retry success.

    Any other failure shape (credentials rejected, host unreachable,
    timeout) is NOT retried here — those are real errors.
    """
    import dataclasses as _dc

    translated = _translate_aiosmb_exception(exc)
    if isinstance(translated, SMBSigningRequiredError) and not cfg.sign:
        print_info_debug(
            "[smb_transport] self-heal: SMB signing required, "
            "queuing retry with sign=True"
        )
        return _dc.replace(cfg, sign=True)
    return None


@asynccontextmanager
async def smb_machine_for(config: SMBConfig) -> AsyncIterator[Any]:
    """Async context manager that yields a connected ``SMBMachine``.

    Translates aiosmb exceptions to ADscan SMB domain exceptions.  Callers
    must run this inside an ``asyncio`` event loop (use ``asyncio.run`` or
    ``asyncio.to_thread`` from sync boundaries).

    Self-healing behaviour: when the server rejects the initial bind
    with :class:`SMBSigningRequiredError` and the caller's config had
    ``sign=False``, the connection is retried ONCE with ``sign=True``
    in the same call. The posture signal
    ``SMB_SIGNING REQUIRED HIGH`` is emitted regardless of whether the
    retry succeeds so future operations on this domain start with
    signing already on. The retry budget is exactly one attempt per
    ``smb_machine_for`` call to prevent infinite loops if the server
    rejects both.

    Usage::

        async with smb_machine_for(config) as machine:
            async for share, err in machine.list_shares():
                ...

    Raises:
        SMBAuthError: credentials were rejected.
        SMBConnectionError: host is unreachable or connection dropped.
        SMBSigningRequiredError: server requires signing AND the retry
            with ``sign=True`` also failed (or ``sign=True`` was already
            on, ruling out the recovery).
    """
    try:
        from aiosmb.commons.connection.factory import SMBConnectionFactory
        from aiosmb.commons.interfaces.machine import SMBMachine
    except ImportError as exc:
        telemetry.capture_exception(exc)
        raise SMBConnectionError(
            f"aiosmb is not available in this runtime environment: {exc}"
        ) from exc

    # Self-healing retry budget: at most one retry per call, scoped to
    # the recovery key (sign-flag flip). Identical pattern to the LDAP
    # transport's ``_self_heal_used`` set.
    _self_heal_used: set[str] = set()
    effective_config = config

    # Loop terminates either by ``yield`` + ``return`` (success), by a
    # raised exception (terminal failure), or by ``next_config`` being
    # set inside the try block (signal to retry with healed config).
    while True:
        url = _build_smb_url(effective_config)
        print_info_debug(
            f"[smb-transport] connecting via aiosmb to "
            f"{effective_config.target_ip}:{effective_config.port}"
        )

        factory = SMBConnectionFactory.from_url(url)
        connection = factory.get_connection()
        next_config: Optional["SMBConfig"] = None

        try:
            async with connection:
                _, err = await connection.login()
                if err is not None:
                    telemetry.capture_exception(err)
                    _emit_smb_failure_posture(
                        effective_config,
                        exc=err,
                        used_kerberos_auth=effective_config.use_kerberos,
                    )
                    recovered = (
                        None
                        if effective_config.disable_self_heal
                        else _classify_recoverable_smb_failure(
                            err, cfg=effective_config
                        )
                    )
                    if recovered is not None:
                        key = f"sign={recovered.sign}"
                        if key not in _self_heal_used:
                            # Record the retry intent, then let the
                            # ``async with connection`` block close
                            # cleanly by raising-to-exit. ``next_config``
                            # is checked after the ``except`` chain to
                            # drive the next while iteration.
                            _self_heal_used.add(key)
                            next_config = recovered
                            raise _SelfHealRetrySentinel()
                    raise _translate_aiosmb_exception(err)
                machine = SMBMachine(connection)
                async with machine:
                    _emit_smb_success_posture(
                        effective_config,
                        used_kerberos_auth=effective_config.use_kerberos,
                        connection=connection,
                    )
                    yield machine
                return  # success — caller exited the ``async with`` cleanly
        except _SelfHealRetrySentinel:
            # Internal sentinel — the ``async with connection`` block has
            # now closed cleanly, so the connection is disposed and we
            # can safely loop back to retry with the healed config.
            assert next_config is not None
            effective_config = next_config
            continue
        except SMBTransportError:
            # Already classified + emitted in the inner block.
            raise
        except asyncio.TimeoutError as exc:
            # Network-level — not posture-relevant.
            telemetry.capture_exception(exc)
            raise SMBConnectionError(
                f"SMB connection to {effective_config.target_ip} timed out "
                f"after {effective_config.timeout}s"
            ) from exc
        except Exception as exc:
            telemetry.capture_exception(exc)
            _emit_smb_failure_posture(
                effective_config,
                exc=exc,
                used_kerberos_auth=effective_config.use_kerberos,
            )
            recovered = (
                None
                if effective_config.disable_self_heal
                else _classify_recoverable_smb_failure(
                    exc, cfg=effective_config
                )
            )
            if recovered is not None:
                key = f"sign={recovered.sign}"
                if key not in _self_heal_used:
                    _self_heal_used.add(key)
                    effective_config = recovered
                    continue  # next iteration of the while loop
            raise _translate_aiosmb_exception(exc)


# ---------------------------------------------------------------------------
# smb_machine_with_fallback — NTLM → Kerberos auto-retry
# ---------------------------------------------------------------------------

_NTLM_BLOCKED_MARKERS = (
    "STATUS_LOGON_FAILURE",
    "STATUS_NTLM_BLOCKED",
    "NTLM_BLOCKED",
    "STATUS_NO_LOGON_SERVERS",
    "NO_LOGON_SERVERS",
    "NTLMSSP",
    # STATUS_ACCESS_DENIED excluded — that is a privilege error,
    # not an NTLM-disabled signal; let it propagate as SMBAccessDeniedError.
)


def _is_kerberos_infra_error(exc_or_msg: Any) -> bool:
    """Return True when a Kerberos SMB failure is an infrastructure problem."""
    from adscan_internal.services.auth_error_classification import (
        is_aiosmb_kerberos_infra_error,
    )

    return is_aiosmb_kerberos_infra_error(exc_or_msg)


def _is_kerberos_soft_error(exc_or_msg: Any) -> bool:
    """Return True for account-level Kerberos failures where NTLM fallback is warranted.

    Distinct from infra errors: the KDC responded but cannot authenticate this
    principal right now (e.g. KDC_ERR_KEY_EXPIRED = password must change).
    NTLM may still succeed with the same credential for SAMR / SMB operations.
    """
    from adscan_internal.services.auth_error_classification import (
        is_kerberos_soft_error,
    )

    return is_kerberos_soft_error(exc_or_msg)


@asynccontextmanager
async def smb_machine_with_fallback(config: SMBConfig) -> AsyncIterator[Any]:
    """Like smb_machine_for, but posture-aware and auto-retries with Kerberos.

    When ``config.posture_snapshot`` is set and records
    ``NTLM_AUTHENTICATION = DISABLED (HIGH)``, the plan forces Kerberos from
    the first attempt — the doomed NTLM bind is skipped entirely. This is the
    PR10 posture-plan integration; all other behavior is identical to pre-PR10.

    When ``config.use_kerberos`` is True (either from the caller or forced by
    the plan), the call is forwarded directly to :func:`smb_machine_for` with
    no retry logic. Otherwise the first attempt uses NTLM and, if a
    :class:`SMBAuthError` that looks like NTLM being disabled is raised
    (STATUS_LOGON_FAILURE, NTLM, NTLMSSP), a second attempt is made with
    ``use_kerberos=True`` provided that ``config.kdc_ip`` or ``config.domain``
    is populated.

    Raises:
        SMBAuthError: both NTLM and Kerberos attempts failed, or the error does
            not look like NTLM being blocked.
        SMBConnectionError: network-level failure.
        SMBSigningRequiredError: signing negotiation failed.
    """
    from adscan_internal.services.auth_plan import build_smb_plan

    plan = build_smb_plan(config=config, posture=config.posture_snapshot)

    if plan.is_pruned:
        print_info_debug(f"[smb_transport] posture plan: {plan.attempt.rationale}")

    # Apply the plan — may upgrade NTLM→Kerberos when posture says NTLM disabled.
    effective_config = (
        dataclasses.replace(config, use_kerberos=plan.attempt.use_kerberos)
        if plan.attempt.use_kerberos != config.use_kerberos
        else config
    )

    if effective_config.use_kerberos:
        from adscan_internal.services._kerberos_spn import KerberosSpnUnresolvedError

        try:
            async with smb_machine_for(effective_config) as machine:
                yield machine
            return
        except (
            SMBAuthError,
            AttributeError,
            TypeError,
            KerberosSpnUnresolvedError,
        ) as exc:
            # SMBAuthError — auth rejected by the server.
            # AttributeError / TypeError — can occur when Kerberos auth URL
            # construction crashes with empty credentials (username="",
            # password="") because aiosmb expects a non-None principal.
            # KerberosSpnUnresolvedError — the target is an IP with no
            # resolvable FQDN, so cifs/<ip> cannot be requested. This is an
            # infrastructure-level Kerberos failure, not a credential rejection;
            # NTLM with the same credential is the correct fallback (the netexec
            # sweep that fed this host already authenticated over NTLM).
            # In all cases, fall back to NTLM when the plan allows it.
            has_nt_hash = bool(effective_config.nt_hash)
            if not plan.ntlm_fallback_allowed:
                raise
            is_soft = isinstance(exc, SMBAuthError) and _is_kerberos_soft_error(exc)
            if isinstance(exc, SMBAuthError) and not (
                _is_kerberos_infra_error(exc) or is_soft or has_nt_hash
            ):
                raise

            # Stale-DNS self-heal (centralized for EVERY SMB-backed path —
            # collector, sweeps, share-enum all flow through here): when the IP
            # has more than one enabled computer FQDN (a decommissioned name
            # sharing the IP with the live host, no reverse PTR), the KDC issues a
            # TGS the live host rejects (Kerberos AP/KDC error). Retry with the
            # next ranked live-first candidate FQDN for this IP BEFORE the NTLM
            # fallback (which is unavailable in NTLM-disabled domains). The
            # candidates come from the workspace inventory via the injected
            # resolver; with none registered this is a no-op.
            if isinstance(exc, SMBAuthError) and (
                _is_kerberos_infra_error(exc) or is_soft
            ):
                from adscan_internal.services._kerberos_spn_candidates import (
                    spn_candidates_for_ip,
                )

                current_spn = (effective_config.target_hostname or "").strip().lower()
                alternates = [
                    cand
                    for cand in spn_candidates_for_ip(
                        effective_config.target_ip, effective_config.domain
                    )
                    if "." in cand and cand.strip().lower() != current_spn
                ]
                for candidate in alternates[:3]:
                    print_info_debug(
                        "[smb_transport] Kerberos AP/KDC error on "
                        f"{effective_config.target_ip} with SPN host "
                        f"{current_spn!r}; retrying live candidate {candidate!r}"
                    )
                    alt_config = dataclasses.replace(
                        effective_config, target_hostname=candidate
                    )
                    try:
                        async with smb_machine_for(alt_config) as machine:
                            yield machine
                        return
                    except (
                        SMBAuthError,
                        KerberosSpnUnresolvedError,
                        AttributeError,
                        TypeError,
                    ):
                        continue  # try the next candidate, then NTLM

            reason = (
                "NT hash PTH fallback"
                if has_nt_hash
                else "soft error (e.g. key_expired)"
                if is_soft
                else "infra error"
            )
            print_info_debug(
                f"[smb_transport] Kerberos failed — retrying with NTLM ({reason},"
                f" {type(exc).__name__})"
            )
            ntlm_config = dataclasses.replace(effective_config, use_kerberos=False)
            async with smb_machine_for(ntlm_config) as machine:
                yield machine
            return

    # Conservative NTLM-first with Kerberos fallback (pre-PR10 behavior).
    try:
        async with smb_machine_for(effective_config) as machine:
            yield machine
    except SMBAuthError as exc:
        msg = str(exc).upper()
        ntlm_blocked = any(marker in msg for marker in _NTLM_BLOCKED_MARKERS)
        can_retry = bool(config.kdc_ip or config.domain)

        if not ntlm_blocked or not can_retry:
            raise

        print_info_debug("[smb_transport] NTLM auth failed — retrying with Kerberos")
        kerb_config = dataclasses.replace(effective_config, use_kerberos=True)
        async with smb_machine_for(kerb_config) as machine:
            # Kerberos succeeded after NTLM was rejected — that is the
            # strongest possible "NTLM disabled" signal: NTLM was attempted,
            # rejected, and the same credential worked over Kerberos. Single
            # emit, no duplicates.
            _emit_posture_signal(
                config,
                category=ConstraintCategory.NTLM_AUTHENTICATION,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="NTLM_REJECTED_VIA_SMB_KERBEROS_FALLBACK_OK",
                message=(
                    "NTLM rejected over SMB but Kerberos succeeded — NTLM "
                    "disabled by policy"
                ),
            )
            yield machine


# ---------------------------------------------------------------------------
# File download helper — centralises all aiosmb.SMBFile usage
# ---------------------------------------------------------------------------


async def download_admin_file_bytes(machine: Any, remote_win_path: str) -> bytes:
    """Download a file from the ADMIN$ share and return its raw bytes.

    ``remote_win_path`` must be a Windows-style absolute path such as
    ``\\Windows\\Temp\\foo.sav``.  The path is mapped to the ADMIN$ share
    (``\\ADMIN$\\Temp\\foo.sav``) so the caller must have admin access.

    The remote file is deleted after a successful read.  Deletion failures are
    logged at debug level and do not raise.

    Raises:
        SMBConnectionError: if the file cannot be opened or a read chunk fails.
    """
    from aiosmb.commons.interfaces.file import SMBFile

    # \\Windows\\Temp\\foo.sav  ->  \\ADMIN$\\Temp\\foo.sav
    stripped = remote_win_path.lstrip("\\")
    # Remove leading "Windows\" component (case-insensitive)
    if stripped.lower().startswith("windows\\"):
        stripped = stripped[len("windows\\") :]
    admin_path = f"\\ADMIN$\\{stripped}"

    print_info_debug(f"[smb-transport] downloading {admin_path}")
    smb_file = SMBFile.from_remotepath(machine.connection, admin_path)

    _, err = await smb_file.open(machine.connection, "r")
    if err is not None:
        raise SMBConnectionError(f"Cannot open remote file {admin_path}: {err}")

    buf = bytearray()
    async for chunk, err in smb_file.read_chunked():
        if err is not None:
            raise SMBConnectionError(f"Read error on {admin_path}: {err}")
        if not chunk:
            break
        buf.extend(chunk)

    try:
        await smb_file.close()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[smb-transport] close failed (ignored): {exc}")

    # Best-effort remote cleanup — surface failures visibly so the operator
    # knows a sensitive file was left on the target and can remove it manually.
    try:
        _, derr = await machine.del_file(admin_path)
        if derr is not None:
            from adscan_core.rich_output import print_warning as _pw
            _pw(
                f"Remote file not deleted: {admin_path}\n"
                f"  Remove it manually: del {remote_win_path}"
            )
            print_info_debug(f"[smb-transport] del_file error: {derr}")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        from adscan_core.rich_output import print_warning as _pw
        _pw(
            f"Remote file not deleted (exception): {admin_path}\n"
            f"  Remove it manually: del {remote_win_path}"
        )
        print_info_debug(f"[smb-transport] delete raised (ignored): {exc}")

    return bytes(buf)


# ---------------------------------------------------------------------------
# UNC file download helper — for arbitrary share paths
# ---------------------------------------------------------------------------


async def read_unc_file_bytes(
    machine: Any, remote_unc_path: str, *, max_bytes: int | None = None
) -> bytes:
    """Read a UNC file fully into memory and return its bytes.

    ``remote_unc_path`` must be a full UNC such as ``\\\\host\\C$\\Windows\\Temp\\foo``
    and its host must match ``machine``'s open connection. ``max_bytes`` caps the
    read (extra chunks are discarded once the cap is reached) to bound memory for
    untrusted/large files.

    Raises:
        SMBConnectionError: if the file cannot be opened or a chunk read fails.
    """
    from aiosmb.commons.interfaces.file import SMBFile

    smb_file = SMBFile.from_uncpath(remote_unc_path)
    _, err = await smb_file.open(machine.connection, "r")
    if err is not None:
        raise SMBConnectionError(f"Cannot open remote file {remote_unc_path}: {err}")

    buf = bytearray()
    try:
        async for chunk, cerr in smb_file.read_chunked():
            if cerr is not None:
                raise SMBConnectionError(f"Read error on {remote_unc_path}: {cerr}")
            if not chunk:
                break
            buf.extend(chunk)
            if max_bytes is not None and len(buf) >= max_bytes:
                del buf[max_bytes:]
                break
    finally:
        try:
            await smb_file.close()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[smb-transport] close failed (ignored): {exc}")

    return bytes(buf)


async def download_unc_file_to_local(
    machine: Any, remote_unc_path: str, local_path: str
) -> int:
    """Download a file from any UNC path to ``local_path``. Returns bytes written.

    ``remote_unc_path`` must be a full UNC such as ``\\\\host\\C$\\Windows\\Temp\\foo``.

    Raises:
        SMBConnectionError: if the file cannot be opened or a chunk read fails.
    """
    from pathlib import Path as _Path

    data = await read_unc_file_bytes(machine, remote_unc_path)
    _Path(local_path).parent.mkdir(parents=True, exist_ok=True)
    _Path(local_path).write_bytes(data)
    return len(data)


# ---------------------------------------------------------------------------
# UNC file upload / delete / directory helpers — for SYSVOL writes
# ---------------------------------------------------------------------------


async def upload_unc_file_from_local(
    machine: Any, remote_unc_path: str, local_path: str
) -> int:
    """Upload a local file to ``remote_unc_path`` (full UNC). Returns bytes written.

    ``remote_unc_path`` must be a full UNC such as
    ``\\\\rodc01.example.local\\C$\\Windows\\Temp\\foo.exe``.

    Streams the local file in chunks to avoid loading large binaries into
    memory.  Bypasses ``aiosmb`` ``machine.put_file`` because that helper
    feeds the path through ``SMBFile.from_remotepath``, which expects a
    *share-relative* path (e.g. ``\\C$\\Temp\\foo``).  Passing a full UNC
    there causes a double-prefix and a malformed tree-connect path that
    the server rejects with ``STATUS_INVALID_PARAMETER``.

    Raises:
        SMBConnectionError: if the file cannot be opened or any chunk
            write fails.
    """
    from aiosmb.commons.interfaces.file import SMBFile

    smb_file = SMBFile.from_uncpath(remote_unc_path)
    _, err = await smb_file.open(machine.connection, "w")
    if err is not None:
        raise SMBConnectionError(f"Cannot open remote file {remote_unc_path}: {err}")

    try:
        with open(local_path, "rb") as fh:
            written, werr = await smb_file.write_buffer(fh)
            if werr is not None:
                raise SMBConnectionError(
                    f"Write error on {remote_unc_path}: {werr}"
                )
        try:
            await smb_file.flush()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[smb-transport] flush failed (ignored): {exc}")
        return int(written or 0)
    finally:
        try:
            await smb_file.close()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[smb-transport] close failed (ignored): {exc}")


async def upload_unc_file_bytes(machine: Any, remote_unc_path: str, data: bytes) -> int:
    """Upload ``data`` to ``remote_unc_path`` (full UNC) and return bytes written.

    ``remote_unc_path`` must be a full UNC such as
    ``\\\\dc01.example.local\\SYSVOL\\example.local\\Policies\\{GUID}\\foo.xml``.

    The remote file is created if it does not exist and overwritten if it does
    (aiosmb open mode ``"w"`` maps to ``FILE_OPEN_IF`` with GENERIC_READ |
    GENERIC_WRITE — verified at vendor/aiosmb/aiosmb/commons/interfaces/file.py:341).

    Caller is responsible for registering the corresponding ledger entry
    BEFORE invoking this primitive (write-ahead audit).

    Raises:
        SMBConnectionError: if the file cannot be opened or any chunk write fails.
    """
    from aiosmb.commons.interfaces.file import SMBFile

    smb_file = SMBFile.from_uncpath(remote_unc_path)
    _, err = await smb_file.open(machine.connection, "w")
    if err is not None:
        raise SMBConnectionError(f"Cannot open remote file {remote_unc_path}: {err}")

    try:
        written, werr = await smb_file.write(bytes(data))
        if werr is not None:
            raise SMBConnectionError(f"Write error on {remote_unc_path}: {werr}")
        # Best-effort flush to make the bytes visible to subsequent reads.
        try:
            await smb_file.flush()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[smb-transport] flush failed (ignored): {exc}")
        return int(written or 0)
    finally:
        try:
            await smb_file.close()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(f"[smb-transport] close failed (ignored): {exc}")


async def delete_unc_file(machine: Any, remote_unc_path: str) -> None:
    """Delete the file at ``remote_unc_path`` (full UNC). Raises on failure.

    Mirrors the cleanup pattern used by :func:`download_admin_file_bytes` but
    promotes failure to an exception (vs. silent debug log) — callers in the
    GPO rollback path need to know whether deletion actually happened in order
    to update the ledger correctly.
    """
    from aiosmb.commons.interfaces.file import SMBFile

    # SMBFile.delete_unc(connection, remotepath) is the canonical helper —
    # verified at vendor/aiosmb/aiosmb/commons/interfaces/file.py:115.
    _, err = await SMBFile.delete_unc(machine.connection, remote_unc_path)
    if err is not None:
        raise SMBConnectionError(f"Cannot delete remote file {remote_unc_path}: {err}")


async def create_unc_directory(machine: Any, remote_unc_path: str) -> None:
    """Create a directory at ``remote_unc_path`` (full UNC). Raises on failure.

    Replicates the create-directory body from
    ``vendor/aiosmb/aiosmb/commons/interfaces/directory.py:115`` (``create_remote``)
    against a UNC path — the upstream helper accepts a per-host remotepath
    rather than a UNC, which would double the host segment when given a UNC.
    Uses ``CreateDisposition.FILE_CREATE``: fails if the directory already
    exists. Callers should treat ``OBJECT_NAME_COLLISION`` as already-present.
    """
    from aiosmb.commons.interfaces.directory import SMBDirectory
    from aiosmb.protocol.smb2.commands.create import (
        CreateDisposition,
        CreateOptions,
        ShareAccess,
    )
    from aiosmb.wintypes.access_mask import FileAccessMask

    remfile = SMBDirectory.from_uncpath(remote_unc_path)
    tree_entry, err = await machine.connection.tree_connect(remfile.share_path)
    if err is not None:
        raise SMBConnectionError(f"tree_connect failed for {remfile.share_path}: {err}")
    tree_id = tree_entry.tree_id

    desired_access = (
        FileAccessMask.FILE_READ_DATA
        | FileAccessMask.FILE_WRITE_DATA
        | FileAccessMask.FILE_READ_EA
        | FileAccessMask.FILE_WRITE_EA
        | FileAccessMask.FILE_READ_ATTRIBUTES
        | FileAccessMask.FILE_WRITE_ATTRIBUTES
        | FileAccessMask.READ_CONTROL
        | FileAccessMask.DELETE
        | FileAccessMask.SYNCHRONIZE
    )
    share_mode = (
        ShareAccess.FILE_SHARE_READ
        | ShareAccess.FILE_SHARE_WRITE
        | ShareAccess.FILE_SHARE_DELETE
    )
    create_options = (
        CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
    )
    create_disposition = CreateDisposition.FILE_CREATE
    file_attrs = 0

    try:
        file_id, cerr = await machine.connection.create(
            tree_id,
            remfile.fullpath,
            desired_access,
            share_mode,
            create_options,
            create_disposition,
            file_attrs,
            return_reply=False,
        )
        if cerr is not None:
            raise SMBConnectionError(
                f"create directory {remote_unc_path} failed: {cerr}"
            )
        if file_id is not None:
            try:
                await machine.connection.close(tree_id, file_id)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[smb-transport] close after mkdir failed (ignored): {exc}"
                )
    finally:
        try:
            await machine.connection.tree_disconnect(tree_id)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[smb-transport] tree_disconnect after mkdir failed (ignored): {exc}"
            )


async def delete_unc_directory(machine: Any, remote_unc_path: str) -> None:
    """Delete a (typically empty) directory at ``remote_unc_path`` (full UNC).

    Wraps :meth:`SMBDirectory.delete_unc` (verified at
    vendor/aiosmb/aiosmb/commons/interfaces/directory.py:86). Raises on failure
    so rollback callers can mark the ledger entry appropriately.
    """
    from aiosmb.commons.interfaces.directory import SMBDirectory

    _, err = await SMBDirectory.delete_unc(machine.connection, remote_unc_path)
    if err is not None:
        raise SMBConnectionError(
            f"Cannot delete remote directory {remote_unc_path}: {err}"
        )


# ---------------------------------------------------------------------------
# Local Administrators group enumeration via SAMR
# ---------------------------------------------------------------------------


async def get_local_admin_rids(machine: Any) -> set[int]:
    """Return the set of local-account RIDs that are members of BUILTIN\\Administrators.

    Thin backward-compatible wrapper around
    :func:`adscan_internal.services.native_samr_service.get_local_admin_rids_via` —
    the consolidated SAMR home. Always returns at least ``{500}``. Never
    raises; failures are silently swallowed and ``{500}`` is the fallback.
    """
    from adscan_internal.services.native_samr_service import get_local_admin_rids_via

    rids, _status, _err = await get_local_admin_rids_via(
        machine, include_well_known=True
    )
    return rids


# ---------------------------------------------------------------------------
# Sync bridge — for sync callers in the service layer
# ---------------------------------------------------------------------------


def run_smb_operation(coro: Any) -> Any:
    """Run one aiosmb coroutine from a synchronous call site.

    This is an escape hatch for legacy sync callers.  New code should be
    written async-first.
    """
    return run_async_sync(coro)


# ---------------------------------------------------------------------------
# PDC host resolution — replaces resolve_bloody_host from integrations/bloody
# ---------------------------------------------------------------------------


def resolve_pdc_host(
    *,
    pdc_ip: str | None,
    pdc_hostname: str | None,
    domain: str | None,
    kerberos: bool,
) -> str | None:
    """Resolve the best host string for connecting to a PDC.

    Prefers FQDN for Kerberos auth (SPN matching); falls back to short
    hostname or IP. Replaces ``resolve_bloody_host`` from the legacy
    ``integrations/bloody`` module.
    """
    import ipaddress as _ipaddress

    hostname = (pdc_hostname or "").strip()
    if kerberos and hostname:
        if "." in hostname:
            return hostname
        if domain:
            return f"{hostname}.{domain}"
        return hostname

    if hostname:
        return hostname

    if pdc_ip:
        try:
            _ipaddress.ip_address(pdc_ip)
        except ValueError:
            pass
        return pdc_ip

    return None
