"""Shared LDAP transport helpers with LDAPS->LDAP fallback.

This module centralizes the transport policy for LDAP-backed domain collectors.
ADscan still relies heavily on CLI tooling, but for the smaller set of
domain-scope collectors implemented in Python we want a single place that
decides:

- how CertiHound-style LDAP connections are opened
- when an LDAPS failure should trigger an LDAP retry
- how those retries are logged consistently
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import os
import re
import urllib.parse
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    log_exception_debug,
    mark_sensitive,
    print_info_debug,
    print_warning_debug,
)
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    DomainPosture,
    SignalConfidence,
    TriState,
    PostureSignal,
)
from adscan_internal.services.posture_sink import (  # noqa: F401  (re-exported)
    PostureSink,
    make_workspace_posture_sink,
)

# Activate centralised Kerberos recovery (TKT_EXPIRED/NYV/TGT_REVOKED → auto
# refresh TGT & retry). See _kerberos_recovery for details.
from adscan_internal.services import _kerberos_recovery  # noqa: F401
from adscan_internal.services.auth_error_classification import (
    exception_chain_text,
    is_native_kerberos_infra_error,
    is_unreachable_foreign_realm_error,
)
from adscan_internal.services.async_bridge import run_async_sync, run_sync_off_loop


SD_FLAGS_DACL_CONTROL: str = "sd_flags_dacl"
"""Sentinel passed to ADscanLDAPConnection.search(controls=...) to request nTSecurityDescriptor."""

SD_FLAGS_OWNER_CONTROL: str = "sd_flags_owner"
"""Sentinel passed to ADscanLDAPConnection.search/modify to request owner nTSecurityDescriptor."""

SD_FLAGS_ALL_CONTROL: str = "sd_flags_all"
"""Sentinel requesting OWNER+GROUP+DACL (flags=7) so AD computes allowedAttributesEffective."""

_SD_FLAGS_DACL_CONTROL_VALUE: int = 0x04  # DACL only
_SD_FLAGS_OWNER_CONTROL_VALUE: int = 0x01  # Owner only
_SD_FLAGS_ALL_CONTROL_VALUE: int = 0x07  # OWNER + GROUP + DACL


@dataclass
class _LDAPAttrProxy:
    """Minimal attribute proxy exposing .value for ldap3-compatible callsites."""

    value: Any
    raw_value: bytes | None = None


@dataclass
class LDAPEntry:
    """Backend-agnostic LDAP entry returned by ADscanLDAPConnection.search().

    Exposes three access patterns used across ADscan services:
    - entry_attributes_as_dict  → dict[str, list[Any]] (decoded strings or raw bytes)
    - entry_raw_attributes       → dict[str, list[bytes]]
    - entry["attrName"].value    → first decoded value (ldap3-compatible)
    """

    dn: str
    _raw_attrs: dict[str, list[Any]] = field(default_factory=dict)

    @property
    def entry_attributes_as_dict(self) -> dict[str, list[Any]]:
        result: dict[str, list[Any]] = {}
        for name, raw_list in self._raw_attrs.items():
            decoded: list[Any] = []
            for val in raw_list:
                if not isinstance(val, bytes):
                    decoded.append(val)
                    continue
                try:
                    decoded.append(val.decode("utf-8"))
                except (UnicodeDecodeError, AttributeError):
                    decoded.append(val)
            result[name] = decoded
        return result

    @property
    def entry_raw_attributes(self) -> dict[str, list[bytes]]:
        return self._raw_attrs

    def __getitem__(self, attr_name: str) -> _LDAPAttrProxy:
        raw_list = self._raw_attrs.get(attr_name, [])
        if not raw_list:
            return _LDAPAttrProxy(value=None, raw_value=None)
        raw = raw_list[0]
        if not isinstance(raw, bytes):
            return _LDAPAttrProxy(value=raw, raw_value=None)
        try:
            return _LDAPAttrProxy(value=raw.decode("utf-8"), raw_value=raw)
        except UnicodeDecodeError:
            return _LDAPAttrProxy(value=None, raw_value=raw)


@dataclass
class ADscanLDAPConfig:
    """LDAP connection config for ADscanLDAPConnection.

    For cross-domain scenarios (e.g. ping.htb creds → pong.htb LDAP):
    - ``domain`` / ``dc_ip`` describe the *target* domain and DC
    - ``auth_domain`` / ``auth_kdc`` describe the *credentials* domain and its KDC

    Without ``auth_domain``/``auth_kdc``, Kerberos AS-REQ is sent to the target DC,
    which fails when the user account lives in a different domain.

    Restrictive-AD fields (all optional, default to safe no-op values):
    - ``aes_key``: AES-128 (32 hex chars) or AES-256 (64 hex chars) Kerberos session key.
      Used in AES-only domains where RC4 is blocked by GPO. When set, ``use_kerberos``
      must also be True. The URL scheme becomes ``kerberos-aes``.
    - ``etypes``: explicit Kerberos encryption type list (e.g. [18, 17] for AES-256/128 only).
      Passed to badldap via ``etype`` URL query params. Requires ``use_kerberos=True``.
    - ``channel_binding``: request LDAPS channel binding tokens (CBT). Required in
      environments with ``LdapEnforceChannelBinding=2`` GPO. badldap ≥0.7.5 negotiates
      CBT automatically on LDAPS; this field is reserved for explicit opt-in once
      badldap exposes a URL param for it.
    - ``sign``: request LDAP signing (integrity protection). Required when the
      ``LDAPServerIntegrity`` GPO is set to 2. badldap exposes ``_disable_signing``
      on ``MSLDAPClient``; this field wires the inverse.
    - ``encrypt``: request LDAP encryption (confidentiality). Only valid for plain
      LDAP (not LDAPS). badldap exposes this via ``encrypt`` URL query param.
    - ``tls_sni``: explicit TLS SNI hostname for LDAPS connections. When set,
      used as the URL host instead of ``dc_ip``, so the TLS handshake presents the
      correct hostname for certificate validation. Prevents LDAPS failures in
      environments with strict hostname-verifying certs.
    - ``ccache_path``: explicit ccache file path for ``kerberos-ccache`` auth. Takes
      priority over the ``KRB5CCNAME`` environment variable. Use this for programmatic
      flows where the ccache was minted by ``KerberosTicketService`` at a known path.
    - ``paged_size``: LDAP paged-search page size passed to badldap via the
      ``pagesize`` URL param. Max 1000 (badldap enforces this). Default 1000.
    - ``require_confidential``: the operation reads (or writes) a CONFIDENTIAL
      directory attribute (e.g. ``msDS-ManagedPassword`` for gMSA). AD only
      returns such attributes over a SEALED channel — LDAPS (TLS) or plain LDAP
      with GSS-API confidentiality (sign+seal) negotiated. When True the
      LDAPS->LDAP fallback MUST NOT downgrade to an unsealed plain-LDAP channel:
      the plain-LDAP attempt is forced to negotiate sign+seal (``sign=True``, so
      badauth requests ``ISC_REQ.CONFIDENTIALITY`` and badldap wraps every
      message), and any transport that cannot guarantee confidentiality
      (anonymous / SIMPLE bind, which negotiates no GSS context) is skipped.
      When no sealed channel can be established the connect raises
      :class:`ConfidentialChannelUnavailableError` with an actionable message
      instead of letting the DC reject the attribute with the cryptic
      ``operationsError / ERROR_DS_CONFIDENTIALITY_REQUIRED``. Default False, so
      every non-confidential operation keeps the transparent LDAPS->LDAP
      downgrade unchanged.
    """

    domain: str
    dc_ip: str
    use_ldaps: bool
    use_kerberos: bool
    username: str | None = None
    password: str | None = None
    kerberos_target_hostname: str | None = None
    auth_domain: str | None = None
    auth_kdc: str | None = None
    # Restrictive-AD fields — all optional, safe defaults
    aes_key: str | None = None
    etypes: list[int] | None = None
    channel_binding: bool = False
    null_channel_binding: bool = False
    """When True, badldap sends a CBT field populated with a deliberately
    invalid token instead of either the real one or no field at all.
    Used by the CBT posture probe's "When Supported" disambiguation step
    (after a no-CBT bind got ``STATUS_LOGON_FAILURE``, a wrong-CBT bind
    that gets ``SEC_E_BAD_BINDINGS`` proves the DC validates CBT only
    when present — i.e. the "When Supported" GPO value).

    Has no operational use outside posture probing. Defaults to False
    so it never accidentally trips real consumers.
    """
    disable_self_heal: bool = False
    """When True, the transport will NOT retry with a healed config on
    a posture-recoverable failure (CBT mismatch, signing required). The
    caller wants the raw failure to propagate so it can classify it.

    Set by callers whose purpose is to ELICIT specific failures and
    classify them — the posture probes are the canonical example. A
    probe that tests "does the DC enforce CBT?" needs the
    ``SEC_E_BAD_BINDINGS`` to bubble up; if the transport silently
    retries with CBT=True and the bind succeeds, the probe thinks CBT
    is not required, falsifying the posture. Same logic for the LDAP
    signing probe and any future failure-eliciting consumer.

    Default is ``False`` — operational consumers (collector, kerberoast,
    ADCS enum, etc.) WANT self-heal because the operation goal is to
    succeed, not to characterise the failure.
    """
    sign: bool = False
    encrypt: bool = False
    tls_sni: str | None = None
    ccache_path: str | None = None
    paged_size: int = 1000
    require_confidential: bool = False
    use_starttls: bool = False
    """Request an RFC 2830 StartTLS upgrade on a plain LDAP/389 connection.

    When ``True`` (and ``use_ldaps`` is ``False``) the transport tells
    badldap to wrap the TCP/389 session in TLS BEFORE binding, so the bind
    and every query travel encrypted without needing port 636 or channel
    binding. Set internally by :func:`async_connect_with_ldap_fallback`
    when it inserts the StartTLS rung into the confidentiality ladder; not
    intended to be set directly by most callers (the ladder manages it).
    A refused StartTLS (no DC cert / unsupported) makes the ladder fall
    through to the SASL sign+seal rung."""
    disable_default_seal: bool = False
    """Opt out of the seal-by-default policy for authenticated plain-LDAP/389.

    By default (``False``) every AUTHENTICATED, GSS-capable bind (Kerberos or
    NTLM-with-creds) that lands on plain LDAP/389 -- because LDAPS/636 is
    unavailable -- negotiates GSS-API sign+seal (``sign`` is forced to
    ``True``) so the bind, queries, and results are encrypted on the wire
    rather than sent in cleartext. This is an OPSEC + confidentiality default:
    passive sniffing of an unsealed 389 channel would otherwise expose every
    LDAP query and result in sensitive internal AD environments.

    Set this to ``True`` only when a caller deliberately needs the legacy
    cleartext plain-LDAP behaviour (e.g. interoperating with a non-Windows
    LDAP server that cannot negotiate GSS sealing where the seal-failure
    auto-degrade below is not wanted). It does NOT affect:

    - LDAPS/636 -- TLS already provides confidentiality (``sign`` is a no-op).
    - Anonymous / SIMPLE binds -- they establish no GSS context and cannot
      seal regardless of this flag; they stay cleartext (unavoidable).
    - Callers that explicitly set ``sign=True`` -- already sealed.

    The seal-by-default upgrade also degrades gracefully: if a default-sealed
    plain-LDAP bind fails specifically because sealing could not be negotiated
    (a non-Windows/legacy DC), the transport retries once unsealed with a
    debug note -- an auth/credential failure is NOT treated as a seal failure
    and propagates unchanged."""
    _default_seal_applied: bool = field(default=False, repr=False)
    """Private marker set by :func:`_apply_default_seal_to_plain_ldap` when it
    upgrades an authenticated plain-LDAP attempt to sign+seal as the OPSEC
    DEFAULT (not caller intent). The fallback loop reads it to know a
    seal-negotiation failure on that attempt may be degraded back to unsealed
    exactly once. Never set by callers; not part of the public config surface."""
    use_simple_bind: bool = False
    """Force RFC 4513 SIMPLE bind. Anonymous SIMPLE (empty creds) yields
    the ``ldap+simple://`` URL form which leaves the connection in RUNNING
    state after bind — required for ``pagedsearch`` against hardened DCs."""

    credential_context: Any = None
    """Optional :class:`CredentialContext` driving PAC-freshness refresh.

    When set, ``async_connect_with_ldap_fallback`` calls
    ``await credential_context.refresh_if_stale(registry)`` immediately before
    each connect attempt.  If the registry has invalidated the bound principal
    since the last bind (e.g. an AddMember step ran), the context re-issues
    the TGT through ``KerberosTicketService`` and the bind uses the fresh
    ccache — fixing the classic ``insufficientAccessRights`` after a
    successful privilege grant.  When ``None``, the legacy ``ccache_path`` /
    ``KRB5CCNAME`` path is used unchanged (no refresh)."""

    posture_sink: "PostureSink | None" = None
    """Optional callable invoked when this transport observes a domain-wide
    LDAP posture signal (LDAPS unreachable, LDAP signing required, channel
    binding required, NTLM rejected via LDAP, etc.). Receives one
    :class:`PostureSignal` and may return an :class:`IntelligenceFinding`
    for the caller to surface to the user. When ``None`` (default), posture
    signals are silently dropped — the transport remains a pure protocol
    module with no workspace coupling. See PR2 (``KerberosConfig.posture_sink``)
    for the matching pattern in the Kerberos transport."""

    posture_snapshot: "DomainPosture | None" = None
    """Optional immutable snapshot of the domain's posture at config-construction
    time. When set, the LDAP fallback uses
    :func:`adscan_internal.services.auth_plan.build_ldap_auth_plan` to drive a
    posture-aware attempt sequence. When ``None`` (default), the conservative
    full retry chain is used — byte-identical to the legacy speculative loop."""

    def __post_init__(self) -> None:
        # Promote short Kerberos target hostnames to FQDN. Centralised here so
        # every call site is fixed at once — see services/_kerberos_spn.py.
        from adscan_internal.services._kerberos_spn import (
            is_ip_address,
            normalize_kerberos_target_hostname,
        )

        if self.use_kerberos and not self.kerberos_target_hostname and self.dc_ip:
            dc_candidate = str(self.dc_ip or "").strip()
            if dc_candidate and not is_ip_address(dc_candidate):
                self.kerberos_target_hostname = dc_candidate
        self.kerberos_target_hostname = normalize_kerberos_target_hostname(
            self.kerberos_target_hostname, self.domain
        )

        # Promote bare KDC addresses to FQDN so Kerberos realm detection
        # works correctly.  IPs pass through unchanged; FQDNs pass through
        # unchanged; bare labels like "dc01" → "dc01.garfield.htb".
        # Without this, callers that read pdc_hostname instead of resolve_dc_ip
        # silently get KDC_ERR_WRONG_REALM.
        self.dc_ip = (
            normalize_kerberos_target_hostname(self.dc_ip, self.domain)
            or self.dc_ip
        )
        if self.auth_kdc:
            # auth_kdc belongs to the auth domain; use auth_domain when set,
            # fall back to target domain for single-realm environments.
            auth_realm = str(self.auth_domain or self.domain or "").strip()
            self.auth_kdc = (
                normalize_kerberos_target_hostname(self.auth_kdc, auth_realm)
                or self.auth_kdc
            )

        # Note: ADscanLDAPConfig intentionally does NOT have a separate
        # ``nt_hash`` field. Pass-the-hash via LDAP works by placing the hash
        # in ``password`` and letting ``_build_ldap_connection_url`` detect
        # the format with ``_is_nt_hash`` and emit the
        # ``ldap+kerberos-rc4://`` (or ``ldap+ntlm-nt://``) URL scheme. Do
        # NOT clear the password here — it would silently break LDAP PtH.

    @property
    def domain_dn(self) -> str:
        labels = [p.strip() for p in str(self.domain or "").split(".") if p.strip()]
        return ",".join(f"DC={label}" for label in labels)

    @property
    def config_dn(self) -> str:
        return f"CN=Configuration,{self.domain_dn}"


_LDAP_SCOPE_MAP: dict[Any, int] = {
    "BASE": 0,
    "ONELEVEL": 1,
    "SUBTREE": 2,
    0: 0,
    1: 1,
    2: 2,
}


def _load_badldap_modules() -> dict[str, Any]:
    """Load badldap modules from installed runtime dependencies.

    Only badldap is supported. The msldap fallback was removed because msldap
    is not installed in the runtime image (only badldap==0.7.5 is present) and
    the silent fallback masked real import errors. If badldap fails to import,
    the exception propagates with a clear RuntimeError.
    """
    try:
        from badldap.client import MSLDAPClient
        from badldap.commons.factory import LDAPConnectionFactory
        from badldap.protocol.constants import BASE, LEVEL
        from badldap.wintypes.asn1.sdflagsrequest import (
            SDFlagsRequest,
            SDFlagsRequestValue,
        )

        return {
            "backend": "badldap",
            "MSLDAPClient": MSLDAPClient,
            "LDAPConnectionFactory": LDAPConnectionFactory,
            "BASE": BASE,
            "LEVEL": LEVEL,
            "SDFlagsRequest": SDFlagsRequest,
            "SDFlagsRequestValue": SDFlagsRequestValue,
        }
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"Failed to import badldap backend. "
            f"Ensure badldap>=0.7.5 is installed in the runtime venv. "
            f"Cause: {type(exc).__name__}: {exc}"
        ) from exc


def _build_sd_flags_control(flags: int) -> list[Any]:
    """Return an SD_FLAGS control tuple list compatible with badldap."""
    modules = _load_badldap_modules()
    request_value = modules["SDFlagsRequestValue"]({"Flags": flags})
    return [("1.2.840.113556.1.4.801", True, request_value.dump())]


# LDAP_SERVER_SHOW_DELETED_OID — required to enumerate/modify tombstoned objects in
# CN=Deleted Objects (a normal search never returns them).
SHOW_DELETED_CONTROL_OID: str = "1.2.840.113556.1.4.417"


def build_show_deleted_controls(with_sd_flags: bool = True) -> list[Any]:
    """Controls for enumerating tombstones (AD Recycle Bin discovery).

    Combines the Show Deleted Objects control with (optionally) SD_FLAGS_ALL so the
    DC computes ``allowedAttributesEffective`` / ``sDRightsEffective`` on each
    deleted object — i.e. what the authenticated principal can write (and therefore
    whether it can reanimate the tombstone). Returned as a raw control-tuple list,
    which the search path passes straight through to badldap.
    """
    controls: list[Any] = []
    if with_sd_flags:
        controls.extend(_build_sd_flags_control(_SD_FLAGS_ALL_CONTROL_VALUE))
    controls.append((SHOW_DELETED_CONTROL_OID, True, None))
    return controls


def _resolve_sd_flags_control(controls: Any) -> Any:
    """Translate ADscan SD flag sentinels to badldap control tuples."""
    if controls == SD_FLAGS_DACL_CONTROL:
        return _build_sd_flags_control(_SD_FLAGS_DACL_CONTROL_VALUE)
    if controls == SD_FLAGS_OWNER_CONTROL:
        return _build_sd_flags_control(_SD_FLAGS_OWNER_CONTROL_VALUE)
    if controls == SD_FLAGS_ALL_CONTROL:
        return _build_sd_flags_control(_SD_FLAGS_ALL_CONTROL_VALUE)
    return controls


def _resolve_modify_controls(controls: Any) -> Any:
    """Translate ADscan controls to badldap modify control dictionaries."""
    resolved = _resolve_sd_flags_control(controls)
    if isinstance(resolved, list):
        converted = []
        for control in resolved:
            if isinstance(control, tuple) and len(control) == 3:
                converted.append(
                    {
                        "controlType": str(control[0]).encode(),
                        "criticality": control[1],
                        "controlValue": control[2],
                    }
                )
            else:
                converted.append(control)
        return converted
    return resolved


def _quote_url_component(value: str) -> str:
    """URL-encode one LDAP URL component."""
    return urllib.parse.quote(str(value or ""), safe="")


def _is_nt_hash(value: str) -> bool:
    """Return True if value looks like a 32-hex NT hash."""
    return len(value) == 32 and all(c in "0123456789abcdef" for c in value.lower())


def _build_ldap_connection_url(config: "ADscanLDAPConfig") -> tuple[str, bool]:
    """Build a badldap connection URL for one ADscan config.

    URL scheme reference (from badldap/commons/factory.py help_epilog):
        ldap+ntlm-password://DOMAIN\\user:password@host
        ldap+ntlm-nt://DOMAIN\\user:<nthash>@host
        ldap+kerberos-password://DOMAIN\\user:password@host/?dc=<kdc_ip>
        ldap+kerberos-rc4://DOMAIN\\user:<nthash>@host/?dc=<kdc_ip>   ← NT hash Kerberos
        ldap+kerberos-aes://DOMAIN\\user:<aeskey>@host/?dc=<kdc_ip>   ← AES key Kerberos
        ldap+kerberos-ccache://DOMAIN\\user:<ccache_path>@host/?dc=<kdc_ip>  ← ccache
        ldap://host  (anonymous)

    The URL transport prefix (ldap vs ldaps) is controlled by config.use_ldaps.
    The host used for the URL (and therefore TLS SNI on LDAPS) is config.tls_sni
    when set, otherwise config.kerberos_target_hostname or config.dc_ip.

    Returns:
        Tuple of (url, requires_cross_target). requires_cross_target is True when
        auth_domain differs from target domain — caller must use get_client_newtarget.
    """
    transport = "ldaps" if config.use_ldaps else "ldap"

    # For LDAPS TLS: prefer tls_sni (explicit hostname) → kerberos_target_hostname → dc_ip.
    # Using dc_ip as the URL host causes TLS SNI to present an IP address which
    # will fail certificate validation in strict environments.
    if config.use_kerberos:
        from adscan_internal.services._kerberos_spn import (
            require_kerberos_target_hostname,
        )

        url_host = require_kerberos_target_hostname(
            config.tls_sni or config.kerberos_target_hostname,
            protocol="LDAP",
        )
    else:
        url_host = str(
            config.tls_sni or config.kerberos_target_hostname or config.dc_ip or ""
        ).strip()
    if not url_host:
        raise ValueError("LDAP connection requires a DC address or target hostname.")

    auth_domain = str(config.auth_domain or config.domain or "").strip()
    username = str(config.username or "").strip()
    password = str(config.password or "")

    # ---- Kerberos branch ----
    if config.use_kerberos:
        params: list[str] = []

        # dc= is mandatory for Kerberos in badldap — the KDC address.
        kdc_host = str(config.auth_kdc or config.dc_ip or "").strip()
        # Defensive: __post_init__ should have promoted bare hostnames already.
        if kdc_host and "." not in kdc_host:
            from adscan_internal.services._kerberos_spn import is_ip_address
            if not is_ip_address(kdc_host):
                print_info_debug(
                    f"[ldap_transport] bare hostname {kdc_host!r} reached URL builder as KDC — "
                    "expected FQDN or IP (was ADscanLDAPConfig.__post_init__ bypassed?); "
                    f"domain={config.domain!r}"
                )
        if kdc_host:
            params.append(f"dc={_quote_url_component(kdc_host)}")

        # pagesize URL param (badldap enforces max 1000).
        if config.paged_size and config.paged_size != 1000:
            params.append(f"pagesize={min(int(config.paged_size), 1000)}")

        # etypes → repeated etype= params (badldap parses via int_list).
        if config.etypes:
            for etype in config.etypes:
                params.append(f"etype={int(etype)}")

        # encrypt= URL param — only valid for plain LDAP, not LDAPS.
        if config.encrypt and not config.use_ldaps:
            params.append("encrypt=true")

        username_part = (
            f"{_quote_url_component(auth_domain)}\\{_quote_url_component(username)}"
            if username
            else ""
        )

        # Determine auth scheme and secret component. Priority chain
        # — explicit caller intent ALWAYS beats ambient process state:
        #
        #   1. config.ccache_path → kerberos-ccache; secret = ccache path.
        #      Caller explicitly opted into ccache-based auth.
        #   2. config.aes_key → kerberos-aes; secret = AES hex key.
        #      Caller has the AES key material.
        #   3. NT hash (32 hex chars) → kerberos-rc4; secret = NT hash.
        #      Caller has the NT hash (overpass-the-hash).
        #   4. plaintext password → kerberos-password; fresh AS-REQ.
        #      Caller has the cleartext password.
        #   5. KRB5CCNAME env var (LAST resort) → kerberos-ccache.
        #      No explicit credential material at all — only then fall
        #      back to the global Kerberos state.
        #
        # *** Why KRB5CCNAME comes LAST, not first as it used to ***
        #
        # The previous order put ``KRB5CCNAME`` in slot #1 (it was OR'd
        # with ``config.ccache_path`` into a single ``ccache_value``).
        # When a caller passed an explicit ``username + password`` for a
        # FRESH AS-REQ as a specific user but did NOT pass an explicit
        # ``ccache_path``, the LDAP transport silently used whatever TGT
        # was sitting in ``KRB5CCNAME`` from a prior operation. The bind
        # succeeded as the WRONG principal (the one in the env ccache)
        # and the password the caller had explicitly provided was
        # ignored. Symptoms: read succeeds, write fails with
        # ``insufficientAccessRights`` because the principal in the
        # ambient ccache lacks the rights the caller's principal has.
        #
        # Real-world incident (2026-05-21, HTB Puppy): post-spraying
        # ``enable_user`` ran with ``username='ant.edwards'``,
        # ``password='Antman2025!'``, ``ccache=None``. ``KRB5CCNAME``
        # still pointed at LEVI.JAMES's ccache from the initial bind.
        # The LDAP modify was performed as LEVI.JAMES — who does not
        # have GenericAll over adam.silver — and the DC rejected it.
        # bloodyAD invoked with the same explicit creds worked because
        # it uses ``ldap+ntlm-pw://`` and never consults ``KRB5CCNAME``.
        #
        # The new order honours caller intent: if you passed creds, we
        # use those creds. KRB5CCNAME only acts when nothing else is
        # available — preserving legacy behaviour for callers that
        # really do rely on the global Kerberos state.

        explicit_ccache = str(config.ccache_path or "").strip()

        if explicit_ccache:
            # Slot 1: caller explicitly passed ccache_path.
            auth_kind = "kerberos-ccache"
            secret_part = _quote_url_component(explicit_ccache)
        elif config.aes_key:
            # Slot 2: AES key (AS-REQ with AES session key).
            auth_kind = "kerberos-aes"
            secret_part = _quote_url_component(config.aes_key.strip())
        elif password and _is_nt_hash(password):
            # Slot 3: NT hash (overpass-the-hash). badauth maps
            # asyauthSecret.NT → asyauthSecret.RC4 internally.
            auth_kind = "kerberos-rc4"
            secret_part = _quote_url_component(password)
        elif password:
            # Slot 4: plaintext password → fresh AS-REQ.
            auth_kind = "kerberos-password"
            secret_part = _quote_url_component(password)
        else:
            # Slot 5: legacy KRB5CCNAME fallback (no explicit creds).
            env_ccache = str(os.environ.get("KRB5CCNAME") or "").strip()
            if env_ccache:
                print_info_debug(
                    "[kerberos-auth] no explicit credentials in config; "
                    f"falling back to KRB5CCNAME ccache "
                    f"{mark_sensitive(env_ccache, 'path')!r}. Callers that "
                    "want a specific principal must pass ccache_path or "
                    "username+password explicitly."
                )
                # Read-only principal guard: warn + record telemetry if the
                # ambient ccache authenticates as a principal other than the
                # one the caller asked for. Only runs on this env-fallback
                # branch (the explicit ccache_path branch above is EXEMPT —
                # ESC13 capability-bearing TGTs / S4U / RBCD service tickets
                # flow there and their principal mismatch is intentional).
                if username:
                    from adscan_internal.services._kerberos_ccache_guard import (
                        assert_ccache_principal_matches,
                    )

                    assert_ccache_principal_matches(
                        env_ccache,
                        username,
                        auth_domain,
                        source="env",
                        context="ldap_transport",
                    )
                auth_kind = "kerberos-ccache"
                secret_part = _quote_url_component(env_ccache)
            else:
                # Truly no credential material — emit an empty-password
                # AS-REQ so the bind surfaces a clear KRB5KDC_ERR_PREAUTH
                # rather than a silent connection error.
                auth_kind = "kerberos-password"
                secret_part = ""

        print_info_debug(
            f"[kerberos-auth] selected auth_kind={auth_kind!r} for "
            f"user={mark_sensitive(str(username or ''), 'user')} "
            f"realm={mark_sensitive(str(auth_domain or ''), 'domain')}"
        )

        credential_part = ""
        if username:
            credential_part = f"{username_part}:{secret_part}@"
        elif auth_kind == "kerberos-ccache" and auth_domain:
            # No explicit username but we have domain + ccache.
            # badldap requires at least a domain in the URL to set the Kerberos realm;
            # username will be resolved from the ccache ticket itself.
            credential_part = f"{_quote_url_component(auth_domain)}\\:{secret_part}@"

        query = f"/?{'&'.join(params)}" if params else "/"
        url = f"{transport}+{auth_kind}://{credential_part}{url_host}{query}"

        requires_cross_target = bool(
            auth_domain
            and auth_domain.casefold() != str(config.domain or "").strip().casefold()
        )

        # Cross-realm: add dcc= (auth KDC) + realmc= (auth realm) so badldap can
        # request a cross-realm referral TGS before binding to the target DC.
        # Mirrors bloodyAD's `params += f"&dcc={cnf.kdcc}&realmc={cnf.realmc}"`.
        if requires_cross_target:
            cross_kdc = str(config.auth_kdc or kdc_host or "").strip()
            if cross_kdc:
                params.append(f"dcc={_quote_url_component(cross_kdc)}")
            params.append(f"realmc={_quote_url_component(auth_domain)}")
            query = f"/?{'&'.join(params)}" if params else "/"
            url = f"{transport}+{auth_kind}://{credential_part}{url_host}{query}"

        return url, requires_cross_target

    # ---- SIMPLE bind branch ----
    # ``use_simple_bind`` selects RFC 4513 SIMPLE bind regardless of other
    # auth state. With empty creds it yields ``ldap+simple://@host``, the
    # canonical anonymous SIMPLE bind that puts the post-bind connection in
    # RUNNING state (required for paged search). With creds it yields the
    # plaintext-over-LDAPS form ``ldap+simple://user:pwd@host``.
    if config.use_simple_bind:
        if username and password is not None:
            principal = f"{auth_domain}\\{username}" if auth_domain else username
            cred_part = (
                f"{_quote_url_component(principal)}:{_quote_url_component(password)}@"
            )
        else:
            # Anonymous SIMPLE bind requires the literal ``@`` separator so
            # badldap recognises empty credentials rather than treating the
            # URL as authenticated.
            cred_part = "@"
        return f"{transport}+simple://{cred_part}{url_host}", False

    # ---- Anonymous branch ----
    if not username and not password:
        return f"{transport}://{url_host}", False

    # ---- NTLM branch ----
    auth_kind = "ntlm-nt" if _is_nt_hash(password) else "ntlm-password"
    principal = username
    if auth_domain:
        principal = f"{auth_domain}\\{username}"

    params_ntlm: list[str] = []
    if config.paged_size and config.paged_size != 1000:
        params_ntlm.append(f"pagesize={min(int(config.paged_size), 1000)}")
    if config.encrypt and not config.use_ldaps:
        params_ntlm.append("encrypt=true")

    query_ntlm = f"/?{'&'.join(params_ntlm)}" if params_ntlm else ""
    url = (
        f"{transport}+{auth_kind}://{_quote_url_component(principal)}:"
        f"{_quote_url_component(password)}@{url_host}{query_ntlm}"
    )
    return url, False


class ADscanLDAPConnection:
    """badldap-backed LDAP context manager for ADscan collectors."""

    def __init__(
        self, config: ADscanLDAPConfig, *, connect_timeout: float | None = None
    ) -> None:
        self.config = config
        # Optional per-transport connect budget (seconds). When set, each
        # ``conn.connect()`` is wrapped in ``asyncio.wait_for`` so a silently
        # DROPped port or an unreachable/AES-only foreign DC surfaces a
        # ``TimeoutError`` in a few seconds instead of hanging the caller for
        # ~77-90s. ``None`` (default) preserves the legacy unbounded-connect
        # behaviour for authenticated callers that rely on the underlying
        # transport's own timeouts.
        self.connect_timeout = connect_timeout
        self._conn: Any | None = None
        self._factory: Any | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        # Which confidentiality mechanism sealed the connection, populated
        # by ``__enter__`` from the ``LDAPConnectResult``. ``None`` until
        # the context manager is entered. Callers read it to learn whether
        # the channel was protected by LDAPS, StartTLS, SASL sign+seal, or
        # was cleartext (e.g. for an operator advisory).
        self.mechanism: "ConfidentialityMechanism | None" = None
        self._entries: list[LDAPEntry] = []
        self._server_info: dict[str, Any] = {}
        # Last write-style operation exception (modify/add/delete).  Exposed so
        # the auth-aware retry layer can detect insufficientAccessRights even
        # though the wrapper methods themselves swallow and return False.
        self.last_error: Exception | None = None

    def __enter__(self) -> "ADscanLDAPConnection":
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        result = self._loop.run_until_complete(
            async_connect_with_ldap_fallback(
                self.config, connect_timeout=self.connect_timeout
            )
        )
        # ``async_connect_with_ldap_fallback`` returns an
        # ``LDAPConnectResult``; read the live client and the
        # confidentiality mechanism that sealed it (instead of
        # discarding the second element as the legacy code did).
        self._conn = result.client
        self.mechanism = result.mechanism
        self._server_info = dict(getattr(self._conn, "_serverinfo", {}) or {})
        return self

    def __exit__(self, *_args: Any) -> None:
        if self._conn is not None and self._loop is not None:
            try:
                self._loop.run_until_complete(self._conn.disconnect())
            except Exception:  # noqa: BLE001
                pass
        if self._loop is not None:
            try:
                self._loop.close()
            except Exception:  # noqa: BLE001
                pass
        self._conn = None
        self._factory = None
        self._loop = None
        self.mechanism = None
        self._entries = []
        self._server_info = {}

    def _run_coroutine(self, awaitable: Any) -> Any:
        """Run one coroutine on the private connection loop."""
        if self._loop is None:
            raise RuntimeError(
                "ADscanLDAPConnection: connection loop is not initialized"
            )
        return self._loop.run_until_complete(awaitable)

    def _coerce_raw_attribute_values(self, raw_value: Any) -> list[bytes]:
        """Normalize one backend attribute value into a list of raw bytes."""
        values = raw_value if isinstance(raw_value, (list, tuple, set)) else [raw_value]
        normalized: list[bytes] = []
        for value in values:
            if value is None:
                continue
            if isinstance(value, bytes):
                normalized.append(value)
                continue
            normalized.append(str(value).encode("utf-8", errors="surrogatepass"))
        return normalized

    def _build_rootdse_entry(self, attributes: list[str] | None = None) -> LDAPEntry:
        """Synthesize a rootDSE entry from server info returned during connect."""
        requested = list(attributes or [])
        raw_attrs: dict[str, list[bytes]] = {}
        for key, value in self._server_info.items():
            if requested and "*" not in requested and key not in requested:
                continue
            raw_attrs[key] = self._coerce_raw_attribute_values(value)
        return LDAPEntry(dn="", _raw_attrs=raw_attrs)

    def _scope_value(self, search_scope: Any) -> int:
        """Translate ADscan scope values into backend search scope integers."""
        scope_key = (
            str(search_scope).upper() if isinstance(search_scope, str) else search_scope
        )
        scope_int = _LDAP_SCOPE_MAP.get(scope_key, None)
        if scope_int is None:
            print_warning_debug(
                f"[ldap] Unknown search_scope {search_scope!r}; defaulting to SUBTREE"
            )
            return 2
        return scope_int

    @property
    def entries(self) -> list[LDAPEntry]:
        return self._entries

    @property
    def domain_dn(self) -> str:
        return self.config.domain_dn

    @property
    def config_dn(self) -> str:
        return self.config.config_dn

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str] | None = None,
        search_scope: Any = "SUBTREE",
        paged_size: int = 1000,
        controls: Any = None,
    ) -> None:
        """Execute an LDAP search and populate ``self.entries``.

        Args:
            search_base: LDAP search base DN.
            search_filter: LDAP filter string.
            attributes: List of attributes to retrieve; defaults to all ("*").
            search_scope: "BASE", "ONELEVEL", "SUBTREE", or integer 0/1/2.
            paged_size: Page size for paged search. Honored via badldap pagedsearch;
                also wired into the connection URL at construction time via
                ``ADscanLDAPConfig.paged_size``. Max 1000.
            controls: Pass ``SD_FLAGS_DACL_CONTROL`` to request nTSecurityDescriptor DACL.
        """
        if self._conn is None:
            raise RuntimeError(
                "ADscanLDAPConnection: search called outside context manager"
            )

        effective_attrs = list(attributes or ["*"])
        scope_int = self._scope_value(search_scope)
        self._entries = []
        if search_base == "" and self._server_info and scope_int == 0:
            self._entries = [self._build_rootdse_entry(effective_attrs)]
            return

        # paged_size is honored at the connection URL level (pagesize= param).
        # The pagedsearch call does not accept an explicit page size argument;
        # badldap uses the value from MSLDAPTarget.ldap_query_page_size.
        _ = paged_size

        async def _collect_entries() -> list[LDAPEntry]:
            collected: list[LDAPEntry] = []
            async for item, err in self._conn.pagedsearch(  # type: ignore[union-attr]
                search_filter,
                effective_attrs,
                controls=_resolve_sd_flags_control(controls),
                tree=search_base or None,
                search_scope=scope_int,
                raw=True,
            ):
                if err is not None:
                    raise err
                raw_attrs = {
                    str(attr_name): self._coerce_raw_attribute_values(attr_value)
                    for attr_name, attr_value in dict(
                        item.get("attributes", {}) or {}
                    ).items()
                }
                dn = str(item.get("objectName", "") or "")
                collected.append(LDAPEntry(dn=dn, _raw_attrs=raw_attrs))
            return collected

        self._entries = list(self._run_coroutine(_collect_entries()) or [])

    def add(self, dn: str, object_class: list[str], attributes: dict[str, Any]) -> bool:
        """Add a new LDAP object.

        Args:
            dn: Distinguished name of the new object.
            object_class: List of objectClass values (e.g. ["top", "organizationalUnit"]).
            attributes: Dictionary of attribute names to values. ``objectClass`` is
                merged from the ``object_class`` parameter.

        Returns:
            True on success, False on failure.
        """
        from adscan_internal import telemetry

        if self._conn is None:
            raise RuntimeError(
                "ADscanLDAPConnection: add called outside context manager"
            )

        merged: dict[str, Any] = dict(attributes)
        merged["objectClass"] = object_class

        async def _do_add() -> bool:
            ok, err = await self._conn.add(dn, merged)  # type: ignore[union-attr]
            if err is not None:
                raise err
            return bool(ok)

        try:
            result = self._run_coroutine(_do_add())
            self.last_error = None
            return result
        except Exception as exc:  # noqa: BLE001
            self.last_error = exc
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap] add failed for dn={mark_sensitive(dn, 'path')}: {exc}"
            )
            return False

    def modify(
        self,
        dn: str,
        changes: dict[str, Any],
        encode: bool = True,
        controls: Any = None,
    ) -> bool:
        """Modify attributes on an existing LDAP object.

        Args:
            dn: Distinguished name of the object to modify.
            changes: badldap-style changes dict:
                ``{'attribute': [('MODIFY_REPLACE', [value])]}``
                Change operation keys follow ldap3/badldap conventions:
                MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE.
            encode: When True (default), badldap encodes str/int values.
                Set to False when passing raw bytes (e.g. nTSecurityDescriptor,
                msDS-KeyCredentialLink) to avoid double-encoding.
            controls: Optional LDAP controls. Pass ``SD_FLAGS_DACL_CONTROL`` when
                replacing ``nTSecurityDescriptor`` DACL bytes.

        Returns:
            True on success, False on failure.
        """
        from adscan_internal import telemetry

        if self._conn is None:
            raise RuntimeError(
                "ADscanLDAPConnection: modify called outside context manager"
            )

        async def _do_modify() -> bool:
            effective_controls = _resolve_modify_controls(controls)
            ok, err = await self._conn.modify(  # type: ignore[union-attr]
                dn, changes, controls=effective_controls, encode=encode
            )
            if err is not None:
                raise err
            return bool(ok)

        try:
            result = self._run_coroutine(_do_modify())
            self.last_error = None
            return result
        except Exception as exc:  # noqa: BLE001
            self.last_error = exc
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap] modify failed for dn={mark_sensitive(dn, 'path')}: {exc}"
            )
            return False

    def delete(self, dn: str) -> bool:
        """Delete an LDAP object.

        Args:
            dn: Distinguished name of the object to delete.

        Returns:
            True on success, False on failure.
        """
        from adscan_internal import telemetry

        if self._conn is None:
            raise RuntimeError(
                "ADscanLDAPConnection: delete called outside context manager"
            )

        async def _do_delete() -> bool:
            ok, err = await self._conn.delete(dn)  # type: ignore[union-attr]
            if err is not None:
                raise err
            return bool(ok)

        try:
            result = self._run_coroutine(_do_delete())
            self.last_error = None
            return result
        except Exception as exc:  # noqa: BLE001
            self.last_error = exc
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap] delete failed for dn={mark_sensitive(dn, 'path')}: {exc}"
            )
            return False

    def modify_dn(
        self,
        dn: str,
        new_rdn: str,
        new_superior: str | None = None,
    ) -> bool:
        """Rename or move an LDAP object (modifyDN / modifyRDN).

        badldap does not expose a dedicated modifyDN method on MSLDAPClient.
        This is implemented via the underlying MSLDAPClientConnection.modify_dn
        if available, otherwise raises NotImplementedError.

        Args:
            dn: Current distinguished name.
            new_rdn: New relative distinguished name (e.g. "CN=newname").
            new_superior: New parent DN for move operations; None for rename-only.

        Returns:
            True on success, False on failure.

        Raises:
            NotImplementedError: If badldap does not expose modifyDN at the
                connection level. Upgrade badldap or use a raw connection.
        """
        from adscan_internal import telemetry

        if self._conn is None:
            raise RuntimeError(
                "ADscanLDAPConnection: modify_dn called outside context manager"
            )

        # badldap MSLDAPClient does not have a modify_dn wrapper — fall through
        # to the underlying _con (MSLDAPClientConnection) if it exposes one.
        underlying = getattr(self._conn, "_con", None)
        if underlying is None or not hasattr(underlying, "modify_dn"):
            raise NotImplementedError(
                "modify_dn is not exposed by the current badldap MSLDAPClient. "
                "Use the underlying MSLDAPClientConnection directly or upgrade badldap."
            )

        async def _do_modify_dn() -> bool:
            ok, err = await underlying.modify_dn(
                dn, new_rdn, deleteoldrdn=True, newSuperior=new_superior
            )
            if err is not None:
                raise err
            return bool(ok)

        try:
            return self._run_coroutine(_do_modify_dn())
        except NotImplementedError:
            raise
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap] modify_dn failed for dn={mark_sensitive(dn, 'path')}: {exc}"
            )
            return False


class LDAPTransportValidationError(RuntimeError):
    """Raised when an LDAP connection opens but is not usable for queries."""


class ConfidentialChannelUnavailableError(RuntimeError):
    """Raised when a confidential-attribute read cannot use a sealed channel.

    A CONFIDENTIAL directory attribute (``msDS-ManagedPassword``, ``unicodePwd``,
    ...) is only returned by AD over a sealed channel: LDAPS (TLS) or plain LDAP
    with GSS-API confidentiality (sign+seal). When ``ADscanLDAPConfig.require_confidential``
    is set and neither a working LDAPS transport nor a sign+seal-capable plain-LDAP
    bind is achievable, this is raised instead of silently downgrading to an
    unsealed plain-LDAP channel that can NEVER return the attribute (the DC would
    answer ``ERROR_DS_CONFIDENTIALITY_REQUIRED`` / omit the value)."""


class ForeignRealmUnreachableError(RuntimeError):
    """Raised when an LDAP bind targets a foreign/trust realm we cannot reach.

    The current credential cannot authenticate against the target realm's KDC
    (cross-forest AES-only KDC, no shared trust key, no usable secret for that
    realm). The AS-REQ comes back ``KDC_ERR_ETYPE_NOTSUPP`` / preauth-failed, or
    kerbad returns a ``None`` ticket which asn1crypto then fails to ``load`` with
    ``encoded_data must be a byte string, not NoneType``. Both are ONE root
    cause and have NO recovery (re-mint / clock-resync / ETYPE-INFO2 all assume a
    secret valid in that realm). This typed error replaces the raw asn1
    ``TypeError`` / 160-line ``KerberosError`` traceback with one clean line so a
    caller (attack-path discovery, trust enum) can render "realm not reachable"
    instead of crashing the phase. See
    :func:`auth_error_classification.is_unreachable_foreign_realm_error`."""


class ConfidentialityMechanism(str, enum.Enum):
    """Which confidentiality mechanism actually sealed an LDAP connection.

    Returned on the success path of :func:`async_connect_with_ldap_fallback`
    (via :class:`LDAPConnectResult`) so callers — and downstream posture /
    findings layers — can learn HOW the channel was protected, not just
    whether LDAPS was used. The ordering mirrors the confidentiality ladder:
    LDAPS (TLS/636) > StartTLS (TLS/389) > SASL sign+seal (GSS/389) > cleartext.
    """

    LDAPS = "ldaps"          # TLS on port 636
    STARTTLS = "starttls"    # TLS on port 389 via RFC 2830 StartTLS
    SASL_SEAL = "sasl_seal"  # GSS-API application-layer sign+seal on port 389
    CLEARTEXT = "cleartext"  # no confidentiality (last resort, plain 389)


@dataclass(frozen=True)
class LDAPConnectResult:
    """Result of :func:`async_connect_with_ldap_fallback`.

    Carries the live ``MSLDAPClient`` plus the :class:`ConfidentialityMechanism`
    that sealed it. Backward-compatible with the legacy ``(client, used_ldaps)``
    2-tuple return: the dataclass is iterable as ``(client, used_ldaps)`` so
    existing call sites that unpack ``conn, used_ldaps = await ...`` keep working
    unchanged, while new callers can read ``.client`` / ``.mechanism`` directly.
    """

    client: Any
    mechanism: "ConfidentialityMechanism"

    @property
    def used_ldaps(self) -> bool:
        """Back-compat shim: True iff the channel was sealed by LDAPS/636 TLS."""
        return self.mechanism is ConfidentialityMechanism.LDAPS

    @property
    def is_confidential(self) -> bool:
        """True iff the channel is sealed by ANY mechanism (not cleartext)."""
        return self.mechanism is not ConfidentialityMechanism.CLEARTEXT

    def __iter__(self):
        # Preserve ``conn, used_ldaps = await async_connect_with_ldap_fallback(...)``
        # unpacking for every legacy caller. Order matches the old 2-tuple.
        yield self.client
        yield self.used_ldaps


@dataclass(frozen=True)
class LDAPTargetEndpoints:
    """Resolved LDAP transport and Kerberos target endpoints for one domain."""

    dc_address: str | None
    kerberos_target_hostname: str | None
    dc_ip: str | None
    dc_fqdn: str | None


def _format_gssapi_ccache_name(ccache_name: str) -> str:
    """Return a Kerberos ccache name suitable for python-gssapi."""
    value = str(ccache_name or "").strip()
    if not value:
        return value
    if re.match(r"^[A-Za-z][A-Za-z0-9_+-]*:", value):
        return value
    return f"FILE:{value}"


def _set_gssapi_default_ccache_from_environment() -> bool:
    """Bind python-gssapi's default ccache to ``KRB5CCNAME`` for LDAP SASL.

    ldap3's GSSAPI path ultimately calls GSS-API with ``GSS_C_NO_CREDENTIAL``.
    On some runtimes the GSS layer keeps using the UID default cache even after
    ``KRB5CCNAME`` was updated in Python. Setting python-gssapi's krb5 ccache
    name explicitly makes the workspace ticket authoritative for the thread.

    Returns:
        True when a ccache was explicitly applied.
    """
    ccache_env = str(os.environ.get("KRB5CCNAME") or "").strip()
    if not ccache_env:
        return False

    ccache_name = _format_gssapi_ccache_name(ccache_env)
    try:
        from gssapi.raw.ext_krb5 import krb5_ccache_name  # pylint: disable=no-name-in-module

        krb5_ccache_name(ccache_name.encode("utf-8"))
        print_info_debug(
            "[ldap] Bound python-gssapi default credential cache to "
            f"{mark_sensitive(ccache_name, 'path')}"
        )
        return True
    except Exception as exc:  # noqa: BLE001
        log_exception_debug(
            "Failed to bind python-gssapi default credential cache",
            exception=exc,
            context={"krb5ccname": mark_sensitive(ccache_name, "path")},
        )
        print_warning_debug(
            "[ldap] Failed to bind python-gssapi default credential cache from "
            f"KRB5CCNAME={mark_sensitive(ccache_name, 'path')}. "
            f"Cause: {_format_exception_chain_summary(exc)}"
        )
        return False


def bind_workspace_ticket_for_user(
    *,
    domains_data: Mapping[str, Any] | None,
    domain: str,
    username: str,
    realm: str | None = None,
) -> bool:
    """Activate the workspace TGT for *username* in the current process.

    This is the fast-path counterpart to :func:`prepare_kerberos_ldap_environment`
    used by hot LDAP query helpers (``query_shell_ldap_attribute_values``).
    It avoids the full ticket-refresh dance and instead:

    1. Looks up the ccache registered under
       ``domains_data[domain]["kerberos_tickets"][username]``.
    2. Verifies via :func:`validate_tgt_for_user` that the file actually
       contains a TGT for *username* — defending against the historical bug
       where any non-empty ``kerberos_tickets`` entry was treated as "Kerberos
       is ready", regardless of which user was active.
    3. Sets ``KRB5CCNAME`` and binds python-gssapi's default credential cache
       so subsequent badldap / aiosmb Kerberos calls honour the workspace
       ticket without falling back to the UID default cache.

    Returns:
        ``True`` when the workspace ticket was bound; ``False`` when no
        usable TGT for *username* is registered.  Callers should fall back to
        :func:`prepare_kerberos_ldap_environment` (which can refresh) or skip
        Kerberos altogether on ``False``.
    """
    from adscan_internal.services.kerberos_ccache_inspector import (  # noqa: PLC0415
        validate_tgt_for_user,
    )

    if not isinstance(domains_data, Mapping):
        return False
    domain_data = domains_data.get(domain, {}) if isinstance(domains_data, Mapping) else {}
    if not isinstance(domain_data, Mapping):
        return False

    tickets = domain_data.get("kerberos_tickets", {})
    if not isinstance(tickets, Mapping):
        return False

    user_key = str(username or "").strip()
    if not user_key:
        return False
    ticket_path = tickets.get(user_key)
    if not ticket_path:
        # Try a case-insensitive lookup for tolerance with mixed-case names.
        for stored_user, stored_path in tickets.items():
            if isinstance(stored_user, str) and stored_user.casefold() == user_key.casefold():
                ticket_path = stored_path
                break
    ticket_path = str(ticket_path or "").strip()
    if not ticket_path or not os.path.exists(ticket_path):
        return False

    effective_realm = (realm or domain or "").strip().upper() or None
    result = validate_tgt_for_user(
        ticket_path, username=user_key, realm=effective_realm
    )
    if not result.ok:
        print_info_debug(
            f"[ldap] workspace ticket for {mark_sensitive(user_key, 'user')}@"
            f"{mark_sensitive(effective_realm or '?', 'domain')} rejected: {result.reason}"
        )
        return False

    os.environ["KRB5CCNAME"] = ticket_path
    _set_gssapi_default_ccache_from_environment()
    print_info_debug(
        f"[ldap] bound workspace ticket {mark_sensitive(ticket_path, 'path')} "
        f"for {mark_sensitive(user_key, 'user')}@{mark_sensitive(effective_realm or '?', 'domain')}"
    )
    return True


def resolve_ldap_target_endpoints(
    *,
    target_domain: str,
    domain_data: Mapping[str, Any] | None,
    kerberos_ready: bool,
    ip_hostname_inventory: dict | None = None,
) -> LDAPTargetEndpoints:
    """Resolve transport and Kerberos target endpoints for one domain.

    Delegates FQDN selection to :func:`resolve_dc_fqdn` so the canonical
    fallback chain (incl. workspace inventory) is honoured here too.

    Args:
        target_domain: DNS domain name.
        domain_data: Domain metadata loaded in the shell workspace.
        kerberos_ready: Whether the caller intends to authenticate with Kerberos.
        ip_hostname_inventory: Optional ``{ip: [hostname, …]}`` map from the
            workspace reachability scan. When provided, used as a last-resort
            FQDN source when no hostname field is populated.

    Returns:
        Resolved transport target plus the FQDN that Kerberos should use for the
        service principal name.
    """
    from adscan_internal.models.domain import resolve_dc_fqdn  # noqa: PLC0415

    domain_data_dict = dict(domain_data) if isinstance(domain_data, Mapping) else {}
    dc_fqdn = resolve_dc_fqdn(
        domain_data_dict,
        target_domain=target_domain,
        ip_hostname_inventory=ip_hostname_inventory,
    )
    dc_ip = str(domain_data_dict.get("pdc") or "").strip() or None
    kerberos_target_hostname = dc_fqdn or None
    _ = kerberos_ready  # preserved for callers that may inspect signature
    dc_address = dc_ip or dc_fqdn
    return LDAPTargetEndpoints(
        dc_address=dc_address,
        kerberos_target_hostname=kerberos_target_hostname,
        dc_ip=dc_ip,
        dc_fqdn=dc_fqdn,
    )


def build_ldap_config_for_domain(
    domains_data: Mapping[str, Any],
    domain: str,
    *,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    ccache_path: str | None = None,
    auth_domain: str | None = None,
    auth_kdc: str | None = None,
    use_ldaps: bool = True,
    use_kerberos: bool | None = None,
    ip_hostname_inventory: dict | None = None,
    posture_sink: Any = None,
    posture_snapshot: Any = None,
) -> ADscanLDAPConfig:
    """Build an ``ADscanLDAPConfig`` from ``domains_data`` with FQDN resolution.

    Single canonical entry point for any caller that wants an LDAP transport
    config derived from the workspace ``domains_data`` map. Walks the FQDN
    fallback chain via ``resolve_dc_fqdn`` so Kerberos-aware callers never
    end up with ``kerberos_target_hostname=None`` while ``dc_ip`` is an IP —
    the exact bug class the dataclass guard exists to surface.

    Args:
        domains_data: ``shell.domains_data`` map (``{domain: {…}}``).
        domain: Target domain key to look up.
        username: Account name for authentication.
        password: Plaintext password (ignored when nt_hash or ccache_path is set).
        nt_hash: NT hash for pass-the-hash Kerberos.
        ccache_path: Explicit ccache file path for ``kerberos-ccache`` auth.
        auth_domain: Cross-domain auth override for the credential's home domain.
        auth_kdc: KDC IP override for cross-domain authentication.
        use_ldaps: Prefer LDAPS (port 636). Defaults to True; the transport
            layer falls back to LDAP automatically when LDAPS is unavailable.
        use_kerberos: When None, inferred from ``ccache_path`` presence.
        ip_hostname_inventory: Optional pre-loaded inventory for IP → FQDN
            fallback. Pass ``load_workspace_ip_hostname_inventory(...)`` from
            the call site that has workspace paths.
        posture_sink: Forwarded to the dataclass for posture signal emission.
        posture_snapshot: Forwarded to the dataclass for auth-plan pruning.

    Returns:
        Fully-formed ``ADscanLDAPConfig`` with ``kerberos_target_hostname``
        resolved from the FQDN fallback chain whenever possible.

    Raises:
        KeyError: ``domain`` is not in ``domains_data``.
        ValueError: No DC IP could be resolved from the ``domains_data`` entry.
    """
    from adscan_internal.models.domain import resolve_dc_fqdn, resolve_dc_ip  # noqa: PLC0415

    if domain not in domains_data:
        raise KeyError(domain)

    domain_data = domains_data[domain] or {}
    dc_ip = resolve_dc_ip(domain_data)
    if not dc_ip:
        raise ValueError(
            f"DC IP could not be resolved for domain {domain!r} from domains_data; "
            "ensure the domain entry has a 'pdc' / 'dc_ip' / 'dcs' field."
        )

    kerberos_active = bool(ccache_path) if use_kerberos is None else bool(use_kerberos)
    kerberos_target_hostname = resolve_dc_fqdn(
        domain_data,
        target_domain=domain,
        ip_hostname_inventory=ip_hostname_inventory,
    )

    return ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        kerberos_target_hostname=kerberos_target_hostname,
        use_ldaps=use_ldaps,
        use_kerberos=kerberos_active,
        username=username,
        password=None if (nt_hash or ccache_path) else password,
        ccache_path=ccache_path,
        auth_domain=auth_domain,
        auth_kdc=auth_kdc,
        posture_sink=posture_sink,
        posture_snapshot=posture_snapshot,
    )


def prepare_kerberos_ldap_environment(
    *,
    operation_name: str,
    target_domain: str,
    workspace_dir: str,
    username: str,
    user_domain: str,
    credential: str | None = None,
    dc_ip: str | None = None,
    domains_data: Mapping[str, Any] | None = None,
    sync_clock: Callable[[str], Any] | None = None,
    force_ticket_refresh: bool = False,
) -> bool:
    """Prepare Kerberos env vars and clock sync for LDAP-backed collectors.

    This is the canonical preflight for any Python LDAP workflow that wants to
    authenticate with Kerberos against a domain controller. It validates the
    workspace ccache, refreshes it when missing/expired and credentials are
    available, then explicitly binds python-gssapi to the chosen ccache.

    Returns:
        ``True`` when a usable workspace Kerberos ticket was configured.
    """
    from adscan_internal import telemetry
    from adscan_internal.services import KerberosTicketService

    domain_key = str(target_domain or "").strip()
    workspace_root = str(workspace_dir or "").strip()
    user_name = str(username or "").strip()
    auth_domain = str(user_domain or domain_key).strip() or domain_key
    credential_value = str(credential or "").strip()
    marked_operation = mark_sensitive(operation_name, "path")
    marked_user = mark_sensitive(user_name, "user")
    marked_auth_domain = mark_sensitive(auth_domain, "domain")

    if not domain_key or not workspace_root:
        print_info_debug(
            f"[ldap] {marked_operation} missing workspace/domain context; Kerberos LDAP env setup skipped."
        )
        return False

    if sync_clock is not None:
        try:
            sync_clock(domain_key)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[ldap] Kerberos clock sync failed before {marked_operation} for "
                f"{mark_sensitive(domain_key, 'domain')}: {exc}"
            )

    service = KerberosTicketService()

    def _setup_environment() -> tuple[bool, bool, str | None, str | None]:
        return service.setup_environment_for_domain(
            workspace_dir=workspace_root,
            domain=domain_key,
            user_domain=auth_domain,
            username=user_name or None,
            domains_data=domains_data,
        )

    try:
        krb5_config_set, kerberos_ticket_set, krb5_config_path, ticket_path = (
            _setup_environment()
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[ldap] Failed to prepare Kerberos LDAP environment for "
            f"{mark_sensitive(domain_key, 'domain')}: {exc}"
        )
        return False

    ticket_valid = None
    if kerberos_ticket_set and ticket_path and os.path.exists(ticket_path):
        try:
            ticket_valid = service.is_ticket_valid(ticket_path=ticket_path)
            print_info_debug(
                f"[ldap] Workspace Kerberos ticket state for {marked_operation}: "
                f"user={marked_user}@{marked_auth_domain} "
                f"ccache={mark_sensitive(ticket_path, 'path')} valid={ticket_valid!r}"
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[ldap] Kerberos ticket validation failed for {marked_user}@"
                f"{marked_auth_domain} during {marked_operation}: {exc}"
            )

    should_refresh_ticket = bool(
        credential_value
        and user_name
        and (
            force_ticket_refresh
            or not kerberos_ticket_set
            or not ticket_path
            or not os.path.exists(ticket_path)
            or ticket_valid is False
        )
    )
    if should_refresh_ticket:
        refresh_reason = (
            "forced"
            if force_ticket_refresh
            else "missing"
            if not kerberos_ticket_set
            or not ticket_path
            or not os.path.exists(ticket_path)
            else "invalid"
        )
        print_info_debug(
            f"[ldap] Refreshing Kerberos ticket for {marked_operation}: "
            f"user={marked_user}@{marked_auth_domain} reason={refresh_reason}"
        )
        try:
            auth_domain_data = (
                domains_data.get(auth_domain, {})
                if isinstance(domains_data, Mapping)
                else {}
            )
            refresh_dc_ip = (
                str(
                    dc_ip
                    or (
                        auth_domain_data.get("pdc")
                        if isinstance(auth_domain_data, Mapping)
                        else ""
                    )
                    or ""
                ).strip()
                or None
            )
            result = service.auto_generate_tgt(
                username=user_name,
                credential=credential_value,
                domain=auth_domain,
                workspace_dir=workspace_root,
                dc_ip=refresh_dc_ip,
            )
            if not result.success:
                print_warning_debug(
                    f"[ldap] Kerberos ticket refresh failed for {marked_operation}: "
                    f"user={marked_user}@{marked_auth_domain} error={result.error_message!r}"
                )
            krb5_config_set, kerberos_ticket_set, krb5_config_path, ticket_path = (
                _setup_environment()
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap] Kerberos ticket refresh raised during {marked_operation}: "
                f"Cause: {_format_exception_chain_summary(exc)}"
            )

    if krb5_config_set and krb5_config_path:
        print_info_debug(
            f"[ldap] Using workspace krb5.conf for {marked_operation}: "
            f"{mark_sensitive(krb5_config_path, 'path')}"
        )
    else:
        workspace_conf = Path(workspace_root).expanduser().resolve() / "krb5.conf"
        print_info_debug(
            f"[ldap] No workspace krb5.conf available for {marked_operation} at "
            f"{mark_sensitive(str(workspace_conf), 'path')}"
        )

    if kerberos_ticket_set and ticket_path and os.path.exists(ticket_path):
        _set_gssapi_default_ccache_from_environment()
        print_info_debug(
            f"[ldap] Using workspace Kerberos ticket for {marked_operation}: "
            f"{mark_sensitive(ticket_path, 'path')}"
        )
        return True

    print_info_debug(
        f"[ldap] No workspace Kerberos ticket available for "
        f"{mark_sensitive(user_name, 'username')}@{mark_sensitive(auth_domain, 'domain')} "
        f"during {marked_operation}; falling back to password-backed LDAP bind."
    )
    return False


def _walk_exception_chain(exc: BaseException) -> list[BaseException]:
    """Return the exception with its ``__cause__`` / ``__context__`` chain."""
    seen: set[int] = set()
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _format_exception_chain_summary(exc: BaseException, *, max_items: int = 3) -> str:
    """Return a compact exception chain summary for debug messages."""
    parts: list[str] = []
    for candidate in _walk_exception_chain(exc)[:max_items]:
        class_name = type(candidate).__name__.strip() or "Exception"
        message = str(candidate or "").strip()
        parts.append(f"{class_name}: {message}" if message else class_name)
    if not parts:
        return type(exc).__name__
    return " <- ".join(parts)


def is_ldaps_transport_failure(exc: BaseException) -> bool:
    """Return whether one exception looks like an LDAPS transport/TLS failure.

    Includes two classes of connect-time connectivity failure, both of which
    are *never* auth failures and so must trigger the LDAPS->LDAP fallback:

    1. Timeout-class exceptions -- when LDAPS:636 is silently dropped (firewall
       DROP) the TCP connect never completes and asyncio raises
       ``TimeoutError`` / ``CancelledError``.
    2. ``ConnectionError`` subclasses -- when LDAPS:636 is actively rejected
       (firewall REJECT / ``--reject-with tcp-reset``, or the service is down)
       asyncio raises ``ConnectionResetError`` / ``ConnectionRefusedError`` /
       ``ConnectionAbortedError`` with a message like
       ``"Connect call failed (\'<ip>\', 636)"``. That message contains none
       of the string indicators below (it never says "reset by peer", "tls", or
       "ldaps"), so before this type check such a reset on 636 silently failed
       to fall back to plain LDAP/389 even though 389 was open. Verified from
       sanitised customer telemetry: the native collector connected fine on
       LDAP/389 but the LDAP description query died with
       ``ConnectionResetError(104, "Connect call failed (\'<dc>\', 636)")``.

    A ``ConnectionError`` at the socket layer is *always* a connectivity
    event -- badldap surfaces server-side auth rejections as
    ``LDAPBindException`` / ``LDAPServerException`` (``invalidCredentials``,
    ``strongerAuthRequired``, ``SEC_E_LOGON_DENIED``, ``SEC_E_BAD_BINDINGS``),
    never as a ``ConnectionError``. So matching ``ConnectionError`` here cannot
    misclassify a post-connect auth/bind failure as a transport failure, which
    is why it is safe even though some callers invoke this on whole-operation
    exceptions (connect + bind + query), not just connect.
    """
    # Connectivity-class exceptions at connect time. Port 636 filtered ->
    # either no answer (timeout) or an active RST/refusal (ConnectionError).
    # Both are connectivity failures, never auth failures.
    for candidate in _walk_exception_chain(exc):
        if isinstance(candidate, (TimeoutError, asyncio.TimeoutError,
                                   asyncio.CancelledError, ConnectionError)):
            return True

    indicators = (
        "socket ssl wrapping error",
        "socket is not open",
        "ldapsocketopenerror",
        "ssl handshake error",
        "connection reset by peer",
        "unable to send message",
        "tls",
        "ldaps",
        "ldaptransportvalidationerror",
    )
    for candidate in _walk_exception_chain(exc):
        class_name = type(candidate).__name__.strip().lower()
        message = str(candidate or "").strip().lower()
        haystacks = (class_name, message)
        if any(
            indicator in haystack for haystack in haystacks for indicator in indicators
        ):
            return True
    return False


def is_kerberos_auth_failure(exc: BaseException) -> bool:
    """Return whether one exception looks like a Kerberos/GSSAPI auth failure."""

    indicators = (
        "server not found in kerberos database",
        "ticket expired",
        "krb_ap_err",
        "kerberos",
        "gssapi",
        "gsserror",
        "preauthentication failed",
        "no credentials were supplied",
        "cannot find kdc",
        "client not found in kerberos database",
    )
    for candidate in _walk_exception_chain(exc):
        class_name = type(candidate).__name__.strip().lower()
        message = str(candidate or "").strip().lower()
        haystacks = (class_name, message)
        if any(
            indicator in haystack for haystack in haystacks for indicator in indicators
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# Posture signal emission (PR3)
# ---------------------------------------------------------------------------


def _emit_posture_signal(
    config: "ADscanLDAPConfig",
    *,
    category: ConstraintCategory,
    state: TriState,
    confidence: SignalConfidence,
    signal_code: str,
    message: str,
    protocol: str = "ldap",
) -> None:
    """Emit an LDAP posture signal to the configured sink, if any.

    Pure best-effort: any exception in the sink is captured via telemetry and
    never propagates — posture telemetry must never break an LDAP bind.
    """
    sink = getattr(config, "posture_sink", None)
    if sink is None:
        return
    try:
        signal = PostureSignal(
            domain=config.domain,
            category=category,
            state=state,
            confidence=confidence,
            source="ldap_transport",
            signal_code=signal_code,
            message=message,
            protocol=protocol,
            observed_at=datetime.now(timezone.utc),
        )
        sink(signal)
    except Exception as sink_exc:
        telemetry.capture_exception(sink_exc)
        print_info_debug(
            f"[ldap_transport] posture sink raised: "
            f"{type(sink_exc).__name__}: {sink_exc}"
        )


def _is_seal_negotiation_failure(exc: BaseException) -> bool:
    """Return whether a bind failure looks like a sealing/GSS-confidentiality problem.

    Used only by the seal-by-default degrade path: when a plain-LDAP/389 bind
    that we upgraded to sign+seal (CONFIDENTIALITY) fails, we want to retry it
    UNSEALED iff the failure is specifically about negotiating confidentiality
    against a server that cannot provide it (a non-Windows / legacy LDAP
    server) -- NOT an auth/credential failure (which must propagate unchanged).

    Returns ``True`` only for signatures that indicate the GSS confidentiality
    layer could not be established, AND never for an unambiguous credential
    failure. Conservatively, an ``invalidCredentials`` / ``SEC_E_LOGON_DENIED``
    chain is treated as auth failure (returns ``False``) so a real bad-creds
    rejection is never silently downgraded to a cleartext retry.
    """
    chain_text = " ".join(
        f"{type(c).__name__}: {c}".lower() for c in _walk_exception_chain(exc)
    )

    # Unambiguous credential failures are NOT seal failures. Bail out first so a
    # genuine bad-password / disabled-NTLM rejection never triggers a cleartext
    # downgrade retry.
    auth_failure_markers = (
        "invalidcredentials",
        "sec_e_logon_denied",
        "preauthentication failed",
        "krb_ap_err",
        "client not found in kerberos database",
        "strongerauthrequired",  # signing-required: handled by its own self-heal
    )
    if any(marker in chain_text for marker in auth_failure_markers):
        return False

    # Signatures that point at the confidentiality/integrity (sealing) layer
    # failing to negotiate against a server that does not support it.
    seal_markers = (
        "confidentiality",
        "sec_e_unsupported_function",
        "sec_e_qop_not_supported",
        "qop not supported",
        "encryption needed",
        "unwrap",
        "wrap",
        "seal",
        "no common protection level",
        "gss_s_failure",
    )
    return any(marker in chain_text for marker in seal_markers)


def _is_starttls_unavailable(exc: BaseException) -> bool:
    """Return whether a StartTLS-rung failure means "no usable TLS on 389".

    Used only by the confidentiality ladder to decide whether a failed
    StartTLS attempt should fall THROUGH to the SASL sign+seal rung (the DC
    has no usable cert on 389 / does not support StartTLS) versus being a
    hard TCP/389 failure that means the whole 389 path is dead.

    Returns ``True`` for:

    - A refused StartTLS extendedReq — badldap surfaces this as an
      ``LDAPBindException`` with a non-success result code
      (``unwillingToPerform`` / ``protocolError``), raised from
      ``MSLDAPClientConnection.connect()`` when ``_use_starttls`` is set.
    - A post-StartTLS TLS handshake error (``ssl.SSLError`` / "ssl handshake
      error" / "tls"), meaning the cert is broken or absent on 389.
    - The AD "Error initializing SSL/TLS" StartTLS comment — the DC accepted
      the StartTLS extendedReq but cannot initialise TLS (no / broken cert),
      surfaced by badldap as an ``LDAPBindException`` carrying that comment
      (observed on HTB Sauna, "channel binding:No TLS cert"). Without this the
      anonymous probe would raise out of the ladder instead of falling through
      to the cleartext rung. (The chained ``RuntimeError('no running event
      loop')`` sometimes seen alongside it is a benign teardown artifact, not a
      ``ConnectionError`` — so the early-return below does not pre-empt this.)

    Returns ``False`` for a bare connect-time TCP failure (the 389 socket
    never opened) — that is a transport-dead signal the caller propagates,
    not a "fall through to the next rung" signal. ``ConnectionError`` /
    bare ``TimeoutError`` are therefore NOT matched here.
    """
    chain = _walk_exception_chain(exc)
    # A pure connect-time TCP failure (socket never opened) is not a StartTLS
    # availability signal — the whole 389 path is dead, propagate it.
    for candidate in chain:
        if isinstance(candidate, (ConnectionError,)):
            return False
    chain_text = " ".join(
        f"{type(c).__name__}: {c}".lower() for c in chain
    )
    starttls_markers = (
        "unwillingtoperform",
        "protocolerror",
        "ssl handshake error",
        "socket ssl wrapping error",
        "ssl: ",
        "sslerror",
        "tlsv1",
        "wrong_version_number",
        "certificate",
        "starttls",
        "extended operation",
        # AD comment when the DC accepts the StartTLS extendedReq but cannot
        # initialise TLS (no / broken cert) — observed on HTB Sauna. Both
        # markers are safe here: this classifier is only consulted on a failure
        # of the StartTLS rung, so any "ssl/tls" mention means "TLS unusable on
        # 389" → fall through to the cleartext rung rather than raise.
        "error initializing ssl/tls",
        "ssl/tls",
    )
    return any(marker in chain_text for marker in starttls_markers)


def _ldap_ntlm_disabled_high(posture: "DomainPosture | None") -> bool:
    """Return True when posture HIGH-knows NTLM is DISABLED for this domain.

    Mirrors the ``ntlm_disabled_high`` guard in ``build_smb_plan`` /
    ``build_winrm_plan``: the NTLM last-resort rung is granted only when NTLM has
    not been ruled out by HIGH-confidence posture. ``None`` posture (or any
    UNKNOWN/LOW NTLM state) means "not ruled out" → the grant is allowed.
    """
    if posture is None:
        return False
    entry = posture.get(ConstraintCategory.NTLM_AUTHENTICATION)
    if entry is None:
        return False
    return bool(
        entry.confidence is SignalConfidence.HIGH
        and entry.effective_state is TriState.DISABLED
    )


def _classify_recoverable_bind_failure(
    exc: BaseException,
    *,
    cfg: "ADscanLDAPConfig",
    transport_was_ldaps: bool,
) -> Optional["ADscanLDAPConfig"]:
    """Identify bind failures whose fix is a posture-driven config tweak.

    When the failure matches a known *recoverable* pattern, return a new
    ``ADscanLDAPConfig`` with the single field flipped that would have
    avoided it. The caller appends that config to ``configs_to_try`` and
    keeps iterating — that is the self-healing retry.

    The recoverable patterns are intentionally narrow: only the failures
    where the posture system has a clean 1:1 mapping to a transport
    flag. Anything else (wrong creds, expired ticket, KDC down) bubbles
    up unchanged.

    Returns ``None`` when the exception is not in the recoverable set,
    when the recovery would not change ``cfg`` (we already had the flag
    on), or when the recovery makes no sense for the current transport
    (CBT-on-plain-LDAP, for example).
    """
    import dataclasses as _dc

    chain_text = " ".join(
        f"{type(c).__name__}: {c}".lower() for c in _walk_exception_chain(exc)
    )

    # LDAP channel binding required — only meaningful on LDAPS, and only
    # if we did NOT already have CBT on. Signature inventory verified
    # against ``vendor/badldap/wintypes/winerror.py`` (0x80090346 →
    # SEC_E_BAD_BINDINGS, message "Client's supplied Security Support
    # Provider Interface (SSPI) channel bindings were incorrect.").
    # badldap's ``format_bind_error`` substitutes the raw hex with the
    # WINERROR code-name + message at exception-render time; we match
    # the rendered forms but keep the hex as a defensive fallback in
    # case any code path skips the formatter.
    cbt_signatures = (
        "sec_e_bad_bindings",
        "channel bindings were incorrect",
        "channel binding",
        "0x80090346",
        "80090346",
    )
    if (
        transport_was_ldaps
        and not cfg.channel_binding
        and any(sig in chain_text for sig in cbt_signatures)
    ):
        print_info_debug(
            "[ldap_transport] self-heal: bind failed with CBT signature, "
            "queuing retry with channel_binding=True"
        )
        return _dc.replace(cfg, channel_binding=True)

    # LDAP signing required — only meaningful on plain LDAP, and only
    # if we did NOT already have signing on.
    #
    # Signatures verified against ``vendor/badldap``:
    #   * ``badldap/commons/exceptions.py`` line 16 — LDAP result code 8
    #     renders as ``strongerAuthRequired``.
    #   * ``badldap/wintypes/winerror.py`` 0x00002028 — when AD adds the
    #     extended hex code, badldap's formatter replaces it with
    #     ``ERROR_DS_STRONG_AUTH_REQUIRED``.
    signing_signatures = (
        "strongerauthrequired",
        "error_ds_strong_auth_required",
        "0x00002028",
        # Samba/Heimdal AD with `ldap server require strong auth = yes` rejects a
        # GSS-SPNEGO bind that negotiates no SASL security layer with this phrasing
        # — and it does so even over LDAPS/StartTLS (TLS does NOT satisfy it).
        "sign or seal",
    )
    _signing_required = any(sig in chain_text for sig in signing_signatures)
    _on_tls = transport_was_ldaps or getattr(cfg, "use_starttls", False)
    if _signing_required and (_on_tls or not cfg.sign):
        if _on_tls:
            # The DC demands a SASL sign+seal security layer that a TLS-protected
            # channel cannot carry: RFC 4513 / MS-ADTS forbid negotiating a SASL
            # security layer once TLS is active (Windows rejects it; over LDAPS
            # ``sign`` is a documented no-op). Retrying signing on the SAME TLS
            # transport therefore loops to the identical rejection. Descend to
            # PLAIN LDAP/389 and negotiate GSS sign+seal there — the only rung
            # that satisfies `require strong auth = yes`. Verified against a live
            # Samba 4 AD DC: plain-LDAP + sign+seal binds where LDAPS-without-seal
            # is rejected with this exact error. Zero Windows regression: a
            # standard Windows DC accepts the LDAPS bind, so this path never runs
            # there; if a hardened Windows DC ever returned it, plain+seal also
            # satisfies Windows.
            print_info_debug(
                "[ldap_transport] self-heal: TLS rung rejected with sign/seal-"
                "required; descending to plain LDAP + SASL sign+seal"
            )
            # Clear channel_binding too: CBT is a TLS-only token (the vendor
            # derives it only on a true-LDAPS connection), so carrying it onto
            # the plain-LDAP descent is meaningless and just wastes a self-heal
            # hop. Dropping it lets the descent converge to SASL sign+seal in a
            # single retry.
            return _dc.replace(
                cfg,
                sign=True,
                use_ldaps=False,
                use_starttls=False,
                channel_binding=False,
            )
        print_info_debug(
            "[ldap_transport] self-heal: bind failed with signing-required "
            "signature, queuing retry with sign=True"
        )
        return _dc.replace(cfg, sign=True)

    return None


def _emit_ldap_failure_posture(
    config: "ADscanLDAPConfig",
    *,
    exc: BaseException,
    used_kerberos_auth: bool,
    transport_was_ldaps: bool,
) -> None:
    """Classify one LDAP bind failure and emit any matching posture signals.

    A single failure may match multiple rules — each emits a separate signal
    (the posture module deduplicates downstream). ``transport_was_ldaps``
    represents the user's transport intent (LDAPS vs plain LDAP) and is used
    to gate channel-binding detection (only meaningful on LDAPS).
    """
    chain_text = " ".join(
        f"{type(c).__name__}: {c}".lower() for c in _walk_exception_chain(exc)
    )
    # Rule 1 — LDAP signing required.
    #
    # Signatures inventory (vendor verification — see commit message):
    #   * ``strongerauthrequired`` — LDAP result code 8, the protocol-
    #     level signal RFC 4511 §4.2 defines for "client must upgrade".
    #     badldap renders it as the lowercased string above.
    #   * ``error_ds_strong_auth_required`` — AD-specific WINERROR
    #     0x00002028 surfaced through badldap's formatter when the DC
    #     attaches the extended hex code.
    #   * ``0x00002028`` — defensive raw-hex match in case any path
    #     bypasses the WINERROR translator.
    if (
        "strongerauthrequired" in chain_text
        or "error_ds_strong_auth_required" in chain_text
        or "0x00002028" in chain_text
    ):
        _emit_posture_signal(
            config,
            category=ConstraintCategory.LDAP_SIGNING,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STRONG_AUTH_REQUIRED",
            message="DC requires LDAP signing for unencrypted binds",
        )
    # Rule 2 — LDAP channel binding required (only meaningful on LDAPS).
    #
    # Signatures inventory (vendor verification):
    #   * ``sec_e_bad_bindings`` / ``channel bindings were incorrect``
    #     — WINERROR 0x80090346 surfaced via
    #     ``vendor/badldap/wintypes/winerror.py:15005``.
    #   * ``0x80090346`` — defensive raw-hex match if the formatter is
    #     bypassed.
    #   * ``channel binding`` — broad match for any phrasing variation
    #     the DC version might produce; safe because we already gate on
    #     ``transport_was_ldaps``.
    cbt_signatures = (
        "sec_e_bad_bindings",
        "channel bindings were incorrect",
        "channel binding",
        "0x80090346",
        "80090346",
    )
    if transport_was_ldaps and any(sig in chain_text for sig in cbt_signatures):
        _emit_posture_signal(
            config,
            category=ConstraintCategory.LDAP_CHANNEL_BINDING,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CHANNEL_BINDING_REQUIRED",
            message="DC enforces LDAP channel binding for LDAPS binds",
        )
    # Rule 3 — NTLM rejected via LDAP while a Kerberos TGT was valid.
    if (
        used_kerberos_auth
        and "invalidcredentials" in chain_text
        and "sec_e_logon_denied" in chain_text
    ):
        _emit_posture_signal(
            config,
            category=ConstraintCategory.NTLM_AUTHENTICATION,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="NTLM_REJECTED_VIA_LDAP",
            message=(
                "DC rejected NTLM bind with SEC_E_LOGON_DENIED while a "
                "Kerberos TGT was valid — NTLM appears disabled by policy"
            ),
        )


def _emit_ldap_success_posture(
    config: "ADscanLDAPConfig",
    *,
    used_kerberos_auth: bool,
    used_ldaps: bool,
    mechanism: "ConfidentialityMechanism | None" = None,
) -> None:
    """Emit posture signals for a successful LDAP bind.

    LDAPS success → ``LDAPS_AVAILABLE = ENABLED`` (HIGH).
    StartTLS-on-389 success → ``LDAP_STARTTLS_AVAILABLE = ENABLED`` (HIGH).
    NTLM (password) success → ``NTLM_AUTHENTICATION = ENABLED`` (MEDIUM).
    Kerberos success is intentionally not emitted: Kerberos is the default
    auth mechanism and its success carries no hardening signal.

    The ``mechanism`` confirmatory emit is an OBSERVATION (the DC actually
    StartTLS'd at bind time), so it is legitimate to cache. It mirrors the
    ``LDAPS_BIND_OK`` emit. We DELIBERATELY emit NOTHING for
    ``ConfidentialityMechanism.CLEARTEXT``: cleartext means "no confidential
    mechanism was available" — an absence / our-situation, not a DC
    observation. Caching an absence is forbidden (CLAUDE.md § Posture
    caching policy, Invariant 2). The cleartext outcome is surfaced only via
    the operator advisory (a separate, ephemeral CLI surface), never the
    posture cache.

    The reactive emits here leave ``probe_schema_version`` unset (``None``)
    via ``_emit_posture_signal`` — a reactive transport observation must not
    stamp/wipe the probe's schema version (CLAUDE.md § Schema-version
    invalidation); ``None`` is treated as version-agnostic and trusts the
    cache until the natural TTL expires.
    """
    if used_ldaps:
        _emit_posture_signal(
            config,
            category=ConstraintCategory.LDAPS_AVAILABLE,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_BIND_OK",
            message="LDAPS bind succeeded on port 636",
        )
    if mechanism is ConfidentialityMechanism.STARTTLS:
        _emit_posture_signal(
            config,
            category=ConstraintCategory.LDAP_STARTTLS_AVAILABLE,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_BIND_OK",
            message="StartTLS upgrade succeeded on LDAP/389 at bind time",
        )
    if not used_kerberos_auth:
        _emit_posture_signal(
            config,
            category=ConstraintCategory.NTLM_AUTHENTICATION,
            state=TriState.ENABLED,
            confidence=SignalConfidence.MEDIUM,
            signal_code="NTLM_BIND_OK",
            message="NTLM bind via LDAP succeeded",
        )


def _validate_rootdse_query(connection: Any) -> None:
    """Ensure one LDAP connection can execute a minimal rootDSE query."""
    attempts = (
        ["namingContexts"],
        ["defaultNamingContext"],
        ["*"],
    )
    last_exc: BaseException | None = None
    for attributes in attempts:
        try:
            search_result = connection.search(
                search_base="",
                search_filter="(objectClass=*)",
                attributes=attributes,
                search_scope="BASE",
            )
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            continue

        # Support ADscanLDAPConnection (.entries), ldap3 connections
        # (.connection.entries), and connections that return results directly from search().
        entries = getattr(connection, "entries", None)
        if entries is None:
            entries = getattr(getattr(connection, "connection", None), "entries", None)
        if isinstance(entries, list) and entries:
            return
        if isinstance(search_result, list) and search_result:
            return

    if last_exc is not None:
        raise LDAPTransportValidationError(
            "LDAP transport validation failed during rootDSE query"
        ) from last_exc
    raise LDAPTransportValidationError(
        "LDAP transport validation failed: rootDSE query returned no entries"
    )


def _diag_dump_ccache(ccache_path: str | Path | None) -> None:
    """Diagnostic: log TGT timestamps and clock skew to debug SEC_E_LOGON_DENIED."""
    import time

    try:
        path = Path(ccache_path) if ccache_path else None
        if not path or not path.exists():
            print_info_debug(f"ldap_transport diag: ccache missing: {ccache_path}")
            return

        from kerbad.common.ccache import CCACHE  # type: ignore

        ccache = CCACHE.from_file(str(path))
        now = time.time()
        now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
        creds = list(getattr(ccache, "credentials", []) or [])
        print_info_debug(
            f"[ldap_transport][diag] ccache={path} now={now_iso} creds={len(creds)}"
        )
        for idx, cred in enumerate(creds):
            try:
                times = getattr(cred, "time", None)
                authtime = getattr(times, "authtime", None)
                starttime = getattr(times, "starttime", None)
                endtime = getattr(times, "endtime", None)
                renew_till = getattr(times, "renew_till", None)
                server = getattr(cred, "server", None)
                spn = (
                    "/".join([c.to_string() for c in server.components])
                    if server is not None and getattr(server, "components", None)
                    else repr(server)
                )
                skew = (
                    f"{int(now - starttime)}s past starttime"
                    if isinstance(starttime, (int, float))
                    else "n/a"
                )
                expired = isinstance(endtime, (int, float)) and now > endtime
                print_info_debug(
                    f"[ldap_transport][diag] cred[{idx}] spn={spn} "
                    f"authtime={authtime} starttime={starttime} endtime={endtime} "
                    f"renew_till={renew_till} expired={expired} {skew}"
                )
            except Exception as exc:  # noqa: BLE001
                print_info_debug(
                    f"[ldap_transport][diag] cred[{idx}] dump failed: "
                    f"{type(exc).__name__}: {exc}"
                )
    except Exception as exc:  # noqa: BLE001
        print_info_debug(
            f"[ldap_transport][diag] ccache dump raised {type(exc).__name__}: {exc}"
        )


def _diag_dump_bind_exception(exc: BaseException) -> None:
    """Diagnostic: walk exception chain to surface Kerberos error under SEC_E_LOGON_DENIED."""
    try:
        chain = _walk_exception_chain(exc)
        for idx, e in enumerate(chain):
            print_info_debug(
                f"[ldap_transport][diag] exc[{idx}] type={type(e).__name__} repr={e!r}"
            )
            for attr in (
                "error_code",
                "errorCode",
                "result_code",
                "kerberos_error",
                "native_errno",
            ):
                val = getattr(e, attr, None)
                if val is not None:
                    print_info_debug(
                        f"[ldap_transport][diag] exc[{idx}].{attr}={val!r}"
                    )
    except Exception as inner:  # noqa: BLE001
        print_info_debug(
            f"[ldap_transport][diag] bind exception dump failed: "
            f"{type(inner).__name__}: {inner}"
        )


def _plain_ldap_can_seal(config: "ADscanLDAPConfig") -> bool:
    """Return whether a plain-LDAP (389) bind for *config* can negotiate sealing.

    Sealing (GSS-API confidentiality) over plain LDAP requires an authenticated
    SASL bind that establishes a GSS context — Kerberos (``use_kerberos=True``) or
    NTLM (a username plus a password/hash, via the non-simple-bind path). An
    anonymous bind or an RFC 4513 SIMPLE bind establishes no GSS context, so
    badldap cannot wrap (seal) any message regardless of the ``sign`` flag.

    Used only by the confidential-attribute policy in
    :func:`async_connect_with_ldap_fallback`; never gates non-confidential reads.
    """
    if config.use_kerberos:
        return True
    if config.use_simple_bind:
        # SIMPLE bind is RFC 4513 cleartext-over-transport; no GSS sealing.
        return False
    has_user = bool(str(config.username or "").strip())
    has_secret = bool(str(config.password or ""))
    # NTLM bind with credentials → SASL GSS-SPNEGO → can negotiate sealing.
    return has_user and has_secret


def _apply_default_seal_to_plain_ldap(
    configs_to_try: list[tuple["ADscanLDAPConfig", bool]],
) -> list[tuple["ADscanLDAPConfig", bool]]:
    """Seal authenticated plain-LDAP/389 attempts by default (OPSEC default).

    Walks the prepared transport attempts and, for every PLAIN-LDAP (port 389)
    attempt whose bind is AUTHENTICATED and GSS-capable (Kerberos or
    NTLM-with-creds, per :func:`_plain_ldap_can_seal`), forces ``sign=True`` so
    badldap negotiates GSS-API sign+seal and the bind/queries/results are
    encrypted on the wire instead of sent in cleartext.

    Strictly scoped — leaves untouched:

    - LDAPS/636 attempts (``is_ldaps=True``) — TLS already seals; ``sign`` is a
      harmless no-op there.
    - Anonymous / SIMPLE plain-LDAP attempts — they establish no GSS context
      and cannot seal; cleartext is unavoidable, so they pass through as-is.
    - Attempts whose caller already set ``sign=True`` — already sealed.
    - Attempts whose caller opted out via ``disable_default_seal=True``.
    - Attempts whose caller set ``disable_self_heal=True`` — failure-eliciting
      callers (posture probes) that need the raw, unsealed DC response.

    Each upgraded attempt gets the private ``_default_seal_applied=True`` marker
    so the fallback loop can tell a transport-applied DEFAULT seal apart from
    caller-requested ``sign=True`` -- only the former is degraded back to
    unsealed on a genuine seal-negotiation failure.

    Returns a new list; the input list is not mutated.
    """
    import dataclasses as _dc_seal

    upgraded: list[tuple["ADscanLDAPConfig", bool]] = []
    for cfg, is_ldaps in configs_to_try:
        if (
            is_ldaps
            # The StartTLS rung is already confidential at the transport layer
            # (TLS via RFC 2830); GSS sign+seal on top would be redundant and
            # can conflict, so leave it unsealed.
            or getattr(cfg, "use_starttls", False)
            or cfg.sign
            or getattr(cfg, "disable_default_seal", False)
            # ``disable_self_heal`` marks a failure-ELICITING caller (the posture
            # probes) that needs the RAW DC response — e.g. the LDAP-signing
            # probe deliberately binds unsigned on 389 to read back
            # ``strongerAuthRequired``. Sealing it would mask that answer, so the
            # same flag that suppresses the reactive self-heal also suppresses
            # this proactive seal upgrade.
            or getattr(cfg, "disable_self_heal", False)
            or not _plain_ldap_can_seal(cfg)
        ):
            upgraded.append((cfg, is_ldaps))
            continue
        sealed_cfg = _dc_seal.replace(cfg, sign=True, _default_seal_applied=True)
        upgraded.append((sealed_cfg, is_ldaps))
    return upgraded


def _config_requests_explicit_cbt(config: "ADscanLDAPConfig") -> bool:
    """Return whether *config* carries an EXPLICIT channel-binding intent.

    A caller that set either ``channel_binding=True`` (send the real CBT) or
    ``null_channel_binding=True`` (send a deliberately wrong CBT, used by the
    CBT posture probe) has expressed an explicit intent that always wins over
    the operational default-on policy below. Leaving both at their ``False``
    defaults means "no opinion" -- eligible for the proactive default.
    """
    return bool(config.channel_binding or config.null_channel_binding)


def _apply_default_cbt_to_authenticated_ldaps(
    configs_to_try: list[tuple["ADscanLDAPConfig", bool]],
) -> list[tuple["ADscanLDAPConfig", bool]]:
    """Send the real ``tls-server-end-point`` CBT on operational LDAPS binds.

    Hardened DCs with ``LdapEnforceChannelBinding=2`` reject an authenticated
    Kerberos/NTLM bind over LDAPS that carries no channel binding (the AP-REQ
    GSS checksum then advertises the 16-zero "no bindings" token) with
    ``SEC_E_BAD_BINDINGS``. The vendor cb_data computation in
    ``vendor/badldap/badldap/connection.py`` is correct but only runs when
    ``_disable_channel_binding is False`` -- which the transport sets from
    ``cfg.channel_binding``. Because that field defaults to ``False``, ADscan
    historically sent no CBT on the FIRST attempt and only flipped it on via
    the reactive self-heal AFTER a wasted failed round-trip.

    A correctly-computed ``tls-server-end-point`` CBT is accepted by EVERY
    Windows DC whether it enforces channel binding or not (the DC either
    validates it or ignores it), so sending it proactively is always safe and
    removes the wasted failure round-trip. This helper therefore forces
    ``channel_binding=True`` on every LDAPS rung of an OPERATIONAL,
    AUTHENTICATED bind so the real token is computed on the first try.

    Strictly scoped -- leaves untouched (so the posture CBT probe can still
    MEASURE enforcement, and explicit caller intent always wins):

    - Plain-LDAP / StartTLS rungs (``is_ldaps=False``) -- there is no LDAPS TLS
      cert to derive ``tls-server-end-point`` from; CBT is N/A.
    - Anonymous / SIMPLE binds (``not _plain_ldap_can_seal``) -- they establish
      no GSS context to carry a channel-binding token.
    - Probe / failure-eliciting callers (``disable_self_heal=True``) -- the CBT
      posture probe (U3) deliberately binds with no-CBT or wrong-CBT and
      ``disable_self_heal=True`` to read back ``SEC_E_BAD_BINDINGS`` and
      MEASURE enforcement. Forcing CBT on here would make the probe blind to
      the answer it exists to collect.
    - Callers that already expressed explicit CBT intent
      (``channel_binding`` or ``null_channel_binding`` set) -- respected
      unchanged via :func:`_config_requests_explicit_cbt`.

    Returns a new list; the input list is not mutated.
    """
    import dataclasses as _dc_cbt

    upgraded: list[tuple["ADscanLDAPConfig", bool]] = []
    for cfg, is_ldaps in configs_to_try:
        if (
            not is_ldaps
            or getattr(cfg, "disable_self_heal", False)
            or _config_requests_explicit_cbt(cfg)
            or not _plain_ldap_can_seal(cfg)
        ):
            upgraded.append((cfg, is_ldaps))
            continue
        upgraded.append((_dc_cbt.replace(cfg, channel_binding=True), is_ldaps))
    return upgraded


def _ldap_config_would_mint_fresh_tgt(config: "ADscanLDAPConfig") -> bool:
    """Return True when an authenticated LDAP bind would mint a NEW TGT.

    The badldap Kerberos auth kinds split into two families:

    * ``kerberos-ccache`` (explicit ``ccache_path`` or, as the last-resort
      slot, ``KRB5CCNAME``) — reuses an EXISTING ticket. No fresh AS-REQ is
      sent, so the salt is irrelevant and there is nothing to pre-mint.
    * ``kerberos-password`` / ``kerberos-aes`` / ``kerberos-rc4`` — badldap
      sends a FRESH AS-REQ and derives the key from the credential. badldap's
      ``get_TGT`` does NOT issue an ETYPE-INFO2 probe first, so on an AES-only
      KDC with a NON-DEFAULT salt the AES key is derived with the wrong
      (default) salt and the AS-REQ fails with ``KDC_ERR_PREAUTH_FAILED``.

    Only the second family needs the salt-aware pre-mint (FIX 1). This mirrors
    the auth-kind selection in :func:`_build_ldap_connection_url` exactly:
    ``ccache_path`` wins (slot 1), then ``aes_key`` (slot 2), then NT-hash
    (slot 3), then plaintext password (slot 4); ``KRB5CCNAME`` is the last
    resort (slot 5) and is intentionally NOT pre-minted so its legacy
    "reuse the ambient ticket" behaviour is preserved.
    """
    if not config.use_kerberos:
        return False
    # Slot 1: explicit ccache already reuses an existing ticket — never mint.
    if str(config.ccache_path or "").strip():
        return False
    # Slots 2/3/4: a fresh-mintable secret is present.
    if config.aes_key:
        return True
    password = str(config.password or "")
    if password:  # NT hash (kerberos-rc4) or plaintext (kerberos-password)
        return True
    # Slot 5 (KRB5CCNAME) or no credential at all — leave as-is.
    return False


async def _premint_kerberos_ccache_for_ldap(
    config: "ADscanLDAPConfig",
    *,
    connect_timeout: float | None = None,
) -> "ADscanLDAPConfig":
    """Pre-mint a TGT once and rewrite ``config`` to ``kerberos-ccache``.

    ``connect_timeout`` (when set) bounds the AS-REQ round-trip so an
    unreachable / un-authenticatable foreign realm (e.g. a cross-forest
    AES-only KDC the credential cannot satisfy) fails in a few seconds instead
    of hanging the caller for the kerbad default (~30s per AS-REQ × retries).
    The budget is applied BOTH as the ``KerberosConfig.timeout`` and as an
    overall ``asyncio.wait_for`` wrapper; a timeout falls back to the original
    config (best-effort, like every other pre-mint failure).

    FIX 1 — ladder-bind dedup (the value that remains after the vendor fix):
    an authenticated LDAPS→LDAP confidentiality ladder rebuilds the bind config
    for every rung. If each rung carries a fresh-mintable Kerberos secret
    (``kerberos-password`` / ``kerberos-aes`` / ``kerberos-rc4``), badldap →
    badauth → kerbad mints a brand-new TGT (a full AS-REQ round-trip) on EVERY
    rung. This helper mints ONCE up front, into a ccache, and switches the config
    to ``kerberos-ccache`` so every subsequent rung reuses the cached ticket
    instead of re-minting — one mint, many rungs.

    Salt-correctness is NO LONGER this helper's job: it is now guaranteed at the
    kerbad vendor layer. ``kerbad.aioclient.get_TGT`` runs the ETYPE-INFO2 salt
    probe-first for password creds, so a fresh badldap-driven mint on a
    non-default-salt KDC (e.g. ping.htb's ``PING.HTBC.Roberts``) already derives
    the correct AES key without this pre-mint. The pre-mint still routes through
    :func:`kerberos_transport.get_tgt` (which also probes and emits the posture
    signal), so the cached ticket is salt-correct on BOTH default-salt (common)
    and non-default-salt (hardened) domains; the behaviour is unchanged.

    Best-effort: if the pre-mint fails (bad credentials, KDC unreachable, etc.)
    the ORIGINAL config is returned unchanged so the bind surfaces the real
    error through the existing path rather than masking it. Genuine credential
    failures (``KDC_ERR_PREAUTH_FAILED`` from a wrong password) still surface on
    the subsequent bind attempt.

    Preserves:
      * ``kerberos-ccache`` binds — :func:`_ldap_config_would_mint_fresh_tgt`
        returns False for them, so this helper is never called.
      * NTLM / anonymous / SIMPLE binds — gated on ``use_kerberos`` upstream.
      * Cross-realm — ``auth_domain`` / ``auth_kdc`` map to the KerberosConfig
        auth-realm fields so the AS-REQ reaches the correct KDC.
      * The LDAPS→LDAP confidentiality ladder — every rung is rebuilt from the
        rewritten (ccache) config by ``dataclasses.replace`` downstream.
      * Clock-skew recovery — ``get_tgt`` calls ``with_clock_skew`` internally.
    """
    import tempfile as _tempfile
    from pathlib import Path as _Path

    from adscan_internal.services.kerberos_transport import (
        KerberosConfig,
        get_tgt,
    )

    # The Kerberos realm of the CREDENTIAL (auth domain), and the KDC that
    # serves it. For single-realm binds auth_domain/auth_kdc are unset and we
    # fall back to the target domain/DC. For cross-realm binds (ping → pong)
    # the TGT must be minted against the AUTH KDC.
    auth_realm = str(config.auth_domain or config.domain or "").strip()
    auth_kdc_ip = str(config.auth_kdc or config.dc_ip or "").strip()
    target_kdc_ip = str(config.dc_ip or "").strip()

    password = str(config.password or "")
    nt_hash = password if (password and _is_nt_hash(password)) else None
    plaintext = password if (password and not _is_nt_hash(password)) else None

    cross_realm = bool(
        config.auth_domain
        and config.auth_domain.strip().casefold()
        != str(config.domain or "").strip().casefold()
    )

    # Bound the AS-REQ when a connect budget was supplied so an unreachable /
    # un-authenticatable foreign realm fails fast instead of hanging for the
    # kerbad default (~30s × retries). Floor at 3s so a slow-but-alive KDC over
    # VPN is not falsely timed out (see adscan-ad-constraints § 7bis).
    _krb_timeout_kwargs: dict[str, Any] = {}
    if connect_timeout is not None:
        _krb_timeout_kwargs["timeout"] = max(3, int(connect_timeout))

    try:
        krb_cfg = KerberosConfig(
            domain=auth_realm,
            kdc_ip=auth_kdc_ip or target_kdc_ip,
            username=str(config.username or "").strip(),
            password=plaintext,
            nt_hash=nt_hash,
            aes_key=config.aes_key,
            etypes=config.etypes,
            # use_auth_kdc=True in get_tgt sends the AS-REQ to auth_kdc_ip when
            # set; for single-realm leave it None so kdc_ip is used for both.
            auth_kdc_ip=auth_kdc_ip if cross_realm else None,
            posture_sink=getattr(config, "posture_sink", None),
            posture_snapshot=getattr(config, "posture_snapshot", None),
            **_krb_timeout_kwargs,
        )
        print_info_debug(
            "[ldap_transport] pre-minting salt-correct TGT via kerberos_transport."
            f"get_tgt for user={mark_sensitive(krb_cfg.username, 'user')} "
            f"realm={mark_sensitive(auth_realm, 'domain')} "
            "(LDAP Kerberos bind would otherwise skip the ETYPE-INFO2 salt probe)"
        )
        if connect_timeout is not None:
            ccache_bytes = await asyncio.wait_for(
                get_tgt(krb_cfg), timeout=max(3.0, float(connect_timeout))
            )
        else:
            ccache_bytes = await get_tgt(krb_cfg)
    except Exception as exc:  # noqa: BLE001
        # Best-effort: do not mask the real error. Fall back to the original
        # config so the bind surfaces the authentic failure on its own path.
        telemetry.capture_exception(exc)
        print_info_debug(
            "[ldap_transport] Kerberos TGT pre-mint failed "
            f"({type(exc).__name__}: {exc}); falling back to the direct "
            "kerberos-password/aes/rc4 bind path"
        )
        return config

    # Persist the minted ccache to a private temp file for badldap.
    fd, tmp_path = _tempfile.mkstemp(suffix=".ccache", prefix="adscan_ldap_tgt_")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(ccache_bytes)
        _Path(tmp_path).chmod(0o600)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[ldap_transport] failed to persist pre-minted ccache: {exc}; "
            "falling back to the direct kerberos bind path"
        )
        with contextlib.suppress(Exception):
            os.unlink(tmp_path)
        return config

    import dataclasses as _dc_premint

    # Switch to kerberos-ccache: clear the fresh-mint secrets so the URL
    # builder selects ``kerberos-ccache`` (slot 1) and reuses our salt-correct
    # ticket. ccache_path takes priority over KRB5CCNAME in the URL builder.
    rewritten = _dc_premint.replace(
        config,
        ccache_path=tmp_path,
        password=None,
        aes_key=None,
    )
    print_info_debug(
        f"[ldap_transport] pre-minted TGT written ({len(ccache_bytes)} B); "
        "LDAP bind will reuse it as kerberos-ccache (salt-correct)"
    )
    return rewritten


def _ldap_credential_context_can_remint(cred_ctx: Any) -> bool:
    """True when *cred_ctx* carries secret material for a generic re-mint.

    Capability-bearing ESC13 PAC-TGTs and scoped S4U/RBCD/silver ServiceTickets
    flow through the explicit ``ccache_path`` branch WITHOUT a CredentialContext,
    so they never reach this gate — re-minting them would destroy the synthetic
    group SID / impersonated principal. We additionally require at least one
    re-mintable secret (password / NT hash / AES key) so a context with nothing
    to re-issue from does not register a no-op reminter.
    """
    if cred_ctx is None:
        return False
    for attr in ("password", "nt_hash", "aes_key"):
        if getattr(cred_ctx, attr, None):
            return True
    return False


def _make_ldap_expiry_reminter(cred_ctx: Any) -> "Callable[[], str | None]":
    """Build the realm reminter closure used by the Kerberos expiry recovery.

    The closure is SYNCHRONOUS (the recovery layer calls it from inside an
    active event loop) so it drives the async ``refresh_if_stale(force=True)``
    on a private off-loop thread via :func:`run_async_sync`. Returns the path to
    the freshly minted ccache, or ``None`` when the re-mint produced nothing.
    """

    def _reminter() -> str | None:
        try:
            run_async_sync(cred_ctx.refresh_if_stale(force=True))
        except Exception as exc:  # noqa: BLE001 — never mask the original expiry error
            print_info_debug(
                "[ldap_transport] expiry reminter re-mint raised "
                f"{type(exc).__name__}: {exc}"
            )
            return None
        return getattr(cred_ctx, "ccache_path", None)

    return _reminter


async def _premint_via_credential_context(
    config: "ADscanLDAPConfig",
    cred_ctx: Any,
) -> "ADscanLDAPConfig":
    """Salt-correct pre-mint routed through the bound CredentialContext.

    SSOT reconciliation (B1): when a :class:`CredentialContext` is present and
    the bind would otherwise mint a FRESH TGT (no ``ccache_path``), do NOT spin
    up a separate ``/tmp/adscan_ldap_tgt_*.ccache`` via
    :func:`_premint_kerberos_ccache_for_ldap`. Instead drive the mint through
    the context's own ``refresh_if_stale(force=True)``, then point
    ``config.ccache_path`` at the context's canonical *workspace* ccache.

    Why this is correct AND salt-correct:
      * ``CredentialContext.refresh_if_stale`` -> ``KerberosTicketService.
        auto_generate_tgt`` -> ``kerberos_transport.get_tgt`` — the SAME
        salt-probing (ETYPE-INFO2), posture-aware path the /tmp pre-mint used.
        AES-only KDCs with a non-default salt derive the correct key either way.
      * The result is ONE canonical per-user ccache shared by: this pre-mint,
        the pre-bind ``refresh_if_stale()`` (which now no-ops — the ccache it
        just wrote is not stale), the expiry reminter (``refresh_if_stale
        (force=True)`` writes the SAME workspace path), and the live bind. No
        orphaned /tmp temp, no redundant double re-mint to a file the bind
        never reads.

    Best-effort: if the context could not produce a ccache (no re-mintable
    secret, missing ``workspace_dir``, mint failure) we fall back to the
    standalone /tmp pre-mint so the salt-correct behaviour is never lost. The
    capability-bearing / scoped-ticket axis never reaches here: those flow
    through the explicit ``ccache_path`` branch with no CredentialContext, so
    ``_ldap_config_would_mint_fresh_tgt`` already returned False upstream.
    """
    import dataclasses as _dc_ctx_premint

    try:
        # force=True: the bind is about to fire and we have nothing cached on
        # this config (no ccache_path), so mint unconditionally rather than let
        # the staleness heuristic skip it and leave the bind credential-less.
        await cred_ctx.refresh_if_stale(force=True)
    except Exception as exc:  # noqa: BLE001 — never mask the real bind error
        telemetry.capture_exception(exc)
        print_info_debug(
            "[ldap_transport] CredentialContext pre-mint raised "
            f"{type(exc).__name__}: {exc}; falling back to the standalone "
            "/tmp salt-correct pre-mint"
        )
        return await _premint_kerberos_ccache_for_ldap(config)

    ctx_path = str(getattr(cred_ctx, "ccache_path", None) or "").strip()
    if not ctx_path:
        # The context had no re-mintable secret or could not persist a ccache.
        # Preserve salt-correctness via the standalone /tmp pre-mint path.
        print_info_debug(
            "[ldap_transport] CredentialContext produced no ccache; falling "
            "back to the standalone /tmp salt-correct pre-mint"
        )
        return await _premint_kerberos_ccache_for_ldap(config)

    # Switch to kerberos-ccache on the SHARED workspace ccache. Clear the
    # fresh-mint secrets so the URL builder selects ``kerberos-ccache`` (slot 1)
    # and reuses this one salt-correct ticket — identical to the /tmp path,
    # except the path is the context's canonical per-user ccache, so the
    # pre-bind refresh and the expiry reminter all converge on the same file.
    rewritten = _dc_ctx_premint.replace(
        config,
        ccache_path=ctx_path,
        password=None,
        aes_key=None,
    )
    print_info_debug(
        "[ldap_transport] pre-minted salt-correct TGT via CredentialContext; "
        "LDAP bind, pre-bind refresh, and expiry reminter share the canonical "
        f"workspace ccache {mark_sensitive(ctx_path, 'path')} (no /tmp temp)"
    )
    return rewritten


async def async_connect_with_ldap_fallback(
    config: "ADscanLDAPConfig",
    *,
    connect_timeout: float | None = None,
    bind_only: bool = False,
) -> "LDAPConnectResult":
    """Async LDAP confidentiality ladder for native badldap consumers.

    Preferred over direct ``LDAPConnectionFactory.from_url()`` calls because it:
    - Walks the confidentiality ladder LDAPS(636) -> LDAP/389+StartTLS ->
      LDAP/389+SASL sign+seal -> cleartext(last resort)
    - Detects TLS transport failures via :func:`is_ldaps_transport_failure`
    - Detects StartTLS unavailability via :func:`_is_starttls_unavailable`
    - Retries transparently down the ladder
    - Handles cross-domain referrals when ``config.auth_domain``/``config.auth_kdc`` are set

    Args:
        config: LDAP connection config. Set ``config.use_ldaps = True`` (the default);
            the fallback will downgrade to ``False`` automatically if LDAPS is unavailable.
        connect_timeout: Optional per-transport connect budget in seconds. When set,
            each ``conn.connect()`` is wrapped in ``asyncio.wait_for`` so a silently
            DROPped LDAPS:636 port surfaces a ``TimeoutError`` (classified as a
            transport failure by :func:`is_ldaps_transport_failure`) and the fallback
            proceeds to plain LDAP:389 instead of hanging. ``None`` (default) preserves
            the legacy unbounded-connect behaviour for authenticated callers that rely
            on the underlying transport's own timeouts.
        bind_only: When ``True``, stop after the LDAP bind and return the bound
            client WITHOUT running the post-bind rootDSE discovery
            (``get_serverinfo`` / ``get_ad_info``). Used by the posture probes
            (U2 LDAP signing, U3 channel binding) which must read the raw bind
            result code to classify transport policy: a RestrictAnonymous DC
            answers the post-bind rootDSE search with ``operationsError
            (ERROR_NOT_AUTHENTICATED)``, masking the bind-level answer
            (``strongerAuthRequired`` for signing-required, or bind success for
            not-required). ``False`` (default) preserves the full discovery for
            normal callers that need ``serverinfo`` / naming contexts.

    Returns:
        :class:`LDAPConnectResult` carrying the live ``MSLDAPClient``
        (``.client``) and the :class:`ConfidentialityMechanism` that
        sealed it (``.mechanism``). The result is iterable as the legacy
        ``(client, used_ldaps)`` 2-tuple and exposes a ``.used_ldaps``
        property, so existing callers that unpack ``conn, used_ldaps =
        await ...`` keep working unchanged.

    Raises:
        Exception: last connection error when every ladder rung fails.
    """
    modules = _load_badldap_modules()
    LDAPConnectionFactory = modules["LDAPConnectionFactory"]

    # ---- FIX 1: salt-aware Kerberos TGT pre-mint ----------------------------
    # When the bind would mint a FRESH TGT (kerberos-password / -aes / -rc4),
    # badldap's get_TGT skips the ETYPE-INFO2 salt probe, so on an AES-only KDC
    # with a non-default salt the AES key is derived wrong and the AS-REQ fails
    # with KDC_ERR_PREAUTH_FAILED. Pre-mint the TGT via the salt-probing
    # ``kerberos_transport.get_tgt`` into a ccache FIRST, then bind as
    # ``kerberos-ccache`` so EVERY rung of the ladder below reuses one
    # salt-correct ticket. ccache-based and non-Kerberos binds are untouched.
    if _ldap_config_would_mint_fresh_tgt(config):
        # SSOT reconciliation (B1): when a CredentialContext is bound, route the
        # salt-correct pre-mint THROUGH it so the resulting ccache is the
        # context's canonical per-user workspace ccache — shared by the bind,
        # the pre-bind ``refresh_if_stale()`` below, and the expiry reminter. No
        # orphaned /tmp temp and no redundant double re-mint. The standalone
        # /tmp pre-mint is kept for the no-context case (and as a fallback when
        # the context cannot mint). Capability-bearing ESC13 PAC-TGTs and scoped
        # S4U/RBCD/silver ServiceTickets never reach here: they carry an
        # explicit ``ccache_path`` (slot 1) with no CredentialContext, so
        # ``_ldap_config_would_mint_fresh_tgt`` already returned False.
        _premint_cred_ctx = getattr(config, "credential_context", None)
        if _ldap_credential_context_can_remint(_premint_cred_ctx):
            config = await _premint_via_credential_context(config, _premint_cred_ctx)
        else:
            config = await _premint_kerberos_ccache_for_ldap(
                config, connect_timeout=connect_timeout
            )
    # ------------------------------------------------------------------------

    # ---- Build the confidentiality ladder (per LDAP connection) -------------
    # Order, strongest-confidentiality-first:
    #   1. LDAPS (636)               — TLS transport; works for ANY bind
    #   2. LDAP/389 + StartTLS        — TLS post-upgrade (RFC 2830); ANY bind,
    #                                   incl. anonymous/SIMPLE; needs a DC cert,
    #                                   no channel binding required
    #   3. LDAP/389 + SASL sign+seal  — GSS app-layer seal; AUTHENTICATED only;
    #                                   no cert needed (applied below by
    #                                   ``_apply_default_seal_to_plain_ldap``)
    #   4. LDAP/389 cleartext         — last resort (degrade hook / anon no-cert)
    # StartTLS sits ABOVE SASL-seal because it covers anonymous/SIMPLE binds
    # (no GSS context) and 636-filtered-but-cert-present DCs, and needs no CBT.
    configs_to_try: list[tuple["ADscanLDAPConfig", bool]] = []
    import dataclasses as _dc
    if config.use_ldaps:
        configs_to_try.append((config, True))
        # Rung 2: plain 389 + StartTLS, between LDAPS and the seal/cleartext rung.
        starttls_config = _dc.replace(config, use_ldaps=False, use_starttls=True)
        configs_to_try.append((starttls_config, False))
        # Rung 3/4: plain 389 (seal-by-default upgrades authenticated binds;
        # degrade hook drops to cleartext if the DC cannot seal).
        plain_config = _dc.replace(config, use_ldaps=False, use_starttls=False)
        configs_to_try.append((plain_config, False))
    elif config.use_starttls:
        # Caller explicitly asked for StartTLS on 389 — honour it, with a plain
        # 389 fallback below if StartTLS is unavailable.
        configs_to_try.append((config, False))
        plain_config = _dc.replace(config, use_starttls=False)
        configs_to_try.append((plain_config, False))
    else:
        configs_to_try.append((config, False))

    # ---- PR6b: posture-driven plan pruning ---------------------------------
    # When the caller threaded a ``posture_snapshot`` into the config, consult
    # ``auth_plan.build_ldap_auth_plan`` and prune the speculative chain to
    # only the transport+auth combinations the posture says are viable. When
    # ``posture_snapshot`` is ``None`` the conservative chain above is used
    # unchanged (byte-identical with pre-PR6b behaviour).
    if getattr(config, "posture_snapshot", None) is not None:
        from adscan_internal.services.auth_plan import (
            LDAPTransport as _PlanTransport,
            NoViableLDAPAuthError,
            _has_high_confidence,
            build_ldap_auth_plan,
        )
        from adscan_internal.services.domain_posture import (
            ConstraintCategory as _PlanConstraint,
            TriState as _PlanTriState,
        )
        import dataclasses as _dc_plan

        plan = build_ldap_auth_plan(config=config, posture=config.posture_snapshot)
        if plan.is_empty:
            note = plan.notes[0] if plan.notes else "no viable LDAP auth combinations"
            raise NoViableLDAPAuthError(note)

        plan_transports = {att.transport for att in plan.attempts}
        # Field overrides from the plan (CBT on LDAPS, signing on LDAP) are
        # taken from the first attempt of each transport, since the planner
        # only ever produces one attempt per transport per primary scheme in
        # PR6b's LDAP-only scope.
        ldaps_overrides = next(
            (a for a in plan.attempts if a.transport is _PlanTransport.LDAPS), None
        )
        ldap_overrides = next(
            (a for a in plan.attempts if a.transport is _PlanTransport.LDAP), None
        )

        # §1.F — teach the ladder the StartTLS rung. When posture HIGH-knows
        # StartTLS is unavailable (refused / port-closed / cert-broken, observed
        # by the P2 ``LDAP_STARTTLS_AVAILABLE`` probe) drop the StartTLS rung so
        # the ladder does not waste a round-trip on a doomed StartTLS
        # extendedReq before falling to SASL-seal. ENABLED HIGH keeps it ordered
        # above SASL-seal (the existing ladder order); UNKNOWN / LOW / absent
        # keeps it (conservative baseline — never prune on non-observed state,
        # identical discipline to ``_has_high_confidence``). The planner's own
        # rules (LDAPS / CBT / signing / NTLM / RC4) are untouched below.
        starttls_state = config.posture_snapshot.get(
            _PlanConstraint.LDAP_STARTTLS_AVAILABLE
        )
        starttls_disabled_high = (
            _has_high_confidence(
                starttls_state.effective_state, starttls_state.confidence
            )
            and starttls_state.effective_state is _PlanTriState.DISABLED
        )

        pruned: list[tuple["ADscanLDAPConfig", bool]] = []
        for cfg, is_ldaps in configs_to_try:
            transport_key = _PlanTransport.LDAPS if is_ldaps else _PlanTransport.LDAP
            if transport_key not in plan_transports:
                continue
            # The StartTLS rung carries its own transport-layer confidentiality
            # (TLS via RFC 2830) and needs neither GSS sign+seal nor channel
            # binding, so it is preserved as-is — applying the plan's
            # ``sign``/``channel_binding`` overrides to it would double-wrap
            # the connection. The plan overrides only shape the LDAPS and the
            # plain SASL-seal rungs.
            if getattr(cfg, "use_starttls", False):
                if starttls_disabled_high:
                    # Observed-unavailable StartTLS — drop the rung. LDAPS,
                    # SASL-seal, and cleartext rungs are untouched.
                    continue
                pruned.append((cfg, is_ldaps))
                continue
            override = ldaps_overrides if is_ldaps else ldap_overrides
            if override is not None and (
                override.channel_binding != cfg.channel_binding
                or override.sign != cfg.sign
            ):
                cfg = _dc_plan.replace(
                    cfg,
                    channel_binding=override.channel_binding,
                    sign=override.sign,
                )
            pruned.append((cfg, is_ldaps))
        configs_to_try = pruned
        if not configs_to_try:
            raise NoViableLDAPAuthError(
                "Posture pruning produced no viable LDAP transport"
            )
    # ------------------------------------------------------------------------

    # ---- Seal authenticated plain-LDAP/389 by default (OPSEC default) ---------
    # When LDAPS/636 is unavailable and the transparent fallback drops to plain
    # LDAP/389, an AUTHENTICATED bind + its queries + its results would travel
    # in CLEARTEXT unless the DC happens to require signing. For a security tool
    # operating in sensitive internal AD, that is a confidentiality exposure
    # (passive sniffing). We pre-empt the reactive ``strongerAuthRequired``
    # retry by forcing GSS-API sign+seal on every authenticated, GSS-capable
    # plain-LDAP attempt. Anonymous/SIMPLE binds cannot seal and are left as-is;
    # LDAPS is untouched (TLS already seals). Callers may opt out via
    # ``disable_default_seal`` or by explicitly setting ``sign``.
    configs_to_try = _apply_default_seal_to_plain_ldap(configs_to_try)
    # ---------------------------------------------------------------------------

    # ---- Send the real CBT on operational authenticated LDAPS binds -----------
    # Hardened DCs (LdapEnforceChannelBinding=2) reject an authenticated LDAPS
    # bind that carries no channel binding with SEC_E_BAD_BINDINGS. A correctly
    # computed ``tls-server-end-point`` CBT is accepted by EVERY Windows DC
    # whether it enforces CBT or not, so sending it proactively on the FIRST
    # attempt is always safe and removes the wasted failed round-trip that the
    # reactive self-heal would otherwise incur. Strictly scoped to LDAPS rungs of
    # OPERATIONAL authenticated binds -- the CBT posture probe (disable_self_heal
    # =True) and any caller with explicit channel_binding/null_channel_binding
    # intent are left untouched so the probe can still MEASURE enforcement. See
    # :func:`_apply_default_cbt_to_authenticated_ldaps` for the full rule.
    configs_to_try = _apply_default_cbt_to_authenticated_ldaps(configs_to_try)
    # ---------------------------------------------------------------------------

    # Refresh stale Kerberos ticket once before the LDAPS/LDAP attempts.  The
    # refresh result applies to every fallback attempt below — both transports
    # use the same ccache.  Errors are swallowed by ``refresh_if_stale`` itself,
    # so the bind can still surface the canonical auth error if the refresh
    # could not run.
    cred_ctx = getattr(config, "credential_context", None)
    if cred_ctx is not None:
        try:
            refreshed = await cred_ctx.refresh_if_stale()
            if refreshed:
                # Propagate the new ccache path into every prepared config.
                refreshed_path = getattr(cred_ctx, "ccache_path", None)
                if refreshed_path:
                    import dataclasses as _dc_refresh

                    configs_to_try = [
                        (_dc_refresh.replace(c, ccache_path=refreshed_path), is_l)
                        for (c, is_l) in configs_to_try
                    ]
        except Exception as exc:  # noqa: BLE001
            print_info_debug(
                f"[ldap_transport] credential refresh raised {type(exc).__name__}: {exc}"
            )
    elif config.use_kerberos and config.ccache_path:
        # Legacy call site — flag once so we can migrate it later.
        print_info_debug(
            "[ldap_transport] kerberos bind without CredentialContext; "
            "PAC freshness not guaranteed (legacy ccache path)"
        )
        _diag_dump_ccache(config.ccache_path)

    # ---- Confidential-attribute sealing policy --------------------------------
    # When the caller is reading a CONFIDENTIAL attribute (gMSA managed password,
    # etc.) the channel MUST be sealed or the DC refuses the value with
    # ``ERROR_DS_CONFIDENTIALITY_REQUIRED``. LDAPS is sealed by TLS. Plain LDAP is
    # sealed ONLY when an authenticated GSS bind (Kerberos or NTLM) negotiates
    # confidentiality — which badldap does iff ``_disable_signing`` is False, i.e.
    # ``cfg.sign=True``. An anonymous / SIMPLE bind establishes no GSS context and
    # can never seal, so that plain-LDAP attempt is dropped entirely.
    #
    # The general (non-confidential) LDAPS->LDAP downgrade is untouched: this block
    # only runs when ``config.require_confidential`` is True.
    confidential_dropped_unsealed = False
    if getattr(config, "require_confidential", False):
        import dataclasses as _dc_conf

        sealed_configs: list[tuple["ADscanLDAPConfig", bool]] = []
        for cfg, is_ldaps in configs_to_try:
            if is_ldaps:
                # LDAPS is sealed by TLS — accept unchanged.
                sealed_configs.append((cfg, is_ldaps))
                continue
            if getattr(cfg, "use_starttls", False):
                # StartTLS provides transport-layer confidentiality (TLS via
                # RFC 2830) for ANY bind, including anonymous/SIMPLE. It is a
                # VALID confidential rung — so a 636-filtered-but-cert-present
                # DC can still read gMSA/LAPS over StartTLS even without a GSS
                # sealing context. Accept unchanged; if StartTLS turns out to
                # be unavailable at connect time, the rung fails and the loop
                # falls through to the SASL-seal rung below.
                sealed_configs.append((cfg, is_ldaps))
                continue
            if not _plain_ldap_can_seal(cfg):
                # Anonymous / SIMPLE bind over plain LDAP can never seal.
                confidential_dropped_unsealed = True
                continue
            # Force sign+seal so badldap negotiates GSS confidentiality (389).
            sealed_cfg = (
                cfg if cfg.sign else _dc_conf.replace(cfg, sign=True)
            )
            sealed_configs.append((sealed_cfg, is_ldaps))
        if confidential_dropped_unsealed:
            print_info_debug(
                "[ldap_transport] confidential read: dropped unsealed plain-LDAP "
                "attempt (anonymous/SIMPLE bind cannot negotiate sealing)"
            )
        if not sealed_configs:
            raise ConfidentialChannelUnavailableError(
                "gMSA / confidential-attribute read requires a sealed channel, "
                "but none is available: LDAPS (port 636) is unreachable and no "
                "authenticated (Kerberos or NTLM) bind is configured to negotiate "
                "LDAP sign+seal on port 389. The managed password cannot be read "
                "over an unsealed plain-LDAP channel. Provide credentials for an "
                "authenticated bind, or restore LDAPS reachability to the DC."
            )
        configs_to_try = sealed_configs
    # ---------------------------------------------------------------------------

    # Register a realm-scoped expiry reminter so a mid-bind
    # KRB_AP_ERR_TKT_EXPIRED on a ccache-only Kerberos bind can be re-minted
    # transparently (real 12h ticket expiry, not clock skew). Only the GENERIC
    # shell-aware branch qualifies: a CredentialContext carrying re-mintable
    # secret material. Capability-bearing ESC13 PAC-TGTs and scoped S4U/RBCD
    # ServiceTickets flow without a CredentialContext, so they are never
    # registered (re-minting would destroy their synthetic SID / impersonation).
    # Always deregistered in the finally so it never leaks across operations or
    # principals.
    _expiry_reminter_realm: str | None = None
    if _ldap_credential_context_can_remint(cred_ctx):
        _expiry_reminter_realm = str(
            getattr(cred_ctx, "auth_domain", None) or config.domain or ""
        ).strip()
        if _expiry_reminter_realm:
            _kerberos_recovery.register_expiry_reminter(
                _expiry_reminter_realm, _make_ldap_expiry_reminter(cred_ctx)
            )

    # NTLM last-resort rung for a caller-requested-Kerberos bind that dead-ends
    # on a residual Kerberos AP-exchange rejection (the GSSAPI-wrapped KRB-ERROR
    # envelope, "AP EXCHANGE REJECTED BY SERVER"). This mirrors the SMB planner
    # grant (build_smb_plan / build_winrm_plan) elevated to the planner SSOT so
    # all caller-requested-Kerberos transports inherit the same defensive
    # recovery. It is built here (NOT placed in the eager ``configs_to_try``) and
    # injected ONLY at loop exhaustion, gated on the AP-exchange infra marker —
    # so it NEVER fires on KDC_ERR_ETYPE_NOTSUPP / KRB_AP_ERR_SKEW /
    # KRB_AP_ERR_MODIFIED (those own dedicated recovery: ETYPE-INFO2 mint,
    # clock-resync, SPN-candidate). Posture-gated: skipped when NTLM is known
    # DISABLED HIGH (capability-bearing ccache binds excluded — they carry an
    # explicit ccache the NTLM rung cannot reproduce).
    _ntlm_last_resort_cfg: "ADscanLDAPConfig | None" = None
    if (
        config.use_kerberos
        and not _ldap_ntlm_disabled_high(getattr(config, "posture_snapshot", None))
        and not str(getattr(config, "ccache_path", "") or "").strip()
        and not getattr(config, "aes_key", None)
    ):
        import dataclasses as _dc_ntlm_lr

        _ntlm_last_resort_cfg = _dc_ntlm_lr.replace(
            config,
            use_kerberos=False,
            ccache_path=None,
            aes_key=None,
            channel_binding=False,
        )

    try:
        last_exc: Exception | None = None
        last_attempt_was_ldaps: bool = False
        ldaps_disabled_emitted: bool = False
        # One-shot budget for the NTLM last-resort rung (see above). A single
        # injected attempt — never a loop.
        _ntlm_last_resort_used: bool = False

        # Self-healing retry budget. For each recoverable posture category
        # (CBT, LDAP signing) we allow EXACTLY ONE injected retry per
        # ``async_connect_with_ldap_fallback`` invocation. The budget is
        # global to the loop so a CBT failure cannot cascade into a CBT
        # retry that ALSO fails with CBT and triggers a third attempt. The
        # bound is intentional: anything beyond "fail once, learn, fix
        # once" is a sign that posture inference is broken and we want a
        # loud error, not an infinite loop.
        _self_heal_used: set[str] = set()
        # Separate one-shot budget for the seal-by-default DEGRADE retry
        # (sealed authenticated plain-LDAP -> unsealed) so it can never
        # interact with or exhaust the signing/CBT self-heal budget above.
        _seal_degrade_used: bool = False
        # We iterate with an index so that injected attempts (appended to
        # ``configs_to_try`` mid-iteration) participate naturally in the
        # loop instead of needing a recursive call.
        cfg_index = 0
        while cfg_index < len(configs_to_try):
            cfg, is_ldaps = configs_to_try[cfg_index]
            cfg_index += 1
            transport_label = "LDAPS" if is_ldaps else "LDAP"
            last_attempt_was_ldaps = is_ldaps
            try:
                url, requires_cross_target = _build_ldap_connection_url(cfg)
                if cfg.use_kerberos:
                    _host_for_spn = str(
                        cfg.tls_sni or cfg.kerberos_target_hostname or cfg.dc_ip or ""
                    ).strip()
                    _is_ip_spn = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", _host_for_spn))
                    print_info_debug(
                        f"[ldap_transport][diag] kerberos SPN host={_host_for_spn!r} "
                        f"is_ip={_is_ip_spn} kerberos_target_hostname="
                        f"{cfg.kerberos_target_hostname!r} tls_sni={cfg.tls_sni!r} "
                        f"dc_ip={cfg.dc_ip!r}"
                    )
                factory = LDAPConnectionFactory.from_url(url)

                if cfg.use_kerberos:
                    target_host = str(
                        cfg.tls_sni or cfg.kerberos_target_hostname or ""
                    ).strip()
                    conn = factory.get_client_newtarget(
                        hostname_or_ip=target_host,
                        ip=cfg.dc_ip,
                        new_domain=cfg.domain if requires_cross_target else None,
                        old_target_ip=str(cfg.auth_kdc or cfg.dc_ip or "").strip() or None,
                    )
                elif requires_cross_target:
                    target_host = str(
                        cfg.kerberos_target_hostname or cfg.dc_ip or ""
                    ).strip()
                    conn = factory.get_client_newtarget(
                        hostname_or_ip=target_host,
                        ip=cfg.dc_ip,
                        new_domain=cfg.domain,
                        old_target_ip=str(cfg.auth_kdc or cfg.dc_ip or "").strip() or None,
                    )
                else:
                    conn = factory.get_client()

                if hasattr(conn, "_disable_signing"):
                    conn._disable_signing = not cfg.sign
                if hasattr(conn, "_disable_channel_binding"):
                    # CBT is driven solely by ``cfg.channel_binding`` so an explicit
                    # CBT requirement (e.g. a SEC_E_BAD_BINDINGS self-heal retry, or
                    # the operational LDAPS default-on set by
                    # ``_apply_default_cbt_to_authenticated_ldaps``) is never silently
                    # dropped. On a StartTLS rung the vendor cb_data computation is
                    # gated on ``protocol == CLIENT_SSL_TCP`` (true LDAPS only), so a
                    # non-LDAPS StartTLS connection never derives a token regardless
                    # of this flag -- meaning we do NOT need to force-disable CBT for
                    # StartTLS here, and doing so would defeat an explicit CBT-required
                    # retry that lands on an LDAPS rung. ``channel_binding`` is left at
                    # its False default for StartTLS/plain rungs (see
                    # ``_apply_default_cbt_to_authenticated_ldaps``, which skips them),
                    # so this stays a no-op there.
                    conn._disable_channel_binding = not cfg.channel_binding
                if hasattr(conn, "_null_channel_binding"):
                    conn._null_channel_binding = cfg.null_channel_binding
                if hasattr(conn, "_use_starttls"):
                    # Tell badldap to upgrade the plain 389 session to TLS via
                    # StartTLS BEFORE bind when this rung requested it.
                    conn._use_starttls = bool(cfg.use_starttls)
                if bind_only and hasattr(conn, "_bind_only"):
                    # BIND-ONLY mode: stop after the LDAP bind, skip the
                    # post-bind rootDSE discovery. Used by the posture probes so
                    # they read the raw bind result code (strongerAuthRequired vs
                    # success) instead of a downstream rootDSE search that a
                    # RestrictAnonymous DC answers with operationsError
                    # (ERROR_NOT_AUTHENTICATED), which would mask the policy
                    # answer. See vendor/badldap/badldap/client.py bind_only.
                    conn._bind_only = True

                if connect_timeout is not None:
                    ok, err = await asyncio.wait_for(
                        conn.connect(), timeout=connect_timeout
                    )
                else:
                    ok, err = await conn.connect()
                if not ok:
                    raise err or RuntimeError(
                        f"{transport_label} connect returned ok=False"
                    )

                # Determine which confidentiality mechanism sealed this channel.
                #   LDAPS (636) ......... TLS transport
                #   StartTLS (389) ...... TLS post-upgrade (RFC 2830)
                #   SASL sign+seal (389)  GSS app-layer (``sign=True`` on 389)
                #   cleartext (389) ..... none (unsealed plain bind)
                if is_ldaps:
                    mechanism = ConfidentialityMechanism.LDAPS
                elif getattr(cfg, "use_starttls", False):
                    mechanism = ConfidentialityMechanism.STARTTLS
                elif cfg.sign:
                    mechanism = ConfidentialityMechanism.SASL_SEAL
                else:
                    mechanism = ConfidentialityMechanism.CLEARTEXT
                conn_label = (
                    "LDAP+StartTLS"
                    if (not is_ldaps and getattr(cfg, "use_starttls", False))
                    else transport_label
                )
                print_info_debug(
                    f"[ldap_transport] async connect: {conn_label} on {cfg.dc_ip} "
                    f"(confidentiality={mechanism.value})"
                )
                _emit_ldap_success_posture(
                    config,
                    used_kerberos_auth=cfg.use_kerberos,
                    used_ldaps=is_ldaps,
                    mechanism=mechanism,
                )
                return LDAPConnectResult(client=conn, mechanism=mechanism)

            except Exception as exc:
                last_exc = exc
                _diag_dump_bind_exception(exc)
                if is_ldaps and is_ldaps_transport_failure(exc):
                    if not ldaps_disabled_emitted:
                        _emit_posture_signal(
                            config,
                            category=ConstraintCategory.LDAPS_AVAILABLE,
                            state=TriState.DISABLED,
                            confidence=SignalConfidence.HIGH,
                            signal_code="LDAPS_TRANSPORT_FAILURE",
                            message=(
                                "LDAPS port unreachable or TLS handshake failed — "
                                "domain does not expose LDAPS"
                            ),
                        )
                        ldaps_disabled_emitted = True
                    print_info_debug(
                        f"ldap_transport: LDAPS unavailable on {config.dc_ip}, retrying on plain LDAP"
                    )
                    continue

                # StartTLS rung fall-through. When THIS attempt requested StartTLS
                # on plain 389 and the upgrade was refused / no usable DC cert is
                # present (``_is_starttls_unavailable``), fall THROUGH to the next
                # rung — the SASL sign+seal rung (authenticated) or the cleartext
                # last-resort — instead of emitting a failure or raising. A bare
                # TCP/389 failure is NOT a StartTLS-availability signal and is
                # handled by the normal failure path below. This is purely a
                # confidentiality-mechanism fallback, not an auth failure, so it
                # must not emit ``_emit_ldap_failure_posture``.
                if (
                    not is_ldaps
                    and getattr(cfg, "use_starttls", False)
                    and _is_starttls_unavailable(exc)
                ):
                    print_info_debug(
                        f"[ldap_transport] StartTLS unavailable on {config.dc_ip} "
                        f"(no DC cert on 389 / not supported); falling through to "
                        f"the next confidentiality rung"
                    )
                    continue

                if last_exc is not None:
                    _emit_ldap_failure_posture(
                        config,
                        exc=last_exc,
                        used_kerberos_auth=config.use_kerberos,
                        transport_was_ldaps=last_attempt_was_ldaps,
                    )

                # Seal-by-default DEGRADE hook. When THIS attempt was a
                # transport-applied default seal (authenticated plain-LDAP we
                # upgraded to sign+seal, marked ``_default_seal_applied``) and it
                # failed specifically because sealing could not be negotiated
                # against a server that cannot provide it (a non-Windows / legacy
                # LDAP server) -- NOT an auth/credential failure -- retry once
                # unsealed so we degrade gracefully instead of hanging or failing
                # hard against a DC that genuinely cannot seal. Budget-gated to a
                # single shot. A bad-creds rejection is excluded by
                # ``_is_seal_negotiation_failure`` and propagates unchanged.
                if (
                    not is_ldaps
                    and getattr(cfg, "_default_seal_applied", False)
                    and not getattr(config, "require_confidential", False)
                    and not _seal_degrade_used
                    and _is_seal_negotiation_failure(exc)
                ):
                    _seal_degrade_used = True
                    import dataclasses as _dc_degrade

                    unsealed_cfg = _dc_degrade.replace(
                        cfg, sign=False, _default_seal_applied=False
                    )
                    configs_to_try.append((unsealed_cfg, is_ldaps))
                    print_warning_debug(
                        "[ldap_transport] seal-by-default: authenticated plain-LDAP "
                        "bind could not negotiate GSS sign+seal against this DC; "
                        "degrading to an UNSEALED plain-LDAP retry. Queries/results "
                        "on this connection will travel in cleartext -- the DC does "
                        "not support LDAP sealing on port 389."
                    )
                    continue

                # Self-healing retry hook. The failure posture above already
                # taught the bus what the DC requires; here we synthesise the
                # corresponding transport config and append it to the
                # iteration queue. The next ``while`` iteration picks it up.
                #
                # Budget-gated by ``_self_heal_used`` so a misclassified
                # recovery cannot loop. The synth uses ``_dc.replace(cfg, …)``
                # so the new attempt carries the same credentials, posture
                # snapshot, kerberos target hostname, etc. — only the single
                # offending flag flips.
                #
                # Disabled by ``config.disable_self_heal`` for failure-
                # eliciting consumers (posture probes) — they need the raw
                # rejection to propagate so they can classify it instead of
                # the transport silently "fixing" the call. See the field
                # docstring on ``ADscanLDAPConfig.disable_self_heal``.
                recovered_cfg = (
                    None
                    if config.disable_self_heal
                    else _classify_recoverable_bind_failure(
                        exc, cfg=cfg, transport_was_ldaps=is_ldaps
                    )
                )
                if recovered_cfg is not None:
                    # A recovery may switch transport (e.g. a sign/seal-required
                    # rejection on LDAPS descends to plain LDAP/389), so the queued
                    # attempt's LDAPS flag must follow the recovered config — NOT the
                    # transport that just failed. Reusing the old ``is_ldaps`` here
                    # would re-queue the SAME TLS rung where ``sign`` is a no-op and
                    # loop to the identical rejection.
                    recovered_is_ldaps = bool(
                        getattr(recovered_cfg, "use_ldaps", is_ldaps)
                    )
                    recovery_key = (
                        f"cbt={recovered_cfg.channel_binding}|"
                        f"sign={recovered_cfg.sign}|"
                        f"ldaps={recovered_is_ldaps}"
                    )
                    if recovery_key not in _self_heal_used:
                        _self_heal_used.add(recovery_key)
                        configs_to_try.append((recovered_cfg, recovered_is_ldaps))
                        print_info_debug(
                            f"[ldap_transport] self-heal: queued retry "
                            f"{recovery_key} after recoverable bind failure on "
                            f"{transport_label}"
                        )
                    else:
                        # The identical recovery was ALREADY queued by a prior failed
                        # rung — e.g. both the LDAPS and StartTLS rungs descend to the
                        # same plain-LDAP sign+seal rung. The fix is already pending in
                        # configs_to_try, so do NOT raise here: continue so the loop
                        # reaches that queued rung instead of aborting before it runs.
                        # (Bad-creds / non-recoverable failures have recovered_cfg=None
                        # and still fast-fail via the raise below — no extra binds, so
                        # this does not add account-lockout risk.)
                        print_info_debug(
                            f"[ldap_transport] self-heal: recovery {recovery_key} "
                            f"already queued by a prior rung; continuing to it"
                        )
                    continue

                # NTLM last-resort rung. Reached only when no posture self-heal
                # was queued (recovered_cfg is None) — so the dedicated-code
                # recoveries (ETYPE-INFO2 mint, clock-resync, SPN-candidate) have
                # already had their chance at mint/transport time. Inject the
                # single NTLM attempt ONLY when THIS failure is the residual
                # Kerberos AP-exchange rejection envelope and NTLM was not ruled
                # out by posture. ``is_native_kerberos_infra_error`` keys on
                # "AP EXCHANGE REJECTED BY SERVER" (and the kindred KDC/SPN/AP
                # infra markers) — it does NOT match the decoded ETYPE/SKEW/
                # MODIFIED codes, so the carve-out holds exactly.
                if (
                    _ntlm_last_resort_cfg is not None
                    and not _ntlm_last_resort_used
                    and is_native_kerberos_infra_error(exc)
                ):
                    _ntlm_last_resort_used = True
                    _ntlm_is_ldaps = bool(
                        getattr(_ntlm_last_resort_cfg, "use_ldaps", is_ldaps)
                    )
                    configs_to_try.append((_ntlm_last_resort_cfg, _ntlm_is_ldaps))
                    print_info_debug(
                        "[ldap_transport] NTLM last-resort: caller-requested "
                        "Kerberos dead-ended on a residual AP-exchange rejection; "
                        "queued one NTLM bind with the same credential "
                        f"(transport={'LDAPS' if _ntlm_is_ldaps else 'LDAP'})"
                    )
                    continue
                raise

        if last_exc is not None:
            _emit_ldap_failure_posture(
                config,
                exc=last_exc,
                used_kerberos_auth=config.use_kerberos,
                transport_was_ldaps=last_attempt_was_ldaps,
            )
        if confidential_dropped_unsealed:
            # The only sealed option (LDAPS) failed and the plain-LDAP fallback was
            # dropped because it could not seal. Surface the actionable confidential
            # error rather than the raw LDAPS transport exception.
            raise ConfidentialChannelUnavailableError(
                "gMSA / confidential-attribute read requires a sealed channel, but "
                "none succeeded: LDAPS (port 636) failed to connect and the plain-LDAP "
                "(port 389) fallback was skipped because the configured bind "
                "(anonymous / SIMPLE) cannot negotiate LDAP sign+seal. The managed "
                "password cannot be read over an unsealed channel. Provide credentials "
                "for an authenticated bind, or restore LDAPS reachability to the DC."
            ) from last_exc
        # Foreign / trust realm we genuinely cannot authenticate to (cross-forest
        # AES-only KDC, no shared trust key) — collapse the raw asn1 ``None``-ticket
        # ``TypeError`` / 160-line ``KerberosError`` traceback into one clean typed
        # error so attack-path discovery (and any other caller) surfaces a single
        # "realm not reachable" line instead of crashing the phase. There is no
        # recovery for this case; the dedicated-code recoveries (ETYPE-INFO2 mint,
        # clock-resync, SPN-candidate) all assume a secret valid in that realm.
        if last_exc is not None and is_unreachable_foreign_realm_error(last_exc):
            realm = mark_sensitive(str(config.domain or "the target realm"), "domain")
            raise ForeignRealmUnreachableError(
                f"Foreign/trust realm {realm} is not reachable with the current "
                "credential (cross-realm Kerberos auth unavailable)."
            ) from last_exc
        raise last_exc or RuntimeError(
            "Both LDAPS and plain LDAP connection attempts failed"
        )
    finally:
        if _expiry_reminter_realm:
            _kerberos_recovery.unregister_expiry_reminter(_expiry_reminter_realm)


def execute_with_ldap_fallback(
    *,
    operation_name: str,
    target_domain: str,
    dc_address: str,
    callback: Callable[[Any], Any],
    config_cls: type[Any] | None = None,
    connection_cls: type[Any] | None = None,
    username: str | None = None,
    password: str | None = None,
    use_kerberos: bool = False,
    prefer_ldaps: bool = True,
    validate_connection: Callable[[Any], None] | None = None,
    config_overrides: Mapping[str, Any] | None = None,
    kerberos_target_hostname: str | None = None,
    allow_password_fallback_on_kerberos_failure: bool = False,
    auth_domain: str | None = None,
    auth_kdc: str | None = None,
    posture_sink: "PostureSink | None" = None,
) -> tuple[Any, bool]:
    """Execute one LDAP-backed callback with centralized LDAPS->LDAP fallback.

    Loop-safe entry point. The implementation drives a private event loop via
    ``ADscanLDAPConnection`` (``asyncio.new_event_loop()`` +
    ``run_until_complete()``), which raises ``RuntimeError: Cannot run the
    event loop while another loop is running`` when called from inside an
    active asyncio loop (e.g. the credential-dump follow-up chain). This
    wrapper offloads the entire synchronous operation to a loop-free worker
    thread via :func:`run_sync_off_loop` when a loop is already running, and
    runs inline (no offload) otherwise.

    See :func:`_execute_with_ldap_fallback_impl` for full argument and return
    documentation.
    """
    return run_sync_off_loop(
        _execute_with_ldap_fallback_impl,
        operation_name=operation_name,
        target_domain=target_domain,
        dc_address=dc_address,
        callback=callback,
        config_cls=config_cls,
        connection_cls=connection_cls,
        username=username,
        password=password,
        use_kerberos=use_kerberos,
        prefer_ldaps=prefer_ldaps,
        validate_connection=validate_connection,
        config_overrides=config_overrides,
        kerberos_target_hostname=kerberos_target_hostname,
        allow_password_fallback_on_kerberos_failure=allow_password_fallback_on_kerberos_failure,
        auth_domain=auth_domain,
        auth_kdc=auth_kdc,
        posture_sink=posture_sink,
    )


def _execute_with_ldap_fallback_impl(
    *,
    operation_name: str,
    target_domain: str,
    dc_address: str,
    callback: Callable[[Any], Any],
    config_cls: type[Any] | None = None,
    connection_cls: type[Any] | None = None,
    username: str | None = None,
    password: str | None = None,
    use_kerberos: bool = False,
    prefer_ldaps: bool = True,
    validate_connection: Callable[[Any], None] | None = None,
    config_overrides: Mapping[str, Any] | None = None,
    kerberos_target_hostname: str | None = None,
    allow_password_fallback_on_kerberos_failure: bool = False,
    auth_domain: str | None = None,
    auth_kdc: str | None = None,
    posture_sink: "PostureSink | None" = None,
) -> tuple[Any, bool]:
    """Execute one LDAP-backed callback with centralized LDAPS->LDAP fallback.

    When ``config_cls`` and ``connection_cls`` are None (the default), the
    ADscan-native badldap-backed classes are used.

    Args:
        posture_sink: Optional :data:`PostureSink` propagated into every
            ``ADscanLDAPConfig`` built by this helper. Lets callers receive
            posture signals (LDAPS unavailable, signing required, NTLM
            disabled, etc.) emitted by the underlying transport. ``None`` is
            a no-op.

    Returns:
        Tuple ``(result, used_ldaps)``.

    Raises:
        Exception: Re-raises the terminal connection/operation error.
    """
    effective_config_cls = config_cls if config_cls is not None else ADscanLDAPConfig
    effective_connection_cls = (
        connection_cls if connection_cls is not None else ADscanLDAPConnection
    )

    attempts = [prefer_ldaps]
    if prefer_ldaps:
        attempts.append(False)

    marked_operation = mark_sensitive(operation_name, "path")
    marked_domain = mark_sensitive(target_domain, "domain")
    marked_dc = mark_sensitive(dc_address, "host")
    marked_kerberos_target = mark_sensitive(
        str(kerberos_target_hostname or "").strip() or "n/a",
        "hostname",
    )
    last_exc: Exception | None = None

    auth_attempts: list[bool] = [use_kerberos]
    can_retry_with_password = (
        use_kerberos
        and allow_password_fallback_on_kerberos_failure
        and bool(str(username or "").strip())
        and bool(str(password or "").strip())
    )
    if can_retry_with_password:
        auth_attempts.append(False)

    for use_kerberos_auth in auth_attempts:
        retry_with_password = False
        for use_ldaps in attempts:
            transport = "LDAPS" if use_ldaps else "LDAP"
            auth_mode = "Kerberos" if use_kerberos_auth else "password"
            print_info_debug(
                f"[ldap] Attempting {marked_operation} over {transport} for "
                f"{marked_domain} via {marked_dc} using {auth_mode} auth"
            )
            config_kwargs: dict[str, Any] = {
                "domain": target_domain,
                "dc_ip": dc_address,
                "use_ldaps": use_ldaps,
                "use_kerberos": use_kerberos_auth,
            }
            if posture_sink is not None:
                config_kwargs["posture_sink"] = posture_sink
            if isinstance(config_overrides, Mapping):
                config_kwargs.update(dict(config_overrides))
            if use_kerberos_auth and str(kerberos_target_hostname or "").strip():
                config_kwargs["kerberos_target_hostname"] = str(
                    kerberos_target_hostname
                ).strip()
            if use_kerberos_auth and str(auth_domain or "").strip():
                config_kwargs["auth_domain"] = str(auth_domain).strip()
            if use_kerberos_auth and str(auth_kdc or "").strip():
                config_kwargs["auth_kdc"] = str(auth_kdc).strip()
            if str(username or "").strip():
                config_kwargs["username"] = str(username).strip()
            if password:
                config_kwargs["password"] = password
            if not use_kerberos_auth and (not str(username or "").strip() or not password):
                raise ValueError(
                    f"{operation_name} with password auth requires username and password."
                )

            try:
                config = effective_config_cls(**config_kwargs)
                with effective_connection_cls(config) as connection:
                    validator = validate_connection or _validate_rootdse_query
                    validator(connection)
                    result = callback(connection)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if use_ldaps and prefer_ldaps and is_ldaps_transport_failure(exc):
                    log_exception_debug(
                        f"LDAP transport retry for {marked_operation}",
                        exception=exc,
                        context={
                            "domain": marked_domain,
                            "dc": marked_dc,
                            "transport": transport,
                            "auth_mode": auth_mode,
                            "kerberos_target_hostname": marked_kerberos_target,
                        },
                    )
                    print_warning_debug(
                        f"[ldap] {marked_operation} failed over LDAPS for {marked_domain}; "
                        "retrying over LDAP. "
                        f"Cause: {_format_exception_chain_summary(exc)}"
                    )
                    continue
                if (
                    use_kerberos_auth
                    and can_retry_with_password
                    and is_kerberos_auth_failure(exc)
                ):
                    # When the TGT has expired, try to renew it before falling
                    # back to password bind.  Renewal preserves Kerberos auth
                    # (more secure, matches what the DC expects) and avoids
                    # downgrading to plaintext credentials.
                    _exc_text = exception_chain_text(exc).upper()
                    _tgt_expired = "TKT_EXPIRED" in _exc_text or "TICKET HAS EXPIRED" in _exc_text
                    if _tgt_expired:
                        _ccache = str(
                            (config_overrides or {}).get("ccache_path", "") or ""
                        ).strip()
                        if _ccache:
                            try:
                                from adscan_internal.services.kerberos_ticket_service import (
                                    KerberosTicketService,
                                )
                                _renewed = KerberosTicketService().try_renew_tgt(
                                    ticket_path=_ccache
                                )
                                if _renewed:
                                    print_info_debug(
                                        f"[ldap] Kerberos TGT renewed for {marked_operation} — "
                                        f"retrying Kerberos auth instead of password fallback"
                                    )
                                    continue  # retry this transport with fresh TGT
                            except Exception as _renew_exc:  # noqa: BLE001
                                print_info_debug(
                                    f"[ldap] TGT renewal failed for {marked_operation}: "
                                    f"{type(_renew_exc).__name__}: {_renew_exc}"
                                )
                    # For TKT_EXPIRED specifically: this is expected when a
                    # session runs longer than the TGT's validity window and
                    # renewal wasn't possible.  Log without the full traceback
                    # to keep the operator's debug output clean.
                    if _tgt_expired:
                        print_info_debug(
                            f"[ldap] {marked_operation} Kerberos TGT expired for "
                            f"{marked_domain} via {marked_dc} — falling back to "
                            f"password bind (renewal not available or failed)"
                        )
                    else:
                        log_exception_debug(
                            f"LDAP Kerberos auth retry for {marked_operation}",
                            exception=exc,
                            context={
                                "domain": marked_domain,
                                "dc": marked_dc,
                                "transport": transport,
                                "auth_mode": auth_mode,
                                "kerberos_target_hostname": marked_kerberos_target,
                            },
                        )
                        print_warning_debug(
                            f"[ldap] {marked_operation} Kerberos auth failed for {marked_domain} "
                            f"via {marked_dc}; retrying with password bind. "
                            f"Cause: {_format_exception_chain_summary(exc)}"
                        )
                    retry_with_password = True
                    break
                raise

            if not use_ldaps:
                print_info_debug(
                    f"[ldap] LDAP fallback succeeded for {marked_operation} on {marked_domain}"
                )
            if not use_kerberos_auth and use_kerberos:
                print_info_debug(
                    f"[ldap] Password bind fallback succeeded for {marked_operation} on "
                    f"{marked_domain}"
                )
            return result, bool(use_ldaps)

        if retry_with_password:
            continue

    if last_exc is not None:
        if posture_sink is not None:
            # Synthesize a minimal config purely to carry the sink + domain so
            # the failure classifier can emit. The posture signals only need
            # ``domain`` and ``posture_sink`` to be set.
            try:
                _emit_ldap_failure_posture(
                    ADscanLDAPConfig(
                        domain=target_domain,
                        dc_ip=dc_address,
                        use_ldaps=bool(prefer_ldaps),
                        use_kerberos=bool(use_kerberos),
                        posture_sink=posture_sink,
                    ),
                    exc=last_exc,
                    used_kerberos_auth=bool(use_kerberos),
                    transport_was_ldaps=bool(prefer_ldaps),
                )
            except Exception as _emit_exc:  # noqa: BLE001
                telemetry.capture_exception(_emit_exc)
        raise last_exc
    raise RuntimeError(f"{operation_name} failed without executing any LDAP attempt")


# ---------------------------------------------------------------------------
# Anonymous (simple-bind) LDAP — centralized LDAPS->LDAP fallback
# ---------------------------------------------------------------------------


def _build_anonymous_ldap_config(
    dc_ip: str,
    *,
    posture_snapshot: "DomainPosture | None" = None,
    posture_sink: "PostureSink | None" = None,
) -> "ADscanLDAPConfig":
    """Build an ``ADscanLDAPConfig`` for an anonymous RFC 4513 SIMPLE bind.

    Empty credentials + ``use_simple_bind=True`` route ``_build_ldap_connection_url``
    to the ``ldap+simple://@host`` form — the canonical anonymous SIMPLE bind that
    leaves the connection in RUNNING state after bind (required for ``pagedsearch``
    against hardened DCs). ``use_kerberos`` and ``use_ldaps`` keep their roles: the
    LDAPS->LDAP fallback in :func:`async_connect_with_ldap_fallback` downgrades 636→389
    automatically.

    The defaults (``sign=False``, ``channel_binding=False``) make
    ``async_connect_with_ldap_fallback`` set ``_disable_signing=True`` and
    ``_disable_channel_binding=True`` on the client — exactly the flag surgery the
    hand-rolled anonymous loops performed, since anonymous binds negotiate neither.
    """
    return ADscanLDAPConfig(
        domain="",
        dc_ip=str(dc_ip or "").strip(),
        use_ldaps=True,
        use_kerberos=False,
        username=None,
        password=None,
        use_simple_bind=True,
        posture_snapshot=posture_snapshot,
        posture_sink=posture_sink,
    )


async def async_connect_anonymous_with_ldap_fallback(
    dc_ip: str,
    *,
    timeout: float = 8.0,
    posture_snapshot: "DomainPosture | None" = None,
    posture_sink: "PostureSink | None" = None,
) -> "LDAPConnectResult":
    """Async anonymous SIMPLE-bind LDAP connect with LDAPS->LDAP fallback.

    The anonymous counterpart to :func:`async_connect_with_ldap_fallback`. It builds
    an anonymous SIMPLE-bind config (empty creds, ``ldap+simple://@host``) and routes
    it through the SAME fallback machinery, so the LDAPS(636)->LDAP(389) downgrade and
    the type-based :func:`is_ldaps_transport_failure` classifier (connect-time
    ``ConnectionReset`` / ``ConnectionRefused`` / ``TimeoutError`` on 636 → retry on 389)
    are inherited for free.

    Args:
        dc_ip: Domain controller address (IP or FQDN).
        timeout: Per-transport connect budget in seconds. A silently DROPped 636 port
            surfaces a ``TimeoutError`` and the fallback proceeds to plain LDAP:389.
        posture_snapshot: Optional posture snapshot for auth-plan pruning (e.g. skip a
            doomed 636 connect when the workspace recorded LDAPS down).
        posture_sink: Optional sink for LDAPS-availability posture signals emitted by
            the underlying transport.

    Returns:
        ``(connected_client, used_ldaps)`` — a live ``MSLDAPClient`` bound anonymously
        plus which transport succeeded. The caller owns the connection and must call
        ``await client.disconnect()`` (or use
        :func:`async_anonymous_ldap_connection`, which disconnects automatically).

    Raises:
        Exception: last connection error when both LDAPS and plain LDAP fail.
    """
    config = _build_anonymous_ldap_config(
        dc_ip,
        posture_snapshot=posture_snapshot,
        posture_sink=posture_sink,
    )
    return await async_connect_with_ldap_fallback(config, connect_timeout=timeout)


@contextlib.asynccontextmanager
async def async_anonymous_ldap_connection(
    dc_ip: str,
    *,
    timeout: float = 8.0,
    posture_snapshot: "DomainPosture | None" = None,
    posture_sink: "PostureSink | None" = None,
):
    """Async context manager yielding an anonymous-bound ``MSLDAPClient``.

    Wraps :func:`async_connect_anonymous_with_ldap_fallback` and guarantees the
    connection is disconnected on exit (even on error). Use this for the common
    anonymous-enumeration pattern: connect anonymously, read ``_serverinfo`` for the
    naming context, then ``pagedsearch``.

    Example::

        async with async_anonymous_ldap_connection(dc_ip, timeout=8) as (client, used_ldaps):
            base_dn = anonymous_default_naming_context(client)
            async for item, err in client.pagedsearch("(objectClass=user)", ["*"], tree=base_dn, search_scope=2):
                ...
    """
    client, used_ldaps = await async_connect_anonymous_with_ldap_fallback(
        dc_ip,
        timeout=timeout,
        posture_snapshot=posture_snapshot,
        posture_sink=posture_sink,
    )
    try:
        yield client, used_ldaps
    finally:
        try:
            disconnect = getattr(client, "disconnect", None)
            if disconnect is not None:
                maybe = disconnect()
                if asyncio.iscoroutine(maybe):
                    await maybe
        except Exception:  # noqa: BLE001
            pass


def anonymous_default_naming_context(client: Any) -> str:
    """Return the directory's default naming context DN from a bound client.

    Reads ``get_server_info()`` / ``_serverinfo`` (populated during connect) and
    extracts ``defaultNamingContext``, falling back to the first ``namingContexts``
    entry. Returns ``""`` when no naming context is available — callers treat that as
    "directory denied the anonymous RootDSE read" and stop.
    """
    server_info: Any = None
    getter = getattr(client, "get_server_info", None)
    if callable(getter):
        try:
            server_info = getter()
        except Exception:  # noqa: BLE001
            server_info = None
    if not server_info:
        server_info = getattr(client, "_serverinfo", None)
    if not isinstance(server_info, dict):
        return ""
    raw = server_info.get("defaultNamingContext")
    if isinstance(raw, list):
        base_dn = str(raw[0]) if raw else ""
    elif raw:
        base_dn = str(raw)
    else:
        base_dn = ""
    if not base_dn:
        ncs = server_info.get("namingContexts")
        if isinstance(ncs, list) and ncs:
            base_dn = str(ncs[0])
    return base_dn.strip()
