"""Native LDAP deletion of a domain account — single source of truth.

Every rollback/cleanup path that must remove an account ADscan created during
exploitation (the MSSQL minted-DA revert, the HasSession del-user rollback, and
any future minted-principal cleanup) deletes it through THIS helper, so the
behaviour is identical and there is one place to maintain.

It binds AS the account being removed (a freshly-minted DA holds full LDAP
rights), resolves the object DN by ``sAMAccountName`` and deletes it via
badldap's ``get_user`` / ``delete_user`` over the canonical ADscan LDAP entry
point (LDAPS with the transparent LDAPS->LDAP fallback), honouring the domain
posture snapshot so it works on hardened DCs. It is NEVER a subprocess — this is
the native replacement for the former ``nxc ldap --del-user`` fallback.
"""

from __future__ import annotations

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_core.rich_output import print_exception


def classify_secret_kind(secret: str) -> str:
    """Classify an account secret for transport config builders.

    Returns one of ``"password"`` / ``"nt_hash"`` / ``"ccache"``. Minted
    accounts normally carry a generated password, but the operator can override
    the identity with an NT hash or a ccache path, so classify defensively.
    """
    value = str(secret or "").strip()
    if value.lower().endswith(".ccache"):
        return "ccache"
    if len(value) == 32 and all(c in "0123456789abcdefABCDEF" for c in value):
        return "nt_hash"
    return "password"


async def delete_domain_account_via_ldap_async(
    *, domains_data: dict, domain: str, username: str, secret: str
) -> bool:
    """Delete a domain account by sAMAccountName, binding AS that account.

    Args:
        domains_data: The shell's ``domains_data`` map (for DC IP/FQDN + posture).
        domain: Realm the account lives in.
        username: sAMAccountName of the account to delete.
        secret: The account's own credential — password, 32-hex NT hash, or a
            ``.ccache`` path (classified via :func:`classify_secret_kind`).

    Returns:
        ``True`` only when the object is confirmed gone (the delete succeeded, a
        follow-up resolve finds nothing, or the account was already absent);
        ``False`` when no DC IP resolves or the DN cannot be found. Transport
        errors propagate to the caller (the sync wrapper swallows + logs them).
    """
    from adscan_internal.models.domain import resolve_dc_fqdn, resolve_dc_ip
    from adscan_internal.services.domain_posture import get_posture
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
    )

    domain_record = (domains_data or {}).get(domain) or {}
    dc_ip = resolve_dc_ip(domain_record)
    if not dc_ip:
        return False
    # FQDN is required for the Kerberos SPN when the credential is a ccache/AES
    # ticket; a password/NT-hash bind uses a plain LDAPS/LDAP bind.
    dc_fqdn = resolve_dc_fqdn(domain_record, target_domain=domain)
    secret_kind = classify_secret_kind(secret)
    use_kerberos = secret_kind == "ccache"

    try:
        posture_snapshot = get_posture(domains_data or {}, domain=domain)
    except Exception:  # noqa: BLE001
        posture_snapshot = None

    config = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=use_kerberos,
        username=username if secret_kind != "ccache" else None,
        # badldap takes both passwords and NT hashes through the password field
        # (NTLM mechanism); a ccache path goes through ``ccache_path`` instead.
        password=secret if secret_kind in {"password", "nt_hash"} else None,
        kerberos_target_hostname=dc_fqdn if use_kerberos else None,
        ccache_path=secret if secret_kind == "ccache" else None,
        posture_snapshot=posture_snapshot,
    )

    confirmed, _reason = await delete_domain_account_as(config, username=username)
    return confirmed


async def delete_domain_account_as(
    ldap_config: object, *, username: str
) -> tuple[bool, str | None]:
    """Delete domain account ``username`` binding with ``ldap_config``, then re-read.

    The bind is whoever performs the revert (the shared revert precedence builds
    the config per candidate). ``(True, None)`` only when a re-resolve after the
    delete finds no such account; an account already absent also confirms.
    Transport errors propagate.
    """
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        async_connect_with_ldap_fallback,
    )

    conn = None
    try:
        conn, _used_ldaps = await async_connect_with_ldap_fallback(ldap_config)
        user, err = await conn.get_user(username)
        if err is not None:
            raise err
        if user is not None:
            user_dn = getattr(user, "distinguishedName", None)
            if not user_dn:
                return False, "the account's DN could not be read"
            _ok, del_err = await conn.delete_user(user_dn)
            if del_err is not None:
                return False, str(del_err)
        # Verify by re-resolving: a missing object confirms the deletion.
        check, check_err = await conn.get_user(username)
        if check_err is None and check is None:
            return True, None
        return False, "the re-read still finds the account"
    finally:
        if conn is not None:
            try:
                await conn.disconnect()
            except Exception:  # noqa: BLE001
                pass


_SAMR_ABSENT_MARKERS = ("NONE_MAPPED", "NO_SUCH_USER", "0xc0000073", "0xc0000064")


def _samr_absent(error: object) -> bool:
    text = str(error or "")
    return any(marker.lower() in text.lower() for marker in _SAMR_ABSENT_MARKERS)


async def delete_account_via_samr_as(
    smb_config: object, *, username: str
) -> tuple[bool, str | None]:
    """Delete account ``username`` from the host's SAM over SAMR, then re-read.

    Works for a member server's local account and, on a domain controller, for
    a domain account (its SAM domain is the directory). Native SAMR
    (``SamrDeleteUser``), no command execution, so no output to parse in the
    host's locale. ``(True, None)`` only when a name lookup after the delete
    returns "none mapped"; an account already absent also confirms.
    """
    from aiosmb.dcerpc.v5.interfaces.samrmgr import samrrpc_from_smb  # noqa: PLC0415

    from adscan_internal.services.smb_transport import (  # noqa: PLC0415
        smb_machine_with_fallback,
    )

    async with smb_machine_with_fallback(smb_config) as machine:
        async with samrrpc_from_smb(machine.connection) as samr:
            domain_name = None
            async for name, err in samr.list_domains():
                if err is not None:
                    return False, f"SAMR domain enumeration failed: {err}"
                if str(name or "").strip().lower() != "builtin":
                    domain_name = str(name)
                    break
            if not domain_name:
                return False, "the host exposes no account domain over SAMR"
            dhandle, err = await samr.open_domain_by_name(domain_name)
            if err is not None:
                return False, f"SAMR open domain failed: {err}"
            delete_error: str | None = None
            rid, err = await samr.get_user_rid_by_name(dhandle, username)
            if err is None:
                uhandle, err = await samr.open_user(dhandle, rid)
                if err is not None:
                    delete_error = str(err)
                else:
                    _resp, err = await samr.delete_account(uhandle)
                    if err is not None:
                        delete_error = str(err)
            elif not _samr_absent(err):
                return False, f"SAMR lookup failed: {err}"
            _rid, err = await samr.get_user_rid_by_name(dhandle, username)
            if err is not None and _samr_absent(err):
                return True, None
            if err is None:
                return False, delete_error or "the re-read still finds the account"
            return False, f"SAMR re-read failed: {err}"


def delete_minted_account_as(
    domains_data: dict,
    candidate: object,
    *,
    domain: str,
    host: str,
    username: str,
    scope: str,
    kdc_ip: str | None = None,
) -> tuple[bool, str | None]:
    """Delete an account ADscan minted, authenticated as ``candidate``, then re-read.

    The transport of the shared revert precedence for a minted account. Domain
    scope (a domain controller): native LDAP delete with a re-resolve, then SAMR
    on the DC as the same candidate when LDAP did not confirm. Local scope (a
    member server): SAMR on ``host``. Never ``xp_cmdshell``: a freshly minted
    Domain Admin is not a SQL sysadmin. ``(True, None)`` only when the re-read no
    longer finds the account. Synchronous.
    """
    from adscan_internal.models.domain import resolve_dc_fqdn, resolve_dc_ip
    from adscan_internal.services.async_bridge import run_async_sync

    record = (domains_data or {}).get(domain) or {}
    dc_ip = str(resolve_dc_ip(record) or "")
    dc_fqdn = str(resolve_dc_fqdn(record, target_domain=domain) or "")
    is_domain = str(scope or "").strip().lower() == "domain"
    reason: str | None = None
    if is_domain and dc_ip:
        try:
            confirmed, reason = run_async_sync(
                delete_domain_account_as(
                    candidate.ldap_config(dc_ip=dc_ip, dc_fqdn=dc_fqdn or None),
                    username=username,
                )
            )
        except Exception as exc:  # noqa: BLE001 - try SAMR as the same candidate
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            confirmed, reason = False, str(exc)
        if confirmed:
            return True, None
    target_ip = dc_ip if is_domain and dc_ip else host
    target_name = dc_fqdn if target_ip == dc_ip and dc_fqdn else host
    if not target_ip:
        return False, reason or "no host to reach the account database on"
    try:
        confirmed, samr_reason = run_async_sync(
            delete_account_via_samr_as(
                candidate.smb_config(
                    target_ip=target_ip,
                    target_hostname=target_name or target_ip,
                    kdc_ip=kdc_ip or dc_ip or None,
                ),
                username=username,
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False, reason or str(exc)
    return (True, None) if confirmed else (False, samr_reason or reason)


def delete_domain_account_via_ldap(
    *, domains_data: dict, domain: str, username: str, secret: str
) -> bool:
    """Sync wrapper over :func:`delete_domain_account_via_ldap_async`.

    Best-effort: any transport error is captured + logged at debug and reported
    as ``False`` so callers can surface a manual-cleanup hint.
    """
    from adscan_internal.services.async_bridge import run_async_sync

    try:
        return bool(
            run_async_sync(
                delete_domain_account_via_ldap_async(
                    domains_data=domains_data,
                    domain=domain,
                    username=username,
                    secret=secret,
                )
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[native-account-cleanup] LDAP delete of {username} failed: {exc}"
        )
        return False


def resolve_domain_dc(shell: object, domain: str) -> tuple[str, str]:
    """``(dc_ip, dc_fqdn)`` for ``domain`` from the workspace (empty when unknown)."""
    from adscan_internal.models.domain import resolve_dc_fqdn, resolve_dc_ip  # noqa: PLC0415

    record = (getattr(shell, "domains_data", None) or {}).get(domain) or {}
    return (
        str(resolve_dc_ip(record) or ""),
        str(resolve_dc_fqdn(record, target_domain=domain) or ""),
    )


def delete_account_as_candidate(
    shell: object,
    candidate: object,
    *,
    domain: str,
    host: str,
    username: str,
    scope: str,
    kdc_ip: str | None = None,
) -> tuple[bool, str | None]:
    """Shell-taking entry to :func:`delete_minted_account_as`, the one implementation.

    The account-deletion transport of the shared revert precedence: domain scope
    is a native LDAP delete then SAMR on the DC as the same candidate, local scope
    is SAMR on ``host``. ``(True, None)`` only when the re-read no longer finds
    the account. Callers without a shell (the deferred cleanup service, the
    SeImpersonate session) call :func:`delete_minted_account_as` directly.
    """
    return delete_minted_account_as(
        getattr(shell, "domains_data", None) or {},
        candidate,
        domain=domain,
        host=host,
        username=username,
        scope=scope,
        kdc_ip=kdc_ip,
    )


def remove_group_member_as_candidate(
    shell: object,
    candidate: object,
    *,
    domain: str,
    group: str,
    member: str,
    pdc_host: str = "",
) -> tuple[bool, str | None]:
    """Remove ``member`` from domain group ``group`` as one revert candidate, then re-read.

    The removal call may fail because the member is already gone (an account
    deleted first takes its memberships with it); the re-read on the
    candidate's own LDAP connection decides. ``(True, None)`` only when the
    group no longer lists the member.
    """
    from adscan_internal.services.cleanup_verification import (  # noqa: PLC0415
        verify_group_membership_removed,
    )
    from adscan_internal.services.exploitation import ExploitationService  # noqa: PLC0415
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        ADscanLDAPConnection,
    )

    dc_ip, dc_fqdn = resolve_domain_dc(shell, domain)
    removal_error: str | None = None
    try:
        result = ExploitationService().acl.remove_group_member(
            pdc_host=pdc_host or dc_fqdn or dc_ip,
            domain=getattr(candidate, "domain", "") or domain,
            username=getattr(candidate, "username", ""),
            password=getattr(candidate, "secret", ""),
            target_group=group,
            target_username=member,
            kerberos=getattr(candidate, "kind", "") == "ccache_path",
            target_domain=domain,
            timeout=300,
        )
        if not bool(getattr(result, "success", False)):
            removal_error = str(getattr(result, "raw_output", "") or "").strip() or (
                "the directory refused the membership removal"
            )
    except Exception as exc:  # noqa: BLE001 - the re-read decides
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        removal_error = str(exc)
    with ADscanLDAPConnection(
        candidate.ldap_config(dc_ip=dc_ip or pdc_host, dc_fqdn=dc_fqdn or None)
    ) as conn:
        if verify_group_membership_removed(conn, group=group, member=member):
            return True, None
    return False, removal_error or "the re-read still shows the membership"


#: RID of the BUILTIN\Administrators alias.
LOCAL_ADMINISTRATORS_RID = 544


async def remove_local_alias_member_via_samr_as(
    smb_config: object, *, username: str, alias_rid: int = LOCAL_ADMINISTRATORS_RID
) -> tuple[bool, str | None]:
    """Remove ``username`` from a host's local alias over SAMR, then re-read it.

    For a membership ADscan added on a member server (the local Administrators
    group by default). ``username`` is resolved in the host's own account
    domain; native SAMR (``SamrRemoveMemberFromAlias``), no command execution.
    ``(True, None)`` only when the alias no longer lists the account's SID, or
    when the account no longer exists (a deleted account is no member).
    """
    from aiosmb.dcerpc.v5 import samr as samr_rpc  # noqa: PLC0415
    from aiosmb.dcerpc.v5.dtypes import RPC_SID  # noqa: PLC0415
    from aiosmb.dcerpc.v5.interfaces.samrmgr import samrrpc_from_smb  # noqa: PLC0415

    from adscan_internal.services.smb_transport import (  # noqa: PLC0415
        smb_machine_with_fallback,
    )

    async with smb_machine_with_fallback(smb_config) as machine:
        async with samrrpc_from_smb(machine.connection) as samr:
            domain_name = None
            async for name, err in samr.list_domains():
                if err is not None:
                    return False, f"SAMR domain enumeration failed: {err}"
                if str(name or "").strip().lower() != "builtin":
                    domain_name = str(name)
                    break
            if not domain_name:
                return False, "the host exposes no account domain over SAMR"
            domain_sid, err = await samr.get_domain_sid(domain_name)
            if err is not None:
                return False, f"SAMR domain lookup failed: {err}"
            dhandle, err = await samr.open_domain_by_name(domain_name)
            if err is not None:
                return False, f"SAMR open domain failed: {err}"
            rid, err = await samr.get_user_rid_by_name(dhandle, username)
            if err is not None:
                if _samr_absent(err):
                    return True, None
                return False, f"SAMR lookup failed: {err}"
            member_sid = f"{domain_sid}-{int(rid)}"
            bhandle, err = await samr.open_domain_by_name("Builtin")
            if err is not None:
                return False, f"SAMR open Builtin failed: {err}"
            ahandle, err = await samr.open_alias(bhandle, alias_rid)
            if err is not None:
                return False, f"SAMR open alias failed: {err}"
            sid_obj = RPC_SID()
            sid_obj.fromCanonical(member_sid)
            removal_error: str | None = None
            _resp, err = await samr_rpc.hSamrRemoveMemberFromAlias(samr.dce, ahandle, sid_obj)
            if err is not None and "MEMBER_NOT_IN_ALIAS" not in str(err).upper():
                removal_error = str(err)
            members: set[str] = set()
            async for sid, err in samr.list_alias_members(ahandle):
                if err is not None:
                    return False, f"SAMR alias re-read failed: {err}"
                members.add(str(sid or "").upper())
            if member_sid.upper() not in members:
                return True, None
            return False, removal_error or "the re-read still lists the account in the group"


def remove_local_admin_member_as_candidate(
    candidate: object, *, host: str, username: str, kdc_ip: str | None = None
) -> tuple[bool, str | None]:
    """Remove ``username`` from ``host``'s local Administrators as one revert candidate."""
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415

    try:
        return run_async_sync(
            remove_local_alias_member_via_samr_as(
                candidate.smb_config(target_ip=host, target_hostname=host, kdc_ip=kdc_ip),
                username=username,
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False, str(exc)


async def _domain_account_absent_as(ldap_config: object, *, username: str) -> bool:
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        async_connect_with_ldap_fallback,
    )

    conn = None
    try:
        conn, _used_ldaps = await async_connect_with_ldap_fallback(ldap_config)
        user, err = await conn.get_user(username)
        return err is None and user is None
    finally:
        if conn is not None:
            try:
                await conn.disconnect()
            except Exception:  # noqa: BLE001 - best-effort teardown
                pass


async def _local_account_absent_via_samr_as(smb_config: object, *, username: str) -> bool:
    from aiosmb.dcerpc.v5.interfaces.samrmgr import samrrpc_from_smb  # noqa: PLC0415

    from adscan_internal.services.smb_transport import (  # noqa: PLC0415
        smb_machine_with_fallback,
    )

    async with smb_machine_with_fallback(smb_config) as machine:
        async with samrrpc_from_smb(machine.connection) as samr:
            domain_name = None
            async for name, err in samr.list_domains():
                if err is not None:
                    return False
                if str(name or "").strip().lower() != "builtin":
                    domain_name = str(name)
                    break
            if not domain_name:
                return False
            dhandle, err = await samr.open_domain_by_name(domain_name)
            if err is not None:
                return False
            _rid, err = await samr.get_user_rid_by_name(dhandle, username)
            return err is not None and _samr_absent(err)


def account_absent_as_candidate(
    shell: object,
    candidate: object,
    *,
    domain: str,
    host: str,
    username: str,
    scope: str,
    kdc_ip: str | None = None,
) -> bool:
    """Read-only re-read: True only when the account provably no longer exists.

    For a revert performed through a channel that is not a credential (a
    command run in a logged-on session): the confirming re-read is done by the
    ``candidate`` credential, which only reads. Domain scope looks the account
    up over LDAP; local scope over SAMR on ``host``. Fail-closed.
    """
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415

    dc_ip, dc_fqdn = resolve_domain_dc(shell, domain)
    try:
        if str(scope or "").strip().lower() == "domain":
            if not dc_ip:
                return False
            return bool(
                run_async_sync(
                    _domain_account_absent_as(
                        candidate.ldap_config(dc_ip=dc_ip, dc_fqdn=dc_fqdn or None),
                        username=username,
                    )
                )
            )
        return bool(
            run_async_sync(
                _local_account_absent_via_samr_as(
                    candidate.smb_config(target_ip=host, target_hostname=host, kdc_ip=kdc_ip),
                    username=username,
                )
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
