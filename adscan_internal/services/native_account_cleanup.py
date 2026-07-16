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
        async_connect_with_ldap_fallback,
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

    conn = None
    try:
        conn, _used_ldaps = await async_connect_with_ldap_fallback(config)
        user, err = await conn.get_user(username)
        if err is not None:
            raise err
        if user is None:
            # Already gone — treat as a confirmed deletion.
            return True
        user_dn = getattr(user, "distinguishedName", None)
        if not user_dn:
            return False
        ok, del_err = await conn.delete_user(user_dn)
        if del_err is not None:
            raise del_err
        if ok:
            return True
        # Verify by re-resolving: a missing object confirms deletion.
        check, check_err = await conn.get_user(username)
        return check_err is None and check is None
    finally:
        if conn is not None:
            try:
                await conn.disconnect()
            except Exception:  # noqa: BLE001
                pass


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
        print_info_debug(
            f"[native-account-cleanup] LDAP delete of {username} failed: {exc}"
        )
        return False
