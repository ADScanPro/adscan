"""Resolve a LOCAL account name on a target host from its RID.

A local account's *name* is not portable knowledge. The built-in local
administrator is RID 500 on every Windows host, but its **name** varies:
``Administrator`` by default, ``Administrador`` / ``Rendszergazda`` /
``Administrateur`` in a localized install, and anything at all once an
administrator renames it (a common hardening step). Any code that needs to
authenticate as "the built-in local administrator" therefore has to resolve
the RID on the host, not assume a name.

This module is that resolution primitive. It is deliberately generic — it
takes a RID, not "the admin" — so the same call resolves RID 501 (Guest) or a
custom local RID when a future caller needs it.

Two interfaces are tried, in this order, over ONE authenticated SMB session:

1. **MS-LSAT / MS-LSAD** (``lsarpc`` pipe) — ``LsarQueryInformationPolicy2``
   with ``PolicyAccountDomainInformation`` yields the host's own account-domain
   SID, then ``LsarLookupSids`` translates ``<host_sid>-<rid>`` to a name. This
   is the primary because it survives the hardening that blocks the obvious
   alternative: ``Network access: Restrict clients allowed to make remote calls
   to SAM`` (RestrictRemoteSam, default-on since Windows 10 1607 / Server 2016)
   limits **SAMR** to local administrators, while LSAT name translation stays
   available to an authenticated domain principal. Verified against a Server
   2019 member server with a low-privileged domain account.
2. **MS-SAMR** (``samr`` pipe) — enumerate the host's non-BUILTIN account
   domain, open RID ``<rid>`` and read ``UserName``. Used only when LSAT is
   denied or unavailable (older hosts, or an LSA policy DACL that denies the
   policy read while SAMR is reachable because the caller is a local admin).

Both are read-only. The result carries the interface that produced it so the
caller can be honest about provenance instead of presenting an inference as a
read fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core.rich_output import print_info_debug


# The built-in local Administrator is RID 500 on every Windows installation,
# whatever the account is named. See ``LOCAL_ADMIN_RID`` consumers.
LOCAL_ADMIN_RID = 500

# Resolution interfaces, reported verbatim in ``LocalAccountLookup.method``.
METHOD_LSAT = "lsat"
METHOD_SAMR = "samr"

_DEFAULT_TIMEOUT_S = 25


@dataclass(frozen=True)
class LocalAccountLookup:
    """Outcome of one RID -> local account name resolution against a host."""

    name: str = ""
    """Resolved account name, or ``""`` when the host did not answer."""

    rid: int = LOCAL_ADMIN_RID
    account_domain: str = ""
    """NetBIOS name of the host's own account domain (its local SAM domain)."""

    host_sid: str = ""
    method: str = ""
    """``lsat`` / ``samr`` / ``""`` when nothing resolved."""

    error: str = ""

    @property
    def resolved(self) -> bool:
        return bool(self.name)


def _is_local_account_domain(name: str) -> bool:
    """Return whether a SAMR domain name is the host's own account domain."""
    return bool(name) and name.strip().lower() != "builtin"


async def _lookup_via_lsat(connection: Any, rid: int) -> LocalAccountLookup:
    """Resolve ``rid`` against the host's own account domain via MS-LSAT."""
    from aiosmb.dcerpc.v5.interfaces.lsatmgr import LSADRPC

    lsa, err = await LSADRPC.from_smbconnection(connection)
    if err is not None:
        return LocalAccountLookup(rid=rid, error=f"LSAT bind failed: {err}")
    try:
        policy_handle, err = await lsa.open_policy2()
        if err is not None:
            return LocalAccountLookup(rid=rid, error=f"LsarOpenPolicy2 failed: {err}")

        host_sid, err = await lsa.get_host_sid(policy_handle)
        if err is not None or not host_sid:
            return LocalAccountLookup(
                rid=rid,
                error=f"PolicyAccountDomainInformation failed: {err or 'empty SID'}",
            )

        target_sid = f"{host_sid}-{int(rid)}"
        async for account_domain, name, lookup_err in lsa.lookup_sids(
            policy_handle, [target_sid]
        ):
            if lookup_err is not None:
                return LocalAccountLookup(
                    rid=rid,
                    host_sid=host_sid,
                    error=f"LsarLookupSids failed: {lookup_err}",
                )
            resolved = str(name or "").strip()
            if resolved:
                return LocalAccountLookup(
                    name=resolved,
                    rid=rid,
                    account_domain=str(account_domain or "").strip(),
                    host_sid=host_sid,
                    method=METHOD_LSAT,
                )
        return LocalAccountLookup(
            rid=rid,
            host_sid=host_sid,
            error=f"RID {rid} did not translate to a name on this host",
        )
    finally:
        try:
            await lsa.close()
        except Exception as exc:  # noqa: BLE001 - best-effort teardown
            print_info_debug(f"native-local-account: lsa close (ignored): {exc}")


async def _lookup_via_samr(connection: Any, rid: int) -> LocalAccountLookup:
    """Resolve ``rid`` against the host's own account domain via MS-SAMR."""
    from aiosmb.dcerpc.v5.interfaces.samrmgr import SAMRRPC

    samr, err = await SAMRRPC.from_smbconnection(connection)
    if err is not None:
        return LocalAccountLookup(rid=rid, error=f"SAMR bind failed: {err}")
    try:
        account_domain = ""
        async for domain_name, list_err in samr.list_domains():
            if list_err is not None:
                return LocalAccountLookup(
                    rid=rid, error=f"SamrEnumerateDomainsInSamServer failed: {list_err}"
                )
            if _is_local_account_domain(str(domain_name or "")):
                account_domain = str(domain_name).strip()
                break
        if not account_domain:
            return LocalAccountLookup(
                rid=rid, error="host reported no local account domain over SAMR"
            )

        domain_handle, err = await samr.open_domain_by_name(account_domain)
        if err is not None:
            return LocalAccountLookup(
                rid=rid,
                account_domain=account_domain,
                error=f"SamrOpenDomain failed: {err}",
            )

        user_handle, err = await samr.open_user(domain_handle, rid)
        if err is not None:
            return LocalAccountLookup(
                rid=rid,
                account_domain=account_domain,
                error=f"SamrOpenUser(RID {rid}) failed: {err}",
            )

        username, err = await samr.get_user_username(user_handle)
        if err is not None or not str(username or "").strip():
            return LocalAccountLookup(
                rid=rid,
                account_domain=account_domain,
                error=f"SamrQueryInformationUser failed: {err or 'empty name'}",
            )
        return LocalAccountLookup(
            name=str(username).strip(),
            rid=rid,
            account_domain=account_domain,
            method=METHOD_SAMR,
        )
    finally:
        try:
            await samr.close()
        except Exception as exc:  # noqa: BLE001 - best-effort teardown
            print_info_debug(f"native-local-account: samr close (ignored): {exc}")


async def resolve_local_account_name_by_rid(
    *,
    host: str,
    domain: str,
    auth_domain: str = "",
    username: str = "",
    password: str | None = None,
    nt_hash: str | None = None,
    aes_key: str | None = None,
    ccache_path: str | None = None,
    kdc_ip: str | None = None,
    host_fqdn: str | None = None,
    rid: int = LOCAL_ADMIN_RID,
    posture_snapshot: Any = None,
    timeout: int = _DEFAULT_TIMEOUT_S,
) -> LocalAccountLookup:
    """Resolve a local account name on ``host`` from its ``rid``.

    Opens ONE authenticated SMB session and drives the LSAT and SAMR pipes
    sequentially over it (never concurrently — a single ``SMBConnection``
    multiplexes one DCE-RPC operation at a time).

    Args:
        host: Target host — IP, short name or FQDN. Used as the connect target.
        domain: Target domain, for transport context and Kerberos realm.
        auth_domain: Domain the credential belongs to (may differ from
            ``domain`` across a trust). Defaults to ``domain``.
        username: Principal performing the lookup. A plain domain user is
            enough for the LSAT path.
        password / nt_hash / aes_key / ccache_path: Credential material; passed
            straight to :class:`SMBConfig`, which picks the right auth method.
        kdc_ip: KDC for ``auth_domain``, when Kerberos is needed.
        host_fqdn: FQDN to use as the Kerberos SPN target when ``host`` is an IP.
        rid: RID to resolve. Defaults to the built-in administrator (500).
        posture_snapshot: Optional domain posture so the transport planner can
            prune impossible auth combinations (NTLM disabled, AES-only, ...).
        timeout: Per-connection timeout in seconds.

    Returns:
        A :class:`LocalAccountLookup`. Never raises — a failure to resolve is a
        normal outcome (the host may deny both interfaces) and is reported in
        ``error`` so the caller can fall back and stay honest about it.
    """
    from adscan_internal.services.smb_transport import (
        SMBConfig,
        smb_machine_with_fallback,
    )

    target = str(host or "").strip()
    if not target:
        return LocalAccountLookup(rid=rid, error="no target host supplied")

    config = SMBConfig(
        target_ip=target,
        target_hostname=str(host_fqdn or "").strip() or None,
        domain=domain or None,
        auth_domain=(auth_domain or domain) or None,
        username=username or None,
        password=password or None,
        nt_hash=nt_hash or None,
        aes_key=aes_key or None,
        ccache_path=ccache_path or None,
        kdc_ip=kdc_ip or None,
        use_kerberos=bool(ccache_path or aes_key),
        timeout=timeout,
        posture_snapshot=posture_snapshot,
    )

    try:
        async with smb_machine_with_fallback(config) as machine:
            connection = getattr(machine, "connection", machine)

            lookup = await _lookup_via_lsat(connection, rid)
            if lookup.resolved:
                return lookup
            lsat_error = lookup.error
            print_info_debug(
                f"native-local-account: LSAT RID {rid} lookup on {target} "
                f"did not resolve ({lsat_error}); trying SAMR"
            )

            samr_lookup = await _lookup_via_samr(connection, rid)
            if samr_lookup.resolved:
                return samr_lookup
            return LocalAccountLookup(
                rid=rid,
                host_sid=lookup.host_sid,
                error=f"LSAT: {lsat_error or 'no result'}; SAMR: {samr_lookup.error or 'no result'}",
            )
    except Exception as exc:  # noqa: BLE001 - resolution is best-effort by contract
        return LocalAccountLookup(rid=rid, error=f"{type(exc).__name__}: {exc}")


def resolve_local_account_name_by_rid_sync(
    *,
    host: str,
    domain: str,
    auth_domain: str = "",
    username: str = "",
    password: str | None = None,
    nt_hash: str | None = None,
    aes_key: str | None = None,
    ccache_path: str | None = None,
    kdc_ip: str | None = None,
    host_fqdn: str | None = None,
    rid: int = LOCAL_ADMIN_RID,
    posture_snapshot: Any = None,
    timeout: int = _DEFAULT_TIMEOUT_S,
) -> LocalAccountLookup:
    """Synchronous wrapper around :func:`resolve_local_account_name_by_rid`."""
    from adscan_internal.services.async_bridge import run_async_sync

    try:
        return run_async_sync(
            resolve_local_account_name_by_rid(
                host=host,
                domain=domain,
                auth_domain=auth_domain,
                username=username,
                password=password,
                nt_hash=nt_hash,
                aes_key=aes_key,
                ccache_path=ccache_path,
                kdc_ip=kdc_ip,
                host_fqdn=host_fqdn,
                rid=rid,
                posture_snapshot=posture_snapshot,
                timeout=timeout,
            )
        )
    except Exception as exc:  # noqa: BLE001 - never break a caller's flow
        return LocalAccountLookup(rid=rid, error=f"{type(exc).__name__}: {exc}")
