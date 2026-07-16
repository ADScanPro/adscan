"""CLI helpers for privilege enumeration commands."""

from __future__ import annotations

from typing import Any
import os

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_warning,
    telemetry,
)
from adscan_core.interaction import is_non_interactive
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.cli.rdp import run_rdp_service_access_sweep
from adscan_internal.services.service_access_probe_history import (
    load_service_access_probe_history,
    partition_targets_by_probe_history,
    record_service_access_probe_batch,
)
from adscan_internal.services.service_access_results import (
    render_no_confirmed_service_access,
    render_service_access_results,
    select_confirmed_service_access_followup_targets,
)
from adscan_internal.services.pivot_capability_registry import is_service_pivot_capable
from adscan_internal.services.auth_posture_service import get_ntlm_status
from adscan_internal.services.host_reachability_filter import (
    filter_reachable_hosts_sync,
    print_reachability_summary,
    render_no_reachable_panel,
)
from adscan_internal.services.winrm_access_probe_service import (
    WINRM_ACCESS_PROBE_BACKEND,
    get_winrm_probe_worker_count,
    run_winrm_access_probe_sweep,
)
from adscan_internal.services.smb_access_probe_service import (
    SMB_ACCESS_PROBE_BACKEND,
    get_smb_probe_worker_count,
    run_smb_access_probe_sweep,
)
from adscan_internal.services.mssql_access_probe_service import (
    DEFAULT_MSSQL_PORT,
    MSSQL_ACCESS_PROBE_BACKEND,
    get_mssql_probe_worker_count,
    run_mssql_access_probe_sweep,
)
from adscan_internal.workspaces import domain_subpath
from adscan_internal.workspaces.computers import (
    count_target_file_entries,
    consume_service_targeting_fallback_notice,
    load_target_entries,
    resolve_domain_service_scope_preference,
    resolve_domain_service_target_file,
)
from rich.prompt import Confirm


def _handle_confirmed_service_followups(
    shell: Any,
    *,
    domain: str,
    service: str,
    username: str,
    password: str,
    findings: list[Any],
    prompt: bool,
    workflow_intent: str | None = None,
) -> None:
    """Launch optional follow-up prompts for confirmed service-access findings."""
    if not prompt:
        for finding in findings:
            print_info_debug(
                "[service-access] service follow-up prompt suppressed: "
                f"service={service} user={mark_sensitive(finding.username, 'user')} "
                f"host={mark_sensitive(finding.host, 'hostname')}"
            )
        return

    selected_followups, used_selector = (
        select_confirmed_service_access_followup_targets(
            shell,
            service=service,
            findings=findings,
        )
    )
    followups = selected_followups if used_selector else findings
    func = getattr(shell, f"ask_for_{service}_access", None)
    if not callable(func):
        return
    if not followups:
        return

    # SMB consolidates all confirmed hosts into one batched prompt (parity with
    # the legacy netexec path); other services prompt per-host.
    if service == "smb":
        selected_hosts = [finding.host for finding in followups]
        print_info_debug(
            "[service-access] launching batch SMB follow-up: "
            f"service={service} user={mark_sensitive(username, 'user')} "
            f"hosts={[mark_sensitive(host, 'hostname') for host in selected_hosts]}"
        )
        func(domain, selected_hosts, username, password)
        return

    for finding in followups:
        print_info_debug(
            "[service-access] launching service follow-up prompt: "
            f"service={service} user={mark_sensitive(finding.username, 'user')} "
            f"host={mark_sensitive(finding.host, 'hostname')}"
        )
        func(
            domain,
            finding.host,
            finding.username,
            password,
            **(
                {"workflow_intent": workflow_intent}
                if service == "winrm" and workflow_intent
                else {}
            ),
        )


def _run_winrm_psrp_service_access_sweep(
    shell: Any,
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    username: str,
    password: str,
    targets: list[str],
    prompt: bool,
    workflow_intent: str | None = None,
) -> bool:
    """Run a reusable PSRP-backed WinRM access sweep and persist normalized results."""
    posture_sink = None
    posture_snapshot = None
    try:
        from adscan_internal import get_console
        from adscan_internal.cli.widgets.intelligence_update import (
            render_intelligence_update,
        )
        from adscan_internal.services.domain_posture import get_posture
        from adscan_internal.services.posture_sink import (
            make_workspace_posture_sink,
        )

        posture_sink = make_workspace_posture_sink(
            shell.domains_data,
            on_finding=lambda finding: get_console().print(
                render_intelligence_update(finding)
            ),
        )
        posture_snapshot = get_posture(shell.domains_data, domain=domain)
    except Exception as posture_exc:  # noqa: BLE001
        telemetry.capture_exception(posture_exc)
        print_info_debug(
            f"[privileges] posture wiring skipped (non-fatal): {posture_exc}"
        )

    # Pre-flight TCP probe on 5985 — WinRM negotiation has its own per-host
    # timeout that adds up fast on offline workstations. Centralized via
    # host_reachability_filter so the summary line matches every other sweep.
    if len(targets) > 1:
        winrm_reach = filter_reachable_hosts_sync(targets, port=5985)
        print_reachability_summary(winrm_reach, service_label="WinRM")
        if not winrm_reach.reachable:
            render_no_reachable_panel(
                winrm_reach, operation_label="WinRM Access Sweep"
            )
            return False
        targets = list(winrm_reach.reachable)

    # Pre-mint ONE TGT for the whole WinRM sweep and reuse it across hosts, so
    # the secret touches the wire once instead of once per host (scale +
    # domain-lockout protection). SSOT: sweep_credential. The probe accepts a
    # ``.ccache`` path in its ``password`` slot and uses it directly.
    creds = getattr(shell, "current_creds", None) or {}
    winrm_auth_domain = creds.get("auth_domain") or domain
    winrm_kdc_ip = ""
    try:
        from adscan_internal.models.domain import resolve_dc_ip

        winrm_kdc_ip = str(resolve_dc_ip(shell.domains_data.get(domain, {}) or {}) or "")
    except Exception:  # noqa: BLE001
        winrm_kdc_ip = ""
    from adscan_internal.services.sweep_credential import resolve_sweep_credential

    winrm_cred = resolve_sweep_credential(
        shell,
        domain=domain,
        username=username,
        password=password,
        auth_domain=winrm_auth_domain,
        kdc_ip=winrm_kdc_ip or None,
    )
    if not winrm_cred.ok:
        print_warning(
            winrm_cred.abort_reason or "WinRM sweep aborted: credential pre-mint failed."
        )
        return False
    winrm_secret = winrm_cred.ccache_path or winrm_cred.password or password

    findings = run_winrm_access_probe_sweep(
        domain=domain,
        username=username,
        password=winrm_secret,
        targets=targets,
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain_data=shell.domains_data.get(domain, {}),
        auth_mode="kerberos",
        max_workers=get_winrm_probe_worker_count(),
        sync_clock_with_pdc=lambda value: bool(
            shell.do_sync_clock_with_pdc(value, verbose=True)
        ),
        posture_sink=posture_sink,
        posture_snapshot=posture_snapshot,
    )
    confirmed_findings = [finding for finding in findings if finding.is_confirmed]
    if findings:
        render_service_access_results(
            service="winrm",
            username=username,
            findings=findings,
            total_targets=len(targets),
        )
    else:
        render_no_confirmed_service_access(
            service="winrm",
            username=username,
            total_targets=len(targets),
        )

    try:
        record_service_access_probe_batch(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
            username=username,
            service="winrm",
            targets=targets,
            confirmed_hosts=[finding.host for finding in confirmed_findings],
            source="run_winrm_psrp_service_access_sweep",
            backend=WINRM_ACCESS_PROBE_BACKEND,
            pivot_capable=is_service_pivot_capable("winrm"),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[service-access] failed to persist WinRM PSRP probe history: {exc}"
        )

    if confirmed_findings:
        for finding in confirmed_findings:
            try:
                from adscan_internal.services.attack_graph_service import (
                    upsert_netexec_privilege_edge,
                )

                upsert_netexec_privilege_edge(
                    shell,
                    domain,
                    username=username,
                    relation="CanPSRemote",
                    target_ip=finding.host,
                    target_hostname=None,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        _handle_confirmed_service_followups(
            shell,
            domain=domain,
            service="winrm",
            username=username,
            password=password,
            findings=confirmed_findings,
            prompt=prompt,
            workflow_intent=workflow_intent,
        )
    return bool(confirmed_findings)


def _resolve_service_sweep_posture(shell, *, domain):
    """Resolve a posture sink + snapshot for one native service sweep.

    Returns ``(posture_sink, posture_snapshot)``. Either may be ``None`` when
    posture wiring fails — the native transport then uses conservative
    defaults, identical to the WinRM PSRP sweep. Best-effort: never raises.
    """
    posture_sink = None
    posture_snapshot = None
    try:
        from adscan_internal import get_console
        from adscan_internal.cli.widgets.intelligence_update import (
            render_intelligence_update,
        )
        from adscan_internal.services.domain_posture import get_posture
        from adscan_internal.services.posture_sink import (
            make_workspace_posture_sink,
        )

        posture_sink = make_workspace_posture_sink(
            shell.domains_data,
            on_finding=lambda finding: get_console().print(
                render_intelligence_update(finding)
            ),
        )
        posture_snapshot = get_posture(shell.domains_data, domain=domain)
    except Exception as posture_exc:  # noqa: BLE001
        telemetry.capture_exception(posture_exc)
        print_info_debug(
            f"[privileges] posture wiring skipped (non-fatal): {posture_exc}"
        )
    return posture_sink, posture_snapshot


def _ensure_service_sweep_posture_fresh(shell, *, domain) -> None:
    """Run the idempotent posture freshness guard at a native sweep entry.

    Best-effort: a posture probe failure never aborts the sweep. The DC IP is
    resolved via ``resolve_dc_ip`` so a silent ``None`` does not make Kerberos
    fall back to the target host as KDC.
    """
    try:
        from adscan_internal.models.domain import resolve_dc_ip
        from adscan_internal.services.posture_orchestration import (
            ensure_posture_fresh,
        )
        from adscan_internal.services.async_bridge import run_async_sync

        dc_ip = resolve_dc_ip(shell.domains_data.get(domain) or {})
        if not dc_ip:
            return
        run_async_sync(
            ensure_posture_fresh(shell, domain=domain, dc_ip=str(dc_ip))
        )
    except Exception as exc:  # noqa: BLE001 — posture guard is best-effort
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[privileges] ensure_posture_fresh skipped (non-fatal): {exc}"
        )


def _build_service_target_hostname_map(shell, *, domain, targets):
    """Build an IP→FQDN map from the workspace inventory for Kerberos SPNs.

    Only IP targets get a mapping; FQDN targets are already SPN-ready. Returns
    an empty dict when no inventory is available (the transport then relies on
    posture-gated NTLM fallback). Never raises.
    """
    mapping: dict[str, str] = {}
    try:
        from adscan_internal.services.kerberos_hostname_inventory import (
            load_workspace_ip_hostname_inventory,
        )

        workspace_dir = getattr(shell, "current_workspace_dir", None) or ""
        domains_dir = getattr(shell, "domains_dir", None) or ""
        if not workspace_dir or not domains_dir:
            return mapping
        inventory = load_workspace_ip_hostname_inventory(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
        )
        if not isinstance(inventory, dict):
            return mapping
        target_set = {str(t).strip().lower() for t in targets if str(t or "").strip()}
        for ip, candidates in inventory.items():
            ip_norm = str(ip or "").strip()
            if not ip_norm or ip_norm.lower() not in target_set:
                continue
            if not isinstance(candidates, list):
                continue
            for candidate in candidates:
                fqdn = str(candidate or "").strip().rstrip(".")
                if fqdn:
                    mapping[ip_norm] = fqdn
                    break
    except Exception as exc:  # noqa: BLE001 — inventory is best-effort
        telemetry.capture_exception(exc)
    return mapping


def _run_native_smb_service_access_sweep(
    shell,
    *,
    workspace_dir,
    domains_dir,
    domain,
    username,
    password,
    targets,
    prompt,
) -> bool:
    """Run a native aiosmb SMB admin-access sweep and persist the results.

    Mirrors :func:`_run_winrm_psrp_service_access_sweep`: posture-aware,
    bounded concurrency, TCP pre-filter on 445, normalized findings, probe
    history persistence, attack-graph edge recording, and the batched SMB
    follow-up UX. Returns whether any host confirmed admin access.
    """
    from adscan_internal.services.async_bridge import run_async_sync

    _ensure_service_sweep_posture_fresh(shell, domain=domain)
    posture_sink, posture_snapshot = _resolve_service_sweep_posture(
        shell, domain=domain
    )

    # Pre-flight TCP probe on 445 — skip offline hosts before paying auth cost.
    if len(targets) > 1:
        smb_reach = filter_reachable_hosts_sync(targets, port=445)
        print_reachability_summary(smb_reach, service_label="SMB")
        if not smb_reach.reachable:
            render_no_reachable_panel(smb_reach, operation_label="SMB Access Sweep")
            return False
        targets = list(smb_reach.reachable)

    creds = getattr(shell, "current_creds", None) or {}
    domain_data = shell.domains_data.get(domain, {}) or {}
    auth_domain = creds.get("auth_domain") or domain
    dc_ip = ""
    try:
        from adscan_internal.models.domain import resolve_dc_ip

        dc_ip = str(resolve_dc_ip(domain_data) or "")
    except Exception:  # noqa: BLE001
        dc_ip = ""
    target_hostnames = _build_service_target_hostname_map(
        shell, domain=domain, targets=targets
    )
    # Resolve the credential ONCE for the whole sweep: pre-mint a single TGT and
    # reuse it across every host, so the secret touches the wire once instead of
    # once per host (scale + domain-lockout protection). SSOT: sweep_credential.
    from adscan_internal.services.sweep_credential import resolve_sweep_credential

    sweep_cred = resolve_sweep_credential(
        shell,
        domain=domain,
        username=username,
        password=password,
        auth_domain=auth_domain,
        kdc_ip=dc_ip or None,
    )
    if not sweep_cred.ok:
        print_warning(
            sweep_cred.abort_reason or "SMB sweep aborted: credential pre-mint failed."
        )
        return False

    findings = run_async_sync(
        run_smb_access_probe_sweep(
            domain=domain,
            username=username,
            password=sweep_cred.password,
            nt_hash=sweep_cred.nt_hash,
            aes_key=sweep_cred.aes_key,
            ccache_path=sweep_cred.ccache_path,
            targets=targets,
            auth_domain=auth_domain,
            kdc_ip=dc_ip or None,
            target_hostnames=target_hostnames,
            max_workers=get_smb_probe_worker_count(),
            posture_sink=posture_sink,
            posture_snapshot=posture_snapshot,
        )
    )

    confirmed_findings = [finding for finding in findings if finding.is_confirmed]
    if findings:
        render_service_access_results(
            service="smb",
            username=username,
            findings=findings,
            total_targets=len(targets),
        )
    else:
        render_no_confirmed_service_access(
            service="smb",
            username=username,
            total_targets=len(targets),
        )

    try:
        record_service_access_probe_batch(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
            username=username,
            service="smb",
            targets=targets,
            confirmed_hosts=[finding.host for finding in confirmed_findings],
            source="run_native_smb_service_access_sweep",
            backend=SMB_ACCESS_PROBE_BACKEND,
            pivot_capable=is_service_pivot_capable("smb"),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[service-access] failed to persist native SMB probe history: {exc}"
        )

    if confirmed_findings:
        for finding in confirmed_findings:
            try:
                from adscan_internal.services.membership_snapshot import (
                    add_runtime_admin_to_edge,
                )

                add_runtime_admin_to_edge(
                    shell,
                    domain,
                    username=username,
                    host_identifier=finding.host,
                    target_hostname=target_hostnames.get(finding.host),
                    source="smb_pwn3d_verified",
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        _handle_confirmed_service_followups(
            shell,
            domain=domain,
            service="smb",
            username=username,
            password=password,
            findings=confirmed_findings,
            prompt=prompt,
        )
    return bool(confirmed_findings)


def run_mssql_authorization_collection(
    shell,
    *,
    domain,
    username,
    password,
    instances=None,
):
    """Materialize MSSQL authorization facts into the attack graph (SSOT).

    Single source of truth for "enumerate MSSQL authorization as credential X".
    Delegates to :func:`collect_mssql_authorization_sync`, which discovers
    instances (``MSSQLSvc`` SPNs ∩ ``mssql/ips.txt``), connects via the existing
    native TDS path, enumerates ``sys.server_principals`` / ``server_role_members``
    / ``server_permissions`` at the depth the connecting login allows, correlates
    SQL principals to AD graph nodes by SID (group login → group node for the
    blast radius), and upserts effective ``SQLAccess`` / ``SQLAdmin`` edges with
    raw evidence. Posture-aware Kerberos/NTLM is handled by the TDS backend.

    Returns the :class:`MSSQLCollectionSummary`. Never raises.
    """
    from adscan_internal.services.collector.mssql_collector import (
        MSSQLCollectionSummary,
        MSSQLCollectorConfig,
        collect_mssql_authorization_sync,
    )
    from adscan_internal.models.domain import resolve_dc_ip

    _ensure_service_sweep_posture_fresh(shell, domain=domain)

    domain_data = shell.domains_data.get(domain, {}) or {}
    kdc_host = resolve_dc_ip(domain_data)
    secret = str(password or "")
    is_ccache = secret.strip().lower().endswith(".ccache")
    use_kerberos = bool(
        is_ccache or str(domain_data.get("auth") or "").strip().lower() == "kerberos"
    )

    # Pre-mint ONE TGT and reuse its ccache across every discovered instance, so
    # the secret touches the wire once instead of once per instance (scale +
    # domain-lockout protection). SSOT: sweep_credential. Only on the Kerberos /
    # Windows-auth branch — a SQL-auth login has no domain TGT, so pre-minting
    # would (wrongly) abort it; the TDS backend keeps NTLM/SQL auth unchanged.
    if use_kerberos and not is_ccache:
        from adscan_internal.services.sweep_credential import resolve_sweep_credential

        mssql_cred = resolve_sweep_credential(
            shell,
            domain=domain,
            username=username,
            password=secret,
            kdc_ip=str(kdc_host) if kdc_host else None,
        )
        if not mssql_cred.ok:
            print_warning(
                mssql_cred.abort_reason
                or "MSSQL authorization collection aborted: credential pre-mint failed."
            )
            return MSSQLCollectionSummary()
        if mssql_cred.ccache_path:
            secret = mssql_cred.ccache_path
            is_ccache = True

    config = MSSQLCollectorConfig(
        domain=domain,
        username=username,
        secret=secret,
        use_kerberos=use_kerberos,
        kdc_host=str(kdc_host) if kdc_host else None,
    )
    summary = collect_mssql_authorization_sync(
        shell, domain, config, instances=instances
    )
    print_info_debug(
        "[service-access] MSSQL authorization collection: "
        f"user={mark_sensitive(username, 'user')} "
        f"instances={summary.instances_discovered} "
        f"connected={summary.instances_connected} "
        f"SQLAccess={summary.sqlaccess_edges} SQLAdmin={summary.sqladmin_edges}"
    )
    return summary


def _resolve_mssql_ntlm_fallback_secret(
    shell,
    *,
    domain: str,
    username: str,
    wire_secret: str,
    password: str,
) -> str | None:
    """Resolve a password / NT hash for the NTLM fallback of a ccache-only sweep.

    A Kerberos-only MSSQL sweep sends a ``.ccache`` on the wire, which forecloses
    NTLM — so an instance with no ``MSSQLSvc`` SPN (Kerberos fails with
    ``KDC_ERR_S_PRINCIPAL_UNKNOWN``) is left unassessed. This returns a
    password / NT hash for the SAME principal so the backend can still try NTLM
    against those instances. Returns ``None`` (no fallback) when:

    - the wire secret is not a ccache (the primary attempt is already NTLM/SQL);
    - domain posture reports NTLM known-blocked (HIGH + ``DISABLED``) — never
      attempt NTLM the DC is known to reject;
    - only a ccache is available for the principal (no NTLM-usable secret).

    The sweep principal's domain password / NT hash lives in the generic
    credential store — NOT a host-scoped service ticket or a local credential —
    so the canonical resolver (:func:`_get_stored_domain_credential_for_user`)
    is used, credential-store-first.
    """
    if not str(wire_secret or "").strip().lower().endswith(".ccache"):
        return None

    from adscan_internal.services.domain_posture import (
        ConstraintCategory,
        SignalConfidence,
        TriState,
        get_posture,
    )

    ntlm_state = get_posture(shell.domains_data, domain=domain).get(
        ConstraintCategory.NTLM_AUTHENTICATION
    )
    if (
        ntlm_state.confidence is SignalConfidence.HIGH
        and ntlm_state.effective_state is TriState.DISABLED
    ):
        print_info_debug(
            "[mssql_probe] NTLM known-blocked by posture — "
            "skipping ccache-only NTLM fallback"
        )
        return None

    # Prefer the in-hand sweep secret when it is a usable password / NT hash;
    # otherwise fall back to the canonical credential-store resolver (covers the
    # ccache-only case where ``password`` is itself a ticket path).
    candidate = str(password or "").strip()
    if not candidate or candidate.lower().endswith(".ccache"):
        from adscan_internal.cli.attack_path_execution import (
            _get_stored_domain_credential_for_user,
        )

        candidate = (
            _get_stored_domain_credential_for_user(
                shell, domain=domain, username=username
            )
            or ""
        )
    candidate = str(candidate).strip()
    if not candidate or candidate.lower().endswith(".ccache"):
        return None
    return candidate


def _run_native_mssql_service_access_sweep(
    shell,
    *,
    workspace_dir,
    domains_dir,
    domain,
    username,
    password,
    targets,
    prompt,
) -> bool:
    """Run a native impacket MSSQL login sweep and trigger the followups.

    Discovery + edge materialization are delegated to the shared collector
    (:func:`run_mssql_authorization_collection`) — the single source of truth
    that resolves SQL principals to AD nodes by SID and emits effective
    ``SQLAccess`` / ``SQLAdmin`` edges with evidence. This function keeps only
    the **trigger + execution** role: the login sweep that confirms which hosts
    the current credential can reach (posture-aware, TCP pre-filter on 1433,
    normalized findings, probe history) and the confirmed-access followup UX.
    """
    from adscan_internal.services.async_bridge import run_async_sync

    _ensure_service_sweep_posture_fresh(shell, domain=domain)

    if len(targets) > 1:
        mssql_reach = filter_reachable_hosts_sync(targets, port=DEFAULT_MSSQL_PORT)
        print_reachability_summary(mssql_reach, service_label="MSSQL")
        if not mssql_reach.reachable:
            render_no_reachable_panel(
                mssql_reach, operation_label="MSSQL Access Sweep"
            )
            return False
        targets = list(mssql_reach.reachable)

    target_hostnames = _build_service_target_hostname_map(
        shell, domain=domain, targets=targets
    )

    # Pass the DC/KDC IP so impacket's self-minted AS-REQ/TGS-REQ reaches the
    # KDC even when the container has no AD DNS to resolve it from the domain.
    from adscan_internal.models.domain import resolve_dc_ip

    kdc_host = resolve_dc_ip(shell.domains_data.get(domain) or {})

    # Pre-mint ONCE for Kerberos/Windows auth and reuse the ccache across hosts
    # (scale + domain-lockout protection). SSOT: sweep_credential. SQL-auth logins
    # have no domain TGT → skip the pre-mint (preserves NTLM/SQL behavior); the
    # service auto-forces Kerberos when ``secret`` is a ``.ccache`` path.
    mssql_secret = password
    mssql_domain_data = shell.domains_data.get(domain) or {}
    mssql_is_ccache = str(password or "").strip().lower().endswith(".ccache")
    mssql_use_kerberos = mssql_is_ccache or (
        str(mssql_domain_data.get("auth") or "").strip().lower() == "kerberos"
    )
    if mssql_use_kerberos and not mssql_is_ccache:
        from adscan_internal.services.sweep_credential import resolve_sweep_credential

        mssql_cred = resolve_sweep_credential(
            shell,
            domain=domain,
            username=username,
            password=password,
            kdc_ip=str(kdc_host) if kdc_host else None,
        )
        if not mssql_cred.ok:
            print_warning(
                mssql_cred.abort_reason
                or "MSSQL access sweep aborted: credential pre-mint failed."
            )
            return False
        mssql_secret = mssql_cred.ccache_path or password

    # A ccache-only sweep credential cannot drive an NTLM bind, so instances
    # with no MSSQLSvc SPN (Kerberos → KDC_ERR_S_PRINCIPAL_UNKNOWN) would be left
    # unassessed. Thread the principal's stored password / NT hash so the backend
    # can still try NTLM there — gated on NTLM not being known-blocked by posture.
    mssql_ntlm_fallback_secret = _resolve_mssql_ntlm_fallback_secret(
        shell,
        domain=domain,
        username=username,
        wire_secret=mssql_secret,
        password=password,
    )

    findings = run_async_sync(
        run_mssql_access_probe_sweep(
            domain=domain,
            username=username,
            secret=mssql_secret,
            targets=targets,
            target_hostnames=target_hostnames,
            kdc_host=kdc_host,
            max_workers=get_mssql_probe_worker_count(),
            ntlm_fallback_secret=mssql_ntlm_fallback_secret,
        )
    )

    confirmed_findings = [finding for finding in findings if finding.is_confirmed]
    if findings:
        render_service_access_results(
            service="mssql",
            username=username,
            findings=findings,
            total_targets=len(targets),
        )
    else:
        render_no_confirmed_service_access(
            service="mssql",
            username=username,
            total_targets=len(targets),
        )

    try:
        record_service_access_probe_batch(
            workspace_dir=workspace_dir,
            domains_dir=domains_dir,
            domain=domain,
            username=username,
            service="mssql",
            targets=targets,
            confirmed_hosts=[finding.host for finding in confirmed_findings],
            source="run_native_mssql_service_access_sweep",
            backend=MSSQL_ACCESS_PROBE_BACKEND,
            pivot_capable=is_service_pivot_capable("mssql"),
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[service-access] failed to persist native MSSQL probe history: {exc}"
        )

    # Edge materialization — delegate to the SSOT collector for this credential
    # (proper SID correlation + group blast-radius + evidence). This replaces the
    # legacy per-host ``upsert_netexec_privilege_edge`` loop so there is exactly
    # one MSSQL discovery/edge path. Best-effort: a collector failure never
    # blocks the confirmed-access followups below.
    try:
        run_mssql_authorization_collection(
            shell, domain=domain, username=username, password=password
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[service-access] MSSQL authorization collection skipped (non-fatal): {exc}"
        )

    if confirmed_findings:
        _handle_confirmed_service_followups(
            shell,
            domain=domain,
            service="mssql",
            username=username,
            password=password,
            findings=confirmed_findings,
            prompt=prompt,
        )
    return bool(confirmed_findings)



def _resolve_winrm_psrp_backend_reason(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
) -> str:
    """Return a label describing why this credential context routes to PSRP.

    WinRM access checks always run through PSRP — NetExec's WinRM backend is
    NTLM-only, breaks under hardened Kerberos posture (AES-only, channel
    binding), and parses output inconsistently across versions. The returned
    string is purely informational for logs and telemetry.
    """
    if str(password or "").strip().lower().endswith(".ccache"):
        return "credential_ccache"

    domain_data = getattr(shell, "domains_data", {}).get(domain, {})
    kerberos_tickets = (
        domain_data.get("kerberos_tickets", {}) if isinstance(domain_data, dict) else {}
    )
    if isinstance(kerberos_tickets, dict):
        username_key = str(username or "").strip().casefold()
        if any(
            str(key or "").strip().casefold() == username_key
            for key in kerberos_tickets
        ):
            return "stored_kerberos_ticket"

    if (
        get_ntlm_status(
            getattr(shell, "domains_data", {}),
            domain=domain,
            protocol="winrm",
        )
        == "likely_disabled"
    ):
        return "ntlm_likely_disabled"
    return "default"


def _build_service_sweep_target_argument(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    service: str,
    username: str,
    targets: list[str],
) -> str | None:
    """Materialize one host list into the argument expected by service backends."""
    cleaned_targets = [
        str(target).strip() for target in targets if str(target or "").strip()
    ]
    if not cleaned_targets:
        return None
    if len(cleaned_targets) == 1:
        return cleaned_targets[0]

    tmp_dir = domain_subpath(workspace_dir, domains_dir, domain, "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    targets_path = os.path.join(
        tmp_dir,
        f"hosts.{service}.{username}.filtered.txt",
    )
    with open(targets_path, "w", encoding="utf-8") as handle:
        for entry in cleaned_targets:
            handle.write(entry + "\n")
    return targets_path


def _select_effective_service_targets(
    shell: Any,
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    username: str,
    service: str,
    current_targets: list[str],
    include_previously_tested: bool,
) -> list[str]:
    """Return the target list that should be probed for one service sweep.

    By default, previously tested targets are skipped. When every target was
    already checked, the caller may offer a re-check prompt with a default of
    ``No`` so the operator can intentionally opt back into reprobing.
    """
    if include_previously_tested:
        return list(current_targets)

    history = load_service_access_probe_history(
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=domain,
    )
    fresh_targets, previous_records = partition_targets_by_probe_history(
        records=history,
        username=username,
        service=service,
        targets=current_targets,
    )
    if fresh_targets:
        if previous_records:
            print_info(
                f"Skipping {len(previous_records)} previously tested "
                f"{service.upper()} target(s) by default. Checking "
                f"{len(fresh_targets)} new target(s)."
            )
            skipped_hosts = [
                mark_sensitive(str(record.get("host") or ""), "hostname")
                for record in previous_records
                if str(record.get("host") or "").strip()
            ]
            if skipped_hosts:
                print_info_debug(
                    "[privileges] previously tested targets skipped by default: "
                    f"service={service} user={mark_sensitive(username, 'user')} "
                    f"targets={skipped_hosts}"
                )
        return fresh_targets

    if not previous_records:
        return list(current_targets)

    prompt = (
        f"All current {service.upper()} targets for "
        f"{mark_sensitive(username, 'user')} were tested before. Re-check them now?"
    )
    confirmer = getattr(shell, "_questionary_confirm", None)
    should_recheck = (
        bool(confirmer(prompt, default=False)) if callable(confirmer) else False
    )
    if should_recheck:
        print_info(
            f"Re-checking {len(previous_records)} previously tested "
            f"{service.upper()} target(s) by user choice."
        )
        return list(current_targets)

    print_info(
        f"Skipping {service.upper()} sweep because all {len(previous_records)} "
        "current target(s) were already tested."
    )
    return []


def _resolve_next_broader_scope(
    *,
    service: str,
    source: str,
    current_scope_preference: str,
) -> str | None:
    """Return the next broader target scope after one empty sweep."""
    normalized_source = str(source or "").strip().lower()
    normalized_scope = str(current_scope_preference or "optimized").strip().lower()

    if normalized_scope == "full":
        return None
    if normalized_scope == "reachable":
        return "full"
    if normalized_source.startswith(f"{service}_ips"):
        return "reachable"
    if normalized_source.startswith("reachable_ips"):
        return "full"
    return None


def _prompt_broader_postauth_scope_retry(
    shell: Any,
    *,
    service: str,
    domain: str,
    current_source: str,
    next_scope_preference: str,
    next_target_count: int,
) -> bool:
    """Ask whether to retry one empty service sweep with a broader scope."""
    _ = domain
    if is_non_interactive(shell):
        return False
    if not hasattr(shell, "_questionary_select"):
        return False

    scope_label_map = {
        "reachable": "Current-vantage reachable hosts only",
        "full": "Full resolved host scope",
    }
    next_scope_label = scope_label_map.get(next_scope_preference, next_scope_preference)
    options = [
        f"Retry {service.upper()} sweep with {next_scope_label} ({next_target_count} targets)",
        "Skip broader retry",
    ]
    selected_idx = shell._questionary_select(  # type: ignore[attr-defined]
        (
            f"No {service.upper()} privileges were found using "
            f"{current_source}. Broaden the sweep?"
        ),
        options,
        default_idx=0,
    )
    return selected_idx == 0


def run_enum_all_user_postauth_access(shell: Any, args: str | None) -> None:
    """Run post-auth user access enumeration for all users in a domain.

    This extracts the logic from the shell wrapper so orchestration
    can live outside ``adscan.py``.
    """
    if not args:
        print_error("You must specify a domain. Usage: enum_all_privs <domain>")
        return

    domain = args.strip()

    # Verify that the domain exists in domains_data
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"The domain {marked_domain} is not in the database.")
        return

    marked_domain = mark_sensitive(domain, "domain")
    print_success(
        f"Enumerating post-auth access for all users in domain {marked_domain}"
    )

    # Check if credentials are stored
    if (
        "credentials" not in shell.domains_data[domain]
        or not shell.domains_data[domain]["credentials"]
    ):
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"No credentials stored for domain {marked_domain}")
        return

    auto = Confirm.ask("Do you want to perform automatic enumeration", default=False)

    # Iterate over each user and their credentials
    for username, credential in shell.domains_data[domain]["credentials"].items():
        # Check if the credential is a hash or a password
        if shell.is_hash(credential):
            marked_username = mark_sensitive(username, "user")
            print_error(
                f"Skipping user {marked_username} - has a hash instead of a password"
            )
            continue

        # Call ask_for_user_privs for each user
        if not auto:
            auto = Confirm.ask(
                "Do you want to switch to automatic enumeration", default=False
            )
        shell.ask_for_user_privs(domain, username, credential, auto)


def run_enum_all_user_privs(shell: Any, args: str | None) -> None:
    """Backward-compatible alias for all-user post-auth access enumeration."""
    run_enum_all_user_postauth_access(shell, args)


def run_netexec_user_postauth_access(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
) -> None:
    """Enumerate post-auth service access for a user across multiple services."""
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain {marked_domain} not found.")
        return

    marked_username = mark_sensitive(username, "user")
    marked_domain = mark_sensitive(domain, "domain")
    response = Confirm.ask(
        "Do you want to enumerate host/service access for user "
        f"{marked_username} on various services on hosts? "
        f"(⚠ WARNING: This will saturate the network if the number of hosts in domain {marked_domain} is very high)"
    )
    if not response:
        return

    run_service_access_sweep(
        shell,
        domain=domain,
        username=username,
        password=password,
        services=["smb", "winrm", "rdp", "mssql"],
        hosts=hosts,
        prompt=True,
        scope_preference="optimized",
    )


def run_postauth_service_and_share_followup(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
    prompt: bool = False,
    scope_preference: str = "optimized",
) -> None:
    """Run the standard post-auth follow-up for one user.

    This is the shared "minimal valuable" post-auth workflow reused by attack-step
    follow-ups and post-pivot follow-ups:

    1. Probe service access across SMB/WinRM/RDP/MSSQL.
    2. Enumerate authenticated SMB shares reachable by that user.
    """
    from adscan_internal.cli.smb_shares_view import SharesViewMode, run_native_shares_view

    run_service_access_sweep(
        shell,
        domain=domain,
        username=username,
        password=password,
        services=["smb", "winrm", "rdp", "mssql"],
        hosts=hosts,
        prompt=prompt,
        scope_preference=scope_preference,
    )
    run_native_shares_view(
        shell,
        domain=domain,
        mode=SharesViewMode.LIVE,
        username=username,
        credential=password,
    )


def run_netexec_user_privs(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
) -> None:
    """Backward-compatible alias for post-auth user access enumeration."""
    run_netexec_user_postauth_access(
        shell,
        domain=domain,
        username=username,
        password=password,
        hosts=hosts,
    )


def run_service_access_sweep(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    services: list[str],
    hosts: list[str] | None = None,
    prompt: bool = False,
    scope_preference: str = "optimized",
    include_previously_tested: bool = False,
    workflow_intent: str | None = None,
) -> None:
    """Enumerate access across a set of services for one user."""
    if domain not in shell.domains_data:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Domain {marked_domain} not found.")
        return

    for service in services:
        try:
            workspace_cwd = (
                shell._get_workspace_cwd()  # type: ignore[attr-defined]
                if hasattr(shell, "_get_workspace_cwd")
                else getattr(shell, "current_workspace_dir", os.getcwd())
            )
            domains_dir = getattr(shell, "domains_dir", "domains")

            cleaned_hosts = [
                h.strip() for h in (hosts or []) if isinstance(h, str) and h.strip()
            ]
            current_scope_preference = scope_preference
            if not cleaned_hosts and current_scope_preference == "optimized":
                current_scope_preference = resolve_domain_service_scope_preference(
                    shell,
                    workspace_dir=workspace_cwd,
                    domains_dir=domains_dir,
                    domain=domain,
                    service=service,
                    domain_data=shell.domains_data.get(domain, {}),
                    prompt_title=(
                        f"Choose the target scope for {service.upper()} post-auth service sweeps:"
                    ),
                )
            while True:
                targets: str | None = None
                original_targets_arg: str | None = None
                current_target_entries: set[str] = set()
                source = "explicit_hosts"
                if cleaned_hosts:
                    current_target_list = list(dict.fromkeys(cleaned_hosts))
                    current_target_entries = {
                        entry.lower() for entry in current_target_list
                    }
                    original_targets_arg = _build_service_sweep_target_argument(
                        workspace_dir=workspace_cwd,
                        domains_dir=domains_dir,
                        domain=domain,
                        service=service,
                        username=username,
                        targets=current_target_list,
                    )
                    targets = original_targets_arg
                else:
                    default_hosts_file, source = resolve_domain_service_target_file(
                        workspace_cwd,
                        domains_dir,
                        domain,
                        service=service,
                        domain_data=shell.domains_data.get(domain, {}),
                        scope_preference=current_scope_preference,
                    )
                    if not default_hosts_file:
                        if source.endswith("_no_open_hosts_current_vantage"):
                            print_info(
                                f"{service.upper()} sweep skipped: no "
                                f"{service.upper()}-open hosts were found in the "
                                "current-vantage port inventory."
                            )
                            print_info_debug(
                                "[privileges] skipping service sweep because "
                                f"source={source} domain={mark_sensitive(domain, 'domain')} "
                                f"service={service}"
                            )
                        break
                    targets = default_hosts_file
                    target_count = count_target_file_entries(default_hosts_file)
                    print_info_debug(
                        f"[privileges] using domain target file source={source} "
                        f"for {mark_sensitive(domain, 'domain')}: "
                        f"{mark_sensitive(str(targets), 'path')}"
                    )
                    print_info(
                        f"{service.upper()} sweep scope: "
                        f"{mark_sensitive(source, 'detail')} "
                        f"({target_count} target(s))"
                    )
                    targeting_notice = consume_service_targeting_fallback_notice(
                        shell,
                        workspace_dir=workspace_cwd,
                        domains_dir=domains_dir,
                        domain=domain,
                        service=service,
                        source=source,
                    )
                    if targeting_notice:
                        print_info(targeting_notice)
                    current_target_entries = load_target_entries(default_hosts_file)
                    current_target_list = sorted(current_target_entries)
                    original_targets_arg = default_hosts_file

                effective_target_list = _select_effective_service_targets(
                    shell,
                    workspace_dir=workspace_cwd,
                    domains_dir=domains_dir,
                    domain=domain,
                    username=username,
                    service=service,
                    current_targets=current_target_list,
                    include_previously_tested=include_previously_tested,
                )
                effective_target_entries = {
                    entry.lower() for entry in effective_target_list
                }
                if (
                    effective_target_list == current_target_list
                    and original_targets_arg
                ):
                    targets = original_targets_arg
                else:
                    targets = _build_service_sweep_target_argument(
                        workspace_dir=workspace_cwd,
                        domains_dir=domains_dir,
                        domain=domain,
                        service=service,
                        username=username,
                        targets=effective_target_list,
                    )
                if not targets:
                    found_hosts = False
                    if cleaned_hosts:
                        break
                    next_scope_preference = _resolve_next_broader_scope(
                        service=service,
                        source=source,
                        current_scope_preference=current_scope_preference,
                    )
                    if not next_scope_preference:
                        break
                    next_targets_file, _next_source = (
                        resolve_domain_service_target_file(
                            workspace_cwd,
                            domains_dir,
                            domain,
                            service=service,
                            domain_data=shell.domains_data.get(domain, {}),
                            scope_preference=next_scope_preference,
                        )
                    )
                    next_target_count = count_target_file_entries(next_targets_file)
                    if not next_targets_file or next_target_count <= 0:
                        break
                    next_target_entries = load_target_entries(next_targets_file)
                    if next_target_entries and next_target_entries.issubset(
                        current_target_entries
                    ):
                        print_info_debug(
                            "[privileges] skipping broader sweep prompt because "
                            f"{mark_sensitive(next_scope_preference, 'detail')} does not add "
                            f"new {service.upper()} targets beyond "
                            f"{mark_sensitive(source, 'detail')}"
                        )
                        break
                    if not _prompt_broader_postauth_scope_retry(
                        shell,
                        service=service,
                        domain=domain,
                        current_source=source,
                        next_scope_preference=next_scope_preference,
                        next_target_count=next_target_count,
                    ):
                        break
                    current_scope_preference = next_scope_preference
                    continue

                marked_domain = mark_sensitive(domain, "domain")
                marked_username = mark_sensitive(username, "user")
                print_info(
                    f"Starting {service} privilege enumeration for user {marked_username}"
                )
                if service == "rdp":
                    print_info_debug(
                        "[privileges] service access sweep dispatch: "
                        f"domain={marked_domain} user={marked_username} service={service} "
                        f"backend=aardwolf prompt_on_success={prompt!r} "
                        f"targets={mark_sensitive(str(targets), 'path')}"
                    )
                    found_hosts = bool(
                        run_rdp_service_access_sweep(
                            shell,
                            domain=domain,
                            username=username,
                            password=password,
                            targets=str(targets),
                            prompt=prompt,
                            target_count=(
                                len(cleaned_hosts)
                                if cleaned_hosts
                                else len(effective_target_list)
                            ),
                        )
                    )
                elif service == "winrm":
                    winrm_psrp_reason = _resolve_winrm_psrp_backend_reason(
                        shell,
                        domain=domain,
                        username=username,
                        password=password,
                    )
                    print_info(
                        "Using PSRP backend for WINRM access checks "
                        f"({mark_sensitive(winrm_psrp_reason, 'detail')})."
                    )
                    print_info_debug(
                        "[privileges] service access sweep dispatch: "
                        f"domain={marked_domain} user={marked_username} service={service} "
                        f"backend={WINRM_ACCESS_PROBE_BACKEND} reason={winrm_psrp_reason} "
                        f"prompt_on_success={prompt!r} "
                        f"targets={mark_sensitive(str(targets), 'path')}"
                    )
                    found_hosts = _run_winrm_psrp_service_access_sweep(
                        shell,
                        workspace_dir=workspace_cwd,
                        domains_dir=domains_dir,
                        domain=domain,
                        username=username,
                        password=password,
                        targets=effective_target_list,
                        prompt=prompt,
                        workflow_intent=workflow_intent,
                    )
                elif service == "smb":
                    print_info(
                        "Using native aiosmb backend for SMB access checks."
                    )
                    print_info_debug(
                        "[privileges] service access sweep dispatch: "
                        f"domain={marked_domain} user={marked_username} service={service} "
                        f"backend={SMB_ACCESS_PROBE_BACKEND} "
                        f"prompt_on_success={prompt!r} "
                        f"targets={mark_sensitive(str(targets), 'path')}"
                    )
                    found_hosts = _run_native_smb_service_access_sweep(
                        shell,
                        workspace_dir=workspace_cwd,
                        domains_dir=domains_dir,
                        domain=domain,
                        username=username,
                        password=password,
                        targets=effective_target_list,
                        prompt=prompt,
                    )
                elif service == "mssql":
                    print_info(
                        "Using native impacket TDS backend for MSSQL access checks."
                    )
                    print_info_debug(
                        "[privileges] service access sweep dispatch: "
                        f"domain={marked_domain} user={marked_username} service={service} "
                        f"backend={MSSQL_ACCESS_PROBE_BACKEND} "
                        f"prompt_on_success={prompt!r} "
                        f"targets={mark_sensitive(str(targets), 'path')}"
                    )
                    found_hosts = _run_native_mssql_service_access_sweep(
                        shell,
                        workspace_dir=workspace_cwd,
                        domains_dir=domains_dir,
                        domain=domain,
                        username=username,
                        password=password,
                        targets=effective_target_list,
                        prompt=prompt,
                    )
                else:
                    # Every service ADscan sweeps (smb, winrm, rdp, mssql) has a
                    # native backend handled above; there is no subprocess
                    # fallback. An unknown service value is a caller bug — skip
                    # it defensively instead of shelling out.
                    print_info_debug(
                        "[privileges] service access sweep dispatch: "
                        f"domain={marked_domain} user={marked_username} service={service} "
                        f"backend=none (no native probe for this service) "
                        f"prompt_on_success={prompt!r} "
                        f"targets={mark_sensitive(str(targets), 'path')}"
                    )
                    print_warning(
                        f"No native access-check backend for service '{service}'; skipping."
                    )
                    found_hosts = False
                if found_hosts or cleaned_hosts:
                    break

                next_scope_preference = _resolve_next_broader_scope(
                    service=service,
                    source=source,
                    current_scope_preference=current_scope_preference,
                )
                if not next_scope_preference:
                    break
                next_targets_file, _next_source = resolve_domain_service_target_file(
                    workspace_cwd,
                    domains_dir,
                    domain,
                    service=service,
                    domain_data=shell.domains_data.get(domain, {}),
                    scope_preference=next_scope_preference,
                )
                next_target_count = count_target_file_entries(next_targets_file)
                if not next_targets_file or next_target_count <= 0:
                    break
                next_target_entries = load_target_entries(next_targets_file)
                if next_target_entries and next_target_entries.issubset(
                    effective_target_entries or current_target_entries
                ):
                    print_info_debug(
                        "[privileges] skipping broader sweep prompt because "
                        f"{mark_sensitive(next_scope_preference, 'detail')} does not add "
                        f"new {service.upper()} targets beyond "
                        f"{mark_sensitive(source, 'detail')}"
                    )
                    break
                if not _prompt_broader_postauth_scope_retry(
                    shell,
                    service=service,
                    domain=domain,
                    current_source=source,
                    next_scope_preference=next_scope_preference,
                    next_target_count=next_target_count,
                ):
                    break
                current_scope_preference = next_scope_preference
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error(f"Error processing service {service}.")
            print_exception(show_locals=False, exception=exc)


def run_user_postauth_access_with_orchestration(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
    include_acl_enumeration: bool = True,
) -> None:
    """Enumerate post-auth user opportunities after attack-path review.

    This flow focuses on service access, delegations, ADCS, shares, and
    spraying. Low-priv ACL review is intentionally optional and can be skipped
    by callers such as ``ask_for_user_privs`` because attack paths already
    surface those routes earlier in the UX.
    """
    from rich.prompt import Confirm

    # First, run the basic privilege enumeration
    run_netexec_user_postauth_access(
        shell, domain=domain, username=username, password=password, hosts=hosts
    )

    # Additional orchestration after privilege enumeration
    if include_acl_enumeration:
        shell.ask_for_enumerate_user_aces(domain, username, password)

    # Check if the user has Kerberos delegations in the attack graph.
    # Data is persisted by the native LDAP collector (allowedtodelegate +
    # hasunconstrainedauth on the user's node). No subprocess re-enum.
    try:
        from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
            get_node_by_label,
        )

        _node = get_node_by_label(
            shell, domain, label=f"{username.upper()}@{domain.upper()}"
        )
        _props = (_node or {}).get("properties", {}) if _node else {}
        _constrained_spns: list = list(_props.get("allowedtodelegate") or [])
        _unconstrained: bool = bool(_props.get("hasunconstrainedauth"))
        if _constrained_spns or _unconstrained:
            marked_username = mark_sensitive(username, "user")
            if _constrained_spns:
                print_info(
                    f"User {marked_username} has constrained delegation "
                    f"configured for: {', '.join(_constrained_spns)}"
                )
            if _unconstrained:
                print_warning(
                    f"User {marked_username} has unconstrained delegation — "
                    "high-value target for ticket harvesting."
                )
    except Exception as _exc:  # noqa: BLE001
        telemetry.capture_exception(_exc)

    # Check if there is ADCS in the domain
    if shell.domains_data[domain].get("adcs"):
        marked_username = mark_sensitive(username, "user")
        respuesta_adcs = Confirm.ask(
            f"Do you want to enumerate ADCS privileges for user {marked_username}?"
        )
        if respuesta_adcs:
            run_enum_adcs_privs(
                shell, domain=domain, username=username, password=password
            )

    if not (shell.type == "ctf" and shell.domains_data[domain]["auth"] == "pwned"):
        shell.ask_for_enum_shares(domain, username, password)
    if not (shell.type == "ctf" and shell.domains_data[domain]["auth"] == "pwned"):
        if shell.is_hash(password):
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_info_verbose(
                "Skipping password spraying prompt for user "
                f"{marked_username} in domain {marked_domain} because the "
                "credential is a hash."
            )
        else:
            marked_password = mark_sensitive(password, "password")
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            respuesta = Confirm.ask(
                "Do you want to perform a password spraying with the "
                f"{marked_password} password of the user {marked_username} "
                f"in the {marked_domain} domain?"
            )
            if respuesta:
                shell.spraying_with_password(domain, password)
    marked_username = mark_sensitive(username, "user")
    print_success(f"Complete enumeration for user {marked_username}")


def run_netexec_user_privs_with_orchestration(
    shell: Any,
    *,
    domain: str,
    username: str,
    password: str,
    hosts: list[str] | None = None,
    include_acl_enumeration: bool = True,
) -> None:
    """Backward-compatible alias for post-auth user access orchestration."""
    run_user_postauth_access_with_orchestration(
        shell,
        domain=domain,
        username=username,
        password=password,
        hosts=hosts,
        include_acl_enumeration=include_acl_enumeration,
    )


def run_enum_adcs_privs(
    shell: Any, *, domain: str, username: str, password: str
) -> None:
    """Enumerate ADCS privileges for a user and prompt for exploitation."""
    from adscan_internal.cli.adcs import ask_for_adcs_esc

    try:
        pdc_ip = shell.domains_data[domain].get("pdc")
        if not pdc_ip:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Missing PDC IP for domain {marked_domain}. "
                "Re-run domain initialization or update domain data."
            )
            return

        marked_username = mark_sensitive(username, "user")
        marked_domain = mark_sensitive(domain, "domain")
        print_info(
            f"Enumerating ADCS privileges for user {marked_username} in domain {marked_domain}"
        )

        domain_dir = shell.domains_data[domain].get("dir")
        vulnerabilities = None

        # Try native collector inventory first (Phase 1 already ran).
        if isinstance(domain_dir, str) and domain_dir:
            try:
                from adscan_internal.services.attack_graph_service import (
                    _attack_path_get_recursive_groups,
                    resolve_adcs_vulns_from_inventory,
                )

                groups = _attack_path_get_recursive_groups(
                    shell, domain=domain, samaccountname=username
                )
                vulnerabilities = resolve_adcs_vulns_from_inventory(
                    domain_dir, username=username, groups=groups
                )
                if vulnerabilities is not None:
                    print_info_verbose(
                        f"[ADCS] Loaded {len(vulnerabilities)} finding(s) from native collector inventory."
                    )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                vulnerabilities = None

        if vulnerabilities is None:
            print_info(
                "No ADCS inventory found for this domain. "
                "Run a full scan to populate the ADCS inventory."
            )
            return

        # Process vulnerabilities
        ca_vulns = [v for v in vulnerabilities if v.source == "ca"]
        template_vulns = [v for v in vulnerabilities if v.source == "template"]

        if ca_vulns:
            marked_username = mark_sensitive(username, "user")
            print_warning(
                f"Vulnerabilities in Certificate Authorities for user {marked_username}:"
            )
            for vuln in sorted(ca_vulns, key=lambda v: int(v.esc_number)):
                shell.console.print(f"   - ESC{vuln.esc_number}")
                ask_for_adcs_esc(
                    shell,
                    domain=domain,
                    esc=vuln.esc_number,
                    username=username,
                    password=password,
                    template=None,
                )
        else:
            marked_username = mark_sensitive(username, "user")
            print_error(
                f"No vulnerabilities found in Certificate Authorities for user {marked_username}"
            )

        if template_vulns:
            for vuln in template_vulns:
                print_warning(
                    f"Vulnerability in template '{vuln.template}': ESC{vuln.esc_number}"
                )
                ask_for_adcs_esc(
                    shell,
                    domain=domain,
                    esc=vuln.esc_number,
                    username=username,
                    password=password,
                    template=vuln.template,
                )
        elif not ca_vulns:
            print_error("No vulnerabilities found in Certificate Templates.")

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error enumerating ADCS.")
        print_exception(show_locals=False, exception=e)


def run_raise_child(shell: Any, *, domain: str, username: str, password: str) -> None:
    """Escalate from a child domain to the forest root using the native skelsec stack.

    Uses ``raise_child_native`` (kerbad + aiosmb DRSUAPI + native ticket forging).
    No subprocess, no impacket dependency at runtime.  Survives NTLM-disabled,
    AES-only, and signing-required environments.
    """
    from adscan_internal.services.exploitation import ExploitationService

    try:
        if domain not in shell.domains_data:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(f"Domain {marked_domain} is not initialized in this session.")
            return

        parts = domain.split(".", 1)
        if len(parts) < 2 or parts[1] not in shell.domains_data:
            marked_domain = mark_sensitive(domain, "domain")
            print_error(
                f"Cannot identify a parent domain for {marked_domain}. "
                "raise_child requires the parent (forest root) domain to be initialized first."
            )
            return

        parent_domain = parts[1]
        child_dc_ip = shell.domains_data[domain].get("pdc")
        parent_dc_ip = shell.domains_data[parent_domain].get("pdc")
        if not child_dc_ip or not parent_dc_ip:
            print_error(
                "Missing PDC IP for child or parent domain. "
                "Re-run domain initialization."
            )
            return

        child_dc_hostname = shell.domains_data[domain].get("pdc_hostname")
        parent_dc_hostname = shell.domains_data[parent_domain].get("pdc_hostname")

        # Decide credential shape: NT hash if password is hash-shaped, else password.
        password_arg: str | None = password
        nt_hash_arg: str | None = None
        try:
            if shell.is_hash(password):
                password_arg = None
                nt_hash_arg = password
        except Exception:
            pass

        marked_child = mark_sensitive(domain, "domain")
        marked_parent = mark_sensitive(parent_domain, "domain")
        print_info_verbose(
            f"[raise_child] native escalation: {marked_child} -> {marked_parent}"
        )

        service = ExploitationService()
        result = service.persistence.raise_child_native(
            child_domain=domain,
            child_dc_ip=child_dc_ip,
            parent_domain=parent_domain,
            parent_dc_ip=parent_dc_ip,
            username=username,
            password=password_arg,
            nt_hash=nt_hash_arg,
            child_dc_hostname=child_dc_hostname,
            parent_dc_hostname=parent_dc_hostname,
        )

        if not result.success:
            stage = result.stage_failed or "unknown"
            detail = result.error or "no error detail returned"
            print_error(
                f"raise_child native escalation failed at stage '{stage}': {detail}"
            )
            # Surface partial credentials (e.g. child krbtgt) so the operator can
            # use them downstream even if the parent dump did not complete.
            for cred in result.credentials:
                marked_username = mark_sensitive(cred["username"], "user")
                marked_nt_hash = mark_sensitive(cred["nt_hash"], "password")
                print_warning(
                    f"Partial credential recovered - Domain: {cred['domain']}, "
                    f"User: {marked_username}, NT Hash: {marked_nt_hash}"
                )
                shell.add_credential(cred["domain"], cred["username"], cred["nt_hash"], credential_origin="dcsync")
            return

        # Success: surface all credentials and the forged ccache path.
        for cred in result.credentials:
            marked_username = mark_sensitive(cred["username"], "user")
            marked_nt_hash = mark_sensitive(cred["nt_hash"], "password")
            print_warning(
                f"Credential found - Domain: {cred['domain']}, "
                f"User: {marked_username}, NT Hash: {marked_nt_hash}"
            )
            shell.add_credential(cred["domain"], cred["username"], cred["nt_hash"], credential_origin="dcsync")

        if result.forged_ticket_path:
            print_info_debug(
                f"[raise_child] inter-realm ccache: {result.forged_ticket_path}"
            )

        print_success(
            f"Escalation completed. {marked_child} -> forest root "
            f"{marked_parent} (admin: {result.parent_administrator or 'Administrator'})."
        )

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing raise_child.")
        print_exception(show_locals=False, exception=e)


def run_enum_cross_domain_acl(shell: Any, *, domain: str) -> None:
    """Enumerate cross-domain ACLs and show options to exploit them."""
    shell.enumerate_user_aces(domain, "", "", cross_domain=True)


def ask_for_enum_cross_domain_acl(shell: Any, *, domain: str) -> None:
    """Ask if you want to attempt to enumerate ACLs from this domain to other domains."""
    # Only prompt if there is at least one other domain configured
    if not any(d != domain for d in shell.domains):
        return

    marked_domain = mark_sensitive(domain, "domain")
    respuesta = Confirm.ask(
        f"Do you want to attempt to enumerate the ACLs from domain {marked_domain} to other domains?"
    )
    if respuesta:
        run_enum_cross_domain_acl(shell, domain=domain)


def ask_for_raise_child(
    shell: Any, *, domain: str, username: str, password: str
) -> None:
    """Ask if you want to attempt to escalate from the child domain to the parent domain."""
    # Only prompt if domain is a subdomain of a configured parent domain
    parts = domain.split(".", 1)
    if len(parts) < 2 or parts[1] not in shell.domains:
        return

    marked_domain = mark_sensitive(domain, "domain")
    respuesta = Confirm.ask(
        f"Do you want to attempt to escalate from the child domain {marked_domain} to the parent domain?"
    )
    if respuesta:
        run_raise_child(shell, domain=domain, username=username, password=password)
    else:
        ask_for_enum_cross_domain_acl(shell, domain=domain)


def run_raise_child_command(shell: Any, args: str) -> None:
    """
    Process the command to raise the child domain to the parent domain level.

    Args:
        shell: The shell instance
        args: A string containing the domain, user, and password separated by spaces.

    Usage:
        raise_child <domain> <user> <password>

    The function splits the input string into components, validates the correct number of arguments,
    and then calls the `run_raise_child` function with the provided domain, user, and password.
    """
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: raise_child <domain> <user> <password>")
        return
    domain, username, password = args_list
    run_raise_child(shell, domain=domain, username=username, password=password)
