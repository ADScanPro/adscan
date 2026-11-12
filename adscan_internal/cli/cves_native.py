"""CLI surface for the native CVE scanner.

Subcommands:

- ``cves scan [--targets <file>] [--cve <id|aka> ...]`` — run a scan with
  the premium Rich Live dashboard.
- ``cves list`` — print the catalog with CVSS, scope, protocol.
- ``cves report`` — show a summary of the most recent scan in the
  current workspace.

This module is the ONLY entry point for the new scanner. The legacy
``do_netexec_cve_*`` shell handlers are deprecated; see ``do_cves`` in
``adscan.py`` for the dispatcher hook.
"""

from __future__ import annotations

from adscan_core.async_bridge import run_on_new_loop
import shlex
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rich.table import Table

from adscan_core.tui import LiveSession, LiveSessionConfig

from adscan_core import telemetry
from adscan_core.output._state import _get_console
from adscan_core.rich_output import (
    print_error,
    print_info,
    print_info_verbose,
    print_success,
    print_warning,
)
from adscan_internal.core.events import EventBus
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.attack_graph_derived import insert_derived_edge
from adscan_internal.services.cve_scanner import (
    CVEScanRunner,
    ScanContext,
    ScanTarget,
    resolve_cves,
)
from adscan_internal.services.cve_scanner.catalog import CVE_CATALOG, CVEDefinition
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Severity,
)
from adscan_internal.services.cve_scanner.ux.dashboard import (
    CVEDashboard,
    DashboardState,
    build_state,
)
from adscan_internal.services.cve_scanner.ux.report import (
    latest_scan_dir,
    load_report_summary,
    persist_report,
)
from adscan_internal.services.cve_scanner.ux.scan_log import ScanLogWriter
from adscan_internal import get_console
from adscan_internal.cli.common import set_active_domain
from adscan_internal.models.domain import resolve_dc_fqdn, resolve_dc_ip
from adscan_internal.services._kerberos_spn import is_ip_address
from adscan_internal.services.ldap_transport_service import (
    async_connect_with_ldap_fallback,
)
from adscan_core.rich_output import print_exception, print_info_debug


_USAGE = (
    "Usage:\n"
    "  cves scan [--targets <file>] [--cve <id|aka> ...] "
    "[--listener <ip>] [--concurrency N]\n"
    "  cves list\n"
    "  cves report"
)


# Severity ranking for sorting the persistent summary block (descending).
# CRITICAL first, then HIGH, MEDIUM, LOW, INFO. Mirrors the report.md
# ordering so the terminal summary and the markdown stay aligned.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


# Rich style applied to each severity tag in the persistent summary block.
# Matches the dashboard's ``_SEVERITY_STYLE`` so the post-scan summary feels
# like the same product as the live view.
_SUMMARY_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def _resolve_known_domain(shell: Any, token: str) -> str | None:
    """Return the loaded domain matching ``token`` (case-insensitive), else None.

    Lets ``cves <domain>`` be recognized as a scan target rather than an unknown
    subcommand — the token must match an ACTUAL loaded domain in ``domains_data``,
    so a genuine typo still falls through to the usage message.
    """
    candidate = str(token or "").strip()
    if not candidate:
        return None
    domains_data = getattr(shell, "domains_data", {}) or {}
    for known in domains_data:
        if str(known).casefold() == candidate.casefold():
            return str(known)
    return None


def dispatch(shell: Any, args: str) -> None:
    """Entry point called from the shell ``do_cves`` handler."""

    tokens = shlex.split(args or "")
    if not tokens:
        print_info(_USAGE)
        return
    raw_sub, *rest = tokens
    sub = raw_sub.lower()
    try:
        if sub == "scan":
            _run_scan(shell, rest)
        elif sub == "list":
            _run_list()
        elif sub == "report":
            _run_report(shell)
        elif _resolve_known_domain(shell, raw_sub) is not None:
            # ``cves <domain>`` — the operator typed a loaded domain where a
            # subcommand is expected (the muscle-memory shape every other
            # exploration verb accepts: ``enum <domain>``, ``shares <domain>``).
            # Treat it as ``cves scan`` scoped to that domain rather than
            # rejecting it as an unknown subcommand.
            domain = _resolve_known_domain(shell, raw_sub)
            set_active_domain(shell, domain)
            _run_scan(shell, rest)
        else:
            print_warning(f"Unknown subcommand {raw_sub!r}.")
            print_info(_USAGE)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"cves {sub} failed: {exc}")


def _run_list() -> None:
    table = Table(title="ADscan native CVE catalog", header_style="bold magenta")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("AKA", style="bold")
    table.add_column("CVSS", justify="right")
    table.add_column("Severity")
    table.add_column("Protocol")
    table.add_column("Scope")
    for cve in CVE_CATALOG:
        table.add_row(
            cve.id,
            cve.aka,
            f"{cve.cvss_v3:.1f}",
            cve.severity.value.upper(),
            cve.affects_protocol,
            cve.target_scope.value,
        )

    get_console().print(table)


def _run_report(shell: Any) -> None:
    workspace_dir = _workspace_dir(shell)
    if workspace_dir is None:
        print_warning("No workspace selected — nothing to report.")
        return
    scan_dir = latest_scan_dir(workspace_dir)
    if scan_dir is None:
        print_info("No CVE scans recorded in this workspace yet.")
        return
    summary = load_report_summary(scan_dir)
    if summary is None:
        print_warning(f"Could not parse report at {scan_dir}.")
        return
    print_success(f"Latest CVE scan: {summary['scan_id']}")
    print_info(
        f"  targets: {len(summary.get('targets', []))} · "
        f"cves: {len(summary.get('cve_ids', []))} · "
        f"finished: {summary.get('finished_at', '?')}"
    )
    counts = summary.get("severity_counts", {})
    for severity, count in counts.items():
        if count:
            print_info(f"  {severity.upper()}: {count}")
    vulnerable = [
        r for r in summary.get("results", []) if r.get("status") == "vulnerable"
    ]
    if not vulnerable:
        print_info("  no confirmed findings.")
        return
    for result in vulnerable[:10]:
        print_info(
            f"  - {result['aka']} on "
            f"{mark_sensitive(result['host'], 'host')} "
            f"({result['severity'].upper()}, CVSS "
            f"{result.get('cvss_v3') or '—'})"
        )


def filter_cves_by_scan_policy(shell: Any, cves: tuple[Any, ...]) -> tuple[Any, ...]:
    """Return ``cves`` minus the probes the active scan policy excludes.

    Each excluded probe is refused once through the enforcement SSOT. No policy:
    ``cves`` is returned unchanged.
    """
    from adscan_internal.services.scan_policy_enforcement import (  # noqa: PLC0415
        cve_excluded,
        policy_active,
        refuse,
    )

    if not policy_active(shell):
        return tuple(cves)
    kept: list[Any] = []
    for cve in cves:
        cve_id = str(getattr(cve, "id", "") or "")
        if cve_excluded(shell, cve_id):
            refuse(shell, f"probe:{cve_id.lower()}", surface="cve_probe")
            continue
        kept.append(cve)
    return tuple(kept)


def _run_scan(shell: Any, argv: list[str]) -> None:
    targets_path: str | None = None
    cve_selectors: list[str] = []
    listener: str | None = None
    from adscan_core.scan_pacing import active_pacing, component_pacing  # noqa: PLC0415

    concurrency = int(component_pacing(active_pacing(), "cve.runner")["concurrency"])
    audience = "technical"
    force_dc = False
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--targets" and i + 1 < len(argv):
            targets_path = argv[i + 1]
            i += 2
            continue
        if token == "--cve" and i + 1 < len(argv):
            cve_selectors.append(argv[i + 1])
            i += 2
            continue
        if token == "--listener" and i + 1 < len(argv):
            listener = argv[i + 1]
            i += 2
            continue
        if token == "--concurrency" and i + 1 < len(argv):
            concurrency = max(1, int(argv[i + 1]))
            i += 2
            continue
        if token == "--audience" and i + 1 < len(argv):
            audience = argv[i + 1]
            i += 2
            continue
        if token == "--dc-scope":
            # Explicit signal from the "Domain Controllers only" scope path
            # (``do_enum_cve_dcs``): every host in the targets file is a DC,
            # so force ``is_dc=True`` even when host-matching cannot confirm
            # it (e.g. a freshly-written ``dcs.txt`` whose IP is not yet in
            # ``domains_data[domain]["dcs"]``). The host-matching backstop in
            # ``_load_targets`` still runs for the mixed "All hosts" scope.
            force_dc = True
            i += 1
            continue
        print_warning(f"Ignoring unknown argument {token!r}")
        i += 1

    domain = getattr(shell, "domain", None)
    targets = _load_targets(
        targets_path, shell=shell, domain=domain, force_dc=force_dc
    )
    if not targets:
        print_error("No targets to scan. Pass --targets <file> with one host per line.")
        return

    try:
        cves = resolve_cves(tuple(cve_selectors))
    except KeyError as exc:
        print_error(str(exc))
        return

    # Scan policy (spec 2026-11-04 § 7.2 S6): drop the probes the policy
    # excludes before any target is touched. An unknown probe id fails closed.
    cves = filter_cves_by_scan_policy(shell, cves)
    if not cves:
        print_info("CVE verification: every selected check is excluded by scan policy.")
        return

    workspace_dir = _workspace_dir(shell) or Path.cwd()
    masked_creds = _masked_creds(shell, domain)
    dc_ip = _shell_dc_ip(shell, domain)

    # Allocate the scan_id eagerly so the persistent log + report all live
    # under the same directory before the runner emits its first event.
    scan_id = _new_scan_id()
    scan_dir = Path(workspace_dir) / "cves" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    event_bus = EventBus()

    # Auto-compute the listener host the coercion adapter advertises to
    # the target. Without it, every coercion technique short-circuits in
    # the adapter (raises ``ScanContext.listener_host is required``).
    # The CLI ``--listener`` flag wins; otherwise we resolve the local
    # interface IP that has a route to the DC via a UDP "connect" trick
    # (no packets sent, just routes through the kernel's lookup). When
    # there is no DC IP we leave ``listener_host`` unset; the runner
    # surfaces coercion entries as Error rather than producing fake
    # NotApplicable rows.
    listener_host = listener or _resolve_listener_host(shell, dc_ip)
    if listener_host is None:
        print_warning(
            "[cves] listener host could not be resolved (no DC IP); "
            "coercion checks will surface as errors. Pass --listener <ip>."
        )

    ctx, creds_obj = build_scan_context(
        shell,
        domain=domain,
        cves=cves,
        scan_id=scan_id,
        workspace_dir=Path(workspace_dir),
        listener_host=listener_host,
        event_bus=event_bus,
    )

    state = build_state(
        domain=domain,
        masked_creds=masked_creds,
        concurrency=concurrency,
        cves=cves,
        targets=targets,
    )
    dashboard = CVEDashboard(state)

    print_info_verbose(
        f"[cves] starting scan: targets={len(targets)} "
        f"cves={len(cves)} audience={audience} scan_id={scan_id} "
        f"smb_factory={'wired' if ctx.smb_connection_factory else 'absent'} "
        f"ldap_factory=wired"
    )

    log_path = scan_dir / "scan.log"
    with ScanLogWriter(log_path) as scan_log:
        scan_log.subscribe(event_bus)

        run_on_new_loop(
            _run_async(
                shell=shell,
                runner=CVEScanRunner(concurrency=concurrency),
                targets=targets,
                cves=cves,
                ctx=ctx,
                creds=creds_obj,
                state=state,
                dashboard=dashboard,
                scan_id=scan_id,
                scan_log=scan_log,
            )
        )


def build_scan_context(
    shell: Any,
    *,
    domain: str | None,
    cves: tuple[Any, ...],
    scan_id: str,
    workspace_dir: Path,
    listener_host: str | None = None,
    event_bus: EventBus | None = None,
) -> tuple[ScanContext, Any | None]:
    """Build the ``ScanContext`` and the credential bundle one CVE scan runs with.

    Shared by the CVE phase and the post-collection patch-level re-run, so both
    resolve credentials, the DC, the host inventory and the patch-level cache
    the same way.
    """
    # Resolve credentials + DC IP once from the shell. These wire both the
    # SMB factory used by the coercion adapter and the cred bundle that
    # authenticated checks (PrintNightmare, BadSuccessor, WebDAV, …)
    # consume via ``getattr(creds, …)``.
    cred_info = _shell_credentials(shell, domain)
    dc_ip = _shell_dc_ip(shell, domain)

    # Workspace state the authenticated checks need to resolve a DC's FQDN
    # through the canonical SSOTs (build_ldap_config_for_domain / resolve_dc_fqdn)
    # instead of handing the transport a bare IP — which degrades the Kerberos
    # SPN to ldap/<ip> or cifs/<ip> and draws SEC_E_LOGON_DENIED from the DC.
    domains_data = dict(getattr(shell, "domains_data", {}) or {})
    ip_hostname_inventory = _load_ip_hostname_inventory(shell, domain)

    ctx = ScanContext(
        workspace_dir=Path(workspace_dir),
        domain=domain,
        listener_host=listener_host,
        smb_connection_factory=_build_smb_factory(cred_info=cred_info, dc_ip=dc_ip),
        ldap_factory=async_connect_with_ldap_fallback,
        event_bus=event_bus,
        domains_data=domains_data,
        ip_hostname_inventory=ip_hostname_inventory,
        extras={"scan_id": scan_id, "dc_ip": dc_ip},
        failing_auth_budget=_failing_auth_budget_for(
            shell, cves=cves, cred_info=cred_info, domain=domain, dc_ip=dc_ip
        ),
        patch_level=_patch_level_cache_for(shell, domain=domain, dc_ip=dc_ip),
    )
    creds_obj = _build_creds_object(
        cred_info=cred_info, dc_ip=dc_ip, target_domain=domain
    )
    return ctx, creds_obj


def _patch_level_cache_for(shell: Any, *, domain: str | None, dc_ip: str | None) -> Any | None:
    """The run's patch-level cache, its administrator resolver refreshed.

    Re-installing the resolver forgets earlier answers, so a credential gained
    since the previous scan (a Domain Admin, a LAPS password) is used now.
    """
    if not domain:
        return None
    try:
        from adscan_internal.services.cve_scanner.host_admin_access import (  # noqa: PLC0415
            build_host_admin_access_resolver,
        )
        from adscan_internal.services.cve_scanner.host_patch_level import (  # noqa: PLC0415
            get_host_patch_level_cache,
        )

        cache = get_host_patch_level_cache(shell, domain)
        cache.set_access_resolver(build_host_admin_access_resolver(shell, domain=domain, dc_ip=dc_ip))
        return cache
    except Exception as exc:  # noqa: BLE001 - without it the checks read as before
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


async def _run_async(
    *,
    shell: Any,
    runner: CVEScanRunner,
    targets: tuple[ScanTarget, ...],
    cves: tuple[CVEDefinition, ...],
    ctx: ScanContext,
    creds: Any | None,
    state: DashboardState,
    dashboard: CVEDashboard,
    scan_id: str,
    scan_log: ScanLogWriter,
) -> None:
    cve_by_id = {cve.id: cve for cve in cves}

    # The whole scan runs inside a single ``LiveSession`` (alt-screen +
    # redirected stdout/stderr by default — see
    # ``adscan_core/tui/live_session.py``). ``session.update`` replaces
    # the cached renderable in place on every event, so the header is
    # rendered exactly once instead of being stamped above each refresh.
    # ``LiveSession`` already gates alt-screen on ``console.is_terminal``
    # so non-TTY runs (CI, pytest captured stdout, redirected pipes)
    # keep inline behaviour without the caller having to branch.
    #
    # The persistent severity-tagged summary block is wired through
    # ``summary=`` so it runs after the alt-screen has popped — that
    # block is the only thing the operator sees in their scrollback.
    persist_target_dir = ctx.workspace_dir
    config = LiveSessionConfig(refresh_per_second=8)

    report_holder: dict[str, Any] = {}

    def _summary(_console: Any) -> None:
        if "report" in report_holder:
            _print_persistent_summary(report=report_holder["report"])

    async with LiveSession(
        dashboard.render(), config=config, summary=_summary
    ) as session:

        def _on_result(result: CVEResult) -> None:
            state.record(result)
            scan_log.record_result(result)
            cve = cve_by_id.get(result.cve_id)
            if (
                cve is not None
                and result.is_vulnerable
                and cve.promotes_to_domain_breaker
            ):
                state.domain_breaker_alert = (
                    f"{result.aka} on {mark_sensitive(result.host, 'host')}"
                )
            if result.is_vulnerable and cve is not None:
                _insert_graph_edge(shell, cve, result, ctx)
            session.update(dashboard.render())

        report = await runner.scan(
            targets=targets,
            cves=cves,
            ctx=ctx,
            creds=creds,
            on_result=_on_result,
            scan_id=scan_id,
        )
        report_holder["report"] = report

    persist_report(persist_target_dir, report)
    _emit_cve_positive_control_evidence(shell, report, targets, ctx)
    _remember_scan(shell, report=report, targets=targets, ctx=ctx)


def _remember_scan(shell: Any, *, report: Any, targets: tuple[ScanTarget, ...], ctx: ScanContext) -> None:
    """Keep the scan for the post-collection re-run and write the host record."""
    try:
        if ctx.patch_level is not None:
            ctx.patch_level.flush()
        from adscan_internal.services.cve_scanner.patch_level_rerun import (  # noqa: PLC0415
            remember_cve_scan,
        )

        remember_cve_scan(shell, report=report, targets=targets, domain=ctx.domain)
    except Exception as exc:  # noqa: BLE001 - bookkeeping never breaks the scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _emit_cve_positive_control_evidence(
    shell: Any,
    report: Any,
    targets: tuple[ScanTarget, ...],
    ctx: ScanContext,
) -> None:
    """Record positive control evidence for definitive NOT_VULNERABLE CVE results.

    A patched DC / host that returns a definitive not-vulnerable verdict for
    Zerologon / NoPac / MS17-010 becomes a green patch-state control in the
    compliance scorecard (OBSERVED-GOOD; skipped/errored checks never emit).
    Best-effort — never breaks the scan flow.
    """
    try:
        from adscan_internal.services.positive_control_evidence import (
            emit_cve_not_vulnerable_positives,
        )

        from adscan_internal.services.engagement.observation_sources import (
            observe_cve_results,
        )

        host_to_domain: dict[str, str] = {}
        for target in targets or ():
            domain = str(getattr(target, "domain", "") or "").strip()
            host = str(getattr(target, "host", "") or "").strip()
            if host and domain:
                host_to_domain[host] = domain

        default_domain = str(getattr(ctx, "domain", "") or "").strip() or None
        # Every probe verdict (clear, vulnerable, errored, skipped) goes to the
        # run's observation record first; the positives below are derived from
        # the same record, so a probe that missed hosts cannot green its control.
        observe_cve_results(
            shell,
            getattr(report, "results", ()),
            host_to_domain=host_to_domain,
            default_domain=default_domain,
        )
        emit_cve_not_vulnerable_positives(
            shell,
            getattr(report, "results", ()),
            host_to_domain=host_to_domain,
            default_domain=str(getattr(ctx, "domain", "") or "").strip() or None,
        )
    except Exception as exc:  # noqa: BLE001 - best effort, never break the scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(f"[cves] positive control evidence emit failed: {exc}")


def _findings_line(report: Any, rel: str) -> str:
    """Return the "Findings:" line naming the evidence files this scan wrote.

    One file is named by its real path; several are counted under the scan
    directory; none says so, instead of printing a path template.
    """
    from adscan_internal.services.cve_scanner.ux.report import (  # noqa: PLC0415
        evidence_relpath,
        writes_evidence,
    )

    written = [r for r in getattr(report, "results", ()) or () if writes_evidence(r)]
    if not written:
        return "  Findings:  none (no host returned a finding, so no evidence file was written)"
    if len(written) == 1:
        path = f"{rel}/{evidence_relpath(written[0])}"
        return f"  Findings:  {mark_sensitive(path, 'path')}"
    return (
        f"  Findings:  {len(written)} evidence files under {rel}/ "
        "(one folder per CVE, one file per host)"
    )


def _print_persistent_summary(*, report: Any) -> None:
    """Emit the post-scan persistent summary block to the scrollback.

    Called after the :class:`Live` context exits — by that point the
    alt-screen has popped back to the normal terminal, so anything we
    print here lands in the operator's permanent scrollback. This is the
    only thing the operator should see after the dashboard tears down.

    When there is at least one confirmed finding, a severity-tagged line
    is rendered per finding (sorted by severity descending, then by CVSS
    descending) so the operator can act without having to open
    ``report.md`` first. With zero findings, a clean "lab/host appears
    clean" message is printed instead.

    Args:
        report: The :class:`CVEScanReport` returned by
            :meth:`CVEScanRunner.scan`. Read fields: ``vulnerable``,
            ``targets``, ``scan_id``.
    """

    rel = f"cves/{report.scan_id}"
    vulnerable: list[CVEResult] = list(report.vulnerable)

    if not vulnerable:
        print_success(
            f"CVE scan complete: 0 confirmed finding(s) across "
            f"{len(report.targets)} host(s). "
            "Lab/host appears clean for the scanned CVEs."
        )
        print_info(f"  Report:    {rel}/report.md")
        print_info(_findings_line(report, rel))
        print_info(f"  Scan log:  {rel}/scan.log")
        return

    print_success(
        f"CVE scan complete: {len(vulnerable)} confirmed finding(s) "
        f"across {len(report.targets)} host(s)."
    )

    # Sort by severity descending, then by CVSS descending, then by aka
    # so the highest-impact finding lands at the top of the block.
    vulnerable.sort(
        key=lambda r: (
            _SEVERITY_RANK.get(r.severity, 99),
            -(r.cvss_v3 or 0.0),
            r.aka,
            r.host,
        )
    )

    # Compute padding so columns line up regardless of finding count.
    sev_width = max(len(r.severity.value.upper()) for r in vulnerable)
    aka_width = max(len(r.aka) for r in vulnerable)

    console = _get_console()
    for result in vulnerable:
        sev_label = result.severity.value.upper().ljust(sev_width)
        aka_label = result.aka.ljust(aka_width)
        host_label = mark_sensitive(result.host, "host")
        cvss_label = (
            f"CVSS {result.cvss_v3:>4.1f}" if result.cvss_v3 is not None else "CVSS  — "
        )
        style = _SUMMARY_SEVERITY_STYLE.get(result.severity, "white")
        # Print directly through the shared console so the severity tag
        # carries its colour into the persistent scrollback. ``print_*``
        # helpers strip Rich markup, which is why we render the line via
        # the console here while keeping the surrounding paths on the
        # plain ``print_info`` channel for consistency with the rest of
        # the CLI.
        console.print(
            f"  [{style}]{sev_label}[/]  {aka_label}  "
            f"[cyan]{host_label}[/cyan]  [dim]{cvss_label}[/dim]"
        )

    print_info(f"  Report:    {rel}/report.md")
    print_info(_findings_line(report, rel))
    print_info(f"  Scan log:  {rel}/scan.log")


def _insert_graph_edge(
    shell: Any,
    cve: CVEDefinition,
    result: CVEResult,
    ctx: ScanContext,
) -> None:
    record_cve_graph_edge(
        shell,
        cve,
        result,
        domain=ctx.domain,
        scan_id=str(ctx.extras.get("scan_id", "latest")),
    )


def record_cve_graph_edge(
    shell: Any,
    cve: CVEDefinition,
    result: CVEResult,
    *,
    domain: str | None,
    scan_id: str,
) -> None:
    """Insert the attack-graph edge of one VULNERABLE CVE result. Never raises.

    Shared by the CVE phase and the post-collection patch-level re-run; the
    edge's evidence path points at the result file of the scan that holds it.
    """
    relation = cve.graph_edge_relation
    if not relation or not domain:
        return
    try:
        insert_derived_edge(
            shell=shell,
            domain=domain,
            source="ADscan",
            relation=relation,
            target=result.host,
            technique_id=cve.id,
            evidence_path=f"cves/{scan_id}/{cve.id}/{result.host}.json",
            extra={
                "aka": cve.aka,
                "cvss_v3": cve.cvss_v3,
                # A score is never published without its vector.
                "cvss_vector": cve.cvss_vector,
            },
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        # Full detail (including the internal derived-edge allow-list carried by
        # a ValueError) goes to the debug log via print_exception — never to the
        # operator's terminal, which can be shared or reach a client.
        print_exception(exception=exc)
        print_error(f"Could not record the {cve.aka} finding in the attack graph.")


def _resolve_known_dc_identities(shell: Any, domain: str | None) -> frozenset[str]:
    """Collect every identity token that names a DC of ``domain``.

    Returns a lowercased set of IPs, FQDNs, and short hostnames drawn from
    ``domains_data[domain]``. A scan target matches a DC when its host equals
    any of these tokens (compared case-insensitively, and — for FQDNs — also
    by short-label prefix). This is the auto-detect backstop that flags DCs
    correctly regardless of how the operator selected the scope, so the
    ``DCS_ONLY`` checks (Zerologon, NoPac, BadSuccessor) actually run.

    Args:
        shell: The interactive shell holding ``domains_data``.
        domain: The current target domain. ``None`` short-circuits to empty.

    Returns:
        A frozenset of lowercased DC identity tokens (may be empty).
    """

    if not domain:
        return frozenset()
    domains_data = getattr(shell, "domains_data", {}) or {}
    info = domains_data.get(domain) or {}

    tokens: set[str] = set()

    # IPs — resolve_dc_ip walks pdc → dc_ip → dcs[0]; also fold in the full
    # dcs[] list so a multi-DC domain flags every controller, not just the PDC.
    dc_ip = resolve_dc_ip(info)
    if dc_ip:
        tokens.add(dc_ip.strip().lower())
    for entry in info.get("dcs") or []:
        token = str(entry or "").strip()
        if token:
            tokens.add(token.lower())

    # FQDNs / hostnames — resolve_dc_fqdn walks the canonical alias chain;
    # add the raw hostname fields too in case the targets file lists a short
    # name rather than an IP.
    fqdn = resolve_dc_fqdn(info, target_domain=domain)
    for candidate in (
        fqdn,
        info.get("pdc_hostname"),
        info.get("pdc_hostname_fqdn"),
        info.get("pdc_fqdn"),
        info.get("dc_fqdn"),
        info.get("dc_hostname"),
    ):
        token = str(candidate or "").strip().rstrip(".")
        if not token:
            continue
        token = token.lower()
        tokens.add(token)
        # Index the short label of any FQDN so a bare-hostname target matches.
        if "." in token and not is_ip_address(token):
            tokens.add(token.split(".", 1)[0])

    return frozenset(tokens)


def _target_is_dc(host: str, domain: str | None, dc_tokens: frozenset[str]) -> bool:
    """Return ``True`` when ``host`` names a known DC of ``domain``.

    Matches case-insensitively by IP, by FQDN, and by short label (so a
    targets file entry of either ``dc01``, ``dc01.corp.local``, or
    ``10.0.0.1`` all resolve to the same controller).

    Args:
        host: The raw target host (IP or hostname) from the targets file.
        domain: The current target domain, used to promote short labels.
        dc_tokens: The identity set from ``_resolve_known_dc_identities``.

    Returns:
        ``True`` when the host matches a known DC token.
    """

    if not host or not dc_tokens:
        return False
    candidate = host.strip().rstrip(".").lower()
    if not candidate:
        return False
    if candidate in dc_tokens:
        return True
    # A short label target also matches when its promoted FQDN is known.
    if "." not in candidate and not is_ip_address(candidate) and domain:
        promoted = f"{candidate}.{str(domain).strip().rstrip('.').lower()}"
        if promoted in dc_tokens:
            return True
    # An FQDN target also matches when only its short label is known.
    if "." in candidate and not is_ip_address(candidate):
        if candidate.split(".", 1)[0] in dc_tokens:
            return True
    return False


def _load_targets(
    path: str | None,
    *,
    shell: Any | None = None,
    domain: str | None = None,
    force_dc: bool = False,
) -> tuple[ScanTarget, ...]:
    """Load scan targets from ``path`` and flag the domain controllers.

    Each non-comment line becomes a ``ScanTarget``. A target is marked
    ``is_dc=True`` when ``force_dc`` is set (explicit "Domain Controllers
    only" scope) OR when its host matches a known DC of ``domain`` (the
    auto-detect backstop). Without this flag, ``scope_applies_to_target``
    marks every ``DCS_ONLY`` check (Zerologon, NoPac, BadSuccessor) as
    NOT_APPLICABLE and they never run.

    Args:
        path: Targets file, one host (IP or hostname) per line.
        shell: Interactive shell holding ``domains_data`` (for auto-detect).
        domain: Current target domain (for DC identity resolution).
        force_dc: When ``True``, every target is flagged as a DC.

    Returns:
        A tuple of ``ScanTarget`` with ``is_dc`` correctly populated.
    """

    if not path:
        return ()
    file_path = Path(path)
    if not file_path.is_file():
        print_error(f"Targets file not found: {path}")
        return ()

    dc_tokens: frozenset[str] = frozenset()
    if shell is not None and not force_dc:
        dc_tokens = _resolve_known_dc_identities(shell, domain)

    out: list[ScanTarget] = []
    for raw in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        host = raw.strip()
        if not host or host.startswith("#"):
            continue
        # Resolve the domain the host actually belongs to (may differ from the
        # scan's --domain in a multi-forest audit) so the cross-forest scope
        # gate can skip a foreign DC the credential cannot cover.
        if shell is not None:
            target_domain, matched_foreign_dc = _resolve_target_domain(
                shell, host, domain
            )
        else:
            target_domain, matched_foreign_dc = domain, False
        is_dc = force_dc or matched_foreign_dc or _target_is_dc(host, domain, dc_tokens)
        out.append(ScanTarget(host=host, is_dc=is_dc, domain=target_domain))
    return tuple(out)


def _workspace_dir(shell: Any) -> Path | None:
    workspace = getattr(shell, "current_workspace_dir", None)
    if not workspace:
        return None
    return Path(workspace)


def _load_ip_hostname_inventory(shell: Any, domain: str | None) -> dict[str, list[str]]:
    """Load the persisted IP → hostname inventory for ``domain``, once.

    Best-effort (empty on any failure). Loaded at this seam — which has the
    workspace paths — and passed down through ``ScanContext`` so the checks
    never re-load it per host.
    """
    if not domain:
        return {}
    from adscan_internal.services.kerberos_hostname_inventory import (  # noqa: PLC0415
        load_workspace_ip_hostname_inventory,
    )

    try:
        workspace_dir = (
            shell._get_workspace_cwd()  # noqa: SLF001
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", "")
        ) or ""
        domains_dir = getattr(shell, "domains_dir", "domains") or "domains"
        return (
            load_workspace_ip_hostname_inventory(
                workspace_dir=str(workspace_dir),
                domains_dir=str(domains_dir),
                domain=domain,
            )
            or {}
        )
    except Exception as exc:  # noqa: BLE001 — inventory is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}


def _resolve_target_domain(
    shell: Any, host: str, default_domain: str | None
) -> tuple[str | None, bool]:
    """Resolve the AD domain a target host actually belongs to.

    Walks ``domains_data`` and matches the host against each domain's known DC
    identities (IP / FQDN / short label). When the host matches a DC of some
    domain, that domain wins — this is how a foreign-forest DC gets its OWN
    domain (not the scan's ``--domain``), which the cross-forest scope gate
    needs to decide the credential cannot cover it.

    Returns ``(domain, matched_a_dc)``. ``matched_a_dc`` is ``True`` when the
    host is a known DC of some domain (used to flag foreign DCs as DCs too).
    Falls back to ``default_domain`` (``matched_a_dc=False``) when the host is
    not a known DC of any domain (member host, or a DC not yet enumerated),
    keeping the gate conservative — an undetermined foreign domain still runs.
    """
    domains_data = getattr(shell, "domains_data", {}) or {}
    for candidate_domain in domains_data:
        dc_tokens = _resolve_known_dc_identities(shell, candidate_domain)
        if _target_is_dc(host, candidate_domain, dc_tokens):
            return candidate_domain, True
    return default_domain, False


def _masked_creds(shell: Any, domain: str | None) -> str:
    if not domain:
        return "—"
    domains_data = getattr(shell, "domains_data", {}) or {}
    info = domains_data.get(domain) or {}
    user = info.get("username")
    if not user:
        return "anonymous"
    return mark_sensitive(f"{user}@{domain}", "user")


def _shell_credentials(shell: Any, domain: str | None) -> dict[str, Any]:
    """Return the credential dict from ``shell.domains_data[domain]``.

    Returns an empty dict when the shell has no credential for the
    domain — callers must handle the unauthenticated case.
    """

    if not domain:
        return {}
    domains_data = getattr(shell, "domains_data", {}) or {}
    info = domains_data.get(domain) or {}
    return {
        "username": info.get("username"),
        "password": info.get("password"),
        "nt_hash": info.get("nt_hash") or info.get("ntlm_hash"),
        "domain": domain,
    }


def _failing_auth_budget_for(
    shell: Any,
    *,
    cves: Any,
    cred_info: dict[str, Any],
    domain: str | None,
    dc_ip: str | None,
) -> Any | None:
    """Return the scanning account's lockout budget when a selected probe needs it.

    Probes declared with the ``failing_auth_budget`` lockout guard (a patched
    target records their tampered sign-in as a failure for the scanning account)
    only run against this budget. ``None`` when no such probe is selected; the
    probes treat a missing budget as no headroom, so nothing is sent blind.
    """
    from adscan_core.scan_policy.model import (  # noqa: PLC0415
        LOCKOUT_GUARD_FAILING_AUTH_BUDGET,
    )
    from adscan_internal.services.cve_scanner.catalog import (  # noqa: PLC0415
        CVE_POLICY_DECLARATIONS,
    )

    needs_budget = any(
        CVE_POLICY_DECLARATIONS.get(str(getattr(cve, "id", "")), {}).get("lockout_guard")
        == LOCKOUT_GUARD_FAILING_AUTH_BUDGET
        for cve in (cves or ())
    )
    if not needs_budget:
        return None
    from adscan_internal.services.failing_auth_budget import (  # noqa: PLC0415
        resolve_failing_auth_budget,
    )

    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain or "", {}) or {}
    return resolve_failing_auth_budget(
        shell,
        domain=str(domain or ""),
        username=str(cred_info.get("username") or ""),
        password=cred_info.get("password"),
        dc_ip=dc_ip,
        kerberos_target_hostname=(
            domain_data.get("pdc_hostname_fqdn") or domain_data.get("pdc_hostname") or None
        ),
    )


def _resolve_listener_host(shell: Any, dc_ip: str | None) -> str | None:
    """Return the IP advertised to the coerced DC, or ``None`` when unknown.

    Per-target through the listener-IP SSOT (declared ``myip``, kernel route
    toward ``dc_ip``, interface ``myip``). ``None`` when the DC IP is unknown,
    so the runner surfaces coercion entries as Error instead of advertising a
    guess.

    Args:
        shell: Active shell (source of a declared ``myip``).
        dc_ip: The IPv4 address of the domain controller being coerced.
    """

    if not dc_ip:
        return None
    from adscan_internal.services.listener_ip import (  # noqa: PLC0415
        resolve_listener_ip,
    )

    return resolve_listener_ip(shell, target=dc_ip).ip


def _shell_dc_ip(shell: Any, domain: str | None) -> str | None:
    """Return the DC IP for ``domain`` from ``domains_data``."""

    if not domain:
        return None
    domains_data = getattr(shell, "domains_data", {}) or {}
    info = domains_data.get(domain) or {}
    return info.get("pdc") or info.get("dc_ip") or info.get("dc")


def _build_smb_factory(*, cred_info: dict[str, Any], dc_ip: str | None) -> Any | None:
    """Build the aiosmb ``SMBConnectionFactory`` consumed by the coercion adapter.

    Mirrors ``tests/lab/parity/cve_native_vs_netexec.py::_build_smb_factory``
    which is the canonical wiring for the same engine. Returns ``None``
    when there is no credential or no DC IP — callers will surface a
    cleaner ``ScanContext.smb_connection_factory`` missing error than a
    half-built factory would.
    """

    user = cred_info.get("username")
    password = cred_info.get("password")
    domain = cred_info.get("domain")
    if not (user and password and domain and dc_ip):
        return None
    try:
        from aiosmb.commons.connection.factory import SMBConnectionFactory

        return SMBConnectionFactory.from_components(
            dc_ip,
            user,
            password,
            domain=domain,
            dcip=dc_ip,
            authproto="ntlm",
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(
            f"[cves] could not build SMB connection factory: {exc}; "
            "coercion checks will be unable to run."
        )
        return None


def _build_creds_object(
    *,
    cred_info: dict[str, Any],
    dc_ip: str | None,
    target_domain: str | None,
) -> Any | None:
    """Build the ``SimpleNamespace`` creds object the native checks expect.

    Mirrors the canonical lab cases (see
    ``tests/lab/cases/cve/goad_webdav.py`` and
    ``tests/lab/parity/cve_native_vs_netexec.py::_make_creds``).
    Returns ``None`` when no credential is configured — checks gate on
    ``creds is not None`` to choose unauthenticated paths.
    """

    user = cred_info.get("username")
    password = cred_info.get("password")
    auth_domain = cred_info.get("domain")
    if not (user and auth_domain):
        return None
    return SimpleNamespace(
        username=user,
        password=password,
        domain=auth_domain,
        auth_domain=auth_domain,
        target_domain=target_domain or auth_domain,
        nt_hash=cred_info.get("nt_hash"),
        use_kerberos=False,
        kdc_ip=dc_ip,
        auth_kdc_ip=dc_ip,
    )


def _new_scan_id() -> str:
    """Mint a scan id matching the runner's format so logs + reports align."""

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"cve-{stamp}-{uuid.uuid4().hex[:6]}"


def status_label(status: CVEStatus) -> str:
    """Return a short human label for a status (used by tests)."""

    return status.value


__all__ = ["build_scan_context", "dispatch", "record_cve_graph_edge"]
