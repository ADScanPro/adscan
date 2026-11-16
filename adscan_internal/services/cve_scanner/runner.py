"""Async parallel scheduler for native CVE checks."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.scan_pacing import active_pacing, component_pacing
from adscan_core.scan_pacing.pacing_consumers import consumer as _pacing_consumer
from adscan_core.scan_pacing.pacing_runtime import Outcome, active_runtime
from adscan_core.rich_output import print_error, print_info, print_info_debug, print_info_verbose
from adscan_internal.core.events import Event, EventBus, EventType
from adscan_internal.services.cve_scanner.catalog import (
    CVEDefinition,
    TargetScope,
    credential_covers_domain,
    scope_applies_to_target,
)
from adscan_internal.services.cve_scanner.checks.coercion import CoercionCVECheck
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEScanReport,
    CVEStatus,
    Severity,
)
from adscan_internal.services.auth_error_classification import SCOPE_EGRESS_REFUSAL_LABEL
from adscan_internal.services.engagement_scope_targets import HELD_UNCONFIRMED_TEXT
from adscan_internal.services.network_probe_service import PROBE_EXCLUDED, tcp_probe_hosts
from adscan_core.rich_output import print_exception


# Bounded concurrency for the reachability preflight (a raw TCP connect per
# (host, port) is ~50× cheaper than an auth handshake, so a higher fan-out
# than the auth concurrency is safe — mirrors the SMB sweep's gate). Kept in
# one place so a corporate-scale bump is a one-line change.
# The values live in the scan-pacing SSOT (consumer ``probe.cve_preflight``);
# these names are the default-level values.
_PREFLIGHT_PROBE_CONCURRENCY = _pacing_consumer("probe.cve_preflight").param("concurrency").default  # 64
_PREFLIGHT_PROBE_TIMEOUT_SECONDS = _pacing_consumer("probe.cve_preflight").param("timeout_s").default  # 3.0


class _PausedBySafeguard(Exception):
    """The strain safeguard paused this host earlier in the assessment."""


class _HeldByScope(Exception):
    """The engagement scope keeps this host out now: nothing is sent to it."""


@dataclass(frozen=True)
class ScanTarget:
    """One host to scan.

    ``domain`` names the AD domain the host actually belongs to (resolved
    from the workspace ``domains_data`` at load time). In a single-domain
    audit it equals the scan's ``--domain``; in a multi-forest audit it can
    be a DIFFERENT domain than the credential's, which is exactly how the
    foreign-DC scope gate (``scope_applies_to_target``) decides a check must
    be skipped rather than attempted with a credential that cannot cover it.
    ``None`` means "could not be determined" — the gate then stays
    conservative and still lets the check run.
    """

    host: str
    is_dc: bool = False
    display_name: str | None = None
    domain: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    """Runtime context passed into every check.

    ``domains_data`` and ``ip_hostname_inventory`` are threaded so the
    authenticated LDAP/SMB checks (BadSuccessor, WebDAV) can resolve a DC's
    FQDN through the canonical SSOT (``build_ldap_config_for_domain`` /
    ``resolve_dc_fqdn``) instead of handing the transport a bare IP, which
    would degrade the Kerberos SPN to ``ldap/<ip>`` and be rejected by the
    DC with ``SEC_E_LOGON_DENIED``. Both default empty so test contexts and
    non-workspace callers keep working unchanged.
    """

    workspace_dir: Path
    domain: str | None = None
    event_bus: EventBus | None = None
    listener_host: str | None = None
    smb_connection_factory: Any | None = None
    ldap_factory: Any | None = None
    kerb_factory: Any | None = None
    domains_data: Mapping[str, Any] = field(default_factory=dict)
    ip_hostname_inventory: dict[str, list[str]] = field(default_factory=dict)
    extras: dict[str, Any] = field(default_factory=dict)
    #: The scanning account's lockout headroom for checks whose negative outcome
    #: is a failed sign-in (``failing_auth_budget.FailingAuthBudget``). ``None``
    #: means unknown, and those checks then send nothing (fail closed).
    failing_auth_budget: Any | None = None
    #: The run's per-host patch-level cache (``host_patch_level.HostPatchLevelCache``):
    #: one Remote Registry read per host serves every patch-level check, made
    #: with an administrator of the host when ADscan holds one. ``None`` (tests,
    #: ad-hoc callers) keeps each check reading with the scan credential.
    patch_level: Any | None = None
    #: The engagement scope's per-host check (``engagement_scope_targets.
    #: host_contact_gate`` over the scan's targets), asked for a target right
    #: before each of its checks. The target list was partitioned when it was
    #: loaded; a scan over many hosts can outlast that answer, and the scope can
    #: be narrowed while it runs. A target the scope keeps out now is not
    #: contacted and its check reads as kept off by the scope
    #: (:func:`_scope_excluded_result`). ``None`` (tests, ad-hoc callers): every
    #: target is admitted.
    scope_admit: Callable[[ScanTarget], bool] | None = None
    #: Whether a target the scope keeps out is "not confirmed inside the scope"
    #: (its place could not be established) rather than excluded. Asked only for
    #: a target that was kept out, so its check carries the right one of the two
    #: labels. ``None``: every kept-out target reads as excluded.
    scope_unconfirmed: Callable[[ScanTarget], bool] | None = None


@dataclass
class CheckEvent(Event):
    """Lifecycle event emitted around a single (host, cve) check."""

    cve_id: str = ""
    aka: str = ""
    host: str = ""
    phase: str = ""  # "started" | "finished"
    status: str | None = None
    severity: str | None = None

    def __post_init__(self) -> None:
        """Override the base ``event_type`` based on phase."""

        self.event_type = (
            EventType.PHASE_COMPLETED
            if self.phase == "finished"
            else EventType.PHASE_STARTED
        )


# Callback invoked by the runner whenever a result is finalised. Lets the
# caller (typically the dashboard) update Live UI without coupling the
# runner to Rich.
ResultCallback = Callable[[CVEResult], None]


class CVEScanRunner:
    """Schedule CVE checks across hosts with bounded concurrency.

    Concurrency budget:

    - ``concurrency`` — global cap on simultaneous checks across the run.
    - ``per_host_concurrency`` — cap on simultaneous checks per host.

    Defaults match the spec (10 global, 3 per host). Coercion catalog
    entries (PetitPotam, PrinterBug, ShadowCoerce, MSEvenCoerce,
    DFSCoerce) all share a single :class:`CoercionCVECheck` engine call
    per host; the runner groups them so the adapter is invoked once per
    host (not once per technique) and the per-technique results are
    fanned out to their corresponding catalog rows.
    """

    def __init__(
        self,
        *,
        concurrency: int | None = None,
        per_host_concurrency: int | None = None,
        check_timeout_seconds: float | None = None,
    ) -> None:
        # Unset values come from the scan pacing (``cve.runner``: 10, 3 and 120 s
        # at the default level).
        pacing = component_pacing(active_pacing(), "cve.runner")
        self._concurrency = pacing["concurrency"] if concurrency is None else concurrency
        self._per_host_concurrency = (
            pacing["per_host_concurrency"] if per_host_concurrency is None else per_host_concurrency
        )
        self._check_timeout = (
            pacing["check_timeout_s"] if check_timeout_seconds is None else check_timeout_seconds
        )

    async def scan(
        self,
        *,
        targets: Iterable[ScanTarget],
        cves: Iterable[CVEDefinition],
        ctx: ScanContext,
        creds: Any | None = None,
        on_result: ResultCallback | None = None,
        scan_id: str | None = None,
    ) -> CVEScanReport:
        """Run the work matrix and return the aggregate report."""

        scan_id = scan_id or _new_scan_id()
        targets_t = tuple(targets)
        cves_t = tuple(cves)
        cred_auth_domains = _credential_auth_domains(creds)
        started_at = datetime.now(timezone.utc)
        runtime = active_runtime()
        global_sem = runtime.semaphore(self._concurrency)
        per_host_sems: dict[str, asyncio.Semaphore] = {}

        async def _scope_admits(target: ScanTarget) -> bool:
            # Asked off the loop: the gate may prepare the chunk it has reached.
            if ctx.scope_admit is None:
                return True
            try:
                return bool(await asyncio.to_thread(ctx.scope_admit, target))
            except Exception as exc:  # noqa: BLE001 - a gate that cannot ask keeps the host out
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                return False

        async def _scope_unconfirmed(target: ScanTarget) -> bool:
            # Which of the two "kept off" labels the target's checks carry.
            if ctx.scope_unconfirmed is None:
                return False
            try:
                return bool(await asyncio.to_thread(ctx.scope_unconfirmed, target))
            except Exception as exc:  # noqa: BLE001 - without an answer it reads as excluded
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                return False

        async def _paced_run(check: Any, target: ScanTarget) -> Any:
            # Engagement scope first, right before the check's first packet: the
            # target list passed the scope when it was loaded, and that answer
            # is not current for a check that starts an hour into the scan.
            if not await _scope_admits(target):
                raise _HeldByScope(target.host)
            # Per-host pause and request rate (no-op at the default level); a host
            # the safeguard paused is not checked and reads as unreachable.
            if not await runtime.before_op(target.host):
                raise _PausedBySafeguard(target.host)
            return await check.run(target, creds, ctx)

        # Partition CVE catalog entries: coercion entries share a single
        # engine call per host (the adapter emits one CVEResult per
        # technique). Treating each as a separate work item would invoke
        # the adapter N times per host (where N is the number of coercion
        # rows in the catalog) and pay the full sweep cost on each call.
        coercion_cves = tuple(
            cve for cve in cves_t if cve.check_class is CoercionCVECheck
        )
        normal_cves = tuple(
            cve for cve in cves_t if cve.check_class is not CoercionCVECheck
        )

        results: list[CVEResult] = []
        results_lock = asyncio.Lock()

        # Reachability preflight (SSOT gate). CVE checks do NOT all use one
        # port — zerologon needs the RPC endpoint mapper (135), the Kerberos
        # checks need 88, the SMB/RPRN/EFSR checks need 445, the LDAP checks
        # 636/389. Probe each host's required ports ONCE up front (like the SMB
        # sweep's 445 liveness gate), then dispatch a check only when its
        # transport port is reachable. A host whose required port is
        # unreachable is a DATA GAP (recorded SKIPPED), never a "not
        # vulnerable" verdict and never a per-host TimeoutError.
        reachable_ports = await self._preflight_required_ports(
            targets_t, normal_cves, coercion_cves, cred_auth_domains
        )
        # Ports the engagement scope kept the preflight off (nothing was sent):
        # a check that needs one of them was not run because the scope says so,
        # which is a different fact from a host that did not answer.
        scope_excluded_ports: dict[str, frozenset[int]] = dict(
            getattr(self, "_scope_excluded_ports", None) or {}
        )
        # Of those hosts, the ones the scope could not place (asked once per
        # host, off the loop): their checks read "not confirmed", not "excluded".
        unconfirmed_hosts: set[str] = set()
        if scope_excluded_ports and ctx.scope_unconfirmed is not None:
            for target in targets_t:
                if target.host in scope_excluded_ports and await _scope_unconfirmed(target):
                    unconfirmed_hosts.add(target.host)
        # Count of (host, check) pairs skipped for unreachability, for the
        # single end-of-sweep operator summary line.
        unreachable_skips = 0
        scope_excluded_skips = 0

        def _not_dispatched(cve: CVEDefinition, target: ScanTarget) -> CVEResult:
            """The data gap of a check whose transport port did not answer the preflight."""
            nonlocal unreachable_skips, scope_excluded_skips
            kept_off = scope_excluded_ports.get(target.host, frozenset())
            if any(port in kept_off for port in cve.required_ports):
                scope_excluded_skips += 1
                return _scope_excluded_result(
                    cve, target, unconfirmed=target.host in unconfirmed_hosts
                )
            unreachable_skips += 1
            return _unreachable_result(cve, target)

        def _reachable_for(cve: CVEDefinition, target: ScanTarget) -> bool:
            """Whether ANY of the check's required ports is open on the host.

            Empty ``required_ports`` (synthetic/test entries) → always
            dispatch (no reachability precondition).
            """

            if not cve.required_ports:
                return True
            open_ports = reachable_ports.get(target.host, frozenset())
            return any(port in open_ports for port in cve.required_ports)

        # Build the standard work matrix for non-coercion checks.
        normal_work: list[tuple[ScanTarget, CVEDefinition]] = []
        for target in targets_t:
            for cve in normal_cves:
                if not _applies(cve, target, cred_auth_domains):
                    skipped = _skipped_result(cve, target, cred_auth_domains)
                    results.append(skipped)
                    if on_result is not None:
                        on_result(skipped)
                    continue
                if not _reachable_for(cve, target):
                    unreachable = _not_dispatched(cve, target)
                    results.append(unreachable)
                    if on_result is not None:
                        on_result(unreachable)
                    continue
                normal_work.append((target, cve))

        # Coercion entries form one synthetic work item per applicable host
        # — the adapter call. NOT_APPLICABLE coercion entries (host not in
        # scope) still emit a result so the dashboard fills the cell.
        coercion_hosts: list[ScanTarget] = []
        for target in targets_t:
            applicable = [
                c for c in coercion_cves if _applies(c, target, cred_auth_domains)
            ]
            if not applicable:
                for cve in coercion_cves:
                    skipped = _skipped_result(cve, target, cred_auth_domains)
                    results.append(skipped)
                    if on_result is not None:
                        on_result(skipped)
                continue
            # Skipped entries (some scopes excluded) still need recording.
            for cve in coercion_cves:
                if cve not in applicable:
                    skipped = _skipped_result(cve, target, cred_auth_domains)
                    results.append(skipped)
                    if on_result is not None:
                        on_result(skipped)
            # Reachability gate: the coercion sweep drives one SMB (445)
            # connection per host. If 445 is unreachable, record every
            # applicable technique as a data gap rather than letting the
            # single adapter call time out.
            if not _reachable_for(applicable[0], target):
                for cve in applicable:
                    unreachable = _not_dispatched(cve, target)
                    results.append(unreachable)
                    if on_result is not None:
                        on_result(unreachable)
                continue
            coercion_hosts.append(target)

        async def _run_normal(target: ScanTarget, cve: CVEDefinition) -> None:
            host_sem = per_host_sems.setdefault(
                target.host, asyncio.Semaphore(self._per_host_concurrency)
            )
            async with global_sem, host_sem:
                _emit_check_started(ctx.event_bus, scan_id, cve, target)
                check = cve.check_class()
                started = time.monotonic()
                try:
                    raw = await asyncio.wait_for(
                        _paced_run(check, target),
                        timeout=self._check_timeout,
                    )
                    cve_results = list(raw) if isinstance(raw, list) else [raw]
                    runtime.record(target.host, Outcome.OK, time.monotonic() - started)
                except _HeldByScope:
                    # Kept off by the scope since the list was loaded: the same
                    # result, and the same count, as a host the preflight was
                    # kept off.
                    nonlocal scope_excluded_skips
                    scope_excluded_skips += 1
                    cve_results = [
                        _scope_excluded_result(
                            cve, target, unconfirmed=await _scope_unconfirmed(target)
                        )
                    ]
                except _PausedBySafeguard:
                    cve_results = [_unreachable_result(cve, target)]
                except asyncio.TimeoutError:
                    runtime.record(target.host, Outcome.TIMEOUT)
                    # A host that passed the reachability preflight but then
                    # timed out mid-check is unreachable-at-depth, not a tool
                    # fault: render a concise unreachable line, NOT the generic
                    # "contact support" template (do not route a routine
                    # per-host connect timeout through print_exception).
                    print_info_debug(
                        f"[cve_scanner] {cve.id} timed out on {target.host} "
                        "after passing the reachability preflight"
                    )
                    print_info(
                        f"  ⚠ {target.host} unreachable (timeout) — {cve.aka} not evaluated"
                    )
                    cve_results = [_unreachable_result(cve, target)]
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    print_error(f"CVE check {cve.id} failed on {target.host}: {exc}")
                    cve_results = [_error_result(cve, target, str(exc))]
                duration = time.monotonic() - started

                async with results_lock:
                    for result in cve_results:
                        annotated = _stamp_duration(
                            _stamp_catalog_severity(result, cve), duration
                        )
                        results.append(annotated)
                        if on_result is not None:
                            on_result(annotated)
                        _emit_check_finished(
                            ctx.event_bus, scan_id, cve, target, annotated
                        )

        async def _run_coercion_for_host(target: ScanTarget) -> None:
            """Invoke the coercion adapter once and dispatch per-technique
            results to their corresponding catalog rows.
            """

            host_sem = per_host_sems.setdefault(
                target.host, asyncio.Semaphore(self._per_host_concurrency)
            )
            applicable = [
                c for c in coercion_cves if _applies(c, target, cred_auth_domains)
            ]
            if not applicable:
                return

            async with global_sem, host_sem:
                # Emit ONE synthetic "Coercion" started event per host
                # so the scan log shows a single START line, not one per
                # catalog row. The 5 finished verdicts (one per
                # technique) fan out below.
                if ctx.event_bus is not None:
                    ctx.event_bus.emit(
                        CheckEvent(
                            scan_id=scan_id,
                            cve_id="ADSCAN-COERCION",
                            aka="Coercion",
                            host=target.host,
                            phase="started",
                        )
                    )

                check = CoercionCVECheck()
                started = time.monotonic()
                technique_results: list[CVEResult] = []
                timed_out = False
                scope_held = False
                scope_held_unconfirmed = False
                try:
                    technique_results = await asyncio.wait_for(
                        _paced_run(check, target),
                        timeout=self._check_timeout,
                    )
                    runtime.record(target.host, Outcome.OK, time.monotonic() - started)
                except _HeldByScope:
                    scope_held = True
                    scope_held_unconfirmed = await _scope_unconfirmed(target)
                except _PausedBySafeguard:
                    timed_out = True
                except asyncio.TimeoutError:
                    runtime.record(target.host, Outcome.TIMEOUT)
                    # Passed the 445 preflight but the sweep timed out
                    # mid-flight → unreachable-at-depth, a data gap. Concise
                    # line, not the generic support template.
                    timed_out = True
                    print_info_debug(
                        f"[cve_scanner] coercion sweep timed out on {target.host} "
                        "after passing the reachability preflight"
                    )
                    print_info(
                        f"  ⚠ {target.host} unreachable (timeout) — coercion not evaluated"
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    print_error(f"Coercion sweep failed on {target.host}: {exc}")
                duration = time.monotonic() - started

                # Index adapter outputs by technique / aka.
                by_technique: dict[str, CVEResult] = {}
                for result in technique_results:
                    key = (result.technique or result.aka or "").strip()
                    if key:
                        by_technique[key] = result

                async with results_lock:
                    for cve in applicable:
                        key = (cve.technique or cve.aka or "").strip()
                        adapter_result = by_technique.get(key)
                        if scope_held:
                            # The scope keeps the host out now: nothing was sent.
                            nonlocal scope_excluded_skips
                            scope_excluded_skips += 1
                            final = _scope_excluded_result(
                                cve, target, unconfirmed=scope_held_unconfirmed
                            )
                        elif adapter_result is None and timed_out:
                            # Sweep timed out after passing the preflight →
                            # data gap, not an error (never a false verdict).
                            final = _unreachable_result(cve, target)
                        elif adapter_result is None:
                            # Adapter raised before producing per-technique
                            # rows — emit an error result for this entry so
                            # the dashboard cell does not stay blank.
                            final = _error_result(
                                cve, target, "coercion adapter produced no result"
                            )
                        else:
                            # Re-stamp the result against the catalog entry
                            # so cve_id/aka align with the row the user
                            # selected (the adapter emits its own
                            # ADSCAN-COERCION-* ids; they may already
                            # match, but normalise unconditionally).
                            final = CVEResult(
                                cve_id=cve.id,
                                aka=cve.aka,
                                host=adapter_result.host,
                                status=adapter_result.status,
                                severity=adapter_result.severity,
                                cvss_v3=adapter_result.cvss_v3 or cve.cvss_v3,
                                cvss_vector=(
                                    adapter_result.cvss_vector or cve.cvss_vector
                                ),
                                technique=adapter_result.technique or cve.technique,
                                error=adapter_result.error,
                                evidence=adapter_result.evidence,
                                duration_seconds=adapter_result.duration_seconds
                                or duration,
                                finished_at=adapter_result.finished_at,
                            )
                        annotated = _stamp_duration(final, duration)
                        results.append(annotated)
                        if on_result is not None:
                            on_result(annotated)
                        _emit_check_finished(
                            ctx.event_bus, scan_id, cve, target, annotated
                        )

        print_info_verbose(
            f"[cve_scanner] scheduling {len(normal_work)} checks + "
            f"{len(coercion_hosts)} coercion sweep(s) across "
            f"{len(targets_t)} target(s); "
            f"{unreachable_skips} check(s) skipped (required port unreachable)"
        )
        await asyncio.gather(
            *(_run_normal(target, cve) for target, cve in normal_work),
            *(_run_coercion_for_host(target) for target in coercion_hosts),
        )

        _emit_unreachable_summary(unreachable_skips, results)
        _emit_scope_excluded_summary(scope_excluded_skips, results)
        _emit_foreign_dc_summary(results)

        return CVEScanReport(
            scan_id=scan_id,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            targets=tuple(t.host for t in targets_t),
            cve_ids=tuple(c.id for c in cves_t),
            results=tuple(results),
        )

    async def _preflight_required_ports(
        self,
        targets: tuple[ScanTarget, ...],
        normal_cves: tuple[CVEDefinition, ...],
        coercion_cves: tuple[CVEDefinition, ...],
        cred_auth_domains: frozenset[str] | None = None,
    ) -> dict[str, frozenset[int]]:
        """Live-probe each target's required ports, once, up front.

        Returns ``host -> frozenset(open_ports)``. Reuses the reachability
        SSOT (``tcp_probe_hosts``) that backs the SMB/WinRM/RDP sweeps'
        liveness gate, so a check is dispatched only against a host whose
        transport port actually answers — the per-host TimeoutError flood
        never happens. The probe is ALWAYS live (cheap TCP connect,
        multi-homed aware, never raises) and respects a bounded fan-out.

        Only the ports an APPLICABLE check needs on a given target are
        probed: for each required port we probe the subset of hosts that
        have at least one applicable check needing it, so a member host is
        never probed on 88/135 for DC-only checks.
        """

        # Map each required port to the hosts for which an applicable check
        # needs it. Applicability reuses the catalog scope gate (`_applies`),
        # so a DC-only check's port is only probed on DCs.
        port_to_hosts: dict[int, set[str]] = {}
        for target in targets:
            for cve in (*normal_cves, *coercion_cves):
                if not _applies(cve, target, cred_auth_domains):
                    continue
                for port in cve.required_ports:
                    port_to_hosts.setdefault(port, set()).add(target.host)

        if not port_to_hosts:
            return {}

        open_by_host: dict[str, set[int]] = {}
        excluded_by_host: dict[str, set[int]] = {}
        self._scope_excluded_ports = {}
        for port, hosts in port_to_hosts.items():
            probe_map = await tcp_probe_hosts(
                sorted(hosts),
                port,
                timeout=component_pacing(active_pacing(), "probe.cve_preflight")["timeout_s"],
                max_concurrency=component_pacing(active_pacing(), "probe.cve_preflight")["concurrency"],
                # The probe fan-out asks the scope about each host right before
                # its probe and records a refusal under the scan's own surface.
                scope_surface="cve_probe",
            )
            for host, probe in probe_map.items():
                if probe.status == "open":
                    open_by_host.setdefault(host, set()).add(port)
                elif probe.status == PROBE_EXCLUDED:
                    # The engagement scope kept the probe off: nothing was sent.
                    excluded_by_host.setdefault(host, set()).add(port)

        self._scope_excluded_ports = {
            host: frozenset(ports) for host, ports in excluded_by_host.items()
        }
        return {host: frozenset(ports) for host, ports in open_by_host.items()}


def _applies(
    cve: CVEDefinition,
    target: ScanTarget,
    cred_auth_domains: frozenset[str] | None = None,
) -> bool:
    """Return whether ``cve`` runs against ``target``.

    Delegates to :func:`scope_applies_to_target` (the catalog's canonical
    scope→target gate) so the scheduler and any pre-scan display derived
    from the catalog can never disagree about which checks execute.

    ``cred_auth_domains`` (the domains the scan credential can authenticate
    to) drives the cross-forest foreign-DC skip: a DC-only check against a
    controller in a domain the credential does not cover is skipped rather
    than attempted with a bind that would fail ``SEC_E_LOGON_DENIED``.
    """

    return scope_applies_to_target(
        cve.target_scope,
        is_dc=target.is_dc,
        target_domain=target.domain,
        cred_auth_domains=cred_auth_domains,
    )


def _credential_auth_domains(creds: Any | None) -> frozenset[str]:
    """Collect the domain(s) a scan credential can authenticate to.

    Conservative: only the credential's own ``auth_domain`` / ``domain``
    (ADscan does not model trust reachability here). Empty when unknown, which
    makes the foreign-DC gate a no-op (every DC still runs).
    """

    if creds is None:
        return frozenset()
    domains: set[str] = set()
    for attr in ("auth_domain", "domain"):
        value = getattr(creds, attr, None)
        if value:
            domains.add(str(value))
    return frozenset(domains)


# Prefix that marks a skip caused by the cross-forest foreign-DC gate, so the
# end-of-scan summary can de-duplicate it into ONE operator line instead of
# repeating a raw transport error per (host, check).
_FOREIGN_DC_SKIP_PREFIX = "cross-domain:"


def _skipped_result(
    cve: CVEDefinition,
    target: ScanTarget,
    cred_auth_domains: frozenset[str] | None = None,
) -> CVEResult:
    # Distinguish a plain scope skip (member host, DC-only check) from a
    # foreign-DC skip (the credential cannot cover this DC's domain) so the
    # operator gets a clear cross-domain note rather than the raw
    # SEC_E_LOGON_DENIED a bind attempt would have produced.
    error: str | None = None
    if (
        target.is_dc
        and cve.target_scope in (TargetScope.DCS_ONLY, TargetScope.DOMAIN_LDAP)
        and not credential_covers_domain(target.domain, cred_auth_domains)
        and target.domain
    ):
        error = (
            f"{_FOREIGN_DC_SKIP_PREFIX} no credential for domain "
            f"{target.domain} — LDAP check skipped"
        )
    return CVEResult(
        cve_id=cve.id,
        aka=cve.aka,
        host=target.host,
        status=CVEStatus.NOT_APPLICABLE,
        severity=Severity.INFO,
        cvss_v3=cve.cvss_v3,
        cvss_vector=cve.cvss_vector,
        technique=cve.technique,
        error=error,
    )


#: Prefix of the error every unreachable-host result carries (see
#: :func:`_unreachable_result`); :func:`is_unreachable_result` is its reader.
UNREACHABLE_ERROR_PREFIX = "not evaluated: port"


def is_unreachable_result(result: CVEResult) -> bool:
    """True when ``result`` is a check skipped because its host did not answer."""
    return result.status is CVEStatus.SKIPPED and str(result.error or "").startswith(
        UNREACHABLE_ERROR_PREFIX
    )


#: Error of a check the engagement scope kept from being sent (see
#: :func:`_scope_excluded_result`); :func:`is_scope_excluded_result` is its reader.
SCOPE_EXCLUDED_ERROR = SCOPE_EGRESS_REFUSAL_LABEL
#: The same, for a host the scope could not place: the words every host fan-out
#: uses for that outcome (``engagement_scope_targets.HELD_UNCONFIRMED_TEXT``).
SCOPE_UNCONFIRMED_ERROR = f"not checked: {HELD_UNCONFIRMED_TEXT}"


def is_scope_excluded_result(result: CVEResult) -> bool:
    """True when ``result`` is a check the engagement scope kept off its host.

    Nothing was sent: the client excluded the host, or the scope could not
    confirm it is inside (:func:`is_scope_unconfirmed_result`). It is not a host
    that did not answer, and it never counts toward a lost domain controller.
    """
    return result.status is CVEStatus.SKIPPED and str(result.error or "").startswith(
        (SCOPE_EXCLUDED_ERROR, SCOPE_UNCONFIRMED_ERROR)
    )


def is_scope_unconfirmed_result(result: CVEResult) -> bool:
    """True when the check was kept off a host the scope could not confirm as inside."""
    return result.status is CVEStatus.SKIPPED and str(result.error or "").startswith(
        SCOPE_UNCONFIRMED_ERROR
    )


#: Statuses that prove the host answered the check.
_ANSWERED_STATUSES = frozenset({CVEStatus.VULNERABLE, CVEStatus.NOT_VULNERABLE})


def lost_domain_controllers(
    targets: Iterable[ScanTarget],
    results: Iterable[CVEResult],
    *,
    default_domain: str | None = None,
) -> dict[str, list[str]]:
    """Domain controllers that answered none of the checks sent to them, per domain.

    A controller is lost when at least one check against it was skipped because
    it did not answer (:func:`is_unreachable_result`) and no check against it
    returned a verdict. A controller that answered even one check is reached
    (its remaining skips are per-check gaps the coverage record carries); a
    member server is never counted here.

    A controller the engagement scope kept a check off
    (:func:`is_scope_excluded_result`) is never lost either: its checks did not
    run because the client excluded it (or keeps it to directory reads), which
    is a gap the scope record declares, not a controller that went away.
    """
    dc_domain: dict[str, str] = {}
    for target in targets:
        if not getattr(target, "is_dc", False):
            continue
        domain = str(getattr(target, "domain", None) or default_domain or "").strip()
        if domain and target.host:
            dc_domain[str(target.host)] = domain
    unreachable: set[str] = set()
    answered: set[str] = set()
    kept_off_by_scope: set[str] = set()
    for result in results:
        if result.host not in dc_domain:
            continue
        if result.status in _ANSWERED_STATUSES:
            answered.add(result.host)
        elif is_scope_excluded_result(result):
            kept_off_by_scope.add(result.host)
        elif is_unreachable_result(result):
            unreachable.add(result.host)
    lost: dict[str, list[str]] = {}
    for host in sorted(unreachable - answered - kept_off_by_scope):
        lost.setdefault(dc_domain[host], []).append(host)
    return lost


def _unreachable_result(cve: CVEDefinition, target: ScanTarget) -> CVEResult:
    """Record a check whose transport port was unreachable from this vantage.

    This is a DATA GAP (``SKIPPED``), NOT a verdict: the check was never run,
    so the host is neither "vulnerable" nor "not vulnerable" — it was simply
    not evaluated. Using ``NOT_VULNERABLE`` here would falsely credit the host
    with passing a check that never executed (Exposure-Validation doctrine).
    """

    ports = ", ".join(str(p) for p in cve.required_ports) or "required"
    return CVEResult(
        cve_id=cve.id,
        aka=cve.aka,
        host=target.host,
        status=CVEStatus.SKIPPED,
        severity=Severity.INFO,
        cvss_v3=cve.cvss_v3,
        cvss_vector=cve.cvss_vector,
        technique=cve.technique,
        error=f"{UNREACHABLE_ERROR_PREFIX} {ports}/tcp unreachable from this vantage",
    )


def _scope_excluded_result(
    cve: CVEDefinition, target: ScanTarget, *, unconfirmed: bool = False
) -> CVEResult:
    """Record a check the engagement scope kept from being sent to its host.

    A DATA GAP (``SKIPPED``) like an unreachable host, with a different cause
    that every reader must be able to tell apart: nothing was sent because the
    client excluded the host, so it is neither "not vulnerable" nor a host that
    stopped answering. ``unconfirmed``: the scope could not place the host, so
    the check says "not confirmed" and never that the client excluded it.
    """

    return CVEResult(
        cve_id=cve.id,
        aka=cve.aka,
        host=target.host,
        status=CVEStatus.SKIPPED,
        severity=Severity.INFO,
        cvss_v3=cve.cvss_v3,
        cvss_vector=cve.cvss_vector,
        technique=cve.technique,
        error=SCOPE_UNCONFIRMED_ERROR if unconfirmed else SCOPE_EXCLUDED_ERROR,
    )


def _emit_scope_excluded_summary(
    scope_excluded_skips: int, results: list[CVEResult]
) -> None:
    """Emit ONE operator line for the checks the engagement scope kept off a host."""

    if scope_excluded_skips <= 0:
        return
    unconfirmed = [r for r in results if is_scope_unconfirmed_result(r)]
    excluded = [
        r for r in results if is_scope_excluded_result(r) and not is_scope_unconfirmed_result(r)
    ]
    if excluded:
        print_info(
            f"  {len({r.host for r in excluded})} host(s) not checked for {len(excluded)} "
            "CVE check(s): excluded from the engagement scope. Nothing was sent to them."
        )
    if unconfirmed:
        print_info(
            f"  {len({r.host for r in unconfirmed})} host(s) not checked for "
            f"{len(unconfirmed)} CVE check(s): {HELD_UNCONFIRMED_TEXT}. Nothing was "
            "sent to them."
        )


def _emit_unreachable_summary(
    unreachable_skips: int, results: list[CVEResult]
) -> None:
    """Emit ONE concise operator line for hosts skipped for unreachability.

    Declares the data gap without flooding the terminal with one red error
    per unreachable (host, check). Stays silent when nothing was skipped so
    clean runs are uncluttered. Per-(host, check) detail lives at debug
    level (each ``_unreachable_result`` carries its own reason).
    """

    if unreachable_skips <= 0:
        return
    hosts = {r.host for r in results if is_unreachable_result(r)}
    host_count = len(hosts)
    print_info(
        f"  {host_count} host(s) skipped for {unreachable_skips} CVE check(s) "
        "(required port unreachable from this vantage) — recorded as not "
        "evaluated, not as not-vulnerable."
    )


def _emit_foreign_dc_summary(results: list[CVEResult]) -> None:
    """Emit ONE concise note per foreign domain whose DC checks were skipped.

    A cross-forest audit points the scan at DCs in domains the scan credential
    cannot authenticate to. The gate skips those DC-only checks up front, so the
    operator would otherwise see nothing (previously: repeated raw
    ``SEC_E_LOGON_DENIED`` errors). One informative line per foreign domain
    replaces both the silence and the error spam. Stays quiet when nothing was
    skipped for this reason.
    """

    domains: set[str] = set()
    for result in results:
        error = result.error or ""
        if error.startswith(_FOREIGN_DC_SKIP_PREFIX):
            # "cross-domain: no credential for domain <X> — LDAP check skipped"
            marker = "domain "
            start = error.find(marker)
            if start != -1:
                rest = error[start + len(marker):]
                domain = rest.split(" —", 1)[0].split(" -", 1)[0].strip()
                if domain:
                    domains.add(domain)
    for domain in sorted(domains):
        print_info(
            f"  ℹ cross-domain: no credential for domain {domain} — "
            "DC checks skipped (not evaluated, not a finding)"
        )


def _error_result(cve: CVEDefinition, target: ScanTarget, message: str) -> CVEResult:
    return CVEResult(
        cve_id=cve.id,
        aka=cve.aka,
        host=target.host,
        status=CVEStatus.ERROR,
        severity=Severity.from_cvss(cve.cvss_v3),
        cvss_v3=cve.cvss_v3,
        cvss_vector=cve.cvss_vector,
        technique=cve.technique,
        error=message,
    )


def _stamp_catalog_severity(result: CVEResult, cve: CVEDefinition) -> CVEResult:
    """Grade a VULNERABLE result by the catalog band, not the check's CVSS bucket.

    Each check stamps ``Severity.from_cvss(CVSS_V3)``, which grades the CVE's
    worst case. The catalog band follows how the verdict was reached
    (``CVEDefinition.detection_basis``), so a probe confirmation and a
    patch-level inference no longer read the same. Only CVE checks carry a
    basis; every other result is returned unchanged.
    """
    if result.status is not CVEStatus.VULNERABLE or not cve.detection_basis:
        return result
    if result.severity is cve.severity:
        return result
    return replace(result, severity=cve.severity)


def _stamp_duration(result: CVEResult, duration: float) -> CVEResult:
    if result.duration_seconds:
        return result
    return CVEResult(
        cve_id=result.cve_id,
        aka=result.aka,
        host=result.host,
        status=result.status,
        severity=result.severity,
        cvss_v3=result.cvss_v3,
        cvss_vector=result.cvss_vector,
        technique=result.technique,
        error=result.error,
        evidence=result.evidence,
        duration_seconds=duration,
        finished_at=result.finished_at,
    )


def _emit_check_started(
    bus: EventBus | None,
    scan_id: str,
    cve: CVEDefinition,
    target: ScanTarget,
) -> None:
    if bus is None:
        return
    bus.emit(
        CheckEvent(
            scan_id=scan_id,
            cve_id=cve.id,
            aka=cve.aka,
            host=target.host,
            phase="started",
        )
    )


def _emit_check_finished(
    bus: EventBus | None,
    scan_id: str,
    cve: CVEDefinition,
    target: ScanTarget,
    result: CVEResult,
) -> None:
    if bus is None:
        return
    bus.emit(
        CheckEvent(
            scan_id=scan_id,
            cve_id=cve.id,
            aka=cve.aka,
            host=target.host,
            phase="finished",
            status=result.status.value,
            severity=result.severity.value,
        )
    )


def _new_scan_id() -> str:
    return f"cve-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


__all__ = [
    "SCOPE_EXCLUDED_ERROR",
    "SCOPE_UNCONFIRMED_ERROR",
    "is_scope_excluded_result",
    "is_scope_unconfirmed_result",
    "CVEScanRunner",
    "CheckEvent",
    "ScanContext",
    "ScanTarget",
    "UNREACHABLE_ERROR_PREFIX",
    "is_unreachable_result",
    "lost_domain_controllers",
]
