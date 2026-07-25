"""Async parallel scheduler for native CVE checks."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose
from adscan_internal.core.events import Event, EventBus, EventType
from adscan_internal.services.cve_scanner.catalog import (
    CVEDefinition,
    scope_applies_to_target,
)
from adscan_internal.services.cve_scanner.checks.coercion import CoercionCVECheck
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEScanReport,
    CVEStatus,
    Severity,
)
from adscan_core.rich_output import print_exception


@dataclass(frozen=True)
class ScanTarget:
    """One host to scan."""

    host: str
    is_dc: bool = False
    display_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    """Runtime context passed into every check."""

    workspace_dir: Path
    domain: str | None = None
    event_bus: EventBus | None = None
    listener_host: str | None = None
    smb_connection_factory: Any | None = None
    ldap_factory: Any | None = None
    kerb_factory: Any | None = None
    extras: dict[str, Any] = field(default_factory=dict)


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
        concurrency: int = 10,
        per_host_concurrency: int = 3,
        check_timeout_seconds: float = 120.0,
    ) -> None:
        self._concurrency = concurrency
        self._per_host_concurrency = per_host_concurrency
        self._check_timeout = check_timeout_seconds

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
        started_at = datetime.now(timezone.utc)
        global_sem = asyncio.Semaphore(self._concurrency)
        per_host_sems: dict[str, asyncio.Semaphore] = {}

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

        # Build the standard work matrix for non-coercion checks.
        normal_work: list[tuple[ScanTarget, CVEDefinition]] = []
        for target in targets_t:
            for cve in normal_cves:
                if not _applies(cve, target):
                    skipped = _skipped_result(cve, target)
                    results.append(skipped)
                    if on_result is not None:
                        on_result(skipped)
                    continue
                normal_work.append((target, cve))

        # Coercion entries form one synthetic work item per applicable host
        # — the adapter call. NOT_APPLICABLE coercion entries (host not in
        # scope) still emit a result so the dashboard fills the cell.
        coercion_hosts: list[ScanTarget] = []
        for target in targets_t:
            applicable = [c for c in coercion_cves if _applies(c, target)]
            if not applicable:
                for cve in coercion_cves:
                    skipped = _skipped_result(cve, target)
                    results.append(skipped)
                    if on_result is not None:
                        on_result(skipped)
                continue
            # Skipped entries (some scopes excluded) still need recording.
            for cve in coercion_cves:
                if cve not in applicable:
                    skipped = _skipped_result(cve, target)
                    results.append(skipped)
                    if on_result is not None:
                        on_result(skipped)
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
                        check.run(target, creds, ctx),
                        timeout=self._check_timeout,
                    )
                    cve_results = list(raw) if isinstance(raw, list) else [raw]
                except asyncio.TimeoutError as exc:
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    cve_results = [_error_result(cve, target, "check timed out")]
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                    print_error(f"CVE check {cve.id} failed on {target.host}: {exc}")
                    cve_results = [_error_result(cve, target, str(exc))]
                duration = time.monotonic() - started

                async with results_lock:
                    for result in cve_results:
                        annotated = _stamp_duration(result, duration)
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
            applicable = [c for c in coercion_cves if _applies(c, target)]
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
                try:
                    technique_results = await asyncio.wait_for(
                        check.run(target, creds, ctx),
                        timeout=self._check_timeout,
                    )
                except asyncio.TimeoutError as exc:
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
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
                        if adapter_result is None:
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
            f"{len(targets_t)} target(s)"
        )
        await asyncio.gather(
            *(_run_normal(target, cve) for target, cve in normal_work),
            *(_run_coercion_for_host(target) for target in coercion_hosts),
        )

        return CVEScanReport(
            scan_id=scan_id,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            targets=tuple(t.host for t in targets_t),
            cve_ids=tuple(c.id for c in cves_t),
            results=tuple(results),
        )


def _applies(cve: CVEDefinition, target: ScanTarget) -> bool:
    """Return whether ``cve`` runs against ``target``.

    Delegates to :func:`scope_applies_to_target` (the catalog's canonical
    scope→target gate) so the scheduler and any pre-scan display derived
    from the catalog can never disagree about which checks execute.
    """

    return scope_applies_to_target(cve.target_scope, is_dc=target.is_dc)


def _skipped_result(cve: CVEDefinition, target: ScanTarget) -> CVEResult:
    return CVEResult(
        cve_id=cve.id,
        aka=cve.aka,
        host=target.host,
        status=CVEStatus.NOT_APPLICABLE,
        severity=Severity.INFO,
        cvss_v3=cve.cvss_v3,
        cvss_vector=cve.cvss_vector,
        technique=cve.technique,
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


__all__ = ["CVEScanRunner", "ScanContext", "ScanTarget", "CheckEvent"]
