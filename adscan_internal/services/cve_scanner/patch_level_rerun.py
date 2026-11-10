"""Re-evaluate the patch-level CVE checks once ADscan holds administrator access.

The patch-level checks (Drop the MIC 2, PrintNightmare; any catalog check whose
class sets ``reads_patch_level``) read the host's build and UBR over Remote
Registry, which a default host answers for an administrator and refuses for an
ordinary user. A scan that starts as an ordinary user therefore records most
hosts as "not assessed" for them. The CVE phase already reads with an
administrator when it holds one (``host_patch_level`` / ``host_admin_access``);
this module covers the other order, where administrator access arrives AFTER the
CVE phase ran: a Domain Admin reached late in the run, a LAPS password, a local
administrator found by the SMB sweep.

It runs from the collection orchestrator after each persist, so the privileged
refresh that follows a domain compromise picks it up, in ``start`` and ``ci``
alike (both converge on ``collect_scope``). For every (host, check) the run's CVE
scans left not assessed, and that were not already tried with administrative
access, it re-runs the same check through the same runner, now with an
administrator's session, when the host has one. The run's patch-level cache
makes that one registry read per host for all the checks.

What a re-graded result updates, through the same paths as the CVE phase:

* the persisted CVE result (``cves/<scan_id>/report.json`` and the per-host
  evidence file of the scan that held the old result, rewritten in place);
* the attack-graph edge, for a host now VULNERABLE (``record_cve_graph_edge``);
* the run's observation record, rebuilt from every per-host verdict of the run
  (``observe_cve_results(..., replace=True)``), so a host is never counted twice.

A host no credential can read stays not assessed with its reason, never "not
vulnerable". A host whose check was skipped for reachability (port closed from
this vantage) is not retried: administrator access does not open a port.

Scan-policy gating is the checks' own: a probe the active policy excludes is not
re-run, and the checks keep their registry ids.
"""

from __future__ import annotations

from dataclasses import dataclass, replace as dc_replace
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info, print_info_debug

#: Shell attribute holding the CVE scans of this run (one run = one process).
_RUN_SCANS_ATTR = "_cve_scans_this_run"
#: Prefix of the runner's unreachable data gap (``runner._unreachable_result``).
_UNREACHABLE_PREFIX = "not evaluated: port"


@dataclass
class _ScanRecord:
    scan_id: str
    domain: str | None
    report: Any
    targets: tuple[Any, ...]


def remember_cve_scan(shell: Any, *, report: Any, targets: tuple[Any, ...], domain: str | None) -> None:
    """Keep one finished CVE scan of this run for a later re-run. Never raises."""
    if shell is None or report is None:
        return
    try:
        scans = getattr(shell, _RUN_SCANS_ATTR, None)
        if not isinstance(scans, list):
            scans = []
            setattr(shell, _RUN_SCANS_ATTR, scans)
        scans.append(
            _ScanRecord(
                scan_id=str(getattr(report, "scan_id", "") or ""),
                domain=domain,
                report=report,
                targets=tuple(targets or ()),
            )
        )
    except Exception as exc:  # noqa: BLE001 - bookkeeping only
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def patch_level_cve_ids() -> frozenset[str]:
    """Catalog ids of the checks graded from the host's patch level."""
    from adscan_internal.services.cve_scanner.catalog import CVE_CATALOG  # noqa: PLC0415

    return frozenset(
        cve.id for cve in CVE_CATALOG if getattr(cve.check_class, "reads_patch_level", False)
    )


def needs_administrative_rerun(result: Any) -> bool:
    """Whether a result is not assessed and an administrator read could change that.

    ``SKIPPED`` / ``ERROR`` only; not a reachability gap (no credential opens a
    closed port); not a result already produced with administrative access.
    """
    from adscan_internal.services.cve_scanner.checks._os_patch_level import (  # noqa: PLC0415
        ACCESS_ADMINISTRATIVE,
    )
    from adscan_internal.services.cve_scanner.result import CVEStatus  # noqa: PLC0415

    if getattr(result, "status", None) not in (CVEStatus.SKIPPED, CVEStatus.ERROR):
        return False
    if str(getattr(result, "error", "") or "").startswith(_UNREACHABLE_PREFIX):
        return False
    evidence = getattr(result, "evidence", None)
    payload = getattr(evidence, "payload", None) or {}
    return not (isinstance(payload, dict) and payload.get("read_access") == ACCESS_ADMINISTRATIVE)


def _norm(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _target_domain(record: _ScanRecord, target: Any) -> str:
    return _norm(getattr(target, "domain", None) or record.domain)


def _latest(records: list[_ScanRecord], domain: str, cve_ids: frozenset[str]) -> dict[tuple[str, str], tuple[int, Any, Any]]:
    """``{(cve_id, host): (record index, result, target)}``, the run's latest verdict."""
    wanted = _norm(domain)
    latest: dict[tuple[str, str], tuple[int, Any, Any]] = {}
    for index, record in enumerate(records):
        targets = {_norm(t.host): t for t in record.targets}
        for result in getattr(record.report, "results", ()) or ():
            if result.cve_id not in cve_ids:
                continue
            target = targets.get(_norm(result.host))
            if target is None or _target_domain(record, target) != wanted:
                continue
            latest[(result.cve_id, _norm(result.host))] = (index, result, target)
    return latest


def _policy_allows(shell: Any, cve_id: str) -> bool:
    try:
        from adscan_internal.services.scan_policy_enforcement import (  # noqa: PLC0415
            cve_excluded,
            policy_active,
        )

        return not (policy_active(shell) and cve_excluded(shell, cve_id))
    except Exception as exc:  # noqa: BLE001 - unknown policy state: do not run
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False


def rerun_not_assessed_patch_level_checks(shell: Any, *, domain: str, dc_ip: str | None) -> int:
    """Re-run the patch-level checks the run left not assessed, with administrator access.

    Returns the number of (host, check) verdicts that changed. Never raises; a
    no-op when no CVE scan ran in this run for ``domain``.
    """
    try:
        return _rerun(shell, domain=domain, dc_ip=dc_ip)
    except Exception as exc:  # noqa: BLE001 - never break the collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return 0


def _rerun(shell: Any, *, domain: str, dc_ip: str | None) -> int:
    records = getattr(shell, _RUN_SCANS_ATTR, None)
    if not isinstance(records, list) or not records or not domain:
        return 0
    cve_ids = frozenset(c for c in patch_level_cve_ids() if _policy_allows(shell, c))
    if not cve_ids:
        return 0
    latest = _latest(records, domain, cve_ids)
    pending: dict[str, dict[str, Any]] = {}
    for (cve_id, host_key), (_index, result, target) in latest.items():
        if needs_administrative_rerun(result):
            pending.setdefault(cve_id, {})[host_key] = target
    if not pending:
        return 0

    from adscan_internal.cli.cves_native import build_scan_context  # noqa: PLC0415
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
    from adscan_internal.services.cve_scanner.catalog import CVE_CATALOG  # noqa: PLC0415
    from adscan_internal.services.cve_scanner.runner import CVEScanRunner  # noqa: PLC0415

    catalog = {cve.id: cve for cve in CVE_CATALOG}
    cves = tuple(catalog[c] for c in sorted(pending))
    workspace = getattr(shell, "current_workspace_dir", None)
    workspace_dir = Path(workspace) if workspace else Path.cwd()
    ctx, creds = build_scan_context(
        shell,
        domain=domain,
        cves=cves,
        scan_id=records[-1].scan_id or "latest",
        workspace_dir=workspace_dir,
    )
    cache = ctx.patch_level
    if cache is None:
        return 0

    async def _run() -> list[Any]:
        from adscan_internal.services.cve_scanner.checks.webdav import (  # noqa: PLC0415
            _resolve_target_fqdn,
        )

        runner = CVEScanRunner()
        new_results: list[Any] = []
        for cve in cves:
            eligible = []
            for target in pending[cve.id].values():
                fqdn = _resolve_target_fqdn(target=target, ctx=ctx, domain=target.domain or domain)
                if await cache.resolve_access(target.host, fqdn) is not None:
                    eligible.append(target)
            if not eligible:
                continue
            report = await runner.scan(targets=tuple(eligible), cves=(cve,), ctx=ctx, creds=creds)
            new_results.extend(report.results)
        return new_results

    new_results = run_async_sync(_run())
    cache.flush()
    if not new_results:
        print_info_debug(
            "[patch-level-rerun] no host left not assessed has administrator access yet"
        )
        return 0
    return _apply(shell, records=records, latest=latest, new_results=new_results, catalog=catalog, domain=domain,
                  workspace_dir=workspace_dir)


def _apply(
    shell: Any,
    *,
    records: list[_ScanRecord],
    latest: dict[tuple[str, str], tuple[int, Any, Any]],
    new_results: list[Any],
    catalog: dict[str, Any],
    domain: str,
    workspace_dir: Path,
) -> int:
    """Write the re-graded verdicts back where the CVE phase put the old ones."""
    from adscan_internal.cli.cves_native import record_cve_graph_edge  # noqa: PLC0415
    from adscan_internal.services.cve_scanner.result import CVEStatus  # noqa: PLC0415
    from adscan_internal.services.cve_scanner.ux.report import persist_report  # noqa: PLC0415

    regraded: dict[tuple[str, str], Any] = {}
    changed = 0
    vulnerable = 0
    assessed = 0
    for result in new_results:
        key = (result.cve_id, _norm(result.host))
        located = latest.get(key)
        if located is None:
            continue
        index, old, _target = located
        regraded[key] = result
        if result.status is not old.status:
            changed += 1
        if result.status in (CVEStatus.VULNERABLE, CVEStatus.NOT_VULNERABLE, CVEStatus.NOT_APPLICABLE):
            assessed += 1
        if result.status is CVEStatus.VULNERABLE:
            vulnerable += 1
            record = records[index]
            record_cve_graph_edge(
                shell,
                catalog[result.cve_id],
                result,
                domain=record.domain or domain,
                scan_id=record.scan_id or "latest",
            )

    # Every scan of the run that holds the old verdict gets the new one: a
    # domain controller is in both the DC-scope and the all-hosts scan.
    for record in records:
        old_results = tuple(getattr(record.report, "results", ()) or ())
        if not any((r.cve_id, _norm(r.host)) in regraded for r in old_results):
            continue
        results = tuple(regraded.get((r.cve_id, _norm(r.host)), r) for r in old_results)
        record.report = dc_replace(record.report, results=results)
        persist_report(workspace_dir, record.report)
    touched = {cve_id for cve_id, _host in regraded}

    _reobserve(shell, records=records, domain=domain, cve_ids=frozenset(touched))
    print_info(
        f"Patch level re-read with administrative access on {len(new_results)} host check(s): "
        f"{assessed} now assessed ({vulnerable} vulnerable), "
        f"{len(new_results) - assessed} still not assessed."
    )
    return changed


def _reobserve(shell: Any, *, records: list[_ScanRecord], domain: str, cve_ids: frozenset[str]) -> None:
    """Rebuild the run's observation of each touched probe from every per-host verdict."""
    if not cve_ids:
        return
    try:
        from adscan_internal.services.engagement.observation_sources import (  # noqa: PLC0415
            observe_cve_results,
        )
        from adscan_internal.services.positive_control_evidence import (  # noqa: PLC0415
            emit_cve_not_vulnerable_positives,
        )

        merged = _latest(records, domain, cve_ids)
        results = [result for _index, result, _target in merged.values()]
        host_to_domain = {
            str(target.host): str(target.domain or domain) for _index, _result, target in merged.values()
        }
        observe_cve_results(
            shell, results, host_to_domain=host_to_domain, default_domain=domain, replace=True
        )
        emit_cve_not_vulnerable_positives(
            shell, results, host_to_domain=host_to_domain, default_domain=domain
        )
    except Exception as exc:  # noqa: BLE001 - coverage never breaks collection
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = [
    "needs_administrative_rerun",
    "patch_level_cve_ids",
    "remember_cve_scan",
    "rerun_not_assessed_patch_level_checks",
]
