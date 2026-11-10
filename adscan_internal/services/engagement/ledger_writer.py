"""End-of-run hook: reconcile the run against the engagement ledger and record it.

Called once a recorded run's artifacts are final. It reads what the run wrote
(``coverage.json``, ``technical_report.json``, each domain's ``attack_graph.json``),
decomposes it into ledger items (``adscan_core.reporting.engagement_items``),
asks the shared ``reconcile`` what changed against the ledger's prior state,
applies the decisions in one transaction, regenerates ``engagement/export/``,
and leaves the run's evidence in ``runs/<run_id>/``.

It follows the web ingestion's reading of the same files on purpose, so the CLI
ledger and the Enterprise projection reach the same transitions: coverage is
bound to the artifact it describes (a report or graph rewritten by another run
reads as unknown and closes nothing), and an unreadable or edgeless graph makes
no edge "absent".

Tier: the store is PRO and Enterprise only (spec decision D12a); the caller
gates on the tier. Best-effort for the scan: a failure here is reported and
never fails the run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from adscan_core.engagement.coverage_io import bind_coverage_to_artifact, load_run_coverage
from adscan_core.engagement.model import RUN_UNKNOWN, ItemResult, Transition
from adscan_core.engagement.reconcile import REASON_ARTIFACT_UNREADABLE, reconcile
from adscan_core.engagement.specs import KIND_STRUCTURAL_STEP, edge_spec_lookup
from adscan_core.engagement.store import (
    EXPORT_DIRNAME,
    STORE_DIRNAME,
    LedgerItem,
    RunRecord,
    open_store,
    store_path,
)
from adscan_core.reporting.engagement_items import (
    domain_key,
    finding_items,
    observed,
    step_items,
)
from adscan_internal.services.engagement.run_folder import (
    BULKY_ARTIFACT_RETENTION,
    rotate_bulky_artifacts,
    write_run_folder,
)

__all__ = ("BULKY_ARTIFACT_RETENTION", "LedgerOutcome", "record_run_in_ledger")

_REPORT = "technical_report.json"
_GRAPH = "attack_graph.json"


@dataclass(frozen=True)
class LedgerOutcome:
    """What recording one run did (for the CLI summary and tests)."""

    applied: bool
    reason: str = ""
    run_id: str = ""
    new: int = 0
    reopened: int = 0
    remediated: int = 0
    not_reevaluated: int = 0
    run_folder: str = ""


def _read_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _report_domains(report: Any) -> dict[str, Mapping[str, Any]]:
    raw = report.get("domains") if isinstance(report, Mapping) else None
    if not isinstance(raw, Mapping):
        return {}
    return {domain_key(k): v for k, v in raw.items() if isinstance(v, Mapping) and domain_key(k)}


def _graph_domains(root: Path) -> dict[str, Path]:
    domains_dir = root / "domains"
    if not domains_dir.is_dir():
        return {}
    return {
        domain_key(p.parent.name): p for p in sorted(domains_dir.glob(f"*/{_GRAPH}"))
    }


def record_run_in_ledger(
    workspace_dir: str, *, clock_released: bool, kind: str = "scan"
) -> LedgerOutcome:
    """Reconcile and record the run whose artifacts sit in ``workspace_dir``.

    Args:
        workspace_dir: The workspace the run wrote (the execution workspace on
            the appliance, the workspace itself on the CLI).
        clock_released: Whether the run already restored the host clock (the
            stamps then state which clock produced them either way).
        kind: The run kind (``scan``; ``recheck`` / ``postprocess`` later).

    Returns:
        A :class:`LedgerOutcome`; ``applied=False`` with a reason when nothing
        was recorded (no recorded run, or already recorded).
    """
    root = Path(workspace_dir)
    coverage = load_run_coverage(str(root))
    if coverage.run_status == RUN_UNKNOWN or not coverage.run_id:
        return LedgerOutcome(applied=False, reason="no_recorded_run")

    from adscan_internal.services.engagement.run_summary import run_stamp  # noqa: PLC0415

    recorded_at, frame = run_stamp(root, clock_released=clock_released)
    store = open_store(store_path(root))
    try:
        if store.has_run(coverage.run_id):
            return LedgerOutcome(applied=False, reason="already_applied", run_id=coverage.run_id)

        # Client decisions exported by the Enterprise database (once per file).
        from adscan_internal.services.engagement.importer import (  # noqa: PLC0415
            apply_engagement_import,
        )

        apply_engagement_import(store, root, at=recorded_at)
        report = _read_json(root / _REPORT)
        report_coverage = bind_coverage_to_artifact(coverage, report)
        report_absence = None if isinstance(report, Mapping) else REASON_ARTIFACT_UNREADABLE
        reports = _report_domains(report)
        graphs = _graph_domains(root)
        prior_domains = {i.domain_id for i in store.iter_prior()}
        terminal = store.terminal_ids()

        results: list[ItemResult] = []
        items: list[LedgerItem] = []
        for domain in sorted(set(reports) | set(graphs) | prior_domains):
            present = finding_items(reports.get(domain, {}), domain)
            items.extend(present)
            results.extend(
                reconcile(
                    store.iter_prior(domain, "finding"),
                    observed(present),
                    report_coverage,
                    terminal_ids=terminal,
                    absence_reason=report_absence,
                )
            )
            graph = _read_json(graphs[domain]) if domain in graphs else None
            steps = step_items(graph, domain) if isinstance(graph, Mapping) else []
            items.extend(steps)
            prior_steps = store.iter_prior(domain, "step") + store.iter_prior(
                domain, KIND_STRUCTURAL_STEP
            )
            results.extend(
                reconcile(
                    prior_steps,
                    observed(steps),
                    bind_coverage_to_artifact(coverage, graph),
                    spec_lookup=edge_spec_lookup,
                    terminal_ids=terminal,
                    # Absence is only interpretable against a graph that was
                    # read and holds edges (the web ingestion's rule).
                    absence_reason=None if steps else REASON_ARTIFACT_UNREADABLE,
                )
            )

        run = RunRecord(
            run_id=coverage.run_id,
            kind=kind,
            status=coverage.run_status,
            vantage=coverage.vantage,
            finished_at=recorded_at,
        )
        store.apply_run(run, results, items, coverage, at=recorded_at)
        store.export(root / STORE_DIRNAME / EXPORT_DIRNAME, generated_at=recorded_at)

        from adscan_core.version import get_version  # noqa: PLC0415

        folder = write_run_folder(
            root,
            {
                "run_id": run.run_id,
                "kind": kind,
                "parent_run_id": "",
                "run_status": run.status,
                "vantage": int(run.vantage),
                "engagement_id": store.engagement_id,
                "recorded_at": recorded_at,
                "recorded_at_frame": frame,
                "engine_version": get_version(),
            },
        )
        # A recheck folder holds no bulky artifacts; it must not use up a slot
        # of the retention window that keeps the scans' raw artifacts.
        rotate_bulky_artifacts(
            root, [r["run_id"] for r in store.runs() if r["kind"] != "recheck"]
        )
        counts = {t: 0 for t in Transition}
        for result in results:
            counts[result.transition] += 1
        return LedgerOutcome(
            applied=True,
            run_id=run.run_id,
            new=counts[Transition.NEW],
            reopened=counts[Transition.REOPENED],
            remediated=counts[Transition.REMEDIATED],
            not_reevaluated=counts[Transition.NOT_REEVALUATED],
            run_folder=str(folder),
        )
    finally:
        store.close()


def record_ci_run_in_ledger(workspace_dir: str, *, clock_released: bool) -> Optional[LedgerOutcome]:
    """``adscan ci`` hook: PRO / Enterprise only, never fails the scan."""
    try:
        from adscan_core.tier import is_pro  # noqa: PLC0415

        if not is_pro() or not str(workspace_dir or "").strip():
            return None
        outcome = record_run_in_ledger(workspace_dir, clock_released=clock_released)
        if outcome.applied:
            from adscan_core.rich_output import print_info  # noqa: PLC0415

            print_info(
                "Engagement history updated: "
                f"{outcome.new} new, {outcome.remediated} fixed, {outcome.reopened} reopened, "
                f"{outcome.not_reevaluated} not re-checked in this run."
            )
        return outcome
    except Exception as exc:  # noqa: BLE001 - the ledger never fails a scan
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception, print_warning  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning("The engagement history could not be updated for this run.")
        return None
