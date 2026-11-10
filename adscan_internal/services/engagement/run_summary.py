"""``run_summary.json`` (``adscan.run_summary/1``): the metadata projection of a run.

The one result document a ``metadata_only`` data policy lets leave an assessed
network, so it carries counts, ratios, booleans and closed enums only: no AD
object, domain, host or finding key. Every figure is READ, through the same
functions the reports use, from the blocks the scan stamps into
``technical_report.json``:

* attack-path counts by status and compromise class, and the standard-user
  (Tier 2) exposure headline: :func:`client_path_totals_from_kpis` over each
  domain's ``exposure_kpis`` block, merged with :meth:`ClientPathTotals.merged_with`
  (the LITE report's own aggregation, ``_aggregate_client_path_totals``);
* findings per severity band: the LITE report's
  :func:`reportable_finding_severity_counts` (the reportable gate, the alias
  collapse and the severity the scan authored);
* the AD Exposure Score: each domain's stamped ``exposure_score`` block, of
  which the summary reports the most exposed domain.

The summary computes nothing of its own. A workspace without a report yields an
honest, schema-valid summary whose sections say ``available: false``.

:func:`finalize_run_results` writes the summary and then the artifact manifest
(``adscan_core.node_link.artifact_classes``) at the end of a run. Best-effort:
a failure here never fails a scan.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from adscan_core.engagement.contract import validate
from adscan_core.reporting.hero_domain import hero_exposure_key

RUN_SUMMARY_FILENAME = "run_summary.json"

_SEVERITIES = ("critical", "high", "medium", "low")
_COVERAGE_MODES = frozenset({"complete", "sampled", "bounded", "mixed"})
_KNOWN_CLASSES = frozenset(
    {
        "domain_breaker",
        "tier0_control",
        "tier0_foothold",
        "privileged_escalator",
        "compromise_enabler",
        "unauthenticated_principal",
        "none",
    }
)

_LAST_RESULT_PATH: Optional[str] = None

_UNVERIFIED_FRAME = {"frame": "unverified", "stepped": False}


def _domain_stores(workspace_dir: Path) -> list[Mapping[str, Any]]:
    """Every ASSESSED domain's persisted store (its clock-sync record lives there).

    A workspace holds a store for every domain the run became aware of, which on
    any forest with trusts includes domains it discovered across a trust and
    never authenticated to. Those carry no clock-sync record, because ADscan
    never compared a clock against their controllers, and
    ``summarize_stamp_frame`` reads a store with no record as a domain the stamp
    does NOT agree with: one trust-discovered domain was enough to report the
    whole run's stamp as ``mixed`` on a run whose single assessed domain agreed
    to a millisecond and stepped nothing.

    That is the same error the posture doctrine forbids, inferring a verdict from
    an absence, and it has the same cost here: in a forest with trusts ``mixed``
    becomes the default and the field stops meaning anything. So an unassessed
    domain is excluded from the question entirely, exactly as a control nobody
    tested is excluded from a compliance score's numerator AND denominator. The
    record's presence is the marker, because it is precisely the observation this
    summary is about: a record that exists and places nothing (its agreement
    instant unknown) still counts, and ``mixed`` still means what it says.
    """
    from adscan_core.reporting.clock_frame import CLOCK_SYNC_KEY  # noqa: PLC0415
    from adscan_core.workspace_domain_buckets import is_reserved_domain_bucket  # noqa: PLC0415
    from adscan_internal.workspaces import read_json_file  # noqa: PLC0415

    path = Path(workspace_dir) / "variables.json"
    if not path.is_file():
        return []
    try:
        data = read_json_file(str(path))
    except Exception:  # noqa: BLE001 - unreadable reads as no record: unverified
        return []
    domains = data.get("domains_data") if isinstance(data, Mapping) else None
    if not isinstance(domains, Mapping):
        return []
    return [
        store
        for name, store in domains.items()
        if isinstance(store, Mapping)
        and not is_reserved_domain_bucket(str(name))
        and isinstance(store.get(CLOCK_SYNC_KEY), Mapping)
    ]


def run_stamp(workspace_dir: Path, *, clock_released: bool) -> tuple[str, dict[str, Any]]:
    """Return ``(generated_at, generated_at_frame)`` for a run-level document.

    The frame is resolved through ``adscan_core.reporting.clock_frame`` from each
    domain's persisted clock-sync record: ADscan steps the host clock to a domain
    controller mid-run, so an absolute stamp states which clock produced it.
    """
    from adscan_core.reporting.clock_frame import summarize_stamp_frame  # noqa: PLC0415

    generated_at = datetime.now(timezone.utc).isoformat()
    frame = summarize_stamp_frame(_domain_stores(workspace_dir), generated_at, clock_released=clock_released)
    return generated_at, frame


def last_result_path() -> Optional[str]:
    """Workspace-relative path of the last summary this process wrote, if any."""
    return _LAST_RESULT_PATH


def reset_last_result_path() -> None:
    """Forget the last summary and the noted workspace (a new run in this process)."""
    global _LAST_RESULT_PATH, _NOTED_WORKSPACE  # noqa: PLW0603
    _LAST_RESULT_PATH = None
    _NOTED_WORKSPACE = None


_NOTED_WORKSPACE: Optional[tuple[str, bool]] = None


def note_run_workspace(workspace_dir: Any, *, removed: bool) -> None:
    """Record the workspace a handler used and whether it removes it on exit.

    Pure bookkeeping, no IO: the legacy command stays unchanged, and the
    ``adscan run`` lifecycle reads the note once the handler has returned.
    """
    global _NOTED_WORKSPACE  # noqa: PLW0603
    path = str(workspace_dir or "").strip()
    _NOTED_WORKSPACE = (path, bool(removed)) if path else None


def finalize_noted_run(*, kind: str, status: str) -> Optional[str]:
    """Write the results for the noted workspace, unless the run removed it."""
    noted = _NOTED_WORKSPACE
    if noted is None:
        return None
    path, removed = noted  # pylint: disable=unpacking-non-sequence  # None is returned above
    if removed:
        return None
    return finalize_run_results(path, kind=kind, status=status, clock_released=True)


def _read_report_domains(workspace_dir: Path) -> Optional[dict[str, Any]]:
    from adscan_core.workspace_domain_buckets import is_reserved_domain_bucket  # noqa: PLC0415
    from adscan_internal.workspaces import read_json_file  # noqa: PLC0415

    path = Path(workspace_dir) / "technical_report.json"
    if not path.is_file():
        return None
    try:
        report = read_json_file(str(path))
    except Exception:  # noqa: BLE001 - an unreadable report reads as absent
        return None
    domains = report.get("domains") if isinstance(report, Mapping) else None
    if not isinstance(domains, Mapping):
        return {}
    return {
        str(name): entry
        for name, entry in domains.items()
        if isinstance(entry, Mapping) and not is_reserved_domain_bucket(str(name))
    }


def _coverage_mode(value: str) -> str:
    mode = str(value or "complete").strip().lower() or "complete"
    # An unrecognised mode is a bounded computation we cannot name: say bounded,
    # never complete (a bounded run must never read as a complete one).
    return mode if mode in _COVERAGE_MODES else "bounded"


def _attack_paths_section(domains: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    from adscan_internal.services.lite_html_report import (  # noqa: PLC0415
        _aggregate_client_path_totals,
    )

    available = any(
        isinstance(entry.get("exposure_kpis"), Mapping)
        and isinstance(entry["exposure_kpis"].get("path_axis"), Mapping)
        for entry in domains.values()
    )
    totals = _aggregate_client_path_totals(domains)
    paths = {
        "available": available,
        "total": totals.paths_total,
        "open_exposure": totals.paths_open_exposure,
        "full_domain_compromise": totals.paths_full_domain_compromise,
        "proven": totals.paths_proven,
        "partial": totals.paths_partial,
        "closed_by_configuration": totals.paths_closed_by_configuration,
        "not_assessed": totals.paths_not_assessed,
        "open_by_class": {
            cls: int(count)
            for cls, count in sorted(totals.open_exposure_by_class.items())
            if cls in _KNOWN_CLASSES and int(count or 0) > 0
        },
        "coverage_mode": _coverage_mode(totals.coverage_mode),
    }
    exposure = {
        "available": bool(totals.has_tier2_exposure),
        "tier2_with_path": totals.tier2_exposure_with_path,
        "tier2_total": totals.tier2_exposure_total,
        "tier2_pct": totals.tier2_exposure_pct,
    }
    return paths, exposure


def _exposure_score_section(domains: Mapping[str, Any]) -> dict[str, Any]:
    best: Optional[Mapping[str, Any]] = None
    for entry in domains.values():
        score = entry.get("exposure_score")
        if not isinstance(score, Mapping) or "overall_pct" not in score:
            continue
        if best is None or hero_exposure_key(score) > hero_exposure_key(best):
            best = score
    if best is None:
        return {"available": False}
    return {
        "available": True,
        "overall_pct": max(0.0, min(100.0, float(best.get("overall_pct") or 0))),
        "proven_pct": max(0.0, min(100.0, float(best.get("proven_pct") or 0))),
    }


def _findings_section(domains: Mapping[str, Any]) -> dict[str, Any]:
    from adscan_internal.services.lite_html_report import (  # noqa: PLC0415
        reportable_finding_severity_counts,
    )

    counts = reportable_finding_severity_counts(dict(domains)) if domains else {}
    by_severity = {sev: int(counts.get(sev, 0) or 0) for sev in _SEVERITIES}
    return {"total": sum(by_severity.values()), "by_severity": by_severity}


def build_run_summary(
    workspace_dir: Path,
    *,
    run_id: str,
    kind: str,
    status: str,
    generated_at: Optional[str] = None,
    generated_at_frame: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """Return the validated ``adscan.run_summary/1`` document for a workspace.

    Raises:
        ContractError: The projection does not satisfy the schema (a programming
            error: every value here is a count, a ratio or a closed enum).
    """
    domains = _read_report_domains(Path(workspace_dir))
    report_available = domains is not None
    domains = domains or {}
    paths, exposure = _attack_paths_section(domains)
    summary = {
        "schema": "adscan.run_summary/1",
        "run_id": run_id,
        "kind": kind,
        "status": status,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "generated_at_frame": dict(generated_at_frame or _UNVERIFIED_FRAME),
        "report_available": report_available,
        "domain_count": len(domains),
        "findings": _findings_section(domains),
        "attack_paths": paths,
        "exposure": exposure,
        "exposure_score": _exposure_score_section(domains),
    }
    validate("run_summary", summary)
    return summary


def finalize_run_results(
    workspace_dir: Any,
    *,
    kind: str,
    status: str,
    run_id: Optional[str] = None,
    clock_released: bool = True,
) -> Optional[str]:
    """Write ``run_summary.json`` then ``artifact_manifest.json`` into the workspace.

    The manifest is written last so it lists the summary. Returns the summary's
    workspace-relative path, or ``None`` when nothing could be written (never
    raises: the end of a scan must not fail on its own bookkeeping).
    """
    global _LAST_RESULT_PATH  # noqa: PLW0603
    from adscan_core import telemetry  # noqa: PLC0415
    from adscan_core.engagement.run_identity import current_run_id  # noqa: PLC0415
    from adscan_core.node_link.artifact_classes import write_artifact_manifest  # noqa: PLC0415
    from adscan_core.rich_output import print_exception  # noqa: PLC0415

    try:
        root = Path(str(workspace_dir or ""))
        if not str(workspace_dir or "") or not root.is_dir():
            return None
        resolved_run_id = run_id or current_run_id()
        generated_at, frame = run_stamp(root, clock_released=clock_released)
        summary = build_run_summary(
            root,
            run_id=resolved_run_id,
            kind=kind,
            status=status,
            generated_at=generated_at,
            generated_at_frame=frame,
        )
        from adscan_internal.workspaces import write_json_file  # noqa: PLC0415

        write_json_file(os.path.join(str(root), RUN_SUMMARY_FILENAME), summary)
        _LAST_RESULT_PATH = RUN_SUMMARY_FILENAME
        write_artifact_manifest(root, resolved_run_id, generated_at=generated_at, generated_at_frame=frame)
        return RUN_SUMMARY_FILENAME
    except Exception as exc:  # noqa: BLE001 - bookkeeping must never fail a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


__all__ = (
    "RUN_SUMMARY_FILENAME",
    "build_run_summary",
    "finalize_run_results",
    "last_result_path",
)
