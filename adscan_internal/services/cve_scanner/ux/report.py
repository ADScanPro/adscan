"""Workspace persistence for CVE scan reports.

Layout per spec §5.4::

    <workspace>/cves/<scan_id>/
        report.json          # full structured report
        report.md            # human summary
        <cve_id>/<host>.json # per-finding raw evidence
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEScanReport,
    CVEStatus,
    Severity,
)
from adscan_core.rich_output import print_exception


_SAFE_FS = re.compile(r"[^A-Za-z0-9._-]+")


def persist_report(workspace_dir: str | Path, report: CVEScanReport) -> Path:
    """Persist ``report`` under ``<workspace>/cves/<scan_id>/``.

    Returns the scan directory path. Best-effort — errors are logged and
    captured in telemetry but do not raise, so a writable-disk hiccup
    cannot lose the in-memory report the dashboard already showed.
    """

    scan_dir = Path(workspace_dir) / "cves" / report.scan_id
    try:
        scan_dir.mkdir(parents=True, exist_ok=True)
        (scan_dir / "report.json").write_text(
            json.dumps(_serialise_report(report), indent=2, default=_json_default),
            encoding="utf-8",
        )
        (scan_dir / "report.md").write_text(_render_markdown(report), encoding="utf-8")
        for result in report.results:
            _persist_evidence(scan_dir, result)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"[cve_scanner] failed to persist report: {exc}")
    print_info_verbose(f"[cve_scanner] report persisted to {scan_dir}")
    return scan_dir


def latest_scan_dir(workspace_dir: str | Path) -> Path | None:
    """Return the most recent CVE scan directory, or ``None``."""

    base = Path(workspace_dir) / "cves"
    if not base.is_dir():
        return None
    candidates = sorted(
        (p for p in base.iterdir() if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def load_report_summary(scan_dir: Path) -> dict[str, Any] | None:
    """Load the ``report.json`` summary for ``scan_dir``."""

    path = scan_dir / "report.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _persist_evidence(scan_dir: Path, result: CVEResult) -> None:
    if result.status not in (CVEStatus.VULNERABLE, CVEStatus.ERROR):
        return
    cve_dir = scan_dir / _safe(result.cve_id)
    cve_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "cve_id": result.cve_id,
        "aka": result.aka,
        "host": result.host,
        "status": result.status.value,
        "severity": result.severity.value,
        "cvss_v3": result.cvss_v3,
        "cvss_vector": result.cvss_vector,
        "technique": result.technique,
        "error": result.error,
        "evidence": _serialise(result.evidence),
        "duration_seconds": result.duration_seconds,
        "finished_at": result.finished_at.isoformat(),
    }
    (cve_dir / f"{_safe(result.host)}.json").write_text(
        json.dumps(payload, indent=2, default=_json_default), encoding="utf-8"
    )


def _serialise_report(report: CVEScanReport) -> dict[str, Any]:
    return {
        "scan_id": report.scan_id,
        "started_at": report.started_at.isoformat(),
        "finished_at": report.finished_at.isoformat(),
        "targets": list(report.targets),
        "cve_ids": list(report.cve_ids),
        "severity_counts": {
            sev.value: count for sev, count in report.severity_counts().items()
        },
        "results": [_serialise(r) for r in report.results],
    }


def _serialise(obj: Any) -> Any:
    if obj is None:
        return None
    if is_dataclass(obj):
        return asdict(obj)
    return obj


def _render_markdown(report: CVEScanReport) -> str:
    lines = [
        f"# CVE scan {report.scan_id}",
        "",
        f"- Started: {report.started_at.isoformat()}",
        f"- Finished: {report.finished_at.isoformat()}",
        f"- Targets: {len(report.targets)}",
        f"- CVEs scanned: {len(report.cve_ids)}",
        "",
        "## Severity tally",
        "",
    ]
    counts = report.severity_counts()
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        lines.append(f"- **{sev.value.upper()}**: {counts[sev]}")
    lines.extend(["", "## Confirmed findings", ""])
    vulnerable = report.vulnerable
    if not vulnerable:
        lines.append("_No confirmed findings._")
    for result in vulnerable:
        cvss = f"CVSS {result.cvss_v3:.1f}" if result.cvss_v3 is not None else "CVSS —"
        lines.append(
            f"- `{result.aka}` on `{result.host}` — "
            f"{result.severity.value.upper()} ({cvss}) — {result.cve_id}"
        )
        if result.evidence and result.evidence.summary:
            lines.append(f"  - {result.evidence.summary}")
    lines.append("")
    return "\n".join(lines)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    raise TypeError(f"unserialisable type: {type(obj)!r}")


def _safe(value: str) -> str:
    return _SAFE_FS.sub("_", value).strip("_") or "unknown"


__all__ = [
    "latest_scan_dir",
    "load_report_summary",
    "persist_report",
]
