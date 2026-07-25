"""Workspace data loader for the ADscan TUI.

Read-only helpers that surface workspace metadata (name, recent scans,
posture score inputs) directly from disk so the TUI can render summaries
without depending on a live ``PentestShell`` instance.

This module is consumed by the workbench widgets — workspace tree, posture
badge, context panel — and by the ``--demo`` boot path. It does **not**
mutate any workspace state.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.paths import get_workspaces_dir
from adscan_core.posture_score import (
    PostureInputs,
    PostureScore,
    compute_posture_score,
)
from adscan_core.rich_output import print_info_debug
from adscan_core.rich_output import print_exception


@dataclass(frozen=True)
class WorkspaceSummary:
    """Lightweight workspace summary for the TUI sidebar.

    Attributes:
        name: Workspace directory name (typically the domain).
        path: Absolute path to the workspace root.
        scans: Recent scan labels (most recent first, max 5).
        findings_count: Total findings recorded for the workspace.
        paths_to_da: Number of distinct paths to Domain Compromised.
        tier0_exposed: Tier-0 accounts compromised or trivially reachable.
    """

    name: str
    path: Path
    scans: tuple[str, ...] = ()
    findings_count: int = 0
    paths_to_da: int = 0
    tier0_exposed: int = 0
    posture: PostureScore | None = None
    top_actions: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def workspaces_root() -> Path:
    """Return the workspaces root directory (host or container aware)."""
    return get_workspaces_dir()


def list_workspaces(root: Path | None = None) -> list[WorkspaceSummary]:
    """Enumerate workspaces under ``root`` (defaults to ``workspaces_root()``).

    Hidden directories and non-directories are skipped. Each summary is built
    via :func:`load_workspace_summary` so a malformed workspace logs a debug
    message but never aborts the listing.
    """
    base = root or workspaces_root()
    if not base.exists():
        return []
    out: list[WorkspaceSummary] = []
    for entry in sorted(base.iterdir(), key=lambda p: p.name.lower()):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        out.append(load_workspace_summary(entry))
    return out


def load_workspace_summary(workspace_path: Path) -> WorkspaceSummary:
    """Load a single workspace summary from disk.

    Best-effort: any IO or JSON error is captured via telemetry and a partial
    summary (with zero counts) is returned so the TUI can still render the
    workspace name.
    """
    name = workspace_path.name
    scans = _scan_labels(workspace_path)
    report = _load_technical_report(workspace_path)

    findings = _count_findings(report)
    paths_to_da = _count_paths_to_da(report)
    tier0 = _count_tier0(report)

    posture = compute_posture_score(
        PostureInputs(
            critical_findings=findings.get("critical", 0),
            high_findings=findings.get("high", 0),
            medium_findings=findings.get("medium", 0),
            low_findings=findings.get("low", 0),
            paths_to_da=paths_to_da,
            tier0_exposed=tier0,
        )
    )
    actions = _top_actions(report)

    return WorkspaceSummary(
        name=name,
        path=workspace_path,
        scans=tuple(scans[:5]),
        findings_count=sum(findings.values()),
        paths_to_da=paths_to_da,
        tier0_exposed=tier0,
        posture=posture,
        top_actions=tuple(actions[:3]),
    )


def empty_posture() -> PostureScore:
    """Return the posture score for a clean (no-findings) workspace."""
    return compute_posture_score(PostureInputs())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _scan_labels(workspace_path: Path) -> list[str]:
    """Return recent scan labels for the workspace, newest first."""
    candidates: list[tuple[float, str]] = []
    for pattern in ("technical_report*.json", "scan_*.json", "*_recap.json"):
        try:
            for f in workspace_path.glob(pattern):
                if f.is_file():
                    candidates.append((f.stat().st_mtime, f.stem))
        except OSError as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    candidates.sort(reverse=True)
    seen: set[str] = set()
    out: list[str] = []
    for _mtime, label in candidates:
        if label in seen:
            continue
        seen.add(label)
        out.append(label)
    return out


def _load_technical_report(workspace_path: Path) -> dict[str, Any]:
    """Load the most recent ``technical_report*.json`` if present."""
    candidates = sorted(
        workspace_path.glob("technical_report*.json"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    for candidate in candidates:
        try:
            with candidate.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except (OSError, json.JSONDecodeError) as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(f"Could not read {candidate.name}: {exc}")
    return {}


def _count_findings(report: dict[str, Any]) -> dict[str, int]:
    """Tally finding severities from a technical report."""
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings = report.get("findings") or report.get("issues") or []
    if not isinstance(findings, list):
        return out
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or f.get("risk") or "").lower()
        if sev in out:
            out[sev] += 1
    return out


def _count_paths_to_da(report: dict[str, Any]) -> int:
    """Count attack paths terminating at Domain Compromised."""
    paths = report.get("attack_paths") or report.get("paths") or []
    if isinstance(paths, list):
        return len(paths)
    if isinstance(paths, dict):
        return int(paths.get("count") or len(paths.get("items") or []))
    return 0


def _count_tier0(report: dict[str, Any]) -> int:
    """Count Tier-0 accounts compromised."""
    tier0 = report.get("tier0_exposed") or report.get("tier0_compromised")
    if isinstance(tier0, int):
        return tier0
    if isinstance(tier0, list):
        return len(tier0)
    return 0


def _top_actions(report: dict[str, Any]) -> list[str]:
    """Extract top-3 remediation actions from a report, if available."""
    actions = report.get("top_actions") or report.get("recommendations") or []
    out: list[str] = []
    if isinstance(actions, list):
        for a in actions:
            if isinstance(a, str):
                out.append(a)
            elif isinstance(a, dict):
                label = a.get("title") or a.get("label") or a.get("name")
                if label:
                    out.append(str(label))
    return out
