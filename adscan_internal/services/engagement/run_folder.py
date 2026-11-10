"""Immutable per-run folders: ``<workspace>/runs/<run_id>/`` (spec section 4.1).

Each recorded run leaves a folder holding its evidence: ``run_manifest.json``,
``coverage.json``, ``observations.json`` and, when written, ``run_summary.json``
and ``artifact_manifest.json``; plus an ``artifacts/`` copy of the bulky raw
artifacts (``technical_report.json``, each domain's ``attack_graph.json``).

Retention (decision D11). Evidence is never rotated: the manifest, coverage,
observations and summaries stay for the engagement's lifetime (DORA / ENS
evidence). Only ``artifacts/`` rotates: the first run and the last
:data:`BULKY_ARTIFACT_RETENTION` keep theirs, and a run folder holding a
``.pinned`` file is exempt. The flat files in the workspace root stay the
"latest view" every existing reader uses.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Iterable, Mapping

RUNS_DIRNAME = "runs"
RUN_MANIFEST_FILENAME = "run_manifest.json"
RUN_MANIFEST_SCHEMA = "adscan.run_manifest/1"
ARTIFACTS_DIRNAME = "artifacts"
PIN_FILENAME = ".pinned"
#: Most recent runs whose bulky artifacts are kept (plus the first run).
BULKY_ARTIFACT_RETENTION = 5

#: Evidence copied into every run folder and never rotated.
EVIDENCE_FILES = (
    "coverage.json",
    "observations.json",
    "run_summary.json",
    "artifact_manifest.json",
)
_REPORT_ARTIFACT = "technical_report.json"
_GRAPH_ARTIFACT = "attack_graph.json"


def run_folder_path(workspace_dir: Any, run_id: str) -> Path:
    return Path(str(workspace_dir)) / RUNS_DIRNAME / run_id


def _copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _write_json(path: Path, doc: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    tmp.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def write_run_folder(workspace_dir: Any, manifest: Mapping[str, Any]) -> Path:
    """Write ``runs/<run_id>/`` from the workspace's current flat artifacts.

    Idempotent: a second call for the same run refreshes nothing it already
    holds (a run folder is immutable once written).
    """
    root = Path(str(workspace_dir))
    folder = run_folder_path(root, str(manifest["run_id"]))
    manifest_path = folder / RUN_MANIFEST_FILENAME
    if manifest_path.is_file():
        return folder
    for name in EVIDENCE_FILES:
        src = root / name
        if src.is_file():
            _copy(src, folder / name)
    artifacts = folder / ARTIFACTS_DIRNAME
    report = root / _REPORT_ARTIFACT
    if report.is_file():
        _copy(report, artifacts / _REPORT_ARTIFACT)
    domains_dir = root / "domains"
    if domains_dir.is_dir():
        for graph in sorted(domains_dir.glob(f"*/{_GRAPH_ARTIFACT}")):
            _copy(graph, artifacts / "domains" / graph.parent.name / _GRAPH_ARTIFACT)
    # The manifest goes last: its presence is what marks the folder complete.
    _write_json(manifest_path, {"schema": RUN_MANIFEST_SCHEMA, **manifest})
    return folder


def write_run_evidence(
    workspace_dir: Any,
    manifest: Mapping[str, Any],
    documents: Mapping[str, Mapping[str, Any]],
) -> Path:
    """Write a run folder from documents the run produced itself (no flat copy).

    For runs that do not own the workspace's flat artifacts (a ``recheck``): the
    flat ``coverage.json`` and reports describe the last scan, so copying them
    would file the scan's evidence under this run. Immutable like
    :func:`write_run_folder`: a folder whose manifest exists is left untouched.
    """
    folder = run_folder_path(workspace_dir, str(manifest["run_id"]))
    manifest_path = folder / RUN_MANIFEST_FILENAME
    if manifest_path.is_file():
        return folder
    for name, doc in documents.items():
        _write_json(folder / name, doc)
    _write_json(manifest_path, {"schema": RUN_MANIFEST_SCHEMA, **manifest})
    return folder


def rotate_bulky_artifacts(
    workspace_dir: Any, ordered_run_ids: Iterable[str], *, keep: int = BULKY_ARTIFACT_RETENTION
) -> list[str]:
    """Drop ``artifacts/`` from runs outside the retention window; never evidence.

    Args:
        workspace_dir: The workspace.
        ordered_run_ids: Run ids oldest first (the ledger's application order).
        keep: How many of the most recent runs keep their artifacts.

    Returns:
        The run ids whose ``artifacts/`` were removed.
    """
    order = [r for r in ordered_run_ids if run_folder_path(workspace_dir, r).is_dir()]
    protected = set(order[:1]) | set(order[-keep:] if keep > 0 else [])
    removed = []
    for run_id in order:
        folder = run_folder_path(workspace_dir, run_id)
        if run_id in protected or (folder / PIN_FILENAME).exists():
            continue
        artifacts = folder / ARTIFACTS_DIRNAME
        if artifacts.is_dir():
            shutil.rmtree(artifacts)
            removed.append(run_id)
    return removed


__all__ = (
    "BULKY_ARTIFACT_RETENTION",
    "EVIDENCE_FILES",
    "PIN_FILENAME",
    "RUNS_DIRNAME",
    "RUN_MANIFEST_SCHEMA",
    "rotate_bulky_artifacts",
    "run_folder_path",
    "write_run_evidence",
    "write_run_folder",
)
