"""Read and write ``coverage.json`` (schema ``adscan.coverage/1``).

Shared by the engine recorder (writer) and the web ingestion (reader) so the two
sides cannot drift. Reading is fail-closed: a missing, unreadable or foreign
document yields ``run_status="unknown"`` with no checks, which closes nothing.
Unrecognised enum values degrade to the *weaker* reading (vantage ``UNAUTH``,
check status ``FAILED``): a corrupted record can only make reconciliation close
less, never more. A check record without a ``domain_id`` is dropped rather than
read as the run-wide wildcard, for the same reason.

Binding. ``coverage.json`` describes one run, but the report and the graphs it
describes can be rewritten later (a REPL regeneration, another engine). Every
artifact a recorded run writes carries that run's id under
:data:`ARTIFACT_RUN_ID_KEY` (:func:`stamp_artifact_run_id`); a consumer keeps the
coverage only for an artifact carrying the same id
(:func:`bind_coverage_to_artifact`) and otherwise reads it as unknown.

Which run is writing is a property of the PROCESS and the WORKSPACE, not of the
object that happens to call a writer: the report's last writer in a scan is a
render-time enrichment pass that takes a workspace directory and builds a stub
shell for the report IO, so a writer-object lookup dropped the id on the final
write (:func:`register_active_run` / :func:`active_run_id_for_workspace`).
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional

from adscan_core.engagement import COVERAGE_SCHEMA
from adscan_core.engagement.model import (
    RUN_UNKNOWN,
    CheckCoverage,
    CheckStatus,
    RunCoverage,
    Vantage,
)

COVERAGE_FILENAME = "coverage.json"

#: Key under which an artifact (``technical_report.json``, a domain's
#: ``attack_graph.json``) records the id of the recorded run that last wrote it.
ARTIFACT_RUN_ID_KEY = "coverage_run_id"

_VANTAGE_NAMES = {
    "unauth": Vantage.UNAUTH,
    "auth": Vantage.AUTH,
    "privileged_read": Vantage.PRIVILEGED_READ,
}

#: Workspace directory -> id of the recorded run THIS PROCESS is executing on it.
#: Process-local by construction, so a later session (a new process) resolves
#: nothing and a rewrite there clears the id, which is the binding guarantee.
_ACTIVE_RUNS: dict[str, str] = {}


def _workspace_key(workspace_dir: Any) -> str:
    text = str(workspace_dir or "").strip()
    return os.path.abspath(text) if text else ""


def register_active_run(workspace_dir: Any, run_id: str) -> None:
    """Declare that this process is executing ``run_id`` on ``workspace_dir``.

    Called once, by the engine's coverage recorder when the run starts. Every
    artifact writer in the process then stamps that id for that workspace,
    whether it holds the scan's shell or a stub built for report IO.
    """
    key = _workspace_key(workspace_dir)
    if not key or not run_id:
        return
    _ACTIVE_RUNS[key] = str(run_id)


def forget_active_run(workspace_dir: Any) -> None:
    """Drop the registration, so later writes in this process clear the id.

    For a process that stops owning the run's artifacts before it exits (a
    long-lived REPL leaving the workspace). A separate invocation does not need
    it: a new process starts with nothing registered.
    """
    _ACTIVE_RUNS.pop(_workspace_key(workspace_dir), None)


def active_run_id_for_workspace(workspace_dir: Any) -> str:
    """Id of the run this process is executing on ``workspace_dir`` ('' if none)."""
    return _ACTIVE_RUNS.get(_workspace_key(workspace_dir), "")


@contextmanager
def render_of_recorded_run(workspace_dir: Any) -> Iterator[str]:
    """Let a render rewrite a recorded run's report without unbinding it.

    A report render (``adscan deliver``, the web's kit) runs in a NEW process, so
    nothing is registered and every write it makes used to CLEAR the run id from
    ``technical_report.json``. A render adds blocks derived from the run's own
    artifacts (compliance, affected assets, the fan-out rollup); it observes
    nothing new. Dropping the id therefore lost the binding for no reason: the
    web re-ingesting the post-render report read its coverage as unknown, so a
    finding the run proved remediated could no longer close.

    Inside this context the run that wrote the report is adopted as active for
    the workspace, ONLY when the report still carries the id of the run recorded
    in ``coverage.json``. That equality is the proof that no unrecorded writer
    (a later REPL session) has touched the report since: every such write clears
    the id. Anything else (no coverage, unknown status, a different or missing
    id) adopts nothing, and the render clears the id exactly as before. A run
    already active in this process (``adscan ci`` rendering inline) is left as
    is. The adoption is undone on exit, so later writes in a long-lived process
    cannot inherit it.

    Yields:
        The adopted run id, or ``""`` when nothing was adopted.
    """
    key = _workspace_key(workspace_dir)
    adopted = ""
    if key and not _ACTIVE_RUNS.get(key):
        coverage = load_run_coverage(str(workspace_dir))
        report_run_id = _artifact_run_id(Path(str(workspace_dir)) / _REPORT_FILENAME)
        if (
            coverage.run_status != RUN_UNKNOWN
            and coverage.run_id
            and report_run_id == coverage.run_id
        ):
            adopted = coverage.run_id
            _ACTIVE_RUNS[key] = adopted
    try:
        yield adopted
    finally:
        if adopted and _ACTIVE_RUNS.get(key) == adopted:
            _ACTIVE_RUNS.pop(key, None)


#: The artifact :func:`render_of_recorded_run` reads the binding from.
_REPORT_FILENAME = "technical_report.json"


def _artifact_run_id(path: Path) -> str:
    """The run id an artifact on disk carries ('' when absent or unreadable)."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    value = doc.get(ARTIFACT_RUN_ID_KEY) if isinstance(doc, Mapping) else None
    return str(value) if value else ""


def _unknown() -> RunCoverage:
    return RunCoverage(run_status=RUN_UNKNOWN, vantage=Vantage.UNAUTH, checks={})


def _parse_check(raw: Any) -> Optional[CheckCoverage]:
    if not isinstance(raw, Mapping):
        return None
    check_id = str(raw.get("check_id") or "").strip()
    domain_id = str(raw.get("domain_id") or "").strip()
    if not check_id or not domain_id:
        # A record that does not say which domain it covers proves nothing; it
        # must never widen into the run-wide wildcard.
        return None
    try:
        status = CheckStatus(str(raw.get("status") or ""))
    except ValueError:
        status = CheckStatus.FAILED
    ids = raw.get("examined_ids")
    return CheckCoverage(
        check_id=check_id,
        status=status,
        domain_id=domain_id,
        scope_kind=str(raw.get("scope_kind") or "domain"),
        examined=raw.get("examined") if isinstance(raw.get("examined"), int) else None,
        total=raw.get("total") if isinstance(raw.get("total"), int) else None,
        examined_ids=frozenset(str(i) for i in ids) if isinstance(ids, list) else None,
        reason=str(raw.get("reason") or ""),
    )


def parse_run_coverage(doc: Any) -> RunCoverage:
    """Build a :class:`RunCoverage` from a parsed ``coverage.json`` document."""
    if not isinstance(doc, Mapping) or doc.get("schema") != COVERAGE_SCHEMA:
        return _unknown()
    checks: dict[tuple[str, str], CheckCoverage] = {}
    raw_checks = doc.get("checks")
    for raw in raw_checks if isinstance(raw_checks, list) else []:
        parsed = _parse_check(raw)
        if parsed is not None:
            checks[(parsed.check_id, parsed.domain_id)] = parsed
    return RunCoverage(
        run_status=str(doc.get("run_status") or RUN_UNKNOWN),
        vantage=_VANTAGE_NAMES.get(str(doc.get("vantage") or ""), Vantage.UNAUTH),
        checks=checks,
        run_id=str(doc.get("run_id") or ""),
    )


def load_run_coverage(workspace_dir: str) -> RunCoverage:
    """Load ``<workspace_dir>/coverage.json``; ``unknown`` when absent or invalid."""
    path = Path(workspace_dir) / COVERAGE_FILENAME
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _unknown()
    return parse_run_coverage(doc)


def run_coverage_to_document(
    coverage: RunCoverage, *, run_id: str = "", extra: Optional[Mapping[str, Any]] = None
) -> dict[str, Any]:
    """Serialise a :class:`RunCoverage` into the ``adscan.coverage/1`` document."""
    names = {v: k for k, v in _VANTAGE_NAMES.items()}
    checks = []
    for _key, chk in sorted(coverage.checks.items()):
        entry: dict[str, Any] = {
            "check_id": chk.check_id,
            "status": chk.status.value,
            "domain_id": chk.domain_id,
            "scope_kind": chk.scope_kind,
            "examined": chk.examined,
            "total": chk.total,
            "reason": chk.reason,
        }
        if chk.examined_ids is not None:
            entry["examined_ids"] = sorted(chk.examined_ids)
        checks.append(entry)
    doc: dict[str, Any] = {
        "schema": COVERAGE_SCHEMA,
        "run_id": run_id or coverage.run_id,
        "run_status": coverage.run_status,
        "vantage": names[coverage.vantage],
        "checks": checks,
    }
    if extra:
        doc.update(extra)
    return doc


def stamp_artifact_run_id(doc: Any, run_id: Optional[str]) -> None:
    """Record on an artifact which recorded run wrote it.

    Always OVERWRITES: an artifact written outside a recorded run (``run_id``
    empty) loses any id it carried, because a writer that loaded and re-saved
    the document would otherwise keep a previous run's id and re-bind the old
    coverage to new content.
    """
    if not isinstance(doc, dict):
        return
    if run_id:
        doc[ARTIFACT_RUN_ID_KEY] = str(run_id)
    else:
        doc.pop(ARTIFACT_RUN_ID_KEY, None)


def bind_coverage_to_artifact(coverage: RunCoverage, artifact: Any) -> RunCoverage:
    """Return ``coverage`` when ``artifact`` was written by its run, else unknown.

    Unknown closes nothing. A coverage without a run id, an unreadable artifact
    (``None``) and an artifact carrying a different or no id all read unknown.
    """
    if coverage.run_status == RUN_UNKNOWN:
        return coverage
    stamped = artifact.get(ARTIFACT_RUN_ID_KEY) if isinstance(artifact, Mapping) else None
    if not coverage.run_id or not stamped or str(stamped) != coverage.run_id:
        return _unknown()
    return coverage


def write_json_atomic(path: str, doc: Mapping[str, Any]) -> None:
    """Write ``doc`` to ``path`` atomically (temp file in the same dir + replace)."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
