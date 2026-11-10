"""Bring what an engagement already knows into its ledger, once.

Two sources (spec section 12):

* **A workspace scanned before the ledger existed.** Its flat artifacts become a
  synthetic ``import`` run: every finding and step present is recorded as
  ``open``, nothing is reconciled by absence (there is no coverage for it), and
  the flat files are only read. Called before a recorded run overwrites them.
* **Client decisions held by the Enterprise database.** Accepted and
  false-positive findings arrive as ``engagement/engagement_import.json``
  (``adscan.engagement_import/1``, written by the backend's
  ``engagement_import_export``) and become ledger dispositions, which
  reconciliation never changes. Applied once per file content.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Mapping

from adscan_core.engagement.identity import finding_id
from adscan_core.engagement.model import (
    RUN_UNKNOWN,
    TERMINAL_STATUSES,
    ItemResult,
    Transition,
    Vantage,
)
from adscan_core.engagement.store import (
    STORE_DIRNAME,
    EngagementStore,
    RunRecord,
    open_store,
    store_path,
)
from adscan_core.reporting.engagement_items import domain_key, finding_items, step_items
from adscan_internal.services.engagement.ledger_writer import LedgerOutcome

ENGAGEMENT_IMPORT_FILENAME = "engagement_import.json"
ENGAGEMENT_IMPORT_SCHEMA = "adscan.engagement_import/1"
_IMPORT_META_PREFIX = "engagement_import:"


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def import_flat_workspace(workspace_dir: str, *, at: str) -> LedgerOutcome:
    """Create the ledger from a pre-ledger workspace's flat artifacts (once)."""
    root = Path(workspace_dir)
    if store_path(root).exists():
        return LedgerOutcome(applied=False, reason="ledger_exists")
    report = _read(root / "technical_report.json")
    domains = report.get("domains") if isinstance(report, Mapping) else None
    graphs = sorted((root / "domains").glob("*/attack_graph.json")) if (root / "domains").is_dir() else []
    if not isinstance(domains, Mapping) and not graphs:
        return LedgerOutcome(applied=False, reason="nothing_to_import")
    items = []
    for name, entry in (domains or {}).items():
        if isinstance(entry, Mapping):
            items.extend(finding_items(entry, name))
    for graph_path in graphs:
        graph = _read(graph_path)
        if isinstance(graph, Mapping):
            items.extend(step_items(graph, graph_path.parent.name))
    unique = {i.item_id: i for i in items}
    store = open_store(store_path(root))
    try:
        run = RunRecord(run_id=f"import-{uuid.uuid4().hex[:16]}", kind="import",
                        status=RUN_UNKNOWN, vantage=Vantage.UNAUTH, finished_at=at)
        results = [ItemResult(item_id, Transition.NEW) for item_id in sorted(unique)]
        store.apply_run(run, results, list(unique.values()), None, at=at)
        apply_engagement_import(store, root, at=at)
        return LedgerOutcome(applied=True, run_id=run.run_id, new=len(results))
    finally:
        store.close()


def apply_engagement_import(store: EngagementStore, workspace_dir: Any, *, at: str) -> int:
    """Apply ``engagement/engagement_import.json`` dispositions once per content.

    Returns:
        How many dispositions were recorded (0 when absent or already applied).
        Entries with an unknown status or no finding key are skipped.
    """
    path = Path(str(workspace_dir)) / STORE_DIRNAME / ENGAGEMENT_IMPORT_FILENAME
    if not path.is_file():
        return 0
    raw = path.read_bytes()
    marker = _IMPORT_META_PREFIX + hashlib.sha256(raw).hexdigest()
    if store.get_meta(marker):
        return 0
    try:
        doc = json.loads(raw)
    except ValueError:
        return 0
    if not isinstance(doc, Mapping) or doc.get("schema") != ENGAGEMENT_IMPORT_SCHEMA:
        return 0
    applied = 0
    for entry in doc.get("dispositions") or ():
        if not isinstance(entry, Mapping):
            continue
        key = str(entry.get("finding_key") or "").strip()
        status = str(entry.get("status") or "").strip().lower()
        if not key or status not in TERMINAL_STATUSES:
            continue
        store.set_disposition(
            finding_id(key, domain_key(str(entry.get("domain") or ""))),
            status,
            reason=str(entry.get("reason") or ""),
            set_by=str(entry.get("set_by") or "client"),
            at=str(entry.get("set_at") or at),
        )
        applied += 1
    store.set_meta(marker, at)
    return applied


def import_before_run(workspace_dir: str, *, at: str) -> None:
    """``adscan ci`` hook (PRO): import a pre-ledger workspace before the run
    overwrites its flat artifacts. Never fails the scan."""
    try:
        from adscan_core.tier import is_pro  # noqa: PLC0415

        if is_pro() and str(workspace_dir or "").strip():
            import_flat_workspace(workspace_dir, at=at)
    except Exception as exc:  # noqa: BLE001 - history import never fails a scan
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = (
    "ENGAGEMENT_IMPORT_FILENAME",
    "ENGAGEMENT_IMPORT_SCHEMA",
    "apply_engagement_import",
    "import_before_run",
    "import_flat_workspace",
)
