"""When was a control last seen: the newest of the scan and its rechecks.

A recheck never rewrites the scan's ``technical_report.json``. Its observations
live in its own run folder (``runs/<run_id>/recheck_result.json``,
``control_observations``). Anything that wants a control's "last seen" reads it
through :func:`latest_control_last_seen`, which takes the newest of the scan's
``control_evidence[].last_seen`` and every recheck's observation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from adscan_internal.services.engagement.run_folder import RUNS_DIRNAME

_RESULT_FILENAME = "recheck_result.json"
_REPORT_FILENAME = "technical_report.json"


def _norm(domain: Any) -> str:
    return str(domain or "").strip().rstrip(".").lower()


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _scan_last_seen(workspace_dir: Path, domain: str, key: str) -> Optional[str]:
    report = _read_json(workspace_dir / _REPORT_FILENAME)
    domains = (report or {}).get("domains") if isinstance(report, dict) else None
    if not isinstance(domains, dict):
        return None
    for name, block in domains.items():
        if _norm(name) != domain or not isinstance(block, dict):
            continue
        for entry in block.get("control_evidence") or []:
            if isinstance(entry, dict) and entry.get("key") == key:
                return str(entry.get("last_seen") or "") or None
    return None


def latest_control_last_seen(workspace_dir: Any, domain: str, key: str) -> Optional[str]:
    """Newest ISO instant at which control ``key`` was observed for ``domain``.

    Reads the scan's report and every recheck run folder; writes nothing. ISO-8601
    UTC strings compare chronologically, so ``max`` is the newest.
    """
    root = Path(str(workspace_dir))
    wanted = _norm(domain)
    seen = [s for s in (_scan_last_seen(root, wanted, key),) if s]
    for result in sorted((root / RUNS_DIRNAME).glob(f"*/{_RESULT_FILENAME}")):
        doc = _read_json(result)
        if not isinstance(doc, dict):
            continue
        for obs in doc.get("control_observations") or []:
            if (
                isinstance(obs, dict)
                and obs.get("key") == key
                and _norm(obs.get("domain_id")) == wanted
                and obs.get("last_seen")
            ):
                seen.append(str(obs["last_seen"]))
    return max(seen) if seen else None


__all__ = ("latest_control_last_seen",)
