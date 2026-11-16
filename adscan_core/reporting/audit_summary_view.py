"""What the end-of-scan Audit Summary may say about the collector's hygiene findings.

The panel used to read ``report["findings"]`` as a dict keyed by finding key. The
technical report has no such key: it writes findings as a LIST under
``domains.<domain>.findings``. The lookup matched nothing, so the panel could only
print "No passive findings recorded - clean posture or collector did not run", on
a scan whose report held twenty findings. Two further defects hid behind it: the
sentence welded two different statements together with an "or", and an absent
reading was rendered as nothing to see.

This module is the single reading of that block. It is pure logic (no shell, no
console) so a test can drive it from a report written by the real writer.

Three states, never merged:

``findings``
    The domain has at least one hygiene finding; the rows are returned.
``none``
    The collector finished and none of the hygiene findings were recorded. A real
    clean result for this set of checks.
``no_reading``
    There is no reading: the report or the domain entry is missing, the
    collector's export is absent, or the collector stopped before it finished.
    This is NOT a clean result and must never be worded like one.
"""

from __future__ import annotations

from typing import Any, Iterable, Literal

STATE_FINDINGS = "findings"
STATE_NONE = "none"
STATE_NO_READING = "no_reading"

#: Collection stage statuses that mean the stage did not finish what it set out to do.
_UNFINISHED_STAGE_STATUSES = frozenset({"stopped", "failed"})

CollectorState = Literal["complete", "unfinished", "absent"]


def collector_state(graph: Any) -> CollectorState:
    """Whether the collector ran to completion, from the graph's ``collection.stages``.

    ``absent`` when there is no graph or no stage record, ``unfinished`` when any
    stage was stopped or failed, ``complete`` when stages are recorded and none
    were cut short.
    """
    if not isinstance(graph, dict):
        return "absent"
    collection = graph.get("collection")
    stages = collection.get("stages") if isinstance(collection, dict) else None
    if not isinstance(stages, list) or not stages:
        return "absent"
    statuses = {
        str(stage.get("status") or "").strip().lower()
        for stage in stages
        if isinstance(stage, dict)
    }
    if statuses & _UNFINISHED_STAGE_STATUSES:
        return "unfinished"
    if "complete" not in statuses:
        return "absent"
    return "complete"


def _domain_findings(report: Any, domain: str) -> list[dict[str, Any]] | None:
    """The finding list the report holds for ``domain``, or ``None`` when absent."""
    if not isinstance(report, dict):
        return None
    domains = report.get("domains")
    if not isinstance(domains, dict):
        return None
    entry = domains.get(domain)
    if not isinstance(entry, dict):
        return None
    findings = entry.get("findings")
    if not isinstance(findings, list):
        return None
    return [item for item in findings if isinstance(item, dict)]


def build_hygiene_view(
    report: Any,
    domain: str,
    rows_spec: Iterable[tuple[str, str, str, str]],
    *,
    collector: CollectorState,
) -> dict[str, Any]:
    """Resolve the Audit Summary's passive-findings block for one domain.

    Args:
        report: The parsed ``technical_report.json`` (or ``None`` when unreadable).
        domain: The domain the panel is about. Findings are read for this domain
            only: the panel is rendered once per domain, and merging counts across
            domains would put another domain's accounts on this domain's line.
        rows_spec: ``(finding key, label, singular unit, plural unit)`` rows the
            panel reports.
        collector: Result of :func:`collector_state` for this domain.

    Returns:
        ``{"state": ..., "rows": [(severity, label, value_text), ...], "reason": str}``.
        ``rows`` is ordered by the caller; ``reason`` explains a ``no_reading``.
    """
    findings = _domain_findings(report, domain)
    if findings is None:
        return {
            "state": STATE_NO_READING,
            "rows": [],
            "reason": "no technical report entry for this domain",
        }

    by_key: dict[str, dict[str, Any]] = {}
    for item in findings:
        key = str(item.get("key") or "").strip()
        if key and key not in by_key:
            by_key[key] = item

    rows: list[tuple[str, str, str]] = []
    for key, label, unit_singular, unit_plural in rows_spec:
        item = by_key.get(key)
        if item is None:
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        count = details.get("count")
        severity = str(
            details.get("severity_summary") or item.get("severity") or ""
        ).lower().strip()
        if unit_singular == unit_plural:
            # Policy-level finding: the count is 1 by construction and reads as noise.
            value_text = unit_singular
        elif isinstance(count, int) and not isinstance(count, bool) and count > 0:
            value_text = f"{count} {unit_singular if count == 1 else unit_plural}"
        elif isinstance(count, int) and not isinstance(count, bool) and count <= 0:
            continue
        else:
            # Recorded without a usable count: it is still a finding, never dropped.
            value_text = "present"
        rows.append((severity, label, value_text))

    if rows:
        return {"state": STATE_FINDINGS, "rows": rows, "reason": ""}
    if collector == "complete":
        return {"state": STATE_NONE, "rows": [], "reason": ""}
    if collector == "unfinished":
        reason = "the collector stopped before it finished"
    else:
        reason = "no completed collector run is recorded for this domain"
    return {"state": STATE_NO_READING, "rows": [], "reason": reason}


__all__ = (
    "STATE_FINDINGS",
    "STATE_NONE",
    "STATE_NO_READING",
    "build_hygiene_view",
    "collector_state",
)
