"""Operator-stop coverage: the client-facing statement for a stopped step, derived once.

The scan control plane (:mod:`adscan_core.scan_control`) lets the operator stop
a long step and keep what it found, skip the rest of a phase, or stop the whole
assessment. Under the Exposure-Validation doctrine every such stop is a **data
gap**, in the family of ``unsupported`` and the bounded-computation gaps: the
deliverable states what was stopped, how far it got and what that leaves
unexamined, and a stopped step never reads as a step that ran and found nothing.

This module is the SSOT for both halves, mirroring
:mod:`adscan_core.reporting.host_enrichment_coverage`:

* :func:`build_operator_stop_entry` turns one stop into the entry persisted by
  :func:`adscan_core.reporting.technical_report.record_operator_stop` under
  ``domains[<domain>]["operator_stop_coverage"]``; and
* :func:`operator_stop_coverage_view` / :func:`merge_operator_stop_coverage`
  turn the persisted blocks into the render-ready shape the PDF report, the LITE
  report and the web platform all read, so the three surfaces cannot word the
  same gap differently.

Pure logic: no IO, no console, no network.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

#: Per-domain key the block lives under in ``technical_report.json``.
OPERATOR_STOP_COVERAGE_KEY = "operator_stop_coverage"

ACTION_SKIP_STEP = "skip_step"
ACTION_SKIP_PHASE = "skip_phase"
ACTION_ABORT_SCAN = "abort_scan"
_ACTIONS = (ACTION_SKIP_STEP, ACTION_SKIP_PHASE, ACTION_ABORT_SCAN)

#: Cap on persisted entries per domain (a scan with dozens of stops is noise).
MAX_ENTRIES_PER_DOMAIN = 25


#: Leading words that are proper nouns and keep their capital mid-sentence.
_PROPER_LEADING_WORDS = frozenset({"Kerberos", "Windows", "Active", "Microsoft", "NTLM"})


def _the(label: str) -> str:
    """``"Password spraying"`` -> ``"the password spraying"``; acronyms kept."""
    text = str(label or "").strip()
    if not text:
        return "the step"
    first = text.split(" ", 1)[0]
    if first in _PROPER_LEADING_WORDS or first.isupper() or not first[:1].isupper():
        return f"the {text}"
    return f"the {text[0].lower()}{text[1:]}"


def _sentence(text: str) -> str:
    text = text.strip()
    return text[:1].upper() + text[1:] if text else text


def _progress_clause(examined: int | None, total: int | None, unit: str) -> str:
    if examined is None or total is None or total <= 0:
        return ""
    noun = f" {unit}" if unit else ""
    return f" after {examined:,} of {total:,}{noun}"


def _remaining_clause(examined: int | None, total: int | None, unit: str) -> str:
    if examined is None or total is None or total <= 0:
        return ""
    remaining = max(0, total - examined)
    if remaining <= 0:
        return ""
    noun = f" {unit}" if unit else ""
    verb = "was" if remaining == 1 else "were"
    return f" The remaining {remaining:,}{noun} {verb} not examined."


def operator_stop_statement(
    *,
    action: str,
    label: str = "",
    phase_title: str = "",
    examined: int | None = None,
    total: int | None = None,
    unit: str = "",
) -> str:
    """Return the client-facing sentence for one stop.

    States what was stopped, how far it got and what was left unexamined. Never
    gives an internal reason, never names a tool, and never lets the stopped
    work read as complete.
    """
    progress = _progress_clause(examined, total, unit)
    remaining = _remaining_clause(examined, total, unit)
    step = _the(label) if label else ""
    phase = f"the {phase_title} phase" if phase_title else "the current phase"
    if action == ACTION_SKIP_STEP:
        subject = step or "a step"
        return _sentence(
            f"{subject} was stopped by the operator{progress}. Results found up to "
            f"that point are included in this report.{remaining}"
        )
    if action == ACTION_SKIP_PHASE:
        same = bool(label) and str(label).strip().lower() == str(phase_title).strip().lower()
        during = progress if same else (f" during {step}{progress}" if step else "")
        return _sentence(
            f"{phase} was cut short by the operator{during}. Results found up to "
            "that point are included in this report; the rest of the phase was "
            "not run."
        )
    where = f"during {step}{progress}" if step else f"during {phase}"
    return _sentence(
        f"the assessment was stopped by the operator {where}. Results found up to "
        "that point are included in this report; the checks that would have run "
        "afterwards were not run."
    )


def build_operator_stop_entry(
    *,
    action: str,
    step_id: str = "",
    label: str = "",
    phase_id: str = "",
    phase_title: str = "",
    examined: int | None = None,
    total: int | None = None,
    unit: str = "",
    source: str = "",
) -> dict[str, Any]:
    """Build one persisted entry (always carries ``statement``)."""
    clean_action = action if action in _ACTIONS else ACTION_ABORT_SCAN
    examined_value = None if examined is None else max(0, int(examined))
    total_value = None if total is None else max(examined_value or 0, int(total))
    return {
        "action": clean_action,
        "step_id": str(step_id or ""),
        "label": str(label or ""),
        "phase_id": str(phase_id or ""),
        "phase_title": str(phase_title or ""),
        "examined": examined_value,
        "total": total_value,
        "unit": str(unit or ""),
        "source": str(source or ""),
        "statement": operator_stop_statement(
            action=clean_action,
            label=label,
            phase_title=phase_title,
            examined=examined_value,
            total=total_value,
            unit=unit,
        ),
    }


def append_operator_stop(block: Any, entry: Mapping[str, Any]) -> dict[str, Any]:
    """Return ``block`` with ``entry`` appended (same step and action: replaced)."""
    stops: list[dict[str, Any]] = []
    if isinstance(block, Mapping):
        stops = [dict(s) for s in block.get("stops") or [] if isinstance(s, Mapping)]
    key = (entry.get("action"), entry.get("step_id"), entry.get("phase_id"))
    stops = [s for s in stops if (s.get("action"), s.get("step_id"), s.get("phase_id")) != key]
    stops.append(dict(entry))
    return {"stops": stops[-MAX_ENTRIES_PER_DOMAIN:]}


def operator_stop_coverage_view(block: Any) -> dict[str, Any]:
    """Render-ready view of one persisted block.

    Returns ``has_gap``, ``statements`` (client sentences, in order) and
    ``stops`` (the machine entries). An absent or unreadable block yields
    ``has_gap=False``: a scan nobody stopped renders exactly as before.
    """
    stops: list[dict[str, Any]] = []
    if isinstance(block, Mapping):
        for raw in block.get("stops") or []:
            if isinstance(raw, Mapping) and str(raw.get("statement") or "").strip():
                stops.append(dict(raw))
    statements = []
    for stop in stops:
        statement = str(stop.get("statement") or "").strip()
        if statement and statement not in statements:
            statements.append(statement)
    return {"has_gap": bool(statements), "statements": statements, "stops": stops}


def merge_operator_stop_coverage(domain_entries: Iterable[Any]) -> dict[str, Any]:
    """Merge every domain's block into one view (statements de-duplicated)."""
    merged: list[dict[str, Any]] = []
    for entry in domain_entries or []:
        if not isinstance(entry, Mapping):
            continue
        view = operator_stop_coverage_view(entry.get(OPERATOR_STOP_COVERAGE_KEY))
        merged.extend(view["stops"])
    return operator_stop_coverage_view({"stops": merged})


__all__ = [
    "ACTION_ABORT_SCAN",
    "ACTION_SKIP_PHASE",
    "ACTION_SKIP_STEP",
    "OPERATOR_STOP_COVERAGE_KEY",
    "append_operator_stop",
    "build_operator_stop_entry",
    "merge_operator_stop_coverage",
    "operator_stop_coverage_view",
    "operator_stop_statement",
]
