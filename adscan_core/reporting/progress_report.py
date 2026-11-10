"""The executive progress report: one document model, worded once.

The board-ready progress PDF (Enterprise, on demand and attached to the periodic
digest) is rendered from the dictionary :func:`build_progress_report` returns.
Every figure in it is read from a :class:`~adscan_core.reporting.assessment_progress.PeriodSummary`
(``summarize_period``), the same derivation the assessment summary, the
regression alert and the digest read, so the PDF cannot disagree with them. This
module only chooses the period, picks the figures and words them. The renderer
(``adscan_internal.pro.reporting.progress_report_render``) only lays them out.

Pure by contract: stdlib plus sibling ``adscan_core`` modules, no clock (the
caller passes ``now``/``generated_at``), so the web backend builds the model in
the appliance, where ``adscan_internal`` is absent, and hands it to the engine
to render.

Copy rules (client-facing, English): no probability, no CVSS (ADscan's own
severity is the rating), no em dash, the status vocabulary of the shared core,
and a route that was not re-checked is named as such, never as closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional, Sequence

from adscan_core.reporting.assessment_progress import (
    Assessment,
    ComplianceReading,
    HeadlineFigures,
    ItemRef,
    KindActivity,
    PeriodSummary,
    StartHereAction,
    TrendPoint,
    evidence_label,
    previous_period_window,
)

__all__ = [
    "PRESETS",
    "PROGRESS_REPORT_KIND",
    "PROGRESS_REPORT_SCHEMA_VERSION",
    "ReportPeriod",
    "build_progress_report",
    "resolve_report_period",
]

#: Version of the document model. The renderer refuses a model it does not know.
PROGRESS_REPORT_SCHEMA_VERSION = 1
PROGRESS_REPORT_KIND = "executive_progress"

#: Period presets a client can pick. ``custom`` takes an explicit range.
PRESETS = ("last_month", "last_quarter", "since_onboarding", "custom")

#: Risks listed on the summary page, from the "Start here" ranking.
_TOP_RISKS = 3
#: Routes listed per list before the rest are counted.
_LIST_LIMIT = 6

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MONTH_NAMES = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)
_SEVERITIES = ("critical", "high", "medium", "low", "info")

_NOT_RECHECKED_NOTE = (
    "These routes keep their last known status. The checks that observe them did "
    "not run in the last assessment, so ADscan does not report them as closed."
)
_REGRESSION_NOTE = (
    "A regression is a route to Tier 0 executed end to end that the previous "
    "assessment did not have, or tried without getting through. A route that was "
    "only mapped never counts as one."
)
_METHOD_NOTE = (
    "Every figure comes from the assessments ADscan ran in this period. An item "
    "counts as closed only when an assessment observed it closed. Items your team "
    "accepted or dismissed are counted apart, and an item the last assessment could "
    "not re-check keeps its last known status. Severity is ADscan's own rating, "
    "derived from what each route reaches in this directory. The AD Exposure Score "
    "is the share of the worst-case exposure to full domain compromise the "
    "environment carries, so a lower score is better."
)


# ── Period ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ReportPeriod:
    """The ``[start, end)`` window a report covers, and how it reads."""

    start: datetime
    end: datetime
    preset: str
    label: str


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _day(value: Optional[datetime]) -> str:
    """``3 Nov 2026``. Empty for ``None``."""
    if value is None:
        return ""
    value = _utc(value)
    return f"{value.day} {_MONTHS[value.month - 1]} {value.year}"


def _short_day(value: datetime) -> str:
    value = _utc(value)
    return f"{value.day} {_MONTHS[value.month - 1]}"


def _inclusive_end(end: datetime) -> datetime:
    """The last day a ``[start, end)`` window covers, for display."""
    end = _utc(end)
    if (end.hour, end.minute, end.second, end.microsecond) == (0, 0, 0, 0):
        return end - timedelta(days=1)
    return end


def _range_label(start: datetime, end: datetime) -> str:
    return f"{_day(start)} to {_day(_inclusive_end(end))}"


def _period_phrase(period: ReportPeriod) -> str:
    """The period inside a sentence: ``in October 2026``, ``since onboarding on 10 Sep 2026``."""
    if period.preset == "since_onboarding":
        return f"since onboarding on {_day(period.start)}"
    if period.preset in ("last_month", "last_quarter"):
        return f"in {period.label}"
    return f"between {_day(period.start)} and {_day(_inclusive_end(period.end))}"


def resolve_report_period(
    preset: str,
    *,
    now: datetime,
    onboarded_at: Optional[datetime] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> ReportPeriod:
    """Return the window for a preset (or an explicit range for ``custom``).

    Args:
        preset: One of :data:`PRESETS`.
        now: Reference instant (the caller's clock).
        onboarded_at: The workspace's first assessment, for ``since_onboarding``.
            Without one the window starts at ``now`` minus a year, which still
            holds every assessment a new workspace can have.
        start / end: The explicit range for ``custom`` (``end`` exclusive).

    Raises:
        ValueError: for an unknown preset, or a ``custom`` range that is missing
            or not ordered.
    """
    token = str(preset or "").strip().lower()
    now = _utc(now)
    if token == "last_month":
        s, e = previous_period_window("monthly", now)
        return ReportPeriod(s, e, token, f"{_MONTH_NAMES[s.month - 1]} {s.year}")
    if token == "last_quarter":
        s, e = previous_period_window("quarterly", now)
        return ReportPeriod(s, e, token, f"Q{(s.month - 1) // 3 + 1} {s.year}")
    if token == "since_onboarding":
        s = _utc(onboarded_at) if onboarded_at is not None else now - timedelta(days=365)
        e = now if now > s else s + timedelta(seconds=1)
        return ReportPeriod(s, e, token, f"Since onboarding, {_range_label(s, e)}")
    if token == "custom":
        if start is None or end is None:
            raise ValueError("A custom period needs a start and an end")
        s, e = _utc(start), _utc(end)
        if e <= s:
            raise ValueError("The period end must be after its start")
        return ReportPeriod(s, e, token, _range_label(s, e))
    raise ValueError(f"Unknown period preset {preset!r}")


# ── Wording helpers ─────────────────────────────────────────────────────────


def _plural(count: int, singular: str, plural: Optional[str] = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _num(value: Optional[int]) -> str:
    return "Not recorded" if value is None else f"{value:,}"


def _pct(value: Optional[float]) -> str:
    return "Not recorded" if value is None else f"{round(value)}%"


def _change(start: Optional[float], end: Optional[float], *, unit: str = "") -> dict[str, Any]:
    """Describe a lower-is-better change: its text and its tone."""
    if start is None or end is None:
        return {"display": "", "tone": "neutral"}
    diff = end - start
    if abs(diff) < 0.5:
        return {"display": "No change", "tone": "neutral"}
    amount = f"{round(abs(diff)):,}{unit}"
    if diff < 0:
        return {"display": f"Down {amount}", "tone": "good"}
    return {"display": f"Up {amount}", "tone": "bad"}


def _figure_rows(
    start: Optional[HeadlineFigures], end: Optional[HeadlineFigures]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, label in (
        ("routes_to_full_compromise", "Routes to full domain compromise"),
        ("routes_executed_end_to_end", "Of those, executed end to end"),
        ("tier0_foothold_routes", "Routes onto a Tier 0 asset, control not yet proven"),
    ):
        a = start.get(name) if start is not None else None
        b = end.get(name) if end is not None else None
        rows.append(
            {"key": name, "label": label, "start": _num(a), "end": _num(b), **_change(a, b)}
        )
    a_with = start.ordinary_accounts_with_path if start is not None else None
    b_with = end.ordinary_accounts_with_path if end is not None else None

    def _accounts(f: Optional[HeadlineFigures]) -> str:
        if f is None or f.ordinary_accounts_with_path is None:
            return "Not recorded"
        if f.ordinary_accounts_total:
            return f"{f.ordinary_accounts_with_path:,} of {f.ordinary_accounts_total:,}"
        return f"{f.ordinary_accounts_with_path:,}"

    rows.append(
        {
            "key": "ordinary_accounts_with_path",
            "label": "Standard accounts with a validated path to Tier 0",
            "start": _accounts(start),
            "end": _accounts(end),
            **_change(a_with, b_with),
        }
    )
    return rows


def _figures_dict(figures: Optional[HeadlineFigures]) -> dict[str, Optional[int]]:
    names = (
        "routes_to_full_compromise",
        "routes_executed_end_to_end",
        "tier0_foothold_routes",
        "ordinary_accounts_with_path",
        "ordinary_accounts_total",
    )
    return {n: (figures.get(n) if figures is not None else None) for n in names}


def _severity_counts(refs: Iterable[ItemRef]) -> dict[str, int]:
    counts = {s: 0 for s in _SEVERITIES}
    for ref in refs:
        token = str(ref.severity or "").lower()
        if token in counts:
            counts[token] += 1
    return {k: v for k, v in counts.items() if v}


def _lifecycle(activity: KindActivity) -> dict[str, Any]:
    return {
        "found": len(activity.found),
        "closed_verified": len(activity.closed_verified),
        "closed_by_decision": len(activity.closed_by_decision),
        "not_reevaluated": len(activity.not_reevaluated),
        "open_at_end": activity.open_at_end,
        "found_by_severity": _severity_counts(activity.found),
        "closed_by_severity": _severity_counts(activity.closed_verified),
    }


def _route_entry(ref: ItemRef) -> dict[str, Any]:
    return {
        "title": ref.title,
        "domain": ref.domain,
        "evidence": evidence_label(ref.execution_status),
        "validated": ref.validated,
    }


def _limited(refs: Sequence[ItemRef]) -> tuple[list[dict[str, Any]], int]:
    shown = [_route_entry(r) for r in refs[:_LIST_LIMIT]]
    return shown, max(0, len(refs) - _LIST_LIMIT)


def _trend_series(
    points: Sequence[TrendPoint], value_of, *, unit: str = "%"
) -> list[dict[str, Any]]:
    """Points on a fixed 0 to 100 axis: both series are percentages."""
    series: list[dict[str, Any]] = []
    for point in points:
        value = value_of(point)
        series.append(
            {
                "label": _short_day(point.completed_at),
                "date": _day(point.completed_at),
                "value": value,
                "display": "Not recorded" if value is None else f"{round(value)}{unit}",
                "ratio": 0.0 if value is None else max(0.0, min(1.0, float(value) / 100.0)),
                "recorded": value is not None,
            }
        )
    return series


def _first_last(series: Sequence[dict[str, Any]]) -> tuple[Optional[float], Optional[float]]:
    recorded = [p["value"] for p in series if p["recorded"]]
    if not recorded:
        return None, None
    return recorded[0], recorded[-1]


def _exposure_trend(summary: PeriodSummary) -> dict[str, Any]:
    series = _trend_series(
        summary.trend, lambda p: p.exposure.overall_pct if p.exposure is not None else None
    )
    first, last = _first_last(series)
    if first is None:
        line = "No assessment in this period recorded an AD Exposure Score."
    elif len([p for p in series if p["recorded"]]) == 1:
        line = f"The AD Exposure Score was {_pct(last)} of the maximum."
    else:
        line = (
            f"The AD Exposure Score went from {_pct(first)} to {_pct(last)} of the "
            "maximum. Lower is better."
        )
    return {"points": series, "available": first is not None, "line": line, **_change(first, last, unit=" points")}


def _compliance_trend(summary: PeriodSummary) -> list[dict[str, Any]]:
    """One series per framework the latest assessment stamped (the ones selected)."""
    end = summary.end
    if end is None:
        return []
    out: list[dict[str, Any]] = []
    for reading in end.compliance:

        def _value(point: TrendPoint, key: str = reading.key) -> Optional[float]:
            match = next((c for c in point.compliance if c.key == key), None)
            return None if match is None or match.display_score is None else float(match.display_score)

        series = _trend_series(summary.trend, _value)
        first, last = _first_last(series)
        latest = _compliance_line(reading)
        out.append(
            {
                "key": reading.key,
                "label": reading.label,
                "points": series,
                "line": latest,
                # Higher is better here, so the tone is the inverse of exposure.
                **_higher_is_better(first, last),
            }
        )
    return out


def _compliance_line(reading: ComplianceReading) -> str:
    if reading.display_score is None:
        return f"No {reading.label} control was assessed in the latest assessment."
    return (
        f"{reading.conformant} of {reading.assessed} assessed controls conformant "
        f"({reading.display_score}%). Controls ADscan could not test are left out of the score."
    )


def _higher_is_better(start: Optional[float], end: Optional[float]) -> dict[str, Any]:
    change = _change(start, end, unit=" points")
    tone = {"good": "bad", "bad": "good"}.get(change["tone"], change["tone"])
    return {"display": change["display"], "tone": tone}


def _top_risks(end: Optional[Assessment]) -> list[dict[str, Any]]:
    if end is None:
        return []
    actions: Sequence[StartHereAction] = end.start_here_actions or (
        (end.start_here,) if end.start_here is not None else ()
    )
    return [
        {"rank": i + 1, "label": a.label, "line": a.line, "proven": bool(a.proven)}
        for i, a in enumerate(actions[:_TOP_RISKS])
    ]


def _mttr(summary: PeriodSummary) -> dict[str, Any]:
    routes = summary.activity.routes
    findings = summary.activity.findings
    r_days = routes.mean_days_to_remediate
    f_days = findings.mean_days_to_remediate
    parts: list[str] = []
    if f_days is not None:
        parts.append(
            f"Findings {_plural(round(f_days), 'day')} "
            f"({_plural(len(findings.remediation_days), 'verified closure')})."
        )
    if r_days is not None:
        parts.append(
            f"Routes to Tier 0 {_plural(round(r_days), 'day')} "
            f"({_plural(len(routes.remediation_days), 'verified closure')})."
        )
    if parts:
        line = (
            "Mean time to remediate, from detection to the assessment that verified the fix. "
            + " ".join(parts)
            + " Accepted and dismissed items are not counted."
        )
    else:
        line = "No fix was verified by an assessment in this period, so there is no remediation time to report."
    return {
        "findings_days": round(f_days) if f_days is not None else None,
        "routes_days": round(r_days) if r_days is not None else None,
        "findings_closures": len(findings.remediation_days),
        "routes_closures": len(routes.remediation_days),
        "line": line,
    }


def _verdict(summary: PeriodSummary, period: ReportPeriod) -> dict[str, str]:
    start = summary.baseline.figures if summary.baseline is not None else None
    end = summary.end.figures if summary.end is not None else None
    a = start.routes_to_full_compromise if start is not None else None
    b = end.routes_to_full_compromise if end is not None else None
    routes = summary.activity.routes
    regressions = len(summary.regressions.new_validated_routes) + len(
        summary.regressions.newly_succeeding_routes
    )
    if a is not None and b is not None and a != b:
        headline = f"Routes to full domain compromise went from {a:,} to {b:,} {_period_phrase(period)}."
    elif b is not None:
        headline = f"Routes to full domain compromise held at {b:,} {_period_phrase(period)}."
    else:
        headline = f"Progress on Active Directory exposure {_period_phrase(period)}."
    sub: list[str] = []
    if routes.closed_verified:
        sub.append(
            f"{_plural(len(routes.closed_verified), 'route')} to Tier 0 closed and verified by an assessment."
        )
    if regressions:
        sub.append(
            f"{_plural(regressions, 'new route')} to Tier 0 executed end to end, reported as "
            f"{'a regression' if regressions == 1 else 'regressions'}."
        )
    if routes.not_reevaluated:
        sub.append(
            f"{_plural(len(routes.not_reevaluated), 'route')} not re-checked in the last assessment, kept open."
        )
    tone = "bad" if regressions else ("good" if routes.closed_verified else "neutral")
    return {"headline": headline, "sub": " ".join(sub), "tone": tone}


def _coverage(summary: PeriodSummary) -> dict[str, Any]:
    count = len(summary.assessments_in_period)
    days = summary.days_since_last_verification
    if count:
        line = f"{_plural(count, 'assessment')} completed in this period."
    else:
        line = "No assessment completed in this period."
    if summary.last_verified_at is not None:
        line += (
            f" The most recent verification was on {_day(summary.last_verified_at)}, "
            f"{_plural(days or 0, 'day')} before the end of the period."
        )
    else:
        line += " This workspace has not been assessed yet."
    if summary.next_scheduled_at is not None:
        line += f" The next scheduled assessment is on {_day(summary.next_scheduled_at)}."
    return {
        "assessments_in_period": count,
        "last_verified": _day(summary.last_verified_at),
        "days_since_last_verification": days,
        "next_scheduled": _day(summary.next_scheduled_at),
        "line": line,
    }


def _since_onboarding(cumulative: Optional[PeriodSummary]) -> Optional[dict[str, Any]]:
    if cumulative is None or not cumulative.has_assessment:
        return None
    routes = len(cumulative.activity.routes.closed_verified)
    findings = len(cumulative.activity.findings.closed_verified)
    since = _day(cumulative.assessments_in_period[0].completed_at)
    line = (
        f"Since onboarding on {since}, {_plural(routes, 'route')} to Tier 0 and "
        f"{_plural(findings, 'finding')} closed and verified by an assessment."
    )
    return {
        "since": since,
        "routes_closed_verified": routes,
        "findings_closed_verified": findings,
        "assessments": len(cumulative.assessments_in_period),
        "line": line,
    }


# ── Public API ──────────────────────────────────────────────────────────────


def build_progress_report(
    summary: PeriodSummary,
    *,
    since_onboarding: Optional[PeriodSummary],
    workspace_name: str,
    period: ReportPeriod,
    generated_at: datetime,
    client_name: Optional[str] = None,
) -> dict[str, Any]:
    """Return the JSON-safe document model of the executive progress report.

    Args:
        summary: ``summarize_period`` over ``period``.
        since_onboarding: ``summarize_period`` from the first assessment to the
            end of ``period``, for the cumulative line (``None`` to omit it).
        workspace_name: The workspace (shown when there is no client name).
        period: The resolved window.
        generated_at: When the report is generated (the caller's clock).
        client_name: Optional client display name for the masthead.

    A period with no assessment carries the coverage line and nothing else, so
    an older scan's numbers can never read as the period's state.
    """
    base: dict[str, Any] = {
        "schema_version": PROGRESS_REPORT_SCHEMA_VERSION,
        "kind": PROGRESS_REPORT_KIND,
        "title": "Executive Progress Report",
        "workspace": workspace_name,
        "client_name": client_name or "",
        "subject": client_name or workspace_name,
        "generated_at": _utc(generated_at).isoformat(),
        "generated": _day(generated_at),
        "period": {
            "start": period.start.isoformat(),
            "end": period.end.isoformat(),
            "preset": period.preset,
            "label": period.label,
            "range": _range_label(period.start, period.end),
        },
        "has_assessment": summary.has_assessment,
        "coverage": _coverage(summary),
        "method_note": _METHOD_NOTE,
    }
    if not summary.has_assessment:
        return {
            **base,
            "verdict": {
                "headline": f"No assessment completed {_period_phrase(period)}.",
                "sub": "This report states only when the environment was last verified. "
                "Figures from an earlier assessment are not presented as this period's state.",
                "tone": "neutral",
            },
            "routes_to_tier0": None,
            "lifecycle": None,
            "regressions": None,
            "not_rechecked": None,
            "mttr": None,
            "exposure_trend": None,
            "compliance": [],
            "top_risks": None,
            "since_onboarding": None,
        }

    start_figures = summary.baseline.figures if summary.baseline is not None else None
    end_figures = summary.end.figures if summary.end is not None else None
    regressions = summary.regressions
    regression_refs = (*regressions.new_validated_routes, *regressions.newly_succeeding_routes)
    regression_items, regression_more = _limited(regression_refs)
    stale_items, stale_more = _limited(summary.activity.routes.not_reevaluated)
    start_label = (
        _day(summary.baseline.completed_at) if summary.baseline is not None else ""
    )
    return {
        **base,
        "verdict": _verdict(summary, period),
        "routes_to_tier0": {
            "start_assessment": start_label,
            "end_assessment": _day(summary.end.completed_at) if summary.end else "",
            "start": _figures_dict(start_figures),
            "end": _figures_dict(end_figures),
            "rows": _figure_rows(start_figures, end_figures),
            "baseline_note": (
                ""
                if summary.baseline is not None and not summary.baseline_in_period
                else "The first assessment in this period is the starting point."
            ),
        },
        "lifecycle": {
            "routes": _lifecycle(summary.activity.routes),
            "findings": _lifecycle(summary.activity.findings),
        },
        "regressions": {
            "count": len(regression_refs),
            "routes": regression_items,
            "more": regression_more,
            "domains_newly_compromised": list(regressions.domains_newly_compromised),
            "note": _REGRESSION_NOTE,
        },
        "not_rechecked": {
            "count": len(summary.activity.routes.not_reevaluated),
            "routes": stale_items,
            "more": stale_more,
            "note": _NOT_RECHECKED_NOTE,
        },
        "mttr": _mttr(summary),
        "exposure_trend": _exposure_trend(summary),
        "compliance": _compliance_trend(summary),
        "top_risks": _top_risks(summary.end),
        "since_onboarding": _since_onboarding(since_onboarding),
    }
