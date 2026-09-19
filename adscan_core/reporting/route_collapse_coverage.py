"""Attack-path route-collapse coverage: the client-facing statement, derived once.

Domain-scope attack-path discovery evaluates every candidate route to a
finding, not just the one the report shows. Several near-duplicate routes
(same source, same terminal technique, different intermediate hops) usually
collapse into ONE reported finding, and a large domain can additionally hit
a rendering cap that shows only the top routes and moves the rest into an
appendix. Both are legitimate: a client deliverable that listed every raw
route would bury the finding under its own duplicates, and one that rendered
every evaluated route regardless of count would be unreadable at enterprise
scale.

Under the Exposure-Validation doctrine, a bounded or collapsed result is a
**data gap in the same family as** :mod:`adscan_core.reporting.cracking_coverage`:
ADscan states where the count stopped and why, rather than letting a
collapsed or capped listing silently read as an exhaustive one. So the
deliverable declares, in one client-safe sentence, how many routes were
evaluated, how many were executed, how many distinct findings that folded
into, and, when the render was capped, that the remainder sits in an
appendix rather than having been dropped.

This module is the SSOT for both halves, mirroring
:mod:`adscan_core.reporting.cracking_coverage`:

* :func:`build_route_collapse_coverage` turns the observed collapse counts
  into the report-level block persisted alongside the domain-scope
  attack-path listing. It carries only the raw fields, so no prose is baked
  in here and a persisted block never goes stale if the wording changes later.
* :func:`route_collapse_coverage_view` turns that persisted block (or any
  bare mapping carrying a subset of the same fields) into the small
  render-ready shape the PDF report and the paid web platform both consume,
  including the client-facing ``coverage_line``, so the two surfaces cannot
  word the same collapse differently.

Pure logic: no IO, no console, no network. Safe to import from
``adscan_core``, the LITE runtime, the PRO report renderer and the web
backend alike.
"""

from __future__ import annotations

from typing import Any, Mapping

#: Key the domain-scope route-collapse coverage block is stamped under (one
#: report-level block per domain-scope attack-path listing), mirroring
#: :data:`adscan_core.reporting.cracking_coverage.CRACKING_COVERAGE_KEY`.
ROUTE_COLLAPSE_COVERAGE_KEY = "route_collapse_coverage"


def _clean_count(value: Any) -> int:
    """Coerce an arbitrary field into a non-negative count.

    A ``None``, missing, or otherwise unreadable value yields ``0`` rather
    than raising, so a partially-populated block — one written before a
    later field was added, or a hand-built mapping carrying only some of the
    fields — still renders a coherent (if conservative) sentence instead of
    crashing the report.
    """

    try:
        if value is None:
            return 0
        count = int(value)
    except (TypeError, ValueError):
        return 0
    return count if count >= 0 else 0


def _noun(count: int, singular: str, plural: str) -> str:
    """Return the grammatically-agreeing noun for a count."""

    return singular if count == 1 else plural


def _render_coverage_line(
    *,
    distinct_findings: int,
    raw_routes: int,
    executed_routes: int,
    partial_routes: int,
    rendered: int,
    capped: bool,
) -> str:
    """Render the client-facing route-collapse sentence.

    Leads with what ADscan actually PROVED, never a modeled percentage, per
    the Exposure-Validation doctrine on choke-point and remediation prose.
    ``executed_routes`` counts only routes walked FULLY end to end;
    ``partial_routes`` counts routes where ADscan proved the entry step
    without walking the rest of the chain (a real distinct proof level, not
    a rounding error). When ``partial_routes`` is zero the sentence is
    unchanged from the original wording; when it is non-zero the sentence
    states both proof levels honestly rather than folding a partial route
    into "executed" (which would claim an end-to-end walk that never
    happened) or silently dropping it from the count.
    """

    lead = (
        f"ADscan evaluated {raw_routes} candidate {_noun(raw_routes, 'route', 'routes')}, "
        f"which deduplicated into {distinct_findings} attack "
        f"{_noun(distinct_findings, 'path', 'paths')}."
    )
    if partial_routes <= 0:
        statement = (
            f"ADscan executed {executed_routes} of {raw_routes} evaluated candidate "
            f"{_noun(raw_routes, 'route', 'routes')}, which deduplicated into "
            f"{distinct_findings} attack "
            f"{_noun(distinct_findings, 'path', 'paths')}."
        )
    elif executed_routes > 0:
        statement = (
            f"{lead} ADscan walked {executed_routes} of them fully to domain "
            f"compromise and proved the entry step on {partial_routes} more."
        )
    else:
        statement = (
            f"{lead} ADscan proved the entry step on {partial_routes} of them. "
            "None were walked to full domain compromise."
        )
    if not capped:
        return statement
    return (
        f"{statement} The report lists the top {rendered} attack "
        f"{_noun(rendered, 'path', 'paths')} here, with the remainder "
        "in the appendix."
    )


def build_route_collapse_coverage(
    *,
    distinct_findings: int,
    raw_routes: int,
    executed_routes: int,
    rendered: int,
    capped: bool,
    partial_routes: int = 0,
) -> dict[str, Any]:
    """Build the ``route_collapse_coverage`` block for a domain-scope report.

    Report-level, not per-finding: it summarises the whole domain-scope
    attack-path listing (how many candidate routes were evaluated across it,
    how many distinct findings they folded into), mirroring how
    :mod:`adscan_core.reporting.cracking_coverage` summarises a report's
    cracking coverage once rather than per hash.

    Args:
        distinct_findings: How many distinct findings the raw routes folded
            into after collapsing near-duplicates.
        raw_routes: How many candidate routes were evaluated before the
            collapse.
        executed_routes: How many of those routes ADscan walked FULLY end to
            end (excludes a route proven only up to its entry step).
        rendered: How many routes the report actually lists. Equal to
            ``raw_routes`` when nothing was capped.
        capped: Whether the render stopped short of listing every evaluated
            route, moving the remainder into an appendix.
        partial_routes: How many of those routes ADscan proved only the
            entry step of, without walking the rest of the chain to full
            domain compromise. Defaults to ``0`` for a caller that has not
            yet distinguished partial proof from full execution.

    Returns:
        The block to persist alongside the domain-scope report. Carries only the raw
        counts (no derived prose), mirroring how
        :func:`adscan_core.reporting.cracking_coverage.build_cracking_coverage`
        separates the persisted data from its render view — the wording
        lives entirely in :func:`route_collapse_coverage_view`, so a change
        to the sentence never requires re-deriving or migrating already-
        persisted blocks.
    """

    return {
        "distinct_findings": _clean_count(distinct_findings),
        "raw_routes": _clean_count(raw_routes),
        "executed_routes": _clean_count(executed_routes),
        "partial_routes": _clean_count(partial_routes),
        "rendered": _clean_count(rendered),
        "capped": bool(capped),
    }


def route_collapse_coverage_view(block: Any) -> dict[str, Any]:
    """Return the render-ready view of a persisted ``route_collapse_coverage`` block.

    The one shape the PDF report and the web platform both read, so a
    collapsed or capped route count is worded identically wherever a client
    meets it.

    Args:
        block: The persisted block (as built by
            :func:`build_route_collapse_coverage`), or any mapping carrying
            a subset of its fields. Every field is read defensively: a
            missing or unreadable count defaults to ``0`` and a missing
            ``capped`` defaults to ``False``, so a lone-survivor record —
            one written before a later field existed, or one this module's
            caller only partially populated — still renders a coherent
            sentence instead of raising.

    Returns:
        A mapping with:
          * ``distinct_findings`` / ``raw_routes`` / ``executed_routes`` /
            ``partial_routes`` / ``rendered`` — the counts, cleaned to
            non-negative integers;
          * ``capped`` — whether the render stopped short of the full
            evaluated set;
          * ``coverage_line`` — the client-facing sentence declaring the
            collapse, honest about the bound when ``capped`` is ``True`` and
            about the proof level (fully executed vs. entry-step-only
            partial) when ``partial_routes`` is non-zero.

        A non-mapping ``block`` (e.g. ``None``, an absent record) is treated
        as an all-zero, uncapped block rather than raising, so a scan
        predating this record renders a plain "nothing was collapsed"
        sentence instead of crashing the report.
    """

    if not isinstance(block, Mapping):
        block = {}
    distinct_findings = _clean_count(block.get("distinct_findings"))
    raw_routes = _clean_count(block.get("raw_routes"))
    executed_routes = _clean_count(block.get("executed_routes"))
    partial_routes = _clean_count(block.get("partial_routes"))
    rendered = _clean_count(block.get("rendered"))
    capped = bool(block.get("capped") or False)
    coverage_line = _render_coverage_line(
        distinct_findings=distinct_findings,
        raw_routes=raw_routes,
        executed_routes=executed_routes,
        partial_routes=partial_routes,
        rendered=rendered,
        capped=capped,
    )
    return {
        "distinct_findings": distinct_findings,
        "raw_routes": raw_routes,
        "executed_routes": executed_routes,
        "partial_routes": partial_routes,
        "rendered": rendered,
        "capped": capped,
        "coverage_line": coverage_line,
    }


__all__ = [
    "ROUTE_COLLAPSE_COVERAGE_KEY",
    "build_route_collapse_coverage",
    "route_collapse_coverage_view",
]
