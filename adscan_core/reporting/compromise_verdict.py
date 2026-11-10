"""What a scan may say about whether a domain was compromised: the verdict SSOT.

"This domain held" is a claim about the client's directory, and the only
evidence that supports it is an attempt: every route to full domain compromise
was tried and none completed. A route ADscan mapped but never executed proves
nothing either way. The release gate found a Production-sensitive scan that
mapped one route to domain compromise, executed none of its steps (the policy
asks an operator to approve each step and none was present), and closed with
"no full compromise: this domain held". The domain did not hold; ADscan was not
allowed to try.

So every surface that states the outcome reads it here, from the per-domain
``exposure_kpis`` block the scan stamps (the ``path_axis.domain_breaker``
counts behind every "routes to full domain compromise" figure, plus the
operator-decision route counts) and the ``scan_policy_coverage`` block beside it.

Verdicts:

* ``domain_compromised`` -- a route was walked end to end, or the caller holds
  proof of Domain Admin control.
* ``assessment_incomplete`` -- the core phases did not complete (the caller
  passes which), so nothing below can be claimed.
* ``routes_awaiting_operator`` -- every unexecuted route waits for an operator's
  approval that never came (reason 2 below).
* ``routes_not_executed`` -- routes to domain compromise were left unexecuted
  for any mix of reasons; each reason is stated with its route count.
* ``held`` -- routes existed and every one was attempted without completing, or
  closed by a configuration ADscan observed. The only state that may say the
  domain held.
* ``no_route_found`` -- the analysis found no route to domain compromise. Not
  "held": nothing was tried because there was nothing to try.

The four reasons a mapped route did not run, each with its own wording on
every surface (founder decisions, 2026-11-08 and 2026-11-09):

1. ``excluded_by_scan_policy`` -- the scan policy excludes a step (the check is off).
2. ``operator_required`` -- awaiting approval: an attended policy, and nobody
   answered (no operator connected, or the relayed decision timed out). Nobody
   decided "no", so it is never worded as a decision.
3. ``operator_declined`` -- an operator answered "no" during the scan.
4. ``outside_engagement_scope`` -- a step acts on, or from, a domain outside the
   engagement scope (``adscan_core.reporting.engagement_scope``). Scope is
   contractual, so the route is mapped and never executed, in any run mode.

A route can also be unexecuted for none of them (an operator never reached it,
or only its entry step ran); that is stated as "in this assessment".

Stdlib only, so the CLI, both report tiers and the web backend share it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from adscan_core.reporting.reach_claim import awaiting_approval_cause

__all__ = [
    "NOT_EXECUTED_AWAITING_OPERATOR",
    "NOT_EXECUTED_OPERATOR_DECLINED",
    "NOT_EXECUTED_OUTSIDE_SCOPE",
    "NOT_EXECUTED_POLICY_EXCLUDED",
    "NOT_EXECUTED_THIS_RUN",
    "OPERATOR_DECISION_ROUTES_KEY",
    "OUTSIDE_SCOPE_DOMAINS_KEY",
    "outside_scope_domains_of",
    "REACH_ATTEMPTED",
    "REACH_ENTRY_PROVEN",
    "REACH_MAPPED",
    "REACH_PROVEN",
    "VERDICT_ASSESSMENT_INCOMPLETE",
    "VERDICT_DOMAIN_COMPROMISED",
    "VERDICT_HELD",
    "VERDICT_NO_ROUTE_FOUND",
    "VERDICT_ROUTES_AWAITING_OPERATOR",
    "VERDICT_ROUTES_NOT_EXECUTED",
    "UNEXECUTED_VERDICTS",
    "CompromiseVerdict",
    "aggregate_awaiting_wait_seconds",
    "aggregate_reach_evidence",
    "operator_awaiting_wait_seconds",
    "OPERATOR_AWAITING_WAIT_KEY",
    "derive_compromise_verdict",
    "not_executed_reason_from_coverage",
    "operator_decision_route_counts",
    "verdict_from_kpis",
    "verdict_from_report_entry",
]

VERDICT_DOMAIN_COMPROMISED = "domain_compromised"
VERDICT_ASSESSMENT_INCOMPLETE = "assessment_incomplete"
VERDICT_ROUTES_AWAITING_OPERATOR = "routes_awaiting_operator"
VERDICT_ROUTES_NOT_EXECUTED = "routes_not_executed"
VERDICT_HELD = "held"
VERDICT_NO_ROUTE_FOUND = "no_route_found"
#: Verdicts whose routes to domain compromise were mapped and not run.
UNEXECUTED_VERDICTS = frozenset({VERDICT_ROUTES_AWAITING_OPERATOR, VERDICT_ROUTES_NOT_EXECUTED})

#: The reason tokens. They are the engine's own step-note values
#: (``adscan_core.scan_policy.annotate.NOT_EXECUTED_REASON`` and
#: ``adscan_core.scan_policy.execution.REASON_*``), repeated as literals so this
#: module stays a leaf; a unit test locks them together.
NOT_EXECUTED_POLICY_EXCLUDED = "excluded_by_scan_policy"
NOT_EXECUTED_AWAITING_OPERATOR = "operator_required"
NOT_EXECUTED_OPERATOR_DECLINED = "operator_declined"
#: ``adscan_core.reporting.engagement_scope.NOT_EXECUTED_OUTSIDE_SCOPE``.
NOT_EXECUTED_OUTSIDE_SCOPE = "outside_engagement_scope"
NOT_EXECUTED_THIS_RUN = ""
#: Reasons the engine notes on the step itself; counted per route into
#: :data:`OPERATOR_DECISION_ROUTES_KEY`.
_STEP_NOTED_REASONS = (
    NOT_EXECUTED_OUTSIDE_SCOPE,
    NOT_EXECUTED_OPERATOR_DECLINED,
    NOT_EXECUTED_AWAITING_OPERATOR,
)

#: ``exposure_kpis`` key: ``{reason: routes}`` for the routes to full domain
#: compromise a step-level note kept from running (``operator_declined`` /
#: ``operator_required`` / ``outside_engagement_scope``). Absent when there are
#: none. The key keeps its historical name so persisted blocks still read.
OPERATOR_DECISION_ROUTES_KEY = "operator_decision_routes"
#: ``exposure_kpis`` key: how long the relayed approval requests behind the
#: routes awaiting approval waited before they timed out (seconds, the longest).
#: Absent when no request timed out, which is how the verdict tells "nobody
#: answered in time" from "nobody was there to ask".
OPERATOR_AWAITING_WAIT_KEY = "operator_awaiting_wait_seconds"
#: ``exposure_kpis`` key: the out-of-scope domains the unexecuted routes to full
#: domain compromise pass through, so the verdict can name them. Absent when
#: there are none.
OUTSIDE_SCOPE_DOMAINS_KEY = "outside_scope_domains"

#: How far the strongest route to domain compromise was executed. Drives the
#: reach phrase (``reach_claim``) so a mapped route is never described as having
#: its entry step proven.
REACH_PROVEN = "proven"
REACH_ENTRY_PROVEN = "entry_proven"
REACH_ATTEMPTED = "attempted"
REACH_MAPPED = "mapped"

_REACH_ORDER = (REACH_PROVEN, REACH_ENTRY_PROVEN, REACH_ATTEMPTED, REACH_MAPPED)
#: Order reasons are stated in, and the tie-break for one aggregated reason.
_REASON_ORDER = (
    NOT_EXECUTED_OUTSIDE_SCOPE,
    NOT_EXECUTED_OPERATOR_DECLINED,
    NOT_EXECUTED_AWAITING_OPERATOR,
    NOT_EXECUTED_POLICY_EXCLUDED,
    NOT_EXECUTED_THIS_RUN,
)

#: Status tokens of a ``path_axis`` bucket, grouped by what they prove. Mirrors
#: the engine vocabulary (``path_state`` / ``exposure_score_service``) and the
#: web tiers (``exposure_kpis_view``). Any token not listed is NOT an attempt:
#: an unknown status can never support "held".
_PROVEN = frozenset({"success", "exploited", "domain_compromised"})
_ENTRY_PROVEN = frozenset({"partial"})
_ATTEMPTED = frozenset({"attempted", "failed", "error", "post_ex_failed", "blocked"})
_CLOSED = frozenset({"closed_by_configuration", "not_vulnerable"})
_NON_STATUS_KEYS = frozenset({"total", "exposure_total", "safety_withheld"})


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _plural(count: int, one: str, many: str) -> str:
    return one if count == 1 else many


def _routes(count: int) -> str:
    return f"{count} {_plural(count, 'route', 'routes')}"


#: Short CLI clause per reason, after "N routes to domain compromise ...".
_RECAP_REASON: dict[str, str] = {
    NOT_EXECUTED_POLICY_EXCLUDED: "not executed, your scan policy excludes a step",
    NOT_EXECUTED_AWAITING_OPERATOR: "mapped, awaiting approval (no operator was present to decide)",
    NOT_EXECUTED_OPERATOR_DECLINED: "not executed, the operator chose not to run them",
    NOT_EXECUTED_OUTSIDE_SCOPE: "not executed, outside the engagement scope",
    NOT_EXECUTED_THIS_RUN: "mapped, not executed in this run",
}
#: Client sentence fragment per reason, after "N routes to full domain compromise ...".
_SENTENCE_REASON: dict[str, tuple[str, str]] = {
    # (singular verb phrase, plural verb phrase)
    NOT_EXECUTED_POLICY_EXCLUDED: (
        "was not executed because your scan policy excludes a step on it",
        "were not executed because your scan policy excludes a step on them",
    ),
    NOT_EXECUTED_AWAITING_OPERATOR: (
        "was mapped and awaits approval, because no operator was present to decide",
        "were mapped and await approval, because no operator was present to decide",
    ),
    NOT_EXECUTED_OPERATOR_DECLINED: (
        "was not executed because the operator chose not to run it",
        "were not executed because the operator chose not to run them",
    ),
    NOT_EXECUTED_OUTSIDE_SCOPE: (
        "was mapped and not executed because a step on it is outside the engagement scope",
        "were mapped and not executed because a step on them is outside the engagement scope",
    ),
    NOT_EXECUTED_THIS_RUN: (
        "was mapped and not executed in this assessment",
        "were mapped and not executed in this assessment",
    ),
}


@dataclass(frozen=True)
class CompromiseVerdict:
    """The outcome a surface may state for one domain.

    Every count is a ROUTE count over routes to full domain compromise.
    ``routes`` is the open-exposure figure every "routes to full domain
    compromise" headline prints, so the verdict and the headline cannot differ.
    ``causes`` splits the unexecuted routes by reason, in statement order.
    """

    kind: str
    routes: int = 0
    proven: int = 0
    entry_proven: int = 0
    attempted: int = 0
    not_executed: int = 0
    closed: int = 0
    causes: tuple[tuple[str, int], ...] = field(default_factory=tuple)
    missing_phases: tuple[str, ...] = ()
    outside_scope_domains: tuple[str, ...] = ()
    #: The recorded wait of the approval requests that timed out (seconds); 0
    #: when the routes awaiting approval had nobody to ask.
    awaiting_wait_seconds: int = 0

    @property
    def not_completed(self) -> int:
        """Routes not attempted in full (mapped, entry step only, withheld)."""
        return self.not_executed + self.entry_proven

    @property
    def not_executed_reason(self) -> str:
        """The single reason to name when a surface can state only one."""
        return self.causes[0][0] if self.causes else NOT_EXECUTED_THIS_RUN

    @property
    def reach_evidence(self) -> str:
        """How far the strongest route was executed (``REACH_*``)."""
        if self.proven > 0:
            return REACH_PROVEN
        if self.entry_proven > 0:
            return REACH_ENTRY_PROVEN
        if self.attempted > 0 and self.not_executed == 0:
            return REACH_ATTEMPTED
        return REACH_MAPPED

    def recap_phrase(self) -> str:
        """The short outcome line the CLI recap prints beside the domain name."""
        if self.kind == VERDICT_HELD:
            if self.closed and not self.attempted:
                return (
                    "no full compromise: every route to domain compromise is closed "
                    "by configuration"
                )
            tail = " or closed by configuration" if self.closed else ""
            return (
                "no full compromise: every route to domain compromise was "
                f"attempted{tail}, none completed"
            )
        if self.kind in UNEXECUTED_VERDICTS:
            if len(self.causes) == 1:
                reason, count = self.causes[0]
                clause = _RECAP_REASON[reason]
                if reason == NOT_EXECUTED_AWAITING_OPERATOR:
                    clause = (
                        "mapped, awaiting approval "
                        f"({awaiting_approval_cause(self.awaiting_wait_seconds)})"
                    )
                if reason == NOT_EXECUTED_OPERATOR_DECLINED and count == 1:
                    clause = clause.replace("run them", "run it")
                if reason == NOT_EXECUTED_THIS_RUN and self.entry_proven and not self.not_executed:
                    clause = "not walked end to end in this run"
                return f"{_routes(count)} to domain compromise {clause}"
            parts = ", ".join(
                f"{count} {_short_reason(reason)}" for reason, count in self.causes
            )
            return f"{_routes(self.not_completed)} to domain compromise not executed ({parts})"
        if self.kind == VERDICT_NO_ROUTE_FOUND:
            return "no route to domain compromise found"
        if self.kind == VERDICT_ASSESSMENT_INCOMPLETE:
            return "assessment incomplete"
        return "full domain compromise"

    def sentence(self) -> str:
        """A full client sentence (or two) for a report or the platform."""
        if self.kind == VERDICT_DOMAIN_COMPROMISED:
            return "Full domain compromise was proven."
        if self.kind == VERDICT_ASSESSMENT_INCOMPLETE:
            return (
                "The assessment did not complete, so it cannot show whether the "
                "domain resisted compromise."
            )
        if self.kind == VERDICT_NO_ROUTE_FOUND:
            return "No route to full domain compromise was found."
        if self.kind == VERDICT_HELD:
            if self.closed and not self.attempted:
                return (
                    "Every route to full domain compromise is closed by the "
                    "domain's own configuration."
                )
            closed = " or closed by configuration" if self.closed else ""
            return (
                "Every route to full domain compromise was attempted"
                f"{closed}, and none completed."
            )
        clauses = []
        for reason, count in self.causes:
            one, many = _SENTENCE_REASON[reason]
            if reason == NOT_EXECUTED_AWAITING_OPERATOR:
                cause = awaiting_approval_cause(self.awaiting_wait_seconds)
                one = f"was mapped and awaits approval, because {cause}"
                many = f"were mapped and await approval, because {cause}"
            if reason == NOT_EXECUTED_OUTSIDE_SCOPE and self.outside_scope_domains:
                one, many = _outside_scope_clauses(
                    self.outside_scope_domains, entry_proven=self.entry_proven > 0
                )
            if reason == NOT_EXECUTED_THIS_RUN and self.entry_proven and not self.not_executed:
                one = "was walked only as far as its entry step"
                many = "were walked only as far as their entry step"
            clauses.append(
                f"{_routes(count)} to full domain compromise {one if count == 1 else many}"
            )
        lead = ". ".join(c[0].upper() + c[1:] for c in clauses)
        return f"{lead}. The assessment cannot say whether the domain held."

    def to_dict(self) -> dict[str, Any]:
        """JSON shape for a persisted block or an API response."""
        return {
            "kind": self.kind,
            "routes": self.routes,
            "proven": self.proven,
            "entry_proven": self.entry_proven,
            "attempted": self.attempted,
            "not_executed": self.not_executed,
            "closed": self.closed,
            "causes": [{"reason": r, "routes": n} for r, n in self.causes],
            "outside_scope_domains": list(self.outside_scope_domains),
            "awaiting_wait_seconds": self.awaiting_wait_seconds,
            "reach_evidence": self.reach_evidence,
            "recap_phrase": self.recap_phrase(),
            "sentence": self.sentence(),
        }


def _outside_scope_clauses(
    domains: tuple[str, ...], *, entry_proven: bool
) -> tuple[str, str]:
    """The fourth reason's clauses, naming the out-of-scope domains it crosses."""
    names = list(domains)
    where = names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"
    verb = "is" if len(names) == 1 else "are"
    if entry_proven:
        return (
            f"was walked up to {where}, which {verb} outside the engagement scope, "
            "and not executed past it",
            f"were walked up to {where}, which {verb} outside the engagement scope, "
            "and not executed past it",
        )
    return (
        f"was mapped and not executed because it passes through {where}, which "
        f"{verb} outside the engagement scope",
        f"were mapped and not executed because they pass through {where}, which "
        f"{verb} outside the engagement scope",
    )


def outside_scope_domains_of(records: Iterable[Any]) -> list[str]:
    """The out-of-scope domains the unproven routes to full domain compromise cross.

    Read from the engine's own step notes through the shared route split
    (``engagement_scope.split_route_at_scope``), on the routes whose stopping
    cause is the engagement scope, so it holds before any report annotation
    runs. Sorted, de-duplicated.
    """
    from adscan_core.reporting.engagement_scope import (  # noqa: PLC0415
        split_route_at_scope,
    )
    from adscan_core.scan_policy.annotate import (  # noqa: PLC0415
        route_not_executed_cause,
    )

    found: set[str] = set()
    for record in records or ():
        if not isinstance(record, Mapping):
            continue
        if str(record.get("compromise_class") or "").strip().lower() != "domain_breaker":
            continue
        if str(record.get("status") or "").strip().lower() in _PROVEN:
            continue
        if route_not_executed_cause(record) != NOT_EXECUTED_OUTSIDE_SCOPE:
            continue
        steps = record.get("steps")
        if isinstance(steps, list):
            found.update(split_route_at_scope(steps).out_domains)
    return sorted(found)


def _short_reason(reason: str) -> str:
    return {
        NOT_EXECUTED_POLICY_EXCLUDED: "excluded by your scan policy",
        NOT_EXECUTED_AWAITING_OPERATOR: "awaiting approval",
        NOT_EXECUTED_OPERATOR_DECLINED: "declined by the operator",
        NOT_EXECUTED_OUTSIDE_SCOPE: "outside the engagement scope",
        NOT_EXECUTED_THIS_RUN: "not reached in this run",
    }.get(reason, "not executed")


def operator_decision_route_counts(records: Iterable[Any]) -> dict[str, int]:
    """Count the unproven full-domain-compromise routes each step note stopped.

    Reads the first not-run step's engine note on each record
    (``annotate.route_not_executed_cause``); the two operator-decision reasons
    and the engagement scope are counted here.
    """
    from adscan_core.scan_policy.annotate import route_not_executed_cause  # noqa: PLC0415

    counts: dict[str, int] = {}
    for record in records or ():
        if not isinstance(record, Mapping):
            continue
        if str(record.get("compromise_class") or "").strip().lower() != "domain_breaker":
            continue
        if str(record.get("status") or "").strip().lower() in _PROVEN:
            continue
        cause = route_not_executed_cause(record)
        if cause in _STEP_NOTED_REASONS:
            counts[cause] = counts.get(cause, 0) + 1
    return counts


def operator_awaiting_wait_seconds(records: Iterable[Any]) -> int:
    """The recorded wait behind the routes to full domain compromise awaiting approval.

    Read from the step the route stopped at (``annotate.route_awaiting_wait_seconds``):
    the longest wait among the unproven routes whose cause is an approval nobody
    gave. 0 when none of them recorded one (nobody was there to ask).
    """
    from adscan_core.scan_policy.annotate import route_awaiting_wait_seconds  # noqa: PLC0415

    longest = 0
    for record in records or ():
        if not isinstance(record, Mapping):
            continue
        if str(record.get("compromise_class") or "").strip().lower() != "domain_breaker":
            continue
        if str(record.get("status") or "").strip().lower() in _PROVEN:
            continue
        longest = max(longest, route_awaiting_wait_seconds(record))
    return longest


def not_executed_reason_from_coverage(
    scan_policy_coverage: Mapping[str, Any] | None,
) -> str:
    """Why this run's mapped routes did not execute, from the stamped policy block.

    ``operator_required`` when the policy left every attack step to an operator
    and none was present (``execution_decision == "map_only"``): no step of any
    route could run, whatever the policy enables. Otherwise
    ``excluded_by_scan_policy`` when a reported route carries a step the policy
    excludes, and ``""`` (this run) when the policy is not the reason.
    """
    if not isinstance(scan_policy_coverage, Mapping):
        return NOT_EXECUTED_THIS_RUN
    if str(scan_policy_coverage.get("execution_decision") or "") == "map_only":
        return NOT_EXECUTED_AWAITING_OPERATOR
    if _int(scan_policy_coverage.get("routes_not_executed")) > 0:
        return NOT_EXECUTED_POLICY_EXCLUDED
    return NOT_EXECUTED_THIS_RUN


def derive_compromise_verdict(
    domain_breaker: Mapping[str, Any] | None,
    *,
    domain_compromised: bool = False,
    missing_phases: Iterable[str] = (),
    not_executed_reason: str = NOT_EXECUTED_THIS_RUN,
    operator_decisions: Mapping[str, Any] | None = None,
    outside_scope_domains: Iterable[str] = (),
    awaiting_wait_seconds: int = 0,
) -> CompromiseVerdict:
    """Return the verdict for one domain's ``path_axis.domain_breaker`` bucket.

    Args:
        domain_breaker: The stamped bucket (per-status counts plus ``total``,
            ``exposure_total`` and ``safety_withheld``). ``None`` reads as no
            route found.
        domain_compromised: Proof of Domain Admin control held by the caller
            (the ``pwned`` marker), which outranks every count.
        missing_phases: Core phases that did not complete; any makes the
            verdict ``assessment_incomplete``.
        not_executed_reason: The run-wide reason for the unexecuted routes no
            operator decision covers (:func:`not_executed_reason_from_coverage`).
        operator_decisions: ``{operator_declined|operator_required|
            outside_engagement_scope: routes}`` (the stamped
            :data:`OPERATOR_DECISION_ROUTES_KEY` block).
        awaiting_wait_seconds: The stamped :data:`OPERATOR_AWAITING_WAIT_KEY`,
            so "awaits approval" names an unanswered request rather than an
            absent operator when one was asked.
    """
    bucket = domain_breaker if isinstance(domain_breaker, Mapping) else {}
    counts = {
        str(k).strip().lower(): _int(v)
        for k, v in bucket.items()
        if str(k) not in _NON_STATUS_KEYS
    }
    proven = sum(n for k, n in counts.items() if k in _PROVEN)
    entry_proven = sum(n for k, n in counts.items() if k in _ENTRY_PROVEN)
    attempted_raw = sum(n for k, n in counts.items() if k in _ATTEMPTED)
    # A route withheld for safety is counted under ``blocked``: ADscan declined
    # to run it, so it is not an attempt.
    withheld = min(_int(bucket.get("safety_withheld")), attempted_raw)
    attempted = attempted_raw - withheld
    closed = sum(n for k, n in counts.items() if k in _CLOSED)
    known = _PROVEN | _ENTRY_PROVEN | _ATTEMPTED | _CLOSED
    not_executed = sum(n for k, n in counts.items() if k not in known) + withheld
    routes = proven + entry_proven + attempted + not_executed
    if bucket.get("exposure_total") is not None:
        # The headline figure. Not-assessed routes sit outside it but still
        # block a "held" claim through ``not_executed``.
        routes = max(_int(bucket.get("exposure_total")), proven + entry_proven + attempted)
    missing = tuple(str(p) for p in missing_phases if str(p or "").strip())

    # Split the unexecuted routes by reason: the operator decisions recorded on
    # their steps first, then the run-wide reason for the rest.
    remaining = not_executed + entry_proven
    by_reason: dict[str, int] = {}
    for reason in _STEP_NOTED_REASONS:
        n = min(_int((operator_decisions or {}).get(reason)), remaining)
        if n:
            by_reason[reason] = by_reason.get(reason, 0) + n
            remaining -= n
    if remaining:
        run_reason = str(not_executed_reason or "")
        if run_reason not in _SENTENCE_REASON:
            run_reason = NOT_EXECUTED_THIS_RUN
        by_reason[run_reason] = by_reason.get(run_reason, 0) + remaining
    causes = tuple((r, by_reason[r]) for r in _REASON_ORDER if by_reason.get(r))
    scope_domains = tuple(
        dict.fromkeys(
            str(d).strip().lower() for d in (outside_scope_domains or ()) if str(d or "").strip()
        )
    )

    def _make(kind: str) -> CompromiseVerdict:
        return CompromiseVerdict(
            kind=kind,
            routes=max(routes, not_executed + entry_proven if kind in UNEXECUTED_VERDICTS else 0),
            proven=proven,
            entry_proven=entry_proven,
            attempted=attempted,
            not_executed=not_executed,
            closed=closed,
            causes=causes,
            missing_phases=missing,
            outside_scope_domains=scope_domains,
            awaiting_wait_seconds=_int(awaiting_wait_seconds),
        )

    if domain_compromised or proven > 0:
        return _make(VERDICT_DOMAIN_COMPROMISED)
    if missing:
        return _make(VERDICT_ASSESSMENT_INCOMPLETE)
    if entry_proven + not_executed > 0:
        only_awaiting = [r for r, _n in causes] == [NOT_EXECUTED_AWAITING_OPERATOR]
        return _make(
            VERDICT_ROUTES_AWAITING_OPERATOR if only_awaiting else VERDICT_ROUTES_NOT_EXECUTED
        )
    if attempted + closed > 0:
        return _make(VERDICT_HELD)
    return _make(VERDICT_NO_ROUTE_FOUND)


def verdict_from_report_entry(
    entry: Mapping[str, Any] | None,
    *,
    domain_compromised: bool | None = None,
    missing_phases: Iterable[str] = (),
) -> CompromiseVerdict:
    """Return the verdict for one ``technical_report.json`` domain entry.

    Reads ``exposure_kpis`` (the ``domain_breaker`` bucket and the operator
    decision counts) and ``scan_policy_coverage``. ``domain_compromised``
    defaults to the entry's own ``auth == "pwned"`` marker.
    """
    entry = entry if isinstance(entry, Mapping) else {}
    return verdict_from_kpis(
        entry.get("exposure_kpis"),
        entry.get("scan_policy_coverage"),
        domain_compromised=(
            str(entry.get("auth") or "").strip().lower() == "pwned"
            if domain_compromised is None
            else bool(domain_compromised)
        ),
        missing_phases=missing_phases,
    )


def verdict_from_kpis(
    exposure_kpis: Mapping[str, Any] | None,
    scan_policy_coverage: Mapping[str, Any] | None,
    *,
    domain_compromised: bool = False,
    missing_phases: Iterable[str] = (),
) -> CompromiseVerdict:
    """The verdict from the two stamped blocks (the web's persisted shape)."""
    kpis = exposure_kpis if isinstance(exposure_kpis, Mapping) else {}
    path_axis = kpis.get("path_axis")
    bucket = path_axis.get("domain_breaker") if isinstance(path_axis, Mapping) else None
    decisions = kpis.get(OPERATOR_DECISION_ROUTES_KEY)
    scope_domains = kpis.get(OUTSIDE_SCOPE_DOMAINS_KEY)
    return derive_compromise_verdict(
        bucket,
        domain_compromised=domain_compromised,
        missing_phases=missing_phases,
        not_executed_reason=not_executed_reason_from_coverage(scan_policy_coverage),
        operator_decisions=decisions if isinstance(decisions, Mapping) else None,
        outside_scope_domains=scope_domains if isinstance(scope_domains, (list, tuple)) else (),
        awaiting_wait_seconds=_int(kpis.get(OPERATOR_AWAITING_WAIT_KEY)),
    )


def aggregate_awaiting_wait_seconds(verdicts: Iterable[CompromiseVerdict]) -> int:
    """The longest recorded approval wait across domains (0 when none timed out).

    Passed beside :func:`aggregate_reach_evidence`'s reason to the reach phrase,
    so a multi-domain document names the same cause the per-domain verdicts do.
    """
    longest = 0
    for verdict in verdicts:
        if isinstance(verdict, CompromiseVerdict):
            longest = max(longest, int(verdict.awaiting_wait_seconds or 0))
    return longest


def aggregate_reach_evidence(
    verdicts: Iterable[CompromiseVerdict],
) -> tuple[str | None, str]:
    """Return the strongest ``REACH_*`` across domains and the reason to name.

    A multi-domain document states one reach phrase. It may claim only what the
    strongest domain proves; the reason is the first, in statement order, that
    any domain's unexecuted routes carry. ``None`` evidence when no domain
    carries a stamped route to full domain compromise (an artifact without the
    KPI block): the caller then keeps its historical wording rather than
    asserting "not executed" off an absence of data.
    """
    best: str | None = None
    reasons: set[str] = set()
    for verdict in verdicts:
        if not isinstance(verdict, CompromiseVerdict) or verdict.routes <= 0:
            continue
        if best is None or _REACH_ORDER.index(verdict.reach_evidence) < _REACH_ORDER.index(best):
            best = verdict.reach_evidence
        reasons.update(r for r, n in verdict.causes if n)
    for reason in _REASON_ORDER:
        if reason in reasons:
            return best, reason
    return best, NOT_EXECUTED_THIS_RUN
