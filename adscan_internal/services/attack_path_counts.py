"""Named attack-path cardinalities — the SSOT for "how many attack paths".

The repo already has one canonical answer for the *status* of a path
(``attack_paths_core._derive_display_status_from_steps``), one for its *reach
label* (``compromise_class.compromise_reach_label_short``) and one for the
report's *path derivation* (``report_attack_paths.compute_report_attack_paths``).
It had none for the **cardinality** of a path set, and that gap was expensive:
one GOAD run answered "how many attack paths" with ``458``, ``33``, ``30``,
``22`` and ``0`` depending on which projection was asked, and two of those
numbers were printed to the operator seconds apart under interchangeable
wording — one of them a raw DFS walk enumeration described as "validated paths".

This module computes nothing new. It gives the concepts NAMES and one entry
point, so two quantities can never again be said to a human under the same
words:

* :attr:`ClientPathTotals.paths_total` — the curated client inventory. What the
  report means by "N identified attack paths".
* :attr:`ClientPathTotals.paths_open_exposure` — the subset that still describes
  exposure the client carries (``carries_client_exposure``). Excludes the
  positive hardening bucket and ADscan's own data gaps.
* :attr:`ClientPathTotals.paths_full_domain_compromise` — the ``domain_breaker``
  open-exposure count. The ONLY figure a "you have N routes to full domain
  compromise" headline may use.
* :attr:`ClientPathTotals.paths_proven` / :attr:`~ClientPathTotals.paths_partial`
  — the evidence split, through the ``_PROVEN_STATUSES`` SSOT (never a bare
  ``status == "exploited"`` literal).
* :attr:`ClientPathTotals.paths_closed_by_configuration` — the POSITIVE bucket.
  Counted, never presented as exposure.
* :attr:`ClientPathTotals.paths_not_assessed` — ADscan had no surface to walk
  the avenue. A data gap, never credited to the client as a defence.

**Rules this module exists to enforce** (locked by
``tests/unit/services/test_attack_path_counts.py``):

1. Every human-facing attack-path count and every telemetry path denominator
   comes from here.
2. A raw graph-walk enumeration is NOT a path count. It is combinatorial and
   depth-sensitive (the same graph yielded 123 walks at depth 3 and 458 at depth
   7 over ONE distinct target), it applies no status filter, and it terminates
   only on the domain object — so it over-counts by permutation and under-scopes
   by terminal at once. It is barred from panels, reports and published ratios.
3. Reach wording comes from :func:`compromise_reach_label_short`, never
   hand-written per surface.

Sourcing is cheap by design. The run-stamped ``exposure_kpis`` block in
``technical_report.json`` is preferred (~1 ms to read; it is written by the same
run, from the same derivation); the fall-back recomputes
``compute_report_attack_paths`` + ``compute_exposure_kpis``, which the report
has usually already warmed in-process. LITE-safe: no ``pro/`` imports.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.services.compromise_class import (
    CompromiseClass,
    compromise_reach_label_short,
)
from adscan_internal.services.exposure_score_service import (
    PATH_AXIS_NON_STATUS_KEYS,
    open_exposure_total,
    split_open_exposure,
)
from adscan_internal.services.path_state import NOT_ASSESSED_STATUSES
from adscan_internal.services.relay_status_constants import CONFIGURATION_CLOSE_STATUS

#: Compromise classes in descending reach order. The FIRST class in this tuple
#: with open exposure is the run's strongest proven-or-identified reach, which is
#: what a one-line digest names. Mirrors the canonical report order in
#: ``exposure_score_service._KPI_COMPROMISE_CLASSES``.
_REACH_ORDER: tuple[CompromiseClass, ...] = (
    CompromiseClass.DOMAIN_BREAKER,
    CompromiseClass.TIER0_FOOTHOLD,
    CompromiseClass.PRIVILEGED_ESCALATOR,
    CompromiseClass.COMPROMISE_ENABLER,
)


@dataclass(frozen=True)
class PathHeadline:
    """The one client-facing attack-path headline every surface renders.

    Built once by :meth:`ClientPathTotals.render_headline` so the CLI panel, the
    LITE/PRO report cards and the web CTEM say the SAME sentence. ``reachable``
    is the effective full-domain-compromise figure (k when materialization
    walked the graph, the reachable-set cardinality when the mega-hub fallback
    fired); ``proven`` is the end-to-end ``exploited`` count shown distinctly.
    ``label`` never reads "0" / "not compromised" when ``compromised`` is true.
    """

    proven: int
    reachable: int
    sampled: bool
    compromised: bool
    label: str


@dataclass(frozen=True)
class ClientPathTotals:
    """The cardinalities of one curated client attack-path set.

    Every field is a DIFFERENT question with a DIFFERENT answer, which is
    exactly why they are named rather than passed around as a bare int. The
    invariant that holds across all of them::

        paths_total >= paths_open_exposure >= paths_full_domain_compromise
        paths_open_exposure >= paths_proven + paths_partial

    ``paths_total`` is the inventory (it keeps the positive
    ``closed_by_configuration`` bucket visible); ``paths_open_exposure`` is the
    only one a client-facing risk figure may use.

    The ``reachable_*`` fields are a DIFFERENT quantity from the ``paths_*``
    ones: they are k-independent SET cardinalities (the number of DISTINCT
    reachable compromise terminals), not enumerated path counts. They are the
    EXPOSURE numbers — "how many distinct high-value targets can be reached" —
    distinct from the ``paths_*`` EVIDENCE numbers, which count validated/
    identified routes. They are populated whenever the run stamped a
    ``reachability`` block and default to 0 otherwise.
    """

    paths_total: int = 0
    paths_open_exposure: int = 0
    paths_full_domain_compromise: int = 0
    paths_proven: int = 0
    paths_partial: int = 0
    paths_closed_by_configuration: int = 0
    paths_not_assessed: int = 0
    #: Reachable-terminal SET cardinalities (k-independent EXPOSURE numbers).
    reachable_full_domain_compromise: int = 0
    reachable_tier0: int = 0
    reachable_domain_object: int = 0
    reachable_tier0_direct: int = 0
    reachable_tier0_enabler: int = 0
    #: Standard-user (enabled, non-Tier-0, non-synthetic) exposure ratio — how
    #: many real user accounts hold a reachable path to full domain compromise.
    #: k-INDEPENDENT (a reverse-reachability set cardinality), so it is the client
    #: exposure headline that survives the mega-hub sampled fallback. Distinct
    #: from the reachable_* PRINCIPAL count, whose denominator folds in machine
    #: accounts via ``Authenticated Users``. 0/0 when the block is absent.
    tier2_exposure_with_path: int = 0
    tier2_exposure_total: int = 0
    #: ``compromise_class`` -> open-exposure path count. Drives the reach label
    #: without any surface re-deriving the class ordering.
    open_exposure_by_class: Mapping[str, int] = field(default_factory=dict)
    #: Coverage mode of the run that produced these figures: ``"complete"`` when
    #: materialization walked the graph, ``"sampled"``/``"bounded"`` when the
    #: control-mega-hub fallback fired. Drives the effective figures below.
    coverage_mode: str = "complete"
    #: Proven full-domain-compromise count sourced from the persisted snapshot
    #: (k-independent), used when coverage is sampled and ``path_axis`` collapsed
    #: so the proven ``exploited`` count is not lost with the materialized set.
    proven_full_domain_compromise_override: int = 0

    def __bool__(self) -> bool:
        """Truthy when the run produced any curated path at all."""
        return self.paths_total > 0

    @property
    def strongest_reach_class(self) -> CompromiseClass | None:
        """Return the highest-reach class that still carries open exposure."""
        for cls in _REACH_ORDER:
            if int(self.open_exposure_by_class.get(cls.value, 0) or 0) > 0:
                return cls
        return None

    @property
    def strongest_reach_label(self) -> str:
        """Return the client label for :attr:`strongest_reach_class`.

        Sourced from :func:`compromise_reach_label_short` — the ONE reach
        vocabulary the PDF cards, the web KPI table and the CLI share. Empty
        string when nothing carries open exposure.
        """
        cls = self.strongest_reach_class
        return compromise_reach_label_short(cls) if cls is not None else ""

    @property
    def tier2_exposure_pct(self) -> float:
        """Share of standard user accounts with a reachable path to Tier 0."""
        if self.tier2_exposure_total <= 0:
            return 0.0
        return min(
            100.0,
            round(self.tier2_exposure_with_path / self.tier2_exposure_total * 100.0, 1),
        )

    @property
    def has_tier2_exposure(self) -> bool:
        """True when a standard-user exposure ratio is available to report."""
        return self.tier2_exposure_total > 0

    def render_tier2_exposure_headline(self) -> str | None:
        """Return the one client/operator standard-user exposure sentence.

        The exposure thesis as a ratio a CISO reads directly: of the domain's
        real, non-privileged user accounts, how many hold a reachable route to
        full domain compromise. Rendered from the SSOT so the CLI panel, the
        LITE/PRO reports and the web CTEM say the SAME sentence. ``None`` when no
        standard-user population is available (older/empty workspace), so a
        surface degrades rather than printing a zero it cannot stand behind.

        The magnitude is REACHABILITY (a route exists), not proven execution —
        the wording says "reachable", never "validated", per the
        Exposure-Validation doctrine.
        """
        if not self.has_tier2_exposure:
            return None
        pct = self.tier2_exposure_pct
        pct_text = f"{pct:g}"
        return (
            f"{pct_text}% of standard user accounts "
            f"({self.tier2_exposure_with_path:,} of {self.tier2_exposure_total:,}) "
            "hold a reachable path to full domain compromise"
        )

    @property
    def effective_reach_is_sampled(self) -> bool:
        """True when materialization fell back (``sampled``/``bounded`` coverage).

        In that mode ``path_axis`` (k) is empty by construction, so the client
        figures MUST come from the reachability set, not from k.
        """
        return self.coverage_mode != "complete"

    @property
    def effective_full_domain_compromise(self) -> int:
        """Routes to full domain compromise a client-facing headline may use.

        ``paths_full_domain_compromise`` (k) on a complete run — byte-identical
        to today — and the reachable-set cardinality when the mega-hub fallback
        collapsed k to 0. Never renders 0 on a domain that has reachable routes.
        """
        if self.effective_reach_is_sampled:
            return self.reachable_full_domain_compromise
        return self.paths_full_domain_compromise

    @property
    def effective_proven_full_domain_compromise(self) -> int:
        """The end-to-end ``exploited`` count, snapshot-sourced under fallback.

        Under sampled coverage ``path_axis`` is empty, so ``paths_proven`` is 0;
        the persisted snapshot's ``exploited`` count (the override) preserves the
        proven figure that k lost.
        """
        if (
            self.effective_reach_is_sampled
            and self.proven_full_domain_compromise_override > 0
        ):
            return self.proven_full_domain_compromise_override
        return self.paths_proven

    def render_headline(self, domain_compromised: bool) -> "PathHeadline":
        """Build the one shared client/operator attack-path headline.

        Every surface renders from this so proven-vs-reachable and the "never 0
        on a compromised domain" rule live in exactly one place.
        """
        reachable = self.effective_full_domain_compromise
        # Tie proven to the runtime compromise oracle: a stale snapshot can never
        # invent a proven route on a domain the current state says is not owned.
        proven = (
            self.effective_proven_full_domain_compromise if domain_compromised else 0
        )
        sampled = self.effective_reach_is_sampled
        suffix = " (sampled coverage)" if sampled else ""
        if domain_compromised:
            head = "full domain compromise proven"
            if proven > 0:
                head = f"{head} ({proven} route(s) validated end-to-end)"
            parts = [head]
            if reachable > 0:
                parts.append(f"{reachable} reachable route(s) to full domain compromise")
            label = "; ".join(parts) + suffix
        elif reachable > 0:
            label = f"{reachable} reachable route(s) to full domain compromise{suffix}"
        else:
            label = "no attack paths found"
        return PathHeadline(
            proven=proven,
            reachable=reachable,
            sampled=sampled,
            compromised=bool(domain_compromised),
            label=label,
        )

    def merged_with(self, other: "ClientPathTotals") -> "ClientPathTotals":
        """Return the sum of two domains' totals (for a multi-domain session)."""
        by_class: dict[str, int] = dict(self.open_exposure_by_class)
        for key, value in other.open_exposure_by_class.items():
            by_class[key] = by_class.get(key, 0) + int(value or 0)
        # A session is sampled if ANY of its domains fell back — the honest
        # headline for the whole session must not claim complete coverage.
        merged_modes = {self.coverage_mode, other.coverage_mode} - {"complete"}
        merged_mode = next(iter(merged_modes)) if merged_modes else "complete"
        return ClientPathTotals(
            paths_total=self.paths_total + other.paths_total,
            paths_open_exposure=self.paths_open_exposure + other.paths_open_exposure,
            paths_full_domain_compromise=(
                self.paths_full_domain_compromise + other.paths_full_domain_compromise
            ),
            paths_proven=self.paths_proven + other.paths_proven,
            paths_partial=self.paths_partial + other.paths_partial,
            paths_closed_by_configuration=(
                self.paths_closed_by_configuration + other.paths_closed_by_configuration
            ),
            paths_not_assessed=self.paths_not_assessed + other.paths_not_assessed,
            reachable_full_domain_compromise=(
                self.reachable_full_domain_compromise
                + other.reachable_full_domain_compromise
            ),
            reachable_tier0=self.reachable_tier0 + other.reachable_tier0,
            reachable_domain_object=(
                self.reachable_domain_object + other.reachable_domain_object
            ),
            reachable_tier0_direct=(
                self.reachable_tier0_direct + other.reachable_tier0_direct
            ),
            reachable_tier0_enabler=(
                self.reachable_tier0_enabler + other.reachable_tier0_enabler
            ),
            tier2_exposure_with_path=(
                self.tier2_exposure_with_path + other.tier2_exposure_with_path
            ),
            tier2_exposure_total=(
                self.tier2_exposure_total + other.tier2_exposure_total
            ),
            coverage_mode=merged_mode,
            proven_full_domain_compromise_override=(
                self.proven_full_domain_compromise_override
                + other.proven_full_domain_compromise_override
            ),
            open_exposure_by_class=by_class,
        )

    def telemetry_properties(self) -> dict[str, int]:
        """Return the path denominators for a telemetry event.

        One projection, named. An event that carries these alongside
        ``paths_total_analyzed`` (the convergence denominator, derived from the
        SAME curated set) can never again ship two mutually incomparable path
        denominators under adjacent names.
        """
        return {
            "paths_total": self.paths_total,
            "paths_open_exposure": self.paths_open_exposure,
            "paths_full_domain_compromise": self.paths_full_domain_compromise,
            "paths_proven": self.paths_proven,
            "paths_partial": self.paths_partial,
            "paths_closed_by_configuration": self.paths_closed_by_configuration,
            "paths_not_assessed": self.paths_not_assessed,
            "reachable_full_domain_compromise": self.reachable_full_domain_compromise,
            "reachable_tier0": self.reachable_tier0,
            "reachable_domain_object": self.reachable_domain_object,
            "reachable_tier0_direct": self.reachable_tier0_direct,
            "reachable_tier0_enabler": self.reachable_tier0_enabler,
        }


def _coerce_int(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def client_path_totals_from_kpis(
    exposure_kpis: Mapping[str, Any] | None,
    *,
    proven_override: int | None = None,
) -> ClientPathTotals:
    """Return the named totals from an ``exposure_kpis`` block. Pure.

    Reads the engine-stamped ``path_axis`` VERBATIM — the block written by
    :func:`~adscan_internal.services.exposure_score_service.compute_exposure_kpis`
    — so this never re-derives a status, a class or an exposure filter.

    Args:
        exposure_kpis: The ``domains[<domain>]["exposure_kpis"]`` block, or
            ``None``.

    Returns:
        The populated :class:`ClientPathTotals`, or an all-zero instance when the
        block is missing or malformed.
    """
    if not isinstance(exposure_kpis, Mapping):
        return ClientPathTotals()
    path_axis = exposure_kpis.get("path_axis")
    if not isinstance(path_axis, Mapping):
        return ClientPathTotals()

    reachability = exposure_kpis.get("reachability")
    reach = reachability if isinstance(reachability, Mapping) else {}

    tier2_raw = exposure_kpis.get("tier2_exposure")
    tier2 = tier2_raw if isinstance(tier2_raw, Mapping) else {}

    # Reconcile the standard-user population to ONE figure across every surface.
    # The tier2_exposure block is a reverse-reachability set cardinality whose
    # denominator can drift a handful of accounts above the ASSESSED non-Tier-0
    # (tier2) population the tiering breakdown records — the same population the
    # SAR and LITE report through ``derive_domain_user_reach``/
    # ``derive_ordinary_breaker_stat`` (its ``ordinary_total``). When that happens,
    # the Playbook/CLI/web (which read this block) print a bigger "N of M standard
    # user accounts" than the SAR/LITE, a cross-surface concordance defect. The
    # assessed population is authoritative, so cap the standard-user denominator
    # (and numerator) to it. Only fires on the over-count case, so a workspace
    # without a tiering breakdown, or one where the two already agree, is
    # byte-identical to before.
    tier2_with = _coerce_int(tier2.get("with_path"))
    tier2_total = _coerce_int(tier2.get("total"))
    _population = exposure_kpis.get("population_tier_breakdown")
    if isinstance(_population, Mapping):
        _assessed_tier2 = _coerce_int(_population.get("tier2"))
        if _assessed_tier2 > 0 and tier2_total > _assessed_tier2:
            tier2_total = _assessed_tier2
            tier2_with = min(tier2_with, _assessed_tier2)

    total = 0
    open_exposure = 0
    proven = 0
    partial = 0
    closed_by_configuration = 0
    not_assessed = 0
    by_class: dict[str, int] = {}

    for raw_class, bucket in path_axis.items():
        if not isinstance(bucket, Mapping):
            continue
        cls = str(raw_class or "").strip().lower()
        total += _coerce_int(bucket.get("total"))
        bucket_open = open_exposure_total(bucket)
        open_exposure += bucket_open
        by_class[cls] = bucket_open
        evidence = split_open_exposure(bucket)
        proven += evidence.proven
        partial += evidence.partial
        for token, count in bucket.items():
            if token in PATH_AXIS_NON_STATUS_KEYS:
                continue
            status = str(token or "").strip().lower()
            if status == CONFIGURATION_CLOSE_STATUS:
                closed_by_configuration += _coerce_int(count)
            elif status in NOT_ASSESSED_STATUSES:
                not_assessed += _coerce_int(count)

    # Coverage mode: prefer the engine-stamped flag; infer it when absent (older
    # workspace) from the k-collapsed-but-reachable signature. "sampled"/
    # "bounded" both mean the effective figures must read reachability, not k.
    reachable_fdc = _coerce_int(reach.get("full_domain_compromise"))
    declared_mode = exposure_kpis.get("coverage_mode")
    if isinstance(declared_mode, str) and declared_mode.strip():
        coverage_mode = declared_mode.strip().lower()
    else:
        coverage_mode = "sampled" if (total == 0 and reachable_fdc > 0) else "complete"

    return ClientPathTotals(
        paths_total=total,
        paths_open_exposure=open_exposure,
        paths_full_domain_compromise=by_class.get(
            CompromiseClass.DOMAIN_BREAKER.value, 0
        ),
        paths_proven=proven,
        paths_partial=partial,
        paths_closed_by_configuration=closed_by_configuration,
        paths_not_assessed=not_assessed,
        reachable_full_domain_compromise=_coerce_int(
            reach.get("full_domain_compromise")
        ),
        reachable_tier0=_coerce_int(reach.get("tier0_reachable")),
        reachable_domain_object=_coerce_int(reach.get("domain_object")),
        reachable_tier0_direct=_coerce_int(reach.get("tier0_direct")),
        reachable_tier0_enabler=_coerce_int(reach.get("tier0_enabler")),
        tier2_exposure_with_path=tier2_with,
        tier2_exposure_total=tier2_total,
        coverage_mode=coverage_mode,
        proven_full_domain_compromise_override=_coerce_int(proven_override),
        open_exposure_by_class=by_class,
    )


#: Snapshot path statuses that count as an END-TO-END proven route. Spans the
#: three status vocabularies' proven tokens (see CLAUDE.md § status vocabularies)
#: so a proven route keyed "domain_compromised" or "success" is not missed.
_SNAPSHOT_PROVEN_STATUSES = frozenset({"exploited", "domain_compromised", "success"})


def proven_full_domain_compromise_from_snapshot(
    snapshot: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None,
) -> int:
    """Count end-to-end proven routes to full domain compromise in a snapshot.

    Reads ``attack_paths_snapshot.json`` (a ``{"paths": [...]}`` mapping or the
    bare path list) and counts ``domain_breaker`` paths whose status is proven.
    This is k-INDEPENDENT: it survives the control-mega-hub fallback that empties
    ``path_axis``, so it preserves the proven figure the report cards would
    otherwise lose with the materialized set. Pure; 0 for a missing snapshot.
    """
    if isinstance(snapshot, Mapping):
        paths: Any = snapshot.get("paths")
    else:
        paths = snapshot
    if not isinstance(paths, Sequence) or isinstance(paths, (str, bytes)):
        return 0
    count = 0
    for path in paths:
        if not isinstance(path, Mapping):
            continue
        status = str(path.get("status") or "").strip().lower()
        cls = str(path.get("compromise_class") or "").strip().lower()
        if cls == CompromiseClass.DOMAIN_BREAKER.value:
            if status in _SNAPSHOT_PROVEN_STATUSES:
                count += 1
    return count


def proven_full_domain_compromise_from_executions(
    executions: Sequence[Mapping[str, Any]] | None,
) -> int:
    """Count distinct proven full-domain-compromise routes from execution rows.

    Reads the RUNTIME execution sidecar (``domains/<domain>/post_ex/
    path_executions.json`` via ``load_executions``): the record of attacks that
    actually ran, independent of the theoretical-path snapshot. Counts distinct
    ``attack_path_id`` whose recorded ``path_state`` reached
    ``domain_compromised``. This is the PREFERRED proven source (a run fact, not
    a projection); the snapshot is the fallback when the sidecar is absent. Pure.
    """
    if not isinstance(executions, Sequence) or isinstance(executions, (str, bytes)):
        return 0
    proven_paths: set[str] = set()
    for row in executions:
        if not isinstance(row, Mapping):
            continue
        state = str(row.get("path_state") or "").strip().lower()
        ap_id = str(row.get("attack_path_id") or "").strip()
        if ap_id and state == "domain_compromised":
            proven_paths.add(ap_id)
    return len(proven_paths)


def client_path_totals_for_domain(
    exposure_kpis: Mapping[str, Any] | None,
    *,
    snapshot: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
    executions: Sequence[Mapping[str, Any]] | None = None,
) -> ClientPathTotals:
    """SSOT entry point: combine ``exposure_kpis`` with the proven-route sources.

    ``exposure_kpis`` supplies the k / reachability figures (both RUNTIME).
    ``executions`` (the preferred, runtime execution sidecar) and ``snapshot``
    (the fallback) each supply a k-independent proven full-domain-compromise
    count that survives the mega-hub fallback which empties ``path_axis``; the
    higher of the available sources is used, so a run still reports "N proven"
    alongside the reachable routes. The proven figure is only ASSERTED by
    :meth:`ClientPathTotals.render_headline` when the caller's compromise oracle
    (``auth == "pwned"``) agrees, so neither a stale snapshot nor a stale sidecar
    can ever claim a proven route on a domain the current state says is not owned.
    Every client- and operator-facing surface calls THIS, so the proven-vs-
    reachable resolution lives in exactly one place.
    """
    candidates: list[int] = []
    if executions is not None:
        candidates.append(proven_full_domain_compromise_from_executions(executions))
    if snapshot is not None:
        candidates.append(proven_full_domain_compromise_from_snapshot(snapshot))
    proven_override = max(candidates) if candidates else None
    return client_path_totals_from_kpis(exposure_kpis, proven_override=proven_override)


def client_path_totals_from_paths(
    paths: Sequence[Mapping[str, Any]],
    *,
    executions: Sequence[Mapping[str, Any]] | None = None,
    reachability: Mapping[str, int] | None = None,
) -> ClientPathTotals:
    """Return the named totals for an already-computed path set. Pure.

    Args:
        paths: Curated attack-path summaries, as produced by
            :func:`~adscan_internal.services.report_attack_paths.compute_report_attack_paths`.
        executions: Optional path-execution sidecar rows, so a path's status is
            its executed :class:`PathState` rather than the LDAP-derived display
            status — the same reconciliation the report applies.
        reachability: Optional reachable-terminal summary (from
            :func:`~adscan_internal.services.attack_reachability.summarize_reachable_terminals`).
            When supplied it populates the ``reachable_*`` EXPOSURE fields;
            ``None`` leaves the block absent and those fields default to 0.
    """
    from adscan_internal.services.exposure_score_service import compute_exposure_kpis

    kpis = compute_exposure_kpis(
        list(paths),
        # The path axis does not depend on the user denominator; only the
        # user-axis percentages do, and this module reads neither.
        domain_user_count=None,
        executions=list(executions) if executions else None,
        reachability=reachability,
    )
    return client_path_totals_from_kpis(kpis)


def iter_distinct_hardening_avenues(
    raw_paths: Sequence[Mapping[str, Any]] | None,
) -> list[tuple[str, str]]:
    """Distinct closed-by-config AVENUES in the raw path set, in first-seen order.

    An "avenue" is a way an attacker would have relayed or escalated that the
    client's own configuration or topology closes with certainty. Several attack
    PATHS can traverse ONE avenue (e.g. two chains that both start with the same
    relay), so the closed-by-config PATH count over-states how much hardening the
    reader intuits. This collapses that: each closed-by-config path contributes
    its ``(relation, observed-reason)`` pair, deduplicated so N identical closes
    read as one avenue.

    This is the cross-tier SSOT for the "attack surface reduced / hardening
    observed" HEADLINE unit, so the free LITE report and the paid PRO deliverable
    lead with the SAME number and a client never sees the paid report appear to
    have "found more" hardening (dual-tier doctrine: the two must never disagree
    on a number). The identity is read off the same on-disk fields both tiers
    already carry — the closing step's ``details.blocked_reason`` (the engine
    spreads the edge ``notes`` into the step ``details``) and the step's own
    ``action``/``relation`` — so no tier re-derives it.

    Returns:
        The list of distinct ``(relation, blocked_reason)`` pairs (raw, so each
        tier can word its own client-safe prose from them). Non-closed paths and
        malformed records are ignored. Empty when nothing was closed by config.
    """
    avenues: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path in raw_paths or []:
        if not isinstance(path, Mapping):
            continue
        if str(path.get("status") or "").strip().lower() != "closed_by_configuration":
            continue
        reason = ""
        relation = ""
        steps = path.get("steps")
        for step in steps if isinstance(steps, Sequence) else []:
            if not isinstance(step, Mapping):
                continue
            if (
                str(step.get("status") or "").strip().lower()
                != "closed_by_configuration"
            ):
                continue
            details = step.get("details")
            details = details if isinstance(details, Mapping) else {}
            reason = str(details.get("blocked_reason") or "").strip()
            relation = str(step.get("action") or step.get("relation") or "").strip()
            if reason:
                break
        if not relation:
            relations = path.get("relations")
            if isinstance(relations, Sequence) and not isinstance(relations, str):
                relation = str(relations[0] or "").strip() if relations else ""
        # Case-fold the relation so two records that differ only in casing on the
        # BloodHound edge token are one avenue; the reason is the observed
        # configuration sentence and is compared verbatim.
        key = (relation.lower(), reason)
        if key in seen:
            continue
        seen.add(key)
        avenues.append((relation, reason))
    return avenues


def count_distinct_hardening_avenues(
    raw_paths: Sequence[Mapping[str, Any]] | None,
) -> int:
    """Number of distinct closed-by-config avenues — the shared hardening headline.

    Thin cardinality wrapper over :func:`iter_distinct_hardening_avenues`; see it
    for the definition of an "avenue" and why this is the cross-tier headline unit.
    """
    return len(iter_distinct_hardening_avenues(raw_paths))


def _stamped_exposure_kpis(workspace_dir: str, domain: str) -> Mapping[str, Any] | None:
    """Return the run-stamped ``exposure_kpis`` block, or ``None``.

    The block is written by the same run that produced the report, from the same
    derivation, so reading it is both cheaper than recomputing and guaranteed to
    match what the client's document states.
    """
    try:
        from adscan_internal.workspaces import read_json_file

        report_path = os.path.join(workspace_dir, "technical_report.json")
        if not os.path.exists(report_path):
            return None
        report = read_json_file(report_path)
        domains = report.get("domains") if isinstance(report, dict) else None
        entry = domains.get(domain) if isinstance(domains, dict) else None
        kpis = entry.get("exposure_kpis") if isinstance(entry, dict) else None
        return kpis if isinstance(kpis, Mapping) else None
    except Exception:  # noqa: BLE001 - a missing or unreadable artifact just means "recompute"
        return None


def client_path_totals(workspace_dir: str, domain: str) -> ClientPathTotals:
    """Return the named totals for one domain in one workspace.

    Prefers the run-stamped ``exposure_kpis`` block; recomputes the canonical
    report projection when it is absent (an older artifact, or a run whose
    report has not been written yet). Best-effort by construction: any failure
    yields an all-zero instance rather than raising, because every consumer is a
    panel, a summary or a telemetry event that must never break a scan.

    Args:
        workspace_dir: Workspace root. For a LIVE scan this is the execution
            (``.run_*``) workspace — the directory the scan is writing into.
        domain: The domain whose paths are counted.
    """
    if not workspace_dir or not str(domain or "").strip():
        return ClientPathTotals()
    domain_name = str(domain).strip()

    stamped = _stamped_exposure_kpis(workspace_dir, domain_name)
    if stamped is not None:
        totals = client_path_totals_from_kpis(stamped)
        if totals.paths_total > 0:
            return totals

    try:
        from adscan_internal.services.post_exploitation.path_promotion import (
            load_executions,
        )
        from adscan_internal.services.report_attack_paths import (
            compute_report_attack_paths,
        )

        paths = compute_report_attack_paths(workspace_dir, domain_name)
        if not paths:
            return ClientPathTotals()
        executions = None
        try:
            from types import SimpleNamespace

            executions = load_executions(
                SimpleNamespace(
                    current_workspace_dir=str(workspace_dir), domains_dir="domains"
                ),
                domain_name,
            )
        except Exception:  # noqa: BLE001 - no sidecar just means "display status"
            executions = None
        return client_path_totals_from_paths(paths, executions=executions or None)
    except Exception as exc:  # noqa: BLE001 - counts never break a scan
        print_exception(exception=exc)
        print_info_debug(f"[path-counts] totals unavailable for {domain_name}: {exc}")
        return ClientPathTotals()


def resolve_scan_workspace_dir(shell: Any) -> str:
    """Return the workspace root whose artifacts belong to THIS scan.

    A live scan writes into its execution (``.run_*``) workspace, which is what
    ``current_workspace_dir`` points at while the scan runs — so this resolves
    the same directory the report generator reads.
    """
    getter = getattr(shell, "_get_workspace_cwd", None)
    if callable(getter):
        try:
            resolved = getter()
        except Exception:  # noqa: BLE001
            resolved = None
        if isinstance(resolved, str) and resolved:
            return resolved
    workspace_dir = getattr(shell, "current_workspace_dir", None)
    return workspace_dir if isinstance(workspace_dir, str) and workspace_dir else ""


def client_path_totals_for_shell(shell: Any, domain: str) -> ClientPathTotals:
    """Return the named totals for one domain, resolved from a live shell."""
    return client_path_totals(resolve_scan_workspace_dir(shell), domain)


def client_path_totals_for_session(
    shell: Any, *, domains: Sequence[str] | None = None
) -> ClientPathTotals:
    """Return the named totals summed across a session's domains.

    Args:
        shell: The active shell (workspace context only).
        domains: Restrict to these domains; ``None`` counts every domain the
            session loaded.
    """
    workspace_dir = resolve_scan_workspace_dir(shell)
    if not workspace_dir:
        return ClientPathTotals()

    if domains is None:
        loaded = getattr(shell, "domains_data", None)
        names = list(loaded.keys()) if isinstance(loaded, dict) else []
    else:
        names = list(domains)

    from adscan_internal.services.attack_step_domain_resolution import (
        is_placeholder_domain,
    )

    totals = ClientPathTotals()
    for name in names:
        domain_name = str(name or "").strip()
        if not domain_name:
            continue
        # Skip the synthetic ``wellknown`` placeholder: well-known / global
        # principals carry it, but there is no ``domains/wellknown/*.json`` to
        # read and no real graph to compute — iterating it only wastes a full
        # per-domain compute and logs "enabled users file missing for wellknown".
        if is_placeholder_domain(domain_name):
            continue
        totals = totals.merged_with(client_path_totals(workspace_dir, domain_name))
    return totals


__all__ = [
    "ClientPathTotals",
    "client_path_totals",
    "client_path_totals_for_session",
    "client_path_totals_for_shell",
    "client_path_totals_from_kpis",
    "client_path_totals_from_paths",
    "resolve_scan_workspace_dir",
]
