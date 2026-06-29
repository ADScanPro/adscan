"""AD Exposure Score — the single, defensible headline metric.

Computes a 0–100% **AD Exposure Score** quantifying how exposed an Active
Directory is to **full domain compromise (Tier 0 / Domain Admin) starting from
a low-privilege foothold**, plus a **Proven Exposure** sub-number (the "we
actually demonstrated it" figure) and a per-compromise-class breakdown for
explainability.

This is the *single source of truth* (spec
``docs/specs/exposure-score-spec.md``): the CLI report, the
``technical_report.json`` export, and (later) ``adscan_web`` all consume
:func:`compute_exposure_score` — the logic is NEVER re-implemented downstream.

It is a **scoring/aggregation layer over already-computed data** — it does NOT
recompute attack paths. The caller passes the attack-path summaries already
produced by
``attack_graph_service.get_attack_path_summaries(scope=…, target="highvalue",
target_mode="tier0")``; this module only weights and aggregates them.

Model (v1) — union-saturating exposure:

    w(p)      = proof_weight(status) * ease_weight(hops)
    exposure  = 1 - Π_p (1 - w(p))           over all included S→Tier-0 paths

Properties (acceptance criteria, see spec §5):

* ``0%`` iff there is no supported path (proven or theoretical) from the
  low-priv start set to any Tier-0 target (empty product → ``1 - 1 = 0``).
* A single PROVEN path → ``w = 1`` → ``100%`` (honest AEV: demonstrated).
* Theoretical-only paths saturate below 100%; multiplicity adds but saturates.
* ``Proven Exposure ≤ Total Exposure`` always; theoretical is never counted as
  proven.

The spec assumed ``compromise_effort`` / ``confidence`` were emitted per path;
in practice they are ``None`` on the records, so the model relies on the fields
that ARE reliably present (``status`` for proof, ``length`` for ease,
``compromise_class`` for the breakdown) and degrades gracefully if the optional
ones ever appear (``compromise_effort`` would refine ``ease_weight``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from adscan_internal.services.path_state import PathState

# --------------------------------------------------------------------------- #
# Tunables — the weights/shape are the only thing to tune; the union form and
# the acceptance properties above must NOT change.
# --------------------------------------------------------------------------- #

#: Proof weight by rolled-up path status. ``None`` => exclude the path entirely
#: (an unsupported/unavailable path contributes nothing to exposure). Covers
#: BOTH the edge-status vocabulary (theoretical/attempted/success/blocked/…)
#: and the executed PathState vocabulary (domain_compromised/foothold_obtained/…).
_PROOF_WEIGHT: dict[str, float | None] = {
    # Proven domain compromise — we demonstrably reached the Tier-0 target.
    "success": 1.0,
    "exploited": 1.0,
    "domain_compromised": 1.0,
    # Executed and on the way, reality demonstrated but not full domain yet.
    "foothold_obtained": 0.6,
    "post_ex_in_progress": 0.6,
    # Attempted but did not land (tried against the real DC, no compromise).
    "attempted": 0.6,
    "failed": 0.6,
    "error": 0.6,
    "post_ex_failed": 0.6,
    # Supported but never executed — LDAP-derived theoretical path.
    "theoretical": 0.4,
    "discovered": 0.4,
    # A control actively stopped this path (still a residual signal, not zero).
    "blocked": 0.1,
    # Not runnable / no reachable surface — excluded from the score.
    "unsupported": None,
    "unavailable": None,
}

#: Statuses that count as PROVEN domain compromise for the Proven Exposure
#: number. Strict on purpose: only a demonstrably-reached Tier-0 target counts,
#: so a failed post-ex is NOT presented as proven (honesty acceptance crit. §5.4).
_PROVEN_STATUSES: frozenset[str] = frozenset(
    {"success", "exploited", "domain_compromised"}
)

#: ease_weight(hops) = 1 / (1 + EASE_ALPHA * (hops - 1)). A 1-hop path scores
#: 1.0 (maximally exposing); longer chains decay. α=0.25 → 2-hop 0.80,
#: 3-hop 0.67, 5-hop 0.50, 9-hop 0.33.
EASE_ALPHA: float = 0.25

#: Compromise classes that constitute reaching domain compromise (Tier-0). A
#: path whose terminal is one of these counts toward exposure; enabler/pivot
#: terminals do not (they are not domain compromise on their own).
_TIER0_COMPROMISE_CLASSES: frozenset[str] = frozenset(
    {"domain_breaker", "tier0_foothold"}
)

#: Canonical, single-source-of-truth mapping from the engine's per-path
#: ``compromise_class`` to the three report exposure tiers (the report renderer
#: AND any exposure logic MUST import this — never re-derive the split):
#:
#: * ``domain_breaker``        → ``"T1"`` — Full domain compromise. The path
#:   proves (or theoretically reaches) total control of the domain. This
#:   intentionally folds together paths that end at the domain object via
#:   DCSync AND paths that end at DOMAIN ADMINS but stopped at the depth cap:
#:   both ARE full domain compromise; the ``domain_compromise_tier`` 3-vs-4
#:   difference there is a depth-cap artifact, not a risk difference.
#: * ``tier0_foothold``        → ``"T2"`` — Tier-0 host foothold. Access to a
#:   Tier-0 HOST (e.g. CanRDP to a DC) where post-exploitation is still
#:   required; takeover is NOT yet proven.
#: * ``privileged_escalator``  → ``"T3"`` — Privilege-escalation enabler.
#:   Reaches a privileged asset (e.g. an issuance-policy group via ESC13, or a
#:   server via LSA dump) but does not constitute domain takeover on its own.
#:
#: Any other / unknown class maps to ``None`` and is NOT counted in these three
#: tiers (it is neither domain compromise nor a tracked enabler tier here).
_COMPROMISE_CLASS_TO_REPORT_TIER: dict[str, str] = {
    "domain_breaker": "T1",
    "tier0_foothold": "T2",
    "privileged_escalator": "T3",
}

#: Legacy fallback ONLY — for records that predate ``compromise_class`` stamping
#: and carry just an ``outcome_class``. Mirrors the fallback already used by
#: :func:`_is_tier0_target`. Current engine records always carry
#: ``compromise_class``, so this is never consulted for live scans; it keeps the
#: predicate correct for legacy/synthetic records (and report fixtures).
_OUTCOME_CLASS_TO_REPORT_TIER: dict[str, str] = {
    "direct_domain_control": "T1",
    "direct_compromise": "T1",
    "tier0_foothold": "T2",
    "domain_compromise_enabler": "T3",
    "followup_terminal": "T3",
    "high_impact_privilege": "T3",
}


def report_tier_for_class(compromise_class: str | None) -> str | None:
    """Map a path ``compromise_class`` to its report tier (``T1``/``T2``/``T3``).

    This is the single source of truth for the report's 3-tier exposure
    breakdown. Returns ``None`` for any class outside the three tracked tiers
    (e.g. ``compromise_enabler``, ``unauthenticated_principal``, ``""``), so
    callers can count only the three canonical tiers.

    Args:
        compromise_class: The engine's per-path ``compromise_class`` value.

    Returns:
        ``"T1"`` (full domain compromise), ``"T2"`` (Tier-0 host foothold),
        ``"T3"`` (privilege-escalation enabler), or ``None`` if not tracked.
    """
    return _COMPROMISE_CLASS_TO_REPORT_TIER.get(
        (compromise_class or "").strip().lower()
    )


def report_tier_for_record(record: Mapping[str, Any]) -> str | None:
    """Resolve the report tier for a single attack-path record.

    Prefers the canonical ``compromise_class``; falls back to ``outcome_class``
    only when the class is absent (legacy/synthetic records). This is the
    record-level single source of truth used by the report renderer and
    :func:`count_report_tiers`.

    Args:
        record: An attack-path record mapping.

    Returns:
        ``"T1"`` / ``"T2"`` / ``"T3"`` or ``None`` when untracked.
    """
    tier = report_tier_for_class(record.get("compromise_class"))
    if tier is not None:
        return tier
    return _OUTCOME_CLASS_TO_REPORT_TIER.get(
        str(record.get("outcome_class") or "").strip().lower()
    )


def count_report_tiers(
    records: Sequence[Mapping[str, Any]],
) -> dict[str, int]:
    """Tally attack-path records into the three canonical report tiers.

    Reads each record's ``compromise_class`` and routes it through
    :func:`report_tier_for_class`. Records whose class is outside the three
    tracked tiers are ignored (not counted in any bucket).

    Args:
        records: Attack-path records, each a mapping carrying
            ``compromise_class`` (as produced by ``get_attack_path_summaries``
            and threaded onto the report path dicts).

    Returns:
        ``{"T1": <full domain compromise>, "T2": <Tier-0 footholds>,
        "T3": <privilege-escalation enablers>}``.
    """
    counts = {"T1": 0, "T2": 0, "T3": 0}
    for record in records:
        if not isinstance(record, Mapping):
            continue
        tier = report_tier_for_record(record)
        if tier is not None:
            counts[tier] += 1
    return counts


# --------------------------------------------------------------------------- #
# Exposure KPIs - path-axis + user-axis (blast-radius) aggregation
# --------------------------------------------------------------------------- #

#: Compromise classes the KPI engine tracks, in the canonical report order. Any
#: path whose class is outside this set contributes to NO axis (it is neither a
#: tracked terminal nor an enabler tier here).
_KPI_COMPROMISE_CLASSES: tuple[str, ...] = (
    "domain_breaker",
    "tier0_foothold",
    "privileged_escalator",
    "compromise_enabler",
)

#: ``affected_users_source`` markers that mean the user set is a BROAD-GROUP
#: all-users expansion (Domain Users / Authenticated Users / Everyone -> every
#: domain user), as emitted by ``_classify_broad_group_scope`` /
#: ``fallback_domain_users_source`` in ``attack_graph_service``. When any
#: contributing path carries one of these, the (class, status) user count is the
#: WHOLE domain (``all_users=True``, ``pct_of_domain`` saturates at 100).
_BROAD_GROUP_USER_SOURCES: frozenset[str] = frozenset(
    {"enabled_users", "users", "snapshot"}
)

#: Cap on the per-class ``affected_accounts`` drill-down list serialized into
#: ``technical_report.json``. The aggregate ``count`` is always exact; the
#: explicit account list is bounded so a 100k-user domain does not bloat the
#: artifact. When the deduped set exceeds this, the list is truncated (sorted,
#: stable prefix) and ``affected_accounts_truncated`` is set so consumers know
#: to fall back to ``count`` for the full magnitude.
_MAX_AFFECTED_ACCOUNTS: int = 500

#: The fine Privilege-Tier values the per-account drill-down map may carry — the
#: engine SSOT ``PrivilegeTier`` ``.value`` strings (the two Tier-0 sub-tiers
#: kept distinct so the badge can render directness). Any other value is dropped
#: defensively; an account absent from the map falls back to Tier 2 (no badge),
#: which is the artifact's Tier-2 convention.
_AFFECTED_FINE_TIER_VALUES: frozenset[str] = frozenset(
    {"tier0_direct", "tier0_escalation_capable", "tier1", "tier2"}
)


def _serialize_affected_accounts(users: set[str]) -> tuple[list[str], bool]:
    """Return ``(sorted_capped_account_list, truncated)`` for the drill-down.

    The set holds normalized (realm-stripped, lower-cased) sAMAccountNames — the
    stable identifier the web resolves to a ``/assets`` user. Sorted for a
    deterministic artifact; capped at :data:`_MAX_AFFECTED_ACCOUNTS`.
    """
    ordered = sorted(users)
    if len(ordered) > _MAX_AFFECTED_ACCOUNTS:
        return ordered[:_MAX_AFFECTED_ACCOUNTS], True
    return ordered, False


def _serialize_affected_accounts_detail(
    accounts: list[str],
    tier_map: Mapping[str, str],
) -> list[dict[str, str]]:
    """Pair each (already sorted + capped) account with its fine Privilege Tier.

    ``accounts`` is the output of :func:`_serialize_affected_accounts` (sorted,
    deduped, capped), so the detail list aligns 1:1 with ``affected_accounts``
    and inherits the same cap. The tier comes verbatim from ``tier_map`` (the
    engine SSOT classification that produced ``tier_breakdown``); an account the
    map does not cover defaults to ``"tier2"`` (the no-badge Standard convention),
    so the per-account tiers always fold back onto ``tier_breakdown``.
    """
    return [
        {"sam": account, "tier": tier_map.get(account, "tier2")}
        for account in accounts
    ]


#: Canonical reconciliation of any sidecar ``path_state`` value (which may use
#: the legacy ``execution_failed`` token) onto the canonical :class:`PathState`
#: vocabulary used as KPI status keys.
_SIDECAR_STATE_TO_PATH_STATE: dict[str, str] = {
    "execution_failed": PathState.POST_EX_FAILED.value,
}


def _normalize_user(value: Any) -> str:
    """Return a case-folded, realm-stripped user key for cross-path dedupe.

    A principal can appear on two contributing paths as both its UPN
    (``jorah.mormont@essos.local``) and its sAMAccountName
    (``jorah.mormont``). Without canonicalisation those two spellings are
    distinct set members and the SAME user is counted twice, inflating the
    user-axis numerator (observed on Essos-Demo: 6 distinct humans reported as
    10). Strip the ``@realm`` suffix so both spellings collapse to one key.
    Empty / non-string values yield ``""`` (skipped by the caller).
    """
    if not isinstance(value, str):
        return ""
    key = value.strip().lower()
    if "@" in key:
        # UPN form ``user@realm`` -> ``user``. A leading-``@`` oddity (no local
        # part) keeps the original so we never produce an empty key from junk.
        local = key.split("@", 1)[0]
        if local:
            key = local
    return key


def _record_affected_users(
    record: Mapping[str, Any],
) -> tuple[set[str], bool, dict[str, int], dict[str, str]]:
    """Return ``(normalized_user_set, is_broad, tier_breakdown, tier_map)``.

    Reads ``meta.affected_users`` (the resolved per-path principal set, already
    broad-group-expanded by ``attack_graph_service``).

    The broad-group "all enabled domain users" decision flows from the EXPLICIT
    boolean ``meta.affected_users_all_enabled`` the materializer stamps from the
    ``is_broad_group_scope`` it already computed (the robust contract). The
    legacy ``affected_users_source`` string allowlist is consulted only as a
    backward-compatible fallback for artifacts written before the boolean
    existed — it had drifted out of sync with the resolver's real source tokens
    (``group_resolver`` / ``snapshot_group_members`` / ``principal``), which is
    exactly the undercount this fix removes.

    ``tier_breakdown`` is the per-record ``meta.affected_users_tier_breakdown``
    (``{"tier0": n, "tier1": n, "tier2": n}``) when present, else ``{}``.

    ``tier_map`` is the per-account fine Privilege-Tier map
    (``meta.affected_users_tier_map``: normalised sAMAccountName -> fine tier
    value ``"tier0_direct"`` / ``"tier0_escalation_capable"`` / ``"tier1"`` /
    ``"tier2"``) when present, else ``{}``. Keys are re-normalised through
    :func:`_normalize_user` so they match the ``affected_accounts`` set exactly.
    """
    meta = record.get("meta")
    if not isinstance(meta, Mapping):
        return set(), False, {}, {}
    users = {
        norm
        for raw in (meta.get("affected_users") or [])
        if (norm := _normalize_user(raw))
    }
    all_enabled_flag = meta.get("affected_users_all_enabled")
    if isinstance(all_enabled_flag, bool):
        is_broad = all_enabled_flag
    else:
        # Legacy artifact (no explicit boolean): fall back to the source string.
        source = str(meta.get("affected_users_source") or "").strip().lower()
        is_broad = source in _BROAD_GROUP_USER_SOURCES
    raw_breakdown = meta.get("affected_users_tier_breakdown")
    breakdown: dict[str, int] = {}
    if isinstance(raw_breakdown, Mapping):
        for bucket in ("tier0", "tier1", "tier2"):
            value = raw_breakdown.get(bucket)
            if isinstance(value, int) and value >= 0:
                breakdown[bucket] = value
    raw_tier_map = meta.get("affected_users_tier_map")
    tier_map: dict[str, str] = {}
    if isinstance(raw_tier_map, Mapping):
        for raw_user, raw_tier in raw_tier_map.items():
            norm = _normalize_user(raw_user)
            tier = str(raw_tier or "").strip().lower()
            if norm and tier in _AFFECTED_FINE_TIER_VALUES:
                tier_map[norm] = tier
    return users, is_broad, breakdown, tier_map


def _reconcile_status(record: Mapping[str, Any], has_execution: bool) -> str:
    """Return the single canonical status for a path.

    PathState from a post-exploitation execution wins over the display
    ``status`` whenever a real execution row exists for the path; otherwise the
    LDAP-derived display ``status`` stands. Sidecar ``execution_failed`` is
    folded onto the canonical ``post_ex_failed`` token.
    """
    if has_execution:
        state = str(record.get("path_state") or "").strip().lower()
        state = _SIDECAR_STATE_TO_PATH_STATE.get(state, state)
        if state:
            return state
    return str(record.get("status") or "theoretical").strip().lower()


def compute_exposure_kpis(
    summaries: Sequence[Mapping[str, Any]],
    *,
    domain_user_count: int | None,
    executions: Sequence[Mapping[str, Any]] | None = None,
    computed_at: str | None = None,
) -> dict[str, Any]:
    """Compute the exposure KPI block (path-axis + user-axis blast radius).

    Single source of truth feeding BOTH the PDF report and (phase 3) the web
    dashboard. It is a pure aggregation over already-computed attack-path
    summaries - it never recomputes paths. The user-axis is the blast-radius
    spine: per ``(compromise_class, status)`` it reports how many DISTINCT
    domain users can reach that terminal, deduped across every contributing
    path (a user reachable by two paths counts once).

    Args:
        summaries: Attack-path summary records (as produced by
            ``get_attack_path_summaries``), each carrying ``compromise_class``,
            ``status``, ``length`` and ``meta.affected_users[]`` /
            ``meta.affected_users_source``.
        domain_user_count: Total enabled domain users (for ``pct_of_domain``).
            ``None`` or ``<=0`` disables the percentage (reported as ``0.0``).
        executions: Optional raw path-execution sidecar rows. When supplied, a
            path's reconciled status is its executed :class:`PathState` (via the
            canonical :func:`enrich_paths_with_executions` merge) instead of the
            display ``status``.
        computed_at: Provenance timestamp (ISO-8601). Pure / deterministic - the
            caller passes it; this function NEVER calls ``datetime.now``.

    Returns:
        The ``exposure_kpis`` dict persisted verbatim under
        ``domains[<domain>]["exposure_kpis"]`` (schema_version 1).
    """
    user_total = (
        int(domain_user_count)
        if isinstance(domain_user_count, int) and domain_user_count > 0
        else 0
    )

    # Reconcile a single status per path. When executions are supplied, fold the
    # executed PathState in via the canonical SSOT merge so the status reflects
    # reality (foothold_obtained / domain_compromised / post_ex_failed) rather
    # than the LDAP-derived display status.
    records: list[Mapping[str, Any]] = [r for r in summaries if isinstance(r, Mapping)]
    has_exec_by_index: list[bool] = [False] * len(records)
    if executions:
        try:
            from adscan_internal.services.post_exploitation.path_promotion import (  # noqa: PLC0415
                enrich_paths_with_executions,
            )

            merged = enrich_paths_with_executions(
                [dict(r) for r in records], list(executions)
            )
            # `enrich_paths_with_executions` sets the "executions" key ONLY when a
            # real run touched the path; that is our "has_execution" signal.
            records = merged
            has_exec_by_index = [bool(r.get("executions")) for r in merged]
        except Exception:  # noqa: BLE001 - pure aggregator never breaks the report
            records = [r for r in summaries if isinstance(r, Mapping)]
            has_exec_by_index = [False] * len(records)

    # path_axis[class][status] = count ; path_axis[class]["total"] = all in class.
    path_axis: dict[str, dict[str, int]] = {cls: {} for cls in _KPI_COMPROMISE_CLASSES}
    # user_axis accumulators: per (class, status) -> (user_set, all_users_flag);
    # per class -> (any_user_set, any_all_users_flag, distinct_path_count).
    per_status_users: dict[str, dict[str, set[str]]] = {
        cls: {} for cls in _KPI_COMPROMISE_CLASSES
    }
    per_status_all_users: dict[str, dict[str, bool]] = {
        cls: {} for cls in _KPI_COMPROMISE_CLASSES
    }
    any_users: dict[str, set[str]] = {cls: set() for cls in _KPI_COMPROMISE_CLASSES}
    any_all_users: dict[str, bool] = {cls: False for cls in _KPI_COMPROMISE_CLASSES}
    distinct_paths: dict[str, int] = {cls: 0 for cls in _KPI_COMPROMISE_CLASSES}
    # Per-class Tier 0/1/2 breakdown of the blast radius (max over contributing
    # paths per bucket — a broad-group path classifies the same population, so a
    # union by max is the deduplicated count, not a sum across paths).
    any_tier_breakdown: dict[str, dict[str, int]] = {
        cls: {"tier0": 0, "tier1": 0, "tier2": 0} for cls in _KPI_COMPROMISE_CLASSES
    }
    # Per-class per-account fine Privilege-Tier map (normalised sAMAccountName ->
    # fine tier value). Unioned across the paths contributing to a class; every
    # broad-group path over the same population classifies it identically, so a
    # plain merge is the deduplicated map (no double counting). Drives the
    # per-row TierBadge in the blast-radius drill-down.
    any_tier_map: dict[str, dict[str, str]] = {
        cls: {} for cls in _KPI_COMPROMISE_CLASSES
    }

    for index, record in enumerate(records):
        cls = str(record.get("compromise_class") or "").strip().lower()
        if cls not in path_axis:
            continue
        status = _reconcile_status(record, has_exec_by_index[index])

        path_axis[cls][status] = path_axis[cls].get(status, 0) + 1
        path_axis[cls]["total"] = path_axis[cls].get("total", 0) + 1
        distinct_paths[cls] += 1

        users, is_broad, breakdown, tier_map = _record_affected_users(record)
        per_status_users[cls].setdefault(status, set()).update(users)
        per_status_all_users[cls][status] = (
            per_status_all_users[cls].get(status, False) or is_broad
        )
        any_users[cls].update(users)
        any_all_users[cls] = any_all_users[cls] or is_broad
        for bucket in ("tier0", "tier1", "tier2"):
            any_tier_breakdown[cls][bucket] = max(
                any_tier_breakdown[cls][bucket], breakdown.get(bucket, 0)
            )
        any_tier_map[cls].update(tier_map)

    def _pct(count: int, all_users: bool) -> float:
        if all_users:
            return 100.0
        if user_total <= 0:
            return 0.0
        return min(100.0, round(count / user_total * 100.0, 1))

    def _count(users: set[str], all_users: bool) -> int:
        # A broad-group path means the whole domain is in scope; the union of
        # explicit users is a lower bound, so saturate to the domain size.
        if all_users and user_total > 0:
            return user_total
        return len(users)

    user_axis: dict[str, dict[str, Any]] = {}
    for cls in _KPI_COMPROMISE_CLASSES:
        per_status: dict[str, Any] = {}
        for status, users in per_status_users[cls].items():
            all_flag = per_status_all_users[cls].get(status, False)
            per_status[status] = {
                "count": _count(users, all_flag),
                "all_users": all_flag,
            }
        any_count = _count(any_users[cls], any_all_users[cls])
        accounts, accounts_truncated = _serialize_affected_accounts(any_users[cls])
        per_status["any"] = {
            "count": any_count,
            "all_users": any_all_users[cls],
            "pct_of_domain": _pct(any_count, any_all_users[cls]),
            # Drill-down foundation (web /assets resolution + PDF appendix). The
            # explicit list of affected accounts (deduped sAMAccountNames) and a
            # Tier 0/1/2 breakdown of who can reach this terminal. The breakdown
            # buckets sum to the FULL blast radius (Tier-0 members INCLUDED — they
            # take over because they are admins; lower-tier members via the path),
            # which is the product delta the deliverable headlines.
            "affected_accounts": accounts,
            "affected_accounts_truncated": accounts_truncated,
            "tier_breakdown": dict(any_tier_breakdown[cls]),
            # Per-account fine Privilege Tier (additive; backward-compatible with
            # the string ``affected_accounts`` above). Aligned 1:1 with that list
            # (same sort + cap) so each drill-down row can carry its own tier
            # badge. The fine tiers fold back onto ``tier_breakdown`` exactly.
            "affected_accounts_detail": _serialize_affected_accounts_detail(
                accounts, any_tier_map[cls]
            ),
        }
        per_status["distinct_paths"] = distinct_paths[cls]
        user_axis[cls] = per_status

    return {
        "schema_version": 1,
        "computed_at": computed_at or "",
        "domain_user_count": user_total,
        "path_axis": path_axis,
        "user_axis": user_axis,
    }


#: How many top contributing paths to surface for explainability.
_TOP_CONTRIBUTORS: int = 8


# --------------------------------------------------------------------------- #
# Output model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExposureContributor:
    """One attack path contributing to the exposure score (explainability)."""

    start: str
    target: str
    proof_state: str
    hops: int
    primary_vector: str
    weight: float


@dataclass(frozen=True)
class ExposureScore:
    """The AD Exposure Score and its honest breakdown.

    ``overall_pct`` is the headline; ``proven_pct`` is the AEV "demonstrated"
    figure (always ``<= overall_pct``). ``by_class`` explains which compromise
    classes drive the number; ``top_contributors`` lists the heaviest paths;
    ``explanation`` is an auditor-grade one-paragraph "why this number".
    """

    overall_pct: float
    proven_pct: float
    by_class: dict[str, float]
    reachable_tier0: int
    total_tier0: int | None
    top_contributors: list[ExposureContributor] = field(default_factory=list)
    explanation: str = ""
    scope: str = "domain"
    computed_at: str = ""
    scan_id: str | None = None
    workspace: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe representation for ``technical_report.json`` / the API."""
        return {
            "overall_pct": round(self.overall_pct, 1),
            "proven_pct": round(self.proven_pct, 1),
            "by_class": {k: round(v, 1) for k, v in self.by_class.items()},
            "reachable_tier0": self.reachable_tier0,
            "total_tier0": self.total_tier0,
            "top_contributors": [
                {
                    "start": c.start,
                    "target": c.target,
                    "proof_state": c.proof_state,
                    "hops": c.hops,
                    "primary_vector": c.primary_vector,
                    "weight": round(c.weight, 3),
                }
                for c in self.top_contributors
            ],
            "explanation": self.explanation,
            "scope": self.scope,
            "computed_at": self.computed_at,
            "scan_id": self.scan_id,
            "workspace": self.workspace,
        }


# --------------------------------------------------------------------------- #
# Scoring primitives
# --------------------------------------------------------------------------- #


def _proof_weight(status: str) -> float | None:
    """Return the proof weight for a path status, or ``None`` to exclude it."""
    return _PROOF_WEIGHT.get((status or "").strip().lower(), 0.4)


def _ease_weight(hops: int) -> float:
    """Return the ease weight: shorter paths are more exposing."""
    h = max(1, int(hops or 1))
    return 1.0 / (1.0 + EASE_ALPHA * (h - 1))


def _is_proven_status(status: str) -> bool:
    """Return whether a status demonstrably reached the Tier-0 target.

    Cross-checks the canonical :class:`PathState` so the proven set stays in
    lock-step with the engine's own ``is_proven`` notion for the reached states.
    """
    value = (status or "").strip().lower()
    if value in _PROVEN_STATUSES:
        return True
    try:
        return PathState(value) is PathState.DOMAIN_COMPROMISED
    except ValueError:
        return False


def _record_hops(record: Mapping[str, Any]) -> int:
    """Return the executable hop count of a path record (>=1)."""
    raw = record.get("length")
    if isinstance(raw, int):
        return max(1, raw)
    if isinstance(raw, str) and raw.strip().isdigit():
        return max(1, int(raw.strip()))
    relations = record.get("relations")
    if isinstance(relations, list) and relations:
        return max(1, len(relations))
    return 1


def _is_tier0_target(record: Mapping[str, Any]) -> bool:
    """Return whether a path's terminal IS domain compromise (Tier-0).

    Strict by design: the canonical ``compromise_class`` is the authority
    (always stamped by ``apply_path_based_classification``). Only
    ``domain_breaker`` and ``tier0_foothold`` are domain compromise — a path
    terminating at a ``privileged_escalator`` / ``compromise_enabler`` group
    (GPCO, Cert Publishers, DnsAdmins, …) is NOT domain compromise on its own
    and must NOT inflate the headline, even though such a group is Tier-0 in
    BloodHound. (Using the looser ``is_tier_zero`` flag here would wrongly pull
    enabler paths into the score — observed on Essos with JORAH.MORMONT.)

    Falls back to ``outcome_class`` only when ``compromise_class`` is absent
    (legacy records pre-dating the stamping).
    """
    cls = str(record.get("compromise_class") or "").strip().lower()
    if cls:
        return cls in _TIER0_COMPROMISE_CLASSES
    return str(record.get("outcome_class") or "").strip().lower() in {
        "direct_compromise",
        "tier0_foothold",
    }


def _primary_vector(record: Mapping[str, Any]) -> str:
    """Best-effort human label for the path's defining technique."""
    relations = record.get("relations")
    if isinstance(relations, list):
        # Last non-membership relation is the one that actually grants Tier-0.
        for rel in reversed(relations):
            r = str(rel or "").strip()
            if r and r.lower() not in {"memberof", "member of"}:
                return r
    return str(record.get("target_terminal_class") or "unknown")


def _union(weights: Sequence[float]) -> float:
    """Saturating union: ``1 - Π (1 - w)``. Empty → 0.0."""
    product = 1.0
    for w in weights:
        product *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - product


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def compute_exposure_score(
    summaries: Sequence[Mapping[str, Any]],
    *,
    scope: str = "domain",
    total_tier0: int | None = None,
    scan_id: str | None = None,
    workspace: str | None = None,
    computed_at: str | None = None,
) -> ExposureScore:
    """Compute the :class:`ExposureScore` from attack-path summaries.

    Args:
        summaries: Attack-path summary records from
            ``get_attack_path_summaries(...)`` (already computed — NOT
            recomputed here). Each is a mapping with at least ``status``,
            ``length``, ``compromise_class``/``outcome_class``, ``source``,
            ``target``, ``relations``.
        scope: The start-set scope these summaries were computed for
            (``"domain"`` for the low-priv headline, ``"owned"`` for the
            post-foothold view). Recorded on the result for context.
        total_tier0: Total number of Tier-0 targets in the domain (for the
            ``reachable / total`` display stat). ``None`` if not supplied.
        scan_id, workspace, computed_at: provenance metadata. ``computed_at``
            defaults to ``utcnow`` ISO-8601 when not given.

    Returns:
        A fully-populated, JSON-serialisable :class:`ExposureScore`.
    """
    stamp = computed_at or datetime.now(timezone.utc).isoformat()

    # Weight every included Tier-0 path. Each entry: (weight, is_proven, record).
    weighted: list[tuple[float, bool, Mapping[str, Any]]] = []
    for rec in summaries:
        if not isinstance(rec, Mapping):
            continue
        if not _is_tier0_target(rec):
            continue
        status = str(rec.get("status") or "theoretical").strip().lower()
        pw = _proof_weight(status)
        if pw is None:  # unsupported / unavailable — excluded from the score
            continue
        w = pw * _ease_weight(_record_hops(rec))
        if w <= 0.0:
            continue
        weighted.append((w, _is_proven_status(status), rec))

    overall = _union([w for w, _, _ in weighted]) * 100.0
    proven = _union([w for w, is_p, _ in weighted if is_p]) * 100.0

    # Per-compromise-class breakdown (union restricted to each class).
    by_class: dict[str, float] = {}
    for cls in ("domain_breaker", "tier0_foothold", "privileged_escalator", "compromise_enabler"):
        cls_weights = [
            w
            for w, _, rec in weighted
            if str(rec.get("compromise_class") or "").strip().lower() == cls
        ]
        by_class[cls] = _union(cls_weights) * 100.0

    reachable_targets = {
        str(rec.get("target") or "").strip().upper()
        for _, _, rec in weighted
        if str(rec.get("target") or "").strip()
    }
    reachable_tier0 = len(reachable_targets)

    top = sorted(weighted, key=lambda t: t[0], reverse=True)[:_TOP_CONTRIBUTORS]
    top_contributors = [
        ExposureContributor(
            start=str(rec.get("source") or ""),
            target=str(rec.get("target") or ""),
            proof_state=str(rec.get("status") or "theoretical"),
            hops=_record_hops(rec),
            primary_vector=_primary_vector(rec),
            weight=w,
        )
        for w, _, rec in top
    ]

    explanation = _build_explanation(
        overall=overall,
        proven=proven,
        reachable_tier0=reachable_tier0,
        total_tier0=total_tier0,
        path_count=len(weighted),
        proven_count=sum(1 for _, is_p, _ in weighted if is_p),
        scope=scope,
    )

    return ExposureScore(
        overall_pct=overall,
        proven_pct=proven,
        by_class=by_class,
        reachable_tier0=reachable_tier0,
        total_tier0=total_tier0,
        top_contributors=top_contributors,
        explanation=explanation,
        scope=scope,
        computed_at=stamp,
        scan_id=scan_id,
        workspace=workspace,
    )


def _build_explanation(
    *,
    overall: float,
    proven: float,
    reachable_tier0: int,
    total_tier0: int | None,
    path_count: int,
    proven_count: int,
    scope: str,
) -> str:
    """Return an auditor-grade one-paragraph 'why this number'."""
    if path_count == 0:
        return (
            "Exposure 0%: no supported attack path (proven or theoretical) from "
            "a low-privilege foothold to any Tier-0 / Domain Admin target was "
            "found in this scan."
        )
    start_label = "an already-compromised principal" if scope == "owned" else "a low-privilege user"
    tier0_label = (
        f"{reachable_tier0} of {total_tier0} Tier-0 targets"
        if total_tier0
        else f"{reachable_tier0} Tier-0 target(s)"
    )
    proven_clause = (
        f"{proven_count} of these were demonstrably executed end-to-end "
        f"(Proven Exposure {proven:.0f}%)."
        if proven_count
        else "none of these have been executed yet (Proven Exposure 0%); the "
        "figure reflects theoretical, LDAP-derived paths."
    )
    return (
        f"Exposure {overall:.0f}%: {path_count} supported attack path(s) reach "
        f"{tier0_label} from {start_label}. Shorter, higher-proof paths weigh "
        f"more; the score saturates as paths multiply. {proven_clause} "
        "0% is reached only when every such path is remediated."
    )


__all__ = [
    "ExposureScore",
    "ExposureContributor",
    "compute_exposure_score",
    "compute_exposure_kpis",
    "EASE_ALPHA",
]
