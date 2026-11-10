"""Client-facing exposure figures that BOTH the reports and the web CTEM render.

Dependency-light on purpose: it imports only ``compromise_class`` and
``path_state`` (both already bundled into the appliance web backend), so the web
CTEM backend can call the SAME functions the PRO SAR and the LITE report call,
instead of keeping a mirror that drifts. Every function here is pure.

What lives here, and who reads it:

* The report-tier split (``report_tier_for_class`` / ``report_tier_for_record``
  / ``count_report_tiers``) and the posture-score path inputs
  (``derive_posture_path_inputs``). Read by the PRO SAR, the LITE report and the
  web ``/dashboard/posture`` route.
* The domain-takeover blast radius aggregated across domains
  (``aggregate_blast_radius``), the figure the SAR leads page 2 with: how many
  ordinary (non-administrative) accounts hold a path to full domain compromise,
  out of how many. Read by the SAR (``html_pdf_generator``) and the web Overview.
* The privilege-sprawl companion (``aggregate_tier0_population``): how many
  accounts already hold Tier 0 by membership and are excluded from the figure
  above. Read by both report tiers and the web Overview.

``exposure_score_service`` re-exports every name, so existing import paths keep
working. Moving a figure here is how a new surface stops re-deriving it.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from adscan_internal.services.path_state import carries_client_exposure

# The report-tier split and the posture path inputs live in the dependency-light
# SSOT ``adscan_core.reporting.posture_inputs`` so the web worker, which has no
# engine on its path, computes the posture score with the same function the
# SAR calls. Re-exported here unchanged.
from adscan_core.reporting.posture_inputs import (  # noqa: F401
    _COMPROMISE_CLASS_TO_REPORT_TIER,
    _OUTCOME_CLASS_TO_REPORT_TIER,
    derive_posture_path_inputs,
    report_tier_for_class,
    report_tier_for_record,
)

def count_report_tiers(
    records: Sequence[Mapping[str, Any]],
    *,
    exposure_only: bool = False,
) -> dict[str, int]:
    """Tally attack-path records into the four canonical report tiers.

    Reads each record's ``compromise_class`` and routes it through
    :func:`report_tier_for_class`. Records whose class is outside the four
    tracked tiers are ignored (not counted in any bucket). The four buckets
    are the whole Compromise Reach quartet the executive summary renders —
    summing them equals the domain's OPEN-exposure attack-path total (with
    ``exposure_only=True``), which is what keeps the report's reach chips
    from silently undercounting against the engine-stamped total.

    Args:
        records: Attack-path records, each a mapping carrying
            ``compromise_class`` (as produced by ``get_attack_path_summaries``
            and threaded onto the report path dicts).
        exposure_only: Count only paths that describe OPEN exposure — the same
            filter the exposure score applies
            (:func:`~adscan_internal.services.path_state.carries_client_exposure`),
            so an avenue the client's own configuration closed and a path
            ADscan had no surface to walk do not land in a number the report
            presents as their exposure. Leave ``False`` for the raw inventory
            tally.

    Returns:
        ``{"T1": <full domain compromise>, "T1C": <Tier 0 control>,
        "T2": <Tier-0 footholds>, "T3": <privilege-escalation enablers>,
        "T4": <stepping stones>}``.
    """
    counts = {"T1": 0, "T1C": 0, "T2": 0, "T3": 0, "T4": 0}
    for record in records:
        if not isinstance(record, Mapping):
            continue
        if exposure_only and not carries_client_exposure(record.get("status")):
            continue
        tier = report_tier_for_record(record)
        if tier is not None:
            counts[tier] += 1
    return counts





def aggregate_blast_radius(
    domains: Mapping[str, Any] | Iterable[Mapping[str, Any]],
    classes: tuple[str, ...],
) -> dict[str, Any]:
    """Aggregate the user-axis blast radius of ``classes`` across every domain.

    The SAR's page-2 figure ("N of M ordinary (non-administrative) domain users
    have a path to full domain compromise"), lifted out of the PDF generator so
    the web Overview renders the SAME numbers from the SAME code. Reads only the
    engine-stamped ``exposure_kpis`` block of each entry; never recomputes a
    path. Domains are disjoint, so their counts sum.

    Args:
        domains: The ``technical_report["domains"]`` mapping, or an iterable of
            per-domain dicts, each optionally carrying ``exposure_kpis``. A
            domain without the block contributes nothing.
        classes: The compromise classes to union within each domain (for
            example ``("domain_breaker",)`` for the takeover figure).

    Returns:
        ``count``, ``domain_user_count``, ``pct``, ``all_users``, ``available``,
        ``tier_breakdown`` (or ``None`` when the split does not reconcile with
        the count), ``segments``, ``ordinary_stat`` (the ordinary-account
        headline from :func:`compromise_class.derive_ordinary_breaker_stat`) and
        ``unaffected_accounts`` (named only when every one is ordinary).
    """
    entries = list(domains.values()) if isinstance(domains, Mapping) else list(domains)
    total_users = 0
    affected = 0
    any_all_users = False
    # Privilege Tier split of the affected accounts, read VERBATIM from the
    # engine-stamped user_axis.<class>.any.tier_breakdown (single source of
    # truth: privilege_tier_for_principal). Never recomputed here. For each
    # domain we take the winning bucket's breakdown (the bucket whose count
    # set _dom_count) and sum the {tier0,tier1,tier2} keys across domains.
    tier0 = 0
    tier1 = 0
    tier2 = 0
    # Enabled accounts holding NO path of these classes, read verbatim from
    # the engine block. Named in the document only when every one of them is
    # an ordinary account (see the reconciliation below), because "one
    # account has no route" is a positive finding and "one privileged
    # account has no route" is noise.
    unaffected: list[str] = []
    # Accounts that ARE Tier 0 by MEMBERSHIP (population, not path-bearing) —
    # the denominator exclusion for the ordinary-account headline, so a Tier-0
    # sink like the RID-500 Administrator is never counted as an ordinary
    # account without a route. Summed disjointly across domains.
    population_tier0 = 0
    # Accounts graded Tier 1 by the stamped tier SSOT. Administrative, so they
    # are excluded from the ORDINARY (Tier 2) denominator the same way.
    population_tier1 = 0
    for _di in entries:
        _k = _di.get("exposure_kpis")
        if not isinstance(_k, dict):
            continue
        total_users += int(_k.get("domain_user_count", 0) or 0)
        _ptb = _k.get("population_tier_breakdown")
        if isinstance(_ptb, dict):
            population_tier0 += int(_ptb.get("tier0", 0) or 0)
            population_tier1 += int(_ptb.get("tier1", 0) or 0)
        _ua = _k.get("user_axis")
        if not isinstance(_ua, dict):
            continue
        # Union the contributing classes WITHIN a domain (cap at the domain's
        # own user count) before summing disjoint domains.
        _dom_all = False
        _dom_count = 0
        _dom_breakdown: dict[str, Any] | None = None
        _dom_unaffected: list[str] = []
        for _cls in classes:
            _bucket = _ua.get(_cls)
            if not isinstance(_bucket, dict):
                continue
            _anyb = _bucket.get("any")
            if isinstance(_anyb, dict):
                _cnt = int(_anyb.get("count", 0) or 0)
                if _cnt >= _dom_count:
                    _dom_count = _cnt
                    _tb = _anyb.get("tier_breakdown")
                    _dom_breakdown = _tb if isinstance(_tb, dict) else None
                    _ua_list = _anyb.get("unaffected_accounts")
                    _dom_unaffected = (
                        [str(_a) for _a in _ua_list if str(_a).strip()]
                        if isinstance(_ua_list, list)
                        and not _anyb.get("unaffected_accounts_truncated")
                        else []
                    )
                _dom_all = _dom_all or bool(_anyb.get("all_users"))
        # No saturation to the domain population here. The engine already
        # resolved whether the affected set covers it; rounding the count up
        # a second time is what made the count disagree with the Tier split
        # it has to reconcile against, which suppressed the ordinary-account
        # headline and left page 2 pairing a foothold figure with a
        # full-compromise sentence.
        any_all_users = any_all_users or _dom_all
        unaffected.extend(_dom_unaffected)
        if isinstance(_dom_breakdown, dict):
            affected += _dom_count
            tier0 += int(_dom_breakdown.get("tier0", 0) or 0)
            tier1 += int(_dom_breakdown.get("tier1", 0) or 0)
            tier2 += int(_dom_breakdown.get("tier2", 0) or 0)
        elif _dom_count == 0:
            # Sampled fallback: the control-mega-hub coverage collapsed
            # user_axis to 0 even on a compromised domain. The engine-stamped
            # tier2_exposure ratio is a k-independent reverse-reachability set
            # cardinality of the standard (enabled, non-Tier-0) USER accounts,
            # so treat it as the Tier-2 breakdown contribution — the tile then
            # reports the real standard-user reach instead of a false 0.
            # Healthy domains carry a breakdown and never reach this branch.
            _t2 = _k.get("tier2_exposure")
            if isinstance(_t2, dict):
                _t2_with = int(_t2.get("with_path", 0) or 0)
                if _t2_with > 0:
                    affected += _t2_with
                    tier2 += _t2_with
        else:
            affected += _dom_count
    pct = 0.0
    if total_users > 0:
        pct = min(100.0, round(affected / total_users * 100.0, 1))
    elif any_all_users:
        pct = 100.0
    # Expose the tier split only when it reconciles with the displayed total.
    # A broad-group saturation (all_users) inflates `count` to the full domain
    # population, which the per-bucket breakdown does not cover, so suppress
    # the split there rather than print a sum that does not add up.
    _breakdown: dict[str, int] | None = None
    _segments: dict[str, Any] | None = None
    if (tier0 + tier1 + tier2) == affected and affected > 0:
        _breakdown = {
            "tier0": tier0,
            "tier1": tier1,
            "tier2": tier2,
            "lower": tier1 + tier2,
        }
        # Segment + severity STATE from the engine SSOT — never recomputed
        # here. The escalators (Tier 1 + Tier 2) drive the tile colour, the
        # already-Tier-0 accounts are the baseline context.
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            domain_takeover_kpi_segments,
        )

        _segments = domain_takeover_kpi_segments(
            total=affected,
            tier0=tier0,
            tier1=tier1,
            tier2=tier2,
            # Enabled domain-user population — denominator for the
            # everyone-/most-Tier-0 guard so a domain where (nearly) every
            # user is already Tier-0 is forced CRITICAL, never a green
            # baseline (~100% ransomware exposure by construction).
            domain_user_count=total_users,
        )
    # Tier-aware, non-circular ordinary-account headline (SSOT:
    # compromise_class.derive_ordinary_breaker_stat). Only when the tier
    # split reconciles with the displayed total (same gate as the breakdown
    # above) — otherwise the ordinary/admin split would not add up. The
    # web mirror (exposure_kpis_view) computes the identical tuple.
    _ordinary_stat: dict[str, Any] | None = None
    if _breakdown is not None:
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            derive_ordinary_breaker_stat,
        )

        _ordinary_stat = derive_ordinary_breaker_stat(
            tier0=tier0,
            tier1=tier1,
            tier2=tier2,
            domain_user_count=total_users,
            population_tier0=population_tier0,
            population_tier1=population_tier1,
        )
    # Name the accounts with no route only when EVERY one of them is an
    # ordinary account — that is what makes the sentence a finding rather
    # than trivia. The test is arithmetic against the SSOT: the ordinary
    # population minus the ordinary accounts holding a path must equal the
    # number of unaffected names we hold. When it does not, the unaffected
    # set includes privileged accounts (or the split did not reconcile) and
    # the document says nothing rather than something it cannot support.
    _named_exceptions: list[str] = []
    if _ordinary_stat is not None and unaffected:
        _ordinary_gap = int(_ordinary_stat["ordinary_total"]) - int(
            _ordinary_stat["ordinary_with_breaker"]
        )
        if _ordinary_gap == len(unaffected):
            _named_exceptions = sorted(set(unaffected))
    return {
        "count": affected,
        "domain_user_count": total_users,
        "pct": pct,
        "all_users": any_all_users,
        "available": total_users > 0 or affected > 0,
        "tier_breakdown": _breakdown,
        "segments": _segments,
        "ordinary_stat": _ordinary_stat,
        "unaffected_accounts": _named_exceptions,
    }


def aggregate_tier0_population(
    domains: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """Aggregate the privilege-SPRAWL figure across every assessed domain.

    How many accounts ALREADY hold Tier 0 by membership. This is the companion
    to :func:`derive_domain_user_reach`, and the reason that figure is honest:
    the path metric excludes the already-privileged accounts, and an exclusion
    reported without its count does not clean the number, it hides the
    population. A domain of a hundred where forty are Domain Admins can show
    modest path exposure and be entirely lost — those forty need no route,
    they are the destination.

    Reads the engine-stamped ``population_tier_breakdown`` (the POPULATION's
    Tier split, NOT the affected set's) and hands the estate totals to the SSOT
    :func:`~adscan_internal.services.compromise_class.derive_tier0_population_stat`,
    which also decides PRECEDENCE via ``leads``: where sprawl is pathological
    it takes the headline and path exposure becomes the second line, because
    asking whether a tier separation holds is moot where there is none left to
    hold.

    The affected set cannot stand in for the population here. In that same
    domain of a hundred, if only twelve of the forty administrators appear on a
    path, the affected split reads twelve and the escalation never fires — a
    silent failure to escalate, which is the dangerous direction.

    Lives in this shared layer, beside the reach derivation it qualifies,
    because BOTH report tiers print the figure. A second copy for the free
    report is how the two tiers end up quoting different numbers off one scan.

    Args:
        domains: Either the ``technical_report["domains"]`` mapping or an
            iterable of per-domain dicts, each optionally carrying an
            ``exposure_kpis`` block — the same input
            :func:`derive_domain_user_reach` takes, so one call site can feed
            both.

    Returns:
        The flat stat dict every surface renders directly (``tier0_count``,
        ``domain_user_count``, ``pct``, ``leads``, ``degenerate``,
        ``dominant_kind``, …), or ``None`` when no domain carries a graded
        population — the caller then renders no sprawl figure rather than a
        zeroed one, which would read as "nobody is privileged".
    """
    entries = list(domains.values()) if isinstance(domains, Mapping) else list(domains)

    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        derive_tier0_population_stat,
    )

    population = 0
    tier0 = 0
    tier0_direct = 0
    tier1 = 0
    tier1_accounts: list[str] = []
    found = False
    any_domain_leads = False
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        kpis = entry.get("exposure_kpis")
        if not isinstance(kpis, Mapping):
            continue
        split = kpis.get("population_tier_breakdown")
        if not isinstance(split, Mapping):
            continue
        # The denominator sums ONLY the domains that carry a breakdown.
        # Counting a domain whose Tier 0 population could not be graded would
        # dilute the share, and diluting is the direction that suppresses the
        # escalation.
        found = True
        domain_population = max(0, int(kpis.get("domain_user_count", 0) or 0))
        domain_tier0 = max(0, int(split.get("tier0", 0) or 0))
        domain_tier0_direct = max(0, int(split.get("tier0_direct", 0) or 0))
        domain_tier1 = max(0, int(split.get("tier1", 0) or 0))
        population += domain_population
        tier0 += domain_tier0
        tier0_direct += domain_tier0_direct
        tier1 += domain_tier1
        names = split.get("tier1_accounts")
        if isinstance(names, list):
            tier1_accounts.extend(str(n) for n in names)
        if derive_tier0_population_stat(
            tier0=domain_tier0,
            tier0_direct=domain_tier0_direct,
            domain_user_count=domain_population,
            tier1=domain_tier1,
        )["leads"]:
            any_domain_leads = True
    if not found or population <= 0:
        return None

    stat = derive_tier0_population_stat(
        tier0=tier0,
        tier0_direct=tier0_direct,
        domain_user_count=population,
        tier1=tier1,
        tier1_accounts=tier1_accounts,
    )
    # PRECEDENCE is decided per domain, never on the sum. The sprawl rule
    # carries an absolute floor (``_TIER0_SPRAWL_FLOOR``) so a small directory
    # cannot trip it on arithmetic alone, and adding domains together is exactly
    # that arithmetic: two domains with three Tier 0 accounts each cross a floor
    # of five that neither crosses, and the estate headline would flip to
    # sprawl while every per-domain view leads with path exposure. An estate
    # view must tell the same story as its domains, summed. So sprawl leads the
    # estate exactly when it leads at least one domain. Nothing is hidden by
    # this: the summed sprawl figure is still returned and rendered as the
    # second line; only which sentence comes first changes.
    stat["leads"] = any_domain_leads
    return stat
