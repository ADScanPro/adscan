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

Model (v2) — union of per-path (evidence × exploitability):

    w(p)              = proof_base(status) × exploitability(p)
    exploitability(p) = Π_step  P(a capable attacker executes that step)
                      = Π_step  effort_to_rate(compromise_effort(relation))
    exposure          = 1 - Π_p (1 - w(p))     over all included S→Tier-0 paths

Two orthogonal axes, never collapsed into one flat per-status weight:

* ``proof_base(status)`` — how much WE demonstrated (the evidence axis).
  ``success`` / ``exploited`` / ``domain_compromised`` OVERRIDE to 1.0 (proof
  beats the technique prior — a cracked Kerberoast is 100%, not 30%).
  ``attempted`` is a NEGATIVE observation (below the theoretical prior — we tried
  and it did not land). ``blocked`` gated on the ``dangerous_destructive`` marker
  shares the theoretical base: a safety abstention is a CONFIRMED-precondition
  avenue we withheld (e.g. Zerologon whose all-zero bypass we PROVED over the
  wire, stopping before the destructive reset), NOT "unknown".
* ``exploitability(p)`` — how executable the TECHNIQUE(s) are for a real
  attacker, as the PER-STEP PRODUCT over the path's relations. A 1-hop Kerberoast
  (crack required) is harder than a 3-hop GenericAll chain (deterministic) — hop
  COUNT is not difficulty. The product naturally encodes length (more hops →
  lower weight, each weighted by its real difficulty), which REPLACES the old
  crude ``ease_weight(hops)``. It sources ``compromise_effort`` already authored
  per technique in ``attack_step_catalog`` (the SSOT), so it never drifts.

Properties (acceptance criteria, see spec §5):

* ``0%`` iff there is no supported path (proven or theoretical) from the
  low-priv start set to any Tier-0 target (empty product → ``1 - 1 = 0``).
* A single PROVEN path → ``w = 1`` → ``100%`` (honest AEV: demonstrated).
* Theoretical-only paths saturate below 100%; multiplicity adds but saturates.
* ``Proven Exposure ≤ Total Exposure`` always; theoretical is never counted as
  proven.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from adscan_internal.services.attack_step_support_registry import (
    classify_relation_support,
)
from adscan_internal.services.path_state import (
    _PROVEN_STATUSES,
    NO_EXPOSURE_STATUSES,
    PathState,
    carries_client_exposure,
)

# --------------------------------------------------------------------------- #
# Tunables — the weights/shape are the only thing to tune; the union form and
# the acceptance properties above must NOT change.
# --------------------------------------------------------------------------- #

#: EVIDENCE axis — ``proof_base(status)``: how much WE demonstrated, INDEPENDENT
#: of how hard the technique is (that is the exploitability axis below). The final
#: per-path weight is ``proof_base × exploitability`` (except proven statuses,
#: which override to 1.0). ``None`` => exclude the path entirely. Covers BOTH the
#: edge-status vocabulary (theoretical/attempted/success/blocked/…) and the
#: executed PathState vocabulary (domain_compromised/foothold_obtained/…).
_PROOF_WEIGHT: dict[str, float | None] = {
    # Proven domain compromise — we demonstrably reached the Tier-0 target. This
    # OVERRIDES exploitability to 1.0 (proof beats the technique prior: a cracked
    # Kerberoast is 100%, not 30%).
    "success": 1.0,
    "exploited": 1.0,
    "domain_compromised": 1.0,
    # Partially validated — a chain with a DEMONSTRATED (success) segment that did
    # not execute end-to-end. Above theoretical (a segment is validated, not merely
    # theorized). Deliberately NOT in ``_PROVEN_STATUSES`` — not a full compromise,
    # so it never inflates the strict Proven-Exposure headline.
    "partial": 0.9,
    # Executed and on the way — reality demonstrated but not full domain yet.
    "foothold_obtained": 0.85,
    "post_ex_in_progress": 0.85,
    # Supported but never executed — LDAP-derived theoretical path. The technique
    # prior (exploitability) IS our estimate here; this base only discounts for
    # "not demonstrated".
    "theoretical": 0.8,
    "discovered": 0.8,
    # ``blocked`` = an avenue ADscan chose NOT to run — NOT "tried and failed".
    # It carries NO negative signal, so it is theoretical-tier (a supported,
    # un-executed avenue), NOT attempted-tier. The safety-abstention destructive
    # case (``dangerous_destructive`` marker) is elevated ABOVE theoretical in
    # ``_proof_base`` — for those (e.g. Zerologon) we CONFIRMED the exploit over
    # the wire and withheld only the detonation.
    "blocked": 0.8,
    # Attempted but did NOT land (tried against the real DC, no compromise). A
    # NEGATIVE observation — below the theoretical prior, because a confirmed
    # non-result is weaker exposure than an untried structural edge. Still nonzero:
    # an attacker with more resources (bigger wordlist / GPU / time) might succeed.
    "attempted": 0.4,
    "failed": 0.4,
    "error": 0.4,
    "post_ex_failed": 0.4,
    # No client exposure at all → excluded from the score entirely:
    # ``closed_by_configuration`` (an avenue the environment's own configuration
    # closed, observed with certainty — a POSITIVE fact) and ``unsupported`` /
    # ``unavailable`` (an ADscan data gap, no reachable surface). Unpacked from
    # the shared vocabulary so the exposure score and the remediation rankings
    # exclude exactly the same paths — one definition, not two tables.
    **{status: None for status in NO_EXPOSURE_STATUSES},
}

#: Evidence base for a safety-abstention destructive avenue (``blocked`` +
#: ``dangerous_destructive``). ABOVE ``theoretical`` (0.8) because for these
#: (Zerologon/NoPac/PrintNightmare, FCP-on-computer) the precondition is
#: CONFIRMED — e.g. Zerologon's all-zero bypass succeeded over the wire and we
#: withheld only the destructive reset — which is stronger evidence than an
#: LDAP-derived theoretical edge. Below a full proven compromise (kept out of
#: ``_PROVEN_STATUSES``: we did not complete the destructive action).
_CONFIRMED_DESTRUCTIVE_BASE: float = 0.9

#: EXPLOITABILITY axis — maps the per-technique ``compromise_effort`` (authored in
#: ``attack_step_catalog``, the SSOT, and read per relation via
#: ``classify_relation_support``) to ``P(a capable attacker executes this step)``.
#: Deterministic control edges (GenericAll/DCSync/FCP — ``low``) are set HIGH so a
#: uniform-easy multi-hop chain decays GENTLY under the per-step product (0.95⁵ ≈
#: 0.77), reserving the low values for genuinely probabilistic techniques
#: (Kerberoast/ASREPRoast — ``high`` — need an offline crack). Setting the
#: deterministic rate high is what keeps the independent-product assumption from
#: over-penalizing correlated same-technique chains.
_EFFORT_TO_EXPLOITABILITY: dict[str, float] = {
    "none": 1.0,       # you already ARE the principal (pure membership terminal)
    "immediate": 1.0,  # single deterministic control edge to compromise
    "low": 0.95,       # GenericAll / GenericWrite / DCSync / ForceChangePassword
    "medium": 0.6,     # needs a condition (coercion target present, config)
    "high": 0.3,       # Kerberoast / ASREPRoast — offline crack required
    "other": 0.5,      # unknown technique — neutral prior
}

#: Per-technique exploitability, authored SPECIFICALLY for the exposure score
#: (the "P(a capable attacker executes this step)" axis), keyed by lower-cased
#: relation. This is DELIBERATELY DECOUPLED from the catalog ``compromise_effort``:
#: that field drives attack-path ORDERING (its own priority semantics) and is
#: under-authored for exploitability (DCSync/Zerologon/ESC1 resolve to ``other``
#: or do not resolve at all), so overloading it would both mis-score AND perturb
#: ordering. A relation absent here falls back to the ``compromise_effort``-derived
#: rate above. VALUES ARE THE EXPOSURE SEMANTICS — review before shipping; the
#: long-term home is a dedicated ``exploitability`` field on the catalog entry
#: (see BACKLOG), which this map seeds.
_RELATION_EXPLOITABILITY: dict[str, float] = {
    # Deterministic ACL / control edges — near-certain given the ACL is real.
    "genericall": 0.97,
    "allextendedrights": 0.95,
    "forcechangepassword": 0.95,
    "addself": 0.95,
    "addmember": 0.97,
    "addmembers": 0.97,
    "genericwrite": 0.9,
    "writedacl": 0.9,
    "writeowner": 0.9,
    "owns": 0.9,
    "writeaccountrestrictions": 0.85,
    "addkeycredentiallink": 0.85,  # shadow creds — needs a PKINIT-capable KDC
    "writespn": 0.35,              # targeted Kerberoast — still needs an offline crack
    # DCSync (replication rights) — deterministic domain-secret extraction.
    "dcsync": 0.97,
    "getchanges": 0.9,
    "getchangesall": 0.95,
    # CVE domain takeover — confirmed over-the-wire BEFORE the safety block.
    "zerologon": 1.0,
    "nopac": 0.95,
    "printnightmare": 0.85,
    # Delegation.
    "allowedtodelegate": 0.8,
    "allowedtoact": 0.8,
    # ADCS ESCs (BloodHound relation spellings — verified against live graphs).
    "adcsesc1": 0.9,
    "adcsesc2": 0.85,
    "adcsesc3": 0.85,
    "adcsesc4": 0.85,
    "adcsesc5": 0.85,
    "adcsesc6": 0.85,
    "adcsesc7": 0.85,
    "adcsesc8": 0.7,   # relay-dependent
    "adcsesc9": 0.7,
    "adcsesc10": 0.7,
    "adcsesc13": 0.9,
    # Secret-read edges — deterministic given the right (verified on live graphs).
    "readlapspassword": 0.95,
    "synclapspassword": 0.9,
    "readgmsapassword": 0.95,
    "dumplsa": 0.85,   # needs a local-admin session first, then deterministic
    # Crack-dependent — PROBABILISTIC (offline crack required). NOTE the live
    # relation spellings are `Kerberoasting` / `ASREPRoasting` (the `-ing` form);
    # both spellings kept so neither falls through to the coarse effort default.
    "kerberoasting": 0.3,
    "kerberoast": 0.3,
    "asreproasting": 0.35,
    "asreproast": 0.35,
    "asreproastable": 0.35,
    # Access / session edges (usually tier0_foothold terminals).
    "adminto": 0.9,
    "hassession": 0.7,
    "canrdp": 0.7,
    "canpsremote": 0.7,
    "executedcom": 0.7,
    "sqladmin": 0.6,
    "sqlaccess": 0.5,   # DB session, usually no host code-exec
    # Coercion — needs a reachable relay target.
    "coerce": 0.75,
    "coercetorelay": 0.75,
    "printerbug": 0.75,
    "petitpotam": 0.75,
}

# ``_PROVEN_STATUSES`` (statuses that count as PROVEN domain compromise for the
# Proven Exposure number) is now owned by the lean leaf ``path_state`` and
# imported at the top of this module — so it is re-exported here unchanged for
# full backward compat (every ``exposure_score_service._PROVEN_STATUSES``
# reference, including the documented SSOT name, keeps working). Do NOT
# re-declare the value here; the import above IS the re-export.

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
    *,
    exposure_only: bool = False,
) -> dict[str, int]:
    """Tally attack-path records into the three canonical report tiers.

    Reads each record's ``compromise_class`` and routes it through
    :func:`report_tier_for_class`. Records whose class is outside the three
    tracked tiers are ignored (not counted in any bucket).

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
        ``{"T1": <full domain compromise>, "T2": <Tier-0 footholds>,
        "T3": <privilege-escalation enablers>}``.
    """
    counts = {"T1": 0, "T2": 0, "T3": 0}
    for record in records:
        if not isinstance(record, Mapping):
            continue
        if exposure_only and not carries_client_exposure(record.get("status")):
            continue
        tier = report_tier_for_record(record)
        if tier is not None:
            counts[tier] += 1
    return counts


def derive_posture_path_inputs(
    records: Sequence[Mapping[str, Any]],
    *,
    paths_to_da: int | None = None,
) -> tuple[int, int]:
    """Return ``(paths_to_da, tier0_exposed)`` for :func:`compute_posture_score`.

    The **single source of truth** for the two path-derived posture-score inputs,
    shared by the PRO report and the LITE HTML exposure report so the SAME
    workspace always yields the SAME score on both tiers. A client who sees one
    number in the free tier and a different one after buying has a number they
    cannot trust, so this derivation must never be re-implemented per surface.

    Both inputs are class-driven via the canonical report-tier split
    (:func:`report_tier_for_record`), never via a per-record ``is_tier_zero``
    flag:

    Both counts describe OPEN exposure, so a path whose status carries none is
    skipped — the same
    :func:`~adscan_internal.services.path_state.carries_client_exposure` filter
    the exposure score applies through ``_PROOF_WEIGHT``. Without it the posture
    score and the executive headline counted avenues the client's own
    configuration had closed, plus paths ADscan never had the surface to walk,
    and reported the sum as exposure demanding immediate attention.

    * ``paths_to_da`` — the **T1** count (``domain_breaker``): paths that reach
      full domain compromise. Counted per PATH, not deduplicated by
      source/target/relations: two distinct chains to the same target are two
      distinct ways in, and the score's path penalty is meant to reflect that.
    * ``tier0_exposed`` — the count of **distinct targets** reached by **T1 or
      T2** paths (the canonical :data:`_TIER0_COMPROMISE_CLASSES`: full domain
      compromise plus Tier-0 host footholds). Targets are compared
      case-insensitively so ``ESSOS.LOCAL`` and ``essos.local`` are one asset.
      **T3 (``privileged_escalator``) is deliberately EXCLUDED**: control of a
      Tier-0 escalation group (Cert Publishers, DnsAdmins, the Operators) is a
      privilege-escalation enabler, not Tier-0 asset exposure on its own, and
      counting it inflates the penalty. Including T3 was exactly the defect that
      made LITE render 0/100 where PRO rendered 2/100 on the same workspace.

    Args:
        records: Attack-path records carrying ``compromise_class`` and
            ``target`` (as produced by ``get_attack_path_summaries`` and
            persisted into ``attack_paths_snapshot.json``).
        paths_to_da: Optional pre-resolved T1 count. Callers that already
            resolved it from the engine-stamped ``exposure_kpis`` ``path_axis``
            block (the PRO report's preferred source) pass it here so this
            helper does not recount; every other caller leaves it ``None`` and
            gets the records-derived T1 count. The two agree by construction —
            the caller must pass the block's ``exposure_total``, not its raw
            ``total``, or it reintroduces the no-exposure paths this filters.

    Returns:
        A ``(paths_to_da, tier0_exposed)`` tuple of non-negative ints.
    """
    tier0_targets: set[str] = set()
    t1_count = 0
    for record in records:
        if not isinstance(record, Mapping):
            continue
        if not carries_client_exposure(record.get("status")):
            continue
        tier = report_tier_for_record(record)
        if tier == "T1":
            t1_count += 1
        if tier in {"T1", "T2"}:
            target = str(record.get("target") or "").strip().lower()
            if target:
                tier0_targets.add(target)
    resolved_da = t1_count if paths_to_da is None else max(0, int(paths_to_da))
    return resolved_da, len(tier0_targets)


def _coerce_tier_breakdown(
    breakdown: Mapping[str, Any] | None,
) -> tuple[int, int, int] | None:
    """Return ``(tier0, tier1, tier2)`` from a stamped breakdown, or ``None``.

    ``None`` when the block is absent or malformed, which the caller treats as
    "no Tier split available" rather than as three zeros — a zeroed split reads
    as "nobody is privileged", which is a claim, not a missing value.
    """
    if not isinstance(breakdown, Mapping):
        return None
    values: list[int] = []
    for bucket in ("tier0", "tier1", "tier2"):
        try:
            values.append(max(0, int(breakdown.get(bucket, 0) or 0)))
        except (TypeError, ValueError):
            return None
    return values[0], values[1], values[2]


@dataclass(frozen=True)
class DomainUserReach:
    """How much of the domain's user population a compromise class reaches.

    The blast-radius figure in human terms. "25 of 31 paths" is an inventory
    count; "10 of 10 domain users hold a path to full domain compromise" is the
    same evidence in the unit a CISO budgets in, and it is the sentence the
    paid report leads with.

    Attributes:
        affected: Distinct domain users holding at least one path of the
            requested class.
        total: The domain's enabled user population (the denominator).
        all_users: Every enabled account in the population is affected — a
            measured fact about the resolved set, not an assumption drawn from
            the scope being a broad group.
        available: There was a KPI block to read. ``False`` means the artifact
            predates the KPI engine and the caller should say nothing at all
            rather than render a zero it cannot stand behind.
        ordinary_affected: The subset of :attr:`affected` that is NOT already
            Tier 0. This is the finding. A Tier 0 account "reaching" full domain
            compromise is the directory's own hierarchy restated — the built-in
            Administrator can take over the domain because it IS the domain —
            so counting it inflates the headline toward 100% by construction
            and costs the figure its credibility when it genuinely is high.
        ordinary_total: The enabled NON-Tier-0 population, the denominator that
            pairs with :attr:`ordinary_affected`. Numerator and denominator are
            drawn from the same population, so 100% means every ordinary
            account and the metric has no hidden ceiling.
        tier0_affected: The already-privileged accounts among :attr:`affected`,
            kept as context rather than dropped: a reader is owed the whole
            number as well as the part of it that is a finding.
        ordinary_available: The Tier split reconciled with :attr:`affected`, so
            the ordinary figures can be stood behind. ``False`` means fall back
            to the plain reach framing rather than print a split that does not
            add up.
    """

    affected: int = 0
    total: int = 0
    all_users: bool = False
    available: bool = False
    ordinary_affected: int = 0
    ordinary_total: int = 0
    tier0_affected: int = 0
    ordinary_available: bool = False

    @property
    def pct(self) -> float:
        """Share of the domain population, saturating at 100."""
        if self.total > 0:
            return min(100.0, round(self.affected / self.total * 100.0, 1))
        return 100.0 if self.all_users else 0.0

    @property
    def ordinary_pct(self) -> float:
        """Share of the NON-Tier-0 population, saturating at 100."""
        if self.ordinary_total > 0:
            return min(
                100.0, round(self.ordinary_affected / self.ordinary_total * 100.0, 1)
            )
        return 0.0

    @property
    def is_every_account(self) -> bool:
        """True when every account in the domain is affected."""
        return bool(self.all_users or (self.total > 0 and self.affected >= self.total))


def derive_domain_user_reach(
    domains: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    compromise_classes: Sequence[str] = ("domain_breaker",),
) -> DomainUserReach:
    """Return the user-population reach of ``compromise_classes`` across domains.

    Reads the engine-stamped ``exposure_kpis`` ``user_axis`` block VERBATIM —
    the single source of truth written by :func:`compute_exposure_kpis`. Never
    recomputed from paths here: a second derivation is how the free and paid
    tiers end up quoting different numbers off one scan.

    Per-domain the requested classes are unioned (capped at that domain's own
    population), then summed across domains, which is sound because the counts
    are domain-disjoint. The engine already resolved whether the affected set
    covers the whole population, so no saturation happens here — re-applying it
    would restore the over-claim the engine derivation exists to prevent.

    The Tier-0-excluded figures ride along (``ordinary_*``), derived through the
    shared :func:`~adscan_internal.services.compromise_class.derive_ordinary_breaker_stat`
    so the free report, the paid report and the platform answer "how many of
    your people are exposed" with one number.

    Args:
        domains: Either the ``technical_report["domains"]`` mapping or an
            iterable of per-domain dicts, each optionally carrying an
            ``exposure_kpis`` block.
        compromise_classes: Which classes to union. Defaults to the headline
            one, ``domain_breaker`` (full domain compromise).

    Returns:
        A :class:`DomainUserReach`. ``available`` is False when no domain
        carried a KPI block.
    """
    entries = list(domains.values()) if isinstance(domains, Mapping) else list(domains)

    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        derive_ordinary_breaker_stat,
    )

    affected = 0
    total = 0
    any_all_users = False
    available = False
    ordinary_affected = 0
    ordinary_total = 0
    tier0_affected = 0
    ordinary_available = False

    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        kpis = entry.get("exposure_kpis")
        if not isinstance(kpis, Mapping):
            continue
        available = True
        domain_users = max(0, int(kpis.get("domain_user_count", 0) or 0))
        total += domain_users
        user_axis = kpis.get("user_axis")
        if not isinstance(user_axis, Mapping):
            continue
        domain_affected = 0
        domain_all_users = False
        domain_breakdown: Mapping[str, Any] | None = None
        for class_name in compromise_classes:
            bucket = user_axis.get(class_name)
            if not isinstance(bucket, Mapping):
                continue
            any_bucket = bucket.get("any")
            if not isinstance(any_bucket, Mapping):
                continue
            class_count = max(0, int(any_bucket.get("count", 0) or 0))
            if class_count >= domain_affected:
                domain_affected = class_count
                candidate = any_bucket.get("tier_breakdown")
                domain_breakdown = candidate if isinstance(candidate, Mapping) else None
            domain_all_users = domain_all_users or bool(any_bucket.get("all_users"))
        affected += domain_affected
        any_all_users = any_all_users or domain_all_users

        # The Tier split may only be shown when it reconciles with the count it
        # splits — the same gate the paid report and the platform apply, so all
        # three fall back together rather than one of them printing a breakdown
        # that does not add up.
        tiers = _coerce_tier_breakdown(domain_breakdown)
        if tiers is None or sum(tiers) != domain_affected or domain_affected <= 0:
            continue
        stat = derive_ordinary_breaker_stat(
            tier0=tiers[0],
            tier1=tiers[1],
            tier2=tiers[2],
            domain_user_count=domain_users,
        )
        ordinary_affected += int(stat["ordinary_with_breaker"])
        ordinary_total += int(stat["ordinary_total"])
        tier0_affected += int(stat["tier0_with_breaker"])
        ordinary_available = True

    return DomainUserReach(
        affected=affected,
        total=total,
        all_users=any_all_users,
        available=available,
        ordinary_affected=ordinary_affected,
        ordinary_total=ordinary_total,
        tier0_affected=tier0_affected,
        ordinary_available=ordinary_available and ordinary_total > 0,
    )


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

    population = 0
    tier0 = 0
    tier0_direct = 0
    found = False
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
        population += max(0, int(kpis.get("domain_user_count", 0) or 0))
        tier0 += max(0, int(split.get("tier0", 0) or 0))
        tier0_direct += max(0, int(split.get("tier0_direct", 0) or 0))
    if not found or population <= 0:
        return None

    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        derive_tier0_population_stat,
    )

    return derive_tier0_population_stat(
        tier0=tier0,
        tier0_direct=tier0_direct,
        domain_user_count=population,
    )


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

#: Fold of a FINE Privilege-Tier value onto its coarse blast-radius bucket.
#: Mirrors ``attack_graph_service._coarse_tier_bucket``, which produced both the
#: map and the breakdown in the first place, so a breakdown re-derived here from
#: a filtered map is the one the producer would have written.
_COARSE_TIER_BUCKET: dict[str, str] = {
    "tier0_direct": "tier0",
    "tier0_escalation_capable": "tier0",
    "tier1": "tier1",
    "tier2": "tier2",
}


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
    excluded: frozenset[str] = frozenset(),
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

    ``excluded`` names accounts outside the measured population (machine-managed
    service accounts — see ``services/account_population``). They are dropped
    from all three outputs together, so the numerator is drawn from the same
    population as the denominator. When the drop touches an account the record
    graded, the Tier breakdown is re-derived from the surviving map rather than
    decremented, which keeps it exactly reconciled with the count it splits.
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
    if excluded:
        users -= excluded
        dropped_graded = excluded & set(tier_map)
        if dropped_graded:
            for key in dropped_graded:
                tier_map.pop(key, None)
            breakdown = {"tier0": 0, "tier1": 0, "tier2": 0}
            for tier in tier_map.values():
                breakdown[_COARSE_TIER_BUCKET.get(tier, "tier2")] += 1
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


#: Keys the engine stamps inside a ``path_axis[<class>]`` bucket that are NOT
#: per-status counts. ``total`` is the class inventory; ``exposure_total`` is the
#: subset that still describes OPEN exposure. Anything iterating a bucket as a
#: status map must skip both. Mirrored by the web view
#: (``exposure_kpis_view._PATH_AXIS_NON_STATUS_KEYS``).
PATH_AXIS_NON_STATUS_KEYS: frozenset[str] = frozenset({"total", "exposure_total"})


@dataclass(frozen=True)
class OpenExposureSplit:
    """One ``path_axis`` class bucket, split the way a client reads it.

    Three buckets that always sum to :attr:`total` — the SAME figure every
    client-facing "N routes to full domain compromise" headline prints:

    * :attr:`proven` — walked end-to-end against the live environment.
    * :attr:`partial` — a segment executed successfully, not run end-to-end.
      Its own bucket precisely because folding it into either neighbour lies:
      calling it proven overclaims, calling it configuration analysis erases
      the steps ADscan actually executed.
    * :attr:`unproven` — everything else that still carries exposure
      (theoretical, attempted, withheld for safety).

    Avenues the client's own configuration closes, and avenues ADscan had no
    surface to assess, are excluded — they are not routes into the domain.
    """

    proven: int
    partial: int
    unproven: int

    @property
    def total(self) -> int:
        """Open-exposure paths in the class (``proven + partial + unproven``)."""
        return self.proven + self.partial + self.unproven


def open_exposure_total(bucket: Mapping[str, Any] | None) -> int:
    """Return a ``path_axis`` class bucket's OPEN-exposure path count.

    Reads ``exposure_total`` (the subset describing exposure the client still
    carries), falling back to ``total`` for an artifact produced before the
    engine stamped it, so an older workspace still renders a figure.
    """
    if not isinstance(bucket, Mapping):
        return 0
    key = "exposure_total" if "exposure_total" in bucket else "total"
    try:
        return int(bucket.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def split_open_exposure(bucket: Mapping[str, Any] | None) -> OpenExposureSplit:
    """Split one ``path_axis`` class bucket into the client-facing three.

    The ONE rule for reading a compromise class as "validated / partially
    validated / identified by configuration". Every surface that prints that
    split calls this, so the hero band, the executive narrative and the section
    counts cannot answer the same question three different ways.

    ``unproven`` absorbs the remainder against :func:`open_exposure_total`, so
    the three buckets are guaranteed to reconcile to the headline figure even
    for an artifact whose status tokens this build does not recognise.
    """
    if not isinstance(bucket, Mapping):
        return OpenExposureSplit(0, 0, 0)
    proven = 0
    partial = 0
    for token, count in bucket.items():
        if token in PATH_AXIS_NON_STATUS_KEYS:
            continue
        if not carries_client_exposure(token):
            continue
        try:
            value = int(count or 0)
        except (TypeError, ValueError):
            continue
        if token in _PROVEN_STATUSES:
            proven += value
        elif token == "partial":
            partial += value
    unproven = max(0, open_exposure_total(bucket) - proven - partial)
    return OpenExposureSplit(proven=proven, partial=partial, unproven=unproven)


def compute_exposure_kpis(
    summaries: Sequence[Mapping[str, Any]],
    *,
    domain_user_count: int | None,
    executions: Sequence[Mapping[str, Any]] | None = None,
    computed_at: str | None = None,
    domain_users: Sequence[str] | None = None,
    excluded_users: Sequence[str] | None = None,
    population_tier_breakdown: Mapping[str, Any] | None = None,
    reachability: Mapping[str, int] | None = None,
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
        domain_users: The enabled domain user population itself, when the caller
            has it. Supplying the names as well as the count lets the block name
            the accounts that hold NO path — which on a small domain is the fact
            that proves the metric measures something, because a figure that
            could only ever read "all of them" tells a reader nothing. Optional:
            omitting it changes no count, it only leaves the exception unnamed.
        excluded_users: Accounts the caller removed from the measured population
            — machine-managed service accounts, whose credential is a
            KDC-rotated random value and so is not reachable by anything this
            metric measures (SSOT: ``services/account_population``). They are
            dropped from every affected set here as well, so numerator and
            denominator describe the same population, and the names are stamped
            so the document can say why the denominator reads as it does.
            ``domain_user_count`` is expected to be net of them already.
        population_tier_breakdown: ``{"tier0", "tier0_direct", "tier1",
            "tier2"}`` for the POPULATION (not the affected set) — how many
            accounts already hold each tier by membership. Stamped verbatim and
            consumed by the privilege-sprawl figure, which is what makes
            excluding the already-privileged accounts from the path figure
            defensible rather than a way of hiding them.
        reachability: Optional reachable-terminal summary (from
            ``summarize_reachable_terminals``). When supplied, stamped verbatim
            as the ``"reachability"`` key; ``None`` leaves the key absent.
            Additive — never affects ``path_axis`` / ``user_axis``.

    Returns:
        The ``exposure_kpis`` dict persisted verbatim under
        ``domains[<domain>]["exposure_kpis"]`` (schema_version 1).
    """
    user_total = (
        int(domain_user_count)
        if isinstance(domain_user_count, int) and domain_user_count > 0
        else 0
    )
    excluded: frozenset[str] = frozenset(
        norm for raw in (excluded_users or ()) if (norm := _normalize_user(raw))
    )
    population: set[str] = {
        norm for raw in (domain_users or ()) if (norm := _normalize_user(raw))
    } - excluded

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

    # path_axis[class][status] = count ; path_axis[class]["total"] = all in class ;
    # path_axis[class]["exposure_total"] = the subset that describes OPEN
    # exposure (`carries_client_exposure`). Both are kept because they answer
    # different questions: `total` is the inventory (and keeps the positive
    # `closed_by_configuration` bucket visible), `exposure_total` is the only
    # one a client-facing "you have N routes to domain compromise" may use.
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
        if carries_client_exposure(status):
            path_axis[cls]["exposure_total"] = (
                path_axis[cls].get("exposure_total", 0) + 1
            )
        distinct_paths[cls] += 1

        users, is_broad, breakdown, tier_map = _record_affected_users(record, excluded)
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

    def _resolve_population(users: set[str], broad_scope: bool) -> tuple[int, bool]:
        """Return ``(affected_count, covers_whole_domain)`` for one bucket.

        ``broad_scope`` records that a contributing path started at a broad
        group (Domain Users / Authenticated Users / Everyone). It does NOT say
        the affected population is every enabled account, and treating the two
        as the same thing is what put "10 of 10 domain users · every domain user
        is in scope" on page 2 of a run whose own enumerated list held nine: a
        broad group is not the enabled-user population, because an account whose
        primary group sits elsewhere — a group managed service account, a trust
        account — is enabled and is not a member.

        So the enumerated set wins whenever there is one, and ``all_users`` is
        then a measured fact (the set covers the population) rather than an
        assumption. Saturation survives only for the case it was written for: a
        broad-group path whose membership could not be resolved at all, where
        the alternative is printing 0 for a population known to be domain-wide.

        The count is also what the Tier 0/1/2 breakdown has to reconcile
        against before either surface may show the tier split, so an inflated
        count does not merely overstate — it silently suppresses the
        non-circular ordinary-account headline both documents lead with.
        """
        resolved = len(users)
        if resolved:
            return resolved, user_total > 0 and resolved >= user_total
        if broad_scope and user_total > 0:
            return user_total, True
        return 0, False

    def _pct(count: int) -> float:
        if user_total <= 0:
            return 0.0
        return min(100.0, round(count / user_total * 100.0, 1))

    user_axis: dict[str, dict[str, Any]] = {}
    for cls in _KPI_COMPROMISE_CLASSES:
        per_status: dict[str, Any] = {}
        for status, users in per_status_users[cls].items():
            status_count, status_all = _resolve_population(
                users, per_status_all_users[cls].get(status, False)
            )
            per_status[status] = {
                "count": status_count,
                "all_users": status_all,
            }
        any_count, any_covers_domain = _resolve_population(
            any_users[cls], any_all_users[cls]
        )
        accounts, accounts_truncated = _serialize_affected_accounts(any_users[cls])
        unaffected, unaffected_truncated = _serialize_affected_accounts(
            population - any_users[cls]
        )
        per_status["any"] = {
            "count": any_count,
            "all_users": any_covers_domain,
            "pct_of_domain": _pct(any_count),
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
            # The complement: enabled accounts that hold NO path of this class.
            # Named because a negative fact stated well is a positive result —
            # the same reasoning as reporting an avenue the client's own
            # configuration closed. It is also what demonstrates the figure can
            # read something other than "everyone", which is the objection a
            # blast-radius percentage has to survive. Empty when the caller did
            # not supply the population.
            "unaffected_accounts": unaffected,
            "unaffected_accounts_truncated": unaffected_truncated,
        }
        per_status["distinct_paths"] = distinct_paths[cls]
        user_axis[cls] = per_status

    block: dict[str, Any] = {
        "schema_version": 1,
        "computed_at": computed_at or "",
        "domain_user_count": user_total,
        "path_axis": path_axis,
        "user_axis": user_axis,
    }
    if excluded:
        # Why the denominator reads as it does. A reader who counts the accounts
        # in the appendix and lands one short is owed the reason, and the reason
        # is a positive one: this account's password is machine-managed, so it is
        # not exposed by anything this figure measures.
        block["excluded_service_accounts"] = sorted(excluded)
    if isinstance(population_tier_breakdown, Mapping):
        block["population_tier_breakdown"] = {
            bucket: max(0, int(population_tier_breakdown.get(bucket, 0) or 0))
            for bucket in ("tier0", "tier0_direct", "tier1", "tier2")
        }
    if reachability is not None:
        block["reachability"] = dict(reachability)
    return block


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


def _proof_base(status: str, record: Mapping[str, Any]) -> float | None:
    """Return the EVIDENCE-axis base for a path, or ``None`` to exclude it.

    Handles the ``blocked`` marker gate: a ``blocked`` path carrying the
    ``dangerous_destructive`` marker is a safety abstention over a
    CONFIRMED-precondition avenue (e.g. Zerologon whose over-the-wire bypass we
    PROVED, stopping before the destructive reset), so it scores ABOVE a purely
    LDAP-derived theoretical path (:data:`_CONFIRMED_DESTRUCTIVE_BASE`). A bare
    ``blocked`` (no marker) is an un-executed but supported avenue — no negative
    signal — so it is theoretical-tier, NOT attempted-tier. Every other status
    maps straight through ``_PROOF_WEIGHT`` (unknown → theoretical base, since it
    IS a supported Tier-0 path).
    """
    key = (status or "").strip().lower()
    if key == "blocked":
        marker = str(record.get("blocked_kind") or "").strip().lower()
        if marker == "dangerous_destructive":
            return _CONFIRMED_DESTRUCTIVE_BASE
        return _PROOF_WEIGHT["blocked"]
    if key in _PROOF_WEIGHT:
        return _PROOF_WEIGHT[key]
    return _PROOF_WEIGHT["theoretical"]


def _path_exploitability(record: Mapping[str, Any]) -> float:
    """Return P(a capable attacker executes this path) as the per-step product.

    Reads each of the path's ``relations``, looks up the technique's
    ``compromise_effort`` (``attack_step_catalog`` SSOT via
    ``classify_relation_support``), maps it to a rate, and MULTIPLIES across the
    actionable steps. ``context`` steps (MemberOf/Contains/GpLink — structural,
    no attacker action) are skipped. The product encodes length: more hops →
    lower weight, each weighted by its real difficulty (replaces ``ease_weight``).
    An all-context / relation-less path is deterministic (1.0).
    """
    relations = record.get("relations")
    if not isinstance(relations, list) or not relations:
        return 1.0
    product = 1.0
    saw_actionable = False
    for rel in relations:
        raw = str(rel or "")
        support = classify_relation_support(raw)
        if support.kind == "context":
            continue  # structural (MemberOf/Contains/GpLink) — no attacker action
        saw_actionable = True
        key = raw.strip().lower()
        rate = _RELATION_EXPLOITABILITY.get(key)
        if rate is None:
            # Fallback: the catalog compromise_effort mapping (coarser).
            effort = (support.compromise_effort or "other").strip().lower()
            rate = _EFFORT_TO_EXPLOITABILITY.get(
                effort, _EFFORT_TO_EXPLOITABILITY["other"]
            )
        product *= rate
    return product if saw_actionable else 1.0


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
        base = _proof_base(status, rec)
        if base is None:  # unsupported / unavailable / closed_by_configuration
            continue
        proven = _is_proven_status(status)
        # Proven paths override to their base (1.0): demonstrated compromise beats
        # the technique prior. Everything else = evidence × per-step exploitability.
        w = base if proven else base * _path_exploitability(rec)
        if w <= 0.0:
            continue
        weighted.append((w, proven, rec))

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
        f"{tier0_label} from {start_label}. Paths weigh more the more we proved "
        f"them and the more executable their techniques are (a deterministic "
        f"one-hop control edge outweighs a multi-step or crack-dependent chain); "
        f"the score saturates as paths multiply. {proven_clause} "
        "0% is reached only when every such path is remediated."
    )


__all__ = [
    "DomainUserReach",
    "ExposureScore",
    "ExposureContributor",
    "compute_exposure_score",
    "compute_exposure_kpis",
    "derive_domain_user_reach",
]
