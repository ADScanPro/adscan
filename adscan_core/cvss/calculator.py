"""Severity calculator for ADscan reports.

Design goals
------------
1. Keep a formally defensible CVSS Base result.
2. Keep ADscan's contextual prioritization logic, but label it clearly as
   ADscan-specific severity rather than "effective CVSS".
3. Preserve easy integration with the current report generator.
4. Leave a clean path for future CVSS v4 support.

Important semantics
-------------------
- base.score / base.vector:
    Formal CVSS Base output only.
- adscan.score:
    ADscan contextual prioritization overlay (Tier-0 / DC / exploitation /
    other environment-specific signals). This is NOT CVSS Base.
- display_score / display_severity:
    Recommended primary value for report prioritization when you want the
    report to reflect real AD risk to the client.

Public API
----------
compute_base_cvss_result(vuln_key, *, catalog_base_score=None)
compute_adscan_priority_result(vuln_key, context, *, catalog_base_score=None)
compute_finding_severity(vuln_key, context, *, catalog_base_score=None)
extract_context_from_details(vuln_key, details)
make_finding_severity_fn(vulnerabilities_map)
make_report_priority_fn(vulnerabilities_map)
make_report_cvss_base_fn(vulnerabilities_map)
make_global_finding_severity_fn(json_data)
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable

from adscan_core.cvss.contextual_rules import get_vuln_cvss_definition
from adscan_core.cvss.models import (
    CONDITION_DC_TARGETS,
    CONDITION_EXPLOITATION,
    CONDITION_RELAY_CONFIRMED,
    CONDITION_TIER_ZERO,
    CvssContext,
    CvssElevationRule,
    FindingType,
)
from adscan_core.cvss.severity_mapper import score_to_severity, severity_to_min_score
from adscan_core.cvss.vector_score import score_from_vector
from adscan_core.reporting.affected_assets_contract import (
    AFFECTED_ASSETS_STRUCT_KEY,
    LEGACY_AFFECTED_ASSETS_KEY,
)
from adscan_core.reporting.privilege_tier_labels import token_is_tier0


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BaseCvssResult:
    """The baseline score of a finding, and its formal CVSS Base when it has one.

    Two different numbers live here and only one of them is CVSS:

    * ``score`` is ADscan's own baseline for the finding key, read from the
      vulnerability catalog. It is the floor the contextual priority overlay
      builds on. It is **not** a CVSS score and must never be labelled as one.
    * ``formal_score`` is the CVSS Base score recomputed from ``vector`` per the
      FIRST v3.1 equations, and is ``None`` for any finding without a Base
      vector (posture findings, chain prerequisites, and any vulnerability we
      have not scored formally). A reader can verify it; that is the whole
      point of calling something CVSS.

    Presenting ``score`` as "CVSS Base" is what let one deliverable print
    ``CVSS Base 5.0`` above the line "no CVSS Base applies", and print a Base
    score a reader could falsify against the vector shown beside it. Consumers
    show a CVSS Base **only** when :attr:`has_formal_base` is true, and use
    :attr:`formal_score` — never ``score`` — as its value.

    Attributes:
        scheme: Scoring scheme name.
        version: CVSS version, e.g. "3.1". ``None`` when no formal vector exists.
        score: ADscan's catalog baseline for the key (the priority floor).
        severity: Severity label mapped from ``score``.
        vector: CVSS Base vector string, or ``None``.
        source: Where the baseline score came from.
        formal_score: CVSS Base score derived from ``vector``, or ``None``.
    """

    scheme: str
    version: str | None
    score: float
    severity: str
    vector: str | None
    source: str
    formal_score: float | None = None

    @property
    def has_formal_base(self) -> bool:
        """Whether this finding has a verifiable CVSS Base score."""
        return self.formal_score is not None


@dataclass(frozen=True)
class AdscanPriorityResult:
    """ADscan contextual severity overlay.

    This is not a CVSS score. It is an ADscan-specific prioritization layer
    that uses environmental and exploitation context.

    Attributes:
        scheme: Scoring scheme name.
        version: Internal methodology version.
        score: Effective ADscan priority score.
        severity: Severity label mapped from the score.
        is_elevated: Whether the score was elevated beyond the base.
        matched_conditions: Ordered list of matched rule condition names.
        applied_rule: The rule that won, if any.
        reason: Human-readable reason for elevation.
    """

    scheme: str
    version: str
    score: float
    severity: str
    is_elevated: bool
    matched_conditions: tuple[str, ...] = ()
    applied_rule: CvssElevationRule | None = None
    reason: str | None = None


@dataclass(frozen=True)
class FindingSeverityResult:
    """Combined severity output for one finding instance.

    Attributes:
        finding_type: Canonical taxonomy classification — drives how UI/PDF
            renders the finding (badge variant, label) and informs whether
            a CVSS Base vector is even applicable.
        base: Formal CVSS Base output (only meaningful for VULNERABILITY-typed
            findings — for CHAIN_PREREQUISITE / POSTURE the score is a
            reasonable Medium-grade baseline rather than a real CVSS).
        adscan: ADscan contextual priority overlay.
        context: The CvssContext used for the computation.
        display_score / display_severity: Recommended primary value for
            prioritization in reports and dashboards.
    """

    finding_type: FindingType
    base: BaseCvssResult
    adscan: AdscanPriorityResult
    context: CvssContext
    display_score: float
    display_severity: str

    @property
    def cvss_base_score(self) -> float | None:
        """The verifiable CVSS Base score, or ``None`` when there is none."""
        return self.base.formal_score

    @property
    def has_formal_cvss_base(self) -> bool:
        """Whether a CVSS Base score may be shown for this finding."""
        return self.base.has_formal_base

    @property
    def cvss_base_vector(self) -> str | None:
        return self.base.vector

    @property
    def adscan_effective_score(self) -> float:
        return self.adscan.score

    @property
    def is_vulnerability(self) -> bool:
        return self.finding_type == FindingType.VULNERABILITY

    @property
    def is_chain_prerequisite(self) -> bool:
        return self.finding_type == FindingType.CHAIN_PREREQUISITE

    @property
    def is_posture(self) -> bool:
        return self.finding_type == FindingType.POSTURE


# ---------------------------------------------------------------------------
# Internal fallback catalog lookup
# ---------------------------------------------------------------------------

def _authored_catalog_band(vuln_key: str) -> str:
    """Return the severity band the finding catalog AUTHORS for *vuln_key*.

    Reads the active catalog (the PRO catalog when its provider is installed,
    the LITE-safe meta slice otherwise), so it resolves in every deployment,
    the web backend included. Returns ``""`` for a key no catalog knows.
    """
    try:
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            finding_catalog,
        )

        entry = finding_catalog().get(vuln_key)
    except Exception:  # noqa: BLE001 - an unloadable catalog falls back below
        entry = None
    if not isinstance(entry, Mapping):
        try:
            from adscan_core.reporting.vuln_catalog_meta import (  # noqa: PLC0415
                VULN_CATALOG_META,
            )

            entry = VULN_CATALOG_META.get(vuln_key)
        except Exception:  # noqa: BLE001
            entry = None
    if not isinstance(entry, Mapping):
        return ""
    band = str(entry.get("severity") or "").strip().lower()
    return band if band in _PUBLISHED_BANDS else ""


_PUBLISHED_BANDS = frozenset({"critical", "high", "medium", "low", "info"})


def baseline_score_for_band(band: str) -> float:
    """Return ADscan's numeric baseline for a finding authored in *band*.

    The ONE baseline the contextual priority overlay builds on, used by the
    scan's stamp and by every surface that scores a finding. It is the floor of
    the band, never the catalog's ``cvss`` scalar: that scalar is a CVSS-shaped
    number (76 of the 93 keys carry it with no vector, and 14 of the 17 that do
    contradict their own vector), and a client surface does not print a CVSS
    score. Reading it as the baseline is what made the paid report print
    ``8.8`` where the scan itself, the platform and the free report printed
    ``7.0`` for the same finding: the PRO image loads the catalog that carries
    the scalar and the others do not.

    Args:
        band: A published severity band.

    Returns:
        The band's floor, or ``0.0`` for an unknown band.
    """
    normalized = str(band or "").strip().lower()
    if normalized not in _PUBLISHED_BANDS:
        return 0.0
    return severity_to_min_score(normalized)


def _base_score_from_catalog(vuln_key: str) -> tuple[float, str]:
    """Return (numeric baseline, source label) for a finding key.

    The baseline is the floor of the band the catalog AUTHORS for the key
    (:func:`baseline_score_for_band`). It never reads the catalog ``cvss``
    scalar. Falls back to ``0.0`` when no catalog knows the key.

    Returns:
        (score, source)
    """
    band = _authored_catalog_band(vuln_key)
    if band:
        return baseline_score_for_band(band), "authored_band"
    return 0.0, "fallback_0.0"


# ---------------------------------------------------------------------------
# Context extraction
# ---------------------------------------------------------------------------

_TIER_ZERO_DETAIL_KEYS = (
    "tier_zero_accounts",
    "tier_zero_targets",
    "high_value_accounts",
    "privileged_accounts",
    "tier0_accounts",
)

_DC_HOST_DETAIL_KEYS = (
    "dc_hosts",
    "domain_controller_hosts",
    "dcs",
)

# Generic exploitation hints.
_GENERIC_EXPLOITATION_DETAIL_KEYS = (
    "exploitation_confirmed",
    "exploited",
    "relay_success",
    "success",
)

# Per-family exploitation hints.
_EXPLOITATION_KEYS_BY_VULN: dict[str, tuple[str, ...]] = {
    "kerberoast": ("cracked", "hash_cracked", "password_recovered"),
    "asreproast": ("cracked", "hash_cracked", "password_recovered"),
    "gpp_passwords": ("password_recovered", "credentials_verified", "valid_login"),
    "gpp_autologin": ("password_recovered", "credentials_verified", "valid_login"),
    "smb_share_secrets": ("password_recovered", "credentials_verified", "valid_login"),
    "smb_guest_shares": ("password_recovered", "credentials_verified", "valid_login"),
    "ldap_security_posture": ("relay_success", "ldap_write_success", "shadow_creds_added"),
    "petitpotam": ("relay_success", "cert_issued", "ldap_write_success"),
    "dfscoerce": ("relay_success", "cert_issued", "ldap_write_success"),
    "mseven": ("relay_success", "cert_issued", "ldap_write_success"),
    "printerbug": ("relay_success", "cert_issued", "ldap_write_success"),
}

# Optional future refinement: registry of vuln-specific extractors.
def _recovered_password_context(details: dict[str, Any]) -> dict[str, Any]:
    """Elevate the password-recovery finding on the ADMIN-LIKE count.

    Severity has to key on whether an ADMINISTRATIVE account's password was
    recovered, not on how many were. A hundred ordinary accounts with
    recoverable passwords is a hygiene programme with a budget and a timeline;
    one administrative account is an incident, and a severity driven by volume
    averages the second away inside the first (the reference engagement had 122
    ordinary and 4 administrative).

    ``exploitation_confirmed`` is set whenever an enabled account was recovered,
    because that is precisely what the flag is for: an outcome ADscan
    MATERIALISED, not an opportunity it identified. The password is in hand.
    """
    try:
        admin_like = int(details.get("admin_like_recovered") or 0)
    except (TypeError, ValueError):
        admin_like = 0
    try:
        enabled = int(details.get("enabled_recovered") or 0)
    except (TypeError, ValueError):
        enabled = 0
    return {
        "has_tier_zero_targets": admin_like > 0,
        "tier_zero_count": max(admin_like, 0),
        "total_affected": max(enabled, 0),
        "exploitation_confirmed": enabled > 0,
    }


def _reversible_encryption_context(details: dict[str, Any]) -> dict[str, Any]:
    """Grade reversible password storage on the scope of the policy that sets it.

    The finding is domain-wide, so its affected asset is the domain itself, which
    carries no privilege tier, and nothing else would ever raise it. What
    separates the cases is WHICH policy enables the setting. The Default Domain
    Password Policy covers privileged accounts (unless a fine-grained policy
    overrides it for them), so it puts Tier 0 passwords in recoverable form; a
    fine-grained policy alone applies only to the principals it targets, and the
    workspace does not show those are privileged, so it stays at its baseline.
    """
    observed = details.get("observed")
    if not isinstance(observed, Mapping):
        return {}
    if _boolish(observed.get("default_domain_policy")):
        return {"has_tier_zero_targets": True}
    return {}


_CONTEXT_EXTRACTORS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "recovered_account_passwords": _recovered_password_context,
    "reversible_encryption_enabled": _reversible_encryption_context,
}


@dataclass(frozen=True)
class _AffectedAssetScan:
    """What one affected-asset collection says about the affected population.

    The Tier-0 and DC members are sets of identities rather than counters so the
    same asset listed twice in one finding (once as the source of an edge, once
    as its target) counts once. A finding that inflates its Tier-0 count by
    double-listing the one account it found reads as a wider compromise than it
    proved.
    """

    total: int
    tier_zero: frozenset[str]
    dc: frozenset[str]


def _asset_identity(asset: Mapping[str, Any], position: int) -> str:
    """A stable identity for one affected asset, for de-duplicated counting."""
    for field in ("identifier", "node_id", "sid", "fqdn", "name", "asset", "display"):
        value = asset.get(field)
        if isinstance(value, str) and value.strip():
            return f"{asset.get('type') or ''}:{value.strip().lower()}"
    return f"#{position}"


def _asset_is_tier_zero(asset: Mapping[str, Any]) -> bool:
    """Whether one affected asset sits inside the Tier 0 containment boundary.

    Reads the STAMPED, membership-and-ACL-aware ``tier`` token the engine writes
    onto every structured entity, through the tier SSOT — so an account that is
    Tier 0 only by control-plane group membership (a Backup Operators member,
    graded ``tier0_escalation_capable``) counts, exactly as the nomenclature
    standard requires. Reading the legacy ``isTierZero`` boolean instead is what
    made these conditions unreachable: it is RID-gated at collection time and
    legitimately reads false for a membership-derived Tier 0.

    The legacy ``is_tier_zero`` / ``tier_zero`` booleans are still honoured so an
    older persisted finding keeps elevating. An absent or unrecognised tier is
    NOT Tier 0: a false elevation is the dangerous direction.
    """
    if token_is_tier0(asset.get("tier")):
        return True
    return _boolish(asset.get("is_tier_zero")) or _boolish(asset.get("tier_zero"))


def _scan_affected_assets(raw: Any) -> _AffectedAssetScan | None:
    """Summarise one affected-asset collection, or ``None`` when there is none.

    Accepts every shape a finding has ever carried: the live list of structured
    entities, the legacy ``{"users": [...], "hosts": [...]}`` mapping, and the
    legacy flat list (whose members may be bare display strings, which count
    toward the total and carry no tier).

    The structured entity contract carries no domain-controller marker, so DC
    detection stays on the explicit ``dc_hosts`` / ``has_dc_targets`` detail keys
    the caller already reads; only a legacy entry's own ``is_dc`` is honoured
    here. Inferring "domain controller" from a Tier-0 tier would be wrong, since
    a certificate authority grades Tier 0 without being a DC.
    """
    if isinstance(raw, Mapping):
        entries: list[Any] = []
        for bucket in ("users", "hosts", "computers", "groups"):
            value = raw.get(bucket)
            if isinstance(value, list):
                entries.extend(value)
    elif isinstance(raw, list):
        entries = list(raw)
    else:
        return None

    tier_zero: set[str] = set()
    dc: set[str] = set()
    for position, asset in enumerate(entries):
        if not isinstance(asset, Mapping):
            continue
        identity = _asset_identity(asset, position)
        if _asset_is_tier_zero(asset):
            tier_zero.add(identity)
        if _boolish(asset.get("is_dc")) or _boolish(asset.get("is_domain_controller")):
            dc.add(identity)

    return _AffectedAssetScan(
        total=len(entries),
        tier_zero=frozenset(tier_zero),
        dc=frozenset(dc),
    )


def _boolish(val: Any) -> bool:
    """Interpret a few common truthy string forms safely."""
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val != 0
    if isinstance(val, str):
        return val.strip().lower() in {"1", "true", "yes", "y", "confirmed"}
    return False


def extract_context_from_details(
    vuln_key: str,
    details: dict[str, Any] | None,
) -> CvssContext:
    """Derive a ``CvssContext`` from a raw finding details dictionary.

    Strategy:
    1. Generic explicit fields in ``details``.
    2. Affected-asset summaries injected by report generation.
    3. Attack-graph annotations.
    4. Optional vuln-specific extractor hook.
    """
    if not details or not isinstance(details, dict):
        return CvssContext.empty()

    has_tier_zero = False
    has_dc = False
    tier_zero_count = 0
    dc_count = 0
    total_affected = 0
    exploitation_confirmed = False

    # --- Tier-Zero detection ---
    for key in _TIER_ZERO_DETAIL_KEYS:
        val = details.get(key)
        if isinstance(val, bool) and val:
            has_tier_zero = True
        elif isinstance(val, list) and val:
            has_tier_zero = True
            tier_zero_count = max(tier_zero_count, len(val))
        elif isinstance(val, (int, float)) and val > 0:
            has_tier_zero = True
            tier_zero_count = max(tier_zero_count, int(val))

    # --- DC detection ---
    for key in _DC_HOST_DETAIL_KEYS:
        val = details.get(key)
        if isinstance(val, bool) and val:
            has_dc = True
        elif isinstance(val, list) and val:
            has_dc = True
            dc_count = max(dc_count, len(val))

    if (
        _boolish(details.get("has_dc_targets"))
        or _boolish(details.get("includes_dc"))
        or _boolish(details.get("dc_affected"))
    ):
        has_dc = True

    # --- Exploitation detection ---
    per_vuln_keys = _EXPLOITATION_KEYS_BY_VULN.get(vuln_key, ())
    for key in (*_GENERIC_EXPLOITATION_DETAIL_KEYS, *per_vuln_keys):
        if _boolish(details.get(key)):
            exploitation_confirmed = True
            break

    # --- Affected assets stamped by the engine ---
    # The live key is the structured one; the legacy flat key is read too so an
    # older persisted finding keeps whatever elevation it already had. Both are
    # scanned (never one instead of the other) and the result is the union.
    for key in (AFFECTED_ASSETS_STRUCT_KEY, LEGACY_AFFECTED_ASSETS_KEY):
        scan = _scan_affected_assets(details.get(key))
        if scan is None:
            continue
        total_affected = max(total_affected, scan.total)
        if scan.tier_zero:
            has_tier_zero = True
            tier_zero_count = max(tier_zero_count, len(scan.tier_zero))
        if scan.dc:
            has_dc = True
            dc_count = max(dc_count, len(scan.dc))

    # --- Attack graph edge annotations ---
    edges = details.get("attack_graph_edges")
    if isinstance(edges, list):
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            notes = edge.get("notes") or {}
            if isinstance(notes, dict):
                if _boolish(notes.get("is_tier_zero")) or _boolish(notes.get("tier_zero_target")):
                    has_tier_zero = True
                if _boolish(notes.get("is_dc")) or _boolish(notes.get("dc_target")):
                    has_dc = True

    # --- Attack path annotations ---
    attack_paths = details.get("attack_paths") or details.get("_attack_paths")
    if isinstance(attack_paths, list):
        for path in attack_paths:
            if not isinstance(path, dict):
                continue
            if _boolish(path.get("is_tier_zero")):
                has_tier_zero = True
            if _boolish(path.get("is_dc")):
                has_dc = True

    # --- Optional vuln-specific extractor hook ---
    extractor = _CONTEXT_EXTRACTORS.get(vuln_key)
    if extractor:
        try:
            extra = extractor(details) or {}
            if _boolish(extra.get("has_tier_zero_targets")):
                has_tier_zero = True
            if _boolish(extra.get("has_dc_targets")):
                has_dc = True
            tier_zero_count = max(tier_zero_count, int(extra.get("tier_zero_count", 0) or 0))
            dc_count = max(dc_count, int(extra.get("dc_count", 0) or 0))
            total_affected = max(total_affected, int(extra.get("total_affected", 0) or 0))
            if _boolish(extra.get("exploitation_confirmed")):
                exploitation_confirmed = True
        except Exception:
            # Best-effort: extractor hooks must not break report generation.
            pass

    return CvssContext(
        has_tier_zero_targets=has_tier_zero,
        has_dc_targets=has_dc,
        tier_zero_count=tier_zero_count,
        dc_count=dc_count,
        total_affected=total_affected,
        exploitation_confirmed=exploitation_confirmed,
    )


# ---------------------------------------------------------------------------
# Base CVSS
# ---------------------------------------------------------------------------

def compute_base_cvss_result(
    vuln_key: str,
    *,
    catalog_base_score: float | None = None,
) -> BaseCvssResult:
    """Return the baseline score for a finding key, plus its formal CVSS Base.

    ``score`` stays the catalog baseline the contextual overlay builds on.
    ``formal_score`` is computed from the finding's Base vector, so it is
    present only where a vector exists and always agrees with that vector.
    """
    looked_up_score, source = _base_score_from_catalog(vuln_key)
    base_score = catalog_base_score if catalog_base_score is not None else looked_up_score

    definition = get_vuln_cvss_definition(vuln_key)
    cvss_vector = definition.cvss_vector if definition else None
    formal_score = score_from_vector(cvss_vector)

    version = "3.1" if formal_score is not None else None

    return BaseCvssResult(
        scheme="CVSS",
        version=version,
        score=float(base_score),
        severity=score_to_severity(float(base_score)),
        vector=cvss_vector if formal_score is not None else None,
        source="override" if catalog_base_score is not None else source,
        formal_score=formal_score,
    )


# ---------------------------------------------------------------------------
# ADscan contextual severity overlay
# ---------------------------------------------------------------------------

def _matching_conditions(context: CvssContext) -> dict[str, bool]:
    return {
        CONDITION_TIER_ZERO: context.has_tier_zero_targets,
        CONDITION_DC_TARGETS: context.has_dc_targets,
        CONDITION_RELAY_CONFIRMED: context.relay_confirmed,
        CONDITION_EXPLOITATION: context.exploitation_confirmed,
    }


def _select_best_rule(
    vuln_key: str,
    context: CvssContext,
    *,
    base_score: float,
) -> tuple[CvssElevationRule | None, tuple[str, ...]]:
    """Return the best matching elevation rule and the matched conditions.

    Unlike the old implementation, this does not depend purely on declaration
    order. It gathers all matching rules and picks the one with the highest
    elevated score. Ties preserve declaration order.
    """
    definition = get_vuln_cvss_definition(vuln_key)
    if not definition or not definition.elevation_rules:
        return None, ()

    condition_map = _matching_conditions(context)
    matched_conditions = tuple(
        condition for condition, matched in condition_map.items() if matched
    )

    matched_rules: list[CvssElevationRule] = [
        rule for rule in definition.elevation_rules if condition_map.get(rule.condition, False)
    ]
    if not matched_rules:
        return None, matched_conditions

    best_rule = max(
        matched_rules,
        key=lambda rule: (float(rule.elevated_score), -definition.elevation_rules.index(rule)),
    )

    if float(best_rule.elevated_score) <= float(base_score):
        return None, matched_conditions

    return best_rule, matched_conditions


def compute_adscan_priority_result(
    vuln_key: str,
    context: CvssContext,
    *,
    catalog_base_score: float | None = None,
) -> AdscanPriorityResult:
    """Return ADscan's contextual severity overlay.

    This is intentionally separate from formal CVSS.
    """
    base = compute_base_cvss_result(vuln_key, catalog_base_score=catalog_base_score)
    best_rule, matched_conditions = _select_best_rule(
        vuln_key,
        context,
        base_score=base.score,
    )

    if not best_rule:
        return AdscanPriorityResult(
            scheme="ADSCAN",
            version="contextual-v1",
            score=base.score,
            severity=base.severity,
            is_elevated=False,
            matched_conditions=matched_conditions,
            applied_rule=None,
            reason=None,
        )

    effective_score = max(float(best_rule.elevated_score), float(base.score))

    return AdscanPriorityResult(
        scheme="ADSCAN",
        version="contextual-v1",
        score=effective_score,
        severity=score_to_severity(effective_score),
        is_elevated=effective_score > base.score,
        matched_conditions=matched_conditions,
        applied_rule=best_rule,
        reason=best_rule.reason,
    )


# ---------------------------------------------------------------------------
# Unified result
# ---------------------------------------------------------------------------

def compute_finding_severity(
    vuln_key: str,
    context: CvssContext,
    *,
    catalog_base_score: float | None = None,
) -> FindingSeverityResult:
    """Return the full severity model for one finding instance.

    Resolves the finding's canonical type from the contextual rules registry.
    Findings not registered in ``CVSS_RULES`` default to
    ``FindingType.VULNERABILITY`` to preserve backward compatibility with
    legacy detectors that may not yet be classified — these still receive a
    formal CVSS Base score from the catalog.
    """
    definition = get_vuln_cvss_definition(vuln_key)
    finding_type = definition.finding_type if definition else FindingType.VULNERABILITY

    base = compute_base_cvss_result(
        vuln_key,
        catalog_base_score=catalog_base_score,
    )
    adscan = compute_adscan_priority_result(
        vuln_key,
        context,
        catalog_base_score=base.score,
    )

    return FindingSeverityResult(
        finding_type=finding_type,
        base=base,
        adscan=adscan,
        context=context,
        display_score=adscan.score,
        display_severity=adscan.severity,
    )


def finding_severity_for_record(
    vuln_key: str,
    details: Any = None,
) -> FindingSeverityResult:
    """Return the severity model for a finding AS THE SCAN RECORDED IT.

    The one call every client-facing surface makes to score a finding it holds
    the details of: the assessment report's finding cards, the hardening
    playbook, the security checklist and the compliance sections. It resolves
    the finding's own context (Tier-0 targets, DC targets, confirmed
    exploitation) and returns the full model, whose ``display_score`` is the
    ADscan Priority the deliverable prints.

    Three surfaces used to each build this call themselves, and each drift was
    the same shape: one document printed the contextual priority (ESC2 at 9.9)
    while another printed the catalog baseline it is built on (8.5), for the
    same finding in the same kit. Route new surfaces through here instead of
    composing ``extract_context_from_details`` + ``compute_finding_severity``
    again.

    Args:
        vuln_key: Vulnerability catalog key.
        details: The finding's recorded details mapping, if any.

    Returns:
        The finding's :class:`FindingSeverityResult`.
    """
    context = extract_context_from_details(
        vuln_key, dict(details) if isinstance(details, Mapping) else None
    )
    recorded_band = ""
    if isinstance(details, Mapping):
        recorded_band = str(details.get(RECORDED_BASELINE_BAND_KEY) or "").strip().lower()
    catalog_base_score = (
        baseline_score_for_band(recorded_band)
        if recorded_band in _PUBLISHED_BANDS
        else None
    )
    result = compute_finding_severity(
        vuln_key, context, catalog_base_score=catalog_base_score
    )
    return _with_authored_priority(result, details)


#: Key under which a report's vulnerability map carries the finding's RECORDED
#: baseline band (the band the scan's stamp built on).
RECORDED_BASELINE_BAND_KEY = "_severity"
#: Key under which a report's vulnerability map carries the ADscan Priority the
#: scan STAMPED onto the finding (``technical_report.stamp_adscan_severity``).
AUTHORED_PRIORITY_SCORE_KEY = "_adscan_priority_score"
#: Key under which it carries the stamped contextual band.
AUTHORED_SEVERITY_KEY = "_adscan_severity"


def _with_authored_priority(
    result: FindingSeverityResult, details: Any
) -> FindingSeverityResult:
    """Return *result* carrying the priority the SCAN stamped, when it has one.

    The scan computes the ADscan Priority once and persists it on the finding;
    every surface prints THAT number. A render that recomputes may hold a
    slightly different context (a later affected-asset stamp), and two numbers
    for one finding in one kit is the defect this closes. So when the record
    carries the stamped score, the display value is the stamp.
    """
    if not isinstance(details, Mapping):
        return result
    raw = details.get(AUTHORED_PRIORITY_SCORE_KEY)
    if raw is None or isinstance(raw, bool):
        return result
    try:
        score = round(float(raw), 1)
    except (TypeError, ValueError):
        return result
    band = str(details.get(AUTHORED_SEVERITY_KEY) or "").strip().lower()
    if band not in _PUBLISHED_BANDS:
        band = score_to_severity(score)
    from dataclasses import replace  # noqa: PLC0415

    adscan = replace(
        result.adscan,
        score=score,
        severity=band,
        is_elevated=bool(result.adscan.is_elevated) and score > result.base.score,
    )
    return replace(result, adscan=adscan, display_score=score, display_severity=band)


# ---------------------------------------------------------------------------
# Report generator factories
# ---------------------------------------------------------------------------

def make_finding_severity_fn(
    vulnerabilities_map: dict[str, Any],
) -> Callable[[str], FindingSeverityResult]:
    """Return a closure that yields the full severity result per vuln key."""
    def _severity_fn(vuln_key: str) -> FindingSeverityResult:
        raw = vulnerabilities_map.get(vuln_key)
        details: dict[str, Any] = raw if isinstance(raw, dict) else {}
        context = extract_context_from_details(vuln_key, details)
        return compute_finding_severity(vuln_key, context)

    return _severity_fn


def make_report_priority_fn(
    vulnerabilities_map: dict[str, Any],
) -> Callable[[str], float]:
    """Return the score you should use for report prioritization/order.

    This is what consumers take as their ``priority_fn``: the returned value is
    the ADscan contextual priority, not a formal CVSS score. The parameter used
    to be called ``cvss_fn`` everywhere, which is how a reader of
    ``compliance_section_builder`` concluded the DORA / ENS / ISO / PCI
    conformity verdicts were graded by CVSS when they never were.
    """
    severity_fn = make_finding_severity_fn(vulnerabilities_map)

    def _priority_fn(vuln_key: str) -> float:
        return severity_fn(vuln_key).adscan.score

    return _priority_fn


def make_report_cvss_base_fn(
    vulnerabilities_map: dict[str, Any],
) -> Callable[[str], float]:
    """Return the formal CVSS Base score for reporting/comparison."""
    severity_fn = make_finding_severity_fn(vulnerabilities_map)

    def _base_fn(vuln_key: str) -> float:
        return severity_fn(vuln_key).base.score

    return _base_fn


def make_global_finding_severity_fn(
    json_data: dict[str, Any],
) -> Callable[[str], FindingSeverityResult]:
    """Return a closure that searches all domains and keeps the highest-priority
    result for the given vulnerability key.
    """
    def _severity_fn(vuln_key: str) -> FindingSeverityResult:
        best: FindingSeverityResult | None = None

        for domain_data in json_data.values():
            if not isinstance(domain_data, dict):
                continue

            vulns = domain_data.get("vulnerabilities") or {}
            if not isinstance(vulns, dict) or vuln_key not in vulns:
                continue

            raw = vulns.get(vuln_key)
            details: dict[str, Any] = raw if isinstance(raw, dict) else {}
            context = extract_context_from_details(vuln_key, details)
            result = compute_finding_severity(vuln_key, context)

            if best is None or result.adscan.score > best.adscan.score:
                best = result

        if best is not None:
            return best

        return compute_finding_severity(vuln_key, CvssContext.empty())

    return _severity_fn


def make_global_report_priority_fn(
    json_data: dict[str, Any],
) -> Callable[[str], float]:
    """Global report-priority helper."""
    severity_fn = make_global_finding_severity_fn(json_data)

    def _priority_fn(vuln_key: str) -> float:
        return severity_fn(vuln_key).adscan.score

    return _priority_fn


def make_global_cvss_base_fn(
    json_data: dict[str, Any],
) -> Callable[[str], float]:
    """Global formal CVSS Base helper."""
    severity_fn = make_global_finding_severity_fn(json_data)

    def _base_fn(vuln_key: str) -> float:
        return severity_fn(vuln_key).base.score

    return _base_fn
