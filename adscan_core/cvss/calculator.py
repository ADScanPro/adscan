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

from dataclasses import dataclass
from typing import Any, Callable

from adscan_core.cvss.contextual_rules import get_vuln_cvss_definition
from adscan_core.cvss.models import (
    CONDITION_DC_TARGETS,
    CONDITION_EXPLOITATION,
    CONDITION_TIER_ZERO,
    CvssContext,
    CvssElevationRule,
)
from adscan_core.cvss.severity_mapper import score_to_severity


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BaseCvssResult:
    """Formal CVSS Base output.

    Attributes:
        scheme: Scoring scheme name.
        version: CVSS version, e.g. "3.1". ``None`` when no formal vector exists.
        score: Numeric base score.
        severity: Severity label mapped from the score.
        vector: CVSS Base vector string, or ``None``.
        source: Where the base score came from.
    """

    scheme: str
    version: str | None
    score: float
    severity: str
    vector: str | None
    source: str


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
    """Combined severity output for one finding instance."""

    base: BaseCvssResult
    adscan: AdscanPriorityResult
    context: CvssContext
    display_score: float
    display_severity: str

    @property
    def cvss_base_score(self) -> float:
        return self.base.score

    @property
    def cvss_base_vector(self) -> str | None:
        return self.base.vector

    @property
    def adscan_effective_score(self) -> float:
        return self.adscan.score


# ---------------------------------------------------------------------------
# Internal fallback catalog lookup
# ---------------------------------------------------------------------------

def _base_score_from_catalog(vuln_key: str) -> tuple[float, str]:
    """Return (numeric base score, source label) from the vulnerability catalog.

    Tries both the CLI catalog and the web-service catalog. Falls back to
    ``0.0`` when the key is not found in either.

    Returns:
        (score, source)
    """
    try:
        from adscan_internal.pro.reporting.vuln_catalog import get_vuln_cvss_value

        score = float(get_vuln_cvss_value(vuln_key))
        if score > 0.0:
            return score, "cli_catalog"
    except (ImportError, Exception):
        pass

    try:
        from app.services.vuln_catalog import VULN_CATALOG as _WEB_CATALOG

        entry = _WEB_CATALOG.get(vuln_key, {})
        raw = entry.get("cvss")
        if isinstance(raw, (int, float)):
            score = float(raw)
            if score > 0.0:
                return score, "web_catalog"

        raw_str = str(raw or "").strip()
        for token in raw_str.replace("(", " ").replace(")", " ").split():
            try:
                score = float(token)
                if score >= 0.0:
                    return score, "web_catalog_legacy_parse"
            except ValueError:
                continue
    except (ImportError, Exception):
        pass

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
_CONTEXT_EXTRACTORS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {}


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

    # --- Affected assets injected by report builder ---
    affected_assets = details.get("_affected_assets")
    if isinstance(affected_assets, dict):
        users = affected_assets.get("users", [])
        hosts = affected_assets.get("hosts", [])
        total_affected = len(users) + len(hosts)

        for asset in users + hosts:
            if not isinstance(asset, dict):
                continue
            if _boolish(asset.get("is_tier_zero")) or _boolish(asset.get("tier_zero")):
                has_tier_zero = True
                tier_zero_count += 1
            if _boolish(asset.get("is_dc")) or _boolish(asset.get("is_domain_controller")):
                has_dc = True
                dc_count += 1

    elif isinstance(affected_assets, list):
        total_affected = len(affected_assets)
        for asset in affected_assets:
            if not isinstance(asset, dict):
                continue
            if _boolish(asset.get("is_tier_zero")) or _boolish(asset.get("tier_zero")):
                has_tier_zero = True
                tier_zero_count += 1
            if _boolish(asset.get("is_dc")) or _boolish(asset.get("is_domain_controller")):
                has_dc = True
                dc_count += 1

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
    """Return the formal CVSS Base result for a finding type."""
    looked_up_score, source = _base_score_from_catalog(vuln_key)
    base_score = catalog_base_score if catalog_base_score is not None else looked_up_score

    definition = get_vuln_cvss_definition(vuln_key)
    cvss_vector = definition.cvss_vector if definition else None

    version = "3.1" if cvss_vector else None

    return BaseCvssResult(
        scheme="CVSS",
        version=version,
        score=float(base_score),
        severity=score_to_severity(float(base_score)),
        vector=cvss_vector,
        source="override" if catalog_base_score is not None else source,
    )


# ---------------------------------------------------------------------------
# ADscan contextual severity overlay
# ---------------------------------------------------------------------------

def _matching_conditions(context: CvssContext) -> dict[str, bool]:
    return {
        CONDITION_TIER_ZERO: context.has_tier_zero_targets,
        CONDITION_DC_TARGETS: context.has_dc_targets,
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
    """Return the full severity model for one finding instance."""
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
        base=base,
        adscan=adscan,
        context=context,
        display_score=adscan.score,
        display_severity=adscan.severity,
    )


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

    This replaces the old contextual 'cvss_fn' usage semantically, but note:
    the returned value is ADscan contextual severity, not formal CVSS.
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
