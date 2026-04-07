"""Contextual CVSS scoring calculator.

Public API
----------
``compute_contextual_score(vuln_key, context, *, catalog_base_score)``
    Core function.  Takes a vulnerability key, an environmental context, and
    an optional override for the base score (looked up from the catalog when
    not provided).  Returns a ``CvssResult``.

``extract_context_from_details(vuln_key, details)``
    Derives a ``CvssContext`` from the raw finding ``details`` dict produced
    by the scanner.  Works for both CLI report generation and web ingestion.

``make_contextual_cvss_fn(vulnerabilities_map)``
    Factory that wraps the calculator as a ``Callable[[str], float]`` closure
    compatible with the existing ``cvss_fn`` protocol used throughout the
    report generator.  Pass the per-domain vulnerability dict so the closure
    can build context for each vulnerability key.
"""

from __future__ import annotations

from typing import Any, Callable

from adscan_core.cvss.contextual_rules import get_vuln_cvss_definition
from adscan_core.cvss.models import (
    CONDITION_DC_TARGETS,
    CONDITION_EXPLOITATION,
    CONDITION_TIER_ZERO,
    CvssContext,
    CvssResult,
)
from adscan_core.cvss.severity_mapper import score_to_severity

# ---------------------------------------------------------------------------
# Internal fallback catalog lookup
# ---------------------------------------------------------------------------

def _base_score_from_catalog(vuln_key: str) -> float:
    """Return the numeric base CVSS score from the vulnerability catalog.

    Tries both the CLI catalog and the web-service catalog.  Falls back to
    0.0 when the key is not found in either.

    Args:
        vuln_key: Canonical vulnerability key.

    Returns:
        Numeric CVSS score, or 0.0.
    """
    # Try CLI catalog first (canonical source).
    try:
        from adscan_internal.pro.reporting.vuln_catalog import get_vuln_cvss_value
        score = get_vuln_cvss_value(vuln_key)
        if score > 0.0:
            return score
    except (ImportError, Exception):
        pass

    # Try web-service catalog.
    try:
        from app.services.vuln_catalog import VULN_CATALOG as _WEB_CATALOG
        entry = _WEB_CATALOG.get(vuln_key, {})
        raw = str(entry.get("cvss", "")).strip()
        for token in raw.replace("(", " ").replace(")", " ").split():
            try:
                return float(token)
            except ValueError:
                continue
    except (ImportError, Exception):
        pass

    return 0.0


# ---------------------------------------------------------------------------
# Context extraction from raw finding details
# ---------------------------------------------------------------------------

# Detail-dict keys that indicate Tier-0 or high-value accounts.
_TIER_ZERO_DETAIL_KEYS = (
    "tier_zero_accounts",
    "tier_zero_targets",
    "high_value_accounts",
    "privileged_accounts",
    "tier0_accounts",
)

# Detail-dict keys that carry lists of affected DC hostnames.
_DC_HOST_DETAIL_KEYS = (
    "dc_hosts",
    "domain_controller_hosts",
    "dcs",
)

# Detail-dict keys that indicate confirmed exploitation.
_EXPLOITATION_DETAIL_KEYS = (
    "exploitation_confirmed",
    "cracked",
    "exploited",
    "hash_cracked",
    "password_recovered",
    "relay_success",
)


def extract_context_from_details(
    vuln_key: str,
    details: dict[str, Any] | None,
) -> CvssContext:
    """Derive a ``CvssContext`` from a raw finding details dictionary.

    This is called during CLI report generation (from ``make_contextual_cvss_fn``)
    and during web-service ingestion (``ingestion_service._ingest_findings``).

    The extractor applies a layered strategy:
    1. Explicit boolean/list fields in ``details`` (most reliable).
    2. Affected-asset summaries injected by the report builder (``_affected_assets``).
    3. Attack-graph path annotations (``attack_graph_edges``, ``is_tier_zero``).

    Args:
        vuln_key: Canonical vulnerability key (e.g. ``"kerberoast"``).
        details: Raw finding details dict from ``technical_report.json``.
            May be ``None`` or empty.

    Returns:
        ``CvssContext`` populated with whatever signals are detectable.
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

    # Scalar DC flag (e.g. from smb_relay_targets details)
    if details.get("has_dc_targets") or details.get("includes_dc") or details.get("dc_affected"):
        has_dc = True

    # --- Exploitation detection ---
    for key in _EXPLOITATION_DETAIL_KEYS:
        val = details.get(key)
        if val:
            exploitation_confirmed = True
            break

    # --- Affected assets injected by report builder ---
    affected_assets = details.get("_affected_assets")
    if isinstance(affected_assets, dict):
        users = affected_assets.get("users", [])
        hosts = affected_assets.get("hosts", [])
        total_affected = len(users) + len(hosts)

        # Check for is_tier_zero / is_dc flags on individual assets.
        for asset in users + hosts:
            if not isinstance(asset, dict):
                continue
            if asset.get("is_tier_zero") or asset.get("tier_zero"):
                has_tier_zero = True
                tier_zero_count += 1
            if asset.get("is_dc") or asset.get("is_domain_controller"):
                has_dc = True
                dc_count += 1
    elif isinstance(affected_assets, list):
        total_affected = len(affected_assets)
        for asset in affected_assets:
            if not isinstance(asset, dict):
                continue
            if asset.get("is_tier_zero") or asset.get("tier_zero"):
                has_tier_zero = True
                tier_zero_count += 1
            if asset.get("is_dc") or asset.get("is_domain_controller"):
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
                if notes.get("is_tier_zero") or notes.get("tier_zero_target"):
                    has_tier_zero = True
                if notes.get("is_dc") or notes.get("dc_target"):
                    has_dc = True

    # --- Attack path tier-zero annotations (web ingestion payload) ---
    attack_paths = details.get("attack_paths") or details.get("_attack_paths")
    if isinstance(attack_paths, list):
        for path in attack_paths:
            if not isinstance(path, dict):
                continue
            if path.get("is_tier_zero"):
                has_tier_zero = True

    return CvssContext(
        has_tier_zero_targets=has_tier_zero,
        has_dc_targets=has_dc,
        tier_zero_count=tier_zero_count,
        dc_count=dc_count,
        total_affected=total_affected,
        exploitation_confirmed=exploitation_confirmed,
    )


# ---------------------------------------------------------------------------
# Core calculator
# ---------------------------------------------------------------------------

def compute_contextual_score(
    vuln_key: str,
    context: CvssContext,
    *,
    catalog_base_score: float | None = None,
) -> CvssResult:
    """Compute the effective CVSS score for a finding instance.

    The function evaluates the ordered elevation rules for *vuln_key* against
    *context*.  The first matching rule wins (highest-impact condition first).
    When no rule matches, or no rules are defined, the base score is returned
    unchanged.

    Args:
        vuln_key: Canonical vulnerability catalog key.
        context: Environmental context derived from the finding.
        catalog_base_score: Override for the base score.  When ``None``, the
            base score is looked up from the vulnerability catalog.

    Returns:
        ``CvssResult`` with base and effective scores, severity labels, the
        CVSS 3.1 vector string, and elevation metadata.
    """
    base_score = (
        catalog_base_score
        if catalog_base_score is not None
        else _base_score_from_catalog(vuln_key)
    )
    base_severity = score_to_severity(base_score)

    definition = get_vuln_cvss_definition(vuln_key)
    cvss_vector = definition.cvss_vector if definition else None

    # Evaluate elevation rules.
    if definition and context.is_elevated():
        condition_map = {
            CONDITION_TIER_ZERO: context.has_tier_zero_targets,
            CONDITION_DC_TARGETS: context.has_dc_targets,
            CONDITION_EXPLOITATION: context.exploitation_confirmed,
        }
        for rule in definition.elevation_rules:
            if condition_map.get(rule.condition):
                effective_score = max(rule.elevated_score, base_score)
                if effective_score > base_score:
                    return CvssResult(
                        base_score=base_score,
                        base_severity=base_severity,
                        effective_score=effective_score,
                        effective_severity=score_to_severity(effective_score),
                        cvss_vector=cvss_vector,
                        is_elevated=True,
                        elevation_reason=rule.reason,
                        context=context,
                    )

    # No elevation — return base score.
    return CvssResult(
        base_score=base_score,
        base_severity=base_severity,
        effective_score=base_score,
        effective_severity=base_severity,
        cvss_vector=cvss_vector,
        is_elevated=False,
        elevation_reason=None,
        context=context,
    )


# ---------------------------------------------------------------------------
# cvss_fn factory for the report generator
# ---------------------------------------------------------------------------

def make_contextual_cvss_fn(
    vulnerabilities_map: dict[str, Any],
) -> Callable[[str], float]:
    """Return a ``cvss_fn`` closure suitable for the report-generator protocol.

    The closure captures *vulnerabilities_map* (a per-domain ``{key: details}``
    dict) and computes the contextual effective score for each key when called.

    This is a drop-in replacement for the module-level ``get_cvss_value``
    function in ``report_generator.py``, used wherever per-domain context is
    available.

    Args:
        vulnerabilities_map: Mapping of ``vuln_key → details_dict`` for one
            domain in the report JSON (``json_data[domain]["vulnerabilities"]``).

    Returns:
        ``Callable[[str], float]`` — accepts a vulnerability key, returns the
        effective CVSS score as a float.

    Example::

        cvss_fn = make_contextual_cvss_fn(domain_data["vulnerabilities"])
        collect_valid_vulnerabilities(vulns, is_valid_fn=…, cvss_fn=cvss_fn)
    """
    def _cvss_fn(vuln_key: str) -> float:
        raw = vulnerabilities_map.get(vuln_key)
        details: dict[str, Any] = raw if isinstance(raw, dict) else {}
        context = extract_context_from_details(vuln_key, details)
        result = compute_contextual_score(vuln_key, context)
        return result.effective_score

    return _cvss_fn


def make_global_cvss_fn(
    json_data: dict[str, Any],
) -> Callable[[str], float]:
    """Return a ``cvss_fn`` that searches all domains for the best context.

    Used by multi-domain render functions (executive summary, technical
    snapshot) where a single ``cvss_fn`` must handle vulnerabilities from
    all assessed domains.  When a key appears in multiple domains, the
    context with the highest effective score wins.

    Args:
        json_data: Full report dict (``{domain: {vulnerabilities: {…}}}``).

    Returns:
        ``Callable[[str], float]``.
    """
    def _cvss_fn(vuln_key: str) -> float:
        best_score = 0.0
        for domain_data in json_data.values():
            if not isinstance(domain_data, dict):
                continue
            vulns = domain_data.get("vulnerabilities") or {}
            if not isinstance(vulns, dict) or vuln_key not in vulns:
                continue
            raw = vulns.get(vuln_key)
            details: dict[str, Any] = raw if isinstance(raw, dict) else {}
            context = extract_context_from_details(vuln_key, details)
            result = compute_contextual_score(vuln_key, context)
            if result.effective_score > best_score:
                best_score = result.effective_score
        # Fall back to catalog base score if key not in json_data at all.
        if best_score == 0.0:
            best_score = _base_score_from_catalog(vuln_key)
        return best_score

    return _cvss_fn
