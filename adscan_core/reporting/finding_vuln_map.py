"""LITE-safe finding -> vulnerability-map projection.

The on-disk ``technical_report.json`` stores ``domains[*].findings`` populated
but ``domains[*].vulnerabilities`` empty/``null`` -- the vuln map is a derived
view synthesized on demand. This module owns the base projection from a domain's
flat findings list to the ``{vuln_key: entry}`` mapping consumed by:

    * the LITE ``adscan mitre-navigator`` CLI (which reads ``entry["mitre"]``
      to build the ATT&CK Navigator layer), and
    * the PRO report builder (which layers ``_affected_assets`` / ``_evidence``
      enrichment on top of this base for the compliance engine and renderers).

It lives under ``adscan_core`` so it survives the LITE image strip and can be
imported from any tier. It has **no** dependency on ``adscan_internal/pro`` --
the ATT&CK technique metadata comes from the LITE-safe
:data:`~adscan_core.reporting.vuln_catalog_meta.VULN_CATALOG_META` slice.

Single source of truth: the PRO ``_build_vuln_map_from_findings`` calls this
function for the base map, so the finding-key gating logic cannot diverge
between tiers.
"""

from __future__ import annotations

from typing import Any, Mapping

from adscan_core.reporting.finding_aliases import collapse_finding_aliases
from adscan_core.reporting.vuln_catalog_meta import VULN_CATALOG_META


def is_catalog_finding_key(
    key: Any,
    *,
    catalog_meta: Mapping[str, dict[str, Any]] = VULN_CATALOG_META,
) -> bool:
    """Return whether *key* names a real vulnerability finding.

    The single gate every report surface shares. A key is a genuine finding
    only when it exists in the finding catalog (``VULN_CATALOG_META``, kept
    drift-locked to the PRO ``VULN_CATALOG``). Anything else -- posture/coverage
    metrics like ``*_count``, ad-hoc keys recorded directly into
    ``technical_report.json`` with no catalog entry -- is NOT a finding and must
    not reach any finding-rendering surface.

    Centralising the gate here is what keeps the three consumers (main PDF
    builder via :func:`build_vuln_map_from_findings`, the bonus playbook
    databinding, and the ``adscan_web`` ingestion) from diverging: a non-catalog
    key can no longer render as an empty card in one surface while the main PDF
    silently drops it.

    Args:
        key: Candidate finding key (any type; non-strings are rejected).
        catalog_meta: The finding-key catalog to gate against. Defaults to the
            LITE-safe :data:`VULN_CATALOG_META`.

    Returns:
        ``True`` iff ``key`` is a non-empty string present in ``catalog_meta``.
    """
    if not isinstance(key, str):
        return False
    return key.strip() in catalog_meta


#: Severity labels a genuine recorded finding carries. A record whose severity
#: is outside this set is not a finding the client inventory can rank.
_FINDING_SEVERITIES: frozenset[str] = frozenset(
    {"critical", "high", "medium", "low", "info"}
)

#: Legacy metric residue. ``update_report_field`` now routes every non-catalog
#: key to ``control_evidence``, so the current recorder cannot produce these
#: under ``findings[]`` any more -- but workspaces written before that gate
#: landed still carry counters like ``unauth_users_count`` in the findings
#: list, and a counter is coverage data, never a client finding.
_LEGACY_METRIC_KEY_SUFFIXES: tuple[str, ...] = ("_count",)


def is_reportable_finding(
    finding: Any,
    *,
    catalog_meta: Mapping[str, dict[str, Any]] = VULN_CATALOG_META,
) -> bool:
    """Return whether a recorded finding belongs in the client inventory.

    The RENDER-time gate, and the counterpart to :func:`is_catalog_finding_key`
    (which is the RECORD-time gate: given only a key, does it name a catalog
    finding?). The two answer different questions and both are needed.

    A catalogued key is always reportable. An **uncatalogued** one still is,
    provided the record is a well-formed finding -- a key, a title, and a
    severity from :data:`_FINDING_SEVERITIES`. That fallback is the whole point:
    an uncatalogued finding must degrade to the data the recorder already
    stamped on it, never vanish. It vanishing is how the paid deliverable came
    to report fewer findings than the free one from the same scan
    (``ldap_user_description_password_leak`` had a detector, an affected-asset
    rule and a coverage mapping, but no catalog entry, so PRO dropped it while
    LITE showed it).

    The one exclusion is legacy metric residue (``*_count``): counters written
    into ``findings[]`` by workspaces that predate the ``update_report_field``
    routing gate. Those are coverage data and must not resurface as findings.

    Args:
        finding: One entry from a domain's ``findings`` list.
        catalog_meta: The finding-key catalog. Defaults to the LITE-safe
            :data:`VULN_CATALOG_META`.

    Returns:
        ``True`` when the record should reach a finding-rendering surface.
    """
    if not isinstance(finding, Mapping):
        return False
    key = str(finding.get("key") or "").strip()
    if not key:
        return False
    if is_catalog_finding_key(key, catalog_meta=catalog_meta):
        return True
    if key.endswith(_LEGACY_METRIC_KEY_SUFFIXES):
        return False
    if not str(finding.get("title") or "").strip():
        return False
    return str(finding.get("severity") or "").strip().lower() in _FINDING_SEVERITIES


def build_vuln_map_from_findings(
    findings: list[dict[str, Any]] | None,
    *,
    catalog_meta: Mapping[str, dict[str, Any]] = VULN_CATALOG_META,
    attach_mitre: bool = True,
) -> dict[str, Any]:
    """Project a domain's flat findings list onto the legacy vulnerability map.

    Gated by :func:`is_reportable_finding`: a catalogued key always survives, an
    uncatalogued but well-formed finding survives on its own recorded title and
    severity, and legacy metric residue (``*_count``) is dropped. Each kept
    entry is the finding's ``details`` dict (copied so callers cannot mutate the
    source report), or ``True`` when there are no details and ``attach_mitre``
    is off.

    Args:
        findings: The domain's ``findings`` list from ``technical_report.json``.
            ``None`` / non-list inputs yield an empty map.
        catalog_meta: The finding-key -> metadata slice gating which findings are
            kept and supplying the ATT&CK ``mitre`` list. Defaults to the
            LITE-safe :data:`VULN_CATALOG_META`.
        attach_mitre: When ``True`` (default, LITE/Navigator path), the catalog's
            ``mitre`` list is attached to each synthesized entry under the
            ``mitre`` key so ATT&CK technique aggregation works. When ``False``
            (PRO base-map path), no ``mitre`` key is added, keeping the entry
            byte-identical to the historical PRO base so compliance verdicts do
            not change.

    Returns:
        ``{vuln_key: entry}`` where ``entry`` is a ``dict`` (the finding details,
        optionally with a ``mitre`` key) or ``True`` for detail-less findings.
    """
    vuln_map: dict[str, Any] = {}
    if not isinstance(findings, list):
        return vuln_map
    # One weakness, one entry: two producers recording the same weakness under
    # their own spellings collapse into the family's canonical key before the
    # map is built, so a client never sees it listed twice at two severities.
    for finding in collapse_finding_aliases(findings):
        if not isinstance(finding, dict):
            continue
        if not is_reportable_finding(finding, catalog_meta=catalog_meta):
            continue
        key = str(finding.get("key") or "").strip()
        details = finding.get("details")
        entry: dict[str, Any] = dict(details) if isinstance(details, dict) else {}
        if attach_mitre:
            # An uncatalogued finding has no ATT&CK mapping to attach; it still
            # belongs in the map, it simply contributes no technique cell.
            mitre = (catalog_meta.get(key) or {}).get("mitre") or []
            if mitre:
                entry["mitre"] = list(mitre)
            vuln_map[key] = entry
        else:
            # PRO base-map parity: detail-less findings collapse to ``True``.
            vuln_map[key] = entry or True
    return vuln_map


__all__ = (
    "build_vuln_map_from_findings",
    "is_catalog_finding_key",
    "is_reportable_finding",
)
