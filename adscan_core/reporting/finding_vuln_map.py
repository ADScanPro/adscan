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


def build_vuln_map_from_findings(
    findings: list[dict[str, Any]] | None,
    *,
    catalog_meta: Mapping[str, dict[str, Any]] = VULN_CATALOG_META,
    attach_mitre: bool = True,
) -> dict[str, Any]:
    """Project a domain's flat findings list onto the legacy vulnerability map.

    Gated on the catalog keyset: only findings whose ``key`` exists in
    ``catalog_meta`` become vuln entries (keeps the report focused, matching the
    historical PRO behaviour). Each kept entry is the finding's ``details`` dict
    (copied so callers cannot mutate the source report), or ``True`` when there
    are no details and ``attach_mitre`` is off.

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
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = str(finding.get("key") or "").strip()
        if not key:
            continue
        if not is_catalog_finding_key(key, catalog_meta=catalog_meta):
            # Skip non-vulnerability findings (keeps the report focused).
            continue
        details = finding.get("details")
        entry: dict[str, Any] = dict(details) if isinstance(details, dict) else {}
        if attach_mitre:
            mitre = catalog_meta[key].get("mitre") or []
            if mitre:
                entry["mitre"] = list(mitre)
            vuln_map[key] = entry
        else:
            # PRO base-map parity: detail-less findings collapse to ``True``.
            vuln_map[key] = entry or True
    return vuln_map


__all__ = ("build_vuln_map_from_findings", "is_catalog_finding_key")
