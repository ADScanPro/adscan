"""MITRE ATT&CK Navigator layer builder.

Pure-functions module — no I/O, no network, no PRO dependencies. Produces
JSON layers conforming to the official MITRE ATT&CK Navigator layer schema
v4.5 (https://github.com/mitre-attack/attack-navigator), so the output can
be loaded directly in https://mitre-attack.github.io/attack-navigator/ —
the official, free MITRE-hosted UI.

Three artefacts are produced from the same finding stream:

    * ``build_navigator_layer``        — single-scan posture layer.
    * ``build_diff_layer``             — three-state delta between two
                                          previous layers (NEW / RESOLVED
                                          / UNCHANGED).
    * ``aggregate_findings_by_technique`` — internal helper exposed for
                                          the interactive HTML bundle.

The module is consumed both by the LITE CLI (``adscan mitre-navigator``,
which writes the snapshot JSON with a community watermark) and by the PRO
deliver pipeline (which enriches the layer, renders an interactive HTML
bundle, and snapshots the layer into the workspace history for diffing).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

# ---------------------------------------------------------------------------
# Navigator layer schema — pinned to the format ADscan emits.
# Bumping these triples requires re-validating against the upstream schema.
# ---------------------------------------------------------------------------
NAVIGATOR_LAYER_VERSION: str = "4.5"
NAVIGATOR_FORMAT_VERSION: str = "4.5"
ATTACK_VERSION: str = "14"

# Score range expected by Navigator: 0 (unobserved) → 100 (critical).
_SEVERITY_SCORE: dict[str, int] = {
    "info": 10,
    "informational": 10,
    "low": 25,
    "medium": 50,
    "moderate": 50,
    "high": 75,
    "critical": 100,
}

# Heat colour ramp — Navigator uses these per-cell when ``color`` is set.
# Five buckets keyed off the score, mapped to a colour-blind safe scale.
_COLOR_RAMP: list[tuple[int, str]] = [
    (0,   "#e7eaf0"),  # unobserved (light grey)
    (25,  "#fde68a"),  # low        (amber)
    (50,  "#fbbf24"),  # medium     (orange)
    (75,  "#f97316"),  # high       (deep orange)
    (100, "#dc2626"),  # critical   (red)
]

# Diff palette — three-state semantic colours.
DIFF_COLOR_NEW: str = "#dc2626"        # regression — newly observed
DIFF_COLOR_RESOLVED: str = "#16a34a"   # remediated — gone since previous
DIFF_COLOR_UNCHANGED: str = "#94a3b8"  # carried over

WATERMARK_COMMUNITY: str = "ADscan Community"
WATERMARK_PRO: str = "ADscan PRO"


def _normalize_severity(value: str | None) -> str:
    """Return a canonical lowercase severity label."""
    if not value:
        return "low"
    label = str(value).strip().lower()
    return label if label in _SEVERITY_SCORE else "low"


def severity_to_score(severity: str | None) -> int:
    """Map a severity label to a Navigator score (0-100)."""
    return _SEVERITY_SCORE[_normalize_severity(severity)]


def score_to_color(score: int) -> str:
    """Return the heat colour for a Navigator cell score (0-100).

    The mapping is monotonic on the curated 5-bucket ramp; arbitrary
    intermediate scores snap up to the next bucket.
    """
    bounded = max(0, min(100, int(score)))
    for threshold, colour in _COLOR_RAMP:
        if bounded <= threshold:
            return colour
    return _COLOR_RAMP[-1][1]


def _technique_mapping_for_key(key: str) -> list[dict[str, Any]]:
    """Return the catalog's ATT&CK technique list for a finding key.

    The ATT&CK mapping is a property of the finding CATALOG, not of a
    particular scan, so it is resolved here rather than expected on the
    entry. Only the PRO report path builds its vulnerability map with the
    mapping omitted (it feeds the compliance engine, whose verdicts must
    stay byte-identical), and that is exactly the path this module is fed
    from — which is why every PRO layer shipped with zero techniques while
    the catalog held a mapping for 71 of its 79 keys. Reading the catalog
    makes the layer independent of which map shape it was handed.

    Returns an empty list for an uncatalogued key or if the catalog cannot
    be imported: a finding with no mapping simply contributes no cell.
    """
    if not key:
        return []
    try:
        from adscan_core.reporting.vuln_catalog_meta import VULN_CATALOG_META
    except Exception:  # pragma: no cover - always importable in-tree
        return []
    meta = VULN_CATALOG_META.get(key)
    if not isinstance(meta, Mapping):
        return []
    mitre = meta.get("mitre")
    return [entry for entry in mitre if isinstance(entry, Mapping)] if isinstance(mitre, (list, tuple)) else []


def _iter_findings(report_data: Mapping[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield finding dicts from a ``technical_report.json`` payload.

    Tolerates both the multi-domain shape (``{domain: {vulnerabilities:
    {key: finding}}}``) and a flat single-domain dict, since the report
    layout has shifted between releases. An entry that already carries a
    ``mitre`` list keeps it; otherwise the mapping is resolved from the
    finding catalog by key, so a map built without it still produces a
    populated layer.
    """
    if not isinstance(report_data, Mapping):
        return
    for value in report_data.values():
        if not isinstance(value, Mapping):
            continue
        vulns = value.get("vulnerabilities")
        if not isinstance(vulns, Mapping):
            continue
        for key, finding in vulns.items():
            key_text = str(key or "")
            # A detail-less finding is stored as ``True`` rather than a dict
            # (the PRO base map collapses it). It still names a real weakness
            # with a real technique mapping, so it must not be skipped.
            entry: Mapping[str, Any] = finding if isinstance(finding, Mapping) else {}
            if not isinstance(finding, Mapping) and finding is not True:
                continue
            mitre = entry.get("mitre")
            if not isinstance(mitre, (list, tuple)) or not mitre:
                mitre = _technique_mapping_for_key(key_text)
            # Surface the catalog key when the finding has no explicit title.
            yield {
                "key": key_text,
                "title": entry.get("title") or entry.get("_title") or key_text,
                "severity": entry.get("severity") or entry.get("_severity"),
                "mitre": list(mitre),
            }


def aggregate_findings_by_technique(
    findings: Iterable[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Collapse findings into one entry per ATT&CK technique.

    Each finding may map to multiple techniques (``mitre`` list with
    ``{id, name}`` dicts). The aggregate keeps the highest severity seen
    per technique and the list of finding titles that fired it.

    Args:
        findings: Iterable of finding dicts. ``mitre`` is expected to be
            a list of ``{id, name}`` mappings. Anything else is skipped.

    Returns:
        ``{technique_id: {name, max_severity, count, hits: [{title,
        severity}]}}`` — empty when no finding maps to any technique.
    """
    aggregate: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        mitre_list = finding.get("mitre") or []
        if not isinstance(mitre_list, (list, tuple)):
            continue
        severity = _normalize_severity(finding.get("severity"))
        title = str(finding.get("title") or finding.get("key") or "")
        for entry in mitre_list:
            if not isinstance(entry, Mapping):
                continue
            tid = str(entry.get("id") or "").strip()
            if not tid:
                continue
            slot = aggregate.get(tid)
            if slot is None:
                slot = {
                    "id": tid,
                    "name": str(entry.get("name") or tid),
                    "max_severity": severity,
                    "count": 0,
                    "hits": [],
                }
                aggregate[tid] = slot
            slot["count"] += 1
            if _SEVERITY_SCORE[severity] > _SEVERITY_SCORE[slot["max_severity"]]:
                slot["max_severity"] = severity
            slot["hits"].append({"title": title, "severity": severity})
    return aggregate


def _build_layer_envelope(
    *,
    name: str,
    description: str,
    domain: str | None,
    watermark: str,
) -> dict[str, Any]:
    """Return the static envelope expected by Navigator (no techniques yet).

    The envelope mirrors the schema defaults Navigator ships with. ADscan
    diverges only on legend, gradient, and metadata — every other field
    is left to Navigator's own defaults to stay forward-compatible.
    """
    full_description = description
    if domain:
        full_description = f"{description} — domain: {domain}"
    full_description = f"{full_description} (generated by {watermark})"

    return {
        "name": name,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_LAYER_VERSION,
            "layer": NAVIGATOR_FORMAT_VERSION,
        },
        "domain": "enterprise-attack",
        "description": full_description,
        "filters": {"platforms": ["Windows", "Azure AD", "Office 365"]},
        "sorting": 3,  # techniques sorted by score descending
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": ["#e7eaf0", "#fbbf24", "#dc2626"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Low", "color": _COLOR_RAMP[1][1]},
            {"label": "Medium", "color": _COLOR_RAMP[2][1]},
            {"label": "High", "color": _COLOR_RAMP[3][1]},
            {"label": "Critical", "color": _COLOR_RAMP[4][1]},
        ],
        "metadata": [
            {"name": "generated_by", "value": watermark},
            {"name": "tool", "value": "ADscan"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#0f172a",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def build_navigator_layer(
    findings: Iterable[Mapping[str, Any]] | Mapping[str, Any],
    *,
    name: str = "ADscan AD Posture",
    description: str = "Active Directory adversary technique exposure",
    domain: str | None = None,
    watermark: str = WATERMARK_COMMUNITY,
    extra_metadata: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build a Navigator v4.5 layer from a finding stream.

    Args:
        findings: Either an iterable of finding dicts (preferred) or a
            ``technical_report.json``-shaped mapping. The mapping form is
            normalised internally.
        name: Layer name shown in Navigator's tab.
        description: Layer description (a domain suffix is appended when
            ``domain`` is provided).
        domain: Optional AD domain FQDN — embedded in the description and
            metadata so a CISO opening the layer knows which assessment
            it represents.
        watermark: Source attribution. Use :data:`WATERMARK_COMMUNITY`
            for LITE exports (viral marketing) and :data:`WATERMARK_PRO`
            for paid-tier exports.
        extra_metadata: Additional ``{name: value}`` metadata entries
            appended after the defaults — useful for engagement codes,
            assessment dates, or scan IDs.

    Returns:
        A dict ready to ``json.dump`` and load in Navigator.
    """
    if isinstance(findings, Mapping):
        finding_iter = list(_iter_findings(findings))
    else:
        finding_iter = list(findings)

    aggregate = aggregate_findings_by_technique(finding_iter)
    envelope = _build_layer_envelope(
        name=name,
        description=description,
        domain=domain,
        watermark=watermark,
    )

    if domain:
        envelope["metadata"].append({"name": "ad_domain", "value": domain})
    if extra_metadata:
        for k, v in extra_metadata.items():
            envelope["metadata"].append({"name": str(k), "value": str(v)})

    techniques: list[dict[str, Any]] = []
    for tid in sorted(aggregate.keys()):
        data = aggregate[tid]
        score = severity_to_score(data["max_severity"])
        # Comment surfaces the highest-severity finding titles so the
        # analyst sees *why* a cell is hot without leaving Navigator.
        top_titles = [
            h["title"] for h in
            sorted(
                data["hits"],
                key=lambda h: -_SEVERITY_SCORE[_normalize_severity(h["severity"])],
            )[:5]
        ]
        comment_lines = [
            f"{data['count']} finding(s) — max severity: {data['max_severity']}",
        ]
        if top_titles:
            comment_lines.append("Top hits:")
            comment_lines.extend(f"• {t}" for t in top_titles if t)
        techniques.append({
            "techniqueID": tid,
            "score": score,
            "color": score_to_color(score),
            "comment": "\n".join(comment_lines),
            "enabled": True,
            "metadata": [
                {"name": "finding_count", "value": str(data["count"])},
                {"name": "max_severity", "value": data["max_severity"]},
            ],
            "showSubtechniques": False,
        })

    envelope["techniques"] = techniques
    return envelope


def build_diff_layer(
    current: Mapping[str, Any],
    previous: Mapping[str, Any],
    *,
    name: str = "ADscan Posture Diff",
    domain: str | None = None,
    watermark: str = WATERMARK_PRO,
) -> dict[str, Any]:
    """Return a three-state delta layer between two posture snapshots.

    Each technique present in either layer is emitted with one of three
    semantic states encoded in the cell colour and comment:

        * **NEW**       — present in ``current`` only (regression).
        * **RESOLVED**  — present in ``previous`` only (improvement).
        * **UNCHANGED** — present in both (carried over).

    Args:
        current: Most recent layer (the result of a fresh scan).
        previous: Reference layer (the prior snapshot).
        name: Layer name shown in Navigator.
        domain: Optional AD domain — appended to description.
        watermark: Source attribution. Defaults to PRO since diffing is a
            paid-tier feature.

    Returns:
        A Navigator v4.5 layer dict whose techniques carry colour-coded
        diff state. Identical to ``build_navigator_layer`` shape — safe
        to drop into the same UI.
    """
    cur_techs = {t["techniqueID"]: t for t in current.get("techniques", []) if isinstance(t, Mapping)}
    prev_techs = {t["techniqueID"]: t for t in previous.get("techniques", []) if isinstance(t, Mapping)}

    envelope = _build_layer_envelope(
        name=name,
        description="Posture diff vs previous scan",
        domain=domain,
        watermark=watermark,
    )
    envelope["legendItems"] = [
        {"label": "NEW (regression)", "color": DIFF_COLOR_NEW},
        {"label": "RESOLVED (fixed)", "color": DIFF_COLOR_RESOLVED},
        {"label": "UNCHANGED", "color": DIFF_COLOR_UNCHANGED},
    ]
    envelope["gradient"] = {
        "colors": [DIFF_COLOR_RESOLVED, DIFF_COLOR_UNCHANGED, DIFF_COLOR_NEW],
        "minValue": -1,
        "maxValue": 1,
    }

    diff_techniques: list[dict[str, Any]] = []
    for tid in sorted(set(cur_techs) | set(prev_techs)):
        in_cur = tid in cur_techs
        in_prev = tid in prev_techs
        if in_cur and not in_prev:
            state, colour, score = "NEW", DIFF_COLOR_NEW, 1
            sev = (cur_techs[tid].get("comment") or "").splitlines()[0] if cur_techs[tid].get("comment") else ""
        elif in_prev and not in_cur:
            state, colour, score = "RESOLVED", DIFF_COLOR_RESOLVED, -1
            sev = (prev_techs[tid].get("comment") or "").splitlines()[0] if prev_techs[tid].get("comment") else ""
        else:
            state, colour, score = "UNCHANGED", DIFF_COLOR_UNCHANGED, 0
            sev = (cur_techs[tid].get("comment") or "").splitlines()[0] if cur_techs[tid].get("comment") else ""
        diff_techniques.append({
            "techniqueID": tid,
            "score": score,
            "color": colour,
            "comment": f"{state}\n{sev}".strip(),
            "enabled": True,
            "metadata": [{"name": "diff_state", "value": state}],
            "showSubtechniques": False,
        })

    envelope["techniques"] = diff_techniques
    return envelope


def diff_summary(
    current: Mapping[str, Any],
    previous: Mapping[str, Any],
) -> dict[str, int]:
    """Return ``{new, resolved, unchanged}`` counts between two layers."""
    cur = {t["techniqueID"] for t in current.get("techniques", []) if isinstance(t, Mapping)}
    prev = {t["techniqueID"] for t in previous.get("techniques", []) if isinstance(t, Mapping)}
    return {
        "new": len(cur - prev),
        "resolved": len(prev - cur),
        "unchanged": len(cur & prev),
    }


__all__ = (
    "ATTACK_VERSION",
    "DIFF_COLOR_NEW",
    "DIFF_COLOR_RESOLVED",
    "DIFF_COLOR_UNCHANGED",
    "NAVIGATOR_FORMAT_VERSION",
    "NAVIGATOR_LAYER_VERSION",
    "WATERMARK_COMMUNITY",
    "WATERMARK_PRO",
    "aggregate_findings_by_technique",
    "build_diff_layer",
    "build_navigator_layer",
    "diff_summary",
    "score_to_color",
    "severity_to_score",
)
