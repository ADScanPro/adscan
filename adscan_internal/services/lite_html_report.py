"""Exposure report for the LITE (community) tier — one template, HTML + PDF.

This is the LITE counterpart to the PRO deliverable kit. From ONE template it
emits two copies of the same report:

* a self-contained ``.html`` — inline CSS, inline SVG, no external assets, no
  CDN, no network at view time — so the file survives being emailed as an
  attachment and opens anywhere with no reader;
* a paginated ``.pdf``, rendered from that same markup through the shared
  Chromium engine (:mod:`adscan_internal.services.report_engines`, the same
  engine the PRO kit renders through). Corporate mail gateways routinely strip
  or quarantine HTML attachments, and a CISO putting something in front of a
  board or an auditor forwards a PDF — the artifact's whole job is to
  circulate, so it exists in the format that circulates.

Both are drawn on the shared design system
(:mod:`adscan_internal.services.report_design`): the same warm-bone paper, the
same type stacks, the same severity scale and the same components as the paid
deliverable. What differs is COMPOSITION, not craft — this is a short document
someone forwards to their manager, so it opens on a masthead rather than a
cover page and states its verdict in one sentence instead of a full-page
spread. The free report is the only artifact most people ever see; it is the
sample of the work, and it is dressed accordingly.

PDF-vs-HTML is deliberately NOT the paid boundary: Chromium ships in the LITE
image, so withholding a format we can already produce would be an artificial
limitation. The paid boundary is absent capability, listed below.

It is the free-tier artifact a team can circulate internally: a scored
one-pager built from the user's own scan.

The commercial boundary is deliberate and lives here. This report includes only
the evidence LITE already computes:

* the 0-100 posture score (:mod:`adscan_core.posture_score`),
* the severity breakdown of findings,
* the findings themselves (title, severity, ATT&CK mapping — the LITE slice),
  each naming the objects it affects, resolved through the tier-shared
  :mod:`adscan_internal.services.affected_assets` so a finding names the same
  account, host, share or certificate template it names in the paid kit,
* the validated attack paths with each step's honest status.

It EXCLUDES everything that makes a consultant pay for PRO: compliance mapping
(DORA / NIS2 / ENS / ISO 27001 / PCI), a remediation roadmap, white-labelling /
custom branding, and anything CTEM / continuous. Those stay in the PRO kit.

LITE-safety (hard constraints — the whole ``adscan_internal/pro`` tree is
physically deleted from the LITE image):

* This module imports NOTHING from ``adscan_internal.pro`` /
  ``adscan_internal.reporting`` at module level. It reads finding metadata from
  the LITE-safe :data:`~adscan_core.reporting.vuln_catalog_meta.VULN_CATALOG_META`
  slice, attack-step prose from the LITE-safe
  :mod:`adscan_internal.services.attack_step_catalog` (whose PRO lookups are all
  lazy + best-effort, degrading cleanly when PRO is absent), and affected assets
  from the tier-shared :mod:`adscan_internal.services.affected_assets_struct`.
* A LITE ``technical_report.json`` has findings with ``key``, ``title``,
  ``severity``, ``status`` but NO rich ``knowledge`` prose and no ``cvss_base``
  (both are omitted by the recorder in LITE). This renderer never reads those
  fields, so a PRO-produced JSON renders identically to a LITE one — the report
  is the LITE shape regardless of which tier produced the input.

Honesty (CLAUDE.md § Nomenclature Standard):

* Compromise-reach labels come only from
  :func:`adscan_internal.services.compromise_class.compromise_reach_label_short`
  — never hand-rolled. The FULL form (``compromise_reach_label``) is a LEGEND
  DEFINITION, not a per-row caption: it opens with "Validated path to …", which
  on a THEORETICAL row contradicts the status chip beside it. This document has
  no legend, so it never carries the full form at all.
* A step or path that did not succeed is never attributed to a defensive
  control. The status labels are the doctrine-legal ones: "Validated",
  "Partially Validated", "Attempted", "Not Executed for Safety", "Attack
  Surface Reduced", "Not Assessed", "Theoretical".
* "Proven" is tested against the SSOT set
  :data:`~adscan_internal.services.path_state._PROVEN_STATUSES`, never a bare
  ``== "exploited"`` literal.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, select_autoescape

from adscan_core import telemetry
from adscan_core.offline import offline_mode_enabled
from adscan_core.outbound_links import (
    cta_display_url,
    cta_link_style,
    cta_markup,
    cta_url,
)
from adscan_core.posture_score import (
    BAND_ACCEPTABLE,
    BAND_ELEVATED,
    BAND_HEALTHY,
    CRITICAL_BAND_TOP,
    PostureInputs,
    PostureScore,
    compute_posture_score,
)
from adscan_core.reporting.technical_report import _get_technical_report_path
from adscan_core.reporting.vuln_catalog_meta import VULN_CATALOG_META
from adscan_core.rich_output import (
    print_error,
    print_exception,
    print_warning,
)
from adscan_internal.services.adcs_path_display import (
    extract_adcs_authority_names,
    extract_adcs_template_names,
)
from adscan_internal.services.affected_assets_struct import (
    SERIALIZED_KEY,
    TYPE_DOMAIN,
)
from adscan_internal.services.attack_path_presentation import (
    order_paths_for_client_presentation,
)
from adscan_internal.services.attack_relation_labels import (
    format_business_relation_label,
    format_relation_label,
)
from adscan_internal.services.attack_step_catalog import (
    get_attack_step_entry,
    render_step_narrative,
)
from adscan_internal.services.attack_surface_analysis import (
    compute_attack_surface_analysis,
    top_remediation_targets,
)
from adscan_internal.services.brand_assets import (
    brand_favicon_data_uri,
    brand_logo_svg_markup,
)
from adscan_internal.services.compromise_class import (
    CompromiseClass,
    compromise_reach_label_short,
)
from adscan_internal.services.environment_change_ledger import (
    EnvironmentChangeResolution,
    resolve_environment_changes,
)
from adscan_internal.services.exposure_score_service import (
    DomainUserReach,
    derive_domain_user_reach,
    derive_posture_path_inputs,
)
from adscan_internal.services.path_state import _PROVEN_STATUSES
from adscan_internal.services.report_design import load_design_css

# How many attack paths to render before collapsing the rest into an honest
# "N more omitted" note. A dump of every path is not an artifact anyone
# forwards; the client-presentation ordering puts the most valuable ones first.
MAX_RENDERED_PATHS = 15

# How many steps of a single path to render inline before summarising the tail.
MAX_RENDERED_STEPS = 10

_SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")

# Attack-step relations that are pure graph-expansion context, not a technique a
# reader needs narrated (kept out of the step list so the story reads cleanly).
_CONTEXT_RELATIONS: frozenset[str] = frozenset({"memberof", "hassession"})

_REPORT_FILENAME_PREFIX = "adscan_exposure_report"
# The upgrade links inside the rendered HTML/PDF document. The terminal
# panel that announces the report uses the ``report_ready_panel``
# placement instead, so a click from the document and a click from the
# shell stay distinguishable.
_PRO_URL = cta_url("lite_report")
_LITE_REPO_URL = "https://github.com/ADScanPro/adscan"

#: The house theme. Warm bone paper, editorial serif display, one deep-teal
#: accent — the same tokens the paid deliverable renders on.
LITE_THEME = "editorial"


# --- Status presentation (client-safe, doctrine-legal) ----------------------
#
# The path/step ``status`` vocabulary is derived by
# ``attack_paths_core._derive_display_status_from_steps``:
#   exploited | partial | attempted | unavailable | blocked | unsupported |
#   closed_by_configuration | theoretical
# (step statuses also include success / failed / error).
#
# "Proven" is the SSOT set _PROVEN_STATUSES (success / exploited /
# domain_compromised) — NEVER a bare literal. Everything else maps below. No
# label claims a defensive control blocked the attack.
_NONPROVEN_STATUS_PRESENTATION: dict[str, tuple[str, str]] = {
    "partial": ("Partially Validated", "partial"),
    "attempted": ("Attempted", "attempted"),
    "failed": ("Attempted", "attempted"),
    "error": ("Attempted", "attempted"),
    "unavailable": ("Not Assessed", "gap"),
    "unsupported": ("Not Assessed", "gap"),
    "blocked": ("Not Executed for Safety", "safety"),
    "safety_blocked": ("Not Executed for Safety", "safety"),
    "closed_by_configuration": ("Attack Surface Reduced", "hardening"),
    "theoretical": ("Theoretical", "theoretical"),
}


def status_presentation(status: object) -> tuple[str, str]:
    """Return the ``(label, tone)`` for a path/step status.

    ``tone`` is a stable CSS-class token the template maps to a colour. Proven
    statuses (the SSOT :data:`_PROVEN_STATUSES` set) return ``("Validated",
    "proven")``; every other status maps through
    :data:`_NONPROVEN_STATUS_PRESENTATION`, defaulting to Theoretical.
    """
    token = str(status or "").strip().lower()
    if token in _PROVEN_STATUSES:
        return ("Validated", "proven")
    return _NONPROVEN_STATUS_PRESENTATION.get(token, ("Theoretical", "theoretical"))


def _score_tone(score: int) -> str:
    """Map a 0-100 score to a stable band tone token for the template."""
    if score >= BAND_HEALTHY:
        return "healthy"
    if score >= BAND_ACCEPTABLE:
        return "acceptable"
    if score >= BAND_ELEVATED:
        return "elevated"
    return "critical"


# --- Model ------------------------------------------------------------------


@dataclass(frozen=True)
class FindingRow:
    """One finding as rendered: LITE fields only (no knowledge prose).

    ``assets`` names the objects the finding is about — the accounts, hosts,
    shares, certificate templates and files an administrator can open, disable
    or revoke. It is capped at :data:`_INLINE_ASSET_CAP` and ``assets_overflow``
    carries how many were left out, so a posture finding covering a thousand
    hosts states its scale instead of running for pages.
    """

    title: str
    severity: str
    category: str
    mitre: tuple[dict[str, str], ...] = ()
    domain: str = ""
    assets: tuple[str, ...] = ()
    assets_overflow: int = 0


@dataclass(frozen=True)
class PathStepRow:
    """One narrated attack-path step.

    ``technique`` is the client headline (the business phrase from the shared
    label SSOT); ``narrative`` is the sentence underneath it, with the raw
    edge-token prefix the catalog templates carry for the CLI stripped off. A
    step whose object could not be resolved still names its source and target,
    so no line in the document describes nothing.
    """

    order: int
    technique: str
    narrative: str
    status_label: str
    status_tone: str


@dataclass(frozen=True)
class AttackPathRow:
    """One validated / candidate attack path as rendered."""

    index: int
    source: str
    target: str
    domain: str
    #: SHORT compromise-reach label ("Full domain compromise"). Deliberately the
    #: only reach wording the row carries: the FULL SSOT sentence is a legend
    #: definition that asserts "Validated path to …", so rendering it per row
    #: contradicts a THEORETICAL / PARTIALLY VALIDATED chip on the same line.
    reach_label_short: str
    status_label: str
    status_tone: str
    length: int
    steps: tuple[PathStepRow, ...]
    #: The technique spine, e.g. ``"Certificate Template Takeover →
    #: Replicate Directory Secrets"``. Twelve paths can share one route; what
    #: tells them apart is how they get there.
    via: str = ""
    extra_steps: int = 0


@dataclass(frozen=True)
class ChokePointRow:
    """One entry in the choke-point ranking: fix this, and N paths close."""

    rank: int
    technique: str
    paths_eliminated: int
    share: int
    principals: int


@dataclass(frozen=True)
class EnvironmentChangeRow:
    """One directory change ADscan made, as disclosed to the client."""

    kind: str
    target: str
    object_dn: str
    domain: str
    status_label: str
    status_tone: str
    detail: str
    performed_at: str


@dataclass(frozen=True)
class ChangeDisclosure:
    """The scan's write ledger, as the client is owed it.

    Rendered whether or not this run wrote anything: "we changed nothing" is a
    statement the client needs to have in writing, and a section that only
    appears when something went wrong teaches the reader that its absence means
    nothing was checked.

    :attr:`determined` is what keeps that statement honest. All-zero counts have
    two very different causes — a ledger that was read and holds nothing, and no
    ledger at all — and only the first may be reported as a clean run. When the
    record could not be read the document says exactly that.
    """

    total: int
    reverted: int
    manual_required: int
    kept: int
    in_progress: int
    manual_rows: tuple[EnvironmentChangeRow, ...] = ()
    reverted_rows: tuple[EnvironmentChangeRow, ...] = ()
    other_rows: tuple[EnvironmentChangeRow, ...] = ()
    #: False when no write ledger could be read for this scan.
    determined: bool = True

    @property
    def needs_action(self) -> bool:
        """True when something is left for the client's administrator to undo."""
        return bool(self.manual_required or self.in_progress)

    @property
    def clean_run(self) -> bool:
        """True only when a ledger was read AND it holds nothing."""
        return self.determined and self.total == 0


@dataclass(frozen=True)
class FindingAssetCoverage:
    """How many findings name something the reader can act on.

    The ratio of :attr:`with_locator` to :attr:`total` is how much work the
    document pushes back onto the client's administrator: a finding that names
    only its domain leaves them to find the affected object themselves.

    :attr:`with_affected_assets` is the honest denominator for that ratio. A
    run whose findings carry no structured assets at all (nothing was stamped)
    is a different fact from a run whose findings resolved to the bare domain,
    and collapsing the two would read as a quality regression that never
    happened.
    """

    total: int = 0
    with_affected_assets: int = 0
    with_locator: int = 0


@dataclass(frozen=True)
class SeveritySlice:
    """One segment of the proportional severity bar."""

    key: str
    label: str
    count: int
    share: float


@dataclass(frozen=True)
class LiteReportModel:
    """Everything the template needs, fully resolved and client-safe."""

    workspace_name: str
    domain_label: str
    domain_count: int
    generated_at: str
    # The verdict — one sentence, the thing the document is about. Composed in
    # Python (see :func:`build_verdict`) so the template interpolates values
    # instead of branching on them, and so the wording is testable.
    verdict_figure: str
    verdict_text: str
    verdict_tone: str
    #: The blast radius in accounts, not paths — the second line of the verdict
    #: and the figure a CISO repeats. Empty when the artifact carries no KPI
    #: block, in which case the document says nothing rather than a bare zero.
    verdict_reach: str
    # Ledger figures — the finding load and the paths to full domain
    # compromise. The score is a SUPPORTING figure beside them, never the hero
    # (the PRO report deliberately demoted it and this mirrors that decision).
    priority_findings: int
    paths_to_domain_compromise: int
    tier0_exposed: int
    bottom_line: str
    # Brand assets, resolved from the shared SSOT. Inline SVG so the file stays
    # self-contained; empty string when unavailable and the template falls back
    # to the text wordmark (same shape as the PRO templates' ``brand_logo``).
    brand_logo_svg: str
    favicon_data_uri: str
    score: int
    score_label: str
    score_tone: str
    severity_counts: dict[str, int]
    severity_slices: tuple[SeveritySlice, ...]
    total_findings: int
    findings: tuple[FindingRow, ...]
    paths: tuple[AttackPathRow, ...]
    paths_total: int
    paths_omitted: int
    proven_paths: int
    choke_points: tuple[ChokePointRow, ...]
    changes: ChangeDisclosure
    #: How many paths carry a validated segment without being proven end to end.
    #: Not rendered as its own figure today; carried so the document's own
    #: proof mix can be measured (see :func:`derive_report_content_metrics`).
    partial_paths: int = 0
    #: Affected-asset coverage of the findings above. The rows themselves carry
    #: the assets; this is the roll-up of how many name something the reader can
    #: act on, which is what the content telemetry reports.
    finding_assets: FindingAssetCoverage = FindingAssetCoverage()
    pro_url: str = _PRO_URL
    repo_url: str = _LITE_REPO_URL


# --- Pure builders ----------------------------------------------------------


def _finding_mitre(key: str) -> tuple[dict[str, str], ...]:
    """Return the ATT&CK technique cells for a finding key (LITE slice)."""
    meta = VULN_CATALOG_META.get(str(key)) or {}
    mitre = meta.get("mitre")
    if not isinstance(mitre, list):
        return ()
    cells: list[dict[str, str]] = []
    for item in mitre:
        if not isinstance(item, dict):
            continue
        tid = str(item.get("id") or "").strip()
        name = str(item.get("name") or "").strip()
        if tid:
            cells.append({"id": tid, "name": name})
    return tuple(cells)


#: How many affected assets a finding row lists inline. A posture finding can
#: cover every host in the estate; the row states the first few and then says
#: how many more there are, so the document keeps its shape.
_INLINE_ASSET_CAP = 6


def _finding_asset_entities(finding: Any) -> list[dict[str, Any]]:
    """Return the structured affected-asset entities stamped on one finding."""
    if not isinstance(finding, dict):
        return []
    details = finding.get("details")
    if not isinstance(details, dict):
        return []
    entities = details.get(SERIALIZED_KEY)
    if not isinstance(entities, list):
        return []
    return [entity for entity in entities if isinstance(entity, dict)]


def _entity_label(entity: dict[str, Any]) -> str:
    """Return the reader-facing label for one entity, or ``""`` when unnamed."""
    return (
        str(entity.get("display") or "").strip()
        or str(entity.get("identifier") or "").strip()
    )


def finding_asset_state(finding: Any) -> tuple[bool, bool]:
    """Return ``(has_affected_assets, has_locator)`` for one finding record.

    Both answers come from the structured affected-asset entities the engine
    stamped onto the finding's ``details``; nothing is resolved or recomputed
    here.

    * ``has_affected_assets`` — the finding carries at least one entity at all.
      This is the denominator that keeps the second figure readable: zero here
      means the run never stamped assets, which is a different fact from a
      finding that names only its domain.
    * ``has_locator`` — at least one entity is something an administrator can
      act on: an account, a host, a share, a certificate template, a CA, an
      artifact. The bare domain object does not count, because it is the
      fallback every scope emits when no concrete asset resolved.
    """
    has_assets = False
    for entity in _finding_asset_entities(finding):
        if not _entity_label(entity):
            continue
        has_assets = True
        if str(entity.get("type") or "").strip().lower() != TYPE_DOMAIN:
            return (True, True)
    return (has_assets, False)


def _finding_asset_labels(finding: Any) -> tuple[tuple[str, ...], int]:
    """Return the capped asset labels for a finding row plus the overflow count.

    Locators come first — an account, host, share, certificate template or file
    is what the reader acts on, while the bare domain object is the fallback the
    resolver emits when nothing concrete was found, and it is worth showing only
    when it is all there is.
    """
    locators: list[str] = []
    fallback: list[str] = []
    for entity in _finding_asset_entities(finding):
        label = _entity_label(entity)
        if not label:
            continue
        bucket = (
            fallback
            if str(entity.get("type") or "").strip().lower() == TYPE_DOMAIN
            else locators
        )
        if label not in bucket:
            bucket.append(label)
    ordered = locators or fallback
    shown = tuple(ordered[:_INLINE_ASSET_CAP])
    return shown, max(0, len(ordered) - len(shown))


def _collect_findings(
    domains: dict[str, Any], *, multi_domain: bool
) -> tuple[list[FindingRow], dict[str, int], FindingAssetCoverage]:
    """Flatten findings across domains into rows, severity counts and coverage.

    Reads ONLY the LITE-safe fields (key, title, severity, category). The rich
    ``knowledge`` object and ``cvss_base`` are deliberately never read, so a
    PRO-produced JSON renders exactly like a LITE one.
    """
    counts: dict[str, int] = {sev: 0 for sev in _SEVERITY_ORDER}
    rows: list[FindingRow] = []
    with_assets = 0
    with_locator = 0
    for domain_name, entry in domains.items():
        if not isinstance(entry, dict):
            continue
        findings = entry.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "").strip().lower()
            title = str(finding.get("title") or "").strip()
            if not title:
                continue
            if severity in counts:
                counts[severity] += 1
            has_assets, has_locator = finding_asset_state(finding)
            with_assets += int(has_assets)
            with_locator += int(has_locator)
            assets, assets_overflow = _finding_asset_labels(finding)
            rows.append(
                FindingRow(
                    title=title,
                    severity=severity if severity in counts else "low",
                    category=str(finding.get("category") or "General").strip(),
                    mitre=_finding_mitre(str(finding.get("key") or "")),
                    domain=str(domain_name) if multi_domain else "",
                    assets=assets,
                    assets_overflow=assets_overflow,
                )
            )
    rows.sort(
        key=lambda r: (
            _SEVERITY_ORDER.index(r.severity) if r.severity in _SEVERITY_ORDER else 99,
            r.title.lower(),
        )
    )
    coverage = FindingAssetCoverage(
        total=len(rows),
        with_affected_assets=with_assets,
        with_locator=with_locator,
    )
    return rows, counts, coverage


def _humanize_relation(relation: str) -> str:
    """Split a PascalCase relation into a readable label as a last resort."""
    if not relation:
        return "Attack step"
    out: list[str] = []
    for i, ch in enumerate(relation):
        if ch.isupper() and i > 0 and not relation[i - 1].isupper():
            out.append(" ")
        out.append(ch)
    return "".join(out).strip()


def _technique_phrase(relation: str) -> str:
    """Return the plain-language name of a technique, no edge token attached.

    The shared SSOT :func:`format_business_relation_label` renders
    ``"Replicate Directory Secrets (DCSync)"``: the phrase for the executive,
    the token for the engineer. In this document the token is dropped from the
    step headline and the path spine — both are read as running text, where a
    parenthetical on every line is noise — and the technical detail lives in
    the sentence underneath. When the SSOT has no business phrase for an edge,
    the technical label IS the answer and comes through unchanged.
    """
    label = format_business_relation_label(str(relation or "")).strip()
    if label.endswith(")") and "(" in label:
        return label[: label.rindex("(")].strip()
    return label


def _step_endpoints(step: dict[str, Any]) -> tuple[str, str]:
    """Return the ``(source, target)`` principals a step runs between.

    Reads the persisted step shape directly (``details.from`` / ``details.to``
    / ``details.display_to``, with the flat step keys as a fallback) and returns
    empty strings when a side is genuinely unknown — unlike the catalog's
    placeholder resolver, which substitutes a generic phrase. The caller needs
    to know the difference: a clause naming "the target object" is noise, so it
    is better left out.
    """
    details = step.get("details") if isinstance(step.get("details"), dict) else {}

    def _pick(*keys: str) -> str:
        for key in keys:
            value = details.get(key) if isinstance(details, dict) else None
            if isinstance(value, str) and value.strip():
                return value.strip()
        for key in keys:
            value = step.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    return _pick("from", "source"), _pick("display_to", "to", "target")


def _step_affected_object(step: dict[str, Any]) -> str:
    """Name the concrete object a step abuses, when the data carries one.

    Today that is the ADCS surface, which is exactly where the placeholder
    narratives live: a certificate template for the template-level escalations,
    the issuing authority for the CA-level ones. Both come from the shared
    extractors in ``adcs_path_display`` (the abused object is recorded under
    ``vulnerable_resources`` / ``template_used_for_run``, never as a flat
    ``details.template``).
    """
    details = step.get("details") if isinstance(step.get("details"), dict) else {}
    if not isinstance(details, dict):
        return ""
    templates = extract_adcs_template_names(details)
    if templates:
        plural = "s" if len(templates) > 1 else ""
        return f"certificate template{plural} {', '.join(templates)}"
    authorities = extract_adcs_authority_names(details)
    if authorities:
        plural = "ies" if len(authorities) > 1 else "y"
        return f"certificate authorit{plural} {', '.join(authorities)}"
    return ""


def _strip_relation_prefix(text: str, relation: str) -> str:
    """Drop the leading ``"<EdgeToken>: "`` the CLI narrative templates carry.

    The catalog's short templates open with the raw BloodHound token because
    the CLI reads them as a technical log line. In a client document the token
    is the wrong register and it is already carried by the step's technique
    headline, so the sentence starts at the sentence.
    """
    body = text.strip()
    candidates = {format_relation_label(relation).lower(), relation.strip().lower()}
    for candidate in candidates:
        if candidate and body.lower().startswith(candidate + ":"):
            body = body[len(candidate) + 1 :].lstrip()
            return body[:1].upper() + body[1:] if body else body
    return body


def _step_narrative(step: dict[str, Any]) -> str:
    """Resolve a client-safe narrative for one step, LITE fallbacks in order.

    1. short catalog narrative template, 2. full catalog narrative template,
    3. the catalog entry's ``description``, augmented with the object the step
    abuses and the principals it runs between, 4. a humanised relation label.
    The PRO-only prose paths inside the catalog are lazy + best-effort, so this
    never requires PRO.

    Level 3 is where the placeholder lines came from. A catalog description like
    "ADCS ESC2 privilege escalation path" is true and names nothing; the step's
    own data knows which template and which principals, so the sentence is
    completed from the data rather than left as a label. No technique semantics
    are authored here — that stays in the catalog SSOT.
    """
    relation = str(step.get("action") or step.get("relation") or "").strip()
    text = render_step_narrative(step, short=True) or render_step_narrative(step)
    if text:
        return _strip_relation_prefix(text, relation)

    entry = get_attack_step_entry(relation)
    description = str(entry.description).strip() if entry is not None and entry.description else ""
    # A description that opens with the edge token ("ADCS ESC8 privilege
    # escalation path") only restates the technique headline this step already
    # carries. Printing both is a line that says the same thing twice; the
    # objects resolved below are what the reader does not already have.
    technical = format_relation_label(relation).strip().lower()
    if technical and description.lower().startswith(technical):
        description = ""

    affected = _step_affected_object(step)
    source, target = _step_endpoints(step)
    known = f"{description} {affected}".lower()
    endpoints = ""
    if source and target and source.lower() not in known and target.lower() not in known:
        endpoints = f"from {source} to {target}"

    if description:
        clauses = [c for c in (f"on {affected}" if affected else "", endpoints) if c]
        body = description.rstrip(".")
        return f"{body}, {', '.join(clauses)}." if clauses else f"{body}."
    if affected:
        tail = f", {endpoints}" if endpoints else ""
        return f"Targets {affected}{tail}."
    if endpoints:
        return f"Runs {endpoints}."
    return f"{_humanize_relation(relation)}."


def _build_path_steps(
    steps: list[dict[str, Any]],
) -> tuple[list[PathStepRow], int, list[str]]:
    """Narrate an attack path's steps (skipping pure context edges).

    Returns ``(rows, extra, techniques)``. ``techniques`` is the distinct
    technique spine in path order, used to tell otherwise-identical paths apart
    in their headers.
    """
    rows: list[PathStepRow] = []
    techniques: list[str] = []
    order = 0
    for step in steps:
        if not isinstance(step, dict):
            continue
        relation = str(step.get("action") or step.get("relation") or "").strip()
        if relation.lower() in _CONTEXT_RELATIONS:
            continue
        order += 1
        label, tone = status_presentation(step.get("status"))
        # The step headline carries the full SSOT label — business phrase plus
        # the canonical edge token in parentheses, which is the one place in
        # the document the technical reader gets it. The spine below the route
        # line takes the phrase alone: a parenthetical on every hop of a
        # running line is noise.
        phrase = _technique_phrase(relation)
        if phrase and phrase not in techniques:
            techniques.append(phrase)
        rows.append(
            PathStepRow(
                order=order,
                technique=format_business_relation_label(relation).strip(),
                narrative=_step_narrative(step),
                status_label=label,
                status_tone=tone,
            )
        )
    extra = 0
    if len(rows) > MAX_RENDERED_STEPS:
        extra = len(rows) - MAX_RENDERED_STEPS
        rows = rows[:MAX_RENDERED_STEPS]
    return rows, extra, techniques


def _reach_label_short(compromise_class: str) -> str:
    """Return the SHORT compromise-reach label from the SSOT.

    Short, not full, on purpose. The full form is the legend definition
    ("Validated path to full domain compromise (control of a Tier 0 asset)")
    and this document renders no legend — see :class:`AttackPathRow`.
    """
    try:
        cls = CompromiseClass(str(compromise_class or "").strip().lower())
    except ValueError:
        cls = CompromiseClass.NONE
    return compromise_reach_label_short(cls)


def _build_path_rows(
    raw_paths: list[dict[str, Any]], *, multi_domain: bool
) -> tuple[list[AttackPathRow], int, int, int]:
    """Order paths PROVEN-first (SSOT) and build the capped render rows.

    Returns ``(rows, total, proven, partial)`` where ``rows`` is at most
    :data:`MAX_RENDERED_PATHS` long; the caller derives the omitted count. The
    ``proven`` and ``partial`` tallies cover every path the document accounts
    for, not just the ones rendered in full — the tail is disclosed as an
    honest "N more" note rather than dropped, so the counts have to match it.
    """
    ordered = order_paths_for_client_presentation(raw_paths)
    proven = 0
    partial = 0
    for p in ordered:
        if not isinstance(p, dict):
            continue
        status = str(p.get("status") or "").strip().lower()
        if status in _PROVEN_STATUSES:
            proven += 1
        elif status == "partial":
            partial += 1
    rows: list[AttackPathRow] = []
    for path in ordered[:MAX_RENDERED_PATHS]:
        if not isinstance(path, dict):
            continue
        reach_short = _reach_label_short(str(path.get("compromise_class") or ""))
        status_label, status_tone = status_presentation(path.get("status"))
        steps = path.get("steps") if isinstance(path.get("steps"), list) else []
        step_rows, extra, techniques = _build_path_steps(steps)
        if not techniques:
            # A record with relations but no narrated steps still gets a spine:
            # the header has to tell this path apart from the eleven others
            # sharing its route line, and the relation list is the same data.
            techniques = _relation_techniques(path.get("relations"))
        nodes = path.get("nodes") if isinstance(path.get("nodes"), list) else []
        source = str(path.get("source") or (nodes[0] if nodes else ""))
        target = str(path.get("target") or (nodes[-1] if nodes else ""))
        rows.append(
            AttackPathRow(
                index=len(rows) + 1,
                source=source,
                target=target,
                domain=str(path.get("_domain") or "") if multi_domain else "",
                reach_label_short=reach_short,
                status_label=status_label,
                status_tone=status_tone,
                length=int(path.get("length") or len(step_rows)),
                steps=tuple(step_rows),
                via=_format_via(techniques),
                extra_steps=extra,
            )
        )
    return rows, len(ordered), proven, partial


#: How many techniques the path spine names before it elides. Three is what
#: fits on one line at the header's size, and a fourth adds nothing to telling
#: two paths apart.
_MAX_VIA_TECHNIQUES = 3


def _relation_techniques(relations: Any) -> list[str]:
    """Distinct technique phrases from a path's ``relations`` list, in order."""
    if not isinstance(relations, list):
        return []
    out: list[str] = []
    for raw in relations:
        token = str(raw or "").strip()
        if not token or token.lower() in _CONTEXT_RELATIONS:
            continue
        phrase = _technique_phrase(token)
        if phrase and phrase not in out:
            out.append(phrase)
    return out


def _format_via(techniques: list[str]) -> str:
    """Compose the technique spine shown under a path's route line."""
    named = [t for t in techniques if t]
    if not named:
        return ""
    if len(named) <= _MAX_VIA_TECHNIQUES:
        return " → ".join(named)
    head = " → ".join(named[:_MAX_VIA_TECHNIQUES])
    remaining = len(named) - _MAX_VIA_TECHNIQUES
    return f"{head} → +{remaining} more"


def _count_score_inputs(
    counts: dict[str, int], raw_paths: list[dict[str, Any]]
) -> PostureInputs:
    """Translate finding counts + paths into :class:`PostureInputs`.

    The two path-derived inputs come from the SHARED SSOT
    (:func:`~adscan_internal.services.exposure_score_service.derive_posture_path_inputs`),
    the exact derivation the PRO report uses, so the same workspace yields the
    same score on both tiers. Never re-derive them here.
    """
    paths_to_da, tier0_exposed = derive_posture_path_inputs(raw_paths)
    return PostureInputs(
        critical_findings=counts.get("critical", 0),
        high_findings=counts.get("high", 0),
        medium_findings=counts.get("medium", 0),
        low_findings=counts.get("low", 0),
        paths_to_da=paths_to_da,
        tier0_exposed=tier0_exposed,
    )


#: How many choke points the ranking shows. The point of the table is that a
#: short list of fixes covers most of the exposure; a long one restates the
#: path list and loses the argument.
MAX_CHOKE_POINTS = 6


def build_choke_points(
    raw_paths: list[dict[str, Any]], *, limit: int = MAX_CHOKE_POINTS
) -> tuple[ChokePointRow, ...]:
    """Rank the techniques that carry the most attack paths.

    "You are exposed 25 ways" is a problem statement with no handle on it. The
    same 25 paths usually run through a handful of techniques, so naming those
    turns the finding into a short list of decisions. That ranking is computed
    by the shared SSOT
    :func:`~adscan_internal.services.attack_surface_analysis.compute_attack_surface_analysis`
    — the same derivation the paid deliverable ranks its remediation on, so the
    two tiers never disagree about which fix matters most.

    What LITE renders is the ranking and its arithmetic: how many paths close,
    what share of the total that is, and how many principals it covers. HOW to
    close each one is the paid deliverable's remediation section and is
    deliberately not derived here.

    Args:
        raw_paths: The union of every domain's attack-path records.
        limit: Maximum rows to return.

    Returns:
        Ranked rows, highest path coverage first. Empty when there are no paths.
    """
    if not raw_paths:
        return ()
    analysis = compute_attack_surface_analysis(raw_paths)
    if analysis.total_paths <= 0:
        return ()
    rows: list[ChokePointRow] = []
    # Relation targets only: a technique is a decision the client can make once,
    # where a single over-connected object is a symptom of one of them.
    for target in top_remediation_targets(analysis, top_n=limit * 3):
        if target.target_type != "relation" or target.paths_eliminated <= 0:
            continue
        rows.append(
            ChokePointRow(
                rank=len(rows) + 1,
                technique=_technique_phrase(target.target_id),
                paths_eliminated=target.paths_eliminated,
                share=round(target.elimination_rate * 100),
                principals=target.affected_principals,
            )
        )
        if len(rows) >= limit:
            break
    return tuple(rows)


#: Status tones for the change ledger, mapped from the cleanup taxonomy's
#: buckets onto the design system's chip tones. ``manual`` is the one the
#: client must act on, so it carries the same weight as an unresolved finding.
_CHANGE_BUCKET_TONE: dict[str, str] = {
    "reverted": "hardening",
    "manual": "critical",
    "kept": "attempted",
    "in_progress": "attempted",
}


def _display_timestamp(value: Any) -> str:
    """Render an ISO-8601 ledger timestamp the way a person reads a date.

    ``2026-07-25T14:00:24+00:00`` is a machine field; a client document says
    ``July 25, 2026 · 14:00 UTC``, the same format the masthead uses. Anything
    unparseable is passed through unchanged rather than dropped, so a
    hand-edited or future-schema value still appears.
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.strftime("%B %d, %Y · %H:%M UTC")


def _change_rows(
    entries: list[dict[str, Any]], bucket: str
) -> tuple[EnvironmentChangeRow, ...]:
    """Project normalized ledger records into render rows."""
    tone = _CHANGE_BUCKET_TONE.get(bucket, "gap")
    rows: list[EnvironmentChangeRow] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        detail = str(
            entry.get("manual_reason_label")
            or entry.get("remediation_command")
            or ""
        ).strip()
        performed_at = _display_timestamp(
            entry.get("verified_at") or entry.get("reverted_at") or entry.get("registered_at")
        )
        rows.append(
            EnvironmentChangeRow(
                kind=str(entry.get("kind_display") or entry.get("kind") or "Change"),
                target=str(entry.get("target") or ""),
                object_dn=str(entry.get("object_dn") or ""),
                domain=str(entry.get("domain") or ""),
                status_label=str(entry.get("status_label") or ""),
                status_tone=tone,
                detail=detail,
                performed_at=performed_at,
            )
        )
    return tuple(rows)


def build_change_disclosure(
    resolution: EnvironmentChangeResolution,
) -> ChangeDisclosure:
    """Build the write-ledger disclosure from the resolved change record.

    A scan that validates an attack path writes to the directory: it enrolls a
    certificate, mints a machine account, edits a template. Those writes are
    tracked in the environment-change ledger and reverted, and the client is
    owed a statement of what was touched and whether anything is still
    outstanding — the free report is routinely forwarded to the domain owner,
    so it is the copy that has to carry it.

    The input is a resolution, never a raw block, because the report renders
    while the session is still open: whether a ledger could be read at all is
    part of the answer, and a caller that hands over only "no block" must not
    have that read as a clean run
    (:func:`~adscan_internal.services.environment_change_ledger.resolve_environment_changes`).

    Bucketing and labels come from the ledger SSOT (which reads the
    ``cleanup_taxonomy`` vocabulary). Nothing is classified here.

    Args:
        resolution: The resolved record for this scan.

    Returns:
        A :class:`ChangeDisclosure`. All-zero and ``determined=False`` when no
        ledger could be read — the document then says the record is unavailable
        instead of claiming nothing was touched.
    """
    determined = resolution.determined
    report = resolution.cleanup_report() if determined else None
    if not isinstance(report, dict):
        return ChangeDisclosure(
            total=0,
            reverted=0,
            manual_required=0,
            kept=0,
            in_progress=0,
            determined=determined,
        )

    def _bucket(name: str) -> list[dict[str, Any]]:
        value = report.get(name)
        return value if isinstance(value, list) else []

    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    manual = _bucket("manual")
    reverted = _bucket("reverted")
    kept = _bucket("kept")
    in_progress = _bucket("in_progress")

    def _count(key: str, fallback: int) -> int:
        value = summary.get(key)
        return int(value) if isinstance(value, int) else fallback

    return ChangeDisclosure(
        total=_count("total", len(manual) + len(reverted) + len(kept) + len(in_progress)),
        reverted=len(reverted),
        manual_required=len(manual),
        kept=len(kept),
        in_progress=len(in_progress),
        manual_rows=_change_rows(manual, "manual"),
        reverted_rows=_change_rows(reverted, "reverted"),
        other_rows=_change_rows(kept, "kept") + _change_rows(in_progress, "in_progress"),
        determined=True,
    )


def build_bottom_line(
    *,
    score: PostureScore,
    counts: dict[str, int],
    paths_to_da: int,
    tier0_exposed: int,
) -> str:
    """Compose the BOTTOM LINE sentence explaining the score.

    Mirrors the PRO report's "BOTTOM LINE" pattern: give the number, WHY it sits
    there, and WHAT would lift it. A score with no explanation is a verdict; a
    score with its drivers named is a scoreboard the client can play against.

    When the critical floor fired (``critical_floor_applied``), say so plainly
    and name what lifts the cap: a floored score cannot move while any path to
    full domain compromise remains, so the client must know that closing paths
    is the precondition for the number improving at all.

    Args:
        score: The computed :class:`PostureScore` (its ``components`` carry the
            per-penalty breakdown and the ``critical_floor_applied`` flag).
        counts: Severity counts keyed ``critical``/``high``/``medium``/``low``.
        paths_to_da: Paths reaching full domain compromise.
        tier0_exposed: Distinct Tier-0 assets reached.

    Returns:
        A client-safe paragraph. Never claims a defensive control did anything.
    """
    components = score.components or {}
    floored = bool(components.get("critical_floor_applied"))
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    priority = critical + high

    parts: list[str] = []

    # 1. The number and the band. Posture, not exposure: the scale runs the
    #    other way (100 is healthy), and calling a 2 an "exposure score" in a
    #    document titled Exposure Report reads as "2% exposed, we are fine".
    parts.append(f"The posture score is {score.score} of 100, in the {score.label.lower()} band.")

    # 2. WHY it sits there — lead with the dominant driver.
    if paths_to_da > 0:
        parts.append(
            f"{paths_to_da} attack path{'' if paths_to_da == 1 else 's'} "
            f"reach{'es' if paths_to_da == 1 else ''} full domain compromise, "
            "which is the finding that matters most here regardless of how the "
            "severity counts read."
        )
    elif tier0_exposed > 0:
        parts.append(
            f"{tier0_exposed} Tier 0 asset{'' if tier0_exposed == 1 else 's'} "
            f"{'is' if tier0_exposed == 1 else 'are'} reachable, which drives the "
            "score more than the severity counts do."
        )
    elif priority > 0:
        parts.append(
            f"{priority} high-priority finding{'' if priority == 1 else 's'} "
            f"({critical} critical, {high} high) drive the score."
        )
    else:
        parts.append("No paths to domain compromise and no high-priority findings were identified.")

    # 3. The floor, stated plainly, with what lifts the cap.
    if floored:
        parts.append(
            f"While any of those remain, the score is capped at {CRITICAL_BAND_TOP} "
            "no matter how many findings are closed, so closing them is what lets "
            "the number move at all."
        )

    # 4. WHAT lifts it — concrete, ordered, and honest about what LITE can point at.
    if paths_to_da > 0 or tier0_exposed > 0:
        if priority > 0:
            parts.append(
                f"Cut the paths first by closing the {priority} high-priority "
                f"finding{'' if priority == 1 else 's'} ({critical} critical, "
                f"{high} high) listed below; the paths overlap heavily, so start "
                "with the techniques ranked overleaf, where one fix closes many "
                "paths at once."
            )
        else:
            parts.append(
                "Start with the techniques ranked overleaf: they are ordered by "
                "how many paths each one closes."
            )
    elif priority > 0:
        parts.append(
            "Closing the critical and high findings below is what moves the score."
        )

    return " ".join(parts)


def build_verdict(*, paths_to_da: int, paths_total: int) -> tuple[str, str, str]:
    """Compose the one-sentence verdict the report opens with.

    Returns ``(figure, text, tone)``. The figure is set large beside the
    sentence, so it carries the number and the text carries the claim. Tone is
    a CSS token: ``critical`` when at least one path reaches full domain
    compromise, ``ok`` when none does.

    The wording never overstates: "reach full domain compromise" is what the
    graph shows; whether each path was executed end to end is the per-path
    status further down.
    """
    if paths_total <= 0:
        return ("0", "attack paths were identified in this environment.", "ok")
    if paths_to_da <= 0:
        plural = "" if paths_total == 1 else "s"
        return (
            "0",
            f"of the {paths_total} identified attack path{plural} reaches full "
            "domain compromise.",
            "ok",
        )
    plural = "" if paths_total == 1 else "s"
    return (
        str(paths_to_da),
        f"of {paths_total} identified attack path{plural} reach full domain "
        "compromise.",
        "critical",
    )


def build_verdict_reach(reach: DomainUserReach) -> str:
    """Compose the account-population line that sits under the verdict.

    "25 of 31 paths" counts inventory. "10 of 10 domain users hold a validated
    path to full domain compromise" counts people, which is the unit the reader
    owns and the one that makes the finding land. The figures come from the
    engine-stamped KPI block via the shared derivation, never recomputed.

    Returns an empty string when the artifact carries no KPI block or nobody is
    affected: a document that says nothing there is honest, one that prints a
    zero it cannot stand behind is not.
    """
    if not reach.available or reach.affected <= 0 or reach.total <= 0:
        return ""
    accounts = "account" if reach.total == 1 else "accounts"
    lead = (
        f"{reach.affected} of {reach.total} domain user {accounts} "
        f"hold a path to full domain compromise"
    )
    if reach.is_every_account:
        return f"{lead}: every account in the domain."
    return f"{lead} ({reach.pct:g}% of the directory)."


def build_severity_slices(counts: dict[str, int]) -> tuple[SeveritySlice, ...]:
    """Turn severity counts into the proportional bar's segments.

    Shares are percentages of the total finding count, rounded to two decimals
    so the segments add up on the page. A severity with no findings still gets
    a slice — the legend lists every level, and a zero there is information.
    """
    total = sum(max(0, counts.get(sev, 0)) for sev in _SEVERITY_ORDER)
    denominator = total if total > 0 else 1
    return tuple(
        SeveritySlice(
            key=sev,
            label=sev.capitalize(),
            count=counts.get(sev, 0),
            share=round(counts.get(sev, 0) / denominator * 100, 2),
        )
        for sev in _SEVERITY_ORDER
    )


def _now_display() -> str:
    """Return a human-readable UTC timestamp for the report footer/cover."""
    return datetime.now(timezone.utc).strftime("%B %d, %Y · %H:%M UTC")


def build_report_model(
    *,
    workspace_name: str,
    technical_report: dict[str, Any],
    raw_paths: list[dict[str, Any]],
    generated_at: Optional[str] = None,
    environment_changes: Optional[EnvironmentChangeResolution] = None,
) -> LiteReportModel:
    """Build the fully-resolved, client-safe report model from loaded data.

    Pure (no I/O). ``technical_report`` is the parsed ``technical_report.json``;
    ``raw_paths`` is the union of every domain's canonical attack-path summaries
    (from :func:`~adscan_internal.services.report_attack_paths.compute_report_attack_paths`),
    each optionally tagged with a ``_domain`` key. Safe to call with a
    PRO-produced ``technical_report`` — the PRO-only fields are ignored.

    ``environment_changes`` carries what the caller could read about this scan's
    writes to the directory. It is a parameter rather than a lookup because the
    report renders while the session is still open, so the freshest record lives
    in the live ledger and the workspace file, not in the technical report — the
    block there is attached at exit and is absent on a first run. Omit it and the
    model falls back to that block alone, which yields "record unavailable"
    rather than a clean run when it is missing.
    """
    domains = technical_report.get("domains")
    if not isinstance(domains, dict):
        domains = {}
    domain_names = [str(d) for d in domains.keys() if isinstance(d, str) and d]
    multi_domain = len(domain_names) > 1

    findings, counts, finding_assets = _collect_findings(
        domains, multi_domain=multi_domain
    )
    path_rows, paths_total, proven, partial = _build_path_rows(
        raw_paths, multi_domain=multi_domain
    )
    inputs = _count_score_inputs(counts, raw_paths)
    score: PostureScore = compute_posture_score(inputs)
    bottom_line = build_bottom_line(
        score=score,
        counts=counts,
        paths_to_da=inputs.paths_to_da,
        tier0_exposed=inputs.tier0_exposed,
    )

    if not domain_names:
        domain_label = "the assessed environment"
    elif multi_domain:
        domain_label = f"{len(domain_names)} domains ({', '.join(sorted(domain_names))})"
    else:
        domain_label = domain_names[0]

    verdict_figure, verdict_text, verdict_tone = build_verdict(
        paths_to_da=inputs.paths_to_da, paths_total=paths_total
    )
    verdict_reach = build_verdict_reach(derive_domain_user_reach(domains))

    return LiteReportModel(
        workspace_name=workspace_name,
        domain_label=domain_label,
        domain_count=len(domain_names),
        generated_at=generated_at or _now_display(),
        verdict_figure=verdict_figure,
        verdict_text=verdict_text,
        verdict_tone=verdict_tone,
        verdict_reach=verdict_reach,
        priority_findings=counts.get("critical", 0) + counts.get("high", 0),
        paths_to_domain_compromise=inputs.paths_to_da,
        tier0_exposed=inputs.tier0_exposed,
        bottom_line=bottom_line,
        # Charcoal-ink master mark: the document is set on warm bone paper.
        # ``brand_assets`` names its variants after the BACKGROUND, so the
        # light-paper mark is "light".
        brand_logo_svg=brand_logo_svg_markup("light"),
        favicon_data_uri=brand_favicon_data_uri("light"),
        score=score.score,
        score_label=score.label,
        score_tone=_score_tone(score.score),
        severity_counts=counts,
        severity_slices=build_severity_slices(counts),
        total_findings=sum(counts.values()),
        findings=tuple(findings),
        paths=tuple(path_rows),
        paths_total=paths_total,
        paths_omitted=max(0, paths_total - len(path_rows)),
        proven_paths=proven,
        choke_points=build_choke_points(raw_paths),
        changes=build_change_disclosure(
            environment_changes
            if environment_changes is not None
            else resolve_environment_changes(
                report_block=technical_report.get("environment_changes")
            )
        ),
        partial_paths=partial,
        finding_assets=finding_assets,
    )


# --- What the document says (measurement, never content) --------------------


@dataclass(frozen=True)
class ReportContentMetrics:
    """Counts describing what one rendered report SAYS.

    The report funnel already records that a document was produced. This
    records whether the document was worth producing, in the only two terms
    that matter to the reader:

    * how many findings name something the reader can act on
      (:attr:`findings_with_locator` against :attr:`findings_total`) — the work
      the deliverable pushes back onto the client's administrator;
    * how much of the proof survived the trip from the engine to the page
      (:attr:`paths_rendered_exploited` against the engine's own count) — the
      one claim the product is built on.

    Counts only. No hostname, path, account or finding title is ever carried
    here: this rides to an analytics backend, which learns the shape of a
    deliverable and nothing about the environment it describes.
    """

    findings_total: int = 0
    findings_with_affected_assets: int = 0
    findings_with_locator: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    #: Every path the document accounts for: the ones it renders in full plus
    #: the tail it discloses as "N more". Comparable to the engine's own count.
    paths_rendered_total: int = 0
    paths_rendered_exploited: int = 0
    paths_rendered_partial: int = 0

    def as_event_properties(self) -> dict[str, int]:
        """Return the counts as flat telemetry properties."""
        return {
            "findings_total": int(self.findings_total),
            "findings_with_affected_assets": int(self.findings_with_affected_assets),
            "findings_with_locator": int(self.findings_with_locator),
            "findings_critical": int(self.findings_critical),
            "findings_high": int(self.findings_high),
            "findings_medium": int(self.findings_medium),
            "findings_low": int(self.findings_low),
            "paths_rendered_total": int(self.paths_rendered_total),
            "paths_rendered_exploited": int(self.paths_rendered_exploited),
            "paths_rendered_partial": int(self.paths_rendered_partial),
        }


def derive_report_content_metrics(model: LiteReportModel) -> ReportContentMetrics:
    """Read the content counts off an already-built report model.

    Pure and free: every figure is already resolved on the model, so this adds
    no work to a render and cannot disagree with the document it describes.
    """
    counts = model.severity_counts if isinstance(model.severity_counts, dict) else {}
    assets = model.finding_assets or FindingAssetCoverage()
    return ReportContentMetrics(
        findings_total=int(model.total_findings),
        findings_with_affected_assets=int(assets.with_affected_assets),
        findings_with_locator=int(assets.with_locator),
        findings_critical=int(counts.get("critical", 0)),
        findings_high=int(counts.get("high", 0)),
        findings_medium=int(counts.get("medium", 0)),
        findings_low=int(counts.get("low", 0)),
        paths_rendered_total=int(model.paths_total),
        paths_rendered_exploited=int(model.proven_paths),
        paths_rendered_partial=int(model.partial_paths),
    )


# --- Rendering --------------------------------------------------------------


def render_report_html(model: LiteReportModel, *, webfonts: bool = False) -> str:
    """Render the model to a single self-contained HTML string.

    Args:
        model: The resolved report model.
        webfonts: Load the display faces from the web-font provider. Only the
            copy handed to the PDF engine sets this: Chromium fetches the
            faces once at render time and embeds them in the document, so the
            resulting PDF is still self-contained. The ``.html`` written to
            disk must never set it — that file has to open with no network,
            and it degrades to the local fallbacks in the same type stacks.

    Returns:
        One HTML document with all CSS inline.
    """
    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = env.from_string(_TEMPLATE)
    return template.render(
        m=model,
        design_css=load_design_css(LITE_THEME, webfonts=webfonts),
    )


# Page geometry for the PDF. The same values are declared in the template's
# ``@page`` rule, so the result is identical whichever of the two Chromium
# honours — and the generous bottom margin is the band the running footer is
# drawn into.
LITE_PDF_MARGIN: dict[str, str] = {
    "top": "13mm",
    "right": "12mm",
    "bottom": "16mm",
    "left": "12mm",
}


def _pdf_footer_template(domain_label: str) -> str:
    """Return the Chromium running-footer template for the PDF.

    Chromium renders header/footer templates in their own document, isolated
    from the page's stylesheet, and substitutes the ``pageNumber`` /
    ``totalPages`` spans. So every style has to be inline and every font has to
    be one the renderer always has.
    """
    return (
        '<div style="width:100%;box-sizing:border-box;padding:0 13mm;'
        "font-family:Helvetica,Arial,sans-serif;font-size:6.5pt;color:#968b7d;"
        "letter-spacing:0.09em;text-transform:uppercase;"
        "display:flex;justify-content:space-between;align-items:center;"
        '-webkit-print-color-adjust:exact;">'
        f"<span>ADscan &middot; Active Directory Exposure Report &middot; {escape(domain_label)}</span>"
        '<span><span class="pageNumber"></span> / <span class="totalPages"></span></span>'
        "</div>"
    )


def build_pdf_options(model: LiteReportModel) -> dict[str, Any]:
    """Return the engine options that paginate this report."""
    return {
        "format": "A4",
        "print_background": True,
        "prefer_css_page_size": True,
        "margin": dict(LITE_PDF_MARGIN),
        "display_header_footer": True,
        # An empty template still prints Chromium's default title/date header.
        "header_template": "<span></span>",
        "footer_template": _pdf_footer_template(model.domain_label),
    }


def render_report_pdf(
    model: LiteReportModel, *, html_text: Optional[str] = None
) -> bytes:
    """Render the report to PDF bytes through the shared Chromium engine.

    Same model, same template and the same design system as
    :func:`render_report_html` — the pagination lives in the shared print layer
    plus the template's ``@page`` rule, and the running footer in the engine
    options. The engine itself (``adscan_internal.services.report_engines``) is
    shared with the PRO deliverable kit: there is exactly one HTML-to-PDF
    implementation in ADscan.

    The markup handed to Chromium asks for the real display faces, which the
    engine fetches once and embeds, so the PDF reads in the same typography as
    the paid deliverable while the ``.html`` on disk stays network-free. In
    offline deployments the request is skipped and both fall back to the local
    faces in the same stacks.

    Args:
        model: The resolved report model.
        html_text: An already-rendered HTML string to use as-is. Only pass the
            copy that was rendered for the PDF; the self-contained ``.html``
            is a different render.

    Returns:
        Raw PDF bytes.

    Raises:
        EngineRenderError: If Chromium is unavailable or the render fails.
    """
    from adscan_internal.services.report_engines import EngineRenderError, get_engine

    engine = get_engine("chromium")
    available, reason = engine.is_available()
    if not available:
        raise EngineRenderError(f"Chromium engine unavailable: {reason}")
    if html_text is None:
        html_text = render_report_html(
            model, webfonts=not offline_mode_enabled()
        )
    return engine.render_pdf(
        html_text,
        base_url=None,
        options=build_pdf_options(model),
    )


# --- Orchestration (I/O) ----------------------------------------------------


def _compute_report_paths(
    workspace_dir: str, domains: list[str]
) -> list[dict[str, Any]]:
    """Compute and tag the per-domain canonical attack-path picture for the report.

    Derives each domain's paths from the reconciled attack graph via the shared
    SSOT :func:`~adscan_internal.services.report_attack_paths.compute_report_attack_paths`,
    the SAME domain-scoped computation the PRO kit uses — so both tiers show the
    same exposure. This deliberately does NOT read the interactive path snapshot:
    that file is a point-in-time projection of whatever query last wrote it (any
    scope/target, including a single-principal listing an operator was
    investigating), which is not the domain's exposure.
    Recomputing every time also makes the report deterministic. Each path is
    tagged with its ``_domain`` so a multi-domain report can label it.
    """
    from adscan_internal.services.report_attack_paths import (
        compute_report_attack_paths,
    )

    collected: list[dict[str, Any]] = []
    for domain in domains:
        for path in compute_report_attack_paths(workspace_dir, domain):
            if isinstance(path, dict):
                tagged = dict(path)
                tagged["_domain"] = domain
                collected.append(tagged)
    return collected


def _stamp_affected_assets(
    workspace_dir: str, domains: list[str], raw_paths: list[dict[str, Any]]
) -> bool:
    """Resolve each domain's affected assets into the technical report.

    Runs the tier-shared resolution seam
    (:func:`~adscan_internal.services.affected_assets_struct.stamp_workspace_affected_assets`)
    that the paid kit also calls, so a finding names the same object in both
    artifacts. Without this the free report knows a finding's title and severity
    but not which account, host or file it is about — which is the difference
    between a document a reader can act on and one they cannot.

    Best-effort by construction: the seam swallows its own failures, so a
    missing attack graph or an unwritable report leaves the findings unstamped
    and the document simply omits the assets.

    Returns:
        ``True`` when any domain's findings changed on disk.
    """
    from adscan_internal.services.affected_assets_struct import (
        stamp_workspace_affected_assets,
    )

    changed = False
    for domain in domains:
        domain_paths = [
            path for path in raw_paths if str(path.get("_domain") or "") == domain
        ]
        changed |= stamp_workspace_affected_assets(
            workspace_dir, domain, attack_paths=domain_paths or None
        )
    return changed


@dataclass(frozen=True)
class LiteReportArtifacts:
    """What one LITE report generation produced.

    Both files come from the same model and the same template. The ``.html``
    always exists — it is the copy that opens anywhere with no reader and
    survives being forwarded. The ``.pdf`` is the copy that circulates through
    a mail gateway and lands in front of a board or an auditor; it is absent
    only when Chromium could not run, which never fails the generation.
    """

    html_path: str
    pdf_path: Optional[str] = None
    #: What the document says, in counts. Carried here so the instrumented
    #: caller can record it without re-reading the workspace or rebuilding the
    #: model. ``None`` only when the model could not be built.
    content: Optional[ReportContentMetrics] = None


def generate_lite_report_artifacts(
    shell: Any,
    *,
    report_file: Optional[str] = None,
    output_path: Optional[str] = None,
    asked_for_the_kit: bool = False,
) -> Optional[LiteReportArtifacts]:
    """Generate the LITE exposure report as both HTML and PDF.

    Resolves the technical report + per-domain attack-path snapshots from the
    active workspace, builds the client-safe model, renders one self-contained
    ``.html`` file plus the paginated ``.pdf`` beside it, and prints a success
    panel with a short pointer to PRO. This is the single LITE render entry
    point behind the REPL ``generate_report`` / ``deliver`` verbs and
    ``adscan ci``.

    Args:
        shell: The active CLI shell (workspace context).
        report_file: Explicit path to ``technical_report.json``; defaults to the
            shell's resolved technical-report path.
        output_path: Explicit output ``.html`` path; defaults to a timestamped
            file at the workspace root. The PDF is written alongside it with a
            ``.pdf`` suffix.
        asked_for_the_kit: The operator typed ``deliver``, so the panel spells
            out what the paid kit adds instead of the one-line pointer.

    Returns:
        The produced artifacts, or ``None`` on failure (no workspace,
        unreadable report, or an HTML render/write error).
    """
    try:
        from adscan_internal.workspaces import read_json_file

        tr_path = (
            Path(report_file)
            if report_file
            else Path(_get_technical_report_path(shell))
        )
        if not tr_path.exists():
            print_error(
                "No scan data found yet. Run a scan first, then generate the report."
            )
            return None

        technical_report = read_json_file(str(tr_path))
        if not isinstance(technical_report, dict):
            print_error("The technical report is unreadable; cannot build the report.")
            return None

        domains = technical_report.get("domains")
        domain_names = (
            [str(d) for d in domains.keys() if isinstance(d, str) and d]
            if isinstance(domains, dict)
            else []
        )

        workspace_dir = str(
            getattr(shell, "current_workspace_dir", None) or tr_path.parent
        )
        raw_paths = _compute_report_paths(workspace_dir, domain_names)

        # Resolve what each finding is ABOUT before the model is built. The seam
        # writes back to the workspace's technical report, so re-read it when it
        # changed rather than resolving a second time in memory.
        if _stamp_affected_assets(workspace_dir, domain_names, raw_paths):
            restamped = read_json_file(str(tr_path))
            if isinstance(restamped, dict):
                technical_report = restamped

        workspace_name = str(
            getattr(shell, "current_workspace", None)
            or (domain_names[0] if domain_names else Path(workspace_dir).name)
        )

        # Read the write ledger from the live session first. The report renders
        # before the session ends, so the ``environment_changes`` block inside
        # technical_report.json is written LATER (at exit) and on a first run is
        # simply not there — reading it alone made a scan that minted machine
        # accounts and mutated templates tell the client nothing was touched.
        model = build_report_model(
            workspace_name=workspace_name,
            technical_report=technical_report,
            raw_paths=raw_paths,
            environment_changes=resolve_environment_changes(
                ledger=getattr(shell, "environment_change_ledger", None),
                workspace_dir=workspace_dir,
                report_block=technical_report.get("environment_changes"),
            ),
        )
        html_text = render_report_html(model)

        if output_path:
            out_path = Path(output_path)
        else:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path = Path(workspace_dir) / f"{_REPORT_FILENAME_PREFIX}_{stamp}.html"

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html_text, encoding="utf-8")

        pdf_path = _write_report_pdf(model, out_path)

        _print_report_ready_panel(
            str(out_path), pdf_path, asked_for_the_kit=asked_for_the_kit
        )
        return LiteReportArtifacts(
            html_path=str(out_path),
            pdf_path=pdf_path,
            content=derive_report_content_metrics(model),
        )
    except Exception as exc:  # noqa: BLE001 - report generation must never crash the caller
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error("Failed to generate the exposure report.")
        return None


def generate_lite_html_report(
    shell: Any,
    *,
    report_file: Optional[str] = None,
    output_path: Optional[str] = None,
    asked_for_the_kit: bool = False,
) -> Optional[str]:
    """Generate the LITE exposure report and return the ``.html`` path.

    Thin wrapper over :func:`generate_lite_report_artifacts` for the callers
    that carry a single report path (the REPL verbs and ``adscan ci``). The
    ``.pdf`` is written alongside regardless; the HTML is what is returned
    because it is the artifact that always exists.
    """
    artifacts = generate_lite_report_artifacts(
        shell,
        report_file=report_file,
        output_path=output_path,
        asked_for_the_kit=asked_for_the_kit,
    )
    return artifacts.html_path if artifacts else None


def _write_report_pdf(model: LiteReportModel, html_path: Path) -> Optional[str]:
    """Write the PDF next to the HTML; return its path, or ``None`` on failure.

    Best-effort by design: the HTML is already on disk and is the artifact the
    operator was promised, so a missing Chromium degrades to "one file instead
    of two" rather than failing the whole generation. The traceback still
    reaches the debug log so the absence is diagnosable.
    """
    pdf_path = html_path.with_suffix(".pdf")
    try:
        pdf_path.write_bytes(render_report_pdf(model))
        return str(pdf_path)
    except Exception as exc:  # noqa: BLE001 - the HTML report stands on its own
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(
            "The PDF copy of the exposure report could not be rendered; "
            "the self-contained HTML report was written."
        )
        return None


def _print_report_ready_panel(
    path: str,
    pdf_path: Optional[str] = None,
    *,
    asked_for_the_kit: bool = False,
) -> None:
    """Print the post-generation success panel.

    Leads with what the operator GOT (the shareable files), then a single dim
    line naming the paid, client-ready version. Built from Rich ``Text`` objects
    (never markup strings) so an absolute path in the body can never be misread
    as Rich markup.
    """
    from rich.console import Group
    from rich.text import Text

    from adscan_core.rich_output import print_panel

    # The PDF leads when it exists: it is the copy that gets forwarded onward.
    lines: list[Text] = []
    if pdf_path:
        lines.append(Text(pdf_path, style="bold"))
    lines.append(Text(path, style="bold"))
    lines.append(Text(""))

    if pdf_path:
        lines.append(
            Text(
                "Two copies of the same report. The PDF is the one that gets "
                "past a mail gateway and in front of a board; the HTML is "
                "self-contained and opens anywhere with no reader."
            )
        )
    else:
        lines.append(
            Text(
                "Self-contained HTML: no external files, so it survives being "
                "forwarded or attached to an email."
            )
        )

    lines.extend(
        [
            Text(""),
            Text(
                "It carries the exposure score, every finding with its severity and "
                "ATT&CK mapping, and the attack paths ADscan proved by executing them."
            ),
            Text(""),
            Text(
                "Send it to whoever owns the domain. Those paths stay open until "
                "someone closes them."
            ),
            Text(""),
        ]
    )

    if asked_for_the_kit:
        # The operator typed `deliver`, not `report`. They asked for the client
        # kit by name, so they are owed a straight answer about what the kit is
        # rather than the one-line pointer the report on-ramps get. Same
        # artifact, fuller answer, because the intent expressed was different.
        lines.extend(
            [
                Text("This is the free exposure report. The client kit adds:"),
                Text(""),
                Text("  Security Assessment Report mapped to DORA, NIS2, ENS and ISO 27001"),
                Text("  Per-finding remediation your client's sysadmin can execute"),
                Text("  AD Hardening Playbook"),
                Text("  AD Control Coverage Report"),
                Text("  Your branding, not ours"),
                Text(""),
                Text("An evening of writing, or a ZIP at the end of the engagement."),
                Text(""),
                Text(
                    cta_display_url("report_ready_panel"),
                    style=cta_link_style("report_ready_panel"),
                ),
            ]
        )
    else:
        lines.append(
            Text.from_markup(
                "Client-ready version with DORA / NIS2 / ENS mapping, per-finding "
                "remediation and your own branding: "
                + cta_markup(
                    "report_ready_panel", cta_display_url("report_ready_panel")
                ),
                style="dim",
            )
        )

    print_panel(Group(*lines), title="Exposure report ready", border_style="green")


def find_latest_exposure_report(shell: Any) -> Optional[str]:
    """Return the newest generated exposure-report ``.html`` in the workspace.

    Used by the LITE ``deliver`` upsell so it can point at an already-generated
    report instead of telling the operator to generate one again. Best-effort:
    returns ``None`` when there is no workspace or no report yet.
    """
    try:
        workspace_dir = getattr(shell, "current_workspace_dir", None)
        if not workspace_dir:
            return None
        candidates = sorted(
            Path(str(workspace_dir)).glob(f"{_REPORT_FILENAME_PREFIX}_*.html"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        return str(candidates[0]) if candidates else None
    except Exception:  # noqa: BLE001 - best effort, absence is a valid answer
        return None


# --- Template (self-contained, inline CSS + inline SVG) ---------------------

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ADscan Exposure Report — {{ m.domain_label }} — {{ m.generated_at }}</title>
<meta name="description" content="Active Directory exposure report for {{ m.domain_label }}, generated {{ m.generated_at }} with ADscan.">
{% if m.favicon_data_uri %}<link rel="icon" href="{{ m.favicon_data_uri }}">{% endif %}
<style>
{# The shared design system: theme tokens, reset and base type, the component
   grammar and the print rules. Same source the paid deliverable renders on.
   `safe` because it is bundled CSS, not user data — autoescaping it turns
   every child combinator into `&gt;` and silently kills those rules. #}
{{ design_css | safe }}

/* ═══════════════════════════════════════════════════════════════════════════
   Composition — this document only.

   A short report someone forwards to their manager. It opens on a masthead
   rather than a cover page, states its verdict in one sentence, and separates
   its sections with rules instead of boxes. Everything visual it uses beyond
   this file comes from the design system above.
   ═══════════════════════════════════════════════════════════════════════════ */

/* ── Sheet ──────────────────────────────────────────────────────────────── */
.sheet { max-width: 186mm; margin: 0 auto; }

@media screen {
  html, body { background: var(--bg-3); }
  /* A paper simulation, not a web page: the same document at the same scale,
     nudged up so body copy is comfortable on a laptop. `zoom` is the one
     property that scales absolute point sizes uniformly; where it is not
     supported the sheet simply renders at true A4 scale. */
  body { padding: 14mm 6mm 22mm; zoom: 1.12; }
  .sheet {
    background: var(--bg-0);
    padding: 14mm 14mm 16mm;
    box-shadow: 0 1px 2px rgba(28,24,21,.06), 0 12px 32px rgba(28,24,21,.09);
  }
}
@media screen and (max-width: 760px) {
  body { padding: 0; zoom: 1; }
  .sheet { padding: 10mm 6mm 12mm; box-shadow: none; }
}

/* ── Masthead ───────────────────────────────────────────────────────────── */
.masthead { border-top: 2px solid var(--accent); padding-top: 4mm; }
.masthead-row {
  display: flex; align-items: center; justify-content: space-between;
  gap: 6mm; margin-bottom: 9mm;
}
/* 11mm, the same physical size the paid deliverable sets its cover mark at, so
   the two tiers sign their work identically. At the previous 8mm the lockup's
   letterforms sat at roughly body-text height and the mark read as page
   furniture rather than as a signature on a document that gets forwarded to a
   CISO. It stays subordinate to the 30pt domain name below it, which is the
   headline. The running footer keeps the name as TEXT and gains no mark: a
   per-page logo band is brochure register, and this audience reads real
   penetration-test reports, which do not carry one. */
.masthead-mark svg { display: block; height: 11mm; width: auto; }
.masthead-mark .wordmark {
  font-family: var(--font-serif); font-weight: 800; font-size: 18pt;
  letter-spacing: -0.4px; color: var(--text);
}
.masthead-tag {
  font-size: 6pt; font-weight: 700; letter-spacing: 0.24em;
  text-transform: uppercase; color: var(--text-4);
  border: 1px solid var(--line-2); border-radius: 999px; padding: 1.4mm 3mm;
  white-space: nowrap;
}
.doc-title {
  font-family: var(--font-serif); font-weight: 700;
  font-size: 30pt; line-height: 1.02; letter-spacing: -1.2px;
  color: var(--text); margin-top: 3mm; word-break: break-word;
}
.doc-standfirst {
  font-size: 9pt; color: var(--text-3); line-height: 1.55;
  margin-top: 3mm; max-width: 62ch;
}
.masthead .ds-meta { padding-bottom: 5mm; border-bottom: 1px solid var(--line-2); }

/* ── Lede: the verdict, then the ledger ─────────────────────────────────── */
.lede { page-break-inside: avoid; }
.lede .ds-verdict { max-width: 30ch; margin-top: 12mm; }
.lede .ds-cols { margin-top: 12mm; }
.lede .ds-col { padding-top: 5mm; }

/* ── Sections ───────────────────────────────────────────────────────────── */
.ds-section { margin-top: 12mm; }
/* Page one is the executive page: masthead, verdict, ledger, bottom line and
   the severity split. The evidence starts on its own page — deliberately,
   rather than by accident of where the first table row happened to fall. */
.section-new-page { break-before: page; page-break-before: always; }

/* ── Findings table ─────────────────────────────────────────────────────── */
.findings-table { table-layout: fixed; }
.findings-table th.col-finding { width: 46%; }
.findings-table th.col-sev { width: 13%; }
.findings-table th.col-attck { width: 25%; }
.findings-table th.col-domain { width: 16%; }
.finding-name { font-weight: 600; color: var(--text); line-height: 1.35; }
.finding-cat {
  font-size: 7pt; letter-spacing: 0.1em; text-transform: uppercase;
  color: var(--text-4); margin-top: 0.8mm;
}
/* The objects a finding is about. Set in the mono stack because these are
   identifiers a reader copies into a console, and allowed to wrap mid-token so
   a long UNC path or FQDN cannot push the column open. */
.finding-assets {
  margin-top: 1.4mm; font-family: var(--font-mono); font-size: 6.8pt;
  line-height: 1.5; color: var(--text-2); overflow-wrap: anywhere;
}
.finding-asset + .finding-asset::before {
  content: "·"; color: var(--text-4); margin: 0 1.2mm;
}
.finding-assets-more { color: var(--text-4); margin-left: 1.2mm; }
.attck {
  display: inline-block; font-family: var(--font-mono); font-size: 6.5pt;
  color: var(--accent); border: 1px solid rgba(14,110,120,0.28);
  border-radius: 3px; padding: 0.4mm 1.4mm; margin: 0 1mm 1mm 0;
  white-space: nowrap;
}

/* ── Choke points ───────────────────────────────────────────────────────── */
.choke-table { table-layout: fixed; }
.choke-table th.col-rank { width: 7%; text-align: right; }
.choke-table th.col-tech { width: 43%; }
.choke-table th.col-paths { width: 32%; }
.choke-table th.col-princ { width: 18%; }
.choke-tech { font-weight: 600; color: var(--text); line-height: 1.35; }
.choke-n { font-family: var(--font-mono); font-weight: 600; color: var(--text-2); }

/* ── Attack paths ───────────────────────────────────────────────────────── */
.path + .path { margin-top: 5mm; }
.path {
  border-top: 1px solid var(--line-2); padding-top: 4mm;
  page-break-inside: avoid;
}
.path-head {
  display: flex; align-items: baseline; justify-content: space-between;
  gap: 4mm;
}
/* The status chip is the fixed element in this row and the route line is what
   gives: without this the chip was squeezed, wrapped to two lines and lifted
   itself off the baseline it shares with the path index. `min-width: 0` lets
   the left column actually shrink (a flex item defaults to min-width:auto and
   would otherwise push the chip instead of wrapping its own route line). */
.path-head > div { min-width: 0; }
.path-head > .chip { flex: none; }
/* Twelve paths can share one route line. The index makes each block
   referenceable in conversation ("path 07"), and the spine underneath is what
   actually tells them apart. */
.path-ix {
  font-family: var(--font-mono); font-size: 6.5pt; font-weight: 700;
  letter-spacing: 0.16em; color: var(--text-4); margin-bottom: 1.2mm;
}
.path-via {
  font-size: 7.5pt; color: var(--text-2); margin-top: 1.5mm; line-height: 1.45;
}
.path-via .ds-arrow { color: var(--accent); margin: 0 1mm; }
.path-more { font-size: 7.5pt; color: var(--text-4); margin-top: 2mm; }
/* The step technique reads as a lead-in to its own sentence, not as a label
   floating above it: same line, weight carries the distinction. */
.step-tech { font-weight: 700; color: var(--text); }
.omitted {
  margin-top: 6mm; padding: 3.5mm 4mm; background: var(--bg-1);
  border: 1px solid var(--line); font-size: 7.5pt; color: var(--text-3);
  line-height: 1.5;
}
.omitted b { color: var(--text-2); }
.empty { font-size: 8.5pt; color: var(--text-3); font-style: italic; }
.omitted a, .ds-fineprint a { color: var(--accent); font-weight: 600; text-decoration: none; }

/* ── Change disclosure ──────────────────────────────────────────────────── */
.changes-caption {
  font-size: 6.5pt; font-weight: 700; letter-spacing: 0.2em;
  text-transform: uppercase; color: var(--text-4); margin-top: 7mm;
}
.changes-table { table-layout: fixed; margin-top: 2mm; }
.changes-table th.col-change { width: 26%; }
.changes-table th.col-object { width: 44%; }
.changes-table th.col-state { width: 30%; }
.change-obj {
  font-family: var(--font-mono); font-size: 7pt; color: var(--text-3);
  margin-top: 0.8mm; word-break: break-all; line-height: 1.35;
}
.change-detail { font-size: 7.5pt; color: var(--text-3); margin-top: 1mm; line-height: 1.4; }

/* ── Colophon ───────────────────────────────────────────────────────────── */
.colophon {
  margin-top: 10mm; padding-top: 4mm; border-top: 2px solid var(--accent);
  font-size: 7.5pt; color: var(--text-3); line-height: 1.6;
  page-break-inside: avoid;
}
.colophon a { color: var(--accent); font-weight: 600; text-decoration: none; }
.colophon-upsell { margin-top: 2mm; color: var(--text-4); }

/* ── Print ──────────────────────────────────────────────────────────────── */
/* Geometry, plus the sheet colour. The pagination behaviour lives in the
   shared print layer, and the running footer is drawn by the engine into the
   bottom margin (Chromium has no @page margin boxes), configured in
   LITE_PDF_MARGIN.

   The background belongs HERE and nowhere else. Chromium does not propagate
   the root element's background into the @page margin area, so a document
   whose paper colour is only set on html/body prints a warm text column
   floating on a white border — the artifact reads as a screenshot of a page
   rather than as a page. Declaring it on @page fills the whole sheet, which
   is why the paid deliverable is full-bleed. */
@page { size: A4; margin: 13mm 12mm 16mm; background: var(--bg-0); }
@media print {
  /* A hairline of inner clearance, because Chromium clips at the printable
     box: an element whose own border lands exactly ON that edge prints
     without it. That is how the old severity strip shipped a card with three
     sides, and it catches anything flush-right — a status chip, the
     Confidential pill, the severity bar. One millimetre costs nothing and
     closes the whole class. */
  .sheet { max-width: none; padding: 0 1mm; }
  .doc-title { font-size: 26pt; }
}
</style>
</head>
<body class="ds-doc">
<div class="sheet">

  <header class="masthead">
    <div class="masthead-row">
      <div class="masthead-mark">
        {# Trusted, bundled brand asset (adscan_internal/assets/logos), resolved
           through the shared brand_assets SSOT — safe to inline unescaped. #}
        {% if m.brand_logo_svg %}{{ m.brand_logo_svg | safe }}{% else %}<span class="wordmark">ADscan</span>{% endif %}
      </div>
      <div class="masthead-tag">Confidential</div>
    </div>

    <div class="ds-eyebrow">Active Directory Exposure Report</div>
    <h1 class="doc-title">{{ m.domain_label }}</h1>
    {# The second sentence must stay true for a THEORETICAL path as well as a
       validated one. It once read "every path below was walked by the scanner",
       which the badges contradicted on the same render (1 of 15 walked) and
       which the attack-paths section lead contradicted three pages later. State
       what is actually guaranteed: the paths are derived from this directory,
       and each step is labelled with how far it was taken. #}
    <p class="doc-standfirst">
      Where an attacker can get to from inside this environment, and how far.
      Every path below was mapped from the directory's own configuration; each
      step is labelled with what was proven and what was not.
    </p>

    <div class="ds-meta">
      <div>
        <div class="ds-meta-k">Report date</div>
        <div class="ds-meta-v">{{ m.generated_at }}</div>
      </div>
      <div>
        <div class="ds-meta-k">Scope</div>
        <div class="ds-meta-v">{{ m.domain_count }} domain{{ '' if m.domain_count == 1 else 's' }}</div>
      </div>
      <div>
        <div class="ds-meta-k">Findings</div>
        <div class="ds-meta-v">{{ m.total_findings }}</div>
      </div>
      <div>
        <div class="ds-meta-k">Produced with</div>
        <div class="ds-meta-v">ADscan LITE</div>
      </div>
    </div>
  </header>

  <section class="lede">
    <p class="ds-verdict">
      <span class="ds-verdict-n{% if m.verdict_tone == 'ok' %} ds-tone-ok{% endif %}">{{ m.verdict_figure }}</span>
      {{ m.verdict_text }}
    </p>
    {% if m.verdict_reach %}<p class="ds-verdict-sub">{{ m.verdict_reach }}</p>{% endif %}

    <div class="ds-cols">
      <div class="ds-col">
        <div class="ds-figure-v{% if m.priority_findings %} critical{% endif %}">{{ m.priority_findings }}</div>
        <div class="ds-figure-k">High-priority findings</div>
        <div class="ds-figure-sub">{{ m.severity_counts['critical'] }} critical &middot; {{ m.severity_counts['high'] }} high</div>
      </div>
      <div class="ds-col">
        <div class="ds-figure-v{% if m.paths_to_domain_compromise %} critical{% endif %}">{{ m.paths_to_domain_compromise }}</div>
        <div class="ds-figure-k">Paths to full domain compromise</div>
        <div class="ds-figure-sub">of {{ m.paths_total }} identified attack path{{ '' if m.paths_total == 1 else 's' }}</div>
      </div>
      {# Posture, not exposure: this scale runs the other way (100 is healthy).
         Labelling it "exposure" inside a document called an Exposure Report is
         how a 2 gets read as "2% exposed, we are fine". The sub-line carries
         the exposure reading beside it so the two are never confused. #}
      <div class="ds-col">
        <div class="ds-figure-v{% if m.score_tone == 'critical' %} critical{% else %} accent{% endif %}">{{ m.score }}<small>/100</small></div>
        <div class="ds-figure-k">Posture score</div>
        <div class="ds-figure-sub">{{ m.score_label }} &middot; higher is safer</div>
      </div>
    </div>
  </section>

  <section class="ds-section">
    <div class="ds-note">
      <div class="ds-note-k">Bottom line</div>
      <div class="ds-note-t">{{ m.bottom_line }}</div>
    </div>
  </section>

  <section class="ds-section">
    <div class="sev-bar-wrap">
      <div class="sev-bar-label">Severity distribution &middot; {{ m.total_findings }} finding{{ '' if m.total_findings == 1 else 's' }}</div>
      <div class="sev-bar">
        {% for s in m.severity_slices %}{% if s.count %}<div class="sev-bar-seg {{ s.key }}" style="width: {{ s.share }}%"></div>{% endif %}{% endfor %}
      </div>
      <div class="sev-legend">
        {% for s in m.severity_slices %}
        <div class="sev-legend-item"><span class="sev-legend-dot {{ s.key }}"></span>{{ s.label }} <span class="sev-legend-n">{{ s.count }}</span></div>
        {% endfor %}
      </div>
    </div>
  </section>

  {% if m.choke_points %}
  <section class="ds-section section-new-page">
    <div class="ds-section-head">
      <div class="ds-eyebrow">Where to start</div>
      <h2 class="ds-section-title">The techniques that carry the most paths</h2>
      <p class="ds-section-lead">
        The {{ m.paths_total }} path{{ '' if m.paths_total == 1 else 's' }} above are not
        {{ m.paths_total }} separate problem{{ '' if m.paths_total == 1 else 's' }}. They run through a
        much smaller set of techniques, so closing the ones at the top of this table removes
        whole groups of paths at once. Ranked by how many paths each one carries.
      </p>
    </div>
    <table class="adscan-table choke-table">
      <thead>
        <tr>
          <th class="col-rank">#</th>
          <th class="col-tech">Technique</th>
          <th class="col-paths">Paths closed</th>
          <th class="col-princ">Principals</th>
        </tr>
      </thead>
      <tbody>
        {% for c in m.choke_points %}
        <tr>
          <td class="ds-rank">{{ c.rank }}</td>
          <td><div class="choke-tech">{{ c.technique }}</div></td>
          <td>
            <div class="ds-meter">
              <span class="ds-meter-n">{{ c.paths_eliminated }}</span>
              <span class="ds-meter-track"><span class="ds-meter-fill" style="width: {{ c.share }}%"></span></span>
              <span class="ds-meter-n">{{ c.share }}%</span>
            </div>
          </td>
          <td class="choke-n">{{ c.principals }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <div class="ds-fineprint">
      <b>How to read this.</b> &ldquo;Paths closed&rdquo; is how many of the
      {{ m.paths_total }} identified path{{ '' if m.paths_total == 1 else 's' }} stop working once that
      technique is no longer available, and the share is that count as a percentage of the total.
      &ldquo;Principals&rdquo; is how many distinct accounts start a path that uses it. Paths overlap,
      so the counts are not meant to add up to {{ m.paths_total }}.
      The step-by-step remediation for each one, written for the administrator who has to apply it,
      is part of <a href="{{ m.pro_url }}">ADscan PRO</a>.
    </div>
  </section>
  {% endif %}

  <section class="ds-section{% if not m.choke_points %} section-new-page{% endif %}">
    <div class="ds-section-head">
      <div class="ds-eyebrow">Evidence</div>
      <h2 class="ds-section-title">Findings</h2>
      <p class="ds-section-lead">
        Each finding names the objects it affects and the MITRE ATT&amp;CK techniques it enables.
        A finding that names only the domain is one where no single object carries it.
      </p>
    </div>
    {% if m.findings %}
    <table class="adscan-table findings-table">
      <thead>
        <tr>
          <th class="col-finding">Finding &amp; affected assets</th>
          <th class="col-sev">Severity</th>
          <th class="col-attck">ATT&amp;CK</th>
          {% if m.findings[0].domain %}<th class="col-domain">Domain</th>{% endif %}
        </tr>
      </thead>
      <tbody>
        {% for f in m.findings %}
        <tr>
          <td>
            <div class="finding-name">{{ f.title }}</div>
            <div class="finding-cat">{{ f.category }}</div>
            {% if f.assets %}
            <div class="finding-assets">
              {%- for a in f.assets %}<span class="finding-asset">{{ a }}</span>{% endfor -%}
              {%- if f.assets_overflow %}<span class="finding-assets-more">and {{ f.assets_overflow }} more</span>{% endif -%}
            </div>
            {% endif %}
          </td>
          <td><span class="chip {{ f.severity }}">{{ f.severity }}</span></td>
          <td>
            {% for t in f.mitre %}<span class="attck" title="{{ t.name }}">{{ t.id }}</span>{% endfor %}
            {% if not f.mitre %}<span class="ds-muted">&mdash;</span>{% endif %}
          </td>
          {% if f.domain %}<td class="ds-muted">{{ f.domain }}</td>{% endif %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p class="empty">No findings were recorded for this scan.</p>
    {% endif %}
  </section>

  <section class="ds-section">
    <div class="ds-section-head">
      <div class="ds-eyebrow">Evidence</div>
      <h2 class="ds-section-title">Attack paths</h2>
      <p class="ds-section-lead">
        {% if m.proven_paths %}{{ m.proven_paths }} path{{ '' if m.proven_paths == 1 else 's' }}
        validated end to end. {% endif %}Each step carries its honest outcome. A step that did
        not succeed is never attributed to a defensive control.
      </p>
    </div>
    {% if m.paths %}
    {% for p in m.paths %}
    <div class="path">
      <div class="path-head">
        <div>
          <div class="path-ix">Path {{ '%02d'|format(p.index) }}</div>
          <div class="ds-route">{{ p.source }}<span class="ds-arrow">&rarr;</span>{{ p.target }}</div>
          {% if p.via %}<div class="path-via">{% if p.steps %}{{ p.steps|length }}{% if p.extra_steps %}+{% endif %} step{{ '' if p.steps|length == 1 and not p.extra_steps else 's' }}, via {% else %}Via {% endif %}{{ p.via }}</div>{% endif %}
          {# SHORT reach label only. The full SSOT sentence opens with
             "Validated path to …" and would contradict the status chip on the
             same line for a theoretical or partially-validated path. #}
          <div class="ds-reach">{{ p.reach_label_short }}{% if p.domain %} &middot; {{ p.domain }}{% endif %}</div>
        </div>
        <span class="chip {{ p.status_tone }}">{{ p.status_label }}</span>
      </div>
      {% if p.steps %}
      <ol class="ds-steps">
        {% for s in p.steps %}
        <li>
          <span class="ds-step-txt">{% if s.technique %}<span class="step-tech">{{ s.technique }}.</span> {% endif %}{{ s.narrative }}</span>
          <span class="chip {{ s.status_tone }} ds-step-status">{{ s.status_label }}</span>
        </li>
        {% endfor %}
      </ol>
      {% if p.extra_steps %}<div class="path-more">+ {{ p.extra_steps }} further step{{ '' if p.extra_steps == 1 else 's' }} in this path.</div>{% endif %}
      {% endif %}
    </div>
    {% endfor %}
    {% if m.paths_omitted %}
    <div class="omitted">
      <b>{{ m.paths_omitted }} further path{{ '' if m.paths_omitted == 1 else 's' }} {{ 'is' if m.paths_omitted == 1 else 'are' }} not printed here.</b>
      This document shows the {{ m.paths|length }} highest-impact of {{ m.paths_total }};
      the rest reach the same or lower severity and reuse the techniques already ranked above,
      so they close with the same fixes. Every one of them is in the scan data on disk,
      and the full set is enumerated path by path in the
      <a href="{{ m.pro_url }}">ADscan PRO</a> deliverable.
    </div>
    {% endif %}
    {% else %}
    <p class="empty">No attack paths were materialised for this scan.</p>
    {% endif %}
    <div class="ds-fineprint">
      <b>Status legend.</b> Validated &mdash; proven end to end. Partially Validated &mdash; at
      least one step proven. Attempted &mdash; tried, did not complete. Not Executed for Safety
      &mdash; deliberately not run to avoid disruption. Attack Surface Reduced &mdash; an avenue
      observed closed by configuration. Not Assessed &mdash; outside this scan's coverage.
      Theoretical &mdash; derived from configuration, not executed.
    </div>
  </section>

  {# Written whether or not this run touched anything. A section that appears
     only when something went wrong teaches the reader that its absence means
     nothing was checked; a clean run is a statement the client is owed in
     writing. Buckets, labels and status vocabulary come from the cleanup
     ledger SSOT. #}
  <section class="ds-section">
    <div class="ds-section-head">
      <div class="ds-eyebrow">Accountability</div>
      <h2 class="ds-section-title">Changes made to your directory</h2>
      <p class="ds-section-lead">
        Proving an attack path sometimes requires writing to Active Directory: enrolling a
        certificate, creating an account, changing a permission. Every write is recorded as it
        happens and undone at the end, and this is the complete record for this scan.
      </p>
    </div>

    {% if not m.changes.determined %}
    <div class="ds-note">
      <div class="ds-note-k">Record not available</div>
      <div class="ds-note-t">
        The write record for this scan could not be read, so this report cannot state whether
        anything was changed. Check <code>environment_changes.json</code> in the workspace before
        treating the directory as untouched.
      </div>
    </div>
    {% elif m.changes.total == 0 %}
    <div class="ds-note">
      <div class="ds-note-k">Nothing was changed</div>
      <div class="ds-note-t">
        This scan made no writes to the directory. Nothing needs to be undone.
      </div>
    </div>
    {% else %}
    <div class="ds-cols">
      <div class="ds-col">
        <div class="ds-figure-v">{{ m.changes.total }}</div>
        <div class="ds-figure-k">Changes made</div>
        <div class="ds-figure-sub">recorded as they happened</div>
      </div>
      <div class="ds-col">
        <div class="ds-figure-v">{{ m.changes.reverted }}</div>
        <div class="ds-figure-k">Undone and confirmed</div>
        <div class="ds-figure-sub">re-read afterwards to verify</div>
      </div>
      <div class="ds-col">
        <div class="ds-figure-v{% if m.changes.needs_action %} critical{% endif %}">{{ m.changes.manual_required + m.changes.in_progress }}</div>
        <div class="ds-figure-k">Awaiting your action</div>
        <div class="ds-figure-sub">{% if m.changes.needs_action %}listed below with the object{% else %}nothing outstanding{% endif %}</div>
      </div>
    </div>

    {% if m.changes.manual_rows or m.changes.other_rows %}
    <div class="changes-caption">Still in place</div>
    <table class="adscan-table changes-table">
      <thead>
        <tr>
          <th class="col-change">Change</th>
          <th class="col-object">Object</th>
          <th class="col-state">State</th>
        </tr>
      </thead>
      <tbody>
        {% for c in m.changes.manual_rows + m.changes.other_rows %}
        <tr>
          <td>
            <div class="finding-name">{{ c.kind }}</div>
            {% if c.domain %}<div class="finding-cat">{{ c.domain }}</div>{% endif %}
          </td>
          <td>
            <div class="finding-name">{{ c.target }}</div>
            {% if c.object_dn %}<div class="change-obj">{{ c.object_dn }}</div>{% endif %}
          </td>
          <td>
            <span class="chip {{ c.status_tone }}">{{ c.status_label }}</span>
            {% if c.detail %}<div class="change-detail">{{ c.detail }}</div>{% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% endif %}

    {% if m.changes.reverted_rows %}
    <div class="changes-caption">Undone</div>
    <table class="adscan-table changes-table">
      <thead>
        <tr>
          <th class="col-change">Change</th>
          <th class="col-object">Object</th>
          <th class="col-state">Undone at</th>
        </tr>
      </thead>
      <tbody>
        {% for c in m.changes.reverted_rows %}
        <tr>
          <td>
            <div class="finding-name">{{ c.kind }}</div>
            {% if c.domain %}<div class="finding-cat">{{ c.domain }}</div>{% endif %}
          </td>
          <td>
            <div class="finding-name">{{ c.target }}</div>
            {% if c.object_dn %}<div class="change-obj">{{ c.object_dn }}</div>{% endif %}
          </td>
          <td>
            <span class="chip {{ c.status_tone }}">{{ c.status_label }}</span>
            {% if c.performed_at %}<div class="change-detail">{{ c.performed_at }}</div>{% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% endif %}
    {% endif %}

    <div class="ds-fineprint">
      {% if not m.changes.determined %}
      <b>Nothing is being claimed here.</b> This section reports the write ledger, and the ledger
      could not be read for this scan. Absence of a record is not evidence that the directory was
      left untouched.
      {% elif m.changes.needs_action %}
      <b>Action required.</b> The changes above could not be undone automatically. Each one names
      the exact object, so an administrator can reverse it directly. Until that is done, the
      change is still in place.
      {% elif m.changes.total %}
      <b>Nothing is outstanding.</b> Every change was reversed and then re-read to confirm the
      object was back to its original state.
      {% else %}
      This section is written on every scan, including this one. When a change cannot be undone
      automatically it appears here with the exact object, so it is never left to be discovered
      later.
      {% endif %}
    </div>
  </section>

  <footer class="colophon">
    Generated with ADscan LITE, the free Active Directory exposure scanner &mdash;
    <a href="{{ m.repo_url }}">{{ m.repo_url }}</a>
    <div class="colophon-upsell">
      <a href="{{ m.pro_url }}">ADscan PRO</a> turns this into the document you hand a client:
      how to close each technique above, written for the administrator who has to apply it,
      and the same evidence mapped to DORA, NIS2, ENS and ISO 27001.
    </div>
  </footer>

</div>
</body>
</html>
"""


__all__ = (
    "AttackPathRow",
    "ChangeDisclosure",
    "ChokePointRow",
    "EnvironmentChangeRow",
    "FindingAssetCoverage",
    "FindingRow",
    "LITE_PDF_MARGIN",
    "LITE_THEME",
    "LiteReportArtifacts",
    "LiteReportModel",
    "MAX_CHOKE_POINTS",
    "MAX_RENDERED_PATHS",
    "PathStepRow",
    "ReportContentMetrics",
    "SeveritySlice",
    "build_bottom_line",
    "build_change_disclosure",
    "build_choke_points",
    "build_pdf_options",
    "build_report_model",
    "build_severity_slices",
    "build_verdict",
    "build_verdict_reach",
    "derive_report_content_metrics",
    "find_latest_exposure_report",
    "finding_asset_state",
    "generate_lite_html_report",
    "generate_lite_report_artifacts",
    "render_report_html",
    "render_report_pdf",
    "status_presentation",
)
