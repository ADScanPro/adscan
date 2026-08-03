"""Attack-graph → technical-finding derivation (SHARED, LITE-safe).

Every technique ADscan proves lands in ``attack_graph.json`` as an exploitation
edge carrying a ``vuln_key``. This module is the ONLY producer that turns those
edges into findings in ``technical_report.json`` — which is the artifact the
free exposure report, the paid deliverable kit, the end-of-scan recap panel and
the web CTEM all count from.

Why it lives here and not under ``pro/``
----------------------------------------
It used to live in ``adscan_internal/pro/services/report_service.py``, which the
LITE image physically strips. On a LITE runtime the import failed, the sync was
cached as unavailable, and NO graph-derived finding was recorded for the whole
session: 37 of the 41 catalog keys an exploitation edge can carry — every ADCS
ESC, both domain-takeover CVEs, the delegation family, both roasting techniques,
the coercion primitives, LAPS and gMSA — reach a report only through this
derivation. The visible result was a free report whose cover printed
``0 critical`` on the same page it reported paths exploited end to end to full
domain compromise.

The derivation carries no product knowledge — it reads a key off an edge, groups
by key, and upserts a finding — so it belongs in the shared data layer of the
four-layer report doctrine (``CLAUDE.md`` § Dual-tier reporting). It is NOT in
``adscan_core`` because it needs two ``adscan_internal`` classifiers
(:func:`~adscan_internal.services.compromise_class.is_direct_domain_breaker_target`
and
:func:`~adscan_internal.services.domain_controller_classifier.classify_computer_node_role`)
and ``adscan_core`` may not import ``adscan_internal``.

What stays in ``pro/``: the narrative prose. The catalog block is resolved
through the injection seam in
:mod:`adscan_core.reporting.technical_report` (LITE gets the ``VULN_CATALOG_META``
slice, PRO installs the full ``VULN_CATALOG``-derived catalog), and the
per-instance personalisation
(``pro.reporting.finding_specifics.weave_specifics_into_knowledge``) is a lazy
optional import that simply does not run in LITE.
"""

from __future__ import annotations

import os
import uuid
from types import SimpleNamespace
from typing import Any, Iterable

from adscan_core.reporting.technical_report import (
    ReportShell,
    _append_unique,
    _ensure_technical_domain,
    _load_technical_report,
    _save_technical_report,
    _utc_now_iso,
    finding_catalog,
)
from adscan_core.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_warning,
)
from adscan_internal.reporting_compat import load_optional_pro_attr
from adscan_internal.services.attack_step_catalog import (
    classify_edge_relation,
    finding_basis_for_relation,
)
from adscan_internal.services.compromise_class import is_direct_domain_breaker_target
from adscan_internal.services.destructive_action_policy import non_execution_statement
from adscan_internal.services.domain_controller_classifier import (
    classify_computer_node_role,
)
from adscan_internal.services.path_state import carries_client_exposure
from adscan_internal.services.relay_status_constants import CONFIGURATION_CLOSE_STATUS

#: Directory (relative to a workspace root) holding the per-domain artifacts.
#: Mirrors the default ``shell.domains_dir`` and the report-path convention in
#: :mod:`adscan_internal.services.report_attack_paths`.
_DOMAINS_DIRNAME = "domains"

_PRO_CATALOG_PROVIDER_RESOLVED = False


def _ensure_pro_finding_catalog_provider() -> None:
    """Install the PRO finding-catalog provider once, when this build has it.

    The provider is what gives a PRO finding its ``category``, formal CVSS base
    and rich ``knowledge`` block. It used to be installed as an import SIDE
    EFFECT of the PRO report service, which the sync happened to import — so
    moving the derivation out of ``pro/`` would silently have stripped PRO's
    graph-derived findings of their depth. Installing it explicitly here, before
    the catalog is first resolved (which happens at the first graph save, ahead
    of any render), removes the dependency on that accident.

    A no-op in LITE: the optional-PRO seam resolves ``None`` when the module is
    stripped and the recorder keeps the ``VULN_CATALOG_META`` default.
    """
    global _PRO_CATALOG_PROVIDER_RESOLVED  # noqa: PLW0603
    if _PRO_CATALOG_PROVIDER_RESOLVED:
        return
    _PRO_CATALOG_PROVIDER_RESOLVED = True
    installer = load_optional_pro_attr(
        "adscan_internal.pro.reporting.finding_catalog",
        "install_finding_catalog_provider",
        action="PRO finding catalog",
        debug_printer=print_info_debug,
        prefix="[report]",
    )
    if callable(installer):
        installer()


def _resolve_finding_catalog() -> dict[str, dict[str, Any]]:
    """Return the finding catalog this build should stamp onto findings."""
    _ensure_pro_finding_catalog_provider()
    return finding_catalog()


def _summarize_attack_graph_edge_notes(notes: Any) -> dict[str, Any]:
    """Keep only report-relevant edge note fields when syncing findings."""
    if not isinstance(notes, dict):
        return {}

    summarized: dict[str, Any] = {}
    for key in (
        "template",
        "templates",
        "templates_summary",
        # Concrete per-instance ADCS assets the specifics weaver names in the
        # remediation prose (the abused certificate template(s) and CA). Without
        # preserving these here, an attack-graph-materialised ADCS finding loses
        # the template name and the narrative stays generic ("the affected
        # template"). ``vulnerable_resources`` is the canonical post-derivation
        # field; ``template_used_for_run`` / ``template_dn`` cover executed runs.
        "vulnerable_resources",
        "template_used_for_run",
        "template_dn",
        # Roasting / share-secret specifics: the cracking attempts (wordlist),
        # the share path and host where a secret was recovered, the SYSVOL
        # artifact. Preserved so the same weaver names them per instance.
        "attempts",
        "share_path",
        "share",
        "shares",
        # ``share_name`` is the field the attack-graph share edges carry (the
        # concrete share, e.g. ``public``); preserved so a share-secret finding
        # materialised from the graph still names the share in its narrative.
        "share_name",
        "host",
        "hostname",
        "artifact",
        "username",
        "principal",
        "expected_user",
        "matched_expected_user",
        "ptc_success",
        "resolved_domain",
        "source",
    ):
        value = notes.get(key)
        if value in (None, "", [], {}):
            continue
        summarized[key] = value
    return summarized


def _stamp_attack_graph_context_into_details(
    details: dict[str, Any],
    nodes_map: dict[str, Any],
    edges: list[dict[str, Any]],
) -> None:
    """Stamp Tier-0 / DC / exploitation context keys derived from edges.

    The shared CVSS engine (``adscan_core.cvss.calculator.extract_context_from_details``)
    only elevates a finding's severity to its contextual ADscan Priority when the
    finding ``details`` carry the exact context keys it reads. Attack-graph
    materialized findings used to carry only ``attack_graph_edges`` without that
    context, so contextual elevation never fired for them in either the PDF report
    or the web (both ingest the same ``technical_report.json``).

    This stamps, using ONLY the metadata already present on the graph nodes/edges
    (no re-tiering), the keys the calculator reads:
      * ``tier_zero_accounts`` (list[str]) — target labels that are Tier-0 /
        high-value / domain objects.
      * ``dc_hosts`` (list[str]) — target labels that are Domain Controllers.
      * ``exploitation_confirmed`` (bool) — any edge with a success status.

    Per the proven ``smb_relay_targets`` pattern, list-shaped context keys make
    the calculator set ``has_tier_zero_targets`` / ``has_dc_targets`` so the
    matching elevation rule (CONDITION_TIER_ZERO / CONDITION_DC_TARGETS /
    CONDITION_EXPLOITATION) is selected.
    """

    def _target_node(edge: dict[str, Any]) -> dict[str, Any] | None:
        node = nodes_map.get(str(edge.get("to") or ""))
        return node if isinstance(node, dict) else None

    def _label(node: dict[str, Any], fallback: str) -> str:
        return str(node.get("label") or node.get("name") or fallback)

    tier_zero_targets: list[str] = []
    dc_targets: list[str] = []
    exploitation_confirmed = False

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        # Any successfully-executed exploitation edge confirms exploitation.
        if str(edge.get("status") or "").strip().lower() == "success":
            exploitation_confirmed = True

        node = _target_node(edge)
        if node is None:
            continue
        label = _label(node, str(edge.get("to") or ""))

        # Tier-0 / high-value / domain object — reuse the metadata the graph
        # builder already stamped (isTierZero / highvalue), never recompute.
        if bool(node.get("isTierZero")) or bool(node.get("highvalue")):
            _append_unique(tier_zero_targets, label)

        # Domain Controller — alias/role-aware classification of Computer nodes
        # via the single source of truth (reads primaryGroupID / SPN / UAC).
        if classify_computer_node_role(node) in ("writable_dc", "rodc"):
            _append_unique(dc_targets, label)

    if tier_zero_targets:
        details["tier_zero_accounts"] = tier_zero_targets
    if dc_targets:
        details["dc_hosts"] = dc_targets
    if exploitation_confirmed:
        details["exploitation_confirmed"] = True


# Relations that are a real misconfiguration finding ONLY when the holder is a
# NON-breaker principal. When the holder/source IS a direct domain breaker
# (Domain Admins, Enterprise Admins, BUILTIN\Administrators, Domain Controllers,
# krbtgt, the domain object, DC computer accounts) the right is held BY DESIGN —
# surfacing it as a vulnerability is a false positive that erodes trust in front
# of a customer. The attack-graph EDGE is always preserved (the kill-chain /
# attack-path materialization still needs it); only the FINDING materialization
# is suppressed for breaker-held instances.
#
# Keyed by the lowercased edge ``relation`` so the set is trivially extensible to
# any other "legitimate-when-held-by-a-breaker" relation the same FP class
# applies to. Add the relation string here; the suppression logic below needs no
# change.
_BREAKER_HELD_LEGITIMATE_RELATIONS: frozenset[str] = frozenset({"dcsync"})


def _is_breaker_held_legitimate_edge(
    edge: dict[str, Any],
    nodes_map: dict[str, Any],
) -> bool:
    """Return whether *edge* is a breaker-held legitimate relation (no finding).

    A DCSync (or any other relation in
    :data:`_BREAKER_HELD_LEGITIMATE_RELATIONS`) whose SOURCE/holder node is a
    direct domain breaker holds that right by design — it is NOT a finding. A
    DCSync held by a NON-breaker (a regular/low-priv principal that somehow
    carries replication rights) is a genuine misconfiguration and MUST still
    become a finding, so only the breaker-held case returns ``True``.

    Reuses the nomenclature SSOT
    :func:`adscan_internal.services.compromise_class.is_direct_domain_breaker_target`
    on the source node — the same predicate ``/adcs`` uses to prune breaker
    actors — so this never drifts from the engine/report. Only the finding
    materialization consults this; the attack-graph edge is never touched.
    """
    relation = str(edge.get("relation") or "").strip().lower()
    if relation not in _BREAKER_HELD_LEGITIMATE_RELATIONS:
        return False
    source_node = nodes_map.get(str(edge.get("from") or ""))
    if not isinstance(source_node, dict):
        return False
    return is_direct_domain_breaker_target(source_node)


def _edge_declares_no_client_exposure(edge: dict[str, Any]) -> bool:
    """Return whether the graph itself declares this edge closes no exposure.

    Two shapes, both written by the ONE producer of the marker
    (``ntlmv1_relay_graph_builder._escalation_edge``), and neither of them a
    finding:

    * ``status == "closed_by_configuration"`` — the client's own configuration
      already closed the avenue and ADscan observed the close with certainty.
      This is the report's POSITIVE bucket ("Attack Surface Reduced — Hardening
      Observed"); billing them to fix hardening they already have inverts what
      the deliverable is for.
    * ``notes["blocked_reason"]`` present — the builder's durable verdict, set
      only alongside a configuration close or the ``no DC LDAP relay target``
      data gap. It is read as well as the status because a later execution pass
      REWRITES the status (``attempted`` / ``discovered`` / ``blocked``) while
      leaving the note intact, and the avenue does not reopen because a status
      field was overwritten. Reading it recovers the builder's verdict rather
      than inventing a second one.

    A safety abstention is deliberately NOT here: it carries ``blocked_kind`` and
    ``reason``, never ``blocked_reason``. ADscan refusing to run a destructive
    step says nothing about whether the avenue is open, so those edges keep
    producing findings (CLAUDE.md § Exposure Validation).
    """
    if str(edge.get("status") or "").strip().lower() == CONFIGURATION_CLOSE_STATUS:
        return True
    notes = edge.get("notes")
    if not isinstance(notes, dict):
        return False
    return bool(str(notes.get("blocked_reason") or "").strip())


def _key_carries_client_exposure(edges: list[dict[str, Any]]) -> bool:
    """Return whether a ``vuln_key``'s edges describe exposure worth reporting.

    Applied at KEY level, never per edge, because the not-assessed statuses are
    overloaded: ``unsupported`` on an ADCS ESC5 or AllExtendedRights edge means
    "the misconfiguration was read out of the directory, ADscan just does not
    auto-exploit it" (a real finding), while on an offline-crack edge it means
    "ADscan has no backend for this" (a gap in our coverage). A per-edge drop
    would delete the former along with the latter.

    The rule, in order:

    1. Any contributing edge whose status carries client exposure — anything
       outside ``closed_by_configuration`` / ``unsupported`` / ``unavailable``,
       so ``discovered``, ``attempted``, ``success`` and a safety ``blocked``
       all qualify — makes the key a finding.
    2. Otherwise every edge is not-assessed, and the answer comes from the
       catalog's :data:`~adscan_internal.services.attack_step_catalog.FindingBasis`
       axis: an ``observed_configuration`` relation still has an observed
       weakness to report; an ``execution_outcome`` relation has nothing left
       once execution is off the table.

    Args:
        edges: The key's exploitation edges, already filtered of the ones
            :func:`_edge_declares_no_client_exposure` rejects.

    Returns:
        ``True`` when the key belongs in the client's finding inventory.
    """
    if not edges:
        return False
    if any(carries_client_exposure(edge.get("status")) for edge in edges):
        return True
    return any(
        finding_basis_for_relation(str(edge.get("relation") or ""))
        == "observed_configuration"
        for edge in edges
    )


#: ``details`` keys the attack-graph derivation (and the affected-assets stamper
#: that runs behind it) owns. A finding whose details hold NOTHING else, and that
#: carries no evidence of its own, exists only because of the graph — so when the
#: gate stops backing its key, retracting it removes no independently-recorded
#: data. A detector-recorded finding always carries its own observation keys
#: (``probe_status``, ``captured_user``, …) and survives.
_DERIVATION_OWNED_DETAIL_KEYS: frozenset[str] = frozenset(
    {
        "attack_graph_edges",
        "attack_graph_edge_statuses",
        "attack_graph_non_execution",
        "tier_zero_accounts",
        "dc_hosts",
        "exploitation_confirmed",
        "_affected_assets_struct",
    }
)


def _finding_is_graph_only(finding: Any) -> bool:
    """Return whether a recorded finding exists ONLY because of graph edges.

    True when it is graph-derived, carries no evidence of its own, and every one
    of its ``details`` keys is in :data:`_DERIVATION_OWNED_DETAIL_KEYS`. A
    finding that also has a detector behind it (its own ``probe_status``,
    ``captured_user``, … keys) answers False, so retracting the graph backing
    never destroys independently-recorded observations.
    """
    if not isinstance(finding, dict):
        return False
    if finding.get("from_attack_graph") is not True:
        return False
    if finding.get("evidence"):
        return False
    details = finding.get("details")
    details = details if isinstance(details, dict) else {}
    return all(name in _DERIVATION_OWNED_DETAIL_KEYS for name in details)


def _retract_gated_findings(
    findings: list[Any],
    findings_by_key: dict[str, Any],
    gated_keys: set[str],
) -> bool:
    """Remove findings the gate no longer backs, so a re-sync heals the artifact.

    The derivation only ever upserted, so a workspace written before the gate
    landed keeps its false criticals until it is re-scanned. Both tiers reconcile
    the graph before they read ``technical_report.json``, so retracting here
    corrects those workspaces on the next render instead.

    Retraction is deliberately narrow. A finding is removed only when it is
    graph-derived, carries no evidence, and every one of its ``details`` keys is
    in :data:`_DERIVATION_OWNED_DETAIL_KEYS`. A finding that ALSO has a detector
    behind it keeps its row and merely loses the stale graph edges.

    Args:
        findings: The domain's mutable findings list.
        findings_by_key: Index into that list, updated in place.
        gated_keys: ``vuln_key`` values present in the graph that the gate
            excluded from the client inventory.

    Returns:
        True when the report was modified.
    """
    if not gated_keys:
        return False

    updated = False
    for key in gated_keys:
        finding = findings_by_key.get(key)
        if not isinstance(finding, dict):
            continue
        details = finding.get("details")
        details = details if isinstance(details, dict) else {}
        if not _finding_is_graph_only(finding):
            # Keep the row, drop the graph backing that no longer applies.
            for name in (
                "attack_graph_edges",
                "attack_graph_edge_statuses",
                "attack_graph_non_execution",
            ):
                if name in details:
                    details.pop(name)
                    updated = True
            continue
        try:
            findings.remove(finding)
        except ValueError:  # pragma: no cover - index/list already diverged
            continue
        findings_by_key.pop(key, None)
        updated = True
    return updated


def _group_reportable_edges_by_key(
    edges: list[Any],
    nodes_map: dict[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    """Group exploitation edges by ``vuln_key`` and split off the gated keys.

    The SSOT both :func:`sync_attack_graph_findings` and
    :func:`validate_attack_graph_findings_correlation` read, so the derivation
    and the guard that checks it can never disagree about which keys belong in
    the client's inventory — the guard previously reported zero errors on a
    workspace missing six findings because it applied a different filter.

    Args:
        edges: The graph's ``edges`` list.
        nodes_map: The graph's ``nodes`` mapping, for the breaker-held check.

    A graph written before edge classification moved to the save seam carries
    edges with no ``category`` at all — the CVE scanner's noPac / PrintNightmare
    and the whole NTLMv1 family. Reading the pair off the relation when the edge
    does not carry it heals those workspaces at render time, with no graph
    rewrite, and is what lets the guard below see the violation instead of
    filtering it away. A ``category`` the graph DOES carry always wins, so the
    fallback can only add findings, never move or drop one.

    Returns:
        ``(reportable, gated)`` — the surviving ``vuln_key`` → contributing-edge
        mapping, and the set of ``vuln_key`` values that appeared in the graph
        but carry no client exposure.
    """
    by_key: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or "").strip()
        if not relation:
            continue
        category, derived_vuln_key = classify_edge_relation(relation)
        if edge.get("category") is not None:
            category = str(edge.get("category") or "")
        if category != "exploitation":
            continue
        # Suppress finding materialization for breaker-held legitimate relations
        # (e.g. DCSync held by Domain Admins / Domain Controllers): the right is
        # held by design, so it is a false positive as a finding. The graph EDGE
        # is untouched — this only governs which edges feed the derivation, so
        # the kill-chain / attack-path materialization keeps the edge.
        if _is_breaker_held_legitimate_edge(edge, nodes_map):
            continue
        vuln_key = str(edge.get("vuln_key") or "").strip() or str(
            derived_vuln_key or ""
        )
        if not vuln_key:
            continue
        by_key.setdefault(vuln_key, [])
        if not _edge_declares_no_client_exposure(edge):
            by_key[vuln_key].append(edge)

    reportable: dict[str, list[dict[str, Any]]] = {}
    gated: set[str] = set()
    for vuln_key, key_edges in by_key.items():
        if _key_carries_client_exposure(key_edges):
            reportable[vuln_key] = key_edges
        else:
            gated.add(vuln_key)
    return reportable, gated


def _stamp_exposure_provenance_into_details(
    details: dict[str, Any],
    edges: list[dict[str, Any]],
) -> None:
    """Stamp what the contributing edges actually proved onto the finding.

    Without this the finding says only *that* the graph backs it, never *how far
    the graph got* — so a render surface has to re-derive the distinction from
    ``attack_graph.json``, and the deliverable ends up describing a detected-but-
    never-executed technique in the same words as one ADscan ran end to end.

    Two keys, both read straight off the edges:

    * ``attack_graph_edge_statuses`` — the sorted, de-duplicated execution
      statuses behind the finding.
    * ``attack_graph_non_execution`` — the client-safe sentence for a technique
      ADscan withheld or could not exercise, resolved through the ONE mapping
      every client surface uses (``destructive_action_policy``), so a safety
      abstention renders as "Not executed for safety" and never implies ADscan
      ran the destructive step.
    """
    statuses = sorted(
        {
            status
            for status in (
                str(edge.get("status") or "").strip().lower() for edge in edges
            )
            if status
        }
    )
    if statuses:
        details["attack_graph_edge_statuses"] = statuses
    else:
        details.pop("attack_graph_edge_statuses", None)

    statement = ""
    for edge in edges:
        notes = edge.get("notes")
        if not isinstance(notes, dict):
            continue
        statement = non_execution_statement(notes)
        if statement:
            break
    if statement:
        details["attack_graph_non_execution"] = statement
    else:
        details.pop("attack_graph_non_execution", None)


_SPECIFICS_WEAVER: Any = None
_SPECIFICS_WEAVER_RESOLVED = False


def _resolve_specifics_weaver() -> Any:
    """Resolve the PRO per-instance knowledge weaver once (``None`` in LITE).

    Memoized because the optional-PRO seam logs a debug line on every miss, and
    an unmemoized lookup inside the per-key loop emitted one such line per
    finding per sync on a LITE runtime.
    """
    global _SPECIFICS_WEAVER, _SPECIFICS_WEAVER_RESOLVED  # noqa: PLW0603
    if _SPECIFICS_WEAVER_RESOLVED:
        return _SPECIFICS_WEAVER
    _SPECIFICS_WEAVER_RESOLVED = True
    _SPECIFICS_WEAVER = load_optional_pro_attr(
        "adscan_internal.pro.reporting.finding_specifics",
        "weave_specifics_into_knowledge",
        action="Finding specifics",
        debug_printer=print_info_debug,
        prefix="[report]",
    )
    return _SPECIFICS_WEAVER


def _weave_specifics(
    vuln_key: str, knowledge: dict[str, Any], details: dict[str, Any]
) -> dict[str, Any]:
    """Personalise a catalog knowledge block with this instance's assets.

    The weaver is PRO-only narrative work and is stripped from LITE, so it is a
    lazy optional import: LITE keeps the generic catalog prose (or, on the meta
    catalog, no knowledge block at all) and nothing fails.
    """
    weave = _resolve_specifics_weaver()
    if not callable(weave):
        return knowledge
    return weave(vuln_key, knowledge, details)


def sync_attack_graph_findings(
    shell: ReportShell,
    domain: str,
    graph: dict[str, Any],
) -> bool:
    """Ensure exploitation edges appear as findings in the technical report.

    Idempotent: re-running against the same graph re-weaves the same knowledge
    and merges the same edge entries, so both the per-save call during a scan
    and the reconciliation at render time are safe.

    Returns:
        True if the report was updated, False otherwise.
    """
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not edges:
        return False

    def _label(node_id: str) -> str:
        node = nodes_map.get(node_id)
        if isinstance(node, dict):
            return str(node.get("label") or node.get("name") or node_id)
        return node_id

    # Keep the raw exploitation edges per vuln_key so we can derive Tier-0 / DC /
    # exploitation context from their target nodes (the labelled `entry` below
    # loses the node reference needed for that classification), and so the KEY
    # gate can read every contributing edge's status at once.
    raw_edges_by_key, gated_keys = _group_reportable_edges_by_key(edges, nodes_map)

    edges_by_key: dict[str, list[dict[str, Any]]] = {}
    for vuln_key, key_edges in raw_edges_by_key.items():
        entries: list[dict[str, Any]] = []
        for edge in key_edges:
            # Not every exploitation edge is written with node ids. The CVE and
            # post-exploitation writers record the endpoints as LABELS on the
            # edge itself (``source`` / ``target``), so resolving only
            # ``from``/``to`` summarized those edges to empty strings — which is
            # why a critical noPac or PrintNightmare finding named no vulnerable
            # host at all.
            from_id = str(edge.get("from") or "")
            to_id = str(edge.get("to") or "")
            entry = {
                "relation": str(edge.get("relation") or "").strip(),
                "source": _label(from_id)
                if from_id
                else str(edge.get("source") or "").strip(),
                "target": _label(to_id)
                if to_id
                else str(edge.get("target") or "").strip(),
            }
            note_summary = _summarize_attack_graph_edge_notes(edge.get("notes"))
            if note_summary:
                entry["notes"] = note_summary
            _append_unique(entries, entry)
        edges_by_key[vuln_key] = entries

    if not edges_by_key and not gated_keys:
        return False

    catalog_by_key = _resolve_finding_catalog()

    report = _load_technical_report(shell)
    domain_entry = _ensure_technical_domain(report, domain)
    findings = domain_entry["findings"]

    findings_by_key = {
        str(item.get("key") or ""): item for item in findings if isinstance(item, dict)
    }

    updated = False
    now = _utc_now_iso()

    # Heal FIRST: a workspace written before this gate landed carries findings
    # the graph no longer backs, and leaving them in place would have the report
    # keep asserting an avenue its own attack-path section reports as closed.
    if _retract_gated_findings(findings, findings_by_key, gated_keys):
        updated = True

    for finding in findings:
        if isinstance(finding, dict) and "from_attack_graph" not in finding:
            finding["from_attack_graph"] = False
            updated = True
        if isinstance(finding, dict) and "discovered_at" not in finding:
            finding["discovered_at"] = finding.get("first_seen") or now
            updated = True

    for vuln_key, edge_entries in edges_by_key.items():
        finding = findings_by_key.get(vuln_key)
        catalog = catalog_by_key.get(vuln_key, {})
        catalog_knowledge = catalog.get("knowledge")
        if finding is None:
            finding = {
                "id": uuid.uuid4().hex,
                "key": vuln_key,
                "title": catalog.get("title", vuln_key.replace("_", " ").title()),
                "severity": catalog.get("severity", "medium"),
                "category": catalog.get("category", "General"),
                "status": "confirmed",
                "from_attack_graph": True,
                "details": {},
                "evidence": [],
                "discovered_at": now,
                "first_seen": now,
                "last_seen": now,
            }
            # Attach the catalog's rich ``knowledge`` block (description, impact,
            # remediation, references) onto the materialized finding — mirroring
            # ``record_technical_finding`` in adscan_core. Without this, a finding
            # surfaced ONLY through the attack graph (e.g. ADCS ESC1) ships with
            # empty knowledge, so the web detail panel + PDF render no remediation
            # and the ingestion has nothing to enrich.
            if isinstance(catalog_knowledge, dict) and catalog_knowledge:
                finding["knowledge"] = catalog_knowledge
            findings.append(finding)
            findings_by_key[vuln_key] = finding
            updated = True
        else:
            if finding.get("from_attack_graph") is not True:
                finding["from_attack_graph"] = True
                updated = True
            if "discovered_at" not in finding:
                finding["discovered_at"] = finding.get("first_seen") or now
                updated = True
            if not finding.get("status"):
                finding["status"] = "confirmed"
            # Heal an existing finding that predates this fix (or was recorded
            # without knowledge) so re-syncs / replays backfill the catalog block.
            existing_knowledge = finding.get("knowledge")
            if (
                not isinstance(existing_knowledge, dict) or not existing_knowledge
            ) and (isinstance(catalog_knowledge, dict) and catalog_knowledge):
                finding["knowledge"] = catalog_knowledge
                updated = True
            finding["last_seen"] = now

        details = finding.get("details")
        if not isinstance(details, dict):
            details = {}
        existing_edges = details.get("attack_graph_edges")
        if not isinstance(existing_edges, list):
            existing_edges = []
        for entry in edge_entries:
            _append_unique(existing_edges, entry)
        details["attack_graph_edges"] = existing_edges

        # Stamp the Tier-0 / DC / exploitation context keys the shared CVSS
        # calculator reads so contextual elevation (ADscan Priority) fires for
        # attack-graph materialized findings in both the PDF and the web.
        previous_context = {
            "tier_zero_accounts": details.get("tier_zero_accounts"),
            "dc_hosts": details.get("dc_hosts"),
            "exploitation_confirmed": details.get("exploitation_confirmed"),
            "attack_graph_edge_statuses": details.get("attack_graph_edge_statuses"),
            "attack_graph_non_execution": details.get("attack_graph_non_execution"),
        }
        _stamp_attack_graph_context_into_details(
            details,
            nodes_map,
            raw_edges_by_key.get(vuln_key, []),
        )
        _stamp_exposure_provenance_into_details(
            details,
            raw_edges_by_key.get(vuln_key, []),
        )
        if any(details.get(key) != previous_context[key] for key in previous_context):
            updated = True
        finding["details"] = details

        # Personalise the catalog ``knowledge`` with THIS instance's concrete
        # assets (the abused certificate template(s), the roastable accounts,
        # the share/host where a secret was recovered). Run AFTER the edges are
        # merged into ``details`` so the specifics weaver can mine them. Both
        # the PDF report and the web platform render these ``knowledge`` strings
        # verbatim, so naming the assets here reaches both surfaces with no
        # per-technique render code. Re-weaves from the catalog baseline so a
        # re-sync stays idempotent and never double-appends. Generic narrative
        # stands gracefully when the instance carries no surfaceable specifics.
        if isinstance(catalog_knowledge, dict) and catalog_knowledge:
            personalized = _weave_specifics(vuln_key, catalog_knowledge, details)
            if personalized != finding.get("knowledge"):
                finding["knowledge"] = personalized
                updated = True

    if updated:
        _save_technical_report(shell, report)
    return updated


def validate_attack_graph_findings_correlation(
    attack_graph: dict[str, Any],
    technical_report: dict[str, Any],
    *,
    domain: str | None = None,
) -> list[str]:
    """Validate that exploitation edges and recorded findings agree.

    Checks the correlation in BOTH directions, through the same
    :func:`_group_reportable_edges_by_key` gate the derivation uses:

    * an edge whose key carries client exposure but has no finding — the report
      would under-count the domain;
    * a finding whose key the graph no longer backs — the report would keep
      asserting an avenue its own attack-path section reports as closed by the
      client's configuration, or one ADscan never assessed.

    The second direction is new. The guard used to walk edges only, so a
    workspace carrying stale false criticals passed clean — which is exactly the
    state this function exists to catch.
    """
    errors: list[str] = []
    findings_keys: set[str] = set()
    graph_only_keys: set[str] = set()

    domains_data = (
        technical_report.get("domains") if isinstance(technical_report, dict) else {}
    )
    if isinstance(domains_data, dict):
        for domain_key, domain_entry in domains_data.items():
            if (
                domain
                and str(domain_key).strip().lower() != str(domain).strip().lower()
            ):
                continue
            if not isinstance(domain_entry, dict):
                continue
            for finding in domain_entry.get("findings", []) or []:
                if not isinstance(finding, dict):
                    continue
                key = str(finding.get("key") or "").strip()
                if key:
                    findings_keys.add(key)
                    if _finding_is_graph_only(finding):
                        graph_only_keys.add(key)

    edges = (
        attack_graph.get("edges") if isinstance(attack_graph.get("edges"), list) else []
    )
    nodes_map = (
        attack_graph.get("nodes") if isinstance(attack_graph.get("nodes"), dict) else {}
    )
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or edge.get("type") or "").strip()
        if not relation:
            continue
        # EITHER source may declare the edge an exploitation step. Asking only the
        # persisted ``category`` is what made this guard blind to the defect it
        # exists to catch: an edge a writer persisted with no ``category`` answered
        # "not exploitation" and was skipped, so a workspace missing six findings
        # reported zero correlation errors. Asking only the relation would lose the
        # opposite gap — a graph that calls an edge exploitation while the catalog
        # has no technique behind it. A guard should see both.
        if (
            classify_edge_relation(relation)[0] != "exploitation"
            and str(edge.get("category") or "") != "exploitation"
        ):
            continue
        # A breaker-held legitimate relation is deliberately NOT materialized as
        # a finding (see _is_breaker_held_legitimate_edge) — reporting it as a
        # correlation gap would make the reconciliation warn on every run of a
        # perfectly healthy workspace.
        if _is_breaker_held_legitimate_edge(edge, nodes_map):
            continue
        if not str(edge.get("vuln_key") or "").strip():
            errors.append(f"Exploitation edge {relation} missing vuln_key")

    reportable, gated = _group_reportable_edges_by_key(edges, nodes_map)
    for vuln_key, key_edges in reportable.items():
        if vuln_key in findings_keys:
            continue
        relation = str(key_edges[0].get("relation") or "").strip()
        errors.append(
            f"Exploitation edge {relation} has vuln_key '{vuln_key}' but no corresponding finding"
        )
    for vuln_key in sorted(gated & graph_only_keys):
        errors.append(
            f"Finding '{vuln_key}' is recorded but no attack-graph edge backs it as "
            "client exposure (the avenue is closed by configuration or was never assessed)"
        )

    return errors


def validate_attack_graph_findings(shell: ReportShell, domain: str) -> list[str]:
    """Validate attack graph to technical report correlation for a domain."""
    from adscan_internal.services import attack_graph_service  # noqa: PLC0415

    graph = attack_graph_service.load_attack_graph(shell, domain)
    technical_report = _load_technical_report(shell)
    return validate_attack_graph_findings_correlation(
        graph,
        technical_report,
        domain=domain,
    )


def _workspace_graph_path(workspace_dir: str, domain: str) -> str:
    """Return ``<workspace_dir>/domains/<domain>/attack_graph.json``."""
    return os.path.join(
        str(workspace_dir), _DOMAINS_DIRNAME, str(domain), "attack_graph.json"
    )


def _discover_graph_domains(workspace_dir: str) -> list[str]:
    """Return the workspace domains that have an ``attack_graph.json`` on disk."""
    domains_root = os.path.join(str(workspace_dir), _DOMAINS_DIRNAME)
    try:
        entries = sorted(os.listdir(domains_root))
    except OSError:
        return []
    return [
        name
        for name in entries
        if os.path.isfile(_workspace_graph_path(workspace_dir, name))
    ]


def reconcile_workspace_attack_graph_findings(
    workspace_dir: str,
    *,
    technical_report_path: str | None = None,
    domains: Iterable[str] | None = None,
) -> list[str]:
    """Re-derive graph findings for a workspace and report residual gaps.

    The render-time backstop for the invariant "the findings and the attack
    graph tell the same story" — every exploitation edge that carries client
    exposure has a finding, and no finding outlives the edges that backed it.
    The per-save sync during a scan is what normally satisfies it; this exists
    because a report is also rendered against
    a workspace produced by an EARLIER build or a different runtime, and a
    deliverable that has the complete ``attack_graph.json`` in front of it must
    never render a document that contradicts it in silence.

    Both tiers call it before they read ``technical_report.json``, so the free
    report, the recap panel and the paid kit all count the same finding set.

    Args:
        workspace_dir: Workspace root (container path) — where the per-domain
            attack graphs live. For a LIVE scan this is the ``.run_*`` execution
            root, not the logical workspace.
        technical_report_path: Explicit ``technical_report.json`` to reconcile.
            Defaults to the one inside *workspace_dir*; pass it when the caller
            renders from a report path that is not under that root, so the file
            reconciled is the file rendered.
        domains: Domains to reconcile. ``None`` discovers every domain in the
            workspace that has an attack graph on disk.

    Returns:
        The residual correlation errors, one message per unmatched edge. Empty
        when the artifacts agree. Best-effort — never raises.
    """
    from adscan_internal.workspaces import read_json_file  # noqa: PLC0415

    residual: list[str] = []
    try:
        names = (
            [str(d) for d in domains if str(d).strip()]
            if domains is not None
            else _discover_graph_domains(workspace_dir)
        )
        if not names:
            return residual

        shell = SimpleNamespace(current_workspace_dir=str(workspace_dir))
        if technical_report_path:
            # ``_get_technical_report_path`` returns an absolute value as-is, so
            # this pins the reconciliation to exactly the file being rendered.
            shell.technical_report_file = str(
                os.path.abspath(str(technical_report_path))
            )
        for domain in names:
            graph_path = _workspace_graph_path(workspace_dir, domain)
            if not os.path.isfile(graph_path):
                continue
            graph = read_json_file(graph_path)
            if not isinstance(graph, dict):
                continue
            sync_attack_graph_findings(shell, domain, graph)
            errors = validate_attack_graph_findings_correlation(
                graph,
                _load_technical_report(shell),
                domain=domain,
            )
            if errors:
                residual.extend(errors)
                print_warning(
                    f"{len(errors)} attack-graph/finding disagreement(s) in "
                    f"{mark_sensitive(domain, 'domain')}; the report may "
                    "mis-count this domain."
                )
                for message in errors:
                    print_info_debug(f"[report] correlation gap: {message}")
    except Exception as exc:  # noqa: BLE001 - a report must never break on this
        print_info_debug(
            f"[report] attack-graph finding reconciliation failed: "
            f"{type(exc).__name__}: {exc}"
        )
    return residual


__all__ = [
    "reconcile_workspace_attack_graph_findings",
    "sync_attack_graph_findings",
    "validate_attack_graph_findings",
    "validate_attack_graph_findings_correlation",
]
