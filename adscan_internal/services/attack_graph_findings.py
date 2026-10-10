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
from typing import Any, Callable, Iterable, Optional

from adscan_core.reporting.technical_report import (
    ReportShell,
    _append_unique,
    _ensure_technical_domain,
    _load_technical_report,
    _save_technical_report,
    _utc_now_iso,
    finding_catalog,
)
from adscan_core import telemetry
from adscan_core.reporting.unauthenticated_reach import reached_via_from_notes
from adscan_core.rich_output import (
    mark_sensitive,
    print_exception,
    print_info_debug,
    print_warning,
)
from adscan_internal.reporting_compat import load_optional_pro_attr
from adscan_internal.services.attack_step_catalog import (
    classify_edge_relation,
    finding_basis_for_relation,
    source_tier_gated_for_relation,
)
from adscan_internal.services.compromise_class import (
    CompromiseClass,
    esae_tier_number,
    is_direct_domain_breaker_target,
    node_is_tier0_by_stamped_label,
    node_stamped_privilege_tier,
)
from adscan_internal.services.destructive_action_policy import non_execution_statement
from adscan_internal.services.domain_controller_classifier import (
    classify_computer_node_role,
)
from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind
from adscan_internal.services.path_state import carries_client_exposure
from adscan_internal.services.relay_status_constants import CONFIGURATION_CLOSE_STATUS
from adscan_internal.services.severity import (
    EdgeSeverityInput,
    Severity,
    compute_edge_severity,
)

#: Directory (relative to a workspace root) holding the per-domain artifacts.
#: Mirrors the default ``shell.domains_dir`` and the report-path convention in
#: :mod:`adscan_internal.services.report_attack_paths`.
_DOMAINS_DIRNAME = "domains"

#: Synthetic ``properties.domain`` placeholder a graph node carries for a
#: built-in / well-known-SID principal (Everyone, BUILTIN\\Administrators,
#: Domain Users, ...). A WELLKNOWN principal is LOCAL — never a foreign forest —
#: so its domain is unresolvable as a REAL domain yet must count as same-forest
#: with any resolvable endpoint. Single spelling shared by
#: :func:`_node_report_domain` and :func:`_node_is_synthetic_wellknown`; never
#: hardcode a second copy.
_WELLKNOWN_DOMAIN_SENTINEL = "wellknown"

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
        # ESC14 variant A carries no vulnerable SAN-UPN template — instead an
        # honest marker of the client-auth enrollment path the attacker uses to
        # obtain its own certificate (e.g. a Machine template via
        # MachineAccountQuota). Preserve it so the finding names the real
        # enrollment vehicle rather than leaving the template blank.
        "esc14a_enroll_path",
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


def _node_tier_zero_flagged(node: Any) -> bool:
    """Return whether a graph node is Tier-0 by its PRIVILEGE GRADE.

    The ONE authority in this module for "does this object's own privilege put
    it in Tier 0". It reads, in order:

    1. The stamped, membership+ACL-aware ``privilege_tier`` label
       (:func:`~adscan_internal.services.compromise_class.node_is_tier0_by_stamped_label`)
       — the SSOT, written post-graph from the transitive group closure, so a
       principal that is Tier 0 only THROUGH group membership (Backup Operators,
       Account Operators, Exchange Windows Permissions with a per-install RID) or
       through a reconciled ACL grant resolves here.
    2. The LEGACY raw ``isTierZero`` / ``highvalue`` booleans (top level and
       under ``properties``) as a FALLBACK ONLY. The collector writes them before
       the graph exists and gates them on a RID/SID allow-list, so they
       legitimately read ``False`` for every membership-derived Tier 0 — they are
       never the authority. Keeping them means a node with no stamp (an older
       graph) resolves exactly as it did before, making this read a strict
       SUPERSET: it can only ADD a correct Tier-0 promotion, never drop one.

    A node with no stamp AND no legacy flag is NOT Tier 0: an ungraded or
    indeterminate object must never be elevated, because a false Tier-0 claim in
    a client report is an overclaim (``CLAUDE.md`` § Exposure Validation).
    """
    if not isinstance(node, dict):
        return False
    if node_is_tier0_by_stamped_label(node):
        return True
    if bool(node.get("isTierZero")) or bool(node.get("highvalue")):
        return True
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    return bool(props.get("isTierZero")) or bool(props.get("highvalue"))


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
      * ``tier_zero_accounts`` (list[str]) — target labels that are Tier-0,
        graded through :func:`_node_tier_zero_flagged`: the stamped
        membership+ACL-aware ``privilege_tier`` SSOT first, the legacy
        ``isTierZero`` / ``highvalue`` booleans only as a fallback. This runs for
        EVERY finding key, so a finding whose target is Tier 0 through group
        membership alone (Backup Operators, Account Operators, Exchange Windows
        Permissions) elevates like any other — it used to read the legacy
        boolean, which is ``False`` for exactly those principals, so Tier-0
        elevation under-fired across the catalog.
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

        # Tier-0 / high-value object — graded through the module's single tier
        # authority, which consults the stamped membership+ACL-aware
        # ``privilege_tier`` SSOT first and only falls back to the legacy
        # ``isTierZero`` / ``highvalue`` booleans. Never re-tiers.
        if _node_tier_zero_flagged(node):
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


def _node_report_domain(node: Any) -> str:
    """Return a graph node's lowercased home domain, or ``""`` when unresolvable.

    Reads ``properties.domain`` first (populated on ~every node kind, including
    ``CertTemplate`` / ``EnterpriseCA``), then a top-level ``domain`` fallback.
    The synthetic ``"wellknown"`` placeholder is treated as unresolvable so it
    can never be used as a real domain to prove a same-forest relationship.
    """
    if not isinstance(node, dict):
        return ""
    domain = ""
    props = node.get("properties")
    if isinstance(props, dict):
        domain = str(props.get("domain") or "").strip().lower()
    if not domain:
        domain = str(node.get("domain") or "").strip().lower()
    if domain in ("", _WELLKNOWN_DOMAIN_SENTINEL):
        return ""
    return domain


def _node_is_synthetic_wellknown(node: Any) -> bool:
    """Return whether a node is a SYNTHETIC well-known-SID principal.

    The collector materialises ONE shared synthetic node per well-known SID
    (``collector/well_known_sids.py::_make_well_known_node``): top-level
    ``domain == "WELLKNOWN"`` and ``properties`` carrying ``synthetic`` /
    ``well_known_sid`` True. A well-known SID has no home domain of its own — it
    is evaluated LOCALLY in the security context of the object the right is on —
    so it is never a foreign forest. Detected by the robust property flags
    first, falling back to the ``_WELLKNOWN_DOMAIN_SENTINEL`` domain spelling
    :func:`_node_report_domain` already special-cases, so the two never diverge.
    DISTINCT from a genuinely MISSING domain (empty / absent, no flags), which
    stays unresolvable and must fail OPEN.
    """
    if not isinstance(node, dict):
        return False
    props = node.get("properties")
    if isinstance(props, dict) and (
        bool(props.get("well_known_sid")) or bool(props.get("synthetic"))
    ):
        return True
    domain = ""
    if isinstance(props, dict):
        domain = str(props.get("domain") or "").strip().lower()
    if not domain:
        domain = str(node.get("domain") or "").strip().lower()
    return domain == _WELLKNOWN_DOMAIN_SENTINEL


def _source_effective_domain_for_edge(source_node: Any, target_node: Any) -> str:
    """Return the SOURCE principal's EFFECTIVE domain for a tier-gated edge.

    A tier-gated exploitation edge (ACL / control: GenericAll / WriteDACL /
    DCSync / an ADCS ESC) is evaluated in the security context of the object the
    right sits ON — the edge's TARGET object. So a SYNTHETIC well-known-SID
    source (one shared node reused across every domain, so it may carry edges to
    targets in DIFFERENT domains/forests) has no home domain of its own; its
    effective domain for THIS edge is the target object's domain. The ladder:

    1. The source carries its OWN resolvable real domain (any non-synthetic
       node, or a future per-domain well-known materialisation) → use it. This
       is what keeps a GENUINE cross-forest edge firing.
    2. Else the source is a synthetic well-known node → anchor to the edge's
       TARGET-object domain (:func:`_node_report_domain`), the context the SID is
       evaluated in. (When the target is itself unresolvable this yields ``""``,
       so the caller fails OPEN — an unanchorable synthetic edge is kept.)
    3. Else a genuinely-missing (non-well-known) domain → ``""``; the caller
       fails OPEN (keep).
    """
    real = _node_report_domain(source_node)
    if real:
        return real
    if _node_is_synthetic_wellknown(source_node):
        return _node_report_domain(target_node)
    return ""


def _domains_linked_within_forest(
    source_domain: str,
    target_domain: str,
    domains_data: Any,
) -> bool:
    """Return whether a ``WITHIN_FOREST`` trust links the two domains (either way).

    Reads the trust SSOT ``domains_data[<d>]["trusts"]`` exactly as
    :func:`attack_graph_core._iter_within_forest_child_parent` does — a trust
    entry matching the partner on ``target_domain`` with the ``WITHIN_FOREST``
    bit in its ``attribute_flags``. A ``FOREST_TRANSITIVE`` / ``CROSS_ORGANIZATION``
    / external / absent trust is therefore NOT a same-forest proof. Fail-closed:
    no usable trust data → ``False`` (keep the finding).
    """
    if not isinstance(domains_data, dict):
        return False

    def _has_within_forest(entry: Any, partner: str) -> bool:
        if not isinstance(entry, dict):
            return False
        for trust in entry.get("trusts") or ():
            if not isinstance(trust, dict):
                continue
            tgt = str(trust.get("target_domain") or "").strip().lower()
            flags = {
                str(flag).strip().upper()
                for flag in (trust.get("attribute_flags") or ())
            }
            if tgt == partner and "WITHIN_FOREST" in flags:
                return True
        return False

    return _has_within_forest(
        domains_data.get(source_domain), target_domain
    ) or _has_within_forest(domains_data.get(target_domain), source_domain)


def _edge_endpoints_same_forest(
    edge: dict[str, Any],
    nodes_map: dict[str, Any],
    domains_data: Any,
) -> bool:
    """Return ``True`` ONLY on a POSITIVE same-forest proof for an edge.

    Same domain is the always-provable same-forest floor (needs no trust data);
    two different domains require a ``WITHIN_FOREST`` trust linking them. The
    SOURCE domain is its EFFECTIVE domain for THIS edge
    (:func:`_source_effective_domain_for_edge`): a real domain when the node
    carries one (so a genuine cross-forest crossing still fires), else — for a
    SYNTHETIC well-known-SID source — the edge's TARGET-object domain, because a
    well-known SID is evaluated in the target's security context (never a
    foreign forest). Every OTHER unresolvable case — a genuinely MISSING (empty,
    non-well-known) domain on either endpoint, no trust data, a
    non-``WITHIN_FOREST`` or absent linking trust — returns ``False`` so the
    finding is KEPT. Suppression requires positive proof; cross-forest (either
    direction) and any doubt fail OPEN.
    """
    source_node = nodes_map.get(str(edge.get("from") or ""))
    target_node = nodes_map.get(str(edge.get("to") or ""))
    source_domain = _source_effective_domain_for_edge(source_node, target_node)
    target_domain = _node_report_domain(target_node)
    if not source_domain or not target_domain:
        return False
    if source_domain == target_domain:
        return True
    return _domains_linked_within_forest(source_domain, target_domain, domains_data)


def _source_is_broad_or_dynamic_identity(source_node: dict[str, Any]) -> bool:
    """Return whether the edge source is a broad / dynamic well-known identity.

    Everyone / Authenticated Users / BUILTIN Users / Domain Users / Domain
    Computers / Anonymous Logon and the like. If such an identity is (wrongly)
    stamped Tier-0 because it was placed INTO a Tier-0 group, its Tier-0 status
    IS the finding — so it must NEVER be suppressed. Reuses the ACE-step SSOT
    predicates (:func:`is_broad_domain_source` /
    :func:`is_wellknown_all_principals_source`) plus the dynamic-identity SSOT
    (:func:`principal_is_dynamic_identity`).
    """
    from adscan_internal.cli.ace_step_execution import (  # noqa: PLC0415
        is_broad_domain_source,
        is_wellknown_all_principals_source,
    )
    from adscan_internal.services.well_known_principals import (  # noqa: PLC0415
        principal_is_dynamic_identity,
    )

    label = str(source_node.get("label") or source_node.get("name") or "")
    sid = ""
    props = source_node.get("properties")
    if isinstance(props, dict):
        sid = str(props.get("objectid") or "").strip()
    if not sid:
        sid = str(source_node.get("objectId") or "").strip()
    if is_broad_domain_source(label) or is_wellknown_all_principals_source(label):
        return True
    return principal_is_dynamic_identity(sid=sid, label=label)


def _source_is_non_compromisable_identity(source_node: dict[str, Any]) -> bool:
    """Return whether the edge source is a machine/control-plane NT-AUTHORITY SID.

    System / LocalService / NetworkService (``S-1-5-18/19/20``) are not
    compromisable attack sources (see
    :func:`adscan_internal.services.well_known_principals.is_non_compromisable_source`),
    so an edge sourced from one — most commonly the by-design ``System
    --GenericAll--> Domain`` ACE — must NOT become a client finding. Reads the
    node's stamped SID, never its label name.
    """
    from adscan_internal.services.well_known_principals import (  # noqa: PLC0415
        is_non_compromisable_source,
    )

    if not isinstance(source_node, dict):
        return False
    sid = ""
    props = source_node.get("properties")
    if isinstance(props, dict):
        sid = str(props.get("objectid") or "").strip()
    if not sid:
        sid = str(
            source_node.get("objectId") or source_node.get("objectid") or ""
        ).strip()
    return is_non_compromisable_source(sid)


def _node_tier_number(node: Any) -> int | None:
    """Return a graph node's coarse ESAE tier number (0/1/2), or ``None``.

    Reads the membership-aware STAMPED ``privilege_tier`` SSOT
    (:func:`node_stamped_privilege_tier`), collapsing both Tier-0 subtiers to 0
    via :func:`esae_tier_number` (lower = more privileged). When the node carries
    no stamp (an older graph / a synthetic node), falls back to the identity
    direct-breaker SSOT (:func:`is_direct_domain_breaker_target`, True for the
    domain object, the RID-500/512/… principals and DC accounts) as Tier-0.
    Returns ``None`` only when the tier is genuinely unresolvable, so the caller
    fails OPEN rather than inventing a tier. NEVER reads the raw ``isTierZero``.
    """
    if not isinstance(node, dict):
        return None
    stamped = node_stamped_privilege_tier(node)
    if stamped is not None:
        return esae_tier_number(stamped)
    if is_direct_domain_breaker_target(node):
        return 0
    return None


def _edge_vuln_key(edge: dict[str, Any]) -> str:
    """Return the ``vuln_key`` an edge carries, falling back to its relation.

    Mirrors the resolution in :func:`_group_reportable_edges_by_key`: an explicit
    ``edge["vuln_key"]`` wins, else the key the catalog derives from the relation.
    """
    _, derived_vuln_key = classify_edge_relation(str(edge.get("relation") or ""))
    return str(edge.get("vuln_key") or "").strip() or str(derived_vuln_key or "")


def _effective_target_tier_number(
    edge: dict[str, Any], nodes_map: dict[str, Any]
) -> int | None:
    """Return the EFFECTIVE target tier number of a tier-gated exploitation edge.

    The gate evaluates where the edge ACTUALLY leads, not its literal graph
    endpoint. Every other tier-gated finding (the generic control group,
    constrained delegation, LAPS/gMSA read, RBCD write, and DCSync — whose target
    node IS the domain, stamped ``tier0_direct``) reads the STAMPED tier of its
    literal target node via :func:`_node_tier_number`.

    **The ``adcs_esc*`` branch holds for TWO different reasons, and the second one
    is why it must not be "corrected" away.**

    1. For a TEMPLATE-terminal ESC edge the target is a ``CertTemplate`` /
       ``EnterpriseCA`` object, but the capability it grants is a certificate that
       impersonates a Tier-0 identity, so the effective target tier is Tier-0 (0)
       whatever tier the template node carries.
    2. **ESC14-A is no longer template-terminal: it terminates on the VICTIM
       account** (the collector emits ``writer -> ADCSESC14 -> victim``), which is
       routinely an ordinary Tier-2 user. So reason 1 does NOT describe it, and
       reading the victim's stamped tier instead would make a Tier-2 writer over a
       Tier-2 victim a same-tier edge, drop it out of the gate, and silently
       delete the finding. That is forbidden: an ESC14 condition is reported
       whether or not it reaches Tier 0, because a weak explicit
       ``altSecurityIdentities`` mapping (or write access to one) is never a
       legitimate configuration, unlike a ``GenericAll`` that may be a real
       delegation model (founder decision, 2026-10-10; see BACKLOG.md § "Every
       ESC14 finding claims a Tier-0 reach"). The proposal to suppress
       non-escalating ESC14 findings was evaluated and REJECTED.

    So do not narrow this branch to template-terminal ESC edges on the grounds
    that reason 1 misdescribes ESC14-A. Reason 2 keeps it, and
    ``tests/unit/services/test_tier_jump_finding_gate.py`` locks it.
    """
    if _edge_vuln_key(edge).lower().startswith("adcs_esc"):
        return 0
    return _node_tier_number(nodes_map.get(str(edge.get("to") or "")))


def _edge_is_tier_jump_finding(
    edge: dict[str, Any],
    nodes_map: dict[str, Any],
    domains_data: Any = None,
) -> bool:
    """Return whether a TIER-GATED exploitation edge is a boundary violation.

    The single SSOT predicate (spec ``2026-10-02-acl-tier-jump-finding-gate`` §4)
    deciding whether a relationship/ACL/escalation edge becomes a client finding.
    A tier-gated right matters ONLY when the SOURCE principal crosses a boundary
    it should not — a forest-trust crossing, or an UPWARD tier-band crossing —
    regardless of the client's intent. Fires iff:

    * the endpoints are NOT provably same-forest (cross-forest = a trust
      escalation finding, regardless of the source's home-forest tier; every
      unresolvable same-forest case fails OPEN to keep); OR
    * same-forest AND the source is a broad / dynamic well-known identity
      (Everyone / Authenticated Users / Domain Users / Domain Computers): the
      whole authenticated population holding the right IS the finding; OR
    * same-forest AND the source tier is strictly LOWER-privilege (a larger ESAE
      number) than the EFFECTIVE target tier (:func:`_effective_target_tier_number`)
      — the upward escalation.

    A Tier-0 source administering its own same-forest estate (``Domain Admins ->
    DCSync``, a CA's machine account over its PKI, ``Domain Admins -> ESC1``) is
    NOT a finding: it cannot cross upward (effective target Tier-0, source
    Tier-0, ``0 > 0`` is False), which SUBSUMES the former
    ``_is_tier0_source_legitimate_edge``. A same-tier or downward same-forest edge
    (e.g. ``tier2 -> tier2`` GenericAll/ForceChangePassword) is likewise NOT a
    finding: it is a path step + choke point, not a standalone client finding.

    Tiers are read from the STAMPED ``privilege_tier`` SSOT, NEVER raw
    ``isTierZero``. The attack-graph EDGE is never touched — only finding
    materialisation reads this, so the kill-chain / attack-path / reach surface
    keeps the edge.
    """
    if not _edge_endpoints_same_forest(edge, nodes_map, domains_data):
        return True
    source_node = nodes_map.get(str(edge.get("from") or ""))
    if isinstance(source_node, dict) and _source_is_broad_or_dynamic_identity(
        source_node
    ):
        return True
    source_tier = _node_tier_number(source_node)
    target_tier = _effective_target_tier_number(edge, nodes_map)
    if source_tier is None or target_tier is None:
        # Fail OPEN: an unresolvable tier must not silently suppress a finding.
        return True
    return source_tier > target_tier


def edge_qualifies_as_finding(
    edge: dict[str, Any],
    nodes_map: dict[str, Any],
    domains_data: Any = None,
) -> bool:
    """Return whether an attack-graph edge qualifies as a client finding.

    The PUBLIC single source of truth for "is this edge a reportable finding?",
    shared by the report/CTEM finding materializer (via the private inverse
    :func:`_tier_gated_edge_suppressed`) AND the CLI post-collection tactical
    findings panel (``adscan_internal.cli.intelligence._build_tactical_findings``)
    so the two surfaces apply ONE gate and can never diverge. The rule:

    * CONDITION relation (``source_tier_gated=False``: kerberoast, asreproast,
      unconstrained delegation, the CVEs, the access/session edges, ESC8, …) —
      always qualifies; it BYPASSES the tier-jump gate.
    * TIER-GATED relation (``source_tier_gated=True``: the generic control ACLs,
      DCSync, constrained delegation, LAPS/gMSA read, RBCD write, the tier-gated
      ADCS ESCs) — qualifies ONLY when the source principal crosses a boundary it
      should not, per the SSOT predicate :func:`_edge_is_tier_jump_finding`
      (cross-forest OR an upward tier-band crossing). A Tier-0 source over its own
      same-forest estate (a DC / sync account / Account-or-Backup Operators / an
      RODC's own ADCS ESC) is NOT a finding.
    * Unknown relation — ``source_tier_gated_for_relation`` returns ``False`` (the
      safe direction), so it qualifies, preserving the pre-gate behaviour.

    Tiers are read from the STAMPED ``privilege_tier`` SSOT, never raw
    ``isTierZero``. The attack-graph EDGE is never mutated — only finding
    materialisation reads this, so the kill-chain / attack-path / reach surface
    keeps the edge.
    """
    source_node = nodes_map.get(str(edge.get("from") or ""))
    if isinstance(source_node, dict) and _source_is_non_compromisable_identity(
        source_node
    ):
        # Machine / control-plane NT-AUTHORITY source (System / LocalService /
        # NetworkService): a by-design ACE, never a compromisable finding source.
        # Applied to EVERY relation (the materializer iterates raw edges and never
        # consults the traversal gate) so the false SYSTEM->domain finding is
        # suppressed regardless of whether the relation is tier-gated.
        return False
    relation = str(edge.get("relation") or "").strip()
    if not source_tier_gated_for_relation(relation):
        return True
    return _edge_is_tier_jump_finding(edge, nodes_map, domains_data)


def _tier_gated_edge_suppressed(
    edge: dict[str, Any],
    nodes_map: dict[str, Any],
    domains_data: Any = None,
) -> bool:
    """Return whether the tier-jump gate suppresses this edge from finding materialisation.

    The flag-aware seam applied at every finding-materialization point, defined as
    the exact inverse of the public SSOT :func:`edge_qualifies_as_finding` so there
    is ONE gate implementation shared by the materializer and the CLI tactical
    findings panel. A CONDITION finding (``source_tier_gated=False`` — kerberoast,
    the CVEs, unconstrained delegation, the privileged-session finding) BYPASSES
    the gate and is never suppressed by it. A TIER-GATED finding is suppressed iff
    its edge is NOT a boundary violation (:func:`_edge_is_tier_jump_finding`).
    """
    return not edge_qualifies_as_finding(edge, nodes_map, domains_data)


def _is_tier0_source_legitimate_edge(
    edge: dict[str, Any],
    nodes_map: dict[str, Any],
    domains_data: Any = None,
) -> bool:
    """Return whether an exploitation edge is a Tier-0-source, same-forest
    legitimate relation that must NOT become a client finding.

    The Tier-0-source case of the general tier-jump predicate
    (:func:`_edge_is_tier_jump_finding`), kept as a named inverse for the PRO
    import surface (``adscan_internal.pro.services.report_service``) and its
    direct unit coverage (``tests/unit/services/test_attack_graph_findings.py``).
    It is defined ENTIRELY in terms of the general predicate so there is ONE rule,
    not two hand-rolled ones: a Tier-0 source administering its own same-forest
    estate is exactly the ``source_tier > effective_target_tier`` branch failing
    for an effective-Tier-0 target (``0 > 0`` is False), plus the broad-source
    and cross-forest limbs. The production materialization seams call the
    flag-aware :func:`_tier_gated_edge_suppressed`; this wrapper does NOT consult
    the ``source_tier_gated`` flag, so it must only be read for an edge already
    known to be tier-gated (DCSync / ADCS ESC, as its callers use it).
    """
    return not _edge_is_tier_jump_finding(edge, nodes_map, domains_data)


def _emit_control_plane_sync_account_items(
    shell: ReportShell,
    domain: str,
    graph: dict[str, Any],
) -> None:
    """Emit the Tier-0 asset-hardening item(s) for any AAD Connect sync account.

    Thin, best-effort bridge into the positive-evidence SSOT
    (:func:`adscan_internal.services.positive_control_evidence.emit_control_plane_sync_account_items`),
    co-located with the DCSync-finding suppression so the reframe (suppress the
    finding, surface the hardening item) stays atomic. Lazily imported to avoid an
    import cycle and to keep the emit optional; never raises into the caller.
    """
    try:
        from adscan_internal.services.positive_control_evidence import (
            emit_control_plane_sync_account_items,
        )

        emit_control_plane_sync_account_items(shell, domain, graph)
    except Exception as exc:  # pragma: no cover - best effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _reconcile_shadow_credential_segmentation(
    shell: ReportShell,
    domain: str,
    graph: dict[str, Any],
) -> None:
    """Scope the shadow-credential finding to what a Hello rollout cannot explain.

    Thin, best-effort bridge into the positive-evidence SSOT
    (:func:`adscan_internal.services.positive_control_evidence.reconcile_shadow_credential_segmentation`).
    It runs HERE because the segmentation needs the STAMPED privilege tier, which
    only exists once the graph has been built: the collector that records the raw
    finding cannot resolve a membership-derived Tier 0. Lazily imported to avoid
    an import cycle; never raises into the caller.
    """
    try:
        from adscan_internal.services.positive_control_evidence import (
            reconcile_shadow_credential_segmentation,
        )

        reconcile_shadow_credential_segmentation(shell, domain, graph)
    except Exception as exc:  # pragma: no cover - best effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _reconcile_external_tenant_replication(shell: ReportShell) -> None:
    """Settle the external-tenant replication finding across every domain.

    Thin, best-effort bridge into the positive-evidence SSOT
    (:func:`adscan_internal.services.positive_control_evidence.reconcile_external_tenant_replication`),
    co-located with the sync-account emit above because the two are the same
    subject: that emit surfaces the by-design hardening item per domain, this
    decides, once the whole report exists, which of those accounts replicates
    somewhere the organization does not own. Lazily imported to avoid an import
    cycle; never raises into the caller.
    """
    try:
        from adscan_internal.services.positive_control_evidence import (
            reconcile_external_tenant_replication,
        )

        reconcile_external_tenant_replication(shell)
    except Exception as exc:  # pragma: no cover - best effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


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


#: The ``vuln_key`` of the privileged-session exposure finding ("Privileged
#: Sessions on Lower-Tier Hosts"). Its contributing edges are ``HasSession``
#: (``Computer -> User``), and it is a credential-exposure VIOLATION only when the
#: logged-on USER is MORE privileged than the HOST (:func:`_session_edge_is_tier_violation`).
_SESSION_EXPOSURE_VULN_KEY = "da_sessions"

#: The constrained-delegation finding (``allowedtodelegate`` edges). Its severity
#: is graded WITHIN the finding by whether any surviving delegation is a
#: protocol-transition (TrustedToAuthForDelegation) one — see
#: :func:`_grade_constrained_delegation_severity`.
_CONSTRAINED_DELEGATION_VULN_KEY = "constrained_delegation"

#: The ESC15 / EKUwu (CVE-2024-49019) finding key. Its collection-time active
#: confirmation verdict is lifted from the edge notes to a top-level finding
#: detail by :func:`_stamp_esc15_confirmation_into_details`.
_ESC15_VULN_KEY = "adcs_esc15"

#: The ESC14 (weak explicit certificate mapping) finding key. Same confirmation
#: lift as ESC15, keyed on the ``esc14_confirmed`` edge-note marker.
_ESC14_VULN_KEY = "adcs_esc14"


def _esc15_note_flag_is_true(value: Any) -> bool:
    """Return whether an ESC confirmation edge-note flag is truthy."""
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _stamp_adcs_confirmation_into_details(
    details: dict[str, Any],
    raw_edges: list[dict[str, Any]],
    *,
    confirmed_note_key: str,
) -> None:
    """Lift an ADCS-ESC collection-time confirmation verdict to the finding details.

    The collection-stage confirmation phase stamps ``<confirmed_note_key>`` (e.g.
    ``esc15_confirmed`` / ``esc14_confirmed``) and ``confirmation_pending`` onto the
    derived ``ADCSESC*`` edge notes. This reads those across the contributing edges
    and sets a top-level ``confirmation_resolved`` (a confirmed-exploitable
    instance, graded a hard non-conformity) or ``confirmation_pending`` (the
    existence condition could not be actively verified) on the finding details,
    which :func:`finding_confidence.finding_requires_client_confirmation` consumes.

    A confirmed instance wins over a pending one (a proven-exploitable candidate in
    the finding makes it a real non-conformity regardless of other candidates). When
    no edge carries a confirmation marker, neither flag is set and the static
    ``CONFIRMATION_PENDING_FINDING_KEYS`` default (pending) stands.
    """
    resolved = False
    pending = False
    for edge in raw_edges:
        if not isinstance(edge, dict):
            continue
        notes = edge.get("notes")
        if not isinstance(notes, dict):
            continue
        if _esc15_note_flag_is_true(notes.get(confirmed_note_key)):
            resolved = True
        if _esc15_note_flag_is_true(notes.get("confirmation_pending")):
            pending = True
    if resolved:
        details["confirmation_resolved"] = True
        details.pop("confirmation_pending", None)
    elif pending:
        details["confirmation_pending"] = True
        details.pop("confirmation_resolved", None)


def _stamp_esc15_confirmation_into_details(
    details: dict[str, Any],
    raw_edges: list[dict[str, Any]],
) -> None:
    """Lift the ESC15 confirmation verdict from edge notes to the finding details."""
    _stamp_adcs_confirmation_into_details(
        details, raw_edges, confirmed_note_key="esc15_confirmed"
    )


_ESC14_FOOTPRINT_ORDER = ("A", "B", "D", "C")


def _stamp_esc14_variant_summary_into_details(
    details: dict[str, Any],
    raw_edges: list[dict[str, Any]],
) -> None:
    """Lift the FULL confirmed ESC14 variant set + executed variant to the finding.

    ESC14 renders as ONE finding across its (up to four) avenues, not four
    near-identical findings. The confirmation phase stamps ``esc14_variants`` (the
    full confirmed set) and the executor stamps ``esc14_executed_variant`` (the one
    proven end to end) onto the contributing edges. This unions the confirmed set
    across edges, footprint-orders it, and records which single variant was
    executed, so the report and the web CTEM can say "N avenues confirmed; variant
    X proven end to end; one root fix (StrongCertificateBindingEnforcement = Full)
    closes all". Reach is NOT summed across variants — they are the same avenues of
    one finding with one root remediation.
    """
    confirmed: set[str] = set()
    executed: Optional[str] = None
    for edge in raw_edges:
        if not isinstance(edge, dict):
            continue
        notes = edge.get("notes")
        if not isinstance(notes, dict):
            continue
        for value in notes.get("esc14_variants") or ():
            letter = str(value).strip().upper()
            if letter in _ESC14_FOOTPRINT_ORDER:
                confirmed.add(letter)
        marker = str(notes.get("esc14_executed_variant") or "").strip().upper()
        if marker in _ESC14_FOOTPRINT_ORDER:
            executed = marker
    if confirmed:
        details["esc14_confirmed_variants"] = [
            letter for letter in _ESC14_FOOTPRINT_ORDER if letter in confirmed
        ]
    if executed:
        details["esc14_executed_variant"] = executed


def _grade_constrained_delegation_severity(
    finding: dict[str, Any],
    raw_edges: list[dict[str, Any]],
) -> bool:
    """Uplift the constrained-delegation finding when it is protocol-transition.

    A constrained delegation with TrustedToAuthForDelegation ("Use any
    authentication protocol", S4U2Self + S4U2Proxy) impersonates a victim
    WITHOUT the victim ever authenticating to the delegating service, so it is
    materially more dangerous than a Kerberos-only (S4U2Proxy-only) delegation.
    The collector stamps ``protocol_transition`` on each ``AllowedToDelegate``
    edge from the source principal's userAccountControl; if ANY surviving
    (tier-gated, upward-crossing) delegation carries it, the finding is graded
    HIGH (above the Kerberos-only catalog base). Uplift only — never downgrades a
    finding the edge-severity SSOT already raised higher.

    Returns ``True`` when the severity changed.
    """
    protocol_transition = any(
        isinstance(edge, dict)
        and isinstance(edge.get("notes"), dict)
        and bool(edge["notes"].get("protocol_transition"))
        for edge in raw_edges
    )
    if not protocol_transition:
        return False
    current = str(finding.get("severity") or "medium").lower()
    graded = _uplift_finding_severity(current, Severity.HIGH)
    if graded != current:
        finding["severity"] = graded
        return True
    return False


def _session_edge_is_tier_violation(
    edge: dict[str, Any],
    nodes_map: dict[str, Any],
) -> bool:
    """Return whether a ``HasSession`` edge is a real tiered-admin violation.

    A logon session is a credential-exposure violation ONLY when the user whose
    session sits on the host is MORE privileged (a LOWER ESAE tier number) than
    the host itself: a Tier-0 user on a Tier-1/Tier-2 host, or a Tier-1 user on a
    Tier-2 host. Then the higher-tier credential (NTLM hash / Kerberos TGT /
    cached secret) is exposed in the LSASS of a lower-trust machine, so a
    compromise of that host escalates the attacker's tier.

    The edge is ``Computer -> HasSession -> User`` (``from`` = session host,
    ``to`` = logged-on user). Tiers are read from the stamped, membership-aware
    ``privilege_tier`` SSOT for BOTH endpoints (never raw ``isTierZero``). The
    directness split within Tier 0 is collapsed by :func:`esae_tier_number`, so a
    Tier-0-direct user on a Tier-0-escalation-capable host (both ESAE Tier 0) is
    NOT a violation.

    Fails open to EXCLUDE: a same-tier session, an inverse session (a lower-tier
    user on a higher-tier host, which is expected and exposes no higher
    credential), and any pair where either endpoint carries no tier stamp (an
    honest data gap, not a provable violation) are all dropped.
    """
    host_node = nodes_map.get(str(edge.get("from") or ""))
    user_node = nodes_map.get(str(edge.get("to") or ""))
    if not isinstance(host_node, dict) or not isinstance(user_node, dict):
        return False
    host_tier = node_stamped_privilege_tier(host_node)
    user_tier = node_stamped_privilege_tier(user_node)
    if host_tier is None or user_tier is None:
        return False
    return esae_tier_number(user_tier) < esae_tier_number(host_tier)


def _group_reportable_edges_by_key(
    edges: list[Any],
    nodes_map: dict[str, Any],
    domains_data: Any = None,
) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    """Group exploitation edges by ``vuln_key`` and split off the gated keys.

    The SSOT both :func:`sync_attack_graph_findings` and
    :func:`validate_attack_graph_findings_correlation` read, so the derivation
    and the guard that checks it can never disagree about which keys belong in
    the client's inventory — the guard previously reported zero errors on a
    workspace missing six findings because it applied a different filter.

    Args:
        edges: The graph's ``edges`` list.
        nodes_map: The graph's ``nodes`` mapping, for the Tier-0-source check.
        domains_data: The session trust SSOT (``shell.domains_data``), consulted
            only to prove a cross-domain endpoint pair is same-forest. ``None`` /
            empty is the standalone-render case and fails open (keeps the
            finding), so the only positive same-forest proof it is not needed for
            is a same-domain edge.

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
        vuln_key = str(edge.get("vuln_key") or "").strip() or str(
            derived_vuln_key or ""
        )
        if not vuln_key:
            continue
        # Register the key for gating BEFORE any per-edge suppression, so a key
        # whose edges are ALL suppressed still reaches ``gated`` below and
        # ``_retract_gated_findings`` prunes a stale row written on a pre-gate
        # workspace. (The earlier DCSync carve-out used a bare ``continue`` here,
        # which dropped the key from ``by_key`` entirely — a latent linger bug.)
        by_key.setdefault(vuln_key, [])
        # Tier-jump gate (spec 2026-10-02-acl-tier-jump-finding-gate §4/§6). A
        # TIER-GATED finding (``source_tier_gated=True``: DCSync, the generic
        # control group, constrained delegation, LAPS/gMSA read, RBCD write, the
        # ADCS ESCs) is a client finding ONLY when the source principal crosses a
        # boundary upward or across a forest trust — so a Tier-0 source over its
        # own same-forest estate (``Domain Admins -> DCSync``, ``Domain Admins ->
        # ESC1``, a CA's machine account over its PKI) and a same-tier / downward
        # same-forest edge (``tier2 -> tier2`` GenericAll/ForceChangePassword) are
        # NOT findings: held/placed by design, path-shaping only. A CONDITION
        # finding (``source_tier_gated=False``: kerberoast, the CVEs, unconstrained
        # delegation) BYPASSES the gate and always contributes. The edge is NOT
        # contributed when suppressed (so an all-suppressed key drops), but a
        # MIXED-origin key survives via its upward / cross-forest edges. The graph
        # EDGE is untouched — the kill-chain / attack-path materialization keeps it.
        if _tier_gated_edge_suppressed(edge, nodes_map, domains_data):
            continue
        # Privileged-session exposure: a ``HasSession`` edge is only a tiered-admin
        # violation when the logged-on user is MORE privileged than the host it
        # sits on. Same-tier, inverse, and tier-unknown sessions are NOT a
        # credential-exposure finding — they only dilute the inventory with rows a
        # remediator cannot act on. (Keeps the key registered above so an
        # all-suppressed workspace still prunes a stale row.)
        if vuln_key == _SESSION_EXPOSURE_VULN_KEY and not _session_edge_is_tier_violation(
            edge, nodes_map
        ):
            continue
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


def _edge_report_entry(
    edge: dict[str, Any], label_fn: Callable[[str], str]
) -> dict[str, Any]:
    """Build the label-based ``attack_graph_edges`` entry for a graph edge.

    Not every exploitation edge is written with node ids — the CVE and
    post-exploitation writers record the endpoints as LABELS on the edge itself
    (``source`` / ``target``), so resolving only ``from``/``to`` would summarize
    those edges to empty strings. Shared by the surviving-edge stamping and the
    suppressed-edge pruning so both build byte-identical entries (``_append_unique``
    / list membership match on value equality).
    """
    from_id = str(edge.get("from") or "")
    to_id = str(edge.get("to") or "")
    entry = {
        "relation": str(edge.get("relation") or "").strip(),
        "source": label_fn(from_id)
        if from_id
        else str(edge.get("source") or "").strip(),
        "target": label_fn(to_id)
        if to_id
        else str(edge.get("target") or "").strip(),
    }
    # Carry the per-edge STEP status onto the summarized entry. The roasting
    # affected-assets builder reads it to stamp a per-account crack status
    # (success -> CRACKED, attempted/failed -> attempted, discovered -> exposed);
    # other consumers dedupe by display string, so a status-only difference never
    # duplicates a rendered row. Both the surviving-edge stamping and the
    # suppressed-edge pruning go through here, so they stay byte-identical.
    status = str(edge.get("status") or "").strip()
    if status:
        entry["status"] = status
    note_summary = _summarize_attack_graph_edge_notes(edge.get("notes"))
    if note_summary:
        entry["notes"] = note_summary
    return entry


def _suppressed_tier0_edge_entries_by_key(
    edges: list[Any],
    nodes_map: dict[str, Any],
    label_fn: Callable[[str], str],
    domains_data: Any = None,
) -> dict[str, list[dict[str, Any]]]:
    """Return, per ``vuln_key``, the label-entries of exploitation edges that the
    tier-jump gate suppresses.

    Finding EXISTENCE is already gated per-edge in
    :func:`_group_reportable_edges_by_key` (a suppressed tier-gated edge is never
    contributed, so an all-suppressed key drops). This completes the suppression
    for the AFFECTED-ASSETS surface of a MIXED finding that survives on its
    upward / cross-forest edges: the merge into ``details.attack_graph_edges`` is
    additive, so a finding first stamped on a pre-gate workspace keeps its stale
    same-tier / Tier-0-source rows (e.g. the Force Change Password finding carried
    its ~1.8k ``Exchange Windows Permissions`` -> user self-management rows
    alongside the handful of real upward-crossing rows). Reuses the SAME
    :func:`_tier_gated_edge_suppressed` seam — no re-derived tier logic — so the
    entries pruned here match exactly the edges the grouping gate dropped. The
    classification mirrors :func:`_group_reportable_edges_by_key` so the two can
    never disagree about which edges are suppressed.
    """
    suppressed: dict[str, list[dict[str, Any]]] = {}
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
        vuln_key = str(edge.get("vuln_key") or "").strip() or str(
            derived_vuln_key or ""
        )
        if not vuln_key:
            continue
        if not _tier_gated_edge_suppressed(edge, nodes_map, domains_data):
            continue
        suppressed.setdefault(vuln_key, []).append(
            _edge_report_entry(edge, label_fn)
        )
    return suppressed


def _edge_entry_identity(entry: Any) -> tuple[str, str, str] | None:
    """Return a STABLE ``(relation, source, target)`` identity for an edge entry.

    The prune of suppressed Tier-0-source edges matches on this identity, NOT on
    full-dict value equality: a persisted entry stamped by an earlier build carries
    only ``relation``/``source``/``target``, while a freshly built one can also
    carry ``status`` / ``notes``, so a value-equality match silently misses the
    stale rows (the 1.8k ``Exchange Windows Permissions`` self-management rows the
    Force Change Password finding kept). The identity is case-normalised so a label
    casing difference never defeats the prune.
    """
    if not isinstance(entry, dict):
        return None
    return (
        str(entry.get("relation") or "").strip().casefold(),
        str(entry.get("source") or "").strip().casefold(),
        str(entry.get("target") or "").strip().casefold(),
    )


def _merge_edge_entries_by_identity(
    existing: list[Any], new_entries: Any
) -> list[dict[str, Any]]:
    """Merge edge entries deduped by ``(relation, source, target)`` identity.

    The additive merge into ``details.attack_graph_edges`` must collapse entries
    that describe the SAME edge, not keep one copy per dict shape. Two copies of
    one edge appear whenever a persisted entry (stamped before a per-edge key like
    ``status``/``notes`` existed) meets a freshly built one that now carries it:
    full-dict ``_append_unique`` sees them as different and keeps both, which then
    renders as a DUPLICATE affected-asset row (e.g. the same session pair twice in
    the Privileged Sessions finding). Keying on the stable identity and UNIONING
    the keys (richer value wins) collapses them to one entry while preserving the
    added ``status``/``notes``. First-seen order is kept.
    """
    by_identity: dict[tuple[str, str, str], dict[str, Any]] = {}
    order: list[tuple[str, str, str]] = []
    passthrough: list[dict[str, Any]] = []
    for entry in list(existing) + [e for e in new_entries]:
        if not isinstance(entry, dict):
            continue
        ident = _edge_entry_identity(entry)
        if ident is None:
            passthrough.append(entry)
            continue
        if ident in by_identity:
            for key, value in entry.items():
                if value not in (None, "") and not by_identity[ident].get(key):
                    by_identity[ident][key] = value
        else:
            by_identity[ident] = dict(entry)
            order.append(ident)
    return [by_identity[i] for i in order] + passthrough


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


#: Finding-severity rank (lowercase report labels). Higher = more severe. Used
#: to uplift a finding's catalog base severity with an edge-derived severity
#: without ever downgrading it (the edge-severity SSOT can only raise the floor).
_FINDING_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _uplift_finding_severity(catalog_base: str, edge_severity: Severity) -> str:
    """Return the more severe of the catalog base and the edge-derived severity.

    The edge-severity SSOT (:func:`compute_edge_severity`) expresses the
    CONTEXTUAL exposure of the materialized entry (e.g. CRITICAL for a proven
    no-credential chain onto a Tier-0 terminal). A credential-leak finding also
    has an intrinsic catalog base (HIGH for a GPP cpassword). The finding's
    severity is the maximum of the two — the context can only uplift, never
    downgrade a real finding below what it warrants on its own.
    """
    base_label = str(catalog_base or "medium").lower()
    edge_label = edge_severity.value.lower()
    base_rank = _FINDING_SEVERITY_RANK.get(base_label, 2)
    edge_rank = _FINDING_SEVERITY_RANK.get(edge_label, 2)
    return edge_label if edge_rank >= base_rank else base_label


#: Loose finding keys that link to the materialized attack graph through their
#: ``details._affected_assets_struct[].node_id`` rather than through an
#: ``exploitation`` edge carrying a ``vuln_key`` (the credential-read edge is
#: classified ``relationship`` — it shapes the path but is not itself a reportable
#: exploitation edge). These findings are recorded with their affected-asset
#: struct at scan time; this module links them to the proven-unauthenticated
#: credential edge so they inherit ``from_attack_graph`` and a contextual
#: severity derived from the edge-severity SSOT.
#:
#: ``gpp_passwords`` (GPP cpassword / autologon over SYSVOL) already stamps
#: ``unauthenticated_reachable``/``reached_via`` on its own details at record
#: time (``scan.py``'s unauth-enrichment path). ``smb_share_secrets`` (any
#: other credential found in a readable share file, ``cli/creds.py``'s
#: CredSweeper path) does NOT — its details only carry ``unc_path``/
#: ``username``, so the link below must PROPAGATE both from the matched edge.
_UNAUTH_ENTRY_LINK_FINDING_KEYS: frozenset[str] = frozenset(
    {"gpp_passwords", "smb_share_secrets"}
)


def _node_is_tier0(node: Any) -> bool:
    """Return whether a graph node is a Tier-0 / high-value / domain target.

    Layers the structural kinds (the domain object itself, a writable DC or an
    RODC) on top of :func:`_node_tier_zero_flagged`, the module's single
    privilege-grade authority — so this read inherits the stamped
    membership-aware ``privilege_tier`` SSOT and never re-tiers.
    """
    if not isinstance(node, dict):
        return False
    if _node_tier_zero_flagged(node):
        return True
    if str(node.get("kind") or "") == "Domain":
        return True
    return classify_computer_node_role(node) in ("writable_dc", "rodc")


#: Forward-walk depth cap for the success-edge reachability from a credential
#: owner to a Tier-0 terminal. AD attack chains from a harvested credential to
#: the domain are short (svc_tgs → roast → DCSync → domain is 3 hops); a generous
#: cap keeps the walk bounded on a large/pathological graph without truncating a
#: real chain.
_TIER0_FORWARD_WALK_MAX_DEPTH = 64


def _forward_chain_edge_traversable(edge: dict[str, Any]) -> bool:
    """Return whether the forward chain-reachability walk may cross this edge.

    The walk proves "does the no-credential chain from the harvested credential
    owner actually reach Tier-0". Two edge kinds may be crossed:

    * A ``MEMBERSHIP`` edge (``MemberOf``) — structural directory TRUTH, not an
      executed action. Its status is ``discovered``, never ``success``, so a
      success-only gate would sever the chain at the first group hop (the owned
      principal → its group, through which the proven attack actually fires).
      Membership is a valid connector regardless of status.
    * Any OTHER edge (an attack/action edge) ONLY when ``status == "success"`` —
      the action must be PROVEN-executed. A merely-theoretical onward attack never
      elevates the finding (an Exposure-Validation overclaim otherwise).

    This keeps the honesty guarantee (every ACTION in the chain is proven) while
    modelling the chain exactly as the attack graph does: owned principal →
    (membership) → group → (proven attack) → Tier-0.
    """
    relation = str(edge.get("relation") or "")
    if classify_edge_kind(relation) is EdgeKind.MEMBERSHIP:
        return True
    return str(edge.get("status") or "").strip().lower() == "success"


def _proven_tier0_terminal_labels_from(
    start_node_id: str,
    edges: list[Any],
    nodes_map: dict[str, Any],
) -> list[str]:
    """Return Tier-0 terminals reachable FORWARD from *start_node_id* over the
    PROVEN chain (structural membership + executed attack edges).

    This is the CAUSAL scope for the no-credential severity uplift: it answers
    "does the chain that STARTS at this credential owner actually reach a Tier-0
    terminal", NOT "does the graph contain a Tier-0 compromise ANYWHERE". A global
    scan would falsely stamp the credential-leak finding CRITICAL whenever the
    domain is compromised by a COMPLETELY UNRELATED authenticated path — an
    Exposure-Validation overclaim (asserting a no-credential path to Domain Admin
    the graph does not show). Edge admission is :func:`_forward_chain_edge_traversable`
    (membership = structural connector; every other edge must be ``success``), so a
    merely-theoretical onward attack never elevates. A non-empty result lifts the
    finding to CRITICAL and its labels are stamped as the finding's Tier-0 context
    so the shared CVSS engine (the SSOT both the PDF report and the web CTEM read)
    elevates it identically; an empty result leaves the finding at its HIGH base
    (a real credential leak, not proven to reach Tier-0 from this entry).
    Cycle-safe (visited set) and depth-capped.
    """
    start = str(start_node_id or "").strip()
    if not start:
        return []

    # Forward adjacency over the PROVEN chain: from-node → [to-node, ...].
    chain_adjacency: dict[str, list[str]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if not _forward_chain_edge_traversable(edge):
            continue
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if from_id and to_id:
            chain_adjacency.setdefault(from_id, []).append(to_id)

    labels: list[str] = []
    visited: set[str] = {start}
    # BFS with an explicit depth so a pathological graph cannot run unbounded.
    frontier: list[str] = [start]
    depth = 0
    while frontier and depth < _TIER0_FORWARD_WALK_MAX_DEPTH:
        next_frontier: list[str] = []
        for current in frontier:
            for neighbor in chain_adjacency.get(current, ()):
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                next_frontier.append(neighbor)
                node = nodes_map.get(neighbor)
                if _node_is_tier0(node):
                    label = str(
                        (node or {}).get("label")
                        or (node or {}).get("name")
                        or neighbor
                        or ""
                    ).strip()
                    if label:
                        _append_unique(labels, label)
        frontier = next_frontier
        depth += 1
    return labels


def _affected_node_ids(finding: dict[str, Any]) -> set[str]:
    """Return the ``node_id`` link hooks carried on a finding's affected assets.

    The affected-assets stamper records each resolved principal/host with a
    ``node_id`` (the attack-graph node key). Retained as an ADDITIONAL fallback
    hook for the unauthenticated-entry linker; the authoritative match is by the
    shared artifact (see :func:`_link_unauthenticated_reach_findings`).
    """
    details = finding.get("details")
    if not isinstance(details, dict):
        return set()
    struct = details.get("_affected_assets_struct")
    if not isinstance(struct, list):
        return set()
    ids: set[str] = set()
    for entry in struct:
        if isinstance(entry, dict):
            node_id = str(entry.get("node_id") or "").strip()
            if node_id:
                ids.add(node_id)
    return ids


def _normalize_artifact_path(raw: Any) -> str:
    """Canonicalize a UNC/file artifact path for cross-reference matching.

    The GPP finding's ``details.unc_path`` and the proven-unauthenticated edge's
    ``notes.artifact`` are the SAME file, stamped from the same source value at
    record time — so they normally match byte-for-byte. This normalizer makes
    the match robust to the separator/case/whitespace drift that an FQDN-vs-IP
    host rewrite or a later re-stamp could introduce: it lowercases, collapses
    both separators to a single ``/``, and strips trailing separators, so
    ``\\\\HOST\\Replication\\...\\Groups.xml`` and
    ``//host/replication/.../groups.xml`` compare equal. Returns ``""`` for an
    empty/non-string value (never matches).
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    collapsed = text.replace("\\", "/").lower()
    while "//" in collapsed.lstrip("/"):
        # Collapse interior doubled separators but keep a single leading marker.
        head = "/" if collapsed.startswith("/") else ""
        collapsed = head + "/".join(part for part in collapsed.split("/") if part)
        break
    return collapsed.rstrip("/")


def _sam_account_name(raw: Any) -> str:
    """Extract a lowercase sAMAccountName from a principal reference.

    Accepts the forms the finding and the graph carry for the SAME owner:
    ``DOMAIN\\user`` / ``domain.local\\user`` (finding ``details.username``),
    ``user@domain.local`` (UPN), a bare ``user``, a node id ``name:user``, and a
    node label ``USER@DOMAIN``. Returns the bare account name, lowercased, so the
    owner-consistency reinforcement compares like for like. Returns ``""`` when
    no account name can be extracted.
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.lower().startswith("name:"):
        text = text[len("name:"):].strip()
    # DOMAIN\\user -> user
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1].strip()
    # user@domain / USER@DOMAIN -> user
    if "@" in text:
        text = text.split("@", 1)[0].strip()
    return text.lower()


def _finding_owner_sam(finding: dict[str, Any]) -> str:
    """Return the lowercase sAMAccountName of the GPP credential's owner.

    The owner is the account the leaked credential belongs to, recorded as
    ``details.username`` (e.g. ``active.htb\\SVC_TGS``). Used as the reinforcing
    confirmation for the artifact match so two distinct GPP credentials from
    different files for the same owner never cross-link.
    """
    details = finding.get("details")
    if not isinstance(details, dict):
        return ""
    return _sam_account_name(details.get("username"))


def _match_unauth_edge_for_finding(
    finding: dict[str, Any],
    unauth_edges_by_artifact: dict[str, list[dict[str, Any]]],
    unauth_edges_by_target: dict[str, list[dict[str, Any]]],
) -> dict[str, Any] | None:
    """Resolve the proven-unauthenticated edge a loose finding links to.

    PRIMARY: the shared artifact. The finding's ``details.unc_path`` is
    normalized and looked up against the by-artifact index; the owner
    (``details.username`` ↔ the edge ``to`` node's account name) is a reinforcing
    check so two GPP credentials from different files for the same owner never
    cross-link. The match requires the artifact AND (owner-consistent OR the
    finding carries no owner). When multiple edges share the artifact (e.g. the
    same file readable by Everyone and by Users), an owner-consistent edge wins;
    otherwise the first artifact edge is used (they all reference the same read).

    FALLBACK: the legacy ``_affected_assets_struct[].node_id`` → edge-target hook,
    kept for any finding whose struct still carries the owner's node id.
    """
    finding_artifact = ""
    details = finding.get("details")
    if isinstance(details, dict):
        finding_artifact = _normalize_artifact_path(details.get("unc_path"))

    if finding_artifact:
        artifact_edges = unauth_edges_by_artifact.get(finding_artifact)
        if artifact_edges:
            owner_sam = _finding_owner_sam(finding)
            if owner_sam:
                for edge in artifact_edges:
                    if _sam_account_name(edge.get("to")) == owner_sam:
                        return edge
                # Artifact matched but NO edge is owner-consistent: a different
                # GPP credential on the same file — do not cross-link.
                return None
            # Owner absent on the finding: the artifact identity is sufficient.
            return artifact_edges[0]

    # Fallback: the affected-assets struct node_id → edge target hook.
    for node_id in _affected_node_ids(finding):
        candidates = unauth_edges_by_target.get(node_id)
        if candidates:
            return candidates[0]

    return None


def _link_unauthenticated_reach_findings(
    graph: dict[str, Any],
    findings: list[Any],
    findings_by_key: dict[str, Any],
    catalog_by_key: dict[str, dict[str, Any]],
    *,
    now: str,
) -> bool:
    """Link a loose credential-leak finding to its proven-unauthenticated edge.

    The GPP credential-read edge is a ``relationship`` edge (no ``vuln_key``), so
    the exploitation-edge derivation never touches it. But the recovered
    credential is a real, graph-backed foothold whose severity is CONTEXTUAL: a
    read proven over a null/guest session onto a chain that reaches a Tier-0
    terminal is a no-credential path to full domain compromise — the
    highest-severity case — while the same read not proven to reach Tier-0 is a
    HIGH-grade credential leak.

    The link is resolved by the SHARED ARTIFACT — the finding's
    ``details.unc_path`` (the leaked ``\\host\\...\\Groups.xml``) matched against a
    proven-unauthenticated edge's ``notes.artifact`` (the identical file),
    normalized on both sides (:func:`_normalize_artifact_path`). This is the
    FUNDAMENTAL fact ("the same file was the finding AND the proven read"), stamped
    at record time on both sides (the emitter stamps ``unc_path`` at
    ``scan.py``; the provenance service stamps ``notes.artifact`` on the edge),
    so the match resolves at CI time — it does NOT depend on the deliver-time
    ``_affected_assets_struct``, which carries the READ-SET group node ids (the
    edge FROMs) rather than the credential owner (the edge TO) and so would never
    match the edge target. The owner (``details.username`` ↔ the edge ``to`` node)
    is a REINFORCING confirmation: the match requires the artifact AND either an
    owner-consistent edge or an owner-absent finding, so two distinct GPP
    credentials from different files for the same owner never cross-link. The
    ``_affected_assets_struct[].node_id`` → edge-target path is kept only as an
    additional fallback; the artifact match is authoritative.

    On a match the finding inherits ``from_attack_graph=True``, the catalog
    knowledge block, and a severity derived from the edge-severity SSOT
    (``compute_edge_severity``) — never a static per-finding constant and never
    independently of the materialized edge. Idempotent.

    Returns:
        True when the report was modified.
    """
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    if not edges:
        return False

    # Index proven-unauthenticated edges by (a) their normalized artifact path
    # (the authoritative link key — the same file was the finding AND the read)
    # and (b) their target node id (the fallback struct-node_id hook). Two edges
    # can share ONE artifact (the same Groups.xml readable by Everyone AND Users),
    # so each index bucket is a list.
    unauth_edges_by_artifact: dict[str, list[dict[str, Any]]] = {}
    unauth_edges_by_target: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        notes = edge.get("notes")
        if not isinstance(notes, dict) or not notes.get("unauthenticated_reachable"):
            continue
        artifact_key = _normalize_artifact_path(notes.get("artifact"))
        if artifact_key:
            unauth_edges_by_artifact.setdefault(artifact_key, []).append(edge)
        target = str(edge.get("to") or "").strip()
        if target:
            unauth_edges_by_target.setdefault(target, []).append(edge)
    if not unauth_edges_by_artifact and not unauth_edges_by_target:
        return False

    updated = False
    for key in _UNAUTH_ENTRY_LINK_FINDING_KEYS:
        finding = findings_by_key.get(key)
        if not isinstance(finding, dict):
            continue

        matched_edge = _match_unauth_edge_for_finding(
            finding,
            unauth_edges_by_artifact,
            unauth_edges_by_target,
        )
        if matched_edge is None:
            continue

        # Scope the Tier-0 signal to THIS chain: the Tier-0 terminals reachable
        # FORWARD over executed edges from the matched edge's own target (the
        # harvested credential owner), NOT any Tier-0 compromise elsewhere in the
        # graph. A global scan would falsely elevate the finding whenever the
        # domain is compromised by an UNRELATED authenticated path — an
        # Exposure-Validation overclaim the forward walk prevents.
        chain_start = str(matched_edge.get("to") or "").strip()
        tier0_terminals = _proven_tier0_terminal_labels_from(
            chain_start, edges, nodes_map
        )
        reaches_tier0 = bool(tier0_terminals)

        # Derive the finding's severity from the materialized edge via the
        # edge-severity SSOT. Source = Unauthenticated Principal (the proven
        # no-credential position). The entry edge's OWN target is the harvested
        # account (not Tier-0), so the Tier-0 signal flows through the dedicated
        # ``proven_unauth_reaches_tier0`` field (the forward-chain reachability),
        # NOT by repurposing the node-kind ``target_is_domain`` booleans. The edge
        # severity can only UPLIFT the finding's catalog base — a proven GPP
        # credential leak is already HIGH on its own — so the result is
        # max(base, edge-derived): HIGH when the chain does not reach Tier-0,
        # CRITICAL when it does.
        relation = str(matched_edge.get("relation") or "")
        edge_severity = compute_edge_severity(
            EdgeSeverityInput(
                source_compromise_class=CompromiseClass.UNAUTHENTICATED_PRINCIPAL,
                target_compromise_class=None,
                edge_kind=classify_edge_kind(relation),
                proven_unauthenticated_reachable=True,
                proven_unauth_reaches_tier0=reaches_tier0,
            )
        )
        catalog = catalog_by_key.get(key, {})
        catalog_base = str(catalog.get("severity") or "medium")
        severity_label = _uplift_finding_severity(catalog_base, edge_severity)

        if finding.get("from_attack_graph") is not True:
            finding["from_attack_graph"] = True
            updated = True
        if finding.get("severity") != severity_label:
            finding["severity"] = severity_label
            updated = True
        if "discovered_at" not in finding:
            finding["discovered_at"] = finding.get("first_seen") or now
            updated = True

        # Attach the catalog knowledge block so the honest SSOT copy (the native
        # remediation, the MITRE mapping) reaches the report and the web CTEM.
        catalog_knowledge = catalog.get("knowledge")
        existing_knowledge = finding.get("knowledge")
        if (
            (not isinstance(existing_knowledge, dict) or not existing_knowledge)
            and isinstance(catalog_knowledge, dict)
            and catalog_knowledge
        ):
            finding["knowledge"] = catalog_knowledge
            updated = True

        # Record the linking edge + the unauthenticated-reach marker onto the
        # finding's details, so the render surfaces (and the shared CVSS context
        # extractor) see the materialized edge behind the severity.
        details = finding.get("details")
        if not isinstance(details, dict):
            details = {}
            finding["details"] = details
        existing_edges = details.get("attack_graph_edges")
        if not isinstance(existing_edges, list):
            existing_edges = []
        edge_entry = {
            "relation": relation,
            "source": str(matched_edge.get("source") or matched_edge.get("from") or ""),
            "target": str(matched_edge.get("target") or matched_edge.get("to") or ""),
        }
        note_summary = _summarize_attack_graph_edge_notes(matched_edge.get("notes"))
        if note_summary:
            edge_entry["notes"] = note_summary
        _append_unique(existing_edges, edge_entry)
        details["attack_graph_edges"] = existing_edges
        if details.get("unauthenticated_reachable") is not True:
            details["unauthenticated_reachable"] = True
            updated = True

        # Carry the HOW-was-this-reached vector forward from the matched edge.
        # ``gpp_passwords`` already stamps it at record time (the unauth-
        # enrichment emitter knows the mechanism directly); other linked keys
        # (``smb_share_secrets``) do not — their emitter never observes the
        # null/guest bind that actually produced the read. The matched edge is
        # the SSOT for the mechanism either way (it is what
        # ``unauthenticated_reachable`` above is derived from), so a matched
        # finding always inherits the edge's ``reached_via`` when its own
        # details do not already carry one, keeping the reached_via-aware
        # narrative and affected-assets renderers fed regardless of which
        # emitter produced the finding.
        if "reached_via" not in details:
            edge_reached_via = reached_via_from_notes(matched_edge.get("notes"))
            if edge_reached_via:
                details["reached_via"] = edge_reached_via
                updated = True

        # Stamp the Tier-0 / exploitation context keys the shared CVSS engine
        # reads (``extract_context_from_details``), so the CONTEXTUAL severity
        # the PDF report AND the web CTEM both render from that ONE SSOT matches
        # the ``severity`` field set above — the proven no-credential chain into
        # a Tier-0 terminal elevates ``gpp_passwords`` to its CRITICAL rule.
        # A success read always confirms exploitation; the Tier-0 terminals are
        # stamped only when the chain was proven to reach them.
        if details.get("exploitation_confirmed") is not True:
            details["exploitation_confirmed"] = True
            updated = True
        if tier0_terminals:
            if details.get("tier_zero_accounts") != tier0_terminals:
                details["tier_zero_accounts"] = list(tier0_terminals)
                updated = True
        finding["last_seen"] = now

    return updated


#: The catalog ``vuln_key`` a proven, credential-less anonymous LDAP bind lands
#: under. The ``LDAPAnonymousBind`` graph relation is an ENTRY vector, not an
#: exploitation edge (it owns no ``vuln_key``), so :func:`_group_reportable_edges_by_key`
#: never turns it into a finding — yet a proven anonymous bind accepted on a DC is a
#: first-class finding a client must see and remediate. Mirrors the same-named entry
#: in ``pro/reporting/vuln_catalog.py`` (and the ``ldap_anonymous`` slice of
#: ``VULN_CATALOG_META`` in LITE).
_ANONYMOUS_LDAP_BIND_VULN_KEY = "ldap_anonymous"


def _proven_anonymous_ldap_bind_edge(edges: list[Any]) -> dict[str, Any] | None:
    """Return the proven credential-less anonymous LDAP bind edge, or ``None``.

    The unauthenticated probe records a successful anonymous LDAP bind as an
    ``LDAPAnonymousBind`` entry-vector edge (``kind="auth"``, notes
    ``authentication="anonymous_bind"``). It carries no ``vuln_key``, so the
    exploitation-edge derivation never materializes it — this locates it so the
    anonymous-bind finding can be synthesized directly from the proof. Returns the
    first such edge whose status is ``success`` (an unproven / attempted bind is
    never rendered as a confirmed finding).
    """
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or "").strip().lower()
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        is_anon = relation == "ldapanonymousbind" or (
            str(notes.get("authentication") or "").strip().lower() == "anonymous_bind"
        )
        if not is_anon:
            continue
        if str(edge.get("status") or "").strip().lower() == "success":
            return edge
    return None


def _stamp_anonymous_bind_dc_context(
    finding: dict[str, Any], edge: dict[str, Any], *, now: str
) -> bool:
    """Stamp the DC-target context a proven anonymous bind carries onto the finding.

    A successful anonymous LDAP bind is, by construction, accepted BY a domain
    controller (the LDAP server it bound to). Recording the DC among the finding's
    ``details`` lets the shared contextual-CVSS overlay (``ldap_anonymous`` ->
    ``CONDITION_DC_TARGETS``) elevate the finding's ADscan Priority so it lands in
    the immediate remediation window, matching the executive summary's "close first"
    ranking. Honest: the DC is the host that accepted the credential-less bind, not
    a claim of domain compromise. Idempotent — only writes when the value changes.
    """
    notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
    dc = str(notes.get("pdc") or notes.get("dc") or notes.get("dc_ip") or "").strip()
    details = finding.get("details")
    if not isinstance(details, dict):
        details = {}
    changed = False
    if dc and details.get("dc_hosts") != [dc]:
        details["dc_hosts"] = [dc]
        changed = True
    finding["details"] = details
    if changed:
        finding["last_seen"] = now
    return changed


def _materialize_anonymous_ldap_bind_finding(
    anon_edge: dict[str, Any] | None,
    findings: list[Any],
    findings_by_key: dict[str, Any],
    catalog_by_key: dict[str, dict[str, Any]],
    *,
    now: str,
) -> bool:
    """Synthesize the ``ldap_anonymous`` finding from a proven anonymous-bind edge.

    The anonymous-bind entry vector owns no ``vuln_key``, so the exploitation-edge
    derivation skips it. This materializes the finding directly from the proof
    (mirroring the ``gpp_passwords`` unauthenticated-link path in
    :func:`_link_unauthenticated_reach_findings`) so a proven, credential-less
    directory read reaches the Technical Findings and the remediation roadmap
    instead of surfacing only as a blast-radius row. Idempotent: an existing
    finding is left in place and only its DC context is backfilled.

    Args:
        anon_edge: The proven ``LDAPAnonymousBind`` edge, or ``None`` when the graph
            carries no successful anonymous bind (then this is a no-op).
        findings: The domain's mutable findings list.
        findings_by_key: The ``vuln_key`` -> finding index (kept in sync).
        catalog_by_key: The resolved finding catalog.
        now: The ISO timestamp to stamp on a freshly materialized finding.

    Returns:
        ``True`` when a finding was created or updated.
    """
    if anon_edge is None:
        return False
    existing = findings_by_key.get(_ANONYMOUS_LDAP_BIND_VULN_KEY)
    if isinstance(existing, dict):
        return _stamp_anonymous_bind_dc_context(existing, anon_edge, now=now)

    catalog = catalog_by_key.get(_ANONYMOUS_LDAP_BIND_VULN_KEY, {})
    catalog_knowledge = catalog.get("knowledge")
    finding: dict[str, Any] = {
        "id": uuid.uuid4().hex,
        "key": _ANONYMOUS_LDAP_BIND_VULN_KEY,
        "title": catalog.get("title", "LDAP Anonymous Bind Enabled"),
        "severity": catalog.get("severity", "medium"),
        "category": catalog.get("category", "LDAP"),
        "status": "confirmed",
        "from_attack_graph": True,
        "details": {},
        "evidence": [],
        "discovered_at": now,
        "first_seen": now,
        "last_seen": now,
    }
    if isinstance(catalog_knowledge, dict) and catalog_knowledge:
        finding["knowledge"] = catalog_knowledge
    _stamp_anonymous_bind_dc_context(finding, anon_edge, now=now)
    findings.append(finding)
    findings_by_key[_ANONYMOUS_LDAP_BIND_VULN_KEY] = finding
    return True


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

    # ── NODE-driven reconciliations, above the no-edges early return ───────────
    # Both of these read the graph's NODES, not its edges, so an edgeless graph
    # must not skip them. (The sync-account emit's own comment always claimed it
    # ran before the early return; it did not, so a domain whose only relevant
    # observation carried no edge silently lost its Tier-0 hardening item.)

    # Reframe a legitimate control-plane (Azure AD Connect) sync account's by-design
    # DCSync — suppressed as a finding by the tier-jump gate — into
    # a Tier-0 asset-hardening item, so the report is never silent about a Tier-0
    # asset (the third-state doctrine).
    _emit_control_plane_sync_account_items(shell, domain, graph)

    # Segment the raw shadow-credential finding by population shape, now that the
    # stamped privilege tier exists. Runs AFTER the sync-account emit above,
    # because an observed Azure AD Connect account is the hybrid corroboration the
    # segmentation reads. A Hello rollout produces NO graph edge at all (the
    # analyzer deliberately emits none), so this one in particular would never
    # fire below the early return.
    _reconcile_shadow_credential_segmentation(shell, domain, graph)

    if not edges:
        return False

    # Session trust SSOT, consulted by the Tier-0-source gate only to prove a
    # cross-domain endpoint pair is same-forest. Absent (a standalone render off a
    # bare shell) → the gate fails open, which still kills the common same-domain
    # false-positive class and keeps every cross-forest finding.
    domains_data = getattr(shell, "domains_data", {}) or {}

    def _label(node_id: str) -> str:
        node = nodes_map.get(node_id)
        if isinstance(node, dict):
            return str(node.get("label") or node.get("name") or node_id)
        return node_id

    # Keep the raw exploitation edges per vuln_key so we can derive Tier-0 / DC /
    # exploitation context from their target nodes (the labelled `entry` below
    # loses the node reference needed for that classification), and so the KEY
    # gate can read every contributing edge's status at once.
    raw_edges_by_key, gated_keys = _group_reportable_edges_by_key(
        edges, nodes_map, domains_data
    )

    edges_by_key: dict[str, list[dict[str, Any]]] = {}
    for vuln_key, key_edges in raw_edges_by_key.items():
        entries: list[dict[str, Any]] = []
        for edge in key_edges:
            # Status is now carried by the shared ``_edge_report_entry`` helper
            # (so the suppressed-edge builder stays byte-identical for the prune).
            _append_unique(entries, _edge_report_entry(edge, _label))
        edges_by_key[vuln_key] = entries

    # Tier-0-source exploitation edges the grouping gate drops (held by design,
    # e.g. Exchange Windows Permissions administering its own estate). The merge
    # into ``details.attack_graph_edges`` below is additive, so a MIXED finding
    # that survives on its non-Tier-0 edges would keep these stale rows and the
    # affected-assets surface would render them — this is the set pruned at stamp
    # time so only the NON-suppressed edges populate the finding.
    suppressed_edges_by_key = _suppressed_tier0_edge_entries_by_key(
        edges, nodes_map, _label, domains_data
    )

    # A loose credential-leak finding (the canonical gpp_passwords) links to a proven
    # unauthenticated relationship edge, not a reportable exploitation edge, so
    # the presence of such an edge must keep this sync running even when there is
    # no exploitation-edge work to do.
    has_unauth_link_edge = any(
        isinstance(edge, dict)
        and isinstance(edge.get("notes"), dict)
        and edge["notes"].get("unauthenticated_reachable")
        for edge in edges
    )
    # A proven anonymous LDAP bind is an ENTRY vector (no vuln_key), so it never
    # reaches ``edges_by_key`` — resolve it once here so its finding is synthesized
    # even in a domain whose only exposure is the credential-less directory read.
    anon_bind_edge = _proven_anonymous_ldap_bind_edge(edges)
    if (
        not edges_by_key
        and not gated_keys
        and not has_unauth_link_edge
        and anon_bind_edge is None
    ):
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
        # Prune any Tier-0-source edge the grouping gate suppressed — both a stale
        # one the additive merge carried from a pre-gate workspace and one that
        # would otherwise slip in — so the finding's affected-assets surface shows
        # only the non-suppressed (non-Tier-0-source, cross-forest, or
        # broad-identity-source) edges, matching the gated finding set.
        suppressed_entries = suppressed_edges_by_key.get(vuln_key)
        if suppressed_entries:
            suppressed_identities = {
                identity
                for entry in suppressed_entries
                if (identity := _edge_entry_identity(entry)) is not None
            }
            pruned_edges = [
                entry
                for entry in existing_edges
                if _edge_entry_identity(entry) not in suppressed_identities
            ]
            if len(pruned_edges) != len(existing_edges):
                updated = True
            existing_edges = pruned_edges
        # Snapshot (after the prune) so a change to the edge entries (e.g. a
        # newly-stamped per-edge ``status`` the roasting crack-status reads) flips
        # ``updated`` and is persisted — the context stamp below only reacts to the
        # SUMMARY statuses, not to the per-entry status carried on each edge.
        edges_before = [dict(e) for e in existing_edges if isinstance(e, dict)]
        # Merge deduped by (relation, source, target) identity, not full-dict
        # equality: a persisted entry (no per-edge ``status``) and a freshly built
        # one (with ``status``) describe the SAME edge and must collapse to one, or
        # the finding renders a duplicate affected-asset row.
        existing_edges = _merge_edge_entries_by_identity(existing_edges, edge_entries)
        details["attack_graph_edges"] = existing_edges
        if existing_edges != edges_before:
            updated = True

        # Stamp the Tier-0 / DC / exploitation context keys the shared CVSS
        # calculator reads so contextual elevation (ADscan Priority) fires for
        # attack-graph materialized findings in both the PDF and the web.
        previous_context = {
            "tier_zero_accounts": details.get("tier_zero_accounts"),
            "dc_hosts": details.get("dc_hosts"),
            "exploitation_confirmed": details.get("exploitation_confirmed"),
            "attack_graph_edge_statuses": details.get("attack_graph_edge_statuses"),
            "attack_graph_non_execution": details.get("attack_graph_non_execution"),
            "confirmation_pending": details.get("confirmation_pending"),
            "confirmation_resolved": details.get("confirmation_resolved"),
        }
        _stamp_attack_graph_context_into_details(
            details,
            nodes_map,
            raw_edges_by_key.get(vuln_key, []),
        )
        if vuln_key == _CONSTRAINED_DELEGATION_VULN_KEY:
            # Grade protocol-transition delegations above Kerberos-only ones
            # (severity modulation, not a gate change — both already survived
            # the upward-tier gate). Runs after the catalog-base severity is set.
            if _grade_constrained_delegation_severity(
                finding, raw_edges_by_key.get(vuln_key, [])
            ):
                updated = True
        _stamp_exposure_provenance_into_details(
            details,
            raw_edges_by_key.get(vuln_key, []),
        )
        if vuln_key == _ESC15_VULN_KEY:
            # Lift the ESC15 collection-time confirmation verdict (stamped on the
            # derived edge notes by the confirmation phase) to a top-level finding
            # detail, so the compliance annex grades a confirmed-vulnerable ESC15
            # as a hard non-conformity and routes an unconfirmed one to pending
            # client evidence (see finding_confidence.CONFIRMATION_PENDING_*).
            _stamp_esc15_confirmation_into_details(
                details,
                raw_edges_by_key.get(vuln_key, []),
            )
        if vuln_key == _ESC14_VULN_KEY:
            # Same confirmation lift for ESC14, keyed on the esc14_confirmed marker
            # the ESC14 confirmation phase stamps when a DC accepts weak explicit
            # certificate mappings (StrongCertificateBindingEnforcement < Full).
            _stamp_adcs_confirmation_into_details(
                details,
                raw_edges_by_key.get(vuln_key, []),
                confirmed_note_key="esc14_confirmed",
            )
            # One finding, all avenues: lift the full confirmed-variant set and the
            # executed variant so the report / web CTEM render every open avenue and
            # the single root remediation, not one finding per variant.
            _stamp_esc14_variant_summary_into_details(
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

    # Synthesize the anonymous-bind finding from the proven entry-vector edge
    # (owns no vuln_key, so the exploitation-edge derivation above skipped it).
    if _materialize_anonymous_ldap_bind_finding(
        anon_bind_edge, findings, findings_by_key, catalog_by_key, now=now
    ):
        updated = True

    # Link loose credential-leak findings to their proven-unauthenticated entry
    # edge (node-id hook, not vuln_key) and derive their contextual severity from
    # the edge-severity SSOT.
    if _link_unauthenticated_reach_findings(
        graph, findings, findings_by_key, catalog_by_key, now=now
    ):
        updated = True

    if updated:
        _save_technical_report(shell, report)
    return updated


def validate_attack_graph_findings_correlation(
    attack_graph: dict[str, Any],
    technical_report: dict[str, Any],
    *,
    domain: str | None = None,
    trust_domains_data: Any = None,
) -> list[str]:
    """Validate that exploitation edges and recorded findings agree.

    ``trust_domains_data`` is the session trust SSOT (``shell.domains_data``),
    threaded to the SAME :func:`_group_reportable_edges_by_key` /
    :func:`_tier_gated_edge_suppressed` gate the derivation uses so the guard and
    the derivation can never disagree about a tier-jump suppression. ``None``
    fails open exactly as the derivation does.

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
        # A tier-gated edge the tier-jump gate suppresses is deliberately NOT
        # materialized as a finding (see _tier_gated_edge_suppressed) — reporting
        # it as a correlation gap would make the reconciliation warn on every run
        # of a perfectly healthy workspace. The guard applies the SAME flag-aware
        # gate as the derivation, so the two can never disagree.
        if _tier_gated_edge_suppressed(edge, nodes_map, trust_domains_data):
            continue
        if not str(edge.get("vuln_key") or "").strip():
            errors.append(f"Exploitation edge {relation} missing vuln_key")

    reportable, gated = _group_reportable_edges_by_key(
        edges, nodes_map, trust_domains_data
    )
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
        trust_domains_data=getattr(shell, "domains_data", {}) or {},
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

        shell = SimpleNamespace(current_workspace_dir=str(workspace_dir))
        if technical_report_path:
            # ``_get_technical_report_path`` returns an absolute value as-is, so
            # this pins the reconciliation to exactly the file being rendered.
            shell.technical_report_file = str(
                os.path.abspath(str(technical_report_path))
            )

        # Cross-domain reconciliation of the external-tenant replication finding.
        # It reads ONLY the technical report (the persisted Tier-0 hardening
        # control evidence), so it runs above the per-domain graph loop and
        # independently of whether an attack graph is on disk. Its verdict needs
        # every assessed domain at once, which is why it cannot be settled by the
        # per-domain emit during the scan.
        _reconcile_external_tenant_replication(shell)

        if not names:
            return residual
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
                trust_domains_data=getattr(shell, "domains_data", {}) or {},
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
