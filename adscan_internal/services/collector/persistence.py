"""Persistence bridge from CollectionResult to ADscan artifacts."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug, print_warning
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.inventory_persistence import (
    CollectorInventoryPersistence,
)
from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    ForeignNodeRef,
    HttpSpnFinding,
)
from adscan_internal.services.credential_store_service import hosts_match
from adscan_internal.services.privileged_group_classifier import (
    classify_privileged_membership,
    resolve_privileged_followup_decision,
    sid_rid,
)
from adscan_internal.workspaces import domain_subpath, write_json_file
from adscan_core.rich_output import print_exception

_ADCS_OBJECT_KINDS: frozenset[str] = frozenset(
    {
        "CertTemplate",
        "EnterpriseCA",
        "RootCA",
        "AIACA",
        "NTAuthStore",
    }
)
_ADCS_RAW_ACL_RELATIONS: frozenset[str] = frozenset(
    {
        "AllExtendedRights",
        "AutoEnroll",
        "Enroll",
        "GenericAll",
        "GenericWrite",
        "WriteDACL",
        "WriteOwner",
    }
)
_CONTAINER_SCOPE_RELATIONS: frozenset[str] = frozenset(
    {
        "ReadLAPSPassword",
        "SyncLAPSPassword",
    }
)
_CONTAINER_SCOPE_KINDS: frozenset[str] = frozenset({"OU", "Container"})

# ESC relations whose target is Domain Admins after impersonation.
_ESC_TO_DOMAIN_ADMINS: frozenset[str] = frozenset(
    {
        "ADCSESC1",
        "ADCSESC2",
        "ADCSESC3",
        "ADCSESC4",
        "ADCSESC5",
        "ADCSESC6",
        "ADCSESC7",
        "ADCSESC9",
        "ADCSESC10",
        "ADCSESC15",
    }
)
# ESC relations whose target is Domain Controllers after NTLM relay.
_ESC_TO_DOMAIN_CONTROLLERS: frozenset[str] = frozenset({"ADCSESC8", "ADCSESC11"})

# All ESC relations the collector re-emits as compromise-centric edges.
# ADCSESC13 is intentionally excluded until issuance-policy OID resolution lands —
# its target group is per-template and not yet derivable from raw edge notes.
_ESC_DERIVED_RELATIONS: frozenset[str] = (
    _ESC_TO_DOMAIN_ADMINS | _ESC_TO_DOMAIN_CONTROLLERS
)

# Replication-rights extended rights that are evidence-only when targeting the
# Domain object. ``_persist_dcsync_steps`` derives a single canonical
# ``DCSync`` edge from the (GetChanges + GetChangesAll) pair (or from
# ``AllExtendedRights``); persisting the raw component edges as separate
# attack-path steps just produces 3 visually-identical paths through the same
# principal (e.g. Administrators -GetChanges-> Domain, -GetChangesAll-> Domain,
# -GetChangesInFilteredSet-> Domain). One DCSync edge is the kill chain; the
# raws are noise.
_REPLICATION_RIGHT_RELATIONS: frozenset[str] = frozenset(
    {
        "GetChanges",
        "GetChangesAll",
        "GetChangesInFilteredSet",
    }
)

_DOMAIN_ADMINS_RID = 512
_DOMAIN_CONTROLLERS_RID = 516

# Well-known Authenticated Users SID — the broadest actor for Kerberoasting /
# AS-REP Roasting (only *being authenticated* is required, which is cross-forest
# capable). Sourcing those derived edges here (not from the domain-local Domain
# Users group) is what surfaces the cross-forest roasting paths.
_AUTHENTICATED_USERS_SID = "S-1-5-11"

# Canonical display names for synthesized well-known groups (used only when the
# real node is absent from the collection result). Keyed by domain-relative RID.
_WELL_KNOWN_GROUP_LABELS: dict[int, str] = {
    _DOMAIN_ADMINS_RID: "DOMAIN ADMINS",
    _DOMAIN_CONTROLLERS_RID: "DOMAIN CONTROLLERS",
}

# Key Admins (RID 526) and Enterprise Key Admins (RID 527) are only exploitable
# via shadow credentials + PKINIT, which requires an EnterpriseCA. ACL edges
# targeting these groups are noise when no ADCS is present.
_KEY_ADMINS_RIDS: frozenset[int] = frozenset({526, 527})

# Relations that give a writer control over a puppet user's identity attributes.
# Used by the ESC9/ESC10 precondition check to find (writer, puppet) pairs.
# Do not expand beyond the listed set — over-inclusion creates false positives.
_ESC9_USER_WRITE_RELATIONS: frozenset[str] = frozenset(
    {
        "GenericAll",
        "GenericWrite",
        "WriteOwner",
        "WriteDacl",
        "AllExtendedRights",
        "AddKeyCredentialLink",
        "WriteProperty",
    }
)

# ESC9/10/14 require a second precondition beyond enrollment rights: the
# attacker must hold user-write control over a puppet account.
#   ESC9:  write UPN + msDS-KeyCredentialLink on puppet → shadow creds + UPN swap
#   ESC10: write UPN on puppet → weak KDC cert binding
#   ESC14: write altSecurityIdentities on puppet → map attacker cert to puppet
# All three share the same writer-mediated detection logic.
_ESC_WRITER_MEDIATED: frozenset[str] = frozenset({"ADCSESC9", "ADCSESC10", "ADCSESC14"})

# Maximum BFS depth for group-membership expansion when checking whether a
# puppet user transitively satisfies the enroll-set of an ESC9/10/14 template.
_ESC9_BFS_MAX_DEPTH = 8


def _build_classified_node_payloads(result: CollectionResult) -> list[dict[str, Any]]:
    """Return graph node payloads with effective privileged-membership annotations."""
    payloads = {
        sid.upper(): node.to_graph_payload() for sid, node in result.nodes.items()
    }
    inherited = _resolve_inherited_privileged_memberships(result)

    for sid, record in inherited.items():
        payload = payloads.get(sid)
        if not payload:
            continue
        props = payload.setdefault("properties", {})
        if not isinstance(props, dict):
            props = {}
            payload["properties"] = props

        memberships = tuple(
            str(item) for item in record.get("memberships", ()) if str(item).strip()
        )
        terminal_class = str(record.get("terminal_class") or "direct_compromise")
        matched_keys = tuple(
            str(item) for item in record.get("matched_keys", ()) if str(item).strip()
        )

        payload["isTierZero"] = True
        payload["highvalue"] = True
        payload["system_tags"] = _merge_system_tags(
            payload.get("system_tags"), "admin_tier_0"
        )
        payload["tier0_inherited"] = True
        payload["tier0_memberships"] = list(memberships)
        payload["target_terminal_class"] = terminal_class

        props["isTierZero"] = True
        props["highvalue"] = True
        props["system_tags"] = _merge_system_tags(
            props.get("system_tags"), "admin_tier_0"
        )
        props["tier0_inherited"] = True
        props["tier0_memberships"] = list(memberships)
        props["tier0_membership_keys"] = list(matched_keys)
        props["target_terminal_class"] = terminal_class

    return list(payloads.values())


def _merge_system_tags(existing: object, *tags: str) -> str:
    """Return a stable comma-separated system_tags string."""
    values: list[str] = []
    if isinstance(existing, str):
        values.extend(part.strip() for part in existing.replace(" ", ",").split(","))
    elif isinstance(existing, list):
        values.extend(str(part).strip() for part in existing)
    values.extend(tag.strip() for tag in tags)
    deduped = sorted({value for value in values if value})
    return ",".join(deduped)


def _resolve_inherited_privileged_memberships(
    result: CollectionResult,
) -> dict[str, dict[str, Any]]:
    """Classify User/Computer nodes by recursive membership in privileged groups."""
    group_parents: dict[str, set[str]] = {}
    principal_groups: dict[str, set[str]] = {}
    for edge in result.edges:
        if edge.relation != "MemberOf":
            continue
        source_sid = edge.source_object_id.upper()
        target_sid = edge.target_object_id.upper()
        source_node = result.nodes.get(source_sid)
        target_node = result.nodes.get(target_sid)
        if not source_node or not target_node or target_node.kind != "Group":
            continue
        if source_node.kind == "Group":
            group_parents.setdefault(source_sid, set()).add(target_sid)
        elif source_node.kind in {"User", "Computer"}:
            principal_groups.setdefault(source_sid, set()).add(target_sid)

    def _expand_groups(group_sids: set[str]) -> set[str]:
        expanded: set[str] = set()
        pending = list(group_sids)
        while pending:
            group_sid = pending.pop()
            if group_sid in expanded:
                continue
            expanded.add(group_sid)
            pending.extend(sorted(group_parents.get(group_sid, set()) - expanded))
        return expanded

    inherited: dict[str, dict[str, Any]] = {}
    for principal_sid, direct_group_sids in principal_groups.items():
        principal_node = result.nodes.get(principal_sid)
        if not principal_node or principal_node.kind not in {"User", "Computer"}:
            continue
        group_sids = _expand_groups(direct_group_sids)
        group_nodes = [
            result.nodes[group_sid]
            for group_sid in sorted(group_sids)
            if group_sid in result.nodes
        ]
        membership = classify_privileged_membership(
            group_sids=[node.object_id for node in group_nodes],
            group_names=[node.name for node in group_nodes],
            group_distinguished_names=[node.distinguished_name for node in group_nodes],
        )
        decision = resolve_privileged_followup_decision(membership)
        if not decision.matched_keys:
            continue
        terminal_class = _terminal_class_from_privileged_decision(decision)
        inherited[principal_sid] = {
            "memberships": tuple(node.name for node in group_nodes),
            "matched_keys": decision.matched_keys,
            "terminal_class": terminal_class,
        }
    return inherited


def _terminal_class_from_privileged_decision(decision: object) -> str:
    """Map a privileged follow-up decision to attack-graph terminal semantics."""
    direct_keys = set(getattr(decision, "direct_action_keys", ()) or ())
    enrichment_keys = set(getattr(decision, "enrichment_keys", ()) or ())
    future_keys = set(getattr(decision, "future_followup_keys", ()) or ())
    dependency_keys = set(getattr(decision, "dependency_only_keys", ()) or ())
    actionable_keys = set(getattr(decision, "actionable_keys", ()) or ())

    if direct_keys:
        return "direct_compromise"
    if {"backup_operators", "dns_admins"} & actionable_keys:
        return "followup_terminal"
    if enrichment_keys:
        return "graph_extension"
    if future_keys:
        return "future_followup"
    if dependency_keys:
        return "dependency_only"
    return "direct_compromise"


def _register_collected_hostnames_for_telemetry(result: CollectionResult) -> None:
    """Register every collected computer name with the telemetry sanitizer.

    The workspace loader seeds the sanitizer's hostname set from
    ``enabled_computers.txt`` at workspace-ACTIVATION time. On a fresh
    ``adscan ci`` that file does not exist yet -- activation happens before
    collection -- so the set is seeded EMPTY and nothing re-seeds it once
    collection discovers the estate. An FQDN and an IP still get scrubbed by
    their structural nets, but a single-label NetBIOS name has no structural
    signature to anchor on, so the customer's DC short name travelled to the
    uploaded recording in cleartext beside its own pseudonymized FQDN.

    This is the right seam because every collection path converges here: both
    the writer of ``enabled_computers.txt`` (``_process_computers_list``) and
    the Phase-2 port scan, which writes that file directly, run downstream of
    it. Registering the FQDN alone would not be enough either -- the sanitizer
    derives the short label from a known domain suffix, and a computer whose
    DNS name sits outside the collected domains has no suffix to strip -- so the
    ``sAMAccountName`` is registered as well, stripped of its trailing ``$``.

    Sanitization runs at EXPORT time over the whole buffer, so registering here
    also masks every occurrence recorded BEFORE collection reached this point.

    Best-effort by construction: telemetry hygiene must never be able to abort
    a collection run.

    Args:
        result: The collection result whose Computer nodes should be registered.
    """
    try:
        names: list[str] = []
        for node in result.nodes.values():
            if getattr(node, "kind", "") != "Computer":
                continue
            fqdn = str(getattr(node, "name", "") or "").strip()
            if fqdn:
                names.append(fqdn)
            sam = str(getattr(node, "samaccountname", "") or "").strip()
            short = sam.rstrip("$")
            if short:
                names.append(short)
            dns_name = str(
                (getattr(node, "properties", None) or {}).get("dnshostname") or ""
            ).strip()
            if dns_name:
                names.append(dns_name)
        if names:
            telemetry.add_known_hostname(*names)
    except Exception as exc:  # noqa: BLE001 - never break collection for telemetry
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _ensure_foreign_endpoint_node(
    graph: dict[str, Any],
    target_sid: str,
    foreign_sid_to_label: dict[str, ForeignNodeRef],
) -> str | None:
    """Resolve a foreign target SID to a graph id, creating a light endpoint node.

    When an edge's target SID belongs to another collected domain, the current
    graph has no node for it, so the edge would be dropped. If the cross-domain
    registry knows the SID, we create (idempotently) a light node in THIS graph
    keyed by the foreign node's canonical graph id — the SAME id the foreign
    domain's own graph uses — so the query-time merge collapses the two onto one
    node and the DFS crosses the domain boundary.

    Args:
        graph: The origin domain's attack graph being persisted.
        target_sid: The edge's (foreign) target object SID.
        foreign_sid_to_label: SID -> :class:`ForeignNodeRef` registry.

    Returns:
        The foreign node's graph id, or ``None`` when the SID is genuinely
        unresolvable (out of scope, no registry entry) — the edge stays dropped.
    """
    ref = foreign_sid_to_label.get(str(target_sid or "").upper())
    if ref is None or not ref.node_id:
        return None
    nodes = graph.setdefault("nodes", {})
    if not isinstance(nodes, dict):
        nodes = {}
        graph["nodes"] = nodes
    if ref.node_id not in nodes:
        # Light placeholder — the real foreign node (same graph id) overwrites it
        # when the graphs merge. ``cross_domain_endpoint`` marks it as a stand-in.
        nodes[ref.node_id] = {
            "kind": ref.kind,
            "label": ref.label,
            "name": ref.label,
            "objectId": str(target_sid or "").upper(),
            "highvalue": ref.is_tier0,
            "isTierZero": ref.is_tier0,
            "properties": {
                "name": ref.label,
                "objectid": str(target_sid or "").upper(),
                "cross_domain_endpoint": True,
            },
        }
    return ref.node_id


class CollectorPersistence:
    """Persist collector output into attack_graph.json and memberships.json."""

    def persist(
        self,
        shell: object,
        *,
        domain: str,
        result: CollectionResult,
        foreign_sid_to_label: dict[str, "ForeignNodeRef"] | None = None,
    ) -> dict[str, int]:
        """Persist one CollectionResult and return artifact counters.

        Args:
            foreign_sid_to_label: SID -> :class:`ForeignNodeRef` for principals in
                OTHER collected domains, so an edge whose target SID belongs to a
                foreign domain is persisted as a real cross-domain edge (pointing
                at the foreign node's canonical graph id) instead of being dropped.
                ``None``/empty preserves the legacy single-domain behaviour.
        """

        foreign_sid_to_label = foreign_sid_to_label or {}

        _register_collected_hostnames_for_telemetry(result)

        graph = attack_graph_service.load_attack_graph(shell, domain)
        graph.setdefault("maintenance", {})["native_collector_synced"] = True

        node_payloads = _build_classified_node_payloads(result)
        attack_graph_service.upsert_nodes(graph, node_payloads)
        pruned_edges = _prune_existing_adcs_raw_acl_edges(graph)
        pruned_edges += _prune_existing_container_scope_attack_edges(graph)
        pruned_edges += _prune_existing_group_inferred_host_access_edges(graph)
        pruned_edges += _prune_key_admins_acl_edges_without_adcs(graph)

        _has_enterprise_ca = _result_has_enterprise_ca(result)

        sid_to_graph_id: dict[str, str] = {}
        payload_by_sid = {
            str(payload.get("objectId") or "").upper(): payload
            for payload in node_payloads
            if str(payload.get("objectId") or "").strip()
        }
        for sid in result.nodes:
            payload = payload_by_sid.get(sid.upper())
            if not payload:
                payload = result.nodes[sid].to_graph_payload()
            sid_to_graph_id[sid.upper()] = attack_graph_service._node_id(payload)  # noqa: SLF001

        edge_count = 0
        for edge in result.edges:
            if _should_skip_attack_graph_edge(edge, result, has_enterprise_ca=_has_enterprise_ca):
                continue
            from_id = sid_to_graph_id.get(edge.source_object_id.upper())
            if not from_id:
                continue
            to_id = sid_to_graph_id.get(edge.target_object_id.upper())
            cross_domain = False
            if not to_id:
                to_id = _ensure_foreign_endpoint_node(
                    graph, edge.target_object_id, foreign_sid_to_label
                )
                if not to_id:
                    continue  # genuinely unresolvable (out-of-scope, no ref)
                cross_domain = True
            notes: dict[str, Any] = {"collector_method": edge.method, **edge.notes}
            if cross_domain:
                notes["cross_domain"] = True
            persisted = attack_graph_service.upsert_edge(
                graph,
                from_id=from_id,
                to_id=to_id,
                relation=edge.relation,
                edge_type=f"native_{edge.source}",
                status="discovered",
                notes=notes,
                log_creation=False,
            )
            if persisted:
                edge_count += 1

        derived_edges = _persist_derived_attack_steps(
            graph,
            domain=domain,
            result=result,
            sid_to_graph_id=sid_to_graph_id,
        )
        # SPN-jacking + KCD escalation: derived from delegation + ACL state already
        # in the graph (runs after the raw ACL edges and AllowedToDelegate are
        # present). Graph-dict based so the same logic re-derives over an existing
        # attack_graph.json without a collector re-run.
        derived_edges += derive_spnjack_edges(graph)

        _drop_redundant_direct_compromise_to_domain_edges(graph)

        attack_graph_service.save_attack_graph(shell, domain, graph)
        membership_edges = self._write_memberships(
            shell,
            domain,
            result,
            sid_to_graph_id,
            node_payloads,
            foreign_sid_to_label,
        )
        inventory_counters = CollectorInventoryPersistence().persist(
            shell,
            domain=domain,
            result=result,
        )
        return {
            "nodes": len(node_payloads),
            "edges": edge_count + derived_edges,
            "derived_edges": derived_edges,
            "pruned_edges": pruned_edges,
            "membership_edges": membership_edges,
            **inventory_counters,
        }

    def _write_memberships(
        self,
        shell: object,
        domain: str,
        result: CollectionResult,
        sid_to_graph_id: dict[str, str],
        node_payloads: list[dict[str, Any]],
        foreign_sid_to_label: dict[str, "ForeignNodeRef"] | None = None,
    ) -> int:
        foreign_sid_to_label = foreign_sid_to_label or {}
        graph: dict[str, Any] = {
            "domain": domain,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "schema_version": "membership-1.0",
            "nodes": {},
            "edges": [],
            "version": 2,
        }
        for sid, node in result.nodes.items():
            graph_id = sid_to_graph_id.get(sid.upper())
            if not graph_id:
                continue
            graph["nodes"][graph_id] = node.to_graph_payload()

        seen: set[tuple[str, str, str]] = set()
        for edge in result.edges:
            if edge.relation != "MemberOf":
                continue
            from_id = sid_to_graph_id.get(edge.source_object_id.upper())
            if not from_id:
                continue
            to_id = sid_to_graph_id.get(edge.target_object_id.upper())
            if not to_id:
                # Foreign group membership: the user "belongs" to a group in
                # another collected domain. Point at that group's canonical id
                # so the merge collapses it onto the real foreign group node.
                to_id = _ensure_foreign_endpoint_node(
                    graph, edge.target_object_id, foreign_sid_to_label
                )
                if not to_id:
                    continue
            key = (from_id, edge.relation, to_id)
            if key in seen:
                continue
            seen.add(key)
            graph["edges"].append(
                {
                    "from": from_id,
                    "to": to_id,
                    "relation": edge.relation,
                    "edge_type": "native_ldap",
                    "status": "discovered",
                    "notes": {"collector_method": edge.method},
                }
            )

        workspace_cwd = (
            shell._get_workspace_cwd()  # noqa: SLF001
            if hasattr(shell, "_get_workspace_cwd")
            else getattr(shell, "current_workspace_dir", "")
        )
        domains_dir = getattr(shell, "domains_dir", "domains")
        output_path = domain_subpath(
            workspace_cwd, domains_dir, domain, "memberships.json"
        )
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        write_json_file(output_path, graph)
        return len(graph["edges"])


def _result_has_enterprise_ca(result: CollectionResult) -> bool:
    """Return True when the collection found at least one EnterpriseCA node."""
    return any(str(n.kind) == "EnterpriseCA" for n in result.nodes.values())


def _prune_key_admins_acl_edges_without_adcs(graph: dict[str, Any]) -> int:
    """Remove stale ACL edges targeting Key Admins / Enterprise Key Admins from graph.

    Called after node upsert so ``graph["nodes"]`` already reflects the current
    collection. When an EnterpriseCA node exists the function is a no-op — ADCS
    is present and those ACL edges are meaningful. Without ADCS the groups are
    not exploitable and the edges only generate noise in the attack-path DFS.
    """
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, dict) or not isinstance(edges, list):
        return 0

    if any(
        str(n.get("kind") or "") == "EnterpriseCA"
        for n in nodes.values()
        if isinstance(n, dict)
    ):
        return 0

    def _target_rid(target_id: str) -> int | None:
        node = nodes.get(target_id)
        if not isinstance(node, dict):
            return None
        obj_id = str(node.get("objectId") or node.get("objectid") or "")
        return sid_rid(obj_id)

    kept: list[dict[str, Any]] = []
    removed = 0
    for edge in edges:
        if not isinstance(edge, dict):
            kept.append(edge)
            continue
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        if (
            str(notes.get("collector_method") or "").strip().lower() == "acl"
            and _target_rid(str(edge.get("to") or "")) in _KEY_ADMINS_RIDS
        ):
            removed += 1
            continue
        kept.append(edge)

    if removed:
        graph["edges"] = kept
    return removed


def _should_skip_attack_graph_edge(
    edge: CollectorEdge,
    result: CollectionResult,
    *,
    has_enterprise_ca: bool = True,
) -> bool:
    """Return True for raw ACL facts that should not become path steps.

    ADCS detectors consume ACL facts on templates and CAs to emit interpreted
    ``ADCSESC*`` attack steps. Persisting the raw ACL edge as a separate attack
    path transition adds noisy duplicate paths such as ``AllExtendedRights ->
    ESC1`` or non-exploitable standalone paths such as ``Enroll -> ESC1``
    without improving operator actionability.

    The interpreted ``ADCSESC*`` edges that target a CertTemplate or
    EnterpriseCA are also skipped here. ``_persist_esc_compromise_steps``
    re-emits them with the impersonated principal (Domain Admins, Domain
    Controllers, or the ESC13 issuance-policy group) as the target so attack
    paths terminate at the actual compromise instead of at the abuse-vector
    configuration. ESC13 raw edges only get skipped when their linked group is
    resolved — otherwise the raw template-targeted edge is preserved so the
    misconfiguration remains visible.
    """
    if edge.relation in _ESC_DERIVED_RELATIONS:
        return True
    if edge.relation == "ADCSESC13":
        linked_dn = str((edge.notes or {}).get("linked_group_dn") or "").strip()
        if linked_dn:
            return True
    # Replication-rights to Domain are subsumed by the derived ``DCSync`` edge.
    # Without the full pair the raw edge isn't actionable on its own; with the
    # pair the DCSync edge is the canonical kill-chain step. Either way the
    # raw component edges are noise as path steps.
    if edge.relation in _REPLICATION_RIGHT_RELATIONS:
        target = result.nodes.get(edge.target_object_id.upper())
        if target is not None and str(target.kind) == "Domain":
            return True
    # ACL edges targeting Key Admins (RID 526) / Enterprise Key Admins (RID 527)
    # are only exploitable via shadow credentials + PKINIT, which requires an
    # EnterpriseCA. Without ADCS the groups are not abusable — skip all ACL
    # relations regardless of which specific right is granted.
    if (
        not has_enterprise_ca
        and str(edge.method or "").strip().lower() == "acl"
        and sid_rid(edge.target_object_id) in _KEY_ADMINS_RIDS
    ):
        return True
    if edge.relation not in _ADCS_RAW_ACL_RELATIONS:
        return _is_redundant_container_scope_edge(edge, result)
    if str(edge.method or "").strip().lower() != "acl":
        return False
    target = result.nodes.get(edge.target_object_id.upper())
    if target is None:
        return False
    return str(target.kind) in _ADCS_OBJECT_KINDS


def _is_redundant_container_scope_edge(
    edge: CollectorEdge,
    result: CollectionResult,
) -> bool:
    """Return True when a container-scope secret read has concrete targets."""
    if edge.relation not in _CONTAINER_SCOPE_RELATIONS:
        return False
    target = result.nodes.get(edge.target_object_id.upper())
    if target is None or str(target.kind) not in _CONTAINER_SCOPE_KINDS:
        return False
    source_id = edge.source_object_id.upper()
    for candidate in result.edges:
        if candidate is edge:
            continue
        if candidate.relation != edge.relation:
            continue
        if candidate.source_object_id.upper() != source_id:
            continue
        candidate_target = result.nodes.get(candidate.target_object_id.upper())
        if (
            candidate_target
            and str(candidate_target.kind) not in _CONTAINER_SCOPE_KINDS
        ):
            return True
    return False


def _persist_derived_attack_steps(
    graph: dict[str, Any],
    *,
    domain: str,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
) -> int:
    """Persist attack steps derived from collected account properties."""
    # Kerberoasting and AS-REP Roasting only require the requester to be
    # *authenticated* against the target realm — NOT to be a member of the
    # target domain's local Domain Users group. The correct broadest actor is
    # therefore Authenticated Users (well-known SID S-1-5-11), which a
    # foreign-forest authenticated principal is also a member of (a trusted-forest
    # user CAN kerberoast/AS-REP-roast the target domain). Sourcing these edges
    # from Domain Users (513) — which contains only the domain's own users —
    # silently drops every cross-forest roasting path. The Authenticated Users
    # node is guaranteed present: the orchestrator injects it and wires every
    # enabled principal's MemberOf into it before persistence runs.
    authenticated_users_id = _find_authenticated_users_graph_id(sid_to_graph_id)
    # ADCS Enterprise CA web-enrollment hosts carry an ``HTTP/<ca>`` SPN, but the
    # ADCS collector already owns that host's Kerberos-relay story (ESC8 detection
    # plus the active EPA probe in ``adcs_web_enrollment_probe``). Collect those
    # host identifiers up front so the generic HTTP-SPN surface finding below is
    # suppressed there — otherwise the same asset is reported twice.
    adcs_ca_hosts = _adcs_ca_web_enrollment_hosts(result)
    created = 0
    created += _persist_dcsync_steps(
        graph, result=result, sid_to_graph_id=sid_to_graph_id
    )
    created += _persist_esc_compromise_steps(
        graph, domain=domain, result=result, sid_to_graph_id=sid_to_graph_id
    )
    for node in result.nodes.values():
        graph_id = sid_to_graph_id.get(node.object_id.upper())
        if not graph_id:
            continue
        # Single account-type classification (user / computer / gMSA) shared by
        # every derivation below, so the HTTP-SPN scoping and the kerberoast /
        # AS-REP roast filters agree on what a gMSA is.
        account_type = _node_account_type(node)
        # HTTP/* SPN classification — the SAME collected SPN list the
        # kerberoastable derivation reads, classified for the Kerberos
        # web-app / relay-coercion surface (user, service account, gMSA, or
        # computer). Not a graph edge: it is an observed configuration
        # exposure surfaced as a report finding via ``result.http_spn_findings``
        # (emitted in cli/intelligence.py alongside the trust-posture findings,
        # reaching both the PDF and the web CTEM).
        if node.kind in {"User", "Computer"}:
            # Fire only for structurally UNCRACKABLE accounts — machine accounts
            # and gMSAs (random 120/240-char passwords kerberoast cannot crack),
            # where the relay-surface / EPA-hardening signal is the UNIQUE finding.
            # A normal USER account carrying an HTTP/* SPN is already owned by the
            # Kerberoasting finding (offline password cracking is the direct,
            # higher-value attack); emitting a relay-surface finding on the same
            # account is the same one-asset/two-findings duplication we remove for
            # the ADCS CA vs ESC8 case below.
            if account_type in {"computer", "gmsa"}:
                http_spns = _exclude_adcs_ca_http_spns(
                    _http_service_spns(
                        _node_list_property(node, "serviceprincipalnames")
                    ),
                    adcs_ca_hosts,
                )
                if http_spns:
                    result.http_spn_findings.append(
                        HttpSpnFinding(
                            object_id=node.object_id,
                            samaccountname=node.samaccountname,
                            kind=node.kind,
                            account_type=account_type,
                            distinguished_name=node.distinguished_name,
                            http_spns=tuple(http_spns),
                            enabled=node.enabled,
                        )
                    )
        # A gMSA (``account_type == "gmsa"``) has a KDC-managed 240-char random
        # password, so it is NEVER a valid kerberoast / AS-REP target even though
        # it is a ``User`` node that commonly carries SPNs. Exclude it explicitly
        # by account type (not the fragile trailing-``$`` heuristic) so no
        # false-positive Kerberoasting / ASREPRoasting edge is derived on an
        # account nobody can crack offline.
        if (
            node.kind == "User"
            and account_type != "gmsa"
            and authenticated_users_id
            and _node_is_enabled(node)
        ):
            if _node_bool_property(node, "hasspn"):
                created += _upsert_derived_edge(
                    graph,
                    from_id=authenticated_users_id,
                    to_id=graph_id,
                    relation="Kerberoasting",
                    notes={
                        "collector_method": "derived_kerberoastable_user",
                        "source_property": "servicePrincipalName",
                        "serviceprincipalnames": _node_list_property(
                            node, "serviceprincipalnames"
                        ),
                    },
                )
            if _node_bool_property(node, "dontreqpreauth"):
                created += _upsert_derived_edge(
                    graph,
                    from_id=authenticated_users_id,
                    to_id=graph_id,
                    relation="ASREPRoasting",
                    notes={
                        "collector_method": "derived_asreproastable_user",
                        "source_property": "userAccountControl",
                    },
                )
        if node.kind in {"User", "Computer"}:
            created += _persist_delegation_steps(
                graph,
                domain=domain,
                result=result,
                sid_to_graph_id=sid_to_graph_id,
                source_node=node,
                source_graph_id=graph_id,
            )
    return created


def _persist_dcsync_steps(
    graph: dict[str, Any],
    *,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
) -> int:
    """Derive DCSync edges using intrinsic-token rights evaluation.

    For every User / Computer / Group / ManagedServiceAccount in the
    collection, evaluate the principal's *intrinsic* token — self plus
    kind-implicit well-known SIDs (e.g. S-1-5-9 for DC groups) but
    without transitive MemberOf expansion. A ``DCSync`` edge is emitted
    when the rights union of the intrinsic token satisfies the canonical
    DCSync spec.

    Why intrinsic-only (no MemberOf BFS):
      Deriving DCSync on a principal that has no direct ACE rights, only
      transitively reachable via MemberOf, violates the "one edge = one
      permission" invariant and produces denormalized paths.  The MemberOf
      edges are already in the graph; the path-finding engine traverses
      them naturally, producing the canonical kill chain:

          Domain Admins → MemberOf → Administrators → DCSync → Domain

      rather than the misleading short-cut:

          Domain Admins → DCSync → Domain  ← no literal ACE

    Split-rights (GOAD-essos) exception:
      S-1-5-9 (Enterprise DCs) carries GetChanges; -516 (Domain
      Controllers) carries GetChangesAll. Neither comes from MemberOf —
      the S-1-5-9 SID is *implicit* (added by the KDC to all DC machine
      accounts and to groups whose RID is 516/498). Domain Controllers
      IS the union point, so deriving DCSync on -516 is correct.

    ``GenericAll`` on the Domain is intentionally NOT mapped here — the
    semantic mapping to DCSync belongs to the attack-path step layer.
    """
    from collections import defaultdict

    from adscan_internal.services.effective_principal_rights import (
        DCSYNC,
        compute_intrinsic_token_sids,
        evaluate_compound_right,
    )

    domain_target_sids: set[str] = {
        oid.upper() for oid, n in result.nodes.items() if n.kind == "Domain"
    }
    if not domain_target_sids:
        return 0

    # Build (target, source) → frozenset(rights) index from collected ACEs.
    raw_index: dict[tuple[str, str], set[str]] = defaultdict(set)
    for edge in result.edges:
        relation = str(edge.relation or "")
        if not relation:
            continue
        raw_index[(edge.target_object_id.upper(), edge.source_object_id.upper())].add(
            relation
        )
    rights_index: dict[tuple[str, str], frozenset[str]] = {
        key: frozenset(value) for key, value in raw_index.items()
    }

    eligible_kinds: set[str] = {
        "User",
        "Computer",
        "Group",
        "ManagedServiceAccount",
    }
    token_cache: dict[str, frozenset[str]] = {}

    created = 0
    for principal_oid, principal_node in result.nodes.items():
        if str(principal_node.kind) not in eligible_kinds:
            continue
        principal_upper = principal_oid.upper()

        if principal_upper not in token_cache:
            token_cache[principal_upper] = compute_intrinsic_token_sids(
                principal_oid,
                nodes=result.nodes,
            )

        for target_sid in domain_target_sids:
            if not evaluate_compound_right(
                principal_oid,
                target_sid,
                DCSYNC,
                rights_index=rights_index,
                effective_token=token_cache,
            ):
                continue
            from_id = sid_to_graph_id.get(principal_upper)
            to_id = sid_to_graph_id.get(target_sid)
            if not from_id or not to_id:
                continue
            created += _upsert_derived_edge(
                graph,
                from_id=from_id,
                to_id=to_id,
                relation="DCSync",
                notes={"collector_method": "derived_dcsync_intrinsic_token"},
            )

    return created


# Priority hierarchy for ``direct_compromise → Domain`` edges: smaller rank
# wins. Anything not in the table is treated as "no opinion" — neither
# considered a candidate for the best edge, nor dropped as redundant.
_DOMAIN_COMPROMISE_RELATION_PRIORITY: dict[str, int] = {
    "DCSync": 0,
    "AllExtendedRights": 1,
    "GenericAll": 2,
    "WriteDACL": 3,
    "WriteOwner": 4,
    "GenericWrite": 5,
}


def _drop_redundant_direct_compromise_to_domain_edges(
    graph: dict[str, Any],
) -> int:
    """Collapse direct-compromise → Domain edges to the highest-impact relation.

    For each ``direct_compromise`` source S that has any edge to the Domain
    object, compute the highest-priority relation reachable from S to Domain
    by traversing nested ``MemberOf`` edges through other direct-compromise
    groups. S's own edges to Domain are then trimmed: anything below the
    transitively-reachable best relation is dropped.

    Concrete Active.htb example:

    * ``Domain Admins -GenericWrite-> active.htb``
    * ``Enterprise Admins -GenericAll-> active.htb``
    * ``BUILTIN Administrators -DCSync-> active.htb``
    * ``Domain Admins -MemberOf-> BUILTIN Administrators``
    * ``Enterprise Admins -MemberOf-> BUILTIN Administrators``

    DA can reach DCSync transitively via Administrators, so DA's direct
    ``GenericWrite-> Domain`` edge is redundant noise — drop it. Same for
    EA's ``GenericAll`` edge. The kill chain becomes a single canonical
    path: ``Admin → MemberOf → DA → MemberOf → Administrators → DCSync →
    Domain``. If DA were NOT a member of Administrators (custom env), the
    direct ``GenericWrite`` would survive as the best DA can reach.

    Stepping-stone sources (graph_extension groups like Account Operators,
    EWP, Exchange Trusted Subsystem) are not touched — their lower-impact
    edges to Domain are the legitimate kill chain when no DCSync is
    reachable, and silencing them would break Forest-style multi-hop paths.

    Returns the number of edges removed.
    """
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, dict) or not isinstance(edges, list):
        return 0

    domain_ids = {
        nid
        for nid, node in nodes.items()
        if isinstance(node, dict) and str(node.get("kind") or "") == "Domain"
    }
    if not domain_ids:
        return 0

    # Map: group_id → set of direct parent group_ids (only Group → Group MemberOf).
    from collections import defaultdict

    group_parents: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("relation") or "") != "MemberOf":
            continue
        src = str(edge.get("from") or "")
        dst = str(edge.get("to") or "")
        if not src or not dst:
            continue
        src_node = nodes.get(src)
        dst_node = nodes.get(dst)
        if not isinstance(src_node, dict) or not isinstance(dst_node, dict):
            continue
        if (
            str(src_node.get("kind") or "") == "Group"
            and str(dst_node.get("kind") or "") == "Group"
        ):
            group_parents[src].add(dst)

    def _ancestors(group_id: str) -> set[str]:
        seen: set[str] = set()
        stack = [group_id]
        while stack:
            current = stack.pop()
            for parent in group_parents.get(current, ()):
                if parent not in seen:
                    seen.add(parent)
                    stack.append(parent)
        return seen

    def _is_direct_compromise(node_id: str) -> bool:
        node = nodes.get(node_id)
        if not isinstance(node, dict):
            return False
        # Reuse the canonical classifier from attack_graph_service to stay in
        # sync with the rest of the path/filter pipeline.
        return attack_graph_service._node_is_direct_compromise_source(node)  # noqa: SLF001

    # Index direct edges to Domain per source: src_id → relation → list[edge].
    edges_to_domain: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("to") or "") not in domain_ids:
            continue
        src = str(edge.get("from") or "")
        rel = str(edge.get("relation") or "")
        if not src or not rel:
            continue
        edges_to_domain[src][rel].append(edge)

    def _best(rels: set[str]) -> str | None:
        candidates = [r for r in rels if r in _DOMAIN_COMPROMISE_RELATION_PRIORITY]
        if not candidates:
            return None
        return min(candidates, key=lambda r: _DOMAIN_COMPROMISE_RELATION_PRIORITY[r])

    edges_to_drop: list[dict[str, Any]] = []
    for src_id, rel_to_edges in list(edges_to_domain.items()):
        if not _is_direct_compromise(src_id):
            # Stepping stones (graph_extension etc.) keep all their edges.
            continue

        direct_rels = set(rel_to_edges.keys())
        transitive_rels: set[str] = set()
        for ancestor in _ancestors(src_id):
            if not _is_direct_compromise(ancestor):
                continue
            transitive_rels.update(edges_to_domain.get(ancestor, {}).keys())

        best = _best(direct_rels | transitive_rels)
        if best is None:
            continue

        for rel, edge_list in rel_to_edges.items():
            if rel not in _DOMAIN_COMPROMISE_RELATION_PRIORITY:
                continue
            if rel == best:
                continue
            edges_to_drop.extend(edge_list)

    if not edges_to_drop:
        return 0

    drop_ids = {id(e) for e in edges_to_drop}
    new_edges = [e for e in edges if id(e) not in drop_ids]
    removed = len(edges) - len(new_edges)
    graph["edges"] = new_edges
    return removed


def _persist_delegation_steps(
    graph: dict[str, Any],
    *,
    domain: str,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
    source_node: Any,
    source_graph_id: str,
) -> int:
    """Persist constrained and unconstrained delegation attack steps."""
    created = 0
    for spn in _node_list_property(source_node, "allowedtodelegate"):
        target_id = _resolve_delegation_target_graph_id(
            graph,
            domain=domain,
            result=result,
            sid_to_graph_id=sid_to_graph_id,
            spn=spn,
        )
        if not target_id:
            continue
        created += _upsert_derived_edge(
            graph,
            from_id=source_graph_id,
            to_id=target_id,
            relation="AllowedToDelegate",
            notes={
                "collector_method": "derived_constrained_delegation",
                "source_property": "msDS-AllowedToDelegateTo",
                "delegated_spn": spn,
            },
        )
    if _node_bool_property(source_node, "hasunconstrainedauth") or _node_bool_property(
        source_node, "unconstraineddelegation"
    ):
        # Domain Controllers (primarygroupid=516) always have TrustedForDelegation=True
        # by design — it is required for the DC to function as a KDC.  Emitting an
        # UnconstrainedDelegation edge for a DC is a false positive and clutters
        # attack paths.  Only non-DC machines with this flag set are a finding.
        _pgid = source_node.properties.get("primarygroupid")
        _is_dc = int(_pgid) == 516 if _pgid is not None else False
        if not _is_dc:
            created += _upsert_derived_edge(
                graph,
                from_id=source_graph_id,
                to_id=source_graph_id,
                relation="UnconstrainedDelegation",
                notes={
                    "collector_method": "derived_unconstrained_delegation",
                    "source_property": "userAccountControl",
                },
            )
    return created


# servicePrincipalName-write capability: any ACE that lets the holder set an
# SPN on the target object. WriteSPN is the precise right; the three generic
# property-set writes and ownership transitively grant it too.
_SPN_WRITE_RELATIONS: frozenset[str] = frozenset(
    {"writespn", "genericall", "genericwrite", "writedacl", "owns"}
)


def _bfs_memberof_node_ids(
    memberof_adjacency: dict[str, set[str]], start_id: str
) -> set[str]:
    """Return all node ids reachable from ``start_id`` via MemberOf edges (cycle-safe).

    Operates on graph *node ids* (``name:<sam|sid>``), not raw SIDs, so it works
    against the canonical graph dict at both collector persist-time and standalone
    re-derivation over an existing ``attack_graph.json``. ``start_id`` is NOT
    included in the result.
    """
    visited: set[str] = set()
    queue: list[str] = list(memberof_adjacency.get(start_id, set()))
    while queue:
        current = queue.pop()
        if current in visited:
            continue
        visited.add(current)
        for nxt in memberof_adjacency.get(current, ()):
            if nxt not in visited:
                queue.append(nxt)
    return visited


def derive_spnjack_edges(graph: dict[str, Any]) -> int:
    """Derive ``SPNJack`` escalation edges from collected delegation + ACL state.

    SPN-jacking + KCD with protocol transition. A principal P escalates to a
    target computer T when **all three** conditions hold:

    1. **KCD + protocol transition (T2A4D):** ``P.hastrustedtoauth`` is True and
       ``P.allowedtodelegate`` (msDS-AllowedToDelegateTo) is non-empty. T2A4D is
       required so P can S4U2Self an *arbitrary* user (e.g. Administrator), not
       only users who authenticate to P.
    2. **servicePrincipalName-write over a Computer T:** P holds — directly or via
       transitive group membership — an edge of relation in
       :data:`_SPN_WRITE_RELATIONS` to a Computer object T. The WriteSPN edges in
       the wild frequently originate from a *group* P belongs to, so the
       capability is resolved over P's effective token (self + MemberOf closure).
    3. **Vehicle SPN is plantable:** at least one SPN S in ``P.allowedtodelegate``
       is either currently unowned (free) or owned by a computer P can write SPNs
       on (so P can ``delspn`` S from it before ``addspn`` onto T).

    For each qualifying target T the edge ``P -> SPNJack -> T`` is emitted
    (``EdgeKind.ESCALATION``, ``direct_target_compromise``, deterministic — no
    offline crack). Targets that are the current owner of P's vehicle SPN are
    skipped: P can already delegate to them directly (modelled by the existing
    ``AllowedToDelegate`` edge), so SPNJack would duplicate it.

    Operates purely on the canonical graph dict (``nodes`` + ``edges``) and is
    idempotent (``upsert_edge`` keys on ``(from, relation, to)``), so it is safe
    to run at collector persist-time and to re-derive over an existing graph.

    Returns:
        Count of SPNJack edges created.
    """
    from collections import defaultdict

    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, dict) or not isinstance(edges, list):
        return 0

    # Index 1 — SPN string (lower) -> owning computer node id. First writer wins;
    # an SPN is unique in AD so there is at most one owner.
    spn_owner: dict[str, str] = {}
    for node_id, node in nodes.items():
        if not isinstance(node, dict) or str(node.get("kind") or "") != "Computer":
            continue
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        for spn in props.get("serviceprincipalnames") or []:
            key = str(spn).strip().lower()
            if key:
                spn_owner.setdefault(key, str(node_id))

    # Index 2 — MemberOf adjacency (node id -> set(group node id)).
    # Index 3 — SPN-write source node id -> set(Computer target node id).
    # Snapshot existing SPNJack pairs so the created-count stays accurate on a
    # re-derive (upsert is idempotent but returns the existing edge truthily).
    memberof_adjacency: dict[str, set[str]] = defaultdict(set)
    spnwrite_targets_by_source: dict[str, set[str]] = defaultdict(set)
    existing_spnjack: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or "").strip().lower()
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if not from_id or not to_id:
            continue
        if relation == "memberof":
            memberof_adjacency[from_id].add(to_id)
        elif relation == "spnjack":
            existing_spnjack.add((from_id, to_id))
        elif relation in _SPN_WRITE_RELATIONS:
            target_node = nodes.get(to_id)
            if (
                isinstance(target_node, dict)
                and str(target_node.get("kind") or "") == "Computer"
            ):
                spnwrite_targets_by_source[from_id].add(to_id)

    created = 0
    for principal_id, principal in nodes.items():
        if not isinstance(principal, dict):
            continue
        if str(principal.get("kind") or "") not in {"User", "Computer"}:
            continue
        props = (
            principal.get("properties")
            if isinstance(principal.get("properties"), dict)
            else {}
        )
        # Condition 1 — KCD + T2A4D.
        if not bool(props.get("hastrustedtoauth")):
            continue
        kcd_spns = [
            str(spn).strip()
            for spn in (props.get("allowedtodelegate") or [])
            if str(spn).strip()
        ]
        if not kcd_spns:
            continue

        # Condition 2 — effective SPN-write computer targets (self + groups).
        effective_token = {str(principal_id)} | _bfs_memberof_node_ids(
            memberof_adjacency, str(principal_id)
        )
        targets: set[str] = set()
        for sid in effective_token:
            targets |= spnwrite_targets_by_source.get(sid, set())
        if not targets:
            continue

        # Condition 3 — a plantable vehicle SPN (free, or owner P can write).
        vehicle_spn: str | None = None
        vehicle_owner: str | None = None
        kcd_owner_ids: set[str] = set()
        for spn in kcd_spns:
            owner = spn_owner.get(spn.lower())
            if owner is not None:
                kcd_owner_ids.add(owner)
            if vehicle_spn is None and (owner is None or owner in targets):
                vehicle_spn = spn
                vehicle_owner = owner
        if vehicle_spn is None:
            continue

        # Emit SPNJack to each writable computer target, skipping targets P can
        # already delegate to directly (current owners of P's KCD SPNs) — those
        # are covered by the AllowedToDelegate edge and would be duplicates.
        def _label(node_id: str | None) -> str:
            node = nodes.get(node_id) if node_id else None
            return str(node.get("label") or node_id or "") if isinstance(node, dict) else (node_id or "")

        owner_label = _label(vehicle_owner) if vehicle_owner is not None else ""
        vehicle_mode = "free_spn" if vehicle_owner is None else "delspn_from_owner"
        for target_id in sorted(targets):
            if target_id == str(principal_id) or target_id in kcd_owner_ids:
                continue
            is_new = (str(principal_id), target_id) not in existing_spnjack
            # Which principal(s) in P's token actually grant the SPN-write on this
            # target — the precondition the report/UX must surface faithfully so a
            # group-mediated right is never shown as a direct one. Self when P
            # holds it directly; otherwise the group(s) in P's membership token.
            grantors = sorted(
                _label(sid)
                for sid in effective_token
                if target_id in spnwrite_targets_by_source.get(sid, set())
            )
            spn_write_via = (
                "direct"
                if _label(str(principal_id)) in grantors and len(grantors) == 1
                else ", ".join(g for g in grantors if g)
            )
            edge = attack_graph_service.upsert_edge(
                graph,
                from_id=str(principal_id),
                to_id=target_id,
                relation="SPNJack",
                edge_type="native_derived",
                status="discovered",
                notes={
                    "collector_method": "derived_spnjack",
                    # Precondition chain — kept structured so report/UX can expand
                    # the single SPNJack edge into the multi-step requirement it
                    # represents (no over-simplification of a multi-step technique).
                    "delegated_spn": vehicle_spn,
                    "vehicle_spn_owner": owner_label,
                    "vehicle_mode": vehicle_mode,
                    "spn_write_via": spn_write_via,
                    "protocol_transition": True,
                    "source_property": (
                        "msDS-AllowedToDelegateTo + TrustedToAuthForDelegation"
                    ),
                },
            )
            if edge and is_new:
                existing_spnjack.add((str(principal_id), target_id))
                created += 1
    return created


def _persist_esc_compromise_steps(
    graph: dict[str, Any],
    *,
    domain: str,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
) -> int:
    """Re-emit ADCSESC* edges with the impersonated principal as target.

    Raw collector edges target the abuse vector (CertTemplate or EnterpriseCA),
    which breaks kill-chain semantics: the path terminates at a configuration
    object instead of at the principal that is actually compromised. This
    helper aggregates raw ESC edges by ``(source_principal, relation,
    impersonated_principal)`` and re-emits one derived edge per group with the
    abuse-vector resources preserved in ``notes.vulnerable_resources`` so
    reporting and remediation workflows still see them.

    Mapping rules:
        * ``ADCSESC1/2/3/4/5/6/7/15`` impersonate Domain Admins directly
          (arbitrary SAN/UPN — any enroller is sufficient).
        * ``ADCSESC9/10`` require a writer-mediated attack chain: the
          attacker must additionally hold user-write rights over a puppet
          account whose UPN they can swap. The source of the derived edge is
          the writer, not the enroll-principal (which is often Domain Users).
        * ``ADCSESC8/11`` target Domain Controllers (NTLM relay → cert as a
          DC computer account).
        * ``ADCSESC13`` is deferred until issuance-policy OID resolution lands —
          its target group is per-template and cannot be inferred from raw
          edge notes alone.
    """
    from collections import defaultdict

    domain_admins_id = _find_well_known_group_graph_id(
        result, sid_to_graph_id, rid=_DOMAIN_ADMINS_RID
    )
    domain_controllers_id = _find_well_known_group_graph_id(
        result, sid_to_graph_id, rid=_DOMAIN_CONTROLLERS_RID
    )
    domain_sid = _derive_domain_sid_from_result(result)

    def _resolve_well_known_target(graph_id: str, rid: int, relation: str) -> str:
        """Return the Tier-0 target id, synthesizing the node if absent.

        When the real Domain Admins / Domain Controllers node was not in the
        collection result, the interpreted ``ADCSESC*`` step would otherwise be
        dropped silently and the kill chain to the privileged principal lost.
        Synthesize a Tier-0 node from the domain SID so the path survives.
        Emit a warning (never a silent drop) when no domain SID is derivable.
        """
        if graph_id:
            return graph_id
        if not domain_sid:
            print_warning(
                "Skipping interpreted ADCS attack step "
                f"{mark_sensitive(relation, 'domain')}: cannot synthesize the "
                "privileged target (RID "
                f"{rid}) because no domain SID was found in the collection "
                f"result for {mark_sensitive(domain, 'domain')}."
            )
            return ""
        synthesized = _synthesize_well_known_group_node(
            graph, domain=domain, domain_sid=domain_sid, rid=rid
        )
        print_info_debug(
            "Synthesized Tier-0 target "
            f"{mark_sensitive(_WELL_KNOWN_GROUP_LABELS.get(rid, str(rid)), 'domain')} "
            f"(RID {rid}) for interpreted ADCS attack step "
            f"{mark_sensitive(relation, 'domain')} in "
            f"{mark_sensitive(domain, 'domain')} (target node absent from collection)."
        )
        return synthesized

    template_lookup = {oid.upper(): node for oid, node in result.nodes.items()}
    dn_to_graph_id = _build_dn_to_graph_id_map(result, sid_to_graph_id)

    # ── Pre-pass A: index (writer_sid -> [puppet_sid]) for ESC9/10 ────────────
    # A writer must have one of _ESC9_USER_WRITE_RELATIONS on a User account
    # that is NOT itself (self-edges are meaningless for UPN-swap).
    user_writers: dict[str, list[str]] = defaultdict(list)
    for edge in result.edges:
        if edge.relation not in _ESC9_USER_WRITE_RELATIONS:
            continue
        target_node = result.nodes.get(edge.target_object_id.upper())
        if not target_node or target_node.kind != "User":
            continue
        writer_sid = edge.source_object_id.upper()
        puppet_sid = edge.target_object_id.upper()
        if writer_sid == puppet_sid:
            continue
        user_writers[writer_sid].append(puppet_sid)

    # ── Pre-pass B: index enroll-set per ESC9/10 template ────────────────────
    # esc9_template_enrollers[template_oid] = {enroller_sid, ...}
    esc9_template_enrollers: dict[str, set[str]] = defaultdict(set)
    for edge in result.edges:
        if edge.relation not in _ESC_WRITER_MEDIATED:
            continue
        esc9_template_enrollers[edge.target_object_id.upper()].add(
            edge.source_object_id.upper()
        )

    # ── Pre-pass C: build group-member index from MemberOf edges ─────────────
    # group_members[group_sid] = {member_sid, ...}
    group_members: dict[str, set[str]] = defaultdict(set)
    for edge in result.edges:
        if edge.relation == "MemberOf":
            group_members[edge.target_object_id.upper()].add(
                edge.source_object_id.upper()
            )

    def _puppet_in_enrollers(puppet_sid: str, template_oid: str) -> bool:
        """Return True when puppet_sid is directly or transitively in the enroll set."""
        enroll_set = esc9_template_enrollers.get(template_oid)
        if not enroll_set:
            return False
        if puppet_sid in enroll_set:
            return True
        # BFS over group_members to find whether puppet_sid is a transitive
        # member of any group in the enroll set.
        visited: set[str] = set()
        pending = list(enroll_set)
        depth = 0
        while pending and depth < _ESC9_BFS_MAX_DEPTH:
            next_layer: list[str] = []
            for group_sid in pending:
                if group_sid in visited:
                    continue
                visited.add(group_sid)
                members = group_members.get(group_sid, set())
                if puppet_sid in members:
                    return True
                for member_sid in members:
                    # Only follow group members further to expand nested groups.
                    member_node = result.nodes.get(member_sid)
                    if member_node and member_node.kind == "Group":
                        next_layer.append(member_sid)
            pending = next_layer
            depth += 1
        return False

    # ── Main aggregation loop ─────────────────────────────────────────────────
    # Group raw ESC edges by (source_sid, relation, derived_target_id).
    # For most ESCs the derived target is fixed by the relation; for ESC13 it is
    # per-edge (the group linked to the issuance policy).
    Bucket = tuple[str, str, str]  # (source_sid, relation, target_id)
    aggregated: dict[Bucket, list[dict[str, Any]]] = defaultdict(list)

    for edge in result.edges:
        relation = edge.relation
        impersonation_method = ""
        impersonated_principal_hint = ""

        # ESC9/10 special path: derive edges from writers, not from enrollers.
        if relation in _ESC_WRITER_MEDIATED:
            domain_admins_id = _resolve_well_known_target(
                domain_admins_id, _DOMAIN_ADMINS_RID, relation
            )
            if not domain_admins_id:
                continue
            template_oid = edge.target_object_id.upper()
            vulnerable = _build_esc_vulnerable_resource_entry(
                edge=edge, template_lookup=template_lookup
            )
            for writer_sid, puppets in user_writers.items():
                viable_puppets = [
                    p for p in puppets if _puppet_in_enrollers(p, template_oid)
                ]
                if not viable_puppets:
                    continue
                writer_graph_id = sid_to_graph_id.get(writer_sid)
                if not writer_graph_id:
                    continue
                puppet_resources = []
                seen_puppets: set[str] = set()
                for puppet_sid in viable_puppets:
                    if puppet_sid in seen_puppets:
                        continue
                    seen_puppets.add(puppet_sid)
                    puppet_node = result.nodes.get(puppet_sid)
                    if puppet_node and puppet_node.kind == "User":
                        puppet_resources.append(
                            {
                                "kind": "User",
                                "object_id": puppet_sid,
                                "name": puppet_node.name,
                                "distinguished_name": puppet_node.distinguished_name,
                                "role": "puppet",
                            }
                        )
                aggregated[(writer_graph_id, relation, domain_admins_id)].append(
                    {
                        "vulnerable": vulnerable,
                        "extra_resources": puppet_resources,
                        "raw_notes": dict(edge.notes or {}),
                        "impersonation_method": "san_arbitrary_subject_via_upn_swap_pkinit",
                        "impersonated_principal_hint": "Administrator",
                        "raw_notes_extra": {
                            "puppet_user_sids": viable_puppets,
                            "template_dn": (
                                getattr(
                                    template_lookup.get(template_oid),
                                    "distinguished_name",
                                    None,
                                )
                            ),
                            "attack_chain": "shadow_creds_pkinit_upn_swap_pkinit",
                        },
                    }
                )
            continue  # skip the standard path for this edge

        target_id = ""
        if relation in _ESC_TO_DOMAIN_ADMINS:
            domain_admins_id = _resolve_well_known_target(
                domain_admins_id, _DOMAIN_ADMINS_RID, relation
            )
            target_id = domain_admins_id
            impersonation_method = "san_arbitrary_subject"
            impersonated_principal_hint = "Administrator"
        elif relation in _ESC_TO_DOMAIN_CONTROLLERS:
            domain_controllers_id = _resolve_well_known_target(
                domain_controllers_id, _DOMAIN_CONTROLLERS_RID, relation
            )
            target_id = domain_controllers_id
            impersonation_method = "ntlm_relay_to_enrollment"
            impersonated_principal_hint = "DC computer account"
        elif relation == "ADCSESC13":
            linked_dn = str((edge.notes or {}).get("linked_group_dn") or "").strip()
            if not linked_dn:
                continue  # raw edge survives in the main loop until OID resolves
            target_id = dn_to_graph_id.get(linked_dn.casefold(), "")
            impersonation_method = "issuance_policy_group_link"
            impersonated_principal_hint = "issuance-policy linked group"
        else:
            continue

        if not target_id:
            # _resolve_well_known_target already warned for DA/DC synthesis
            # failures; ESC13 reaching here means the issuance-policy linked
            # group DN did not resolve to a known node. Never drop silently.
            if relation == "ADCSESC13":
                print_warning(
                    "Skipping interpreted ADCS attack step "
                    f"{mark_sensitive(relation, 'domain')}: issuance-policy "
                    "linked group could not be resolved to a known node in "
                    f"{mark_sensitive(domain, 'domain')}."
                )
            continue
        from_id = sid_to_graph_id.get(edge.source_object_id.upper())
        if not from_id:
            continue

        vulnerable = _build_esc_vulnerable_resource_entry(
            edge=edge, template_lookup=template_lookup
        )
        aggregated[(from_id, relation, target_id)].append(
            {
                "vulnerable": vulnerable,
                "extra_resources": [],
                "raw_notes": dict(edge.notes or {}),
                "impersonation_method": impersonation_method,
                "impersonated_principal_hint": impersonated_principal_hint,
                "raw_notes_extra": {},
            }
        )

    created = 0
    for (from_id, relation, to_id), entries in aggregated.items():
        # Deduplicate vulnerable resources by (kind, object_id).
        seen: set[tuple[str, str]] = set()
        vulnerable_resources: list[dict[str, Any]] = []
        merged_raw_notes: dict[str, Any] = {}
        merged_extra_notes: dict[str, Any] = {}
        for entry in entries:
            resource = entry["vulnerable"]
            key = (
                str(resource.get("kind") or ""),
                str(resource.get("object_id") or ""),
            )
            if key not in seen:
                seen.add(key)
                vulnerable_resources.append(resource)
            # Append puppet-user entries (deduplicated by (kind, object_id)).
            for extra in entry.get("extra_resources") or []:
                extra_key = (
                    str(extra.get("kind") or ""),
                    str(extra.get("object_id") or ""),
                )
                if extra_key not in seen:
                    seen.add(extra_key)
                    vulnerable_resources.append(extra)
            for note_key, note_value in entry["raw_notes"].items():
                # Preserve any unique raw-edge note fields (e.g. ESC8 web/RPC
                # endpoint hints) alongside the aggregated resources.
                merged_raw_notes.setdefault(note_key, note_value)
            for note_key, note_value in (entry.get("raw_notes_extra") or {}).items():
                merged_extra_notes.setdefault(note_key, note_value)

        first = entries[0]
        notes: dict[str, Any] = {
            "collector_method": "derived_esc_compromise",
            "vulnerable_resources": vulnerable_resources,
            "vulnerable_resource_count": len(vulnerable_resources),
            "impersonation_method": first["impersonation_method"],
            "impersonated_principal_hint": first["impersonated_principal_hint"],
        }
        if merged_raw_notes:
            notes["raw_collector_notes"] = merged_raw_notes
        if merged_extra_notes:
            notes.update(merged_extra_notes)

        created += _upsert_derived_edge(
            graph,
            from_id=from_id,
            to_id=to_id,
            relation=relation,
            notes=notes,
        )

    return created


def _build_esc_vulnerable_resource_entry(
    *,
    edge: CollectorEdge,
    template_lookup: dict[str, Any],
) -> dict[str, Any]:
    """Return a vulnerable-resource entry for one raw ESC edge."""
    object_id = str(edge.target_object_id or "").upper()
    node = template_lookup.get(object_id)
    kind = str(getattr(node, "kind", None) or "Unknown")
    # Prefer the actual enrollment CN (e.g. "RetroClients") over the display name ("RETRO CLIENTS").
    # The CA requires the template CN for enrollment, not the displayName.
    cn_prop = (getattr(node, "properties", None) or {}).get("cn")
    name = cn_prop or str(getattr(node, "name", None) or "").split("@", 1)[0]
    entry: dict[str, Any] = {
        "kind": kind,
        "object_id": edge.target_object_id,
    }
    if name:
        entry["name"] = name
    distinguished = str(getattr(node, "distinguished_name", None) or "")
    if distinguished:
        entry["distinguished_name"] = distinguished
    return entry


def _build_dn_to_graph_id_map(
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
) -> dict[str, str]:
    """Return a case-folded distinguishedName → graph id index for groups."""
    mapping: dict[str, str] = {}
    for object_id, node in result.nodes.items():
        if node.kind != "Group":
            continue
        dn = str(node.distinguished_name or "").strip()
        if not dn:
            continue
        graph_id = sid_to_graph_id.get(object_id.upper())
        if graph_id:
            mapping[dn.casefold()] = graph_id
    return mapping


def _derive_domain_sid_from_result(result: CollectionResult) -> str:
    """Return the domain SID (``S-1-5-21-...`` prefix) from any domain object.

    Scans the collection result for the first ``S-1-5-21-`` object SID and
    strips its trailing relative identifier, yielding the machine/domain SID.
    Returns an empty string when no domain-scoped object is present.
    """
    for object_id in result.nodes:
        oid_upper = str(object_id or "").upper()
        if not oid_upper.startswith("S-1-5-21-"):
            continue
        head, _, tail = oid_upper.rpartition("-")
        if head and tail.isdigit():
            return head
    return ""


def _synthesize_well_known_group_node(
    graph: dict[str, Any],
    *,
    domain: str,
    domain_sid: str,
    rid: int,
) -> str:
    """Synthesize a Tier-0 well-known group node and return its graph id.

    Used only when the real Domain Admins (RID 512) / Domain Controllers
    (RID 516) node is absent from the collection result (e.g. the operator
    lacked read rights over the group, or it fell outside the collected
    base). Without a target node the interpreted ``ADCSESC*`` attack step
    would be dropped, breaking the kill-chain semantics ``... -> Domain
    Admins``. Re-anchoring the derived edge on a synthesized Tier-0 node
    preserves the path while flagging the node as synthetic for downstream
    consumers.
    """
    object_id = f"{domain_sid.upper()}-{rid}"
    base_label = _WELL_KNOWN_GROUP_LABELS.get(rid, f"WELL-KNOWN-{rid}")
    label = f"{base_label}@{domain.upper()}"
    node_payload = {
        "kind": "Group",
        "label": label,
        "name": label,
        "objectId": object_id,
        "highvalue": True,
        "isTierZero": True,
        "properties": {
            "domain": domain.upper(),
            "name": label,
            "objectid": object_id,
            "highvalue": True,
            "isTierZero": True,
            "system_tags": "admin_tier_0",
            "synthetic": True,
            "source": "synthesized_well_known_group",
        },
    }
    try:
        attack_graph_service.upsert_nodes(graph, [node_payload])
        return attack_graph_service._node_id(node_payload)  # noqa: SLF001
    except Exception as exc:  # pragma: no cover - defensive
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_warning(
            "Failed to synthesize Tier-0 target node "
            f"{mark_sensitive(label, 'domain')}: {exc}"
        )
        return ""


def _find_well_known_group_graph_id(
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
    *,
    rid: int,
) -> str:
    """Return the graph id of a domain group identified by RID, or empty string."""
    suffix = f"-{rid}"
    for object_id in result.nodes:
        oid_upper = object_id.upper()
        if oid_upper.endswith(suffix) and oid_upper.startswith("S-1-5-21-"):
            graph_id = sid_to_graph_id.get(oid_upper)
            if graph_id:
                return graph_id
    return ""


def _upsert_derived_edge(
    graph: dict[str, Any],
    *,
    from_id: str,
    to_id: str,
    relation: str,
    notes: dict[str, Any],
) -> int:
    edge = attack_graph_service.upsert_edge(
        graph,
        from_id=from_id,
        to_id=to_id,
        relation=relation,
        edge_type="native_derived",
        status="discovered",
        notes=notes,
        log_creation=False,
    )
    return 1 if edge else 0


def _find_authenticated_users_graph_id(
    sid_to_graph_id: dict[str, str],
) -> str:
    """Return the graph id of the Authenticated Users well-known node (S-1-5-11).

    Resolved by its fixed well-known SID rather than by group name — the node is
    synthetic (``Authenticated Users@WELLKNOWN``), guaranteed injected by
    ``well_known_sids.inject_all_well_known_sid_nodes`` before persistence, and
    keyed under its SID in ``sid_to_graph_id`` like every other collected node.
    Returns ``""`` when the node is absent so the caller can skip emission rather
    than sourcing an edge from an unresolvable placeholder.
    """
    return sid_to_graph_id.get(_AUTHENTICATED_USERS_SID, "")


def _resolve_delegation_target_graph_id(
    graph: dict[str, Any],
    *,
    domain: str,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
    spn: str,
) -> str:
    host = _host_from_spn(spn)
    if not host:
        return ""
    host_key = host.casefold().rstrip(".")
    short_key = host_key.split(".", 1)[0].rstrip("$")
    for object_id, node in result.nodes.items():
        if node.kind != "Computer":
            continue
        candidates = {
            str(node.name or "").casefold().rstrip("."),
            str(node.samaccountname or "").casefold().rstrip("$"),
        }
        dns_name = str(node.properties.get("dnshostname") or "").casefold().rstrip(".")
        if dns_name:
            candidates.add(dns_name)
            candidates.add(dns_name.split(".", 1)[0].rstrip("$"))
        if host_key in candidates or short_key in candidates:
            return sid_to_graph_id.get(object_id.upper(), "")

    hostname = host.rstrip(".")
    node_payload = {
        "kind": "Computer",
        "label": hostname.upper(),
        "name": hostname.upper(),
        "objectId": f"{domain.upper()}-DELEGATION-SPN-{hostname.upper()}",
        "properties": {
            "domain": domain.upper(),
            "dnshostname": hostname.lower(),
            "name": hostname.upper(),
            "synthetic": True,
            "source": "msDS-AllowedToDelegateTo",
        },
    }
    attack_graph_service.upsert_nodes(graph, [node_payload])
    return attack_graph_service._node_id(node_payload)  # noqa: SLF001


def _host_from_spn(spn: str) -> str:
    raw = str(spn or "").strip()
    if "/" not in raw:
        return ""
    host = raw.split("/", 1)[1].split(":", 1)[0].split("/", 1)[0].strip()
    return host.rstrip(".")


def _node_bool_property(node: Any, key: str) -> bool:
    return bool(node.properties.get(key))


def _node_is_enabled(node: Any) -> bool:
    """Return whether a collected principal should produce executable paths."""
    return node.enabled is not False


def _node_list_property(node: Any, key: str) -> list[str]:
    value = node.properties.get(key)
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _http_service_spns(spns: list[str]) -> list[str]:
    """Return the subset of ``spns`` whose service class is HTTP.

    An SPN is ``serviceclass/instance[:port][/name]``; the service class is the
    token before the first ``/`` (MS-ADTS 2.2.21), matched case-insensitively.
    Unlike the auto-registered ``HOST/`` / ``RestrictedKrbHost/`` SPNs, an
    ``HTTP/`` SPN is registered deliberately when a Kerberos web service is
    published under the account, so every occurrence is the signal. Reuses the
    already-collected SPN list — the same one the kerberoastable derivation
    walks — so there is no second SPN pass.
    """
    out: list[str] = []
    for spn in spns or []:
        text = str(spn).strip()
        if text and text.split("/", 1)[0].strip().lower() == "http":
            out.append(text)
    return out


def _adcs_ca_web_enrollment_hosts(result: CollectionResult) -> set[str]:
    """Return the FQDN host identifiers of every ADCS Enterprise CA collected.

    An Enterprise CA's web-enrollment endpoint publishes an ``HTTP/<ca>`` SPN, so
    the generic HTTP-SPN relay-surface finding would fire on the very host that
    ADCS/ESC8 detection (and the active EPA probe in ``adcs_web_enrollment_probe``)
    already covers with a specific, higher-value finding. The authoritative marker
    is the ``EnterpriseCA`` node's ``dns_hostname`` (the CA's FQDN, populated by
    the ADCS collector). These hosts are used to suppress the duplicate.
    """
    hosts: set[str] = set()
    for node in result.nodes.values():
        if str(node.kind) != "EnterpriseCA":
            continue
        dns_hostname = str(node.properties.get("dns_hostname") or "").strip()
        if dns_hostname:
            hosts.add(dns_hostname)
    return hosts


def _spn_instance_host(spn: str) -> str:
    """Return the instance host of an SPN (``serviceclass/instance[:port][/name]``).

    The instance is the token after the first ``/``; an optional ``:port`` and an
    optional ``/servicename`` suffix are dropped. Returns ``""`` for a malformed
    SPN with no instance.
    """
    text = str(spn or "").strip()
    if "/" not in text:
        return ""
    instance = text.split("/", 1)[1].strip()
    instance = instance.split("/", 1)[0]
    instance = instance.split(":", 1)[0]
    return instance.strip()


def _exclude_adcs_ca_http_spns(
    http_spns: list[str], adcs_ca_hosts: set[str]
) -> list[str]:
    """Drop HTTP SPNs whose instance host is an ADCS CA web-enrollment endpoint.

    ADCS/ESC8 detection owns those hosts' Kerberos-relay story, so the generic
    HTTP-SPN surface finding would be a duplicate on the same asset. Host matching
    is alias-aware (IP <-> short <-> FQDN <-> ``HOST$``) via the canonical
    resolver. Non-ADCS HTTP SPNs are kept unchanged, so a principal carrying both
    a CA and a non-CA HTTP SPN still surfaces only for the non-CA endpoint.
    """
    if not adcs_ca_hosts:
        return http_spns
    kept: list[str] = []
    for spn in http_spns:
        instance = _spn_instance_host(spn)
        if instance and any(
            hosts_match(instance, ca_host) for ca_host in adcs_ca_hosts
        ):
            continue
        kept.append(spn)
    return kept


def _node_account_type(node: Any) -> str:
    """Human account-type label for the HTTP-SPN finding evidence."""
    explicit = str(node.properties.get("account_type") or "").strip().lower()
    if explicit:
        return explicit
    return "computer" if node.kind == "Computer" else "user"


def _prune_existing_adcs_raw_acl_edges(graph: dict[str, Any]) -> int:
    """Remove stale raw ACL edges to ADCS nodes from an attack graph."""
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, dict) or not isinstance(edges, list):
        return 0

    def _node_kind(node_id: str) -> str:
        node = nodes.get(node_id)
        if not isinstance(node, dict):
            return ""
        return str(node.get("kind") or "")

    kept: list[dict[str, Any]] = []
    removed = 0
    for edge in edges:
        if not isinstance(edge, dict):
            kept.append(edge)
            continue
        relation = str(edge.get("relation") or "")
        target_id = str(edge.get("to") or "")
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        collector_method = str(notes.get("collector_method") or "").strip().lower()
        if (
            relation in _ADCS_RAW_ACL_RELATIONS
            and collector_method == "acl"
            and _node_kind(target_id) in _ADCS_OBJECT_KINDS
        ):
            removed += 1
            continue
        kept.append(edge)

    if removed:
        graph["edges"] = kept
    return removed


def _prune_existing_container_scope_attack_edges(graph: dict[str, Any]) -> int:
    """Remove stale container-scope secret-read edges when concrete targets exist."""
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, dict) or not isinstance(edges, list):
        return 0

    def _node_kind(node_id: str) -> str:
        node = nodes.get(node_id)
        if not isinstance(node, dict):
            return ""
        return str(node.get("kind") or "")

    concrete_sources: set[tuple[str, str]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        relation = str(edge.get("relation") or "")
        if relation not in _CONTAINER_SCOPE_RELATIONS:
            continue
        target_id = str(edge.get("to") or "")
        if _node_kind(target_id) not in _CONTAINER_SCOPE_KINDS:
            concrete_sources.add((str(edge.get("from") or ""), relation))

    if not concrete_sources:
        return 0

    kept: list[dict[str, Any]] = []
    removed = 0
    for edge in edges:
        if not isinstance(edge, dict):
            kept.append(edge)
            continue
        relation = str(edge.get("relation") or "")
        source_id = str(edge.get("from") or "")
        target_id = str(edge.get("to") or "")
        if (
            relation in _CONTAINER_SCOPE_RELATIONS
            and _node_kind(target_id) in _CONTAINER_SCOPE_KINDS
            and (source_id, relation) in concrete_sources
        ):
            removed += 1
            continue
        kept.append(edge)

    if removed:
        graph["edges"] = kept
    return removed


def _prune_existing_group_inferred_host_access_edges(graph: dict[str, Any]) -> int:
    """Remove stale expanded LDAP host-access inferences before compression."""
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return 0

    kept: list[dict[str, Any]] = []
    removed = 0
    for edge in edges:
        if not isinstance(edge, dict):
            kept.append(edge)
            continue
        relation = str(edge.get("relation") or "")
        if relation not in {"CanRDP", "CanPSRemote"}:
            kept.append(edge)
            continue
        edge_type = str(edge.get("edge_type") or "").strip().lower()
        notes = edge.get("notes") if isinstance(edge.get("notes"), dict) else {}
        collector_method = str(notes.get("collector_method") or "").strip().lower()
        target_selector = str(notes.get("target_selector") or "").strip().lower()
        if (
            edge_type == "native_ldap"
            and collector_method == "group_inferred"
            and target_selector != "all_collectable_computers"
        ):
            removed += 1
            continue
        kept.append(edge)

    if removed:
        graph["edges"] = kept
    return removed
