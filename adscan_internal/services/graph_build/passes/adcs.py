"""AD CS derivation: the interpreted ``ADCSESC*`` steps, re-emitted to the principal they compromise.

Moved from ``collector/persistence.py`` (bodies unchanged).
"""

from __future__ import annotations

from typing import Any

from adscan_core import telemetry
from adscan_core.directory_object_state import is_live
from adscan_core.reporting.well_known_principals import is_worthless_victim_principal
from adscan_core.rich_output import print_exception, print_info_debug, print_warning
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.adcs_detectors._common import (
    _ENROLL_RELATIONS,
    template_has_authentication_eku,
)
from adscan_internal.services.collector.models import CollectionResult, CollectorEdge
from adscan_internal.services.graph_build.edge_view import edges_of
from adscan_internal.services.graph_build.passes._common import _upsert_derived_edge
from adscan_internal.services.privileged_group_classifier import sid_rid


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


# ESC relations where the CA SIGNING KEY itself is usable by whoever controls the
# CA host: ESC12 (the YubiHSM KSP password stored in clear text in the CA host
# registry). A forged certificate can name any principal, so the derived edge
# targets Domain Admins like the SAN-arbitrary ESCs, with its own impersonation
# method so reporting does not describe it as a template enrollment.
_ESC_CA_KEY_TO_DOMAIN_ADMINS: frozenset[str] = frozenset({"ADCSESC12"})


# ESC relations whose target is the VICTIM principal itself (NOT an arbitrary
# Tier-0 account). ESC14 variant A abuses the altSecurityIdentities attribute on
# a puppet's OWN account, so a certificate maps to that puppet and the actor
# BECOMES the puppet — never an arbitrary Domain Admin. The derived edge
# therefore terminates at the puppet (the victim), and any Tier-0 reach flows
# through the victim's own MemberOf edges, not a hardcoded collapse.
_ESC_TO_VICTIM: frozenset[str] = frozenset({"ADCSESC14"})


# All ESC relations the collector re-emits as compromise-centric edges. The raw
# ``principal -> template`` detector edge for each of these is skipped as a path
# step (see ``_should_skip_attack_graph_edge``) so paths terminate at the actual
# compromise instead of at the abuse-vector template.
# ADCSESC13 is intentionally excluded until issuance-policy OID resolution lands —
# its target group is per-template and not yet derivable from raw edge notes.
_ESC_DERIVED_RELATIONS: frozenset[str] = (
    _ESC_TO_DOMAIN_ADMINS
    | _ESC_TO_DOMAIN_CONTROLLERS
    | _ESC_TO_VICTIM
    | _ESC_CA_KEY_TO_DOMAIN_ADMINS
)


_DOMAIN_ADMINS_RID = 512


_DOMAIN_CONTROLLERS_RID = 516


# Canonical display names for synthesized well-known groups (used only when the
# real node is absent from the collection result). Keyed by domain-relative RID.
_WELL_KNOWN_GROUP_LABELS: dict[int, str] = {
    _DOMAIN_ADMINS_RID: "DOMAIN ADMINS",
    _DOMAIN_CONTROLLERS_RID: "DOMAIN CONTROLLERS",
}


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


# ESC9/10 require a second precondition beyond enrollment rights: the attacker
# must hold user-write control over a puppet account AND the puppet must be able
# to enroll the vulnerable SAN-UPN template (the UPN swap authenticates AS the
# puppet via that template).
#   ESC9:  write UPN + msDS-KeyCredentialLink on puppet → shadow creds + UPN swap
#   ESC10: write UPN on puppet → weak KDC cert binding
# ESC14 variant A is DELIBERATELY NOT in this set. It is decoupled from the
# SAN-UPN puppet-enroll machinery: the attacker writes the VICTIM's
# altSecurityIdentities (a write-ACE already in the graph) and enrolls a
# client-auth certificate IT controls (a Machine-template machine account via
# MachineAccountQuota, or a directly-enrollable client-auth template) — the
# victim enrolls nothing and no vulnerable SAN-UPN template is required. Gating
# it on a SAN-UPN template + victim enrollment (the ESC9/10 logic) was a false
# negative on every domain lacking such a template. See
# ``_emit_esc14a_write_access_edges``.
_ESC_WRITER_MEDIATED: frozenset[str] = frozenset({"ADCSESC9", "ADCSESC10"})

#: Every relation the main aggregation loop of
#: ``_persist_esc_compromise_steps`` reads: any other relationship falls through
#: its ``else: continue``, so the loop streams only these.
_ESC_AGGREGATED_RELATIONS: frozenset[str] = (
    _ESC_WRITER_MEDIATED
    | _ESC_TO_DOMAIN_ADMINS
    | _ESC_CA_KEY_TO_DOMAIN_ADMINS
    | _ESC_TO_DOMAIN_CONTROLLERS
    | frozenset({"ADCSESC13"})
)


# Maximum BFS depth for group-membership expansion when checking whether a
# puppet user transitively satisfies the enroll-set of an ESC9/10/14 template.
_ESC9_BFS_MAX_DEPTH = 8


def _result_has_enterprise_ca(result: CollectionResult) -> bool:
    """Return True when the collection found at least one EnterpriseCA node."""
    return any(str(n.kind) == "EnterpriseCA" for n in result.nodes.values())


def _persist_esc_compromise_steps(
    graph: dict[str, Any],
    *,
    domain: str,
    result: CollectionResult,
    sid_to_graph_id: dict[str, str],
    edge_index: "attack_graph_service.EdgeUpsertIndex | None" = None,
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
        * ``ADCSESC12`` is sourced at the CA HOST (its administrators can use
          the CA signing key held in the YubiHSM) and targets Domain Admins
          (a certificate forged with the CA key can name any principal).
        * ``ADCSESC13`` is deferred until issuance-policy OID resolution lands —
          its target group is per-template and cannot be inferred from raw
          edge notes alone.
    """
    if edge_index is None:
        edge_index = attack_graph_service.EdgeUpsertIndex()
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
    for edge in edges_of(result.edges, _ESC9_USER_WRITE_RELATIONS):
        if edge.relation not in _ESC9_USER_WRITE_RELATIONS:
            continue
        target_node = result.nodes.get(edge.target_object_id.upper())
        if not target_node or target_node.kind != "User":
            continue
        # A deleted (tombstoned) account cannot be authenticated as, so it is
        # never a viable puppet/victim for the writer-mediated ESCs that READ
        # this index (ESC9/ESC10 UPN-swap, ESC14-A altSecurityIdentities map +
        # PKINIT-as-victim). It keeps its write ACEs in the Recycle Bin, so a
        # writer-ACE edge still lands on it, but impersonating it is impossible
        # and the LDAP write ADscan would attempt fails ``noSuchObject`` against
        # the live tree. Filter it at this SSOT index so no derived ESC edge
        # ever terminates at a deleted object (its restore-route value, if any,
        # is carried by the raw control edges that remain in the graph).
        if not is_live(target_node):
            continue
        writer_sid = edge.source_object_id.upper()
        puppet_sid = edge.target_object_id.upper()
        if writer_sid == puppet_sid:
            continue
        user_writers[writer_sid].append(puppet_sid)

    # ── Pre-pass B: index enroll-set per ESC9/10 template ────────────────────
    # esc9_template_enrollers[template_oid] = {enroller_sid, ...}
    esc9_template_enrollers: dict[str, set[str]] = defaultdict(set)
    for edge in edges_of(result.edges, _ESC_WRITER_MEDIATED):
        if edge.relation not in _ESC_WRITER_MEDIATED:
            continue
        esc9_template_enrollers[edge.target_object_id.upper()].add(
            edge.source_object_id.upper()
        )

    # ── Pre-pass C: build group-member index from MemberOf edges ─────────────
    # group_members[group_sid] = {member_sid, ...}
    group_members: dict[str, set[str]] = defaultdict(set)
    for edge in edges_of(result.edges, ("MemberOf",)):
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

    for edge in edges_of(result.edges, _ESC_AGGREGATED_RELATIONS):
        relation = edge.relation
        impersonation_method = ""
        impersonated_principal_hint = ""

        # ESC9/10 special path: derive edges from writers, not from enrollers.
        # (ESC14 variant A is handled separately by
        # ``_emit_esc14a_write_access_edges`` — it is NOT in _ESC_WRITER_MEDIATED
        # and so never enters this branch; the raw ADCSESC14 detector edge falls
        # through to the standard path's ``else: continue`` and is dropped, which
        # is correct — it is already excluded from the graph as a path step by
        # ``_should_skip_attack_graph_edge`` via ``_ESC_DERIVED_RELATIONS``.)
        if relation in _ESC_WRITER_MEDIATED:
            template_oid = edge.target_object_id.upper()
            vulnerable = _build_esc_vulnerable_resource_entry(
                edge=edge, template_lookup=template_lookup
            )
            template_dn_value = getattr(
                template_lookup.get(template_oid), "distinguished_name", None
            )

            # ESC9/10: the UPN swap authenticates as an ARBITRARY target, so any
            # writable puppet reaches Domain Admins — keep the DA collapse.
            domain_admins_id = _resolve_well_known_target(
                domain_admins_id, _DOMAIN_ADMINS_RID, relation
            )
            if not domain_admins_id:
                continue
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
                            "template_dn": template_dn_value,
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
        elif relation in _ESC_CA_KEY_TO_DOMAIN_ADMINS:
            domain_admins_id = _resolve_well_known_target(
                domain_admins_id, _DOMAIN_ADMINS_RID, relation
            )
            target_id = domain_admins_id
            impersonation_method = "forged_certificate_with_ca_signing_key"
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
            edge_index=edge_index,
            from_id=from_id,
            to_id=to_id,
            relation=relation,
            notes=notes,
        )

    # ESC14 variant A — decoupled from the SAN-UPN / victim-enroll machinery
    # above. Emitted once, driven by the write-ACE edges already in the graph
    # (``user_writers``) plus a domain-level "attacker can enroll a client-auth
    # certificate" precondition.
    created += _emit_esc14a_write_access_edges(
        graph,
        result=result,
        user_writers=user_writers,
        sid_to_graph_id=sid_to_graph_id,
        edge_index=edge_index,
    )

    return created


# Broad principals whose direct client-auth enrollment makes a certificate
# obtainable by any attacker (the MAQ-independent ESC14-A enroll route).
_BROAD_ENROLL_WELLKNOWN_SIDS: frozenset[str] = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-11",  # Authenticated Users
    }
)


_BROAD_ENROLL_RIDS: frozenset[int] = frozenset(
    {
        513,  # Domain Users
        515,  # Domain Computers
    }
)


def _sid_is_broad_principal(sid: str) -> bool:
    """Return True when ``sid`` is a broad principal any attacker belongs to."""
    normalized = str(sid or "").strip().upper()
    if normalized in _BROAD_ENROLL_WELLKNOWN_SIDS:
        return True
    return sid_rid(normalized) in _BROAD_ENROLL_RIDS


def _client_auth_template_enroller_sids(
    result: CollectionResult,
) -> dict[str, set[str]]:
    """Index enroller SIDs per CertTemplate OID from the raw enroll-ACL edges."""
    enrollers: dict[str, set[str]] = {}
    for edge in edges_of(result.edges, _ENROLL_RELATIONS):
        if edge.relation not in _ENROLL_RELATIONS:
            continue
        target_node = result.nodes.get(edge.target_object_id.upper())
        if not target_node or str(target_node.kind) != "CertTemplate":
            continue
        enrollers.setdefault(edge.target_object_id.upper(), set()).add(
            edge.source_object_id.upper()
        )
    return enrollers


def _domain_can_enroll_client_auth_cert(
    result: CollectionResult,
) -> tuple[bool, str, list[str]]:
    """Return ``(can_enroll, enroll_path_label, template_cns)`` for ESC14-A.

    ESC14 variant A needs the ATTACKER to obtain a client-authentication
    certificate IT controls (the victim enrolls nothing). This is satisfiable
    whenever ADCS is deployed AND a client-auth certificate is obtainable by a
    broad principal:

    * ``ms-DS-MachineAccountQuota`` > 0 → any authenticated principal (every
      ACE-holding writer is authenticated) can create a machine account and
      enroll the default ``Machine`` template (client-auth, Domain
      Computers-enrollable). Lab-proven on a patched DC.
    * a client-auth template that is directly enrollable by a broad well-known
      principal (Authenticated Users / Domain Users / Domain Computers /
      Everyone) when the machine-account route is closed (MAQ == 0).

    Two values come back alongside the verdict, and they are NOT interchangeable:

    * ``enroll_path_label`` is human PROSE for the report / finding narrative
      (e.g. ``"Machine template via MachineAccountQuota"``). It is sometimes a
      bare CN and sometimes a sentence, so it is NOT machine-consumable.
    * ``template_cns`` is the machine-consumable list of concrete template CNs
      this function actually RESOLVED, for execution to enroll with. It stays
      empty when no template could be named, so the executor degrades honestly
      instead of enrolling a guessed name.

    Neither is a vulnerable SAN-UPN template — variant A requires none. Returns
    ``(False, "", [])`` when ADCS is absent or no client-auth certificate is
    obtainable (so a domain with write-ACEs but no enrollable client-auth path
    emits no ESC14-A edge).
    """
    if not _result_has_enterprise_ca(result):
        return (False, "", [])
    client_auth_templates = [
        node
        for node in result.nodes.values()
        if str(node.kind) == "CertTemplate" and template_has_authentication_eku(node)
    ]
    if not client_auth_templates:
        return (False, "", [])

    maq = getattr(result.domain_policy, "machine_account_quota", None)
    if maq is not None and maq > 0:
        # Prefer the DEFAULT ``Machine`` template by exact CN over any CN that
        # merely contains "machine" (``MachineEnrollmentAgent`` is the trap: it
        # is a request-agent template, not the client-auth one a new machine
        # account enrolls), then fall back to the substring match so a renamed
        # machine template is still named.
        machine_candidates = [
            (node, cn)
            for node, cn in ((node, _template_cn(node)) for node in client_auth_templates)
            if cn and "machine" in cn.lower()
        ]
        machine_cn = next(
            (cn for _node, cn in machine_candidates if cn.lower() == "machine"),
            next((cn for _node, cn in machine_candidates), ""),
        )
        label = (
            f"{machine_cn} template via MachineAccountQuota"
            if machine_cn
            else "Machine template via MachineAccountQuota"
        )
        return (True, label, [machine_cn] if machine_cn else [])

    # MAQ == 0 / unknown: the machine-account route is closed. Fall back to the
    # client-auth templates a broad well-known principal can directly enroll.
    # EVERY such template is a usable enrollment vehicle, so all of them are
    # returned and execution lets the operator pick; the prose label keeps
    # naming the first, unchanged.
    enrollers_by_template = _client_auth_template_enroller_sids(result)
    broad_cns: list[str] = []
    for node in client_auth_templates:
        enrollers = enrollers_by_template.get(str(node.object_id).upper())
        if not enrollers:
            continue
        if any(_sid_is_broad_principal(sid) for sid in enrollers):
            cn = _template_cn(node)
            if cn and cn not in broad_cns:
                broad_cns.append(cn)
    if broad_cns:
        first = broad_cns[0]
        return (True, f"{first} template (directly enrollable)", broad_cns)
    # A broadly-enrollable template with no resolvable CN still proves the
    # precondition; it just cannot name the vehicle.
    for node in client_auth_templates:
        enrollers = enrollers_by_template.get(str(node.object_id).upper())
        if enrollers and any(_sid_is_broad_principal(sid) for sid in enrollers):
            return (True, "a directly-enrollable client-auth template", [])
    return (False, "", [])


def _template_cn(node: Any) -> str:
    """Return a CertTemplate node's enrollment CN (``cn`` property, else name)."""
    raw = str((getattr(node, "properties", None) or {}).get("cn") or node.name or "")
    return raw.split("@", 1)[0].strip()


def _emit_esc14a_write_access_edges(
    graph: dict[str, Any],
    *,
    result: CollectionResult,
    user_writers: dict[str, list[str]],
    sid_to_graph_id: dict[str, str],
    edge_index: "attack_graph_service.EdgeUpsertIndex | None" = None,
) -> int:
    """Emit ESC14 variant-A derived edges, decoupled from any SAN-UPN template.

    Variant A: a principal that can WRITE a victim's ``altSecurityIdentities``
    plants a STRONG certificate mapping to a client-auth certificate it ENROLLS
    ITSELF and PKINITs as the victim. The decisive preconditions are (a) write
    access to the victim (``user_writers`` — already a graph ACE) and (b) the
    attacker can obtain a client-auth certificate
    (``_domain_can_enroll_client_auth_cert``) — NOT a vulnerable SAN-UPN
    template and NOT the victim's own enrollment rights. The derived edge
    terminates at the VICTIM; any Tier-0 reach flows through the victim's own
    ``MemberOf`` edges (never a hardcoded Domain Admins collapse).
    """
    if edge_index is None:
        edge_index = attack_graph_service.EdgeUpsertIndex()
    can_enroll, enroll_path, enroll_templates = _domain_can_enroll_client_auth_cert(
        result
    )
    if not can_enroll:
        return 0
    created = 0
    for writer_sid, puppets in user_writers.items():
        writer_graph_id = sid_to_graph_id.get(writer_sid)
        if not writer_graph_id:
            continue
        seen_victims: set[str] = set()
        for puppet_sid in puppets:
            if puppet_sid in seen_victims:
                continue
            seen_victims.add(puppet_sid)
            victim_graph_id = sid_to_graph_id.get(puppet_sid)
            if not victim_graph_id or victim_graph_id == writer_graph_id:
                continue
            # Suppress a worthless-built-in victim at the EMISSION SSOT so the
            # graph itself stays clean and every downstream surface (the
            # adcs_esc14 finding, technical_report.json, the CLI "ADCS ESC
            # paths" tactical count) inherits the fix. ESC14-A terminates at the
            # VICTIM, so a disabled/no-privilege reserved built-in (the domain
            # Guest/DefaultAccount, BUILTIN\Guests, Anonymous Logon) is not a
            # real compromise target. The deeper root is that the finding gate
            # `_effective_target_tier_number` force-returns Tier-0 for ANY
            # adcs_esc* edge (a shortcut from the old model where the edge target
            # was a CertTemplate impersonating Tier-0); that shortcut is a
            # separate severity-modeling decision and is intentionally left
            # untouched here. This emission gate suppresses the worthless-victim
            # symptom at the SSOT regardless.
            if is_worthless_victim_principal(puppet_sid):
                continue
            puppet_node = result.nodes.get(puppet_sid)
            victim_label = puppet_sid
            puppet_resources: list[dict[str, Any]] = []
            if puppet_node and puppet_node.kind == "User":
                victim_label = puppet_node.name or puppet_sid
                puppet_resources.append(
                    {
                        "kind": "User",
                        "object_id": puppet_sid,
                        "name": puppet_node.name,
                        "distinguished_name": puppet_node.distinguished_name,
                        "role": "puppet",
                    }
                )
            notes: dict[str, Any] = {
                "collector_method": "derived_esc_compromise",
                "vulnerable_resources": puppet_resources,
                "vulnerable_resource_count": len(puppet_resources),
                "impersonation_method": "weak_explicit_mapping_altsecid",
                "impersonated_principal_hint": victim_label,
                "puppet_user_sids": [puppet_sid],
                "esc14a_enroll_path": enroll_path,
                "attack_chain": "write_altsecurityidentities_map_cert_pkinit",
            }
            # The MACHINE-CONSUMABLE companion to ``esc14a_enroll_path``, which
            # is prose and cannot be fed to a CA. ESC14-A moved its terminal to
            # the VICTIM account, so the template is no longer derivable from
            # the edge's target the way ESC1/ESC2 derive theirs — without this
            # list, execution has nothing to resolve and falls back to asking
            # the operator to TYPE a template name. Recorded only when a CN was
            # actually resolved; an unnamed vehicle records nothing rather than
            # a guess.
            if enroll_templates:
                notes["esc14a_enroll_templates"] = list(enroll_templates)
            created += _upsert_derived_edge(
                graph,
                edge_index=edge_index,
                from_id=writer_graph_id,
                to_id=victim_graph_id,
                relation="ADCSESC14",
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

    The Domain object's own SID IS the domain SID, so it answers first. Else
    the first ``S-1-5-21-`` object SID with its trailing relative identifier
    stripped. A Domain object's SID has no RID to strip: stripping it gave a
    wrong prefix whenever the domain object came first, which is the case for
    a store-backed build (objects ordered by id, the domain SID sorting before
    its principals). Returns an empty string when no domain-scoped object is
    present.
    """
    for object_id, node in result.nodes.items():
        oid_upper = str(object_id or "").upper()
        if str(getattr(node, "kind", "")) == "Domain" and oid_upper.startswith("S-1-5-21-"):
            return oid_upper
    for object_id, node in result.nodes.items():
        oid_upper = str(object_id or "").upper()
        if not oid_upper.startswith("S-1-5-21-") or str(getattr(node, "kind", "")) == "Domain":
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
