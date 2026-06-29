"""Offline inventory persistence for native collector output."""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    CollectorNode,
    DomainPolicy,
    PasswordComplianceReport,
    PasswordSettingsObject,
)
from adscan_internal.workspaces import domain_subpath, write_json_file

INVENTORY_SCHEMA_VERSION = "inventory-1.0"

_NODE_KIND_TO_FILE: dict[str, str] = {
    "User": "users.json",
    "Group": "groups.json",
    "Computer": "computers.json",
    "OU": "ous.json",
    "GPO": "gpos.json",
    "Container": "containers.json",
    "ForeignSecurityPrincipal": "foreign_security_principals.json",
    "CertTemplate": "adcs_templates.json",
    "EnterpriseCA": "adcs_enterprise_cas.json",
    "RootCA": "adcs_root_cas.json",
    "AIACA": "adcs_aia_cas.json",
    "NTAuthStore": "adcs_ntauth_stores.json",
    "Domain": "domains.json",
}

_RELATION_TO_FILE: dict[str, str] = {
    "MemberOf": "memberships.json",
    "GPLink": "gpo_links.json",
    "TrustedBy": "trusts.json",
    "ADCSESC1": "adcs_attack_steps.json",
    "ADCSESC2": "adcs_attack_steps.json",
    "ADCSESC3": "adcs_attack_steps.json",
    "ADCSESC4": "adcs_attack_steps.json",  # write on template
    "ADCSESC5": "adcs_attack_steps.json",  # write on PKI container objects
    "ADCSESC6": "adcs_attack_steps.json",
    "ADCSESC7": "adcs_attack_steps.json",
    "ADCSESC8": "adcs_attack_steps.json",
    "ADCSESC9": "adcs_attack_steps.json",
    "ADCSESC10": "adcs_attack_steps.json",
    "ADCSESC11": "adcs_attack_steps.json",
    "ADCSESC13": "adcs_attack_steps.json",
    "ADCSESC14": "adcs_attack_steps.json",
    "ADCSESC15": "adcs_attack_steps.json",
    "ADCSESC16": "adcs_attack_steps.json",
    "ADCSESC17": "adcs_attack_steps.json",
}
_DCSYNC_RELATIONS: frozenset[str] = frozenset(
    {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet"}
)

_DEFAULT_EDGE_FILE = "acls.json"


class CollectorInventoryPersistence:
    """Persist complete collector inventory into query-oriented JSON files."""

    def persist(
        self,
        shell: object,
        *,
        domain: str,
        result: CollectionResult,
    ) -> dict[str, int]:
        """Persist inventory files for one collector result.

        Args:
            shell: Runtime shell used to resolve workspace paths.
            domain: Domain being persisted.
            result: Complete collector output.

        Returns:
            File/category counters useful for logs and tests.
        """
        generated_at = datetime.now(timezone.utc).isoformat()
        inventory_dir = _inventory_dir(shell, domain)
        os.makedirs(inventory_dir, exist_ok=True)

        principal_class_by_id, principal_tier_by_id = (
            _classify_principals_by_membership(result)
        )
        node_records_by_file = _group_node_records(
            result, principal_class_by_id, principal_tier_by_id
        )
        edge_records_by_file = _group_edge_records(result)

        files_written = 0
        object_count = 0
        edge_count = 0
        index_files: dict[str, dict[str, Any]] = {}

        for filename, records in sorted(node_records_by_file.items()):
            _write_inventory_file(
                inventory_dir,
                filename,
                domain=domain,
                generated_at=generated_at,
                record_type="nodes",
                records=records,
            )
            files_written += 1
            object_count += len(records)
            index_files[filename] = {"type": "nodes", "count": len(records)}

        for filename, records in sorted(edge_records_by_file.items()):
            _write_inventory_file(
                inventory_dir,
                filename,
                domain=domain,
                generated_at=generated_at,
                record_type="edges",
                records=records,
            )
            files_written += 1
            edge_count += len(records)
            index_files[filename] = {"type": "edges", "count": len(records)}

        # Persist the DomainPolicy snapshot when the collector captured it.
        # This unblocks the web app's Password posture card — the data was
        # collected for the spray-policy heuristics but never made it past
        # the collector's in-process state. Writing it as one inventory
        # file keeps the workspace shape consistent with every other
        # collector artefact.
        if isinstance(result.domain_policy, DomainPolicy):
            _write_domain_policy_file(
                inventory_dir,
                domain=domain,
                generated_at=generated_at,
                policy=result.domain_policy,
            )
            files_written += 1
            index_files["domain_policy.json"] = {
                "type": "policy",
                "count": 1,
            }

        # PSOs (fine-grained password policies). One file per workspace
        # listing every PSO under the Password Settings Container — can
        # be empty (no PSO configured) which is the common case.
        if result.psos:
            _write_psos_file(
                inventory_dir,
                domain=domain,
                generated_at=generated_at,
                psos=result.psos,
            )
            files_written += 1
            index_files["password_settings_objects.json"] = {
                "type": "psos",
                "count": len(result.psos),
            }

        # Password compliance snapshot — per-user diagnostic of which
        # users are likely outside the current policy because their
        # pwdLastSet predates the last modification of the policy
        # object that governs them. Consumed by the report builder,
        # the web product and password-spraying candidate selection.
        if isinstance(result.password_compliance, PasswordComplianceReport):
            _write_password_compliance_file(
                inventory_dir,
                domain=domain,
                generated_at=generated_at,
                report=result.password_compliance,
            )
            files_written += 1
            index_files["password_compliance.json"] = {
                "type": "password_compliance",
                "count": result.password_compliance.users_total,
            }

        index = {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "domain": domain,
            "generated_at": generated_at,
            "files": index_files,
            "totals": {
                "files": files_written,
                "nodes": object_count,
                "edges": edge_count,
            },
        }
        write_json_file(os.path.join(inventory_dir, "index.json"), index)
        return {
            "inventory_files": files_written + 1,
            "inventory_nodes": object_count,
            "inventory_edges": edge_count,
        }


def _inventory_dir(shell: object, domain: str) -> str:
    workspace_cwd = (
        shell._get_workspace_cwd()  # noqa: SLF001
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", "")
    )
    domains_dir = getattr(shell, "domains_dir", "domains")
    return domain_subpath(workspace_cwd, domains_dir, domain, "inventory")


def _classify_principals_by_membership(
    result: CollectionResult,
) -> tuple[dict[str, str], dict[str, str]]:
    """Map each User/Computer object_id to its privilege class AND tier.

    Walks the ``MemberOf`` edges to compute every group a principal belongs to
    transitively (nested groups included, with a cycle guard), then runs the
    SSOT per-principal classifiers in ``compromise_class.py``
    (:func:`classify_principal_by_groups` for the compromise class,
    :func:`privilege_tier_for_principal` / :func:`privilege_tier_for_computer`
    for the ESAE privilege tier — all share ONE set of group lists, never
    mirrored here).

    Both ``User`` and ``Computer`` nodes are classified the SAME way — by their
    own (transitive) group memberships. The decisive consequence: ``BRAAVOS$``,
    a member of **Cert Publishers** (RID 517), grades Tier 0 escalation-capable,
    and ``MEEREEN$``, a member of **Domain Controllers** (RID 516), grades Tier 0
    direct — generically, by membership, no per-role (ADCS/Exchange) special
    case. The computer membership graph stores groups as SIDs, so the group
    tokens fed to the classifier are the group nodes' SIDs (object_ids) and the
    RID-matching path in ``classify_principal_by_groups`` is the load-bearing
    one; resolved names are added too (belt-and-suspenders).

    Two parallel axes are stamped (see CLAUDE.md § Nomenclature Standard,
    "Two orthogonal axes"):

    * ``privilege_class`` — the :class:`CompromiseClass` ``.value`` (Users only;
      computers carry the tier, not a buyer-facing principal class).
    * ``privilege_tier`` — the :class:`PrivilegeTier` ``.value``
      (``tier0_direct`` / ``tier0_escalation_capable`` / ``tier1`` for computers /
      ``tier2``).

    Both are kept compact: a default principal (NONE / Tier 2) carries neither
    field, so a missing field reads as "Standard / Tier 2".

    Returns:
        A ``(class_by_id, tier_by_id)`` pair of mappings keyed by upper-cased
        object_id. Tier-2 principals are omitted from ``tier_by_id``; NONE
        principals from ``class_by_id``.
    """
    # Lazy import keeps the collector module import-light and avoids a cycle
    # (compromise_class imports edge_kind, not the collector).
    from adscan_internal.services.collector.well_known_sids import (
        _DC_PRIMARY_GROUP_RIDS,
        _node_primary_group_id,
    )
    from adscan_internal.services.compromise_class import (
        CompromiseClass,
        PrivilegeTier,
        classify_principal_by_groups,
        privilege_tier_for_computer,
        privilege_tier_for_principal,
    )

    # group object_id (upper) → set of parent group object_ids (upper) it is a
    # MemberOf, so we can expand a principal's groups transitively.
    parents_by_id: dict[str, set[str]] = defaultdict(set)
    for edge in result.edges:
        if str(edge.relation or "").strip() != "MemberOf":
            continue
        src = str(edge.source_object_id or "").upper()
        dst = str(edge.target_object_id or "").upper()
        if src and dst:
            parents_by_id[src].add(dst)

    def _expand_groups(start: str) -> set[str]:
        """Return the upper-cased object_ids of every group reached from start."""
        seen: set[str] = set()
        stack: list[str] = list(parents_by_id.get(start, ()))
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(parents_by_id.get(current, ()))
        return seen

    def _group_tokens(group_oids: set[str]) -> list[str]:
        """Return the group membership tokens for the classifier.

        Each group's SID (its object_id) is always included — the RID-matching
        path classifies SID-only memberships (computers store groups as SIDs).
        The resolved name is added when available, so name-only groups
        (DnsAdmins / Exchange) still classify.
        """
        tokens: list[str] = []
        for goid in group_oids:
            tokens.append(goid)
            grp = result.nodes.get(goid)
            if grp is not None and grp.name:
                tokens.append(grp.name)
        return tokens

    classes: dict[str, str] = {}
    tiers: dict[str, str] = {}
    for node in result.nodes.values():
        kind = str(node.kind)
        if kind not in ("User", "Computer"):
            continue
        oid = str(node.object_id or "").upper()
        if not oid:
            continue
        tokens = _group_tokens(_expand_groups(oid))

        if kind == "User":
            cls = classify_principal_by_groups(tokens, sid=node.object_id)
            tier = privilege_tier_for_principal(tokens, sid=node.object_id)
            # Only stamp a non-default class/tier; low-priv principals carry
            # NONE / Tier 2 implicitly so the artifact stays compact.
            if cls is not CompromiseClass.NONE:
                classes[oid] = cls.value
            if tier is not PrivilegeTier.TIER2:
                tiers[oid] = tier.value
            continue

        # Computer — group-membership-driven tier (generic; ANY Tier 0 group
        # classifies it). Role signals come from node properties: DC fast-path
        # via primaryGroupID (516/521), member-server vs workstation via the OS
        # string, and the highvalue tag as the degraded last-resort fallback.
        is_dc = _node_primary_group_id(node) in _DC_PRIMARY_GROUP_RIDS
        os_str = str(node.properties.get("os") or "").lower()
        tier = privilege_tier_for_computer(
            group_names=tokens,
            sid=node.object_id,
            is_dc=is_dc,
            is_tier0_asset=bool(node.highvalue),
            is_server=_SERVER_OS_MARKER in os_str,
        )
        if tier is not PrivilegeTier.TIER2:
            tiers[oid] = tier.value
    return classes, tiers


def _group_node_records(
    result: CollectionResult,
    principal_class_by_id: dict[str, str] | None = None,
    principal_tier_by_id: dict[str, str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    # Both axes are derived from group membership in ONE place
    # (:func:`_classify_principals_by_membership`). Computers are classified the
    # same way as users — by their (transitive) group SIDs — so an ADCS CA host
    # (member of Cert Publishers, RID 517) grades Tier 0 escalation-capable and a
    # DC (member of Domain Controllers, RID 516) grades Tier 0 direct, generically
    # by membership with no per-role special case. When the caller did not supply
    # the maps (direct unit-test entry), derive them here so this stays the SSOT.
    if principal_class_by_id is None or principal_tier_by_id is None:
        derived_classes, derived_tiers = _classify_principals_by_membership(result)
        principal_class_by_id = (
            principal_class_by_id if principal_class_by_id is not None else derived_classes
        )
        principal_tier_by_id = (
            principal_tier_by_id if principal_tier_by_id is not None else derived_tiers
        )
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in result.nodes.values():
        if node.properties.get("well_known_sid"):
            filename = "well_known_principals.json"
        else:
            filename = _NODE_KIND_TO_FILE.get(str(node.kind), "objects.json")
        record = _node_inventory_record(node)
        oid_upper = str(node.object_id or "").upper()
        cls_value = principal_class_by_id.get(oid_upper)
        if cls_value:
            record["privilege_class"] = cls_value
        # Axis 1 — Privilege Tier (ESAE). Users and Computers both get the
        # membership-derived tier from the single classifier above.
        tier_value = principal_tier_by_id.get(oid_upper)
        if tier_value:
            record["privilege_tier"] = tier_value
        grouped[filename].append(record)
    return {
        name: sorted(records, key=_record_sort_key) for name, records in grouped.items()
    }


# OS strings that mark a member server (not a workstation). AD exposes the role
# only through the ``operatingSystem`` string; "Server" is the canonical marker
# Microsoft uses for every server SKU.
_SERVER_OS_MARKER = "server"


def _group_edge_records(result: CollectionResult) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in result.edges:
        filename = _edge_inventory_filename(edge)
        grouped[filename].append(_edge_inventory_record(edge, result))
    return {
        name: sorted(records, key=_record_sort_key) for name, records in grouped.items()
    }


def _edge_inventory_filename(edge: CollectorEdge) -> str:
    relation = str(edge.relation or "").strip()
    if relation in _RELATION_TO_FILE:
        return _RELATION_TO_FILE[relation]
    if relation in _DCSYNC_RELATIONS:
        return "dcsync_rights.json"
    if str(edge.method or "").strip().lower() == "acl":
        return _DEFAULT_EDGE_FILE
    return "relationships.json"


def _node_inventory_record(node: CollectorNode) -> dict[str, Any]:
    payload = node.to_graph_payload()
    properties = (
        payload.get("properties") if isinstance(payload.get("properties"), dict) else {}
    )
    return {
        "object_id": node.object_id,
        "kind": node.kind,
        "name": node.name,
        "domain": node.domain,
        "samaccountname": node.samaccountname,
        "distinguished_name": node.distinguished_name,
        "enabled": node.enabled,
        "highvalue": node.highvalue,
        "properties": properties,
    }


def _edge_inventory_record(
    edge: CollectorEdge,
    result: CollectionResult,
) -> dict[str, Any]:
    source = result.nodes.get(edge.source_object_id.upper())
    target = result.nodes.get(edge.target_object_id.upper())
    return {
        "source_object_id": edge.source_object_id,
        "source_name": source.name if source else "",
        "source_kind": source.kind if source else "",
        "target_object_id": edge.target_object_id,
        "target_name": target.name if target else "",
        "target_kind": target.kind if target else "",
        "relation": edge.relation,
        "source": edge.source,
        "method": edge.method,
        "notes": edge.notes,
    }


def _write_inventory_file(
    inventory_dir: str,
    filename: str,
    *,
    domain: str,
    generated_at: str,
    record_type: str,
    records: list[dict[str, Any]],
) -> None:
    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "domain": domain,
        "generated_at": generated_at,
        "record_type": record_type,
        "count": len(records),
        "records": records,
    }
    write_json_file(os.path.join(inventory_dir, filename), payload)


def _write_domain_policy_file(
    inventory_dir: str,
    *,
    domain: str,
    generated_at: str,
    policy: DomainPolicy,
) -> None:
    """Persist the DomainPolicy snapshot as ``domain_policy.json``.

    Shape mirrors ``DomainPolicy`` exactly so the backend parser can
    rebuild the dataclass with no ambiguity. ``None`` values stay
    ``null`` in JSON — they distinguish "policy bit not set" from
    "policy bit explicitly zero" (lockoutThreshold=0 means lockout
    disabled, very different from None=not collected).
    """
    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "domain": domain,
        "generated_at": generated_at,
        "record_type": "policy",
        "policy": {
            "min_pwd_length": policy.min_pwd_length,
            "lockout_threshold": policy.lockout_threshold,
            "lockout_window_minutes": policy.lockout_window_minutes,
            "max_pwd_age_days": policy.max_pwd_age_days,
            "pwd_history_length": policy.pwd_history_length,
            "machine_account_quota": policy.machine_account_quota,
            # ``None`` distinguishes "attribute unreadable" from "explicitly
            # disabled"; downstream renderers must treat None as unknown.
            "complexity_enabled": policy.complexity_enabled,
            # ISO timestamp of the most recent password-policy attribute
            # change, derived from msDS-ReplAttributeMetaData. None when
            # the attribute was unreadable.
            "pwd_policy_last_changed": policy.pwd_policy_last_changed,
            # Per-attribute breakdown: list of [attr, iso_ts, version].
            # version==1 means set at provisioning, never explicitly changed.
            "pwd_attrs_when_changed": [
                list(t) for t in policy.pwd_attrs_when_changed
            ],
        },
    }
    write_json_file(os.path.join(inventory_dir, "domain_policy.json"), payload)


def _write_psos_file(
    inventory_dir: str,
    *,
    domain: str,
    generated_at: str,
    psos: list[PasswordSettingsObject],
) -> None:
    """Persist all PSOs as ``password_settings_objects.json``.

    Shape mirrors :class:`PasswordSettingsObject` so the backend parser
    rebuilds the dataclass with no ambiguity. ``applies_to`` is a list
    of trustee DNs (the principals targeted by each PSO).
    """
    records = [
        {
            "name": pso.name,
            "distinguished_name": pso.distinguished_name,
            "precedence": pso.precedence,
            "min_pwd_length": pso.min_pwd_length,
            "max_pwd_age_days": pso.max_pwd_age_days,
            "min_pwd_age_days": pso.min_pwd_age_days,
            "lockout_threshold": pso.lockout_threshold,
            "lockout_observation_window_minutes": pso.lockout_observation_window_minutes,
            "lockout_duration_minutes": pso.lockout_duration_minutes,
            "pwd_history_length": pso.pwd_history_length,
            "complexity_enabled": pso.complexity_enabled,
            "reversible_encryption_enabled": pso.reversible_encryption_enabled,
            "applies_to": list(pso.applies_to),
            "pwd_policy_last_changed": pso.pwd_policy_last_changed,
            "pwd_attrs_when_changed": [list(t) for t in pso.pwd_attrs_when_changed],
        }
        for pso in psos
    ]
    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "domain": domain,
        "generated_at": generated_at,
        "record_type": "psos",
        "count": len(records),
        "psos": records,
    }
    write_json_file(
        os.path.join(inventory_dir, "password_settings_objects.json"), payload
    )


def _write_password_compliance_file(
    inventory_dir: str,
    *,
    domain: str,
    generated_at: str,
    report: PasswordComplianceReport,
) -> None:
    """Persist the password compliance snapshot as
    ``password_compliance.json``.

    Shape mirrors :class:`PasswordComplianceReport` exactly. The full
    list of enabled-user rows is included — downstream consumers can
    re-filter offline (e.g. password spraying may want only entries
    with ``pwd_predates_policy=True``; the PDF report may want admin
    rows first; the web UI may show paginated full data). Storing the
    full table once avoids re-running the analysis from each surface.
    """
    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "domain": domain,
        "generated_at": generated_at,
        "record_type": "password_compliance",
        "policy_pwd_last_changed": report.policy_pwd_last_changed,
        "policy_never_modified": report.policy_never_modified,
        "policy_pwd_attrs": [list(t) for t in report.policy_pwd_attrs],
        "psos_count": report.psos_count,
        "totals": {
            "users": report.users_total,
            "users_with_predates_policy": report.users_with_predates_policy,
            "users_with_over_max_age": report.users_with_over_max_age,
            "users_with_never_expires": report.users_with_never_expires,
        },
        "entries": [
            {
                "samaccountname": entry.samaccountname,
                "object_id": entry.object_id,
                "distinguished_name": entry.distinguished_name,
                "enabled": entry.enabled,
                "is_admin_like": entry.is_admin_like,
                "pwd_last_set_filetime": entry.pwd_last_set_filetime,
                "pwd_last_set_iso": entry.pwd_last_set_iso,
                "pwd_age_days": entry.pwd_age_days,
                "applied_policy_name": entry.applied_policy_name,
                "applied_policy_dn": entry.applied_policy_dn,
                "applied_policy_when_changed": entry.applied_policy_when_changed,
                "pwd_predates_policy": entry.pwd_predates_policy,
                "pwd_over_max_age": entry.pwd_over_max_age,
                "pwd_never_expires": entry.pwd_never_expires,
                "risk_level": entry.risk_level,
                "notes": list(entry.notes),
            }
            for entry in report.entries
        ],
    }
    write_json_file(
        os.path.join(inventory_dir, "password_compliance.json"), payload
    )


def _record_sort_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(record.get("name") or record.get("source_name") or "").casefold(),
        str(record.get("relation") or "").casefold(),
        str(record.get("target_name") or record.get("object_id") or "").casefold(),
    )
