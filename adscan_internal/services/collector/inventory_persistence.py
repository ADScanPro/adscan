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

        principal_class_by_id, principal_tier_by_id, principal_tier_basis_by_id = (
            _classify_principals_by_membership(result)
        )
        node_records_by_file = _group_node_records(
            result,
            principal_class_by_id,
            principal_tier_by_id,
            principal_tier_basis_by_id,
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


# Well-known SIDs whose membership is the ENTIRE authenticated / user population.
# A member server that lets one of these interactively log on (a CanRDP edge) is
# an RDS / Citrix / Terminal server — a Tier 2 client despite the "Server" OS
# (the current Microsoft AD DS tier model's #1 documented Tier-1 misclassification).
# Deliberately NOT here: Remote Desktop Users (S-1-5-32-555) — an intentionally
# SCOPED group, not the broad population; treating it as broad would downgrade any
# server with a normal RDS-admin group. Domain Users is matched by its -513 RID
# suffix (domain-relative). Domain Computers (-515) is excluded (a computer logon
# is not an interactive user session).
_BROAD_LOGON_WELL_KNOWN_SIDS: frozenset[str] = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-11",  # Authenticated Users
        "S-1-5-32-545",  # BUILTIN\Users
    }
)


def _sid_is_broad_logon_population(sid: str | None) -> bool:
    """Return whether a SID is the whole authenticated / standard-user population.

    ``True`` for Everyone (S-1-1-0), Authenticated Users (S-1-5-11), BUILTIN\\Users
    (S-1-5-32-545) and Domain Users (any ``…-513``). These are the broad
    populations whose interactive-logon right marks an RDS / Citrix / Terminal
    server. Not broad: a scoped group like Remote Desktop Users.
    """
    if not sid:
        return False
    sid_upper = str(sid).strip().upper()
    if sid_upper in _BROAD_LOGON_WELL_KNOWN_SIDS:
        return True
    # Domain Users is domain-relative: S-1-5-21-<domain>-513.
    return sid_upper.endswith("-513")


def _computer_controls_tier0_asset(
    computer_oid: str,
    *,
    admin_grant_targets: "frozenset[str] | set[str]",
    deleg_targets: "frozenset[str] | set[str]",
    result: CollectionResult,
    member_of_by_src: dict[str, set[str]],
) -> bool:
    """Return whether a member server CONTROLS a Tier 0 asset (→ it is Tier 0).

    The detectable form of Microsoft's "these servers are Tier 0, NOT Tier 1"
    exclusion: a jump server used to reach a DC, a hypervisor of a Tier-0 VM, or a
    backup / EDR / monitoring agent with Tier-0 control all show up in the graph as
    the server holding an admin/exec/delegation edge whose TARGET is a Tier 0
    asset. We check two edge families the collector reliably produces:

    * ``AdminTo`` / ``SQLAdmin`` (admin-grant) from the server onto a Tier 0 host —
      e.g. a backup or management server that is local admin on a DC.
    * ``AllowedToDelegate`` from the server to a Tier 0 host's service —
      constrained delegation toward a DC is a classic jump-server signal.

    A target is "Tier 0" when it is a DC (primaryGroupID 516/521), carries the
    ``highvalue`` tag, or is a member of a Tier 0 group — the same deterministic
    signals the computer tier itself is graded on, so this never depends on the
    order computers are processed in.

    NOT detectable from collected LDAP/graph data (documented, deliberately NOT
    guessed into Tier 0): a hypervisor whose Tier-0 control is only at the
    virtualization layer with no AD edge, or an EDR/backup agent whose Tier-0
    reach is through its own management console rather than an AD admin grant.
    Where the control does not surface as an AD edge, the server conservatively
    stays Tier 1 (never a false Tier 0).
    """
    from adscan_internal.services.collector.well_known_sids import (  # noqa: PLC0415
        _DC_PRIMARY_GROUP_RIDS,
        _node_primary_group_id,
    )
    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        PrivilegeTier,
        classify_principal_by_groups,
    )

    def _target_is_tier0(target_oid: str) -> bool:
        target = result.nodes.get(target_oid) or result.nodes.get(
            str(target_oid).upper()
        )
        if target is None:
            return False
        # A server controlling ITSELF is not a Tier-0 control signal.
        if str(target.object_id or "").upper() == str(computer_oid).upper():
            return False
        if _node_primary_group_id(target) in _DC_PRIMARY_GROUP_RIDS:
            return True
        if bool(getattr(target, "highvalue", False)):
            return True
        # Tier-0 group membership (SID token = its own object_id; RID path is the
        # load-bearing one). Only the target's DIRECT group SIDs are needed — a
        # Tier-0 group SID classifies regardless of nesting. Read from the
        # pre-built MemberOf index (no per-target edge re-scan).
        direct_groups = member_of_by_src.get(str(target_oid).upper())
        if not direct_groups:
            return False
        target_groups: list[str] = []
        for gid in direct_groups:
            target_groups.append(gid)
            grp = result.nodes.get(gid)
            if grp is not None and grp.name:
                target_groups.append(grp.name)
        cls = classify_principal_by_groups(
            target_groups, sid=target.object_id
        )
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            _COMPROMISE_CLASS_TO_PRIVILEGE_TIER,
        )

        tier = _COMPROMISE_CLASS_TO_PRIVILEGE_TIER.get(cls, PrivilegeTier.TIER2)
        return tier.is_tier0

    for target_oid in set(admin_grant_targets) | set(deleg_targets):
        if _target_is_tier0(target_oid):
            return True
    return False


def _classify_principals_by_membership(
    result: CollectionResult,
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Map each User/Computer object_id to its privilege class, tier AND tier-basis.

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

    **Tier 1 is refined with graph-edge signals (axis 1, GRANT tier).** The
    membership pass gives the deterministic Tier 0 boundary; two heuristic
    refinements then apply, grounded in the current Microsoft AD DS tier model:

    * **Computers (PART A)** — a member server (base Tier 1) is corrected via
      :func:`refine_server_privilege_tier`: to **Tier 0** when it controls a
      Tier 0 asset (jump-server-to-DC / hypervisor-of-Tier0 / EDR-over-Tier0,
      detected from an outbound admin/exec/delegation edge onto a Tier 0 node),
      to **Tier 2** when a broad user population can log on interactively
      (RDS / Citrix, detected from a broad-group ``CanRDP`` edge into it), and its
      Tier-1 confidence is strengthened by an application-class SPN
      (MSSQL / Exchange / SharePoint).
    * **Principals (PART B)** — a principal's effective tier is floored by the
      tier of the computers it ADMINISTERS BY GRANT (``AdminTo`` / ``SQLAdmin`` —
      full control, NOT session/reach), via
      :func:`privilege_tier_for_principal_with_admin_assets`. So an account that
      is local admin over a Tier-1 app server and holds no Tier-0 group is Tier 1.
      PART A runs FIRST so PART B consumes CORRECTED computer tiers (an RDS box
      mislabelled Tier 1, or a jump server that is really Tier 0, must not
      mis-floor its admins).

    Three parallel axes are stamped (see CLAUDE.md § Nomenclature Standard,
    "Two orthogonal axes"):

    * ``privilege_class`` — the :class:`CompromiseClass` ``.value`` (Users only;
      computers carry the tier, not a buyer-facing principal class).
    * ``privilege_tier`` — the :class:`PrivilegeTier` ``.value``
      (``tier0_direct`` / ``tier0_escalation_capable`` / ``tier1`` for computers /
      ``tier2``).
    * ``privilege_tier_basis`` — the :class:`TierBasis` ``.value`` recording HOW a
      COMPUTER's tier was inferred (``tier0_group`` deterministic /
      ``server_heuristic`` / ``app_spn`` / ``rds_downgrade`` / ``tier0_control``),
      so the client report can declare Tier 1 as a heuristic. Computers only.

    All are kept compact: a default principal (NONE / Tier 2) carries no
    class/tier field, so a missing field reads as "Standard / Tier 2".

    Returns:
        A ``(class_by_id, tier_by_id, tier_basis_by_id)`` triple of mappings keyed
        by upper-cased object_id. Tier-2 principals are omitted from
        ``tier_by_id``; NONE principals from ``class_by_id``; only computers with
        a resolved server basis appear in ``tier_basis_by_id``.
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
        privilege_tier_for_principal_with_admin_assets,
        refine_server_privilege_tier,
        relation_is_admin_grant,
        spns_indicate_app_server,
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

    # ── Edge-signal indices for the Tier-1 refinements (PART A + PART B) ──────
    # Built once from result.edges so the per-node passes are O(1) lookups.
    #   admin_grant_targets_by_src: principal/computer -> {computer it ADMINISTERS
    #       BY GRANT (AdminTo/SQLAdmin)} — feeds PART B (principal floor) and
    #       PART A's controls-Tier0 signal (a server admin OVER a Tier 0 asset).
    #   broad_logon_targets:  {computer a BROAD user population can CanRDP into} —
    #       feeds PART A's RDS/Citrix downgrade.
    #   deleg_targets_by_src: computer -> {computer it can delegate TO
    #       (AllowedToDelegate)} — a jump-server-to-DC / hypervisor signal.
    admin_grant_targets_by_src: dict[str, set[str]] = defaultdict(set)
    broad_logon_targets: set[str] = set()
    deleg_targets_by_src: dict[str, set[str]] = defaultdict(set)
    for edge in result.edges:
        relation = str(edge.relation or "").strip()
        src = str(edge.source_object_id or "").upper()
        dst = str(edge.target_object_id or "").upper()
        if not src or not dst:
            continue
        if relation_is_admin_grant(relation):
            admin_grant_targets_by_src[src].add(dst)
        elif relation == "CanRDP" and _sid_is_broad_logon_population(src):
            broad_logon_targets.add(dst)
        elif relation == "AllowedToDelegate":
            deleg_targets_by_src[src].add(dst)

    def _tier_of_node(oid_upper: str) -> "PrivilegeTier | None":
        """Return the resolved computer/principal tier of a node id, if known."""
        return _COMPUTER_TIER_CACHE.get(oid_upper)

    classes: dict[str, str] = {}
    tiers: dict[str, str] = {}
    tier_basis: dict[str, str] = {}
    # Resolved PrivilegeTier per node id — populated in the computer pass and read
    # in the principal pass (PART B floors a principal by the tier of the computers
    # it administers). Local cache, never leaks out of this call.
    _COMPUTER_TIER_CACHE: dict[str, PrivilegeTier] = {}

    # ── PASS 1 — Computers (PART A): membership tier, then graph refinement ──
    # Runs BEFORE the principal pass so PART B consumes CORRECTED computer tiers.
    for node in result.nodes.values():
        if str(node.kind) != "Computer":
            continue
        oid = str(node.object_id or "").upper()
        if not oid:
            continue
        tokens = _group_tokens(_expand_groups(oid))
        # Group-membership-driven base tier (generic; ANY Tier 0 group classifies
        # it). Role signals: DC fast-path via primaryGroupID (516/521),
        # member-server vs workstation via the OS string, highvalue as the
        # degraded last-resort fallback.
        is_dc = _node_primary_group_id(node) in _DC_PRIMARY_GROUP_RIDS
        os_str = str(node.properties.get("os") or "").lower()
        base_tier = privilege_tier_for_computer(
            group_names=tokens,
            sid=node.object_id,
            is_dc=is_dc,
            is_tier0_asset=bool(node.highvalue),
            is_server=_SERVER_OS_MARKER in os_str,
        )
        # Graph-signal refinement of a member-server (Tier 1) verdict. Tier 0 and
        # Tier 2 bases are returned unchanged (Tier 0 stays deterministic).
        controls_tier0 = _computer_controls_tier0_asset(
            oid,
            admin_grant_targets=admin_grant_targets_by_src.get(oid, frozenset()),
            deleg_targets=deleg_targets_by_src.get(oid, frozenset()),
            result=result,
            member_of_by_src=parents_by_id,
        )
        spns = node.properties.get("serviceprincipalnames")
        refined_tier, basis = refine_server_privilege_tier(
            base_tier,
            controls_tier0_asset=controls_tier0,
            has_broad_interactive_logon=oid in broad_logon_targets,
            has_app_server_spn=spns_indicate_app_server(
                spns if isinstance(spns, (list, tuple)) else None
            ),
        )
        _COMPUTER_TIER_CACHE[oid] = refined_tier
        if refined_tier is not PrivilegeTier.TIER2:
            tiers[oid] = refined_tier.value
        if basis is not None:
            tier_basis[oid] = basis

    # ── PASS 2 — Users (PART B): membership tier floored by administered assets ─
    for node in result.nodes.values():
        if str(node.kind) != "User":
            continue
        oid = str(node.object_id or "").upper()
        if not oid:
            continue
        tokens = _group_tokens(_expand_groups(oid))
        cls = classify_principal_by_groups(tokens, sid=node.object_id)
        membership_tier = privilege_tier_for_principal(tokens, sid=node.object_id)
        # Floor the membership tier by the tier of the computers this principal
        # ADMINISTERS BY GRANT (AdminTo/SQLAdmin). Session/reach edges are excluded
        # at index-build time (only admin-grant relations enter the index), so a
        # CanRDP/SQLAccess never promotes the tier (that is axis-2 reach).
        administered_tiers = [
            t
            for t in (
                _tier_of_node(target)
                for target in admin_grant_targets_by_src.get(oid, ())
            )
            if t is not None
        ]
        effective_tier = privilege_tier_for_principal_with_admin_assets(
            membership_tier, administered_tiers
        )
        # Only stamp a non-default class/tier; low-priv principals carry NONE /
        # Tier 2 implicitly so the artifact stays compact.
        if cls is not CompromiseClass.NONE:
            classes[oid] = cls.value
        if effective_tier is not PrivilegeTier.TIER2:
            tiers[oid] = effective_tier.value
    return classes, tiers, tier_basis


def _group_node_records(
    result: CollectionResult,
    principal_class_by_id: dict[str, str] | None = None,
    principal_tier_by_id: dict[str, str] | None = None,
    principal_tier_basis_by_id: dict[str, str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    # Both axes are derived from group membership in ONE place
    # (:func:`_classify_principals_by_membership`). Computers are classified the
    # same way as users — by their (transitive) group SIDs — so an ADCS CA host
    # (member of Cert Publishers, RID 517) grades Tier 0 escalation-capable and a
    # DC (member of Domain Controllers, RID 516) grades Tier 0 direct, generically
    # by membership with no per-role special case. When the caller did not supply
    # the maps (direct unit-test entry), derive them here so this stays the SSOT.
    if (
        principal_class_by_id is None
        or principal_tier_by_id is None
        or principal_tier_basis_by_id is None
    ):
        derived_classes, derived_tiers, derived_basis = (
            _classify_principals_by_membership(result)
        )
        principal_class_by_id = (
            principal_class_by_id if principal_class_by_id is not None else derived_classes
        )
        principal_tier_by_id = (
            principal_tier_by_id if principal_tier_by_id is not None else derived_tiers
        )
        principal_tier_basis_by_id = (
            principal_tier_basis_by_id
            if principal_tier_basis_by_id is not None
            else derived_basis
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
        # Axis-1 confidence — HOW a computer's tier was inferred (heuristic
        # Tier 1 vs deterministic Tier 0), so the client report can declare it.
        basis_value = principal_tier_basis_by_id.get(oid_upper)
        if basis_value:
            record["privilege_tier_basis"] = basis_value
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
