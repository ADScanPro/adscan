"""Local graph query service used by ADscan's native attack graph runtime."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from adscan_internal.services.attack_graph_service import load_attack_graph
from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind
from adscan_internal.services.graph_queries import (
    get_admincount_users,
    get_asreproastable_users,
    get_enabled_computers,
    get_enabled_users,
    get_high_value_users,
    get_kerberoastable_users,
    get_laps_computers,
    get_non_laps_computers,
    get_passwordnotreqd_users,
    get_pwdneverexpires_users,
    get_stale_users,
)
from adscan_internal.workspaces import domain_subpath, read_json_file

# ``control``-kind edges that are NOT AD-object DACL primitives — share /
# resource / file-credential access capabilities. BloodHound does not flag
# these ``isacl=true``; ADscan classifies them ``control`` because a downstream
# technique consumes the capability, but they are not object ACEs, so the ACL
# enumeration surface excludes them. Everything else classified as
# :data:`EdgeKind.CONTROL` is an ACE (single source of truth: ``edge_kind``).
_ACL_ACE_EXCLUDED_RELATIONS: frozenset[str] = frozenset(
    {
        "ReadShare",
        "WriteShare",
        "FullControlShare",
        "GPPPassword",
        "PasswordInShare",
        "PasswordInFile",
    }
)


class LocalGraphService:
    """BloodHound-compatible facade backed by ADscan's local attack graph.

    The CLI still has several compatibility call sites named after the older
    BloodHound service. This facade keeps those call sites functional while
    sourcing data from ``attack_graph.json`` and avoiding any CE/Neo4j client
    initialization in the default runtime.
    """

    edition = "native"

    def __init__(self, shell: Any) -> None:
        self._shell = shell
        self._inventory_cache: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def _graph(self, domain: str) -> dict[str, Any]:
        return load_attack_graph(self._shell, domain)

    def _workspace_cwd(self) -> str:
        getter = getattr(self._shell, "_get_workspace_cwd", None)
        if callable(getter):
            return str(getter() or "")
        return str(getattr(self._shell, "current_workspace_dir", "") or "")

    def _inventory_path(self, domain: str, filename: str) -> str:
        domains_dir = str(getattr(self._shell, "domains_dir", "domains") or "domains")
        return domain_subpath(
            self._workspace_cwd(),
            domains_dir,
            domain,
            "inventory",
            filename,
        )

    def _inventory_records(self, domain: str, filename: str) -> list[dict[str, Any]]:
        cache_key = (str(domain or "").casefold(), filename)
        cached = self._inventory_cache.get(cache_key)
        if cached is not None:
            return cached

        path = self._inventory_path(domain, filename)
        if not os.path.exists(path):
            self._inventory_cache[cache_key] = []
            return []

        payload = read_json_file(path)
        raw_records = payload.get("records") if isinstance(payload, dict) else []
        records = [
            self._flatten_inventory_record(record)
            for record in raw_records
            if isinstance(record, dict)
        ]
        self._inventory_cache[cache_key] = records
        return records

    @staticmethod
    def _flatten_inventory_record(record: dict[str, Any]) -> dict[str, Any]:
        properties = record.get("properties")
        flattened = dict(properties) if isinstance(properties, dict) else {}
        for source_key, target_key in (
            ("object_id", "objectid"),
            ("name", "name"),
            ("domain", "domain"),
            ("samaccountname", "samaccountname"),
            ("distinguished_name", "distinguishedname"),
            ("enabled", "enabled"),
            ("highvalue", "highvalue"),
        ):
            value = record.get(source_key)
            if value is not None and value != "":
                flattened.setdefault(target_key, value)
        flattened.setdefault("_inventory_record", record)
        return flattened

    def _principal_inventory_records(
        self,
        domain: str,
        *,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        if kind == "User":
            return self._inventory_records(domain, "users.json")
        if kind == "Group":
            return self._inventory_records(domain, "groups.json")
        if kind == "Computer":
            return self._inventory_records(domain, "computers.json")
        return [
            *self._inventory_records(domain, "users.json"),
            *self._inventory_records(domain, "groups.json"),
            *self._inventory_records(domain, "computers.json"),
        ]

    @staticmethod
    def _identity_name(properties: dict[str, Any]) -> str:
        for key in ("samaccountname", "name"):
            value = str(properties.get(key) or "").strip()
            if value:
                return value.split("@", 1)[0]
        return ""

    @classmethod
    def _is_human_user(cls, properties: dict[str, Any]) -> bool:
        return not cls._identity_name(properties).endswith("$")

    @staticmethod
    def _computer_name(properties: dict[str, Any], domain: str) -> str:
        dns_name = str(properties.get("dnshostname") or "").strip().rstrip(".")
        if dns_name:
            return dns_name
        name = str(properties.get("name") or "").strip().rstrip(".")
        if "." in name and "@" not in name:
            return name
        samaccountname = str(properties.get("samaccountname") or "").strip().rstrip("$")
        if not samaccountname:
            return ""
        normalized_domain = domain.strip().rstrip(".")
        return (
            f"{samaccountname}.{normalized_domain}"
            if normalized_domain
            else samaccountname
        )

    @staticmethod
    def _node_name_candidates(
        node: dict[str, Any], properties: dict[str, Any]
    ) -> set[str]:
        candidates: set[str] = set()
        for value in (
            node.get("id"),
            node.get("objectid"),
            properties.get("objectid"),
            properties.get("objectId"),
            properties.get("samaccountname"),
            properties.get("name"),
            properties.get("dnshostname"),
        ):
            text = str(value or "").strip()
            if not text:
                continue
            candidates.add(text.casefold())
            candidates.add(text.rstrip("$").casefold())
            candidates.add(text.split("@", 1)[0].rstrip("$").casefold())
            candidates.add(text.split(".", 1)[0].rstrip("$").casefold())
        return {candidate for candidate in candidates if candidate}

    def _find_node(
        self,
        domain: str,
        lookup: str,
        *,
        kind: str | None = None,
    ) -> dict[str, Any] | None:
        lookup_clean = str(lookup or "").strip()
        if not lookup_clean:
            return None
        normalized_lookup = lookup_clean.casefold()
        normalized_lookup_short = lookup_clean.split("@", 1)[0].rstrip("$").casefold()
        for properties in self._principal_inventory_records(domain, kind=kind):
            candidates = self._node_name_candidates({}, properties)
            if normalized_lookup in candidates or normalized_lookup_short in candidates:
                return dict(properties)

        graph = self._graph(domain)
        for node in (graph.get("nodes") or {}).values():
            if kind and node.get("kind") != kind:
                continue
            properties = node.get("properties") or {}
            candidates = self._node_name_candidates(node, properties)
            if normalized_lookup in candidates or normalized_lookup_short in candidates:
                return dict(properties)
        return None

    def get_user_node_by_samaccountname(
        self,
        domain: str,
        samaccountname: str,
    ) -> dict[str, Any] | None:
        """Return one user node from the local graph by SAM account name."""
        return self._find_node(domain, samaccountname, kind="User")

    def get_group_node_by_samaccountname(
        self,
        domain: str,
        samaccountname: str,
    ) -> dict[str, Any] | None:
        """Return one group node from the local graph by SAM account name."""
        return self._find_node(domain, samaccountname, kind="Group")

    def get_computer_node_by_name(
        self,
        domain: str,
        computer_name: str,
    ) -> dict[str, Any] | None:
        """Return one computer node from the local graph by hostname or SAM name."""
        return self._find_node(domain, computer_name, kind="Computer")

    def get_principal_node(
        self,
        domain: str,
        principal_name: str,
        *,
        principal_type: str | None = None,
        object_id: str | None = None,
        lookup_name: str | None = None,
    ) -> dict[str, Any] | None:
        """Return a principal node using the local graph compatibility lookup.

        Resolution order: the human-facing ``principal_name`` first, then any
        alternate ``lookup_name`` (e.g. a UPN/short form), then the SID via
        ``object_id`` — ``_find_node`` indexes the objectId/SID candidate set,
        so a name-less enrichment (SID only) still resolves.
        """
        kind = (
            principal_type[:1].upper() + principal_type[1:] if principal_type else None
        )

        def _lookup(name: str | None) -> dict[str, Any] | None:
            candidate = str(name or "").strip()
            if not candidate:
                return None
            if kind in {"User", "Group", "Computer"}:
                return self._find_node(domain, candidate, kind=kind)
            return (
                self.get_user_node_by_samaccountname(domain, candidate)
                or self.get_group_node_by_samaccountname(domain, candidate)
                or self.get_computer_node_by_name(domain, candidate)
            )

        return (
            _lookup(principal_name)
            or _lookup(lookup_name)
            or _lookup(object_id)
        )

    def get_users(
        self,
        domain: str,
        filter_type: str | None = None,
        scan_id: str | None = None,  # noqa: ARG002 - compatibility surface
    ) -> list[str]:
        """Return users from the local attack graph."""
        records = self._inventory_records(domain, "users.json")
        if records:
            records = [record for record in records if self._is_human_user(record)]
            if filter_type == "high_value":
                records = [
                    record for record in records if bool(record.get("highvalue"))
                ]
            elif filter_type == "admin":
                records = [
                    record for record in records if bool(record.get("admincount"))
                ]
            elif filter_type == "pwd_never_expires":
                records = [
                    record for record in records if bool(record.get("pwdneverexpires"))
                ]
            elif filter_type == "pwd_not_required":
                records = [
                    record for record in records if bool(record.get("passwordnotreqd"))
                ]
            else:
                records = [
                    record for record in records if record.get("enabled") is not False
                ]
        else:
            graph = self._graph(domain)
            if filter_type == "high_value":
                records = get_high_value_users(graph, domain)
            elif filter_type == "admin":
                records = get_admincount_users(graph, domain)
            elif filter_type == "pwd_never_expires":
                records = get_pwdneverexpires_users(graph, domain)
            elif filter_type == "pwd_not_required":
                records = get_passwordnotreqd_users(graph, domain)
            else:
                records = get_enabled_users(graph, domain)
        return [name for record in records if (name := self._identity_name(record))]

    def get_stale_enabled_users(
        self,
        domain: str,
        *,
        stale_days: int = 180,
        scan_id: str | None = None,  # noqa: ARG002 - compatibility surface
    ) -> list[dict[str, Any]]:
        """Return stale enabled users from the local attack graph."""
        return get_stale_users(self._graph(domain), domain, stale_days=stale_days)

    def get_users_in_ou(
        self,
        domain: str,
        ou_distinguished_name: str,
        scan_id: str | None = None,  # noqa: ARG002 - compatibility surface
    ) -> list[str]:
        """Return users whose distinguishedName is under the requested OU."""
        ou_dn = str(ou_distinguished_name or "").strip().casefold()
        if not ou_dn:
            return []
        users: list[str] = []
        for record in self._inventory_records(domain, "users.json"):
            if not self._is_human_user(record):
                continue
            dn = str(
                record.get("distinguishedname")
                or record.get("distinguishedName")
                or ""
            ).strip()
            if dn.casefold().endswith(ou_dn):
                name = self._identity_name(record)
                if name:
                    users.append(name)
        if users:
            return users

        graph = self._graph(domain)
        for node in (graph.get("nodes") or {}).values():
            if node.get("kind") != "User":
                continue
            properties = node.get("properties") or {}
            if not self._is_human_user(properties):
                continue
            dn = str(
                properties.get("distinguishedname")
                or properties.get("distinguishedName")
                or ""
            ).strip()
            if dn.casefold().endswith(ou_dn):
                name = self._identity_name(properties)
                if name:
                    users.append(name)
        return users

    def get_password_last_change(
        self,
        domain: str,
        *,
        user: str | None = None,
        users: list[str] | None = None,
        enabled_only: bool = True,
        scan_id: str | None = None,  # noqa: ARG002 - compatibility surface
    ) -> list[dict[str, Any]]:
        """Return password-last-set records from local user node properties."""
        requested = {value.casefold() for value in (users or []) if value}
        if user:
            requested.add(user.casefold())

        records: list[dict[str, Any]] = []
        inventory_records = self._inventory_records(domain, "users.json")
        if inventory_records:
            source_records = (
                [
                    record
                    for record in inventory_records
                    if record.get("enabled") is not False
                ]
                if enabled_only
                else inventory_records
            )
        else:
            graph = self._graph(domain)
            source_records = (
                get_enabled_users(graph, domain)
                if enabled_only
                else [
                    node.get("properties") or {}
                    for node in (graph.get("nodes") or {}).values()
                    if node.get("kind") == "User"
                ]
            )
        for properties in source_records:
            name = self._identity_name(properties)
            if requested and name.casefold() not in requested:
                continue
            record = dict(properties)
            record.setdefault("samaccountname", name)
            records.append(record)
        return records

    def get_computers(
        self,
        domain: str,
        laps_filter: bool | None = None,
        scan_id: str | None = None,  # noqa: ARG002 - compatibility surface
    ) -> list[str]:
        """Return computers from the local attack graph."""
        records = self._inventory_records(domain, "computers.json")
        if records:
            if laps_filter is True:
                records = [record for record in records if bool(record.get("haslaps"))]
            elif laps_filter is False:
                records = [
                    record for record in records if not bool(record.get("haslaps"))
                ]
            else:
                records = [
                    record for record in records if record.get("enabled") is not False
                ]
        else:
            graph = self._graph(domain)
            if laps_filter is True:
                records = get_laps_computers(graph, domain)
            elif laps_filter is False:
                records = get_non_laps_computers(graph, domain)
            else:
                records = get_enabled_computers(graph, domain)
        return [
            name for record in records if (name := self._computer_name(record, domain))
        ]

    def get_kerberoastable_users(self, domain: str) -> list[str]:
        """Return Kerberoastable users from the local attack graph."""
        records = [
            record
            for record in self._inventory_records(domain, "users.json")
            if record.get("enabled") is not False and bool(record.get("hasspn"))
        ]
        if records:
            return [
                name
                for record in records
                if (name := self._identity_name(record))
            ]
        return [
            name
            for record in get_kerberoastable_users(self._graph(domain), domain)
            if (name := self._identity_name(record))
        ]

    def get_asreproastable_users(self, domain: str) -> list[str]:
        """Return AS-REP-roastable users from the local attack graph."""
        records = [
            record
            for record in self._inventory_records(domain, "users.json")
            if record.get("enabled") is not False and bool(record.get("dontreqpreauth"))
        ]
        if records:
            return [
                name
                for record in records
                if (name := self._identity_name(record))
            ]
        return [
            name
            for record in get_asreproastable_users(self._graph(domain), domain)
            if (name := self._identity_name(record))
        ]

    def get_timeroast_candidates(
        self,
        domain: str,
        *,
        max_results: int = 250,
        scan_id: str | None = None,  # noqa: ARG002 - compatibility surface
    ) -> list[dict[str, Any]]:
        """Return enabled computer accounts with enough local metadata for Timeroast."""
        candidates: list[dict[str, Any]] = []
        for record in self._inventory_records(domain, "computers.json"):
            if record.get("enabled") is False:
                continue
            pwdlastset = _ad_time_to_epoch_seconds(record.get("pwdlastset"))
            whencreated = _ad_time_to_epoch_seconds(record.get("whencreated"))
            if not pwdlastset or not whencreated:
                continue
            candidate = dict(record)
            candidate["pwdlastset"] = pwdlastset
            candidate["whencreated"] = whencreated
            candidates.append(candidate)
        return candidates[:max_results]

    def start_upload_job(self, zip_path: str) -> None:  # noqa: ARG002
        """Legacy no-op: native graph mode does not upload ZIPs to BloodHound CE."""
        return None

    def wait_for_upload_job(self, job_id: str | None, *, timeout: int) -> bool:  # noqa: ARG002
        """Legacy no-op: native graph mode has no remote ingestion job."""
        return True

    def get_user_groups(
        self, domain: str, username: str, *, recursive: bool = True
    ) -> list[str]:
        """Return group labels for *username* from the membership snapshot."""
        from adscan_internal.services.attack_graph_service import (
            get_recursive_principal_groups_from_snapshot,
        )
        try:
            result = get_recursive_principal_groups_from_snapshot(
                self._shell, domain=domain, principal=username
            )
            return list(result or [])
        except Exception:  # noqa: BLE001
            return []

    # ------------------------------------------------------------------
    # Critical ACE enumeration (native attack-graph backed)
    # ------------------------------------------------------------------

    @staticmethod
    def _is_acl_relation(relation: str, kind: str = "") -> bool:
        """Return True when *relation* is an AD-object DACL/control ACE.

        Mirrors BloodHound's ``r.isacl = true`` filter using ADscan's canonical
        :func:`classify_edge_kind` SSOT, minus the non-object share/file-credential
        access edges (see :data:`_ACL_ACE_EXCLUDED_RELATIONS`).
        """
        if not relation or relation in _ACL_ACE_EXCLUDED_RELATIONS:
            return False
        if kind == EdgeKind.CONTROL.value:
            return True
        return classify_edge_kind(relation) is EdgeKind.CONTROL

    @staticmethod
    def _ace_principal_name(node: dict[str, Any], properties: dict[str, Any]) -> str:
        for value in (
            properties.get("samaccountname"),
            properties.get("name"),
            node.get("label"),
        ):
            text = str(value or "").strip()
            if text:
                return text.split("@", 1)[0]
        return ""

    @staticmethod
    def _ace_object_id(
        ref: str, node: dict[str, Any], properties: dict[str, Any]
    ) -> str:
        for value in (
            properties.get("objectid"),
            properties.get("objectId"),
            node.get("objectId"),
            node.get("objectid"),
        ):
            text = str(value or "").strip()
            if text:
                return text
        ref_text = str(ref or "")
        return ref_text.split(":", 1)[1] if ref_text.startswith("name:") else ref_text

    @staticmethod
    def _node_is_high_value(node: dict[str, Any]) -> bool:
        properties = node.get("properties") or {}
        if node.get("highvalue") or node.get("is_high_value") or node.get("isTierZero"):
            return True
        if properties.get("highvalue") or properties.get("isTierZero"):
            return True
        tags = node.get("system_tags") or properties.get("system_tags") or []
        return "admin_tier_0" in tags

    def get_critical_aces(
        self,
        source_domain: str,
        high_value: bool = False,
        username: str = "all",
        target_domain: str = "all",
        relation: str = "all",
        scan_id: str | None = None,  # noqa: ARG002 - signature parity (legacy CE)
    ) -> list[dict[str, Any]]:
        """Return critical ACEs (object-control edges) from the native graph.

        Drop-in replacement for the removed BloodHound-CE ``get_critical_aces``.
        Reads ``attack_graph.json`` for *source_domain* and, for every source
        principal, follows ``MemberOf`` transitively (including nested groups —
        equivalent to BloodHound's ``[:MemberOf*0..]``) so that a control edge
        held by a group is attributed to each member principal. Only DACL/control
        edges (:func:`classify_edge_kind` == CONTROL) are returned.

        Args:
            source_domain: Domain whose principals are treated as ACE holders.
            high_value: Keep only edges whose target is a Tier 0 / high-value node.
            username: Restrict source principals to this SAM/name, or ``"all"``.
            target_domain: Filter targets by domain, or ``"all"`` / ``"high-value"``.
            relation: Filter by ACE relation (e.g. ``GenericAll``), or ``"all"``.
            scan_id: Accepted for signature parity with the legacy CE service; unused.

        Returns:
            A list of ACE dicts with the legacy CE keys: ``source``, ``sourceType``,
            ``sourceDomain``, ``target``, ``targetType``, ``targetDomain``,
            ``relation``, ``targetEnabled``, ``sourceObjectId``, ``targetObjectId``.
        """
        graph = self._graph(source_domain)
        nodes = graph.get("nodes") if isinstance(graph, dict) else None
        edges = graph.get("edges") if isinstance(graph, dict) else None
        if not isinstance(nodes, dict) or not isinstance(edges, list):
            return []

        # Index nodes by every identifier an edge endpoint might use.
        node_by_ref: dict[str, dict[str, Any]] = {}
        for key, node in nodes.items():
            if not isinstance(node, dict):
                continue
            properties = node.get("properties") or {}
            for candidate in (
                key,
                node.get("id"),
                node.get("objectId"),
                node.get("objectid"),
                properties.get("objectid"),
                properties.get("objectId"),
            ):
                ref = str(candidate or "").strip()
                if ref:
                    node_by_ref.setdefault(ref, node)

        # Build membership + control adjacency in one pass over the edges.
        member_of: dict[str, set[str]] = {}
        control_out: dict[str, list[tuple[str, str]]] = {}
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            frm = str(edge.get("from") or "").strip()
            to = str(edge.get("to") or "").strip()
            if not frm or not to:
                continue
            edge_relation = str(edge.get("relation") or "")
            edge_kind = str(edge.get("kind") or "")
            if edge_kind == EdgeKind.MEMBERSHIP.value or edge_relation == "MemberOf":
                member_of.setdefault(frm, set()).add(to)
            if self._is_acl_relation(edge_relation, edge_kind):
                control_out.setdefault(frm, []).append((to, edge_relation))

        if not control_out:
            return []

        closure_cache: dict[str, set[str]] = {}

        def _transitive_groups(start: str) -> set[str]:
            cached = closure_cache.get(start)
            if cached is not None:
                return cached
            seen: set[str] = set()
            stack = [start]
            while stack:
                current = stack.pop()
                for group in member_of.get(current, ()):  # noqa: PLR1704
                    if group not in seen:
                        seen.add(group)
                        stack.append(group)
            closure_cache[start] = seen
            return seen

        # Resolve source principals.
        want_all = username.strip().lower() in ("", "all")
        wanted_short = username.strip().split("@", 1)[0].rstrip("$").lower()
        source_domain_lower = source_domain.strip().lower()

        source_nodes: list[tuple[str, dict[str, Any]]] = []
        for key, node in nodes.items():
            if not isinstance(node, dict):
                continue
            properties = node.get("properties") or {}
            node_domain = str(properties.get("domain") or "").strip().lower()
            if source_domain_lower and node_domain != source_domain_lower:
                continue
            if want_all:
                if node.get("kind") in ("User", "Computer"):
                    source_nodes.append((key, node))
                continue
            candidates = {
                str(properties.get("samaccountname") or "").rstrip("$").lower(),
                str(properties.get("name") or "").split("@", 1)[0].rstrip("$").lower(),
                str(node.get("label") or "").split("@", 1)[0].rstrip("$").lower(),
            }
            if wanted_short in candidates:
                source_nodes.append((key, node))

        target_dom_filter = target_domain.strip().lower()
        apply_target_dom = target_dom_filter not in ("", "all", "high-value")
        rel_filter = relation.strip().lower()
        apply_rel = rel_filter not in ("", "all")

        results: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str, str]] = set()
        limit = 1000

        for key, node in source_nodes:
            src_props = node.get("properties") or {}
            src_name = self._ace_principal_name(node, src_props)
            if not src_name:
                continue
            src_type = str(node.get("kind") or "Unknown")
            src_domain = str(src_props.get("domain") or source_domain)
            src_object_id = self._ace_object_id(key, node, src_props)

            holders = {key} | _transitive_groups(key)
            for holder in holders:
                for target_ref, edge_relation in control_out.get(holder, ()):
                    if apply_rel and edge_relation.lower() != rel_filter:
                        continue
                    target_node = node_by_ref.get(target_ref)
                    if not target_node:
                        continue
                    if high_value and not self._node_is_high_value(target_node):
                        continue
                    tgt_props = target_node.get("properties") or {}
                    tgt_domain = str(tgt_props.get("domain") or source_domain)
                    if apply_target_dom and tgt_domain.lower() != target_dom_filter:
                        continue
                    tgt_name = self._ace_principal_name(target_node, tgt_props)
                    if not tgt_name:
                        continue
                    dedup = (src_name.lower(), tgt_name.lower(), edge_relation)
                    if dedup in seen_keys:
                        continue
                    seen_keys.add(dedup)
                    results.append(
                        {
                            "source": src_name,
                            "sourceType": src_type,
                            "sourceDomain": src_domain.lower() if src_domain else "N/A",
                            "target": tgt_name,
                            "targetType": str(target_node.get("kind") or "Unknown"),
                            "targetDomain": tgt_domain.lower() if tgt_domain else "N/A",
                            "relation": edge_relation,
                            "targetEnabled": bool(tgt_props.get("enabled", True)),
                            "sourceObjectId": src_object_id,
                            "targetObjectId": self._ace_object_id(
                                target_ref, target_node, tgt_props
                            ),
                        }
                    )
                    if len(results) >= limit:
                        return results

        return results

    def get_principals_with_tier0_access(
        self, domain: str
    ) -> list[dict[str, Any]]:
        """Return non-Tier-0 principals that have an ACCESS edge onto a Tier-0 asset.

        Axis 2 (Compromise Reach), NOT axis 1: this reports what a principal can
        REACH, never re-tiering the principal itself. For every access/auth edge
        (``AdminTo`` / ``CanPSRemote`` / ``CanRDP`` / ``ExecuteDCOM`` /
        ``SQLAdmin`` / ``SQLAccess`` — the relations carrying a
        :class:`ControlStrength`) that terminates on a Tier-0 COMPUTER asset (a
        DC, an ADCS CA, an Exchange server), it attributes the reach to every
        NON-Tier-0 source principal, following ``MemberOf`` transitively so a
        group-held session/admin edge reaches each member.

        The two axes stay separate, per CLAUDE.md § Nomenclature Standard: a
        Tier-2 user with ``CanRDP`` to a DC is reported here as Tier-2 (its
        ``principal_tier``) with a Tier-0 REACH (``target_tier``). A source that
        is itself Tier-0 is excluded — its access to a Tier-0 asset is structural
        AD hierarchy, not an exposure finding.

        Args:
            domain: The domain whose materialized attack graph is read.

        Returns:
            One record per (principal, target, relation) with keys:
            ``principal``, ``principal_object_id``, ``principal_tier`` (the tier
            the principal IS GRANTED — Tier 2/1/…), ``target``,
            ``target_object_id``, ``target_role`` (``"DC"`` / ``"ADCS CA"`` /
            ``"Exchange"`` / ``"Tier 0"``), ``target_tier``
            (``tier0_direct`` / ``tier0_escalation_capable``), ``relation``,
            ``control_strength`` (``full`` / ``session`` / ``conditional_exec`` /
            ``low``), ``via_group`` (the group label the edge was held by, or
            ``""`` when the principal holds it directly), ``target_enabled``.
        """
        from adscan_internal.services.compromise_class import (  # noqa: PLC0415
            PrivilegeTier,
            _node_group_tokens_for_kind,
            node_stamped_privilege_tier,
            privilege_tier_for_computer,
            privilege_tier_for_node,
            privilege_tier_for_principal,
            privilege_tier_for_principal_node,
        )
        from adscan_internal.services.computer_node_role import (  # noqa: PLC0415
            node_is_rodc_computer,
        )
        from adscan_internal.services.edge_kind import (  # noqa: PLC0415
            ControlStrength,
            edge_control_strength,
        )

        graph = self._graph(domain)
        nodes = graph.get("nodes") if isinstance(graph, dict) else None
        edges = graph.get("edges") if isinstance(graph, dict) else None
        if not isinstance(nodes, dict) or not isinstance(edges, list):
            return []

        # Index nodes by every identifier an edge endpoint might use.
        node_by_ref: dict[str, dict[str, Any]] = {}
        for key, node in nodes.items():
            if not isinstance(node, dict):
                continue
            properties = node.get("properties") or {}
            for candidate in (
                key,
                node.get("id"),
                node.get("objectId"),
                node.get("objectid"),
                properties.get("objectid"),
                properties.get("objectId"),
            ):
                ref = str(candidate or "").strip()
                if ref:
                    node_by_ref.setdefault(ref, node)

        def _target_tier_of(node: dict[str, Any]) -> PrivilegeTier:
            # The TARGET's granted tier — a Tier-0 ASSET must be recognised even
            # when it carries only the degraded ``isTierZero`` flag (a collector
            # highvalue tag with no resolvable Tier-0 GROUP membership, e.g. an
            # ADCS CA or Exchange host tagged but ungrouped). Prefer the
            # collector-stamped membership-aware tier, else the node resolver WITH
            # the degraded flag so the asset is still graded Tier 0.
            stamped = node_stamped_privilege_tier(node)
            if stamped is not None:
                return stamped
            is_t0_flag = bool(node.get("isTierZero")) or bool(
                (node.get("properties") or {}).get("isTierZero")
            )
            if str(node.get("kind") or "").strip().lower() == "computer":
                return privilege_tier_for_node(node, is_tier0_asset=is_t0_flag)
            return privilege_tier_for_principal_node(node, is_tier0_asset=is_t0_flag)

        def _source_grant_tier_of(
            node_ref: str, node: dict[str, Any]
        ) -> PrivilegeTier:
            # The SOURCE principal's GRANTED tier — MEMBERSHIP-BASED ONLY, never
            # the degraded ``isTierZero`` highvalue flag. A low-priv account that
            # the collector merely TAGGED high-value (e.g. Forest's svc-alfresco:
            # a kerberoastable Tier-2 service account flagged highvalue) must keep
            # its true Tier-2 grant, so its Tier-0 REACH is REPORTED, not
            # suppressed as "structural". A principal is structurally Tier-0 only
            # by real control-plane GROUP MEMBERSHIP — so grade the source from
            # its transitive MemberOf closure in THIS graph (the same SSOT the
            # collector uses), NOT from the collector stamp (which may itself be
            # the degraded highvalue-flag fallback) and NOT from the highvalue
            # tag. This is the axis-1/axis-2 separation: highvalue-tag ≠ granted
            # Tier 0.
            group_tokens: list[str] = []
            for group_id in _closure(node_ref):
                group_node = nodes.get(group_id)
                if isinstance(group_node, dict):
                    group_tokens.extend(_node_group_tokens_for_kind(group_node))
            props = node.get("properties") or {}
            sid = (
                str(props.get("objectid") or node.get("objectId") or "").strip()
                or None
            )
            if str(node.get("kind") or "").strip().lower() == "computer":
                return privilege_tier_for_computer(
                    group_names=group_tokens, sid=sid, is_tier0_asset=False
                )
            return privilege_tier_for_principal(group_tokens, sid=sid)

        def _target_role(node: dict[str, Any]) -> str:
            # LABEL ONLY — the display string the client sees for the reached
            # asset. It never affects inclusion (membership-driven "is Tier 0")
            # or severity (access-strength + concentration, tier-collapsed). RODC
            # detection reuses the computer-role SSOT (primaryGroupID 521 / local
            # krbtgt SPN / RODC UAC bit / explicit flags), never a hand-rolled
            # check. Any Tier-0 asset with no specific label falls back to the
            # generic "Tier 0 asset" — still correctly included and rated.
            props = node.get("properties") or {}
            name = self._ace_principal_name(node, props).lower()
            if node_is_rodc_computer(node):
                return "RODC"
            if bool(node.get("is_dc")) or bool(props.get("is_dc")):
                return "DC"
            for fragment in ("exch", "mail"):
                if fragment in name:
                    return "Exchange"
            for fragment in ("adcs", "-ca", "certsrv", "pki"):
                if fragment in name:
                    return "ADCS CA"
            tier = _target_tier_of(node)
            if tier is PrivilegeTier.TIER0_DIRECT:
                return "DC"
            return "Tier 0 asset"

        # Build membership adjacency and collect access edges onto Tier-0
        # COMPUTER targets in one pass. Only a Tier-0 computer counts as an
        # "asset" here — a DC, an ADCS CA host, an Exchange server; a Tier-0
        # GROUP/user is not a reachable machine.
        member_of: dict[str, set[str]] = {}
        access_edges: list[tuple[str, str, str, dict[str, Any]]] = []
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            frm = str(edge.get("from") or "").strip()
            to = str(edge.get("to") or "").strip()
            if not frm or not to:
                continue
            relation = str(edge.get("relation") or "")
            if relation == "MemberOf":
                member_of.setdefault(frm, set()).add(to)
                continue
            strength = edge_control_strength(relation)
            if strength is ControlStrength.NOT_APPLICABLE:
                continue
            target_node = node_by_ref.get(to)
            if not target_node:
                continue
            if str(target_node.get("kind") or "").strip().lower() != "computer":
                continue
            if not _target_tier_of(target_node).is_tier0:
                continue
            access_edges.append((frm, to, relation, target_node))

        if not access_edges:
            return []

        # Transitive members of a group (inverse of the MemberOf closure), built
        # ONCE so a group-held access edge is attributed to every member without
        # an O(N^2) per-group re-walk (enterprise scale: § AD constraints §10).
        closure_cache: dict[str, set[str]] = {}

        def _closure(start: str) -> set[str]:
            cached = closure_cache.get(start)
            if cached is not None:
                return cached
            seen: set[str] = set()
            stack = list(member_of.get(start, ()))
            while stack:
                current = stack.pop()
                if current not in seen:
                    seen.add(current)
                    stack.extend(member_of.get(current, ()))
            closure_cache[start] = seen
            return seen

        members_by_group: dict[str, set[str]] = {}
        for src_ref in member_of:
            for group_ref in _closure(src_ref):
                members_by_group.setdefault(group_ref, set()).add(src_ref)

        def _transitive_members(group_ref: str) -> set[str]:
            return members_by_group.get(group_ref, set())

        results: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str, str]] = set()
        limit = 1000
        for frm, to, relation, target_node in access_edges:
            holder_node = node_by_ref.get(frm)
            holder_kind = (
                str(holder_node.get("kind") or "").strip().lower()
                if holder_node
                else ""
            )
            via_group = ""
            if holder_kind == "group":
                via_group = self._ace_principal_name(
                    holder_node, holder_node.get("properties") or {}
                )
                # Attribute to every transitive member principal.
                candidate_refs = _transitive_members(frm)
            elif holder_kind in ("user", "computer"):
                candidate_refs = {frm}
            else:
                continue

            tgt_props = target_node.get("properties") or {}
            tgt_name = self._ace_principal_name(target_node, tgt_props)
            tgt_role = _target_role(target_node)
            tgt_tier = _target_tier_of(target_node)
            strength = edge_control_strength(relation)

            for principal_ref in candidate_refs:
                principal_node = node_by_ref.get(principal_ref)
                if not principal_node:
                    continue
                if str(principal_node.get("kind") or "").strip().lower() not in (
                    "user",
                    "computer",
                ):
                    continue
                principal_tier = _source_grant_tier_of(principal_ref, principal_node)
                # Exclude a Tier-0 source: its access to a Tier-0 asset is
                # structural AD hierarchy, not an exposure finding.
                if principal_tier.is_tier0:
                    continue
                p_props = principal_node.get("properties") or {}
                principal_name = self._ace_principal_name(principal_node, p_props)
                if not principal_name:
                    continue
                dedup = (
                    principal_name.lower(),
                    tgt_name.lower(),
                    relation.lower(),
                )
                if dedup in seen_keys:
                    continue
                seen_keys.add(dedup)
                results.append(
                    {
                        "principal": principal_name,
                        "principal_object_id": self._ace_object_id(
                            principal_ref, principal_node, p_props
                        ),
                        "principal_tier": principal_tier.value,
                        "target": tgt_name,
                        "target_object_id": self._ace_object_id(
                            to, target_node, tgt_props
                        ),
                        "target_role": tgt_role,
                        "target_tier": tgt_tier.value,
                        "relation": relation,
                        "control_strength": strength.value,
                        "via_group": via_group,
                        "target_enabled": bool(tgt_props.get("enabled", True)),
                    }
                )
                if len(results) >= limit:
                    return results
        return results

    def get_users_with_dc_access(self, domain: str) -> list[dict[str, Any]]:
        """Back-compat alias for the DC/Tier-0 access reader.

        The legacy CLI call site (``run_dc_access``) expects this name. It now
        returns the Tier-0 access exposure records from
        :meth:`get_principals_with_tier0_access` — which covers DCs plus the
        other Tier-0 assets (ADCS CA, Exchange) — mapped to the legacy
        ``{origen, destino, acl, ...}`` shape the DC-access renderer consumes.
        """
        records = self.get_principals_with_tier0_access(domain)
        legacy: list[dict[str, Any]] = []
        for record in records:
            legacy.append(
                {
                    "origen": record["principal"],
                    "tipoorigen": "User",
                    "dominio_origen": domain,
                    "destino": record["target"],
                    "tipodestino": "Computer",
                    "dominio_destino": domain,
                    "acl": record["relation"],
                    "target_enabled": record.get("target_enabled", True),
                }
            )
        return legacy


def _ad_time_to_epoch_seconds(value: object) -> int | None:
    """Normalize AD FILETIME, generalized time, or epoch seconds to epoch seconds."""
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    text = str(value).strip()
    try:
        parsed = int(float(text))
    except (TypeError, ValueError):
        parsed = None
    if parsed:
        if parsed > 10_000_000_000_000:
            return int((parsed - 116444736000000000) / 10_000_000)
        return parsed
    for fmt in ("%Y%m%d%H%M%S.%f%z", "%Y%m%d%H%M%S%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            normalized = text.replace("Z", "+0000")
            return int(datetime.strptime(normalized, fmt).timestamp())
        except ValueError:
            continue
    return None
