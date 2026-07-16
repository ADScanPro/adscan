from __future__ import annotations

from typing import Any

from adscan_core.rich_output import print_info_verbose


# ---------------------------------------------------------------------------
# Legacy state migration
# ---------------------------------------------------------------------------

# Legacy workspace-state keys that referenced the now-removed managed Neo4j /
# BloodHound CE stack. They held connection details for a service ADscan no
# longer ships, so they are dropped on read instead of being remapped.
_LEGACY_NEO4J_STATE_KEYS: tuple[str, ...] = (
    "neo4j_host",
    "neo4j_port",
    "neo4j_db_user",
    "neo4j_db_password",
)

# Legacy edge_type / source provenance literal that BloodHound-CE-derived
# graph data was tagged with. Renamed to a transport-neutral name now that
# graph collection is performed natively.
_LEGACY_BLOODHOUND_EDGE_TYPE = "bloodhound_ce"
_CURRENT_GRAPH_EDGE_TYPE = "graph_collection"


def migrate_legacy_workspace_state(state: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Strip legacy BloodHound/Neo4j keys from a persisted workspace state dict.

    The workspace ``variables.json`` schema previously carried ``neo4j_*``
    connection settings for the managed Neo4j container. That stack has been
    removed, so any persisted keys are stale and must be dropped on load to
    keep the in-memory shape consistent with the current writer.

    The migration is idempotent: a subsequent call returns ``changed=False``.

    Args:
        state: Parsed ``variables.json`` payload (may be mutated in place).

    Returns:
        A tuple ``(state, changed)`` where ``changed`` indicates whether any
        legacy key was removed.
    """
    if not isinstance(state, dict):
        return state, False
    changed = False
    for key in _LEGACY_NEO4J_STATE_KEYS:
        if key in state:
            state.pop(key, None)
            changed = True
    return state, changed


def migrate_legacy_attack_graph(graph: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Rewrite legacy ``bloodhound_ce`` edge_type tags in an attack graph dict.

    Edges and nodes persisted before the BloodHound-CE removal carry an
    ``edge_type == "bloodhound_ce"`` provenance tag. The literal has been
    renamed to ``graph_collection`` so the on-disk graph is normalised on
    first load.

    Idempotent: subsequent calls find no legacy literal and return
    ``changed=False``.
    """
    if not isinstance(graph, dict):
        return graph, False
    changed = False
    edges = graph.get("edges")
    if isinstance(edges, list):
        for edge in edges:
            if (
                isinstance(edge, dict)
                and edge.get("edge_type") == _LEGACY_BLOODHOUND_EDGE_TYPE
            ):
                edge["edge_type"] = _CURRENT_GRAPH_EDGE_TYPE
                changed = True
    nodes = graph.get("nodes")
    if isinstance(nodes, dict):
        node_iter: Any = nodes.values()
    elif isinstance(nodes, list):
        node_iter = nodes
    else:
        node_iter = ()
    for node in node_iter:
        if (
            isinstance(node, dict)
            and node.get("edge_type") == _LEGACY_BLOODHOUND_EDGE_TYPE
        ):
            node["edge_type"] = _CURRENT_GRAPH_EDGE_TYPE
            changed = True
    return graph, changed


def _coerce_json_safe(value: Any) -> Any:
    """Recursively coerce a value into a JSON-serializable form.

    Defense-in-depth over the atomic ``write_json_file`` primitive: even if a
    non-``_``-prefixed co-tenant (a stray ``set``, ``bytes``, or a custom object)
    lands in a ``domain_data`` entry, it is normalized here before the write so
    it cannot poison ``variables.json``.

    * JSON scalars (``str``/``int``/``float``/``bool``/``None``) pass through.
    * ``bytes`` / ``bytearray`` -> ``None`` (dropped).
    * ``set`` / ``frozenset`` -> sorted ``list`` (``repr`` order when the members
      are not mutually comparable).
    * ``dict`` / ``list`` / ``tuple`` -> recursed.
    * anything else -> ``str(value)``.

    Deterministic and cheap.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return None
    if isinstance(value, (set, frozenset)):
        try:
            items = sorted(value)
        except TypeError:
            items = sorted(value, key=repr)
        return [_coerce_json_safe(item) for item in items]
    if isinstance(value, dict):
        return {key: _coerce_json_safe(val) for key, val in value.items()}
    if isinstance(value, (list, tuple)):
        return [_coerce_json_safe(item) for item in value]
    return str(value)


def collect_workspace_variables_from_shell(shell: Any) -> dict[str, Any]:
    """Collect workspace-level variables from the CLI shell instance."""
    workspace_vars = {
        "hosts": getattr(shell, "hosts", None),
        "myip": getattr(shell, "myip", None),
        "interface": getattr(shell, "interface", None),
        "pdc": getattr(shell, "pdc", None),
        "pdc_hostname": getattr(shell, "pdc_hostname", None),
        "dcs": getattr(shell, "dcs", []),
        "domain": getattr(shell, "domain", None),
        "domains": getattr(shell, "domains", []),
        "username": getattr(shell, "username", None),
        "password": getattr(shell, "password", None),
        "hash": getattr(shell, "hash", None),
        "base_dn": getattr(shell, "base_dn", None),
        "dns": getattr(shell, "dns", None),
        "current_workspace": getattr(shell, "current_workspace", None),
        "current_workspace_dir": getattr(shell, "current_workspace_dir", None),
        "current_domain_dir": getattr(shell, "current_domain_dir", None),
        "domains_data": getattr(shell, "domains_data", {}),
        "domain_connectivity": getattr(shell, "domain_connectivity", {}),
        "auto": getattr(shell, "auto", False),
        "telemetry": getattr(shell, "telemetry", True),
        "type": getattr(shell, "type", None),
        "lab_provider": getattr(shell, "lab_provider", None),
        "lab_name": getattr(shell, "lab_name", None),
        "lab_name_whitelisted": getattr(shell, "lab_name_whitelisted", None),
        "lab_confirmation_state": getattr(shell, "lab_confirmation_state", None),
        "lab_inference_source": getattr(shell, "lab_inference_source", None),
        "lab_inference_confidence": getattr(shell, "lab_inference_confidence", None),
        "password_spraying_history": getattr(shell, "password_spraying_history", {}),
        "cracking_history": getattr(shell, "cracking_history", {}),
    }

    domains_data = workspace_vars.get("domains_data")
    if isinstance(domains_data, dict):
        sanitized = {}
        for domain_key, domain_data in domains_data.items():
            if isinstance(domain_data, dict):
                domain_data = dict(domain_data)
                domain_data.pop("credential_previews", None)
                # Drop transient in-memory keys that contain non-JSON types
                # (e.g. ``set``) or that should never leak across sessions.
                # Prefix convention: keys starting with "_" are runtime-only.
                for _transient_key in [
                    k for k in domain_data.keys() if str(k).startswith("_")
                ]:
                    domain_data.pop(_transient_key, None)
                # Belt-and-suspenders over the atomic write: recursively coerce
                # any non-JSON-serializable co-tenant (set/bytes/custom object)
                # so it can never poison variables.json.
                domain_data = {
                    key: _coerce_json_safe(val) for key, val in domain_data.items()
                }
            sanitized[domain_key] = domain_data
        workspace_vars["domains_data"] = sanitized

    return workspace_vars


def collect_domain_variables_from_shell(shell: Any) -> dict[str, Any]:
    """Collect domain-level variables from the CLI shell instance."""
    domain = getattr(shell, "current_domain", None)
    variables: dict[str, Any] = {
        "hosts": getattr(shell, "hosts", None),
        "myip": getattr(shell, "myip", None),
        "interface": getattr(shell, "interface", None),
        "pdc": getattr(shell, "pdc", None),
        "pdc_hostname": getattr(shell, "pdc_hostname", None),
        "dcs": getattr(shell, "dcs", []),
        "domain": domain,
        "username": getattr(shell, "username", None),
        "password": getattr(shell, "password", None),
        "hash": getattr(shell, "hash", None),
        "base_dn": getattr(shell, "base_dn", None),
        "dns": getattr(shell, "dns", None),
        "current_workspace_dir": getattr(shell, "current_workspace_dir", None),
        "current_domain_dir": getattr(shell, "current_domain_dir", None),
    }

    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict) and domain and domain in domains_data:
        domain_entry = domains_data.get(domain)
        if isinstance(domain_entry, dict):
            variables.update(domain_entry)
    return variables


def apply_workspace_variables_to_shell(shell: Any, variables: dict[str, Any]) -> None:
    """Apply loaded workspace variables to the CLI shell instance.

    Legacy BloodHound/Neo4j keys are stripped before application so older
    workspaces load cleanly against the current shell schema.
    """
    if isinstance(variables, dict):
        variables, migrated = migrate_legacy_workspace_state(variables)
        if migrated:
            workspace_label = variables.get("current_workspace") or "workspace"
            print_info_verbose(
                f"Migrated legacy BloodHound/Neo4j state keys for {workspace_label}"
            )
    defaults: dict[str, Any] = {
        "hosts": None,
        "myip": None,
        "interface": None,
        "pdc": None,
        "pdc_hostname": None,
        "dcs": [],
        "domain": None,
        "domains": [],
        "username": None,
        "password": None,
        "hash": None,
        "base_dn": None,
        "dns": None,
        "current_workspace": None,
        "current_workspace_dir": None,
        "current_domain": None,
        "current_domain_dir": None,
        "domains_data": {},
        "domain_connectivity": {},
        "auto": False,
        "telemetry": True,
        "type": None,
        "lab_provider": None,
        "lab_name": None,
        "lab_name_whitelisted": None,
        "lab_confirmation_state": None,
        "lab_inference_source": None,
        "lab_inference_confidence": None,
        "password_spraying_history": {},
        "cracking_history": {},
    }

    for key, default in defaults.items():
        if key in variables:
            setattr(shell, key, variables.get(key))
        else:
            setattr(shell, key, default)

    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict):
        for _, domain_data in domains_data.items():
            if isinstance(domain_data, dict):
                domain_data.pop("credential_previews", None)


__all__ = [
    "apply_workspace_variables_to_shell",
    "collect_domain_variables_from_shell",
    "collect_workspace_variables_from_shell",
    "migrate_legacy_attack_graph",
    "migrate_legacy_workspace_state",
]
