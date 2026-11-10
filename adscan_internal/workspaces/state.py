from __future__ import annotations

from typing import Any

from adscan_core.rich_output import print_info_verbose
from adscan_core.telemetry_preference import (
    WORKSPACE_PREFERENCE_ATTR,
    load_global_preference,
    resolve_effective_telemetry,
)
from adscan_internal.models.domain import CaseInsensitiveDict
from adscan_internal.services import cleanup_credential_store


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

# Emitted as a ``_snapshot_note`` key into every per-domain ``variables.json``
# so anyone inspecting one on disk knows what it is before they trust it.
DOMAIN_SNAPSHOT_NOTE = (
    "Derived write-only snapshot of the shell state at the moment this domain was "
    "last saved. ADscan never loads it back, so it can be arbitrarily stale. The "
    "single source of truth for workspace state - domains_data, credentials, the "
    "domain list - is the workspace-root variables.json one directory up."
)


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


def _workspace_telemetry_preference_for_save(shell: Any) -> bool | None:
    """Return the workspace's own telemetry preference for persistence.

    Returns the explicitly tracked workspace preference (``True``/``False``), or
    ``None`` when the workspace is UNSET — a new/untouched workspace must not
    freeze a boolean, so it can keep inheriting the global preference live.
    """
    preference = getattr(shell, WORKSPACE_PREFERENCE_ATTR, None)
    if isinstance(preference, bool):
        return preference
    return None


def _apply_telemetry_preference_to_shell(shell: Any, raw_value: Any) -> None:
    """Split the loaded ``telemetry`` value into workspace vs effective state.

    ``shell.telemetry`` is the EFFECTIVE state (resolved live against the global
    preference), while ``shell.telemetry_workspace_preference`` keeps what this
    workspace itself recorded — ``True``/``False`` for an explicit choice, or
    ``None`` when the key is absent (unset) so the workspace inherits the global
    preference rather than freezing a value at creation.
    """
    workspace_preference = raw_value if isinstance(raw_value, bool) else None
    setattr(shell, WORKSPACE_PREFERENCE_ATTR, workspace_preference)
    shell.telemetry = resolve_effective_telemetry(
        load_global_preference(), workspace_preference
    )


def _workspace_pacing_for_save(shell: Any) -> dict[str, Any] | None:
    """The persisted form of ``shell.scan_pacing_request`` (``None`` = unset)."""
    from adscan_internal.services.scan_controls import pacing_request_for_save

    try:
        return pacing_request_for_save(shell)
    except Exception:  # noqa: BLE001 - a pace that cannot be serialised is not persisted
        return None


def _apply_workspace_pacing_to_shell(
    shell: Any, variables: dict[str, Any], *, reset_missing_to_defaults: bool
) -> None:
    """Load the persisted pace request into ``shell.scan_pacing_request``.

    It is only loaded here; the pace is resolved and published by the
    workspace loader, once the workspace policy (its ceiling) is known.
    """
    from adscan_internal.services.scan_controls import (
        ATTR_PACING_REQUEST,
        pacing_request_from_saved,
    )

    if "pacing" in variables:
        setattr(shell, ATTR_PACING_REQUEST, pacing_request_from_saved(variables.get("pacing")))
    elif reset_missing_to_defaults:
        setattr(shell, ATTR_PACING_REQUEST, None)


def _workspace_auto_revert_for_save(shell: Any) -> bool | None:
    """The operator's explicit ``set auto_revert`` choice (``None`` = unset)."""
    value = getattr(shell, "auto_revert", None)
    return value if isinstance(value, bool) else None


#: ``variables.json`` keys this seam writes to disk but never keeps on
#: ``shell.variables`` (the in-memory mirror every module can read). The client
#: cleanup account is the only one: its owner module serializes it on save and
#: takes it back on load, and nothing else may see it (spec 8.1).
_CLEANUP_CREDENTIALS_KEY = cleanup_credential_store.WORKSPACE_VARIABLES_KEY
WRITE_ONLY_WORKSPACE_KEYS: tuple[str, ...] = (_CLEANUP_CREDENTIALS_KEY,)


def _cleanup_credentials_for_save() -> dict[str, Any] | None:
    """The cleanup store's own serialization (``None`` = nothing saved)."""
    return cleanup_credential_store.export_workspace_state()


def _restore_cleanup_credentials(
    variables: dict[str, Any], *, reset_missing_to_defaults: bool
) -> None:
    """Hand the saved cleanup account to its store and drop it from ``variables``.

    Popped so that the loaded dict, which becomes ``shell.variables``, never
    carries the secret.
    """
    present = _CLEANUP_CREDENTIALS_KEY in variables
    raw = variables.pop(_CLEANUP_CREDENTIALS_KEY, None)
    cleanup_credential_store.restore_workspace_state(
        raw, present=present, reset=reset_missing_to_defaults
    )


def collect_workspace_variables_from_shell(shell: Any) -> dict[str, Any]:
    """Collect workspace-level variables from the CLI shell instance."""
    workspace_vars = {
        "hosts": getattr(shell, "hosts", None),
        "myip": getattr(shell, "myip", None),
        "myip_source": getattr(shell, "myip_source", None),
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
        # Persist the WORKSPACE's own preference, not the resolved effective
        # state: a global opt-out must not be written back here as though the
        # user had disabled telemetry for this engagement specifically. ``None``
        # (unset) is dropped below so the workspace keeps inheriting the global.
        "telemetry": _workspace_telemetry_preference_for_save(shell),
        # A derived mirror of the policy's environment (``scan_controls.workspace_type``)
        # for the web and older readers. It is never read back as the type: on
        # load it is only a migration input for a workspace without a policy.
        "type": getattr(shell, "type", None),
        "lab_provider": getattr(shell, "lab_provider", None),
        "lab_name": getattr(shell, "lab_name", None),
        "lab_name_whitelisted": getattr(shell, "lab_name_whitelisted", None),
        "lab_confirmation_state": getattr(shell, "lab_confirmation_state", None),
        "lab_inference_source": getattr(shell, "lab_inference_source", None),
        "lab_inference_confidence": getattr(shell, "lab_inference_confidence", None),
        "password_spraying_history": getattr(shell, "password_spraying_history", {}),
        "cracking_history": getattr(shell, "cracking_history", {}),
        "listener_callback_history": getattr(shell, "listener_callback_history", {}),
        # The workspace's scan pace REQUEST (level + knob overrides), set with
        # ``set pacing`` or by a run. Dropped below when unset, so a workspace
        # without one keeps following the default and any policy's pace.
        "pacing": _workspace_pacing_for_save(shell),
        # Automatic reversion of ADscan's directory changes, set with
        # ``set auto_revert on|off``. Dropped when unset so the workspace keeps
        # the type default (on for audit, off for ctf).
        "auto_revert": _workspace_auto_revert_for_save(shell),
    }
    # The client's cleanup-only account, serialized by its own store (the only
    # reader and writer of the value). Absent when the workspace saved none.
    cleanup_state = _cleanup_credentials_for_save()
    if cleanup_state is not None:
        workspace_vars[_CLEANUP_CREDENTIALS_KEY] = cleanup_state
    if workspace_vars.get("pacing") is None:
        workspace_vars.pop("pacing", None)
    if workspace_vars.get("auto_revert") is None:
        workspace_vars.pop("auto_revert", None)

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

    # An UNSET workspace telemetry preference is represented by the ABSENCE of
    # the key (not a frozen boolean), so it keeps inheriting the global default.
    if workspace_vars.get("telemetry") is None:
        workspace_vars.pop("telemetry", None)

    return workspace_vars


def collect_domain_variables_from_shell(shell: Any) -> dict[str, Any]:
    """Collect domain-level variables for the per-domain snapshot file.

    This payload is written to ``<workspace>/domains/<domain>/variables.json`` and
    is **write-only** — nothing in ADscan loads it back into a shell. It is a
    flattened point-in-time view (no ``domains_data``, no ``domains``), so it can
    never serve as the credential store; the workspace-root ``variables.json`` is
    the single source of truth. The payload carries a ``_snapshot_note`` saying so,
    because a stale copy of it has already cost a debugging cycle.
    """
    domain = getattr(shell, "current_domain", None)
    variables: dict[str, Any] = {
        "hosts": getattr(shell, "hosts", None),
        "myip": getattr(shell, "myip", None),
        "myip_source": getattr(shell, "myip_source", None),
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
    # Stamped last so a domain entry can never overwrite it.
    variables["_snapshot_note"] = DOMAIN_SNAPSHOT_NOTE
    return variables


def apply_workspace_variables_to_shell(
    shell: Any,
    variables: dict[str, Any],
    *,
    reset_missing_to_defaults: bool = False,
) -> None:
    """Apply loaded workspace variables to the CLI shell instance.

    Legacy BloodHound/Neo4j keys are stripped before application so older
    workspaces load cleanly against the current shell schema.

    Args:
        shell: CLI shell instance to populate.
        variables: Parsed payload to apply.
        reset_missing_to_defaults: When ``True``, every schema key absent from
            ``variables`` is reset to its default. Only a load of a workspace-root
            ``variables.json`` may ask for this — see below.

    Why the default is ``False``. This helper is a blunt ``setattr`` loop, and the
    defaults it can apply include ``domains_data={}`` and ``domains=[]`` — the
    in-memory credential store and domain list for the whole engagement. Applying
    those defaults from a payload that simply does not carry the keys empties the
    store in memory, and the next ``save_workspace_data()`` (the hot-path autosave,
    called from dozens of places) then persists the empty store over the
    workspace-root ``variables.json``, destroying every captured credential with
    no way back. That is exactly what happened when a flattened per-domain
    snapshot was fed in here.

    So a partial payload applies only what it actually carries. A genuine
    workspace-root load asks for the reset explicitly, because switching
    workspaces must not leak the previous workspace's state into the new one.
    Forgetting the flag leaves a stale value behind; passing it wrongly destroys
    data, so the harmless mistake is the default.
    """
    if isinstance(variables, dict):
        variables, migrated = migrate_legacy_workspace_state(variables)
        if migrated:
            workspace_label = variables.get("current_workspace") or "workspace"
            print_info_verbose(
                f"Migrated legacy BloodHound/Neo4j state keys for {workspace_label}"
            )
        _restore_cleanup_credentials(
            variables, reset_missing_to_defaults=reset_missing_to_defaults
        )
    defaults: dict[str, Any] = {
        "hosts": None,
        "myip": None,
        "myip_source": None,
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
        "domains_data": CaseInsensitiveDict(),
        "domain_connectivity": {},
        "auto": False,
        # Handled out of band by ``_apply_telemetry_preference_to_shell`` below;
        # listed here so the schema stays complete.
        "telemetry": True,
        # Never applied to the shell: the type is derived from the scan policy.
        # The stored value reaches ``apply_workspace_scan_controls`` as a
        # migration input only (``workspaces/loader.py``).
        "type": None,
        "lab_provider": None,
        "lab_name": None,
        "lab_name_whitelisted": None,
        "lab_confirmation_state": None,
        "lab_inference_source": None,
        "lab_inference_confidence": None,
        "password_spraying_history": {},
        "cracking_history": {},
        "listener_callback_history": {},
        "auto_revert": None,
    }

    for key, default in defaults.items():
        if key in ("telemetry", "type"):
            continue
        if key in variables:
            value = variables.get(key)
            # ``domains_data`` is the case-insensitive SSOT, but ``json.load``
            # returns a plain ``dict``. Re-wrap it here (the load seam) so the
            # reloaded map resolves keys regardless of case — otherwise every
            # workspace load silently reverts the shell to a plain ``dict``.
            if key == "domains_data" and not isinstance(value, CaseInsensitiveDict):
                value = CaseInsensitiveDict(value or {})
            setattr(shell, key, value)
        elif reset_missing_to_defaults:
            setattr(shell, key, default)

    # Telemetry is resolved, not copied: the persisted workspace value is only
    # one of the two inputs (the global opt-out is the other, and it wins). It is
    # resolved on every apply regardless of ``reset_missing_to_defaults`` — the
    # effective state is a live function of the global preference, so leaving a
    # previous workspace's resolved value in place would be wrong, and a boolean
    # preference is not part of the data-loss class the flag guards.
    _apply_telemetry_preference_to_shell(shell, variables.get("telemetry"))
    _apply_workspace_pacing_to_shell(
        shell, variables, reset_missing_to_defaults=reset_missing_to_defaults
    )

    domains_data = getattr(shell, "domains_data", None)
    if isinstance(domains_data, dict):
        for _, domain_data in domains_data.items():
            if isinstance(domain_data, dict):
                domain_data.pop("credential_previews", None)


__all__ = [
    "DOMAIN_SNAPSHOT_NOTE",
    "WRITE_ONLY_WORKSPACE_KEYS",
    "apply_workspace_variables_to_shell",
    "collect_domain_variables_from_shell",
    "collect_workspace_variables_from_shell",
    "migrate_legacy_attack_graph",
    "migrate_legacy_workspace_state",
]
