"""Materialize NTLMv1 coerce→relay / offline-crack attack steps into the graph.

Sub-project #3 (+ refinement 2026-06-02b). Reads the per-host NTLMv1 verdicts
written by sub-project #2 (``domains_data[domain]["ntlm_auth_type_by_host"]`` —
see ``adscan_internal/cli/ntlm_capture.py``) and, for each host that
authenticates with NTLMv1, materializes:

* the ``Ntlmv1Enabled`` surface marker (a finding on its own — like the CVE
  scanner's ``PrinterBugSurface``), as a derived edge ``ADscan → Computer X``;
* three THEORETICAL escalation edges ``Domain Users → Computer X``:
  ``Ntlmv1RelayRBCD`` (admin-capability → DumpLSA chains),
  ``Ntlmv1RelayShadowCreds`` (credential-granting → no DumpLSA), and
  ``CrackNTLMv1`` (offline crack — the most universal avenue, no relay target,
  no reflection/signing/CBT/ADCS dependency → credential-granting, no DumpLSA).

The three escalation edges are ``EdgeKind.ESCALATION``, so they cannot go
through ``insert_derived_edge`` (which only accepts ``EdgeKind.DERIVED``); the
persistence function writes them straight to ``attack_graph.json`` with the
same idempotent signature pattern used by ``attack_graph_derived``. The planning
function (:func:`plan_ntlmv1_relay_edges`) is pure (no disk) so it is
unit-testable.

Reflection gate (refinement 1): NTLM relay cannot be reflected to the SAME host
(post-CVE-2019-1384 reflection mitigations), so both RELAY edges require a relay
target distinct from the coerced node. When the coerced node is the only DC in
the domain, no eligible relay target exists and both relay edges are emitted
``blocked`` (never silently dropped). ``CrackNTLMv1`` is exempt — it has no relay
target.

Blocked-state evaluation (``status="blocked"`` + ``notes["blocked_reason"]``) is
wired in via the ``feasibility_for_host`` callback; :func:`compute_host_feasibility`
builds that callback's verdicts from ``relay_feasibility.evaluate_relay_feasibility``
(the single source of truth for relay viability) plus the reflection gate.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_exception, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.attack_paths_materialized_cache import (
    invalidate_attack_path_artifacts,
)
from adscan_internal.models.domain import resolve_dc_ip
from adscan_internal.workspaces import domain_subpath

_RBCD_BADGE = "Local Admin via NTLMv1→RBCD relay"
_SHADOW_BADGE = "Computer credential via NTLMv1→Shadow Creds relay"
_CRACK_BADGE = "Machine credential via NTLMv1 offline crack"

# Relay status / blocked-reason strings live in the lean ``relay_status_constants``
# leaf so client-facing report code can reference them without importing this
# heavy relay-graph engine (the appliance-backend bundling taproot). Re-exported
# here for backward-compat — internal uses below and the L1 tests import them
# from this module. See ``relay_status_constants`` for the doctrine comments.
from adscan_internal.services.relay_status_constants import (  # noqa: F401,E402
    CONFIGURATION_CLOSE_STATUS,
    NO_RELAY_TARGET_REASON,
    REFLECTION_BLOCKED_REASON,
)

# The RBCD block reason that is a PARTIAL close (MAQ==0 → cannot mint a new
# delegate account, but RBCD via an already-controlled computer account still
# works). Imported from the feasibility SSOT so there is no second copy of the
# string; the builder routes it to ``theoretical`` (conditionally open), NEVER the
# positive ``closed_by_configuration``.
from adscan_internal.services.relay.relay_feasibility import (  # noqa: E402
    MAQ_EXHAUSTED_REASON as _MAQ_EXHAUSTED_REASON,
)


# A per-host feasibility verdict supplied by Task 4 / R3. ``None`` for a method
# means "viable / theoretical"; a non-empty string is the blocked reason. The
# ``"crack"`` key is always present and (when NTLMv1 is observed) always ``None``
# — the offline crack carries none of the relay gates.
HostFeasibility = Mapping[str, Optional[str]]  # {"rbcd"|"shadow_credentials"|"crack": reason|None}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _select_relay_target(
    *,
    coerced_node_id: str,
    coerced_is_dc: bool,
    dc_nodes: Sequence[Mapping[str, Any]],
) -> tuple[Optional[str], Optional[str]]:
    """Pick the LDAP relay-target DC for a coerced node (reflection gate).

    NTLM relay cannot be reflected to the coerced host itself, so the relay
    target must be a DC whose node id differs from the coerced node.

    Args:
        coerced_node_id: Canonical node id of the coerced (NTLMv1) host.
        coerced_is_dc: Whether the coerced host is itself a DC
            (``primarygroupid == 516``).
        dc_nodes: The domain's DC node set — each a mapping with at least
            ``"id"`` and ``"fqdn"``.

    Returns:
        ``(relay_target_fqdn, blocked_reason)``. ``blocked_reason`` is set iff
        ``relay_target_fqdn`` is ``None`` (no eligible target). A topologically
        eligible DC whose ``fqdn`` is missing/empty is NOT a usable relay
        endpoint, so it yields ``(None, NO_RELAY_TARGET_REASON)`` rather than
        ``(None, None)`` — the latter would emit a silently-broken edge that
        looks viable but cannot execute (no relay target, no blocked reason).
    """
    if not coerced_is_dc:
        # Any DC is a valid target; a non-DC coerced node can never equal a DC
        # node, so the reflection constraint is trivially satisfied.
        if dc_nodes:
            fqdn = str(dc_nodes[0].get("fqdn") or "").strip()
            if fqdn:
                return fqdn, None
            # Eligible DC exists but has no usable LDAP endpoint → block, don't
            # silently emit a target-less "theoretical" edge.
            return None, NO_RELAY_TARGET_REASON
        return None, NO_RELAY_TARGET_REASON
    # Coerced node IS a DC → need a DIFFERENT DC as the relay target.
    other_dcs = [d for d in dc_nodes if str(d.get("id") or "") != str(coerced_node_id or "")]
    if other_dcs:
        fqdn = str(other_dcs[0].get("fqdn") or "").strip()
        if fqdn:
            return fqdn, None
        # A different DC exists but its FQDN is empty → no usable relay endpoint.
        return None, NO_RELAY_TARGET_REASON
    return None, REFLECTION_BLOCKED_REASON


def _escalation_edge(
    *,
    relation: str,
    technique: str,
    source: str,
    target: str,
    relay_target_fqdn: Optional[str],
    privilege_badge: str,
    blocked_reason: Optional[str],
) -> dict[str, Any]:
    notes: dict[str, Any] = {
        "technique": technique,
        "privilege_badge": privilege_badge,
    }
    if relay_target_fqdn:
        notes["relay_target"] = relay_target_fqdn
    status = "theoretical"
    if blocked_reason == NO_RELAY_TARGET_REASON:
        # ADscan data-gap (no usable relay target resolved) — not a client
        # control. Surface as a data-gap, never as a defensive close.
        notes["blocked_reason"] = blocked_reason
        status = "unsupported"
    elif blocked_reason == _MAQ_EXHAUSTED_REASON:
        # PARTIAL close only: MAQ==0 blocks minting a NEW delegate account, but
        # RBCD via an already-controlled computer account still works — the avenue
        # is NOT closed. Keep it theoretical (conditionally open) with a caveat,
        # NEVER the positive closed_by_configuration (that would over-credit a
        # defense the client does not fully have). No ``blocked_reason`` is set so
        # the render never frames it as "attack surface reduced".
        notes["caveat"] = (
            "Requires an already-controlled computer account: MachineAccountQuota "
            "is 0, so a new delegate account cannot be minted, but an existing "
            "owned computer account still enables this avenue."
        )
    elif blocked_reason:
        # Closed by configuration/topology observed with certainty (LDAP signing +
        # channel binding, no ADCS, single-DC reflection). A POSITIVE exposure fact
        # — never claim a defensive tool stopped it.
        notes["blocked_reason"] = blocked_reason
        status = CONFIGURATION_CLOSE_STATUS
    # The DFS adjacency reads ``from`` / ``to`` (the universal edge convention in
    # attack_graph.json); ``source`` / ``target`` are kept as aliases for callers
    # that read either form.
    return {
        "from": source,
        "to": target,
        "source": source,
        "target": target,
        "relation": relation,
        "kind": "escalation",
        "status": status,
        "notes": notes,
    }


def plan_ntlmv1_relay_edges(
    *,
    ntlm_auth_type_by_host: Mapping[str, Mapping[str, Any]],
    domain_users_label: str,
    relay_target_fqdn: str,
    computer_label_for_ip: Callable[[str], str],
    feasibility_for_host: Optional[Callable[[str], HostFeasibility]] = None,
    dc_nodes: Optional[Sequence[Mapping[str, Any]]] = None,
    coerced_node_meta_for_ip: Optional[Callable[[str], Mapping[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Return the surface + escalation edges for every NTLMv1 host (pure, no disk).

    Args:
        ntlm_auth_type_by_host: The #2→#3 seam — ``{ip: {"ntlm_auth_type": ...}}``.
        domain_users_label: Canonical ``Domain Users@DOMAIN`` source node label.
        relay_target_fqdn: Default DC used as the relay target (FQDN). Overridden
            per-host by the reflection gate when ``dc_nodes`` /
            ``coerced_node_meta_for_ip`` are supplied.
        computer_label_for_ip: Resolver IP → canonical Computer node label
            (``""`` when the IP has no Computer node in the graph — skip it).
        feasibility_for_host: Optional callback IP → ``{"rbcd": reason|None,
            "shadow_credentials": reason|None, "crack": reason|None}``; a reason
            string blocks that method. ``None`` → every method theoretical.
        dc_nodes: The domain DC node set (``primarygroupid == 516``), each a
            mapping with ``"id"`` / ``"fqdn"``. When provided, the reflection
            gate selects the relay target per host; when ``None`` the
            ``relay_target_fqdn`` default is used and the gate is not applied.
        coerced_node_meta_for_ip: Resolver IP → ``{"id": ..., "is_dc": bool}``
            for the coerced node, used by the reflection gate. ``None`` → the
            coerced node is treated as a non-DC (relay target always eligible).

    Returns:
        A list of edge dicts (surface marker + three escalation edges per
        NTLMv1 host with a resolvable Computer node).
    """
    edges: list[dict[str, Any]] = []
    dc_node_seq: Sequence[Mapping[str, Any]] = dc_nodes or ()
    for ip, verdict in (ntlm_auth_type_by_host or {}).items():
        if not isinstance(verdict, Mapping):
            continue
        if str(verdict.get("ntlm_auth_type") or "").strip() != "NTLMv1":
            continue
        computer_label = str(computer_label_for_ip(ip) or "").strip()
        if not computer_label:
            # No Computer node for this IP → a relay edge would be a DFS orphan.
            continue

        feas: HostFeasibility = (
            feasibility_for_host(ip) if feasibility_for_host is not None else {}
        )

        # --- Reflection gate: per-host relay-target selection. ---------------
        reflection_reason: Optional[str] = None
        host_relay_target = str(relay_target_fqdn or "").strip() or None
        if dc_nodes is not None:
            coerced_meta: Mapping[str, Any] = (
                coerced_node_meta_for_ip(ip)
                if coerced_node_meta_for_ip is not None
                else {}
            ) or {}
            coerced_node_id = str(coerced_meta.get("id") or computer_label)
            coerced_is_dc = bool(coerced_meta.get("is_dc"))
            host_relay_target, reflection_reason = _select_relay_target(
                coerced_node_id=coerced_node_id,
                coerced_is_dc=coerced_is_dc,
                dc_nodes=dc_node_seq,
            )

        def _relay_block_reason(method_key: str) -> Optional[str]:
            # The reflection gate (and the no-usable-target case it also covers)
            # blocks RELAY edges only; its reason takes precedence so the report
            # shows the topology control first.
            if reflection_reason:
                return reflection_reason
            return feas.get(method_key)

        # Surface marker — always materialized (finding on its own).
        edges.append(
            {
                "from": "ADscan",
                "to": computer_label,
                "source": "ADscan",
                "target": computer_label,
                "relation": "Ntlmv1Enabled",
                "kind": "derived",
                "status": "theoretical",
                "notes": {"observed_on_ip": ip},
            }
        )
        # RBCD relay edge (reflection-gated).
        edges.append(
            _escalation_edge(
                relation="Ntlmv1RelayRBCD",
                technique="rbcd",
                source=domain_users_label,
                target=computer_label,
                relay_target_fqdn=host_relay_target,
                privilege_badge=_RBCD_BADGE,
                blocked_reason=_relay_block_reason("rbcd"),
            )
        )
        # Shadow Credentials relay edge (reflection-gated).
        edges.append(
            _escalation_edge(
                relation="Ntlmv1RelayShadowCreds",
                technique="shadow_credentials",
                source=domain_users_label,
                target=computer_label,
                relay_target_fqdn=host_relay_target,
                privilege_badge=_SHADOW_BADGE,
                blocked_reason=_relay_block_reason("shadow_credentials"),
            )
        )
        # Offline crack edge — NO relay target, exempt from the reflection gate.
        edges.append(
            _escalation_edge(
                relation="CrackNTLMv1",
                technique="crack",
                source=domain_users_label,
                target=computer_label,
                relay_target_fqdn=None,
                privilege_badge=_CRACK_BADGE,
                blocked_reason=feas.get("crack"),
            )
        )
    return edges


def _attack_graph_path(shell: object, domain: str) -> Path:
    workspace_dir = getattr(shell, "current_workspace_dir", "") or ""
    domains_dir = getattr(shell, "domains_dir", "domains")
    return Path(domain_subpath(workspace_dir, domains_dir, domain, "attack_graph.json"))


def _edge_signature(edge: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(edge.get("from") or edge.get("source") or ""),
        str(edge.get("relation") or ""),
        str(edge.get("to") or edge.get("target") or ""),
    )


def persist_ntlmv1_relay_edges(
    *,
    shell: object,
    domain: str,
    edges: list[dict[str, Any]],
) -> int:
    """Write the planned edges into ``attack_graph.json`` (idempotent).

    Updates an existing edge in place when its ``(source, relation, target)``
    signature already exists (so a re-run that flips a status theoretical→blocked
    or →exploited overwrites cleanly). Returns the number of edges written.
    """
    if not edges:
        return 0
    graph_path = _attack_graph_path(shell, domain)
    graph_path.parent.mkdir(parents=True, exist_ok=True)

    graph: dict[str, Any]
    if graph_path.exists():
        try:
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
            if not isinstance(graph, dict):
                graph = {"nodes": [], "edges": []}
        except (OSError, ValueError, TypeError):
            graph = {"nodes": [], "edges": []}
    else:
        graph = {"nodes": [], "edges": []}
    graph.setdefault("nodes", [])
    edges_list = graph.setdefault("edges", [])
    if not isinstance(edges_list, list):
        edges_list = []
        graph["edges"] = edges_list

    index: dict[tuple[str, str, str], int] = {}
    for pos, existing in enumerate(edges_list):
        if isinstance(existing, Mapping):
            index[_edge_signature(existing)] = pos

    written = 0
    for edge in edges:
        edge = {**edge, "recorded_at": _utc_now_iso()}
        sig = _edge_signature(edge)
        if sig in index:
            edges_list[index[sig]] = edge
        else:
            index[sig] = len(edges_list)
            edges_list.append(edge)
        written += 1

    try:
        graph_path.write_text(
            json.dumps(graph, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            f"[ntlmv1_relay_graph_builder] failed to write attack_graph.json: {exc}"
        )
        return 0

    try:
        invalidate_attack_path_artifacts(shell, domain)
    except Exception as exc:  # noqa: BLE001 — telemetry sink
        telemetry.capture_exception(exc)
        print_exception(exception=exc)

    print_info_verbose(
        f"[ntlmv1_relay_graph_builder] materialized {written} NTLMv1 attack "
        f"edge(s) for {mark_sensitive(domain, 'domain')}"
    )
    return written


def compute_host_feasibility(
    *,
    domains_data: Optional[Mapping[str, Any]],
    domain: str,
    dc_host: str,
    ntlmv1_observed: bool,
    adcs_pki_present: Optional[bool],
    machine_account_quota: Optional[int],
) -> dict[str, Optional[str]]:
    """Return ``{"rbcd"|"shadow_credentials"|"crack": reason|None}``.

    Reuses ``relay_feasibility.evaluate_relay_feasibility`` (the single source of
    truth for relay viability) for the two RELAY methods. A non-None reason marks
    that method ``blocked``. Per spec §8:

    * a blocking verdict that is NOT method-specific (LDAP signing/CBT, NTLM
      disabled, no viable relay target) blocks BOTH relay methods;
    * ``adcs_pki_present`` False blocks ShadowCreds only (needs PKINIT);
    * ``machine_account_quota`` exhausted blocks RBCD only.

    ``CrackNTLMv1`` (the ``"crack"`` key) carries none of the relay gates — it is
    ``None`` (viable) whenever ``ntlmv1_observed`` is True, independent of
    signing/CBT/ADCS/MAQ/reflection (the crack is offline). It is the floor of
    the NTLMv1 finding's exploitability: the one avenue still open when every
    relay path is blocked.
    """
    from adscan_internal.services.relay.relay_feasibility import (  # noqa: PLC0415
        NtlmAuthVerdict,
        RelayFeasibilityInputs,
        evaluate_relay_feasibility,
    )

    ntlm_auth = NtlmAuthVerdict(ntlmv1_observed=bool(ntlmv1_observed))

    def _block_reason_for(method: str) -> Optional[str]:
        inputs = RelayFeasibilityInputs(
            domains_data=domains_data,
            domain=domain,
            dc_host=dc_host,
            method=method,  # "rbcd" | "shadow_creds" (RelayMethod literal)
            ntlm_auth=ntlm_auth,
            adcs_pki_present=adcs_pki_present,
            machine_account_quota=machine_account_quota,
        )
        result = evaluate_relay_feasibility(inputs)
        if result.viable:
            return None
        blocking = result.blocking_verdicts
        if not blocking:
            return None
        return blocking[0].why

    # CrackNTLMv1: offline once captured → always viable when NTLMv1 is observed.
    crack_reason: Optional[str] = None
    if not ntlmv1_observed:
        crack_reason = "NTLMv1 not observed on this host"

    return {
        "rbcd": _block_reason_for("rbcd"),
        # Feasibility framework keys shadow creds as "shadow_creds" (underscore);
        # the builder's notes["technique"] uses "shadow_credentials".
        "shadow_credentials": _block_reason_for("shadow_creds"),
        "crack": crack_reason,
    }


# --------------------------------------------------------------------------- #
# Orchestration wrapper — the production caller of the pure planner.
#
# ``plan_ntlmv1_relay_edges`` / ``compute_host_feasibility`` are pure (no disk,
# no network). The wrapper below does ALL the I/O wiring they need: it reads the
# LIVE attack graph + ``domains_data`` + posture, resolves the real graph node
# ids (the DFS keys edges on node ids — ``name:meereen$``, ``name:<domsid>-513``
# — NOT on the human label), builds the reflection-gate inputs from the existing
# DC marker (``primarygroupid == 516``), then calls the planner and persists.
#
# Resolving every id against the SAME node set the DFS reads is the single
# guarantee that the materialized edges are traversable rather than DFS orphans.
# We never reconstruct ids from heuristics — the graph nodes are the source of
# truth (``properties.ip_address``, ``properties.primarygroupid``,
# ``properties.dnshostname``, the well-known ``-513`` Domain Users group node).
# --------------------------------------------------------------------------- #

_DOMAIN_CONTROLLERS_RID = 516  # mirrors collector/persistence.py marker
_DOMAIN_USERS_RID_SUFFIX = "-513"  # well-known Domain Users group RID


def _graph_nodes_as_mapping(graph: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Return the graph node set as ``{node_id: node}``.

    The live ``attack_graph.json`` stores ``nodes`` as a dict keyed by node id;
    older artefacts may store a list of node dicts (each carrying its own
    ``"id"``). Normalise both to the dict form so the resolvers below have one
    shape to read.
    """
    nodes = graph.get("nodes")
    out: dict[str, Mapping[str, Any]] = {}
    if isinstance(nodes, Mapping):
        for nid, node in nodes.items():
            if isinstance(node, Mapping):
                out[str(node.get("id") or nid)] = node
    elif isinstance(nodes, list):
        for node in nodes:
            if isinstance(node, Mapping):
                nid = str(node.get("id") or "")
                if nid:
                    out[nid] = node
    return out


def _node_primary_group_id(node: Mapping[str, Any]) -> Optional[int]:
    props = node.get("properties")
    if not isinstance(props, Mapping):
        return None
    raw = props.get("primarygroupid")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _node_is_dc(node: Mapping[str, Any]) -> bool:
    """A Computer node is a DC when ``primarygroupid == 516`` (the collector marker)."""
    return _node_primary_group_id(node) == _DOMAIN_CONTROLLERS_RID


def _node_fqdn(node: Mapping[str, Any]) -> str:
    """Best FQDN for a (DC) node — ``dnshostname`` is the canonical relay endpoint."""
    props = node.get("properties")
    if isinstance(props, Mapping):
        fqdn = str(props.get("dnshostname") or "").strip()
        if fqdn:
            return fqdn
    return ""


def _resolve_graph_resolvers(
    graph: Mapping[str, Any],
) -> tuple[dict[str, str], str, list[dict[str, str]]]:
    """Derive ``(ip→node_id, domain_users_node_id, dc_nodes)`` from the live graph.

    All three are read straight from the node set the DFS traverses, so any edge
    the planner emits using these ids is guaranteed to connect to a real node
    (no orphan). Returns ``""`` for the Domain Users id when no such node exists;
    the caller skips materialization in that case (the escalation edges would
    have no traversable source).
    """
    nodes = _graph_nodes_as_mapping(graph)

    ip_to_node_id: dict[str, str] = {}
    domain_users_node_id = ""
    dc_nodes: list[dict[str, str]] = []

    for node_id, node in nodes.items():
        props = node.get("properties")
        props = props if isinstance(props, Mapping) else {}

        # IP → computer node id (the DFS endpoint). First node wins per IP.
        ip_value = str(props.get("ip_address") or "").strip()
        if ip_value and ip_value not in ip_to_node_id:
            ip_to_node_id[ip_value] = node_id

        # Domain Users group node (well-known ``<domain_sid>-513``).
        if not domain_users_node_id:
            object_id = str(node.get("objectId") or props.get("objectid") or "").strip()
            label = str(node.get("label") or "").strip().upper()
            kind = str(node.get("kind") or "").strip().lower()
            if object_id.upper().endswith(_DOMAIN_USERS_RID_SUFFIX) or (
                kind == "group" and label.startswith("DOMAIN USERS@")
            ):
                domain_users_node_id = node_id

        # DC node set (reflection gate + default relay target).
        if _node_is_dc(node):
            dc_nodes.append({"id": node_id, "fqdn": _node_fqdn(node)})

    return ip_to_node_id, domain_users_node_id, dc_nodes


def _adcs_pki_present_from_workspace(shell: object, domain: str) -> Optional[bool]:
    """Best-effort read of whether a CA / NTAuth PKI is present for the domain.

    Mirrors the canonical reader in ``relay_rbcd.py`` (no network): returns
    ``True`` when an enterprise CA is recorded, else ``None`` (unknown). RBCD
    does not need PKI, so ``None`` is a caveat there; for Shadow Creds the
    feasibility framework treats an explicit ``False`` as blocking and ``None``
    as a caveat. We never assert ``False`` from absence — that would be
    inferring-by-absence (see CLAUDE.md posture caching policy).
    """
    domain_data = (getattr(shell, "domains_data", {}) or {}).get(domain) or {}
    adcs = domain_data.get("adcs") or domain_data.get("certipy") or {}
    if isinstance(adcs, Mapping) and adcs:
        cas = adcs.get("certificate_authorities") or adcs.get("cas") or adcs.get("ca")
        if cas:
            return True
    return None


def _machine_account_quota_for(
    shell: object, *, domain: str, username: str
) -> Optional[int]:
    """Return a MAQ value for feasibility from PERSISTED state (no network probe).

    The materialization wrapper must not authenticate, so we read the persisted
    MAQ-exhausted verdict rather than re-probing LDAP. ``0`` when the actor is
    recorded as exhausted (blocks the RBCD create-new-delegate branch), else
    ``None`` (unknown → a warning, RBCD stays theoretical). Never blocks Shadow
    Creds or Crack.
    """
    if not username:
        return None
    try:
        from adscan_internal.services.machine_account_quota_state_service import (  # noqa: PLC0415
            is_machine_account_quota_exhausted,
        )

        if is_machine_account_quota_exhausted(shell, domain=domain, username=username):
            return 0
    except Exception as exc:  # noqa: BLE001 — best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    return None


def materialize_ntlmv1_relay_edges(shell: object, domain: str) -> int:
    """Materialize the NTLMv1 attack steps into ``attack_graph.json`` (I/O wrapper).

    Reads the persisted per-host NTLMv1 verdicts
    (``domains_data[domain]["ntlm_auth_type_by_host"]`` — the #2→#3 seam),
    resolves the live graph node ids, computes per-host feasibility (reusing the
    single-source-of-truth :func:`compute_host_feasibility` /
    ``relay_feasibility.evaluate_relay_feasibility``), and persists the surface
    marker + three escalation edges per NTLMv1 host.

    Non-destructive, idempotent (:func:`persist_ntlmv1_relay_edges` updates edges
    in place by ``(source, relation, target)`` signature), prompt-free, and
    posture-aware — safe to call from the sweep, the DC-only quick win, and under
    ``adscan ci``. Best-effort: any failure is captured to telemetry and returns
    ``0`` rather than aborting the caller.

    Args:
        shell: The ADscan shell (provides ``domains_data`` + workspace dirs).
        domain: Target domain whose graph is materialized.

    Returns:
        The number of edges written (0 when there is nothing to materialize or
        on a handled failure).
    """
    try:
        domains_data = getattr(shell, "domains_data", {}) or {}
        domain_state = domains_data.get(domain) or {}
        host_map = domain_state.get("ntlm_auth_type_by_host") or {}
        if not isinstance(host_map, Mapping) or not host_map:
            return 0

        # Short-circuit when no host actually speaks NTLMv1 — avoid loading the
        # graph for nothing.
        has_ntlmv1 = any(
            isinstance(verdict, Mapping)
            and str(verdict.get("ntlm_auth_type") or "").strip() == "NTLMv1"
            for verdict in host_map.values()
        )
        if not has_ntlmv1:
            return 0

        graph_path = _attack_graph_path(shell, domain)
        if not graph_path.exists():
            print_info_verbose(
                "[ntlmv1_relay_graph_builder] no attack_graph.json yet for "
                f"{mark_sensitive(domain, 'domain')}; skipping NTLMv1 materialization"
            )
            return 0
        try:
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
            if not isinstance(graph, dict):
                return 0
        except (OSError, ValueError, TypeError) as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return 0

        ip_to_node_id, domain_users_node_id, dc_nodes = _resolve_graph_resolvers(graph)
        if not domain_users_node_id:
            # Without the real Domain Users node the escalation edges would be
            # DFS orphans (no traversable source) — do not emit them.
            print_info_verbose(
                "[ntlmv1_relay_graph_builder] Domain Users node absent from the "
                f"graph for {mark_sensitive(domain, 'domain')}; skipping NTLMv1 "
                "materialization (edges would be orphans)"
            )
            return 0

        # Default relay target (overridden per-host by the reflection gate using
        # dc_nodes). The first DC with a usable FQDN is the conservative default.
        default_relay_target = ""
        for dc in dc_nodes:
            if dc.get("fqdn"):
                default_relay_target = str(dc["fqdn"])
                break

        dc_host = str(resolve_dc_ip(domain_state) or "").strip()
        actor_username = str(domain_state.get("username") or "").strip()
        adcs_pki_present = _adcs_pki_present_from_workspace(shell, domain)
        maq_value = _machine_account_quota_for(
            shell, domain=domain, username=actor_username
        )
        nodes_by_id = _graph_nodes_as_mapping(graph)

        def _computer_label_for_ip(ip: str) -> str:
            return ip_to_node_id.get(str(ip).strip(), "")

        def _coerced_node_meta_for_ip(ip: str) -> Mapping[str, Any]:
            node_id = ip_to_node_id.get(str(ip).strip(), "")
            node = nodes_by_id.get(node_id) or {}
            return {"id": node_id, "is_dc": _node_is_dc(node) if node else False}

        def _feasibility_for_host(ip: str) -> dict[str, Optional[str]]:
            verdict = host_map.get(ip) or {}
            observed = (
                isinstance(verdict, Mapping)
                and str(verdict.get("ntlm_auth_type") or "").strip() == "NTLMv1"
            )
            return compute_host_feasibility(
                domains_data=domains_data,
                domain=domain,
                dc_host=dc_host,
                ntlmv1_observed=observed,
                adcs_pki_present=adcs_pki_present,
                machine_account_quota=maq_value,
            )

        edges = plan_ntlmv1_relay_edges(
            ntlm_auth_type_by_host=host_map,
            domain_users_label=domain_users_node_id,
            relay_target_fqdn=default_relay_target,
            computer_label_for_ip=_computer_label_for_ip,
            feasibility_for_host=_feasibility_for_host,
            dc_nodes=dc_nodes,
            coerced_node_meta_for_ip=_coerced_node_meta_for_ip,
        )
        return persist_ntlmv1_relay_edges(shell=shell, domain=domain, edges=edges)
    except Exception as exc:  # noqa: BLE001 — best-effort, never abort the caller
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(
            "[ntlmv1_relay_graph_builder] NTLMv1 materialization failed: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
        return 0


__all__ = [
    "plan_ntlmv1_relay_edges",
    "persist_ntlmv1_relay_edges",
    "compute_host_feasibility",
    "materialize_ntlmv1_relay_edges",
    "REFLECTION_BLOCKED_REASON",
    "NO_RELAY_TARGET_REASON",
]

