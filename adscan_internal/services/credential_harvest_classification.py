"""Tier + Compromise-Reach classification for harvested principals.

Dispatches by account type (:func:`captured_credential_policy.classify_principal`
— the sub-project A SSOT) rather than re-deriving user-vs-machine detection:

* A USER principal's Privilege Tier comes from the batched
  :func:`high_value.classify_users_tier0_high_value` (single graph load,
  proven at spraying-scale) mapped onto the canonical
  :class:`compromise_class.PrivilegeTier` — ``is_tier0`` -> TIER0_DIRECT,
  ``is_high_value`` -> TIER0_ESCALATION_CAPABLE, else TIER2. A captured user
  principal never grades TIER1 by AD semantics (Tier 1 is the server/app-admin
  tier for MACHINES, not domain users) — that is not a gap, it is why machine
  accounts are classified separately below.
* A MACHINE principal's Privilege Tier comes from its computer graph node via
  :func:`compromise_class.privilege_tier_for_computer_node` — the same
  resolver ``cli/intelligence.py`` uses for attack-path targets — so a
  harvested machine credential's host correctly grades TIER1 (member server)
  when applicable, fixing the gap where spraying's user-only classifier never
  covered machine-account harvests (NTLMv1 rainbow-pending, poisoning captures
  of a server's machine account, timeroast).

Compromise Reach is axis 2 — the validated attack-path reach — computed in one
batched call to :func:`attack_graph_service.get_attack_path_summaries` +
the canonical :func:`order_attack_paths_for_display` priority ordering, so the
"best" (highest-priority) path per principal is picked without re-implementing
the choke-point-severity/execution-priority/path-length sort.
"""
from __future__ import annotations

from typing import Any

from adscan_core import telemetry
from adscan_internal.rich_output import order_attack_paths_for_display
from adscan_internal.services.attack_graph_service import (
    get_attack_path_summaries,
    load_attack_graph,
)
from adscan_internal.services.compromise_class import (
    CompromiseClass,
    PrivilegeTier,
    privilege_tier_for_computer_node,
)
from adscan_internal.services.credential_harvest_reach_memo import (
    split_hits_and_misses,
    store_reach,
)
from adscan_internal.services.high_value import (
    is_node_high_value,
    is_node_tier0,
    normalize_samaccountname,
)
from adscan_internal.services.path_renderer import _path_compromise_class
from adscan_internal.services.principal_tier_resolver import resolve_user_privilege_tier


def classify_harvested_principal_tier(
    shell: Any, *, domain: str, username: str, account_type: str
) -> PrivilegeTier | None:
    """Return the :class:`PrivilegeTier` a harvested principal IS GRANTED.

    Dispatches by ``account_type`` (``"user"`` or ``"machine"``, from
    :func:`captured_credential_policy.classify_principal`). Never raises.

    Returns ``None`` (UNDETERMINED) when there is NO real membership data for the
    principal — the state a typical ``start_unauth`` scan is in (no
    ``memberships.json``, only synthetic fallback graph nodes), where every
    principal would otherwise falsely grade ``TIER2: Standard``. A concrete
    :class:`PrivilegeTier` (including :attr:`PrivilegeTier.TIER2`) is returned
    ONLY when the principal HAS real membership data, so a non-Tier-0 verdict is
    trustworthy — the user genuinely is not Tier 0, not merely unclassified.

    Users resolve through the canonical membership->tier SSOT
    (:func:`principal_tier_resolver.resolve_user_privilege_tier`, which reads
    the real ``memberships.json`` MemberOf edges); machines resolve from their
    computer graph node.
    """
    if str(account_type).strip().lower() == "machine":
        return _machine_privilege_tier(shell, domain=domain, username=username)
    return resolve_user_privilege_tier(shell, domain=domain, username=username)


def _machine_privilege_tier(
    shell: Any, *, domain: str, username: str
) -> PrivilegeTier | None:
    hostname = username.strip().rstrip("$")
    if not hostname:
        return None
    node: dict[str, Any] | None = None
    try:
        graph_service_getter = getattr(shell, "_get_graph_service", None)
        graph_service = graph_service_getter() if callable(graph_service_getter) else None
        if graph_service is not None:
            resolver = getattr(graph_service, "get_computer_node_by_name", None)
            if callable(resolver):
                node = resolver(domain, hostname) or resolver(domain, f"{hostname}.{domain}")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        node = None
    # No computer node resolved (no graph / node not yet collected) → the tier
    # is UNDETERMINED, not a false TIER2. A machine's tier is entirely derived
    # from its node (DC vs member server vs workstation), so with no node we
    # genuinely cannot know.
    if node is None:
        return None
    is_tier0_asset = bool(is_node_tier0(node) or is_node_high_value(node))
    return privilege_tier_for_computer_node(node, is_tier0_asset=is_tier0_asset)


def _node_is_synthetic(node: Any) -> bool:
    """Return whether an attack-graph node is a SYNTHETIC fallback placeholder.

    An unauthenticated scan writes synthetic fallback nodes (a stand-in User, a
    ``Domain Users`` Group) marked ``properties.synthetic`` / ``synthetic_source``.
    These are placeholders, not real enumerated data.
    """
    if not isinstance(node, dict):
        return False
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    return bool(node.get("synthetic") or props.get("synthetic") or props.get("synthetic_source"))


def _edge_is_real(edge: Any, synthetic_node_ids: set[str]) -> bool:
    """Return whether an edge reflects a REAL attack surface (non-synthetic).

    True only when the edge is not itself synthetic AND both endpoints are
    non-synthetic nodes. The unauth ASREPRoasting ``entry_vector`` edge connects
    the synthetic ``Domain Users`` fallback node, so it fails this.
    """
    if not isinstance(edge, dict):
        return False
    props = edge.get("properties") if isinstance(edge.get("properties"), dict) else {}
    if edge.get("synthetic") or props.get("synthetic") or props.get("synthetic_source"):
        return False
    src = str(edge.get("from") or edge.get("source") or "")
    dst = str(edge.get("to") or edge.get("target") or "")
    return src not in synthetic_node_ids and dst not in synthetic_node_ids


def _attack_graph_has_data(shell: Any, domain: str) -> bool:
    """Return whether the domain's attack graph holds a REAL (non-synthetic) edge.

    The "reach source populated?" signal for :func:`classify_harvested_principals_reach`:
    reach is a validated attack path, so it is only ASSESSABLE when the graph
    holds at least one edge between REAL (non-synthetic) nodes. A graph of only
    synthetic fallback nodes plus a synthetic-endpoint ``entry_vector`` edge (the
    unauth case) has NO real attack surface → reach is UNDETERMINED — distinct
    from a populated graph where a principal simply has no validated path
    (genuinely "Standard reach"). Best-effort; never raises.
    """
    try:
        graph = load_attack_graph(shell, domain)
        if not isinstance(graph, dict):
            return False
        edges = graph.get("edges")
        if not isinstance(edges, list) or not edges:
            return False
        nodes_map = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
        synthetic_ids = {
            str(nid) for nid, node in nodes_map.items() if _node_is_synthetic(node)
        }
        return any(_edge_is_real(edge, synthetic_ids) for edge in edges)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return False


def classify_harvested_principals_reach(
    shell: Any, *, domain: str, usernames: list[str]
) -> dict[str, CompromiseClass | None]:
    """Return the highest-priority validated Compromise Reach per principal.

    Batched (one attack-path computation for every principal), reusing the
    canonical :func:`order_attack_paths_for_display` priority order — the
    FIRST path per principal in that order is the "best" reach, matching what
    the CLI/report/web already treat as the top path for a principal. Never
    raises.

    A value of ``None`` (UNDETERMINED) is returned for every principal when
    there is no attack-graph/path data at all (an unauthenticated scan, or
    before Attack Paths Discovery has run) — instead of a false
    :attr:`CompromiseClass.NONE` ("Standard reach"), which would wrongly imply
    "assessed, and no path found". When the graph IS populated, a principal
    with no validated path is a genuine :attr:`CompromiseClass.NONE`.

    Returns:
        Mapping keyed by ``normalize_samaccountname(username)``. Every
        requested username is present; the value is a :class:`CompromiseClass`
        when reach was assessed, or ``None`` when it is UNDETERMINED.
    """
    # Map each normalized principal key back to the RAW username form(s) it came
    # from, so a cache-miss recompute feeds the engine the exact same input the
    # unmemoized path would (the engine lower-cases raw forms; passing the
    # normalized key instead could resolve a different graph node — the reach
    # returned MUST be identical to a fresh recompute).
    raw_by_normalized: dict[str, list[str]] = {}
    for raw in usernames:
        key = normalize_samaccountname(raw)
        if key:
            raw_by_normalized.setdefault(key, []).append(raw)
    normalized = sorted(raw_by_normalized)
    if not normalized:
        return {}

    # No attack-graph data → reach is UNDETERMINED for every principal (not a
    # false "Standard reach").
    if not _attack_graph_has_data(shell, domain):
        return {user: None for user in normalized}

    # Per-principal reach memo in front of the set-granular compute cache: reuse
    # any principal already computed under the CURRENT graph epoch, recompute
    # only the misses. Once `eddard` is computed under a graph epoch, every later
    # drain reuses it until `save_attack_graph` bumps the epoch (§ spec). Pure
    # performance — the memoized value is identical to a fresh recompute.
    hits, misses = split_hits_and_misses(shell, domain=domain, principals=normalized)
    best: dict[str, CompromiseClass | None] = dict(hits)
    if not misses:
        return best

    miss_raw_usernames = [raw for key in misses for raw in raw_by_normalized[key]]
    try:
        summaries = get_attack_path_summaries(
            shell,
            domain,
            scope="principals",
            principals=miss_raw_usernames,
            max_depth=10,
            max_paths=None,
            target="all",
            target_mode="object",
        )
        ordered = order_attack_paths_for_display(summaries)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        # Recompute failed for the misses — return UNDETERMINED for them, do NOT
        # memoize a guessed value, and keep any reused hits.
        for user in misses:
            best.setdefault(user, None)
        return best

    miss_set = set(misses)
    computed: dict[str, CompromiseClass | None] = {}
    for path in ordered:
        source_label = normalize_samaccountname(str(path.get("source") or ""))
        if not source_label or source_label not in miss_set or source_label in computed:
            continue
        computed[source_label] = _path_compromise_class(path)
    # Graph is populated → a miss principal with no path has a genuine "Standard
    # reach" (NONE), not UNDETERMINED.
    for user in misses:
        computed.setdefault(user, CompromiseClass.NONE)

    store_reach(shell, domain=domain, reach_by_principal=computed)
    best.update(computed)
    return best
