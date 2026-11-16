"""Choke-point cardinality over the reachable set (set algebra, no enumeration).

When a dense directory graph is routed to the bounded fallback engine, the route
sample is capped, so the client needs a prioritization signal that does NOT
depend on enumerating every route: "which single edge, if removed, severs the
most source -> value-terminal reach?". This is the BloodHound-Enterprise
choke-point idea expressed as *set cardinality over reachability*, which is cheap
because it is set algebra and never touches path enumeration.

This module produces the cardinality DATA only. It performs no scoring, no
ranking, and no rendering (those belong to a later render task, E3). It also
provides a best-effort persistence helper that stamps a compact summary into the
technical report the same way the exposure KPIs are stamped, so a future render
can read it.

Design notes:
    * Works on the PERSISTED graph (``attack_graph.json``), not the DFS-visible
      frontier. It deliberately does NOT reuse
      :func:`attack_graph_core._build_reverse_reachable_node_ids`, which needs
      local-reuse / frontier arguments this module does not have. Instead it
      builds a self-contained forward/reverse adjacency and runs plain BFS.
    * ``Reach^-1(S)`` = every node that can reach some terminal in ``S`` by
      following edges forward toward ``S`` (equivalently, reachable backward from
      ``S`` over the reversed adjacency).
    * Two choke views, both exact set-cardinality (no path enumeration):
        - EDGE choke (:func:`compute_chokepoint_cardinality`): for each edge, how
          many *sources* (leaf originators — reachable nodes with no inbound reach
          edge) have EVERY path to ``S`` traversing it, so cutting that one edge
          severs all of them.
        - NODE choke (:func:`compute_node_chokepoint_cardinality`): for each node,
          how many *source principals* (enabled User/Computer/Group nodes that
          reach ``S``) lose all reach when that node is removed, via a dominator
          tree.
    * On a dense directory graph the EDGE list is usually empty — path redundancy
      means no single edge is a bottleneck — while the NODE choke carries the
      large cardinalities (a mega-hub group / well-known SID). Reporting both lets
      the render (E3) prioritise the strongest choke of either kind. The edge view
      is the exact one the H3 brief's bridge test pins; the node view is the one
      that lights up at Contoso scale.

Complexity:
    Both choke views and the exposure-source anchor read ONE dominator tree
    (Lengauer-Tarjan, ``O(E log V)``) of the reachable subgraph, reversed,
    rooted at a virtual node joined to every terminal, with each candidate edge
    split into its own node. An object (node or edge) lies on every route from a
    source to ``S`` exactly when it dominates that source, so a cardinality is a
    subtree count. The earlier edge view re-flooded the graph once per source and
    per reachable edge (``O(sources * reachable_edges * E_r)``); a dense directory
    has tens of thousands of sources, and at a partner-sized directory (58k
    objects, 900k relationships) it ran for over two hours. That implementation is
    the test-only oracle (``tests/unit/services/_chokepoint_reference.py``) and
    this one returns the identical result.
"""

from __future__ import annotations

from array import array
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from adscan_core.reporting.remediation_scope_view import (
    PATH_DERIVED_BLOCKS_KEY as _PATH_DERIVED_BLOCKS_KEY,
)
from adscan_internal.services.attack_graph_core import is_traversable_attack_edge
from adscan_internal.services.graph_queries.filters import is_tombstoned

# Node kinds that can plausibly originate an attack (an enabled principal).
_PRINCIPAL_KINDS: frozenset[str] = frozenset({"User", "Computer", "Group"})

#: Key of the derivation marker that records whether the two path-derived
#: sub-blocks (``remediation_start_here``, ``user_exposure``) were ever DERIVED
#: for a stamped choke block, and from how many attack paths.
#:
#: It exists because those two sub-blocks are legitimately absent in two
#: different situations that look identical on disk: the domain genuinely has no
#: attack paths to rank, or the derivation never ran at all (a stamp written
#: before the paths were in scope). A consumer that cannot tell them apart will
#: read an UNCOMPUTED block as a complete one, which CLAUDE.md § "A bounded
#: computation is a data gap" forbids. The marker is always written, so its
#: presence means "derived", its ``attack_paths_considered`` says what it had to
#: work with, and its two booleans say honestly whether each sub-block came out
#: non-empty.
PATH_DERIVED_BLOCKS_KEY = _PATH_DERIVED_BLOCKS_KEY

#: Set (``True``) on a stamped block whose choke-point analysis was stopped, by
#: the memory guard or by the operator, before it finished. Such a block carries
#: no cardinality, no ranking and no KPI card (a partial count is never shown as
#: complete), and its gap is declared in the domain's ``resource_coverage`` or
#: ``operator_stop_coverage`` block. Absent on a completed block, which keeps a
#: completed block byte-identical to what it always was.
CARDINALITY_STOPPED_KEY = "cardinality_stopped"


def chokepoint_block_is_derived(block: Any) -> bool:
    """Whether a persisted choke block is complete enough to reuse as-is.

    The single predicate behind the stamp's idempotency, shared with the LITE
    report flow so the cheap pre-check that skips the (expensive) graph load and
    the stamp's own guard can never disagree about what counts as "already
    stamped" — they were two hand-copied conditions before.

    "Already stamped" means ranked AND carrying the path-derivation marker
    (:data:`PATH_DERIVED_BLOCKS_KEY`). Requiring the marker is what makes the
    stamp self-healing for a block written before the attack paths reached this
    seam: such a block is ranked but can never have derived
    ``remediation_start_here`` / ``user_exposure``, so it is re-stamped ONCE and
    then carries the marker forever. Recomputation is therefore bounded at one
    pass per workspace even for a domain with zero attack paths, whose marker
    records that honest emptiness rather than looking uncomputed.

    Args:
        block: The value at ``domains[<domain>]["chokepoint_cardinality"]``.

    Returns:
        ``True`` when the block may be reused untouched.
    """
    return (
        isinstance(block, dict)
        and bool(block.get("schema_version"))
        and isinstance(block.get("ranked_chokepoints"), list)
        and isinstance(block.get(PATH_DERIVED_BLOCKS_KEY), dict)
    )


def _iter_nodes(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Normalize ``graph["nodes"]`` into an ``id -> node`` mapping.

    Nodes may be persisted either as a dict keyed by node id (the live
    ``attack_graph.json`` shape) or as a plain list of node dicts (the shape the
    brief's tests use). Both normalize to the same mapping.

    Args:
        graph: The attack graph dict.

    Returns:
        A mapping from node id to the node dict. Nodes without a resolvable id
        are dropped.
    """
    raw = graph.get("nodes")
    result: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        for key, node in raw.items():
            if not isinstance(node, dict):
                continue
            node_id = str(node.get("id") or key or "").strip()
            if node_id:
                result[node_id] = node
    elif isinstance(raw, list):
        for node in raw:
            if not isinstance(node, dict):
                continue
            node_id = str(node.get("id") or "").strip()
            if node_id:
                result[node_id] = node
    return result


def _build_reverse_adjacency(
    graph: dict[str, Any],
    *,
    nodes_map: dict[str, dict[str, Any]] | None = None,
) -> dict[str, set[str]]:
    """Build the reverse adjacency ``to -> {from, ...}`` from the graph edges.

    Each edge dict carries ``from``/``to`` (and a ``relation`` used only for the
    stable edge key). A reverse edge ``to -> from`` is what a reverse BFS from a
    terminal follows to discover every node that can reach that terminal.

    Only TRAVERSABLE compromise edges enter the adjacency — the SAME gate the DFS
    uses (:func:`attack_graph_core.is_traversable_attack_edge`). Without it the
    reverse flood would cross share-access edges (``ReadShare`` / ``WriteShare`` /
    ``FullControlShare``) that are exposure findings, not host-compromise
    transitions, and would falsely count every standard user as reaching the
    value-terminal set (the ``Everyone --FullControlShare--> DC$`` flood).

    Args:
        graph: The attack graph dict.
        nodes_map: The ``id -> node`` map for the class-aware ``WriteSPN``
            exclusion. When ``None`` it is built from ``graph`` (the relation-only
            exclusions still apply either way).

    Returns:
        A mapping from a node id to the set of node ids that have an edge INTO
        it.
    """
    reverse: dict[str, set[str]] = {}
    edges = graph.get("edges")
    if not isinstance(edges, list):
        return reverse
    resolved_nodes = nodes_map if isinstance(nodes_map, dict) else _iter_nodes(graph)
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if not is_traversable_attack_edge(edge, resolved_nodes):
            continue
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        if not from_id or not to_id:
            continue
        reverse.setdefault(to_id, set()).add(from_id)
    return reverse


def _reverse_reach(
    reverse: dict[str, set[str]],
    seeds: set[str],
    *,
    excluded_edge: tuple[str, str] | None = None,
) -> set[str]:
    """Return every node that can reach ``seeds`` over the reverse adjacency.

    A plain BFS backward from every seed. When ``excluded_edge`` is supplied the
    corresponding reverse hop ``v -> u`` (i.e. the forward edge ``u -> v``) is
    skipped, which yields ``Reach^-1(S)`` with that single edge removed without
    mutating the adjacency.

    Args:
        reverse: The reverse adjacency ``to -> {from, ...}``.
        seeds: The value-terminal node ids to flood back from.
        excluded_edge: An optional ``(u, v)`` forward edge to treat as removed.

    Returns:
        The set of node ids that can reach some seed (the seeds are included).
    """
    reachable: set[str] = set(seeds)
    pending = list(seeds)
    while pending:
        current = pending.pop()
        for predecessor in reverse.get(current, ()):
            if excluded_edge is not None and (predecessor, current) == excluded_edge:
                continue
            if predecessor in reachable:
                continue
            reachable.add(predecessor)
            pending.append(predecessor)
    return reachable


def _node_is_disabled(node: dict[str, Any]) -> bool:
    """Return ``True`` only when the node is EXPLICITLY marked disabled.

    The persisted graph records the ``enabled`` flag under ``properties`` (the
    top-level ``enabled`` is usually ``None``). Only an explicit ``False`` (at
    either location) counts as disabled; a missing flag is treated as enabled so
    the predicate stays permissive, which is what the brief asks for.

    Args:
        node: The node dict.

    Returns:
        ``True`` if the node is explicitly disabled, else ``False``.
    """
    if node.get("enabled") is False:
        return True
    props = node.get("properties")
    if isinstance(props, dict) and props.get("enabled") is False:
        return True
    return False


def _node_is_enabled_principal(node: dict[str, Any]) -> bool:
    """Return ``True`` if the node is a plausible, non-disabled attack source.

    An enabled principal is a node whose ``kind`` is a user / computer / group
    principal, that is not explicitly disabled, and that still EXISTS in the
    directory. The predicate is deliberately permissive about kind:
    over-counting a container as a principal is harmless here because the
    reverse-reachable set already bounds the count to nodes that actually reach
    a value terminal.

    Deletion is the one exclusion that is not permissive, because it is not a
    matter of degree: a tombstone preserves its ``userAccountControl`` and so
    reads as enabled, but nobody can authenticate as a deleted account without
    reanimating it first. Counting one as a source would overstate how many of
    the client's principals hold a route to the crown jewels.

    Args:
        node: The node dict.

    Returns:
        ``True`` for an active principal node.
    """
    kind = str(node.get("kind") or "").strip()
    if kind not in _PRINCIPAL_KINDS:
        return False
    if is_tombstoned(node):
        return False
    return not _node_is_disabled(node)


def exposure_source_count(graph: dict[str, Any], *, value_terminals: set[str]) -> int:
    """Count enabled principals that can reach the value-terminal set.

    This is ``|Reach^-1(S) intersect enabled-principals|`` — the complete-exposure
    anchor: how many principals in the directory have SOME route to the crown
    jewels, independent of how many individual routes exist. It is the number the
    bounded engine can report honestly even when the route sample is capped,
    because it is a set cardinality, not a path count.

    The value-terminal set itself is excluded from the source count (a crown
    jewel is not one of its own attackers).

    Args:
        graph: The attack graph dict (``nodes`` dict-or-list, ``edges`` list).
        value_terminals: The value-terminal (crown-jewel) node ids.

    Returns:
        The number of enabled principal nodes that can reach ``value_terminals``.
    """
    terminals = {str(t) for t in value_terminals if str(t)}
    if not terminals:
        return 0
    nodes = _iter_nodes(graph)
    reverse = _build_reverse_adjacency(graph, nodes_map=nodes)
    reachable = _reverse_reach(reverse, terminals)
    count = 0
    for node_id in reachable:
        if node_id in terminals:
            continue
        node = nodes.get(node_id)
        if isinstance(node, dict) and _node_is_enabled_principal(node):
            count += 1
    return count


def _node_is_tier_zero(node: dict[str, Any]) -> bool:
    """Return ``True`` when the node is Tier 0 (control-plane).

    Reads the STAMPED, membership-aware ``privilege_tier`` first (the tier SSOT,
    :func:`compromise_class.node_stamped_privilege_tier`): a member of Backup
    Operators is Tier 0 escalation-capable and a member of BUILTIN\\Administrators
    Tier 0 direct whatever the collector's legacy ``isTierZero`` flag says, and
    that flag is RID-gated and misses both. The raw flag is the fallback only for
    a node that carries no stamp (an older graph). A Tier-0 principal is excluded
    from the "standard user" denominator: a Domain Admin reaching full domain
    compromise is the directory's own hierarchy restated, and counting it
    inflates the ratio toward 100% by construction (mirrors
    ``DomainUserReach.ordinary_*`` doctrine).
    """
    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        node_stamped_privilege_tier,
    )

    stamped = node_stamped_privilege_tier(node)
    if stamped is not None:
        return stamped.is_tier0
    if bool(node.get("isTierZero")):
        return True
    props = node.get("properties")
    return isinstance(props, dict) and bool(props.get("isTierZero"))


def _node_label_is_wellknown(node: dict[str, Any]) -> bool:
    """Return ``True`` for a synthetic well-known principal node.

    Well-known SIDs (``Creator Owner@WELLKNOWN``, ``Network Service@WELLKNOWN``,
    ``Principal Self@WELLKNOWN``) are modelled as ``User`` nodes but are NOT real
    standard accounts, so they are excluded from the "standard user" denominator.
    They are identified by the ``@WELLKNOWN`` label suffix or a ``WELLKNOWN``
    ``properties.domain`` (the collector's synthetic realm).
    """
    label = str(node.get("label") or node.get("name") or "").strip()
    if label.upper().endswith("@WELLKNOWN"):
        return True
    props = node.get("properties")
    if isinstance(props, dict):
        return str(props.get("domain") or "").strip().upper() == "WELLKNOWN"
    return False


def _node_is_standard_user(node: dict[str, Any]) -> bool:
    """Return ``True`` for an enabled, non-Tier-0, non-synthetic USER account.

    The denominator population of the Tier-2 exposure ratio: a real standard
    (Tier 2) directory user. Deliberately excludes computers and groups (the
    permissive ``exposure_source_count`` counts those — machine accounts fold in
    via ``Authenticated Users`` and dominate the figure), disabled accounts,
    Tier-0 principals, and synthetic well-known SIDs.

    It also drops the two account classes the population SSOT drops
    (``account_population`` / ``graph_queries.inventories``), so this ratio and
    the population breakdown printed beside it count the same people: an
    inter-domain TRUST account, which the collector surfaces as a ``User`` node
    named after the trusted domain (``SEVENKINGDOMS$`` made "11 of 11" sit next
    to a population of 10), and a managed service account, whose password is
    machine-managed and not exposed by anything this ratio measures.

    And it drops a DELETED account, as that SSOT does (``is_active``). A scan
    that reaches Domain Admin reads the directory's Deleted Objects container,
    and a deleted account keeps its ``userAccountControl``, so it reads as
    enabled. Counted here, a client whose recycle bin holds a thousand deleted
    users would be told a thousand more ordinary accounts hold a path, beside a
    population that never included them ("11 of 11" over a population of 9).
    """
    if str(node.get("kind") or "").strip() != "User":
        return False
    if is_tombstoned(node):
        return False
    if _node_is_disabled(node):
        return False
    if _node_is_tier_zero(node) or _node_is_tier_one(node):
        return False
    props = node.get("properties")
    props = props if isinstance(props, dict) else {}
    from adscan_internal.services.graph_queries.inventories import (  # noqa: PLC0415
        is_machine_or_trust_user,
        is_managed_service_account,
    )

    if is_machine_or_trust_user(props) or is_managed_service_account(props):
        return False
    return not _node_label_is_wellknown(node)


def _node_is_tier_one(node: dict[str, Any]) -> bool:
    """Return ``True`` when the node's STAMPED tier is Tier 1.

    A Tier 1 account (local administrator of a server, a grade the stamp reads
    from host rights no group closure sees) is not an ordinary user: the
    findings badge it Tier 1 and the account-population grader counts it Tier 1
    (``attack_graph_service._classify_accounts_by_privilege_tier`` reads the same
    stamp), so this ratio must not count it among the Tier 2 people either. Only
    the stamp decides; an unstamped node has no Tier 1 signal.
    """
    from adscan_internal.services.compromise_class import (  # noqa: PLC0415
        PrivilegeTier,
        node_stamped_privilege_tier,
    )

    return node_stamped_privilege_tier(node) == PrivilegeTier.TIER1


@dataclass(frozen=True)
class Tier2ExposureRatio:
    """Share of standard user accounts that can reach full domain compromise.

    ADscan's exposure thesis expressed as ONE ratio a CISO reads directly: of the
    domain's real, non-privileged user accounts, how many hold a reachable route
    to a Tier-0 / full-domain-compromise target. It is k-INDEPENDENT (a
    reverse-reachability SET cardinality over the base graph, exactly like
    :func:`exposure_source_count`), so it survives the control-mega-hub sampled
    fallback that collapses the materialized ``path_axis``/``user_axis`` counts to
    0 — unlike the materialization-derived ``DomainUserReach``.

    Distinct from :func:`exposure_source_count`, which counts ALL enabled
    principals (users + computers + groups) and is dominated by machine accounts
    folded in through ``Authenticated Users``. This ratio's denominator is real
    standard USER accounts only, so it answers the buyer's question ("what share
    of my people are exposed") without the machine-account inflation.

    Attributes:
        with_path: Standard user accounts with a reachable path to a value
            terminal (the numerator).
        total: The standard-user population (the denominator).
    """

    with_path: int = 0
    total: int = 0

    @property
    def pct(self) -> float:
        """Share of the standard-user population, saturating at 100."""
        if self.total <= 0:
            return 0.0
        return min(100.0, round(self.with_path / self.total * 100.0, 1))

    @property
    def available(self) -> bool:
        """True when there is a standard-user population to report against."""
        return self.total > 0

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-safe block stamped into ``exposure_kpis``."""
        return {
            "with_path": int(self.with_path),
            "total": int(self.total),
            "pct": self.pct,
        }


def tier2_exposure_ratio(
    graph: dict[str, Any], *, value_terminals: set[str]
) -> Tier2ExposureRatio:
    """Compute the standard-user → Tier-0 reachability ratio. Pure, k-independent.

    ``with_path = |Reach^-1(S) intersect standard-users|`` and
    ``total = |standard-users|``, where a standard user is an enabled, non-Tier-0,
    non-synthetic ``User`` node (see :func:`_node_is_standard_user`). Uses the SAME
    reverse-reachability primitive and value-terminal set as
    :func:`exposure_source_count`, so it is cheap set algebra and reports honestly
    even when the route sample is capped.

    Args:
        graph: The attack graph dict (``nodes`` dict-or-list, ``edges`` list).
        value_terminals: The value-terminal (crown-jewel / Tier-0) node ids.

    Returns:
        The :class:`Tier2ExposureRatio`; an all-zero value when there is no
        standard-user population or no value terminal.
    """
    nodes = _iter_nodes(graph)
    standard_users = {
        node_id
        for node_id, node in nodes.items()
        if isinstance(node, dict) and _node_is_standard_user(node)
    }
    total = len(standard_users)
    if total == 0:
        return Tier2ExposureRatio(with_path=0, total=0)

    terminals = {str(t) for t in value_terminals if str(t)}
    if not terminals:
        return Tier2ExposureRatio(with_path=0, total=total)

    reverse = _build_reverse_adjacency(graph, nodes_map=nodes)
    reachable = _reverse_reach(reverse, terminals)
    with_path = sum(1 for node_id in standard_users if node_id in reachable)
    return Tier2ExposureRatio(with_path=with_path, total=total)


def edge_key(from_id: str, relation: str, to_id: str) -> str:
    """Build the stable string key for an edge.

    Args:
        from_id: The edge source node id.
        relation: The edge relation label.
        to_id: The edge target node id.

    Returns:
        A ``"{from}|{relation}|{to}"`` key.
    """
    return f"{from_id}|{relation}|{to_id}"


#: Units of work (flow-graph nodes or edges visited) between two calls of the
#: ``checkpoint`` a caller passes to the choke computation. The seam uses it to
#: tick the memory guard and to honour an operator stop; one call costs a few
#: microseconds, a unit well under one, so this keeps the overhead negligible
#: while a stop still lands within a fraction of a second.
CHECKPOINT_EVERY = 65_536

#: Index of the virtual root of the dominator flow graph (joined to every terminal).
_ROOT = 0


class _ChokeIndex:
    """The reachable subgraph both choke views and the source count share.

    Built ONCE per summary from a single pass over the edges through the shared
    admission gate, instead of once per view: the edge choke, the node choke and
    :func:`exposure_source_count` all read the same reverse adjacency and the same
    ``Reach^-1(S)``.

    Attributes:
        nodes: ``id -> node`` map.
        terminals: The value-terminal ids.
        reverse: Reverse adjacency ``to -> {from, ...}`` over traversable edges.
        reach: ``Reach^-1(S)`` (terminals included).
    """

    __slots__ = ("nodes", "terminals", "reverse", "reach", "graph")

    def __init__(self, graph: dict[str, Any], terminals: set[str]) -> None:
        self.graph = graph
        self.terminals = terminals
        self.nodes = _iter_nodes(graph)
        self.reverse = _build_reverse_adjacency(graph, nodes_map=self.nodes)
        self.reach = _reverse_reach(self.reverse, terminals)

    def principal_sources(self) -> set[str]:
        """Enabled principals that reach ``S`` (terminals excluded)."""
        nodes = self.nodes
        terminals = self.terminals
        return {
            node_id
            for node_id in self.reach
            if node_id not in terminals
            and isinstance(nodes.get(node_id), dict)
            and _node_is_enabled_principal(nodes[node_id])
        }

    def leaf_sources(self) -> set[str]:
        """Leaf originators: reachable non-terminals with no inbound reach edge."""
        reach = self.reach
        reverse = self.reverse
        terminals = self.terminals
        return {
            node_id
            for node_id in reach
            if node_id not in terminals and not (reverse.get(node_id, set()) & reach)
        }


def _first_traversable_relations(
    index: _ChokeIndex, pairs: set[tuple[str, str]]
) -> dict[tuple[str, str], str]:
    """The first-seen traversable relation of each ``(from, to)`` pair asked for.

    The stable edge key carries the relation of the FIRST traversable edge of a
    parallel-edge pair, in edge-list order. Only the pairs that turned out to be
    choke edges need a key, so the edge list is scanned once and the admission
    gate is evaluated only for an edge whose pair is one of them.
    """
    edges = index.graph.get("edges")
    found: dict[tuple[str, str], str] = {}
    if not pairs or not isinstance(edges, list):
        return found
    nodes = index.nodes
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        from_id = str(edge.get("from") or "").strip()
        to_id = str(edge.get("to") or "").strip()
        pair = (from_id, to_id)
        if pair not in pairs or pair in found:
            continue
        if not is_traversable_attack_edge(edge, nodes):
            continue
        found[pair] = str(edge.get("relation") or "").strip()
        if len(found) == len(pairs):
            break
    return found


def _csr(
    n: int, src: "array[int]", dst: "array[int]"
) -> tuple["array[int]", "array[int]"]:
    """Compressed adjacency (``offsets``, ``targets``) of ``n`` nodes from edge arrays."""
    offsets = array("l", bytes(8 * (n + 1)))
    for s in src:
        offsets[s + 1] += 1
    running = 0
    for i in range(n + 1):
        running += offsets[i]
        offsets[i] = running
    targets = array("l", bytes(8 * len(src)))
    cursor = array("l", offsets)
    for s, d in zip(src, dst):
        pos = cursor[s]
        targets[pos] = d
        cursor[s] = pos + 1
    return offsets, targets


def _dominator_tree(
    n: int,
    succ_off: "array[int]",
    succ_idx: "array[int]",
    pred_off: "array[int]",
    pred_idx: "array[int]",
    checkpoint: Callable[[int], None] | None,
) -> tuple["array[int]", "array[int]", "array[int]"]:
    """Immediate dominators of a flowgraph rooted at :data:`_ROOT` (Lengauer-Tarjan).

    The iterative Lengauer-Tarjan algorithm with path compression (the "simple"
    variant, ``O(m log n)``), in pure Python over compact integer arrays. The
    immediate dominator of a node is unique, so the result is the same whatever
    algorithm computes it; this one is chosen because its bound does not depend
    on the graph's loop structure (an iterative data-flow formulation can take
    many passes over a directory graph full of membership cycles).

    Args:
        n: Number of flow-graph nodes (``0`` is the root).
        succ_off, succ_idx: Flow-forward adjacency in CSR form.
        pred_off, pred_idx: Its transpose.
        checkpoint: Called with a unit count every :data:`CHECKPOINT_EVERY` units.

    Returns:
        ``(vertex, idom, dfn)`` in DFS-preorder numbering: ``vertex[i]`` is the
        node with preorder number ``i`` (only nodes reachable from the root are
        numbered), ``idom[i]`` the preorder number of its immediate dominator
        (``idom[0]`` is ``0``) and ``dfn[node]`` the preorder number of a node
        (``-1`` when unreachable). An immediate dominator always precedes its
        node in preorder.
    """
    dfn = array("l", [-1]) * n
    vertex = array("l")
    parent = array("l")

    # Iterative depth-first search assigning preorder numbers.
    dfn[_ROOT] = 0
    vertex.append(_ROOT)
    parent.append(-1)
    stack_node = [_ROOT]
    stack_pos = [succ_off[_ROOT]]
    visited = 0
    while stack_node:
        v = stack_node[-1]
        p = stack_pos[-1]
        end = succ_off[v + 1]
        descended = False
        while p < end:
            w = succ_idx[p]
            p += 1
            if dfn[w] < 0:
                dfn[w] = len(vertex)
                vertex.append(w)
                parent.append(dfn[v])
                stack_pos[-1] = p
                stack_node.append(w)
                stack_pos.append(succ_off[w])
                descended = True
                break
        if not descended:
            stack_node.pop()
            stack_pos.pop()
        visited += 1
        if checkpoint is not None and not visited % CHECKPOINT_EVERY:
            checkpoint(CHECKPOINT_EVERY)

    m = len(vertex)
    semi = array("l", range(m))
    label = array("l", range(m))
    ancestor = array("l", [-1]) * m
    idom = array("l", bytes(8 * m))
    bucket_head = array("l", [-1]) * m
    bucket_next = array("l", [-1]) * m
    compress_stack: list[int] = []

    def _eval(v: int) -> int:
        # Lowest-semi label on the forest path above ``v`` (path compression).
        if ancestor[v] < 0:
            return v
        x = v
        while ancestor[ancestor[x]] >= 0:
            compress_stack.append(x)
            x = ancestor[x]
        while compress_stack:
            y = compress_stack.pop()
            a = ancestor[y]
            if semi[label[a]] < semi[label[y]]:
                label[y] = label[a]
            ancestor[y] = ancestor[a]
        return label[v]

    for w in range(m - 1, 0, -1):
        node = vertex[w]
        sw = semi[w]
        for pos in range(pred_off[node], pred_off[node + 1]):
            vd = dfn[pred_idx[pos]]
            if vd < 0:
                continue
            u = _eval(vd)
            su = semi[u]
            if su < sw:
                sw = su
        semi[w] = sw
        bucket_next[w] = bucket_head[sw]
        bucket_head[sw] = w
        pw = parent[w]
        ancestor[w] = pw
        v = bucket_head[pw]
        bucket_head[pw] = -1
        while v >= 0:
            nxt = bucket_next[v]
            u = _eval(v)
            idom[v] = u if semi[u] < semi[v] else pw
            v = nxt
        if checkpoint is not None and not w % CHECKPOINT_EVERY:
            checkpoint(CHECKPOINT_EVERY)

    for w in range(1, m):
        if idom[w] != semi[w]:
            idom[w] = idom[idom[w]]
    return vertex, idom, dfn


def _subtree_counts(
    vertex: "array[int]", idom: "array[int]", members: "bytearray"
) -> "array[int]":
    """Members in each dominator subtree, indexed by preorder number.

    ``members[node]`` flags the flow-graph nodes to count. An immediate dominator
    precedes its node in preorder, so one pass from the last preorder number to
    the first folds every subtree into its parent.
    """
    m = len(vertex)
    counts = array("l", (members[vertex[i]] for i in range(m)))
    for i in range(m - 1, 0, -1):
        c = counts[i]
        if c:
            counts[idom[i]] += c
    return counts


def _choke_cardinalities(
    index: _ChokeIndex,
    *,
    want_edges: bool,
    want_nodes: bool,
    checkpoint: Callable[[int], None] | None = None,
) -> tuple[dict[str, int], dict[str, int]]:
    """Both choke views from ONE dominator tree of the edge-split reachable graph.

    The flow graph is the reachable subgraph reversed and rooted at a virtual root
    joined to every terminal, with every candidate edge ``(u, v)`` split into its
    own node (``v -> e -> u`` in flow direction). In it, a node or an edge-node
    ``d`` dominates a node ``s`` exactly when every path from ``s`` to the
    terminal set passes through ``d``. So:

    * an edge's cardinality is the number of leaf originators in its edge-node's
      dominator subtree (the original per-source, per-edge reflood counted the
      same set: the edges whose removal leaves the source unable to reach ``S``);
    * a node's cardinality is the number of enabled source principals strictly
      inside its subtree (the original idom-chain walk counted the same set).

    Two edge classes are left out of the split graph because they can never be on
    every route and leaving them in changes no dominance: a self-loop, and an edge
    leaving a terminal (any route through it already reached a terminal before
    it). A node's dominators are the same with or without them, so the node view
    reads the same tree. Parallel edges were already one ``(u, v)`` pair in the set
    adjacency, exactly as the original reflood removed the whole pair.

    Returns:
        ``(edge_cardinality, node_cardinality)``; a view not asked for is ``{}``.
    """
    terminals = index.terminals
    reach = index.reach
    reverse = index.reverse

    edge_sources = index.leaf_sources() if want_edges else set()
    node_sources = index.principal_sources() if want_nodes else set()
    if not edge_sources and not node_sources:
        return {}, {}

    # Node numbering: 0 = root, then the reachable nodes.
    order = sorted(reach)
    node_index = {node_id: i + 1 for i, node_id in enumerate(order)}
    r = len(order)

    # Candidate edges, grouped by their head so a head's edge-nodes are contiguous.
    pair_from = array("l")
    pair_to = array("l")
    for v_id in order:
        froms = reverse.get(v_id)
        if not froms:
            continue
        v_ix = node_index[v_id]
        for u_id in froms:
            if u_id == v_id or u_id in terminals:
                continue
            u_ix = node_index.get(u_id)
            if u_ix is None:
                continue
            pair_from.append(u_ix)
            pair_to.append(v_ix)
    p = len(pair_from)
    n = 1 + r + p
    edge_base = 1 + r

    # Flow edges: root -> terminal, head -> edge-node, edge-node -> tail.
    src = array("l")
    dst = array("l")
    for t_id in sorted(terminals):
        src.append(_ROOT)
        dst.append(node_index[t_id])
    for k in range(p):
        e = edge_base + k
        src.append(pair_to[k])
        dst.append(e)
        src.append(e)
        dst.append(pair_from[k])
    if checkpoint is not None:
        checkpoint(len(src))
    succ_off, succ_idx = _csr(n, src, dst)
    pred_off, pred_idx = _csr(n, dst, src)
    del src, dst

    vertex, idom, dfn = _dominator_tree(
        n, succ_off, succ_idx, pred_off, pred_idx, checkpoint
    )
    del succ_off, succ_idx, pred_off, pred_idx

    edge_result: dict[str, int] = {}
    if edge_sources:
        members = bytearray(n)
        for node_id in edge_sources:
            members[node_index[node_id]] = 1
        counts = _subtree_counts(vertex, idom, members)
        critical: dict[tuple[str, str], int] = {}
        for k in range(p):
            i = dfn[edge_base + k]
            if i < 0:
                continue
            c = counts[i]
            if c > 0:
                critical[(order[pair_from[k] - 1], order[pair_to[k] - 1])] = c
        relations = _first_traversable_relations(index, set(critical))
        for (u_id, v_id), c in critical.items():
            key = edge_key(u_id, relations.get((u_id, v_id), ""), v_id)
            edge_result[key] = edge_result.get(key, 0) + c

    node_result: dict[str, int] = {}
    if node_sources:
        members = bytearray(n)
        for node_id in node_sources:
            members[node_index[node_id]] = 1
        counts = _subtree_counts(vertex, idom, members)
        for node_id in order:
            if node_id in terminals:
                continue
            ix = node_index[node_id]
            i = dfn[ix]
            if i < 0:
                continue
            c = counts[i] - members[ix]
            if c > 0:
                node_result[node_id] = c
    return edge_result, node_result


def compute_chokepoint_cardinality(
    graph: dict[str, Any],
    *,
    value_terminals: set[str],
    checkpoint: Callable[[int], None] | None = None,
) -> dict[str, int]:
    """Return per-edge choke-point cardinality (one dominator tree, near-linear).

    The cardinality of edge ``e = (u, v)`` (oriented toward the value-terminal set
    ``S``) is the number of *sources* — leaf originators, i.e. reachable nodes
    with no inbound reach edge — whose EVERY path to ``S`` traverses ``e``, so
    cutting that single edge severs all of them. This is the set reading of
    ``|Reach^-1(S)| - |Reach^-1(S) with e removed|`` restricted to source nodes.

    Computed with ONE dominator tree of the edge-split reachable graph (see
    :func:`_choke_cardinalities`): the edges a source cannot avoid are exactly the
    edge-nodes among its dominators, so an edge's cardinality is the number of
    sources in its subtree. ``O(E log V)`` for all sources at once. The previous
    implementation re-flooded the graph once per source and per reachable edge,
    which did not finish in two hours at a partner-sized directory; it is kept as
    the test oracle and this function returns the identical dict.

    Counting SOURCES (not every reachable node) is what the bridge test expects:
    three low-priv sources funnelling through one bridge edge returns a
    cardinality of 3 — the intermediary bridge node is a relay, not a fourth
    source of itself.

    Args:
        graph: The attack graph dict (``nodes`` dict-or-list, ``edges`` list).
        value_terminals: The value-terminal (crown-jewel) node ids.
        checkpoint: Optional; called with a unit count every
            :data:`CHECKPOINT_EVERY` units of work (memory guard, operator stop).
            Whatever it raises propagates and no partial result is returned.

    Returns:
        A mapping from a stable edge key (``"{from}|{relation}|{to}"``) to its
        choke-point cardinality (>= 1). Non-choke edges are omitted. Returns an
        empty dict when there are no terminals, edges, or sources.
    """
    terminals = {str(t) for t in value_terminals if str(t)}
    if not terminals or not isinstance(graph.get("edges"), list):
        return {}
    index = _ChokeIndex(graph, terminals)
    edge_result, _ = _choke_cardinalities(
        index, want_edges=True, want_nodes=False, checkpoint=checkpoint
    )
    return edge_result


def compute_node_chokepoint_cardinality(
    graph: dict[str, Any],
    *,
    value_terminals: set[str],
    checkpoint: Callable[[int], None] | None = None,
) -> dict[str, int]:
    """Return per-NODE choke-point cardinality via a dominator tree (set algebra).

    The cardinality of a node ``n`` is the number of *source principals* — enabled
    User / Computer / Group nodes that can reach the value-terminal set ``S`` —
    that lose ALL reach to ``S`` when ``n`` is removed, i.e. every one of their
    paths to ``S`` passes through ``n``. On a dense directory graph the strongest
    choke is almost always a NODE (a mega-hub group like Account Operators / a
    well-known SID) rather than a single edge, because path redundancy means no
    single edge is a bottleneck while a hub still is — which is why this
    node-level signal, not :func:`compute_chokepoint_cardinality`, carries the
    large cardinalities at scale.

    Computed WITHOUT re-flooding per node: one dominator tree over the reachable
    subgraph (rooted at a virtual root joined to every terminal, the same tree the
    edge view reads). A node ``d`` *dominates* node ``m`` when every path from
    ``m`` to ``S`` passes through ``d``; the number of source principals in
    ``n``'s dominator subtree is exactly how many are severed by removing ``n``.

    Args:
        graph: The attack graph dict (``nodes`` dict-or-list, ``edges`` list).
        value_terminals: The value-terminal (crown-jewel) node ids.
        checkpoint: As in :func:`compute_chokepoint_cardinality`.

    Returns:
        A mapping from a node id to its choke-point cardinality (>= 1). Nodes that
        sever no source are omitted. Returns an empty dict when there are no
        terminals, edges, or source principals.
    """
    terminals = {str(t) for t in value_terminals if str(t)}
    if not terminals or not isinstance(graph.get("edges"), list):
        return {}
    index = _ChokeIndex(graph, terminals)
    _, node_result = _choke_cardinalities(
        index, want_edges=False, want_nodes=True, checkpoint=checkpoint
    )
    return node_result


def build_chokepoint_summary(
    graph: dict[str, Any],
    *,
    value_terminals: set[str],
    top_k: int = 20,
    checkpoint: Callable[[int], None] | None = None,
) -> dict[str, Any]:
    """Build the compact, JSON-safe choke-point summary for persistence.

    Runs the edge choke, the node choke and the exposure-source anchor, returning
    the top-``K`` of each. The shape is deliberately small (only the top entries,
    not the full per-edge / per-node maps) so it is cheap to stamp into the report
    and read back for a later render (E3).

    On a dense directory graph the edge list is usually empty (path redundancy
    means no single edge is a bottleneck) while the node list carries the large
    cardinalities (a mega-hub group / well-known SID). Both are reported so E3 can
    prioritise the strongest choke of either kind.

    Args:
        graph: The attack graph dict.
        value_terminals: The value-terminal node ids.
        top_k: How many top choke points of each kind to keep.
        checkpoint: As in :func:`compute_chokepoint_cardinality`; whatever it
            raises propagates and no partial summary is returned.

    Returns:
        A JSON-safe dict with ``schema_version``, ``exposure_source_count``,
        ``value_terminal_count``, ``edge_candidate_count``, ``node_candidate_count``,
        a ``top_chokepoints`` list of ``{"edge_key", "cardinality"}`` entries and a
        ``top_node_chokepoints`` list of ``{"node_id", "cardinality"}`` entries,
        each in descending order.
    """
    terminals = {str(t) for t in value_terminals if str(t)}
    keep = max(0, int(top_k))

    # One reachable-subgraph index and ONE dominator tree for all three figures
    # (the edge choke, the node choke and the exposure-source anchor).
    edge_cardinality: dict[str, int] = {}
    node_cardinality: dict[str, int] = {}
    source_count = 0
    if terminals:
        index = _ChokeIndex(graph, terminals)
        source_count = len(index.principal_sources())
        if isinstance(graph.get("edges"), list):
            edge_cardinality, node_cardinality = _choke_cardinalities(
                index, want_edges=True, want_nodes=True, checkpoint=checkpoint
            )
        del index

    edge_ranked = sorted(edge_cardinality.items(), key=lambda kv: (-kv[1], kv[0]))
    top_edges = [
        {"edge_key": key, "cardinality": int(count)}
        for key, count in edge_ranked[:keep]
    ]

    node_ranked = sorted(node_cardinality.items(), key=lambda kv: (-kv[1], kv[0]))
    top_nodes = [
        {"node_id": node_id, "cardinality": int(count)}
        for node_id, count in node_ranked[:keep]
    ]

    return {
        "schema_version": 1,
        "exposure_source_count": source_count,
        "value_terminal_count": len(terminals),
        "edge_candidate_count": len(edge_cardinality),
        "node_candidate_count": len(node_cardinality),
        "top_chokepoints": top_edges,
        "top_node_chokepoints": top_nodes,
    }


def derive_chokepoint_kpi(summary: dict[str, Any] | None) -> dict[str, Any] | None:
    """Derive the three-line choke-point KPI headline card from a persisted block.

    This is the CISO-first summary the report leads with: a tiny fix against a
    large, measured blast radius. It is derived ENTIRELY from the
    already-persisted ``chokepoint_cardinality`` block (the same source the
    "Start here" section renders from), so it never re-loads or recomputes over
    the graph, and the wording comes from the copy SSOT
    (:func:`adscan_core.reporting.chokepoint_copy.chokepoint_kpi_lines`) — never
    hand-authored here.

    The blast-radius / percentage semantics:

    * ``routes_severed`` = the TOP single choke's OWN cardinality
      (``ranked_chokepoints[0]["cardinality"]``), because the copy says "fixing 1
      object" — it is that one object's blast radius, never the aggregate of the
      shown rows.
    * ``validated_exposure_pct`` = ``round(100 * routes_severed /
      exposure_source_count)`` when ``exposure_source_count > 0``, else ``None``.
      The DENOMINATOR is ``exposure_source_count`` — the count of principals that
      hold a validated path to a value (Tier 0) target, i.e. *validated reach*.
      It is NOT the total domain user/account population; using that would inflate
      the share and mislabel it. This is the "% of validated exposure" the copy
      SSOT renders, and it appears ONLY in the ``context`` line.
    * ``bounded`` (from the persisted block) drives the "among the routes we
      evaluated" caveat, handled inside ``chokepoint_kpi_lines``.

    Args:
        summary: The persisted ``domain_data["chokepoint_cardinality"]`` dict
            (must carry ``ranked_chokepoints``), or ``None``.

    Returns:
        A JSON-safe dict ``{big, ratio, context, top_object_count,
        routes_severed, validated_exposure_pct}``, or ``None`` when the block is
        absent or carries no ranked rows (older scans render unchanged).
    """
    if not isinstance(summary, dict):
        return None
    ranked = summary.get("ranked_chokepoints")
    if not isinstance(ranked, list) or not ranked:
        return None
    top = ranked[0]
    if not isinstance(top, dict):
        return None

    # The "fixing 1 object" number is the top choke's OWN blast radius, never the
    # aggregate of the rows.
    routes_severed = int(top.get("cardinality") or 0)
    # The KPI card headlines the SINGLE top choke — the copy's ``big`` is
    # "…cut by fixing 1 object" and ``routes_severed`` is that one object's own
    # blast radius, so ``top_object_count`` is 1 to keep the "N objects → M
    # routes" ratio internally consistent (pairing >1 objects with the top-1
    # object's route count would misread). The full ranked list is the detail the
    # "Start here" section renders below the card.
    top_object_count = 1

    # Denominator = validated reach (principals with a proven path to a value
    # target), NEVER the total domain population.
    exposure_source_count = int(summary.get("exposure_source_count") or 0)
    if exposure_source_count > 0:
        # Clamp to [0, 100]: routes_severed (a choke's cardinality) and
        # exposure_source_count (source principals with validated reach) are
        # different counts whose co-domain is not guaranteed, so a persisted block
        # could yield >100. A "112% of validated exposure removed" headline is
        # client-visible nonsense in the paid deliverable; the clamp can never turn
        # a valid percentage wrong, it only bounds an out-of-range one.
        validated_exposure_pct: int | None = min(
            100, max(0, round(100 * routes_severed / exposure_source_count))
        )
    else:
        validated_exposure_pct = None

    bounded = bool(summary.get("bounded"))

    from adscan_core.reporting.chokepoint_copy import (  # noqa: PLC0415
        chokepoint_kpi_lines,
    )

    lines = chokepoint_kpi_lines(
        top_object_count=top_object_count,
        routes_severed=routes_severed,
        validated_exposure_pct=validated_exposure_pct,
        bounded=bounded,
    )

    return {
        "big": lines["big"],
        "ratio": lines["ratio"],
        "context": lines["context"],
        "top_object_count": int(top_object_count),
        "routes_severed": int(routes_severed),
        "validated_exposure_pct": validated_exposure_pct,
    }


def record_chokepoint_cardinality(
    shell: Any,
    domain: str,
    *,
    summary: dict[str, Any],
) -> None:
    """Best-effort persist the choke-point summary into the technical report.

    Mirrors the exposure-KPI stamper
    (:func:`adscan_core.reporting.technical_report.record_exposure_kpis`): stamps
    the value onto ``domains[<domain>]["chokepoint_cardinality"]`` so the JSON
    export carries it and a future render (task E3) reads it instead of
    recomputing. Best-effort: ignores a missing/invalid payload and never raises
    into the caller.

    Live-flow wiring (calling this from the scan pipeline once discovery routes a
    dense graph to the bounded engine) is deferred to the E3 render task; this
    function is the stamp seam it will call.

    Args:
        shell: The report shell carrying the technical-report path.
        domain: The domain the summary belongs to.
        summary: The output of :func:`build_chokepoint_summary`.
    """
    if not domain or not isinstance(summary, dict):
        return
    # A computed block, or one whose analysis was stopped (persisted so the
    # platform reads the same honest absence the report renders).
    if "top_chokepoints" not in summary and not summary.get(CARDINALITY_STOPPED_KEY):
        return
    try:
        from adscan_core.reporting.technical_report import (
            _ensure_technical_domain,
            _load_technical_report,
            _save_technical_report,
        )

        report = _load_technical_report(shell)
        domain_entry = _ensure_technical_domain(report, domain)
        domain_entry["chokepoint_cardinality"] = summary
        _save_technical_report(shell, report)
    except Exception:  # noqa: BLE001 - persistence is best-effort, never fatal
        return


def resolve_choke_bounded(
    domain_data: dict[str, Any], *, engine_marker_bounded: bool
) -> bool:
    """Decide whether the choke summary should carry the bounded caveat.

    Reads the SAME "was this run capped" truth the report and web already render,
    so the choke caveat and the coverage declaration can never disagree. This is
    the tier-shared, LITE-safe SSOT both the PRO report seam and the LITE report
    flow call — it depends only on ``adscan_core`` (no ``adscan_internal.pro``).
    Resolution order (first available wins), best-effort:

    1. The persisted ``attack_path_coverage`` block (H4) on ``domain_data``: a
       ``sampled`` OR ``bounded`` coverage mode means the route sample was capped,
       which is precisely when the client needs "the highest-impact choke point
       among the routes we evaluated". Read through the public
       :func:`attack_path_coverage_view`, which normalizes older blocks too.
    2. Else the engine marker observed on the scan shell (``_attack_path_engine_used
       == "fallback"``), passed in by the caller.
    3. Else ``False``.

    Args:
        domain_data: The in-memory report entry (may carry ``attack_path_coverage``).
        engine_marker_bounded: The shell-marker fallback the caller resolved.

    Returns:
        ``True`` when the run was capped/sampled, else the marker fallback / ``False``.
    """
    try:
        coverage = domain_data.get("attack_path_coverage")
        if coverage is not None:
            from adscan_core.reporting.attack_path_memory_gate import (  # noqa: PLC0415
                COVERAGE_MODE_BOUNDED,
                COVERAGE_MODE_SAMPLED,
                attack_path_coverage_view,
            )

            mode = attack_path_coverage_view(coverage).get("mode")
            return mode in (COVERAGE_MODE_SAMPLED, COVERAGE_MODE_BOUNDED)
    except Exception:  # noqa: BLE001 - coverage read is best-effort
        pass
    return bool(engine_marker_bounded)


def _node_cardinality_map_from_summary(summary: dict[str, Any]) -> dict[str, int]:
    """Build the node total-cut map used only for the structural-choke badge.

    Keys the persisted cardinality by BOTH node id (from ``top_node_chokepoints``)
    AND node label (from the enriched ``ranked_chokepoints``), so a priority row
    whose ``top_choke_point`` is a label OR an id resolves either way. This mirrors
    the PDF's ``_node_cardinality`` construction exactly, so the badge decision the
    web reads matches the deliverable. Only positive cardinalities are kept.
    """
    card_map: dict[str, int] = {}
    for _n in summary.get("top_node_chokepoints") or []:
        if not isinstance(_n, dict):
            continue
        _nid = str(_n.get("node_id") or "").strip()
        try:
            _card = int(_n.get("cardinality") or 0)
        except (TypeError, ValueError):
            _card = 0
        if _nid and _card > 0:
            card_map[_nid] = max(card_map.get(_nid, 0), _card)
    for _r in summary.get("ranked_chokepoints") or []:
        if not isinstance(_r, dict):
            continue
        try:
            _card = int(_r.get("cardinality") or 0)
        except (TypeError, ValueError):
            _card = 0
        if _card <= 0:
            continue
        for _idk in ("node_id", "node_label"):
            _idv = str(_r.get(_idk) or "").strip()
            if _idv:
                card_map[_idv] = max(card_map.get(_idv, 0), _card)
    return card_map


def _build_remediation_start_here_for_domain(
    *,
    domain: str,
    domain_data: dict[str, Any],
    summary: dict[str, Any],
    bounded: bool,
) -> dict[str, Any] | None:
    """Build the persisted "Start here" remediation LEAD for one domain.

    Reuses the ONE tier-shared model-builder
    (:func:`adscan_internal.services.remediation_start_here.build_remediation_start_here`)
    fed the SAME impact-score ranking the PRO PDF renders
    (:func:`~adscan_internal.services.remediation_start_here.compute_remediation_priorities`),
    so the persisted block the web reads carries the exact ranking, counts and
    copy the deliverable shows. Executed / mapped counts are scoped to this
    domain's paths (executed = the proven bucket ``_PROVEN_STATUSES``; mapped =
    all statuses), so the "validated / executed" wording is literally true.

    Returns the JSON/Jinja-safe render model, or ``None`` when the domain has no
    attack paths or no technique carries client exposure.
    """
    from adscan_internal.services.remediation_start_here import (  # noqa: PLC0415
        build_start_here_for_domains,
    )

    raw_paths = domain_data.get("attack_paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        return None

    return build_start_here_for_domains(
        [{"name": domain, "attack_paths": raw_paths}],
        node_cardinality=_node_cardinality_map_from_summary(summary),
        bounded=bounded,
    )


def _ranking_population_exclusions(
    shell: Any, domain: str, domain_data: dict[str, Any]
) -> list[str]:
    """The accounts the exposure KPIs leave out of their population.

    So "Most Exposed Accounts" counts the SAME population as the headline: a
    gMSA the KPI excluded (``services/account_population``) is not ranked. Read
    from the domain's in-memory KPI block when present, else resolved through
    the same population SSOT the KPI stamp uses. Best-effort: an unreadable
    population returns no exclusion, which keeps the ranking exactly as before.
    """
    from adscan_core.reporting.user_exposure_ranking import (  # noqa: PLC0415
        population_exclusions,
    )

    persisted = population_exclusions([domain_data])
    if persisted:
        return sorted(persisted)
    try:
        from types import SimpleNamespace  # noqa: PLC0415

        from adscan_internal.services.account_population import (  # noqa: PLC0415
            resolve_account_population,
        )

        population = resolve_account_population(
            SimpleNamespace(
                current_workspace_dir=str(
                    getattr(shell, "current_workspace_dir", "") or ""
                ),
                domains_dir="domains",
            ),
            domain,
        )
        return population.sorted_excluded()
    except Exception as exc:  # noqa: BLE001 - the ranking never depends on it
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return []


#: Scan-control step id of the choke-point analysis.
CHOKEPOINT_STEP_ID = "chokepoint_analysis"

#: What the analysis counts for its progress and its memory declaration: the
#: nodes and edges of the dominator flow graph it walks.
CHOKEPOINT_UNIT = "graph elements"


class _OperatorStoppedChokepoints(Exception):
    """The operator stopped the choke-point step; no partial summary survives."""


def _summary_or_stop(
    graph: dict[str, Any],
    value_terminals: set[str],
    stage: Any,
    step: Any,
) -> dict[str, Any] | None:
    """The memory-bounded body: the whole summary, or ``None`` on an operator stop.

    One function call, as :func:`adscan_core.memory_guard.memory_bounded`
    requires, so everything the computation built is released before the
    boundary declares a memory stop.
    """
    done = 0

    def _checkpoint(units: int) -> None:
        nonlocal done
        done += int(units)
        stage.tick(int(units))
        step.progress(done=done)
        if step.should_stop():
            raise _OperatorStoppedChokepoints()

    try:
        return build_chokepoint_summary(
            graph, value_terminals=value_terminals, top_k=20, checkpoint=_checkpoint
        )
    except _OperatorStoppedChokepoints:
        return None


def _clear_previous_chokepoint_stop(shell: Any, domain: str) -> None:
    """Forget an earlier stop of this analysis: it has just completed. Never raises."""
    try:
        from adscan_core.reporting.resource_coverage import (  # noqa: PLC0415
            STAGE_CHOKEPOINT_ANALYSIS,
        )
        from adscan_core.reporting.technical_report import (  # noqa: PLC0415
            read_resource_coverage,
        )
        from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
            record_stage_coverage,
        )

        block = read_resource_coverage(shell, domain) or {}
        if any(
            isinstance(item, dict) and item.get("stage") == STAGE_CHOKEPOINT_ANALYSIS
            for item in block.get("stages") or ()
        ):
            record_stage_coverage(
                shell,
                domain,
                {"complete": True, "stages": []},
                replace_stage=STAGE_CHOKEPOINT_ANALYSIS,
            )
    except Exception as exc:  # noqa: BLE001 - clearing a stop never raises
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def build_chokepoint_summary_bounded(
    *,
    shell: Any,
    domain: str,
    graph: dict[str, Any],
    value_terminals: set[str],
) -> dict[str, Any] | None:
    """:func:`build_chokepoint_summary` under the memory guard and the scan control.

    The computation is a long step the operator can stop and a memory-bounded
    stage (``chokepoint_analysis``). Either stop discards everything it computed:
    a partial cardinality is never returned as if it were complete. A memory stop
    is declared in the domain's ``resource_coverage`` block (the analysis maps to
    no scan phase: the paths and their figures are whole without it); an operator
    stop is declared by the scan control as a stopped step.

    Returns:
        The summary, or ``None`` when the analysis was stopped.
    """
    from adscan_core.memory_guard import OUTCOME_COMPLETE, memory_bounded  # noqa: PLC0415
    from adscan_core.reporting.resource_coverage import (  # noqa: PLC0415
        STAGE_CHOKEPOINT_ANALYSIS,
    )
    from adscan_core.scan_control import scan_control  # noqa: PLC0415
    from adscan_internal.services.resource_coverage_recorder import (  # noqa: PLC0415
        record_stage_coverage,
    )

    def _record(block: dict[str, Any]) -> None:
        record_stage_coverage(shell, domain, block)

    summary: dict[str, Any] | None = None
    with scan_control().step(
        CHOKEPOINT_STEP_ID,
        label="Choke-point analysis",
        long=True,
        unit=CHOKEPOINT_UNIT,
        domain=domain,
    ) as step:
        with memory_bounded(
            STAGE_CHOKEPOINT_ANALYSIS, unit=CHOKEPOINT_UNIT, record=_record
        ) as stage:
            summary = _summary_or_stop(graph, value_terminals, stage, step)
    if stage.outcome != OUTCOME_COMPLETE or summary is None:
        return None
    _clear_previous_chokepoint_stop(shell, domain)
    return summary


def stamp_chokepoint_cardinality_for_domain(
    *,
    shell: Any,
    domain: str,
    norm_graph: dict[str, Any],
    value_terminals: set[str],
    bounded: bool,
    domain_data: dict[str, Any],
    no_cache: bool = False,
) -> None:
    """Build + rank + persist the choke-point cardinality summary for one domain.

    This is the ONE tier-shared, LITE-safe stamp seam. Both the PRO report service
    (``ensure_report_attack_paths``) and the LITE report flow
    (``generate_lite_report_artifacts``) call it, so the choke-point block is
    computed identically in both tiers and no renderer has to re-load the (large)
    attack graph. It depends only on modules under ``services``/``adscan_core`` —
    never ``adscan_internal.pro`` — so it is reachable from the stripped LITE build.

    The choke-point summary answers "which single object, if removed, severs the
    most source -> value-terminal reach?" as set cardinality over the reachable
    set (no path enumeration). It is scoped to the REAL reachable value-terminal
    set (``value_terminals``), never an inferred one, so the ranking reflects the
    crown jewels this scope can actually reach.

    The ``bounded`` caveat is passed in already resolved (via
    :func:`resolve_choke_bounded`) so it reflects the same capped-run truth the
    report/web render — the choke caveat can never disagree with the coverage
    declaration.

    Best-effort by design: a choke-summary failure must NEVER break report
    generation or the KPI record, so the whole body is guarded and the summary is
    simply absent on failure. Persists to
    ``domains[<domain>]["chokepoint_cardinality"]`` (both the in-memory
    ``domain_data`` and the technical-report file) exactly the way the exposure
    KPIs are recorded.

    The two path-derived sub-blocks (``remediation_start_here`` and
    ``user_exposure``) come from ``domain_data["attack_paths"]``, so a caller
    that wants them must seed that list before calling — the persisted
    ``technical_report.json`` carries ``attack_paths: []`` by design (paths are
    derived on demand, never persisted).

    Idempotency: a block that :func:`chokepoint_block_is_derived` accepts is
    left untouched — nothing is recomputed or overwritten. A ranked block
    written before the attack paths reached this seam lacks the derivation
    marker and is re-stamped exactly once.

    ``no_cache=True`` BYPASSES that guard and always recomputes + overwrites.
    The guard exists for COST only (the choke set algebra over the graph): every
    caller derives the block from the same canonical domain listing, so a
    recompute yields the same block, never a different input set. But the guard
    keys only on "a derived block exists", so it cannot tell a block stamped
    THIS run from one a PREVIOUS run left in ``technical_report.json``, and that
    is how a stale ranking survives. A caller holding a freshly recomputed
    listing (the scan-end seam, the LITE render) passes ``no_cache=True``; the
    guard then only saves the repeat within one in-memory generation (PRO).

    Args:
        shell: A shell namespace carrying ``current_workspace_dir`` (the same
            shape ``record_exposure_kpis`` is called with).
        domain: The domain the summary belongs to.
        norm_graph: The normalized attack graph (``{"nodes": [...], "edges": [...]}``).
        value_terminals: The reachable value-terminal node ids.
        bounded: The already-resolved capped-run caveat (see
            :func:`resolve_choke_bounded`).
        domain_data: The in-memory report entry to stamp the summary onto.
        no_cache: Recompute and overwrite even when a derived block exists (see
            the idempotency note above).
    """
    # A graph a build stopped on is not this domain's graph: nothing may be ranked
    # or persisted from it (the readers declare "not evaluated" instead).
    try:
        from adscan_internal.services.graph_availability import (  # noqa: PLC0415
            domain_graph_unavailable_stage,
        )

        if domain_graph_unavailable_stage(shell, domain, graph=norm_graph):
            return None
    except Exception as exc:  # noqa: BLE001 -- availability is best-effort here
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    # Idempotency guard (cost only): a block that is ranked AND carries the
    # path-derivation marker was already derived from the attack paths, so there
    # is nothing left to add WITHIN one generation. ``no_cache`` bypasses it for
    # a caller whose listing is fresh, because a block persisted by an earlier
    # run satisfies the same predicate. See :func:`chokepoint_block_is_derived`.
    if not no_cache and chokepoint_block_is_derived(
        domain_data.get("chokepoint_cardinality")
    ):
        return

    try:
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415
    except Exception:  # noqa: BLE001 - never let an import break the report
        telemetry = None  # type: ignore[assignment]
        print_exception = None  # type: ignore[assignment]

    try:
        summary = build_chokepoint_summary_bounded(
            shell=shell,
            domain=domain,
            graph=norm_graph,
            value_terminals=value_terminals,
        )
        cardinality_complete = summary is not None
        if summary is None:
            # Stopped (memory or operator) and already declared. No cardinality,
            # no ranking and no KPI card are written: a partial count must never
            # read as complete, so the badge and the choke summary are simply
            # absent. The path-derived sub-blocks below do not depend on the
            # cardinality and are still derived. Without ``ranked_chokepoints``
            # the block is not "derived" (``chokepoint_block_is_derived``), so the
            # next stamp retries the analysis.
            summary = {
                "schema_version": 1,
                "value_terminal_count": len(
                    {str(t) for t in value_terminals if str(t)}
                ),
                CARDINALITY_STOPPED_KEY: True,
            }
        summary["bounded"] = bool(bounded)
        if cardinality_complete:
            # Rank + severity-enrich HERE, at the one seam that HAS the graph, so
            # every downstream render (PRO PDF, LITE, web) inherits the two-axis
            # order (severity leads cardinality) with real labels, WITHOUT re-loading
            # the ~194MB graph in each renderer. The persisted rows are kept JSON-safe:
            # the severity SSOT returns a ``Severity`` enum, coerced to its string
            # value; the shared ``ranked_edges`` back-reference each row carries is
            # dropped (identical on every row, not needed by the render). Best-effort —
            # a ranking failure must never break the summary.
            try:
                from adscan_internal.services.chokepoint_scoring import (  # noqa: PLC0415
                    rank_chokepoints,
                )

                _choke_nodes = (
                    norm_graph.get("nodes") if isinstance(norm_graph, dict) else None
                )
                _nodes_map: dict[str, Any] = {}
                if isinstance(_choke_nodes, dict):
                    for _nid, _node in _choke_nodes.items():
                        if isinstance(_node, dict):
                            _nodes_map[str(_node.get("id") or _nid)] = _node
                elif isinstance(_choke_nodes, list):
                    for _node in _choke_nodes:
                        if isinstance(_node, dict) and _node.get("id"):
                            _nodes_map[str(_node["id"])] = _node

                _ranked = rank_chokepoints(summary, nodes_map=_nodes_map, graph=norm_graph)
                summary["ranked_chokepoints"] = [
                    {
                        "node_id": str(_r.get("node_id") or ""),
                        "node_label": str(_r.get("node_label") or _r.get("node_id") or ""),
                        "cardinality": int(_r.get("cardinality") or 0),
                        # Severity is a ``str, Enum`` — store its plain string value.
                        "severity": str(getattr(_r.get("severity"), "value", "") or ""),
                        "severity_rank": int(_r.get("severity_rank") or 0),
                        "protected_terminal_label": str(
                            _r.get("protected_terminal_label") or ""
                        ),
                    }
                    for _r in _ranked
                ]
            except Exception as _rank_exc:  # noqa: BLE001 - ranking is best-effort
                if print_exception is not None:
                    print_exception(exception=_rank_exc)

            # Derive + persist the KPI headline card HERE, at the stamp seam, so every
            # downstream render (PRO PDF, LITE, web T6) reads the SAME card without
            # recomputing. It is derived from the ranked rows + exposure_source_count
            # already on the summary; JSON-safe; best-effort (a failure just omits the
            # card, older scans render unchanged).
            try:
                _kpi = derive_chokepoint_kpi(summary)
                if _kpi is not None:
                    summary["chokepoint_kpi"] = _kpi
            except Exception as _kpi_exc:  # noqa: BLE001 - card is best-effort
                if print_exception is not None:
                    print_exception(exception=_kpi_exc)

        # Derive + persist the "Start here" remediation LEAD (E4) HERE, at the one
        # seam that already has the domain's attack paths + the choke cardinality,
        # so every downstream render reads the SAME lead without recomputing. This
        # calls the ONE tier-shared model-builder the PRO PDF and LITE report use
        # (``services.remediation_start_here``): the validated-paths-broken ranking
        # (executed-over-theoretical), the executed/mapped count framing, the
        # structural-choke badge, and the KPI card. The paid web CTEM inherits it
        # verbatim (T6). JSON-safe; best-effort (a failure just omits the lead,
        # older scans render unchanged).
        try:
            _start_here = _build_remediation_start_here_for_domain(
                domain=domain,
                domain_data=domain_data,
                summary=summary,
                bounded=bool(bounded),
            )
            if _start_here is not None:
                summary["remediation_start_here"] = _start_here
        except Exception as _sh_exc:  # noqa: BLE001 - lead is best-effort
            if print_exception is not None:
                print_exception(exception=_sh_exc)

        # Persist the "Most Exposed Accounts" per-user exposure (IA v2) HERE, at the
        # same seam, so the web CTEM renders the SAME sub-block the PDF/LITE report
        # fold under the exposure headline without recomputing. Built from THIS
        # domain's attack paths (the SAME meta.affected_users the reach metric reads)
        # via the import-safe ranking SSOT; scale-safe (top-N + tail collapse).
        # JSON-safe; best-effort (a failure just omits the block).
        try:
            from adscan_core.reporting.user_exposure_ranking import (  # noqa: PLC0415
                build_user_exposure_ranking,
            )

            _ue_paths = domain_data.get("attack_paths")
            if isinstance(_ue_paths, list) and _ue_paths:
                _user_exposure = build_user_exposure_ranking(
                    [_p for _p in _ue_paths if isinstance(_p, dict)],
                    excluded_users=_ranking_population_exclusions(
                        shell, domain, domain_data
                    ),
                )
                if _user_exposure.get("top_users"):
                    summary["user_exposure"] = _user_exposure
        except Exception as _ue_exc:  # noqa: BLE001 - block is best-effort
            if print_exception is not None:
                print_exception(exception=_ue_exc)

        # Declare the derivation, always. Both sub-blocks above are omitted when
        # they come out empty, and on disk that is indistinguishable from never
        # having been derived at all — so a renderer or the paid web CTEM would
        # read an uncomputed block as a complete one. This marker is the
        # distinction: it records how many attack paths the derivation had and
        # whether each sub-block materialised, so "none to rank" reads as the
        # honest result it is and only a genuinely unmarked block is re-derived.
        _considered = domain_data.get("attack_paths")
        summary[PATH_DERIVED_BLOCKS_KEY] = {
            "attack_paths_considered": (
                len([_p for _p in _considered if isinstance(_p, dict)])
                if isinstance(_considered, list)
                else 0
            ),
            "remediation_start_here": "remediation_start_here" in summary,
            "user_exposure": "user_exposure" in summary,
        }

        domain_data["chokepoint_cardinality"] = summary
        record_chokepoint_cardinality(shell, domain, summary=summary)
    except Exception as exc:  # noqa: BLE001
        if telemetry is not None:
            telemetry.capture_exception(exc)
        if print_exception is not None:
            print_exception(exception=exc)
