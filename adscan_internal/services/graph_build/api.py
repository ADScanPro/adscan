"""The graph build: inventory -> edges -> derived edges -> runtime overlay -> graph.

ONE deterministic function turns whatever the store holds into the attack graph.
It is stage-agnostic: it works on any subset of stages, in whatever order they
ran, and re-running it after a later stage added data gives the graph a single
build over the final inventory would have given. It concentrates the edge
derivation rules that 14.0.x spread across ``collector/persistence.py``,
``collector/mssql_collector.py``, ``attack_graph_service.save_attack_graph`` and
the load-time backfills. Design:
``docs/superpowers/specs/2026-11-12-inventory-first-graph-persistence.md``.

No ``shell`` anywhere in this package: the build takes a :class:`GraphBuildContext`
of plain values, so the same function runs in the CLI, in a test, in the bench
and (later) in the web worker.

Interface stubs. Package B implements the build, package C the export.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from adscan_core.graph_store import GraphStore, OverlayOp, StageRun, StoreGeneration

#: The graph as every consumer already knows it: the ``attack_graph.json``
#: document as a dict (``nodes`` keyed by node id, ``edges`` a list).
Graph = dict[str, Any]


#: The keys of a ``domains_data`` entry the build READS: an allow-list, so the
#: build context (and the live graph and export memo keyed on its fingerprint)
#: moves only when one of them does. Everything else the scan records about a
#: domain (posture signals, clock sync, authentication and lockout records,
#: credentials, progress, the export's own write-backs) is not a build input,
#: and a deny-list let every one of them force a full rebuild.
#:
#: Who reads what:
#: * DC coordinates and topology (``resolve_dc_ip``, ``resolve_dc_fqdn``,
#:   ``resolve_domain_controllers``): the graph root's command coordinates and
#:   the DC-targeted privileged-group escalation;
#: * ``netbios``, ``username`` (the scan principal), ``ca``, ``adcs``,
#:   ``adcs_fqdn``: the root's command coordinates;
#: * ``trusts``: the trust escalation edges and the AD CS display contract's
#:   same-forest test;
#: * ``domain_sid``: the trusted domain's Domain node the foreign-DC role
#:   marker synthesises (``enrich_foreign_dc_nodes_from_inventory``).
#:
#: Locked by ``tests/unit/services/graph_build/test_build_context_keys.py``:
#: a build over the fixtures with every key visible equals one over this view,
#: and every key the build reads is on the list.
BUILD_INPUT_KEYS: frozenset[str] = frozenset(
    {
        # DC coordinates and topology
        "pdc",
        "pdc_ip",
        "dc_ip",
        "dcs",
        "dc_fqdn",
        "pdc_fqdn",
        "pdc_hostname",
        "pdc_hostname_fqdn",
        "dns_server",
        "connectivity",
        # Command coordinates
        "netbios",
        "username",
        "ca",
        "adcs",
        "adcs_fqdn",
        # Trust records and the domain's own SID (the trusted Domain node the
        # foreign-DC marker synthesises is keyed by it)
        "trusts",
        "domain_sid",
    }
)

#: Kept for readers of the former deny-list: what the scan writes about ITSELF.
SCAN_BOOKKEEPING_KEYS: frozenset[str] = frozenset(
    {"attack_graph_file", "collection_stats", "collection_progress", "scan_progress"}
)


#: Build inputs nested inside a larger record: only the named path is kept, so
#: the rest of the record (a reachability summary that moves during a scan)
#: never reaches the fingerprint. ``resolve_dc_ip`` reads
#: ``connectivity.summary.pdc_ip`` and nothing else of it.
NESTED_BUILD_INPUTS: dict[str, tuple[str, ...]] = {"connectivity": ("summary", "pdc_ip")}


def _nested_view(value: Any, path: tuple[str, ...]) -> Any:
    """``value`` reduced to the one nested ``path`` (absent when it is not there)."""
    if not path:
        return value
    if not isinstance(value, Mapping) or path[0] not in value:
        return None
    inner = _nested_view(value[path[0]], path[1:])
    return None if inner is None else {path[0]: inner}


def domain_entry_build_view(entry: Any) -> dict[str, Any]:
    """A shallow copy of one ``domains_data`` entry holding only build inputs
    (:data:`BUILD_INPUT_KEYS`, nested records reduced to
    :data:`NESTED_BUILD_INPUTS`): never a credential, a secret field, a
    posture record or the scan's bookkeeping."""
    if not isinstance(entry, Mapping):
        return {}
    view: dict[str, Any] = {}
    for key in entry.keys():
        name = str(key)
        if name not in BUILD_INPUT_KEYS:
            continue
        if name in NESTED_BUILD_INPUTS:
            nested = _nested_view(entry[key], NESTED_BUILD_INPUTS[name])
            if nested is not None:
                view[name] = nested
            continue
        view[name] = entry[key]
    return view


def _canonical(value: Any) -> Any:
    """``value`` as plain JSON types with a total order, for the fingerprint.

    Keys become strings (a ``domains_data`` entry may carry a non-string key),
    sets and tuples become lists (a set sorted by its elements' JSON text), and
    anything else JSON cannot hold becomes its ``str``.
    """
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_canonical(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, default=str))
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


@dataclass(frozen=True)
class GraphBuildContext:
    """Everything the build needs that is not in the store. Plain values only.

    Attributes:
        domain: The domain being built.
        domain_data: This domain's ``domains_data`` entry (recorded DC, NetBIOS,
            CA name and host, scan principal). Read-only; may be empty. When
            empty and ``domains_data`` holds the domain, it is taken from there.
        domains_data: Every domain's recorded facts, by domain name, as a
            read-only view (the session's ``domains_data``). The post-overlay
            passes read the whole map: the AD CS display contract decides
            whether an edge crossing domains stays inside one forest from the
            trusts recorded on BOTH ends, so a map holding only this domain is
            wrong in a forest. This domain's entry is ``domain_data``.
        sibling_stores: Stores of the OTHER collected domains, by domain name.
            The build resolves a foreign SID through ``get_object`` on them,
            which replaces the cross-domain re-persist pass of 14.0.x.
        membership_resolver: Optional group-member example resolver for the
            command renderers. Never changes the edge set.
        coverage_run_id: Recorded run to stamp on the graph ("" when none).
        now: Clock for ``generated_at`` only. Edge timestamps come from the
            store, so two builds of one generation differ in ``generated_at``
            and nothing else.

    The context holds build inputs only and drops the rest on construction:
    each ``domains_data`` entry is reduced to :data:`BUILD_INPUT_KEYS` (an
    allow-list), so no credential, secret field, posture record or scan
    bookkeeping is ever held, and none of them invalidates the export
    (:meth:`fingerprint`).

    The views are shallow: nested values are shared with what the caller
    passed, so a caller that keeps mutating its map (the live session) builds
    the context from a snapshot (``graph_runtime.build_context_for`` does).
    """

    domain: str
    domain_data: Mapping[str, Any] = field(default_factory=dict)
    sibling_stores: Mapping[str, GraphStore] = field(default_factory=dict)
    membership_resolver: Callable[[str], Sequence[str]] | None = None
    coverage_run_id: str = ""
    now: Callable[[], str] | None = None
    domains_data: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        domains: dict[str, Mapping[str, Any]] = {}
        source = self.domains_data if isinstance(self.domains_data, Mapping) else {}
        for name, entry in source.items():
            domains[str(name)] = MappingProxyType(domain_entry_build_view(entry))
        own = domain_entry_build_view(self.domain_data)
        if not own and self.domain in domains:
            own = dict(domains[self.domain])
        if own or self.domain not in domains:
            domains[self.domain] = MappingProxyType(dict(own))
        object.__setattr__(self, "domain_data", own)
        object.__setattr__(self, "domains_data", MappingProxyType(domains))

    def domains_data_for_passes(self) -> dict[str, dict[str, Any]]:
        """The ``domains_data`` map as plain dicts, for code that checks
        ``isinstance(..., dict)`` (the AD CS display contract does)."""
        return {name: dict(entry) for name, entry in self.domains_data.items()}

    def fingerprint(self) -> str:
        """A stable digest of every input of the build that is not in the store.

        Covers ``domain``, ``domain_data``, ``domains_data``, ``coverage_run_id``
        and the generation of each sibling store (a foreign endpoint's label
        comes from there). The build depends on these, so the store generation
        alone is not a valid cache key: a graph is current for
        ``(store.generation(), context.fingerprint())``. ``now`` and
        ``membership_resolver`` are left out: they change ``generated_at`` and
        rendered commands, never the graph.

        The static part is computed once per context; the sibling generations
        are read on every call (a context outlives no build, but a sibling may
        commit while it lives).
        """
        static = self.__dict__.get("_static_fingerprint")
        if static is None:
            document = {
                "domain": self.domain,
                "domain_data": _canonical(self.domain_data),
                "domains_data": _canonical(self.domains_data),
                "coverage_run_id": self.coverage_run_id or "",
            }
            static = hashlib.sha256(
                json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            object.__setattr__(self, "_static_fingerprint", static)
        siblings: list[list[Any]] = []
        for name in sorted(self.sibling_stores):
            try:
                generation = self.sibling_stores[name].generation()
                siblings.append([name, int(generation.inventory), int(generation.overlay)])
            except Exception:  # noqa: BLE001 - an unreadable sibling is a distinct state
                siblings.append([name, -1, -1])
        if not siblings:
            return static
        digest = hashlib.sha256(static.encode("ascii"))
        digest.update(json.dumps(siblings, separators=(",", ":")).encode("utf-8"))
        return digest.hexdigest()


@dataclass(frozen=True)
class BuildReport:
    """What one build did. Feeds the bench, the debug log and the coverage record."""

    generation: StoreGeneration
    nodes: int = 0
    base_edges: int = 0
    derived_edges: int = 0
    overlay_edges: int = 0
    overlay_ops_applied: int = 0
    #: Overlay ops whose edge or node no longer exists in the base (kept, reported).
    overlay_ops_orphaned: int = 0
    dropped_facts: Mapping[str, int] = field(default_factory=dict)
    stages: Sequence[StageRun] = ()
    seconds_by_pass: Mapping[str, float] = field(default_factory=dict)
    seconds_total: float = 0.0


class DerivationPass(Protocol):
    """One edge-derivation rule set, run by the build in registry order.

    A pass reads the graph built so far (and the store, for data it needs) and
    adds, stamps or removes edges. It must be idempotent and must not depend on
    which stage ran last: it re-evaluates from what exists.
    """

    #: Stable name, used in ``BuildReport.seconds_by_pass`` and the spec's stage table.
    name: str
    #: Stages whose inventory this pass reads. Documentation and the planned
    #: incremental build; the full build runs every pass regardless.
    reads_stages: tuple[str, ...]

    def run(self, graph: Graph, store: GraphStore, context: GraphBuildContext) -> int:
        """Apply the pass in place. Returns how many edges it added or changed."""
        ...


def derivation_passes() -> tuple[DerivationPass, ...]:
    """The ordered registry of derivation passes (the SSOT of derived edges)."""
    from adscan_internal.services.graph_build.passes import registry  # noqa: PLC0415

    return registry()


def build_graph(store: GraphStore, context: GraphBuildContext) -> tuple[Graph, BuildReport]:
    """Build the attack graph of one domain from its store.

    Steps, in order: nodes from objects; base edges from facts; the derivation
    passes; the runtime overlay (:func:`apply_overlay_op`, in ``seq`` order);
    the post-overlay passes (engine follow-ups, edge classification, the Tier-0
    source prune, the AD CS display contract); stable ordering.

    Deterministic: the same generation and context give an identical graph
    apart from ``generated_at``. Never writes to disk and never mutates the store.
    """
    from adscan_internal.services.graph_build import build as _build  # noqa: PLC0415

    return _build.build_graph(store, context)


def apply_overlay_op(graph: Graph, op: OverlayOp) -> bool:
    """Apply ONE runtime operation to a built graph, in place.

    The single implementation of overlay semantics: the build calls it for every
    stored op, and the runtime facade calls it on the in-memory graph right
    after appending the op, so the live graph and a rebuilt graph can never
    disagree. Returns ``False`` when the op found nothing to act on (orphaned).

    Precisely (``graph_build.overlay``): ``False`` when the graph refused the op
    (a Tier-0-source edge), or when a patch, retire or node patch found no
    target. A status or edge write whose endpoint left the directory is still
    recorded, on a placeholder node, and returns ``True`` (the build counts it
    in ``BuildReport.overlay_ops_orphaned``), so a caller never reports a status
    that was not recorded and never loses one that was.
    """
    from adscan_internal.services.graph_build.overlay import (  # noqa: PLC0415
        OverlayOutcome,
        apply_op,
    )

    outcome = apply_op(graph, op)
    if outcome in (OverlayOutcome.REFUSED, OverlayOutcome.INVALID):
        return False
    if outcome is OverlayOutcome.ORPHANED:
        return op.kind in {"set_edge_status", "upsert_edge"}
    return True


def run_post_overlay_passes(graph: Graph, context: GraphBuildContext) -> None:
    """Re-run the passes that depend on edge statuses, after overlay changes.

    The same step the build ends with (``build.finish_post_overlay``): the
    post-overlay passes over the real ``context.domains_data``, then the root
    ``technique_knowledge`` block, so a live graph patched by the runtime facade
    carries the block a rebuild would write.
    """
    from adscan_internal.services.graph_build.build import (  # noqa: PLC0415
        finish_post_overlay,
    )

    finish_post_overlay(graph, context)


# --------------------------------------------------------------------------- #
# Export (package C)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExportPolicy:
    """When a dirty store is written out to ``attack_graph.json``.

    Attributes:
        min_interval_seconds: Floor between two automatic exports.
        cost_multiple: An automatic export also waits ``cost_multiple`` times
            the previous export's duration, so a slow disk or a huge graph backs
            off on its own instead of exporting back to back.
    """

    min_interval_seconds: float = 60.0
    cost_multiple: float = 10.0


def export_graph(graph: Graph, path: str | Path) -> int:
    """Write ``graph`` to ``path`` as ``attack_graph.json`` (format 2).

    Streams node by node and edge by edge into a temporary file, fsyncs and
    atomically replaces ``path``; peak memory is the graph plus one element, not
    the graph plus its whole serialisation. Returns the bytes written.
    """
    # Package C creates ``graph_build/export.py``; this module never changes for it.
    from adscan_internal.services.graph_build import export as _export

    return _export.export_graph(graph, path)


def export_if_due(
    store: GraphStore,
    context: GraphBuildContext,
    path: str | Path,
    *,
    policy: ExportPolicy = ExportPolicy(),
    force: bool = False,
    after_export: Callable[[Graph], None] | None = None,
) -> bool:
    """Build and export when ``(store.generation(), context.fingerprint())``
    moved since the last export and the policy allows it (or ``force``).
    Returns whether a file was written. ``after_export`` receives the built
    graph once the file is in place (the sidecar exports)."""
    from adscan_internal.services.graph_build import export as _export

    return _export.export_if_due(
        store, context, path, policy=policy, force=force, after_export=after_export
    )


__all__ = (
    "BUILD_INPUT_KEYS",
    "NESTED_BUILD_INPUTS",
    "SCAN_BOOKKEEPING_KEYS",
    "BuildReport",
    "domain_entry_build_view",
    "DerivationPass",
    "ExportPolicy",
    "Graph",
    "GraphBuildContext",
    "apply_overlay_op",
    "build_graph",
    "derivation_passes",
    "export_graph",
    "export_if_due",
    "run_post_overlay_passes",
)
