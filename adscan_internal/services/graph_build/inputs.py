"""What the derivation passes of one build read: the store's collected view, resolved.

A derivation pass has the :class:`~adscan_internal.services.graph_build.api.DerivationPass`
signature ``run(graph, store, context)``. The collection view it derives from
(the ``CollectionResult`` the rules were written against, the object-SID to
graph-id index, the foreign-endpoint registry) is computed ONCE per build and
handed to every pass through :func:`active_build_inputs`, a context variable the
build sets while its passes run. A pass called on its own, outside a build,
computes the same inputs itself; the result is identical, only slower.

No ``shell``: every input comes from the store and the build context.
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from adscan_core.graph_store import GraphStore, ObjectRecord
from adscan_internal.services import attack_graph_service
from adscan_internal.services.collector.models import CollectionResult, ForeignNodeRef
from adscan_internal.services.graph_build.ingest import (
    collection_result_from_store,
    collector_node_from_record,
)
from adscan_internal.services.graph_build.nodes import UpsertedNodes, upsert_result_nodes

if TYPE_CHECKING:
    from adscan_internal.services.graph_build.api import GraphBuildContext


class SiblingForeignRefs(Mapping[str, ForeignNodeRef]):
    """Object SID -> :class:`ForeignNodeRef` over the OTHER collected domains' stores.

    The store-backed equivalent of the orchestrator's cross-domain label
    registry (``collector.orchestrator.build_cross_domain_label_registry``): a
    foreign SID resolves to the exact graph id its own domain's graph uses, so a
    cross-domain edge's light endpoint merges onto the real foreign node. Looked
    up per SID through each sibling's indexed ``get_object`` (no full scan),
    memoised for the build. Siblings are consulted in domain-name order, so the
    answer never depends on dict ordering.
    """

    def __init__(self, sibling_stores: Mapping[str, GraphStore]) -> None:
        self._stores = [sibling_stores[name] for name in sorted(sibling_stores)]
        self._cache: dict[str, ForeignNodeRef | None] = {}

    def _resolve(self, sid: str) -> ForeignNodeRef | None:
        for store in self._stores:
            record = store.get_object(sid)
            if record is not None:
                return foreign_ref_from_record(record)
        return None

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        sid = str(key or "").upper()
        if not sid:
            return default
        if sid not in self._cache:
            self._cache[sid] = self._resolve(sid)
        ref = self._cache[sid]
        return default if ref is None else ref

    def __getitem__(self, key: str) -> ForeignNodeRef:
        ref = self.get(key)
        if ref is None:
            raise KeyError(key)
        return ref

    def __iter__(self) -> Iterator[str]:
        return iter(sid for sid, ref in self._cache.items() if ref is not None)

    def __len__(self) -> int:
        return sum(1 for ref in self._cache.values() if ref is not None)

    def __bool__(self) -> bool:
        # Resolves lazily, so "nothing resolved yet" must not read as "empty":
        # a caller's ``registry or {}`` would otherwise discard it.
        return bool(self._stores)


def foreign_ref_from_record(record: ObjectRecord) -> ForeignNodeRef:
    """The cross-domain reference of one collected object (same rule as the orchestrator)."""
    payload = collector_node_from_record(record).to_graph_payload()
    return ForeignNodeRef(
        node_id=attack_graph_service._node_id(payload),  # noqa: SLF001
        label=str(payload.get("label") or record.name or record.object_id),
        kind=str(payload.get("kind") or "Base"),
        is_tier0=bool(payload.get("isTierZero") or payload.get("highvalue")),
    )


@dataclass
class BuildInputs:
    """The resolved collection view of one build.

    Attributes:
        result: The store's collected objects and relationships as the
            ``CollectionResult`` the derivation rules read.
        nodes: The classified node payloads and the SID -> graph id index, set
            once the build has written the nodes into its graph.
        foreign_refs: Foreign SID resolution over the sibling stores.
        domain_data: This domain's recorded facts (``context.domain_data``).
    """

    result: CollectionResult
    foreign_refs: Mapping[str, ForeignNodeRef]
    domain_data: Mapping[str, Any] = field(default_factory=dict)
    nodes: UpsertedNodes | None = None

    @property
    def sid_to_graph_id(self) -> dict[str, str]:
        return self.nodes.sid_to_graph_id if self.nodes is not None else {}


_ACTIVE: contextvars.ContextVar[tuple[GraphStore, BuildInputs] | None] = contextvars.ContextVar(
    "adscan_graph_build_inputs", default=None
)


def compute_build_inputs(store: GraphStore, context: "GraphBuildContext") -> BuildInputs:
    """The inputs of a build of ``store`` (no graph written)."""
    return BuildInputs(
        result=collection_result_from_store(store),
        foreign_refs=SiblingForeignRefs(context.sibling_stores),
        domain_data=dict(context.domain_data or {}),
    )


@contextmanager
def activate_build_inputs(store: GraphStore, inputs: BuildInputs) -> Iterator[BuildInputs]:
    """Hand ``inputs`` to every pass that runs inside the block."""
    token = _ACTIVE.set((store, inputs))
    try:
        yield inputs
    finally:
        _ACTIVE.reset(token)


def active_build_inputs(
    store: GraphStore, context: "GraphBuildContext", graph: dict[str, Any]
) -> BuildInputs:
    """The inputs of the build running on ``store``, or freshly computed ones.

    Outside a build the node index is computed by writing the nodes into a
    scratch graph of the same domain, so a pass run on its own resolves the same
    graph ids the build would.
    """
    active = _ACTIVE.get()
    if active is not None and active[0] is store:
        return active[1]
    inputs = compute_build_inputs(store, context)
    scratch = {"domain": str(graph.get("domain") or context.domain), "nodes": {}, "edges": []}
    inputs.nodes = upsert_result_nodes(scratch, inputs.result)
    return inputs


__all__ = (
    "BuildInputs",
    "SiblingForeignRefs",
    "activate_build_inputs",
    "active_build_inputs",
    "compute_build_inputs",
    "foreign_ref_from_record",
)
