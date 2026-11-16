"""The collected relationships of one build, as a re-iterable view over the store.

Wave 1 of the graph build turned every stored fact into a ``CollectorEdge`` held
in ``CollectionResult.edges`` for the whole build: memory that grows with the
number of FACTS, a multiple of the graph itself (spec section 14). This module
replaces that list with :class:`EdgeView`, which streams the store each time it
is iterated and holds nothing between iterations.

Rules every consumer follows (section 14.2):

* Iterate, never index or count. :class:`EdgeView` refuses ``len()`` and
  indexing with a ``TypeError``, so a rule cannot quietly depend on a list.
* Read only the relations you need: :meth:`EdgeView.of` (or :func:`edges_of`,
  which also accepts the plain list the 14.0.x persist still passes) pushes the
  filter into the store, so the other facts are never decoded.
* Never filter by subject or object id: those store filters build a lazy index
  meant for the reader paths, not for the build.
* The order is the store's stable order (stage, unit, position in the unit),
  the order the wave-1 list had, so a rule that keeps "the first" keeps the
  same one.

Every stream is closed when its iteration ends, early exit included: an open
read pins the SQLite WAL.

:func:`streamed_build_inputs` is the build's entry point: the objects and the
typed data materialised exactly as :func:`ingest.collection_result_from_store`
reads them, with ``result.edges`` the view.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

from adscan_core.graph_store import FactRecord, GraphStore
from adscan_internal.services.collector.models import CollectorEdge
from adscan_internal.services.graph_build import ingest

if TYPE_CHECKING:
    from adscan_internal.services.graph_build.api import GraphBuildContext
    from adscan_internal.services.graph_build.inputs import BuildInputs


def _close(stream: Any) -> None:
    close = getattr(stream, "close", None)
    if callable(close):
        close()


class EdgeView:
    """Re-iterable, filter-able view of a store's collected relationships.

    Each iteration streams ``store.iter_facts()`` and yields one
    ``CollectorEdge`` per fact, skipping the facts of an imported 14.0.x graph
    (``ingest.LEGACY_FACT_SOURCE``) and the evidence-only facts
    (``ingest.is_evidence_only_fact``) exactly as ``collection_result_from_store``
    does. Iteration and truthiness only.

    Args:
        store: The store to read.
        relations: Restrict to these relations (case-insensitive, as the store
            filters). ``None`` is every relation.
        on_fact: Called once per fact streamed (legacy ones included); the
            build's memory guard ticks here.
    """

    __slots__ = ("_store", "_relations", "_on_fact")

    def __init__(
        self,
        store: GraphStore,
        *,
        relations: Iterable[str] | None = None,
        on_fact: Callable[[], None] | None = None,
    ) -> None:
        self._store = store
        self._relations = (
            None if relations is None else frozenset(str(r).lower() for r in relations)
        )
        self._on_fact = on_fact

    @property
    def store(self) -> GraphStore:
        return self._store

    @property
    def relations(self) -> frozenset[str] | None:
        """The lowercase relation filter, or ``None`` for every relation."""
        return self._relations

    def of(self, relations: Iterable[str]) -> "EdgeView":
        """The same view restricted to ``relations`` (intersected with any filter already set)."""
        wanted = frozenset(str(r).lower() for r in relations)
        if self._relations is not None:
            wanted = wanted & self._relations
        return EdgeView(self._store, relations=wanted, on_fact=self._on_fact)

    def facts(self, *, include_legacy: bool = False) -> Iterator[FactRecord]:
        """Stream the stored facts themselves (they carry ``first_seen``/``last_seen``).

        Evidence-only facts (``ingest.is_evidence_only_fact``: the light share
        probe's readers) are never yielded: they are not collected
        relationships, never become an edge and never date one.
        ``include_legacy`` keeps the facts of an imported 14.0.x graph (the
        base-edge stream needs them for the inventory span, as wave 1 did).
        """
        stream = self._store.iter_facts(relations=self._relations)
        on_fact = self._on_fact
        try:
            for fact in stream:
                if on_fact is not None:
                    on_fact()
                if ingest.is_evidence_only_fact(fact):
                    continue
                if not include_legacy and ingest._is_legacy_fact(fact):  # noqa: SLF001
                    continue
                yield fact
        finally:
            _close(stream)

    def __iter__(self) -> Iterator[CollectorEdge]:
        stream = self.facts()
        try:
            for fact in stream:
                yield ingest.collector_edge_from_record(fact)
        finally:
            stream.close()

    def __bool__(self) -> bool:
        stream = self.facts()
        try:
            return next(stream, None) is not None
        finally:
            stream.close()

    def __len__(self) -> int:
        raise TypeError(
            "EdgeView streams the store and has no length; iterate it (spec section 14.2)"
        )

    def __getitem__(self, _index: Any) -> Any:
        raise TypeError(
            "EdgeView streams the store and cannot be indexed; iterate it (spec section 14.2)"
        )

    def __repr__(self) -> str:
        relations = "all" if self._relations is None else sorted(self._relations)
        return f"EdgeView(domain={self._store.domain!r}, relations={relations})"


def edges_of(edges: Any, relations: Iterable[str]) -> Any:
    """The relationships of ``edges`` whose relation is in ``relations``, re-iterable.

    ``edges`` is an :class:`EdgeView` (the build: the filter goes to the store)
    or the list a ``CollectionResult`` holds (the 14.0.x persist: a filtered
    list, in the same order). The match is case-insensitive, as the store's is;
    a rule that compares the exact relation keeps doing so on what it gets.
    """
    if isinstance(edges, EdgeView):
        return edges.of(relations)
    wanted = frozenset(str(r).lower() for r in relations)
    return [edge for edge in edges if str(edge.relation or "").lower() in wanted]


@dataclass(frozen=True)
class StampedEdge:
    """One collected relationship and, when it came from the store, its dates."""

    edge: CollectorEdge
    first_seen: str | None
    last_seen: str | None


class InventorySpan:
    """Earliest ``first_seen`` and latest ``last_seen`` over every fact of the store.

    The stamp of an edge no fact maps to (a derived edge): its inputs are the
    whole inventory, so its age is the inventory's.
    """

    __slots__ = ("earliest", "latest")

    def __init__(self) -> None:
        self.earliest = ""
        self.latest = ""

    def add(self, fact: FactRecord) -> None:
        if fact.last_seen > self.latest:
            self.latest = fact.last_seen
        if fact.first_seen and (not self.earliest or fact.first_seen < self.earliest):
            self.earliest = fact.first_seen

    def as_tuple(self) -> tuple[str, str]:
        return self.earliest, self.latest


def iter_stamped_edges(edges: Any, span: InventorySpan | None = None) -> Iterator[StampedEdge]:
    """Every relationship of ``edges`` with its store dates, in order.

    For an :class:`EdgeView` this is ONE stream of the store: every fact (the
    legacy-import ones included) widens ``span``, and the collected ones are
    yielded with ``first_seen``/``last_seen``. A plain list carries no dates
    (``None``): the 14.0.x persist stamps from the clock, as it always did.
    """
    if isinstance(edges, EdgeView):
        stream = edges.facts(include_legacy=True)
        try:
            for fact in stream:
                if span is not None:
                    span.add(fact)
                if ingest._is_legacy_fact(fact):  # noqa: SLF001
                    continue
                yield StampedEdge(
                    ingest.collector_edge_from_record(fact), fact.first_seen, fact.last_seen
                )
        finally:
            stream.close()
        return
    for edge in edges:
        yield StampedEdge(edge, None, None)


def streamed_build_inputs(
    store: GraphStore,
    context: "GraphBuildContext",
    *,
    on_fact: Callable[[], None] | None = None,
) -> "BuildInputs":
    """The inputs of a build of ``store``, with the relationships as an :class:`EdgeView`.

    Objects, the domain policy, the foreign-principal placeholders and the ACL
    census come from ``ingest.collection_result_from_store`` (its object half:
    asked for no stage's relationships, it decodes no fact); ``result.edges`` is
    the view. ``inputs.compute_build_inputs`` stays for a pass run on its own.
    """
    from adscan_internal.services.graph_build.inputs import (  # noqa: PLC0415
        BuildInputs,
        SiblingForeignRefs,
    )

    result = ingest.collection_result_from_store(store, stages=())
    result.edges = EdgeView(store, on_fact=on_fact)  # type: ignore[assignment]
    return BuildInputs(
        result=result,
        foreign_refs=SiblingForeignRefs(context.sibling_stores),
        domain_data=dict(context.domain_data or {}),
    )


__all__ = (
    "EdgeView",
    "InventorySpan",
    "StampedEdge",
    "edges_of",
    "iter_stamped_edges",
    "streamed_build_inputs",
)
