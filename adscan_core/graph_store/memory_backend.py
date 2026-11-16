"""In-memory reference implementation of :class:`GraphStore`.

Not a product backend: nothing is persisted. It exists so that

* the packages that CONSUME the store (the graph build, the collector stages,
  the runtime facade) are developed and unit-tested against the interface
  before, and independently of, the on-disk backend;
* the conformance suite has a second implementation to run against, which is
  what proves the interface (not one backend's accidents) is the contract.

It honours the same contract as the on-disk backend (unit atomicity, unit
replacement, stable order, append-only overlay); see ``interface.py``.

Stdlib only.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from adscan_core.graph_store.interface import GraphStoreFrozenError
from adscan_core.graph_store.records import (
    DatumRecord,
    ExportRecord,
    FactRecord,
    ObjectRecord,
    OverlayOp,
    StageRun,
    StageStatus,
    StoreGeneration,
    StoreStats,
)
from adscan_core.graph_store.secret_guard import guard_secrets


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fact_identity(stage: str, fact: FactRecord) -> tuple[str, str, str, str, str, str]:
    from adscan_core.attack_graph_edge_identity import edge_identity_discriminator

    return (
        stage,
        fact.subject_id.upper(),
        fact.object_id.upper(),
        fact.relation.lower(),
        fact.method,
        edge_identity_discriminator(fact.relation, fact.notes),
    )


class _MemoryUnitWriter:
    """Buffers one unit; the store applies the buffer when the block commits.

    Every payload passes the store's secret guard on the way in, as in the
    on-disk backend, so a test against this store sees what is persisted.
    """

    def __init__(self, domain: str = "") -> None:
        self._domain = domain
        self.objects: list[ObjectRecord] = []
        self.facts: list[FactRecord] = []
        self.data: list[DatumRecord] = []
        self.patches: list[tuple[str, dict[str, Any]]] = []

    def add_objects(self, objects: Iterable[ObjectRecord]) -> int:
        before = len(self.objects)
        self.objects.extend(
            replace(
                obj,
                properties=guard_secrets(
                    obj.properties, domain=self._domain, object_id=obj.object_id
                ),
            )
            for obj in objects
        )
        return len(self.objects) - before

    def add_facts(self, facts: Iterable[FactRecord]) -> int:
        before = len(self.facts)
        self.facts.extend(
            replace(
                fact,
                notes=guard_secrets(
                    fact.notes,
                    relation=fact.relation,
                    domain=self._domain,
                    object_id=fact.subject_id,
                ),
            )
            for fact in facts
        )
        return len(self.facts) - before

    def add_data(self, data: Iterable[DatumRecord]) -> int:
        before = len(self.data)
        self.data.extend(
            replace(
                datum,
                body=guard_secrets(
                    datum.body,
                    domain=self._domain,
                    object_id=f"{datum.kind}:{datum.key}",
                ),
            )
            for datum in data
        )
        return len(self.data) - before

    def patch_object(self, object_id: str, properties: dict[str, Any]) -> None:
        self.patches.append(
            (
                object_id.upper(),
                dict(
                    guard_secrets(
                        properties, domain=self._domain, object_id=str(object_id)
                    )
                ),
            )
        )


class MemoryGraphStore:
    """A :class:`GraphStore` held in process memory."""

    def __init__(self, domain: str, *, read_only: bool = False) -> None:
        self._domain = domain
        self._read_only = read_only
        self._lock = threading.RLock()
        self._objects: dict[str, ObjectRecord] = {}
        # (stage, unit) -> (commit order, facts, data, object patches)
        self._units: dict[
            tuple[str, str], tuple[int, list[FactRecord], list[DatumRecord]]
        ] = {}
        self._patches: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = {}
        self._first_seen: dict[tuple[str, str, str, str, str, str], str] = {}
        self._stages: dict[str, StageRun] = {}
        self._overlay: list[OverlayOp] = []
        self._inventory_generation = 0
        self._export: ExportRecord | None = None

    # ---- lifecycle -------------------------------------------------------- #

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def read_only(self) -> bool:
        return self._read_only

    def close(self) -> None:
        return None

    def _require_writable(self) -> None:
        if self._read_only:
            raise GraphStoreFrozenError(f"graph store of {self._domain} is read-only")

    # ---- collection -------------------------------------------------------- #

    def begin_stage(
        self,
        stage: str,
        *,
        run_id: str = "",
        units_total: int = 0,
        collector_version: str = "",
        fresh: bool = False,
    ) -> StageRun:
        self._require_writable()
        with self._lock:
            if fresh:
                for key in [k for k in self._units if k[0] == stage]:
                    del self._units[key]
                    self._patches.pop(key, None)
                self._inventory_generation += 1
            now = _utc_now()
            previous = self._stages.get(stage)
            run = StageRun(
                stage=stage,
                status="running",
                run_id=run_id,
                units_total=units_total,
                units_done=len(self.done_units(stage)),
                collector_version=collector_version,
                started_at=previous.started_at if previous and not fresh else now,
                updated_at=now,
            )
            self._stages[stage] = run
            return run

    @contextmanager
    def unit(
        self, stage: str, unit: str, *, observed_at: str = ""
    ) -> Iterator[_MemoryUnitWriter]:
        self._require_writable()
        writer = _MemoryUnitWriter(self._domain)
        yield writer  # an exception here discards the buffer: nothing was applied
        stamp = observed_at or _utc_now()
        with self._lock:
            for obj in writer.objects:
                self._objects[obj.object_id.upper()] = obj
            facts = []
            for fact in writer.facts:
                identity = _fact_identity(stage, fact)
                first = self._first_seen.setdefault(identity, stamp)
                facts.append(replace(fact, first_seen=first, last_seen=stamp))
            self._inventory_generation += 1
            self._units[(stage, unit)] = (
                self._inventory_generation,
                facts,
                list(writer.data),
            )
            self._patches[(stage, unit)] = list(writer.patches)
            run = self._stages.get(stage)
            if run is not None:
                self._stages[stage] = replace(
                    run, units_done=len(self.done_units(stage)), updated_at=_utc_now()
                )

    def end_stage(
        self, stage: str, status: StageStatus, *, reason: str = "", detail: str = ""
    ) -> StageRun:
        self._require_writable()
        with self._lock:
            now = _utc_now()
            run = self._stages.get(stage) or StageRun(
                stage=stage, status=status, started_at=now
            )
            run = replace(
                run,
                status=status,
                reason=reason,
                detail=detail,
                units_done=len(self.done_units(stage)),
                updated_at=now,
            )
            self._stages[stage] = run
            self._inventory_generation += 1
            return run

    def stage_runs(self) -> list[StageRun]:
        with self._lock:
            return list(self._stages.values())

    def done_units(self, stage: str) -> frozenset[str]:
        with self._lock:
            return frozenset(unit for (st, unit) in self._units if st == stage)

    # ---- inventory reads --------------------------------------------------- #

    def _patched(self, obj: ObjectRecord) -> ObjectRecord:
        merged: dict[str, Any] | None = None
        key = obj.object_id.upper()
        for unit_key in sorted(self._patches, key=lambda k: self._units[k][0]):
            for object_id, properties in self._patches[unit_key]:
                if object_id == key:
                    merged = {
                        **(merged if merged is not None else obj.properties),
                        **properties,
                    }
        return obj if merged is None else replace(obj, properties=merged)

    def iter_objects(
        self, *, kinds: Iterable[str] | None = None
    ) -> Iterator[ObjectRecord]:
        wanted = {k.lower() for k in kinds} if kinds is not None else None
        with self._lock:
            snapshot = [self._patched(self._objects[k]) for k in sorted(self._objects)]
        for obj in snapshot:
            if wanted is None or obj.kind.lower() in wanted:
                yield obj

    def get_object(self, object_id: str) -> ObjectRecord | None:
        with self._lock:
            obj = self._objects.get(str(object_id or "").upper())
            return self._patched(obj) if obj is not None else None

    def find_objects(
        self, *, name: str = "", distinguished_name: str = "", samaccountname: str = ""
    ) -> list[ObjectRecord]:
        def _match(obj: ObjectRecord) -> bool:
            return (
                (not name or obj.name.casefold() == name.casefold())
                and (
                    not distinguished_name
                    or obj.distinguished_name.casefold()
                    == distinguished_name.casefold()
                )
                and (
                    not samaccountname
                    or obj.samaccountname.casefold() == samaccountname.casefold()
                )
            )

        if not (name or distinguished_name or samaccountname):
            return []
        return [obj for obj in self.iter_objects() if _match(obj)]

    def iter_facts(
        self,
        *,
        stages: Iterable[str] | None = None,
        relations: Iterable[str] | None = None,
        subject_id: str = "",
        object_id: str = "",
    ) -> Iterator[FactRecord]:
        stage_set = set(stages) if stages is not None else None
        relation_set = {r.lower() for r in relations} if relations is not None else None
        subject = subject_id.upper()
        target = object_id.upper()
        with self._lock:
            # Stable order: stage name, unit name, then position inside the unit.
            snapshot = [
                fact
                for key in sorted(self._units)
                if stage_set is None or key[0] in stage_set
                for fact in self._units[key][1]
            ]
        for fact in snapshot:
            if relation_set is not None and fact.relation.lower() not in relation_set:
                continue
            if subject and fact.subject_id.upper() != subject:
                continue
            if target and fact.object_id.upper() != target:
                continue
            yield fact

    def iter_data(self, kind: str) -> Iterator[DatumRecord]:
        with self._lock:
            latest: dict[str, tuple[int, DatumRecord]] = {}
            for order, _facts, data in self._units.values():
                for datum in data:
                    if (
                        datum.kind == kind
                        and order >= latest.get(datum.key, (0, datum))[0]
                    ):
                        latest[datum.key] = (order, datum)
        for key in sorted(latest):
            yield latest[key][1]

    # ---- runtime overlay --------------------------------------------------- #

    def append_overlay(self, ops: Iterable[OverlayOp]) -> StoreGeneration:
        self._require_writable()
        with self._lock:
            for op in ops:
                relation = op.edge.relation if op.edge is not None else ""
                edge = op.edge
                if edge is not None:
                    edge = replace(
                        edge,
                        identity_notes=guard_secrets(
                            edge.identity_notes, relation=relation, domain=self._domain
                        ),
                    )
                self._overlay.append(
                    replace(
                        op,
                        edge=edge,
                        payload=guard_secrets(
                            op.payload, relation=relation, domain=self._domain
                        ),
                        seq=len(self._overlay) + 1,
                        recorded_at=op.recorded_at or _utc_now(),
                    )
                )
            return self.generation()

    def iter_overlay(self, *, after_seq: int = 0) -> Iterator[OverlayOp]:
        with self._lock:
            snapshot = self._overlay[max(after_seq, 0) :]
        yield from snapshot

    # ---- build state -------------------------------------------------------- #

    def generation(self) -> StoreGeneration:
        with self._lock:
            return StoreGeneration(
                inventory=self._inventory_generation, overlay=len(self._overlay)
            )

    def last_export(self) -> ExportRecord | None:
        return self._export

    def record_export(self, record: ExportRecord) -> None:
        self._require_writable()
        self._export = record

    def stats(self) -> StoreStats:
        with self._lock:
            return StoreStats(
                objects=len(self._objects),
                facts=sum(len(facts) for _o, facts, _d in self._units.values()),
                data=sum(len(data) for _o, _f, data in self._units.values()),
                overlay_ops=len(self._overlay),
                size_bytes=0,
            )


__all__ = ("MemoryGraphStore",)
