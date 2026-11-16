"""The ONE interface to the workspace graph store.

Every collector stage, every runtime writer, the graph build and the export go
through :class:`GraphStore`. No caller names the backend, a file inside the
store, or a SQL statement: replacing the backend touches the backend module and
:func:`open_graph_store`, nothing else. Locked by
``tests/unit/core/graph_store/test_store_is_behind_one_interface.py`` (package A).

Contract every backend honours (the conformance suite in
``tests/unit/core/graph_store/conformance.py`` runs against any implementation):

* **Unit atomicity.** Everything written inside one ``unit(...)`` block becomes
  visible together, with the unit marked done, or not at all. A crash, an
  exception or a Ctrl+C inside the block leaves the store exactly as it was
  before the block. This is what replaces the "persist the graph, THEN record
  the host as done" ordering of 14.0.x: the two are one commit.
* **Unit replacement.** Opening a unit that already exists replaces its facts
  and data (a re-collected host drops the sessions that are gone). Objects are
  keyed by id and replaced per object.
* **A fact's unit is a function of its own object, never of paging order.**
  The unit a stage files a fact under must be derived from the object the
  fact belongs to (the host's SID, the object class, the CA, the instance),
  never from the position the object happened to have in a result page, a
  batch or a worker queue. Re-collection must put the same fact in the same
  unit, because that is what makes the replacement above drop exactly what
  is gone, makes ``done_units`` a valid resume skip-set, and lets the fact
  keep its ``first_seen``: a backend only has to carry ``first_seen`` across
  the replacement of the unit the fact was in, so a fact that moves to
  another unit (object 51 lands on page 2 instead of page 1 after one object
  was added) reads as new and the old unit keeps a stale copy until it is
  re-collected itself.
* **Readers never block the writer and never see a partial unit.** A second
  process (the web backend, during a running scan) reads committed state only.
* **One writer process per store.** Threads of that process may write
  concurrently; the store serialises them.
* **The overlay is append-only.** No call rewrites or deletes an appended op.
* **Order is stable.** ``iter_facts`` and ``iter_overlay`` return records in a
  deterministic order that does not depend on timing, so two builds from one
  generation produce the same graph.
* **No secrets.** A value that is a recovered credential never reaches the store.
* **It lives in the workspace.** One directory per domain,
  ``<workspace>/domains/<domain>/graph_store/``; deleting the workspace removes it.

Stdlib only.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

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

#: Directory of one domain's store, relative to ``domains/<domain>/``.
GRAPH_STORE_DIRNAME = "graph_store"


class GraphStoreError(Exception):
    """The store could not be opened, read or written."""


class GraphStoreVersionError(GraphStoreError):
    """The store on disk was written by an incompatible schema major."""


class GraphStoreFrozenError(GraphStoreError):
    """A write was attempted on a store opened read-only or on a frozen workspace."""


@runtime_checkable
class UnitWriter(Protocol):
    """Writes of ONE collection unit (one host, one LDAP object class, one instance).

    Obtained from :meth:`GraphStore.unit`. All methods buffer or stream into the
    unit's transaction; nothing is visible to a reader until the block exits
    without an exception.
    """

    def add_objects(self, objects: Iterable[ObjectRecord]) -> int:
        """Add or replace directory objects. Returns how many were written."""
        ...

    def add_facts(self, facts: Iterable[FactRecord]) -> int:
        """Add raw relationships observed in this unit. Returns how many were written."""
        ...

    def add_data(self, data: Iterable[DatumRecord]) -> int:
        """Add or replace typed non-graph records observed in this unit."""
        ...

    def patch_object(self, object_id: str, properties: dict[str, Any]) -> None:
        """Merge ``properties`` into an object this or an earlier stage wrote.

        For a later stage that learns something about an existing object (the
        SMB stage reading a host's OS build, its signing state). A patch on an
        unknown object id is kept and applied when the object arrives.
        """
        ...


@runtime_checkable
class GraphStore(Protocol):
    """One domain's working store: inventory, runtime overlay, build state."""

    # ---- lifecycle -------------------------------------------------------- #

    @property
    def domain(self) -> str:
        """The domain this store belongs to."""
        ...

    @property
    def read_only(self) -> bool:
        """Whether writes raise :class:`GraphStoreFrozenError`."""
        ...

    def close(self) -> None:
        """Flush and release the store. Idempotent. Leaves no lock or journal a
        whole-directory copy of the workspace could capture half-written."""
        ...

    # ---- collection: stages and units ------------------------------------- #

    def begin_stage(
        self,
        stage: str,
        *,
        run_id: str = "",
        units_total: int = 0,
        collector_version: str = "",
        fresh: bool = False,
    ) -> StageRun:
        """Mark ``stage`` running. ``fresh=True`` discards the stage's earlier
        units (the ``ADSCAN_COLLECTOR_FRESH`` re-scan); otherwise done units are
        kept and :meth:`done_units` is the resume skip-set."""
        ...

    def unit(
        self, stage: str, unit: str, *, observed_at: str = ""
    ) -> AbstractContextManager[UnitWriter]:
        """Open one collection unit as an atomic block (see the module contract).

        ``observed_at`` (UTC ISO) is the calendar time the unit is stamped with;
        the store uses its own wall clock when empty. It is a persisted absolute
        timestamp, never used to measure a duration.
        """
        ...

    def end_stage(
        self, stage: str, status: StageStatus, *, reason: str = "", detail: str = ""
    ) -> StageRun:
        """Record how ``stage`` ended. ``skipped`` may be recorded without a
        ``begin_stage``: a stage the policy or the operator left out is a
        declared gap, never an absence."""
        ...

    def stage_runs(self) -> list[StageRun]:
        """Every stage the store knows, in first-seen order."""
        ...

    def done_units(self, stage: str) -> frozenset[str]:
        """Units of ``stage`` whose block committed."""
        ...

    # ---- inventory reads --------------------------------------------------- #

    def iter_objects(
        self, *, kinds: Iterable[str] | None = None
    ) -> Iterator[ObjectRecord]:
        """Every object, patches applied, ordered by object id."""
        ...

    def get_object(self, object_id: str) -> ObjectRecord | None:
        """One object by id (SID or GUID), case-insensitive. Indexed."""
        ...

    def find_objects(
        self, *, name: str = "", distinguished_name: str = "", samaccountname: str = ""
    ) -> list[ObjectRecord]:
        """Objects by label, DN or sAMAccountName, case-insensitive. Indexed."""
        ...

    def iter_facts(
        self,
        *,
        stages: Iterable[str] | None = None,
        relations: Iterable[str] | None = None,
        subject_id: str = "",
        object_id: str = "",
    ) -> Iterator[FactRecord]:
        """Raw relationships of committed units, in stable order. The filters
        are indexed; no filter streams everything in bounded memory."""
        ...

    def iter_data(self, kind: str) -> Iterator[DatumRecord]:
        """Typed non-graph records of one family, ordered by key."""
        ...

    # ---- runtime overlay --------------------------------------------------- #

    def append_overlay(self, ops: Iterable[OverlayOp]) -> StoreGeneration:
        """Append runtime operations atomically and durably; returns the new
        generation. Safe from any thread of the writer process."""
        ...

    def iter_overlay(self, *, after_seq: int = 0) -> Iterator[OverlayOp]:
        """Overlay operations with ``seq > after_seq``, in ``seq`` order."""
        ...

    # ---- build state -------------------------------------------------------- #

    def generation(self) -> StoreGeneration:
        """What the store holds now. Cheap: called on every graph load."""
        ...

    def last_export(self) -> ExportRecord | None:
        """The last ``attack_graph.json`` written from this store, if any."""
        ...

    def record_export(self, record: ExportRecord) -> None:
        """Record an export (called by the exporter after its atomic replace)."""
        ...

    def stats(self) -> StoreStats:
        """Counts and on-disk size."""
        ...


def graph_store_dir(domain_dir: str | Path) -> Path:
    """Where one domain's store lives: ``<domain_dir>/graph_store``."""
    return Path(domain_dir) / GRAPH_STORE_DIRNAME


def graph_store_exists(domain_dir: str | Path) -> bool:
    """Whether a store has been created for this domain directory.

    ``False`` for a workspace written by 14.0.x: its graph is read from
    ``attack_graph.json`` and imported on the first write.
    """
    from adscan_core.graph_store.sqlite_backend import store_exists  # noqa: PLC0415

    return store_exists(graph_store_dir(domain_dir))


def open_graph_store(
    domain_dir: str | Path, *, domain: str, read_only: bool = False, create: bool = True
) -> GraphStore:
    """Open (or create) the store of one domain. THE factory: the only place a
    backend is chosen.

    Args:
        domain_dir: ``<workspace>/domains/<domain>`` (the execution workspace's
            during a live scan, exactly like every other per-scan artifact).
        domain: The domain name, recorded in the store and checked on reopen.
        read_only: Open for reads only. Forced when the workspace is frozen
            (``adscan_core.workspace_freeze.write_blocked``).
        create: Create the store when absent. ``False`` raises
            :class:`GraphStoreError` on a missing store.

    Raises:
        GraphStoreVersionError: The store was written by another schema major.
        GraphStoreError: It cannot be opened, or another process holds it for writing.
    """
    from adscan_core.graph_store.sqlite_backend import SqliteGraphStore  # noqa: PLC0415
    from adscan_core.workspace_freeze import write_blocked  # noqa: PLC0415

    store_dir = graph_store_dir(domain_dir)
    return SqliteGraphStore(
        store_dir,
        domain=domain,
        read_only=read_only,
        create=create,
        frozen=write_blocked(store_dir),
    )


def scrub_graph_store(domain_dir: str | Path, transform: Callable[[Any], Any]) -> int:
    """Rewrite every JSON document of one domain's store through ``transform``.

    The workspace secret purge's single entry into the store
    (``adscan_core.workspace_secret_purge``): the overlay is append-only for every
    other caller, and removing a recovered value from the history is the one
    exception. The backend also discards the freed bytes, so the removed value
    is gone from the files, not only unreferenced. Returns how many stored
    documents changed; 0 when the domain has no store.

    Raises:
        GraphStoreError: The store cannot be opened, or a writer holds it.
    """
    if not graph_store_exists(domain_dir):
        return 0
    from adscan_core.graph_store.sqlite_backend import scrub_store_documents  # noqa: PLC0415

    return scrub_store_documents(graph_store_dir(domain_dir), transform)


__all__ = (
    "GRAPH_STORE_DIRNAME",
    "GraphStore",
    "GraphStoreError",
    "GraphStoreFrozenError",
    "GraphStoreVersionError",
    "UnitWriter",
    "graph_store_dir",
    "graph_store_exists",
    "open_graph_store",
    "scrub_graph_store",
)
