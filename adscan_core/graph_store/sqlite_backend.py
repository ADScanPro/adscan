"""On-disk :class:`GraphStore`: stdlib ``sqlite3`` in WAL mode.

The ONLY module that imports ``sqlite3`` for the graph store, names a table, or
names a file inside the store directory (locked by
``tests/unit/core/graph_store/test_store_is_behind_one_interface.py``). Callers
reach it through :func:`adscan_core.graph_store.interface.open_graph_store`.
Design: ``docs/superpowers/specs/2026-11-12-inventory-first-graph-persistence.md``
section 5.2.

Layout of one store (``<workspace>/domains/<domain>/graph_store/``):

* ``store.sqlite3`` (plus ``-wal`` / ``-shm`` while a connection is open);
* ``writer.lock``, an advisory lock held by the one writer process.

How the contract is met:

* **A unit is one transaction.** A unit's rows are buffered in the writer
  object and written in ONE ``BEGIN IMMEDIATE`` ... ``COMMIT`` together with
  the unit's done-mark. A unit too large to buffer (an LDAP object class in a
  very large directory) spills to ``pending_*`` tables in short transactions of
  its own, which no reader consults; the commit moves them across. So no lock
  is held while a collector works between two ``add_*`` calls, memory stays
  bounded, and a crash or an exception leaves the spilled rows behind as
  garbage the next writer open deletes, never as visible data.
* **A unit's facts are contiguous.** They are inserted in one statement run per
  commit, under the writer lock, so their ``seq`` values form one range that the
  ``units`` row records. Replacing the unit deletes that range by primary key,
  the ordered scan the build reads walks the ranges in ``(stage, unit)`` order,
  and no secondary index is maintained while collecting. That is the spec's
  measured rule (section 5.1): random B-tree inserts into a large index are
  most of the append cost, so the subject, object and relation indexes are
  created by the first read that filters on them (``CREATE INDEX IF NOT
  EXISTS``) and dropped when a stage begins, and the
  per-row ``last_seen`` is the unit's stamp, stored once on the unit.
* **``first_seen`` survives replacement without a maintained index.** A fact's
  ``first_seen`` is NULL when it equals its unit's stamp (the common case: the
  first collection). When a unit is replaced, or a stage is collected afresh,
  the outgoing facts' identities and first dates are archived into
  ``fact_first_seen`` (keyed by a 64-bit hash of the identity), and every
  incoming fact looks its identity up there. The archive is empty on a first
  collection, so the lookup is free when nothing was ever replaced.
  Identity = ``(stage, subject, object, relation, method, identity notes)``,
  exactly the memory backend's.
* **Readers see snapshots.** Every read runs on a read-only connection from a
  pool, inside one read transaction, so a long scan sees one committed state
  and never blocks the writer (WAL). A second process opens the same files
  read-only.
* **One writer process.** The writer holds ``writer.lock`` (PAL advisory lock,
  released by the OS if the process dies); a second process that asks to write
  gets :class:`GraphStoreError`. Threads of the writer process share one writer
  connection behind an ``RLock``.
* **Close leaves a copyable tree.** ``close()`` checkpoints with ``TRUNCATE``
  and closes every connection, so the ``-wal`` is gone (or empty) and a
  ``shutil.copytree`` of the workspace captures a complete database.
* **No secret.** Every JSON payload passes :func:`secret_guard.guard_secrets`.

Known, deliberate difference from :class:`MemoryGraphStore`: the memory store
gives a fact the first date of the same identity held by ANOTHER live unit; this
store only consults identities that left the store (replaced or freshly
re-collected). The identity carries the unit's own object (the host of a host
unit, the target of an ACL), so two live units never share one in practice.

Stdlib only.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core.graph_store.interface import (
    GraphStoreError,
    GraphStoreFrozenError,
    GraphStoreVersionError,
)
from adscan_core.graph_store.records import (
    GRAPH_STORE_SCHEMA_VERSION,
    DatumRecord,
    EdgeRef,
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

#: The database file inside the store directory.
STORE_FILENAME = "store.sqlite3"
#: The advisory lock the writer process holds for its lifetime.
WRITER_LOCK_FILENAME = "writer.lock"

_BUSY_TIMEOUT_MS = 30_000
#: Rows a unit buffers in memory before it spills to the pending tables.
_SPILL_ROWS = 20_000
#: Rows fetched per round trip by a streaming read.
_FETCH_ROWS = 2_000
#: Idle read connections kept per store.
_MAX_IDLE_READERS = 4
#: Writer page cache: 32 MiB (negative = KiB).
_WRITER_CACHE_KIB = 32_768
#: Cap the WAL file left on disk between checkpoints.
_JOURNAL_SIZE_LIMIT = 64 * 1024 * 1024
#: Least time between two background checkpoints, and the idle wake-up.
_CHECKPOINT_INTERVAL_S = 0.25
_CHECKPOINT_IDLE_S = 5.0

_WAL_FALLBACK_REPORTED = False

# --------------------------------------------------------------------------- #
# Schema (the only place the tables are named)
# --------------------------------------------------------------------------- #

_SCHEMA = (
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)",
    # Directory objects, keyed by the upper-cased object id. body: object_id,
    # domain, enabled, highvalue, properties.
    "CREATE TABLE objects (object_key TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL,"
    " sam TEXT NOT NULL, dn TEXT NOT NULL, body TEXT NOT NULL)",
    # One row per committed unit. f_/d_/p_ ranges are the seq ranges of the
    # unit's facts, data and object patches (lo > hi when empty).
    "CREATE TABLE units (uid INTEGER PRIMARY KEY, stage TEXT NOT NULL, unit TEXT NOT NULL,"
    " stamp TEXT NOT NULL, committed_at TEXT NOT NULL,"
    " f_lo INTEGER NOT NULL, f_hi INTEGER NOT NULL, n_facts INTEGER NOT NULL,"
    " d_lo INTEGER NOT NULL, d_hi INTEGER NOT NULL, n_data INTEGER NOT NULL,"
    " p_lo INTEGER NOT NULL, p_hi INTEGER NOT NULL, UNIQUE (stage, unit))",
    # Raw relationships. first_seen NULL = the unit's stamp. No secondary index
    # while collecting: facts_subject / facts_object are created on first use.
    "CREATE TABLE facts (seq INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL,"
    " subject_id TEXT NOT NULL, object_id TEXT NOT NULL, relation TEXT NOT NULL,"
    " source TEXT NOT NULL, method TEXT NOT NULL, notes TEXT, ident INTEGER NOT NULL,"
    " first_seen TEXT)",
    # Identities that left the store, with the date they were first committed.
    "CREATE TABLE fact_first_seen (identity INTEGER PRIMARY KEY, first_seen TEXT NOT NULL)",
    "CREATE TABLE data (seq INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL, kind TEXT NOT NULL,"
    " key TEXT NOT NULL, body TEXT NOT NULL)",
    "CREATE INDEX data_kind_key ON data (kind, key, seq)",
    "CREATE TABLE object_patches (seq INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL,"
    " object_key TEXT NOT NULL, body TEXT NOT NULL)",
    "CREATE INDEX object_patches_key ON object_patches (object_key, seq)",
    "CREATE TABLE stage_runs (stage TEXT PRIMARY KEY, ord INTEGER NOT NULL, status TEXT NOT NULL,"
    " run_id TEXT NOT NULL, units_total INTEGER NOT NULL, units_done INTEGER NOT NULL,"
    " reason TEXT NOT NULL, detail TEXT NOT NULL, collector_version TEXT NOT NULL,"
    " started_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE overlay (seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,"
    " edge_key TEXT NOT NULL, body TEXT NOT NULL, recorded_at TEXT NOT NULL)",
    # Spill area of units too large to buffer. Never read except by a commit.
    "CREATE TABLE pending_objects (token TEXT NOT NULL, object_key TEXT NOT NULL, kind TEXT NOT NULL,"
    " name TEXT NOT NULL, sam TEXT NOT NULL, dn TEXT NOT NULL, body TEXT NOT NULL)",
    "CREATE TABLE pending_facts (token TEXT NOT NULL, subject_id TEXT NOT NULL, object_id TEXT NOT NULL,"
    " relation TEXT NOT NULL, source TEXT NOT NULL, method TEXT NOT NULL, notes TEXT,"
    " ident INTEGER NOT NULL)",
    "CREATE TABLE pending_data (token TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,"
    " body TEXT NOT NULL)",
    "CREATE TABLE pending_patches (token TEXT NOT NULL, object_key TEXT NOT NULL, body TEXT NOT NULL)",
    "CREATE INDEX pending_objects_token ON pending_objects (token)",
    "CREATE INDEX pending_facts_token ON pending_facts (token)",
    "CREATE INDEX pending_data_token ON pending_data (token)",
    "CREATE INDEX pending_patches_token ON pending_patches (token)",
)

_PENDING_TABLES = (
    "pending_objects",
    "pending_facts",
    "pending_data",
    "pending_patches",
)

#: Indexes created by the first read that needs them (name -> DDL).
_LAZY_INDEXES = {
    "facts_subject": "CREATE INDEX IF NOT EXISTS facts_subject ON facts (gs_upper(subject_id))",
    "facts_object": "CREATE INDEX IF NOT EXISTS facts_object ON facts (gs_upper(object_id))",
    "objects_name": "CREATE INDEX IF NOT EXISTS objects_name ON objects (gs_casefold(name))",
    "objects_sam": "CREATE INDEX IF NOT EXISTS objects_sam ON objects (gs_casefold(sam))",
    "objects_dn": "CREATE INDEX IF NOT EXISTS objects_dn ON objects (gs_casefold(dn))",
    # Relation names are ASCII, so the built-in NOCASE collation folds them
    # exactly as ``str.lower`` does, with no Python call per row.
    "facts_relation": "CREATE INDEX IF NOT EXISTS facts_relation ON facts (relation COLLATE NOCASE)",
}

# Order of the unit's facts as the build reads them: (stage, unit, position).
# The lazy indexes that serve fact reads only; dropped when a stage begins.
_FACT_INDEXES = ("facts_subject", "facts_object", "facts_relation")

# Walks the units index in order and each unit's seq range by primary key, so
# the full scan needs neither a sort nor a secondary index on facts.
_FACT_COLUMNS = (
    "f.subject_id, f.object_id, f.relation, f.source, f.method, f.notes,"
    " COALESCE(f.first_seen, u.stamp), u.stamp"
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sql_upper(value: Any) -> Any:
    return value.upper() if isinstance(value, str) else value


def _sql_lower(value: Any) -> Any:
    return value.lower() if isinstance(value, str) else value


def _sql_casefold(value: Any) -> Any:
    return value.casefold() if isinstance(value, str) else value


def _register_functions(conn: sqlite3.Connection) -> None:
    """Unicode-correct case functions (SQLite's own are ASCII only).

    Deterministic, so they can back an index. Registered on EVERY connection
    this module opens: an index on ``gs_upper(...)`` needs it to be written.
    """
    conn.create_function("gs_upper", 1, _sql_upper, deterministic=True)
    conn.create_function("gs_lower", 1, _sql_lower, deterministic=True)
    conn.create_function("gs_casefold", 1, _sql_casefold, deterministic=True)


def _dumps(value: Any) -> str:
    try:
        return json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise GraphStoreError(
            f"graph store records hold JSON values only: {exc}"
        ) from exc


def _loads(text: str | None, default: Any) -> Any:
    if text is None:
        return default
    return json.loads(text)


def _identity_hash(stage: str, fact: FactRecord) -> int:
    """64-bit signed hash of the fact identity (the memory backend's tuple)."""
    from adscan_core.attack_graph_edge_identity import edge_identity_discriminator

    text = "\x1f".join(
        (
            stage,
            fact.subject_id.upper(),
            fact.object_id.upper(),
            fact.relation.lower(),
            fact.method,
            edge_identity_discriminator(fact.relation, fact.notes),
        )
    )
    digest = hashlib.blake2b(
        text.encode("utf-8", "surrogatepass"), digest_size=8
    ).digest()
    return int.from_bytes(digest, "big", signed=True)


def _request_wal(conn: sqlite3.Connection) -> str:
    """Ask for WAL; returns the journal mode SQLite actually set."""
    row = conn.execute("PRAGMA journal_mode=WAL").fetchone()
    return str(row[0] if row else "").lower()


def _report_wal_fallback(path: Path, mode: str) -> None:
    """Say once per process that WAL is unavailable here (debug log only)."""
    global _WAL_FALLBACK_REPORTED  # noqa: PLW0603 - once-per-process flag
    if _WAL_FALLBACK_REPORTED:
        return
    _WAL_FALLBACK_REPORTED = True
    try:
        from adscan_core.rich_output import print_info_debug  # noqa: PLC0415 - optional sink
    except Exception:  # noqa: BLE001 - the store must open without the console layer
        return
    print_info_debug(
        f"graph store: WAL journal unavailable on this filesystem (got {mode or 'none'}); "
        "using the rollback journal. Readers and the writer now wait for each other."
    )


def _database_path(store_dir: Path) -> Path:
    return store_dir / STORE_FILENAME


def store_exists(store_dir: str | Path) -> bool:
    """Whether a store database exists in ``store_dir``."""
    return _database_path(Path(store_dir)).is_file()


def _read_only_uri(db_path: Path, *, immutable: bool) -> str:
    base = db_path.resolve().as_uri()
    return f"{base}?immutable=1" if immutable else f"{base}?mode=ro"


# --------------------------------------------------------------------------- #
# Writer-process lock (one writer process per store)
# --------------------------------------------------------------------------- #

_HELD_LOCKS: dict[str, list[Any]] = {}  # resolved path -> [handle, refcount]
_HELD_LOCKS_GUARD = threading.Lock()


def _acquire_writer_lock(store_dir: Path) -> tuple[str, bool]:
    """Take the writer lock for this process. Returns ``(key, first_holder)``.

    ``first_holder`` is True when this call took the OS lock (no other handle in
    this process held it): only then is it safe to clear the spill area.
    """
    from adscan_core.pal.filelock import acquire_file_lock, file_lock_supported  # noqa: PLC0415

    key = str((store_dir / WRITER_LOCK_FILENAME).resolve())
    with _HELD_LOCKS_GUARD:
        held = _HELD_LOCKS.get(key)
        if held is not None:
            held[1] += 1
            return key, False
        handle = None
        if file_lock_supported():
            try:
                handle = acquire_file_lock(key, blocking=False)
            except OSError as exc:
                raise GraphStoreError(
                    f"graph store writer lock could not be created: {exc}"
                ) from exc
            if handle is None:
                raise GraphStoreError(
                    "another process holds the graph store for writing; open it read-only"
                )
        _HELD_LOCKS[key] = [handle, 1]
        return key, True


def _release_writer_lock(key: str) -> None:
    from adscan_core.pal.filelock import release_file_lock  # noqa: PLC0415

    with _HELD_LOCKS_GUARD:
        held = _HELD_LOCKS.get(key)
        if held is None:
            return
        held[1] -= 1
        if held[1] > 0:
            return
        del _HELD_LOCKS[key]
        release_file_lock(held[0])


# --------------------------------------------------------------------------- #
# Read connections
# --------------------------------------------------------------------------- #


class _ReaderPool:
    """Read-only connections; each in use by exactly one thread at a time."""

    def __init__(self, uri: str) -> None:
        self._uri = uri
        self._lock = threading.Lock()
        self._idle: list[sqlite3.Connection] = []
        self._all: set[sqlite3.Connection] = set()
        self._closed = False

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._uri,
            uri=True,
            isolation_level=None,
            check_same_thread=False,
            timeout=_BUSY_TIMEOUT_MS / 1000,
        )
        conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        _register_functions(conn)
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise GraphStoreError("graph store is closed")
            conn = self._idle.pop() if self._idle else None
        if conn is None:
            conn = self._open()
            with self._lock:
                self._all.add(conn)
        try:
            yield conn
        finally:
            with self._lock:
                if (
                    not self._closed
                    and len(self._idle) < _MAX_IDLE_READERS
                    and not conn.in_transaction
                ):
                    self._idle.append(conn)
                    conn = None
                else:
                    self._all.discard(conn)
            if conn is not None:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass

    def close(self) -> None:
        with self._lock:
            self._closed = True
            conns = list(self._all)
            self._all.clear()
            self._idle.clear()
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass


# --------------------------------------------------------------------------- #
# WAL checkpoints, off the commit path
# --------------------------------------------------------------------------- #


class _Checkpointer:
    """Copies committed WAL pages into the database on its own thread.

    SQLite's automatic checkpoint runs inside the commit that crosses its
    threshold, on the writer's thread, and ends with an fsync. Measured on the
    partner's shape that made one host commit in a hundred take about a second
    and the worst several seconds, while the commit itself takes two
    milliseconds. So the writer connection has ``wal_autocheckpoint = 0`` and
    this thread runs ``PASSIVE`` checkpoints on a second connection after
    commits, at most every ``_CHECKPOINT_INTERVAL_S``. A passive checkpoint
    never blocks the writer or a reader; if one cannot finish (a long read
    holds old pages), the next one continues where it stopped.
    """

    def __init__(self, db_path: Path) -> None:
        self._conn = sqlite3.connect(
            str(db_path),
            isolation_level=None,
            check_same_thread=False,
            timeout=_BUSY_TIMEOUT_MS / 1000,
        )
        self._conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        self._wake = threading.Event()
        self._stopping = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="graph-store-checkpoint", daemon=True
        )
        self._thread.start()

    def nudge(self) -> None:
        """A commit happened: checkpoint soon."""
        self._wake.set()

    def _run(self) -> None:
        while not self._stopping.is_set():
            self._wake.wait(_CHECKPOINT_IDLE_S)
            self._wake.clear()
            if self._stopping.is_set():
                return
            try:
                self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
            except sqlite3.Error:
                pass  # retried on the next nudge; close() checkpoints regardless
            self._stopping.wait(_CHECKPOINT_INTERVAL_S)

    def close(self) -> None:
        self._stopping.set()
        self._wake.set()
        self._thread.join(timeout=_BUSY_TIMEOUT_MS / 1000)
        try:
            self._conn.close()
        except sqlite3.Error:
            pass


# --------------------------------------------------------------------------- #
# Unit writer
# --------------------------------------------------------------------------- #


class _SqliteUnitWriter:
    """Buffers one unit; spills to the pending tables past ``_SPILL_ROWS``."""

    def __init__(self, store: "SqliteGraphStore", stage: str) -> None:
        self._store = store
        self._stage = stage
        self.token = uuid.uuid4().hex
        self.objects: list[tuple[Any, ...]] = []
        self.facts: list[tuple[Any, ...]] = []
        self.data: list[tuple[Any, ...]] = []
        self.patches: list[tuple[Any, ...]] = []
        self.spilled = False
        self.finished = False

    def _check(self) -> None:
        if self.finished:
            raise GraphStoreError("this unit block has already ended")

    def _buffered(self) -> int:
        return len(self.objects) + len(self.facts) + len(self.data) + len(self.patches)

    def _maybe_spill(self) -> None:
        if self._buffered() >= _SPILL_ROWS:
            self._store._spill(self)

    def add_objects(self, objects: Iterable[ObjectRecord]) -> int:
        self._check()
        domain = self._store.domain
        count = 0
        for obj in objects:
            body = {
                "object_id": obj.object_id,
                "domain": obj.domain,
                "enabled": obj.enabled,
                "highvalue": obj.highvalue,
                "properties": guard_secrets(
                    dict(obj.properties), domain=domain, object_id=obj.object_id
                ),
            }
            self.objects.append(
                (
                    obj.object_id.upper(),
                    obj.kind,
                    obj.name,
                    obj.samaccountname,
                    obj.distinguished_name,
                    _dumps(body),
                )
            )
            count += 1
            if len(self.objects) >= _SPILL_ROWS:
                self._maybe_spill()
        self._maybe_spill()
        return count

    def add_facts(self, facts: Iterable[FactRecord]) -> int:
        self._check()
        domain = self._store.domain
        stage = self._stage
        count = 0
        for fact in facts:
            notes = (
                guard_secrets(
                    fact.notes,
                    relation=fact.relation,
                    domain=domain,
                    object_id=fact.subject_id,
                )
                if fact.notes
                else None
            )
            self.facts.append(
                (
                    fact.subject_id,
                    fact.object_id,
                    fact.relation,
                    fact.source,
                    fact.method,
                    _dumps(notes) if notes else None,
                    _identity_hash(stage, fact),
                )
            )
            count += 1
            if len(self.facts) >= _SPILL_ROWS:
                self._maybe_spill()
        self._maybe_spill()
        return count

    def add_data(self, data: Iterable[DatumRecord]) -> int:
        self._check()
        domain = self._store.domain
        count = 0
        for datum in data:
            body = guard_secrets(
                dict(datum.body), domain=domain, object_id=f"{datum.kind}:{datum.key}"
            )
            self.data.append((datum.kind, datum.key, _dumps(body)))
            count += 1
        self._maybe_spill()
        return count

    def patch_object(self, object_id: str, properties: dict[str, Any]) -> None:
        self._check()
        body = guard_secrets(
            dict(properties), domain=self._store.domain, object_id=str(object_id)
        )
        self.patches.append((str(object_id or "").upper(), _dumps(body)))
        self._maybe_spill()


# --------------------------------------------------------------------------- #
# The store
# --------------------------------------------------------------------------- #


def _empty_range() -> tuple[int, int]:
    return 1, 0


class SqliteGraphStore:
    """A :class:`GraphStore` persisted in one SQLite database (WAL)."""

    def __init__(
        self,
        store_dir: str | Path,
        *,
        domain: str,
        read_only: bool = False,
        create: bool = True,
        frozen: bool = False,
    ) -> None:
        """Open the store in ``store_dir``. Use :func:`open_graph_store` instead.

        Args:
            store_dir: ``<domain_dir>/graph_store``.
            domain: Recorded on creation; a reopen with another domain is refused.
            read_only: Open for reads only.
            create: Create the store when absent (ignored when ``read_only``).
            frozen: The workspace is frozen: open read-only and create no file.
        """
        self._dir = Path(store_dir)
        self._db = _database_path(self._dir)
        self._domain = domain
        self._read_only = bool(read_only or frozen)
        self._closed = False
        self._wlock = threading.RLock()
        self._writer: sqlite3.Connection | None = None
        self._lock_key: str | None = None
        self._journal_mode = ""
        self._known_indexes: set[str] = set()
        self._checkpointer: _Checkpointer | None = None

        if not self._db.is_file():
            if self._read_only or not create:
                raise GraphStoreError(f"no graph store for {domain} at {self._dir}")
        if self._read_only:
            wal = self._db.with_name(STORE_FILENAME + "-wal")
            immutable = frozen and (not wal.exists() or wal.stat().st_size == 0)
            self._readers = _ReaderPool(_read_only_uri(self._db, immutable=immutable))
            try:
                with self._readers.connection() as conn:
                    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
                    self._check_version(version)
                    stored = self._meta_value(conn, "domain")
                    self._check_domain(stored)
            except sqlite3.Error as exc:
                self._readers.close()
                raise GraphStoreError(
                    f"graph store of {domain} cannot be read: {exc}"
                ) from exc
            except GraphStoreError:
                self._readers.close()
                raise
            return

        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock_key, first_holder = _acquire_writer_lock(self._dir)
        try:
            self._writer = self._open_writer()
            self._initialise(first_holder=first_holder)
        except BaseException:
            if self._writer is not None:
                self._writer.close()
                self._writer = None
            _release_writer_lock(self._lock_key)
            self._lock_key = None
            raise
        self._readers = _ReaderPool(_read_only_uri(self._db, immutable=False))
        if self._journal_mode == "wal":
            self._writer.execute("PRAGMA wal_autocheckpoint = 0")
            self._checkpointer = _Checkpointer(self._db)

    # ---- opening ----------------------------------------------------------- #

    def _open_writer(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(
                str(self._db),
                isolation_level=None,
                check_same_thread=False,
                timeout=_BUSY_TIMEOUT_MS / 1000,
            )
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} cannot be opened: {exc}"
            ) from exc
        try:
            conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
            _register_functions(conn)
            mode = _request_wal(conn)
            if mode != "wal":
                row = conn.execute("PRAGMA journal_mode=DELETE").fetchone()
                mode = str(row[0] if row else "delete").lower()
                _report_wal_fallback(self._db, mode)
            self._journal_mode = mode
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute(f"PRAGMA cache_size = -{_WRITER_CACHE_KIB}")
            conn.execute(f"PRAGMA journal_size_limit = {_JOURNAL_SIZE_LIMIT}")
        except sqlite3.Error as exc:
            conn.close()
            raise GraphStoreError(
                f"graph store of {self._domain} cannot be opened: {exc}"
            ) from exc
        return conn

    def _initialise(self, *, first_holder: bool) -> None:
        conn = self._writer
        assert conn is not None
        try:
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version == 0:
                tables = conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[
                    0
                ]
                if tables:
                    raise GraphStoreError(f"{self._db} is not a graph store")
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for statement in _SCHEMA:
                        conn.execute(statement)
                    now = _utc_now()
                    conn.executemany(
                        "INSERT INTO meta (key, value) VALUES (?, ?)",
                        (
                            ("domain", self._domain),
                            ("created_at", now),
                            ("inventory_generation", "0"),
                        ),
                    )
                    conn.execute(f"PRAGMA user_version = {GRAPH_STORE_SCHEMA_VERSION}")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                conn.execute("COMMIT")
                return
            self._check_version(version)
            self._check_domain(self._meta_value(conn, "domain"))
            if first_holder:
                # Spilled rows of a unit whose writer died before its commit.
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for table in _PENDING_TABLES:
                        conn.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                conn.execute("COMMIT")
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} cannot be opened: {exc}"
            ) from exc

    @staticmethod
    def _check_version(version: int) -> None:
        if version != GRAPH_STORE_SCHEMA_VERSION:
            raise GraphStoreVersionError(
                f"graph store schema {version} is not {GRAPH_STORE_SCHEMA_VERSION}; "
                "re-collect the domain to rebuild it"
            )

    def _check_domain(self, stored: str | None) -> None:
        if stored is not None and stored.casefold() != str(self._domain).casefold():
            raise GraphStoreError(
                f"graph store belongs to {stored}, not {self._domain}"
            )

    @staticmethod
    def _meta_value(conn: sqlite3.Connection, key: str) -> str | None:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else row[0]

    # ---- lifecycle -------------------------------------------------------- #

    @property
    def domain(self) -> str:
        return self._domain

    @property
    def read_only(self) -> bool:
        return self._read_only

    @property
    def journal_mode(self) -> str:
        """``wal`` normally; ``delete`` where WAL is unavailable; ``""`` read-only."""
        return self._journal_mode

    def close(self) -> None:
        with self._wlock:
            if self._closed:
                return
            self._closed = True
            self._readers.close()
            if self._checkpointer is not None:
                self._checkpointer.close()
                self._checkpointer = None
            if self._writer is not None:
                try:
                    if self._journal_mode == "wal":
                        self._writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
                try:
                    self._writer.close()
                except sqlite3.Error:
                    pass
                self._writer = None
            if self._lock_key is not None:
                _release_writer_lock(self._lock_key)
                self._lock_key = None

    def _check_open(self) -> None:
        if self._closed:
            raise GraphStoreError(f"graph store of {self._domain} is closed")

    def _require_writable(self) -> None:
        self._check_open()
        if self._read_only:
            raise GraphStoreFrozenError(f"graph store of {self._domain} is read-only")

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """One write transaction on the writer connection, serialised."""
        with self._wlock:
            self._require_writable()
            conn = self._writer
            assert conn is not None
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise GraphStoreError(
                    f"graph store of {self._domain} is busy: {exc}"
                ) from exc
            try:
                yield conn
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            try:
                conn.execute("COMMIT")
            except sqlite3.Error as exc:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise GraphStoreError(
                    f"graph store of {self._domain} could not commit: {exc}"
                ) from exc
            if self._checkpointer is not None:
                self._checkpointer.nudge()

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        """One read transaction (a consistent snapshot) on a pooled connection."""
        self._check_open()
        with self._readers.connection() as conn:
            conn.execute("BEGIN")
            try:
                yield conn
            finally:
                if conn.in_transaction:
                    try:
                        conn.execute("COMMIT")
                    except sqlite3.Error:
                        pass

    def _stream(
        self,
        sql: str,
        params: Iterable[Any],
        decode: Callable[[tuple[Any, ...]], Any],
    ) -> Iterator[Any]:
        """Stream rows of one query from one snapshot, in bounded memory."""
        self._check_open()
        params = tuple(params)

        def _gen() -> Iterator[Any]:
            try:
                with self._read() as conn:
                    cursor = conn.execute(sql, params)
                    while True:
                        rows = cursor.fetchmany(_FETCH_ROWS)
                        if not rows:
                            return
                        for row in rows:
                            yield decode(row)
            except sqlite3.Error as exc:
                raise GraphStoreError(
                    f"graph store of {self._domain} read failed: {exc}"
                ) from exc

        return _gen()

    def _ensure_index(self, name: str) -> None:
        """Create a lazy index on the first read that needs it (writer only)."""
        if name in self._known_indexes or self._read_only:
            return
        with self._write() as conn:
            conn.execute(_LAZY_INDEXES[name])
        self._known_indexes.add(name)

    # ---- collection: stages and units ------------------------------------- #

    def _units_done(self, conn: sqlite3.Connection, stage: str) -> int:
        return int(
            conn.execute(
                "SELECT count(*) FROM units WHERE stage = ?", (stage,)
            ).fetchone()[0]
        )

    @staticmethod
    def _bump_inventory(conn: sqlite3.Connection) -> None:
        conn.execute(
            "UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)"
            " WHERE key = 'inventory_generation'"
        )

    @staticmethod
    def _archive_and_delete_unit(
        conn: sqlite3.Connection, row: tuple[Any, ...]
    ) -> None:
        """Archive the outgoing facts' first dates, then delete the unit's rows."""
        _uid, stamp, f_lo, f_hi, d_lo, d_hi, p_lo, p_hi = row
        if f_lo <= f_hi:
            conn.execute(
                "INSERT OR IGNORE INTO fact_first_seen (identity, first_seen)"
                " SELECT ident, COALESCE(first_seen, ?) FROM facts WHERE seq BETWEEN ? AND ?"
                " ORDER BY ident",
                (stamp, f_lo, f_hi),
            )
            conn.execute("DELETE FROM facts WHERE seq BETWEEN ? AND ?", (f_lo, f_hi))
        if d_lo <= d_hi:
            conn.execute("DELETE FROM data WHERE seq BETWEEN ? AND ?", (d_lo, d_hi))
        if p_lo <= p_hi:
            conn.execute(
                "DELETE FROM object_patches WHERE seq BETWEEN ? AND ?", (p_lo, p_hi)
            )

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
        with self._write() as conn:
            # A stage is write-heavy: a read-only fact index only slows every
            # append, so drop it now and let the next read that needs it
            # rebuild it (``_ensure_index``). Reads return the same rows either way.
            for index_name in _FACT_INDEXES:
                conn.execute(f"DROP INDEX IF EXISTS {index_name}")
                self._known_indexes.discard(index_name)
            if fresh:
                rows = conn.execute(
                    "SELECT uid, stamp, f_lo, f_hi, d_lo, d_hi, p_lo, p_hi FROM units WHERE stage = ?",
                    (stage,),
                ).fetchall()
                for row in rows:
                    self._archive_and_delete_unit(conn, row)
                conn.execute("DELETE FROM units WHERE stage = ?", (stage,))
                self._bump_inventory(conn)
            now = _utc_now()
            previous = self._stage_run(conn, stage)
            run = StageRun(
                stage=stage,
                status="running",
                run_id=run_id,
                units_total=units_total,
                units_done=self._units_done(conn, stage),
                collector_version=collector_version,
                started_at=previous.started_at if previous and not fresh else now,
                updated_at=now,
            )
            self._put_stage_run(conn, run)
            return run

    @contextmanager
    def unit(
        self, stage: str, unit: str, *, observed_at: str = ""
    ) -> Iterator[_SqliteUnitWriter]:
        self._require_writable()
        writer = _SqliteUnitWriter(self, stage)
        try:
            yield writer
        except BaseException:
            writer.finished = True
            self._discard_spill(writer)
            raise
        writer.finished = True
        try:
            self._commit_unit(writer, stage, unit, observed_at or _utc_now())
        except BaseException:
            self._discard_spill(writer)
            raise

    def _spill(self, writer: _SqliteUnitWriter) -> None:
        """Move a unit's buffer to the pending tables (its own short transaction)."""
        token = writer.token
        try:
            with self._write() as conn:
                if writer.objects:
                    conn.executemany(
                        "INSERT INTO pending_objects (token, object_key, kind, name, sam, dn, body)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?)",
                        ((token, *row) for row in writer.objects),
                    )
                if writer.facts:
                    conn.executemany(
                        "INSERT INTO pending_facts (token, subject_id, object_id, relation, source,"
                        " method, notes, ident) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        ((token, *row) for row in writer.facts),
                    )
                if writer.data:
                    conn.executemany(
                        "INSERT INTO pending_data (token, kind, key, body) VALUES (?, ?, ?, ?)",
                        ((token, *row) for row in writer.data),
                    )
                if writer.patches:
                    conn.executemany(
                        "INSERT INTO pending_patches (token, object_key, body) VALUES (?, ?, ?)",
                        ((token, *row) for row in writer.patches),
                    )
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} could not stage a unit: {exc}"
            ) from exc
        writer.spilled = True
        writer.objects.clear()
        writer.facts.clear()
        writer.data.clear()
        writer.patches.clear()

    def _discard_spill(self, writer: _SqliteUnitWriter) -> None:
        if not writer.spilled or self._closed:
            return
        try:
            with self._write() as conn:
                for table in _PENDING_TABLES:
                    conn.execute(
                        f"DELETE FROM {table} WHERE token = ?", (writer.token,)
                    )  # noqa: S608
        except (sqlite3.Error, GraphStoreError):
            pass  # the next writer open clears the spill area

    @staticmethod
    def _max_seq(conn: sqlite3.Connection, table: str) -> int:
        return int(
            conn.execute(f"SELECT COALESCE(MAX(seq), 0) FROM {table}").fetchone()[0]
        )  # noqa: S608

    def _commit_unit(
        self, writer: _SqliteUnitWriter, stage: str, unit: str, stamp: str
    ) -> None:
        token = writer.token
        try:
            with self._write() as conn:
                existing = conn.execute(
                    "SELECT uid, stamp, f_lo, f_hi, d_lo, d_hi, p_lo, p_hi FROM units"
                    " WHERE stage = ? AND unit = ?",
                    (stage, unit),
                ).fetchone()
                now = _utc_now()
                if existing is not None:
                    self._archive_and_delete_unit(conn, existing)
                    uid = int(existing[0])
                else:
                    lo, hi = _empty_range()
                    cursor = conn.execute(
                        "INSERT INTO units (stage, unit, stamp, committed_at, f_lo, f_hi, n_facts,"
                        " d_lo, d_hi, n_data, p_lo, p_hi) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, 0, ?, ?)",
                        (stage, unit, stamp, now, lo, hi, lo, hi, lo, hi),
                    )
                    uid = int(cursor.lastrowid)

                # Objects: replace per object, pending first (they were added first).
                upsert_objects = (
                    "INSERT INTO objects (object_key, kind, name, sam, dn, body) VALUES (?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT (object_key) DO UPDATE SET kind = excluded.kind, name = excluded.name,"
                    " sam = excluded.sam, dn = excluded.dn, body = excluded.body"
                )
                if writer.spilled:
                    rows = conn.execute(
                        "SELECT object_key, kind, name, sam, dn, body FROM pending_objects"
                        " WHERE token = ? ORDER BY rowid",
                        (token,),
                    )
                    while True:
                        batch = rows.fetchmany(_FETCH_ROWS)
                        if not batch:
                            break
                        conn.executemany(upsert_objects, batch)
                if writer.objects:
                    conn.executemany(upsert_objects, writer.objects)

                f_lo, f_hi, n_facts = self._insert_facts(conn, writer, uid)
                d_lo, d_hi, n_data = self._insert_simple(
                    conn,
                    writer,
                    uid,
                    table="data",
                    columns="kind, key, body",
                    pending="pending_data",
                    rows=writer.data,
                )
                p_lo, p_hi, _n_patches = self._insert_simple(
                    conn,
                    writer,
                    uid,
                    table="object_patches",
                    columns="object_key, body",
                    pending="pending_patches",
                    rows=writer.patches,
                )
                conn.execute(
                    "UPDATE units SET stamp = ?, committed_at = ?, f_lo = ?, f_hi = ?, n_facts = ?,"
                    " d_lo = ?, d_hi = ?, n_data = ?, p_lo = ?, p_hi = ? WHERE uid = ?",
                    (
                        stamp,
                        now,
                        f_lo,
                        f_hi,
                        n_facts,
                        d_lo,
                        d_hi,
                        n_data,
                        p_lo,
                        p_hi,
                        uid,
                    ),
                )
                conn.execute(
                    "UPDATE stage_runs SET units_done = ?, updated_at = ? WHERE stage = ?",
                    (self._units_done(conn, stage), _utc_now(), stage),
                )
                self._bump_inventory(conn)
                if writer.spilled:
                    for table in _PENDING_TABLES:
                        conn.execute(f"DELETE FROM {table} WHERE token = ?", (token,))  # noqa: S608
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} could not commit a unit: {exc}"
            ) from exc

    def _insert_facts(
        self, conn: sqlite3.Connection, writer: _SqliteUnitWriter, uid: int
    ) -> tuple[int, int, int]:
        """Insert the unit's facts as one contiguous seq range."""
        start = self._max_seq(conn, "facts") + 1
        archive_empty = (
            conn.execute("SELECT 1 FROM fact_first_seen LIMIT 1").fetchone() is None
        )
        first_seen_sql = (
            "NULL"
            if archive_empty
            else (
                "(SELECT a.first_seen FROM fact_first_seen a WHERE a.identity = {ident})"
            )
        )
        if writer.spilled:
            conn.execute(
                "INSERT INTO facts (unit_id, subject_id, object_id, relation, source, method, notes,"
                " ident, first_seen) SELECT ?, p.subject_id, p.object_id, p.relation, p.source,"
                " p.method, p.notes, p.ident, "
                + first_seen_sql.format(ident="p.ident")
                + " FROM pending_facts p WHERE p.token = ? ORDER BY p.rowid",
                (uid, writer.token),
            )
        if writer.facts:
            if archive_empty:
                conn.executemany(
                    "INSERT INTO facts (unit_id, subject_id, object_id, relation, source, method,"
                    " notes, ident) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ((uid, *row) for row in writer.facts),
                )
            else:
                conn.executemany(
                    "INSERT INTO facts (unit_id, subject_id, object_id, relation, source, method,"
                    " notes, ident, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?,"
                    " (SELECT a.first_seen FROM fact_first_seen a WHERE a.identity = ?))",
                    ((uid, *row, row[-1]) for row in writer.facts),
                )
        end = self._max_seq(conn, "facts")
        if end < start:
            lo, hi = _empty_range()
            return lo, hi, 0
        return start, end, end - start + 1

    def _insert_simple(
        self,
        conn: sqlite3.Connection,
        writer: _SqliteUnitWriter,
        uid: int,
        *,
        table: str,
        columns: str,
        pending: str,
        rows: list[tuple[Any, ...]],
    ) -> tuple[int, int, int]:
        start = self._max_seq(conn, table) + 1
        placeholders = ", ".join("?" for _ in columns.split(","))
        if writer.spilled:
            conn.execute(
                f"INSERT INTO {table} (unit_id, {columns}) SELECT ?, {columns} FROM {pending}"  # noqa: S608
                " WHERE token = ? ORDER BY rowid",
                (uid, writer.token),
            )
        if rows:
            conn.executemany(
                f"INSERT INTO {table} (unit_id, {columns}) VALUES (?, {placeholders})",  # noqa: S608
                ((uid, *row) for row in rows),
            )
        end = self._max_seq(conn, table)
        if end < start:
            lo, hi = _empty_range()
            return lo, hi, 0
        return start, end, end - start + 1

    def end_stage(
        self, stage: str, status: StageStatus, *, reason: str = "", detail: str = ""
    ) -> StageRun:
        self._require_writable()
        with self._write() as conn:
            now = _utc_now()
            run = self._stage_run(conn, stage) or StageRun(
                stage=stage, status=status, started_at=now
            )
            run = replace(
                run,
                status=status,
                reason=reason,
                detail=detail,
                units_done=self._units_done(conn, stage),
                updated_at=now,
            )
            self._put_stage_run(conn, run)
            self._bump_inventory(conn)
            return run

    _STAGE_COLUMNS = (
        "stage, status, run_id, units_total, units_done, reason, detail, collector_version,"
        " started_at, updated_at"
    )

    @staticmethod
    def _decode_stage(row: tuple[Any, ...]) -> StageRun:
        return StageRun(
            stage=row[0],
            status=row[1],
            run_id=row[2],
            units_total=int(row[3]),
            units_done=int(row[4]),
            reason=row[5],
            detail=row[6],
            collector_version=row[7],
            started_at=row[8],
            updated_at=row[9],
        )

    def _stage_run(self, conn: sqlite3.Connection, stage: str) -> StageRun | None:
        row = conn.execute(
            f"SELECT {self._STAGE_COLUMNS} FROM stage_runs WHERE stage = ?",
            (stage,),  # noqa: S608
        ).fetchone()
        return None if row is None else self._decode_stage(row)

    @staticmethod
    def _put_stage_run(conn: sqlite3.Connection, run: StageRun) -> None:
        conn.execute(
            "INSERT INTO stage_runs (stage, ord, status, run_id, units_total, units_done, reason,"
            " detail, collector_version, started_at, updated_at)"
            " VALUES (?, (SELECT COALESCE(MAX(ord), 0) + 1 FROM stage_runs), ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (stage) DO UPDATE SET status = excluded.status, run_id = excluded.run_id,"
            " units_total = excluded.units_total, units_done = excluded.units_done,"
            " reason = excluded.reason, detail = excluded.detail,"
            " collector_version = excluded.collector_version, started_at = excluded.started_at,"
            " updated_at = excluded.updated_at",
            (
                run.stage,
                run.status,
                run.run_id,
                int(run.units_total),
                int(run.units_done),
                run.reason,
                run.detail,
                run.collector_version,
                run.started_at,
                run.updated_at,
            ),
        )

    def stage_runs(self) -> list[StageRun]:
        try:
            with self._read() as conn:
                rows = conn.execute(
                    f"SELECT {self._STAGE_COLUMNS} FROM stage_runs ORDER BY ord"  # noqa: S608
                ).fetchall()
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} read failed: {exc}"
            ) from exc
        return [self._decode_stage(row) for row in rows]

    def done_units(self, stage: str) -> frozenset[str]:
        try:
            with self._read() as conn:
                rows = conn.execute(
                    "SELECT unit FROM units WHERE stage = ?", (stage,)
                ).fetchall()
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} read failed: {exc}"
            ) from exc
        return frozenset(row[0] for row in rows)

    # ---- inventory reads --------------------------------------------------- #

    @staticmethod
    def _decode_object(row: tuple[Any, ...], patches: list[str] | None) -> ObjectRecord:
        _key, kind, name, sam, dn, body_text = row
        body = json.loads(body_text)
        properties = body.get("properties") or {}
        if patches:
            merged = dict(properties)
            for patch in patches:
                merged.update(json.loads(patch))
            properties = merged
        return ObjectRecord(
            object_id=body["object_id"],
            kind=kind,
            name=name,
            domain=body.get("domain", ""),
            samaccountname=sam,
            distinguished_name=dn,
            enabled=body.get("enabled"),
            highvalue=bool(body.get("highvalue", False)),
            properties=properties,
        )

    @staticmethod
    def _patches_of(conn: sqlite3.Connection, object_key: str) -> list[str]:
        return [
            row[0]
            for row in conn.execute(
                "SELECT body FROM object_patches WHERE object_key = ? ORDER BY seq",
                (object_key,),
            )
        ]

    def iter_objects(
        self, *, kinds: Iterable[str] | None = None
    ) -> Iterator[ObjectRecord]:
        self._check_open()
        wanted = sorted({k.lower() for k in kinds}) if kinds is not None else None

        def _gen() -> Iterator[ObjectRecord]:
            try:
                with self._read() as conn:
                    patches: dict[str, list[str]] = {}
                    for key, body in conn.execute(
                        "SELECT object_key, body FROM object_patches ORDER BY seq"
                    ):
                        patches.setdefault(key, []).append(body)
                    sql = "SELECT object_key, kind, name, sam, dn, body FROM objects"
                    params: tuple[Any, ...] = ()
                    if wanted is not None:
                        if not wanted:
                            return
                        sql += f" WHERE gs_lower(kind) IN ({', '.join('?' for _ in wanted)})"
                        params = tuple(wanted)
                    cursor = conn.execute(sql + " ORDER BY object_key", params)
                    while True:
                        rows = cursor.fetchmany(_FETCH_ROWS)
                        if not rows:
                            return
                        for row in rows:
                            yield self._decode_object(row, patches.get(row[0]))
            except sqlite3.Error as exc:
                raise GraphStoreError(
                    f"graph store of {self._domain} read failed: {exc}"
                ) from exc

        return _gen()

    def get_object(self, object_id: str) -> ObjectRecord | None:
        key = str(object_id or "").upper()
        try:
            with self._read() as conn:
                row = conn.execute(
                    "SELECT object_key, kind, name, sam, dn, body FROM objects WHERE object_key = ?",
                    (key,),
                ).fetchone()
                if row is None:
                    return None
                return self._decode_object(row, self._patches_of(conn, key))
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} read failed: {exc}"
            ) from exc

    def find_objects(
        self, *, name: str = "", distinguished_name: str = "", samaccountname: str = ""
    ) -> list[ObjectRecord]:
        self._check_open()
        clauses: list[str] = []
        params: list[Any] = []
        for value, column, index in (
            (name, "name", "objects_name"),
            (distinguished_name, "dn", "objects_dn"),
            (samaccountname, "sam", "objects_sam"),
        ):
            if value:
                self._ensure_index(index)
                clauses.append(f"gs_casefold({column}) = ?")
                params.append(value.casefold())
        if not clauses:
            return []
        try:
            with self._read() as conn:
                rows = conn.execute(
                    "SELECT object_key, kind, name, sam, dn, body FROM objects WHERE "  # noqa: S608
                    + " AND ".join(clauses)
                    + " ORDER BY object_key",
                    params,
                ).fetchall()
                return [
                    self._decode_object(row, self._patches_of(conn, row[0]))
                    for row in rows
                ]
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} read failed: {exc}"
            ) from exc

    @staticmethod
    def _decode_fact(row: tuple[Any, ...]) -> FactRecord:
        subject, target, relation, source, method, notes, first_seen, last_seen = row
        return FactRecord(
            subject_id=subject,
            object_id=target,
            relation=relation,
            source=source,
            method=method,
            notes=_loads(notes, {}),
            first_seen=first_seen,
            last_seen=last_seen,
        )

    def iter_facts(
        self,
        *,
        stages: Iterable[str] | None = None,
        relations: Iterable[str] | None = None,
        subject_id: str = "",
        object_id: str = "",
    ) -> Iterator[FactRecord]:
        self._check_open()
        stage_list = sorted(set(stages)) if stages is not None else None
        relation_list = (
            sorted({r.lower() for r in relations}) if relations is not None else None
        )
        if (stage_list is not None and not stage_list) or (
            relation_list is not None and not relation_list
        ):
            return iter(())
        clauses: list[str] = []
        params: list[Any] = []
        if subject_id:
            self._ensure_index("facts_subject")
            clauses.append("gs_upper(f.subject_id) = ?")
            params.append(subject_id.upper())
        if object_id:
            self._ensure_index("facts_object")
            clauses.append("gs_upper(f.object_id) = ?")
            params.append(object_id.upper())
        if stage_list is not None:
            clauses.append(f"u.stage IN ({', '.join('?' for _ in stage_list)})")
            params.extend(stage_list)
        indexed_relations = relation_list is not None and all(r.isascii() for r in relation_list)
        if relation_list is not None:
            marks = ", ".join("?" for _ in relation_list)
            if indexed_relations:
                # ASCII names (every relation the engine writes): the built-in
                # NOCASE collation equals ``str.lower`` on them and the lazy
                # relation index serves the filter.
                self._ensure_index("facts_relation")
                clauses.append(f"f.relation COLLATE NOCASE IN ({marks})")
            else:
                # A non-ASCII name: NOCASE folds ASCII only, so keep the exact
                # Python folding (a full scan, as before).
                clauses.append(f"gs_lower(f.relation) IN ({marks})")
            params.extend(relation_list)
        where = (" AND " + " AND ".join(clauses)) if clauses else ""
        if subject_id or object_id or indexed_relations:
            # Indexed lookup, then the matching rows sorted into scan order.
            sql = (
                f"SELECT {_FACT_COLUMNS} FROM facts f JOIN units u ON u.uid = f.unit_id"  # noqa: S608
                f" WHERE 1 = 1{where} ORDER BY u.stage, u.unit, f.seq"
            )
        else:
            sql = (
                f"SELECT {_FACT_COLUMNS} FROM units u JOIN facts f"  # noqa: S608
                f" ON f.seq BETWEEN u.f_lo AND u.f_hi WHERE u.n_facts > 0{where}"
                " ORDER BY u.stage, u.unit, f.seq"
            )
        return self._stream(sql, params, self._decode_fact)

    def iter_data(self, kind: str) -> Iterator[DatumRecord]:
        return self._stream(
            "SELECT d.kind, d.key, d.body FROM data d WHERE d.kind = ?"
            " AND d.seq = (SELECT MAX(d2.seq) FROM data d2 WHERE d2.kind = d.kind AND d2.key = d.key)"
            " ORDER BY d.key",
            (kind,),
            lambda row: DatumRecord(kind=row[0], key=row[1], body=json.loads(row[2])),
        )

    # ---- runtime overlay --------------------------------------------------- #

    def append_overlay(self, ops: Iterable[OverlayOp]) -> StoreGeneration:
        self._require_writable()
        from adscan_core.attack_graph_edge_identity import attack_graph_edge_fingerprint  # noqa: PLC0415

        encoded: list[tuple[str, str, str, str]] = []
        for op in ops:
            edge = op.edge
            relation = edge.relation if edge is not None else ""
            payload = guard_secrets(
                dict(op.payload),
                relation=relation,
                domain=self._domain,
                object_id=op.node_id or "",
            )
            body = {
                "edge": None
                if edge is None
                else {
                    "from_id": edge.from_id,
                    "to_id": edge.to_id,
                    "relation": edge.relation,
                    "identity_notes": guard_secrets(
                        dict(edge.identity_notes),
                        relation=relation,
                        domain=self._domain,
                    ),
                },
                "node_id": op.node_id,
                "status": op.status,
                "edge_type": op.edge_type,
                "payload": payload,
                "origin": op.origin,
                "run_id": op.run_id,
            }
            edge_key = (
                attack_graph_edge_fingerprint(
                    edge.from_id, edge.relation, edge.to_id, edge.identity_notes
                )
                if edge is not None
                else ""
            )
            encoded.append(
                (op.kind, edge_key, _dumps(body), op.recorded_at or _utc_now())
            )
        with self._write() as conn:
            if encoded:
                conn.executemany(
                    "INSERT INTO overlay (kind, edge_key, body, recorded_at) VALUES (?, ?, ?, ?)",
                    encoded,
                )
            return self._generation(conn)

    @staticmethod
    def _decode_op(row: tuple[Any, ...]) -> OverlayOp:
        seq, kind, body_text, recorded_at = row
        body = json.loads(body_text)
        edge = body.get("edge")
        return OverlayOp(
            kind=kind,
            edge=None
            if edge is None
            else EdgeRef(
                from_id=edge["from_id"],
                to_id=edge["to_id"],
                relation=edge["relation"],
                identity_notes=edge.get("identity_notes") or {},
            ),
            node_id=body.get("node_id", ""),
            status=body.get("status", ""),
            edge_type=body.get("edge_type", ""),
            payload=body.get("payload") or {},
            origin=body.get("origin", ""),
            run_id=body.get("run_id", ""),
            seq=int(seq),
            recorded_at=recorded_at,
        )

    def iter_overlay(self, *, after_seq: int = 0) -> Iterator[OverlayOp]:
        return self._stream(
            "SELECT seq, kind, body, recorded_at FROM overlay WHERE seq > ? ORDER BY seq",
            (max(int(after_seq), 0),),
            self._decode_op,
        )

    # ---- build state -------------------------------------------------------- #

    @staticmethod
    def _generation(conn: sqlite3.Connection) -> StoreGeneration:
        row = conn.execute(
            "SELECT (SELECT value FROM meta WHERE key = 'inventory_generation'),"
            " (SELECT COALESCE(MAX(seq), 0) FROM overlay)"
        ).fetchone()
        return StoreGeneration(inventory=int(row[0] or 0), overlay=int(row[1] or 0))

    def generation(self) -> StoreGeneration:
        try:
            with self._read() as conn:
                return self._generation(conn)
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} read failed: {exc}"
            ) from exc

    def last_export(self) -> ExportRecord | None:
        try:
            with self._read() as conn:
                text = self._meta_value(conn, "last_export")
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} read failed: {exc}"
            ) from exc
        if text is None:
            return None
        body = json.loads(text)
        generation = body.get("generation") or {}
        return ExportRecord(
            generation=StoreGeneration(
                inventory=int(generation.get("inventory", 0)),
                overlay=int(generation.get("overlay", 0)),
            ),
            exported_at=body.get("exported_at", ""),
            duration_seconds=float(body.get("duration_seconds", 0.0)),
            nodes=int(body.get("nodes", 0)),
            edges=int(body.get("edges", 0)),
            size_bytes=int(body.get("size_bytes", 0)),
            # A record written before the fingerprint was kept reads as "",
            # which proves nothing current (the next export rewrites).
            fingerprint=str(body.get("fingerprint", "") or ""),
        )

    def record_export(self, record: ExportRecord) -> None:
        self._require_writable()
        body = _dumps(
            {
                "generation": {
                    "inventory": record.generation.inventory,
                    "overlay": record.generation.overlay,
                },
                "exported_at": record.exported_at,
                "duration_seconds": record.duration_seconds,
                "nodes": record.nodes,
                "edges": record.edges,
                "size_bytes": record.size_bytes,
                "fingerprint": record.fingerprint,
            }
        )
        with self._write() as conn:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('last_export', ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (body,),
            )

    def stats(self) -> StoreStats:
        try:
            with self._read() as conn:
                objects = int(
                    conn.execute("SELECT count(*) FROM objects").fetchone()[0]
                )
                facts, data = conn.execute(
                    "SELECT COALESCE(SUM(n_facts), 0), COALESCE(SUM(n_data), 0) FROM units"
                ).fetchone()
                overlay = int(
                    conn.execute("SELECT count(*) FROM overlay").fetchone()[0]
                )
        except sqlite3.Error as exc:
            raise GraphStoreError(
                f"graph store of {self._domain} read failed: {exc}"
            ) from exc
        size = 0
        for suffix in ("", "-wal"):
            try:
                size += (self._dir / (STORE_FILENAME + suffix)).stat().st_size
            except OSError:
                pass
        return StoreStats(
            objects=objects,
            facts=int(facts),
            data=int(data),
            overlay_ops=overlay,
            size_bytes=size,
        )


# --------------------------------------------------------------------------- #
# Maintenance: the secret purge
# --------------------------------------------------------------------------- #


def scrub_store_documents(
    store_dir: str | Path, transform: Callable[[Any], Any]
) -> int:
    """Rewrite every stored JSON document through ``transform``; returns rows changed.

    The workspace secret purge's entry into the store (it is the one caller).
    It runs outside the :class:`GraphStore` interface on purpose: the overlay is
    append-only for every writer, and removing a recovered secret from history
    is the single exception. Covers fact notes, datum bodies, overlay bodies,
    object bodies, object patches and stage-run reasons. Afterwards the
    database is checkpointed and vacuumed with ``secure_delete`` on, so the old
    bytes are gone from the file, not just unreferenced.

    Raises:
        GraphStoreError: The store is missing or another process holds it.
    """
    directory = Path(store_dir)
    db_path = _database_path(directory)
    if not db_path.is_file():
        raise GraphStoreError(f"no graph store at {directory}")
    lock_key, first_holder = _acquire_writer_lock(directory)
    changed = 0
    try:
        conn = sqlite3.connect(
            str(db_path), isolation_level=None, timeout=_BUSY_TIMEOUT_MS / 1000
        )
        try:
            conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
            _register_functions(conn)
            conn.execute("PRAGMA secure_delete = ON")
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            SqliteGraphStore._check_version(version)
            conn.execute("BEGIN IMMEDIATE")
            try:
                for table, key, column in (
                    ("facts", "seq", "notes"),
                    ("data", "seq", "body"),
                    ("object_patches", "seq", "body"),
                    ("overlay", "seq", "body"),
                    ("objects", "object_key", "body"),
                ):
                    changed += _scrub_column(conn, table, key, column, transform)
                for column in ("reason", "detail"):
                    rows = conn.execute(
                        f"SELECT stage, {column} FROM stage_runs"
                    ).fetchall()  # noqa: S608
                    for stage, text in rows:
                        new = transform(text)
                        if new != text:
                            conn.execute(
                                f"UPDATE stage_runs SET {column} = ? WHERE stage = ?",  # noqa: S608
                                (new, stage),
                            )
                            changed += 1
                if first_holder:
                    # Left by a writer that died mid-unit: never visible, just delete.
                    for table in _PENDING_TABLES:
                        conn.execute(f"DELETE FROM {table}")  # noqa: S608
                else:
                    # A writer of this process is mid-unit: scrub, do not take its rows.
                    for table, column in (
                        ("pending_facts", "notes"),
                        ("pending_data", "body"),
                        ("pending_objects", "body"),
                        ("pending_patches", "body"),
                    ):
                        changed += _scrub_column(
                            conn, table, "rowid", column, transform
                        )
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.execute("VACUUM")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
    except sqlite3.Error as exc:
        raise GraphStoreError(
            f"graph store at {directory} could not be scrubbed: {exc}"
        ) from exc
    finally:
        _release_writer_lock(lock_key)
    return changed


def _scrub_column(
    conn: sqlite3.Connection,
    table: str,
    key: str,
    column: str,
    transform: Callable[[Any], Any],
) -> int:
    changed = 0
    cursor = conn.execute(
        f"SELECT {key}, {column} FROM {table} WHERE {column} IS NOT NULL"  # noqa: S608
    )
    updates: list[tuple[str, Any]] = []
    while True:
        rows = cursor.fetchmany(_FETCH_ROWS)
        if not rows:
            break
        for row_key, text in rows:
            doc = json.loads(text)
            new = transform(doc)
            if new != doc:
                updates.append((_dumps(new), row_key))
    for start in range(0, len(updates), _FETCH_ROWS):
        batch = updates[start : start + _FETCH_ROWS]
        conn.executemany(f"UPDATE {table} SET {column} = ? WHERE {key} = ?", batch)  # noqa: S608
        changed += len(batch)
    return changed


__all__ = (
    "STORE_FILENAME",
    "WRITER_LOCK_FILENAME",
    "SqliteGraphStore",
    "scrub_store_documents",
    "store_exists",
)
