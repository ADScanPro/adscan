"""The engagement ledger store: ``<workspace>/engagement/engagement.sqlite``.

The durable, engine-owned record of one client engagement (spec section 7.1):
the runs applied, every finding and attack-step item with its lifecycle status,
the transitions that changed a status, per-run check coverage, and the client's
dispositions. The engine is the only writer; consumers read the versioned
export (``adscan.ledger/1``, :meth:`EngagementStore.export`).

Decisions this module encodes:

* **Reconciliation is not here.** The store applies the decisions
  ``adscan_core.engagement.reconcile`` made, so the CLI ledger and the web's
  Postgres projection cannot disagree on a rule.
* **One run, one transaction, once.** :meth:`EngagementStore.apply_run` writes a
  whole run atomically under ``BEGIN IMMEDIATE`` (the writer lock, shared by
  every process opening the file) and is idempotent per ``run_id``: a retried
  ingestion writes nothing twice.
* **History records real status changes only.** ``not_reevaluated`` is a state
  on the item row (with its reason), never a history event, so counting events
  by new status never inflates "opened" or "reopened".
* **No secrets.** No column holds a credential; the vault arrives with Phase 4
  in its own encrypted tables.
* **No clock.** Every stamp is passed in by the caller, who knows its frame.

Journal: WAL where the filesystem honours it, else ``DELETE`` (network and some
bind-mounted filesystems refuse WAL). Migrations: ``PRAGMA user_version`` plus
ordered migration functions; a store written by a newer engine is refused.

Stdlib only; ``sqlite3`` is imported lazily, so importing ``adscan_core.engagement``
never needs it (LITE on Windows does not use the store, decision D12a).
"""

from __future__ import annotations

import json
import os
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional, Sequence

from adscan_core.engagement.model import (
    STATUS_OPEN,
    STATUS_REMEDIATED,
    STATUS_REOPENED,
    TERMINAL_STATUSES,
    ItemResult,
    PriorItem,
    RunCoverage,
    Transition,
    Vantage,
)

STORE_DIRNAME = "engagement"
STORE_FILENAME = "engagement.sqlite"
EXPORT_DIRNAME = "export"
LEDGER_EXPORT_FILENAME = "ledger.json"
LEDGER_SCHEMA = "adscan.ledger/1"
EVALUATED = "evaluated"
NOT_REEVALUATED = "not_reevaluated"
_BUSY_TIMEOUT_MS = 30_000


class EngagementStoreError(RuntimeError):
    """The store cannot be opened or written; the message says what to do."""


@dataclass(frozen=True)
class RunRecord:
    """One run applied to the ledger."""

    run_id: str
    kind: str
    status: str
    vantage: Vantage
    started_at: str = ""
    finished_at: str = ""
    parent_run_id: str = ""


@dataclass(frozen=True)
class LedgerItem:
    """What the ledger keeps about an item it may not have seen before."""

    item_id: str
    kind: str
    key: str
    domain_id: str
    object_id: Optional[str] = None
    label: str = ""
    legacy_alias: str = ""


def store_path(workspace_dir: Any) -> Path:
    """``<workspace>/engagement/engagement.sqlite``."""
    return Path(str(workspace_dir)) / STORE_DIRNAME / STORE_FILENAME


# ---------------------------------------------------------------------------
# Schema and migrations.
# ---------------------------------------------------------------------------


def _run_script(conn: Any, script: str) -> None:
    # Statement by statement: ``executescript`` commits first, which would end
    # the migration's transaction and let a half-migrated store survive a crash.
    for statement in script.split(";"):
        if statement.strip():
            conn.execute(statement)


def _migration_1(conn: Any) -> None:
    _run_script(
        conn,
        """
        CREATE TABLE engagement_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            vantage INTEGER NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            parent_run_id TEXT,
            applied_at TEXT NOT NULL,
            seq INTEGER NOT NULL
        );
        CREATE TABLE items (
            item_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            key TEXT NOT NULL,
            domain_id TEXT NOT NULL,
            object_id TEXT,
            label TEXT,
            legacy_alias TEXT,
            status TEXT NOT NULL,
            last_vantage INTEGER NOT NULL,
            first_seen_run TEXT,
            last_seen_run TEXT,
            last_verified_run TEXT,
            last_verified_at TEXT,
            evaluation_state TEXT NOT NULL,
            evaluation_reason TEXT
        );
        CREATE INDEX items_domain ON items (domain_id, kind);
        CREATE TABLE item_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            transition TEXT NOT NULL,
            old_status TEXT,
            new_status TEXT NOT NULL,
            reason TEXT,
            at TEXT NOT NULL,
            UNIQUE (run_id, item_id)
        );
        CREATE TABLE check_coverage (
            run_id TEXT NOT NULL,
            check_id TEXT NOT NULL,
            domain_id TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            examined INTEGER,
            total INTEGER,
            PRIMARY KEY (run_id, check_id, domain_id)
        );
        CREATE TABLE dispositions (
            item_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            reason TEXT,
            set_by TEXT,
            set_at TEXT NOT NULL,
            expires_at TEXT
        );
        """
    )


#: Ordered migrations; index + 1 is the ``user_version`` each one produces.
_MIGRATIONS: tuple[Callable[[Any], None], ...] = (_migration_1,)
SCHEMA_VERSION = len(_MIGRATIONS)


def choose_journal_mode(conn: Any) -> str:
    """Use WAL where the filesystem honours it, else fall back to DELETE."""
    row = conn.execute("PRAGMA journal_mode=WAL").fetchone()
    mode = str(row[0] if row else "").lower()
    if mode == "wal":
        return mode
    row = conn.execute("PRAGMA journal_mode=DELETE").fetchone()
    return str(row[0] if row else "delete").lower()


def _connect(path: Path) -> Any:
    import sqlite3  # noqa: PLC0415 - lazy: the package stays importable without it

    conn = sqlite3.connect(str(path), timeout=_BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def open_store(path: Any) -> "EngagementStore":
    """Open (creating and migrating if needed) the store at ``path``.

    Raises:
        EngagementStoreError: the file is not a usable database, or a newer
            ADscan wrote it.
    """
    import sqlite3  # noqa: PLC0415

    target = Path(str(path))
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        conn = _connect(target)
        journal = choose_journal_mode(conn)
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            conn.close()
            raise EngagementStoreError(
                f"The engagement ledger at {target} was written by a newer ADscan "
                f"(schema {version}, this version reads up to {SCHEMA_VERSION}). "
                "Update ADscan to read it."
            )
        if version < SCHEMA_VERSION:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for index in range(version, SCHEMA_VERSION):
                    _MIGRATIONS[index](conn)
                conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                existing = conn.execute(
                    "SELECT value FROM engagement_meta WHERE key='engagement_id'"
                ).fetchone()
                if existing is None:
                    conn.execute(
                        "INSERT INTO engagement_meta (key, value) VALUES ('engagement_id', ?)",
                        (uuid.uuid4().hex,),
                    )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return EngagementStore(target, conn, journal)
    except EngagementStoreError:
        raise
    except sqlite3.DatabaseError as exc:
        raise EngagementStoreError(
            f"The engagement ledger at {target} cannot be read ({exc}). Move it aside "
            "(rename the file) and rerun: ADscan starts a new ledger, and the run "
            "folders under runs/ keep every past run's evidence."
        ) from exc


# ---------------------------------------------------------------------------
# The store.
# ---------------------------------------------------------------------------

_STATUS_AFTER: Mapping[Transition, Optional[str]] = {
    Transition.NEW: STATUS_OPEN,
    Transition.REOPENED: STATUS_REOPENED,
    Transition.REMEDIATED: STATUS_REMEDIATED,
    Transition.STILL_PRESENT: None,  # unchanged
    Transition.NOT_REEVALUATED: None,
    Transition.TERMINAL_UNCHANGED: None,
}


class EngagementStore:
    """A connection to one engagement ledger."""

    def __init__(self, path: Path, conn: Any, journal_mode: str) -> None:
        self.path = path
        self.journal_mode = journal_mode
        self._conn = conn

    # -- metadata ----------------------------------------------------------
    @property
    def schema_version(self) -> int:
        return int(self._conn.execute("PRAGMA user_version").fetchone()[0])

    @property
    def engagement_id(self) -> str:
        row = self._conn.execute(
            "SELECT value FROM engagement_meta WHERE key='engagement_id'"
        ).fetchone()
        return str(row[0]) if row else ""

    def get_meta(self, key: str) -> Optional[str]:
        row = self._conn.execute("SELECT value FROM engagement_meta WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.writer() as conn:
            conn.execute(
                "INSERT INTO engagement_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def schema_columns(self) -> dict[str, list[str]]:
        """Every table and its columns (used by the no-secret-column lock)."""
        tables = [
            r[0]
            for r in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        return {
            t: [r[1] for r in self._conn.execute(f"PRAGMA table_info({t})")] for t in tables
        }

    def close(self) -> None:
        self._conn.close()

    # -- writer lock -------------------------------------------------------
    @contextmanager
    def writer(self) -> Iterator[Any]:
        """One write transaction, holding the engagement's writer lock."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    # -- reads -------------------------------------------------------------
    def runs(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._conn.execute("SELECT * FROM runs ORDER BY seq")]

    def item(self, item_id: str) -> Optional[dict[str, Any]]:
        row = self._conn.execute("SELECT * FROM items WHERE item_id=?", (item_id,)).fetchone()
        return dict(row) if row else None

    def items(
        self, *, domain_id: Optional[str] = None, kind: Optional[str] = None
    ) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM items WHERE 1=1", []
        if domain_id is not None:
            sql, args = sql + " AND domain_id=?", [*args, domain_id]
        if kind is not None:
            sql, args = sql + " AND kind=?", [*args, kind]
        rows = [dict(r) for r in self._conn.execute(sql + " ORDER BY item_id", args)]
        dispositions = self._dispositions()
        for row in rows:
            disposition = dispositions.get(row["item_id"])
            row["disposition"] = disposition["status"] if disposition else None
        return rows

    def history(self, item_id: str) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self._conn.execute(
                "SELECT e.* FROM item_events e JOIN runs r ON r.run_id = e.run_id "
                "WHERE e.item_id=? ORDER BY r.seq",
                (item_id,),
            )
        ]

    def coverage(self, run_id: str) -> list[dict[str, Any]]:
        return [
            dict(r)
            for r in self._conn.execute(
                "SELECT * FROM check_coverage WHERE run_id=? ORDER BY check_id, domain_id",
                (run_id,),
            )
        ]

    def _dispositions(self) -> dict[str, dict[str, Any]]:
        return {r["item_id"]: dict(r) for r in self._conn.execute("SELECT * FROM dispositions")}

    def terminal_ids(self) -> frozenset[str]:
        """Items carrying a client disposition (never changed automatically)."""
        return frozenset(self._dispositions())

    def iter_prior(
        self, domain_id: Optional[str] = None, kind: Optional[str] = None
    ) -> list[PriorItem]:
        """The ledger's items as reconciliation's prior state."""
        out = []
        for row in self.items(domain_id=domain_id, kind=kind):
            status = row["disposition"] or row["status"]
            out.append(
                PriorItem(
                    item_id=row["item_id"],
                    kind=row["kind"],
                    key=row["key"],
                    domain_id=row["domain_id"],
                    object_id=row["object_id"],
                    status=status,
                    last_vantage=Vantage(int(row["last_vantage"])),
                )
            )
        return out

    def has_run(self, run_id: str) -> bool:
        return (
            self._conn.execute("SELECT 1 FROM runs WHERE run_id=?", (run_id,)).fetchone()
            is not None
        )

    # -- writes ------------------------------------------------------------
    def set_disposition(
        self,
        item_id: str,
        status: str,
        *,
        reason: str,
        set_by: str,
        at: str,
        expires_at: Optional[str] = None,
    ) -> None:
        """Record a client decision (accepted / false positive) on an item."""
        if status not in TERMINAL_STATUSES:
            raise EngagementStoreError(f"Unknown disposition {status!r}.")
        with self.writer() as conn:
            conn.execute(
                "INSERT INTO dispositions (item_id, status, reason, set_by, set_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(item_id) DO UPDATE SET "
                "status=excluded.status, reason=excluded.reason, set_by=excluded.set_by, "
                "set_at=excluded.set_at, expires_at=excluded.expires_at",
                (item_id, status, reason, set_by, at, expires_at),
            )

    def apply_run(
        self,
        run: RunRecord,
        results: Sequence[ItemResult],
        items: Sequence[LedgerItem],
        coverage: Optional[RunCoverage],
        *,
        at: str,
    ) -> int:
        """Apply one run's reconciliation decisions atomically, once.

        Args:
            run: The run being applied.
            results: ``reconcile``'s decisions for this run.
            items: Metadata of the items this run observed (required for every
                ``NEW`` item; refreshes label and object for the others).
            coverage: The run's coverage, stored as a per-check summary.
            at: Absolute stamp of the application, in the run's clock frame.

        Returns:
            The number of history events written (0 when the run was already
            applied).

        Raises:
            EngagementStoreError: a decision names an item the ledger does not
                hold and the run did not describe. Nothing is written.
        """
        meta = {i.item_id: i for i in items}
        written = 0
        try:
            with self.writer() as conn:
                if self.has_run(run.run_id):
                    return 0
                seq = int(conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM runs").fetchone()[0])
                conn.execute(
                    "INSERT INTO runs (run_id, kind, status, vantage, started_at, finished_at, "
                    "parent_run_id, applied_at, seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (run.run_id, run.kind, run.status, int(run.vantage), run.started_at,
                     run.finished_at, run.parent_run_id, at, seq),
                )
                for check in (coverage.checks.values() if coverage is not None else ()):
                    conn.execute(
                        "INSERT INTO check_coverage (run_id, check_id, domain_id, status, reason, "
                        "examined, total) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (run.run_id, check.check_id, check.domain_id, check.status.value,
                         check.reason, check.examined, check.total),
                    )
                for result in results:
                    written += self._apply_result(conn, run, result, meta.get(result.item_id), at)
        except EngagementStoreError:
            raise
        return written

    def _apply_result(
        self, conn: Any, run: RunRecord, result: ItemResult, meta: Optional[LedgerItem], at: str
    ) -> int:
        row = conn.execute("SELECT * FROM items WHERE item_id=?", (result.item_id,)).fetchone()
        transition = result.transition
        if row is None:
            if meta is None or transition is not Transition.NEW:
                raise EngagementStoreError(
                    f"Run {run.run_id} decided {transition.value!r} for an item the ledger does "
                    f"not hold ({result.item_id}); nothing was applied."
                )
            conn.execute(
                "INSERT INTO items (item_id, kind, key, domain_id, object_id, label, legacy_alias, "
                "status, last_vantage, first_seen_run, last_seen_run, last_verified_run, "
                "last_verified_at, evaluation_state, evaluation_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (meta.item_id, meta.kind, meta.key, meta.domain_id, meta.object_id, meta.label,
                 meta.legacy_alias, STATUS_OPEN, int(run.vantage), run.run_id, run.run_id,
                 run.run_id, at, EVALUATED),
            )
            self._event(conn, run, result, None, STATUS_OPEN, at)
            return 1
        if transition is Transition.TERMINAL_UNCHANGED:
            return 0
        if transition is Transition.NOT_REEVALUATED:
            conn.execute(
                "UPDATE items SET evaluation_state=?, evaluation_reason=? WHERE item_id=?",
                (NOT_REEVALUATED, result.reason or None, result.item_id),
            )
            return 0
        new_status = _STATUS_AFTER.get(transition) or row["status"]
        present = transition is not Transition.REMEDIATED
        conn.execute(
            "UPDATE items SET status=?, last_verified_run=?, last_verified_at=?, "
            "evaluation_state=?, evaluation_reason=NULL, "
            "last_seen_run=CASE WHEN ? THEN ? ELSE last_seen_run END, "
            "last_vantage=CASE WHEN ? THEN ? ELSE last_vantage END, "
            "label=COALESCE(NULLIF(?, ''), label), object_id=COALESCE(?, object_id) "
            "WHERE item_id=?",
            (new_status, run.run_id, at, EVALUATED, present, run.run_id, present,
             int(run.vantage), meta.label if meta else "", meta.object_id if meta else None,
             result.item_id),
        )
        if new_status != row["status"]:
            self._event(conn, run, result, row["status"], new_status, at)
            return 1
        return 0

    @staticmethod
    def _event(
        conn: Any, run: RunRecord, result: ItemResult, old: Optional[str], new: str, at: str
    ) -> None:
        conn.execute(
            "INSERT INTO item_events (run_id, item_id, transition, old_status, new_status, reason, at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run.run_id, result.item_id, result.transition.value, old, new, result.reason or None, at),
        )

    # -- export ------------------------------------------------------------
    def export_document(self, *, generated_at: str) -> dict[str, Any]:
        """The ``adscan.ledger/1`` projection (no secrets; ids, states, dates)."""
        items = []
        for row in self.items():
            items.append(
                {
                    "item_id": row["item_id"],
                    "kind": row["kind"],
                    "key": row["key"],
                    "domain_id": row["domain_id"],
                    "object_id": row["object_id"],
                    "label": row["label"] or "",
                    "legacy_alias": row["legacy_alias"] or "",
                    "status": row["status"],
                    "disposition": row["disposition"],
                    "evaluation_state": row["evaluation_state"],
                    "evaluation_reason": row["evaluation_reason"],
                    "first_seen_run": row["first_seen_run"],
                    "last_seen_run": row["last_seen_run"],
                    "last_verified_run": row["last_verified_run"],
                    "last_verified_at": row["last_verified_at"],
                }
            )
        return {
            "schema": LEDGER_SCHEMA,
            "engagement_id": self.engagement_id,
            "generated_at": generated_at,
            "runs": [
                {k: r[k] for k in ("run_id", "kind", "status", "vantage", "started_at",
                                   "finished_at", "parent_run_id", "applied_at")}
                for r in self.runs()
            ],
            "items": items,
            "events": [
                {k: e[k] for k in ("run_id", "item_id", "transition", "old_status",
                                   "new_status", "reason", "at")}
                for e in (
                    dict(r)
                    for r in self._conn.execute(
                        "SELECT e.* FROM item_events e JOIN runs r ON r.run_id = e.run_id "
                        "ORDER BY r.seq, e.event_id"
                    )
                )
            ],
            "dispositions": [
                {k: d[k] for k in ("item_id", "status", "reason", "set_by", "set_at", "expires_at")}
                for d in sorted(self._dispositions().values(), key=lambda d: d["item_id"])
            ],
        }

    def export(self, directory: Any, *, generated_at: str) -> Path:
        """Write ``<directory>/ledger.json`` atomically and return its path."""
        target = Path(str(directory))
        target.mkdir(parents=True, exist_ok=True)
        path = target / LEDGER_EXPORT_FILENAME
        tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
        tmp.write_text(
            json.dumps(self.export_document(generated_at=generated_at), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        os.replace(tmp, path)
        return path


__all__ = (
    "EVALUATED",
    "LEDGER_SCHEMA",
    "NOT_REEVALUATED",
    "SCHEMA_VERSION",
    "EngagementStore",
    "EngagementStoreError",
    "LedgerItem",
    "RunRecord",
    "choose_journal_mode",
    "open_store",
    "store_path",
)
