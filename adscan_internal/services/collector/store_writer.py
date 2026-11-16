"""Collector stages write through the graph store (inventory-first persistence, package G).

A collector stage never writes a graph edge. It commits what it collected as
store UNITS (``GraphStore.unit``), and the graph is built from the store
(``graph_build``) and exported by ``graph_runtime.export_graph_if_due``. This
module is the one place the collector turns a ``CollectionResult`` into units:

* **Units are keyed by what a fact is about, never by paging order** (the
  interface contract): directory objects by object class (``User``,
  ``Computer``, ...), LDAP relationships by relationship family (the relation
  name), ACL facts by the class of the object the right is over, a host's
  sessions, local groups and shares by the host's SID, the whole stage for the
  small ones (well-known principals, trusts, AD CS facts).
* **Idempotent and cheap to repeat.** The writer keeps, per store, a digest of
  every unit it committed in this process; a unit whose content did not change
  is not rewritten. So the orchestrator can commit the directory stages right
  after the LDAP pass (the graph exists before the long host sweep) and again
  at the end of the domain (DNS-resolved and SMB-learned host properties, the
  host audit findings), and only what moved is written.
* **A complete directory pass drops what it no longer saw.** When a stage
  committed in full and without a recorded stage failure, a unit of that stage
  from an earlier collection that this one did not produce (a relationship
  family that is gone) is replaced by an empty unit. Objects are never removed
  (spec D5) and SMB host units are never dropped this way (a host not reached
  this time keeps what it said last time).
* **Every stage ends.** A stage that wrote is ended ``complete``, or ``failed``
  with the collector's own stage-failure reason, so a graph never reads as
  complete over a cut-off directory read.
* **No secret reaches the store.** Fact notes and datum bodies are redacted with
  the workspace fingerprint key before they become records (the same seam and
  sidecar ``save_attack_graph`` uses); the store's own guard stays the last line.

The per-host commits of the SMB sweep are in :class:`HostUnitCommitter`.
"""

from __future__ import annotations

import hashlib
import json
import threading
import weakref
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from adscan_core import telemetry
from adscan_core.graph_store import DatumRecord, FactRecord, GraphStore, ObjectRecord
from adscan_core.graph_store.records import (
    STAGE_ADCS,
    STAGE_LDAP_ACLS,
    STAGE_LDAP_OBJECTS,
    STAGE_LDAP_RELATIONSHIPS,
    STAGE_SMB_HOSTS,
    STAGE_SMB_SHARES,
    STAGE_TRUSTS,
    STAGE_WELL_KNOWN,
    WHOLE_STAGE_UNIT,
    StageStatus,
)
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    CollectorNode,
)
from adscan_internal.services.graph_build.ingest import (
    _directory_result_data,
    _result_data,
    default_stage_of_edge,
    default_unit_of_edge,
    fact_record_from_edge,
    object_record_from_node,
)

#: Unit of the domain-level data records (policy, PSOs, findings, census).
DOMAIN_DATA_UNIT = "domain_data"

#: Stages a host sweep owns: their units are only ever written per host.
SMB_STAGES = frozenset({STAGE_SMB_HOSTS, STAGE_SMB_SHARES})

#: Stages whose units a complete directory pass replaces wholesale.
_DIRECTORY_STAGES = frozenset(
    {
        STAGE_LDAP_OBJECTS,
        STAGE_LDAP_RELATIONSHIPS,
        STAGE_LDAP_ACLS,
        STAGE_WELL_KNOWN,
        STAGE_ADCS,
        STAGE_TRUSTS,
    }
)

_ADCS_OBJECT_KINDS = frozenset({"CertTemplate", "EnterpriseCA", "RootCA", "AIACA", "NTAuthStore"})

#: Redacts one JSON payload before it becomes a record: ``(payload, relation) -> payload``.
Redactor = Callable[[Mapping[str, Any], str], dict[str, Any]]


def _no_redaction(payload: Mapping[str, Any], _relation: str) -> dict[str, Any]:
    return dict(payload)


# --------------------------------------------------------------------------- #
# Splitting a CollectionResult into units
# --------------------------------------------------------------------------- #


@dataclass
class UnitSource:
    """What one unit commits, still as collector types (converted on commit)."""

    nodes: list[CollectorNode] = field(default_factory=list)
    edges: list[CollectorEdge] = field(default_factory=list)
    data: list[DatumRecord] = field(default_factory=list)
    patches: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.nodes or self.edges or self.data or self.patches)


def stage_of_node(node: CollectorNode) -> str:
    """The stage that collects ``node``."""
    if str(node.kind) in _ADCS_OBJECT_KINDS:
        return STAGE_ADCS
    if (node.properties or {}).get("well_known_sid"):
        return STAGE_WELL_KNOWN
    return STAGE_LDAP_OBJECTS


def unit_of_node(node: CollectorNode) -> str:
    """The unit ``node`` commits in: its object class (one unit for well-known)."""
    if stage_of_node(node) == STAGE_WELL_KNOWN:
        return WHOLE_STAGE_UNIT
    return str(node.kind or "Unknown")


def unit_of_edge(edge: CollectorEdge, stage: str, kind_of: Callable[[str], str]) -> str:
    """The unit ``edge`` commits in (a function of the fact's own object).

    SMB facts: the host's SID. LDAP relationships: the relationship family.
    ACL facts: the class of the object the right is over. Well-known
    principals, trusts and AD CS facts: the whole stage.
    """
    if stage in SMB_STAGES:
        return default_unit_of_edge(edge)
    if stage == STAGE_LDAP_RELATIONSHIPS:
        return str(edge.relation or "Unknown")
    if stage == STAGE_LDAP_ACLS:
        return kind_of(str(edge.target_object_id or "").upper()) or "Unknown"
    return WHOLE_STAGE_UNIT


def split_collection_units(
    result: CollectionResult, *, include_smb: bool = True
) -> dict[tuple[str, str], UnitSource]:
    """Split ``result`` into the units its stages commit.

    ``result.edges`` is read once, in order (it may be a single-pass stream).
    ``include_smb=False`` leaves the SMB host and share facts out: a host sweep
    that commits them per host owns them.
    """
    units: dict[tuple[str, str], UnitSource] = {}
    nodes = result.nodes

    def kind_of(sid: str) -> str:
        node = nodes.get(sid)
        return str(node.kind) if node is not None else ""

    for node in nodes.values():
        key = (stage_of_node(node), unit_of_node(node))
        units.setdefault(key, UnitSource()).nodes.append(node)
    for edge in result.edges:
        stage = default_stage_of_edge(edge)
        if stage in SMB_STAGES and not include_smb:
            continue
        key = (stage, unit_of_edge(edge, stage, kind_of))
        units.setdefault(key, UnitSource()).edges.append(edge)
    data = _result_data(result) + _directory_result_data(result)
    if data:
        units.setdefault((STAGE_LDAP_OBJECTS, DOMAIN_DATA_UNIT), UnitSource()).data.extend(data)
    return units


# --------------------------------------------------------------------------- #
# Digests: commit a unit only when its content moved
# --------------------------------------------------------------------------- #


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def unit_digest(source: UnitSource) -> str:
    """A stable digest of a unit's content (order-sensitive, as the store is)."""
    digest = hashlib.blake2b(digest_size=20)
    for node in source.nodes:
        digest.update(b"N")
        digest.update(
            _canonical(
                (
                    node.object_id,
                    node.kind,
                    node.name,
                    node.domain,
                    node.samaccountname,
                    node.distinguished_name,
                    node.enabled,
                    node.highvalue,
                    node.properties,
                )
            ).encode("utf-8", "surrogatepass")
        )
    for edge in source.edges:
        digest.update(b"E")
        digest.update(
            _canonical(
                (
                    edge.source_object_id,
                    edge.target_object_id,
                    edge.relation,
                    edge.source,
                    edge.method,
                    edge.notes,
                )
            ).encode("utf-8", "surrogatepass")
        )
    for datum in source.data:
        digest.update(b"D")
        digest.update(_canonical((datum.kind, datum.key, datum.body)).encode("utf-8", "surrogatepass"))
    for object_id, props in source.patches:
        digest.update(b"P")
        digest.update(_canonical((object_id, props)).encode("utf-8", "surrogatepass"))
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# The writer
# --------------------------------------------------------------------------- #


def _stage_failure_for(stage: str, result: CollectionResult | None) -> tuple[str, str] | None:
    """``(reason, detail)`` of the first collector failure that cut ``stage``, else None.

    The collector's own failure ids are coarser than the store's stages: an
    ``adcs*`` failure cuts the AD CS stage, any other cuts the directory read
    (objects, relationships and ACLs come from one connection-scoped block).
    """
    failures = list(getattr(result, "stage_failures", None) or ()) if result is not None else []
    for failure in failures:
        name = str(getattr(failure, "stage", "") or "")
        cuts_adcs = name.startswith("adcs")
        if (stage == STAGE_ADCS) == cuts_adcs and stage in _DIRECTORY_STAGES:
            reason = str(getattr(failure, "reason", "") or "aborted")
            return reason, name
    return None


class CollectorStoreWriter:
    """Commits collector units into one domain's store, skipping what did not move.

    One per store object (:func:`writer_for`), so the digests of a session's
    earlier commits are remembered across the orchestrator's calls. Thread-safe:
    the host sweep commits from its writer thread while nothing else writes the
    same units.
    """

    def __init__(self, store: GraphStore, *, redactor: Redactor | None = None) -> None:
        self.store = store
        self.redactor: Redactor = redactor or _no_redaction
        self._digests: dict[tuple[str, str], str] = {}
        self._lock = threading.RLock()
        #: Set by the orchestrator when a host sweep commits the SMB units
        #: itself; a later :meth:`commit_result` then leaves them out.
        self.sweep_owns_smb = False

    # ---- records ------------------------------------------------------------ #

    def _facts(self, edges: Iterable[CollectorEdge]) -> Iterator[FactRecord]:
        for edge in edges:
            record = fact_record_from_edge(edge)
            if record.notes:
                record = FactRecord(
                    subject_id=record.subject_id,
                    object_id=record.object_id,
                    relation=record.relation,
                    source=record.source,
                    method=record.method,
                    notes=self.redactor(record.notes, record.relation),
                )
            yield record

    def _data(self, data: Iterable[DatumRecord]) -> Iterator[DatumRecord]:
        for datum in data:
            yield DatumRecord(kind=datum.kind, key=datum.key, body=self.redactor(datum.body, ""))

    @staticmethod
    def _objects(nodes: Iterable[CollectorNode]) -> Iterator[ObjectRecord]:
        for node in nodes:
            yield object_record_from_node(node)

    # ---- commits ------------------------------------------------------------ #

    def commit_unit(
        self,
        stage: str,
        unit: str,
        source: UnitSource,
        *,
        observed_at: str = "",
        force: bool = False,
        digest: str = "",
    ) -> bool:
        """Commit one unit when its content moved (or ``force``). Returns whether it wrote."""
        digest = digest or unit_digest(source)
        key = (stage, unit)
        with self._lock:
            if not force and self._digests.get(key) == digest:
                return False
            with self.store.unit(stage, unit, observed_at=observed_at) as writer:
                if source.nodes:
                    writer.add_objects(self._objects(source.nodes))
                if source.edges:
                    writer.add_facts(self._facts(source.edges))
                if source.data:
                    writer.add_data(self._data(source.data))
                for object_id, props in source.patches:
                    writer.patch_object(object_id, dict(props))
            self._digests[key] = digest
            return True

    def commit_units(
        self,
        units: Mapping[tuple[str, str], UnitSource],
        *,
        result: CollectionResult | None = None,
        prune_stale: bool = True,
        observed_at: str = "",
    ) -> dict[str, int]:
        """Commit ``units`` stage by stage; end every stage that wrote.

        A stage the collector recorded as cut off ends ``failed`` with that
        reason and keeps every unit of an earlier collection. A complete
        directory stage replaces each earlier unit it did not produce with an
        empty one (``prune_stale``). Returns ``{"units_written", "units_unchanged",
        "units_pruned"}``.
        """
        counts = {"units_written": 0, "units_unchanged": 0, "units_pruned": 0}
        by_stage: dict[str, list[str]] = {}
        for stage, unit in units:
            by_stage.setdefault(stage, []).append(unit)
        for stage in sorted(by_stage):
            failure = _stage_failure_for(stage, result)
            begun = False
            try:
                for unit in sorted(by_stage[stage]):
                    digest = unit_digest(units[(stage, unit)])
                    if self._digests.get((stage, unit)) == digest:
                        counts["units_unchanged"] += 1
                        continue
                    if not begun:
                        self.store.begin_stage(stage)
                        begun = True
                    self.commit_unit(
                        stage, unit, units[(stage, unit)], observed_at=observed_at, digest=digest
                    )
                    counts["units_written"] += 1
                if prune_stale and failure is None and stage in _DIRECTORY_STAGES:
                    produced = set(by_stage[stage])
                    for stale in sorted(self.store.done_units(stage) - produced):
                        if not begun:
                            self.store.begin_stage(stage)
                            begun = True
                        self.commit_unit(stage, stale, UnitSource(), observed_at=observed_at, force=True)
                        counts["units_pruned"] += 1
            except BaseException as exc:
                if begun:
                    status: StageStatus = "stopped" if not isinstance(exc, Exception) else "failed"
                    self._end_quietly(stage, status, reason=type(exc).__name__)
                raise
            if begun:
                if failure is not None:
                    self.store.end_stage(stage, "failed", reason=failure[0], detail=failure[1])
                else:
                    self.store.end_stage(stage, "complete")
        return counts

    def commit_result(
        self, result: CollectionResult, *, include_smb: bool | None = None, observed_at: str = ""
    ) -> dict[str, int]:
        """Commit every unit of ``result`` (the SMB ones unless a sweep owns them)."""
        smb = (not self.sweep_owns_smb) if include_smb is None else include_smb
        units = split_collection_units(result, include_smb=smb)
        return self.commit_units(units, result=result, observed_at=observed_at)

    def _end_quietly(self, stage: str, status: StageStatus, *, reason: str = "", detail: str = "") -> None:
        try:
            self.store.end_stage(stage, status, reason=reason, detail=detail)
        except Exception as exc:  # noqa: BLE001 - the original error is what propagates
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


_WRITERS: "weakref.WeakKeyDictionary[Any, CollectorStoreWriter]" = weakref.WeakKeyDictionary()
_WRITERS_GUARD = threading.Lock()


def writer_for(store: GraphStore, *, redactor: Redactor | None = None) -> CollectorStoreWriter:
    """The writer of ``store`` (one per open store, so digests persist for the session)."""
    with _WRITERS_GUARD:
        writer = _WRITERS.get(store)
        if writer is None:
            writer = CollectorStoreWriter(store, redactor=redactor)
            _WRITERS[store] = writer
        elif redactor is not None:
            writer.redactor = redactor
        return writer


# --------------------------------------------------------------------------- #
# Shell binding: the store and the redaction key of a session
# --------------------------------------------------------------------------- #


def shell_redactor(shell: object, domain: str) -> Redactor:
    """A redactor bound to the workspace's fingerprint key and sidecar.

    Same seam as ``save_attack_graph`` (``graph_secret_store``): a secret value
    becomes a reference carrying its keyed fingerprint and the value is
    retained in the domain's sidecar. A payload with no inline secret is
    returned as a copy after one cheap check. Fails closed: when the key or the
    sidecar is unavailable the value is still removed.
    """
    from adscan_core import graph_secret_refs as refs  # noqa: PLC0415

    state: dict[str, Any] = {}

    def _key() -> bytes | None:
        if "key" not in state:
            try:
                from adscan_internal.services.graph_secret_store import (  # noqa: PLC0415
                    fingerprint_key_for,
                )

                state["key"] = fingerprint_key_for(shell, create=True)
            except Exception:  # noqa: BLE001 - fail closed below
                state["key"] = None
        return state["key"]

    def _redact(payload: Mapping[str, Any], relation: str) -> dict[str, Any]:
        out = dict(payload or {})
        if not refs.notes_carry_inline_secret(out) and not _nested_secret(out):
            return out
        try:
            redacted, extracted = refs.redact_note_secrets(
                out, key=_key(), domain=domain, relation=relation
            )
            redacted = refs.redact_secrets_deep(redacted)
            if extracted:
                from adscan_internal.services.graph_secret_store import (  # noqa: PLC0415
                    sidecar_path_for,
                )

                refs.retain_extracted_secrets(sidecar_path_for(shell, domain), extracted)
            print_info_debug(
                f"collector store writer: redacted a secret-bearing field before it became a record "
                f"(relation={relation or 'data'})"
            )
            return redacted if isinstance(redacted, dict) else {}
        except Exception as exc:  # noqa: BLE001 - fail closed
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            stripped = refs.redact_secrets_deep(out)
            return stripped if isinstance(stripped, dict) else {}

    return _redact


def _nested_secret(payload: Mapping[str, Any]) -> bool:
    from adscan_core.graph_store.secret_guard import _may_hold_secret  # noqa: PLC0415

    return _may_hold_secret(payload)


def store_writer_for_shell(shell: object, domain: str) -> CollectorStoreWriter:
    """The store writer of ``domain`` for this session (creates the store).

    Raises ``GraphStoreError`` when the store cannot be opened, and returns a
    writer over a read-only store on a frozen workspace (its commits raise
    ``GraphStoreFrozenError``); the caller decides.
    """
    from adscan_internal.services.graph_runtime import graph_store_for  # noqa: PLC0415

    store = graph_store_for(shell, domain, create=True)
    if store is None:
        from adscan_core.graph_store import GraphStoreFrozenError  # noqa: PLC0415

        raise GraphStoreFrozenError(f"no writable graph store for {domain}")
    return writer_for(store, redactor=shell_redactor(shell, domain))


__all__ = (
    "DOMAIN_DATA_UNIT",
    "SMB_STAGES",
    "CollectorStoreWriter",
    "UnitSource",
    "shell_redactor",
    "split_collection_units",
    "stage_of_node",
    "store_writer_for_shell",
    "unit_digest",
    "unit_of_edge",
    "unit_of_node",
    "writer_for",
)


# --------------------------------------------------------------------------- #
# The SMB host sweep: one unit per host, committed on its own thread
# --------------------------------------------------------------------------- #


def smb_stages_for(*, collect_samr: bool, collect_shares: bool) -> tuple[str, ...]:
    """The store stages a host sweep writes, given what it collects.

    Sessions and local groups come from the SAMR / SRVSVC stage
    (``smb_hosts``), share grants from the share stage (``smb_shares``). A
    stage the sweep does not collect is never written, so a shares-only sweep
    never wipes the sessions an earlier sweep committed for a host.
    """
    stages: list[str] = []
    if collect_samr:
        stages.append(STAGE_SMB_HOSTS)
    if collect_shares:
        stages.append(STAGE_SMB_SHARES)
    return tuple(stages)


class HostUnitCommitter:
    """Commits each swept host as store units on a dedicated writer thread.

    The sweep calls :meth:`submit` on its event-loop thread right after a host
    is merged; the call only queues, so the loop never waits on the disk. The
    writer thread commits, per host and per stage the sweep collects, one unit
    named by the host's SID: its facts (sessions, local groups, share grants)
    and the node properties the merge set (OS, signing, share names) as a
    patch. The share unit is committed first and the host unit last, so a crash
    between the two leaves the host out of the resume skip-set (the
    intersection of the stages' done units) and it is collected again.

    A commit's cost does not depend on how much was collected before (a store
    unit is one transaction). ``on_commit`` runs after each commit on the
    writer thread (the orchestrator passes the throttled live export).
    """

    _SENTINEL = object()

    def __init__(
        self,
        writer: CollectorStoreWriter,
        *,
        stages: tuple[str, ...],
        on_commit: Callable[[], Any] | None = None,
        clock: Callable[[], str] | None = None,
    ) -> None:
        import queue  # noqa: PLC0415

        #: UTC ISO stamp of a commit (the store's own clock when ``None``).
        self._clock = clock
        self._writer = writer
        self._stages = tuple(stage for stage in (STAGE_SMB_SHARES, STAGE_SMB_HOSTS) if stage in stages)
        self._on_commit = on_commit
        self._queue: "queue.Queue[Any]" = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.committed = 0
        self.failed = 0
        #: Hosts a resumed sweep skipped because an earlier run committed them.
        self.resumed_count = 0
        #: The sweep's :class:`LiveExporter` (unattended runs only), set by the orchestrator.
        self.live_exporter: Any = None
        self.commit_seconds: list[float] = []

    @property
    def stages(self) -> tuple[str, ...]:
        return self._stages

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                return
            self._thread = threading.Thread(
                target=self._run, name="adscan-graph-store-host-commit", daemon=True
            )
            self._thread.start()

    def submit(self, host_id: str, edges: list[Any], properties: dict[str, Any]) -> None:
        """Queue one merged host (loop thread; never blocks)."""
        self._queue.put((str(host_id).upper(), list(edges), dict(properties or {})))

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is self._SENTINEL:
                return
            self.commit_host(*item)

    def commit_host(self, host_id: str, edges: list[Any], properties: dict[str, Any]) -> bool:
        """Commit one host now (the writer thread's step; callable directly)."""
        import time  # noqa: PLC0415

        by_stage: dict[str, list[Any]] = {stage: [] for stage in self._stages}
        for edge in edges:
            stage = default_stage_of_edge(edge)
            if stage in by_stage:
                by_stage[stage].append(edge)
        started = time.monotonic()
        try:
            observed_at = self._clock() if self._clock is not None else ""
            for stage in self._stages:
                patches = [(host_id, properties)] if stage == self._stages[-1] and properties else []
                self._writer.commit_unit(
                    stage,
                    host_id,
                    UnitSource(edges=by_stage[stage], patches=patches),
                    force=True,
                    observed_at=observed_at,
                )
        except Exception as exc:  # noqa: BLE001 - the host stays out of the done-set
            self.failed += 1
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return False
        self.commit_seconds.append(time.monotonic() - started)
        self.committed += 1
        if self._on_commit is not None:
            try:
                self._on_commit()
            except Exception as exc:  # noqa: BLE001 - an export never stops the commits
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
        return True

    def close(self, timeout: float = 300.0) -> bool:
        """Commit everything queued and stop the thread. Returns whether it drained.

        Hosts still queued are committed (each in milliseconds), so a stop
        keeps every host that was merged. Bounded by ``timeout``: a writer that
        cannot finish is left behind (daemon) and its hosts are not done.
        """
        with self._lock:
            thread = self._thread
        if thread is None:
            return True
        self._queue.put(self._SENTINEL)
        thread.join(timeout)
        return not thread.is_alive()

    def end_stages(self, status: StageStatus, *, reason: str = "", detail: str = "") -> None:
        """End every stage this sweep writes with ``status``."""
        for stage in self._stages:
            self._writer._end_quietly(stage, status, reason=reason, detail=detail)  # noqa: SLF001


__all__ = (*__all__, "HostUnitCommitter", "smb_stages_for")


class LiveExporter:
    """Runs the throttled live export on its own single-flight thread.

    The host sweep asks for an export after a commit (:meth:`request`); the
    request never blocks the committer. One export runs at a time: a request
    that arrives while one runs is coalesced into ONE follow-up run. The export
    itself is throttled by the export policy, so most requests write nothing.

    :meth:`stop` takes no new request and returns at once; an export already
    running finishes on its own thread (daemon) and nothing waits for it, so a
    stop or the end of the sweep never sits behind a build. :meth:`wait` exists
    for a caller that must not start its own export concurrently (tests).
    """

    def __init__(self, export: Callable[[], Any], *, name: str = "adscan-graph-live-export") -> None:
        self._export = export
        self._name = name
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._pending = False
        self._stopped = False
        self.runs = 0

    def request(self) -> None:
        """Ask for an export (any thread; never blocks)."""
        with self._lock:
            if self._stopped:
                return
            if self._thread is not None and self._thread.is_alive():
                self._pending = True
                return
            self._pending = False
            self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
            self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                self.runs += 1
                self._export()
            except Exception as exc:  # noqa: BLE001 - a live export never stops the sweep
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
            with self._lock:
                if not self._pending or self._stopped:
                    self._pending = False
                    return
                self._pending = False

    def stop(self) -> None:
        """Take no new request. Returns at once; a running export finishes alone."""
        with self._lock:
            self._stopped = True
            self._pending = False

    def busy(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for a running export (never called on the stop path). Returns whether idle."""
        with self._lock:
            thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()


__all__ = (*__all__, "LiveExporter")


def commit_share_probe_read_sets(shell: object, domain: str, host: str, views: Iterable[Mapping[str, Any]]) -> int:
    """Commit the light share probe's proven readers as ``unauthenticated`` evidence.

    The credential-less share probe (``cli/smb_shares_view``) measures, per
    share of ``host``, which principals can read it (``live.read_set`` with its
    ``read_set_verification``). 14.0.x kept that only in ``smb/shares.json`` and
    the share-credential reconciliation merged it from there. The store keeps
    it as one ``unauthenticated`` unit per host (``share_probe:<host>``):
    ``ReadShare`` facts from each reader SID, with source
    :data:`~adscan_internal.services.graph_build.ingest.SHARE_PROBE_FACT_SOURCE`,
    which the build reads only as reconciliation evidence (never a base edge,
    never an inventory relationship). A re-probe of the host replaces its unit.
    Returns how many facts were committed; best-effort (never raises).
    """
    from adscan_core.graph_store.records import STAGE_UNAUTH  # noqa: PLC0415
    from adscan_internal.services.graph_build.ingest import SHARE_PROBE_FACT_SOURCE  # noqa: PLC0415

    host_key = str(host or "").strip().lower()
    if not host_key:
        return 0
    edges: list[CollectorEdge] = []
    for view in views or ():
        if not isinstance(view, Mapping):
            continue
        share = str(view.get("name") or "").strip()
        live = view.get("live") if isinstance(view.get("live"), Mapping) else {}
        verification = str(live.get("read_set_verification") or "").strip().lower()
        for entry in live.get("read_set") or ():
            if not isinstance(entry, Mapping):
                continue
            sid = str(entry.get("sid") or "").strip().upper()
            if not sid or not share:
                continue
            try:
                mask = int(entry.get("mask") or 0)
            except (TypeError, ValueError):
                mask = 0
            edges.append(
                CollectorEdge(
                    source_object_id=sid,
                    target_object_id=host_key,
                    relation="ReadShare",
                    source=SHARE_PROBE_FACT_SOURCE,
                    method="smb_shares_native",
                    notes={
                        "share_name": share,
                        "verification": verification,
                        "mask": mask,
                        "label": str(entry.get("label") or ""),
                    },
                )
            )
    try:
        writer = store_writer_for_shell(shell, domain)
        writer.store.begin_stage(STAGE_UNAUTH)
        writer.commit_unit(STAGE_UNAUTH, f"share_probe:{host_key}", UnitSource(edges=edges), force=True)
        writer.store.end_stage(STAGE_UNAUTH, "complete")
    except Exception as exc:  # noqa: BLE001 - the snapshot file still stands
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return 0
    return len(edges)


__all__ = (*__all__, "commit_share_probe_read_sets")
