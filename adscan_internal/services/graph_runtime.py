"""Runtime writes to the attack graph: the facade over the runtime overlay.

Every change the graph receives AFTER collection goes through this module: an
attack step's status, an edge found while exploiting (a privilege sweep's
AdminTo, a password-reuse edge, a roast entry edge), a synthetic node, a
cleanup's retirement of an edge, a bulk status reset. Each call appends one
operation to the store's overlay (durable, a few milliseconds, independent of
graph size) and applies the same operation to the in-memory graph, so nothing
rewrites ``attack_graph.json`` per step any more.

No module outside this one and ``graph_build`` may call
``attack_graph_service.save_attack_graph`` or mutate a loaded graph dict and
save it. Locked by ``tests/unit/services/test_graph_runtime_is_the_only_writer.py``
(package D), whose allow-list shrinks to empty as package E converts callers.
Design: ``docs/superpowers/specs/2026-11-12-inventory-first-graph-persistence.md``.

What lives here:

* :func:`graph_store_for` / :func:`close_graph_stores`: one open store per
  domain directory of the session's CURRENT workspace (the execution ``.run_*``
  workspace during a live scan), cached on the shell; the first write to a
  14.0.x workspace imports its ``attack_graph.json`` (``legacy_import``);
* :func:`build_context_for`: the build context of one domain, a snapshot of the
  session's recorded facts;
* the LIVE graph (:func:`live_graph`): the built graph of a store, memoised on
  ``(store.generation(), context.fingerprint())``; ``load_attack_graph``
  returns it, and every runtime write patches it in place through
  ``overlay.apply_op`` (the post-overlay passes are deferred to the next read),
  so a write costs the same on 2,000 edges as on 200,000;
* the writers: :func:`record_edge_status`, :func:`record_runtime_edge`,
  :func:`record_runtime_node`, :func:`patch_runtime_edge`,
  :func:`retire_runtime_edge`, :func:`reset_edge_statuses`,
  :func:`record_overlay_ops`; and :func:`mutate` / :func:`runtime_writer`, which
  turn ``upsert_edge`` / ``upsert_nodes`` on the live graph into overlay ops;
  every op is redacted (``redact_graph_for_persist`` semantics) before it is
  stored;
* the legacy save bridge (:func:`record_saved_graph`, what
  ``save_attack_graph`` now is): the caller's graph diffed against the built
  one, the difference recorded as ops;
* :func:`export_graph_if_due` / :func:`ensure_export_fresh`: the export keyed
  on ``(generation, fingerprint)``, followed by the sidecar exports and the
  findings sync.

Nothing here is bound to an event loop: the stores are synchronous, and the
registry holds plain objects behind a ``threading.Lock``, so a call from any
thread or any bridge loop sees the same handles.
"""

from __future__ import annotations

import copy
import functools
import json
import os
import threading
import time
import uuid
import weakref
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adscan_core import telemetry
from adscan_core.graph_store import (
    EdgeRef,
    GraphStore,
    GraphStoreError,
    OverlayOp,
    StoreGeneration,
    graph_store_dir,
    graph_store_exists,
    open_graph_store,
)
from adscan_core.graph_store.records import STAGE_LEGACY_IMPORT
from adscan_core.reporting.resource_coverage import GRAPH_BUILD_STOPPED_FLAG
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_core.workspace_freeze import write_blocked
from adscan_internal.services.graph_build import api as graph_build_api
from adscan_internal.services.graph_build import export as graph_export
from adscan_internal.services.graph_build.sidecars import export_sidecars
from adscan_internal.workspaces import domain_subpath, resolve_workspace_cwd
from adscan_internal.workspaces.io import json_default

#: The graph as every consumer knows it (``attack_graph.json`` as a dict).
Graph = dict[str, Any]

#: File name of the graph export inside ``domains/<domain>/``.
ATTACK_GRAPH_FILENAME = "attack_graph.json"

#: Attribute of the shell that carries the session's store registry.
_REGISTRY_ATTR = "_graph_store_registry"
#: Serialises the creation of a shell's registry (two threads asking at once).
_REGISTRY_GUARD = threading.Lock()
#: Every session that opened a store, for the unattended entry points'
#: ``finally`` (:func:`close_all_graph_stores`). Weak: a finished session goes.
_SESSIONS: "weakref.WeakSet[Any]" = weakref.WeakSet()
#: Sessions that cannot be weakly referenced (a ``SimpleNamespace``, a slotted
#: context object), held by identity until :func:`close_graph_stores`.
_STRONG_SESSIONS: dict[int, object] = {}


def _path_key(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


@dataclass
class _OpenStore:
    """One open store of the session, where it belongs, and its live graph.

    ``live`` is the built graph the session reads and the runtime writes patch
    in place; it is current for ``(live_generation, live_fingerprint)``.
    ``pending_post_overlay`` says writes were applied since the post-overlay
    passes last ran (a reader runs them first). ``lock`` serialises the
    session's writes to this store with the reads of its live graph.
    """

    domain: str
    domain_dir: str
    workspace_key: str
    store: GraphStore
    lock: threading.RLock = field(default_factory=threading.RLock)
    live: dict[str, Any] | None = None
    live_generation: StoreGeneration | None = None
    live_fingerprint: str = ""
    live_context: Any = None
    live_index: Any = None
    pending_post_overlay: bool = False
    #: What the pending writes touched: ``pending_full`` when the full
    #: post-overlay passes are needed (a new edge, a node, a retirement, a bulk
    #: reset, a change to an edge the follow-up derivation reads), else the
    #: edges whose classification and Tier-0-source verdict must be refreshed.
    pending_full: bool = False
    pending_edges: list[dict[str, Any]] = field(default_factory=list)
    export_dirty: bool = False
    #: The build of this store stopped at the memory ceiling in this session
    #: (``graph_runtime_memory``). It is not retried: every reader gets an empty
    #: graph, nothing is exported, and the stop is already declared.
    build_stopped: bool = False
    #: Set with ``build_stopped``: a token unique to this stop, folded into the
    #: store's epoch (:func:`store_generation_token`) so nothing computed while
    #: the graph was unavailable keys like a full build of the same generation.
    stop_token: str = ""
    #: Holders of ``lock`` right now (a read, a write, a writer scope): a store
    #: in use is never closed by the open-store cap.
    busy: int = 0
    #: The session registries holding this entry. One entry per domain
    #: directory is shared by every session of the process (a scan and the
    #: report's own shell read ONE live graph, never two); the store is closed
    #: when the last holder releases it (:func:`_release`).
    holders: list[Any] = field(default_factory=list)


#: Guards every change of an entry's in-use count.
_BUSY_LOCK = threading.Lock()


def _pin(entry: _OpenStore) -> None:
    with _BUSY_LOCK:
        entry.busy += 1


def _unpin(entry: _OpenStore) -> None:
    with _BUSY_LOCK:
        entry.busy -= 1


@contextmanager
def _using(entry: _OpenStore) -> Iterator[None]:
    """Hold ``entry`` for a read or a write (its lock, and the in-use count)."""
    with entry.lock:
        _pin(entry)
        try:
            yield
        finally:
            _unpin(entry)


@dataclass
class _GraphStoreRegistry:
    """The session's open stores, by resolved domain directory."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    entries: dict[str, _OpenStore] = field(default_factory=dict)


#: Every open entry of the process, by resolved domain directory. A session
#: asking for a domain directory another session already holds gets the SAME
#: entry (store handle, lock and live graph), so the process never holds two
#: live graphs of one domain. Guarded by :data:`_SHARED_LOCK`; lock order is a
#: registry's lock, then this one.
_SHARED_ENTRIES: dict[str, "_OpenStore"] = {}
_SHARED_LOCK = threading.Lock()


def _hold(entry: "_OpenStore", registry: "_GraphStoreRegistry") -> None:
    with _SHARED_LOCK:
        if not any(held is registry for held in entry.holders):
            entry.holders.append(registry)


def _release(entry: "_OpenStore", registry: "_GraphStoreRegistry | None") -> bool:
    """Drop ``registry``'s hold on ``entry``; close it when nobody holds it.

    Returns whether the store was closed. Never raises.
    """
    with _SHARED_LOCK:
        entry.holders[:] = [held for held in entry.holders if held is not registry]
        last = not entry.holders
        if last:
            key = _path_key(entry.domain_dir)
            if _SHARED_ENTRIES.get(key) is entry:
                _SHARED_ENTRIES.pop(key, None)
    if last:
        entry.live = None
        _close_quietly(entry)
    return last


def _all_open_entries() -> list["_OpenStore"]:
    """Every entry the process holds open (a snapshot)."""
    with _SHARED_LOCK:
        return list(_SHARED_ENTRIES.values())


#: Registries of sessions that cannot carry an attribute (a slotted context
#: object such as ``AttackPathResetShell``), by identity. Such a session is
#: short-lived and is closed by its caller; the entry holds it strongly so the
#: id is never reused while the registry lives.
_EXTERNAL_REGISTRIES: dict[int, tuple[object, _GraphStoreRegistry]] = {}


def _registry(shell: object, *, create: bool) -> _GraphStoreRegistry | None:
    registry = getattr(shell, _REGISTRY_ATTR, None)
    if not isinstance(registry, _GraphStoreRegistry):
        held = _EXTERNAL_REGISTRIES.get(id(shell))
        registry = held[1] if held is not None and held[0] is shell else None
    if registry is not None or not create:
        return registry
    with _REGISTRY_GUARD:
        registry = getattr(shell, _REGISTRY_ATTR, None)
        if isinstance(registry, _GraphStoreRegistry):
            return registry
        held = _EXTERNAL_REGISTRIES.get(id(shell))
        if held is not None and held[0] is shell:
            return held[1]
        registry = _GraphStoreRegistry()
        try:
            setattr(shell, _REGISTRY_ATTR, registry)
        except (AttributeError, TypeError):
            _EXTERNAL_REGISTRIES[id(shell)] = (shell, registry)
        try:
            _SESSIONS.add(shell)
        except TypeError:  # an object that cannot be weakly referenced
            _STRONG_SESSIONS[id(shell)] = shell
        return registry


def _workspace_dir(shell: object) -> str:
    return os.path.abspath(resolve_workspace_cwd(shell))


def domain_dir_for(shell: object, domain: str) -> str:
    """``<current workspace>/<domains_dir>/<domain>`` for this shell.

    The current workspace is the execution ``.run_*`` one during a live scan,
    so the store, the export and every sidecar resolve to the same directory
    the rest of the run writes into.
    """
    domains_dir = str(getattr(shell, "domains_dir", "") or "domains")
    return domain_subpath(_workspace_dir(shell), domains_dir, domain)


def graph_store_for(shell: object, domain: str, *, create: bool = True) -> GraphStore | None:
    """The open store of ``domain`` for this session.

    One handle per domain directory, cached on the shell and closed by
    :func:`close_graph_stores`. The directory comes from the shell's current
    workspace (:func:`domain_dir_for`).

    Args:
        shell: The session (anything ``resolve_workspace_cwd`` accepts).
        domain: The domain name, as the workspace's ``domains/`` directory names it.
        create: Create the store when the domain has none. ``False`` is the
            read path: a domain without a store (a 14.0.x workspace, a domain
            not collected yet) returns ``None`` and NOTHING is created on disk.

    Returns:
        The store, or ``None`` when there is none and none may be created.
        A frozen workspace never gets a store created, whatever ``create``
        says, and an existing one opens read-only (writes raise
        ``GraphStoreFrozenError``).

    Raises:
        ValueError: ``domain`` is empty.
        GraphStoreError: The store exists but cannot be opened (another process
            holds it for writing, or its schema major is newer:
            ``GraphStoreVersionError``). Not swallowed: the caller decides.
    """
    domain = str(domain or "").strip()
    if not domain:
        raise ValueError("graph_store_for needs a domain")
    domain_dir = domain_dir_for(shell, domain)
    key = _path_key(domain_dir)
    store_dir = graph_store_dir(domain_dir)
    registry = _registry(shell, create=True)
    assert registry is not None
    with registry.lock:
        frozen = write_blocked(store_dir)
        entry = registry.entries.get(key)
        if entry is not None:
            if not entry.store.read_only or frozen:
                _touch_open(entry)
                return entry.store
            # Opened read-only while the workspace was frozen (a recheck);
            # the freeze is over, so reopen it for writing.
            registry.entries.pop(key, None)
            _release(entry, registry)
        with _SHARED_LOCK:
            shared = _SHARED_ENTRIES.get(key)
        if shared is not None and (not shared.store.read_only or frozen):
            # Another session of this process holds the directory: share its
            # entry (one store handle, one live graph per domain).
            _hold(shared, registry)
            registry.entries[key] = shared
            _touch_open(shared)
            return shared.store
        if not graph_store_exists(domain_dir) and (not create or frozen):
            return None
        store = open_graph_store(domain_dir, domain=domain, read_only=frozen, create=create)
        entry = _OpenStore(
            domain=domain,
            domain_dir=os.path.abspath(domain_dir),
            workspace_key=_path_key(_workspace_dir(shell)),
            store=store,
        )
        if create and not store.read_only:
            try:
                _import_legacy_graph_if_due(shell, domain, entry)
            except BaseException:
                _close_quietly(entry)
                raise
        registry.entries[key] = entry
        entry.holders.append(registry)
        with _SHARED_LOCK:
            _SHARED_ENTRIES[key] = entry
        _touch_open(entry, shell=shell, registry=registry, key=key)
    _evict_beyond_cap(keep=entry)
    return store


#: How many stores the PROCESS keeps open at once, across every session. A
#: store holds a few file handles (database, journal, shared memory, writer
#: lock); a long-lived process (the web worker, a session that walked many
#: workspaces, a test run) must not accumulate them. Past the cap the least
#: recently used store is exported if it moved, then closed; it reopens on the
#: next use, so nothing is lost.
_MAX_OPEN_STORES = max(4, int(os.environ.get("ADSCAN_GRAPH_STORE_MAX_OPEN", "32") or 32))

#: id(entry) -> (entry, weak shell, registry, registry key), least recent first.
_OPEN_ORDER: "OrderedDict[int, tuple[_OpenStore, Any, _GraphStoreRegistry, str]]" = OrderedDict()
_OPEN_ORDER_LOCK = threading.Lock()


class _StrongRef:
    """``weakref.ref``'s call interface over a strong reference."""

    def __init__(self, obj: object) -> None:
        self._obj = obj

    def __call__(self) -> object:
        return self._obj


def _touch_open(
    entry: _OpenStore,
    *,
    shell: object | None = None,
    registry: _GraphStoreRegistry | None = None,
    key: str = "",
) -> None:
    with _OPEN_ORDER_LOCK:
        held = _OPEN_ORDER.get(id(entry))
        if held is not None and held[0] is entry:
            _OPEN_ORDER.move_to_end(id(entry))
            return
        if registry is None:
            return
        shell_ref: Any = None
        if shell is not None:
            try:
                shell_ref = weakref.ref(shell)
            except TypeError:  # a slotted session object: held strongly
                shell_ref = _StrongRef(shell)
        _OPEN_ORDER[id(entry)] = (entry, shell_ref, registry, key)


def _forget_open(entry: _OpenStore) -> None:
    with _OPEN_ORDER_LOCK:
        held = _OPEN_ORDER.get(id(entry))
        if held is not None and held[0] is entry:
            _OPEN_ORDER.pop(id(entry), None)


def _evict_beyond_cap(*, keep: _OpenStore | None) -> None:
    """Close the least recently used stores past :data:`_MAX_OPEN_STORES`.

    A store in use (its lock held: a write, a writer scope) is skipped. One
    whose graph moved since its last export is exported first, when its
    session is still alive. Never raises.
    """
    while True:
        with _OPEN_ORDER_LOCK:
            if len(_OPEN_ORDER) <= _MAX_OPEN_STORES:
                return
            candidates = [held for held in _OPEN_ORDER.values() if held[0] is not keep]
        evicted = False
        for entry, shell_ref, registry, key in candidates:
            if entry.busy or not entry.lock.acquire(blocking=False):
                continue
            if entry.busy:  # taken by this very thread (the lock is re-entrant)
                entry.lock.release()
                continue
            try:
                shell = shell_ref() if shell_ref is not None else None
                if shell is not None and not entry.store.read_only:
                    try:
                        if _path_key(_workspace_dir(shell)) == entry.workspace_key:
                            _export_live_if_current(shell, entry)
                    except Exception as exc:  # noqa: BLE001 - the close still happens
                        telemetry.capture_exception(exc)
                        print_exception(exception=exc)
                with _SHARED_LOCK:
                    holders = list(entry.holders) or [registry]
                for holder in holders:
                    with holder.lock:
                        if holder.entries.get(key) is entry:
                            holder.entries.pop(key, None)
                with _SHARED_LOCK:
                    entry.holders.clear()
                    if _SHARED_ENTRIES.get(key) is entry:
                        _SHARED_ENTRIES.pop(key, None)
                entry.live = None
                _close_quietly(entry)
            finally:
                entry.lock.release()
            _forget_open(entry)
            evicted = True
            break
        if not evicted:
            return


def _open_entry(shell: object, domain: str, *, create: bool) -> _OpenStore | None:
    """The registry entry of ``domain``'s store (opened through
    :func:`graph_store_for`), or ``None`` when it has none."""
    store = graph_store_for(shell, domain, create=create)
    if store is None:
        return None
    registry = _registry(shell, create=False)
    if registry is None:
        return None
    with registry.lock:
        entry = registry.entries.get(_path_key(domain_dir_for(shell, domain)))
    return entry if entry is not None and entry.store is store else None


def _held_entry(shell: object, domain: str) -> _OpenStore | None:
    """The entry already open for ``domain`` in this session, or ``None``.

    Opens nothing, creates nothing: for a question about a store's state
    (:func:`graph_build_stopped`) that must not have side effects.
    """
    domain = str(domain or "").strip()
    if not domain:
        return None
    key = _path_key(domain_dir_for(shell, domain))
    registry = _registry(shell, create=False)
    if registry is not None:
        with registry.lock:
            entry = registry.entries.get(key)
        if entry is not None:
            return entry
    # A stop is a fact about the domain's store, whichever session hit it.
    with _SHARED_LOCK:
        return _SHARED_ENTRIES.get(key)


def _import_legacy_graph_if_due(shell: object, domain: str, entry: _OpenStore) -> None:
    """Import the domain's 14.0.x ``attack_graph.json`` into a new store, once.

    Due when the file exists, the store never exported (a file written by the
    store is its own export, never a legacy graph), no stage other than the
    import ran, and no import completed. The graph is read the way the
    store-less read path reads it, its secrets retained in the sidecar first.
    """
    from adscan_internal.services.graph_build.legacy_import import (  # noqa: PLC0415
        import_legacy_graph,
        legacy_import_complete,
    )

    store = entry.store
    path = os.path.join(entry.domain_dir, ATTACK_GRAPH_FILENAME)
    if not os.path.isfile(path) or store.last_export() is not None:
        return
    if legacy_import_complete(store):
        return
    if any(run.stage != STAGE_LEGACY_IMPORT for run in store.stage_runs()):
        return
    graph = attack_graph_service_module().read_attack_graph_file(
        shell, domain, path, retain_secrets=True
    )
    if not isinstance(graph, dict) or not (graph.get("nodes") or graph.get("edges")):
        return
    written = import_legacy_graph(store, graph)
    print_info_debug(
        "graph runtime: imported the existing attack graph into the store "
        f"(nodes={len(graph.get('nodes') or {})} edges={len(graph.get('edges') or [])} "
        f"overlay_ops={written})"
    )


def _close_quietly(entry: _OpenStore) -> None:
    _forget_open(entry)
    try:
        entry.store.close()
    except Exception as exc:  # noqa: BLE001 - closing one store never stops the others
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _snapshot_entry(entry: Any) -> dict[str, Any]:
    """A private copy of one ``domains_data`` entry, build inputs only.

    The view drops the credential stores and the scan bookkeeping BEFORE the
    copy, so no secret is ever copied and the copy stays small. A value that
    cannot be deep-copied is kept shared (the context documents shallowness).
    """
    view = graph_build_api.domain_entry_build_view(entry)
    try:
        return copy.deepcopy(view)
    except Exception:  # noqa: BLE001 - an exotic value in domains_data
        return {key: _copy_value(value) for key, value in view.items()}


def _copy_value(value: Any) -> Any:
    try:
        return copy.deepcopy(value)
    except Exception:  # noqa: BLE001
        return value


def _domains_data_items(shell: object) -> list[tuple[str, Any]]:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, Mapping):
        return []
    for _attempt in range(3):
        try:
            return [(str(name), entry) for name, entry in list(domains_data.items())]
        except RuntimeError:  # another thread added a domain mid-iteration
            continue
    return []


def _active_run_id(shell: object) -> str:
    try:
        from adscan_internal.services.engagement.coverage_recorder import (  # noqa: PLC0415
            active_run_id,
        )

        return str(active_run_id(shell) or "")
    except Exception as exc:  # noqa: BLE001 - a missing run id only unbinds the graph
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ""


#: Attribute a reader sets when its ``domains_data`` is scratch space rather
#: than a session's recorded facts (the report's own shell, a stamp's stub).
#: Such a reader never supplies the build context: an engine helper caching a
#: value into that scratch map (the domain SID, a coverage record) would
#: otherwise turn it into a context of its own, and the next read through it
#: would rebuild the whole graph from that partial context, replacing the
#: session's live graph and making the export look out of date.
CONTEXT_FREE_READER_ATTR = "graph_reader_without_context"


@dataclass(frozen=True)
class _ContextSource:
    """Where one build's context comes from: ``domains_data`` items and run id."""

    items: tuple[tuple[str, Any], ...]
    run_id: str


def _brings_build_context(shell: object) -> bool:
    """Whether ``shell`` is a session whose ``domains_data`` is a build input."""
    if getattr(shell, CONTEXT_FREE_READER_ATTR, False):
        return False
    return bool(_domains_data_items(shell))


def _persisted_domains_data_items(shell: object) -> list[tuple[str, Any]]:
    """The ``domains_data`` the workspace last saved (``variables.json``).

    For a reader without a context of its own in a process where no session
    built the graph (``deliver`` and the report verbs in a later process): the
    graph it builds is then the one the scan recorded, not one built from an
    empty map. Only the build-input keys of each entry are kept downstream
    (``GraphBuildContext``). Best-effort: anything unreadable is an empty map.
    """
    try:
        path = os.path.join(_workspace_dir(shell), "variables.json")
        if not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except Exception:  # noqa: BLE001 - no persisted context is an empty context
        return []
    domains_data = document.get("domains_data") if isinstance(document, dict) else None
    if not isinstance(domains_data, Mapping):
        return []
    return [
        (str(name), graph_build_api.domain_entry_build_view(entry))
        for name, entry in domains_data.items()
        if isinstance(entry, Mapping)
    ]


def _context_source(shell: object, entry: _OpenStore | None = None) -> _ContextSource:
    """The context a build or a freshness check uses when ``shell`` reads.

    A session brings its own ``domains_data``. A reader without one
    (:data:`CONTEXT_FREE_READER_ATTR`, or no ``domains_data`` at all) takes the
    context the domain's live graph was last built with, so it reads the same
    graph and keeps the same fingerprint as the session; with no live graph in
    the process, the context the workspace saved.
    """
    if _brings_build_context(shell):
        return _ContextSource(tuple(_domains_data_items(shell)), _active_run_id(shell))
    live_context = getattr(entry, "live_context", None) if entry is not None else None
    if isinstance(live_context, graph_build_api.GraphBuildContext):
        return _ContextSource(
            tuple((str(name), item) for name, item in live_context.domains_data.items()),
            str(live_context.coverage_run_id or ""),
        )
    return _ContextSource(tuple(_persisted_domains_data_items(shell)), _active_run_id(shell))


def build_context_for(
    shell: object,
    domain: str,
    *,
    sibling_stores: Mapping[str, GraphStore] | None = None,
    source: _ContextSource | None = None,
) -> graph_build_api.GraphBuildContext:
    """The build context of ``domain`` for this session, as a snapshot.

    * ``domains_data``: a private copy of the session's ``domains_data`` (every
      domain), holding build inputs only (``GraphBuildContext`` drops credential
      stores and scan bookkeeping; they are dropped here before copying). Taken
      now, so a later change of the session map cannot change a build or its
      fingerprint mid-way. A reader without a context of its own gets the one
      :func:`_context_source` resolves for it.
    * ``domain_data``: this domain's entry of that copy (matched exactly, then
      case-insensitively).
    * ``sibling_stores``: the existing stores of the other domains of the
      workspace (never created by this call; one that cannot be opened is
      left out, logged).
    * ``coverage_run_id``: the run writing through the shell, as
      ``save_attack_graph`` stamps it.
    """
    domain = str(domain or "").strip()
    if source is None:
        source = _context_source(shell)
    snapshot: dict[str, dict[str, Any]] = {}
    for name, entry in source.items:
        snapshot[name] = _snapshot_entry(entry)
    own_key = domain if domain in snapshot else next(
        (name for name in snapshot if name.casefold() == domain.casefold()), ""
    )
    own = snapshot.get(own_key, {}) if own_key else {}
    if own_key and own_key != domain:
        snapshot[domain] = snapshot.pop(own_key)
    siblings: dict[str, GraphStore] = (
        dict(sibling_stores)
        if sibling_stores is not None
        else _sibling_stores(shell, domain, source=source)
    )
    return graph_build_api.GraphBuildContext(
        domain=domain,
        domain_data=own,
        domains_data=snapshot,
        sibling_stores=siblings,
        coverage_run_id=source.run_id,
        membership_resolver=_format1_member_resolver(shell, domain),
    )


def _format1_member_resolver(shell: object, domain: str) -> Any:
    """The group-member example resolver of the format-1 writer, only when the
    deprecation-window format is requested (it renders every edge's commands)."""
    if graph_export.requested_format_major() != 1:
        return None
    try:
        from adscan_internal.services.affected_assets_struct import (  # noqa: PLC0415
            safe_member_example_resolver,
        )

        return safe_member_example_resolver(_workspace_dir(shell), domain)
    except Exception as exc:  # noqa: BLE001 - commands keep their fill-in tokens
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _export(
    shell: object,
    domain: str,
    domain_dir: str,
    store: GraphStore,
    *,
    force: bool,
    policy: graph_build_api.ExportPolicy | None,
) -> bool:
    """Export one domain's graph to its ``attack_graph.json`` and sidecars.

    The file is the session's LIVE graph, finalised: never a second build next
    to it. When the live graph is stale it is rebuilt once (the old one dropped
    first) and becomes the live graph. The stream runs from a shallow snapshot
    of the node map and the edge list taken under the store's lock, so a writer
    is never blocked for the length of the write and peak memory stays the
    graph plus one element.

    ``force`` skips the throttle only: an export whose ``(generation,
    fingerprint)`` key equals the last one, with the file in place, is never
    rewritten.
    """
    if store.read_only:
        return False
    path = os.path.join(domain_dir, ATTACK_GRAPH_FILENAME)
    if write_blocked(path):
        return False
    if not force and graph_export.is_throttled(path, policy):
        return False
    entry = _open_entry(shell, domain, create=False)
    if entry is None or entry.store is not store:
        return False
    from adscan_internal.services.graph_runtime_memory import export_bounded  # noqa: PLC0415

    return export_bounded(
        shell, domain, path, lambda: _export_live(shell, entry), store=entry.store
    )


def _export_live(shell: object, entry: _OpenStore) -> bool:
    """Finish ``entry``'s live graph (building it when stale) and stream it."""
    started = time.monotonic()
    try:
        with _using(entry):
            _ensure_live(shell, entry, finalize=True, drop_stale_first=True)
    except Exception as exc:  # noqa: BLE001 - an export never ends a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
    return _stream_live(shell, entry, started=started)


def _export_live_if_current(shell: object, entry: _OpenStore) -> bool:
    """Stream ``entry``'s live graph when it is current for the store, else do
    nothing (the open-store cap closing a store: never a build, never another
    store opened). The store keeps everything; the next export catches up."""
    with _using(entry):
        if entry.live is None or entry.live_generation != entry.store.generation():
            return False
        _finalize_live(entry)
    return _stream_live(shell, entry, started=time.monotonic())


def _stream_live(shell: object, entry: _OpenStore, *, started: float) -> bool:
    """Write ``entry``'s (finalised) live graph to its ``attack_graph.json``.

    The stream runs from a shallow snapshot of the node map and the edge list
    taken under the store's lock, so a writer is never blocked for the length
    of the write; an element a writer changes mid-encode is encoded again.
    """
    store = entry.store
    domain, domain_dir = entry.domain, entry.domain_dir
    path = os.path.join(domain_dir, ATTACK_GRAPH_FILENAME)
    with _using(entry):
        live = entry.live
        if live is None:
            return False
        generation = entry.live_generation or store.generation()
        fingerprint = entry.live_fingerprint
        if graph_export.is_key_current(store, path, generation=generation, fingerprint=fingerprint):
            return False
        snapshot: dict[str, Any] = dict(live)
        nodes = live.get("nodes")
        edges = live.get("edges")
        snapshot["nodes"] = dict(nodes) if isinstance(nodes, dict) else {}
        snapshot["edges"] = list(edges) if isinstance(edges, list) else []
        resolver = getattr(entry.live_context, "membership_resolver", None)

    def _sidecars(graph: Mapping[str, Any]) -> None:
        try:
            export_sidecars(store, graph, domain_dir)
        finally:
            attack_graph_service_module().after_graph_export(shell, domain, path, graph)

    written = graph_export.export_built_graph(
        store,
        snapshot,
        path,
        generation=generation,
        fingerprint=fingerprint,
        started=started,
        member_resolver=resolver,
        after_export=_sidecars,
    )
    if written:
        entry.export_dirty = False
    return written


def export_graph_if_due(
    shell: object,
    domain: str,
    *,
    force: bool = False,
    policy: graph_build_api.ExportPolicy | None = None,
) -> bool:
    """Export ``domain``'s graph when it moved, then its sidecar files.

    The graph is rebuilt from the store and written to
    ``<current workspace>/domains/<domain>/attack_graph.json`` when the key
    ``(store.generation(), context.fingerprint())`` differs from the last
    export's (or the file is gone), the export policy's throttle allows it,
    the store is writable and the workspace is not frozen. After a successful
    write, ``graph_build.sidecars.export_sidecars`` writes ``memberships.json``
    and ``inventory/*.json`` from the same store.

    Args:
        shell: The session.
        domain: The domain to export.
        force: Ignore the throttle (stage end, session end, a reader about to
            open the file). Never rewrites a file that is current.
        policy: The throttle (``ExportPolicy()`` when ``None``).

    Returns:
        Whether a file was written. A domain without a store, a frozen
        workspace or a failed export (logged with its traceback, retried on the
        next call) return ``False``; this never raises for an export problem.
    """
    try:
        store = graph_store_for(shell, domain, create=False)
    except GraphStoreError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
    if store is None:
        return False
    return _export(
        shell, str(domain).strip(), domain_dir_for(shell, domain), store, force=force, policy=policy
    )


def mark_open_exports_incomplete(
    shell: object, block: Mapping[str, Any], *, seen: set[int] | None = None
) -> int:
    """Mark the ``attack_graph.json`` of every store ``shell`` holds open as not
    this run's export (``graph_build.export.mark_export_incomplete``).

    For the last-resort memory sentinel, which runs on its own thread while the
    session's threads may hold any lock: the registry lock is only TRIED, entry
    locks are never taken, and nothing is built or exported. Returns how many
    files were handled. Never raises.
    """
    registry = _registry(shell, create=False)
    if registry is None:
        return 0
    if not registry.lock.acquire(timeout=0.5):
        return 0
    try:
        entries = list(registry.entries.values())
    finally:
        registry.lock.release()
    handled = 0
    for entry in entries:
        if entry.store.read_only:
            continue
        if seen is not None:
            # An entry shared by several sessions is marked once.
            if id(entry) in seen:
                continue
            seen.add(id(entry))
        try:
            graph_export.mark_export_incomplete(
                os.path.join(entry.domain_dir, ATTACK_GRAPH_FILENAME),
                dict(block),
                store=entry.store,
            )
            handled += 1
        except Exception:  # noqa: BLE001 - the process is about to exit; mark what can be marked
            continue
    return handled


#: Prefix of the temporary file a stream copy writes beside ``attack_graph.json``
#: (``graph_build.export``): one an interrupted copy left is never a graph.
_EXPORT_TMP_PREFIX = ".attack_graph-"
_EXPORT_TMP_SUFFIX = ".tmp"


def remove_interrupted_export_copies(domain_dir: str | Path) -> int:
    """Delete the temporary files an interrupted export or mark left in
    ``domain_dir``. Returns how many were removed. Never raises."""
    removed = 0
    try:
        names = os.listdir(domain_dir)
    except OSError:
        return 0
    for name in names:
        if name.startswith(_EXPORT_TMP_PREFIX) and name.endswith(_EXPORT_TMP_SUFFIX):
            try:
                os.unlink(os.path.join(domain_dir, name))
                removed += 1
            except OSError:
                continue
    return removed


def mark_domain_export_not_current(
    shell: object, workspace_dir: str | Path, domain: str, block: Mapping[str, Any]
) -> str:
    """Mark ``domain``'s ``attack_graph.json`` in ``workspace_dir`` as not current.

    The unhurried twin of the memory sentinel's mark: called when a stop the
    sentinel recorded is folded on the next load, where there is no time budget
    (the sentinel's own mark stream-copies the whole file under three seconds
    and usually ran out on a large export). Removes any temporary copy an
    interrupted mark or export left, then marks the file with the stop's stage
    and reason and resets the store's export record, so the next export rewrites
    the file instead of skipping it as current. The store is the session's open
    one when it holds this directory, else opened for the mark and closed.

    Returns ``graph_build.export.mark_export_incomplete``'s outcome, or
    ``"error"``. Never raises.
    """
    domains_dir = str(getattr(shell, "domains_dir", "") or "domains")
    domain_dir = domain_subpath(os.path.abspath(os.fspath(workspace_dir)), domains_dir, domain)
    remove_interrupted_export_copies(domain_dir)
    path = os.path.join(domain_dir, ATTACK_GRAPH_FILENAME)
    store: GraphStore | None = None
    transient = False
    try:
        with _SHARED_LOCK:
            entry = _SHARED_ENTRIES.get(_path_key(domain_dir))
        if entry is not None and not entry.store.read_only:
            store = entry.store
        if store is None and graph_store_exists(domain_dir) and not write_blocked(path):
            store = open_graph_store(domain_dir, domain=domain, create=False)
            transient = True
        return graph_export.mark_export_incomplete(path, dict(block), store=store)
    except Exception as exc:  # noqa: BLE001 - folding a stop never breaks a load
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return "error"
    finally:
        if transient and store is not None:
            try:
                store.close()
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)


def close_graph_stores_under(root: str | Path) -> int:
    """Close every store the PROCESS holds open under ``root``, without an export.

    Call it BEFORE deleting a directory that can contain a store (clearing a
    workspace, deleting a workspace or a domain, trimming a failed run to its
    logs). A store a session opened earlier stays cached; deleting its
    directory under it leaves the handle writing into an unlinked database, so
    everything the run collects afterwards lands nowhere on disk and the
    workspace ends without its ``graph_store`` (F30: a resumed ``ci`` cleared
    the workspace after a reader had opened the store). Every session's hold is
    dropped, so the next ``graph_store_for`` opens (or creates) a fresh store.

    Waits for a write in progress on the store to finish. Never raises.

    Returns:
        How many stores were closed.
    """
    try:
        prefix = _path_key(root)
    except Exception:  # noqa: BLE001 - an unusable path closes nothing
        return 0
    closed = 0
    for entry in _all_open_entries():
        key = _path_key(entry.domain_dir)
        if key != prefix and not key.startswith(prefix.rstrip(os.sep) + os.sep):
            continue
        with entry.lock:
            with _SHARED_LOCK:
                holders = list(entry.holders)
            for holder in holders:
                with holder.lock:
                    if holder.entries.get(key) is entry:
                        holder.entries.pop(key, None)
            with _SHARED_LOCK:
                entry.holders.clear()
                if _SHARED_ENTRIES.get(key) is entry:
                    _SHARED_ENTRIES.pop(key, None)
            entry.live = None
            _close_quietly(entry)
        closed += 1
    if closed:
        print_info_debug(f"graph runtime: closed {closed} store(s) before their directory is removed")
    return closed


def close_graph_stores(shell: object, *, export: bool = True) -> None:
    """Export what is dirty and close every store of the session.

    Wired into ``do_exit`` and the unattended entry points' ``finally``
    (package D), and to be called BEFORE the shell switches workspace: only the
    stores of the shell's current workspace are exported (the session's
    ``domains_data`` describes that workspace and no other); a store left open
    from an earlier workspace is closed without an export. ``export=False``
    closes without exporting (a discarded run).

    Each export skips the throttle and is still a no-op when the file is
    current. Never raises: a failure is logged and the next store is handled.
    """
    registry = _registry(shell, create=False)
    if registry is None:
        return
    if export:
        try:
            current = _path_key(_workspace_dir(shell))
        except Exception as exc:  # noqa: BLE001 - no workspace: close without export
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            current = ""
        with registry.lock:
            entries = list(registry.entries.values())
        for entry in entries:
            if entry.store.read_only:
                continue
            if entry.workspace_key != current:
                print_info_debug(
                    f"graph store of {entry.domain} belongs to an earlier workspace; "
                    "closing it without an export"
                )
                continue
            try:
                _export(
                    shell, entry.domain, entry.domain_dir, entry.store, force=True, policy=None
                )
            except Exception as exc:  # noqa: BLE001 - one domain never blocks the others
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
    with registry.lock:
        entries = list(registry.entries.values())
        registry.entries.clear()
    for entry in entries:
        # Closed only when no other session of the process still holds it.
        _release(entry, registry)
    held = _EXTERNAL_REGISTRIES.get(id(shell))
    if held is not None and held[0] is shell:
        _EXTERNAL_REGISTRIES.pop(id(shell), None)
    if _STRONG_SESSIONS.get(id(shell)) is shell:
        _STRONG_SESSIONS.pop(id(shell), None)


# --------------------------------------------------------------------------- #
# The live graph: the built graph of a store, held for the session
# --------------------------------------------------------------------------- #


def _fast_fingerprint(
    shell: object, domain: str, *, source: _ContextSource | None = None
) -> str:
    """``context.fingerprint()`` of the session as it is now, without the copy.

    The memo of the live graph is checked on every load, so the check must not
    deep-copy ``domains_data``. The context built here shares the session's
    values (it is used for the digest only, never handed to a build).
    """
    if source is None:
        source = _context_source(shell)
    with _pinned_siblings(shell, domain, source=source) as siblings:
        context = graph_build_api.GraphBuildContext(
            domain=str(domain or "").strip(),
            domains_data={name: entry for name, entry in source.items},
            sibling_stores=siblings,
            coverage_run_id=source.run_id,
        )
        return context.fingerprint()


def _sibling_stores(
    shell: object, domain: str, *, source: _ContextSource | None = None
) -> dict[str, GraphStore]:
    siblings: dict[str, GraphStore] = {}
    names = (source or _context_source(shell)).items
    for name, _entry in names:
        if name.casefold() == str(domain or "").strip().casefold():
            continue
        try:
            sibling = graph_store_for(shell, name, create=False)
        except GraphStoreError as exc:
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            continue
        if sibling is not None:
            siblings[name] = sibling
    return siblings


@contextmanager
def _pinned_siblings(
    shell: object, domain: str, *, source: _ContextSource | None = None
) -> Iterator[dict[str, GraphStore]]:
    """The other domains' stores, held open for a build that reads them.

    Each is pinned as it is opened, so the open-store cap never closes a
    sibling a running build still reads (a forest with more domains than the
    cap). Released when the build ends. The domains are those of the context
    the build uses (:func:`_context_source`).
    """
    pinned: list[_OpenStore] = []
    stores: dict[str, GraphStore] = {}
    names = (source or _context_source(shell)).items
    try:
        for name, _entry in names:
            if name.casefold() == str(domain or "").strip().casefold():
                continue
            try:
                entry = _open_entry(shell, name, create=False)
            except GraphStoreError as exc:
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
                continue
            if entry is None:
                continue
            _pin(entry)
            pinned.append(entry)
            stores[name] = entry.store
        yield stores
    finally:
        for entry in pinned:
            _unpin(entry)
        if pinned:
            # The cap could not close a pinned store while the build read it;
            # bring the open set back under it now.
            _evict_beyond_cap(keep=None)


def _ensure_live(
    shell: object, entry: _OpenStore, *, finalize: bool, drop_stale_first: bool = True
) -> Graph:
    """The live graph of ``entry``, built when the store or the context moved.

    Current for ``(store.generation(), context.fingerprint())``. ``finalize``
    runs the post-overlay passes the runtime writes since the build deferred
    (engine follow-ups, classification, the Tier-0-source prune, the AD CS
    display contract), so a reader sees exactly what a rebuild would give. A
    writer passes ``False``: one more op does not need them, and running them
    per write would make a status change cost the graph's size.
    """
    with _using(entry):
        if entry.build_stopped:
            return _stopped_graph(entry)
        generation = entry.store.generation()
        if (
            entry.live is not None
            and entry.live_generation == generation
            and not _brings_build_context(shell)
        ):
            # A reader that brings no context of its own (the report's shell,
            # a scan-end stamp: no ``domains_data``, or one that is scratch
            # space) reads the graph the process already holds for this
            # generation, built with the session's context, instead of building
            # a second one from an empty context (a second graph in memory, and
            # a different one).
            if finalize:
                _finalize_live(entry)
            return entry.live
        # Resolved once, under the entry's lock: the context a reader without
        # one of its own rebuilds with is the live graph's, so a write that
        # moved the generation never changes which context the graph has.
        source = _context_source(shell, entry)
        fingerprint = _fast_fingerprint(shell, entry.domain, source=source)
        if (
            entry.live is not None
            and entry.live_generation == generation
            and entry.live_fingerprint == fingerprint
        ):
            if finalize:
                _finalize_live(entry)
            return entry.live
        if drop_stale_first:
            # The stale graph goes before the new one is built: the process
            # never holds two graphs of one domain (a reader still holding the
            # old dict keeps it alive, nothing else does).
            entry.live = None
            entry.live_index = None
        from adscan_internal.services.graph_runtime_memory import (  # noqa: PLC0415
            build_bounded,
        )

        if _stopped_earlier_in_this_run(shell, entry):
            return _stopped_graph(entry)
        path = os.path.join(entry.domain_dir, ATTACK_GRAPH_FILENAME)
        with _pinned_siblings(shell, entry.domain, source=source) as siblings:
            context = build_context_for(
                shell, entry.domain, sibling_stores=siblings, source=source
            )
            with _engine_writes():
                built = build_bounded(
                    shell,
                    entry.domain,
                    path,
                    lambda: graph_build_api.build_graph(entry.store, context),
                    store=entry.store,
                )
        if built is None:
            entry.build_stopped = True
            entry.stop_token = uuid.uuid4().hex
            entry.live = None
            entry.live_index = None
            return _stopped_graph(entry)
        graph, report = built
        entry.live = graph
        entry.live_generation = report.generation
        entry.live_fingerprint = context.fingerprint()
        entry.live_context = context
        entry.live_index = _primed_live_index(graph)
        _clear_pending(entry)
        return graph


def _stopped_earlier_in_this_run(shell: object, entry: _OpenStore) -> bool:
    """Whether this run already stopped building ``entry``'s graph; marks it so.

    The in-memory flag dies with the entry (the export closes the session's
    store, the report reopens it), so the run's own recorded stop is the
    source: a build that already climbed to the ceiling in THIS run is not
    attempted again. A later run builds normally and clears the stop.
    """
    from adscan_internal.services.graph_availability import (  # noqa: PLC0415
        graph_build_stopped_this_run,
    )

    if not graph_build_stopped_this_run(shell, entry.domain):
        return False
    entry.build_stopped = True
    entry.stop_token = entry.stop_token or uuid.uuid4().hex
    entry.live = None
    entry.live_index = None
    print_info_debug(
        f"graph runtime: the build of {entry.domain} already stopped at the memory "
        "ceiling in this run; not attempted again"
    )
    return True


def _stopped_graph(entry: _OpenStore) -> Graph:
    """The graph a reader gets once the build stopped at the memory ceiling.

    Empty, and never the live graph (so it is never exported over the previous
    file). The stop is declared in the domain's ``resource_coverage`` block, and
    the graph carries :data:`GRAPH_BUILD_STOPPED_FLAG` so a reader that consults
    the availability predicate (``resource_coverage.graph_unavailable_stage``)
    computes nothing from it rather than from a stale or partial graph.
    """
    return {"domain": entry.domain, "nodes": {}, "edges": [], GRAPH_BUILD_STOPPED_FLAG: True}


def _finalize_live(entry: _OpenStore) -> None:
    """Run the post-overlay passes the pending writes deferred (the caller
    holds the entry)."""
    if not entry.pending_post_overlay or entry.live is None:
        return
    with _engine_writes():
        if entry.pending_full:
            graph_build_api.run_post_overlay_passes(entry.live, entry.live_context)
            entry.live_index = _primed_live_index(entry.live)
        else:
            _finish_touched_edges(entry)
    _clear_pending(entry)


def _clear_pending(entry: _OpenStore) -> None:
    entry.pending_post_overlay = False
    entry.pending_full = False
    entry.pending_edges = []


def _followup_sensitive(edge: Mapping[str, Any], op_kind: str) -> bool:
    """Whether the write just applied to ``edge`` can change the engine follow-ups.

    Decided on the edge as the write left it. The follow-up derivation
    (``attack_graph_core.materialize_engine_followup_edges``) reads, from a
    parent edge, its relation, its endpoints, the source node's properties and,
    for the linked-server lateral edge only, its notes; it never reads a status.
    From a follow-up edge it reads one thing: whether a run recorded an outcome
    on it, which decides whether a follow-up that is no longer derived is kept
    as history or dropped. So only two writes can move it:

    * a write that leaves a follow-up step with no recorded outcome (a reset to
      ``discovered``): a follow-up whose parent left the graph is then dropped;
    * a notes write on the linked-server lateral edge (``remote_is_sysadmin``
      and ``xp_cmdshell_enabled`` shape its ``XpCmdshell`` follow-up).

    A status write on any other edge, an access edge included, cannot change
    the derivation: the touched-edge pass is exact for it (locked by the
    live-equals-rebuild tests).
    """
    from adscan_internal.services import attack_graph_core  # noqa: PLC0415

    if attack_graph_core.edge_is_engine_followup(edge):
        return not attack_graph_core.engine_followup_outcome_recorded(edge)
    if op_kind == "set_edge_status":
        return False
    relation = str(edge.get("relation") or "").strip().lower()
    return relation == attack_graph_core._MSSQL_LINKED_KEY  # noqa: SLF001


def _finish_touched_edges(entry: _OpenStore) -> None:
    """The post-overlay passes, restricted to the edges the pending writes touched.

    Exact for those writes (they changed an existing edge's status or notes,
    none the follow-up derivation reads): the edge order, the nodes, the
    follow-ups and the technique-knowledge relations are unchanged, so only
    the touched edges' classification and Tier-0-source verdict, and the AD CS
    display contract (cheap, whole graph), are re-derived. Locked by the
    live-equals-rebuild tests.
    """
    from adscan_internal.services.attack_graph_findings import (  # noqa: PLC0415
        stamp_adcs_edge_display_contract,
    )
    from adscan_internal.services.edge_knowledge import (  # noqa: PLC0415
        build_technique_knowledge,
    )

    ags = attack_graph_service_module()
    graph = entry.live
    assert graph is not None
    seen: set[int] = set()
    touched = [e for e in entry.pending_edges if not (id(e) in seen or seen.add(id(e)))]
    ags.classify_graph_edges(graph, edges=touched)
    pruned = ags._prune_tier0_source_attack_edges(graph, only=touched)  # noqa: SLF001
    ags._flush_tier0_source_attack_edge_skip_summary(graph)  # noqa: SLF001
    context = entry.live_context
    domains_data = context.domains_data_for_passes() if context is not None else {}
    stamp_adcs_edge_display_contract(graph, domains_data, edges=touched)
    if pruned:
        graph["technique_knowledge"] = build_technique_knowledge(graph)


def _primed_live_index(graph: Graph) -> Any:
    """The live graph's edge index, built now: a write never pays a scan."""
    edges = graph.get("edges")
    index = attack_graph_service_module().EdgeUpsertIndex()
    return index.prime(edges) if isinstance(edges, list) else index


def attack_graph_service_module() -> Any:
    from adscan_internal.services import attack_graph_service  # noqa: PLC0415

    return attack_graph_service


def live_graph(
    shell: object, domain: str, *, create: bool = False, finalize: bool = True
) -> Graph | None:
    """The built graph of ``domain`` for this session, or ``None`` without a store.

    ``create=True`` is the write path: the store is created (and a 14.0.x
    graph imported) when the domain has none. A frozen workspace gets ``None``.
    ``finalize=False`` is for a writer resolving endpoints before it records.
    """
    entry = _open_entry(shell, domain, create=create)
    if entry is None:
        return None
    return _ensure_live(shell, entry, finalize=finalize)


def store_generation_token(shell: object, domain: str) -> tuple[Any, ...] | None:
    """``("store", inventory, overlay)`` of ``domain``'s store, or ``None``.

    The epoch the attack-path caches key on when the graph lives in a store
    (the file's mtime no longer moves on a runtime write). Cheap, never raises.

    A build that stopped at the memory ceiling leaves the generation where it
    was, so the token alone would key the empty graph handed out after the stop
    exactly like the full build of the same generation in a later, larger
    session. While the stop holds, the token is
    ``("store-stopped", inventory, overlay, <token of this stop>)``: unique to
    the stop, so nothing keyed on it is ever served to a session that built.
    """
    try:
        entry = _open_entry(shell, domain, create=False)
    except Exception:  # noqa: BLE001 - an unreadable store keys as "no store"
        return None
    if entry is None:
        return None
    generation = entry.store.generation()
    if entry.build_stopped:
        return (
            "store-stopped",
            int(generation.inventory),
            int(generation.overlay),
            entry.stop_token or "stopped",
        )
    return ("store", int(generation.inventory), int(generation.overlay))


def graph_build_stopped(shell: object, domain: str) -> bool:
    """Whether the build of ``domain``'s graph stopped at the memory ceiling in
    this process. Opens and builds nothing; never raises."""
    try:
        entry = _held_entry(shell, domain)
    except Exception:  # noqa: BLE001 - a lookup never raises
        return False
    return bool(entry is not None and entry.build_stopped)


# --------------------------------------------------------------------------- #
# Writes: every runtime change is an overlay op, applied to the live graph
# --------------------------------------------------------------------------- #

#: Set while an op is being applied, so the edge-writing SSOT does not record
#: the write it is performing on the recorder's behalf a second time.
_APPLYING: ContextVar[bool] = ContextVar("graph_runtime_applying", default=False)
#: The recorders open in this thread or task, innermost last.
_RECORDERS: ContextVar[tuple["_Recorder", ...]] = ContextVar(
    "graph_runtime_recorders", default=()
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _engine_writes() -> Iterator[None]:
    """The engine itself is writing the live graph (a build, the post-overlay
    passes, an op being applied): nothing it does is recorded as a new op."""
    token = _APPLYING.set(True)
    try:
        yield
    finally:
        _APPLYING.reset(token)


def _json_safe(value: Any) -> Any:
    """``value`` as the store will hold it (plain JSON types)."""
    return json.loads(json.dumps(value, default=json_default))


def _redacted(shell: object, domain: str, relation: str, notes: Mapping[str, Any]) -> dict[str, Any]:
    """``notes`` with every recovered secret replaced by its credential-store
    reference, the value retained in the secret sidecar first: the semantics
    ``save_attack_graph`` applied to a whole graph, applied to one op. The
    store's own guard is only the backstop."""
    if not notes:
        return {}
    from adscan_core.graph_secret_refs import SECRET_NOTE_KEYS  # noqa: PLC0415

    def _has_secret_key(obj: Any) -> bool:
        if isinstance(obj, Mapping):
            if not SECRET_NOTE_KEYS.isdisjoint(obj.keys()):
                return True
            return any(_has_secret_key(v) for v in obj.values())
        if isinstance(obj, (list, tuple)):
            return any(_has_secret_key(v) for v in obj)
        return False

    if not _has_secret_key(notes):
        return dict(notes)
    from adscan_internal.services.graph_secret_store import (  # noqa: PLC0415
        redact_graph_for_persist,
    )

    holder = {"nodes": {}, "edges": [{"relation": relation, "notes": dict(notes)}]}
    redact_graph_for_persist(shell, domain, holder)
    return dict(holder["edges"][0].get("notes") or {})


def _prepare_op(shell: object, domain: str, op: OverlayOp, *, origin: str, run_id: str) -> OverlayOp:
    """The op as it is stored and applied: secrets out, JSON types, stamped."""
    payload = dict(op.payload or {})
    relation = op.edge.relation if op.edge is not None else ""
    if op.kind in {"upsert_edge", "set_edge_status"}:
        payload = _redacted(shell, domain, relation, payload)
    elif op.kind == "patch_edge":
        notes = payload.get("notes")
        if isinstance(notes, Mapping):
            payload["notes"] = _redacted(shell, domain, relation, notes)
    edge = op.edge
    if edge is not None and edge.identity_notes:
        edge = EdgeRef(
            from_id=edge.from_id,
            to_id=edge.to_id,
            relation=edge.relation,
            identity_notes=_json_safe(dict(edge.identity_notes)),
        )
    return replace(
        op,
        edge=edge,
        payload=_json_safe(payload),
        origin=op.origin or origin,
        run_id=op.run_id or run_id,
        recorded_at=op.recorded_at or _utc_now_iso(),
    )


#: Op kinds that, on an edge the graph already holds, change only its status,
#: notes or stamps (never the edge set, the order or the nodes).
_TOUCH_KINDS = frozenset({"set_edge_status", "patch_edge", "upsert_edge"})


class _Recorder:
    """The writes of one block, applied to the live graph at once and appended
    to the store in ONE commit when the block ends."""

    def __init__(self, shell: object, domain: str, entry: _OpenStore, graph: Graph, origin: str) -> None:
        self.shell = shell
        self.domain = domain
        self.entry = entry
        self.graph = graph
        self.origin = origin
        self.run_id = _active_run_id(shell)
        self.ops: list[OverlayOp] = []

    def apply(self, ops: Iterable[OverlayOp]) -> list[Any]:
        """Prepare, apply to the live graph, and buffer ``ops``; returns outcomes."""
        from adscan_internal.services.graph_build.overlay import apply_op  # noqa: PLC0415

        from adscan_internal.services.graph_build.overlay import find_edge  # noqa: PLC0415

        outcomes = []
        for op in ops:
            prepared = _prepare_op(self.shell, self.domain, op, origin=self.origin, run_id=self.run_id)
            existing = None
            if prepared.edge is not None and prepared.kind in _TOUCH_KINDS:
                existing = find_edge(self.graph, prepared.edge, index=self.entry.live_index)
            with _engine_writes():
                outcomes.append(apply_op(self.graph, prepared, index=self.entry.live_index))
            self.ops.append(prepared)
            if existing is not None and not _followup_sensitive(existing, prepared.kind):
                self.entry.pending_edges.append(existing)
            else:
                self.entry.pending_full = True
        self.entry.pending_post_overlay = True
        return outcomes

    def upsert_edge(
        self,
        *,
        from_id: str,
        to_id: str,
        relation: str,
        edge_type: str,
        status: str,
        notes: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """``attack_graph_service.upsert_edge`` on the recorded graph, as an op.

        Returns the edge as the graph now holds it, or ``{}`` when the graph
        refused it (the same contract as ``upsert_edge``).
        """
        from adscan_internal.services.graph_build.legacy_import import (  # noqa: PLC0415
            identity_notes_for,
        )
        from adscan_internal.services.graph_build.overlay import (  # noqa: PLC0415
            OverlayOutcome,
            find_edge,
        )

        if not from_id or not to_id or not str(relation or "").strip():
            return {}
        ref = EdgeRef(
            from_id=str(from_id),
            to_id=str(to_id),
            relation=str(relation),
            identity_notes=identity_notes_for(str(relation), notes),
        )
        outcome = self.apply(
            [
                OverlayOp(
                    kind="upsert_edge",
                    edge=ref,
                    edge_type=str(edge_type or "runtime"),
                    status=str(status or "discovered"),
                    payload=dict(notes or {}),
                )
            ]
        )[0]
        if outcome in (OverlayOutcome.REFUSED, OverlayOutcome.INVALID):
            return {}
        return find_edge(self.graph, ref, index=self.entry.live_index) or {}

    def upsert_nodes(self, nodes: Iterable[Mapping[str, Any]]) -> dict[str, str]:
        """``attack_graph_service.upsert_nodes`` on the recorded graph, as ops."""
        from adscan_internal.services import attack_graph_service  # noqa: PLC0415

        computed: dict[str, str] = {}
        ops: list[OverlayOp] = []
        for node in nodes:
            if not isinstance(node, Mapping):
                continue
            payload = _json_safe(dict(node))
            computed[attack_graph_service._node_display_name(payload)] = (  # noqa: SLF001
                attack_graph_service._node_id(payload)  # noqa: SLF001
            )
            ops.append(OverlayOp(kind="upsert_node", payload=payload))
        if ops:
            self.apply(ops)
        return computed

    def buffer_applied(self, ops: Iterable[OverlayOp]) -> None:
        """Buffer ops whose effect the caller already made on the live graph."""
        for op in ops:
            self.ops.append(
                _prepare_op(self.shell, self.domain, op, origin=self.origin, run_id=self.run_id)
            )
        self.entry.pending_post_overlay = True
        self.entry.pending_full = True

    def commit(self) -> None:
        if not self.ops:
            return
        entry = self.entry
        before = entry.live_generation
        generation = entry.store.append_overlay(self.ops)
        if (
            before is not None
            and generation.inventory == before.inventory
            and generation.overlay == before.overlay + len(self.ops)
        ):
            entry.live_generation = generation
        else:
            # Another writer moved the store meanwhile: rebuild on the next read.
            entry.live = None
        entry.export_dirty = True
        self.ops = []


def active_recorder(graph: Any) -> "_Recorder | None":
    """The open recorder whose live graph is ``graph`` (``None`` while an op is
    being applied). The edge-writing SSOT asks this, so a write made through
    ``upsert_edge`` / ``upsert_nodes`` on a store-backed graph inside
    :func:`mutate` becomes an overlay op instead of an unrecorded change."""
    if _APPLYING.get():
        return None
    for recorder in reversed(_RECORDERS.get()):
        if recorder.graph is graph:
            return recorder
    return None


@contextmanager
def mutate(shell: object, domain: str, *, origin: str) -> Iterator[Graph | None]:
    """Change ``domain``'s graph through the overlay, in one commit.

    Yields the live graph (the store and a 14.0.x import are created when
    missing). Inside the block, every ``attack_graph_service.upsert_edge`` and
    ``upsert_nodes`` on that graph is recorded as an op and applied at once, so
    later reads in the block see it; the ops are appended in ONE commit when
    the block ends. If the block raises, nothing is appended and the live graph
    is dropped (it holds changes the store does not). Yields ``None`` on a
    frozen workspace: nothing may be written there.

    Re-entrant: a nested block for the same domain joins the outer one.
    Never mutate the yielded dict other than through those two functions (or
    :func:`record_direct_writes` for what was changed in place).
    """
    entry = _open_entry(shell, domain, create=True)
    if entry is None or entry.store.read_only:
        yield None
        return
    with _using(entry):
        for recorder in _RECORDERS.get():
            if recorder.entry is entry:
                yield recorder.graph
                return
        graph = _ensure_live(shell, entry, finalize=False)
        recorder = _Recorder(shell, str(domain).strip(), entry, graph, origin)
        token = _RECORDERS.set(_RECORDERS.get() + (recorder,))
        try:
            yield graph
        except BaseException:
            entry.live = None
            raise
        finally:
            _RECORDERS.reset(token)
        try:
            recorder.commit()
        except BaseException:
            entry.live = None
            raise
    _after_write(shell, str(domain).strip())


@dataclass
class _WriteScope:
    """The open writer scope of one runtime helper (:func:`runtime_writer`)."""

    shell: object
    origin: str
    recorders: dict[int, tuple[_Recorder, Any]] = field(default_factory=dict)
    locked: list[_OpenStore] = field(default_factory=list)


_SCOPES: ContextVar[tuple[_WriteScope, ...]] = ContextVar("graph_runtime_scopes", default=())


def _scope_for(shell: object) -> _WriteScope | None:
    for scope in reversed(_SCOPES.get()):
        if scope.shell is shell:
            return scope
    return None


def scoped_graph(shell: object, domain: str) -> Graph | None:
    """The recorded live graph of ``domain`` inside a :func:`runtime_writer`
    scope, or ``None`` outside one (or on a frozen workspace)."""
    scope = _scope_for(shell)
    if scope is None:
        return None
    entry = _open_entry(shell, domain, create=True)
    if entry is None or entry.store.read_only:
        return None
    held = scope.recorders.get(id(entry))
    if held is not None:
        return held[0].graph
    for recorder in _RECORDERS.get():
        if recorder.entry is entry:
            return recorder.graph
    entry.lock.acquire()
    _pin(entry)
    scope.locked.append(entry)
    graph = _ensure_live(shell, entry, finalize=True)
    recorder = _Recorder(shell, str(domain).strip(), entry, graph, scope.origin)
    token = _RECORDERS.set(_RECORDERS.get() + (recorder,))
    scope.recorders[id(entry)] = (recorder, token)
    return graph


@contextmanager
def write_scope(shell: object, *, origin: str) -> Iterator[None]:
    """Record every graph a runtime helper loads and changes, in one commit per
    domain when it returns.

    Inside the scope ``load_attack_graph`` hands out the recorded live graph
    (creating the store, and importing a 14.0.x graph, when missing), its
    ``upsert_edge`` / ``upsert_nodes`` become overlay ops, and
    ``save_attack_graph`` on it is a no-op (nothing is left to diff). A change
    made in place must be declared with :func:`record_direct_writes`. If the
    helper raises, nothing is appended and the live graphs are dropped.
    """
    if _scope_for(shell) is not None:
        yield
        return
    scope = _WriteScope(shell=shell, origin=origin)
    scope_token = _SCOPES.set(_SCOPES.get() + (scope,))
    ok = False
    try:
        yield
        ok = True
    finally:
        held = list(scope.recorders.values())
        error: BaseException | None = None
        for recorder, _token in held:
            if not ok:
                recorder.entry.live = None
                continue
            try:
                recorder.commit()
            except BaseException as exc:  # noqa: BLE001 - re-raised below
                recorder.entry.live = None
                error = error or exc
        for _recorder, token in reversed(held):
            _RECORDERS.reset(token)
        _SCOPES.reset(scope_token)
        for entry in reversed(scope.locked):
            _unpin(entry)
            entry.lock.release()
        if ok and error is not None:
            raise error
    for recorder, _token in held:
        _after_write(shell, recorder.domain)


def runtime_writer(origin: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: run a runtime graph helper inside :func:`write_scope`.

    The helper's first positional argument (or its ``shell`` keyword) is the
    session. Its signature and return value do not change.
    """

    def decorate(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            shell = kwargs.get("shell", args[0] if args else None)
            if shell is None:
                return func(*args, **kwargs)
            with write_scope(shell, origin=origin):
                return func(*args, **kwargs)

        return wrapper

    return decorate


def _apply_ops(shell: object, domain: str, ops: list[OverlayOp], *, origin: str) -> list[Any] | None:
    with mutate(shell, domain, origin=origin) as graph:
        if graph is None:
            return None
        recorder = active_recorder(graph)
        assert recorder is not None
        return recorder.apply(ops)


def record_direct_writes(
    graph: Any,
    *,
    node_ids: Iterable[str] = (),
    edges: Iterable[Mapping[str, Any]] = (),
    removed_edges: Iterable[Mapping[str, Any]] = (),
) -> bool:
    """Record nodes and edges a caller already changed IN PLACE on a live graph.

    For code that writes a node or an edge dict directly instead of through
    ``upsert_nodes`` / ``upsert_edge`` (a synthesized trust-partner Domain
    node). Each becomes an exact op (the node merged under its id; the edge
    upserted then patched to exactly its status, notes and extra fields), and
    each edge removed from the list becomes a retirement, so a rebuild
    reproduces it. Returns ``False`` when ``graph`` is not being
    recorded (no store: nothing to do, the caller persists as before).
    """
    recorder = active_recorder(graph)
    if recorder is None:
        return False
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    ops: list[OverlayOp] = []
    for node_id in node_ids:
        node = nodes.get(node_id)
        if isinstance(node, dict):
            ops.append(OverlayOp(kind="upsert_node", node_id=str(node_id), payload=dict(node)))
    for edge in edges:
        ops.extend(_exact_edge_ops(edge))
    for edge in removed_edges:
        ref = _edge_identity_ref(edge)
        if ref is not None:
            ops.append(OverlayOp(kind="retire_edge", edge=ref, payload={"reason": "removed"}))
    recorder.buffer_applied(ops)
    if recorder.entry.live_index is not None:
        recorder.entry.live_index.invalidate()
    return True


def record_edge_exactly(graph: Any, edge: Mapping[str, Any]) -> bool:
    """Record ``edge`` on a recorded live graph exactly as given (its status,
    notes and extra top-level fields such as a host-check edge's
    ``source``/``target``/``evidence``), applying it now. ``False`` when
    ``graph`` is not being recorded."""
    recorder = active_recorder(graph)
    if recorder is None:
        return False
    recorder.apply(_exact_edge_ops(edge))
    return True


# --------------------------------------------------------------------------- #
# The legacy save bridge
# --------------------------------------------------------------------------- #

#: ``OverlayOp.origin`` of what ``save_attack_graph`` records for a caller that
#: still mutates a loaded graph and saves it (package J removes it).
LEGACY_SAVE_BRIDGE_ORIGIN = "legacy_save_bridge"

#: Top-level edge fields the build computes: never carried as a stamp.
_COMPUTED_EDGE_FIELDS = frozenset(
    {
        "id", "from", "to", "relation", "status", "notes", "kind", "edge_type",
        "category", "vuln_key", "first_seen", "last_seen", "discovered_at",
    }
)


def _edge_identity_ref(edge: Mapping[str, Any]) -> EdgeRef | None:
    from adscan_internal.services.graph_build.legacy_import import edge_ref_for  # noqa: PLC0415

    return edge_ref_for(edge)


def _exact_edge_ops(edge: Mapping[str, Any]) -> list[OverlayOp]:
    """Ops that make the graph hold exactly ``edge``: an upsert (so the edge
    exists after any rebuild) and an exact patch (status, notes, extra fields)."""
    from adscan_internal.services.graph_build.overlay import (  # noqa: PLC0415
        edge_payload_for_patch,
    )

    ref = _edge_identity_ref(edge)
    if ref is None:
        return []
    notes = edge.get("notes") if isinstance(edge.get("notes"), Mapping) else {}
    status = str(edge.get("status") or "discovered")
    stamps = {k: v for k, v in edge.items() if k not in _COMPUTED_EDGE_FIELDS}
    # The edge keeps its own timestamps: the ops are stamped with them, never
    # with the clock at the time of the save.
    first_seen = str(edge.get("first_seen") or edge.get("discovered_at") or "")
    last_seen = str(edge.get("last_seen") or first_seen)
    for key in ("first_seen", "discovered_at"):
        if edge.get(key):
            stamps[key] = edge[key]
    return [
        OverlayOp(
            kind="upsert_edge",
            edge=ref,
            edge_type=str(edge.get("edge_type") or "runtime"),
            status=status,
            payload=dict(notes),
            recorded_at=first_seen or last_seen,
        ),
        OverlayOp(
            kind="patch_edge",
            edge=ref,
            payload=edge_payload_for_patch(
                notes=dict(notes),
                stamps=stamps,
                status=status,
                replace_notes=True,
                exact_edge_type=True,
                edge_type=edge.get("edge_type"),
            ),
            recorded_at=last_seen,
        ),
    ]


def diff_graph_to_ops(baseline: Mapping[str, Any], graph: Mapping[str, Any]) -> list[OverlayOp]:
    """The overlay ops that turn ``baseline`` into ``graph``.

    Nodes added or changed become exact node upserts; edges added or changed
    become exact edge ops; an edge the caller removed is retired (it leaves the
    graph, as the 14.0.x save removed it). Root fields are the build's, not
    the caller's, and are not carried.
    """
    from adscan_internal.services import attack_graph_service  # noqa: PLC0415

    ops: list[OverlayOp] = []
    base_nodes = baseline.get("nodes") if isinstance(baseline.get("nodes"), Mapping) else {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), Mapping) else {}
    for node_id in sorted(nodes):
        node = nodes[node_id]
        if isinstance(node, Mapping) and base_nodes.get(node_id) != node:
            ops.append(OverlayOp(kind="upsert_node", node_id=str(node_id), payload=dict(node)))

    key_of = attack_graph_service._existing_edge_upsert_key  # noqa: SLF001
    base_edges: dict[Any, Mapping[str, Any]] = {}
    for edge in baseline.get("edges") or ():
        if isinstance(edge, Mapping):
            base_edges.setdefault(key_of(dict(edge)), edge)
    seen: set[Any] = set()
    for edge in graph.get("edges") or ():
        if not isinstance(edge, Mapping):
            continue
        key = key_of(dict(edge))
        if key in seen:
            continue
        seen.add(key)
        if base_edges.get(key) != edge:
            ops.extend(_exact_edge_ops(edge))
    for key, edge in base_edges.items():
        if key not in seen:
            ref = _edge_identity_ref(edge)
            if ref is not None:
                ops.append(
                    OverlayOp(kind="retire_edge", edge=ref, payload={"reason": "removed_by_save"})
                )
    return ops


def record_saved_graph(shell: object, domain: str, graph: Mapping[str, Any], *, caller: str = "") -> int:
    """The legacy save bridge: record what a caller changed in ``graph``.

    ``graph`` is diffed against the graph the store builds now and the
    difference is appended as ops (``origin="legacy_save_bridge"``), then the
    export is written. Correct for any caller; it costs one build, which is
    why the callers move to the facade (package E). Returns ops recorded, or
    -1 on a frozen workspace or when the baseline build stopped at the memory
    ceiling (declared by the boundary; nothing recorded).
    """
    entry = _open_entry(shell, domain, create=True)
    if entry is None or entry.store.read_only:
        return -1
    domain = str(domain).strip()
    with _using(entry):
        if entry.live is not None and entry.live is not graph:
            baseline = _ensure_live(shell, entry, finalize=True)
        else:
            # The caller changed the live graph itself: the baseline is a build,
            # under the same memory boundary as every build (a stop is declared
            # and the domain's graph is then not available, as after
            # ``_ensure_live``; the caller's changes cannot be diffed).
            from adscan_internal.services.graph_runtime_memory import (  # noqa: PLC0415
                build_bounded,
            )

            if entry.build_stopped or _stopped_earlier_in_this_run(shell, entry):
                return -1
            source = _context_source(shell, entry)
            with _pinned_siblings(shell, domain, source=source) as siblings:
                context = build_context_for(
                    shell, domain, sibling_stores=siblings, source=source
                )
                with _engine_writes():
                    built = build_bounded(
                        shell,
                        domain,
                        os.path.join(entry.domain_dir, ATTACK_GRAPH_FILENAME),
                        lambda: graph_build_api.build_graph(entry.store, context),
                        store=entry.store,
                    )
            if built is None:
                entry.build_stopped = True
                entry.stop_token = uuid.uuid4().hex
                entry.live = None
                entry.live_index = None
                return -1
            baseline, report = built
            entry.live = baseline
            entry.live_generation = report.generation
            entry.live_fingerprint = context.fingerprint()
            entry.live_context = context
            entry.live_index = _primed_live_index(baseline)
            _clear_pending(entry)
        if baseline is graph:
            baseline = _ensure_live(shell, entry, finalize=True)
        ops = diff_graph_to_ops(baseline, graph)
        if ops:
            print_info_debug(
                f"graph runtime: legacy save bridge recorded {len(ops)} op(s)"
                + (f" for {caller}" if caller else "")
            )
            recorder = _Recorder(shell, domain, entry, baseline, LEGACY_SAVE_BRIDGE_ORIGIN)
            token = _RECORDERS.set(_RECORDERS.get() + (recorder,))
            try:
                recorder.apply(ops)
            except BaseException:
                entry.live = None
                raise
            finally:
                _RECORDERS.reset(token)
            recorder.commit()
        # 14.0.x processed the saved dict in place (follow-ups, the Tier-0
        # source prune, the technique-knowledge block); a caller may keep using
        # it. The caller's dict becomes the live graph, with the content a
        # rebuild gives, so what it holds is what the store holds.
        if entry.live is baseline:
            finalized = _ensure_live(shell, entry, finalize=True)
            if finalized is baseline and graph is not baseline:
                graph.clear()
                graph.update(baseline)
                entry.live = graph
    if ops:
        _after_write(shell, domain)
    export_graph_if_due(shell, domain, force=True)
    return len(ops)


# --------------------------------------------------------------------------- #
# The facade
# --------------------------------------------------------------------------- #


def _after_write(shell: object, domain: str) -> None:
    """What every committed write is followed by.

    The attack-path caches key on the store generation (or on the graph's
    structure), so nothing is invalidated imperatively here. In an unattended
    run (the web worker) the export follows on its throttle, so the live view
    of a running scan keeps up; interactively it waits for a reader, the end
    of an attack-path execution or the session end.
    """
    try:
        from adscan_core.interaction import is_non_interactive  # noqa: PLC0415

        if is_non_interactive(shell):
            export_graph_if_due(shell, domain)
    except Exception as exc:  # noqa: BLE001 - an export never fails a write
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _accepted(outcomes: list[Any] | None) -> bool:
    if not outcomes:
        return False
    from adscan_internal.services.graph_build.overlay import OverlayOutcome  # noqa: PLC0415

    return all(o in (OverlayOutcome.APPLIED, OverlayOutcome.ORPHANED) for o in outcomes)


def live_sessions() -> tuple[object, ...]:
    """The sessions of this process that hold an open graph store.

    A snapshot (a tuple, taken now): for a reader that must find the session
    owning a workspace without a shell of its own. Callers must not mutate the
    sessions or anything reached through them; to read a graph use
    :func:`live_graph_for_domain_dir` (or ``load_attack_graph`` with the shell).
    """
    strong = [shell for shell in list(_STRONG_SESSIONS.values())]
    return tuple(list(_SESSIONS) + [s for s in strong if s not in _SESSIONS])


def live_graph_for_domain_dir(domain_dir: str | Path) -> Graph | None:
    """The live graph a session of this process holds for ``domain_dir``, when
    it is current for its store; else ``None`` (nothing is built or opened).

    For a reader without a shell (``services/graph_live_reader.py``). The graph
    returned is the session's own object: READ-ONLY. A caller that mutates it
    changes what every reader sees without recording anything; writes go
    through the facade. It may carry writes whose post-overlay passes have not
    run yet (they run on the owner's next ``load_attack_graph``).
    """
    with _SHARED_LOCK:
        entry = _SHARED_ENTRIES.get(_path_key(domain_dir))
    if entry is None or entry.live is None:
        return None
    try:
        if entry.live_generation != entry.store.generation():
            return None
    except GraphStoreError:
        return None
    return entry.live


def close_all_graph_stores() -> None:
    """:func:`close_graph_stores` for every session of the process.

    The unattended entry points (``ci``, ``execute``, ``run``) call it in their
    ``finally``, so a run that ends on an error before ``do_exit`` still leaves
    its graphs exported. Never raises.
    """
    for shell in live_sessions():
        try:
            close_graph_stores(shell)
        except Exception as exc:  # noqa: BLE001 - one session never blocks the others
            telemetry.capture_exception(exc)
            print_exception(exception=exc)


def record_edge_status(
    shell: object,
    domain: str,
    edge: EdgeRef,
    status: str,
    *,
    notes: Mapping[str, Any] | None = None,
    origin: str = "",
) -> bool:
    """Record an attack-step status transition on one edge.

    Creates the edge (``edge_type="runtime"``) when the graph has none, exactly
    as ``update_edge_status_by_labels`` does today. Returns ``False`` when the
    graph refuses the edge (a Tier-0-source edge), so a caller never reports a
    status that was not recorded. The status follows ``upsert_edge``'s rank
    rule (a lower-ranked status never overwrites a higher one).
    """
    op = OverlayOp(
        kind="set_edge_status", edge=edge, status=str(status or ""), payload=dict(notes or {})
    )
    return _accepted(_apply_ops(shell, domain, [op], origin=origin or "record_edge_status"))


def record_runtime_edge(
    shell: object,
    domain: str,
    edge: EdgeRef,
    *,
    edge_type: str,
    status: str = "discovered",
    notes: Mapping[str, Any] | None = None,
    origin: str = "",
) -> bool:
    """Record an edge found at runtime (never by a collector stage).

    Same rules as ``upsert_edge``, the no-downgrade status rank included: a
    runtime record never lowers an executed status. A writer that must set an
    edge to exactly a state (a lower status, replaced notes) follows it with
    :func:`patch_runtime_edge` and ``status=`` / ``replace_notes=True``.
    """
    op = OverlayOp(
        kind="upsert_edge",
        edge=edge,
        edge_type=str(edge_type or "runtime"),
        status=str(status or "discovered"),
        payload=dict(notes or {}),
    )
    return _accepted(_apply_ops(shell, domain, [op], origin=origin or "record_runtime_edge"))


def record_runtime_node(
    shell: object, domain: str, node: Mapping[str, Any], *, origin: str = ""
) -> str:
    """Record a node the inventory does not hold. Returns its graph node id."""
    from adscan_internal.services import attack_graph_service  # noqa: PLC0415

    payload = _json_safe(dict(node))
    node_id = attack_graph_service._node_id(payload)  # noqa: SLF001
    outcomes = _apply_ops(
        shell,
        domain,
        [OverlayOp(kind="upsert_node", payload=payload)],
        origin=origin or "record_runtime_node",
    )
    return node_id if _accepted(outcomes) else ""


def patch_runtime_edge(
    shell: object,
    domain: str,
    edge: EdgeRef,
    *,
    notes: Mapping[str, Any] | None = None,
    stamps: Mapping[str, Any] | None = None,
    origin: str = "",
    status: str | None = None,
    replace_notes: bool = False,
) -> bool:
    """Merge notes or top-level stamps into an edge without touching its status.

    ``status`` sets the status exactly (no rank rule) and ``replace_notes``
    replaces the notes instead of merging: the exact form, for a writer that
    must put an edge back to a state (the edge must exist; nothing is created).
    """
    from adscan_internal.services.graph_build.overlay import (  # noqa: PLC0415
        OverlayOutcome,
        edge_payload_for_patch,
    )

    op = OverlayOp(
        kind="patch_edge",
        edge=edge,
        payload=edge_payload_for_patch(
            notes=notes, stamps=stamps, status=status, replace_notes=replace_notes
        ),
    )
    outcomes = _apply_ops(shell, domain, [op], origin=origin or "patch_runtime_edge")
    return bool(outcomes) and outcomes[0] is OverlayOutcome.APPLIED


def retire_runtime_edge(
    shell: object, domain: str, edge: EdgeRef, *, reason: str, origin: str = ""
) -> bool:
    """Retire an edge that no longer holds (a reverted change, a dismissed
    candidate). It leaves the graph, and therefore every reader; who retired it,
    when and why stays in the store's op log. Returns whether it was present."""
    from adscan_internal.services.graph_build.overlay import OverlayOutcome  # noqa: PLC0415

    op = OverlayOp(kind="retire_edge", edge=edge, payload={"reason": str(reason or "")})
    outcomes = _apply_ops(shell, domain, [op], origin=origin or "retire_runtime_edge")
    return bool(outcomes) and outcomes[0] is OverlayOutcome.APPLIED


def reset_edge_statuses(
    shell: object, domain: str, *, selector: Mapping[str, Any] | None = None, origin: str = ""
) -> int:
    """Bulk reset of executed statuses (``attack_path_reset``, the execution
    support refresh at workspace load). Returns how many edges changed status."""
    from adscan_internal.services.graph_build.overlay import (  # noqa: PLC0415
        reset_statuses_selector,
    )

    with mutate(shell, domain, origin=origin or "reset_edge_statuses") as graph:
        if graph is None:
            return 0
        before = {
            id(edge): str(edge.get("status") or "")
            for edge in graph.get("edges") or ()
            if isinstance(edge, dict)
        }
        recorder = active_recorder(graph)
        assert recorder is not None
        recorder.apply(
            [
                OverlayOp(
                    kind="reset_statuses",
                    payload=dict(selector) if selector is not None else reset_statuses_selector(),
                )
            ]
        )
        return sum(
            1
            for edge in graph.get("edges") or ()
            if isinstance(edge, dict)
            and id(edge) in before
            and before[id(edge)] != str(edge.get("status") or "")
        )


def record_overlay_ops(shell: object, domain: str, ops: Iterable[OverlayOp]) -> int:
    """Append several operations in ONE commit (a builder that adds a node and
    its edges together). Returns how many were applied."""
    from adscan_internal.services.graph_build.overlay import OverlayOutcome  # noqa: PLC0415

    outcomes = _apply_ops(shell, domain, list(ops), origin="record_overlay_ops") or []
    return sum(1 for outcome in outcomes if outcome is OverlayOutcome.APPLIED)


def ensure_export_fresh(shell: object, domain: str) -> str:
    """Make ``attack_graph.json`` reflect the store now and return its path.

    For the readers that open the FILE (a report build, ``deliver``, a handoff
    to another process). In-process readers use ``load_attack_graph`` and never
    need it. A domain without a store returns the path of the file it has.
    """
    export_graph_if_due(shell, domain, force=True)
    return os.path.join(domain_dir_for(shell, domain), ATTACK_GRAPH_FILENAME)


__all__ = (
    "ATTACK_GRAPH_FILENAME",
    "LEGACY_SAVE_BRIDGE_ORIGIN",
    "active_recorder",
    "build_context_for",
    "close_all_graph_stores",
    "close_graph_stores_under",
    "close_graph_stores",
    "diff_graph_to_ops",
    "domain_dir_for",
    "ensure_export_fresh",
    "export_graph_if_due",
    "graph_store_for",
    "live_graph",
    "live_graph_for_domain_dir",
    "live_sessions",
    "mutate",
    "patch_runtime_edge",
    "record_direct_writes",
    "record_edge_exactly",
    "record_edge_status",
    "record_overlay_ops",
    "record_runtime_edge",
    "record_runtime_node",
    "record_saved_graph",
    "runtime_writer",
    "scoped_graph",
    "write_scope",
    "reset_edge_statuses",
    "retire_runtime_edge",
    "graph_build_stopped",
    "store_generation_token",
)
