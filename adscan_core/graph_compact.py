"""Compact in-memory residency for the attack graph, and its streaming loader.

Spec: ``docs/superpowers/specs/2026-11-12-inventory-first-graph-persistence.md``
section 15.3. Stdlib only, so the web backend imports it as it is.

The graph stays what every reader expects: a root ``dict`` with a ``nodes``
dict and an ``edges`` list of real ``dict`` objects. About 207 call sites test
``isinstance(edge, dict)``, so a view type would be skipped by them without an
error; nothing here changes a type a reader sees. What changes is how the
objects are built:

* **Key-sharing dicts.** Every edge (and every top-level node dict) is the
  instance dictionary of a small private class. CPython then stores the key
  table once for all of them (PEP 412) and each edge holds only its values.
  ``type(edge) is dict`` stays true. If an interpreter stopped sharing keys the
  cost would be memory, never behaviour.
* **Interned strings.** ``json`` creates a new string per occurrence when a
  file is parsed line by line. The loader routes keys and short values through
  a memo that lives for one load only (never ``sys.intern``, which would keep
  every node id of every workspace alive in a long-running backend).
* **Shared notes** (behind one switch, :data:`SHARED_NOTES_ENV_VAR`).
  Identical ``notes`` objects whose values are all scalars become one
  :class:`SharedNotes` object. It is a ``dict`` subclass that raises
  :class:`SharedNotesMutationError` on any in-place mutation, so a writer that
  mutates instead of replacing (``edge["notes"] = {**edge["notes"], ...}``)
  fails in the test suite instead of changing thousands of edges at once. Only
  scalar-valued notes are shared: a nested list or dict could be mutated
  through the shared object without passing through any method this class
  guards.
* **A streaming loader.** The format-2 export (``graph_build/export.py``)
  writes one node and one edge per line with compact separators. The loader
  reads that layout line by line and never holds the file's text. Any other
  layout (the 14.0.x ``indent=4`` file, a compact one-line file) falls back to
  ``json.load`` followed by compaction: the old peak, once, then the new
  residency. Every reader takes a path or an open binary file
  (:data:`GraphSource`). A handle is read from its start and left open, so a
  caller can run several passes over ONE open file (the web ingests edges,
  then nodes) and an atomic replace of the export in between cannot pair the
  nodes of one document with the edges of another.

Equality is exact: :func:`load_graph_file` returns a graph that is ``==`` to
``json.load`` of the same file, with the same key order at every level.
"""

from __future__ import annotations

import json
import os
import weakref
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from json.decoder import scanstring as _scanstring
from typing import Any, BinaryIO, Union

__all__ = (
    "SHARED_NOTES_ENV_VAR",
    "GraphSource",
    "GraphFileFormatError",
    "SharedNotes",
    "SharedNotesMutationError",
    "compact_edge",
    "compact_graph",
    "compact_node",
    "count_graph_file",
    "is_compact",
    "is_line_layout",
    "iter_graph_edges",
    "iter_graph_file",
    "iter_graph_nodes",
    "load_graph_file",
    "make_edge",
    "share_notes",
    "shared_notes_enabled",
)

#: ``1`` shares identical scalar ``notes`` objects, ``0`` keeps one per edge.
SHARED_NOTES_ENV_VAR = "ADSCAN_GRAPH_SHARED_NOTES"

#: Value of the switch when the environment does not set it. ON for 15.0.0
#: (decided 2026-11-13): with it on, every writer replaces an edge's notes
#: instead of mutating in place (locked by the test-session guard), the
#: affected unit set, the engine snapshot (9) and the attack-path digests on
#: Goad-example, Forest and Scale-Exchange (workers 0 and -1) are all clean, and
#: ON vs OFF is byte-identical across those 30 combinations. See the module
#: docstring and the R1 handoff for the evidence.
_SHARED_NOTES_DEFAULT = True

#: String values longer than this are kept as parsed (they are almost always
#: unique: descriptions, certificates). Shorter ones go through the load memo.
_INTERN_MAX_CHARS = 160

#: Edge fields never routed through the memo: unique per edge, so interning
#: them only grows the memo.
_EDGE_UNIQUE_FIELDS = frozenset({"id"})

_SCALAR_TYPES = (str, int, float, bool, type(None))


# --------------------------------------------------------------------------
# Key-sharing containers
# --------------------------------------------------------------------------


class _EdgeSlot:
    """Owner of the shared key table for edge dicts. Instances never escape."""


class _NodeSlot:
    """Owner of the shared key table for top-level node dicts."""


#: The keys every edge and node carries, seeded into each class's shared key
#: table at import. CPython builds that table from the FIRST instance of the
#: process and caps it (30 keys): when the first edge a process meets is an
#: unusual one (a 14.0.x file, a malformed record) its keys fill the table and
#: every canonical edge after it is a plain dict, silently losing the memory
#: this module exists to save, for the rest of the process. Seeded first, the
#: canonical keys always share, in any insertion order (build order or a file's
#: sorted order); an unusual key only costs the dict that carries it.
_SEED_EDGE_KEYS = (
    "id", "from", "to", "relation", "kind", "edge_type", "category", "vuln_key",
    "status", "notes", "discovered_at", "first_seen", "last_seen",
)
_SEED_NODE_KEYS = (
    "id", "kind", "label", "objectId", "properties", "highvalue", "isTierZero",
    "is_high_value", "compromise_class", "system_tags", "target_terminal_class",
    "tier0_inherited",
)


def _seed_shared_keys(owner: type, keys: tuple[str, ...]) -> None:
    seed = owner().__dict__
    for key in keys:
        seed[key] = None


_seed_shared_keys(_EdgeSlot, _SEED_EDGE_KEYS)
_seed_shared_keys(_NodeSlot, _SEED_NODE_KEYS)


def _new_edge_dict() -> dict[str, Any]:
    return _EdgeSlot().__dict__


def _new_node_dict() -> dict[str, Any]:
    return _NodeSlot().__dict__


def is_compact(obj: Any) -> bool:
    """Whether ``obj`` is a key-sharing dict built here (a diagnostic aid).

    A key-sharing dict and a plain one are indistinguishable to readers; this
    compares their size, which is all that differs.
    """
    if type(obj) is not dict or not obj:
        return False
    import sys  # noqa: PLC0415 - diagnostic only

    return sys.getsizeof(obj) < sys.getsizeof(dict(obj))


# --------------------------------------------------------------------------
# Shared notes
# --------------------------------------------------------------------------


class SharedNotesMutationError(TypeError):
    """An in-place mutation of a shared ``notes`` object.

    The object is referenced by every edge with identical notes. Replace the
    edge's notes instead: ``edge["notes"] = {**edge["notes"], key: value}``.
    """


def _refuse(self: SharedNotes, *_args: Any, **_kwargs: Any) -> Any:
    raise SharedNotesMutationError(
        "edge notes are shared between edges and cannot be changed in place; "
        'replace them: edge["notes"] = {**edge["notes"], key: value}'
    )


class SharedNotes(dict):
    """A read-only ``dict`` shared by every edge whose ``notes`` are identical.

    Reading works exactly as on a ``dict`` (``get``, ``in``, iteration,
    ``{**notes}``, ``dict(notes)``, ``json.dumps``). ``copy()``, ``|``,
    ``copy.copy``, ``copy.deepcopy`` and pickling all produce a plain,
    writable ``dict``. Every in-place mutation raises
    :class:`SharedNotesMutationError`.
    """

    __slots__ = ("__weakref__",)

    __setitem__ = _refuse
    __delitem__ = _refuse
    __ior__ = _refuse
    clear = _refuse
    pop = _refuse
    popitem = _refuse
    setdefault = _refuse
    update = _refuse

    def __copy__(self) -> dict[str, Any]:
        return dict(self)

    def __deepcopy__(self, memo: dict[int, Any]) -> dict[str, Any]:
        # Values are scalars by construction, so a shallow copy is deep.
        return dict(self)

    def __reduce__(self) -> tuple[Any, tuple[dict[str, Any]]]:
        return (dict, (dict(self),))


#: Canonical shared notes, keyed by their typed items. Weak values: an entry
#: disappears with the last edge that references it.
_SHARED_NOTES: weakref.WeakValueDictionary[tuple[Any, ...], SharedNotes] = (
    weakref.WeakValueDictionary()
)


def shared_notes_enabled() -> bool:
    """The :data:`SHARED_NOTES_ENV_VAR` switch (default ``_SHARED_NOTES_DEFAULT``)."""
    raw = os.environ.get(SHARED_NOTES_ENV_VAR, "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return _SHARED_NOTES_DEFAULT


def _notes_key(notes: Mapping[str, Any]) -> tuple[Any, ...] | None:
    """Typed, order-preserving identity of scalar-only notes, else ``None``.

    The value's type is part of the key so ``True``, ``1`` and ``1.0`` never
    collapse, and floats key on ``repr`` so ``-0.0`` stays apart from ``0.0``.
    Order is part of the key so a shared object never reorders an edge's notes.
    """
    parts: list[Any] = []
    for key, value in notes.items():
        if type(key) is not str:
            return None
        value_type = type(value)
        if value_type is float:
            parts.append((key, float, repr(value)))
        elif value_type in (str, int, bool) or value is None:
            parts.append((key, value_type, value))
        else:
            return None
    return tuple(parts)


def share_notes(
    notes: Any,
    *,
    enabled: bool | None = None,
    intern: Callable[[str], str] | None = None,
) -> Any:
    """The shared object for ``notes``, or ``notes`` itself when not shareable.

    Shareable means: a ``dict`` (or a :class:`SharedNotes`) with string keys
    and only scalar values. Anything else is returned unchanged, as is every
    value while the switch is off.

    Args:
        notes: An edge's ``notes`` value.
        enabled: Overrides the switch for this call (the loader reads it once).
        intern: Applied to the keys and string values of a NEW shared object.
    """
    if type(notes) is SharedNotes:
        return notes
    if type(notes) is not dict:
        return notes
    if not (shared_notes_enabled() if enabled is None else enabled):
        return notes
    key = _notes_key(notes)
    if key is None:
        return notes
    found = _SHARED_NOTES.get(key)
    if found is not None:
        return found
    shared = SharedNotes()
    if intern is None:
        dict.update(shared, notes)
    else:
        for name, value in notes.items():
            dict.__setitem__(
                shared,
                intern(name),
                intern(value) if type(value) is str and len(value) <= _INTERN_MAX_CHARS else value,
            )
    return _SHARED_NOTES.setdefault(key, shared)


# --------------------------------------------------------------------------
# Factories and compaction
# --------------------------------------------------------------------------

_sys_intern: Callable[[str], str]
try:  # stdlib, always present; kept local for speed
    from sys import intern as _sys_intern
except ImportError:  # pragma: no cover
    def _sys_intern(value: str) -> str:
        return value


def _vocab(value: Any) -> Any:
    """Intern a low-cardinality vocabulary value (relation, kind, status, ...)."""
    return _sys_intern(value) if type(value) is str else value


def make_edge(
    *,
    id: str,  # noqa: A002 - the edge's field name
    from_: str,
    to: str,
    relation: str,
    kind: str,
    edge_type: str,
    category: Any,
    vuln_key: Any,
    status: str,
    notes: Any,
    discovered_at: str,
    first_seen: str,
    last_seen: str,
    **extra: Any,
) -> dict[str, Any]:
    """A new edge as a key-sharing ``dict``, with ``upsert_edge``'s key order.

    The result is ``==`` to the literal ``upsert_edge`` builds today
    (``{"id": ..., "from": ..., ..., "last_seen": ...}``) and has the same key
    order. ``from_`` is the ``"from"`` field. Vocabulary fields (relation,
    kind, edge type, category, vulnerability key, status) are interned; the
    endpoints and timestamps are stored as given. ``notes`` goes through
    :func:`share_notes`. ``extra`` keys are appended in call order.
    """
    edge = _new_edge_dict()
    edge["id"] = id
    edge["from"] = from_
    edge["to"] = to
    edge["relation"] = _vocab(relation)
    edge["kind"] = _vocab(kind)
    edge["edge_type"] = _vocab(edge_type)
    edge["category"] = _vocab(category)
    edge["vuln_key"] = _vocab(vuln_key)
    edge["status"] = _vocab(status)
    edge["notes"] = share_notes(notes)
    edge["discovered_at"] = discovered_at
    edge["first_seen"] = first_seen
    edge["last_seen"] = last_seen
    for key, value in extra.items():
        edge[key] = value
    return edge


class _Memo:
    """One load's string memo: keys always, short string values on request."""

    __slots__ = ("_table",)

    def __init__(self) -> None:
        self._table: dict[str, str] = {}

    def key(self, value: str) -> str:
        return self._table.setdefault(value, value)

    def value(self, value: Any) -> Any:
        if type(value) is str and len(value) <= _INTERN_MAX_CHARS:
            return self._table.setdefault(value, value)
        return value


def _compact_value(value: Any, memo: _Memo) -> Any:
    """A nested value with its dict keys and short strings interned.

    Plain ``dict``/``list`` in, plain ``dict``/``list`` out (same order).
    """
    value_type = type(value)
    if value_type is str:
        return memo.value(value)
    if value_type is dict:
        return {memo.key(k) if type(k) is str else k: _compact_value(v, memo) for k, v in value.items()}
    if value_type is list:
        return [_compact_value(item, memo) for item in value]
    return value


def _compact_notes(notes: Any, memo: _Memo, shared: bool) -> Any:
    if type(notes) is SharedNotes:
        return notes
    if shared and type(notes) is dict:
        result = share_notes(notes, enabled=True, intern=memo.value)
        if result is not notes:
            return result
    return _compact_value(notes, memo)


def compact_edge(
    edge: Any, memo: _Memo | None = None, *, shared_notes: bool | None = None
) -> Any:
    """``edge`` rebuilt as a key-sharing ``dict``, same keys, values and order.

    A non-dict is returned unchanged (``json.load`` would keep it, so does the
    loader). Endpoints, timestamps and vocabulary go through ``memo`` (a fresh
    one when omitted); ``notes`` through :func:`share_notes`.
    """
    if type(edge) is not dict:
        return edge
    if memo is None:
        memo = _Memo()
    shared = shared_notes_enabled() if shared_notes is None else shared_notes
    out = _new_edge_dict()
    for key, value in edge.items():
        name = memo.key(key) if type(key) is str else key
        if name == "notes":
            out[name] = _compact_notes(value, memo, shared)
        elif name in _EDGE_UNIQUE_FIELDS:
            out[name] = value
        else:
            out[name] = _compact_value(value, memo)
    return out


def compact_node(node: Any, memo: _Memo | None = None) -> Any:
    """``node`` rebuilt as a key-sharing ``dict``; nested values interned."""
    if type(node) is not dict:
        return node
    if memo is None:
        memo = _Memo()
    out = _new_node_dict()
    for key, value in node.items():
        out[memo.key(key) if type(key) is str else key] = _compact_value(value, memo)
    return out


def compact_graph(
    graph: dict[str, Any], *, shared_notes: bool | None = None
) -> dict[str, Any]:
    """Compact ``graph`` in place and return it.

    Each edge and node is replaced one at a time, so the replaced original is
    released as the next is built: the peak is the graph plus one element.
    Node ids are routed through the same memo as the edge endpoints, so an id
    and every ``from``/``to`` naming it are one string.
    """
    memo = _Memo()
    shared = shared_notes_enabled() if shared_notes is None else shared_notes
    edges = graph.get("edges")
    if isinstance(edges, list):
        for index, edge in enumerate(edges):
            edges[index] = compact_edge(edge, memo, shared_notes=shared)
    nodes = graph.get("nodes")
    if type(nodes) is dict:
        for node_id in list(nodes):
            value = nodes.pop(node_id)
            nodes[memo.key(node_id) if type(node_id) is str else node_id] = compact_node(value, memo)
    return graph


# --------------------------------------------------------------------------
# Streaming the format-2 export
# --------------------------------------------------------------------------


class GraphFileFormatError(ValueError):
    """The file stopped following the line layout after it was detected.

    :func:`load_graph_file` recovers by reading the file whole; the iterators
    cannot (they already yielded), so they raise it.
    """


_ROOT = "root"
_EDGE = "edge"
_NODE = "node"
_BEGIN = "begin"  # internal: a multi-line root value starts (list or dict)

_decode_value = json.JSONDecoder().decode


def _split_entry(line: str) -> tuple[str, str]:
    """``"key":rest`` -> ``(key, rest)``; compact separator only."""
    if not line.startswith('"'):
        raise GraphFileFormatError("expected a key")
    try:
        key, end = _scanstring(line, 1)
    except ValueError as exc:
        raise GraphFileFormatError("unreadable key") from exc
    if line[end : end + 1] != ":":
        raise GraphFileFormatError("expected ':' after a key")
    rest = line[end + 1 :]
    if not rest or rest[0].isspace():
        raise GraphFileFormatError("not the compact layout")
    return key, rest


def _strip_comma(text: str) -> tuple[str, bool]:
    if text.endswith(","):
        return text[:-1], True
    return text, False


def _parse(text: str) -> Any:
    try:
        return _decode_value(text)
    except ValueError as exc:
        raise GraphFileFormatError("unreadable value") from exc


def _is_line_layout(handle: BinaryIO) -> bool:
    """Whether ``handle`` starts like the format-2 line layout.

    Line 1 is exactly ``{`` and line 2 is a root entry with the compact
    separator: ``"key":`` followed by a non-space. An ``indent`` file (14.0.x
    wrote ``indent=4``; ``indent=0`` writes ``": "``) or a one-line file does
    not match.
    """
    with _rewound(handle):
        first = handle.readline()
        if first.rstrip(b"\r\n") != b"{":
            return False
        second = handle.readline().rstrip(b"\r\n")
    if not second:
        return False
    try:
        line = second.decode("utf-8")
        _split_entry(line)
    except (UnicodeDecodeError, GraphFileFormatError):
        return False
    return True


def is_line_layout(handle: BinaryIO) -> bool:
    """Whether an open binary file starts like the format-2 line layout.

    The check the streaming readers run (line 1 is exactly ``{``, line 2 a
    compact root entry); the handle's position is restored.
    """
    return _is_line_layout(handle)


def _scan_lines(
    handle: BinaryIO, *, want_edges: bool, want_nodes: bool, stop_after_edges: bool
) -> Iterator[tuple[str, Any, Any]]:
    """Events of a line-layout handle, read from its start. Raises :class:`GraphFileFormatError`.

    Events: ``(root, key, value)`` for a one-line root value, ``(begin, key,
    "list"|"dict")`` when a multi-line root value opens, then ``(edge, index,
    element)`` for each element of a multi-line list and ``(node, key, value)``
    for each entry of a multi-line dict. Elements of ``edges`` are not parsed
    when ``want_edges`` is false; entries of ``nodes`` not when ``want_nodes``
    is false.
    """
    handle.seek(0)
    lines = iter(handle)

    def _next() -> str:
        raw = next(lines, None)
        if raw is None:
            raise GraphFileFormatError("unexpected end of file")
        if raw.endswith(b"\n"):
            raw = raw[:-1]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
        else:
            raise GraphFileFormatError("unterminated line")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GraphFileFormatError("not UTF-8") from exc

    if _next() != "{":
        raise GraphFileFormatError("expected '{'")
    more = True
    while True:
        line = _next()
        if line == "}":
            break
        if not more:
            raise GraphFileFormatError("missing ',' between root keys")
        key, rest = _split_entry(line)
        if rest in ("[", "{"):
            is_list = rest == "["
            yield (_BEGIN, key, "list" if is_list else "dict")
            parse = (want_edges if key == "edges" else want_nodes if key == "nodes" else True)
            close = "]" if is_list else "}"
            index = 0
            expect_more = True
            while True:
                item = _next()
                if item == close or item == close + ",":
                    if index and expect_more:
                        raise GraphFileFormatError("trailing ',' before the close")
                    if index == 0:
                        raise GraphFileFormatError("empty multi-line value")
                    more = item.endswith(",")
                    break
                if not expect_more:
                    raise GraphFileFormatError("missing ',' between elements")
                body, expect_more = _strip_comma(item)
                if is_list:
                    yield (_EDGE, index, _parse(body) if parse else None)
                else:
                    entry_key, entry_value = _split_entry(body)
                    yield (_NODE, entry_key, _parse(entry_value) if parse else None)
                index += 1
            if stop_after_edges and key == "edges":
                return
        else:
            body, more = _strip_comma(rest)
            yield (_ROOT, key, _parse(body))
    if more:
        raise GraphFileFormatError("trailing ',' before the end")
    for raw in lines:
        if raw.strip():
            raise GraphFileFormatError("content after the document")


#: Peak memory of a whole-document load, as a multiple of the file size
#: (measured: about 2.8 for a 14.0.x ``attack_graph.json``: the bytes, the
#: decoded text and the objects are held together). Rounded up.
WHOLE_LOAD_PEAK_FACTOR = 3


def _load_whole(handle: BinaryIO) -> Any:
    """``json.load`` of the whole document, as a text-mode ``json.load`` reads it.

    One long C call: no memory guard and no sentinel can run while it does. So
    before reading, the guard is asked whether ``WHOLE_LOAD_PEAK_FACTOR`` times
    the file size fits under its line; when it does not, the load is refused
    with :class:`~adscan_core.memory_guard.MemoryCeilingReached` (the enclosing
    stage's, else ``graph_build``) and nothing is read. The stage boundary that
    catches it declares the stop.
    """
    _refuse_a_load_that_does_not_fit(handle)
    handle.seek(0)
    return json.loads(handle.read().decode("utf-8"))


def _refuse_a_load_that_does_not_fit(handle: BinaryIO) -> None:
    from adscan_core.memory_guard import (  # noqa: PLC0415
        MemoryCeilingReached,
        MemoryGuard,
        current_guard,
    )

    try:
        size = os.fstat(handle.fileno()).st_size
    except (AttributeError, OSError, ValueError):
        try:
            position = handle.tell()
            size = handle.seek(0, os.SEEK_END)
            handle.seek(position)
        except (OSError, ValueError):
            return
    guard = current_guard()
    if guard is None:
        guard = MemoryGuard("graph_build")
    if guard.fits(int(size) * WHOLE_LOAD_PEAK_FACTOR):
        return
    raise MemoryCeilingReached(
        stage=guard.stage, units_done=guard.units_done, reading=guard.sample()
    )


@contextmanager
def _rewound(handle: BinaryIO) -> Iterator[BinaryIO]:
    """Read from the start, then put the position back to the start."""
    handle.seek(0)
    try:
        yield handle
    finally:
        handle.seek(0)


GraphSource = Union[str, "os.PathLike[str]", BinaryIO]


@contextmanager
def _source(source: GraphSource) -> Iterator[BinaryIO]:
    """A binary handle on ``source``: a path is opened (and closed after);
    an open binary file is used as it is, read from its start, and left open.

    One handle per call: a whole call reads ONE file even if the export is
    atomically replaced meanwhile, and a caller that runs several passes on
    the same open handle (seeking back each time) keeps reading the document
    it opened.
    """
    if hasattr(source, "read"):
        handle = source  # type: ignore[assignment]
        if not hasattr(handle, "seek"):
            raise TypeError("a graph file handle must be seekable")
        handle.seek(0)
        if not isinstance(handle.read(0), bytes):
            raise TypeError("a graph file handle must be opened in binary mode ('rb')")
        yield handle  # type: ignore[misc]
        return
    with open(source, "rb") as opened:  # type: ignore[arg-type]
        yield opened


def iter_graph_file(
    path: GraphSource, *, compact: bool = False
) -> Iterator[tuple[str, Any, Any]]:
    """The root values, the edges and the nodes of a graph file, in file order.

    Yields ``("root", key, value)`` for each root key other than the streamed
    ``edges``/``nodes``, ``("edge", index, edge)`` for each edge and
    ``("node", node_id, node)`` for each node. A format-2 file is read line by
    line (one element in memory at a time); any other layout is read whole
    with ``json.load`` first. ``compact`` yields key-sharing dicts (a memo
    shared across the whole iteration).

    ``path`` is a path or an open binary file (``"rb"``); a file is read from
    its start and left open (see :func:`_source`).

    Raises:
        GraphFileFormatError: the file stopped following the line layout
            partway through (it is corrupt, or not written by the export).
        json.JSONDecodeError: a whole-file read failed.
    """
    with _source(path) as target:
        memo = _Memo() if compact else None
        shared = shared_notes_enabled() if compact else False
        if not _is_line_layout(target):
            graph = _load_whole(target)
            if not isinstance(graph, dict):
                raise GraphFileFormatError("the document is not an object")
            yield from _events_of_loaded(graph, memo, shared)
            return
        section: str | None = None
        for event, key, value in _scan_lines(
            target, want_edges=True, want_nodes=True, stop_after_edges=False
        ):
            if event == _BEGIN:
                section = key
                continue
            if event == _ROOT:
                if key in ("edges", "nodes"):
                    # A one-line ``edges``/``nodes`` (empty): expand it like the rest.
                    yield from _events_of_loaded({key: value}, memo, shared)
                else:
                    yield (_ROOT, key, _compact_value(value, memo) if memo else value)
            elif event == _EDGE:
                if section == "edges":
                    yield (_EDGE, key, compact_edge(value, memo, shared_notes=shared) if memo else value)
                else:
                    raise GraphFileFormatError(f"unexpected multi-line list {section!r}")
            elif section == "nodes":
                node_id = memo.key(key) if memo else key
                yield (_NODE, node_id, compact_node(value, memo) if memo else value)
            else:
                raise GraphFileFormatError(f"unexpected multi-line object {section!r}")


def _events_of_loaded(
    graph: dict[str, Any], memo: _Memo | None, shared: bool
) -> Iterator[tuple[str, Any, Any]]:
    for key, value in graph.items():
        if key == "edges" and isinstance(value, list):
            for index, edge in enumerate(value):
                yield (_EDGE, index, compact_edge(edge, memo, shared_notes=shared) if memo else edge)
        elif key == "nodes" and isinstance(value, dict):
            for node_id, node in value.items():
                yield (_NODE, memo.key(node_id) if memo else node_id, compact_node(node, memo) if memo else node)
        else:
            yield (_ROOT, key, _compact_value(value, memo) if memo else value)


def count_graph_file(path: GraphSource) -> tuple[int, int]:
    """``(node_count, edge_count)`` of a graph file without holding the graph.

    A format-2 file is scanned line by line, one element at a time, so a
    multi-gigabyte export is counted in flat memory. Any other layout (a 14.0.x
    file) is read whole, exactly as the counters that used this did before;
    such a file was written by a 14.0.x run, whose graph was a whole-file
    document anyway. Same inputs and errors as :func:`iter_graph_file`.
    """
    with _source(path) as target:
        if not _is_line_layout(target):
            target.seek(0)
            graph = json.loads(target.read().decode("utf-8"))
            if not isinstance(graph, dict):
                return (0, 0)
            nodes, edges = graph.get("nodes"), graph.get("edges")
            return (
                len(nodes) if isinstance(nodes, (dict, list)) else 0,
                len(edges) if isinstance(edges, list) else 0,
            )
        node_count = edge_count = 0
        for event, _key, _value in iter_graph_file(target):
            if event == _NODE:
                node_count += 1
            elif event == _EDGE:
                edge_count += 1
        return (node_count, edge_count)


def iter_graph_edges(
    path: GraphSource, *, compact: bool = False
) -> Iterator[Any]:
    """Each edge of a graph file, in order, one in memory at a time.

    A format-2 file is read up to the end of its ``edges`` list and no further
    (``edges`` sorts before ``nodes``, so the nodes are never read). Other
    layouts are read whole first. Same inputs (a path or an open binary file) and errors as
    :func:`iter_graph_file`.
    """
    with _source(path) as target:
        if not _is_line_layout(target):
            graph = _load_whole(target)
            edges = graph.get("edges") if isinstance(graph, dict) else None
            if isinstance(edges, list):
                memo = _Memo() if compact else None
                shared = shared_notes_enabled() if compact else False
                for edge in edges:
                    yield compact_edge(edge, memo, shared_notes=shared) if memo else edge
            return
        memo = _Memo() if compact else None
        shared = shared_notes_enabled() if compact else False
        section: str | None = None
        for event, key, value in _scan_lines(
            target, want_edges=True, want_nodes=False, stop_after_edges=True
        ):
            if event == _BEGIN:
                section = key
            elif event == _EDGE and section == "edges":
                yield compact_edge(value, memo, shared_notes=shared) if memo else value
            elif event == _ROOT and key == "edges" and isinstance(value, list):
                # ``"edges":[]`` (or a one-line list): written on one line.
                for edge in value:
                    yield compact_edge(edge, memo, shared_notes=shared) if memo else edge


def iter_graph_nodes(
    path: GraphSource, *, compact: bool = False
) -> Iterator[tuple[str, Any]]:
    """Each ``(node_id, node)`` of a graph file, in order.

    Edge lines are skipped without being parsed. Other layouts are read whole
    first. Same inputs (a path or an open binary file) and errors as
    :func:`iter_graph_file`.
    """
    with _source(path) as target:
        if not _is_line_layout(target):
            graph = _load_whole(target)
            nodes = graph.get("nodes") if isinstance(graph, dict) else None
            if isinstance(nodes, dict):
                memo = _Memo() if compact else None
                for node_id, node in nodes.items():
                    yield (memo.key(node_id), compact_node(node, memo)) if memo else (node_id, node)
            return
        memo = _Memo() if compact else None
        section: str | None = None
        for event, key, value in _scan_lines(
            target, want_edges=False, want_nodes=True, stop_after_edges=False
        ):
            if event == _BEGIN:
                section = key
            elif event == _NODE and section == "nodes":
                yield (memo.key(key), compact_node(value, memo)) if memo else (key, value)
            elif event == _ROOT and key == "nodes" and isinstance(value, dict):
                for node_id, node in value.items():
                    yield (memo.key(node_id), compact_node(node, memo)) if memo else (node_id, node)


def load_graph_file(
    path: GraphSource, *, shared_notes: bool | None = None
) -> Any:
    """The graph in ``path``, compact, ``==`` to ``json.load`` of the file.

    Key order is the file's at every level, as ``json.load`` gives it. A
    format-2 file is read line by line (peak: the compact graph plus one line);
    any other layout, or a file that stops following the layout partway, is
    read whole with ``json.load`` and compacted in place (the old peak, once).
    A document that is not an object is returned as ``json.load`` returns it.
    ``path`` may be an open binary file: read from its start, left open.

    Raises:
        json.JSONDecodeError: the file is not valid JSON (a caller that wants
            the corrupt-file recovery of ``read_json_file`` catches it).
        OSError: the file cannot be read.
    """
    with _source(path) as target:
        shared = shared_notes_enabled() if shared_notes is None else shared_notes
        if _is_line_layout(target):
            try:
                return _load_line_layout(target, shared)
            except GraphFileFormatError:
                pass
        graph = _load_whole(target)
        if isinstance(graph, dict):
            compact_graph(graph, shared_notes=shared)
        return graph


def _load_line_layout(path: BinaryIO, shared: bool) -> dict[str, Any]:
    memo = _Memo()
    root: dict[str, Any] = {}
    section = ""
    items: list[Any] = []
    entries: dict[str, Any] = {}
    for event, key, value in _scan_lines(
        path, want_edges=True, want_nodes=True, stop_after_edges=False
    ):
        if event == _EDGE:
            if section == "edges":
                items.append(compact_edge(value, memo, shared_notes=shared))
            else:
                items.append(_compact_value(value, memo))
        elif event == _NODE:
            if section == "nodes":
                entries[memo.key(key)] = compact_node(value, memo)
            else:
                entries[memo.key(key)] = _compact_value(value, memo)
        elif event == _BEGIN:
            section = key
            # A repeated root key keeps its first position and its last value,
            # exactly as ``json.load`` builds the object.
            if value == "list":
                items = []
                root[memo.key(key)] = items
            else:
                entries = {}
                root[memo.key(key)] = entries
        else:
            root[memo.key(key)] = _compact_root_value(key, value, memo, shared)
    return root


def _compact_root_value(key: str, value: Any, memo: _Memo, shared: bool) -> Any:
    """A root value written on one line (``"edges":[]``, ``"nodes":{}``, ...)."""
    if key == "edges" and isinstance(value, list):
        return [compact_edge(edge, memo, shared_notes=shared) for edge in value]
    if key == "nodes" and type(value) is dict:
        return {
            memo.key(node_id) if type(node_id) is str else node_id: compact_node(node, memo)
            for node_id, node in value.items()
        }
    return _compact_value(value, memo)
