"""Streamed, atomic export of the attack graph to ``attack_graph.json``.

The file is the contract every other reader (web ingestion, integrators, the
report) consumes; the store and the build are internal. This module turns the
in-memory graph into that file without ever holding its serialisation.

Layout (spec section 4.6 and decision T4): compact separators, keys sorted at
every level, ASCII-escaped, one node and one edge per line. A line break is
written ONLY between the elements of the root ``nodes`` and ``edges`` and
around the root keys, and a JSON string can never contain a raw line break, so
deleting every line feed from the file yields exactly::

    json.dumps(graph, sort_keys=True, separators=(",", ":"), default=json_default)

That identity is the byte-identity proof (``test_export.py``): the streamed
file is the compact one-shot dump plus line breaks, nothing else.

Format 2 is the default. ``ADSCAN_ATTACK_GRAPH_FORMAT=1`` (decision D3, for the
deprecation window only, unsuitable for large directories) re-inflates each
technique edge's ``knowledge`` block while streaming and writes format 1.

Peak extra memory is the sorted node-id list plus one element and one write
buffer, never the whole document.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from json.decoder import scanstring as _scanstring

from adscan_core import telemetry
from adscan_core.graph_compact import is_line_layout
from adscan_core.engagement.output_formats import output_marker, previous_major_marker
from adscan_core.graph_store import ExportRecord, GraphStore, StoreGeneration
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_core.workspace_freeze import write_blocked
from adscan_internal.workspaces.io import json_default

#: Env switch for the deprecation-window writer (decision D3).
FORMAT_ENV_VAR = "ADSCAN_ATTACK_GRAPH_FORMAT"

#: Root keys that exist only in format 2 (dropped by the format-1 writer).
_FORMAT2_ONLY_ROOT_KEYS = frozenset({"technique_knowledge", "collection"})

#: Root key of a file a stopped build left behind (``mark_export_incomplete``).
EXPORT_STATE_KEY = "export_state"

#: Suffix a file outside the line layout is moved aside to.
PREVIOUS_EXPORT_SUFFIX = ".previous.json"

#: Flush the write buffer past this many characters.
_FLUSH_CHARS = 1 << 20

_ENCODER = json.JSONEncoder(sort_keys=True, separators=(",", ":"), default=json_default)

_monotonic = time.monotonic

_throttle_lock = threading.Lock()
#: ``resolved path -> (finished_at_monotonic, seconds the export cost, key)``,
#: ``key`` being the ``(generation, fingerprint)`` the file was built from.
#: Plain values only, so nothing here is bound to an event loop or a thread.
_LAST_EXPORT: dict[str, tuple[float, float, tuple[StoreGeneration, str]]] = {}


def requested_format_major() -> int:
    """The major the environment asks for: 1 only on an explicit opt-in."""
    return 1 if os.environ.get(FORMAT_ENV_VAR, "").strip() == "1" else 2


def _encode(value: Any) -> str:
    """One element's JSON. The live graph is streamed from a shallow snapshot
    while writers may still change an element's dict; an element changed
    mid-encode (``RuntimeError``) is encoded again, once, from its new state."""
    try:
        return _ENCODER.encode(value)
    except RuntimeError:
        return _ENCODER.encode(value)


def _edge_with_knowledge(
    edge: Any,
    nodes: Mapping[str, Any],
    coordinates: Any,
    render: Any,
    member_resolver: Any = None,
) -> Any:
    """A copy of ``edge`` with the format-1 ``knowledge`` block, when it has one."""
    if not isinstance(edge, Mapping):
        return edge
    from adscan_internal.services.edge_knowledge import edge_endpoints

    source_id, target_id = edge_endpoints(edge)
    kwargs: dict[str, Any] = {
        "source_node": nodes.get(source_id),
        "target_node": nodes.get(target_id),
        "coordinates": coordinates,
    }
    if member_resolver is not None:
        kwargs["member_resolver"] = member_resolver
    block = render(edge, **kwargs)
    if not block:
        return edge
    inflated = dict(edge)
    inflated["knowledge"] = block
    return inflated


def _root_pieces(
    graph: Mapping[str, Any], fmt: int, member_resolver: Any = None
) -> Iterator[str]:
    """The document as text pieces, in order. Streams ``nodes`` and ``edges``."""
    root: dict[str, Any] = dict(graph)
    if fmt != 0:
        # A graph exported in full is current by definition; a stale marker
        # read back from an earlier, stopped file never travels into it.
        root.pop(EXPORT_STATE_KEY, None)
    if fmt == 0:
        pass  # another document (a sidecar): written as given, its own marker kept
    elif fmt == 2:
        root["schema_version"] = output_marker("attack_graph")
    else:
        root["schema_version"] = previous_major_marker("attack_graph")
        for key in _FORMAT2_ONLY_ROOT_KEYS:
            root.pop(key, None)
    nodes = root.get("nodes")
    edges = root.get("edges")
    render = coordinates = None
    if fmt == 1 and isinstance(edges, list) and isinstance(nodes, Mapping):
        from adscan_internal.services import edge_knowledge

        coordinates = edge_knowledge.GraphCoordinates.from_graph(graph)
        render = edge_knowledge.render_edge_knowledge

    yield "{\n"
    for index, key in enumerate(sorted(root)):
        if index:
            yield ",\n"
        yield _encode(key) + ":"
        value = root[key]
        if key == "edges" and isinstance(value, list):
            if not value:
                yield "[]"
                continue
            yield "[\n"
            for position, edge in enumerate(value):
                if render is not None:
                    edge = _edge_with_knowledge(
                        edge, nodes, coordinates, render, member_resolver
                    )
                yield (",\n" if position else "") + _encode(edge)
            yield "\n]"
        elif key == "nodes" and isinstance(value, Mapping):
            if not value:
                yield "{}"
                continue
            yield "{\n"
            for position, node_id in enumerate(sorted(value)):
                yield (
                    (",\n" if position else "")
                    + _encode(node_id)
                    + ":"
                    + _encode(value[node_id])
                )
            yield "\n}"
        else:
            yield _encode(value)
    yield "\n}\n"


def export_graph(
    graph: Mapping[str, Any],
    path: str | Path,
    *,
    format_major: int | None = None,
    member_resolver: Any = None,
    stamp_attack_graph_marker: bool = True,
) -> int:
    """Write ``graph`` to ``path`` as ``attack_graph.json``, atomically.

    Streams into a temporary file beside ``path``, flushes, fsyncs and replaces
    ``path``; on any failure (including a stop request) the previous file is
    left untouched and no temporary file remains. A path that belongs to a
    frozen workspace is not written.

    Args:
        graph: The built graph (``nodes`` dict, ``edges`` list, root metadata).
        path: Destination file.
        format_major: 2 (default) or 1 (the deprecation-window writer). When
            ``None`` the ``ADSCAN_ATTACK_GRAPH_FORMAT`` environment decides.
            This is the ONLY format-1 writer of the engine.
        member_resolver: The group-member example resolver the format-1
            writer fills commands with (``edge_knowledge``); unused by format 2.
        stamp_attack_graph_marker: ``False`` streams another document with
            the same layout and the same atomic replace (a sidecar such as
            ``memberships.json``): its root is written as given, its own
            ``schema_version`` kept, and the format switch does not apply.

    Returns:
        Bytes written, or 0 when the workspace is frozen.
    """
    destination = os.path.abspath(os.fspath(path))
    if write_blocked(destination):
        print_info_debug("graph export skipped: the workspace is frozen")
        return 0
    if not stamp_attack_graph_marker:
        fmt = 0
    else:
        fmt = format_major if format_major in (1, 2) else requested_format_major()
    directory = os.path.dirname(destination)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=directory, prefix=".attack_graph-", suffix=".tmp"
    )
    written = 0
    try:
        with os.fdopen(fd, "wb") as handle:
            buffer: list[str] = []
            size = 0
            pieces = (
                _root_pieces(graph, fmt)
                if member_resolver is None
                else _root_pieces(graph, fmt, member_resolver)
            )
            for piece in pieces:
                buffer.append(piece)
                size += len(piece)
                if size >= _FLUSH_CHARS:
                    data = "".join(buffer).encode("utf-8")
                    handle.write(data)
                    written += len(data)
                    buffer.clear()
                    size = 0
            data = "".join(buffer).encode("utf-8")
            handle.write(data)
            written += len(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, destination)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return written


def _throttled(path: str, policy: Any) -> bool:
    with _throttle_lock:
        last = _LAST_EXPORT.get(path)
    if last is None:
        return False
    finished_at, cost = last[0], last[1]
    wait = max(float(policy.min_interval_seconds), float(policy.cost_multiple) * cost)
    return (_monotonic() - finished_at) < wait


def is_throttled(path: str | Path, policy: Any = None) -> bool:
    """Whether an automatic export to ``path`` must wait (``ExportPolicy``).

    Cheap (no build, no store read), so a caller that calls often checks it
    before assembling a build context.
    """
    if policy is None:
        from adscan_internal.services.graph_build import api

        policy = api.ExportPolicy()
    return _throttled(os.path.abspath(os.fspath(path)), policy)


def context_fingerprint(context: Any) -> str:
    """``context.fingerprint()``, or "" for no context (or one without it)."""
    fingerprint = getattr(context, "fingerprint", None)
    if not callable(fingerprint):
        return ""
    return str(fingerprint() or "")


def is_export_current(store: GraphStore, context: Any, path: str | Path) -> bool:
    """Whether ``path`` holds the export of the store and the context as they are now.

    The cache key is ``(store.generation(), context.fingerprint())``: the build
    depends on values outside the store (``GraphBuildContext``), so the
    generation alone does not prove a file current. The store's last export
    record is authoritative for the generation (a new store at the same path
    never inherits a file); its fingerprint, when the backend persisted none,
    is taken from this process's own record of the export. Without either, the
    file is not proven current and the next export rewrites it.
    """
    return is_key_current(
        store, path, generation=store.generation(), fingerprint=context_fingerprint(context)
    )


def is_key_current(
    store: GraphStore, path: str | Path, *, generation: StoreGeneration, fingerprint: str
) -> bool:
    """Whether ``path`` holds the export of ``(generation, fingerprint)``.

    The store's last export record is authoritative for the generation; its
    fingerprint, when the backend persisted none, is taken from this
    process's own record of the export.
    """
    destination = os.path.abspath(os.fspath(path))
    if not os.path.exists(destination):
        return False
    recorded = store.last_export()
    if recorded is None or recorded.generation != generation:
        return False
    if recorded.fingerprint:
        return recorded.fingerprint == fingerprint
    with _throttle_lock:
        last = _LAST_EXPORT.get(destination)
    return last is not None and last[2] == (generation, fingerprint)


def export_if_due(
    store: GraphStore,
    context: Any,
    path: str | Path,
    *,
    policy: Any = None,
    force: bool = False,
    after_export: Callable[[Mapping[str, Any]], None] | None = None,
) -> bool:
    """Build and export when the store or the context moved since the last
    export and the policy allows it (or ``force``). Returns whether a file was
    written.

    "Moved" is :func:`is_export_current` false: the ``(generation,
    fingerprint)`` key differs from the last export's, or the file is gone. An
    automatic export is also throttled to
    ``policy.min_interval_seconds`` and ``policy.cost_multiple`` times the
    previous export's cost (build plus write, measured in this process with a
    monotonic clock); ``force`` ignores the throttle but never the frozen
    state. A failure is logged with its traceback and reported as ``False``: an
    export problem must not end a scan, and the next call retries.

    ``after_export`` receives the built graph once the file is in place and
    recorded (the sidecar exports hang there). Its failure is logged and does
    not undo the export: the call still returns ``True``.
    """
    from adscan_internal.services.graph_build import api

    if policy is None:
        policy = api.ExportPolicy()
    destination = os.path.abspath(os.fspath(path))
    if store.read_only or write_blocked(destination):
        return False
    try:
        if not force:
            if is_export_current(store, context, destination):
                return False
            if _throttled(destination, policy):
                return False
        fingerprint = context_fingerprint(context)
        started = _monotonic()
        graph, report = api.build_graph(store, context)
    except Exception as exc:  # noqa: BLE001 - best effort, never ends a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
    return export_built_graph(
        store,
        graph,
        destination,
        generation=report.generation,
        fingerprint=fingerprint,
        started=started,
        member_resolver=getattr(context, "membership_resolver", None),
        after_export=after_export,
    )


def export_built_graph(
    store: GraphStore,
    graph: Mapping[str, Any],
    path: str | Path,
    *,
    generation: StoreGeneration,
    fingerprint: str,
    started: float | None = None,
    member_resolver: Any = None,
    after_export: Callable[[Mapping[str, Any]], None] | None = None,
) -> bool:
    """Write a graph already built for ``(generation, fingerprint)`` and record it.

    The second half of :func:`export_if_due`, for a caller that holds the
    built graph (the runtime facade exports its live graph instead of building
    a second one). Records the export on the store and in the throttle, then
    runs ``after_export``. Never raises for an export problem.
    """
    destination = os.path.abspath(os.fspath(path))
    if store.read_only or write_blocked(destination):
        return False
    began = _monotonic() if started is None else started
    try:
        size = export_graph(graph, destination, member_resolver=member_resolver)
        if not size:
            return False
        cost = _monotonic() - began
        store.record_export(
            ExportRecord(
                generation=generation,
                exported_at=datetime.now(timezone.utc).isoformat(),
                duration_seconds=cost,
                nodes=len(graph.get("nodes") or ()),
                edges=len(graph.get("edges") or ()),
                size_bytes=size,
                fingerprint=fingerprint,
            )
        )
        with _throttle_lock:
            _LAST_EXPORT[destination] = (_monotonic(), cost, (generation, fingerprint))
    except Exception as exc:  # noqa: BLE001 - best effort, never ends a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return False
    if after_export is not None:
        try:
            after_export(graph)
        except Exception as exc:  # noqa: BLE001 - the graph export already stands
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    return True


def _previous_export_path(destination: str) -> str:
    base = destination[: -len(".json")] if destination.endswith(".json") else destination
    return base + PREVIOUS_EXPORT_SUFFIX


def _root_key(line: bytes) -> str:
    """The key of a root entry line (``"key":value``) of the line layout."""
    text = line.decode("utf-8")
    if not text.startswith('"'):
        raise ValueError("expected a root key")
    key, end = _scanstring(text, 1)
    if text[end : end + 1] != ":":
        raise ValueError("expected ':' after a root key")
    return key


def _copy_with_export_state(source: Any, target: Any, state_line: bytes) -> None:
    """Stream ``source`` (the line layout) into ``target`` with ``state_line``
    as the ``export_state`` root entry, in sorted key position.

    One line at a time: the multi-line ``nodes`` and ``edges`` blocks are copied
    verbatim. The final line of each root entry is held back until the next
    one starts, so the separating comma is always right, whether an old
    ``export_state`` entry is dropped or the new one goes first or last.
    Raises ``ValueError`` when the file stops following the layout.
    """
    if source.readline().rstrip(b"\r\n") != b"{":
        raise ValueError("expected '{'")
    target.write(b"{\n")
    held: bytes | None = None
    inserted = False

    def start_entry() -> None:
        if held is not None:
            target.write(held + b",\n")

    while True:
        raw = source.readline()
        if not raw:
            raise ValueError("unexpected end of file")
        line = raw.rstrip(b"\r\n")
        if line == b"}":
            break
        key = _root_key(line)
        if key == EXPORT_STATE_KEY:
            continue  # replaced by the new state below
        if not inserted and key > EXPORT_STATE_KEY:
            start_entry()
            held = state_line
            inserted = True
        start_entry()
        body = line[:-1] if line.endswith(b",") else line
        rest = body.split(b":", 1)[1] if b":" in body else b""
        if body.endswith((b":[", b":{")) and rest in (b"[", b"{"):
            close = b"]" if rest == b"[" else b"}"
            target.write(body + b"\n")
            while True:
                item_raw = source.readline()
                if not item_raw:
                    raise ValueError("unexpected end of file in a block")
                item = item_raw.rstrip(b"\r\n")
                if item in (close, close + b","):
                    held = close
                    break
                target.write(item + b"\n")
        else:
            held = body
    if not inserted:
        start_entry()
        held = state_line
    if held is not None:
        target.write(held + b"\n")
    target.write(b"}\n")


def mark_export_incomplete(
    path: str | Path,
    block: Mapping[str, Any],
    *,
    store: GraphStore | None = None,
) -> str:
    """Declare that ``path`` no longer describes the current graph.

    Called when a build was stopped (the memory guard, an operator stop) after
    the store moved past the last export: without it the previous
    ``attack_graph.json`` stays on disk and reads as current, a silent
    truncation. Two cases:

    * a file in the format-2 line layout is stream-copied into a temporary file
      with a root ``export_state`` entry, ``{"current": false, "stage",
      "reason", "at"}``, and atomically replaced. Memory stays flat (one line at
      a time). A reader (the web ingestion, an integrator) sees the flag;
    * any other file (a 14.0.x export, a one-line file) cannot be amended by
      streaming, so it is moved aside to ``attack_graph.previous.json``: no
      reader takes it as current.

    The export record of ``store`` (when given) and this process's own record
    are cleared, so the next export never skips the file as current. A frozen
    workspace is left untouched. The next full export drops the flag.

    Args:
        path: The ``attack_graph.json`` to mark.
        block: ``stage`` and ``reason`` of the stop, and ``at`` (an ISO 8601
            UTC instant, now by default).
        store: The domain's store, whose export record is reset.

    Returns:
        ``"marked"``, ``"moved_aside"``, ``"absent"`` or ``"frozen"``.
    """
    destination = os.path.abspath(os.fspath(path))
    if write_blocked(destination):
        return "frozen"
    with _throttle_lock:
        _LAST_EXPORT.pop(destination, None)
    if store is not None and not store.read_only:
        store.record_export(ExportRecord(exported_at=datetime.now(timezone.utc).isoformat()))
    if not os.path.exists(destination):
        return "absent"
    state = {
        "current": False,
        "stage": str(block.get("stage") or ""),
        "reason": str(block.get("reason") or ""),
        "at": str(block.get("at") or datetime.now(timezone.utc).isoformat()),
    }
    state_line = (_encode(EXPORT_STATE_KEY) + ":" + _encode(state)).encode("utf-8")
    with open(destination, "rb") as source:
        layout = is_line_layout(source)
        if layout:
            fd, tmp_path = tempfile.mkstemp(
                dir=os.path.dirname(destination), prefix=".attack_graph-", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "wb") as target:
                    _copy_with_export_state(source, target, state_line)
                    target.flush()
                    os.fsync(target.fileno())
            except ValueError:
                # The file stopped following the layout part-way: treat it as
                # one we cannot amend.
                os.unlink(tmp_path)
                layout = False
            except BaseException:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
    if layout:
        os.replace(tmp_path, destination)
        return "marked"
    os.replace(destination, _previous_export_path(destination))
    return "moved_aside"


__all__ = (
    "EXPORT_STATE_KEY",
    "FORMAT_ENV_VAR",
    "PREVIOUS_EXPORT_SUFFIX",
    "mark_export_incomplete",
    "export_built_graph",
    "is_key_current",
    "context_fingerprint",
    "export_graph",
    "export_if_due",
    "is_export_current",
    "is_throttled",
    "requested_format_major",
)
