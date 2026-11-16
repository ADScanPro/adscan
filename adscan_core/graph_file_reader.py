"""Read one domain's attack graph for a caller that holds a directory, not a shell.

Report builders, the recheck walk, the writeup and the web's verification panel
receive a workspace path. The graph is built from the domain's store and
``attack_graph.json`` is only its export, so a file read can be behind what the
session has recorded. The live in-session graph is NOT what these callers read:
it carries session enrichments (target-priority overrides, foreign-DC role
markers, trust couplings) that the export does not, and a deliverable must read
the same document wherever it is rendered (inside the scan, ``deliver`` in a
later process, the web). So there is one source of truth for them, the export:

1. when a live engine session owns the domain directory, its export is brought
   up to date first (``ensure_export_fresh``, a no-op when the file is current);
2. the file is parsed ONCE and memoised on ``(path, size, mtime)``, so five
   readers building one report share one parse instead of making five copies of
   a graph that weighs about 2 KB per edge.

The returned dict is shared: READ ONLY. Dependency-light on purpose: the
appliance backend imports this module and has no engine, so the freshness hook
is an optional import that quietly does nothing there (by design: the appliance
only ever reads a finished export).
"""

from __future__ import annotations

import importlib
import os
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

from adscan_core.graph_compact import load_graph_file

#: Module of the engine that can resolve a live session (absent in the web backend).
_LIVE_READER_MODULE = "adscan_internal.services.graph_live_reader"
#: File name of the export inside the domain directory.
GRAPH_FILENAME = "attack_graph.json"

#: Parsed exports, keyed by ``(path, size, mtime_ns)``. Two entries: a report that
#: alternates between two domains must not re-parse on every reader. Each one is
#: the compact load (``graph_compact.load_graph_file``): ``==`` to ``json.load``
#: of the file, about a third of its residency (one copy of each repeated key and
#: short value; a ``json.load`` of the format-2 export held 3.4 times the live
#: graph), read line by line without holding the file's text.
_MEMO_CAPACITY = 2
_MEMO: "OrderedDict[tuple[str, int, int], dict[str, Any]]" = OrderedDict()
_MEMO_LOCK = threading.Lock()


def ensure_export_fresh_in_dir(domain_dir: str | os.PathLike[str]) -> None:
    """Bring the export of ``domain_dir`` up to date when a live session owns it.

    Does nothing when the engine is not installed or no session holds the
    domain. A failure is reported (telemetry and the debug log) and the caller
    reads the file as it stands: never silent, never fatal.
    """
    try:
        module = importlib.import_module(_LIVE_READER_MODULE)
    except ImportError:
        return
    try:
        module.ensure_export_fresh_for_domain_dir(os.fspath(domain_dir))
    except Exception as exc:  # noqa: BLE001 - the reader falls back to the file as it stands
        # Imported here: the appliance backend imports this module and must not pay for
        # (or start) the telemetry stack just to read a file.
        from adscan_core import telemetry  # noqa: PLC0415
        from adscan_core.rich_output import print_exception  # noqa: PLC0415

        telemetry.capture_exception(exc)
        print_exception(exception=exc)


def _parse(path: Path) -> dict[str, Any] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    key = (os.fspath(path), stat.st_size, stat.st_mtime_ns)
    with _MEMO_LOCK:
        hit = _MEMO.get(key)
        if hit is not None:
            _MEMO.move_to_end(key)
            return hit
    try:
        doc = load_graph_file(path)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    with _MEMO_LOCK:
        _MEMO[key] = doc
        while len(_MEMO) > _MEMO_CAPACITY:
            _MEMO.popitem(last=False)
    return doc


def read_graph_in_dir(domain_dir: str | os.PathLike[str]) -> dict[str, Any] | None:
    """The domain's exported attack graph, current and parsed once.

    Returns ``None`` when there is no readable export. The dict is shared with
    every other reader of the same file: do not mutate it.
    """
    ensure_export_fresh_in_dir(domain_dir)
    return _parse(Path(domain_dir) / GRAPH_FILENAME)


def read_domain_graph(
    workspace_dir: str | os.PathLike[str], domain: str, *, domains_dir: str = "domains"
) -> dict[str, Any] | None:
    """:func:`read_graph_in_dir` for ``<workspace>/<domains_dir>/<domain>``."""
    return read_graph_in_dir(Path(workspace_dir) / domains_dir / str(domain))


def clear_memo() -> None:
    """Drop the memoised parses (tests)."""
    with _MEMO_LOCK:
        _MEMO.clear()


__all__ = (
    "GRAPH_FILENAME",
    "clear_memo",
    "ensure_export_fresh_in_dir",
    "read_domain_graph",
    "read_graph_in_dir",
)
