"""Streamed writing of the inventory files, byte-identical to ``write_json_file``.

An inventory file (``inventory/acls.json`` and its siblings) is a header plus a
``records`` list sorted by ``(name, relation, target)``. On a dense directory
the edge files hold hundreds of thousands of records; building the record dicts
and the whole document string before writing (``write_json_file``) doubled the
export's memory. This module writes the SAME bytes while holding only a bounded
chunk:

* each record is encoded on its own (``json.dumps(..., indent=4,
  sort_keys=True)`` re-indented to its depth in the document, which is exactly
  how ``json.dumps`` lays out a list element), and buffered with its sort key
  and its arrival order;
* a full buffer is sorted and spilled to a temporary file in the inventory
  directory; at write time the spilled chunks are merged (``heapq.merge`` on
  ``(key, arrival)``), which reproduces the stable ``sorted(records,
  key=_record_sort_key)`` order exactly;
* the header is the document ``json.dumps`` writes, cut where the records go.

Atomic like ``write_json_file`` (temp file, fsync, replace) and never written
on a frozen workspace.
"""

from __future__ import annotations

import heapq
import json
import os
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from adscan_internal.workspaces.io import json_default

#: Records buffered per output file before a sorted chunk is spilled.
SPILL_CHUNK = 5000

_RECORDS_SENTINEL = "\x00adscan-inventory-records\x00"
_RECORD_INDENT = " " * 8  # a record's depth in the document: root -> "records" -> item


def encode_record(record: Mapping[str, Any]) -> str:
    """One record as ``json.dumps`` writes it inside the document's ``records`` list."""
    text = json.dumps(record, indent=4, sort_keys=True, default=json_default)
    return "\n".join(_RECORD_INDENT + line for line in text.split("\n"))


def _header_and_footer(header: Mapping[str, Any]) -> tuple[str, str]:
    """The document text before and after the records of a non-empty list."""
    document = dict(header)
    document["records"] = [_RECORDS_SENTINEL]
    text = json.dumps(document, indent=4, sort_keys=True, default=json_default)
    marker = _RECORD_INDENT + json.dumps(_RECORDS_SENTINEL)
    before, after = text.split(marker, 1)
    return before, after


class SortedRecordSpool:
    """Records of one output file, sorted on write, in bounded memory."""

    def __init__(self, tmpdir: str, *, chunk: int = SPILL_CHUNK) -> None:
        self._tmpdir = tmpdir
        self._chunk = max(1, int(chunk))
        self._buffer: list[tuple[tuple[str, ...], int, str]] = []
        self._spills: list[str] = []
        self.count = 0

    def add(self, key: tuple[str, ...], text: str) -> None:
        self._buffer.append((tuple(key), self.count, text))
        self.count += 1
        if len(self._buffer) >= self._chunk:
            self._spill()

    def _spill(self) -> None:
        if not self._buffer:
            return
        self._buffer.sort(key=lambda item: (item[0], item[1]))
        fd, path = tempfile.mkstemp(dir=self._tmpdir, prefix=".inventory-chunk-", suffix=".jsonl")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for key, order, text in self._buffer:
                handle.write(json.dumps([list(key), order, text]))
                handle.write("\n")
        self._spills.append(path)
        self._buffer = []

    @staticmethod
    def _read(path: str) -> Iterator[tuple[tuple[str, ...], int, str]]:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                key, order, text = json.loads(line)
                yield tuple(key), int(order), text

    def iter_sorted(self) -> Iterator[str]:
        """The encoded records in ``(key, arrival)`` order (consumes the spool)."""
        if not self._spills:
            self._buffer.sort(key=lambda item: (item[0], item[1]))
            for _key, _order, text in self._buffer:
                yield text
            self._buffer = []
            return
        self._spill()
        streams = [self._read(path) for path in self._spills]
        for _key, _order, text in heapq.merge(*streams, key=lambda item: (item[0], item[1])):
            yield text
        for path in self._spills:
            try:
                os.unlink(path)
            except OSError:
                pass
        self._spills = []


def write_records_document(path: str, header: Mapping[str, Any], records: Iterable[str], count: int) -> None:
    """Write ``header`` with ``records`` (already encoded, in order) to ``path``.

    Byte-identical to ``write_json_file(path, {**header, "records": [...]})``.
    ``count`` is how many records ``records`` yields (an empty list is written
    by ``json.dumps`` itself, as ``write_json_file`` would).
    """
    from adscan_core.workspace_freeze import write_blocked  # noqa: PLC0415

    destination = os.path.abspath(path)
    if write_blocked(destination):
        return
    directory = os.path.dirname(destination)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".variables-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            if count <= 0:
                document = dict(header)
                document["records"] = []
                handle.write(json.dumps(document, indent=4, sort_keys=True, default=json_default))
            else:
                before, after = _header_and_footer(header)
                handle.write(before)
                for position, text in enumerate(records):
                    if position:
                        handle.write(",\n")
                    handle.write(text)
                handle.write(after)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, destination)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


__all__ = (
    "SPILL_CHUNK",
    "SortedRecordSpool",
    "encode_record",
    "write_records_document",
)
