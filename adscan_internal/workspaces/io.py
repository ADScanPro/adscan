from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any


def read_json_file(path: str) -> dict[str, Any]:
    """Read a JSON file and return its parsed dictionary.

    Resilient to corrupted state: when parsing fails (truncated/malformed JSON
    left by a buggy prior run), the corrupted file is backed up to
    ``<path>.corrupted.<timestamp>.bak`` and an empty dict is returned, instead
    of propagating ``JSONDecodeError`` and breaking workspace load.
    """
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            try:
                handle.seek(0)
                _content = handle.read()
            except Exception:  # noqa: BLE001
                _content = ""
            _backup = f"{path}.corrupted.{int(time.time())}.bak"
            try:
                with open(_backup, "w", encoding="utf-8") as _bh:
                    _bh.write(_content)
            except OSError:
                _backup = ""
            try:
                from adscan_core.rich_output import print_warning
                _msg = f"variables JSON at {path} was corrupted ({exc}); recovered with empty state."
                if _backup:
                    _msg += f" Original backed up to {_backup}."
                print_warning(_msg)
            except Exception:  # noqa: BLE001
                pass
            return {}
    if isinstance(data, dict):
        return data
    return {}


def _json_default(obj: Any) -> Any:
    """Coerce a non-JSON value into a serializable form deterministically.

    ``json.dumps`` invokes this only for values it cannot natively serialize, so
    a stray ``set``/``bytes``/custom object degrades gracefully instead of
    raising ``TypeError`` mid-write:

    * ``set`` / ``frozenset`` -> sorted ``list`` (natural order; ``repr`` order
      when the members are not mutually comparable, so it never raises).
    * ``bytes`` / ``bytearray`` -> ``None`` (dropped; a lost value is safer than
      a crashed write that destroys the whole file).
    * anything else -> ``str(obj)``.
    """
    if isinstance(obj, (set, frozenset)):
        try:
            return sorted(obj)
        except TypeError:
            return sorted(obj, key=repr)
    if isinstance(obj, (bytes, bytearray)):
        return None
    return str(obj)


def write_json_file(path: str, data: dict[str, Any]) -> None:
    """Write a JSON dict to disk atomically, with stable formatting.

    Two invariants a naive ``open(path, "w") + json.dump`` violates:

    * **Atomic.** The payload is serialized to a string FIRST, then written to a
      temp file in the same directory and ``os.replace``d over the destination
      (atomic on POSIX). A serialization error therefore never truncates or
      corrupts the existing good file — the previous content survives
      byte-for-byte and the temp fragment is cleaned up.
    * **Serialization-safe.** A ``default`` coercer (:func:`_json_default`)
      degrades non-JSON values instead of raising, so a stray ``set``/``bytes``
      in ``domains_data`` cannot poison the write and drop the whole layer.
    """
    # Serialize BEFORE touching the destination: if this raises, the existing
    # file on disk is untouched.
    payload = json.dumps(data, indent=4, sort_keys=True, default=_json_default)

    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".variables-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


__all__ = [
    "read_json_file",
    "write_json_file",
]
