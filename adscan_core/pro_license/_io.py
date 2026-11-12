"""File helpers for the PRO licence state (atomic writes with an explicit mode)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from adscan_core.license_storage import LicenseStorageError, adopt_directory_owner


def atomic_write(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    """Replace ``path`` atomically with ``data``; the file takes the directory's owner.

    ``mode`` is applied before any byte is written, so a secret (``0o600``) is
    never readable by others, even for an instant.

    Raises:
        LicenseStorageError: the directory or the file could not be written.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    except OSError as exc:
        raise LicenseStorageError.from_os_error(exc, path) from exc
    try:
        os.chmod(tmp, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        adopt_directory_owner(Path(tmp), directory=path.parent)
        os.replace(tmp, path)
    except BaseException as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if isinstance(exc, OSError) and not isinstance(exc, LicenseStorageError):
            raise LicenseStorageError.from_os_error(exc, path) from exc
        raise


def write_json(path: Path, data: Any, *, mode: int = 0o644) -> None:
    """Write ``data`` as sorted, indented JSON (atomic)."""
    atomic_write(path, json.dumps(data, sort_keys=True, indent=2).encode("utf-8"), mode=mode)


def read_json(path: Path) -> Any:
    """Return the parsed JSON at ``path``, or None when absent or unreadable."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
