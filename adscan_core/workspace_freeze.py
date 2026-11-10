"""A frozen workspace: the artifacts of a recorded scan are read, never rewritten.

A recheck re-observes a finished scan. The scan's own artifacts (``variables.json``,
every ``attack_graph.json`` and its path cache, ``scan_policy.json``,
``technical_report.json``, ...) are the record of what that scan found, so a later
run must leave them byte-identical. What a recheck records goes to the engagement
ledger and to its own run folder, which this guard never covers.

The workspace loader and the engine carry many best-effort writers (migrations,
status refreshes, autosaves, cache invalidation). Rather than chasing each by
name, every persistence seam for a scan artifact asks :func:`write_blocked` and
declines while the workspace is frozen. A new writer of a scan artifact adds the
same one-line check; ``tests/unit/services/recheck/test_recheck_scan_artifacts_untouched.py``
hashes the whole workspace tree to catch one that does not.

Pure stdlib so any layer can ask.
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

#: Top-level entries of a workspace that stay writable while it is frozen: the
#: engagement ledger, every run folder (the recheck's own evidence included) and
#: the logs, which are workspace-scoped by design.
WRITABLE_TOP_LEVEL = frozenset({"engagement", "runs", "logs"})

_lock = threading.Lock()
_frozen_roots: list[Path] = []


def _resolve(path: Any) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def freeze_workspace(root: Any) -> None:
    """Freeze ``root`` for the rest of the process."""
    resolved = _resolve(root)
    with _lock:
        if resolved not in _frozen_roots:
            _frozen_roots.append(resolved)


def unfreeze_workspace(root: Any) -> None:
    resolved = _resolve(root)
    with _lock:
        if resolved in _frozen_roots:
            _frozen_roots.remove(resolved)


@contextmanager
def frozen_workspace(root: Any) -> Iterator[None]:
    """Freeze ``root`` inside the block (tests, and any read-only entry point)."""
    freeze_workspace(root)
    try:
        yield
    finally:
        unfreeze_workspace(root)


def write_blocked(path: Any) -> bool:
    """True when ``path`` is a scan artifact of a frozen workspace.

    Cheap and never raises: the common case (nothing frozen) is one list check.
    """
    if not _frozen_roots:
        return False
    try:
        target = _resolve(path)
    except (TypeError, ValueError):
        return False
    with _lock:
        roots = list(_frozen_roots)
    for root in roots:
        try:
            relative = target.relative_to(root)
        except ValueError:
            continue
        parts = relative.parts
        if parts and parts[0] in WRITABLE_TOP_LEVEL:
            return False
        return True
    return False


__all__ = (
    "WRITABLE_TOP_LEVEL",
    "freeze_workspace",
    "frozen_workspace",
    "unfreeze_workspace",
    "write_blocked",
)
