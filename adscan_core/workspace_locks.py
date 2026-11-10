"""Removal of a per-workspace single-instance lock file (shared primitive).

The lock path itself is resolved by :func:`adscan_core.paths.get_workspace_lock_path`
and its file name carries the workspace name, so the file must not outlive the
engagement: it is unlinked on release, and removed again when the workspace is
deleted. This module owns the one careful way to remove it, because three
callers need it and each got it wrong differently when they rolled their own:

* the container-side residue purge, for a deleted workspace;
* the same purge, for every ``.run_<logical>_<scanid>`` execution workspace of
  that workspace (its lock file name carries the logical name too);
* the host-side launcher housekeeping, for an orphaned execution workspace.

"Careful" means two things, both of which a naive ``unlink`` gets wrong:

* a lock a LIVE run holds is never removed (the run unlinks it on release);
* the file we locked is confirmed to still be the file at that path, so a lock
  released and re-created by a new owner between our open and our lock is left
  to that owner.

Lives in ``adscan_core`` because the launcher (host) and the runtime (container)
both need it and neither may import the other.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path


def _same_inode(handle, path: Path) -> bool:
    """Whether the open handle still refers to the file now at ``path``."""
    try:
        opened = os.fstat(handle.fileno())
        current = os.stat(path)
    except OSError:
        return False
    return (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino)


def _open_lock_exclusively(path: Path):
    """Open ``path`` and take its lock, or return ``None`` when it is live.

    Returns the open handle (caller closes it) when the lock was free AND the
    locked file is still the one at ``path``; ``None`` when a live run holds it,
    the file was swapped, or it cannot be opened.
    """
    try:
        fcntl = importlib.import_module("fcntl")
    except ImportError:
        fcntl = None
    try:
        handle = open(path, "a+", encoding="utf-8")  # noqa: SIM115
    except OSError:
        return None
    if fcntl is not None:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            _close(handle)
            return None  # a live run holds it; it is unlinked on release
    if not _same_inode(handle, path):
        # The file we locked was released and replaced by a new owner's lock
        # between our open and our lock: that one is live, keep it.
        _close(handle)
        return None
    return handle


def _close(handle) -> None:
    try:
        handle.close()
    except OSError:
        pass


def workspace_lock_is_held(workspace_name: str) -> bool:
    """Whether a live run currently holds this workspace's lock.

    Read-only: it takes the lock to find out and releases it immediately,
    removing nothing. ``False`` when there is no lock file at all, which is also
    the answer in a deployment where the lock directory is not visible from this
    process (in the Docker deployment ``run/locks`` is host-only), so a caller
    that must not act on a live run needs a second signal as well.
    """
    from adscan_core.paths import get_workspace_lock_path  # noqa: PLC0415

    try:
        path = get_workspace_lock_path(workspace_name)
    except ValueError:
        return False
    if not path.exists():
        return False
    handle = _open_lock_exclusively(path)
    if handle is None:
        return True
    _close(handle)
    return False


def remove_workspace_lock_if_free(workspace_name: str) -> bool:
    """Remove this workspace's lock file unless a live run holds it.

    Args:
        workspace_name: The workspace (or execution workspace) whose lock file
            should go. Both are workspace names as the launcher locks them.

    Returns:
        Whether the file was removed.
    """
    from adscan_core.paths import get_workspace_lock_path  # noqa: PLC0415

    try:
        path = get_workspace_lock_path(workspace_name)
    except ValueError:
        return False
    if not path.exists():
        return False
    handle = _open_lock_exclusively(path)
    if handle is None:
        return False
    try:
        try:
            path.unlink()
            return True
        except OSError:
            return False
    finally:
        _close(handle)


__all__ = ["remove_workspace_lock_if_free", "workspace_lock_is_held"]
