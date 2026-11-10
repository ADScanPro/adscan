"""Per-launcher runtime session: granular locks + per-session directories.

This module replaces the previous launcher-wide single-instance lock with
three orthogonal concerns so that two launchers targeting different
workspaces (for instance ``goad`` and ``htb``) can run side by side.

Concerns
--------

* **Per-launcher session directory** — each launcher process mints a
  fresh directory under ``~/.adscan/run/sessions/<token>/``. The
  privileged host-helper Unix socket is created inside that directory,
  and the directory itself is bind-mounted into the container at
  ``/run/adscan`` so the container code keeps reading from the fixed
  ``/run/adscan/host-helper.sock`` path. Two launchers therefore have
  two private sockets in two private host paths.

* **Per-workspace lock** — workspace persistence (workspace files,
  reports, deduped artefacts) cannot tolerate two writers at once. The
  lock keys on the workspace name only, so two workspaces are
  independent.

* **Install lock** — Docker ``pull``/``update`` is serialised launcher-wide
  to avoid duplicate or concurrent image pulls clobbering each other.

* **Atomic loopback-IP claim** — ADscan runs the in-container Unbound
  on a host loopback IP from a known pool (``--network host`` shares
  the network namespace). Without serialisation two launchers can both
  pick the same IP and the second container fails to bind. The claim
  here uses ``flock`` on a per-IP file so two launchers always end up
  on different IPs.

Locks are released either explicitly via :func:`release_lock` or
implicitly when the launcher process exits (``flock`` is held against
an open file description and the kernel releases it on close).
"""

from __future__ import annotations

import errno
import importlib
import json
import os
import secrets
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, IO

from adscan_core.paths import (
    get_adscan_home_dir,
    get_locks_dir as _core_get_locks_dir,
    get_resolver_locks_dir as _core_get_resolver_locks_dir,
    get_sessions_dir as _core_get_sessions_dir,
    get_workspace_lock_path as _core_get_workspace_lock_path,
    normalize_workspace_lock_name as _core_normalize_workspace_lock_name,
)


__all__ = (
    "LockHandle",
    "LOOPBACK_RESOLVER_POOL",
    "acquire_install_lock",
    "acquire_workspace_lock",
    "claim_resolver_ip",
    "cleanup_session_dir",
    "cleanup_stale_session_dirs",
    "sweep_orphaned_execution_workspaces",
    "sweep_stale_workspace_locks",
    "create_session_dir",
    "get_locks_dir",
    "get_resolver_locks_dir",
    "get_sessions_dir",
    "is_pid_alive",
    "normalize_workspace_name",
    "read_lock_metadata",
    "release_lock",
)


# Loopback pool for the in-container Unbound listener. ``--network host``
# shares the namespace so each container needs its own IP. The pool is
# intentionally larger than what a single user typically needs so that
# multi-instance scenarios (lab + customer + dev all at once) never run
# out of addresses; ``127.0.0.1`` is kept last so it is only chosen when
# every dedicated address is already in use.
LOOPBACK_RESOLVER_POOL: tuple[str, ...] = (
    *[f"127.0.0.{i}" for i in range(2, 32)],
    "127.0.0.1",
)


# Sub-paths inside ``run/sessions/<token>/``.
_SESSION_DIR_NAME_PREFIX = "pid-"
_SESSION_DIR_RAND_LEN = 8  # 4 hex bytes


# Bookkeeping: locks held by the current process. ``flock`` against
# different open file descriptions in the same process can succeed
# even though logically the lock is "ours", so we add an in-process
# registry to make double-acquire deterministic.
_HELD_LOCK_PATHS: set[Path] = set()


# ---------------------------------------------------------------------------
# directories
# ---------------------------------------------------------------------------


def get_sessions_dir() -> Path:
    """Return ``~/.adscan/run/sessions`` (created on demand)."""
    sessions_dir = _core_get_sessions_dir()
    sessions_dir.mkdir(parents=True, exist_ok=True)
    return sessions_dir


def get_locks_dir() -> Path:
    """Return ``~/.adscan/run/locks`` (created on demand)."""
    locks_dir = _core_get_locks_dir()
    locks_dir.mkdir(parents=True, exist_ok=True)
    return locks_dir


def get_resolver_locks_dir() -> Path:
    """Return ``~/.adscan/run/locks/resolvers`` (created on demand)."""
    resolver_locks_dir = _core_get_resolver_locks_dir()
    resolver_locks_dir.mkdir(parents=True, exist_ok=True)
    return resolver_locks_dir


# ---------------------------------------------------------------------------
# lock handles
# ---------------------------------------------------------------------------


@dataclass
class LockHandle:
    """Owned ``flock`` handle plus the path it covers and its metadata."""

    path: Path
    fd: IO[str]
    metadata: dict[str, Any] = field(default_factory=dict)
    # Remove the file when the lock is released. Set for workspace locks: their
    # name carries the workspace (often the client) name, so they must not
    # outlive the run.
    unlink_on_release: bool = False


def _format_lock_metadata(
    *,
    command_name: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "pid": os.getpid(),
        "command_name": str(command_name or "").strip() or "unknown",
        "started_at_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "adscan_home": str(get_adscan_home_dir()),
    }
    if extra:
        metadata.update(extra)
    return metadata


def _write_lock_metadata(handle: IO[str], metadata: dict[str, Any]) -> None:
    handle.seek(0)
    handle.truncate()
    json.dump(metadata, handle, indent=2, sort_keys=True)
    handle.write("\n")
    handle.flush()
    try:
        os.fsync(handle.fileno())
    except OSError:
        # fsync on tmpfs can fail on some filesystems; flock has already
        # taken effect so the on-disk durability is best-effort.
        pass


def read_lock_metadata(path: Path) -> dict[str, Any]:
    """Return the JSON metadata stored inside a lock file (best effort)."""
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return {}
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _same_file_still_at_path(handle: IO[str], path: Path) -> bool:
    """True when ``path`` still names the inode ``handle`` has open.

    A lock file that is unlinked on release can be removed between our
    ``open`` and our ``flock``; locking the orphaned inode would then lock
    nothing. Comparing the inode after the lock closes that race.
    """
    try:
        opened = os.fstat(handle.fileno())
        current = os.stat(path)
    except OSError:
        return False
    return (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino)


def _try_flock(
    path: Path,
    *,
    metadata: dict[str, Any],
    unlink_on_release: bool = False,
) -> LockHandle | None:
    """Attempt to acquire an exclusive non-blocking ``flock`` on ``path``.

    Returns the owning :class:`LockHandle` on success or ``None`` when
    the lock is already held by another process (or by this one).
    """
    if path in _HELD_LOCK_PATHS:
        return None
    if unlink_on_release:
        # The file may be unlinked by a releasing owner while we lock it;
        # retry until the inode we lock is the one at the path.
        for _attempt in range(5):
            handle = _try_flock_once(path, metadata=metadata)
            if handle is None:
                return None
            if _same_file_still_at_path(handle.fd, path):
                handle.unlink_on_release = True
                return handle
            _HELD_LOCK_PATHS.discard(path)
            try:
                handle.fd.close()
            except OSError:
                pass
        return None
    return _try_flock_once(path, metadata=metadata)


def _try_flock_once(
    path: Path,
    *,
    metadata: dict[str, Any],
) -> LockHandle | None:
    """One ``open`` + non-blocking ``flock`` attempt (see :func:`_try_flock`)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+", encoding="utf-8")  # noqa: SIM115
    # ``fcntl`` is POSIX-only (absent on Windows). Load it lazily so this module
    # imports cleanly off-platform. Without it the advisory single-instance lock is
    # a best-effort no-op: we still record the metadata and return a handle so the
    # caller proceeds. (A real Windows lock via ``msvcrt.locking`` is future work.)
    try:
        fcntl = importlib.import_module("fcntl")
    except ImportError:
        try:
            _write_lock_metadata(handle, metadata)
        except OSError:
            pass
        _HELD_LOCK_PATHS.add(path)
        return LockHandle(path=path, fd=handle, metadata=metadata)
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        try:
            handle.close()
        except OSError:
            pass
        return None
    except OSError:
        try:
            handle.close()
        except OSError:
            pass
        return None
    try:
        _write_lock_metadata(handle, metadata)
    except OSError:
        # We still hold flock; metadata is informational, not load-bearing.
        pass
    _HELD_LOCK_PATHS.add(path)
    return LockHandle(path=path, fd=handle, metadata=metadata)


def release_lock(handle: LockHandle | None) -> None:
    """Release a previously-acquired lock and clear its metadata."""
    if handle is None:
        return
    fd = handle.fd
    try:
        fd.seek(0)
        fd.truncate()
        fd.flush()
    except OSError:
        pass
    if handle.unlink_on_release:
        # Unlink while still holding the lock, so no other process can lock
        # this inode thinking it is the live one (see _same_file_still_at_path).
        try:
            handle.path.unlink()
        except OSError:
            pass
    try:
        fcntl = importlib.import_module("fcntl")
        fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
    except (ImportError, OSError):
        # No POSIX ``fcntl`` (Windows) or the unlock failed: closing the fd below
        # releases any lock anyway. Best-effort by design.
        pass
    try:
        fd.close()
    except OSError:
        pass
    _HELD_LOCK_PATHS.discard(handle.path)


# ---------------------------------------------------------------------------
# workspace & install locks
# ---------------------------------------------------------------------------


def normalize_workspace_name(name: str) -> str:
    """Canonical key used for workspace lock paths."""
    return _core_normalize_workspace_lock_name(name)


def _workspace_lock_path(workspace_name: str) -> Path:
    get_locks_dir()  # created on demand
    return _core_get_workspace_lock_path(workspace_name)


def acquire_workspace_lock(
    workspace_name: str,
    *,
    command_name: str,
) -> LockHandle | None:
    """Acquire the lock for a workspace name (per-workspace concurrency)."""
    if not normalize_workspace_name(workspace_name):
        return None
    path = _workspace_lock_path(workspace_name)
    metadata = _format_lock_metadata(
        command_name=command_name,
        extra={"workspace_name": normalize_workspace_name(workspace_name)},
    )
    return _try_flock(path, metadata=metadata, unlink_on_release=True)


def sweep_stale_workspace_locks() -> int:
    """Remove workspace lock files whose recorded owner is no longer running.

    Locks are unlinked on release, so a leftover is a run killed before it
    could release, or a lock written by an older launcher. Its file name keeps
    the workspace name. The sweep never takes the lock itself (a concurrent
    acquire must never see a false "busy"): it reads the owner PID written in
    the file and removes the file only when that PID is gone. A file with no
    readable owner is left alone (it may be one being created right now; the
    acquirer's inode check already copes with a file removed under it).

    Returns:
        How many stale lock files were removed.
    """
    removed = 0
    locks_dir = _core_get_workspace_lock_path("x").parent
    if not locks_dir.is_dir():
        return 0
    for path in locks_dir.glob("workspace-*.lock"):
        if path in _HELD_LOCK_PATHS:
            continue
        metadata = read_lock_metadata(path)
        try:
            owner_pid = int(metadata.get("pid"))
        except (TypeError, ValueError):
            continue
        if owner_pid <= 0 or is_pid_alive(owner_pid):
            continue
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def sweep_orphaned_execution_workspaces() -> int:
    """Remove execution workspaces whose own workspace is already gone.

    A scan writes its artifacts into a hidden ``.run_<logical>_<scanid>``
    directory that is a SIBLING of the logical workspace, so deleting the
    workspace never removed it and it kept a full copy of the engagement: the
    reports, the change ledger, the logs, any certificate with its private key.
    Deleting a workspace is the whole end-of-engagement procedure, so an
    execution workspace whose logical workspace no longer exists is a delete
    that only half happened; finishing it is completing what the operator
    already asked for, and they cannot be expected to find these by hand (the
    workspace listing hides every dot-prefixed directory).

    Only directories no run is using are removed (the lock, plus a window of
    write quiet), so a scan is never robbed of the directory it is writing
    into. Its lock file goes with it, because that file name carries the
    logical workspace name. Best-effort: never raises.

    Returns:
        How many execution workspaces were removed.
    """
    from adscan_core.execution_workspace import (  # noqa: PLC0415
        orphaned_execution_workspaces,
        remove_execution_workspaces,
    )
    from adscan_core.paths import get_workspaces_dir  # noqa: PLC0415

    try:
        workspaces_dir = get_workspaces_dir()
        if not workspaces_dir.is_dir():
            return 0
        removal = remove_execution_workspaces(
            orphaned_execution_workspaces(workspaces_dir)
        )
    except Exception:  # noqa: BLE001 - housekeeping never blocks a launch
        return 0
    return len(removal.removed)


def acquire_install_lock(*, command_name: str) -> LockHandle | None:
    """Serialise ``adscan install`` / ``adscan update`` pulls."""
    path = get_locks_dir() / "install.lock"
    metadata = _format_lock_metadata(
        command_name=command_name,
        extra={"scope": "install"},
    )
    return _try_flock(path, metadata=metadata)


# ---------------------------------------------------------------------------
# resolver IP claim
# ---------------------------------------------------------------------------


def _resolver_lock_path(ip: str) -> Path:
    return get_resolver_locks_dir() / f"resolver-{ip}.lock"


def claim_resolver_ip(
    *,
    skip_ips: set[str],
    command_name: str,
) -> tuple[str, LockHandle] | None:
    """Atomically reserve the first free loopback IP for the local resolver.

    The caller passes ``skip_ips`` for addresses already bound on the host
    (typically discovered via ``ss``); the function picks the first
    candidate that is both unbound and not held by another launcher.
    """
    skip_set = {str(ip).strip() for ip in (skip_ips or set()) if ip}
    for candidate in LOOPBACK_RESOLVER_POOL:
        if candidate in skip_set:
            continue
        metadata = _format_lock_metadata(
            command_name=command_name,
            extra={"scope": "resolver", "resolver_ip": candidate},
        )
        handle = _try_flock(_resolver_lock_path(candidate), metadata=metadata)
        if handle is not None:
            return candidate, handle
    return None


# ---------------------------------------------------------------------------
# session directories
# ---------------------------------------------------------------------------


def _generate_session_dir_name() -> str:
    rand = secrets.token_hex(_SESSION_DIR_RAND_LEN // 2)
    return f"{_SESSION_DIR_NAME_PREFIX}{os.getpid()}-{rand}"


def create_session_dir(*, command_name: str) -> Path:
    """Create a fresh session directory unique to this launcher process."""
    sessions_dir = get_sessions_dir()
    while True:
        candidate = sessions_dir / _generate_session_dir_name()
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            # Astronomically unlikely on a 4-byte random suffix, but cheap
            # to retry.
            continue
        else:
            break

    metadata = _format_lock_metadata(
        command_name=command_name,
        extra={"scope": "session_dir"},
    )
    try:
        (candidate / "metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        # Metadata is informational; the dir itself is what we need.
        pass
    return candidate


def cleanup_session_dir(path: Path) -> None:
    """Remove a session directory and everything inside it."""
    try:
        shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


def is_pid_alive(pid: int) -> bool:
    """Return True if a process with ``pid`` exists on this host."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but is owned by another user.
        return True
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        if exc.errno == errno.EPERM:
            return True
        return False
    return True


def _parse_pid_from_session_dir_name(name: str) -> int | None:
    if not name.startswith(_SESSION_DIR_NAME_PREFIX):
        return None
    try:
        # Expected layout: pid-<int>-<rand>
        _prefix, pid_str, _rand = name.split("-", 2)
    except ValueError:
        return None
    try:
        return int(pid_str)
    except ValueError:
        return None


def cleanup_stale_session_dirs() -> int:
    """Remove session directories whose owner PID no longer exists."""
    sessions_dir = get_sessions_dir()
    removed = 0
    for child in sessions_dir.iterdir():
        if not child.is_dir():
            continue
        owner_pid = _parse_pid_from_session_dir_name(child.name)
        if owner_pid is None:
            # Foreign directory we did not create; do not touch it.
            continue
        if is_pid_alive(owner_pid):
            continue
        cleanup_session_dir(child)
        removed += 1
    return removed
