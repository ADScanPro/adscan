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
)


__all__ = (
    "LockHandle",
    "LOOPBACK_RESOLVER_POOL",
    "acquire_install_lock",
    "acquire_workspace_lock",
    "claim_resolver_ip",
    "cleanup_session_dir",
    "cleanup_stale_session_dirs",
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


def _try_flock(
    path: Path,
    *,
    metadata: dict[str, Any],
) -> LockHandle | None:
    """Attempt to acquire an exclusive non-blocking ``flock`` on ``path``.

    Returns the owning :class:`LockHandle` on success or ``None`` when
    the lock is already held by another process (or by this one).
    """
    if path in _HELD_LOCK_PATHS:
        return None
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
    return str(name or "").strip().lower()


def _workspace_lock_path(workspace_name: str) -> Path:
    safe = normalize_workspace_name(workspace_name)
    if not safe:
        raise ValueError("workspace_name must be non-empty")
    # Restrict to a path-safe subset; the lock path is operator-visible.
    sanitized = "".join(c if c.isalnum() or c in "-._" else "_" for c in safe)
    return get_locks_dir() / f"workspace-{sanitized}.lock"


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
    return _try_flock(path, metadata=metadata)


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
