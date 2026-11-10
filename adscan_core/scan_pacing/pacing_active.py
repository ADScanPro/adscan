"""The session's active pacing, readable by code that has no shell.

Components deep in services build their configuration without a shell (the
host collector resolves its tuning in dataclass default factories), so the
resolved pacing is published process-wide, the same shell-less bridge pattern as
``dc_time._ACTIVE_CLOCK_SHELL``. One process runs one scan (the web worker
spawns ``adscan ci`` per scan), so a process-scoped value is the right scope;
background-job threads read the same object.

Entry points that set it: ``adscan ci`` after the scan config is resolved, the
REPL ``set pacing`` handler, and workspace load. Nothing else calls
:func:`set_active_pacing`.

When nothing was set, :func:`active_pacing` resolves the default on every call,
which reads the deprecated env vars at call time exactly as the components do
today, so unit tests and library callers see unchanged behaviour.
"""

from __future__ import annotations

import os
import threading

from adscan_core.scan_pacing.pacing_consumers import LEGACY_PACING_ENV
from adscan_core.scan_pacing.pacing_resolver import ResolvedPacing, resolve_pacing

_LOCK = threading.Lock()
_ACTIVE: ResolvedPacing | None = None
#: Default resolution cached per value of the deprecated env vars, so the
#: object is stable (the runtime binds to it) while env changes still apply.
_DEFAULT_CACHE: tuple[tuple[str | None, ...], ResolvedPacing] | None = None


def set_active_pacing(resolved: ResolvedPacing) -> None:
    """Publish the session's resolved pacing."""
    global _ACTIVE  # noqa: PLW0603 - deliberate process-scoped bridge
    with _LOCK:
        _ACTIVE = resolved


def clear_active_pacing() -> None:
    """Forget the published pacing (session end, tests)."""
    global _ACTIVE  # noqa: PLW0603 - deliberate process-scoped bridge
    with _LOCK:
        _ACTIVE = None


def active_pacing() -> ResolvedPacing:
    """Return the published pacing, or today's default resolved from the current env.

    The default is re-resolved only when one of the deprecated env vars changed,
    so repeated calls return the same object (cheap, and stable for the runtime)
    while a changed env var still takes effect at the next call, exactly as the
    components read their env vars at call time today.
    """
    global _DEFAULT_CACHE  # noqa: PLW0603 - deliberate process-scoped cache
    with _LOCK:
        current = _ACTIVE
        if current is not None:
            return current
        key = tuple(os.environ.get(name) for name in LEGACY_PACING_ENV)
        cached = _DEFAULT_CACHE
        if cached is not None and cached[0] == key:
            return cached[1]
    resolved = resolve_pacing()
    with _LOCK:
        _DEFAULT_CACHE = (key, resolved)
    return resolved


def has_active_pacing() -> bool:
    """True when an entry point published a pacing for this session."""
    with _LOCK:
        return _ACTIVE is not None


__all__ = [
    "active_pacing",
    "clear_active_pacing",
    "has_active_pacing",
    "set_active_pacing",
]
