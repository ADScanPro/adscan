"""Dependency-light memory situation reader for the runtime process.

ADscan runs inside a container, so the real memory ceiling a process can use is
the **cgroup memory limit**, not host free RAM. When attack-path discovery
OOM-kills on a large domain the kill is a ``SIGKILL`` — no ``atexit``/signal
handler runs — so any diagnostic must be emitted (and flushed) *before* the
expensive allocation. This module supplies the memory figures that beacon
carries.

Everything here is best-effort: reading ``/sys/fs/cgroup`` or ``/proc`` must
never raise into the caller. Every public function returns ``None``/an unknown
sentinel on any error and lets the caller proceed. It lives in ``adscan_core``
(importable by both the host launcher and the container runtime) because the
launcher may want the same reader for its own preflight gating.

Sources, in order of preference for the container ceiling:

1. cgroup v2 — ``/sys/fs/cgroup/memory.max`` (value ``max`` means unlimited).
2. cgroup v1 — ``/sys/fs/cgroup/memory/memory.limit_in_bytes`` (a very large
   sentinel near ``PAGE_COUNTER_MAX`` means unlimited).
3. ``MemAvailable`` from ``/proc/meminfo`` (a HOST figure, not a container
   ceiling — the returned ``source`` says so).
4. Final fallback — ``psutil.virtual_memory()`` (``.total`` as the ceiling,
   ``.available`` as free-now). This is what carries the gate on **native
   Windows**, where there is no cgroup and no ``/proc``, so sources 1–3 all
   return nothing and the gate would otherwise never fire. ``psutil`` is
   cross-platform and already shipped (it backs ``pal.process.peak_rss_bytes``),
   so it also serves as a universal last resort on any host whose cgroup/proc
   files are unreadable. It runs LAST, so on native Linux the cgroup/proc
   sources still win and behaviour is byte-identical. Like the meminfo source
   it reports HOST figures — the ``source`` tag says so; never mix a host
   number with a container ceiling silently.

Current RSS is read from ``/proc/self/status`` (``VmRSS``), falling back to the
PAL peak-RSS reader (``ru_maxrss`` on POSIX, ``psutil`` on Windows — a
high-water mark, not live RSS).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from adscan_core.pal.process import peak_rss_bytes

# cgroup v2 unified-hierarchy mount root + the limit/usage file names within a
# cgroup directory. The process's OWN cgroup is resolved from ``/proc/self/cgroup``
# (see ``_cgroup_v2_dir``) and the files are read from THAT directory — reading the
# mount root directly is only a fallback. In a container the process sits at the
# cgroup namespace root, so the root files ARE the container's; but under a host
# sub-cgroup (``systemd-run --scope``, a nested slice) the root reports ``max``
# while the real cap lives in the process's own sub-directory.
_CGROUP_V2_ROOT = "/sys/fs/cgroup"
_CGROUP_V2_MAX_NAME = "memory.max"
_CGROUP_V2_CURRENT_NAME = "memory.current"
_PROC_SELF_CGROUP = "/proc/self/cgroup"
# Legacy fixed paths — the container-root fallback when the per-process directory
# cannot be resolved.
_CGROUP_V2_MAX = "/sys/fs/cgroup/memory.max"
_CGROUP_V2_CURRENT = "/sys/fs/cgroup/memory.current"
# cgroup v1 memory-controller limit + usage files.
_CGROUP_V1_LIMIT = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
_CGROUP_V1_USAGE = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
# Host-wide available memory.
_PROC_MEMINFO = "/proc/meminfo"
# Per-process status (VmRSS).
_PROC_SELF_STATUS = "/proc/self/status"

# cgroup v1 encodes "unlimited" as a very large sentinel — PAGE_COUNTER_MAX
# rounded down to the page size, i.e. 0x7FFFFFFFFFFFF000 == 9223372036854771712,
# which is just BELOW 2^63. Any limit at or above this floor is treated as
# unlimited rather than a real cap. 2^62 (~4.6 EiB) sits far above any realistic
# container memory limit yet well below the sentinel, so it never mistakes a real
# cap for unlimited nor a sentinel for a cap.
_CGROUP_V1_UNLIMITED_FLOOR = 1 << 62

# Source tags so a downstream reader knows whether a memory number is a container
# ceiling or a host figure. Never mix the two silently.
SOURCE_CGROUP_V2 = "cgroup_v2"
SOURCE_CGROUP_V1 = "cgroup_v1"
SOURCE_PROC_MEMINFO = "proc_meminfo"
#: psutil host figures (``virtual_memory().total`` / ``.available``). A HOST
#: number, not a container ceiling — kept a distinct tag so a downstream reader
#: never mistakes it for a cgroup cap. This is the source that carries the memory
#: gate on native Windows (no cgroup, no ``/proc``) and the universal last resort
#: elsewhere.
SOURCE_PSUTIL_HOST = "psutil_host"
SOURCE_UNKNOWN = "unknown"


@dataclass(frozen=True)
class MemorySituation:
    """A best-effort snapshot of the process memory situation.

    Attributes:
        available_bytes: Memory the process can still use before it is killed.
            For a cgroup source this is ``limit - current_usage``; for the
            ``/proc/meminfo`` fallback it is host ``MemAvailable``; for the
            psutil fallback it is host ``virtual_memory().available``. ``None``
            when nothing could be read.
        limit_bytes: The memory ceiling. The cgroup limit when readable; host
            physical total (``virtual_memory().total``) for the psutil source;
            else ``None`` (an unlimited/unreadable cgroup, or the meminfo
            fallback which has no ceiling figure).
        rss_bytes: Current process resident set size, or ``None``.
        source: One of the ``SOURCE_*`` tags identifying where
            ``available_bytes``/``limit_bytes`` came from — so a later reader
            knows whether the figure is a container ceiling or a host number.
    """

    available_bytes: Optional[int]
    limit_bytes: Optional[int]
    rss_bytes: Optional[int]
    source: str


def _read_text(path: str) -> Optional[str]:
    """Read a small pseudo-file, returning ``None`` on any error."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except (OSError, ValueError):
        return None


def _read_int_file(path: str) -> Optional[int]:
    """Read a single-integer pseudo-file (usage/current), or ``None``."""
    raw = _read_text(path)
    if raw is None:
        return None
    token = raw.strip()
    try:
        return int(token)
    except ValueError:
        return None


def _cgroup_v2_dir() -> Optional[str]:
    """Return the cgroup v2 directory for THIS process, or ``None``.

    Resolves the process's own cgroup from ``/proc/self/cgroup`` — a cgroup v2
    line is ``0::<path>`` where ``<path>`` is relative to the unified mount root
    (``/`` for the root cgroup). Joining it under :data:`_CGROUP_V2_ROOT` gives the
    directory whose ``memory.max`` is the cap that actually applies to this
    process, which the fixed root path misses under a host sub-cgroup. Returns
    ``None`` when the file is absent (cgroup v1, or no ``0::`` line) so the caller
    falls back to the fixed root path.
    """
    raw = _read_text(_PROC_SELF_CGROUP)
    if raw is None:
        return None
    for line in raw.splitlines():
        # Unified (v2) hierarchy line: ``0::/path/relative/to/root``.
        if line.startswith("0::"):
            rel = line[3:].strip()
            if not rel or rel == "/":
                return _CGROUP_V2_ROOT
            return _CGROUP_V2_ROOT + rel
    return None


def _read_cgroup_v2_limit_from(directory: str) -> Optional[int]:
    """Read ``memory.max`` from a resolved cgroup v2 directory, or ``None``.

    Returns ``None`` when the file is absent, unreadable, malformed, or set to
    ``max`` (unlimited).
    """
    raw = _read_text(directory.rstrip("/") + "/" + _CGROUP_V2_MAX_NAME)
    if raw is None:
        return None
    token = raw.strip()
    if not token or token == "max":
        return None
    try:
        value = int(token)
    except ValueError:
        return None
    return value if value > 0 else None


def _read_cgroup_v2_limit() -> Optional[int]:
    """Read the effective cgroup v2 memory limit in bytes.

    Prefers the process's OWN cgroup directory (resolved from
    ``/proc/self/cgroup``) and falls back to the fixed mount-root path. Returns
    ``None`` when no directory yields a real cap (unlimited/unreadable).
    """
    directory = _cgroup_v2_dir()
    if directory is not None:
        value = _read_cgroup_v2_limit_from(directory)
        if value is not None:
            return value
    return _read_cgroup_v2_limit_from(_CGROUP_V2_ROOT)


def _read_cgroup_v1_limit() -> Optional[int]:
    """Read the cgroup v1 memory limit in bytes.

    Returns ``None`` when the file is absent, unreadable, malformed, or set to
    the "unlimited" sentinel.
    """
    raw = _read_text(_CGROUP_V1_LIMIT)
    if raw is None:
        return None
    token = raw.strip()
    if not token:
        return None
    try:
        value = int(token)
    except ValueError:
        return None
    if value <= 0 or value >= _CGROUP_V1_UNLIMITED_FLOOR:
        return None
    return value


def _parse_meminfo_kb(raw: str, key: str) -> Optional[int]:
    """Extract a ``key: <n> kB`` line from meminfo-style text as bytes."""
    for line in raw.splitlines():
        if not line.startswith(key):
            continue
        parts = line.split()
        # Expected shape: ``MemAvailable:   12345 kB`` / ``VmRSS:  1234 kB``.
        for part in parts[1:]:
            if part.isdigit():
                return int(part) * 1024
        return None
    return None


def _read_mem_available() -> Optional[int]:
    """Read host ``MemAvailable`` from ``/proc/meminfo`` in bytes, or ``None``."""
    raw = _read_text(_PROC_MEMINFO)
    if raw is None:
        return None
    return _parse_meminfo_kb(raw, "MemAvailable:")


def _read_psutil_host_situation() -> Optional[tuple[int, int]]:
    """Return ``(available_bytes, total_bytes)`` from psutil, or ``None``.

    Reads ``psutil.virtual_memory()``: ``.available`` is the memory free right
    now (the real headroom the gate compares against), ``.total`` is the physical
    ceiling (analogous to a cgroup limit — used by the gate's scenario classifier
    to tell "resize the host" apart from "free memory held by another workload").
    Both are HOST figures.

    ``psutil`` is cross-platform, so this works on Windows AND Linux; it is wired
    as the LAST source in :func:`read_memory_situation`, so the Linux cgroup/proc
    paths still take precedence and only Windows (or a host with no readable
    cgroup/proc files) reaches it. Best-effort: any import/read error, or a
    non-positive ``.available``, returns ``None`` so the caller degrades to
    :data:`SOURCE_UNKNOWN` exactly as before — a broken reader must never break
    discovery.
    """
    try:
        import psutil

        vm = psutil.virtual_memory()
        available = int(vm.available)
        total = int(vm.total)
    except Exception:  # noqa: BLE001 — a memory beacon must never crash the caller.
        return None
    if available <= 0 or total <= 0:
        return None
    return available, total


def read_process_rss_bytes() -> Optional[int]:
    """Return current process RSS in bytes, best-effort.

    Prefers ``/proc/self/status`` (``VmRSS``, live RSS). Falls back to the PAL
    peak-RSS reader (``resource.getrusage(RUSAGE_SELF).ru_maxrss`` on POSIX, a
    high-water mark; ``psutil`` on Windows) when the status file is unavailable.
    Returns ``None`` when neither is readable.
    """
    raw = _read_text(_PROC_SELF_STATUS)
    if raw is not None:
        vmrss = _parse_meminfo_kb(raw, "VmRSS:")
        if vmrss is not None:
            return vmrss
    # High-water mark (peak RSS in bytes) via the PAL process seam — POSIX reads
    # ``resource.getrusage``, Windows falls back to ``psutil`` / ``None``.
    peak = peak_rss_bytes()
    if isinstance(peak, int) and peak > 0:
        return peak
    return None


def read_memory_situation() -> MemorySituation:
    """Return a best-effort :class:`MemorySituation` snapshot.

    Never raises. Resolves the container ceiling from cgroup v2, then cgroup v1,
    then host ``MemAvailable`` (``/proc/meminfo``), then — as the universal final
    fallback for hosts without cgroup/proc, chiefly **native Windows** —
    ``psutil.virtual_memory()`` (``.total`` ceiling, ``.available`` free-now).
    ``source`` is tagged so a later reader can tell a container ceiling apart
    from a host figure. ``available`` for a cgroup source is ``limit - usage``
    (clamped at 0); for the meminfo source it is host ``MemAvailable``; for the
    psutil source it is host ``.available``. The psutil source runs LAST so the
    Linux cgroup/proc paths are byte-identical.
    """
    rss = read_process_rss_bytes()

    try:
        v2_limit = _read_cgroup_v2_limit()
        if v2_limit is not None:
            # Read current usage from the SAME resolved directory the limit came
            # from, so available = limit - usage is consistent under a sub-cgroup.
            v2_dir = _cgroup_v2_dir()
            usage = _read_int_file(
                (v2_dir.rstrip("/") + "/" + _CGROUP_V2_CURRENT_NAME)
                if v2_dir is not None
                else _CGROUP_V2_CURRENT
            )
            available = max(v2_limit - usage, 0) if isinstance(usage, int) else None
            return MemorySituation(
                available_bytes=available,
                limit_bytes=v2_limit,
                rss_bytes=rss,
                source=SOURCE_CGROUP_V2,
            )

        v1_limit = _read_cgroup_v1_limit()
        if v1_limit is not None:
            usage = _read_int_file(_CGROUP_V1_USAGE)
            available = max(v1_limit - usage, 0) if isinstance(usage, int) else None
            return MemorySituation(
                available_bytes=available,
                limit_bytes=v1_limit,
                rss_bytes=rss,
                source=SOURCE_CGROUP_V1,
            )

        mem_available = _read_mem_available()
        if mem_available is not None:
            return MemorySituation(
                available_bytes=mem_available,
                limit_bytes=None,
                rss_bytes=rss,
                source=SOURCE_PROC_MEMINFO,
            )

        # Final fallback — psutil host figures. This is the ONLY source on native
        # Windows (no cgroup, no ``/proc``), and a universal last resort anywhere
        # cgroup/proc are unreadable. It runs LAST, so Linux is byte-identical.
        psutil_situation = _read_psutil_host_situation()
        if psutil_situation is not None:
            available, total = psutil_situation
            return MemorySituation(
                available_bytes=available,
                limit_bytes=total,
                rss_bytes=rss,
                source=SOURCE_PSUTIL_HOST,
            )
    except Exception:  # noqa: BLE001 — a memory beacon must never crash the caller.
        pass

    return MemorySituation(
        available_bytes=None,
        limit_bytes=None,
        rss_bytes=rss,
        source=SOURCE_UNKNOWN,
    )


def memory_situation_fields() -> dict[str, object]:
    """Return a flat, telemetry-safe dict of the current memory situation.

    Keys: ``mem_available_bytes``, ``mem_limit_bytes``, ``mem_rss_bytes``,
    ``mem_source``. Values are plain ints (or ``None``) plus a source string —
    no secrets, no PII. Best-effort; never raises.
    """
    situation = read_memory_situation()
    return {
        "mem_available_bytes": situation.available_bytes,
        "mem_limit_bytes": situation.limit_bytes,
        "mem_rss_bytes": situation.rss_bytes,
        "mem_source": situation.source,
    }


__all__ = (
    "MemorySituation",
    "read_memory_situation",
    "read_process_rss_bytes",
    "memory_situation_fields",
    "SOURCE_CGROUP_V2",
    "SOURCE_CGROUP_V1",
    "SOURCE_PROC_MEMINFO",
    "SOURCE_PSUTIL_HOST",
    "SOURCE_UNKNOWN",
)
