"""One memory doctrine for every pipeline stage: the memory guard.

ADscan must scan a directory of any size on whatever machine runs it, LITE
included, and it must never be killed for memory nor return a truncated result
that reads as complete. The kernel's out-of-memory kill is a ``SIGKILL``: no
handler runs, no report is written, the operator learns nothing. So every stage
that holds a lot of memory watches the memory it is charged for and stops BEFORE
the kill, at a boundary that declares what it did not finish.

This module is the single primitive for that (spec
``docs/superpowers/specs/2026-11-12-inventory-first-graph-persistence.md`` §15.7):

* :class:`MemoryGuard` resolves the real ceiling through
  :mod:`adscan_core.memory_probe` (the cgroup limit inside a container, never
  host RAM) and samples live memory as the authority.
* :meth:`MemoryGuard.fits` answers, before a stage starts, whether a known
  amount of extra memory fits under the stop line.
* :meth:`MemoryGuard.tick` is called per unit of work. It is cheap: it samples
  only every ``sample_every`` calls and at most once per ``min_interval_s`` (every
  eligible tick once memory is past half the line), and raises
  :class:`MemoryCeilingReached` once the line is crossed.
* :meth:`MemoryGuard.over_line` is the non-raising question for worker threads
  and async tasks, the way scan control has ``should_stop()``.
* :class:`MemoryCeilingReached` derives from ``BaseException``, so the many
  ``except Exception`` blocks in the pipeline cannot swallow it and keep
  allocating, and every ``finally`` on the way out still runs.
* :func:`memory_bounded` is the ONLY catcher. At the stage boundary it switches
  to the stage's streamed mode when the stage has one; otherwise (or when even
  that does not fit) it stops, tells the operator the real cause, and records a
  coverage block through :mod:`adscan_core.reporting.resource_coverage`, the
  client-facing statement of how far the stage got.

What is measured, and against what
----------------------------------
**Inside a cgroup** (a container, a ``systemd-run`` scope with ``MemoryMax``) the
cgroup kills on EVERYTHING charged to it: this process, its children (Chromium
rendering a report, a password cracker, any subprocess) and tmpfs or shared
memory. So the guard measures ``max(own RSS, the cgroup's non-reclaimable
usage)``, the latter being ``memory.current`` minus the reclaimable file cache
(see :mod:`adscan_core.memory_probe`). Raw ``memory.current`` is never used as
the measure: it counts page cache the kernel drops before it kills, and sits
near the limit on any run that reads large files. The ceiling is the cgroup
limit, read once, capped by what the host can really give: when the limit was
set above the host's free memory, ``measured + host MemAvailable`` is the lower
and real ceiling. Host total RAM is never the ceiling.

**On a host without a cgroup limit** (a bare Linux process, native Windows) the
ceiling is the process's RSS plus what the host reports available right now,
re-read at every sample. A small process on a nearly full host would only cross
85% of that when free memory fell below about a sixth of its own RSS, so a
second condition applies there: the line is also crossed when the host's free
memory drops under :func:`free_memory_floor` (the larger of 256 MB and 5% of host
RAM). :meth:`MemoryGuard.fits` applies the same floor.

RSS comes from :func:`adscan_core.memory_probe.read_process_rss_bytes`: live
``VmRSS`` on Linux, the PAL live reader (``pal.process.current_rss_bytes``)
elsewhere, never the ``resource`` module directly.

Best-effort by construction: a reader that fails, or a host where no figure can
be read, leaves the guard inert (it never stops a stage on a blind read). A stage
that needs a hard bound on such a host keeps its own count cap, as the
attack-path DFS does.

Known limits of the sentinel (the last-resort thread, see ``start_memory_sentinel``):

* A single long C call that holds the GIL (one huge ``json.load``, a large regex
  over a big buffer) blocks the sentinel thread until the call returns, so it
  cannot sample or fire during it. The protection for such a call is
  :meth:`MemoryGuard.fits` before making it, with the size it will need.
* The thread freeze at fire time uses a profile hook installed in all threads
  (``threading.setprofile_all_threads``, Python 3.12+). It is verified on the
  source runtime; the PyArmor-obfuscated PRO image is NOT yet verified for it.
  Where the hook is unavailable or ineffective the sentinel still writes the
  marker and exits, but an allocating thread keeps running during the steps.

Threads: only the thread that runs the stage boundary may call :meth:`tick` or
:meth:`check`. A :class:`MemoryCeilingReached` raised on a worker thread dies
with that thread and never reaches :func:`memory_bounded`. A worker asks
:meth:`MemoryGuard.over_line` and returns early; the boundary thread's next
``tick`` raises.
"""

from __future__ import annotations

import gc
import os
import sys
import threading
import time
import traceback
from contextvars import ContextVar
from dataclasses import dataclass
from collections import deque
from typing import Any, Callable, Optional, Sequence

#: Fraction of the ceiling the measured memory may reach before a stage is
#: stopped. The kill is unrecoverable and memory is sampled, not watched
#: continuously, so the guard leaves headroom rather than aiming at the exact
#: limit. One value for the whole product: the attack-path projection gate and
#: its in-DFS bound use this one.
STOP_FRACTION = 0.85

#: Absolute floor of free host memory (no cgroup) under which the line is crossed
#: whatever the fraction says. See :func:`free_memory_floor`.
FREE_FLOOR_MIN_BYTES = 256 * 1024 * 1024

#: Share of host RAM the free-memory floor scales to on a large host.
FREE_FLOOR_HOST_FRACTION = 0.05

#: Default number of :meth:`MemoryGuard.tick` calls between two samples. A stage
#: whose unit of work is tiny (a DFS state) raises it; the default of one makes a
#: heavy unit (a host, an LDAP page) sample on every unit, with the time rate
#: limit below keeping a fast loop cheap.
DEFAULT_SAMPLE_EVERY = 1

#: Default minimum seconds between two samples taken by :meth:`MemoryGuard.tick`
#: while memory is far from the line. A sample reads a few ``/proc`` and cgroup
#: files (tens of microseconds); twenty a second is negligible.
DEFAULT_MIN_INTERVAL_S = 0.05

#: Once the measured memory passes this fraction of the stop line (or free host
#: memory is within four floors of the floor) the time rate limit is dropped and
#: every eligible tick samples: near the line a fast allocator could cover the
#: last stretch between two timed samples.
NEAR_LINE_FRACTION = 0.5

# Ceiling kinds, recorded on a reading so an operator line can say what the
# figure was.
CEILING_LIMIT = "limit"
CEILING_HOST_CAPPED = "host_capped"
CEILING_HEADROOM = "headroom"

# memory_probe source tags that carry a HOST figure, never a cgroup limit. Kept as
# literals so this module does not import memory_probe at load time.
_HOST_SOURCES = frozenset({"proc_meminfo", "psutil_host", "unknown"})
_PSUTIL_SOURCE = "psutil_host"


def free_memory_floor(host_total_bytes: Optional[int]) -> int:
    """Free host memory under which a stage stops: ``max(256 MB, 5% of host RAM)``."""
    if isinstance(host_total_bytes, int) and host_total_bytes > 0:
        return max(FREE_FLOOR_MIN_BYTES, int(host_total_bytes * FREE_FLOOR_HOST_FRACTION))
    return FREE_FLOOR_MIN_BYTES


def _int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


@dataclass(frozen=True)
class MemoryReading:
    """One sample of memory against the ceiling.

    Attributes:
        rss_bytes: Live resident set of this process, or ``None``.
        ceiling_bytes: What the measured memory can grow to (see the module
            docstring), or ``None`` when it could not be resolved.
        available_bytes: What the probe reported as still available, or ``None``.
        source: The :mod:`adscan_core.memory_probe` source tag.
        ceiling_kind: :data:`CEILING_LIMIT`, :data:`CEILING_HOST_CAPPED` or
            :data:`CEILING_HEADROOM` (``""`` when unresolved).
        stop_fraction: The fraction the verdict was taken against.
        measured_bytes: What is compared with the line: ``max(rss, cgroup
            non-reclaimable usage)`` inside a cgroup, RSS otherwise.
        cgroup_usage_bytes: The cgroup's non-reclaimable usage, or ``None``.
        free_bytes: Host free memory the floor is checked against, or ``None``
            when the floor does not apply (a cgroup limit below host free).
        floor_bytes: The free-memory floor, or ``None`` when it does not apply.
    """

    rss_bytes: Optional[int]
    ceiling_bytes: Optional[int]
    available_bytes: Optional[int]
    source: str
    ceiling_kind: str
    stop_fraction: float
    measured_bytes: Optional[int] = None
    cgroup_usage_bytes: Optional[int] = None
    free_bytes: Optional[int] = None
    floor_bytes: Optional[int] = None

    @property
    def _measured(self) -> Optional[int]:
        return self.measured_bytes if self.measured_bytes is not None else self.rss_bytes

    @property
    def usable(self) -> bool:
        """Whether a measure and a positive ceiling were read."""
        return (
            isinstance(self._measured, int)
            and isinstance(self.ceiling_bytes, int)
            and self.ceiling_bytes > 0
        )

    @property
    def stop_line_bytes(self) -> Optional[int]:
        """The measured memory at which the guard stops, or ``None``."""
        if not self.usable:
            return None
        return int(self.ceiling_bytes * self.stop_fraction)  # type: ignore[operator]

    @property
    def under_floor(self) -> bool:
        """Whether host free memory is under the floor (when the floor applies)."""
        return (
            self.floor_bytes is not None
            and self.free_bytes is not None
            and self.free_bytes < self.floor_bytes
        )

    @property
    def crossed(self) -> bool:
        """Whether the line is crossed. ``False`` on a blind read."""
        line = self.stop_line_bytes
        if line is None:
            return False
        return self._measured >= line or self.under_floor  # type: ignore[operator]

    @property
    def headroom_bytes(self) -> Optional[int]:
        """Bytes left before the line or the floor, whichever is closer (may be
        negative), or ``None`` when unknown."""
        line = self.stop_line_bytes
        if line is None:
            return None
        room = line - self._measured  # type: ignore[operator]
        if self.floor_bytes is not None and self.free_bytes is not None:
            room = min(room, self.free_bytes - self.floor_bytes)
        return room


_BLIND = MemoryReading(None, None, None, "unknown", "", STOP_FRACTION)


def _mb(value: Optional[int]) -> str:
    if not isinstance(value, int) or value < 0:
        return "an unknown amount"
    return f"{value / (1024 * 1024):,.0f} MB"


class MemoryCeilingReached(BaseException):
    """Raised when a stage crosses the stop line of its memory ceiling.

    A ``BaseException`` on purpose, like ``ScanAbortRequested``: the pipeline has
    many ``except Exception`` blocks that log and continue, and none of them may
    swallow this and keep allocating towards the kill. Only
    :func:`memory_bounded` catches it, at the stage boundary.

    Attributes:
        stage: The stage id the guard was built for.
        units_done: Units the stage finished before the stop.
        reading: The sample that crossed the line.
        cause: The terminal sentence naming the real cause.
        remedy: The terminal sentence naming what the operator can do.
        operator_message: ``cause`` and ``remedy`` together. Never shown to a
            client; the client reads the ``resource_coverage`` statement.
    """

    REMEDY = "Raise the memory available to ADscan and re-run to complete it."

    def __init__(self, *, stage: str, units_done: int, reading: MemoryReading) -> None:
        from adscan_core.reporting.resource_coverage import stage_label

        self.stage = stage
        self.units_done = int(units_done)
        self.reading = reading
        label = stage_label(stage)
        if reading.under_floor and not (
            reading.stop_line_bytes is not None
            and (reading.measured_bytes or reading.rss_bytes or 0) >= reading.stop_line_bytes
        ):
            self.cause = (
                f"{label} stopped because the machine had only "
                f"{_mb(reading.free_bytes)} of memory left free, under the "
                f"{_mb(reading.floor_bytes)} ADscan keeps in reserve so the "
                "system does not kill it."
            )
        else:
            measured = reading.measured_bytes or reading.rss_bytes
            self.cause = (
                f"{label} stopped at about {_mb(measured)} of memory, "
                f"{int(round(reading.stop_fraction * 100))}% of the "
                f"{_mb(reading.ceiling_bytes)} it can use, before the system "
                "would kill it."
            )
        self.remedy = self.REMEDY
        self.operator_message = f"{self.cause} {self.remedy}"
        super().__init__(self.operator_message)


def _gb(value: Optional[int]) -> str:
    """Round a byte count UP to a friendly GB figure for an operator remedy."""
    if not isinstance(value, int) or value <= 0:
        return "more memory"
    gb = value / (1024 * 1024 * 1024)
    if gb < 1:
        return f"{max(1, int(round(value / (1024 * 1024)))):,} MB"
    # Round up to the nearest 0.5 GB so the figure is a target that comfortably fits.
    return f"{(int(gb * 2) + 1) / 2:g} GB"


_WSL_CACHE: Optional[bool] = None


def _is_wsl() -> bool:
    """Whether ADscan runs under WSL (its memory is capped in ``.wslconfig``).

    Read once from ``/proc/version`` (the kernel string carries ``microsoft`` on
    WSL1/WSL2). Best-effort: anything unreadable is "not WSL".
    """
    global _WSL_CACHE
    if _WSL_CACHE is not None:
        return _WSL_CACHE
    verdict = False
    try:
        with open("/proc/version", encoding="utf-8", errors="ignore") as handle:
            verdict = "microsoft" in handle.read().lower()
    except Exception:  # noqa: BLE001 — a probe failure is just "not WSL"
        verdict = False
    _WSL_CACHE = verdict
    return verdict


def memory_scaleup_options(reading: Optional[MemoryReading]) -> tuple[str, ...]:
    """The ways to give ADscan more memory that APPLY to where it is running.

    Each line is client-safe English and names only an option that fits the
    detected environment — a container with a memory limit, WSL, a host whose
    own total RAM is the cap, or other workloads competing for memory. The
    hypervisor is never guessed: a generic virtual-machine line is offered only
    when the machine's own total memory is the ceiling.
    """
    if reading is None:
        return ()
    options: list[str] = []
    kind = reading.ceiling_kind
    source = str(reading.source or "")
    in_cgroup = source.startswith("cgroup")
    if kind == CEILING_LIMIT or (in_cgroup and kind != CEILING_HEADROOM):
        options.append(
            "This container has a memory limit. Raise it (for Docker, "
            "run with a larger --memory) and re-run."
        )
    if _is_wsl():
        options.append(
            "WSL caps the memory Linux can use. Raise it in your .wslconfig "
            "(for example memory=8GB) and restart WSL, then re-run."
        )
    if kind == CEILING_HOST_CAPPED and not in_cgroup:
        options.append(
            "The machine's own memory is the limit. If it is a virtual machine, "
            "raise the memory assigned to it; on a physical host, add RAM."
        )
    if kind == CEILING_HEADROOM or source == _PSUTIL_SOURCE:
        options.append(
            "Other programs are using this machine's memory. Close the heavy "
            "ones and re-run."
        )
    # Always leave at least one actionable line, even when nothing was detected.
    if not options:
        options.append(
            "Give ADscan more memory (a larger container limit, more RAM on the "
            "machine, or fewer other programs running) and re-run."
        )
    return tuple(options)


def estimate_need_phrase(
    *, estimate_bytes: Optional[int], ceiling_bytes: Optional[int]
) -> str:
    """Say how much memory the computation needs, as an estimate the figures support.

    With a projected peak, state it as an estimate (``about N GB``). Without one,
    all that is known is that it did not fit in the ceiling, so the honest claim
    is ``more than`` the ceiling. The figure is about MEMORY, never a verdict
    about the client's directory.
    """
    if isinstance(estimate_bytes, int) and estimate_bytes > 0:
        return f"needs about {_gb(estimate_bytes)} to finish"
    if isinstance(ceiling_bytes, int) and ceiling_bytes > 0:
        return f"needs more than the {_mb(ceiling_bytes)} ADscan could use here"
    return "needs more memory than was available here"


def build_memory_stop_lines(
    reached: "MemoryCeilingReached",
    *,
    unit: str,
    next_command: str,
    estimate_bytes: Optional[int] = None,
) -> list[str]:
    """The operator panel body for a memory stop: what happened, the figures, the
    ways to give more memory, and the exact next command.

    Honest about cause (memory on THIS machine) and never a verdict about the
    client's directory. The client reads the ``resource_coverage`` statement; this
    is the operator's copy.
    """
    from adscan_core.reporting.resource_coverage import stage_label  # noqa: PLC0415

    reading = reached.reading
    label = stage_label(reached.stage)
    done = f"{reached.units_done:,}"
    lines: list[str] = [reached.cause]
    lines.append(
        f"Kept: {done} {unit} already examined. The rest is reported as "
        "not evaluated, so nothing is hidden."
    )
    need = estimate_need_phrase(
        estimate_bytes=estimate_bytes,
        ceiling_bytes=getattr(reading, "ceiling_bytes", None),
    )
    lines.append(f"This computation {need}.")
    lines.append("")
    lines.append("To finish it, give ADscan more memory:")
    lines.extend(f"  • {opt}" for opt in memory_scaleup_options(reading))
    lines.append("")
    lines.append(f"Then {next_command} to finish {label.lower()}.")
    return lines


def build_memory_prestage_notice(
    *,
    projected_peak_bytes: Optional[int],
    ceiling_bytes: Optional[int],
    unit: str,
) -> str:
    """One line, before a stage starts, when the directory will not fit in memory.

    Said when the directory size is known (after collection) and the predictor
    expects the full computation not to fit: ADscan will examine a representative
    sample, and the operator is told roughly how much memory the full set needs.
    """
    had = (
        f"the {_mb(ceiling_bytes)} available"
        if isinstance(ceiling_bytes, int) and ceiling_bytes > 0
        else "the memory available"
    )
    full = (
        f"give it about {_gb(projected_peak_bytes)} for the full set"
        if isinstance(projected_peak_bytes, int) and projected_peak_bytes > 0
        else "give it more memory for the full set"
    )
    return (
        f"This directory is large: with {had}, ADscan will examine a "
        f"representative sample of {unit}; {full}."
    )


def _default_reader() -> Any:
    """Return the current memory situation from :mod:`adscan_core.memory_probe`.

    Looked up on the module at call time, so a test (or the DFS bound tests) can
    monkeypatch ``memory_probe.read_memory_situation``.
    """
    from adscan_core import memory_probe

    return memory_probe.read_memory_situation()


class MemoryGuard:
    """Watches memory against the ceiling for one stage.

    Build one per stage run. Use :meth:`fits` before work whose size is known,
    :meth:`tick` per unit of work ON THE BOUNDARY THREAD, :meth:`over_line` from
    worker threads and async tasks, :meth:`check` to sample right now, and
    :meth:`sample` for a reading without any raise (the in-DFS bound uses that,
    since it raises its own exception).
    """

    def __init__(
        self,
        stage: str,
        *,
        stop_fraction: float = STOP_FRACTION,
        sample_every: int = DEFAULT_SAMPLE_EVERY,
        min_interval_s: float = DEFAULT_MIN_INTERVAL_S,
        reader: Callable[[], Any] | None = None,
    ) -> None:
        self.stage = str(stage or "").strip() or "stage"
        self.stop_fraction = float(stop_fraction)
        self.units_done = 0
        self._sample_every = max(1, int(sample_every))
        self._min_interval_s = max(0.0, float(min_interval_s))
        self._reader = reader
        self._next_sample_at = self._sample_every
        self._last_sample_at: float | None = None
        self._near_line = False
        self._last_crossed = False
        self.last_reading: MemoryReading = _BLIND
        # The ceiling is read ONCE: a cgroup limit does not move during a run.
        self._limit_bytes: int | None = None
        situation = self._read()
        if situation is not None:
            self._limit_bytes = self._limit_from(situation)

    # -- reading -------------------------------------------------------------

    def _read(self) -> Any:
        try:
            if self._reader is not None:
                return self._reader()
            return _default_reader()
        except Exception:  # noqa: BLE001 — a memory read must never break a stage.
            return None

    @staticmethod
    def _limit_from(situation: Any) -> int | None:
        """Return the fixed limit a situation carries, or ``None`` for a host figure."""
        source = str(getattr(situation, "source", "") or "")
        if source in _HOST_SOURCES:
            return None
        limit = _int_or_none(getattr(situation, "limit_bytes", None))
        return limit if limit is not None and limit > 0 else None

    def sample(self) -> MemoryReading:
        """Take one reading now. Never raises; a blind read is ``usable=False``."""
        situation = self._read()
        if situation is None:
            reading = MemoryReading(None, None, None, "unknown", "", self.stop_fraction)
            self.last_reading = reading
            return reading
        source = str(getattr(situation, "source", "") or "unknown")
        rss = _int_or_none(getattr(situation, "rss_bytes", None))
        if rss is not None and rss < 0:
            rss = None
        available = _int_or_none(getattr(situation, "available_bytes", None))
        cgroup_usage = _int_or_none(getattr(situation, "cgroup_usage_bytes", None))
        host_available = _int_or_none(getattr(situation, "host_available_bytes", None))
        host_total = _int_or_none(getattr(situation, "host_total_bytes", None))
        if host_total is None and source == _PSUTIL_SOURCE:
            host_total = _int_or_none(getattr(situation, "limit_bytes", None))

        limit = self._limit_bytes
        if limit is None:
            limit = self._limit_from(situation)
            if limit is not None:
                self._limit_bytes = limit

        ceiling: int | None = None
        kind = ""
        measured: int | None = rss
        free: int | None = None
        floor: int | None = None
        if limit is not None:
            # Everything the cgroup is charged for counts, children included.
            candidates = [v for v in (rss, cgroup_usage) if v is not None]
            measured = max(candidates) if candidates else None
            ceiling, kind = limit, CEILING_LIMIT
            if measured is not None and host_available is not None:
                host_cap = measured + max(host_available, 0)
                if host_cap < limit:
                    # A limit above what the host has free does not make that
                    # memory exist: the host is the real ceiling, and its floor
                    # applies.
                    ceiling, kind = host_cap, CEILING_HOST_CAPPED
                    free, floor = max(host_available, 0), free_memory_floor(host_total)
        elif rss is not None and available is not None and available >= 0:
            # Host figure: what this process can grow to is what it holds plus
            # what the host still has free. Host total RAM is never the ceiling.
            ceiling, kind = rss + available, CEILING_HEADROOM
            free, floor = available, free_memory_floor(host_total)
        reading = MemoryReading(
            rss_bytes=rss,
            ceiling_bytes=ceiling,
            available_bytes=available,
            source=source,
            ceiling_kind=kind,
            stop_fraction=self.stop_fraction,
            measured_bytes=measured,
            cgroup_usage_bytes=cgroup_usage,
            free_bytes=free,
            floor_bytes=floor,
        )
        self.last_reading = reading
        return reading

    def _note(self, reading: MemoryReading) -> None:
        """Remember when and how close the last sample was, for the rate limit."""
        self._last_sample_at = time.monotonic()
        self._last_crossed = reading.crossed
        line = reading.stop_line_bytes
        near = line is not None and (
            (reading.measured_bytes or reading.rss_bytes or 0) >= int(line * NEAR_LINE_FRACTION)
        )
        if reading.floor_bytes is not None and reading.free_bytes is not None:
            near = near or reading.free_bytes < 4 * reading.floor_bytes
        self._near_line = near

    def _rate_limited(self) -> bool:
        return (
            self._min_interval_s > 0.0
            and self._last_sample_at is not None
            and not self._near_line
            and time.monotonic() - self._last_sample_at < self._min_interval_s
        )

    # -- decisions -----------------------------------------------------------

    def fits(self, projected_bytes: int) -> bool:
        """Whether ``projected_bytes`` more fits under the line right now.

        ``True`` when the measured memory plus the projection stays at or under
        ``STOP_FRACTION`` of the ceiling AND, where the free-memory floor applies,
        the host keeps at least the floor free after the projection. Also
        ``True`` on a blind read: without a ceiling the guard cannot say no, and
        a stage must not be refused on a reader that failed.
        """
        try:
            projected = max(int(projected_bytes), 0)
        except (TypeError, ValueError):
            projected = 0
        reading = self.sample()
        line = reading.stop_line_bytes
        if line is None:
            return True
        measured = reading.measured_bytes if reading.measured_bytes is not None else reading.rss_bytes
        if measured + projected > line:  # type: ignore[operator]
            return False
        if reading.floor_bytes is not None and reading.free_bytes is not None:
            return reading.free_bytes - projected >= reading.floor_bytes
        return True

    def headroom_bytes(self) -> int | None:
        """Bytes left before the line or the floor right now, or ``None``."""
        return self.sample().headroom_bytes

    def over_line(self) -> bool:
        """Whether the line is crossed, WITHOUT raising. For worker threads.

        The non-raising twin of :meth:`check`, the way scan control has
        ``should_stop()``: a worker thread or an async task asks it per unit and
        returns early, and the boundary thread's next :meth:`tick` raises. Rate
        limited like :meth:`tick` (the last verdict is returned inside the
        interval), so it is cheap to call often. Safe to call from any thread:
        the worst a race does is one extra sample.
        """
        if self._rate_limited():
            return self._last_crossed
        reading = self.sample()
        self._note(reading)
        return reading.crossed

    def check(self) -> MemoryReading:
        """Sample now and raise :class:`MemoryCeilingReached` if over the line.

        Boundary thread only: raised on a worker thread it dies with the thread.
        """
        reading = self.sample()
        self._note(reading)
        if reading.crossed:
            raise MemoryCeilingReached(
                stage=self.stage, units_done=self.units_done, reading=reading
            )
        return reading

    def tick(self, units: int = 1) -> None:
        """Account ``units`` of finished work; sample when the rate limit allows.

        Boundary thread only (see the module docstring). Cheap: an integer
        compare per call until ``sample_every`` calls have passed, then one
        monotonic-clock read; the sample itself runs at most once per
        ``min_interval_s`` while memory is far from the line, and on every
        eligible tick near it.

        Raises:
            MemoryCeilingReached: the line was crossed.
        """
        self.units_done += units
        if self.units_done < self._next_sample_at:
            return
        self._next_sample_at = self.units_done + self._sample_every
        if self._rate_limited():
            return
        self.check()

    def progress(self, done: int) -> None:
        """Set the absolute number of finished units (no sampling)."""
        try:
            self.units_done = max(int(done), 0)
        except (TypeError, ValueError):
            return
        if self._next_sample_at <= self.units_done:
            self._next_sample_at = self.units_done + 1

    def stop_now(self) -> None:
        """Raise :class:`MemoryCeilingReached` for a stop a worker already decided.

        Boundary thread only. A stage whose workers stopped on
        :meth:`over_line` (a host sweep, a paged directory read) returns its
        partial result to the boundary thread; memory may already be back under
        the line by then (the workers released their buffers), so a fresh
        :meth:`check` would let the stop go undeclared. This raises with the
        reading that crossed the line, so the boundary declares it.

        Raises:
            MemoryCeilingReached: always.
        """
        reading = self.last_reading
        if not reading.crossed:
            fresh = self.sample()
            if fresh.usable:
                reading = fresh
        raise MemoryCeilingReached(
            stage=self.stage, units_done=self.units_done, reading=reading
        )


def _release_traceback(tb: Any) -> None:
    """Clear the locals of every finished frame in ``tb`` and cut the chain.

    ``traceback.clear_frames`` skips a frame that is still executing (the frame
    of the ``with`` statement), so only the frames of the functions the stage body
    called lose their locals. Best-effort; never raises.
    """
    if tb is None:
        return
    try:
        traceback.clear_frames(tb)
    except Exception:  # noqa: BLE001
        pass
    try:
        tb.tb_next = None
    except Exception:  # noqa: BLE001
        pass


def _release_memory() -> None:
    """Collect garbage and hand freed heap back to the OS, best-effort."""
    try:
        gc.collect()
    except Exception:  # noqa: BLE001
        pass
    try:
        from adscan_core.pal.process import release_free_heap

        release_free_heap()
    except Exception:  # noqa: BLE001
        pass


def _print_operator_warning(message: str) -> None:
    try:
        from adscan_core.rich_output import print_warning

        print_warning(message)
    except Exception:  # noqa: BLE001 — a console failure must not mask the stop.
        pass


def _print_operator_info(message: str) -> None:
    try:
        from adscan_core.rich_output import print_info

        print_info(message)
    except Exception:  # noqa: BLE001
        pass


#: The one next step a memory stop points the operator at — the resume front door
#: recomputes the stopped stage once there is more memory (every bounded stage is
#: resumable through it: a stopped collection, graph build, export, attack-path
#: discovery or report render is re-run on reopen).
RESUME_NEXT_COMMAND = "reopen this workspace and choose Resume"


def print_memory_stop_panel(
    reached: "MemoryCeilingReached",
    *,
    unit: str,
    next_command: str = RESUME_NEXT_COMMAND,
    estimate_bytes: Optional[int] = None,
) -> None:
    """Render the one operator panel for a memory stop (best-effort, never raises).

    Falls back to the single warning line when a panel cannot be drawn, so a stop
    always tells the operator what to do next.
    """
    lines = build_memory_stop_lines(
        reached, unit=unit, next_command=next_command, estimate_bytes=estimate_bytes
    )
    try:
        from adscan_core.reporting.resource_coverage import stage_label
        from adscan_core.rich_output import print_panel

        print_panel(
            "\n".join(lines),
            title=f"[bold]» Not enough memory to finish {stage_label(reached.stage).lower()}[/bold]",
            border_style="yellow",
            padding=(1, 2),
        )
    except Exception:  # noqa: BLE001 — a panel failure must never mask the stop.
        _print_operator_warning(" ".join(line for line in lines if line.strip()))


#: Outcomes of a :func:`memory_bounded` stage.
#: The guard of the memory-bounded stage the current context runs in, bound by
#: :class:`MemoryBoundedStage` for the duration of its body. Lets code deep in a
#: stage (a paged directory read, a per-host sweep) watch the stage's memory
#: without a guard threaded through every signature. ``None`` outside a stage.
_ACTIVE_GUARD: ContextVar["MemoryGuard | None"] = ContextVar(
    "adscan_memory_guard_active", default=None
)


def current_guard() -> "MemoryGuard | None":
    """The guard of the enclosing :func:`memory_bounded` stage, or ``None``.

    Read it on the thread that runs the stage (context variables do not cross
    into a worker thread's own context); hand the object to workers, which call
    :meth:`MemoryGuard.over_line` only.
    """
    return _ACTIVE_GUARD.get()


def check_enclosing_stage() -> None:
    """Stop the enclosing :func:`memory_bounded` stage if memory crossed its line.

    For a helper deep inside a stage that holds no guard and counts no units of
    its own (a classification loop shared by several stages): it asks the
    stage's guard, rate limited like :meth:`MemoryGuard.over_line`, and raises
    the stage's :class:`MemoryCeilingReached` when the line is crossed. The
    stage's unit count is untouched, so the coverage statement keeps counting
    what the stage itself counts. A no-op outside a stage.

    Boundary thread only, like :meth:`MemoryGuard.tick`.

    Raises:
        MemoryCeilingReached: the enclosing stage's line was crossed.
    """
    guard = _ACTIVE_GUARD.get()
    if guard is not None and guard.over_line():
        guard.stop_now()


OUTCOME_COMPLETE = "complete"
OUTCOME_STREAMED = "streamed"
OUTCOME_STOPPED = "stopped"


class MemoryBoundedStage:
    """The stage boundary: the one place a :class:`MemoryCeilingReached` is caught.

    Use through :func:`memory_bounded`, whose body must be a single function
    call (see there). Inside the ``with`` block it behaves like the stage's
    :class:`MemoryGuard` (``tick``, ``check``, ``fits``, ``over_line``,
    ``progress``, ``units_done``). After the block, :attr:`outcome` says how the
    stage ended:

    * :data:`OUTCOME_COMPLETE` — the body finished.
    * :data:`OUTCOME_STREAMED` — the body stopped at the ceiling and the stage's
      streamed mode ran to the end instead; its return value is :attr:`result`.
    * :data:`OUTCOME_STOPPED` — nothing more fitted. :attr:`coverage` holds the
      ``resource_coverage`` block, already handed to ``record`` when given.

    Any other exception, including ``KeyboardInterrupt`` and a scan abort,
    propagates untouched.
    """

    def __init__(
        self,
        stage: str,
        *,
        unit: str,
        total: int | None = None,
        streamed: Callable[["MemoryBoundedStage"], Any] | None = None,
        record: Callable[[dict[str, Any]], Any] | None = None,
        announce: bool = True,
        estimate_bytes: int | None = None,
        **guard_kwargs: Any,
    ) -> None:
        self.stage = str(stage or "").strip() or "stage"
        self.unit = str(unit or "").strip() or "items"
        self.total = total
        self.outcome: str | None = None
        self.coverage: dict[str, Any] | None = None
        self.result: Any = None
        self.reached: MemoryCeilingReached | None = None
        self._streamed = streamed
        self._record = record
        self._announce = bool(announce)
        # Optional projected peak (a stage with a predictor, e.g. attack paths)
        # so the stop panel can say "needs about N GB"; None → "more than <ceiling>".
        self._estimate_bytes = (
            int(estimate_bytes) if isinstance(estimate_bytes, int) else None
        )
        self._guard_kwargs = guard_kwargs
        self.guard = MemoryGuard(self.stage, **guard_kwargs)
        self._token: Any = None

    # -- guard proxy -----------------------------------------------------------

    @property
    def units_done(self) -> int:
        return self.guard.units_done

    def tick(self, units: int = 1) -> None:
        self.guard.tick(units)

    def check(self) -> MemoryReading:
        return self.guard.check()

    def fits(self, projected_bytes: int) -> bool:
        return self.guard.fits(projected_bytes)

    def over_line(self) -> bool:
        return self.guard.over_line()

    def progress(self, done: int) -> None:
        self.guard.progress(done)

    # -- boundary --------------------------------------------------------------

    def __enter__(self) -> "MemoryBoundedStage":
        self._token = _ACTIVE_GUARD.set(self.guard)
        _push_stage(self)
        return self

    def _unbind(self) -> None:
        token = getattr(self, "_token", None)
        if token is not None:
            self._token = None
            try:
                _ACTIVE_GUARD.reset(token)
            except ValueError:  # entered in another context: leave it be
                _ACTIVE_GUARD.set(None)

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._unbind()
        # The stage stays on the stack while its streamed mode or its declaration
        # runs inside ``__exit__``: the sentinel must still name it.
        try:
            return self._exit_boundary(exc, tb)
        finally:
            _pop_stage(self)

    def _exit_boundary(self, exc, tb) -> bool:
        if exc is None:
            self.outcome = OUTCOME_COMPLETE
            return False
        if not isinstance(exc, MemoryCeilingReached):
            return False
        self.reached = exc
        # Release what the aborted stage built before anything else allocates.
        # The traceback holds the frames of every function the body called, and
        # through them every local those functions built: clear their locals,
        # then cut the chain below this frame. The ``with`` statement's OWN frame
        # (the caller's) is still executing and cannot be cleared, which is why
        # the body must be a single function call (see ``memory_bounded``).
        _release_traceback(tb)
        exc.__traceback__ = None
        del tb
        _release_memory()
        if self._streamed is not None:
            if self._announce:
                _print_operator_info(
                    f"{exc.cause} Continuing in streamed mode, which holds less "
                    "in memory at once."
                )
            # A fresh guard: the streamed mode counts its own units from zero.
            self.guard = MemoryGuard(self.stage, **self._guard_kwargs)
            token = _ACTIVE_GUARD.set(self.guard)
            try:
                self.result = self._streamed(self)
            except MemoryCeilingReached as again:
                _release_traceback(again.__traceback__)
                again.__traceback__ = None
                self.reached = again
                _release_memory()
            else:
                self.outcome = OUTCOME_STREAMED
                return True
            finally:
                _ACTIVE_GUARD.reset(token)
        self._declare(self.reached)
        return True

    def _declare(self, reached: MemoryCeilingReached) -> None:
        from adscan_core.reporting.resource_coverage import (
            REASON_MEMORY,
            build_resource_coverage,
        )

        self.outcome = OUTCOME_STOPPED
        examined = reached.units_done
        self.coverage = build_resource_coverage(
            stage=self.stage,
            unit=self.unit,
            examined=examined,
            total=self.total,
            reason=REASON_MEMORY,
        )
        if self._announce:
            # One operator panel: what stopped and what was kept, how much memory
            # ADscan had and how much this computation needs, the ways to give it
            # more that apply here, and the exact next command (reopen and resume,
            # which recomputes this stage). The client reads the coverage
            # statement; this is the operator's copy.
            print_memory_stop_panel(
                reached,
                unit=self.unit,
                estimate_bytes=self._estimate_bytes,
            )
        if self._record is not None:
            try:
                self._record(self.coverage)
            except Exception as exc:  # noqa: BLE001 — the stop must still return cleanly.
                try:
                    from adscan_core import telemetry
                    from adscan_core.rich_output import print_exception

                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
                except Exception:  # noqa: BLE001
                    pass


def memory_bounded(
    stage: str,
    *,
    unit: str,
    total: int | None = None,
    streamed: Callable[[MemoryBoundedStage], Any] | None = None,
    record: Callable[[dict[str, Any]], Any] | None = None,
    announce: bool = True,
    estimate_bytes: int | None = None,
    **guard_kwargs: Any,
) -> MemoryBoundedStage:
    """Open a memory-bounded stage: the only catcher of :class:`MemoryCeilingReached`.

    The stage body MUST be one function call, so everything the stage builds
    lives in that function's frame::

        def run_graph_build(stage):
            graph = new_graph()
            for edge in edges:
                add(graph, edge)
                stage.tick()
            return graph

        with memory_bounded(STAGE_GRAPH_BUILD, unit="edges", total=n,
                            streamed=run_graph_build_streamed,
                            record=persist_block) as stage:
            result = run_graph_build(stage)
        if stage.outcome == OUTCOME_STOPPED:
            ...  # the graph is partial and stage.coverage says so

    Why: the streamed mode and the declaration run inside ``__exit__``, while the
    frame that holds the ``with`` statement is still alive. Locals bound directly
    in the ``with`` body belong to that frame and cannot be freed until it
    returns, so a streamed mode would start with the aborted attempt's memory
    still held and stop at once. A function called from the body has finished
    when the stop reaches the boundary, so its locals are released (the
    boundary clears them from the traceback) before the streamed mode starts.

    Threads: call ``stage.tick()`` only from the thread that entered the
    ``with``. Workers ask ``stage.guard.over_line()`` and return early.

    Args:
        stage: A ``STAGE_*`` id from :mod:`adscan_core.reporting.resource_coverage`.
        unit: Plural noun for the unit of work (``"edges"``, ``"hosts"``).
        total: Units the stage has in front of it, when known.
        streamed: The stage's streamed or chunked mode, called once with this
            stage object after the body stopped and its frames were released.
            It runs under a fresh guard; if it also crosses the line the stage
            stops and declares.
        record: Called with the ``resource_coverage`` block when the stage stops,
            to persist it. A failure there is logged and does not escape.
        announce: Print the operator stop panel (what stopped and was kept, the
            memory figures, the ways to give more, and the next command). On by
            default.
        estimate_bytes: A projected peak for this stage (a stage with a predictor,
            e.g. attack paths) so the stop panel says "needs about N GB". When
            omitted the panel says "needs more than" the ceiling.
        **guard_kwargs: Passed to :class:`MemoryGuard` (``stop_fraction``,
            ``sample_every``, ``min_interval_s``, ``reader``).
    """
    return MemoryBoundedStage(
        stage,
        unit=unit,
        total=total,
        streamed=streamed,
        record=record,
        announce=announce,
        estimate_bytes=estimate_bytes,
        **guard_kwargs,
    )


# --- The stage stack --------------------------------------------------------------
#
# Which memory-bounded stage is running right now, process-wide. ``memory_bounded``
# pushes on enter and pops on exit; the sentinel reads the innermost entry to name
# the stage in its stop record. Stages entered from worker threads go on the same
# stack: the sentinel stops the whole process, so the most recently entered stage
# is the one it names.

#: Stage id the sentinel records when no memory-bounded stage is running.
UNKNOWN_STAGE = "unknown"

_STAGE_STACK: list[MemoryBoundedStage] = []
_STAGE_STACK_LOCK = threading.Lock()


def _push_stage(stage: MemoryBoundedStage) -> None:
    with _STAGE_STACK_LOCK:
        _STAGE_STACK.append(stage)


def _pop_stage(stage: MemoryBoundedStage) -> None:
    """Remove THIS stage (by identity, last occurrence): threads exit out of order."""
    with _STAGE_STACK_LOCK:
        for index in range(len(_STAGE_STACK) - 1, -1, -1):
            if _STAGE_STACK[index] is stage:
                del _STAGE_STACK[index]
                return


def active_stages() -> tuple[MemoryBoundedStage, ...]:
    """Snapshot of the running memory-bounded stages, outermost first."""
    with _STAGE_STACK_LOCK:
        return tuple(_STAGE_STACK)


def current_stage() -> MemoryBoundedStage | None:
    """The innermost running memory-bounded stage, or ``None`` outside any."""
    with _STAGE_STACK_LOCK:
        return _STAGE_STACK[-1] if _STAGE_STACK else None


# --- The last-resort sentinel ------------------------------------------------------
#
# The guard only acts where a stage ticks. A stage that forgot to tick, or one
# allocation that jumps past the stop line between two ticks, would still reach the
# kernel's kill, and a killed process declares nothing. The sentinel is a daemon
# thread that samples the SAME reading the guard uses and, at a hard line above the
# guard's stop line, writes the stop record and exits the process itself with the
# incomplete-run code. A declared incomplete run instead of an undeclared corpse.
#
# It never starts at import: only an explicit ``start_memory_sentinel`` call, made
# by a CLI entry point, starts it. The web backend must never call it (an
# ``os._exit`` there would take down the web server).

#: Fraction of the ceiling at which the sentinel stops the process.
SENTINEL_HARD_FRACTION = 0.95

#: Seconds between two sentinel samples while memory is under the guard's line.
SENTINEL_INTERVAL_S = 0.25

#: Seconds between two sentinel samples once memory is past the guard's line.
SENTINEL_FAST_INTERVAL_S = 0.05

#: Shortest interval the adaptive cadence may reach. Between samples the sentinel
#: projects the time to the hard line from the growth it measured, and samples
#: again after a quarter of it: a fast allocator can cross the last few percent
#: of a small cgroup in milliseconds.
SENTINEL_MIN_INTERVAL_S = 0.002

#: Allocation rate the cadence assumes before it has measured any: a pure-Python
#: loop building objects reaches about 1.3 GB/s on current hardware (measured
#: 300 MB in 0.32 s), so 2 GB/s covers it with margin.
SENTINEL_ASSUMED_MAX_GROWTH_BPS = 2 * 1024 * 1024 * 1024

#: Past the guard's line, the sentinel also fires when the measured growth would
#: reach the full ceiling within this many seconds (a sample plus the freeze).
SENTINEL_REACTION_S = 0.05

#: The growth rate is measured over at least this many seconds, and over at least
#: two sampling intervals, so the noise of one short interval cannot fire.
SENTINEL_RATE_MIN_SPAN_S = 0.02

#: How many recent samples the rate keeps (enough to span the minimum at the
#: 2 ms floor of the cadence).
SENTINEL_RATE_HISTORY = 32

#: GIL switch interval the sentinel sets while memory is near the line (the
#: interpreter default is 5 ms). Reading the memory files releases the GIL a few
#: times per sample, and at the default each hand-back could give an allocating
#: thread another 5 ms. Restored when memory falls back under the line.
SENTINEL_NEAR_SWITCH_INTERVAL_S = 0.0005

#: Name prefix of every thread the sentinel runs. The freeze at fire time lets
#: exactly these threads continue.
SENTINEL_THREAD_PREFIX = "adscan-memory-sentinel"

#: Time budgets of the steps the sentinel runs before it exits. A step that does
#: not finish in its budget is abandoned (its thread dies with the process).
SENTINEL_OPERATOR_LINE_BUDGET_S = 1.0
SENTINEL_STOP_RECORD_BUDGET_S = 2.0
SENTINEL_EXPORT_MARK_BUDGET_S = 3.0
SENTINEL_FLUSH_BUDGET_S = 1.0

#: Why the sentinel fired.
SENTINEL_REASON_CEILING = "ceiling"
SENTINEL_REASON_FREE_MEMORY = "free_memory"


@dataclass(frozen=True)
class SentinelStop:
    """What the sentinel hands to the registered callbacks when it fires.

    Attributes:
        stage: The innermost running stage id, or :data:`UNKNOWN_STAGE`.
        unit: That stage's unit noun (``"items"`` when unknown).
        units_done: Units that stage had finished.
        total: Units it had in front of it, when known.
        reason: :data:`SENTINEL_REASON_CEILING` or :data:`SENTINEL_REASON_FREE_MEMORY`.
        reading: The sample that fired.
        coverage: The ``resource_coverage`` block to persist (client wording).
        operator_message: The terminal line (real cause and remedy).
    """

    stage: str
    unit: str
    units_done: int
    total: int | None
    reason: str
    reading: MemoryReading
    coverage: dict[str, Any]
    operator_message: str


def sentinel_verdict(reading: MemoryReading, hard_fraction: float = SENTINEL_HARD_FRACTION) -> str:
    """Return why the sentinel must fire on ``reading``, or ``""`` when it must not.

    Fires when the measured memory reaches ``hard_fraction`` of the ceiling, or,
    where the free-memory floor applies (a host without a cgroup, or a cgroup
    capped by host free memory), when free memory drops under HALF the guard's
    floor. On a host without a cgroup (native Windows included) the free-memory
    rule is the one that fires first in practice. Never fires on a blind read.
    """
    if not reading.usable:
        return ""
    if (
        reading.floor_bytes is not None
        and reading.free_bytes is not None
        and reading.free_bytes < reading.floor_bytes // 2
    ):
        return SENTINEL_REASON_FREE_MEMORY
    measured = reading.measured_bytes if reading.measured_bytes is not None else reading.rss_bytes
    if measured >= int(reading.ceiling_bytes * hard_fraction):  # type: ignore[operator]
        return SENTINEL_REASON_CEILING
    return ""


_CALLBACKS_LOCK = threading.Lock()
_RECORD_STOP: Callable[[SentinelStop], Any] | None = None
_MARK_EXPORT_INCOMPLETE: Callable[[SentinelStop], Any] | None = None


#: Schema tag of the memory-stop marker. An internal recovery file read by the
#: engine's stop-record reader and by the next run, not an integrator output.
MEMORY_STOP_MARKER_SCHEMA = "adscan.memory_stop_marker/1"

#: The marker's destination, pre-encoded at registration so firing allocates no
#: path object: ``(final_path_bytes, temporary_path_bytes)``, or ``None``.
_MARKER_PATHS: tuple[bytes, bytes] | None = None


def set_sentinel_marker_path(path: Any) -> None:
    """Register (or replace, or with ``None`` clear) the memory-stop marker path.

    The entry point registers a path inside the CURRENT workspace and registers
    it again when the workspace changes. The bytes are encoded now, so firing
    needs nothing but ``os.open``/``os.write``/``os.replace``/``os.close``.
    """
    global _MARKER_PATHS
    if path is None:
        _MARKER_PATHS = None
        return
    final = os.fsencode(os.fspath(path))
    _MARKER_PATHS = (final, final + b".tmp")


def sentinel_marker_path() -> str | None:
    """The registered marker path, or ``None``."""
    paths = _MARKER_PATHS
    return os.fsdecode(paths[0]) if paths is not None else None


def _json_token(value: Any) -> str:
    """A JSON value for an int or a short id, built without the json module."""
    if isinstance(value, bool) or value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    text = "".join(ch for ch in str(value) if ch.isalnum() or ch in "._-")[:64]
    return '"' + text + '"'


def _write_stop_marker(
    reading: MemoryReading, reason: str, exit_code: int
) -> bool:
    """Write the memory-stop marker with raw OS calls only. Never raises.

    No logging, no console, no store, no import, no lock: a frozen or busy thread
    may hold any of those, and this is the one record that must exist whatever
    the callbacks manage. Written to a temporary file and renamed into place, so
    a reader never sees half a marker. The stage is read from the stage stack
    without its lock (a list read is atomic).
    """
    paths = _MARKER_PATHS
    if paths is None:
        return False
    try:
        try:
            top = _STAGE_STACK[-1]
            stage = top.stage
        except IndexError:
            stage = UNKNOWN_STAGE
        now = time.time()
        content = (
            "{"
            f'"schema": "{MEMORY_STOP_MARKER_SCHEMA}", '
            '"stopped_for": "memory", "record_written": false, '
            f'"stage": {_json_token(stage)}, '
            f'"reason": {_json_token(reason)}, '
            f'"measured_bytes": {_json_token(_measured_of(reading))}, '
            f'"rss_bytes": {_json_token(reading.rss_bytes)}, '
            f'"ceiling_bytes": {_json_token(reading.ceiling_bytes)}, '
            f'"free_bytes": {_json_token(reading.free_bytes)}, '
            f'"ceiling_kind": {_json_token(reading.ceiling_kind)}, '
            f'"source": {_json_token(reading.source)}, '
            f'"utc": "{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))}", '
            f'"epoch": {int(now)}, '
            f'"exit_code": {int(exit_code)}, '
            f'"pid": {os.getpid()}'
            "}\n"
        ).encode("ascii", "replace")
        final, temporary = paths
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
        fd = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        finally:
            os.close(fd)
        os.replace(temporary, final)
        return True
    except BaseException:  # noqa: BLE001 — the exit must happen whatever this does.
        return False


def read_memory_stop_marker(path: Any) -> dict[str, Any] | None:
    """Read a memory-stop marker, or ``None`` when absent or unreadable.

    A marker means "this run stopped for memory; the full stop record may not
    have been written". The engine's stop-record reader and the next run treat
    it that way, and remove it (:func:`remove_memory_stop_marker`) once a full
    record exists.
    """
    import json

    try:
        with open(os.fspath(path), "r", encoding="utf-8") as handle:
            data = json.loads(handle.read())
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("schema") != MEMORY_STOP_MARKER_SCHEMA:
        return None
    return data


def remove_memory_stop_marker(path: Any) -> bool:
    """Remove the marker (and a leftover temporary). True when one was removed."""
    removed = False
    for candidate in (os.fspath(path), os.fspath(path) + ".tmp"):
        try:
            os.remove(candidate)
            removed = True
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return removed


def register_sentinel_callbacks(
    *,
    record_stop: Callable[[SentinelStop], Any] | None = None,
    mark_export_incomplete: Callable[[SentinelStop], Any] | None = None,
    marker_path: Any = None,
) -> None:
    """Register the entry point's callbacks; a given one replaces the previous one.

    ``marker_path`` registers the memory-stop marker (see
    :func:`set_sentinel_marker_path`); it is written FIRST at fire, with raw OS
    calls, before the freeze and before either callback.

    ``record_stop`` runs first, under :data:`SENTINEL_STOP_RECORD_BUDGET_S`: it
    should write the stop record (the scan-progress incomplete mark plus
    ``stop.coverage``) as one small file write. ``mark_export_incomplete`` runs
    second, under :data:`SENTINEL_EXPORT_MARK_BUDGET_S`, and is abandoned if it
    does not finish. Both receive the :class:`SentinelStop`. ``adscan_core`` never
    imports the engine; the engine supplies these.
    """
    global _RECORD_STOP, _MARK_EXPORT_INCOMPLETE
    with _CALLBACKS_LOCK:
        if record_stop is not None:
            _RECORD_STOP = record_stop
        if mark_export_incomplete is not None:
            _MARK_EXPORT_INCOMPLETE = mark_export_incomplete
    if marker_path is not None:
        set_sentinel_marker_path(marker_path)


def clear_sentinel_callbacks() -> None:
    """Forget both registered callbacks and the marker path."""
    global _RECORD_STOP, _MARK_EXPORT_INCOMPLETE, _MARKER_PATHS
    with _CALLBACKS_LOCK:
        _RECORD_STOP = None
        _MARK_EXPORT_INCOMPLETE = None
    _MARKER_PATHS = None


def _registered_callbacks() -> tuple[Any, Any]:
    with _CALLBACKS_LOCK:
        return _RECORD_STOP, _MARK_EXPORT_INCOMPLETE


def _run_bounded(fn: Callable[[], Any], budget_s: float) -> bool:
    """Run ``fn`` on a daemon thread and wait at most ``budget_s``.

    Returns whether it finished. A step that hangs is abandoned; its daemon
    thread dies with the process at ``os._exit``. A step whose thread cannot even
    be started (no memory left for it) is skipped.
    """

    def _target() -> None:
        try:
            fn()
        except BaseException:  # noqa: BLE001 — a best-effort step must not escape.
            pass

    try:
        worker = threading.Thread(
            target=_target, name=f"{SENTINEL_THREAD_PREFIX}-step", daemon=True
        )
        worker.start()
    except BaseException:  # noqa: BLE001
        return False
    worker.join(max(0.0, float(budget_s)))
    return not worker.is_alive()


def _flush_outputs() -> None:
    """Flush the debug log file handlers and stdout/stderr. No telemetry upload."""
    try:
        from adscan_core import logging_config

        handlers: list[Any] = []
        logger = getattr(logging_config, "_logger", None)
        if logger is not None:
            handlers.extend(getattr(logger, "handlers", ()))
        sinks = getattr(logging_config, "_active_file_sinks", None)
        if callable(sinks):
            handlers.extend(h for h in sinks() if h not in handlers)
        for handler in handlers:
            try:
                handler.flush()
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:  # noqa: BLE001
            pass


def _print_operator_error(message: str) -> None:
    try:
        from adscan_core.rich_output import print_error

        print_error(message)
    except Exception:  # noqa: BLE001
        pass


def _measured_of(reading: MemoryReading) -> int | None:
    return reading.measured_bytes if reading.measured_bytes is not None else reading.rss_bytes


def _prewarm_fire_path() -> None:
    """Import now what firing needs, so firing allocates no modules.

    Importing the console stack costs several MB, which a small cgroup at 95% may
    not have. A CLI entry point has these loaded already; this makes it certain.
    """
    for name in (
        "adscan_core.reporting.resource_coverage",
        "adscan_core.rich_output",
        "adscan_core.logging_config",
    ):
        try:
            __import__(name)
        except Exception:  # noqa: BLE001
            pass


def _build_sentinel_stop(reading: MemoryReading, reason: str) -> SentinelStop:
    from adscan_core.reporting.resource_coverage import (
        REASON_MEMORY,
        build_resource_coverage,
        stage_label,
    )

    top = current_stage()
    if top is not None:
        stage, unit, done, total = top.stage, top.unit, top.units_done, top.total
    else:
        stage, unit, done, total = UNKNOWN_STAGE, "items", 0, None
    # Zero counted units at a sentinel stop means the stage does not count, not
    # that it never ran: declare its progress as unknown, never "did not start".
    coverage = build_resource_coverage(
        stage=stage,
        unit=unit,
        examined=done if done > 0 else None,
        total=total,
        reason=REASON_MEMORY,
    )
    where = f" during {stage_label(stage).lower()}" if top is not None else ""
    if reason == SENTINEL_REASON_FREE_MEMORY:
        cause = (
            f"The machine had only {_mb(reading.free_bytes)} of memory left free{where}, "
            "so ADscan stopped the run before the system would kill it and "
            "recorded where it stopped."
        )
    else:
        measured = reading.measured_bytes if reading.measured_bytes is not None else reading.rss_bytes
        cause = (
            f"Memory reached about {_mb(measured)} of the {_mb(reading.ceiling_bytes)} "
            f"ADscan can use{where}, so ADscan stopped the run before the system "
            "would kill it and recorded where it stopped."
        )
    return SentinelStop(
        stage=stage,
        unit=unit,
        units_done=int(done),
        total=total,
        reason=reason,
        reading=reading,
        coverage=coverage,
        operator_message=f"{cause} {MemoryCeilingReached.REMEDY}",
    )


class MemorySentinel:
    """The last-resort memory sentinel thread. Build through :func:`start_memory_sentinel`."""

    def __init__(
        self,
        *,
        exit_code: int,
        hard_fraction: float = SENTINEL_HARD_FRACTION,
        interval_s: float = SENTINEL_INTERVAL_S,
        fast_interval_s: float = SENTINEL_FAST_INTERVAL_S,
        stop_record_budget_s: float = SENTINEL_STOP_RECORD_BUDGET_S,
        export_mark_budget_s: float = SENTINEL_EXPORT_MARK_BUDGET_S,
        reader: Callable[[], Any] | None = None,
        exit_fn: Callable[[int], Any] | None = None,
        freeze_threads: bool = True,
    ) -> None:
        self.exit_code = int(exit_code)
        self.hard_fraction = float(hard_fraction)
        self.interval_s = max(0.01, float(interval_s))
        self.fast_interval_s = max(0.005, float(fast_interval_s))
        self.stop_record_budget_s = float(stop_record_budget_s)
        self.export_mark_budget_s = float(export_mark_budget_s)
        self.fired = threading.Event()
        self.last_stop: SentinelStop | None = None
        self.steps_finished: dict[str, bool] = {}
        self._exit_fn = exit_fn if exit_fn is not None else os._exit
        self._guard = MemoryGuard("sentinel", reader=reader, min_interval_s=0.0)
        self._halt = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name=SENTINEL_THREAD_PREFIX, daemon=True
        )
        self._freeze_threads = bool(freeze_threads)
        self._default_switch_interval: float | None = None
        self._release_frozen = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def start(self) -> "MemorySentinel":
        self._thread.start()
        return self

    def stop(self, timeout: float = 2.0) -> None:
        """Stop sampling (tests, or an entry point that ends inside a long-lived process)."""
        self._halt.set()
        if self._thread.is_alive() and self._thread is not threading.current_thread():
            self._thread.join(timeout)

    def _run(self) -> None:
        history: deque[tuple[float, int]] = deque(maxlen=SENTINEL_RATE_HISTORY)
        try:
            while not self._halt.is_set():
                now = time.monotonic()
                try:
                    reading = self._guard.sample()
                    reason = sentinel_verdict(reading, self.hard_fraction)
                    if not reason:
                        reason = self._rate_verdict(reading, now, history)
                except Exception:  # noqa: BLE001 — a broken sample must not kill the sentinel.
                    reading, reason = _BLIND, ""
                if reason:
                    self._fire(reading, reason)
                    return
                interval = self._next_interval(reading, now, history)
                measured = _measured_of(reading)
                if measured is None:
                    history.clear()
                else:
                    history.append((now, measured))
                self._set_near(interval < self.interval_s)
                self._halt.wait(interval)
        finally:
            self._set_near(False)

    @staticmethod
    def _growth_rate(
        reading: MemoryReading, now: float, history: Sequence[tuple[float, int]]
    ) -> float:
        """Growth in bytes per second over at least two intervals (0 if not known).

        Measured against the newest earlier sample that is at least TWO samples
        back AND at least :data:`SENTINEL_RATE_MIN_SPAN_S` old: over one 2 ms
        interval a 1 MB jitter reads as 500 MB/s. With fewer samples, unknown.
        """
        measured = _measured_of(reading)
        if measured is None or len(history) < 2:
            return 0.0
        base: tuple[float, int] | None = None
        for index in range(len(history) - 2, -1, -1):
            if now - history[index][0] >= SENTINEL_RATE_MIN_SPAN_S:
                base = history[index]
                break
        if base is None:
            return 0.0
        elapsed = now - base[0]
        grown = measured - base[1]
        if elapsed <= 0 or grown <= 0:
            return 0.0
        return grown / elapsed

    def _rate_verdict(
        self, reading: MemoryReading, now: float, history: Sequence[tuple[float, int]]
    ) -> str:
        """Past the guard's line, fire when the measured growth would reach the
        full ceiling within :data:`SENTINEL_REACTION_S`: the last few percent of a
        small cgroup go in milliseconds, faster than a sample plus the freeze."""
        if not reading.crossed or not reading.usable:
            return ""
        rate = self._growth_rate(reading, now, history)
        if rate <= 0:
            return ""
        remaining = max(reading.ceiling_bytes - _measured_of(reading), 0)  # type: ignore[operator]
        if remaining / rate < SENTINEL_REACTION_S:
            return SENTINEL_REASON_CEILING
        return ""

    def _next_interval(
        self, reading: MemoryReading, now: float, history: Sequence[tuple[float, int]]
    ) -> float:
        """The base cadence, tightened by headroom and by measured growth.

        Never longer than half the time an allocator growing at
        :data:`SENTINEL_ASSUMED_MAX_GROWTH_BPS` needs to reach the hard line (so
        a small cap is watched closely from the first sample, before any growth
        has been measured), nor than a quarter of the time the MEASURED growth
        needs. On a large ceiling both bounds exceed the base cadence.
        """
        interval = self.fast_interval_s if reading.crossed else self.interval_s
        measured = _measured_of(reading)
        if not reading.usable or measured is None:
            return interval
        hard_line = int(reading.ceiling_bytes * self.hard_fraction)  # type: ignore[operator]
        remaining = max(hard_line - measured, 0)
        interval = min(interval, remaining / SENTINEL_ASSUMED_MAX_GROWTH_BPS / 2.0)
        rate = self._growth_rate(reading, now, history)
        if rate > 0:
            interval = min(interval, remaining / rate / 4.0)
        return max(SENTINEL_MIN_INTERVAL_S, interval)

    def _set_near(self, near: bool) -> None:
        """Shorten the GIL switch interval near the line; restore it otherwise."""
        try:
            if near and self._default_switch_interval is None:
                self._default_switch_interval = sys.getswitchinterval()
                sys.setswitchinterval(SENTINEL_NEAR_SWITCH_INTERVAL_S)
            elif not near and self._default_switch_interval is not None:
                sys.setswitchinterval(self._default_switch_interval)
                self._default_switch_interval = None
        except Exception:  # noqa: BLE001
            pass

    def _freeze_other_threads(self) -> bool:
        """Stop every other Python thread at its next call, before the steps run.

        Installs a profile hook in all threads (Python 3.12+). Any thread whose
        name does not carry :data:`SENTINEL_THREAD_PREFIX` blocks inside the hook
        until the process exits, so an allocating stage cannot push the cgroup
        over its limit while the stop record is written. A thread inside one long
        C call (a large parse) stops when that call returns; a thread inside the
        ``threading`` module stops at its next call outside it, so no frozen
        thread holds the lock the sentinel needs to start a step thread. Without the API
        (Python < 3.12) the steps race the allocator, as before.
        """
        if not self._freeze_threads:
            return False
        setter = getattr(threading, "setprofile_all_threads", None)
        if setter is None:
            return False
        release = self._release_frozen
        # Sentinel threads are remembered by id the first time the hook sees them
        # (by name), because a finishing thread is removed from the thread
        # registry before its last calls, and its name is gone by then.
        allowed: set[int] = {threading.get_ident()}
        threading_file = getattr(threading, "__file__", None)

        def _hold(frame: Any, _event: str, _arg: Any) -> None:
            ident = threading.get_ident()
            if ident in allowed:
                return
            # Never freeze a thread inside the threading module: it may hold the
            # thread-registry lock, which the sentinel needs to start its steps.
            # Such a thread freezes at its next call outside threading.
            if frame is not None and frame.f_code.co_filename == threading_file:
                return
            if threading.current_thread().name.startswith(SENTINEL_THREAD_PREFIX):
                allowed.add(ident)
                return
            release.wait()

        try:
            setter(_hold)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _thaw(self) -> None:
        """Undo the freeze. Only reached when the exit function returned (tests)."""
        setter = getattr(threading, "setprofile_all_threads", None)
        try:
            if setter is not None:
                setter(None)
        except Exception:  # noqa: BLE001
            pass
        self._release_frozen.set()

    def _fire(self, reading: MemoryReading, reason: str) -> None:
        """Marker, freeze, record, mark, flush, exit. Never joins worker threads."""
        # The one record that needs no lock, no import and no other thread.
        self.steps_finished["marker"] = _write_stop_marker(reading, reason, self.exit_code)
        # Read the callbacks without their lock: a thread frozen next could hold it.
        record_stop, mark_export = _RECORD_STOP, _MARK_EXPORT_INCOMPLETE
        self.steps_finished["froze_threads"] = self._freeze_other_threads()
        try:
            stop = _build_sentinel_stop(reading, reason)
        except Exception:  # noqa: BLE001 — still exit; the kill would record nothing.
            stop = None
        self.last_stop = stop
        self.fired.set()
        if stop is not None:
            message = stop.operator_message
            self.steps_finished["operator_line"] = _run_bounded(
                lambda: _print_operator_error(message), SENTINEL_OPERATOR_LINE_BUDGET_S
            )
            if record_stop is not None:
                self.steps_finished["record_stop"] = _run_bounded(
                    lambda: record_stop(stop), self.stop_record_budget_s
                )
            if mark_export is not None:
                self.steps_finished["mark_export_incomplete"] = _run_bounded(
                    lambda: mark_export(stop), self.export_mark_budget_s
                )
        self.steps_finished["flush"] = _run_bounded(_flush_outputs, SENTINEL_FLUSH_BUDGET_S)
        try:
            self._exit_fn(self.exit_code)
        finally:
            # os._exit never returns; an injected exit (tests) does, and the
            # process must then get its threads back.
            self._thaw()


_SENTINEL: MemorySentinel | None = None
_SENTINEL_LOCK = threading.Lock()


def start_memory_sentinel(
    exit_code: int,
    *,
    record_stop: Callable[[SentinelStop], Any] | None = None,
    mark_export_incomplete: Callable[[SentinelStop], Any] | None = None,
    marker_path: Any = None,
    hard_fraction: float = SENTINEL_HARD_FRACTION,
    interval_s: float = SENTINEL_INTERVAL_S,
    fast_interval_s: float = SENTINEL_FAST_INTERVAL_S,
    stop_record_budget_s: float = SENTINEL_STOP_RECORD_BUDGET_S,
    export_mark_budget_s: float = SENTINEL_EXPORT_MARK_BUDGET_S,
    reader: Callable[[], Any] | None = None,
    exit_fn: Callable[[int], Any] | None = None,
    freeze_threads: bool = True,
) -> MemorySentinel:
    """Start the process's memory sentinel. Idempotent: one thread per process.

    Call it ONCE from a CLI entry point (never from the web backend, never at
    import). When memory reaches :data:`SENTINEL_HARD_FRACTION` of the ceiling,
    or free host memory drops under half the guard's floor, it first writes the
    memory-stop marker with raw OS calls (no lock, no import), then freezes
    every other Python thread at its next call (so an allocating stage stops
    growing), then runs, each best-effort and time-bounded: the operator line,
    ``record_stop(stop)``, ``mark_export_incomplete(stop)``, a flush of the debug
    log handlers and of stdout/stderr; then ``os._exit(exit_code)``. It never
    joins worker threads: a unit interrupted mid-transaction stays uncommitted,
    which the store tolerates as it tolerates a killed writer. A callback that
    needs a lock a frozen thread holds (a log handler mid-write) times out under
    its budget and is skipped.

    Sampling adapts: every :data:`SENTINEL_INTERVAL_S` while calm, every
    :data:`SENTINEL_FAST_INTERVAL_S` past the guard's line, and down to
    :data:`SENTINEL_MIN_INTERVAL_S` when the measured growth projects the hard
    line close; near the line the GIL switch interval is shortened so a sample is
    not stalled behind an allocating thread.

    Args:
        exit_code: The incomplete-run exit code (the engine's constant; this
            module does not import the engine).
        record_stop: See :func:`register_sentinel_callbacks`.
        mark_export_incomplete: See :func:`register_sentinel_callbacks`.
        marker_path: The memory-stop marker path inside the current workspace;
            see :func:`set_sentinel_marker_path`. Re-register it there when the
            workspace changes.
        hard_fraction, interval_s, fast_interval_s, stop_record_budget_s,
        export_mark_budget_s: Tuning; the defaults are the documented ones.
        reader: Memory reader override (tests).
        exit_fn: Exit override (tests); defaults to ``os._exit``.
        freeze_threads: Freeze every other Python thread when firing (default).
            Tests that inject ``exit_fn`` in-process turn it off.

    Returns:
        The running sentinel. A second call returns the SAME sentinel (its exit
        code and tuning are those of the first call) and only registers any
        callbacks it was given.
    """
    global _SENTINEL
    register_sentinel_callbacks(
        record_stop=record_stop,
        mark_export_incomplete=mark_export_incomplete,
        marker_path=marker_path,
    )
    with _SENTINEL_LOCK:
        if _SENTINEL is not None and _SENTINEL.running:
            return _SENTINEL
        _prewarm_fire_path()
        _SENTINEL = MemorySentinel(
            exit_code=exit_code,
            hard_fraction=hard_fraction,
            interval_s=interval_s,
            fast_interval_s=fast_interval_s,
            stop_record_budget_s=stop_record_budget_s,
            export_mark_budget_s=export_mark_budget_s,
            reader=reader,
            exit_fn=exit_fn,
            freeze_threads=freeze_threads,
        ).start()
        return _SENTINEL


#: Peak memory of a whole-document JSON load, as a multiple of the file size
#: (measured about 2.8 for a 14.0.x ``attack_graph.json``: the bytes, the decoded
#: text and the objects are held together; ``graph_compact`` uses the same).
WHOLE_DOCUMENT_PEAK_FACTOR = 3


def refuse_whole_load(size_bytes: int, *, stage: str) -> None:
    """Raise :class:`MemoryCeilingReached` when loading a whole document does not fit.

    One ``json.load`` is a long C call the guard and the sentinel cannot
    interrupt, so the question is asked BEFORE reading: does
    :data:`WHOLE_DOCUMENT_PEAK_FACTOR` times ``size_bytes`` fit under the line?
    The enclosing stage's guard answers when there is one (and the stop is
    raised in that stage's name, so its boundary declares it); otherwise a
    guard for ``stage``. A blind reading never refuses.

    Raises:
        MemoryCeilingReached: the load would not fit; nothing was read.
    """
    guard = current_guard()
    if guard is None:
        guard = MemoryGuard(stage)
    if guard.fits(max(0, int(size_bytes)) * WHOLE_DOCUMENT_PEAK_FACTOR):
        return
    raise MemoryCeilingReached(stage=guard.stage, units_done=guard.units_done, reading=guard.sample())


#: The smallest memory ceiling ADscan supports. Below it the last-resort
#: sentinel cannot be relied on: a stage that grows fast can cover the distance
#: from the guard's line to the kill between two samples (measured on the
#: development machine: at a 400 MB ceiling and ~800 MB/s growth the sentinel
#: lost the race; at ~80 MB/s it held). The launcher refuses a host with less
#: free memory than this unless the operator overrides it; the engine warns.
SUPPORTED_MEMORY_FLOOR_BYTES = 1024 * 1024 * 1024


def supported_floor_warning(ceiling_bytes: int | None) -> str:
    """The operator line for a ceiling under :data:`SUPPORTED_MEMORY_FLOOR_BYTES`,
    or ``""`` when the ceiling is at or above it (or unknown)."""
    if not isinstance(ceiling_bytes, int) or ceiling_bytes <= 0:
        return ""
    if ceiling_bytes >= SUPPORTED_MEMORY_FLOOR_BYTES:
        return ""
    return (
        f"ADscan has {_mb(ceiling_bytes)} of memory here, below the supported minimum "
        "of 1 GB: a stage that grows quickly can run out of memory before ADscan "
        "stops it cleanly, so the run may end without recording where it stopped."
    )


def warn_if_below_supported_floor(reader: Callable[[], Any] | None = None) -> bool:
    """Print :func:`supported_floor_warning` once for this process's ceiling.

    Returns whether it warned. Never raises; a ceiling it cannot read is not
    below the floor.
    """
    try:
        reading = MemoryGuard("sentinel", reader=reader).sample()
        line = supported_floor_warning(reading.ceiling_bytes)
    except Exception:  # noqa: BLE001 - a warning never breaks a start
        return False
    if not line:
        return False
    _print_operator_warning(line)
    return True


def stop_memory_sentinel(timeout: float = 2.0) -> None:
    """Stop the process's sentinel, if any, and forget it."""
    global _SENTINEL
    with _SENTINEL_LOCK:
        sentinel, _SENTINEL = _SENTINEL, None
    if sentinel is not None:
        sentinel.stop(timeout)


def memory_sentinel() -> MemorySentinel | None:
    """The process's sentinel, or ``None`` when none was started."""
    with _SENTINEL_LOCK:
        return _SENTINEL


__all__ = [
    "SENTINEL_EXPORT_MARK_BUDGET_S",
    "SENTINEL_FAST_INTERVAL_S",
    "SENTINEL_HARD_FRACTION",
    "SENTINEL_INTERVAL_S",
    "SENTINEL_ASSUMED_MAX_GROWTH_BPS",
    "SENTINEL_MIN_INTERVAL_S",
    "SENTINEL_REACTION_S",
    "SENTINEL_NEAR_SWITCH_INTERVAL_S",
    "SENTINEL_THREAD_PREFIX",
    "SENTINEL_REASON_CEILING",
    "SENTINEL_REASON_FREE_MEMORY",
    "SENTINEL_STOP_RECORD_BUDGET_S",
    "UNKNOWN_STAGE",
    "MEMORY_STOP_MARKER_SCHEMA",
    "SENTINEL_RATE_HISTORY",
    "SENTINEL_RATE_MIN_SPAN_S",
    "MemorySentinel",
    "read_memory_stop_marker",
    "remove_memory_stop_marker",
    "sentinel_marker_path",
    "set_sentinel_marker_path",
    "SentinelStop",
    "active_stages",
    "clear_sentinel_callbacks",
    "current_stage",
    "memory_sentinel",
    "register_sentinel_callbacks",
    "sentinel_verdict",
    "start_memory_sentinel",
    "stop_memory_sentinel",
    "CEILING_HEADROOM",
    "CEILING_HOST_CAPPED",
    "CEILING_LIMIT",
    "FREE_FLOOR_HOST_FRACTION",
    "FREE_FLOOR_MIN_BYTES",
    "DEFAULT_MIN_INTERVAL_S",
    "DEFAULT_SAMPLE_EVERY",
    "MemoryBoundedStage",
    "MemoryCeilingReached",
    "MemoryGuard",
    "MemoryReading",
    "NEAR_LINE_FRACTION",
    "OUTCOME_COMPLETE",
    "OUTCOME_STOPPED",
    "OUTCOME_STREAMED",
    "STOP_FRACTION",
    "check_enclosing_stage",
    "current_guard",
    "free_memory_floor",
    "memory_bounded",
    "RESUME_NEXT_COMMAND",
    "build_memory_prestage_notice",
    "build_memory_stop_lines",
    "estimate_need_phrase",
    "memory_scaleup_options",
    "print_memory_stop_panel",
]
