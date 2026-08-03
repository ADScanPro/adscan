"""Progress observation for the long, synchronous attack-path compute.

``get_attack_path_summaries`` is a single blocking call whose internal stages
(raw DFS, minimize, dedup, containment filter, ordering) can dominate a large
scan — on a 774-host graph the containment filter alone has run for over two
hours. The compute stays synchronous by design (see CLAUDE.md § "Attack-path
logic changes"), so this module is the SSOT seam that lets a UI surface *where*
that time goes without restructuring the compute or touching any path result.

The mechanism is a passive observer: the compute pipeline calls
:func:`notify_stage` / :func:`notify_graph_size` at the stage boundaries it
already crosses, and a UI (the CLI ``LiveSession`` progress panel) registers an
:class:`AttackPathComputeProgress` via :func:`track_compute_progress` for the
duration of one compute. When no observer is registered (web calls, report
generation, the attack-path debug script) the notify functions are a cheap
early return — a single module-global read — so the compute is byte-for-byte
unchanged.

The module is intentionally dependency-light (stdlib + typing only) so the
compute files can import it without any risk of an import cycle.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Callable, Iterator, Optional

__all__ = [
    "AttackPathComputeProgress",
    "track_compute_progress",
    "notify_stage",
    "notify_graph_size",
    "notify_principal",
    "friendly_stage_label",
    "compute_eta_seconds",
]


# Internal stage label (as emitted by the compute checkpoints) → operator-facing
# label. Matched by prefix so the raw-paths checkpoint ("raw paths
# start_node_id=…") and any label variant resolve cleanly.
_STAGE_LABELS: tuple[tuple[str, str], ...] = (
    ("raw", "Enumerating attack paths"),
    ("input+scope-filter", "Enumerating attack paths"),
    ("terminal-memberof", "Filtering group-membership tails"),
    ("minimize", "Minimizing display paths"),
    ("dedup", "Deduplicating paths"),
    ("annotate-affected-users", "Annotating affected principals"),
    ("contained-filter", "Applying containment filter"),
    ("contextual-dedup", "Deduplicating by context"),
    ("prefix-dominated", "Removing dominated prefixes"),
    ("ordering", "Ordering by compromise directness"),
)

# Label prefix that marks the containment-filter stage — the one the field
# profiling flagged as the dominant cost. Kept as a constant so the telemetry
# attribution and the label map agree.
_CONTAINED_FILTER_PREFIX = "contained-filter"

# Ordered, de-duplicated operator-facing stage names — the pipeline's canonical
# order, derived once from ``_STAGE_LABELS`` (its SSOT). The DFS ("Enumerating
# attack paths") is index 0 and is surfaced as the per-principal progress bar,
# not a checklist row; the rest form the post-DFS phase checklist. Deriving the
# order from the same map the compute notifies against keeps the two in lockstep.
_PIPELINE_STAGE_ORDER: tuple[str, ...] = tuple(
    dict.fromkeys(friendly for _prefix, friendly in _STAGE_LABELS)
)


def compute_eta_seconds(
    done: int, total: int, elapsed_seconds: float
) -> Optional[float]:
    """Return the honest linear-extrapolation ETA for a per-item loop, or ``None``.

    The DFS cost is dominated by a per-principal loop whose denominator is known
    up front, so a rate-based estimate is defensible: ``rate = elapsed / done``
    seconds-per-principal, ``ETA = rate * (total - done)``. Returns ``None`` when
    there is not yet enough signal to extrapolate (no principal finished, no
    elapsed time, or an unknown total) rather than fabricating a number, and
    ``0.0`` once every principal is done.

    Args:
        done: Principals fully processed so far.
        total: Total principals the loop will process.
        elapsed_seconds: Monotonic seconds spent in the loop so far. Must be
            measured with ``time.monotonic()`` (the wall clock is stepped
            mid-scan) — the caller owns that.

    Returns:
        Estimated remaining seconds, ``0.0`` when complete, or ``None`` when the
        estimate cannot yet be justified.
    """
    if total <= 0 or done <= 0 or elapsed_seconds <= 0:
        return None
    remaining = total - done
    if remaining <= 0:
        return 0.0
    rate = elapsed_seconds / done
    return rate * remaining


def friendly_stage_label(label: str) -> str:
    """Return the operator-facing name for an internal compute-stage label."""
    key = str(label or "").strip().lower()
    for prefix, friendly in _STAGE_LABELS:
        if key.startswith(prefix):
            return friendly
    return str(label or "").strip() or "Computing"


@dataclass
class AttackPathComputeProgress:
    """Mutable, thread-safe snapshot of one attack-path compute in flight.

    A UI creates one instance, registers it with :func:`track_compute_progress`
    around the blocking compute, and reads :meth:`elapsed` / :attr:`stage` /
    :attr:`raw_paths` from a live-updating renderable. The compute records stage
    boundaries into it via the module-level ``notify_*`` functions.

    Durations are measured with ``time.monotonic()`` — ADscan physically steps
    the host wall clock mid-scan for Kerberos, so a wall-clock elapsed would be
    corrupted (CLAUDE.md § "Measure DURATIONS with time.monotonic()").

    Attributes:
        started_at: ``time.monotonic()`` captured when the compute began.
        stage: Operator-facing name of the most recent stage.
        raw_paths: Raw path count reported by the first checkpoint.
        final_paths: Final path count, set by :meth:`mark_done`.
        nodes: Node count of the graph the compute walked.
        edges: Edge count of the graph the compute walked.
        ordering_seconds: Accumulated time spent in the UX ordering step.
        principals_done: Start-principals whose DFS has fully completed.
        principals_total: Total start-principals the DFS will walk (the ETA
            denominator). ``0`` until the DFS reports its first principal.
        on_update: Optional callback invoked (best-effort) after every stage
            record so the UI can refresh.
    """

    started_at: float
    stage: str = "Starting"
    raw_paths: int = 0
    final_paths: int = 0
    nodes: int = 0
    edges: int = 0
    ordering_seconds: float = 0.0
    principals_done: int = 0
    principals_total: int = 0
    on_update: Optional[Callable[["AttackPathComputeProgress"], None]] = None
    _events: list[tuple[str, float, int]] = field(default_factory=list, repr=False)
    _finished_at: Optional[float] = field(default=None, repr=False)
    # ``time.monotonic()`` captured when the DFS reported its first principal —
    # the anchor the per-principal ETA extrapolates from (so the estimate is not
    # skewed by the graph-prep work that precedes the DFS loop).
    _dfs_anchor: Optional[float] = field(default=None, repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def elapsed(self) -> float:
        """Return seconds since the compute began (frozen once done)."""
        end = self._finished_at if self._finished_at is not None else time.monotonic()
        return max(0.0, end - self.started_at)

    def record_stage(self, label: str, count: int) -> None:
        """Record one stage boundary and notify the UI (best-effort)."""
        now = time.monotonic()
        with self._lock:
            if not self._events:
                # The first checkpoint carries the raw path count.
                self.raw_paths = int(count)
            self._events.append((str(label), now, int(count)))
            self.stage = friendly_stage_label(label)
        self._fire_update()

    def record_graph_size(self, nodes: int, edges: int) -> None:
        """Record the size of the graph being walked."""
        with self._lock:
            self.nodes = int(nodes)
            self.edges = int(edges)

    def record_principal(self, done: int, total: int) -> None:
        """Record DFS per-principal progress (``done`` of ``total`` walked).

        The DFS is the dominant, unobserved phase before the first stage
        checkpoint. Reporting the per-principal position lets the UI show a real
        progress bar + linear ETA. The first call anchors the ETA clock so the
        rate ignores the graph-prep work that runs before the loop. Notifies the
        UI best-effort.
        """
        now = time.monotonic()
        with self._lock:
            if self._dfs_anchor is None:
                self._dfs_anchor = now
            self.principals_done = int(done)
            self.principals_total = int(total)
        self._fire_update()

    def principal_fraction(self) -> Optional[float]:
        """Return DFS completion as a ``0.0``–``1.0`` fraction, or ``None``.

        ``None`` until the DFS has reported a positive total (so the UI can hide
        the bar rather than render an empty one).
        """
        with self._lock:
            done = self.principals_done
            total = self.principals_total
        if total <= 0:
            return None
        return max(0.0, min(1.0, done / total))

    def principal_eta_seconds(self) -> Optional[float]:
        """Return the honest per-principal ETA in seconds, or ``None``.

        Extrapolates linearly from the elapsed DFS time (anchored at the first
        principal, frozen once the compute is done) via :func:`compute_eta_seconds`.
        ``None`` until at least one principal has finished.
        """
        with self._lock:
            done = self.principals_done
            total = self.principals_total
            anchor = self._dfs_anchor
            finished = self._finished_at
        if anchor is None:
            return None
        end = finished if finished is not None else time.monotonic()
        return compute_eta_seconds(done, total, max(0.0, end - anchor))

    def pipeline_checklist(self) -> list[tuple[str, str]]:
        """Return the post-DFS phase checklist as ``(stage_label, state)`` rows.

        ``state`` is ``"done"`` / ``"running"`` / ``"pending"``. The order is the
        canonical :data:`_PIPELINE_STAGE_ORDER` (the DFS row is excluded — it is
        the progress bar). A stage is ``done`` when a later stage has started (so
        a stage that never fires for a given scope is closed out when the pipeline
        advances past it), ``running`` when it is the current stage, else
        ``pending``. Every row is ``done`` once the compute is complete.
        """
        order = _PIPELINE_STAGE_ORDER
        with self._lock:
            current = self.stage
            done_flag = self._finished_at is not None
        try:
            cur_idx = order.index(current)
        except ValueError:
            # "Starting" (pre-DFS) → treat as index 0; "Complete" → all done.
            cur_idx = len(order) if done_flag else 0
        rows: list[tuple[str, str]] = []
        for idx, label in enumerate(order):
            if idx == 0:
                continue  # DFS row — surfaced as the progress bar, not a checkmark
            if done_flag or idx < cur_idx:
                state = "done"
            elif idx == cur_idx:
                state = "running"
            else:
                state = "pending"
            rows.append((label, state))
        return rows

    def record_ordering(self, seconds: float) -> None:
        """Accumulate time spent in the display-ordering step."""
        with self._lock:
            self.ordering_seconds += max(0.0, float(seconds))

    def mark_done(self, *, final_paths: int) -> None:
        """Freeze the elapsed timer and record the final path count."""
        with self._lock:
            self.final_paths = int(final_paths)
            self._finished_at = time.monotonic()
            self.stage = "Complete"
        self._fire_update()

    def has_run(self) -> bool:
        """True when at least one compute stage was recorded (not a cache hit)."""
        with self._lock:
            return bool(self._events)

    def telemetry_properties(self) -> dict[str, Any]:
        """Return the counts + per-stage seconds for the performance event.

        Counts and durations only — no path content, no principal names. The
        stage attribution is derived from the recorded checkpoint timeline:
        ``dfs_seconds`` is the time to the first checkpoint (the DFS walk),
        ``contained_filter_seconds`` is the delta of the containment-filter
        stage (the field-profiling bottleneck).
        """
        with self._lock:
            events = list(self._events)
            ordering_seconds = self.ordering_seconds
            raw_paths = self.raw_paths
            final_paths = self.final_paths
            nodes = self.nodes
            edges = self.edges
        total_seconds = self.elapsed()
        dfs_seconds = 0.0
        contained_filter_seconds = 0.0
        # Per-stage seconds keyed by the internal checkpoint label — the whole
        # point of the event is that the NEXT multi-hour run is diagnosable, and
        # the dominant stage varies by graph shape (a dense graph can spend its
        # hours in affected-user annotation rather than the containment filter),
        # so a generic breakdown is what actually attributes the time. Deltas
        # accumulate per label (handles the raw+scope-filter double checkpoint
        # and any repeated stage).
        stage_seconds: dict[str, float] = {}
        if events:
            dfs_seconds = max(0.0, events[0][1] - self.started_at)
            prev_ts = self.started_at
            for label, ts, _count in events:
                key = str(label).strip().lower()
                delta = max(0.0, ts - prev_ts)
                stage_seconds[key] = round(stage_seconds.get(key, 0.0) + delta, 3)
                if key.startswith(_CONTAINED_FILTER_PREFIX):
                    contained_filter_seconds = max(contained_filter_seconds, delta)
                prev_ts = ts
        return {
            "raw_paths": raw_paths,
            "final_paths": final_paths,
            "nodes": nodes,
            "edges": edges,
            "dfs_seconds": round(dfs_seconds, 3),
            "contained_filter_seconds": round(contained_filter_seconds, 3),
            "ordering_seconds": round(ordering_seconds, 3),
            "total_seconds": round(total_seconds, 3),
            "stage_seconds": stage_seconds,
        }

    def _fire_update(self) -> None:
        callback = self.on_update
        if callback is None:
            return
        try:
            callback(self)
        except Exception:  # noqa: BLE001 — a UI refresh must never break compute
            pass


# Module-global active observer. Only the interactive CLI wrapper registers one;
# every other caller leaves it ``None`` so the notify functions early-return.
_ACTIVE: Optional[AttackPathComputeProgress] = None
_ACTIVE_LOCK = Lock()


@contextmanager
def track_compute_progress(
    progress: AttackPathComputeProgress,
) -> Iterator[AttackPathComputeProgress]:
    """Register ``progress`` as the active observer for the enclosed compute.

    Restores the previous observer on exit so nested registrations are safe.
    """
    global _ACTIVE  # noqa: PLW0603 — single module-global observer by design
    with _ACTIVE_LOCK:
        previous = _ACTIVE
        _ACTIVE = progress
    try:
        yield progress
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE = previous


def notify_stage(label: str, count: int) -> None:
    """Record a compute-stage boundary on the active observer, if any.

    A no-op (one module-global read) when no UI has registered an observer, so
    the compute path is unchanged for web / report / debug-script callers.
    """
    observer = _ACTIVE
    if observer is None:
        return
    observer.record_stage(label, count)


def notify_graph_size(nodes: int, edges: int) -> None:
    """Record the walked graph's node/edge counts on the active observer, if any."""
    observer = _ACTIVE
    if observer is None:
        return
    observer.record_graph_size(nodes, edges)


def notify_principal(done: int, total: int) -> None:
    """Record DFS per-principal progress on the active observer, if any.

    A no-op (one module-global read) when no UI has registered an observer, so
    the DFS loop is unchanged for web / report / debug-script callers.
    """
    observer = _ACTIVE
    if observer is None:
        return
    observer.record_principal(done, total)
