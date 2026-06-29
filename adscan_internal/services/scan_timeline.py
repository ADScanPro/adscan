"""Per-phase scan timeline — delta footers + persistent JSONL audit trail.

Each major scan phase is wrapped in :func:`phase_span`, a context manager
that snapshots the workspace before and after the phase, computes the
deltas (nodes, edges, credentials, attack paths, elapsed seconds), renders
a compact "premium" footer to the operator, and appends one structured
row to ``timeline.jsonl`` for the workspace audit trail.

The audit trail powers the ADscan web service dashboard and the (future)
``adscan show timeline`` command. Rows are stable JSON, one per line, with
the same schema as the structured event sink so downstream consumers can
mix-and-match without parsing two formats.

Why this matters operationally:

* Pentesters get an immediate "what just changed" signal per phase instead
  of inferring from scattered logs — high-value moments (e.g. a phase
  produced +12 paths or +3 credentials) become impossible to miss.
* Engagements get a stable, replayable audit trail without the operator
  doing anything extra. The web service can render a phase-by-phase
  storyline; report generation can quote it verbatim.
* Regression hunting: comparing yesterday's ``timeline.jsonl`` against
  today's is one ``diff`` away.

This module never raises — failure to write the timeline or to render the
footer is silently degraded (debug-logged) so the underlying scan flow is
never interrupted by telemetry.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


@dataclass(frozen=True)
class PhaseMetrics:
    """Workspace state snapshot captured at one phase boundary.

    All fields are best-effort and default to ``0`` / ``False`` when the
    underlying artefact is missing — never raises.
    """

    node_count: int = 0
    edge_count: int = 0
    credential_count: int = 0
    attack_path_count: int = 0
    enabled_computer_count: int = 0
    enabled_user_count: int = 0


@dataclass(frozen=True)
class PhaseDelta:
    """Difference between an end-of-phase and start-of-phase snapshot."""

    nodes: int = 0
    edges: int = 0
    credentials: int = 0
    attack_paths: int = 0
    enabled_computers: int = 0
    enabled_users: int = 0

    def is_empty(self) -> bool:
        """Return True when no field changed across the phase."""
        return all(value == 0 for value in asdict(self).values())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def begin_timeline_run(shell: Any) -> str:
    """Open a fresh timeline-run grouping and return its identifier.

    Every phase row written via :func:`phase_span` until the next call to
    this function is tagged with the same ``run_id``. Callers (typically
    ``_run_enum_domain_auth`` and ``run_enum_trusts``) invoke this once at
    the start of a scan so the rendered timeline can group the run cleanly
    and the diff command has a stable key.

    The id is short, sortable, and human-friendly (``20260505_103045_a1b2``)
    so it works equally well in CLI output, file names, and structured logs.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = uuid.uuid4().hex[:4]
    run_id = f"{stamp}_{suffix}"
    setattr(shell, "_timeline_run_id", run_id)
    return run_id


def get_active_run_id(shell: Any) -> str:
    """Return the active timeline ``run_id``, lazily creating one if absent."""
    rid = getattr(shell, "_timeline_run_id", None)
    if rid:
        return str(rid)
    return begin_timeline_run(shell)


@contextmanager
def phase_span(
    shell: Any,
    domain: str,
    *,
    phase_id: str,
    phase_title: str,
) -> Iterator[None]:
    """Wrap a scan phase to capture deltas and emit timeline rows.

    Usage::

        with phase_span(shell, domain, phase_id="domain_collection",
                        phase_title="Domain Collection"):
            run_collection(...)

    On exit the helper:
      * Computes the delta vs. the start snapshot.
      * Appends a row to ``timeline.jsonl`` in the workspace.
      * Mirrors the row to the structured event sink (``stderr-json``)
        so the web service can render it live.
      * Renders a premium delta footer to the console (skipped when the
        delta is empty to avoid noise on cached/skipped phases).

    On exception, the row is still emitted with ``status="error"`` and the
    exception is re-raised — the timeline always reflects what happened.
    """
    started_at = time.time()
    started_iso = _utc_now_iso()
    try:
        start_metrics = capture_phase_metrics(shell, domain)
    except Exception:  # noqa: BLE001
        start_metrics = PhaseMetrics()

    error: BaseException | None = None
    try:
        yield
    except GeneratorExit:
        # The span was abandoned, not failed: a caller opened the span via
        # ``__enter__`` and returned early without an explicit ``__exit__``
        # (common in ``run_enumeration``'s many early-return points), so the
        # suspended generator is closed/GC'd and Python throws ``GeneratorExit``
        # in here. That is a clean teardown, NOT a phase error — recording it as
        # ``status="error"`` mislabels a healthy phase (e.g. domain_analysis with
        # +9 users / +4 edges showed up as an error). Re-raise so the generator
        # protocol stays correct, but leave ``error`` unset so the row reads ok.
        raise
    except BaseException as exc:  # noqa: BLE001 — captured to enrich timeline row
        error = exc
        raise
    finally:
        elapsed = time.time() - started_at
        try:
            end_metrics = capture_phase_metrics(shell, domain)
        except Exception:  # noqa: BLE001
            end_metrics = start_metrics

        delta = _compute_delta(start_metrics, end_metrics)
        status = "error" if error is not None else "ok"

        _append_timeline_row(
            shell,
            domain,
            run_id=get_active_run_id(shell),
            phase_id=phase_id,
            phase_title=phase_title,
            status=status,
            started_iso=started_iso,
            elapsed_seconds=elapsed,
            start_metrics=start_metrics,
            end_metrics=end_metrics,
            delta=delta,
            error_text=str(error) if error is not None else None,
        )

        if status == "ok":
            _render_phase_footer(
                phase_title=phase_title,
                elapsed_seconds=elapsed,
                delta=delta,
                end_metrics=end_metrics,
            )


def capture_phase_metrics(shell: Any, domain: str) -> PhaseMetrics:
    """Capture a workspace snapshot for delta computation.

    Reads cheaply from local artefacts only (no AD access). Returns zeroed
    metrics when artefacts are missing — never raises.
    """
    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    domains_dir = getattr(shell, "domains_dir", "domains")

    try:
        from adscan_internal.workspaces import domain_subpath
    except Exception:  # noqa: BLE001 — keep telemetry pure
        return PhaseMetrics()

    graph_path = Path(domain_subpath(workspace_dir, domains_dir, domain, "attack_graph.json"))
    paths_path = Path(domain_subpath(workspace_dir, domains_dir, domain, "attack_paths.json"))
    creds_path = Path(domain_subpath(workspace_dir, domains_dir, domain, "credentials.json"))
    computers_path = Path(domain_subpath(workspace_dir, domains_dir, domain, "enabled_computers.txt"))
    users_path = Path(domain_subpath(workspace_dir, domains_dir, domain, "enabled_users.txt"))

    nodes, edges = _count_graph_size(graph_path)
    return PhaseMetrics(
        node_count=nodes,
        edge_count=edges,
        credential_count=_count_credentials(creds_path),
        attack_path_count=_count_attack_paths(paths_path),
        enabled_computer_count=_count_lines(computers_path),
        enabled_user_count=_count_lines(users_path),
    )


# ---------------------------------------------------------------------------
# Internals — counting helpers
# ---------------------------------------------------------------------------


def _count_graph_size(graph_path: Path) -> tuple[int, int]:
    if not graph_path.is_file():
        return (0, 0)
    try:
        data = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return (0, 0)
    nodes = data.get("nodes")
    edges = data.get("edges")
    n = len(nodes) if isinstance(nodes, (dict, list)) else 0
    e = len(edges) if isinstance(edges, list) else 0
    return (n, e)


def _count_credentials(creds_path: Path) -> int:
    if not creds_path.is_file():
        return 0
    try:
        data = json.loads(creds_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        creds = data.get("credentials")
        if isinstance(creds, list):
            return len(creds)
    return 0


def _count_attack_paths(paths_path: Path) -> int:
    if not paths_path.is_file():
        return 0
    try:
        data = json.loads(paths_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("paths", "attack_paths", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return len(value)
    return 0


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return sum(1 for line in fh if line.strip())
    except OSError:
        return 0


def _compute_delta(start: PhaseMetrics, end: PhaseMetrics) -> PhaseDelta:
    return PhaseDelta(
        nodes=end.node_count - start.node_count,
        edges=end.edge_count - start.edge_count,
        credentials=end.credential_count - start.credential_count,
        attack_paths=end.attack_path_count - start.attack_path_count,
        enabled_computers=end.enabled_computer_count - start.enabled_computer_count,
        enabled_users=end.enabled_user_count - start.enabled_user_count,
    )


# ---------------------------------------------------------------------------
# Internals — emission
# ---------------------------------------------------------------------------


def _append_timeline_row(
    shell: Any,
    domain: str,
    *,
    run_id: str,
    phase_id: str,
    phase_title: str,
    status: str,
    started_iso: str,
    elapsed_seconds: float,
    start_metrics: PhaseMetrics,
    end_metrics: PhaseMetrics,
    delta: PhaseDelta,
    error_text: str | None,
) -> None:
    """Persist + emit one structured timeline row.

    The on-disk file is ``<workspace>/<domains_dir>/<domain>/timeline.jsonl``.
    The structured-event sink mirror uses event type ``timeline`` so the web
    service receives the exact same payload as the file.
    """
    payload: dict[str, Any] = {
        "run_id": run_id,
        "domain": domain,
        "phase_id": phase_id,
        "phase_title": phase_title,
        "status": status,
        "started_at": started_iso,
        "ended_at": _utc_now_iso(),
        "elapsed_seconds": round(elapsed_seconds, 3),
        "start_metrics": asdict(start_metrics),
        "end_metrics": asdict(end_metrics),
        "delta": asdict(delta),
    }
    if error_text:
        payload["error"] = error_text[:500]

    _write_to_file(shell, domain, payload)
    _mirror_to_event_sink(payload)


def _write_to_file(shell: Any, domain: str, payload: dict[str, Any]) -> None:
    workspace_dir = getattr(shell, "current_workspace_dir", None) or os.getcwd()
    domains_dir = getattr(shell, "domains_dir", "domains")
    try:
        from adscan_internal.workspaces import domain_subpath
    except Exception:  # noqa: BLE001
        return

    try:
        timeline_path = Path(
            domain_subpath(workspace_dir, domains_dir, domain, "timeline.jsonl")
        )
        timeline_path.parent.mkdir(parents=True, exist_ok=True)
        with timeline_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError:
        # Telemetry path: never block the scan because of disk failures.
        try:
            from adscan_core.rich_output import print_info_debug

            print_info_debug(f"[timeline] failed to persist row for {domain}")
        except Exception:  # noqa: BLE001
            pass


def _mirror_to_event_sink(payload: dict[str, Any]) -> None:
    try:
        from adscan_internal.cli.ci_events import emit_event

        emit_event("timeline", **payload)
    except Exception:  # noqa: BLE001
        pass


def _render_phase_footer(
    *,
    phase_title: str,
    elapsed_seconds: float,
    delta: PhaseDelta,
    end_metrics: PhaseMetrics,
) -> None:
    """Render the per-phase delta footer to the console.

    Skipped silently when the delta is fully empty (nothing changed) so
    cached/skipped phases don't generate visual noise. Designed to be
    immediately scannable: one line of high-signal counts.
    """
    if delta.is_empty() and elapsed_seconds < 0.5:
        return

    try:
        from rich.text import Text

        from adscan_core.rich_output import get_console

        line = Text()
        line.append("  ✓ ", style="bold green")
        line.append(phase_title, style="bold")
        line.append("  ·  ", style="dim")
        line.append(f"{elapsed_seconds:.1f}s", style="cyan")

        deltas = _format_delta_chips(delta)
        if deltas:
            line.append("   ")
            line.append_text(deltas)
        else:
            line.append("   ")
            line.append("no new findings", style="dim")

        get_console().print(line)
    except Exception:  # noqa: BLE001
        pass


def _format_delta_chips(delta: PhaseDelta) -> "Any":
    """Compose a Rich ``Text`` of `+N nodes  +N edges  ...` style chips."""
    from rich.text import Text

    out = Text()
    chips: list[tuple[int, str, str]] = [
        (delta.nodes, "nodes", "blue"),
        (delta.edges, "edges", "blue"),
        (delta.attack_paths, "paths", "magenta"),
        (delta.credentials, "creds", "yellow"),
        (delta.enabled_users, "users", "cyan"),
        (delta.enabled_computers, "hosts", "cyan"),
    ]
    first = True
    for value, label, colour in chips:
        if value == 0:
            continue
        if not first:
            out.append("  ", style="dim")
        first = False
        sign = "+" if value > 0 else ""
        out.append(f"{sign}{value} ", style=f"bold {colour}")
        out.append(label, style="dim")
    return out


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
