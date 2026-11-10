"""Structured execution event emitter for opt-in machine-readable scan telemetry.

This module is intentionally transport-neutral. When a compatible execution
sink is enabled, it writes JSON-encoded progress events to **stderr** so an
external orchestrator can parse them on a separate pipe without interfering
with the human-readable stdout output.

Each event is a single JSON line:
    {"type": "phase", "phase": "bloodhound_collection", ...}

**Single source of truth:** the canonical plan lives in
``adscan_internal.services.scan_phases`` (``SCAN_PHASES`` + ``build_scan_plan``).
``PHASE_CATALOG`` below is a *literal mirror* of that registry — kept as a literal
dict only because the Celery worker AST-parses this assignment as a backstop
(``ast.literal_eval``). A module-level guard asserts the literal matches the
SSOT, so any drift fails loudly at import. Call sites just call
``emit_phase("phase_id")`` with a canonical ``scan_phases`` id — no metadata is
authored twice.

The engine declares the ordered plan up-front via :func:`emit_scan_plan` (one
``scan_plan`` event at scan start); the web renders that declared plan directly,
with this catalog as the worker-side fallback.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone

import logging

_EVENT_SINK: str = str(os.environ.get("ADSCAN_EVENT_SINK", "") or "").strip().lower()
_STRUCTURED_STDERR_ENABLED: bool = _EVENT_SINK == "stderr-json"
# Keep the historical CI marker as an additional guard, but require the sink.
_CI_SESSION: bool = os.environ.get("ADSCAN_SESSION_ENV") == "ci"
_EVENT_DEBUG: bool = os.environ.get("ADSCAN_EVENT_DEBUG") == "1"
_LOGGER = logging.getLogger("adscan.events")

# (label, order, progress_percent) — literal mirror of
# ``adscan_internal.services.scan_phases.SCAN_PHASES`` (canonical ids, global
# order, monotonic order-based percent). The precise per-command weight-based
# percent comes from the declared ``scan_plan`` event; this flat catalog is the
# worker-side backstop (AST-parsed) and the monotonic phase-order source.
#
# Kept as a literal so the Celery worker can ``ast.literal_eval`` it. The
# ``_assert_catalog_matches_ssot`` guard below fails import if it drifts.
PHASE_CATALOG: dict[str, tuple[str, int, float]] = {
    # ── Setup ─────────────────────────────────────────────────────────────────
    "dns_validation":                 ("DNS Validation",                  1,   5.6),
    "dns_configuration":              ("DNS Configuration",               2,  11.1),
    "network_preflight":              ("Network Preflight",               3,  16.7),
    "credential_setup":               ("Credential Setup",                4,  22.2),
    "domain_setup":                   ("Domain Setup",                    5,  27.8),
    # ── Collection ────────────────────────────────────────────────────────────
    "topology_and_trusts":            ("Topology & Trusts",               6,  33.3),
    "domain_collection":              ("Domain Collection",               7,  38.9),
    "domain_analysis":                ("Domain Intelligence",             8,  44.4),
    # ── Exploitation ──────────────────────────────────────────────────────────
    "attack_paths_discovery":         ("Attack Paths Discovery",          9,  50.0),
    "quick_credential_wins":          ("Quick Credential Wins",          10,  55.6),
    "password_spraying":              ("Password Spraying",              11,  61.1),
    "share_credential_hunt":          ("SMB Share Exposure",             12,  66.7),
    "unauthenticated_attack_surface": ("Unauthenticated Attack Surface", 13,  72.2),
    "audit_extras":                   ("CVE Verification",               14,  77.8),
    "post_compromise_validation":     ("Exposure Validation",            15,  83.3),
    # ── Post-Processing ───────────────────────────────────────────────────────
    "report_generation":              ("Reporting",                      16,  88.9),
    "ctem_reconciliation":            ("Post-Processing",                17,  94.4),
    "complete":                       ("Completed",                      18, 100.0),
}


def _expected_catalog_from_ssot() -> dict[str, tuple[str, int, float]]:
    """Derive the expected ``PHASE_CATALOG`` from the canonical registry.

    Returns the same shape as the literal above: ``{id: (label, order, pct)}``
    with global order and monotonic order-based percent, plus the synthetic
    terminal ``complete`` entry. Used by the import-time drift guard and the
    contract test.
    """
    from adscan_internal.services.scan_phases import SCAN_PHASES

    total = len(SCAN_PHASES)
    catalog: dict[str, tuple[str, int, float]] = {}
    for index, phase in enumerate(SCAN_PHASES):
        order = index + 1
        catalog[phase.phase_id] = (
            phase.title,
            order,
            round(order / (total + 1) * 100.0, 1),
        )
    catalog["complete"] = ("Completed", total + 1, 100.0)
    return catalog


def _assert_catalog_matches_ssot() -> None:
    """Fail loudly at import if the literal catalog drifted from the SSOT."""
    try:
        expected = _expected_catalog_from_ssot()
    except Exception:  # pragma: no cover — never block import on the guard itself
        return
    if PHASE_CATALOG != expected:
        raise AssertionError(
            "PHASE_CATALOG drifted from scan_phases.SCAN_PHASES. Regenerate the "
            "literal mirror in ci_events.py from the canonical registry."
        )


_assert_catalog_matches_ssot()


def emit_phase(phase: str, message: str = "") -> None:
    """Emit a phase-progress event looked up from ``PHASE_CATALOG``.

    This is the primary call site API.  Call sites only need the phase key;
    all metadata (label, order, percent) is resolved here.

    This is a no-op unless a structured event sink is explicitly enabled.

    Args:
        phase: Key from ``PHASE_CATALOG`` (e.g. ``"bloodhound_collection"``).
        message: Optional override for the display message; defaults to label.
    """
    if not _should_emit_events():
        return
    entry = PHASE_CATALOG.get(phase)
    if not entry:
        return
    label, order, percent = entry
    _write_event({
        "type": "phase",
        "phase": phase,
        "phase_label": label,
        "phase_order": order,
        "percent": percent,
        "message": message or label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


def emit_scan_plan(command: str, config: object | None = None) -> None:
    """Emit the declared scan plan for ``command`` as one ``scan_plan`` event.

    Called once at scan start. The plan (chapters → phases → optional subphases,
    with weight-based cumulative percent) is derived from the canonical registry
    in :mod:`adscan_internal.services.scan_phases`. The worker forwards this
    event to the web (and persists it as the ``/scans/{id}/plan`` backstop), so
    the web renders the engine-declared plan dynamically — no hardcoded phase
    list anywhere on the frontend.

    No-op unless a structured event sink is explicitly enabled, exactly like
    :func:`emit_phase`.

    Args:
        command: Canonical command key (see ``scan_phases`` ``COMMAND_*``).
        config: Optional ``ScanConfig`` whose ``phases.disabled`` set filters
            the OPTIONAL phases out of the declared plan, so the web renders
            exactly what will run. ``None`` = the full plan (default behavior).
    """
    if not _should_emit_events():
        return
    try:
        from adscan_internal.services.scan_phases import build_scan_plan

        plan = build_scan_plan(command, config)
    except Exception:  # pragma: no cover — never raise from a telemetry helper
        return
    _write_event(
        {
            "type": "scan_plan",
            "command": command,
            "plan": plan,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def emit_error(message: str) -> None:
    """Emit a structured error event to stderr (CI mode only).

    Args:
        message: Error description.
    """
    if not _should_emit_events():
        return
    _write_event({
        "type": "error",
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


def emit_event(event_type: str, **fields: object) -> None:
    """Emit one structured non-phase event to stderr in CI mode only.

    Args:
        event_type: Transport-neutral event type identifier.
        **fields: Additional serializable event payload fields.
    """
    if not _should_emit_events():
        return
    payload = {
        "type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    payload.update(fields)
    _write_event(payload)


def emit_widget(
    widget_type: str,
    *,
    key: str,
    title: str,
    data: dict,
    domain: str | None = None,
    schema_version: int | None = None,
) -> None:
    """Emit one structured *widget* event to stderr in CI mode only.

    A widget is a transport-neutral, render-agnostic data payload (see
    ``adscan_internal/cli/widgets/widget_contract.py``). The engine emits it
    once; both the CLI Rich renderer and the web premium components render this
    same contract. This is the live half — the Celery worker reads it off the
    structured stderr stream during the scan. The post-scan half is the
    persisted widget artifact (``inventory/widgets/<key>.json``), written by
    ``adscan_internal/cli/widgets/widget_artifacts.py``.

    No-op unless a structured event sink is explicitly enabled, exactly like
    :func:`emit_event` and :func:`emit_phase`.

    Args:
        widget_type: One of the contract's widget types
            (``finding-table`` / ``kpi-strip`` / ``matrix-panel``).
        key: Stable identifier, unique per ``(domain, key)``.
        title: Human-readable panel title.
        data: The type-specific JSON payload.
        domain: Optional owning domain.
        schema_version: Contract schema version; defaults applied by consumers.
    """
    if not _should_emit_events():
        return
    payload = {
        "type": "widget",
        "widget_type": widget_type,
        "key": key,
        "title": title,
        "domain": domain,
        "schema_version": schema_version,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _write_event(payload)


def emit_operation_progress(
    *,
    operation: str,
    label: str,
    phase: str | None = None,
    phase_label: str | None = None,
    current: int | None = None,
    total: int | None = None,
    percent: float | None = None,
    rate: float | None = None,
    eta_seconds: float | None = None,
    elapsed_seconds: float | None = None,
    detail: str | None = None,
    message: str | None = None,
    done: bool = False,
) -> None:
    """Emit one structured *current-operation* progress event.

    This is the live observability channel for the long-running steps that
    today only render progress to the CLI ``rich.live`` dashboard (the port
    scan, the share collector, share enumeration). The platform renders a calm
    "current operation" surface from these events so the client watches what
    the active long step is doing right now — not just the phase name.

    Pure observability plumbing: the caller must NOT change the step's own
    logic to emit this. It is a no-op unless a structured event sink is enabled,
    exactly like :func:`emit_phase`.

    Client-safe contract: ``label`` and ``detail`` are surfaced verbatim in the
    web UI, so callers MUST pass client-safe, English, vendor-neutral text
    (e.g. "Port scan", "Share collector" — never an internal tool name). The
    derived ``message`` flows through the worker's user-facing sanitizer as a
    second line of defense.

    Args:
        operation: Stable machine key for the operation (e.g. ``"port_scan"``,
            ``"share_collector"``, ``"share_enumeration"``). Drives de-dup +
            iconography on the frontend.
        label: Short client-safe display name (e.g. ``"Port scan"``).
        phase: Optional canonical ``scan_phases`` id this operation runs under.
        phase_label: Optional human phase label.
        current: Optional count completed so far (for "current of total").
        total: Optional known total; omit for an indeterminate operation.
        percent: Optional 0-100 completion when no discrete count exists.
        rate: Optional throughput in items/second, computed by the SAME estimator
            the CLI rich.live dashboard uses (``ProgressDashboard.rate`` /
            ``ProgressEstimator.rate``). Lets the platform show "1.2k objects/s"
            consistent with the terminal. Omit for an indeterminate run with no
            measured rate.
        eta_seconds: Optional estimated seconds remaining, from the same
            estimator. MUST be omitted when the total is unknown — never pass a
            fabricated ETA for an indeterminate operation.
        elapsed_seconds: Optional wall-clock seconds the operation has been
            running, surfaced verbatim so the platform shows "elapsed" like the
            CLI even when there is no total.
        detail: Optional client-safe context (e.g. the target domain).
        message: Optional pre-composed line; one is derived when omitted.
        done: Terminal-completion marker. When True this is the FINAL event for
            ``operation`` — the operation has finished. The web hides a done
            operation immediately (even while its phase is still the current
            phase), so a finished long step never freezes on its last progress
            tick. A done event also reads ``percent=100`` (forced here) so the
            UI shows a complete bar in the brief moment before it clears. Every
            operation emitter MUST fire exactly one ``done=True`` event at its
            natural completion point (loop end / ``finally``).
    """
    if not _should_emit_events():
        return

    # A completed operation always reads as 100% so the strip never lingers on a
    # mid-scan percent at the instant it finishes.
    if done:
        percent = 100.0

    if not message:
        parts: list[str] = [label]
        if current is not None and total is not None and total > 0:
            parts.append(f"{current} of {total}")
        elif current is not None:
            parts.append(str(current))
        elif percent is not None:
            parts.append(f"{round(percent)}%")
        if detail:
            parts.append(detail)
        message = " · ".join(parts)

    _write_event(
        {
            "type": "operation_progress",
            "operation": operation,
            "label": label,
            "phase": phase,
            "phase_label": phase_label,
            "current": current,
            "total": total,
            "percent": percent,
            "rate": rate,
            "eta_seconds": eta_seconds,
            "elapsed_seconds": elapsed_seconds,
            "detail": detail,
            "message": message,
            "done": done,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def emit_run_started(*, kind: str) -> None:
    """Emit the ``run_started`` lifecycle event (contract: closed object)."""
    from adscan_core.engagement.run_identity import current_run_id

    emit_event("run_started", run_id=current_run_id(), kind=kind)


def emit_run_completed(
    *, kind: str, status: str, exit_code: int, result_path: str | None = None
) -> None:
    """Emit the ``run_completed`` lifecycle event (contract: closed object).

    Args:
        kind: The RunPlan kind.
        status: ``completed`` | ``failed`` | ``cancelled`` | ``interrupted``.
        exit_code: The process exit code the run ends with.
        result_path: Workspace-relative path of ``run_summary.json``, when one
            was written.
    """
    from adscan_core.engagement.run_identity import current_run_id

    fields: dict[str, object] = {
        "run_id": current_run_id(),
        "kind": kind,
        "status": status,
        "exit_code": int(exit_code),
    }
    if result_path:
        fields["result_path"] = result_path
    emit_event("run_completed", **fields)


# --------------------------------------------------------------------------- #
# Versioned file sink (adscan.events/1)
# --------------------------------------------------------------------------- #
#
# ``ADSCAN_EVENTS_FILE`` (``adscan run --events-file``) receives the VERSIONED
# stream: a ``stream_header`` first, then every event with a contiguous ``seq``,
# appended and flushed one line at a time. It is read from the environment at
# each write (``adscan run`` sets it after this module is imported), and a change
# of path or run id starts a new stream with its own header. The stderr stream
# below keeps its historical line shape (no header, no seq) because the appliance
# worker parses it today. Event PAYLOADS are not frozen: interactive_resolution,
# for one, now nests the operator's answer under ``response`` on both sinks.

EVENTS_SCHEMA_TAG = "adscan.events/1"
_EVENTS_FILE_ENV = "ADSCAN_EVENTS_FILE"
_RUN_KIND_ENV = "ADSCAN_RUN_KIND"
_RUN_KINDS = frozenset({"scan", "recheck", "postprocess", "doctor", "deliver"})

_FILE_LOCK = threading.Lock()


class _EventFileStream:
    """One open versioned stream: the handle, its identity and its counter."""

    def __init__(self, path: str, run_id: str, handle) -> None:
        self.path = path
        self.run_id = run_id
        self.handle = handle
        self.seq = 0
        self.torn = False

    def write(self, event: dict) -> None:
        """Append one event line; ``seq`` is consumed only by a line that landed.

        The line is serialised BEFORE a sequence number is taken, so an event
        that cannot be serialised consumes none. A write that failed part-way
        (disk full) may have left a fragment; the next line then starts with a
        newline, so the fragment sits alone on its own line and every later line
        is whole.
        """
        seq = self.seq + 1
        line = dict(event)
        line["seq"] = seq
        text = json.dumps(line, ensure_ascii=False) + "\n"
        if self.torn:
            text = "\n" + text
        try:
            self.handle.write(text)
            self.handle.flush()
        except Exception:
            self.torn = True
            raise
        self.torn = False
        self.seq = seq


_FILE_STREAM: _EventFileStream | None = None


def _events_file_path() -> str | None:
    value = str(os.environ.get(_EVENTS_FILE_ENV, "") or "").strip()
    return value or None


def reset_event_file_stream() -> None:
    """Close the current versioned stream (tests, and the end of a run)."""
    global _FILE_STREAM  # noqa: PLW0603
    with _FILE_LOCK:
        if _FILE_STREAM is not None:
            try:
                _FILE_STREAM.handle.close()
            except Exception:  # pragma: no cover — closing must never raise
                pass
        _FILE_STREAM = None


def _open_stream(path: str) -> _EventFileStream:
    from adscan_core.engagement.run_identity import current_run_id

    run_id = current_run_id()
    handle = open(path, "a", encoding="utf-8")  # noqa: SIM115 — kept open for the run
    stream = _EventFileStream(path, run_id, handle)
    header: dict[str, object] = {
        "type": "stream_header",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema": EVENTS_SCHEMA_TAG,
        "run_id": run_id,
    }
    kind = str(os.environ.get(_RUN_KIND_ENV, "") or "").strip()
    if kind in _RUN_KINDS:
        header["kind"] = kind
    stream.write(header)
    return stream


def _write_event_file(event: dict) -> None:
    """Append ``event`` to the versioned stream, opening it (with a header) if needed."""
    global _FILE_STREAM  # noqa: PLW0603
    path = _events_file_path()
    if path is None:
        return
    from adscan_core.engagement.run_identity import current_run_id

    with _FILE_LOCK:
        stream = _FILE_STREAM
        if stream is None or stream.path != path or stream.run_id != current_run_id():
            if stream is not None:
                try:
                    stream.handle.close()
                except Exception:  # pragma: no cover
                    pass
            stream = _FILE_STREAM = _open_stream(path)
        stream.write(event)


def _write_event(event: dict) -> None:
    """Serialize one event to every enabled sink.

    stderr carries the historical shape (no header, no ``seq``) when the
    ``stderr-json`` sink is on; the versioned file gets the same payload plus
    its sequence number. A failing sink never raises into the scan.
    """
    _debug_event("emit", event)
    if _CI_SESSION and _STRUCTURED_STDERR_ENABLED:
        try:
            sys.stderr.write(json.dumps(event, ensure_ascii=False) + "\n")
            sys.stderr.flush()
        except Exception:  # pragma: no cover — never raise from telemetry-like helper
            pass
    try:
        _write_event_file(event)
    except Exception as exc:  # noqa: BLE001 — never raise from telemetry-like helper
        _LOGGER.debug("Event file sink write failed: %s", exc, exc_info=True)


def _should_emit_events() -> bool:
    """Return whether any structured execution event sink is enabled."""
    return (_CI_SESSION and _STRUCTURED_STDERR_ENABLED) or _events_file_path() is not None


def _debug_event(stage: str, event: dict) -> None:
    """Emit debug-only telemetry about structured event publication."""
    if not _EVENT_DEBUG:
        return

    try:
        from adscan_core.rich_output import mark_sensitive, print_event_debug

        def _mask(key: str, value: object) -> str:
            text = str(value)
            key_lower = key.lower()
            if key_lower in {"username", "user"}:
                return mark_sensitive(text, "user")
            if key_lower in {"domain", "realm", "forest"}:
                return mark_sensitive(text, "domain")
            if key_lower in {"host", "hostname", "target_host"}:
                return mark_sensitive(text, "hostname")
            if key_lower in {"service", "credential_type", "metric_type", "scope", "phase"}:
                return mark_sensitive(text, "service")
            return text

        keys_of_interest = (
            "type",
            "phase",
            "phase_label",
            "username",
            "domain",
            "host",
            "service",
            "metric_type",
            "count",
            "reachable_ips",
            "total_ips",
            "possible_segments",
            "scope",
        )
        summary_parts = [
            f"{key}={_mask(key, event[key])}"
            for key in keys_of_interest
            if key in event and event.get(key) not in (None, "")
        ]
        summary = " ".join(summary_parts) if summary_parts else json.dumps(event, ensure_ascii=False)
        print_event_debug(f"[{stage}] {summary}")
    except Exception as exc:  # pragma: no cover - diagnostic path must never fail emission
        _LOGGER.debug("Event debug output failed: %s", exc, exc_info=True)
