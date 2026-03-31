"""Structured execution event emitter for opt-in machine-readable scan telemetry.

This module is intentionally transport-neutral. When a compatible execution
sink is enabled, it writes JSON-encoded progress events to **stderr** so an
external orchestrator can parse them on a separate pipe without interfering
with the human-readable stdout output.

Each event is a single JSON line:
    {"type": "phase", "phase": "bloodhound_collection", ...}

**Single source of truth:** ``PHASE_CATALOG`` owns every phase's label, order,
and progress percentage.  Call sites just call ``emit_phase("phase_id")`` —
no metadata duplication anywhere in the codebase.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import logging

_EVENT_SINK: str = str(os.environ.get("ADSCAN_EVENT_SINK", "") or "").strip().lower()
_STRUCTURED_STDERR_ENABLED: bool = _EVENT_SINK == "stderr-json"
# Keep the historical CI marker as an additional guard, but require the sink.
_CI_SESSION: bool = os.environ.get("ADSCAN_SESSION_ENV") == "ci"
_EVENT_DEBUG: bool = os.environ.get("ADSCAN_EVENT_DEBUG") == "1"
_LOGGER = logging.getLogger("adscan.events")

# (label, order, progress_percent)
PHASE_CATALOG: dict[str, tuple[str, int, float]] = {
    # ── Pre-scan setup ────────────────────────────────────────────────────────
    "dns_validation":         ("DNS Validation",          1,   3.0),
    "dns_configuration":      ("DNS Configuration",       2,   7.0),
    "network_preflight":      ("Network Preflight",       3,  10.0),
    "credential_setup":       ("Credential Setup",        4,  12.0),
    "domain_setup":           ("Domain Setup",            5,  14.0),
    # ── Authenticated scan setup ──────────────────────────────────────────────
    "trust_enumeration":      ("Trust Analysis",          6,  17.0),
    "graph_collection":       ("Directory Collection",    7,  22.0),
    # ── Main scan phases ──────────────────────────────────────────────────────
    "domain_analysis":        ("Domain Analysis",         8,  38.0),
    "attack_paths_discovery": ("Exposure Path Analysis",  9,  55.0),
    "attack_path_execution":  ("Exposure Validation",    10,  70.0),
    "roasting_&_cracking":    ("Credential Analysis",    11,  82.0),
    "report_generation":      ("Reporting",              12,  92.0),
    "ctem_reconciliation":    ("Post-Processing",        13,  97.0),
    "complete":               ("Completed",              14, 100.0),
}


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


def _write_event(event: dict) -> None:
    """Serialize and write a single JSON event line to stderr."""
    try:
        _debug_event("emit", event)
        sys.stderr.write(json.dumps(event, ensure_ascii=False) + "\n")
        sys.stderr.flush()
    except Exception:  # pragma: no cover — never raise from telemetry-like helper
        pass


def _should_emit_events() -> bool:
    """Return whether structured execution events are explicitly enabled."""
    return _CI_SESSION and _STRUCTURED_STDERR_ENABLED


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
