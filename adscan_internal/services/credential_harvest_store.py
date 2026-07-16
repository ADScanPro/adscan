"""Durable ``credential_harvest.json`` workspace artifact.

Single source of truth for the persisted view of every harvested principal
across all four surfaces (poisoning, spraying, kerberoasting, AS-REP
roasting). The CLI panel renders from this file; the PDF report and the web
dashboard (a documented follow-on — see
docs/superpowers/specs/2026-07-07-cracking-job-and-credential-harvest-design.md
§ Data flow) ingest the SAME artifact, so this is the one place the schema is
defined.

Mirrors the JSON-persistence pattern of
``adscan_internal.services.background_jobs.registry`` (best-effort read,
corrupt-file resilience via ``read_json_file``, stable
``write_json_file`` formatting).
"""
from __future__ import annotations

import os
from typing import Any

from adscan_core import telemetry
from adscan_internal.services.credential_harvest_record import HarvestedPrincipal
from adscan_internal.workspaces.io import read_json_file, write_json_file

HARVEST_ARTIFACT_FILENAME = "credential_harvest.json"
_SCHEMA_VERSION = "1.0"


def _artifact_path(shell: Any) -> str | None:
    workspace_dir = getattr(shell, "current_workspace_dir", None)
    if not workspace_dir:
        return None
    return os.path.join(str(workspace_dir), HARVEST_ARTIFACT_FILENAME)


def load_harvest_records(shell: Any) -> list[HarvestedPrincipal]:
    """Load every persisted harvested principal. Never raises."""
    path = _artifact_path(shell)
    if not path or not os.path.exists(path):
        return []
    try:
        raw = read_json_file(path)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return []
    principals = raw.get("principals") if isinstance(raw, dict) else None
    if not isinstance(principals, list):
        return []
    return [
        HarvestedPrincipal.from_dict(entry)
        for entry in principals
        if isinstance(entry, dict)
    ]


def append_harvest_records(shell: Any, records: list[HarvestedPrincipal]) -> None:
    """Upsert ``records`` into the workspace artifact, keyed by (domain, username).

    A record for a principal already present overwrites the stored one (the
    newest harvest event — e.g. a fresh crack, or a stronger tier/reach signal
    from a later scan phase — wins). Best-effort: any I/O or serialization
    failure is telemetered and swallowed, never raised, so a persistence
    failure never blocks the harvesting surface that called this.
    """
    if not records:
        return
    path = _artifact_path(shell)
    if not path:
        return
    try:
        existing = load_harvest_records(shell)
        by_key: dict[tuple[str, str], HarvestedPrincipal] = {
            (rec.domain.strip().lower(), rec.username.strip().lower()): rec
            for rec in existing
        }
        for record in records:
            key = (record.domain.strip().lower(), record.username.strip().lower())
            by_key[key] = record
        payload = {
            "schema": _SCHEMA_VERSION,
            "principals": [rec.to_dict() for rec in by_key.values()],
        }
        os.makedirs(os.path.dirname(path), exist_ok=True)
        write_json_file(path, payload)
    except Exception as exc:  # noqa: BLE001 — persistence is best-effort
        telemetry.capture_exception(exc)


__all__ = [
    "HARVEST_ARTIFACT_FILENAME",
    "append_harvest_records",
    "load_harvest_records",
]
