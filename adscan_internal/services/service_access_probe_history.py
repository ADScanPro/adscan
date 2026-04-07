"""Persist and query service-access probe history."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import os
from typing import Any

from adscan_internal.workspaces import domain_subpath, write_json_file
from adscan_internal.workspaces.io import read_json_file


SERVICE_ACCESS_PROBE_HISTORY_FILENAME = "service_access_probe_history.json"


@dataclass(frozen=True, slots=True)
class ServiceAccessProbeRecord:
    """Structured record for one user/service/host access probe."""

    domain: str
    username: str
    service: str
    host: str
    result: str
    checked_at: str
    source: str
    backend: str
    pivot_capable: bool


def _normalize_probe_key(*, username: str, service: str, host: str) -> str:
    """Return a stable case-insensitive key for one probe tuple."""

    return "|".join(
        [
            str(username or "").strip().lower(),
            str(service or "").strip().lower(),
            str(host or "").strip().lower(),
        ]
    )


def _history_path(*, workspace_dir: str, domains_dir: str, domain: str) -> str:
    """Return the persisted history file path for one domain."""

    return domain_subpath(
        workspace_dir,
        domains_dir,
        domain,
        SERVICE_ACCESS_PROBE_HISTORY_FILENAME,
    )


def load_service_access_probe_history(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> list[dict[str, Any]]:
    """Load persisted service-access probe records for one domain."""

    path = _history_path(workspace_dir=workspace_dir, domains_dir=domains_dir, domain=domain)
    try:
        payload = read_json_file(path)
    except OSError:
        return []
    if not isinstance(payload, dict):
        return []
    records = payload.get("records")
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict)]


def save_service_access_probe_history(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    records: list[dict[str, Any]],
) -> None:
    """Persist service-access probe records for one domain."""

    path = _history_path(workspace_dir=workspace_dir, domains_dir=domains_dir, domain=domain)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "schema_version": "1.0",
        "updated_at": datetime.now(UTC).isoformat(),
        "domain": domain,
        "records": records,
    }
    write_json_file(path, payload)


def record_service_access_probe_batch(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
    username: str,
    service: str,
    targets: list[str],
    confirmed_hosts: list[str],
    source: str,
    backend: str,
    pivot_capable: bool,
) -> list[dict[str, Any]]:
    """Upsert one batch of probes for a user/service across multiple targets."""

    existing_records = load_service_access_probe_history(
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=domain,
    )
    records_by_key = {
        _normalize_probe_key(
            username=str(record.get("username") or ""),
            service=str(record.get("service") or ""),
            host=str(record.get("host") or ""),
        ): dict(record)
        for record in existing_records
    }
    confirmed_set = {
        str(host or "").strip().lower()
        for host in confirmed_hosts
        if str(host or "").strip()
    }
    timestamp = datetime.now(UTC).isoformat()
    for raw_target in targets:
        target = str(raw_target or "").strip()
        if not target:
            continue
        record = ServiceAccessProbeRecord(
            domain=domain,
            username=username,
            service=service,
            host=target,
            result="confirmed" if target.lower() in confirmed_set else "unconfirmed",
            checked_at=timestamp,
            source=source,
            backend=backend,
            pivot_capable=bool(pivot_capable),
        )
        records_by_key[
            _normalize_probe_key(username=username, service=service, host=target)
        ] = asdict(record)

    updated_records = sorted(
        records_by_key.values(),
        key=lambda item: (
            str(item.get("username") or "").lower(),
            str(item.get("service") or "").lower(),
            str(item.get("host") or "").lower(),
        ),
    )
    save_service_access_probe_history(
        workspace_dir=workspace_dir,
        domains_dir=domains_dir,
        domain=domain,
        records=updated_records,
    )
    return updated_records


def partition_targets_by_probe_history(
    *,
    records: list[dict[str, Any]],
    username: str,
    service: str,
    targets: list[str],
) -> tuple[list[str], list[dict[str, Any]]]:
    """Split targets into fresh and previously tested sets for one user/service.

    Args:
        records: Previously persisted probe records for the domain.
        username: Username attempting the probe.
        service: Service name being tested.
        targets: Candidate host identifiers in display order.

    Returns:
        A tuple of ``(fresh_targets, previously_tested_records)``. The second
        element preserves target order and includes the matching persisted
        record for each previously tested target.
    """
    history_by_key = {
        _normalize_probe_key(
            username=str(record.get("username") or ""),
            service=str(record.get("service") or ""),
            host=str(record.get("host") or ""),
        ): record
        for record in records
        if isinstance(record, dict)
    }

    fresh_targets: list[str] = []
    previously_tested_records: list[dict[str, Any]] = []
    for raw_target in targets:
        target = str(raw_target or "").strip()
        if not target:
            continue
        key = _normalize_probe_key(username=username, service=service, host=target)
        record = history_by_key.get(key)
        if record is None:
            fresh_targets.append(target)
            continue
        previously_tested_records.append(dict(record))

    return fresh_targets, previously_tested_records
