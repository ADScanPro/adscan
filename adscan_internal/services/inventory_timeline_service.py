"""Per-domain persistent timeline of current-vantage reachability snapshots.

This service is the centralized core for inventory history, diff computation,
and Rich CLI rendering. Both the workspace-load freshness flow and the
post-pivot follow-up flow consume this module so deltas are computed
consistently and persisted under each domain.

Disk layout (per domain)::

    domains/<domain>/
    ├── network_reachability_report.json        ← latest (untouched)
    └── inventory_timeline/
        ├── index.jsonl                          ← append-only index
        └── snap_<ISO-timestamp-Z>.json          ← full snapshot payloads

Snapshots are content-deduplicated: writing an identical snapshot is a no-op
and returns the existing entry. Snapshots are GC'd to a maximum of
``MAX_SNAPSHOTS_PER_DOMAIN`` per domain. CTF workspaces opt out entirely.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
import re
import tempfile
from typing import Any, Literal

from rich.table import Table

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info,
    print_info_debug,
    print_panel,
    print_warning,
)
from adscan_internal.workspaces import domain_subpath, write_json_file
from adscan_internal.workspaces.io import read_json_file
from adscan_core.rich_output import print_exception


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INVENTORY_TIMELINE_DIRNAME = "inventory_timeline"
INVENTORY_TIMELINE_INDEX_FILENAME = "index.jsonl"
INVENTORY_TIMELINE_SCHEMA_VERSION = "1.0"
MAX_SNAPSHOTS_PER_DOMAIN = 50

TRIGGER_PHASE1_INITIAL = "phase1_initial"
TRIGGER_WORKSPACE_LOAD_REFRESH = "workspace_load_refresh"
TRIGGER_MANUAL_REFRESH_INVENTORY = "manual_refresh_inventory"
TRIGGER_POST_PIVOT = "post_pivot"

_REACHABLE_STATUSES = frozenset(
    {
        "open_service_observed",
        "host_responded_no_important_ports_open",
        "responded_to_discovery",
    }
)

_SERVICE_LABELS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    139: "SMB/NetBIOS",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    636: "LDAPS",
    1433: "MSSQL",
    1521: "Oracle",
    3268: "Global Catalog",
    3269: "Global Catalog/LDAPS-GC",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5985: "WinRM",
    5986: "WinRM/HTTPS",
    6379: "Redis",
    9100: "Printer/JetDirect",
    27017: "MongoDB",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InventorySnapshotIndexEntry:
    """One indexed snapshot entry (slim metadata, references payload file)."""

    id: str
    at: str
    trigger: str
    trigger_detail: str
    snapshot_file: str
    reachable_count: int | None
    no_response_count: int | None
    total_count: int | None
    important_port_scan_performed: bool | None


@dataclass(frozen=True, slots=True)
class HostChange:
    """One host that became reachable or stopped being reachable."""

    ip: str
    display_name: str
    hostname_candidates: tuple[str, ...]
    previous_status: str | None
    current_status: str | None
    open_ports: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PortChange:
    """One per-host port that opened or closed between two snapshots."""

    ip: str
    display_name: str
    port: int
    service_label: str
    direction: Literal["opened", "closed"]


@dataclass(frozen=True, slots=True)
class InventoryDiff:
    """Structured diff between two inventory snapshots for one domain."""

    domain: str
    before_id: str | None
    after_id: str
    before_at: str | None
    after_at: str
    hosts_added: tuple[HostChange, ...]
    hosts_removed: tuple[HostChange, ...]
    ports_opened: tuple[PortChange, ...]
    ports_closed: tuple[PortChange, ...]
    caveats: tuple[str, ...]
    is_empty: bool


# ---------------------------------------------------------------------------
# Workspace plumbing
# ---------------------------------------------------------------------------


def _workspace_dir(shell: Any) -> str:
    """Return the active workspace root for the given shell."""

    return str(getattr(shell, "current_workspace_dir", "") or "").strip()


def _domains_dir(shell: Any) -> str:
    """Return the domains directory name configured on the shell."""

    return (
        str(getattr(shell, "domains_dir", "domains") or "domains").strip() or "domains"
    )


def _timeline_dir(shell: Any, *, domain: str) -> str:
    """Return the per-domain timeline directory path."""

    return domain_subpath(
        _workspace_dir(shell),
        _domains_dir(shell),
        domain,
        INVENTORY_TIMELINE_DIRNAME,
    )


def _index_path(shell: Any, *, domain: str) -> str:
    """Return the per-domain timeline index file path."""

    return os.path.join(
        _timeline_dir(shell, domain=domain), INVENTORY_TIMELINE_INDEX_FILENAME
    )


def _report_path(shell: Any, *, domain: str) -> str:
    """Return the latest current-vantage reachability report path."""

    return domain_subpath(
        _workspace_dir(shell),
        _domains_dir(shell),
        domain,
        "network_reachability_report.json",
    )


def is_timeline_enabled(shell: Any) -> bool:
    """Return whether inventory timeline is enabled for the active workspace.

    CTF workspaces opt out: the snapshot churn there is not useful and the
    extra files clutter the per-domain directory.
    """

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    return workspace_type != "ctf"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _format_snapshot_id(when: datetime) -> str:
    """Return a filesystem-safe snapshot id from a UTC ``datetime``."""

    text = when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    return f"snap_{text}"


def _iso_now() -> str:
    return _now_utc().isoformat().replace("+00:00", "Z")


def _atomic_write_text(path: str, text: str) -> None:
    """Write ``text`` to ``path`` atomically via tmp+rename."""

    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _is_reachable_entry(entry: dict[str, Any]) -> bool:
    status = str(entry.get("status") or "").strip()
    return status in _REACHABLE_STATUSES


def _display_name_for_entry(entry: dict[str, Any]) -> str:
    candidates = entry.get("hostname_candidates", [])
    if isinstance(candidates, list):
        for candidate in candidates:
            text = str(candidate or "").strip()
            if text:
                return text
    return str(entry.get("ip") or "").strip()


def _hostname_candidates_tuple(entry: dict[str, Any]) -> tuple[str, ...]:
    candidates = entry.get("hostname_candidates", [])
    if not isinstance(candidates, list):
        return ()
    out: list[str] = []
    for candidate in candidates:
        text = str(candidate or "").strip()
        if text:
            out.append(text)
    return tuple(out)


def _open_ports_tuple(entry: dict[str, Any]) -> tuple[int, ...]:
    raw = entry.get("open_ports") or []
    if not isinstance(raw, list):
        return ()
    ports: list[int] = []
    for value in raw:
        try:
            ports.append(int(value))
        except (TypeError, ValueError):
            continue
    return tuple(sorted(set(ports)))


def service_label_for_port(port: int) -> str:
    """Return the operator-facing label for a TCP port number."""

    label = _SERVICE_LABELS.get(int(port))
    if label:
        return label
    return f"port/{int(port)}"


# ---------------------------------------------------------------------------
# Index I/O
# ---------------------------------------------------------------------------


def _read_index(shell: Any, *, domain: str) -> list[InventorySnapshotIndexEntry]:
    path = _index_path(shell, domain=domain)
    if not os.path.exists(path):
        return []
    entries: list[InventorySnapshotIndexEntry] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                summary = record.get("summary") or {}
                if not isinstance(summary, dict):
                    summary = {}
                entries.append(
                    InventorySnapshotIndexEntry(
                        id=str(record.get("id") or "").strip(),
                        at=str(record.get("at") or "").strip(),
                        trigger=str(record.get("trigger") or "").strip(),
                        trigger_detail=str(record.get("trigger_detail") or "").strip(),
                        snapshot_file=str(record.get("snapshot_file") or "").strip(),
                        reachable_count=(
                            int(summary["reachable"])
                            if isinstance(summary.get("reachable"), int)
                            else None
                        ),
                        no_response_count=(
                            int(summary["no_response"])
                            if isinstance(summary.get("no_response"), int)
                            else None
                        ),
                        total_count=(
                            int(summary["total"])
                            if isinstance(summary.get("total"), int)
                            else None
                        ),
                        important_port_scan_performed=(
                            bool(summary["important_port_scan_performed"])
                            if "important_port_scan_performed" in summary
                            else None
                        ),
                    )
                )
    except OSError:
        return []
    return [entry for entry in entries if entry.id and entry.snapshot_file]


def _write_index(
    shell: Any, *, domain: str, entries: list[InventorySnapshotIndexEntry]
) -> None:
    path = _index_path(shell, domain=domain)
    lines: list[str] = []
    for entry in entries:
        record = {
            "id": entry.id,
            "at": entry.at,
            "trigger": entry.trigger,
            "trigger_detail": entry.trigger_detail,
            "snapshot_file": entry.snapshot_file,
            "summary": {
                "reachable": entry.reachable_count,
                "no_response": entry.no_response_count,
                "total": entry.total_count,
                "important_port_scan_performed": entry.important_port_scan_performed,
            },
        }
        lines.append(json.dumps(record, sort_keys=True))
    text = "\n".join(lines) + ("\n" if lines else "")
    _atomic_write_text(path, text)


def _snapshot_path(shell: Any, *, domain: str, snapshot_file: str) -> str:
    return os.path.join(_timeline_dir(shell, domain=domain), snapshot_file)


# ---------------------------------------------------------------------------
# Public lookup helpers
# ---------------------------------------------------------------------------


def list_snapshots(shell: Any, *, domain: str) -> list[InventorySnapshotIndexEntry]:
    """Return all snapshots for ``domain`` ordered oldest → newest."""

    if not is_timeline_enabled(shell):
        return []
    return _read_index(shell, domain=domain)


def load_snapshot_payload(
    shell: Any, *, domain: str, snapshot_id: str
) -> dict[str, Any] | None:
    """Load the full payload for ``snapshot_id`` from the timeline."""

    if not is_timeline_enabled(shell):
        return None
    entries = _read_index(shell, domain=domain)
    entry = next((item for item in entries if item.id == snapshot_id), None)
    if entry is None:
        return None
    path = _snapshot_path(shell, domain=domain, snapshot_file=entry.snapshot_file)
    if not os.path.exists(path):
        return None
    try:
        return read_json_file(path)
    except (OSError, json.JSONDecodeError):
        return None


def find_snapshot_at_or_before(
    shell: Any, *, domain: str, when: datetime
) -> InventorySnapshotIndexEntry | None:
    """Return the latest snapshot whose ``at`` is at or before ``when``."""

    if not is_timeline_enabled(shell):
        return None
    target = (
        when.astimezone(timezone.utc)
        if when.tzinfo
        else when.replace(tzinfo=timezone.utc)
    )
    matching: InventorySnapshotIndexEntry | None = None
    for entry in _read_index(shell, domain=domain):
        parsed = _parse_iso_timestamp(entry.at)
        if parsed is None:
            continue
        if parsed <= target:
            matching = entry
        else:
            break
    return matching


def _parse_iso_timestamp(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


_SINCE_RELATIVE_RE = re.compile(r"^\s*(\d+)\s*([dhm])\s*$", re.IGNORECASE)
_SINCE_HHMM_RE = re.compile(r"^\s*(\d{1,2}):(\d{2})\s*$")


def parse_since_expression(value: str) -> datetime | None:
    """Parse ``Nd`` / ``Nh`` / ``Nm`` / ``HH:MM`` / ISO-8601 into UTC datetime.

    Returns ``None`` when the expression is invalid or empty.
    """

    text = str(value or "").strip()
    if not text:
        return None

    rel = _SINCE_RELATIVE_RE.match(text)
    if rel:
        amount = int(rel.group(1))
        unit = rel.group(2).lower()
        if unit == "d":
            delta = timedelta(days=amount)
        elif unit == "h":
            delta = timedelta(hours=amount)
        else:
            delta = timedelta(minutes=amount)
        return _now_utc() - delta

    hhmm = _SINCE_HHMM_RE.match(text)
    if hhmm:
        hour = int(hhmm.group(1))
        minute = int(hhmm.group(2))
        if 0 <= hour < 24 and 0 <= minute < 60:
            today_local = datetime.now().astimezone()
            local_target = today_local.replace(
                hour=hour, minute=minute, second=0, microsecond=0
            )
            return local_target.astimezone(timezone.utc)
        return None

    return _parse_iso_timestamp(text)


# ---------------------------------------------------------------------------
# Snapshot recording
# ---------------------------------------------------------------------------


def _build_summary(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("summary") if isinstance(payload, dict) else None
    if not isinstance(summary, dict):
        summary = {}
    return {
        "reachable": (
            int(summary["responsive_ips"])
            if isinstance(summary.get("responsive_ips"), int)
            else None
        ),
        "no_response": (
            int(summary["no_response_ips"])
            if isinstance(summary.get("no_response_ips"), int)
            else None
        ),
        "total": (
            int(summary["total_ips"])
            if isinstance(summary.get("total_ips"), int)
            else None
        ),
        "important_port_scan_performed": (
            bool(summary["important_port_scan_performed"])
            if "important_port_scan_performed" in summary
            else None
        ),
    }


def _payload_fingerprint(payload: dict[str, Any]) -> tuple[Any, ...]:
    summary = _build_summary(payload)
    ips_block = payload.get("ips") if isinstance(payload, dict) else None
    ip_signatures: set[tuple[str, str, frozenset[int]]] = set()
    if isinstance(ips_block, list):
        for entry in ips_block:
            if not isinstance(entry, dict):
                continue
            ip = str(entry.get("ip") or "").strip()
            if not ip:
                continue
            status = str(entry.get("status") or "").strip()
            ip_signatures.add((ip, status, frozenset(_open_ports_tuple(entry))))
    return (
        summary.get("reachable"),
        summary.get("no_response"),
        summary.get("total"),
        summary.get("important_port_scan_performed"),
        frozenset(ip_signatures),
    )


def record_inventory_snapshot(
    shell: Any,
    *,
    domain: str,
    trigger: str,
    trigger_detail: str = "",
) -> InventorySnapshotIndexEntry | None:
    """Record one snapshot of the current reachability report for ``domain``.

    Idempotent: if the latest indexed snapshot has the same fingerprint
    (summary + per-IP status + per-IP open ports), no new file is written and
    the existing index entry is returned.

    Returns ``None`` when timeline is disabled, the report is missing, or the
    workspace is incomplete.
    """

    if not is_timeline_enabled(shell):
        return None
    workspace_dir = _workspace_dir(shell)
    domain_value = str(domain or "").strip()
    if not workspace_dir or not domain_value:
        return None

    report_path = _report_path(shell, domain=domain_value)
    if not os.path.exists(report_path):
        return None

    try:
        payload = read_json_file(report_path)
    except (OSError, json.JSONDecodeError) as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            "[inventory-timeline] failed to read reachability report for "
            f"{mark_sensitive(domain_value, 'domain')}: {exc}"
        )
        return None
    if not isinstance(payload, dict):
        return None

    entries = _read_index(shell, domain=domain_value)
    fingerprint = _payload_fingerprint(payload)
    if entries:
        latest = entries[-1]
        latest_payload = load_snapshot_payload(
            shell, domain=domain_value, snapshot_id=latest.id
        )
        if (
            isinstance(latest_payload, dict)
            and _payload_fingerprint(latest_payload) == fingerprint
        ):
            print_info_debug(
                "[inventory-timeline] snapshot deduplicated against latest entry: "
                f"domain={mark_sensitive(domain_value, 'domain')} id={latest.id}"
            )
            return latest

    when = _now_utc()
    snapshot_id = _format_snapshot_id(when)
    # Ensure uniqueness even if a second snapshot is requested in the same second.
    existing_ids = {entry.id for entry in entries}
    if snapshot_id in existing_ids:
        suffix = 1
        while f"{snapshot_id}_{suffix}" in existing_ids:
            suffix += 1
        snapshot_id = f"{snapshot_id}_{suffix}"

    snapshot_file = f"{snapshot_id}.json"
    timeline_dir = _timeline_dir(shell, domain=domain_value)
    os.makedirs(timeline_dir, exist_ok=True)
    snapshot_full_path = os.path.join(timeline_dir, snapshot_file)
    enriched = dict(payload)
    enriched.setdefault("snapshot_id", snapshot_id)
    enriched.setdefault("snapshot_at", when.isoformat().replace("+00:00", "Z"))
    enriched.setdefault("trigger", trigger)
    enriched.setdefault("trigger_detail", trigger_detail)
    try:
        write_json_file(snapshot_full_path, enriched)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            "[inventory-timeline] failed to write snapshot for "
            f"{mark_sensitive(domain_value, 'domain')}: {exc}"
        )
        return None

    summary = _build_summary(payload)
    new_entry = InventorySnapshotIndexEntry(
        id=snapshot_id,
        at=when.isoformat().replace("+00:00", "Z"),
        trigger=trigger,
        trigger_detail=trigger_detail,
        snapshot_file=snapshot_file,
        reachable_count=summary["reachable"],
        no_response_count=summary["no_response"],
        total_count=summary["total"],
        important_port_scan_performed=summary["important_port_scan_performed"],
    )
    entries.append(new_entry)

    # GC oldest snapshots when over the cap.
    if len(entries) > MAX_SNAPSHOTS_PER_DOMAIN:
        excess = len(entries) - MAX_SNAPSHOTS_PER_DOMAIN
        evicted = entries[:excess]
        entries = entries[excess:]
        for old in evicted:
            try:
                old_path = _snapshot_path(
                    shell, domain=domain_value, snapshot_file=old.snapshot_file
                )
                if os.path.exists(old_path):
                    os.unlink(old_path)
            except OSError as exc:
                print_info_debug(
                    f"[inventory-timeline] failed to evict old snapshot {old.id}: {exc}"
                )

    try:
        _write_index(shell, domain=domain_value, entries=entries)
    except OSError as exc:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            "[inventory-timeline] failed to update index for "
            f"{mark_sensitive(domain_value, 'domain')}: {exc}"
        )
        return None

    return new_entry


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------


def _index_payload_by_ip(payload: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict):
        return {}
    ips = payload.get("ips") or []
    if not isinstance(ips, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for entry in ips:
        if not isinstance(entry, dict):
            continue
        ip = str(entry.get("ip") or "").strip()
        if not ip:
            continue
        result[ip] = entry
    return result


def _important_port_scan(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict):
        return False
    summary = payload.get("summary") or {}
    if not isinstance(summary, dict):
        return False
    return bool(summary.get("important_port_scan_performed"))


def compute_inventory_diff(
    *,
    domain: str,
    before_payload: dict[str, Any] | None,
    before_id: str | None,
    before_at: str | None,
    after_payload: dict[str, Any],
    after_id: str,
    after_at: str,
) -> InventoryDiff:
    """Pure function returning the structured diff between two snapshots."""

    before_map = _index_payload_by_ip(before_payload)
    after_map = _index_payload_by_ip(after_payload)
    before_has_ports = _important_port_scan(before_payload) if before_payload else False
    after_has_ports = _important_port_scan(after_payload)

    hosts_added: list[HostChange] = []
    hosts_removed: list[HostChange] = []
    ports_opened: list[PortChange] = []
    ports_closed: list[PortChange] = []
    caveats: list[str] = []

    if before_payload is None:
        caveats.append(
            "no prior snapshot: first observation, port-level comparison skipped"
        )

    # Hosts added: reachable in after but not (or not reachable) in before.
    for ip, after_entry in after_map.items():
        if not _is_reachable_entry(after_entry):
            continue
        before_entry = before_map.get(ip)
        was_reachable_before = bool(before_entry and _is_reachable_entry(before_entry))
        if was_reachable_before:
            continue
        hosts_added.append(
            HostChange(
                ip=ip,
                display_name=_display_name_for_entry(after_entry) or ip,
                hostname_candidates=_hostname_candidates_tuple(after_entry),
                previous_status=(
                    str(before_entry.get("status") or "").strip()
                    if isinstance(before_entry, dict)
                    else None
                ),
                current_status=str(after_entry.get("status") or "").strip(),
                open_ports=_open_ports_tuple(after_entry),
            )
        )

    # Hosts removed: reachable in before, not (or absent) in after. Skip if no before.
    if before_payload is not None:
        for ip, before_entry in before_map.items():
            if not _is_reachable_entry(before_entry):
                continue
            after_entry = after_map.get(ip)
            still_reachable = bool(after_entry and _is_reachable_entry(after_entry))
            if still_reachable:
                continue
            hosts_removed.append(
                HostChange(
                    ip=ip,
                    display_name=_display_name_for_entry(before_entry) or ip,
                    hostname_candidates=_hostname_candidates_tuple(before_entry),
                    previous_status=str(before_entry.get("status") or "").strip(),
                    current_status=(
                        str(after_entry.get("status") or "").strip()
                        if isinstance(after_entry, dict)
                        else None
                    ),
                    open_ports=_open_ports_tuple(before_entry),
                )
            )

    # Port-level deltas only when both sides have a service-scan baseline.
    added_ips = {host.ip for host in hosts_added}
    removed_ips = {host.ip for host in hosts_removed}

    if before_payload is None:
        # Caveat already recorded above.
        pass
    elif not before_has_ports:
        caveats.append("port-level comparison skipped: discovery-only baseline")
    elif not after_has_ports:
        caveats.append("port-level comparison skipped: discovery-only current snapshot")
    else:
        # Both sides have port info. Compare per-IP open_ports for IPs present in both
        # AND not already covered by a host-level add/remove.
        common_ips = (
            (set(before_map.keys()) & set(after_map.keys())) - added_ips - removed_ips
        )
        for ip in common_ips:
            before_entry = before_map[ip]
            after_entry = after_map[ip]
            # Only meaningful when at least one side is reachable; closed ports on a
            # host that disappeared are already represented in hosts_removed.
            before_ports = set(_open_ports_tuple(before_entry))
            after_ports = set(_open_ports_tuple(after_entry))
            display = _display_name_for_entry(after_entry) or ip
            for port in sorted(after_ports - before_ports):
                ports_opened.append(
                    PortChange(
                        ip=ip,
                        display_name=display,
                        port=port,
                        service_label=service_label_for_port(port),
                        direction="opened",
                    )
                )
            for port in sorted(before_ports - after_ports):
                ports_closed.append(
                    PortChange(
                        ip=ip,
                        display_name=display,
                        port=port,
                        service_label=service_label_for_port(port),
                        direction="closed",
                    )
                )

    hosts_added.sort(key=lambda item: (item.display_name.lower(), item.ip))
    hosts_removed.sort(key=lambda item: (item.display_name.lower(), item.ip))
    ports_opened.sort(key=lambda item: (item.ip, item.port))
    ports_closed.sort(key=lambda item: (item.ip, item.port))

    is_empty = not (hosts_added or hosts_removed or ports_opened or ports_closed)
    return InventoryDiff(
        domain=domain,
        before_id=before_id,
        after_id=after_id,
        before_at=before_at,
        after_at=after_at,
        hosts_added=tuple(hosts_added),
        hosts_removed=tuple(hosts_removed),
        ports_opened=tuple(ports_opened),
        ports_closed=tuple(ports_closed),
        caveats=tuple(caveats),
        is_empty=is_empty,
    )


# ---------------------------------------------------------------------------
# High-level helpers
# ---------------------------------------------------------------------------


def _last_seen_snapshot_id(shell: Any, *, domain: str) -> str | None:
    domains_data = getattr(shell, "domains_data", {})
    if not isinstance(domains_data, dict):
        return None
    domain_state = domains_data.get(domain) or {}
    if not isinstance(domain_state, dict):
        return None
    value = str(domain_state.get("inventory_last_seen_snapshot_id") or "").strip()
    return value or None


def diff_against_last_seen(shell: Any, *, domain: str) -> InventoryDiff | None:
    """Return the diff between the latest snapshot and the operator's last view.

    Returns ``None`` when no snapshots exist or the latest snapshot equals the
    persisted ``inventory_last_seen_snapshot_id`` for ``domain``. The caller
    decides when (if ever) to call :func:`mark_diff_seen`.
    """

    if not is_timeline_enabled(shell):
        return None
    entries = _read_index(shell, domain=domain)
    if not entries:
        return None
    latest = entries[-1]
    last_seen_id = _last_seen_snapshot_id(shell, domain=domain)
    if last_seen_id == latest.id:
        return None

    after_payload = load_snapshot_payload(shell, domain=domain, snapshot_id=latest.id)
    if not isinstance(after_payload, dict):
        return None

    before_entry: InventorySnapshotIndexEntry | None = None
    if last_seen_id:
        before_entry = next((item for item in entries if item.id == last_seen_id), None)
    if before_entry is None and len(entries) >= 2:
        before_entry = entries[-2]

    before_payload: dict[str, Any] | None = None
    if before_entry is not None:
        before_payload = load_snapshot_payload(
            shell, domain=domain, snapshot_id=before_entry.id
        )

    return compute_inventory_diff(
        domain=domain,
        before_payload=before_payload,
        before_id=before_entry.id if before_entry else None,
        before_at=before_entry.at if before_entry else None,
        after_payload=after_payload,
        after_id=latest.id,
        after_at=latest.at,
    )


def mark_diff_seen(shell: Any, *, domain: str, snapshot_id: str) -> None:
    """Persist ``snapshot_id`` as the operator's last viewed snapshot."""

    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return
    domain_state = domains_data.setdefault(domain, {})
    if not isinstance(domain_state, dict):
        return
    domain_state["inventory_last_seen_snapshot_id"] = snapshot_id
    saver = getattr(shell, "save_workspace_data", None)
    if callable(saver):
        try:
            saver()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_info_debug(
                "[inventory-timeline] failed to persist last-seen snapshot for "
                f"{mark_sensitive(domain, 'domain')}: {exc}"
            )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _format_age(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    total = int(max(seconds, 0.0))
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def _age_for_iso(value: str | None) -> float | None:
    parsed = _parse_iso_timestamp(value or "")
    if parsed is None:
        return None
    return max((_now_utc() - parsed).total_seconds(), 0.0)


def _border_style_for_diff(diff: InventoryDiff) -> str:
    if diff.hosts_removed:
        return "red"
    has_positive = bool(diff.hosts_added or diff.ports_opened)
    has_negative = bool(diff.ports_closed)
    if has_positive and not has_negative and not diff.caveats:
        return "cyan"
    if has_negative and not has_positive:
        return "dim"
    if diff.caveats and (has_positive or has_negative):
        return "yellow"
    if has_positive and has_negative:
        return "yellow"
    return "cyan"


def _maybe_truncate_table(
    table: Table, rows: list[tuple[str, ...]], *, max_rows: int, section_name: str
) -> None:
    visible = rows[:max_rows]
    for row in visible:
        table.add_row(*row)
    if len(rows) > max_rows:
        remaining = len(rows) - max_rows
        filler = ["" for _ in range(max(len(table.columns) - 1, 0))]
        table.add_row(
            f"[italic dim]… and {remaining} more {section_name}[/italic dim]",
            *filler,
        )


def render_inventory_diff(
    shell: Any,
    *,
    diff: InventoryDiff,
    title: str,
    context_lines: list[str] | None = None,
    max_rows_per_section: int = 12,
) -> None:
    """Render a Rich panel + tables for the structured inventory diff."""

    if not is_timeline_enabled(shell):
        return
    if diff.is_empty and not diff.caveats:
        print_info(
            f"No inventory changes in {mark_sensitive(diff.domain, 'domain')} since the last snapshot."
        )
        return

    border_style = _border_style_for_diff(diff)
    header_lines: list[str] = []
    if context_lines:
        header_lines.extend(context_lines)
        header_lines.append("")

    summary_parts: list[str] = []
    if diff.hosts_added:
        summary_parts.append(f"[green]+{len(diff.hosts_added)} hosts[/green]")
    if diff.hosts_removed:
        summary_parts.append(f"[red]-{len(diff.hosts_removed)} hosts[/red]")
    if diff.ports_opened:
        summary_parts.append(f"[cyan]+{len(diff.ports_opened)} ports[/cyan]")
    if diff.ports_closed:
        summary_parts.append(f"[dim]-{len(diff.ports_closed)} ports[/dim]")
    if not summary_parts:
        summary_parts.append("[dim]no host- or port-level changes[/dim]")

    header_lines.append("Changes: " + "  ".join(summary_parts))
    if diff.before_at and diff.after_at:
        header_lines.append(
            f"Window: [dim]{mark_sensitive(diff.before_at, 'detail')}[/dim] → "
            f"[dim]{mark_sensitive(diff.after_at, 'detail')}[/dim]"
        )
    elif diff.after_at:
        header_lines.append(
            f"Latest snapshot at [dim]{mark_sensitive(diff.after_at, 'detail')}[/dim] "
            "(no prior baseline)"
        )

    print_panel(
        "\n".join(header_lines),
        title=title,
        border_style=border_style,
        expand=False,
    )

    console = getattr(shell, "console", None)

    def _render_table(table: Table) -> None:
        if console is not None:
            console.print(table)
        else:
            print_info(str(table))

    if diff.hosts_added:
        table = Table(
            title="[green]Hosts added[/green]",
            box=None,
            show_header=True,
            header_style="bold",
            pad_edge=False,
        )
        table.add_column("Indicator")
        table.add_column("Host")
        table.add_column("IP")
        table.add_column("Open ports")
        table.add_column("Status")
        rows: list[tuple[str, ...]] = []
        for host in diff.hosts_added:
            rows.append(
                (
                    "[green]+ added[/green]",
                    mark_sensitive(host.display_name, "hostname"),
                    mark_sensitive(host.ip, "ip"),
                    ", ".join(str(port) for port in host.open_ports) or "-",
                    mark_sensitive(host.current_status or "-", "text"),
                )
            )
        _maybe_truncate_table(
            table, rows, max_rows=max_rows_per_section, section_name="hosts"
        )
        _render_table(table)

    if diff.hosts_removed:
        table = Table(
            title="[red]Hosts removed[/red]",
            box=None,
            show_header=True,
            header_style="bold",
            pad_edge=False,
        )
        table.add_column("Indicator")
        table.add_column("Host")
        table.add_column("IP")
        table.add_column("Last seen")
        table.add_column("Previous status")
        rows = []
        for host in diff.hosts_removed:
            rows.append(
                (
                    "[red]− removed[/red]",
                    mark_sensitive(host.display_name, "hostname"),
                    mark_sensitive(host.ip, "ip"),
                    mark_sensitive(diff.before_at or "-", "detail"),
                    mark_sensitive(host.previous_status or "-", "text"),
                )
            )
        _maybe_truncate_table(
            table, rows, max_rows=max_rows_per_section, section_name="hosts"
        )
        _render_table(table)

    if diff.ports_opened:
        table = Table(
            title="[cyan]Ports opened[/cyan]",
            box=None,
            show_header=True,
            header_style="bold",
            pad_edge=False,
        )
        table.add_column("Indicator")
        table.add_column("Host")
        table.add_column("IP")
        table.add_column("Service")
        table.add_column("Port")
        rows = []
        for change in diff.ports_opened:
            rows.append(
                (
                    "[cyan]▲ opened[/cyan]",
                    mark_sensitive(change.display_name, "hostname"),
                    mark_sensitive(change.ip, "ip"),
                    mark_sensitive(change.service_label, "text"),
                    str(change.port),
                )
            )
        _maybe_truncate_table(
            table, rows, max_rows=max_rows_per_section, section_name="ports"
        )
        _render_table(table)

    if diff.ports_closed:
        table = Table(
            title="[dim]Ports closed[/dim]",
            box=None,
            show_header=True,
            header_style="bold",
            pad_edge=False,
        )
        table.add_column("Indicator")
        table.add_column("Host")
        table.add_column("IP")
        table.add_column("Service")
        table.add_column("Port")
        rows = []
        for change in diff.ports_closed:
            rows.append(
                (
                    "[dim]▼ closed[/dim]",
                    mark_sensitive(change.display_name, "hostname"),
                    mark_sensitive(change.ip, "ip"),
                    mark_sensitive(change.service_label, "text"),
                    str(change.port),
                )
            )
        _maybe_truncate_table(
            table, rows, max_rows=max_rows_per_section, section_name="ports"
        )
        _render_table(table)

    if diff.caveats:
        for caveat in diff.caveats:
            print_info_debug(f"[inventory-timeline] caveat: {caveat}")
        print_warning(
            "Some sections were skipped due to baseline limitations; see details above."
        )


def render_inventory_status_banner(
    shell: Any,
    *,
    statuses: list[Any],
    pending_diffs: dict[str, InventoryDiff],
) -> None:
    """Render a compact one-panel status banner across all known domains."""

    if not statuses:
        return

    aggregate_border = "default"
    has_removed = any(diff.hosts_removed for diff in pending_diffs.values())
    has_positive_only = not has_removed and any(
        diff.hosts_added or diff.ports_opened or diff.ports_closed
        for diff in pending_diffs.values()
    )
    if has_removed:
        aggregate_border = "red"
    elif has_positive_only:
        aggregate_border = "cyan"
    else:
        aggregate_border = "yellow"

    lines: list[str] = []
    for status in statuses:
        domain = getattr(status, "domain", "")
        report_exists = bool(getattr(status, "report_exists", False))
        age_seconds = getattr(status, "age_seconds", None)
        reachable = getattr(status, "reachable_ip_count", None)

        if not report_exists:
            refresh_phrase = "no report yet"
        else:
            refresh_phrase = f"last refresh {_format_age(age_seconds)} ago"

        diff = pending_diffs.get(domain)
        if diff is None:
            hint = "[dim]no changes since last view[/dim]"
        elif diff.before_id is None:
            hint = "[dim]first observation[/dim]"
        elif diff.is_empty:
            hint = "[dim]no changes since last view[/dim]"
        else:
            hint_parts: list[str] = []
            if diff.hosts_added:
                hint_parts.append(f"[green]▲ +{len(diff.hosts_added)}[/green]")
            if diff.hosts_removed:
                hint_parts.append(f"[red]▼ -{len(diff.hosts_removed)}[/red]")
            if diff.ports_opened or diff.ports_closed:
                opened = len(diff.ports_opened)
                closed = len(diff.ports_closed)
                hint_parts.append(f"[cyan]⚡ +{opened}[/cyan]/[dim]-{closed}[/dim]")
            hint = (
                "  ".join(hint_parts)
                if hint_parts
                else "[dim]no changes since last view[/dim]"
            )

        reachable_phrase = (
            f"reachable={mark_sensitive(str(reachable), 'detail')}"
            if isinstance(reachable, int)
            else "reachable=[dim]unknown[/dim]"
        )
        lines.append(
            f"{mark_sensitive(domain, 'domain')} | {refresh_phrase} | {reachable_phrase} | {hint}"
        )

    body = "\n".join(
        [
            "Current-vantage inventory status:",
            "",
            *lines,
            "",
            "Refresh now: refresh_inventory <domain> | refresh_inventory all",
            "View detailed diff: inventory_diff <domain> [--since 1d|2h|<ISO>]",
        ]
    )
    print_panel(
        body,
        title="Current-Vantage Inventory Status",
        border_style=aggregate_border,
        expand=False,
    )


# ---------------------------------------------------------------------------
# Helper for HH:MM parsing (kept module-level to support testing)
# ---------------------------------------------------------------------------


def _today_at_local(hour: int, minute: int) -> datetime:
    today = datetime.now().astimezone()
    target = today.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return target.astimezone(timezone.utc)


__all__ = [
    "INVENTORY_TIMELINE_DIRNAME",
    "INVENTORY_TIMELINE_INDEX_FILENAME",
    "INVENTORY_TIMELINE_SCHEMA_VERSION",
    "MAX_SNAPSHOTS_PER_DOMAIN",
    "TRIGGER_PHASE1_INITIAL",
    "TRIGGER_WORKSPACE_LOAD_REFRESH",
    "TRIGGER_MANUAL_REFRESH_INVENTORY",
    "TRIGGER_POST_PIVOT",
    "InventorySnapshotIndexEntry",
    "HostChange",
    "PortChange",
    "InventoryDiff",
    "is_timeline_enabled",
    "service_label_for_port",
    "record_inventory_snapshot",
    "list_snapshots",
    "load_snapshot_payload",
    "find_snapshot_at_or_before",
    "parse_since_expression",
    "compute_inventory_diff",
    "diff_against_last_seen",
    "mark_diff_seen",
    "render_inventory_diff",
    "render_inventory_status_banner",
]
