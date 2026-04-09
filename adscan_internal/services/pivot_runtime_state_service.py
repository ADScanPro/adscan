"""Reconcile persisted pivot-assisted reachability with live Ligolo runtime state.

This module prevents ADscan from trusting stale pivot-assisted inventories after
the operator exits the container/runtime and the Ligolo tunnel disappears. The
service snapshots the pre-pivot current-vantage artifacts and restores them when
the persisted pivot state is no longer backed by a live Ligolo tunnel.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
from typing import Any

from adscan_internal import print_info, print_info_debug, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.ligolo_service import LigoloProxyService
from adscan_internal.workspaces import domain_subpath

_PIVOT_RUNTIME_STATE_DIR = ".pivot_runtime_state"
_DIRECT_VANTAGE_SNAPSHOT_DIR = "direct_vantage_snapshot"
_SNAPSHOT_MANIFEST_FILE = "manifest.json"
_CURRENT_VANTAGE_ROOT_FILES = (
    "network_reachability_report.json",
    "enabled_computers_reachable_ips.txt",
    "enabled_computers_no_response_ips.txt",
)


@dataclass(frozen=True, slots=True)
class PivotRuntimeReconciliationResult:
    """Result for one domain-level pivot runtime reconciliation."""

    domain: str
    pivot_active: bool
    restored_direct_vantage: bool
    snapshot_available: bool


def _utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO format."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _domain_root(workspace_dir: str, domains_dir: str, domain: str) -> Path:
    """Return the canonical domain root path."""

    return Path(domain_subpath(workspace_dir, domains_dir, domain)).resolve()


def _snapshot_root(domain_root: Path) -> Path:
    """Return the snapshot directory for one domain."""

    return domain_root / _PIVOT_RUNTIME_STATE_DIR / _DIRECT_VANTAGE_SNAPSHOT_DIR


def _snapshot_manifest_path(domain_root: Path) -> Path:
    """Return the snapshot manifest path for one domain."""

    return _snapshot_root(domain_root) / _SNAPSHOT_MANIFEST_FILE


def _list_current_vantage_artifact_paths(domain_root: Path) -> list[Path]:
    """Return current-vantage artifacts that should be snapshot/restored."""

    artifacts: list[Path] = []
    for relative_name in _CURRENT_VANTAGE_ROOT_FILES:
        path = domain_root / relative_name
        if path.is_file():
            artifacts.append(path)

    for path in domain_root.rglob("ips.txt"):
        if path.is_file():
            artifacts.append(path)
    unique_paths = sorted({path.resolve() for path in artifacts})
    return unique_paths


def snapshot_direct_vantage_artifacts(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> dict[str, Any] | None:
    """Snapshot current-vantage artifacts before a pivot-assisted refresh.

    The snapshot is captured only once per domain so that multiple pivots can be
    restored back to the original direct/current-vantage baseline.
    """

    domain_root = _domain_root(workspace_dir, domains_dir, domain)
    snapshot_root = _snapshot_root(domain_root)
    manifest_path = _snapshot_manifest_path(domain_root)
    if manifest_path.is_file():
        try:
            with manifest_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            return payload if isinstance(payload, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    artifact_paths = _list_current_vantage_artifact_paths(domain_root)
    if not artifact_paths:
        return None

    snapshot_root.mkdir(parents=True, exist_ok=True)
    copied_files: list[str] = []
    for source_path in artifact_paths:
        relative_path = source_path.relative_to(domain_root)
        destination = snapshot_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)
        copied_files.append(str(relative_path))

    manifest = {
        "created_at": _utc_now_iso(),
        "domain": domain,
        "files": copied_files,
    }
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=False)
        handle.write("\n")
    return manifest


def restore_direct_vantage_artifacts(
    *,
    workspace_dir: str,
    domains_dir: str,
    domain: str,
) -> bool:
    """Restore the pre-pivot direct/current-vantage artifacts for one domain."""

    domain_root = _domain_root(workspace_dir, domains_dir, domain)
    snapshot_root = _snapshot_root(domain_root)
    manifest_path = _snapshot_manifest_path(domain_root)
    if not manifest_path.is_file():
        return False

    try:
        with manifest_path.open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return False
    files = manifest.get("files", []) if isinstance(manifest, dict) else []
    restored_any = False
    for relative_name in files:
        relative_path = Path(str(relative_name))
        source = snapshot_root / relative_path
        destination = domain_root / relative_path
        if not source.is_file():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        restored_any = True
    return restored_any


def has_active_ligolo_tunnel_for_domain(*, workspace_dir: str, domain: str) -> bool:
    """Return whether the workspace still has one active Ligolo tunnel for domain."""

    service = LigoloProxyService(workspace_dir=workspace_dir, current_domain=domain)
    for record in service.list_tunnel_records():
        if str(record.get("domain") or "").strip().lower() != domain.lower():
            continue
        if str(record.get("status") or "").strip().lower() not in {"running", "connected"}:
            continue
        if bool(record.get("alive")):
            return True
    return False


def reconcile_workspace_pivot_runtime_state(
    shell: Any,
    *,
    workspace_dir: str,
    domain_filter: str | None = None,
) -> list[PivotRuntimeReconciliationResult]:
    """Restore direct-vantage state when persisted pivot metadata is stale.

    This should run on workspace load so all later helpers consume a coherent
    "current vantage" view.
    """

    domains_dir = str(getattr(shell, "domains_dir", "domains"))
    domains_data = getattr(shell, "domains_data", {})
    if not isinstance(domains_data, dict):
        return []

    results: list[PivotRuntimeReconciliationResult] = []
    reconciled = False
    normalized_filter = str(domain_filter or "").strip().lower() or None
    for domain, domain_state in domains_data.items():
        if normalized_filter and str(domain).strip().lower() != normalized_filter:
            continue
        if not isinstance(domain_state, dict):
            continue
        network_vantage = domain_state.get("network_vantage")
        if not isinstance(network_vantage, dict):
            continue
        if str(network_vantage.get("mode") or "").strip().lower() != "pivot_assisted":
            continue

        snapshot_available = _snapshot_manifest_path(
            _domain_root(workspace_dir, domains_dir, domain)
        ).is_file()
        try:
            pivot_active = has_active_ligolo_tunnel_for_domain(
                workspace_dir=workspace_dir,
                domain=domain,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "[pivot-runtime] failed to inspect Ligolo state: "
                f"domain={mark_sensitive(domain, 'domain')} "
                f"error={mark_sensitive(str(exc), 'detail')}"
            )
            pivot_active = False

        restored = False
        if not pivot_active:
            restored = restore_direct_vantage_artifacts(
                workspace_dir=workspace_dir,
                domains_dir=domains_dir,
                domain=domain,
            )
            previous_vantage = dict(network_vantage)
            domain_state["network_vantage"] = {
                "mode": "direct",
                "restored_from_stale_pivot": restored,
                "stale_pivot_detected_at": _utc_now_iso(),
                "stale_reason": "ligolo_tunnel_not_active",
                "last_pivot": previous_vantage,
            }
            reconciled = True
            print_info(
                "Restored direct/current-vantage inventory because the persisted "
                f"Ligolo pivot for {mark_sensitive(domain, 'domain')} is no longer active."
            )
            print_info_debug(
                "[pivot-runtime] stale pivot reconciled: "
                f"domain={mark_sensitive(domain, 'domain')} "
                f"snapshot_available={snapshot_available!r} restored={restored!r}"
            )

        results.append(
            PivotRuntimeReconciliationResult(
                domain=domain,
                pivot_active=pivot_active,
                restored_direct_vantage=restored,
                snapshot_available=snapshot_available,
            )
        )

    if reconciled and callable(getattr(shell, "save_workspace_data", None)):
        try:
            shell.save_workspace_data()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "[pivot-runtime] failed to persist reconciled workspace state: "
                f"{mark_sensitive(str(exc), 'detail')}"
            )
    return results


def reconcile_domain_pivot_runtime_state(
    shell: Any,
    *,
    workspace_dir: str,
    domain: str,
) -> PivotRuntimeReconciliationResult | None:
    """Reconcile one domain and return its result if pivot metadata exists."""

    results = reconcile_workspace_pivot_runtime_state(
        shell,
        workspace_dir=workspace_dir,
        domain_filter=domain,
    )
    return results[0] if results else None


__all__ = [
    "PivotRuntimeReconciliationResult",
    "has_active_ligolo_tunnel_for_domain",
    "reconcile_domain_pivot_runtime_state",
    "reconcile_workspace_pivot_runtime_state",
    "restore_direct_vantage_artifacts",
    "snapshot_direct_vantage_artifacts",
]
