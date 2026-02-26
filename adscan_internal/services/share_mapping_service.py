"""SMB share mapping service based on NetExec spider_plus metadata.

This service centralizes consolidation of per-host ``spider_plus`` JSON output
into one domain-scoped mapping file that can be reused across future scans.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import os

from adscan_internal.services.base_service import BaseService
from adscan_internal.workspaces import read_json_file, write_json_file


def _now_utc_iso() -> str:
    """Return an ISO-8601 UTC timestamp with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _unique_sorted(values: list[str]) -> list[str]:
    """Return sorted unique non-empty strings preserving deterministic output."""
    return sorted(
        {value for value in values if isinstance(value, str) and value.strip()}
    )


class ShareMappingService(BaseService):
    """Merge NetExec spider_plus metadata into a persistent domain map."""

    def merge_spider_plus_run(
        self,
        *,
        domain: str,
        principal: str,
        run_id: str,
        run_output_dir: str,
        aggregate_map_path: str,
        requested_hosts: list[str],
        requested_shares: list[str],
        host_share_permissions: dict[str, dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Merge one spider_plus run into a consolidated mapping JSON.

        Args:
            domain: Domain where the spidering run was executed.
            principal: Logical principal label used for the run (e.g. user).
            run_id: Unique run identifier.
            run_output_dir: Directory where spider_plus wrote host JSON files.
            aggregate_map_path: Destination JSON path for consolidated map.
            requested_hosts: Host targets requested for the run.
            requested_shares: Shares requested/known at run start.
            host_share_permissions: Optional host->share->permission map.

        Returns:
            Summary dictionary with counts and output paths.
        """
        observed_at = _now_utc_iso()
        host_json_files = sorted(Path(run_output_dir).glob("*.json"))
        aggregate = self._load_or_init_aggregate(
            domain=domain,
            aggregate_map_path=aggregate_map_path,
        )
        merged_file_entries = 0
        merged_hosts = 0
        merged_shares = 0

        for host_json in host_json_files:
            try:
                host_data = read_json_file(str(host_json))
            except Exception:
                # Malformed file should not stop a full run merge.
                self.logger.exception(
                    "Failed to parse spider_plus host metadata file: %s",
                    host_json,
                )
                continue

            if not isinstance(host_data, dict):
                continue

            host = host_json.stem
            host_bucket = aggregate["hosts"].setdefault(
                host,
                {
                    "first_seen": observed_at,
                    "last_seen": observed_at,
                    "shares": {},
                },
            )
            host_bucket["last_seen"] = observed_at
            merged_hosts += 1

            for share_name, files_map in host_data.items():
                if not isinstance(share_name, str) or not isinstance(files_map, dict):
                    continue

                share_bucket = host_bucket["shares"].setdefault(
                    share_name,
                    {
                        "first_seen": observed_at,
                        "last_seen": observed_at,
                        "files": {},
                        "file_count": 0,
                    },
                )
                share_bucket["last_seen"] = observed_at
                merged_shares += 1

                for remote_path, metadata in files_map.items():
                    if not isinstance(remote_path, str):
                        continue
                    file_metadata = metadata if isinstance(metadata, dict) else {}
                    existing = share_bucket["files"].get(remote_path, {})
                    share_bucket["files"][remote_path] = {
                        "size": str(
                            file_metadata.get("size", existing.get("size", ""))
                        ),
                        "ctime_epoch": str(
                            file_metadata.get(
                                "ctime_epoch", existing.get("ctime_epoch", "")
                            )
                        ),
                        "mtime_epoch": str(
                            file_metadata.get(
                                "mtime_epoch", existing.get("mtime_epoch", "")
                            )
                        ),
                        "atime_epoch": str(
                            file_metadata.get(
                                "atime_epoch", existing.get("atime_epoch", "")
                            )
                        ),
                        "last_seen": observed_at,
                    }
                    merged_file_entries += 1

                share_bucket["file_count"] = len(share_bucket["files"])

        principal_key = principal.strip() or "unknown"
        principal_bucket = aggregate["principals"].setdefault(
            principal_key,
            {
                "first_seen": observed_at,
                "last_seen": observed_at,
                "runs": [],
                "requested_hosts": [],
                "requested_shares": [],
                "host_share_permissions": {},
            },
        )
        principal_bucket["last_seen"] = observed_at
        principal_bucket["requested_hosts"] = _unique_sorted(
            list(principal_bucket["requested_hosts"]) + requested_hosts
        )
        principal_bucket["requested_shares"] = _unique_sorted(
            list(principal_bucket["requested_shares"]) + requested_shares
        )
        if run_id not in principal_bucket["runs"]:
            principal_bucket["runs"].append(run_id)

        if host_share_permissions:
            for host, share_perms in host_share_permissions.items():
                if not isinstance(host, str) or not isinstance(share_perms, dict):
                    continue
                host_perm_bucket = principal_bucket[
                    "host_share_permissions"
                ].setdefault(host, {})
                for share_name, perms in share_perms.items():
                    if isinstance(share_name, str) and isinstance(perms, str):
                        host_perm_bucket[share_name] = perms

        aggregate["runs"].append(
            {
                "run_id": run_id,
                "timestamp": observed_at,
                "principal": principal_key,
                "run_output_dir": run_output_dir,
                "host_json_files": len(host_json_files),
                "merged_hosts": merged_hosts,
                "merged_shares": merged_shares,
                "merged_file_entries": merged_file_entries,
                "requested_hosts": _unique_sorted(requested_hosts),
                "requested_shares": _unique_sorted(requested_shares),
            }
        )
        aggregate["runs"] = aggregate["runs"][-200:]
        aggregate["updated_at"] = observed_at
        os.makedirs(os.path.dirname(aggregate_map_path), exist_ok=True)
        write_json_file(aggregate_map_path, aggregate)

        return {
            "aggregate_map_path": aggregate_map_path,
            "run_output_dir": run_output_dir,
            "host_json_files": len(host_json_files),
            "merged_hosts": merged_hosts,
            "merged_shares": merged_shares,
            "merged_file_entries": merged_file_entries,
            "run_id": run_id,
        }

    def _load_or_init_aggregate(
        self,
        *,
        domain: str,
        aggregate_map_path: str,
    ) -> dict[str, Any]:
        """Load existing aggregate map or create a default structure."""
        if os.path.exists(aggregate_map_path):
            existing = read_json_file(aggregate_map_path)
            if isinstance(existing, dict) and existing.get("schema_version") == 1:
                existing.setdefault("hosts", {})
                existing.setdefault("principals", {})
                existing.setdefault("runs", [])
                return existing

        now = _now_utc_iso()
        return {
            "schema_version": 1,
            "domain": domain,
            "created_at": now,
            "updated_at": now,
            "hosts": {},
            "principals": {},
            "runs": [],
        }
