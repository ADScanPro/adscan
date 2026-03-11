"""CIFS-backed SMB share mapping helpers.

This service builds per-host share metadata JSON files from an existing CIFS
mount tree so downstream pipelines can reuse the same consolidated mapping
format produced by ``spider_plus``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import os

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.smb_exclusion_policy import (
    is_globally_excluded_smb_relative_path,
    prune_excluded_walk_dirs,
)
from adscan_internal.workspaces import read_json_file, write_json_file


class CIFSShareMappingService(BaseService):
    """Generate spider_plus-compatible host JSON metadata from CIFS mounts."""

    def generate_host_metadata_json(
        self,
        *,
        mount_root: str,
        run_output_dir: str,
        hosts: list[str],
        shares: list[str],
    ) -> dict[str, Any]:
        """Generate host JSON metadata files from CIFS mount paths.

        Args:
            mount_root: Root directory containing CIFS-mounted content.
            run_output_dir: Output directory where host JSON files are written.
            hosts: Hostnames/IPs to include in the mapping run.
            shares: Share names to enumerate for each host.

        Returns:
            Summary with host/share/file counters.
        """
        mount_root_path = Path(mount_root).expanduser().resolve(strict=False)
        run_output_path = Path(run_output_dir).expanduser().resolve(strict=False)
        run_output_path.mkdir(parents=True, exist_ok=True)

        unique_hosts = self._unique_non_empty(hosts)
        unique_shares = self._unique_non_empty(shares)
        allow_share_fallback = len(unique_hosts) <= 1

        host_json_files = 0
        mapped_shares = 0
        mapped_files = 0

        for host in unique_hosts:
            host_payload: dict[str, dict[str, dict[str, str]]] = {}
            for share in unique_shares:
                share_root = self.resolve_share_mount_path(
                    mount_root=mount_root_path,
                    host=host,
                    share=share,
                    allow_share_root_fallback=allow_share_fallback,
                )
                if share_root is None:
                    continue
                files_map = self._collect_share_files(share_root=share_root)
                if not files_map:
                    continue
                host_payload[share] = files_map
                mapped_shares += 1
                mapped_files += len(files_map)

            if not host_payload:
                continue

            output_path = run_output_path / f"{host}.json"
            write_json_file(str(output_path), host_payload)
            host_json_files += 1

        return {
            "mount_root": str(mount_root_path),
            "run_output_dir": str(run_output_path),
            "host_json_files": host_json_files,
            "mapped_shares": mapped_shares,
            "mapped_file_entries": mapped_files,
        }

    def resolve_candidate_local_path(
        self,
        *,
        mount_root: str,
        host: str,
        share: str,
        remote_path: str,
        allow_share_root_fallback: bool = True,
    ) -> str | None:
        """Resolve a local CIFS-backed file path for one host/share remote path."""
        mount_root_path = Path(mount_root).expanduser().resolve(strict=False)
        share_root = self.resolve_share_mount_path(
            mount_root=mount_root_path,
            host=host,
            share=share,
            allow_share_root_fallback=allow_share_root_fallback,
        )
        if share_root is None:
            return None

        normalized_parts = self._normalize_remote_path_parts(remote_path)
        if not normalized_parts:
            return None

        direct_candidate = share_root.joinpath(*normalized_parts)
        if direct_candidate.is_file():
            return str(direct_candidate)

        resolved_case_path = self._resolve_case_insensitive_path(
            root=share_root,
            parts=normalized_parts,
        )
        if resolved_case_path is None or not resolved_case_path.is_file():
            return None
        return str(resolved_case_path)

    def resolve_share_mount_path(
        self,
        *,
        mount_root: Path,
        host: str,
        share: str,
        allow_share_root_fallback: bool = True,
    ) -> Path | None:
        """Resolve mount path for one host/share pair with case-insensitive fallback."""
        host_name = str(host or "").strip()
        share_name = str(share or "").strip()
        if not host_name or not share_name or not mount_root.is_dir():
            return None

        direct_host_share = mount_root / host_name / share_name
        if direct_host_share.is_dir():
            return direct_host_share

        host_dir = self._resolve_child_case_insensitive(mount_root, host_name)
        if host_dir is not None:
            host_share = self._resolve_child_case_insensitive(host_dir, share_name)
            if host_share is not None and host_share.is_dir():
                return host_share

        if allow_share_root_fallback:
            direct_share = mount_root / share_name
            if direct_share.is_dir():
                return direct_share
            root_share = self._resolve_child_case_insensitive(mount_root, share_name)
            if root_share is not None and root_share.is_dir():
                return root_share

        return None

    def resolve_candidate_local_paths_from_aggregate(
        self,
        *,
        aggregate_map_path: str,
        mount_root: str,
        hosts: list[str],
        shares: list[str],
        extensions: tuple[str, ...],
    ) -> list[str]:
        """Resolve local CIFS candidate paths from a consolidated mapping JSON."""
        if not aggregate_map_path or not os.path.exists(aggregate_map_path):
            return []
        aggregate = read_json_file(aggregate_map_path)
        if not isinstance(aggregate, dict):
            return []
        hosts_bucket = aggregate.get("hosts")
        if not isinstance(hosts_bucket, dict):
            return []

        requested_hosts = {
            str(host).strip().casefold() for host in hosts if str(host).strip()
        }
        requested_shares = {
            str(share).strip().casefold() for share in shares if str(share).strip()
        }
        normalized_extensions = {
            str(extension).strip().casefold()
            for extension in extensions
            if str(extension).strip()
        }
        if not normalized_extensions:
            return []

        resolved_paths: list[str] = []
        seen_paths: set[str] = set()
        allow_share_root_fallback = len(requested_hosts) <= 1
        for host_name, host_entry in hosts_bucket.items():
            if not isinstance(host_name, str) or not isinstance(host_entry, dict):
                continue
            if requested_hosts and host_name.casefold() not in requested_hosts:
                continue
            shares_bucket = host_entry.get("shares")
            if not isinstance(shares_bucket, dict):
                continue
            for share_name, share_entry in shares_bucket.items():
                if not isinstance(share_name, str) or not isinstance(share_entry, dict):
                    continue
                if requested_shares and share_name.casefold() not in requested_shares:
                    continue
                files_bucket = share_entry.get("files")
                if not isinstance(files_bucket, dict):
                    continue
                for remote_path in files_bucket.keys():
                    if not isinstance(remote_path, str):
                        continue
                    if is_globally_excluded_smb_relative_path(remote_path):
                        continue
                    if Path(remote_path).suffix.casefold() not in normalized_extensions:
                        continue
                    local_path = self.resolve_candidate_local_path(
                        mount_root=mount_root,
                        host=host_name,
                        share=share_name,
                        remote_path=remote_path,
                        allow_share_root_fallback=allow_share_root_fallback,
                    )
                    if not local_path or local_path in seen_paths:
                        continue
                    seen_paths.add(local_path)
                    resolved_paths.append(local_path)
        return resolved_paths

    def _collect_share_files(
        self,
        *,
        share_root: Path,
    ) -> dict[str, dict[str, str]]:
        """Collect spider_plus-like file metadata for one mounted share path."""
        files_map: dict[str, dict[str, str]] = {}
        for dirpath, dirnames, filenames in os.walk(share_root):
            prune_excluded_walk_dirs(dirnames)
            base_dir = Path(dirpath)
            for filename in filenames:
                file_path = base_dir / filename
                try:
                    stat_result = file_path.stat()
                except OSError:
                    self.logger.exception(
                        "Failed stat() on CIFS file during mapping: %s",
                        file_path,
                    )
                    continue

                try:
                    relative_path = file_path.relative_to(share_root).as_posix()
                except ValueError:
                    continue
                if is_globally_excluded_smb_relative_path(relative_path):
                    continue

                files_map[relative_path] = {
                    "size": self._format_size_human(int(stat_result.st_size)),
                    "ctime_epoch": str(int(stat_result.st_ctime)),
                    "mtime_epoch": str(int(stat_result.st_mtime)),
                    "atime_epoch": str(int(stat_result.st_atime)),
                }
        return files_map

    @staticmethod
    def _unique_non_empty(values: list[str]) -> list[str]:
        """Return stable unique non-empty string values."""
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            text = str(value or "").strip()
            if not text or text.lower() in seen:
                continue
            seen.add(text.lower())
            ordered.append(text)
        return ordered

    @staticmethod
    def _resolve_child_case_insensitive(parent: Path, child_name: str) -> Path | None:
        """Resolve one directory child from parent with case-insensitive matching."""
        if not parent.is_dir():
            return None
        direct = parent / child_name
        if direct.exists():
            return direct
        target = child_name.casefold()
        try:
            for child in parent.iterdir():
                if child.name.casefold() == target:
                    return child
        except OSError:
            return None
        return None

    def _resolve_case_insensitive_path(
        self,
        *,
        root: Path,
        parts: list[str],
    ) -> Path | None:
        """Resolve nested path with case-insensitive matching per segment."""
        current = root
        for part in parts:
            candidate = self._resolve_child_case_insensitive(current, part)
            if candidate is None:
                return None
            current = candidate
        return current

    @staticmethod
    def _normalize_remote_path_parts(remote_path: str) -> list[str]:
        """Normalize remote SMB path into sanitized relative path parts."""
        normalized = str(remote_path or "").replace("\\", "/").strip().lstrip("/")
        if not normalized:
            return []
        raw_parts = [part for part in normalized.split("/") if part and part != "."]
        parts = [part for part in raw_parts if part != ".."]
        return parts

    @staticmethod
    def _format_size_human(num_bytes: int) -> str:
        """Format byte count into spider_plus-compatible human readable string."""
        value = float(max(0, num_bytes))
        units = ["B", "KB", "MB", "GB", "TB"]
        unit_idx = 0
        while value >= 1024 and unit_idx < len(units) - 1:
            value /= 1024
            unit_idx += 1
        if unit_idx == 0:
            return f"{int(value)} B"
        return f"{value:.2f} {units[unit_idx]}"
