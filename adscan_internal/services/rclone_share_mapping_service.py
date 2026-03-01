"""Rclone-backed SMB share mapping helpers.

This service builds per-host share metadata JSON files by invoking ``rclone``
against SMB shares and transforming the output into the same shape expected by
``ShareMappingService.merge_spider_plus_run``.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Callable
import json
import shlex

from adscan_internal.services.base_service import BaseService
from adscan_internal.workspaces import write_json_file


class RcloneShareMappingService(BaseService):
    """Generate spider_plus-compatible host JSON metadata using rclone."""

    def generate_host_metadata_json(
        self,
        *,
        run_output_dir: str,
        host_share_targets: list[tuple[str, str]],
        username: str,
        password: str,
        domain: str,
        command_executor: Callable[..., Any],
        rclone_path: str = "rclone",
        timeout_seconds: int = 1200,
    ) -> dict[str, Any]:
        """Generate host JSON metadata files using ``rclone lsjson``.

        Args:
            run_output_dir: Directory where per-host JSON files will be written.
            host_share_targets: List of (host, share) tuples to enumerate.
            username: SMB username.
            password: SMB password.
            domain: SMB domain/workgroup.
            command_executor: Callable used to run shell commands.
            rclone_path: Path to ``rclone`` executable.
            timeout_seconds: Per-target listing timeout.

        Returns:
            Mapping summary with counters and failed targets.
        """
        run_output_path = Path(run_output_dir).expanduser().resolve(strict=False)
        run_output_path.mkdir(parents=True, exist_ok=True)
        normalized_targets = self._unique_targets(host_share_targets)
        obscured_password = self._obscure_password(
            command_executor=command_executor,
            rclone_path=rclone_path,
            password=password,
        )
        if not obscured_password:
            return {
                "run_output_dir": str(run_output_path),
                "host_json_files": 0,
                "mapped_shares": 0,
                "mapped_file_entries": 0,
                "partial_targets": 0,
                "failed_targets": len(normalized_targets),
            }

        host_payloads: dict[str, dict[str, dict[str, dict[str, str]]]] = {}
        failed_targets = 0
        partial_targets = 0
        mapped_shares = 0
        mapped_file_entries = 0

        for host, share in normalized_targets:
            command = self._build_lsjson_command(
                rclone_path=rclone_path,
                host=host,
                share=share,
                username=username,
                obscured_password=obscured_password,
                domain=domain,
            )
            result = command_executor(
                command,
                timeout=timeout_seconds,
                ignore_errors=True,
            )
            if result is None:
                failed_targets += 1
                continue

            return_code = int(getattr(result, "returncode", 1))
            stdout_text = str(getattr(result, "stdout", "") or "").strip()
            stderr_text = str(getattr(result, "stderr", "") or "").strip()
            if not stdout_text and return_code != 0:
                failed_targets += 1
                continue

            files_map = self._parse_lsjson_output(stdout_text)
            if return_code != 0 and files_map:
                partial_targets += 1
                self.logger.warning(
                    "rclone lsjson returned non-zero but produced partial JSON; "
                    "accepting partial metadata for host=%s share=%s rc=%s stderr=%s",
                    host,
                    share,
                    return_code,
                    stderr_text,
                )
            elif return_code != 0 and not files_map:
                failed_targets += 1
                continue
            if not files_map:
                continue

            host_bucket = host_payloads.setdefault(host, {})
            host_bucket[share] = files_map
            mapped_shares += 1
            mapped_file_entries += len(files_map)

        host_json_files = 0
        for host, payload in host_payloads.items():
            if not payload:
                continue
            output_path = run_output_path / f"{host}.json"
            write_json_file(str(output_path), payload)
            host_json_files += 1

        return {
            "run_output_dir": str(run_output_path),
            "host_json_files": host_json_files,
            "mapped_shares": mapped_shares,
            "mapped_file_entries": mapped_file_entries,
            "partial_targets": partial_targets,
            "failed_targets": failed_targets,
        }

    @staticmethod
    def _unique_targets(
        targets: list[tuple[str, str]],
    ) -> list[tuple[str, str]]:
        """Return stable unique non-empty host/share targets."""
        unique: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for host, share in targets:
            host_name = str(host or "").strip()
            share_name = str(share or "").strip()
            if not host_name or not share_name:
                continue
            key = (host_name.lower(), share_name.lower())
            if key in seen:
                continue
            seen.add(key)
            unique.append((host_name, share_name))
        return unique

    def _obscure_password(
        self,
        *,
        command_executor: Callable[..., Any],
        rclone_path: str,
        password: str,
    ) -> str:
        """Obscure SMB password via ``rclone obscure`` for backend inline config."""
        command = f"{shlex.quote(rclone_path)} obscure {shlex.quote(password)}"
        result = command_executor(command, timeout=30, ignore_errors=True)
        if result is None or int(getattr(result, "returncode", 1)) != 0:
            return ""
        return str(getattr(result, "stdout", "") or "").strip()

    @staticmethod
    def _build_lsjson_command(
        *,
        rclone_path: str,
        host: str,
        share: str,
        username: str,
        obscured_password: str,
        domain: str,
    ) -> str:
        """Build one ``rclone lsjson`` command for one SMB host/share target."""
        remote = (
            f":smb,host={host},user={username},pass={obscured_password},"
            f"domain={domain}:{share}"
        )
        return (
            f"{shlex.quote(rclone_path)} lsjson {shlex.quote(remote)} "
            "--recursive --files-only --no-mimetype"
        )

    def _parse_lsjson_output(self, raw_json: str) -> dict[str, dict[str, str]]:
        """Parse rclone lsjson output into spider_plus-compatible file metadata."""
        try:
            payload = json.loads(raw_json)
        except Exception:
            payload = self._parse_partial_lsjson_entries(raw_json)
            if payload:
                self.logger.warning(
                    "rclone lsjson output was not valid JSON array; "
                    "recovered %s entries via line-by-line parser",
                    len(payload),
                )
            else:
                return {}
        if not isinstance(payload, list):
            return {}

        files_map: dict[str, dict[str, str]] = {}
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            if bool(entry.get("IsDir", False)):
                continue
            path = str(entry.get("Path") or entry.get("Name") or "").strip()
            if not path:
                continue
            size_bytes = self._parse_size(entry.get("Size"))
            modtime_epoch = self._parse_modtime_epoch(entry.get("ModTime"))
            files_map[path] = {
                "size": self._format_size_human(size_bytes),
                "ctime_epoch": "",
                "mtime_epoch": modtime_epoch,
                "atime_epoch": "",
            }
        return files_map

    @staticmethod
    def _parse_partial_lsjson_entries(raw_json: str) -> list[dict[str, Any]]:
        """Best-effort parse for lsjson partial output when full JSON is malformed."""
        entries: list[dict[str, Any]] = []
        for line in str(raw_json or "").splitlines():
            candidate = line.strip()
            if not candidate or candidate in {"[", "]"}:
                continue
            if candidate.endswith(","):
                candidate = candidate[:-1].rstrip()
            if not candidate.startswith("{"):
                continue
            try:
                parsed = json.loads(candidate)
            except Exception:
                continue
            if isinstance(parsed, dict):
                entries.append(parsed)
        return entries

    @staticmethod
    def _parse_size(value: Any) -> int:
        """Parse size to non-negative integer bytes."""
        try:
            parsed = int(value)
        except Exception:
            return 0
        return max(0, parsed)

    @staticmethod
    def _parse_modtime_epoch(value: Any) -> str:
        """Parse RFC3339 timestamp into epoch seconds as string."""
        text = str(value or "").strip()
        if not text:
            return ""
        normalized = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except Exception:
            return ""
        return str(int(parsed.timestamp()))

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
