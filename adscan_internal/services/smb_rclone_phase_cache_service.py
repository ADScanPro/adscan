"""Cache helpers for SMB rclone deterministic phase reuse.

This service supports premium reuse in audit workflows where the same
principal scans the same SMB share content repeatedly. It deliberately keeps
the cache logic deterministic and separate from any AI enrichment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
import json
import os

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.smb_exclusion_policy import (
    is_globally_excluded_smb_relative_path,
)
from adscan_internal.services.smb_sensitive_file_policy import (
    resolve_effective_sensitive_extension,
)
from adscan_internal.workspaces import read_json_file, write_json_file


def _now_utc_iso() -> str:
    """Return one ISO-8601 UTC timestamp with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_size_to_bytes(size_text: str) -> int:
    """Parse one human-readable size field into bytes when possible."""
    text = str(size_text or "").strip()
    if not text:
        return 0
    parts = text.split()
    if not parts:
        return 0
    try:
        value = float(parts[0])
    except ValueError:
        return 0
    unit = parts[1].upper() if len(parts) > 1 else "B"
    factors = {
        "B": 1,
        "KB": 1024,
        "MB": 1024 * 1024,
        "GB": 1024 * 1024 * 1024,
        "TB": 1024 * 1024 * 1024 * 1024,
    }
    factor = factors.get(unit)
    if factor is None:
        return 0
    return int(value * factor)


@dataclass(frozen=True)
class SMBRclonePhaseCacheEntry:
    """One deterministic remote file candidate eligible for rclone phase reuse."""

    host: str
    share: str
    remote_path: str
    size: str
    mtime_epoch: str
    local_relative_path: str


class SMBRclonePhaseCacheService(BaseService):
    """Resolve and persist deterministic SMB rclone phase cache state."""

    SCHEMA_VERSION = 1

    def resolve_candidate_entries_from_aggregate(
        self,
        *,
        aggregate_map_path: str,
        hosts: list[str],
        shares: list[str],
        extensions: tuple[str, ...],
        max_file_size_bytes: int | None = None,
    ) -> list[SMBRclonePhaseCacheEntry]:
        """Resolve remote candidate entries with stable metadata from one aggregate map."""
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

        resolved: list[SMBRclonePhaseCacheEntry] = []
        seen: set[tuple[str, str, str]] = set()
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
                for remote_path, metadata in files_bucket.items():
                    if not isinstance(remote_path, str):
                        continue
                    normalized_path = remote_path.strip().replace("\\", "/")
                    if not normalized_path:
                        continue
                    if is_globally_excluded_smb_relative_path(normalized_path):
                        continue
                    if resolve_effective_sensitive_extension(
                        normalized_path,
                        allowed_extensions=tuple(normalized_extensions),
                    ) not in normalized_extensions:
                        continue
                    metadata_dict = metadata if isinstance(metadata, dict) else {}
                    size_text = str(metadata_dict.get("size", "") or "").strip()
                    if (
                        isinstance(max_file_size_bytes, int)
                        and max_file_size_bytes > 0
                        and _parse_size_to_bytes(size_text) > max_file_size_bytes
                    ):
                        continue
                    dedup_key = (
                        host_name.casefold(),
                        share_name.casefold(),
                        normalized_path.casefold(),
                    )
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    resolved.append(
                        SMBRclonePhaseCacheEntry(
                            host=host_name,
                            share=share_name,
                            remote_path=normalized_path,
                            size=size_text,
                            mtime_epoch=str(metadata_dict.get("mtime_epoch", "") or "").strip(),
                            local_relative_path=f"{host_name}/{share_name}/{normalized_path}".replace(
                                "\\",
                                "/",
                            ),
                        )
                    )
        return sorted(
            resolved,
            key=lambda item: (
                item.host.casefold(),
                item.share.casefold(),
                item.remote_path.casefold(),
            ),
        )

    def build_phase_signature(
        self,
        *,
        phase: str,
        entries: list[SMBRclonePhaseCacheEntry],
        max_file_size_bytes: int | None = None,
    ) -> str:
        """Build one stable signature for a deterministic phase candidate set."""
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "phase": str(phase or "").strip(),
            "max_file_size_bytes": int(max_file_size_bytes or 0),
            "entries": [
                {
                    "host": item.host,
                    "share": item.share,
                    "remote_path": item.remote_path,
                    "size": item.size,
                    "mtime_epoch": item.mtime_epoch,
                }
                for item in entries
            ],
        }
        digest = sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        )
        return digest.hexdigest()

    def load_cache_manifest(self, *, manifest_path: str) -> dict[str, Any] | None:
        """Load one persisted cache manifest when it exists and is valid."""
        if not manifest_path or not os.path.exists(manifest_path):
            return None
        payload = read_json_file(manifest_path)
        if not isinstance(payload, dict):
            return None
        if int(payload.get("schema_version") or 0) != self.SCHEMA_VERSION:
            return None
        return payload

    def write_cache_manifest(
        self,
        *,
        manifest_path: str,
        phase: str,
        signature: str,
        candidate_files: int,
        generated_at: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        """Persist one deterministic phase cache manifest."""
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "phase": str(phase or "").strip(),
            "signature": str(signature or "").strip(),
            "candidate_files": int(candidate_files or 0),
            "generated_at": str(generated_at or _now_utc_iso()).strip(),
        }
        if isinstance(extra, dict):
            payload.update(extra)
        os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
        write_json_file(manifest_path, payload)
        return manifest_path

    def cache_payload_is_reusable(
        self,
        *,
        manifest_payload: dict[str, Any] | None,
        expected_signature: str,
        required_paths: list[str],
    ) -> tuple[bool, str]:
        """Validate whether one persisted phase cache can be reused safely."""
        if not isinstance(manifest_payload, dict):
            return False, "cache manifest missing"
        if str(manifest_payload.get("signature") or "").strip() != str(expected_signature or "").strip():
            return False, "candidate signature mismatch"
        for required_path in required_paths:
            path = str(required_path or "").strip()
            if path and not os.path.exists(path):
                return False, f"required cache artifact missing: {path}"
        return True, "compatible"

    @staticmethod
    def serialize_grouped_findings(
        findings: dict[str, list[tuple[str, float | None, str, int, str]]],
    ) -> dict[str, list[list[object]]]:
        """Convert grouped finding tuples into JSON-safe lists."""
        serialized: dict[str, list[list[object]]] = {}
        for key, entries in findings.items():
            if not isinstance(entries, list):
                continue
            serialized[str(key)] = [
                [
                    entry[0] if len(entry) > 0 else "",
                    entry[1] if len(entry) > 1 else None,
                    entry[2] if len(entry) > 2 else "",
                    entry[3] if len(entry) > 3 else 0,
                    entry[4] if len(entry) > 4 else "",
                ]
                for entry in entries
                if isinstance(entry, tuple)
            ]
        return serialized

    @staticmethod
    def deserialize_grouped_findings(
        payload: dict[str, Any] | None,
    ) -> dict[str, list[tuple[str, float | None, str, int, str]]]:
        """Convert JSON-safe grouped findings back into tuple form."""
        restored: dict[str, list[tuple[str, float | None, str, int, str]]] = {}
        for key, entries in dict(payload or {}).items():
            if not isinstance(entries, list):
                continue
            restored_entries: list[tuple[str, float | None, str, int, str]] = []
            for entry in entries:
                if not isinstance(entry, list) or len(entry) < 5:
                    continue
                score = entry[1]
                if score is not None:
                    try:
                        score = float(score)
                    except (TypeError, ValueError):
                        score = None
                try:
                    line_no = int(entry[3])
                except (TypeError, ValueError):
                    line_no = 0
                restored_entries.append(
                    (
                        str(entry[0] or "").strip(),
                        score,
                        str(entry[2] or "").strip(),
                        line_no,
                        str(entry[4] or "").strip(),
                    )
                )
            restored[str(key)] = restored_entries
        return restored

    @staticmethod
    def serialize_artifact_records(records: list[Any]) -> list[dict[str, Any]]:
        """Convert artifact processing records into JSON-safe dictionaries."""
        serialized: list[dict[str, Any]] = []
        for record in records:
            if record is None:
                continue
            serialized.append(
                {
                    "path": str(getattr(record, "path", "") or "").strip(),
                    "filename": str(getattr(record, "filename", "") or "").strip(),
                    "artifact_type": str(getattr(record, "artifact_type", "") or "").strip(),
                    "status": str(getattr(record, "status", "") or "").strip(),
                    "note": str(getattr(record, "note", "") or "").strip(),
                    "manual_review": bool(getattr(record, "manual_review", False)),
                    "details": dict(getattr(record, "details", {}) or {}),
                }
            )
        return serialized


__all__ = [
    "SMBRclonePhaseCacheEntry",
    "SMBRclonePhaseCacheService",
]
