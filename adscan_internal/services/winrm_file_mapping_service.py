"""WinRM file mapping helpers built on top of PSRP."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Iterable

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.smb_sensitive_file_policy import (
    resolve_effective_sensitive_extension,
)
from adscan_internal.services.winrm_exclusion_policy import (
    get_winrm_excluded_directory_names,
    get_winrm_excluded_path_prefixes,
)
from adscan_internal.services.winrm_psrp_service import (
    WinRMPSRPError,
    WinRMPSRPService,
)


@dataclass(slots=True, frozen=True)
class WinRMFileMapEntry:
    """One remotely discovered file entry on a WinRM target."""

    full_name: str
    extension: str
    length: int
    directory: str
    last_write_time_utc: str


class WinRMFileMappingService(BaseService):
    """Generate and query WinRM file manifests over PSRP."""

    SCHEMA_VERSION = 1

    @staticmethod
    def _normalize_entry_identity(full_name: str) -> str:
        """Build a stable deduplication identity for one WinRM file path."""
        return str(full_name or "").strip().replace("/", "\\").lower()

    @classmethod
    def _deduplicate_entries(
        cls,
        entries: Iterable[WinRMFileMapEntry],
    ) -> list[WinRMFileMapEntry]:
        """Deduplicate manifest entries by normalized full path while preserving order."""
        deduplicated: list[WinRMFileMapEntry] = []
        seen: set[str] = set()
        for entry in entries:
            identity = cls._normalize_entry_identity(entry.full_name)
            if not identity or identity in seen:
                continue
            seen.add(identity)
            deduplicated.append(entry)
        return deduplicated

    @staticmethod
    def build_root_discovery_script() -> str:
        """Build a PowerShell script that enumerates reachable filesystem roots."""
        return "\n".join(
            [
                "$ErrorActionPreference='SilentlyContinue'",
                "Get-PSDrive -PSProvider FileSystem |",
                "Where-Object { $_.Root } |",
                "Sort-Object Root -Unique |",
                "ForEach-Object {",
                "    [PSCustomObject]@{ Root = ([string]$_.Root).Replace('/', '\\') } | ConvertTo-Json -Compress",
                "}",
            ]
        )

    def discover_file_system_roots(
        self,
        *,
        psrp_service: WinRMPSRPService,
    ) -> tuple[str, ...]:
        """Discover reachable filesystem roots for one WinRM target."""
        result = psrp_service.execute_powershell(self.build_root_discovery_script())
        if result.had_errors and not result.stdout.strip():
            raise WinRMPSRPError(result.stderr or "WinRM root discovery failed.")

        roots: list[str] = []
        for line in result.stdout.splitlines():
            payload = line.strip()
            if not payload:
                continue
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                continue
            root = str(data.get("Root") or "").strip().replace("/", "\\")
            if not root:
                continue
            if not root.endswith("\\"):
                root += "\\"
            roots.append(root)
        return tuple(dict.fromkeys(roots))

    @staticmethod
    def _escape_ps_single_quoted(value: str) -> str:
        """Escape a string for a single-quoted PowerShell literal."""
        return value.replace("'", "''")

    def build_mapping_script(
        self,
        *,
        roots: Iterable[str],
        excluded_path_prefixes: Iterable[str],
        excluded_directory_names: Iterable[str],
    ) -> str:
        """Build a PowerShell script that emits one JSON object per file."""
        escaped_roots = ",".join(
            f"'{self._escape_ps_single_quoted(root)}'" for root in roots if str(root).strip()
        )
        escaped_excluded_prefixes = ",".join(
            f"'{self._escape_ps_single_quoted(prefix)}'"
            for prefix in excluded_path_prefixes
            if str(prefix).strip()
        )
        escaped_excluded_names = ",".join(
            f"'{self._escape_ps_single_quoted(name)}'"
            for name in excluded_directory_names
            if str(name).strip()
        )
        return "\n".join(
            [
                "$ErrorActionPreference='SilentlyContinue'",
                f"$roots=@({escaped_roots})",
                f"$excludedPrefixes=@({escaped_excluded_prefixes})",
                f"$excludedDirectoryNames=@({escaped_excluded_names})",
                "$existing=@()",
                "foreach($root in $roots){",
                "    if(Test-Path -LiteralPath $root){ $existing += $root }",
                "}",
                "if($existing.Count -eq 0){ return }",
                "Get-ChildItem -Path $existing -Recurse -Force -File -ErrorAction SilentlyContinue |",
                "Where-Object {",
                "    $fullName = [string]$_.FullName",
                "    if (-not $fullName) { return $false }",
                "    $normalizedPath = $fullName.Replace('/', '\\').ToLowerInvariant()",
                "    foreach($prefix in $excludedPrefixes){",
                "        if($prefix -and $normalizedPath.StartsWith($prefix)){ return $false }",
                "    }",
                "    $pathParts = $normalizedPath -split '\\\\'",
                "    foreach($part in $pathParts){",
                "        if([string]::IsNullOrWhiteSpace($part)){ continue }",
                "        foreach($excludedName in $excludedDirectoryNames){",
                "            if($part -eq $excludedName){ return $false }",
                "        }",
                "    }",
                "    return $true",
                "} |",
                "ForEach-Object {",
                "    [PSCustomObject]@{",
                "        FullName=$_.FullName",
                "        Extension=$_.Extension",
                "        Length=[int64]$_.Length",
                "        Directory=$_.DirectoryName",
                "        LastWriteTimeUtc=$_.LastWriteTimeUtc.ToString('o')",
                "    } | ConvertTo-Json -Compress",
                "}",
            ]
        )

    def generate_file_map(
        self,
        *,
        psrp_service: WinRMPSRPService,
        output_path: str,
        roots: Iterable[str] | None = None,
        excluded_path_prefixes: Iterable[str] | None = None,
        excluded_directory_names: Iterable[str] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Generate a WinRM file manifest and persist it to disk."""
        roots_tuple = tuple(root for root in (roots or ()) if str(root).strip())
        if not roots_tuple:
            roots_tuple = self.discover_file_system_roots(psrp_service=psrp_service)
        excluded_prefixes_tuple = tuple(
            prefix
            for prefix in (excluded_path_prefixes or get_winrm_excluded_path_prefixes())
            if str(prefix).strip()
        )
        excluded_names_tuple = tuple(
            name
            for name in (excluded_directory_names or get_winrm_excluded_directory_names())
            if str(name).strip()
        )
        script = self.build_mapping_script(
            roots=roots_tuple,
            excluded_path_prefixes=excluded_prefixes_tuple,
            excluded_directory_names=excluded_names_tuple,
        )
        result = psrp_service.execute_powershell(script)
        if result.had_errors and not result.stdout.strip():
            raise WinRMPSRPError(result.stderr or "WinRM file mapping failed.")

        entries: list[WinRMFileMapEntry] = []
        for line in result.stdout.splitlines():
            payload = line.strip()
            if not payload:
                continue
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                continue
            entries.append(
                WinRMFileMapEntry(
                    full_name=str(data.get("FullName") or "").strip(),
                    extension=resolve_effective_sensitive_extension(
                        str(data.get("FullName") or "").strip()
                    )
                    or str(data.get("Extension") or "").strip().lower(),
                    length=int(data.get("Length") or 0),
                    directory=str(data.get("Directory") or "").strip(),
                    last_write_time_utc=str(data.get("LastWriteTimeUtc") or "").strip(),
                )
            )

        entries = self._deduplicate_entries(entries)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        generated_at = datetime.now(timezone.utc).isoformat()
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "schema_version": self.SCHEMA_VERSION,
                    "generated_at": generated_at,
                    "roots": list(roots_tuple),
                    "excluded_path_prefixes": list(excluded_prefixes_tuple),
                    "excluded_directory_names": list(excluded_names_tuple),
                    "metadata": dict(metadata or {}),
                    "entries": [asdict(entry) for entry in entries],
                },
                handle,
                indent=2,
            )
        return {
            "schema_version": self.SCHEMA_VERSION,
            "generated_at": generated_at,
            "roots": list(roots_tuple),
            "excluded_path_prefixes": list(excluded_prefixes_tuple),
            "excluded_directory_names": list(excluded_names_tuple),
            "metadata": dict(metadata or {}),
            "entries": entries,
            "stderr": result.stderr,
        }

    @staticmethod
    def load_file_map(*, input_path: str) -> dict[str, object]:
        """Load a persisted WinRM file manifest from disk."""
        with open(input_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        entries = [
            WinRMFileMapEntry(
                full_name=str(item.get("full_name") or item.get("FullName") or "").strip(),
                extension=str(item.get("extension") or item.get("Extension") or "").strip().lower(),
                length=int(item.get("length") or item.get("Length") or 0),
                directory=str(item.get("directory") or item.get("Directory") or "").strip(),
                last_write_time_utc=str(
                    item.get("last_write_time_utc") or item.get("LastWriteTimeUtc") or ""
                ).strip(),
            )
            for item in list(payload.get("entries") or [])
        ]
        entries = WinRMFileMappingService._deduplicate_entries(entries)
        return {
            "schema_version": int(payload.get("schema_version") or 0),
            "generated_at": str(payload.get("generated_at") or "").strip(),
            "roots": list(payload.get("roots") or []),
            "excluded_path_prefixes": list(payload.get("excluded_path_prefixes") or []),
            "excluded_directory_names": list(payload.get("excluded_directory_names") or []),
            "metadata": dict(payload.get("metadata") or {}),
            "entries": entries,
        }

    @staticmethod
    def build_cache_key(*, host: str, username: str, root_strategy: str) -> str:
        """Build a stable cache key for WinRM mapping reuse."""
        raw = f"{host}_{username}_{root_strategy}".strip().lower()
        return re.sub(r"[^a-z0-9._-]+", "_", raw).strip("_") or "default"

    @staticmethod
    def select_entries_by_extensions(
        *,
        entries: Iterable[WinRMFileMapEntry],
        extensions: Iterable[str],
    ) -> list[WinRMFileMapEntry]:
        """Filter manifest entries by case-insensitive extension."""
        normalized = {str(ext).strip().lower() for ext in extensions if str(ext).strip()}
        if not normalized:
            return []
        return [
            entry
            for entry in entries
            if entry.full_name and entry.extension.lower() in normalized
        ]

    @staticmethod
    def build_local_relative_path(remote_path: str) -> str:
        """Convert a remote Windows path into a stable local relative path."""
        path = str(remote_path or "").strip().replace("/", "\\")
        if not path:
            return ""
        drive = ""
        remainder = path
        if len(path) > 2 and path[1:3] == ":\\":
            drive = f"{path[0].upper()}_drive"
            remainder = path[3:]
        parts = [part for part in remainder.split("\\") if part]
        if drive:
            parts.insert(0, drive)
        return str(Path(*parts))


__all__ = [
    "WinRMFileMapEntry",
    "WinRMFileMappingService",
]
