"""Transport-agnostic Windows filesystem mapping helpers.

This service builds deterministic file manifests by executing PowerShell over
any backend that can return stdout/stderr and an error flag. It is intentionally
separate from WinRM so MSSQL/xp_cmdshell or future transports can reuse the
same mapping, exclusion, and extension-selection logic.
"""

from __future__ import annotations

import base64
import binascii
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import re
from typing import Callable, Iterable

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.smb_sensitive_file_policy import (
    resolve_effective_sensitive_extension,
)


@dataclass(slots=True, frozen=True)
class WindowsFileMapEntry:
    """One remotely discovered Windows file entry."""

    full_name: str
    extension: str
    length: int
    directory: str
    last_write_time_utc: str


@dataclass(slots=True, frozen=True)
class WindowsPowerShellExecutionResult:
    """Normalized PowerShell execution result for mapping backends."""

    stdout: str
    stderr: str = ""
    had_errors: bool = False


class WindowsFileMappingError(RuntimeError):
    """Raised when a transport backend cannot produce a usable file mapping."""


@dataclass(slots=True, frozen=True)
class WindowsFileMapLimits:
    """Bounds of a file listing read over a transport that buffers each reply.

    The MSSQL transport returns one reply row per output line and holds the
    whole reply in memory; the WinRM transport keeps every output line of a
    pipeline and joins them when it ends. Either way one unbounded listing of a
    real drive is held whole, and on a large drive cannot complete within the
    memory a scan has. A bounded listing never asks for more than
    ``max_entries_per_query`` entries in one reply, refuses a reply longer than
    ``max_reply_chars`` on the server, and stops for good at
    ``max_total_entries`` entries or ``max_queries`` queries. Whatever it did
    not list is returned as a declared gap, never as a shorter listing.

    The defaults: 2,000 entries compress to well under 120,000 characters of
    reply (about 480 rows of 250 characters), which the TDS client parses in
    tens of megabytes. 50,000 entries and 300 queries are more than a server's
    reviewable files need once the listing is filtered by extension, and keep
    the whole review within minutes.
    """

    max_entries_per_query: int = 2000
    max_reply_chars: int = 120_000
    max_total_entries: int = 50_000
    max_queries: int = 300
    #: Directories named in the manifest when the listing stopped before them.
    max_unlisted_named: int = 50

    def as_dict(self) -> dict[str, int]:
        """The limits as the manifest records them."""
        return {
            "max_entries_per_query": self.max_entries_per_query,
            "max_reply_chars": self.max_reply_chars,
            "max_total_entries": self.max_total_entries,
            "max_queries": self.max_queries,
        }


@dataclass(slots=True, frozen=True)
class _BoundedListingReply:
    """One decoded reply of the bounded listing script."""

    records: tuple[tuple[str, int, str], ...]
    truncated: bool
    oversize: bool = False


#: Directories a bounded listing reads LAST. Nothing is left out: every
#: directory is still walked. These hold the bulk of a server's files and the
#: fewest of the client's own, so when a listing reaches its total, what it did
#: not reach is operating-system and vendor content, and a custom location
#: (``C:\\backups``, an application's own folder, a user profile) was already read.
BULK_SYSTEM_DIRECTORY_NAMES: tuple[str, ...] = (
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
)

#: Listing kinds the bounded script reads.
_LISTING_FILES_RECURSIVE = "files_recursive"
_LISTING_FILES_DIRECT = "files_direct"
_LISTING_DIRECTORIES = "directories"

_REPLY_BEGIN = "#adscan-filemap-begin"
_REPLY_END = "#adscan-filemap-end"
_REPLY_OVERSIZE = "#adscan-filemap-oversize"
_REPLY_TRAILER = "#end"


PowerShellCommandExecutor = Callable[[str], WindowsPowerShellExecutionResult]


class WindowsFileMappingService(BaseService):
    """Generate and query Windows file manifests over reusable PowerShell backends."""

    SCHEMA_VERSION = 1

    @staticmethod
    def _normalize_entry_identity(full_name: str) -> str:
        """Build a stable deduplication identity for one Windows file path."""
        return str(full_name or "").strip().replace("/", "\\").lower()

    @classmethod
    def _deduplicate_entries(
        cls,
        entries: Iterable[WindowsFileMapEntry],
    ) -> list[WindowsFileMapEntry]:
        """Deduplicate manifest entries by normalized full path while preserving order."""
        deduplicated: list[WindowsFileMapEntry] = []
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
        command_executor: PowerShellCommandExecutor,
    ) -> tuple[str, ...]:
        """Discover reachable filesystem roots for one remote Windows target."""
        result = command_executor(self.build_root_discovery_script())
        if result.had_errors and not result.stdout.strip():
            raise WindowsFileMappingError(result.stderr or "Windows root discovery failed.")

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
        command_executor: PowerShellCommandExecutor,
        output_path: str,
        roots: Iterable[str] | None = None,
        excluded_path_prefixes: Iterable[str] | None = None,
        excluded_directory_names: Iterable[str] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Generate a Windows file manifest and persist it to disk."""
        roots_tuple = tuple(root for root in (roots or ()) if str(root).strip())
        if not roots_tuple:
            roots_tuple = self.discover_file_system_roots(command_executor=command_executor)
        excluded_prefixes_tuple = tuple(
            prefix for prefix in (excluded_path_prefixes or ()) if str(prefix).strip()
        )
        excluded_names_tuple = tuple(
            name for name in (excluded_directory_names or ()) if str(name).strip()
        )
        script = self.build_mapping_script(
            roots=roots_tuple,
            excluded_path_prefixes=excluded_prefixes_tuple,
            excluded_directory_names=excluded_names_tuple,
        )
        result = command_executor(script)
        if result.had_errors and not result.stdout.strip():
            raise WindowsFileMappingError(result.stderr or "Windows file mapping failed.")

        entries: list[WindowsFileMapEntry] = []
        for line in result.stdout.splitlines():
            payload = line.strip()
            if not payload:
                continue
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                continue
            entries.append(
                WindowsFileMapEntry(
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

    # ------------------------------------------------------------------
    # Bounded listing: for a transport that buffers every reply (MSSQL, WinRM).
    # ------------------------------------------------------------------

    def build_bounded_listing_script(
        self,
        *,
        directory: str,
        kind: str,
        excluded_path_prefixes: Iterable[str],
        excluded_directory_names: Iterable[str],
        included_extensions: Iterable[str],
        max_entries: int,
        max_reply_chars: int,
        skip: int = 0,
    ) -> str:
        """Build the PowerShell that lists ONE directory within fixed bounds.

        The script filters on the server (exclusions, and extensions when
        given), stops the walk at ``max_entries + 1`` matches, and returns the
        records gzip-compressed and base64-encoded in lines of 200 characters
        between two marker lines. Compression keeps the reply to a few hundred
        rows; base64 keeps non-ASCII names and long paths intact across the
        255-character rows of the transport. A reply longer than
        ``max_reply_chars`` is replaced by one marker line.

        Args:
            directory: The directory to list.
            kind: ``files_recursive``, ``files_direct`` or ``directories``.
            excluded_path_prefixes: Lower-case path prefixes left out.
            excluded_directory_names: Lower-case directory names left out.
            included_extensions: Lower-case extensions kept (``.txt``); empty
                keeps every file. A file matches when any of its dot-separated
                suffixes is in the set, so ``Groups.xml.bak`` matches ``.xml``.
            max_entries: Entries the reply may carry.
            max_reply_chars: Characters of base64 the reply may carry.
            skip: Matches to pass over first, to read a directory's own files
                or subdirectories page by page.
        """
        if kind not in {_LISTING_FILES_RECURSIVE, _LISTING_FILES_DIRECT, _LISTING_DIRECTORIES}:
            raise ValueError(f"unknown listing kind: {kind}")

        def _ps_list(values: Iterable[str]) -> str:
            return ",".join(
                f"'{self._escape_ps_single_quoted(str(value).strip().lower())}'"
                for value in values
                if str(value).strip()
            )

        recurse = " -Recurse" if kind == _LISTING_FILES_RECURSIVE else ""
        want_directories = "$true" if kind == _LISTING_DIRECTORIES else "$false"
        return "\n".join(
            [
                "$ErrorActionPreference='SilentlyContinue'",
                f"$dir='{self._escape_ps_single_quoted(directory)}'",
                f"$excludedPrefixes=@({_ps_list(excluded_path_prefixes)})",
                f"$excludedDirectoryNames=@({_ps_list(excluded_directory_names)})",
                f"$extensions=@({_ps_list(included_extensions)})",
                f"$maxEntries={int(max_entries)}",
                f"$maxChars={int(max_reply_chars)}",
                f"$skip={max(0, int(skip))}",
                f"$wantDirectories={want_directories}",
                "$extSet=@{}",
                "foreach($e in $extensions){ $extSet[$e]=$true }",
                "$sb=New-Object System.Text.StringBuilder",
                "$count=0",
                "$truncated=0",
                "if(Test-Path -LiteralPath $dir){",
                f"Get-ChildItem -LiteralPath $dir -Force{recurse} -ErrorAction SilentlyContinue |",
                "Where-Object {",
                "    if([bool]$_.PSIsContainer -ne $wantDirectories){ return $false }",
                "    if($wantDirectories -and ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)){ return $false }",
                "    $fullName = [string]$_.FullName",
                "    if (-not $fullName) { return $false }",
                "    $normalizedPath = $fullName.Replace('/', '\\').ToLowerInvariant()",
                "    $prefixPath = $normalizedPath",
                "    if($wantDirectories){ $prefixPath = $normalizedPath.TrimEnd('\\') + '\\' }",
                "    foreach($prefix in $excludedPrefixes){",
                "        if($prefix -and $prefixPath.StartsWith($prefix)){ return $false }",
                "    }",
                "    $pathParts = $normalizedPath -split '\\\\'",
                "    foreach($part in $pathParts){",
                "        if([string]::IsNullOrWhiteSpace($part)){ continue }",
                "        foreach($excludedName in $excludedDirectoryNames){",
                "            if($part -eq $excludedName){ return $false }",
                "        }",
                "    }",
                "    if((-not $wantDirectories) -and ($extSet.Count -gt 0)){",
                "        $nameParts = ([string]$_.Name).ToLowerInvariant().Split('.')",
                "        $hit = $false",
                "        for($i=1; $i -lt $nameParts.Length; $i++){",
                "            if($extSet.ContainsKey('.' + $nameParts[$i])){ $hit = $true; break }",
                "        }",
                "        if(-not $hit){ return $false }",
                "    }",
                "    return $true",
                "} |",
                "Select-Object -Skip $skip -First ($maxEntries + 1) |",
                "ForEach-Object {",
                "    $count++",
                "    if($count -le $maxEntries){",
                "        $length = 0",
                "        $written = ''",
                "        if(-not $wantDirectories){",
                "            $length = [int64]$_.Length",
                "            $written = $_.LastWriteTimeUtc.ToString('o')",
                "        }",
                "        [void]$sb.Append([string]$_.FullName).Append(\"`t\").Append($length).Append(\"`t\").Append($written).Append(\"`n\")",
                "    } else { $truncated = 1 }",
                "}",
                "}",
                "$kept = [Math]::Min($count, $maxEntries)",
                f"[void]$sb.Append('{_REPLY_TRAILER}').Append(\"`t\").Append($kept).Append(\"`t\").Append($truncated).Append(\"`n\")",
                "$bytes = [Text.Encoding]::UTF8.GetBytes($sb.ToString())",
                "$ms = New-Object IO.MemoryStream",
                "$gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)",
                "$gz.Write($bytes, 0, $bytes.Length)",
                "$gz.Close()",
                "$b = [Convert]::ToBase64String($ms.ToArray())",
                f"if($b.Length -gt $maxChars){{ '{_REPLY_OVERSIZE}'; return }}",
                f"'{_REPLY_BEGIN}'",
                "for($i=0; $i -lt $b.Length; $i+=200){ $b.Substring($i, [Math]::Min(200, $b.Length - $i)) }",
                f"'{_REPLY_END}'",
            ]
        )

    @staticmethod
    def decode_bounded_listing_reply(stdout: str) -> _BoundedListingReply:
        """Decode one reply of the bounded listing script.

        Raises:
            WindowsFileMappingError: the reply is not a whole listing (a marker
                or the trailer is missing, or the payload does not decode). An
                incomplete reply is never read as an empty directory.
        """
        lines = [line.strip() for line in str(stdout or "").splitlines()]
        lines = [line for line in lines if line and line.upper() != "NULL"]
        if _REPLY_OVERSIZE in lines:
            return _BoundedListingReply(records=(), truncated=True, oversize=True)
        try:
            begin = lines.index(_REPLY_BEGIN)
            end = lines.index(_REPLY_END, begin + 1)
        except ValueError as exc:
            raise WindowsFileMappingError(
                "The file listing reply is incomplete (no begin or end marker)."
            ) from exc
        try:
            text = gzip.decompress(
                base64.b64decode("".join(lines[begin + 1 : end]), validate=True)
            ).decode("utf-8")
        except (binascii.Error, OSError, EOFError, UnicodeDecodeError) as exc:
            raise WindowsFileMappingError(
                "The file listing reply could not be decoded."
            ) from exc
        records: list[tuple[str, int, str]] = []
        trailer: tuple[int, bool] | None = None
        for line in text.split("\n"):
            if not line:
                continue
            fields = line.split("\t")
            if fields[0] == _REPLY_TRAILER and len(fields) >= 3:
                try:
                    trailer = (int(fields[1]), fields[2].strip() == "1")
                except ValueError:
                    trailer = None
                continue
            if len(fields) < 3 or not fields[0].strip():
                continue
            try:
                length = int(fields[1] or 0)
            except ValueError:
                length = 0
            records.append((fields[0].strip(), length, fields[2].strip()))
        if trailer is None or trailer[0] != len(records):
            raise WindowsFileMappingError(
                "The file listing reply is incomplete (its record count does not match)."
            )
        return _BoundedListingReply(records=tuple(records), truncated=trailer[1])

    def generate_bounded_file_map(
        self,
        *,
        command_executor: PowerShellCommandExecutor,
        output_path: str,
        limits: WindowsFileMapLimits | None = None,
        roots: Iterable[str] | None = None,
        excluded_path_prefixes: Iterable[str] | None = None,
        excluded_directory_names: Iterable[str] | None = None,
        included_extensions: Iterable[str] | None = None,
        deferred_directory_names: Iterable[str] | None = None,
        metadata: dict[str, object] | None = None,
        on_query: Callable[[], None] | None = None,
    ) -> dict[str, object]:
        """Generate a file manifest in bounded replies and persist it to disk.

        Each directory is listed in one reply of at most
        ``limits.max_entries_per_query`` entries. A directory that holds more is
        split: its own files are read in one reply and each subdirectory is
        queued, so a large drive is read whole in small replies. The listing
        stops at ``limits.max_total_entries`` entries or ``limits.max_queries``
        queries; the manifest's ``listing`` block then says ``complete: false``
        and names the directories it did not reach.

        Args:
            command_executor: Runs one PowerShell script on the target.
            output_path: Where the manifest is written.
            limits: The bounds (default :class:`WindowsFileMapLimits`).
            roots: Roots to list; discovered when omitted.
            excluded_path_prefixes: Path prefixes left out.
            excluded_directory_names: Directory names left out.
            included_extensions: Extensions kept; every file when empty.
            deferred_directory_names: Directory names read after every other
                directory (see :data:`BULK_SYSTEM_DIRECTORY_NAMES`). They are
                still read: this orders the walk, it excludes nothing.
            metadata: Stored with the manifest.
            on_query: Called before each query (a memory-stage check).

        Returns:
            The manifest, with ``entries`` as :class:`WindowsFileMapEntry` and a
            ``listing`` block (see :meth:`_listing_block`).
        """
        bounds = limits or WindowsFileMapLimits()
        roots_tuple = tuple(root for root in (roots or ()) if str(root).strip())
        if not roots_tuple:
            roots_tuple = self.discover_file_system_roots(command_executor=command_executor)
        prefixes = tuple(
            str(prefix).strip().replace("/", "\\").lower()
            for prefix in (excluded_path_prefixes or ())
            if str(prefix).strip()
        )
        names = tuple(
            str(name).strip().lower() for name in (excluded_directory_names or ()) if str(name).strip()
        )
        extensions = tuple(
            dict.fromkeys(
                str(ext).strip().lower() for ext in (included_extensions or ()) if str(ext).strip()
            )
        )

        deferred = {
            str(name).strip().lower() for name in (deferred_directory_names or ()) if str(name).strip()
        }

        def _queue(directories: list[str]) -> None:
            """Queue subdirectories: the deferred ones last, the others next."""
            late = [d for d in directories if d.rstrip("\\").rsplit("\\", 1)[-1].lower() in deferred]
            pending.extendleft(reversed([d for d in directories if d not in late]))
            pending.extend(late)

        entries: list[WindowsFileMapEntry] = []
        seen: set[str] = set()
        pending: deque[str] = deque(roots_tuple)
        partial: list[str] = []
        queries = 0
        stderr_parts: list[str] = []

        def _query(directory: str, kind: str, skip: int = 0) -> _BoundedListingReply | None:
            """Run one bounded query, or ``None`` when the query budget is spent."""
            nonlocal queries
            if queries >= bounds.max_queries:
                return None
            if on_query is not None:
                on_query()
            queries += 1
            result = command_executor(
                self.build_bounded_listing_script(
                    directory=directory,
                    kind=kind,
                    excluded_path_prefixes=prefixes,
                    excluded_directory_names=names,
                    included_extensions=extensions,
                    max_entries=bounds.max_entries_per_query,
                    max_reply_chars=bounds.max_reply_chars,
                    skip=skip,
                )
            )
            if result.stderr:
                stderr_parts.append(str(result.stderr))
            if result.had_errors and not str(result.stdout or "").strip():
                raise WindowsFileMappingError(result.stderr or "Windows file mapping failed.")
            return self.decode_bounded_listing_reply(result.stdout)

        def _keep(records: Iterable[tuple[str, int, str]]) -> None:
            for full_name, length, written in records:
                identity = self._normalize_entry_identity(full_name)
                if not identity or identity in seen:
                    continue
                seen.add(identity)
                entries.append(
                    WindowsFileMapEntry(
                        full_name=full_name,
                        extension=resolve_effective_sensitive_extension(full_name),
                        length=length,
                        directory=full_name.rsplit("\\", 1)[0] if "\\" in full_name else "",
                        last_write_time_utc=written,
                    )
                )

        def _paged(directory: str, kind: str) -> tuple[list[tuple[str, int, str]], bool]:
            """Read one directory's own files or subdirectories page by page.

            Returns the records read and whether the directory was read whole.
            """
            records: list[tuple[str, int, str]] = []
            while True:
                reply = _query(directory, kind, skip=len(records))
                if reply is None or reply.oversize:
                    return records, False
                records.extend(reply.records)
                if not reply.truncated:
                    return records, True
                if not reply.records or len(entries) + len(records) > bounds.max_total_entries:
                    return records, False

        stopped = False
        while pending:
            if len(entries) >= bounds.max_total_entries:
                stopped = True
                break
            directory = pending.popleft()
            reply = _query(directory, _LISTING_FILES_RECURSIVE)
            if reply is None:
                pending.appendleft(directory)
                stopped = True
                break
            if not reply.truncated:
                _keep(reply.records)
                continue
            # More than one reply holds: read this directory's own files, then
            # queue each subdirectory for a reply of its own.
            subdirectories, whole = _paged(directory, _LISTING_DIRECTORIES)
            if whole:
                files, whole = _paged(directory, _LISTING_FILES_DIRECT)
                _keep(files)
            _queue([record[0] for record in subdirectories])
            if not whole:
                # The pages of this directory were cut short (the query budget
                # ran out, or one page would not fit a reply): it is declared.
                partial.append(directory)
                if queries >= bounds.max_queries:
                    stopped = True
                    break

        if len(entries) > bounds.max_total_entries:
            del entries[bounds.max_total_entries :]
            stopped = True
        unlisted = list(dict.fromkeys(list(pending) + partial)) if (stopped or partial) else []
        listing = self._listing_block(
            limits=bounds,
            entries_listed=len(entries),
            queries=queries,
            unlisted=unlisted,
            included_extensions=extensions,
        )

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        generated_at = datetime.now(timezone.utc).isoformat()
        manifest: dict[str, object] = {
            "schema_version": self.SCHEMA_VERSION,
            "generated_at": generated_at,
            "roots": list(roots_tuple),
            "excluded_path_prefixes": list(prefixes),
            "excluded_directory_names": list(names),
            "metadata": dict(metadata or {}),
            "listing": listing,
        }
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump({**manifest, "entries": [asdict(entry) for entry in entries]}, handle, indent=2)
        return {**manifest, "entries": entries, "stderr": "\n".join(stderr_parts)}

    @staticmethod
    def _listing_block(
        *,
        limits: WindowsFileMapLimits,
        entries_listed: int,
        queries: int,
        unlisted: list[str],
        included_extensions: Iterable[str],
    ) -> dict[str, object]:
        """The manifest's record of how a bounded listing ended.

        ``complete`` is false when any directory was not listed in full; the
        first ``limits.max_unlisted_named`` of them are named and
        ``unlisted_directory_count`` is the exact count.
        """
        return {
            "mode": "bounded",
            "complete": not unlisted,
            "entries_listed": int(entries_listed),
            "queries": int(queries),
            "limits": limits.as_dict(),
            "included_extensions": list(included_extensions),
            "unlisted_directory_count": len(unlisted),
            "unlisted_directories": list(unlisted[: limits.max_unlisted_named]),
        }

    @classmethod
    def load_file_map(cls, *, input_path: str) -> dict[str, object]:
        """Load a persisted Windows file manifest from disk."""
        with open(input_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        entries = [
            WindowsFileMapEntry(
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
        entries = cls._deduplicate_entries(entries)
        return {
            "schema_version": int(payload.get("schema_version") or 0),
            "generated_at": str(payload.get("generated_at") or "").strip(),
            "roots": list(payload.get("roots") or []),
            "excluded_path_prefixes": list(payload.get("excluded_path_prefixes") or []),
            "excluded_directory_names": list(payload.get("excluded_directory_names") or []),
            "metadata": dict(payload.get("metadata") or {}),
            "listing": dict(payload.get("listing") or {}),
            "entries": entries,
        }

    @staticmethod
    def build_cache_key(*, host: str, username: str, root_strategy: str) -> str:
        """Build a stable cache key for mapping reuse."""
        raw = f"{host}_{username}_{root_strategy}".strip().lower()
        return re.sub(r"[^a-z0-9._-]+", "_", raw).strip("_") or "default"

    @staticmethod
    def select_entries_by_extensions(
        *,
        entries: Iterable[WindowsFileMapEntry],
        extensions: Iterable[str],
    ) -> list[WindowsFileMapEntry]:
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
    "PowerShellCommandExecutor",
    "BULK_SYSTEM_DIRECTORY_NAMES",
    "WindowsFileMapEntry",
    "WindowsFileMapLimits",
    "WindowsFileMappingError",
    "WindowsFileMappingService",
    "WindowsPowerShellExecutionResult",
]
