"""Reusable WinRM/PSRP helpers for command execution and file transfer.

This service centralises the PSRP-backed operations that were previously
implemented ad hoc via ``nxc winrm -X``. The goal is to keep WinRM features
modular and reusable while preserving the legacy NetExec flows as fallbacks.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
from pathlib import Path
import os
import re
import tempfile
from typing import Iterable
import zipfile


class WinRMPSRPError(RuntimeError):
    """Raised when a PSRP-backed WinRM operation fails."""


@dataclass(slots=True)
class WinRMPSRPExecutionResult:
    """Structured result for a PowerShell execution over PSRP."""

    stdout: str
    stderr: str
    had_errors: bool


@dataclass(slots=True)
class WinRMPSRPBatchFetchResult:
    """Structured result for batched WinRM file staging and download."""

    downloaded_files: list[str]
    staged_file_count: int
    skipped_files: list[tuple[str, str]]


class WinRMPSRPService:
    """Execute commands and transfer files over WinRM using ``pypsrp``."""

    def __init__(
        self,
        *,
        domain: str,
        host: str,
        username: str,
        password: str,
    ) -> None:
        self.domain = domain
        self.host = host
        self.username = username
        self.password = password
        self._client = None

    def _build_full_username(self) -> str:
        """Return the WinRM username in the format expected by PSRP."""
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username

    def _normalize_secret(self) -> str:
        """Normalize a password or bare NT hash for requests-ntlm."""
        secret = self.password
        if secret and re.fullmatch(r"[0-9A-Fa-f]{32}", secret):
            return f"{'0' * 32}:{secret}"
        return secret

    def _load_client_class(self):
        """Load the ``pypsrp`` client class or raise a PSRP-specific error."""
        try:
            from pypsrp.client import Client  # type: ignore[import]
        except Exception as exc:  # pragma: no cover - import depends on runtime
            raise WinRMPSRPError(
                "pypsrp is not available; unable to use the WinRM PSRP backend."
            ) from exc
        return Client

    def _get_client(self):
        """Return a cached PSRP client instance."""
        if self._client is None:
            client_class = self._load_client_class()
            try:
                self._client = client_class(
                    self.host,
                    username=self._build_full_username(),
                    password=self._normalize_secret(),
                    ssl=False,
                    port=5985,
                    auth="ntlm",
                )
            except Exception as exc:  # pragma: no cover - network/runtime specific
                raise WinRMPSRPError(
                    f"Failed to initialise WinRM PSRP client for {self.host}: {exc}"
                ) from exc
        return self._client

    def execute_powershell(self, script: str) -> WinRMPSRPExecutionResult:
        """Execute PowerShell over PSRP and return structured output."""
        client = self._get_client()
        try:
            stdout, streams, had_errors = client.execute_ps(script)
        except Exception as exc:  # pragma: no cover - network/runtime specific
            raise WinRMPSRPError(
                f"WinRM PSRP PowerShell execution failed on {self.host}: {exc}"
            ) from exc

        stderr_parts: list[str] = []
        for stream_name in ("error", "warning", "verbose", "debug"):
            stream = getattr(streams, stream_name, None)
            if not stream:
                continue
            stderr_parts.extend(str(item) for item in stream if str(item).strip())

        return WinRMPSRPExecutionResult(
            stdout=stdout or "",
            stderr="\n".join(stderr_parts).strip(),
            had_errors=bool(had_errors),
        )

    def fetch_files(self, paths: Iterable[str], download_dir: str) -> list[str]:
        """Download remote files to a local directory via PSRP."""
        os.makedirs(download_dir, exist_ok=True)
        downloaded_files: list[str] = []

        for remote_path in paths:
            file_name = remote_path.split("\\")[-1]
            save_path = str(Path(download_dir) / file_name)
            self.fetch_file(remote_path, save_path)
            downloaded_files.append(save_path)

        return downloaded_files

    def fetch_file(self, remote_path: str, save_path: str) -> str:
        """Download one remote file to one explicit local path via PSRP."""
        client = self._get_client()
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        try:
            client.fetch(remote_path, save_path)
        except Exception as exc:  # pragma: no cover - network/runtime specific
            raise WinRMPSRPError(
                f"WinRM PSRP file download failed for {remote_path} on "
                f"{self.host}: {exc}"
            ) from exc
        return save_path

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload one local file to one remote path via PSRP."""
        try:
            from pypsrp.complex_objects import PSInvocationState  # type: ignore[import]
            from pypsrp.powershell import PowerShell, RunspacePool  # type: ignore[import]
        except Exception as exc:  # pragma: no cover - import depends on runtime
            raise WinRMPSRPError(
                "pypsrp PowerShell helpers are not available; unable to upload via PSRP."
            ) from exc

        if not os.path.exists(local_path) or not os.path.isfile(local_path):
            raise WinRMPSRPError(
                f"Local file '{local_path}' does not exist or is not a file."
            )

        file_path = Path(local_path)
        try:
            file_size = file_path.stat().st_size
            with file_path.open("rb") as handle:
                hexdigest = hashlib.md5(handle.read()).hexdigest().upper()
        except OSError as exc:
            raise WinRMPSRPError(
                f"Unable to prepare local file '{local_path}' for WinRM upload: {exc}"
            ) from exc

        send_ps_script = r"""
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Base64Chunk,
    [Parameter(Mandatory=$true, Position=1)]
    [int]$ChunkType = 0,
    [Parameter(Mandatory=$false, Position=2)]
    [string]$TempFilePath,
    [Parameter(Mandatory=$false, Position=3)]
    [string]$FilePath,
    [Parameter(Mandatory=$false, Position=4)]
    [string]$FileHash
)

$fileStream = $null

if ($ChunkType -eq 0 -or $ChunkType -eq 3) {
    $TempFilePath = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        [System.IO.Path]::GetRandomFileName()
    )

    [PSCustomObject]@{
        Type         = "Metadata"
        TempFilePath = $TempFilePath
    } | ConvertTo-Json -Compress | Write-Output
}

try {
    $chunkBytes = [System.Convert]::FromBase64String($Base64Chunk)

    $fileStream = New-Object System.IO.FileStream(
        $TempFilePath,
        [System.IO.FileMode]::Append,
        [System.IO.FileAccess]::Write
    )

    $fileStream.Write($chunkBytes, 0, $chunkBytes.Length)
    $fileStream.Close()
} catch {
    $msg = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
    [PSCustomObject]@{
        Type    = "Error"
        Message = "Error processing chunk or writing to file: $msg"
    } | ConvertTo-Json -Compress | Write-Output
} finally {
    if ($fileStream) {
        $fileStream.Dispose()
    }
}

if ($ChunkType -eq 1 -or $ChunkType -eq 3) {
    try {
        if ($TempFilePath) {
            $calculatedHash = (Get-FileHash -Path $TempFilePath -Algorithm MD5).Hash
            if ($calculatedHash -eq $FileHash) {
                [System.IO.File]::Delete($FilePath)
                [System.IO.File]::Move($TempFilePath, $FilePath)

                $fileInfo = Get-Item -Path $FilePath
                $fileSize = $fileInfo.Length
                $fileHash = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash

                [PSCustomObject]@{
                    Type     = "Metadata"
                    FilePath = $FilePath
                    FileSize = $fileSize
                    FileHash = $fileHash
                    FileName = $fileInfo.Name
                } | ConvertTo-Json -Compress | Write-Output
            } else {
                [PSCustomObject]@{
                    Type    = "Error"
                    Message = "File hash mismatch. Expected: $FileHash, Calculated: $calculatedHash"
                } | ConvertTo-Json -Compress | Write-Output
            }
        } else {
            [PSCustomObject]@{
                Type    = "Error"
                Message = "File hash not provided for verification."
            } | ConvertTo-Json -Compress | Write-Output
        }
    } catch {
        $msg = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
        [PSCustomObject]@{
            Type    = "Error"
            Message = "Error processing chunk or writing to file: $msg"
        } | ConvertTo-Json -Compress | Write-Output
    }
}
"""

        chunk_size = 65536
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        client = self._get_client()

        try:
            with RunspacePool(client.wsman) as pool:
                temp_file_path = ""
                metadata: dict | None = None

                with file_path.open("rb") as src:
                    for index in range(total_chunks):
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break

                        if total_chunks == 1:
                            chunk_type = 3
                        elif index == 0:
                            chunk_type = 0
                        elif index == total_chunks - 1:
                            chunk_type = 1
                        else:
                            chunk_type = 2

                        base64_chunk = base64.b64encode(chunk).decode("utf-8")

                        ps = PowerShell(pool)
                        ps.add_script(send_ps_script)
                        ps.add_parameter("Base64Chunk", base64_chunk)
                        ps.add_parameter("ChunkType", chunk_type)

                        if chunk_type in (1, 2) and temp_file_path:
                            ps.add_parameter("TempFilePath", temp_file_path)

                        if chunk_type in (1, 3):
                            ps.add_parameter("FilePath", remote_path)
                            ps.add_parameter("FileHash", hexdigest)

                        ps.begin_invoke()
                        while ps.state == PSInvocationState.RUNNING:
                            ps.poll_invoke()

                        for line in ps.output:
                            try:
                                data = json.loads(str(line))
                            except Exception:
                                continue

                            if data.get("Type") == "Metadata":
                                metadata = data
                                if "TempFilePath" in data:
                                    temp_file_path = str(data["TempFilePath"])
                            elif data.get("Type") == "Error":
                                raise WinRMPSRPError(
                                    str(data.get("Message") or "Unknown WinRM upload error.")
                                )

                        if ps.had_errors and ps.streams.error:
                            raise WinRMPSRPError(str(ps.streams.error[0]))

            return bool(metadata and metadata.get("FilePath") == remote_path)
        except WinRMPSRPError:
            raise
        except Exception as exc:  # pragma: no cover - runtime specific
            raise WinRMPSRPError(f"WinRM upload failed for {remote_path}: {exc}") from exc

    @staticmethod
    def _escape_ps_single_quoted(value: str) -> str:
        """Escape a string for a single-quoted PowerShell literal."""
        return value.replace("'", "''")

    def _build_archive_stage_script(self, *, files: Iterable[tuple[str, str]]) -> str:
        """Build a PowerShell script that stages selected files into one ZIP."""
        manifest_json = json.dumps(
            [
                {"RemotePath": remote_path, "RelativePath": relative_path.replace("/", "\\")}
                for remote_path, relative_path in files
            ]
        )
        escaped_manifest = self._escape_ps_single_quoted(manifest_json)
        script_lines = [
            "$ErrorActionPreference='Stop'",
            "$guid=[guid]::NewGuid().Guid",
            "$stageRoot=Join-Path $env:TEMP ('adscan_psrp_stage_'+$guid)",
            "$archivePath=Join-Path $env:TEMP ('adscan_psrp_stage_'+$guid+'.zip')",
            "$manifest=@'",
            escaped_manifest,
            "'@ | ConvertFrom-Json",
            "New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null",
            "$staged=@()",
            "$skipped=@()",
            "foreach($item in $manifest){",
            "    try {",
            "        $destination=Join-Path $stageRoot $item.RelativePath",
            "        $destinationDir=Split-Path -Parent $destination",
            "        if($destinationDir){ New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null }",
            "        Copy-Item -LiteralPath $item.RemotePath -Destination $destination -Force -ErrorAction Stop",
            "        $staged += $item.RemotePath",
            "    } catch {",
            "        $skipped += [PSCustomObject]@{",
            "            RemotePath = $item.RemotePath",
            "            Reason = $_.Exception.Message",
            "        }",
            "    }",
            "}",
            "if($staged.Count -gt 0){",
            "    Compress-Archive -Path (Join-Path $stageRoot '*') -DestinationPath $archivePath -Force",
            "}",
            "[PSCustomObject]@{",
            "    ArchivePath = $(if($staged.Count -gt 0){ $archivePath } else { '' })",
            "    StageRoot = $stageRoot",
            "    StagedFileCount = $staged.Count",
            "    Skipped = @($skipped)",
            "} | ConvertTo-Json -Compress -Depth 4",
        ]
        return "\n".join(script_lines)

    @staticmethod
    def _build_archive_cleanup_script(*, archive_path: str, stage_root: str) -> str:
        """Build a PowerShell cleanup script for remote staging artifacts."""
        def _quoted(value: str) -> str:
            return "'" + value.replace("'", "''") + "'"

        return (
            "$ErrorActionPreference='SilentlyContinue';"
            f"Remove-Item -LiteralPath {_quoted(archive_path)} -Force -ErrorAction SilentlyContinue;"
            f"Remove-Item -LiteralPath {_quoted(stage_root)} -Recurse -Force -ErrorAction SilentlyContinue"
        )

    def fetch_files_batched(
        self,
        *,
        files: Iterable[tuple[str, str]],
        download_dir: str,
    ) -> WinRMPSRPBatchFetchResult:
        """Stage selected remote files into one ZIP, fetch it, and extract locally."""
        file_list = [(remote_path, relative_path) for remote_path, relative_path in files if remote_path and relative_path]
        if not file_list:
            return WinRMPSRPBatchFetchResult(downloaded_files=[], staged_file_count=0, skipped_files=[])

        os.makedirs(download_dir, exist_ok=True)
        stage_result = self.execute_powershell(self._build_archive_stage_script(files=file_list))
        if stage_result.had_errors and not stage_result.stdout.strip():
            raise WinRMPSRPError(stage_result.stderr or "WinRM PSRP archive staging failed.")

        archive_path = ""
        stage_root = ""
        staged_file_count = 0
        skipped_files: list[tuple[str, str]] = []
        try:
            payload = json.loads(stage_result.stdout.strip())
            archive_path = str(payload.get("ArchivePath") or "").strip()
            stage_root = str(payload.get("StageRoot") or "").strip()
            staged_file_count = int(payload.get("StagedFileCount") or 0)
            skipped_payload = payload.get("Skipped") or []
            if isinstance(skipped_payload, list):
                skipped_files = [
                    (
                        str(item.get("RemotePath") or "").strip(),
                        str(item.get("Reason") or "").strip(),
                    )
                    for item in skipped_payload
                    if isinstance(item, dict) and str(item.get("RemotePath") or "").strip()
                ]
        except (json.JSONDecodeError, AttributeError) as exc:
            raise WinRMPSRPError(
                "WinRM PSRP archive staging returned an invalid response."
            ) from exc

        if not stage_root:
            raise WinRMPSRPError(
                "WinRM PSRP archive staging did not return the remote staging metadata."
            )
        if staged_file_count <= 0 and archive_path:
            staged_file_count = len(file_list)
        if staged_file_count <= 0:
            raise WinRMPSRPError(
                "WinRM PSRP archive staging could not access any of the selected files."
            )

        temp_archive_path = ""
        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
                temp_archive_path = handle.name
            self.fetch_file(archive_path, temp_archive_path)
            with zipfile.ZipFile(temp_archive_path, "r") as archive_handle:
                archive_handle.extractall(download_dir)
        except zipfile.BadZipFile as exc:
            raise WinRMPSRPError(
                f"WinRM PSRP staged archive for {self.host} is not a valid ZIP file: {exc}"
            ) from exc
        finally:
            try:
                self.execute_powershell(
                    self._build_archive_cleanup_script(
                        archive_path=archive_path,
                        stage_root=stage_root,
                    )
                )
            except WinRMPSRPError:
                pass
            if temp_archive_path and os.path.exists(temp_archive_path):
                os.remove(temp_archive_path)

        downloaded_files: list[str] = []
        for _remote_path, relative_path in file_list:
            save_path = str(Path(download_dir) / relative_path)
            if os.path.exists(save_path):
                downloaded_files.append(save_path)
        return WinRMPSRPBatchFetchResult(
            downloaded_files=downloaded_files,
            staged_file_count=staged_file_count,
            skipped_files=skipped_files,
        )
