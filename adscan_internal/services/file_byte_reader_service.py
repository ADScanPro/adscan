"""Generic file byte readers for SMB and local filesystem sources."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.impacket_smb_byte_reader_service import (
    ImpacketSMBByteReaderService,
)


@dataclass(frozen=True)
class FileByteReadResult:
    """Result for one file byte-read operation from any backend."""

    success: bool
    data: bytes
    truncated: bool
    backend: str
    source_path: str
    error_message: str | None = None
    auth_username: str = ""
    auth_domain: str = ""
    auth_mode: str = ""
    resolved_domain_key: str = ""
    normalized_path: str = ""
    status_code: str | None = None


class LocalFileByteReaderService(BaseService):
    """Read local file bytes with a configurable in-memory cap."""

    def read_file_bytes(
        self,
        *,
        source_path: str,
        max_bytes: int = 262144,
    ) -> FileByteReadResult:
        """Read one local file from disk and cap in-memory bytes."""
        if max_bytes <= 0:
            return FileByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                backend="local",
                source_path=source_path,
                error_message="max_bytes must be positive.",
            )
        path = Path(source_path)
        if not path.exists() or not path.is_file():
            return FileByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                backend="local",
                source_path=source_path,
                error_message=f"Local file not found: {source_path}",
            )

        try:
            with path.open("rb") as handle:
                payload = handle.read(max_bytes + 1)
        except Exception as exc:  # noqa: BLE001
            self.logger.exception(
                "Failed reading local file bytes: path=%s",
                source_path,
            )
            return FileByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                backend="local",
                source_path=source_path,
                error_message=str(exc),
            )

        truncated = len(payload) > max_bytes
        if truncated:
            payload = payload[:max_bytes]
        return FileByteReadResult(
            success=True,
            data=payload,
            truncated=truncated,
            backend="local",
            source_path=source_path,
            normalized_path=str(path),
        )


class SMBFileByteReaderService(BaseService):
    """Adapter exposing SMB byte reads under a backend-agnostic API."""

    def __init__(
        self,
        *,
        smb_reader: ImpacketSMBByteReaderService | None = None,
    ) -> None:
        """Initialize adapter with the concrete Impacket SMB reader."""
        super().__init__()
        self._smb_reader = smb_reader or ImpacketSMBByteReaderService()

    def read_file_bytes(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str,
        max_bytes: int = 262144,
        timeout_seconds: int = 30,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> FileByteReadResult:
        """Read one SMB file and map result to generic read result model."""
        smb_result = self._smb_reader.read_file_bytes(
            shell=shell,
            domain=domain,
            host=host,
            share=share,
            source_path=source_path,
            max_bytes=max_bytes,
            timeout_seconds=timeout_seconds,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_domain=auth_domain,
        )
        return FileByteReadResult(
            success=smb_result.success,
            data=smb_result.data,
            truncated=smb_result.truncated,
            backend="smb_impacket",
            source_path=smb_result.source_path or source_path,
            error_message=smb_result.error_message,
            auth_username=smb_result.auth_username,
            auth_domain=smb_result.auth_domain,
            auth_mode=smb_result.auth_mode,
            resolved_domain_key=smb_result.resolved_domain_key,
            normalized_path=smb_result.normalized_path,
            status_code=smb_result.status_code,
        )
