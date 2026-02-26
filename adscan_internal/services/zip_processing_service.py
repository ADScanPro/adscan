"""Central ZIP inspection and extraction helpers.

This service provides reusable ZIP logic for:
- legacy CLI ZIP workflows (listing/encryption checks)
- AI share file extraction flows
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable
import io
import zipfile

from adscan_internal.file_content_type import detect_file_content_type
from adscan_internal.services.base_service import BaseService


@dataclass(frozen=True)
class ZipEntryInfo:
    """Metadata for one ZIP entry."""

    name: str
    is_dir: bool
    is_encrypted: bool
    file_size: int
    compress_size: int


@dataclass(frozen=True)
class ZipInspectionResult:
    """Outcome of ZIP metadata inspection."""

    success: bool
    entries: list[ZipEntryInfo]
    is_password_protected: bool
    encrypted_entries: int
    error_message: str | None = None


@dataclass(frozen=True)
class ZipAIExtractionResult:
    """Prompt-ready extraction output from ZIP content for AI analysis."""

    success: bool
    content_block: str
    notes: list[str]
    processed_entries: int
    encrypted_entries: int
    skipped_entries: int
    error_message: str | None = None


class ZipProcessingService(BaseService):
    """Reusable ZIP processing primitives for ADscan workflows."""

    def inspect_zip_file(self, *, zip_path: str) -> ZipInspectionResult:
        """Inspect a local ZIP file for entries and encryption flags."""
        path = Path(zip_path)
        if not path.exists():
            return ZipInspectionResult(
                success=False,
                entries=[],
                is_password_protected=False,
                encrypted_entries=0,
                error_message=f"ZIP file not found: {zip_path}",
            )
        try:
            with path.open("rb") as handle:
                data = handle.read()
        except Exception as exc:  # noqa: BLE001
            return ZipInspectionResult(
                success=False,
                entries=[],
                is_password_protected=False,
                encrypted_entries=0,
                error_message=str(exc),
            )
        return self.inspect_zip_bytes(file_bytes=data)

    def inspect_zip_bytes(self, *, file_bytes: bytes) -> ZipInspectionResult:
        """Inspect ZIP entries from bytes using `zipfile`."""
        try:
            archive = zipfile.ZipFile(io.BytesIO(file_bytes))
        except Exception as exc:  # noqa: BLE001
            return ZipInspectionResult(
                success=False,
                entries=[],
                is_password_protected=False,
                encrypted_entries=0,
                error_message=f"ZIP parsing failed: {type(exc).__name__}",
            )

        entries: list[ZipEntryInfo] = []
        encrypted_entries = 0
        for info in archive.infolist():
            is_encrypted = bool(info.flag_bits & 0x1)
            if is_encrypted and not info.is_dir():
                encrypted_entries += 1
            entries.append(
                ZipEntryInfo(
                    name=info.filename,
                    is_dir=info.is_dir(),
                    is_encrypted=is_encrypted,
                    file_size=int(getattr(info, "file_size", 0) or 0),
                    compress_size=int(getattr(info, "compress_size", 0) or 0),
                )
            )
        archive.close()

        return ZipInspectionResult(
            success=True,
            entries=entries,
            is_password_protected=encrypted_entries > 0,
            encrypted_entries=encrypted_entries,
            error_message=None,
        )

    def extract_for_ai_from_bytes(
        self,
        *,
        file_bytes: bytes,
        max_entry_bytes: int,
        max_entries: int,
        max_chars: int,
        binary_entry_converter: Callable[[bytes, str], str],
    ) -> ZipAIExtractionResult:
        """Extract readable candidate content from ZIP entries for AI prompts."""
        inspect_result = self.inspect_zip_bytes(file_bytes=file_bytes)
        if not inspect_result.success:
            return ZipAIExtractionResult(
                success=False,
                content_block="",
                notes=[],
                processed_entries=0,
                encrypted_entries=0,
                skipped_entries=0,
                error_message=inspect_result.error_message,
            )

        try:
            archive = zipfile.ZipFile(io.BytesIO(file_bytes))
        except Exception as exc:  # noqa: BLE001
            return ZipAIExtractionResult(
                success=False,
                content_block="",
                notes=[],
                processed_entries=0,
                encrypted_entries=0,
                skipped_entries=0,
                error_message=f"ZIP parsing failed: {type(exc).__name__}",
            )

        processed_entries = 0
        encrypted_entries = 0
        skipped_entries = 0
        chars_accumulated = 0
        sections: list[str] = []

        for info in archive.infolist():
            if processed_entries >= max_entries or chars_accumulated >= max_chars:
                break
            if info.is_dir():
                continue

            processed_entries += 1
            entry_name = info.filename
            if info.flag_bits & 0x1:
                encrypted_entries += 1
                section = f"[entry] {entry_name}\nEncrypted ZIP entry."
                sections.append(section)
                chars_accumulated += len(section)
                continue

            try:
                with archive.open(info, "r") as entry_handle:
                    entry_bytes = entry_handle.read(max(1, max_entry_bytes))
            except Exception as exc:  # noqa: BLE001
                skipped_entries += 1
                section = f"[entry] {entry_name}\nCould not read entry: {type(exc).__name__}."
                sections.append(section)
                chars_accumulated += len(section)
                continue

            entry_type = detect_file_content_type(file_bytes=entry_bytes)
            entry_suffix = Path(entry_name).suffix.lower()
            if entry_type.kind == "text":
                entry_text = entry_bytes.decode("utf-8", errors="replace")[:3000]
                section = f"[entry] {entry_name}\n{entry_text}"
            elif entry_type.kind == "zip_archive":
                skipped_entries += 1
                section = (
                    f"[entry] {entry_name}\nNested ZIP detected; "
                    "skipping nested archive recursion in this pass."
                )
            else:
                converted = binary_entry_converter(entry_bytes, entry_suffix)
                if converted:
                    section = (
                        f"[entry] {entry_name}\nExtracted with MarkItDown:\n"
                        f"{converted[:3000]}"
                    )
                else:
                    skipped_entries += 1
                    section = (
                        f"[entry] {entry_name}\nUnsupported binary content "
                        "(MarkItDown unavailable/failed)."
                    )

            remaining = max_chars - chars_accumulated
            if remaining <= 0:
                break
            if len(section) > remaining:
                section = section[:remaining]
            sections.append(section)
            chars_accumulated += len(section)

        archive.close()

        notes = [f"ZIP processed entries={processed_entries} (max={max_entries})."]
        if encrypted_entries > 0:
            notes.append(f"Encrypted ZIP entries detected: {encrypted_entries}.")
        if skipped_entries > 0:
            notes.append(f"Entries skipped/unparsed: {skipped_entries}.")

        if not sections:
            content = "ZIP archive did not yield readable candidate entries."
        else:
            content = "ZIP entry extraction:\n" + "\n\n".join(sections)
        return ZipAIExtractionResult(
            success=True,
            content_block=content,
            notes=notes,
            processed_entries=processed_entries,
            encrypted_entries=encrypted_entries,
            skipped_entries=skipped_entries,
            error_message=None,
        )

