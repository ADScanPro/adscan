"""Extract normalized text content from SMB file byte streams for AI analysis.

This service keeps file parsing deterministic in ADscan (instead of delegating
binary decoding to the model) and provides one normalized content block string
that can be embedded in AI prompts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
import base64
import importlib
import os

from adscan_internal.file_content_type import detect_file_content_type
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.zip_processing_service import ZipProcessingService


@dataclass(frozen=True)
class ShareFileContentExtractionResult:
    """Normalized extraction output to feed file-analysis prompts."""

    success: bool
    mode: str
    content_block: str
    notes: list[str]
    truncated: bool
    error_message: str | None = None


class ShareFileContentExtractionService(BaseService):
    """Extract prompt-ready text from plain text, documents, and ZIP archives."""

    def __init__(self) -> None:
        super().__init__()
        self._zip_service = ZipProcessingService()

    def extract_for_ai(
        self,
        *,
        source_path: str | None = None,
        remote_path: str | None = None,
        file_bytes: bytes,
        truncated: bool,
        max_bytes: int,
    ) -> ShareFileContentExtractionResult:
        """Extract content from one SMB file stream for AI analysis."""
        effective_source_path = str(source_path or remote_path or "").strip()
        if not file_bytes:
            return ShareFileContentExtractionResult(
                success=True,
                mode="empty",
                content_block="File byte stream is empty.",
                notes=[],
                truncated=truncated,
            )

        detection = detect_file_content_type(file_bytes=file_bytes)
        if detection.kind == "zip_archive":
            return self._extract_zip_content(
                source_path=effective_source_path,
                file_bytes=file_bytes,
                truncated=truncated,
                max_bytes=max_bytes,
            )

        if detection.kind == "text":
            return self._extract_plain_text(
                file_bytes=file_bytes,
                truncated=truncated,
                detection_reason=detection.reason,
            )

        return self._extract_binary_document(
            source_path=effective_source_path,
            file_bytes=file_bytes,
            truncated=truncated,
            detection_reason=detection.reason,
        )

    def _extract_plain_text(
        self,
        *,
        file_bytes: bytes,
        truncated: bool,
        detection_reason: str,
    ) -> ShareFileContentExtractionResult:
        """Decode plain-text files directly with UTF-8 replacement strategy."""
        text = file_bytes.decode("utf-8", errors="replace")
        snippet = text[:20000]
        note = (
            f"Plain-text snippet truncated to {len(snippet)} chars."
            if len(text) > len(snippet)
            else "Plain-text decoding completed."
        )
        return ShareFileContentExtractionResult(
            success=True,
            mode="plain_text",
            content_block="Plain-text content:\n" + snippet,
            notes=[f"Content detector: {detection_reason}.", note],
            truncated=truncated,
        )

    def _extract_binary_document(
        self,
        *,
        source_path: str,
        file_bytes: bytes,
        truncated: bool,
        detection_reason: str,
    ) -> ShareFileContentExtractionResult:
        """Extract text from one binary document using MarkItDown."""
        converted = self._convert_bytes_with_markitdown(
            file_bytes=file_bytes,
            suffix=Path(source_path).suffix.lower(),
        )
        if converted:
            snippet = converted[:22000]
            notes: list[str] = ["Extracted with MarkItDown."]
            notes.insert(0, f"Content detector: {detection_reason}.")
            if len(converted) > len(snippet):
                notes.append(
                    f"Converted markdown truncated to {len(snippet)} chars for prompt."
                )
            return ShareFileContentExtractionResult(
                success=True,
                mode="markitdown",
                content_block="Converted document content:\n" + snippet,
                notes=notes,
                truncated=truncated,
            )

        return ShareFileContentExtractionResult(
            success=True,
            mode="binary_fallback",
            content_block=self._build_binary_fallback_block(file_bytes=file_bytes),
            notes=[
                f"Content detector: {detection_reason}.",
                "MarkItDown conversion failed or unavailable; using base64 fallback."
            ],
            truncated=truncated,
        )

    def _extract_zip_content(
        self,
        *,
        source_path: str,
        file_bytes: bytes,
        truncated: bool,
        max_bytes: int,
    ) -> ShareFileContentExtractionResult:
        """Extract textual candidates from ZIP archive entries."""
        zip_max_entries = self._resolve_zip_max_entries()
        zip_max_chars = self._resolve_zip_max_chars()
        zip_result = self._zip_service.extract_for_ai_from_bytes(
            file_bytes=file_bytes,
            max_entry_bytes=min(max_bytes, 2 * 1024 * 1024),
            max_entries=zip_max_entries,
            max_chars=zip_max_chars,
            binary_entry_converter=lambda payload, suffix: self._convert_bytes_with_markitdown(
                file_bytes=payload,
                suffix=suffix,
            ),
        )
        if not zip_result.success:
            notes = [zip_result.error_message or "ZIP extraction failed."]
            if truncated:
                notes.append(f"Archive byte stream truncated to first {max_bytes} bytes.")
            return ShareFileContentExtractionResult(
                success=True,
                mode="zip_invalid_fallback",
                content_block=self._build_binary_fallback_block(file_bytes=file_bytes),
                notes=notes,
                truncated=truncated,
            )

        notes = list(zip_result.notes)
        if truncated:
            notes.append(f"Archive byte stream truncated to first {max_bytes} bytes.")

        mode = "zip_entries"
        if (
            zip_result.processed_entries == 0
            or "did not yield readable candidate entries" in zip_result.content_block
        ):
            mode = "zip_metadata_only"
        return ShareFileContentExtractionResult(
            success=True,
            mode=mode,
            content_block=zip_result.content_block.replace(
                "ZIP archive did not yield readable candidate entries.",
                f"ZIP archive {source_path} did not yield readable candidate entries.",
            ),
            notes=notes,
            truncated=truncated,
        )

    def _convert_bytes_with_markitdown(self, *, file_bytes: bytes, suffix: str) -> str:
        """Convert arbitrary file bytes to markdown text using MarkItDown."""
        try:
            markitdown_module = importlib.import_module("markitdown")
            markitdown_cls = getattr(markitdown_module, "MarkItDown", None)
            if markitdown_cls is None:
                return ""
        except Exception:
            return ""

        temp_path: str | None = None
        try:
            with NamedTemporaryFile(delete=False, suffix=suffix or ".bin") as handle:
                handle.write(file_bytes)
                handle.flush()
                temp_path = handle.name
            converter = markitdown_cls(enable_plugins=False)
            result = converter.convert(temp_path)
            text_content = getattr(result, "text_content", "")
            if isinstance(text_content, str):
                return text_content.strip()
            return str(text_content).strip()
        except Exception:
            return ""
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except Exception:  # noqa: BLE001
                    pass

    @staticmethod
    def _build_binary_fallback_block(*, file_bytes: bytes) -> str:
        """Fallback serializer when extraction cannot produce readable text."""
        encoded = base64.b64encode(file_bytes).decode("ascii")
        return "Binary content (base64):\n" + encoded[:16000]

    @staticmethod
    def _resolve_zip_max_entries() -> int:
        """Read max ZIP entries to inspect for one archive."""
        raw = os.getenv("ADSCAN_AI_ZIP_MAX_ENTRIES", "12").strip()
        try:
            value = int(raw)
        except ValueError:
            return 12
        return max(1, min(value, 50))

    @staticmethod
    def _resolve_zip_max_chars() -> int:
        """Read max characters to include from one ZIP extraction prompt block."""
        raw = os.getenv("ADSCAN_AI_ZIP_MAX_CHARS", "22000").strip()
        try:
            value = int(raw)
        except ValueError:
            return 22000
        return max(4000, min(value, 120000))
