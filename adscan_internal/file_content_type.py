"""Global helpers to classify file content from bytes.

These helpers avoid extension-only decisions and keep file-type detection
consistent across ADscan features.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import codecs
import io
import zipfile


@dataclass(frozen=True)
class FileContentTypeInfo:
    """Detected content type based on byte-level inspection."""

    kind: str
    reason: str


def detect_file_content_type(*, file_bytes: bytes) -> FileContentTypeInfo:
    """Classify bytes into empty/text/binary/zip_archive.

    Detection strategy:
    1. Empty stream guard.
    2. ZIP detection from bytes.
    3. MIME detection via libmagic/python-magic (when available).
    4. Heuristic fallback from byte/text analysis.
    """
    if not file_bytes:
        return FileContentTypeInfo(kind="empty", reason="byte stream is empty")

    if _is_zip_archive(file_bytes):
        return FileContentTypeInfo(kind="zip_archive", reason="zip magic/header detected")

    mime_info = _classify_with_libmagic_mime(file_bytes=file_bytes)
    if mime_info is not None:
        return mime_info

    text_eval = _evaluate_text_likelihood(file_bytes)
    if text_eval.is_text:
        return FileContentTypeInfo(kind="text", reason=text_eval.reason)

    return FileContentTypeInfo(kind="binary", reason=text_eval.reason)


@dataclass(frozen=True)
class _TextEvaluation:
    is_text: bool
    reason: str


def _evaluate_text_likelihood(file_bytes: bytes) -> _TextEvaluation:
    """Evaluate if bytes are likely plain text using byte-pattern heuristics."""
    sample = file_bytes[:65536]
    if not sample:
        return _TextEvaluation(is_text=True, reason="empty sample")

    bom_eval = _evaluate_bom_text(sample)
    if bom_eval is not None:
        return bom_eval

    binary_magic = _detect_binary_magic(sample)
    if binary_magic:
        return _TextEvaluation(
            is_text=False, reason=f"binary magic detected: {binary_magic}"
        )

    # NUL bytes strongly indicate binary formats.
    if b"\x00" in sample:
        return _TextEvaluation(
            is_text=False,
            reason="contains NUL bytes in sampled payload",
        )

    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        decoded = sample.decode("utf-8", errors="replace")

    if not decoded:
        return _TextEvaluation(is_text=True, reason="decoded to empty text")

    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded)
    printable_ratio = printable / max(1, len(decoded))

    # Text-like payloads are mostly printable characters/newlines/tabs.
    if printable_ratio >= 0.85:
        return _TextEvaluation(
            is_text=True,
            reason=f"printable_ratio={printable_ratio:.2f} (>=0.85)",
        )

    return _TextEvaluation(
        is_text=False,
        reason=f"printable_ratio={printable_ratio:.2f} (<0.85)",
    )


def _is_zip_archive(file_bytes: bytes) -> bool:
    """Return True when byte stream appears to be a valid ZIP archive."""
    try:
        return zipfile.is_zipfile(io.BytesIO(file_bytes))
    except Exception:
        return False


def _evaluate_bom_text(sample: bytes) -> _TextEvaluation | None:
    """Detect text streams that use BOM-prefixed encodings."""
    bom_encodings = (
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
    )
    for bom, encoding in bom_encodings:
        if not sample.startswith(bom):
            continue
        try:
            decoded = sample.decode(encoding, errors="replace")
        except Exception:  # noqa: BLE001
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded)
        ratio = printable / max(1, len(decoded))
        if ratio >= 0.7:
            return _TextEvaluation(
                is_text=True,
                reason=f"text BOM detected ({encoding}), printable_ratio={ratio:.2f}",
            )
        return _TextEvaluation(
            is_text=False,
            reason=f"BOM detected ({encoding}) but low printable_ratio={ratio:.2f}",
        )
    return None


def _classify_with_libmagic_mime(*, file_bytes: bytes) -> FileContentTypeInfo | None:
    """Classify content using MIME detected by libmagic/python-magic."""
    mime = _detect_mime_via_libmagic(file_bytes=file_bytes)
    if not mime:
        return None
    if mime == "application/zip":
        return FileContentTypeInfo(
            kind="zip_archive",
            reason=f"libmagic mime={mime}",
        )
    if _is_text_mime(mime):
        return FileContentTypeInfo(kind="text", reason=f"libmagic mime={mime}")
    if _is_binary_mime(mime):
        return FileContentTypeInfo(kind="binary", reason=f"libmagic mime={mime}")
    return None


def _is_text_mime(mime: str) -> bool:
    """Return True when MIME reliably indicates text payload."""
    if mime.startswith("text/"):
        return True
    text_like = {
        "application/json",
        "application/xml",
        "application/yaml",
        "application/x-yaml",
        "application/toml",
        "application/x-sh",
        "application/javascript",
        "application/x-javascript",
        "application/sql",
    }
    if mime in text_like:
        return True
    return mime.endswith("+json") or mime.endswith("+xml")


def _is_binary_mime(mime: str) -> bool:
    """Return True when MIME reliably indicates binary payload."""
    if mime.startswith(("image/", "audio/", "video/", "font/", "model/")):
        return True
    binary_like_exact = {
        "application/pdf",
        "application/octet-stream",
        "application/x-dosexec",
        "application/x-executable",
        "application/x-archive",
    }
    if mime in binary_like_exact:
        return True
    # Office/OpenXML and many vendor MIME types are binary containers.
    if "officedocument" in mime:
        return True
    if mime.startswith("application/vnd.ms-"):
        return True
    if mime.startswith("application/vnd.openxmlformats-"):
        return True
    return False


def _detect_mime_via_libmagic(*, file_bytes: bytes) -> str:
    """Return MIME from libmagic when available; otherwise empty string."""
    try:
        detector = _get_libmagic_detector()
    except Exception:  # noqa: BLE001
        return ""
    sample = file_bytes[:262144]
    try:
        mime = detector.from_buffer(sample)
    except Exception:  # noqa: BLE001
        return ""
    if not isinstance(mime, str):
        return ""
    return mime.strip().lower()


@lru_cache(maxsize=1)
def _get_libmagic_detector():  # noqa: ANN201
    """Return cached libmagic detector instance (python-magic wrapper)."""
    import magic  # type: ignore

    return magic.Magic(mime=True)


def _detect_binary_magic(sample: bytes) -> str:
    """Return binary signature label when known magic bytes are detected."""
    signatures = (
        (b"%PDF-", "pdf"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"GIF87a", "gif"),
        (b"GIF89a", "gif"),
        (b"\x7fELF", "elf"),
        (b"MZ", "pe"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole-cfb"),
    )
    for magic, label in signatures:
        if sample.startswith(magic):
            return label
    return ""
