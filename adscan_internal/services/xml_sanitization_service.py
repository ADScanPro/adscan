"""Helpers for non-destructive XML sanitization during analysis.

The goal of this module is to improve parser-based tooling such as
``CredSweeper`` when XML files are almost-valid but contain bare ampersands
(``&``) that break XML parsing. Original evidence must remain untouched; any
sanitization only applies to temporary analysis copies.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from adscan_internal.services.smb_sensitive_file_policy import (
    SENSITIVE_FILE_WRAPPER_EXTENSIONS,
    resolve_effective_sensitive_extension,
)


_UNESCAPED_XML_AMPERSAND_PATTERN = re.compile(
    r"&(?!#\d+;|#x[0-9A-Fa-f]+;|[A-Za-z][A-Za-z0-9]+;)"
)
_ANALYSIS_SCRATCH_DIRNAME = ".adscan_analysis_tmp"
logger = logging.getLogger("adscan")


def contains_unescaped_xml_ampersand(text: str) -> bool:
    """Return whether XML-like text contains bare ampersands.

    Args:
        text: Raw XML text to inspect.

    Returns:
        ``True`` when at least one ``&`` is not already encoded as an entity.
    """
    return bool(_UNESCAPED_XML_AMPERSAND_PATTERN.search(str(text or "")))


def sanitize_xml_for_analysis(text: str) -> str:
    """Escape bare ampersands in XML-like text for parser-based analysis.

    Args:
        text: Raw XML text.

    Returns:
        Sanitized XML text safe for tolerant parser-based tooling.
    """
    return _UNESCAPED_XML_AMPERSAND_PATTERN.sub("&amp;", str(text or ""))


def build_sanitized_xml_analysis_copy(
    *,
    source_path: str,
    text: str,
    temp_root: Path,
) -> Path:
    """Write one sanitized XML analysis copy under ``temp_root``.

    The generated path always ends with ``.xml`` so downstream tools can treat
    wrapped names such as ``config.xml.bak`` as XML.

    Args:
        source_path: Original evidence path.
        text: Original XML text.
        temp_root: Temporary directory where the copy should be written.

    Returns:
        Path to the sanitized temporary XML copy.
    """
    original = Path(str(source_path or "input.xml"))
    file_name = original.name or "input.xml"
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", original.stem).strip("._") or "input"
    effective_suffix = resolve_effective_sensitive_extension(
        file_name,
        allowed_extensions={".xml"},
    )
    output_path = temp_root / f"{safe_stem}{effective_suffix or '.xml'}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(sanitize_xml_for_analysis(text), encoding="utf-8")
    return output_path


def create_analysis_temp_root(
    *,
    prefix: str,
    preferred_parent: Path | None = None,
) -> Path:
    """Create one temporary analysis directory, preferring a workspace-local parent."""
    if preferred_parent is not None:
        try:
            preferred_parent.mkdir(parents=True, exist_ok=True)
            if preferred_parent.is_dir():
                scratch_root = preferred_parent / _ANALYSIS_SCRATCH_DIRNAME
                scratch_root.mkdir(parents=True, exist_ok=True)
                if not os.access(scratch_root, os.W_OK | os.X_OK):
                    raise PermissionError(f"Scratch root is not writable: {scratch_root}")
                return Path(
                    tempfile.mkdtemp(
                        prefix=prefix,
                        dir=str(scratch_root),
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Falling back to system temporary directory for analysis scratch: "
                "preferred_parent=%s reason=%s",
                preferred_parent,
                exc,
                exc_info=True,
            )
    return Path(tempfile.mkdtemp(prefix=prefix))


def discover_malformed_xml_candidates(root: Path) -> list[Path]:
    """Find XML-like files under one directory that contain bare ampersands.

    Preference is given to ``ripgrep`` for fast candidate discovery. A Python
    fallback is used when ``rg`` is unavailable or when its execution fails.

    Args:
        root: Directory to inspect.

    Returns:
        List of original candidate paths.
    """
    if not root.exists() or not root.is_dir():
        return []

    candidates = _discover_with_ripgrep(root)
    if candidates is None:
        candidates = _discover_with_python(root)
    return candidates


def _discover_with_ripgrep(root: Path) -> list[Path] | None:
    """Use ``rg`` to shortlist XML-like files containing ampersands."""
    rg_path = shutil.which("rg")
    if not rg_path:
        return None

    globs = ["*.xml"] + [
        f"*.xml{wrapper}" for wrapper in SENSITIVE_FILE_WRAPPER_EXTENSIONS
    ]
    command = [
        rg_path,
        "-l",
        "-0",
    ]
    for pattern in globs:
        command.extend(["--iglob", pattern])
    command.extend(["&", str(root)])
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception:  # noqa: BLE001
        return None

    if completed.returncode not in {0, 1}:
        return None

    raw_paths = [item for item in completed.stdout.split(b"\x00") if item]
    candidates: list[Path] = []
    for raw_path in raw_paths:
        try:
            path = Path(raw_path.decode("utf-8", errors="replace"))
            if not path.is_file():
                continue
            if resolve_effective_sensitive_extension(
                path.name,
                allowed_extensions={".xml"},
            ) != ".xml":
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if contains_unescaped_xml_ampersand(text):
            candidates.append(path)
    return candidates


def _discover_with_python(root: Path) -> list[Path]:
    """Fallback XML candidate discovery using recursive Python traversal."""
    candidates: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if resolve_effective_sensitive_extension(
            path.name,
            allowed_extensions={".xml"},
        ) != ".xml":
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if contains_unescaped_xml_ampersand(text):
            candidates.append(path)
    return candidates


def build_sanitized_xml_overlay(
    *,
    candidate_paths: list[Path],
    temp_parent: Path | None = None,
) -> tuple[Path, dict[str, str]] | None:
    """Create one temporary overlay with sanitized XML files.

    Args:
        candidate_paths: Original XML paths that require sanitization.

    Returns:
        Tuple of ``(overlay_root, path_aliases)`` where ``path_aliases`` maps
        sanitized temporary paths back to original evidence paths.
    """
    if not candidate_paths:
        return None

    overlay_root = create_analysis_temp_root(
        prefix=".adscan_xml_overlay_",
        preferred_parent=temp_parent,
    )
    path_aliases: dict[str, str] = {}
    for index, original_path in enumerate(candidate_paths):
        try:
            text = original_path.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if not contains_unescaped_xml_ampersand(text):
            continue
        target_dir = overlay_root / f"{index:04d}"
        target_path = build_sanitized_xml_analysis_copy(
            source_path=str(original_path),
            text=text,
            temp_root=target_dir,
        )
        path_aliases[str(target_path)] = str(original_path)
    if not path_aliases:
        try:
            shutil.rmtree(overlay_root, ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass
        return None
    return overlay_root, path_aliases


__all__ = [
    "create_analysis_temp_root",
    "build_sanitized_xml_analysis_copy",
    "build_sanitized_xml_overlay",
    "contains_unescaped_xml_ampersand",
    "discover_malformed_xml_candidates",
    "sanitize_xml_for_analysis",
]
