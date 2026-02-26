"""Template path utilities for report generation."""

from __future__ import annotations

import os
import sys
from typing import Optional

from adscan_internal import print_info_debug
from adscan_internal.rich_output import mark_sensitive


def _get_docx_path(docx_name: str) -> Optional[str]:
    """Get the path to a bundled DOCX by name."""
    if not docx_name:
        return None

    searched_paths: list[str] = []

    # Check if running in PyInstaller bundle
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass = getattr(sys, "_MEIPASS", None)  # type: ignore[attr-defined]
        if meipass:
            docx_path = os.path.join(meipass, docx_name)
            searched_paths.append(docx_path)
            if os.path.exists(docx_path):
                return docx_path
            docx_path = os.path.join(meipass, "templates", docx_name)
            searched_paths.append(docx_path)
            if os.path.exists(docx_path):
                return docx_path

    # Development mode: check in templates/ directory first
    current_file = os.path.abspath(__file__)
    project_root = os.path.dirname(os.path.dirname(current_file))
    docx_path = os.path.join(project_root, "templates", docx_name)
    searched_paths.append(docx_path)
    if os.path.exists(docx_path):
        return docx_path

    # Fallback: check in project root (legacy location)
    docx_path = os.path.join(project_root, docx_name)
    searched_paths.append(docx_path)
    if os.path.exists(docx_path):
        return docx_path

    print_info_debug(
        "[template] missing template asset: "
        f"{mark_sensitive(docx_name, 'path')}"
    )
    if searched_paths:
        formatted = ", ".join(mark_sensitive(p, "path") for p in searched_paths)
        print_info_debug(f"[template] searched paths: {formatted}")
    return None


def get_template_path() -> Optional[str]:
    """Get the path to the Word template file.

    Handles both PyInstaller bundle (sys._MEIPASS) and development mode.
    The template is bundled with PyInstaller using --add-data.

    Search order:
    1. PyInstaller bundle (_MEIPASS)
    2. templates/ directory (development mode)
    3. Project root (legacy location)

    Returns:
        str: Path to template.docx, or None if not found
    """
    return _get_docx_path("template.docx")


def get_cover_path() -> Optional[str]:
    """Get the path to the Word cover template, if available."""
    return _get_docx_path("cover.docx")
