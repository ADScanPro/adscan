"""Chromium engine — headless Playwright/Chromium renderer for full modern CSS.

The one PDF engine ADscan ships, for every tier. Templates can rely on the
whole modern print surface:
    - CSS grid / flex (full spec)
    - ``backdrop-filter``, ``filter``, ``mix-blend-mode``
    - Web fonts loaded from CDN or local files
    - CSS variables in all contexts
    - Page-break control via ``break-before`` / ``break-after`` / ``break-inside``
    - Repeating page headers/footers with page numbers, via the
      ``display_header_footer`` + ``header_template`` / ``footer_template``
      options (Chromium substitutes ``pageNumber`` / ``totalPages`` / ``date``
      / ``title`` / ``url`` spans inside those templates).

Requires the Playwright Python package + a Chromium browser to be installed.
Install with:

    pip install playwright
    playwright install chromium
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from adscan_internal.services.report_engines.base import (
    EngineRenderError,
    ReportEngine,
    register_engine,
)


_DEFAULT_PDF_OPTIONS: dict[str, Any] = {
    "format": "A4",
    "print_background": True,
    "margin": {"top": "14mm", "right": "15mm", "bottom": "20mm", "left": "15mm"},
    "prefer_css_page_size": True,
    "display_header_footer": False,
}


@register_engine
class ChromiumEngine(ReportEngine):
    """Headless Chromium → PDF engine via Playwright (sync API)."""

    name = "chromium"

    def is_available(self) -> tuple[bool, str]:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError as exc:
            return False, (
                f"playwright not importable ({exc}). "
                "Install with: pip install playwright && playwright install chromium"
            )
        return True, ""

    def render_pdf(
        self,
        html_str: str,
        *,
        base_url: str | Path | None = None,
        options: dict[str, Any] | None = None,
    ) -> bytes:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise EngineRenderError(
                "Playwright is required for the chromium engine. "
                "Install with: pip install playwright && playwright install chromium"
            ) from exc

        pdf_opts: dict[str, Any] = dict(_DEFAULT_PDF_OPTIONS)
        if options:
            pdf_opts.update(options)

        executable_path = os.environ.get("ADSCAN_CHROMIUM_EXECUTABLE") or None

        launch_kwargs: dict[str, Any] = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-dev-shm-usage"],
        }
        if executable_path:
            launch_kwargs["executable_path"] = executable_path

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(**launch_kwargs)
                try:
                    context = browser.new_context()
                    page = context.new_page()

                    base_url_str = str(base_url) if base_url is not None else None
                    page.set_content(
                        html_str,
                        wait_until="networkidle",
                        timeout=60_000,
                    )
                    if base_url_str:
                        page.evaluate(
                            "(url) => { const b = document.querySelector('base'); "
                            "if (b) b.href = url; else { "
                            "const nb = document.createElement('base'); nb.href = url; "
                            "document.head.prepend(nb); } }",
                            base_url_str,
                        )

                    # Wait briefly for any in-page JS (e.g. Cytoscape) to finish layout.
                    try:
                        page.wait_for_function(
                            "() => document.readyState === 'complete' && "
                            "(!window.__adscanReportReady || window.__adscanReportReady === true)",
                            timeout=15_000,
                        )
                    except Exception:
                        pass

                    page.emulate_media(media="print")
                    pdf_bytes: bytes = page.pdf(**pdf_opts)
                finally:
                    browser.close()
        except Exception as exc:
            raise EngineRenderError(f"Chromium render failed: {exc}") from exc

        return pdf_bytes
