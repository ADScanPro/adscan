"""Chromium engine — headless Playwright/Chromium renderer for full modern CSS.

The one PDF engine ADscan ships, for every tier. Templates can rely on the
whole modern print surface:
    - CSS grid / flex (full spec)
    - ``backdrop-filter``, ``filter``, ``mix-blend-mode``
    - The report faces shipped in ``report_design/_fonts`` (never a CDN)
    - CSS variables in all contexts
    - Page-break control via ``break-before`` / ``break-after`` / ``break-inside``
    - Repeating page headers/footers with page numbers, via the
      ``display_header_footer`` + ``header_template`` / ``footer_template``
      options (Chromium substitutes ``pageNumber`` / ``totalPages`` / ``date``
      / ``title`` / ``url`` spans inside those templates).

A render makes no outbound connection, whatever the deployment. Every request
the page issues is intercepted: the report faces are answered from the package
(see :mod:`adscan_internal.services.report_design.fonts`), anything else with a
network scheme is refused, and Chromium itself is launched with every host name
mapped to "not found", so not even a DNS prefetch leaves the machine. A template
that references an external resource therefore renders without it instead of
reaching the internet.

Requires the Playwright Python package + a Chromium browser to be installed.
Install with:

    pip install playwright
    playwright install chromium
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from adscan_core.rich_output import print_info_debug
from adscan_internal.services.report_design.fonts import (
    ENGINE_FONT_ORIGIN,
    OPTICAL_BINDER_JS,
    OPTICAL_LOADS_JS,
    OPTICAL_SIZE_AXES,
    resolve_engine_font_request,
    route_font_refs_to_engine,
)
from adscan_internal.services.report_engines.base import (
    EngineRenderError,
    ReportEngine,
    register_engine,
)

#: Chromium switches that keep the browser itself off the network. Requests the
#: page makes are already intercepted (see ``_PageRequestPolicy``); these cover
#: what interception does not see: host resolution (DNS prefetch, preconnect)
#: and a proxy picked up from the environment. Every Chromium the report
#: pipeline launches uses them (the attack-graph layout browser included).
OFFLINE_CHROMIUM_ARGS: tuple[str, ...] = (
    "--host-resolver-rules=MAP * ~NOTFOUND",
    "--no-proxy-server",
    "--disable-background-networking",
)

#: URL schemes that would leave the machine. Anything else (``data:``,
#: ``blob:``, ``about:``) stays in the page.
_NETWORK_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})


class _PageRequestPolicy:
    """Answers the report faces from the package and refuses every other fetch."""

    def __init__(self) -> None:
        self.refused: list[str] = []
        self.approximate_faces: set[str] = set()
        self.missing_faces: set[str] = set()

    def __call__(self, route: Any) -> None:
        url = str(route.request.url)
        if url.startswith(ENGINE_FONT_ORIGIN + "/"):
            answer = resolve_engine_font_request(url)
            if answer is None:
                self.missing_faces.add(url)
                route.fulfill(status=404, body=b"")
                return
            if not answer.exact:
                self.approximate_faces.add(url)
            route.fulfill(
                status=200,
                body=answer.body,
                headers={
                    "content-type": "font/woff2",
                    "access-control-allow-origin": "*",
                },
            )
            return
        scheme = url.split(":", 1)[0].lower()
        if scheme in _NETWORK_SCHEMES:
            self.refused.append(url)
            route.abort("blockedbyclient")
            return
        route.continue_()

    def report(self) -> None:
        """Say, at debug level, what the render could not have from the package."""
        if self.refused:
            hosts = sorted({u.split("/")[2] if "//" in u else u for u in self.refused})
            print_info_debug(
                f"Report render refused {len(self.refused)} external request(s) "
                f"(hosts: {', '.join(hosts)}); the document rendered without them."
            )
        if self.missing_faces:
            print_info_debug(
                f"Report render: {len(self.missing_faces)} face request(s) have no "
                "file in the font kit; those elements print in the next family of their stack."
            )
        if self.approximate_faces:
            print_info_debug(
                f"Report render: {len(self.approximate_faces)} optical size(s) have no "
                "exact instance in the font kit and use the nearest one; add them to "
                "scripts/build_report_fonts.py."
            )


#: How a document declares the scale it prints at:
#: ``<meta name="adscan-print-scale" content="0.8667">`` in its head. A document
#: composed on a canvas wider than its page's text block states the ratio here,
#: so every render of it (the deliverable, a test, a concatenated body) prints at
#: the same scale, instead of leaving Chromium to shrink the pages to whatever
#: happens to overflow. That shrink is silent and document-wide, and it is what
#: left the Security Assessment Report cover short of the sheet edges.
PRINT_SCALE_META = "adscan-print-scale"
_PRINT_SCALE_RE = re.compile(
    r"<meta\s+name=[\"']" + re.escape(PRINT_SCALE_META) + r"[\"']\s+content=[\"']([0-9.]+)[\"']",
    re.IGNORECASE,
)
#: Playwright's accepted range for ``page.pdf(scale=...)``.
_SCALE_RANGE = (0.1, 2.0)


def declared_print_scale(html_str: str) -> float | None:
    """Return the print scale a document declares in its head, if any.

    Only the head is read (the declaration must come before ``<body>``), and a
    value outside Playwright's range is ignored rather than clamped, so a typo
    cannot silently print a document at a tenth of its size.
    """
    head = html_str.split("<body", 1)[0]
    match = _PRINT_SCALE_RE.search(head)
    if not match:
        return None
    try:
        value = float(match.group(1))
    except ValueError:
        return None
    low, high = _SCALE_RANGE
    return value if low <= value <= high else None


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
        scale = declared_print_scale(html_str)
        if scale is not None:
            pdf_opts["scale"] = scale
        if options:
            pdf_opts.update(options)

        executable_path = os.environ.get("ADSCAN_CHROMIUM_EXECUTABLE") or None

        launch_kwargs: dict[str, Any] = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-dev-shm-usage", *OFFLINE_CHROMIUM_ARGS],
        }
        if executable_path:
            launch_kwargs["executable_path"] = executable_path

        requests = _PageRequestPolicy()
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(**launch_kwargs)
                try:
                    context = browser.new_context()
                    page = context.new_page()
                    page.route("**/*", requests)

                    base_url_str = str(base_url) if base_url is not None else None
                    page.set_content(
                        route_font_refs_to_engine(html_str),
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
                    # After the print media is in force: a print rule may set a
                    # different size, and the optical size follows the size.
                    _bind_optical_sizes(page)
                    pdf_bytes: bytes = page.pdf(**pdf_opts)
                finally:
                    browser.close()
        except Exception as exc:
            raise EngineRenderError(f"Chromium render failed: {exc}") from exc
        finally:
            requests.report()

        return pdf_bytes


def _bind_optical_sizes(page: Any) -> None:
    """Draw each optical-family element from the static instance for its size.

    See :data:`~adscan_internal.services.report_design.fonts.OPTICAL_BINDER_JS`.
    Best-effort by design: if binding fails the document still prints, in the
    base instance of each face, which is the behaviour before binding existed.
    """
    try:
        bound = page.evaluate(
            OPTICAL_BINDER_JS,
            {
                "axes": {family: list(axis) for family, axis in OPTICAL_SIZE_AXES.items()},
                "origin": ENGINE_FONT_ORIGIN,
            },
        )
        failed = page.evaluate(OPTICAL_LOADS_JS, list(bound.get("loads") or []))
    except Exception as exc:  # noqa: BLE001 - typography must never fail a render
        print_info_debug(f"Report render: optical-size binding skipped ({type(exc).__name__}: {exc}).")
        return
    print_info_debug(
        f"Report render: bound {bound.get('elements', 0)} element(s) and "
        f"{bound.get('pseudos', 0)} pseudo-element(s) to "
        f"{bound.get('families', 0)} optical size(s)."
    )
    if failed:
        print_info_debug(f"Report render: {len(failed)} face(s) failed to load: {', '.join(sorted(failed)[:6])}")
