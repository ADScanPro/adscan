"""HTML → PDF render engines, shared by every ADscan tier.

This package is *infrastructure*, not intellectual property: it owns the
mechanics of turning an already-rendered HTML string into PDF bytes (the
Chromium/Playwright invocation, page format, margins, background printing,
``prefer_css_page_size``, header/footer templates, error handling). Nothing
here knows what a finding or an attack path is.

That is why it lives under ``adscan_internal/services/`` and not under
``adscan_internal/pro/``: both the LITE exposure report and the PRO Client
Deliverable Kit render through it, so a pagination, font or Chromium-flag bug
is fixed once. The *templates* stay separate per tier — that is the layer that
genuinely differs — but the engine underneath them is one implementation.

It is not in ``adscan_core`` either: ``adscan_core`` is the dependency-light
primitive layer safe to distribute anywhere, and Playwright is neither light
nor a primitive. The Playwright import is deliberately lazy (inside the render
method), so importing this package costs nothing when no PDF is produced.

The only registered implementation is:
    - ``chromium``: Playwright-driven headless Chromium, full modern CSS.

Importing this package registers the built-in engines, so a caller only needs::

    from adscan_internal.services.report_engines import get_engine

    pdf_bytes = get_engine("chromium").render_pdf(html_str)
"""

from adscan_internal.services.report_engines.base import (
    ReportEngine,
    EngineRenderError,
    get_engine,
    list_engines,
    register_engine,
)

# Imported for its side effect: the ``@register_engine`` decorator populates the
# registry. Doing it here rather than at each call site means ``get_engine``
# always resolves the built-ins, whichever tier imported the package.
from adscan_internal.services.report_engines import (  # noqa: F401  (registration)
    chromium_engine as _chromium_engine,
)

__all__ = [
    "ReportEngine",
    "EngineRenderError",
    "get_engine",
    "list_engines",
    "register_engine",
]
