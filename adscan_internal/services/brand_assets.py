"""Shared brand-asset resolution for every ADscan deliverable.

Per CLAUDE.md § "Dual-tier reporting — share the DATA, not the TEMPLATES":
**brand tokens are shared between tiers, templates are not.** The LITE HTML
exposure report and the PRO Client Deliverable Kit render completely different
page structures, but they must use the SAME logo, so a reader who receives the
free report and later sees the paid PDF recognises the same product. The LITE
report is the artifact that circulates, and every forward is a brand impression.

This module is the single source of truth for reading an asset out of the
canonical logos home ``adscan_internal/assets/logos/``. It owns the search-root
discipline (module-relative first, then the PyInstaller ``_MEIPASS`` bundle
root) so no consumer re-implements it and a brand refresh is one asset swap.

Three output shapes, because the consumers need different things:

* :func:`brand_logo_svg_markup` — the raw ``<svg>…</svg>`` element, for a
  self-contained HTML file that must carry no external references and no
  base64 bloat (the LITE exposure report).
* :func:`brand_logo_svg_data_uri` — the same VECTOR master logo as a ``data:``
  URI for an ``<img src>``. For a document whose CSS already sizes an ``<img>``
  (the PRO deliverable's cover): it stays sharp at any print size and drops in
  without the extra ``svg`` selectors an inline element would need.
* :func:`brand_logo_data_uri` — the raster wordmark PNG as a ``data:`` URI, for
  the consumers already built on it (the bonus documents, the cheatsheet).

Variant naming follows the asset files and is about the BACKGROUND the mark
sits on, not the ink: ``"dark"`` is the white-ink mark FOR a dark background,
``"light"`` is the charcoal-ink mark FOR light paper. **This is the inverse of
the ink-named vocabulary** ``report_design.wordmark_variant_for_theme`` returns,
so resolve a theme through :func:`brand_variant_for_theme` rather than passing
that value straight in. Every caller keeps a text fallback: the logo is
cosmetic and a missing asset must never break a render.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

from adscan_core import telemetry
from adscan_core.rich_output import print_exception

#: Wordmark PNGs — for the Chromium/PDF bake (``<img src>`` data-URI).
BRAND_WORDMARK_FILENAMES: dict[str, str] = {
    # Charcoal ink for LIGHT paper themes (the deliverable default).
    "light": "logo-wordmark-dark.png",
    # White ink for a DARK band.
    "dark": "logo-wordmark.png",
}

#: Master logo SVGs — for inline embedding in a self-contained HTML file.
#: ``logo-master-dark.svg`` is white ink + the bright teal accent (#1AA0AE),
#: which is the variant that reads correctly on the deep-teal brand cover.
#: ``logo-master-light.svg`` is charcoal ink + #0E6E78 for light backgrounds.
BRAND_MASTER_SVG_FILENAMES: dict[str, str] = {
    "dark": "logo-master-dark.svg",
    "light": "logo-master-light.svg",
}

#: Favicon SVGs — the browser-tab mark for an HTML deliverable. Same
#: background-naming: ``"light"`` is the charcoal + #0E6E78 mark for a light
#: tab strip, ``"dark"`` is the white + #1AA0AE mark for a dark one.
BRAND_FAVICON_FILENAMES: dict[str, str] = {
    "light": "logo-favicon-light.svg",
    "dark": "logo-favicon-dark.svg",
}

_ASSET_CACHE: dict[str, bytes | None] = {}


def _read_brand_asset(filename: str) -> bytes | None:
    """Read one file from the canonical logos home, or ``None``.

    The ONLY search discipline in the codebase — ``report_service`` used to
    carry a second copy that also reached for a developer's local vault, which
    could have put a stray asset on a client deliverable. Roots, in order:

    1. **Module-relative** — ``brand_assets.py`` → ``services/`` →
       ``adscan_internal/`` → ``assets/logos/``. Correct in source mode, in the
       LITE image, and in the PyInstaller-unpacked tree (the binary unpacks
       ``assets/logos`` into its tree via the ``--add-data`` line in
       ``build_adscan.sh`` / ``adscan.spec``).
    2. **PyInstaller ``_MEIPASS`` bundle root** — defensive fallback.

    Result is cached per filename (including a ``None`` miss) so a render that
    stamps the logo on several sections pays one stat call.

    Args:
        filename: Bare filename inside ``adscan_internal/assets/logos/``.

    Returns:
        The file bytes, or ``None`` when the asset cannot be read. Never raises.
    """
    if filename in _ASSET_CACHE:
        return _ASSET_CACHE[filename]

    raw: bytes | None = None
    try:
        candidate = Path(__file__).parent.parent / "assets" / "logos" / filename
        try:
            if candidate.is_file():
                raw = candidate.read_bytes()
        except OSError:
            raw = None
        if raw is None:
            meipass = getattr(sys, "_MEIPASS", None)
            if meipass:
                bundled = (
                    Path(meipass) / "adscan_internal" / "assets" / "logos" / filename
                )
                try:
                    if bundled.is_file():
                        raw = bundled.read_bytes()
                except OSError:
                    raw = None
    except Exception as exc:  # noqa: BLE001 — logo is cosmetic; never break a render
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        raw = None

    _ASSET_CACHE[filename] = raw
    return raw


def brand_logo_svg_markup(variant: str = "dark") -> str:
    """Return the ADscan master logo as an inline ``<svg>`` element.

    For a self-contained HTML deliverable: the markup is embedded directly, so
    the file carries no external reference and no base64 payload.

    Args:
        variant: ``"dark"`` for the white-ink mark on a dark background (the
            brand cover), ``"light"`` for the charcoal-ink mark on light paper.

    Returns:
        The ``<svg>…</svg>`` source, or ``""`` when the asset is unavailable
        (callers render their text wordmark fallback instead).
    """
    filename = BRAND_MASTER_SVG_FILENAMES.get(
        variant, BRAND_MASTER_SVG_FILENAMES["dark"]
    )
    raw = _read_brand_asset(filename)
    if raw is None:
        return ""
    try:
        markup = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return ""
    # Drop an XML prolog / doctype if the asset ever gains one: an inline SVG
    # inside an HTML body must start at the <svg> element.
    start = markup.find("<svg")
    return markup[start:] if start > 0 else markup


def brand_variant_for_theme(theme_name: str | None) -> str:
    """Resolve a report theme to this module's BACKGROUND-named variant.

    The one place the naming inversion is handled. ``report_design`` decides
    whether a theme renders on dark paper (the SSOT, keyed on the *rendered*
    background rather than the theme's name — ``premium_dark`` is a misnomer
    and renders warm-bone light); this translates that verdict into the
    ``"dark"`` / ``"light"`` vocabulary the asset filenames use.

    Args:
        theme_name: A report theme, or ``None`` for the light default.

    Returns:
        ``"dark"`` (white-ink mark, for a dark page) or ``"light"``
        (charcoal-ink mark, for light paper).
    """
    from adscan_internal.services.report_design import (  # noqa: PLC0415
        theme_background_is_dark,
    )

    return "dark" if theme_background_is_dark(theme_name) else "light"


def brand_logo_svg_data_uri(variant: str = "light") -> str:
    """Return the ADscan master logo as an SVG ``data:`` URI for an ``<img>``.

    The vector counterpart to :func:`brand_logo_data_uri`, for a document that
    already sizes its mark through CSS on an ``<img>`` element. Vector matters
    here: a print deliverable's cover mark is the first thing a reader sees at
    full page size, and a raster wordmark scaled to it prints visibly soft.

    Args:
        variant: ``"light"`` (charcoal ink for light paper — the deliverable
            default) or ``"dark"`` (white ink for a dark page). Resolve a theme
            through :func:`brand_variant_for_theme`; do not pass an ink-named
            value straight in.

    Returns:
        ``data:image/svg+xml;base64,…``, or ``""`` when the asset is
        unavailable (callers render their text wordmark fallback instead).
    """
    filename = BRAND_MASTER_SVG_FILENAMES.get(
        variant, BRAND_MASTER_SVG_FILENAMES["light"]
    )
    raw = _read_brand_asset(filename)
    if raw is None:
        return ""
    return f"data:image/svg+xml;base64,{base64.b64encode(raw).decode('ascii')}"


def brand_logo_data_uri(variant: str = "light") -> str:
    """Return the ADscan wordmark as a base64 PNG ``data:`` URI.

    For the Chromium/PDF bake, where a data-URI is the render-time-robust
    option: the bytes travel inside the HTML so there is no path to resolve
    when the renderer runs.

    Args:
        variant: ``"light"`` (charcoal ink for light paper — the deliverable
            default) or ``"dark"`` (white ink for a dark band).

    Returns:
        ``data:image/png;base64,…``, or ``""`` when the asset is unavailable.
    """
    filename = BRAND_WORDMARK_FILENAMES.get(variant, BRAND_WORDMARK_FILENAMES["light"])
    raw = _read_brand_asset(filename)
    if raw is None:
        return ""
    return f"data:image/png;base64,{base64.b64encode(raw).decode('ascii')}"


def brand_favicon_data_uri(variant: str = "light") -> str:
    """Return the ADscan favicon as an SVG ``data:`` URI for ``<link rel=icon>``.

    An HTML deliverable gets opened in a browser and forwarded, so the tab must
    read as ADscan rather than as a generic document.

    Args:
        variant: ``"light"`` (charcoal + #0E6E78, for a light tab strip — the
            default) or ``"dark"`` (white + #1AA0AE).

    Returns:
        ``data:image/svg+xml;base64,…``, or ``""`` when unavailable (the caller
        simply omits the ``<link>``).
    """
    filename = BRAND_FAVICON_FILENAMES.get(variant, BRAND_FAVICON_FILENAMES["light"])
    raw = _read_brand_asset(filename)
    if raw is None:
        return ""
    return f"data:image/svg+xml;base64,{base64.b64encode(raw).decode('ascii')}"


__all__ = (
    "BRAND_FAVICON_FILENAMES",
    "BRAND_MASTER_SVG_FILENAMES",
    "BRAND_WORDMARK_FILENAMES",
    "brand_favicon_data_uri",
    "brand_logo_data_uri",
    "brand_logo_svg_data_uri",
    "brand_logo_svg_markup",
    "brand_variant_for_theme",
)
