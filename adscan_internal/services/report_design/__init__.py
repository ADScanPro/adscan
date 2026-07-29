"""ADscan report design system — the shared visual layer for every tier.

This is layer 3 of the four-layer reporting split (see ``CLAUDE.md`` §
"Dual-tier reporting"): data SHARED, render engine SHARED, **design system
SHARED**, document composition SEPARATE.

What lives here
---------------
How ADscan *looks*, expressed once:

``_css/tokens_<theme>.css``
    The token vocabulary of one theme — colour ramps, the severity scale, the
    type stacks, radii, the bonus-document token bridge and the OKLCH
    refinement layer. Nothing but custom properties.
``_css/webfonts_<theme>.css``
    The theme's web-font ``@import``. Opt-in, because an artifact that must be
    self-contained (the LITE ``.html``) may not fetch anything at view time.
``_css/defaults.css``
    The token floor a document renders on before any theme is applied, so a
    template is never token-less.
``_css/foundation.css``
    The reset, the base type, and the tabular-figure rule every numeric
    surface needs.
``_css/components.css``
    The component grammar both documents draw on: severity chips, the
    proportional severity bar and its legend, the hairline table, the eyebrow,
    the figure ledger, the note, the numbered step list.
``_css/print.css``
    Page-break control and the print rules a paginated document needs.

What does NOT live here
-----------------------
Document *composition*: which sections a document has, in what order, its
cover, its page furniture, its ``@page`` geometry, and any styling that only
makes sense for one document. PRO keeps that under
``adscan_internal/pro/reporting/templates`` + ``themes``; LITE keeps it in its
own template.

Two rules keep the shared layer safe to change
----------------------------------------------
1. A rule that PRO's markup already relies on is carried here **verbatim**, so
   moving it cannot change the paid deliverable.
2. A rule that is new (or would alter PRO's existing render) is scoped under
   the opt-in document class ``.ds-doc``. LITE sets it on ``<body>``; PRO does
   not. That is how a new component can be authored once, today, without
   touching the revenue artifact — PRO opts in when its composition is
   reworked, not before.

The package is LITE-safe: it imports nothing from ``adscan_internal.pro`` and
nothing beyond the standard library.
"""

from __future__ import annotations

from importlib.resources import files

_CSS_PACKAGE = "adscan_internal.services.report_design._css"

#: Themes that ship a token file. ``editorial`` is the house style — warm bone
#: paper, Fraunces display, one deep-teal accent — and the default for any new
#: surface. ``corporate_light`` is the white/navy auditor variant;
#: ``premium_dark`` is the (misnamed, actually light) bonus-document theme.
DESIGN_THEMES: tuple[str, ...] = ("editorial", "corporate_light", "premium_dark")

DEFAULT_THEME = "editorial"

#: The non-theme layers a caller gets by default, in cascade order.
DESIGN_LAYERS: tuple[str, ...] = ("foundation", "components", "print")

#: Every layer that can be requested. ``defaults`` is opt-in: it is the token
#: floor for a document that may render with no theme selected, and it must
#: come before everything else when used.
AVAILABLE_LAYERS: tuple[str, ...] = ("defaults", *DESIGN_LAYERS)

#: Themes whose rendered PAGE BACKGROUND is dark — keyed by the *rendered*
#: background, NOT by the theme name. ``premium_dark`` is a misnomer: it
#: renders a warm-bone LIGHT paper (``--paper:#faf7f2``), so it is
#: intentionally NOT in this set. Both light themes are light. This is the one
#: place that decides "white-ink or charcoal-ink wordmark?" for every document
#: — adding a genuinely dark theme here flips the wordmark everywhere with no
#: template or call-site edits.
_DARK_BACKGROUND_THEMES: frozenset[str] = frozenset()


def _normalize(theme: str | None) -> str:
    return (theme or "").strip().lower()


def _read(filename: str) -> str:
    """Return the text of a bundled CSS file, or ``""`` when absent."""
    try:
        resource = files(_CSS_PACKAGE).joinpath(filename)
        if not resource.is_file():
            return ""
        return resource.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return ""


def list_design_themes() -> list[str]:
    """List the themes that ship a token file."""
    return [name for name in DESIGN_THEMES if _read(f"tokens_{name}.css")]


def load_design_tokens(theme: str | None, *, webfonts: bool = False) -> str:
    """Return the token CSS for ``theme``.

    Args:
        theme: A name from :data:`DESIGN_THEMES`. Unknown or empty falls back
            to :data:`DEFAULT_THEME` so a caller can never render token-less.
        webfonts: Prepend the theme's ``@import`` so Chromium fetches the real
            display faces. Leave ``False`` for any artifact that must not
            reach the network when it is opened.

    Returns:
        CSS text. The ``@import`` (when requested) comes first, as the CSS
        grammar requires.
    """
    name = _normalize(theme)
    if name not in DESIGN_THEMES:
        name = DEFAULT_THEME
    tokens = _read(f"tokens_{name}.css")
    if not webfonts:
        return tokens
    imports = _read(f"webfonts_{name}.css")
    return f"{imports}\n{tokens}" if imports else tokens


def load_design_layer(layer: str) -> str:
    """Return one layer from :data:`AVAILABLE_LAYERS`."""
    key = _normalize(layer)
    if key not in AVAILABLE_LAYERS:
        raise KeyError(f"Unknown design layer '{layer}'")
    return _read(f"{key}.css")


def load_design_css(
    theme: str | None = None,
    *,
    webfonts: bool = False,
    tokens: bool = True,
    layers: tuple[str, ...] = DESIGN_LAYERS,
) -> str:
    """Return the shared design CSS, assembled in cascade order.

    Args:
        theme: Theme whose tokens to include. Ignored when ``tokens`` is False.
        webfonts: Include the theme's web-font ``@import``.
        tokens: Include the token layer. PRO passes ``False`` here because its
            tokens arrive with the theme, later in the cascade, so that a theme
            can still override the template's own fallbacks.
        layers: Which non-token layers to include, in order.

    Returns:
        One CSS string, safe to drop into a single ``<style>`` element.
    """
    parts: list[str] = []
    if tokens:
        parts.append(load_design_tokens(theme, webfonts=webfonts))
    elif webfonts:
        name = _normalize(theme)
        parts.append(_read(f"webfonts_{name}.css"))
    parts.extend(load_design_layer(layer) for layer in layers)
    return "\n".join(part for part in parts if part.strip())


def theme_background_is_dark(theme_name: str | None) -> bool:
    """Return whether ``theme_name`` renders on a dark page background."""
    return _normalize(theme_name) in _DARK_BACKGROUND_THEMES


def wordmark_variant_for_theme(theme_name: str | None) -> str:
    """Pick the wordmark ink that contrasts with ``theme_name``'s background.

    Returns:
        ``"light"`` (white ink on a dark background) or ``"dark"`` (charcoal
        ink on a light background, the default).
    """
    return "light" if theme_background_is_dark(theme_name) else "dark"


__all__ = [
    "AVAILABLE_LAYERS",
    "DEFAULT_THEME",
    "DESIGN_LAYERS",
    "DESIGN_THEMES",
    "list_design_themes",
    "load_design_css",
    "load_design_layer",
    "load_design_tokens",
    "theme_background_is_dark",
    "wordmark_variant_for_theme",
]
