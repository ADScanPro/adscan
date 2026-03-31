"""Shared branding assets for ADscan UIs.

Used by both:
- The prompt_toolkit shell (``PentestShell.show_intro``)
- The Textual TUI splash screen and header

Centralizing here ensures the ASCII art, gradient, and tagline stay
consistent across both UIs without making the default shell depend on
the optional TUI package layout.
"""

from __future__ import annotations

from rich.text import Text

from adscan_core.theme import ADSCAN_PRIMARY

# ── Brand constants ───────────────────────────────────────────────────────────

# Parsed once from the hex brand color.
_BRAND_R, _BRAND_G, _BRAND_B = 0x00, 0xD4, 0xFF  # #00D4FF

ADSCAN_TAGLINE = "Automate the AD kill chain."

ADSCAN_COPYRIGHT = "© 2026 Yeray Martín · Macroblond44"

ADSCAN_LINKS = {
    "github": "https://github.com/ADscanPro/adscan",
    "discord": "https://discord.gg/fXBR3P8H74",
    "linkedin": "https://linkedin.com/in/yeray-martín-domínguez-324a64223",
}

# ── ASCII logo ────────────────────────────────────────────────────────────────

# Full-width block art (requires ~90 columns).
ADSCAN_ASCII_WIDE = """\

   █████████   ██████████
  ███░░░░░███ ░░███░░░░███
 ░███    ░███  ░███   ░░███  █████   ██████   ██████   ████████
 ░███████████  ░███    ░███ ███░░   ███░░███ ░░░░░███ ░░███░░███
 ░███░░░░░███  ░███    ░███░░█████ ░███ ░░░   ███████  ░███ ░███
 ░███    ░███  ░███    ███  ░░░░███░███  ███ ███░░███  ░███ ░███
 █████   █████ ██████████   ██████ ░░██████ ░░████████ ████ █████
░░░░░   ░░░░░ ░░░░░░░░░░   ░░░░░░   ░░░░░░   ░░░░░░░░░░░░░░░░░
"""

# Compact single-line mark for narrow terminals or headers.
ADSCAN_MARK = "◈  ADscan"


# ── Gradient helpers ──────────────────────────────────────────────────────────

def build_gradient_ascii(width: int = 120) -> Text:
    """Return the wide ASCII logo as a Rich ``Text`` with a brand gradient.

    Gradient: brand cyan (#00D4FF) at the top → white (#ffffff) at the bottom.
    Falls back to a compact centered line when ``width`` is below 90.

    Args:
        width: Terminal width in columns.

    Returns:
        Rich ``Text`` object ready to print with ``console.print()``.
    """
    if width < 90:
        return Text(
            f"  {ADSCAN_MARK}  ",
            style=f"bold {ADSCAN_PRIMARY}",
            justify="center",
        )

    lines = ADSCAN_ASCII_WIDE.splitlines(keepends=True)
    gradient = Text()
    total = max(len(lines) - 1, 1)
    for idx, line in enumerate(lines):
        blend = idx / total
        r = int(_BRAND_R + (0xFF - _BRAND_R) * blend)
        g = int(_BRAND_G + (0xFF - _BRAND_G) * blend)
        b = int(_BRAND_B + (0xFF - _BRAND_B) * blend)
        gradient.append(line, style=f"#{r:02x}{g:02x}{b:02x}")
    return gradient


def build_intro_lines(version_tag: str) -> list[tuple[str, str]]:
    """Return the intro metadata lines as (markup_text, style) pairs.

    Suitable for both Rich ``console.print`` and Textual ``Static`` widgets.

    Args:
        version_tag: e.g. "6.3.0-lite"

    Returns:
        List of (text, style) tuples.
    """
    from adscan_core.theme import ADSCAN_PRIMARY_DIM

    return [
        (f"ADscan  {version_tag}", f"bold {ADSCAN_PRIMARY}"),
        (ADSCAN_TAGLINE, f"italic {ADSCAN_PRIMARY_DIM}"),
        ("", ""),
        (ADSCAN_COPYRIGHT, "dim"),
        (
            f"[link={ADSCAN_LINKS['discord']}]💬 Discord[/link]"
            f"  ·  [link={ADSCAN_LINKS['github']}]🔗 GitHub[/link]"
            f"  ·  [link={ADSCAN_LINKS['linkedin']}]💼 LinkedIn[/link]",
            "dim",
        ),
    ]
