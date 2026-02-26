"""Centralized theme and styling configuration for ADscan Rich UIs.

This module is intentionally shared by both:
- the host-side launcher (PyPI)
- the runtime CLI inside the Docker image

It contains brand colors and a Rich `Theme` that can be used by any console
instantiated outside of `adscan_core.rich_output`.
"""

from __future__ import annotations

from rich import box
from rich.theme import Theme

# ============================================================================
# Brand Colors
# ============================================================================

# Primary brand colors (cyan/blue from logo)
ADSCAN_PRIMARY = "#00D4FF"  # Bright cyan - main brand color
ADSCAN_PRIMARY_DIM = "#00A8CC"  # Dimmed version for subtle elements
ADSCAN_PRIMARY_BRIGHT = "#00E5FF"  # Brighter version for highlights

# Secondary brand colors (dark gray from logo)
ADSCAN_SECONDARY = "#2A2A2A"  # Dark metallic gray
ADSCAN_SECONDARY_DARK = "#1A1A1A"  # Very dark gray/black

# Semantic colors (standard but with brand integration)
COLOR_SUCCESS = "green"
COLOR_WARNING = "yellow"
COLOR_ERROR = "red"
COLOR_INFO = ADSCAN_PRIMARY
COLOR_DIM = "dim"

# ============================================================================
# Rich Theme Configuration
# ============================================================================

ADSCAN_THEME = Theme(
    {
        "info": f"bold {ADSCAN_PRIMARY}",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "dim": "dim",
        "highlight": f"bold {ADSCAN_PRIMARY_BRIGHT}",
        "emphasis": f"italic {ADSCAN_PRIMARY}",
        "code": f"{ADSCAN_SECONDARY} on white",
        "progress.description": ADSCAN_PRIMARY,
        "progress.percentage": f"bold {ADSCAN_PRIMARY}",
        "progress.data.speed": ADSCAN_PRIMARY_DIM,
        "progress.spinner": ADSCAN_PRIMARY,
        "bar.complete": ADSCAN_PRIMARY,
        "bar.finished": "green",
        "bar.pulse": ADSCAN_PRIMARY_BRIGHT,
        "table.header": f"bold {ADSCAN_PRIMARY}",
        "table.border": ADSCAN_PRIMARY,
        "table.caption": f"italic {ADSCAN_PRIMARY_DIM}",
        "panel.border": ADSCAN_PRIMARY,
        "panel.border.success": "green",
        "panel.border.warning": "yellow",
        "panel.border.error": "red",
        "status.spinner": ADSCAN_PRIMARY,
        "status.text": ADSCAN_PRIMARY,
        "tree.line": ADSCAN_PRIMARY_DIM,
        "prompt": f"bold {ADSCAN_PRIMARY}",
        "prompt.default": ADSCAN_PRIMARY_DIM,
        "prompt.choices": f"dim {ADSCAN_PRIMARY}",
    }
)

# ============================================================================
# Box Styles
# ============================================================================

BOX_MINIMAL = box.MINIMAL
BOX_ROUNDED = box.ROUNDED
BOX_HEAVY = box.HEAVY
BOX_DOUBLE = box.DOUBLE
BOX_SIMPLE = box.SIMPLE

BOX_PANEL_INFO = BOX_MINIMAL
BOX_PANEL_IMPORTANT = BOX_ROUNDED
BOX_TABLE_DEFAULT = BOX_ROUNDED
BOX_TABLE_DETAILED = BOX_HEAVY

# ============================================================================
# Icons and Symbols
# ============================================================================

ICON_SUCCESS = "✓"
ICON_ERROR = "✗"
ICON_WARNING = "⚠"
ICON_INFO = "ℹ"
ICON_QUESTION = "?"
ICON_BULLET = "•"
ICON_ARROW_RIGHT = "→"
ICON_ARROW_DOWN = "↓"

ICON_LOADING = "⏳"
ICON_COMPLETE = "✓"
ICON_FAILED = "✗"
ICON_PENDING = "○"
ICON_RUNNING = "◉"

# Severity icons (findings/vulnerabilities)
ICON_CRITICAL = "🔴"
ICON_HIGH = "🟠"
ICON_MEDIUM = "🟡"
ICON_LOW = "🔵"
ICON_INFO_FINDING = "⚪"

# Tool/feature icons
ICON_SCAN = "🔍"
ICON_NETWORK = "🌐"
ICON_CREDENTIALS = "🔑"
ICON_REPORT = "📊"
ICON_INSTALL = "📦"
ICON_CONFIG = "⚙"
ICON_DATABASE = "🗄"
ICON_FOLDER = "📁"
ICON_FILE = "📄"
ICON_LOCK = "🔒"
ICON_UNLOCK = "🔓"

# ============================================================================
# Spinner Styles
# ============================================================================

SPINNER_DOTS = "dots"
SPINNER_DOTS_SCROLLING = "dots_scrolling"
SPINNER_LINE = "line"
SPINNER_LINE2 = "line2"
SPINNER_PIPE = "pipe"
SPINNER_SIMPLE_DOTS = "simpleDots"
SPINNER_SIMPLE_DOTS_SCROLLING = "simpleDotsScrolling"
SPINNER_STAR = "star"
SPINNER_STAR2 = "star2"
SPINNER_ARROW = "arrow"
SPINNER_BOUNCINGBAR = "bouncingBar"
SPINNER_BOUNCINGBALL = "bouncingBall"
SPINNER_CIRCLE = "circle"
SPINNER_MONKEY = "monkey"
SPINNER_CLOCK = "clock"
SPINNER_EARTH = "earth"
SPINNER_MOON = "moon"

SPINNER_DEFAULT = SPINNER_DOTS

# ============================================================================
# Padding and Spacing
# ============================================================================

PADDING_MINIMAL = (0, 1)
PADDING_NORMAL = (1, 2)
PADDING_LARGE = (2, 3)

# ============================================================================
# Style Presets
# ============================================================================

STYLE_PRESETS = {
    "panel_info": {
        "border_style": ADSCAN_PRIMARY,
        "box": BOX_PANEL_INFO,
        "padding": PADDING_MINIMAL,
    },
    "panel_success": {
        "border_style": COLOR_SUCCESS,
        "box": BOX_PANEL_INFO,
        "padding": PADDING_MINIMAL,
    },
    "panel_warning": {
        "border_style": COLOR_WARNING,
        "box": BOX_PANEL_IMPORTANT,
        "padding": PADDING_NORMAL,
    },
    "panel_error": {
        "border_style": COLOR_ERROR,
        "box": BOX_PANEL_IMPORTANT,
        "padding": PADDING_NORMAL,
    },
    "panel_important": {
        "border_style": ADSCAN_PRIMARY_BRIGHT,
        "box": BOX_PANEL_IMPORTANT,
        "padding": PADDING_NORMAL,
    },
    "table_default": {
        "box": BOX_TABLE_DEFAULT,
        "header_style": f"bold {ADSCAN_PRIMARY}",
        "border_style": ADSCAN_PRIMARY,
        "show_lines": False,
        "padding": (0, 1),
    },
    "table_detailed": {
        "box": BOX_TABLE_DETAILED,
        "header_style": f"bold {ADSCAN_PRIMARY}",
        "border_style": ADSCAN_PRIMARY,
        "show_lines": True,
        "padding": (0, 1),
    },
}
