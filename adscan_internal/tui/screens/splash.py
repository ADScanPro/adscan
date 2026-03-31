"""ADscan splash screen — shown on TUI startup before the main layout.

Displays the brand ASCII art with gradient, version, edition badge,
tagline and an animated progress bar. Auto-dismisses after ~1.5 s
or immediately on any keypress.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Middle
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import ProgressBar, Static

from adscan_core.theme import ADSCAN_PRIMARY, ADSCAN_PRIMARY_DIM
from adscan_internal.branding import (
    ADSCAN_COPYRIGHT,
    ADSCAN_TAGLINE,
    build_gradient_ascii,
)

# Total animation steps and interval (steps × interval ≈ 1.5 s)
_STEPS = 60
_INTERVAL = 1.5 / _STEPS


def _build_css() -> str:
    bg = "#0d1117"
    panel = "#161b22"
    border = "#21262d"
    c = ADSCAN_PRIMARY
    dim = "#8b949e"
    return f"""
SplashScreen {{
    background: {bg};
    align: center middle;
}}

#splash-container {{
    width: auto;
    height: auto;
    padding: 3 6;
    background: {panel};
    border: solid {border};
    align: center middle;
    layout: vertical;
}}

#splash-logo {{
    width: auto;
    content-align: center middle;
    color: {c};
    padding: 0 0 1 0;
}}

#splash-version {{
    color: {c};
    text-style: bold;
    content-align: center middle;
    width: 100%;
    padding: 0 0 0 0;
}}

#splash-tagline {{
    color: {ADSCAN_PRIMARY_DIM};
    text-style: italic;
    content-align: center middle;
    width: 100%;
    padding: 0 0 1 0;
}}

#splash-progress {{
    width: 40;
    padding: 1 0;
}}

#splash-hint {{
    color: {dim};
    content-align: center middle;
    width: 100%;
    padding: 1 0 0 0;
}}

#splash-copyright {{
    color: {dim};
    content-align: center middle;
    width: 100%;
}}
"""


class SplashScreen(Screen):
    """Full-screen branded splash shown before the main layout."""

    CSS = _build_css()

    BINDINGS = [
        Binding("space", "dismiss_splash", "Skip", show=False),
        Binding("enter", "dismiss_splash", "Skip", show=False),
        Binding("escape", "dismiss_splash", "Skip", show=False),
    ]

    progress: reactive[float] = reactive(0.0)

    def __init__(self, version_tag: str, license_mode: str) -> None:
        super().__init__()
        self._version_tag = version_tag
        self._license_mode = license_mode.upper()
        self._step = 0

    # ── Composition ───────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        logo = build_gradient_ascii(width=self.app.console.width)

        badge_style = (
            f"bold {ADSCAN_PRIMARY}" if self._license_mode == "PRO"
            else "bold #d29922"
        )
        badge = f"[{badge_style}]{self._license_mode}[/{badge_style}]"

        with Middle():
            with Center():
                from textual.containers import Container

                with Container(id="splash-container"):
                    yield Static(logo, id="splash-logo")
                    yield Static(
                        f"[bold {ADSCAN_PRIMARY}]ADscan  "
                        f"[dim]{self._version_tag}[/dim][/bold {ADSCAN_PRIMARY}]"
                        f"   {badge}",
                        id="splash-version",
                    )
                    yield Static(ADSCAN_TAGLINE, id="splash-tagline")
                    yield ProgressBar(
                        total=_STEPS,
                        show_eta=False,
                        show_percentage=False,
                        id="splash-progress",
                    )
                    yield Static(
                        "[dim]Press any key to skip[/dim]",
                        id="splash-hint",
                    )
                    yield Static(ADSCAN_COPYRIGHT, id="splash-copyright")

    def on_mount(self) -> None:
        self.set_interval(_INTERVAL, self._tick)

    # ── Animation ─────────────────────────────────────────────────────────────

    def _tick(self) -> None:
        self._step += 1
        self.query_one("#splash-progress", ProgressBar).advance(1)
        if self._step >= _STEPS:
            self.dismiss()

    def action_dismiss_splash(self) -> None:
        self.dismiss()

    # ── Forward any key to dismiss ────────────────────────────────────────────

    def on_key(self, _event) -> None:  # noqa: ANN001
        self.dismiss()
