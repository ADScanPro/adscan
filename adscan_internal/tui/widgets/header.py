"""ADscan custom header widget.

Replaces Textual's default ``Header`` with a 3-column layout:
  Left  : ◈ ADscan  (brand mark + name)
  Center: workspace name + edition badge
  Right : live clock (updates every second)

Colors are driven by ``adscan_core.theme`` — same source as the
prompt_toolkit shell.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

from adscan_core.theme import ADSCAN_PRIMARY, ADSCAN_PRIMARY_DIM
from adscan_internal.branding import ADSCAN_MARK


def _build_css() -> str:
    bg = "#161b22"
    border = "#21262d"
    c = ADSCAN_PRIMARY
    dim = "#8b949e"
    return f"""
ADscanHeader {{
    height: 1;
    background: {bg};
    border-bottom: solid {border};
    layout: horizontal;
    padding: 0 1;
}}

#header-brand {{
    color: {c};
    text-style: bold;
    width: auto;
    padding: 0 2 0 0;
}}

#header-workspace {{
    color: {ADSCAN_PRIMARY_DIM};
    width: 1fr;
    content-align: center middle;
}}

#header-clock {{
    color: {dim};
    width: auto;
    content-align: right middle;
    padding: 0 0 0 2;
}}
"""


class ADscanHeader(Widget):
    """Premium header: brand mark · workspace · edition badge · clock."""

    CSS = _build_css()

    # Reactive clock — updates every second via set_interval.
    _time: reactive[str] = reactive("", layout=False)

    def __init__(self, shell: Any, **kwargs) -> None:
        super().__init__(**kwargs)
        self._shell = shell

    def compose(self) -> ComposeResult:
        yield Static(f" {ADSCAN_MARK}", id="header-brand")
        yield Static(self._workspace_label(), id="header-workspace")
        yield Static("", id="header-clock")

    def on_mount(self) -> None:
        self._tick()
        self.set_interval(1.0, self._tick)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _tick(self) -> None:
        self.query_one("#header-clock", Static).update(
            datetime.now().strftime("%H:%M:%S")
        )

    def _workspace_label(self) -> str:
        workspace = getattr(self._shell, "current_workspace", None) or "—"
        license_mode = str(
            getattr(self._shell, "license_mode", "LITE") or "LITE"
        ).upper()

        badge_style = (
            f"bold {ADSCAN_PRIMARY}" if license_mode == "PRO"
            else "bold #d29922"
        )
        badge = f"[{badge_style}]{license_mode}[/{badge_style}]"
        return f"[{ADSCAN_PRIMARY_DIM}]{workspace}[/{ADSCAN_PRIMARY_DIM}]  {badge}"

    def refresh_workspace(self) -> None:
        """Call after workspace changes to update the center label."""
        self.query_one("#header-workspace", Static).update(
            self._workspace_label()
        )
