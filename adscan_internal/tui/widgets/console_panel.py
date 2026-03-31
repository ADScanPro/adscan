"""Console panel widget: scrollable log + command input."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Input, RichLog, Static
from textual.widget import Widget


class ConsolePanel(Widget):
    """Main interactive panel: Rich output log + command input bar."""

    BINDINGS = [
        Binding("up", "history_prev", "History prev", show=False),
        Binding("down", "history_next", "History next", show=False),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._history: list[str] = []
        self._history_idx: int = -1

    def compose(self) -> ComposeResult:
        yield Static("  CONSOLE", id="console-title")
        yield RichLog(id="console-log", markup=True, highlight=True, wrap=True)
        yield _InputRow()

    def append_ansi(self, text: str) -> None:
        """Append raw ANSI-formatted text from Rich to the log widget."""
        from rich.text import Text

        log = self.query_one("#console-log", RichLog)
        try:
            rich_text = Text.from_ansi(text.rstrip("\n"))
            if rich_text.plain.strip():
                log.write(rich_text)
        except Exception:  # noqa: BLE001
            plain = text.rstrip("\n")
            if plain.strip():
                log.write(plain)

    def append_markup(self, markup: str) -> None:
        """Append Rich markup text to the log widget."""
        log = self.query_one("#console-log", RichLog)
        log.write(markup)

    def clear(self) -> None:
        """Clear the console output."""
        self.query_one("#console-log", RichLog).clear()

    def add_to_history(self, command: str) -> None:
        """Add a command to history."""
        if command and (not self._history or self._history[-1] != command):
            self._history.append(command)
        self._history_idx = -1

    def action_history_prev(self) -> None:
        """Navigate to previous history entry."""
        if not self._history:
            return
        if self._history_idx == -1:
            self._history_idx = len(self._history) - 1
        elif self._history_idx > 0:
            self._history_idx -= 1
        inp = self.query_one("#command-input", Input)
        inp.value = self._history[self._history_idx]
        inp.cursor_position = len(inp.value)

    def action_history_next(self) -> None:
        """Navigate to next history entry."""
        if self._history_idx == -1:
            return
        if self._history_idx < len(self._history) - 1:
            self._history_idx += 1
            inp = self.query_one("#command-input", Input)
            inp.value = self._history[self._history_idx]
        else:
            self._history_idx = -1
            self.query_one("#command-input", Input).value = ""


class _InputRow(Widget):
    """Prompt label + text input row."""

    def compose(self) -> ComposeResult:
        yield Static("(ADscan) ❯", id="prompt-label")
        yield Input(placeholder="type a command…", id="command-input")
