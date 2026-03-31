"""ADscan Textual TUI application.

Launched via ``adscan start --tui`` as an alternative to the default
prompt_toolkit interactive shell. Both modes coexist: the flag selects which
one runs. All scanning logic is shared — only the UI layer differs.

Architecture
------------
* ``TuiShellWrapper`` wraps a ``PentestShell`` instance, exposing the same
  interface expected by ``run_start_session`` (attributes, ``.run()``).
* When ``.run()`` is called, it redirects the ``adscan_core.rich_output``
  global console to a thread-safe bridge that feeds Textual's ``RichLog``.
* Commands typed in the TUI input are dispatched in a background worker to
  the shell's existing ``commands`` dict — no logic duplication.

Brand colors
------------
All colors are pulled from ``adscan_core.theme`` — the single source of truth
shared with the prompt_toolkit shell. If the brand palette changes it
automatically applies to both UIs.
"""

from __future__ import annotations

import io
import shlex
import threading
from typing import Any, Callable

from rich.console import Console
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.widgets import Footer, Input
from textual.containers import Horizontal

from adscan_core.theme import ADSCAN_PRIMARY, ADSCAN_PRIMARY_DIM
from adscan_internal.tui.widgets.console_panel import ConsolePanel
from adscan_internal.tui.widgets.context_panel import ContextPanel
from adscan_internal.tui.widgets.header import ADscanHeader
from adscan_internal.tui.widgets.workspace_sidebar import WorkspaceSidebar


# ── CSS (generated from brand constants) ─────────────────────────────────────

def _build_css() -> str:
    """Return the Textual CSS string with ADscan brand colors injected."""
    bg_base  = "#0d1117"
    bg_panel = "#161b22"
    bg_border = "#21262d"
    bg_hover = "#1f2937"

    txt_primary = "#c9d1d9"
    txt_dim     = "#8b949e"
    txt_muted   = "#30363d"

    c_primary = ADSCAN_PRIMARY
    c_success = "#3fb950"
    c_warning = "#d29922"
    c_error   = "#f85149"

    return f"""
/* ADscan TUI — Enterprise Dark Theme
   Colors sourced from adscan_core.theme for brand consistency. */

Screen {{
    background: {bg_base};
    color: {txt_primary};
    layers: base overlay;
}}

Footer {{
    background: {bg_panel};
    color: {txt_dim};
    border-top: solid {bg_border};
}}

Footer > .footer--key {{
    background: {bg_border};
    color: {c_primary};
}}

#layout {{
    layout: horizontal;
    height: 1fr;
}}

/* ── Workspace Sidebar ──────────────────────────────────────────── */

#sidebar {{
    width: 26;
    min-width: 20;
    background: {bg_base};
    border-right: solid {bg_border};
    padding: 0 1;
}}

#sidebar-title {{
    color: {c_primary};
    text-style: bold;
    padding: 0 0 1 0;
    border-bottom: solid {bg_border};
}}

#workspace-tree {{
    background: {bg_base};
    color: {txt_primary};
    scrollbar-background: {bg_base};
    scrollbar-color: {bg_border};
    scrollbar-color-hover: {c_primary};
}}

Tree > .tree--label     {{ color: {txt_primary}; }}
Tree > .tree--guides    {{ color: {bg_border}; }}
Tree > .tree--cursor    {{ background: {bg_hover}; color: {c_primary}; }}
Tree > .tree--highlight {{ background: {bg_hover}; }}

/* ── Console Panel ──────────────────────────────────────────────── */

#console-panel {{
    width: 1fr;
    background: {bg_base};
    border-right: solid {bg_border};
    layout: vertical;
}}

#console-title {{
    color: {c_primary};
    text-style: bold;
    background: {bg_panel};
    height: 1;
    padding: 0 1;
    border-bottom: solid {bg_border};
}}

#console-log {{
    height: 1fr;
    background: {bg_base};
    scrollbar-background: {bg_base};
    scrollbar-color: {bg_border};
    scrollbar-color-hover: {c_primary};
    padding: 0 1;
}}

#input-row {{
    height: 3;
    background: {bg_base};
    border-top: solid {bg_border};
    layout: horizontal;
    padding: 0 1;
    align: left middle;
}}

#prompt-label {{
    color: {c_primary};
    text-style: bold;
    width: auto;
    padding: 0 1 0 0;
}}

#command-input {{
    background: {bg_base};
    color: {txt_primary};
    border: none;
    width: 1fr;
    padding: 0;
}}

#command-input:focus {{
    border: none;
    background: {bg_base};
    color: #e6edf3;
}}

/* ── Context Panel ──────────────────────────────────────────────── */

#context-panel {{
    width: 30;
    min-width: 24;
    background: {bg_base};
    layout: vertical;
}}

#attack-paths-section {{
    height: 1fr;
    layout: vertical;
    border-bottom: solid {bg_border};
}}

#attack-paths-title {{
    color: {c_error};
    text-style: bold;
    background: {bg_panel};
    height: 1;
    padding: 0 1;
    border-bottom: solid {bg_border};
}}

#attack-paths-list {{
    height: 1fr;
    background: {bg_base};
    padding: 0 1;
    scrollbar-background: {bg_base};
    scrollbar-color: {bg_border};
}}

#credentials-section {{
    height: 1fr;
    layout: vertical;
}}

#credentials-title {{
    color: {c_success};
    text-style: bold;
    background: {bg_panel};
    height: 1;
    padding: 0 1;
    border-bottom: solid {bg_border};
}}

#credentials-list {{
    height: 1fr;
    background: {bg_base};
    padding: 0 1;
    scrollbar-background: {bg_base};
    scrollbar-color: {bg_border};
}}

/* ── Utility classes ────────────────────────────────────────────── */

.empty-label  {{ color: {txt_muted}; padding: 1 0; }}
.status-ok    {{ color: {c_success}; }}
.status-warn  {{ color: {c_warning}; }}
.status-error {{ color: {c_error}; }}
.status-info  {{ color: {c_primary}; }}
.status-dim   {{ color: {txt_dim}; }}

LoadingIndicator {{
    color: {c_primary};
    background: {bg_base};
}}
"""


_CSS = _build_css()


# ── Output bridge ─────────────────────────────────────────────────────────────

class _TuiBridge(io.TextIOBase):
    """File-like object that routes Rich console output to the Textual app."""

    def __init__(self, callback: Callable[[str], None]) -> None:
        self._callback = callback
        self._lock = threading.Lock()

    def write(self, s: str) -> int:  # type: ignore[override]
        if s:
            with self._lock:
                self._callback(s)
        return len(s)

    def flush(self) -> None:
        pass

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return False


# ── Shell wrapper ─────────────────────────────────────────────────────────────

class TuiShellWrapper:
    """Wraps PentestShell to satisfy the ``run_start_session`` contract.

    All attribute access is forwarded to the inner shell. Only ``.run()``
    is overridden to launch the Textual app instead of the prompt_toolkit loop.
    """

    def __init__(self, shell: Any) -> None:
        object.__setattr__(self, "_shell", shell)
        object.__setattr__(self, "_tui_app", None)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_shell"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_shell", "_tui_app"):
            object.__setattr__(self, name, value)
        else:
            setattr(object.__getattribute__(self, "_shell"), name, value)

    def run(self) -> None:
        """Replace the prompt_toolkit REPL with the Textual TUI."""
        shell = object.__getattribute__(self, "_shell")
        app = ADscanApp(shell=shell)
        object.__setattr__(self, "_tui_app", app)
        app.run()


def create_tui_shell_wrapper(shell: Any) -> TuiShellWrapper:
    """Factory used by ``adscan.py handle_start()``."""
    return TuiShellWrapper(shell)


# ── Messages ──────────────────────────────────────────────────────────────────

class _ConsoleOutput(Message):
    """Carries a chunk of Rich-rendered ANSI text to the console panel."""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text


class _CommandDone(Message):
    """Signals that a shell command worker has finished."""

    def __init__(self, command: str) -> None:
        super().__init__()
        self.command = command


# ── Main App ──────────────────────────────────────────────────────────────────

class ADscanApp(App):
    """Enterprise-grade Textual TUI for ADscan.

    Colors are driven by ``adscan_core.theme`` — the same source used by the
    prompt_toolkit shell — so the brand stays consistent across both UIs.
    """

    CSS = _CSS

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", priority=True),
        Binding("f1", "show_help", "Help"),
        Binding("f2", "focus_workspaces", "Workspaces"),
        Binding("f3", "refresh_context", "Refresh"),
        Binding("f5", "focus_input", "Input"),
        Binding("ctrl+l", "clear_console", "Clear"),
    ]

    TITLE = "ADscan"

    def __init__(self, shell: Any) -> None:
        super().__init__()
        self._shell = shell
        self._bridge: _TuiBridge | None = None
        self._bridge_console: Console | None = None
        self._command_lock = threading.Lock()

    # ── Composition ───────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield ADscanHeader(shell=self._shell)
        with Horizontal(id="layout"):
            yield WorkspaceSidebar(shell=self._shell, id="sidebar")
            yield ConsolePanel(id="console-panel")
            yield ContextPanel(shell=self._shell, id="context-panel")
        yield Footer()

    def on_mount(self) -> None:
        self._setup_output_bridge()
        self._show_splash()

    # ── Splash ────────────────────────────────────────────────────────────────

    def _show_splash(self) -> None:
        """Push the branded splash screen; focus input after it dismisses."""
        from adscan_core.version import get_version_tag
        from adscan_internal.tui.screens.splash import SplashScreen

        version_tag = get_version_tag(
            getattr(self._shell, "license_mode", "LITE")
        )
        license_mode = str(
            getattr(self._shell, "license_mode", "LITE") or "LITE"
        )

        def _after_splash(_result: object) -> None:
            self.query_one("#command-input", Input).focus()
            self._print_ready()

        self.push_screen(SplashScreen(version_tag, license_mode), _after_splash)

    def _print_ready(self) -> None:
        """Brief prompt shown in console after splash dismisses."""
        panel = self.query_one("#console-panel", ConsolePanel)
        panel.append_markup(
            f"[bold {ADSCAN_PRIMARY}]Ready.[/bold {ADSCAN_PRIMARY}]  "
            f"[dim]Type [/dim][bold]help[/bold][dim] to list commands "
            f"or [/dim][bold]Ctrl+C[/bold][dim] to quit.[/dim]"
        )

    # ── Output bridge setup ────────────────────────────────────────────────────

    def _setup_output_bridge(self) -> None:
        """Redirect the global rich_output console to this TUI."""
        from adscan_core import rich_output

        bridge = _TuiBridge(lambda text: self.post_message(_ConsoleOutput(text)))
        bridge_console = Console(
            file=bridge,
            force_terminal=True,
            highlight=False,
            markup=False,
            no_color=False,
        )
        object.__setattr__(self, "_bridge", bridge)
        object.__setattr__(self, "_bridge_console", bridge_console)

        rich_output.init_rich_output(
            bridge_console,
            verbose_mode=bool(getattr(self._shell, "verbose_mode", False)),
            debug_mode=bool(getattr(self._shell, "debug_mode", False)),
            secret_mode=bool(getattr(self._shell, "SECRET_MODE", False)),
        )

    # ── Message handlers ───────────────────────────────────────────────────────

    def on__console_output(self, message: _ConsoleOutput) -> None:
        """Route bridge output to the console panel (called in Textual thread)."""
        self.query_one("#console-panel", ConsolePanel).append_ansi(message.text)

    def on__command_done(self, message: _CommandDone) -> None:
        """After a command finishes, refresh sidebar, context panel and header."""
        try:
            self.query_one(ADscanHeader).refresh_workspace()
            self.query_one("#sidebar", WorkspaceSidebar).refresh_tree()
            self.query_one("#context-panel", ContextPanel).refresh_context()
        except Exception:  # noqa: BLE001
            pass

    # ── Input handling ─────────────────────────────────────────────────────────

    @on(Input.Submitted, "#command-input")
    def _on_command_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        event.input.value = ""
        if not raw:
            return
        if raw.lower() in ("exit", "quit"):
            self.exit()
            return
        console_panel = self.query_one("#console-panel", ConsolePanel)
        console_panel.add_to_history(raw)
        console_panel.append_markup(
            f"[bold {ADSCAN_PRIMARY}](ADscan) ❯[/bold {ADSCAN_PRIMARY}] [white]{raw}[/white]"
        )
        self._dispatch_command(raw)

    # ── Command dispatch (background worker) ───────────────────────────────────

    @work(thread=True, exclusive=False)
    def _dispatch_command(self, raw_input: str) -> None:
        """Execute a shell command in a background thread."""
        try:
            parts = shlex.split(raw_input)
        except ValueError:
            self.post_message(_ConsoleOutput("\x1b[33mError: mismatched quotes\x1b[0m\n"))
            return

        if not parts:
            return

        from adscan_internal.cli.common import (
            normalize_command_alias,
            normalize_help_alias,
        )

        command_name = parts[0].lower()
        args_list = parts[1:]
        shell = self._shell
        known = set(shell.commands.keys())

        try:
            command_name, args_list, _ = normalize_command_alias(
                command_name, args_list, known_commands=known
            )
            command_name, args_list, _ = normalize_help_alias(
                command_name, args_list, known_commands=known
            )
        except Exception:  # noqa: BLE001
            pass

        cmd_method = shell.commands.get(command_name)
        if not cmd_method:
            self.post_message(
                _ConsoleOutput(f"\x1b[33mUnknown command: {command_name}\x1b[0m\n")
            )
            self.post_message(_CommandDone(command_name))
            return

        arg_string = " ".join(args_list)
        try:
            cmd_method(arg_string)
        except Exception as exc:  # noqa: BLE001
            from adscan_internal import telemetry

            telemetry.capture_exception(exc)
            self.post_message(
                _ConsoleOutput(
                    f"\x1b[31mError executing '{command_name}': {exc}\x1b[0m\n"
                )
            )
        finally:
            self.post_message(_CommandDone(command_name))

    # ── Actions ────────────────────────────────────────────────────────────────

    def action_focus_input(self) -> None:
        self.query_one("#command-input", Input).focus()

    def action_focus_workspaces(self) -> None:
        from textual.widgets import Tree

        self.query_one("#workspace-tree", Tree).focus()

    def action_clear_console(self) -> None:
        self.query_one("#console-panel", ConsolePanel).clear()

    def action_refresh_context(self) -> None:
        self.query_one(ADscanHeader).refresh_workspace()
        self.query_one("#sidebar", WorkspaceSidebar).refresh_tree()
        self.query_one("#context-panel", ContextPanel).refresh_context()

    def action_show_help(self) -> None:
        """Print available commands to the console."""
        shell = self._shell
        cmds = sorted(shell.commands.keys()) if hasattr(shell, "commands") else []
        panel = self.query_one("#console-panel", ConsolePanel)
        panel.append_markup(
            f"[bold {ADSCAN_PRIMARY}]Available commands:[/bold {ADSCAN_PRIMARY}]"
        )
        for cmd in cmds:
            panel.append_markup(
                f"  [{ADSCAN_PRIMARY_DIM}]{cmd}[/{ADSCAN_PRIMARY_DIM}]"
            )

    def action_quit(self) -> None:
        self.exit()
