"""Table, code-block, and error-context output helpers."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.box import Box, ROUNDED

import adscan_core.output._state as _state
from adscan_core.theme import ADSCAN_PRIMARY, ADSCAN_SECONDARY_DARK
from adscan_core.output._log import (
    BRAND_COLORS,
    _get_logger,
    _handle_spacing,
    print_info,
)
from adscan_core.output._panels import print_panel  # noqa: F401 (re-exported)


def print_table(
    table: Table,
    spacing: str = "auto",
) -> None:
    """Print a Rich Table directly with intelligent spacing.

    Args:
        table: Rich Table object to print
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
    """
    console = _state._get_console()
    _state._get_telemetry_console()

    spacing_before = _handle_spacing("info", False, spacing)
    if spacing_before:
        console.print()

    console.print(table)

    if spacing in ("after", "both"):
        console.print()


def print_table_debug(table: "Table", *, title: str | None = None) -> None:
    """Print a Rich table only when debug mode is enabled."""
    logger = _get_logger()
    logger.debug(title or "Debug table output")
    if not _state._debug_mode:
        return
    _state._console.print(table)
    _state._console.print()


def print_info_table(
    data: List[Dict[str, Any]], columns: List[str], title: Optional[str] = None
) -> None:
    """Print data in a formatted table.

    Args:
        data: List of dictionaries with data rows
        columns: List of column names (keys from data dictionaries)
        title: Optional table title
    """
    table = Table(
        title=title, show_header=True, header_style=f"bold {ADSCAN_PRIMARY}", box=ROUNDED
    )

    for col in columns:
        table.add_column(col, style=BRAND_COLORS["info"])

    for row in data:
        table.add_row(*[str(row.get(col, "")) for col in columns])

    print_table(table)


def print_info_list(
    items: List[str], title: Optional[str] = None, icon: str = "•"
) -> None:
    """Print a list of items in a formatted panel.

    Args:
        items: List of items to display
        title: Optional panel title
        icon: Icon to use for list items
    """
    console = _state._get_console()
    _state._get_telemetry_console()

    content = Text()
    for item in items:
        content.append(f"{icon} {item}\n", style="white")

    if title:
        panel_renderable = Panel(
            content,
            title=title,
            border_style=BRAND_COLORS["info"],
            box=ROUNDED,
            padding=(1, 2),
        )
    else:
        panel_renderable = Panel(
            content, border_style=BRAND_COLORS["info"], box=ROUNDED, padding=(0, 1)
        )

    console.print(panel_renderable)


def print_adaptive_table_or_summary(
    items: List[Dict[str, Any]],
    *,
    columns: List[str],
    title: Optional[str] = None,
    threshold: int = 10,
    summary_label: str = "items",
) -> None:
    """Print a detailed table for small sets or a compact summary for large sets."""
    count = len(items)
    if count == 0:
        return

    if count <= threshold:
        print_info_table(items, columns, title=title)
        return

    label = summary_label if count == 1 else summary_label
    print_info(f"Extracted {count} {label}.")


def create_styled_table(
    title: Optional[str] = None,
    caption: Optional[str] = None,
    show_header: bool = True,
    show_lines: bool = False,
    show_edge: bool = True,
    expand: bool = False,
    box_style: Box = ROUNDED,
) -> Table:
    """Create a Rich Table with consistent ADscan brand styling."""
    table = Table(
        title=title,
        caption=caption,
        show_header=show_header,
        show_lines=show_lines,
        show_edge=show_edge,
        expand=expand,
        box=box_style,
        border_style=ADSCAN_PRIMARY,
        header_style=f"bold {ADSCAN_PRIMARY}",
        caption_style=f"dim {ADSCAN_PRIMARY}",
        padding=(0, 1),
    )
    return table


def create_summary_table(items: List[tuple], title: str = "Summary") -> Table:
    """Create a two-column summary table (key-value pairs)."""
    table = create_styled_table(title=title, show_header=False)
    table.add_column("Property", style=f"bold {ADSCAN_PRIMARY}", no_wrap=True)
    table.add_column("Value", style="white")

    for key, value in items:
        table.add_row(key, str(value))

    return table


def create_findings_table(
    findings: List[Dict[str, Any]],
    title: str = "Findings",
    show_severity: bool = True,
) -> Table:
    """Create a findings table with severity color-coding."""
    table = create_styled_table(title=title, show_lines=True)

    table.add_column("Target", style=ADSCAN_PRIMARY, no_wrap=True)
    table.add_column("Finding", style="white")

    if show_severity:
        table.add_column("Severity", justify="center", no_wrap=True)

    for finding in findings:
        severity = finding.get("severity", "Unknown")
        severity_color = {
            "Critical": "red",
            "High": "orange1",
            "Medium": "yellow",
            "Low": "blue",
            "Info": ADSCAN_PRIMARY,
        }.get(severity, "white")

        severity_icon = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🔵",
            "Info": "⚪",
        }.get(severity, "⚪")

        if show_severity:
            table.add_row(
                finding.get("target", "N/A"),
                finding.get("finding", "N/A"),
                f"[{severity_color}]{severity_icon} {severity}[/{severity_color}]",
            )
        else:
            table.add_row(
                finding.get("target", "N/A"),
                finding.get("finding", "N/A"),
            )

    return table


def create_status_table(
    items: List[Dict[str, Any]],
    title: str = "Status",
    show_icons: bool = True,
) -> Table:
    """Create a status table with success/failure indicators."""
    table = create_styled_table(title=title)

    table.add_column("Component", style=f"bold {ADSCAN_PRIMARY}")
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Details", style="dim")

    for item in items:
        name = item.get("name", "N/A")
        status = item.get("status", "unknown").lower()
        details = item.get("details", "")

        if status == "success":
            status_text = (
                "[green]✓ Success[/green]" if show_icons else "[green]Success[/green]"
            )
        elif status == "failed":
            status_text = "[red]✗ Failed[/red]" if show_icons else "[red]Failed[/red]"
        elif status == "pending":
            status_text = (
                "[yellow]○ Pending[/yellow]"
                if show_icons
                else "[yellow]Pending[/yellow]"
            )
        elif status == "running":
            status_text = (
                f"[{ADSCAN_PRIMARY}]◉ Running[/]" if show_icons else f"[{ADSCAN_PRIMARY}]Running[/]"
            )
        else:
            status_text = "[dim]? Unknown[/dim]" if show_icons else "[dim]Unknown[/dim]"

        table.add_row(name, status_text, details)

    return table


def print_code(
    code: str,
    language: str = "python",
    theme: str = "monokai",
    line_numbers: bool = False,
    title: Optional[str] = None,
    background_color: Optional[str] = None,
) -> None:
    """Print code with syntax highlighting."""
    console = _state._get_console()
    _state._get_telemetry_console()

    syntax = Syntax(
        code,
        language,
        theme=theme,
        line_numbers=line_numbers,
        background_color=background_color,
    )

    if title:
        renderable: RenderableType = Panel(
            syntax,
            title=title,
            border_style=ADSCAN_PRIMARY,
            padding=(1, 2),
        )
    else:
        renderable = syntax

    console.print(renderable)


def print_command(
    command: str,
    title: Optional[str] = None,
    show_copy_hint: bool = False,
) -> None:
    """Print a command with bash syntax highlighting."""
    console = _state._get_console()
    _state._get_telemetry_console()

    if title is None:
        title = f"[bold {ADSCAN_PRIMARY}]Command[/bold {ADSCAN_PRIMARY}]"

    syntax = Syntax(
        command,
        "bash",
        theme="monokai",
        line_numbers=False,
        background_color=ADSCAN_SECONDARY_DARK,
    )

    if show_copy_hint:
        hint = Text("💡 Tip: Copy the command above", style="dim italic")
        content: RenderableType = Group(syntax, Text(""), hint)
    else:
        content = syntax

    panel = Panel(
        content,
        title=title,
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
    )

    console.print(panel)


def print_error_context(
    error_message: str,
    context: Optional[Dict[str, Any]] = None,
    suggestions: Optional[List[str]] = None,
    title: str = "Error Details",
    show_exception: bool = False,
    exception: Optional[Exception] = None,
) -> None:
    """Print error with structured context panel."""
    console = _state._get_console()

    content_parts = []

    error_text = Text()
    error_text.append("✗ ", style="bold red")
    error_text.append(error_message, style="bold red")
    content_parts.append(error_text)

    if context:
        content_parts.append(Text(""))
        context_header = Text("Context:", style=f"bold {ADSCAN_PRIMARY}")
        content_parts.append(context_header)

        marked_context = _state._mark_operation_details(context)

        for key, value in marked_context.items():
            context_line = Text()
            context_line.append(f"  • {key}: ", style="dim")
            context_line.append(str(value), style="white")
            content_parts.append(context_line)

    if suggestions:
        content_parts.append(Text(""))
        suggestions_header = Text("Suggestions:", style="bold yellow")
        content_parts.append(suggestions_header)

        for i, suggestion in enumerate(suggestions, 1):
            suggestion_line = Text()
            suggestion_line.append(f"  {i}. ", style="yellow")
            suggestion_line.append(suggestion, style="white")
            content_parts.append(suggestion_line)

    if show_exception and exception:
        if _state.is_debug_mode():
            content_parts.append(Text(""))
            exception_header = Text("Exception Details:", style="bold red")
            content_parts.append(exception_header)

            exception_text = Text()
            exception_text.append(f"  {type(exception).__name__}: ", style="bold red")
            exception_text.append(str(exception), style="red")
            content_parts.append(exception_text)
        else:
            logger = logging.getLogger(__name__)
            logger.debug(
                "Exception details hidden (run with --debug to show)",
                extra={"exception_type": type(exception).__name__},
            )

    content = Group(*content_parts)

    panel = Panel(
        content,
        title=f"[bold red]{title}[/bold red]",
        border_style="red",
        padding=(1, 2),
    )

    console.print(panel)
    _state._get_telemetry_console()


__all__ = [
    "print_table",
    "print_table_debug",
    "print_info_table",
    "print_info_list",
    "print_adaptive_table_or_summary",
    "create_styled_table",
    "create_summary_table",
    "create_findings_table",
    "create_status_table",
    "print_code",
    "print_command",
    "print_error_context",
]
