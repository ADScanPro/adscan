"""Panel rendering primitives — boxed sections with titles, headers, instructions."""

from __future__ import annotations

from typing import Optional, List, Dict, Union

from rich.console import Group, RenderableType
from rich.errors import MissingStyle
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.box import Box, ROUNDED

from adscan_core.theme import ADSCAN_PRIMARY, ADSCAN_THEME
from adscan_core.output._state import (
    _get_console,
    _get_telemetry_console,
    _mark_operation_details,
)
from adscan_core.output._display_paths import translate_paths_for_display
from adscan_core.output._log import BRAND_COLORS, _handle_spacing


def _resolve_border_style(console, border_style):
    """Return ``border_style`` if this console can render it, else the brand colour.

    Rich resolves a style NAME against the console's theme and raises
    ``MissingStyle`` when it is absent — at render time, so the exception
    escapes ``console.print`` and kills the caller's message. Panels are how
    ADscan delivers warnings the operator needs, so a style miss must degrade
    to the brand colour, never to a traceback.
    """
    if not isinstance(border_style, str):
        return border_style
    try:
        console.get_style(border_style)
    except Exception:  # noqa: BLE001 — MissingStyle and any future style error
        return BRAND_COLORS["info"]
    return border_style


def print_instruction(
    message: Union[str, Text], panel: bool = False, spacing: str = "auto"
):
    """Print an instruction message with dimmed style.

    Args:
        message: Message to display. Can be:
            - Plain string: "Enter your name"
            - Rich markup string: "[bold]Enter[/bold] your [dim]name[/dim]"
            - Text object: Text("Enter", style="bold")
        panel: If True, display in a panel with border
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
    """
    console = _get_console()
    _get_telemetry_console()

    message = translate_paths_for_display(message)

    # Handle spacing
    spacing_before = _handle_spacing("instruction", panel, spacing)
    if spacing_before:
        console.print()

    # Format message (preserves Rich markup or Text object)
    if isinstance(message, Text):
        message_text = message
    elif "[" in message and "]" in message:
        # Rich markup string - parse it
        message_text = Text.from_markup(message)
    else:
        # Plain string - apply default style
        message_text = Text(message, style="dim")

    if panel:
        panel_renderable = Panel(
            message_text, border_style="dim", box=ROUNDED, padding=(0, 1)
        )
        console.print(panel_renderable)
        # Panels always get space after
        if spacing != "none":
            console.print()
    else:
        output = Text("   ", style="dim")
        output.append(message_text)
        console.print(output)

        # Handle spacing after if requested
        if spacing in ("after", "both"):
            console.print()


def print_panel(
    content: Union[str, Text, Group, list[RenderableType], tuple[RenderableType, ...]],
    title: Optional[str] = None,
    subtitle: Optional[str] = None,
    title_align: Optional[str] = None,
    border_style: Optional[str] = None,
    box: Box = ROUNDED,
    padding: tuple = (1, 2),
    expand: bool = True,
    fit: bool = False,
    spacing: str = "auto",
):
    """Print a custom panel with full control over content and styling.

    This function provides a generic way to create panels with custom content,
    maintaining consistency with brand colors and intelligent spacing.

    Args:
        content: Panel content. Can be:
            - Plain string: "Simple content"
            - Rich markup string: "[bold]Content[/bold] with [red]markup[/red]"
            - Text object: Text("Content", style="bold")
            - Group object: Group(Text(...), Text(...)) for multiple renderables
            - List/tuple of renderables: [Table(...), Text(...)] (wrapped in Group)
        title: Optional panel title (supports Rich markup strings)
        title_align: Optional panel title alignment (e.g., "left", "center", "right")
        border_style: Border color style (defaults to brand color if None)
        box: Box style (MINIMAL, ROUNDED, etc.) - default: MINIMAL
        padding: Padding tuple (vertical, horizontal) - default: (0, 1)
        expand: Whether panel expands to full width - default: True
        fit: If True, use Panel.fit() to fit panel to content width (ignores expand/padding) - default: False
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"
            - "auto": Intelligent spacing (panels always get spacing)
            - "none": No spacing
            - "before": Space before panel
            - "after": Space after panel
            - "both": Space before and after

    Examples:
        # Simple panel with brand color
        print_panel("Simple content", title="Title")

        # Custom panel with Rich markup
        print_panel(
            "[bold]Domain[/bold]: example.local",
            title="[bold]Domain Information[/bold]",
            border_style=BRAND_COLORS["info"],
            expand=False
        )

        # Fit panel to content (like Panel.fit)
        print_panel(
            "Content that fits exactly",
            title="Fitted Panel",
            fit=True,
            border_style="yellow"
        )

        # Centered content panel
        from rich.text import Text
        content = Text("Centered", justify="center")
        print_panel(content, title="Centered Panel", box=ROUNDED)

        # Panel with Group (multiple renderables)
        from rich.console import Group
        group_content = Group(
            Text.from_markup("[bold]Title[/bold]"),
            Text("Body content")
        )
        print_panel(group_content, title="Group Panel")
    """
    console = _get_console()
    _get_telemetry_console()

    # Rewrite container paths in user-facing output so the path the user sees
    # matches what they can ``cat`` or open from their host shell. Panels carry
    # the money paths (report ready, workspace saved), and their content is
    # usually a Group of styled Text — which is exactly what a str-only rewrite
    # would miss.
    content = translate_paths_for_display(content)
    title = translate_paths_for_display(title)
    subtitle = translate_paths_for_display(subtitle)

    if title is not None and title_align is None:
        title_align = "center"

    # Use brand color as default border style. A style NAME (rather than a
    # colour) only resolves if the console's theme defines it, and Rich raises
    # MissingStyle at RENDER time — inside console.print, far from this call —
    # so an unthemed console anywhere upstream would turn the whole panel into
    # a traceback. Resolve it here, where a miss costs the brand colour instead
    # of the message.
    if border_style is None:
        border_style = BRAND_COLORS["info"]
    else:
        border_style = _resolve_border_style(console, border_style)

    # Handle spacing (panels always get spacing by default)
    spacing_before = _handle_spacing("info", True, spacing)
    if spacing_before:
        console.print()

    def _coerce_renderable(item: object) -> RenderableType:
        """Convert a supported value into a Rich renderable.

        This avoids Rich calling string-only APIs (e.g. `.translate`) on
        non-strings when callers accidentally pass lists of renderables.
        """
        if isinstance(item, Group):
            return item
        if isinstance(item, Text):
            return item
        if isinstance(item, str) and "[" in item and "]" in item:
            return Text.from_markup(item)
        if isinstance(item, str):
            return Text(item, style="white")
        # For any other Rich renderables (Table, Panel, etc.) pass-through.
        return item  # type: ignore[return-value]

    # Format content (preserves Rich markup, Text object, or Group)
    panel_content: RenderableType
    if isinstance(content, (list, tuple)):
        panel_content = Group(*[_coerce_renderable(item) for item in content])
    else:
        panel_content = _coerce_renderable(content)

    # Create panel (use Panel.fit if fit=True, otherwise regular Panel)
    if fit:
        panel = Panel.fit(
            panel_content,
            title=title,
            subtitle=subtitle,
            title_align=title_align,
            border_style=border_style,
            box=box,
            padding=padding,
        )
    else:
        panel = Panel(
            panel_content,
            title=title,
            subtitle=subtitle,
            title_align=title_align,
            border_style=border_style,
            box=box,
            padding=padding,
            expand=expand,
        )

    try:
        console.print(panel)
    except MissingStyle:
        # A theme style name inside the CONTENT (e.g. "[warning]⚠[/warning]")
        # resolves at render time against the console's theme. Retry under the
        # product theme rather than losing the message: an unthemed console is
        # the failure mode here, not a bad panel.
        with console.use_theme(ADSCAN_THEME):
            console.print(panel)

    # Handle spacing after
    if spacing != "none":
        if spacing in ("after", "both"):
            console.print()
        else:
            # Auto mode: panels always get space after
            console.print()


def print_system_change_warning(
    *,
    title: str,
    summary: str,
    planned_changes: List[str] | tuple[str, ...] = (),
    impact_notes: List[str] | tuple[str, ...] = (),
    cleanup_notes: List[str] | tuple[str, ...] = (),
    authorization_note: Optional[str] = None,
    border_style: str = "yellow",
    expand: bool = False,
) -> None:
    """Print a standardized warning panel for disruptive system changes.

    The implementation delegates to ``print_panel`` so telemetry and spacing
    follow the same path as the other high-level Rich output helpers.
    """
    content_lines: list[str] = [summary]

    if planned_changes:
        content_lines.extend(["", "Planned changes:"])
        content_lines.extend(
            f"- {item}" for item in planned_changes if str(item).strip()
        )

    if impact_notes:
        content_lines.extend(["", "Operational impact:"])
        content_lines.extend(f"- {item}" for item in impact_notes if str(item).strip())

    if cleanup_notes:
        content_lines.extend(["", "Cleanup notes:"])
        content_lines.extend(f"- {item}" for item in cleanup_notes if str(item).strip())

    if authorization_note:
        content_lines.extend(["", authorization_note])

    print_panel(
        "\n".join(content_lines),
        title=title,
        border_style=border_style,
        expand=expand,
    )


def print_section(
    title: str, content: str, border_style: str = "blue", icon: Optional[str] = None
):
    """Print a section with title and content in a panel.

    Args:
        title: Section title
        content: Section content
        border_style: Border color style
        icon: Optional icon to display before title
    """
    console = _get_console()
    _get_telemetry_console()

    title_text = Text()
    if icon:
        title_text.append(f"{icon} ", style=border_style)
    title_text.append(title, style=f"bold {border_style}")

    panel_content = Text()
    panel_content.append(f"{title_text}\n\n", style=border_style)
    panel_content.append(content, style="white")

    panel_renderable = Panel(
        panel_content, border_style=border_style, box=ROUNDED, padding=(1, 2)
    )
    console.print(panel_renderable)


def print_panel_with_table(
    table: Table,
    title: Optional[str] = None,
    border_style: Optional[str] = None,
    box: Box = ROUNDED,
    padding: tuple = (1, 2),
    expand: bool = True,
    spacing: str = "auto",
):
    """Print a Rich Table inside a Panel with consistent styling.

    This is useful for displaying tables in a visually distinct panel,
    such as installation summaries or configuration displays.

    Args:
        table: Rich Table object to display inside the panel
        title: Optional panel title (supports Rich markup strings)
        border_style: Border color style (defaults to brand color if None)
        box: Box style (MINIMAL, ROUNDED, etc.) - default: ROUNDED
        padding: Padding tuple (vertical, horizontal) - default: (1, 2)
        expand: Whether panel expands to full width - default: True
        spacing: Spacing control ("auto", "none", "before", "after", "both"). Default: "auto"

    Examples:
        from rich.table import Table
        table = Table()
        table.add_column("Item", style=BRAND_COLORS["info"])
        table.add_row("Value")
        print_panel_with_table(
            table,
            title="[bold]Installation Summary[/bold]",
            border_style="green"
        )
    """
    console = _get_console()
    _get_telemetry_console()

    # Use brand color as default border style
    if border_style is None:
        border_style = BRAND_COLORS["info"]

    # Handle spacing (panels always get spacing by default)
    spacing_before = _handle_spacing("info", True, spacing)
    if spacing_before:
        console.print()

    # Create panel with table inside
    panel = Panel(
        table,
        title=title,
        border_style=border_style,
        box=box,
        padding=padding,
        expand=expand,
    )

    console.print(panel)

    # Handle spacing after
    if spacing != "none":
        if spacing in ("after", "both"):
            console.print()
        else:
            # Auto mode: panels always get space after
            console.print()


def print_group(messages: List[tuple], group_title: Optional[str] = None):
    """Print a group of related messages together.

    Args:
        messages: List of tuples (message_type, message) where message_type is
            'info', 'success', 'warning', 'error'
        group_title: Optional title for the group
    """
    console = _get_console()
    _get_telemetry_console()
    group_items = []

    if group_title:
        title_text = Text(group_title, style=f"bold {BRAND_COLORS['info']}")
        group_items.append(title_text)
        group_items.append(Text(""))  # Empty line

    for msg_type, message in messages:
        if msg_type == "info":
            group_items.append(Text(f"ℹ {message}", style=BRAND_COLORS["info"]))
        elif msg_type == "success":
            group_items.append(Text(f"✓ {message}", style="green"))
        elif msg_type == "warning":
            group_items.append(Text(f"⚠ {message}", style="yellow"))
        elif msg_type == "error":
            group_items.append(Text(f"✗ {message}", style="bold red"))
        else:
            group_items.append(Text(message))

    if group_title:
        panel_renderable = Panel(
            Group(*group_items),
            border_style=BRAND_COLORS["info"],
            box=ROUNDED,
            padding=(1, 2),
        )
        console.print(panel_renderable)
    else:
        group_renderable = Group(*group_items)
        console.print(group_renderable)


def print_operation_header(
    operation: str,
    details: Optional[Dict[str, str]] = None,
    icon: str = "🔍",
) -> None:
    """Print a professional header for operations (scans, enumeration, etc.).

    Args:
        operation: Operation name (e.g., "SMB Scan", "Trust Enumeration")
        details: Optional dict of key-value details to display
        icon: Icon to display (default: 🔍)

    Example:
        >>> print_operation_header("SMB Scan", {"Target": "10.0.0.0/24", "Mode": "Unauthenticated"})
    """
    console = _get_console()
    _get_telemetry_console()

    # Build header content
    header_text = Text()
    header_text.append(f"{icon} ", style="bold")
    header_text.append(operation, style=f"bold {ADSCAN_PRIMARY}")

    if details:
        # Automatically mark sensitive values based on key patterns
        marked_details = _mark_operation_details(details)

        # Create a mini table for details
        details_table = Table.grid(padding=(0, 2))
        details_table.add_column(style="dim", justify="right")
        details_table.add_column(style="white")

        for key, value in marked_details.items():
            details_table.add_row(f"{key}:", value)

        content = Group(header_text, Text(""), details_table)
    else:
        content = header_text

    panel = Panel(
        content,
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
    )

    spacing_before = _handle_spacing("info", True, "auto")
    if spacing_before:
        console.print()

    console.print(panel)


def print_phase_header(
    phase_name: str,
    phase_number: Optional[int] = None,
    total_phases: Optional[int] = None,
    details: Optional[Dict[str, str]] = None,
    icon: str = "📍",
) -> None:
    """Print a professional phase header to group related scan operations.

    This function creates a visual separator between different phases of a scan workflow,
    helping users understand the overall progress and structure of the operation.

    Args:
        phase_name: Name of the phase (e.g., "Initial Reconnaissance", "Credential Attacks")
        phase_number: Current phase number (e.g., 1 for Phase 1/3)
        total_phases: Total number of phases in the workflow
        details: Optional dict of key-value details to display
        icon: Icon to display (default: 📍)

    Examples:
        # Simple phase header
        print_phase_header("Initial Reconnaissance")

        # With progress tracking
        print_phase_header("Credential Attacks", phase_number=2, total_phases=3)

        # With additional details
        print_phase_header(
            "Domain Enumeration",
            phase_number=1,
            total_phases=2,
            details={"Target": "example.local", "Mode": "Authenticated"}
        )
    """
    console = _get_console()
    _get_telemetry_console()

    # Build header text with phase progress
    header_text = Text()
    header_text.append(f"{icon} ", style="bold")

    if phase_number is not None and total_phases is not None:
        phase_info = f"Phase {phase_number}/{total_phases}: "
        header_text.append(phase_info, style=f"bold {ADSCAN_PRIMARY}")

    header_text.append(phase_name, style=f"bold {ADSCAN_PRIMARY}")

    # Create content for panel
    if details:
        details_table = Table.grid(padding=(0, 2))
        details_table.add_column(style="dim", justify="right")
        details_table.add_column(style="white")

        for key, value in details.items():
            details_table.add_row(f"{key}:", value)

        content = Group(header_text, Text(""), details_table)
    else:
        content = header_text

    # Create panel
    panel = Panel(
        content,
        border_style=ADSCAN_PRIMARY,
        padding=(1, 2),
        box=ROUNDED,
    )

    # Handle spacing
    spacing_before = _handle_spacing("info", True, "auto")
    if spacing_before:
        console.print()

    console.print(panel)


def print_step_status(
    step_name: str,
    status: str = "running",
    step_number: Optional[int] = None,
    total_steps: Optional[int] = None,
    details: Optional[str] = None,
) -> None:
    """Print a single step status in a scan workflow with professional styling.

    This function provides real-time feedback on individual steps within a phase,
    showing progress and current status to keep users informed.

    Args:
        step_name: Name of the step (e.g., "SMB Scan", "LDAP Enumeration")
        status: Step status - one of:
            - "starting": Step is about to start (⚡ yellow)
            - "running": Step is currently executing (⏳ cyan)
            - "completed": Step finished successfully (✓ green)
            - "failed": Step failed (✗ red)
            - "skipped": Step was skipped (○ dim)
            - "pending": Step is waiting (○ dim)
        step_number: Current step number (e.g., 1 for Step 1/5)
        total_steps: Total number of steps in this phase
        details: Optional additional details about the step

    Examples:
        # Simple step status
        print_step_status("SMB Scan", status="running")

        # With progress tracking
        print_step_status("LDAP Enumeration", status="completed", step_number=2, total_steps=5)

        # With additional details
        print_step_status(
            "Credential Validation",
            status="running",
            step_number=3,
            total_steps=5,
            details="Testing 15 credentials"
        )
    """
    console = _get_console()
    _get_telemetry_console()

    step_name = translate_paths_for_display(step_name)
    details = translate_paths_for_display(details)

    # Status styling
    status_styles = {
        "starting": ("⚡", "bold yellow"),
        "running": ("⏳", f"bold {ADSCAN_PRIMARY}"),
        "completed": ("✓ ", "bold green"),
        "failed": ("✗", "bold red"),
        "skipped": ("○", "dim"),
        "pending": ("○", "dim"),
    }

    icon, style = status_styles.get(status.lower(), ("•", "white"))

    # Build step text
    text = Text()
    text.append(f"{icon} ", style=style)

    # Add step progress if provided
    if step_number is not None and total_steps is not None:
        progress_text = f"[{step_number}/{total_steps}] "
        text.append(progress_text, style="dim")

    # Add step name
    text.append(f"{step_name} ", style=f"bold {ADSCAN_PRIMARY}")

    # Add status text
    status_text = status.title()
    text.append(status_text, style=style)

    # Add details if provided
    if details:
        text.append(" - ", style="dim")
        text.append(details, style="white")

    console.print(text)


__all__ = [
    "print_panel",
    "print_panel_with_table",
    "print_section",
    "print_phase_header",
    "print_operation_header",
    "print_step_status",
    "print_system_change_warning",
    "print_group",
    "print_instruction",
]
