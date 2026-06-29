"""Generic Rich renderer for the shared widget contract.

This is the CLI half of "one definition, both renderers". It renders any
:class:`~adscan_internal.cli.widgets.widget_contract.Widget` payload —
``finding-table`` / ``kpi-strip`` / ``matrix-panel`` — as a Rich panel, with
zero knowledge of which feature produced the data. Adding a panel of an
existing widget type needs no code here: the engine builds the payload and
calls ``publish_widget`` / ``build_widget``; this renderer draws it.

The web counterpart (``adscan_web/frontend/components/widgets/``) renders the
exact same payload. The two never hand-build the same panel twice.

Severity / state tones are the closed vocabularies from the contract
(:data:`SEVERITY_TOKENS`, :data:`STATE_TONES`); they are mapped to Rich styles
here and to CSS tokens on the web — the data carries neither.
"""

from __future__ import annotations

from typing import Any

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from adscan_internal.rich_output import BRAND_COLORS, print_panel, print_panel_with_table

# Fixed-width severity badges — the badge text alone communicates severity
# (NO_COLOR / colourblind safe), colour reinforces it. Mirrors the legacy
# hygiene-panel badges so the converted panel reads identically.
_SEVERITY_BADGE: dict[str, str] = {
    "critical": "[bold red]CRITICAL[/bold red]",
    "high": "[red]HIGH    [/red]",
    "medium": "[yellow]MEDIUM  [/yellow]",
    "low": "[cyan]LOW     [/cyan]",
    "info": "[dim]INFO    [/dim]",
}
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# State-tone → Rich style for matrix-panel rows and KPI tone.
_TONE_STYLE: dict[str, str] = {
    "secure": "green",
    "permissive": "yellow",
    "neutral": "dim",
    "unknown": "dim",
}
_TONE_ICON: dict[str, str] = {
    "secure": "[green]✓[/green]",
    "permissive": "[yellow]✗[/yellow]",
    "neutral": "[dim]•[/dim]",
    "unknown": "[dim]○[/dim]",
}

# Border colour by widget type — keeps the three shapes visually distinct
# while staying inside the brand palette.
_BORDER_BY_TYPE: dict[str, str] = {
    "finding-table": BRAND_COLORS["info"],
    "kpi-strip": BRAND_COLORS.get("primary", BRAND_COLORS["info"]),
    "matrix-panel": "green",
}


def render_widget(payload: dict[str, Any]) -> None:
    """Render one widget payload as a Rich panel (auto-mirrored to telemetry).

    Dispatches on ``payload["widget_type"]``. Unknown types are rendered as a
    minimal info panel rather than dropped, so a forward-compatible engine
    never produces a blank where a panel should be.

    Args:
        payload: A widget envelope (``to_payload()`` shape): ``widget_type``,
            ``title``, ``data``, optional ``domain``.
    """
    widget_type = str(payload.get("widget_type") or "")
    title = str(payload.get("title") or "Widget")
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    border = _BORDER_BY_TYPE.get(widget_type, BRAND_COLORS["info"])

    if widget_type == "finding-table":
        _render_finding_table(title, data, border)
    elif widget_type == "kpi-strip":
        _render_kpi_strip(title, data, border)
    elif widget_type == "matrix-panel":
        _render_matrix_panel(title, data, border)
    else:
        print_panel(
            "[dim]No renderer for this widget type.[/dim]",
            title=title,
            border_style=border,
        )


def _render_finding_table(title: str, data: dict[str, Any], border: str) -> None:
    rows = data.get("rows") if isinstance(data.get("rows"), list) else []
    footnote = str(data.get("footnote") or "")

    ordered = sorted(
        (r for r in rows if isinstance(r, dict)),
        key=lambda r: _SEVERITY_ORDER.get(str(r.get("severity") or "info"), 9),
    )

    lines: list[str] = []
    for row in ordered:
        sev = str(row.get("severity") or "info")
        badge = _SEVERITY_BADGE.get(sev, sev)
        label = str(row.get("label") or "")
        value = str(row.get("value") or "")
        priv = int(row.get("privileged_count") or 0)
        priv_suffix = f"  [red]({priv} privileged)[/red]" if priv > 0 else ""
        value_part = f": [bold]{value}[/bold]" if value else ""
        lines.append(f"{badge}  {label}{value_part}{priv_suffix}")

    body_lines: list[str] = []
    if lines:
        body_lines.append(f"[bold]Findings ({len(lines)})[/bold]")
        body_lines.extend(f"  {line}" for line in lines)
    else:
        body_lines.append("[dim]No findings.[/dim]")
    if footnote:
        body_lines.append("")
        body_lines.append(f"[dim]{footnote}[/dim]")

    print_panel("\n".join(body_lines), title=title, border_style=border)


def _render_kpi_strip(title: str, data: dict[str, Any], border: str) -> None:
    items = data.get("items") if isinstance(data.get("items"), list) else []
    table = Table.grid(padding=(0, 3))
    valid = [i for i in items if isinstance(i, dict)]
    for _ in valid:
        table.add_column(justify="left")

    value_cells: list[RenderableType] = []
    label_cells: list[RenderableType] = []
    for item in valid:
        tone = str(item.get("tone") or "neutral")
        style = _TONE_STYLE.get(tone, "white")
        value = str(item.get("value") or "")
        unit = str(item.get("unit") or "")
        value_text = Text()
        value_text.append(value, style=f"bold {style}")
        if unit:
            value_text.append(f" {unit}", style="dim")
        value_cells.append(value_text)
        label = str(item.get("label") or "")
        hint = str(item.get("hint") or "")
        label_text = Text()
        label_text.append(label, style="dim")
        if hint:
            label_text.append(f"  {hint}", style="dim")
        label_cells.append(label_text)

    if value_cells:
        table.add_row(*value_cells)
        table.add_row(*label_cells)
        print_panel_with_table(table, title=title, border_style=border)
    else:
        print_panel("[dim]No metrics.[/dim]", title=title, border_style=border)


def _render_matrix_panel(title: str, data: dict[str, Any], border: str) -> None:
    sections = data.get("sections") if isinstance(data.get("sections"), list) else []
    groups: list[RenderableType] = []

    for section in sections:
        if not isinstance(section, dict):
            continue
        label = str(section.get("label") or "")
        section_rows = (
            section.get("rows") if isinstance(section.get("rows"), list) else []
        )
        if label:
            groups.append(Text(label, style="bold"))
        table = Table.grid(padding=(0, 2))
        table.add_column(width=2)
        table.add_column(no_wrap=False)
        table.add_column(style="dim")
        table.add_column(style="dim")
        any_row = False
        for row in section_rows:
            if not isinstance(row, dict):
                continue
            any_row = True
            tone = str(row.get("state_tone") or "neutral")
            icon = _TONE_ICON.get(tone, "[dim]•[/dim]")
            row_label = str(row.get("label") or "")
            state = str(row.get("state") or "")
            confidence = str(row.get("confidence") or "")
            table.add_row(
                Text.from_markup(icon),
                Text(row_label),
                Text(state, style=_TONE_STYLE.get(tone, "dim")),
                Text(confidence),
            )
        if not any_row:
            table.add_row(Text("○", style="dim"), Text("none", style="dim"), "", "")
        groups.append(table)
        groups.append(Text())

    if groups:
        # Drop the trailing blank line for a tight panel.
        if isinstance(groups[-1], Text) and not groups[-1].plain:
            groups.pop()
        print_panel_with_table(Group(*groups), title=title, border_style=border)
    else:
        print_panel("[dim]No controls observed.[/dim]", title=title, border_style=border)


__all__ = ["render_widget"]
