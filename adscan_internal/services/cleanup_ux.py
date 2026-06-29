"""Rich terminal UX for environment change ledger summary display."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.console import Group
from rich.table import Table
from rich.text import Text

from adscan_internal.rich_output import mark_sensitive, print_panel
from adscan_internal.services import cleanup_taxonomy as _tax

if TYPE_CHECKING:
    from adscan_internal.services.environment_change_ledger import EnvironmentChangeLedger

# All status/kind vocabulary is the SSOT in cleanup_taxonomy; never re-derived here.
_STATUS_ICON = _tax.STATUS_ICON
_STATUS_STYLE = _tax.STATUS_STYLE
_KIND_DISPLAY = _tax.KIND_DISPLAY


class _ChangesTable(Table):
    """Rich Table subclass that exposes ``column_count`` as a convenience property."""

    @property
    def column_count(self) -> int:
        """Return the number of columns currently defined in the table."""
        return len(self.columns)


def render_cleanup_exit_panel(ledger: "EnvironmentChangeLedger") -> None:
    """Render the cleanup summary panel at scan exit. No-op when no changes.

    Args:
        ledger: EnvironmentChangeLedger instance with recorded changes.
    """
    changes = ledger.get_changes()
    if not changes:
        return

    summary = ledger.get_summary()
    by_bucket: dict[str, list[dict[str, Any]]] = {
        _tax.CLEANUP_BUCKET_REVERTED: [],
        _tax.CLEANUP_BUCKET_MANUAL: [],
        _tax.CLEANUP_BUCKET_KEPT: [],
        _tax.CLEANUP_BUCKET_IN_PROGRESS: [],
    }
    for c in changes:
        by_bucket[_tax.cleanup_bucket(c.get("revert_status"))].append(c)
    reverted = by_bucket[_tax.CLEANUP_BUCKET_REVERTED]
    kept = by_bucket[_tax.CLEANUP_BUCKET_KEPT]
    # Anything not yet on the good/kept side needs the client's attention.
    needs_action = (
        by_bucket[_tax.CLEANUP_BUCKET_MANUAL]
        + by_bucket[_tax.CLEANUP_BUCKET_IN_PROGRESS]
    )

    renderables: list[Any] = []

    if reverted:
        count = len(reverted)
        renderables.append(
            Text(
                f"✓ REVERTED (CONFIRMED)            {count} change{'s' if count != 1 else ''}",
                style="bold green",
            )
        )
        renderables.append(_build_changes_table(reverted, show_instructions=False))

    if kept:
        if renderables:
            renderables.append(Text(""))
        count = len(kept)
        renderables.append(
            Text(
                f"★ KEPT BY OPERATOR                {count} change{'s' if count != 1 else ''}",
                style="bold cyan",
            )
        )
        renderables.append(_build_changes_table(kept, show_instructions=False))

    if needs_action:
        if renderables:
            renderables.append(Text(""))
        count = len(needs_action)
        renderables.append(
            Text(
                f"⚠ REQUIRES MANUAL CLEANUP         {count} change{'s' if count != 1 else ''}",
                style="bold red",
            )
        )
        renderables.append(_build_changes_table(needs_action, show_instructions=True))

    manual_count = summary.get("manual_required", summary.get("failed", 0))
    in_progress_count = summary.get("in_progress", summary.get("pending", 0))
    border_style = "green"
    if manual_count > 0:
        border_style = "red"
    elif in_progress_count > 0:
        border_style = "yellow"
    elif kept and not reverted:
        border_style = "cyan"

    print_panel(
        Group(*renderables),
        title="ENVIRONMENT CHANGES — CLEANUP REPORT",
        border_style=border_style,
        expand=False,
        spacing="before",
    )


def _build_changes_table(changes: list[dict[str, Any]], *, show_instructions: bool) -> _ChangesTable:
    """Build a Rich Table of change entries.

    Args:
        changes: List of change dictionaries from the ledger.
        show_instructions: Whether to include the manual cleanup instructions column.

    Returns:
        Populated _ChangesTable (subclass of Table) ready for rendering.
    """
    table = _ChangesTable(show_header=False, box=None, padding=(0, 1, 0, 0))
    table.add_column("icon", width=3, no_wrap=True)
    table.add_column("kind", min_width=18, no_wrap=True)
    table.add_column("target", min_width=30)
    if show_instructions:
        table.add_column("instructions")

    for change in changes:
        status = str(change.get("revert_status") or "pending")
        icon = _STATUS_ICON.get(status, "?")
        style = _STATUS_STYLE.get(status, "")
        kind_raw = str(change.get("kind") or "")
        kind_display = _KIND_DISPLAY.get(kind_raw, kind_raw)
        target = mark_sensitive(str(change.get("target") or ""), "text")

        if show_instructions:
            instructions = str(
                change.get("remediation_command")
                or change.get("manual_cleanup_instructions")
                or ""
            )
            instr_text = Text(f"→ {instructions}", style="dim") if instructions else Text("")
            table.add_row(
                Text(icon, style=style),
                Text(kind_display, style=style),
                Text(target, style=style),
                instr_text,
            )
        else:
            table.add_row(
                Text(icon, style=style),
                Text(kind_display, style=style),
                Text(target, style=style),
            )

    return table
