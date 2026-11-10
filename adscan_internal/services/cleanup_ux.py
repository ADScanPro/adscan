"""Rich terminal UX for environment change ledger summary display."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.console import Group
from rich.table import Table
from rich.text import Text

from adscan_core.reporting.cleanup_outcome import (
    OUTCOME_COPY,
    OUTCOME_FAILED,
    OUTCOME_ORDER,
    OUTCOME_REVERTED,
    client_revert_error,
    cleanup_outcome,
    revert_attempt_rows,
)
from adscan_core.reporting.cleanup_remediation import remediation_steps
from adscan_internal.rich_output import mark_sensitive, print_panel
from adscan_internal.services import cleanup_taxonomy as _tax

if TYPE_CHECKING:
    from adscan_internal.services.environment_change_ledger import EnvironmentChangeLedger

# All status/kind vocabulary is the SSOT in cleanup_taxonomy; never re-derived here.
# Outcome tones (cleanup_outcome.OutcomeCopy.tone) onto terminal styles: the four
# outcomes a client must tell apart never share a style.
_OUTCOME_STYLE: dict[str, str] = {
    "error": "bold red",
    "access": "bold blue",
    "check": "bold yellow",
    "action": "bold magenta",
    "neutral": "bold cyan",
    "pending": "bold white",
}
_OUTCOME_ICON: dict[str, str] = {
    "error": "✗",
    "access": "◇",
    "check": "?",
    "action": "⚠",
    "neutral": "★",
    "pending": "…",
}
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

    # Everything still in place, grouped by WHY, with the copy the reports and
    # the platform use (adscan_core.reporting.cleanup_outcome): a revert that
    # failed with the rights to do it never reads like a missing account.
    still_in_place = kept + needs_action
    by_outcome: dict[str, list[dict[str, Any]]] = {}
    for c in still_in_place:
        key = cleanup_outcome(
            {
                "bucket": _tax.cleanup_bucket(c.get("revert_status")),
                "manual_reason": c.get("manual_reason"),
            }
        )
        by_outcome.setdefault(key, []).append(c)
    for key in OUTCOME_ORDER:
        group = by_outcome.get(key)
        if key == OUTCOME_REVERTED or not group:
            continue
        copy = OUTCOME_COPY[key]
        style = _OUTCOME_STYLE.get(copy.tone, "bold")
        if renderables:
            renderables.append(Text(""))
        count = len(group)
        renderables.append(
            Text(
                f"{_OUTCOME_ICON.get(copy.tone, '•')} {copy.title.upper():<44} "
                f"{count} change{'s' if count != 1 else ''}",
                style=style,
            )
        )
        renderables.append(Text(copy.explanation, style="dim"))
        if copy.next_step:
            renderables.append(Text(copy.next_step))
        if copy.cta_where:
            renderables.append(Text(copy.cta_where, style="dim"))
        renderables.append(
            _build_changes_table(group, show_instructions=True, show_failure=key == OUTCOME_FAILED)
        )

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


def _instructions_text(instructions: str) -> Text:
    """Render a cleanup instruction as prose lines followed by their command lines.

    The explanation is dim prose and the command lines are plain, so what a
    client copies is never mixed with a ``#`` comment.
    """
    text = Text("")
    first = True
    for step in remediation_steps(instructions):
        intro = step["intro"].strip()
        if intro:
            text.append(("→ " if first else "") + intro + "\n", style="dim")
            first = False
        for line in step["command"].splitlines():
            if line.strip():
                text.append(f"  {line.strip()}\n")
                first = False
    text.rstrip()
    return text


def _failure_text(change: dict[str, Any]) -> Text:
    """The recorded reason and the accounts a failed revert tried."""
    text = Text("")
    label = _tax.manual_reason_label(change.get("manual_reason"))
    if label:
        text.append(label + "\n", style="red")
    error = client_revert_error(change.get("revert_error"))
    if error:
        text.append("Recorded reason: ", style="bold")
        text.append(mark_sensitive(error, "text") + "\n")
    for row in revert_attempt_rows(change.get("revert_credential_attempts")):
        account = f" ({mark_sensitive(row['account'], 'user')})" if row["account"] else ""
        text.append(f"Tried {row['role_label']}{account}: {row['outcome_label']}\n", style="dim")
    return text


def _build_changes_table(
    changes: list[dict[str, Any]], *, show_instructions: bool, show_failure: bool = False
) -> _ChangesTable:
    """Build a Rich Table of change entries.

    Args:
        changes: List of change dictionaries from the ledger.
        show_instructions: Whether to include the manual cleanup instructions column.
        show_failure: Whether to lead the instructions with the recorded reason
            and the accounts a failed revert tried.

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
            instr_text = _instructions_text(instructions)
            if show_failure:
                instr_text = Text.assemble(_failure_text(change), instr_text)
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
