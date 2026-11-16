"""A Rich table that degrades by design when the terminal is narrow.

A plain :class:`rich.table.Table` with more fixed-width columns than the
terminal can hold does not fail loudly: Rich shrinks the columns it can, and
the ones that cannot shrink any further are squeezed to nothing. At 80
columns the attack-path listing printed an empty route column, an empty
index column, a header made of a single ellipsis and status words cut in
half ("theoret…"). The trust matrix inside its summary panel cut every
domain name.

:class:`ResponsiveTable` decides the layout at RENDER time, from the width it
is actually given (``options.max_width``), so it behaves the same printed
straight to the console or nested inside a padded panel:

* Every column declares a PRIORITY. Priority 0 columns are never dropped; a
  higher number is dropped first.
* Each kept column is given its measured minimum width (its header and its
  longest word), so Rich never has to ellipsize a header or a status word.
* When the kept columns do not fit, the lowest-priority column is removed and
  its values are STACKED under the primary cell as one dim line
  (``Affected 1 · Target Computer``). Nothing the operator needs disappears;
  it moves to where it fits.
* A droppable column whose every cell is empty is never printed at all, so a
  table never shows a column of blanks.

The primary column (the route, the domain pair) wraps (``overflow="fold"``)
and takes the remaining width, so it is the one thing that always shows in
full.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from rich import box as rich_box
from rich.console import Console, ConsoleOptions, RenderResult
from rich.measure import Measurement
from rich.table import Table
from rich.text import Text

__all__ = ["ResponsiveColumn", "ResponsiveTable", "cell_is_empty"]


@dataclass(frozen=True)
class ResponsiveColumn:
    """One column of a :class:`ResponsiveTable`.

    Attributes:
        header: Column header. Never truncated: the column is dropped (and its
            values stacked) before its header would be cut.
        priority: 0 = always shown. Higher numbers are dropped first when the
            width runs out.
        stack_label: Prefix used when the column is stacked under the primary
            cell (``"Affected"`` renders ``Affected 1``). Empty = value only.
        min_width: Floor for the column width. For the primary column this is
            the width it is guaranteed before anything else is laid out.
        max_width: Cap on a secondary column's natural width (0 = none); a
            longer value wraps inside the column.
        style / justify: Passed to :meth:`rich.table.Table.add_column`.
    """

    header: str
    priority: int = 0
    stack_label: str = ""
    min_width: int = 0
    max_width: int = 0
    style: str | None = None
    justify: str = "left"


#: Placeholders that say "no value" — a column of only these is as empty as a
#: blank one, and stacking ``Latency —`` under a name is noise.
_NO_VALUE_PLACEHOLDERS = frozenset({"", "—", "-", "–"})


def cell_is_empty(cell: Any) -> bool:
    """True when ``cell`` renders nothing, or only a no-value placeholder."""
    if cell is None:
        return True
    if isinstance(cell, Text):
        return cell.plain.strip() in _NO_VALUE_PLACEHOLDERS
    if isinstance(cell, str):
        return _as_text(cell).plain.strip() in _NO_VALUE_PLACEHOLDERS
    return False


def _as_text(cell: Any) -> Text:
    if isinstance(cell, Text):
        return cell.copy()
    value = "" if cell is None else str(cell)
    try:
        return Text.from_markup(value)
    except Exception:  # noqa: BLE001 - a value that is not valid markup is literal
        return Text(value)


def _longest_word(cell: Any) -> int:
    plain = _as_text(cell).plain
    words = plain.split()
    return max((Text(w).cell_len for w in words), default=0)


@dataclass
class _Row:
    cells: list[Any]
    style: str | None = None
    end_section: bool = False


@dataclass
class ResponsiveTable:
    """A table that drops and stacks low-priority columns below its fit width.

    Args:
        columns: The column specs, in display order.
        primary: Index of the column that always shows in full and receives
            the stacked values of dropped columns.
        table_kwargs: Extra keyword arguments for :class:`rich.table.Table`
            (title, styles, box, ...). ``padding`` must be ``(0, n)``.
    """

    columns: Sequence[ResponsiveColumn]
    primary: int = 0
    table_kwargs: dict[str, Any] = field(default_factory=dict)
    rows: list[_Row] = field(default_factory=list)

    def add_row(
        self, *cells: Any, style: str | None = None, end_section: bool = False
    ) -> None:
        """Append a row (one cell per column)."""
        padded = list(cells) + [""] * (len(self.columns) - len(cells))
        self.rows.append(_Row(cells=padded, style=style, end_section=end_section))

    # ── layout ──────────────────────────────────────────────────────────────

    def _column_min(self, index: int) -> int:
        spec = self.columns[index]
        header_len = Text(spec.header).cell_len
        if index == self.primary:
            return max(spec.min_width, header_len)
        cells_min = max((_longest_word(r.cells[index]) for r in self.rows), default=0)
        return max(spec.min_width, header_len, cells_min)

    def _chrome(self, count: int) -> int:
        padding = self.table_kwargs.get("padding", (0, 1))
        if isinstance(padding, int):
            horizontal = padding
        else:
            horizontal = padding[1] if len(padding) in (2, 4) else padding[0]
        pad_edge = self.table_kwargs.get("pad_edge", True)
        show_edge = self.table_kwargs.get("show_edge", True)
        box = self.table_kwargs.get("box", rich_box.HEAVY_HEAD)
        pad = 2 * horizontal * count - (0 if pad_edge else 2 * horizontal)
        if box is None:
            borders = 0
        else:
            borders = (count + 1) if show_edge else max(0, count - 1)
        return pad + borders

    def layout(self, width: int) -> tuple[list[int], list[int]]:
        """Return ``(kept, stacked)`` column indexes for ``width`` cells."""
        kept = [
            i
            for i, spec in enumerate(self.columns)
            if spec.priority == 0
            or i == self.primary
            or any(not cell_is_empty(r.cells[i]) for r in self.rows)
        ]
        stacked: list[int] = []
        mins = {i: self._column_min(i) for i in kept}
        primary_cells = [r.cells[self.primary] for r in self.rows]

        def fits() -> bool:
            available = width - self._chrome(len(kept))
            secondary = sum(mins[i] for i in kept if i != self.primary)
            return secondary + self._primary_floor(available, primary_cells) <= available

        droppable = sorted(
            (i for i in kept if self.columns[i].priority > 0 and i != self.primary),
            key=lambda i: (self.columns[i].priority, i),
            reverse=True,
        )
        for index in droppable:
            if fits():
                break
            kept.remove(index)
            stacked.append(index)
        stacked.sort()
        return kept, stacked

    def _primary_floor(self, available: int, primary_cells: Sequence[Any]) -> int:
        """Width the primary column is owed before secondaries are kept.

        Enough to hold its longest word (a domain name, an FQDN) unbroken, but
        never more than half the table, so one pathological token cannot
        starve every other column.
        """
        return max(
            self._column_min(self.primary),
            min(
                max((_longest_word(c) for c in primary_cells), default=0),
                available // 2,
            ),
        )

    def _column_desired(self, index: int, cells: Sequence[Any]) -> int:
        """Widest single line of the column (header included), capped."""
        spec = self.columns[index]
        widest = Text(spec.header).cell_len
        for cell in cells:
            for line in _as_text(cell).plain.splitlines() or [""]:
                widest = max(widest, Text(line).cell_len)
        if spec.max_width:
            widest = min(widest, spec.max_width)
        return max(widest, self._column_min(index))

    def column_widths(
        self, width: int, kept: Sequence[int], primary_cells: Sequence[Any]
    ) -> dict[int, int]:
        """Exact content width per kept column for a ``width``-cell table.

        Rich's own collapse ignores ``min_width`` until after it has shrunk the
        columns, then re-inflates them, so a table it cannot fit overflows the
        terminal. The widths are therefore decided here and handed to Rich as
        fixed values: every secondary column gets its natural width (shrunk
        toward its minimum only when the primary would otherwise fall below
        its own), and the primary takes what is left, up to what it needs.
        """
        widths = {
            i: self._column_desired(i, [r.cells[i] for r in self.rows])
            for i in kept
            if i != self.primary
        }
        mins = {i: self._column_min(i) for i in kept}
        available = width - self._chrome(len(kept))
        primary_min = self._primary_floor(available, primary_cells)
        while available - sum(widths.values()) < primary_min:
            shrinkable = [i for i in widths if widths[i] > mins[i]]
            if not shrinkable:
                break
            widest = max(shrinkable, key=lambda i: widths[i] - mins[i])
            widths[widest] -= 1
        # Still too narrow with every droppable column gone (a terminal far
        # below 80 columns): fold the never-dropped columns too, down to their
        # headers, rather than overflow the terminal.
        hard_floor = {
            i: max(1, Text(self.columns[i].header).cell_len) for i in widths
        }
        primary_hard = max(
            1,
            self.columns[self.primary].min_width,
            Text(self.columns[self.primary].header).cell_len,
        )
        while available - sum(widths.values()) < primary_min:
            shrinkable = [i for i in widths if widths[i] > hard_floor[i]]
            if not shrinkable:
                primary_min = max(primary_hard, available - sum(widths.values()))
                break
            widest = max(shrinkable, key=lambda i: widths[i])
            widths[widest] -= 1
        primary_desired = max(
            primary_min,
            max(
                (
                    Text(line).cell_len
                    for cell in primary_cells
                    for line in (_as_text(cell).plain.splitlines() or [""])
                ),
                default=0,
            ),
            Text(self.columns[self.primary].header).cell_len,
        )
        remaining = available - sum(widths.values())
        widths[self.primary] = max(primary_min, min(primary_desired, remaining))
        return widths

    def build(self, width: int) -> Table:
        """Build the concrete :class:`Table` for ``width`` cells."""
        kept, stacked = self.layout(width)
        primary_cells = [self._primary_cell(row, stacked) for row in self.rows]
        widths = self.column_widths(width, kept, primary_cells)
        table = Table(**self.table_kwargs)
        for i in kept:
            spec = self.columns[i]
            table.add_column(
                spec.header,
                style=spec.style,
                justify=spec.justify,  # type: ignore[arg-type]
                width=widths[i],
                no_wrap=False,
                overflow="fold",
            )
        for row, primary_cell in zip(self.rows, primary_cells):
            cells = list(row.cells)
            cells[self.primary] = primary_cell
            table.add_row(
                *(cells[i] for i in kept), style=row.style, end_section=row.end_section
            )
        return table

    def _primary_cell(self, row: _Row, stacked: Sequence[int]) -> Any:
        """The primary cell, with the dropped columns' values stacked under it."""
        cells = row.cells
        extras = [
            (self.columns[i].stack_label, cells[i])
            for i in stacked
            if not cell_is_empty(cells[i])
        ]
        if not extras:
            return cells[self.primary]
        primary_cell = _as_text(cells[self.primary])
        line = Text(style="dim")
        for n, (label, value) in enumerate(extras):
            if n:
                line.append(" · ")
            if label:
                line.append(f"{label} ")
            line.append_text(_as_text(value))
        primary_cell.append("\n")
        primary_cell.append_text(line)
        return primary_cell

    # ── Rich protocol ───────────────────────────────────────────────────────

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:
        yield self.build(options.max_width)

    def __rich_measure__(
        self, console: Console, options: ConsoleOptions
    ) -> Measurement:
        table = self.build(options.max_width)
        return Measurement.get(console, options, table)

