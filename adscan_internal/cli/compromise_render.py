"""Premium CLI rendering for the canonical compromise taxonomy.

Aesthetic direction: editorial-forensic. Hairline separators, tabular
numerals, restrained color. One crimson reserved for the
``DOMAIN COMPROMISED`` terminus and Domain Breaker class, never used
for decoration. The terminus also carries a ``★`` glyph so the
jackpot frame remains legible under NO_COLOR / monochrome terminals
(skill ``tui-design`` § Accessibility, "Never use color alone").

Pentester audience sees technical edge labels by default;
``audience="executive"`` translates edges to the business vocabulary
documented in
``adscan-obsidian/business/12_nomenclature_standard.md``.

Surfaces consumed by:
- ``adscan_internal/cli/attack_graph_reports.py`` (KPI panel +
  per-path summary)
- any future CLI flow that exposes attack paths to the operator
"""

from __future__ import annotations

from typing import Any, Literal, Sequence

from rich import box
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.theme import COLOR_CRIMSON
from adscan_internal.services.compromise_class import (
    CompromiseClass,
    compromise_reach_label,
    tier_glossary,
)
from adscan_internal.services.edge_phrasing import translate_edge


Audience = Literal["technical", "executive"]


# Visual landmark for the ``DOMAIN COMPROMISED`` terminus. Paired with
# the crimson style so NO_COLOR renderings still flag the jackpot row.
_TERMINUS_GLYPH: str = "★"
_DOMAIN_TERMINUS_LABEL: str = f"{_TERMINUS_GLYPH} DOMAIN COMPROMISED"
_TERMINUS_STYLE: str = f"bold {COLOR_CRIMSON}"

# Style tokens, single source of truth for CLI output. Keep restrained:
# Domain Breaker = crimson (the only place red appears, by design).
# Privileged Escalator = amber. Compromise Enabler = cyan.
_CLASS_STYLE: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: f"bold {COLOR_CRIMSON}",
    # Tier 0 Foothold: distinct from amber (Privileged Escalator) and
    # crimson (Domain Breaker). Bright magenta reads as urgent without
    # colliding with either neighbour on the severity ramp.
    CompromiseClass.TIER0_FOOTHOLD: "bold magenta",
    CompromiseClass.PRIVILEGED_ESCALATOR: "bold yellow",
    CompromiseClass.COMPROMISE_ENABLER: "bold cyan",
    CompromiseClass.NONE: "dim",
}

_KPI_HEADERS: tuple[str, str, str, str] = ("CLASS", "ACCOUNTS", "PATHS", "REACH")


def class_badge(klass: CompromiseClass, *, audience: Audience = "technical") -> Text:
    """Return a styled badge for one compromise class.

    Technical audience: ``[T0/Domain Breaker]`` style with bracket.
    Executive audience: bare display label without bracket.
    """
    style = _CLASS_STYLE[klass]
    if audience == "executive":
        return Text(klass.display_label, style=style)
    return Text(klass.cli_badge, style=style)


def class_reach(klass: CompromiseClass) -> Text:
    """Return the axis-2 Compromise Reach phrase for one class, styled dim.

    Translates from the SSOT :func:`compromise_reach_label` so the CLI shows
    the SAME reach vocabulary the report and web carry. Pairs with
    :func:`class_badge`: the badge is the technical class, the reach phrase is
    the shared plain-language axis.
    """
    return Text(compromise_reach_label(klass), style="dim")


def render_kpi_panel(
    *,
    domain_breaker: tuple[int, int],
    privileged_escalator: tuple[int, int],
    compromise_enabler: tuple[int, int],
    tier0_foothold: tuple[int, int] = (0, 0),
    audience: Audience = "technical",
    title: str = "Compromise Exposure",
) -> Panel:
    """Return a Rich Panel summarizing the canonical compromise classes.

    Each class contributes one row showing account count and confirmed
    path count. Tabular figures keep numerals aligned. Class color is
    reserved: it appears only on the badge, never on the numerals.
    Rows are ordered highest-impact-wins:
    Domain Breaker, Tier 0 Foothold, Privileged Escalator, Compromise Enabler.

    Args:
        domain_breaker: Tuple of ``(account_count, path_count)``.
        privileged_escalator: Tuple of ``(account_count, path_count)``.
        compromise_enabler: Tuple of ``(account_count, path_count)``.
        tier0_foothold: Tuple of ``(account_count, path_count)`` for the
            new auth-edge-to-Tier0 bucket. Defaults to ``(0, 0)`` so
            existing call sites that have not yet wired the foothold
            data keep working without breakage.
        audience: Selects badge style. Default ``"technical"``.
        title: Panel title. Defaults to "Compromise Exposure".
    """
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="dim bold",
        pad_edge=False,
        padding=(0, 2),
        expand=False,
    )
    for header in _KPI_HEADERS:
        if header == "CLASS" or header == "REACH":
            justify = "left"
        else:
            justify = "right"
        # The REACH column carries a full phrase; keep it wrap-free off.
        table.add_column(header, justify=justify, no_wrap=header != "REACH")

    rows: Sequence[tuple[CompromiseClass, tuple[int, int]]] = (
        (CompromiseClass.DOMAIN_BREAKER, domain_breaker),
        (CompromiseClass.TIER0_FOOTHOLD, tier0_foothold),
        (CompromiseClass.PRIVILEGED_ESCALATOR, privileged_escalator),
        (CompromiseClass.COMPROMISE_ENABLER, compromise_enabler),
    )
    for klass, (accounts, paths) in rows:
        table.add_row(
            class_badge(klass, audience=audience),
            Text(f"{accounts:>4d}", style="bold"),
            Text(f"{paths:>4d}", style="bold"),
            class_reach(klass),
        )

    return Panel(
        table,
        title=Text(title, style="bold"),
        title_align="left",
        border_style="dim",
        box=box.SQUARE,
        padding=(1, 2),
    )


def render_path_chain(
    *,
    nodes: Sequence[str],
    edges: Sequence[str],
    klass: CompromiseClass,
    n_hop: int,
    path_id: str | None = None,
    audience: Audience = "technical",
) -> Group:
    """Return a Rich Group rendering one attack path.

    The chain always terminates at ``DOMAIN COMPROMISED``, the canonical
    terminus enforced by the standard. The pentester (``technical``) sees
    raw edge labels; the executive view translates each edge.

    Args:
        nodes: Ordered node labels along the path. The final caller-supplied
            node is replaced visually by the canonical terminus.
        edges: Edge labels between consecutive nodes. ``len(edges) ==
            len(nodes) - 1``. Edges are rendered between nodes.
        klass: Compromise class used for the path badge.
        n_hop: Path length in edges (shortest-path metric).
        path_id: Optional caller-supplied identifier shown next to the
            badge (e.g. ``"#42"``).
        audience: Selects edge label style. Default ``"technical"``.
    """
    if len(nodes) < 2:
        raise ValueError("render_path_chain requires at least two nodes")
    if len(edges) != len(nodes) - 1:
        raise ValueError("render_path_chain requires len(edges) == len(nodes) - 1")

    header_parts: list[Text] = [class_badge(klass, audience=audience)]
    if path_id:
        header_parts.append(Text(f" {path_id}", style="dim"))
    header_parts.append(Text(f"  {n_hop}-hop", style="dim"))
    header = Text.assemble(*header_parts)

    chain_lines: list[Text] = []
    last_index = len(nodes) - 1
    for index, node in enumerate(nodes):
        is_terminus = index == last_index
        if is_terminus:
            node_text = Text(_DOMAIN_TERMINUS_LABEL, style=_TERMINUS_STYLE)
        else:
            node_text = Text(str(node), style="bold")
        chain_lines.append(node_text)

        if not is_terminus:
            edge_raw = str(edges[index])
            edge_label = (
                translate_edge(edge_raw) if audience == "executive" else edge_raw
            )
            edge_text = Text.assemble(
                Text("  └─ ", style="dim"),
                Text(
                    edge_label,
                    style="italic dim" if audience == "executive" else "italic",
                ),
                Text("  ─┐", style="dim"),
            )
            chain_lines.append(edge_text)

    return Group(header, Text(""), *chain_lines)


def render_path_summary_line(
    *,
    klass: CompromiseClass,
    n_hop: int,
    source: str,
    primary_edge: str,
    audience: Audience = "technical",
) -> Text:
    """Return a one-line path summary for dense list rendering.

    Format (technical):
        ``[T0/Domain Breaker] alice -> DCSync -> ★ DOMAIN COMPROMISED  (1-hop)``
    Format (executive):
        ``Domain Breaker  alice -> Credential replication -> Domain  (1-hop)``
    """
    badge = class_badge(klass, audience=audience)
    edge_label = (
        translate_edge(primary_edge) if audience == "executive" else primary_edge
    )
    if audience == "technical":
        terminus_label = _DOMAIN_TERMINUS_LABEL
        terminus_style = _TERMINUS_STYLE
    else:
        terminus_label = "Domain"
        terminus_style = f"bold {COLOR_CRIMSON}"
    arrow = " -> "
    return Text.assemble(
        badge,
        Text("  ", style=""),
        Text(source, style="bold"),
        Text(arrow, style="dim"),
        Text(edge_label, style="italic"),
        Text(arrow, style="dim"),
        Text(terminus_label, style=terminus_style),
        Text(f"  ({n_hop}-hop)", style="dim"),
    )


def render_tiering_legend(*, title: str = "Tiering legend") -> Panel:
    """Return a compact legend explaining the Privilege Tiers (axis 1).

    The content is pulled verbatim from the SSOT :func:`tier_glossary` so the
    operator reads the SAME tier definitions the client report and web carry.
    One row per tier, ordered most-privileged-first, with the canonical label
    and a one-line meaning. Rendered restrained: the tier label is the only
    styled cell, the meaning is dim body text.
    """
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="dim bold",
        pad_edge=False,
        padding=(0, 2),
        expand=False,
    )
    table.add_column("TIER", justify="left", no_wrap=True)
    table.add_column("MEANS", justify="left", overflow="fold")

    # Map each glossary tier value to a restrained accent so the legend reads
    # on the same severity ramp as the KPI panel without inventing new colors.
    tier_styles: dict[str, str] = {
        "tier0_direct": f"bold {COLOR_CRIMSON}",
        "tier0_escalation_capable": "bold yellow",
        "tier1": "bold cyan",
        "tier2": "dim",
    }
    for entry in tier_glossary():
        style = tier_styles.get(entry.get("tier", ""), "default")
        table.add_row(
            Text(entry.get("label", ""), style=style),
            Text(entry.get("meaning", ""), style="dim"),
        )

    return Panel(
        table,
        title=Text(title, style="bold"),
        title_align="left",
        border_style="dim",
        box=box.SQUARE,
        padding=(1, 2),
    )


def coerce_class(raw: Any) -> CompromiseClass:
    """Coerce stored payload values into a :class:`CompromiseClass`.

    Accepts the enum, the canonical string value, or the legacy
    outcome-class strings that may still appear in older snapshots.
    Returns :attr:`CompromiseClass.NONE` for unknown inputs rather than
    raising: render code must never crash on unrecognized data.
    """
    if isinstance(raw, CompromiseClass):
        return raw
    value = str(raw or "").strip().lower()
    if not value:
        return CompromiseClass.NONE
    try:
        return CompromiseClass(value)
    except ValueError:
        pass
    legacy_map = {
        "direct_domain_control": CompromiseClass.DOMAIN_BREAKER,
        "domain_compromise_enabler": CompromiseClass.PRIVILEGED_ESCALATOR,
        "high_impact_privilege": CompromiseClass.PRIVILEGED_ESCALATOR,
    }
    return legacy_map.get(value, CompromiseClass.NONE)


__all__ = [
    "Audience",
    "class_badge",
    "class_reach",
    "coerce_class",
    "render_kpi_panel",
    "render_path_chain",
    "render_path_summary_line",
    "render_tiering_legend",
]
