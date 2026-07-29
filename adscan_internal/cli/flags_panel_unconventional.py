"""Premium "🏴‍☠️ UNCONVENTIONAL FLAG LOCATIONS" panel.

Rendered in addition to (not instead of) the standard FLAGS CAPTURED
panel whenever at least one hit was discovered outside the conventional
``\\Users\\<owner>\\Desktop\\`` Catalog. This is the screenshot artifact
for the CTF channel, the panel that proves ADscan dug deeper than the
box author expected.
"""

from __future__ import annotations

import rich.box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.outbound_links import ADSCAN_SITE_HOST
from adscan_internal.services.ctf_flag_collector import (
    FlagCollectionResult,
    FlagDiscoveryStrategy,
    FlagHit,
    WalkStats,
)
from adscan_internal.services.exploitation.dump_display import (
    ACID_GREEN,
    AMBER,
    GHOST,
    LAVA,
    MUTED,
)
from adscan_internal.services.ctf_flag_collector_catalog import WALK_DEPTH


# Panel width cap, keeps the panel screenshot-friendly on narrow terms.
_MAX_WIDTH = 96

# Glyph paired with the ACID_GREEN "kind" cell so the brag remains
# legible under NO_COLOR. Found-and-unconventional == captured loot.
_GLYPH_HIT = "✓"


def _discovery_label(hit: FlagHit) -> str:
    """Render a human-friendly label for the discovery method."""
    via = hit.discovered_via
    if via == FlagDiscoveryStrategy.CONVENTIONAL:
        return "conventional"
    if via == FlagDiscoveryStrategy.ALTERNATIVE:
        return "alternative"
    if via == FlagDiscoveryStrategy.SMB_WALK:
        return f"smb walk d={WALK_DEPTH}"
    return str(via)


def has_unconventional_hits(result: FlagCollectionResult) -> bool:
    """Return True when at least one hit comes from a non-Desktop strategy."""
    return any(
        h.discovered_via != FlagDiscoveryStrategy.CONVENTIONAL
        for h in result.hits
    )


def render_unconventional_panel(
    *,
    console: Console,
    result: FlagCollectionResult,
) -> None:
    """Render the unconventional-locations panel.

    Args:
        console: Rich console.
        result: Output of :func:`collect_ctf_flags`. Only hits whose
            ``discovered_via`` is not :attr:`FlagDiscoveryStrategy.CONVENTIONAL`
            are surfaced.
    """
    unconv = [
        h for h in result.hits
        if h.discovered_via != FlagDiscoveryStrategy.CONVENTIONAL
    ]
    if not unconv:
        return

    title = Text("🏴‍☠️  UNCONVENTIONAL FLAG LOCATIONS", style=f"bold {LAVA}")

    inner = Table.grid(padding=(0, 0))
    inner.add_column()

    # Tagline. Narrative, sets up the brag.
    inner.add_row(
        Text(
            "The box author hid these flags outside the Desktop. ADscan found them.",
            style=MUTED,
        )
    )
    inner.add_row(Text(""))

    table = Table(
        box=rich.box.SIMPLE,
        show_edge=False,
        pad_edge=False,
        expand=False,
    )
    table.add_column("kind", style=ACID_GREEN, no_wrap=True)
    table.add_column("discovery", style=AMBER, no_wrap=True)
    table.add_column("path", style="white", overflow="fold")
    table.add_column("flag (sha256)", style=ACID_GREEN, no_wrap=True)

    for hit in unconv:
        table.add_row(
            Text(f"{_GLYPH_HIT} {hit.kind}", style=f"bold {ACID_GREEN}"),
            Text(_discovery_label(hit), style=AMBER),
            Text(hit.path, style="white"),
            Text(hit.flag_hash, style=f"bold {ACID_GREEN}"),
        )

    inner.add_row(table)
    inner.add_row(Text(""))

    walk_stats: WalkStats | None = result.walk_stats
    if walk_stats is not None:
        stats_line = (
            f"Walk stats: {walk_stats.files_scanned} files scanned  ·  "
            f"{walk_stats.dirs_traversed} dirs traversed  ·  "
            f"{walk_stats.dirs_excluded} dirs excluded"
        )
        inner.add_row(Text(stats_line, style=MUTED))

        if walk_stats.hit_max_entries:
            inner.add_row(Text(""))
            inner.add_row(
                Text(
                    "⚠  Walk stopped at the entry cap: host has more files than "
                    "searched.",
                    style=AMBER,
                )
            )
            inner.add_row(
                Text(
                    "    A flag may exist deeper. Try: get_flags <domain> --deep",
                    style=AMBER,
                )
            )

    inner.add_row(Text(""))
    inner.add_row(
        Text(
            f"{ADSCAN_SITE_HOST}  ·  ctf  ·  native aiosmb deep scan",
            style=MUTED,
        )
    )

    panel = Panel(
        inner,
        title=title,
        title_align="left",
        border_style=GHOST,
        box=rich.box.DOUBLE_EDGE,
        padding=(1, 2),
        width=_MAX_WIDTH,
        expand=False,
    )
    console.print(panel)


__all__ = ["has_unconventional_hits", "render_unconventional_panel"]
