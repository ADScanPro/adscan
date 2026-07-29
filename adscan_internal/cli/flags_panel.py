"""Screenshot-first panel for ``FLAGS CAPTURED · DOMAIN PWNED``.

Reuses the palette from
:mod:`adscan_internal.services.exploitation.dump_display` so the flag
panel is visually consistent with the rest of the operator dark UI.

Display rules:
- Flag values are NEVER rendered. Only the SHA-256 prefix.
- Missing flags are shown with the right semantic colour so the operator
  can tell apart a definitive ACL deny, a "file just isn't there", and a
  transient network blip that may need a re-run.
- Every row state is encoded by both colour AND a leading glyph so the
  panel stays readable under ``NO_COLOR`` and color-blind conditions.
- Footer reflects the actual transport path used. When any missing-row
  outcome is transient (network/timeout/other error), an extra hint is
  appended so the operator knows a re-run might fix it.
"""

from __future__ import annotations

from datetime import timedelta

import rich.box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core.outbound_links import ADSCAN_SITE_HOST
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.ctf_flag_collector import (
    FlagCollectionResult,
    FlagHit,
    FlagKind,
    FlagProbeError,
    FlagProbeOutcome,
)
from adscan_internal.services.exploitation.dump_display import (
    ACID_GREEN,
    AMBER,
    GHOST,
    ICE_BLUE,
    LAVA,
    MUTED,
)


# Worst-first priority for picking which outcome to surface for a given
# kind when multiple owners produced different non-SUCCESS outcomes.
# Transient errors are the most actionable; they are the reason the
# operator might want to re-run, so we surface them over a definitive
# NOT_FOUND.
_OUTCOME_PRIORITY: tuple[FlagProbeOutcome, ...] = (
    FlagProbeOutcome.NETWORK_ERROR,
    FlagProbeOutcome.TIMEOUT,
    FlagProbeOutcome.OTHER_ERROR,
    FlagProbeOutcome.ACCESS_DENIED,
    FlagProbeOutcome.NOT_FOUND,
)

# Glyph vocabulary. Pairing a glyph with each color slot keeps the panel
# usable when NO_COLOR is set, when the terminal palette is unusual, or
# for color-blind operators. Never use color alone to convey state.
_GLYPH_HIT = "✓"           # ACID_GREEN  flag captured
_GLYPH_NOT_FOUND = "✗"     # MUTED       definitive miss (file not there)
_GLYPH_DENIED = "⊘"        # AMBER       access denied (definitive)
_GLYPH_TRANSIENT = "…"     # LAVA        transient error, re-run may help
_GLYPH_EMPTY = "-"         # MUTED       empty cell placeholder


def _fmt_duration(td: timedelta | None) -> str:
    """Render a duration with one decimal of precision."""
    if td is None:
        return _GLYPH_EMPTY
    seconds = td.total_seconds()
    if seconds < 1.0:
        return f"{seconds:.1f}s"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    rem = seconds - minutes * 60
    return f"{minutes}m {rem:.0f}s"


def _by_kind(hits: tuple[FlagHit, ...]) -> dict[FlagKind, FlagHit]:
    out: dict[FlagKind, FlagHit] = {}
    for hit in hits:
        # Prefer SMB-read hit when duplicates exist for the same kind.
        existing = out.get(hit.kind)
        if existing is None:
            out[hit.kind] = hit
        elif existing.method != "smb_read" and hit.method == "smb_read":
            out[hit.kind] = hit
    return out


def _worst_probe_for_kind(
    probes: tuple[FlagProbeError, ...], kind: FlagKind
) -> FlagProbeError | None:
    """Pick the most actionable probe error for ``kind``.

    When multiple owners exercised the same ``kind`` and produced
    different outcomes (e.g. one NOT_FOUND, one NETWORK_ERROR), surface
    the transient error: that is what the operator can act on (re-run).
    Definitive outcomes (NOT_FOUND, ACCESS_DENIED) come last in the
    priority list.
    """
    candidates = [p for p in probes if p.kind == kind]
    if not candidates:
        return None
    rank = {o: i for i, o in enumerate(_OUTCOME_PRIORITY)}
    candidates.sort(key=lambda p: rank.get(p.outcome, len(rank)))
    return candidates[0]


def _render_missing_row(
    flag_table: Table, kind: str, probe: FlagProbeError | None
) -> bool:
    """Render the missing-flag row for ``kind``.

    Returns ``True`` when the row used a LAVA-coloured (transient
    error) state. Caller uses this to decide whether to show the
    "re-run" footer hint.
    """
    if probe is None:
        flag_table.add_row(
            Text(f"{_GLYPH_NOT_FOUND} {kind}", style=MUTED),
            Text(_GLYPH_EMPTY, style=MUTED),
            Text("not found", style=MUTED),
            Text(_GLYPH_EMPTY, style=MUTED),
        )
        return False

    owner_display = (
        mark_sensitive(probe.owner, "user") if probe.owner else _GLYPH_EMPTY
    )

    transient = False
    if probe.outcome is FlagProbeOutcome.NOT_FOUND:
        glyph = _GLYPH_NOT_FOUND
        message = "not found"
        message_style = MUTED
        owner_style = MUTED
        kind_style = MUTED
    elif probe.outcome is FlagProbeOutcome.ACCESS_DENIED:
        glyph = _GLYPH_DENIED
        message = "access denied"
        message_style = AMBER
        owner_style = AMBER
        kind_style = AMBER
    elif probe.outcome is FlagProbeOutcome.NETWORK_ERROR:
        suffix = (
            f", retried {probe.attempts - 1}x"
            if probe.attempts and probe.attempts > 1
            else ""
        )
        glyph = _GLYPH_TRANSIENT
        message = f"network error{suffix}"
        message_style = LAVA
        owner_style = LAVA
        kind_style = LAVA
        transient = True
    elif probe.outcome is FlagProbeOutcome.TIMEOUT:
        glyph = _GLYPH_TRANSIENT
        message = "timeout"
        message_style = LAVA
        owner_style = LAVA
        kind_style = LAVA
        transient = True
    else:  # OTHER_ERROR / SUCCESS-without-token / unknown
        short = (probe.detail or "error").splitlines()[0]
        if len(short) > 48:
            short = short[:45] + "..."
        glyph = _GLYPH_TRANSIENT
        message = f"error: {short}"
        message_style = LAVA
        owner_style = LAVA
        kind_style = LAVA
        transient = True

    flag_table.add_row(
        Text(f"{glyph} {kind}", style=kind_style),
        Text(owner_display, style=owner_style),
        Text(message, style=message_style),
        Text(_GLYPH_EMPTY, style=MUTED),
    )
    return transient


def render_flags_captured_panel(
    *,
    console: Console,
    result: FlagCollectionResult,
    domain: str,
    host: str | None = None,
    time_from_foothold_to_da: timedelta | None = None,
    time_from_da_to_flags: timedelta | None = None,
) -> None:
    """Render the FLAGS CAPTURED panel.

    Args:
        console: Rich console to print into.
        result: Output of :func:`collect_ctf_flags`.
        domain: The domain the flags were captured from (for the
            header).
        host: Target host display string. When omitted, taken from the
            first hit.
        time_from_foothold_to_da: Optional timing for the header.
        time_from_da_to_flags: Optional timing for the header.
    """
    by_kind = _by_kind(result.hits)
    has_any = bool(result.hits)
    target_host = host or (result.hits[0].host if result.hits else _GLYPH_EMPTY)

    # ------------------------------------------------------------------
    # Header lines
    # ------------------------------------------------------------------
    title = Text("🚩  FLAGS CAPTURED  ·  DOMAIN PWNED", style=f"bold {ICE_BLUE}")
    if not has_any:
        title = Text("🚩  FLAG COLLECTION  ·  NO FLAGS FOUND", style=f"bold {LAVA}")

    body = Table.grid(padding=(0, 1))
    body.add_column(style=MUTED)
    body.add_column()

    body.add_row("Domain", Text(mark_sensitive(domain, "domain"), style=ICE_BLUE))
    body.add_row("Host", Text(target_host, style=ICE_BLUE))
    body.add_row("Foothold→DA", _fmt_duration(time_from_foothold_to_da))
    da_flags_text = _fmt_duration(time_from_da_to_flags)
    if not result.fallback_used and result.primary_strategy == "smb_read":
        da_flags_text = f"{da_flags_text}    ← SMB byte-read, no command exec"
    body.add_row("DA→Flags", da_flags_text)

    # ------------------------------------------------------------------
    # Flag table. Show user, root, system in a fixed order so missing
    # rows are visible. State is encoded by glyph + color (NO_COLOR safe).
    # ------------------------------------------------------------------
    flag_table = Table(
        box=rich.box.SIMPLE,
        show_edge=False,
        pad_edge=False,
        expand=False,
    )
    flag_table.add_column("kind", style=MUTED, no_wrap=True)
    flag_table.add_column("owner", style=MUTED, no_wrap=True)
    flag_table.add_column("path", style=MUTED, overflow="fold")
    flag_table.add_column("flag (sha256)", style=MUTED, no_wrap=True)

    has_transient_row = False

    # user flag
    _user_hit = by_kind.get("user")
    if _user_hit is None:
        if _render_missing_row(flag_table, "user", _worst_probe_for_kind(result.probes, "user")):
            has_transient_row = True
    else:
        flag_table.add_row(
            Text(f"{_GLYPH_HIT} user", style=f"bold {ACID_GREEN}"),
            Text(
                mark_sensitive(_user_hit.owner_user, "user") if _user_hit.owner_user else _GLYPH_EMPTY,
                style=ICE_BLUE,
            ),
            Text(_user_hit.path, style="white"),
            Text(_user_hit.flag_hash, style=f"bold {ACID_GREEN}"),
        )

    # Privileged flag. HTB uses "root", THM uses "system", never both.
    # Show only the one that was found; if neither was found, show a
    # single combined "root/system" row so the panel never falsely
    # implies the absent provider's flag name was expected and missed.
    _root_hit = by_kind.get("root")
    _system_hit = by_kind.get("system")
    _priv_hit = _root_hit or _system_hit
    if _priv_hit is not None:
        flag_table.add_row(
            Text(f"{_GLYPH_HIT} {_priv_hit.kind}", style=f"bold {ACID_GREEN}"),
            Text(
                mark_sensitive(_priv_hit.owner_user, "user") if _priv_hit.owner_user else _GLYPH_EMPTY,
                style=ICE_BLUE,
            ),
            Text(_priv_hit.path, style="white"),
            Text(_priv_hit.flag_hash, style=f"bold {ACID_GREEN}"),
        )
    else:
        _probe = _worst_probe_for_kind(result.probes, "root") or _worst_probe_for_kind(result.probes, "system")
        if _render_missing_row(flag_table, "root/system", _probe):
            has_transient_row = True

    # Stitch panel content together.
    inner = Table.grid(padding=(0, 0))
    inner.add_column()
    inner.add_row(body)
    inner.add_row(Text(""))
    inner.add_row(flag_table)

    if has_transient_row:
        inner.add_row(Text(""))
        inner.add_row(
            Text(
                "ⓘ  network instability detected, re-run if results look incomplete",
                style=AMBER,
            )
        )

    inner.add_row(Text(""))

    if result.fallback_used and result.fallback_method is not None:
        footer_text = (
            f"{ADSCAN_SITE_HOST}  ·  ctf  ·  native aiosmb byte-read  ·  "
            f"fallback: {result.fallback_method.value}"
        )
        footer_style = AMBER
    elif has_any:
        footer_text = f"{ADSCAN_SITE_HOST}  ·  ctf  ·  native aiosmb byte-read"
        footer_style = MUTED
    else:
        footer_text = (
            f"{ADSCAN_SITE_HOST}  ·  ctf  ·  no flags accessible at this access level"
        )
        footer_style = LAVA
    inner.add_row(Text(footer_text, style=footer_style))

    panel = Panel(
        inner,
        title=title,
        title_align="left",
        border_style=GHOST,
        box=rich.box.DOUBLE_EDGE,
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)

    # Mode B: if any hit is unconventional, follow up with the premium
    # "UNCONVENTIONAL FLAG LOCATIONS" panel. This is the screenshot
    # artifact for the CTF channel.
    try:
        from adscan_internal.cli.flags_panel_unconventional import (
            has_unconventional_hits,
            render_unconventional_panel,
        )
        if has_unconventional_hits(result):
            console.print()
            render_unconventional_panel(console=console, result=result)
    except Exception:  # noqa: BLE001
        # Never let panel rendering break the collection report.
        pass


__all__ = ["render_flags_captured_panel"]
