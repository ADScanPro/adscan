"""Premium one-time-per-host panel announcing the adaptive cascade.

Fires the first time the remote-exec adaptive selector resolves a host
in this session. Subsequent calls within the cache window stay silent.
Uses the dump-display palette so AV/EDR work shares one visual language.

Design notes:
- Glyphs are paired with color so the panel still reads in NO_COLOR /
  monochrome terminals (skill ``tui-design`` § Accessibility).
- Plain-Unicode glyphs only (◆ / ▲ / ✓), no emoji + VS16 sequences:
  emoji renderings vary across terminal emulators (anti-pattern #5).
- Headline copy is English-only (project-wide rule).
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

from adscan_core.outbound_links import ADSCAN_SITE_HOST
from adscan_internal.services.exploitation.dump_display import (
    ACID_GREEN,
    AMBER,
    ICE_BLUE,
    LAVA,
    MUTED,
)
from adscan_internal.services.host_intelligence.models import HostFingerprint
from adscan_internal.services.remote_exec.models import ExecMethod


_PANEL_WIDTH = 96


def _classify(fp: HostFingerprint) -> tuple[str, str, str]:
    """Return ``(border_color, header_glyph, headline)`` for the variant.

    Each variant pairs a glyph with the border color so the headline still
    reads under NO_COLOR. Glyphs are plain BMP characters to avoid the
    emoji + variation-selector inconsistency described in
    ``tui-design`` anti-pattern #5.
    """
    if fp.has_edr:
        return LAVA, "◆", "EDR active, stealth cascade engaged"
    if fp.has_av:
        return AMBER, "▲", "AV present, balanced cascade engaged"
    return ACID_GREEN, "✓", "Clean host, speed cascade engaged"


def _format_cache_footer(cache_ttl_remaining_s: int | None) -> str:
    if cache_ttl_remaining_s is None:
        return "fresh fingerprint  ·  native aiosmb"
    minutes = max(1, cache_ttl_remaining_s // 60)
    return f"cached {minutes}m  ·  native aiosmb"


def render_host_intelligence_panel(
    *,
    console: Console,
    fingerprint: HostFingerprint,
    cascade: list[ExecMethod],
    reason_lines: list[str],
    workspace_type: str | None,
    cache_ttl_remaining_s: int | None,
) -> None:
    """Render the host-intelligence panel.

    Args:
        console: Rich console to print to.
        fingerprint: Resolved host fingerprint.
        cascade: Ordered list of methods chosen by the selector.
        reason_lines: Human-readable bullet reasons (e.g. ``"active EDR
            detected, stealth bias applied"``).
        workspace_type: Optional ``"ctf"`` / ``"audit"`` / ``"engagement"``.
        cache_ttl_remaining_s: Seconds until cached entry expires; None
            for a fresh scan.
    """
    border, glyph, headline = _classify(fingerprint)

    header = Text()
    header.append(f"  {glyph}  ", style=f"bold {border}")
    header.append("HOST INTELLIGENCE", style=f"bold {ICE_BLUE}")
    header.append("   ·   ", style=MUTED)
    header.append(fingerprint.target_ip, style=f"bold {border}")

    body = Text()
    if fingerprint.detected_products:
        body.append("\n  Detected products    ", style=MUTED)
        first = True
        for product in fingerprint.detected_products:
            if not first:
                body.append("\n                       ", style=MUTED)
            body.append("·   ", style=MUTED)
            body.append(f"{product.name:<24}", style=f"bold {border}")
            body.append(" ")
            body.append(product.status_label, style=border if product.active else MUTED)
            first = False
    else:
        body.append("\n  Detected products    ", style=MUTED)
        body.append("·   ", style=MUTED)
        body.append(headline, style=f"bold {border}")

    body.append("\n  Cascade              ", style=MUTED)
    body.append("·   ", style=MUTED)
    if cascade:
        body.append(
            "  →  ".join(m.value.upper() for m in cascade),
            style=f"bold {ICE_BLUE}",
        )
    else:
        body.append("(no methods selected)", style=MUTED)

    if reason_lines:
        body.append("\n  Reason               ", style=MUTED)
        body.append("·   ", style=MUTED)
        body.append("  ·  ".join(reason_lines), style=border)

    if workspace_type:
        body.append("\n  Workspace            ", style=MUTED)
        body.append("·   ", style=MUTED)
        body.append(workspace_type, style=ICE_BLUE)

    footer = Text()
    footer.append(f"\n  {ADSCAN_SITE_HOST}  ·  ", style=MUTED)
    footer.append(_format_cache_footer(cache_ttl_remaining_s), style=MUTED)

    console.print(
        Panel(
            Group(header, body, footer),
            box=box.DOUBLE_EDGE,
            border_style=border,
            width=_PANEL_WIDTH,
            padding=(1, 2),
        )
    )


def build_reason_lines(
    fingerprint: HostFingerprint, workspace_type: str | None
) -> list[str]:
    """Compose the short human-readable reason string for the panel."""
    reasons: list[str] = []
    if fingerprint.has_edr:
        reasons.append("active EDR detected, stealth bias applied")
    elif fingerprint.has_av:
        reasons.append("AV detected, balanced cascade")
    elif fingerprint.defender_rtp is False:
        reasons.append("Defender RTP off, speed bias applied")
    else:
        reasons.append("clean host, default cascade")
    if workspace_type == "ctf":
        reasons.append("CTF profile")
    elif workspace_type == "engagement":
        reasons.append("engagement profile")
    return reasons


__all__ = [
    "render_host_intelligence_panel",
    "build_reason_lines",
]
