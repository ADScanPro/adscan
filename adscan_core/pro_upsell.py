"""PRO upsell panel — single source of truth.

Three contexts in the codebase need to surface "this is a PRO feature":

- ``direct_invocation``: user typed a PRO-only verb in LITE.
- ``post_scan``: post-scan suggestions panel mentions the kit.
- ``help_listing``: help tree shows PRO commands greyed out.

All three render through :func:`render_pro_upsell_panel` so the copy is
identical and the brand stays consistent. Do not duplicate the panel in
call sites — extend the context table here.

The panel is intentionally premium: cyan brand border, eyebrow caps,
generous padding, mono-styled CTA URL. No emojis.
"""

from __future__ import annotations

from typing import Literal

from rich.console import Group
from rich.panel import Panel
from rich.text import Text

from adscan_core.outbound_links import cta_display, cta_link_style

UpsellContext = Literal["direct_invocation", "post_scan", "help_listing"]

_BRAND_CYAN = "bright_cyan"

_FEATURE_DISPLAY_NAMES: dict[str, str] = {
    "playbook": "AD Hardening Playbook",
    # ``coverage_matrix`` is the kept slug; the deliverable it renders is the
    # AD Control Coverage Report (the old Coverage Matrix folded into a
    # positive-assurance, control-evidence view).
    "coverage_matrix": "AD Control Coverage Report",
    "deliver": "Client Deliverable Kit",
    # ``generate_report`` is the REPL verb that renders the standalone
    # Security Assessment Report (one PDF, the headline artefact in the
    # 3-PDF Kit). LITE users who type it land on the same upsell panel
    # as the ones who type ``deliver`` — single source of truth for the
    # PRO ask, same brand, same CTA.
    "generate_report": "Security Assessment Report",
}

_PDFS = (
    "Security Assessment Report",
    "AD Hardening Playbook",
    "AD Control Coverage Report",
)

# What the paid kit adds on top of the free LITE exposure report. Ordered by
# what a consultant weighs: the regulatory mapping and the remediation depth
# first (the hours saved per engagement), then the two hardening documents, then
# the branding boundary stated plainly.
#
# The regime list reads "or", not "and": the kit maps to the regimes the
# operator SELECTS for the engagement, and a kit built for one client's regime
# never carries another's. Promising all of them would be the same misdescription
# the report itself was fixed for.
#
# PCI DSS is supported too and is named in the exposure report's own PRO note,
# which has room for it. It is left out HERE because a bullet must survive an
# 80-column terminal: the panel adds 6 columns of padding and 2 of border, so an
# item over 70 characters wraps and splits a regime name across two lines.
_KIT_ITEMS = (
    "Security Assessment Report mapped to DORA, NIS2, ENS or ISO 27001",
    "Per-finding remediation your client's sysadmin can execute",
    "AD Hardening Playbook",
    "AD Control Coverage Report",
    "Your branding, not ours",
)


def _feature_display_name(feature: str) -> str:
    """Return a human-readable name for ``feature`` (fallback: title-case)."""
    return _FEATURE_DISPLAY_NAMES.get(feature, feature.replace("_", " ").title())


def render_pro_upsell_panel(
    feature: str,
    context: UpsellContext,
    *,
    report_path: str | None = None,
) -> Panel:
    """Render the canonical PRO upsell panel for the Client Deliverable Kit.

    The panel leads with what the LITE operator can do RIGHT NOW — generate the
    free HTML exposure report — and only then states what the paid kit adds. It
    reads as a next step after a successful scan, never as a refusal.

    Args:
        feature: PRO verb being promoted (kept for call-site compatibility;
            the body is kit-focused and no longer branches on it).
        context: Where the panel is rendered (unused for copy today; kept for
            signature stability across the three call sites).
        report_path: Absolute path to an exposure report already generated in
            this workspace. When provided, the panel points at that file instead
            of telling the operator to generate one again.

    Returns:
        A configured :class:`rich.panel.Panel` ready to print. Callers should
        print it with ``console.print(panel)`` directly — wrapping it through
        ``print_panel`` produces a double-bordered render. Most callers prefer
        :func:`print_pro_upsell` which handles this.
    """
    del feature, context  # body is kit-focused; params kept for compatibility

    eyebrow = Text(
        "CLIENT DELIVERABLE KIT · PRO FEATURE",
        style=f"bold {_BRAND_CYAN}",
    )
    header = Text("Client Deliverable Kit", style="bold")

    capability = Text()
    if report_path:
        capability.append("Your exposure report is ready:\n")
        capability.append(report_path, style=_BRAND_CYAN)
        capability.append(
            "\nScore, findings and the proven attack paths, and it is yours to send."
        )
    else:
        capability.append(
            "You can generate your exposure report right now with 'generate_report'.\n"
            "Score, findings and the proven attack paths, and it is yours to send."
        )

    adds_intro = Text("The kit adds what you bill for:", style="bold")
    bullets: list[Text] = [Text("  " + item) for item in _KIT_ITEMS]

    cost = Text("An evening of writing, or a ZIP at the end of the engagement.")

    # Short, clean text; the tracking parameters ride in the hyperlink target.
    primary_cta = Text(
        cta_display("pro_upsell_panel"),
        style=cta_link_style("pro_upsell_panel", f"{_BRAND_CYAN} on grey11"),
    )

    parts: list[Text] = [
        eyebrow,
        Text(""),
        header,
        Text(""),
        capability,
        Text(""),
        adds_intro,
        *bullets,
        Text(""),
        cost,
        Text(""),
        primary_cta,
    ]

    return Panel(
        Group(*parts),
        border_style=_BRAND_CYAN,
        padding=(1, 3),
    )


def print_pro_upsell(
    feature: str,
    context: UpsellContext,
    *,
    report_path: str | None = None,
) -> None:
    """Render the PRO upsell panel and print it without double-wrapping.

    Convenience wrapper for the container call sites (REPL ``deliver``,
    top-level ``adscan deliver``) that previously did
    ``print_panel(render_pro_upsell_panel(...))`` and got a panel-inside-a-panel
    render — two stacked cyan borders.

    This helper prints the panel directly through the shared Rich console so the
    operator sees the canonical single-frame premium panel. ``report_path`` is
    forwarded so the panel can point at an already-generated exposure report.
    """
    from adscan_core.output._panels import _get_console

    panel = render_pro_upsell_panel(feature, context, report_path=report_path)
    _get_console().print(panel)


__all__ = (
    "render_pro_upsell_panel",
    "print_pro_upsell",
    "UpsellContext",
)
