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


def _feature_display_name(feature: str) -> str:
    """Return a human-readable name for ``feature`` (fallback: title-case)."""
    return _FEATURE_DISPLAY_NAMES.get(feature, feature.replace("_", " ").title())


def _secondary_cta(context: UpsellContext) -> str | None:
    if context == "direct_invocation":
        return "Preview:  adscan demo  (generates a sample report — no AD required)"
    if context == "post_scan":
        return "Preview:  adscan demo  (see the full report from your scan data)"
    # help_listing: omit secondary
    return None


def render_pro_upsell_panel(feature: str, context: UpsellContext) -> Panel:
    """Render the canonical PRO upsell panel for ``feature`` in ``context``.

    Args:
        feature: PRO verb being promoted (e.g. ``"playbook"``,
            ``"coverage_matrix"``, ``"deliver"``, ``"generate_report"``).
        context: Where the panel is being rendered. Drives the secondary
            CTA: ``direct_invocation`` shows ``adscan demo`` as zero-risk
            preview, ``post_scan`` invites rendering against the user's
            own scan data, and ``help_listing`` omits the secondary CTA.

    Returns:
        A configured :class:`rich.panel.Panel` ready to print. Callers
        should print it with ``console.print(panel)`` directly — wrapping
        it through ``print_panel`` produces a double-bordered render.
        Most callers prefer :func:`print_pro_upsell` which handles this.
    """
    display = _feature_display_name(feature)

    eyebrow = Text(
        "CLIENT DELIVERABLE KIT · PRO FEATURE",
        style=f"bold {_BRAND_CYAN}",
    )

    # The default headline construction ("<X> is part of the Client
    # Deliverable Kit — …") works for components (Security Assessment
    # Report, Playbook, AD Control Coverage Report). When the feature IS
    # the Kit itself (``deliver``), it collapses into a tautology
    # ("Client Deliverable Kit is part of the Client Deliverable Kit").
    # Branch on the feature name to keep the copy clean.
    headline = Text()
    if feature == "deliver":
        headline.append("The Client Deliverable Kit", style="bold")
        headline.append(
            " is the 3 PDFs you hand to the customer after every engagement.",
        )
    else:
        headline.append(display, style="bold")
        headline.append(
            " is part of the Client Deliverable Kit — the 3 PDFs you "
            "hand to the customer after every engagement.",
        )

    pdfs_line = Text()
    for idx, name in enumerate(_PDFS):
        if idx > 0:
            pdfs_line.append("  ·  ", style=_BRAND_CYAN)
        pdfs_line.append(name)

    punchline = Text(
        "Stop writing reports. Ship the kit in 90 seconds.",
        style="bold",
    )

    primary_cta = Text()
    primary_cta.append("Upgrade:  ", style="bold")
    primary_cta.append("https://adscanpro.com/pro", style=f"{_BRAND_CYAN} on grey11")

    parts: list[Text] = [
        eyebrow,
        Text(""),
        headline,
        Text(""),
        pdfs_line,
        Text(""),
        punchline,
        Text(""),
        primary_cta,
    ]

    secondary = _secondary_cta(context)
    if secondary is not None:
        sec = Text(secondary, style=_BRAND_CYAN)
        parts.append(sec)

    return Panel(
        Group(*parts),
        border_style=_BRAND_CYAN,
        padding=(1, 3),
    )


def print_pro_upsell(feature: str, context: UpsellContext) -> None:
    """Render the PRO upsell panel and print it without double-wrapping.

    Convenience wrapper for the three container call sites (REPL
    ``deliver``, REPL ``generate_report``, top-level ``adscan deliver``)
    that previously did ``print_panel(render_pro_upsell_panel(...))`` and
    got a panel-inside-a-panel render — two stacked cyan borders.

    This helper prints the panel directly through the shared Rich console
    so the operator sees the canonical single-frame premium panel. Prefer
    it over the raw renderer in any call site that just wants to surface
    the upsell — only reach for :func:`render_pro_upsell_panel` when the
    panel is being composed into a larger layout (e.g. embedded inside a
    Group, a Layout, or another Panel intentionally).
    """
    from adscan_core.output._panels import _get_console

    panel = render_pro_upsell_panel(feature, context)
    _get_console().print(panel)


__all__ = (
    "render_pro_upsell_panel",
    "print_pro_upsell",
    "UpsellContext",
)
