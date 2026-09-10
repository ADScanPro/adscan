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

from typing import TYPE_CHECKING, Literal

from rich.console import Group
from rich.panel import Panel
from rich.text import Text

from adscan_core.outbound_links import cta_display, cta_link_style

if TYPE_CHECKING:
    from adscan_core.operator_role import CtaLane

UpsellContext = Literal["direct_invocation", "post_scan", "help_listing"]

_BRAND_CYAN = "bright_cyan"

# Non-deliverable PRO commands render a distinct, on-message panel body
# instead of the kit panel below. `ci` is the first member: autonomous,
# non-interactive scanning has nothing to do with the Client Deliverable
# Kit, and pointing a `ci` user at `generate_report` (a kit-only verb) was
# both wrong and confusing. Extend this set when a new non-deliverable PRO
# command needs its own upsell body.
_AUTONOMOUS_MODE_FEATURES: frozenset[str] = frozenset({"ci"})

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


def _primary_cta(placement: str = "pro_upsell_panel") -> Text:
    # Short, clean text; the tracking parameters ride in the hyperlink target.
    return Text(
        cta_display(placement),
        style=cta_link_style(placement, f"{_BRAND_CYAN} on grey11"),
    )


def _render_kit_panel_body(*, report_path: str | None) -> list[Text]:
    """Body for the Client Deliverable Kit upsell (deliver/generate_report/…)."""
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

    return [
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
        _primary_cta("pro_upsell_panel"),
    ]


def _render_autonomous_mode_panel_body() -> list[Text]:
    """Body for the `adscan ci` (autonomous/non-interactive mode) upsell.

    Distinct from the Client Deliverable Kit panel: `ci` is about how a scan
    RUNS (unattended, scripted, no prompts), not about the report artefacts
    the kit renders. Never suggests `generate_report` here — that verb is
    kit-focused and irrelevant to what a `ci` user is trying to do.
    """
    eyebrow = Text(
        "AUTONOMOUS MODE · PRO FEATURE",
        style=f"bold {_BRAND_CYAN}",
    )
    header = Text("Autonomous Scanning", style="bold")

    capability = Text(
        "'adscan ci' runs a full assessment end to end with no prompts: "
        "CI/CD pipelines, lab automation, and scheduled or unattended runs.\n"
        "This is a PRO capability."
    )

    lite_line = Text(
        "The free LITE tier includes the full interactive 'adscan start' "
        "workflow, on every platform: the same engine, driven step by step."
    )

    return [
        eyebrow,
        Text(""),
        header,
        Text(""),
        capability,
        Text(""),
        lite_line,
        Text(""),
        _primary_cta("pro_upsell_panel"),
    ]


def _render_enterprise_panel_body() -> list[Text]:
    """Body for the Enterprise-lane upsell: one platform pitch, any feature.

    Shown instead of a per-feature PRO body when the operator's role profile
    resolves to the buyer lane (own-estate security/sysadmin/CISO): the ask is
    not "run this CLI yourself", it is continuous validation delivered as a
    platform, with a report built for a board or an auditor.
    """
    from adscan_core.operator_role import CtaLane
    from adscan_core.outbound_links import cta_placement_for_lane

    eyebrow = Text(
        "ENTERPRISE PLATFORM · CONTINUOUS VALIDATION",
        style=f"bold {_BRAND_CYAN}",
    )
    header = Text("ADscan Enterprise", style="bold")

    capability = Text(
        "The Active Directory exposure ADscan just surfaced is real, and it "
        "will not stay still: new users, new group memberships and new "
        "misconfigurations reopen paths to Domain Admin between scans.\n"
        "ADscan Enterprise validates your domain continuously and turns every "
        "run into a report your board and your auditors can read."
    )

    platform_line = Text(
        "No CLI to run, no scan to remember: a platform your team logs into, "
        "with trend lines, ownership and remediation tracked over time."
    )

    return [
        eyebrow,
        Text(""),
        header,
        Text(""),
        capability,
        Text(""),
        platform_line,
        Text(""),
        _primary_cta(cta_placement_for_lane(CtaLane.ENTERPRISE)),
    ]


def render_pro_upsell_panel(
    feature: str,
    context: UpsellContext,
    *,
    report_path: str | None = None,
    lane: "CtaLane | None" = None,
) -> Panel:
    """Render the canonical PRO upsell panel for the triggering ``feature``.

    Most PRO commands are deliverable-family (``deliver``, ``generate_report``,
    ``playbook``, ``coverage_matrix``) and render the Client Deliverable Kit
    panel: it leads with what the LITE operator can do RIGHT NOW — generate the
    free HTML exposure report — and only then states what the paid kit adds.

    ``ci`` (and any future non-deliverable PRO command registered in
    :data:`_AUTONOMOUS_MODE_FEATURES`) renders a distinct, accurate body
    instead: autonomous/non-interactive scanning has nothing to do with the
    Client Deliverable Kit, so it must not reuse that panel's copy.

    ``lane`` overrides both of the above: when it resolves to
    :attr:`~adscan_core.operator_role.CtaLane.ENTERPRISE`, the panel renders
    the single Enterprise-platform body regardless of ``feature`` — the
    operator's role profile says they are a buyer evaluating their own
    estate, not a pentester who wants the CLI feature they just typed.

    Args:
        feature: PRO verb that triggered the panel. Selects the panel body
            when ``lane`` is not the Enterprise lane.
        context: Where the panel is rendered (unused for copy today; kept for
            signature stability across call sites).
        report_path: Absolute path to an exposure report already generated in
            this workspace. Only consulted for the kit panel; when provided,
            the panel points at that file instead of telling the operator to
            generate one again.
        lane: The resolved commercial CTA lane. ``None`` (the default) and
            :attr:`~adscan_core.operator_role.CtaLane.PRO` are equivalent and
            render the existing per-feature PRO body with the ``/pro`` CTA.
            :attr:`~adscan_core.operator_role.CtaLane.ENTERPRISE` renders the
            Enterprise-platform body with the ``/get-a-demo`` CTA.

    Returns:
        A configured :class:`rich.panel.Panel` ready to print. Callers should
        print it with ``console.print(panel)`` directly — wrapping it through
        ``print_panel`` produces a double-bordered render. Most callers prefer
        :func:`print_pro_upsell` which handles this.
    """
    del context  # unused for copy today; kept for signature stability

    from adscan_core.operator_role import CtaLane

    if lane is CtaLane.ENTERPRISE:
        parts = _render_enterprise_panel_body()
    elif feature in _AUTONOMOUS_MODE_FEATURES:
        parts = _render_autonomous_mode_panel_body()
    else:
        parts = _render_kit_panel_body(report_path=report_path)

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
    lane: "CtaLane | None" = None,
) -> None:
    """Render the PRO upsell panel and print it without double-wrapping.

    Convenience wrapper for the container call sites (REPL ``deliver``,
    top-level ``adscan deliver``) that previously did
    ``print_panel(render_pro_upsell_panel(...))`` and got a panel-inside-a-panel
    render — two stacked cyan borders.

    This helper prints the panel directly through the shared Rich console so the
    operator sees the canonical single-frame premium panel. ``report_path`` is
    forwarded so the panel can point at an already-generated exposure report.
    ``lane`` is forwarded so this peak-value gate also routes by operator role
    (see :func:`render_pro_upsell_panel`); callers should resolve it via
    :func:`adscan_core.operator_role.resolve_cta_lane` rather than leave it
    unset, so a buyer role reaches the Enterprise body here too.
    """
    from adscan_core.output._panels import _get_console

    panel = render_pro_upsell_panel(
        feature, context, report_path=report_path, lane=lane
    )
    _get_console().print(panel)


__all__ = (
    "render_pro_upsell_panel",
    "print_pro_upsell",
    "UpsellContext",
)
