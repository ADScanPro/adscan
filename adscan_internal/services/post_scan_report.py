"""The post-scan exposure-report moment — one seam, one decision, one artifact.

A scan that just proved a path to compromise is the moment the free exposure
report is worth the most, and it is also the moment nobody goes looking for it.
This module owns what happens to that report the instant a scan finishes, so
the decision lives in one place instead of being re-litigated at every
scan-completion call site.

The decision is keyed on the workspace type, because the two populations want
opposite things:

* ``audit`` — the operator is running an engagement, so the client-ready
  artifact is obviously wanted. It is generated automatically and announced.
  No question is asked: rendering costs a few seconds off a scan that already
  ran, and a prompt here only adds friction to something the operator would
  have said yes to.
* ``ctf`` (and anything else) — a lab or a box. A client report is usually not
  wanted, and asking a question most people decline is how an operator learns
  to ignore every prompt the product renders. One line is offered instead, and
  only in an interactive session where typing the verb is actually possible.

PRO is deliberately excluded: its post-scan recap already surfaces the
deliverable-kit verbs, and rendering the free report unasked next to that CTA
would be two panels arguing over the same moment.

Everything here is best-effort. A render failure logs and returns; it never
delays or breaks the scan flow. No prompt is rendered on any path, so
``adscan ci`` can never block on it.

This module is also the single instrumented entry point for LITE report
generation (the REPL verbs and ``adscan ci`` route through
:func:`generate_report_with_telemetry`), so the adoption funnel is measurable
from one place and a report is never rendered twice in the same run.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from adscan_core import tier
from adscan_core.lab_context import normalize_workspace_type
from adscan_core.rich_output import get_console, print_exception
from adscan_core.theme import ADSCAN_PRIMARY_BRIGHT
from adscan_internal import telemetry
from adscan_internal.interaction import is_non_interactive

# Workspace types (SSOT: ``PentestShell.type``, validated to these two values).
WORKSPACE_TYPE_AUDIT = "audit"
WORKSPACE_TYPE_CTF = "ctf"
WORKSPACE_TYPE_UNKNOWN = "unknown"

# What the seam decided to do with the report at scan completion.
DISPOSITION_AUTO_GENERATED = "auto_generated"
DISPOSITION_OFFERED = "offered"
DISPOSITION_ALREADY_GENERATED = "already_generated"
DISPOSITION_PRO_KIT = "pro_kit"
DISPOSITION_NO_SCAN_DATA = "no_scan_data"
DISPOSITION_SILENT = "silent"

# Who asked for a report. ``auto_post_scan`` is the only automatic one.
TRIGGER_AUTO_POST_SCAN = "auto_post_scan"
TRIGGER_REPL_REPORT = "repl_report"
TRIGGER_REPL_DELIVER = "repl_deliver"
TRIGGER_CI = "ci"

_AUTOMATIC_TRIGGERS = frozenset({TRIGGER_AUTO_POST_SCAN})

# Session state. Plain shell attributes, never ``domains_data`` — that dict is
# JSON-persisted and must not carry transient per-run bookkeeping.
_PATH_ATTR = "_post_scan_report_path"
_OFFER_ATTR = "_post_scan_report_offer_shown"
_DISPOSITION_ATTR = "_post_scan_report_disposition"


def resolve_workspace_type(shell: Any) -> str:
    """Return the canonical workspace type for this session.

    Reuses the telemetry normalizer so the value joins cleanly with the
    ``workspace_type`` already carried by ``scan_complete``. Falls back to
    ``"unknown"`` rather than guessing, so an unset type is never treated as an
    engagement.
    """
    return normalize_workspace_type(getattr(shell, "type", None)) or WORKSPACE_TYPE_UNKNOWN


def get_post_scan_report_path(shell: Any) -> str | None:
    """Return the exposure report already rendered in this run, if any.

    This is the ``.html`` path — the artifact that always exists — and it is
    what the idempotency guard keys on.
    """
    value = getattr(shell, _PATH_ATTR, None)
    return str(value) if isinstance(value, str) and value else None


def get_post_scan_report_display_path(shell: Any) -> str | None:
    """Return the path to show an operator: the PDF when it rendered, else HTML.

    The PDF is the copy that gets forwarded, so it leads wherever a single path
    is displayed. The ``.pdf`` sibling convention is the renderer's own (it
    writes ``html_path.with_suffix('.pdf')``), and the existence check keeps the
    display honest when Chromium was unavailable.
    """
    html_path = get_post_scan_report_path(shell)
    if not html_path:
        return None
    pdf_path = _sibling_pdf(html_path)
    return pdf_path or html_path


def _sibling_pdf(html_path: str) -> str | None:
    """Return the rendered PDF beside ``html_path``, or ``None``."""
    try:
        candidate = Path(html_path).with_suffix(".pdf")
        return str(candidate) if candidate.exists() else None
    except Exception:  # noqa: BLE001 - a display detail, never fatal
        return None


def _remember(shell: Any, attribute: str, value: Any) -> None:
    """Best-effort ``setattr`` on the shell (some callers pass a stub object)."""
    try:
        setattr(shell, attribute, value)
    except Exception:  # noqa: BLE001 - bookkeeping, never fatal
        pass


def _technical_report_exists(shell: Any) -> bool:
    """Return whether the scan actually produced data to report on.

    Without this, a scan that wrote nothing would end on the renderer's "No scan
    data found yet. Run a scan first" error, which reads as a failure right
    after a completed scan.
    """
    try:
        from adscan_core.reporting.technical_report import _get_technical_report_path

        return Path(_get_technical_report_path(shell)).exists()
    except Exception:  # noqa: BLE001 - absence is the safe answer
        return False


def _lab_fields(shell: Any) -> dict[str, Any]:
    """Return the shared lab identification fields, or ``{}`` on any failure."""
    try:
        from adscan_internal.cli.common import build_lab_event_fields

        return dict(build_lab_event_fields(shell=shell, include_slug=True))
    except Exception:  # noqa: BLE001 - analytics context is optional
        return {}


def _swallow(exc: Exception) -> None:
    """Record a swallowed failure in both the telemetry and debug-log sinks."""
    try:
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
    except Exception:  # noqa: BLE001 - the sinks themselves must never raise
        pass


def _content_properties(artifacts: Any) -> dict[str, Any]:
    """Return the content-quality counts for a produced report, or ``{}``.

    The report funnel records that a document was produced; these record what
    it SAYS, which is the only way a regression in the deliverable itself shows
    up without someone reading a session recording by hand. Two comparisons pay
    for the whole thing:

    * ``findings_with_locator`` against ``findings_total`` — how many findings
      name an account, host, share or template the reader can act on, rather
      than the bare-domain fallback. That ratio is the work the deliverable
      hands back to the client's administrator.
    * ``paths_rendered_exploited`` against the engine's own ``paths_exploited``
      (``scan_complete``) — whether the proof survived the trip from the graph
      to the page. Every domain compromise in production reported zero
      exploited paths in the document, and nothing flagged it.

    Counts only, never content. The figures are read off the model the renderer
    already built, so this costs nothing and cannot disagree with the document.
    """
    try:
        content = getattr(artifacts, "content", None)
        if content is None:
            return {}
        properties = content.as_event_properties()
        return properties if isinstance(properties, dict) else {}
    except Exception as exc:  # noqa: BLE001 - measurement never breaks a render
        _swallow(exc)
        return {}


def _emit_generated(properties: dict[str, Any]) -> None:
    """Capture ``exposure_report_generated`` without disturbing the scan flow.

    The event name is a literal here on purpose: the closed-vocabulary lock in
    ``tests/unit/test_telemetry_event_name_allowlist.py`` reads
    ``telemetry.capture`` first arguments straight out of the AST.
    """
    try:
        telemetry.capture("exposure_report_generated", properties)
    except Exception as exc:  # noqa: BLE001 - analytics must never break a scan
        _swallow(exc)


def _emit_moment(properties: dict[str, Any]) -> None:
    """Capture ``post_scan_report_moment`` without disturbing the scan flow."""
    try:
        telemetry.capture("post_scan_report_moment", properties)
    except Exception as exc:  # noqa: BLE001 - analytics must never break a scan
        _swallow(exc)


def generate_report_with_telemetry(
    shell: Any,
    *,
    trigger: str,
    report_file: str | None = None,
    asked_for_the_kit: bool = False,
) -> str | None:
    """Render the LITE exposure report and record the outcome.

    The single instrumented entry point for every LITE report on-ramp: the
    automatic post-scan render, the REPL reporting verbs, and ``adscan ci``.
    Routing them all through here is what makes the adoption funnel readable
    (auto versus user-initiated, how long a render takes, how often it fails)
    and what lets a run avoid rendering the same report twice. The same event
    also carries what the document SAYS in counts (see
    :func:`_content_properties`), so a deliverable that quietly stops
    representing the scan is visible from the field rather than from someone
    reading a recording.

    Args:
        shell: The active CLI shell (workspace context).
        trigger: Which on-ramp asked for the report (one of the ``TRIGGER_*``
            constants).
        report_file: Explicit ``technical_report.json`` path, forwarded to the
            renderer. ``None`` lets the renderer resolve it from the shell.
        asked_for_the_kit: The operator typed ``deliver``, so the renderer's
            panel spells out what the paid kit adds.

    Returns:
        The written ``.html`` path, or ``None`` when the render failed.
    """
    started = time.monotonic()
    artifacts: Any = None
    try:
        from adscan_internal.services.lite_html_report import (
            generate_lite_report_artifacts,
        )

        kwargs: dict[str, Any] = {}
        if report_file is not None:
            kwargs["report_file"] = report_file
        if asked_for_the_kit:
            kwargs["asked_for_the_kit"] = True
        artifacts = generate_lite_report_artifacts(shell, **kwargs)
    except Exception as exc:  # noqa: BLE001 - a report must never break a scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        artifacts = None

    duration_seconds = round(max(0.0, time.monotonic() - started), 2)
    html_path = getattr(artifacts, "html_path", None)
    resolved = str(html_path) if isinstance(html_path, str) and html_path else None
    if resolved:
        _remember(shell, _PATH_ATTR, resolved)

    properties: dict[str, Any] = {
        "trigger": str(trigger),
        "automatic": trigger in _AUTOMATIC_TRIGGERS,
        "success": resolved is not None,
        "duration_seconds": duration_seconds,
        "workspace_type": resolve_workspace_type(shell),
        "pdf_rendered": bool(resolved and _sibling_pdf(resolved)),
        "after_offer": bool(getattr(shell, _OFFER_ATTR, False)),
        "asked_for_the_kit": bool(asked_for_the_kit),
        "non_interactive": bool(is_non_interactive(shell)),
        "tier": tier.tier_name(),
    }
    properties.update(_content_properties(artifacts))
    properties.update(_lab_fields(shell))
    _emit_generated(properties)
    return resolved


def _resolve_disposition(shell: Any, workspace_type: str) -> str:
    """Decide what this scan-completion moment does with the exposure report."""
    if get_post_scan_report_path(shell):
        return DISPOSITION_ALREADY_GENERATED
    if tier.is_pro():
        return DISPOSITION_PRO_KIT
    if workspace_type == WORKSPACE_TYPE_AUDIT:
        if not _technical_report_exists(shell):
            return DISPOSITION_NO_SCAN_DATA
        return DISPOSITION_AUTO_GENERATED
    if is_non_interactive(shell):
        # A lab run with nobody at the keyboard: an offer nobody can act on is
        # just noise in a log.
        return DISPOSITION_SILENT
    return DISPOSITION_OFFERED


def _print_rendering_notice() -> None:
    """Print the one dim line that covers the render, so the pause is explained."""
    from rich.text import Text

    try:
        get_console().print(
            Text("Writing the exposure report for this engagement...", style="dim")
        )
    except Exception:  # noqa: BLE001 - cosmetic
        pass


def run_post_scan_report(shell: Any, verb: str) -> str | None:
    """Resolve and execute the post-scan report moment. Never raises.

    Call this once per completed scan, BEFORE the ``Scan complete`` recap panel
    renders, so the recap can point at the artifact this produced.

    Args:
        shell: The active pentest shell.
        verb: The completed scan verb (``"start_auth"`` / ``"start_unauth"``).

    Returns:
        The path to the exposure report when one exists for this run, else
        ``None``.
    """
    try:
        workspace_type = resolve_workspace_type(shell)
        disposition = _resolve_disposition(shell, workspace_type)
        _remember(shell, _DISPOSITION_ATTR, disposition)

        properties: dict[str, Any] = {
            "command": str(verb),
            "workspace_type": workspace_type,
            "disposition": disposition,
            "auto_generated": disposition == DISPOSITION_AUTO_GENERATED,
            "non_interactive": bool(is_non_interactive(shell)),
            "tier": tier.tier_name(),
        }
        properties.update(_lab_fields(shell))
        _emit_moment(properties)

        if disposition == DISPOSITION_ALREADY_GENERATED:
            return get_post_scan_report_path(shell)
        if disposition != DISPOSITION_AUTO_GENERATED:
            return None

        _print_rendering_notice()
        return generate_report_with_telemetry(shell, trigger=TRIGGER_AUTO_POST_SCAN)
    except Exception as exc:  # noqa: BLE001 - the scan flow owns this thread
        _swallow(exc)
        return None


def _print_offer_line(prose: str, verb: str) -> None:
    """Print one dim offer line with the verb highlighted."""
    from rich.text import Text

    get_console().print(
        Text.assemble(
            Text(f"  {prose}  ", style="dim"),
            Text(verb, style=f"bold {ADSCAN_PRIMARY_BRIGHT}"),
        )
    )


def print_post_scan_report_offer(shell: Any) -> None:
    """Print the one-line offers, when this moment resolved to one.

    Rendered AFTER the ``Scan complete`` recap so they read as a footnote to the
    result rather than competing with it. A dim line with the verb highlighted:
    the same grammar the recap's ``Try next`` block uses, so it lands as part of
    the same moment instead of a second surface.

    A lab workspace gets the writeup spine first, because that is the artifact
    that population actually wants and the one whose value decays: publication
    on these platforms waits for the target to retire, so by the time anyone
    writes the post the order things happened in is gone. The exposure report
    stays below it, unchanged, for the operator who wants the shareable
    document instead.

    No-op unless :func:`run_post_scan_report` resolved to
    :data:`DISPOSITION_OFFERED`, which already excludes PRO, engagements, and
    non-interactive runs.
    """
    if getattr(shell, _DISPOSITION_ATTR, None) != DISPOSITION_OFFERED:
        return
    try:
        if resolve_workspace_type(shell) == WORKSPACE_TYPE_CTF:
            _print_offer_line(
                "Keep the evidence for the writeup while you still remember it:", "writeup"
            )
        _print_offer_line(
            "Turn this run into a shareable HTML and PDF report:", "generate_report"
        )
        _remember(shell, _OFFER_ATTR, True)
    except Exception as exc:  # noqa: BLE001 - a hint must never break the flow
        _swallow(exc)


__all__ = [
    "DISPOSITION_ALREADY_GENERATED",
    "DISPOSITION_AUTO_GENERATED",
    "DISPOSITION_NO_SCAN_DATA",
    "DISPOSITION_OFFERED",
    "DISPOSITION_PRO_KIT",
    "DISPOSITION_SILENT",
    "TRIGGER_AUTO_POST_SCAN",
    "TRIGGER_CI",
    "TRIGGER_REPL_DELIVER",
    "TRIGGER_REPL_REPORT",
    "WORKSPACE_TYPE_AUDIT",
    "WORKSPACE_TYPE_CTF",
    "generate_report_with_telemetry",
    "get_post_scan_report_display_path",
    "get_post_scan_report_path",
    "print_post_scan_report_offer",
    "resolve_workspace_type",
    "run_post_scan_report",
]
