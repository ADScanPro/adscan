"""The post-scan moment — one seam, two artifacts, no question asked.

A scan that just proved a path to compromise is the moment its write-up is
worth the most, and it is also the moment nobody goes looking for it. This
module owns what happens the instant a scan finishes, so the decision lives in
one place instead of being re-litigated at every scan-completion call site.

Two artifacts are in scope and they are wanted by opposite populations, so the
seam resolves **two independent dispositions** rather than one (see
:class:`PostScanDisposition`):

* The **exposure report** is the engagement artifact. On an ``audit`` workspace
  it is generated automatically and announced — rendering costs a few seconds
  off a scan that already ran, and a prompt here only adds friction to
  something the operator would have said yes to. On a lab it stays a one-line
  offer, because a client report is usually not what that run was for.
* The **writeup spine** is the lab artifact, and it is generated automatically
  on a ``ctf`` workspace for exactly the reason the engagement report is.
  Anything the operator has to opt into is an artifact some fraction of them
  never produce, and the ones who skip it are the ones who never publish it.
  Its value also decays fastest: lab platforms hold publication back until a
  target retires, so by the time anyone writes the post, the order things
  happened in is gone. Writing it while the evidence is fresh is worth more
  than asking.

Both artifacts TRAVEL — a report is forwarded to a CISO, a writeup is published
under the author's name — and that distribution is the whole commercial reason
the free tier exists.

Tier and workspace type are ORTHOGONAL, and the resolution is a matrix rather
than a chain because a tier test placed first silently swallows every workspace
type under it:

===========  =====================================  =========================
             LITE                                   PRO
===========  =====================================  =========================
``audit``    exposure report rendered and           the ``Scan complete`` recap
             announced                              names the deliverable kit
``ctf``      writeup spine written; the exposure    writeup spine written, and
             report stays a one-line offer          nothing else is named
===========  =====================================  =========================

PRO is excluded from the free exposure report on an engagement — its recap
already carries the deliverable-kit verbs, and rendering a second report unasked
next to them would be two surfaces arguing over one moment — but it is NOT
excluded from the writeup. Producing it costs nothing, format availability has
never been this product's paid boundary, and a PRO licence on a practice box
means a pentester practising or preparing content: they want exactly what the
free user wants. The reverse holds too, which is the cell that is easy to get
wrong: a client-deliverable call to action after rooting a practice box points
at a client who does not exist, and an operator who learns to skip that panel
skips it on the engagement where it pays.

Everything here is best-effort. A generation failure logs and returns; it never
delays or breaks the scan flow. No prompt is rendered on any path, so
``adscan ci`` can never block on it.

This module is also the single instrumented entry point for LITE report
generation (the REPL verbs and ``adscan ci`` route through
:func:`generate_report_with_telemetry`), so the adoption funnel is measurable
from one place and neither artifact is ever produced twice in the same run.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
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

# What the seam decided to do with the exposure report at scan completion.
DISPOSITION_AUTO_GENERATED = "auto_generated"
DISPOSITION_OFFERED = "offered"
DISPOSITION_ALREADY_GENERATED = "already_generated"
DISPOSITION_PRO_KIT = "pro_kit"
DISPOSITION_LAB_ARTIFACT = "lab_artifact"
DISPOSITION_NO_SCAN_DATA = "no_scan_data"
DISPOSITION_SILENT = "silent"

# What the seam decided to do with the writeup spine. A separate vocabulary on
# purpose: the two artifacts answer to different rules (the writeup is a lab
# artifact and is tier-independent), and folding them into one enum would mean a
# value per combination — which is how a change to one tier silently drops the
# other tier's artifact.
WRITEUP_AUTO_GENERATED = "auto_generated"
WRITEUP_ALREADY_GENERATED = "already_generated"
WRITEUP_NOT_A_LAB = "not_a_lab"
WRITEUP_NO_SCAN_DATA = "no_scan_data"
WRITEUP_SILENT = "silent"

# Who asked for an artifact. ``auto_post_scan`` is the only automatic one, and
# telling it apart from the operator-invoked triggers is the whole point of
# recording it: it is what measures how many artifacts exist because ADscan
# produced them versus because somebody asked.
TRIGGER_AUTO_POST_SCAN = "auto_post_scan"
TRIGGER_REPL_REPORT = "repl_report"
TRIGGER_REPL_DELIVER = "repl_deliver"
TRIGGER_REPL_WRITEUP = "repl_writeup"
TRIGGER_CI = "ci"

_AUTOMATIC_TRIGGERS = frozenset({TRIGGER_AUTO_POST_SCAN})

# Session state. Plain shell attributes, never ``domains_data`` — that dict is
# JSON-persisted and must not carry transient per-run bookkeeping.
_PATH_ATTR = "_post_scan_report_path"
_OFFER_ATTR = "_post_scan_report_offer_shown"
_DISPOSITION_ATTR = "_post_scan_report_disposition"
_WRITEUP_PATH_ATTR = "_post_scan_writeup_path"
_WRITEUP_DISPOSITION_ATTR = "_post_scan_writeup_disposition"


@dataclass(frozen=True, slots=True)
class PostScanDisposition:
    """What this scan-completion moment does with each of the two artifacts.

    Attributes:
        report: One of the ``DISPOSITION_*`` constants.
        writeup: One of the ``WRITEUP_*`` constants.
    """

    report: str
    writeup: str


def is_automatic_trigger(trigger: str) -> bool:
    """Return whether ``trigger`` names an artifact ADscan produced unasked.

    The single definition both artifact events consume, so ``automatic`` means
    the same thing on ``exposure_report_generated`` and on
    ``writeup_spine_generated`` and the two can be compared directly.
    """
    return str(trigger) in _AUTOMATIC_TRIGGERS


def resolve_workspace_type(shell: Any) -> str:
    """Return the canonical workspace type for this session.

    Reuses the telemetry normalizer so the value joins cleanly with the
    ``workspace_type`` already carried by ``scan_complete``. Falls back to
    ``"unknown"`` rather than guessing, so an unset type is never treated as an
    engagement.
    """
    return (
        normalize_workspace_type(getattr(shell, "type", None)) or WORKSPACE_TYPE_UNKNOWN
    )


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


def get_post_scan_writeup_path(shell: Any) -> str | None:
    """Return the writeup spine already written in this run, if any.

    This is what the idempotency guard keys on, and it is recorded by
    :func:`remember_post_scan_writeup_path` from the one instrumented generator
    — so a spine the operator built by hand with ``writeup`` counts too, and a
    later scan completion in the same session does not quietly write a second
    draft beside the one they are already editing.
    """
    value = getattr(shell, _WRITEUP_PATH_ATTR, None)
    return str(value) if isinstance(value, str) and value else None


def remember_post_scan_writeup_path(shell: Any, markdown_path: str | None) -> None:
    """Record the spine this run produced, whoever asked for it."""
    if isinstance(markdown_path, str) and markdown_path:
        _remember(shell, _WRITEUP_PATH_ATTR, markdown_path)


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


def _writeup_source_exists(shell: Any) -> bool:
    """Return whether the workspace holds a domain to write a spine about.

    Mirrors exactly what the generator refuses on, and does it without touching
    the disk: a spine needs an open workspace and a resolvable domain, and
    everything else it reads degrades the document rather than blocking it (a
    workspace with no execution record still produces a useful spine, which is
    why this gate is NOT the technical-report check the exposure report uses).
    Without the gate, a scan that collected nothing would end on the generator's
    "Run a scan first" error, which reads as a failure right after a scan.
    """
    if not str(getattr(shell, "current_workspace_dir", "") or ""):
        return False
    current = getattr(shell, "domain", None) or getattr(shell, "current_domain", None)
    if str(current or "").strip():
        return True
    domains_data = getattr(shell, "domains_data", None)
    return bool(isinstance(domains_data, dict) and domains_data)


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
        "automatic": is_automatic_trigger(trigger),
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


def _resolve_report_disposition(shell: Any, workspace_type: str) -> str:
    """Decide what this scan-completion moment does with the exposure report.

    Workspace type and tier are ORTHOGONAL, so the workspace type is branched on
    first and each branch resolves the tier inside it. Written as one flat chain
    with the tier tested first, a ``tier.is_pro()`` early return swallows every
    workspace type below it — which is how a PRO operator on a practice box
    would be handed a client-deliverable call to action for a client that does
    not exist. Keep the split; do not flatten this back into a chain.
    """
    if get_post_scan_report_path(shell):
        return DISPOSITION_ALREADY_GENERATED
    if workspace_type == WORKSPACE_TYPE_CTF:
        return _lab_report_disposition(shell)
    return _engagement_report_disposition(shell, workspace_type)


def _lab_report_disposition(shell: Any) -> str:
    """Resolve the report decision on a DECLARED lab workspace, either tier.

    PRO gets no client-deliverable call to action here and no report offer
    either. There is no client behind a practice box, the REPL's report verbs
    resolve to the paid kit on this tier, and the artifact this run actually
    produced — the writeup spine — has already landed with its own panel.
    Naming a second, wrong artifact in the same moment is what teaches an
    operator to skip the panel on the engagement where it matters.
    """
    if is_non_interactive(shell):
        # A lab run with nobody at the keyboard: an offer nobody can act on is
        # just noise in a log.
        return DISPOSITION_SILENT
    if tier.is_pro():
        return DISPOSITION_LAB_ARTIFACT
    return DISPOSITION_OFFERED


def _engagement_report_disposition(shell: Any, workspace_type: str) -> str:
    """Resolve the report decision on an engagement or an unlabelled workspace.

    An unlabelled workspace is treated as an engagement for PRO and as a lab for
    LITE, and both are the fail-safe direction for their tier: hiding the paid
    tier's only call to action because nobody set a workspace type is worse than
    naming it once too often, and auto-rendering a client report for a run that
    was never declared an engagement is worse than offering it.
    """
    if tier.is_pro():
        # Naming the kit after a scan that collected nothing points the operator
        # at a command with no document behind it, so the kit answers to the
        # same scan-data gate the engagement report does.
        if not _technical_report_exists(shell):
            return DISPOSITION_NO_SCAN_DATA
        return DISPOSITION_PRO_KIT
    if workspace_type == WORKSPACE_TYPE_AUDIT:
        if not _technical_report_exists(shell):
            return DISPOSITION_NO_SCAN_DATA
        return DISPOSITION_AUTO_GENERATED
    if is_non_interactive(shell):
        return DISPOSITION_SILENT
    return DISPOSITION_OFFERED


def _resolve_writeup_disposition(shell: Any, workspace_type: str) -> str:
    """Decide what this scan-completion moment does with the writeup spine.

    Deliberately does NOT consult the tier. The spine is a lab artifact, it
    costs nothing to produce, and format availability is not this product's paid
    boundary — a PRO operator running a box gets it on the same terms as a free
    one.

    Non-interactive stays silent, and that is about generation, not just about
    printing: an unattended lab run (the validation loop, a scripted box) has
    nobody who wanted a draft, so writing one into the workspace would be
    unasked-for churn rather than the artifact-while-it-is-fresh this exists
    for.
    """
    if workspace_type != WORKSPACE_TYPE_CTF:
        return WRITEUP_NOT_A_LAB
    if get_post_scan_writeup_path(shell):
        return WRITEUP_ALREADY_GENERATED
    if is_non_interactive(shell):
        return WRITEUP_SILENT
    if not _writeup_source_exists(shell):
        return WRITEUP_NO_SCAN_DATA
    return WRITEUP_AUTO_GENERATED


def _resolve_disposition(shell: Any, workspace_type: str) -> PostScanDisposition:
    """Resolve both artifact decisions for this scan-completion moment."""
    return PostScanDisposition(
        report=_resolve_report_disposition(shell, workspace_type),
        writeup=_resolve_writeup_disposition(shell, workspace_type),
    )


def _print_rendering_notice() -> None:
    """Print the one dim line that covers the render, so the pause is explained."""
    from rich.text import Text

    try:
        get_console().print(
            Text("Writing the exposure report for this engagement...", style="dim")
        )
    except Exception:  # noqa: BLE001 - cosmetic
        pass


def _generate_writeup_spine(shell: Any) -> str | None:
    """Write the writeup spine for this run, or return ``None``.

    Best-effort twice over: the generator is already written never to raise, and
    the import itself is wrapped so a stripped or broken module degrades to "no
    spine" instead of into the scan's success path.
    """
    try:
        from adscan_internal.services.writeup_spine import generate_writeup_spine

        artifacts = generate_writeup_spine(shell, trigger=TRIGGER_AUTO_POST_SCAN)
    except Exception as exc:  # noqa: BLE001 - a convenience never breaks a scan
        _swallow(exc)
        return None
    return get_post_scan_writeup_path(shell) if artifacts is not None else None


def run_post_scan_report(shell: Any, verb: str) -> str | None:
    """Resolve and execute the post-scan moment for both artifacts. Never raises.

    Call this once per completed scan, BEFORE the ``Scan complete`` recap panel
    renders, so the recap can point at the artifact this produced.

    The writeup spine goes first because it is a handful of file reads while the
    report render drives Chromium; on any given workspace only one of the two
    ever runs automatically, so the order is about not making a fast artifact
    wait behind a slow one.

    Args:
        shell: The active pentest shell.
        verb: The completed scan verb (``"start_auth"`` / ``"start_unauth"``).

    Returns:
        The path to the exposure report when one exists for this run, else
        ``None``. The writeup spine, when one was written, is reachable through
        :func:`get_post_scan_writeup_path`.
    """
    try:
        workspace_type = resolve_workspace_type(shell)
        disposition = _resolve_disposition(shell, workspace_type)
        _remember(shell, _DISPOSITION_ATTR, disposition.report)
        _remember(shell, _WRITEUP_DISPOSITION_ATTR, disposition.writeup)

        properties: dict[str, Any] = {
            "command": str(verb),
            "workspace_type": workspace_type,
            "disposition": disposition.report,
            "auto_generated": disposition.report == DISPOSITION_AUTO_GENERATED,
            "writeup_disposition": disposition.writeup,
            "writeup_auto_generated": disposition.writeup == WRITEUP_AUTO_GENERATED,
            "non_interactive": bool(is_non_interactive(shell)),
            "tier": tier.tier_name(),
        }
        properties.update(_lab_fields(shell))
        _emit_moment(properties)

        if disposition.writeup == WRITEUP_AUTO_GENERATED:
            _generate_writeup_spine(shell)

        if disposition.report == DISPOSITION_ALREADY_GENERATED:
            return get_post_scan_report_path(shell)
        if disposition.report != DISPOSITION_AUTO_GENERATED:
            return None

        _print_rendering_notice()
        return generate_report_with_telemetry(shell, trigger=TRIGGER_AUTO_POST_SCAN)
    except Exception as exc:  # noqa: BLE001 - the scan flow owns this thread
        _swallow(exc)
        return None


def pro_kit_offer_warranted(shell: Any) -> bool:
    """Return whether the recap should name the paid deliverable kit.

    PRO is the one tier this seam produces nothing for, by design: generating a
    kit unasked would render the wrong document (it carries the frameworks, the
    theme, the branding and the ``--only`` scope the consultant chooses), and on
    a multi-domain forest one scan per subworkspace would mean N unwanted kits.
    So the moment's job for PRO is to NAME the kit at the weight of the result
    it belongs to, which the ``Scan complete`` recap already owns — this
    predicate is what tells that panel whether the naming is warranted.

    Fails OPEN. A ``None`` disposition means this scan-completion seam never ran
    (a non-scan flow rendering the same recap), and hiding a paid tier's only
    call to action on a bookkeeping absence is the worse error of the two.
    """
    disposition = getattr(shell, _DISPOSITION_ATTR, None)
    if disposition is None:
        return True
    return disposition == DISPOSITION_PRO_KIT


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

    On a lab workspace the spine has normally already been written by
    :func:`run_post_scan_report` and announced with its own panel, so there is
    nothing to offer and the line is suppressed. It reappears only when this run
    has no spine on disk — generation failed, or the workspace had nothing to
    write about yet — which is the one case where naming the verb helps rather
    than pointing at work already done.

    No-op unless :func:`run_post_scan_report` resolved the report to
    :data:`DISPOSITION_OFFERED`, which already excludes PRO, engagements, and
    non-interactive runs.
    """
    if getattr(shell, _DISPOSITION_ATTR, None) != DISPOSITION_OFFERED:
        return
    try:
        if resolve_workspace_type(
            shell
        ) == WORKSPACE_TYPE_CTF and not get_post_scan_writeup_path(shell):
            _print_offer_line(
                "Build the writeup spine from this run's evidence:", "writeup"
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
    "DISPOSITION_LAB_ARTIFACT",
    "DISPOSITION_NO_SCAN_DATA",
    "DISPOSITION_OFFERED",
    "DISPOSITION_PRO_KIT",
    "DISPOSITION_SILENT",
    "TRIGGER_AUTO_POST_SCAN",
    "TRIGGER_CI",
    "TRIGGER_REPL_DELIVER",
    "TRIGGER_REPL_REPORT",
    "TRIGGER_REPL_WRITEUP",
    "WORKSPACE_TYPE_AUDIT",
    "WORKSPACE_TYPE_CTF",
    "WRITEUP_ALREADY_GENERATED",
    "WRITEUP_AUTO_GENERATED",
    "WRITEUP_NOT_A_LAB",
    "WRITEUP_NO_SCAN_DATA",
    "WRITEUP_SILENT",
    "PostScanDisposition",
    "generate_report_with_telemetry",
    "get_post_scan_report_display_path",
    "get_post_scan_report_path",
    "get_post_scan_writeup_path",
    "is_automatic_trigger",
    "print_post_scan_report_offer",
    "pro_kit_offer_warranted",
    "remember_post_scan_writeup_path",
    "resolve_workspace_type",
    "run_post_scan_report",
]
