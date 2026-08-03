"""Post-scan ``Scan complete`` panel.

Tier-aware: LITE shows scan results, LITE-friendly next commands, and a
single line mentioning the PRO Client Deliverable Kit. PRO shows the full
deliverable kit as actionable next steps.

GIVE first, ASK at end (LITE) or pure GIVE (PRO). The earlier registry-
driven implementation surfaced PRO-only verbs to LITE users, which is a
give/ask regression — this module is the canonical fix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable

from adscan_core import tier
from adscan_core.rich_output import print_panel
from adscan_core.theme import ADSCAN_PRIMARY, ADSCAN_PRIMARY_BRIGHT
from adscan_internal.cli.shell_commands import (
    ShellCommandSpec,
    specs_suggested_after,
)

if TYPE_CHECKING:
    from adscan_internal.cli.widgets.scan_recap import ScanRecapModel
    from adscan_internal.services.scan_outcome_scope import ScanOutcomeScope


# LITE-friendly next-step commands. Each verb MUST map to a real
# ``PentestShell.do_<verb>`` method that is usable in LITE — no deliverable
# PDF verbs (those are PRO-gated and surfaced via the demo line below). The
# anti-drift test ``tests/unit/cli/test_post_scan_lite_commands_exist.py``
# fails CI if a verb here has no matching ``do_<verb>`` or is a deliverable.
# (base do_<verb> for anti-drift validation, displayed invocation, description).
# The displayed invocation may carry a subcommand + args (e.g. ``creds save …``)
# while the anti-drift test still validates the base ``do_<verb>``. ``creds`` is
# split on purpose: ``creds show`` reviews what was captured, and
# ``creds save`` continues the scan as a freshly-captured principal WITHOUT
# re-running ``start_auth`` — the most direct pivot when a new credential lands.
_LITE_NEXT_COMMANDS: tuple[tuple[str, str, str], ...] = (
    ("attack_paths", "attack_paths", "explore the attack graph"),
    ("creds", "creds show", "review the credentials recovered so far"),
    (
        "creds",
        "creds save <domain> <user> <cred>",
        "continue as a new principal — no need to re-run start_auth",
    ),
)


@dataclass(frozen=True)
class ScanSummary:
    """Severity counts pulled from the scan summary, when available."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    report_path: str | None = None

    def render_findings_line(self) -> str:
        return f"{self.critical} critical · {self.high} high · {self.medium} medium"


def _render_header(summary: ScanSummary | None) -> list[str]:
    """Render the GIVE: scan results header. Always first."""
    findings = summary.render_findings_line() if summary else "— · — · —"
    report = (summary.report_path if summary else None) or "(see workspace)"
    return [
        f"  [bold]Findings:[/] [grey70]{findings}[/]",
        f"  [bold]Report:[/]   [bright_cyan]{report}[/]",
    ]


def _render_lite_body(summary: ScanSummary | None) -> str:
    lines: list[str] = []
    lines.extend(_render_header(summary))
    lines.append("")
    lines.append("  [bold bright_cyan]Next:[/]")
    verb_width = max(len(inv) for _v, inv, _d in _LITE_NEXT_COMMANDS)
    for _verb, invocation, desc in _LITE_NEXT_COMMANDS:
        verb_cell = f"[bright_cyan on grey11]{invocation.ljust(verb_width)}[/]"
        lines.append(f"    {verb_cell}    [grey70]{desc}[/]")
    lines.append("")
    lines.append(
        "  [grey70]PRO ships a client deliverable kit. "
        "See [bold bright_cyan]adscan demo[/].[/]"
    )
    return "\n".join(lines)


def _render_pro_body(
    summary: ScanSummary | None,
    suggestions: Iterable[ShellCommandSpec],
) -> str:
    rows = list(suggestions)
    lines: list[str] = []
    lines.extend(_render_header(summary))
    lines.append("")
    lines.append("  [bold bright_cyan]Generate the client deliverable:[/]")
    if not rows:
        return "\n".join(lines)
    verb_width = max(len(s.verb) for s in rows)
    for spec in rows:
        verb_cell = f"[bright_cyan on grey11]{spec.verb.ljust(verb_width)}[/]"
        lines.append(f"    {verb_cell}    [grey70]{spec.short_help}[/]")
    return "\n".join(lines)


def _resolve_recap_scope(shell: Any) -> "ScanOutcomeScope":
    """Return the scan's :class:`ScanOutcomeScope` — which domain to speak about.

    Delegates to the SSOT (:mod:`adscan_internal.services.scan_outcome_scope`),
    which composes the assessed/discovered split the client reports use with the
    per-domain proven-compromise marker. The recap must never pick a domain by
    position in ``shell.domains``: that list carries trust-discovered names the
    engagement never enumerated, and its order is not even recency.
    """
    from adscan_internal.services.scan_outcome_scope import resolve_scan_outcome_scope

    return resolve_scan_outcome_scope(shell)


def _format_scan_delta(shell: Any, attr: str) -> str | None:
    """Format ``shell.<attr> - shell.scan_start_time`` as ``Nm SSs``.

    Both timestamps are ``time.monotonic()`` values (see ``adscan.py``). Returns
    ``None`` when either is absent. Best-effort; never raises.
    """
    try:
        end = getattr(shell, attr, None)
        start = getattr(shell, "scan_start_time", None)
        if not end or not start:
            return None
        seconds = max(0.0, float(end) - float(start))
        minutes = int(seconds // 60)
        return f"{minutes}m {int(seconds % 60):02d}s"
    except Exception:  # noqa: BLE001 - cosmetic label, never breaks exit
        return None


def _mark_recap_node(name: str) -> str:
    """Domain-suffix-strip + ``mark_sensitive`` a path node label.

    Mirrors ``attack_graph_reports._mark_node`` so the recap and the interactive
    attack-paths view label nodes identically (cleartext on screen, scrubbed in
    telemetry).
    """
    from adscan_internal.rich_output import mark_sensitive

    display = name.split("@")[0] if "@" in name else name
    if "." in display or display.endswith("$"):
        return mark_sensitive(display, "hostname")
    return mark_sensitive(display, "user")


def _build_headline_path(shell: Any, domain: str) -> "Any | None":
    """Fetch the single highest-value validated path, non-interactively.

    ``engine_override="local"`` is mandatory — it skips the dev engine selector
    that would otherwise prompt/hang at scan-end. ``render_debug_tables=False``
    keeps the recap computation silent. Returns a ``RecapPath`` or ``None``.
    """
    from adscan_internal.cli.widgets.scan_recap import RecapPath
    from adscan_internal.services.attack_graph_service import (
        get_attack_path_summaries,
    )

    summaries = get_attack_path_summaries(
        shell,
        domain,
        max_depth=10,
        max_paths=1,
        engine_override="local",
        render_debug_tables=False,
    )
    if not summaries:
        return None
    entry = summaries[0]
    raw_nodes = entry.get("nodes")
    if not isinstance(raw_nodes, list) or len(raw_nodes) < 2:
        return None
    raw_edges = entry.get("relations") or entry.get("rels") or []
    if not isinstance(raw_edges, list):
        raw_edges = []

    nodes = tuple(_mark_recap_node(str(node)) for node in raw_nodes)
    edges = tuple(str(edge) for edge in raw_edges)
    source = _mark_recap_node(str(entry.get("source") or raw_nodes[0]))
    klass = str(entry.get("compromise_class") or entry.get("outcome_class") or "")
    return RecapPath(
        nodes=nodes,
        edges=edges,
        compromise_class=klass,
        source=source,
    )


# How many collapsed capability nodes the recap surfaces. The recap is a
# digest — the full list lives in ``adscan attack_paths`` — so a tight cap keeps
# the highest-value blast-radius findings front-and-center.
_RECAP_FANOUT_MAX: int = 3


def build_recap_fanout_steps(
    shell: Any, domain: str, *, max_steps: int | None = _RECAP_FANOUT_MAX
) -> tuple[Any, ...]:
    """Resolve the top outbound fan-out capability nodes for a domain.

    Computed directly over the materialized attack-graph EDGES (count-accurate
    and cheap — no per-path DFS budget) via the rollup SSOT
    (:mod:`adscan_internal.services.attack_fanout_rollup`). Structural
    tautologies (a Domain Breaker source, which the AD hierarchy grants full
    control by definition) resolve to ``INFO``/``STRUCTURAL`` severity and are
    dropped, so only real control sprawl surfaces. Best-effort: any failure
    returns an empty tuple and the caller simply omits the section.

    Shared by the end-of-scan recap (default ``max_steps``) and the
    ``attack_paths`` listing (which may surface more). Returns a tuple of
    :class:`adscan_internal.services.attack_fanout_rollup.FanoutStep`.
    """
    try:
        from adscan_internal.cli.intelligence import _node_compromise_class
        from adscan_internal.services.attack_fanout_rollup import (
            fanout_input_from_edge,
            genuine_fanout_steps,
        )
        from adscan_internal.services.attack_graph_service import load_attack_graph
    except Exception:  # noqa: BLE001 - never break the scan success path
        return ()

    try:
        graph = load_attack_graph(shell, domain)
    except Exception:  # noqa: BLE001
        return ()

    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    edges = graph.get("edges") if isinstance(graph, dict) else None
    if not isinstance(nodes, dict) or not isinstance(edges, list):
        return ()

    # Stamp a best-effort compromise class onto each node so the rollup's
    # severity grading (and the Domain-Breaker suppression) can classify the
    # fan-out source/target. Failures per node are non-fatal.
    for node in nodes.values():
        if not isinstance(node, dict) or node.get("compromise_class") is not None:
            continue
        try:
            klass = _node_compromise_class(node)
        except Exception:  # noqa: BLE001
            klass = None
        node["compromise_class"] = klass.value if klass is not None else None

    inputs = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        adapted = fanout_input_from_edge(edge, nodes)
        if adapted is not None:
            inputs.append(adapted)

    # The genuine-fan-out filter (count at/above the floor; drop INFO/STRUCTURAL
    # structural tautologies and the single-edge Tier-0-direct nodes) is the
    # shared SSOT so the recap, PDF, and web read identical blast-radius findings.
    return genuine_fanout_steps(inputs, max_steps=max_steps)


def _recap_try_next(outcome: str) -> tuple[tuple[str, str], ...]:
    """Return the ``Try next`` verbs for an outcome, sourced from the SSOT list.

    Verbs come from :data:`_LITE_NEXT_COMMANDS` so the anti-drift test keeps them
    honest. ``domain_compromised`` shows none (the chain + CTA carry it).
    """
    # Select by BASE verb (first token of the invocation) so a verb with several
    # invocations (``creds show`` / ``creds save …``) surfaces all of them without
    # a dict collapse. Order is preserved from the SSOT list.
    if outcome == "findings":
        wanted = ("attack_paths", "creds")
    elif outcome == "clean":
        wanted = ("attack_paths",)
    else:
        return ()
    return tuple(
        (invocation, desc)
        for base_verb, invocation, desc in _LITE_NEXT_COMMANDS
        if base_verb in wanted
    )


def build_scan_recap_model(shell: Any, verb: str) -> "ScanRecapModel | None":
    """Resolve the end-of-scan recap model from live scan artifacts.

    All AD I/O (findings read, path metrics, headline path) is best-effort and
    isolated in its own try/except — a recap-model failure returns ``None`` and
    the caller falls back to the legacy panel. Never raises.

    Args:
        shell: The active pentest shell (workspace + session state).
        verb: The completed scan verb (``"start_auth"`` / ``"start_unauth"``).

    Returns:
        A populated :class:`ScanRecapModel`, or ``None`` when no domain is in
        scope or the model could not be assembled.
    """
    try:
        from adscan_core.reporting.technical_report import (
            FindingsSummary,
            _get_technical_report_path,
            summarize_findings,
        )
        from adscan_internal.cli.widgets.scan_recap import ScanRecapModel
    except Exception:  # noqa: BLE001 - never break the scan success path
        return None

    # WHICH domain the outcome is about — never "the last name the session
    # learned". A domain reached only through a trust is not a domain this
    # engagement can make a claim about, and the counts below must resolve for
    # the same domain the headline names or they go silently to zero.
    scope = _resolve_recap_scope(shell)
    domain = scope.subject
    if not domain:
        return None

    findings = FindingsSummary()
    try:
        findings = summarize_findings(shell, domain=domain)
    except Exception:  # noqa: BLE001
        findings = FindingsSummary()

    if scope.domain_compromised:
        outcome = "domain_compromised"
    elif findings.total > 0:
        outcome = "findings"
    else:
        outcome = "clean"

    # Attack-path counts come from the counts SSOT, which prefers the
    # ``exposure_kpis`` block this run already stamped into
    # ``technical_report.json`` (the post-scan report runs BEFORE this panel).
    # So the recap states the figures the client's own report states, and reads
    # them instead of re-walking the graph.
    from adscan_internal.services.attack_path_counts import (
        ClientPathTotals,
        client_path_totals_for_shell,
    )

    try:
        path_totals = client_path_totals_for_shell(shell, domain)
    except Exception:  # noqa: BLE001
        path_totals = ClientPathTotals()

    headline_path = None
    try:
        headline_path = _build_headline_path(shell, domain)
    except Exception:  # noqa: BLE001
        headline_path = None

    # Prefer the shareable exposure report when this run produced one: that is
    # the file the operator can actually send. The technical JSON is the
    # fallback, so a run without a report keeps the previous behaviour.
    report_path = None
    try:
        from adscan_internal.services.post_scan_report import (
            get_post_scan_report_display_path,
        )

        report_path = get_post_scan_report_display_path(shell)
    except Exception:  # noqa: BLE001
        report_path = None
    if not report_path:
        try:
            report_path = str(_get_technical_report_path(shell))
        except Exception:  # noqa: BLE001
            report_path = None

    fanout = ()
    try:
        fanout = build_recap_fanout_steps(shell, domain)
    except Exception:  # noqa: BLE001
        fanout = ()

    return ScanRecapModel(
        domain=domain,
        outcome=outcome,  # type: ignore[arg-type]
        findings=findings,
        also_compromised=scope.also_compromised,
        # Only when the engagement saw a domain it never enumerated: the label is
        # the report's own, so the panel and the cover state coverage identically.
        scope_label=scope.scope_label if scope.scope.has_discovered else "",
        headline_path=headline_path,
        paths_total=path_totals.paths_total,
        paths_full_domain_compromise=path_totals.paths_full_domain_compromise,
        paths_proven=path_totals.paths_proven,
        ttc_label=_format_scan_delta(shell, "_scan_compromise_time"),
        ttfc_label=_format_scan_delta(shell, "_scan_first_credential_time"),
        report_path=report_path,
        try_next=_recap_try_next(outcome),
        fanout=fanout,
    )


def _build_lite_cta(model: "ScanRecapModel"):
    """Return the LITE give:ask CTA line, or ``None`` for the clean result.

    No em dash, no puffery: sells PRO's actual differentiation (the done-for-you
    client deliverable) and never implies LITE is crippled. Suppressed on the
    null result per the give:ask gate (no ask after a null win).
    """
    if model.outcome == "domain_compromised":
        body = (
            "You proved a path to full domain compromise. PRO turns this run "
            "into a client-ready PDF report and hardening playbook."
        )
    elif model.outcome == "findings":
        total = model.findings.total
        noun = "finding" if total == 1 else "findings"
        body = (
            f"{total} {noun}, mapped and evidenced. PRO packages them into a "
            "client PDF with prioritized remediation."
        )
    else:
        return None

    from rich.text import Text

    return Text.assemble(
        Text(body, style="dim"),
        Text("   →  ", style="dim"),
        Text("adscan demo", style=f"bold {ADSCAN_PRIMARY_BRIGHT}"),
    )


# What ``deliver`` decides and what it costs, in the moment the operator is
# deciding whether to run it. The verb alone was already here; these are the two
# things that stop someone launching it — not knowing that the frameworks, the
# scope and the branding are theirs to pick, and not knowing whether it returns
# in seconds or in an hour. Kept out of the registry's ``short_help`` on purpose:
# that string is the global one-liner shown in every command listing, and this
# sentence only makes sense at the end of a scan.
_DELIVER_NOTE = (
    "It asks what to include (compliance frameworks, which documents, your "
    "client's logo) and takes a few minutes to render."
)


def _build_pro_cta(suggestions: Iterable[ShellCommandSpec]):
    """Return the PRO deliverable-verb block, or ``None`` when none registered.

    Rendered inside the ``Scan complete`` panel rather than as a panel of its
    own: on a paid engagement the deliverable IS the result, so it belongs at
    the weight of the result, and a second panel in the same moment competes
    with the one the operator is already reading.
    """
    rows = list(suggestions)
    if not rows:
        return None

    from rich.console import Group
    from rich.text import Text

    lines: list[Any] = [Text("Generate the client deliverable:", style="bold")]
    verb_width = max(len(spec.verb) for spec in rows)
    for spec in rows:
        lines.append(
            Text.assemble(
                Text(
                    "  " + spec.verb.ljust(verb_width),
                    style=f"bold {ADSCAN_PRIMARY_BRIGHT}",
                ),
                Text("    "),
                Text(spec.short_help, style="dim"),
            )
        )
    if any(spec.verb == "deliver" for spec in rows):
        from rich.padding import Padding

        # Padding, not a two-space prefix: the note wraps at panel width, and a
        # prefixed string indents only its first line, so the paragraph's left
        # edge would break away from the verb column underneath it.
        lines.append(Text(""))
        lines.append(Padding(Text(_DELIVER_NOTE, style="dim"), (0, 0, 0, 2)))
    return Group(*lines)


def _pro_cta_warranted(shell: Any | None) -> bool:
    """Return whether this run left the deliverable kit something to build.

    Delegates to the post-scan moment, which already resolved it: the kit is
    named on an engagement that collected data, and stays quiet on a practice
    box (no client behind it, and the writeup spine already landed) or after a
    scan that produced nothing. Fails open, exactly like the predicate it calls.
    """
    if shell is None:
        return True
    try:
        from adscan_internal.services.post_scan_report import pro_kit_offer_warranted

        return bool(pro_kit_offer_warranted(shell))
    except Exception:  # noqa: BLE001 - never hide the paid CTA on a lookup error
        return True


def _print_recap_panel(
    model: "ScanRecapModel",
    *,
    is_pro: bool,
    suggestions: Iterable[ShellCommandSpec],
    shell: Any | None = None,
) -> None:
    """Render the premium recap panel (shared body + tier-gated CTA footer)."""
    from rich.console import Group
    from rich.text import Text

    from adscan_internal.cli.widgets.scan_recap import build_recap_body, recap_hairline

    parts: list[Any] = [build_recap_body(model)]

    if is_pro:
        cta = _build_pro_cta(suggestions) if _pro_cta_warranted(shell) else None
    else:
        cta = _build_lite_cta(model)
    if cta is not None:
        parts.append(Text(""))
        parts.append(recap_hairline())
        parts.append(cta)

    print_panel(
        Group(*parts),
        title="[bold]Scan complete[/]",
        border_style=ADSCAN_PRIMARY,
        title_align="left",
        padding=(1, 2),
    )


def print_post_scan_suggestions(
    verb: str,
    summary: ScanSummary | None = None,
    *,
    shell: Any | None = None,
) -> None:
    """Render the ``Scan complete`` panel for the operator.

    When a ``shell`` is provided, renders the premium end-of-scan recap: the
    headline validated attack path, the severity picture, and the top findings,
    plus a tier-gated CTA (LITE → ``adscan demo``; PRO → the deliverable verbs).
    Without a ``shell`` (or if the recap model cannot be assembled), falls back
    to the legacy summary panel and its original no-op contract for non-scan
    flows.

    Args:
        verb: The shell verb that just completed successfully (e.g.
            ``"start_auth"`` or ``"start_unauth"``).
        summary: Optional legacy :class:`ScanSummary` with finding counts, used
            only by the fallback path.
        shell: The active pentest shell. When given, drives the premium recap.
    """
    is_pro = tier.is_pro()
    suggestions = specs_suggested_after(verb)

    # Premium recap path: requires a shell to read the scan artifacts.
    if shell is not None:
        model = None
        try:
            model = build_scan_recap_model(shell, verb)
        except Exception:  # noqa: BLE001 - fall back to the legacy panel
            model = None
        if model is not None:
            _print_recap_panel(
                model, is_pro=is_pro, suggestions=suggestions, shell=shell
            )
            return

    # Legacy fallback. Silent for unknown verbs unless we have something
    # concrete to show (a summary). Preserves the no-op contract for non-scan
    # flows that wire this in defensively.
    if not suggestions and summary is None:
        return

    if is_pro:
        body = _render_pro_body(summary, suggestions)
    else:
        body = _render_lite_body(summary)

    if not body:
        return

    print_panel(
        body,
        title="[bold bright_cyan]Scan complete[/]",
        border_style="bright_cyan",
        title_align="left",
        padding=(1, 2),
    )


__all__ = [
    "print_post_scan_suggestions",
    "build_scan_recap_model",
    "build_recap_fanout_steps",
    "ScanSummary",
]
