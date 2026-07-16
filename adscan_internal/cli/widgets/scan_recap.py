"""Premium end-of-scan recap widget (LITE-safe, pure render).

The recap is the highest-value screen in the LITE experience: it renders what
the scan actually proved (the headline validated attack path, the severity
picture, the top findings) in the same editorial-forensic house style as the
interactive ``attack_paths`` view. It is a DIGEST, not the explorer — one
headline path, severity counts, and a pointer to ``adscan attack_paths``.

Design: a pure data model (:class:`ScanRecapModel`) plus a pure renderer
(:func:`build_recap_body`) that is a total function of the model. All AD I/O
lives in the orchestration seam (``post_scan_suggestions.build_scan_recap_model``)
so the three outcome states are unit-testable without a shell or a DC.

Aesthetic direction is inherited from
``adscan_internal/cli/compromise_render.py``: hairline separators, restrained
color, one crimson reserved for the ``★ DOMAIN COMPROMISED`` terminus. Colors
come from the theme SSOT ``adscan_core.theme`` — no hardcoded hex.

The widget never constructs a raw ``rich.Console`` (TeeConsole invariant) and
never parses uncontrolled strings as markup: every interpolated value is wrapped
in a ``Text`` object (literal, MarkupError-safe). Node/domain labels are
``mark_sensitive``-wrapped so they render cleartext to the operator but are
scrubbed in telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from adscan_core.reporting.technical_report import FindingsSummary
from adscan_core.theme import (
    ADSCAN_PRIMARY_BRIGHT,
    COLOR_AMBER,
    COLOR_CRIMSON,
    COLOR_STEEL,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.attack_fanout_rollup import FanoutStep
from adscan_internal.services.edge_kind import EdgeKind

Outcome = Literal["domain_compromised", "findings", "clean"]

# Width of the hairline separators. Keeps the recap visually aligned with the
# ~78-col premium panels without hardcoding the terminal width (the panel clips).
_HAIRLINE_WIDTH: int = 72

# Severity ramp — only the count/dot carries the color, the word stays dim.
_SEVERITY_STYLE: dict[str, str] = {
    "critical": COLOR_CRIMSON,
    "high": COLOR_AMBER,
    "medium": "yellow",
    "low": COLOR_STEEL,
}

_SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")


@dataclass(frozen=True)
class RecapPath:
    """The headline validated path, node/edge labels already display-ready.

    ``nodes`` are domain-suffix-stripped and ``mark_sensitive``-wrapped by the
    orchestration seam; the widget passes them through to the shared renderer.
    The renderer replaces the final node visually with the crimson terminus.
    """

    nodes: tuple[str, ...]
    edges: tuple[str, ...]
    compromise_class: str
    source: str


@dataclass(frozen=True)
class ScanRecapModel:
    """Everything the recap renders, resolved once by the orchestration seam."""

    domain: str
    outcome: Outcome
    findings: FindingsSummary
    headline_path: RecapPath | None = None
    paths_to_tier0: int = 0
    ttc_label: str | None = None
    ttfc_label: str | None = None
    report_path: str | None = None
    try_next: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    # Collapsed outbound fan-out "capability nodes" (privilege blast radius):
    # one line per (source principal, edge kind, target tier) that fans out to
    # many targets, resolved once by the orchestration seam via the rollup SSOT
    # (:mod:`adscan_internal.services.attack_fanout_rollup`). Empty when no
    # source fans out past the collapse floor.
    fanout: tuple[FanoutStep, ...] = field(default_factory=tuple)


def recap_hairline() -> Text:
    """Return the dim hairline separator used across the recap and CTA."""
    return Text("─" * _HAIRLINE_WIDTH, style="dim")


def _headline(model: ScanRecapModel) -> Text:
    """Render the top outcome line for each of the three states."""
    domain = Text(mark_sensitive(model.domain, "domain"), style="bold")
    if model.outcome == "domain_compromised":
        return Text.assemble(
            Text("★ DOMAIN COMPROMISED", style=f"bold {COLOR_CRIMSON}"),
            Text("   "),
            domain,
            Text("   "),
            Text("full domain compromise", style="dim"),
        )
    if model.outcome == "findings":
        return Text.assemble(
            domain,
            Text("   "),
            Text("no full compromise: this domain held", style="dim"),
        )
    return Text.assemble(
        domain,
        Text("   "),
        Text("no findings surfaced", style="dim"),
    )


def _timing_line(model: ScanRecapModel) -> Text | None:
    """Render the dim time-to / path-reach line beneath the headline."""
    if model.outcome == "domain_compromised":
        parts: list[Text] = []
        if model.ttc_label:
            parts.append(Text(f"Proven in {model.ttc_label}", style="dim"))
        if model.paths_to_tier0 > 0:
            plural = "path" if model.paths_to_tier0 == 1 else "paths"
            parts.append(
                Text(
                    f"{model.paths_to_tier0} validated {plural} to a Tier 0 asset",
                    style="dim",
                )
            )
        return _join_dim(parts)
    if model.outcome == "findings":
        parts = []
        if model.ttfc_label:
            parts.append(
                Text(f"First credential in {model.ttfc_label}", style="dim")
            )
        if model.paths_to_tier0 > 0:
            plural = "path" if model.paths_to_tier0 == 1 else "paths"
            parts.append(
                Text(
                    f"{model.paths_to_tier0} {plural} reach a Tier 0 asset "
                    "(control pending validation)",
                    style="dim",
                )
            )
        return _join_dim(parts)
    # clean: a graceful, honest paragraph — no dead-end framing.
    return Text(
        "No attack paths, no misconfigurations, and no exposed credentials in "
        "the scanned scope. A well-hardened domain, a narrow scan surface, or "
        "both.",
        style="dim",
    )


def _join_dim(parts: list[Text]) -> Text | None:
    """Join non-empty Text parts with a dim middle dot separator."""
    if not parts:
        return None
    out = Text()
    for index, part in enumerate(parts):
        if index:
            out.append("  ·  ", style="dim")
        out.append_text(part)
    return out


def _path_block(model: ScanRecapModel) -> RenderableType | None:
    """Render the headline path via the shared compromise taxonomy renderer.

    Domain-compromise → the full vertical chain terminating at the crimson
    ``★ DOMAIN COMPROMISED`` glyph (:func:`compromise_render.render_path_chain`,
    the same renderer the interactive attack_paths view uses). Findings with a
    Tier 0 reach → a dense "Closest reach" one-liner that terminates at the REAL
    target node, not the domain-compromise glyph (nomenclature rule: an auth edge
    onto a Tier 0 asset is a foothold, control pending — never "compromised").
    Any render failure degrades gracefully, then to nothing — the recap must
    never crash on path data.
    """
    path = model.headline_path
    if path is None or len(path.nodes) < 2:
        return None

    # Lazy import: keeps the widget importable in isolation and reuses the SSOT
    # badge/reach vocabulary (visual + label consistency with attack_paths).
    from adscan_internal.cli import compromise_render as cr

    klass = cr.coerce_class(path.compromise_class)
    nodes = list(path.nodes)
    edges = list(path.edges)
    n_hop = len(edges) or 1

    try:
        if model.outcome == "domain_compromised":
            if edges and len(edges) == len(nodes) - 1:
                return cr.render_path_chain(
                    nodes=nodes,
                    edges=edges,
                    klass=klass,
                    n_hop=n_hop,
                )
            # Malformed edge/node counts: the shared summary line terminates at
            # the DOMAIN COMPROMISED glyph, which is correct for a breaker.
            return cr.render_path_summary_line(
                klass=klass,
                n_hop=n_hop,
                source=path.source or nodes[0],
                primary_edge=edges[-1] if edges else "",
            )
        # findings: "Closest reach" — terminate at the real target node.
        return Group(
            Text("Closest reach", style="dim"),
            _closest_reach_line(cr, klass, path, nodes, edges),
        )
    except Exception:  # noqa: BLE001 - degrade gracefully, never crash exit
        return None


def _closest_reach_line(cr, klass, path: RecapPath, nodes: list[str], edges: list[str]) -> Text:
    """Return the honest one-liner for a Tier 0 foothold (control pending).

    Renders the path FAITHFULLY for any hop count. It follows the real
    ``nodes``/``edges`` chain: the source, its REAL first edge, the node that
    first hop reaches, then — for a multi-hop path — an ellipsis standing in for
    the omitted middle, terminating at the real target node with the SSOT reach
    phrase. It NEVER pairs the source with a non-adjacent edge (the old
    first-node ↔ last-edge splice fabricated a false relationship on any path
    longer than one hop, e.g. ``jon.snow -> MemberOf -> DOMAIN CONTROLLERS``).

    Termination is the real target node (e.g. ``DC01``), never the
    ``★ DOMAIN COMPROMISED`` glyph — the target is reached, its control unproven.

    Shapes:
        1-hop:   ``badge  source -> edge -> target   reach``
        n-hop:   ``badge  source -> first_edge -> next_node -> … -> target   reach``
    """
    source = path.source or (nodes[0] if nodes else "")
    target = nodes[-1] if nodes else ""
    first_edge = edges[0] if edges else ""
    arrow = Text(" -> ", style="dim")

    line = Text.assemble(
        cr.class_badge(klass),
        Text("  "),
        Text(source, style="bold"),
    )
    if first_edge:
        # The node the first (real, adjacent) hop actually reaches. For a
        # single-hop path this IS the target.
        next_node = nodes[1] if len(nodes) > 1 else target
        line.append_text(arrow)
        line.append(first_edge, style="italic")
        line.append_text(arrow)
        line.append(next_node, style="bold")
        # More than one hop: elide the middle with an ellipsis, then the real
        # target. The full chain lives in ``adscan attack_paths``.
        if len(nodes) > 2:
            line.append_text(arrow)
            line.append("…", style="dim")
            line.append_text(arrow)
            line.append(target, style="bold")
    line.append("   ")
    line.append_text(cr.class_reach(klass))
    return line


def _findings_block(model: ScanRecapModel) -> list[RenderableType]:
    """Render the severity strip plus the top findings, or [] when empty."""
    summary = model.findings
    if summary.total <= 0:
        return []

    strip = Text("Findings   ", style="bold")
    for index, severity in enumerate(_SEVERITY_ORDER):
        if index:
            strip.append(" · ", style="dim")
        count = getattr(summary, severity)
        strip.append(str(count), style=_SEVERITY_STYLE[severity])
        strip.append(f" {severity}", style="dim")

    out: list[RenderableType] = [strip]
    if summary.top:
        out.append(Text("─" * 51, style="dim"))
        table = Table.grid(expand=True, padding=(0, 1))
        table.add_column(justify="left", ratio=1)
        table.add_column(justify="right", no_wrap=True)
        for row in summary.top:
            style = _SEVERITY_STYLE.get(row.severity, "dim")
            label = Text.assemble(
                Text("● ", style=style),
                Text(row.title, style="dim"),
            )
            tag = Text(f"[{row.severity}]", style=style)
            table.add_row(label, tag)
        out.append(table)
    return out


# Business-phrased verb per edge kind (nomenclature standard — the client
# headline never carries the raw offensive edge token; the raw relation lives
# only in the dim technical sub-line). Keyed on the SSOT :class:`EdgeKind`.
_FANOUT_VERB: dict[EdgeKind, str] = {
    EdgeKind.CONTROL: "controls",
    EdgeKind.ESCALATION: "can escalate against",
    EdgeKind.DERIVED: "has proven control over",
    EdgeKind.AUTH: "can reach",
}


def _fanout_capability_phrase(step: FanoutStep) -> str:
    """Return the client-safe capability phrase for one collapsed fan-out step.

    Example: ``"controls 4,996 objects via one delegated right"``. No raw edge
    name (nomenclature standard) — the technical relation is rendered separately
    in the dim sub-line.
    """
    verb = _FANOUT_VERB.get(step.edge_kind, "reaches")
    noun = "hosts" if step.edge_kind is EdgeKind.AUTH else "objects"
    tail = " via one delegated right" if step.edge_kind is EdgeKind.CONTROL else ""
    return f"{verb} {step.count:,} {noun}{tail}"


def render_fanout_capability_lines(
    steps: tuple[FanoutStep, ...],
    *,
    with_header: bool = True,
) -> list[RenderableType]:
    """Render collapsed fan-out capability nodes as client-safe headline lines.

    Shared by the end-of-scan recap and the ``attack_paths`` listing so the
    "privilege blast radius" finding reads identically on both surfaces. Each
    step becomes one headline (fanning-out principal, business-phrased blast
    radius, tier, severity dot) plus a dim technical sub-line (the raw right and
    a bounded evidence sample). Returns ``[]`` for no steps.

    Args:
        steps: The collapsed :class:`FanoutStep` capability nodes.
        with_header: Prepend the bold ``Privilege blast radius`` header.
    """
    if not steps:
        return []

    out: list[RenderableType] = []
    if with_header:
        out.append(Text("Privilege blast radius", style="bold"))
    for step in steps:
        sev = step.severity.value.lower()
        sev_style = _SEVERITY_STYLE.get(sev, "dim")
        headline = Text.assemble(
            Text("● ", style=sev_style),
            Text(mark_sensitive(step.source_label.split("@")[0], "user"), style="bold"),
            Text("  "),
            Text(_fanout_capability_phrase(step), style="dim"),
            Text("  "),
            Text(step.tier_label, style=COLOR_STEEL),
        )
        out.append(headline)

        detail = Text("    ", style="dim")
        detail.append(f"via {step.edge_relation}", style="dim")
        if step.sample_target_labels:
            shown = step.sample_target_labels[:3]
            sample = ", ".join(
                mark_sensitive(label.split("@")[0], "hostname") for label in shown
            )
            detail.append("  ·  e.g. ", style="dim")
            detail.append(sample, style="dim")
            if step.count > len(shown):
                detail.append(" …", style="dim")
        out.append(detail)
    return out


def _fanout_block(model: ScanRecapModel) -> list[RenderableType]:
    """Render the recap "Privilege blast radius" section, or [] when empty.

    Each collapsed capability node concentrates what would otherwise be N
    near-identical rows into a single high-value finding — the blast-radius
    count is itself the deliverable.
    """
    return render_fanout_capability_lines(model.fanout)


def _try_next_block(model: ScanRecapModel) -> list[RenderableType]:
    """Render the ``Try next`` verb list, or [] when there is nothing to add."""
    if not model.try_next:
        return []
    out: list[RenderableType] = [Text("Try next", style="bold")]
    verb_width = max(len(verb) for verb, _ in model.try_next)
    for verb, desc in model.try_next:
        out.append(
            Text.assemble(
                Text("  " + verb.ljust(verb_width), style=f"bold {ADSCAN_PRIMARY_BRIGHT}"),
                Text("    "),
                Text(desc, style="dim"),
            )
        )
    return out


def _report_line(model: ScanRecapModel) -> Text | None:
    """Render the report-path line. The path is a literal Text (MarkupError-safe)."""
    if not model.report_path:
        return None
    return Text.assemble(
        Text("Report   ", style="bold"),
        Text(model.report_path, style=ADSCAN_PRIMARY_BRIGHT),
    )


def build_recap_body(model: ScanRecapModel) -> RenderableType:
    """Return the recap body as a Rich ``Group`` (no CTA — that is tier-gated).

    Layout: headline · hairline · timing/verdict · optional path block · optional
    findings strip + top-list · optional ``Try next`` · optional report line. Each
    section is skipped cleanly when its data is absent, so all three outcome
    states render from the same function.
    """
    parts: list[RenderableType] = [_headline(model), recap_hairline()]

    timing = _timing_line(model)
    if timing is not None:
        parts.append(timing)

    path_block = _path_block(model)
    if path_block is not None:
        parts.append(Text(""))
        parts.append(path_block)

    findings = _findings_block(model)
    if findings:
        parts.append(Text(""))
        parts.extend(findings)

    fanout = _fanout_block(model)
    if fanout:
        parts.append(Text(""))
        parts.extend(fanout)

    try_next = _try_next_block(model)
    if try_next:
        parts.append(Text(""))
        parts.extend(try_next)

    report = _report_line(model)
    if report is not None:
        parts.append(Text(""))
        parts.append(report)

    return Group(*parts)


__all__ = [
    "Outcome",
    "RecapPath",
    "ScanRecapModel",
    "build_recap_body",
    "recap_hairline",
    "render_fanout_capability_lines",
]
