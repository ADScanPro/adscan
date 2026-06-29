"""CLI surface — ``paths_inspect`` command rendering.

Renders the post-exploitation menu for one selected attack path.
When invoked with ``workspace_path``, the menu uses the data-driven
ranker (Phase 7): empirical likelihood + workspace-history contextual
adjustments, with a transparent breakdown column. When invoked
without (legacy callers, tests), it falls back to the static-only
ranking and renders the original compact table.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from adscan_core import telemetry
from adscan_core.rich_output import (
    print_error,
    print_info,
    print_warning,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.path_renderer import (
    TechnicalRenderer,
    _path_compromise_class,
)
from adscan_internal.services.post_exploitation.data_driven_ranking import (
    RankedTechnique,
)
from adscan_internal.services.post_exploitation.path_inspection import (
    applicable_techniques,
    applicable_techniques_ranked,
    project_foothold,
)


def _format_static_row(
    technique,
    score: float,
) -> tuple[Text, Text, Text, Text, Text]:
    name = Text(technique.name_technical, style="bold")
    likelihood = Text(
        f"{technique.likelihood_of_dom_compromise:.2f}", style="cyan"
    )
    risk_style = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
    }.get(technique.detection_risk.value, "white")
    risk = Text(technique.detection_risk.value.upper(), style=risk_style)
    duration = Text(f"{technique.typical_duration_seconds}s", style="dim")
    score_text = Text(f"{score:.2f}", style="bold magenta")
    return name, likelihood, risk, duration, score_text


def _render_path_summary(
    console: Console,
    path: dict[str, Any],
    *,
    index: int,
) -> None:
    renderer = TechnicalRenderer()
    title = renderer.render_path_title(path, index)

    projection = project_foothold(path)
    cls_label = renderer.render_class_label(projection.compromise_class)
    reach_label = renderer.render_reach_label(projection.compromise_class)

    source = str(path.get("source") or "")
    target = projection.target_label or "?"
    masked_source = mark_sensitive(source, "user")
    masked_target = mark_sensitive(target, "host")

    relations = path.get("relations") or []
    chain = " -> ".join(str(r) for r in relations) if relations else "(no edges)"

    body = Text()
    body.append("Class: ", style="dim")
    body.append(f"{cls_label}\n")
    body.append("Reach: ", style="dim")
    body.append(f"{reach_label}\n")
    body.append("Source: ", style="dim")
    body.append(f"{masked_source}\n")
    body.append("Target: ", style="dim")
    body.append(f"{masked_target}\n")
    body.append("Edges: ", style="dim")
    body.append(chain + "\n")
    body.append("Foothold: ", style="dim")
    proto = projection.protocol.value if projection.protocol else "unknown"
    body.append(f"protocol={proto}, privilege={projection.privilege.value}")

    console.print(Panel(body, title=title, border_style="cyan"))


def _render_static_table(
    console: Console,
    ranked: list[tuple],
) -> None:
    table = Table(
        title="Applicable post-exploitation techniques (ranked)",
        title_style="bold",
        show_lines=False,
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Technique")
    table.add_column("Likelihood", justify="right")
    table.add_column("Detection", justify="center")
    table.add_column("Duration", justify="right")
    table.add_column("Score", justify="right")

    for i, (technique, score) in enumerate(ranked, start=1):
        name, likelihood, risk, duration, score_text = _format_static_row(
            technique, score
        )
        table.add_row(str(i), name, likelihood, risk, duration, score_text)

    console.print(table)


def _format_base_cell(rt: RankedTechnique) -> Text:
    if rt.base_source == "empirical":
        n = rt.base_metadata.get("n")
        ci_low = rt.base_metadata.get("ci_low")
        ci_high = rt.base_metadata.get("ci_high")
        text = Text(f"{rt.base_score:.2f}", style="cyan")
        bits: list[str] = ["empirical"]
        if isinstance(n, int):
            bits.append(f"N={n}")
        if isinstance(ci_low, (int, float)) and isinstance(ci_high, (int, float)):
            bits.append(f"CI {ci_low:.2f}-{ci_high:.2f}")
        text.append(f" ({', '.join(bits)})", style="dim")
        return text
    return Text(f"{rt.base_score:.2f} (static)", style="cyan")


def _format_adjustments_cell(rt: RankedTechnique) -> Text:
    if not rt.contextual_adjustments:
        return Text("—", style="dim")
    parts = Text()
    first = True
    for key, delta in rt.contextual_adjustments.items():
        if not first:
            parts.append(", ", style="dim")
        first = False
        style = "green" if delta > 0 else "red"
        sign = "+" if delta > 0 else ""
        parts.append(f"{sign}{delta:.2f}", style=style)
        parts.append(f" {key}", style="dim")
    return parts


def _render_data_driven_table(
    console: Console,
    ranked: list[RankedTechnique],
) -> None:
    has_any_breakdown = any(rt.contextual_adjustments for rt in ranked) or any(
        rt.base_source == "empirical" for rt in ranked
    )
    if not has_any_breakdown:
        # Nothing extra to show — render the original compact table
        # so we don't add visual noise without information.
        _render_static_table(
            console,
            [(rt.technique, rt.final_score) for rt in ranked],
        )
        return

    table = Table(
        title="Applicable post-exploitation techniques (data-driven, ranked)",
        title_style="bold",
        show_lines=False,
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Technique")
    table.add_column("Detection", justify="center")
    table.add_column("Duration", justify="right")
    table.add_column("Base score (source)")
    table.add_column("Adjustments")
    table.add_column("Final", justify="right")

    for i, rt in enumerate(ranked, start=1):
        risk_style = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
        }.get(rt.technique.detection_risk.value, "white")
        risk = Text(rt.technique.detection_risk.value.upper(), style=risk_style)
        duration = Text(f"{rt.technique.typical_duration_seconds}s", style="dim")
        table.add_row(
            str(i),
            Text(rt.technique.name_technical, style="bold"),
            risk,
            duration,
            _format_base_cell(rt),
            _format_adjustments_cell(rt),
            Text(f"{rt.final_score:.2f}", style="bold magenta"),
        )

    console.print(table)


def _render_technique_detail_hint(
    console: Console,
    techniques: list,
) -> None:
    for i, technique in enumerate(techniques, start=1):
        mitre = ", ".join(technique.mitre_attack_ids) or "—"
        text = Text()
        text.append(f"  [{i}] ", style="dim")
        text.append(technique.id, style="bold yellow")
        text.append(f"  ({mitre})\n", style="dim")
        text.append(f"      {technique.description_technical}\n", style="white")
        console.print(text)


def render_paths_inspect(
    *,
    console: Console,
    domain: str,
    paths: list[dict[str, Any]],
    index: int,
    workspace_path: Path | None = None,
) -> int:
    """Render the inspection panel for ``paths[index - 1]``.

    When ``workspace_path`` is provided, the data-driven ranker is
    used and the table includes base-source / adjustments / final
    columns. Without it, the original static table is rendered for
    full back-compat with legacy callers.
    """
    if not paths:
        masked = mark_sensitive(domain, "domain")
        print_warning(
            f"No attack paths available for {masked}. "
            "Run 'attack_paths <domain>' first to compute them."
        )
        return 2

    if index < 1 or index > len(paths):
        print_error(
            f"Index {index} out of range. "
            f"Valid range: 1..{len(paths)} ('attack_paths {domain}' to list)."
        )
        return 2

    path = paths[index - 1]
    _render_path_summary(console, path, index=index)

    cls = _path_compromise_class(path)

    if workspace_path is not None:
        ranked_dd = applicable_techniques_ranked(
            path, workspace_path=workspace_path, domain=domain
        )
        if not ranked_dd:
            _render_empty_state(console, path, domain=domain, cls=cls)
            return 0
        _render_data_driven_table(console, ranked_dd)
        _render_technique_detail_hint(console, [rt.technique for rt in ranked_dd])
        num_offered = len(ranked_dd)
    else:
        ranked = applicable_techniques(path)
        if not ranked:
            _render_empty_state(console, path, domain=domain, cls=cls)
            return 0
        _render_static_table(console, ranked)
        _render_technique_detail_hint(console, [t for t, _s in ranked])
        num_offered = len(ranked)

    print_info(
        "Use 'paths_execute <domain> <path-index> <technique-index>' to run a "
        "selected technique. Adjustments come from this workspace's prior "
        "executions; an empty Adjustments column means no relevant history yet."
    )
    try:
        telemetry.capture_post_ex_menu_viewed(
            path_class=cls.value,
            num_techniques_offered=num_offered,
        )
    except Exception:  # noqa: BLE001 — telemetry must never break UX
        pass
    return 0


def _render_empty_state(
    console: Console,
    path: dict[str, Any],
    *,
    domain: str,
    cls,
) -> None:
    projection = project_foothold(path)
    proto = projection.protocol.value if projection.protocol else "unknown"
    print_info(
        "No catalog techniques match this foothold "
        f"(protocol={proto}, privilege={projection.privilege.value}). "
        "This usually means the path's last AUTH edge is informational "
        "(e.g. HasSession) rather than an actionable login surface."
    )
    try:
        telemetry.capture_post_ex_menu_viewed(
            path_class=cls.value,
            num_techniques_offered=0,
        )
    except Exception:  # noqa: BLE001 — telemetry must never break UX
        pass


__all__ = ["render_paths_inspect"]
