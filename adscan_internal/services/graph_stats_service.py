"""Attack-graph pre-flight: surface scale + the engine-routing decision.

Before attack-path discovery walks a large, dense directory graph, an operator
has no signal of how big the graph is or that ADscan's mega-hub predictor has
already decided — silently, inside ``_choose_attack_path_engine`` — to route the
graph to the bounded/sampled fallback engine. This module makes that decision
VISIBLE without changing it.

It is a pentester's pre-flight, not a new analysis and not a client-report
section: every figure it shows already exists (node/edge counts on the loaded
graph, the control mega-hub count and explosion verdict from the predictor, and
the exposure anchor from the choke-point SSOT). The builder is pure and
read-only; three thin render call-sites consume it (the ``graph_stats`` REPL
verb, the inline pre-flight before a normal ``attack_paths`` compute, and the
collapsed ``adscan ci`` beacon line).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from adscan_internal.services.attack_path_explosion_predictor import (
    count_control_mega_hubs,
    predicts_explosion,
    top_control_hubs,
)

# How many top control hubs the panel breaks out. The predictor's mega-hub COUNT
# (the routing signal) is separate — this is only the human-facing "which nodes
# drive the density" list.
_TOP_HUBS_SHOWN = 5


@dataclass(frozen=True)
class GraphStats:
    """Pre-flight facts about an attack graph, all read off the loaded graph.

    Attributes:
        nodes: Node count in the graph.
        edges: Edge count in the graph.
        edge_node_ratio: ``edges / nodes`` (0.0 when there are no nodes).
        mega_hub_count: Control mega-hubs the predictor counts (the routing signal).
        top_hubs: The top control fan-outs as ``(source_label, relation, count)``,
            highest first — the human breakdown of what drives the density.
        predicts_sampled: The predictor's verdict — ``True`` when discovery WILL
            route to the sampled fallback engine (a prediction, never a coverage
            claim).
        exposure_source_count: Enabled principals with SOME validated route to a
            Tier-0 target, or ``None`` when it cannot be resolved.
    """

    nodes: int
    edges: int
    edge_node_ratio: float
    mega_hub_count: int
    top_hubs: list[tuple[str, str, int]] = field(default_factory=list)
    predicts_sampled: bool = False
    exposure_source_count: int | None = None


def _graph_size(graph: dict[str, Any]) -> tuple[int, int]:
    """Return ``(node_count, edge_count)`` for a graph whose collections may be
    either a dict node-map or a list."""
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    node_count = len(nodes) if isinstance(nodes, (list, dict)) else 0
    edge_count = len(edges) if isinstance(edges, (list, dict)) else 0
    return node_count, edge_count


def build_graph_stats(
    shell: object,
    domain: str,
    *,
    graph: dict[str, Any] | None = None,
) -> GraphStats:
    """Assemble the pre-flight facts for ``domain``'s attack graph.

    Pure and read-only: it loads the graph ONCE (or reuses ``graph`` when the
    caller already holds it — never double-loads), runs the explosion predictor,
    the top-hub extractor and the exposure-source count, and returns the facts.
    It performs NO path compute, no console output and no writes.

    Args:
        shell: The active shell (only used to load the graph when ``graph`` is not
            supplied).
        domain: The domain whose attack graph to summarise.
        graph: An already-loaded attack graph to reuse. When ``None`` the graph is
            loaded from the workspace. Reusing it is the caller's way to avoid a
            second ``load_attack_graph`` when it already has the graph in hand.

    Returns:
        A :class:`GraphStats` with the scale, top hubs, sampled-mode prediction and
        exposure anchor. On an unreadable / missing graph, an all-zero stats value.
    """
    from adscan_internal.services.attack_graph_service import (
        _resolve_exposure_source_count_for_graph,
        load_attack_graph,
    )

    if not isinstance(graph, dict):
        try:
            graph = load_attack_graph(shell, domain)
        except Exception:  # noqa: BLE001 — the pre-flight must never break a run.
            graph = None
    if not isinstance(graph, dict):
        return GraphStats(
            nodes=0, edges=0, edge_node_ratio=0.0, mega_hub_count=0
        )

    nodes, edges = _graph_size(graph)
    ratio = (edges / nodes) if nodes else 0.0
    return GraphStats(
        nodes=nodes,
        edges=edges,
        edge_node_ratio=ratio,
        mega_hub_count=count_control_mega_hubs(graph),
        top_hubs=top_control_hubs(graph, top_n=_TOP_HUBS_SHOWN),
        predicts_sampled=predicts_explosion(graph),
        exposure_source_count=_resolve_exposure_source_count_for_graph(graph),
    )


def _humanize_relation(relation: str) -> str:
    """Return a display form of a lower-cased edge relation.

    The predictor counts relations lower-cased; the panel shows them in the
    canonical mixed-case BloodHound form when known, else the raw token.
    """
    known = {
        "genericall": "GenericAll",
        "genericwrite": "GenericWrite",
        "writedacl": "WriteDacl",
        "writeowner": "WriteOwner",
        "owns": "Owns",
        "allextendedrights": "AllExtendedRights",
        "addmember": "AddMember",
        "forcechangepassword": "ForceChangePassword",
        "addkeycredentiallink": "AddKeyCredentialLink",
        "writeproperty": "WriteProperty",
    }
    return known.get(relation.strip().lower(), relation.strip())


def render_graph_stats_panel(stats: GraphStats, domain: str) -> None:
    """Render the pre-flight panel for ``stats`` via ``print_panel``.

    A static one-shot panel (no ``LiveSession``). Uses the shared ``print_panel``
    so the ``_TeeConsole`` auto-mirrors it into the session recording — NEVER
    constructs a ``Console()``. The verdict line is a PREDICTION ("will run in
    sampled mode"), never a coverage claim; "sampled mode" mirrors the post-run
    ``COVERAGE_MODE_SAMPLED`` vocabulary so the pre-flight and the coverage
    declaration use one word for one thing.

    Args:
        stats: The pre-flight facts.
        domain: The domain, shown in the panel title.
    """
    from rich.console import Group
    from rich.text import Text

    from adscan_internal.rich_output import mark_sensitive, print_panel

    lines: list[Text] = []
    ratio = f"{stats.edge_node_ratio:.1f}"
    lines.append(
        Text.from_markup(
            f"[bold]{stats.nodes:,}[/bold] nodes   "
            f"[bold]{stats.edges:,}[/bold] edges   "
            f"({ratio} edges/node)"
        )
    )

    if stats.top_hubs:
        lines.append(Text(""))
        lines.append(Text("Control hubs with heavy fan-out:", style="bold"))
        label_width = max(
            (len(str(label)) for label, _rel, _count in stats.top_hubs), default=0
        )
        label_width = min(label_width, 40)
        for label, relation, count in stats.top_hubs:
            shown_label = str(label)
            if len(shown_label) > label_width:
                shown_label = shown_label[: label_width - 1] + "…"
            lines.append(
                Text(
                    f"  {shown_label.ljust(label_width)}  "
                    f"{count:>7,} {_humanize_relation(relation)}"
                )
            )

    lines.append(Text(""))
    if stats.predicts_sampled:
        hub_word = "hub" if stats.mega_hub_count == 1 else "hubs"
        verdict = Text.from_markup(
            f"[bold]{stats.mega_hub_count}[/bold] control mega-{hub_word} detected. "
            "Path discovery will run in sampled mode: every reachable Tier-0 "
            "target is covered, but the number of routes shown per target is "
            "capped."
        )
    else:
        verdict = Text(
            "Within the full-discovery budget. All routes will be enumerated."
        )
    lines.append(verdict)

    if stats.exposure_source_count is not None and stats.exposure_source_count > 0:
        principal_word = (
            "principal" if stats.exposure_source_count == 1 else "principals"
        )
        holds_word = "holds" if stats.exposure_source_count == 1 else "hold"
        lines.append(
            Text.from_markup(
                f"[bold]{stats.exposure_source_count}[/bold] {principal_word} "
                f"{holds_word} a validated path to a Tier-0 target."
            )
        )

    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        Group(*lines),
        title=f"Attack graph — {marked_domain}",
        title_align="left",
    )
