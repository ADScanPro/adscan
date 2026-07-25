"""CLI surface — ``paths_execute`` command rendering.

Sister to ``post_ex_inspect``: this module performs the *mutate* half
of the post-exploitation flow. It selects the path + technique by
1-based indices (same numbering the inspect view exposes), calls the
:class:`PostExOrchestrator`, and renders a clear before/after summary.

This module knows nothing about specific techniques — it relies on the
catalog and the orchestrator. New techniques therefore work end-to-end
the moment they are registered in the catalog and provide an executor
factory.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from adscan_core import telemetry
from adscan_core.rich_output import (
    print_error,
    print_info,
    print_success,
    print_warning,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.path_renderer import TechnicalRenderer
from adscan_internal.services.post_exploitation.orchestrator import (
    PostExOrchestrator,
)
from adscan_internal.services.post_exploitation.path_inspection import (
    applicable_techniques,
    project_foothold,
)
from adscan_internal.services.post_exploitation.path_promotion import (
    PATH_STATE_DOMAIN_COMPROMISED,
    PATH_STATE_FAILED,
    PATH_STATE_FOOTHOLD_OBTAINED,
)
from adscan_core.rich_output import print_exception


def _default_executor_factory(technique_id: str):
    """Return a fresh executor instance for ``technique_id``.

    Lazy-imports the technique modules so importing this CLI module does
    not pay the cost of loading every executor.
    """
    from adscan_internal.services.post_exploitation.techniques.winrm.filesystem_creds_search import (  # noqa: E501
        WinRMFilesystemCredsSearch,
    )

    factories = {
        "winrm_filesystem_creds_search": WinRMFilesystemCredsSearch,
    }
    factory = factories.get(technique_id)
    if factory is None:
        raise NotImplementedError(
            f"No executor factory wired for technique {technique_id!r}. "
            "Register it in adscan_internal/cli/post_ex_execute.py."
        )
    return factory()


def _render_before_panel(
    console: Console,
    *,
    path: dict[str, Any],
    path_index: int,
    technique_id: str,
) -> None:
    renderer = TechnicalRenderer()
    title = renderer.render_path_title(path, path_index)
    projection = project_foothold(path)

    body = Text()
    body.append("Before: ", style="dim")
    body.append(f"path_state={path.get('path_state') or 'theoretical'}\n")
    body.append("Target: ", style="dim")
    body.append(f"{mark_sensitive(projection.target_label or '?', 'host')}\n")
    body.append("Technique: ", style="dim")
    body.append(f"{technique_id}\n", style="bold yellow")
    proto = projection.protocol.value if projection.protocol else "unknown"
    body.append("Foothold: ", style="dim")
    body.append(f"protocol={proto}, privilege={projection.privilege.value}")
    console.print(Panel(body, title=f"Executing — {title}", border_style="yellow"))


def _render_after_panel(
    console: Console,
    *,
    outcome,
) -> None:
    state = outcome.record.path_state
    style = {
        PATH_STATE_DOMAIN_COMPROMISED: "bold red",
        PATH_STATE_FOOTHOLD_OBTAINED: "bold green",
        PATH_STATE_FAILED: "bold magenta",
    }.get(state, "white")
    body = Text()
    body.append("Outcome: ", style="dim")
    body.append(f"{outcome.result.outcome.value}\n", style="bold")
    body.append("Path state: ", style="dim")
    body.append(f"{state}\n", style=style)
    body.append("Derived edges inserted: ", style="dim")
    body.append(f"{outcome.derived_inserted}\n")
    if outcome.record.evidence_path:
        body.append("Evidence: ", style="dim")
        body.append(f"{outcome.record.evidence_path}\n")
    if outcome.record.error_message:
        body.append("Error: ", style="dim")
        body.append(f"{outcome.record.error_message}\n", style="red")
    console.print(Panel(body, title="After", border_style=style.split()[-1]))


async def render_paths_execute(
    *,
    shell: object,
    console: Console,
    domain: str,
    paths: list[dict[str, Any]],
    path_index: int,
    technique_index: int,
) -> int:
    """Execute the ``technique_index``-th technique against ``paths[path_index-1]``.

    Returns a process-style exit code: 0 on success, 2 on usage error.
    Telemetry events are emitted on the success path so adoption can be
    measured separately from the read-only inspect surface.
    """
    if not paths:
        masked = mark_sensitive(domain, "domain")
        print_warning(
            f"No attack paths available for {masked}. "
            "Run 'attack_paths <domain>' first to compute them."
        )
        return 2

    if path_index < 1 or path_index > len(paths):
        print_error(
            f"path-index {path_index} out of range. "
            f"Valid range: 1..{len(paths)}."
        )
        return 2

    path = paths[path_index - 1]
    ranked = applicable_techniques(path)
    if not ranked:
        print_warning(
            "This path's foothold has no applicable catalog techniques. "
            "Use 'paths_inspect' to see the empty-state explanation."
        )
        return 2

    if technique_index < 1 or technique_index > len(ranked):
        print_error(
            f"technique-index {technique_index} out of range. "
            f"Valid range: 1..{len(ranked)} (see 'paths_inspect {domain} {path_index}')."
        )
        return 2

    technique, _score = ranked[technique_index - 1]
    _render_before_panel(
        console, path=path, path_index=path_index, technique_id=technique.id
    )

    orchestrator = PostExOrchestrator(executor_factory=_default_executor_factory)
    try:
        outcome = await orchestrator.run_path(
            shell=shell,
            domain=domain,
            path=path,
            technique_id=technique.id,
        )
    except Exception as exc:  # noqa: BLE001 — telemetry sink
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"paths_execute aborted: {exc}")
        return 1

    _render_after_panel(console, outcome=outcome)

    if outcome.record.path_state == PATH_STATE_DOMAIN_COMPROMISED:
        print_success(
            "Path promoted to DOMAIN_COMPROMISED. Re-run 'attack_paths' to "
            "see how the new derived edge extends the graph."
        )
    elif outcome.record.path_state == PATH_STATE_FOOTHOLD_OBTAINED:
        print_info(
            "Foothold obtained. The technique did not yield a Tier-0-promoting "
            "edge; chain a follow-up technique to reach domain compromise."
        )

    try:
        telemetry.capture_post_ex_execute_invoked(
            technique_id=technique.id,
            outcome=outcome.result.outcome.value,
            duration_seconds=float(outcome.result.duration_seconds),
        )
    except Exception:  # noqa: BLE001 — telemetry must never break UX
        pass
    return 0


__all__ = ["render_paths_execute"]
