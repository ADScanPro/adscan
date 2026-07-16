"""Premium rich-rendered prompt for the workspace resume decision.

This module renders the four-action panel (Resume / Refresh / Replay / Inspect)
when the operator re-enters a domain workspace that already holds Phase 1
results, and persists the decision both in ``shell.domains_data`` and on the
structured event sink consumed by the ADscan web service.

Design tenets:
    * Pentester reads it once and knows the cost of every action up front.
    * Workspace state visible at a glance — last collection age, edge count,
      whether attack paths exist, credential count.
    * Default action highlighted (RESUME) so an accidental ``Enter`` is the
      cheapest, never destructive.
    * Auto-mode (``shell.auto`` or CI) bypasses the panel deterministically:
      CI defaults to RESUME (cached), explicit refresh is via
      ``ADSCAN_WORKSPACE_ACTION=refresh``.
"""

from __future__ import annotations

import os
from typing import Any

from adscan_core.rich_output import (
    get_console,
    mark_sensitive,
    print_info,
    print_info_debug,
)
from adscan_internal.cli.ci_events import emit_event
from adscan_internal.services.workspace_resume import (
    WorkspaceAction,
    WorkspaceSnapshot,
    inspect_workspace,
)


_ACTION_LABELS: dict[WorkspaceAction, str] = {
    WorkspaceAction.RESUME: "Resume   · keep the collected graph, run the pending phases",
    WorkspaceAction.REFRESH: "Refresh  · re-collect from AD, then re-run the full analysis",
    WorkspaceAction.REPLAY: "Replay   · keep the graph, re-run all analysis (new ADscan rules)",
    WorkspaceAction.INSPECT: "Inspect  · open the workspace, run nothing",
}

_ENV_OVERRIDE_VAR: str = "ADSCAN_WORKSPACE_ACTION"


def resolve_workspace_action(
    shell: Any,
    domain: str,
    *,
    snapshot: WorkspaceSnapshot | None = None,
) -> tuple[WorkspaceAction, WorkspaceSnapshot]:
    """Render the panel (interactive) or resolve the action (auto/CI).

    Returns the chosen :class:`WorkspaceAction` plus the inspected snapshot.
    The snapshot is returned so callers can decide which steps to skip
    without re-reading the filesystem.

    The structured event ``workspace_action`` is emitted in every code path so
    the ADscan web service can render the same decision the operator made.
    """
    if snapshot is None:
        snapshot = inspect_workspace(shell, domain)

    print_info_debug(
        f"[workspace] inspect domain={domain} has_attack_graph={snapshot.has_attack_graph} "
        f"nodes={snapshot.node_count} edges={snapshot.edge_count} "
        f"domain_auth={snapshot.domain_auth!r} phase1_complete={snapshot.phase1_complete}"
    )

    if not snapshot.has_attack_graph and not snapshot.phase1_complete:
        # Nothing to resume — caller should run the full flow as a fresh scan.
        action = WorkspaceAction.REFRESH
        _emit_action_event(action, snapshot, source="fresh_workspace")
        return action, snapshot

    if snapshot.has_attack_graph and snapshot.domain_auth == "unauth":
        # Graph contains only synthetic nodes from the unauthenticated entry-vector
        # phase (LDAPAnonymousBind, ASREPRoasting). The four panel options are all
        # misleading: Resume keeps the cached junk, Replay re-runs analysis on it,
        # Refresh is the only sensible action. Skip the prompt and default to it.
        print_info_debug(
            f"[workspace] entry-vectors-only graph for {domain}; "
            f"skipping panel and defaulting to REFRESH"
        )
        action = WorkspaceAction.REFRESH
        _emit_action_event(action, snapshot, source="entry_vectors_only")
        return action, snapshot

    action = _resolve_auto_action(shell, snapshot)
    if action is not None:
        _emit_action_event(action, snapshot, source="auto")
        print_info(f"Workspace action: {_ACTION_LABELS[action]}")
        return action, snapshot

    _render_panel(snapshot)
    action = _prompt_action(shell, snapshot)
    _emit_action_event(action, snapshot, source="interactive")
    return action, snapshot


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _resolve_auto_action(shell: Any, snapshot: WorkspaceSnapshot) -> WorkspaceAction | None:
    """Return a deterministic action when auto/CI mode applies, else ``None``.

    Precedence:
        1. ``ADSCAN_WORKSPACE_ACTION`` env var (explicit operator override).
        2. ``shell.auto`` flag — defaults to RESUME (cached, fastest).
    """
    override = (os.environ.get(_ENV_OVERRIDE_VAR) or "").strip().lower()
    if override:
        try:
            return WorkspaceAction(override)
        except ValueError:
            print_info_debug(
                f"[workspace] ignored invalid {_ENV_OVERRIDE_VAR}={override!r}"
            )
    if getattr(shell, "auto", False):
        return WorkspaceAction.RESUME
    return None


def _render_panel(snapshot: WorkspaceSnapshot) -> None:
    """Render the rich workspace-state panel above the prompt."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    state = Table.grid(padding=(0, 2))
    state.add_column(style="bold")
    state.add_column()

    if snapshot.has_attack_graph and snapshot.domain_auth in ("auth", "pwned"):
        graph_summary = (
            f"[green]✓[/] {snapshot.node_count} nodes · "
            f"{snapshot.edge_count} edges · "
            f"[dim]{snapshot.last_collection_age_human}[/]"
        )
    elif snapshot.has_attack_graph:
        graph_summary = (
            f"[yellow]⚠[/] Entry vectors only · "
            f"{snapshot.edge_count} edges · "
            f"[dim]{snapshot.last_collection_age_human}[/]"
        )
    else:
        graph_summary = "[dim]not yet collected[/]"
    state.add_row("Domain Collection", graph_summary)

    if snapshot.has_attack_paths:
        paths_summary = "[green]✓[/] materialised"
    else:
        paths_summary = "[dim]not yet computed[/]"
    state.add_row("Attack Paths", paths_summary)

    if snapshot.credential_count > 0:
        creds_summary = f"[green]✓[/] {snapshot.credential_count} captured"
    else:
        creds_summary = "[dim]none yet[/]"
    state.add_row("Credentials", creds_summary)

    actions = Table.grid(padding=(0, 1))
    actions.add_column(style="bold cyan")
    actions.add_column()
    actions.add_row("›", _ACTION_LABELS[WorkspaceAction.RESUME] + "   [dim](default)[/]")
    actions.add_row(" ", _ACTION_LABELS[WorkspaceAction.REFRESH])
    actions.add_row(" ", _ACTION_LABELS[WorkspaceAction.REPLAY])
    actions.add_row(" ", _ACTION_LABELS[WorkspaceAction.INSPECT])

    body = Table.grid(padding=(1, 0))
    body.add_column()
    body.add_row(state)
    body.add_row(Text("How do you want to proceed?", style="bold"))
    body.add_row(actions)

    title = Text.assemble(
        ("🔄  ", "bold cyan"),
        ("Workspace state — ", "bold"),
        (mark_sensitive(snapshot.domain, "domain"), "bold magenta"),
    )
    get_console().print(
        Panel(
            body,
            title=title,
            title_align="left",
            border_style="cyan",
            padding=(1, 2),
        )
    )


def _prompt_action(shell: Any, snapshot: WorkspaceSnapshot) -> WorkspaceAction:
    """Ask the operator for the action; return the parsed choice."""
    _ORDERED_ACTIONS = [
        WorkspaceAction.RESUME,
        WorkspaceAction.REFRESH,
        WorkspaceAction.REPLAY,
        WorkspaceAction.INSPECT,
    ]
    selector = getattr(shell, "_questionary_select", None)
    options = [_ACTION_LABELS[a] for a in _ORDERED_ACTIONS]

    if callable(selector):
        try:
            result = selector(
                title=f"Workspace action for {mark_sensitive(snapshot.domain, 'domain')}",
                options=options,
            )
            # _questionary_select returns an int index, not the label string.
            if isinstance(result, int) and 0 <= result < len(_ORDERED_ACTIONS):
                return _ORDERED_ACTIONS[result]
            if isinstance(result, str):
                for action, label in _ACTION_LABELS.items():
                    if result == label:
                        return action
        except Exception:  # noqa: BLE001
            pass

    # Fallback: questionary directly (shell may not expose the helper yet).
    from adscan_core.prompting import questionary_select_value

    selected = questionary_select_value(
        title=f"Workspace action for {snapshot.domain}",
        options=options,
    )

    if selected is None:
        # Non-interactive terminal or aborted prompt — safest default.
        return WorkspaceAction.RESUME

    for action, label in _ACTION_LABELS.items():
        if selected == label:
            return action
    return WorkspaceAction.RESUME


def _emit_action_event(
    action: WorkspaceAction,
    snapshot: WorkspaceSnapshot,
    *,
    source: str,
) -> None:
    """Mirror the chosen action to the structured event sink (web dashboard)."""
    emit_event(
        "workspace_action",
        action=action.value,
        source=source,
        domain=snapshot.domain,
        has_attack_graph=snapshot.has_attack_graph,
        node_count=snapshot.node_count,
        edge_count=snapshot.edge_count,
        last_collection_at=snapshot.last_collection_at,
        last_collection_age_human=snapshot.last_collection_age_human,
        has_attack_paths=snapshot.has_attack_paths,
        credential_count=snapshot.credential_count,
    )
