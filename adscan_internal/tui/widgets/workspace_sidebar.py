"""Workspace sidebar: tree view of domains and workspaces."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from textual.app import ComposeResult
from textual.widgets import Static, Tree
from textual.widget import Widget

if TYPE_CHECKING:
    pass


class WorkspaceSidebar(Widget):
    """Left sidebar showing workspace tree and domain details."""

    def __init__(self, shell: Any, **kwargs) -> None:
        super().__init__(**kwargs)
        self._shell = shell

    def compose(self) -> ComposeResult:
        yield Static("  WORKSPACES", id="sidebar-title")
        yield Tree("Workspaces", id="workspace-tree")

    def on_mount(self) -> None:
        self.refresh_tree()

    def refresh_tree(self) -> None:
        """Rebuild the workspace tree from shell state."""
        tree = self.query_one("#workspace-tree", Tree)
        tree.clear()

        shell = self._shell
        workspaces: list[str] = []
        try:
            workspaces = list(getattr(shell, "domains_data", {}).keys())
        except Exception:  # noqa: BLE001
            pass

        if not workspaces:
            tree.root.add_leaf("[dim]No workspaces yet[/dim]")
            tree.root.expand()
            return

        for domain in workspaces:
            domain_data: dict = {}
            try:
                domain_data = shell.domains_data.get(domain) or {}
            except Exception:  # noqa: BLE001
                pass

            is_current = getattr(shell, "current_workspace", None) == domain
            label = f"[bold cyan]{domain}[/bold cyan]" if is_current else domain
            node = tree.root.add(label)

            users = domain_data.get("users_count") or domain_data.get("total_users")
            if users:
                node.add_leaf(f"[dim]Users:[/dim]  {users}")

            shares = domain_data.get("shares_count") or domain_data.get("total_shares")
            if shares:
                node.add_leaf(f"[dim]Shares:[/dim] {shares}")

            paths = domain_data.get("attack_paths_count")
            if paths:
                node.add_leaf(f"[dim]Paths:[/dim]  [yellow]{paths}[/yellow]")

            node.expand()

        tree.root.expand()
