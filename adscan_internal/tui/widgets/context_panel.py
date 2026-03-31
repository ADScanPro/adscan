"""Context panel: attack paths and discovered credentials."""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.widgets import Log, Static
from textual.widget import Widget


class ContextPanel(Widget):
    """Right panel showing discovered attack paths and credentials."""

    def __init__(self, shell: Any, **kwargs) -> None:
        super().__init__(**kwargs)
        self._shell = shell

    def compose(self) -> ComposeResult:
        yield _AttackPathsSection(shell=self._shell, id="attack-paths-section")
        yield _CredentialsSection(shell=self._shell, id="credentials-section")

    def refresh_context(self) -> None:
        """Refresh both attack paths and credentials panels."""
        self.query_one(_AttackPathsSection).refresh_content()
        self.query_one(_CredentialsSection).refresh_content()


class _AttackPathsSection(Widget):
    """Attack paths sub-panel."""

    def __init__(self, shell: Any, **kwargs) -> None:
        super().__init__(**kwargs)
        self._shell = shell

    def compose(self) -> ComposeResult:
        yield Static("  ATTACK PATHS", id="attack-paths-title")
        yield Log(id="attack-paths-list", highlight=True)

    def on_mount(self) -> None:
        self.refresh_content()

    def refresh_content(self) -> None:
        """Reload attack paths from shell state."""
        log = self.query_one("#attack-paths-list", Log)
        log.clear()

        paths: list = []
        try:
            bh_svc = getattr(self._shell, "_bloodhound_service", None)
            if bh_svc and hasattr(bh_svc, "get_cached_attack_paths"):
                paths = bh_svc.get_cached_attack_paths() or []
        except Exception:  # noqa: BLE001
            pass

        if not paths:
            log.write_line("[dim]No attack paths yet[/dim]")
            return

        for path in paths[:20]:
            name = str(path) if not isinstance(path, dict) else path.get("name", str(path))
            log.write_line(f"◉ {name}")


class _CredentialsSection(Widget):
    """Discovered credentials sub-panel."""

    def __init__(self, shell: Any, **kwargs) -> None:
        super().__init__(**kwargs)
        self._shell = shell

    def compose(self) -> ComposeResult:
        yield Static("  CREDENTIALS", id="credentials-title")
        yield Log(id="credentials-list", highlight=True)

    def on_mount(self) -> None:
        self.refresh_content()

    def refresh_content(self) -> None:
        """Reload discovered credentials from shell state."""
        log = self.query_one("#credentials-list", Log)
        log.clear()

        creds: list = []
        try:
            cred_svc = getattr(self._shell, "_credential_service", None)
            if cred_svc and hasattr(cred_svc, "get_valid_credentials"):
                creds = cred_svc.get_valid_credentials() or []
        except Exception:  # noqa: BLE001
            pass

        if not creds:
            log.write_line("[dim]No credentials yet[/dim]")
            return

        for cred in creds[:30]:
            if isinstance(cred, dict):
                user = cred.get("username", "?")
                secret = cred.get("password") or cred.get("hash") or "?"
                # Truncate long secrets for display
                if len(str(secret)) > 16:
                    secret = str(secret)[:14] + "…"
                log.write_line(f"● {user} : {secret}")
            else:
                log.write_line(f"● {cred}")
