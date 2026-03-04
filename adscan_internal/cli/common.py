"""Common CLI helpers for telemetry context, workspace selection, first-run, and shared constants.

This module provides shared functionality used across CLI commands to avoid
circular dependencies and duplicate code.
"""

from __future__ import annotations

import hashlib
from typing import Any

from adscan_core.lab_context import (
    build_lab_telemetry_fields,
    build_workspace_telemetry_fields,
)
from adscan_internal.path_utils import get_adscan_state_dir
from adscan_internal.telemetry import TELEMETRY_ID
from adscan_internal.rich_output import mark_sensitive, print_info_debug, print_panel
from rich.text import Text


# SECRET_MODE is a global flag that controls whether internal implementation
# details are shown. It is set in adscan.py during initialization.
# CLI modules should import this from here instead of adscan.py.
# This will be initialized by adscan.py on startup.
import os

SECRET_MODE: bool = os.getenv("ADSCAN_SECRET_MODE") == "1"  # pylint: disable=invalid-name


def build_telemetry_context(
    *,
    shell: Any,
    trigger: str,
) -> dict[str, Any]:
    """Build telemetry context dictionary from shell state.

    This helper extracts workspace and lab information from a shell instance
    and builds a standardized telemetry context dictionary.

    Args:
        shell: Shell instance with workspace attributes (current_workspace, type,
               lab_provider, lab_name, lab_name_whitelisted).
        trigger: Telemetry change trigger (e.g., "session_start", "ci_start").

    Returns:
        Dictionary with telemetry context including workspace_id_hash,
        workspace_type, lab_provider, lab_name, lab_name_whitelisted, and
        telemetry_change_trigger.
    """
    telemetry_context: dict[str, Any] = {}

    if getattr(shell, "current_workspace", None):
        workspace_unique_id = f"{TELEMETRY_ID}:{shell.current_workspace}"
        telemetry_context["workspace_id_hash"] = hashlib.sha256(
            workspace_unique_id.encode()
        ).hexdigest()[:12]

    telemetry_context.update(
        build_workspace_telemetry_fields(workspace_type=getattr(shell, "type", None))
    )

    telemetry_context.update(build_lab_event_fields(shell=shell, include_slug=False))

    telemetry_context["telemetry_change_trigger"] = trigger

    return telemetry_context


def build_lab_event_fields(*, shell: Any, include_slug: bool = True) -> dict[str, Any]:
    """Build normalized lab telemetry fields for event payloads.

    Args:
        shell: Shell instance that may expose ``lab_provider``, ``lab_name``,
            ``lab_name_whitelisted`` and optional ``_get_lab_slug``.
        include_slug: Whether to include ``lab_slug``.

    Returns:
        Dictionary with normalized lab context fields according to privacy rules.
    """
    lab_slug: str | None = None
    if include_slug:
        slug_getter = getattr(shell, "_get_lab_slug", None)
        if callable(slug_getter):
            try:
                lab_slug = slug_getter()
            except Exception:
                lab_slug = None

    return build_lab_telemetry_fields(
        lab_provider=getattr(shell, "lab_provider", None),
        lab_name=getattr(shell, "lab_name", None),
        lab_name_whitelisted=getattr(shell, "lab_name_whitelisted", None),
        include_slug=include_slug,
        lab_slug=lab_slug,
    )


def is_first_run() -> bool:
    """Check if this is the first time running ADscan.

    Returns:
        True if first run, False otherwise.
    """
    # Use persisted state (mounted from host in Docker-mode) so the panel is only shown once.
    flag_file = get_adscan_state_dir() / ".first_run_complete"
    return not flag_file.exists()


def mark_first_run_complete() -> None:
    """Mark first run as complete by creating flag file."""
    flag_file = get_adscan_state_dir() / ".first_run_complete"
    try:
        flag_file.parent.mkdir(parents=True, exist_ok=True)
        flag_file.touch()
    except Exception:
        # Silently fail if can't create flag (non-critical)
        pass


def show_first_run_helper(
    track_docs_link_shown: Any | None = None,
) -> None:
    """Show getting started helper on first run only.

    Args:
        track_docs_link_shown: Optional function to track when docs link is shown.
                              If provided, should accept (context: str, url: str).
    """
    helper_text = Text.from_markup(
        "💡 [bold]New to ADscan?[/bold]\n\n"
        "Quick Start:\n"
        "  1. Create workspace:  [cyan]workspace create my_pentest[/cyan]\n"
        "  2. Scan unauth:       [cyan]start_unauth[/cyan]\n"
        "  3. Scan auth:         [cyan]start_auth[/cyan]\n"
        "  4. Add a credential:  [cyan]creds save <domain> <username> <password>[/cyan]\n\n"
        "📚 Full documentation: [link=https://www.adscanpro.com/docs?utm_source=cli&utm_medium=first_run]"
        "www.adscanpro.com/docs[/link]\n"
        "   (Installation, guides, troubleshooting, and more)\n\n"
        "[dim]Type 'help' for available commands[/dim]"
    )

    print_panel(
        helper_text,
        title="[bold cyan]Getting Started[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )

    # Track docs link shown if tracking function provided
    if track_docs_link_shown is not None:
        try:
            track_docs_link_shown(
                "first_run",
                "https://www.adscanpro.com/docs?utm_source=cli&utm_medium=first_run",
            )
        except Exception:
            # Silently fail if tracking fails (non-critical)
            pass


def resolve_command_context_domain(
    shell: Any,
    command_name: str,
    args_list: list[str],
) -> tuple[str | None, str]:
    """Resolve the most relevant domain for command-context logging."""
    try:
        if args_list:
            arg0 = (args_list[0] or "").strip()
            if arg0:
                if arg0 in getattr(shell, "domains_data", {}):
                    return arg0, "arg0_domains_data"
                if arg0 in getattr(shell, "domains", []):
                    return arg0, "arg0_domains"
        current_domain = getattr(shell, "domain", None)
        if current_domain and current_domain in getattr(shell, "domains_data", {}):
            return current_domain, "current_domain"
        if args_list:
            arg0 = (args_list[0] or "").strip()
            if (
                arg0
                and "." in arg0
                and not arg0.startswith("-")
                and command_name not in {"set", "workspace", "session", "help"}
            ):
                return arg0, "arg0_fallback"
    except Exception:
        pass
    return None, "none"


def load_bloodhound_ce_display_config() -> tuple[str, str, str]:
    """Return BloodHound CE login URL and credentials for CLI info/logging views."""
    default_base_url = "http://localhost:8442"
    base_url = default_base_url
    username = "admin"
    password = "Not configured"
    config_path: str | None = None

    try:
        from adscan_internal.bloodhound_ce_compose import BLOODHOUND_CE_DEFAULT_WEB_PORT
        from adscan_internal.integrations.bloodhound_cli.core.settings import (
            CONFIG_FILE as BLOODHOUND_CONFIG_FILE,
            load_ce_config,
        )

        default_base_url = f"http://localhost:{BLOODHOUND_CE_DEFAULT_WEB_PORT}"
        base_url = default_base_url
        config_path = str(BLOODHOUND_CONFIG_FILE)

        ce_config = load_ce_config()
        base_url_candidate = str(getattr(ce_config, "base_url", "") or "").strip()
        username_candidate = str(getattr(ce_config, "username", "") or "").strip()
        password_candidate = str(getattr(ce_config, "password", "") or "").strip()

        if base_url_candidate:
            base_url = base_url_candidate.rstrip("/")
        if username_candidate:
            username = username_candidate
        if password_candidate:
            password = password_candidate
        else:
            marked_path = (
                mark_sensitive(config_path, "path")
                if config_path
                else mark_sensitive("~/.bloodhound_config", "path")
            )
            print_info_debug(
                f"BloodHound CE password missing in {marked_path}; showing fallback value."
            )
    except Exception as exc:
        marked_path = (
            mark_sensitive(config_path, "path")
            if config_path
            else mark_sensitive("~/.bloodhound_config", "path")
        )
        print_info_debug(
            f"Failed to load BloodHound CE config from {marked_path}; using defaults. Error: {exc}"
        )

    login_url = f"{base_url.rstrip('/')}/ui/login"
    return login_url, username, password


def build_cli_runtime_snapshot(
    *,
    shell: Any,
    command_name: str | None = None,
    args_list: list[str] | None = None,
) -> dict[str, Any]:
    """Build a normalized runtime snapshot shared by `info` and CLI command logging."""
    args = list(args_list or [])
    resolved_command = (command_name or "").strip()
    context_domain: str | None = None
    domain_source = "none"
    if resolved_command:
        context_domain, domain_source = resolve_command_context_domain(
            shell=shell,
            command_name=resolved_command,
            args_list=args,
        )
    elif getattr(shell, "domain", None):
        context_domain = str(getattr(shell, "domain", None))
        domain_source = "current_domain"

    domains_data = getattr(shell, "domains_data", {}) or {}
    current_domain = getattr(shell, "domain", None)
    current_domain_auth = "unknown"
    if current_domain and isinstance(domains_data, dict):
        current_domain_data = domains_data.get(current_domain, {})
        if isinstance(current_domain_data, dict):
            current_domain_auth = str(current_domain_data.get("auth", "unknown"))

    domain_state: dict[str, Any] | None = None
    if context_domain and context_domain in domains_data:
        domain_data = domains_data.get(context_domain, {})
        if isinstance(domain_data, dict):
            creds = domain_data.get("credentials", {})
            creds_count = len(creds) if isinstance(creds, dict) else 0
            domain_state = {
                "domain": context_domain,
                "auth": str(domain_data.get("auth", "unknown")),
                "pdc": str(domain_data.get("pdc", "N/A")),
                "pdc_hostname": str(domain_data.get("pdc_hostname", "N/A")),
                "username": str(domain_data.get("username", "N/A")),
                "credentials_count": creds_count,
            }

    login_url, bh_user, bh_password = load_bloodhound_ce_display_config()

    telemetry_enabled = False
    telemetry_source = "persisted"
    try:
        from adscan_internal import telemetry

        env_val = os.getenv("ADSCAN_TELEMETRY", None)
        telemetry_enabled = bool(telemetry._is_telemetry_enabled())
        telemetry_source = "session override" if env_val is not None else "persisted"
    except Exception:
        pass

    return {
        "hosts": getattr(shell, "hosts", None),
        "interface": getattr(shell, "interface", None),
        "myip": getattr(shell, "myip", None),
        "starting_domain": current_domain,
        "starting_domain_auth": current_domain_auth,
        "configured_domains": getattr(shell, "domains", None),
        "automatic_mode": getattr(shell, "auto", None),
        "pentest_type": getattr(shell, "type", None),
        "current_workspace": getattr(shell, "current_workspace_dir", None),
        "bloodhound_ce_url": login_url,
        "bloodhound_ce_user": bh_user,
        "bloodhound_ce_password": bh_password,
        "telemetry_enabled": telemetry_enabled,
        "telemetry_source": telemetry_source,
        "context_domain": context_domain,
        "domain_source": domain_source,
        "domains_loaded": len(domains_data) if isinstance(domains_data, dict) else 0,
        "domain_state": domain_state,
    }


def log_cli_command_context(
    shell: Any,
    command_name: str,
    args_list: list[str],
    *,
    source: str = "cli",
) -> None:
    """Emit a compact workspace/domain snapshot for CLI command execution."""
    try:
        snapshot = build_cli_runtime_snapshot(
            shell=shell,
            command_name=command_name,
            args_list=args_list,
        )
        marked_workspace = mark_sensitive(
            str(snapshot.get("current_workspace") or "None"), "path"
        )
        marked_current_domain = mark_sensitive(
            str(snapshot.get("starting_domain") or "None"), "domain"
        )
        context_domain = snapshot.get("context_domain")
        marked_context_domain = mark_sensitive(str(context_domain or "None"), "domain")
        print_info_debug(
            f"[{source}] Context: "
            f"command={command_name} "
            f"interface={snapshot.get('interface')} "
            f"type={snapshot.get('pentest_type')} "
            f"auto={snapshot.get('automatic_mode')} "
            f"scan_mode={getattr(shell, 'scan_mode', None)} "
            f"workspace={marked_workspace} "
            f"current_domain={marked_current_domain} "
            f"current_domain_auth={snapshot.get('starting_domain_auth')} "
            f"context_domain={marked_context_domain} "
            f"domain_source={snapshot.get('domain_source')} "
            f"domains_loaded={snapshot.get('domains_loaded')}"
        )

        domain_state = snapshot.get("domain_state")
        if not isinstance(domain_state, dict):
            return

        auth = str(domain_state.get("auth", "unknown"))
        marked_pdc = mark_sensitive(str(domain_state.get("pdc", "N/A")), "ip")
        marked_pdc_host = mark_sensitive(
            str(domain_state.get("pdc_hostname", "N/A")), "hostname"
        )
        marked_username = mark_sensitive(str(domain_state.get("username", "N/A")), "user")
        creds_count = int(domain_state.get("credentials_count", 0) or 0)
        print_info_debug(
            f"[{source}] Domain state: "
            f"domain={mark_sensitive(str(domain_state.get('domain', context_domain)), 'domain')} "
            f"auth={auth} "
            f"pdc={marked_pdc} "
            f"pdc_hostname={marked_pdc_host} "
            f"username={marked_username} "
            f"credentials_count={creds_count}"
        )
    except Exception:
        pass
