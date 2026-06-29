"""Dispatcher for the standalone ``posture <action> [<domain>]`` shell command.

Three actions:
    show   — render the inspection panel for the given domain
    probe  — re-run the posture probes (force=True) and show the resulting panel
    clear  — wipe the persisted ``auth_posture`` block after confirmation

This module is the only consumer of :mod:`adscan_internal.cli.widgets.posture_show`
from the shell. ``adscan.py`` keeps its ``do_posture`` body to a single call here
to avoid bloat.
"""

from __future__ import annotations

from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import (
    print_error,
    print_info,
    print_panel,
    print_success,
    print_warning,
)
from adscan_internal import get_console
from adscan_internal.rich_output import mark_sensitive


# --------------------------------------------------------------------------- #
# Public dispatcher
# --------------------------------------------------------------------------- #


def handle_posture_command(shell: Any, args: str) -> None:
    """Parse and dispatch the ``posture <action> [<domain>]`` command."""
    parts = (args or "").split()
    if not parts:
        # No subcommand: fall back to show against the current domain, or
        # render a usage banner when no domain is selected.
        if not getattr(shell, "current_domain", None):
            _print_usage_banner()
            return
        _do_posture_show(shell, None)
        return

    action = parts[0].lower()
    domain_arg = parts[1] if len(parts) > 1 else None

    if action == "show":
        _do_posture_show(shell, domain_arg)
    elif action == "probe":
        _do_posture_probe(shell, domain_arg)
    elif action == "clear":
        _do_posture_clear(shell, domain_arg)
    else:
        print_error(f"Unknown posture subcommand: {action!r}")
        print_info("Use: posture show | posture probe | posture clear")


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #


def _do_posture_show(shell: Any, domain_arg: Optional[str]) -> None:
    domain = _resolve_domain(shell, domain_arg, require_in_workspace=True)
    if domain is None:
        return
    from adscan_internal.cli.widgets.posture_show import render_posture_show
    from adscan_internal.services.domain_posture import get_posture

    try:
        posture = get_posture(getattr(shell, "domains_data", None) or {}, domain=domain)
        get_console().print(render_posture_show(posture=posture, domain=domain))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Failed to render posture for {domain}: {exc}")


def _do_posture_probe(shell: Any, domain_arg: Optional[str]) -> None:
    domain = _resolve_domain(shell, domain_arg, require_in_workspace=True)
    if domain is None:
        return

    domains_data = getattr(shell, "domains_data", None) or {}
    domain_entry = domains_data.get(domain) or {}
    pdc_ip = domain_entry.get("pdc")
    if not pdc_ip:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Domain {marked_domain} has no PDC IP recorded. Run "
            f"`start_unauth {domain}` first to discover the DC."
        )
        return

    username = domain_entry.get("username") or None
    cred_value = domain_entry.get("password")
    password: Optional[str] = None
    nt_hash: Optional[str] = None
    if cred_value:
        try:
            if shell.is_hash(cred_value):
                nt_hash = cred_value
            else:
                password = cred_value
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            password = cred_value

    from adscan_internal.cli.posture_probe_lifecycle import run_posture_probe

    try:
        run_posture_probe(
            shell,
            domain=domain,
            dc_ip=pdc_ip,
            username=username,
            password=password,
            nt_hash=nt_hash,
            force=True,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Posture probe failed for {domain}: {exc}")
        return

    # Print the updated panel as inline confirmation.
    try:
        from adscan_internal.cli.widgets.posture_show import render_posture_show
        from adscan_internal.services.domain_posture import get_posture

        posture = get_posture(getattr(shell, "domains_data", None) or {}, domain=domain)
        get_console().print(render_posture_show(posture=posture, domain=domain))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)


def _do_posture_clear(shell: Any, domain_arg: Optional[str]) -> None:
    domain = _resolve_domain(shell, domain_arg, require_in_workspace=True)
    if domain is None:
        return

    domains_data = getattr(shell, "domains_data", None) or {}
    domain_entry = domains_data.get(domain) or {}
    auth_posture = domain_entry.get("auth_posture")
    marked_domain = mark_sensitive(domain, "domain")

    if not auth_posture:
        print_info(f"No posture data to clear for {marked_domain}.")
        return

    from adscan_internal.services.domain_posture import TriState, get_posture

    posture = get_posture(domains_data, domain=domain)
    hardening_count = sum(
        1 for c in posture.constraints.values() if c.state is not TriState.UNKNOWN
    )

    print_warning(
        f"About to clear all posture data for {marked_domain} "
        f"({hardening_count} known constraint{'s' if hardening_count != 1 else ''})."
    )
    print_info(
        "ADscan will re-discover the posture from scratch on the next operation."
    )

    from adscan_internal.interaction import is_non_interactive

    if is_non_interactive(shell) or getattr(shell, "ui_silent", False):
        # Never clear without explicit confirmation in non-interactive mode.
        # questionary.confirm is a DIRECT call (not covered by the Rich
        # Prompt/Confirm wrapper), so it would block under adscan ci — guard it
        # with the canonical predicate and resolve to the safe default (False:
        # do not clear).
        print_info("Cancelled (non-interactive mode). Posture unchanged.")
        return

    try:
        import questionary

        answer = questionary.confirm("Proceed?", default=False).ask()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info("Cancelled. Posture unchanged.")
        return

    if not answer:
        print_info("Cancelled. Posture unchanged.")
        return

    try:
        del domains_data[domain]["auth_posture"]
    except KeyError:
        pass
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Failed to clear posture for {domain}: {exc}")
        return

    try:
        shell.save_workspace_data()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning(f"Posture cleared in memory but workspace save failed: {exc}")
        return

    print_success(f"Posture cleared for {marked_domain}.")
    print_info(
        "Re-discovery starts on the next operation, or run `posture probe` "
        "to refresh now."
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _resolve_domain(
    shell: Any,
    domain_arg: Optional[str],
    *,
    require_in_workspace: bool,
) -> Optional[str]:
    """Resolve which domain to act on, printing user-facing errors as needed."""
    domains_data = getattr(shell, "domains_data", None) or {}
    if domain_arg:
        domain = domain_arg.strip()
        if require_in_workspace and domain not in domains_data:
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(f"Domain {marked_domain} is not in the current workspace.")
            available = ", ".join(domains_data.keys()) if domains_data else "(none)"
            print_info(f"Available domains: {available}")
            return None
        return domain

    current = getattr(shell, "current_domain", None)
    if not current:
        print_error(
            "No domain selected. Either pass <domain> or set current_domain "
            "via `set domain <name>`."
        )
        return None
    return current


def _print_usage_banner() -> None:
    """Locked usage banner shown when no current domain and no args."""
    body = (
        "  adscan posture show [<domain>]\n"
        "  adscan posture probe [<domain>]\n"
        "  adscan posture clear [<domain>]\n"
        "\n"
        "  Run a scan first to learn the domain's security posture, or\n"
        "  re-probe an existing one."
    )
    print_panel(body, title="🛡️  Posture · usage", border_style="cyan")


__all__ = ["handle_posture_command"]
