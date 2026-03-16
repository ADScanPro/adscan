"""Detect and auto-repair stale myip when the network interface IP changes.

When ADscan stores a workspace, it persists ``myip`` alongside the interface
name (e.g. ``tun0``).  If the machine reboots or the VPN reconnects, DHCP may
assign a different IP to that interface.  The stored ``myip`` then points to a
dead address, causing reverse-connection operations (Ligolo pivot, reverse
shells) to silently time out.

This module provides:

- :func:`detect_myip_staleness` – pure staleness check, no side-effects.
- :func:`check_and_refresh_myip` – check + auto-update ``shell.myip`` + display
  a premium Rich warning so the user understands what changed and why.

Typical call sites
------------------
- ``adscan_internal/workspaces/loader.py`` – after workspace variables are
  applied, so every workspace load validates the IP up-front.
- ``adscan_internal/services/pivot_service.py`` – inside
  ``_resolve_ligolo_connect_host``, so the Ligolo agent always gets the current
  IP even if the workspace was loaded with a stale one.
"""

from __future__ import annotations

from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_warning,
)


# ---------------------------------------------------------------------------
# Pure detection helpers
# ---------------------------------------------------------------------------


def _get_interface_current_ip(interface: str) -> str | None:
    """Return the first IPv4 address currently assigned to *interface*, or None."""
    try:
        from adscan_internal.services.network_preflight_service import (
            get_interface_ipv4_addresses,
        )

        ips = get_interface_ipv4_addresses(interface)
        return ips[0] if ips else None
    except Exception as exc:
        print_info_debug(f"[myip] Failed to query interface {interface!r}: {exc}")
        return None


def detect_myip_staleness(
    interface: str | None,
    stored_ip: str | None,
) -> dict[str, Any]:
    """Check whether *stored_ip* matches the IP currently on *interface*.

    Args:
        interface: Network interface name stored in the workspace (e.g. ``tun0``).
        stored_ip: ``myip`` value persisted in the workspace variables.

    Returns:
        A dict with the following keys:

        - ``interface`` (str | None): the interface name.
        - ``stored_ip`` (str | None): the value originally stored.
        - ``current_ip`` (str | None): the IP currently on the interface.
        - ``is_stale`` (bool): True when stored_ip ≠ current_ip.
        - ``no_ip_on_interface`` (bool): True when the interface exists but has
          no IPv4 address (VPN not connected?).
        - ``check_skipped`` (bool): True when the check could not be performed
          (interface or stored_ip unknown).
    """
    result: dict[str, Any] = {
        "interface": interface,
        "stored_ip": stored_ip,
        "current_ip": None,
        "is_stale": False,
        "no_ip_on_interface": False,
        "check_skipped": False,
    }

    if not interface or not stored_ip:
        result["check_skipped"] = True
        return result

    current_ip = _get_interface_current_ip(interface)
    result["current_ip"] = current_ip

    if current_ip is None:
        result["no_ip_on_interface"] = True
        return result

    result["is_stale"] = current_ip != stored_ip
    return result


# ---------------------------------------------------------------------------
# UX display
# ---------------------------------------------------------------------------


def _display_ip_changed_warning(
    *,
    interface: str,
    stored_ip: str,
    current_ip: str,
    context: str,
) -> None:
    """Render a premium Rich warning panel describing the IP change."""
    ctx_suffix = f" ({context})" if context else ""
    marked_old = mark_sensitive(stored_ip, "host")
    marked_new = mark_sensitive(current_ip, "host")
    print_warning(
        f"[bold]myip[/bold] on interface [bold cyan]{interface}[/bold cyan] "
        f"has changed{ctx_suffix}",
        items=[
            f"Previous IP:  [dim]{marked_old}[/dim]",
            f"Current IP:   [bold green]{marked_new}[/bold green]  [dim](auto-updated)[/dim]",
            "Likely cause: DHCP renewal after VPN reconnect or host reboot",
        ],
        panel=True,
        spacing="before",
    )
    print_success(
        f"myip automatically updated to [bold]{marked_new}[/bold].",
        spacing="after",
    )


def _display_no_ip_warning(
    *,
    interface: str,
    stored_ip: str,
    context: str,
) -> None:
    """Warn that the interface has no IPv4 address (VPN not connected?)."""
    ctx_suffix = f" ({context})" if context else ""
    marked_stored = mark_sensitive(stored_ip, "host")
    print_warning(
        f"Interface [bold cyan]{interface}[/bold cyan] has no IPv4 address assigned{ctx_suffix}.",
        items=[
            f"Stored myip:  [dim]{marked_stored}[/dim]",
            f"Is the VPN connected? Run [bold]set iface {interface}[/bold] to refresh once connected.",
        ],
        panel=True,
        spacing="before",
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def check_and_refresh_myip(
    shell: Any,
    *,
    context: str = "",
) -> str | None:
    """Validate ``shell.myip`` against the current interface IP and auto-fix.

    Reads ``shell.interface`` and ``shell.myip``, checks whether the IP has
    changed since the workspace was saved, and updates ``shell.myip`` in place
    if a newer IP is detected.  Always shows clear Rich output when the IP
    has changed or the interface has no address.

    Args:
        shell: ADscan shell instance with ``.myip`` and ``.interface`` attrs.
        context: Short human-readable label shown in the warning
                 (e.g. ``"workspace load"``, ``"Ligolo pivot"``).

    Returns:
        The current (possibly refreshed) ``myip``, or ``None`` if undetermined.
    """
    interface = str(getattr(shell, "interface", "") or "").strip()
    stored_ip = str(getattr(shell, "myip", "") or "").strip()

    if not interface:
        print_info_debug("[myip] Staleness check skipped: no interface configured.")
        return stored_ip or None

    staleness = detect_myip_staleness(interface=interface, stored_ip=stored_ip)

    if staleness["check_skipped"]:
        print_info_debug(
            f"[myip] Staleness check skipped: interface={interface!r} stored_ip={stored_ip!r}"
        )
        return stored_ip or None

    if staleness["no_ip_on_interface"]:
        if stored_ip:
            _display_no_ip_warning(
                interface=interface,
                stored_ip=stored_ip,
                context=context,
            )
        else:
            print_info_debug(f"[myip] {interface} has no IPv4 — VPN not connected?")
        return stored_ip or None

    current_ip = staleness["current_ip"]

    if not staleness["is_stale"]:
        print_info_debug(
            f"[myip] IP is current: interface={interface} myip={stored_ip}"
        )
        return stored_ip

    # IP changed — auto-update and show premium UX
    try:
        _display_ip_changed_warning(
            interface=interface,
            stored_ip=stored_ip,
            current_ip=current_ip,
            context=context,
        )
    except Exception as exc:  # never let display failure block the update
        print_info_debug(f"[myip] Display error: {exc}")

    shell.myip = current_ip
    print_info_verbose(
        f"[myip] Auto-updated: interface={interface} old={stored_ip} new={current_ip} context={context!r}"
    )
    telemetry.capture(
        "myip_auto_updated",
        {
            "interface": interface,
            "context": context,
        },
    )
    return current_ip
