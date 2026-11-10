"""Where ADscan asks for a network interface: beside the poisoning decision.

Broadcast poisoning (LLMNR / NBT-NS / mDNS) is the one consumer that needs a
specific NIC, because it binds to one interface and that cannot be inferred from
the route table. Everything else resolves its callback address per target
(``services/listener_ip.py``), so the interface is no longer demanded at startup
and is asked for here, at the moment poisoning is decided.

Two entry points, both used by the consent seam
(:func:`scan_seam.maybe_launch_poisoning_job`) and by the manual ``poisoning``
REPL command so the two cannot ask differently:

* :func:`choose_poisoning_interface` (interactive only): no interface set -> the
  shared picker; an interface already set -> confirm it or switch, with the
  safe answer (keep the current one) pre-selected.
* :func:`warn_poisoning_skipped_no_interface` (non-interactive): the visible
  warning for the case that must never prompt and must never vanish quietly.
"""

from __future__ import annotations

from typing import Any, Optional

from adscan_core import telemetry
from adscan_core.rich_output import (
    print_exception,
    print_warning,
    questionary_select_index,
)

#: Shown to the operator at every skip so the capability never vanishes silently.
_SUPPLY_HINT = (
    "Pass --interface <name> to 'adscan ci', or run 'set iface <name>' and then "
    "'poisoning' in an interactive session. To silence this warning, set "
    "poisoning.enabled=false in the scan config or ADSCAN_NO_POISONING=1."
)

_SKIP_WARNED_ATTR = "_poisoning_skip_warned"


def _interface_label(shell: Any, interface: str) -> str:
    """Return ``"eth0  [10.0.0.5]"`` style text for the keep-current option."""
    try:
        from adscan_internal.services.network_preflight_service import (  # noqa: PLC0415
            get_interface_ipv4_addresses,
        )

        addresses = get_interface_ipv4_addresses(interface)
    except Exception:  # noqa: BLE001 - the address is decoration only
        addresses = []
    if addresses:
        return f"{interface}  [{', '.join(addresses)}]"
    return interface


def choose_poisoning_interface(shell: Any, *, default_launch: bool) -> Optional[str]:
    """Ask which interface poisoning should listen on. Interactive callers only.

    Args:
        shell: Active shell. Its ``interface`` is the currently configured one.
        default_launch: The pre-selected answer. ``True`` keeps/launches (audit
            default or an explicit scan-config enable); ``False`` pre-selects
            "skip" (the ctf default). Whatever the default, a non-interactive
            run never reaches here, so it can never silently switch interfaces.

    Returns:
        The interface to poison on, or ``None`` when the operator declined (or no
        usable interface exists). Never raises.
    """
    try:
        current = str(getattr(shell, "interface", "") or "").strip()
        selector = getattr(shell, "_select_network_interface", None)

        if current:
            label = _interface_label(shell, current)
            options = [
                f"Launch on {label}",
                "Use a different interface...",
                "Skip poisoning",
            ]
            idx = questionary_select_index(
                title=f"Start background poisoning on {current}?",
                options=options,
                default_idx=0 if default_launch else 2,
                shell=shell,
            )
            if idx is None or idx == 2:
                return None
            if idx == 0:
                return current
            if not callable(selector):
                return None
            if selector(
                allow_skip=True,
                purpose="Pick the interface broadcast poisoning should listen on.",
            ):
                return str(getattr(shell, "interface", "") or "").strip() or None
            return None

        if not callable(selector):
            return None
        picked = selector(
            allow_skip=True,
            default_skip=not default_launch,
            purpose=(
                "Broadcast poisoning listens on one network interface. "
                "Which one should it use?"
            ),
        )
        if picked:
            return str(getattr(shell, "interface", "") or "").strip() or None
        return None
    except Exception as exc:  # noqa: BLE001 - a prompt failure must not abort the scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return None


def _segment_option_label(segment: Any) -> str:
    """``eth1  [198.51.100.6] · 12 AD assets`` for one segment interface."""
    address = getattr(segment, "advertise_ip", None) or ", ".join(
        getattr(segment, "addresses", ()) or ()
    )
    count = int(getattr(segment, "routed_asset_count", 0) or 0)
    noun = "AD asset" if count == 1 else "AD assets"
    name = getattr(segment, "interface", "?")
    return f"{name}  [{address}] · {count} {noun}" if address else f"{name} · {count} {noun}"


def choose_poisoning_interfaces(
    shell: Any, *, default_launch: bool, segments: tuple[Any, ...]
) -> tuple[str, ...]:
    """Ask whether to poison every interface that has an AD segment behind it.

    For a host with several such interfaces (an appliance with one NIC per client
    segment). Offers all of them at once, one interface (the single-interface
    chooser), or skip. Interactive callers only. Returns the chosen interface
    names, empty when the operator declined. Never raises.
    """
    try:
        names = [str(getattr(s, "interface", "") or "") for s in segments]
        names = [n for n in names if n]
        if len(names) < 2:
            chosen = choose_poisoning_interface(shell, default_launch=default_launch)
            return (chosen,) if chosen else ()
        listing = "; ".join(_segment_option_label(s) for s in segments)
        options = [
            f"Launch on all {len(names)}: {listing}",
            "Choose one interface...",
            "Skip poisoning",
        ]
        idx = questionary_select_index(
            title=(
                f"{len(names)} interfaces have an AD segment behind them. "
                "Start background poisoning on each?"
            ),
            options=options,
            default_idx=0 if default_launch else 2,
            shell=shell,
        )
        if idx is None or idx == 2:
            return ()
        if idx == 0:
            return tuple(names)
        chosen = choose_poisoning_interface(shell, default_launch=True)
        return (chosen,) if chosen else ()
    except Exception as exc:  # noqa: BLE001 - a prompt failure must not abort the scan
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ()


def warn_poisoning_skipped_no_interface(shell: Any, *, source: str = "scan") -> None:
    """Announce, once per session, that poisoning was skipped for want of an interface.

    A non-interactive run must not prompt, and an auto-launched action must not
    disappear without a word: this is the visible half of that rule. It names the
    missing interface and how to supply it, and is emitted to telemetry so a run
    that lost the capability is countable.
    """
    try:
        if getattr(shell, _SKIP_WARNED_ATTR, False):
            return
        setattr(shell, _SKIP_WARNED_ATTR, True)
    except Exception:  # noqa: BLE001 - a frozen shell just warns every time
        pass
    print_warning(
        "Broadcast poisoning (LLMNR / NBT-NS / mDNS) was skipped: it would run "
        "for this scan, but no network interface was provided and no local "
        "interface has a known AD asset routed through it yet, so it cannot "
        f"choose one unattended. {_SUPPLY_HINT}"
    )
    try:
        telemetry.capture("poisoning_skipped_no_interface", {"source": source})
    except Exception as exc:  # noqa: BLE001 - telemetry is best-effort
        print_exception(exception=exc)


__all__ = [
    "choose_poisoning_interface",
    "choose_poisoning_interfaces",
    "warn_poisoning_skipped_no_interface",
]
