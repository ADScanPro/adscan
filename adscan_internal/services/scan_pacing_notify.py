"""Operator-facing lines for the scan-pacing strain safeguard.

``adscan_core.scan_pacing.pacing_runtime`` decides when to slow down and records
every action for the disclosure; it does not print. This module turns those
actions into terminal lines (mirrored to the sanitized recording like every
``print_*``), so the operator sees the safeguard act while the scan runs.
Installed once at CLI startup.
"""

from __future__ import annotations

from typing import Any

from adscan_core.rich_output import print_info_verbose, print_warning
from adscan_core.scan_pacing.pacing_runtime import set_strain_notifier
from adscan_core.sensitive import mark_sensitive


def _host(detail: dict[str, Any]) -> str:
    return mark_sensitive(str(detail.get("host") or "a host"), "hostname")


def notify_strain_event(kind: str, detail: dict[str, Any]) -> None:
    """Render one safeguard action. Never raises."""
    try:
        if kind == "slowed":
            print_warning(
                f"Pacing: {_host(detail)} is answering slowly or refusing connections, "
                "so ADscan slowed down on it."
            )
        elif kind == "cooldown":
            print_warning(
                f"Pacing: {_host(detail)} stopped answering. ADscan waits "
                f"{int(detail.get('seconds') or 60)}s before trying it once more."
            )
        elif kind == "paused":
            print_warning(
                f"Pacing: {_host(detail)} is still not answering, so ADscan stopped working "
                "against it. Its remaining checks are recorded as not assessed."
            )
        elif kind == "global_backoff":
            percent = int(round(float(detail.get("fraction") or 0.5) * 100))
            print_warning(
                "Pacing: several servers are struggling, so ADscan reduced how much it "
                f"runs in parallel (now {percent}% of the chosen level)."
            )
        elif kind in ("resumed", "recovered"):
            print_info_verbose(f"Pacing: {_host(detail)} is answering normally again.")
        elif kind == "global_recover":
            percent = int(round(float(detail.get("fraction") or 1.0) * 100))
            print_info_verbose(f"Pacing: parallel work restored to {percent}% of the chosen level.")
    except Exception:  # noqa: BLE001 - a notification must never break a scan
        return


def install_strain_notifier() -> None:
    """Route safeguard actions to the operator's terminal."""
    set_strain_notifier(notify_strain_event)


__all__ = ["install_strain_notifier", "notify_strain_event"]
