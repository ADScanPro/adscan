"""Shared RODC host-access outcome helpers.

This module normalizes the execution outcome shape used when ADscan reaches an
operational foothold on an RODC host, regardless of the entry vector
(``RBCD``, ``AdminTo``, ``CanPSRemote``, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal.rich_output import strip_sensitive_markers


@dataclass(frozen=True, slots=True)
class RodcHostAccessContext:
    """Normalized host-access context for one RODC follow-up chain."""

    domain: str
    target_domain: str
    target_computer: str
    access_source: str
    auth_username: str
    auth_secret: str
    auth_mode: str
    attacker_machine: str = ""
    target_spn: str = ""
    delegated_user: str = ""
    ticket_path: str = ""


def build_rodc_host_access_outcome(
    *,
    domain: str,
    target_domain: str,
    target_computer: str,
    access_source: str,
    auth_username: str,
    auth_secret: str,
    auth_mode: str,
    attacker_machine: str = "",
    target_spn: str = "",
    delegated_user: str = "",
    ticket_path: str = "",
) -> dict[str, str]:
    """Build one normalized ``rodc_host_access_prepared`` outcome payload."""
    return {
        "key": "rodc_host_access_prepared",
        "domain": str(domain or "").strip(),
        "target_domain": str(target_domain or "").strip(),
        "target_computer": str(target_computer or "").strip(),
        "access_source": str(access_source or "").strip().lower(),
        "auth_username": str(auth_username or "").strip(),
        "auth_secret": str(auth_secret or "").strip(),
        "auth_mode": str(auth_mode or "").strip().lower(),
        "attacker_machine": str(attacker_machine or "").strip(),
        "target_spn": str(target_spn or "").strip(),
        "delegated_user": str(delegated_user or "").strip(),
        "ticket_path": str(ticket_path or "").strip(),
    }


def parse_rodc_host_access_outcome(
    outcome: dict[str, Any] | None,
) -> RodcHostAccessContext | None:
    """Parse one execution outcome into ``RodcHostAccessContext`` when possible."""
    if not isinstance(outcome, dict):
        return None
    key = str(outcome.get("key") or "").strip().lower()
    if key != "rodc_host_access_prepared":
        return None

    domain = _clean(outcome.get("domain"))
    target_domain = _clean(outcome.get("target_domain")) or domain
    target_computer = _clean(outcome.get("target_computer"))
    access_source = _clean(outcome.get("access_source")).lower()
    auth_username = _clean(outcome.get("auth_username"))
    auth_secret = _clean(outcome.get("auth_secret"))
    auth_mode = _clean(outcome.get("auth_mode")).lower()
    if not target_domain or not target_computer or not auth_username or not auth_secret:
        return None

    return RodcHostAccessContext(
        domain=domain,
        target_domain=target_domain,
        target_computer=target_computer,
        access_source=access_source,
        auth_username=auth_username,
        auth_secret=auth_secret,
        auth_mode=auth_mode or "host_access",
        attacker_machine=_clean(outcome.get("attacker_machine")),
        target_spn=_clean(outcome.get("target_spn")),
        delegated_user=_clean(outcome.get("delegated_user")),
        ticket_path=_clean(outcome.get("ticket_path")),
    )


def _clean(value: Any) -> str:
    """Return one stripped string with sensitive markers removed."""
    return strip_sensitive_markers(str(value or "")).strip()


__all__ = [
    "RodcHostAccessContext",
    "build_rodc_host_access_outcome",
    "parse_rodc_host_access_outcome",
]
