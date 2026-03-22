"""Shared NetExec timeout policy helpers.

This module centralizes ADscan's opinionated timeout policy for the NetExec
services that matter operationally today:

- smb
- ldap
- winrm
- rdp
- mssql

The goals are:
- keep per-target NetExec ``--timeout`` values consistent across builders
- scale the outer ADscan timeout with service cost and target count
- provide sensible extended retry timeouts for timeout recovery in the runner
- centralize CVE-module timeout policy where it differs from generic SMB
"""

from __future__ import annotations

SERVICE_INTERNAL_TIMEOUTS: dict[str, int] = {
    "smb": 45,
    "ldap": 60,
    "winrm": 45,
    "rdp": 60,
    "mssql": 60,
}

_SERVICE_SINGLE_TARGET_TIMEOUTS: dict[str, int] = {
    "smb": 600,
    "ldap": 900,
    "winrm": 900,
    "rdp": 900,
    "mssql": 900,
}

_SERVICE_SWEEP_TIMEOUTS: dict[str, tuple[int, int, int, int]] = {
    "smb": (900, 1500, 2400, 3600),
    "ldap": (1200, 1800, 2700, 3600),
    "winrm": (900, 1500, 2400, 3600),
    "rdp": (1200, 1800, 2700, 3600),
    "mssql": (900, 1500, 2400, 3600),
}

_SERVICE_EXTENDED_TIMEOUT_FLOORS: dict[str, tuple[int, int]] = {
    "smb": (1800, 3600),
    "ldap": (1800, 3600),
    "winrm": (1800, 3600),
    "rdp": (1800, 3600),
    "mssql": (1800, 3600),
}

_CVE_BASE_TIMEOUTS: dict[str, int] = {
    "zerologon": 900,
    "nopac": 600,
    "printnightmare": 600,
    "coerce_plus": 600,
}


def get_recommended_internal_timeout(service: str, *, default: int = 30) -> int:
    """Return the preferred NetExec ``--timeout`` for one service."""

    return SERVICE_INTERNAL_TIMEOUTS.get(str(service or "").strip().lower(), default)


def resolve_service_command_timeout_seconds(
    *,
    service: str,
    target_count: int,
    return_boolean: bool,
) -> int:
    """Return the preferred outer ADscan timeout for one NetExec service command."""

    normalized_service = str(service or "").strip().lower()
    normalized_target_count = max(int(target_count or 1), 1)

    if return_boolean:
        return _SERVICE_SINGLE_TARGET_TIMEOUTS.get(normalized_service, 600)

    low, medium, large, xlarge = _SERVICE_SWEEP_TIMEOUTS.get(
        normalized_service,
        (600, 900, 1200, 1800),
    )
    if normalized_target_count >= 3000:
        return xlarge
    if normalized_target_count >= 1000:
        return large
    if normalized_target_count >= 250:
        return medium
    return low


def resolve_extended_timeout_seconds(
    *,
    service: str | None,
    current_timeout_seconds: int | None,
    target_count: int,
) -> int:
    """Return the preferred extended timeout after one NetExec timeout."""

    base_timeout = int(current_timeout_seconds or 0)
    if base_timeout <= 0:
        return 1800

    normalized_service = str(service or "").strip().lower()
    normalized_target_count = max(int(target_count or 1), 1)
    small_floor, large_floor = _SERVICE_EXTENDED_TIMEOUT_FLOORS.get(
        normalized_service,
        (1200, 2400),
    )
    floor_timeout = large_floor if normalized_target_count >= 1000 else small_floor
    return max(base_timeout * 2, floor_timeout)


def resolve_netexec_cve_timeout_seconds(
    *,
    cve: str,
    target_scope: str,
    target_count: int,
) -> int:
    """Return the preferred outer ADscan timeout for one NetExec CVE module.

    CVE modules are SMB-backed but some, especially Zerologon, legitimately run
    longer than a generic SMB sweep. The initial timeout should therefore be
    more generous while still scaling with the size of the DC target file when
    available.
    """

    normalized_cve = str(cve or "").strip().lower()
    normalized_scope = str(target_scope or "").strip().lower()
    normalized_target_count = max(int(target_count or 1), 1)

    if normalized_cve == "zerologon":
        if normalized_target_count >= 10:
            return 3600
        if normalized_target_count >= 5:
            return 2700
        if normalized_target_count >= 2:
            return 1800
        return 900 if normalized_scope == "dcs" else 600

    base_timeout = _CVE_BASE_TIMEOUTS.get(normalized_cve, 300)
    if normalized_target_count >= 10:
        return max(base_timeout * 4, 1800)
    if normalized_target_count >= 5:
        return max(base_timeout * 3, 1200)
    if normalized_target_count >= 2:
        return max(base_timeout * 2, 900)
    return base_timeout
