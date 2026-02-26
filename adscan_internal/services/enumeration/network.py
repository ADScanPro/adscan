"""Network enumeration mixin.

This module provides network/service enumeration helpers for protocols that are
not strictly "directory" protocols (RDP, WinRM, MSSQL, etc.).

The implementation is intentionally minimal for now: it defines stable public
types and method signatures so callers (CLI orchestration and the future web UX)
can depend on them while we progressively migrate logic out of ``adscan.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional
import logging

from adscan_internal.core import AuthMode, requires_auth


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NetworkServiceFinding:
    """Represents a discovery on a remote host for a given service.

    Attributes:
        host: Host identifier (IP or hostname).
        protocol: Protocol identifier (e.g. "rdp", "winrm", "mssql").
        port: Optional port if known.
        details: Optional free-form details.
    """

    host: str
    protocol: str
    port: Optional[int] = None
    details: Optional[str] = None


class NetworkEnumerationMixin:
    """Network/service enumeration operations."""

    def __init__(self, parent_service):
        """Initialize mixin.

        Args:
            parent_service: Parent EnumerationService instance.
        """
        self.parent = parent_service
        self.logger = parent_service.logger

    @requires_auth(AuthMode.AUTHENTICATED)
    def enumerate_rdp(
        self,
        hosts: list[str],
        *,
        scan_id: Optional[str] = None,
    ) -> list[NetworkServiceFinding]:
        """Enumerate RDP availability on target hosts.

        This method currently emits progress and returns an empty list.
        Migration target: re-use existing CLI logic when moving off ``adscan.py``.

        Args:
            hosts: Target hosts.
            scan_id: Optional scan id.

        Returns:
            List of findings (currently empty).
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="network_rdp",
            progress=0.0,
            message=f"Starting RDP enumeration for {len(hosts)} host(s)",
        )
        self.logger.debug(
            "NetworkEnumerationMixin.enumerate_rdp is not yet implemented"
        )
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="network_rdp",
            progress=1.0,
            message="RDP enumeration completed (stub)",
        )
        return []


def is_computer_dc_for_domain(
    *,
    domain: str,
    target_host: str,
    domain_info: Mapping[str, Any],
) -> bool:
    """Return True if ``target_host`` matches a known DC for the domain.

    This helper centralises the logic that was previously in
    ``PentestShell.is_computer_dc`` so it can be reused from services and CLI
    layers without depending on the shell implementation.

    Args:
        domain: Active Directory domain name.
        target_host: Hostname or IP to check.
        domain_info: Mapping for the domain, typically from ``domains_data``,
            expected to contain ``\"dcs_hostnames\"`` and ``\"dcs\"`` keys.
    """
    dcs_hostnames = domain_info.get("dcs_hostnames", [])
    dcs_ips = domain_info.get("dcs", [])

    # Direct IP match against known DC IPs.
    if target_host in dcs_ips:
        return True

    target_host_norm = (target_host or "").lower()

    # Normalise hostnames list.
    if isinstance(dcs_hostnames, str):
        dcs_hostnames = [dcs_hostnames]

    for hostname in dcs_hostnames:
        hostname_norm = (hostname or "").lower()
        fqdn = f"{hostname_norm}.{(domain or '').lower()}"
        if target_host_norm == hostname_norm or target_host_norm == fqdn:
            return True

    return False

