"""Scan orchestration service.

This module defines the high-level orchestration service that coordinates
service-layer components into a full scan workflow suitable for a future web UX.

Important design goals:
- Keep orchestration logic independent from CLI UI concerns (Prompts, Panels).
- Emit progress events through the shared EventBus.
- Allow incremental migration: orchestration can call into new services while
  legacy CLI code still exists in ``adscan.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import logging

from adscan_core.time_utils import utc_now
from adscan_internal.core import EventBus, LicenseMode, ScanPhase
from adscan_internal.models.scan import (
    ScanConfiguration,
    ScanMode,
    ScanResult,
    ScanStatus,
    ScanType,
)
from adscan_internal.services.base_service import BaseService
from adscan_internal.services.credential_service import CredentialService
from adscan_internal.services.domain_service import DomainService
from adscan_internal.services.enumeration import EnumerationService
from adscan_internal.services.exploitation import ExploitationService


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OrchestrationServices:
    """Container for service dependencies used by orchestration."""

    domain: DomainService
    credentials: CredentialService
    enumeration: EnumerationService
    exploitation: ExploitationService


class ScanOrchestrationService(BaseService):
    """Coordinate a scan workflow using the service layer."""

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        license_mode: LicenseMode = LicenseMode.PRO,
    ):
        """Initialize orchestration service.

        Args:
            event_bus: Event bus for progress tracking.
            license_mode: License mode for composed services.
        """
        super().__init__(event_bus=event_bus, license_mode=license_mode)
        self.services = self._build_services(
            event_bus=self.event_bus, license_mode=license_mode
        )

    @staticmethod
    def _build_services(
        *,
        event_bus: EventBus,
        license_mode: LicenseMode,
    ) -> OrchestrationServices:
        """Create default service instances for orchestration."""
        return OrchestrationServices(
            domain=DomainService(event_bus=event_bus, license_mode=license_mode),
            credentials=CredentialService(
                event_bus=event_bus, license_mode=license_mode
            ),
            enumeration=EnumerationService(
                event_bus=event_bus, license_mode=license_mode
            ),
            exploitation=ExploitationService(
                event_bus=event_bus, license_mode=license_mode
            ),
        )

    def run(self, configuration: ScanConfiguration) -> ScanResult:
        """Run a scan workflow.

        This is an orchestration skeleton intended for the web UX backend. It
        currently performs phase bookkeeping and emits events, but does not
        yet execute the full scan logic present in ``adscan.py``.

        Args:
            configuration: Scan configuration.

        Returns:
            ScanResult with status and timestamps.
        """
        scan_id = configuration.options.get("scan_id")
        started_at = utc_now()

        self._emit_progress(
            scan_id=scan_id,
            phase=ScanPhase.INITIAL.value,
            progress=0.0,
            message="Scan orchestration started",
        )

        try:
            # Placeholder for future: DNS check, enumeration, exploitation, reporting.
            self._emit_progress(
                scan_id=scan_id,
                phase=ScanPhase.COMPLETED.value,
                progress=1.0,
                message="Scan orchestration completed (skeleton)",
            )
            return ScanResult(
                scan_id=str(scan_id) if scan_id is not None else "unknown",
                configuration=configuration,
                status=ScanStatus.COMPLETED,
                started_at=started_at,
                completed_at=utc_now(),
            )
        except Exception as exc:
            self.logger.exception("Scan orchestration failed", exc_info=True)
            self._emit_progress(
                scan_id=scan_id,
                phase=ScanPhase.FAILED.value,
                progress=1.0,
                message="Scan orchestration failed",
            )
            return ScanResult(
                scan_id=str(scan_id) if scan_id is not None else "unknown",
                configuration=configuration,
                status=ScanStatus.FAILED,
                error_message=str(exc),
                started_at=started_at,
                completed_at=utc_now(),
            )

    # ------------------------------------------------------------------ #
    # High-level orchestration helpers
    # ------------------------------------------------------------------ #

    def execute_auth_scan(
        self,
        domain: str,
        pdc: str,
        username: str,
        password: str,
        *,
        scan_id: Optional[str] = None,
        interface: str = "eth0",
        auto_mode: bool = True,
    ) -> ScanResult:
        """Execute authenticated enumeration scan.

        This is a thin orchestration helper that builds a :class:`ScanConfiguration`
        for an authenticated scan and delegates to :meth:`run`. The current
        implementation focuses on progress/event plumbing; the detailed
        enumeration and exploitation steps are still handled by the legacy CLI
        code in ``adscan.py``.
        """
        configuration = ScanConfiguration(
            scan_type=ScanType.AUTH,
            scan_mode=ScanMode.AUDIT,
            domain=domain,
            dc_ip=pdc,
            username=username,
            password=password,
            interface=interface,
            hosts=[],
            auto_mode=auto_mode,
            license_mode=self.license_mode.value,
            options={"scan_id": scan_id} if scan_id is not None else {},
        )
        return self.run(configuration)

    def execute_unauth_scan(
        self,
        domain: str,
        pdc: str,
        *,
        scan_id: Optional[str] = None,
        interface: str = "eth0",
        hosts: Optional[list[str]] = None,
        auto_mode: bool = True,
    ) -> ScanResult:
        """Execute unauthenticated scan.

        This prepares a basic :class:`ScanConfiguration` for unauthenticated
        enumeration and then delegates to :meth:`run`. As with
        :meth:`execute_auth_scan`, the heavy lifting is still performed by the
        legacy CLI for now.
        """
        configuration = ScanConfiguration(
            scan_type=ScanType.UNAUTH,
            scan_mode=ScanMode.AUDIT,
            domain=domain,
            dc_ip=pdc,
            interface=interface,
            hosts=list(hosts or []),
            auto_mode=auto_mode,
            license_mode=self.license_mode.value,
            options={"scan_id": scan_id} if scan_id is not None else {},
        )
        return self.run(configuration)
