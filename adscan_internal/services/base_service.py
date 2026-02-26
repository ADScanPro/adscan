"""Base service class for all ADScan services.

This module provides the foundation for service layer components,
including event emission, logging, license management, and common utilities.
"""

from typing import Optional
import logging
from adscan_internal.core import (
    EventBus,
    NullEventBus,
    ProgressEvent,
    Event,
    LicenseMode,
)


class BaseService:
    """Base class for all ADScan services.

    Provides common functionality:
    - Event emission for progress tracking
    - Logging configuration
    - License mode awareness
    - Shared utilities

    Services should inherit from this class and implement specific
    domain operations (enumeration, credential verification, etc.)
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        license_mode: LicenseMode = LicenseMode.PRO,
    ):
        """Initialize service.

        Args:
            event_bus: Event bus for emitting progress events.
                       If None, uses NullEventBus (no-op for CLI standalone).
            license_mode: License mode (LITE or PRO). Defaults to PRO.
        """
        self.event_bus = event_bus or NullEventBus()
        self.license_mode = license_mode
        self.logger = logging.getLogger(self.__class__.__name__)

        # Log license mode on initialization
        self.logger.debug(
            f"{self.__class__.__name__} initialized with {license_mode.value} license"
        )

    def _emit_progress(
        self,
        scan_id: Optional[str],
        phase: str,
        progress: float,
        message: str,
        current_step: Optional[int] = None,
        total_steps: Optional[int] = None,
    ) -> None:
        """Emit progress event.

        Args:
            scan_id: Scan ID this progress belongs to
            phase: Phase name (e.g., 'trust_enumeration')
            progress: Progress percentage (0.0 - 1.0)
            message: Human-readable progress message
            current_step: Current step number (optional)
            total_steps: Total steps in phase (optional)
        """
        event = ProgressEvent(
            scan_id=scan_id,
            phase=phase,
            progress=progress,
            message=message,
            current_step=current_step,
            total_steps=total_steps,
        )
        self.event_bus.emit(event)
        self.logger.debug(f"Progress: {phase} - {progress:.1%} - {message}")

    def _emit_event(self, event: Event) -> None:
        """Emit custom event.

        Args:
            event: Event to emit
        """
        self.event_bus.emit(event)
        self.logger.debug(f"Event emitted: {event.event_type.value}")

    def _log_and_emit(
        self,
        scan_id: Optional[str],
        phase: str,
        progress: float,
        message: str,
        log_level: str = "info",
    ) -> None:
        """Log message and emit progress event.

        Convenience method for common pattern of logging + emitting.

        Args:
            scan_id: Scan ID
            phase: Phase name
            progress: Progress (0.0 - 1.0)
            message: Message to log and emit
            log_level: Logging level (info, debug, warning, error)
        """
        # Log
        log_method = getattr(self.logger, log_level, self.logger.info)
        log_method(message)

        # Emit
        self._emit_progress(
            scan_id=scan_id,
            phase=phase,
            progress=progress,
            message=message,
        )
