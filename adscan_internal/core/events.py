"""Event system for real-time progress updates.

This module provides an event-driven architecture for tracking scan progress,
vulnerability discoveries, and other important events during ADScan execution.

Events can be consumed by:
- Web UI (via WebSocket for real-time updates)
- CLI (for verbose/debug output)
- Database (for audit logging)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Type of event."""

    PROGRESS = "progress"
    VULNERABILITY_FOUND = "vulnerability_found"
    CREDENTIAL_FOUND = "credential_found"
    HOST_DISCOVERED = "host_discovered"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    PHASE_STARTED = "phase_started"
    PHASE_COMPLETED = "phase_completed"


@dataclass
class Event:
    """Base event class.

    Attributes:
        event_type: Type of event
        scan_id: Scan ID this event belongs to
        timestamp: When event occurred
        metadata: Additional event-specific data
    """

    event_type: EventType = EventType.PROGRESS  # Default, overridden by subclasses
    scan_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "event_type": self.event_type.value,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ProgressEvent(Event):
    """Progress update event.

    Attributes:
        phase: Current phase name (e.g., 'dns_check', 'enumeration')
        progress: Progress percentage (0.0 - 1.0)
        message: Human-readable progress message
        current_step: Current step number (optional)
        total_steps: Total steps in phase (optional)
    """

    phase: str = ""
    progress: float = 0.0
    message: str = ""
    current_step: Optional[int] = None
    total_steps: Optional[int] = None

    def __post_init__(self):
        """Set event type to PROGRESS."""
        self.event_type = EventType.PROGRESS

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = super().to_dict()
        data.update(
            {
                "phase": self.phase,
                "progress": self.progress,
                "message": self.message,
                "current_step": self.current_step,
                "total_steps": self.total_steps,
            }
        )
        return data


@dataclass
class VulnerabilityFoundEvent(Event):
    """Vulnerability discovered event.

    Attributes:
        vulnerability_id: Vulnerability unique ID
        vulnerability_type: Type/category of vulnerability
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        domain: Domain where vulnerability was found
        affected_entities: List of affected entities
        details: Additional vulnerability details
    """

    vulnerability_id: str = ""
    vulnerability_type: str = ""
    severity: str = ""
    domain: str = ""
    affected_entities: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Set event type to VULNERABILITY_FOUND."""
        self.event_type = EventType.VULNERABILITY_FOUND

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = super().to_dict()
        data.update(
            {
                "vulnerability_id": self.vulnerability_id,
                "vulnerability_type": self.vulnerability_type,
                "severity": self.severity,
                "domain": self.domain,
                "affected_entities": self.affected_entities,
                "details": self.details,
            }
        )
        return data


@dataclass
class CredentialFoundEvent(Event):
    """Credential discovered event.

    Attributes:
        credential_type: Type of credential (password, hash, ticket)
        username: Username/account
        domain: Domain
        source: How credential was discovered
        is_admin: Whether this is an admin account
    """

    credential_type: str = ""
    username: str = ""
    domain: str = ""
    source: str = ""
    is_admin: bool = False

    def __post_init__(self):
        """Set event type to CREDENTIAL_FOUND."""
        self.event_type = EventType.CREDENTIAL_FOUND

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = super().to_dict()
        data.update(
            {
                "credential_type": self.credential_type,
                "username": self.username,
                "domain": self.domain,
                "source": self.source,
                "is_admin": self.is_admin,
            }
        )
        return data


class EventBus:
    """Event bus for publishing and subscribing to events.

    This is a simple in-memory event bus. For web mode, events are also
    published to Redis for WebSocket distribution.
    """

    def __init__(self):
        """Initialize event bus."""
        self._subscribers: Dict[EventType, List[Callable]] = {}
        self._all_subscribers: List[Callable] = []

    def subscribe(
        self, event_type: EventType, handler: Callable[[Event], None]
    ) -> None:
        """Subscribe to specific event type.

        Args:
            event_type: Type of event to subscribe to
            handler: Callback function to handle events
        """
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)
        logger.debug(f"Subscribed handler to {event_type.value} events")

    def subscribe_all(self, handler: Callable[[Event], None]) -> None:
        """Subscribe to all events.

        Args:
            handler: Callback function to handle all events
        """
        self._all_subscribers.append(handler)
        logger.debug("Subscribed handler to all events")

    def emit(self, event: Event) -> None:
        """Emit an event to all subscribers.

        Args:
            event: Event to emit
        """
        # Log event for debugging
        logger.debug(f"Event emitted: {event.event_type.value} - {event.to_dict()}")

        # Call specific subscribers
        if event.event_type in self._subscribers:
            for handler in self._subscribers[event.event_type]:
                try:
                    handler(event)
                except Exception as e:
                    logger.exception(f"Error in event handler: {e}")

        # Call all-event subscribers
        for handler in self._all_subscribers:
            try:
                handler(event)
            except Exception as e:
                logger.exception(f"Error in all-event handler: {e}")


class NullEventBus:
    """Null object pattern for EventBus.

    Used in CLI standalone mode where events are not needed.
    All methods are no-ops.
    """

    def subscribe(
        self, event_type: EventType, handler: Callable[[Event], None]
    ) -> None:
        """No-op subscribe."""
        pass

    def subscribe_all(self, handler: Callable[[Event], None]) -> None:
        """No-op subscribe all."""
        pass

    def emit(self, event: Event) -> None:
        """No-op emit."""
        pass
