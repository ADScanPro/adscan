"""Core utilities and base classes for ADScan.

This package provides foundational components like event system,
base services, shared utilities, enums, and decorators.
"""

from .events import (
    Event,
    EventType,
    EventBus,
    NullEventBus,
    ProgressEvent,
    VulnerabilityFoundEvent,
    CredentialFoundEvent,
)
from .enums import (
    AuthMode,
    Protocol,
    LicenseMode,
    ScanPhase,
    OperationType,
)
from .exceptions import (
    ADScanException,
    LicenseError,
    AuthenticationError,
    ProtocolError,
    ToolNotFoundError,
    DomainNotFoundError,
    ConfigurationError,
    ScanExecutionError,
)
from .decorators import (
    requires_auth,
    requires_tool,
    emits_event,
)

__all__ = [
    # Events
    "Event",
    "EventType",
    "EventBus",
    "NullEventBus",
    "ProgressEvent",
    "VulnerabilityFoundEvent",
    "CredentialFoundEvent",
    # Enums
    "AuthMode",
    "Protocol",
    "LicenseMode",
    "ScanPhase",
    "OperationType",
    # Exceptions
    "ADScanException",
    "LicenseError",
    "AuthenticationError",
    "ProtocolError",
    "ToolNotFoundError",
    "DomainNotFoundError",
    "ConfigurationError",
    "ScanExecutionError",
    # Decorators
    "requires_auth",
    "requires_tool",
    "emits_event",
]
