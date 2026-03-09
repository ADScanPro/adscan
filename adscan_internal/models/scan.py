"""Scan models for scan configuration and execution tracking.

This module defines models for configuring and tracking ADScan scan executions,
including scan type, mode, status, and results.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
import uuid

from adscan_core.time_utils import monotonic_now, utc_now


class ScanType(str, Enum):
    """Type of scan being performed."""

    AUTH = "auth"  # Authenticated scan with credentials
    UNAUTH = "unauth"  # Unauthenticated enumeration only


class ScanMode(str, Enum):
    """Scan mode determines behavior and automation level."""

    CTF = "ctf"  # CTF mode - optimized for capture the flag challenges
    AUDIT = "audit"  # Audit mode - comprehensive security assessment
    CI = "ci"  # Continuous Integration - fully automated, no prompts


class ScanStatus(str, Enum):
    """Current status of a scan execution."""

    PENDING = "pending"  # Scan queued but not started
    RUNNING = "running"  # Scan actively executing
    COMPLETED = "completed"  # Scan finished successfully
    FAILED = "failed"  # Scan encountered errors
    CANCELLED = "cancelled"  # Scan was cancelled by user


@dataclass
class ScanConfiguration:
    """Configuration for a scan execution.

    Attributes:
        scan_type: Type of scan (auth/unauth)
        scan_mode: Mode of operation (ctf/audit/ci)
        domain: Target domain name
        dc_ip: Domain Controller IP address
        username: Username for authenticated scans
        password: Password for authenticated scans
        hash: NTLM hash for authenticated scans (alternative to password)
        interface: Network interface to use
        hosts: List of target hosts for unauthenticated scans
        auto_mode: Enable automatic operation (no prompts)
        license_mode: License mode (LITE/FULL)
        options: Additional scan options
    """

    scan_type: ScanType
    scan_mode: ScanMode
    domain: str

    # Authentication (for auth scans)
    dc_ip: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None

    # Network configuration
    interface: str = "eth0"
    hosts: List[str] = field(default_factory=list)

    # Scan behavior
    auto_mode: bool = True
    license_mode: str = "LITE"

    # Additional options
    options: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "scan_type": self.scan_type.value,
            "scan_mode": self.scan_mode.value,
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "username": self.username,
            "password": self.password,  # Note: This should be encrypted before storage
            "hash": self.hash,
            "interface": self.interface,
            "hosts": self.hosts,
            "auto_mode": self.auto_mode,
            "license_mode": self.license_mode,
            "options": self.options,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanConfiguration":
        """Create configuration from dictionary.

        Args:
            data: Configuration dictionary

        Returns:
            ScanConfiguration instance
        """
        scan_type = ScanType(data.get("scan_type", "auth"))
        scan_mode = ScanMode(data.get("scan_mode", "audit"))

        return cls(
            scan_type=scan_type,
            scan_mode=scan_mode,
            domain=data["domain"],
            dc_ip=data.get("dc_ip"),
            username=data.get("username"),
            password=data.get("password"),
            hash=data.get("hash"),
            interface=data.get("interface", "eth0"),
            hosts=data.get("hosts", []),
            auto_mode=data.get("auto_mode", True),
            license_mode=data.get("license_mode", "LITE"),
            options=data.get("options", {}),
        )


@dataclass
class ScanResult:
    """Results from a completed scan execution.

    Attributes:
        scan_id: Unique scan identifier
        configuration: Scan configuration used
        status: Final scan status
        domains_data: Dictionary of domain states (from PentestShell.domains_data)
        vulnerabilities: List of discovered vulnerabilities
        statistics: Scan statistics (hosts discovered, credentials found, etc.)
        error_message: Error message if scan failed
        started_at: Scan start timestamp
        completed_at: Scan completion timestamp
    """

    scan_id: str
    configuration: ScanConfiguration
    status: ScanStatus

    # Results
    domains_data: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)

    # Error tracking
    error_message: Optional[str] = None

    # Timestamps
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "scan_id": self.scan_id,
            "configuration": self.configuration.to_dict(),
            "status": self.status.value,
            "domains_data": self.domains_data,
            "vulnerabilities": self.vulnerabilities,
            "statistics": self.statistics,
            "error_message": self.error_message,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
        }

    @property
    def duration(self) -> Optional[float]:
        """Calculate scan duration in seconds.

        Returns:
            Duration in seconds, or None if not completed
        """
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def is_successful(self) -> bool:
        """Check if scan completed successfully.

        Returns:
            True if status is COMPLETED
        """
        return self.status == ScanStatus.COMPLETED


@dataclass
class Scan:
    """Represents a scan execution instance.

    Combines configuration, status tracking, and results into a single entity
    for web UI and database persistence.

    Attributes:
        id: Unique scan identifier (UUID)
        workspace_id: Workspace this scan belongs to
        configuration: Scan configuration
        status: Current scan status
        current_phase: Current execution phase
        progress_percentage: Overall progress (0-100)
        domains_data: Current domain states
        vulnerabilities: Discovered vulnerabilities
        statistics: Current statistics
        error_message: Error message if failed
        created_at: When scan was created
        started_at: When scan started executing
        completed_at: When scan completed
        updated_at: Last update timestamp
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    workspace_id: Optional[str] = None
    configuration: ScanConfiguration = field(
        default_factory=lambda: ScanConfiguration(
            scan_type=ScanType.AUTH,
            scan_mode=ScanMode.AUDIT,
            domain="",
        )
    )
    status: ScanStatus = ScanStatus.PENDING

    # Progress tracking
    current_phase: str = "initial"
    progress_percentage: int = 0  # 0-100

    # Results
    domains_data: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)

    # Error tracking
    error_message: Optional[str] = None

    # Timestamps
    created_at: datetime = field(default_factory=utc_now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    updated_at: datetime = field(default_factory=utc_now)
    _started_monotonic: Optional[float] = field(
        default=None, init=False, repr=False, compare=False
    )
    _completed_monotonic: Optional[float] = field(
        default=None, init=False, repr=False, compare=False
    )

    def start(self) -> None:
        """Mark scan as started."""
        self.status = ScanStatus.RUNNING
        self.started_at = utc_now()
        self.updated_at = utc_now()
        self._started_monotonic = monotonic_now()
        self._completed_monotonic = None

    def complete(self) -> None:
        """Mark scan as completed successfully."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = utc_now()
        self.progress_percentage = 100
        self.updated_at = utc_now()
        self._completed_monotonic = monotonic_now()

    def fail(self, error_message: str) -> None:
        """Mark scan as failed.

        Args:
            error_message: Description of the failure
        """
        self.status = ScanStatus.FAILED
        self.error_message = error_message
        self.completed_at = utc_now()
        self.updated_at = utc_now()
        self._completed_monotonic = monotonic_now()

    def cancel(self) -> None:
        """Mark scan as cancelled."""
        self.status = ScanStatus.CANCELLED
        self.completed_at = utc_now()
        self.updated_at = utc_now()
        self._completed_monotonic = monotonic_now()

    def update_progress(self, phase: str, percentage: int) -> None:
        """Update scan progress.

        Args:
            phase: Current phase name
            percentage: Progress percentage (0-100)
        """
        self.current_phase = phase
        self.progress_percentage = max(0, min(100, percentage))  # Clamp to [0, 100]
        self.updated_at = utc_now()

    def to_result(self) -> ScanResult:
        """Convert to ScanResult.

        Returns:
            ScanResult instance
        """
        return ScanResult(
            scan_id=self.id,
            configuration=self.configuration,
            status=self.status,
            domains_data=self.domains_data,
            vulnerabilities=self.vulnerabilities,
            statistics=self.statistics,
            error_message=self.error_message,
            started_at=self.started_at,
            completed_at=self.completed_at,
        )

    @property
    def duration(self) -> Optional[float]:
        """Calculate scan duration in seconds.

        Returns:
            Duration in seconds, or None if not started or completed
        """
        if (
            self._started_monotonic is not None
            and self._completed_monotonic is not None
        ):
            return self._completed_monotonic - self._started_monotonic
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def is_running(self) -> bool:
        """Check if scan is currently running.

        Returns:
            True if status is RUNNING
        """
        return self.status == ScanStatus.RUNNING

    @property
    def is_finished(self) -> bool:
        """Check if scan has finished (completed, failed, or cancelled).

        Returns:
            True if scan is in a terminal state
        """
        return self.status in [
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED,
        ]
