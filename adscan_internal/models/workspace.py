"""Workspace models for project and session management.

This module defines models for managing ADScan workspaces, which organize
scans, domains, and results for different projects or engagements.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
import uuid


class WorkspaceType(str, Enum):
    """Type of workspace."""

    CTF = "ctf"  # Capture the Flag challenge
    AUDIT = "audit"  # Security audit/assessment
    PENTEST = "pentest"  # Penetration testing engagement
    RED_TEAM = "red_team"  # Red team operation
    TRAINING = "training"  # Training/demo environment


@dataclass
class Workspace:
    """Represents an ADScan workspace/project.

    A workspace organizes all data for a specific engagement, including
    domains, scans, credentials, and findings.

    Attributes:
        id: Unique workspace identifier
        name: Workspace name
        description: Workspace description
        workspace_type: Type of workspace
        client_name: Client name (for professional engagements)
        domains: List of domain names in this workspace
        active_scan_id: Currently active scan ID
        settings: Workspace-specific settings
        neo4j_config: Neo4j/BloodHound configuration
        created_at: When workspace was created
        updated_at: Last update timestamp
        metadata: Additional metadata
    """

    name: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""
    workspace_type: WorkspaceType = WorkspaceType.AUDIT
    client_name: Optional[str] = None

    # Domain tracking
    domains: List[str] = field(default_factory=list)
    active_scan_id: Optional[str] = None

    # Settings
    settings: Dict[str, Any] = field(default_factory=dict)
    neo4j_config: Dict[str, str] = field(
        default_factory=lambda: {
            "host": "localhost",
            "port": "7687",
            "db_user": "neo4j",
            "db_password": "neo4j",
        }
    )

    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert workspace to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "workspace_type": self.workspace_type.value,
            "client_name": self.client_name,
            "domains": self.domains,
            "active_scan_id": self.active_scan_id,
            "settings": self.settings,
            "neo4j_config": self.neo4j_config,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Workspace":
        """Create workspace from dictionary.

        Args:
            data: Workspace dictionary

        Returns:
            Workspace instance
        """
        workspace_type = WorkspaceType(data.get("workspace_type", "audit"))

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data["name"],
            description=data.get("description", ""),
            workspace_type=workspace_type,
            client_name=data.get("client_name"),
            domains=data.get("domains", []),
            active_scan_id=data.get("active_scan_id"),
            settings=data.get("settings", {}),
            neo4j_config=data.get(
                "neo4j_config",
                {
                    "host": "localhost",
                    "port": "7687",
                    "db_user": "neo4j",
                    "db_password": "neo4j",
                },
            ),
            created_at=datetime.fromisoformat(data["created_at"])
            if "created_at" in data
            else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data["updated_at"])
            if "updated_at" in data
            else datetime.utcnow(),
            metadata=data.get("metadata", {}),
        )

    def add_domain(self, domain_name: str) -> None:
        """Add a domain to this workspace.

        Args:
            domain_name: Domain name to add
        """
        if domain_name not in self.domains:
            self.domains.append(domain_name)
            self.updated_at = datetime.utcnow()

    def remove_domain(self, domain_name: str) -> None:
        """Remove a domain from this workspace.

        Args:
            domain_name: Domain name to remove
        """
        if domain_name in self.domains:
            self.domains.remove(domain_name)
            self.updated_at = datetime.utcnow()

    def update_setting(self, key: str, value: Any) -> None:
        """Update a workspace setting.

        Args:
            key: Setting key
            value: Setting value
        """
        self.settings[key] = value
        self.updated_at = datetime.utcnow()

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a workspace setting.

        Args:
            key: Setting key
            default: Default value if key not found

        Returns:
            Setting value or default
        """
        return self.settings.get(key, default)

    @property
    def display_name(self) -> str:
        """Get display name for workspace.

        Returns:
            Formatted display name with client if available
        """
        if self.client_name:
            return f"{self.name} ({self.client_name})"
        return self.name


@dataclass
class WorkspaceStatistics:
    """Statistics for a workspace.

    Attributes:
        workspace_id: Workspace ID
        total_scans: Total number of scans
        active_scans: Number of currently running scans
        completed_scans: Number of completed scans
        total_domains: Number of domains
        total_hosts: Number of discovered hosts
        total_credentials: Number of discovered credentials
        total_vulnerabilities: Number of vulnerabilities found
        vulnerabilities_by_severity: Breakdown by severity
        last_scan_date: Date of most recent scan
        computed_at: When statistics were computed
    """

    workspace_id: str
    total_scans: int = 0
    active_scans: int = 0
    completed_scans: int = 0
    total_domains: int = 0
    total_hosts: int = 0
    total_credentials: int = 0
    total_vulnerabilities: int = 0
    vulnerabilities_by_severity: Dict[str, int] = field(default_factory=dict)
    last_scan_date: Optional[datetime] = None
    computed_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "workspace_id": self.workspace_id,
            "total_scans": self.total_scans,
            "active_scans": self.active_scans,
            "completed_scans": self.completed_scans,
            "total_domains": self.total_domains,
            "total_hosts": self.total_hosts,
            "total_credentials": self.total_credentials,
            "total_vulnerabilities": self.total_vulnerabilities,
            "vulnerabilities_by_severity": self.vulnerabilities_by_severity,
            "last_scan_date": self.last_scan_date.isoformat()
            if self.last_scan_date
            else None,
            "computed_at": self.computed_at.isoformat(),
        }

    @property
    def critical_vulnerabilities(self) -> int:
        """Get count of critical vulnerabilities.

        Returns:
            Number of CRITICAL vulnerabilities
        """
        return self.vulnerabilities_by_severity.get("CRITICAL", 0)

    @property
    def high_vulnerabilities(self) -> int:
        """Get count of high vulnerabilities.

        Returns:
            Number of HIGH vulnerabilities
        """
        return self.vulnerabilities_by_severity.get("HIGH", 0)

    @property
    def critical_and_high(self) -> int:
        """Get combined count of critical and high vulnerabilities.

        Returns:
            Number of CRITICAL + HIGH vulnerabilities
        """
        return self.critical_vulnerabilities + self.high_vulnerabilities
