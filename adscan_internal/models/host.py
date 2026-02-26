"""Host and Domain Controller models.

This module defines models for representing hosts, Domain Controllers,
and their associated information discovered during scans.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class HostType(str, Enum):
    """Type of host."""

    DOMAIN_CONTROLLER = "domain_controller"  # Domain Controller
    MEMBER_SERVER = "member_server"  # Member server
    WORKSTATION = "workstation"  # Workstation/client
    UNKNOWN = "unknown"  # Unknown type


class HostOS(str, Enum):
    """Operating system family."""

    WINDOWS_SERVER = "windows_server"
    WINDOWS_CLIENT = "windows_client"
    LINUX = "linux"
    UNKNOWN = "unknown"


@dataclass
class Host:
    """Represents a discovered host in the network.

    Attributes:
        hostname: Hostname (FQDN or NetBIOS name)
        ip_address: IP address
        host_type: Type of host
        os: Operating system
        os_version: Detailed OS version
        domain: Domain this host belongs to
        is_dc: Whether this is a Domain Controller
        is_online: Whether host is currently online
        smb_signing: Whether SMB signing is enabled
        ldap_signing: Whether LDAP signing is enabled
        shares: List of discovered SMB shares
        services: List of discovered services
        vulnerabilities: List of vulnerability IDs affecting this host
        discovered_at: When host was discovered
        last_seen: When host was last seen online
        metadata: Additional metadata
    """

    hostname: str
    ip_address: str

    # Type and OS
    host_type: HostType = HostType.UNKNOWN
    os: HostOS = HostOS.UNKNOWN
    os_version: Optional[str] = None

    # Domain membership
    domain: Optional[str] = None
    is_dc: bool = False

    # Status
    is_online: bool = True
    last_seen: datetime = field(default_factory=datetime.utcnow)

    # Security configuration
    smb_signing: Optional[bool] = None
    ldap_signing: Optional[bool] = None

    # Discovered information
    shares: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)  # Vulnerability IDs

    # Timestamps
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert host to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "host_type": self.host_type.value,
            "os": self.os.value,
            "os_version": self.os_version,
            "domain": self.domain,
            "is_dc": self.is_dc,
            "is_online": self.is_online,
            "last_seen": self.last_seen.isoformat(),
            "smb_signing": self.smb_signing,
            "ldap_signing": self.ldap_signing,
            "shares": self.shares,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "discovered_at": self.discovered_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Host":
        """Create host from dictionary.

        Args:
            data: Host dictionary

        Returns:
            Host instance
        """
        host_type = HostType(data.get("host_type", "unknown"))
        os = HostOS(data.get("os", "unknown"))

        return cls(
            hostname=data["hostname"],
            ip_address=data["ip_address"],
            host_type=host_type,
            os=os,
            os_version=data.get("os_version"),
            domain=data.get("domain"),
            is_dc=data.get("is_dc", False),
            is_online=data.get("is_online", True),
            last_seen=datetime.fromisoformat(data["last_seen"])
            if "last_seen" in data
            else datetime.utcnow(),
            smb_signing=data.get("smb_signing"),
            ldap_signing=data.get("ldap_signing"),
            shares=data.get("shares", []),
            services=data.get("services", []),
            vulnerabilities=data.get("vulnerabilities", []),
            discovered_at=datetime.fromisoformat(data["discovered_at"])
            if "discovered_at" in data
            else datetime.utcnow(),
            metadata=data.get("metadata", {}),
        )

    def add_share(
        self, share_name: str, permissions: List[str], accessible: bool = True
    ) -> None:
        """Add a discovered share.

        Args:
            share_name: Name of the share
            permissions: List of permissions
            accessible: Whether share is accessible
        """
        self.shares.append(
            {
                "name": share_name,
                "permissions": permissions,
                "accessible": accessible,
                "discovered_at": datetime.utcnow().isoformat(),
            }
        )

    def add_service(self, service_name: str, port: int, protocol: str = "tcp") -> None:
        """Add a discovered service.

        Args:
            service_name: Service name
            port: Port number
            protocol: Protocol (tcp/udp)
        """
        self.services.append(
            {
                "name": service_name,
                "port": port,
                "protocol": protocol,
                "discovered_at": datetime.utcnow().isoformat(),
            }
        )

    def add_vulnerability(self, vulnerability_id: str) -> None:
        """Add a vulnerability ID affecting this host.

        Args:
            vulnerability_id: Vulnerability ID
        """
        if vulnerability_id not in self.vulnerabilities:
            self.vulnerabilities.append(vulnerability_id)

    @property
    def display_name(self) -> str:
        """Get display name for host.

        Returns:
            Formatted display name
        """
        return f"{self.hostname} ({self.ip_address})"


@dataclass
class DomainController(Host):
    """Represents a Domain Controller (specialized Host).

    Attributes (in addition to Host):
        is_pdc: Whether this is the Primary Domain Controller
        is_global_catalog: Whether this is a Global Catalog server
        site: Active Directory site
        roles: FSMO roles held by this DC
    """

    is_pdc: bool = False
    is_global_catalog: bool = False
    site: Optional[str] = None
    roles: List[str] = field(default_factory=list)  # FSMO roles

    def __post_init__(self):
        """Ensure host_type is set to DOMAIN_CONTROLLER."""
        self.host_type = HostType.DOMAIN_CONTROLLER
        self.is_dc = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert DC to dictionary.

        Returns:
            Dictionary representation
        """
        data = super().to_dict()
        data.update(
            {
                "is_pdc": self.is_pdc,
                "is_global_catalog": self.is_global_catalog,
                "site": self.site,
                "roles": self.roles,
            }
        )
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DomainController":
        """Create DomainController from dictionary.

        Args:
            data: DC dictionary

        Returns:
            DomainController instance
        """
        # Use Host.from_dict to get base attributes
        host = Host.from_dict(data)

        return cls(
            hostname=host.hostname,
            ip_address=host.ip_address,
            host_type=HostType.DOMAIN_CONTROLLER,
            os=host.os,
            os_version=host.os_version,
            domain=host.domain,
            is_dc=True,
            is_online=host.is_online,
            last_seen=host.last_seen,
            smb_signing=host.smb_signing,
            ldap_signing=host.ldap_signing,
            shares=host.shares,
            services=host.services,
            vulnerabilities=host.vulnerabilities,
            discovered_at=host.discovered_at,
            metadata=host.metadata,
            is_pdc=data.get("is_pdc", False),
            is_global_catalog=data.get("is_global_catalog", False),
            site=data.get("site"),
            roles=data.get("roles", []),
        )

    def add_role(self, role: str) -> None:
        """Add an FSMO role to this DC.

        Args:
            role: FSMO role name
        """
        if role not in self.roles:
            self.roles.append(role)


@dataclass
class SMBShare:
    """Represents an SMB share discovered on a host.

    Attributes:
        host: Hostname or IP where share is located
        share_name: Share name (e.g., "C$", "SYSVOL")
        permissions: List of permissions (READ, WRITE, etc.)
        accessible: Whether share is currently accessible
        interesting_files: List of interesting files found in share
        discovered_at: When share was discovered
        metadata: Additional metadata
    """

    host: str
    share_name: str
    permissions: List[str] = field(default_factory=list)
    accessible: bool = True

    # Discovery results
    interesting_files: List[str] = field(default_factory=list)

    # Timestamp
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert share to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "host": self.host,
            "share_name": self.share_name,
            "permissions": self.permissions,
            "accessible": self.accessible,
            "interesting_files": self.interesting_files,
            "discovered_at": self.discovered_at.isoformat(),
            "metadata": self.metadata,
        }

    @property
    def is_writable(self) -> bool:
        """Check if share is writable.

        Returns:
            True if WRITE permission exists
        """
        return "WRITE" in self.permissions or "FULL" in self.permissions

    @property
    def display_name(self) -> str:
        """Get display name for share.

        Returns:
            Formatted display name
        """
        return f"\\\\{self.host}\\{self.share_name}"
