"""Domain model representing Active Directory domain state.

This module defines the Domain dataclass that maps to the domains_data dictionary
structure used throughout ADScan. It provides a strongly-typed interface for
domain information, authentication state, and discovered credentials.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum

from adscan_core.time_utils import utc_now


class AuthStatus(str, Enum):
    """Authentication status for a domain."""

    NONE = "none"  # No authentication attempted
    UNAUTH = "unauth"  # Unauthenticated enumeration only
    WITH_USERS = "with_users"  # Has valid user list
    AUTH = "auth"  # Authenticated with valid credentials
    PWNED = "pwned"  # Domain Administrator access achieved


@dataclass
class Domain:
    """Represents an Active Directory domain and its discovered state.

    This class maps to the domains_data dictionary structure in adscan.py
    and provides type-safe access to domain information.

    Attributes:
        name: Domain name (e.g., "example.local")
        pdc: Primary Domain Controller FQDN
        pdc_hostname: PDC hostname (short name)
        dc_ip: Domain Controller IP address
        base_dn: LDAP Base DN (e.g., "DC=example,DC=local")
        auth_status: Current authentication status
        username: Current authenticated username
        password: Current authenticated password
        hash: Current authenticated hash (NTLM)
        credentials: Dictionary of discovered credentials {username: password/hash}
        local_credentials: Nested dict of local credentials {host: {service: {user: password}}}
        kerberos_tickets: Dictionary of Kerberos tickets {username: ticket_path}
        trusts: List of discovered domain trusts
        users: List of discovered user accounts
        computers: List of discovered computer accounts
        dcs: List of discovered Domain Controllers
        shares: List of discovered SMB shares
        current_phase: Current scan phase (for web progress tracking)
        phase_progress: Progress within current phase (0.0 - 1.0)
        scan_metadata: Additional scan metadata
        created_at: When this domain was first discovered
        updated_at: When this domain was last updated
    """

    # Core identification
    name: str

    # Domain Controllers
    pdc: Optional[str] = None
    pdc_hostname: Optional[str] = None
    dc_ip: Optional[str] = None
    dcs: List[str] = field(default_factory=list)

    # LDAP
    base_dn: Optional[str] = None

    # Authentication state
    auth_status: AuthStatus = AuthStatus.NONE
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None  # NTLM hash

    # Discovered credentials
    credentials: Dict[str, str] = field(
        default_factory=dict
    )  # {username: password/hash}
    local_credentials: Dict[str, Dict[str, Dict[str, str]]] = field(
        default_factory=dict
    )  # {host: {service: {user: password}}}
    kerberos_tickets: Dict[str, str] = field(
        default_factory=dict
    )  # {username: ticket_path}
    auth_posture: Dict[str, Any] = field(default_factory=dict)

    # Discovered entities
    trusts: List[Dict[str, Any]] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    computers: List[str] = field(default_factory=list)
    shares: List[Dict[str, Any]] = field(default_factory=list)

    # Progress tracking (for web UI)
    current_phase: str = "initial"
    phase_progress: float = 0.0

    # Metadata
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert domain to dictionary (compatible with domains_data structure).

        Returns:
            Dictionary representation compatible with existing domains_data format
        """
        return {
            "pdc": self.pdc,
            "pdc_hostname": self.pdc_hostname,
            "dc_ip": self.dc_ip,
            "dcs": self.dcs,
            "base_dn": self.base_dn,
            "auth": self.auth_status.value,
            "username": self.username,
            "password": self.password,
            "hash": self.hash,
            "credentials": self.credentials,
            "local_credentials": self.local_credentials,
            "kerberos_tickets": self.kerberos_tickets,
            "auth_posture": self.auth_posture,
            "trusts": self.trusts,
            "users": self.users,
            "computers": self.computers,
            "shares": self.shares,
            "current_phase": self.current_phase,
            "phase_progress": self.phase_progress,
            "scan_metadata": self.scan_metadata,
        }

    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> "Domain":
        """Create Domain from dictionary (from domains_data structure).

        Args:
            name: Domain name
            data: Dictionary from domains_data

        Returns:
            Domain instance
        """
        # Parse auth status
        auth_str = data.get("auth", "none")
        try:
            auth_status = AuthStatus(auth_str)
        except ValueError:
            auth_status = AuthStatus.NONE

        return cls(
            name=name,
            pdc=data.get("pdc"),
            pdc_hostname=data.get("pdc_hostname"),
            dc_ip=data.get("dc_ip"),
            dcs=data.get("dcs", []),
            base_dn=data.get("base_dn"),
            auth_status=auth_status,
            username=data.get("username"),
            password=data.get("password"),
            hash=data.get("hash"),
            credentials=data.get("credentials", {}),
            local_credentials=data.get("local_credentials", {}),
            kerberos_tickets=data.get("kerberos_tickets", {}),
            auth_posture=data.get("auth_posture", {}),
            trusts=data.get("trusts", []),
            users=data.get("users", []),
            computers=data.get("computers", []),
            shares=data.get("shares", []),
            current_phase=data.get("current_phase", "initial"),
            phase_progress=data.get("phase_progress", 0.0),
            scan_metadata=data.get("scan_metadata", {}),
        )

    def is_authenticated(self) -> bool:
        """Check if domain has valid authentication.

        Returns:
            True if authenticated or pwned
        """
        return self.auth_status in [AuthStatus.AUTH, AuthStatus.PWNED]

    def is_pwned(self) -> bool:
        """Check if domain is fully compromised (DA access).

        Returns:
            True if pwned status
        """
        return self.auth_status == AuthStatus.PWNED

    def add_credential(self, username: str, credential: str) -> None:
        """Add a discovered credential to the domain.

        Args:
            username: Username
            credential: Password or hash
        """
        self.credentials[username] = credential
        self.updated_at = utc_now()

    def add_local_credential(
        self, host: str, service: str, username: str, credential: str
    ) -> None:
        """Add a local credential for a specific host/service.

        Args:
            host: Hostname or IP
            service: Service name (e.g., "smb", "wmi")
            username: Local username
            credential: Password or hash
        """
        if host not in self.local_credentials:
            self.local_credentials[host] = {}
        if service not in self.local_credentials[host]:
            self.local_credentials[host][service] = {}
        self.local_credentials[host][service][username] = credential
        self.updated_at = utc_now()

    def update_progress(self, phase: str, progress: float) -> None:
        """Update scan progress.

        Args:
            phase: Current phase name
            progress: Progress within phase (0.0 - 1.0)
        """
        self.current_phase = phase
        self.phase_progress = max(0.0, min(1.0, progress))  # Clamp to [0, 1]
        self.updated_at = utc_now()
