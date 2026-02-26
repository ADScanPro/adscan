"""Credential models for authentication and discovered secrets.

This module defines models for managing credentials discovered during scans,
including domain credentials, local credentials, and Kerberos tickets.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from enum import Enum


class CredentialType(str, Enum):
    """Type of credential."""

    PASSWORD = "password"  # Plaintext password
    NTLM_HASH = "ntlm_hash"  # NTLM hash
    KERBEROS_TICKET = "kerberos_ticket"  # Kerberos TGT/TGS
    CCACHE = "ccache"  # Kerberos credential cache


class CredentialSource(str, Enum):
    """Source where credential was discovered."""

    SPRAYING = "spraying"  # Password spraying
    KERBEROASTING = "kerberoasting"  # Kerberoast attack
    ASREPROAST = "asreproast"  # AS-REP roast attack
    DCSYNC = "dcsync"  # DCSync attack
    SAM_DUMP = "sam_dump"  # SAM database dump
    LSA_DUMP = "lsa_dump"  # LSA secrets dump
    DPAPI = "dpapi"  # DPAPI credentials
    GPP = "gpp"  # Group Policy Preferences
    REGISTRY = "registry"  # Registry extraction
    MEMORY = "memory"  # Memory dump
    MANUAL = "manual"  # Manually provided
    UNKNOWN = "unknown"  # Source unknown


@dataclass
class Credential:
    """Represents a single credential (username + secret).

    Attributes:
        username: Username or account name
        credential_type: Type of credential
        credential: The actual credential (password/hash/ticket)
        domain: Domain this credential belongs to
        source: How this credential was discovered
        is_valid: Whether credential has been verified
        is_admin: Whether this is an admin/DA account
        discovered_at: When credential was discovered
        metadata: Additional metadata about the credential
    """

    username: str
    credential_type: CredentialType
    credential: str  # The actual password/hash/ticket
    domain: str

    # Discovery metadata
    source: CredentialSource = CredentialSource.UNKNOWN
    is_valid: bool = False
    is_admin: bool = False
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    # Additional metadata
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert credential to dictionary.

        Returns:
            Dictionary representation (credential is NOT included for security)
        """
        return {
            "username": self.username,
            "credential_type": self.credential_type.value,
            "domain": self.domain,
            "source": self.source.value,
            "is_valid": self.is_valid,
            "is_admin": self.is_admin,
            "discovered_at": self.discovered_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict, credential: str) -> "Credential":
        """Create credential from dictionary.

        Args:
            data: Credential metadata dictionary
            credential: The actual credential (password/hash)

        Returns:
            Credential instance
        """
        cred_type = CredentialType(data.get("credential_type", "password"))
        source = CredentialSource(data.get("source", "unknown"))

        return cls(
            username=data["username"],
            credential_type=cred_type,
            credential=credential,
            domain=data["domain"],
            source=source,
            is_valid=data.get("is_valid", False),
            is_admin=data.get("is_admin", False),
            discovered_at=datetime.fromisoformat(data["discovered_at"])
            if "discovered_at" in data
            else datetime.utcnow(),
            metadata=data.get("metadata", {}),
        )

    def mask_credential(self) -> str:
        """Get masked representation of credential for display.

        Returns:
            Masked credential string
        """
        if self.credential_type == CredentialType.PASSWORD:
            return "*" * 8  # Don't show password length
        elif self.credential_type == CredentialType.NTLM_HASH:
            # Show first/last 4 chars of hash
            if len(self.credential) >= 8:
                return f"{self.credential[:4]}...{self.credential[-4:]}"
        return "***"

    @property
    def display_name(self) -> str:
        """Get display name for credential.

        Returns:
            Formatted display name
        """
        return f"{self.domain}\\{self.username}"


@dataclass
class LocalCredential:
    """Represents a local machine credential (non-domain).

    Attributes:
        host: Hostname or IP where credential is valid
        service: Service name (smb, wmi, rdp, etc.)
        username: Local username
        credential_type: Type of credential
        credential: The actual credential
        source: How this credential was discovered
        is_admin: Whether this is a local admin account
        discovered_at: When credential was discovered
        metadata: Additional metadata
    """

    host: str
    service: str
    username: str
    credential_type: CredentialType
    credential: str

    # Discovery metadata
    source: CredentialSource = CredentialSource.UNKNOWN
    is_admin: bool = False
    discovered_at: datetime = field(default_factory=datetime.utcnow)

    # Additional metadata
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert local credential to dictionary.

        Returns:
            Dictionary representation (credential is NOT included)
        """
        return {
            "host": self.host,
            "service": self.service,
            "username": self.username,
            "credential_type": self.credential_type.value,
            "source": self.source.value,
            "is_admin": self.is_admin,
            "discovered_at": self.discovered_at.isoformat(),
            "metadata": self.metadata,
        }

    @property
    def display_name(self) -> str:
        """Get display name for local credential.

        Returns:
            Formatted display name
        """
        return f"{self.host}\\{self.username} ({self.service})"


@dataclass
class KerberosTicket:
    """Represents a Kerberos ticket (TGT or TGS).

    Attributes:
        username: Username this ticket belongs to
        domain: Domain this ticket is for
        ticket_path: Path to ccache file
        ticket_type: Type of ticket (TGT/TGS)
        service: Service principal name (for TGS)
        expires_at: Ticket expiration time
        discovered_at: When ticket was discovered
        metadata: Additional metadata
    """

    username: str
    domain: str
    ticket_path: str

    # Ticket details
    ticket_type: str = "TGT"  # TGT or TGS
    service: Optional[str] = None  # SPN for TGS tickets
    expires_at: Optional[datetime] = None

    # Discovery metadata
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert ticket to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "username": self.username,
            "domain": self.domain,
            "ticket_path": self.ticket_path,
            "ticket_type": self.ticket_type,
            "service": self.service,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "discovered_at": self.discovered_at.isoformat(),
            "metadata": self.metadata,
        }

    @property
    def is_expired(self) -> bool:
        """Check if ticket is expired.

        Returns:
            True if ticket is expired
        """
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False

    @property
    def display_name(self) -> str:
        """Get display name for ticket.

        Returns:
            Formatted display name
        """
        if self.service:
            return f"{self.domain}\\{self.username} -> {self.service}"
        return f"{self.domain}\\{self.username} (TGT)"
