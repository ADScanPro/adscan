"""ADScan data models.

This package provides strongly-typed dataclasses for ADScan entities,
replacing dictionary-based data structures with type-safe models.

These models map directly to existing data structures (domains_data, etc.)
and provide backward compatibility through to_dict() and from_dict() methods.

Usage:
    from adscan_internal.models import Domain, AuthStatus, Scan, Vulnerability

    # Create domain from domains_data dict
    domain = Domain.from_dict("example.local", domains_data["example.local"])

    # Update domain state
    domain.add_credential("admin", "password123")
    domain.update_progress("enumeration", 0.5)

    # Convert back to dict for compatibility
    domains_data["example.local"] = domain.to_dict()
"""

# Domain models
from .domain import (
    Domain,
    AuthStatus,
)

# Scan models
from .scan import (
    Scan,
    ScanConfiguration,
    ScanResult,
    ScanType,
    ScanMode,
    ScanStatus,
)

# Credential models
from .credential import (
    Credential,
    CredentialType,
    CredentialSource,
    LocalCredential,
    KerberosTicket,
)

# Vulnerability models
from .vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityCategory,
    VulnerabilityStatus,
    # Helper functions for common vulnerabilities
    create_kerberoast_vulnerability,
    create_asreproast_vulnerability,
    create_unconstrained_delegation_vulnerability,
)

# Host models
from .host import (
    Host,
    DomainController,
    SMBShare,
    HostType,
    HostOS,
)

# Workspace models
from .workspace import (
    Workspace,
    WorkspaceType,
    WorkspaceStatistics,
)

__all__ = [
    # Domain
    "Domain",
    "AuthStatus",
    # Scan
    "Scan",
    "ScanConfiguration",
    "ScanResult",
    "ScanType",
    "ScanMode",
    "ScanStatus",
    # Credential
    "Credential",
    "CredentialType",
    "CredentialSource",
    "LocalCredential",
    "KerberosTicket",
    # Vulnerability
    "Vulnerability",
    "VulnerabilitySeverity",
    "VulnerabilityCategory",
    "VulnerabilityStatus",
    "create_kerberoast_vulnerability",
    "create_asreproast_vulnerability",
    "create_unconstrained_delegation_vulnerability",
    # Host
    "Host",
    "DomainController",
    "SMBShare",
    "HostType",
    "HostOS",
    # Workspace
    "Workspace",
    "WorkspaceType",
    "WorkspaceStatistics",
]
