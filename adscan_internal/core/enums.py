"""Core enumerations for ADScan.

This module provides enums for authentication modes, protocols,
license modes, and feature flags.
"""

from enum import Enum


class AuthMode(str, Enum):
    """Authentication mode for operations.

    Determines the level of access and available operations:
    - UNAUTHENTICATED: No credentials, uses null/guest sessions
    - USER_LIST: Has enumerated user list but no valid credentials
    - AUTHENTICATED: Valid domain credentials available
    """

    UNAUTHENTICATED = "unauthenticated"
    USER_LIST = "user_list"
    AUTHENTICATED = "authenticated"


class Protocol(str, Enum):
    """Network protocol for enumeration/exploitation.

    Different protocols provide different attack surfaces
    and enumeration capabilities.
    """

    SMB = "smb"
    LDAP = "ldap"
    KERBEROS = "kerberos"
    RDP = "rdp"
    WINRM = "winrm"
    MSSQL = "mssql"
    HTTP = "http"
    HTTPS = "https"


class LicenseMode(str, Enum):
    """License mode for ADScan builds.

    - LITE: Basic features, free version
    - PRO: All features including advanced attacks and trust enumeration
    """

    LITE = "lite"
    PRO = "pro"


class ScanPhase(str, Enum):
    """Scan execution phases.

    Defines the sequential phases of a complete domain scan.
    Used for progress tracking and orchestration.
    """

    INITIAL = "initial"
    DNS_CHECK = "dns_check"
    PDC_DISCOVERY = "pdc_discovery"
    CLOCK_SYNC = "clock_sync"
    UNAUTHENTICATED_ENUM = "unauthenticated_enumeration"
    USER_ENUMERATION = "user_enumeration"
    CREDENTIAL_VERIFICATION = "credential_verification"
    AUTHENTICATED_ENUM = "authenticated_enumeration"
    TRUST_ENUMERATION = "trust_enumeration"
    BLOODHOUND_COLLECTION = "bloodhound_collection"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class OperationType(str, Enum):
    """Type of operation being performed.

    Used for telemetry, logging, and progress tracking.
    """

    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    CREDENTIAL_ATTACK = "credential_attack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    ANALYSIS = "analysis"
