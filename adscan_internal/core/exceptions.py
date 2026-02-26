"""Custom exceptions for ADScan.

This module provides exception classes for license errors,
authentication errors, and operation-specific failures.
"""

from typing import Optional


class ADScanException(Exception):
    """Base exception for all ADScan errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        """Initialize exception.

        Args:
            message: Error message
            details: Optional dictionary with additional error context
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}


class LicenseError(ADScanException):
    """Raised when a PRO feature is accessed with LITE license."""

    def __init__(self, feature: str, message: Optional[str] = None):
        """Initialize license error.

        Args:
            feature: Feature name that requires PRO license
            message: Optional custom message
        """
        if message is None:
            message = (
                f"Feature '{feature}' requires ADScan PRO license. "
                f"Please upgrade to access this functionality."
            )
        super().__init__(message, details={"feature": feature})
        self.feature = feature


class AuthenticationError(ADScanException):
    """Raised when authentication is required but not available."""

    def __init__(
        self,
        operation: str,
        required_auth_mode: str,
        current_auth_mode: str,
        message: Optional[str] = None,
    ):
        """Initialize authentication error.

        Args:
            operation: Operation being attempted
            required_auth_mode: Required authentication mode
            current_auth_mode: Current authentication mode
            message: Optional custom message
        """
        if message is None:
            message = (
                f"Operation '{operation}' requires '{required_auth_mode}' "
                f"authentication but current mode is '{current_auth_mode}'."
            )
        super().__init__(
            message,
            details={
                "operation": operation,
                "required_auth_mode": required_auth_mode,
                "current_auth_mode": current_auth_mode,
            },
        )
        self.operation = operation
        self.required_auth_mode = required_auth_mode
        self.current_auth_mode = current_auth_mode


class ProtocolError(ADScanException):
    """Raised when a protocol-specific operation fails."""

    def __init__(
        self,
        protocol: str,
        operation: str,
        reason: str,
        message: Optional[str] = None,
    ):
        """Initialize protocol error.

        Args:
            protocol: Protocol name (SMB, LDAP, etc.)
            operation: Operation being attempted
            reason: Reason for failure
            message: Optional custom message
        """
        if message is None:
            message = f"Protocol {protocol} operation '{operation}' failed: {reason}"
        super().__init__(
            message,
            details={
                "protocol": protocol,
                "operation": operation,
                "reason": reason,
            },
        )
        self.protocol = protocol
        self.operation = operation
        self.reason = reason


class ToolNotFoundError(ADScanException):
    """Raised when a required external tool is not found."""

    def __init__(self, tool_name: str, install_hint: Optional[str] = None):
        """Initialize tool not found error.

        Args:
            tool_name: Name of the missing tool
            install_hint: Optional hint on how to install
        """
        message = f"Required tool '{tool_name}' not found."
        if install_hint:
            message += f" {install_hint}"
        else:
            message += " Please run 'adscan install' to install required tools."

        super().__init__(message, details={"tool": tool_name})
        self.tool_name = tool_name
        self.install_hint = install_hint


class DomainNotFoundError(ADScanException):
    """Raised when a domain is not configured or accessible."""

    def __init__(self, domain: str, message: Optional[str] = None):
        """Initialize domain not found error.

        Args:
            domain: Domain name
            message: Optional custom message
        """
        if message is None:
            message = (
                f"Domain '{domain}' not found or not configured. "
                f"Please add the domain to the workspace."
            )
        super().__init__(message, details={"domain": domain})
        self.domain = domain


class ConfigurationError(ADScanException):
    """Raised when configuration is invalid or missing."""

    def __init__(
        self,
        config_key: str,
        reason: str,
        message: Optional[str] = None,
    ):
        """Initialize configuration error.

        Args:
            config_key: Configuration key that is invalid
            reason: Reason for error
            message: Optional custom message
        """
        if message is None:
            message = f"Configuration error for '{config_key}': {reason}"
        super().__init__(
            message,
            details={
                "config_key": config_key,
                "reason": reason,
            },
        )
        self.config_key = config_key
        self.reason = reason


class ScanExecutionError(ADScanException):
    """Raised when a scan execution fails."""

    def __init__(
        self,
        scan_id: str,
        phase: str,
        reason: str,
        message: Optional[str] = None,
    ):
        """Initialize scan execution error.

        Args:
            scan_id: Scan ID
            phase: Scan phase where error occurred
            reason: Reason for failure
            message: Optional custom message
        """
        if message is None:
            message = f"Scan {scan_id} failed during phase '{phase}': {reason}"
        super().__init__(
            message,
            details={
                "scan_id": scan_id,
                "phase": phase,
                "reason": reason,
            },
        )
        self.scan_id = scan_id
        self.phase = phase
        self.reason = reason
