"""Base enumeration service.

This module provides the main EnumerationService class that composes
protocol-specific enumeration mixins (SMB, LDAP, Kerberos, etc.).
"""

from typing import Optional
import logging

from adscan_internal.services.base_service import BaseService
from adscan_internal.core import EventBus, LicenseMode


logger = logging.getLogger(__name__)


class EnumerationService(BaseService):
    """Main enumeration service.

    This service provides enumeration capabilities across different
    protocols through composition of protocol-specific mixins:
    - smb: SMB enumeration operations
    - ldap: LDAP enumeration operations
    - kerberos: Kerberos enumeration operations
    - network: RDP, WinRM, MSSQL enumeration operations

    Usage:
        # CLI mode (standalone)
        service = EnumerationService()
        shares = service.smb.enumerate_shares(...)

        # Web mode with events
        bus = EventBus()
        service = EnumerationService(event_bus=bus)
        users = service.ldap.enumerate_users(...)
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        license_mode: LicenseMode = LicenseMode.PRO,
    ):
        """Initialize enumeration service.

        Args:
            event_bus: Event bus for progress tracking
            license_mode: License mode (LITE or PRO)
        """
        super().__init__(event_bus=event_bus, license_mode=license_mode)

        # Import mixins lazily to avoid circular imports
        from .smb import SMBEnumerationMixin
        from .ldap import LDAPEnumerationMixin
        from .kerberos import KerberosEnumerationMixin
        from .delegation import DelegationEnumerationMixin
        from .network import NetworkEnumerationMixin

        # Compose protocol-specific services
        self.smb = SMBEnumerationMixin(self)
        self.ldap = LDAPEnumerationMixin(self)
        self.kerberos = KerberosEnumerationMixin(self)
        self.network = NetworkEnumerationMixin(self)
        self.delegation = DelegationEnumerationMixin(self)

        self.logger.info("EnumerationService initialized with protocol mixins")
