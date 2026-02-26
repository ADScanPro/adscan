"""SMB enumeration mixin.

This module provides SMB-specific enumeration operations including
share enumeration, session enumeration, and file discovery.
"""

import logging
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from adscan_internal.core import (
    AuthMode,
    requires_auth,
)
from adscan_internal.models import SMBShare
from adscan_internal.services.enumeration.rid_cycling import (
    RIDCyclingResult,
    RIDCyclingService,
)
from adscan_internal.integrations.netexec.parsers import parse_smb_share_map
from adscan_internal.subprocess_env import get_clean_env_for_compilation


logger = logging.getLogger(__name__)


@dataclass
class SMBSession:
    """Represents an active SMB session.

    Attributes:
        hostname: Host where session is active
        username: Username of session
        ip_address: IP address of host
        is_admin: Whether session has admin privileges
        connection_time: When session was established (optional)
    """

    hostname: str
    username: str
    ip_address: str
    is_admin: bool = False
    connection_time: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hostname": self.hostname,
            "username": self.username,
            "ip_address": self.ip_address,
            "is_admin": self.is_admin,
            "connection_time": self.connection_time,
        }


class SMBEnumerationMixin:
    """SMB enumeration operations.

    This mixin provides SMB-specific enumeration methods that adapt
    their behavior based on the authentication mode.

    Note: This is a mixin, not a standalone service. It requires a parent
    EnumerationService to provide event_bus, logger, and license_mode.
    """

    def __init__(self, parent_service):
        """Initialize SMB enumeration mixin.

        Args:
            parent_service: Parent EnumerationService instance
        """
        self.parent = parent_service
        self.logger = parent_service.logger

    def enumerate_shares(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        netexec_path: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        scan_id: Optional[str] = None,
        timeout: int = 60,
    ) -> List[SMBShare]:
        """Enumerate SMB shares on target.

        Adapts behavior based on authentication mode:
        - UNAUTHENTICATED: Uses null/guest session
        - USER_LIST: Not applicable (requires credentials)
        - AUTHENTICATED: Uses provided credentials

        Args:
            domain: Domain name
            pdc: PDC hostname/IP
            auth_mode: Authentication mode
            netexec_path: Path to NetExec executable
            username: Username (required for AUTHENTICATED mode)
            password: Password (required for AUTHENTICATED mode)
            scan_id: Optional scan ID
            timeout: Command timeout in seconds

        Returns:
            List of discovered SMB shares

        Raises:
            AuthenticationError: If auth_mode requires credentials but none provided
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="smb_share_enumeration",
            progress=0.0,
            message=f"Starting SMB share enumeration on {pdc}",
        )

        if auth_mode == AuthMode.UNAUTHENTICATED:
            shares = self._enumerate_shares_unauthenticated(
                pdc, netexec_path, scan_id, timeout
            )
        elif auth_mode == AuthMode.AUTHENTICATED:
            if not username or not password:
                raise ValueError(
                    "Username and password required for authenticated SMB enumeration"
                )
            shares = self._enumerate_shares_authenticated(
                domain, pdc, username, password, netexec_path, scan_id, timeout
            )
        else:
            # USER_LIST mode not applicable for share enumeration
            self.logger.warning(
                f"SMB share enumeration not supported with auth_mode={auth_mode.value}"
            )
            shares = []

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="smb_share_enumeration",
            progress=1.0,
            message=f"SMB share enumeration completed: {len(shares)} share(s) found",
        )

        return shares

    def enumerate_users_by_rid(
        self,
        *,
        domain: str,
        pdc: str,
        netexec_path: str,
        auth_args: str,
        max_rid: int = 2000,
        timeout: int = 300,
        scan_id: Optional[str] = None,
        rid_service: Optional[RIDCyclingService] = None,
    ) -> List[str]:
        """Enumerate domain users via RID cycling using NetExec.

        This is a thin wrapper around :class:`RIDCyclingService` so callers of
        :class:`EnumerationService` can stay within the enumeration layer while
        reusing the common NetExec integration.
        """
        service = rid_service or RIDCyclingService(
            event_bus=self.parent.event_bus,
            license_mode=self.parent.license_mode,
        )

        result: RIDCyclingResult = service.enumerate_users_by_rid(
            domain=domain,
            pdc=pdc,
            netexec_path=netexec_path,
            auth_args=auth_args,
            max_rid=max_rid,
            timeout=timeout,
            scan_id=scan_id,
        )
        return result.usernames

    def _enumerate_shares_unauthenticated(
        self,
        pdc: str,
        netexec_path: str,
        scan_id: Optional[str],
        timeout: int,
    ) -> List[SMBShare]:
        """Enumerate SMB shares using null/guest session.

        Args:
            pdc: PDC hostname/IP
            netexec_path: Path to NetExec
            scan_id: Scan ID
            timeout: Timeout in seconds

        Returns:
            List of SMB shares
        """
        self.logger.info(f"Enumerating SMB shares on {pdc} (unauthenticated)")

        # Try null session first, then guest
        auth_options = [
            ("-u '' -p ''", "null"),  # Null session
            ("-u 'guest' -p ''", "guest"),  # Guest session
        ]

        all_shares = []

        for auth_string, session_type in auth_options:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="smb_share_enumeration",
                progress=0.3,
                message=f"Trying {session_type} session",
            )

            command = f"{netexec_path} smb {pdc} {auth_string} --shares"

            try:
                clean_env = get_clean_env_for_compilation()
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                    env=clean_env,
                )

                if result.returncode == 0 and result.stdout:
                    shares = self._parse_netexec_shares_output(result.stdout, pdc)
                    if shares:
                        self.logger.info(
                            f"Found {len(shares)} shares via {session_type} session"
                        )
                        all_shares.extend(shares)
                        break  # Success - no need to try other sessions

            except subprocess.TimeoutExpired:
                self.logger.warning(
                    f"SMB enumeration timed out ({session_type} session)"
                )
            except Exception as e:
                self.logger.error(f"Error during SMB enumeration: {e}")

        return all_shares

    def _enumerate_shares_authenticated(
        self,
        domain: str,
        pdc: str,
        username: str,
        password: str,
        netexec_path: str,
        scan_id: Optional[str],
        timeout: int,
    ) -> List[SMBShare]:
        """Enumerate SMB shares using authenticated session.

        Args:
            domain: Domain name
            pdc: PDC hostname/IP
            username: Username
            password: Password or hash
            netexec_path: Path to NetExec
            scan_id: Scan ID
            timeout: Timeout in seconds

        Returns:
            List of SMB shares
        """
        self.logger.info(
            f"Enumerating SMB shares on {pdc} (authenticated as {username})"
        )

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="smb_share_enumeration",
            progress=0.5,
            message="Enumerating shares with credentials",
        )

        # Check if password is NTLM hash
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )

        if is_hash:
            auth_string = f"-u '{username}' -H '{password}' -d '{domain}'"
        else:
            auth_string = f"-u '{username}' -p '{password}' -d '{domain}'"

        command = f"{netexec_path} smb {pdc} {auth_string} --shares"

        try:
            clean_env = get_clean_env_for_compilation()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=clean_env,
            )

            if result.returncode == 0 and result.stdout:
                shares = self._parse_netexec_shares_output(result.stdout, pdc)
                self.logger.info(f"Found {len(shares)} shares (authenticated)")
                return shares
            else:
                self.logger.warning(
                    f"SMB share enumeration failed: {result.stderr or 'Unknown error'}"
                )
                return []

        except subprocess.TimeoutExpired:
            self.logger.error("SMB share enumeration timed out")
            return []
        except Exception as e:
            self.logger.exception(f"Error during authenticated SMB enumeration: {e}")
            return []

    def _parse_netexec_shares_output(
        self, output: str, hostname: str
    ) -> List[SMBShare]:
        """Parse NetExec --shares output.

        Args:
            output: NetExec stdout
            hostname: Hostname

        Returns:
            List of SMBShare objects
        """
        share_map = parse_smb_share_map(output)
        shares: list[SMBShare] = []
        for host, host_shares in share_map.items():
            for share_name, perm in host_shares.items():
                permissions = [p.strip() for p in perm.split(",") if p.strip()]
                shares.append(
                    SMBShare(
                        host=host or hostname,
                        share_name=share_name,
                        permissions=permissions,
                        metadata={"source": "netexec"},
                    )
                )
        return shares

    @requires_auth(AuthMode.AUTHENTICATED)
    def enumerate_sessions(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        username: str,
        password: str,
        netexec_path: str,
        scan_id: Optional[str] = None,
        timeout: int = 60,
    ) -> List[SMBSession]:
        """Enumerate active SMB sessions on domain controller.

        This operation requires authenticated access.

        Args:
            domain: Domain name
            pdc: PDC hostname/IP
            auth_mode: Authentication mode (must be AUTHENTICATED)
            username: Username
            password: Password or hash
            netexec_path: Path to NetExec
            scan_id: Optional scan ID
            timeout: Timeout in seconds

        Returns:
            List of active SMB sessions

        Raises:
            AuthenticationError: If auth_mode is not AUTHENTICATED
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="smb_session_enumeration",
            progress=0.0,
            message=f"Enumerating SMB sessions on {pdc}",
        )

        self.logger.info(f"Enumerating SMB sessions on {pdc}")

        # Build auth string
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )

        if is_hash:
            auth_string = f"-u '{username}' -H '{password}' -d '{domain}'"
        else:
            auth_string = f"-u '{username}' -p '{password}' -d '{domain}'"

        command = f"{netexec_path} smb {pdc} {auth_string} --sessions"

        try:
            clean_env = get_clean_env_for_compilation()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=clean_env,
            )

            sessions = []
            if result.returncode == 0 and result.stdout:
                sessions = self._parse_netexec_sessions_output(result.stdout, pdc)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="smb_session_enumeration",
                progress=1.0,
                message=f"Session enumeration completed: {len(sessions)} session(s) found",
            )

            self.logger.info(f"Found {len(sessions)} active SMB sessions")
            return sessions

        except subprocess.TimeoutExpired:
            self.logger.error("SMB session enumeration timed out")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="smb_session_enumeration",
                progress=1.0,
                message="Session enumeration timed out",
            )
            return []
        except Exception as e:
            self.logger.exception(f"Error during session enumeration: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="smb_session_enumeration",
                progress=1.0,
                message="Session enumeration failed",
            )
            return []

    def _parse_netexec_sessions_output(
        self, output: str, hostname: str
    ) -> List[SMBSession]:
        """Parse NetExec --sessions output.

        Args:
            output: NetExec stdout
            hostname: Hostname

        Returns:
            List of SMBSession objects
        """
        sessions = []

        # NetExec --sessions output format varies
        # Typically shows active sessions with username and source IP
        lines = output.splitlines()

        for line in lines:
            line = line.strip()
            if not line or "SMB" not in line:
                continue

            # Try to extract session information
            # Format varies, but typically: username from IP_ADDRESS
            if "@" in line or "from" in line:
                # This is a simplified parser - real implementation may need more sophistication
                parts = line.split()
                if len(parts) >= 2:
                    username = parts[1] if len(parts) > 1 else "Unknown"
                    ip_address = parts[-1] if len(parts) > 2 else "Unknown"

                    session = SMBSession(
                        hostname=hostname,
                        username=username,
                        ip_address=ip_address,
                        is_admin=False,  # Can be enhanced to detect admin sessions
                    )
                    sessions.append(session)

        return sessions
