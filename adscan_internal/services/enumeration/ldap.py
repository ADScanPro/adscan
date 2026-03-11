"""LDAP enumeration mixin.

This module provides LDAP-specific enumeration operations including
user enumeration, group enumeration, and computer enumeration.
"""

from collections.abc import Callable
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
import subprocess
import logging

from adscan_internal.core import AuthMode, requires_auth
from adscan_internal.command_runner import CommandSpec, default_runner
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)
from adscan_internal.integrations.netexec.parsers import (
    parse_netexec_ldap_query_objects,
)
from adscan_internal.execution_outcomes import (
    result_is_exact_ldap_connection_timeout,
)


logger = logging.getLogger(__name__)

CommandExecutor = Callable[[str, int], subprocess.CompletedProcess[str]]


def _default_executor(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Execute a command using the shared command runner.

    Args:
        command: Command string to execute.
        timeout: Timeout in seconds.

    Returns:
        Completed process result.
    """
    use_clean_env = command_string_needs_clean_env(command)
    cmd_env = get_clean_env_for_compilation() if use_clean_env else None
    return default_runner.run(
        CommandSpec(
            command=command,
            timeout=timeout,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
            env=cmd_env,
        )
    )


@dataclass
class LDAPUser:
    """Represents a domain user from LDAP.

    Attributes:
        username: User's sAMAccountName
        distinguished_name: User's DN
        description: User description (may contain passwords)
        user_principal_name: User's UPN
        is_enabled: Whether account is enabled
        password_last_set: When password was last changed
        admin_count: AdminCount attribute (1 = privileged account)
    """

    username: str
    distinguished_name: str = ""
    description: str = ""
    user_principal_name: str = ""
    is_enabled: bool = True
    password_last_set: Optional[str] = None
    admin_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "username": self.username,
            "distinguished_name": self.distinguished_name,
            "description": self.description,
            "user_principal_name": self.user_principal_name,
            "is_enabled": self.is_enabled,
            "password_last_set": self.password_last_set,
            "admin_count": self.admin_count,
        }


@dataclass
class LDAPGroup:
    """Represents a domain group from LDAP.

    Attributes:
        name: Group's sAMAccountName
        distinguished_name: Group's DN
        description: Group description
        member_count: Number of members (if available)
        is_privileged: Whether this is a privileged group
    """

    name: str
    distinguished_name: str = ""
    description: str = ""
    member_count: int = 0
    is_privileged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "distinguished_name": self.distinguished_name,
            "description": self.description,
            "member_count": self.member_count,
            "is_privileged": self.is_privileged,
        }


@dataclass
class LDAPComputer:
    """Represents a domain computer from LDAP.

    Attributes:
        hostname: Computer's DNS hostname or sAMAccountName
        samaccountname: Computer's sAMAccountName
        distinguished_name: Computer's DN
        operating_system: Operating system name
        os_version: Operating system version
        is_enabled: Whether computer account is enabled
        dns_hostname: Computer's DNS hostname
    """

    hostname: str
    samaccountname: str = ""
    distinguished_name: str = ""
    operating_system: str = ""
    os_version: str = ""
    is_enabled: bool = True
    dns_hostname: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hostname": self.hostname,
            "samaccountname": self.samaccountname,
            "distinguished_name": self.distinguished_name,
            "operating_system": self.operating_system,
            "os_version": self.os_version,
            "is_enabled": self.is_enabled,
            "dns_hostname": self.dns_hostname,
        }


@dataclass
class LDAPAnonymousUserRecord:
    """Represents a partially-visible user object from anonymous LDAP bind.

    Attributes:
        distinguished_name: Distinguished name of the object.
        common_name: ``cn`` attribute or best-effort DN-derived CN.
        samaccountname: ``sAMAccountName`` when visible to the anonymous bind.
        description: ``description`` attribute, if exposed.
        object_classes: Multi-valued ``objectClass`` entries.
        is_enabled: Best-effort enabled state derived from ``userAccountControl``.
        raw_attributes: Full lower-cased attribute mapping parsed from NetExec.
    """

    distinguished_name: str
    common_name: str = ""
    samaccountname: str = ""
    description: str = ""
    object_classes: list[str] = field(default_factory=list)
    is_enabled: bool = True
    raw_attributes: Dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for persistence/debugging."""
        return {
            "distinguished_name": self.distinguished_name,
            "common_name": self.common_name,
            "samaccountname": self.samaccountname,
            "description": self.description,
            "object_classes": list(self.object_classes),
            "is_enabled": self.is_enabled,
            "raw_attributes": dict(self.raw_attributes),
        }


class LDAPEnumerationMixin:
    """LDAP enumeration operations.

    This mixin provides LDAP-specific enumeration methods that typically
    require authenticated access to query Active Directory.

    Note: This is a mixin, not a standalone service. It requires a parent
    EnumerationService to provide event_bus, logger, and license_mode.
    """

    def __init__(self, parent_service):
        """Initialize LDAP enumeration mixin.

        Args:
            parent_service: Parent EnumerationService instance
        """
        self.parent = parent_service
        self.logger = parent_service.logger

    @requires_auth(AuthMode.AUTHENTICATED)
    def enumerate_users(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        username: str,
        password: str,
        netexec_path: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[LDAPUser]:
        """Enumerate domain users via LDAP.

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
            List of domain users

        Raises:
            AuthenticationError: If auth_mode is not AUTHENTICATED
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_user_enumeration",
            progress=0.0,
            message=f"Enumerating users via LDAP on {domain}",
        )

        self.logger.info(f"Enumerating users via LDAP on domain {domain}")

        # Build auth string
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )

        if is_hash:
            auth_string = f"-u '{username}' -H '{password}' -d '{domain}'"
        else:
            auth_string = f"-u '{username}' -p '{password}' -d '{domain}'"

        command = f"{netexec_path} ldap {pdc} {auth_string} --users"

        try:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_user_enumeration",
                progress=0.3,
                message="Executing LDAP query",
            )

            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)
            if result_is_exact_ldap_connection_timeout(result):
                self.logger.warning(
                    "LDAP user enumeration hit the exact NetExec LDAP timeout signature; "
                    "treating LDAP as unavailable for this attempt."
                )
                self.parent._emit_progress(
                    scan_id=scan_id,
                    phase="ldap_user_enumeration",
                    progress=1.0,
                    message="LDAP user enumeration unavailable (connection timeout)",
                )
                return []

            users = []
            if result.returncode == 0 and result.stdout:
                users = self._parse_netexec_users_output(result.stdout)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_user_enumeration",
                progress=1.0,
                message=f"User enumeration completed: {len(users)} user(s) found",
            )

            self.logger.info(f"Found {len(users)} domain users")
            return users

        except subprocess.TimeoutExpired:
            self.logger.error("LDAP user enumeration timed out")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_user_enumeration",
                progress=1.0,
                message="User enumeration timed out",
            )
            return []
        except Exception as e:
            self.logger.exception(f"Error during LDAP user enumeration: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_user_enumeration",
                progress=1.0,
                message="User enumeration failed",
            )
            return []

    @requires_auth(AuthMode.AUTHENTICATED)
    def enumerate_groups(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        username: str,
        password: str,
        netexec_path: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[LDAPGroup]:
        """Enumerate domain groups via LDAP.

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
            List of domain groups

        Raises:
            AuthenticationError: If auth_mode is not AUTHENTICATED
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_group_enumeration",
            progress=0.0,
            message=f"Enumerating groups via LDAP on {domain}",
        )

        self.logger.info(f"Enumerating groups via LDAP on domain {domain}")

        # Build auth string
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )

        if is_hash:
            auth_string = f"-u '{username}' -H '{password}' -d '{domain}'"
        else:
            auth_string = f"-u '{username}' -p '{password}' -d '{domain}'"

        command = f"{netexec_path} ldap {pdc} {auth_string} --groups"

        try:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_group_enumeration",
                progress=0.3,
                message="Executing LDAP query",
            )

            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)
            if result_is_exact_ldap_connection_timeout(result):
                self.logger.warning(
                    "LDAP group enumeration hit the exact NetExec LDAP timeout signature; "
                    "treating LDAP as unavailable for this attempt."
                )
                self.parent._emit_progress(
                    scan_id=scan_id,
                    phase="ldap_group_enumeration",
                    progress=1.0,
                    message="LDAP group enumeration unavailable (connection timeout)",
                )
                return []

            groups = []
            if result.returncode == 0 and result.stdout:
                groups = self._parse_netexec_groups_output(result.stdout)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_group_enumeration",
                progress=1.0,
                message=f"Group enumeration completed: {len(groups)} group(s) found",
            )

            self.logger.info(f"Found {len(groups)} domain groups")
            return groups

        except subprocess.TimeoutExpired:
            self.logger.error("LDAP group enumeration timed out")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_group_enumeration",
                progress=1.0,
                message="Group enumeration timed out",
            )
            return []
        except Exception as e:
            self.logger.exception(f"Error during LDAP group enumeration: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_group_enumeration",
                progress=1.0,
                message="Group enumeration failed",
            )
            return []

    def _parse_netexec_users_output(self, output: str) -> List[LDAPUser]:
        """Parse NetExec --users output.

        Args:
            output: NetExec stdout

        Returns:
            List of LDAPUser objects
        """
        users = []

        # NetExec LDAP --users output format:
        # LDAP  10.0.0.1  389    DC01  [+] example.local\user1
        # LDAP  10.0.0.1  389    DC01      CN=User1,CN=Users,DC=example,DC=local
        # LDAP  10.0.0.1  389    DC01      Description: IT Admin

        lines = output.splitlines()
        current_user = None

        for line in lines:
            line = line.strip()
            if not line or "LDAP" not in line:
                continue

            # Check if this is a user line
            if "[+]" in line and "\\" in line:
                # Extract username
                parts = line.split("\\")
                if len(parts) >= 2:
                    username = parts[-1].strip()
                    current_user = LDAPUser(username=username)
                    users.append(current_user)

            # Parse additional attributes
            elif current_user:
                if "CN=" in line and "DC=" in line:
                    current_user.distinguished_name = line.split("DC01")[-1].strip()
                elif "Description:" in line:
                    current_user.description = line.split("Description:")[-1].strip()
                elif "userPrincipalName:" in line:
                    current_user.user_principal_name = line.split("userPrincipalName:")[
                        -1
                    ].strip()
                elif "adminCount:" in line:
                    try:
                        admin_count_str = line.split("adminCount:")[-1].strip()
                        current_user.admin_count = int(admin_count_str)
                    except ValueError:
                        pass

        return users

    def _parse_netexec_groups_output(self, output: str) -> List[LDAPGroup]:
        """Parse NetExec --groups output.

        Args:
            output: NetExec stdout

        Returns:
            List of LDAPGroup objects
        """
        groups = []

        # NetExec LDAP --groups output format similar to --users
        lines = output.splitlines()
        current_group = None

        # Privileged groups list
        privileged_groups = {
            "Domain Admins",
            "Enterprise Admins",
            "Administrators",
            "Schema Admins",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators",
        }

        for line in lines:
            line = line.strip()
            if not line or "LDAP" not in line:
                continue

            # Check if this is a group line
            if "[+]" in line or "Group:" in line:
                # Extract group name
                if "\\" in line:
                    parts = line.split("\\")
                    if len(parts) >= 2:
                        group_name = parts[-1].strip()
                    else:
                        continue  # Skip invalid group line
                else:
                    group_name = line.split()[-1].strip()

                if not group_name:
                    continue  # Skip empty group name

                is_privileged = group_name in privileged_groups

                current_group = LDAPGroup(
                    name=group_name,
                    is_privileged=is_privileged,
                )
                groups.append(current_group)

            # Parse additional attributes
            elif current_group:
                if "CN=" in line and "DC=" in line:
                    current_group.distinguished_name = line.split("DC01")[-1].strip()
                elif "Description:" in line:
                    current_group.description = line.split("Description:")[-1].strip()

        return groups

    @requires_auth(AuthMode.AUTHENTICATED)
    def enumerate_active_users(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        username: str,
        password: str,
        netexec_path: str,
        *,
        log_file: Optional[str] = None,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[str]:
        """Enumerate active (enabled) users via NetExec LDAP.

        This mirrors the legacy CLI behavior that used ``--active-users`` to
        generate ``enabled_users.txt``.

        Args:
            domain: Domain name
            pdc: PDC hostname/IP
            auth_mode: Authentication mode (must be AUTHENTICATED)
            username: Username
            password: Password or hash
            netexec_path: Path to NetExec
            log_file: Optional NetExec log file path
            executor: Optional injected executor (CLI should pass run_command wrapper)
            scan_id: Optional scan ID
            timeout: Timeout in seconds

        Returns:
            List of active usernames (sAMAccountName), lowercased and unique.
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_active_user_enumeration",
            progress=0.0,
            message=f"Enumerating active users via LDAP on {domain}",
        )

        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )
        if is_hash:
            auth_string = f"-u '{username}' -H '{password}' -d '{domain}'"
        else:
            auth_string = f"-u '{username}' -p '{password}' -d '{domain}'"

        log_part = f' --log "{log_file}"' if log_file else ""
        command = f"{netexec_path} ldap {pdc} {auth_string} --active-users{log_part}"

        try:
            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)
            usernames: list[str] = []
            if result.returncode == 0 and result.stdout:
                usernames = self._parse_netexec_active_users_output(result.stdout)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_active_user_enumeration",
                progress=1.0,
                message=f"Active user enumeration completed: {len(usernames)} user(s) found",
            )
            return usernames
        except subprocess.TimeoutExpired:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_active_user_enumeration",
                progress=1.0,
                message="Active user enumeration timed out",
            )
            return []
        except Exception as e:
            self.logger.exception(f"Error during LDAP active user enumeration: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_active_user_enumeration",
                progress=1.0,
                message="Active user enumeration failed",
            )
            return []

    def enumerate_active_users_anonymous(
        self,
        *,
        pdc: str,
        netexec_path: str,
        log_file: Optional[str] = None,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[str]:
        """Enumerate active users via anonymous LDAP when the server allows it.

        Args:
            pdc: Domain controller hostname/IP.
            netexec_path: Path to NetExec.
            log_file: Optional NetExec log file path.
            executor: Optional injected executor.
            scan_id: Optional scan ID.
            timeout: Timeout in seconds.

        Returns:
            Lower-cased, de-duplicated username list.
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_active_user_enumeration_anonymous",
            progress=0.0,
            message=f"Enumerating active users via anonymous LDAP on {pdc}",
        )

        log_part = f' --log "{log_file}"' if log_file else ""
        command = f'{netexec_path} ldap {pdc} -u "" -p "" --active-users{log_part}'

        try:
            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)
            usernames: list[str] = []
            if result.returncode == 0 and result.stdout:
                usernames = self._parse_netexec_active_users_output(result.stdout)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_active_user_enumeration_anonymous",
                progress=1.0,
                message=f"Anonymous active user enumeration completed: {len(usernames)} user(s) found",
            )
            return usernames
        except subprocess.TimeoutExpired:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_active_user_enumeration_anonymous",
                progress=1.0,
                message="Anonymous active user enumeration timed out",
            )
            return []
        except Exception as e:
            self.logger.exception(
                f"Error during anonymous LDAP active user enumeration: {e}"
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_active_user_enumeration_anonymous",
                progress=1.0,
                message="Anonymous active user enumeration failed",
            )
            return []

    def query_anonymous_user_inventory(
        self,
        *,
        pdc: str,
        netexec_path: str,
        log_file: Optional[str] = None,
        ldap_filter: Optional[str] = None,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[LDAPAnonymousUserRecord]:
        """Query LDAP anonymously for enabled user objects.

        Args:
            pdc: Domain controller hostname/IP.
            netexec_path: Path to NetExec.
            log_file: Optional NetExec log file path.
            ldap_filter: Optional LDAP filter. When omitted, a default
                enabled-user filter is used.
            executor: Optional injected executor.
            scan_id: Optional scan ID.
            timeout: Timeout in seconds.

        Returns:
            List of best-effort user records extracted from NetExec query output.
        """
        effective_filter = (
            ldap_filter
            or "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_anonymous_user_inventory",
            progress=0.0,
            message=f"Querying anonymous LDAP user inventory on {pdc}",
        )

        log_part = f' --log "{log_file}"' if log_file else ""
        command = (
            f'{netexec_path} ldap {pdc} -u "" -p "" '
            f"--query '{effective_filter}' \"\"{log_part}"
        )

        try:
            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)
            if result.returncode != 0:
                self.parent._emit_progress(
                    scan_id=scan_id,
                    phase="ldap_anonymous_user_inventory",
                    progress=1.0,
                    message="Anonymous LDAP user inventory query failed",
                )
                return []

            combined_output = "\n".join(
                segment for segment in ((result.stdout or ""), (result.stderr or "")) if segment
            )
            objects = parse_netexec_ldap_query_objects(combined_output)
            records = self._parse_netexec_anonymous_user_inventory(objects)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_user_inventory",
                progress=1.0,
                message=f"Anonymous LDAP user inventory completed: {len(records)} user object(s) found",
            )
            return records
        except subprocess.TimeoutExpired:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_user_inventory",
                progress=1.0,
                message="Anonymous LDAP user inventory timed out",
            )
            return []
        except Exception as e:
            self.logger.exception(f"Error during anonymous LDAP user inventory: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_user_inventory",
                progress=1.0,
                message="Anonymous LDAP user inventory failed",
            )
            return []

    def enumerate_computers(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        username: str,
        password: str,
        netexec_path: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[LDAPComputer]:
        """Enumerate domain computers via LDAP.

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
            List of domain computers

        Raises:
            AuthenticationError: If auth_mode is not AUTHENTICATED
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_computer_enumeration",
            progress=0.0,
            message=f"Enumerating computers via LDAP on {domain}",
        )

        self.logger.info(f"Enumerating computers via LDAP on domain {domain}")

        # Build auth string
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )

        if is_hash:
            auth_string = f"-u '{username}' -H '{password}' -d '{domain}'"
        else:
            auth_string = f"-u '{username}' -p '{password}' -d '{domain}'"

        command = f"{netexec_path} ldap {pdc} {auth_string} --computers"

        try:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=0.3,
                message="Executing LDAP query",
            )

            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)

            computers = []
            if result.returncode == 0 and result.stdout:
                computers = self._parse_netexec_computers_output(result.stdout)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=1.0,
                message=f"Computer enumeration completed: {len(computers)} computer(s) found",
            )

            self.logger.info(f"Found {len(computers)} domain computers")
            return computers

        except subprocess.TimeoutExpired:
            self.logger.error("LDAP computer enumeration timed out")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=1.0,
                message="Computer enumeration timed out",
            )
            return []
        except Exception as e:
            self.logger.exception(f"Error during LDAP computer enumeration: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=1.0,
                message="Computer enumeration failed",
            )
            return []

    def test_anonymous_access(
        self,
        pdc: str,
        netexec_path: str,
        log_file: Optional[str] = None,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """Test anonymous LDAP access to the domain controller.

        Attempts to bind to LDAP with empty credentials to test if
        anonymous access is allowed.

        Args:
            pdc: PDC hostname/IP
            netexec_path: Path to NetExec
            scan_id: Optional scan ID
            timeout: Timeout in seconds

        Returns:
            Dictionary with test results:
                - accessible: bool - Whether anonymous access succeeded
                - error: Optional[str] - Error message if failed
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_anonymous_test",
            progress=0.0,
            message=f"Testing anonymous LDAP access on {pdc}",
        )

        self.logger.info(f"Testing anonymous LDAP access on {pdc}")

        log_part = f' --log "{log_file}"' if log_file else ""
        command = f'{netexec_path} ldap {pdc} -u "" -p ""{log_part}'

        try:
            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)

            output = (result.stdout or "") + (result.stderr or "")
            output_lower = output.lower()
            error_markers = (
                "error in searchrequest",
                "operationserror",
                "successful bind must be completed",
                "status_access_denied",
                "invalid credentials",
            )
            success_markers = (
                "[+]",
                "status_success",
                "bind successful",
                "authenticated",
            )

            error_detected = any(marker in output_lower for marker in error_markers)
            success_detected = any(marker in output_lower for marker in success_markers)

            # Treat explicit LDAP errors as a failed anonymous bind even if a [+] line exists.
            accessible = bool(success_detected and not error_detected)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_test",
                progress=1.0,
                message=f"Anonymous LDAP test completed: {'Accessible' if accessible else 'Not accessible'}",
            )

            error_message = None
            if not accessible:
                if error_detected:
                    error_message = "Anonymous access denied (LDAP error reported)."
                else:
                    error_message = "Anonymous access denied."

            result_data = {
                "accessible": accessible,
                "error": error_message,
            }

            self.logger.info(
                f"Anonymous LDAP access test: {'SUCCESS' if accessible else 'DENIED'}",
                extra={"pdc": pdc, "accessible": accessible},
            )

            return result_data

        except subprocess.TimeoutExpired:
            self.logger.error("Anonymous LDAP access test timed out")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_test",
                progress=1.0,
                message="Test timed out",
            )
            return {"accessible": False, "error": "Timeout"}

        except Exception as e:
            self.logger.exception(f"Error during anonymous LDAP test: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_test",
                progress=1.0,
                message="Test failed",
            )
            return {"accessible": False, "error": str(e)}

    def _parse_netexec_anonymous_user_inventory(
        self, objects: list[dict[str, object]]
    ) -> List[LDAPAnonymousUserRecord]:
        """Normalize NetExec LDAP query objects into anonymous user records."""
        records: list[LDAPAnonymousUserRecord] = []
        seen_dns: set[str] = set()

        for item in objects:
            dn = str(item.get("distinguished_name") or "").strip()
            if not dn:
                continue

            attrs_raw = item.get("attributes") or {}
            if not isinstance(attrs_raw, dict):
                continue

            attrs: dict[str, list[str]] = {}
            for key, values in attrs_raw.items():
                normalized_key = str(key or "").casefold()
                if not normalized_key:
                    continue
                if isinstance(values, list):
                    attrs[normalized_key] = [
                        str(value).strip() for value in values if str(value).strip()
                    ]
                else:
                    value = str(values or "").strip()
                    attrs[normalized_key] = [value] if value else []

            object_classes = [entry.casefold() for entry in attrs.get("objectclass", [])]
            if object_classes and "user" not in object_classes:
                continue

            cn = ""
            if attrs.get("cn"):
                cn = attrs["cn"][0]
            elif dn.upper().startswith("CN="):
                cn = dn.split(",", 1)[0].split("=", 1)[1].strip()

            samaccountname = ""
            if attrs.get("samaccountname"):
                samaccountname = attrs["samaccountname"][0]

            description = " | ".join(attrs.get("description", []))

            is_enabled = True
            if attrs.get("useraccountcontrol"):
                try:
                    uac = int(attrs["useraccountcontrol"][0], 10)
                    is_enabled = not bool(uac & 0x0002)
                except (TypeError, ValueError):
                    is_enabled = True

            key = dn.casefold()
            if key in seen_dns:
                continue
            seen_dns.add(key)
            records.append(
                LDAPAnonymousUserRecord(
                    distinguished_name=dn,
                    common_name=cn,
                    samaccountname=samaccountname,
                    description=description,
                    object_classes=object_classes,
                    is_enabled=is_enabled,
                    raw_attributes=attrs,
                )
            )

        return records

    def _parse_netexec_computers_output(self, output: str) -> List[LDAPComputer]:
        """Parse NetExec --computers output.

        Args:
            output: NetExec stdout

        Returns:
            List of LDAPComputer objects
        """
        computers = []

        # NetExec LDAP --computers output format similar to --users
        # LDAP  10.0.0.1  389    DC01  [+] example.local\DC01$
        # LDAP  10.0.0.1  389    DC01      CN=DC01,OU=Domain Controllers,DC=example,DC=local
        # LDAP  10.0.0.1  389    DC01      operatingSystem: Windows Server 2019

        lines = output.splitlines()
        current_computer = None

        for line in lines:
            line = line.strip()
            if not line or "LDAP" not in line:
                continue

            # Check if this is a computer line (ends with $)
            if "[+]" in line and "\\" in line:
                # Extract computer name
                parts = line.split("\\")
                if len(parts) >= 2:
                    computer_name = parts[-1].strip()
                    # Remove trailing $ if present
                    hostname = computer_name.rstrip("$")
                    current_computer = LDAPComputer(
                        hostname=hostname,
                        samaccountname=computer_name,
                    )
                    computers.append(current_computer)

            # Parse additional attributes
            elif current_computer:
                if "CN=" in line and "DC=" in line:
                    current_computer.distinguished_name = line.split("DC01")[-1].strip()
                elif "operatingSystem:" in line:
                    current_computer.operating_system = line.split("operatingSystem:")[
                        -1
                    ].strip()
                elif "operatingSystemVersion:" in line:
                    current_computer.os_version = line.split("operatingSystemVersion:")[
                        -1
                    ].strip()
                elif "dNSHostName:" in line:
                    current_computer.dns_hostname = line.split("dNSHostName:")[
                        -1
                    ].strip()

        return computers

    def _parse_netexec_active_users_output(self, output: str) -> List[str]:
        """Parse NetExec ``--active-users`` output to a username list."""
        if not output:
            return []

        usernames: list[str] = []
        seen: set[str] = set()
        for line in output.splitlines():
            line = line.strip()
            if not line or "LDAP" not in line:
                continue
            if "-Username-" in line:
                continue
            if "\\" in line:
                candidate = line.split("\\")[-1].strip()
            else:
                parts = line.split(None, 5)
                if len(parts) < 5:
                    continue
                candidate = parts[4].strip()

            candidate = candidate.strip("[]")
            if not candidate:
                continue
            if candidate in {"*", "+", "-"}:
                continue
            if candidate.startswith("[") or candidate.startswith("-"):
                continue
            if candidate.casefold() in {
                "ldap",
                "total",
            }:
                continue

            key = candidate.lower()
            if key in seen:
                continue
            seen.add(key)
            usernames.append(key)
        return usernames
