"""Domain service for domain-related operations.

This module provides services for domain enumeration, trust relationships,
and domain authentication operations.
"""

from typing import Dict, List, Optional, Any, Tuple
import logging
import subprocess
import shlex
from dataclasses import dataclass

from adscan_internal.services.base_service import BaseService
from adscan_internal.subprocess_env import get_clean_env_for_compilation


logger = logging.getLogger(__name__)


@dataclass
class TrustRelationship:
    """Represents a domain trust relationship.

    Attributes:
        source_domain: Source domain name
        target_domain: Target domain name
        trust_type: Type of trust (Parent, Child, External, Forest, etc.)
        trust_direction: Direction (Inbound, Outbound, Bidirectional)
        target_pdc: Target domain's PDC (if available)
    """

    source_domain: str
    target_domain: str
    trust_type: str = "Unknown"
    trust_direction: str = "Unknown"
    target_pdc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_domain": self.source_domain,
            "target_domain": self.target_domain,
            "trust_type": self.trust_type,
            "trust_direction": self.trust_direction,
            "target_pdc": self.target_pdc,
        }


class DomainService(BaseService):
    """Service for domain operations.

    This service encapsulates domain-related operations including:
    - Trust enumeration
    - Domain authentication
    - Domain configuration retrieval
    - ADCS detection
    """

    def enumerate_trusts(
        self,
        domain: str,
        pdc: str,
        username: str,
        password: str,
        enum_trusts_path: str,
        nxc_args: Optional[List[str]] = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,
    ) -> Tuple[List[TrustRelationship], List[str]]:
        """Enumerate trust relationships for a domain (PRO only).

        Args:
            domain: Domain name to enumerate
            pdc: Primary domain controller FQDN
            username: Authentication username
            password: Authentication password
            enum_trusts_path: Path to enum-trusts executable
            nxc_args: Optional NetExec CLI arguments
            scan_id: Optional scan ID for progress tracking
            timeout: Command timeout in seconds

        Returns:
            Tuple of:
                - List of discovered trust relationships
                - List of discovered domain names

        Raises:
            FileNotFoundError: If enum-trusts executable not found
            subprocess.TimeoutExpired: If command times out
            subprocess.CalledProcessError: If command fails
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="trust_enumeration",
            progress=0.0,
            message=f"Starting trust enumeration for {domain}",
        )

        # Build command
        cmd_parts = [
            enum_trusts_path,
            "-u",
            username,
            "-p",
            password,
            "-d",
            domain,
            "-pdc",
            pdc,
        ]
        if nxc_args:
            cmd_parts.extend(nxc_args)

        command = " ".join(shlex.quote(part) for part in cmd_parts)

        self.logger.info(f"Executing trust enumeration for domain: {domain}")
        self._emit_progress(
            scan_id=scan_id,
            phase="trust_enumeration",
            progress=0.3,
            message="Executing enum-trusts command",
        )

        # Execute command
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
        except subprocess.TimeoutExpired:
            self.logger.error(f"Trust enumeration timed out after {timeout}s")
            self._emit_progress(
                scan_id=scan_id,
                phase="trust_enumeration",
                progress=1.0,
                message="Trust enumeration timed out",
            )
            raise

        self._emit_progress(
            scan_id=scan_id,
            phase="trust_enumeration",
            progress=0.6,
            message="Parsing trust enumeration results",
        )

        # Parse results
        trusts, discovered_domains = self._parse_trust_output(
            result.stdout,
            domain,
        )

        self._emit_progress(
            scan_id=scan_id,
            phase="trust_enumeration",
            progress=1.0,
            message=f"Trust enumeration completed: {len(trusts)} trust(s) found",
        )

        self.logger.info(
            f"Trust enumeration completed for {domain}: "
            f"{len(trusts)} trust(s), {len(discovered_domains)} domain(s)"
        )

        return trusts, discovered_domains

    def _parse_trust_output(
        self,
        output: str,
        source_domain: str,
    ) -> Tuple[List[TrustRelationship], List[str]]:
        """Parse enum-trusts output.

        Args:
            output: Command stdout
            source_domain: Source domain name

        Returns:
            Tuple of (trust relationships, discovered domains)
        """
        trusts: List[TrustRelationship] = []
        discovered_domains: List[str] = []
        domain_pdc_mapping: Dict[str, str] = {}

        if "SUMMARY OF FOUND TRUST RELATIONSHIPS" not in output:
            return trusts, discovered_domains

        if "[-] No trust relationships found." in output:
            return trusts, discovered_domains

        # Extract summary section
        summary_section = output.split("SUMMARY OF FOUND TRUST RELATIONSHIPS")[1]

        # First pass: Extract domain and PDC mappings
        current_domain = None
        for line in summary_section.splitlines():
            line = line.strip()
            if not line:
                continue

            if "Domain: " in line and not line.startswith("  "):
                current_domain = line.split("Domain: ")[1].strip().rstrip(":")
            elif "PDC IP: " in line and current_domain:
                pdc_ip = line.split("PDC IP: ")[1].strip()
                domain_pdc_mapping[current_domain] = pdc_ip
                self.logger.debug(f"Mapped {current_domain} -> PDC: {pdc_ip}")

        # Second pass: Build domain list and trust relationships
        for line in summary_section.splitlines():
            line = line.strip()
            if "Domain: " in line and not line.startswith("  "):
                domain_name = line.split("Domain: ")[1].strip().rstrip(":")
                if domain_name not in discovered_domains:
                    discovered_domains.append(domain_name)

                    # Create trust relationship
                    trust = TrustRelationship(
                        source_domain=source_domain,
                        target_domain=domain_name,
                        target_pdc=domain_pdc_mapping.get(domain_name),
                    )
                    trusts.append(trust)

        return trusts, discovered_domains

    def verify_domain_connectivity(
        self,
        domain: str,
        pdc: str,
        scan_id: Optional[str] = None,
    ) -> bool:
        """Verify basic connectivity to domain.

        Args:
            domain: Domain name
            pdc: PDC hostname/IP
            scan_id: Optional scan ID

        Returns:
            True if domain is reachable, False otherwise
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="domain_connectivity",
            progress=0.0,
            message=f"Checking connectivity to {domain}",
        )

        # Simple ping check (can be enhanced)
        try:
            clean_env = get_clean_env_for_compilation()
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", pdc],
                capture_output=True,
                timeout=5,
                check=False,
                env=clean_env,
            )
            is_reachable = result.returncode == 0

            self._emit_progress(
                scan_id=scan_id,
                phase="domain_connectivity",
                progress=1.0,
                message=f"Domain {'reachable' if is_reachable else 'unreachable'}",
            )

            return is_reachable
        except (subprocess.TimeoutExpired, Exception) as e:
            self.logger.error(f"Connectivity check failed: {e}")
            self._emit_progress(
                scan_id=scan_id,
                phase="domain_connectivity",
                progress=1.0,
                message="Connectivity check failed",
            )
            return False

    def get_domain_info(
        self,
        domain: str,
        pdc: str,
        username: str,
        password: str,
        netexec_path: str,
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get domain information using NetExec.

        Args:
            domain: Domain name
            pdc: PDC hostname/IP
            username: Authentication username
            password: Authentication password
            netexec_path: Path to NetExec executable
            scan_id: Optional scan ID

        Returns:
            Dictionary with domain information
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="domain_info",
            progress=0.0,
            message=f"Retrieving domain information for {domain}",
        )

        domain_info: Dict[str, Any] = {
            "domain": domain,
            "pdc": pdc,
            "functional_level": None,
            "dc_count": 0,
        }

        # Build argv-style command to avoid shell quoting issues.
        # Detect NT hash: 32 hexadecimal characters.
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )
        command = [netexec_path, "ldap", pdc, "-u", username]
        if is_hash:
            command.extend(["-H", password])
        else:
            command.extend(["-p", password])

        try:
            clean_env = get_clean_env_for_compilation()
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
                env=clean_env,
            )

            if result.returncode == 0:
                # Parse output (simplified - real implementation more complex)
                domain_info["retrieved"] = True
                self.logger.info(f"Domain info retrieved for {domain}")
            else:
                domain_info["retrieved"] = False
                self.logger.warning(f"Failed to retrieve domain info for {domain}")

        except subprocess.TimeoutExpired:
            domain_info["retrieved"] = False
            self.logger.error(f"Domain info retrieval timed out for {domain}")

        self._emit_progress(
            scan_id=scan_id,
            phase="domain_info",
            progress=1.0,
            message="Domain information retrieval completed",
        )

        return domain_info
