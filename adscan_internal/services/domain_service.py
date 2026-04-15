"""Domain service for domain-related operations.

This module provides services for domain enumeration, trust relationships,
and domain authentication operations.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import logging
import re
import subprocess
from typing import Any, Dict, List, Optional

from adscan_internal.services.base_service import BaseService
from adscan_internal.integrations.netexec.helpers import build_auth_nxc
from adscan_internal.subprocess_env import get_clean_env_for_compilation


logger = logging.getLogger(__name__)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


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


@dataclass
class TrustEnumerationResult:
    """Structured output for recursive trust enumeration."""

    trusts: List[TrustRelationship]
    discovered_domains: List[str]
    domain_controllers: Dict[str, str]
    domain_connectivity: Dict[str, Dict[str, Any]]


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
        netexec_path: str,
        executor: Callable[[str, int], subprocess.CompletedProcess[str] | None],
        resolve_pdc_ip: Callable[[str, str], str | None] | None = None,
        check_domain_reachability: Callable[[str, str, str], Dict[str, Any]] | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,
    ) -> TrustEnumerationResult:
        """Enumerate domain trusts recursively using NetExec LDAP.

        Args:
            domain: Domain name to enumerate
            pdc: Primary domain controller IP/FQDN for the starting domain
            username: Authentication username
            password: Authentication password
            netexec_path: Path to the NetExec executable
            executor: Command executor routed through ADscan's NetExec runner
            resolve_pdc_ip: Optional callback to resolve a trusted domain's PDC
            check_domain_reachability: Optional callback to validate that a
                newly discovered trusted domain controller is reachable before
                recursing into it
            scan_id: Optional scan ID for progress tracking
            timeout: Command timeout in seconds

        Returns:
            Structured trust enumeration result.
        """
        normalized_domain = domain.strip().lower()
        auth_string = build_auth_nxc(
            username,
            password,
            normalized_domain,
            kerberos=True,
        )
        pending_domains: list[str] = [normalized_domain]
        seen_domains: set[str] = set()
        discovered_domains: list[str] = [normalized_domain]
        domain_controllers: Dict[str, str] = {normalized_domain: pdc}
        domain_connectivity: Dict[str, Dict[str, Any]] = {}
        trusts: List[TrustRelationship] = []

        self._emit_progress(
            scan_id=scan_id,
            phase="trust_enumeration",
            progress=0.0,
            message=f"Starting trust enumeration for {normalized_domain}",
        )

        while pending_domains:
            current_domain = pending_domains.pop(0)
            if current_domain in seen_domains:
                continue

            current_pdc = domain_controllers.get(current_domain)
            if not current_pdc:
                self.logger.warning(
                    "Skipping trust enumeration for %s: missing PDC", current_domain
                )
                seen_domains.add(current_domain)
                continue

            self._emit_progress(
                scan_id=scan_id,
                phase="trust_enumeration",
                progress=0.3,
                message=f"Enumerating trusts for {current_domain}",
            )
            command = f"{netexec_path} ldap {current_pdc} {auth_string} --dc-list"
            self.logger.info(
                "Executing recursive trust enumeration for domain: %s", current_domain
            )

            result = executor(command, timeout)
            if result is None:
                self.logger.warning(
                    "NetExec runner returned no result for trust enumeration of %s",
                    current_domain,
                )
                seen_domains.add(current_domain)
                continue

            output = self._combine_process_output(result)
            parsed_trusts = self._parse_netexec_trust_output(output)
            seen_domains.add(current_domain)

            if result.returncode != 0 and not parsed_trusts:
                self.logger.warning(
                    "Trust enumeration command for %s failed with rc=%s",
                    current_domain,
                    result.returncode,
                )
                continue

            for parsed_trust in parsed_trusts:
                partner = parsed_trust["partner"]
                if not partner:
                    continue

                partner_pdc = domain_controllers.get(partner)
                if not partner_pdc and resolve_pdc_ip is not None:
                    partner_pdc = resolve_pdc_ip(partner, current_pdc)
                    if partner_pdc:
                        domain_controllers[partner] = partner_pdc

                trusts.append(
                    TrustRelationship(
                        source_domain=current_domain,
                        target_domain=partner,
                        trust_type=parsed_trust["type"],
                        trust_direction=parsed_trust["direction"],
                        target_pdc=partner_pdc,
                    )
                )

                if partner not in discovered_domains:
                    discovered_domains.append(partner)
                should_enqueue = True
                if partner_pdc and check_domain_reachability is not None:
                    connectivity = check_domain_reachability(
                        partner,
                        partner_pdc,
                        current_domain,
                    )
                    if connectivity:
                        domain_connectivity[partner] = connectivity
                        should_enqueue = bool(connectivity.get("reachable"))
                if (
                    should_enqueue
                    and partner not in seen_domains
                    and partner not in pending_domains
                ):
                    pending_domains.append(partner)

        self._emit_progress(
            scan_id=scan_id,
            phase="trust_enumeration",
            progress=1.0,
            message=f"Trust enumeration completed: {len(trusts)} trust(s) found",
        )
        self.logger.info(
            "Trust enumeration completed for %s: %s trust(s), %s domain(s)",
            normalized_domain,
            len(trusts),
            len(discovered_domains),
        )
        return TrustEnumerationResult(
            trusts=trusts,
            discovered_domains=discovered_domains,
            domain_controllers=domain_controllers,
            domain_connectivity=domain_connectivity,
        )

    def _parse_netexec_trust_output(self, output: str) -> List[Dict[str, str]]:
        """Parse NetExec trust lines from ``--dc-list`` output."""
        trusts: List[Dict[str, str]] = []
        for raw_line in output.splitlines():
            parsed = self._parse_trust_line(raw_line)
            if parsed:
                trusts.append(parsed)
        return trusts

    def _parse_trust_line(self, line: str) -> Dict[str, str] | None:
        """Extract trust metadata from one NetExec output line."""
        normalized_line = _ANSI_ESCAPE_RE.sub("", line or "").strip()
        if "->" not in normalized_line:
            return None

        parts = [part.strip() for part in normalized_line.split("->")]
        if len(parts) < 3:
            return None

        left_tokens = parts[0].split()
        if not left_tokens:
            return None

        partner = left_tokens[-1].rstrip(":").lower()
        if "." not in partner:
            return None

        direction = parts[1].strip() or "Unknown"
        trust_type = parts[2].strip() or "Unknown"
        return {
            "partner": partner,
            "direction": direction,
            "type": trust_type,
        }

    def _combine_process_output(self, result: subprocess.CompletedProcess[str]) -> str:
        """Return stdout and stderr combined for best-effort parsing."""
        return "\n".join(
            part
            for part in [(result.stdout or "").strip(), (result.stderr or "").strip()]
            if part
        )

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
