"""Delegation enumeration mixin.

This module encapsulates the logic required to enumerate Kerberos delegation
relationships (unconstrained, constrained, resource-based) using external
tools such as Impacket's ``findDelegation.py``.

The goal is to move parsing and process execution out of ``adscan.py`` and
provide a reusable service API that can be consumed by both the CLI and a
future web backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Dict, Callable
import subprocess
import logging
import re

from adscan_internal.core import AuthMode, requires_auth
from adscan_internal.integrations.impacket.runner import run_raw_impacket_command


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
    result = run_raw_impacket_command(command, timeout=timeout)
    if result is None:
        return subprocess.CompletedProcess(command, 1, "", "Impacket command failed")
    return result


@dataclass
class DelegationAccount:
    """Represents a delegation configuration for an account.

    Attributes:
        account: Account name (typically sAMAccountName).
        account_type: Type of the account (e.g., User, Computer).
        delegation_type: Human-readable delegation type string.
        delegation_to: Target service/SPN or principal.
    """

    account: str
    account_type: str
    delegation_type: str
    delegation_to: str


class DelegationEnumerationMixin:
    """Delegation enumeration operations."""

    def __init__(self, parent_service):
        """Initialize delegation enumeration mixin.

        Args:
            parent_service: Parent EnumerationService instance.
        """
        self.parent = parent_service
        self.logger = parent_service.logger

    @requires_auth(AuthMode.AUTHENTICATED)
    def enumerate_delegations(
        self,
        *,
        domain: str,
        command: str,
        executor: CommandExecutor | None = None,
        timeout: int = 300,
        scan_id: Optional[str] = None,
    ) -> tuple[List[DelegationAccount], Dict[str, int]]:
        """Enumerate Kerberos delegations in a domain.

        This method executes the provided command (typically ``findDelegation.py``)
        and parses its output into structured delegation entries.

        Args:
            domain: Target domain name.
            command: Fully built delegation enumeration command.
            executor: Optional command executor for testing (defaults to subprocess).
            timeout: Command timeout in seconds.
            scan_id: Optional scan id for future progress events.

        Returns:
            A tuple ``(delegations, delegation_type_counts)`` where:

            - ``delegations`` is a list of :class:`DelegationAccount`.
            - ``delegation_type_counts`` aggregates counts per delegation type
              (keys: ``unconstrained``, ``constrained``,
              ``constrained_protocol_transition``, ``resource_based_constrained``,
              ``unknown``).
        """

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="delegation_enumeration",
            progress=0.0,
            message=f"Enumerating Kerberos delegations for {domain}",
        )

        exec_fn = executor or _default_executor

        self.logger.info(
            "Executing delegation enumeration command",
            extra={"domain": domain, "command": command},
        )
        result = exec_fn(command, timeout)

        if result.returncode != 0:
            self.logger.warning(
                "Delegation enumeration command failed",
                extra={
                    "domain": domain,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="delegation_enumeration",
                progress=1.0,
                message="Delegation enumeration failed",
            )
            return [], {
                "unconstrained": 0,
                "constrained": 0,
                "constrained_protocol_transition": 0,
                "resource_based_constrained": 0,
                "unknown": 0,
            }

        output = result.stdout or ""
        if "No entries found!" in output:
            self.logger.info(
                "No delegations found in domain",
                extra={"domain": domain},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="delegation_enumeration",
                progress=1.0,
                message="Delegation enumeration completed: no entries",
            )
            return [], {
                "unconstrained": 0,
                "constrained": 0,
                "constrained_protocol_transition": 0,
                "resource_based_constrained": 0,
                "unknown": 0,
            }

        lines = output.strip().splitlines()
        try:
            account_name_index = next(
                i for i, line in enumerate(lines) if "AccountName" in line
            )
        except StopIteration:
            self.logger.warning(
                "Could not locate AccountName header in delegation output",
                extra={"domain": domain},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="delegation_enumeration",
                progress=1.0,
                message="Delegation enumeration completed: unexpected output format",
            )
            return [], {
                "unconstrained": 0,
                "constrained": 0,
                "constrained_protocol_transition": 0,
                "resource_based_constrained": 0,
                "unknown": 0,
            }

        delegations_start = account_name_index + 2

        delegation_type_counts: Dict[str, int] = {
            "unconstrained": 0,
            "constrained": 0,
            "constrained_protocol_transition": 0,
            "resource_based_constrained": 0,
            "unknown": 0,
        }
        delegations: List[DelegationAccount] = []

        for line in lines[delegations_start:]:
            if not line.strip():
                continue

            matches = re.findall(
                r"(\S+)\s+(\S+)\s+((?:Resource-Based\s+)?"
                r"(?:Unconstrained|Constrained)"
                r"(?:\s+w/(?:o)?\s+Protocol\s+Transition)?)\s+(\S+)",
                line,
                re.IGNORECASE,
            )

            if matches:
                account, account_type, delegation_type, delegation_to = matches[0]
                if not account:
                    continue

                delegation_type_lower = delegation_type.lower()
                key: str
                if "unconstrained" in delegation_type_lower:
                    key = "unconstrained"
                elif "resource-based" in delegation_type_lower:
                    key = "resource_based_constrained"
                elif (
                    "protocol transition" in delegation_type_lower
                    and "w/o" not in delegation_type_lower
                ):
                    key = "constrained_protocol_transition"
                elif "constrained" in delegation_type_lower:
                    key = "constrained"
                else:
                    key = "unknown"
                delegation_type_counts[key] += 1

                delegations.append(
                    DelegationAccount(
                        account=account,
                        account_type=account_type,
                        delegation_type=delegation_type,
                        delegation_to=delegation_to,
                    )
                )
            else:
                # Fallback: treat the first token as account name when structure is unknown
                parts = line.split()
                if not parts:
                    continue
                account = parts[0].strip()
                if not account:
                    continue
                delegations.append(
                    DelegationAccount(
                        account=account,
                        account_type="Unknown",
                        delegation_type="Unknown",
                        delegation_to="N/A",
                    )
                )
                delegation_type_counts["unknown"] += 1

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="delegation_enumeration",
            progress=1.0,
            message=f"Delegation enumeration completed: {len(delegations)} entries",
        )

        return delegations, delegation_type_counts
