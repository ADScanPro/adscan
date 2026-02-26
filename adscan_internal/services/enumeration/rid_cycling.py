"""RID cycling enumeration service.

This service encapsulates NetExec ``--rid-brute`` based enumeration behind a
simple Python API, suitable for use from web backends or higher-level
orchestrators without re-implementing CLI logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import logging

from adscan_internal.core import EventBus, LicenseMode
from adscan_internal.integrations.netexec.parsers import parse_rid_usernames
from adscan_internal.integrations.netexec.runner import (
    ExecutionResult,
    NetExecContext,
    NetExecRunner,
)
from adscan_internal.command_runner import CommandRunner, default_runner
from adscan_internal.services.base_service import BaseService


logger = logging.getLogger(__name__)


@dataclass
class RIDCyclingResult:
    """Result of a RID cycling enumeration."""

    domain: str
    usernames: List[str]
    raw_output: str


class RIDCyclingService(BaseService):
    """Service that performs RID cycling via NetExec.

    This is intentionally small and focused; it can be composed alongside
    other services when a dedicated RID enumeration API is desirable.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        license_mode: LicenseMode = LicenseMode.PRO,
        runner: Optional[NetExecRunner] = None,
    ) -> None:
        """Initialize RID cycling service.

        Args:
            event_bus: Optional event bus for progress reporting.
            license_mode: License mode (LITE or PRO).
            runner: Optional NetExecRunner instance, primarily for testing.
        """
        super().__init__(event_bus=event_bus, license_mode=license_mode)
        command_runner: CommandRunner = default_runner
        self._runner: NetExecRunner = runner or NetExecRunner(
            command_runner=command_runner
        )

    def _build_netexec_ctx(self, domain: str) -> NetExecContext:
        """Build a minimal NetExec context for RID cycling.

        The service does not manage workspaces or clock sync; those concerns
        are handled elsewhere in the CLI layer if needed.
        """

        return NetExecContext(
            state_owner=self,
            default_domain=domain,
            extract_domain=lambda _cmd: domain,
            is_domain_configured=lambda _d: True,
            sync_clock_with_pdc=lambda _d: False,
            detect_output_redirection=lambda _cmd: (False, None),
            redirected_file_has_content=lambda _path: False,
            clean_workspaces=lambda _cleanup_logs: True,
            get_workspaces_dir=lambda: Path.home(),
            confirm_ask=lambda _text, default: default,
        )

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
    ) -> RIDCyclingResult:
        """Enumerate domain users via RID cycling.

        Args:
            domain: Target domain name.
            pdc: PDC hostname or IP.
            netexec_path: Full path to NetExec executable.
            auth_args: Authentication arguments for NetExec (e.g., ``-u 'guest' -p ''``).
            max_rid: Maximum RID value to brute force.
            timeout: Command timeout in seconds.
            scan_id: Optional scan identifier for progress events.

        Returns:
            RIDCyclingResult with discovered usernames and raw output.
        """
        self._emit_progress(
            scan_id=scan_id,
            phase="rid_cycling",
            progress=0.0,
            message=f"Starting RID cycling on {pdc}",
        )

        command = (
            f"{netexec_path} smb {pdc} {auth_args} --rid-brute {max_rid}"
        )
        ctx = self._build_netexec_ctx(domain)

        logger.debug("Executing RID cycling command: %s", command)
        proc: ExecutionResult | None = self._runner.run(
            command,
            ctx=ctx,
            domain=domain,
            timeout=timeout,
            pre_sync=False,
        )

        if proc is None:
            logger.error("RID cycling failed: no result returned from NetExec")
            self._emit_progress(
                scan_id=scan_id,
                phase="rid_cycling",
                progress=1.0,
                message="RID cycling failed: no result returned from NetExec",
            )
            return RIDCyclingResult(domain=domain, usernames=[], raw_output="")

        output = proc.stdout or ""
        if proc.returncode != 0:
            logger.warning(
                "RID cycling command exited with non-zero code %s; output: %s",
                proc.returncode,
                output.strip(),
            )

        usernames = parse_rid_usernames(output)

        self._emit_progress(
            scan_id=scan_id,
            phase="rid_cycling",
            progress=1.0,
            message=f"RID cycling completed: {len(usernames)} user(s) found",
        )

        return RIDCyclingResult(domain=domain, usernames=usernames, raw_output=output)


