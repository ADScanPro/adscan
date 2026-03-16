"""Reusable WinRM network-logon bypass helpers built on top of PSRP.

This backend keeps PSRP as the transport layer but can re-launch selected
PowerShell operations through RunasCs when the remote WinRM session is limited
by a network logon token. The bypass is optional and only activates when the
caller explicitly requests it for one operation.
"""

from __future__ import annotations

import base64
import re
from typing import Final

from adscan_internal import print_info_debug, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.runascs_manager import get_runascs_local_path
from adscan_internal.services.winrm_psrp_service import (
    WinRMPSRPError,
    WinRMPSRPExecutionResult,
    WinRMPSRPService,
)

_RUNASCS_REMOTE_DIR: Final[str] = r"C:\Windows\Temp"
_RUNASCS_REMOTE_PATH: Final[str] = rf"{_RUNASCS_REMOTE_DIR}\adscan_runascs.exe"
_RUNASCS_LOGON_TYPE: Final[int] = 8
_HASH_ONLY_SECRET_PATTERN = re.compile(r"^[0-9A-Fa-f]{32}$")
_HASH_PAIR_SECRET_PATTERN = re.compile(r"^[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32}$")


class WinRMLogonBypassService:
    """Wrap one PSRP backend with an optional RunasCs-based logon bypass."""

    def __init__(
        self,
        *,
        domain: str,
        host: str,
        username: str,
        password: str,
        psrp_service: WinRMPSRPService | None = None,
        remote_runascs_path: str = _RUNASCS_REMOTE_PATH,
    ) -> None:
        self.domain = domain
        self.host = host
        self.username = username
        self.password = password
        self._psrp_service = psrp_service or WinRMPSRPService(
            domain=domain,
            host=host,
            username=username,
            password=password,
        )
        self._remote_runascs_path = remote_runascs_path
        self._runascs_uploaded = False

    def fetch_file(self, remote_path: str, save_path: str) -> str:
        """Delegate one PSRP file fetch to the underlying backend."""
        return self._psrp_service.fetch_file(remote_path, save_path)

    def fetch_files(self, paths, download_dir: str):
        """Delegate multi-file PSRP downloads to the underlying backend."""
        return self._psrp_service.fetch_files(paths, download_dir)

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Delegate one PSRP upload to the underlying backend."""
        return self._psrp_service.upload_file(local_path, remote_path)

    def execute_powershell(
        self,
        script: str,
        *,
        operation_name: str | None = None,
        require_logon_bypass: bool = False,
    ) -> WinRMPSRPExecutionResult:
        """Execute PowerShell and optionally escape WinRM network-logon limits.

        Args:
            script: PowerShell payload to execute remotely.
            operation_name: Stable label used for debug/telemetry context.
            require_logon_bypass: When True, attempt to re-launch the PowerShell
                payload through RunasCs with logon type 8 before falling back to
                the plain PSRP execution path.

        Returns:
            Structured PSRP execution result.
        """
        normalized_operation = str(operation_name or "winrm_powershell").strip() or "winrm_powershell"
        if not require_logon_bypass:
            return self._psrp_service.execute_powershell(script, operation_name=normalized_operation)

        bypass_reason = self._get_bypass_unavailability_reason()
        if bypass_reason:
            print_info_debug(
                "WinRM logon bypass unavailable: "
                f"operation={mark_sensitive(normalized_operation, 'text')} "
                f"reason={mark_sensitive(bypass_reason, 'text')}"
            )
            return self._psrp_service.execute_powershell(script, operation_name=normalized_operation)

        try:
            remote_runascs_path = self._ensure_runascs_uploaded()
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_info_debug(
                "WinRM logon bypass setup failed; falling back to plain PSRP: "
                f"operation={mark_sensitive(normalized_operation, 'text')} "
                f"error={mark_sensitive(str(exc), 'text')}"
            )
            return self._psrp_service.execute_powershell(script, operation_name=normalized_operation)

        print_info_debug(
            "WinRM logon bypass active: "
            f"operation={mark_sensitive(normalized_operation, 'text')} "
            f"method={mark_sensitive('RunAsCs', 'text')} "
            f"logon_type={_RUNASCS_LOGON_TYPE}"
        )
        bypass_script = self._build_runascs_wrapper_script(
            script=script,
            remote_runascs_path=remote_runascs_path,
        )
        return self._psrp_service.execute_powershell(
            bypass_script,
            operation_name=f"{normalized_operation}:runascs",
        )

    def _get_bypass_unavailability_reason(self) -> str | None:
        """Return one stable reason when the RunasCs bypass cannot be used."""
        secret = str(self.password or "").strip()
        if not secret:
            return "missing_password"
        if self._secret_looks_like_hash(secret):
            return "secret_is_hash_only"
        if get_runascs_local_path(target_os="windows", arch="amd64") is None:
            return "runascs_binary_missing"
        return None

    @staticmethod
    def _secret_looks_like_hash(secret: str) -> bool:
        """Return True when the supplied WinRM secret is a hash, not plaintext."""
        return bool(
            _HASH_ONLY_SECRET_PATTERN.fullmatch(secret)
            or _HASH_PAIR_SECRET_PATTERN.fullmatch(secret)
        )

    def _ensure_runascs_uploaded(self) -> str:
        """Upload RunasCs to the remote host once and return the remote path."""
        if self._runascs_uploaded:
            return self._remote_runascs_path

        runascs_path = get_runascs_local_path(target_os="windows", arch="amd64")
        if runascs_path is None:
            raise WinRMPSRPError("RunasCs binary is not available on the operator host.")
        self._psrp_service.upload_file(str(runascs_path), self._remote_runascs_path)
        self._runascs_uploaded = True
        return self._remote_runascs_path

    @staticmethod
    def _escape_powershell_single_quoted(value: str) -> str:
        """Escape one string for safe use in a PowerShell single-quoted literal."""
        return str(value or "").replace("'", "''")

    def _build_runascs_wrapper_script(self, *, script: str, remote_runascs_path: str) -> str:
        """Return a PSRP wrapper script that re-launches PowerShell through RunasCs."""
        encoded_command = base64.b64encode((script or "").encode("utf-16-le")).decode("ascii")
        command_line = (
            "powershell.exe -NoLogo -NoProfile -NonInteractive "
            "-ExecutionPolicy Bypass -EncodedCommand "
            f"{encoded_command}"
        )
        domain_value = self.domain or "."
        return (
            f"$runasPath = '{self._escape_powershell_single_quoted(remote_runascs_path)}'\n"
            f"$runasUser = '{self._escape_powershell_single_quoted(self.username)}'\n"
            f"$runasPassword = '{self._escape_powershell_single_quoted(self.password)}'\n"
            f"$runasDomain = '{self._escape_powershell_single_quoted(domain_value)}'\n"
            f"$commandLine = '{self._escape_powershell_single_quoted(command_line)}'\n"
            "$runasArgs = @($runasUser, $runasPassword, $commandLine, '-d', $runasDomain, '-l', '8')\n"
            "& $runasPath @runasArgs 2>&1 | ForEach-Object { $_.ToString() }\n"
        )


__all__ = ["WinRMLogonBypassService"]
