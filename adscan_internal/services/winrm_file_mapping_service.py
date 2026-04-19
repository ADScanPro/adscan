"""WinRM compatibility wrapper for transport-agnostic Windows file mapping."""

from __future__ import annotations

from typing import Iterable

from adscan_internal.services.windows_file_mapping_service import (
    PowerShellCommandExecutor,
    WindowsFileMapEntry,
    WindowsFileMappingError,
    WindowsFileMappingService,
    WindowsPowerShellExecutionResult,
)
from adscan_internal.services.winrm_exclusion_policy import (
    get_winrm_excluded_directory_names,
    get_winrm_excluded_path_prefixes,
)
from adscan_internal.services.winrm_psrp_service import (
    WinRMPSRPError,
    WinRMPSRPService,
)


WinRMFileMapEntry = WindowsFileMapEntry


class WinRMFileMappingService(WindowsFileMappingService):
    """Backward-compatible WinRM file mapping API built on the generic service."""

    @staticmethod
    def _wrap_psrp_service(psrp_service: WinRMPSRPService):
        """Adapt a PSRP service into the generic mapping executor contract."""

        def _executor(script: str) -> WindowsPowerShellExecutionResult:
            result = psrp_service.execute_powershell(script)
            return WindowsPowerShellExecutionResult(
                stdout=result.stdout,
                stderr=result.stderr,
                had_errors=result.had_errors,
            )

        return _executor

    def discover_file_system_roots(
        self,
        *,
        psrp_service: WinRMPSRPService | None = None,
        command_executor: PowerShellCommandExecutor | None = None,
    ) -> tuple[str, ...]:
        """Discover reachable filesystem roots for one WinRM target."""
        executor = command_executor
        if executor is None:
            if psrp_service is None:
                raise TypeError("psrp_service or command_executor is required")
            executor = self._wrap_psrp_service(psrp_service)
        try:
            return super().discover_file_system_roots(command_executor=executor)
        except WindowsFileMappingError as exc:
            raise WinRMPSRPError(str(exc)) from exc

    def generate_file_map(
        self,
        *,
        psrp_service: WinRMPSRPService,
        output_path: str,
        roots: Iterable[str] | None = None,
        excluded_path_prefixes: Iterable[str] | None = None,
        excluded_directory_names: Iterable[str] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Generate a WinRM file manifest and persist it to disk."""
        try:
            return super().generate_file_map(
                command_executor=self._wrap_psrp_service(psrp_service),
                output_path=output_path,
                roots=roots,
                excluded_path_prefixes=(
                    excluded_path_prefixes or get_winrm_excluded_path_prefixes()
                ),
                excluded_directory_names=(
                    excluded_directory_names or get_winrm_excluded_directory_names()
                ),
                metadata=metadata,
            )
        except WindowsFileMappingError as exc:
            raise WinRMPSRPError(str(exc)) from exc


__all__ = [
    "WinRMFileMapEntry",
    "WinRMFileMappingService",
]
