"""WinRM compatibility wrapper for transport-agnostic Windows file mapping."""

from __future__ import annotations

from typing import Callable, Iterable

from adscan_internal.services.windows_file_mapping_service import (
    BULK_SYSTEM_DIRECTORY_NAMES,
    PowerShellCommandExecutor,
    WindowsFileMapEntry,
    WindowsFileMapLimits,
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

#: Bounds of the file listing read over Windows Remote Management. A reply
#: carries the same 2,000 entries as on any transport (see
#: :class:`WindowsFileMapLimits`). The totals are twice the defaults: a listing
#: is held in memory that grows with its entries alone (about 1 KB each, so
#: 100,000 entries stay near 100 MB), and one query here costs a runspace, not
#: a parsed TDS reply, so 600 queries keep the listing within minutes.
WINRM_FILE_MAP_LIMITS = WindowsFileMapLimits(
    max_total_entries=100_000,
    max_queries=600,
)

#: Characters of output one bounded listing query may return before the client
#: refuses it, as a multiple of the reply the script itself is capped to. The
#: script already replaces an oversize reply by one marker line; this is the
#: client's own ceiling, for a host that does not honour it.
_REPLY_CEILING_FACTOR = 2
_REPLY_CEILING_SLACK_CHARS = 16_384


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

    @staticmethod
    def _wrap_psrp_service_bounded(
        psrp_service: WinRMPSRPService, *, max_output_chars: int
    ):
        """Adapt a PSRP service into an executor whose every reply is bounded.

        Each script's output is counted while it is received and refused past
        ``max_output_chars`` (``WinRMPSRPService.execute_powershell``), so no
        reply is ever held in memory beyond that, whatever the host returns.
        """

        def _executor(script: str) -> WindowsPowerShellExecutionResult:
            result = psrp_service.execute_powershell(
                script,
                operation_name="winrm_sensitive_file_map",
                max_output_chars=max_output_chars,
                debug_output_preview=False,
            )
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

    def generate_bounded_file_map(  # pylint: disable=arguments-differ
        self,
        *,
        psrp_service: WinRMPSRPService | None = None,
        command_executor: PowerShellCommandExecutor | None = None,
        output_path: str,
        limits: WindowsFileMapLimits | None = None,
        roots: Iterable[str] | None = None,
        excluded_path_prefixes: Iterable[str] | None = None,
        excluded_directory_names: Iterable[str] | None = None,
        included_extensions: Iterable[str] | None = None,
        deferred_directory_names: Iterable[str] | None = None,
        metadata: dict[str, object] | None = None,
        on_query: Callable[[], None] | None = None,
    ) -> dict[str, object]:
        """Generate a WinRM file manifest in bounded replies and persist it.

        The whole tree is walked (only the WinRM noise folders are left out,
        never a path allowlist); the server keeps the files whose extension the
        review reads; each reply carries at most ``limits.max_entries_per_query``
        entries and is refused by the client past its ceiling; the listing
        stops at ``limits.max_total_entries`` and the manifest's ``listing``
        block then names what it did not reach. The operating system's and
        vendors' folders are read last, so a custom location is read first.

        Args:
            psrp_service: The PSRP session to list through.
            command_executor: An executor to list through instead (tests).
            output_path: Where the manifest is written.
            limits: The bounds (default :data:`WINRM_FILE_MAP_LIMITS`).
            roots: Roots to list; every filesystem drive when omitted.
            excluded_path_prefixes: Path prefixes left out (default: the WinRM
                noise folders).
            excluded_directory_names: Directory names left out (same default).
            included_extensions: Extensions kept; every file when empty.
            deferred_directory_names: Directory names read last (default
                :data:`BULK_SYSTEM_DIRECTORY_NAMES`); an ordering, not an
                exclusion.
            metadata: Stored with the manifest.
            on_query: Called before each query (a memory-stage check).

        Raises:
            WinRMPSRPError: the listing could not be read.
        """
        bounds = limits or WINRM_FILE_MAP_LIMITS
        executor = command_executor
        if executor is None:
            if psrp_service is None:
                raise TypeError("psrp_service or command_executor is required")
            executor = self._wrap_psrp_service_bounded(
                psrp_service,
                max_output_chars=(
                    bounds.max_reply_chars * _REPLY_CEILING_FACTOR
                    + _REPLY_CEILING_SLACK_CHARS
                ),
            )
        try:
            return super().generate_bounded_file_map(
                command_executor=executor,
                output_path=output_path,
                limits=bounds,
                roots=roots,
                excluded_path_prefixes=(
                    excluded_path_prefixes or get_winrm_excluded_path_prefixes()
                ),
                excluded_directory_names=(
                    excluded_directory_names or get_winrm_excluded_directory_names()
                ),
                included_extensions=included_extensions,
                deferred_directory_names=(
                    BULK_SYSTEM_DIRECTORY_NAMES
                    if deferred_directory_names is None
                    else deferred_directory_names
                ),
                metadata=metadata,
                on_query=on_query,
            )
        except WindowsFileMappingError as exc:
            raise WinRMPSRPError(str(exc)) from exc


__all__ = [
    "WINRM_FILE_MAP_LIMITS",
    "WinRMFileMapEntry",
    "WinRMFileMappingService",
]
