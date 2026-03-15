"""Stable backend contract for reusable WinRM operations."""

from __future__ import annotations

from typing import Iterable, Protocol

from adscan_internal.services.winrm_psrp_service import (
    WinRMPSRPExecutionResult,
    WinRMPSRPService,
)


class WinRMExecutionBackend(Protocol):
    """Contract for WinRM backends shared by automatic and manual flows."""

    def execute_powershell(self, script: str) -> WinRMPSRPExecutionResult:
        """Execute one PowerShell script remotely."""

    def fetch_file(self, remote_path: str, save_path: str) -> str:
        """Fetch one remote file to one local path."""

    def fetch_files(self, paths: Iterable[str], download_dir: str) -> list[str]:
        """Fetch multiple remote files into one local directory."""

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload one local file to one remote path."""


def build_winrm_backend(
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
) -> WinRMExecutionBackend:
    """Return the default reusable WinRM backend implementation.

    This currently returns the PSRP-backed service. The factory keeps the
    contract stable so a future agent-backed backend can slot in without
    changing the higher-level WinRM workflows.
    """
    return WinRMPSRPService(
        domain=domain,
        host=host,
        username=username,
        password=password,
    )


__all__ = ["WinRMExecutionBackend", "build_winrm_backend"]
