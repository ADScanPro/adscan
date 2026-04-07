"""Runner for Coercer command execution."""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Callable, cast

from adscan_internal import print_info_debug
from adscan_internal.execution_outcomes import (
    build_no_result_completed_process,
    build_timeout_completed_process,
)
from adscan_internal.text_utils import normalize_cli_output


RunCommand = Callable[..., subprocess.CompletedProcess[str] | None]
LastErrorGetter = Callable[[], tuple[str, Exception] | None]


def looks_like_ntlm_hash(value: str) -> bool:
    """Return whether ``value`` looks like a bare NT hash."""

    candidate = str(value or "").strip()
    if len(candidate) != 32:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in candidate)


@dataclass(frozen=True)
class CoercerExecution:
    """Outcome of one Coercer execution attempt."""

    command: list[str]
    result: subprocess.CompletedProcess[str]
    error_kind: str | None
    error_detail: str | None


class CoercerRunner:
    """Execute Coercer commands with structured outcomes and debug logging."""

    def __init__(
        self,
        *,
        coercer_python: str,
        coercer_script: str,
        run_command: RunCommand,
        get_last_error: LastErrorGetter | None = None,
    ) -> None:
        self.coercer_python = coercer_python
        self.coercer_script = coercer_script
        self.run_command = run_command
        self.get_last_error = get_last_error

    def build_command(
        self,
        *,
        target: str,
        listener_ip: str,
        username: str,
        secret: str,
        domain: str,
        auth_type: str = "smb",
        dc_ip: str | None = None,
        method_filter: str | None = None,
    ) -> list[str]:
        """Build the Coercer subprocess command."""

        command = [
            self.coercer_python,
            self.coercer_script,
            "coerce",
            "-t",
            target,
            "-l",
            listener_ip,
            "-u",
            username,
            "-d",
            domain,
            "--auth-type",
            auth_type,
            "--always-continue",
        ]
        if dc_ip:
            command.extend(["--dc-ip", dc_ip])
        if method_filter:
            command.extend(["--filter-method-name", method_filter])
        if looks_like_ntlm_hash(secret):
            command.extend(["--hashes", f":{secret}"])
        else:
            command.extend(["-p", secret])
        return command

    def _redact_command(self, command: list[str]) -> list[str]:
        """Return a copy of the command with secrets removed for debug logs."""

        redacted = list(command)
        for index, token in enumerate(redacted):
            if token == "-p" and index + 1 < len(redacted):
                redacted[index + 1] = "[REDACTED]"
            if token == "--hashes" and index + 1 < len(redacted):
                redacted[index + 1] = ":[REDACTED]"
        return redacted

    def run(
        self,
        *,
        target: str,
        listener_ip: str,
        username: str,
        secret: str,
        domain: str,
        timeout_seconds: int,
        auth_type: str = "smb",
        dc_ip: str | None = None,
        method_filter: str | None = None,
    ) -> CoercerExecution:
        """Execute Coercer and return a structured result."""

        command = self.build_command(
            target=target,
            listener_ip=listener_ip,
            username=username,
            secret=secret,
            domain=domain,
            auth_type=auth_type,
            dc_ip=dc_ip,
            method_filter=method_filter,
        )
        serialized_command = shlex.join(command)

        result = self.run_command(
            serialized_command,
            timeout=timeout_seconds,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
            ignore_errors=True,
        )

        error_kind: str | None = None
        error_detail: str | None = None

        if not isinstance(result, subprocess.CompletedProcess):
            last_error = self.get_last_error() if self.get_last_error else None
            if isinstance(last_error, tuple) and len(last_error) == 2:
                last_error_tuple = cast(tuple[str, Exception], last_error)
                # Pylint does not narrow cast(tuple[str, Exception], ...) here.
                error_kind = str(last_error_tuple[0] or "").strip() or "error"  # pylint: disable=unsubscriptable-object
                error_detail = str(last_error_tuple[1])  # pylint: disable=unsubscriptable-object
            else:
                error_kind = "no_result"
                error_detail = "Command runner returned no result."

            if error_kind == "timeout":
                result = build_timeout_completed_process(
                    serialized_command,
                    tool_name="coercer",
                )
            else:
                result = build_no_result_completed_process(
                    serialized_command,
                    tool_name="coercer",
                )

            print_info_debug(
                f"[coercer] Synthetic result built: error_kind={error_kind} "
                f"detail={error_detail or 'n/a'}"
            )

        result.stdout = normalize_cli_output(result.stdout or "")
        result.stderr = normalize_cli_output(result.stderr or "")

        return CoercerExecution(
            command=command,
            result=result,
            error_kind=error_kind,
            error_detail=error_detail,
        )
