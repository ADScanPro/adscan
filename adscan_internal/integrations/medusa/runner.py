"""Runner for Medusa command execution."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from typing import Any, Callable

from adscan_internal import print_info_debug, telemetry
from adscan_internal.command_runner import (
    build_execution_output_preview,
    summarize_execution_result,
)
from adscan_internal.execution_outcomes import build_timeout_completed_process
from adscan_internal.rich_output import strip_sensitive_markers
from adscan_internal.text_utils import normalize_cli_output

from .helpers import MedusaSweepSettings, build_medusa_login_sweep_command


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MedusaContext:
    """Dependencies required to execute Medusa commands."""

    medusa_path: str
    command_runner: Callable[[str, int], Any]


class MedusaRunner:
    """Execute Medusa commands with consistent timeout handling."""

    def run(
        self,
        command: str,
        *,
        ctx: MedusaContext,
        timeout: int,
    ) -> subprocess.CompletedProcess[str] | None:
        """Execute one Medusa command string."""
        sanitized_command = strip_sensitive_markers(command)
        try:
            print_info_debug(f"[medusa] Running command: {sanitized_command}")
        except Exception:
            pass

        try:
            result = ctx.command_runner(sanitized_command, timeout)
            if isinstance(result, subprocess.CompletedProcess):
                result.stdout = normalize_cli_output(result.stdout or "")
                result.stderr = normalize_cli_output(result.stderr or "")
                try:
                    exit_code, stdout_count, stderr_count, duration_text = (
                        summarize_execution_result(result)
                    )
                    print_info_debug(
                        "[medusa] Result: "
                        f"exit_code={exit_code}, "
                        f"stdout_lines={stdout_count}, "
                        f"stderr_lines={stderr_count}, "
                        f"duration={duration_text}"
                    )
                    preview_text = build_execution_output_preview(
                        result,
                        stdout_head=20,
                        stdout_tail=20,
                        stderr_head=20,
                        stderr_tail=20,
                    )
                    if preview_text:
                        print_info_debug(
                            "[medusa] Output preview:\n" + preview_text,
                            panel=True,
                        )
                except Exception:
                    pass
            return result
        except subprocess.TimeoutExpired as exc:
            telemetry.capture_exception(exc)
            logger.warning(
                "Medusa command timed out", extra={"command": sanitized_command}
            )
            return build_timeout_completed_process(
                sanitized_command, tool_name="medusa"
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            logger.exception("Medusa execution failed")
            return None

    def execute_login_sweep(
        self,
        *,
        ctx: MedusaContext,
        protocol: str,
        targets: str,
        username: str,
        password: str,
        settings: MedusaSweepSettings,
        log_file: str | None,
        module_arguments: list[str] | None,
        timeout: int,
    ) -> subprocess.CompletedProcess[str] | None:
        """Build and execute one Medusa login sweep."""
        command = build_medusa_login_sweep_command(
            medusa_path=ctx.medusa_path,
            protocol=protocol,
            targets=targets,
            username=username,
            password=password,
            settings=settings,
            log_file=log_file,
            module_arguments=module_arguments,
        )
        return self.run(command, ctx=ctx, timeout=timeout)
