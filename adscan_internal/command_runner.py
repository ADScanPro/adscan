from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional

ExecutionResult = subprocess.CompletedProcess[str]


@dataclass(frozen=True)
class CommandSpec:
    command: str | list[str]
    timeout: Optional[int] = None
    shell: bool = True
    capture_output: bool = True
    text: bool = True
    check: bool = False
    env: Optional[Mapping[str, str]] = None
    cwd: Optional[str] = None
    input: Optional[str] = None
    extra: Optional[Mapping[str, object]] = None


def _extract_non_empty_lines(text: str | None) -> list[str]:
    """Return non-empty output lines from stdout/stderr text."""
    if not text:
        return []
    return [line for line in text.splitlines() if line.strip()]


def summarize_execution_result(result: ExecutionResult) -> tuple[int, int, int, str]:
    """Return normalized execution summary.

    Returns:
        Tuple containing:
            - return code
            - stdout non-empty line count
            - stderr non-empty line count
            - duration text (``<seconds>.3fs`` or ``unknown``)
    """
    stdout_lines = _extract_non_empty_lines(result.stdout)
    stderr_lines = _extract_non_empty_lines(result.stderr)
    elapsed_seconds = getattr(result, "_adscan_elapsed_seconds", None)
    duration_text = (
        f"{float(elapsed_seconds):.3f}s"
        if isinstance(elapsed_seconds, (int, float))
        else "unknown"
    )
    return (
        int(result.returncode),
        len(stdout_lines),
        len(stderr_lines),
        duration_text,
    )


def build_execution_output_preview(
    result: ExecutionResult,
    *,
    stdout_head: int = 10,
    stdout_tail: int = 10,
    stderr_head: int = 10,
) -> str:
    """Build a compact output preview text (head/tail) for debug logs."""
    stdout_lines = _extract_non_empty_lines(result.stdout)
    stderr_lines = _extract_non_empty_lines(result.stderr)

    preview_lines: list[str] = []

    head = stdout_lines[:stdout_head]
    tail = (
        stdout_lines[-stdout_tail:]
        if len(stdout_lines) > (stdout_head + stdout_tail)
        else stdout_lines[stdout_head:]
    )
    if head:
        preview_lines.append("STDOUT (head):")
        preview_lines.extend(head)
    if tail:
        preview_lines.append("STDOUT (tail):")
        preview_lines.extend(tail)
    if stderr_lines:
        preview_lines.append("STDERR (head):")
        preview_lines.extend(stderr_lines[:stderr_head])

    return "\n".join(preview_lines)


class CommandRunner:
    """Execute shell commands with configurable behaviour."""

    def run(self, spec: CommandSpec) -> ExecutionResult:
        """Run a command and annotate the result with elapsed seconds."""
        kwargs: dict[str, Any] = dict(
            shell=spec.shell,
            capture_output=spec.capture_output,
            text=spec.text,
            check=spec.check,
        )

        if spec.timeout is not None:
            kwargs["timeout"] = spec.timeout
        if spec.env is not None:
            kwargs["env"] = dict(spec.env)
        if spec.cwd is not None:
            kwargs["cwd"] = spec.cwd
        if spec.input is not None:
            kwargs["input"] = spec.input
        if spec.extra:
            kwargs.update(spec.extra)

        started_at = time.perf_counter()
        result = subprocess.run(spec.command, **kwargs)
        setattr(
            result,
            "_adscan_elapsed_seconds",
            max(0.0, time.perf_counter() - started_at),
        )
        return result


default_runner = CommandRunner()
