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


def _coerce_timeout_output_text(output: str | bytes | None) -> str:
    """Normalize timeout output payloads into text."""
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return str(output)


def build_text_preview(
    text: str | None,
    *,
    head: int = 10,
    tail: int = 10,
    include_omission_notice: bool = True,
) -> str:
    """Build a compact head/tail preview for one multiline text payload.

    Args:
        text: Source text to summarize.
        head: Number of non-empty lines to keep from the beginning.
        tail: Number of non-empty lines to keep from the end when truncation occurs.
        include_omission_notice: Whether to include an omitted-lines marker.

    Returns:
        A newline-joined preview string. Empty when the input has no non-empty lines.
    """
    lines = _extract_non_empty_lines(text)
    if not lines:
        return ""

    head_lines = lines[:head]
    tail_lines = (
        lines[-tail:]
        if len(lines) > (head + tail)
        else lines[head:]
    )
    omitted_lines = len(lines) - len(head_lines) - len(tail_lines)

    preview_lines: list[str] = []
    preview_lines.extend(head_lines)
    if include_omission_notice and omitted_lines > 0:
        preview_lines.append(f"... ({omitted_lines} line(s) omitted) ...")
    preview_lines.extend(tail_lines)
    return "\n".join(preview_lines)


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
    stderr_tail: int = 10,
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
    omitted_stdout = len(stdout_lines) - len(head) - len(tail)
    if omitted_stdout > 0:
        preview_lines.append(f"... ({omitted_stdout} stdout line(s) omitted) ...")
    if tail:
        preview_lines.append("STDOUT (tail):")
        preview_lines.extend(tail)
    if stderr_lines:
        preview_lines.append("STDERR (head):")
        preview_lines.extend(stderr_lines[:stderr_head])
        stderr_tail_lines = (
            stderr_lines[-stderr_tail:]
            if len(stderr_lines) > (stderr_head + stderr_tail)
            else stderr_lines[stderr_head:]
        )
        omitted_stderr = len(stderr_lines) - stderr_head - len(stderr_tail_lines)
        if omitted_stderr > 0:
            preview_lines.append(
                f"... ({omitted_stderr} stderr line(s) omitted) ..."
            )
        if stderr_tail_lines:
            preview_lines.append("STDERR (tail):")
            preview_lines.extend(stderr_tail_lines)

    return "\n".join(preview_lines)


def build_timeout_output_preview(
    exc: subprocess.TimeoutExpired,
    *,
    stdout_head: int = 10,
    stdout_tail: int = 10,
    stderr_head: int = 10,
    stderr_tail: int = 10,
) -> str:
    """Build a compact output preview from one ``TimeoutExpired`` exception."""
    timeout_result = subprocess.CompletedProcess(
        args=exc.cmd,
        returncode=124,
        stdout=_coerce_timeout_output_text(getattr(exc, "stdout", None)),
        stderr=_coerce_timeout_output_text(getattr(exc, "stderr", None)),
    )
    return build_execution_output_preview(
        timeout_result,
        stdout_head=stdout_head,
        stdout_tail=stdout_tail,
        stderr_head=stderr_head,
        stderr_tail=stderr_tail,
    )


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
