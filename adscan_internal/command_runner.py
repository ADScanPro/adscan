from __future__ import annotations

import selectors
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from adscan_core.native_secret_scrub import scrub_native_secrets

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
    # When set, the command runs in STREAMING mode: each stdout line is handed
    # to ``on_line`` the moment it is emitted (instead of only after the process
    # exits), while the full output is still accumulated and returned. Used for
    # long-running commands whose incremental output carries live progress — e.g.
    # a hashcat crack emitting ``--status-json`` ticks every few seconds. The
    # callback is best-effort (its exceptions never break the command) and MUST
    # NOT print (it may run on a background worker thread).
    on_line: Optional[Callable[[str], None]] = None
    # STREAMING mode only (requires ``on_line``): an output-SILENCE watchdog.
    # When set, the process is killed and ``TimeoutExpired`` is raised if it
    # emits NO output at all for this many seconds — independent of the overall
    # ``timeout``. This bounds a WEDGED long-running command (e.g. a hung
    # hashcat) without an elapsed cap that would kill a healthy one that is still
    # emitting incremental output (a status tick every few seconds). ``None``
    # (default) preserves the original behaviour: no silence watchdog.
    silence_timeout: Optional[float] = None


def _extract_non_empty_lines(text: str | None) -> list[str]:
    """Return non-empty output lines from stdout/stderr text.

    Belt-and-suspenders secret hygiene: every preview line is routed through the
    native-secret scrubber (the SSOT in :mod:`adscan_core.native_secret_scrub`)
    before it can reach a recorded ``print_*`` call. This guarantees that even an
    unforeseen secret-bearing token in command output — e.g. an rclone backend
    connection string echoed in STDERR with a reversible ``pass=<obscured>`` blob
    — is redacted at the preview boundary. Scrubbing is best-effort and never
    raises; it does not change the line COUNT, so execution summaries are
    unaffected.
    """
    if not text:
        return []
    return [
        scrub_native_secrets(line)
        for line in text.splitlines()
        if line.strip()
    ]


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
    max_line_length: int | None = None,
) -> str:
    """Build a compact head/tail preview for one multiline text payload.

    Args:
        text: Source text to summarize.
        head: Number of non-empty lines to keep from the beginning.
        tail: Number of non-empty lines to keep from the end when truncation occurs.
        include_omission_notice: Whether to include an omitted-lines marker.
        max_line_length: When set, individual lines longer than this are truncated
            with a ``[…N chars]`` suffix. Useful for scripts that embed large
            inline payloads (e.g. JSON manifests) as a single line.

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

    def _cap(line: str) -> str:
        if max_line_length and len(line) > max_line_length:
            return line[:max_line_length] + f" […{len(line)} chars]"
        return line

    preview_lines: list[str] = []
    preview_lines.extend(_cap(ln) for ln in head_lines)
    if include_omission_notice and omitted_lines > 0:
        preview_lines.append(f"... ({omitted_lines} line(s) omitted) ...")
    preview_lines.extend(_cap(ln) for ln in tail_lines)
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
        """Run a command and annotate the result with elapsed seconds.

        When ``spec.on_line`` is set the command is executed in STREAMING mode
        (see :meth:`_run_streaming`): each stdout line reaches the callback the
        moment it is emitted while the full output is still accumulated and
        returned, so post-hoc completion parsing keeps working. Otherwise the
        blocking :func:`subprocess.run` path is used unchanged.
        """
        if spec.on_line is not None:
            return self._run_streaming(spec)

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

    def _run_streaming(self, spec: CommandSpec) -> ExecutionResult:
        """Stream stdout line-by-line to ``spec.on_line`` while capturing output.

        Preserves the blocking path's contract so a caller can swap in an
        ``on_line`` callback without any other change: ``env`` (the clean env the
        shell derives for PyInstaller binaries), ``cwd``, ``shell``, ``timeout``
        and ``check`` are all honoured, and a ``CompletedProcess[str]`` carrying
        the FULL accumulated stdout is returned (so completion parsing that reads
        the whole output still works). stderr is merged into stdout so a single
        stream can be read incrementally; the returned ``stderr`` is therefore
        ``None``. The callback is best-effort — its exceptions never break the
        command. A timeout raises :class:`subprocess.TimeoutExpired` exactly like
        the blocking path, so the caller's existing timeout handling applies.
        """
        popen_kwargs: dict[str, Any] = dict(
            shell=spec.shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            # Detach the child from the terminal: with an inherited TTY on stdin a
            # streamed long-running child (hashcat) goes INTERACTIVE — it starts
            # its keypress/menu thread ([s]tatus [p]ause [b]ypass … =>) and races
            # the prompt_toolkit REPL for terminal input, STEALING the operator's
            # keystrokes (typed keys were consumed as hashcat's 'b'=bypass, so the
            # REPL lagged AND hashcat bypassed its own dictionary). A non-TTY stdin
            # makes the child fully non-interactive; --status-json/--status-timer
            # still emit on STDOUT, so the live ETA is unaffected. Streaming mode
            # never wires stdin input, so DEVNULL is always safe here.
            stdin=subprocess.DEVNULL,
        )
        if spec.env is not None:
            popen_kwargs["env"] = dict(spec.env)
        if spec.cwd is not None:
            popen_kwargs["cwd"] = spec.cwd

        on_line = spec.on_line
        collected: list[str] = []

        def _emit(segment: str) -> None:
            line = segment.rstrip("\r\n")
            collected.append(line)
            if on_line is None:
                return
            try:
                on_line(line)
            except Exception:  # noqa: BLE001 — the callback must never break the run
                pass

        started_at = time.perf_counter()
        proc = subprocess.Popen(spec.command, **popen_kwargs)  # nosec B603
        pending = ""
        # Last wall-clock time ANY output chunk was received. Seeded at launch so
        # the silence watchdog tolerates the initial startup/autotune gap, and
        # reset on every chunk (any output — status ticks AND non-status banners
        # like "Starting autotune. Please be patient…" — counts as "alive").
        last_output_at = time.perf_counter()
        try:
            assert proc.stdout is not None
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                now = time.perf_counter()
                if (
                    spec.timeout is not None
                    and (now - started_at) > spec.timeout
                ):
                    proc.kill()
                    proc.wait()
                    raise subprocess.TimeoutExpired(
                        spec.command, spec.timeout, output="\n".join(collected)
                    )
                if (
                    spec.silence_timeout is not None
                    and (now - last_output_at) > spec.silence_timeout
                ):
                    proc.kill()
                    proc.wait()
                    raise subprocess.TimeoutExpired(
                        spec.command,
                        spec.silence_timeout,
                        output="\n".join(collected),
                    )
                events = selector.select(timeout=0.2)
                if not events:
                    if proc.poll() is not None:
                        break
                    continue
                try:
                    chunk = proc.stdout.read1(4096)  # type: ignore[attr-defined]
                except Exception:  # noqa: BLE001 — fall back to a plain read
                    chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                # Fresh output — the process is alive; reset the silence window.
                last_output_at = time.perf_counter()
                pending += (
                    chunk.decode("utf-8", errors="replace")
                    if isinstance(chunk, bytes)
                    else chunk
                )
                while True:
                    idx_nl = pending.find("\n")
                    idx_cr = pending.find("\r")
                    if idx_nl == -1 and idx_cr == -1:
                        break
                    if idx_nl == -1:
                        idx = idx_cr
                    elif idx_cr == -1:
                        idx = idx_nl
                    else:
                        idx = min(idx_nl, idx_cr)
                    segment, pending = pending[:idx], pending[idx + 1:]
                    if segment.strip():
                        _emit(segment)
            if pending.strip():
                _emit(pending)
        finally:
            try:
                if proc.stdout is not None:
                    proc.stdout.close()
            except Exception:  # noqa: BLE001 — best-effort cleanup
                pass

        returncode = proc.wait()
        stdout = "\n".join(collected)
        if spec.check and returncode != 0:
            raise subprocess.CalledProcessError(returncode, spec.command, output=stdout)
        result: ExecutionResult = subprocess.CompletedProcess(
            spec.command, returncode, stdout, None
        )
        setattr(
            result,
            "_adscan_elapsed_seconds",
            max(0.0, time.perf_counter() - started_at),
        )
        return result


default_runner = CommandRunner()
