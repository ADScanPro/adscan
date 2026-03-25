"""Reusable helpers for structured ``codex exec`` invocations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import json
import os
import shlex
import time

from adscan_internal import print_info_debug
from adscan_internal.command_runner import CommandRunner, CommandSpec, default_runner


@dataclass(frozen=True)
class CodexExecJsonResult:
    """Normalized result for one structured ``codex exec`` run."""

    completed: bool
    command: list[str]
    payload: dict[str, Any]
    output_path: str
    returncode: int
    error_message: str
    stdout_text: str
    stderr_text: str
    stdout_tail: str
    stderr_tail: str
    output_exists: bool
    output_empty: bool
    output_bytes: int
    output_excerpt: str


class CodexExecService:
    """Run ``codex exec`` with JSON-schema constrained output."""

    def __init__(self, *, runner: CommandRunner | None = None) -> None:
        """Initialize service dependencies."""
        self._runner = runner or default_runner

    @staticmethod
    def _format_command_for_log(command: list[str]) -> str:
        """Return one readable command string with the final prompt truncated."""
        if not command:
            return ""
        logged_command = list(command)
        if logged_command:
            last_arg = str(logged_command[-1] or "")
            if len(last_arg) > 240:
                logged_command[-1] = f"{last_arg[:240]}..."
        try:
            return shlex.join(logged_command)
        except Exception:
            return " ".join(str(part) for part in logged_command)

    @staticmethod
    def _collect_output_preview(text: str, label: str) -> list[str]:
        """Return head/tail preview lines for one output stream."""
        lines = [line for line in str(text or "").splitlines() if line.strip()]
        if not lines:
            return []
        preview: list[str] = [f"{label} (head):"]
        preview.extend(lines[:10])
        tail = lines[-10:] if len(lines) > 20 else lines[10:]
        if tail:
            preview.append(f"{label} (tail):")
            preview.extend(tail)
        return preview

    @staticmethod
    def _should_bypass_codex_sandbox() -> bool:
        """Return whether Codex should avoid its nested sandbox in this runtime.

        Inside the ADscan Docker runtime, ``codex exec --sandbox read-only`` may
        fail because the nested bubblewrap/user-namespace sandbox is not always
        available. The container is already the outer isolation boundary, so for
        this case we intentionally let Codex run without its inner sandbox.
        """
        return str(os.environ.get("ADSCAN_CONTAINER_RUNTIME", "")).strip() == "1"

    @classmethod
    def build_command(
        cls,
        *,
        working_dir: str,
        schema_path: str,
        output_path: str,
        model: str,
        prompt: str,
    ) -> list[str]:
        """Build one ``codex exec`` command for structured JSON output."""
        command = [
            "codex",
            "exec",
            "--skip-git-repo-check",
            "--cd",
            working_dir,
            "--color",
            "never",
            "--output-schema",
            schema_path,
            "--output-last-message",
            output_path,
        ]
        if cls._should_bypass_codex_sandbox():
            command.append("--dangerously-bypass-approvals-and-sandbox")
        else:
            command.extend(["--sandbox", "read-only"])
        normalized_model = str(model or "").strip().lower()
        if normalized_model and (
            normalized_model.startswith("gpt-") or "codex" in normalized_model
        ):
            command.extend(["--model", model])
        command.append(prompt)
        return command

    def run_structured_json(
        self,
        *,
        working_dir: str,
        schema: dict[str, Any],
        model: str,
        prompt: str,
        timeout_seconds: int,
    ) -> CodexExecJsonResult:
        """Run ``codex exec`` and parse one schema-constrained JSON payload."""
        with TemporaryDirectory(prefix="adscan-codex-exec-") as temp_dir:
            schema_path = Path(temp_dir) / "output.schema.json"
            output_path = Path(temp_dir) / "output.json"
            schema_path.write_text(
                json.dumps(schema, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            command = self.build_command(
                working_dir=working_dir,
                schema_path=str(schema_path),
                output_path=str(output_path),
                model=model,
                prompt=prompt,
            )
            if self._should_bypass_codex_sandbox():
                print_info_debug(
                    "[codex_exec] Using unsandboxed Codex exec inside ADSCAN_CONTAINER_RUNTIME=1. "
                    "The Docker runtime remains the outer isolation boundary."
                )
            command_for_log = self._format_command_for_log(command)
            print_info_debug(f"[codex_exec] Running: {command_for_log}")
            started_at = time.monotonic()
            result = self._runner.run(
                CommandSpec(
                    command=command,
                    timeout=timeout_seconds,
                    shell=False,
                    capture_output=True,
                    text=True,
                    check=False,
                    env={
                        **os.environ,
                        "FORCE_COLOR": "0",
                        "TERM": "dumb",
                    },
                )
            )
            elapsed_seconds = getattr(result, "_adscan_elapsed_seconds", None)
            if not isinstance(elapsed_seconds, (int, float)):
                elapsed_seconds = time.monotonic() - started_at
            stdout_text = str(result.stdout or "")
            stderr_text = str(result.stderr or "")
            stdout_tail = stdout_text[-400:].strip().replace("\n", "\\n")
            stderr_tail = stderr_text[-400:].strip().replace("\n", "\\n")
            stdout_lines = [line for line in stdout_text.splitlines() if line.strip()]
            stderr_lines = [line for line in stderr_text.splitlines() if line.strip()]
            print_info_debug(
                "[codex_exec] Result: "
                f"exit_code={int(result.returncode)}, "
                f"stdout_lines={len(stdout_lines)}, "
                f"stderr_lines={len(stderr_lines)}, "
                f"duration={float(elapsed_seconds):.3f}s"
            )
            preview_lines = []
            preview_lines.extend(self._collect_output_preview(stdout_text, "STDOUT"))
            preview_lines.extend(self._collect_output_preview(stderr_text, "STDERR"))
            if preview_lines:
                print_info_debug(
                    "[codex_exec] Output preview:\n" + "\n".join(preview_lines),
                    panel=True,
                )
            if not output_path.exists():
                return CodexExecJsonResult(
                    completed=False,
                    command=command,
                    payload={},
                    output_path=str(output_path),
                    returncode=int(result.returncode),
                    error_message=(
                        stderr_text.strip()
                        or stdout_text.strip()
                        or "Codex exec did not produce a JSON result."
                    ),
                    stdout_text=stdout_text,
                    stderr_text=stderr_text,
                    stdout_tail=stdout_tail,
                    stderr_tail=stderr_tail,
                    output_exists=False,
                    output_empty=True,
                    output_bytes=0,
                    output_excerpt="",
                )
            raw_payload = output_path.read_text(encoding="utf-8")
            payload_excerpt = raw_payload[:400].strip().replace("\n", "\\n")
            output_bytes = len(raw_payload.encode("utf-8", "ignore"))
            output_empty = output_bytes == 0
            try:
                parsed_payload = json.loads(raw_payload)
            except json.JSONDecodeError as exc:
                return CodexExecJsonResult(
                    completed=False,
                    command=command,
                    payload={},
                    output_path=str(output_path),
                    returncode=int(result.returncode),
                    error_message=(
                        "Codex exec produced invalid JSON output "
                        f"(JSONDecodeError at line {exc.lineno}, column {exc.colno}). "
                        f"Excerpt: {payload_excerpt}"
                    ),
                    stdout_text=stdout_text,
                    stderr_text=stderr_text,
                    stdout_tail=stdout_tail,
                    stderr_tail=stderr_tail,
                    output_exists=True,
                    output_empty=output_empty,
                    output_bytes=output_bytes,
                    output_excerpt=payload_excerpt,
                )
            if not isinstance(parsed_payload, dict):
                return CodexExecJsonResult(
                    completed=False,
                    command=command,
                    payload={},
                    output_path=str(output_path),
                    returncode=int(result.returncode),
                    error_message="Codex exec produced a non-object JSON payload.",
                    stdout_text=stdout_text,
                    stderr_text=stderr_text,
                    stdout_tail=stdout_tail,
                    stderr_tail=stderr_tail,
                    output_exists=True,
                    output_empty=output_empty,
                    output_bytes=output_bytes,
                    output_excerpt=payload_excerpt,
                )
            return CodexExecJsonResult(
                completed=int(result.returncode) == 0,
                command=command,
                payload=parsed_payload,
                output_path=str(output_path),
                returncode=int(result.returncode),
                error_message="" if int(result.returncode) == 0 else stderr_text.strip(),
                stdout_text=stdout_text,
                stderr_text=stderr_text,
                stdout_tail=stdout_tail,
                stderr_tail=stderr_tail,
                output_exists=True,
                output_empty=output_empty,
                output_bytes=output_bytes,
                output_excerpt=payload_excerpt,
            )
