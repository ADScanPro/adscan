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
    extra: Optional[Mapping[str, object]] = None


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
