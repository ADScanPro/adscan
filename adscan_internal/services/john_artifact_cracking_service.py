"""Reusable John-the-Ripper helpers for artifact cracking workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
import os
import re
import shlex
import shutil
import subprocess

from adscan_internal import print_info_debug, print_warning, print_warning_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.base_service import BaseService


CommandExecutor = Callable[..., subprocess.CompletedProcess[str] | None]


@dataclass(frozen=True)
class JohnArtifactCrackingResult:
    """Outcome of one John cracking attempt."""

    hash_file: str
    cracked_secret: str | None
    converter_succeeded: bool
    john_succeeded: bool


class JohnArtifactCrackingService(BaseService):
    """Encapsulate converter -> john -> john --show workflows."""

    def __init__(
        self,
        *,
        command_executor: CommandExecutor | None = None,
        john_path: str | None = None,
    ) -> None:
        """Initialize cracking service dependencies."""
        super().__init__()
        self._command_executor = command_executor
        self._john_path = str(john_path or self.resolve_john_path() or "john").strip() or "john"

    @staticmethod
    def resolve_john_path() -> str | None:
        """Resolve the preferred John binary path."""
        candidates = [
            "/opt/adscan/tools/john/run/john",
            "/opt/adscan/bin/john",
            shutil.which("john"),
        ]
        for candidate in candidates:
            normalized = str(candidate or "").strip()
            if normalized and os.path.exists(normalized):
                return os.path.realpath(normalized)
        return None

    @staticmethod
    def resolve_converter_path(converter_name: str) -> str | None:
        """Resolve one ``*2john`` converter path from official and legacy locations."""
        normalized_name = str(converter_name or "").strip()
        if not normalized_name:
            return None

        candidates = [
            shutil.which(normalized_name),
            shutil.which(f"{normalized_name}.py"),
            shutil.which(f"{normalized_name}.pl"),
            f"/opt/adscan/bin/{normalized_name}",
            f"/opt/adscan/bin/{normalized_name}.py",
            f"/opt/adscan/bin/{normalized_name}.pl",
            f"/opt/adscan/tools/john/run/{normalized_name}",
            f"/opt/adscan/tools/john/run/{normalized_name}.py",
            f"/opt/adscan/tools/john/run/{normalized_name}.pl",
        ]

        if normalized_name == "keepass2john":
            candidates.extend(
                [
                    "/opt/adscan/tools/keepass2john/keepass2john.py",
                    "external_tools/keepass2john/keepass2john.py",
                ]
            )

        for candidate in candidates:
            normalized = str(candidate or "").strip()
            if normalized and os.path.exists(normalized):
                return normalized
        return None

    def extract_hash_with_script(
        self,
        *,
        script_path: str,
        input_paths: list[str],
        hash_file: str,
        python_executable: str | None = None,
        timeout: int = 300,
    ) -> bool:
        """Run one external converter script and persist the resulting John hash."""
        if not self._command_executor:
            return False
        normalized_inputs = [str(path or "").strip() for path in input_paths if str(path or "").strip()]
        if not script_path or not normalized_inputs or not hash_file:
            return False

        os.makedirs(os.path.dirname(hash_file) or ".", exist_ok=True)
        files_str = " ".join(shlex.quote(path) for path in normalized_inputs)
        command = self._build_converter_command(
            converter_path=script_path,
            files_str=files_str,
            hash_file=hash_file,
            python_executable=python_executable,
        )
        print_info_debug(
            "John artifact converter command: "
            f"script={mark_sensitive(script_path, 'path')} "
            f"hash_file={mark_sensitive(hash_file, 'path')} "
            f"inputs={len(normalized_inputs)}"
        )
        completed = self._command_executor(
            command,
            timeout=timeout,
            use_clean_env=True,
        )
        self.normalize_hash_file(hash_file)
        if completed is None:
            return False
        if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
            return True
        print_warning_debug(
            "John artifact converter produced no hash output: "
            f"script={mark_sensitive(script_path, 'path')} rc={completed.returncode}"
        )
        return False

    @staticmethod
    def _build_converter_command(
        *,
        converter_path: str,
        files_str: str,
        hash_file: str,
        python_executable: str | None = None,
    ) -> str:
        """Build one converter command line that persists output through ``tee``."""
        normalized_converter = str(converter_path or "").strip()
        normalized_python = str(python_executable or "python3").strip() or "python3"
        if normalized_converter.endswith(".py"):
            runner = (
                f"{shlex.quote(normalized_python)} {shlex.quote(normalized_converter)}"
            )
        else:
            runner = shlex.quote(normalized_converter)
        return f"{runner} {files_str} | tee {shlex.quote(hash_file)}"

    def crack_hash(
        self,
        *,
        hash_file: str,
        wordlist_path: str,
        timeout: int = 300,
    ) -> JohnArtifactCrackingResult:
        """Run John using one resolved wordlist and return cracked secret if any."""
        if not self._command_executor:
            return JohnArtifactCrackingResult(
                hash_file=hash_file,
                cracked_secret=None,
                converter_succeeded=False,
                john_succeeded=False,
            )
        marked_hash = mark_sensitive(hash_file, "path")
        marked_wordlist = mark_sensitive(wordlist_path, "path")
        command = (
            f"{shlex.quote(self._john_path)} --wordlist={shlex.quote(wordlist_path)} "
            f"{shlex.quote(hash_file)}"
        )
        print_info_debug(
            "John cracking command prepared: "
            f"hash_file={marked_hash} wordlist={marked_wordlist}"
        )
        completed = self._command_executor(
            command,
            timeout=timeout,
            use_clean_env=True,
        )
        if completed is None:
            return JohnArtifactCrackingResult(
                hash_file=hash_file,
                cracked_secret=None,
                converter_succeeded=True,
                john_succeeded=False,
            )
        cracked_secret = self._show_cracked_secret(hash_file=hash_file, timeout=timeout)
        return JohnArtifactCrackingResult(
            hash_file=hash_file,
            cracked_secret=cracked_secret,
            converter_succeeded=True,
            john_succeeded=int(getattr(completed, "returncode", 1)) == 0,
        )

    def _show_cracked_secret(
        self,
        *,
        hash_file: str,
        timeout: int,
    ) -> str | None:
        """Return the cracked secret from ``john --show`` output when present."""
        if not self._command_executor:
            return None
        command = f"{shlex.quote(self._john_path)} --show {shlex.quote(hash_file)}"
        completed = self._command_executor(
            command,
            timeout=timeout,
            use_clean_env=True,
        )
        if completed is None or int(getattr(completed, "returncode", 1)) != 0:
            return None
        stdout_text = str(getattr(completed, "stdout", "") or "")
        secret = self.parse_john_show_output(stdout_text)
        if secret:
            print_warning(
                f"Password found: {mark_sensitive(secret, 'password')}"
            )
            return secret
        return None

    @staticmethod
    def normalize_hash_file(hash_file: str) -> bool:
        """Normalize known converter artifacts in one generated John hash file."""
        normalized_hash_file = str(hash_file or "").strip()
        if not normalized_hash_file or not os.path.exists(normalized_hash_file):
            return False
        try:
            with open(normalized_hash_file, "r", encoding="utf-8") as handle:
                original = handle.read()
        except OSError:
            return False

        placeholder = "<SHOULD_BE_REMOVED_INCLUDING_COLON>:"
        sanitized = original
        if placeholder in sanitized:
            normalized_lines: list[str] = []
            for line in sanitized.splitlines():
                if placeholder not in line:
                    normalized_lines.append(line)
                    continue
                _prefix, suffix = line.split(placeholder, 1)
                normalized_lines.append(suffix)
            sanitized = "\n".join(normalized_lines)
            if original.endswith("\n"):
                sanitized += "\n"
        if sanitized == original:
            return False

        with open(normalized_hash_file, "w", encoding="utf-8") as handle:
            handle.write(sanitized)
        return True

    @staticmethod
    def parse_john_show_output(stdout_text: str) -> str | None:
        """Return one cracked secret from ``john --show`` output, skipping summaries."""
        summary_re = re.compile(
            r"^\d+\s+password\s+hash(?:es)?\s+cracked,\s+\d+\s+left$",
            re.IGNORECASE,
        )
        for line in str(stdout_text or "").splitlines():
            normalized = str(line or "").strip()
            if not normalized or normalized.startswith("#"):
                continue
            if normalized.lower().startswith("no password hashes loaded"):
                return None
            if summary_re.match(normalized):
                continue
            if ":" in normalized:
                _, secret = normalized.split(":", 1)
                secret = secret.strip()
                if secret:
                    return secret
                continue
            tokens = normalized.split()
            if tokens:
                candidate = tokens[-1].strip()
                if candidate and candidate.lower() != "left":
                    return candidate
        return None
