"""Policy and execution boundary for AI-driven CLI actions."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
import json
import os
import inspect
import re

from rich.prompt import Confirm

from adscan_core.paths import get_logs_dir
from adscan_internal import (
    print_error,
    print_error_debug,
    print_exception,
    print_info_debug,
    print_warning,
    print_warning_debug,
    telemetry,
)


class AIPolicyExecutor:
    """Execute only allowlisted actions requested by AI tools."""

    # Legacy intent/action names exposed to the LLM -> CLI command mappings.
    DOMAIN_ACTIONS: dict[str, str] = {
        "show_domain_info": "info",
        "start_authenticated_scan": "start_auth",
        "enumerate_kerberos_users": "kerberos_enum_users",
        "enumerate_shares": "netexec_auth_shares",
        "run_kerberoast": "kerberoast",
        "run_dcsync": "dcsync",
    }
    BLOCKED_CLI_COMMANDS: set[str] = {
        "system",
        "ask",
        "help",
        "exit",
        "quit",
        "eof",
    }
    HIGH_RISK_COMMANDS: set[str] = {"dcsync", "start_auth"}

    def __init__(
        self,
        *,
        shell: Any,
        max_output_file_size_mb: int = 5,
        confirm_callback: Callable[[str, bool], bool] | None = None,
    ) -> None:
        """Initialize policy executor.

        Args:
            shell: Active shell instance used for dispatching allowlisted methods.
            max_output_file_size_mb: Max output file size for AI-generated files.
            confirm_callback: Optional custom confirmation callback.
        """
        self._shell = shell
        self._max_file_size_bytes = max_output_file_size_mb * 1024 * 1024
        self._confirm_callback = confirm_callback or (
            lambda question, default: Confirm.ask(question, default=default)
        )
        self._audit_path = get_logs_dir() / "ai_audit.log"
        self._command_descriptions: dict[str, str] = {}
        self._allowed_cli_commands = self._discover_allowed_cli_commands()

    def get_workspace_summary(self) -> str:
        """Return a compact textual summary of current workspace state."""
        domain = getattr(self._shell, "domain", None) or "N/A"
        domains = getattr(self._shell, "domains", []) or []
        current_domain_data = (
            getattr(self._shell, "domains_data", {}).get(domain, {})
            if domain != "N/A"
            else {}
        )
        auth = current_domain_data.get("auth", "unknown")
        username = current_domain_data.get("username", "unknown")
        creds = current_domain_data.get("credentials", {})
        cred_count = len(creds) if isinstance(creds, dict) else 0
        return (
            f"workspace={getattr(self._shell, 'current_workspace', 'N/A')}; "
            f"domain={domain}; domains={len(domains)}; auth={auth}; "
            f"user={username}; creds={cred_count}"
        )

    def write_output_file(self, *, filename: str, content: str) -> str:
        """Write AI output into workspace-local `ai_output` directory."""
        if not filename.strip():
            return "blocked: filename is empty"
        safe_name = Path(filename).name
        if safe_name != filename.strip():
            return "blocked: filename must not include path separators"

        output_dir = self._get_ai_output_dir()
        output_dir.mkdir(parents=True, exist_ok=True)
        target_path = (output_dir / safe_name).resolve()
        if not str(target_path).startswith(str(output_dir.resolve())):
            return "blocked: invalid target path"

        payload = content.encode("utf-8")
        if len(payload) > self._max_file_size_bytes:
            return "blocked: output exceeds max allowed size"

        target_path.write_bytes(payload)
        self._audit("file_written", {"path": str(target_path), "bytes": len(payload)})
        return f"ok: wrote {safe_name}"

    def dispatch_domain_action(
        self,
        *,
        action: str,
        domain: str | None = None,
        arguments: str = "",
        reason: str = "",
    ) -> str:
        """Execute legacy mapped actions through the centralized CLI dispatcher."""
        if action not in self.DOMAIN_ACTIONS:
            self._audit(
                "domain_action_blocked", {"action": action, "reason": "allowlist"}
            )
            return f"blocked: action '{action}' is not allowed"

        command = self.DOMAIN_ACTIONS[action]
        arguments_to_use = arguments or (domain or "")
        result = self.dispatch_cli_command(
            command=command,
            arguments=arguments_to_use,
            reason=reason,
        )
        self._audit(
            "domain_action_dispatch_result",
            {"action": action, "command": command, "result": result},
        )
        return result

    def list_allowed_cli_commands(self) -> list[str]:
        """Return all allowlisted CLI commands (without the `do_` prefix)."""
        return sorted(self._allowed_cli_commands.keys())

    def get_cli_command_catalog(
        self,
        *,
        prompt: str,
        max_entries: int = 20,
    ) -> list[tuple[str, str]]:
        """Return command catalog entries without ranking-based filtering."""
        _ = prompt  # kept for interface stability
        catalog = [
            (command, self._command_descriptions.get(command, ""))
            for command in sorted(self._allowed_cli_commands.keys())
        ]
        if max_entries <= 0:
            return catalog
        return catalog[:max_entries]

    def dispatch_cli_command(
        self,
        *,
        command: str,
        arguments: str = "",
        reason: str = "",
    ) -> str:
        """Execute one allowlisted CLI command (excluding blocked commands)."""
        normalized_command = command.strip()
        if not normalized_command:
            return "blocked: command is empty"
        method_name = self._allowed_cli_commands.get(normalized_command)
        if method_name is None:
            self._audit(
                "cli_command_blocked",
                {"command": normalized_command, "reason": "allowlist"},
            )
            print_warning_debug(
                f"AI CLI command blocked by allowlist: command={normalized_command}"
            )
            return f"blocked: command '{normalized_command}' is not allowed"

        target_domain = (getattr(self._shell, "domain", "") or "").strip()
        prompt = (
            f"AI requested command '{normalized_command}'"
            f"{' for ' + target_domain if target_domain else ''}."
            f"{' Arguments: ' + arguments if arguments.strip() else ''} Execute?"
        )
        approved = self._confirm_callback(prompt, False)
        if not approved:
            self._audit(
                "cli_command_denied",
                {"command": normalized_command, "domain": target_domain},
            )
            print_info_debug(
                "AI CLI command denied by user confirmation: "
                f"command={normalized_command} domain={target_domain}"
            )
            return f"denied: command '{normalized_command}'"

        try:
            self._audit(
                "cli_command_dispatched",
                {
                    "command": normalized_command,
                    "method": method_name,
                    "domain": target_domain,
                    "has_arguments": bool(arguments.strip()),
                },
            )
            print_info_debug(
                "AI CLI command dispatched: "
                f"command={normalized_command} method={method_name} "
                f"domain={target_domain} has_arguments={bool(arguments.strip())}"
            )
            method = getattr(self._shell, method_name)
            self._invoke_shell_method(
                method=method,
                command=normalized_command,
                arguments=arguments,
            )
            return f"ok: executed {normalized_command}"
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_error("AI action execution failed.")
            print_exception(show_locals=False, exception=exc)
            self._audit(
                "cli_command_error",
                {"command": normalized_command, "error": type(exc).__name__},
            )
            print_error_debug(
                "AI CLI command execution failed: "
                f"command={normalized_command} method={method_name} "
                f"error={type(exc).__name__}: {exc}"
            )
            return f"error: failed to execute '{normalized_command}'"

    def _discover_allowed_cli_commands(self) -> dict[str, str]:
        """Discover CLI command methods from shell (`do_*`) excluding blocked ones."""
        commands: dict[str, str] = {}
        for attr_name in dir(self._shell):
            if not attr_name.startswith("do_"):
                continue
            method = getattr(self._shell, attr_name, None)
            if not callable(method):
                continue
            command = attr_name[3:]
            if command in self.BLOCKED_CLI_COMMANDS:
                continue
            if not command:
                continue
            commands[command] = attr_name
            self._command_descriptions[command] = self._extract_method_description(method)
        print_info_debug(
            "AI CLI allowlist initialized: "
            f"total_allowed={len(commands)} blocked={sorted(self.BLOCKED_CLI_COMMANDS)}"
        )
        return commands

    @staticmethod
    def _extract_method_description(method: Any) -> str:
        """Extract first useful line from a command method docstring."""
        doc = inspect.getdoc(method) or ""
        if not doc.strip():
            return ""
        for line in doc.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            if candidate.lower().startswith("usage"):
                continue
            return candidate
        return ""

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        """Tokenize text for lightweight command ranking."""
        parts = re.findall(r"[a-z0-9_]{3,}", text.lower())
        return set(parts)

    @staticmethod
    def _invoke_shell_method(*, method: Any, command: str, arguments: str) -> None:
        """Invoke one shell command handler using an argument-safe strategy."""
        signature = inspect.signature(method)
        params = list(signature.parameters.values())
        positional_params = [
            param
            for param in params
            if param.kind in (param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD)
        ]
        if not positional_params:
            method()
            return
        if command == "kerberoast":
            method(arguments.strip())
            return
        method(arguments)

    def _get_ai_output_dir(self) -> Path:
        """Resolve workspace-local AI output directory."""
        workspace_cwd = getattr(
            self._shell, "_get_workspace_cwd", lambda: os.getcwd()
        )()
        return Path(workspace_cwd) / "ai_output"

    def _audit(self, event: str, payload: dict[str, Any]) -> None:
        """Append one JSON-lines audit entry."""
        entry = {
            "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "event": event,
            "payload": payload,
        }
        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._audit_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            print_warning("AI audit logging failed (non-fatal).")
